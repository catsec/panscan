//! panscan: single-pass parallel PAN (Primary Account Number) scanner.
//!
//! Architecture:
//!
//!   detect  → every Luhn-valid 14-16 digit candidate (cheap, lossy-positive)
//!   score   → compute signals into a PanSignals struct
//!   classify → Reject(reason) or Accept(Confidence)
//!
//! The detection layer is intentionally permissive: it produces candidates,
//! not decisions. All FP suppression lives in `score` + `classify` as
//! POSITIVE descriptions of what a real PAN looks like in its surrounding
//! bytes (scheme + length, low digit density, low entropy, nearby keyword,
//! card-shaped grouping). Adding a new FP source means tuning a threshold
//! or adding a signal, not appending another negative special case.

use std::fs::File;
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use ignore::{WalkBuilder, WalkState};
use memmap2::Mmap;

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------
//
// Surfaced at the top of the file so they're tunable without spelunking. Each
// has a comment with the FP class it targets; raise to be more permissive,
// lower to be stricter. Don't add new constants unless they correspond to a
// new signal, not a new exception.

/// Bytes before/after the candidate inspected for digit density.
const DENSITY_WINDOW: usize = 64;

/// Above this fraction of digits in the surrounding window, the candidate
/// is in a numeric blob (STL vertex lines, OBJ face indices, CSV float
/// columns, hex dumps) and cannot be a typed PAN. Hard reject above this.
const DENSITY_HARD_MAX: f32 = 0.55;

/// Bytes before/after the candidate inspected for Shannon entropy.
const ENTROPY_WINDOW: usize = 128;

/// Above this bits/byte, surroundings are compressed/encrypted/binary
/// (Insta360 thumbnails, PNG/JPEG payloads, .lrv frames). Hard reject.
const ENTROPY_HARD_MAX: f32 = 7.0;

/// Bytes before/after the candidate scanned for card-related keywords.
const KEYWORD_WINDOW: usize = 256;

/// If a card keyword (card, pan, visa, cvv, כרטיס, אשראי, ...) is within
/// this many bytes of the candidate, it's High confidence regardless of
/// the other signals.
const KEYWORD_HIGH_DIST: u16 = 64;

/// Card-context keywords. Match is ASCII-case-insensitive; Hebrew bytes
/// pass through unchanged (no case mapping for Hebrew). Adding new
/// keywords here is the right way to handle a new context — adding new
/// reject heuristics is not.
const KEYWORDS: &[&[u8]] = &[
    b"card",
    b"pan",
    b"visa",
    b"mastercard",
    b"amex",
    b"cvv",
    b"cvc",
    b"creditcard",
    b"credit",
    b"ccnum",
    b"cc_num",
    b"cardnumber",
    b"card_number",
    b"cardno",
    b"card_no",
    b"iin",
    b"primary account",
    b"payment",
    b"cardholder",
    // Hebrew: כרטיס (card), אשראי (credit), מספר (number)
    "כרטיס".as_bytes(),
    "אשראי".as_bytes(),
    "מספר".as_bytes(),
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Quick,
    Complete,
}

/// Card scheme identified by BIN + length. A None outcome from
/// [`detect_scheme`] means either the BIN is unknown or the length
/// doesn't match what the scheme actually issues. Real cards don't have
/// a Luhn-valid number with the wrong length-for-prefix combination, so
/// this gates the largest single class of coincidental-Luhn FPs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Visa,
    Mastercard,
    Amex,
    Diners,
    Jcb,
}

impl Scheme {
    fn name(self) -> &'static str {
        match self {
            Scheme::Visa => "Visa",
            Scheme::Mastercard => "Mastercard",
            Scheme::Amex => "Amex",
            Scheme::Diners => "Diners",
            Scheme::Jcb => "JCB",
        }
    }
}

/// Confidence tier assigned by [`classify`]. The CSV always includes this
/// so reviewers triage cheaply: filter to High for known-good hits, scan
/// Medium for likely real, audit Low only when looking for misses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    fn name(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MinConfidence {
    Low,
    Medium,
    High,
}

impl MinConfidence {
    fn to_confidence(self) -> Confidence {
        match self {
            MinConfidence::Low => Confidence::Low,
            MinConfidence::Medium => Confidence::Medium,
            MinConfidence::High => Confidence::High,
        }
    }
}

#[derive(Clone, Debug)]
struct ScanOpts {
    /// Reject candidates whose BIN+length doesn't match a known scheme.
    /// Off (`--no-strict`) emits unscheme'd Luhn-valid candidates at Low
    /// confidence so reviewers can spot non-major schemes (UnionPay,
    /// Maestro variants, regional cards).
    strict: bool,
    max_bytes: u64,
    debug: bool,
    min_confidence: Confidence,
}

#[derive(Clone, Debug)]
struct Hit {
    offset: usize,
    pan: Vec<u8>,
    scheme: Option<Scheme>,
    confidence: Confidence,
}

#[derive(Clone, Debug)]
struct FileHits {
    path: PathBuf,
    hits: Vec<Hit>,
}

/// Live counters updated by worker threads. Both fields are cheap atomic
/// reads, suitable for polling from the periodic stderr printer.
#[derive(Clone, Default)]
struct ScanProgress {
    files_scanned: Arc<AtomicUsize>,
    files_with_hits: Arc<AtomicUsize>,
}

impl ScanProgress {
    fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Boundary classification
// ---------------------------------------------------------------------------

#[inline(always)]
fn is_digit(b: u8) -> bool {
    b.wrapping_sub(b'0') < 10
}

#[inline(always)]
fn is_separator(b: u8) -> bool {
    matches!(b, b'-' | b' ' | b'.')
}

/// A PAN must be bracketed by a "clearly text" byte (or buffer edge) on both
/// sides. Rejecting boundaries goes beyond just "non-alphanumeric":
///
/// - Letters/digits — embedded in hex blobs or identifiers.
/// - `_` — code identifiers like `id_4111111111111111_token`.
/// - NUL and ASCII control bytes (except `\t \n \r`) — binary-file noise.
///
/// Allowed: ASCII whitespace, printable ASCII punctuation, and any high-bit
/// byte (>= 0x80) so UTF-8 multibyte text — e.g. Hebrew adjacent to ASCII
/// digits — still counts as a valid boundary.
#[inline(always)]
fn is_pan_boundary(b: u8) -> bool {
    match b {
        b' ' | b'\t' | b'\n' | b'\r' => true,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' => false,
        0x00..=0x1F | 0x7F => false,
        _ => true,
    }
}

/// Left boundary check. `is_pan_boundary` plus the numeric-chain-tail veto:
/// a separator (`-`, ` `, `.`) directly preceded by a digit signals that
/// `start` is the head of a long numeric chain whose bridge attempt failed
/// upstream — e.g. `19.47879981994629` re-enters the outer loop at the
/// 14-digit standalone with `.` before it. Reject.
#[inline]
fn is_left_boundary(data: &[u8], start: usize) -> bool {
    if start == 0 {
        return true;
    }
    let b = data[start - 1];
    is_pan_boundary(b) && !(is_separator(b) && start >= 2 && is_digit(data[start - 2]))
}

/// Right boundary check, symmetric: reject if the boundary byte is a
/// separator followed by another digit — tail of a long numeric chain.
#[inline]
fn is_right_boundary(data: &[u8], end: usize) -> bool {
    let n = data.len();
    if end >= n {
        return true;
    }
    let b = data[end];
    is_pan_boundary(b) && !(end + 1 < n && is_separator(b) && is_digit(data[end + 1]))
}

// ---------------------------------------------------------------------------
// SIMD: find the offset of the first ASCII digit byte in a slice
// ---------------------------------------------------------------------------
//
// This dominates throughput on sparse (mostly non-digit) content. Scalar code
// autovectorises decently but a hand-tuned vector skip processes 16 bytes per
// SIMD instruction with one branch per chunk. NEON is in the aarch64 baseline
// and SSE2 in the x86_64 baseline, so no runtime feature detection needed.

#[cfg(target_arch = "aarch64")]
#[inline]
fn find_first_digit(haystack: &[u8]) -> Option<usize> {
    use std::arch::aarch64::*;
    let n = haystack.len();
    let ptr = haystack.as_ptr();
    let mut i = 0;
    unsafe {
        let zero30 = vdupq_n_u8(b'0');
        let ten = vdupq_n_u8(10);
        while i + 16 <= n {
            let chunk = vld1q_u8(ptr.add(i));
            let diff = vsubq_u8(chunk, zero30); // wraps for non-digits
            let mask = vcltq_u8(diff, ten); // 0xFF where digit, 0x00 else
            let narrow = vshrn_n_u16(vreinterpretq_u16_u8(mask), 4);
            let bits = vget_lane_u64(vreinterpret_u64_u8(narrow), 0);
            if bits != 0 {
                return Some(i + bits.trailing_zeros() as usize / 4);
            }
            i += 16;
        }
    }
    haystack[i..].iter().position(|&b| is_digit(b)).map(|p| i + p)
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn find_first_non_digit(haystack: &[u8]) -> Option<usize> {
    use std::arch::aarch64::*;
    let n = haystack.len();
    let ptr = haystack.as_ptr();
    let mut i = 0;
    unsafe {
        let zero30 = vdupq_n_u8(b'0');
        let ten = vdupq_n_u8(10);
        while i + 16 <= n {
            let chunk = vld1q_u8(ptr.add(i));
            let diff = vsubq_u8(chunk, zero30);
            let mask = vcltq_u8(diff, ten);
            let inv = vmvnq_u8(mask);
            let narrow = vshrn_n_u16(vreinterpretq_u16_u8(inv), 4);
            let bits = vget_lane_u64(vreinterpret_u64_u8(narrow), 0);
            if bits != 0 {
                return Some(i + bits.trailing_zeros() as usize / 4);
            }
            i += 16;
        }
    }
    haystack[i..].iter().position(|&b| !is_digit(b)).map(|p| i + p)
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn find_first_digit(haystack: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;
    let n = haystack.len();
    let ptr = haystack.as_ptr();
    let mut i = 0;
    unsafe {
        let lo = _mm_set1_epi8(0x2Fi8); // 47
        let hi = _mm_set1_epi8(0x3Ai8); // 58
        while i + 16 <= n {
            let chunk = _mm_loadu_si128(ptr.add(i) as *const __m128i);
            let gt = _mm_cmpgt_epi8(chunk, lo);
            let lt = _mm_cmplt_epi8(chunk, hi);
            let m = _mm_and_si128(gt, lt);
            let bits = _mm_movemask_epi8(m) as u32;
            if bits != 0 {
                return Some(i + bits.trailing_zeros() as usize);
            }
            i += 16;
        }
    }
    haystack[i..].iter().position(|&b| is_digit(b)).map(|p| i + p)
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn find_first_non_digit(haystack: &[u8]) -> Option<usize> {
    use std::arch::x86_64::*;
    let n = haystack.len();
    let ptr = haystack.as_ptr();
    let mut i = 0;
    unsafe {
        let lo = _mm_set1_epi8(0x2Fi8);
        let hi = _mm_set1_epi8(0x3Ai8);
        while i + 16 <= n {
            let chunk = _mm_loadu_si128(ptr.add(i) as *const __m128i);
            let gt = _mm_cmpgt_epi8(chunk, lo);
            let lt = _mm_cmplt_epi8(chunk, hi);
            let m = _mm_and_si128(gt, lt);
            let bits = _mm_movemask_epi8(m) as u32;
            let inverted = !bits & 0xFFFF;
            if inverted != 0 {
                return Some(i + inverted.trailing_zeros() as usize);
            }
            i += 16;
        }
    }
    haystack[i..].iter().position(|&b| !is_digit(b)).map(|p| i + p)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[inline]
fn find_first_digit(haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| is_digit(b))
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[inline]
fn find_first_non_digit(haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| !is_digit(b))
}

// ---------------------------------------------------------------------------
// Signals: digit density, entropy, keyword proximity
// ---------------------------------------------------------------------------
//
// Three positive descriptions of "what PAN context looks like". Each runs
// only on candidates that survive Luhn + scheme/length — typically ~1% of
// raw candidates — so the cost is amortised.

/// Fraction of ASCII-digit bytes in the surrounding window, EXCLUDING the
/// candidate digits themselves. Low for prose ("...customer 4111... paid"),
/// high for STL vertices, OBJ faces, CSV float columns, hex dumps.
///
/// Counted via the same SIMD predicate as the scanner: a popcount over
/// 16-byte vector lanes. Two passes (left window, right window) keep the
/// boundary case simple.
fn digit_density(data: &[u8], start: usize, end: usize) -> f32 {
    let lo = start.saturating_sub(DENSITY_WINDOW);
    let hi = end.saturating_add(DENSITY_WINDOW).min(data.len());
    let left = &data[lo..start];
    let right = &data[end..hi];
    let total = left.len() + right.len();
    if total == 0 {
        return 0.0;
    }
    let count = left.iter().filter(|&&b| is_digit(b)).count()
        + right.iter().filter(|&&b| is_digit(b)).count();
    count as f32 / total as f32
}

/// Shannon entropy (bits/byte) of the surrounding window, including the
/// candidate. Range:
///
/// - ASCII prose: 4.0 – 5.0
/// - Hex / base64: 4.0 – 6.0
/// - Compressed / encrypted / pixel data: 7.5 – 8.0
///
/// The candidate itself is included because excluding it would underestimate
/// the entropy of binary blobs whose ASCII-digit run is the only "text-
/// ish" stretch in 256 bytes of noise.
fn entropy(data: &[u8], start: usize, end: usize) -> f32 {
    let lo = start.saturating_sub(ENTROPY_WINDOW);
    let hi = end.saturating_add(ENTROPY_WINDOW).min(data.len());
    let window = &data[lo..hi];
    if window.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in window {
        counts[b as usize] += 1;
    }
    let n = window.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / n;
        h -= p * p.log2();
    }
    h
}

/// Minimum byte-distance from the candidate to any card-context keyword in
/// `KEYWORDS`. `None` means no keyword found in the window.
///
/// ASCII case is folded by lowercasing into a stack buffer; Hebrew bytes
/// (UTF-8 high-bit) pass through unchanged because the lookup table is
/// itself stored in normalized form.
fn keyword_distance(data: &[u8], start: usize, end: usize) -> Option<u16> {
    let lo = start.saturating_sub(KEYWORD_WINDOW);
    let hi = end.saturating_add(KEYWORD_WINDOW).min(data.len());
    let window = &data[lo..hi];

    // Lowercase the window. Bounded at 2 * KEYWORD_WINDOW + 16 (candidate
    // max length is 16). Stack alloc to keep this allocation-free in the
    // hot path.
    let mut buf = [0u8; 2 * KEYWORD_WINDOW + 32];
    let len = window.len().min(buf.len());
    for i in 0..len {
        buf[i] = window[i].to_ascii_lowercase();
    }
    let lower = &buf[..len];

    let cand_start_in_window = start - lo;
    let cand_end_in_window = end - lo;

    let mut min_dist: Option<usize> = None;
    for kw in KEYWORDS {
        let mut search_from = 0;
        while search_from + kw.len() <= lower.len() {
            let Some(rel) = subslice_find(&lower[search_from..], kw) else {
                break;
            };
            let abs = search_from + rel;
            let kw_end = abs + kw.len();
            // Distance from the keyword to the candidate's nearest edge,
            // zero if they overlap (keyword inside the candidate run — rare
            // but possible if a numeric ID is labelled with "pan").
            let d = if kw_end <= cand_start_in_window {
                cand_start_in_window - kw_end
            } else if abs >= cand_end_in_window {
                abs - cand_end_in_window
            } else {
                0
            };
            min_dist = Some(min_dist.map_or(d, |m| m.min(d)));
            if d == 0 {
                break; // Can't beat zero; stop scanning this keyword.
            }
            search_from = abs + 1;
        }
    }
    min_dist.map(|d| d.min(u16::MAX as usize) as u16)
}

/// Naïve `memmem` replacement: small needles (avg ~6 bytes) over a small
/// haystack (~512 bytes), <30 patterns total, so the constant-factor wins
/// over pulling in a multi-pattern matcher. Critical-path cost is bounded
/// at ~256k byte comparisons per file, only on candidates that survived
/// Luhn + BIN/length.
#[inline]
fn subslice_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Grouping pattern
// ---------------------------------------------------------------------------

/// Maximum 16 groups (every-digit obfuscation `4-1-1-1-...-1`) + the
/// contiguous-run case.
#[derive(Clone, Debug)]
struct Grouping {
    sizes: Vec<u8>,
    /// Set of separator characters used (may be empty for contiguous runs).
    /// Tracked as bytes; small fixed set so we don't allocate.
    sep: u8,
    mixed_sep: bool,
}

/// A grouping pattern is "card-shaped" if it matches a real card-formatting
/// convention. This is a positive description, not a filter for noise.
///
/// - Contiguous (1 group): always card-shaped.
/// - Every-digit obfuscation (all 1s): always card-shaped.
/// - Space-separated: only the three actual issued patterns — Visa/MC
///   `[4,4,4,4]`, Amex `[4,6,5]`, Diners `[4,6,4]`. STL/OBJ noise
///   (`[4,5,5]`, `[1,5,2,4,1,1]`, etc.) is by definition not card-shaped.
/// - Dash/dot: every group in 3..=6 digits. Looser because dash-typed PANs
///   appear in more variants.
/// - Mixed separators within a single run are never card-shaped (real
///   typed PANs use one separator throughout).
fn grouping_is_card_shaped(g: &Grouping) -> bool {
    if g.sizes.len() <= 1 {
        return true;
    }
    if g.mixed_sep {
        return false;
    }
    if g.sizes.iter().all(|&s| s == 1) {
        return true;
    }
    match g.sep {
        b' ' => matches!(g.sizes.as_slice(), [4, 4, 4, 4] | [4, 6, 5] | [4, 6, 4]),
        b'-' | b'.' => g.sizes.iter().all(|&s| (3..=6).contains(&s)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Candidate emission (DETECT stage)
// ---------------------------------------------------------------------------
//
// Walks the buffer once. Yields every digit run of 14..=16 digits that:
//
//   - has valid boundaries on both sides
//   - has Luhn-valid digits
//
// Nothing else. Scheme, length-vs-scheme, density, entropy, keywords —
// all of that lives downstream in [`score`] + [`classify`]. This keeps the
// detect stage cheap, predictable, and easy to reason about: every survivor
// is "could plausibly be a PAN, decide downstream".

#[inline]
fn for_each_pan_candidate<F>(data: &[u8], mut f: F)
where
    F: FnMut(usize, &[u8], &Grouping) -> ControlFlow<()>,
{
    let n = data.len();
    let mut i = 0;
    loop {
        // SIMD skip to next digit.
        let Some(off) = find_first_digit(&data[i..]) else { return };
        i += off;
        let start = i;

        // Contiguous digit run starting here.
        let run_end = i + find_first_non_digit(&data[i..]).unwrap_or(n - i);
        let contig_len = run_end - i;

        // Contiguous run > 16 digits: too long, skip past it.
        if contig_len > 16 {
            i = run_end;
            continue;
        }

        let mut buf = [0u8; 17];
        buf[..contig_len].copy_from_slice(&data[i..run_end]);
        let mut count = contig_len;
        i = run_end;

        let mut sizes: Vec<u8> = Vec::with_capacity(17);
        sizes.push(contig_len as u8);
        let mut sep: u8 = 0;
        let mut mixed_sep = false;

        // Try to bridge across single separators.
        while count <= 16 && i + 1 < n && is_separator(data[i]) && is_digit(data[i + 1]) {
            let s = data[i];
            if sep == 0 {
                sep = s;
            } else if sep != s {
                mixed_sep = true;
            }
            i += 1;
            let next_end = i + find_first_non_digit(&data[i..]).unwrap_or(n - i);
            let next_len = next_end - i;
            if count + next_len > 16 {
                // Would overflow the 16-digit cap. Stop bridging; do NOT
                // emit — overflow shape is not a PAN.
                count += next_len;
                i = next_end;
                break;
            }
            buf[count..count + next_len].copy_from_slice(&data[i..next_end]);
            count += next_len;
            i = next_end;
            sizes.push(next_len as u8);
        }

        if !(14..=16).contains(&count) {
            continue;
        }
        if !is_left_boundary(data, start) || !is_right_boundary(data, i) {
            continue;
        }
        if !luhn_ok(&buf[..count]) {
            continue;
        }

        let grouping = Grouping { sizes, sep, mixed_sep };
        if f(start, &buf[..count], &grouping).is_break() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Luhn
// ---------------------------------------------------------------------------

#[inline]
fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum: u32 = 0;
    let n = digits.len();
    for i in 0..n {
        let mut d = (digits[n - 1 - i] - b'0') as u32;
        if i & 1 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

// ---------------------------------------------------------------------------
// Scheme detection (BIN + LENGTH)
// ---------------------------------------------------------------------------
//
// The fix that the previous code was missing: real card schemes issue at
// specific lengths-for-BIN. A 14-digit run starting with `4` is not a Visa.
// A 16-digit run starting with `34` is not an Amex. Pairing the BIN table
// with a length check kills the largest single class of coincidental-Luhn
// FPs without any context heuristics — many of the rejections previously
// achieved by `looks_like_url_token` and friends are subsumed.
//
// Note: rare lengths are intentionally NOT recognized:
//   - 13-digit Visa (legacy, mostly retired)
//   - 19-digit Visa / Discover / JCB (some co-branded / commercial)
//   - Discover / UnionPay / Maestro 2-series (out of scope per original
//     comment; raise FP rate too much in the target environment).
// Scanning is fixed at 14..=16 digits anyway, so we never see 13 or 19.

/// Returns the scheme if both the BIN prefix and the digit length match a
/// known issuance pattern. `None` otherwise.
#[inline]
fn detect_scheme(pan: &[u8]) -> Option<Scheme> {
    let len = pan.len();
    let p1 = *pan.first()?;
    let p2 = pan.get(1).copied();
    let p3 = pan.get(2).copied();
    let p4 = pan.get(3).copied();

    match p1 {
        b'4' => (len == 16).then_some(Scheme::Visa),
        b'5' => (len == 16 && matches!(p2, Some(b'1'..=b'5'))).then_some(Scheme::Mastercard),
        b'3' => match p2? {
            // Amex: 34, 37 → 15 digits only.
            b'4' | b'7' => (len == 15).then_some(Scheme::Amex),
            // JCB: 3528-3589 → 16 digits.
            b'5' => {
                if len != 16 {
                    return None;
                }
                match p3? {
                    b'3'..=b'8' => Some(Scheme::Jcb),
                    b'2' => matches!(p4, Some(b'8' | b'9')).then_some(Scheme::Jcb),
                    _ => None,
                }
            }
            // Diners: 300-305, 3095, 36, 38, 39 → 14 or 16 digits.
            b'0' => {
                if !matches!(len, 14 | 16) {
                    return None;
                }
                match p3? {
                    b'0'..=b'5' => Some(Scheme::Diners),
                    b'9' => (p4 == Some(b'5')).then_some(Scheme::Diners),
                    _ => None,
                }
            }
            b'6' | b'8' | b'9' => matches!(len, 14 | 16).then_some(Scheme::Diners),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SCORE + CLASSIFY
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PanSignals {
    scheme: Option<Scheme>,
    digit_density: f32,
    entropy: f32,
    keyword_distance: Option<u16>,
    grouping_card_shaped: bool,
}

fn score(data: &[u8], start: usize, end: usize, pan: &[u8], grouping: &Grouping) -> PanSignals {
    PanSignals {
        scheme: detect_scheme(pan),
        digit_density: digit_density(data, start, end),
        entropy: entropy(data, start, end),
        keyword_distance: keyword_distance(data, start, end),
        grouping_card_shaped: grouping_is_card_shaped(grouping),
    }
}

#[derive(Debug)]
enum Decision {
    Reject(&'static str),
    Accept(Confidence),
}

/// Hard rejects first (provably non-PAN properties), then tier the survivor
/// by keyword presence — the strongest single signal distinguishing "labeled
/// card number" from "coincidental Luhn-valid digit string in similar-
/// looking surroundings."
///
/// The tiering is intentionally simple:
///
///   - keyword within KEYWORD_HIGH_DIST   →  High
///   - keyword within KEYWORD_WINDOW       →  Medium
///   - no keyword                          →  Low
///
/// Capped at Medium when scheme/length doesn't match a known issuance —
/// even with a card label nearby, an unknown-BIN Luhn-valid number is at
/// best "labeled candidate", not "labeled card".
///
/// Density and entropy do NOT feed the tier; they only hard-reject. This
/// avoids the trap of letting "looks-like text" upgrade unlabeled URL
/// tokens (Yahoo CID, tracking IDs) into Medium just because the
/// surrounding HTML is well-mixed ASCII.
///
/// Strict-mode policy: `strict` hard-rejects unscheme'd candidates outright.
/// Non-strict keeps them but caps at Medium.
fn classify(s: &PanSignals, strict: bool) -> Decision {
    if !s.grouping_card_shaped {
        return Decision::Reject("grouping pattern not card-shaped");
    }
    if s.entropy > ENTROPY_HARD_MAX {
        return Decision::Reject("high-entropy surround (binary blob)");
    }
    if s.digit_density > DENSITY_HARD_MAX {
        return Decision::Reject("dense-numeric surround (not a PAN context)");
    }
    if strict && s.scheme.is_none() {
        return Decision::Reject("BIN/length doesn't match any known scheme");
    }

    let tier = match s.keyword_distance {
        Some(d) if d <= KEYWORD_HIGH_DIST => Confidence::High,
        Some(_) => Confidence::Medium,
        None => Confidence::Low,
    };
    let cap = if s.scheme.is_some() {
        Confidence::High
    } else {
        Confidence::Medium
    };
    Decision::Accept(tier.min(cap))
}

// ---------------------------------------------------------------------------
// Per-file dedup
// ---------------------------------------------------------------------------

#[inline]
fn pan_key(pan: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[..pan.len()].copy_from_slice(pan);
    k
}

struct DedupSet {
    keys: Vec<[u8; 16]>,
}

impl DedupSet {
    fn new() -> Self {
        Self { keys: Vec::new() }
    }
    /// Returns true if `key` is new (and inserts it).
    #[inline]
    fn insert(&mut self, key: [u8; 16]) -> bool {
        if self.keys.iter().any(|k| k == &key) {
            return false;
        }
        self.keys.push(key);
        true
    }
}

// ---------------------------------------------------------------------------
// find_pans: single-pass enumeration of every valid PAN in a buffer
// ---------------------------------------------------------------------------

fn find_pans(data: &[u8], opts: &ScanOpts) -> Vec<Hit> {
    let mut seen = DedupSet::new();
    let mut hits: Vec<Hit> = Vec::new();

    for_each_pan_candidate(data, |off, pan, grouping| {
        // Source-span end: packed digit count + separators between groups.
        // pan.len() is the digit count (14-16); grouping.sizes.len() - 1 is
        // the number of bridged separators (0 for a contiguous run).
        let span_end = off + pan.len() + grouping.sizes.len().saturating_sub(1);

        let signals = score(data, off, span_end, pan, grouping);
        let decision = classify(&signals, opts.strict);

        match decision {
            Decision::Reject(reason) => {
                if opts.debug {
                    eprintln!(
                        "[DEBUG-REJECT] offset={} pan={} reason={} density={:.2} entropy={:.2} kwdist={:?}",
                        off,
                        std::str::from_utf8(pan).unwrap_or("?"),
                        reason,
                        signals.digit_density,
                        signals.entropy,
                        signals.keyword_distance,
                    );
                }
            }
            Decision::Accept(conf) => {
                if conf < opts.min_confidence {
                    return ControlFlow::Continue(());
                }
                if seen.insert(pan_key(pan)) {
                    hits.push(Hit {
                        offset: off,
                        pan: pan.to_vec(),
                        scheme: signals.scheme,
                        confidence: conf,
                    });
                }
            }
        }
        ControlFlow::Continue(())
    });

    hits
}

// ---------------------------------------------------------------------------
// File I/O - mmap (large) or Vec (small)
// ---------------------------------------------------------------------------

enum FileData {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl FileData {
    fn as_slice(&self) -> &[u8] {
        match self {
            FileData::Mapped(m) => &m[..],
            FileData::Owned(v) => v.as_slice(),
        }
    }
}

fn read_file(path: &Path, max_bytes: u64) -> Option<FileData> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let size = meta.len();
    if size == 0 || size > max_bytes {
        return None;
    }
    if size > 1024 * 1024 {
        let mmap = unsafe { Mmap::map(&file).ok()? };
        #[cfg(unix)]
        let _ = mmap.advise(memmap2::Advice::Sequential);
        Some(FileData::Mapped(mmap))
    } else {
        let mut buf = Vec::with_capacity(size as usize);
        let mut f = file;
        f.read_to_end(&mut buf).ok()?;
        Some(FileData::Owned(buf))
    }
}

fn scan_file_deep(path: &Path, opts: &ScanOpts) -> Vec<Hit> {
    let Some(data) = read_file(path, opts.max_bytes) else { return Vec::new() };
    find_pans(data.as_slice(), opts)
}

// ---------------------------------------------------------------------------
// OS detection: admin check, targets, skip paths
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn is_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_admin() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

#[cfg(target_os = "macos")]
fn os_targets(mode: Mode) -> Vec<PathBuf> {
    match mode {
        Mode::Quick => ["/Users", "/var/log", "/Library/Logs", "/tmp",
                        "/var/tmp", "/Users/Shared"]
            .iter().map(PathBuf::from).collect(),
        Mode::Complete => {
            let mut t: Vec<PathBuf> = vec![PathBuf::from("/")];
            if let Ok(entries) = std::fs::read_dir("/Volumes") {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir()
                        && !p.file_name().and_then(|n| n.to_str())
                            .map(|n| n.starts_with('.'))
                            .unwrap_or(true)
                    {
                        t.push(p);
                    }
                }
            }
            t
        }
    }
}

#[cfg(target_os = "macos")]
fn os_skip_paths() -> Vec<PathBuf> {
    ["/System", "/dev", "/.fseventsd", "/.Spotlight-V100",
     "/.DocumentRevisions-V100", "/.TemporaryItems",
     "/private/var/db/dyld", "/private/var/vm",
     "/Library/Caches/com.apple.dyld"]
        .iter().map(PathBuf::from).collect()
}

#[cfg(target_os = "linux")]
fn os_targets(mode: Mode) -> Vec<PathBuf> {
    match mode {
        Mode::Quick => ["/home", "/root", "/var/log", "/tmp", "/var/tmp",
                        "/var/spool/mail", "/var/mail", "/var/www"]
            .iter().map(PathBuf::from).filter(|p| p.exists()).collect(),
        Mode::Complete => vec![PathBuf::from("/")],
    }
}

#[cfg(target_os = "linux")]
fn os_skip_paths() -> Vec<PathBuf> {
    ["/proc", "/sys", "/dev", "/run",
     "/var/lib/docker", "/var/lib/containerd", "/var/lib/lxcfs",
     "/snap", "/var/snap", "/var/cache", "/.snapshots",
     "/swap.img", "/swapfile"]
        .iter().map(PathBuf::from).collect()
}

#[cfg(target_os = "windows")]
fn os_targets(mode: Mode) -> Vec<PathBuf> {
    match mode {
        Mode::Quick => {
            let sd = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
            let base = format!("{}\\", sd);
            ["Users", "Windows\\Logs", "Windows\\Panther", "Windows\\Temp",
             "ProgramData", "inetpub\\logs"]
                .iter()
                .map(|p| PathBuf::from(&base).join(p))
                .filter(|p| p.exists())
                .collect()
        }
        Mode::Complete => {
            let mut drives = Vec::new();
            for letter in b'A'..=b'Z' {
                let p = PathBuf::from(format!("{}:\\", letter as char));
                if p.exists() {
                    drives.push(p);
                }
            }
            drives
        }
    }
}

#[cfg(target_os = "windows")]
fn os_skip_paths() -> Vec<PathBuf> {
    let sr = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let sd = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\";
    [
        format!(r"{}\WinSxS", sr),
        format!(r"{}\Installer", sr),
        format!(r"{}\Servicing", sr),
        format!(r"{}\System32\DriverStore", sr),
        format!(r"{}\System32\config", sr),
        format!(r"{}\assembly", sr),
        format!(r"{}$Recycle.Bin", sd),
        format!(r"{}System Volume Information", sd),
        format!(r"{}hiberfil.sys", sd),
        format!(r"{}pagefile.sys", sd),
        format!(r"{}swapfile.sys", sd),
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// Directory names to skip wholesale. This is a PERFORMANCE optimization
/// (build artifacts, package caches, VCS metadata, IDE state — all noisy,
/// none should plausibly contain a typed PAN), not an FP filter. Kept
/// because it's principled: these are categorically not user-data
/// directories.
const NAME_SKIP: &[&str] = &[
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    "target", ".gradle", ".m2", "Pods",
];

// Note: the previous `EXT_SKIP` list (.insp, .insv, .lrv) is intentionally
// removed. Those formats were being skipped because their pixel-delta
// payloads produced FPs — a structural problem now handled by the entropy
// signal in `classify`, generically, without per-extension code.

fn normalize(p: &Path) -> String {
    #[cfg(windows)]
    {
        p.to_string_lossy().to_lowercase()
    }
    #[cfg(not(windows))]
    {
        p.to_string_lossy().into_owned()
    }
}

// ---------------------------------------------------------------------------
// Single-pass parallel scan: walk + deep-scan each file inline
// ---------------------------------------------------------------------------

fn scan_all(
    targets: &[PathBuf],
    skip_paths: Vec<PathBuf>,
    threads: usize,
    opts: &ScanOpts,
    interrupted: &Arc<AtomicBool>,
    progress: &ScanProgress,
    events_tx: Sender<FileHits>,
) {
    use std::collections::HashSet;
    let skip_set: HashSet<String> = skip_paths.iter().map(|p| normalize(p)).collect();
    let skip_set = Arc::new(skip_set);
    let name_set: HashSet<&'static str> = NAME_SKIP.iter().copied().collect();
    let name_set = Arc::new(name_set);

    if targets.is_empty() {
        return;
    }

    let mut wb = WalkBuilder::new(&targets[0]);
    for t in &targets[1..] {
        wb.add(t);
    }
    wb.standard_filters(false)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .threads(if threads == 0 {
            num_cpus().min(64)
        } else {
            threads
        })
        .filter_entry({
            let skip = Arc::clone(&skip_set);
            let names = Arc::clone(&name_set);
            move |entry| {
                // User-specified roots (depth 0) bypass skip filters.
                if entry.depth() == 0 {
                    return true;
                }
                let path = entry.path();
                if skip.contains(&normalize(path)) {
                    return false;
                }
                if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
                    if names.contains(n) {
                        return false;
                    }
                }
                true
            }
        });

    let walker = wb.build_parallel();
    walker.run(|| {
        let files_scanned = Arc::clone(&progress.files_scanned);
        let files_with_hits = Arc::clone(&progress.files_with_hits);
        let tx = events_tx.clone();
        let opts = opts.clone();
        let interrupted = Arc::clone(interrupted);
        Box::new(move |entry| {
            if interrupted.load(Ordering::Relaxed) {
                return WalkState::Quit;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => return WalkState::Continue,
            };
            if entry.path_is_symlink() {
                return WalkState::Continue;
            }
            let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
            if !is_file {
                return WalkState::Continue;
            }
            files_scanned.fetch_add(1, Ordering::Relaxed);
            let mut hits = scan_file_deep(entry.path(), &opts);
            if !hits.is_empty() {
                hits.sort_by_key(|h| h.offset);
                if opts.debug {
                    use std::fmt::Write;
                    let mut msg = String::with_capacity(64 + hits.len() * 64);
                    let _ = writeln!(
                        msg,
                        "[DEBUG] {}: {} PAN(s)",
                        entry.path().display(),
                        hits.len()
                    );
                    for h in &hits {
                        let pan_str = std::str::from_utf8(&h.pan).unwrap_or("?");
                        let scheme = h.scheme.map(|s| s.name()).unwrap_or("?");
                        let _ = writeln!(
                            msg,
                            "  offset={:<10} scheme={:<10} conf={:<6} pan={}",
                            h.offset,
                            scheme,
                            h.confidence.name(),
                            pan_str
                        );
                    }
                    eprint!("{}", msg);
                }
                files_with_hits.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send(FileHits {
                    path: entry.path().to_path_buf(),
                    hits,
                });
            }
            WalkState::Continue
        })
    });
}

fn dedup_files(files: &mut Vec<FileHits>) {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
}

fn human_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{}k", n / 1000)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn mask_pan(pan: &[u8]) -> String {
    let s = std::str::from_utf8(pan).unwrap_or("");
    if s.len() < 10 {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..6]);
    for _ in 0..(s.len() - 10) {
        out.push('*');
    }
    out.push_str(&s[s.len() - 4..]);
    out
}

fn write_csv(path: &Path, files: &[FileHits], unmask: bool) -> io::Result<(usize, usize)> {
    use std::cmp::Reverse;
    use std::fs::OpenOptions;

    // Refuse to write through a symlink at the final path component. panscan
    // requires root, and the default output name is a second-resolution
    // timestamp in CWD, so a local non-root attacker on a multi-user box could
    // otherwise pre-plant a symlink and have us truncate /etc/passwd or
    // /etc/sudoers as root. O_NOFOLLOW on the open is atomic; the Windows
    // symlink_metadata check has a TOCTOU window but creating Windows symlinks
    // requires admin or developer mode, narrowing the practical risk.
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to write CSV through a symlink",
                ));
            }
        }
    }
    let file = opts.open(path)?;
    let mut w = csv::Writer::from_writer(file);
    w.write_record(["location", "offset", "scheme", "confidence", "pan"])?;

    // Flatten + sort: confidence DESC, then path ASC, then offset ASC. High-
    // confidence findings land at the top of the CSV so a reviewer triages
    // strongest-evidence rows first. Within a tier, results group by file.
    let mut rows: Vec<(&Path, &Hit)> = files
        .iter()
        .flat_map(|fh| fh.hits.iter().map(move |h| (fh.path.as_path(), h)))
        .collect();
    rows.sort_by(|(pa, ha), (pb, hb)| {
        Reverse(ha.confidence)
            .cmp(&Reverse(hb.confidence))
            .then_with(|| pa.cmp(pb))
            .then_with(|| ha.offset.cmp(&hb.offset))
    });

    let mut total = 0;
    for (loc_path, h) in &rows {
        let loc = loc_path.to_string_lossy();
        let pan_str = if unmask {
            String::from_utf8_lossy(&h.pan).into_owned()
        } else {
            mask_pan(&h.pan)
        };
        let scheme = h.scheme.map(|s| s.name()).unwrap_or("?");
        w.write_record([
            loc.as_ref(),
            &h.offset.to_string(),
            scheme,
            h.confidence.name(),
            &pan_str,
        ])?;
        total += 1;
    }
    w.flush()?;
    Ok((files.len(), total))
}

fn default_csv_path() -> PathBuf {
    let now = chrono::Local::now();
    PathBuf::from(format!(
        "panfind-{}.csv",
        now.format("%Y-%m-%d-%H%M%S")
    ))
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "panscan", version, about, long_about = None)]
struct Args {
    /// Custom path to scan (overrides --mode)
    path: Option<PathBuf>,

    /// OS-aware preset: quick = user folders + logs; complete = whole disk
    #[arg(long, value_enum)]
    mode: Option<Mode>,

    /// Worker threads (0 = auto)
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// Emit Luhn-valid runs whose BIN/length doesn't match a known scheme.
    /// Such hits are reported at low confidence — useful for catching
    /// non-major schemes (UnionPay, Maestro 2-series, regional cards).
    #[arg(long)]
    no_strict: bool,

    /// Minimum confidence to emit. Default `medium` drops weakly-supported
    /// hits (no card keyword nearby, no recognized scheme). Use `low` to see
    /// every Luhn+boundary survivor, `high` for hits with a card keyword in
    /// the immediate vicinity.
    #[arg(long, value_enum, default_value_t = MinConfidence::Medium)]
    min_confidence: MinConfidence,

    /// Skip files larger than N MB
    #[arg(long, default_value_t = 500)]
    max_size: u64,

    /// CSV output path (default: panfind-<timestamp>.csv in cwd)
    #[arg(long)]
    csv: Option<PathBuf>,

    /// Write full PANs (default masks middle digits)
    #[arg(long)]
    unmask: bool,

    /// Print targets that would be scanned, then exit
    #[arg(long)]
    list_targets: bool,

    /// Verbose stderr output: prints accepted hits (path, offset, scheme,
    /// confidence, FULL unmasked PAN) and per-candidate rejection reasons
    /// with their signal values. Useful for tuning thresholds against a
    /// known corpus. Output is in PCI scope.
    #[arg(long)]
    debug: bool,
}

fn main() {
    let mut args = Args::parse();
    eprintln!("------------------------------");
    eprintln!("  /\\_/\\    PANscan v{}", env!("CARGO_PKG_VERSION"));
    eprintln!(" ( o.o )   Ram Prass");
    eprintln!("  > ^ <    CATSEC");
    eprintln!("------------------------------");
    eprintln!();

    if args.path.is_none() && args.mode.is_none() {
        args.mode = Some(Mode::Quick);
    }

    let (targets, skip_paths, label) = match (&args.path, args.mode) {
        (Some(p), None) => (
            vec![p.clone()],
            Vec::<PathBuf>::new(),
            format!("custom: {}", p.display()),
        ),
        (None, Some(m)) => {
            let label = format!("{:?} ({})", m, std::env::consts::OS);
            (os_targets(m), os_skip_paths(), label)
        }
        (Some(p), Some(m)) => {
            let mut t = os_targets(m);
            t.push(p.clone());
            let label = format!("{:?} ({}) + custom: {}", m, std::env::consts::OS, p.display());
            (t, os_skip_paths(), label)
        }
        (None, None) => unreachable!("set to Quick above"),
    };

    let admin = is_admin();
    eprintln!(
        "[+] OS: {}   Privileged: {}   Mode: {}",
        std::env::consts::OS,
        admin,
        label
    );

    if args.list_targets {
        println!("\nTargets to walk:");
        for t in &targets {
            let mark = if t.exists() { "OK" } else { "MISSING" };
            println!("  [{:7}] {}", mark, t.display());
        }
        println!("\nSkip absolute paths:");
        let mut sp: Vec<&PathBuf> = skip_paths.iter().collect();
        sp.sort();
        for p in sp {
            println!("  {}", p.display());
        }
        println!("\nSkip directory names (at any depth):");
        let mut ns: Vec<&&str> = NAME_SKIP.iter().collect();
        ns.sort();
        for n in ns {
            println!("  {}", n);
        }
        return;
    }

    if !admin {
        eprintln!();
        eprintln!("error: panscan requires elevated privileges.");
        eprintln!("       Re-run with sudo (Unix) or as Administrator (Windows).");
        eprintln!("       Use --list-targets to preview targets without scanning.");
        std::process::exit(1);
    }

    let strict = !args.no_strict;

    eprintln!(
        "[+] Targets: {}   Workers: {}   Strict: {}   Debug: {}",
        targets.len(),
        if args.threads == 0 { num_cpus() } else { args.threads },
        strict,
        args.debug
    );
    eprintln!(
        "[+] Min-confidence: {}",
        args.min_confidence.to_confidence().name()
    );
    if args.min_confidence != MinConfidence::Low {
        eprintln!(
            "    Re-run with --min-confidence low to see every Luhn+boundary survivor (more false positives)."
        );
    }
    if args.debug {
        eprintln!("[!] DEBUG: full unmasked PANs will be printed to stderr (PCI scope).");
    }

    let opts = ScanOpts {
        strict,
        max_bytes: args.max_size * 1024 * 1024,
        debug: args.debug,
        min_confidence: args.min_confidence.to_confidence(),
    };

    let csv_path = args.csv.clone().unwrap_or_else(default_csv_path);
    eprintln!(
        "[+] Output: {}",
        csv_path.canonicalize().unwrap_or(csv_path.clone()).display()
    );

    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&interrupted);
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
            eprintln!("\n[!] Interrupt received - finishing current pass...");
        })
        .ok();
    }

    eprintln!("\n[+] Scanning");
    let t0 = Instant::now();

    let progress = ScanProgress::new();
    let (tx, rx) = mpsc::channel::<FileHits>();

    let scan_done = Arc::new(AtomicBool::new(false));
    let progress_thread = {
        let progress = progress.clone();
        let done = Arc::clone(&scan_done);
        thread::spawn(move || {
            use std::io::Write;
            let mut last_milestone = 0;
            while !done.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(500));
                let n = progress.files_scanned.load(Ordering::Relaxed);
                let milestone = n / 10000;
                if milestone > last_milestone {
                    last_milestone = milestone;
                    // \r returns to column 0, \x1b[K clears to end of line —
                    // the line redraws in place instead of stacking.
                    eprint!(
                        "\r\x1b[K  scan: {} files scanned, {} with PANs",
                        human_count(n),
                        progress.files_with_hits.load(Ordering::Relaxed)
                    );
                    let _ = std::io::stderr().flush();
                }
            }
            // Terminate the in-place progress line so subsequent stderr
            // output ("Done", error messages, etc.) starts on a fresh line.
            if last_milestone > 0 {
                eprintln!();
            }
        })
    };

    let scan_thread = {
        let opts = opts.clone();
        let interrupted = Arc::clone(&interrupted);
        let progress = progress.clone();
        let threads = args.threads;
        thread::spawn(move || {
            scan_all(&targets, skip_paths, threads, &opts, &interrupted, &progress, tx);
        })
    };

    let mut files: Vec<FileHits> = Vec::new();
    while let Ok(fh) = rx.recv() {
        files.push(fh);
    }
    scan_thread.join().ok();
    scan_done.store(true, Ordering::Relaxed);
    progress_thread.join().ok();

    dedup_files(&mut files);
    let elapsed = t0.elapsed();
    let total_scanned = progress.files_scanned.load(Ordering::Relaxed);
    let pan_count: usize = files.iter().map(|f| f.hits.len()).sum();

    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for f in &files {
        for h in &f.hits {
            match h.confidence {
                Confidence::High => high += 1,
                Confidence::Medium => medium += 1,
                Confidence::Low => low += 1,
            }
        }
    }

    eprintln!(
        "[+] Done: {} files scanned, {} files with PANs, {} PANs total  (high={} medium={} low={})  ({:.1}s)",
        total_scanned,
        files.len(),
        pan_count,
        high,
        medium,
        low,
        elapsed.as_secs_f64()
    );

    if files.is_empty() {
        eprintln!("\n[+] No PANs found. No CSV written.");
        return;
    }

    match write_csv(&csv_path, &files, args.unmask) {
        Ok((n_files, n_pans)) => {
            eprintln!("\n[+] Results: {} PANs across {} files", n_pans, n_files);
            eprintln!("[+] Saved: {}", csv_path.display());
        }
        Err(e) => {
            eprintln!("[!] Failed to write CSV: {}", e);
            std::process::exit(1);
        }
    }
}
