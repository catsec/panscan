//! panscan: single-pass parallel PAN (Primary Account Number) scanner.
//!
//! Walks the target tree in parallel via ignore's worker pool, deep-scans each
//! file inline (collecting every Luhn-valid 14-16 digit run with byte offset),
//! and streams `FileHits` over an `mpsc::Sender` so the CLI can render live
//! progress. SIMD candidate scanner, structured BIN/Luhn filter, per-file dedup.

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
// Public types
// ---------------------------------------------------------------------------

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Quick,
    Complete,
}

#[derive(Clone, Debug)]
struct ScanOpts {
    strict: bool,
    max_bytes: u64,
    debug: bool,
}

#[derive(Clone, Debug)]
struct FileHits {
    path: PathBuf,
    hits: Vec<(usize, Vec<u8>)>,
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
// PAN candidate scanner (separator-aware)
// ---------------------------------------------------------------------------
//
// Walks maximal `digit (sep? digit)*` runs and yields candidates with exactly
// 14..=16 digits. Separators are `-`, ` `, `.` (the typical hand-typed groupings:
// `4111-1111-1111-1111`, `4111 1111 1111 1111`, `4111.1111.1111.1111`, plus
// irregular and dash-every-digit obfuscation). Only ONE separator is consumed
// between two digits — `4111--1111` doesn't bridge, and trailing separators
// don't extend the run.
//
// The outer non-digit skip is the hot path on sparse content. The predicate
// `b.wrapping_sub(b'0') < 10` lets LLVM autovectorise it to pcmpgtb / cmhi.16b.

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

/// Heuristic: the candidate looks like a URL / mail-header token, not a
/// typed PAN. Common shapes:
///
/// - `cid:DIGITS@web…` — Yahoo Mail CID image references in HTML email
///   (digits framed by `:` immediately before and `@<alpha>` after).
/// - `key=DIGITS&amp;` / `…/DIGITS%2F…` — URL query / quoted-printable
///   parameters where the digits are an opaque identifier.
/// - Quoted-printable line continuation `=\nDIGITS…` immediately followed
///   by URL-encoding `%XX`.
///
/// Rule: if the byte immediately following the candidate is `@`, `&`, `%`,
/// `?`, or `=` AND the next byte is alphanumeric, reject. Also: if the byte
/// immediately preceding is `:` and the byte before that is alphanumeric
/// (e.g. `cid:`), reject. Real typed PANs are framed by whitespace, quotes,
/// `,`, `\n`, etc. — never by URL/email tokenization punctuation followed
/// by a continuation letter.
#[inline]
fn looks_like_url_token(data: &[u8], start: usize, end: usize) -> bool {
    if end + 1 < data.len() {
        let trailer = data[end];
        let next = data[end + 1];
        if matches!(trailer, b'@' | b'&' | b'%' | b'?' | b'=')
            && next.is_ascii_alphanumeric()
        {
            return true;
        }
    }
    // Preceded by `%` — the first two digits of our candidate are the hex
    // payload of a URL escape (`%40DIGITS…` = `@DIGITS…`). Common in Yahoo
    // CID URLs that have been URL-encoded inside email HTML.
    if start >= 1 && data[start - 1] == b'%' {
        return true;
    }
    if start >= 2 && data[start - 1] == b':' && data[start - 2].is_ascii_alphanumeric() {
        return true;
    }
    false
}

/// Heuristic: a candidate inside a binary blob (Insta360 `.insp`, `.lrv`,
/// `.psd` thumbnails) is surrounded by two telltale signals:
///
/// 1. **Bare UTF-8 continuations** — runs of `0x80..=0xBF` with no preceding
///    start byte. Real text, even Hebrew-heavy iMessage records, only has
///    continuation bytes after a valid 2/3/4-byte start. Reject at >4.
/// 2. **Dense ASCII control bytes** — Insta360 thumbnails are pixel deltas
///    that hover in `0x00..=0x1F`. SQLite/PDF have a handful of control
///    bytes from record framing, so the threshold has to clear that.
///    Reject at >14 strict controls in the window.
///
/// `0x09 / 0x0A / 0x0D` (tab/LF/CR) are whitespace and excluded from the
/// control count. Window is ±32 bytes; early-exits on first overage.
#[inline]
fn context_is_textish(data: &[u8], start: usize, end: usize) -> bool {
    let lo = start.saturating_sub(32);
    let hi = end.saturating_add(32).min(data.len());
    let mut bare_cont = 0u32;
    let mut strict_ctrl = 0u32;
    let mut expect: u8 = 0;
    for &b in &data[lo..hi] {
        match b {
            0x09 | 0x0A | 0x0D => expect = 0,
            0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F => {
                strict_ctrl += 1;
                if strict_ctrl > 14 {
                    return false;
                }
                expect = 0;
            }
            0x80..=0xBF => {
                if expect == 0 {
                    bare_cont += 1;
                    if bare_cont > 4 {
                        return false;
                    }
                } else {
                    expect -= 1;
                }
            }
            0xC2..=0xDF => expect = 1,
            0xE0..=0xEF => expect = 2,
            0xF0..=0xF4 => expect = 3,
            0xC0 | 0xC1 | 0xF5..=0xFF => {
                bare_cont += 1;
                if bare_cont > 4 {
                    return false;
                }
                expect = 0;
            }
            _ => expect = 0,
        }
    }
    true
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
            let mask = vcltq_u8(diff, ten);     // 0xFF where digit, 0x00 else
            // NEON movemask substitute: `vshrn_n_u16(mask, 4)` packs each
            // pair of byte-mask lanes into one nibble pair (high nibble =
            // high byte's bits, low nibble = low byte's). The resulting u64
            // has a nonzero nibble exactly where the source byte matched;
            // `trailing_zeros() / 4` == first matching byte index. One pop
            // beats a 16-iter scalar confirm loop.
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
            // Invert so 0xFF marks non-digits, then apply the same narrow-
            // by-4 movemask substitute as `find_first_digit`.
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
        // Signed compare: bytes 0x30..=0x39 are in the safe positive range,
        // and bytes >= 0x80 (non-ASCII) are signed-negative so excluded.
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
            // bits has a 1 for every digit byte. Find first 0 in low 16 bits.
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

/// Yield every maximal `digit (sep? digit)*` run whose digit count is 14..=16.
/// Digits are packed into a stack buffer; the offset is the position of the
/// first digit in `data`. Callback returns `Break` to stop early.
///
/// Two-level SIMD: outer skip finds the next digit byte; inner scan finds
/// the end of each contiguous digit run. Only the separator-bridge logic is
/// scalar (rare path, complex branching).
/// A separator-bridged run only counts as a PAN candidate if the chunks look
/// like a real card grouping. Typical real-world groupings: 4-4-4-4 (16
/// digits), 4-6-5 (Amex, 15 digits), 4-4-4-2 / 4-6-4 (old Diners, 14
/// digits), or 1-1-1-... (dash-every-digit obfuscation). Anything else is
/// float / coordinate / version-string noise — STL alone produced ~20k FPs
/// because vertex coordinates like `vertex 5.50684 61.1543 0.5` bridged
/// across space + dot.
///
/// Rule: if there are any separators, they must be the same character. Then:
///
/// - All-1s groups are always allowed (every-digit obfuscation).
/// - For space separators, only the exact issued-card patterns count:
///   `[4,4,4,4]` (Visa/MC 16), `[4,6,5]` (Amex 15), `[4,6,4]` (Diners 14).
///   Anything else (OBJ face indices `f 3666 88669 88670` → [4,5,5], STL
///   vertex tuples) is rejected. Hand-typed spaced PANs always use one of
///   these three patterns.
/// - For dash/dot separators, every group must be in 3..=6 digits — looser
///   because dash-typed PANs come in more variants (1-1-1-... obfuscation,
///   3-digit chunks in some manual layouts).
#[inline]
fn group_pattern_ok(group_sizes: &[u8], sep_chars: &[u8]) -> bool {
    if group_sizes.len() <= 1 {
        return true; // contiguous run, no separator constraints apply
    }
    // Uniform separator character.
    let first = sep_chars[0];
    if sep_chars.iter().any(|&s| s != first) {
        return false;
    }
    // Obfuscation: every group is exactly one digit.
    if group_sizes.iter().all(|&g| g == 1) {
        return true;
    }
    if first == b' ' {
        return matches!(
            group_sizes,
            [4, 4, 4, 4] | [4, 6, 5] | [4, 6, 4]
        );
    }
    group_sizes.iter().all(|&g| (3..=6).contains(&g))
}

/// Yield every Luhn-valid (and BIN-valid, if `strict`) 14-16 digit candidate
/// in `data` to `f`. The FP-rejection layers run in this order:
///
/// 1. shape/length (14..=16 digits packed)
/// 2. boundary + numeric-chain-tail on both sides
/// 3. `group_pattern_ok` separator-aware whitelist
/// 4. `looks_like_url_token` URL/CID shape rejection
/// 5. **Luhn** (here, not in the callback — moved ahead so the expensive
///    `context_is_textish` only runs on the ~10% of candidates that pass)
/// 6. **BIN** (strict only — rejects ~85% of Luhn passes)
/// 7. `context_is_textish` ±32 byte binary-blob window check
///
/// Callers (`find_pans`) only need to dedup + collect.
#[inline]
fn for_each_pan_candidate<F>(data: &[u8], strict: bool, mut f: F)
where
    F: FnMut(usize, &[u8]) -> ControlFlow<()>,
{
    let n = data.len();
    let mut i = 0;
    loop {
        // (1) SIMD skip non-digit bytes.
        let Some(off) = find_first_digit(&data[i..]) else { return };
        i += off;
        let start = i;

        // (2) SIMD-find end of contiguous digit run starting at i.
        let run_end = i + find_first_non_digit(&data[i..]).unwrap_or(n - i);
        let contig_len = run_end - i;

        // Contiguous run > 16: too long to be a PAN, skip whole run.
        if contig_len > 16 {
            i = run_end;
            continue;
        }

        let mut buf = [0u8; 17];
        buf[..contig_len].copy_from_slice(&data[i..run_end]);
        let mut count = contig_len;
        i = run_end;

        // Track group sizes + separators for the pattern check below. The
        // 17/16 sizing covers the worst case of every-digit-separated runs
        // (16 single-digit groups + 15 separators between them).
        let mut group_sizes = [0u8; 17];
        let mut sep_chars = [0u8; 16];
        group_sizes[0] = contig_len as u8;
        let mut group_count = 1usize;

        // (3) Scalar: try to bridge across single separators to more digits.
        while count <= 16
            && i + 1 < n
            && is_separator(data[i])
            && is_digit(data[i + 1])
        {
            let sep = data[i];
            i += 1; // consume separator
            let next_end = i + find_first_non_digit(&data[i..]).unwrap_or(n - i);
            let next_len = next_end - i;
            if count + next_len > 16 {
                // Bridge would overflow the 16-digit cap. Mark as over-length
                // and stop — this run is not a valid PAN candidate.
                count += next_len;
                i = next_end;
                break;
            }
            buf[count..count + next_len].copy_from_slice(&data[i..next_end]);
            count += next_len;
            i = next_end;
            if group_count < group_sizes.len() {
                sep_chars[group_count - 1] = sep;
                group_sizes[group_count] = next_len as u8;
                group_count += 1;
            }
        }

        // Gate order is performance-tuned: cheap O(1) shape checks, then the
        // O(<17) pattern check, then Luhn (~10% pass rate, kills 90% of
        // candidates), then strict-mode BIN (~15% of Luhn passes survive),
        // and only THEN the ±80-byte `context_is_textish` window scan.
        let pattern_ok = group_pattern_ok(
            &group_sizes[..group_count],
            &sep_chars[..group_count.saturating_sub(1)],
        );
        if (14..=16).contains(&count)
            && is_left_boundary(data, start)
            && is_right_boundary(data, i)
            && pattern_ok
            && !looks_like_url_token(data, start, i)
            && luhn_ok(&buf[..count])
            && (!strict || has_valid_bin(&buf[..count]))
            && context_is_textish(data, start, i)
            && f(start, &buf[..count]).is_break()
        {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Luhn + BIN
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

/// Card-scheme BIN prefix table, expanded inline as a structured `match`.
/// First digit is restricted to 3/4/5 — Mastercard 2-series (post-2017 IINs)
/// and Discover (first digit 6) are intentionally excluded to keep the false
/// positive rate down in the target environment.
///
///   Visa:        4
///   Mastercard:  51-55
///   Amex:        34, 37
///   Diners/JCB:  300-305, 3095, 36, 38, 39, 3528-3529, 353-358
#[inline]
fn has_valid_bin(pan: &[u8]) -> bool {
    let p1 = pan.get(1);
    let p2 = pan.get(2);
    let p3 = pan.get(3);
    match pan.first() {
        Some(b'4') => true,
        Some(b'5') => matches!(p1, Some(b'1'..=b'5')),
        Some(b'3') => match p1 {
            Some(b'4' | b'7' | b'6' | b'8' | b'9') => true,
            Some(b'0') => match p2 {
                Some(b'0'..=b'5') => true,
                Some(b'9') => p3 == Some(&b'5'),
                _ => false,
            },
            Some(b'5') => match p2 {
                Some(b'3'..=b'8') => true,
                Some(b'2') => matches!(p3, Some(b'8' | b'9')),
                _ => false,
            },
            _ => false,
        },
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Dedup key — fixed-size, stack-resident
// ---------------------------------------------------------------------------

#[inline]
fn pan_key(pan: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[..pan.len()].copy_from_slice(pan);
    k
}

// ---------------------------------------------------------------------------
// find_pans: single-pass enumeration of every valid PAN in a buffer
// ---------------------------------------------------------------------------

/// Per-file dedup: linear scan over `Vec<[u8; 16]>`. For typical N (<100) this
/// beats hashing — 16-byte compares vectorize to a single SSE/NEON compare and
/// stay hot in L1.
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

fn find_pans(data: &[u8], opts: &ScanOpts) -> Vec<(usize, Vec<u8>)> {
    let mut seen = DedupSet::new();
    let mut hits: Vec<(usize, Vec<u8>)> = Vec::new();

    for_each_pan_candidate(data, opts.strict, |off, pan| {
        if seen.insert(pan_key(pan)) {
            hits.push((off, pan.to_vec()));
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
        // Hint the kernel that we'll read sequentially — kicks off aggressive
        // read-ahead so the scanner doesn't stall on demand-paged faults.
        // Unix only; Windows' file-mapping prefetch goes through different APIs
        // that aren't exposed by memmap2.
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

fn scan_file_deep(path: &Path, opts: &ScanOpts) -> Vec<(usize, Vec<u8>)> {
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

const NAME_SKIP: &[&str] = &[
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
    "target", ".gradle", ".m2", "Pods",
];

/// File extensions that are skipped wholesale. These are formats whose
/// payloads are dense numeric byte streams (pixel deltas, motion vectors,
/// audio samples) where ASCII digit-byte runs occur as raw data and produce
/// only false positives. Matched case-insensitively against the final `.ext`.
/// User-specified roots (depth 0) bypass this filter, so explicitly passing
/// a `.insp` file still scans it.
const EXT_SKIP: &[&str] = &[
    "insp",   // Insta360 photo
    "insv",   // Insta360 video
    "lrv",    // GoPro / Insta360 low-resolution proxy video
];

fn normalize(p: &Path) -> String {
    #[cfg(windows)]
    {
        // Case-insensitive on Windows
        p.to_string_lossy().to_lowercase()
    }
    #[cfg(not(windows))]
    {
        p.to_string_lossy().into_owned()
    }
}

/// Card scheme for debug output. Mirrors the [`has_valid_bin`] ranges; a
/// strict-mode hit always returns a real scheme name, a `--no-strict` hit
/// outside those ranges returns `"?"`.
fn pan_scheme(pan: &[u8]) -> &'static str {
    match pan.first() {
        Some(b'4') => "Visa",
        Some(b'5') => "Mastercard",
        Some(b'3') => match pan.get(1) {
            Some(b'4' | b'7') => "Amex",
            Some(b'5') => "JCB",
            Some(b'0' | b'6' | b'8' | b'9') => "Diners",
            _ => "3xxx",
        },
        Some(b'0'..=b'9') => "other",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Single-pass parallel scan: walk + deep-scan each file inline
// ---------------------------------------------------------------------------

/// Walk `targets` in parallel, deep-scan each file, and stream every file
/// that produced ≥1 valid PAN over `events_tx`. Updates `progress` counters
/// continuously; check `interrupted` to stop early. Returns when the walker
/// finishes — the channel closes naturally when this function's sender
/// (cloned into each worker) is dropped.
///
/// Caller is responsible for collecting results from the receiver and, if
/// targets overlap, calling [`dedup_files`] on the collected `Vec`.
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
    let ext_set: HashSet<&'static str> = EXT_SKIP.iter().copied().collect();
    let ext_set = Arc::new(ext_set);

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
            let exts = Arc::clone(&ext_set);
            move |entry| {
                // User-specified roots (depth 0) are exempt from skip filters.
                // Lets `panscan ./node_modules` or `panscan /System/foo --mode complete`
                // scan paths that would normally be excluded — the depth-0 exemption
                // applies regardless of where the path lives in the skip list.
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
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    // Lowercase a stack buffer to match `EXT_SKIP` case-insensitively
                    // (the list is lowercase). Most extensions are <= 8 bytes.
                    let mut buf = [0u8; 16];
                    if ext.len() <= buf.len() {
                        for (i, b) in ext.bytes().enumerate() {
                            buf[i] = b.to_ascii_lowercase();
                        }
                        if let Ok(lower) = std::str::from_utf8(&buf[..ext.len()]) {
                            if exts.contains(lower) {
                                return false;
                            }
                        }
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
                hits.sort_by_key(|(off, _)| *off);
                if opts.debug {
                    // Build one buffered string per file so concurrent worker
                    // threads emit atomically — eprint!'s lock is per-write,
                    // not per-line, so emitting line-by-line would interleave.
                    use std::fmt::Write;
                    let mut msg = String::with_capacity(64 + hits.len() * 64);
                    let _ = writeln!(
                        msg,
                        "[DEBUG] {}: {} PAN(s)",
                        entry.path().display(),
                        hits.len()
                    );
                    for (off, pan) in &hits {
                        let pan_str = std::str::from_utf8(pan).unwrap_or("?");
                        let _ = writeln!(
                            msg,
                            "  offset={:<10} scheme={:<10} pan={}",
                            off,
                            pan_scheme(pan),
                            pan_str
                        );
                    }
                    eprint!("{}", msg);
                }
                files_with_hits.fetch_add(1, Ordering::Relaxed);
                // Receiver dropped → caller bailed; let the walker wind down
                // naturally on its own interrupt check rather than panicking.
                let _ = tx.send(FileHits {
                    path: entry.path().to_path_buf(),
                    hits,
                });
            }
            WalkState::Continue
        })
    });
}

/// Overlapping targets (mode preset + user-specified path under one of the
/// mode roots) can scan the same file twice. Sort by path and dedup so the
/// caller sees each file once.
fn dedup_files(files: &mut Vec<FileHits>) {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
}

/// Compact thousands/millions formatter for progress output.
/// Examples: 999 -> "999", 1500 -> "1.5k", 25000 -> "25k", 1_500_000 -> "1.5M".
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
    let mut w = csv::Writer::from_path(path)?;
    w.write_record(["location", "offset", "pan"])?;
    let mut total = 0;
    for fh in files {
        let loc = fh.path.to_string_lossy();
        for (off, pan) in &fh.hits {
            let pan_str = if unmask {
                String::from_utf8_lossy(pan).into_owned()
            } else {
                mask_pan(pan)
            };
            w.write_record([loc.as_ref(), &off.to_string(), &pan_str])?;
            total += 1;
        }
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

    /// Emit all Luhn-valid 14-16 digit runs without filtering to known card-scheme BIN prefixes
    #[arg(long)]
    no_strict: bool,

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

    /// Verbose stderr output: for every file with hits, print path, offset,
    /// scheme, and the FULL unmasked PAN. Stderr only — CSV masking is
    /// unaffected. Intended for debugging false positives in a known corpus;
    /// the output is in PCI scope.
    #[arg(long)]
    debug: bool,
}

fn main() {
    let mut args = Args::parse();

    // No path and no mode → default to --mode quick.
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
    if args.debug {
        eprintln!("[!] DEBUG: full unmasked PANs will be printed to stderr (PCI scope).");
    }

    let opts = ScanOpts {
        strict,
        max_bytes: args.max_size * 1024 * 1024,
        debug: args.debug,
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

    // Periodic stderr progress every ~10k files.
    let scan_done = Arc::new(AtomicBool::new(false));
    let progress_thread = {
        let progress = progress.clone();
        let done = Arc::clone(&scan_done);
        thread::spawn(move || {
            let mut last_milestone = 0;
            while !done.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(500));
                let n = progress.files_scanned.load(Ordering::Relaxed);
                let milestone = n / 10000;
                if milestone > last_milestone {
                    last_milestone = milestone;
                    eprintln!(
                        "  scan: {} files scanned, {} with PANs",
                        human_count(n),
                        progress.files_with_hits.load(Ordering::Relaxed)
                    );
                }
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
    eprintln!(
        "[+] Done: {} files scanned, {} files with PANs, {} PANs total  ({:.1}s)",
        total_scanned,
        files.len(),
        pan_count,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn opts_default() -> ScanOpts {
        ScanOpts {
            strict: false,
            max_bytes: u64::MAX,
            debug: false,
        }
    }

    #[test]
    fn luhn_vectors() {
        assert!(luhn_ok(b"4111111111111111"));
        assert!(luhn_ok(b"5555555555554444"));
        assert!(luhn_ok(b"378282246310005")); // 15-digit Amex
        assert!(!luhn_ok(b"4111111111111112"));
    }

    #[test]
    fn finds_visa_in_text() {
        let data = b"contact us: 4111111111111111 (sample card)";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 12);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn rejects_too_short_and_too_long_runs() {
        // 13 digits (too short), then 17 (too long — would yield no maximal run of 14-16)
        let data = b"4111111111111 41111111111111110";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn dedup_within_file() {
        let data = b"4111111111111111 stuff 4111111111111111 more";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn at_buffer_edges() {
        // PAN at the very start, and at the very end
        let data = b"4111111111111111";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0);
    }

    #[test]
    fn dash_separated_4_4_4_4() {
        let data = b"call 4111-1111-1111-1111 today";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
        assert_eq!(hits[0].0, 5); // offset of first digit
    }

    #[test]
    fn space_separated_4_4_4_4() {
        let data = b"PAN: 4111 1111 1111 1111 thanks";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn dot_separated_4_4_4_4() {
        let data = b"copy 4111.1111.1111.1111 here";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn mixed_separators_rejected() {
        // Mixed `-` and ` ` and `.` in the same run is float/coordinate noise,
        // not a hand-typed PAN. Big FP source on STL/CSV/log content; rejecting
        // it costs nothing in practice because real typed PANs use one
        // separator throughout.
        let data = b"weird 4111-1111 1111.1111 typing";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn stl_vertex_coordinates_rejected() {
        // The single biggest false-positive source: ASCII STL vertex lines.
        // `vertex 5.50684 61.1543 0.5` has group pattern [1, 5, 2, 4, 1, 1]
        // — wildly inconsistent and mixed separators.
        let data = b"  vertex 5.50684 61.1543 0.5\n";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn stl_float_tail_rejected() {
        // STL float `19.47879981994629`: bridge tries `19` + 14 digits, fails
        // pattern (2 < min). Outer loop advances and re-finds the 14-digit run
        // standalone — its preceding byte is `.`, which is_pan_boundary alone
        // accepts, but the byte before that is a digit. Reject as a numeric-
        // chain tail.
        let data = b"  vertex -52.68 19.47879981994629\n";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn space_bridged_three_digit_groups_rejected() {
        // `123 456 789 012 345 6` would Luhn-check by accident on real STL.
        // Space-separated PANs in the wild are 4-digit groups; 3-digit space
        // groups are float-column / numeric-tuple noise. Rule: space sep
        // requires every group >= 4 digits.
        let data = b"x 411 111 111 111 1111 y";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn obj_face_indices_rejected() {
        // Wavefront OBJ face records: `f 3666 88669 88670` — group widths
        // [4,5,5] (or [5,5,4], [5,4,5]). No real card-spacing pattern has a
        // 5-digit group; only [4,4,4,4], [4,6,5], [4,6,4] are valid for
        // space-bridged PANs.
        let data = b"f 3666 88669 88670\nf 49124 88789 88790\n";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn binary_blob_digit_run_rejected() {
        // Insta360 .insp pattern: digit-valued bytes embedded in a sea of
        // control bytes and high-bit values. Boundary-byte check alone passes
        // because `*` (0x2A) and `<` (0x3C) are allowed boundaries; the
        // binary-context check is what kills these.
        let data: &[u8] = &[
            0x98, 0x95, 0x92, 0x90, 0x8e, 0x87, 0x78, 0x68, 0x5e, 0x58, 0x56,
            0x61, 0x7c, 0x99, 0x9a, 0x94, 0x8e, 0x89, 0x87, 0x81, 0x6a, 0x3e,
            0x37, 0x36, 0x32, 0x29, 0x1f, 0x1c, 0x1d, 0x2a, // boundary `*`
            b'3', b'6', b'6', b'7', b'7', b'7', b'7', b'7', b'7', b'7', b'7',
            b'7', b'7', b'5', b'7', // 15 digits, Luhn-tunable
            0x3c, 0x39, 0x25, 0x34, 0x4c, 0x5e, 0x70, 0x7c, 0x7d, 0x7c, 0x81,
            0x7e, 0x76, 0x6f, 0x6a, 0x67, 0x65, 0x65, 0x63,
        ];
        // Even if some Luhn-valid subset would otherwise emit, the dense
        // binary surroundings should suppress it.
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn insta360_thumbnail_digit_run_rejected() {
        // Real .insp pattern: pixel-delta payload — bytes in 0x00..=0x1F
        // (control range) packed densely around an ASCII-digit run that just
        // happens to Luhn-check. No bare continuations (the relevant bytes
        // are 0x06/0x07/0x0B/0x11/0x16/0x1B/0x1F etc., not high-bit). The
        // strict-control branch is what rejects this.
        let data: &[u8] = &[
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x08, 0x09,
            0x0b, 0x0d, 0x11, 0x16, 0x18, 0x17, 0x19, 0x1b, 0x1d, 0x1f, 0x1f,
            0x21, 0x22, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2f,
            b'3', b'6', b'8', b'9', b'9', b'9', b'9', b'9', b'8', b'7', b'6',
            b'4', b'2', b'1', b'0', // 15 digits
            0x2f, 0x2d, 0x2a, 0x28, 0x25, 0x24, 0x24, 0x24, 0x23, 0x24, 0x24,
            0x23, 0x20, 0x1e, 0x1e, 0x1a, 0x0d, 0x07, 0x07, 0x06, 0x06, 0x07,
            0x07, 0x08, 0x0b, 0x0b, 0x09, 0x0a, 0x0c, 0x22, 0x2d, 0x32, 0x34,
        ];
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn yahoo_cid_url_token_rejected() {
        // Yahoo Mail HTML CID: `cid:DIGITS@web53001.mail.yahoo.com`. Digits
        // are framed by `:` (preceded by `cid`) and `@web` — pure URL token,
        // not a typed PAN. Boundary check passes because `:` and `@` are
        // valid `is_pan_boundary` bytes alone; the looks_like_url_token
        // shape check is what kills these.
        let data = b"<img src=\"cid:3932733649000000@web53001.mail.yahoo.com\">";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn url_query_param_rejected() {
        // Email-tracking redirect URL with the digits as an opaque ID
        // followed by URL-encoded query separator.
        let data = b"href=https://x.example/track?id=360714801549783&u=foo";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn url_encoded_at_sign_rejected() {
        // `%40` is the URL-encoded form of `@`. The digits of `%40DIGITS…`
        // start at the `4` of `%40`, so the candidate is preceded by `%`.
        // Common in Yahoo Mail HTML/QP-encoded CID URLs that have been
        // doubly URL-encoded.
        let data = b"track?id=foo%21%21%4021412158170005&u=bar";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn pan_in_text_context_still_found() {
        // Sanity check that context_is_textish doesn't reject normal text.
        // 32 bytes of plain ASCII on each side of a Visa PAN.
        let data = b"prefix lorem ipsum dolor sit amet 4111-1111-1111-1111 suffix consectetur adipiscing";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1, "got {:?}", hits);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn float_column_csv_rejected() {
        // Pandas/matplotlib sample CSVs flag float columns where a value like
        // 375.2200012207031 strips the `.` into a Luhn-valid 16-digit run.
        // Group pattern [3, 13] — 13 > 6, reject.
        let data = b",375.2200012207031,482.29998779296875,";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn version_string_rejected() {
        // 1.2.3.4567.8901.2345.6 → groups [1,1,1,4,4,4,1], 1-digit and 4-digit
        // mixed, all-1s check fails, 3..=6 check fails on the 1-digit ones.
        let data = b" 1.2.3.4567.8901.2345.6 ";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn dash_every_digit() {
        let data = b"obfusc 4-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1 end";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn separated_amex_4_6_5() {
        let data = b"amex 3782-822463-10005 ok";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"378282246310005");
    }

    #[test]
    fn double_separator_does_not_bridge() {
        // 4111--1111-1111-1111 — only single separators bridge digit groups.
        // The first dash isn't followed by a digit (it's followed by another
        // dash), so the run ends at 4 digits.
        let data = b"x 4111--1111-1111-1111 y";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn trailing_separator_ignored() {
        let data = b"x 4111-1111-1111-1111- y";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn separator_run_too_long_no_emit() {
        // Five 4-digit groups dash-joined = 20 digits; over the 16-digit cap.
        let data = b"too many 1234-1234-1234-1234-1234 digits";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn adjacent_space_separated_pans_merge_limitation() {
        // Known limitation of single-pass scanning: two adjacent PANs separated
        // by exactly one space bridge into a single 32-digit run and are
        // discarded together. Use a non-separator boundary (comma, newline,
        // tab) to keep them distinct.
        let data = b"7000000000000003 4111111111111111";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "merged-and-rejected; got {:?}", hits);
    }

    #[test]
    fn strict_accepts_visa_rejects_unknown() {
        // 7000000000000003 is Luhn-valid but no BIN scheme starts with 7.
        // Comma boundary prevents the two PANs from bridging via space-separator.
        let data = b"7000000000000003,4111111111111111";
        let mut opts = opts_default();
        opts.strict = true;
        let hits = find_pans(data, &opts);
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
    }

    #[test]
    fn bin_table_spot_checks() {
        assert!(has_valid_bin(b"4111111111111111"));   // Visa
        assert!(has_valid_bin(b"5111111111111111"));   // MC 51
        assert!(has_valid_bin(b"5511111111111111"));   // MC 55
        assert!(!has_valid_bin(b"5611111111111111"));  // not MC range
        assert!(has_valid_bin(b"341111111111111"));    // Amex 34
        assert!(has_valid_bin(b"371111111111111"));    // Amex 37
        assert!(has_valid_bin(b"3095000000000000"));   // Diners 3095
        assert!(!has_valid_bin(b"3094000000000000"));  // 3094 not covered
        assert!(has_valid_bin(b"3528111111111111"));   // JCB
        assert!(has_valid_bin(b"3531111111111111"));   // JCB 353
        // First digit must be 3, 4, or 5 — anything else rejects.
        assert!(!has_valid_bin(b"6011111111111111"));  // Discover 6011 — excluded
        assert!(!has_valid_bin(b"6511111111111111"));  // Discover 65   — excluded
        assert!(!has_valid_bin(b"2221111111111111"));  // MC 2-series   — excluded
        assert!(!has_valid_bin(b"2720111111111111"));  // MC 2720       — excluded
        assert!(!has_valid_bin(b"7111111111111111"));  // unknown
        assert!(!has_valid_bin(b"1111111111111111"));  // unknown
        assert!(!has_valid_bin(b"0111111111111111"));  // unknown
    }

    #[test]
    fn pan_scheme_labels() {
        assert_eq!(pan_scheme(b"4111111111111111"), "Visa");
        assert_eq!(pan_scheme(b"5111111111111111"), "Mastercard");
        assert_eq!(pan_scheme(b"341111111111111"),  "Amex");
        assert_eq!(pan_scheme(b"371111111111111"),  "Amex");
        assert_eq!(pan_scheme(b"3528111111111111"), "JCB");
        assert_eq!(pan_scheme(b"3095000000000000"), "Diners");
        assert_eq!(pan_scheme(b"3611111111111111"), "Diners");
        assert_eq!(pan_scheme(b"7000000000000003"), "other");
    }

    #[test]
    fn rejects_pan_embedded_in_hex_letters() {
        // 4111111111111111 sandwiched between hex letters — looks like
        // hex/binary content, not a real PAN reference.
        let data = b"abc4111111111111111def";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_pan_with_letter_before() {
        let data = b"x4111111111111111 ";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_pan_with_letter_after() {
        let data = b" 4111111111111111x";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_separated_pan_with_letter_after() {
        let data = b" 4111-1111-1111-1111x";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_pan_inside_long_hex_run() {
        // Hex-blob test vectors (openssl test data, signature dumps) often
        // contain 14-16 digit sub-runs flanked by hex letters. Must not flag.
        let data = b"sig=deadbeef4111111111111111deadbeef";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn accepts_pan_with_newline_boundaries() {
        let data = b"header\n4111111111111111\nfooter";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn accepts_pan_with_punct_boundaries() {
        let data = b"pan=4111111111111111;";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn accepts_pan_with_tab_boundaries() {
        let data = b"col1\t4111111111111111\tcol3";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn rejects_underscore_boundary_before() {
        let data = b"id_4111111111111111 ";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_underscore_boundary_after() {
        let data = b" 4111111111111111_token";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_nul_byte_boundary() {
        // NUL and other control bytes (except \t \n \r) usually flank a digit
        // run inside binary file content, not a real PAN.
        let data = b"\x004111111111111111\x00";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn rejects_control_byte_boundary() {
        let data = b"\x014111111111111111\x02";
        let hits = find_pans(data, &opts_default());
        assert!(hits.is_empty(), "got {:?}", hits);
    }

    #[test]
    fn accepts_utf8_multibyte_boundary() {
        // Hebrew aleph (U+05D0) is 0xD7 0x90 in UTF-8 — high-bit bytes must
        // still count as boundary so PANs embedded in Hebrew text are caught.
        let data = b"\xd7\x90 4111111111111111 \xd7\x90";
        let hits = find_pans(data, &opts_default());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn finds_one_pan_in_large_buffer() {
        // Sanity: one valid PAN among thousands of Luhn-invalid candidates.
        // 1111111111111111 has Luhn sum 24, fails check. All-zeros would pass
        // (sum = 0), so don't use that as filler.
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"4111111111111111 ");
        for _ in 0..10000 {
            data.extend_from_slice(b"junk text 1111111111111111 ");
        }
        let hits = find_pans(&data, &opts_default());
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].1, b"4111111111111111");
        assert_eq!(hits[0].0, 0);
    }
}
