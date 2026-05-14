# panscan (Rust)

Cross-platform single-pass PAN (credit card number) discovery scanner for PCI DSS req 3 sweeps.

## What it does

- Walks disk in parallel and deep-scans each file inline, enumerating every PAN with byte offset in one pass
- **Output**: `panfind-YYYY-MM-DD-HHMMSS.csv` with columns `location, offset, pan`

Detects both contiguous PANs (`4111111111111111`) and PANs typed with separators (`4111-1111-1111-1111`, `4111 1111 1111 1111`, `4111.1111.1111.1111`, irregular groupings, even dash-every-digit obfuscation `4-1-1-1-...`). Luhn-10 check is mandatory for every emit. **Strict mode (card-scheme BIN-prefix filter) is on by default** — drops ~85% of random Luhn-passing false positives in real-world data. Pass `--no-strict` to scan all Luhn-valid 14-16 digit runs regardless of BIN.

Two-level SIMD scanner (NEON on arm64, SSE2 on x86_64): the outer "find next digit byte" loop and the "find end of digit run" loop both process 16 bytes per instruction. Single-pass walker: every file is scanned exactly once. `madvise(MADV_SEQUENTIAL)` on every mmap. The result on M-series Mac: ~2.5 GB/s sparse text, ~1.3 GB/s realistic numeric content (CSV exports, financial logs), and a `release-native` build profile (`./build-native.sh`) that tunes for the host CPU for another ~2× on top.

## Usage

```bash
# Bare command runs --mode quick (user folders + system logs).
sudo panscan

# Explicit modes
sudo panscan --mode quick
sudo panscan --mode complete                    # whole disk

# Custom path
sudo panscan ~/Documents

# Path + mode = union (custom path added to mode preset, exempt from skip lists)
sudo panscan ~/Downloads --mode quick

# Preview targets without scanning (no elevation required)
panscan --mode complete --list-targets

# Custom output, unmasked PANs (be careful)
sudo panscan /data --csv my_report.csv --unmask

# Scan ALL Luhn-valid 14-16 digit runs — broader, more false positives
sudo panscan ~/Downloads --no-strict

# Debug: print every hit (full unmasked PAN, offset, scheme) to stderr.
# Independent of --unmask, which controls the CSV.
sudo panscan /tmp/sample --debug
```

Separator-aware scanning (`-`, space, `.`) is always on.

**panscan refuses to run unprivileged** — for forensic / IR use, a partial scan that silently skips system paths is worse than no scan, so the program exits with an error if not run as root / Administrator. `--list-targets` and `--help` still work without elevation (they don't scan anything).

On Windows, run from an elevated PowerShell / cmd.exe. On Unix, use `sudo`. The program refuses to run otherwise.

## Build

### Native build on each platform

Requires Rust 1.85+ (edition 2024). Install via [rustup](https://rustup.rs).

```bash
cargo build --release
# binary: target/release/panscan  (or panscan.exe on Windows)
```

For a host-tuned build (2× faster on this machine but non-portable):

```bash
./build-native.sh          # produces ./panscan_native
./build-pgo.sh /var/log    # PGO on top, training against /var/log
```

### Cross-compile from a Mac M-series

```bash
# One-time setup
brew install zig
cargo install cargo-zigbuild

rustup target add aarch64-apple-darwin      # native
rustup target add x86_64-apple-darwin       # Intel Mac
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
rustup target add x86_64-pc-windows-gnu

cargo build         --release --target aarch64-apple-darwin
cargo build         --release --target x86_64-apple-darwin
cargo zigbuild      --release --target x86_64-unknown-linux-musl
cargo zigbuild      --release --target aarch64-unknown-linux-musl
cargo zigbuild      --release --target x86_64-pc-windows-gnu
```

Linux musl builds are statically linked — no glibc dependency, so they run on any Linux distro including stripped-down containers and embedded systems.

### Release binaries

Pre-built binaries for macOS (arm64), Linux (amd64 + arm64, statically linked musl), and Windows are attached to each [GitHub Release](https://github.com/catsec/panscan/releases). To rebuild locally, run `./build-all.sh` (needs `cargo-zigbuild`); produces `panscan_mac`, `panscan_linux_amd64`, `panscan_linux_arm64`, `panscan_windows.exe` in the project root.

## Performance notes

| Workload | release | release-native |
|---|---|---|
| Numeric content (CSV, financial logs, 16-digit runs) | ~1.3 GB/s | ~2.5 GB/s |
| Sparse prose / logs | ~2.5 GB/s | ~3 GB/s |
| Adversarial random hex + spaces | ~600 MB/s | ~1 GB/s |
| Mostly-empty filesystem | walk-speed limited | walk-speed limited |

Build the host-tuned `release-native` binary with `./build-native.sh` (uses `RUSTFLAGS=-C target-cpu=native` and a dedicated Cargo profile). The output binary is NOT portable. For one more 5-15% on top, `./build-pgo.sh <training-corpus>` runs an instrumented build, scans the corpus, then rebuilds with the profile.

Architecture:
- `ignore` crate (ripgrep's directory walker) for parallel walking, single-pass deep scan inline.
- Two-level SIMD digit-run finder: NEON on arm64, SSE2 on x86_64, scalar fallback elsewhere.
- `memmap2` + `madvise(MADV_SEQUENTIAL)` for files > 1 MB.

## Output format

`panfind-2026-05-11-143022.csv`:

```csv
location,offset,pan
/Users/ram/Downloads/orders.csv,2841,411111******1111
/Users/ram/Downloads/orders.csv,3102,555555******4444
/var/log/charge.log,15890,378282*****0005
```

- `location`: absolute path
- `offset`: byte offset in file where the first digit of the PAN starts
- `pan`: masked by default (`411111` + asterisks + last 4); use `--unmask` for full

Rows sorted by path then offset. Stable across runs.

## Detection details

- **Separators** between digits: `-`, space, `.` (one at a time — `4111--1111` does not bridge).
- **Length**: 14, 15, or 16 digits after stripping separators.
- **Luhn-10**: every candidate must pass; reject otherwise.
- **Boundaries**: the byte immediately before and immediately after the candidate must be ASCII whitespace, printable ASCII punctuation (excluding `_`), or a high-bit UTF-8 byte (>= 0x80, for adjacent Hebrew/other non-ASCII text) — or a buffer edge. Rejects matches inside hex blobs, code identifiers (`id_4111…_token`), and binary noise (NUL / control bytes flanking a 14-16 digit run).
- **Strict mode (default)**: require the first digit to be 3, 4, or 5, and the leading BIN to match a covered scheme (Visa 4; MC 51-55; Amex 34/37; Diners/JCB 300-305, 3095, 36, 38, 39, 3528-3529, 353-358). Discover (first digit 6) and the post-2017 MC 2-series are intentionally excluded to cut false positives. Disable the BIN filter entirely with `--no-strict`.

### Known limitation

Two adjacent PANs separated by exactly one space (`4111111111111111 4111111111111111`) bridge into a 32-digit run and are discarded together. Non-separator boundaries (comma, tab, newline, parentheses, etc.) keep them distinct — which is how PANs appear in CSVs, logs, and most machine-generated formats. Human-typed text rarely puts two PANs side-by-side, so this is an acceptable trade for catching every separator-typed single PAN.

## Safety / operational notes

- **The masked output is fine for evidence/audit trails.** Use `--unmask` only when you genuinely need the full PAN (e.g., to grep a specific number out of source files for remediation). Unmasked output is itself in scope for PCI controls.
- **`--max-size 500` (default) skips files >500 MB.** Override only if you need to scan `pagefile.sys`-style large files; expect long scan times.
- **Ctrl-C is graceful.** The walker stops at the next file boundary, but the CSV gets written with partial results.
- **Symlinks are not followed.** Avoids loops and prevents the scanner from leaving the intended target tree via stray links.

## License

MIT.
