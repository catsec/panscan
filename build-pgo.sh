#!/usr/bin/env bash
# Profile-Guided Optimization build.
#
# Two-phase: (1) build an instrumented binary, (2) run it against a
# representative scan target to collect profile data, (3) rebuild with the
# profile applied.
#
# Pass the training corpus as $1 (defaults to the project's own checkout —
# fine as a smoke test, but for production gains use a realistic corpus, e.g.
# /var/log or a synthetic CSV dump of the kind you'll be sweeping).
#
# Output: ./panscan_pgo (host-tuned + profile-guided, NOT portable).

set -euo pipefail
cd "$(dirname "$0")"

CORPUS="${1:-$PWD}"
PROFDIR="/tmp/panscan-pgo-$$"
mkdir -p "$PROFDIR"

LLVM_PROFDATA="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | awk '/host:/ {print $2}')/bin/llvm-profdata"
if [ ! -x "$LLVM_PROFDATA" ]; then
    echo "error: llvm-profdata not found at $LLVM_PROFDATA"
    echo "install with: rustup component add llvm-tools-preview"
    exit 1
fi

echo "==> Phase 1: instrumented build"
RUSTFLAGS="-Cprofile-generate=$PROFDIR -Ctarget-cpu=native" \
    cargo build --profile release-native --target-dir target/pgo-build

echo ""
echo "==> Phase 2: training run against $CORPUS"
target/pgo-build/release-native/panscan "$CORPUS" --csv /tmp/pgo-training.csv >/dev/null 2>&1 || true
rm -f /tmp/pgo-training.csv

echo ""
echo "==> Phase 3: merging profile data"
"$LLVM_PROFDATA" merge -o "$PROFDIR/merged.profdata" "$PROFDIR"

echo ""
echo "==> Phase 4: final build using profile"
RUSTFLAGS="-Cprofile-use=$PROFDIR/merged.profdata -Ctarget-cpu=native" \
    cargo build --profile release-native --target-dir target/pgo-final

cp -f target/pgo-final/release-native/panscan ./panscan_pgo
rm -rf "$PROFDIR"

echo ""
echo "Built: ./panscan_pgo (PGO + host-tuned, non-portable)"
ls -lh ./panscan_pgo
