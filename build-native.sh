#!/usr/bin/env bash
# Build panscan tuned for the local CPU (uses every ISA extension available:
# AVX-2/BMI2 on Intel, NEON+specific Apple-Silicon tuning on M-series, etc.).
# The resulting binary is NOT portable — run it only on the build host.
#
# Drops into ./target/release-native/panscan and copies it to ./panscan_native.
set -euo pipefail
cd "$(dirname "$0")"

RUSTFLAGS="-C target-cpu=native" cargo build --profile release-native

cp -f target/release-native/panscan ./panscan_native
echo ""
echo "Built: ./panscan_native (host-tuned, non-portable)"
ls -lh ./panscan_native
