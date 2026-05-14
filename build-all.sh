#!/usr/bin/env bash
# Build panscan (CLI) for all release targets and move the binaries into the
# project root with stable distribution names.
#
# Cross-compiles cleanly from a Mac for all four targets via zigbuild
# (Linux musl-static + Windows mingw-gnu) plus the native cargo
# aarch64-apple-darwin build.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "error: cargo-zigbuild not found"
    echo "install with: brew install zig && cargo install cargo-zigbuild"
    exit 1
fi

# triple                          out                    builder
TARGETS=(
    "aarch64-apple-darwin         panscan_mac            cargo"
    "x86_64-unknown-linux-musl    panscan_linux_amd64    zigbuild"
    "aarch64-unknown-linux-musl   panscan_linux_arm64    zigbuild"
    "x86_64-pc-windows-gnu        panscan_windows.exe    zigbuild"
)

for row in "${TARGETS[@]}"; do
    read -r triple _ _ <<< "$row"
    rustup target add "$triple" >/dev/null
done

for row in "${TARGETS[@]}"; do
    read -r triple out builder <<< "$row"
    echo "==> $triple"

    # x86-64-v3 enables AVX2/BMI1/BMI2/F16C (Intel Haswell+, AMD Excavator+,
    # both from ~2013). aarch64 baseline already includes NEON so no flags
    # needed there. The Windows binary relies on the Universal CRT shipped
    # with Windows 10 / Server 2016 and later — older Windows isn't supported.
    case "$triple" in
        x86_64-*) export RUSTFLAGS="-C target-cpu=x86-64-v3" ;;
        *)        unset RUSTFLAGS ;;
    esac

    case "$builder" in
        zigbuild) cargo zigbuild --release --target "$triple" ;;
        cargo)    cargo build    --release --target "$triple" ;;
    esac

    case "$triple" in
        *windows*) src="target/$triple/release/panscan.exe" ;;
        *)         src="target/$triple/release/panscan" ;;
    esac

    mv -f "$src" "./$out"
    echo "    -> ./$out"
done

unset RUSTFLAGS

echo ""
echo "Done. Release binaries in $(pwd):"
ls -lh panscan_mac panscan_linux_amd64 panscan_linux_arm64 panscan_windows.exe 2>/dev/null || true
