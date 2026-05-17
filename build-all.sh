#!/usr/bin/env bash
# Build panscan (CLI) for all release targets and move the binaries into the
# project root with stable distribution names.
#
# Cross-compiles cleanly from a Mac for all four targets via zigbuild
# (Linux musl-static + Windows mingw-gnu) plus the native cargo
# aarch64-apple-darwin build.
#
# Size pipeline (matches .github/workflows/build.yml):
#   - nightly toolchain + rust-src
#   - `-Z build-std=std,panic_abort` + `-C panic=immediate-abort` in
#     RUSTFLAGS rebuilds std with panic messages stripped (~10-20% off)
#   - UPX --best --lzma on Linux + Windows binaries (~50-60% off)
#   - aarch64-apple-darwin is left uncompressed (Mach-O packing is flaky on
#     Apple Silicon — Gatekeeper / loader edge cases)
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "error: cargo-zigbuild not found"
    echo "install with: brew install zig && cargo install cargo-zigbuild"
    exit 1
fi

if ! command -v upx >/dev/null 2>&1; then
    echo "error: upx not found"
    echo "install with: brew install upx"
    exit 1
fi

if ! rustup run nightly cargo --version >/dev/null 2>&1; then
    echo "error: nightly toolchain not installed"
    echo "install with: rustup toolchain install nightly"
    exit 1
fi

if ! rustup +nightly component list --installed 2>/dev/null | grep -q '^rust-src'; then
    echo "error: rust-src component not installed for nightly"
    echo "install with: rustup +nightly component add rust-src"
    exit 1
fi

# triple                          out                    builder      upx
TARGETS=(
    "aarch64-apple-darwin         panscan_mac            cargo        no"
    "x86_64-unknown-linux-musl    panscan_linux_amd64    zigbuild     yes"
    "aarch64-unknown-linux-musl   panscan_linux_arm64    zigbuild     yes"
    "x86_64-pc-windows-gnu        panscan_windows.exe    zigbuild     yes"
)

for row in "${TARGETS[@]}"; do
    read -r triple _ _ _ <<< "$row"
    rustup +nightly target add "$triple" >/dev/null
done

BUILDSTD=(-Z build-std=std,panic_abort)
PANIC_FLAGS="-Z unstable-options -C panic=immediate-abort"

for row in "${TARGETS[@]}"; do
    read -r triple out builder upx_flag <<< "$row"
    echo "==> $triple"

    # x86-64-v3 enables AVX2/BMI1/BMI2/F16C (Intel Haswell+, AMD Excavator+,
    # both from ~2013). aarch64 baseline already includes NEON so no flags
    # needed there. The Windows binary relies on the Universal CRT shipped
    # with Windows 10 / Server 2016 and later — older Windows isn't supported.
    case "$triple" in
        x86_64-*) export RUSTFLAGS="-C target-cpu=x86-64-v3 $PANIC_FLAGS" ;;
        *)        export RUSTFLAGS="$PANIC_FLAGS" ;;
    esac

    case "$builder" in
        zigbuild) cargo +nightly zigbuild --release --target "$triple" "${BUILDSTD[@]}" ;;
        cargo)    cargo +nightly build    --release --target "$triple" "${BUILDSTD[@]}" ;;
    esac

    case "$triple" in
        *windows*) src="target/$triple/release/panscan.exe" ;;
        *)         src="target/$triple/release/panscan" ;;
    esac

    mv -f "$src" "./$out"

    if [ "$upx_flag" = "yes" ]; then
        upx --best --lzma "./$out" >/dev/null
    fi

    echo "    -> ./$out"
done

unset RUSTFLAGS

echo ""
echo "Done. Release binaries in $(pwd):"
ls -lh panscan_mac panscan_linux_amd64 panscan_linux_arm64 panscan_windows.exe 2>/dev/null || true
