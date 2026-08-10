#!/usr/bin/env bash
# Build spora-ffi for Apple platforms and emit a universal static library plus
# generated Swift bindings, staged into the sibling macOS client repo.
#
# Counterpart to build-ffi.sh (Android). Produces:
#   <OUT>/lib/libspora_ffi.a                 universal (arm64 + x86_64) staticlib
#   <OUT>/Sources/SporaFFI/spora_ffi.swift   generated Swift API
#   <OUT>/include/spora_ffiFFI.h             C header
#   <OUT>/include/module.modulemap           clang modulemap for the header
#
# Usage: ./build-ffi-apple.sh [--debug]
# Env:   SPORA_MAC_OUT (default: ../spora-mac/rust-out)
set -euo pipefail

cd "$(dirname "$0")"

PROFILE="release"
CARGO_PROFILE_FLAG="--release"
for arg in "$@"; do
  case "$arg" in
    --debug) PROFILE="debug"; CARGO_PROFILE_FLAG="" ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

OUT="${SPORA_MAC_OUT:-../spora-mac/rust-out}"
MAC_TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin")
LIB="libspora_ffi.a"

echo "==> Building spora-ffi staticlib for: ${MAC_TARGETS[*]} ($PROFILE)"
for t in "${MAC_TARGETS[@]}"; do
  rustup target add "$t" >/dev/null 2>&1 || true
  cargo build -p spora-ffi --lib $CARGO_PROFILE_FLAG --target "$t"
done

mkdir -p "$OUT/lib" "$OUT/include" "$OUT/Sources/SporaFFI"

echo "==> Creating universal static library"
lipo -create \
  "target/aarch64-apple-darwin/$PROFILE/$LIB" \
  "target/x86_64-apple-darwin/$PROFILE/$LIB" \
  -output "$OUT/lib/$LIB"
lipo -info "$OUT/lib/$LIB"

echo "==> Generating Swift bindings"
# uniffi-bindgen reads metadata from a built library. Use the host-arch dylib
# (cdylib) which the crate also emits.
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  arm64) HOST_TARGET="aarch64-apple-darwin" ;;
  x86_64) HOST_TARGET="x86_64-apple-darwin" ;;
  *) echo "unsupported host arch: $HOST_ARCH" >&2; exit 1 ;;
esac
HOST_DYLIB="target/$HOST_TARGET/$PROFILE/libspora_ffi.dylib"

GEN_TMP="$(mktemp -d)"
trap 'rm -rf "$GEN_TMP"' EXIT
cargo run -p spora-ffi --bin uniffi-bindgen $CARGO_PROFILE_FLAG --target "$HOST_TARGET" -- \
  generate --library "$HOST_DYLIB" --language swift --out-dir "$GEN_TMP"

# Stage generated files. UniFFI emits <ns>.swift, <ns>FFI.h, <ns>FFI.modulemap.
cp "$GEN_TMP/spora_ffi.swift" "$OUT/Sources/SporaFFI/spora_ffi.swift"
cp "$GEN_TMP/spora_ffiFFI.h" "$OUT/include/spora_ffiFFI.h"
# Normalize the modulemap name so SwiftPM/Xcode find it as `module.modulemap`.
if [ -f "$GEN_TMP/spora_ffiFFI.modulemap" ]; then
  cp "$GEN_TMP/spora_ffiFFI.modulemap" "$OUT/include/module.modulemap"
elif [ -f "$GEN_TMP/module.modulemap" ]; then
  cp "$GEN_TMP/module.modulemap" "$OUT/include/module.modulemap"
fi

echo "==> Done. Staged into $OUT"
ls -R "$OUT"
