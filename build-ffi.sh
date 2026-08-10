#!/bin/bash
# Cross-compile spora-ffi for Android and generate the Kotlin bindings.
#
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi \
#                     i686-linux-android x86_64-linux-android
#   cargo install cargo-ndk
#   An Android NDK, located via (in order): $ANDROID_NDK_HOME,
#   $ANDROID_NDK_LATEST_HOME (GitHub runners), newest under ~/Android/Sdk/ndk.
#
# Usage:
#   ./build-ffi.sh                    debug build, copied into ../spora-android
#   ./build-ffi.sh --release         release build, copied into ../spora-android
#   ./build-ffi.sh --release --out D  assemble a distributable bundle under D
#                                     (D/jniLibs/<abi>/libspora_ffi.so,
#                                      D/kotlin/uniffi/...) and skip the app copy

set -euo pipefail
cd "$(dirname "$0")"

PROFILE=debug
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --release) PROFILE=release ;;
    --out) OUT="${2:?--out needs a directory}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  if [ -n "${ANDROID_NDK_LATEST_HOME:-}" ]; then
    export ANDROID_NDK_HOME="$ANDROID_NDK_LATEST_HOME"
  else
    ANDROID_NDK_HOME="$(ls -d "$HOME"/Android/Sdk/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
    [ -n "$ANDROID_NDK_HOME" ] || { echo "no NDK found; set ANDROID_NDK_HOME" >&2; exit 1; }
    export ANDROID_NDK_HOME
  fi
fi
command -v cargo-ndk >/dev/null || { echo "cargo-ndk missing: cargo install cargo-ndk" >&2; exit 1; }

JNIDIR="${OUT:+$OUT/jniLibs}"; JNIDIR="${JNIDIR:-jniLibs}"
KOUT="${OUT:+$OUT/kotlin}"; KOUT="${KOUT:-out}"

FLAGS=()
[ "$PROFILE" = release ] && FLAGS+=(--release)

# cargo-ndk resolves per-ABI clang/sysroot from ANDROID_NDK_HOME and lays the
# .so files out as $JNIDIR/<abi>/libspora_ffi.so.
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 \
  -o "$JNIDIR" build -p spora-ffi "${FLAGS[@]}"

for abi in arm64-v8a armeabi-v7a x86 x86_64; do
  [ -f "$JNIDIR/$abi/libspora_ffi.so" ] || { echo "missing $JNIDIR/$abi/libspora_ffi.so" >&2; exit 1; }
done

# generate the Kotlin scaffolding from the built library
cargo run --bin uniffi-bindgen generate \
  --library "target/aarch64-linux-android/$PROFILE/libspora_ffi.so" \
  --language kotlin --out-dir "$KOUT"
[ -s "$KOUT/uniffi/spora_ffi/spora_ffi.kt" ] || { echo "bindgen produced no spora_ffi.kt" >&2; exit 1; }

if [ -z "$OUT" ]; then
  # dev loop: install straight into the sibling Android app checkout
  cp -r "$JNIDIR"/ ../spora-android/app/src/main/
  cp -r "$KOUT"/uniffi ../spora-android/app/src/main/java/
  echo "installed $PROFILE jniLibs + bindings into ../spora-android"
else
  echo "bundle assembled under $OUT"
fi
