#!/bin/bash

set -e # abort on error

# Preparation:
#
# 1. Add linkers from NDK to ~/.cargo/config.toml:
#
#[target.x86_64-linux-android]
#linker = ".../Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang"
#
#[target.i686-linux-android]
#linker = ".../Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android35-clang"
#
#[target.armv7-linux-androideabi]
#linker = ".../Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi35-clang"
#
#[target.aarch64-linux-android]
#linker = ".../Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
#
# 2. Install support for Android targets:
#
# $ rustup target add x86_64-linux-android i686-linux-android armv7-linux-androideabi aarch64-linux-android
#

# Set CC for each Android target so ring's build script can find the NDK compiler
NDK_BIN="$HOME/Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android35-clang"
export CC_armv7_linux_androideabi="$NDK_BIN/armv7a-linux-androideabi35-clang"
export CC_i686_linux_android="$NDK_BIN/i686-linux-android35-clang"
export CC_x86_64_linux_android="$NDK_BIN/x86_64-linux-android35-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export AR_armv7_linux_androideabi="$NDK_BIN/llvm-ar"
export AR_i686_linux_android="$NDK_BIN/llvm-ar"
export AR_x86_64_linux_android="$NDK_BIN/llvm-ar"

# build the library
cargo build --lib --target x86_64-linux-android --target i686-linux-android --target armv7-linux-androideabi --target aarch64-linux-android

# generate scaffolding
#cargo run --bin uniffi-bindgen generate --library target/debug/libspora_ffi.so --language kotlin --out-dir out
cargo run --bin uniffi-bindgen generate --library target/aarch64-linux-android/debug/libspora_ffi.so --language kotlin --out-dir out

# copy the binaries to a structure suitable for Android app build
mkdir -p jniLibs/arm64-v8a/ || true
cp target/aarch64-linux-android/debug/libspora_ffi.so jniLibs/arm64-v8a/

mkdir -p jniLibs/armeabi-v7a/ || true
cp target/armv7-linux-androideabi/debug/libspora_ffi.so jniLibs/armeabi-v7a/

mkdir -p jniLibs/x86/ || true
cp target/i686-linux-android/debug/libspora_ffi.so jniLibs/x86/

mkdir -p jniLibs/x86_64/
cp target/x86_64-linux-android/debug/libspora_ffi.so jniLibs/x86_64/

# copy the library binaries to Andoid app
cp -r jniLibs/ ../spora-android/app/src/main/

# copy scaffolding to Android app sources
cp -r out/uniffi ../spora-android/app/src/main/java/
