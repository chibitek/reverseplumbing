#!/bin/bash
# Rebuild the ELF fixtures offline: Homebrew clang compiles, the lld that ships with rustup links.
# Usage: bash build.sh [clang] [ld.lld]
set -euo pipefail
cd "$(dirname "$0")"
CC=${1:-/opt/homebrew/opt/llvm@22/bin/clang}
LLD=${2:-$HOME/.rustup/toolchains/1.95.0-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/gcc-ld/ld.lld}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
build() { # name triple codegen-flag interpreter
  "$CC" --target=$2 $3 -O2 -fPIC -ffreestanding -c chibi.c -o "$TMP/chibi.o"
  "$CC" --target=$2 $3 -O2 -fPIE -ffreestanding -c main.c -o "$TMP/main.o"
  "$LLD" -shared -soname libchibi.so.1 --version-script chibi.map --build-id=sha1 -z relro -z now -z noexecstack \
    -o libchibi-$1.so "$TMP/chibi.o"
  "$LLD" -pie --dynamic-linker $4 --build-id=sha1 -z relro -z now -z noexecstack -rpath '$ORIGIN' --allow-shlib-undefined \
    -o fixture-$1 "$TMP/main.o" libchibi-$1.so
}
build aarch64 aarch64-linux-gnu -mbranch-protection=standard /lib/ld-linux-aarch64.so.1
build armhf armv7a-linux-gnueabihf -mthumb /lib/ld-linux-armhf.so.3
build aarch64_be aarch64_be-linux-gnu -mbranch-protection=standard /lib/ld-linux-aarch64_be.so.1
