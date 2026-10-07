#!/usr/bin/env bash
# Sanitizer-backed mutation fuzzing of the DTB and image parsers.
# usage: fuzz_dtb.sh [ITERATIONS] [RNG_SEED]
set -euo pipefail
cd "$(dirname "$0")/.."
N=${1:-200000}; S=${2:-1}
MC=third_party/monocypher
OUT=build/fuzz; mkdir -p $OUT
gcc -std=c11 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -DQV_HOST_TEST \
    -Iinclude -Iarch/arm64 -Iformat -Ilib -Isecurity -Istorage -Idtb -Iplatform/qemu_virt -I$MC \
    -o $OUT/fuzz_main tests/fuzz/fuzz_main.c dtb/dtb_validate.c dtb/dtb_parser.c format/image_parser.c format/pe_validate.c \
    security/image_verify.c security/key_store.c security/crypto_backend.c lib/sha256.c lib/status.c \
    $MC/monocypher.c $MC/monocypher-ed25519.c
[ -f build/virt.dtb ] || make -s dtb
# Seed for the image fuzzer: a real signed kernel image from the flash.
dd if=build/flash.img of=$OUT/image.seed bs=1 skip=$((0x400000)) count=1024 2>/dev/null
echo "DTB seed: $(stat -c %s build/virt.dtb) bytes"
$OUT/fuzz_main dtb   build/virt.dtb "$N" "$S"
$OUT/fuzz_main image $OUT/image.seed    "$N" "$S"
$OUT/fuzz_main pe    -                 "$N" "$S"
