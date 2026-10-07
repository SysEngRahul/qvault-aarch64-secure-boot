#!/usr/bin/env bash
# Fault injection: flip one byte inside a region of the flash image.
# usage: corrupt_image.sh FLASH REGION FIELD [OUT]
#   REGION: stage2a stage2b uefia uefib kernela kernelb dtba dtbb store(use the .pflash file)
#   FIELD : magic version type fwversion entry size hash cert sig payload payload2
# Writes to OUT (default: FLASH.corrupt) and leaves FLASH untouched.
set -euo pipefail
f=$1; region=$2; field=$3; out=${4:-$1.corrupt}
case $region in
  stage2a) base=$((0x000000));; stage2b) base=$((0x100000));;
  uefia)   base=$((0x200000));; uefib)   base=$((0x300000));;
  kernela) base=$((0x400000));; kernelb) base=$((0x500000));;
  dtba)    base=$((0x600000));; dtbb)    base=$((0x700000));; store)   base=0;;  # store = the .pflash file
  *) echo "unknown region $region" >&2; exit 2;;
esac
case $field in
  magic) o=0;; version) o=4;; type) o=8;; fwversion) o=12;; entry) o=24;; size) o=32;;
  hash) o=56;; cert) o=120;; sig) o=184;; payload) o=260;; payload2) o=456;;
  *) echo "unknown field $field" >&2; exit 2;;
esac
cp "$f" "$out"
off=$((base + o))
b=$(dd if="$out" bs=1 skip=$off count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
printf "$(printf '\\x%02x' $((b ^ 0xff)))" | dd of="$out" bs=1 seek=$off conv=notrunc 2>/dev/null
echo "corrupted $region.$field (byte 0x$(printf %x $off): $b -> $((b ^ 255))) -> $out"
