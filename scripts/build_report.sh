#!/usr/bin/env bash
# Binary inspection used by CI: verify the artefacts are what we claim they are.
set -euo pipefail
cd "$(dirname "$0")/.."
X=aarch64-linux-gnu-
echo "== QVault build report =="
for e in build/stage1.elf build/stage2.elf; do
    echo "-- $e"
    ${X}readelf -h "$e" | grep -E "Class|Machine|Entry point"
    ${X}size "$e" | tail -1
    ${X}readelf -lW "$e" | grep -E "LOAD"
done
m=$(${X}readelf -h build/stage1.elf | awk '/Machine/{print $2}')
[ "$m" = "AArch64" ] || { echo "FAIL: stage1 is not AArch64"; exit 1; }
e=$(${X}readelf -h build/stage1.elf | awk '/Entry point/{print $4}')
[ "$e" = "0x40080000" ] || { echo "FAIL: stage1 entry $e != 0x40080000"; exit 1; }
echo "stage2.bin: $(stat -c %s build/stage2.bin) bytes, sha256 $(sha256sum build/stage2.bin | cut -d' ' -f1)"
echo "stage1.elf sha256: $(sha256sum build/stage1.elf | cut -d' ' -f1)"
echo "checks: arch=AArch64 entry=$e  OK"
