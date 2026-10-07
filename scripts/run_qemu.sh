#!/usr/bin/env bash
# usage: run_qemu.sh [flash.img]      (persistent state: PFLASH=file, default <flash.img>.pflash)
#   GDB=1            start paused with a GDB stub on :1234
#   QV_EL=2|3        boot Stage 1 at EL2 (virtualization=on) or EL3 (secure=on) to exercise the EL drop
# NOTE: the pflash file is WRITTEN by the firmware (counters, slot state). Copy it first if you
#       want a repeatable run.
set -euo pipefail
cd "$(dirname "$0")/.."
FLASH=${1:-build/flash.img}
PFLASH=${PFLASH:-$FLASH.pflash}
[ -f "$FLASH" ] && [ -f "$PFLASH" ] || { echo "missing $FLASH or $PFLASH (run: make)" >&2; exit 1; }
MACH=virt
case "${QV_EL:-1}" in 2) MACH=virt,virtualization=on;; 3) MACH=virt,secure=on;; esac
EXTRA=()
[ "${GDB:-0}" = 1 ] && EXTRA+=(-S -s)
exec qemu-system-aarch64 -M "$MACH" -cpu cortex-a72 -smp 1 -m 1G -nographic -no-reboot \
    -kernel build/stage1.elf \
    -device loader,file="$FLASH",addr=0x60000000,force-raw=on \
    -drive if=pflash,format=raw,unit=1,file="$PFLASH" \
    "${EXTRA[@]}"
