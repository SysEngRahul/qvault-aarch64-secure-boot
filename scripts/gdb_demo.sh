#!/usr/bin/env bash
# Scripted, non-interactive GDB session against the real firmware in QEMU.
# Shows: breakpoint in the verifier, struct inspection, registers, memory, stepping, and a
# conditional "what would happen if" by reading the verification result.
# NOTE: firmware is built without CFI (-fno-asynchronous-unwind-tables), so `finish`/`bt` are only reliable at
# function entry; stepping with `next` works anywhere.
# Interactive use: terminal 1: GDB=1 scripts/run_qemu.sh      terminal 2: gdb-multiarch build/stage1.elf -ex 'target remote :1234'
set -euo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d); trap 'kill $QPID 2>/dev/null || true; rm -rf "$T"' EXIT
cp build/flash.img.pflash "$T/p"
GDB=1 PFLASH="$T/p" scripts/run_qemu.sh build/flash.img > "$T/qemu.log" 2>&1 &
QPID=$!
sleep 2
cat > "$T/cmds" <<'GDBCMDS'
set pagination off
set confirm off
file build/stage1.elf
target remote :1234
echo \n=== 1. breakpoint at the Stage-1 header parser ===\n
break qv_image_parse
continue
echo \n=== 2. where are we / registers (x0=blob x1=len x2=expect_type, AAPCS64) ===\n
bt 2
info registers pc sp x0 x1 x2
echo \n=== 3. memory: first 32 bytes of the image blob = start of the header (magic 0x544c5651 'QVLT') ===\n
x/8xw $x0
echo \n=== 4. run to the end of the parser, inspect the validated header copy ===\n
finish
echo \n=== 5. breakpoint in the verifier, step through the three checks ===\n
break qv_image_verify
continue
print/x hdr->image_type
print hdr->fw_version
print/x hdr->load_addr
print hdr->payload_size
next
next
next
next
echo \n--- after hashing: does the computed digest match the signed header hash? ---\n
print res->hash
x/8xw res->digest
x/8xw hdr->payload_hash
echo \n=== 6. rollback check: what does the store say, what is the image version? ===\n
break qv_rollback_check
continue
info registers x0 x1
echo (x0 = image type, x1 = fw_version being checked against the stored floor)\n
next
next
next
echo \n=== done ===\n
kill
quit
GDBCMDS
timeout 60 gdb-multiarch -q -batch -x "$T/cmds" 2>&1 | sed 's/\r//'
