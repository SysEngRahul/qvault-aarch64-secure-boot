#!/usr/bin/env bash
# QEMU integration + negative (fault-injection) tests.
# Every scenario boots a FRESH copy of flash + pflash (the firmware writes the pflash) and asserts on
# the serial log. Rule: a bad image ends in REJECT/RECOVERY - never a crash or an unverified boot.
set -uo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
REF=$T/ref.img      # pristine reference image + pflash; "$REF" may have been mutated by manual runs
RESULTS=${RESULTS:-}      # optional: file to append "PASS|FAIL<TAB>name" lines to

boot() { # flash log [pflash-to-reuse]   (default: fresh copy of flash.pflash)
    local f=$1 log=$2 pf=${3:-}
    if [ -z "$pf" ]; then cp "$f.pflash" "$log.pf"; pf="$log.pf"; fi
    PFLASH="$pf" timeout ${BOOT_TIMEOUT:-10} scripts/run_qemu.sh "$f" > "$log" 2>&1 || true
    tr -d '\r' < "$log" > "$log.txt"
}
note() { [ -n "$RESULTS" ] && printf '%s\t%s\n' "$1" "$2" >> "$RESULTS"; true; }
expect() { # name logbase pattern...
    local name=$1 log=$2.txt; shift 2
    for pat in "$@"; do
        if ! grep -qE -- "$pat" "$log"; then
            echo "FAIL  $name  (missing: $pat)"; fail=$((fail+1)); note FAIL "$name"; sed 's/^/      | /' "$log" | tail -25; return
        fi
    done
    echo "PASS  $name"; pass=$((pass+1)); note PASS "$name"
}
refuse() { # name logbase pattern  (must NOT appear)
    if grep -qE -- "$3" "$2.txt"; then echo "FAIL  $1  (forbidden: $3)"; fail=$((fail+1)); note FAIL "$1"
    else echo "PASS  $1"; pass=$((pass+1)); note PASS "$1"; fi
}
corrupt() { # region field -> $T/f.img (+ .pflash)
    cp "$REF.pflash" "$T/f.img.pflash"
    if [ "$1" = store ]; then scripts/corrupt_image.sh "$T/f.img.pflash" store "$2" "$T/f.img.pflash.new" >/dev/null && mv "$T/f.img.pflash.new" "$T/f.img.pflash"; cp "$REF" "$T/f.img"
    else scripts/corrupt_image.sh "$REF" "$1" "$2" "$T/f.img" >/dev/null; fi
}
mkflash() { OUT="$1" "${@:2}" scripts/make_flash.sh >/dev/null; }
mkflash "$REF" env     # mkflash OUT ENV=... (env passed through)

# ---------------------------------------------------------------- 0. baseline
boot "$REF" "$T/base"
expect "baseline: full chain boots" "$T/base" "Stage-2 signature +OK" "Anti-rollback +OK" "UEFI image signature +OK" \
       "Kernel signature +OK" "Device Tree signature +OK" "MEASURE\] DTB" "Device Tree validation +OK" "SECURE BOOT SUCCESS" "KERNEL\] DTB handoff: magic OK"

# ---------------------------------------------------------------- 1. image tampering (kernel)
corrupt kernela payload; boot "$T/f.img" "$T/k1"
expect "kernel A payload flipped -> recovery to B" "$T/k1" "Kernel hash +FAIL" "Kernel rejected \(slot A\)" "Trying backup slot B" "Booting slot B" "SECURE BOOT SUCCESS"
corrupt kernela fwversion; boot "$T/f.img" "$T/k2"
expect "kernel A header field flipped -> signature FAIL, recovery" "$T/k2" "Kernel signature +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
corrupt kernela sig; boot "$T/f.img" "$T/k3"
expect "kernel A signature flipped" "$T/k3" "Kernel signature +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
corrupt kernela cert; boot "$T/f.img" "$T/k4"
expect "kernel A key certificate flipped" "$T/k4" "Kernel key certificate +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
for f in magic version type entry; do
    corrupt kernela $f; boot "$T/f.img" "$T/p_$f"
    expect "kernel A malformed '$f' -> rejected at parse, recovery" "$T/p_$f" "Kernel image format +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
    refuse "kernel A malformed '$f' -> no exception" "$T/p_$f" "QVault Exception"
done
corrupt kernela size; boot "$T/f.img" "$T/p_size"
expect "kernel A size field altered -> hash/sig FAIL, recovery" "$T/p_size" "Kernel (hash|signature) +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
refuse "kernel A size field altered -> no exception" "$T/p_size" "QVault Exception"
corrupt stage2a payload; boot "$T/f.img" "$T/s2"
expect "stage2 A tampered -> Stage 1 recovers to B" "$T/s2" "Stage-2 hash +FAIL" "Trying backup slot B" "SECURE BOOT SUCCESS"
corrupt kernela payload; cp "$T/f.img" "$T/g1.img"; scripts/corrupt_image.sh "$T/g1.img" kernelb payload "$T/g2.img" >/dev/null; cp "$T/f.img.pflash" "$T/g2.img.pflash"
boot "$T/g2.img" "$T/both"
expect "both kernel slots bad -> recovery halt" "$T/both" "Entering recovery mode"
refuse "both kernel slots bad -> kernel never runs" "$T/both" "SECURE BOOT SUCCESS|\[KERNEL\]"

# ---------------------------------------------------------------- 2. DTB authentication (structure != trust)
corrupt dtba payload2; boot "$T/f.img" "$T/d1"
expect "DTB A modified -> hash FAIL, recovery to DTB B" "$T/d1" "Device Tree hash +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
# Valid-structure DTB with different CONTENT (RAM size halved), injected without re-signing, in both slots.
dtc -q -I dtb -O dts build/virt.dtb 2>/dev/null | python3 -c "
import sys,re
t=sys.stdin.read()
m=re.search(r'(memory@40000000 \{.*?reg = <0x00 0x40000000 0x00 )0x40000000', t, re.S)
assert m, 'memory node not found'
sys.stdout.write(t[:m.start()]+m.group(1)+'0x20000000'+t[m.end():])" | dtc -q -I dts -O dtb -o "$T/alt.dtb" 2>/dev/null
if [ -s "$T/alt.dtb" ] && ! cmp -s "$T/alt.dtb" build/virt.dtb; then
    cp "$REF" "$T/inj.img"; cp "$REF.pflash" "$T/inj.img.pflash"
    for off in $((0x600000+256)) $((0x700000+256)); do dd if="$T/alt.dtb" of="$T/inj.img" bs=1 seek=$off conv=notrunc status=none; done
    boot "$T/inj.img" "$T/d2"
    expect "structurally VALID but unsigned DTB (both slots) -> rejected" "$T/d2" "Device Tree hash +FAIL" "Entering recovery mode"
    refuse "structurally valid but unsigned DTB -> kernel never runs" "$T/d2" "SECURE BOOT SUCCESS|\[KERNEL\]"
else echo "FAIL  could not build alternate DTB for injection test"; fail=$((fail+1)); note FAIL "alt DTB build"; fi
# Attacker re-signs the DTB with their OWN key hierarchy (valid signature, untrusted root).
KEYDIR=$T/attacker scripts/gen_keys.sh
DTB_KEYDIR=$T/attacker mkflash "$T/atk.img" env DTB_KEYDIR=$T/attacker
boot "$T/atk.img" "$T/d3"
expect "DTB signed by attacker key -> certificate FAIL, halt" "$T/d3" "Device Tree key certificate +FAIL" "Entering recovery mode"
refuse "DTB signed by attacker key -> kernel never runs" "$T/d3" "SECURE BOOT SUCCESS|\[KERNEL\]"
# Authentic but malformed: legitimately signed garbage must still be rejected by structural validation.
python3 - "$T" <<'PY'
import sys; T=sys.argv[1]; d=bytearray(open('build/virt.dtb','rb').read())
open(T+'/badmagic.dtb','wb').write(bytes([d[0]^0xff])+bytes(d[1:]))        # bad magic
open(T+'/trunc.dtb','wb').write(bytes(d[:len(d)//2]))                       # truncated (totalsize > blob)
o=bytearray(d); o[4:8]=(0xFFFFFFF0).to_bytes(4,'big'); open(T+'/oversize.dtb','wb').write(bytes(o))   # oversized totalsize
PY
for v in badmagic trunc oversize; do
    mkflash "$T/m_$v.img" env DTB="$T/$v.dtb"; boot "$T/m_$v.img" "$T/m_$v"
    expect "authentic-but-malformed DTB ($v) -> signature OK, validation FAIL" "$T/m_$v" "Device Tree signature +OK" "Device Tree validation +FAIL" "Entering recovery mode"
    refuse "authentic-but-malformed DTB ($v) -> kernel never runs" "$T/m_$v" "SECURE BOOT SUCCESS|\[KERNEL\]"
done
mkflash "$T/dr.img" env DA_VER=2 DB_VER=2; boot "$T/dr.img" "$T/d4"
expect "DTB older than rollback floor -> rejected" "$T/d4" "Device Tree anti-rollback +FAIL" "Entering recovery mode"

# ---------------------------------------------------------------- 3. revocation
mkflash "$T/rk.img" env REVOKE_KEY=2; boot "$T/rk.img" "$T/r1"
expect "revoked UEFI signing key -> rejected (valid signature, revoked)" "$T/r1" "UEFI image signature +OK|UEFI image hash +OK" "UEFI image revocation +FAIL" "revoked" "Entering recovery mode"
refuse "revoked key -> kernel never runs" "$T/r1" "SECURE BOOT SUCCESS|\[KERNEL\]"
mkflash "$T/rk2.img" env REVOKE_KEY=9; boot "$T/rk2.img" "$T/r2"
expect "revoking an unrelated key does not block boot" "$T/r2" "SECURE BOOT SUCCESS"
{ cat build/payloads/kernel.bin; printf '\0\0\0\0'; } > "$T/kernel_vuln.bin"
mkflash "$T/rh.img" env KA_PAYLOAD="$T/kernel_vuln.bin" REVOKE_PAYLOAD="$T/kernel_vuln.bin"; boot "$T/rh.img" "$T/r3"
expect "validly signed kernel with REVOKED hash -> rejected, falls back to B" "$T/r3" "Kernel revocation +FAIL" "Booting slot B" "SECURE BOOT SUCCESS"
mkflash "$T/rh2.img" env KA_PAYLOAD="$T/kernel_vuln.bin"; boot "$T/rh2.img" "$T/r4"
expect "same kernel, hash NOT revoked -> accepted from slot A" "$T/r4" "Kernel signature +OK" "SECURE BOOT SUCCESS"
refuse "same kernel, hash not revoked -> no fallback needed" "$T/r4" "Trying backup slot"

# ---------------------------------------------------------------- 4. rollback with PERSISTENCE across reboots
cp "$REF" "$T/v13.img"; cp "$REF.pflash" "$T/pers.pflash"
boot "$T/v13.img" "$T/pb1" "$T/pers.pflash"
expect "persistence 1/4: kernel v13 boots and commits its version" "$T/pb1" "SECURE BOOT SUCCESS"
mkflash "$T/old.img" env KA_VER=12 KB_VER=12                      # only older (but validly signed) kernels
boot "$T/old.img" "$T/pb2" "$T/pers.pflash"
expect "persistence 2/4: validly signed older kernel rejected after reboot" "$T/pb2" "Kernel anti-rollback +FAIL" "rollback rejected" "Entering recovery mode"
boot "$T/old.img" "$T/pb3" "$T/pers.pflash"
expect "persistence 3/4: still rejected after another reboot" "$T/pb3" "Kernel anti-rollback +FAIL|no usable|Entering recovery mode"
refuse "persistence 4/4: older kernel never executes" "$T/pb3" "SECURE BOOT SUCCESS|\[KERNEL\]"
boot "$T/old.img" "$T/pb4"                                        # control: FRESH state accepts it => rejection came from stored state
expect "control: same old image with fresh pflash boots (state, not image, caused the rejection)" "$T/pb4" "SECURE BOOT SUCCESS"

# ---------------------------------------------------------------- 5. secure store / lifecycle
corrupt store magic; boot "$T/f.img" "$T/st"
expect "secure store corrupted -> fail closed" "$T/st" "Secure storage +FAIL"
refuse "secure store corrupted -> no boot" "$T/st" "SECURE BOOT SUCCESS"
mkflash "$T/prod.img" env LIFECYCLE=prod; boot "$T/prod.img" "$T/lc"
expect "PROD lifecycle: OS lock set and read back, boot continues" "$T/lc" "Debug policy +PROD \(OS lock set\)" "SECURE BOOT SUCCESS"
expect "DEV lifecycle announced in baseline" "$T/base" "Debug policy +DEV \(debug enabled\)"

# ---------------------------------------------------------------- 6. entry exception levels
for el in 2 3; do QV_EL=$el boot "$REF" "$T/el$el"; expect "boot from EL$el" "$T/el$el" "AArch64 initialization +OK" "SECURE BOOT SUCCESS"; done

echo; echo "integration: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
