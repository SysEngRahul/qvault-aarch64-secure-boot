#!/usr/bin/env bash
# Proves the integration harness cannot be fooled by a QEMU that does not run the firmware.
# We put fake `qemu-system-aarch64` binaries first on PATH and require the harness to FAIL (never pass).
#   case 1: QEMU "succeeds" (exit 0) but prints nothing at all     -> harness must abort at its precondition (exit 2)
#   case 2: QEMU boots once (precondition passes), then goes silent -> EVERY scenario must fail, including the
#           "must NOT appear" ones, so zero tests may pass and the exit status must be non-zero.
set -uo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/silent" "$T/once"
printf '#!/bin/sh\nexit 0\n' > "$T/silent/qemu-system-aarch64"
cat > "$T/once/qemu-system-aarch64" <<EOS
#!/bin/sh
# first launch: pretend to be a successful boot; every later launch: silent exit 0
if [ ! -f "$T/once/used" ]; then
  touch "$T/once/used"; echo "        QVAULT SECURE BOOT"; echo "        SECURE BOOT SUCCESS"
fi
exit 0
EOS
chmod +x "$T"/*/qemu-system-aarch64
ok=0; bad=0
chk() { if [ "$2" = ok ]; then echo "PASS  harness self-test: $1"; ok=$((ok+1)); else echo "FAIL  harness self-test: $1"; bad=$((bad+1)); fi; }

PATH="$T/silent:$PATH" BOOT_TIMEOUT=3 QV_TEST_LOGS="$T/logs1" tests/integration/run_qemu_tests.sh > "$T/o1" 2>&1 < /dev/null; rc=$?
[ $rc -eq 2 ] && grep -q "PRECONDITION FAILED" "$T/o1" && ! grep -q '^PASS' "$T/o1" && chk "silent QEMU aborts at precondition (rc=2, no PASS lines)" ok || chk "silent QEMU aborts at precondition (rc=$rc)" bad

PATH="$T/once:$PATH" BOOT_TIMEOUT=3 QV_TEST_LOGS="$T/logs2" tests/integration/run_qemu_tests.sh > "$T/o2" 2>&1 < /dev/null; rc=$?
passes=$(grep -c '^PASS' "$T/o2"); fails=$(grep -c '^FAIL' "$T/o2")
[ $rc -ne 0 ] && [ "$passes" -eq 0 ] && [ "$fails" -gt 40 ] && grep -q "NO BOOT BANNER" "$T/o2" \
    && chk "QEMU that goes silent: $fails scenarios FAIL, $passes pass (negative tests cannot pass vacuously)" ok \
    || chk "QEMU that goes silent: rc=$rc passes=$passes fails=$fails" bad
[ -n "$(ls "$T/logs2" 2>/dev/null)" ] && chk "failing scenarios keep their logs" ok || chk "failing scenarios keep their logs" bad
echo "harness self-test: $ok passed, $bad failed"
[ "$bad" -eq 0 ]
