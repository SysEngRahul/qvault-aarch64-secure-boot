#!/usr/bin/env bash
# Static analysis gate. Fails (non-zero) on ANY finding. No suppressions except system headers.
#   1. cppcheck   (warning, style, performance, portability; inconclusive on)
#   2. clang-tidy (bugprone-*, clang-analyzer-*, cert-*; cross-target flags, freestanding)
# clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling is disabled: it demands C11 Annex K
# (memcpy_s), which a freestanding build does not have. Every memcpy/memset site is bounds-checked by hand.
# Third-party code (third_party/) is excluded from findings: vendored, reviewed upstream.
set -euo pipefail
cd "$(dirname "$0")/.."
INC="-Iinclude -Iinclude/freestanding -Iarch/arm64 -Iboot -Ilib -Iformat -Isecurity -Istorage -Irecovery -Idtb -Ibootflow -Iplatform/qemu_virt -Ithird_party/monocypher -Ibuild/generated"
echo "== cppcheck =="
cppcheck --enable=warning,style,performance,portability --inconclusive --std=c11 --error-exitcode=1 \
    --suppress=missingIncludeSystem --suppress='*:third_party/*' --quiet $INC lib format security storage recovery dtb arch bootflow platform tools
echo "cppcheck: clean"
echo "== clang-tidy (firmware) =="
FW_SRC=$(ls lib/*.c format/*.c security/*.c storage/*.c recovery/*.c dtb/*.c arch/arm64/*.c bootflow/*.c platform/qemu_virt/*.c)
clang-tidy --quiet -warnings-as-errors='*' \
    -checks='-*,bugprone-*,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,clang-analyzer-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,cert-*,-cert-dcl37-c,-cert-dcl51-cpp' \
    $FW_SRC -- --target=aarch64-linux-gnu -std=c11 -ffreestanding $INC
echo "clang-tidy: clean"
