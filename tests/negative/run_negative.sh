#!/usr/bin/env bash
# Negative tests = "hostile input must be rejected, never crash".
#  1) quick sanitizer mutation run over the DTB + image parsers (host)
#  2) the QEMU fault-injection scenarios live in tests/integration/run_qemu_tests.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
scripts/fuzz_dtb.sh 20000 7
