#!/usr/bin/env bash
# Reproducibility evidence.
#  A) SAME keys, two from-scratch builds           -> firmware AND signed flash images must be byte-identical.
#  B) DIFFERENT root key, otherwise same source    -> firmware is EXPECTED to differ (the root public key is
#     compiled into the verifier). Reported so nobody mistakes "reproducible" for "key independent".
# Keys are moved aside and restored on exit; nothing in keys/ is modified permanently.
set -euo pipefail
cd "$(dirname "$0")/.."
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}
SAVE=$(mktemp -d); [ -d keys ] && cp -a keys/. "$SAVE/"
restore() { rm -rf keys; mkdir -p keys; cp -a "$SAVE/." keys/ 2>/dev/null || true; rm -rf "$SAVE"; }
trap restore EXIT
art() { sha256sum build/stage1.elf build/stage2.bin build/flash.img build/flash.img.pflash | sed 's#build/##'; }
fullbuild() { make -s clean >/dev/null; make -s all >/dev/null 2>&1; }

[ -f keys/root.key ] || { make -s tools >/dev/null; scripts/gen_keys.sh; }
fullbuild; A=$(art); sleep 1; fullbuild; B=$(art)
echo "== A) same keys, two clean builds =="; echo "$A" | sed 's/^/  build1 /'; echo "$B" | sed 's/^/  build2 /'
if [ "$A" = "$B" ]; then echo "A: REPRODUCIBLE (all 4 artefacts identical)"; else echo "A: NOT reproducible"; exit 1; fi

rm -rf keys; mkdir -p keys; make -s tools >/dev/null 2>&1 || true; scripts/gen_keys.sh
fullbuild; C=$(art)
echo "== B) different root key =="; echo "$C" | sed 's/^/  newkey /'
S1A=$(echo "$A" | grep stage1.elf | cut -d' ' -f1); S1C=$(echo "$C" | grep stage1.elf | cut -d' ' -f1)
[ "$S1A" != "$S1C" ] && echo "B: firmware differs with a different root key (expected: root pubkey is embedded)" \
                     || { echo "B: UNEXPECTED: firmware identical across root keys"; exit 1; }
