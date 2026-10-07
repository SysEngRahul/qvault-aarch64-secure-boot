#!/usr/bin/env bash
# Sign / verify build/manifest.json with the firmware key (key_id 1, role fw), chained to the root.
# HOST-SIDE ONLY: the boot firmware does not parse or check the manifest (see docs/VERIFICATION.md).
set -euo pipefail
cd "$(dirname "$0")/.."
Q=build/tools/qvsign
case "${1:-sign}" in
  sign)   python3 scripts/gen_manifest.py
          $Q sign-blob --in build/manifest.json --key keys/fw.key --out build/manifest.json.sig
          echo "signed: build/manifest.json.sig" ;;
  verify) $Q verify-blob --in build/manifest.json --sig build/manifest.json.sig --pub "${PUB:-keys/fw.pub}" \
              --cert "${CERT:-keys/fw.cert}" --root-pub "${ROOT_PUB:-keys/root.pub}" --key-id 1 --role fw
          # Recompute the hashes the manifest claims, from the actual files.
          python3 - <<'PY'
import json, hashlib
m = json.load(open('build/manifest.json'))
for f, h in m['build_outputs'].items():
    assert hashlib.sha256(open('build/' + f, 'rb').read()).hexdigest() == h, f'{f} does not match manifest'
flash = open('build/flash.img', 'rb').read()
offs = {('stage2','A'):0,('stage2','B'):0x100000,('uefi','A'):0x200000,('uefi','B'):0x300000,('kernel','A'):0x400000,('kernel','B'):0x500000,('dtb','A'):0x600000,('dtb','B'):0x700000}
for a in m['artifacts']:
    o = offs[(a['name'], a['slot'])]
    assert hashlib.sha256(flash[o:o + 256 + a['payload_size']]).hexdigest() == a['image_sha256'], f"{a['name']}/{a['slot']} differs from manifest"
print('manifest contents match the files: OK')
PY
          ;;
esac
