#!/usr/bin/env python3
"""Generate build/manifest.json describing every boot artefact in build/flash.img.
Deterministic (no timestamps). Signed separately by scripts/sign_manifest.sh.
Fields per artefact: slot, type, version, key_id, load/entry, payload size, SHA-256 of payload, SHA-256 of the
whole signed slot image. Also records Stage 1 / Stage 2 build outputs and the toolchain."""
import hashlib, json, struct, subprocess, sys, os
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(root)
SLOTS = [('stage2', 'A', 0x000000), ('stage2', 'B', 0x100000), ('uefi', 'A', 0x200000), ('uefi', 'B', 0x300000),
         ('kernel', 'A', 0x400000), ('kernel', 'B', 0x500000), ('dtb', 'A', 0x600000), ('dtb', 'B', 0x700000)]
flash = open('build/flash.img', 'rb').read()
arts = []
for name, slot, off in SLOTS:
    hdr = flash[off:off + 248]
    (magic, hv, hs, typ, ver, load, entry, psize, halg, salg, kid, role, flags) = struct.unpack_from('<IHHIIQQIIIIII', hdr)
    assert magic == 0x544C5651, f'{name}/{slot}: bad magic'
    payload = flash[off + 256: off + 256 + psize]
    arts.append({'name': name, 'slot': slot, 'image_type': typ, 'fw_version': ver, 'signing_key_id': kid, 'key_role': role,
                 'load_addr': hex(load), 'entry_point': hex(entry), 'payload_size': psize,
                 'payload_sha256': hashlib.sha256(payload).hexdigest(),
                 'declared_payload_sha256': hdr[56:88].hex(),
                 'image_sha256': hashlib.sha256(flash[off:off + 256 + psize]).hexdigest()})
    assert arts[-1]['payload_sha256'] == arts[-1]['declared_payload_sha256'], 'header hash != payload hash'
sh = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()
try:
    gcc = subprocess.run(['aarch64-linux-gnu-gcc', '--version'], capture_output=True, text=True).stdout.splitlines()[0]
except Exception:
    gcc = 'unknown'
try:
    build_id = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
except Exception:
    build_id = 'uncommitted'
m = {'format': 'qvault-manifest-1', 'build_id': build_id, 'toolchain': gcc,
     'build_outputs': {'stage1.elf': sh('build/stage1.elf'), 'stage2.bin': sh('build/stage2.bin'), 'virt.dtb': sh('build/virt.dtb')},
     'artifacts': arts}
open('build/manifest.json', 'w').write(json.dumps(m, indent=2, sort_keys=True) + '\n')
print(f'manifest: {len(arts)} artefacts -> build/manifest.json')
