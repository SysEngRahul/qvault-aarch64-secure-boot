#!/usr/bin/env python3
"""Generate build/qvault.spdx.json (SPDX 2.3, JSON). Deterministic: no timestamps beyond a fixed epoch."""
import hashlib, json, os, subprocess
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(root)
def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()
def sha1(p): return hashlib.sha1(open(p, 'rb').read()).hexdigest()   # SPDX mandates SHA-1 for files
# SPDX package verification code: SHA-1 over the sorted, concatenated file SHA-1s
vcode = hashlib.sha1(''.join(sorted(sha1(f) for f in [f'third_party/monocypher/{n}' for n in ('monocypher.c','monocypher.h','monocypher-ed25519.c','monocypher-ed25519.h')])).encode()).hexdigest()
def run(*c):
    try: return subprocess.run(c, capture_output=True, text=True, check=True).stdout.strip().splitlines()[0]
    except Exception: return 'unknown'
mc = 'third_party/monocypher'
files = [f'{mc}/{n}' for n in ('monocypher.c', 'monocypher.h', 'monocypher-ed25519.c', 'monocypher-ed25519.h')]
rev = run('git', 'rev-parse', 'HEAD')
doc = {
  'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT', 'name': 'qvault-sbom',
  'documentNamespace': f'https://github.com/SysEngRahul/qvault/spdx/{rev}',
  'creationInfo': {'created': '2023-11-14T22:13:20Z', 'creators': ['Tool: qvault-scripts/gen_sbom.py'],
                   'comment': 'created field is a fixed epoch so the SBOM is reproducible'},
  'packages': [
    {'SPDXID': 'SPDXRef-qvault', 'name': 'qvault', 'versionInfo': rev, 'downloadLocation': 'NOASSERTION',
     'filesAnalyzed': False, 'licenseConcluded': 'MIT', 'licenseDeclared': 'MIT', 'copyrightText': 'NOASSERTION',
     'primaryPackagePurpose': 'FIRMWARE'},
    {'SPDXID': 'SPDXRef-monocypher', 'name': 'monocypher', 'versionInfo': '4.0.2',
     'downloadLocation': 'https://github.com/LoupVaillant/Monocypher/tree/4.0.2', 'filesAnalyzed': True,
     'packageVerificationCode': {'packageVerificationCodeValue': vcode},
     'licenseInfoFromFiles': ['BSD-2-Clause', 'CC0-1.0'],
     'licenseConcluded': 'BSD-2-Clause OR CC0-1.0', 'licenseDeclared': 'BSD-2-Clause OR CC0-1.0', 'copyrightText': 'NOASSERTION',
     'comment': 'Vendored in third_party/monocypher; Ed25519 + SHA-512. Per-file hashes in the files section.'},
    {'SPDXID': 'SPDXRef-gcc-aarch64', 'name': 'gcc-aarch64-linux-gnu', 'versionInfo': run('aarch64-linux-gnu-gcc', '-dumpfullversion'),
     'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION'},
    {'SPDXID': 'SPDXRef-qemu', 'name': 'qemu-system-aarch64', 'versionInfo': run('qemu-system-aarch64', '--version').replace('QEMU emulator version ', '').split()[0],
     'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION'},
    {'SPDXID': 'SPDXRef-dtc', 'name': 'device-tree-compiler', 'versionInfo': run('dtc', '--version').replace('Version: DTC ', ''),
     'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION'},
  ],
  'files': [{'SPDXID': f'SPDXRef-File-{i}', 'fileName': f, 'checksums': [{'algorithm': 'SHA1', 'checksumValue': sha1(f)}, {'algorithm': 'SHA256', 'checksumValue': sha(f)}],
             'licenseInfoInFiles': ['BSD-2-Clause', 'CC0-1.0'],
             'licenseConcluded': 'BSD-2-Clause OR CC0-1.0', 'copyrightText': 'NOASSERTION'} for i, f in enumerate(files)],
  'relationships': [
    {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-qvault'},
    {'spdxElementId': 'SPDXRef-qvault', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'SPDXRef-monocypher'},
    {'spdxElementId': 'SPDXRef-gcc-aarch64', 'relationshipType': 'BUILD_TOOL_OF', 'relatedSpdxElement': 'SPDXRef-qvault'},
    {'spdxElementId': 'SPDXRef-dtc', 'relationshipType': 'BUILD_TOOL_OF', 'relatedSpdxElement': 'SPDXRef-qvault'},
    {'spdxElementId': 'SPDXRef-qemu', 'relationshipType': 'TEST_TOOL_OF', 'relatedSpdxElement': 'SPDXRef-qvault'},
  ] + [{'spdxElementId': 'SPDXRef-monocypher', 'relationshipType': 'CONTAINS', 'relatedSpdxElement': f'SPDXRef-File-{i}'} for i in range(len(files))],
}
open('build/qvault.spdx.json', 'w').write(json.dumps(doc, indent=2) + '\n')
print('sbom: build/qvault.spdx.json')
