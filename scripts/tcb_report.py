#!/usr/bin/env python3
"""TCB size report. Methodology (see docs/tcb.md):

 * Input: the linker maps of the two firmware stages (so --gc-sections is already applied: only code
   that is actually linked in is counted).
 * Every linked object file is classified by ROLE, not by which stage it is in:
     TCB      = code whose bug could let unauthenticated/untrusted content execute, defeat a
                verification/rollback/revocation decision, corrupt measurements, or break the
                memory-protection boundary.
     NON-TCB  = linked but has no decision authority (console I/O, formatting, status strings).
 * Size = .text + .rodata + .data contributions of that object (bytes). .bss/stack excluded.
 * "Third-party" (Monocypher) is reported separately: it is TCB but not our code.
Host tools, tests and the update manager (not linked into firmware) are NOT in the TCB of the boot path.
"""
import re, sys, collections, subprocess, os

TCB = {  # object path fragment -> reason
 'boot/start':            'reset/EL drop, stack, VBAR',
 'boot/vectors':          'exception vector table',
 'boot/exceptions':       'exception context save/restore',
 'bootflow/stage1':       'Stage 1 control flow',
 'bootflow/stage2':       'Stage 2 control flow',
 'bootflow/boot_policy':  'slot selection / fail-over / halt policy',
 'bootflow/image_loader': 'copy image to load address',
 'bootflow/recovery':     'halt-on-failure path',
 'format/image_parser':   'untrusted header parsing',
 'security/image_verify': 'hash + cert + signature decision',
 'security/secure_boot':  'verification orchestration',
 'security/key_store':    'root of trust (root pubkey)',
 'security/crypto_backend': 'crypto glue',
 'security/rollback':     'anti-rollback decision',
 'security/measurement':  'measured boot / PCR extend',
 'storage/qemu_storage':  'counters, revocation, lifecycle, slots',
 'platform/qemu_virt/pflash': 'persistent-state driver',
 'recovery/slot_manager': 'A/B state machine',
 'dtb/dtb_validate':      'untrusted DTB structure validation',
 'dtb/dtb_parser':        'DTB reader (RAM description)',
 'arch/arm64/mmu':        'W^X page-table enforcement',
 'arch/arm64/cache':      'cache maintenance for code loading',
 'arch/arm64/exception':  'fault handling',
 'arch/arm64/debug':      'debug policy',
 'lib/sha256':            'hash used for verification',
 'lib/string':            'memcpy/memset/memcmp used by every TCB function',
}
THIRD = ('third_party/monocypher',)
NONTCB = {'platform/qemu_virt/uart': 'console', 'lib/log': 'formatting', 'lib/status': 'error strings',
          'recovery/update_manager': 'linked then gc-removed in the boot path'}

def parse(map_path):
    txt = open(map_path, errors='replace').read()
    txt = txt[txt.index('Linker script and memory map'):]
    sizes = collections.Counter()
    lines = txt.splitlines()
    i = 0
    sec_re = re.compile(r'^ (\.\S+)\s*(0x[0-9a-f]+)?\s*(0x[0-9a-f]+)?\s*(\S+\.o)?\s*$')
    while i < len(lines):
        m = sec_re.match(lines[i])
        if m and m.group(1).split('.')[1] in ('text', 'rodata', 'data', 'sdata', 'srodata'):
            addr, size, obj = m.group(2), m.group(3), m.group(4)
            if not size:   # name on its own line; values on the next
                n = re.match(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)\s*$', lines[i + 1]) if i + 1 < len(lines) else None
                if n: addr, size, obj = n.groups(); i += 1
            if size and obj and int(size, 16) > 0:
                sizes[obj] += int(size, 16)
        i += 1
    return sizes

def classify(obj):
    o = obj.replace('.o', '')
    for k in TCB:
        if o.endswith(k): return 'TCB', k
    for k in THIRD:
        if k in o: return 'THIRD', k
    for k in NONTCB:
        if o.endswith(k): return 'NON', k
    return 'UNCLASSIFIED', o

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = []; tot = {}
    for stage, mp in (('Stage 1', 'build/stage1.map'), ('Stage 2', 'build/stage2.map')):
        sizes = parse(os.path.join(root, mp))
        rows = collections.defaultdict(lambda: [0, None])
        for obj, sz in sizes.items():
            cls, key = classify(obj)
            rows[(cls, key)][0] += sz
        agg = collections.Counter()
        for (cls, key), (sz, _) in rows.items(): agg[cls] += sz
        tot[stage] = agg
        out.append(f'\n### {stage}  (linked .text+.rodata+.data after --gc-sections)\n')
        out.append('| Class | Component | Bytes | Why |')
        out.append('|---|---|---:|---|')
        for (cls, key), (sz, _) in sorted(rows.items(), key=lambda kv: (kv[0][0], -kv[1][0])):
            why = TCB.get(key) or NONTCB.get(key) or ('vendored Ed25519/SHA-512' if cls == 'THIRD' else '')
            out.append(f'| {cls} | `{key}` | {sz} | {why} |')
        unk = [k for (c, k) in rows if c == 'UNCLASSIFIED']
        if unk: print('UNCLASSIFIED objects (fix tcb_report.py):', unk, file=sys.stderr); sys.exit(1)
    out.append('\n### Summary (bytes)\n')
    out.append('| Stage | First-party TCB | Third-party TCB (Monocypher) | Total TCB | Non-TCB linked | Whole image |')
    out.append('|---|---:|---:|---:|---:|---:|')
    for stage, a in tot.items():
        t = a['TCB']; th = a['THIRD']; n = a['NON']
        out.append(f'| {stage} | {t} | {th} | {t+th} | {n} | {t+th+n} |')
    # first-party TCB source lines
    loc = 0
    for k in TCB:
        for ext in ('.c', '.S'):
            for base in ('', ):
                p = os.path.join(root, k + ext)
                if os.path.exists(p): loc += sum(1 for _ in open(p))
    out.append(f'\nFirst-party TCB source: {loc} lines (C/asm, incl. comments; headers excluded). '
               f'Stages share most objects, so the two stage columns overlap; they are not additive.')
    print('\n'.join(out))
main()
