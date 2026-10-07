# Architecture, boot flow and memory map

## Trust chain (what is real, what is modeled)

```
 [Boot ROM]  ── SIMULATED: QEMU loads Stage 1 unauthenticated. There is no immutable ROM.
     │          The root PUBLIC key is compiled into Stage 1 and Stage 2 (software-modeled root of trust).
     ▼
 Stage 1 (0x40080000)  EL3/EL2→EL1, exception+MMU+W^X self-tests, storage, debug policy
     │   authenticates ──► Stage 2   (A/B)
     ▼
 Stage 2 (0x41000000)
     │   authenticates ──► UEFI image (placeholder blob), Kernel, Device Tree   (each A/B)
     │   per image:  parse → copy → hash → certificate → signature → revocation → rollback
     │   measures    ──► Stage 1, Stage 2, UEFI, Kernel, DTB  (software PCRs + event log)
     │   then validates the (already authenticated) DTB structure and cross-checks RAM ranges
     ▼
 Kernel (0x43000000)   handoff: x0 = DTB, x1..x3 = 0, MMU + D-cache off, EL1
```
The "kernel" is a ~400-byte test stub and "UEFI" is a signed placeholder. There is no EDK II and no Linux boot.

## Per-image verification pipeline (`security/secure_boot.c`)

```
 slot blob ─► parse (format, bounds, load window, entry, role)   REJECT on any failure, nothing copied
           ─► copy payload to its load address                   (verify the COPY - no TOCTOU)
           ─► SHA-256 == header hash          ┐
           ─► root-signed signer certificate  ├ all three always run so the log shows exactly what failed
           ─► Ed25519 signature over header   ┘
           ─► revocation (signer key id, payload hash)
           ─► rollback (fw_version >= stored floor)
           ─► any failure: scrub the copy, mark slot INVALID, try the other slot, else halt in recovery
 success only after the WHOLE boot: commit rollback floors, mark slots good (commit-after-success)
```
Authentic ≠ trusted ≠ safe: hash/cert/signature = *authentic*; revocation + rollback = *trusted/fresh*;
structural parsing of header, DTB (and PE, host-only) = *safe to interpret*. The DTB is authenticated **before**
it is parsed, so an unauthenticated blob never reaches the DTB parser.

## Boot output (default run)
See `docs/VERIFICATION.md` for the output captured from a real run.

## Memory map (QEMU virt, `-m 1G`)
| Range | Use |
|---|---|
| 0x04000000 | pflash bank 1: persistent store (counters, slot state, revocation lists, lifecycle) in sector 0 |
| 0x09000000 | PL011 UART (device mapping) |
| 0x40080000 | Stage 1: text RX, rodata RO, data/bss/stack RW+XN (4 KiB-aligned sections; `SCTLR.WXN` set) |
| 0x41000000–0x417FFFFF | Stage 2 load window |
| 0x42000000–0x427FFFFF | UEFI window |
| 0x43000000–0x43FFFFFF | Kernel window |
| 0x44000000–0x440FFFFF | authenticated DTB (1 MiB window) |
| 0x44100000 | measurement log (`qv_meas_state_t`, magic "QSEM") handed to the OS |
| 0x60000000–0x607FFFFF | simulated image storage via `-device loader` (NOT persisted): S2 A/B, UEFI A/B, Kernel A/B, DTB A/B, 1 MiB slots |

Identity map (VA=PA), 39-bit VA, L1→L2(2 MiB)→L3(4 KiB, split on demand). Slots are 1 MiB, so payloads are ≤ 1 MiB − 256 B.

## Image format (`format/image_format.h`)
256-byte header (248 B struct + pad) then payload. Signed region = header bytes `[0,184)`, which contains SHA-256(payload).
Fields: magic, header version/size, image type, fw_version, load/entry, payload size, hash/sig alg, key id, key role, flags(=0),
payload hash, signer pubkey, root-signed certificate, signature. Type↔role binding: a UEFI key cannot sign a kernel or DTB.

## Interfaces that isolate the simulation
`storage/storage.h` (counters, slots, revocation, lifecycle), `security/crypto_backend.h`, `security/key_store.h`,
`platform/qemu_virt/*`. A real port replaces those files only.
