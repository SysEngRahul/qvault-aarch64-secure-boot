
### Stage 1  (linked .text+.rodata+.data after --gc-sections)

| Class | Component | Bytes | Why |
|---|---|---:|---|
| NON | `lib/log` | 2289 | formatting |
| NON | `lib/status` | 506 | error strings |
| NON | `platform/qemu_virt/uart` | 100 | console |
| TCB | `bootflow/stage1` | 2806 | Stage 1 control flow |
| TCB | `bootflow/boot_policy` | 2394 | slot selection / fail-over / halt policy |
| TCB | `boot/vectors` | 1924 | exception vector table |
| TCB | `arch/arm64/exception` | 1856 | fault handling |
| TCB | `lib/sha256` | 1200 | hash used for verification |
| TCB | `arch/arm64/mmu` | 844 | W^X page-table enforcement |
| TCB | `storage/qemu_storage` | 832 | counters, revocation, lifecycle, slots |
| TCB | `format/image_parser` | 650 | untrusted header parsing |
| TCB | `platform/qemu_virt/pflash` | 476 | persistent-state driver |
| TCB | `recovery/slot_manager` | 442 | A/B state machine |
| TCB | `boot/exceptions` | 428 | exception context save/restore |
| TCB | `security/secure_boot` | 368 | verification orchestration |
| TCB | `security/measurement` | 360 | measured boot / PCR extend |
| TCB | `arch/arm64/cache` | 332 | cache maintenance for code loading |
| TCB | `boot/start` | 304 | reset/EL drop, stack, VBAR |
| TCB | `bootflow/image_loader` | 220 | copy image to load address |
| TCB | `security/image_verify` | 208 | hash + cert + signature decision |
| TCB | `lib/string` | 160 | memcpy/memset/memcmp used by every TCB function |
| TCB | `bootflow/recovery` | 134 | halt-on-failure path |
| TCB | `security/key_store` | 112 | root of trust (root pubkey) |
| TCB | `arch/arm64/debug` | 60 | debug policy |
| TCB | `security/crypto_backend` | 60 | crypto glue |
| TCB | `security/rollback` | 56 | anti-rollback decision |
| THIRD | `third_party/monocypher` | 12216 | vendored Ed25519/SHA-512 |

### Stage 2  (linked .text+.rodata+.data after --gc-sections)

| Class | Component | Bytes | Why |
|---|---|---:|---|
| NON | `lib/log` | 2447 | formatting |
| NON | `lib/status` | 506 | error strings |
| NON | `platform/qemu_virt/uart` | 100 | console |
| TCB | `bootflow/stage2` | 3106 | Stage 2 control flow |
| TCB | `bootflow/boot_policy` | 2394 | slot selection / fail-over / halt policy |
| TCB | `boot/vectors` | 1924 | exception vector table |
| TCB | `arch/arm64/exception` | 1776 | fault handling |
| TCB | `dtb/dtb_parser` | 1396 | DTB reader (RAM description) |
| TCB | `dtb/dtb_validate` | 1288 | untrusted DTB structure validation |
| TCB | `lib/sha256` | 1200 | hash used for verification |
| TCB | `storage/qemu_storage` | 872 | counters, revocation, lifecycle, slots |
| TCB | `arch/arm64/mmu` | 796 | W^X page-table enforcement |
| TCB | `format/image_parser` | 650 | untrusted header parsing |
| TCB | `recovery/slot_manager` | 538 | A/B state machine |
| TCB | `platform/qemu_virt/pflash` | 476 | persistent-state driver |
| TCB | `boot/exceptions` | 428 | exception context save/restore |
| TCB | `arch/arm64/cache` | 396 | cache maintenance for code loading |
| TCB | `security/secure_boot` | 368 | verification orchestration |
| TCB | `security/measurement` | 364 | measured boot / PCR extend |
| TCB | `lib/string` | 228 | memcpy/memset/memcmp used by every TCB function |
| TCB | `bootflow/image_loader` | 220 | copy image to load address |
| TCB | `security/image_verify` | 208 | hash + cert + signature decision |
| TCB | `security/rollback` | 136 | anti-rollback decision |
| TCB | `bootflow/recovery` | 134 | halt-on-failure path |
| TCB | `boot/start` | 112 | reset/EL drop, stack, VBAR |
| TCB | `security/key_store` | 112 | root of trust (root pubkey) |
| TCB | `security/crypto_backend` | 60 | crypto glue |
| THIRD | `third_party/monocypher` | 12216 | vendored Ed25519/SHA-512 |

### Summary (bytes)

| Stage | First-party TCB | Third-party TCB (Monocypher) | Total TCB | Non-TCB linked | Whole image |
|---|---:|---:|---:|---:|---:|
| Stage 1 | 16226 | 12216 | 28442 | 2895 | 31337 |
| Stage 2 | 19182 | 12216 | 31398 | 3053 | 34451 |

First-party TCB source: 1756 lines (C/asm, incl. comments; headers excluded). Stages share most objects, so the two stage columns overlap; they are not additive.
