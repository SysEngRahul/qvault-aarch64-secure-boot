# Threat model

**Attacker can:** modify/replace any image in storage, modify the persistent-store file, replay old *validly signed*
images, supply malformed headers/DTBs/PE files, interrupt updates, read the serial log.
**Attacker cannot:** break SHA-256 or Ed25519, obtain private signing keys, change the compiled-in root public key / Stage 1
(the simulated ROM), or execute before Stage 1.

| Threat | Defence | Evidence (scenario names in `docs/VERIFICATION.md`) |
|---|---|---|
| Modified payload | SHA-256 bound into the signed header | "kernel A payload flipped", "stage2 A tampered" |
| Modified header / forged signature | Ed25519 over header | "header field flipped", "signature flipped" |
| Unauthorised or untrusted signer | root-signed certificate; role must match image type | "key certificate flipped", "DTB signed by attacker key" |
| **Valid-but-unauthentic DTB** (well-formed tree, wrong content) | DTB is an authenticated image; parsed only *after* authentication | "structurally VALID but unsigned DTB", unit `test_dtb_authentication` |
| **Authentic-but-malformed DTB** | structural validation after authentication | "authentic-but-malformed DTB (badmagic / trunc / oversize)" |
| Replay of older signed image | per-type monotonic floor, **persisted** | "persistence 1/4 … 4/4" + control |
| Compromised signer key / known-bad image | key-id and payload-hash deny-lists | "revoked UEFI signing key", "REVOKED hash" |
| Malformed lengths / addresses / overflow | overflow-safe parser, load windows, entry checks | malformed-field scenarios, unit tests, fuzzing |
| Malformed PE/COFF *(host-only, not wired into boot)* | `format/pe_validate.c` | unit tests, fuzzing |
| W+X memory | page permissions + `SCTLR.WXN`, hardware `AT` self-test | boot self-test line `MMU OK` |
| Unknown boot state | software measurement log | `[MEASURE]` lines |
| Corrupt/missing secure store | fail closed | "secure store corrupted" |
| Debug left on in production | lifecycle PROD → OS lock set and read back | "PROD lifecycle" scenario (QEMU only) |

## Not protected / simulated (be explicit)
* **The persistent store has no integrity or access control.** Rollback floors, slot state, revocation lists and the
  DEV/PROD lifecycle live in a file. Whoever can write it can lower counters, un-revoke keys, or switch to DEV. Persistence
  is real; *protection* is not. A real design needs fuses/RPMB/secure element.
* **Stage 1 is unauthenticated** (no Boot ROM in QEMU); the root public key is compiled in (software-modeled root of trust).
* **Revocation lists are not signed**; they inherit the store's (absent) protection.
* **Measured boot is software-only**: no TPM, no attestation, no signed quote.
* **No watchdog:** a kernel that starts and hangs is not detected or recovered.
* Not addressed: glitching/fault attacks, side channels beyond Monocypher, secure update transport, a compromised signing key
  before it is revoked, DMA attacks, physical access.
* QEMU's gdbstub is outside the guest and is not affected by the PROD debug policy.
