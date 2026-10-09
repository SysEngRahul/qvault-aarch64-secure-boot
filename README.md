# QVault — AArch64 secure-boot research prototype (QEMU)

QVault is an **educational** secure-boot chain for AArch64 that runs on QEMU `virt`. It demonstrates image
authentication, rollback protection, device-tree authentication, revocation, measured boot, A/B fail-over, parser
hardening, fault injection, fuzzing and reproducible builds — and is explicit about what is *simulated*.

> It does **not** reproduce Qualcomm (or any vendor's) proprietary boot firmware. There is **no hardware root of trust,
> no TPM, no TrustZone, no real UEFI/EDK II, and the persistent store is not tamper-resistant.** The "root of trust" is a
> *software-modeled* root public key compiled into the firmware; Stage 1 itself is not authenticated (QEMU has no Boot ROM).

## Architecture
```
 [Boot ROM: SIMULATED]  root public key compiled in
        │
        ▼
     Stage 1 ── EL3/EL2→EL1, exceptions, MMU+W^X, storage, debug policy ── authenticates ─┐
                                                                                          ▼
     Stage 2 ── authenticates UEFI(placeholder), Kernel(stub), Device Tree ── measures all ── validates DTB
        │          per image: parse → hash → certificate → signature → revocation → rollback → (else other slot / halt)
        ▼
     Kernel stub (Linux arm64 boot protocol: x0 = authenticated DTB, MMU off)
```
Details: [`docs/architecture.md`](docs/architecture.md) · threat model: [`docs/threat-model.md`](docs/threat-model.md) · limits: [`SECURITY.md`](SECURITY.md)

## Quick start (Ubuntu 24.04 / WSL)
```bash
sudo apt update
sudo apt install -y build-essential gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu qemu-system-arm device-tree-compiler
make
make run
```
`make` generates a fresh key hierarchy in `keys/` on first use (git-ignored), builds the firmware, signs every image and
creates `build/flash.img` (+ `build/flash.img.pflash`, the persistent state). `make run` boots from a throwaway copy of the
state; the kernel stub powers QEMU off by itself. (Stuck? press `Ctrl-A`, release, then `X`.)

## Tests and checks
```bash
make unit            # host unit tests under ASan+UBSan
make integration     # QEMU fault-injection suite (a few minutes)
make negative        # quick sanitizer fuzz run
make test            # unit + negative + integration
make verify          # EVERYTHING from a clean tree; regenerates docs/VERIFICATION.md (~10 min)
```
Optional tools: `sudo apt install -y cppcheck clang-tidy gdb-multiarch python3-pip && pip install --break-system-packages spdx-tools`
```bash
make lint            # cppcheck + clang-tidy, fails on any finding
make fuzz            # 200,000-iteration default budget per target is used by `make verify`; `scripts/fuzz_dtb.sh N SEED` to choose
make repro           # reproducible-build evidence
make tcb             # TCB size report
make manifest        # signed manifest, then verify it
make sbom            # SPDX SBOM + validation
make gdb-demo        # scripted GDB session
```

**Troubleshooting:** if QEMU prints nothing and a scenario hangs until its timeout, check that nothing launches it with an
interactive terminal on stdin from a background process group (`timeout qemu -nographic …` does). Use `</dev/null`
(the test scripts already do) or `timeout --foreground`. Failing integration scenarios keep their logs in
`build/integration-logs/`; `BOOT_TIMEOUT=<s>` changes the per-boot limit (default 10 s).

## Try an attack
```bash
cp build/flash.img /tmp/clean.img && cp build/flash.img.pflash /tmp/clean.img.pflash
scripts/corrupt_image.sh /tmp/clean.img kernela payload /tmp/bad.img
cp /tmp/clean.img.pflash /tmp/bad.img.pflash
scripts/run_qemu.sh /tmp/bad.img
```
Expected: `Kernel hash FAIL`, `Kernel rejected (slot A)`, `Trying backup slot B...`, then a successful boot from slot B.
(The firmware writes the `.pflash` file — rollback floors and slot state persist between runs, which is why the demo copies it.)
Other regions/fields: `scripts/corrupt_image.sh` header lists them (`stage2a … dtbb`, `magic sig cert payload …`).

## Debugging with GDB
```bash
make gdb-demo                      # scripted; transcript saved in docs/gdb-session.txt
```
Interactive: terminal 1 `GDB=1 scripts/run_qemu.sh` (paused, gdbstub on :1234); terminal 2
`gdb-multiarch build/stage1.elf -ex 'target remote :1234' -ex 'break qv_image_verify' -ex continue`.
Firmware has no CFI, so `bt`/`finish` are reliable only at function entry; `next` always works.

## Security properties — status (every status is backed by `docs/VERIFICATION.md`)
Legend: **Verified** = implemented and exercised by an automated test; **Simulated** = works but the protection is modeled;
**Host-only** = implemented/tested on the host, not in the boot path; **Partial**; **Not implemented**.

| # | Feature | Status | Evidence / caveat |
|---|---|---|---|
| 1 | Chain of trust | **Verified, software-modeled root** | Stage 1 is not authenticated; root key compiled in |
| 2 | Strict image validation | **Verified** | malformed-field scenarios, unit tests (every header byte flipped), fuzzing |
| 3 | Signature verification (Ed25519, cert chain, role binding) | **Verified** | tamper/cert/attacker-key scenarios |
| 4 | Anti-rollback | **Verified; persistent across reboot; Simulated protection** | 4-step reboot scenario + fresh-state control. Store is an unprotected file |
| 5 | DTB structural validation + fuzzing | **Verified** | bad magic/truncated/oversized; mutation fuzzing (not coverage-guided) |
| 6 | **DTB authentication** | **Verified** | unsigned-but-valid DTB and attacker-signed DTB rejected; DTB measured |
| 7 | Measured boot | **Simulated** | software PCRs + log for Stage 1/2, UEFI, Kernel, DTB; no TPM/attestation |
| 8 | Fault injection | **Verified** | see scenario table in the report |
| 9 | Reproducible build | **Verified, with conditions** | byte-identical for the same keys; firmware *differs* per root key; DTB depends on QEMU version |
| 10 | A/B slots + recovery | **Partial** | fail-over verified for all four image types; installer host-tested only; **no watchdog, no recovery image** |
| 11 | Minimal TCB | **Partial** | measured (`docs/tcb.md`), but **not partitioned**: ~91% of the Stage 2 image is TCB |
| 12 | Static analysis | **Verified** | cppcheck + clang-tidy clean; **no MISRA claim** |
| 13 | QEMU + GDB | **Verified** | scripted session, transcript committed |
| 14 | Revocation (key id, payload hash) | **Verified; Simulated protection** | lists live in the unprotected store and are not signed |
| 15 | Debug policy (DEV/PROD) | **Verified in QEMU only** | OS lock set and read back; **not** a hardware debug lock |
| 16 | PE/COFF validation | **Host-only** | unit-tested and fuzzed; not wired into the boot flow |
| 17 | Signed manifest | **Verified, host-side** | firmware does not consume it |
| 18 | SBOM | **Verified** | SPDX 2.3, validated by `pyspdxtools` |
| 19 | UEFI / EDK II | **Not implemented** | UEFI stage is a signed placeholder; see `uefi/QVaultSecurity/README.md` |

Numbers (test counts, fuzz iterations, TCB bytes, hashes) are in [`docs/VERIFICATION.md`](docs/VERIFICATION.md) and
[`docs/tcb-report.md`](docs/tcb-report.md), generated by `make verify`; they are not copied here to avoid drifting.

## Known limitations worth knowing
* After a boot raises a rollback floor, an older **backup slot can no longer boot** until the backup is refreshed.
* `INVALID` slot state is persisted; a transient failure retires a slot until reinstalled.
* A kernel that boots and then hangs is not detected (no watchdog).
* Payloads are limited to ~1 MiB per slot; the kernel is a 400-byte test stub, not Linux.

## Layout
`boot/` asm · `arch/arm64/` MMU, cache, exceptions, debug · `bootflow/` stages, policy, loader · `security/` verify, keys,
rollback, measurement · `format/` image format + PE validator · `dtb/` · `storage/` · `recovery/` · `platform/qemu_virt/` ·
`tools/` host C tools (builder, signer, inspector) · `scripts/` · `tests/` · `docs/` · `third_party/monocypher` (vendored, BSD-2/CC0).
Additions to the original plan: `lib/`, `include/`, `payloads/`, `third_party/`.

License: MIT (see `LICENSE`); Monocypher under its own terms.
