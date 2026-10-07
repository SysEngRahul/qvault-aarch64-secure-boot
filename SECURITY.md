# Security policy

QVault is an **educational / research prototype**. It is not production firmware and must not protect anything of value.

## Reporting
Open a private security advisory on GitHub (Security → Report a vulnerability) or email the maintainer. Please include
a reproducer (a flash image or `scripts/corrupt_image.sh` invocation is ideal).

## Security goals (what the code tries to guarantee in QEMU)
Unauthenticated, tampered, malformed, revoked, or older-than-floor images are not executed; hostile DTB/image/PE input
must not crash the parsers; a failed image falls back to the other slot or halts.

## Assumptions
* The attacker can modify image storage and (separately) the persistent store file, but cannot obtain private signing keys
  and cannot break SHA-256 / Ed25519.
* **Software-modeled root of trust:** Stage 1 is *not* authenticated (QEMU has no Boot ROM). The root public key is compiled
  into the firmware.

## Limitations (read before relying on anything)
* The persistent store (rollback floors, slot state, revocation lists, **lifecycle DEV/PROD**) is an ordinary file/flash
  region with no integrity or access protection. Anyone who can write it can lower counters, clear revocations or switch to DEV.
* No hardware root of trust, no fuses, no TPM, no TrustZone, no hardware debug lock. The PROD "OS lock" is an architectural
  register write that QEMU honours; it proves nothing about SoC debug fuses.
* Measured boot is a software log without attestation or signing.
* No side-channel or fault-injection (glitching) resistance beyond what Monocypher provides.
* Not implemented: EDK II/UEFI Secure Boot, key rotation, watchdog recovery, secure update transport.

## Key handling
* `keys/` is git-ignored and must never be committed. `root.key` is the root of trust: in any real use it belongs in an HSM.
* Only public keys (`root.pub`, `*.pub`) and certificates are non-secret. Test keys are generated locally per machine.
* **CI/release keys are ephemeral test keys** generated on the runner. Release artifacts are labelled
  "CI TEST KEY — NOT A PRODUCTION TRUST ANCHOR".

## Development vs production lifecycle
`DEV` (default): debug allowed, announced at boot. `PROD`: Stage 1 sets the AArch64 OS Lock and clears `MDSCR_EL1`
debug-enable bits, then reads `OSLSR_EL1` back and halts if the lock is not observable. Unknown/corrupt lifecycle values
resolve to `PROD`. The QEMU gdbstub is outside the guest and is unaffected by either mode.
