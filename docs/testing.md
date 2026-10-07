# Testing

Every claim in the README maps to one of these. Run `make verify` to execute all of them from a clean tree and regenerate
`docs/VERIFICATION.md` (counts and per-scenario results are taken from the tools' own output).

| Level | Command | What it covers |
|---|---|---|
| Unit (host, ASan+UBSan) | `make unit` | SHA-256 NIST vectors, RFC 8032 Ed25519, image parse/verify incl. every header byte flipped, rollback, PCR extend, slots/update, DTB, **DTB authentication**, **revocation/lifecycle**, **PE/COFF** |
| Static analysis | `make lint` | cppcheck + clang-tidy (bugprone, cert, analyzer); fails on any finding |
| Fuzzing | `make fuzz` / `make negative` | mutation fuzzing of DTB, image and PE parsers under ASan+UBSan. **Not coverage-guided.** libFuzzer entry point exists (`LLVMFuzzerTestOneInput`) but has not been run |
| QEMU integration | `make integration` | boots the real firmware per scenario on fresh flash+pflash copies: tamper, recovery, DTB authentication, revocation, persistent rollback across reboots, store corruption, lifecycle, EL1/EL2/EL3 entry |
| Reproducibility | `make repro` | two clean builds with the same keys → byte-identical firmware, flash and pflash; different root key → firmware differs (expected) |
| Manifest / SBOM | `make manifest`, `make sbom` | signature + chain-to-root + content hashes (with tamper checks); SBOM validated with `pyspdxtools` |
| Debugger | `make gdb-demo` | scripted GDB session (transcript in `docs/gdb-session.txt`) |
| TCB | `make tcb` | per-component linked size from the linker maps (`docs/tcb.md`) |

**Test discipline:** each security feature has a valid case, a tampered/malformed case, a boundary case, and (where relevant)
a rollback/overflow case. The rule for the integration suite is that hostile input ends in REJECT/RECOVER/HALT — never a
crash and never execution of unverified code. Tests start from a pristine reference image because the firmware *writes*
the pflash (a manual boot changes rollback floors).

**Not done:** code-coverage measurement, coverage-guided fuzzing, MISRA checking, hardware testing, a QEMU scenario that
installs a PENDING image through the update manager.
