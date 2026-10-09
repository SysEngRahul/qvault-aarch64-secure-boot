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

**Harness integrity (added after a real failure).** On an interactive terminal the first harness reported
`15 passed, 32 failed`: `timeout` moves QEMU into a background process group, `-nographic` then touches the terminal, and
the kernel *stops* QEMU (process state `T`) before it prints a byte. CI and non-tty runs never showed it. Fixes:
QEMU is always launched with `stdin </dev/null`; its exit status is kept (`124` = timeout) instead of discarded; a scenario
only counts if the Stage 1 banner appeared (so "must not appear" checks cannot pass on an empty log); the pristine reference
image must boot before any scenario runs (otherwise exit 2, no misleading cascade); failing scenarios keep their logs in
`build/integration-logs/`. `make harness-selftest` proves this with fake QEMU binaries (silent exit-0 QEMU => 0 scenarios pass).

**Not done:** code-coverage measurement, coverage-guided fuzzing, MISRA checking, hardware testing, a QEMU scenario that
installs a PENDING image through the update manager.
