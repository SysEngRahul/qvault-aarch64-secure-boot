# Deviations and honesty notes

* **No MISRA compliance is claimed.** The code uses MISRA/CERT-*inspired* habits (fixed-width types, explicit bounds checks,
  no dynamic allocation or recursion in firmware) and passes `-Wall -Wextra -Wshadow -Wformat=2 -Wundef -Werror`, cppcheck and
  clang-tidy (bugprone/cert/analyzer). No MISRA checker has been run. Known deviations: inline assembly, function-pointer
  casts for entry jumps, `__builtin_clz`, volatile-free shadow access to simulated storage.
* clang-tidy's `DeprecatedOrUnsafeBufferHandling` check is disabled: it demands C11 Annex K (`memcpy_s`), unavailable in a
  freestanding build. Every `memcpy`/`memset` site is bounds-checked by hand. `third_party/` is excluded from analysis.
* Linux hardening flags (`-fstack-protector`, PIE, FORTIFY) do not apply to freestanding firmware. W^X is enforced by page
  permissions + `SCTLR.WXN`.
* `qv_keystore_test_set_root` exists only under `QV_HOST_TEST` (unit tests); not compiled into firmware.
* The DTB is QEMU-generated at build time with `rng-seed`/`kaslr-seed` stripped (determinism + weak-entropy avoidance);
  it therefore depends on the installed QEMU version. A real loader would inject entropy after authentication.
* Directory additions beyond the original plan: `lib/`, `include/`, `payloads/`, `third_party/`, `scripts/`. `boot-flow.md`
  and `memory-map.md` were merged into `architecture.md`.
* The kernel stub powers off with `hvc`; on `QV_EL=3` (no EL2) that instruction faults *after* a successful handoff.
