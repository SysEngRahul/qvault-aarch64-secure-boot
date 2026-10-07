# A/B slots, recovery and update

Per image type (stage2, uefi, kernel, dtb): `active` slot, `state[A|B]` ∈ {EMPTY, VALID, PENDING, INVALID}, `tries[]`.
Persisted in the pflash store.

| Piece | Status |
|---|---|
| Slot A / B, active slot | implemented, QEMU-verified for all four image types |
| Fail-over on verification failure | implemented, QEMU-verified (tamper, revocation, rollback, bad signature → other slot) |
| Both slots bad → halt, never execute | implemented, QEMU-verified |
| Boot-attempt counter for PENDING slots | implemented; **unit-tested only** (no QEMU scenario installs a PENDING image) |
| Update installer (`recovery/update_manager.c`) | implemented; **host unit-tested only**, not invoked by the boot flow |
| Success marker (`mark_good`) | implemented, runs at end of Stage 2 |
| Watchdog / recovery after the kernel has started | **NOT implemented** (a kernel that boots and then hangs is not detected) |
| Dedicated recovery image | **NOT implemented** (recovery = the other A/B slot, or halt) |

**Update order (power-fail safety, host-tested):** authenticate in scratch → mark target EMPTY → write → re-verify →
single record write (target PENDING + active). `qv_storage_set_slot` writes the record as one unit, but the QEMU backend
persists by erase+program, so it is **not** power-fail-safe at the flash level (a cut between erase and program leaves
an invalid store → boot fails closed).

**Design consequences worth knowing**
* After a successful boot raises a rollback floor, an older backup slot can no longer boot (it is "older than the
  floor"). A real update flow must refresh the backup slot after the primary is proven good.
* `INVALID` is persisted: a slot that failed once stays unusable until an update reinstalls it. This avoids repeatedly
  executing a bad image but means a transient read error can retire a good slot.
