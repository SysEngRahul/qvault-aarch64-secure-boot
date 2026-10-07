#ifndef QV_DEBUG_H
#define QV_DEBUG_H
#include <stdbool.h>
#include "storage.h"
/* Apply the lifecycle's debug policy. PROD: set the AArch64 OS Lock (OSLAR_EL1) and clear
 * MDSCR_EL1 debug-enable bits so self-hosted debug exceptions (breakpoints/watchpoints/
 * single-step) cannot be raised by software at lower levels. Returns true if the lock is
 * observably set (OSLSR_EL1.OSLK) or, for DEV, if debug was intentionally left enabled.
 *
 * NOT a hardware debug lock: external debuggers (JTAG/CoreSight) are gated by SoC fuses/
 * DBGAUTHSTATUS signals that QEMU does not model, and the QEMU gdbstub sits outside the guest. */
bool qv_debug_apply(qv_lifecycle_t lc);
#endif
