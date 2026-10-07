#include "debug.h"
#include "system_regs.h"
#include "barriers.h"

#define MDSCR_SS  (1ULL << 0)
#define MDSCR_KDE (1ULL << 13)
#define MDSCR_MDE (1ULL << 15)
#define OSLSR_OSLK (1ULL << 1)

bool qv_debug_apply(qv_lifecycle_t lc)
{
    if (lc != QV_LIFECYCLE_PROD) { return true; }            /* DEV: debug stays enabled by design */
    QV_WRITE_SYSREG(OSLAR_EL1, 1);                           /* lock */
    qv_isb();
    QV_WRITE_SYSREG(MDSCR_EL1, QV_READ_SYSREG(MDSCR_EL1) & ~(MDSCR_SS | MDSCR_KDE | MDSCR_MDE));
    qv_isb();
    return (QV_READ_SYSREG(OSLSR_EL1) & OSLSR_OSLK) != 0U;   /* read back: do not assume */
}
