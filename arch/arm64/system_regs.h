/* AArch64 system-register access and the bit definitions QVault uses. */
#ifndef QV_SYSTEM_REGS_H
#define QV_SYSTEM_REGS_H

#include <stdint.h>

#define QV_READ_SYSREG(reg) __extension__ ({                 \
        uint64_t _v;                                         \
        __asm__ volatile("mrs %0, " #reg : "=r"(_v));        \
        _v; })

#define QV_WRITE_SYSREG(reg, val) do {                       \
        uint64_t _w = (uint64_t)(val);                       \
        __asm__ volatile("msr " #reg ", %0" :: "r"(_w));     \
    } while (0)

/* CurrentEL[3:2] */
static inline unsigned qv_current_el(void)
{
    return (unsigned)((QV_READ_SYSREG(CurrentEL) >> 2) & 3U);
}

/* SCTLR_EL1 */
#define SCTLR_M      (1ULL << 0)    /* MMU enable */
#define SCTLR_A      (1ULL << 1)    /* alignment check */
#define SCTLR_C      (1ULL << 2)    /* data cache */
#define SCTLR_SA     (1ULL << 3)    /* SP alignment check */
#define SCTLR_I      (1ULL << 12)   /* instruction cache */
#define SCTLR_WXN    (1ULL << 19)   /* writable => execute-never */
#define SCTLR_EE     (1ULL << 25)
#define SCTLR_EL1_RES1 0x30D00800ULL

/* TCR_EL1 (39-bit VA, 4 KiB granule, TTBR0 only) */
#define TCR_T0SZ(x)  ((uint64_t)(x))
#define TCR_IRGN0_WBWA (1ULL << 8)
#define TCR_ORGN0_WBWA (1ULL << 10)
#define TCR_SH0_INNER  (3ULL << 12)
#define TCR_TG0_4K     (0ULL << 14)
#define TCR_EPD1       (1ULL << 23)
#define TCR_IPS_SHIFT  32

/* MAIR_EL1 attribute indices */
#define MAIR_IDX_DEVICE 0U     /* Device-nGnRnE */
#define MAIR_IDX_NORMAL 1U     /* Normal, Inner/Outer Write-Back */
#define MAIR_VALUE      ((0x00ULL << (8 * MAIR_IDX_DEVICE)) | (0xFFULL << (8 * MAIR_IDX_NORMAL)))

/* ESR_ELx */
#define ESR_EC_SHIFT   26
#define ESR_EC_MASK    0x3FU
#define ESR_ISS_MASK   0x1FFFFFFULL
#define ESR_EC_UNKNOWN 0x00U
#define ESR_EC_SVC64   0x15U
#define ESR_EC_IABT_LO 0x20U
#define ESR_EC_IABT    0x21U
#define ESR_EC_PC_ALN  0x22U
#define ESR_EC_DABT_LO 0x24U
#define ESR_EC_DABT    0x25U
#define ESR_EC_SP_ALN  0x26U
#define ESR_EC_SERROR  0x2FU
#define ESR_EC_BRK64   0x3CU

/* SPSR / EL transitions */
#define SPSR_DAIF_MASK (0xFULL << 6)
#define SPSR_EL1H      0x5ULL
#define SPSR_EL2H      0x9ULL
#define SCR_EL3_NS     (1ULL << 0)
#define SCR_EL3_HCE    (1ULL << 8)
#define SCR_EL3_RW     (1ULL << 10)
#define SCR_EL3_RES1   ((1ULL << 4) | (1ULL << 5))
#define HCR_EL2_RW     (1ULL << 31)

#endif
