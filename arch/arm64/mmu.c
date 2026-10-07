/* Identity-mapped stage-1 translation, 4 KiB granule, 39-bit VA.
 *
 *   L1 (512 x 1 GiB)  -> L2 tables (512 x 2 MiB blocks) -> optional L3 (512 x 4 KiB pages)
 *
 * Default map: 0-1 GiB device (UART etc.), 1-2 GiB RAM as RW+XN. Code and
 * rodata are then re-mapped RX / RO at page granularity. SCTLR.WXN is set so
 * the hardware itself refuses to execute anything writable (W^X). */
#include <string.h>
#include "mmu.h"
#include "system_regs.h"
#include "barriers.h"
#include "cache.h"

#define PAGE      4096UL
#define BLOCK2M   (2UL * 1024 * 1024)
#define ENTRIES   512U
#define L3_POOL   6U

#define D_VALID   (1ULL << 0)
#define D_TABLE   (1ULL << 1)            /* table (L1/L2) or page (L3) */
#define D_AF      (1ULL << 10)
#define D_SH_INNER (3ULL << 8)
#define D_AP_RO   (1ULL << 7)
#define D_PXN     (1ULL << 53)
#define D_UXN     (1ULL << 54)
#define D_ATTR(i) ((uint64_t)(i) << 2)
#define D_ADDR_MASK 0x0000FFFFFFFFF000ULL

static uint64_t l1[ENTRIES]       __attribute__((aligned(4096)));
static uint64_t l2_dev[ENTRIES]   __attribute__((aligned(4096)));
static uint64_t l2_ram[ENTRIES]   __attribute__((aligned(4096)));
static uint64_t l3_pool[L3_POOL][ENTRIES] __attribute__((aligned(4096)));
static unsigned l3_used;

static uint64_t attr_bits(qv_mmu_attr_t a)
{
    switch (a) {
    case QV_MMU_RX:  return D_ATTR(MAIR_IDX_NORMAL) | D_SH_INNER | D_AF | D_AP_RO | D_UXN;
    case QV_MMU_RO:  return D_ATTR(MAIR_IDX_NORMAL) | D_SH_INNER | D_AF | D_AP_RO | D_PXN | D_UXN;
    case QV_MMU_DEV: return D_ATTR(MAIR_IDX_DEVICE) | D_AF | D_PXN | D_UXN;
    case QV_MMU_RW:
    default:         return D_ATTR(MAIR_IDX_NORMAL) | D_SH_INNER | D_AF | D_PXN | D_UXN;
    }
}

static void tlb_flush(void)
{
    qv_dsb(ishst);
    __asm__ volatile("tlbi vmalle1" ::: "memory");
    qv_dsb(ish);
    qv_isb();
}

void qv_mmu_init(void)
{
    unsigned i;
    memset(l1, 0, sizeof l1);
    memset(l3_pool, 0, sizeof l3_pool);
    l3_used = 0;
    for (i = 0; i < ENTRIES; i++) {
        l2_dev[i] = ((uint64_t)i * BLOCK2M) | D_VALID | attr_bits(QV_MMU_DEV);
        l2_ram[i] = (0x40000000ULL + (uint64_t)i * BLOCK2M) | D_VALID | attr_bits(QV_MMU_RW);
    }
    l1[0] = (uint64_t)(uintptr_t)l2_dev | D_VALID | D_TABLE;
    l1[1] = (uint64_t)(uintptr_t)l2_ram | D_VALID | D_TABLE;
}

/* Replace a 2 MiB block descriptor by a table of 4 KiB pages with the same attributes. */
static uint64_t *split_block(uint64_t *l2e)
{
    uint64_t blk = *l2e, attrs, base;
    uint64_t *l3;
    unsigned i;

    if ((blk & (D_VALID | D_TABLE)) == (D_VALID | D_TABLE)) {
        return (uint64_t *)(uintptr_t)(blk & D_ADDR_MASK);   /* already split */
    }
    if (l3_used >= L3_POOL) { return NULL; }
    l3 = l3_pool[l3_used++];
    base = blk & 0x0000FFFFFFE00000ULL;
    attrs = blk & ~0x0000FFFFFFE00000ULL & ~(D_VALID | D_TABLE);
    for (i = 0; i < ENTRIES; i++) {
        l3[i] = (base + (uint64_t)i * PAGE) | attrs | D_VALID | D_TABLE;   /* page desc: bits[1:0]=11 */
    }
    *l2e = (uint64_t)(uintptr_t)l3 | D_VALID | D_TABLE;
    return l3;
}

qv_status_t qv_mmu_map(uintptr_t pa, size_t size, qv_mmu_attr_t attr)
{
    uint64_t bits = attr_bits(attr);
    uintptr_t end;

    if ((pa & (PAGE - 1)) || (size & (PAGE - 1)) || size == 0) { return QV_ERR_PARAM; }
    end = pa + size;
    if (end < pa || end > 0x80000000UL) { return QV_ERR_RANGE; }

    while (pa < end) {
        uint64_t *l2 = (pa < 0x40000000UL) ? l2_dev : l2_ram;
        unsigned idx = (unsigned)((pa >> 21) & 0x1FFU);
        uintptr_t blk_base = pa & ~(BLOCK2M - 1);
        if (pa == blk_base && end - pa >= BLOCK2M &&
            (l2[idx] & (D_VALID | D_TABLE)) == D_VALID) {
            l2[idx] = (uint64_t)blk_base | D_VALID | bits;           /* whole block */
            pa += BLOCK2M;
        } else {
            uint64_t *l3 = split_block(&l2[idx]);
            if (!l3) { return QV_ERR_SIZE; }
            l3[(pa >> 12) & 0x1FFU] = (uint64_t)pa | D_VALID | D_TABLE | bits;
            pa += PAGE;
        }
    }
    qv_dsb(ishst);
    return QV_OK;
}

void qv_mmu_enable(void)
{
    uint64_t parange = QV_READ_SYSREG(ID_AA64MMFR0_EL1) & 0xFU;
    uint64_t tcr = TCR_T0SZ(25) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA | TCR_SH0_INNER |
                   TCR_TG0_4K | TCR_EPD1 | ((parange > 5 ? 5 : parange) << TCR_IPS_SHIFT);
    uint64_t sctlr;

    qv_dsb(ish);
    QV_WRITE_SYSREG(MAIR_EL1, MAIR_VALUE);
    QV_WRITE_SYSREG(TCR_EL1, tcr);
    QV_WRITE_SYSREG(TTBR0_EL1, (uint64_t)(uintptr_t)l1);
    qv_isb();
    tlb_flush();
    qv_icache_invalidate_all();

    sctlr = QV_READ_SYSREG(SCTLR_EL1);
    sctlr |= SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_WXN | SCTLR_SA;
    sctlr &= ~(SCTLR_A | SCTLR_EE);
    QV_WRITE_SYSREG(SCTLR_EL1, sctlr);
    qv_isb();
}

void qv_mmu_disable(void)
{
    uint64_t sctlr;
    qv_dcache_flush_all();
    sctlr = QV_READ_SYSREG(SCTLR_EL1);
    sctlr &= ~(SCTLR_M | SCTLR_C | SCTLR_I);
    QV_WRITE_SYSREG(SCTLR_EL1, sctlr);
    qv_isb();
    tlb_flush();
    qv_icache_invalidate_all();
}

bool qv_mmu_is_enabled(void)
{
    return (QV_READ_SYSREG(SCTLR_EL1) & SCTLR_M) != 0;
}

bool qv_mmu_probe_write(uintptr_t va)
{
    uint64_t par;
    __asm__ volatile("at s1e1w, %0" :: "r"(va));
    qv_isb();
    par = QV_READ_SYSREG(PAR_EL1);
    return (par & 1ULL) == 0;                /* PAR.F == 0: translation permitted */
}

bool qv_mmu_probe_read(uintptr_t va)
{
    uint64_t par;
    __asm__ volatile("at s1e1r, %0" :: "r"(va));
    qv_isb();
    par = QV_READ_SYSREG(PAR_EL1);
    return (par & 1ULL) == 0;
}
