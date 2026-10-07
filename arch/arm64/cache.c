/* Cache maintenance. Needed whenever code is written as data and then
 * executed (image load), and before the MMU/caches are turned off. */
#include "cache.h"
#include "system_regs.h"
#include "barriers.h"

static inline size_t dline(void) { return (size_t)4U << ((QV_READ_SYSREG(CTR_EL0) >> 16) & 0xFU); }
static inline size_t iline(void) { return (size_t)4U << (QV_READ_SYSREG(CTR_EL0) & 0xFU); }

void qv_cache_clean_range(uintptr_t addr, size_t size)
{
    size_t line = dline();
    uintptr_t p, end;
    if (size == 0) { return; }
    end = addr + size;
    for (p = addr & ~(line - 1); p < end; p += line) {
        __asm__ volatile("dc cvac, %0" :: "r"(p) : "memory");
    }
    qv_dsb(sy);
}

void qv_cache_flush_range(uintptr_t addr, size_t size)
{
    size_t line = dline();
    uintptr_t p, end;
    if (size == 0) { return; }
    end = addr + size;
    for (p = addr & ~(line - 1); p < end; p += line) {
        __asm__ volatile("dc civac, %0" :: "r"(p) : "memory");
    }
    qv_dsb(sy);
}

void qv_cache_sync_code(uintptr_t addr, size_t size)
{
    size_t dl = dline(), il = iline();
    uintptr_t p, end;
    if (size == 0) { return; }
    end = addr + size;
    for (p = addr & ~(dl - 1); p < end; p += dl) {
        __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    }
    qv_dsb(ish);
    for (p = addr & ~(il - 1); p < end; p += il) {
        __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    }
    qv_dsb(ish);
    qv_isb();
}

void qv_icache_invalidate_all(void)
{
    __asm__ volatile("ic iallu" ::: "memory");
    qv_dsb(nsh);
    qv_isb();
}

void qv_dcache_flush_all(void)
{
    uint64_t clidr = QV_READ_SYSREG(CLIDR_EL1);
    unsigned loc = (unsigned)((clidr >> 24) & 7U), level;

    for (level = 0; level < loc; level++) {
        unsigned ctype = (unsigned)((clidr >> (3U * level)) & 7U);
        uint64_t ccsidr;
        unsigned linesh, ways, sets, wshift, set, way;
        if (ctype < 2U) { continue; }            /* no data/unified cache here */
        QV_WRITE_SYSREG(CSSELR_EL1, (uint64_t)level << 1);
        qv_isb();
        ccsidr = QV_READ_SYSREG(CCSIDR_EL1);
        linesh = (unsigned)(ccsidr & 7U) + 4U;
        ways   = (unsigned)((ccsidr >> 3) & 0x3FFU);
        sets   = (unsigned)((ccsidr >> 13) & 0x7FFFU);
        wshift = ways ? (unsigned)__builtin_clz(ways) : 0U;
        for (set = 0; set <= sets; set++) {
            for (way = 0; way <= ways; way++) {
                uint64_t v = ((uint64_t)way << wshift) | ((uint64_t)set << linesh) |
                             ((uint64_t)level << 1);
                __asm__ volatile("dc cisw, %0" :: "r"(v) : "memory");
            }
        }
    }
    qv_dsb(sy);
    qv_isb();
}
