#include "exception.h"
#include "system_regs.h"
#include "barriers.h"
#include "log.h"

#define SELFTEST_IMM 0x5156U       /* 'QV' */

static volatile int      selftest_armed;
static volatile unsigned selftest_hits;
static volatile uint64_t selftest_esr;

static const char *const vec_names[16] = {
    "Current EL SP0 Sync", "Current EL SP0 IRQ", "Current EL SP0 FIQ", "Current EL SP0 SError",
    "Current EL SPx Sync", "Current EL SPx IRQ", "Current EL SPx FIQ", "Current EL SPx SError",
    "Lower EL A64 Sync",   "Lower EL A64 IRQ",   "Lower EL A64 FIQ",   "Lower EL A64 SError",
    "Lower EL A32 Sync",   "Lower EL A32 IRQ",   "Lower EL A32 FIQ",   "Lower EL A32 SError",
};

static const char *ec_name(unsigned ec)
{
    switch (ec) {
    case ESR_EC_UNKNOWN: return "Unknown reason";
    case ESR_EC_SVC64:   return "SVC (AArch64)";
    case ESR_EC_IABT:    return "Instruction abort (same EL)";
    case ESR_EC_IABT_LO: return "Instruction abort (lower EL)";
    case ESR_EC_PC_ALN:  return "PC alignment fault";
    case ESR_EC_DABT:    return "Data abort (same EL)";
    case ESR_EC_DABT_LO: return "Data abort (lower EL)";
    case ESR_EC_SP_ALN:  return "SP alignment fault";
    case ESR_EC_SERROR:  return "SError";
    case ESR_EC_BRK64:   return "BRK (AArch64)";
    default:             return "Other";
    }
}

void qv_exception_init(void)
{
    QV_WRITE_SYSREG(VBAR_EL1, (uint64_t)(uintptr_t)qv_vector_table);
    qv_isb();
}

void qv_exception_handler(unsigned vector, qv_exc_frame_t *f)
{
    unsigned ec = (unsigned)((f->esr >> ESR_EC_SHIFT) & ESR_EC_MASK);

    /* Deliberate self-test BRK: record it and step over the instruction. */
    if (selftest_armed && vector == 4U && ec == ESR_EC_BRK64 &&
        (f->esr & 0xFFFFU) == SELFTEST_IMM) {
        selftest_esr = f->esr;
        selftest_hits++;
        f->elr += 4;
        return;
    }

    qv_printf("\n*** QVault Exception: %s ***\n", vector < 16U ? vec_names[vector] : "?");
    qv_printf("  EC   = 0x%02x (%s)\n", ec, ec_name(ec));
    qv_printf("  ESR  = 0x%016lx\n", f->esr);
    qv_printf("  ELR  = 0x%016lx\n", f->elr);
    qv_printf("  FAR  = 0x%016lx\n", f->far);
    qv_printf("  SPSR = 0x%016lx\n", f->spsr);
    qv_printf("  x0=0x%lx x1=0x%lx x30=0x%lx\n", f->x[0], f->x[1], f->x[30]);
    qv_printf("System halted.\n");
    for (;;) { qv_wfe(); }
}

bool qv_exception_selftest(void)
{
    selftest_hits = 0;
    selftest_esr = 0;
    selftest_armed = 1;
    __asm__ volatile("brk #0x5156" ::: "memory");
    selftest_armed = 0;
    return selftest_hits == 1U &&
           ((selftest_esr >> ESR_EC_SHIFT) & ESR_EC_MASK) == ESR_EC_BRK64;
}
