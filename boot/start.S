/* QVault reset entry (AArch64).
 *
 * Stage 1 (default): may be entered at EL3, EL2 or EL1 depending on how the
 * platform boots. We normalise to EL1h:  EL3 -> EL2 -> EL1  (ERET twice).
 * Stage 2 (-DQV_STAGE2): always entered at EL1 from Stage 1; no EL drop.
 *
 * Common tail: mask DAIF, stack, enable FP/SIMD access, zero .bss, VBAR_EL1,
 * call C. AAPCS64: SP must stay 16-byte aligned. */

#include "system_regs_asm.h"

    .section .text.start, "ax"
    .global _start
_start:
    mov     x19, x0                     /* preserve handoff pointer (Stage 2: bootinfo) */
    msr     daifset, #0xf

#ifndef QV_STAGE2
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #3
    b.ne    .Lnot_el3

    /* ---- EL3 -> EL2 (or straight to EL1 if the CPU has no EL2) ---- */
    mrs     x0, id_aa64pfr0_el1
    ubfx    x0, x0, #8, #4              /* ID_AA64PFR0_EL1.EL2: 0 = not implemented */
    cbz     x0, .Lel3_to_el1
    mov     x0, #(SCR_NS | SCR_HCE | SCR_RW | SCR_RES1)
    msr     scr_el3, x0                 /* non-secure, HVC enabled, lower EL is AArch64 */
    msr     cptr_el3, xzr               /* no FP/SIMD trapping at EL3 */
    mov     x0, #SPSR_EL2H_MASKED
    msr     spsr_el3, x0
    adr     x0, .Lnot_el3
    msr     elr_el3, x0
    isb
    eret

.Lel3_to_el1:
    mov     x0, #(SCR_NS | SCR_RW | SCR_RES1)
    msr     scr_el3, x0
    msr     cptr_el3, xzr
    movz    x0, #0x0800
    movk    x0, #0x30d0, lsl #16        /* SCTLR_EL1 reset value: MMU/caches off */
    msr     sctlr_el1, x0
    mov     x0, #SPSR_EL1H_MASKED
    msr     spsr_el3, x0
    adr     x0, .Lat_el1
    msr     elr_el3, x0
    isb
    eret

.Lnot_el3:
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.ne    .Lat_el1

    /* ---- EL2 -> EL1 ---- */
    mov     x0, #HCR_RW
    msr     hcr_el2, x0                 /* EL1 executes in AArch64 */
    mrs     x0, cnthctl_el2
    orr     x0, x0, #3                  /* let EL1 use the physical counter/timer */
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr
    msr     cptr_el2, xzr
    movz    x0, #0x0800
    movk    x0, #0x30d0, lsl #16        /* SCTLR_EL1 reset value: MMU/caches off */
    msr     sctlr_el1, x0
    mov     x0, #SPSR_EL1H_MASKED
    msr     spsr_el2, x0
    adr     x0, .Lat_el1
    msr     elr_el2, x0
    isb
    eret
.Lat_el1:
#endif

    /* ---- Now at EL1h ---- */
    ldr     x0, =__stack_top
    mov     sp, x0
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0               /* FP/SIMD not trapped */
    isb

    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:
    ldr     x0, =qv_vector_table
    msr     vbar_el1, x0
    isb

    mov     x0, x19
#ifdef QV_STAGE2
    bl      qv_stage2_main
#else
    bl      qv_stage1_main
#endif
.Lhang:
    wfe
    b       .Lhang
