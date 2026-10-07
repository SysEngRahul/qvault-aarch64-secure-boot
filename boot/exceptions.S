/* Exception entry stubs: save full context, call C, restore, ERET.
 *
 * Frame layout (must match qv_exc_frame_t): x0..x30 | elr | spsr | esr | far
 * = 35 doublewords = 280 bytes, rounded to 288 to keep SP 16-byte aligned.
 * The stub reads the *_ELx registers of the exception level it is running at,
 * so the same table works if an exception hits before the EL3/EL2 -> EL1 drop. */

#define FRAME_SIZE 288
#define F_ELR      248
#define F_SPSR     256
#define F_ESR      264
#define F_FAR      272

    .section .text.exc, "ax"

    .macro exc_stub idx
    .global qv_exc_entry_\idx
qv_exc_entry_\idx:
    mov     w17, #\idx
    b       qv_exc_common
    .endm

    exc_stub 0
    exc_stub 1
    exc_stub 2
    exc_stub 3
    exc_stub 4
    exc_stub 5
    exc_stub 6
    exc_stub 7
    exc_stub 8
    exc_stub 9
    exc_stub 10
    exc_stub 11
    exc_stub 12
    exc_stub 13
    exc_stub 14
    exc_stub 15

qv_exc_common:
    sub     sp, sp, #FRAME_SIZE
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]

    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #3
    b.eq    3f
    cmp     x9, #2
    b.eq    2f
1:  mrs     x10, elr_el1
    mrs     x11, spsr_el1
    mrs     x12, esr_el1
    mrs     x13, far_el1
    b       4f
2:  mrs     x10, elr_el2
    mrs     x11, spsr_el2
    mrs     x12, esr_el2
    mrs     x13, far_el2
    b       4f
3:  mrs     x10, elr_el3
    mrs     x11, spsr_el3
    mrs     x12, esr_el3
    mrs     x13, far_el3
4:  stp     x10, x11, [sp, #F_ELR]
    stp     x12, x13, [sp, #F_ESR]

    mov     w0, w17                     /* vector index */
    mov     x1, sp                      /* frame */
    bl      qv_exception_handler

    ldp     x10, x11, [sp, #F_ELR]      /* handler may have advanced ELR */
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #3
    b.eq    7f
    cmp     x9, #2
    b.eq    6f
5:  msr     elr_el1, x10
    msr     spsr_el1, x11
    b       8f
6:  msr     elr_el2, x10
    msr     spsr_el2, x11
    b       8f
7:  msr     elr_el3, x10
    msr     spsr_el3, x11
8:
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    add     sp, sp, #FRAME_SIZE
    eret
