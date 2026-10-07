/* Tiny stand-in "kernel" that follows the Linux arm64 boot protocol:
 *   x0 = physical address of the DTB, x1..x3 = 0, MMU off, entered at EL1.
 * It proves the handoff worked: checks the DTB magic and the measurement log
 * left by Stage 2, prints, then powers the VM off through PSCI. */
    .section .text
    .global _start
_start:
    mov     x20, x0
    adr     x0, m_hello
    bl      puts

    ldr     w1, [x20]                   /* FDT magic is big-endian 0xd00dfeed */
    ldr     w2, =0xedfe0dd0
    cmp     w1, w2
    b.ne    1f
    adr     x0, m_dtb_ok
    bl      puts
    b       2f
1:  adr     x0, m_dtb_bad
    bl      puts

2:  ldr     x3, =0x44100000             /* QV_MEASURE_LOG */
    ldr     w1, [x3]
    ldr     w2, =0x4D455351             /* QV_MEAS_MAGIC */
    cmp     w1, w2
    b.ne    3f
    adr     x0, m_log_ok
    bl      puts
    b       4f
3:  adr     x0, m_log_bad
    bl      puts

4:  adr     x0, m_off
    bl      puts
    ldr     x0, =0x84000008             /* PSCI SYSTEM_OFF */
    hvc     #0
5:  wfe
    b       5b

puts:                                   /* x0 = NUL-terminated string */
    ldr     x9, =0x09000000
6:  ldrb    w10, [x0], #1
    cbz     w10, 8f
7:  ldr     w11, [x9, #0x18]
    tbnz    w11, #5, 7b                 /* wait while TXFF */
    str     w10, [x9]
    b       6b
8:  ret

    .balign 4
m_hello:   .asciz "[KERNEL] QVault test kernel running at EL1\r\n"
m_dtb_ok:  .asciz "[KERNEL] DTB handoff: magic OK\r\n"
m_dtb_bad: .asciz "[KERNEL] DTB handoff: BAD MAGIC\r\n"
m_log_ok:  .asciz "[KERNEL] Measurement log found at 0x44100000\r\n"
m_log_bad: .asciz "[KERNEL] Measurement log MISSING\r\n"
m_off:     .asciz "[KERNEL] Powering off via PSCI\r\n"
