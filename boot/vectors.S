/* AArch64 exception vector table: 16 entries x 128 bytes, 2 KiB aligned.
 *   [Current EL, SP0] [Current EL, SPx] [Lower EL A64] [Lower EL A32]
 *   each: Synchronous, IRQ, FIQ, SError
 * Every entry branches to a stub in exceptions.S that records its index. */

    .macro ventry idx
    .balign 128
    b       qv_exc_entry_\idx
    .endm

    .section .text.vectors, "ax"
    .balign 2048
    .global qv_vector_table
qv_vector_table:
    ventry 0
    ventry 1
    ventry 2
    ventry 3
    ventry 4
    ventry 5
    ventry 6
    ventry 7
    ventry 8
    ventry 9
    ventry 10
    ventry 11
    ventry 12
    ventry 13
    ventry 14
    ventry 15
