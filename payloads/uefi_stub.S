/* PLACEHOLDER for the UEFI stage. Real EDK II integration is Phase 2 (see
 * uefi/QVaultSecurity/README.md). It exists so the chain Stage1 -> Stage2 ->
 * UEFI -> Kernel is authenticated and measured end-to-end today. */
    .section .text
    .global _start
_start:
    wfe
    b       _start
    .balign 4
    .asciz  "QVault UEFI placeholder - EDK II integration is Phase 2"
