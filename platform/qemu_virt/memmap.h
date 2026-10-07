/* QVault memory map for QEMU "virt" (run with -m 1G). See docs/memory-map.md. */
#ifndef QV_MEMMAP_H
#define QV_MEMMAP_H

/* ---- Fixed platform devices ---- */
#define QV_UART0_BASE      0x09000000UL   /* PL011 */
#define QV_RAM_BASE        0x40000000UL

/* ---- Where each stage lives ---- */
#define QV_STAGE1_BASE     0x40080000UL   /* loaded by QEMU (-kernel ELF) */

/* Verified-image load windows: the ONLY places an image may be loaded. */
#define QV_STAGE2_WIN_BASE 0x41000000UL
#define QV_STAGE2_WIN_SIZE 0x00800000UL
#define QV_UEFI_WIN_BASE   0x42000000UL
#define QV_UEFI_WIN_SIZE   0x00800000UL
#define QV_KERNEL_WIN_BASE 0x43000000UL
#define QV_KERNEL_WIN_SIZE 0x01000000UL

#define QV_DTB_LOAD        0x44000000UL   /* authenticated DTB is loaded here */
#define QV_DTB_WIN_BASE    0x44000000UL
#define QV_DTB_WIN_SIZE    0x00100000UL   /* 1 MiB */
#define QV_MEASURE_LOG     0x44100000UL   /* measurement log handed to the OS */

/* ---- Simulated image storage (preloaded by QEMU -device loader; contents are NOT persisted) ----
 * Real hardware: eMMC/UFS/NOR + fuses/RPMB. Here: a flat RAM image. */
#define QV_FLASH_BASE      0x60000000UL
#define QV_SLOT_SIZE       0x00100000UL   /* 1 MiB per slot (header + payload) */
#define QV_FLASH_STAGE2_A  (QV_FLASH_BASE + 0x000000UL)
#define QV_FLASH_STAGE2_B  (QV_FLASH_BASE + 0x100000UL)
#define QV_FLASH_UEFI_A    (QV_FLASH_BASE + 0x200000UL)
#define QV_FLASH_UEFI_B    (QV_FLASH_BASE + 0x300000UL)
#define QV_FLASH_KERNEL_A  (QV_FLASH_BASE + 0x400000UL)
#define QV_FLASH_KERNEL_B  (QV_FLASH_BASE + 0x500000UL)
#define QV_FLASH_DTB_A     (QV_FLASH_BASE + 0x600000UL)
#define QV_FLASH_DTB_B     (QV_FLASH_BASE + 0x700000UL)
#define QV_FLASH_TOTAL     0x800000UL

/* ---- Persistent state: QEMU virt pflash bank 1 (CFI, 2x16-bit interleaved) ----
 * Holds counters, slot state, revocation lists and lifecycle. Survives reboots
 * because QEMU writes it back to the host file. Still NOT tamper-resistant. */
#define QV_PFLASH_BASE     0x04000000UL
#define QV_PFLASH_SECTOR   0x00040000UL   /* 256 KiB erase block */

#endif
