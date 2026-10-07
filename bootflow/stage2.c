/* Stage 2: authenticates the UEFI image and OS kernel, validates the device
 * tree, completes the measurement log and hands off to the kernel using the
 * Linux arm64 boot protocol (x0 = DTB physical address, x1..x3 = 0, MMU off). */
#include <string.h>
#include "bootflow.h"
#include "memmap.h"
#include "log.h"
#include "uart.h"
#include "exception.h"
#include "mmu.h"
#include "cache.h"
#include "storage.h"
#include "rollback.h"
#include "slot_manager.h"
#include "dtb.h"

extern char __text_start[], __text_end[], __rodata_start[], __rodata_end[];

static qv_meas_state_t g_meas;

static bool mmu_bringup(void)
{
    bool ok;
    qv_mmu_init();
    ok  = qv_mmu_map((uintptr_t)__text_start,   (size_t)((uintptr_t)__text_end - (uintptr_t)__text_start),     QV_MMU_RX) == QV_OK;
    ok &= qv_mmu_map((uintptr_t)__rodata_start, (size_t)((uintptr_t)__rodata_end - (uintptr_t)__rodata_start), QV_MMU_RO) == QV_OK;
    qv_mmu_enable();
    return ok && qv_mmu_is_enabled();
}

static int inside(uint64_t base, uint64_t size, uint64_t addr, uint64_t len)
{
    return addr >= base && addr - base <= size && len <= size - (addr - base);
}

void qv_stage2_main(qv_bootinfo_t *bi)
{
    qv_loaded_image_t uefi, kern, dtb;
    uint64_t ram_base = 0, ram_size = 0;
    qv_status_t dtb_st;
    const void *fdt;
    unsigned i;
    bool ok;

    qv_uart_init();
    if (!mmu_bringup()) { qv_recovery_halt("Stage 2 MMU setup failed"); }
    qv_exception_init();

    if (!bi || bi->magic != QV_BOOTINFO_MAGIC || !qv_meas_valid(&bi->meas)) {
        qv_recovery_halt("invalid handoff from Stage 1");
    }
    memcpy(&g_meas, &bi->meas, sizeof g_meas);
    if (qv_storage_init() != QV_OK) { qv_recovery_halt("secure storage invalid"); }

    (void)qv_boot_load_with_recovery(QV_IMG_UEFI,   "UEFI image", 0, &uefi);
    (void)qv_boot_load_with_recovery(QV_IMG_KERNEL, "Kernel",     0, &kern);
    /* Structural validity is not trust: the DTB must be AUTHENTICATED before it is even parsed. */
    (void)qv_boot_load_with_recovery(QV_IMG_DTB,    "Device Tree", 0, &dtb);
    qv_printf("\n");

    (void)qv_meas_extend(&g_meas, QV_PCR_UEFI,   "UEFI",   uefi.digest);
    (void)qv_meas_extend(&g_meas, QV_PCR_KERNEL, "Kernel", kern.digest);
    (void)qv_meas_extend(&g_meas, QV_PCR_DTB,    "DTB",    dtb.digest);
    for (i = 0; i < g_meas.count; i++) {
        char l[24];
        size_t n = 0;
        const char *s = g_meas.events[i].name;
        while (n < sizeof l - 1U && s[n]) { l[n] = s[n]; n++; }
        l[n] = 0;
        qv_report_hex("MEASURE", l, g_meas.events[i].digest, 32);
    }
    qv_printf("\n");

    fdt = (const void *)(uintptr_t)dtb.hdr.load_addr;       /* authenticated copy in RAM */
    dtb_st = qv_dtb_validate(fdt, dtb.hdr.payload_size);
    if (dtb_st == QV_OK) { dtb_st = qv_dtb_find_memory(fdt, dtb.hdr.payload_size, &ram_base, &ram_size); }
    qv_report("BOOT", "Device Tree validation", dtb_st == QV_OK ? "OK" : "FAIL");
    if (dtb_st != QV_OK) { qv_recovery_halt("device tree rejected"); }

    /* The DTB describes RAM: everything we hand over must lie inside it. */
    ok  = inside(ram_base, ram_size, kern.hdr.load_addr, kern.hdr.payload_size);
    ok &= inside(ram_base, ram_size, dtb.hdr.load_addr, dtb.hdr.payload_size);
    ok &= inside(kern.hdr.load_addr, kern.hdr.payload_size, kern.hdr.entry_point, 4U);
    qv_report("BOOT", "Kernel handoff", ok ? "OK" : "FAIL");
    if (!ok) { qv_recovery_halt("handoff validation failed"); }

    qv_printf("\n");
    qv_banner("SECURE BOOT SUCCESS");

    /* Commit-after-success: only now raise anti-rollback floors and bless the slots. */
    (void)qv_rollback_commit(QV_IMG_STAGE2, bi->stage2_version);
    (void)qv_rollback_commit(QV_IMG_UEFI,   uefi.hdr.fw_version);
    (void)qv_rollback_commit(QV_IMG_KERNEL, kern.hdr.fw_version);
    (void)qv_rollback_commit(QV_IMG_DTB,    dtb.hdr.fw_version);
    (void)qv_slot_mark_good(QV_IMG_STAGE2, (uint8_t)bi->stage2_slot);
    (void)qv_slot_mark_good(QV_IMG_UEFI,   uefi.slot);
    (void)qv_slot_mark_good(QV_IMG_KERNEL, kern.slot);
    (void)qv_slot_mark_good(QV_IMG_DTB,    dtb.slot);

    /* Expose the measurement log to the OS at a fixed, documented address. */
    memcpy((void *)QV_MEASURE_LOG, &g_meas, sizeof g_meas);
    qv_cache_flush_range(QV_MEASURE_LOG, sizeof g_meas);
    qv_cache_flush_range((uintptr_t)dtb.hdr.load_addr, dtb.hdr.payload_size);

    qv_mmu_disable();       /* Linux boot protocol: MMU off, D-cache off */
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)kern.hdr.entry_point)((uint64_t)dtb.hdr.load_addr, 0, 0, 0);
    qv_recovery_halt("kernel returned");
}
