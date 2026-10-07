/* Stage 1: first mutable code after the (simulated) Boot ROM.
 * Brings the CPU to a known state, proves its own environment works
 * (exceptions, MMU + W^X, secure storage), then authenticates and launches Stage 2. */
#include <string.h>
#include "bootflow.h"
#include "memmap.h"
#include "log.h"
#include "uart.h"
#include "system_regs.h"
#include "exception.h"
#include "mmu.h"
#include "cache.h"
#include "storage.h"
#include "crypto_backend.h"
#include "slot_manager.h"
#include "debug.h"

extern char __image_start[], __text_start[], __text_end[], __rodata_start[], __rodata_end[];
extern char __data_start[];

static qv_bootinfo_t g_bootinfo;

static bool mmu_bringup(void)
{
    volatile uint32_t dummy = 0;
    bool ok;

    qv_mmu_init();
    ok  = qv_mmu_map((uintptr_t)__text_start,   (size_t)((uintptr_t)__text_end - (uintptr_t)__text_start),     QV_MMU_RX) == QV_OK;
    ok &= qv_mmu_map((uintptr_t)__rodata_start, (size_t)((uintptr_t)__rodata_end - (uintptr_t)__rodata_start), QV_MMU_RO) == QV_OK;
    qv_mmu_enable();

    /* Ask the hardware translator whether the permissions we intended are real. */
    ok &= qv_mmu_is_enabled();
    ok &= !qv_mmu_probe_write((uintptr_t)__text_start);      /* code is not writable   */
    ok &= !qv_mmu_probe_write((uintptr_t)__rodata_start);    /* rodata is not writable */
    ok &=  qv_mmu_probe_write((uintptr_t)&dummy);            /* stack/data is writable */
    ok &=  qv_mmu_probe_read(QV_UART0_BASE);                 /* device mapped          */
    return ok;
}

void qv_stage1_main(void)
{
    qv_loaded_image_t s2;
    qv_meas_state_t *m = &g_bootinfo.meas;
    uint8_t s1_digest[32];
    bool ok;

    qv_uart_init();
    qv_printf("\n");
    qv_banner("QVAULT SECURE BOOT");
    qv_printf("\n");

    qv_report("BOOT", "AArch64 initialization", qv_current_el() == 1U ? "OK" : "FAIL");

    qv_exception_init();
    ok = qv_exception_selftest();
    qv_report("BOOT", "Exception vectors", ok ? "OK" : "FAIL");
    if (!ok) { qv_recovery_halt("exception self-test failed"); }

    ok = mmu_bringup();
    qv_report("BOOT", "MMU", ok ? "OK" : "FAIL");
    if (!ok) { qv_recovery_halt("MMU self-test failed"); }

    ok = qv_storage_init() == QV_OK;
    qv_report("BOOT", "Secure storage", ok ? "OK" : "FAIL");
    if (!ok) { qv_recovery_halt("secure storage invalid"); }

    {   /* Debug policy comes from the lifecycle in secure storage; unknown => PROD (restrictive). */
        qv_lifecycle_t lc = qv_storage_lifecycle();
        bool locked = qv_debug_apply(lc);
        qv_report("BOOT", "Debug policy", lc == QV_LIFECYCLE_PROD ? (locked ? "PROD (OS lock set)" : "PROD (LOCK FAILED)")
                                                                   : "DEV (debug enabled)");
        if (lc == QV_LIFECYCLE_PROD && !locked) { qv_recovery_halt("production debug lock failed"); }
    }
    qv_printf("\n");

    /* Measure ourselves (text + rodata, which never change after load). */
    qv_crypto_sha256(__image_start, (size_t)((uintptr_t)__rodata_end - (uintptr_t)__image_start), s1_digest);
    qv_meas_init(m);
    (void)qv_meas_extend(m, QV_PCR_STAGE1, "Stage-1", s1_digest);

    /* Authenticate and load Stage 2 (A/B with automatic fallback). */
    (void)qv_boot_load_with_recovery(QV_IMG_STAGE2, "Stage-2", 1, &s2);
    (void)qv_meas_extend(m, QV_PCR_STAGE2, "Stage-2", s2.digest);
    qv_printf("\n");

    g_bootinfo.magic = QV_BOOTINFO_MAGIC;
    g_bootinfo.stage2_version = s2.hdr.fw_version;
    g_bootinfo.stage2_slot = s2.slot;

    /* Hand over in a clean state: caches flushed, MMU off. Stage 2 builds its own map. */
    qv_mmu_disable();
    ((void (*)(qv_bootinfo_t *))(uintptr_t)s2.hdr.entry_point)(&g_bootinfo);
    qv_recovery_halt("Stage 2 returned");
}
