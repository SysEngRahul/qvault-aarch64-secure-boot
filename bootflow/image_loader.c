#include "bootflow.h"
#include "memmap.h"
#include "cache.h"

const uint8_t *qv_flash_slot(uint32_t type, uint8_t slot)
{
    static const uintptr_t tab[QV_IMG_COUNT][2] = {
        { 0, 0 },
        { QV_FLASH_STAGE2_A, QV_FLASH_STAGE2_B },
        { QV_FLASH_UEFI_A,   QV_FLASH_UEFI_B   },
        { QV_FLASH_KERNEL_A, QV_FLASH_KERNEL_B },
        { QV_FLASH_DTB_A,    QV_FLASH_DTB_B    },
    };
    if (type == 0U || type >= QV_IMG_COUNT || slot > 1U) { return NULL; }
    return (const uint8_t *)tab[type][slot];
}

qv_status_t qv_load_slot(uint32_t type, uint8_t slot, qv_boot_report_t *rep)
{
    const uint8_t *blob = qv_flash_slot(type, slot);
    qv_status_t st;

    if (!blob) { return QV_ERR_PARAM; }
    st = qv_secure_boot_load(type, blob, QV_SLOT_SIZE, NULL, rep);
    if (st == QV_OK) {
        /* Code was written as data: make it visible to instruction fetch. */
        qv_cache_sync_code((uintptr_t)rep->hdr.load_addr, rep->hdr.payload_size);
    }
    return st;
}
