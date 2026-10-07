#include <string.h>
#include "update_manager.h"
#include "secure_boot.h"
#include "slot_manager.h"
#include "storage.h"

qv_status_t qv_update_install(uint32_t type, const uint8_t *new_blob, size_t len,
                              uint8_t *slot_mem[2], size_t slot_size,
                              qv_flash_write_fn write, uint8_t *scratch)
{
    qv_boot_report_t rep;
    qv_slot_record_t rec;
    qv_status_t st;
    unsigned target;

    if (!new_blob || !slot_mem || !write || !scratch || len > slot_size) { return QV_ERR_PARAM; }

    /* 1. Authenticate in a scratch buffer; flash is untouched if this fails. */
    st = qv_secure_boot_load(type, new_blob, len, scratch, &rep);
    if (st != QV_OK) { return st; }

    st = qv_storage_get_slot(type, &rec);
    if (st != QV_OK) { return st; }
    target = 1U - rec.active;

    /* 2. Invalidate target first: power loss from here on leaves it unbootable. */
    rec.state[target] = QV_SLOT_EMPTY;
    rec.tries[target] = 0;
    st = qv_storage_set_slot(type, &rec);
    if (st != QV_OK) { return st; }

    /* 3. Program and read back. */
    write(slot_mem[target], new_blob, len);
    st = qv_secure_boot_load(type, slot_mem[target], len, scratch, &rep);
    if (st != QV_OK) { return st; }

    /* 4. Single commit point. */
    rec.state[target] = QV_SLOT_PENDING;
    rec.tries[target] = 0;
    rec.active = (uint32_t)target;
    return qv_storage_set_slot(type, &rec);
}
