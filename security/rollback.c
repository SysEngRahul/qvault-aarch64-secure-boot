#include "rollback.h"
#include "storage.h"

qv_status_t qv_rollback_check(uint32_t type, uint32_t fw_version)
{
    uint32_t min;
    qv_status_t st = qv_storage_read_counter(type, &min);
    if (st != QV_OK) { return st; }
    return (fw_version < min) ? QV_ERR_ROLLBACK : QV_OK;
}

qv_status_t qv_rollback_commit(uint32_t type, uint32_t fw_version)
{
    uint32_t min;
    qv_status_t st = qv_storage_read_counter(type, &min);
    if (st != QV_OK) { return st; }
    if (fw_version <= min) { return QV_OK; }       /* nothing to raise */
    return qv_storage_write_counter(type, fw_version);
}
