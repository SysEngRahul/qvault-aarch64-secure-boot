/* QEMU storage backend: a RAM shadow of qv_store_t, persisted to pflash.
 *
 * PERSISTENT: state survives reboot (QEMU writes the pflash file back to the host).
 * NOT SECURE:  anyone who can modify the pflash file can change any value, including
 * lowering counters or clearing revocations. Real hardware needs fuses/RPMB/secure element.
 * NOT POWER-FAIL SAFE: persist() = erase then program; a power cut in between leaves an
 * invalid store, which qv_storage_init() reports and the boot flow treats as fail-closed. */
#include <string.h>
#include "storage.h"
#include "pflash.h"

static qv_store_t shadow;
static bool loaded;

static qv_status_t persist(void)
{
    qv_store_t cur;
    qv_pflash_read(0, &cur, sizeof cur);
    if (memcmp(&cur, &shadow, sizeof cur) == 0) { return QV_OK; }    /* no change, no wear */
    return qv_pflash_write_sector0(&shadow, sizeof shadow);
}

qv_status_t qv_storage_init(void)
{
    qv_pflash_read(0, &shadow, sizeof shadow);
    loaded = false;
    if (shadow.magic != QV_STORE_MAGIC || shadow.layout_version != QV_STORE_LAYOUT ||
        shadow.lifecycle > QV_LIFECYCLE_PROD) {
        return QV_ERR_STORAGE;
    }
    loaded = true;
    return QV_OK;
}

qv_status_t qv_storage_read_counter(uint32_t type, uint32_t *value)
{
    if (!loaded || type == 0U || type >= QV_IMG_COUNT || !value) { return QV_ERR_PARAM; }
    *value = shadow.counters[type];
    return QV_OK;
}

qv_status_t qv_storage_write_counter(uint32_t type, uint32_t value)
{
    if (!loaded || type == 0U || type >= QV_IMG_COUNT) { return QV_ERR_PARAM; }
    if (value < shadow.counters[type]) { return QV_ERR_ROLLBACK; }   /* monotonic */
    shadow.counters[type] = value;
    return persist();
}

qv_status_t qv_storage_increment_counter(uint32_t type)
{
    if (!loaded || type == 0U || type >= QV_IMG_COUNT) { return QV_ERR_PARAM; }
    if (shadow.counters[type] == 0xFFFFFFFFU) { return QV_ERR_STORAGE; }
    shadow.counters[type]++;
    return persist();
}

qv_status_t qv_storage_get_slot(uint32_t type, qv_slot_record_t *rec)
{
    if (!loaded || type == 0U || type >= QV_IMG_COUNT || !rec) { return QV_ERR_PARAM; }
    *rec = shadow.slots[type];
    if (rec->active > 1U) { return QV_ERR_STORAGE; }
    return QV_OK;
}

qv_status_t qv_storage_set_slot(uint32_t type, const qv_slot_record_t *rec)
{
    if (!loaded || type == 0U || type >= QV_IMG_COUNT || !rec || rec->active > 1U) { return QV_ERR_PARAM; }
    shadow.slots[type] = *rec;
    return persist();
}

bool qv_storage_key_revoked(uint32_t key_id)
{
    unsigned i;
    if (!loaded) { return true; }                    /* fail closed */
    for (i = 0; i < QV_MAX_REVOKED_KEYS; i++) {
        if (shadow.revoked_key[i] != 0U && shadow.revoked_key[i] == key_id) { return true; }
    }
    return false;
}

bool qv_storage_hash_revoked(const uint8_t hash[32])
{
    static const uint8_t zero[32];
    unsigned i;
    if (!loaded) { return true; }                    /* fail closed */
    for (i = 0; i < QV_MAX_REVOKED_HASHES; i++) {
        if (memcmp(shadow.revoked_hash[i], zero, 32) != 0 && memcmp(shadow.revoked_hash[i], hash, 32) == 0) {
            return true;
        }
    }
    return false;
}

qv_lifecycle_t qv_storage_lifecycle(void)
{
    /* Unknown state defaults to the MORE restrictive lifecycle. */
    return (!loaded || shadow.lifecycle != QV_LIFECYCLE_DEV) ? QV_LIFECYCLE_PROD : QV_LIFECYCLE_DEV;
}
