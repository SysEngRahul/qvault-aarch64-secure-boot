/* Host test backend for storage.h (same interface as storage/qemu_storage.c). */
#include <string.h>
#include "storage.h"

qv_store_t g_test_store;

qv_status_t qv_storage_init(void) { return g_test_store.magic == QV_STORE_MAGIC ? QV_OK : QV_ERR_STORAGE; }
qv_status_t qv_storage_read_counter(uint32_t t, uint32_t *v)
{ if (t == 0 || t >= QV_IMG_COUNT || !v) return QV_ERR_PARAM; *v = g_test_store.counters[t]; return QV_OK; }
qv_status_t qv_storage_write_counter(uint32_t t, uint32_t v)
{ if (t == 0 || t >= QV_IMG_COUNT) return QV_ERR_PARAM; if (v < g_test_store.counters[t]) return QV_ERR_ROLLBACK;
  g_test_store.counters[t] = v; return QV_OK; }
qv_status_t qv_storage_increment_counter(uint32_t t)
{ if (t == 0 || t >= QV_IMG_COUNT) return QV_ERR_PARAM; g_test_store.counters[t]++; return QV_OK; }
qv_status_t qv_storage_get_slot(uint32_t t, qv_slot_record_t *r)
{ if (t == 0 || t >= QV_IMG_COUNT || !r) return QV_ERR_PARAM; *r = g_test_store.slots[t]; return QV_OK; }
qv_status_t qv_storage_set_slot(uint32_t t, const qv_slot_record_t *r)
{ if (t == 0 || t >= QV_IMG_COUNT || !r || r->active > 1) return QV_ERR_PARAM; g_test_store.slots[t] = *r; return QV_OK; }
bool qv_storage_key_revoked(uint32_t id)
{ unsigned i; for (i = 0; i < QV_MAX_REVOKED_KEYS; i++) if (g_test_store.revoked_key[i] && g_test_store.revoked_key[i] == id) return true; return false; }
bool qv_storage_hash_revoked(const uint8_t h[32])
{ static const uint8_t z[32]; unsigned i;
  for (i = 0; i < QV_MAX_REVOKED_HASHES; i++) if (memcmp(g_test_store.revoked_hash[i], z, 32) && !memcmp(g_test_store.revoked_hash[i], h, 32)) return true;
  return false; }
qv_lifecycle_t qv_storage_lifecycle(void) { return g_test_store.lifecycle ? QV_LIFECYCLE_PROD : QV_LIFECYCLE_DEV; }
