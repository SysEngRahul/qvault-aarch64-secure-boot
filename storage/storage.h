/* Secure-storage interface: anti-rollback counters, A/B slot state, revocation
 * lists and the device lifecycle (DEV/PROD).
 *
 * QEMU backend (qemu_storage.c): persistent across reboots via pflash, but NOT
 * tamper-resistant - whoever can write the pflash file can change any value.
 * A production port provides the same functions backed by OTP fuses / RPMB /
 * a secure-element monotonic counter. Nothing outside this header may assume
 * how or where state is kept. */
#ifndef QV_STORAGE_H
#define QV_STORAGE_H
#include <stdint.h>
#include <stdbool.h>
#include "qv_common.h"

#define QV_STORE_MAGIC     0x54535651UL    /* "QVST" */
#define QV_STORE_LAYOUT    2U
#define QV_MAX_REVOKED_KEYS   8U
#define QV_MAX_REVOKED_HASHES 8U

typedef enum {
    QV_SLOT_EMPTY   = 0,
    QV_SLOT_VALID   = 1,   /* booted successfully before            */
    QV_SLOT_PENDING = 2,   /* newly installed, not yet proven good  */
    QV_SLOT_INVALID = 3    /* failed verification / exhausted tries */
} qv_slot_state_t;

typedef enum { QV_LIFECYCLE_DEV = 0, QV_LIFECYCLE_PROD = 1 } qv_lifecycle_t;

typedef struct {
    uint32_t active;           /* 0 = A, 1 = B */
    uint32_t state[2];         /* qv_slot_state_t */
    uint32_t tries[2];         /* boot attempts while PENDING */
} qv_slot_record_t;

typedef struct {
    uint32_t magic;
    uint32_t layout_version;
    uint32_t lifecycle;                                  /* qv_lifecycle_t */
    uint32_t reserved;
    uint32_t counters[QV_IMG_COUNT];                     /* minimum acceptable fw_version per type */
    qv_slot_record_t slots[QV_IMG_COUNT];
    uint32_t revoked_key[QV_MAX_REVOKED_KEYS];           /* key_id, 0 = unused */
    uint8_t  revoked_hash[QV_MAX_REVOKED_HASHES][32];    /* payload SHA-256, all-zero = unused */
} qv_store_t;

qv_status_t qv_storage_init(void);
qv_status_t qv_storage_read_counter(uint32_t type, uint32_t *value);
/* Monotonic: refuses to lower a counter. */
qv_status_t qv_storage_write_counter(uint32_t type, uint32_t value);
qv_status_t qv_storage_increment_counter(uint32_t type);
qv_status_t qv_storage_get_slot(uint32_t type, qv_slot_record_t *rec);
qv_status_t qv_storage_set_slot(uint32_t type, const qv_slot_record_t *rec);
bool        qv_storage_key_revoked(uint32_t key_id);
bool        qv_storage_hash_revoked(const uint8_t hash[32]);
qv_lifecycle_t qv_storage_lifecycle(void);

#endif
