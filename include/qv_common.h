/* QVault common definitions: status codes, image types, helpers. */
#ifndef QV_COMMON_H
#define QV_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define QV_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define QV_ALIGN_UP(x, a) (((x) + ((a) - 1U)) & ~((a) - 1U))

typedef enum {
    QV_OK = 0,
    QV_ERR_PARAM,
    QV_ERR_MAGIC,
    QV_ERR_VERSION,
    QV_ERR_SIZE,
    QV_ERR_RANGE,
    QV_ERR_TYPE,
    QV_ERR_ALG,
    QV_ERR_HASH,
    QV_ERR_CERT,
    QV_ERR_SIG,
    QV_ERR_ROLLBACK,
    QV_ERR_STORAGE,
    QV_ERR_SLOT,
    QV_ERR_DTB,
    QV_ERR_REVOKED,
    QV_ERR_NOTRUN
} qv_status_t;

/* Image types (index into counters / slot tables). */
typedef enum {
    QV_IMG_NONE   = 0,
    QV_IMG_STAGE2 = 1,
    QV_IMG_UEFI   = 2,
    QV_IMG_KERNEL = 3,
    QV_IMG_DTB    = 4,
    QV_IMG_COUNT  = 5   /* array dimension; index 0 unused */
} qv_image_type_t;

/* Signing-key roles in the key hierarchy (Root -> role key -> image). */
typedef enum {
    QV_ROLE_FIRMWARE = 1,
    QV_ROLE_UEFI     = 2,
    QV_ROLE_OS       = 3,
    QV_ROLE_DTB      = 4
} qv_key_role_t;

const char *qv_status_str(qv_status_t s);

#endif
