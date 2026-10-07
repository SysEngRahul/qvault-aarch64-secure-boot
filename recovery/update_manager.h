#ifndef QV_UPDATE_MANAGER_H
#define QV_UPDATE_MANAGER_H
#include "qv_common.h"

/* Writes `len` bytes of `src` into slot memory at `dst`. On QEMU this is memcpy;
 * on real flash it is erase+program. Abstracted so power-fail logic is testable. */
typedef void (*qv_flash_write_fn)(uint8_t *dst, const uint8_t *src, size_t len);

/* Atomic A/B update:
 *   1. authenticate the new image (signature, hash, rollback) BEFORE touching flash
 *   2. mark the inactive slot EMPTY (a torn write can never be booted)
 *   3. write the image, then re-verify it from the slot
 *   4. one record write flips: inactive -> PENDING + active
 * Old slot stays VALID, so a bad/unbootable update falls back automatically. */
qv_status_t qv_update_install(uint32_t type, const uint8_t *new_blob, size_t len,
                              uint8_t *slot_mem[2], size_t slot_size,
                              qv_flash_write_fn write, uint8_t *scratch);
#endif
