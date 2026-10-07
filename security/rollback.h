#ifndef QV_ROLLBACK_H
#define QV_ROLLBACK_H
#include "qv_common.h"

/* Reject if fw_version < stored minimum for this image type. */
qv_status_t qv_rollback_check(uint32_t type, uint32_t fw_version);
/* Raise the minimum to fw_version. Call only AFTER the image is proven to boot,
 * otherwise a bad new image would permanently brick the device. */
qv_status_t qv_rollback_commit(uint32_t type, uint32_t fw_version);
#endif
