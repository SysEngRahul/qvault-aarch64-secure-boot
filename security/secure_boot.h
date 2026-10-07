#ifndef QV_SECURE_BOOT_H
#define QV_SECURE_BOOT_H
#include "image_format.h"
#include "image_verify.h"

typedef struct {
    qv_status_t       parse;
    qv_verify_result_t v;           /* hash / cert / sig */
    qv_status_t       revocation;   /* signer key / payload hash on a deny-list? */
    qv_status_t       rollback;
    qv_status_t       final;        /* QV_OK only if every check passed */
    qv_image_header_t hdr;
} qv_boot_report_t;

/* Parse -> copy to destination -> verify the COPY -> rollback check.
 * `dest` is where the payload is placed (NULL = header's load_addr, firmware use).
 * On failure the destination is scrubbed so rejected code can never execute. */
qv_status_t qv_secure_boot_load(uint32_t type, const uint8_t *blob, size_t blob_len,
                                uint8_t *dest, qv_boot_report_t *rep);
#endif
