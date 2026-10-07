#ifndef QV_IMAGE_VERIFY_H
#define QV_IMAGE_VERIFY_H
#include "image_format.h"

typedef struct {
    qv_status_t hash;     /* payload hash matches header      */
    qv_status_t cert;     /* ROOT certified the signer key    */
    qv_status_t sig;      /* signer signed this header        */
    uint8_t     digest[32];   /* SHA-256 of the bytes actually hashed (for measurement) */
} qv_verify_result_t;

/* Verify an already-parsed image. `payload` must be the bytes that will execute
 * (the load-address copy), not the original storage. All three checks always run
 * so the log can report exactly what failed. Returns QV_OK only if all pass. */
qv_status_t qv_image_verify(const qv_image_header_t *hdr, const uint8_t *payload,
                            qv_verify_result_t *res);
#endif
