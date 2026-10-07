#ifndef QV_SHA256_H
#define QV_SHA256_H
#include <stdint.h>
#include <stddef.h>

#define QV_SHA256_LEN 32U

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total;
    size_t   fill;
} qv_sha256_ctx_t;

void qv_sha256_init(qv_sha256_ctx_t *c);
void qv_sha256_update(qv_sha256_ctx_t *c, const void *data, size_t len);
void qv_sha256_final(qv_sha256_ctx_t *c, uint8_t out[QV_SHA256_LEN]);
void qv_sha256(const void *data, size_t len, uint8_t out[QV_SHA256_LEN]);
#endif
