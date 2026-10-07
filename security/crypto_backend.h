/* Crypto backend interface. Algorithms are NOT implemented here:
 *   SHA-256  -> lib/sha256.c      (FIPS 180-4, tested against NIST vectors)
 *   Ed25519  -> third_party/monocypher (RFC 8032), constant-time-conscious, audited
 * A hardware crypto engine would replace this file only. */
#ifndef QV_CRYPTO_BACKEND_H
#define QV_CRYPTO_BACKEND_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void qv_crypto_sha256(const void *data, size_t len, uint8_t out[32]);
bool qv_crypto_ed25519_verify(const uint8_t sig[64], const uint8_t pub[32],
                              const uint8_t *msg, size_t len);
bool qv_crypto_equal32(const uint8_t a[32], const uint8_t b[32]);   /* constant time */
#endif
