#include "crypto_backend.h"
#include "sha256.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

void qv_crypto_sha256(const void *data, size_t len, uint8_t out[32])
{
    qv_sha256(data, len, out);
}

bool qv_crypto_ed25519_verify(const uint8_t sig[64], const uint8_t pub[32],
                              const uint8_t *msg, size_t len)
{
    return crypto_ed25519_check(sig, pub, msg, len) == 0;
}

bool qv_crypto_equal32(const uint8_t a[32], const uint8_t b[32])
{
    return crypto_verify32(a, b) == 0;
}
