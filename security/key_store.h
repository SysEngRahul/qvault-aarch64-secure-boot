#ifndef QV_KEY_STORE_H
#define QV_KEY_STORE_H
#include <stdint.h>
#include <stdbool.h>

/* The root public key is the device's root of trust. On a real SoC it would be
 * (a hash of) a key fused into OTP and read by the immutable Boot ROM. In this
 * educational build it is compiled in from build/generated/root_pubkey.h.
 * The root PRIVATE key never enters the firmware or the repository. */
const uint8_t *qv_keystore_root_pubkey(void);

/* Verify that the ROOT key certified (key_id, role, pubkey). */
bool qv_keystore_verify_cert(uint32_t key_id, uint32_t role, const uint8_t pubkey[32],
                             const uint8_t cert[64]);

#ifdef QV_HOST_TEST
void qv_keystore_test_set_root(const uint8_t pub[32]);   /* unit tests only */
#endif
#endif
