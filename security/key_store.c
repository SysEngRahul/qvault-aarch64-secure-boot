#include <string.h>
#include "key_store.h"
#include "crypto_backend.h"
#include "image_format.h"

#ifdef QV_HOST_TEST
static uint8_t g_root[32];
const uint8_t *qv_keystore_root_pubkey(void) { return g_root; }
void qv_keystore_test_set_root(const uint8_t pub[32]) { memcpy(g_root, pub, 32); }
#else
#include "root_pubkey.h"          /* generated: static const uint8_t qv_root_pubkey[32] */
const uint8_t *qv_keystore_root_pubkey(void) { return qv_root_pubkey; }
#endif

bool qv_keystore_verify_cert(uint32_t key_id, uint32_t role, const uint8_t pubkey[32],
                             const uint8_t cert[64])
{
    uint8_t msg[QV_CERT_MSG_LEN];
    qv_build_cert_msg(msg, key_id, role, pubkey);
    return qv_crypto_ed25519_verify(cert, qv_keystore_root_pubkey(), msg, sizeof msg);
}
