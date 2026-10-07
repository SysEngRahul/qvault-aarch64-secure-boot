#include <string.h>
#include "image_verify.h"
#include "crypto_backend.h"
#include "key_store.h"

qv_status_t qv_image_verify(const qv_image_header_t *hdr, const uint8_t *payload,
                            qv_verify_result_t *res)
{
    if (!hdr || !payload || !res) { return QV_ERR_PARAM; }

    qv_crypto_sha256(payload, hdr->payload_size, res->digest);
    res->hash = qv_crypto_equal32(res->digest, hdr->payload_hash) ? QV_OK : QV_ERR_HASH;

    res->cert = qv_keystore_verify_cert(hdr->key_id, hdr->key_role, hdr->signer_pubkey,
                                        hdr->signer_cert) ? QV_OK : QV_ERR_CERT;

    /* Signature only means something if the key is certified, but we still evaluate
     * it so the report is complete. The final verdict requires all three. */
    res->sig = qv_crypto_ed25519_verify(hdr->signature, hdr->signer_pubkey,
                                        (const uint8_t *)hdr, QV_SIGNED_LEN) ? QV_OK : QV_ERR_SIG;

    if (res->hash != QV_OK) { return res->hash; }
    if (res->cert != QV_OK) { return res->cert; }
    return res->sig;
}
