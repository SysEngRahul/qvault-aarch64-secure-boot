/* QVault signed image format (little-endian, fixed layout).
 *
 *   offset 0    qv_image_header_t   (248 bytes)
 *   offset 248  zero padding        (8 bytes)
 *   offset 256  payload             (payload_size bytes)
 *
 * Trust chain for one image:
 *   ROOT KEY (compiled into firmware = simulated ROM/eFuse hash)
 *     signs  CERT  over (key_id, key_role, signer_pubkey)
 *       SIGNER KEY signs the header bytes [0, offsetof(signature))
 *         header contains SHA-256(payload)  =>  payload is bound to the signature
 */
#ifndef QV_IMAGE_FORMAT_H
#define QV_IMAGE_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include "qv_common.h"

#define QV_IMAGE_MAGIC        0x544C5651UL   /* "QVLT" little-endian */
#define QV_IMAGE_HDR_VERSION  1U
#define QV_HASH_SHA256        1U
#define QV_SIG_ED25519        1U
#define QV_HEADER_SPACE       256U           /* payload starts here */
#define QV_MAX_PAYLOAD        (0x100000U - QV_HEADER_SPACE)
#define QV_CERT_MSG_LEN       46U

typedef struct {
    uint32_t magic;
    uint16_t header_version;
    uint16_t header_size;
    uint32_t image_type;          /* qv_image_type_t */
    uint32_t fw_version;          /* monotonic security version (anti-rollback) */
    uint64_t load_addr;
    uint64_t entry_point;
    uint32_t payload_size;
    uint32_t hash_alg;
    uint32_t sig_alg;
    uint32_t key_id;
    uint32_t key_role;            /* qv_key_role_t */
    uint32_t flags;               /* must be zero */
    uint8_t  payload_hash[32];
    uint8_t  signer_pubkey[32];
    uint8_t  signer_cert[64];     /* ROOT signature over cert message */
    uint8_t  signature[64];       /* SIGNER signature over header[0..signature) */
} qv_image_header_t;

#define QV_SIGNED_LEN  offsetof(qv_image_header_t, signature)

_Static_assert(sizeof(qv_image_header_t) == 248, "header layout changed");
_Static_assert(offsetof(qv_image_header_t, signature) == 184, "signed region changed");

/* Allowed load window for each image type (from the platform memory map). */
qv_status_t qv_image_window(uint32_t type, uint64_t *base, uint64_t *size);
uint32_t    qv_role_for_type(uint32_t type);

/* Structural validation only. Treats every byte as attacker-controlled.
 * On QV_OK: *hdr is a private copy of the header, *payload points inside blob. */
qv_status_t qv_image_parse(const uint8_t *blob, size_t blob_len, uint32_t expect_type,
                           qv_image_header_t *hdr, const uint8_t **payload);

/* Canonical message the ROOT key signs to certify a signer key. */
void qv_build_cert_msg(uint8_t out[QV_CERT_MSG_LEN], uint32_t key_id, uint32_t role,
                       const uint8_t pubkey[32]);

#endif
