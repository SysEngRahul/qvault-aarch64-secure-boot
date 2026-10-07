#include <string.h>
#include "image_format.h"
#include "memmap.h"

qv_status_t qv_image_window(uint32_t type, uint64_t *base, uint64_t *size)
{
    switch (type) {
    case QV_IMG_STAGE2: *base = QV_STAGE2_WIN_BASE; *size = QV_STAGE2_WIN_SIZE; return QV_OK;
    case QV_IMG_UEFI:   *base = QV_UEFI_WIN_BASE;   *size = QV_UEFI_WIN_SIZE;   return QV_OK;
    case QV_IMG_KERNEL: *base = QV_KERNEL_WIN_BASE; *size = QV_KERNEL_WIN_SIZE; return QV_OK;
    case QV_IMG_DTB:    *base = QV_DTB_WIN_BASE;    *size = QV_DTB_WIN_SIZE;    return QV_OK;
    default:            return QV_ERR_TYPE;
    }
}

uint32_t qv_role_for_type(uint32_t type)
{
    switch (type) {
    case QV_IMG_STAGE2: return QV_ROLE_FIRMWARE;
    case QV_IMG_UEFI:   return QV_ROLE_UEFI;
    case QV_IMG_KERNEL: return QV_ROLE_OS;
    case QV_IMG_DTB:    return QV_ROLE_DTB;
    default:            return 0;
    }
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void qv_build_cert_msg(uint8_t out[QV_CERT_MSG_LEN], uint32_t key_id, uint32_t role,
                       const uint8_t pubkey[32])
{
    static const uint8_t tag[6] = { 'Q', 'V', 'K', 'E', 'Y', 0x01 };
    memcpy(out, tag, sizeof tag);
    put_le32(out + 6, key_id);
    put_le32(out + 10, role);
    memcpy(out + 14, pubkey, 32);
}

qv_status_t qv_image_parse(const uint8_t *blob, size_t blob_len, uint32_t expect_type,
                           qv_image_header_t *hdr, const uint8_t **payload)
{
    uint64_t wbase, wsize, wend;
    qv_status_t st;

    if (!blob || !hdr || !payload) { return QV_ERR_PARAM; }
    if (blob_len < QV_HEADER_SPACE) { return QV_ERR_SIZE; }

    memcpy(hdr, blob, sizeof *hdr);          /* private copy: no TOCTOU on header fields */

    if (hdr->magic != QV_IMAGE_MAGIC) { return QV_ERR_MAGIC; }
    if (hdr->header_version != QV_IMAGE_HDR_VERSION || hdr->header_size != sizeof *hdr) {
        return QV_ERR_VERSION;
    }
    if (hdr->image_type != expect_type) { return QV_ERR_TYPE; }
    st = qv_image_window(hdr->image_type, &wbase, &wsize);
    if (st != QV_OK) { return st; }
    if (hdr->flags != 0U) { return QV_ERR_PARAM; }
    if (hdr->hash_alg != QV_HASH_SHA256 || hdr->sig_alg != QV_SIG_ED25519) { return QV_ERR_ALG; }
    if (hdr->key_role != qv_role_for_type(hdr->image_type)) { return QV_ERR_TYPE; }

    /* payload_size: non-zero, within format limit, and fully inside the supplied blob.
     * blob_len >= QV_HEADER_SPACE was checked above, so the subtraction cannot wrap. */
    if (hdr->payload_size == 0U || hdr->payload_size > QV_MAX_PAYLOAD) { return QV_ERR_SIZE; }
    if ((size_t)hdr->payload_size > blob_len - QV_HEADER_SPACE) { return QV_ERR_SIZE; }

    /* load range must lie entirely inside this type's window; comparisons avoid overflow. */
    wend = wbase + wsize;
    if ((hdr->load_addr & 0xFU) != 0U) { return QV_ERR_RANGE; }
    if (hdr->load_addr < wbase || hdr->load_addr >= wend) { return QV_ERR_RANGE; }
    if ((uint64_t)hdr->payload_size > wend - hdr->load_addr) { return QV_ERR_RANGE; }

    /* entry point must be 4-byte aligned and inside the payload. */
    if ((hdr->entry_point & 3U) != 0U) { return QV_ERR_RANGE; }
    if (hdr->entry_point < hdr->load_addr ||
        hdr->entry_point - hdr->load_addr >= (uint64_t)hdr->payload_size) {
        return QV_ERR_RANGE;
    }

    *payload = blob + QV_HEADER_SPACE;
    return QV_OK;
}
