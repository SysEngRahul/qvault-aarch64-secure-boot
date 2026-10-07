#include <string.h>
#include "secure_boot.h"
#include "rollback.h"
#include "storage.h"

qv_status_t qv_secure_boot_load(uint32_t type, const uint8_t *blob, size_t blob_len,
                                uint8_t *dest, qv_boot_report_t *rep)
{
    const uint8_t *payload = NULL;

    if (!rep) { return QV_ERR_PARAM; }
    memset(rep, 0, sizeof *rep);
    rep->v.hash = rep->v.cert = rep->v.sig = rep->revocation = rep->rollback = QV_ERR_NOTRUN;
    rep->final = QV_ERR_NOTRUN;

    rep->parse = qv_image_parse(blob, blob_len, type, &rep->hdr, &payload);
    if (rep->parse != QV_OK) { rep->final = rep->parse; return rep->final; }

    if (!dest) { dest = (uint8_t *)(uintptr_t)rep->hdr.load_addr; }

    /* Copy first, verify the copy: what we authenticate is what will execute. */
    memcpy(dest, payload, rep->hdr.payload_size);

    (void)qv_image_verify(&rep->hdr, dest, &rep->v);
    /* Authenticated is not the same as trusted: a validly signed key or image can still be revoked. */
    rep->revocation = (qv_storage_key_revoked(rep->hdr.key_id) || qv_storage_hash_revoked(rep->v.digest))
                          ? QV_ERR_REVOKED : QV_OK;
    rep->rollback = qv_rollback_check(type, rep->hdr.fw_version);

    if (rep->v.hash != QV_OK)  { rep->final = rep->v.hash; }
    else if (rep->v.cert != QV_OK) { rep->final = rep->v.cert; }
    else if (rep->v.sig != QV_OK)  { rep->final = rep->v.sig; }
    else if (rep->revocation != QV_OK) { rep->final = rep->revocation; }
    else if (rep->rollback != QV_OK) { rep->final = rep->rollback; }
    else { rep->final = QV_OK; }

    if (rep->final != QV_OK) { memset(dest, 0, rep->hdr.payload_size); }
    return rep->final;
}
