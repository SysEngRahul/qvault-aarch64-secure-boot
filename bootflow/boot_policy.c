/* Boot policy: for each image type, try the candidate slots in order. A slot
 * that fails verification is marked INVALID (so it is not retried) and we fail
 * over to the other slot. If none verifies we halt in recovery mode; we NEVER
 * fall through to executing unverified code. */
#include <string.h>
#include "bootflow.h"
#include "slot_manager.h"
#include "log.h"

static const char *st_ok(qv_status_t s)
{
    return s == QV_OK ? "OK" : (s == QV_ERR_NOTRUN ? "-" : "FAIL");
}

static void label(char *out, size_t n, const char *name, const char *what)
{
    size_t i = 0, j = 0;
    while (i < n - 1U && name[i]) { out[i] = name[i]; i++; }
    if (i < n - 1U) { out[i++] = ' '; }
    while (i < n - 1U && what[j]) { out[i++] = what[j++]; }
    out[i] = 0;
}

static void report_success(const char *name, int verbose, const qv_boot_report_t *r)
{
    char l[48];
    if (verbose) {
        label(l, sizeof l, name, "signature");
        qv_report("AUTH", l, (r->v.cert == QV_OK && r->v.sig == QV_OK) ? "OK" : "FAIL");
        label(l, sizeof l, name, "hash");
        qv_report("AUTH", l, "OK");
        qv_report_u32("AUTH", "Firmware version", r->hdr.fw_version);
        qv_report("AUTH", "Anti-rollback", "OK");
    } else {
        label(l, sizeof l, name, "signature");
        qv_report("AUTH", l, "OK");
    }
}

static void report_failure(const char *name, uint8_t slot, const qv_boot_report_t *r)
{
    char l[48];
    if (r->parse != QV_OK) {
        label(l, sizeof l, name, "image format");
        qv_report("AUTH", l, "FAIL");
    } else {
        label(l, sizeof l, name, "hash");
        qv_report("AUTH", l, st_ok(r->v.hash));
        label(l, sizeof l, name, "key certificate");
        qv_report("AUTH", l, st_ok(r->v.cert));
        label(l, sizeof l, name, "signature");
        qv_report("AUTH", l, st_ok(r->v.sig));
        label(l, sizeof l, name, "revocation");
        qv_report("AUTH", l, st_ok(r->revocation));
        label(l, sizeof l, name, "anti-rollback");
        qv_report("AUTH", l, st_ok(r->rollback));
    }
    qv_printf("[BOOT] %s rejected (slot %s): %s\n", name, qv_slot_name(slot), qv_status_str(r->final));
}

qv_status_t qv_boot_load_with_recovery(uint32_t type, const char *name, int verbose_auth,
                                       qv_loaded_image_t *out)
{
    uint8_t order[2];
    unsigned i, attempts = 0;
    char msg[64];

    for (;;) {
        unsigned n = qv_slot_candidates(type, order);
        if (n == 0U) { break; }
        for (i = 0; i < n; i++) {
            qv_boot_report_t rep;
            uint8_t slot = order[i];

            if (attempts > 0U) { qv_printf("[RECOVERY] Trying backup slot %s...\n", qv_slot_name(slot)); }
            attempts++;
            (void)qv_slot_begin_boot(type, slot);

            if (qv_load_slot(type, slot, &rep) == QV_OK) {
                if (attempts > 1U) {
                    qv_printf("[RECOVERY] Slot %s verified\n[RECOVERY] Booting slot %s\n",
                              qv_slot_name(slot), qv_slot_name(slot));
                }
                report_success(name, verbose_auth, &rep);
                out->slot = slot;
                out->hdr = rep.hdr;
                memcpy(out->digest, rep.v.digest, 32);
                return QV_OK;
            }
            report_failure(name, slot, &rep);
            (void)qv_slot_mark_invalid(type, slot);
            break;                      /* re-read slot state, then try the next candidate */
        }
    }
    label(msg, sizeof msg, name, "unrecoverable");
    qv_recovery_halt(msg);
}
