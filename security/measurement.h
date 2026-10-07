/* Measured boot (software TPM-style PCRs).
 * Secure boot answers "was this allowed to run?"; measured boot records
 * "what actually ran?" so a later verifier/OS can check it. */
#ifndef QV_MEASUREMENT_H
#define QV_MEASUREMENT_H
#include <stdint.h>

#define QV_PCR_COUNT   8U
#define QV_MEAS_MAX    8U
#define QV_MEAS_MAGIC  0x4D455351UL        /* "QSEM" */

enum { QV_PCR_STAGE1 = 0, QV_PCR_STAGE2 = 1, QV_PCR_UEFI = 2, QV_PCR_KERNEL = 3, QV_PCR_DTB = 4 };

typedef struct {
    char     name[16];
    uint32_t pcr;
    uint8_t  digest[32];
} qv_meas_event_t;

typedef struct {
    uint32_t magic;
    uint32_t count;
    uint8_t  pcr[QV_PCR_COUNT][32];
    qv_meas_event_t events[QV_MEAS_MAX];
} qv_meas_state_t;

void qv_meas_init(qv_meas_state_t *m);
/* PCR[i] = SHA-256( PCR[i] || digest ), and append to the event log. */
int  qv_meas_extend(qv_meas_state_t *m, uint32_t pcr, const char *name, const uint8_t digest[32]);
int  qv_meas_valid(const qv_meas_state_t *m);
#endif
