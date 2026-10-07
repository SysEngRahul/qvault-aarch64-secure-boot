#include <string.h>
#include "measurement.h"
#include "crypto_backend.h"

void qv_meas_init(qv_meas_state_t *m)
{
    memset(m, 0, sizeof *m);
    m->magic = QV_MEAS_MAGIC;
}

int qv_meas_valid(const qv_meas_state_t *m)
{
    return m && m->magic == QV_MEAS_MAGIC && m->count <= QV_MEAS_MAX;
}

int qv_meas_extend(qv_meas_state_t *m, uint32_t pcr, const char *name, const uint8_t digest[32])
{
    uint8_t buf[64];
    qv_meas_event_t *e;
    size_t n;

    if (!qv_meas_valid(m) || pcr >= QV_PCR_COUNT || m->count >= QV_MEAS_MAX) { return -1; }
    memcpy(buf, m->pcr[pcr], 32);
    memcpy(buf + 32, digest, 32);
    qv_crypto_sha256(buf, sizeof buf, m->pcr[pcr]);

    e = &m->events[m->count++];
    memset(e, 0, sizeof *e);
    for (n = 0; n < sizeof e->name - 1U && name[n]; n++) { e->name[n] = name[n]; }
    e->pcr = pcr;
    memcpy(e->digest, digest, 32);
    return 0;
}
