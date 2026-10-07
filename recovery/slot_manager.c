#include "slot_manager.h"
#include "storage.h"

const char *qv_slot_name(uint8_t slot) { return slot == 0U ? "A" : "B"; }

static int usable(const qv_slot_record_t *r, unsigned s)
{
    if (r->state[s] == QV_SLOT_VALID) { return 1; }
    if (r->state[s] == QV_SLOT_PENDING && r->tries[s] < QV_MAX_PENDING_TRIES) { return 1; }
    return 0;
}

unsigned qv_slot_candidates(uint32_t type, uint8_t order[2])
{
    qv_slot_record_t r;
    unsigned n = 0, first, second;

    if (qv_storage_get_slot(type, &r) != QV_OK) { return 0; }
    first = r.active; second = 1U - r.active;
    if (usable(&r, first))  { order[n++] = (uint8_t)first; }
    if (usable(&r, second)) { order[n++] = (uint8_t)second; }
    return n;
}

qv_status_t qv_slot_begin_boot(uint32_t type, uint8_t slot)
{
    qv_slot_record_t r;
    qv_status_t st = qv_storage_get_slot(type, &r);
    if (st != QV_OK || slot > 1U) { return QV_ERR_PARAM; }
    if (r.state[slot] == QV_SLOT_PENDING) { r.tries[slot]++; return qv_storage_set_slot(type, &r); }
    return QV_OK;
}

qv_status_t qv_slot_mark_invalid(uint32_t type, uint8_t slot)
{
    qv_slot_record_t r;
    qv_status_t st = qv_storage_get_slot(type, &r);
    if (st != QV_OK || slot > 1U) { return QV_ERR_PARAM; }
    r.state[slot] = QV_SLOT_INVALID;
    if (r.active == slot) { r.active = 1U - slot; }   /* fail over; written last by set_slot */
    return qv_storage_set_slot(type, &r);
}

qv_status_t qv_slot_mark_good(uint32_t type, uint8_t slot)
{
    qv_slot_record_t r;
    qv_status_t st = qv_storage_get_slot(type, &r);
    if (st != QV_OK || slot > 1U) { return QV_ERR_PARAM; }
    r.state[slot] = QV_SLOT_VALID;
    r.tries[slot] = 0;
    r.active = slot;
    return qv_storage_set_slot(type, &r);
}
