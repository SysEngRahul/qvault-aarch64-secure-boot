#ifndef QV_SLOT_MANAGER_H
#define QV_SLOT_MANAGER_H
#include "qv_common.h"

#define QV_MAX_PENDING_TRIES 3U

/* Fill order[] with the slots worth trying, best first. Returns how many (0..2).
 * Active slot first (if VALID or PENDING with tries left), then the other if VALID/PENDING. */
unsigned    qv_slot_candidates(uint32_t type, uint8_t order[2]);
qv_status_t qv_slot_begin_boot(uint32_t type, uint8_t slot);     /* counts a try for PENDING slots */
qv_status_t qv_slot_mark_invalid(uint32_t type, uint8_t slot);
qv_status_t qv_slot_mark_good(uint32_t type, uint8_t slot);      /* promotes PENDING -> VALID, makes it active */
const char *qv_slot_name(uint8_t slot);
#endif
