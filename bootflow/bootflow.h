#ifndef QV_BOOTFLOW_H
#define QV_BOOTFLOW_H
#include <stdint.h>
#include "qv_common.h"
#include "secure_boot.h"
#include "measurement.h"

#define QV_BOOTINFO_MAGIC 0x49425651UL      /* "QVBI" */

/* Stage 1 -> Stage 2 handoff (passed in x0). */
typedef struct {
    uint32_t        magic;
    uint32_t        stage2_version;
    uint32_t        stage2_slot;
    uint32_t        reserved;
    qv_meas_state_t meas;
} qv_bootinfo_t;

typedef struct {
    uint8_t           slot;
    qv_image_header_t hdr;
    uint8_t           digest[32];
} qv_loaded_image_t;

/* image_loader.c */
const uint8_t *qv_flash_slot(uint32_t type, uint8_t slot);      /* storage address of a slot */
qv_status_t    qv_load_slot(uint32_t type, uint8_t slot, qv_boot_report_t *rep);

/* boot_policy.c: try candidates in order, verify, report, fall back, or halt. */
qv_status_t qv_boot_load_with_recovery(uint32_t type, const char *name, int verbose_auth,
                                       qv_loaded_image_t *out);

/* recovery.c */
void qv_recovery_halt(const char *what) __attribute__((noreturn));

void qv_stage1_main(void);
void qv_stage2_main(qv_bootinfo_t *bi);
#endif
