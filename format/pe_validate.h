/* PE/COFF (PE32+) structural validator for boot images. VALIDATION ONLY - it never loads,
 * relocates or executes anything. Treats every byte as attacker-controlled.
 *
 * Policy beyond the file format: machine must match, entry point must lie inside an
 * executable section, and no section may be both writable and executable (W^X). */
#ifndef QV_PE_VALIDATE_H
#define QV_PE_VALIDATE_H
#include <stdint.h>
#include <stddef.h>
#include "qv_common.h"

#define QV_PE_MACHINE_ARM64 0xAA64U

typedef struct {
    uint32_t entry_rva;
    uint32_t size_of_image;
    uint16_t num_sections;
} qv_pe_info_t;

qv_status_t qv_pe_validate(const uint8_t *buf, size_t len, uint16_t expect_machine, qv_pe_info_t *info);
#endif
