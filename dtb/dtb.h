/* Flattened Device Tree: validation (dtb_validate.c) and a minimal safe reader (dtb_parser.c).
 * The blob is treated as ATTACKER-CONTROLLED. Nothing in dtb_parser may be called
 * on a blob that has not passed qv_dtb_validate(). */
#ifndef QV_DTB_H
#define QV_DTB_H
#include <stdint.h>
#include <stddef.h>
#include "qv_common.h"

#define FDT_MAGIC       0xD00DFEEDU
#define FDT_BEGIN_NODE  1U
#define FDT_END_NODE    2U
#define FDT_PROP        3U
#define FDT_NOP         4U
#define FDT_END         9U
#define QV_DTB_MAX_DEPTH 32U

/* `buf_len` = number of bytes actually available at `fdt` (not what the header claims). */
qv_status_t qv_dtb_validate(const void *fdt, size_t buf_len);

/* RAM described by the first /memory node (uses root #address-cells/#size-cells). */
qv_status_t qv_dtb_find_memory(const void *fdt, size_t buf_len, uint64_t *base, uint64_t *size);
/* Total size claimed by the header, bounds-checked. */
qv_status_t qv_dtb_total_size(const void *fdt, size_t buf_len, uint32_t *total);
#endif
