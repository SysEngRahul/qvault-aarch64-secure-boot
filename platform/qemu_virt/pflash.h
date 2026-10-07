#ifndef QV_PFLASH_H
#define QV_PFLASH_H
#include <stdint.h>
#include <stddef.h>
#include "qv_common.h"

/* Driver for QEMU virt pflash bank 1 (Intel/CFI command set, 2 x 16-bit chips in parallel
 * => every command is replicated into both halves of the 32-bit bus word). */
void        qv_pflash_read(size_t off, void *dst, size_t len);
qv_status_t qv_pflash_write_sector0(const void *src, size_t len);   /* erase sector 0, then program */
#endif
