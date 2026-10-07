#ifndef QV_MMU_H
#define QV_MMU_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qv_common.h"

typedef enum {
    QV_MMU_RW  = 0,   /* normal memory, read/write, never executable */
    QV_MMU_RX  = 1,   /* read-only, executable (code)                */
    QV_MMU_RO  = 2,   /* read-only, never executable (rodata)        */
    QV_MMU_DEV = 3    /* device-nGnRnE, never executable             */
} qv_mmu_attr_t;

void        qv_mmu_init(void);      /* build default identity map: 0-1G device, 1-2G RAM RW+XN */
qv_status_t qv_mmu_map(uintptr_t pa, size_t size, qv_mmu_attr_t attr);   /* 4 KiB granular, identity */
void        qv_mmu_enable(void);
void        qv_mmu_disable(void);   /* flushes caches, MMU+D/I-cache off (OS handoff state) */
bool        qv_mmu_is_enabled(void);
/* Ask the hardware translator: can EL1 write / execute this VA? (AT S1E1W/R) */
bool        qv_mmu_probe_write(uintptr_t va);
bool        qv_mmu_probe_read(uintptr_t va);
#endif
