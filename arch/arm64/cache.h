#ifndef QV_CACHE_H
#define QV_CACHE_H
#include <stdint.h>
#include <stddef.h>

void qv_cache_clean_range(uintptr_t addr, size_t size);       /* DC CVAC */
void qv_cache_flush_range(uintptr_t addr, size_t size);       /* DC CIVAC */
void qv_cache_sync_code(uintptr_t addr, size_t size);         /* make freshly written code executable */
void qv_icache_invalidate_all(void);
void qv_dcache_flush_all(void);                                /* clean+invalidate by set/way */
#endif
