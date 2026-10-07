#ifndef QV_BARRIERS_H
#define QV_BARRIERS_H

#define qv_dsb(opt) __asm__ volatile("dsb " #opt ::: "memory")
#define qv_dmb(opt) __asm__ volatile("dmb " #opt ::: "memory")
#define qv_isb()    __asm__ volatile("isb" ::: "memory")
#define qv_wfe()    __asm__ volatile("wfe" ::: "memory")

#endif
