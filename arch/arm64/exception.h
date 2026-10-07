#ifndef QV_EXCEPTION_H
#define QV_EXCEPTION_H
#include <stdint.h>
#include <stdbool.h>

/* Register frame pushed by boot/exceptions.S (must match the assembly). */
typedef struct {
    uint64_t x[31];
    uint64_t elr;
    uint64_t spsr;
    uint64_t esr;
    uint64_t far;
} qv_exc_frame_t;

extern char qv_vector_table[];

void qv_exception_init(void);        /* install VBAR_EL1 */
bool qv_exception_selftest(void);    /* trigger BRK #0x5156 and verify ESR/ELR handling */
void qv_exception_handler(unsigned vector, qv_exc_frame_t *f);   /* called from assembly */
#endif
