/* Builds a minimal valid ARM64 PE32+ image (one .text section) for tests and the fuzzer. */
#ifndef QV_PE_SAMPLE_H
#define QV_PE_SAMPLE_H
#include <stdint.h>
#include <string.h>

static inline void pe_w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void pe_w32(uint8_t *p, uint32_t v) { pe_w16(p, (uint16_t)v); pe_w16(p + 2, (uint16_t)(v >> 16)); }

static inline size_t build_pe(uint8_t *b)       /* returns file length (b must hold 4096 bytes) */
{
    const uint32_t lfanew = 0x80, opt = lfanew + 4 + 20, optsz = 112 + 16 * 8, sec = opt + optsz;
    memset(b, 0, 4096);
    b[0] = 'M'; b[1] = 'Z'; pe_w32(b + 0x3C, lfanew);
    memcpy(b + lfanew, "PE\0\0", 4);
    pe_w16(b + lfanew + 4, 0xAA64); pe_w16(b + lfanew + 6, 1); pe_w16(b + lfanew + 20, optsz);
    pe_w16(b + opt, 0x20B); pe_w32(b + opt + 16, 0x1000);            /* entry RVA */
    pe_w32(b + opt + 32, 0x1000); pe_w32(b + opt + 36, 0x200);       /* section / file alignment */
    pe_w32(b + opt + 56, 0x2000); pe_w32(b + opt + 60, 0x200);       /* size of image / headers */
    pe_w32(b + opt + 108, 16);
    memcpy(b + sec, ".text", 5);
    pe_w32(b + sec + 8, 0x100); pe_w32(b + sec + 12, 0x1000);        /* vsize, va */
    pe_w32(b + sec + 16, 0x200); pe_w32(b + sec + 20, 0x400);        /* raw size, raw ptr */
    pe_w32(b + sec + 36, 0x60000020);                                /* code | exec | read */
    return 0x600;                                                    /* file: headers(0x200) + gap + raw(0x400..0x600) */
}
#endif
