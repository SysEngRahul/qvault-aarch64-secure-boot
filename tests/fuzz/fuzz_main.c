/* Mutation fuzzer for the two attacker-facing parsers (DTB, image header).
 *   fuzz_main dtb|image|pe SEEDFILE ITERATIONS [RNGSEED]
 * Built with ASan+UBSan: any out-of-bounds access, overflow or UB aborts the run.
 * Also exposes LLVMFuzzerTestOneInput for libFuzzer (clang -fsanitize=fuzzer). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "image_format.h"
#include "image_verify.h"
#include "dtb.h"
#include "pe_validate.h"
#include "../common/pe_sample.h"

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static void target_dtb(const uint8_t *d, size_t n)
{
    uint64_t b, s;
    if (qv_dtb_validate(d, n) == QV_OK) { (void)qv_dtb_find_memory(d, n, &b, &s); }
}

static void target_pe(const uint8_t *d, size_t n)
{
    qv_pe_info_t i;
    (void)qv_pe_validate(d, n, QV_PE_MACHINE_ARM64, &i);
}

static void target_image(const uint8_t *d, size_t n)
{
    qv_image_header_t h; const uint8_t *p; qv_verify_result_t r;
    uint32_t t;
    for (t = 1; t <= 3; t++) {
        if (qv_image_parse(d, n, t, &h, &p) == QV_OK) { (void)qv_image_verify(&h, p, &r); }
    }
}

#ifdef __clang__
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { target_dtb(d, n); target_image(d, n); return 0; }
#endif

static void mutate(uint8_t *b, size_t *n, size_t cap)
{
    unsigned k = 1 + (unsigned)(rnd() % 4);
    while (k--) {
        switch (rnd() % 6) {
        case 0: if (*n) b[rnd() % *n] ^= (uint8_t)(1U << (rnd() % 8)); break;           /* bit flip */
        case 1: if (*n) b[rnd() % *n] = (uint8_t)rnd(); break;                           /* random byte */
        case 2: if (*n) { size_t o = rnd() % *n; b[o] = (rnd() & 1) ? 0xFF : 0x00; } break; /* extremes */
        case 3: if (*n > 4) { size_t o = rnd() % (*n - 3); uint32_t v = (uint32_t)rnd();    /* 32-bit field smash */
                  if (rnd() & 1) { v = (rnd() & 1) ? 0xFFFFFFFFu : 0x7FFFFFFFu; } memcpy(b + o, &v, 4); } break;
        case 4: if (*n > 1) { *n = 1 + rnd() % *n; } break;                              /* truncate */
        case 5: if (*n && *n + 16 <= cap) { size_t o = rnd() % *n; memmove(b + o + 8, b + o, *n - o); *n += 8; } break;
        }
    }
}

int main(int argc, char **argv)
{
    FILE *f; uint8_t *seed, *buf; long sl; size_t cap, n; unsigned long iters, i; int dtb;
    if (argc < 4) { fprintf(stderr, "usage: fuzz_main dtb|image SEED ITERS [RNG]\n"); return 2; }
    dtb = strcmp(argv[1], "dtb") == 0;
    if (strcmp(argv[1], "pe") == 0) {                      /* built-in valid PE seed */
        seed = malloc(4096); sl = (long)build_pe(seed);
    } else {
        f = fopen(argv[2], "rb"); if (!f) { perror("seed"); return 2; }
        fseek(f, 0, SEEK_END); sl = ftell(f); fseek(f, 0, SEEK_SET);
        seed = malloc((size_t)sl); if (fread(seed, 1, (size_t)sl, f) != (size_t)sl) { return 2; } fclose(f);
    }
    if (argc > 4) { rs ^= strtoull(argv[4], NULL, 0) * 0x9E3779B97F4A7C15ULL; }
    iters = strtoul(argv[3], NULL, 0);
    cap = (size_t)sl + 4096; buf = malloc(cap);
    for (i = 0; i < iters; i++) {
        n = (size_t)sl; memcpy(buf, seed, n);
        mutate(buf, &n, cap);
        /* Exact-size heap copy so ASan sees any read past the end of the "blob". */
        { uint8_t *e = malloc(n ? n : 1); memcpy(e, buf, n);
          if (dtb) { target_dtb(e, n); } else if (argv[1][0] == 'p') { target_pe(e, n); } else { target_image(e, n); }
          free(e); }
    }
    free(seed); free(buf);
    printf("fuzz %s: %lu iterations, no crashes\n", argv[1], iters);
    return 0;
}
