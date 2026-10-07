#include <string.h>
#include "pe_validate.h"

#define IMAGE_SCN_CNT_CODE   0x00000020U
#define IMAGE_SCN_MEM_EXEC   0x20000000U
#define IMAGE_SCN_MEM_WRITE  0x80000000U
#define MAX_SECTIONS 96U
#define SEC_HDR_SIZE 40U
#define OPT_FIXED_SIZE 112U            /* PE32+ optional header up to the data directories */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static int pow2(uint32_t v) { return v != 0U && (v & (v - 1U)) == 0U; }
/* [off, off+n) inside [0, len) without overflow */
static int fits(uint64_t off, uint64_t n, uint64_t len) { return off <= len && n <= len - off; }

qv_status_t qv_pe_validate(const uint8_t *buf, size_t len, uint16_t expect_machine, qv_pe_info_t *info)
{
    uint32_t lfanew, opt_size, num_rva, falign, salign, soi, soh, entry, prev_end = 0;
    uint64_t coff, opt, sec;
    uint16_t nsec, i;
    int entry_ok = 0;

    if (!buf || !info) { return QV_ERR_PARAM; }
    if (len < 0x40U || buf[0] != 'M' || buf[1] != 'Z') { return QV_ERR_MAGIC; }
    lfanew = rd32(buf + 0x3C);
    if (lfanew < 0x40U || (lfanew & 3U) != 0U) { return QV_ERR_RANGE; }
    if (!fits(lfanew, 4U + 20U, len)) { return QV_ERR_SIZE; }
    if (memcmp(buf + lfanew, "PE\0\0", 4) != 0) { return QV_ERR_MAGIC; }

    coff = (uint64_t)lfanew + 4U;
    if (rd16(buf + coff) != expect_machine) { return QV_ERR_TYPE; }
    nsec = rd16(buf + coff + 2);
    opt_size = rd16(buf + coff + 16);
    if (nsec == 0U || nsec > MAX_SECTIONS) { return QV_ERR_SIZE; }
    if (opt_size < OPT_FIXED_SIZE) { return QV_ERR_SIZE; }

    opt = coff + 20U;
    if (!fits(opt, opt_size, len)) { return QV_ERR_SIZE; }
    if (rd16(buf + opt) != 0x20BU) { return QV_ERR_MAGIC; }            /* PE32+ only */
    entry  = rd32(buf + opt + 16);
    salign = rd32(buf + opt + 32);
    falign = rd32(buf + opt + 36);
    soi    = rd32(buf + opt + 56);
    soh    = rd32(buf + opt + 60);
    num_rva = rd32(buf + opt + 108);
    if (num_rva > 16U || opt_size < OPT_FIXED_SIZE + 8U * num_rva) { return QV_ERR_SIZE; }

    if (!pow2(salign) || !pow2(falign) || falign < 512U || falign > 65536U) { return QV_ERR_RANGE; }
    if (salign < falign && salign < 4096U) { return QV_ERR_RANGE; }
    if (soh == 0U || soh > soi || soh > len || (soi % salign) != 0U) { return QV_ERR_SIZE; }

    sec = opt + opt_size;
    if (!fits(sec, (uint64_t)nsec * SEC_HDR_SIZE, len)) { return QV_ERR_SIZE; }
    if (sec + (uint64_t)nsec * SEC_HDR_SIZE > soh) { return QV_ERR_SIZE; }  /* headers must be covered by SizeOfHeaders */

    for (i = 0; i < nsec; i++) {
        const uint8_t *s = buf + sec + (uint64_t)i * SEC_HDR_SIZE;
        uint32_t vsize = rd32(s + 8), va = rd32(s + 12), rsize = rd32(s + 16), rptr = rd32(s + 20), ch = rd32(s + 36);
        uint64_t extent = (vsize > rsize) ? vsize : rsize;

        if ((ch & IMAGE_SCN_MEM_EXEC) && (ch & IMAGE_SCN_MEM_WRITE)) { return QV_ERR_RANGE; }   /* W^X */
        if (va < soh || (va % salign) != 0U) { return QV_ERR_RANGE; }
        if (va < prev_end) { return QV_ERR_RANGE; }                     /* ascending, non-overlapping */
        if ((uint64_t)va + extent > soi) { return QV_ERR_RANGE; }
        if (rsize != 0U) {
            if ((rptr % falign) != 0U || rptr < soh || !fits(rptr, rsize, len)) { return QV_ERR_SIZE; }
        }
        prev_end = (uint32_t)((uint64_t)va + extent);                   /* <= soi (checked) so no wrap */
        if ((ch & (IMAGE_SCN_MEM_EXEC | IMAGE_SCN_CNT_CODE)) != 0U && (ch & IMAGE_SCN_MEM_EXEC) &&
            entry >= va && (uint64_t)entry < (uint64_t)va + vsize) {
            entry_ok = 1;
        }
    }
    if (!entry_ok) { return QV_ERR_RANGE; }                             /* entry must be inside executable code */

    info->entry_rva = entry; info->size_of_image = soi; info->num_sections = nsec;
    return QV_OK;
}
