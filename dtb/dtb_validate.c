#include <string.h>
#include "dtb.h"

typedef struct {
    uint32_t magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap,
             version, last_comp_version, boot_cpuid_phys, size_dt_strings, size_dt_struct;
} fdt_header_t;

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static qv_status_t read_header(const uint8_t *b, size_t len, fdt_header_t *h)
{
    if (!b || !h || len < 40U) { return QV_ERR_DTB; }
    h->magic = be32(b); h->totalsize = be32(b + 4); h->off_dt_struct = be32(b + 8);
    h->off_dt_strings = be32(b + 12); h->off_mem_rsvmap = be32(b + 16); h->version = be32(b + 20);
    h->last_comp_version = be32(b + 24); h->boot_cpuid_phys = be32(b + 28);
    h->size_dt_strings = be32(b + 32); h->size_dt_struct = be32(b + 36);
    return QV_OK;
}

/* [off, off+size) lies inside [0, total)? (overflow-safe) */
static int in_range(uint64_t off, uint64_t size, uint64_t total)
{
    return off <= total && size <= total - off;
}

qv_status_t qv_dtb_total_size(const void *fdt, size_t buf_len, uint32_t *total)
{
    fdt_header_t h;
    if (read_header(fdt, buf_len, &h) != QV_OK || h.magic != FDT_MAGIC) { return QV_ERR_DTB; }
    if (h.totalsize < 40U || h.totalsize > buf_len) { return QV_ERR_DTB; }
    *total = h.totalsize;
    return QV_OK;
}

qv_status_t qv_dtb_validate(const void *fdt, size_t buf_len)
{
    const uint8_t *b = fdt;
    fdt_header_t h;
    uint64_t off, end;
    unsigned depth = 0;
    int seen_end = 0;

    if (read_header(b, buf_len, &h) != QV_OK) { return QV_ERR_DTB; }
    if (h.magic != FDT_MAGIC) { return QV_ERR_DTB; }
    if (h.totalsize < 40U || h.totalsize > buf_len) { return QV_ERR_DTB; }       /* truncated / oversized */
    if (h.version < 17U || h.last_comp_version > 17U) { return QV_ERR_DTB; }
    if ((h.off_dt_struct & 3U) || (h.size_dt_struct & 3U) || (h.off_mem_rsvmap & 7U)) { return QV_ERR_DTB; }
    if (!in_range(h.off_dt_struct, h.size_dt_struct, h.totalsize)) { return QV_ERR_DTB; }
    if (!in_range(h.off_dt_strings, h.size_dt_strings, h.totalsize)) { return QV_ERR_DTB; }
    if (h.off_mem_rsvmap < 40U || h.off_mem_rsvmap > h.totalsize) { return QV_ERR_DTB; }

    /* Memory reservation map: 16-byte entries, terminated by an all-zero entry. */
    off = h.off_mem_rsvmap;
    for (;;) {
        if (!in_range(off, 16U, h.totalsize)) { return QV_ERR_DTB; }
        if (be64(b + off) == 0 && be64(b + off + 8) == 0) { break; }
        off += 16U;
    }

    /* Structure block walk. */
    off = h.off_dt_struct;
    end = (uint64_t)h.off_dt_struct + h.size_dt_struct;
    while (off < end) {
        uint32_t tok;
        if (end - off < 4U) { return QV_ERR_DTB; }
        tok = be32(b + off); off += 4U;

        switch (tok) {
        case FDT_BEGIN_NODE: {
            uint64_t n = 0;
            if (depth >= QV_DTB_MAX_DEPTH) { return QV_ERR_DTB; }
            while (off + n < end && b[off + n] != 0) { n++; }
            if (off + n >= end) { return QV_ERR_DTB; }              /* unterminated name */
            off += (n + 1U + 3U) & ~(uint64_t)3U;                    /* name + NUL, 4-aligned */
            if (off > end) { return QV_ERR_DTB; }
            depth++;
            break; }
        case FDT_END_NODE:
            if (depth == 0U) { return QV_ERR_DTB; }                  /* underflow */
            depth--;
            break;
        case FDT_PROP: {
            uint32_t len, nameoff;
            uint64_t s;
            if (depth == 0U || end - off < 8U) { return QV_ERR_DTB; }
            len = be32(b + off); nameoff = be32(b + off + 4); off += 8U;
            if (len > end - off) { return QV_ERR_DTB; }              /* oversized property */
            off += ((uint64_t)len + 3U) & ~(uint64_t)3U;
            if (off > end) { return QV_ERR_DTB; }
            if (nameoff >= h.size_dt_strings) { return QV_ERR_DTB; }
            for (s = nameoff; s < h.size_dt_strings && b[h.off_dt_strings + s] != 0; s++) { }
            if (s >= h.size_dt_strings) { return QV_ERR_DTB; }       /* unterminated name string */
            break; }
        case FDT_NOP:
            break;
        case FDT_END:
            seen_end = 1;
            if (off != end || depth != 0U) { return QV_ERR_DTB; }
            break;
        default:
            return QV_ERR_DTB;                                       /* unknown token */
        }
        if (seen_end) { break; }
    }
    return (seen_end && depth == 0U) ? QV_OK : QV_ERR_DTB;
}
