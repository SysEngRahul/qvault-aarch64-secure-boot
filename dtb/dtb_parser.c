/* Minimal reader. PRECONDITION: qv_dtb_validate() == QV_OK on the same blob/length.
 * Every access is still bounds-checked (defence in depth). */
#include <string.h>
#include "dtb.h"

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_cells(const uint8_t *p, uint32_t cells)
{
    uint64_t v = 0;
    uint32_t i;
    for (i = 0; i < cells; i++) { v = (v << 32) | be32(p + (size_t)4U * i); }
    return v;
}

qv_status_t qv_dtb_find_memory(const void *fdt, size_t buf_len, uint64_t *base, uint64_t *size)
{
    const uint8_t *b = fdt;
    uint32_t total, off_struct, size_struct, off_str, size_str;
    uint32_t addr_cells = 2, size_cells = 2;
    uint64_t off, end;
    unsigned depth = 0;
    int mem_node = 0;
    const uint8_t *reg = NULL;
    uint32_t reg_len = 0;
    uint64_t s;

    if (!base || !size || qv_dtb_total_size(fdt, buf_len, &total) != QV_OK) { return QV_ERR_DTB; }
    off_struct = be32(b + 8); off_str = be32(b + 12);
    size_str = be32(b + 32);  size_struct = be32(b + 36);
    off = off_struct; end = (uint64_t)off_struct + size_struct;
    if (end > total || (uint64_t)off_str + size_str > total) { return QV_ERR_DTB; }

    while (off + 4U <= end) {
        uint32_t tok = be32(b + off); off += 4U;
        if (tok == FDT_BEGIN_NODE) {
            uint64_t n = 0;
            while (off + n < end && b[off + n]) { n++; }
            if (off + n >= end) { return QV_ERR_DTB; }
            if (depth == 1U && n >= 6U && memcmp(b + off, "memory", 6) == 0) { mem_node = 1; }
            off += (n + 4U) & ~(uint64_t)3U;
            depth++;
        } else if (tok == FDT_END_NODE) {
            if (depth == 2U && mem_node && reg) { break; }
            if (depth == 2U) { mem_node = 0; }
            if (depth == 0U) { return QV_ERR_DTB; }
            depth--;
        } else if (tok == FDT_PROP) {
            uint32_t len, nameoff;
            const char *name;
            if (off + 8U > end) { return QV_ERR_DTB; }
            len = be32(b + off); nameoff = be32(b + off + 4); off += 8U;
            if (len > end - off || nameoff >= size_str) { return QV_ERR_DTB; }
            name = (const char *)(b + off_str + nameoff);
            for (s = nameoff; s < size_str && b[off_str + s]; s++) { }
            if (s >= size_str) { return QV_ERR_DTB; }
            if (depth == 1U && len == 4U && strcmp(name, "#address-cells") == 0) { addr_cells = be32(b + off); }
            if (depth == 1U && len == 4U && strcmp(name, "#size-cells") == 0)    { size_cells = be32(b + off); }
            if (depth == 2U && mem_node && strcmp(name, "reg") == 0) { reg = b + off; reg_len = len; }
            off += ((uint64_t)len + 3U) & ~(uint64_t)3U;
        } else if (tok == FDT_END) {
            break;
        } else if (tok != FDT_NOP) {
            return QV_ERR_DTB;
        }
    }

    if (!reg || addr_cells == 0U || addr_cells > 2U || size_cells == 0U || size_cells > 2U) { return QV_ERR_DTB; }
    if (reg_len < 4U * (addr_cells + size_cells)) { return QV_ERR_DTB; }
    *base = read_cells(reg, addr_cells);
    *size = read_cells(reg + (size_t)4U * addr_cells, size_cells);
    return QV_OK;
}
