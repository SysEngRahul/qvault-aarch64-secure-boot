#include <string.h>
#include "pflash.h"
#include "memmap.h"

#define CMD(c)        ((((uint32_t)(c)) << 16) | (uint32_t)(c))
#define CMD_READ_ARRAY 0xFFU
#define CMD_READ_STATUS 0x70U
#define CMD_CLEAR_STATUS 0x50U
#define CMD_PROGRAM   0x40U
#define CMD_ERASE     0x20U
#define CMD_CONFIRM   0xD0U
#define ST_READY      0x00800080UL
#define ST_ERRORS     0x00780078UL     /* program/erase/VPP/command-sequence errors */
#define SPIN_LIMIT    2000000UL

static volatile uint32_t *word(size_t off) { return (volatile uint32_t *)(QV_PFLASH_BASE + off); }

static qv_status_t wait_ready(size_t off)
{
    unsigned long i;
    uint32_t st = 0;
    for (i = 0; i < SPIN_LIMIT; i++) {
        st = *word(off);
        if ((st & ST_READY) == ST_READY) { break; }
    }
    *word(off) = CMD(CMD_CLEAR_STATUS);
    *word(off) = CMD(CMD_READ_ARRAY);
    if ((st & ST_READY) != ST_READY || (st & ST_ERRORS) != 0U) { return QV_ERR_STORAGE; }
    return QV_OK;
}

void qv_pflash_read(size_t off, void *dst, size_t len)
{
    uint8_t *d = dst;
    size_t i;
    *word(0) = CMD(CMD_READ_ARRAY);
    for (i = 0; i < len; i += 4U) {
        uint32_t v = *word(off + i);                 /* aligned 32-bit reads only */
        size_t n = (len - i < 4U) ? (len - i) : 4U;
        memcpy(d + i, &v, n);
    }
}

qv_status_t qv_pflash_write_sector0(const void *src, size_t len)
{
    const uint8_t *s = src;
    size_t i;
    qv_status_t st;

    if (len > QV_PFLASH_SECTOR) { return QV_ERR_PARAM; }
    *word(0) = CMD(CMD_ERASE);
    *word(0) = CMD(CMD_CONFIRM);
    st = wait_ready(0);
    if (st != QV_OK) { return st; }
    for (i = 0; i < len; i += 4U) {
        uint32_t v = 0xFFFFFFFFU;
        size_t n = (len - i < 4U) ? (len - i) : 4U;
        memcpy(&v, s + i, n);
        *word(i) = CMD(CMD_PROGRAM);
        *word(i) = v;
        st = wait_ready(i);
        if (st != QV_OK) { return st; }
    }
    return QV_OK;
}
