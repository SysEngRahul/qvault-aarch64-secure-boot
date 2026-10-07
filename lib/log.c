/* Tiny printf for the freestanding build: %c %s %d %u %x %X %p, flags 0/-,
 * width, length modifiers l/ll/z. Output goes to the platform UART. */
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "log.h"
#include "uart.h"

static int is_digit(char c) { return c >= '0' && c <= '9'; }

static int emit_str(const char *s, int width, int left, char pad)
{
    int len = (int)strlen(s), n = 0;
    if (!left) { for (; len < width; width--) { qv_uart_putc(pad); n++; } }
    for (const char *p = s; *p; p++) { qv_uart_putc(*p); n++; }
    if (left) { for (; len < width; width--) { qv_uart_putc(' '); n++; } }
    return n;
}

static void utoa_base(uint64_t v, unsigned base, int upper, char *out)
{
    char tmp[24];
    int i = 0, j = 0;
    const char *dg = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    do { tmp[i++] = dg[v % base]; v /= base; } while (v);
    while (i) { out[j++] = tmp[--i]; }
    out[j] = 0;
}

int qv_vprintf(const char *fmt, va_list ap)
{
    int n = 0;
    for (; *fmt; fmt++) {
        int left = 0, width = 0, lng = 0;
        char pad = ' ', buf[32];
        if (*fmt != '%') { qv_uart_putc(*fmt); n++; continue; }
        fmt++;
        for (;; fmt++) {
            if (*fmt == '-') { left = 1; }
            else if (*fmt == '0') { pad = '0'; }
            else { break; }
        }
        while (is_digit(*fmt)) { width = width * 10 + (*fmt - '0'); fmt++; }
        while (*fmt == 'l' || *fmt == 'z') { lng++; fmt++; }
        switch (*fmt) {
        case 'c': qv_uart_putc((char)va_arg(ap, int)); n++; break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            n += emit_str(s ? s : "(null)", width, left, ' ');
            break; }
        case 'd': {
            int64_t v = lng ? va_arg(ap, int64_t) : va_arg(ap, int);
            char *p = buf;
            uint64_t u = (uint64_t)v;
            if (v < 0) { *p++ = '-'; u = (uint64_t)0 - u; }
            utoa_base(u, 10, 0, p);
            n += emit_str(buf, width, left, pad);
            break; }
        case 'u': case 'x': case 'X': {
            uint64_t v = lng ? va_arg(ap, uint64_t) : va_arg(ap, unsigned);
            utoa_base(v, *fmt == 'u' ? 10U : 16U, *fmt == 'X', buf);
            n += emit_str(buf, width, left, pad);
            break; }
        case 'p': {
            uint64_t v = (uint64_t)(uintptr_t)va_arg(ap, void *);
            qv_uart_putc('0'); qv_uart_putc('x'); n += 2;
            utoa_base(v, 16, 0, buf);
            n += emit_str(buf, 0, 0, '0');
            break; }
        case '%': qv_uart_putc('%'); n++; break;
        default: qv_uart_putc('?'); n++; break;
        }
    }
    return n;
}

int qv_printf(const char *fmt, ...)
{
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = qv_vprintf(fmt, ap);
    va_end(ap);
    return n;
}

#define REPORT_COL 37

void qv_banner(const char *title)
{
    int len = (int)strlen(title), lead = (36 - len) / 2;
    qv_printf("====================================\n");
    for (int i = 0; i < lead; i++) { qv_uart_putc(' '); }
    qv_printf("%s\n", title);
    qv_printf("====================================\n");
}

static void label(const char *tag, const char *text)
{
    int n = qv_printf("[%s] %s", tag, text);
    while (n++ < REPORT_COL) { qv_uart_putc(' '); }
}

void qv_report(const char *tag, const char *text, const char *status)
{
    label(tag, text);
    qv_printf("%s\n", status);
}

void qv_report_u32(const char *tag, const char *text, uint32_t v)
{
    label(tag, text);
    qv_printf("%u\n", v);
}

void qv_report_hex(const char *tag, const char *text, const uint8_t *d, unsigned n)
{
    label(tag, text);
    for (unsigned i = 0; i < n; i++) { qv_printf("%02x", d[i]); }
    qv_printf("\n");
}
