#ifndef QV_LOG_H
#define QV_LOG_H
#include <stdint.h>
#include <stdarg.h>

int  qv_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int  qv_vprintf(const char *fmt, va_list ap);
void qv_banner(const char *title);
/* "[TAG] label" padded to a fixed column, then the status text. */
void qv_report(const char *tag, const char *text, const char *status);
void qv_report_hex(const char *tag, const char *text, const uint8_t *d, unsigned n);
void qv_report_u32(const char *tag, const char *text, uint32_t v);
#endif
