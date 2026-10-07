#ifndef QVTOOL_H
#define QVTOOL_H
#include <stdint.h>
#include <stddef.h>

uint8_t *qt_read_file(const char *path, size_t *len);       /* exits on error */
void     qt_write_file(const char *path, const void *d, size_t len);
void     qt_random(uint8_t *buf, size_t n);                 /* /dev/urandom */
uint64_t qt_parse_u64(const char *s);                       /* dec or 0x hex */
const char *qt_opt(int argc, char **argv, const char *name, const char *def);
void     qt_die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
#endif
