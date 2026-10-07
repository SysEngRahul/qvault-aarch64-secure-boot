#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "qvtool.h"

void qt_die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

uint8_t *qt_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    uint8_t *b;
    if (!f) { qt_die("cannot open %s: %s", path, strerror(errno)); }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) { qt_die("seek %s", path); }
    b = malloc((size_t)n ? (size_t)n : 1U);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) { qt_die("read %s", path); }
    fclose(f);
    *len = (size_t)n;
    return b;
}

void qt_write_file(const char *path, const void *d, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { qt_die("cannot create %s: %s", path, strerror(errno)); }
    if (fwrite(d, 1, len, f) != len) { qt_die("write %s", path); }
    if (fclose(f) != 0) { qt_die("close %s", path); }
}

void qt_random(uint8_t *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, n, f) != n) { qt_die("cannot read /dev/urandom"); }
    fclose(f);
}

uint64_t qt_parse_u64(const char *s)
{
    char *end;
    unsigned long long v;
    errno = 0;
    v = strtoull(s, &end, 0);
    if (errno || *end || end == s) { qt_die("bad number '%s'", s); }
    return v;
}

const char *qt_opt(int argc, char **argv, const char *name, const char *def)
{
    int i;
    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) { return argv[i + 1]; }
    }
    return def;
}
