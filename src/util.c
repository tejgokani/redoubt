/* SPDX-License-Identifier: MIT */
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

void *rd_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "redoubt: out of memory\n");
        exit(2);
    }
    return p;
}

void *rd_xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fprintf(stderr, "redoubt: out of memory\n");
        exit(2);
    }
    return q;
}

char *rd_xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = rd_xmalloc(n);
    memcpy(p, s, n);
    return p;
}

char *rd_xvasprintf(const char *fmt, va_list ap) {
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    if (n < 0) n = 0;
    char *p = rd_xmalloc((size_t)n + 1);
    vsnprintf(p, (size_t)n + 1, fmt, ap);
    return p;
}

char *rd_xasprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *p = rd_xvasprintf(fmt, ap);
    va_end(ap);
    return p;
}

int rd_read_file(const char *path, char **out, size_t *len, size_t max) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t cap = 4096, n = 0;
    char *b = rd_xmalloc(cap + 1);
    for (;;) {
        if (n == cap) {
            if (max && cap >= max) break;
            cap *= 2;
            b = rd_xrealloc(b, cap + 1);
        }
        size_t r = fread(b + n, 1, cap - n, f);
        if (r == 0) break;
        n += r;
    }
    fclose(f);
    b[n] = '\0';
    *out = b;
    if (len) *len = n;
    return 0;
}

int rd_foreach_line(const char *path, int (*cb)(char *line, void *u), void *u) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t r;
    while ((r = getline(&line, &cap, f)) >= 0) {
        while (r > 0 && (line[r - 1] == '\n' || line[r - 1] == '\r')) line[--r] = '\0';
        if (cb(line, u)) break;
    }
    free(line);
    fclose(f);
    return 0;
}

char *rd_trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    return s;
}

int rd_parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno || end == s || *end != '\0') return -1;
    *out = (uint64_t)v;
    return 0;
}

int rd_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

void rd_norm_modname(char *s) {
    for (; *s; s++)
        if (*s == '-') *s = '_';
}

int rd_csv_has(const char *csv, const char *needle) {
    if (!csv || !*csv) return 0;
    size_t nl = strlen(needle);
    const char *p = csv;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == nl && strncmp(p, needle, nl) == 0) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

void rd_sb_addf(rd_sb *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s = rd_xvasprintf(fmt, ap);
    va_end(ap);
    size_t l = strlen(s);
    if (sb->len + l + 1 > sb->cap) {
        sb->cap = (sb->len + l + 1) * 2;
        sb->buf = rd_xrealloc(sb->buf, sb->cap);
    }
    memcpy(sb->buf + sb->len, s, l + 1);
    sb->len += l;
    free(s);
}

char *rd_sb_take(rd_sb *sb) {
    char *r = sb->buf ? sb->buf : rd_xstrdup("");
    sb->buf = NULL;
    sb->len = sb->cap = 0;
    return r;
}

void rd_sb_free(rd_sb *sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->len = sb->cap = 0;
}
