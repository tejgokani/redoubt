/* SPDX-License-Identifier: MIT */
#ifndef RD_UTIL_H
#define RD_UTIL_H

#include "redoubt.h"
#include <stdarg.h>

void *rd_xmalloc(size_t n);
void *rd_xrealloc(void *p, size_t n);
char *rd_xstrdup(const char *s);
char *rd_xvasprintf(const char *fmt, va_list ap);
char *rd_xasprintf(const char *fmt, ...) RD_PRINTF(1, 2);

/* Read a whole (possibly procfs, size-0) file into a NUL-terminated buffer. */
int rd_read_file(const char *path, char **out, size_t *len, size_t max);
/* Stream a file line by line; the callback returns non-zero to stop. */
int rd_foreach_line(const char *path, int (*cb)(char *line, void *u), void *u);

char *rd_trim(char *s);
int rd_parse_u64(const char *s, uint64_t *out); /* base 0; 0 on success */
int rd_starts_with(const char *s, const char *prefix);
void rd_norm_modname(char *s);                  /* '-' -> '_' (kernel treats them alike) */
int rd_csv_has(const char *csv, const char *needle);

/* growable string builder */
typedef struct {
    char *buf;
    size_t len, cap;
} rd_sb;
void rd_sb_addf(rd_sb *sb, const char *fmt, ...) RD_PRINTF(2, 3);
char *rd_sb_take(rd_sb *sb); /* caller frees; never NULL */
void rd_sb_free(rd_sb *sb);

#endif
