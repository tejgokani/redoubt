/* SPDX-License-Identifier: MIT */
#include "util.h"

#include <stdlib.h>
#include <string.h>

static const char *const VIEW_NAMES[RDV_COUNT] = {
    "sysinfo",     "mod.api",    "mod.sysfs",  "mod.kallsyms", "mod.disk",  "mod.mem",
    "dmesg.mods",  "ksyms",      "syscalls",   "ftrace",       "prologues", "proc.api",
    "proc.raw",    "proc.brute", "net.listed", "net.bound",    "dirs",      "probes",
    "preload",     "hardening",  "kext.loaded", "kext.alt",    "kext.disk", "bootargs",
};

const char *rd_view_name(rd_view_id id) {
    return (id >= 0 && id < RDV_COUNT) ? VIEW_NAMES[id] : "?";
}

int rd_view_id_from_name(const char *name) {
    for (int i = 0; i < RDV_COUNT; i++)
        if (strcmp(VIEW_NAMES[i], name) == 0) return i;
    return -1;
}

void rd_view_init(rd_view *v) { memset(v, 0, sizeof *v); }

void rd_view_free(rd_view *v) {
    for (size_t i = 0; i < v->n; i++) {
        free(v->items[i].key);
        free(v->items[i].extra);
    }
    free(v->items);
    rd_view_init(v);
}

rd_item *rd_view_add(rd_view *v, const char *key, uint64_t a, uint64_t b, const char *extra) {
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 16;
        v->items = rd_xrealloc(v->items, v->cap * sizeof *v->items);
    }
    rd_item *it = &v->items[v->n++];
    it->key = rd_xstrdup(key);
    it->a = a;
    it->b = b;
    it->extra = rd_xstrdup(extra ? extra : "");
    v->sorted = 0;
    return it;
}

rd_item *rd_view_addf(rd_view *v, uint64_t a, uint64_t b, const char *extra, const char *keyfmt, ...) {
    va_list ap;
    va_start(ap, keyfmt);
    char *k = rd_xvasprintf(keyfmt, ap);
    va_end(ap);
    rd_item *it = rd_view_add(v, k, a, b, extra);
    free(k);
    return it;
}

static int cmp_item(const void *x, const void *y) {
    return strcmp(((const rd_item *)x)->key, ((const rd_item *)y)->key);
}

void rd_view_sort(rd_view *v) {
    if (v->sorted) return;
    if (v->n > 1) qsort(v->items, v->n, sizeof *v->items, cmp_item);
    v->sorted = 1;
}

void rd_view_dedup(rd_view *v) {
    rd_view_sort(v);
    size_t w = 0;
    for (size_t i = 0; i < v->n; i++) {
        if (w > 0 && strcmp(v->items[w - 1].key, v->items[i].key) == 0) {
            free(v->items[i].key);
            free(v->items[i].extra);
            continue;
        }
        v->items[w++] = v->items[i];
    }
    v->n = w;
}

const rd_item *rd_view_find(rd_view *v, const char *key) {
    if (!v->n) return NULL;
    rd_view_sort(v);
    rd_item k = {(char *)key, 0, 0, NULL};
    return bsearch(&k, v->items, v->n, sizeof *v->items, cmp_item);
}

void rd_view_remove(rd_view *v, const char *key) {
    size_t w = 0;
    for (size_t i = 0; i < v->n; i++) {
        if (strcmp(v->items[i].key, key) == 0) {
            free(v->items[i].key);
            free(v->items[i].extra);
            continue;
        }
        v->items[w++] = v->items[i];
    }
    v->n = w;
}

/* ------------------------------------------------------------------ TSV */

static void put_clean(FILE *f, const char *s) {
    for (; *s; s++) fputc((*s == '\t' || *s == '\n' || *s == '\r') ? ' ' : *s, f);
}

int rd_view_write_tsv(const rd_view *v, FILE *f) {
    fprintf(f, "# key\ta\tb\textra\n");
    for (size_t i = 0; i < v->n; i++) {
        const rd_item *it = &v->items[i];
        put_clean(f, it->key);
        fprintf(f, "\t0x%llx\t0x%llx\t", (unsigned long long)it->a, (unsigned long long)it->b);
        put_clean(f, it->extra);
        fputc('\n', f);
    }
    return ferror(f) ? -1 : 0;
}

struct tsv_ctx {
    rd_view *v;
};

static int tsv_line(char *line, void *u) {
    struct tsv_ctx *t = u;
    if (!*line || line[0] == '#') return 0;
    char *f[4] = {line, NULL, NULL, NULL};
    int nf = 1;
    for (char *p = line; *p && nf < 4; p++) {
        if (*p == '\t') {
            *p = '\0';
            f[nf++] = p + 1;
        }
    }
    uint64_t a = 0, b = 0;
    if (f[1] && *f[1]) rd_parse_u64(rd_trim(f[1]), &a);
    if (f[2] && *f[2]) rd_parse_u64(rd_trim(f[2]), &b);
    rd_view_add(t->v, f[0], a, b, f[3] ? f[3] : "");
    return 0;
}

int rd_view_read_tsv(rd_view *v, const char *path) {
    struct tsv_ctx t = {v};
    return rd_foreach_line(path, tsv_line, &t);
}
