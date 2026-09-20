/* SPDX-License-Identifier: MIT
 *
 * Fault-injection provider.  Wraps any other provider and edits its views the
 * way a rootkit would - dropping a pid from a listing, unlinking a module - so
 * that the detection logic can be demonstrated on REAL live data without a
 * real rootkit.  Every use is announced in the report source line; this is a
 * test tool, not a rootkit.
 *
 *   hide-pid:N          kernel-level: N vanishes from the API and raw listings
 *   hide-pid-api:N      user-space:   N vanishes from the API listing only
 *   hide-pid-deep:N     N vanishes from every view (models an undetectable rootkit)
 *   hide-module:NAME    NAME vanishes from /proc/modules and kallsyms (sysfs still knows)
 *   hide-module-deep:NAME  NAME vanishes from every module view
 *   add-kext:BUNDLE_ID  (macOS) inject a loaded third-party kernel extension
 */
#include "../util.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    rd_provider *inner;
    char *spec;
} sim_t;

static int has_rule(const char *spec, const char *kind, char *arg, size_t argsz, const char **cursor) {
    size_t kl = strlen(kind);
    const char *p = *cursor ? *cursor : spec;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l > kl + 1 && strncmp(p, kind, kl) == 0 && p[kl] == ':') {
            size_t al = l - kl - 1;
            if (al >= argsz) al = argsz - 1;
            memcpy(arg, p + kl + 1, al);
            arg[al] = '\0';
            *cursor = e ? e + 1 : p + l;
            return 1;
        }
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

static void drop_all(const char *spec, const char *kind, rd_view *v) {
    char arg[128];
    const char *cur = NULL;
    while (has_rule(spec, kind, arg, sizeof arg, &cur)) {
        rd_norm_modname(arg);
        rd_view_remove(v, arg);
    }
}

static int sim_collect(rd_provider *p, rd_view_id id, rd_view *out, char *why, size_t whysz) {
    sim_t *s = p->priv;
    int st = s->inner->collect(s->inner, id, out, why, whysz);
    if (st != RD_OK) return st;
    switch (id) {
    case RDV_PROC_API:
        drop_all(s->spec, "hide-pid", out);
        drop_all(s->spec, "hide-pid-api", out);
        drop_all(s->spec, "hide-pid-deep", out);
        break;
    case RDV_PROC_RAW:
        drop_all(s->spec, "hide-pid", out);
        drop_all(s->spec, "hide-pid-deep", out);
        break;
    case RDV_PROC_BRUTE: drop_all(s->spec, "hide-pid-deep", out); break;
    case RDV_MOD_API:
    case RDV_MOD_KALLSYMS: drop_all(s->spec, "hide-module", out); /* fall through */
    case RDV_MOD_SYSFS:
    case RDV_DMESG_MODS:
    case RDV_MOD_DISK: drop_all(s->spec, "hide-module-deep", out); break;
    case RDV_KEXT_LOADED: {
        char arg[128];
        const char *cur = NULL;
        while (has_rule(s->spec, "add-kext", arg, sizeof arg, &cur)) rd_view_add(out, arg, 0, 0, "1.0 (injected)");
        break;
    }
    default: break;
    }
    return RD_OK;
}

static int sim_probe(rd_provider *p, rd_view_id id, const char *key) {
    sim_t *s = p->priv;
    if (!s->inner->probe) return -1;
    return s->inner->probe(s->inner, id, key);
}

static void sim_destroy(rd_provider *p) {
    sim_t *s = p->priv;
    if (s->inner->destroy) s->inner->destroy(s->inner);
    free(s->spec);
    free(s);
    free(p);
}

rd_provider *rd_provider_sim(rd_provider *inner, const char *spec) {
    static const char *const KINDS[] = {"hide-pid",    "hide-pid-api",      "hide-pid-deep", "hide-module",
                                        "hide-module-deep", "add-kext",     NULL};
    /* validate every token so a typo fails loudly instead of silently doing nothing */
    char *copy = rd_xstrdup(spec), *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *colon = strchr(tok, ':');
        int ok = 0;
        if (colon && colon[1]) {
            *colon = '\0';
            for (const char *const *k = KINDS; *k; k++)
                if (strcmp(*k, tok) == 0) ok = 1;
        }
        if (!ok) {
            fprintf(stderr, "redoubt: bad --simulate token '%s' (see docs/DEMO.md)\n", tok);
            free(copy);
            return NULL;
        }
    }
    free(copy);

    rd_provider *p = rd_xmalloc(sizeof *p);
    sim_t *s = rd_xmalloc(sizeof *s);
    s->inner = inner;
    s->spec = rd_xstrdup(spec);
    p->name = "simulated";
    p->priv = s;
    p->collect = sim_collect;
    p->probe = sim_probe;
    p->destroy = sim_destroy;
    return p;
}
