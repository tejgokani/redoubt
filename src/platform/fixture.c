/* SPDX-License-Identifier: MIT
 *
 * Snapshot provider: replays views from a directory of <view>.tsv files.
 *
 *   scenario.txt     title:/story:/expect:/base: metadata
 *   unavailable.tsv  "<view>\t<reason>" - views the capturing tool could not read
 *   <view>.tsv       the view itself (see rd_view_write_tsv)
 *   <view>.recheck.tsv  what a *second* read of the view returns (race modelling)
 *   <view>.probe.tsv    what a targeted re-probe of a key sees (race modelling)
 *
 * `base: ../other` makes a scenario an *overlay*: only files that differ from
 * the base need to exist.  For rootkit scenarios that is exactly the point -
 * the overlay is the list of things the rootkit changed.
 */
#include "../util.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_DEPTH 6

typedef struct {
    char *dir;
    int calls[RDV_COUNT];
} fx_t;

static int is_file(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static char *fx_base(const char *dir) {
    char path[1024];
    snprintf(path, sizeof path, "%s/scenario.txt", dir);
    char *buf = NULL;
    if (rd_read_file(path, &buf, NULL, 1 << 16) != 0) return NULL;
    char *res = NULL, *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (strncmp(ln, "base:", 5) == 0) {
            res = rd_xasprintf("%s/%s", dir, rd_trim(ln + 5));
            break;
        }
    }
    free(buf);
    return res;
}

/* nearest-first walk of the base chain; 1 = file path in out, 2 = unavailable (reason in out), 0 = nothing */
static int fx_lookup(const char *dir, const char *view, const char *suffix, char *out, size_t outsz) {
    char *cur = rd_xstrdup(dir);
    for (int depth = 0; depth < MAX_DEPTH && cur; depth++) {
        char p[1024];
        if (!suffix[0]) {
            snprintf(p, sizeof p, "%s/unavailable.tsv", cur);
            char *ub = NULL;
            if (rd_read_file(p, &ub, NULL, 1 << 16) == 0) {
                char *save = NULL;
                for (char *ln = strtok_r(ub, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
                    char *tab = strchr(ln, '\t');
                    if (!tab) continue;
                    *tab = '\0';
                    if (strcmp(ln, view) == 0) {
                        snprintf(out, outsz, "%s", tab + 1);
                        free(ub);
                        free(cur);
                        return 2;
                    }
                }
                free(ub);
            }
        }
        snprintf(p, sizeof p, "%s/%s%s.tsv", cur, view, suffix);
        if (is_file(p)) {
            snprintf(out, outsz, "%s", p);
            free(cur);
            return 1;
        }
        char *nb = fx_base(cur);
        free(cur);
        cur = nb;
    }
    free(cur);
    return 0;
}

static int is_module_view(rd_view_id id) {
    return id == RDV_MOD_API || id == RDV_MOD_SYSFS || id == RDV_MOD_KALLSYMS || id == RDV_MOD_DISK ||
           id == RDV_DMESG_MODS;
}

static int fx_collect(rd_provider *p, rd_view_id id, rd_view *out, char *why, size_t whysz) {
    fx_t *fx = p->priv;
    char path[1024];
    const char *name = rd_view_name(id);
    int found = 0;
    if (fx->calls[id]++ > 0) found = fx_lookup(fx->dir, name, ".recheck", path, sizeof path) == 1;
    if (!found) {
        int r = fx_lookup(fx->dir, name, "", path, sizeof path);
        if (r == 2) {
            snprintf(why, whysz, "%s", path);
            return RD_UNAVAIL;
        }
        if (r == 0) {
            snprintf(why, whysz, "not captured in this snapshot");
            return RD_UNAVAIL;
        }
    }
    if (rd_view_read_tsv(out, path) != 0) {
        snprintf(why, whysz, "cannot read %s", path);
        return RD_ERR;
    }
    if (is_module_view(id))
        for (size_t i = 0; i < out->n; i++) rd_norm_modname(out->items[i].key);
    return RD_OK;
}

static int fx_probe(rd_provider *p, rd_view_id id, const char *key) {
    fx_t *fx = p->priv;
    char path[1024];
    if (fx_lookup(fx->dir, rd_view_name(id), ".probe", path, sizeof path) != 1 &&
        fx_lookup(fx->dir, rd_view_name(id), "", path, sizeof path) != 1)
        return -1;
    rd_view v;
    rd_view_init(&v);
    if (rd_view_read_tsv(&v, path) != 0) return -1;
    int exists = rd_view_find(&v, key) != NULL;
    rd_view_free(&v);
    return exists;
}

static void fx_destroy(rd_provider *p) {
    fx_t *fx = p->priv;
    free(fx->dir);
    free(fx);
    free(p);
}

rd_provider *rd_provider_fixture(const char *dir) {
    struct stat st;
    if (!dir || stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) return NULL;
    rd_provider *p = rd_xmalloc(sizeof *p);
    fx_t *fx = rd_xmalloc(sizeof *fx);
    memset(fx, 0, sizeof *fx);
    fx->dir = rd_xstrdup(dir);
    p->name = "snapshot";
    p->priv = fx;
    p->collect = fx_collect;
    p->probe = fx_probe;
    p->destroy = fx_destroy;
    return p;
}
