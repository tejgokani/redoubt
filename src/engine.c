/* SPDX-License-Identifier: MIT */
#include "util.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- severities */

const char *rd_sev_name(rd_sev s) {
    static const char *const n[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    return (s >= RD_INFO && s <= RD_CRITICAL) ? n[s] : "?";
}

int rd_sev_parse(const char *s, rd_sev *out) {
    for (int i = RD_INFO; i <= RD_CRITICAL; i++) {
        const char *n = rd_sev_name((rd_sev)i);
        size_t l = strlen(n);
        size_t j = 0;
        while (j < l && s[j] && (s[j] | 0x20) == (n[j] | 0x20)) j++;
        if (j == l && !s[j]) {
            *out = (rd_sev)i;
            return 0;
        }
    }
    return -1;
}

const char *rd_verdict_name(rd_verdict_id v) {
    switch (v) {
    case RD_VERDICT_CLEAN: return "CLEAN";
    case RD_VERDICT_SUSPICIOUS: return "SUSPICIOUS";
    default: return "COMPROMISED";
    }
}

/* ---------------------------------------------------------------- context */

void rd_ctx_init(rd_ctx *c, rd_provider *p, const rd_options *opt) {
    memset(c, 0, sizeof *c);
    c->opt = *opt;
    c->prov = p;
    for (int i = 0; i < RDV_COUNT; i++) c->vstat[i] = -1;
#if defined(__APPLE__)
    c->plat = RD_PLAT_MACOS;
#else
    c->plat = RD_PLAT_LINUX;
#endif
}

void rd_ctx_free(rd_ctx *c) {
    for (int i = 0; i < RDV_COUNT; i++) {
        rd_view_free(&c->views[i]);
        free(c->vwhy[i]);
    }
    for (size_t i = 0; i < c->nfinds; i++) {
        free(c->finds[i].title);
        free(c->finds[i].detail);
    }
    free(c->finds);
    for (size_t i = 0; i < c->nresults; i++) free(c->results[i].reason);
    free(c->results);
    free(c->skip_reason);
    if (c->prov && c->prov->destroy) c->prov->destroy(c->prov);
    memset(c, 0, sizeof *c);
}

int rd_get_view(rd_ctx *c, rd_view_id id, rd_view **out) {
    if (c->vstat[id] < 0) {
        char why[200] = "";
        rd_view_init(&c->views[id]);
        int st = c->prov->collect(c->prov, id, &c->views[id], why, sizeof why);
        if (st != RD_OK) rd_view_free(&c->views[id]);
        c->vstat[id] = st;
        c->vwhy[id] = rd_xstrdup(why[0] ? why : (st == RD_OK ? "" : "not available"));
    }
    if (c->vstat[id] == RD_OK && out) *out = &c->views[id];
    return c->vstat[id];
}

const char *rd_view_why(const rd_ctx *c, rd_view_id id) {
    return (c->vwhy[id] && *c->vwhy[id]) ? c->vwhy[id] : "not available";
}

int rd_recollect(rd_ctx *c, rd_view_id id, rd_view *fresh) {
    char why[200] = "";
    rd_view_init(fresh);
    int st = c->prov->collect(c->prov, id, fresh, why, sizeof why);
    if (st != RD_OK) rd_view_free(fresh);
    return st;
}

int rd_probe(rd_ctx *c, rd_view_id id, const char *key) {
    if (!c->prov->probe) return -1;
    return c->prov->probe(c->prov, id, key);
}

/* --------------------------------------------------------------- findings */

rd_finding *rd_add(rd_ctx *c, rd_sev sev, int conf, const char *title, const char *fmt, ...) {
    if (c->nfinds == c->capfinds) {
        c->capfinds = c->capfinds ? c->capfinds * 2 : 16;
        c->finds = rd_xrealloc(c->finds, c->capfinds * sizeof *c->finds);
    }
    rd_finding *f = &c->finds[c->nfinds++];
    memset(f, 0, sizeof *f);
    f->check = c->cur ? c->cur->id : "?";
    f->sev = sev;
    f->conf = conf < 0 ? 0 : (conf > 100 ? 100 : conf);
    f->kind = RD_KIND_DETECTION;
    f->title = rd_xstrdup(title);
    va_list ap;
    va_start(ap, fmt);
    f->detail = rd_xvasprintf(fmt, ap);
    va_end(ap);
    return f;
}

int rd_skip(rd_ctx *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    free(c->skip_reason);
    c->skip_reason = rd_xvasprintf(fmt, ap);
    va_end(ap);
    return RD_SKIPPED;
}

int rd_na(rd_ctx *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    free(c->skip_reason);
    c->skip_reason = rd_xvasprintf(fmt, ap);
    va_end(ap);
    return RD_NA;
}

/* ------------------------------------------------------------ scan driver */

static const rd_item *lin_find(const rd_view *v, const char *key) {
    for (size_t i = 0; i < v->n; i++)
        if (strcmp(v->items[i].key, key) == 0) return &v->items[i];
    return NULL;
}

void rd_scan(rd_ctx *c) {
    rd_view *si = NULL;
    if (rd_get_view(c, RDV_SYSINFO, &si) == RD_OK) {
        const rd_item *os = lin_find(si, "os");
        if (os && strcmp(os->extra, "Darwin") == 0) c->plat = RD_PLAT_MACOS;
        else if (os && strcmp(os->extra, "Linux") == 0) c->plat = RD_PLAT_LINUX;
    }

    size_t n = 0;
    const rd_check *const *all = rd_all_checks(&n);
    c->results = rd_xmalloc(n * sizeof *c->results);
    c->nresults = 0;
    for (size_t i = 0; i < n; i++) {
        const rd_check *chk = all[i];
        rd_check_result *r = &c->results[c->nresults++];
        memset(r, 0, sizeof *r);
        r->chk = chk;
        if (!(chk->platforms & (unsigned)c->plat)) {
            r->state = RD_NA;
            r->reason = rd_xstrdup("not applicable to this platform");
            continue;
        }
        if ((c->opt.only && *c->opt.only && !rd_csv_has(c->opt.only, chk->id)) ||
            rd_csv_has(c->opt.skip, chk->id)) {
            r->state = RD_NA;
            r->reason = rd_xstrdup("excluded by --only/--skip");
            continue;
        }
        size_t before = c->nfinds;
        c->cur = chk;
        free(c->skip_reason);
        c->skip_reason = NULL;
        int rc = chk->run(c);
        c->cur = NULL;
        r->state = rc == 0 ? RD_RAN : (rc == RD_NA ? RD_NA : RD_SKIPPED);
        if (rc) r->reason = rd_xstrdup(c->skip_reason ? c->skip_reason : "skipped");
        r->nfind = (int)(c->nfinds - before);
    }
}

/* ---------------------------------------------------------------- verdict */

int rd_max_detection_sev(const rd_ctx *c, const char *check_id) {
    int m = -1;
    for (size_t i = 0; i < c->nfinds; i++) {
        const rd_finding *f = &c->finds[i];
        if (f->kind == RD_KIND_DETECTION && strcmp(f->check, check_id) == 0 && (int)f->sev > m)
            m = (int)f->sev;
    }
    return m;
}

rd_verdict rd_verdict_compute(const rd_ctx *c) {
    rd_verdict v;
    memset(&v, 0, sizeof v);
    static const double W[] = {0, 3, 10, 25, 40};
    double score = 0;
    int med_checks = 0, low_checks = 0;

    for (size_t i = 0; i < c->nresults; i++) {
        const rd_check_result *r = &c->results[i];
        if (r->state == RD_RAN) v.ran++;
        else if (r->state == RD_SKIPPED) v.skipped++;
        if (r->state == RD_NA) continue;
        int m = rd_max_detection_sev(c, r->chk->id);
        if (m >= RD_MEDIUM) med_checks++;
        else if (m == RD_LOW) low_checks++;
    }
    v.applicable = v.ran + v.skipped;
    v.checks_flagging = med_checks;

    for (size_t i = 0; i < c->nfinds; i++) {
        const rd_finding *f = &c->finds[i];
        if (f->kind != RD_KIND_DETECTION) continue;
        score += W[f->sev] * f->conf / 100.0;
        if (f->sev >= RD_HIGH && f->conf >= 75) v.strong++;
    }
    v.score = score > 100 ? 100 : (int)(score + 0.5);

    if (v.strong > 0 || med_checks >= 2) v.id = RD_VERDICT_COMPROMISED;
    else if (med_checks == 1 || low_checks >= 2) v.id = RD_VERDICT_SUSPICIOUS;
    else v.id = RD_VERDICT_CLEAN;
    return v;
}
