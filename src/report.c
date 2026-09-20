/* SPDX-License-Identifier: MIT */
#include "util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* --------------------------------------------------------------- helpers */

static const char *K(const rd_ctx *c, const char *code) { return c->opt.color ? code : ""; }
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define DIM "\033[2m"
#define RED "\033[1;31m"
#define YEL "\033[1;33m"
#define GRN "\033[1;32m"
#define CYN "\033[36m"
#define MAG "\033[1;35m"

static const char *sev_col(rd_sev s) {
    switch (s) {
    case RD_CRITICAL:
    case RD_HIGH: return RED;
    case RD_MEDIUM: return YEL;
    case RD_LOW: return CYN;
    default: return DIM;
    }
}

static const rd_item *lin_find(const rd_view *v, const char *key) {
    for (size_t i = 0; i < v->n; i++)
        if (strcmp(v->items[i].key, key) == 0) return &v->items[i];
    return NULL;
}

static const char *sysinfo_str(const rd_ctx *c, const char *key, const char *dflt) {
    if (c->vstat[RDV_SYSINFO] != RD_OK) return dflt;
    const rd_item *it = lin_find(&c->views[RDV_SYSINFO], key);
    return (it && it->extra[0]) ? it->extra : dflt;
}

static uint64_t sysinfo_num(const rd_ctx *c, const char *key, uint64_t dflt) {
    if (c->vstat[RDV_SYSINFO] != RD_OK) return dflt;
    const rd_item *it = lin_find(&c->views[RDV_SYSINFO], key);
    return it ? it->a : dflt;
}

static int cmp_find(const void *x, const void *y) {
    const rd_finding *a = *(const rd_finding *const *)x, *b = *(const rd_finding *const *)y;
    if (a->sev != b->sev) return (int)b->sev - (int)a->sev;
    return b->conf - a->conf;
}

static const rd_finding **sorted_findings(const rd_ctx *c, rd_kind kind, size_t *n) {
    const rd_finding **arr = rd_xmalloc((c->nfinds + 1) * sizeof *arr);
    size_t k = 0;
    for (size_t i = 0; i < c->nfinds; i++)
        if (c->finds[i].kind == kind) arr[k++] = &c->finds[i];
    if (k > 1) qsort(arr, k, sizeof *arr, cmp_find);
    *n = k;
    return arr;
}

static void print_indented(FILE *f, const char *text, const char *indent) {
    const char *p = text;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        fprintf(f, "%s%.*s\n", indent, (int)l, p);
        if (!e) break;
        p = e + 1;
    }
}

/* ------------------------------------------------------------------ text */

void rd_report_text(const rd_ctx *c, const char *source, FILE *f) {
    char when[32];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", &tmv);

    fprintf(f, "\n%s%s REDOUBT %s%s  kernel-module rootkit detector\n", K(c, BOLD), K(c, MAG), RD_VERSION,
            K(c, RESET));
    fprintf(f, "%s  source : %s%s\n", K(c, DIM), source, K(c, RESET));
    fprintf(f, "%s  target : %s %s (%s), euid %llu%s\n", K(c, DIM), sysinfo_str(c, "os", "?"),
            sysinfo_str(c, "kernel", "?"), sysinfo_str(c, "arch", "?"),
            (unsigned long long)sysinfo_num(c, "euid", 0), K(c, RESET));
    fprintf(f, "%s  time   : %s%s\n\n", K(c, DIM), when, K(c, RESET));

    fprintf(f, "%sCHECKS%s\n", K(c, BOLD), K(c, RESET));
    for (size_t i = 0; i < c->nresults; i++) {
        const rd_check_result *r = &c->results[i];
        if (r->state == RD_NA && !c->opt.verbose) continue;
        const char *tag, *tc;
        char note[300];
        if (r->state == RD_RAN && r->nfind == 0) {
            tag = " ok ";
            tc = GRN;
            snprintf(note, sizeof note, "clean");
        } else if (r->state == RD_RAN) {
            int det = rd_max_detection_sev(c, r->chk->id);
            tag = det >= RD_MEDIUM ? "!!!!" : "note";
            tc = det >= RD_MEDIUM ? RED : CYN;
            snprintf(note, sizeof note, "%d finding%s", r->nfind, r->nfind == 1 ? "" : "s");
        } else if (r->state == RD_SKIPPED) {
            tag = " -- ";
            tc = YEL;
            snprintf(note, sizeof note, "skipped: %s", r->reason ? r->reason : "");
        } else {
            tag = " na ";
            tc = DIM;
            snprintf(note, sizeof note, "%s", r->reason ? r->reason : "");
        }
        fprintf(f, "  %s[%s]%s %-16s %-44s %s\n", K(c, tc), tag, K(c, RESET), r->chk->id, r->chk->title, note);
    }

    size_t nd = 0;
    const rd_finding **det = sorted_findings(c, RD_KIND_DETECTION, &nd);
    fprintf(f, "\n%sFINDINGS%s  (%zu)\n", K(c, BOLD), K(c, RESET), nd);
    if (nd == 0) fprintf(f, "  %sNo rootkit indicators found by the checks that ran.%s\n", K(c, GRN), K(c, RESET));
    for (size_t i = 0; i < nd; i++) {
        const rd_finding *x = det[i];
        fprintf(f, "\n  %s%zu. [%-8s %3d%%]%s %s%s%s\n", K(c, sev_col(x->sev)), i + 1, rd_sev_name(x->sev), x->conf,
                K(c, RESET), K(c, BOLD), x->title, K(c, RESET));
        fprintf(f, "     %scheck:%s %s%s%s\n", K(c, DIM), K(c, RESET), x->check,
                x->mitre ? "   ATT&CK: " : "", x->mitre ? x->mitre : "");
        print_indented(f, x->detail, "     ");
        if (x->fix) fprintf(f, "     %sresponse:%s %s\n", K(c, DIM), K(c, RESET), x->fix);
    }
    free(det);

    size_t np = 0;
    const rd_finding **pos = sorted_findings(c, RD_KIND_POSTURE, &np);
    if (np) {
        fprintf(f, "\n%sHARDENING ADVICE%s  (posture only - does not affect the verdict)\n", K(c, BOLD), K(c, RESET));
        for (size_t i = 0; i < np; i++) {
            fprintf(f, "  %s-%s %s\n", K(c, CYN), K(c, RESET), pos[i]->title);
            if (c->opt.verbose) print_indented(f, pos[i]->detail, "      ");
        }
    }
    free(pos);

    rd_verdict v = rd_verdict_compute(c);
    const char *vc = v.id == RD_VERDICT_CLEAN ? GRN : (v.id == RD_VERDICT_SUSPICIOUS ? YEL : RED);
    fprintf(f, "\n%s================================================================%s\n", K(c, DIM), K(c, RESET));
    fprintf(f, " VERDICT  %s%s%s   risk score %d/100   coverage %d/%d checks   %d independent check%s flagging\n",
            K(c, vc), rd_verdict_name(v.id), K(c, RESET), v.score, v.ran, v.applicable, v.checks_flagging,
            v.checks_flagging == 1 ? "" : "s");
    if (v.skipped)
        fprintf(f, " %s%d check%s could not run (see above) - a CLEAN verdict only covers what ran.%s\n", K(c, YEL),
                v.skipped, v.skipped == 1 ? "" : "s", K(c, RESET));
    if (v.id == RD_VERDICT_CLEAN)
        fprintf(f, " %sAbsence of evidence from user space is not proof: see docs/THREAT_MODEL.md.%s\n", K(c, DIM),
                K(c, RESET));
    fprintf(f, "%s================================================================%s\n\n", K(c, DIM), K(c, RESET));
}

/* ------------------------------------------------------------------ JSON */

static void jstr(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        switch (ch) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (ch < 0x20) fprintf(f, "\\u%04x", ch);
            else fputc(ch, f);
        }
    }
    fputc('"', f);
}

void rd_report_json(const rd_ctx *c, const char *source, FILE *f) {
    rd_verdict v = rd_verdict_compute(c);
    fprintf(f, "{\n  \"tool\": \"redoubt\",\n  \"version\": \"%s\",\n  \"source\": ", RD_VERSION);
    jstr(f, source);
    fprintf(f, ",\n  \"host\": {\"os\": ");
    jstr(f, sysinfo_str(c, "os", "unknown"));
    fprintf(f, ", \"kernel\": ");
    jstr(f, sysinfo_str(c, "kernel", "unknown"));
    fprintf(f, ", \"arch\": ");
    jstr(f, sysinfo_str(c, "arch", "unknown"));
    fprintf(f, ", \"euid\": %llu},\n", (unsigned long long)sysinfo_num(c, "euid", 0));
    fprintf(f, "  \"verdict\": \"%s\",\n  \"score\": %d,\n", rd_verdict_name(v.id), v.score);
    fprintf(f, "  \"coverage\": {\"ran\": %d, \"skipped\": %d, \"applicable\": %d},\n", v.ran, v.skipped, v.applicable);
    fprintf(f, "  \"checks\": [\n");
    for (size_t i = 0; i < c->nresults; i++) {
        const rd_check_result *r = &c->results[i];
        const char *st = r->state == RD_RAN ? "ran" : (r->state == RD_SKIPPED ? "skipped" : "n/a");
        fprintf(f, "    {\"id\": ");
        jstr(f, r->chk->id);
        fprintf(f, ", \"status\": \"%s\", \"findings\": %d, \"reason\": ", st, r->nfind);
        jstr(f, r->reason ? r->reason : "");
        fprintf(f, "}%s\n", i + 1 < c->nresults ? "," : "");
    }
    fprintf(f, "  ],\n  \"findings\": [\n");
    for (size_t i = 0; i < c->nfinds; i++) {
        const rd_finding *x = &c->finds[i];
        fprintf(f, "    {\"check\": ");
        jstr(f, x->check);
        fprintf(f, ", \"severity\": \"%s\", \"confidence\": %d, \"kind\": \"%s\", \"title\": ", rd_sev_name(x->sev),
                x->conf, x->kind == RD_KIND_DETECTION ? "detection" : "posture");
        jstr(f, x->title);
        fprintf(f, ", \"detail\": ");
        jstr(f, x->detail);
        fprintf(f, ", \"attack\": ");
        jstr(f, x->mitre ? x->mitre : "");
        fprintf(f, ", \"response\": ");
        jstr(f, x->fix ? x->fix : "");
        fprintf(f, "}%s\n", i + 1 < c->nfinds ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
}

/* -------------------------------------------------------------- snapshot */

int rd_snapshot_write(rd_ctx *c, const char *dir, const char *title) {
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "redoubt: cannot create %s: %s\n", dir, strerror(errno));
        return -1;
    }
    char path[1024];
    rd_sb unavailable = {0};
    for (int i = 0; i < RDV_COUNT; i++) {
        rd_view *v = NULL;
        int st = rd_get_view(c, (rd_view_id)i, &v);
        if (st != RD_OK) {
            rd_sb_addf(&unavailable, "%s\t%s\n", rd_view_name((rd_view_id)i), rd_view_why(c, (rd_view_id)i));
            continue;
        }
        snprintf(path, sizeof path, "%s/%s.tsv", dir, rd_view_name((rd_view_id)i));
        FILE *f = fopen(path, "w");
        if (!f) {
            fprintf(stderr, "redoubt: cannot write %s: %s\n", path, strerror(errno));
            rd_sb_free(&unavailable);
            return -1;
        }
        rd_view_write_tsv(v, f);
        fclose(f);
    }
    snprintf(path, sizeof path, "%s/unavailable.tsv", dir);
    FILE *f = fopen(path, "w");
    if (f) {
        char *u = rd_sb_take(&unavailable);
        fputs(u, f);
        free(u);
        fclose(f);
    }
    snprintf(path, sizeof path, "%s/scenario.txt", dir);
    f = fopen(path, "w");
    if (f) {
        char when[32];
        time_t now = time(NULL);
        struct tm tmv;
        gmtime_r(&now, &tmv);
        strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tmv);
        fprintf(f, "title: %s\ncaptured: %s\ntool: redoubt %s\n", title ? title : "snapshot", when, RD_VERSION);
        fclose(f);
    }
    return 0;
}
