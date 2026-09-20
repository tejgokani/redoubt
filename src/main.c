/* SPDX-License-Identifier: MIT */
#include "util.h"

#include <dirent.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

/* ------------------------------------------------------------- usage */

static void usage(FILE *f) {
    fputs("redoubt " RD_VERSION " - kernel-module rootkit detector\n"
          "\n"
          "usage: redoubt [command] [options]\n"
          "\n"
          "commands:\n"
          "  scan              scan this machine (default)\n"
          "  demo [name|all]   replay a bundled rootkit scenario through the real detection engine\n"
          "  eval [dir]        run every scenario, print the detection matrix (exit 1 on any miss)\n"
          "  snapshot DIR      save every kernel view of this machine as an evidence bundle / baseline\n"
          "  list-checks       list the detection checks\n"
          "  version | help\n"
          "\n"
          "options:\n"
          "  --from DIR        analyse a snapshot/scenario directory instead of this machine\n"
          "  --baseline DIR    also compare against a known-good snapshot\n"
          "  --simulate SPEC   inject rootkit-like lies into live data (see docs/DEMO.md)\n"
          "  --only a,b        run only these checks        --skip a,b   skip these checks\n"
          "  --fail-on SEV     exit 1 if a detection >= SEV (info|low|medium|high|critical; default medium)\n"
          "  --json            machine-readable output      --no-color / --color\n"
          "  --fast            limit the pid brute-force range (Linux; slightly weaker)\n"
          "  -v, --verbose     show n/a checks and hardening detail\n"
          "\n"
          "exit status: 0 nothing at/above --fail-on, 1 detection, 2 usage or internal error\n"
          "Run as root on Linux for full coverage (kallsyms, /proc/kcore, tracefs, dmesg).\n",
          f);
}

/* ------------------------------------------------------ fixtures dir */

static int is_dir(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int exe_dir(char *out, size_t sz) {
#if defined(__APPLE__)
    char raw[PATH_MAX];
    uint32_t n = sizeof raw;
    if (_NSGetExecutablePath(raw, &n) != 0) return -1;
    char *real = realpath(raw, NULL);
    if (!real) return -1;
    snprintf(out, sz, "%s", real);
    free(real);
#else
    ssize_t n = readlink("/proc/self/exe", out, sz - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
#endif
    char *slash = strrchr(out, '/');
    if (!slash) return -1;
    *slash = '\0';
    return 0;
}

static char *find_fixtures(void) {
    const char *env = getenv("REDOUBT_FIXTURES");
    if (env && is_dir(env)) return rd_xstrdup(env);
    if (is_dir("fixtures")) return rd_xstrdup("fixtures");
    char ed[PATH_MAX];
    if (exe_dir(ed, sizeof ed) == 0) {
        static const char *const rel[] = {"fixtures", "../fixtures", "../share/redoubt/fixtures", NULL};
        for (const char *const *r = rel; *r; r++) {
            char p[PATH_MAX + 64];
            snprintf(p, sizeof p, "%s/%s", ed, *r);
            if (is_dir(p)) return rd_xstrdup(p);
        }
    }
    if (is_dir("/usr/local/share/redoubt/fixtures")) return rd_xstrdup("/usr/local/share/redoubt/fixtures");
    if (is_dir("/usr/share/redoubt/fixtures")) return rd_xstrdup("/usr/share/redoubt/fixtures");
    return NULL;
}

/* --------------------------------------------------------- scenarios */

typedef struct {
    char name[128];
    char title[200];
    char *story;
    char expect[512], forbid[512], verdict[32], limits[1024];
} scen_t;

static void scen_free(scen_t *s) { free(s->story); }

static int scen_load(const char *root, const char *name, scen_t *s) {
    memset(s, 0, sizeof *s);
    snprintf(s->name, sizeof s->name, "%s", name);
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s/scenario.txt", root, name);
    char *buf = NULL;
    if (rd_read_file(path, &buf, NULL, 1 << 16) != 0) return -1;
    rd_sb story = {0};
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        char *colon = strchr(ln, ':');
        if (!colon) continue;
        *colon = '\0';
        char *val = rd_trim(colon + 1);
        if (!strcmp(ln, "title")) snprintf(s->title, sizeof s->title, "%s", val);
        else if (!strcmp(ln, "story")) rd_sb_addf(&story, "%s\n", val);
        else if (!strcmp(ln, "expect")) snprintf(s->expect, sizeof s->expect, "%s", val);
        else if (!strcmp(ln, "forbid")) snprintf(s->forbid, sizeof s->forbid, "%s", val);
        else if (!strcmp(ln, "verdict")) snprintf(s->verdict, sizeof s->verdict, "%s", val);
        else if (!strcmp(ln, "limits")) snprintf(s->limits, sizeof s->limits, "%s", val);
    }
    s->story = rd_sb_take(&story);
    free(buf);
    return 0;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* sorted list of scenario directory names */
static char **list_scenarios(const char *root, size_t *n) {
    DIR *d = opendir(root);
    if (!d) return NULL;
    char **names = NULL;
    size_t cnt = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' || e->d_name[0] == '_') continue;
        char p[PATH_MAX];
        snprintf(p, sizeof p, "%s/%s/scenario.txt", root, e->d_name);
        if (access(p, R_OK) != 0) continue;
        if (cnt == cap) {
            cap = cap ? cap * 2 : 16;
            names = rd_xrealloc(names, cap * sizeof *names);
        }
        names[cnt++] = rd_xstrdup(e->d_name);
    }
    closedir(d);
    if (cnt > 1) qsort(names, cnt, sizeof *names, cmp_str);
    *n = cnt;
    return names;
}

static void free_names(char **names, size_t n) {
    for (size_t i = 0; i < n; i++) free(names[i]);
    free(names);
}

/* ------------------------------------------------------------- scan */

static rd_provider *make_provider(const rd_options *o, char *source, size_t srcsz) {
    rd_provider *p;
    if (o->from) {
        p = rd_provider_fixture(o->from);
        if (!p) {
            fprintf(stderr, "redoubt: cannot open snapshot directory '%s'\n", o->from);
            return NULL;
        }
        snprintf(source, srcsz, "snapshot %s", o->from);
    } else {
        p = rd_provider_live(o);
        if (!p) {
            fprintf(stderr, "redoubt: no live provider for this OS (Linux and macOS are supported). "
                            "Use --from DIR to analyse a snapshot.\n");
            return NULL;
        }
        snprintf(source, srcsz, "live system");
    }
    if (o->simulate) {
        p = rd_provider_sim(p, o->simulate);
        if (!p) return NULL;
        size_t l = strlen(source);
        snprintf(source + l, srcsz - l, " + SIMULATED FAULTS (%s)", o->simulate);
    }
    return p;
}

static int detection_at_or_above(const rd_ctx *c, rd_sev thr) {
    for (size_t i = 0; i < c->nfinds; i++)
        if (c->finds[i].kind == RD_KIND_DETECTION && c->finds[i].sev >= thr) return 1;
    return 0;
}

static int cmd_scan(const rd_options *o) {
    char source[512];
    rd_provider *p = make_provider(o, source, sizeof source);
    if (!p) return 2;
    rd_ctx c;
    rd_ctx_init(&c, p, o);
    rd_scan(&c);
    if (o->json) rd_report_json(&c, source, stdout);
    else rd_report_text(&c, source, stdout);
    int rc = detection_at_or_above(&c, o->fail_on) ? 1 : 0;
    rd_verdict v = rd_verdict_compute(&c);
    if (!o->json && !o->from && v.skipped > 0 && geteuid() != 0)
        fprintf(stderr, "tip: %d check(s) were skipped; re-run with sudo for full coverage.\n", v.skipped);
    if (rc == 0 && o->strict_coverage && v.skipped > 0) rc = 3;
    rd_ctx_free(&c);
    return rc;
}

static int cmd_snapshot(const rd_options *o, const char *dir) {
    char source[512];
    rd_provider *p = make_provider(o, source, sizeof source);
    if (!p) return 2;
    rd_ctx c;
    rd_ctx_init(&c, p, o);
    fprintf(stderr, "collecting every kernel view (the Linux pid brute-force can take a few seconds)...\n");
    int rc = rd_snapshot_write(&c, dir, source);
    if (rc == 0) {
        int ok = 0, na = 0;
        for (int i = 0; i < RDV_COUNT; i++) (c.vstat[i] == RD_OK ? ok++ : na++);
        printf("snapshot written to %s/  (%d views captured, %d unavailable on this system)\n", dir, ok, na);
        printf("analyse it later with:  redoubt scan --from %s\n", dir);
    }
    rd_ctx_free(&c);
    return rc == 0 ? 0 : 2;
}

static int cmd_list(void) {
    size_t n = 0;
    const rd_check *const *all = rd_all_checks(&n);
    printf("%-16s %-8s %-34s %s\n", "ID", "PLATFORM", "TITLE", "WHAT IT COMPARES");
    for (size_t i = 0; i < n; i++) {
        const char *pl = all[i]->platforms == RD_PLAT_ANY ? "any" : (all[i]->platforms == RD_PLAT_LINUX ? "linux" : "macos");
        printf("%-16s %-8s %-34s %s\n", all[i]->id, pl, all[i]->title, all[i]->desc);
    }
    return 0;
}

/* ------------------------------------------------------- demo / eval */

static void print_overlay(const char *root, const char *name) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s/%s", root, name);
    DIR *d = opendir(dir);
    if (!d) return;
    char **files = NULL;
    size_t cnt = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l < 5 || strcmp(e->d_name + l - 4, ".tsv") != 0 || !strcmp(e->d_name, "unavailable.tsv")) continue;
        if (cnt == cap) {
            cap = cap ? cap * 2 : 16;
            files = rd_xrealloc(files, cap * sizeof *files);
        }
        files[cnt] = rd_xstrdup(e->d_name);
        files[cnt][l - 4] = '\0';
        cnt++;
    }
    closedir(d);
    if (cnt > 1) qsort(files, cnt, sizeof *files, cmp_str);
    if (cnt) {
        printf("  views this scenario alters vs. the clean base: ");
        for (size_t i = 0; i < cnt; i++) printf("%s%s", i ? ", " : "", files[i]);
        printf("\n");
    }
    free_names(files, cnt);
}

static void print_wrapped(const char *indent, const char *text, size_t width) {
    size_t col = 0, il = strlen(indent);
    printf("%s", indent);
    col = il;
    const char *p = text;
    while (*p) {
        while (*p == ' ') p++;
        const char *e = p;
        while (*e && *e != ' ') e++;
        size_t wl = (size_t)(e - p);
        if (!wl) break;
        if (col + wl + 1 > width && col > il) {
            printf("\n%s", indent);
            col = il;
        } else if (col > il) {
            putchar(' ');
            col++;
        }
        printf("%.*s", (int)wl, p);
        col += wl;
        p = e;
    }
    printf("\n");
}

static void print_story(const rd_options *o, const scen_t *s, const char *root) {
    const char *b = o->color ? "\033[1m" : "", *m = o->color ? "\033[1;35m" : "", *r = o->color ? "\033[0m" : "";
    printf("\n%s%s SCENARIO %s%s  %s\n", b, m, s->name, r, s->title);
    const char *p = s->story;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        printf("  %.*s\n", (int)l, p);
        if (!e) break;
        p = e + 1;
    }
    print_overlay(root, s->name);
    if (s->limits[0]) {
        printf("  limits:\n");
        print_wrapped("    ", s->limits, 92);
    }
}

static int cmd_demo(rd_options o, const char *which) {
    char *root = find_fixtures();
    if (!root) {
        fprintf(stderr, "redoubt: cannot find the fixtures directory (set REDOUBT_FIXTURES or run from the repo root)\n");
        return 2;
    }
    size_t n = 0;
    char **names = list_scenarios(root, &n);
    if (!names || n == 0) {
        fprintf(stderr, "redoubt: no scenarios in %s\n", root);
        free(root);
        return 2;
    }
    int rc = 0;
    if (!which) {
        printf("Bundled scenarios (run: redoubt demo <name>, or redoubt demo all):\n\n");
        for (size_t i = 0; i < n; i++) {
            scen_t s;
            scen_load(root, names[i], &s);
            printf("  %-22s %s\n", s.name, s.title);
            scen_free(&s);
        }
        printf("\nThese replay recorded kernel views through the same engine that scans a live machine.\n");
    } else {
        int matched = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(which, "all") != 0 && strcmp(which, names[i]) != 0) continue;
            matched = 1;
            scen_t s;
            scen_load(root, names[i], &s);
            char dir[PATH_MAX];
            snprintf(dir, sizeof dir, "%s/%s", root, names[i]);
            print_story(&o, &s, root);
            o.from = dir;
            char source[600];
            snprintf(source, sizeof source, "scenario %s (replayed views, not a live scan)", names[i]);
            rd_provider *p = rd_provider_fixture(dir);
            if (!p) {
                rc = 2;
                scen_free(&s);
                continue;
            }
            rd_ctx c;
            rd_ctx_init(&c, p, &o);
            rd_scan(&c);
            rd_report_text(&c, source, stdout);
            rd_ctx_free(&c);
            scen_free(&s);
        }
        if (!matched) {
            fprintf(stderr, "redoubt: no scenario named '%s' (run `redoubt demo` to list them)\n", which);
            rc = 2;
        }
    }
    free_names(names, n);
    free(root);
    return rc;
}

static int cmd_eval(rd_options o, const char *dirarg) {
    char *root = dirarg ? rd_xstrdup(dirarg) : find_fixtures();
    if (!root || !is_dir(root)) {
        fprintf(stderr, "redoubt: fixtures directory not found\n");
        free(root);
        return 2;
    }
    size_t n = 0;
    char **names = list_scenarios(root, &n);
    if (!names || n == 0) {
        fprintf(stderr, "redoubt: no scenarios in %s\n", root);
        free(root);
        return 2;
    }
    o.color = 0;
    printf("\nREDOUBT detection matrix - every scenario replayed through the live detection engine\n\n");
    printf("%-22s %-12s %-12s %-9s %-9s %s\n", "SCENARIO", "EXPECTED", "VERDICT", "DETECTED", "FP-CHECKS", "RESULT");
    printf("%-22s %-12s %-12s %-9s %-9s %s\n", "--------", "--------", "-------", "--------", "---------", "------");

    int failures = 0, expected_total = 0, detected_total = 0, clean_scen = 0, clean_fp = 0, rootkit_scen = 0, rootkit_hit = 0;
    for (size_t i = 0; i < n; i++) {
        scen_t s;
        scen_load(root, names[i], &s);
        char dir[PATH_MAX];
        snprintf(dir, sizeof dir, "%s/%s", root, names[i]);
        rd_provider *p = rd_provider_fixture(dir);
        rd_ctx c;
        rd_ctx_init(&c, p, &o);
        rd_scan(&c);
        rd_verdict v = rd_verdict_compute(&c);

        int exp = 0, det = 0, fpc = 0, bad = 0;
        rd_sb missed = {0};
        char *copy = rd_xstrdup(s.expect), *save = NULL;
        for (char *t = strtok_r(copy, ", ", &save); t; t = strtok_r(NULL, ", ", &save)) {
            exp++;
            if (rd_max_detection_sev(&c, t) >= (int)RD_LOW) det++;
            else rd_sb_addf(&missed, "%s%s", missed.len ? "," : "", t);
        }
        free(copy);
        copy = rd_xstrdup(s.forbid);
        save = NULL;
        for (char *t = strtok_r(copy, ", ", &save); t; t = strtok_r(NULL, ", ", &save))
            if (rd_max_detection_sev(&c, t) >= (int)RD_LOW) bad++;
        free(copy);
        int is_clean = strcmp(s.verdict, "CLEAN") == 0;
        if (is_clean) {
            for (size_t k = 0; k < c.nresults; k++)
                if (rd_max_detection_sev(&c, c.results[k].chk->id) >= (int)RD_MEDIUM) fpc++;
        }
        int verdict_ok = s.verdict[0] == '\0' || strcmp(s.verdict, rd_verdict_name(v.id)) == 0;
        int pass = det == exp && bad == 0 && verdict_ok && (!is_clean || fpc == 0);
        if (!pass) failures++;
        expected_total += exp;
        detected_total += det;
        if (is_clean) {
            clean_scen++;
            if (v.id != RD_VERDICT_CLEAN) clean_fp++;
        } else if (exp > 0) {
            rootkit_scen++;
            if (v.id != RD_VERDICT_CLEAN) rootkit_hit++;
        }
        char expcol[40], detcol[40];
        snprintf(expcol, sizeof expcol, "%s", s.verdict[0] ? s.verdict : "-");
        snprintf(detcol, sizeof detcol, "%d/%d", det, exp);
        printf("%-22s %-12s %-12s %-9s %-9d %s", names[i], expcol, rd_verdict_name(v.id), exp ? detcol : "-", fpc,
               pass ? "PASS" : "FAIL");
        if (missed.len) printf("   missed: %s", missed.buf);
        if (bad) printf("   forbidden check fired");
        if (!verdict_ok) printf("   wrong verdict");
        printf("\n");
        rd_sb_free(&missed);
        rd_ctx_free(&c);
        scen_free(&s);
    }
    printf("\n  expected detections  : %d of %d found\n", detected_total, expected_total);
    printf("  rootkit scenarios    : %d of %d flagged (verdict != CLEAN)\n", rootkit_hit, rootkit_scen);
    printf("  false-positive traps : %d of %d clean/decoy scenarios wrongly flagged\n", clean_fp, clean_scen);
    printf("  result               : %s\n\n", failures ? "FAIL" : "ALL SCENARIOS PASS");
    printf("  note: scenarios are modelled from public documentation of each rootkit family, not captured from\n"
           "  live infections. They verify the engine's logic; docs/EVALUATION.md explains what that does and\n"
           "  does not prove, and reports the real-kernel test results.\n\n");
    free_names(names, n);
    free(root);
    return failures ? 1 : 0;
}

/* ------------------------------------------------------------- main */

int main(int argc, char **argv) {
    rd_options o;
    memset(&o, 0, sizeof o);
    o.fail_on = RD_MEDIUM;
    o.color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");

    const char *cmd = "scan";
    if (argc > 1 && argv[1][0] != '-') {
        cmd = argv[1];
        argv[1] = argv[0];
        argv++;
        argc--;
    }

    static const struct option LONG[] = {
        {"from", required_argument, 0, 'f'},     {"baseline", required_argument, 0, 'b'},
        {"simulate", required_argument, 0, 's'}, {"only", required_argument, 0, 'o'},
        {"skip", required_argument, 0, 'x'},     {"fail-on", required_argument, 0, 'F'},
        {"json", no_argument, 0, 'j'},           {"no-color", no_argument, 0, 'n'},
        {"color", no_argument, 0, 'c'},          {"fast", no_argument, 0, 'q'},
        {"strict-coverage", no_argument, 0, 'S'}, {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},           {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };
    int ch;
    while ((ch = getopt_long(argc, argv, "vhV", LONG, NULL)) != -1) {
        switch (ch) {
        case 'f': o.from = optarg; break;
        case 'b': o.baseline = optarg; break;
        case 's': o.simulate = optarg; break;
        case 'o': o.only = optarg; break;
        case 'x': o.skip = optarg; break;
        case 'F':
            if (rd_sev_parse(optarg, &o.fail_on) != 0) {
                fprintf(stderr, "redoubt: bad severity '%s'\n", optarg);
                return 2;
            }
            break;
        case 'j': o.json = 1; break;
        case 'n': o.color = 0; break;
        case 'c': o.color = 1; break;
        case 'q': o.fast = 1; break;
        case 'S': o.strict_coverage = 1; break;
        case 'v': o.verbose = 1; break;
        case 'h': usage(stdout); return 0;
        case 'V': printf("redoubt %s\n", RD_VERSION); return 0;
        default: usage(stderr); return 2;
        }
    }
    const char *arg = optind < argc ? argv[optind] : NULL;

    if (!strcmp(cmd, "scan")) return cmd_scan(&o);
    if (!strcmp(cmd, "list-checks")) return cmd_list();
    if (!strcmp(cmd, "demo")) return cmd_demo(o, arg);
    if (!strcmp(cmd, "eval")) return cmd_eval(o, arg);
    if (!strcmp(cmd, "snapshot")) {
        if (!arg) {
            fprintf(stderr, "redoubt: snapshot needs a target directory\n");
            return 2;
        }
        return cmd_snapshot(&o, arg);
    }
    if (!strcmp(cmd, "version")) {
        printf("redoubt %s\n", RD_VERSION);
        return 0;
    }
    if (!strcmp(cmd, "help")) {
        usage(stdout);
        return 0;
    }
    fprintf(stderr, "redoubt: unknown command '%s'\n\n", cmd);
    usage(stderr);
    return 2;
}
