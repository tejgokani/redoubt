/* SPDX-License-Identifier: MIT
 *
 * Checks that catch a rootkit hiding *objects* (processes, sockets, files).
 *
 * The rootkit filters what the kernel (or libc) returns from a listing call.
 * It cannot filter questions it does not know we are asking: "does pid N
 * exist?", "can I bind port P?", "does this directory have more sub-directories
 * than it shows me?".  Each check compares a filtered listing with an
 * unfilterable probe.
 */
#include "../checks.h"
#include "../intel.h"

#include <string.h>

/* ------------------------------------------------------------ proc-xview */

typedef struct {
    char pid[24];
    int kernel_level;
    char comm[48];
} pid_cand;

static int has_cand(const pid_cand *cs, size_t n, const char *pid) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(cs[i].pid, pid) == 0) return 1;
    return 0;
}

static int run_proc(rd_ctx *c) {
    NEED(c, RDV_PROC_API, api);
    NEED(c, RDV_PROC_BRUTE, br);
    rd_view *raw = NULL;
    int have_raw = rd_get_view(c, RDV_PROC_RAW, &raw) == RD_OK;

    pid_cand cs[64];
    size_t nc = 0;
    for (size_t i = 0; i < br->n && nc < 64; i++) {
        const char *k = br->items[i].key;
        if (strcmp(k, "0") == 0 || rd_view_find(api, k)) continue;
        int in_raw = have_raw && rd_view_find(raw, k) != NULL;
        snprintf(cs[nc].pid, sizeof cs[nc].pid, "%s", k);
        cs[nc].kernel_level = !in_raw;
        snprintf(cs[nc].comm, sizeof cs[nc].comm, "%s", br->items[i].extra);
        nc++;
    }
    for (size_t i = 0; have_raw && i < raw->n && nc < 64; i++) {
        const char *k = raw->items[i].key;
        if (strcmp(k, "0") == 0 || rd_view_find(api, k) || has_cand(cs, nc, k)) continue;
        snprintf(cs[nc].pid, sizeof cs[nc].pid, "%s", k);
        cs[nc].kernel_level = 0;
        cs[nc].comm[0] = '\0';
        nc++;
    }
    if (nc == 0) return 0;

    /* Re-check.  A process that died, or one that became visible on the second
     * listing, was a race with our scan - not a hidden process. */
    rd_view api2 = {0}, raw2 = {0};
    int sa = rd_recollect(c, RDV_PROC_API, &api2);
    int sr = have_raw ? rd_recollect(c, RDV_PROC_RAW, &raw2) : RD_UNAVAIL;
    size_t reported = 0;
    for (size_t i = 0; i < nc; i++) {
        if (rd_probe(c, RDV_PROC_BRUTE, cs[i].pid) == 0) continue;
        if (sa == RD_OK && rd_view_find(&api2, cs[i].pid)) continue;
        if (cs[i].kernel_level && sr == RD_OK && rd_view_find(&raw2, cs[i].pid)) cs[i].kernel_level = 0;
        if (++reported > 16) break;

        char title[200];
        snprintf(title, sizeof title, "Hidden process: pid %s%s%s%s", cs[i].pid, cs[i].comm[0] ? " (" : "",
                 cs[i].comm, cs[i].comm[0] ? ")" : "");
        rd_finding *f;
        if (cs[i].kernel_level)
            f = rd_add(c, RD_CRITICAL, 93, title,
                       "Exists (answers kill/sched/proc probes) but is absent from BOTH the libc listing and\n"
                       "the raw kernel listing (getdents64 / sysctl).\n"
                       "Even the kernel's own directory-listing path is being filtered: a syscall/VFS-level hook.");
        else
            f = rd_add(c, RD_HIGH, 90, title,
                       "Present in the raw kernel listing but missing from the libc/libproc listing.\n"
                       "The user-space API is being hooked (LD_PRELOAD / DYLD_INSERT_LIBRARIES style rootkit).");
        f->mitre = MITRE_HIDE;
        f->fix = "Do not kill it yet (it may be booby-trapped). Inspect it directly (executable path, command line, "
                 "open files), capture evidence, then isolate the host.";
    }
    if (sa == RD_OK) rd_view_free(&api2);
    if (sr == RD_OK) rd_view_free(&raw2);
    return 0;
}

const rd_check rd_chk_proc_xview = {
    "proc-xview", "Hidden-process cross-view", "process listing vs raw syscall vs brute-force pid probe",
    RD_PLAT_ANY, run_proc,
};

/* ------------------------------------------------------------ net-xview */

static int run_net(rd_ctx *c) {
    NEED(c, RDV_NET_LISTED, listed);
    NEED(c, RDV_NET_BOUND, bound);

    char cands[32][24];
    size_t nc = 0;
    for (size_t i = 0; i < bound->n && nc < 32; i++) {
        if (rd_view_find(listed, bound->items[i].key)) continue;
        snprintf(cands[nc++], sizeof cands[0], "%s", bound->items[i].key);
    }
    if (nc == 0) return 0;

    rd_view l2 = {0};
    int sl = rd_recollect(c, RDV_NET_LISTED, &l2);
    size_t reported = 0;
    for (size_t i = 0; i < nc; i++) {
        if (rd_probe(c, RDV_NET_BOUND, cands[i]) == 0) continue;
        if (sl == RD_OK && rd_view_find(&l2, cands[i])) continue;
        if (++reported > 16) break;
        char title[200];
        snprintf(title, sizeof title, "Hidden network port: %s", cands[i]);
        rd_finding *f = rd_add(c, RD_HIGH, 70, title,
                               "bind() on this port fails with EADDRINUSE - something owns it - but /proc/net/* does\n"
                               "not list it: the socket-table printer (tcp4_seq_show & co.) may be filtered.\n"
                               "Confidence is capped below the conviction threshold on purpose: a socket that is bound but\n"
                               "never listen()ed is also invisible in /proc/net/*, so this needs corroboration.");
        f->mitre = MITRE_ROOTKIT;
        f->fix = "Find the owner with a packet capture from another machine; do not trust local `ss`/`netstat`.";
    }
    if (sl == RD_OK) rd_view_free(&l2);
    return 0;
}

const rd_check rd_chk_net_xview = {
    "net-xview", "Hidden-port cross-view", "/proc/net/* vs bind() probing of every port",
    RD_PLAT_LINUX, run_net,
};

/* ------------------------------------------------------------- fs-xview */

static int run_fs(rd_ctx *c) {
    rd_view *d = NULL, *p = NULL;
    int have_d = rd_get_view(c, RDV_DIRS, &d) == RD_OK;
    int have_p = rd_get_view(c, RDV_FILE_PROBES, &p) == RD_OK;
    if (!have_d && !have_p) return rd_skip(c, "%s", rd_view_why(c, RDV_DIRS));

    if (have_d) {
        /* On ext4/xfs/tmpfs a directory's link count is 2 + its sub-directories.
         * A directory hiding a child from readdir() cannot hide it from st_nlink. */
        rd_view d2 = {0};
        int s2 = rd_recollect(c, RDV_DIRS, &d2);
        for (size_t i = 0; i < d->n; i++) {
            const rd_item *it = &d->items[i];
            if (strstr(it->extra, "unsupported")) continue;
            if (it->a <= 2 + it->b) continue;
            if (s2 == RD_OK) {
                const rd_item *again = rd_view_find(&d2, it->key);
                if (!again || again->a <= 2 + again->b) continue; /* changed under us */
            }
            uint64_t hidden = it->a - 2 - it->b;
            char title[300];
            snprintf(title, sizeof title, "Directory %s hides %llu sub-director%s", it->key, (unsigned long long)hidden,
                     hidden == 1 ? "y" : "ies");
            rd_finding *f = rd_add(c, RD_MEDIUM, 72, title,
                                   "st_nlink = %llu, but only %llu sub-directories are listed (expected nlink %llu).\n"
                                   "The link count includes children that readdir() was told to omit.",
                                   (unsigned long long)it->a, (unsigned long long)it->b, (unsigned long long)(2 + it->b));
            f->mitre = MITRE_HIDEFILE;
            f->fix = "`stat` guessed names under it; look for recently created dirs; compare with an offline mount.";
        }
        if (s2 == RD_OK) rd_view_free(&d2);
    }
    if (have_p) {
        for (size_t i = 0; i < p->n; i++) {
            const rd_item *it = &p->items[i];
            if (!(it->a && !it->b)) continue;
            char title[300];
            snprintf(title, sizeof title, "Hidden path: %s", it->key);
            rd_finding *f = rd_add(c, RD_HIGH, 92, title,
                                   "stat()/open() succeed, but the parent directory's listing omits the entry.\n"
                                   "A file that exists yet is not enumerated is being filtered by a getdents/VFS hook.");
            f->mitre = MITRE_HIDEFILE;
            f->fix = "Mount the disk read-only from another OS and inspect it there.";
        }
    }
    return 0;
}

const rd_check rd_chk_fs_xview = {
    "fs-xview", "Hidden file/directory cross-view", "readdir() vs st_nlink and direct stat() probes",
    RD_PLAT_LINUX, run_fs,
};

/* --------------------------------------------------------------- preload */

/* 2 = relative / temp / hidden path, 1 = outside the standard library dirs, 0 = standard location */
static int lib_class(const char *p) {
    if (p[0] != '/') return 2;
    static const char *const bad[] = {"/tmp", "/dev/shm", "/var/tmp", "/run", "/private/tmp", "/private/var/tmp",
                                      "/Users/Shared", NULL};
    for (const char *const *b = bad; *b; b++)
        if (rd_starts_with(p, *b)) return 2;
    if (strstr(p, "/.")) return 2; /* hidden path component */
    static const char *const std[] = {"/usr/lib", "/lib", "/usr/local/lib", "/opt", "/System", "/Library", NULL};
    for (const char *const *g = std; *g; g++)
        if (rd_starts_with(p, *g)) return 0;
    return 1;
}

static const char *preload_label(const char *src) {
    if (!strcmp(src, "env:self")) return "the scanner's own environment";
    if (!strcmp(src, "env:init")) return "PID 1's environment (inherited by everything)";
    if (!strcmp(src, "ld.so.preload")) return "/etc/ld.so.preload (system-wide)";
    if (!strncmp(src, "launchctl", 9)) return "launchd (system-wide)";
    return src;
}

static int run_preload(rd_ctx *c) {
    NEED(c, RDV_PRELOAD, pl);
    for (size_t i = 0; i < pl->n; i++) {
        const char *src = pl->items[i].key;
        char *val = rd_xstrdup(pl->items[i].extra);
        for (char *q = val; *q; q++)
            if (*q == ':' || *q == '\t') *q = ' ';
        char *save = NULL;
        for (char *tok = strtok_r(val, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
            int cls = lib_class(tok);
            int system_wide = strcmp(src, "ld.so.preload") == 0 || strncmp(src, "launchctl", 9) == 0 ||
                              strcmp(src, "env:init") == 0;
            char title[400];
            snprintf(title, sizeof title, "Library injected via %s: %s", preload_label(src), tok);
            rd_sev sev = cls == 2 ? RD_HIGH : RD_MEDIUM;
            int conf = cls == 2 ? 85 : (cls == 1 ? 60 : (system_wide ? 55 : 50));
            const char *why = cls == 2 ? "The path is relative, in a temp directory, or hidden - not where packages install libraries."
                              : cls == 1 ? "The path is outside the standard library directories."
                                         : "The path looks like a system location, but preloading is rare enough to review.";
            rd_finding *f = rd_add(c, sev, conf, title,
                                   "%s is loaded into dynamically-linked processes before the system libraries, so it\n"
                                   "can rewrite readdir(), proc_listpids(), open() ... and hide anything.\n%s",
                                   tok, why);
            f->mitre = MITRE_LDPRELOAD;
            f->fix = "Inspect the library (`strings`, hash it). Remove the entry only after capturing it as evidence.";
        }
        free(val);
    }
    return 0;
}

const rd_check rd_chk_preload = {
    "preload", "Dynamic-linker hijack", "ld.so.preload / LD_PRELOAD / DYLD_INSERT_LIBRARIES",
    RD_PLAT_ANY, run_preload,
};
