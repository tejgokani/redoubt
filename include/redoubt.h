/* SPDX-License-Identifier: MIT
 *
 * Redoubt - kernel-module rootkit detector.
 *
 * Architecture in one paragraph: a *provider* collects independent "views" of
 * the same kernel-level fact (e.g. the module list as seen through
 * /proc/modules, /sys/module and kallsyms).  A *check* compares views and
 * emits *findings* when they disagree - a rootkit has to lie consistently in
 * every view, the defender only needs one to tell the truth.  Providers are
 * pluggable (live Linux, live macOS, offline snapshot), so the same detection
 * logic runs on a live host or on an evidence bundle.
 */
#ifndef REDOUBT_H
#define REDOUBT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define RD_VERSION "1.0.0"

#if defined(__GNUC__) || defined(__clang__)
#define RD_PRINTF(f, a) __attribute__((format(printf, f, a)))
#else
#define RD_PRINTF(f, a)
#endif

/* ------------------------------------------------------------------ enums */

typedef enum { RD_INFO, RD_LOW, RD_MEDIUM, RD_HIGH, RD_CRITICAL } rd_sev;
typedef enum { RD_KIND_DETECTION, RD_KIND_POSTURE } rd_kind;
typedef enum { RD_VERDICT_CLEAN, RD_VERDICT_SUSPICIOUS, RD_VERDICT_COMPROMISED } rd_verdict_id;

enum { RD_PLAT_LINUX = 1, RD_PLAT_MACOS = 2, RD_PLAT_ANY = 3 };
enum { RD_OK = 0, RD_UNAVAIL = 1, RD_ERR = 2 };      /* view collection status */
enum { RD_RAN = 0, RD_SKIPPED = 1, RD_NA = 2 };      /* check outcome          */

/* Every independent observation the checks can ask a provider for. */
typedef enum {
    RDV_SYSINFO,     /* os, kernel, arch, euid, pid_max, taint mask               */
    RDV_MOD_API,     /* loaded modules per /proc/modules      (name,size,addr)    */
    RDV_MOD_SYSFS,   /* loaded modules per /sys/module        (name,taint chars)  */
    RDV_MOD_KALLSYMS,/* modules that own symbols in kallsyms  (name,count)        */
    RDV_MOD_DISK,    /* modules registered in modules.dep     (name,path)         */
    RDV_MOD_MEM,     /* module-loader vmalloc regions         (addr,size,caller)  */
    RDV_DMESG_MODS,  /* modules named in kernel-log taint messages                */
    RDV_KSYMS,       /* kernel text + module symbols          (name,addr,module)  */
    RDV_SYSCALLS,    /* raw syscall table read from kernel memory (idx,target)    */
    RDV_FTRACE,      /* functions with an ftrace callback attached                */
    RDV_PROLOGUES,   /* first bytes of security-relevant kernel functions         */
    RDV_PROC_API,    /* pids via the normal libc / libproc API                    */
    RDV_PROC_RAW,    /* pids via the raw syscall (getdents64 / sysctl)            */
    RDV_PROC_BRUTE,  /* pids found by probing every possible pid                  */
    RDV_NET_LISTED,  /* local ports the kernel *reports* (/proc/net/ files)      */
    RDV_NET_BOUND,   /* local ports that refuse bind() (EADDRINUSE)               */
    RDV_DIRS,        /* directory link counts vs visible sub-directories          */
    RDV_FILE_PROBES, /* paths that stat() finds vs. that readdir() lists          */
    RDV_PRELOAD,     /* LD_PRELOAD / ld.so.preload / DYLD_INSERT_LIBRARIES        */
    RDV_HARDENING,   /* security posture knobs (sysctl, SIP, lockdown ...)        */
    RDV_KEXT_LOADED, /* macOS: kexts per kmutil                                   */
    RDV_KEXT_ALT,    /* macOS: kernel bundles per the IOKit registry              */
    RDV_KEXT_DISK,   /* macOS: kexts installed under /Library/Extensions          */
    RDV_BOOTARGS,    /* macOS: kernel boot-args                                   */
    RDV_COUNT
} rd_view_id;

/* ------------------------------------------------------------------ views */

typedef struct rd_item {
    char *key;
    uint64_t a, b;
    char *extra;
} rd_item;

typedef struct rd_view {
    rd_item *items;
    size_t n, cap;
    int sorted;
} rd_view;

const char *rd_view_name(rd_view_id id);
int rd_view_id_from_name(const char *name);
void rd_view_init(rd_view *v);
void rd_view_free(rd_view *v);
rd_item *rd_view_add(rd_view *v, const char *key, uint64_t a, uint64_t b, const char *extra);
rd_item *rd_view_addf(rd_view *v, uint64_t a, uint64_t b, const char *extra, const char *keyfmt, ...)
    RD_PRINTF(5, 6);
void rd_view_sort(rd_view *v);
void rd_view_dedup(rd_view *v);
const rd_item *rd_view_find(rd_view *v, const char *key); /* sorts v in place */
void rd_view_remove(rd_view *v, const char *key);
int rd_view_write_tsv(const rd_view *v, FILE *f);
int rd_view_read_tsv(rd_view *v, const char *path); /* 0 ok, -1 cannot open */

/* --------------------------------------------------------------- provider */

typedef struct rd_provider rd_provider;
struct rd_provider {
    const char *name;
    void *priv;
    /* Fill `out`. Return RD_OK, RD_UNAVAIL (write a reason to `why`) or RD_ERR. */
    int (*collect)(rd_provider *, rd_view_id, rd_view *out, char *why, size_t whysz);
    /* Optional cheap re-probe of one key of a racy view: 1 exists, 0 gone, -1 unknown. */
    int (*probe)(rd_provider *, rd_view_id, const char *key);
    void (*destroy)(rd_provider *);
};

typedef struct rd_options {
    int json, color, verbose, fast, strict_coverage;
    rd_sev fail_on;
    const char *only, *skip; /* comma separated check ids  */
    const char *from;        /* snapshot / fixture dir     */
    const char *baseline;    /* baseline snapshot dir      */
    const char *simulate;    /* fault-injection spec       */
} rd_options;

rd_provider *rd_provider_live(const rd_options *opt);      /* NULL if unsupported OS */
rd_provider *rd_provider_fixture(const char *dir);         /* NULL if dir unusable   */
rd_provider *rd_provider_sim(rd_provider *inner, const char *spec); /* owns inner on success; NULL = bad spec, inner untouched */

/* --------------------------------------------------------- findings/checks */

typedef struct rd_finding {
    const char *check;
    rd_sev sev;
    int conf; /* 0-100: how sure are we that this is malicious */
    rd_kind kind;
    char *title;
    char *detail;
    const char *mitre;
    const char *fix;
} rd_finding;

typedef struct rd_ctx rd_ctx;

typedef struct rd_check {
    const char *id;
    const char *title;
    const char *desc;
    unsigned platforms;
    int (*run)(rd_ctx *); /* return 0, or rd_skip(...) */
} rd_check;

typedef struct rd_check_result {
    const rd_check *chk;
    int state;
    char *reason;
    int nfind;
} rd_check_result;

struct rd_ctx {
    rd_options opt;
    rd_provider *prov;
    int plat; /* RD_PLAT_* of the *data*, not of the machine running us */
    rd_view views[RDV_COUNT];
    int vstat[RDV_COUNT]; /* -1 not collected yet */
    char *vwhy[RDV_COUNT];
    rd_finding *finds;
    size_t nfinds, capfinds;
    rd_check_result *results;
    size_t nresults;
    const rd_check *cur;
    char *skip_reason;
};

void rd_ctx_init(rd_ctx *c, rd_provider *p, const rd_options *opt);
void rd_ctx_free(rd_ctx *c);
int rd_get_view(rd_ctx *c, rd_view_id id, rd_view **out); /* cached */
const char *rd_view_why(const rd_ctx *c, rd_view_id id);
int rd_recollect(rd_ctx *c, rd_view_id id, rd_view *fresh); /* uncached re-read */
int rd_probe(rd_ctx *c, rd_view_id id, const char *key);

rd_finding *rd_add(rd_ctx *c, rd_sev sev, int conf, const char *title, const char *detail_fmt, ...)
    RD_PRINTF(5, 6);
int rd_skip(rd_ctx *c, const char *fmt, ...) RD_PRINTF(2, 3);
int rd_na(rd_ctx *c, const char *fmt, ...) RD_PRINTF(2, 3); /* not applicable: does not count against coverage */

const rd_check *const *rd_all_checks(size_t *n);
void rd_scan(rd_ctx *c);

typedef struct rd_verdict {
    rd_verdict_id id;
    int score; /* 0-100 */
    int ran, skipped, applicable;
    int strong; /* detections that are HIGH+ with conf >= 75 */
    int checks_flagging; /* distinct checks with a MEDIUM+ detection */
} rd_verdict;

rd_verdict rd_verdict_compute(const rd_ctx *c);
const char *rd_verdict_name(rd_verdict_id v);
const char *rd_sev_name(rd_sev s);
int rd_sev_parse(const char *s, rd_sev *out);
int rd_max_detection_sev(const rd_ctx *c, const char *check_id); /* -1 if none */

/* ---------------------------------------------------------------- reports */

void rd_report_text(const rd_ctx *c, const char *source, FILE *f);
void rd_report_json(const rd_ctx *c, const char *source, FILE *f);
int rd_snapshot_write(rd_ctx *c, const char *dir, const char *title);

#endif
