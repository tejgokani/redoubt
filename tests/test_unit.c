/* SPDX-License-Identifier: MIT
 *
 * Unit tests.  Checks are exercised through an in-memory provider so each test
 * states exactly which views exist and asserts exactly what fires.
 */
#include "../src/checks.h"
#include "../src/util.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_pass, g_fail;
#define CHECK(cond)                                                                                      \
    do {                                                                                                 \
        if (cond) g_pass++;                                                                              \
        else {                                                                                           \
            g_fail++;                                                                                    \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                             \
        }                                                                                                \
    } while (0)

/* ------------------------------------------------------- in-memory provider */

typedef struct {
    rd_view v[RDV_COUNT];
    int have[RDV_COUNT];
    int probe_ret; /* what probe() answers: 1 exists, 0 gone, -1 unknown */
} memp_t;

static int mem_collect(rd_provider *p, rd_view_id id, rd_view *out, char *why, size_t sz) {
    memp_t *m = p->priv;
    if (!m->have[id]) {
        snprintf(why, sz, "test: view absent");
        return RD_UNAVAIL;
    }
    for (size_t i = 0; i < m->v[id].n; i++) {
        const rd_item *it = &m->v[id].items[i];
        rd_view_add(out, it->key, it->a, it->b, it->extra);
    }
    return RD_OK;
}
static int mem_probe(rd_provider *p, rd_view_id id, const char *key) {
    (void)id;
    (void)key;
    return ((memp_t *)p->priv)->probe_ret;
}
static void mem_destroy(rd_provider *p) {
    memp_t *m = p->priv;
    for (int i = 0; i < RDV_COUNT; i++) rd_view_free(&m->v[i]);
    free(m);
    free(p);
}
static rd_provider *mem_new(const char *os, const char *arch) {
    rd_provider *p = rd_xmalloc(sizeof *p);
    memp_t *m = rd_xmalloc(sizeof *m);
    memset(m, 0, sizeof *m);
    m->probe_ret = -1;
    p->name = "mem";
    p->priv = m;
    p->collect = mem_collect;
    p->probe = mem_probe;
    p->destroy = mem_destroy;
    rd_view_add(&m->v[RDV_SYSINFO], "os", 0, 0, os);
    rd_view_add(&m->v[RDV_SYSINFO], "arch", 0, 0, arch);
    m->have[RDV_SYSINFO] = 1;
    return p;
}
static void put(rd_provider *p, rd_view_id id, const char *key, uint64_t a, uint64_t b, const char *extra) {
    memp_t *m = p->priv;
    m->have[id] = 1;
    rd_view_add(&m->v[id], key, a, b, extra);
}
static void have(rd_provider *p, rd_view_id id) { ((memp_t *)p->priv)->have[id] = 1; }

static void run_only(rd_ctx *c, rd_provider *p, const char *only) {
    rd_options o;
    memset(&o, 0, sizeof o);
    o.only = only;
    o.fail_on = RD_MEDIUM;
    rd_ctx_init(c, p, &o);
    rd_scan(c);
}

static int nfind(const rd_ctx *c, const char *check, int min_sev) {
    int n = 0;
    for (size_t i = 0; i < c->nfinds; i++)
        if (!strcmp(c->finds[i].check, check) && c->finds[i].kind == RD_KIND_DETECTION && (int)c->finds[i].sev >= min_sev) n++;
    return n;
}

static int state_of(const rd_ctx *c, const char *check) {
    for (size_t i = 0; i < c->nresults; i++)
        if (!strcmp(c->results[i].chk->id, check)) return c->results[i].state;
    return -1;
}

/* ------------------------------------------------------------------ tests */

static void test_util(void) {
    uint64_t v = 0;
    CHECK(rd_parse_u64("0x10", &v) == 0 && v == 16);
    CHECK(rd_parse_u64("42", &v) == 0 && v == 42);
    CHECK(rd_parse_u64("12abc", &v) != 0);
    CHECK(rd_parse_u64("", &v) != 0);
    CHECK(rd_csv_has("a,bb,c", "bb") && !rd_csv_has("a,bb,c", "b") && !rd_csv_has(NULL, "a") && !rd_csv_has("", "a"));
    char m[] = "snd-hda-intel";
    rd_norm_modname(m);
    CHECK(strcmp(m, "snd_hda_intel") == 0);
    rd_sb sb = {0};
    rd_sb_addf(&sb, "%d-%s", 7, "x");
    rd_sb_addf(&sb, "!");
    char *s = rd_sb_take(&sb);
    CHECK(strcmp(s, "7-x!") == 0);
    free(s);
    rd_sev sev;
    CHECK(rd_sev_parse("HIGH", &sev) == 0 && sev == RD_HIGH);
    CHECK(rd_sev_parse("medium", &sev) == 0 && sev == RD_MEDIUM);
    CHECK(rd_sev_parse("nope", &sev) != 0);
}

static void test_view(void) {
    rd_view v;
    rd_view_init(&v);
    rd_view_add(&v, "b", 2, 0, "x");
    rd_view_add(&v, "a", 1, 0, "y");
    rd_view_add(&v, "b", 3, 0, "z");
    CHECK(rd_view_find(&v, "a") && rd_view_find(&v, "a")->a == 1);
    CHECK(rd_view_find(&v, "nope") == NULL);
    rd_view_dedup(&v);
    CHECK(v.n == 2);
    rd_view_remove(&v, "a");
    CHECK(v.n == 1 && !rd_view_find(&v, "a"));
    rd_view_add(&v, "tab\there", 0xdead, 0xbeef, "multi\nline");
    char path[] = "/tmp/redoubt-test-XXXXXX";
    int fd = mkstemp(path);
    FILE *f = fdopen(fd, "w");
    rd_view_write_tsv(&v, f);
    fclose(f);
    rd_view w;
    rd_view_init(&w);
    CHECK(rd_view_read_tsv(&w, path) == 0 && w.n == 2);
    CHECK(rd_view_find(&w, "tab here") && rd_view_find(&w, "tab here")->a == 0xdead && rd_view_find(&w, "tab here")->b == 0xbeef);
    unlink(path);
    rd_view_free(&v);
    rd_view_free(&w);
}

static void test_mod_xview(void) {
    rd_ctx c;
    rd_provider *p = mem_new("Linux", "x86_64");
    put(p, RDV_MOD_API, "ext4", 0x1000, 0xffffffffc0000000ULL, "Live");
    put(p, RDV_MOD_SYSFS, "ext4", 0, 0, "");
    put(p, RDV_MOD_SYSFS, "evil", 0, 0, "OE");
    put(p, RDV_MOD_KALLSYMS, "ext4", 1, 0, "");
    put(p, RDV_MOD_KALLSYMS, "evil", 1, 0, "");
    run_only(&c, p, "mod-xview");
    CHECK(nfind(&c, "mod-xview", RD_HIGH) == 1);
    CHECK(c.finds[0].conf >= 95); /* two independent sources agree */
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64"); /* consistent views: silence */
    put(p, RDV_MOD_API, "ext4", 0x1000, 0xffffffffc0000000ULL, "Live");
    put(p, RDV_MOD_SYSFS, "ext4", 0, 0, "");
    run_only(&c, p, "mod-xview");
    CHECK(nfind(&c, "mod-xview", RD_INFO) == 0 && state_of(&c, "mod-xview") == RD_RAN);
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64"); /* listed but sysfs node removed */
    put(p, RDV_MOD_API, "ghost", 0x1000, 0xffffffffc0000000ULL, "Live");
    have(p, RDV_MOD_SYSFS);
    run_only(&c, p, "mod-xview");
    CHECK(nfind(&c, "mod-xview", RD_MEDIUM) == 1);
    rd_ctx_free(&c);

    /* REGRESSION - real kernels tag ftrace trampolines / BPF images in kallsyms as pseudo-modules
     * ([__builtin__ftrace], [bpf], [kprobes]); they are allocators, not hidden modules. */
    p = mem_new("Linux", "x86_64");
    put(p, RDV_MOD_API, "ext4", 0x1000, 0xffffffffc0000000ULL, "Live");
    put(p, RDV_MOD_SYSFS, "ext4", 0, 0, "");
    put(p, RDV_MOD_KALLSYMS, "ext4", 1, 0, "");
    put(p, RDV_MOD_KALLSYMS, "__builtin__ftrace", 1, 0, "");
    put(p, RDV_MOD_KALLSYMS, "bpf", 1, 0, "");
    run_only(&c, p, "mod-xview");
    CHECK(nfind(&c, "mod-xview", RD_INFO) == 0);
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64"); /* missing view => skipped, never a silent "clean" */
    put(p, RDV_MOD_API, "ext4", 0, 0, "Live");
    run_only(&c, p, "mod-xview");
    CHECK(state_of(&c, "mod-xview") == RD_SKIPPED);
    rd_ctx_free(&c);
}

static void ksyms_basic(rd_provider *p) {
    put(p, RDV_KSYMS, "_stext", 0xffffffff81000000ULL, 0, "");
    put(p, RDV_KSYMS, "_etext", 0xffffffff82000000ULL, 0, "");
    put(p, RDV_KSYMS, "__x64_sys_read", 0xffffffff81301a40ULL, 0, "");
    put(p, RDV_KSYMS, "__x64_sys_kill", 0xffffffff810b7d50ULL, 0, "");
    put(p, RDV_KSYMS, "some_core_func", 0xffffffff81400000ULL, 0, "");
    put(p, RDV_KSYMS, "hook_kill", 0xffffffffc0600120ULL, 0, "evilmod");
}

static void test_syscall_table(void) {
    rd_ctx c;
    rd_provider *p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_SYSCALLS, "0", 0xffffffff81301a40ULL, 0, "");
    put(p, RDV_SYSCALLS, "62", 0xffffffffc0600120ULL, 0, "");
    run_only(&c, p, "syscall-table");
    CHECK(nfind(&c, "syscall-table", RD_CRITICAL) == 1);
    CHECK(strstr(c.finds[0].detail, "kill") != NULL);   /* named via the x86_64 table */
    CHECK(strstr(c.finds[0].detail, "evilmod") != NULL); /* resolved to its module */
    rd_ctx_free(&c);

    /* boundaries: text_lo is inside, text_hi is outside */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_KSYMS, "__x64_sys_edge_lo", 0xffffffff81000000ULL, 0, "");
    put(p, RDV_SYSCALLS, "1", 0xffffffff81000000ULL, 0, "");
    run_only(&c, p, "syscall-table");
    CHECK(nfind(&c, "syscall-table", RD_INFO) == 0);
    rd_ctx_free(&c);
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_SYSCALLS, "1", 0xffffffff82000000ULL, 0, "");
    run_only(&c, p, "syscall-table");
    CHECK(nfind(&c, "syscall-table", RD_CRITICAL) == 1);
    rd_ctx_free(&c);

    /* inside kernel text but not a syscall entry point: weaker, MEDIUM */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_SYSCALLS, "0", 0xffffffff81400000ULL, 0, "");
    run_only(&c, p, "syscall-table");
    CHECK(nfind(&c, "syscall-table", RD_CRITICAL) == 0 && nfind(&c, "syscall-table", RD_MEDIUM) == 1);
    rd_ctx_free(&c);

    /* zero entries (table padding) are ignored */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_SYSCALLS, "9", 0, 0, "");
    run_only(&c, p, "syscall-table");
    CHECK(nfind(&c, "syscall-table", RD_INFO) == 0);
    rd_ctx_free(&c);
}

static void test_inline_hooks(void) {
    struct {
        const char *hex;
        int expect; /* min severity that must fire; -1 = none */
        const char *what;
    } cases[] = {
        {"f30f1efae8000000005548", -1, "endbr64 + call __fentry__ is normal"},
        {"e9" "00100000" "90909090", RD_HIGH, "jmp rel32 out of text"},      /* to 0x...82001005: outside */
        {"f30f1efae9" "00100000" "9090", RD_HIGH, "endbr64 then jmp"},
        {"ff25" "00000000" "0000000000", RD_HIGH, "jmp [rip+disp]"},
        {"48b8" "0000000000c0ffff" "ffe0", RD_HIGH, "movabs rax; jmp rax"},
        {"e9" "fbffffff" "90", -1, "jmp to self (inside text) is not flagged"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        rd_ctx c;
        rd_provider *p = mem_new("Linux", "x86_64");
        ksyms_basic(p);
        put(p, RDV_PROLOGUES, "filldir64", 0xffffffff81ffff00ULL, 0, cases[i].hex);
        run_only(&c, p, "inline-hooks");
        int fired = nfind(&c, "inline-hooks", RD_HIGH);
        if (cases[i].expect < 0) CHECK(fired == 0);
        else CHECK(fired == 1);
        if (fired != (cases[i].expect >= 0)) fprintf(stderr, "    (case: %s)\n", cases[i].what);
        rd_ctx_free(&c);
    }
}

static void test_ftrace(void) {
    rd_ctx c;
    rd_provider *p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    have(p, RDV_MOD_API);
    put(p, RDV_MOD_API, "ext4", 1, 1, "Live");
    put(p, RDV_FTRACE, "__x64_sys_getdents64", 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (hook+0x0/0xe0 [ghost])");
    put(p, RDV_FTRACE, "tcp4_seq_show", 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (0xffffffffc0abcd00)");
    run_only(&c, p, "ftrace-hooks");
    CHECK(nfind(&c, "ftrace-hooks", RD_CRITICAL) == 1);
    CHECK(strstr(c.finds[0].detail, "ghost") && strstr(c.finds[0].detail, "0xffffffffc0abcd00"));
    rd_ctx_free(&c);

    /* visible module + IPMODIFY on a sensitive function = review (MEDIUM), not CRITICAL */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_MOD_API, "edr_agent", 1, 1, "Live");
    put(p, RDV_FTRACE, "__x64_sys_kill", 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (cb+0x0/0x10 [edr_agent])");
    run_only(&c, p, "ftrace-hooks");
    CHECK(nfind(&c, "ftrace-hooks", RD_CRITICAL) == 0 && nfind(&c, "ftrace-hooks", RD_MEDIUM) == 1);
    rd_ctx_free(&c);

    /* REGRESSION - captured from a real Linux 6.17 kernel on a clean machine.  A kprobe on ip_send_skb shows the
     * trampoline as a raw module-area address; the owner is the core callback in parentheses.  The first
     * version of this check flagged the trampoline address as "hidden code": a false positive. */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_FTRACE, "ip_send_skb", 1, 0,
        "(1) R          tramp: 0xffffffffc0471000 (kprobe_ftrace_handler+0x0/0x1c0) ->kprobe_ftrace_handler+0x0/0x1c0");
    run_only(&c, p, "ftrace-hooks");
    CHECK(nfind(&c, "ftrace-hooks", RD_INFO) == 0);
    rd_ctx_free(&c);

    /* ...while a hidden module's callback in the SAME real format is still caught */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    have(p, RDV_MOD_API);
    put(p, RDV_FTRACE, "__x64_sys_getdents64", 1, 0,
        "(1) R I        tramp: 0xffffffffc0471000 (hook_getdents64+0x0/0xe0 [ghost]) ->hook_getdents64+0x0/0xe0 [ghost]");
    run_only(&c, p, "ftrace-hooks");
    CHECK(nfind(&c, "ftrace-hooks", RD_CRITICAL) == 1);
    rd_ctx_free(&c);

    /* core-kernel callback (kprobes, livepatch): nothing to say */
    p = mem_new("Linux", "x86_64");
    ksyms_basic(p);
    put(p, RDV_FTRACE, "__x64_sys_kill", 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (kprobe_ftrace_handler+0x0/0x1d0)");
    run_only(&c, p, "ftrace-hooks");
    CHECK(nfind(&c, "ftrace-hooks", RD_INFO) == 0);
    rd_ctx_free(&c);
}

static void test_proc_xview(void) {
    rd_ctx c;
    /* kernel-level: brute finds 99, both listings lack it */
    rd_provider *p = mem_new("Linux", "x86_64");
    put(p, RDV_PROC_API, "1", 0, 0, "");
    put(p, RDV_PROC_RAW, "1", 0, 0, "");
    put(p, RDV_PROC_BRUTE, "1", 0, 0, "init");
    put(p, RDV_PROC_BRUTE, "99", 0, 0, "evil");
    ((memp_t *)p->priv)->probe_ret = 1;
    run_only(&c, p, "proc-xview");
    CHECK(nfind(&c, "proc-xview", RD_CRITICAL) == 1);
    rd_ctx_free(&c);

    /* user-level: raw has it, API does not */
    p = mem_new("Linux", "x86_64");
    put(p, RDV_PROC_API, "1", 0, 0, "");
    put(p, RDV_PROC_RAW, "1", 0, 0, "");
    put(p, RDV_PROC_RAW, "99", 0, 0, "");
    put(p, RDV_PROC_BRUTE, "1", 0, 0, "init");
    put(p, RDV_PROC_BRUTE, "99", 0, 0, "evil");
    ((memp_t *)p->priv)->probe_ret = 1;
    run_only(&c, p, "proc-xview");
    CHECK(nfind(&c, "proc-xview", RD_HIGH) == 1 && nfind(&c, "proc-xview", RD_CRITICAL) == 0);
    rd_ctx_free(&c);

    /* a process that exited before the re-probe is a race, not a rootkit */
    p = mem_new("Linux", "x86_64");
    put(p, RDV_PROC_API, "1", 0, 0, "");
    put(p, RDV_PROC_BRUTE, "1", 0, 0, "init");
    put(p, RDV_PROC_BRUTE, "99", 0, 0, "shortlived");
    ((memp_t *)p->priv)->probe_ret = 0;
    run_only(&c, p, "proc-xview");
    CHECK(nfind(&c, "proc-xview", RD_INFO) == 0);
    rd_ctx_free(&c);

    /* pid 0 (kernel_task on macOS) is never "hidden" */
    p = mem_new("Darwin", "arm64");
    put(p, RDV_PROC_API, "1", 0, 0, "");
    put(p, RDV_PROC_BRUTE, "0", 0, 0, "kernel_task");
    ((memp_t *)p->priv)->probe_ret = 1;
    run_only(&c, p, "proc-xview");
    CHECK(nfind(&c, "proc-xview", RD_INFO) == 0);
    rd_ctx_free(&c);
}

static void test_net_fs_preload(void) {
    rd_ctx c;
    rd_provider *p = mem_new("Linux", "x86_64");
    put(p, RDV_NET_LISTED, "tcp:22", 0, 0, "");
    put(p, RDV_NET_BOUND, "tcp:22", 0, 0, "");
    put(p, RDV_NET_BOUND, "tcp:4444", 0, 0, "");
    ((memp_t *)p->priv)->probe_ret = 1;
    run_only(&c, p, "net-xview");
    CHECK(nfind(&c, "net-xview", RD_HIGH) == 1 && strstr(c.finds[0].title, "4444"));
    CHECK(c.finds[0].conf < 75); /* a bind-only socket is a known benign lookalike: must not alone convict */
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64");
    put(p, RDV_DIRS, "/tmp", 5, 2, "fs=ok");          /* 5 > 2+2: one hidden sub-dir */
    put(p, RDV_DIRS, "/var/lib/docker", 9, 1, "fs=unsupported");  /* overlayfs etc.: ignored */
    put(p, RDV_DIRS, "/etc", 4, 2, "fs=ok");          /* 4 == 2+2: fine */
    have(p, RDV_FILE_PROBES);
    run_only(&c, p, "fs-xview");
    CHECK(nfind(&c, "fs-xview", RD_MEDIUM) == 1 && strstr(c.finds[0].title, "/tmp"));
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64");
    have(p, RDV_DIRS);
    put(p, RDV_FILE_PROBES, "/etc/ld.so.preload", 1, 0, "x"); /* stat ok, not listed */
    put(p, RDV_FILE_PROBES, "/reptile", 1, 1, "x");           /* exists and listed: not "hidden" here */
    run_only(&c, p, "fs-xview");
    CHECK(nfind(&c, "fs-xview", RD_HIGH) == 1);
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64");
    put(p, RDV_PRELOAD, "ld.so.preload", 0, 0, "/dev/shm/.x/libc.so.7");
    put(p, RDV_PRELOAD, "env:self", 0, 0, "/usr/lib/libjemalloc.so.2");
    put(p, RDV_PRELOAD, "env:init", 0, 0, "relative.so");
    run_only(&c, p, "preload");
    CHECK(nfind(&c, "preload", RD_HIGH) == 2);   /* /dev/shm and relative path */
    CHECK(nfind(&c, "preload", RD_MEDIUM) == 3); /* + the system-path one at MEDIUM */
    rd_ctx_free(&c);
}

static void test_taint_iocs(void) {
    rd_ctx c;
    rd_provider *p = mem_new("Linux", "x86_64");
    rd_view_add(&((memp_t *)p->priv)->v[RDV_SYSINFO], "taint", 4096, 0, "");
    put(p, RDV_MOD_SYSFS, "nvidia", 0, 0, "PO"); /* O is explained by a visible module */
    have(p, RDV_MOD_API);
    run_only(&c, p, "mod-taint");
    CHECK(nfind(&c, "mod-taint", RD_INFO) == 0);
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64");
    rd_view_add(&((memp_t *)p->priv)->v[RDV_SYSINFO], "taint", 4096, 0, "");
    have(p, RDV_MOD_SYSFS);
    have(p, RDV_MOD_API);
    run_only(&c, p, "mod-taint");
    CHECK(nfind(&c, "mod-taint", RD_LOW) == 1 && nfind(&c, "mod-taint", RD_MEDIUM) == 0);
    rd_ctx_free(&c);

    /* dmesg names a module no view lists: confidence depends on whether it exists on disk */
    for (int on_disk = 0; on_disk < 2; on_disk++) {
        p = mem_new("Linux", "x86_64");
        rd_view_add(&((memp_t *)p->priv)->v[RDV_SYSINFO], "taint", 0, 0, "");
        have(p, RDV_MOD_SYSFS);
        have(p, RDV_MOD_API);
        put(p, RDV_DMESG_MODS, "ghost", 0, 0, "out-of-tree module taints kernel");
        put(p, RDV_MOD_DISK, "ext4", 0, 0, "x");
        if (on_disk) put(p, RDV_MOD_DISK, "ghost", 0, 0, "x");
        run_only(&c, p, "mod-taint");
        CHECK(nfind(&c, "mod-taint", RD_MEDIUM) == 1);
        CHECK(on_disk ? c.finds[0].conf < 50 : c.finds[0].conf >= 60);
        rd_ctx_free(&c);
    }

    p = mem_new("Linux", "x86_64");
    put(p, RDV_MOD_API, "diamorphine", 0, 0, "Live");
    put(p, RDV_MOD_SYSFS, "reptile_module", 0, 0, "");
    have(p, RDV_MOD_KALLSYMS);
    run_only(&c, p, "known-iocs");
    CHECK(nfind(&c, "known-iocs", RD_HIGH) == 2);
    rd_ctx_free(&c);
}

static void test_verdict(void) {
    rd_ctx c;
    rd_provider *p = mem_new("Linux", "x86_64");
    have(p, RDV_MOD_API);
    run_only(&c, p, "hardening"); /* skipped: no data. Verdict must not be "clean 100% coverage" */
    rd_verdict v = rd_verdict_compute(&c);
    CHECK(v.id == RD_VERDICT_CLEAN && v.skipped == 1 && v.ran == 0);
    rd_ctx_free(&c);

    /* one MEDIUM = SUSPICIOUS, two independent checks at MEDIUM = COMPROMISED, one strong HIGH = COMPROMISED */
    p = mem_new("Linux", "x86_64");
    put(p, RDV_DIRS, "/tmp", 5, 2, "fs=ok");
    have(p, RDV_FILE_PROBES);
    run_only(&c, p, "fs-xview");
    CHECK(rd_verdict_compute(&c).id == RD_VERDICT_SUSPICIOUS);
    rd_ctx_free(&c);

    p = mem_new("Linux", "x86_64");
    put(p, RDV_MOD_API, "a", 1, 1, "Live");
    put(p, RDV_MOD_SYSFS, "a", 0, 0, "");
    put(p, RDV_MOD_SYSFS, "hid", 0, 0, "");
    run_only(&c, p, "mod-xview");
    CHECK(rd_verdict_compute(&c).id == RD_VERDICT_COMPROMISED); /* HIGH @ 90% */
    CHECK(rd_verdict_compute(&c).score > 0);
    rd_ctx_free(&c);

    /* posture findings never move the verdict */
    p = mem_new("Linux", "x86_64");
    put(p, RDV_HARDENING, "modules_disabled", 0, 1, "0");
    put(p, RDV_HARDENING, "lockdown", 0, 1, "none");
    run_only(&c, p, "hardening");
    CHECK(c.nfinds >= 2 && rd_verdict_compute(&c).id == RD_VERDICT_CLEAN && rd_verdict_compute(&c).score == 0);
    rd_ctx_free(&c);
}

/* ------------------------------------------------- fixtures, snapshot, sim */

static int scan_dir(const char *dir, rd_verdict *out, int naive_mode);

/* A provider that never re-samples and never re-probes: what a naive diff tool does. */
typedef struct {
    char dir[512];
} naive_t;
static int naive_collect(rd_provider *p, rd_view_id id, rd_view *out, char *why, size_t sz) {
    rd_provider *fresh = rd_provider_fixture(((naive_t *)p->priv)->dir);
    int st = fresh->collect(fresh, id, out, why, sz);
    fresh->destroy(fresh);
    return st;
}
static void naive_destroy(rd_provider *p) {
    free(p->priv);
    free(p);
}
static int scan_dir(const char *dir, rd_verdict *out, int naive_mode) {
    rd_provider *p;
    if (naive_mode) {
        p = rd_xmalloc(sizeof *p);
        naive_t *n = rd_xmalloc(sizeof *n);
        snprintf(n->dir, sizeof n->dir, "%s", dir);
        p->name = "naive";
        p->priv = n;
        p->collect = naive_collect;
        p->probe = NULL;
        p->destroy = naive_destroy;
    } else {
        p = rd_provider_fixture(dir);
    }
    if (!p) return -1;
    rd_ctx c;
    rd_options o;
    memset(&o, 0, sizeof o);
    rd_ctx_init(&c, p, &o);
    rd_scan(&c);
    *out = rd_verdict_compute(&c);
    int n = (int)c.nfinds;
    rd_ctx_free(&c);
    return n;
}

static void test_false_positive_traps_are_real(void) {
    rd_verdict v;
    CHECK(scan_dir("fixtures/false-positive-traps", &v, 0) >= 0 && v.id == RD_VERDICT_CLEAN);
    /* Mutation: remove the re-sampling and re-probing. The decoys must now fire -
     * proving the scenario is CLEAN because of the race handling, not by accident. */
    CHECK(scan_dir("fixtures/false-positive-traps", &v, 1) >= 0 && v.id != RD_VERDICT_CLEAN);
}

static void test_snapshot_roundtrip(void) {
    char dir[] = "/tmp/redoubt-snap-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    rd_provider *fp = rd_provider_fixture("fixtures/ftrace-lkm");
    rd_ctx c;
    rd_options o;
    memset(&o, 0, sizeof o);
    rd_ctx_init(&c, fp, &o);
    CHECK(rd_snapshot_write(&c, dir, "roundtrip") == 0);
    rd_ctx_free(&c);

    rd_verdict a, b;
    int na = scan_dir("fixtures/ftrace-lkm", &a, 0);
    int nb = scan_dir(dir, &b, 0);
    CHECK(na > 0 && na == nb && a.id == b.id && a.score == b.score); /* flattening base+overlay loses nothing */
    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    CHECK(system(cmd) == 0);
}

static void test_simulate(void) {
    rd_options o;
    memset(&o, 0, sizeof o);
    o.fail_on = RD_MEDIUM;
    rd_ctx c;

    rd_provider *p = rd_provider_sim(rd_provider_fixture("fixtures/clean-macos"), "hide-pid:655");
    CHECK(p != NULL);
    rd_ctx_init(&c, p, &o);
    rd_scan(&c);
    CHECK(nfind(&c, "proc-xview", RD_CRITICAL) == 1 && rd_verdict_compute(&c).id == RD_VERDICT_COMPROMISED);
    rd_ctx_free(&c);

    p = rd_provider_sim(rd_provider_fixture("fixtures/clean-macos"), "hide-pid-api:655");
    rd_ctx_init(&c, p, &o);
    rd_scan(&c);
    CHECK(nfind(&c, "proc-xview", RD_HIGH) == 1 && nfind(&c, "proc-xview", RD_CRITICAL) == 0); /* user-space class */
    rd_ctx_free(&c);

    /* a rootkit that lies in EVERY view including brute-force is invisible: the tool must not pretend otherwise */
    p = rd_provider_sim(rd_provider_fixture("fixtures/clean-macos"), "hide-pid-deep:655");
    rd_ctx_init(&c, p, &o);
    rd_scan(&c);
    CHECK(nfind(&c, "proc-xview", RD_INFO) == 0 && rd_verdict_compute(&c).id == RD_VERDICT_CLEAN);
    rd_ctx_free(&c);

    p = rd_provider_sim(rd_provider_fixture("fixtures/clean-macos"), "add-kext:com.evil.hook");
    rd_ctx_init(&c, p, &o);
    rd_scan(&c);
    CHECK(nfind(&c, "kext-inventory", RD_HIGH) == 1); /* loaded, not installed anywhere */
    rd_ctx_free(&c);

    rd_provider *inner = rd_provider_fixture("fixtures/clean-macos");
    CHECK(rd_provider_sim(inner, "hide-pid:") == NULL); /* typos fail loudly */
    CHECK(rd_provider_sim(inner, "explode:1") == NULL);
    inner->destroy(inner);
}

static void test_baseline(void) {
    rd_options o;
    memset(&o, 0, sizeof o);
    o.baseline = "fixtures/clean-linux";
    o.only = "baseline";
    rd_ctx c;
    rd_ctx_init(&c, rd_provider_fixture("fixtures/diamorphine-lkm"), &o);
    rd_scan(&c);
    CHECK(nfind(&c, "baseline", RD_CRITICAL) == 1); /* same kernel build, three handlers rewritten */
    CHECK(strstr(c.finds[0].detail, "__x64_sys_kill") != NULL);
    rd_ctx_free(&c);

    rd_ctx_init(&c, rd_provider_fixture("fixtures/clean-linux"), &o);
    rd_scan(&c);
    CHECK(nfind(&c, "baseline", RD_INFO) == 0 && state_of(&c, "baseline") == RD_RAN);
    rd_ctx_free(&c);

    o.baseline = NULL; /* no baseline given: n/a, and not counted against coverage */
    rd_ctx_init(&c, rd_provider_fixture("fixtures/clean-linux"), &o);
    rd_scan(&c);
    CHECK(state_of(&c, "baseline") == RD_NA && rd_verdict_compute(&c).skipped == 0);
    rd_ctx_free(&c);
}

static void test_json_report(void) {
    rd_options o;
    memset(&o, 0, sizeof o);
    rd_ctx c;
    rd_ctx_init(&c, rd_provider_fixture("fixtures/diamorphine-lkm"), &o);
    rd_scan(&c);
    char path[] = "/tmp/redoubt-json-XXXXXX";
    int fd = mkstemp(path);
    FILE *f = fdopen(fd, "w+");
    rd_report_json(&c, "test \"quoted\" source", f);
    fflush(f);
    rewind(f);
    char buf[1 << 16];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);
    unlink(path);
    CHECK(strstr(buf, "\"verdict\": \"COMPROMISED\"") && strstr(buf, "test \\\"quoted\\\" source"));
    CHECK(strstr(buf, "\"check\": \"syscall-table\"") && buf[0] == '{');
    rd_ctx_free(&c);
}

int main(void) {
    test_util();
    test_view();
    test_mod_xview();
    test_syscall_table();
    test_inline_hooks();
    test_ftrace();
    test_proc_xview();
    test_net_fs_preload();
    test_taint_iocs();
    test_verdict();
    test_false_positive_traps_are_real();
    test_snapshot_roundtrip();
    test_simulate();
    test_baseline();
    test_json_report();
    printf("unit tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
