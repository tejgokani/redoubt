/* SPDX-License-Identifier: MIT
 *
 * Live Linux provider.  Every view is collected through a path a rootkit would
 * have to hook separately; the checks compare them.
 *
 *   modules   /proc/modules | /sys/module | /proc/kallsyms | /proc/vmallocinfo | dmesg | modules.dep
 *   kernel    sys_call_table + function prologues read from /proc/kcore
 *   objects   readdir(3) | raw getdents64 | kill()/sched_getaffinity() brute force
 *   network   /proc/net/{tcp,udp}* | bind() on every port
 *   files     readdir link counts | stat() of known-bad paths
 */
#if defined(__linux__)

#include "../intel.h"
#include "../util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

typedef struct {
    uint64_t addr;
    char *name;
    char *mod; /* NULL = core kernel */
    char type;
} ksym_t;

typedef struct {
    rd_options opt;
    struct utsname un;
    int ks_state; /* 0 not loaded, 1 ok, -1 failed */
    char ks_why[160];
    ksym_t *ks;
    size_t nks, capks;
    int kc_state;
    char kc_why[160];
    int kc_fd;
    Elf64_Phdr *ph;
    size_t nph;
} lin_t;

/* ------------------------------------------------------------- helpers */

static int exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

static uint64_t read_u64_file(const char *path, uint64_t dflt) {
    char *b = NULL;
    if (rd_read_file(path, &b, NULL, 256) != 0) return dflt;
    uint64_t v = dflt;
    char *t = rd_trim(b);
    rd_parse_u64(t, &v);
    free(b);
    return v;
}

static int is_num(const char *s) {
    if (!*s) return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}

static int is_root(void) { return geteuid() == 0; }

/* ------------------------------------------------------------ kallsyms */

static int cmp_ks(const void *a, const void *b) {
    const ksym_t *x = a, *y = b;
    return x->addr < y->addr ? -1 : (x->addr > y->addr ? 1 : 0);
}

static int ks_load(lin_t *L) {
    if (L->ks_state) return L->ks_state;
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        snprintf(L->ks_why, sizeof L->ks_why, "cannot open /proc/kallsyms: %s", strerror(errno));
        return L->ks_state = -1;
    }
    char *line = NULL;
    size_t cap = 0, zero = 0;
    while (getline(&line, &cap, f) > 0) {
        char *end = NULL;
        uint64_t addr = strtoull(line, &end, 16);
        if (end == line) continue;
        char *p = end;
        while (*p == ' ') p++;
        char type = *p;
        if (!type || type == '\n') continue;
        p++;
        while (*p == ' ') p++;
        char *name = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        char *mod = NULL;
        if (*p) {
            *p++ = '\0';
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '[') {
                char *e = strchr(p, ']');
                if (e) {
                    *e = '\0';
                    mod = p + 1;
                }
            }
        }
        if (!*name) continue;
        if (addr == 0) zero++;
        if (L->nks == L->capks) {
            L->capks = L->capks ? L->capks * 2 : 65536;
            L->ks = rd_xrealloc(L->ks, L->capks * sizeof *L->ks);
        }
        ksym_t *s = &L->ks[L->nks++];
        s->addr = addr;
        s->type = type;
        s->name = rd_xstrdup(name);
        if (mod) {
            s->mod = rd_xstrdup(mod);
            rd_norm_modname(s->mod);
        } else {
            s->mod = NULL;
        }
    }
    free(line);
    fclose(f);
    if (L->nks == 0 || zero == L->nks) {
        snprintf(L->ks_why, sizeof L->ks_why, "kallsyms addresses are hidden (need root; kptr_restrict must be < 2)");
        return L->ks_state = -1;
    }
    qsort(L->ks, L->nks, sizeof *L->ks, cmp_ks);
    return L->ks_state = 1;
}

static const ksym_t *ks_find_core(lin_t *L, const char *name) {
    for (size_t i = 0; i < L->nks; i++)
        if (!L->ks[i].mod && strcmp(L->ks[i].name, name) == 0) return &L->ks[i];
    return NULL;
}

/* first symbol address strictly above `addr` (0 if none) */
static uint64_t ks_next(lin_t *L, uint64_t addr) {
    size_t lo = 0, hi = L->nks;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (L->ks[mid].addr <= addr) lo = mid + 1;
        else hi = mid;
    }
    return lo < L->nks ? L->ks[lo].addr : 0;
}

static void ks_name_of(lin_t *L, uint64_t addr, char *out, size_t sz) {
    size_t lo = 0, hi = L->nks;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (L->ks[mid].addr <= addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo && L->ks[lo - 1].addr == addr) snprintf(out, sz, "%s", L->ks[lo - 1].name);
    else snprintf(out, sz, "?");
}

static int lin_mod_kallsyms(lin_t *L, rd_view *out, char *why, size_t sz) {
    if (ks_load(L) < 0) {
        snprintf(why, sz, "%s", L->ks_why);
        return RD_UNAVAIL;
    }
    for (size_t i = 0; i < L->nks; i++) {
        const char *m = L->ks[i].mod;
        if (!m || rd_is_pseudo_module(m)) continue;
        if (!rd_view_find(out, m)) rd_view_add(out, m, 1, 0, "");
    }
    return RD_OK;
}

static int lin_ksyms(lin_t *L, rd_view *out, char *why, size_t sz) {
    if (ks_load(L) < 0) {
        snprintf(why, sz, "%s", L->ks_why);
        return RD_UNAVAIL;
    }
    for (size_t i = 0; i < L->nks; i++) {
        const ksym_t *s = &L->ks[i];
        int text = strchr("TtWw", s->type) != NULL;
        int special = !s->mod && (!strcmp(s->name, "_stext") || !strcmp(s->name, "_text") || !strcmp(s->name, "_etext"));
        if (!text && !special) continue;
        if (s->mod && rd_is_pseudo_module(s->mod)) continue;
        rd_view_add(out, s->name, s->addr, 0, s->mod ? s->mod : "");
    }
    return RD_OK;
}

/* --------------------------------------------------------------- kcore */

static int kc_open(lin_t *L) {
    if (L->kc_state) return L->kc_state;
    int fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(L->kc_why, sizeof L->kc_why, "cannot open /proc/kcore: %s (need root; may be locked down)", strerror(errno));
        return L->kc_state = -1;
    }
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_phnum == 0) {
        close(fd);
        snprintf(L->kc_why, sizeof L->kc_why, "/proc/kcore is not a 64-bit ELF core");
        return L->kc_state = -1;
    }
    size_t n = eh.e_phnum;
    L->ph = rd_xmalloc(n * sizeof *L->ph);
    if (pread(fd, L->ph, n * sizeof *L->ph, (off_t)eh.e_phoff) != (ssize_t)(n * sizeof *L->ph)) {
        free(L->ph);
        L->ph = NULL;
        close(fd);
        snprintf(L->kc_why, sizeof L->kc_why, "cannot read /proc/kcore program headers");
        return L->kc_state = -1;
    }
    L->nph = n;
    L->kc_fd = fd;
    return L->kc_state = 1;
}

static int kc_read(lin_t *L, uint64_t vaddr, void *buf, size_t len) {
    for (size_t i = 0; i < L->nph; i++) {
        const Elf64_Phdr *p = &L->ph[i];
        if (p->p_type != PT_LOAD) continue;
        if (vaddr >= p->p_vaddr && vaddr + len <= p->p_vaddr + p->p_filesz) {
            ssize_t r = pread(L->kc_fd, buf, len, (off_t)(p->p_offset + (vaddr - p->p_vaddr)));
            return r == (ssize_t)len ? 0 : -1;
        }
    }
    return -1;
}

static int lin_syscalls(lin_t *L, rd_view *out, char *why, size_t sz) {
    if (ks_load(L) < 0) {
        snprintf(why, sz, "%s", L->ks_why);
        return RD_UNAVAIL;
    }
    if (kc_open(L) < 0) {
        snprintf(why, sz, "%s", L->kc_why);
        return RD_UNAVAIL;
    }
    static const struct {
        const char *sym, *prefix;
    } TABLES[] = {{"sys_call_table", ""}, {"ia32_sys_call_table", "ia32:"}};
    int found = 0;
    for (size_t t = 0; t < sizeof TABLES / sizeof TABLES[0]; t++) {
        const ksym_t *s = ks_find_core(L, TABLES[t].sym);
        if (!s) continue;
        uint64_t next = ks_next(L, s->addr);
        size_t count = next > s->addr ? (size_t)((next - s->addr) / 8) : 512;
        if (count < 1) count = 1;
        if (count > 1024) count = 1024;
        uint64_t *tbl = rd_xmalloc(count * 8);
        if (kc_read(L, s->addr, tbl, count * 8) != 0) {
            free(tbl);
            snprintf(why, sz, "cannot read %s from /proc/kcore", TABLES[t].sym);
            return RD_UNAVAIL;
        }
        for (size_t i = 0; i < count; i++) {
            char nm[128];
            ks_name_of(L, tbl[i], nm, sizeof nm);
            rd_view_addf(out, tbl[i], 0, nm, "%s%zu", TABLES[t].prefix, i);
        }
        free(tbl);
        found = 1;
    }
    if (!found) {
        snprintf(why, sz, "no sys_call_table symbol in kallsyms");
        return RD_UNAVAIL;
    }
    return RD_OK;
}

static int lin_prologues(lin_t *L, rd_view *out, char *why, size_t sz) {
    if (strcmp(L->un.machine, "x86_64") != 0) {
        snprintf(why, sz, "prologue decoding is implemented for x86_64 only (this is %s)", L->un.machine);
        return RD_UNAVAIL;
    }
    if (ks_load(L) < 0) {
        snprintf(why, sz, "%s", L->ks_why);
        return RD_UNAVAIL;
    }
    if (kc_open(L) < 0) {
        snprintf(why, sz, "%s", L->kc_why);
        return RD_UNAVAIL;
    }
    for (const char *const *w = rd_watch_syms; *w; w++) {
        const ksym_t *s = ks_find_core(L, *w);
        if (!s || !strchr("Tt", s->type)) continue;
        uint8_t b[32];
        if (kc_read(L, s->addr, b, sizeof b) != 0) continue;
        char hex[sizeof b * 2 + 1];
        for (size_t i = 0; i < sizeof b; i++) snprintf(hex + i * 2, 3, "%02x", b[i]);
        rd_view_add(out, *w, s->addr, 0, hex);
    }
    return RD_OK;
}

/* ------------------------------------------------------------- modules */

static int lin_sysinfo(lin_t *L, rd_view *out) {
    rd_view_add(out, "os", 0, 0, "Linux");
    rd_view_add(out, "kernel", 0, 0, L->un.release);
    rd_view_add(out, "arch", 0, 0, L->un.machine);
    rd_view_add(out, "euid", (uint64_t)geteuid(), 0, "");
    rd_view_add(out, "pid_max", read_u64_file("/proc/sys/kernel/pid_max", 4194304), 0, "");
    rd_view_add(out, "kptr_restrict", read_u64_file("/proc/sys/kernel/kptr_restrict", 0), 0, "");
    rd_view_add(out, "taint", read_u64_file("/proc/sys/kernel/tainted", 0), 0, "");
    return 0;
}

static int lin_mod_api(rd_view *out) {
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return -1;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        char name[128], state[32];
        unsigned long long size = 0, addr = 0;
        char deps[512];
        int refs;
        if (sscanf(line, "%127s %llu %d %511s %31s %llx", name, &size, &refs, deps, state, &addr) >= 5) {
            rd_norm_modname(name);
            rd_view_add(out, name, size, addr, state);
        }
    }
    fclose(f);
    return 0;
}

static int lin_mod_sysfs(rd_view *out) {
    DIR *d = opendir("/sys/module");
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char p[512];
        snprintf(p, sizeof p, "/sys/module/%s/initstate", e->d_name);
        if (!exists(p)) continue; /* built-in modules have no initstate */
        snprintf(p, sizeof p, "/sys/module/%s/taint", e->d_name);
        char *t = NULL;
        char name[300];
        snprintf(name, sizeof name, "%s", e->d_name);
        rd_norm_modname(name);
        if (rd_read_file(p, &t, NULL, 64) == 0) {
            rd_view_add(out, name, 0, 0, rd_trim(t));
            free(t);
        } else {
            rd_view_add(out, name, 0, 0, "");
        }
    }
    closedir(d);
    return 0;
}

struct dep_ctx {
    rd_view *v;
};

static int dep_line(char *line, void *u) {
    struct dep_ctx *c = u;
    char *colon = strchr(line, ':');
    if (!colon) return 0;
    *colon = '\0';
    char *base = strrchr(line, '/');
    base = base ? base + 1 : line;
    char *dot = strstr(base, ".ko");
    if (dot) *dot = '\0';
    rd_norm_modname(base);
    if (*base) rd_view_add(c->v, base, 0, 0, line);
    return 0;
}

static int lin_mod_disk(lin_t *L, rd_view *out) {
    char p[512];
    struct dep_ctx c = {out};
    snprintf(p, sizeof p, "/lib/modules/%s/modules.dep", L->un.release);
    if (rd_foreach_line(p, dep_line, &c) != 0) {
        snprintf(p, sizeof p, "/usr/lib/modules/%s/modules.dep", L->un.release);
        if (rd_foreach_line(p, dep_line, &c) != 0) return -1;
    }
    rd_view_dedup(out);
    return 0;
}

static int lin_mod_mem(rd_view *out) {
    FILE *f = fopen("/proc/vmallocinfo", "r");
    if (!f) return -1;
    static const char *const CALLERS[] = {"move_module", "module_alloc", "load_module", "layout_and_allocate",
                                          "module_memory_alloc", NULL};
    char line[512];
    size_t zero = 0, seen = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long long lo = 0, hi = 0, size = 0;
        char caller[128] = "";
        if (sscanf(line, " 0x%llx-0x%llx %llu %127s", &lo, &hi, &size, caller) < 3) continue;
        seen++;
        if (lo == 0) zero++;
        int mod = 0;
        for (const char *const *c = CALLERS; *c; c++)
            if (strstr(caller, *c)) mod = 1;
        if (!mod) continue;
        rd_view_addf(out, lo, size, caller, "0x%llx", lo);
    }
    fclose(f);
    return (seen && zero == seen) ? -2 : 0;
}

static void dmesg_scan(char *buf, rd_view *out) {
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        char *p = ln;
        if (*p == '<') {
            char *g = strchr(p, '>');
            if (g) p = g + 1;
        }
        if (*p == '[') {
            char *g = strchr(p, ']');
            if (g) p = g + 1;
        }
        while (*p == ' ') p++;
        char *colon = strstr(p, ": ");
        if (!colon) continue;
        const char *msg = colon + 2;
        const char *kind = NULL;
        if (strstr(msg, "loading out-of-tree module taints kernel")) kind = "out-of-tree module taints kernel";
        else if (strstr(msg, "module verification failed")) kind = "module signature verification failed";
        else if (strstr(msg, "module license") && strstr(msg, "taints kernel")) kind = "module license taints kernel";
        if (!kind) continue;
        *colon = '\0';
        int ok = *p != '\0';
        for (char *q = p; *q; q++)
            if (!isalnum((unsigned char)*q) && *q != '_' && *q != '-' && *q != '.') ok = 0;
        if (!ok) continue;
        char name[128];
        snprintf(name, sizeof name, "%s", p);
        rd_norm_modname(name);
        if (!rd_view_find(out, name)) rd_view_add(out, name, 0, 0, kind);
    }
}

static int lin_dmesg(rd_view *out) {
    int sz = klogctl(10, NULL, 0);
    if (sz <= 0) sz = 1 << 20;
    char *buf = rd_xmalloc((size_t)sz + 1);
    int n = klogctl(3, buf, sz);
    if (n < 0) {
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    dmesg_scan(buf, out);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------ ftrace */

static int lin_ftrace(rd_view *out) {
    static const char *const P[] = {"/sys/kernel/tracing/enabled_functions",
                                    "/sys/kernel/debug/tracing/enabled_functions", NULL};
    FILE *f = NULL;
    for (const char *const *p = P; *p && !f; p++) f = fopen(*p, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) > 0) {
        char *ln = rd_trim(line);
        char *paren = strstr(ln, " (");
        while (paren && !isdigit((unsigned char)paren[2])) paren = strstr(paren + 1, " (");
        if (!paren) continue;
        *paren = '\0';
        char *name = ln;
        char *sp = strchr(name, ' ');
        if (sp) *sp = '\0';
        if (*name) rd_view_add(out, name, 1, 0, paren + 1);
    }
    free(line);
    fclose(f);
    return 0;
}

/* --------------------------------------------------------- processes */

struct lin_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/* Enumerate a directory with the raw syscall, bypassing libc's readdir(). */
static int raw_ls(const char *path, void (*cb)(const char *name, void *u), void *u) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[8192] __attribute__((aligned(8)));
    long n;
    while ((n = syscall(SYS_getdents64, fd, buf, sizeof buf)) > 0) {
        for (long off = 0; off < n;) {
            struct lin_dirent64 *e = (struct lin_dirent64 *)(buf + off);
            cb(e->d_name, u);
            off += e->d_reclen;
        }
    }
    close(fd);
    return n < 0 ? -1 : 0;
}

static void cb_pid(const char *name, void *u) {
    if (is_num(name)) rd_view_add(u, name, 0, 0, "");
}

static int lin_proc_raw(rd_view *out) {
    rd_view top;
    rd_view_init(&top);
    if (raw_ls("/proc", cb_pid, &top) != 0) {
        rd_view_free(&top);
        return -1;
    }
    for (size_t i = 0; i < top.n; i++) {
        rd_view_add(out, top.items[i].key, 0, 0, "");
        char p[512];
        snprintf(p, sizeof p, "/proc/%s/task", top.items[i].key);
        raw_ls(p, cb_pid, out);
    }
    rd_view_free(&top);
    rd_view_dedup(out);
    return 0;
}

static int lin_proc_api(rd_view *out) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!is_num(e->d_name)) continue;
        rd_view_add(out, e->d_name, 0, 0, "");
        char p[512];
        snprintf(p, sizeof p, "/proc/%s/task", e->d_name);
        DIR *t = opendir(p);
        if (!t) continue;
        struct dirent *te;
        while ((te = readdir(t)))
            if (is_num(te->d_name)) rd_view_add(out, te->d_name, 0, 0, "");
        closedir(t);
    }
    closedir(d);
    rd_view_dedup(out);
    return 0;
}

static int hidepid_active(void) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    char line[1024];
    int act = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, " /proc proc ")) continue;
        const char *h = strstr(line, "hidepid=");
        if (h) {
            h += 8;
            if (!(h[0] == '0' || strncmp(h, "off", 3) == 0)) act = 1;
        }
    }
    fclose(f);
    return act;
}

static int pid_alive(pid_t pid) {
    if (kill(pid, 0) == 0 || errno == EPERM) return 1;
    unsigned char aff[8192];
    long r = syscall(SYS_sched_getaffinity, pid, sizeof aff, aff);
    return r >= 0 || errno == EPERM;
}

static int lin_proc_brute(lin_t *L, rd_view *out, char *why, size_t sz) {
    if (!is_root() && hidepid_active()) {
        snprintf(why, sz, "/proc is mounted with hidepid: a non-root listing is restricted by design (run as root)");
        return RD_UNAVAIL;
    }
    uint64_t maxp = read_u64_file("/proc/sys/kernel/pid_max", 4194304);
    if (L->opt.fast) {
        char *la = NULL;
        if (rd_read_file("/proc/loadavg", &la, NULL, 256) == 0) {
            /* 5th field is "running/total lastpid": probing far past lastpid only matters after pid wrap-around */
            unsigned total;
            unsigned long long lastpid = 0;
            char *slash = strchr(la, '/');
            if (slash && sscanf(slash, "/%u %llu", &total, &lastpid) == 2 && lastpid + 16384 < maxp)
                maxp = lastpid + 16384;
            free(la);
        }
    }
    for (uint64_t pid = 1; pid <= maxp; pid++) {
        if (!pid_alive((pid_t)pid)) continue;
        char key[24], p[64], comm[64] = "";
        snprintf(key, sizeof key, "%llu", (unsigned long long)pid);
        snprintf(p, sizeof p, "/proc/%llu/comm", (unsigned long long)pid);
        FILE *f = fopen(p, "r");
        if (f) {
            if (fgets(comm, sizeof comm, f)) rd_trim(comm);
            fclose(f);
        }
        rd_view_add(out, key, 0, 0, rd_trim(comm));
    }
    return RD_OK;
}

/* ------------------------------------------------------------- network */

static int lin_net_listed(rd_view *out) {
    static const struct {
        const char *path, *proto;
    } F[] = {{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"}};
    int any = 0;
    for (size_t i = 0; i < sizeof F / sizeof F[0]; i++) {
        FILE *f = fopen(F[i].path, "r");
        if (!f) continue;
        any = 1;
        char line[512];
        if (!fgets(line, sizeof line, f)) {
            fclose(f);
            continue;
        }
        while (fgets(line, sizeof line, f)) {
            int sl;
            char la[80];
            if (sscanf(line, " %d: %79s", &sl, la) != 2) continue;
            char *c = strrchr(la, ':');
            if (!c) continue;
            unsigned long port = strtoul(c + 1, NULL, 16);
            rd_view_addf(out, port, 0, "", "%s:%lu", F[i].proto, port);
        }
        fclose(f);
    }
    if (!any) return -1;
    rd_view_dedup(out);
    return 0;
}

/* 1 if bind() on the wildcard address fails with EADDRINUSE (IPv4 or IPv6) */
static int port_in_use(int type, unsigned port) {
    int r = 0;
    int s = socket(AF_INET, type, 0);
    if (s >= 0) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 && errno == EADDRINUSE) r = 1;
        close(s);
    }
    if (r) return 1;
    s = socket(AF_INET6, type, 0);
    if (s >= 0) {
        int one = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_port = htons((uint16_t)port);
        if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 && errno == EADDRINUSE) r = 1;
        close(s);
    }
    return r;
}

static int lin_net_bound(rd_view *out) {
    for (unsigned port = is_root() ? 1 : 1024; port <= 65535; port++) {
        if (port_in_use(SOCK_STREAM, port)) rd_view_addf(out, port, 0, "", "tcp:%u", port);
        if (port_in_use(SOCK_DGRAM, port)) rd_view_addf(out, port, 0, "", "udp:%u", port);
    }
    return 0;
}

/* --------------------------------------------------------------- files */

static int fs_supported(const struct statfs *sf) {
    /* ext2/3/4, tmpfs, xfs: st_nlink of a directory == 2 + number of sub-directories */
    return sf->f_type == 0xEF53 || sf->f_type == 0x01021994 || sf->f_type == 0x58465342;
}

static void dir_entry(rd_view *out, const char *path) {
    struct stat st;
    struct statfs sf;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode) || statfs(path, &sf) != 0) return;
    DIR *d = opendir(path);
    if (!d) return;
    uint64_t sub = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (e->d_type == DT_DIR) sub++;
        else if (e->d_type == DT_UNKNOWN) {
            struct stat s2;
            if (fstatat(dirfd(d), e->d_name, &s2, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(s2.st_mode)) sub++;
        }
    }
    closedir(d);
    rd_view_add(out, path, (uint64_t)st.st_nlink, sub, fs_supported(&sf) ? "fs=ok" : "fs=unsupported");
}

static int lin_dirs(rd_view *out) {
    static const char *const ROOTS[] = {"/", "/tmp", "/var/tmp", "/dev", "/dev/shm", "/etc", "/usr", "/usr/bin",
                                        "/usr/sbin", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/local/lib",
                                        "/lib/modules", "/boot", "/root", "/home", "/opt", "/var", "/var/lib",
                                        "/var/log", "/run", "/srv", "/mnt", "/media", NULL};
    static const char *const DEEP[] = {"/", "/tmp", "/var/tmp", "/dev/shm", "/home", NULL};
    for (const char *const *r = ROOTS; *r; r++) dir_entry(out, *r);
    for (const char *const *r = DEEP; *r; r++) {
        DIR *d = opendir(*r);
        if (!d) continue;
        struct dirent *e;
        int n = 0;
        while ((e = readdir(d)) && n < 64) {
            if (e->d_type != DT_DIR || e->d_name[0] == '.') continue;
            if (!strcmp(*r, "/") && (!strcmp(e->d_name, "proc") || !strcmp(e->d_name, "sys") || !strcmp(e->d_name, "dev") ||
                                     !strcmp(e->d_name, "run")))
                continue;
            char p[1024];
            snprintf(p, sizeof p, "%s%s%s", *r, strcmp(*r, "/") ? "/" : "", e->d_name);
            dir_entry(out, p);
            n++;
        }
        closedir(d);
    }
    rd_view_dedup(out);
    return 0;
}

static int listed_in_parent(const char *path) {
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash) return 0;
    const char *base = slash + 1;
    if (slash == dir) dir[1] = '\0';
    else *slash = '\0';
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, base) == 0) found = 1;
    closedir(d);
    return found;
}

static int lin_probes(rd_view *out) {
    for (const rd_ioc_file *f = rd_ioc_files; f->path; f++) {
        struct stat st;
        int ok = lstat(f->path, &st) == 0;
        int listed = listed_in_parent(f->path);
        if (ok || listed) rd_view_add(out, f->path, (uint64_t)ok, (uint64_t)listed, f->family);
    }
    return 0;
}

/* ------------------------------------------------------------- posture */

static int lin_preload(rd_view *out) {
    char *b = NULL;
    if (rd_read_file("/etc/ld.so.preload", &b, NULL, 1 << 16) == 0) {
        char *save = NULL;
        for (char *ln = strtok_r(b, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
            char *h = strchr(ln, '#');
            if (h) *h = '\0';
            char *t = rd_trim(ln);
            if (*t) rd_view_add(out, "ld.so.preload", 0, 0, t);
        }
        free(b);
    }
    const char *e = getenv("LD_PRELOAD");
    if (e && *e) rd_view_add(out, "env:self", 0, 0, e);
    if (rd_read_file("/proc/1/environ", &b, NULL, 1 << 16) == 0) {
        for (const char *p = b; *p;) {
            if (strncmp(p, "LD_PRELOAD=", 11) == 0 && p[11]) rd_view_add(out, "env:init", 0, 0, p + 11);
            p += strlen(p) + 1;
        }
        free(b);
    }
    return 0;
}

static void hv(rd_view *out, const char *key, const char *path) {
    char *b = NULL;
    if (rd_read_file(path, &b, NULL, 256) != 0) return;
    char *t = rd_trim(b);
    uint64_t v = 0;
    rd_parse_u64(t, &v);
    rd_view_add(out, key, v, 1, t);
    free(b);
}

static int lin_hardening(rd_view *out) {
    hv(out, "modules_disabled", "/proc/sys/kernel/modules_disabled");
    hv(out, "kptr_restrict", "/proc/sys/kernel/kptr_restrict");
    hv(out, "dmesg_restrict", "/proc/sys/kernel/dmesg_restrict");
    hv(out, "kexec_load_disabled", "/proc/sys/kernel/kexec_load_disabled");
    hv(out, "unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled");
    char *b = NULL;
    if (rd_read_file("/sys/module/module/parameters/sig_enforce", &b, NULL, 16) == 0) {
        rd_view_add(out, "sig_enforce", 0, 1, rd_trim(b));
        free(b);
    } else {
        rd_view_add(out, "sig_enforce", 0, 0, "absent");
    }
    if (rd_read_file("/sys/kernel/security/lockdown", &b, NULL, 128) == 0) {
        char *t = rd_trim(b), *l = strchr(t, '['), *r = l ? strchr(l, ']') : NULL;
        if (l && r) {
            *r = '\0';
            rd_view_add(out, "lockdown", 0, 1, l + 1);
        }
        free(b);
    }
    rd_view_add(out, "dev_kmem", exists("/dev/kmem"), 1, "");
    return 0;
}

/* ------------------------------------------------------------ provider */

static int lin_collect(rd_provider *p, rd_view_id id, rd_view *out, char *why, size_t whysz) {
    lin_t *L = p->priv;
    int rc = 0;
    switch (id) {
    case RDV_SYSINFO: rc = lin_sysinfo(L, out); break;
    case RDV_MOD_API: rc = lin_mod_api(out); break;
    case RDV_MOD_SYSFS: rc = lin_mod_sysfs(out); break;
    case RDV_MOD_KALLSYMS: return lin_mod_kallsyms(L, out, why, whysz);
    case RDV_MOD_DISK: rc = lin_mod_disk(L, out); break;
    case RDV_MOD_MEM:
        rc = lin_mod_mem(out);
        if (rc == -2) {
            snprintf(why, whysz, "vmallocinfo addresses are zeroed (need root; kptr_restrict)");
            return RD_UNAVAIL;
        }
        break;
    case RDV_DMESG_MODS: rc = lin_dmesg(out); break;
    case RDV_KSYMS: return lin_ksyms(L, out, why, whysz);
    case RDV_SYSCALLS: return lin_syscalls(L, out, why, whysz);
    case RDV_FTRACE: rc = lin_ftrace(out); break;
    case RDV_PROLOGUES: return lin_prologues(L, out, why, whysz);
    case RDV_PROC_API: rc = lin_proc_api(out); break;
    case RDV_PROC_RAW: rc = lin_proc_raw(out); break;
    case RDV_PROC_BRUTE: return lin_proc_brute(L, out, why, whysz);
    case RDV_NET_LISTED: rc = lin_net_listed(out); break;
    case RDV_NET_BOUND: rc = lin_net_bound(out); break;
    case RDV_DIRS: rc = lin_dirs(out); break;
    case RDV_FILE_PROBES: rc = lin_probes(out); break;
    case RDV_PRELOAD: rc = lin_preload(out); break;
    case RDV_HARDENING: rc = lin_hardening(out); break;
    default:
        snprintf(why, whysz, "not applicable on Linux");
        return RD_UNAVAIL;
    }
    if (rc != 0) {
        const char *hint = "";
        if (id == RDV_DMESG_MODS || id == RDV_FTRACE || id == RDV_MOD_MEM) hint = " (needs root; tracefs/dmesg may be restricted)";
        snprintf(why, whysz, "cannot read %s: %s%s", rd_view_name(id), strerror(errno), hint);
        return RD_UNAVAIL;
    }
    return RD_OK;
}

static int lin_probe(rd_provider *p, rd_view_id id, const char *key) {
    (void)p;
    if (id == RDV_PROC_BRUTE) {
        long pid = strtol(key, NULL, 10);
        return pid > 0 ? pid_alive((pid_t)pid) : -1;
    }
    if (id == RDV_NET_BOUND) {
        char proto[8];
        unsigned port;
        if (sscanf(key, "%7[a-z]:%u", proto, &port) != 2) return -1;
        return port_in_use(strcmp(proto, "udp") == 0 ? SOCK_DGRAM : SOCK_STREAM, port);
    }
    return -1;
}

static void lin_destroy(rd_provider *p) {
    lin_t *L = p->priv;
    for (size_t i = 0; i < L->nks; i++) {
        free(L->ks[i].name);
        free(L->ks[i].mod);
    }
    free(L->ks);
    free(L->ph);
    if (L->kc_fd > 0) close(L->kc_fd);
    free(L);
    free(p);
}

rd_provider *rd_provider_live(const rd_options *opt) {
    rd_provider *p = rd_xmalloc(sizeof *p);
    lin_t *L = rd_xmalloc(sizeof *L);
    memset(L, 0, sizeof *L);
    L->opt = *opt;
    uname(&L->un);
    p->name = "live";
    p->priv = L;
    p->collect = lin_collect;
    p->probe = lin_probe;
    p->destroy = lin_destroy;
    return p;
}

#endif /* __linux__ */
