/* SPDX-License-Identifier: MIT
 *
 * Checks that catch a kernel module *hooking* the kernel.
 *
 * Whatever mechanism a rootkit uses to intercept getdents/kill/read, it has to
 * leave control flow pointing into memory that is not core kernel text.  We
 * read the raw kernel structures (via /proc/kcore, the ftrace registry) and
 * ask one question: does this pointer land where the kernel image says it
 * should?
 */
#include "../checks.h"
#include "../intel.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------- symbol table */

static int cmp_ksym(const void *x, const void *y) {
    const rd_ksym *a = x, *b = y;
    if (a->addr != b->addr) return a->addr < b->addr ? -1 : 1;
    return strcmp(a->name, b->name);
}

void rd_ksymtab_build(rd_view *ks, rd_ksymtab *t) {
    memset(t, 0, sizeof *t);
    t->s = rd_xmalloc((ks->n + 1) * sizeof *t->s);
    uint64_t stext = 0, text = 0, etext = 0;
    for (size_t i = 0; i < ks->n; i++) {
        const rd_item *it = &ks->items[i];
        t->s[i].addr = it->a;
        t->s[i].name = it->key;
        t->s[i].mod = it->extra;
        if (strcmp(it->key, "_stext") == 0) stext = it->a;
        else if (strcmp(it->key, "_text") == 0) text = it->a;
        else if (strcmp(it->key, "_etext") == 0) etext = it->a;
        if (!it->extra[0] && (rd_starts_with(it->key, "__x64_sys_") || rd_starts_with(it->key, "__arm64_sys_") ||
                              rd_starts_with(it->key, "sys_") || rd_starts_with(it->key, "SyS_")))
            t->have_sysnames = 1;
    }
    t->n = ks->n;
    if (t->n > 1) qsort(t->s, t->n, sizeof *t->s, cmp_ksym);
    t->text_lo = stext ? stext : text;
    t->text_hi = etext;
    t->have_text = t->text_lo && t->text_hi > t->text_lo;
}

void rd_ksymtab_free(rd_ksymtab *t) {
    free(t->s);
    memset(t, 0, sizeof *t);
}

const rd_ksym *rd_ksymtab_lookup(const rd_ksymtab *t, uint64_t addr) {
    size_t lo = 0, hi = t->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (t->s[mid].addr <= addr) lo = mid + 1;
        else hi = mid;
    }
    return lo ? &t->s[lo - 1] : NULL;
}

void rd_ksymtab_describe(const rd_ksymtab *t, uint64_t addr, char *buf, size_t sz) {
    const rd_ksym *s = rd_ksymtab_lookup(t, addr);
    if (s && s->mod[0] && addr - s->addr < 0x100000)
        snprintf(buf, sz, "module '%s' (%s+0x%llx)", s->mod, s->name, (unsigned long long)(addr - s->addr));
    else if (s && t->have_text && addr >= t->text_lo && addr < t->text_hi)
        snprintf(buf, sz, "%s+0x%llx", s->name, (unsigned long long)(addr - s->addr));
    else
        snprintf(buf, sz, "unresolved kernel memory - no symbol: an unlisted/hidden module");
}

static int syscall_like(const char *n) {
    static const char *const pre[] = {"__x64_sys_", "__ia32_sys_", "__ia32_compat_sys_", "__x32_compat_sys_",
                                      "__arm64_sys_", "__arm64_compat_sys_", "__se_sys_", "__do_sys_",
                                      "sys_", "SyS_", "compat_sys_", "ksys_", NULL};
    for (const char *const *p = pre; *p; p++)
        if (rd_starts_with(n, *p)) return 1;
    return strstr(n, "ni_syscall") != NULL;
}

/* any symbol at exactly `addr` that looks like a syscall entry point? returns
 * 1 yes, 0 symbols exist but none look right, -1 no symbol starts at addr */
static int exact_alias_syscall_like(const rd_ksymtab *t, uint64_t addr) {
    const rd_ksym *s = rd_ksymtab_lookup(t, addr);
    if (!s || s->addr != addr) return -1;
    for (size_t i = (size_t)(s - t->s) + 1; i-- > 0;) {
        if (t->s[i].addr != addr) break;
        if (syscall_like(t->s[i].name)) return 1;
    }
    return 0;
}

/* --------------------------------------------------------- syscall-table */

static const char *x64_syscall_name(long nr) {
    static const struct {
        long nr;
        const char *name;
    } T[] = {{0, "read"},       {1, "write"},       {2, "open"},          {3, "close"},        {4, "stat"},
             {5, "fstat"},      {6, "lstat"},       {39, "getpid"},       {56, "clone"},       {57, "fork"},
             {59, "execve"},    {62, "kill"},       {78, "getdents"},     {89, "readlink"},    {105, "setuid"},
             {175, "init_module"}, {176, "delete_module"}, {217, "getdents64"}, {257, "openat"},
             {262, "newfstatat"}, {313, "finit_module"}};
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++)
        if (T[i].nr == nr) return T[i].name;
    return NULL;
}

static int run_syscall(rd_ctx *c) {
    NEED(c, RDV_SYSCALLS, sc);
    NEED(c, RDV_KSYMS, ks);
    if (sc->n == 0) return rd_skip(c, "syscall table is empty");

    int x64 = 0;
    rd_view *si = NULL;
    if (rd_get_view(c, RDV_SYSINFO, &si) == RD_OK) {
        const rd_item *ar = rd_view_find(si, "arch");
        x64 = ar && strcmp(ar->extra, "x86_64") == 0;
    }

    rd_ksymtab t;
    rd_ksymtab_build(ks, &t);
    if (!t.have_text) {
        rd_ksymtab_free(&t);
        return rd_skip(c, "kernel text bounds (_stext/_etext) missing from the symbol table");
    }

    rd_sb hooked = {0}, odd = {0};
    size_t nh = 0, no = 0;
    for (size_t i = 0; i < sc->n; i++) {
        uint64_t tgt = sc->items[i].a;
        if (!tgt) continue;
        char *end = NULL;
        long nr = strtol(sc->items[i].key, &end, 10);
        const char *nm = (x64 && end && !*end) ? x64_syscall_name(nr) : NULL;
        char who[64];
        if (nm) snprintf(who, sizeof who, "#%s %s", sc->items[i].key, nm);
        else snprintf(who, sizeof who, "#%s", sc->items[i].key);

        if (tgt < t.text_lo || tgt >= t.text_hi) {
            char d[160];
            rd_ksymtab_describe(&t, tgt, d, sizeof d);
            if (++nh <= 12) rd_sb_addf(&hooked, "  %-18s -> 0x%llx  %s\n", who, (unsigned long long)tgt, d);
        } else if (t.have_sysnames) {
            int r = exact_alias_syscall_like(&t, tgt);
            if (r != 1) {
                char d[160];
                rd_ksymtab_describe(&t, tgt, d, sizeof d);
                if (++no <= 8)
                    rd_sb_addf(&odd, "  %-18s -> 0x%llx  %s%s\n", who, (unsigned long long)tgt, d,
                               r < 0 ? "  (mid-function)" : "");
            }
        }
    }

    if (nh) {
        char title[200];
        snprintf(title, sizeof title, "%zu syscall-table entr%s redirected outside kernel text", nh, nh == 1 ? "y" : "ies");
        char *lines = rd_sb_take(&hooked);
        rd_finding *f = rd_add(c, RD_CRITICAL, 96, title,
                               "%skernel text is [0x%llx, 0x%llx). Entries pointing elsewhere were overwritten:\n"
                               "the kernel will run that code instead of the real syscall.",
                               lines, (unsigned long long)t.text_lo, (unsigned long long)t.text_hi);
        free(lines);
        f->mitre = MITRE_ROOTKIT;
        f->fix = "This is direct evidence of kernel-level tampering. Isolate the host, capture memory, rebuild.";
    } else {
        rd_sb_free(&hooked);
    }
    if (no) {
        char title[200];
        snprintf(title, sizeof title, "%zu syscall-table entr%s point at a non-syscall function", no, no == 1 ? "y" : "ies");
        char *lines = rd_sb_take(&odd);
        rd_finding *f = rd_add(c, RD_MEDIUM, 60, title,
                               "%sInside kernel text, but not at a *_sys_* entry point - possible redirect to\n"
                               "another core function (or an unusual kernel build).",
                               lines);
        free(lines);
        f->mitre = MITRE_ROOTKIT;
        f->fix = "Compare with `System.map` for this exact kernel package.";
    } else {
        rd_sb_free(&odd);
    }
    rd_ksymtab_free(&t);
    return 0;
}

const rd_check rd_chk_syscall_table = {
    "syscall-table", "Syscall table integrity", "sys_call_table read from /proc/kcore",
    RD_PLAT_LINUX, run_syscall,
};

/* --------------------------------------------------------- ftrace-hooks */

static int is_raw_addr(const char *t) {
    if (t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) t += 2;
    size_t n = 0;
    while (isxdigit((unsigned char)t[n])) n++;
    return n >= 12 && t[n] == '\0';
}

static int run_ftrace(rd_ctx *c) {
    NEED(c, RDV_FTRACE, ft);
    rd_view *api = NULL, *sys = NULL;
    int have_api = rd_get_view(c, RDV_MOD_API, &api) == RD_OK;
    int have_sys = rd_get_view(c, RDV_MOD_SYSFS, &sys) == RD_OK;

    rd_ksymtab t;
    memset(&t, 0, sizeof t);
    rd_view *ks = NULL;
    int have_t = rd_get_view(c, RDV_KSYMS, &ks) == RD_OK;
    if (have_t) rd_ksymtab_build(ks, &t);

    rd_sb hidden = {0}, sens = {0};
    size_t nhid = 0, nsens = 0;

    for (size_t i = 0; i < ft->n; i++) {
        const char *fn = ft->items[i].key;
        char *line = rd_xstrdup(ft->items[i].extra);
        for (char *p = line; *p; p++)
            if (*p == '(' || *p == ')' || *p == ',') *p = ' ';

        int ipmodify = 0;
        char cb_mod[96] = "";
        char cb_sym[96] = "";
        uint64_t raw = 0;
        int have_raw = 0;
        char *save = NULL;
        for (char *tok = strtok_r(line, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
            size_t l = strlen(tok);
            if (l == 1 && strchr("RIDLMO", tok[0])) {
                if (tok[0] == 'I') ipmodify = 1;
            } else if (tok[0] == '[' && tok[l - 1] == ']') {
                snprintf(cb_mod, sizeof cb_mod, "%.*s", (int)(l - 2), tok + 1);
                rd_norm_modname(cb_mod);
            } else if (is_raw_addr(tok)) {
                char tmp[48];
                int has_prefix = tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X');
                snprintf(tmp, sizeof tmp, "%s%s", has_prefix ? "" : "0x", tok);
                have_raw = rd_parse_u64(tmp, &raw) == 0;
            } else if (strchr(tok, '+')) {
                snprintf(cb_sym, sizeof cb_sym, "%.*s", (int)strcspn(tok, "+"), tok);
            }
        }
        free(line);

        int module_hidden = 0;
        if (cb_mod[0] && (have_api || have_sys)) {
            int vis = (have_api && rd_view_find(api, cb_mod)) || (have_sys && rd_view_find(sys, cb_mod));
            module_hidden = !vis;
        }
        int raw_outside = 0;
        if (have_raw && have_t && t.have_text) raw_outside = raw < t.text_lo || raw >= t.text_hi;

        if (module_hidden || raw_outside) {
            if (++nhid <= 8) {
                if (module_hidden)
                    rd_sb_addf(&hidden, "  %-28s callback %s [%s]  <- module not in any module list\n", fn,
                               cb_sym[0] ? cb_sym : "?", cb_mod);
                else
                    rd_sb_addf(&hidden, "  %-28s callback at unresolved 0x%llx\n", fn, (unsigned long long)raw);
            }
        } else if (cb_mod[0] && ipmodify && rd_is_sensitive_fn(fn)) {
            if (++nsens <= 8)
                rd_sb_addf(&sens, "  %-28s IPMODIFY callback %s [%s]\n", fn, cb_sym[0] ? cb_sym : "?", cb_mod);
        }
    }

    if (nhid) {
        char title[200];
        snprintf(title, sizeof title, "%zu ftrace hook%s owned by hidden kernel code", nhid, nhid == 1 ? "" : "s");
        char *lines = rd_sb_take(&hidden);
        rd_finding *f = rd_add(c, RD_CRITICAL, 92, title,
                               "%sftrace lets a module redirect any kernel function (the modern replacement for\n"
                               "syscall-table patching). These callbacks live in code that no module list admits to.",
                               lines);
        free(lines);
        f->mitre = MITRE_ROOTKIT;
        f->fix = "Direct evidence of a hiding module. Isolate, capture memory, rebuild from trusted media.";
    } else {
        rd_sb_free(&hidden);
    }
    if (nsens) {
        char title[200];
        snprintf(title, sizeof title, "%zu security-relevant function%s hooked by a module via ftrace", nsens,
                 nsens == 1 ? "" : "s");
        char *lines = rd_sb_take(&sens);
        rd_finding *f = rd_add(c, RD_MEDIUM, 60, title,
                               "%sA *listed* module that rewrites the instruction pointer of a directory-listing /\n"
                               "process / network function. Legitimate for livepatch or security agents; suspicious "
                               "otherwise.",
                               lines);
        free(lines);
        f->mitre = MITRE_ROOTKIT;
        f->fix = "Identify the module's vendor. Unknown vendor + hooks getdents/kill/tcp_seq_show = rootkit.";
    } else {
        rd_sb_free(&sens);
    }
    if (have_t) rd_ksymtab_free(&t);
    return 0;
}

const rd_check rd_chk_ftrace_hooks = {
    "ftrace-hooks", "ftrace hook ownership", "who owns each ftrace callback",
    RD_PLAT_LINUX, run_ftrace,
};

/* --------------------------------------------------------- inline-hooks */

static int unhex(const char *hex, uint8_t *out, size_t max) {
    size_t n = 0;
    int hi = -1;
    for (; *hex && n < max; hex++) {
        int v;
        if (*hex >= '0' && *hex <= '9') v = *hex - '0';
        else if (*hex >= 'a' && *hex <= 'f') v = *hex - 'a' + 10;
        else if (*hex >= 'A' && *hex <= 'F') v = *hex - 'A' + 10;
        else continue;
        if (hi < 0) hi = v;
        else {
            out[n++] = (uint8_t)(hi << 4 | v);
            hi = -1;
        }
    }
    return (int)n;
}

/* Recognise the jump stubs inline-hooking engines write over a function's
 * first bytes (x86-64).  Returns 1 with *target set, 2 for an indirect jump
 * whose target we cannot know, 0 if the prologue looks normal. */
static int decode_jump(const uint8_t *b, size_t n, uint64_t addr, uint64_t *target, const char **kind) {
    size_t offs[2] = {0, 0};
    int no = 1;
    if (n >= 4 && b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && b[3] == 0xfa) offs[no++] = 4; /* endbr64 */
    for (int k = 0; k < no; k++) {
        size_t o = offs[k];
        if (n >= o + 5 && b[o] == 0xe9) {
            int32_t rel;
            memcpy(&rel, b + o + 1, 4);
            *target = addr + o + 5 + (uint64_t)(int64_t)rel;
            *kind = "jmp rel32";
            return 1;
        }
        if (n >= o + 6 && b[o] == 0xff && b[o + 1] == 0x25) {
            *target = 0;
            *kind = "jmp [rip+disp]";
            return 2;
        }
        if (n >= o + 12 && b[o] == 0x48 && b[o + 1] == 0xb8 && b[o + 10] == 0xff && b[o + 11] == 0xe0) {
            memcpy(target, b + o + 2, 8);
            *kind = "movabs rax,imm64; jmp rax";
            return 1;
        }
        if (n >= o + 13 && b[o] == 0x49 && b[o + 1] == 0xbb && b[o + 10] == 0x41 && b[o + 11] == 0xff &&
            b[o + 12] == 0xe3) {
            memcpy(target, b + o + 2, 8);
            *kind = "movabs r11,imm64; jmp r11";
            return 1;
        }
        if (n >= o + 6 && b[o] == 0x68 && b[o + 5] == 0xc3) {
            int32_t imm;
            memcpy(&imm, b + o + 1, 4);
            *target = (uint64_t)(int64_t)imm;
            *kind = "push imm32; ret";
            return 1;
        }
    }
    return 0;
}

static int run_inline(rd_ctx *c) {
    NEED(c, RDV_PROLOGUES, pr);
    NEED(c, RDV_KSYMS, ks);
    rd_ksymtab t;
    rd_ksymtab_build(ks, &t);
    if (!t.have_text) {
        rd_ksymtab_free(&t);
        return rd_skip(c, "kernel text bounds missing from the symbol table");
    }

    rd_sb sb = {0};
    size_t nh = 0, nind = 0;
    int strong = 0;
    for (size_t i = 0; i < pr->n; i++) {
        uint8_t b[32];
        int n = unhex(pr->items[i].extra, b, sizeof b);
        uint64_t target = 0;
        const char *kind = "";
        int r = decode_jump(b, (size_t)n, pr->items[i].a, &target, &kind);
        if (r == 1 && (target < t.text_lo || target >= t.text_hi)) {
            char d[160];
            rd_ksymtab_describe(&t, target, d, sizeof d);
            if (++nh <= 10)
                rd_sb_addf(&sb, "  %-24s %-26s -> 0x%llx  %s\n", pr->items[i].key, kind, (unsigned long long)target, d);
            strong = 1;
        } else if (r == 2) {
            if (++nh <= 10) rd_sb_addf(&sb, "  %-24s %-26s -> (indirect)\n", pr->items[i].key, kind);
            nind++;
        }
    }
    if (nh) {
        char title[200];
        snprintf(title, sizeof title, "%zu kernel function%s start with a hook jump", nh, nh == 1 ? "" : "s");
        char *lines = rd_sb_take(&sb);
        rd_finding *f = rd_add(c, RD_HIGH, strong ? 92 : 70, title,
                               "%sA compiled kernel function begins with `endbr64`/`call __fentry__`/nop. A jump in\n"
                               "the first bytes that leaves kernel text is an inline hook (Suterusu / khook style).",
                               lines);
        free(lines);
        f->mitre = MITRE_ROOTKIT;
        f->fix = "Direct evidence of kernel-level tampering. Isolate, capture memory, rebuild.";
    } else {
        rd_sb_free(&sb);
    }
    (void)nind;
    rd_ksymtab_free(&t);
    return 0;
}

const rd_check rd_chk_inline_hooks = {
    "inline-hooks", "Inline kernel-function hooks", "prologues of getdents/filldir/tcp4_seq_show/...",
    RD_PLAT_LINUX, run_inline,
};
