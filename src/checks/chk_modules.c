/* SPDX-License-Identifier: MIT
 *
 * Checks that catch a kernel module hiding *itself*.
 *
 * The classic trick (Diamorphine, Reptile, ...) is to unlink `struct module`
 * from the kernel's `modules` list so that `lsmod` and /proc/modules stop
 * showing it.  Nothing forces the rootkit to clean every other place the
 * kernel remembers the module, so we look in those places.
 *
 * Which places are truly independent matters.  /proc/modules and /proc/kallsyms
 * both walk the `modules` list, so a plain list_del hides from BOTH; kallsyms
 * only adds coverage against hiders that filter the /proc/modules *output*.
 * The genuinely independent records are the sysfs kobject (/sys/module) and the
 * kernel's executable-memory map.  A rootkit that removes the list entry AND
 * the sysfs node (Diamorphine does both) is therefore invisible to mod-xview by
 * construction and is caught by mod-orphan-mem / mod-taint instead.
 */
#include "../checks.h"
#include "../intel.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ mod-xview */

/* Re-read both views; keep the discrepancy only if it is still there.  This is
 * what separates a hidden module from a module that was merely (un)loaded
 * between our two reads. */
static int reconfirm(rd_ctx *c, rd_view_id in_id, rd_view_id out_id, const char *name) {
    rd_view a = {0}, b = {0};
    int sa = rd_recollect(c, in_id, &a);
    int sb = rd_recollect(c, out_id, &b);
    int keep = 1;
    if (sa == RD_OK && sb == RD_OK) keep = rd_view_find(&a, name) != NULL && rd_view_find(&b, name) == NULL;
    if (sa == RD_OK) rd_view_free(&a);
    if (sb == RD_OK) rd_view_free(&b);
    return keep;
}

typedef struct {
    char name[96];
    int in_sys, in_ks;
} hidden_mod;

static int run_mod_xview(rd_ctx *c) {
    NEED(c, RDV_MOD_API, api);
    NEED(c, RDV_MOD_SYSFS, sys);
    rd_view *ks = NULL;
    int have_ks = rd_get_view(c, RDV_MOD_KALLSYMS, &ks) == RD_OK;

    hidden_mod hm[32];
    size_t nh = 0;

    for (size_t i = 0; i < sys->n && nh < 32; i++) {
        const char *nm = sys->items[i].key;
        if (rd_view_find(api, nm)) continue;
        if (!reconfirm(c, RDV_MOD_SYSFS, RDV_MOD_API, nm)) continue;
        snprintf(hm[nh].name, sizeof hm[nh].name, "%s", nm);
        hm[nh].in_sys = 1;
        hm[nh].in_ks = have_ks && rd_view_find(ks, nm) != NULL;
        nh++;
    }
    for (size_t i = 0; have_ks && i < ks->n && nh < 32; i++) {
        const char *nm = ks->items[i].key;
        if (rd_is_pseudo_module(nm)) continue; /* [bpf], [__builtin__ftrace]: kernel allocators, not modules */
        if (rd_view_find(api, nm) || rd_view_find(sys, nm)) continue;
        if (!reconfirm(c, RDV_MOD_KALLSYMS, RDV_MOD_API, nm)) continue;
        snprintf(hm[nh].name, sizeof hm[nh].name, "%s", nm);
        hm[nh].in_sys = 0;
        hm[nh].in_ks = 1;
        nh++;
    }

    for (size_t i = 0; i < nh; i++) {
        char title[200];
        snprintf(title, sizeof title, "Module '%s' is hidden from the module list", hm[i].name);
        int both = hm[i].in_sys && hm[i].in_ks;
        rd_finding *f = rd_add(c, RD_HIGH, both ? 96 : 90, title,
                               "Present in:  %s%s%s\n"
                               "Absent from: /proc/modules (what lsmod reads)\n"
                               "The kernel still tracks this module but the /proc/modules listing omits it: it was unlinked\n"
                               "from the module list without removing its sysfs node, or the listing itself is being\n"
                               "filtered. Either way, the module is hiding.",
                               hm[i].in_sys ? "/sys/module" : "", both ? ", " : "", hm[i].in_ks ? "kallsyms" : "");
        f->mitre = MITRE_KMOD;
        f->fix = "Do not unload on the live host (a hiding module usually cannot be rmmod'ed cleanly). Capture "
                 "memory + `redoubt snapshot`, isolate the machine, reinstall from trusted media.";
    }

    /* The reverse: listed but with no sysfs node - kobject_del() without list_del(). */
    for (size_t i = 0; i < api->n; i++) {
        const char *nm = api->items[i].key;
        if (rd_view_find(sys, nm)) continue;
        if (!reconfirm(c, RDV_MOD_API, RDV_MOD_SYSFS, nm)) continue;
        char title[200];
        snprintf(title, sizeof title, "Module '%s' is listed but has no /sys/module entry", nm);
        rd_finding *f = rd_add(c, RD_MEDIUM, 65, title,
                               "Present in /proc/modules but the kernel's sysfs node for it was removed.\n"
                               "Legitimate modules always have /sys/module/<name>; removing it is a hiding step.");
        f->mitre = MITRE_KMOD;
        f->fix = "Inspect the module: `modinfo`, its file on disk, and who loaded it (auditd / journal).";
    }
    return 0;
}

const rd_check rd_chk_mod_xview = {
    "mod-xview", "Module list cross-view", "/proc/modules vs /sys/module vs kallsyms",
    RD_PLAT_LINUX, run_mod_xview,
};

/* ------------------------------------------------------- mod-orphan-mem */

typedef struct {
    uint64_t addr, size;
    char caller[64];
} region;

/* A region is explained if the kernel names anything inside it: a kallsyms symbol ("syms=N": a listed module's
 * text/data, a BPF image, an ftrace trampoline), a section of a listed module ("secs=N": also covers anonymous
 * rodata that has no symbol), or a listed module's base address. */
static size_t find_orphans(rd_view *mem, rd_view *api, region *out, size_t max) {
    size_t k = 0;
    for (size_t i = 0; i < mem->n; i++) {
        uint64_t a = mem->items[i].a, len = mem->items[i].b;
        int covered = 0;
        const char *sy = strstr(mem->items[i].extra, "syms=");
        const char *se = strstr(mem->items[i].extra, "secs=");
        if ((sy && atoi(sy + 5) > 0) || (se && atoi(se + 5) > 0)) covered = 1;
        for (size_t j = 0; j < api->n && !covered; j++) {
            uint64_t base = api->items[j].b;
            if (base && base >= a && base < a + len) covered = 1;
        }
        if (!covered && k < max) {
            out[k].addr = a;
            out[k].size = mem->items[i].b;
            snprintf(out[k].caller, sizeof out[k].caller, "%s", mem->items[i].extra);
            k++;
        }
    }
    return k;
}

static int run_orphan_mem(rd_ctx *c) {
    NEED(c, RDV_MOD_MEM, mem);
    NEED(c, RDV_MOD_API, api);
    int have_addr = 0;
    for (size_t i = 0; i < api->n; i++)
        if (api->items[i].b) have_addr = 1;
    if (api->n && !have_addr) return rd_skip(c, "module addresses hidden (kptr_restrict / not root)");

    region first[64], second[64];
    size_t n1 = find_orphans(mem, api, first, 64);
    if (n1 == 0) return 0;

    /* second sample: a module that was mid-load during sample one will now be listed */
    rd_view m2 = {0}, a2 = {0};
    size_t n2 = n1;
    memcpy(second, first, sizeof first);
    if (rd_recollect(c, RDV_MOD_MEM, &m2) == RD_OK) {
        if (rd_recollect(c, RDV_MOD_API, &a2) == RD_OK) {
            n2 = find_orphans(&m2, &a2, second, 64);
            rd_view_free(&a2);
        }
        rd_view_free(&m2);
    }

    rd_sb sb = {0};
    size_t kept = 0;
    uint64_t total = 0;
    for (size_t i = 0; i < n1; i++) {
        int persists = 0;
        for (size_t j = 0; j < n2; j++)
            if (second[j].addr == first[i].addr) persists = 1;
        if (!persists) continue;
        kept++;
        total += first[i].size;
        if (kept <= 8)
            rd_sb_addf(&sb, "  0x%llx  %llu bytes  (no kernel symbol or module section inside)\n", (unsigned long long)first[i].addr,
                       (unsigned long long)first[i].size);
    }
    if (kept) {
        char title[200];
        snprintf(title, sizeof title, "%zu executable allocation%s in module memory owned by no listed module",
                 kept, kept == 1 ? "" : "s");
        char *lines = rd_sb_take(&sb);
        /* Capped below the conviction threshold: kallsyms could in principle omit a symbol-less legitimate
         * region, so this is a strong lead to correlate rather than standalone proof. */
        rd_finding *f = rd_add(c, RD_HIGH, 65, title,
                               "%sTotal %llu bytes of executable/module address space that no kallsyms symbol and no\n"
                               "listed module's ELF section falls inside. Listed modules, BPF images, ftrace trampolines\n"
                               "and kprobe stubs are all named by one of those; a module that removed itself from the\n"
                               "kernel's lists stops being named, so its regions look exactly like this.\n"
                               "Correlate with mod-xview / mod-taint / syscall-table / ftrace-hooks.",
                               lines, (unsigned long long)total);
        free(lines);
        f->mitre = MITRE_KMOD;
        f->fix = "Correlate with mod-xview / syscall-table / ftrace-hooks. If they agree, treat as compromised.";
    } else {
        rd_sb_free(&sb);
    }
    return 0;
}

const rd_check rd_chk_mod_orphan_mem = {
    "mod-orphan-mem", "Orphaned module memory", "vmalloc module regions vs listed modules",
    RD_PLAT_LINUX, run_orphan_mem,
};

/* ------------------------------------------------------------ mod-taint */

/* Bits of /proc/sys/kernel/tainted that a module load can set. */
#define TAINT_PROPRIETARY 0
#define TAINT_OOT 12
#define TAINT_UNSIGNED 13

static int run_taint(rd_ctx *c) {
    NEED(c, RDV_SYSINFO, si);
    const rd_item *t = rd_view_find(si, "taint");
    if (!t) return rd_skip(c, "taint mask not reported");
    uint64_t mask = t->a;

    rd_view *sys = NULL, *api = NULL, *ks = NULL, *dm = NULL, *disk = NULL;
    int have_sys = rd_get_view(c, RDV_MOD_SYSFS, &sys) == RD_OK;
    int have_api = rd_get_view(c, RDV_MOD_API, &api) == RD_OK;
    int have_ks = rd_get_view(c, RDV_MOD_KALLSYMS, &ks) == RD_OK;
    int have_dm = rd_get_view(c, RDV_DMESG_MODS, &dm) == RD_OK;
    int have_disk = rd_get_view(c, RDV_MOD_DISK, &disk) == RD_OK && disk->n > 0;
    if (!have_sys && !have_dm) return rd_skip(c, "neither /sys/module taint flags nor the kernel log are readable");

    /* 1. taint bits nobody visible owns */
    if (have_sys) {
        int seen_o = 0, seen_e = 0;
        for (size_t i = 0; i < sys->n; i++) {
            if (strchr(sys->items[i].extra, 'O')) seen_o = 1;
            if (strchr(sys->items[i].extra, 'E')) seen_e = 1;
        }
        int unexplained_o = (mask >> TAINT_OOT & 1) && !seen_o;
        int unexplained_e = (mask >> TAINT_UNSIGNED & 1) && !seen_e;
        if (unexplained_o || unexplained_e) {
            rd_finding *f = rd_add(c, RD_LOW, 40, "Kernel taint has no visible owner",
                                   "taint mask 0x%llx sets %s%s%s but no module in /sys/module carries that\n"
                                   "flag. Either an already-unloaded module tainted the kernel, or the module that did is\n"
                                   "hidden.",
                                   (unsigned long long)mask, unexplained_o ? "O (out-of-tree module)" : "",
                                   unexplained_o && unexplained_e ? " and " : "",
                                   unexplained_e ? "E (unsigned module)" : "");
            f->mitre = MITRE_KMOD;
            f->fix = "Weak on its own (a module can be loaded then removed). It is corroboration for other findings.";
        }
    }

    /* 2. modules that announced a taint in the kernel log but are in no module view */
    if (have_dm) {
        for (size_t i = 0; i < dm->n; i++) {
            const char *nm = dm->items[i].key;
            int visible = (have_api && rd_view_find(api, nm)) || (have_sys && rd_view_find(sys, nm)) ||
                          (have_ks && rd_view_find(ks, nm));
            if (visible) continue;
            int on_disk = have_disk && rd_view_find(disk, nm);
            char title[200];
            snprintf(title, sizeof title, "Kernel log names module '%s', which no module view lists", nm);
            rd_finding *f = rd_add(c, RD_MEDIUM, on_disk ? 35 : 62, title,
                                   "dmesg: \"%s\" (%s)\n"
                                   "Not present in /proc/modules, /sys/module or kallsyms.\n%s",
                                   nm, dm->items[i].extra,
                                   on_disk ? "A file with that name exists under /lib/modules, so a plain unload is likely."
                                           : "No such file is registered under /lib/modules: it was insmod'ed from\n"
                                             "elsewhere and is now invisible - the hiding-rootkit pattern.");
            f->mitre = MITRE_KMOD;
            f->fix = "Ask: was this module unloaded on purpose? Check shell history / auditd for insmod/rmmod.";
        }
    }
    return 0;
}

const rd_check rd_chk_mod_taint = {
    "mod-taint", "Taint & kernel-log accounting", "taint flags and dmesg vs module views",
    RD_PLAT_LINUX, run_taint,
};

/* ------------------------------------------------------- mod-provenance */

static int run_provenance(rd_ctx *c) {
    NEED(c, RDV_MOD_API, api);
    NEED(c, RDV_MOD_DISK, disk);
    if (disk->n == 0) return rd_skip(c, "modules.dep is empty or unreadable");

    rd_sb sb = {0};
    size_t n = 0;
    for (size_t i = 0; i < api->n; i++) {
        if (rd_view_find(disk, api->items[i].key)) continue;
        if (++n <= 10) rd_sb_addf(&sb, "  %s\n", api->items[i].key);
    }
    if (n == 0) {
        rd_sb_free(&sb);
        return 0;
    }
    char title[200];
    snprintf(title, sizeof title, "%zu loaded module%s not registered in modules.dep", n, n == 1 ? "" : "s");
    char *names = rd_sb_take(&sb);
    rd_finding *f = rd_add(c, RD_LOW, 35, title,
                           "%sDistribution-managed modules are registered by depmod. Modules loaded straight\n"
                           "from a build directory or /tmp with insmod are not - a common rootkit install path.",
                           names);
    free(names);
    f->mitre = MITRE_KMOD;
    f->fix = "Confirm each module is expected (DKMS, vendor driver). Unknown ones: find the .ko and hash it.";
    return 0;
}

const rd_check rd_chk_mod_provenance = {
    "mod-provenance", "Module provenance", "loaded modules vs modules.dep",
    RD_PLAT_LINUX, run_provenance,
};
