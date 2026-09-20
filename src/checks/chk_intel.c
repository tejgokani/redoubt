/* SPDX-License-Identifier: MIT
 *
 * Signature, posture and drift checks.  These are the *weakest* evidence
 * Redoubt produces (a rootkit author can rename a module) so they are labelled
 * accordingly; they exist because they catch off-the-shelf toolkits cheaply and
 * because posture advice is where most of the defensive value lives.
 */
#include "../checks.h"
#include "../intel.h"

#include <string.h>

/* ------------------------------------------------------------ known-iocs */

typedef struct {
    char name[96];
    const rd_ioc_mod *ioc;
    const char *sources[4];
    int nsrc;
} ioc_hit;

static void note_hit(ioc_hit *hits, size_t *n, const char *name, const rd_ioc_mod *ioc, const char *src) {
    for (size_t i = 0; i < *n; i++)
        if (strcmp(hits[i].name, name) == 0) {
            if (hits[i].nsrc < 4) hits[i].sources[hits[i].nsrc++] = src;
            return;
        }
    if (*n >= 16) return;
    snprintf(hits[*n].name, sizeof hits[*n].name, "%s", name);
    hits[*n].ioc = ioc;
    hits[*n].sources[0] = src;
    hits[*n].nsrc = 1;
    (*n)++;
}

static int run_iocs(rd_ctx *c) {
    static const struct {
        rd_view_id id;
        const char *label;
    } SRC[] = {{RDV_MOD_API, "/proc/modules"},
               {RDV_MOD_SYSFS, "/sys/module"},
               {RDV_MOD_KALLSYMS, "kallsyms"},
               {RDV_DMESG_MODS, "kernel log"}};

    ioc_hit hits[16];
    size_t nh = 0;
    int any = 0;
    for (size_t s = 0; s < sizeof SRC / sizeof SRC[0]; s++) {
        rd_view *v = NULL;
        if (rd_get_view(c, SRC[s].id, &v) != RD_OK) continue;
        any = 1;
        for (size_t i = 0; i < v->n; i++) {
            const rd_ioc_mod *m = rd_ioc_mod_find(v->items[i].key);
            if (m) note_hit(hits, &nh, v->items[i].key, m, SRC[s].label);
        }
    }
    for (size_t i = 0; i < nh; i++) {
        char title[200];
        snprintf(title, sizeof title, "Module '%s' matches known rootkit family %s", hits[i].name, hits[i].ioc->family);
        rd_sb where = {0};
        for (int k = 0; k < hits[i].nsrc; k++) rd_sb_addf(&where, "%s%s", k ? ", " : "", hits[i].sources[k]);
        char *w = rd_sb_take(&where);
        rd_finding *f = rd_add(c, RD_HIGH, 88, title,
                               "Seen in: %s\n%s: %s.\n"
                               "Name match only - renaming defeats it, so the *absence* of a match means nothing.",
                               w, hits[i].ioc->family, hits[i].ioc->note);
        free(w);
        f->mitre = MITRE_KMOD;
        f->fix = "Treat as compromised unless you installed this yourself for research.";
    }

    rd_view *p = NULL;
    if (rd_get_view(c, RDV_FILE_PROBES, &p) == RD_OK) {
        any = 1;
        for (const rd_ioc_file *fl = rd_ioc_files; fl->path; fl++) {
            if (strcmp(fl->path, "/etc/ld.so.preload") == 0) continue; /* owned by the preload check */
            const rd_item *it = rd_view_find(p, fl->path);
            if (!it || !it->a) continue;
            char title[300];
            snprintf(title, sizeof title, "Known %s artefact exists: %s", fl->family, fl->path);
            rd_finding *f = rd_add(c, RD_HIGH, 85, title,
                                   "Direct stat() confirms the path exists%s.\n"
                                   "This path is a documented install location of the %s rootkit.",
                                   it->b ? "" : " (and readdir() hides it)", fl->family);
            f->mitre = MITRE_HIDEFILE;
            f->fix = "Do not delete: preserve as evidence, then isolate and rebuild.";
        }
    }
    if (!any) return rd_skip(c, "no module views or file probes available");
    return 0;
}

const rd_check rd_chk_known_iocs = {
    "known-iocs", "Known rootkit indicators", "module names and install paths of public rootkits",
    RD_PLAT_LINUX, run_iocs,
};

/* ------------------------------------------------------------- hardening */

static void posture(rd_ctx *c, rd_sev sev, const char *title, const char *why) {
    rd_finding *f = rd_add(c, sev, 100, title, "%s", why);
    f->kind = RD_KIND_POSTURE;
}

static int run_hardening(rd_ctx *c) {
    NEED(c, RDV_HARDENING, h);
    const rd_item *it;

    if ((it = rd_view_find(h, "modules_disabled")) && it->a == 0)
        posture(c, RD_LOW,
                "Kernel module loading stays enabled after boot (kernel.modules_disabled=0)",
                "Any root process can insert a kernel module. On servers whose driver set is fixed, set "
                "kernel.modules_disabled=1 once boot has finished: a kernel-module rootkit then cannot load at all.");
    if ((it = rd_view_find(h, "sig_enforce")) && it->extra[0] == 'N')
        posture(c, RD_MEDIUM, "Module signature enforcement is off",
                "Unsigned modules load freely. Enable Secure Boot + module.sig_enforce=1 (or lockdown) so only "
                "modules signed by a trusted key can enter the kernel.");
    else if ((it = rd_view_find(h, "sig_enforce")) && !it->b)
        posture(c, RD_LOW, "Kernel built without module signing",
                "CONFIG_MODULE_SIG is off: there is no cryptographic gate on module loading.");
    if ((it = rd_view_find(h, "lockdown")) && strcmp(it->extra, "none") == 0)
        posture(c, RD_MEDIUM, "Kernel lockdown is off",
                "Lockdown (integrity mode) blocks /dev/mem, /dev/kmem, kexec and unsigned module loads even for root.");
    if ((it = rd_view_find(h, "dev_kmem")) && it->a)
        posture(c, RD_MEDIUM, "/dev/kmem exists",
                "Raw kernel memory is accessible to root - the pre-LKM rootkit installation path.");
    if ((it = rd_view_find(h, "kptr_restrict")) && it->a == 0)
        posture(c, RD_LOW, "Kernel pointers are exposed (kptr_restrict=0)",
                "Exposes kernel addresses that make rootkit hook placement trivial. Set kernel.kptr_restrict=1 or 2.");
    if ((it = rd_view_find(h, "dmesg_restrict")) && it->a == 0)
        posture(c, RD_LOW, "dmesg is readable by unprivileged users (dmesg_restrict=0)",
                "The kernel log leaks module load messages and addresses. Set kernel.dmesg_restrict=1.");
    if ((it = rd_view_find(h, "secureboot")) && it->a == 0)
        posture(c, RD_LOW, "Secure Boot is disabled", "Without it, a bootkit or unsigned kernel can load before the OS.");

    if ((it = rd_view_find(h, "sip")) && strcmp(it->extra, "disabled") == 0)
        posture(c, RD_MEDIUM, "System Integrity Protection (SIP) is disabled",
                "SIP is what stops even root from modifying kernel extensions and protected system files. "
                "Re-enable it from Recovery: `csrutil enable`.");
    if ((it = rd_view_find(h, "gatekeeper")) && strcmp(it->extra, "disabled") == 0)
        posture(c, RD_LOW, "Gatekeeper is disabled", "Unsigned/unnotarised code runs without a prompt.");
    return 0;
}

const rd_check rd_chk_hardening = {
    "hardening", "Hardening posture", "settings that make a kernel rootkit harder to install",
    RD_PLAT_ANY, run_hardening,
};

/* -------------------------------------------------------------- baseline */

static int base_view(rd_provider *bp, rd_view_id id, rd_view *out) {
    char why[64];
    rd_view_init(out);
    int st = bp->collect(bp, id, out, why, sizeof why);
    if (st != RD_OK) rd_view_free(out);
    return st == RD_OK;
}

static int run_baseline(rd_ctx *c) {
    if (!c->opt.baseline || !*c->opt.baseline) return rd_na(c, "no --baseline given");
    rd_provider *bp = rd_provider_fixture(c->opt.baseline);
    if (!bp) return rd_skip(c, "cannot open baseline '%s'", c->opt.baseline);

    int compared = 0;
    rd_view bmod, bsc, bkx;
    rd_view *cmod = NULL, *csc = NULL, *ckx = NULL;

    if (base_view(bp, RDV_MOD_API, &bmod) && rd_get_view(c, RDV_MOD_API, &cmod) == RD_OK) {
        compared++;
        rd_sb added = {0};
        size_t na = 0, nr = 0;
        for (size_t i = 0; i < cmod->n; i++)
            if (!rd_view_find(&bmod, cmod->items[i].key) && ++na <= 10) rd_sb_addf(&added, "  + %s\n", cmod->items[i].key);
        for (size_t i = 0; i < bmod.n; i++)
            if (!rd_view_find(cmod, bmod.items[i].key)) nr++;
        if (na) {
            char title[200];
            snprintf(title, sizeof title, "%zu module%s loaded since the baseline", na, na == 1 ? "" : "s");
            char *l = rd_sb_take(&added);
            rd_finding *f = rd_add(c, RD_MEDIUM, 65, title, "%sNew kernel code on a system whose module set was recorded as known-good.", l);
            free(l);
            f->mitre = MITRE_KMOD;
            f->fix = "Confirm each addition against your change log.";
        } else {
            rd_sb_free(&added);
        }
        if (nr) {
            rd_finding *f = rd_add(c, RD_INFO, 30, "Baseline modules no longer listed",
                                   "%zu module(s) from the baseline are absent from /proc/modules now.\n"
                                   "Unloaded normally - or hidden (check mod-xview).", nr);
            f->mitre = MITRE_KMOD;
        }
        rd_view_free(&bmod);
    }

    if (base_view(bp, RDV_SYSCALLS, &bsc) && rd_get_view(c, RDV_SYSCALLS, &csc) == RD_OK) {
        compared++;
        rd_sb changed = {0};
        size_t nc = 0;
        for (size_t i = 0; i < csc->n; i++) {
            const rd_item *b = rd_view_find(&bsc, csc->items[i].key);
            if (!b || !b->extra[0] || !csc->items[i].extra[0]) continue;
            if (strcmp(b->extra, csc->items[i].extra) != 0 && ++nc <= 10)
                rd_sb_addf(&changed, "  #%s  %s  ->  %s\n", csc->items[i].key, b->extra, csc->items[i].extra);
        }
        if (nc) {
            char title[200];
            snprintf(title, sizeof title, "%zu syscall handler%s differ from the baseline", nc, nc == 1 ? "" : "s");
            char *l = rd_sb_take(&changed);
            rd_finding *f = rd_add(c, RD_CRITICAL, 94, title, "%sSame kernel build, different handlers: the table was rewritten.", l);
            free(l);
            f->mitre = MITRE_ROOTKIT;
            f->fix = "Direct evidence of tampering (assuming the same kernel build as the baseline).";
        } else {
            rd_sb_free(&changed);
        }
        rd_view_free(&bsc);
    }

    if (base_view(bp, RDV_KEXT_LOADED, &bkx) && rd_get_view(c, RDV_KEXT_LOADED, &ckx) == RD_OK) {
        compared++;
        for (size_t i = 0; i < ckx->n; i++) {
            if (rd_view_find(&bkx, ckx->items[i].key)) continue;
            char title[300];
            snprintf(title, sizeof title, "Kernel extension loaded since the baseline: %s", ckx->items[i].key);
            rd_finding *f = rd_add(c, RD_MEDIUM, 65, title, "Not present when the baseline was recorded.");
            f->mitre = MITRE_KMOD;
            f->fix = "Confirm against your change log.";
        }
        rd_view_free(&bkx);
    }

    bp->destroy(bp);
    if (!compared) return rd_skip(c, "baseline shares no comparable views with this scan");
    return 0;
}

const rd_check rd_chk_baseline = {
    "baseline", "Baseline drift", "current kernel state vs a recorded known-good snapshot",
    RD_PLAT_ANY, run_baseline,
};
