/* SPDX-License-Identifier: MIT
 *
 * macOS kernel-extension checks.  macOS has no `lsmod` to unlink from, but the
 * same principle holds: compare what the kernel-management layer reports with
 * an independent source (the IOKit registry, the on-disk install locations).
 */
#include "../checks.h"

#include <string.h>

static int is_apple(const char *id) { return rd_starts_with(id, "com.apple."); }

static int run_kext(rd_ctx *c) {
    NEED(c, RDV_KEXT_LOADED, loaded);
    rd_view *alt = NULL, *disk = NULL;
    int have_alt = rd_get_view(c, RDV_KEXT_ALT, &alt) == RD_OK;
    int have_disk = rd_get_view(c, RDV_KEXT_DISK, &disk) == RD_OK;

    for (size_t i = 0; i < loaded->n; i++) {
        const char *id = loaded->items[i].key;
        if (is_apple(id)) continue;
        int on_disk = have_disk && rd_view_find(disk, id) != NULL;
        char title[300];
        if (have_disk && !on_disk) {
            snprintf(title, sizeof title, "Kernel extension %s is loaded but installed nowhere", id);
            rd_finding *f = rd_add(c, RD_HIGH, 80, title,
                                   "Loaded (per kmutil) yet no bundle with this identifier exists under\n"
                                   "/Library/Extensions or /Library/StagedExtensions: it was loaded from a temporary\n"
                                   "location or its bundle was deleted after loading.");
            f->mitre = MITRE_KMOD;
            f->fix = "Note the version/UUID from `kmutil showloaded`, then isolate and investigate.";
        } else {
            snprintf(title, sizeof title, "Third-party kernel extension loaded: %s", id);
            rd_finding *f = rd_add(c, RD_LOW, 40, title,
                                   "Version %s. Kernel extensions run with full kernel privilege; on Apple silicon\n"
                                   "they need reduced security mode. Legitimate for some drivers - verify the vendor.",
                                   loaded->items[i].extra);
            f->mitre = MITRE_KMOD;
            f->fix = "Confirm you installed it. Prefer DriverKit / system extensions over kexts.";
        }
    }
    if (have_alt) {
        for (size_t i = 0; i < alt->n; i++) {
            const char *id = alt->items[i].key;
            if (is_apple(id) || rd_view_find(loaded, id)) continue;
            char title[300];
            snprintf(title, sizeof title, "Kernel bundle %s is active in IOKit but absent from kmutil", id);
            rd_finding *f = rd_add(c, RD_MEDIUM, 55, title,
                                   "The IOKit registry has an instantiated driver from this bundle that the kernel-\n"
                                   "management listing does not show. Could be a DriverKit extension (user space) -\n"
                                   "or a kext hiding from kmutil.");
            f->mitre = MITRE_KMOD;
            f->fix = "`systemextensionsctl list` tells DriverKit apart from a kext.";
        }
    }
    return 0;
}

const rd_check rd_chk_kext_inventory = {
    "kext-inventory", "Kernel extension inventory", "kmutil vs IOKit registry vs installed bundles",
    RD_PLAT_MACOS, run_kext,
};

static int run_boot(rd_ctx *c) {
    NEED(c, RDV_BOOTARGS, ba);
    static const struct {
        const char *arg;
        const char *why;
    } BAD[] = {
        {"amfi_get_out_of_my_way", "disables Apple Mobile File Integrity: code-signing is no longer enforced"},
        {"cs_enforcement_disable", "turns off code-signing enforcement in the kernel"},
        {"kext-dev-mode", "lets unsigned kernel extensions load"},
        {"rootless", "boot-arg that disables SIP-style protection"},
        {"amfi", "overrides AMFI behaviour"},
        {"debug", "enables kernel debugging hooks"},
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        const rd_item *it = rd_view_find(ba, BAD[i].arg);
        if (!it) continue;
        char title[300];
        snprintf(title, sizeof title, "Suspicious kernel boot-arg: %s%s%s", BAD[i].arg, it->extra[0] ? "=" : "", it->extra);
        rd_finding *f = rd_add(c, RD_MEDIUM, 70, title,
                               "This boot-arg %s.\nStock macOS does not set it; a kernel-level implant or a developer "
                               "workstation does.",
                               BAD[i].why);
        f->mitre = MITRE_KMOD;
        f->fix = "`sudo nvram boot-args=` clears it (from a state where SIP allows it); investigate who set it.";
    }
    return 0;
}

const rd_check rd_chk_boot_integrity = {
    "boot-integrity", "Kernel boot-arg integrity", "boot-args that switch off code-signing / SIP",
    RD_PLAT_MACOS, run_boot,
};
