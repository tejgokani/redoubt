/* SPDX-License-Identifier: MIT */
#ifndef RD_CHECKS_H
#define RD_CHECKS_H

#include "redoubt.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

/* Fetch a view or make the calling check report "skipped" with the reason. */
#define NEED(c, id, var)                                                                                     \
    rd_view *var = NULL;                                                                                     \
    if (rd_get_view((c), (id), &(var)) != RD_OK)                                                             \
    return rd_skip((c), "%s: %s", rd_view_name(id), rd_view_why((c), (id)))

#define MITRE_ROOTKIT "T1014"
#define MITRE_KMOD "T1014, T1547.006"
#define MITRE_HIDE "T1564"
#define MITRE_HIDEFILE "T1564.001"
#define MITRE_LDPRELOAD "T1574.006"

extern const rd_check rd_chk_mod_xview, rd_chk_mod_orphan_mem, rd_chk_mod_taint, rd_chk_mod_provenance,
    rd_chk_syscall_table, rd_chk_ftrace_hooks, rd_chk_inline_hooks, rd_chk_proc_xview, rd_chk_net_xview,
    rd_chk_fs_xview, rd_chk_preload, rd_chk_known_iocs, rd_chk_hardening, rd_chk_baseline,
    rd_chk_kext_inventory, rd_chk_boot_integrity;

/* Kernel symbol table built from the RDV_KSYMS view (chk_kernel.c). */
typedef struct {
    uint64_t addr;
    const char *name;
    const char *mod; /* "" for core kernel */
} rd_ksym;

typedef struct {
    rd_ksym *s;
    size_t n;
    uint64_t text_lo, text_hi;
    int have_text;
    int have_sysnames;
} rd_ksymtab;

void rd_ksymtab_build(rd_view *ksyms, rd_ksymtab *t);
void rd_ksymtab_free(rd_ksymtab *t);
const rd_ksym *rd_ksymtab_lookup(const rd_ksymtab *t, uint64_t addr); /* greatest sym <= addr */
void rd_ksymtab_describe(const rd_ksymtab *t, uint64_t addr, char *buf, size_t sz);

#endif
