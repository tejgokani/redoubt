/* SPDX-License-Identifier: MIT */
#include "../checks.h"

/* Order = report order: kernel code first, hidden objects next, posture last. */
static const rd_check *const ALL[] = {
    &rd_chk_mod_xview,   &rd_chk_mod_orphan_mem, &rd_chk_mod_taint,    &rd_chk_mod_provenance,
    &rd_chk_syscall_table, &rd_chk_ftrace_hooks, &rd_chk_inline_hooks, &rd_chk_proc_xview,
    &rd_chk_net_xview,   &rd_chk_fs_xview,       &rd_chk_preload,      &rd_chk_known_iocs,
    &rd_chk_kext_inventory, &rd_chk_boot_integrity, &rd_chk_baseline,  &rd_chk_hardening,
};

const rd_check *const *rd_all_checks(size_t *n) {
    *n = sizeof ALL / sizeof ALL[0];
    return ALL;
}
