/* SPDX-License-Identifier: MIT */
#include "intel.h"

#include <string.h>

/* Publicly documented LKM rootkit families.  Name matching is the weakest
 * signal Redoubt has - renaming the module defeats it - so findings built on
 * it are labelled as such.  It exists because it is cheap and it catches
 * unmodified off-the-shelf toolkits. */
const rd_ioc_mod rd_ioc_mods[] = {
    {"diamorphine", "Diamorphine", "syscall-table hooks; self-unlinks from the module list on a magic signal"},
    {"reptile", "Reptile", "hides files, processes, ports and its own module"},
    {"reptile_module", "Reptile", "hides files, processes, ports and its own module"},
    {"adore", "Adore", "classic LKM rootkit hiding processes and files"},
    {"adore_ng", "Adore-ng", "VFS-level LKM rootkit"},
    {"knark", "Knark", "classic syscall-hooking LKM rootkit"},
    {"suterusu", "Suterusu", "inline function hooking LKM rootkit"},
    {"sebek", "Sebek", "kernel keystroke/network capture (honeypot tool, abused by attackers)"},
    {"enyelkm", "EnyeLKM", "LKM rootkit with hidden backdoor"},
    {"kbeast", "KBeast", "LKM rootkit hiding files, processes and connections"},
    {"singularity", "Singularity", "ftrace-based LKM rootkit for modern kernels"},
    {"kovid", "KoviD", "ftrace-based LKM rootkit"},
    {"rooty", "Rooty", "LKM rootkit"},
    {"nuk3gh0st", "Nuk3 Gh0st", "LKM rootkit"},
    {"heroin", "Heroin", "the original Phrack-era syscall-hooking LKM"},
    {"phalanx", "Phalanx", "kernel-level rootkit"},
    {NULL, NULL, NULL},
};

/* Well-known on-disk artefacts.  These are searched by direct stat(), which is
 * exactly what a directory-listing hook cannot hide. */
const rd_ioc_file rd_ioc_files[] = {
    {"/proc/knark", "Knark"},
    {"/reptile", "Reptile"},
    {"/reptile/reptile_cmd", "Reptile"},
    {"/reptile/reptile_shell", "Reptile"},
    {"/usr/_h4x_", "KBeast"},
    {"/etc/khubd.p2", "Phalanx"},
    {"/etc/ld.so.preload", "user-space preload rootkits (Azazel, Jynx, BEURK, ...)"},
    {NULL, NULL},
};

/* Functions whose first bytes we read to spot inline hooks (x86_64 names). */
const char *const rd_watch_syms[] = {
    "__x64_sys_getdents", "__x64_sys_getdents64", "__x64_sys_kill",   "__x64_sys_read",
    "__x64_sys_open",     "__x64_sys_openat",     "__x64_sys_stat",   "__x64_sys_lstat",
    "__x64_sys_newfstatat", "__x64_sys_init_module", "__x64_sys_finit_module",
    "__x64_sys_delete_module", "filldir",         "filldir64",        "iterate_dir",
    "tcp4_seq_show",      "tcp6_seq_show",        "udp4_seq_show",    "udp6_seq_show",
    "proc_pid_readdir",   "vfs_read",             "commit_creds",     NULL,
};

const rd_ioc_mod *rd_ioc_mod_find(const char *name) {
    for (const rd_ioc_mod *m = rd_ioc_mods; m->name; m++)
        if (strcmp(m->name, name) == 0) return m;
    return NULL;
}

static const char *const SENSITIVE[] = {
    "getdents", "getdents64", "kill", "read", "open", "openat", "stat", "lstat", "newfstatat",
    "init_module", "finit_module", "delete_module", "filldir", "filldir64", "iterate_dir",
    "tcp4_seq_show", "tcp6_seq_show", "udp4_seq_show", "udp6_seq_show", "proc_pid_readdir",
    "vfs_read", "commit_creds", "prepare_creds", "do_syscall_64", "kallsyms_lookup_name", NULL,
};

int rd_is_sensitive_fn(const char *name) {
    static const char *const prefixes[] = {"__x64_sys_", "__ia32_sys_", "__arm64_sys_", "__se_sys_", "sys_", NULL};
    for (const char *const *p = prefixes; *p; p++) {
        size_t l = strlen(*p);
        if (strncmp(name, *p, l) == 0) {
            name += l;
            break;
        }
    }
    for (const char *const *s = SENSITIVE; *s; s++)
        if (strcmp(name, *s) == 0) return 1;
    return 0;
}
