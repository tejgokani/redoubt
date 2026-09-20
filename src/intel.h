/* SPDX-License-Identifier: MIT
 *
 * Static detection knowledge shared by the checks and the live providers:
 * known-rootkit indicators and the kernel functions worth watching.
 */
#ifndef RD_INTEL_H
#define RD_INTEL_H

typedef struct {
    const char *name;   /* module name, '_' normalised */
    const char *family;
    const char *note;
} rd_ioc_mod;

typedef struct {
    const char *path;
    const char *family;
} rd_ioc_file;

extern const rd_ioc_mod rd_ioc_mods[];   /* NULL-name terminated */
extern const rd_ioc_file rd_ioc_files[]; /* NULL-path terminated */
extern const char *const rd_watch_syms[]; /* kernel functions whose prologue is read, NULL terminated */

const rd_ioc_mod *rd_ioc_mod_find(const char *name);
/* Is this kernel function/syscall one that rootkits routinely hook to hide things? */
int rd_is_sensitive_fn(const char *name);

#endif
