/* SPDX-License-Identifier: MIT
 *
 * Fallback for operating systems without a live provider.  Linux and macOS
 * define rd_provider_live() in linux.c / macos.c.  Snapshot analysis
 * (--from DIR) still works everywhere.
 */
#include "../util.h"

#if !defined(__linux__) && !defined(__APPLE__)
rd_provider *rd_provider_live(const rd_options *opt) {
    (void)opt;
    return NULL;
}
#endif
