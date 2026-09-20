/* SPDX-License-Identifier: MIT
 *
 * Live macOS provider.  macOS has no lsmod to unlink from and third-party
 * kexts are nearly extinct, so the useful independent views are:
 *
 *   processes     libproc listing  vs  sysctl(KERN_PROC_ALL)  vs  pid brute force
 *   kernel bundles kmutil          vs  the IOKit registry     vs  installed bundles
 *   integrity     boot-args, SIP, DYLD injection
 */
#if defined(__APPLE__)

#include "../util.h"

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <libproc.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#define MAC_PID_MAX 99999

typedef struct {
    rd_options opt;
} mac_t;

static char *run_cmd(const char *cmd) {
    FILE *p = popen(cmd, "r");
    if (!p) return NULL;
    size_t cap = 8192, n = 0;
    char *b = rd_xmalloc(cap + 1);
    for (;;) {
        if (n == cap) {
            cap *= 2;
            b = rd_xrealloc(b, cap + 1);
        }
        size_t r = fread(b + n, 1, cap - n, p);
        if (r == 0) break;
        n += r;
    }
    pclose(p);
    b[n] = '\0';
    return b;
}

static void add_pid(rd_view *v, long pid, const char *comm) {
    rd_view_addf(v, 0, 0, comm ? comm : "", "%ld", pid);
}

static int pid_exists(pid_t pid) {
    if (kill(pid, 0) == 0 || errno == EPERM) return 1;
    struct proc_bsdshortinfo si;
    return proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si) > 0;
}

/* ---------------------------------------------------------------- views */

static int mac_sysinfo(rd_view *out) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    rd_view_add(out, "os", 0, 0, "Darwin");
    rd_view_add(out, "kernel", 0, 0, u.release);
    rd_view_add(out, "arch", 0, 0, u.machine);
    rd_view_add(out, "euid", (uint64_t)geteuid(), 0, "");
    rd_view_add(out, "pid_max", MAC_PID_MAX, 0, "");
    return 0;
}

static int mac_proc_api(rd_view *out) {
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) return -1;
    pid_t *buf = rd_xmalloc((size_t)bytes + 64 * sizeof(pid_t));
    bytes = proc_listpids(PROC_ALL_PIDS, 0, buf, bytes + (int)(64 * sizeof(pid_t)));
    if (bytes <= 0) {
        free(buf);
        return -1;
    }
    for (int i = 0; i < bytes / (int)sizeof(pid_t); i++)
        if (buf[i] > 0) add_pid(out, buf[i], NULL);
    free(buf);
    rd_view_dedup(out);
    return 0;
}

static int mac_proc_raw(rd_view *out) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    struct kinfo_proc *kp = NULL;
    for (int tries = 0; tries < 5; tries++) {
        if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0) return -1;
        size += size / 8 + 4096;
        kp = rd_xrealloc(kp, size);
        if (sysctl(mib, 3, kp, &size, NULL, 0) == 0) break;
        if (errno != ENOMEM) {
            free(kp);
            return -1;
        }
    }
    for (size_t i = 0; i < size / sizeof *kp; i++)
        if (kp[i].kp_proc.p_pid > 0) add_pid(out, kp[i].kp_proc.p_pid, NULL);
    free(kp);
    rd_view_dedup(out);
    return 0;
}

static int mac_proc_brute(rd_view *out) {
    for (pid_t pid = 1; pid <= MAC_PID_MAX; pid++) {
        if (!pid_exists(pid)) continue;
        char name[64] = "";
        proc_name(pid, name, sizeof name);
        add_pid(out, pid, name);
    }
    return 0;
}

static void kext_parse(const char *text, rd_view *out) {
    char *copy = rd_xstrdup(text), *save = NULL;
    for (char *ln = strtok_r(copy, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        long idx, refs;
        char addr[40], size[40], wired[40], name[256], ver[80];
        if (sscanf(ln, " %ld %ld %39s %39s %39s %255s (%79[^)])", &idx, &refs, addr, size, wired, name, ver) == 7) {
            uint64_t a = 0, s = 0;
            rd_parse_u64(addr, &a);
            rd_parse_u64(size, &s);
            rd_view_add(out, name, s, a, ver);
        }
    }
    free(copy);
    rd_view_dedup(out);
}

static int mac_kext_loaded(rd_view *out) {
    char *o = run_cmd("/usr/bin/kmutil showloaded 2>/dev/null");
    if (!o) return -1;
    kext_parse(o, out);
    free(o);
    return out->n ? 0 : -1;
}

static int mac_kext_alt(rd_view *out) {
    char *o = run_cmd("/usr/sbin/ioreg -l -w0 2>/dev/null");
    if (!o) return -1;
    const char *needle = "\"CFBundleIdentifier\" = \"";
    size_t nl = strlen(needle);
    const char *p = o;
    while ((p = strstr(p, needle))) {
        p += nl;
        const char *e = strchr(p, '"');
        if (!e) break;
        if (e > p) {
            char id[256];
            size_t l = (size_t)(e - p);
            if (l >= sizeof id) l = sizeof id - 1;
            memcpy(id, p, l);
            id[l] = '\0';
            rd_view_add(out, id, 0, 0, "ioreg");
        }
        p = e + 1;
    }
    free(o);
    rd_view_dedup(out);
    return out->n ? 0 : -1;
}

static void shq(char *dst, size_t sz, const char *s) {
    size_t w = 0;
    dst[w++] = '\'';
    for (; *s && w + 5 < sz; s++) {
        if (*s == '\'') {
            memcpy(dst + w, "'\\''", 4);
            w += 4;
        } else {
            dst[w++] = *s;
        }
    }
    dst[w++] = '\'';
    dst[w] = '\0';
}

static void scan_kext_dir(const char *dir, rd_view *out) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l < 6 || strcmp(e->d_name + l - 5, ".kext") != 0) continue;
        char plist[1024], q[1200], cmd[1400];
        snprintf(plist, sizeof plist, "%s/%s/Contents/Info.plist", dir, e->d_name);
        shq(q, sizeof q, plist);
        snprintf(cmd, sizeof cmd, "/usr/bin/plutil -extract CFBundleIdentifier raw -o - %s 2>/dev/null", q);
        char *id = run_cmd(cmd);
        if (id) {
            char *t = rd_trim(id);
            if (*t) rd_view_add(out, t, 0, 0, plist);
            free(id);
        }
    }
    closedir(d);
}

static int mac_kext_disk(rd_view *out) {
    scan_kext_dir("/Library/Extensions", out);
    scan_kext_dir("/Library/StagedExtensions/Library/Extensions", out);
    rd_view_dedup(out);
    return 0;
}

static int mac_bootargs(rd_view *out) {
    char buf[1024];
    size_t len = sizeof buf - 1;
    if (sysctlbyname("kern.bootargs", buf, &len, NULL, 0) != 0) return -1;
    buf[len < sizeof buf ? len : sizeof buf - 1] = '\0';
    char *save = NULL;
    for (char *tok = strtok_r(buf, " \t\n", &save); tok; tok = strtok_r(NULL, " \t\n", &save)) {
        char *eq = strchr(tok, '=');
        if (eq) {
            *eq = '\0';
            rd_view_add(out, tok, 0, 0, eq + 1);
        } else {
            rd_view_add(out, tok, 0, 0, "");
        }
    }
    return 0;
}

static int mac_hardening(rd_view *out) {
    char *o = run_cmd("/usr/bin/csrutil status 2>&1");
    if (o) {
        const char *st = "custom";
        if (strstr(o, "status: enabled")) st = "enabled";
        else if (strstr(o, "status: disabled")) st = "disabled";
        rd_view_add(out, "sip", 0, 1, st);
        free(o);
    }
    o = run_cmd("/usr/sbin/spctl --status 2>&1");
    if (o) {
        rd_view_add(out, "gatekeeper", 0, 1, strstr(o, "enabled") ? "enabled" : "disabled");
        free(o);
    }
    return 0;
}

static int mac_preload(rd_view *out) {
    const char *e = getenv("DYLD_INSERT_LIBRARIES");
    if (e && *e) rd_view_add(out, "env:self", 0, 0, e);
    char *o = run_cmd("/bin/launchctl getenv DYLD_INSERT_LIBRARIES 2>/dev/null");
    if (o) {
        char *t = rd_trim(o);
        if (*t) rd_view_add(out, "launchctl:DYLD_INSERT_LIBRARIES", 0, 0, t);
        free(o);
    }
    return 0;
}

/* ------------------------------------------------------------- provider */

static int mac_collect(rd_provider *p, rd_view_id id, rd_view *out, char *why, size_t whysz) {
    (void)p;
    int rc = 0;
    switch (id) {
    case RDV_SYSINFO: rc = mac_sysinfo(out); break;
    case RDV_PROC_API: rc = mac_proc_api(out); break;
    case RDV_PROC_RAW: rc = mac_proc_raw(out); break;
    case RDV_PROC_BRUTE: rc = mac_proc_brute(out); break;
    case RDV_KEXT_LOADED: rc = mac_kext_loaded(out); break;
    case RDV_KEXT_ALT: rc = mac_kext_alt(out); break;
    case RDV_KEXT_DISK: rc = mac_kext_disk(out); break;
    case RDV_BOOTARGS: rc = mac_bootargs(out); break;
    case RDV_HARDENING: rc = mac_hardening(out); break;
    case RDV_PRELOAD: rc = mac_preload(out); break;
    default:
        snprintf(why, whysz, "not applicable on Darwin");
        return RD_UNAVAIL;
    }
    if (rc != 0) {
        snprintf(why, whysz, "could not read %s on this system", rd_view_name(id));
        return RD_UNAVAIL;
    }
    return RD_OK;
}

static int mac_probe(rd_provider *p, rd_view_id id, const char *key) {
    (void)p;
    if (id != RDV_PROC_BRUTE) return -1;
    long pid = strtol(key, NULL, 10);
    if (pid <= 0) return -1;
    return pid_exists((pid_t)pid);
}

static void mac_destroy(rd_provider *p) {
    free(p->priv);
    free(p);
}

rd_provider *rd_provider_live(const rd_options *opt) {
    rd_provider *p = rd_xmalloc(sizeof *p);
    mac_t *m = rd_xmalloc(sizeof *m);
    m->opt = *opt;
    p->name = "live";
    p->priv = m;
    p->collect = mac_collect;
    p->probe = mac_probe;
    p->destroy = mac_destroy;
    return p;
}

#endif /* __APPLE__ */
