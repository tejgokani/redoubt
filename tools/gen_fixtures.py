#!/usr/bin/env python3
"""Regenerate the bundled scenarios under fixtures/.

Each scenario is an *overlay* on a clean base: it contains only the views the
rootkit changes.  Reading a scenario directory therefore answers the question
"what does this class of rootkit actually touch?".

The data models the *documented behaviour* of each rootkit family (see
docs/THREAT_MODEL.md).  It is synthetic - it was not captured from a live
infection - and docs/EVALUATION.md says what that does and does not prove.

Usage:  python3 tools/gen_fixtures.py        (run from the repo root)
"""
import os
import shutil
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")

STEXT, ETEXT = 0xFFFFFFFF81000000, 0xFFFFFFFF82000000


def fmt(v):
    return "0x%x" % v if isinstance(v, int) else str(v)


def write(d, view, rows, header=True):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, view + ".tsv"), "w") as f:
        if header:
            f.write("# key\ta\tb\textra\n")
        for r in rows:
            key, a, b, extra = (list(r) + [0, 0, ""])[:4] if len(r) < 4 else r
            f.write("%s\t%s\t%s\t%s\n" % (key, fmt(a), fmt(b), extra))


def scenario(d, **meta):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "scenario.txt"), "w") as f:
        for k in ("base", "title"):
            if k in meta:
                f.write("%s: %s\n" % (k, meta[k]))
        for line in meta.get("story", []):
            f.write("story: %s\n" % line)
        for k in ("expect", "forbid", "verdict", "limits"):
            if k in meta:
                f.write("%s: %s\n" % (k, meta[k]))


# ------------------------------------------------------------------ Linux base

MODS = [  # name, size, addr
    ("ext4", 0xD5000, 0xFFFFFFFFC0100000), ("jbd2", 0x24000, 0xFFFFFFFFC01E0000),
    ("mbcache", 0x4000, 0xFFFFFFFFC0210000), ("crc32c_intel", 0x4000, 0xFFFFFFFFC0220000),
    ("virtio_net", 0x2A000, 0xFFFFFFFFC0230000), ("virtio_blk", 0x8000, 0xFFFFFFFFC0270000),
    ("nf_tables", 0x9A000, 0xFFFFFFFFC0290000), ("nf_conntrack", 0x125000, 0xFFFFFFFFC0340000),
    ("xt_conntrack", 0x4000, 0xFFFFFFFFC0490000), ("br_netfilter", 0x1C000, 0xFFFFFFFFC04A0000),
    ("overlay", 0x21000, 0xFFFFFFFFC04D0000), ("tcp_bbr", 0x8000, 0xFFFFFFFFC0500000),
]
DISK_ONLY = ["snd", "soundcore", "usbhid", "hid", "psmouse", "floppy", "vboxdrv", "nvidia",
             "dummy_mod", "loop", "veth", "bridge", "8021q", "ip_tables", "x_tables", "fuse"]

SYSCALLS = [  # nr, name, addr
    (0, "read", 0xFFFFFFFF81301A40), (1, "write", 0xFFFFFFFF81301E10), (2, "open", 0xFFFFFFFF81302A70),
    (3, "close", 0xFFFFFFFF81303190), (4, "stat", 0xFFFFFFFF81308B20), (5, "fstat", 0xFFFFFFFF81308C50),
    (6, "lstat", 0xFFFFFFFF81308D80), (39, "getpid", 0xFFFFFFFF810A1C30), (62, "kill", 0xFFFFFFFF810B7D50),
    (78, "getdents", 0xFFFFFFFF81324C10), (217, "getdents64", 0xFFFFFFFF81324F60),
    (257, "openat", 0xFFFFFFFF813031A0), (300, "ni_syscall", 0xFFFFFFFF81020010),
]
WATCH = [
    ("filldir", 0xFFFFFFFF81324700), ("filldir64", 0xFFFFFFFF81324800), ("iterate_dir", 0xFFFFFFFF81324300),
    ("tcp4_seq_show", 0xFFFFFFFF81A55100), ("tcp6_seq_show", 0xFFFFFFFF81B02200),
    ("udp4_seq_show", 0xFFFFFFFF81A80300), ("udp6_seq_show", 0xFFFFFFFF81B10400),
    ("proc_pid_readdir", 0xFFFFFFFF8137A500), ("vfs_read", 0xFFFFFFFF812F3F00), ("commit_creds", 0xFFFFFFFF810C0900),
    ("__x64_sys_newfstatat", 0xFFFFFFFF81308F00), ("__x64_sys_init_module", 0xFFFFFFFF811A0100),
    ("__x64_sys_finit_module", 0xFFFFFFFF811A0300), ("__x64_sys_delete_module", 0xFFFFFFFF811A0500),
]
CORE_MISC = [("kprobe_ftrace_handler", 0xFFFFFFFF811E0100), ("ftrace_regs_caller", 0xFFFFFFFF81C01000),
             ("klp_ftrace_handler", 0xFFFFFFFF811F0200), ("call_direct_funcs", 0xFFFFFFFF811E0900)]
MODSYMS = [("ext4_lookup", 0xFFFFFFFFC0100A40, "ext4"), ("nf_tables_newrule", 0xFFFFFFFFC0290840, "nf_tables")]

PIDS = [(1, "systemd"), (2, "kthreadd"), (16, "rcu_sched"), (88, "jbd2/vda1-8"), (342, "systemd-journal"),
        (401, "systemd-udevd"), (655, "cron"), (671, "sshd"), (702, "nginx"), (703, "nginx"), (704, "nginx"),
        (731, "mysqld"), (812, "agetty"), (1290, "sshd"), (1302, "bash")]
PORTS = ["tcp:22", "tcp:80", "tcp:443", "tcp:3306", "udp:68", "udp:323", "tcp:33124"]
DIRS = [("/", 20, 18), ("/tmp", 4, 2), ("/var/tmp", 3, 1), ("/dev/shm", 2, 0), ("/etc", 97, 95), ("/usr", 12, 10),
        ("/usr/lib", 68, 66), ("/root", 5, 3), ("/home", 3, 1), ("/opt", 3, 1), ("/var", 13, 11), ("/boot", 4, 2)]
PROLOGUE = "f30f1efae8{:08x}554889e5415741564155415453"  # endbr64; call __fentry__; push rbp; mov rbp,rsp; ...


def linux_base(d):
    mods = [(n, s, a, "Live") for n, s, a in MODS]
    write(d, "sysinfo", [("os", 0, 0, "Linux"), ("kernel", 0, 0, "6.8.0-45-generic"), ("arch", 0, 0, "x86_64"),
                         ("euid", 0, 0, ""), ("pid_max", 4194304, 0, ""), ("kptr_restrict", 1, 0, ""), ("taint", 0, 0, "")])
    write(d, "mod.api", [(n, s, a, st) for n, s, a, st in mods])
    write(d, "mod.sysfs", [(n, 0, 0, "") for n, _, _ in MODS])
    write(d, "mod.kallsyms", [(n, 40 + i, 0, "") for i, (n, _, _) in enumerate(MODS)])
    write(d, "mod.disk", [(n, 0, 0, "kernel/%s.ko.zst" % n) for n in [m[0] for m in MODS] + DISK_ONLY])
    # extra = "syms=N": how many kallsyms symbols fall inside the region.  On kernels >= 6.11 each module owns
    # several regions (text + data ...) and other users (BPF images, ftrace trampolines) share the allocator.
    write(d, "mod.mem", [("0x%x" % a, a, s + 0x1000, "syms=%d" % (30 + i)) for i, (_, s, a) in enumerate(MODS)] + [
        ("0xffffffffc0a00000", 0xFFFFFFFFC0A00000, 0x8000, "syms=14"),    # ext4's DATA region (not its text base)
        ("0xffffffffc0b00000", 0xFFFFFFFFC0B00000, 0x201000, "syms=7"),   # eBPF JIT pack [bpf]
        ("0xffffffffc0c00000", 0xFFFFFFFFC0C00000, 0x2000, "syms=1"),     # ftrace trampoline [__builtin__ftrace]
        ("0xffffffffc0e00000", 0xFFFFFFFFC0E00000, 0x2000, "syms=0 secs=3"),  # anonymous rodata: named only by /sys/module/*/sections
    ])
    write(d, "dmesg.mods", [])
    ks = [("_stext", STEXT, 0, ""), ("_etext", ETEXT, 0, ""), ("__x64_sys_ni_syscall", 0xFFFFFFFF81020010, 0, "")]
    ks += [("__x64_sys_" + n, a, 0, "") for _, n, a in SYSCALLS if n != "ni_syscall"]
    ks += [(n, a, 0, "") for n, a in WATCH + CORE_MISC]
    ks += [(n, a, 0, m) for n, a, m in MODSYMS]
    write(d, "ksyms", ks)
    write(d, "syscalls", [(str(nr), a, 0, "__x64_sys_" + n) for nr, n, a in SYSCALLS])
    write(d, "ftrace", [
        ("schedule_tail", 1, 0, "(1) R  tramp: ftrace_regs_caller+0x0/0x54 (call_direct_funcs+0x0/0x30)"),
        ("__x64_sys_openat", 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (kprobe_ftrace_handler+0x0/0x1d0)"),
    ])
    write(d, "prologues", [(n, a, 0, PROLOGUE.format(0x1234 + i)) for i, (n, a) in enumerate(WATCH)])
    write(d, "proc.api", [(str(p), 0, 0, "") for p, _ in PIDS])
    write(d, "proc.raw", [(str(p), 0, 0, "") for p, _ in PIDS])
    write(d, "proc.brute", [(str(p), 0, 0, c) for p, c in PIDS])
    write(d, "net.listed", [(p, 0, 0, "") for p in PORTS])
    write(d, "net.bound", [(p, 0, 0, "") for p in PORTS])
    write(d, "dirs", [(p, n, s, "fs=ok") for p, n, s in DIRS])
    write(d, "probes", [])
    write(d, "preload", [])
    write(d, "hardening", [("modules_disabled", 0, 1, "0"), ("sig_enforce", 0, 1, "Y"), ("lockdown", 0, 1, "integrity"),
                           ("kptr_restrict", 1, 1, "1"), ("dmesg_restrict", 1, 1, "1"), ("dev_kmem", 0, 1, "")])
    scenario(d, title="clean Linux base (shared by every Linux scenario)")


def read_rows(d, view):
    rows = []
    with open(os.path.join(d, view + ".tsv")) as f:
        for ln in f:
            if ln.startswith("#") or not ln.strip():
                continue
            k, a, b, e = ln.rstrip("\n").split("\t", 3)
            rows.append((k, int(a, 0), int(b, 0), e))
    return rows


def jmp_rel32(from_addr, to_addr):
    return "e9" + struct.pack("<i", to_addr - (from_addr + 5)).hex()


def main():
    # Regenerate only the modelled scenarios. Directories named real-* are captures from live kernels
    # (made with `redoubt snapshot`) and are precious: never delete them.
    if os.path.isdir(ROOT):
        for name in os.listdir(ROOT):
            if not name.startswith("real-"):
                shutil.rmtree(os.path.join(ROOT, name))
    base = os.path.join(ROOT, "_base-linux")
    linux_base(base)
    B = "../_base-linux"

    # ---- controls ----------------------------------------------------------
    scenario(os.path.join(ROOT, "clean-linux"), base=B, title="Healthy Linux server (false-positive control)",
             story=["A normal Ubuntu-style server: nginx, sshd, MySQL, 12 modules. Every view agrees with every other.",
                    "A correct detector must say CLEAN. (It still prints hardening advice: posture never changes the verdict.)"],
             verdict="CLEAN")

    # ---- 1. Diamorphine-style ---------------------------------------------
    d = os.path.join(ROOT, "diamorphine-lkm")
    orphan = 0xFFFFFFFFC0600000
    write(d, "sysinfo", [("os", 0, 0, "Linux"), ("kernel", 0, 0, "6.8.0-45-generic"), ("arch", 0, 0, "x86_64"),
                         ("euid", 0, 0, ""), ("pid_max", 4194304, 0, ""), ("kptr_restrict", 1, 0, ""),
                         ("taint", 12288, 0, "")])   # O (out-of-tree) + E (unsigned)
    write(d, "dmesg.mods", [("diamorphine", 0, 0, "out-of-tree module taints kernel")])
    write(d, "mod.mem", read_rows(os.path.join(ROOT, "_base-linux"), "mod.mem") +
          [("0x%x" % orphan, orphan, 0x6000, "syms=0")])
    sc = []
    for nr, n, a in SYSCALLS:
        if nr in (62, 78, 217):
            a2 = orphan + {62: 0x120, 78: 0x240, 217: 0x360}[nr]
            sc.append((str(nr), a2, 0, "?"))
        else:
            sc.append((str(nr), a, 0, "__x64_sys_" + n))
    write(d, "syscalls", sc)
    write(d, "proc.brute", read_rows(os.path.join(ROOT, "_base-linux"), "proc.brute") + [("4242", 0, 0, "bash")])
    scenario(d, base=B, title="Diamorphine-style LKM: syscall hooks + a module that erases itself everywhere",
             story=["Modelled on the documented behaviour of Diamorphine: an LKM that overwrites the kill/getdents/getdents64",
                    "syscall-table entries, hides a process ('kill -31'), and unlinks itself from the module list *and* sysfs.",
                    "lsmod shows nothing, /sys/module shows nothing, `ps` shows nothing - yet the kernel still knows."],
             expect="mod-orphan-mem,mod-taint,syscall-table,proc-xview,known-iocs", verdict="COMPROMISED",
             limits="mod-xview stays silent: this rootkit removed its sysfs node too. It is caught by kernel-memory accounting, "
                    "the syscall table, taint/dmesg residue and direct pid probing instead.")

    # ---- 2. ftrace-based (Singularity / KoviD style) -----------------------
    d = os.path.join(ROOT, "ftrace-lkm")
    orphan = 0xFFFFFFFFC0700000
    write(d, "sysinfo", [("os", 0, 0, "Linux"), ("kernel", 0, 0, "6.8.0-45-generic"), ("arch", 0, 0, "x86_64"),
                         ("euid", 0, 0, ""), ("pid_max", 4194304, 0, ""), ("kptr_restrict", 1, 0, ""),
                         ("taint", 12288, 0, "")])
    write(d, "dmesg.mods", [("hid_shim", 0, 0, "module signature verification failed")])
    write(d, "mod.mem", read_rows(os.path.join(ROOT, "_base-linux"), "mod.mem") +
          [("0x%x" % orphan, orphan, 0x4000, "syms=0")])
    hooks = [("__x64_sys_getdents64", "hook_getdents64"), ("__x64_sys_kill", "hook_kill"),
             ("tcp4_seq_show", "hook_tcp4_seq_show"), ("filldir64", "hook_filldir64")]
    write(d, "ftrace", read_rows(os.path.join(ROOT, "_base-linux"), "ftrace") +
          [(fn, 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (%s+0x0/0xe0 [hid_shim])" % cb) for fn, cb in hooks])
    write(d, "proc.brute", read_rows(os.path.join(ROOT, "_base-linux"), "proc.brute") + [("3901", 0, 0, "sh")])
    write(d, "net.bound", [(p, 0, 0, "") for p in PORTS] + [("tcp:4444", 0, 0, "")])
    write(d, "dirs", [(p, (n + 1 if p == "/dev/shm" else n), s, "fs=ok") for p, n, s in DIRS])
    scenario(d, base=B, title="ftrace-hooking LKM (Singularity / KoviD style, modern kernels)",
             story=["Modern rootkits skip the syscall table (it is read-only and monitored) and hijack functions with ftrace instead:",
                    "getdents64 and kill to hide files and processes, tcp4_seq_show to hide a listening port.",
                    "The module hides from lsmod and sysfs - but every hook callback still names the module that owns it."],
             expect="ftrace-hooks,mod-orphan-mem,mod-taint,proc-xview,net-xview,fs-xview", verdict="COMPROMISED",
             limits="The syscall table is intact here (ftrace does not touch it), so syscall-table correctly stays quiet.")

    # ---- 3. inline-hooking (Suterusu style) --------------------------------
    d = os.path.join(ROOT, "inline-hook-lkm")
    base_dir = os.path.join(ROOT, "_base-linux")
    mbase, msize = 0xFFFFFFFFC0800000, 0x7000
    write(d, "sysinfo", [("os", 0, 0, "Linux"), ("kernel", 0, 0, "6.8.0-45-generic"), ("arch", 0, 0, "x86_64"),
                         ("euid", 0, 0, ""), ("pid_max", 4194304, 0, ""), ("kptr_restrict", 1, 0, ""),
                         ("taint", 12288, 0, "")])
    write(d, "mod.sysfs", read_rows(base_dir, "mod.sysfs") + [("snd_hda_shim", 0, 0, "OE")])
    write(d, "mod.kallsyms", read_rows(base_dir, "mod.kallsyms") + [("snd_hda_shim", 12, 0, "")])
    write(d, "mod.mem", read_rows(base_dir, "mod.mem") + [("0x%x" % mbase, mbase, msize + 0x1000, "syms=12")])
    write(d, "ksyms", read_rows(base_dir, "ksyms") + [("hook_filldir64", mbase + 0x40, 0, "snd_hda_shim"),
                                                       ("hook_tcp4_seq_show", mbase + 0x140, 0, "snd_hda_shim")])
    pro = []
    for i, (n, a) in enumerate(WATCH):
        if n == "filldir64":
            pro.append((n, a, 0, jmp_rel32(a, mbase + 0x40) + "90909090554889e5415741564155"))
        elif n == "tcp4_seq_show":
            pro.append((n, a, 0, jmp_rel32(a, mbase + 0x140) + "90909090554889e5415741564155"))
        else:
            pro.append((n, a, 0, PROLOGUE.format(0x1234 + i)))
    write(d, "prologues", pro)
    write(d, "net.bound", [(p, 0, 0, "") for p in PORTS] + [("tcp:31337", 0, 0, "")])
    scenario(d, base=B, title="Inline-hooking LKM (Suterusu style): jumps patched over kernel function prologues",
             story=["Instead of the syscall table, this rootkit overwrites the first bytes of filldir64 (directory listing) and",
                    "tcp4_seq_show (socket listing) with a `jmp` into its own module. It hides from lsmod by filtering the",
                    "/proc/modules output rather than unlinking itself, so sysfs and kallsyms (which walk the kernel's own",
                    "lists) still remember the module - a half-hearted hide, and a very common one."],
             expect="mod-xview,inline-hooks,net-xview", verdict="COMPROMISED",
             limits="Its name ('snd_hda_shim') matches no signature, so known-iocs correctly stays quiet: detection is behavioural.")

    # ---- 4. userland (LD_PRELOAD) -----------------------------------------
    d = os.path.join(ROOT, "userland-preload")
    write(d, "preload", [("ld.so.preload", 0, 0, "/dev/shm/.lib/libc.so.7")])
    write(d, "proc.raw", read_rows(base_dir, "proc.raw") + [("5150", 0, 0, "")])
    write(d, "proc.brute", read_rows(base_dir, "proc.brute") + [("5150", 0, 0, "minerd")])
    write(d, "probes", [("/etc/ld.so.preload", 1, 0, "user-space preload rootkits")])
    scenario(d, base=B, title="Userland rootkit via /etc/ld.so.preload (Azazel / Jynx style) - no kernel module at all",
             story=["A shared library preloaded into every process hooks readdir()/open(), so `ps`, `ls` and `top` lie.",
                    "There is nothing wrong in the kernel - and Redoubt says so - but the raw getdents64 view, a direct stat()",
                    "of /etc/ld.so.preload, and the pid brute-force expose the lie in seconds."],
             expect="preload,proc-xview,fs-xview", verdict="COMPROMISED",
             limits="All kernel-integrity checks correctly report clean: the compromise is entirely in user space.")

    # ---- 5. stealth limit --------------------------------------------------
    d = os.path.join(ROOT, "stealth-limit")
    write(d, "sysinfo", [("os", 0, 0, "Linux"), ("kernel", 0, 0, "6.8.0-45-generic"), ("arch", 0, 0, "x86_64"),
                         ("euid", 0, 0, ""), ("pid_max", 4194304, 0, ""), ("kptr_restrict", 1, 0, ""),
                         ("taint", 12288, 0, "")])
    write(d, "dmesg.mods", [("kthread_helper", 0, 0, "out-of-tree module taints kernel")])
    scenario(d, base=B, title="Limit case: a rootkit that lies consistently in every view user space can read",
             story=["This rootkit hooks kill, getdents, sched_getaffinity, stat, bind and vmallocinfo, restores the syscall table,",
                    "and erases itself from every list. From inside the machine there is no discrepancy left to find.",
                    "All that leaks is what it could not un-say: the kernel's taint flag and one line in the kernel log."],
             expect="mod-taint", verdict="SUSPICIOUS",
             limits="The hidden process/port/hooks in this scenario are invisible to ANY user-space tool. Redoubt can only "
                    "raise SUSPICIOUS from residue. Detecting this class needs an out-of-band memory image - see docs/THREAT_MODEL.md.")

    # ---- 6. false-positive traps ------------------------------------------
    d = os.path.join(ROOT, "false-positive-traps")
    write(d, "sysinfo", [("os", 0, 0, "Linux"), ("kernel", 0, 0, "6.8.0-45-generic"), ("arch", 0, 0, "x86_64"),
                         ("euid", 0, 0, ""), ("pid_max", 4194304, 0, ""), ("kptr_restrict", 1, 0, ""),
                         ("taint", 4097, 0, "")])   # P (proprietary) + O (out-of-tree): NVIDIA driver
    nv = 0xFFFFFFFFC0900000
    write(d, "mod.sysfs", read_rows(base_dir, "mod.sysfs") + [("nvidia", 0, 0, "PO"), ("dummy_mod", 0, 0, "")])
    write(d, "mod.kallsyms", read_rows(base_dir, "mod.kallsyms") + [("nvidia", 900, 0, ""), ("dummy_mod", 3, 0, "")])
    write(d, "mod.mem", read_rows(base_dir, "mod.mem") + [("0x%x" % nv, nv, 0x61000, "syms=900"),
                                                         ("0xffffffffc0980000", 0xFFFFFFFFC0980000, 0x5000, "syms=3"),
                                                         # a module's init-text region, freed right after init: symbol-less and gone on re-read
                                                         ("0xffffffffc0d00000", 0xFFFFFFFFC0D00000, 0x3000, "syms=0")])
    write(d, "mod.mem.recheck", read_rows(base_dir, "mod.mem") + [("0x%x" % nv, nv, 0x61000, "syms=900"),
                                                                 ("0xffffffffc0980000", 0xFFFFFFFFC0980000, 0x5000, "syms=3")])
    write(d, "dmesg.mods", [("nvidia", 0, 0, "module license taints kernel")])
    # race 1: dummy_mod finishes loading between our reads -> absent from the FIRST mod.api read only
    write(d, "mod.api", read_rows(base_dir, "mod.api") + [("nvidia", 0x60000, nv, "Live")])
    write(d, "mod.api.recheck", read_rows(base_dir, "mod.api") + [("nvidia", 0x60000, nv, "Live"), ("dummy_mod", 0x4000, 0xFFFFFFFFC0980000, "Live")])
    # race 2: a short-lived process (9001) and one that appears on relisting (9002)
    write(d, "proc.brute", read_rows(base_dir, "proc.brute") + [("9001", 0, 0, "sh"), ("9002", 0, 0, "make")])
    write(d, "proc.brute.probe", read_rows(base_dir, "proc.brute") + [("9002", 0, 0, "make")])   # 9001 has exited
    write(d, "proc.api.recheck", read_rows(base_dir, "proc.api") + [("9002", 0, 0, "")])
    # race 3: a bind-only socket that closes before we re-probe
    write(d, "net.bound", [(p, 0, 0, "") for p in PORTS] + [("tcp:35001", 0, 0, "")])
    write(d, "net.bound.probe", [(p, 0, 0, "") for p in PORTS])
    # benign: livepatch (core callback) with IPMODIFY on a sensitive function
    write(d, "ftrace", read_rows(base_dir, "ftrace") +
          [("__x64_sys_getdents64", 1, 0, "(1) R I  tramp: ftrace_regs_caller+0x0/0x54 (klp_ftrace_handler+0x0/0x110)")])
    scenario(d, base=B, title="Decoys: things that look like rootkits but are not (false-positive traps)",
             story=["NVIDIA's proprietary driver taints the kernel (P and O). A kernel livepatch hooks getdents64 through ftrace.",
                    "Module data regions, an eBPF image and an ftrace trampoline share module address space but are not modules.",
                    "During the scan a module finishes loading, a process is born and another dies, and a socket closes.",
                    "Each of these creates a *momentary* cross-view mismatch. A naive diff tool cries wolf on all of them;",
                    "Redoubt re-samples the racy views and re-probes each candidate, so none of them survive."],
             verdict="CLEAN", forbid="mod-xview,mod-orphan-mem,proc-xview,net-xview,ftrace-hooks,mod-taint,syscall-table",
             limits="Confidence calibration is the point: this scenario must stay CLEAN or the tool is unusable in production.")

    # ---- macOS -----------------------------------------------------------
    mb = os.path.join(ROOT, "_base-macos")
    apple = ["com.apple.kpi.bsd", "com.apple.kpi.iokit", "com.apple.kpi.libkern", "com.apple.kpi.mach",
             "com.apple.kec.corecrypto", "com.apple.iokit.IOCryptoAcceleratorFamily", "com.apple.driver.AppleMobileFileIntegrity"]
    mp = [(1, "launchd"), (88, "logd"), (95, "UserEventAgent"), (101, "kernelmanagerd"), (312, "WindowServer"),
          (540, "Finder"), (612, "Terminal"), (655, "zsh")]
    write(mb, "sysinfo", [("os", 0, 0, "Darwin"), ("kernel", 0, 0, "25.5.0"), ("arch", 0, 0, "arm64"),
                          ("euid", 501, 0, ""), ("pid_max", 99999, 0, "")])
    write(mb, "proc.api", [(str(p), 0, 0, "") for p, _ in mp])
    write(mb, "proc.raw", [(str(p), 0, 0, "") for p, _ in mp])
    write(mb, "proc.brute", [(str(p), 0, 0, c) for p, c in mp])
    write(mb, "kext.loaded", [(a, 0x1000, 0xFFFFFE0007C9B550, "25.5.0") for a in apple])
    write(mb, "kext.alt", [(a, 0, 0, "ioreg") for a in apple[:4]])
    write(mb, "kext.disk", [("com.highpoint-tech.kext.HighPointIOP", 0, 0, "/Library/Extensions/HighPointIOP.kext"),
                            ("com.joshuawise.kexts.HoRNDIS", 0, 0, "/Library/Extensions/HoRNDIS.kext")])
    write(mb, "bootargs", [])
    write(mb, "preload", [])
    write(mb, "hardening", [("sip", 0, 1, "enabled"), ("gatekeeper", 0, 1, "enabled")])
    scenario(mb, title="clean macOS base")

    scenario(os.path.join(ROOT, "clean-macos"), base="../_base-macos", title="Healthy macOS laptop (false-positive control)",
             story=["Modelled on the machine this project was developed on: SIP on, no third-party kernel extensions loaded.",
                    "Two old third-party kexts sit on disk, not loaded - the inventory correctly treats them as inert."],
             verdict="CLEAN")

    d = os.path.join(ROOT, "macos-kext-implant")
    write(d, "kext.loaded", read_rows(mb, "kext.loaded") + [("com.example.netfilter", 0x8000, 0xFFFFFE0008000000, "1.0.2")])
    write(d, "kext.alt", read_rows(mb, "kext.alt") + [("com.example.hidden.driver", 0, 0, "ioreg")])
    write(d, "bootargs", [("amfi_get_out_of_my_way", 0, 0, "1")])
    write(d, "hardening", [("sip", 0, 1, "disabled"), ("gatekeeper", 0, 1, "enabled")])
    write(d, "preload", [("launchctl:DYLD_INSERT_LIBRARIES", 0, 0, "/tmp/.hook.dylib")])
    write(d, "proc.brute", read_rows(mb, "proc.brute") + [("7331", 0, 0, "keylogd")])
    scenario(d, base="../_base-macos", title="macOS kernel-extension implant with SIP off and code-signing disabled",
             story=["An attacker reduced security (SIP off, AMFI disabled via boot-args), loaded an unregistered kext,",
                    "a second driver that kmutil does not list but IOKit does, injected a dylib system-wide, and hid a process."],
             expect="kext-inventory,boot-integrity,preload,proc-xview", verdict="COMPROMISED",
             limits="Apple-silicon macOS makes kernel extensions rare and hard to load; this models the residual risk.")

    print("fixtures regenerated under", os.path.normpath(ROOT))


if __name__ == "__main__":
    main()
