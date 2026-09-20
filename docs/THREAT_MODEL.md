# Threat model

## What a kernel-module rootkit is

A Linux Kernel Module (LKM) rootkit, or on macOS a malicious kernel extension
(kext), is code that runs with the same privilege as the operating system
itself. Once loaded it can rewrite any answer the kernel gives to any program,
including the shell you're typing into. It is installed after an attacker
already has root — it is a *persistence and stealth* tool, not an initial
foothold — which is exactly why detecting it is hard: the detector and the
rootkit run on the same compromised kernel.

Redoubt targets three public families of technique, in order of how deep they
reach:

| Layer | Technique | Example family | Redoubt's answer |
|---|---|---|---|
| Kernel code | syscall-table patching | Diamorphine, Adore, Knark | [`syscall-table`](../src/checks/chk_kernel.c) reads the real table from `/proc/kcore` |
| Kernel code | `ftrace`/inline hooking | Reptile, Suterusu, KoviD | [`ftrace-hooks`](../src/checks/chk_kernel.c), [`inline-hooks`](../src/checks/chk_kernel.c) read live function prologues |
| Kernel bookkeeping | self-unlinking from the module list | almost all of the above | [`mod-xview`](../src/checks/chk_modules.c), [`mod-orphan-mem`](../src/checks/chk_modules.c), [`mod-taint`](../src/checks/chk_modules.c) |
| User-visible objects | filtering `getdents`/`kill`/`bind` results | any of the above, plus pure user-space kits (Azazel, Jynx, BEURK) | [`proc-xview`](../src/checks/chk_userland.c), [`net-xview`](../src/checks/chk_userland.c), [`fs-xview`](../src/checks/chk_userland.c) |
| Install layer | `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` | user-space kits | [`preload`](../src/checks/chk_userland.c) |
| macOS specific | unregistered/hidden kexts, SIP/AMFI tampering | — | [`kext-inventory`](../src/checks/chk_macos.c), [`boot-integrity`](../src/checks/chk_macos.c) |

See [`src/intel.c`](../src/intel.c) for the specific documented families
(Diamorphine, Reptile, Adore, Knark, Suterusu, KBeast, Singularity, KoviD, ...)
and the kernel functions each check actually reads.

## The core assumption, stated plainly

**A rootkit that hides an object has to lie every time that object is asked
about, through every path the kernel exposes for asking.** It hides the
process from `ps` by filtering `/proc`; it does not usually also patch
`sched_getaffinity()`, the raw `getdents64` syscall, and the socket bind path,
because that is far more code to write and far more places to make a mistake.
Redoubt's checks are built by asking the same question through two or more of
those paths and reporting when they disagree.

This assumption can be **false** for a sufficiently thorough rootkit. Redoubt
is explicit about that rather than hiding it behind a green checkmark — see
"What CLEAN does not mean" below and the `stealth-limit` scenario in
`docs/EVALUATION.md`.

## Trust boundary

Redoubt is a **user-space, on-host, best-effort detector**. It trusts:

- the CPU and firmware (no defence against a hypervisor/firmware implant);
- the parts of the kernel that are *not yet compromised* enough to answer at
  least one of the two views a check compares;
- its own binary and the fixture/snapshot files it is told to read.

It explicitly does **not** trust: `/proc/modules`, `lsmod`, `ps`, `netstat`,
`ls`, or any other single listing — that is the entire point of cross-viewing.

## What CLEAN does not mean

A `CLEAN` verdict means: *every check that could run found no disagreement
between its independent views.* It does not mean the system has no rootkit.
Three specific gaps, honestly:

1. **A check that could not run is not silently "passed".** Redoubt reports
   `SKIPPED` with a reason (e.g. "not root", "`/proc/kcore` locked down") and
   a `CLEAN` verdict says explicitly how many checks that covers (`scan`'s
   footer, `rd_verdict.skipped`).
2. **A rootkit that hooks every single path a check reads is invisible to
   that check by construction.** The `stealth-limit` fixture scenario models
   exactly this and is scored `SUSPICIOUS`, not `CLEAN` — but only because
   the modelled rootkit forgot two pieces of residue: the kernel's taint flag
   and one line in the kernel log. Those are *not* hard to erase for a
   rootkit that runs in the kernel; a more careful one would scrub both and
   this scenario would then score `CLEAN`. Full coverage against this class
   needs an **out-of-band** view: a memory image taken by a hypervisor, a
   baseboard management controller, or a second machine reading the disk
   offline. That is outside what any on-host tool, including this one, can
   promise — the `--baseline` and `snapshot` commands exist to make that
   comparison easy to *set up*, not to fake having it live.
3. **Name/path signature matching (`known-iocs`) only catches unmodified,
   public tools.** Renaming a `.ko` file defeats it entirely. It is included
   because it is cheap and catches real-world laziness, not as a primary
   control — every finding it produces says so.

## Non-goals

- **Prevention.** Redoubt does not block module loads (see the `hardening`
  check for how to configure prevention with existing kernel features:
  `modules_disabled`, lockdown, module signing).
- **Automatic remediation.** It never unloads a module, kills a process, or
  deletes a file — see `fix` text on every finding for why (an unclean
  `rmmod` of a rootkit routinely panics the kernel or corrupts its accounting
  further; the recommended path is always isolate-and-rebuild).
- **A general EDR/IDS.** No persistence, no daemon, no network telemetry.
- **Hypervisor/firmware detection**, or defending against an attacker who
  controls the machine Redoubt itself runs on (if they can tamper with
  Redoubt's own binary, they can make it lie about its findings — ship
  it read-only, or run it from external, known-good media).
