# redoubt

**A kernel-module rootkit detector for Linux and macOS.** Plain C, no
dependencies, no VM required. It doesn't trust any single listing the kernel
gives you (`lsmod`, `ps`, `netstat`, `ls`) — it asks the same question through
two or more independent paths and reports when they disagree, which is
exactly the position a rootkit that hides things is in: it has to lie
*consistently*, everywhere, or get caught.

```
$ ./redoubt demo diamorphine-lkm

 SCENARIO diamorphine-lkm  Diamorphine-style LKM: syscall hooks + a module that erases itself everywhere
  ...

CHECKS
  [!!!!] mod-orphan-mem   Orphaned module memory                       1 finding
  [!!!!] mod-taint        Taint & kernel-log accounting                2 findings
  [!!!!] syscall-table    Syscall table integrity                      1 finding
  [!!!!] proc-xview       Hidden-process cross-view                    1 finding
  [!!!!] known-iocs       Known rootkit indicators                     1 finding
  ...

  1. [CRITICAL  96%] 3 syscall-table entries redirected outside kernel text
     ...

VERDICT  COMPROMISED   risk score 100/100   coverage 13/14 checks   5 independent checks flagging
```

## Why this exists

LKM rootkits (Diamorphine, Reptile, Adore, ...) and their macOS-kext
equivalents run at kernel privilege and rewrite what the kernel tells every
other program — including the tools an administrator would normally reach
for. Redoubt's answer is structural, not a signature list: collect the same
fact through several paths that a rootkit would have to hook *separately*
(the module list via `/proc/modules` **and** `/sys/module` **and**
`kallsyms`; a process via the libc listing **and** the raw `getdents64`
syscall **and** a `kill(pid,0)` probe; a port via `/proc/net/*` **and**
`bind()`), then flag the disagreements. See
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for exactly what this does
and does not catch — read that before trusting a CLEAN result.

## Quick start

```bash
make            # builds ./redoubt  (plain C11, no dependencies)
make test       # 79 unit assertions + the 9-scenario detection matrix
./redoubt demo   # walk through the bundled rootkit scenarios, offline
sudo ./redoubt scan   # scan THIS machine (root recommended: kallsyms, /proc/kcore, dmesg)
```

New to the project? **[docs/DEMO.md](docs/DEMO.md)** is a ready-to-run
presentation script, including a demo that hides a real live process with a
real hook and catches it live.

## Commands

| | |
|---|---|
| `redoubt scan` | scan this machine (default command) |
| `redoubt demo [name\|all]` | replay a bundled scenario through the real engine, offline |
| `redoubt eval [dir]` | run every scenario, print the pass/fail detection matrix |
| `redoubt snapshot DIR` | save every kernel view of this machine to `DIR/` (evidence bundle / `--baseline` input) |
| `redoubt list-checks` | list the 16 detection checks and what each compares |

Useful flags: `--from DIR` (analyse a snapshot instead of live), `--baseline
DIR` (diff against a known-good snapshot), `--simulate SPEC` (inject a
rootkit-like lie into live data for a demo — see `docs/DEMO.md`), `--only`/
`--skip` (check id filters), `--json`, `--fail-on SEV`. `redoubt --help` for
the rest.

## What it checks

16 checks across 5 layers — module-list integrity, kernel-code integrity
(syscall table / ftrace / inline hooks), hidden user-space objects
(processes / ports / files), the dynamic-linker injection path, and macOS
kernel-extension inventory — plus a signature/IOC check and a hardening-
posture report. Full table with source files:
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#what-a-kernel-module-rootkit-is)**.
Architecture (how a check, a view, and a provider fit together):
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Evidence this actually works

- `make eval` — 9 scenarios (6 rootkit families + 3 clean/decoy controls)
  replayed through the production detection engine; a dedicated unit test
  proves the decoy scenario is clean *because of* the anti-race logic, not by
  luck.
- `make unit` — 79 assertions pinning down the exact severity/confidence
  decisions (boundary conditions, livepatch vs. rootkit ftrace hooks, race
  handling).
- A **real** live demo: a minimal user-space hook
  (`tests/hooks/hide_pid.c`) actually hides a running process via
  `DYLD_INSERT_LIBRARIES`/`LD_PRELOAD`, and `redoubt scan` catches it on the
  real, live machine — not a fixture.

Full writeup, including exactly what each piece of evidence proves and does
not prove: **[docs/EVALUATION.md](docs/EVALUATION.md)**.

## Contributing

Checks are pure functions over data (`rd_view` in, `rd_finding` out) with
zero OS-specific code — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for how
to add one, and `tools/gen_fixtures.py` for how the bundled scenarios are
generated.

## License

MIT — see [LICENSE](LICENSE).
