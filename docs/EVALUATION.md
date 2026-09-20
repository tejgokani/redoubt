# Evaluation

Two different kinds of evidence back this project, and they prove different
things. Do not blur them when presenting.

## 1. The scenario matrix (`redoubt eval`) — proves the *logic* is correct

```bash
make eval
# or:  ./redoubt eval fixtures
```

`fixtures/` holds ten scenarios (`fixtures/*/scenario.txt`), each a
directory of `<view>.tsv` files that stand in for what a live scan would have
read. `eval` replays every scenario through the **exact same detection
engine** (`src/checks/*.c`, `src/engine.c`) used for a live scan, then checks
the result against that scenario's declared `expect:`/`forbid:`/`verdict:`.

| # | Scenario | Models | Must produce |
|---|---|---|---|
| 1 | `clean-linux` | a normal server | `CLEAN`, 0 findings |
| 2 | `clean-macos` | a normal laptop | `CLEAN`, 0 findings |
| 3 | `diamorphine-lkm` | syscall-table hooking + full self-hide | `COMPROMISED` via 5 independent checks |
| 4 | `ftrace-lkm` | modern ftrace-hook rootkit (Singularity/KoviD-style) | `COMPROMISED` via 6 checks |
| 5 | `inline-hook-lkm` | inline-patching rootkit (Suterusu-style) | `COMPROMISED` via 3 checks |
| 6 | `userland-preload` | pure user-space rootkit, **no kernel involvement** | `COMPROMISED`; all kernel-integrity checks correctly stay quiet |
| 7 | `macos-kext-implant` | unregistered kext + SIP/AMFI tampering | `COMPROMISED` via 4 checks |
| 8 | `stealth-limit` | a rootkit that scrubs every view *except* taint/dmesg residue | `SUSPICIOUS` (deliberately not `COMPROMISED` — see below) |
| 9 | `false-positive-traps` | 6 things that *look* like rootkits but aren't (see below) | `CLEAN`, and specifically none of the 6 decoy checks fire |
| 10 | `real-linux-6.17-azure` | **not modelled** — a real snapshot captured by `redoubt snapshot` on an unmodified kernel | `CLEAN` (real-data false-positive guard) |

Run it: `./redoubt eval fixtures` prints a pass/fail matrix and exits 1 on
any miss. `make test` runs this plus the unit suite.

### Scenario 9 in detail — this is the check that matters most

A detector that flags everything unusual is useless in production. Scenario
9 bundles six specific decoys and the checks are proven quiet on all of them:

1. **NVIDIA's proprietary driver** taints the kernel (`P`+`O` flags) — normal.
2. **A kernel livepatch** hooks `getdents64` via ftrace with `IPMODIFY` set —
   legitimate infrastructure, not a rootkit. The check keys on *who owns the
   callback*: here it is the kernel's own `klp_ftrace_handler` (core code),
   not a module-owned function, so it is left alone.
3. **A module finishes loading mid-scan** — present on the second
   `/proc/modules` read but not the first.
4/5. **A process is born, and another exits**, between the two process
   listings Redoubt takes.
6. **A socket that is `bind()`ed but never `listen()`ed** closes before the
   re-probe — indistinguishable from a hidden port on a single sample.

`tests/test_unit.c`'s `test_false_positive_traps_are_real` proves this isn't
an accident: it re-runs scenario 9 through a **mutated provider with the
re-sampling and re-probing logic disabled** (`naive_collect` in that file)
and asserts the decoys *do* fire in that configuration. That is the evidence
that the CLEAN verdict on scenario 9 comes from the race-handling logic
actually working, not from the scenario being too easy.

### What this does *not* prove

The `.tsv` fixtures are **modelled from each rootkit family's documented
behaviour** (source repos / write-ups cited in `src/intel.c` and each
scenario's `story:` text), not captured from a live infected machine. `eval`
proves: given inputs shaped like what these rootkits are documented to
produce, the comparison and scoring logic reaches the right verdict, and does
so *only* because of the specific anti-race machinery this project built (not
by accident, and not by being too lenient — see §3). It does not prove the
live collectors (`src/platform/linux.c`) parse a real, messy `/proc/kcore` or
a real ftrace log byte-for-byte correctly — §2 covers that.

## 2. Live testing on real machines — proves the *collectors* work

Everything below was actually run, not simulated.

**macOS (Apple M-series, this repo's dev machine):**
```
./redoubt scan                    # CLEAN, all 5 applicable checks ran without sudo
./redoubt list-checks
```
Then a **real** minimal user-space hook (`tests/hooks/hide_pid.c`, built by
`make hooks`) was loaded with `DYLD_INSERT_LIBRARIES` to hide one live PID
from `proc_listpids`, and the same scan was re-run:

```
HIDE_PID=<pid> DYLD_INSERT_LIBRARIES=build/libhide.dylib ./redoubt scan
```
Result: `proc-xview` correctly reported `Hidden process: pid <pid>` at
HIGH/90%, `preload` flagged the injected library, and the verdict flipped
from `CLEAN` to `COMPROMISED`, exit code 1. This is a real hide, detected by
the real macOS collector, not a fixture. See `docs/DEMO.md` for the exact
transcript and how to reproduce it live in front of a reviewer.

**Linux:** every push runs `sudo ./redoubt scan` against a real, unmodified
kernel on GitHub's `ubuntu-latest` runner (`.github/workflows/ci.yml`) — not
a fixture, not a container pretending to be a kernel, an actual `uname -r`
Linux box with ~60 real modules, real eBPF programs from the runner's own
tooling, and real ftrace/kprobe infrastructure. CI **fails the build** if
that scan is not `CLEAN` with zero skipped checks, so this is enforced on
every commit, not a one-time claim. See the "Live scan" step's log on any
run for the exact output.

Getting there took three rounds of real bugs the fixtures could never have
caught, because the fixtures are only as good as the assumptions used to
write them:

1. **`ftrace-hooks` false-positive**, first real run: it read `enabled_functions`
   lines like `ip_send_skb (1) R  tramp: 0xffffffffc0471000
   (kprobe_ftrace_handler+0x0/0x1c0)` and treated the raw trampoline address
   as the hook owner — but that address is ftrace's *own* allocation, common
   to every hook; the actual owner is the name in parentheses. Fixed by
   parsing past the `tramp:` field. (`src/checks/chk_kernel.c`)
2. **`mod-xview` false-positive**: a real kernel's `kallsyms` tags ftrace's
   own trampoline pool as pseudo-module `[__builtin__ftrace]`, which is not a
   loadable module and was never going to appear in `/proc/modules`. Fixed by
   an explicit pseudo-module allowlist. (`src/intel.c`)
3. **`mod-orphan-mem` false-positive, twice** — the deepest one. The check's
   entire premise (`/proc/vmallocinfo` entries attributed to a module-loading
   function are module memory) turned out to rest on a caller name
   (`move_module`) that Linux's ~6.11 "execmem" rework renamed to a generic
   `execmem_alloc` shared by module loading, eBPF JIT, ftrace trampolines and
   kprobe stubs alike — so on the real 6.17 runner the check first flagged
   **64 unrelated regions**. Switching to "does kallsyms name anything in
   this range" as the independent check cut that to **26** — all one-page
   regions of a module's anonymous rodata, which has no symbol but *is*
   named by the owning module's `/sys/module/<name>/sections/` files. Using
   both sources brought it to zero. Both fixes are `git log`-visible and are
   regression-tested with the data shapes captured from that run
   (`tests/test_unit.c`'s `test_orphan_mem`).

This is the honest version of "tested on a real kernel": not a claim that it
worked the first time, but a CI gate that made every gap impossible to
ignore, plus a fix and a regression test for each one. `docs/DEMO.md`
Demo 2 additionally exercises the macOS collector against a **real** live
process hide.

## 3. Unit tests (`make unit`)

88 assertions in `tests/test_unit.c`, run through an in-memory provider so
each test states exactly which views exist. They pin down the specific
decisions that make the false-positive handling real rather than lucky:
boundary addresses at exactly `_stext`/`_etext`, the "inside text but not a
syscall entry point" case scored weaker than "outside text entirely", a
livepatch's `IPMODIFY` callback correctly left alone, a process that exits
before the re-probe correctly *not* reported, confidence capped below the
conviction threshold for a bind-only (never-`listen()`ed) socket, and the
verdict engine's exact escalation rule (see next section).

## The verdict rule, exactly

```
score = Σ over detections( severity_weight[sev] × confidence / 100 )
        weights: INFO=0  LOW=3  MEDIUM=10  HIGH=25  CRITICAL=40   (capped at 100)

COMPROMISED  if any HIGH+/≥75%-confidence finding, OR ≥2 independent checks
             each reach at least one MEDIUM+ finding
SUSPICIOUS   else if exactly 1 check reaches MEDIUM+, OR ≥2 checks reach LOW
CLEAN        otherwise
```

Counting *independent checks*, not raw finding count, is what escalates the
verdict: one check with ten similar LOW findings is one signal, not ten.
Posture findings (`hardening`) never enter this computation at all. The exact
code is `rd_verdict_compute()` in `src/engine.c`.
