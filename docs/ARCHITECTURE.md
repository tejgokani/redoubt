# Architecture

```
 ┌──────────────┐   rd_view_id    ┌──────────────────┐
 │   provider    │ ─────────────▶ │   rd_view         │  a bag of (key, a, b, extra)
 │ live / fixture│                │  (sorted, dedup'd) │  tuples: one *fact*, e.g. the
 │ / sim wrapper │ ◀───────────── │                    │  module list, seen one way
 └──────────────┘   collect()     └──────────────────┘
        ▲                                   │
        │ probe(id,key)                     ▼
        │ (cheap re-check of one            used by
        │  key, for race handling)     ┌──────────────┐
        └────────────────────────────  │    check      │  compares 2+ views,
                                        │ (src/checks/*)│  calls rd_add() on
                                        └──────────────┘  disagreement
                                                  │
                                                  ▼
                                        ┌──────────────┐
                                        │  rd_finding[]  │  severity, confidence,
                                        │  rd_verdict    │  ATT&CK id, fix advice
                                        └──────────────┘
```

## The three abstractions

**View** (`include/redoubt.h`, `src/view.c`) — a named, flat list of facts.
Every fact is a `(key, a, b, extra)` tuple; what `a`/`b`/`extra` mean is
per-view (documented next to each `RDV_*` enumerator). Views are the only
thing a check is allowed to read — this is what makes the same check run
identically over a live scan or a replayed snapshot.

**Provider** (`include/redoubt.h`'s `rd_provider`) — anything that can fill a
view. Four implementations ship:

- [`src/platform/linux.c`](../src/platform/linux.c) — reads `/proc`, `/sys`,
  `/proc/kcore`, `tracefs`, raw syscalls (`getdents64`), and probes
  (`kill(pid,0)`, `bind()`).
- [`src/platform/macos.c`](../src/platform/macos.c) — `libproc`, `sysctl`,
  `kmutil`, the IOKit registry, `csrutil`/`spctl`.
- [`src/platform/fixture.c`](../src/platform/fixture.c) — replays a directory
  of `<view>.tsv` files. Used for `demo`, `eval`, `--from`, `--baseline`, and
  the output of `snapshot`. Supports an overlay chain (`base:` in
  `scenario.txt`) so a scenario only has to state what it *changes*.
- [`src/platform/sim.c`](../src/platform/sim.c) — wraps another provider and
  edits its views the way a rootkit would (drop a pid, unlink a module). Lets
  every check run against **real, live data with one fact deliberately
  altered**, without needing an actual rootkit — see `docs/DEMO.md`.

A provider can optionally implement `probe()`: a cheap, targeted re-check of
one key (e.g. "does pid 4242 still respond to a signal, right now?"). Checks
use it to rule out a race before calling something a finding.

**Check** (`src/checks/*.c`, registered in `src/checks/checks.c`) — pure
function of `rd_ctx*` that pulls views via `rd_get_view()`/`NEED()`, compares
them, and calls `rd_add()` for each disagreement. A check that needs a view
the provider can't supply calls `rd_skip()` and is reported as `SKIPPED`
— never silently "passed". `rd_na()` is the third outcome, for a check that
is deliberately not exercised (e.g. `baseline` with no `--baseline` given);
it does not count against coverage the way a `SKIPPED` check does.

## Data flow of one scan

1. `main()` builds a provider (`make_provider` in `src/main.c`): live, fixture
   (`--from`), optionally sim-wrapped (`--simulate`).
2. `rd_scan()` (`src/engine.c`) runs every registered check whose platform
   mask matches the data's OS (from `RDV_SYSINFO`, not the host running
   Redoubt — a macOS box can analyse a Linux snapshot).
3. Each check calls `rd_get_view()`, which is **cached per scan** — a view is
   collected once no matter how many checks read it — except when a check
   explicitly calls `rd_recollect()` for a fresh, uncached sample (the race
   handling in `proc-xview`, `net-xview`, `fs-xview`, `mod-xview`,
   `mod-orphan-mem` all do this: sample twice, and a finding only survives
   if it's still true on the second sample and the individual key still
   fails a targeted `rd_probe()`).
4. `rd_verdict_compute()` turns the finding list into a score and a
   three-level verdict (`CLEAN`/`SUSPICIOUS`/`COMPROMISED`) — see
   `docs/EVALUATION.md` for the exact rule and why it is that way.
5. `rd_report_text()` / `rd_report_json()` render it.

## Why this shape

- **Checks never touch the OS.** All 16 checks in `src/checks/`
  are pure C over `rd_view`, with zero `#ifdef __linux__`. That is what lets
  `eval` replay six modelled rootkit scenarios and four clean/decoy scenarios (one a real captured kernel snapshot) through
  the *exact* production detection code with no OS, no VM, and no privilege
  requirement — see `docs/EVALUATION.md`.
- **Confidence is a first-class field, not a side note.** Every finding
  carries `conf` (0-100). A name match (`known-iocs`) is capped around 85-88%
  because renaming defeats it; a syscall-table entry pointing at unmapped
  memory is 96% because there is no legitimate reason for that to happen.
  `rd_verdict_compute()` weights severity by confidence, so ten low-confidence
  guesses don't add up to a false "compromised".
- **Findings are typed `RD_KIND_DETECTION` vs `RD_KIND_POSTURE`.** Detections
  drive the verdict; posture (`hardening` check: `kptr_restrict`, SIP, module
  signing...) is reported for the write-up but never itself convicts a clean
  system — a locked-down kernel is good advice, not evidence of compromise.
