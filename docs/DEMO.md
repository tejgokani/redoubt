# Demo script (for a lab defence / faculty walkthrough)

Three demos. Do 1 and 2 if you have 10 minutes; do #1 alone if you have 3.

## Demo 1 — the fixture scenarios (works offline, no root, no VM)

```bash
make                 # builds ./redoubt
./redoubt demo        # lists the bundled scenarios with one-line descriptions
```

Pick the flagship one:

```bash
./redoubt demo diamorphine-lkm
```

This prints, in order: **the story** (what the rootkit does, in plain
language, modelled on its public documentation), **which recorded kernel
views it alters**, then **runs the real detection engine** against those
views and prints the full report — checks, findings with severity/confidence/
ATT&CK id/response guidance, and the final verdict.

Talking points while it's on screen:
- "`mod-orphan-mem`, `syscall-table`, `proc-xview` and `known-iocs` all fire
  independently — that's four different pieces of kernel/user-space evidence
  agreeing, not one heuristic."
- "The tool tells you *why* each finding is confident: look at the `%`
  numbers — a syscall-table entry pointing into unmapped memory is 96%, a
  module-name match is capped at 88% because renaming defeats it."
- Then run the decoy scenario to show it isn't trigger-happy:
  ```bash
  ./redoubt demo false-positive-traps
  ```
  "This one has a proprietary driver tainting the kernel, a legitimate
  kernel livepatch hooking the same function a rootkit would, and three
  processes/modules/sockets that appear or vanish *while the scan is
  running*. Verdict: CLEAN. Zero of those six decoys fired." Then, if asked
  "how do you know that's not luck":
  ```bash
  grep -n "test_false_positive_traps_are_real" -A8 tests/test_unit.c
  ```
  shows the one test that reruns this exact scenario with the anti-race
  logic disabled and asserts the decoys *do* fire there — proving the CLEAN
  result on the real engine is because of that logic, not an accident.

Run every scenario and show the matrix (the last row is real captured kernel data, not a model):
```bash
./redoubt eval fixtures
```

## Demo 2 — a REAL hide on the machine you're presenting on

This is the strongest thing to show a grader: not a replayed file, an
**actual, currently running process**, hidden by **actual code that hooks a
real system call**, caught by Redoubt scanning the **real, live machine**.

```bash
make hooks                          # builds tests/hooks/hide_pid.c
sleep 300 &                         # a disposable "victim" process
VICTIM=$!
echo "hiding pid $VICTIM"

./redoubt scan --only proc-xview,preload      # 1: baseline, CLEAN

# 2: same scan, with a real hook hiding that one pid
```
macOS:
```bash
HIDE_PID=$VICTIM DYLD_INSERT_LIBRARIES=$PWD/build/libhide.dylib ./redoubt scan --only proc-xview,preload
```
Linux:
```bash
HIDE_PID=$VICTIM LD_PRELOAD=$PWD/build/libhide.so ./redoubt scan --only proc-xview,preload
```
```bash
echo "exit code: $?"                # 1 = detection
kill $VICTIM
```

What just happened, to say out loud: `tests/hooks/hide_pid.c` interposes the
exact OS call `ps`/Activity Monitor/`top` use to list processes
(`proc_listpids` on macOS, `readdir`/`readdir64` on Linux) and deletes one
pid from every answer it gives. Redoubt's `proc-xview` check asks the *same*
question through a second, independent path the hook didn't touch, notices
the mismatch, re-samples to rule out a race, and reports it — while
`preload` independently flags the injection mechanism itself. This is a real,
if minimal, user-space rootkit technique (the same class as Azazel/Jynx/
BEURK), caught live.

## Demo 3 (optional) — the fault-injection layer, on your live data

If you don't want to build the hook library, `--simulate` gets a similar
demo by editing the *live* provider's output in memory (clearly labelled in
the report source line so it's never confused with a real detection):

```bash
./redoubt scan --simulate hide-pid:$$        # hides the current shell's own pid
./redoubt scan --simulate hide-module-deep:ext4   # (Linux) pretend ext4 vanished everywhere
```

`--simulate` specs (comma-separated): `hide-pid:PID`, `hide-pid-api:PID`,
`hide-pid-deep:PID`, `hide-module:NAME`, `hide-module-deep:NAME`,
`add-kext:BUNDLE_ID` (macOS). See `src/platform/sim.c` for exactly what each
one edits.

## If you're asked "why should I believe the verdict"

Point at `docs/EVALUATION.md`. Short version: the *logic* is proven against
ten scenarios including deliberate false-positive traps (`eval`), the exact
severity/confidence math is unit-tested (`make unit`, 88 assertions), the
Linux collectors run against a real unmodified kernel on every commit (CI
fails unless it scans CLEAN), and the macOS collectors were run for real on
this machine (Demo 2, above) — the
combination is what "correctness" means for a tool like this, and the docs
say plainly which parts are simulated and which are not.

## If you're asked "does this actually matter to anyone outside a grade book"

Be direct and modest about it:

- **It is a real, if narrow, defensive gap.** Kernel-module rootkits are
  freely available as open-source code (Diamorphine and Reptile are public
  GitHub repositories), which lowers the bar for hiding after a break-in.
  The standard tools an administrator reaches for on a suspect box — `lsmod`,
  `ps`, `netstat`, `ls` — all read the very interfaces such a rootkit
  rewrites. A tool that cross-checks *independent* paths to the same fact is
  a legitimate, well-established defensive technique (it is what tools like
  `unhide` do for processes; Redoubt generalises it to modules, the syscall
  table, ftrace hooks and more).
- **What makes this implementation useful rather than a toy:** dependency-free
  C that builds on any Linux box or Mac with no install step (so it can run on
  a host you already distrust without pulling in a package manager);
  read-only, no daemon, no persistence, no automatic remediation that could
  itself be abused; every finding carries a confidence and an ATT&CK id and
  says what to do next; and an explicit, tested false-positive story
  (Scenario 9) instead of a detector that cries wolf.
- **What it honestly cannot do** is catch a rootkit that lies consistently
  through every path Redoubt reads — no on-host tool can — and
  `docs/THREAT_MODEL.md` says so up front, along with what would (an
  out-of-band memory image). That candour is deliberate: a green checkmark
  that overstates certainty is worse than no checkmark.
- **It is an open-source teaching artefact too.** The engine is roughly 4,700 lines of
  readable C organised around one idea (views → checks → findings), with
  every check pure over data so a student can add a new one in ~50 lines and
  test it with a fixture — see `CONTRIBUTING.md`.
