# Contributing

Thanks for helping. Redoubt is a small, focused project; a good contribution
is usually one new check, one fixed false positive, or one clearer paragraph
of documentation.

## Ways to contribute

- **Report a false positive.** Use the *False positive* issue form. On a real
  kernel these are the most valuable reports - three bugs fixed before 1.0
  were found by scanning a real machine.
- **Report a bug or suggest a feature** with the matching issue form.
- **Report a security vulnerability privately** - see [`SECURITY.md`](SECURITY.md).
- **Add or improve a check, provider, scenario or translation** (below).

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/tejgokani/redoubt.git && cd redoubt
make WERROR=1        # zero warnings is the bar
make test            # unit tests + the scenario matrix
make syntax-linux    # if you touched src/platform/linux.c on a non-Linux machine
```

Requirements: a C11 compiler and `make`. Python 3 is only needed to regenerate
fixtures (`tools/gen_fixtures.py`). CI builds with GCC on Linux and clang on macOS, and is
stricter than a local clang build, so run `make syntax-linux` before pushing
Linux-provider changes.

## Pull requests

1. Branch from `main`; keep the change focused.
2. Add a test (below) and update `CHANGELOG.md` under *Unreleased*.
3. Fill in the pull-request template. **Docs must not claim more than you tested** - say plainly what is modelled and what is real.
4. CI must be green, including the live scan of a real kernel.

## Translations

The English `README.md` is authoritative. Translations live in
[`docs/i18n/`](docs/i18n/) as `README.<lang>.md` and mirror its structure; only
the README is translated (technical documents stay English). Native-speaker
corrections are very welcome - please keep code blocks, check ids and file
paths unchanged.

## Adding a check

A check is a pure function of `rd_ctx*` — it never touches the OS directly.

1. Pick or add the `RDV_*` view(s) it needs (`include/redoubt.h`; document
   what `a`/`b`/`extra` mean for it).
2. Implement collection for that view in `src/platform/linux.c` and/or
   `src/platform/macos.c`. If a view is racy (an object can appear/disappear
   between two reads), also implement `probe()` for a cheap targeted re-check
   — see `mac_probe`/`lin_probe` for the pattern.
3. Write the check in `src/checks/chk_*.c` (or a new file, added to
   `Makefile`'s `CORE_SRC`):
   ```c
   static int run_mycheck(rd_ctx *c) {
       NEED(c, RDV_SOMETHING, v);           /* skips with a reason if unavailable */
       for (size_t i = 0; i < v->n; i++) {
           if (/* looks wrong */) {
               rd_finding *f = rd_add(c, RD_MEDIUM, 60, "short title",
                                      "multi-line detail explaining *why* this is evidence, not just what");
               f->mitre = "T....";
               f->fix = "one sentence: what to do next";
           }
       }
       return 0;
   }
   const rd_check rd_chk_mycheck = {
       "mycheck-id", "Human title", "one-line: what it compares", RD_PLAT_LINUX, run_mycheck,
   };
   ```
4. Register it in `src/checks/checks.c`'s `ALL[]` and declare it in
   `src/checks.h`.
5. **Pick a confidence honestly.** Ask: "what else, besides a rootkit, could
   produce this exact signal?" A syscall pointer into unmapped memory has no
   innocent explanation → 90%+. A name match defeats itself the moment
   someone renames the file → cap it around 85%. If two independent views
   corroborate each other, that's a good reason to go higher than either
   alone (see `mod-xview`'s `both` case).
6. **Handle the race before calling it a finding.** If your view can change
   between the moment you read it and the moment you report it (almost
   anything involving processes, modules, or sockets), re-sample with
   `rd_recollect()` and re-check the specific key with `rd_probe()` before
   adding the finding — see `run_proc`/`run_net`/`run_mod_xview` for the
   pattern. This is not optional polish; it is the difference between a
   detector and a detector nobody can trust (see the `false-positive-traps`
   scenario in `docs/EVALUATION.md`).
7. Add:
   - a unit test in `tests/test_unit.c` using the in-memory provider (`put`/
     `have`), covering both the finding case and at least one adjacent
     non-finding case;
   - a scenario in `tools/gen_fixtures.py` if the check is a good fit for the
     demo/eval story, then `python3 tools/gen_fixtures.py`.
8. `make test` — must pass, zero warnings with `WERROR=1 make`.

## Code style

- C11, GNU extensions where useful (`strtok_r`, nested designators), no
  external dependencies.
- No check file may `#include` a platform header or call an OS function
  directly — that's what makes `demo`/`eval`/`--from` work. If you need new
  data, add a view and a collector, not a shortcut in the check.
- Every finding needs `title` (one line), `detail` (why this is evidence),
  and `fix` (what to do). Findings without an honest "why" are noise.
- Run `make WERROR=1` before sending a change; `make syntax-linux` if you
  touched `src/platform/linux.c` from a non-Linux machine.

## Regenerating fixtures

`fixtures/` is generated, not hand-edited:
```bash
python3 tools/gen_fixtures.py
make eval
```
See the module docstring in `tools/gen_fixtures.py` for the overlay format
(`base:` in `scenario.txt`) and how `.recheck.tsv`/`.probe.tsv` model races.
