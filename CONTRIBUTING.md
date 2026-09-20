# Contributing

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
