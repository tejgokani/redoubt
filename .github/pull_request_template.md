## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `make WERROR=1 && make test` passes locally (zero warnings; unit tests and the scenario matrix)
- [ ] `make syntax-linux` passes if `src/platform/linux.c` changed (CI compiles with GCC, which is stricter than clang)
- [ ] New or changed behaviour has a unit test, and a scenario in `tools/gen_fixtures.py` if it belongs in the demo
- [ ] A new finding states its confidence and why (what else could produce this signal?), and re-samples or re-probes anything racy
- [ ] Docs updated (`docs/`, `README.md`, `CHANGELOG.md` under *Unreleased*)
- [ ] No claim in the docs goes beyond what was actually tested

## Testing notes

<!-- Which OS and kernel did you run it on? Paste relevant output. -->
