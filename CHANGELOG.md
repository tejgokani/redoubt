# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project banner and social-preview image (`assets/`).
- Professional README with badges, table of contents, platform status, usage reference and an explicit limitations section.
- README translations: Hindi, Spanish, French, German, Brazilian Portuguese, Simplified Chinese, Japanese and Russian (`docs/i18n/`).
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`, issue forms (bug, false positive, feature) and a pull-request template.

## [1.0.0] - 2026-09-21

First release.

### Added
- Cross-view detection engine: providers collect independent *views* of the same kernel-level fact; pure *checks* compare them and emit findings with a severity, a 0&ndash;100 confidence and a MITRE ATT&CK id; a three-level verdict (`CLEAN`, `SUSPICIOUS`, `COMPROMISED`) counts independent checks.
- 16 checks: `mod-xview`, `mod-orphan-mem`, `mod-taint`, `mod-provenance`, `syscall-table`, `ftrace-hooks`, `inline-hooks`, `proc-xview`, `net-xview`, `fs-xview`, `preload`, `known-iocs`, `kext-inventory`, `boot-integrity`, `baseline`, `hardening`.
- Live providers for Linux (`/proc`, `/sys`, `/proc/kcore`, tracefs, raw `getdents64`, pid and port probing) and macOS (`libproc`, `sysctl`, `kmutil`, IOKit registry).
- Snapshot provider and `snapshot`, `--from`, `--baseline` for offline analysis and drift detection.
- Fault-injection provider (`--simulate`) for demonstrating detection on live data.
- Commands `scan`, `demo`, `eval`, `snapshot`, `list-checks`; text and JSON reports; `--fail-on`, `--only`, `--skip`, `--strict-coverage`.
- 10 bundled scenarios (6 modelled rootkit families, 4 clean or decoy controls including a real captured Linux 6.17 snapshot) and 88 unit assertions.
- Race handling: racy views are re-sampled and each candidate is re-probed before it is reported.
- Continuous integration on Linux and macOS, including a live scan of an unmodified Linux 6.17 kernel that must be `CLEAN` with full coverage.

### Fixed (found by scanning a real kernel in CI)
- `ftrace-hooks` treated ftrace's own trampoline address as the hook owner.
- `mod-xview` reported kernel-internal pseudo-modules such as `[__builtin__ftrace]` as hidden modules.
- `mod-orphan-mem` assumed a caller name that newer kernels (execmem rework) no longer use, then flagged the data and rodata regions of legitimate modules. It now explains regions with `kallsyms` symbols and each listed module's `/sys/module/<name>/sections`.
