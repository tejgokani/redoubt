# Security policy

## Supported versions

Only the latest release on `main` receives fixes.

| Version | Supported |
|---|---|
| 1.x (latest) | Yes |
| anything older | No |

## Why security reports matter here

Redoubt is meant to be run **as root, on machines you already suspect are
compromised**, and it parses data an attacker may control: kernel interfaces
(`/proc`, `/sys`, `/proc/kcore`, tracefs), kernel-log text, and the snapshot
directories accepted by `--from` and `--baseline`. A memory-safety or
privilege bug in that path is a real vulnerability, not a cosmetic one.

**In scope**

- Memory-safety bugs (overflow, out-of-bounds read/write, use-after-free, format-string) reachable from any input above, including malformed `.tsv` snapshot files and unexpected `/proc` or tracefs content.
- Anything that makes Redoubt write, delete or execute something it should not, or leak data it reads.
- Path-handling issues in `snapshot`, `--from`, `--baseline` and `demo` (for example, escaping the target directory).

**Not vulnerabilities** (please open a normal issue instead)

- A rootkit that evades a check. Evasion is a documented limitation ([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)); a *specific*, reproducible bypass of a *specific* check is still a welcome bug report.
- False positives or false negatives on a particular system (use the *False positive* issue template).
- Findings that require the attacker to already control the machine running Redoubt and modify its binary.

## How to report

**Please do not open a public issue for a vulnerability.**

1. Go to the repository's **Security** tab and choose **Report a vulnerability**
   (GitHub private vulnerability reporting), or open
   <https://github.com/tejgokani/redoubt/security/advisories/new>.
2. Include the Redoubt version (`redoubt --version`), your OS and kernel
   (`uname -srm`), and a minimal reproduction. For parser bugs, the smallest
   input file that triggers it is ideal.

This is a small, volunteer-maintained project. Reports are handled on a
best-effort basis: expect an acknowledgement within about a week, and a fix or
a clear explanation after triage. Reporters are credited in the advisory and
release notes unless they prefer to stay anonymous.

## Responsible use

Redoubt is a defensive tool: it is read-only and never unloads a module, kills
a process or deletes a file. `tests/hooks/hide_pid.c` is a deliberately minimal
demonstration hook, included only so that detection can be tested; it hides one
process id from the program it is injected into and does nothing else.
