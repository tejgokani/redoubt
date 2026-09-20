<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">Erkennung von Kernel-Modul-Rootkits für Linux und macOS</h3>

<p align="center">
  Reines C. Keine Abhängigkeiten. Keine VM. Nur lesend.<br>Redoubt vertraut nie einer einzelnen Auflistung: Es stellt dem Kernel dieselbe Frage auf mehreren unabhängigen Wegen und meldet, wenn die Antworten voneinander abweichen.
</p>

<p align="center">
  <a href="https://github.com/tejgokani/redoubt/actions/workflows/ci.yml"><img src="https://github.com/tejgokani/redoubt/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/language-C11-555555.svg" alt="Language: C11">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform: Linux | macOS">
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen.svg" alt="Dependencies: none">
</p>

<p align="center">
  <a href="../../README.md">English</a> &middot;
  <a href="README.hi.md">हिन्दी</a> &middot;
  <a href="README.es.md">Español</a> &middot;
  <a href="README.fr.md">Français</a> &middot;
  <b>Deutsch</b> &middot;
  <a href="README.pt-BR.md">Português (BR)</a> &middot;
  <a href="README.zh-CN.md">简体中文</a> &middot;
  <a href="README.ja.md">日本語</a> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> Übersetzung des [englischen README](../../README.md), das maßgeblich ist. Die technischen Dokumente (`docs/`) gibt es nur auf Englisch.

---

## Überblick

Rootkits in Form ladbarer Kernel-Module (LKM) unter Linux und ihre Gegenstücke als Kernel-Erweiterungen unter macOS laufen mit denselben Privilegien wie das Betriebssystem selbst. Sie können umschreiben, was der Kernel jedem anderen Programm mitteilt – auch `lsmod`, `ps`, `netstat` und `ls`, also die Werkzeuge, zu denen Administratoren auf einem verdächtigen Rechner zuerst greifen.

Redoubts Antwort ist strukturell, keine Signaturliste. Um sich zu verstecken, muss ein Rootkit über *jeden* Weg, auf dem der Kernel dieselbe Frage beantwortet, konsistent lügen; dem Verteidiger genügt ein einziger Weg, der die Wahrheit sagt. Redoubt erhebt daher jede Tatsache über mindestens zwei unabhängige Wege – ein Modul über `/proc/modules`, `/sys/module` und die Karte des ausführbaren Kernel-Speichers; einen Prozess über die libc-Auflistung, den rohen Systemaufruf `getdents64` und eine `kill(pid, 0)`-Sonde; einen Port über `/proc/net/*` und `bind()` – und meldet die Abweichungen.

> **Lesen Sie [docs/THREAT_MODEL.md](../THREAT_MODEL.md) (englisch), bevor Sie einem `CLEAN`-Ergebnis vertrauen.**

## Highlights

- **Erkennung durch Ansichtsvergleich statt Signaturen.** Verhaltensbasierte Prüfungen, die auch nach dem Umbenennen eines Rootkits funktionieren.
- **16 Prüfungen:** Modulverbergung, Integrität des Kernel-Codes (Syscall-Tabelle, ftrace, Inline-Hooks), versteckte Prozesse/Ports/Dateien, Injektion über den dynamischen Linker und macOS-Kernel-Erweiterungen.
- **Kalibrierte Befunde.** Jeder Befund trägt eine Konfidenz (0–100), eine MITRE-ATT&CK-ID und einen konkreten nächsten Schritt; das Urteil zählt *unabhängige* Prüfungen.
- **Race-Condition-bewusst.** Was sich während des Scans ändern kann (Prozesse, Module, Sockets), wird vor der Meldung erneut abgetastet und geprüft.
- **Ehrliche Abdeckung.** Eine nicht ausführbare Prüfung wird mit Grund als *skipped* gemeldet; ein `CLEAN` nennt, wie viele Prüfungen es abdeckt.
- **Funktioniert offline.** `snapshot` speichert alle Kernel-Ansichten; `--from` analysiert sie später auf jedem Rechner; `--baseline` vergleicht mit einem bekannten guten Zustand.
- **Keine Abhängigkeiten.** C11 und `make`. Nur lesend: kein Daemon, keine Persistenz, keine automatische Bereinigung.
- **Auf einem echten Kernel verifiziert.** Die CI scannt bei jedem Commit einen unveränderten Linux-6.17-Kernel und schlägt fehl, wenn das Ergebnis nicht `CLEAN` bei voller Abdeckung ist.

## Schnellstart

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` und `make test` benötigen weder Root noch einen bestimmten Kernel; die macOS-Collector laufen nativ. Präsentationsskript: [docs/DEMO.md](../DEMO.md) (englisch).

## Verwendung

| Befehl | Funktion |
|---|---|
| `scan` | Scannt diesen Rechner (Standardbefehl). |
| `demo [name\|all]` | Spielt ein mitgeliefertes Szenario offline durch die echte Erkennungs-Engine. |
| `eval [dir]` | Führt alle Szenarien aus und gibt die Erkennungsmatrix (bestanden/fehlgeschlagen) aus. |
| `snapshot DIR` | Speichert alle Kernel-Ansichten dieses Rechners als Beweissicherung oder Baseline. |
| `list-checks` | Listet die 16 Prüfungen und was jede vergleicht. |

| Option | Funktion |
|---|---|
| `--from DIR` | Analysiert ein Snapshot-/Szenario-Verzeichnis statt des laufenden Systems. |
| `--baseline DIR` | Vergleicht zusätzlich mit einem bekannten guten Snapshot. |
| `--only a,b / --skip a,b` | Führt einzelne Prüfungen per ID aus oder überspringt sie. |
| `--fail-on SEV` | Exit-Code `1` bei einer Erkennung ab dieser Schwere (`info`…`critical`, Standard `medium`). |
| `--json` | Maschinenlesbarer Bericht. |
| `--simulate SPEC` | Speist für Demos eine rootkit-artige Lüge in Live-Daten ein ([docs/DEMO.md](../DEMO.md)). |

**Exit-Status:** `0` nichts gefunden · `1` Erkennung · `2` Bedien- oder interner Fehler · `3` unvollständige Abdeckung mit `--strict-coverage`. Vollständige Liste: `redoubt --help`.

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # Ansichten eines verdächtigen Hosts sichern
./redoubt scan --from /var/tmp/evidence        # später auf einem beliebigen Rechner analysieren
```

## Was erkannt wird

16 Prüfungen für Modulverbergung, Kernel-Hooks, versteckte Prozesse/Ports/Dateien, Injektion über den dynamischen Linker und macOS-Kernel-Erweiterungen. Jede vergleicht die genannten unabhängigen Quellen:

| Prüfung | Verglichene Quellen |
|---|---|
| `mod-xview` | `/proc/modules` &harr; `/sys/module` &harr; `kallsyms` |
| `mod-orphan-mem` | vmalloc &harr; `kallsyms` &harr; `/sys/module/<name>/sections` |
| `mod-taint` | taint &harr; `dmesg` &harr; module views |
| `mod-provenance` | `/proc/modules` &harr; `modules.dep` |
| `syscall-table` | `sys_call_table` (`/proc/kcore`) &harr; `_stext`..`_etext` |
| `ftrace-hooks` | `enabled_functions` &harr; module lists |
| `inline-hooks` | `getdents` / `filldir` / `tcp4_seq_show` &hellip; prologues |
| `proc-xview` | `readdir` / `libproc` &harr; `getdents64` / `sysctl` &harr; `kill(pid, 0)` |
| `net-xview` | `/proc/net/*` &harr; `bind()` |
| `fs-xview` | `readdir()` &harr; `st_nlink` / `stat()` |
| `preload` | `ld.so.preload`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` |
| `known-iocs` | Diamorphine, Reptile, Adore, KBeast, Singularity, KoviD &hellip; |
| `kext-inventory` | `kmutil` &harr; IOKit &harr; `/Library/Extensions` |
| `boot-integrity` | `kern.bootargs` |
| `baseline` | `--baseline` |
| `hardening` | `sysctl`, lockdown, module signing, SIP |

## Nachweise

- **Ein echter Linux-Kernel bei jedem Commit.** Die CI führt `sudo redoubt scan` auf einem unveränderten Ubuntu-6.17-Kernel aus und schlägt fehl, wenn das Urteil nicht `CLEAN` mit allen 13 anwendbaren Prüfungen ist. Dabei wurden drei echte Fehlalarme entdeckt; jeder ist inzwischen ein Regressionstest.
- **Ein echtes Live-Verstecken unter macOS.** `make hooks` baut einen minimalen User-Space-Hook, der einen laufenden Prozess vor `proc_listpids` verbirgt; Redoubt erkennt ihn auf dem Live-System.
- **Szenariomatrix und Unit-Tests.** `make test` führt 88 Assertions und 10 Szenarien aus (6 modellierte Rootkits, 4 saubere bzw. Köder-Kontrollen).

Vollständige Darstellung, auch dazu, was *nicht* bewiesen ist: [docs/EVALUATION.md](../EVALUATION.md) (englisch).

## Einschränkungen

Bewusst offen benannt, denn trügerische Sicherheit ist schlimmer als keine:

- **Es ist ein lokales User-Space-Werkzeug.** Ein Rootkit, das über jeden von Redoubt gelesenen Weg konsistent lügt, bleibt unsichtbar. Nur eine Sicht von außen (ein Speicherabbild vom Hypervisor oder die von einem anderen Rechner gelesene Festplatte) kann das klären.
- **Die sechs Rootkit-Szenarien sind modelliert**, auf Basis öffentlicher Dokumentation, nicht von echten Infektionen aufgezeichnet. Die Nachweise am echten Kernel zeigen, dass das Werkzeug keine Fehlalarme auslöst; sie belegen nicht die Erkennung eines echten versteckten Kernel-Moduls.
- **Für volle Abdeckung unter Linux ist Root nötig.** Ohne Root werden Prüfungen als *skipped* gemeldet. Kernel-Lockdown kann außerdem `/proc/kcore` einschränken.
- **Einige Prüfungen sind Heuristiken** und ihre Konfidenz ist entsprechend begrenzt (z. B. wirkt ein per `bind()` belegter, aber nie `listen()`-ender Socket wie ein versteckter Port).
- **Nur getestet** unter Ubuntu (Kernel 6.17, x86_64) und macOS 26 auf Apple Silicon.

## Dokumentation und Mitwirken

- **Technische Dokumente (englisch):** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **Mitwirken:** [CONTRIBUTING.md](../../CONTRIBUTING.md) – eine neue Prüfung besteht meist aus einigen Dutzend Zeilen plus einem Test.
- **Sicherheitslücken:** siehe [SECURITY.md](../../SECURITY.md); eröffnen Sie für eine Schwachstelle kein öffentliches Issue.
- **Verhaltenskodex:** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md). Redoubt ist ein *defensives* Werkzeug: nur lesend; es entlädt nie ein Modul, beendet keinen Prozess und löscht keine Datei.

## Lizenz

[MIT](../../LICENSE) &copy; 2026 Tej Gokani
