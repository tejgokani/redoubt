<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">Détecteur de rootkits de modules noyau pour Linux et macOS</h3>

<p align="center">
  C pur. Aucune dépendance. Aucune VM. Lecture seule.<br>Il ne se fie jamais à une seule liste : il pose au noyau la même question par plusieurs chemins indépendants et signale les désaccords.
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
  <b>Français</b> &middot;
  <a href="README.de.md">Deutsch</a> &middot;
  <a href="README.pt-BR.md">Português (BR)</a> &middot;
  <a href="README.zh-CN.md">简体中文</a> &middot;
  <a href="README.ja.md">日本語</a> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> Traduction du [README anglais](../../README.md), qui fait foi. Les documents techniques (`docs/`) ne sont disponibles qu'en anglais.

---

## Présentation

Les rootkits de modules noyau (LKM) sous Linux, et leurs équivalents sous forme d'extensions du noyau sous macOS, s'exécutent avec les mêmes privilèges que le système d'exploitation. Ils peuvent réécrire ce que le noyau répond à tous les autres programmes, y compris `lsmod`, `ps`, `netstat` et `ls`, c'est-à-dire les outils qu'un administrateur lance en premier sur une machine suspecte.

La réponse de Redoubt est structurelle, pas une liste de signatures. Pour se cacher, un rootkit doit mentir de façon cohérente sur *tous* les chemins que le noyau offre pour poser la même question ; le défenseur n'a besoin que d'un seul chemin qui dise la vérité. Redoubt recueille donc chaque information par au moins deux chemins indépendants — un module via `/proc/modules`, `/sys/module` et la carte de la mémoire exécutable du noyau ; un processus via la liste de la libc, l'appel système `getdents64` brut et une sonde `kill(pid, 0)` ; un port via `/proc/net/*` et `bind()` — et signale les divergences.

> **Lisez [docs/THREAT_MODEL.md](../THREAT_MODEL.md) (en anglais) avant de vous fier à un verdict `CLEAN`.**

## Points forts

- **Détection par recoupement de vues, pas par signatures.** Des contrôles comportementaux qui fonctionnent encore quand le rootkit est renommé.
- **16 contrôles :** dissimulation de modules, intégrité du code noyau (table des appels système, ftrace, hooks en ligne), processus/ports/fichiers cachés, injection via l'éditeur de liens dynamique et extensions noyau de macOS.
- **Résultats calibrés.** Chaque résultat porte un niveau de confiance (0–100), un identifiant MITRE ATT&CK et une action concrète ; le verdict compte les contrôles *indépendants*.
- **Conscient des accès concurrents.** Ce qui peut changer pendant l'analyse (processus, modules, sockets) est ré-échantillonné et re-sondé avant d'être signalé.
- **Couverture honnête.** Un contrôle qui n'a pas pu s'exécuter est marqué *skipped* avec sa raison ; un `CLEAN` indique le nombre de contrôles couverts.
- **Fonctionne hors ligne.** `snapshot` enregistre toutes les vues du noyau ; `--from` les analyse plus tard sur n'importe quelle machine ; `--baseline` compare à un état sain de référence.
- **Zéro dépendance.** C11 et `make`. Lecture seule : ni démon, ni persistance, ni remédiation automatique.
- **Vérifié sur un vrai noyau.** La CI analyse un noyau Linux 6.17 non modifié à chaque commit et échoue si le résultat n'est pas `CLEAN` avec une couverture complète.

## Démarrage rapide

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` et `make test` n'exigent ni root ni noyau particulier ; les collecteurs macOS fonctionnent nativement. Script de démonstration : [docs/DEMO.md](../DEMO.md) (en anglais).

## Utilisation

| Commande | Rôle |
|---|---|
| `scan` | Analyse cette machine (commande par défaut). |
| `demo [name\|all]` | Rejoue hors ligne un scénario fourni avec le vrai moteur de détection. |
| `eval [dir]` | Exécute tous les scénarios et affiche la matrice de détection (réussite/échec). |
| `snapshot DIR` | Enregistre toutes les vues du noyau de cette machine comme preuve ou état de référence. |
| `list-checks` | Liste les 16 contrôles et ce que chacun compare. |

| Option | Rôle |
|---|---|
| `--from DIR` | Analyse un répertoire de snapshot/scénario au lieu du système en cours d'exécution. |
| `--baseline DIR` | Compare en plus à un snapshot sain de référence. |
| `--only a,b / --skip a,b` | Exécute ou ignore certains contrôles par identifiant. |
| `--fail-on SEV` | Code de sortie `1` si une détection atteint cette gravité (`info`…`critical`, `medium` par défaut). |
| `--json` | Rapport lisible par machine. |
| `--simulate SPEC` | Injecte un mensonge de type rootkit dans des données réelles pour les démonstrations ([docs/DEMO.md](../DEMO.md)). |

**Code de sortie :** `0` rien détecté · `1` détection · `2` erreur d'usage ou interne · `3` couverture incomplète avec `--strict-coverage`. Liste complète : `redoubt --help`.

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # capturer les vues d'un hôte suspect
./redoubt scan --from /var/tmp/evidence        # les analyser plus tard, sur n'importe quelle machine
```

## Ce qu'il détecte

16 contrôles couvrant la dissimulation de modules, les hooks noyau, les processus/ports/fichiers cachés, l'injection via l'éditeur de liens dynamique et les extensions noyau de macOS. Chacun recoupe les sources indépendantes indiquées :

| Contrôle | Sources recoupées |
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

## Preuves

- **Un vrai noyau Linux à chaque commit.** La CI exécute `sudo redoubt scan` sur un noyau Ubuntu 6.17 non modifié et échoue si le verdict n'est pas `CLEAN` avec les 13 contrôles applicables. Cela a révélé trois vrais faux positifs ; chacun est désormais un test de non-régression.
- **Une vraie dissimulation en direct sous macOS.** `make hooks` compile un hook minimal en espace utilisateur qui masque un processus en cours à `proc_listpids` ; Redoubt le détecte sur la machine réelle.
- **Matrice de scénarios et tests unitaires.** `make test` exécute 88 assertions et 10 scénarios (6 rootkits modélisés et 4 contrôles sains/leurres).

Détail complet, y compris ce qui n'est *pas* démontré : [docs/EVALUATION.md](../EVALUATION.md) (en anglais).

## Limites

Énoncées d'emblée, car un faux sentiment de sécurité est pire que l'absence de sécurité :

- **C'est un outil local, en espace utilisateur.** Un rootkit qui ment de façon cohérente sur tous les chemins lus par Redoubt lui reste invisible. Seule une vue hors bande (image mémoire prise par l'hyperviseur, ou disque lu depuis une autre machine) permet de trancher.
- **Les six scénarios de rootkit sont modélisés**, d'après la documentation publique, et non capturés sur de vraies infections. Les preuves sur noyau réel montrent que l'outil ne donne pas de fausses alertes ; elles ne démontrent pas la détection d'un vrai module noyau caché.
- **Il faut être root pour une couverture complète sous Linux.** Sinon des contrôles sont marqués *skipped*. Le verrouillage du noyau (lockdown) peut aussi restreindre `/proc/kcore`.
- **Certains contrôles sont heuristiques** et leur confiance est plafonnée en conséquence (par exemple, une socket liée par `bind()` mais jamais mise en écoute ressemble à un port caché).
- **Testé uniquement** sur Ubuntu (noyau 6.17, x86_64) et macOS 26 sur Apple silicon.

## Documentation et contribution

- **Documents techniques (en anglais) :** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **Contribuer :** [CONTRIBUTING.md](../../CONTRIBUTING.md) — un nouveau contrôle représente en général quelques dizaines de lignes et un test.
- **Failles de sécurité :** voir [SECURITY.md](../../SECURITY.md) ; n'ouvrez pas d'issue publique pour une vulnérabilité.
- **Code de conduite :** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md). Redoubt est un outil *défensif* : lecture seule ; il ne décharge jamais un module, ne tue aucun processus et ne supprime aucun fichier.

## Licence

[MIT](../../LICENSE) &copy; 2026 Tej Gokani
