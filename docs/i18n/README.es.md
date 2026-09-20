<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">Detector de rootkits de módulos del kernel para Linux y macOS</h3>

<p align="center">
  C puro. Sin dependencias. Sin VM. Solo lectura.<br>Nunca confía en un único listado: le hace al kernel la misma pregunta por varias vías independientes e informa cuando las respuestas no coinciden.
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
  <b>Español</b> &middot;
  <a href="README.fr.md">Français</a> &middot;
  <a href="README.de.md">Deutsch</a> &middot;
  <a href="README.pt-BR.md">Português (BR)</a> &middot;
  <a href="README.zh-CN.md">简体中文</a> &middot;
  <a href="README.ja.md">日本語</a> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> Traducción del [README en inglés](../../README.md), que es la versión de referencia. Los documentos técnicos (`docs/`) están solo en inglés.

---

## Descripción general

Los rootkits de módulos del kernel (LKM) en Linux, y sus equivalentes como extensiones del kernel en macOS, se ejecutan con los mismos privilegios que el sistema operativo. Pueden reescribir lo que el kernel le dice a cualquier otro programa, incluidos `lsmod`, `ps`, `netstat` y `ls`: las herramientas que un administrador usa primero en una máquina sospechosa.

La respuesta de Redoubt es estructural, no una lista de firmas. Para ocultarse, un rootkit debe mentir de forma coherente por *todas* las vías que el kernel ofrece para hacer la misma pregunta; a quien defiende le basta con que una diga la verdad. Por eso Redoubt obtiene cada dato por dos o más vías independientes —un módulo mediante `/proc/modules`, `/sys/module` y el mapa de memoria ejecutable del kernel; un proceso mediante el listado de libc, la llamada al sistema `getdents64` en bruto y una sonda `kill(pid, 0)`; un puerto mediante `/proc/net/*` y `bind()`— e informa de las discrepancias.

> **Lea [docs/THREAT_MODEL.md](../THREAT_MODEL.md) (en inglés) antes de fiarse de un veredicto `CLEAN`.**

## Características principales

- **Detección por comparación de vistas, no por firmas.** Comprobaciones de comportamiento que siguen funcionando aunque el rootkit cambie de nombre.
- **16 comprobaciones:** ocultación de módulos, integridad del código del kernel (tabla de syscalls, ftrace, hooks en línea), procesos/puertos/archivos ocultos, inyección vía enlazador dinámico y extensiones del kernel de macOS.
- **Hallazgos calibrados.** Cada hallazgo incluye una confianza (0–100), un identificador MITRE ATT&CK y un siguiente paso concreto; el veredicto cuenta comprobaciones *independientes*.
- **Consciente de las condiciones de carrera.** Lo que puede cambiar durante el escaneo (procesos, módulos, sockets) se vuelve a muestrear y sondear antes de informar.
- **Cobertura honesta.** Una comprobación que no pudo ejecutarse aparece como *skipped* con su motivo; un `CLEAN` indica cuántas comprobaciones cubre.
- **Funciona sin conexión.** `snapshot` guarda todas las vistas del kernel; `--from` las analiza después en cualquier máquina; `--baseline` compara con un estado de confianza.
- **Cero dependencias.** C11 y `make`. Solo lectura: sin demonio, sin persistencia, sin remediación automática.
- **Verificado en un kernel real.** La CI escanea un kernel Linux 6.17 sin modificar en cada commit y falla si el resultado no es `CLEAN` con cobertura completa.

## Inicio rápido

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` y `make test` no necesitan root ni un kernel concreto; los colectores de macOS funcionan de forma nativa. Guion de presentación: [docs/DEMO.md](../DEMO.md) (en inglés).

## Uso

| Comando | Qué hace |
|---|---|
| `scan` | Escanea esta máquina (comando por defecto). |
| `demo [name\|all]` | Reproduce sin conexión un escenario incluido con el motor de detección real. |
| `eval [dir]` | Ejecuta todos los escenarios e imprime la matriz de detección (aprobado/fallido). |
| `snapshot DIR` | Guarda todas las vistas del kernel de esta máquina como evidencia o línea base. |
| `list-checks` | Lista las 16 comprobaciones y qué compara cada una. |

| Opción | Qué hace |
|---|---|
| `--from DIR` | Analiza un directorio de snapshot/escenario en lugar del sistema en vivo. |
| `--baseline DIR` | Compara además con un snapshot de referencia de confianza. |
| `--only a,b / --skip a,b` | Ejecuta u omite comprobaciones concretas por id. |
| `--fail-on SEV` | Código de salida `1` si hay una detección igual o superior a esa gravedad (`info`…`critical`, por defecto `medium`). |
| `--json` | Informe legible por máquinas. |
| `--simulate SPEC` | Inyecta una mentira tipo rootkit en datos en vivo para demostraciones ([docs/DEMO.md](../DEMO.md)). |

**Estado de salida:** `0` nada detectado · `1` detección · `2` error de uso o interno · `3` cobertura incompleta con `--strict-coverage`. Lista completa: `redoubt --help`.

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # capturar las vistas de un equipo sospechoso
./redoubt scan --from /var/tmp/evidence        # analizarlas después, en cualquier máquina
```

## Qué detecta

16 comprobaciones que cubren ocultación de módulos, hooks del kernel, procesos/puertos/archivos ocultos, inyección vía enlazador dinámico y extensiones del kernel de macOS. Cada una contrasta las fuentes independientes indicadas:

| Comprobación | Fuentes contrastadas |
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

## Evidencia

- **Un kernel Linux real en cada commit.** La CI ejecuta `sudo redoubt scan` sobre un kernel Ubuntu 6.17 sin modificar y falla si el veredicto no es `CLEAN` con las 13 comprobaciones aplicables. Por el camino aparecieron tres falsos positivos reales; cada uno es ahora una prueba de regresión.
- **Una ocultación real y en vivo en macOS.** `make hooks` compila un hook mínimo en espacio de usuario que oculta un proceso en ejecución de `proc_listpids`; Redoubt lo detecta en la máquina en vivo.
- **Matriz de escenarios y pruebas unitarias.** `make test` ejecuta 88 aserciones y 10 escenarios (6 rootkits modelados y 4 controles limpios/señuelo).

Descripción completa, incluido lo que *no* está demostrado: [docs/EVALUATION.md](../EVALUATION.md) (en inglés).

## Limitaciones

Se indican desde el principio, porque una falsa sensación de seguridad es peor que ninguna:

- **Es una herramienta local y en espacio de usuario.** Un rootkit que mienta de forma coherente por todas las vías que Redoubt lee le resulta invisible. Solo una vista externa (una imagen de memoria desde el hipervisor o el disco leído desde otra máquina) puede resolverlo.
- **Los seis escenarios de rootkit son modelados**, a partir de documentación pública, no capturas de infecciones reales. La evidencia con kernel real demuestra que la herramienta no da falsas alarmas; no demuestra la detección de un módulo de kernel oculto real.
- **Se necesita root para la cobertura completa en Linux.** Sin él, algunas comprobaciones aparecen como *skipped*. El bloqueo del kernel (lockdown) también puede restringir `/proc/kcore`.
- **Algunas comprobaciones son heurísticas** y su confianza está limitada en consecuencia (p. ej., un socket con `bind()` que nunca hace `listen()` parece un puerto oculto).
- **Probado solo** en Ubuntu (kernel 6.17, x86_64) y macOS 26 en Apple silicon.

## Documentación y contribución

- **Documentos técnicos (en inglés):** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **Contribuir:** [CONTRIBUTING.md](../../CONTRIBUTING.md): una comprobación nueva suele ser unas pocas docenas de líneas más una prueba.
- **Vulnerabilidades de seguridad:** consulte [SECURITY.md](../../SECURITY.md); no abra un issue público para una vulnerabilidad.
- **Código de conducta:** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md). Redoubt es una herramienta *defensiva*: solo lectura; nunca descarga un módulo, mata un proceso ni borra un archivo.

## Licencia

[MIT](../../LICENSE) &copy; 2026 Tej Gokani
