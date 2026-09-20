<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">Detector de rootkits de módulos do kernel para Linux e macOS</h3>

<p align="center">
  C puro. Sem dependências. Sem VM. Somente leitura.<br>Nunca confia em uma única listagem: faz ao kernel a mesma pergunta por vários caminhos independentes e avisa quando as respostas divergem.
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
  <a href="README.de.md">Deutsch</a> &middot;
  <b>Português (BR)</b> &middot;
  <a href="README.zh-CN.md">简体中文</a> &middot;
  <a href="README.ja.md">日本語</a> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> Tradução do [README em inglês](../../README.md), que é a versão de referência. Os documentos técnicos (`docs/`) existem apenas em inglês.

---

## Visão geral

Rootkits de módulos do kernel (LKM) no Linux, e seus equivalentes como extensões do kernel no macOS, são executados com os mesmos privilégios do sistema operacional. Eles podem reescrever o que o kernel informa a qualquer outro programa, inclusive `lsmod`, `ps`, `netstat` e `ls`, as ferramentas que um administrador usa primeiro em uma máquina suspeita.

A resposta do Redoubt é estrutural, não uma lista de assinaturas. Para se esconder, um rootkit precisa mentir de forma consistente por *todos* os caminhos que o kernel oferece para a mesma pergunta; quem defende só precisa que um deles diga a verdade. Por isso o Redoubt coleta cada fato por dois ou mais caminhos independentes — um módulo via `/proc/modules`, `/sys/module` e o mapa de memória executável do kernel; um processo via a listagem da libc, a chamada de sistema `getdents64` crua e uma sonda `kill(pid, 0)`; uma porta via `/proc/net/*` e `bind()` — e relata as divergências.

> **Leia [docs/THREAT_MODEL.md](../THREAT_MODEL.md) (em inglês) antes de confiar em um veredito `CLEAN`.**

## Destaques

- **Detecção por comparação de visões, não por assinaturas.** Verificações comportamentais que continuam funcionando mesmo se o rootkit for renomeado.
- **16 verificações:** ocultação de módulos, integridade do código do kernel (tabela de syscalls, ftrace, hooks inline), processos/portas/arquivos ocultos, injeção via linker dinâmico e extensões do kernel do macOS.
- **Achados calibrados.** Cada achado traz uma confiança (0–100), um ID MITRE ATT&CK e um próximo passo concreto; o veredito conta verificações *independentes*.
- **Ciente de condições de corrida.** O que pode mudar durante a varredura (processos, módulos, sockets) é reamostrado e resondado antes de ser relatado.
- **Cobertura honesta.** Uma verificação que não pôde ser executada aparece como *skipped* com o motivo; um `CLEAN` informa quantas verificações cobre.
- **Funciona offline.** `snapshot` salva todas as visões do kernel; `--from` as analisa depois em qualquer máquina; `--baseline` compara com um estado confiável.
- **Zero dependências.** C11 e `make`. Somente leitura: sem daemon, sem persistência, sem remediação automática.
- **Verificado em um kernel real.** A CI varre um kernel Linux 6.17 sem modificações a cada commit e falha se o resultado não for `CLEAN` com cobertura completa.

## Início rápido

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` e `make test` não exigem root nem um kernel específico; os coletores do macOS rodam nativamente. Roteiro de apresentação: [docs/DEMO.md](../DEMO.md) (em inglês).

## Uso

| Comando | O que faz |
|---|---|
| `scan` | Varre esta máquina (comando padrão). |
| `demo [name\|all]` | Reproduz offline um cenário incluído usando o motor de detecção real. |
| `eval [dir]` | Executa todos os cenários e imprime a matriz de detecção (aprovado/reprovado). |
| `snapshot DIR` | Salva todas as visões do kernel desta máquina como evidência ou linha de base. |
| `list-checks` | Lista as 16 verificações e o que cada uma compara. |

| Opção | O que faz |
|---|---|
| `--from DIR` | Analisa um diretório de snapshot/cenário em vez do sistema ao vivo. |
| `--baseline DIR` | Compara também com um snapshot confiável de referência. |
| `--only a,b / --skip a,b` | Executa ou ignora verificações específicas por id. |
| `--fail-on SEV` | Código de saída `1` se houver detecção a partir dessa gravidade (`info`…`critical`, padrão `medium`). |
| `--json` | Relatório legível por máquina. |
| `--simulate SPEC` | Injeta uma mentira de rootkit em dados ao vivo para demonstrações ([docs/DEMO.md](../DEMO.md)). |

**Status de saída:** `0` nada detectado · `1` detecção · `2` erro de uso ou interno · `3` cobertura incompleta com `--strict-coverage`. Lista completa: `redoubt --help`.

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # capturar as visões de um host suspeito
./redoubt scan --from /var/tmp/evidence        # analisá-las depois, em qualquer máquina
```

## O que detecta

16 verificações cobrindo ocultação de módulos, hooks no kernel, processos/portas/arquivos ocultos, injeção via linker dinâmico e extensões do kernel do macOS. Cada uma confronta as fontes independentes indicadas:

| Verificação | Fontes confrontadas |
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

## Evidências

- **Um kernel Linux real a cada commit.** A CI executa `sudo redoubt scan` em um kernel Ubuntu 6.17 sem modificações e falha se o veredito não for `CLEAN` com as 13 verificações aplicáveis. Isso revelou três falsos positivos reais; cada um agora é um teste de regressão.
- **Uma ocultação real, ao vivo, no macOS.** `make hooks` compila um hook mínimo em espaço de usuário que esconde um processo em execução de `proc_listpids`; o Redoubt o detecta na máquina ao vivo.
- **Matriz de cenários e testes unitários.** `make test` executa 88 asserções e 10 cenários (6 rootkits modelados e 4 controles limpos/isca).

Descrição completa, inclusive o que *não* está provado: [docs/EVALUATION.md](../EVALUATION.md) (em inglês).

## Limitações

Declaradas de antemão, porque uma falsa sensação de segurança é pior do que nenhuma:

- **É uma ferramenta local, em espaço de usuário.** Um rootkit que minta de forma consistente por todos os caminhos que o Redoubt lê fica invisível para ele. Só uma visão externa (imagem de memória tirada pelo hipervisor ou o disco lido de outra máquina) resolve isso.
- **Os seis cenários de rootkit são modelados**, a partir de documentação pública, e não capturados de infecções reais. A evidência com kernel real mostra que a ferramenta não dá alarmes falsos; não prova a detecção de um módulo de kernel oculto real.
- **É preciso ser root para cobertura completa no Linux.** Sem isso, verificações aparecem como *skipped*. O lockdown do kernel também pode restringir `/proc/kcore`.
- **Algumas verificações são heurísticas** e sua confiança é limitada de acordo (por exemplo, um socket com `bind()` que nunca faz `listen()` parece uma porta oculta).
- **Testado apenas** em Ubuntu (kernel 6.17, x86_64) e macOS 26 em Apple silicon.

## Documentação e contribuição

- **Documentos técnicos (em inglês):** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **Contribuir:** [CONTRIBUTING.md](../../CONTRIBUTING.md) — uma nova verificação costuma ter algumas dezenas de linhas mais um teste.
- **Vulnerabilidades de segurança:** veja [SECURITY.md](../../SECURITY.md); não abra uma issue pública para uma vulnerabilidade.
- **Código de conduta:** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md). O Redoubt é uma ferramenta *defensiva*: somente leitura; nunca descarrega um módulo, mata um processo ou apaga um arquivo.

## Licença

[MIT](../../LICENSE) &copy; 2026 Tej Gokani
