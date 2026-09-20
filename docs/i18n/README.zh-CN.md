<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">面向 Linux 与 macOS 的内核模块 Rootkit 检测工具</h3>

<p align="center">
  纯 C 实现。无依赖。无需虚拟机。只读。<br>它从不信任单一列表——而是通过多条相互独立的途径向内核询问同一个问题，并在答案不一致时报告。
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
  <a href="README.pt-BR.md">Português (BR)</a> &middot;
  <b>简体中文</b> &middot;
  <a href="README.ja.md">日本語</a> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> 本文是[英文 README](../../README.md)的翻译，以英文版为准。技术文档（`docs/`）仅提供英文版本。

---

## 概述

Linux 上的可加载内核模块（LKM）Rootkit，以及 macOS 上与之对应的内核扩展，与操作系统本身拥有相同的权限。它们可以篡改内核提供给其他所有程序的信息——包括 `lsmod`、`ps`、`netstat` 和 `ls`，而这些正是管理员在可疑主机上最先使用的工具。

Redoubt 的思路是结构性的，而不是依赖特征库。要隐藏自己，Rootkit 必须在内核提供的*每一条*回答同一问题的途径上始终保持一致地撒谎；而防御方只需要其中一条途径说出真相。因此 Redoubt 通过两条或更多相互独立的途径采集每一项事实——模块：`/proc/modules`、`/sys/module` 以及内核可执行内存映射；进程：libc 列表、原始 `getdents64` 系统调用和 `kill(pid, 0)` 探测；端口：`/proc/net/*` 和 `bind()`——并报告不一致之处。

> **在信任 `CLEAN` 结论之前，请先阅读 [docs/THREAT_MODEL.md](../THREAT_MODEL.md)（英文）。**

## 主要特性

- **基于多视图交叉比对，而非特征码。** 行为层面的检查，即使 Rootkit 被改名也依然有效。
- **16 项检查：** 模块隐藏、内核代码完整性（系统调用表、ftrace、内联钩子）、隐藏的进程/端口/文件、动态链接器注入，以及 macOS 内核扩展。
- **经过校准的发现。** 每条发现都带有置信度（0–100）、MITRE ATT&CK 编号和具体的下一步建议；结论统计的是*相互独立*的检查数量。
- **考虑竞态条件。** 扫描期间可能变化的对象（进程、模块、套接字）在上报前会重新采样并重新探测。
- **如实说明覆盖范围。** 无法运行的检查会连同原因标记为 *skipped*；`CLEAN` 会注明它覆盖了多少项检查。
- **支持离线使用。** `snapshot` 保存全部内核视图；`--from` 之后可在任意机器上分析；`--baseline` 与已知良好状态比对。
- **零依赖。** 仅需 C11 与 `make`。只读：无守护进程、无持久化、无自动处置。
- **已在真实内核上验证。** CI 在每次提交时扫描未经修改的 Linux 6.17 内核，若结果不是完整覆盖下的 `CLEAN` 则构建失败。

## 快速开始

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` 和 `make test` 既不需要 root，也不要求特定内核；macOS 采集器可原生运行。演示脚本：[docs/DEMO.md](../DEMO.md)（英文）。

## 用法

| 命令 | 作用 |
|---|---|
| `scan` | 扫描本机（默认命令）。 |
| `demo [name\|all]` | 使用真实检测引擎离线重放内置场景。 |
| `eval [dir]` | 运行所有场景并输出检测矩阵（通过/失败）。 |
| `snapshot DIR` | 将本机所有内核视图保存为取证材料或基线。 |
| `list-checks` | 列出 16 项检查及各自比对的内容。 |

| 选项 | 作用 |
|---|---|
| `--from DIR` | 分析快照/场景目录，而不是在线系统。 |
| `--baseline DIR` | 同时与已知良好的快照比对。 |
| `--only a,b / --skip a,b` | 按 id 运行或跳过指定检查。 |
| `--fail-on SEV` | 出现不低于该严重级别的检测时退出码为 `1`（`info`…`critical`，默认 `medium`）。 |
| `--json` | 机器可读的报告。 |
| `--simulate SPEC` | 为演示向实时数据注入类似 Rootkit 的谎言（[docs/DEMO.md](../DEMO.md)）。 |

**退出状态：** `0` 未发现问题 · `1` 检测到问题 · `2` 用法或内部错误 · `3` 使用 `--strict-coverage` 时覆盖不完整。完整列表：`redoubt --help`。

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # 从可疑主机采集视图
./redoubt scan --from /var/tmp/evidence        # 之后在任意机器上分析
```

## 检测内容

16 项检查覆盖模块隐藏、内核钩子、隐藏的进程/端口/文件、动态链接器注入以及 macOS 内核扩展。每项检查都会交叉比对下列相互独立的来源：

| 检查项 | 交叉比对的来源 |
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

## 验证证据

- **每次提交都在真实的 Linux 内核上验证。** CI 在未经修改的 Ubuntu 6.17 内核上运行 `sudo redoubt scan`，若结论不是覆盖全部 13 项适用检查的 `CLEAN` 则构建失败。过程中发现了三个真实的误报缺陷，每个现在都是回归测试。
- **macOS 上真实的现场隐藏。** `make hooks` 构建一个极简的用户态钩子，让正在运行的进程对 `proc_listpids` 隐身；Redoubt 在实机上将其检测出来。
- **场景矩阵与单元测试。** `make test` 运行 88 条断言和 10 个场景（6 个建模的 Rootkit 场景与 4 个干净/诱饵对照）。

完整说明（包括*尚未证明*的部分）：[docs/EVALUATION.md](../EVALUATION.md)（英文）。

## 局限性

先把话说在前面，因为虚假的安全感比没有安全感更糟：

- **这是一款本机、用户态工具。** 如果 Rootkit 在 Redoubt 读取的每一条途径上都始终一致地撒谎，它就无法被发现。只有带外视角（由虚拟机监控程序获取的内存镜像，或从另一台机器读取磁盘）才能解决这一问题。
- **六个 Rootkit 场景是建模而成的**，依据公开资料，并非来自真实感染的采集。真实内核上的证据表明工具不会乱报警；但它并未证明能检测到真实存在的隐藏内核模块。
- **在 Linux 上要获得完整覆盖需要 root。** 否则部分检查会显示为 *skipped*。内核 lockdown 也可能限制对 `/proc/kcore` 的访问。
- **部分检查属于启发式**，其置信度相应设有上限（例如：已 `bind()` 但从不 `listen()` 的套接字看起来就像隐藏端口）。
- **仅在以下环境测试过：** Ubuntu（内核 6.17，x86_64）以及 Apple 芯片上的 macOS 26。

## 文档与贡献

- **技术文档（英文）：** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **参与贡献：** [CONTRIBUTING.md](../../CONTRIBUTING.md)——新增一项检查通常只需几十行代码加一个测试。
- **安全漏洞：** 请参阅 [SECURITY.md](../../SECURITY.md)；请勿为漏洞创建公开 issue。
- **行为准则：** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md)。Redoubt 是*防御性*工具：只读；绝不卸载模块、终止进程或删除文件。

## 许可证

[MIT](../../LICENSE) &copy; 2026 Tej Gokani
