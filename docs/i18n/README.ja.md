<p align="center">
  <img src="../../assets/banner.png" alt="REDOUBT" width="560">
</p>

<h3 align="center">Linux / macOS 向け カーネルモジュール rootkit 検出ツール</h3>

<p align="center">
  純粋な C。依存関係なし。VM 不要。読み取り専用。<br>単一の一覧を決して信用せず、同じ質問を複数の独立した経路でカーネルに問い合わせ、答えが食い違ったときに報告します。
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
  <a href="README.zh-CN.md">简体中文</a> &middot;
  <b>日本語</b> &middot;
  <a href="README.ru.md">Русский</a>
</p>

> これは[英語版 README](../../README.md)の翻訳で、英語版が正となります。技術文書（`docs/`）は英語のみです。

---

## 概要

Linux のローダブルカーネルモジュール（LKM）型 rootkit や、macOS におけるそれに相当するカーネル拡張は、OS 自身と同じ権限で動作します。カーネルが他のすべてのプログラムに返す情報 — `lsmod`、`ps`、`netstat`、`ls` など、管理者が不審なマシンで真っ先に使うツールの出力も含めて — を書き換えることができます。

Redoubt のアプローチはシグネチャ一覧ではなく、構造に基づいています。身を隠すには、rootkit は同じ質問に答える*すべて*の経路で一貫して嘘をつかなければなりません。一方、防御側は、そのうち 1 つの経路が真実を返せば十分です。そこで Redoubt は、各事実を 2 つ以上の独立した経路で収集します — モジュールは `/proc/modules`、`/sys/module`、カーネルの実行可能メモリマップ、プロセスは libc の一覧、生の `getdents64` システムコール、`kill(pid, 0)` プローブ、ポートは `/proc/net/*` と `bind()` — そして食い違いを報告します。

> **`CLEAN` 判定を信頼する前に、[docs/THREAT_MODEL.md](../THREAT_MODEL.md)（英語）をお読みください。**

## 特長

- **シグネチャではなく、ビューの突き合わせによる検出。** rootkit の名前を変えられても機能する、振る舞いベースのチェックです。
- **16 個のチェック：** モジュールの隠蔽、カーネルコードの完全性（syscall テーブル、ftrace、インラインフック）、隠されたプロセス／ポート／ファイル、動的リンカ経由のインジェクション、macOS カーネル拡張。
- **較正された検出結果。** 各結果には確信度（0–100）、MITRE ATT&CK ID、具体的な次の一手が付きます。判定は*独立した*チェックの数で決まります。
- **競合状態を考慮。** スキャン中に変化しうるもの（プロセス、モジュール、ソケット）は、報告前に再サンプリングと再プローブを行います。
- **カバレッジを正直に表示。** 実行できなかったチェックは理由付きで *skipped* と報告され、`CLEAN` はカバーしたチェック数を示します。
- **オフラインで動作。** `snapshot` で全カーネルビューを保存し、`--from` で後から任意のマシンで解析、`--baseline` で正常状態と比較します。
- **依存関係ゼロ。** C11 と `make` だけ。読み取り専用で、デーモン・永続化・自動修復はありません。
- **実カーネルで検証済み。** CI が毎コミット、未改変の Linux 6.17 カーネルをスキャンし、フルカバレッジの `CLEAN` でなければビルドを失敗させます。

## クイックスタート

```bash
git clone https://github.com/tejgokani/redoubt.git
cd redoubt
make                      # builds ./redoubt
make test                 # 88 unit assertions + 10 scenarios

./redoubt demo            # replay bundled rootkit scenarios (offline, no root)
sudo ./redoubt scan       # scan THIS machine (root = full coverage on Linux)
```

`./redoubt demo` と `make test` は root も特定のカーネルも不要で、macOS のコレクタはネイティブに動作します。プレゼン用スクリプト：[docs/DEMO.md](../DEMO.md)（英語）。

## 使い方

| コマンド | 内容 |
|---|---|
| `scan` | このマシンをスキャンします（既定のコマンド）。 |
| `demo [name\|all]` | 同梱シナリオを実際の検出エンジンでオフライン再生します。 |
| `eval [dir]` | 全シナリオを実行し、検出マトリクス（合格／不合格）を表示します。 |
| `snapshot DIR` | このマシンの全カーネルビューを証拠またはベースラインとして保存します。 |
| `list-checks` | 16 個のチェックと、それぞれが比較する内容を一覧表示します。 |

| オプション | 内容 |
|---|---|
| `--from DIR` | 稼働中のシステムではなく、スナップショット／シナリオのディレクトリを解析します。 |
| `--baseline DIR` | 正常な既知のスナップショットとも比較します。 |
| `--only a,b / --skip a,b` | ID を指定してチェックを実行またはスキップします。 |
| `--fail-on SEV` | この重大度以上の検出があると終了コード `1`（`info`…`critical`、既定は `medium`）。 |
| `--json` | 機械可読なレポート。 |
| `--simulate SPEC` | デモ用に、稼働中のデータへ rootkit 風の偽情報を注入します（[docs/DEMO.md](../DEMO.md)）。 |

**終了ステータス：** `0` 検出なし · `1` 検出あり · `2` 使用法または内部エラー · `3` `--strict-coverage` 指定時にカバレッジ不足。全一覧：`redoubt --help`。

```bash
sudo ./redoubt snapshot /var/tmp/evidence      # 不審なホストからビューを採取
./redoubt scan --from /var/tmp/evidence        # 後から任意のマシンで解析
```

## 検出できるもの

モジュールの隠蔽、カーネルフック、隠されたプロセス／ポート／ファイル、動的リンカ経由のインジェクション、macOS カーネル拡張をカバーする 16 個のチェックです。各チェックは、次の独立した情報源を突き合わせます：

| チェック | 突き合わせる情報源 |
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

## 検証の裏付け

- **毎コミット、実際の Linux カーネルで検証。** CI は未改変の Ubuntu 6.17 カーネルで `sudo redoubt scan` を実行し、該当する 13 個のチェックすべてを実行したうえで `CLEAN` でなければビルドを失敗させます。この過程で実際の誤検知バグを 3 件発見し、いずれも回帰テストになっています。
- **macOS での実際のライブ隠蔽。** `make hooks` は、実行中のプロセスを `proc_listpids` から隠す最小限のユーザー空間フックをビルドします。Redoubt は実機上でこれを検出します。
- **シナリオマトリクスとユニットテスト。** `make test` は 88 個のアサーションと 10 個のシナリオ（モデル化した rootkit 6 件と、正常／おとり 4 件）を実行します。

*未証明*の点を含む詳細：[docs/EVALUATION.md](../EVALUATION.md)（英語）。

## 制限事項

誤った安心感は、安心感がないことよりも悪いため、最初に明記します：

- **ホスト上で動くユーザー空間ツールです。** Redoubt が読むすべての経路で一貫して嘘をつく rootkit は検出できません。それを判断できるのは帯域外の視点（ハイパーバイザによるメモリイメージ、または別のマシンから読んだディスク）だけです。
- **6 つの rootkit シナリオはモデル化したものです。** 公開資料に基づいており、実際の感染から採取したものではありません。実カーネルでの検証は、このツールが誤報を出さないことを示しますが、実際に隠れたカーネルモジュールを検出できることまでは示していません。
- **Linux で完全なカバレッジを得るには root が必要です。** root でない場合、一部のチェックは *skipped* になります。カーネルの lockdown が `/proc/kcore` を制限することもあります。
- **一部のチェックはヒューリスティックで、**確信度に上限を設けています（例：`bind()` されたが `listen()` されないソケットは、隠れたポートのように見えます）。
- **検証済みの環境：** Ubuntu（カーネル 6.17、x86_64）と、Apple シリコン上の macOS 26 のみ。

## ドキュメントと貢献

- **技術文書（英語）：** [THREAT_MODEL](../THREAT_MODEL.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [EVALUATION](../EVALUATION.md) · [DEMO](../DEMO.md)
- **貢献：** [CONTRIBUTING.md](../../CONTRIBUTING.md) — 新しいチェックの追加は、通常、数十行のコードとテスト 1 件です。
- **セキュリティ上の問題：** [SECURITY.md](../../SECURITY.md) を参照してください。脆弱性について公開 issue は立てないでください。
- **行動規範：** [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md)。Redoubt は*防御用*のツールで、読み取り専用です。モジュールのアンロード、プロセスの強制終了、ファイルの削除は行いません。

## ライセンス

[MIT](../../LICENSE) &copy; 2026 Tej Gokani
