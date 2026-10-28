# 仕様の違和感 棚卸し（DX 観点）

2026-10-28 時点の `main`（cb90d36）を対象に、利用者から見て「気持ち悪い」仕様を 6 観点で洗い出したもの。
実装バグ（push 失敗時に checkout が戻らない件など）は別扱いで、ここでは仕様・設計・命名・既定値を扱う。

- **重要度**: 高 = 利用者が詰まる／安全性の誤解を招く、中 = 毎回の手間・混乱、低 = 一貫性・美観
- **format**: 「破壊」は storage 上の配置やワイヤ形式が変わるもの。prototype で format は unstable と宣言済みなので、まとめて一度に変えるのが望ましい

---

## 1. URL と設定

| # | 違和感 | 理由 | 修正案 | 重要度 | format |
|---|---|---|---|---|---|
| U1 | `e2ee::git+https://...` とスキームが三重 | 一番よく使う GitHub の書き方が一番長い。`git+` は「carrier backend か directory backend か」という実装都合 | `e2ee::https://…` / `e2ee::git@host:…` は carrier と自動判定。directory backend だけ `e2ee::dir:/path` と明示 | 高 | URL のみ |
| U2 | 相対パスの URL がそのまま保存される | `git clone e2ee::store c3` は通るが、`c3` 内の fetch は `c3/store` を探して「not initialized」 | パース時に絶対パス化して保存 | 高 | − |
| U3 | 相対パスの `e2ee.key` がそのまま `remote.origin.e2ee-key` に保存される | clone 後の fetch/push がすべて「read key file」で失敗 | 保存前に canonicalize | 高 | − |
| U4 | key の設定キーが 2 系統 | clone 時は `e2ee.key`、以後は `remote.<name>.e2ee-key`（自動コピー）。どちらを見ればいいか分からない | 解決順（remote 単位 → 全体）を明文化し、`e2ee.key` を普段使いでも正式なフォールバックにする | 中 | − |
| U5 | ブランチ名を指定する手段がない | 固定値 `git-remote-e2ee`（`storage.rs:442`） | 既定を `main` にし、URL の `#branch` で上書き（§4 S3 も参照） | 中 | 破壊 |
| U6 | ドットを含むリモート名・URL を直接指定する呼び出しが動かない | git で正当な `my.backup` や `git ls-remote e2ee::…` が拒否される | 状態ディレクトリ名は名前をエンコードして作る。URL を直接指定されたら URL のハッシュで状態を持つ | 低 | − |

## 2. CLI

| # | 違和感 | 理由 | 修正案 | 重要度 | format |
|---|---|---|---|---|---|
| C1 | `init` と `carrier-init` が別コマンド | backend の違いがコマンド名に漏れている | `git-e2ee init <URL>`（URL は §1 U1 と同じ書式）に統一 | 高 | − |
| C2 | `--storage <path>` と `--remote <url>` の二択フラグが全コマンドにある | git で「remote」はリモート名のこと。`--remote-name` とも並ぶので紛らわしい | 位置引数の URL 1 つにする。もしくは `--remote <git のリモート名>` から URL と key を引く | 高 | − |
| C3 | `push` / `fetch` / `verify` が directory backend 専用 | carrier では使えない。helper と機能が重複していて存在理由も不明瞭 | `verify` だけ両 backend 対応にして残し、`push` / `fetch` は削除するか debug 用に隠す | 中 | − |
| C4 | 初期設定に 4 ステップ必要 | `keygen` → `carrier-init` → `remote add` → `config` | `git-e2ee init <URL> [--key 既定パス]` で鍵生成・初期化・`remote add`・config までを 1 回で | 高 | − |
| C5 | 2 台目のデバイス追加が 3 往復 | A が repository root を B に渡す → B が keygen・export → A が device-add。root を事前に知る必要がある | 鍵生成時に root へ束縛するのをやめ、B は root を知らずに keygen・export できるようにする。root への束縛は A の device-add 時に policy 側で行う（C6 と同じ変更） | 高 | 破壊（鍵形式） |
| C6 | 鍵がリポジトリごとに必要 | 鍵が repository root に束縛されている。リポジトリ N 個 × デバイス M 台 = 鍵 N×M 個 | デバイス鍵を 1 本にして、リポジトリごとの束縛は policy 側で行う | 中 | 破壊 |
| C7 | `device-list` が不透明な ID しか出さない | 失効させたいデバイスがどれか分からない | device-add 時にラベルを付けて policy 内に暗号化して保存し、一覧で表示 | 高 | 破壊（policy） |
| C8 | `--key` が毎回必須 | `--output` / `--key` に既定パスがない | `~/.config/git-e2ee/keys/<repo>.json` などを既定にする。git リポジトリ内で実行したら remote 設定から引く | 中 | − |
| C9 | `git-e2ee` と `git-remote-e2ee` の命名 | `git e2ee …` でも呼べることが書かれていない。ドキュメントは常に `git-e2ee` 表記 | `git e2ee` 表記に統一 | 低 | − |
| C10 | 管理系コマンドが CAS 競合で自動再試行しない | 「勝った状態を見てもう一度」と手作業を要求している | 冪等な操作（同じデバイスの add / revoke）は再読込して 1 回再試行 | 低 | − |

## 3. ディスク上に生まれるファイル

| # | ファイル | 違和感 | 修正案 | 重要度 |
|---|---|---|---|---|
| F1 | `<key>.admin-state.json` | 鍵の隣に黙って作られ、「鍵と一緒にバックアップしろ」と言われる。鍵を移動すると pin を失う | 鍵ファイル内に統合する。もしくは状態ディレクトリ（`~/.local/state/git-e2ee/`）に repository root 単位で置く | 高 |
| F2 | `.git/git-remote-e2ee/<remote名>/state.json` | **リモート名で状態を持つため、`git remote rename` すると rollback 保護の pin が無言で消える** | repository root（またはその URL）で状態を持つ | 高 |
| F3 | `~/.cache/git-remote-e2ee/carrier/<sha>` | 単調に増え続け、gc は無効化されている。消す手段は手動の `rm` だけ | `git e2ee cache gc` / `cache clear` を用意し、ドキュメントに容量の目安を書く | 中 |
| F4 | 名前空間の不一致 | cache は `git-remote-e2ee/`、README が勧める鍵の置き場所は `~/.config/git-e2ee/`、`.git/` 内は `git-remote-e2ee/` | `git-e2ee` に統一する（XDG config / state / cache） | 低 |
| F5 | `rejected-heads.json` | recovery の証拠が `.git` 内に置かれ、存在がドキュメントにない | 置き場所と用途を guide に書く | 低 |
| F6 | directory backend の `.staging/`, `HEAD.lock` | 中断時の残骸を手で消すよう案内している | `git e2ee verify --repair` などで掃除できるようにする | 低 |

## 4. storage 上の配置

| # | 違和感 | 理由 | 修正案 | 重要度 | format |
|---|---|---|---|---|---|
| S1 | トップが `e2ee/` 1 つだけ | 専用ブランチなので包む意味がない。**directory backend には `e2ee/` がなく、2 つの backend で配置が違う**（AGENTS.md の backend 中立方針に反する） | ルート直下に配置し、両 backend 共通にする | 中 | 破壊 |
| S2 | 何のリポジトリか分からない | GitHub のトップページに `e2ee/` しか見えない。誤操作で消す・編集する危険がある | ルートに平文の `README.md`（「暗号化リポジトリ。手で触らない。clone 方法…」）。新たに漏れる情報はない | 中 | 追加のみ |
| S3 | ブランチ名 `git-remote-e2ee` | 空のリポジトリの default は `main`。ブランチ保護の ruleset も `main` 前提のことが多い | 既定を `main` にする。ただし `main` に carrier 以外の中身があれば拒否（README 付きで作った GitHub リポジトリ対策） | 中 | 破壊 |
| S4 | **format の版を示す目印がない** | 版は各オブジェクトの magic（`E2EES05`）にしかない。古いクライアントは「更新してください」ではなく「認証失敗」で落ちる | ルートに `FORMAT`（例 `git-remote-e2ee storage 5`）を置き、最初に読む | 高 | 追加 |
| S5 | `objects/` という名前 | 中身は暗号化 pack。git の `objects/` と紛らわしい | `packs/` | 低 | 破壊 |
| S6 | `HEAD` という名前 | git の HEAD とは別物（最新 manifest へのポインタ） | 用語ごと変えるなら一緒に（優先度低） | 低 | 破壊 |
| S7 | `.gitattributes` が `e2ee/** -delta` | S1 の配置に依存している | `* -delta` | 低 | 破壊 |

提案する配置（両 backend 共通）:

```text
README.md        平文の説明と clone 方法
FORMAT           版の宣言（最初に読む）
.gitattributes   "* -delta"（carrier のみ）
HEAD
manifests/ab/<id>/...
packs/ab/<id>/...
```

## 5. エラーメッセージ

| # | 違和感 | 例・場所 | 修正案 | 重要度 |
|---|---|---|---|---|
| E1 | **git が認識する定型文を返していない** | push 失敗時に `error <ref> non-fast-forward update rejected for refs/heads/main` を返すので、git は `[remote rejected]` と表示し、いつもの「git pull してから」というヒントが出ない | git が解釈する定型文（`non-fast forward` / `fetch first` / `already exists` / `needs force` / `stale info`。手元の git 2.43 のバイナリに含まれることを確認）をそのまま返す。CAS 競合は `fetch first`、タグの上書きは `already exists` | 高 |
| E2 | 改行入りのエラーで helper のプロトコルが壊れる | git の stderr をそのまま埋め込んでいる（`git-remote-e2ee.rs:175`） | 1 行に潰す。詳細は stderr に出す | 高 |
| E3 | 安全性のエラーに次の一手がない | `remote manifest history forked from the locally pinned head` / `remote policy rolled back` / `remote repository root changed` | 何が起きた可能性があるか（storage の改ざん・巻き戻し）と次の行動（`git e2ee recover` で調べる、管理者に連絡）を添える | 高 |
| E4 | 原因と違うメッセージ | パスの誤りで `encrypted repository is not initialized`。push の失敗理由（認証・ネットワーク）がすべて CAS 競合扱い | 「指定パスに storage がない」と「storage が空」を分ける。push の stderr を保持する | 中 |
| E5 | 内部表現の露出 | `required {:?} object` が `Pack` / `Manifest` を Debug 表示。manifest ID・generation が素の 64 桁 hex | 利用者向けの語に直す。ID は短縮表示 | 低 |
| E6 | 失効済み・権限なしのデバイス | `device is not an active reader` / `cannot open the generation key` | 「このデバイスは失効しているか、まだ追加されていません。device ID: … を管理者に伝えてください」 | 中 |
| E7 | 設定不足 | `missing Git config remote.X.e2ee-key (or clone-time e2ee.key)` | 実行すべきコマンド例（`git config remote.X.e2ee-key <path>`）を出す | 中 |
| E8 | 接頭辞の不統一 | helper は `e2ee:`、CLI は anyhow 既定の `Error:` | `git-e2ee:` / `fatal:` など git 風にそろえる | 低 |
| E9 | 判定を文字列照合に頼っている | recovery の分類を `detail.contains("unsupported")` で決めていて、storage が文言に干渉できる | エラー型で分類する（DX というより保守性） | 中 |

## 6. 既定値

| # | 項目 | 現在 | 違和感 | 修正案 | 重要度 |
|---|---|---|---|---|---|
| D1 | `--remote-name` | `fetch` は `e2ee`、`recover` は `origin`、ドキュメントの例は `private` | 3 つばらばらで、`fetch` と `recover` が別の pin を見る | 位置引数で git のリモート名を受け、既定は `origin` にそろえる | 高 |
| D2 | `device-add --role` | `write` | 共有相手に付けると最小権限にならない | 必須にする（明示させる）。既定を残すなら `read` | 中 |
| D3 | HEAD の通知 | `refs/heads/main` 固定、`main` は削除拒否 | `master` / `trunk` のリポジトリで clone 後に HEAD がない | manifest に default branch を記録する（初回 push のブランチ、または `symbolic-ref`） | 中 |
| D4 | carrier ブランチ | `git-remote-e2ee` | §4 S3 | `main` | 中 |
| D5 | 鍵の置き場所 | なし（`--output` 必須） | §2 C8 | XDG config 配下 | 中 |
| D6 | carrier チャンク 32 MiB、pack セグメント 1 MiB、recovery の上限 | 固定値 | 変更できないことは問題ないが、ドキュメントに一覧がない | guide の「Limits」に集約 | 低 |
| D7 | force push で古い tip が手元にない場合 | `fetch first` で拒否 | `+` を付けても上書きできない。git の `--force` と意味が違う | `--force` なら許可する。安全側に残すなら `--force-with-lease` 相当として文書化 | 中 |

---

## 横断的な結論

1. **「storage の指定方法」を URL 1 本に統一するのが根っこ。** U1・C1・C2・C4・D1 は同じ問題の現れで、`git e2ee init <URL>` と `git remote add x e2ee::<URL>` が同じ文字列を受けるようになると、一気に解消する。
2. **ローカル状態の鍵を「名前」ではなく「repository root」にする。** F1・F2・D1 はどれも、名前やパスの変更で rollback 保護が黙って外れる問題。安全性の誤解に直結するので、DX と言いつつ最優先。
3. **format を壊す変更は 1 回にまとめる。** S1・S3・S4・S5・S7・U5（配置とブランチ）、C5・C6・C7（鍵と policy）は次の format 版でまとめて入れる。`FORMAT` ファイル（S4）はその前提になるので最初に入れる。
4. **git の作法に合わせる。** E1・E8・D3・D7 は「git に慣れた人が期待する挙動」とのずれ。小さく直せて効果が大きい。

### 着手順の提案

| 順 | 内容 | format |
|---|---|---|
| 1 | E1・E2（git の定型文と 1 行化）、U2・U3（絶対パス化） | 非破壊・小 |
| 2 | F2・F1・D1（状態を root 単位に） | ローカル状態のみ |
| 3 | URL 統一（U1）と CLI 再編（C1〜C4, C8） | URL・CLI |
| 4 | format v6：配置・`FORMAT`・README・`main`・`packs/`、鍵と policy（C5〜C7） | 破壊 |
