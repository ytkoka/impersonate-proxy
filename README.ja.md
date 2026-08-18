# impersonate-proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**[English](README.md)** | **日本語** | [简体中文](README.zh-CN.md)

TLSフィンガープリント(JA3/JA4)、HTTP/2フィンガープリント、HTTPヘッダーの順序、User-Agent、送信元IPヘッダーを、単一のYAML設定ファイルから制御できるローカルMITMプロキシです。

プロキシを再起動せずにブラウザのツールバーから直接プロキシのON/OFF切り替えやフィンガープリントプロファイルの変更ができる **Chrome拡張機能** も同梱しています。

WAFのボット検知システムに対する **許可されたセキュリティテスト** を目的としています。curl・ブラウザ・Playwrightのトラフィックをこのプロキシ経由にすることで、フィンガープリントの組み合わせごとにどう判定されるかを観察できます。

## 仕組み

```
curl / browser / Playwright
        │  HTTP CONNECT (to proxy)
        ▼
┌─────────────────────────────────────────┐
│            impersonate-proxy            │
│                                         │
│  MITM TLS ◄──────────────► uTLS         │
│  (our CA cert)          (custom JA3/4)  │
│                                         │
│  Header rewriter (UA, order, add/del)   │
│  HTTP/2 framer  (SETTINGS, WINDOW_UPDATE│
│                  pseudo-header order)   │
└─────────────────────────────────────────┘
        │  Custom TLS ClientHello + HTTP/2
        ▼
   Target server / WAF
```

| レイヤー | 制御できる項目 |
|-------|----------------------|
| TLS | uTLSのプリセット、または完全にカスタムな `custom_hello` 指定により、暗号スイート・拡張とその順序(JA3 / JA4)を制御 |
| HTTP/1.1 | ヘッダーの順序、User-Agent、任意ヘッダーの追加/削除、IPスプーフィング(`X-Forwarded-For` / `True-Client-IP`) |
| HTTP/2 | SETTINGSの値と順序、WINDOW_UPDATE、疑似ヘッダーの順序(HTTP/2フィンガープリント) |

## 前提条件

- **macOS** または **Linux**(amd64 / arm64)
- **Go 1.22+**

### macOS

```bash
brew install go
```

### Linux

ディストリビューション同梱のGoは古いことが多いため、公式バイナリを直接インストールしてください:

```bash
# ダウンロードして展開(1.22.5は https://go.dev/dl/ の最新版に置き換えてください)
curl -OL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz

# PATHに追加(恒久化するには ~/.bashrc または ~/.zshrc にこの行を追記)
export PATH=$PATH:/usr/local/go/bin
```

確認:

```bash
go version
# go version go1.22.5 linux/amd64
```

> **ARM64(Raspberry Pi、AWS Gravitonなど):** ダウンロードURL内の `linux-amd64` を `linux-arm64` に置き換えてください。

## セットアップ

### 1. クローンとビルド

```bash
git clone https://github.com/ytkoka/impersonate-proxy.git
cd impersonate-proxy
make build
```

### 2. MITM CA証明書の生成

CAは初回起動時に自動生成されます。一度プロキシを起動して `ca.crt` と `ca.key` を作成してください:

```bash
make run
# 2026/04/22 12:00:00 generated CA certificate → ca.crt
# 2026/04/22 12:00:00 listening on 127.0.0.1:8080  preset=chrome
```

`Ctrl-C` で停止します。

### 3. CA証明書を信頼する

プロキシが生成するリーフ証明書をクライアントが拒否しないよう、MITM CAを信頼させる必要があります。

**macOSシステムキーチェーン**(全アプリに影響):
```bash
make trust-ca        # runs: sudo security add-trusted-cert ...
```

**Linuxシステムのトラストストア**(全アプリに影響。ca-certificatesパッケージが必要):
```bash
# Debian / Ubuntu
sudo cp ca.crt /usr/local/share/ca-certificates/impersonate-proxy.crt
sudo update-ca-certificates

# RHEL / Fedora / Amazon Linux
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/impersonate-proxy.crt
sudo update-ca-trust
```

**curlのみ**(システム全体には影響しない):
```bash
curl --cacert ca.crt ...
```

**Playwright / Node.js**:
```bash
export NODE_EXTRA_CA_CERTS="$(pwd)/ca.crt"
```

**Firefox**: 設定 → プライバシーとセキュリティ → 証明書を表示 → 認証局 → `ca.crt` をインポート

## 設定

プロキシを起動する前に `config.yaml` を編集してください。全項目にデフォルト値があるため、変更したい項目だけを指定すれば十分です。

```yaml
listen: "127.0.0.1:8080"
mgmt_listen: "127.0.0.1:8081"  # Chrome拡張機能が使う管理API(空文字で無効化)
ca_cert: "ca.crt"
ca_key:  "ca.key"

tls:
  # TLSフィンガープリントのプリセット(JA3 / JA4を制御)
  # 選択肢: chrome | firefox | safari | edge | ios | random | golang
  preset: "chrome"

http:
  # User-Agentを上書き(空にするとクライアントのUAをそのまま通す)
  user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

  # 送信元IPを偽装: X-Forwarded-For と True-Client-IP の両方をこの値に設定し、
  # クライアントが既に設定していた値を上書きする(空にすると無効化)
  # client_ip: "1.2.3.4"

  # このヘッダー順で送出する。リストにないヘッダーは末尾に追加される
  header_order:
    - "Host"
    - "User-Agent"
    - "Accept"
    - "Accept-Language"
    - "Accept-Encoding"
    - "Connection"

  # ヘッダーを追加または上書き
  add_headers:
    Accept-Language: "ja,en-US;q=0.9,en;q=0.8"

  # 転送前に削除するヘッダー
  remove_headers: []

http2:
  enabled: true

  # SETTINGSフレームのエントリ — idと順序の両方がHTTP/2フィンガープリントに影響する。
  # RFC 7540 §11.3 のID:
  #   1=HEADER_TABLE_SIZE  2=ENABLE_PUSH  3=MAX_CONCURRENT_STREAMS
  #   4=INITIAL_WINDOW_SIZE  5=MAX_FRAME_SIZE  6=MAX_HEADER_LIST_SIZE
  settings:
    - { id: 1, val: 65536 }    # ここではChromeのデフォルト値を例示
    - { id: 2, val: 0 }
    - { id: 4, val: 6291456 }
    - { id: 6, val: 262144 }

  # コネクションレベルのWINDOW_UPDATE増分
  window_update: 15663105

  # HEADERSフレーム内の疑似ヘッダーの順序
  pseudo_header_order: [method, authority, scheme, path]
```

### 管理API

プロキシ起動時、`mgmt_listen`(デフォルト `127.0.0.1:8081`)にも軽量なHTTP APIが公開されます。Chrome拡張機能はこれを使ってプロキシを再起動せずに実行時の設定を読み書きします。curlから直接呼び出すこともできます:

| エンドポイント | メソッド | 説明 |
|---|---|---|
| `/api/config` | `GET` | 現在の設定をJSONで返す(現在の `custom_hello` を含む) |
| `/api/config` | `POST` | TLSプリセット(完全にカスタムな `custom_hello` を含む)、送信元IP、User-Agentを更新 |

```bash
# 現在の設定を読む
curl http://127.0.0.1:8081/api/config

# Firefoxのフィンガープリントに切り替え、偽装IPを設定
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"tls_preset":"firefox","client_ip":"203.0.113.1","user_agent":""}'

# 実行時に任意のJA3/JA4フィンガープリントへ切り替える — config.yamlのcustom_helloブロックと
# 同じフィールドをJSONとして送信する(後述の「カスタムTLSフィンガープリント」を参照)
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "tls_preset": "custom",
    "custom_hello": {
      "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
      "curves": ["X25519", "P256", "P384"],
      "versions": ["1.3", "1.2"],
      "extensions": [2570, 0, 23, 65281, 10, 11, 35, 16, 5, 18, 13, 51, 45, 43, 27, 21]
    },
    "client_ip": "",
    "user_agent": ""
  }'
```

変更は新規接続から即座に反映されます。APIを完全に無効化するには `mgmt_listen: ""` を設定してください。

### ブラウザ別フィンガープリント早見表

| ブラウザ | TLSプリセット | HTTP/2 SETTINGS | WINDOW_UPDATE |
|---------|-----------|-----------------|---------------|
| Chrome  | `chrome`  | `1:65536,2:0,4:6291456,6:262144` | 15663105 |
| Firefox | `firefox` | `1:65536,4:131072,5:16384`       | 12517377 |
| Safari  | `safari`  | `1:4096,3:100,4:2097152,6:16384` | 10485760 |

### カスタムTLSフィンガープリント(`preset: "custom"`)

組み込みのプリセット(`chrome`、`firefox`、`safari` など)で大半のケースはカバーできます。特定のブラウザバージョンや、これらのプリセットとは異なるフィンガープリントに合わせたい場合は、`preset: "custom"` を設定し `custom_hello` ブロックを指定してください。

**JA3 / JA4と設定フィールドの対応**

| フィンガープリント要素 | 設定フィールド | 備考 |
|---|---|---|
| TLSバージョン範囲 | `versions` | 最小/最大は自動的に算出される |
| 暗号スイートのリストと順序 | `cipher_suites` | GREASEのプレースホルダーとして `0x0a0a` を使用。uTLSが接続ごとにランダム化する |
| 拡張タイプIDと順序 | `extensions` | 順序がJA3のextensions要素を直接左右する。GREASEパターン(`0xXAXA`)に一致する値は接続ごとにランダム化される |
| サポートするグループ(曲線) | `curves` | 送信されるキーシェアも制御する |

> JA3・JA4は一方向ハッシュのため、ハッシュ値から元の仕様を逆算することはできません。対象ブラウザの実際のパラメータは [tls.peet.ws](https://tls.peet.ws) やWiresharkで調べ、それを `custom_hello` に転記してください。

**Chrome 131の例**

```yaml
tls:
  preset: "custom"
  custom_hello:
    cipher_suites:      # 16進ID。0x0a0a = GREASEプレースホルダー(接続ごとにランダム化)
      - 0x0a0a
      - 0x1301          # TLS_AES_128_GCM_SHA256
      - 0x1302          # TLS_AES_256_GCM_SHA384
      - 0x1303          # TLS_CHACHA20_POLY1305_SHA256
      - 0xc02b          # ECDHE-ECDSA-AES128-GCM-SHA256
      - 0xc02f          # ECDHE-RSA-AES128-GCM-SHA256
      - 0xc02c          # ECDHE-ECDSA-AES256-GCM-SHA384
      - 0xc030          # ECDHE-RSA-AES256-GCM-SHA384
      - 0xcca9          # ECDHE-ECDSA-CHACHA20-POLY1305
      - 0xcca8          # ECDHE-RSA-CHACHA20-POLY1305
      - 0xc013          # ECDHE-RSA-AES128-SHA
      - 0xc014          # ECDHE-RSA-AES256-SHA
      - 0x009c          # RSA-AES128-GCM-SHA256
      - 0x009d          # RSA-AES256-GCM-SHA384
      - 0x002f          # RSA-AES128-SHA
      - 0x0035          # RSA-AES256-SHA
    curves:             # X25519 | X25519Kyber768 | P256 | P384 | P521
      - "X25519Kyber768"
      - "X25519"
      - "P256"
    versions:           # アドバタイズするTLSバージョン
      - "1.3"
      - "1.2"
    extensions:         # 拡張タイプIDを順序通りに(JA3のextensions要素を制御)
      - 0x0a0a          # GREASE
      - 0               # server_name (SNI)
      - 23              # extended_master_secret
      - 65281           # renegotiation_info
      - 10              # supported_groups
      - 11              # ec_point_formats
      - 35              # session_ticket
      - 16              # ALPN
      - 5               # status_request
      - 18              # signed_certificate_timestamp
      - 13              # signature_algorithms
      - 51              # key_share
      - 45              # psk_key_exchange_modes
      - 43              # supported_versions
      - 27              # compress_certificate
      - 17513           # application_settings (ALPS)
      - 0x0a0a          # GREASE
      - 21              # padding
```

**対応している拡張タイプID**

| ID | 名前 | 備考 |
|---|---|---|
| `0xXAXA`(GREASEパターン全般) | GREASE | 接続ごとにランダム化 |
| `0` | server_name (SNI) | |
| `5` | status_request | OCSPステープリング |
| `10` | supported_groups | `curves` リストを使用 |
| `11` | ec_point_formats | 固定: uncompressed (0) |
| `13` | signature_algorithms | Chrome相当のデフォルト |
| `16` | ALPN | `h2`、`http/1.1` をアドバタイズ |
| `18` | signed_certificate_timestamp | |
| `21` | padding | BoringSSL方式のパディング |
| `23` | extended_master_secret | |
| `27` | compress_certificate | |
| `28` | record_size_limit | 固定: 0x4001 |
| `35` | session_ticket | |
| `43` | supported_versions | `versions` リストを使用 |
| `45` | psk_key_exchange_modes | PSK with DHE |
| `50` | signature_algorithms_cert | Chrome相当のデフォルト |
| `51` | key_share | `curves` に基づくX25519・P256のキーシェア |
| `17513` | application_settings (ALPS) | `h2` をアドバタイズ |
| `65281` | renegotiation_info | |
| その他 | GenericExtension | 空ペイロードで送信 |

> **実行時の変更:** `preset: "custom"` は `config.yaml` に限定されません。管理API(前述の「管理API」セクションを参照。`POST /api/config` に `custom_hello` オブジェクトを送信)や、Chrome拡張機能のTLS Presetドロップダウンからも、プロキシを再起動せずに実行時に切り替えられます。

## 使い方

### プロキシを起動する

```bash
make run
# ポート8080で動いている既存プロセスを終了し、再ビルドして起動する
```

フィンガープリントのプロファイルを切り替えるには、`config.yaml` を編集して `make run` を再実行してください。

### curl

```bash
# CAをシステム全体で信頼させている場合(make trust-ca 実行後):
curl --proxy http://127.0.0.1:8080 https://tls.peet.ws/api/all

# システムに信頼させていない場合 — CAを明示的に指定:
curl --proxy http://127.0.0.1:8080 --cacert ca.crt https://tls.peet.ws/api/all
```

### Chrome拡張機能

`chrome-extension/` ディレクトリには、ブラウザのツールバーからプロキシを操作するManifest V3拡張機能が入っています。

<img src="image/chrome-extension.png" alt="Chrome拡張機能のポップアップ" width="280">

**インストール:**

1. Chromeで `chrome://extensions` を開く
2. **デベロッパーモード**を有効化(右上のトグル)
3. **パッケージ化されていない拡張機能を読み込む**をクリックし、`chrome-extension/` フォルダを選択

**操作項目:**

| 操作項目 | 内容 |
|---|---|
| プロキシトグル | Chromeのプロキシ設定を有効/無効化(`:8080` 経由でトラフィックをルーティング) |
| TLS Preset | uTLSのフィンガープリントプリセットを切り替え(chrome / firefox / safari / edge / ios / random / golang / **custom**) |
| Cipher Suites / Curves / TLS Versions / Extensions | **Custom (JA3/JA4)** 選択時に表示 — `config.yaml` の `custom_hello` と同じフィールドで、YAMLを編集したりプロキシを再起動したりせずに任意のJA3/JA4フィンガープリントを指定できる |
| Client IP | 全リクエストに `X-Forwarded-For` と `True-Client-IP` を設定 |
| User-Agent | HTTPの `User-Agent` ヘッダーを上書き |
| Applyボタン | 新しい設定を管理APIにPOSTする。即座に反映される |
| APIフィールド | 管理APIのアドレス(デフォルト `http://127.0.0.1:8081`) |

> **User-Agentの適用範囲:** この拡張機能が変更するのはHTTPの `User-Agent` **ヘッダー**のみです。JavaScriptの `navigator.userAgent` はChrome自体が制御しており、影響を受けません。両方を同時に偽装するには、プロキシ設定と併せてChromeを `--user-agent="..."` オプション付きで起動してください。

### Playwright(Node.js)

```js
const { chromium } = require('playwright');

const browser = await chromium.launch();
const context = await browser.newContext({
  proxy: { server: 'http://127.0.0.1:8080' },
});
// CAがシステムキーチェーンに入っていない場合は、起動前に設定:
// NODE_EXTRA_CA_CERTS=./ca.crt node script.js
const page = await context.newPage();
await page.goto('https://tls.peet.ws/api/all');
```

### Playwright(Python)

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context(proxy={"server": "http://127.0.0.1:8080"})
    page = context.new_page()
    page.goto("https://tls.peet.ws/api/all")
```

CAがシステム全体で信頼されていない場合は、`NODE_EXTRA_CA_CERTS`(Node)または `REQUESTS_CA_BUNDLE`(Python)を設定してください。

## フィンガープリントの検証

[tls.peet.ws](https://tls.peet.ws) は受け取ったリクエストのフィンガープリントを詳細に返してくれます。`jq` やPythonに通すと見やすくなります:

```bash
curl -s --proxy http://127.0.0.1:8080 --cacert ca.crt \
  https://tls.peet.ws/api/all | python3 -m json.tool
```

確認すべき主なフィールド:

| フィールド | 説明 |
|-------|-------------|
| `tls.ja3_hash` | JA3フィンガープリントハッシュ |
| `tls.ja4` | JA4フィンガープリント文字列 |
| `http2.akamai_fingerprint` | HTTP/2フィンガープリント文字列(SETTINGS + WINDOW_UPDATE + 疑似ヘッダー順)— フィールド名はtls.peet.ws側のAPI仕様による |
| `http1.headers` | サーバーが受信したヘッダー名の順序 |
| `user_agent` | サーバー側から見えるUser-Agent |
| `ip` | サーバー側から見える送信元IP — `X-Forwarded-For` / `True-Client-IP` の偽装をここで確認 |

## プロジェクト構成

```
impersonate-proxy/
├── main.go                   # エントリーポイント
├── config/config.go          # YAML設定の構造体とデフォルト値
├── fp/dialer.go              # uTLSダイアラー — TLSフィンガープリントのプリセット
├── h2fp/conn.go              # HTTP/2フレーマー — SETTINGS / WINDOW_UPDATE / 疑似ヘッダー制御
├── mitm/ca.go                # MITM CA: リーフ証明書の生成・キャッシュ・発行
├── proxy/proxy.go            # プロキシサーバー: CONNECT処理、プロトコル分岐、実行時設定
├── rewrite/headers.go        # HTTPヘッダー書き換え(UA、順序、追加/削除、IP偽装)
├── mgmt/server.go            # 管理HTTP API(/api/config の GET + POST)
├── chrome-extension/
│   ├── manifest.json         # Manifest V3
│   ├── popup.html            # ツールバーポップアップUI
│   ├── popup.css
│   ├── popup.js               # プロキシトグル + 管理APIクライアント
│   └── icon.svg
├── config.yaml               # デフォルト設定
└── Makefile
```

## Makefileターゲット

| ターゲット | 説明 |
|--------|-------------|
| `make build` | バイナリをコンパイル |
| `make run` | ビルドし、既存プロセスを終了させてから起動 |
| `make trust-ca` | `ca.crt` をmacOSシステムキーチェーンに追加(sudoが必要) |
| `make clean` | バイナリ、`ca.crt`、`ca.key` を削除 |

## クリーンアップ

バイナリと生成されたCAファイルを削除します:

```bash
make clean
```

CAをmacOSシステムキーチェーンに追加していた場合は、**キーチェーンアクセス**(「impersonate-proxy CA」で検索)から削除するか、以下を実行してください:

```bash
sudo security delete-certificate -c "impersonate-proxy CA" /Library/Keychains/System.keychain
```

## 既知の制限

- **MITM前提**: プロキシは通信を復号・再暗号化します。クライアントは生成されたCAを信頼している必要があります。
- **クライアント側はHTTP/2非対応**: クライアント→プロキシ間はHTTP/1.1(CONNECT経由)です。プロキシ→サーバー間のみカスタムフィンガープリント付きのHTTP/2を使用します。
- **チャンク転送のリクエストボディ**: `Transfer-Encoding: chunked` を伴うリクエストボディは現時点で正しく転送されません。
- **QUIC / HTTP/3非対応**: 対象外です。
- **User-Agent(HTTPヘッダーのみ)**: プロキシはHTTPの `User-Agent` ヘッダーを書き換えますが、JavaScriptの `navigator.userAgent` はブラウザが独自に設定するため影響を受けません。両方を同時に上書きするにはChromeの `--user-agent` 起動オプションを使用してください。

## 法的注意事項

本ツールは **許可されたセキュリティテストのみ** を目的としています。例えば、自分が所有するシステムや、書面による明示的なテスト許可を得ているシステムに対するWAF・ボット検知設定のテストなどです。

許可を得ていないシステムに対して本ツールを使用することは、適用される法律(米国のComputer Fraud and Abuse Act、日本の不正アクセス禁止法、または各法域における同等の法令など)や対象の利用規約に違反する可能性があります。

**作者は誤用による一切の責任を負いません。**

## 謝辞

- [uTLS](https://github.com/refraction-networking/utls) — TLSフィンガープリントのカスタマイズ
- [tls.peet.ws](https://tls.peet.ws) — 例で使用しているフィンガープリント検査API
- [JA4+](https://github.com/FoxIO-LLC/ja4) — フィンガープリント標準の参考資料
