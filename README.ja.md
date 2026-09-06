# impersonate-proxy

[![Chrome Web Store](https://img.shields.io/badge/Chrome_Web_Store-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/maodbpimhodidbmbiknomgjfhaondncn)

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

### Docker(Goツールチェーン不要)

Goをインストールせず使い捨て環境で試したい場合は、[Docker](#docker)セクションへ直接進んでください。

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

## Docker

コンテナ内でプロキシを実行できます。ローカルにGo/Makeをインストールする必要はありません。

### 1. プロキシを起動する

> **Linux環境限定の注意:** コンテナは非特権ユーザー(`nonroot`、UID 65532)で動作し、CA証明書/鍵を保存する `./data` ディレクトリへの書き込み権限が必要です。`./data` が存在しない状態で初回起動すると、Dockerが自動作成するディレクトリの所有者は `root` になり他ユーザーからは書き込めないため、CA証明書の生成に失敗します。事前に正しい所有者で作成しておいてください:
> ```bash
> mkdir -p data && sudo chown 65532:65532 data
> ```
> Docker Desktop for Mac/Windowsでは、バインドマウント層が所有権を自動的にマッピングするため不要です。

```bash
git clone https://github.com/ytkoka/impersonate-proxy.git
cd impersonate-proxy
docker compose up -d
```

イメージをローカルでビルドしてコンテナを起動します。初回起動時にMITM CAが生成され、以下のように出力されます:

```
impersonate-proxy  | generated CA certificate → /data/ca.crt (add to OS trust store to avoid cert errors)
impersonate-proxy  | listening on 0.0.0.0:8080  preset=chrome
```

クローンせずビルド済みイメージを直接使う場合:

```bash
docker run -d --name impersonate-proxy \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 \
  -v "$(pwd)/config.docker.yaml:/config.yaml:ro" \
  -v "$(pwd)/data:/data" \
  ghcr.io/ytkoka/impersonate-proxy:latest
```

`docker-compose.yml` は両ポートとも `127.0.0.1` にのみ公開します — ネイティブインストール時と同じループバック限定の露出範囲です(管理APIは無認証のため、独自のアクセス制御を追加しない限り `0.0.0.0` には変更しないでください)。

### 2. CA証明書を信頼する

CAはコンテナ内で生成されますが、ボリュームマウント経由でホストの `./data/ca.crt` と `./data/ca.key` に永続化されるため、コンテナの再起動・再作成をまたいで保持されます。上記の[ネイティブセットアップ](#3-ca証明書を信頼する)と同じ手順で、`./ca.crt` の代わりに `./data/ca.crt` を指定してください:

```bash
# curl
curl --proxy http://127.0.0.1:8080 --cacert ./data/ca.crt https://tls.peet.ws/api/all

# macOSシステムキーチェーン
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./data/ca.crt
```

### 3. 設定する

`config.yaml` ではなく `config.docker.yaml`(Docker用)を編集し、再起動してください:

```bash
docker compose restart
```

`config.docker.yaml` は `config.yaml` とほぼ同一ですが、`listen`/`mgmt_listen` が `0.0.0.0` になっている点(Dockerのポート公開がプロセスに到達するために必須 — コンテナ自身の `127.0.0.1` はホストから到達できないため)と、`ca_cert`/`ca_key` が永続化ボリュームの `/data` 配下を指している点が異なります。指定可能な全項目は下記の[設定](#設定)を参照してください。

### Makefileショートカット

| ターゲット | 説明 |
|--------|-------------|
| `make docker-build` | `docker compose build` でイメージをビルド |
| `make docker-run` | ビルドしてバックグラウンドで起動 |
| `make docker-stop` | コンテナを停止・削除 |

### 停止・クリーンアップ

```bash
docker compose down          # コンテナを停止
rm -rf data                  # 永続化したCAも削除する場合(削除後は再度信頼設定が必要)
```

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
| `/api/config` | `GET` | 現在の設定をJSONで返す(現在の `custom_hello` とアップストリームの状態を含む) |
| `/api/config` | `POST` | TLSプリセット / `custom_hello` / 送信元IP / User-Agent / アップストリームの有効化・選択を部分的に更新する — 指定しなかったフィールドは変更されない |
| `/api/upstream` | `GET` | アップストリームの状態を返す: `enabled`、`select`、設定済みプロキシの**名前**(URLや認証情報は含まない)、IPヘッダー抑制が有効かどうか |

`POST /api/config` は本当の意味での部分更新です。変更したいフィールドだけを送れば、TLSプリセットやアップストリームの選択を含め、それ以外はそのまま維持されます。

```bash
# 現在の設定を読む
curl http://127.0.0.1:8081/api/config

# Firefoxのフィンガープリントに切り替え、偽装IPを設定(他のフィールドは変更しない)
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"tls_preset":"firefox","client_ip":"203.0.113.1"}'

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

# アップストリームプロキシを有効化し、名前で選択する — TLSプリセット・送信元IP・
# User-Agentはそのまま維持される
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"upstream_enabled": true, "upstream_select": "residential_us"}'

# 現在のアップストリームの状態を読む
curl -s http://127.0.0.1:8081/api/upstream
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
| `17613` | application_settings (ALPS, 新コードポイント) | `h2` をアドバタイズ。Chrome 133以降は`17513`の代わりにこちらを送信 |
| `65037` | encrypted_client_hello (ECH) | GREASE ECHペイロード(BoringSSL方式) |
| `65281` | renegotiation_info | |
| その他 | GenericExtension | 空ペイロードで送信 |

> **実行時の変更:** `preset: "custom"` は `config.yaml` に限定されません。管理API(前述の「管理API」セクションを参照。`POST /api/config` に `custom_hello` オブジェクトを送信)や、Chrome拡張機能のTLS Presetドロップダウンからも、プロキシを再起動せずに実行時に切り替えられます。

### アップストリームプロキシ

デフォルトではプロキシはターゲットに直接接続するため、`X-Forwarded-For` / `True-Client-IP` の偽装(前述)はリクエストが「主張する」内容を変えるだけで、TCP接続の実際の送信元IPは自分のままです。`upstream.enabled: true` を設定すると、ターゲットへの接続をまずSOCKS5またはHTTP CONNECTプロキシ経由にするため、**実際のegress IP**も変わります。これにより、偽装可能なヘッダーを無視して接続元IP自体を見るWAFルールをテストしたり、「フィンガープリントは正常だがIPが悪い」場合と「IPは綺麗だがフィンガープリントが変」な場合を切り分けたりできます。

対応しているのはトンネルを張れるスキーム(`socks5`、`socks5h`、`http`(CONNECT))のみです。どちらも生のTCPトンネルを返し、それをプロキシ自身がuTLSでラップするため、このツールが制御しようとしているClientHelloとHTTP/2フレーミングは一切変更されずにそのまま通過します。`https://`(TLSを終端するタイプ)のアップストリームは**サポートされていません**。TLSを自分で復号・再確立してしまい、uTLSのフィンガープリントが自分のものに置き換わってしまうためです。

```yaml
upstream:
  enabled: false                         # デフォルトはオフ。再起動なしで実行時に切り替え可能
  select: "residential_us"               # プロキシ名 | "rotate" | "random" | ""(先頭のプロキシ)
  dial_timeout_ms: 15000
  suppress_ip_headers_when_active: true  # アップストリーム有効時はXFF/True-Client-IPを送らない — 綺麗なIPが偽装ヘッダーを名乗る矛盾を防ぐ
  proxies:
    - name: residential_us
      url: "socks5://user:pass@gw.provider.com:1080"   # ホスト名はプロキシ側で解決される(SOCKS5h相当の挙動)。ローカルでは解決しない
    - name: datacenter
      url: "http://user:pass@dc.provider.com:8080"
    - name: tor
      url: "socks5://127.0.0.1:9050"                   # 無料で試せる: brew install tor && brew services start tor
```

TLSプリセットと同様に、実行時にもプロキシを切り替えられます。Chrome拡張機能の「Upstream proxy」トグル・ドロップダウンから、または:

```bash
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"upstream_enabled": true, "upstream_select": "residential_us"}'
```

`GET /api/upstream` とChrome拡張機能のドロップダウンには、常にプロキシの**名前**しか表示されません。URLや認証情報がプロキシプロセスの外に出ることはありません。

**実際に効いているかの確認方法:** アップストリームを有効化する前後で実際のegress IPを確認し(例: `curl --proxy http://127.0.0.1:8080 https://ifconfig.me`)、あわせて[tls.peet.ws](https://tls.peet.ws)でフィンガープリントに影響がないことも確認してください。ネットワーク経路だけが変わっているので、`upstream.enabled` のオン・オフに関わらずJA3/JA4とHTTP/2フィンガープリントは一致するはずです。

> **注意点:** ブラウザは(curlと違って)オリジンごとに接続を保持・再利用します。`select` を切り替えたり `enabled` をトグルしたりした直後に、すでに接続済みのタブをただリロードしただけだと、ブラウザが新しい接続を張らずに既存の接続を再利用してしまうことがあります。その場合、実際に新規接続が発生するまで変更が反映されているように見えません。切り替えが効いていないように見える場合は、新しいシークレットウィンドウで試すか、`chrome://net-internals/#sockets` でソケットプールをフラッシュしてください。

> **接続を受け付けたからといって、そのプロキシを信用しないでください。** SOCKS5/CONNECTのハンドシェイクが成功したからといって、そのプロキシが正直に動いているとは限りません。悪意のあるプロキシは生のバイト列をトンネリングする代わりに、自分自身でTLSを終端し、自分の証明書を返すことができます。そうなると、本来エンドツーエンドで暗号化されているはずの通信を、まるごと読まれる(あるいは改ざんされる)ことになります。自分で用意したのではないプロキシを信頼する前には、必ずこれを確認してください: そのプロキシ経由で `https://tls.peet.ws` にアクセスし、(a)証明書エラーが出ないこと、(b) `upstream.enabled: false` のときと同じJA4になることを確認します。証明書エラーが出たり、JA4が変わっていたりする場合、その「プロキシ」はトンネリングではなく通信を傍受しています — そこには何も流さないでください。

> **Docker:** ホストマシンを指すアップストリームURL(例: ローカルのTorインスタンス `socks5://127.0.0.1:9050`)は、コンテナ内ではそのままでは名前解決できません。ここでの `127.0.0.1` はホストではなくコンテナ自身のループバックだからです。代わりに `socks5://host.docker.internal:9050`(Docker DesktopのMac/Windows)や、コンテナのデフォルトゲートウェイIP(Linux)を使ってください。

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

**方法A — Chrome Web Store(推奨):** [![Chrome Web Store](https://img.shields.io/badge/Chrome_Web_Store-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/maodbpimhodidbmbiknomgjfhaondncn)

**方法B — パッケージ化されていない拡張機能を読み込む(開発用、または未リリースの変更を試す場合):**

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
| Upstream proxy | アップストリームのSOCKS5/HTTP-CONNECTプロキシ経由のルーティングを有効化し、使用するプロキシ(または `rotate`/`random`)を選択する — [アップストリームプロキシ](#アップストリームプロキシ)を参照 |
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

管理APIでプリセットを切り替えながら、WAFの許可/ブロック判定を記録していくような、より実践的な例は[`examples/waf-fingerprint-test.js`](examples/waf-fingerprint-test.js)を参照してください。

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
├── upstream/                 # アップストリームSOCKS5/HTTP-CONNECTプロキシ: マネージャー、ダイアラー、選択ロジック
├── proxy/proxy.go            # プロキシサーバー: CONNECT処理、プロトコル分岐、実行時設定
├── rewrite/headers.go        # HTTPヘッダー書き換え(UA、順序、追加/削除、IP偽装)
├── mgmt/server.go            # 管理HTTP API(/api/config, /api/upstream)
├── chrome-extension/
│   ├── manifest.json         # Manifest V3
│   ├── popup.html            # ツールバーポップアップUI
│   ├── popup.css
│   ├── popup.js               # プロキシトグル + アップストリームトグル + 管理APIクライアント
│   ├── icon.svg
│   └── icon16.png, icon48.png, icon128.png  # ツールバー / Web Store用アイコン
├── config.yaml               # デフォルト設定
├── config.docker.yaml        # docker-compose.ymlが使用する設定
├── examples/
│   └── waf-fingerprint-test.js  # Playwrightハーネス: プリセットを切り替えながらWAFの判定結果を記録
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## Makefileターゲット

| ターゲット | 説明 |
|--------|-------------|
| `make build` | バイナリをコンパイル |
| `make run` | ビルドし、既存プロセスを終了させてから起動 |
| `make trust-ca` | `ca.crt` をmacOSシステムキーチェーンに追加(sudoが必要) |
| `make clean` | バイナリ、`ca.crt`、`ca.key` を削除 |
| `make docker-build` | Dockerイメージをビルド([Docker](#docker)参照) |
| `make docker-run` | ビルドしてバックグラウンドで起動 |
| `make docker-stop` | コンテナを停止・削除 |

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
- **アップストリームプロキシはTCPトンネルのみ対応**: `socks5` / `socks5h` / `http`(CONNECT)のアップストリームのみサポートしています。TLSを自分で終端するタイプのアップストリームはuTLSのClientHelloを壊してしまうため、起動時に拒否されます。[アップストリームプロキシ](#アップストリームプロキシ)を参照してください。

## 法的注意事項

本ツールは **許可されたセキュリティテストのみ** を目的としています。例えば、自分が所有するシステムや、書面による明示的なテスト許可を得ているシステムに対するWAF・ボット検知設定のテストなどです。

許可を得ていないシステムに対して本ツールを使用することは、適用される法律(米国のComputer Fraud and Abuse Act、日本の不正アクセス禁止法、または各法域における同等の法令など)や対象の利用規約に違反する可能性があります。

**作者は誤用による一切の責任を負いません。**

## 謝辞

- [uTLS](https://github.com/refraction-networking/utls) — TLSフィンガープリントのカスタマイズ
- [tls.peet.ws](https://tls.peet.ws) — 例で使用しているフィンガープリント検査API
- [JA4+](https://github.com/FoxIO-LLC/ja4) — フィンガープリント標準の参考資料

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
