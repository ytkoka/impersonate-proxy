# impersonate-proxy

[![Chrome Web Store](https://img.shields.io/badge/Chrome_Web_Store-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/maodbpimhodidbmbiknomgjfhaondncn)

[English](README.md) | [日本語](README.ja.md) | **简体中文**

一个本地 MITM 代理,可通过单个 YAML 配置文件控制 TLS 指纹(JA3/JA4)、HTTP/2 指纹、HTTP 请求头顺序、User-Agent 以及源 IP 请求头。

项目内置了一个 **Chrome 扩展**,可以直接在浏览器工具栏上切换代理开关和指纹配置,无需重启代理。

本工具用于对 WAF 机器人检测系统进行**授权的安全测试**。将 curl、浏览器或 Playwright 的流量路由到该代理,即可观察不同指纹组合会被如何判定。

## 工作原理

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

| 层级 | 可控制的内容 |
|-------|----------------------|
| TLS | 通过 uTLS 预设或完全自定义的 `custom_hello` 规范,控制加密套件、扩展及其顺序(JA3 / JA4) |
| HTTP/1.1 | 请求头顺序、User-Agent、任意请求头的增删、IP 伪装(`X-Forwarded-For` / `True-Client-IP`) |
| HTTP/2 | SETTINGS 的值与顺序、WINDOW_UPDATE、伪首部顺序(HTTP/2 指纹) |

## 前置条件

- **macOS** 或 **Linux**(amd64 / arm64)
- **Go 1.22+**

### macOS

```bash
brew install go
```

### Linux

发行版自带的 Go 版本通常较旧,建议直接安装官方二进制包:

```bash
# 下载并解压(请将 1.22.5 替换为 https://go.dev/dl/ 上的最新版本)
curl -OL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz

# 添加到 PATH(如需永久生效,请将此行添加到 ~/.bashrc 或 ~/.zshrc)
export PATH=$PATH:/usr/local/go/bin
```

验证:

```bash
go version
# go version go1.22.5 linux/amd64
```

> **ARM64(Raspberry Pi、AWS Graviton 等):** 将下载链接中的 `linux-amd64` 替换为 `linux-arm64`。

### Docker(无需 Go 工具链)

想用一次性环境而不安装 Go?直接跳到 [Docker](#docker) 章节。

## 安装配置

### 1. 克隆并构建

```bash
git clone https://github.com/ytkoka/impersonate-proxy.git
cd impersonate-proxy
make build
```

### 2. 生成 MITM CA 证书

CA 会在首次运行时自动生成。启动一次代理即可创建 `ca.crt` 和 `ca.key`:

```bash
make run
# 2026/04/22 12:00:00 generated CA certificate → ca.crt
# 2026/04/22 12:00:00 listening on 127.0.0.1:8080  preset=chrome
```

使用 `Ctrl-C` 停止。

### 3. 信任 CA 证书

客户端需要信任你的 MITM CA,否则会拒绝代理生成的叶子证书。

**macOS 系统钥匙串**(影响所有应用):
```bash
make trust-ca        # runs: sudo security add-trusted-cert ...
```

**Linux 系统信任库**(影响所有应用;需要 ca-certificates 包):
```bash
# Debian / Ubuntu
sudo cp ca.crt /usr/local/share/ca-certificates/impersonate-proxy.crt
sudo update-ca-certificates

# RHEL / Fedora / Amazon Linux
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/impersonate-proxy.crt
sudo update-ca-trust
```

**仅 curl**(不影响系统全局):
```bash
curl --cacert ca.crt ...
```

**Playwright / Node.js**:
```bash
export NODE_EXTRA_CA_CERTS="$(pwd)/ca.crt"
```

**Firefox**: 设置 → 隐私与安全 → 查看证书 → 证书颁发机构 → 导入 `ca.crt`

## Docker

在容器中运行代理——无需在本地安装 Go/Make。

### 1. 启动代理

> **仅限 Linux:** 容器以非特权用户(`nonroot`,UID 65532)运行,需要对保存 CA 证书/密钥的 `./data` 目录有写权限。如果 `./data` 尚不存在,Docker 会自动创建它并归属 `root`,其他用户没有写权限,导致容器首次启动时无法生成 CA。请提前以正确的属主创建该目录:
> ```bash
> mkdir -p data && sudo chown 65532:65532 data
> ```
> 在 Docker Desktop for Mac/Windows 上不需要此步骤——其绑定挂载层会自动映射属主。

```bash
git clone https://github.com/ytkoka/impersonate-proxy.git
cd impersonate-proxy
docker compose up -d
```

该命令会在本地构建镜像并启动容器。首次运行时会生成 MITM CA,并输出:

```
impersonate-proxy  | generated CA certificate → /data/ca.crt (add to OS trust store to avoid cert errors)
impersonate-proxy  | listening on 0.0.0.0:8080  preset=chrome
```

或者不克隆仓库,直接运行预构建镜像:

```bash
docker run -d --name impersonate-proxy \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 \
  -v "$(pwd)/config.docker.yaml:/config.yaml:ro" \
  -v "$(pwd)/data:/data" \
  ghcr.io/ytkoka/impersonate-proxy:latest
```

`docker-compose.yml` 仅将两个端口发布到 `127.0.0.1`——与原生安装相同的仅回环暴露范围(管理 API 没有身份验证,因此除非你自行添加访问控制,否则不要将其改为 `0.0.0.0`)。

### 2. 信任 CA 证书

CA 在容器内生成,但通过挂载的卷持久化到主机的 `./data/ca.crt` 和 `./data/ca.key`,因此在容器重启/重建后依然保留。按照上面[原生安装](#3-信任-ca-证书)相同的步骤信任它,只需将 `./ca.crt` 替换为 `./data/ca.crt`:

```bash
# curl
curl --proxy http://127.0.0.1:8080 --cacert ./data/ca.crt https://tls.peet.ws/api/all

# macOS 系统钥匙串
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./data/ca.crt
```

### 3. 配置

编辑 `config.docker.yaml`(而不是 `config.yaml`——那是原生安装使用的文件),然后重启:

```bash
docker compose restart
```

`config.docker.yaml` 与 `config.yaml` 基本相同,区别在于 `listen`/`mgmt_listen` 为 `0.0.0.0`(这是 Docker 端口发布能够到达进程的必要条件——容器自身的 `127.0.0.1` 无法从主机访问),以及 `ca_cert`/`ca_key` 指向持久化卷 `/data`。所有可用字段参见下方的[配置](#配置)。

### Makefile 快捷方式

| 目标 | 说明 |
|--------|-------------|
| `make docker-build` | 通过 `docker compose build` 构建镜像 |
| `make docker-run` | 构建并在后台启动 |
| `make docker-stop` | 停止并删除容器 |

### 停止 / 清理

```bash
docker compose down          # 停止容器
rm -rf data                  # 同时删除持久化的 CA(删除后需要重新信任)
```

## 配置

在启动代理之前编辑 `config.yaml`。所有字段都有默认值——你只需要指定想要覆盖的部分。

```yaml
listen: "127.0.0.1:8080"
mgmt_listen: "127.0.0.1:8081"  # Chrome 扩展使用的管理 API(留空可禁用)
ca_cert: "ca.crt"
ca_key:  "ca.key"

tls:
  # TLS 指纹预设(控制 JA3 / JA4)
  # 可选值: chrome | firefox | safari | edge | ios | random | golang
  preset: "chrome"

http:
  # 覆盖 User-Agent(留空则原样转发客户端的 UA)
  # "auto":使用与 tls.preset 对应的 UA(random/golang/custom 时原样转发)
  # "random":从内置列表中随机选择
  user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

  # 伪装源 IP:将 X-Forwarded-For 和 True-Client-IP 都设置为该值,
  # 覆盖客户端可能已设置的值(留空则禁用)
  # client_ip: "1.2.3.4"

  # 按此顺序发送请求头;未列出的请求头会附加在末尾
  header_order:
    - "Host"
    - "User-Agent"
    - "Accept"
    - "Accept-Language"
    - "Accept-Encoding"
    - "Connection"

  # 添加或覆盖请求头
  add_headers:
    Accept-Language: "ja,en-US;q=0.9,en;q=0.8"

  # 转发前移除的请求头
  remove_headers: []

http2:
  enabled: true

  # HTTP/2 指纹跟随 tls.preset(见下方"浏览器指纹对照表"),切换预设时它也会随之切换。
  # 以下字段是可选的覆盖项:设置后会对所有预设固定该值。
  #
  # SETTINGS 帧条目 — id 和顺序都会影响 HTTP/2 指纹
  # RFC 7540 §11.3 的 ID:
  #   1=HEADER_TABLE_SIZE  2=ENABLE_PUSH  3=MAX_CONCURRENT_STREAMS
  #   4=INITIAL_WINDOW_SIZE  5=MAX_FRAME_SIZE  6=MAX_HEADER_LIST_SIZE
  # settings:
  #   - { id: 1, val: 65536 }    # 此处以 Chrome 的值为例
  #   - { id: 2, val: 0 }
  #   - { id: 4, val: 6291456 }
  #   - { id: 6, val: 262144 }

  # 连接级 WINDOW_UPDATE 增量
  # window_update: 15663105

  # HEADERS 帧中伪首部的顺序
  # pseudo_header_order: [method, authority, scheme, path]

  # 连接前言之后发送的 PRIORITY 帧,以及 HEADERS 帧中携带的优先级
  # (weight 为 1-256,与 tls.peet.ws 显示一致)
  # priorities: [{ stream_id: 3, depends_on: 0, weight: 201 }]
  # headers_priority: { depends_on: 0, weight: 256, exclusive: true }

# Impersonate only some target hosts (default: all). Hosts that are not
# impersonated are tunnelled through untouched. Patterns: "example.com" (exact)
# or "*.example.com" (subdomains only, not example.com itself).
filter:
  mode: "off"      # off | include (only the listed hosts) | exclude (all but the listed hosts)
  hosts: []

# MCP 服务器的 fetch_url 工具可以访问的主机(参见"MCP 服务器")。每个条目允许该主机及其子域名;
# 留空表示允许任何公网主机。运行时只读:无法通过管理 API 或 MCP 修改,请在此处编辑,
# 或在启动代理时传入 `-fetch-allow-hosts a.com,b.com`。
fetch_allow_hosts: []
```

### 管理 API

代理启动后,还会在 `mgmt_listen`(默认 `127.0.0.1:8081`)上暴露一个轻量级 HTTP API。Chrome 扩展通过它在运行时读取和更新设置,而无需重启代理。你也可以直接用 curl 调用:

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/config` | `GET` | 以 JSON 返回当前设置(包含当前的 `custom_hello` 和上游代理状态) |
| `/api/config` | `POST` | 部分更新 TLS 预设 / `custom_hello` / 源 IP / User-Agent / 上游代理的启用与选择 / 主机过滤 — 未提供的字段保持不变 |
| `/api/upstream` | `GET` | 返回上游代理状态: `enabled`、`select`、已配置代理的**名称**(绝不包含 URL/凭据)、以及 IP 头抑制是否生效 |

`POST /api/config` 是真正的部分更新:只发送你想修改的字段,其余的——包括 TLS 预设和上游代理选择——都保持原样。

```bash
# 读取当前设置
curl http://127.0.0.1:8081/api/config

# 切换为 Firefox 指纹并设置伪装 IP(其他字段不受影响)
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"tls_preset":"firefox","client_ip":"203.0.113.1"}'

# 在运行时切换为任意 JA3/JA4 指纹 — 字段与 config.yaml 中的
# custom_hello 块相同,以 JSON 形式发送(参见下方的“自定义 TLS 指纹”)
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

# 启用上游代理并按名称选择 — TLS 预设、源 IP、User-Agent 保持不变
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"upstream_enabled": true, "upstream_select": "residential_us"}'

# 读取当前上游代理状态
curl -s http://127.0.0.1:8081/api/upstream
```

更改会立即对新连接生效。将 `mgmt_listen` 设置为空字符串(`""`)可完全禁用该 API。

### 主机过滤

默认会伪装所有主机。若只想伪装部分目标,请设置 `filter`:

```yaml
filter:
  mode: "include"          # off(默认) | include | exclude
  hosts:
    - "www.example.com"    # 精确匹配的主机
    - "*.example.com"      # 子域名(不含 example.com 本身)
```

- `include` 只伪装列表中的主机,`exclude` 伪装列表之外的所有主机,`off` 伪装所有主机。
- **不**伪装的主机会原样放行。对于 HTTPS,`CONNECT` 隧道按原始字节中继而不终止 TLS,因此客户端看到的是源站真实的证书(这些主机无需信任 CA)和客户端自身的 TLS 指纹,请求头也不会被改写。纯 HTTP 请求在不改写请求头的情况下转发。启用[上游代理](#上游代理)时,两者都会经由上游代理。
- 匹配时忽略大小写和端口。`example.com` 只匹配该主机;`*.example.com` 匹配任意层级的子域名,但不匹配 `example.com` 本身,因此要同时覆盖根域名时请两者都写。IP 字面量按精确匹配。端口、路径、CIDR 以及 `*` 的其他用法会在启动时或通过管理 API 被报错拒绝。
- 页面通常还会加载其他主机(CDN、挑战脚本等)。请把它们也列入,否则 WAF 看到的是伪装与真实指纹的混合。被放行的隧道会记录为 `PASSTHROUGH host:port`,便于找出这些主机。
- 运行时可通过管理 API 的 `filter_mode` 和 `filter_hosts` 修改。`filter_hosts` 会替换整个列表,被拒绝的补丁不会改变任何设置。已建立的连接不受影响。

```bash
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"filter_mode":"include","filter_hosts":["www.example.com","*.example.com"]}'
```

### 浏览器指纹对照表

HTTP/2 指纹由 TLS 预设决定。它就是 tls.peet.ws 返回的 `akamai_fingerprint` 字符串:`SETTINGS | WINDOW_UPDATE | PRIORITY 帧 | 伪首部顺序`(`m`=`:method`、`a`=`:authority`、`s`=`:scheme`、`p`=`:path`)。

| 浏览器 | TLS 预设 | HTTP/2 指纹 | 来源 |
|---------|-----------|--------------------|------|
| Chrome 156 | `chrome` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | 实测 |
| Edge(Chromium) | `edge` | 与 Chrome 相同 | 同一网络栈 |
| Firefox 133–148 | `firefox` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | 公开资料 |
| Safari 17(macOS) | `safari` | `2:0;4:4194304;3:100\|10485760\|0\|m,s,p,a` | 公开资料 |
| Safari 17(iOS) | `ios` | `2:0;4:2097152;3:100\|10485760\|0\|m,s,p,a` | 公开资料 |
| — | `custom`、`random`、`golang` | 与 Chrome 相同 | 没有对应的单一浏览器 |

"实测"指通过 tls.peet.ws 观察真实浏览器得到的值;"公开资料"指取自记录真实浏览器流量的 [tls-client](https://github.com/bogdanfinn/tls-client) 和 [curl-impersonate](https://github.com/lexiforest/curl-impersonate)。各配置的出处见 `h2fp/profiles.go`。Safari/iOS 采用 Safari 17,以与 `user_agent: "auto"` 发送的 User-Agent 保持一致;Safari 18.4 及更新版本发送 `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`。当前生效的指纹可通过 `get_config`(以及 `GET /api/config`)的 `http2_fingerprint` 查看。

`config.yaml` 的 `http2:` 下设置的字段会对所有预设覆盖预设的值。如果你的 `config.yaml` 是从旧版本复制来的,仍然列出了 `settings`、`window_update` 和 `pseudo_header_order`,它们会固定为 Chrome 的值:想让它跟随预设,请删除这些字段。

### User-Agent 自动模式(`user_agent: "auto"`)

设置 `user_agent: "auto"` 后,代理会使用与当前 `tls.preset` 对应的 User-Agent,使 TLS 指纹与 UA 不会相互矛盾。切换预设(通过配置文件或 Chrome 扩展)时,UA 也会随之切换。

| `tls.preset` | 发送的 User-Agent |
|---|---|
| `chrome` | Chrome 131(macOS) |
| `firefox` | Firefox 132(macOS) |
| `safari` | Safari 17.2(macOS) |
| `edge` | Edge 131(Windows) |
| `ios` | iPhone / iOS 17.1 Safari |
| `random`、`golang`、`custom` | 不修改 — 原样转发客户端的 UA |

`"random"` 是另一种独立的模式,无论 TLS 预设是什么,每个请求都会从内置列表中随机选择一个 UA。

> **注意:** `edge` 预设发送与 `chrome` 相同的 TLS ClientHello,`ios` 与 `safari` 相同(uTLS 中较旧的 Edge 85 / iOS 14 ClientHello 与 Edg/131、iOS 17 的 User-Agent 相矛盾)。因此它们的 JA3/JA4 值分别与 Chrome、Safari 一致。

### 自定义 TLS 指纹(`preset: "custom"`)

内置预设(`chrome`、`firefox`、`safari` 等)已覆盖大多数常见场景。如果需要匹配特定浏览器版本,或与这些预设不同的指纹,请设置 `preset: "custom"` 并提供 `custom_hello` 块。

**JA3 / JA4 与配置字段的对应关系**

| 指纹组成部分 | 配置字段 | 说明 |
|---|---|---|
| TLS 版本范围 | `versions` | 最小/最大值会自动推导 |
| 加密套件列表及顺序 | `cipher_suites` | 使用 `0x0a0a` 作为 GREASE 占位符;uTLS 会在每次连接时随机化 |
| 扩展类型 ID 及顺序 | `extensions` | 顺序直接决定 JA3 的 extensions 部分;匹配 GREASE 模式(`0xXAXA`)的值会在每次连接时随机化 |
| 支持的分组(曲线) | `curves` | 同时控制发送的密钥共享(key share) |

> JA3 和 JA4 都是单向哈希——无法从哈希值反推出原始参数。请使用 [tls.peet.ws](https://tls.peet.ws) 或 Wireshark 获取目标浏览器的实际参数,再填入 `custom_hello`。

**Chrome 131 示例**

```yaml
tls:
  preset: "custom"
  custom_hello:
    cipher_suites:      # 十六进制 ID;0x0a0a = GREASE 占位符(每次连接随机化)
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
    versions:           # 要通告的 TLS 版本
      - "1.3"
      - "1.2"
    extensions:         # 按顺序排列的扩展类型 ID(控制 JA3 的 extensions 部分)
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

**支持的扩展类型 ID**

| ID | 名称 | 说明 |
|---|---|---|
| `0xXAXA`(任意 GREASE 模式) | GREASE | 每次连接随机化 |
| `0` | server_name (SNI) | |
| `5` | status_request | OCSP 装订 |
| `10` | supported_groups | 使用 `curves` 列表 |
| `11` | ec_point_formats | 固定为:uncompressed (0) |
| `13` | signature_algorithms | 类 Chrome 默认值 |
| `16` | ALPN | 通告 `h2`、`http/1.1` |
| `18` | signed_certificate_timestamp | |
| `21` | padding | BoringSSL 风格的填充 |
| `23` | extended_master_secret | |
| `27` | compress_certificate | |
| `28` | record_size_limit | 固定为:0x4001 |
| `35` | session_ticket | |
| `43` | supported_versions | 使用 `versions` 列表 |
| `45` | psk_key_exchange_modes | PSK with DHE |
| `50` | signature_algorithms_cert | 类 Chrome 默认值 |
| `51` | key_share | 基于 `curves` 的 X25519、P256 密钥共享 |
| `17513` | application_settings (ALPS) | 通告 `h2` |
| `17613` | application_settings (ALPS,新码点) | 通告 `h2`;Chrome 133+ 使用此码点代替 `17513` |
| `65037` | encrypted_client_hello (ECH) | GREASE ECH 负载(BoringSSL 风格) |
| `65281` | renegotiation_info | |
| 其他 | GenericExtension | 以空负载发送 |

> **运行时更新:** `preset: "custom"` 并不局限于 `config.yaml`——也可以通过管理 API(见前面的“管理 API”一节,向 `POST /api/config` 发送 `custom_hello` 对象)或 Chrome 扩展的 TLS Preset 下拉菜单在运行时切换,无需重启代理。

### 上游代理

默认情况下代理直接连接目标,因此前面提到的 `X-Forwarded-For` / `True-Client-IP` 伪装只改变了请求“声称”的内容——TCP 连接的真实源 IP 仍然是你自己的。设置 `upstream.enabled: true` 后,到目标的连接会先经过一个 SOCKS5 或 HTTP CONNECT 代理,这样**真实的出口 IP** 也会改变。这样你就可以测试那些忽略可伪造请求头、直接查看连接源 IP 的 WAF 规则,并区分“指纹正常但 IP 不干净”和“IP 干净但指纹不对”这两种情况。

只支持能够建立隧道的协议——`socks5`、`socks5h` 和 `http`(CONNECT)。这两者都会返回一条原始 TCP 隧道,再由代理自身用 uTLS 包装,因此本工具要控制的 ClientHello 和 HTTP/2 帧结构会完全不变地穿过隧道。**不支持** `https://`(会终止 TLS 的)上游代理:它会自行解密并重新建立 TLS,用它自己的指纹替换掉你的 uTLS 指纹。

```yaml
upstream:
  enabled: false                         # 默认关闭;可在运行时切换,无需重启
  select: "residential_us"               # 代理名称 | "rotate" | "random" | ""(第一个代理)
  dial_timeout_ms: 15000
  suppress_ip_headers_when_active: true  # 上游代理生效时不发送 XFF/True-Client-IP——避免"干净的 IP 却声称伪造的 IP"这种矛盾
  proxies:
    - name: residential_us
      url: "socks5://user:pass@gw.provider.com:1080"   # 主机名由代理端解析(即 SOCKS5h 行为),本地绝不解析
    - name: datacenter
      url: "http://user:pass@dc.provider.com:8080"
    - name: tor
      url: "socks5://127.0.0.1:9050"                   # 可免费试用: brew install tor && brew services start tor
```

和 TLS 预设一样,也可以在运行时切换代理——通过 Chrome 扩展的"Upstream proxy"开关/下拉菜单,或者:

```bash
curl -s -X POST http://127.0.0.1:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{"upstream_enabled": true, "upstream_select": "residential_us"}'
```

`GET /api/upstream` 和 Chrome 扩展的下拉菜单只会显示代理的**名称**——URL 和凭据永远不会离开代理进程。

**验证是否真的生效:** 在启用上游代理前后分别检查真实的出口 IP(例如 `curl --proxy http://127.0.0.1:8080 https://ifconfig.me`),并另外用 [tls.peet.ws](https://tls.peet.ws) 确认指纹未受影响——由于只是网络路径发生了变化,`upstream.enabled` 无论开启还是关闭,JA3/JA4 和 HTTP/2 指纹都应该保持一致。

> **注意:** 浏览器(不同于 curl)会保留并复用每个源的连接。如果你切换了 `select`(或切换了 `enabled`)之后,只是刷新一个已经建立过连接的标签页,浏览器可能会直接复用已有连接而不是重新建立新连接——这样一来,改动要等到真正建立新连接时才会体现出来。如果切换后似乎没有生效,可以在新的隐身窗口中测试,或者在 `chrome://net-internals/#sockets` 中清空套接字池。

> **不要因为一个代理接受了连接就信任它。** SOCKS5/CONNECT 握手成功并不能说明这个代理是诚实的——恶意代理完全可以自己终止你的 TLS 连接、返回它自己的证书,而不是老老实实地转发原始字节,这样一来,你以为端到端加密的通信其实被整个读取(甚至篡改)了。在信任任何非你自己搭建的代理之前,请务必这样检查:通过它访问 `https://tls.peet.ws`,确认 (a) 没有证书错误,并且 (b) JA4 与 `upstream.enabled: false` 时一致。只要出现证书错误或 JA4 发生变化,就说明这个"代理"是在拦截你的流量而不是转发它——不要让任何流量经过它。

> **Docker:** 指向宿主机的上游代理 URL(例如宿主机上本地 Tor 实例 `socks5://127.0.0.1:9050`)在容器内无法照原样解析——这里的 `127.0.0.1` 是容器自己的回环地址,而不是宿主机的。请改用 `socks5://host.docker.internal:9050`(Mac/Windows 上的 Docker Desktop)或容器的默认网关 IP(Linux)。

## 使用方法

### 启动代理

```bash
make run
# 结束占用 8080 端口的旧进程,重新构建并启动。
```

要切换指纹配置,请编辑 `config.yaml` 并重新运行 `make run`。

### curl

```bash
# 在系统已信任 CA 的情况下(执行 make trust-ca 之后):
curl --proxy http://127.0.0.1:8080 https://tls.peet.ws/api/all

# 未在系统中信任 CA — 显式指定 CA:
curl --proxy http://127.0.0.1:8080 --cacert ca.crt https://tls.peet.ws/api/all
```

### Chrome 扩展

`chrome-extension/` 目录中包含一个 Manifest V3 扩展,可从浏览器工具栏控制代理。

<img src="image/chrome-extension.png" alt="Chrome 扩展弹出窗口" width="280">

**安装步骤:**

**方式 A — Chrome 应用商店(推荐):** [![Chrome Web Store](https://img.shields.io/badge/Chrome_Web_Store-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/maodbpimhodidbmbiknomgjfhaondncn)

**方式 B — 加载已解压的扩展程序(用于开发,或体验尚未发布的更改):**

1. 在 Chrome 中打开 `chrome://extensions`
2. 启用**开发者模式**(右上角开关)
3. 点击**加载已解压的扩展程序**,选择 `chrome-extension/` 文件夹

**控制项:**

| 控制项 | 作用 |
|---|---|
| 代理开关 | 启用/禁用 Chrome 的代理设置(将流量通过 `:8080` 路由) |
| TLS Preset | 切换 uTLS 指纹预设(chrome / firefox / safari / edge / ios / random / golang / **custom**) |
| Cipher Suites / Curves / TLS Versions / Extensions | 选择 **Custom (JA3/JA4)** 时显示 — 字段与 `config.yaml` 中的 `custom_hello` 相同,无需编辑 YAML 或重启代理即可设置任意 JA3/JA4 指纹 |
| Client IP | 为每个请求设置 `X-Forwarded-For` 和 `True-Client-IP` |
| User-Agent | 覆盖 HTTP 的 `User-Agent` 请求头。**Auto** 跟随所选的 TLS 预设(见「User-Agent 自动模式」),**Random** 每个请求随机选择;Auto 与 Random 互斥 |
| Upstream proxy | 启用通过上游 SOCKS5/HTTP-CONNECT 代理路由,并选择使用哪一个(或 `rotate`/`random`)——参见[上游代理](#上游代理) |
| Apply 按钮 | 将新设置 POST 到管理 API;立即生效 |
| API 字段 | 管理 API 的地址(默认 `http://127.0.0.1:8081`) |

> **User-Agent 的作用范围:** 该扩展只修改 HTTP 的 `User-Agent` **请求头**。JavaScript 的 `navigator.userAgent` 由 Chrome 自身控制,不受影响。若要同时伪装两者,请在启动 Chrome 时附加 `--user-agent="..."` 参数,并配合代理设置一起使用。

### Playwright(Node.js)

```js
const { chromium } = require('playwright');

const browser = await chromium.launch();
const context = await browser.newContext({
  proxy: { server: 'http://127.0.0.1:8080' },
});
// 如果 CA 未加入系统信任,启动前设置:
// NODE_EXTRA_CA_CERTS=./ca.crt node script.js
const page = await context.newPage();
await page.goto('https://tls.peet.ws/api/all');
```

如需查看更完整的示例——通过管理 API 轮流切换预设并记录 WAF 的放行/拦截结果——请参见 [`examples/waf-fingerprint-test.js`](examples/waf-fingerprint-test.js)。

### Playwright(Python)

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context(proxy={"server": "http://127.0.0.1:8080"})
    page = context.new_page()
    page.goto("https://tls.peet.ws/api/all")
```

如果 CA 未在系统级别被信任,请设置 `NODE_EXTRA_CA_CERTS`(Node)或 `REQUESTS_CA_BUNDLE`(Python)。

## 验证指纹

[tls.peet.ws](https://tls.peet.ws) 会返回它收到的任何请求的完整指纹分解结果。可以通过 `jq` 或 Python 处理输出,便于阅读:

```bash
curl -s --proxy http://127.0.0.1:8080 --cacert ca.crt \
  https://tls.peet.ws/api/all | python3 -m json.tool
```

需要检查的关键字段:

| 字段 | 说明 |
|-------|-------------|
| `tls.ja3_hash` | JA3 指纹哈希 |
| `tls.ja4` | JA4 指纹字符串 |
| `http2.akamai_fingerprint` | HTTP/2 指纹字符串(SETTINGS + WINDOW_UPDATE + 伪首部顺序)— 字段名由 tls.peet.ws 的 API 定义 |
| `http1.headers` | 服务器收到的请求头顺序 |
| `user_agent` | 服务器看到的 User-Agent |
| `ip` | 服务器看到的源 IP — 可在此确认 `X-Forwarded-For` / `True-Client-IP` 的伪装效果 |

## MCP 服务器(可选)

`impersonate-mcp/` 是基于官方 [Go SDK](https://github.com/modelcontextprotocol/go-sdk) 构建的 stdio 方式 [MCP](https://modelcontextprotocol.io) 服务器,让 AI 智能体可以配置代理并检查结果。它只是[管理 API](#管理-api)的客户端,并复用 `config` 包中的类型。它是独立的 Go 模块:`make build` 不会构建它,Docker 镜像也不包含它。

```bash
make build-mcp   # → impersonate-mcp/impersonate-mcp
make test-mcp
```

将其注册到你的 MCP 客户端(需先启动代理)。以 Claude Code 为例:

```bash
claude mcp add impersonate -- /path/to/impersonate-proxy/impersonate-mcp/impersonate-mcp --ca-cert /path/to/impersonate-proxy/ca.crt
```

或在任意客户端的 JSON 配置中:

```json
{
  "mcpServers": {
    "impersonate": {
      "command": "/path/to/impersonate-proxy/impersonate-mcp/impersonate-mcp",
      "args": ["--ca-cert", "/path/to/impersonate-proxy/ca.crt"],
      "env": { "IMPERSONATE_MGMT_URL": "http://127.0.0.1:8081" }
    }
  }
}
```

> **`command` 必须是可执行文件,而不是目录。** 可执行文件位于克隆目录内的 `impersonate-mcp/impersonate-mcp`,`make build-mcp` 结束时会打印其绝对路径。上面示例中的 `/path/to/impersonate-proxy` 即你的克隆目录。

### 工具

| 工具 | 说明 |
|---|---|
| `get_config` | 返回当前运行时设置(TLS 预设、`custom_hello`、User-Agent、客户端 IP、上游状态、主机过滤、`http2_fingerprint`、`fetch_allow_hosts`) |
| `set_tls_preset` | 切换 TLS 预设(`chrome`、`firefox`、`safari` 等)。HTTP/2 指纹随之切换 |
| `set_custom_hello` | 设置任意 ClientHello(密码套件、曲线、版本、扩展),并将预设切换为 `custom` |
| `set_user_agent` | 设置 User-Agent(`""` = 保持原样,`"auto"` = 根据预设自动生成) |
| `set_client_ip` | 设置伪造的客户端 IP(`""` = 关闭) |
| `set_upstream` | 启用/禁用上游代理,和/或按名称(或 `rotate` / `random`)选择 |
| `verify_fingerprint` | 通过代理获取 `tls.peet.ws/api/all`,并汇总 `ja3_hash`、`ja4`、`akamai_fingerprint`、`user_agent` 和 `ip` |
| `fetch_url` | 通过代理获取任意 `http(s)` URL(应用当前的 TLS 预设、User-Agent、客户端 IP、上游和主机过滤),返回 `status`、`http_version`、`final_url`、`redirects`、`headers`、`body`(仅文本;省略 `Set-Cookie` 的值)、`body_truncated`、`elapsed_ms`。选项:`method`、`headers`、`body`、`follow_redirects`(最多 10 次)、`max_body_bytes`(默认 51200,上限 1048576)。失败信息通过 `error` 字段返回 |

### 选项

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--mgmt-url` | `IMPERSONATE_MGMT_URL` | `http://127.0.0.1:8081` | 管理 API 的基础 URL |
| `--proxy-url` | `IMPERSONATE_PROXY_URL` | 根据代理的 `listen` 自动推导 | `verify_fingerprint` 和 `fetch_url` 使用的代理 |
| `--ca-cert` | `IMPERSONATE_CA_CERT` | 系统信任库 | 代理 `ca.crt` 的路径,使 `verify_fingerprint` 和 `fetch_url` 信任 MITM 证书 |
| `--verify-url` | `IMPERSONATE_VERIFY_URL` | `https://tls.peet.ws/api/all` | 返回指纹的回显端点 |
| `--read-only` | `IMPERSONATE_READ_ONLY` | `false` | 隐藏所有会修改设置的工具(`set_*`);`fetch_url` 仍保留,但仅限不带请求体的 `GET` / `HEAD` / `OPTIONS` |

### 注意事项

- 管理 API 没有认证,而此服务器允许智能体修改代理设置。请让 `mgmt_listen` 保持在回环地址(否则会输出警告日志);若只希望智能体观察,请使用 `--read-only`。
- `verify_fingerprint` 会向外部服务(默认 `tls.peet.ws`)发送一次请求。如果[主机过滤](#主机过滤)排除了该主机,结果将不是伪装后的指纹,工具会在 `warnings` 中提示。
- `set_upstream` 只能切换和选择 `config.yaml` 中已定义的代理;管理 API 不支持在运行时添加代理。
- HTTP/2 指纹(`akamai_fingerprint`)跟随 TLS 预设,可通过 `get_config` 的 `http2_fingerprint` 查看。在 `config.yaml` 的 `http2:` 下固定的值会对所有预设覆盖预设的值。
- `fetch_url` 始终经过代理,因此所有当前设置都会生效;它从不直接连接目标。它会拒绝回环、私有和链路本地地址(`127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`::1`,以及 `fc00::/7`、`fe80::/10`、`100.64/10`、`0.0.0.0/8`),同时检查主机名和解析出的每个 IP,并在每次重定向跳转时重新检查。`fetch_allow_hosts`(代理的 `config.yaml` 或 `-fetch-allow-hosts`)可进一步限制为所列主机及其子域名;`get_config` 会显示该列表,但任何工具都无法修改。如果读取不到代理配置,`fetch_url` 会拒绝而不是不受限地获取。局限:域名由 MCP 服务器和代理分别解析,第二次解析返回不同结果的 DNS 重绑定,仅靠此检查无法阻止。
- 日志输出到 stderr;stdout 专用于 MCP 协议。

## 项目结构

```
impersonate-proxy/
├── main.go                   # 入口文件
├── config/config.go          # YAML 配置结构体与默认值
├── fp/dialer.go              # uTLS dialer — TLS 指纹预设
├── h2fp/conn.go              # HTTP/2 帧处理器 — SETTINGS / WINDOW_UPDATE / 伪首部控制
├── mitm/ca.go                # MITM CA:生成、缓存并颁发叶子证书
├── upstream/                 # 上游 SOCKS5/HTTP-CONNECT 代理:管理器、dialer、选择逻辑
├── proxy/proxy.go            # 代理服务器:CONNECT 处理、协议分支、运行时配置
├── rewrite/headers.go        # HTTP 请求头改写(UA、顺序、增删、IP 伪装)
├── filter/filter.go          # 主机过滤:决定哪些目标被伪装
├── mgmt/server.go            # 管理 HTTP API(/api/config, /api/upstream)
├── impersonate-mcp/          # 可选的 MCP 服务器(独立 Go 模块):操作管理 API
├── chrome-extension/
│   ├── manifest.json         # Manifest V3
│   ├── popup.html            # 工具栏弹出窗口 UI
│   ├── popup.css
│   ├── popup.js               # 代理开关 + 上游代理开关 + 管理 API 客户端
│   ├── icon.svg
│   └── icon16.png, icon48.png, icon128.png  # 工具栏 / Web Store 图标
├── config.yaml               # 默认配置
├── config.docker.yaml        # docker-compose.yml 使用的配置
├── examples/
│   └── waf-fingerprint-test.js  # Playwright 测试脚本:轮流切换预设并记录 WAF 判定结果
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## Makefile 目标

| 目标 | 说明 |
|--------|-------------|
| `make build` | 编译二进制文件 |
| `make build-mcp` | 将可选的 MCP 服务器构建为 `impersonate-mcp/impersonate-mcp`(参见 [MCP 服务器](#mcp-服务器可选)) |
| `make test-mcp` | 运行 MCP 服务器的测试 |
| `make run` | 构建、结束已有实例并启动 |
| `make trust-ca` | 将 `ca.crt` 添加到 macOS 系统钥匙串(需要 sudo) |
| `make clean` | 删除二进制文件、`ca.crt` 和 `ca.key` |
| `make docker-build` | 构建 Docker 镜像(参见 [Docker](#docker)) |
| `make docker-run` | 构建并在后台启动 |
| `make docker-stop` | 停止并删除容器 |

## 清理

删除二进制文件和生成的 CA 文件:

```bash
make clean
```

如果你已将 CA 添加到 macOS 系统钥匙串,可以通过**钥匙串访问**(搜索“impersonate-proxy CA”)移除,或执行:

```bash
sudo security delete-certificate -c "impersonate-proxy CA" /Library/Keychains/System.keychain
```

## 已知限制

- **仅支持 MITM 模式**:代理会解密并重新加密流量,客户端必须信任生成的 CA。
- **客户端不支持 HTTP/2**:客户端→代理这一段使用 HTTP/1.1(通过 CONNECT)。只有代理→服务器这一段使用带自定义指纹的 HTTP/2。
- **请求 trailer**:`Transfer-Encoding: chunked` 的请求体可以转发,但其 trailer 会被丢弃。
- **`Expect: 100-continue`**:由代理自行应答并删除该请求头,因此客户端会在服务器接受请求之前发送请求体。
- **WebSocket**:`wss://` 仅支持 HTTP/1.1。服务器使用 h2 时,代理会为升级请求另开一条连接,其 ClientHello 与浏览器的 WebSocket 连接一样只在 ALPN 中提供 `http/1.1` 且不含 ALPS 扩展,因此该连接的 JA3/JA4 与 h2 连接不同,且尚未与真实浏览器抓包对照。升级后的数据按字节原样转发。不支持:经 `CONNECT` 的 `ws://`(隧道默认为 TLS),以及基于 HTTP/2 的 WebSocket(RFC 8441)。
- **主机过滤与纯 HTTP**:发往未伪装主机的请求仍由代理重新序列化,因此请求头顺序不会保留(HTTPS 放行则按字节原样中继)。参见[主机过滤](#主机过滤)。
- **HTTP/2 下的大请求体**:请求体以单个 DATA 帧发送且不做流量控制,超过服务器帧大小上限(通常为 16 KB)时可能被 `FRAME_SIZE_ERROR` 拒绝。HTTP/1.1 不受影响。
- **不支持 QUIC / HTTP/3**:超出本项目范围。
- **User-Agent(仅 HTTP 请求头)**:代理会改写 HTTP 的 `User-Agent` 请求头,但 JavaScript 的 `navigator.userAgent` 由浏览器自行设置,不受影响。如需同时覆盖两者,请使用 Chrome 的 `--user-agent` 启动参数。
- **上游代理仅支持 TCP 隧道**:只支持 `socks5` / `socks5h` / `http`(CONNECT)上游代理——会自行终止 TLS 的上游代理会破坏 uTLS ClientHello,因此在启动时会被拒绝。参见[上游代理](#上游代理)。

## 法律声明

本工具仅用于**授权的安全测试**——例如,对你自己拥有或已获得书面明确授权的系统进行 WAF 与机器人检测配置测试。

在未获授权的系统上使用本工具,可能违反适用法律(例如美国《计算机欺诈与滥用法》、日本《禁止非法访问法》,或你所在司法辖区的同等法律)以及目标系统的服务条款。

**作者不对任何滥用行为承担责任。**

## 致谢

- [uTLS](https://github.com/refraction-networking/utls) — TLS 指纹定制
- [tls.peet.ws](https://tls.peet.ws) — 示例中使用的指纹检测 API
- [JA4+](https://github.com/FoxIO-LLC/ja4) — 指纹标准参考资料

## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)