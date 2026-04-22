# impersonate-proxy

A local MITM proxy that lets you control TLS fingerprints (JA3/JA4), HTTP/2 fingerprints, HTTP header order, and User-Agent — all from a single YAML config file.

Intended for **authorized security testing** of WAF bot-detection systems. Route curl, browsers, or Playwright through the proxy to observe how different fingerprint combinations are classified.

## How it works

```
curl / browser / Playwright
        │  HTTP CONNECT (to proxy)
        ▼
┌─────────────────────────────────────────┐
│            impersonate-proxy            │
│                                         │
│  MITM TLS ◄──────────────► uTLS        │
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

| Layer | What you can control |
|-------|----------------------|
| TLS | Cipher suites, extensions, their order (JA3 / JA4) via uTLS presets |
| HTTP/1.1 | Header order, User-Agent, add/remove any header |
| HTTP/2 | SETTINGS values & order, WINDOW_UPDATE, pseudo-header order (HTTP/2 fingerprint) |

## Prerequisites

- **macOS** (tested on macOS 15 / Apple Silicon; Linux should work too)
- **Go 1.22+**

```bash
# Install Go via Homebrew if needed
brew install go
```

## Setup

### 1. Clone and build

```bash
git clone https://github.com/<you>/impersonate-proxy.git
cd impersonate-proxy
make build
```

### 2. Generate the MITM CA certificate

The CA is generated automatically on first run. Start the proxy once to create `ca.crt` and `ca.key`:

```bash
make run
# 2026/04/22 12:00:00 generated CA certificate → ca.crt
# 2026/04/22 12:00:00 listening on 127.0.0.1:8080  preset=chrome
```

Stop it with `Ctrl-C`.

### 3. Trust the CA certificate

Clients need to trust your MITM CA so they don't reject the proxy-generated leaf certificates.

**macOS system keychain** (affects all apps):
```bash
make trust-ca        # runs: sudo security add-trusted-cert ...
```

**curl only** (no system-wide change):
```bash
curl --cacert ca.crt ...
```

**Playwright / Node.js**:
```bash
export NODE_EXTRA_CA_CERTS="$(pwd)/ca.crt"
```

**Firefox**: Preferences → Privacy & Security → View Certificates → Authorities → Import `ca.crt`

## Configuration

Edit `config.yaml` before starting the proxy. All fields have defaults — you only need to specify what you want to override.

```yaml
listen: "127.0.0.1:8080"
ca_cert: "ca.crt"
ca_key:  "ca.key"

tls:
  # TLS fingerprint preset (controls JA3 / JA4)
  # Options: chrome | firefox | safari | edge | ios | random | golang
  preset: "chrome"

http:
  # Override User-Agent (leave empty to pass through the client's UA)
  user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

  # Emit headers in this order; headers not listed are appended after
  header_order:
    - "Host"
    - "User-Agent"
    - "Accept"
    - "Accept-Language"
    - "Accept-Encoding"
    - "Connection"

  # Add or overwrite headers
  add_headers:
    Accept-Language: "ja,en-US;q=0.9,en;q=0.8"

  # Remove headers before forwarding
  remove_headers: []

http2:
  enabled: true

  # SETTINGS frame entries — id and order both affect the HTTP/2 fingerprint.
  # RFC 7540 §11.3 IDs:
  #   1=HEADER_TABLE_SIZE  2=ENABLE_PUSH  3=MAX_CONCURRENT_STREAMS
  #   4=INITIAL_WINDOW_SIZE  5=MAX_FRAME_SIZE  6=MAX_HEADER_LIST_SIZE
  settings:
    - { id: 1, val: 65536 }    # Chrome defaults shown here
    - { id: 2, val: 0 }
    - { id: 4, val: 6291456 }
    - { id: 6, val: 262144 }

  # Connection-level WINDOW_UPDATE increment
  window_update: 15663105

  # Order of pseudo-headers in the HEADERS frame
  pseudo_header_order: [method, authority, scheme, path]
```

### Browser fingerprint reference

| Browser | TLS preset | HTTP/2 SETTINGS | WINDOW_UPDATE |
|---------|-----------|-----------------|---------------|
| Chrome  | `chrome`  | `1:65536,2:0,4:6291456,6:262144` | 15663105 |
| Firefox | `firefox` | `1:65536,4:131072,5:16384`       | 12517377 |
| Safari  | `safari`  | `1:4096,3:100,4:2097152,6:16384` | 10485760 |

## Usage

### Start the proxy

```bash
make run
# Kills any previous instance on port 8080, rebuilds, and starts.
```

To switch fingerprint profiles, edit `config.yaml` and re-run `make run`.

### curl

```bash
# With CA trusted system-wide (after make trust-ca):
curl --proxy http://127.0.0.1:8080 https://tls.peet.ws/api/all

# Without system trust — pass CA explicitly:
curl --proxy http://127.0.0.1:8080 --cacert ca.crt https://tls.peet.ws/api/all
```

### Playwright (Node.js)

```js
const { chromium } = require('playwright');

const browser = await chromium.launch();
const context = await browser.newContext({
  proxy: { server: 'http://127.0.0.1:8080' },
});
// If CA is not in the system keychain, set before launching:
// NODE_EXTRA_CA_CERTS=./ca.crt node script.js
const page = await context.newPage();
await page.goto('https://tls.peet.ws/api/all');
```

### Playwright (Python)

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context(proxy={"server": "http://127.0.0.1:8080"})
    page = context.new_page()
    page.goto("https://tls.peet.ws/api/all")
```

Set `NODE_EXTRA_CA_CERTS` (Node) or `REQUESTS_CA_BUNDLE` (Python) if the CA is not trusted system-wide.

## Verifying fingerprints

[tls.peet.ws](https://tls.peet.ws) returns the full fingerprint breakdown for any request it receives. Pipe the output through `jq` or Python for a readable view:

```bash
curl -s --proxy http://127.0.0.1:8080 --cacert ca.crt \
  https://tls.peet.ws/api/all | python3 -m json.tool
```

Key fields to check:

| Field | Description |
|-------|-------------|
| `tls.ja3_hash` | JA3 fingerprint hash |
| `tls.ja4` | JA4 fingerprint string |
| `http2.akamai_fingerprint` | HTTP/2 fingerprint string (SETTINGS + WINDOW\_UPDATE + pseudo-header order) — field name is defined by the tls.peet.ws API |
| `http1.headers` | Header names in the order received by the server |
| `user_agent` | User-Agent as seen by the server |

## Project structure

```
impersonate-proxy/
├── main.go               # Entry point
├── config/config.go      # YAML config struct and defaults
├── fp/dialer.go          # uTLS dialer — TLS fingerprint presets
├── h2fp/conn.go          # HTTP/2 framer — SETTINGS / WINDOW_UPDATE / pseudo-header control
├── mitm/ca.go            # MITM CA: generate, cache, and serve leaf certs
├── proxy/proxy.go        # Proxy server: CONNECT handling, protocol branch
├── rewrite/headers.go    # HTTP header rewriting (UA, order, add/remove)
├── config.yaml           # Default configuration
└── Makefile
```

## Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Compile the binary |
| `make run` | Build, kill any existing instance, and start |
| `make trust-ca` | Add `ca.crt` to the macOS system keychain (requires sudo) |
| `make clean` | Remove the binary, `ca.crt`, and `ca.key` |

## Cleanup

Remove the binary and generated CA files:

```bash
make clean
```

If you added the CA to the macOS system keychain, remove it through **Keychain Access** (search for "impersonate-proxy CA") or:

```bash
sudo security delete-certificate -c "impersonate-proxy CA" /Library/Keychains/System.keychain
```

## Limitations

- **MITM only**: The proxy decrypts and re-encrypts traffic. Clients must trust the generated CA.
- **No HTTP/2 from client**: The client→proxy leg uses HTTP/1.1 (via CONNECT). Only the proxy→server leg uses HTTP/2 with custom fingerprints.
- **Chunked request bodies**: Requests with `Transfer-Encoding: chunked` bodies are not currently supported.
- **No QUIC / HTTP/3**: Out of scope.

## Legal notice

This tool is intended for **authorized security testing only** — for example, testing WAF and bot-detection configurations on systems you own or have explicit written permission to test.

Using this tool against systems without authorization may violate applicable laws (such as the Computer Fraud and Abuse Act, Japan's Unauthorized Computer Access Law, or equivalent legislation in your jurisdiction) and the terms of service of the target.

**The authors accept no liability for misuse.**

## Acknowledgements

- [uTLS](https://github.com/refraction-networking/utls) — TLS fingerprint customization
- [tls.peet.ws](https://tls.peet.ws) — Fingerprint inspection API used in examples
- [JA4+](https://github.com/FoxIO-LLC/ja4) — Fingerprinting standard reference
