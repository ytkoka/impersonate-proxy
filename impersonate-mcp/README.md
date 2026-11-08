# impersonate-mcp

An MCP server that lets AI agents (Claude Desktop, Claude Code, and other MCP clients) drive [impersonate-proxy](https://github.com/ytkoka/impersonate-proxy) — switch TLS (JA3/JA4) and HTTP/2 fingerprints, User-Agent, spoofed client IP and upstream proxies, then verify what the server actually sees, all in one conversation.

> **Requires a running impersonate-proxy.** This server is a stdio client for the proxy's management API (`mgmt_listen`, default `http://127.0.0.1:8081`). It does nothing on its own — start the proxy first ([setup](https://github.com/ytkoka/impersonate-proxy#setup)).

Intended for **authorized security testing** of WAF and bot-detection systems you own or have explicit permission to test.

## Tools

| Tool | What it does |
| --- | --- |
| `get_config` | Show the active runtime settings |
| `set_tls_preset` | Switch the TLS preset (`chrome`, `firefox`, `safari`, `edge`, `ios`, `random`, `golang`) |
| `set_custom_hello` | Set an arbitrary ClientHello (cipher suites, curves, versions, extensions) and switch to the `custom` preset |
| `set_user_agent` | Set the User-Agent (`"auto"` derives it from the TLS preset) |
| `set_client_ip` | Set the spoofed client IP (`X-Forwarded-For` / `True-Client-IP`) |
| `set_upstream` | Enable/disable the upstream proxy and select one by name |
| `verify_fingerprint` | Fetch `tls.peet.ws` through the proxy and summarise `ja3_hash`, `ja4`, `akamai_fingerprint`, `user_agent` and `ip` |
| `fetch_url` | Fetch any `http(s)` URL through the proxy — with the current TLS preset, User-Agent, client IP, upstream and host filter — and return `status`, `http_version`, `final_url`, `redirects`, `headers`, `body`, `body_truncated` and `elapsed_ms`. Options: `method`, `headers`, `body`, `follow_redirects`, `max_body_bytes`. Failures come back in an `error` field |

Pass `--read-only` to hide every tool that changes settings (`set_*`). `fetch_url` stays, but only for `GET` / `HEAD` / `OPTIONS` without a body.

## Install

```sh
git clone https://github.com/ytkoka/impersonate-proxy.git
cd impersonate-proxy
make build-mcp   # prints the binary's absolute path
```

This is a separate Go module — `make build` and the Docker image don't include it.

## Configure

### Claude Code

```sh
claude mcp add impersonate -- /path/to/impersonate-proxy/impersonate-mcp/impersonate-mcp \
  --ca-cert /path/to/impersonate-proxy/ca.crt
```

### Claude Desktop

Add to `claude_desktop_config.json` (use absolute paths — Claude Desktop doesn't read your shell `PATH`):

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

If the file already has other keys or servers, add `"impersonate"` inside the existing `mcpServers` object rather than appending a second top-level `{ ... }`.

## Options

| Flag / env | Description |
| --- | --- |
| `--ca-cert` | Path to the proxy's `ca.crt`, used by `verify_fingerprint` and `fetch_url` to trust the MITM certificate |
| `--read-only` | Hide the `set_*` tools; limit `fetch_url` to `GET` / `HEAD` / `OPTIONS` |
| `IMPERSONATE_MGMT_URL` | Management API URL (default `http://127.0.0.1:8081`) |

## Security

The proxy's management API has **no authentication**. Keep `mgmt_listen` on loopback, and run this server locally over stdio only.

`fetch_url` always goes through the proxy and refuses loopback, private and link-local destinations (checking the host, every resolved address and each redirect hop). To limit it further, set `fetch_allow_hosts` in the proxy's `config.yaml` (or start the proxy with `-fetch-allow-hosts a.com,b.com`): only those hosts and their subdomains are reachable. `get_config` shows the list; no tool can change it. If the proxy's configuration can't be read, `fetch_url` refuses rather than fetching unrestricted. DNS rebinding between this server's lookup and the proxy's own lookup is not prevented.

## License

MIT — see the [repository root](https://github.com/ytkoka/impersonate-proxy/blob/main/LICENSE).
