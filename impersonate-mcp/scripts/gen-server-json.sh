#!/usr/bin/env bash
# Generate server.json for the MCP Registry from server.template.json and the
# SHA256SUMS.txt that package-mcpb.sh wrote next to the bundles.
#
# Usage: scripts/gen-server-json.sh <tag-prefix-version> [dist-dir]
#   e.g. scripts/gen-server-json.sh 0.1.0 dist     -> dist/server.json
#
# The bundle URLs point at the GitHub Release for tag mcp-v<version>, so the
# release assets must exist before `mcp-publisher publish` runs.
set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:?usage: gen-server-json.sh <version> [dist-dir]}"
dist="${2:-dist}"
sums="$dist/SHA256SUMS.txt"
[ -f "$sums" ] || { echo "$sums not found" >&2; exit 1; }

base="https://github.com/ytkoka/impersonate-proxy/releases/download/mcp-v${version}"

packages="$(
  while read -r sha file; do
    file="${file#\*}"
    jq -n --arg url "$base/$file" --arg sha "$sha" '{
      registryType: "mcpb",
      identifier: $url,
      fileSha256: $sha,
      transport: { type: "stdio" },
      environmentVariables: [
        { name: "IMPERSONATE_MGMT_URL", description: "Management API URL of the running impersonate-proxy.", isRequired: false, format: "string", default: "http://127.0.0.1:8081" },
        { name: "IMPERSONATE_CA_CERT", description: "Path to the proxy ca.crt, so verify_fingerprint and fetch_url trust its MITM certificate.", isRequired: false, format: "filepath" },
        { name: "IMPERSONATE_READ_ONLY", description: "Set to true to hide every tool that changes proxy settings.", isRequired: false, format: "boolean", default: "false" }
      ]
    }'
  done < "$sums" | jq -s .
)"

jq --arg v "$version" --argjson p "$packages" \
  '.version = $v | .packages = $p' server.template.json > "$dist/server.json"
echo "wrote $dist/server.json"
