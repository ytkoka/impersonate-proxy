#!/usr/bin/env bash
# Build one .mcpb bundle per platform from mcpb/manifest.json.
#
# MCPB's compatibility.platforms names an OS but not an architecture, so each
# OS/arch pair gets its own bundle: dist/impersonate-mcp_<version>_<os>_<arch>.mcpb
# (os is darwin, linux or win32, as MCPB spells it).
#
# Usage: scripts/package-mcpb.sh            # all targets
#        scripts/package-mcpb.sh darwin/arm64 linux/amd64   # a subset (GOOS/GOARCH)
set -euo pipefail

cd "$(dirname "$0")/.."

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is required" >&2; exit 1; }

version="$(sed -n 's/^[[:space:]]*version = "\(.*\)"$/\1/p' main.go | head -n1)"
manifest_version="$(jq -r .version mcpb/manifest.json)"
if [ -z "$version" ] || [ "$version" != "$manifest_version" ]; then
  echo "version mismatch: main.go has '${version}', mcpb/manifest.json has '${manifest_version}'" >&2
  exit 1
fi

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64)
fi

rm -rf dist
mkdir -p dist
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  mcpb_os="$goos"
  exe="impersonate-mcp"
  if [ "$goos" = "windows" ]; then
    mcpb_os="win32"
    exe="impersonate-mcp.exe"
  fi

  stage="$work/${mcpb_os}_${goarch}"
  mkdir -p "$stage/server"

  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w" -o "$stage/server/$exe" .

  jq --arg os "$mcpb_os" --arg exe "server/$exe" '
      .compatibility.platforms = [$os]
      | .server.entry_point = $exe
      | .server.mcp_config.command = "${__dirname}/" + $exe
    ' mcpb/manifest.json > "$stage/manifest.json"
  cp mcpb/icon.png "$stage/icon.png"
  cp ../LICENSE "$stage/LICENSE"

  out="$PWD/dist/impersonate-mcp_${version}_${mcpb_os}_${goarch}.mcpb"
  # -X drops extra file attributes and -r keeps it reproducible enough; the
  # executable bit survives in the zip's external attributes.
  (cd "$stage" && zip -q -X -r "$out" manifest.json icon.png LICENSE server)
  echo "built $out"
done

(cd dist && shasum -a 256 -- *.mcpb > SHA256SUMS.txt)
echo "wrote dist/SHA256SUMS.txt"
