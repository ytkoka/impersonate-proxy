GO := $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)

.PHONY: build build-mcp test-mcp run clean trust-ca docker-build docker-run docker-stop

build:
	$(GO) build -o impersonate-proxy .

# Optional MCP server (separate Go module in impersonate-mcp/) that drives the
# proxy's management API. Not built by `make build`. See README "MCP server".
build-mcp:
	cd impersonate-mcp && $(GO) build -o impersonate-mcp .
	@echo "built: $(CURDIR)/impersonate-mcp/impersonate-mcp  (use this exact path as the MCP server command)"

test-mcp:
	cd impersonate-mcp && $(GO) test ./...

run: build
	@lsof -ti:8080 | xargs kill -9 2>/dev/null || true
	./impersonate-proxy -config config.yaml

clean:
	rm -f impersonate-proxy impersonate-mcp/impersonate-mcp ca.crt ca.key

# macOS: add CA to system keychain (requires sudo)
trust-ca:
	sudo security add-trusted-cert -d -r trustRoot \
		-k /Library/Keychains/System.keychain ca.crt

# Run via Docker instead — no local Go toolchain required. See README "Docker" section.
docker-build:
	docker compose build

docker-run: docker-build
	docker compose up -d
	@echo "proxy:  127.0.0.1:8080"
	@echo "mgmt:   127.0.0.1:8081"
	@echo "CA cert generated at ./data/ca.crt on first run"

docker-stop:
	docker compose down
