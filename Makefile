GO := $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)

.PHONY: build run clean trust-ca

build:
	$(GO) build -o impersonate-proxy .

run: build
	@lsof -ti:8080 | xargs kill -9 2>/dev/null || true
	./impersonate-proxy -config config.yaml

clean:
	rm -f impersonate-proxy ca.crt ca.key

# macOS: add CA to system keychain (requires sudo)
trust-ca:
	sudo security add-trusted-cert -d -r trustRoot \
		-k /Library/Keychains/System.keychain ca.crt
