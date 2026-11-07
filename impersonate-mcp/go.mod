module impersonate-mcp

go 1.25.0

require impersonate-proxy v0.0.0

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/modelcontextprotocol/go-sdk v1.8.0
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Reuse the proxy's config/filter packages from the parent directory. This is a
// separate module so the MCP SDK dependencies stay out of the proxy's go.mod.
replace impersonate-proxy => ../
