package main

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"impersonate-proxy/config"
)

type noArgs struct{}

type setTLSPresetArgs struct {
	Preset string `json:"preset" jsonschema:"TLS preset: chrome, firefox, safari, edge, ios, random, golang. Use set_custom_hello for an arbitrary fingerprint."`
}

type setUserAgentArgs struct {
	UserAgent string `json:"user_agent" jsonschema:"User-Agent to send. Empty string keeps the client's own; \"auto\" derives one from the TLS preset."`
}

type setClientIPArgs struct {
	ClientIP string `json:"client_ip" jsonschema:"IP address to inject into X-Forwarded-For / True-Client-IP style headers. Empty string disables spoofing."`
}

type setUpstreamArgs struct {
	Enabled *bool   `json:"enabled,omitempty" jsonschema:"Route outbound connections through the upstream proxy (true) or connect directly (false)."`
	Select  *string `json:"select,omitempty" jsonschema:"Upstream proxy name from config.yaml, or \"rotate\" / \"random\". Empty string selects the first proxy. Proxies cannot be added at runtime."`
}

// registerTools adds the tools to srv. In read-only mode the tools that change
// the proxy's configuration are not registered, and fetch_url refuses anything
// but GET/HEAD/OPTIONS.
func registerTools(srv *mcp.Server, mgmt *mgmtClient, v *verifier, f *fetcher, readOnly bool) {
	patchTool := func(name, desc string) *mcp.Tool {
		return &mcp.Tool{
			Name:        name,
			Description: desc,
			Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
		}
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_config",
		Description: "Return the proxy's active runtime settings: TLS preset, custom_hello, User-Agent, client IP, upstream state (proxy names only) and host filter.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, config.ActiveConfig, error) {
		cfg, err := mgmt.GetConfig(ctx)
		return nil, cfg, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "verify_fingerprint",
		Description: "Fetch the fingerprint echo service (tls.peet.ws by default) through the proxy and summarise what the server saw: " +
			"ja3_hash, ja4, akamai_fingerprint (HTTP/2), user_agent and ip. Makes one request to that external service.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, FingerprintSummary, error) {
		s, err := v.run(ctx)
		return nil, s, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "fetch_url",
		Description: "Fetch a URL through the proxy using the current TLS preset, User-Agent, client IP and upstream settings, " +
			"and return the status, headers and body.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a fetchArgs) (*mcp.CallToolResult, FetchResult, error) {
		// Failures are reported in the result's error field, not as a tool error.
		return nil, f.run(ctx, a), nil
	})

	if readOnly {
		return
	}

	mcp.AddTool(srv, patchTool("set_tls_preset",
		"Switch the TLS (JA3/JA4) fingerprint to a named browser preset. Other settings are left unchanged."),
		func(ctx context.Context, _ *mcp.CallToolRequest, a setTLSPresetArgs) (*mcp.CallToolResult, config.ActiveConfig, error) {
			if a.Preset == "" {
				return nil, config.ActiveConfig{}, errors.New("preset must not be empty")
			}
			cfg, err := mgmt.Patch(ctx, config.ConfigPatch{TLSPreset: &a.Preset})
			return nil, cfg, err
		})

	mcp.AddTool(srv, patchTool("set_custom_hello",
		"Set an arbitrary TLS ClientHello (switches the preset to \"custom\"). cipher_suites and extensions are numeric IDs in wire order "+
			"(0x0a0a-style values are GREASE placeholders); curves are names such as X25519, P256, P384, P521; versions are \"1.2\" / \"1.3\"."),
		func(ctx context.Context, _ *mcp.CallToolRequest, a config.CustomHello) (*mcp.CallToolResult, config.ActiveConfig, error) {
			custom := "custom"
			cfg, err := mgmt.Patch(ctx, config.ConfigPatch{TLSPreset: &custom, CustomHello: &a})
			return nil, cfg, err
		})

	mcp.AddTool(srv, patchTool("set_user_agent",
		"Set the User-Agent header the proxy sends upstream. Other settings are left unchanged."),
		func(ctx context.Context, _ *mcp.CallToolRequest, a setUserAgentArgs) (*mcp.CallToolResult, config.ActiveConfig, error) {
			cfg, err := mgmt.Patch(ctx, config.ConfigPatch{UserAgent: &a.UserAgent})
			return nil, cfg, err
		})

	mcp.AddTool(srv, patchTool("set_client_ip",
		"Set the client IP the proxy advertises in forwarding headers (X-Forwarded-For etc.). Empty string turns spoofing off."),
		func(ctx context.Context, _ *mcp.CallToolRequest, a setClientIPArgs) (*mcp.CallToolResult, config.ActiveConfig, error) {
			cfg, err := mgmt.Patch(ctx, config.ConfigPatch{ClientIP: &a.ClientIP})
			return nil, cfg, err
		})

	mcp.AddTool(srv, patchTool("set_upstream",
		"Enable or disable routing through an upstream SOCKS5/HTTP proxy and/or choose which configured one to use. "+
			"Give at least one of enabled / select; omitted fields are left unchanged."),
		func(ctx context.Context, _ *mcp.CallToolRequest, a setUpstreamArgs) (*mcp.CallToolResult, config.ActiveConfig, error) {
			if a.Enabled == nil && a.Select == nil {
				return nil, config.ActiveConfig{}, errors.New("specify at least one of enabled / select")
			}
			cfg, err := mgmt.Patch(ctx, config.ConfigPatch{UpstreamEnabled: a.Enabled, UpstreamSelect: a.Select})
			return nil, cfg, err
		})
}

func ptr[T any](v T) *T { return &v }
