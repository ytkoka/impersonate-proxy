package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"impersonate-proxy/config"
)

// mgmtClient talks to the proxy's management API (GET/POST /api/config).
type mgmtClient struct {
	base *url.URL
	http *http.Client
}

func newMgmtClient(raw string) (*mgmtClient, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid management API URL %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid management API URL %q: want http(s)://host:port", raw)
	}
	// The management API must be reached directly, never through HTTP(S)_PROXY.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &mgmtClient{base: u, http: &http.Client{Transport: tr, Timeout: 10 * time.Second}}, nil
}

// loopback reports whether the management API is on a loopback host.
func (c *mgmtClient) loopback() bool {
	h := c.base.Hostname()
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (c *mgmtClient) GetConfig(ctx context.Context) (config.ActiveConfig, error) {
	return c.do(ctx, http.MethodGet, nil)
}

// Patch applies a partial update and returns the resulting active config.
// Nil fields of p are sent as null, which the proxy treats as "unchanged".
func (c *mgmtClient) Patch(ctx context.Context, p config.ConfigPatch) (config.ActiveConfig, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return config.ActiveConfig{}, err
	}
	return c.do(ctx, http.MethodPost, body)
}

func (c *mgmtClient) do(ctx context.Context, method string, body []byte) (config.ActiveConfig, error) {
	var cfg config.ActiveConfig
	endpoint := c.base.JoinPath("/api/config").String()

	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
	if err != nil {
		return cfg, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return cfg, fmt.Errorf("cannot reach the management API at %s (is impersonate-proxy running, and is mgmt_listen set?): %w", c.base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return cfg, fmt.Errorf("management API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decoding management API response: %w", err)
	}
	return cfg, nil
}
