package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"impersonate-proxy/config"
)

// fakeMgmt mimics the proxy's /api/config endpoint with a partial-update POST.
type fakeMgmt struct {
	mu     sync.Mutex
	cfg    config.ActiveConfig
	bodies []string
}

func (f *fakeMgmt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/api/config" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		var p config.ConfigPatch
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.bodies = append(f.bodies, string(raw))
		if p.TLSPreset != nil {
			if *p.TLSPreset == "bogus" {
				http.Error(w, `unknown preset "bogus"`, http.StatusBadRequest)
				return
			}
			f.cfg.TLSPreset = *p.TLSPreset
		}
		if p.CustomHello != nil {
			f.cfg.CustomHello = *p.CustomHello
		}
		if p.ClientIP != nil {
			f.cfg.ClientIP = *p.ClientIP
		}
		if p.UserAgent != nil {
			f.cfg.UserAgent = *p.UserAgent
		}
		if p.UpstreamEnabled != nil {
			f.cfg.UpstreamEnabled = *p.UpstreamEnabled
		}
		if p.UpstreamSelect != nil {
			f.cfg.UpstreamSelect = *p.UpstreamSelect
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(f.cfg)
}

const fixtureAkamai = "1:65536;2:0|15663105|0|m,a,s,p"

const peetFixture = `{
  "ip": "203.0.113.7:51234",
  "http_version": "h2",
  "user_agent": "Mozilla/5.0 test",
  "tls": {"ja3_hash": "abc123", "ja4": "t13d1516h2_aaaa_bbbb", "ja3": "very long"},
  "http2": {"akamai_fingerprint": "1:65536;2:0|15663105|0|m,a,s,p"}
}`

// connect starts a server against fake backends and returns a client session.
func connect(t *testing.T, mutate func(*options, *fakeMgmt)) (*mcp.ClientSession, *fakeMgmt) {
	t.Helper()

	fm := &fakeMgmt{cfg: config.ActiveConfig{TLSPreset: "chrome", Listen: "127.0.0.1:8080", FilterMode: "off", HTTP2Fingerprint: fixtureAkamai}}
	mgmtSrv := httptest.NewServer(fm)
	t.Cleanup(mgmtSrv.Close)

	// Stand-in proxy: answers any proxied plain-HTTP request with the fixture.
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(peetFixture))
	}))
	t.Cleanup(proxySrv.Close)

	o := options{MgmtURL: mgmtSrv.URL, ProxyURL: proxySrv.URL, VerifyURL: "http://tls.peet.ws/api/all"}
	if mutate != nil {
		mutate(&o, fm)
	}
	srv, err := newServer(o)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, fm
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

func decode[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", errText(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decoding %s: %v", b, err)
	}
	return v
}

func errText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

func TestToolListFullAndReadOnly(t *testing.T) {
	cs, _ := connect(t, nil)
	want := []string{"fetch_url", "get_config", "set_client_ip", "set_custom_hello", "set_tls_preset", "set_upstream", "set_user_agent", "verify_fingerprint"}
	if got := toolNames(t, cs); !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}

	ro, _ := connect(t, func(o *options, _ *fakeMgmt) { o.ReadOnly = true })
	want = []string{"fetch_url", "get_config", "verify_fingerprint"}
	if got := toolNames(t, ro); !slices.Equal(got, want) {
		t.Errorf("read-only tools = %v, want %v", got, want)
	}
}

func TestGetConfig(t *testing.T) {
	cs, _ := connect(t, nil)
	cfg := decode[config.ActiveConfig](t, call(t, cs, "get_config", nil))
	if cfg.TLSPreset != "chrome" || cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestSettersSendPartialPatches(t *testing.T) {
	cs, fm := connect(t, nil)

	cfg := decode[config.ActiveConfig](t, call(t, cs, "set_tls_preset", map[string]any{"preset": "firefox"}))
	if cfg.TLSPreset != "firefox" {
		t.Errorf("preset = %q", cfg.TLSPreset)
	}
	call(t, cs, "set_user_agent", map[string]any{"user_agent": "auto"})
	cfg = decode[config.ActiveConfig](t, call(t, cs, "set_client_ip", map[string]any{"client_ip": "198.51.100.1"}))

	if cfg.TLSPreset != "firefox" || cfg.UserAgent != "auto" || cfg.ClientIP != "198.51.100.1" {
		t.Errorf("settings did not accumulate: %+v", cfg)
	}

	// Clearing a value must be sent as an explicit "" (not omitted).
	cfg = decode[config.ActiveConfig](t, call(t, cs, "set_client_ip", map[string]any{"client_ip": ""}))
	if cfg.ClientIP != "" || cfg.TLSPreset != "firefox" {
		t.Errorf("clear failed or clobbered other fields: %+v", cfg)
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if last := fm.bodies[len(fm.bodies)-1]; !strings.Contains(last, `"client_ip":""`) {
		t.Errorf("clear not sent explicitly: %s", last)
	}
}

func TestSetCustomHello(t *testing.T) {
	cs, _ := connect(t, nil)
	cfg := decode[config.ActiveConfig](t, call(t, cs, "set_custom_hello", map[string]any{
		"cipher_suites": []any{2570, 4865, 4866},
		"curves":        []any{"X25519", "P256"},
		"versions":      []any{"1.3", "1.2"},
		"extensions":    []any{2570, 0, 23},
	}))
	if cfg.TLSPreset != "custom" {
		t.Errorf("preset = %q, want custom", cfg.TLSPreset)
	}
	if !slices.Equal(cfg.CustomHello.CipherSuites, []uint16{2570, 4865, 4866}) || !slices.Equal(cfg.CustomHello.Curves, []string{"X25519", "P256"}) {
		t.Errorf("custom_hello = %+v", cfg.CustomHello)
	}
}

func TestSetUpstream(t *testing.T) {
	cs, _ := connect(t, nil)

	cfg := decode[config.ActiveConfig](t, call(t, cs, "set_upstream", map[string]any{"enabled": true, "select": "residential_us"}))
	if !cfg.UpstreamEnabled || cfg.UpstreamSelect != "residential_us" {
		t.Errorf("upstream = %+v", cfg)
	}
	// Disabling alone must keep the selection.
	cfg = decode[config.ActiveConfig](t, call(t, cs, "set_upstream", map[string]any{"enabled": false}))
	if cfg.UpstreamEnabled || cfg.UpstreamSelect != "residential_us" {
		t.Errorf("upstream after disable = %+v", cfg)
	}

	if res := call(t, cs, "set_upstream", map[string]any{}); !res.IsError {
		t.Error("set_upstream with no fields should be a tool error")
	}
}

func TestMgmtErrorsSurfaceAsToolErrors(t *testing.T) {
	cs, _ := connect(t, nil)
	res := call(t, cs, "set_tls_preset", map[string]any{"preset": "bogus"})
	if !res.IsError || !strings.Contains(errText(res), "unknown preset") {
		t.Errorf("want tool error mentioning unknown preset, got IsError=%v %q", res.IsError, errText(res))
	}
}

func TestMgmtUnreachable(t *testing.T) {
	cs, _ := connect(t, func(o *options, _ *fakeMgmt) { o.MgmtURL = "http://127.0.0.1:1" })
	res := call(t, cs, "get_config", nil)
	if !res.IsError || !strings.Contains(errText(res), "cannot reach the management API") {
		t.Errorf("got IsError=%v %q", res.IsError, errText(res))
	}
}

func TestVerifyFingerprintSummary(t *testing.T) {
	cs, _ := connect(t, nil)
	s := decode[FingerprintSummary](t, call(t, cs, "verify_fingerprint", nil))
	want := FingerprintSummary{
		JA3Hash:           "abc123",
		JA4:               "t13d1516h2_aaaa_bbbb",
		AkamaiFingerprint: "1:65536;2:0|15663105|0|m,a,s,p",
		UserAgent:         "Mozilla/5.0 test",
		IP:                "203.0.113.7", // port stripped
		TLSPreset:         "chrome",
		FilterMode:        "off",
	}
	if s.JA3Hash != want.JA3Hash || s.JA4 != want.JA4 || s.AkamaiFingerprint != want.AkamaiFingerprint ||
		s.UserAgent != want.UserAgent || s.IP != want.IP || s.TLSPreset != want.TLSPreset || s.FilterMode != want.FilterMode {
		t.Errorf("summary = %+v, want %+v", s, want)
	}
	if len(s.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", s.Warnings)
	}
}

func TestVerifyWarnsWhenFilteredOut(t *testing.T) {
	cs, _ := connect(t, func(o *options, fm *fakeMgmt) {
		fm.cfg.FilterMode = "include"
		fm.cfg.FilterHosts = []string{"example.com"}
	})
	s := decode[FingerprintSummary](t, call(t, cs, "verify_fingerprint", nil))
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "tls.peet.ws") {
		t.Errorf("warnings = %v", s.Warnings)
	}
}

func TestVerifyDerivesProxyFromListenAndReportsMissingCA(t *testing.T) {
	cs, _ := connect(t, func(o *options, _ *fakeMgmt) {
		o.ProxyURL = ""                                   // derive from cfg.Listen (nothing listens there)
		o.CACert = filepath.Join(t.TempDir(), "nope.crt") // missing file
	})
	res := call(t, cs, "verify_fingerprint", nil)
	if !res.IsError || !strings.Contains(errText(res), "reading CA certificate") {
		t.Errorf("got IsError=%v %q", res.IsError, errText(res))
	}
}

func TestVerifyRejectsNonPEMCA(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, func(o *options, _ *fakeMgmt) { o.CACert = bad })
	res := call(t, cs, "verify_fingerprint", nil)
	if !res.IsError || !strings.Contains(errText(res), "no PEM certificate") {
		t.Errorf("got IsError=%v %q", res.IsError, errText(res))
	}
}

func TestProxyURLFromListen(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:8080": "http://127.0.0.1:8080",
		":8080":          "http://127.0.0.1:8080",
		"0.0.0.0:9000":   "http://127.0.0.1:9000",
		"[::]:8080":      "http://127.0.0.1:8080",
		"10.0.0.5:8080":  "http://10.0.0.5:8080",
	} {
		got, err := proxyURLFromListen(in)
		if err != nil || got != want {
			t.Errorf("proxyURLFromListen(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := proxyURLFromListen("nonsense"); err == nil {
		t.Error("expected error for address without port")
	}
}

func TestNewMgmtClientValidation(t *testing.T) {
	for _, bad := range []string{"", "127.0.0.1:8081", "ftp://x", "http://"} {
		if _, err := newMgmtClient(bad); err == nil {
			t.Errorf("newMgmtClient(%q) should fail", bad)
		}
	}
	for url, want := range map[string]bool{
		"http://127.0.0.1:8081": true, "http://localhost:8081": true, "http://[::1]:8081": true,
		"http://10.0.0.5:8081": false, "http://example.com": false,
	} {
		c, err := newMgmtClient(url)
		if err != nil {
			t.Fatal(err)
		}
		if c.loopback() != want {
			t.Errorf("loopback(%q) = %v, want %v", url, c.loopback(), want)
		}
	}
}

func TestVerifyWarnsAboutAnOlderProxy(t *testing.T) {
	cs, _ := connect(t, func(_ *options, fm *fakeMgmt) { fm.cfg.HTTP2Fingerprint = "" })
	s := decode[FingerprintSummary](t, call(t, cs, "verify_fingerprint", nil))
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "older build") {
		t.Errorf("warnings = %v", s.Warnings)
	}
}

func TestVerifyWarnsWhenTheServerSawAnotherHTTP2Fingerprint(t *testing.T) {
	cs, _ := connect(t, func(_ *options, fm *fakeMgmt) { fm.cfg.HTTP2Fingerprint = "2:0;4:2097152;3:100|10485760|0|m,s,p,a" })
	s := decode[FingerprintSummary](t, call(t, cs, "verify_fingerprint", nil))
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "set to send") {
		t.Errorf("warnings = %v", s.Warnings)
	}
}
