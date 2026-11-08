package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"impersonate-proxy/config"
)

// fakeDNS stands in for the resolver so tests never touch the network.
var fakeDNS = map[string][]string{
	"pub.example":         {"93.184.216.34"},
	"sub.pub.example":     {"93.184.216.40"},
	"other.example":       {"93.184.216.35"},
	"rebind.example":      {"10.0.0.5"},
	"mixed.example":       {"93.184.216.34", "127.0.0.1"},
	"v6internal.example":  {"fd00::1"},
	"mapped.example":      {"::ffff:192.168.1.1"},
	"metadata.example":    {"169.254.169.254"},
	"slow.pub.example":    {"93.184.216.41"},
	"notpub.example.test": {"93.184.216.50"},
}

func lookupFake(_ context.Context, host string) ([]netip.Addr, error) {
	ips, ok := fakeDNS[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

// forwardProxy is a plain-HTTP forward proxy that plays every origin server.
type forwardProxy struct {
	mu   sync.Mutex
	seen []string // "METHOD host/path"
	auth map[string]string
}

func (p *forwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.seen = append(p.seen, r.Method+" "+r.URL.Host+r.URL.Path)
	if p.auth == nil {
		p.auth = map[string]string{}
	}
	p.auth[r.URL.Host+r.URL.Path] = r.Header.Get("Authorization")
	p.mu.Unlock()

	switch r.URL.Host + r.URL.Path {
	case "pub.example/ok":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Set-Cookie", "a=secret1")
		w.Header().Add("Set-Cookie", "b=secret2")
		w.Header().Set("X-Test", "yes")
		fmt.Fprint(w, "hello")
	case "pub.example/redir1":
		http.Redirect(w, r, "/redir2", http.StatusFound)
	case "pub.example/redir2":
		http.Redirect(w, r, "http://other.example/final", http.StatusMovedPermanently)
	case "other.example/final":
		fmt.Fprint(w, "final")
	case "pub.example/to-private":
		http.Redirect(w, r, "http://127.0.0.1:8080/", http.StatusFound)
	case "pub.example/loop":
		http.Redirect(w, r, "/loop", http.StatusFound)
	case "pub.example/big":
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("a", 2000))
	case "pub.example/utf8":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, strings.Repeat("あ", 10)) // 3 bytes each
	case "pub.example/bin":
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00"))
	case "pub.example/echo":
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"method":%q,"body":%q,"x":%q}`, r.Method, b, r.Header.Get("X-Custom"))
	case "pub.example/post-redirect":
		http.Redirect(w, r, "/echo", http.StatusSeeOther)
	case "pub.example/hold":
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	case "pub.example/headers":
		w.Header().Set("Content-Type", "application/json")
		h := map[string]string{}
		for k := range r.Header {
			h[strings.ToLower(k)] = r.Header.Get(k)
		}
		json.NewEncoder(w).Encode(h)
	case "pub.example/gz", "pub.example/br", "pub.example/zstd", "pub.example/deflate", "pub.example/deflate-raw", "pub.example/bomb", "pub.example/stacked":
		serveEncoded(w, r.URL.Path)
	case "pub.example/five":
		w.WriteHeader(http.StatusBadGateway)
	default:
		http.NotFound(w, r)
	}
}

func (p *forwardProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.seen)
}

type fetchEnv struct {
	cs    *mcp.ClientSession
	mgmt  *fakeMgmt
	proxy *forwardProxy
}

func newFetchEnv(t *testing.T, mutate func(*options, *fakeMgmt)) *fetchEnv {
	t.Helper()
	fp := &forwardProxy{}
	srv := httptest.NewServer(fp)
	t.Cleanup(srv.Close)
	cs, fm := connect(t, func(o *options, fm *fakeMgmt) {
		o.ProxyURL = srv.URL
		o.lookup = lookupFake
		fm.cfg.TLSPreset = "ios"
		fm.cfg.UserAgent = "auto"
		if mutate != nil {
			mutate(o, fm)
		}
	})
	return &fetchEnv{cs: cs, mgmt: fm, proxy: fp}
}

func (e *fetchEnv) fetch(t *testing.T, args map[string]any) FetchResult {
	t.Helper()
	return decode[FetchResult](t, call(t, e.cs, "fetch_url", args))
}

func TestFetchBasic(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/ok"})
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	if r.Status != 200 || r.Body != "hello" || r.BodyBytes != 5 || r.BodyTruncated {
		t.Errorf("result = %+v", r)
	}
	if r.FinalURL != "http://pub.example/ok" || len(r.Redirects) != 0 {
		t.Errorf("final_url=%q redirects=%v", r.FinalURL, r.Redirects)
	}
	if r.HTTPVersion != "HTTP/1.1" {
		t.Errorf("http_version = %q", r.HTTPVersion)
	}
	// Settings at send time come from the proxy's config.
	if r.TLSPreset != "ios" || r.UserAgent != "auto" {
		t.Errorf("tls_preset=%q user_agent=%q", r.TLSPreset, r.UserAgent)
	}
	if r.Headers["x-test"] != "yes" {
		t.Errorf("headers = %v", r.Headers)
	}
	// Cookie values must not leak; only the count is reported.
	if got := r.Headers["set-cookie"]; !strings.Contains(got, "2 cookie") || strings.Contains(got, "secret") {
		t.Errorf("set-cookie = %q", got)
	}
}

func TestFetchGoesThroughTheProxyOnly(t *testing.T) {
	e := newFetchEnv(t, nil)
	e.fetch(t, map[string]any{"url": "http://pub.example/ok"})
	if got := e.proxy.requests(); !slices.Equal(got, []string{"GET pub.example/ok"}) {
		t.Errorf("proxy saw %v", got)
	}
}

func TestFetchRedirects(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/redir1", "headers": map[string]any{"Authorization": "Bearer x"}})
	if r.Error != "" || r.Status != 200 || r.Body != "final" {
		t.Fatalf("result = %+v", r)
	}
	if r.FinalURL != "http://other.example/final" {
		t.Errorf("final_url = %q", r.FinalURL)
	}
	if want := []string{"http://pub.example/redir1", "http://pub.example/redir2"}; !slices.Equal(r.Redirects, want) {
		t.Errorf("redirects = %v, want %v", r.Redirects, want)
	}
	e.proxy.mu.Lock()
	defer e.proxy.mu.Unlock()
	if e.proxy.auth["pub.example/redir2"] != "Bearer x" {
		t.Error("same-host redirect should keep Authorization")
	}
	if e.proxy.auth["other.example/final"] != "" {
		t.Error("cross-host redirect must drop Authorization")
	}
}

func TestFetchFollowRedirectsFalse(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/redir1", "follow_redirects": false})
	if r.Status != 302 || r.Headers["location"] != "/redir2" || len(r.Redirects) != 0 {
		t.Errorf("result = %+v", r)
	}
}

func TestFetchRedirectLimit(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/loop"})
	if !strings.Contains(r.Error, "10 redirects") || len(r.Redirects) != maxRedirects {
		t.Errorf("error=%q redirects=%d", r.Error, len(r.Redirects))
	}
}

func TestFetchRedirectIntoPrivateIsRefused(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/to-private"})
	if !strings.Contains(r.Error, "127.0.0.1") {
		t.Errorf("error = %q", r.Error)
	}
	for _, req := range e.proxy.requests() {
		if strings.Contains(req, "127.0.0.1") {
			t.Errorf("the private hop reached the proxy: %v", e.proxy.requests())
		}
	}
}

func TestFetchTruncation(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/big", "max_body_bytes": 100})
	if !r.BodyTruncated || r.BodyBytes != 100 || len(r.Body) != 100 {
		t.Errorf("truncated=%v bytes=%d len=%d", r.BodyTruncated, r.BodyBytes, len(r.Body))
	}
	r = e.fetch(t, map[string]any{"url": "http://pub.example/big"})
	if r.BodyTruncated || r.BodyBytes != 2000 {
		t.Errorf("default limit should fit 2000 bytes: truncated=%v bytes=%d", r.BodyTruncated, r.BodyBytes)
	}
	// Above the hard cap the request is clamped, not rejected.
	r = e.fetch(t, map[string]any{"url": "http://pub.example/big", "max_body_bytes": 99999999})
	if r.Error != "" || r.BodyBytes != 2000 {
		t.Errorf("clamped fetch: %+v", r)
	}
}

func TestFetchTruncationKeepsValidUTF8(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/utf8", "max_body_bytes": 7})
	if !r.BodyTruncated || r.Body != "ああ" || strings.ContainsRune(r.Body, '�') {
		t.Errorf("body = %q truncated=%v", r.Body, r.BodyTruncated)
	}
}

func TestFetchBinaryBody(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/bin"})
	if r.Body != "<binary 11 bytes, image/png>" || r.BodyBytes != 11 {
		t.Errorf("body = %q bytes=%d", r.Body, r.BodyBytes)
	}
}

func TestFetchPostWithBodyAndHeaders(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{
		"url": "http://pub.example/echo", "method": "post", "body": "payload",
		"headers": map[string]any{"X-Custom": "v1"},
	})
	if r.Error != "" || !strings.Contains(r.Body, `"method":"POST"`) || !strings.Contains(r.Body, `"body":"payload"`) || !strings.Contains(r.Body, `"x":"v1"`) {
		t.Errorf("result = %+v", r)
	}
	// 303 turns a POST into a GET without a body.
	r = e.fetch(t, map[string]any{"url": "http://pub.example/post-redirect", "method": "POST", "body": "payload"})
	if !strings.Contains(r.Body, `"method":"GET"`) || !strings.Contains(r.Body, `"body":""`) {
		t.Errorf("after 303: %s", r.Body)
	}
}

func TestFetchValidation(t *testing.T) {
	e := newFetchEnv(t, nil)
	for name, args := range map[string]map[string]any{
		"scheme":   {"url": "ftp://pub.example/x"},
		"file":     {"url": "file:///etc/passwd"},
		"no host":  {"url": "http:///x"},
		"relative": {"url": "/x"},
		"method":   {"url": "http://pub.example/ok", "method": "TRACE"},
	} {
		r := e.fetch(t, args)
		if r.Error == "" {
			t.Errorf("%s: expected an error, got %+v", name, r)
		}
	}
	if got := e.proxy.requests(); len(got) != 0 {
		t.Errorf("invalid requests reached the proxy: %v", got)
	}
}

func TestFetchBlocksInternalDestinations(t *testing.T) {
	e := newFetchEnv(t, nil)
	for _, u := range []string{
		"http://127.0.0.1:8080/",
		"http://localhost/",
		"http://app.localhost/",
		"http://[::1]/",
		"http://10.1.2.3/",
		"http://172.16.0.1/",
		"http://172.31.255.255/",
		"http://192.168.0.10/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::ffff:10.0.0.1]/",
		"http://[fd00::1]/",
		"http://rebind.example/",     // public name, private address
		"http://mixed.example/",      // one bad record is enough
		"http://v6internal.example/", //
		"http://mapped.example/",
		"http://metadata.example/",
	} {
		r := e.fetch(t, map[string]any{"url": u})
		if r.Error == "" || r.Status != 0 {
			t.Errorf("%s: expected refusal, got %+v", u, r)
		}
	}
	if got := e.proxy.requests(); len(got) != 0 {
		t.Errorf("refused requests reached the proxy: %v", got)
	}
}

func TestFetchAllowsPublicBoundaries(t *testing.T) {
	g := targetGuard{lookup: lookupFake}
	for _, h := range []string{"172.15.255.255", "172.32.0.1", "11.0.0.1", "192.169.0.1", "169.255.0.1", "8.8.8.8", "2606:4700::1111"} {
		u := &url.URL{Scheme: "http", Host: h}
		if strings.Contains(h, ":") {
			u.Host = "[" + h + "]"
		}
		if err := g.check(context.Background(), u, nil); err != nil {
			t.Errorf("%s should be allowed: %v", h, err)
		}
	}
}

func TestFetchDNSFailure(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://nonexistent.example/"})
	if !strings.Contains(r.Error, "DNS lookup failed") {
		t.Errorf("error = %q", r.Error)
	}
}

func TestFetchAllowlist(t *testing.T) {
	e := newFetchEnv(t, func(_ *options, fm *fakeMgmt) { fm.cfg.FetchAllowHosts = []string{"pub.example"} })

	if r := e.fetch(t, map[string]any{"url": "http://pub.example/ok"}); r.Error != "" || r.Status != 200 {
		t.Errorf("allowed host: %+v", r)
	}
	// Subdomains are included, but look-alike names are not.
	if r := e.fetch(t, map[string]any{"url": "http://sub.pub.example/ok"}); strings.Contains(r.Error, "fetch_allow_hosts") {
		t.Errorf("subdomain should pass the allowlist: %+v", r)
	}
	for _, u := range []string{"http://other.example/final", "http://notpub.example.test/", "http://xpub.example/"} {
		r := e.fetch(t, map[string]any{"url": u})
		if !strings.Contains(r.Error, "fetch_allow_hosts") {
			t.Errorf("%s: want allowlist refusal, got %+v", u, r)
		}
	}
	// A redirect out of the allowed set is refused at that hop.
	r := e.fetch(t, map[string]any{"url": "http://pub.example/redir1"})
	if !strings.Contains(r.Error, "other.example") || !strings.Contains(r.Error, "fetch_allow_hosts") {
		t.Errorf("redirect out of allowlist: %+v", r)
	}
}

func TestHostAllowed(t *testing.T) {
	for _, tc := range []struct {
		host  string
		allow []string
		want  bool
	}{
		{"anything.example", nil, true},
		{"anything.example", []string{}, true},
		{"example.com", []string{"example.com"}, true},
		{"www.example.com", []string{"example.com"}, true},
		{"a.b.example.com", []string{"example.com"}, true},
		{"EXAMPLE.com.", []string{"Example.COM"}, true},
		{"example.com", []string{"*.example.com"}, true},
		{"www.example.com", []string{".example.com"}, true},
		{"badexample.com", []string{"example.com"}, false},
		{"example.com.evil.net", []string{"example.com"}, false},
		{"example.org", []string{"example.com", "other.net"}, false},
		{"x", []string{" ", ""}, false}, // a list with only blanks never allows anything
	} {
		if got := hostAllowed(tc.host, tc.allow); got != tc.want {
			t.Errorf("hostAllowed(%q, %q) = %v, want %v", tc.host, tc.allow, got, tc.want)
		}
	}
}

func TestFetchCannotEnforceWithoutProxyConfig(t *testing.T) {
	e := newFetchEnv(t, func(o *options, _ *fakeMgmt) { o.MgmtURL = "http://127.0.0.1:1" })
	r := e.fetch(t, map[string]any{"url": "http://pub.example/ok"})
	if !strings.Contains(r.Error, "fetch_allow_hosts") || r.Status != 0 {
		t.Errorf("must fail closed when the config is unreadable: %+v", r)
	}
	if got := e.proxy.requests(); len(got) != 0 {
		t.Errorf("request went out without an allowlist check: %v", got)
	}
}

func TestFetchProxyDown(t *testing.T) {
	e := newFetchEnv(t, func(o *options, _ *fakeMgmt) { o.ProxyURL = "http://127.0.0.1:1" })
	r := e.fetch(t, map[string]any{"url": "http://pub.example/ok"})
	if !strings.Contains(r.Error, "cannot connect to the proxy") {
		t.Errorf("error = %q", r.Error)
	}
}

func TestFetchTimeout(t *testing.T) {
	e := newFetchEnv(t, func(o *options, _ *fakeMgmt) { o.fetchTimeout = 150 * time.Millisecond })
	r := e.fetch(t, map[string]any{"url": "http://pub.example/hold"})
	if !strings.Contains(r.Error, "timed out") {
		t.Errorf("error = %q", r.Error)
	}
}

func TestFetchUpstreamStatusIsNotAnError(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/five"})
	if r.Error != "" || r.Status != 502 {
		t.Errorf("a 5xx from the target is a result, not an error: %+v", r)
	}
}

func TestFetchReadOnlyMode(t *testing.T) {
	e := newFetchEnv(t, func(o *options, _ *fakeMgmt) { o.ReadOnly = true })
	if r := e.fetch(t, map[string]any{"url": "http://pub.example/ok"}); r.Error != "" || r.Body != "hello" {
		t.Errorf("GET should work read-only: %+v", r)
	}
	for _, args := range []map[string]any{
		{"url": "http://pub.example/echo", "method": "POST"},
		{"url": "http://pub.example/echo", "method": "DELETE"},
		{"url": "http://pub.example/echo", "body": "x"},
	} {
		if r := e.fetch(t, args); !strings.Contains(r.Error, "read-only") {
			t.Errorf("%v: want read-only refusal, got %+v", args, r)
		}
	}
}

func TestGetConfigIncludesFetchAllowHosts(t *testing.T) {
	e := newFetchEnv(t, func(_ *options, fm *fakeMgmt) { fm.cfg.FetchAllowHosts = []string{"a.example", "b.example"} })
	cfg := decode[config.ActiveConfig](t, call(t, e.cs, "get_config", nil))
	if !slices.Equal(cfg.FetchAllowHosts, []string{"a.example", "b.example"}) {
		t.Errorf("fetch_allow_hosts = %v", cfg.FetchAllowHosts)
	}
}

func TestNoToolChangesTheAllowlist(t *testing.T) {
	e := newFetchEnv(t, nil)
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if strings.Contains(strings.ToLower(tl.Name), "allow") {
			t.Errorf("tool %q looks like an allowlist editor", tl.Name)
		}
	}
	// And the patch type the management API accepts has no such field.
	pt := reflect.TypeOf(config.ConfigPatch{})
	for i := 0; i < pt.NumField(); i++ {
		if strings.Contains(pt.Field(i).Tag.Get("json"), "fetch_allow") {
			t.Error("ConfigPatch must not carry fetch_allow_hosts")
		}
	}
}

func TestRenderBody(t *testing.T) {
	if s, n := renderBody(nil, "", false); s != "" || n != 0 {
		t.Errorf("empty body: %q %d", s, n)
	}
	if s, _ := renderBody([]byte("{}"), "application/vnd.api+json", false); s != "{}" {
		t.Errorf("+json should be text, got %q", s)
	}
	if s, n := renderBody([]byte{0, 1, 2, 3}, "application/octet-stream", false); s != "<binary 4 bytes, application/octet-stream>" || n != 4 {
		t.Errorf("octet-stream: %q %d", s, n)
	}
	// No Content-Type: sniff.
	if s, _ := renderBody([]byte("<html><body>hi</body></html>"), "", false); !strings.HasPrefix(s, "<html>") {
		t.Errorf("sniffed html: %q", s)
	}
}

const encodedPlain = "decoded body ✓"

func serveEncoded(w http.ResponseWriter, path string) {
	var buf bytes.Buffer
	enc := strings.TrimPrefix(path, "/")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	switch enc {
	case "gz":
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte(encodedPlain))
		zw.Close()
		enc = "gzip"
	case "br":
		bw := brotli.NewWriter(&buf)
		bw.Write([]byte(encodedPlain))
		bw.Close()
	case "zstd":
		zw, _ := zstd.NewWriter(&buf)
		zw.Write([]byte(encodedPlain))
		zw.Close()
	case "deflate":
		zw := zlib.NewWriter(&buf)
		zw.Write([]byte(encodedPlain))
		zw.Close()
	case "deflate-raw":
		fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		fw.Write([]byte(encodedPlain))
		fw.Close()
		enc = "deflate"
	case "bomb":
		zw := gzip.NewWriter(&buf)
		zw.Write(bytes.Repeat([]byte("a"), 50<<20)) // 50 MB of text in a few KB
		zw.Close()
		enc = "gzip"
	case "stacked": // gzip applied after br: "br, gzip"
		var inner bytes.Buffer
		bw := brotli.NewWriter(&inner)
		bw.Write([]byte(encodedPlain))
		bw.Close()
		zw := gzip.NewWriter(&buf)
		zw.Write(inner.Bytes())
		zw.Close()
		enc = "br, gzip"
	}
	w.Header().Set("Content-Encoding", enc)
	w.Write(buf.Bytes())
}

func TestFetchDecodesEveryEncodingBrowsersAccept(t *testing.T) {
	e := newFetchEnv(t, nil)
	for _, path := range []string{"gz", "br", "zstd", "deflate", "deflate-raw", "stacked"} {
		r := e.fetch(t, map[string]any{"url": "http://pub.example/" + path})
		if r.Error != "" || r.Body != encodedPlain {
			t.Errorf("%s: body=%q error=%q", path, r.Body, r.Error)
		}
		if _, ok := r.Headers["content-encoding"]; ok {
			t.Errorf("%s: content-encoding should be dropped once decoded", path)
		}
		if r.BodyBytes != len(encodedPlain) {
			t.Errorf("%s: body_bytes = %d, want %d (decoded size)", path, r.BodyBytes, len(encodedPlain))
		}
	}
}

func TestFetchDecompressionIsBounded(t *testing.T) {
	e := newFetchEnv(t, nil)
	r := e.fetch(t, map[string]any{"url": "http://pub.example/bomb", "max_body_bytes": 1000})
	if r.Error != "" || !r.BodyTruncated || r.BodyBytes != 1000 {
		t.Errorf("a 50 MB decompressed body must be cut at max_body_bytes: %+v", r.BodyBytes)
	}
}

func TestFetchUnsupportedEncodingIsReported(t *testing.T) {
	d := &http.Response{Header: http.Header{"Content-Encoding": {"compress"}}, Body: http.NoBody}
	if _, _, _, err := decodeBody(d); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("err = %v", err)
	}
	// identity and a missing header mean the body is already plain.
	p := &http.Response{Header: http.Header{"Content-Encoding": {"identity"}}, Body: http.NoBody}
	if _, _, decoded, err := decodeBody(p); err != nil || decoded {
		t.Errorf("identity: decoded=%v err=%v", decoded, err)
	}
}

// echoedHeaders fetches the proxy's /headers route, which reports what arrived.
func (e *fetchEnv) echoedHeaders(t *testing.T, args map[string]any) map[string]string {
	t.Helper()
	args["url"] = "http://pub.example/headers"
	r := e.fetch(t, args)
	if r.Error != "" {
		t.Fatalf("fetch: %s", r.Error)
	}
	var h map[string]string
	if err := json.Unmarshal([]byte(r.Body), &h); err != nil {
		t.Fatalf("decoding %q: %v", r.Body, err)
	}
	return h
}

func TestFetchSendsTheBrowsersPageLoadHeaders(t *testing.T) {
	for _, tc := range []struct {
		preset string
		want   map[string]string
		absent []string
	}{
		{"ios", map[string]string{
			"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"accept-encoding": "gzip, deflate, br",
			"sec-fetch-site":  "none", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document",
		}, []string{"sec-ch-ua", "te", "priority"}},
		{"chrome", map[string]string{
			"accept-encoding":  "gzip, deflate, br, zstd",
			"sec-ch-ua-mobile": "?0", "upgrade-insecure-requests": "1", "priority": "u=0, i",
		}, nil},
		{"firefox", map[string]string{"te": "trailers", "accept-language": "en-US,en;q=0.5"}, []string{"sec-ch-ua"}},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			e := newFetchEnv(t, func(_ *options, fm *fakeMgmt) { fm.cfg.TLSPreset = tc.preset })
			got := e.echoedHeaders(t, map[string]any{})
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			for _, k := range tc.absent {
				if _, ok := got[k]; ok {
					t.Errorf("%s should not be sent for %s", k, tc.preset)
				}
			}
		})
	}
}

func TestFetchCallerHeadersReplaceDefaults(t *testing.T) {
	e := newFetchEnv(t, func(_ *options, fm *fakeMgmt) { fm.cfg.TLSPreset = "ios" })
	got := e.echoedHeaders(t, map[string]any{"headers": map[string]any{"accept": "application/json", "X-Extra": "1"}})
	if got["accept"] != "application/json" || got["x-extra"] != "1" || got["sec-fetch-mode"] != "navigate" {
		t.Errorf("headers = %v", got)
	}
}

func TestFetchNonNavigationMethodsGetNoPageLoadHeaders(t *testing.T) {
	e := newFetchEnv(t, func(_ *options, fm *fakeMgmt) { fm.cfg.TLSPreset = "ios" })
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		got := e.echoedHeaders(t, map[string]any{"method": method, "headers": map[string]any{"X-Extra": "1"}})
		if got["x-extra"] != "1" {
			t.Errorf("%s: caller header lost: %v", method, got)
		}
		for _, k := range []string{"sec-fetch-mode", "sec-fetch-site", "accept-language"} {
			if _, ok := got[k]; ok {
				t.Errorf("%s must not carry the page-load header %s", method, k)
			}
		}
	}
}
