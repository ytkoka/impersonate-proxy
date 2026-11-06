package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"impersonate-proxy/config"
	"impersonate-proxy/filter"
	"impersonate-proxy/rewrite"
	"impersonate-proxy/upstream"
)

func mustFilter(t *testing.T, mode string, hosts ...string) *filter.Matcher {
	t.Helper()
	m, err := filter.New(mode, hosts)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// tcpServer runs handle for every accepted connection and returns its address.
func tcpServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().String()
}

// startConnect runs handleConnect for a client that sends "CONNECT target" plus
// extra in a single write (so extra ends up in the proxy's read buffer) and
// returns the client side after the proxy's status line was read.
func startConnect(t *testing.T, s *Server, deps connDeps, target, extra string) (net.Conn, *bufio.Reader, string, <-chan struct{}) {
	t.Helper()
	client, proxySide := tcpPair(t)
	done := goDone(func() {
		br := bufio.NewReader(proxySide)
		if req, err := http.ReadRequest(br); err == nil {
			s.handleConnect(proxySide, br, req, deps)
		}
		proxySide.Close()
	})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"+extra)
	br := bufio.NewReader(client)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	return client, br, strings.TrimSpace(status), done
}

// drainHead consumes the blank line that ends a 200 response's head.
func drainHead(t *testing.T, br *bufio.Reader) {
	t.Helper()
	if line, _ := br.ReadString('\n'); line != "\r\n" {
		t.Fatalf("unexpected response head line %q", line)
	}
}

func echoServer(t *testing.T) string {
	return tcpServer(t, func(c net.Conn) { io.Copy(c, c) })
}

func TestPassthroughConnect(t *testing.T) {
	addr := echoServer(t)
	s, deps := testDeps(t)
	deps.filter = mustFilter(t, "include", "other.test") // the echo server is not a target

	client, br, status, done := startConnect(t, s, deps, addr, "early")
	if status != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status = %q", status)
	}
	drainHead(t, br)
	// "early" was sent right behind the CONNECT and sits in the proxy's buffer.
	for _, want := range []string{"early", "ping"} {
		if want == "ping" {
			io.WriteString(client, "ping")
		}
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != want {
			t.Fatalf("read %q: got %q, err %v", want, buf, err)
		}
	}
	client.Close()
	waitDone(t, done, "handleConnect")
}

// A client that shuts down its sending side must still get the reply: this is
// what separates the raw relay from the upgrade relay, which stops at the
// first closed direction.
func TestPassthroughHalfClose(t *testing.T) {
	addr := tcpServer(t, func(c net.Conn) {
		got, _ := io.ReadAll(c) // until the client's EOF
		io.WriteString(c, "bye:"+string(got))
	})
	s, deps := testDeps(t)
	deps.filter = mustFilter(t, "exclude", "127.0.0.1")

	client, br, _, done := startConnect(t, s, deps, addr, "")
	drainHead(t, br)
	io.WriteString(client, "hi")
	client.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(br)
	if err != nil || string(reply) != "bye:hi" {
		t.Fatalf("reply = %q, err %v; want %q", reply, err, "bye:hi")
	}
	waitDone(t, done, "handleConnect")
}

func TestPassthroughDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close() // nothing listens here any more

	s, deps := testDeps(t)
	deps.filter = mustFilter(t, "include", "other.test")
	client, _, status, done := startConnect(t, s, deps, dead, "")
	if status != "HTTP/1.1 502 Bad Gateway" {
		t.Errorf("status = %q, want 502", status)
	}
	client.Close()
	waitDone(t, done, "handleConnect")
}

// Passthrough still honours the upstream proxy: the connection must reach the
// target through it, not directly.
func TestPassthroughUsesUpstream(t *testing.T) {
	target := echoServer(t)

	var mu sync.Mutex
	var connects []string
	upstreamAddr := tcpServer(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		mu.Lock()
		connects = append(connects, req.Host)
		mu.Unlock()
		backend, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer backend.Close()
		io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		go io.Copy(backend, br)
		io.Copy(c, backend)
	})

	mgr, err := upstream.New(config.UpstreamConfig{
		Enabled: true,
		Proxies: []config.UpstreamProxy{{Name: "test", URL: "http://" + upstreamAddr}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&config.Config{}, nil, nil, mgr)
	if err != nil {
		t.Fatal(err)
	}
	deps := connDeps{
		rewriter: rewrite.New(config.HTTPConfig{}, mgr),
		filter:   mustFilter(t, "include", "other.test"),
	}

	client, br, status, done := startConnect(t, s, deps, target, "")
	if status != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status = %q", status)
	}
	drainHead(t, br)
	io.WriteString(client, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through upstream: got %q, err %v", buf, err)
	}
	client.Close()
	waitDone(t, done, "handleConnect")

	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(connects, []string{target}) {
		t.Errorf("upstream saw CONNECT %v, want [%s]", connects, target)
	}
}

// For plain HTTP the filter is applied per request, because one client
// connection can carry requests for several hosts. Impersonated hosts get the
// configured header rewriting; the others are forwarded as they are.
func TestHandleHTTPFilterPerRequest(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Clone()
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	mgr, err := upstream.New(config.UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&config.Config{}, nil, nil, mgr)
	if err != nil {
		t.Fatal(err)
	}
	deps := connDeps{
		rewriter: rewrite.New(config.HTTPConfig{
			UserAgent:  "impersonated-ua",
			AddHeaders: map[string]string{"X-Impersonated": "1"},
		}, mgr),
		filter: mustFilter(t, "include", "127.0.0.1"),
	}

	client, proxySide := tcpPair(t)
	done := goDone(func() {
		br := bufio.NewReader(proxySide)
		if req, err := http.ReadRequest(br); err == nil {
			s.handleHTTP(proxySide, br, req, deps)
		}
		proxySide.Close()
	})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(client)
	get := func(host, path string) {
		t.Helper()
		io.WriteString(client, "GET http://"+host+":"+port+path+" HTTP/1.1\r\nHost: "+host+":"+port+
			"\r\nUser-Agent: original-ua\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
	}
	get("127.0.0.1", "/target")  // on the list
	get("localhost", "/other")   // same server, but not on the list
	get("127.0.0.1", "/target2") // the connection is still usable afterwards
	client.Close()
	waitDone(t, done, "handleHTTP")

	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/target", "/target2"} {
		if h := seen[p]; h.Get("X-Impersonated") != "1" || h.Get("User-Agent") != "impersonated-ua" {
			t.Errorf("%s: impersonated host got headers %v, want rewriting applied", p, h)
		}
	}
	if h := seen["/other"]; h == nil || h.Get("X-Impersonated") != "" || h.Get("User-Agent") != "original-ua" {
		t.Errorf("/other: non-target host got headers %v, want them untouched", h)
	}
}

func TestUpdateConfigFilter(t *testing.T) {
	s, _ := testDeps(t)
	if got := s.GetActiveConfig(); got.FilterMode != "off" || len(got.FilterHosts) != 0 {
		t.Fatalf("initial filter = %q %v, want off and no hosts", got.FilterMode, got.FilterHosts)
	}
	impersonated := func(host string) bool { return s.snap().filter.Impersonate(host) }

	str := func(v string) *string { return &v }
	hosts := func(v ...string) *[]string { return &v }

	// Partial updates: each field alone leaves the other as it was.
	if err := s.UpdateConfig(config.ConfigPatch{FilterHosts: hosts("a.test", "*.b.test")}); err != nil {
		t.Fatal(err)
	}
	if !impersonated("c.test") {
		t.Error("changing only hosts must not change the mode (still off)")
	}
	if err := s.UpdateConfig(config.ConfigPatch{FilterMode: str("include")}); err != nil {
		t.Fatal(err)
	}
	got := s.GetActiveConfig()
	if got.FilterMode != "include" || !slices.Equal(got.FilterHosts, []string{"a.test", "*.b.test"}) {
		t.Fatalf("filter = %q %v", got.FilterMode, got.FilterHosts)
	}
	if !impersonated("a.test") || !impersonated("x.b.test:443") || impersonated("c.test") || impersonated("b.test") {
		t.Error("include list not applied as configured")
	}

	// A rejected patch changes nothing, including its otherwise valid parts.
	for _, bad := range []config.ConfigPatch{
		{FilterMode: str("bogus")},
		{FilterHosts: hosts("foo.*")},
		{FilterMode: str("exclude"), FilterHosts: hosts("ok.test", "example.com:443"), ClientIP: str("203.0.113.9")},
	} {
		if err := s.UpdateConfig(bad); err == nil {
			t.Errorf("UpdateConfig(%+v) succeeded, want an error", bad)
		}
	}
	got = s.GetActiveConfig()
	if got.FilterMode != "include" || !slices.Equal(got.FilterHosts, []string{"a.test", "*.b.test"}) || got.ClientIP != "" {
		t.Errorf("rejected patches changed state: %+v", got)
	}

	// The reported host list is a copy.
	got.FilterHosts[0] = "mutated.test"
	if !impersonated("a.test") || s.GetActiveConfig().FilterHosts[0] != "a.test" {
		t.Error("mutating GetActiveConfig's result leaked into the server")
	}

	// An explicit empty list clears it.
	if err := s.UpdateConfig(config.ConfigPatch{FilterHosts: hosts()}); err != nil {
		t.Fatal(err)
	}
	if impersonated("a.test") {
		t.Error("include with an emptied list should impersonate nothing")
	}
}

func TestNewRejectsInvalidFilterConfig(t *testing.T) {
	mgr, err := upstream.New(config.UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Filter: config.FilterConfig{Mode: "include", Hosts: []string{"*"}}}
	if _, err := New(cfg, nil, nil, mgr); err == nil {
		t.Error("New accepted an invalid filter pattern")
	}
}
