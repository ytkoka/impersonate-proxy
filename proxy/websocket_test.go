package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"impersonate-proxy/fp"
)

// upgradeHandler accepts a WebSocket-style upgrade, sends "welcome" in the same
// write as the 101 (so the proxy's server-side reader already holds it), then
// echoes whatever it receives.
var upgradeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketUpgrade(r) {
		http.Error(w, "upgrade required", http.StatusBadRequest)
		return
	}
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: test\r\n\r\nwelcome")
	io.Copy(conn, brw.Reader) // brw.Reader still holds anything sent with the handshake
})

func goDone(f func()) <-chan struct{} {
	ch := make(chan struct{})
	go func() { defer close(ch); f() }()
	return ch
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return after the client closed", what)
	}
}

// upgradeRequest is a handshake followed, in the same write, by bytes that
// belong to the upgraded protocol; the proxy's client-side reader will hold them.
func upgradeRequest(target, host string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\nearly"
}

// checkUpgraded runs the client side of an upgrade through the proxy and
// verifies bytes flow both ways, including those that arrived with the handshake.
func checkUpgraded(t *testing.T, client net.Conn, target, host string) {
	t.Helper()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(client)

	io.WriteString(client, upgradeRequest(target, host))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Errorf("Upgrade header = %q, want websocket", got)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "test" {
		t.Errorf("Sec-WebSocket-Accept = %q, want it passed through", got)
	}

	read := func(want string) {
		t.Helper()
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != want {
			t.Fatalf("read %q: got %q, err %v", want, buf, err)
		}
	}
	read("welcome") // sent by the server together with the 101
	read("early")   // sent by the client together with the handshake, echoed back
	io.WriteString(client, "ping")
	read("ping")
}

func TestWebSocketRelay(t *testing.T) {
	cases := []struct {
		name  string
		start func(t *testing.T) (client net.Conn, target, host string, done <-chan struct{})
	}{
		{"plain HTTP", func(t *testing.T) (net.Conn, string, string, <-chan struct{}) {
			srv := httptest.NewServer(upgradeHandler)
			t.Cleanup(srv.Close)
			host := strings.TrimPrefix(srv.URL, "http://")
			s, deps := testDeps(t)
			client, proxySide := tcpPair(t)
			done := goDone(func() {
				br := bufio.NewReader(proxySide)
				if req, err := http.ReadRequest(br); err == nil {
					s.handleHTTP(proxySide, br, req, deps)
				}
				proxySide.Close()
			})
			return client, srv.URL + "/ws", host, done
		}},
		{"tunnel HTTP/1.1", func(t *testing.T) (net.Conn, string, string, <-chan struct{}) {
			srv := httptest.NewServer(upgradeHandler)
			t.Cleanup(srv.Close)
			serverConn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { serverConn.Close() })
			s, deps := testDeps(t)
			client, proxySide := tlsPair(t)
			done := goDone(func() { s.tunnelH1(proxySide, &fp.Conn{Conn: serverConn}, deps) })
			return client, "/ws", "example.test", done
		}},
		{"tunnel HTTP/2 via separate HTTP/1.1 connection", func(t *testing.T) (net.Conn, string, string, <-chan struct{}) {
			srv := httptest.NewServer(upgradeHandler)
			t.Cleanup(srv.Close)
			h2Client, h2Side := tcpPair(t)
			go (&http2.Server{}).ServeConn(h2Side, &http2.ServeConnOpts{Handler: echoHandler})
			dialH1 := func() (*fp.Conn, error) {
				c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
				return &fp.Conn{Conn: c, Proto: "http/1.1"}, err
			}
			s, deps := testDeps(t)
			client, proxySide := tlsPair(t)
			done := goDone(func() { s.tunnelH2(proxySide, &fp.Conn{Conn: h2Client}, "example.test", deps, dialH1) })
			return client, "/ws", "example.test", done
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, target, host, done := tc.start(t)
			checkUpgraded(t, client, target, host)
			client.Close()
			waitDone(t, done, "proxy")
		})
	}
}

// An upgrade the server declines is passed on as an ordinary response, and the
// client connection stays usable for requests that go over h2 as before.
func TestTunnelH2UpgradeDeclined(t *testing.T) {
	var mu sync.Mutex
	var h2Paths []string
	h2Handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h2Paths = append(h2Paths, r.URL.Path)
		mu.Unlock()
		echoHandler(w, r)
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no upgrades here", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	h2Client, h2Side := tcpPair(t)
	go (&http2.Server{}).ServeConn(h2Side, &http2.ServeConnOpts{Handler: h2Handler})
	h1Dials := 0
	dialH1 := func() (*fp.Conn, error) {
		h1Dials++
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		return &fp.Conn{Conn: c, Proto: "http/1.1"}, err
	}
	s, deps := testDeps(t)
	client, proxySide := tlsPair(t)
	done := goDone(func() { s.tunnelH2(proxySide, &fp.Conn{Conn: h2Client}, "example.test", deps, dialH1) })

	client.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(client)
	io.WriteString(client, upgradeRequest("/ws", "example.test")[:len(upgradeRequest("/ws", "example.test"))-len("early")])
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("declined upgrade: status = %d, want 403", resp.StatusCode)
	}

	io.WriteString(client, "GET /after HTTP/1.1\r\nHost: example.test\r\n\r\n")
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("request after declined upgrade: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("follow-up status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if h1Dials != 1 {
		t.Errorf("h1 dials = %d, want 1", h1Dials)
	}
	if len(h2Paths) != 1 || h2Paths[0] != "/after" {
		t.Errorf("h2 connection saw %v, want only [/after]", h2Paths)
	}
	client.Close()
	waitDone(t, done, "tunnelH2")
}

func TestTunnelH2UpgradeDialFailure(t *testing.T) {
	h2Client, h2Side := tcpPair(t)
	go (&http2.Server{}).ServeConn(h2Side, &http2.ServeConnOpts{Handler: echoHandler})
	dialH1 := func() (*fp.Conn, error) { return nil, errors.New("boom") }
	s, deps := testDeps(t)
	client, proxySide := tlsPair(t)
	done := goDone(func() { s.tunnelH2(proxySide, &fp.Conn{Conn: h2Client}, "example.test", deps, dialH1) })

	client.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(client, upgradeRequest("/ws", "example.test"))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	waitDone(t, done, "tunnelH2")
}

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name string
		hdr  http.Header
		want bool
	}{
		{"browser handshake", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, true},
		{"mixed case", http.Header{"Connection": {"upgrade"}, "Upgrade": {"WebSocket"}}, true},
		{"token list (Firefox)", http.Header{"Connection": {"keep-alive, Upgrade"}, "Upgrade": {"websocket"}}, true},
		{"repeated Connection", http.Header{"Connection": {"keep-alive", "Upgrade"}, "Upgrade": {"websocket"}}, true},
		{"no headers", http.Header{}, false},
		{"Upgrade without Connection", http.Header{"Upgrade": {"websocket"}}, false},
		{"Connection without Upgrade", http.Header{"Connection": {"Upgrade"}}, false},
		{"other protocol", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"h2c"}}, false},
		{"keep-alive only", http.Header{"Connection": {"keep-alive"}, "Upgrade": {"websocket"}}, false},
		{"substring is not a token", http.Header{"Connection": {"upgraded"}, "Upgrade": {"websocket"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWebSocketUpgrade(&http.Request{Header: tc.hdr}); got != tc.want {
				t.Errorf("isWebSocketUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

// Without an upgrade, the plain-HTTP path must keep stripping hop-by-hop
// headers exactly as before.
func TestHandleHTTPStripsHopByHopWithoutUpgrade(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	s, deps := testDeps(t)
	client, proxySide := tcpPair(t)
	done := goDone(func() {
		br := bufio.NewReader(proxySide)
		if req, err := http.ReadRequest(br); err == nil {
			s.handleHTTP(proxySide, br, req, deps)
		}
		proxySide.Close()
	})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(client, "GET "+srv.URL+"/ HTTP/1.1\r\nHost: "+strings.TrimPrefix(srv.URL, "http://")+
		"\r\nConnection: close, X-Hop\r\nUpgrade: h2c\r\nX-Hop: 1\r\nKeep-Alive: 5\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	waitDone(t, done, "handleHTTP")
	if v := got.Get("Upgrade"); v != "" {
		t.Errorf("server saw Upgrade %q, want it stripped", v)
	}
	if v := got.Get("Keep-Alive"); v != "" {
		t.Errorf("server saw Keep-Alive %q, want it stripped", v)
	}
}
