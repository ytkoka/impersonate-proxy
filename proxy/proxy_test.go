package proxy

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"impersonate-proxy/config"
	"impersonate-proxy/fp"
	"impersonate-proxy/rewrite"
	"impersonate-proxy/upstream"
)

// echoHandler reports how the request arrived at the server and echoes its body.
var echoHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Got-TE", strings.Join(r.TransferEncoding, ","))
	w.Header().Set("X-Got-Expect", r.Header.Get("Expect"))
	w.Write(body)
})

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// tlsPair returns a handshaked client side and the proxy-facing server side.
func tlsPair(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, b := tcpPair(t)
	client := tls.Client(a, &tls.Config{InsecureSkipVerify: true})
	server := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	return client, server
}

func testDeps(t *testing.T) (*Server, connDeps) {
	t.Helper()
	mgr, err := upstream.New(config.UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s := New(&config.Config{}, nil, nil, mgr)
	return s, connDeps{
		rewriter: rewrite.New(config.HTTPConfig{}, mgr),
		h2cfg:    config.HTTP2Config{Enabled: true, PseudoHeaderOrder: []string{"method", "authority", "scheme", "path"}},
	}
}

// Every forwarding path must deliver a chunked body intact, answer Expect
// itself, and leave the connection usable for a following request.
func TestChunkedBodyWithExpect(t *testing.T) {
	cases := []struct {
		name   string
		wantTE string
		start  func(t *testing.T) (client net.Conn, target string)
	}{
		{"plain HTTP", "chunked", func(t *testing.T) (net.Conn, string) {
			srv := httptest.NewServer(echoHandler)
			t.Cleanup(srv.Close)
			s, deps := testDeps(t)
			client, proxySide := tcpPair(t)
			go func() {
				br := bufio.NewReader(proxySide)
				req, err := http.ReadRequest(br)
				if err == nil {
					s.handleHTTP(proxySide, br, req, deps)
				}
				proxySide.Close()
			}()
			return client, srv.URL + "/"
		}},
		{"tunnel HTTP/1.1", "chunked", func(t *testing.T) (net.Conn, string) {
			srv := httptest.NewServer(echoHandler)
			t.Cleanup(srv.Close)
			addr := strings.TrimPrefix(srv.URL, "http://")
			serverConn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { serverConn.Close() })
			s, deps := testDeps(t)
			client, proxySide := tlsPair(t)
			go s.tunnelH1(proxySide, &fp.Conn{Conn: serverConn}, deps)
			return client, "/"
		}},
		{"tunnel HTTP/2", "", func(t *testing.T) (net.Conn, string) {
			serverConn, h2Side := tcpPair(t)
			go (&http2.Server{}).ServeConn(h2Side, &http2.ServeConnOpts{Handler: echoHandler})
			s, deps := testDeps(t)
			client, proxySide := tlsPair(t)
			go s.tunnelH2(proxySide, &fp.Conn{Conn: serverConn}, "example.test", deps, nil)
			return client, "/"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, target := tc.start(t)
			client.SetDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReader(client)

			io.WriteString(client, "POST "+target+" HTTP/1.1\r\nHost: example.test\r\n"+
				"Expect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n")
			interim, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("read interim response: %v", err)
			}
			if interim.StatusCode != http.StatusContinue {
				t.Fatalf("interim status = %d, want 100", interim.StatusCode)
			}

			io.WriteString(client, "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("read final response: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || string(body) != "hello world" {
				t.Errorf("got %d %q, want 200 %q", resp.StatusCode, body, "hello world")
			}
			if got := resp.Header.Get("X-Got-TE"); got != tc.wantTE {
				t.Errorf("server saw Transfer-Encoding %q, want %q", got, tc.wantTE)
			}
			if got := resp.Header.Get("X-Got-Expect"); got != "" {
				t.Errorf("server saw Expect %q, want none", got)
			}

			// A body with broken framing would desync this second request.
			io.WriteString(client, "GET "+target+" HTTP/1.1\r\nHost: example.test\r\n\r\n")
			resp, err = http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("read second response: %v", err)
			}
			body, _ = io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || len(body) != 0 {
				t.Errorf("second request: got %d %q, want 200 with empty body", resp.StatusCode, body)
			}
		})
	}
}

func chunkedRequest(body io.ReadCloser) *http.Request {
	return &http.Request{
		Method:           http.MethodPost,
		URL:              &url.URL{Path: "/"},
		Host:             "example.test",
		Header:           http.Header{"Accept": {"*/*"}},
		Body:             body,
		TransferEncoding: []string{"chunked"},
	}
}

func TestWriteRequestChunkedHeaderOrder(t *testing.T) {
	var out bytes.Buffer
	req := chunkedRequest(io.NopCloser(strings.NewReader("hi")))
	if err := writeRequest(req, &out, []string{"Host", "Transfer-Encoding", "Accept"}); err != nil {
		t.Fatal(err)
	}
	want := "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nAccept: */*\r\n\r\n2\r\nhi\r\n0\r\n\r\n"
	if got := out.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriteRequestChunkedEmptyBody(t *testing.T) {
	var out bytes.Buffer
	if err := writeRequest(chunkedRequest(http.NoBody), &out, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "\r\n\r\n0\r\n\r\n") {
		t.Errorf("missing terminating chunk: %q", out.String())
	}
}

func TestWriteRequestChunkedStreams(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	server, proxySide := net.Pipe()
	defer server.Close()
	defer proxySide.Close()
	go writeRequest(chunkedRequest(pr), proxySide, nil)
	go pw.Write([]byte("first"))

	// The body is still open, so "first" arriving proves it wasn't held back.
	server.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(server)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("first chunk not delivered while body is open: %v", err)
		}
		if line == "first\r\n" {
			return
		}
	}
}

func TestWriteRequestChunkedBodyErrorWithholdsTerminator(t *testing.T) {
	boom := errors.New("client went away")
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("partial"))
		pw.CloseWithError(boom)
	}()
	var out bytes.Buffer
	err := writeRequest(chunkedRequest(pr), &out, nil)
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
	if strings.Contains(out.String(), "0\r\n\r\n") {
		t.Errorf("truncated body was terminated: %q", out.String())
	}
}

func TestReadFinalResponseRelaysInformational(t *testing.T) {
	upstream := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/", nil)
	var client bytes.Buffer
	resp, err := readFinalResponse(bufio.NewReader(strings.NewReader(upstream)), req, &client)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	want := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n"
	if got := client.String(); got != want {
		t.Errorf("relayed %q, want %q", got, want)
	}
}

func TestHandleExpect(t *testing.T) {
	cases := []struct {
		expect     string
		body       io.ReadCloser
		wantExpect string
		wantWrite  string
	}{
		{"100-continue", io.NopCloser(strings.NewReader("x")), "", "HTTP/1.1 100 Continue\r\n\r\n"},
		{"100-Continue", io.NopCloser(strings.NewReader("x")), "", "HTTP/1.1 100 Continue\r\n\r\n"},
		{"100-continue", http.NoBody, "", ""},
		{"something-else", io.NopCloser(strings.NewReader("x")), "something-else", ""},
	}
	for _, tc := range cases {
		req := &http.Request{Header: http.Header{"Expect": {tc.expect}}, Body: tc.body}
		var client bytes.Buffer
		if err := handleExpect(req, &client); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("Expect"); got != tc.wantExpect {
			t.Errorf("%q: Expect = %q, want %q", tc.expect, got, tc.wantExpect)
		}
		if client.String() != tc.wantWrite {
			t.Errorf("%q: wrote %q, want %q", tc.expect, client.String(), tc.wantWrite)
		}
	}
}
