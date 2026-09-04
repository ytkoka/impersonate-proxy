package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mustListen opens a loopback TCP listener for a test double server.
func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// acceptOnce accepts a single connection and closes it immediately — used
// by tests that only care that DialContext can complete a TCP handshake.
func acceptOnce(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	conn.Close()
}

// fakeConnectProxy is a minimal HTTP CONNECT proxy test double: it reads a
// CONNECT request, replies with the given status line, and — if the status
// is 200 — writes payload immediately after the blank line in the *same*
// write, so a test can catch a dialer that reads too far into the response
// and swallows bytes belonging to the tunneled connection.
func fakeConnectProxy(t *testing.T, ln net.Listener, status string, payload []byte, wantAuth string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		t.Errorf("accept: %v", err)
		return
	}
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		t.Errorf("read CONNECT request: %v", err)
		return
	}
	if req.Method != http.MethodConnect {
		t.Errorf("method = %s, want CONNECT", req.Method)
	}
	if wantAuth != "" && req.Header.Get("Proxy-Authorization") != wantAuth {
		t.Errorf("Proxy-Authorization = %q, want %q", req.Header.Get("Proxy-Authorization"), wantAuth)
	}

	// br may have buffered bytes past the request line/headers if the
	// client pipelined anything — for CONNECT there shouldn't be any, but
	// drain nothing further here; we only wrote the request ourselves.
	resp := status + "\r\n\r\n"
	buf := append([]byte(resp), payload...)
	if _, err := conn.Write(buf); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func TestConnectProxyDialer_success(t *testing.T) {
	ln := mustListen(t)
	defer ln.Close()

	payload := []byte("hello-through-tunnel")
	go fakeConnectProxy(t, ln, "HTTP/1.1 200 Connection Established", payload, "")

	d := newConnectProxyDialer(ln.Addr().String(), "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// This is the over-read regression check: the 1-byte-buffered reader
	// used to parse the CONNECT response must not have consumed any of the
	// payload that immediately follows the blank line. If it did, this
	// read would come back short or empty.
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read payload after CONNECT: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q (bytes were lost to bufio over-read)", got, payload)
	}
}

func TestConnectProxyDialer_sendsBasicAuth(t *testing.T) {
	ln := mustListen(t)
	defer ln.Close()

	go fakeConnectProxy(t, ln, "HTTP/1.1 200 Connection Established", nil, "Basic dXNlcjpodW50ZXIy")

	d := newConnectProxyDialer(ln.Addr().String(), "user", "hunter2")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
}

func TestConnectProxyDialer_nonOKStatusIsError(t *testing.T) {
	ln := mustListen(t)
	defer ln.Close()

	go fakeConnectProxy(t, ln, "HTTP/1.1 407 Proxy Authentication Required", nil, "")

	d := newConnectProxyDialer(ln.Addr().String(), "user", "wrongpass")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error for non-200 CONNECT response, got nil")
	}
	if strings.Contains(err.Error(), "wrongpass") {
		t.Errorf("error leaked the password: %v", err)
	}
}
