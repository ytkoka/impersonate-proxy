// Package upstream routes outbound (proxy → target) connections through an
// optional upstream SOCKS5 or HTTP CONNECT proxy. Only tunnel-capable
// schemes are supported: both hand back a raw net.Conn to the target that
// the caller then wraps with uTLS itself, so the fingerprinting layers in
// fp/ and h2fp/ never see (and can't be broken by) the upstream hop.
package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// BaseDialer returns a raw, unencrypted net.Conn to addr. It is the thing
// that gets wrapped with uTLS afterwards — implementations must not speak
// TLS themselves (that would defeat the fingerprinting this proxy exists
// to control).
type BaseDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DirectDialer dials the target directly, with no upstream proxy. It is the
// same net.Dialer{} behavior the proxy always used before this feature.
type DirectDialer struct{}

func (DirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// connectProxyDialer tunnels through an upstream HTTP proxy via the CONNECT
// method (RFC 7231 §4.3.6). It never terminates TLS itself: after the proxy
// answers 200, the raw connection is handed back as-is for the caller to
// wrap with uTLS.
type connectProxyDialer struct {
	proxyAddr string // host:port of the upstream proxy
	authValue string // pre-built "Basic <base64>", or "" if no auth
}

func newConnectProxyDialer(proxyAddr, user, pass string) *connectProxyDialer {
	d := &connectProxyDialer{proxyAddr: proxyAddr}
	if user != "" || pass != "" {
		d.authValue = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	return d
}

func (d *connectProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	var reqBuf bufio.Writer
	reqBuf.Reset(conn)
	fmt.Fprintf(&reqBuf, "CONNECT %s HTTP/1.1\r\n", addr)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", addr)
	if d.authValue != "" {
		fmt.Fprintf(&reqBuf, "Proxy-Authorization: %s\r\n", d.authValue)
	}
	io.WriteString(&reqBuf, "\r\n")
	if err := reqBuf.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	// bufio.Reader's default (and minimum: bufio enforces >=16 bytes even
	// if a smaller size is requested) internal buffer will almost always
	// read past the blank line that ends the CONNECT response headers and
	// into whatever the upstream proxy or target sent right after —
	// potentially the first bytes of our own uTLS ClientHello response.
	// Rather than trying to avoid that read-ahead, we keep br and route
	// every subsequent read through it via bufConn, so nothing is lost.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT failed: %s", resp.Status)
	}

	return &bufConn{Conn: conn, br: br}, nil
}

// bufConn is a net.Conn whose reads are served from a *bufio.Reader that
// was used to parse the CONNECT response, so any bytes it read ahead past
// the blank line (bufio's minimum internal buffer is 16 bytes, well past
// a typical "HTTP/1.1 200 ...\r\n\r\n") are still delivered to the caller
// instead of being silently dropped.
type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.br.Read(p)
}
