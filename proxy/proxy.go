package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"impersonate-proxy/config"
	"impersonate-proxy/fp"
	"impersonate-proxy/h2fp"
	"impersonate-proxy/mitm"
	"impersonate-proxy/rewrite"
	"impersonate-proxy/upstream"
)

type Server struct {
	cfg         *config.Config
	ca          *mitm.CA
	mu          sync.RWMutex
	dialer      *fp.Dialer
	rewriter    *rewrite.Rewriter
	upstreamMgr *upstream.Manager // independent lifecycle: not rebuilt when TLS/HTTP settings change
}

func New(cfg *config.Config, ca *mitm.CA, dialer *fp.Dialer, upstreamMgr *upstream.Manager) *Server {
	return &Server{
		cfg:         cfg,
		ca:          ca,
		dialer:      dialer,
		rewriter:    rewrite.New(cfg.HTTP, upstreamMgr),
		upstreamMgr: upstreamMgr,
	}
}

// connDeps is a snapshot of the mutable per-connection dependencies taken at
// connection start so that mid-flight config updates don't affect in-progress requests.
type connDeps struct {
	dialer   *fp.Dialer
	rewriter *rewrite.Rewriter
	h2cfg    config.HTTP2Config
	preset   string
}

func (s *Server) snap() connDeps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return connDeps{
		dialer:   s.dialer,
		rewriter: s.rewriter,
		h2cfg:    s.cfg.HTTP2,
		preset:   s.cfg.TLS.Preset,
	}
}

// GetActiveConfig returns the currently active mutable settings.
func (s *Server) GetActiveConfig() config.ActiveConfig {
	s.mu.RLock()
	tls := s.cfg.TLS
	http := s.cfg.HTTP
	listen := s.cfg.Listen
	s.mu.RUnlock()

	return config.ActiveConfig{
		TLSPreset:   tls.Preset,
		CustomHello: tls.CustomHello,
		ClientIP:    http.ClientIP,
		UserAgent:   http.UserAgent,
		Listen:      listen,

		UpstreamEnabled:           s.upstreamMgr.Enabled(),
		UpstreamSelect:            s.upstreamMgr.Selection(),
		UpstreamProxies:           s.upstreamMgr.List(),
		UpstreamSuppressIPHeaders: s.upstreamMgr.SuppressIPHeaders(),
	}
}

// UpdateConfig applies a partial update to the runtime-mutable settings. A
// nil field in patch leaves that setting unchanged — this lets a caller
// flip only upstream_enabled, say, via curl without having to know (and
// resend) the current TLS preset or User-Agent.
//
// TLS preset / custom_hello and upstream enabled/select are independent
// lifecycles: the TLS dialer is only rebuilt when TLSPreset or CustomHello
// is present in the patch, and upstream changes go straight to
// upstreamMgr (which has its own locking) without touching s.dialer at
// all. New connections pick up every change immediately; in-flight
// connections are unaffected.
func (s *Server) UpdateConfig(patch config.ConfigPatch) error {
	if patch.UpstreamSelect != nil {
		// Validate before touching anything else so a bad upstream_select
		// can't partially apply the rest of the patch.
		if err := s.upstreamMgr.Select(*patch.UpstreamSelect); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newTLS := s.cfg.TLS
	tlsChanged := false
	if patch.TLSPreset != nil {
		newTLS.Preset = *patch.TLSPreset
		tlsChanged = true
	}
	if patch.CustomHello != nil {
		newTLS.CustomHello = *patch.CustomHello
		tlsChanged = true
	}

	var newDialer *fp.Dialer
	if tlsChanged {
		d, err := fp.NewDialerFromConfig(newTLS)
		if err != nil {
			return err
		}
		newDialer = d
	}

	newHTTP := s.cfg.HTTP
	if patch.ClientIP != nil {
		newHTTP.ClientIP = *patch.ClientIP
	}
	if patch.UserAgent != nil {
		newHTTP.UserAgent = *patch.UserAgent
	}

	s.cfg.TLS = newTLS
	s.cfg.HTTP = newHTTP
	if newDialer != nil {
		s.dialer = newDialer
	}
	s.rewriter = rewrite.New(s.cfg.HTTP, s.upstreamMgr)

	if patch.UpstreamEnabled != nil {
		s.upstreamMgr.SetEnabled(*patch.UpstreamEnabled)
	}

	return nil
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("listening on %s  preset=%s", s.cfg.Listen, s.cfg.TLS.Preset)
	if host, _, err := net.SplitHostPort(s.cfg.Listen); err == nil {
		ip := net.ParseIP(host)
		// Empty host means all interfaces; non-nil ip must be loopback to be safe.
		if host == "" || (ip != nil && !ip.IsLoopback()) {
			log.Printf("WARNING: proxy is listening on a non-loopback address (%s) with no authentication — ensure firewall rules restrict access", host)
		}
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	deps := s.snap()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(conn, req, deps)
	} else {
		s.handleHTTP(conn, br, req, deps)
	}
}

// handleConnect intercepts HTTPS CONNECT tunnels.
//   - Client-facing: MITM TLS with a dynamically generated leaf cert from our CA.
//   - Server-facing: uTLS with the configured fingerprint preset.
//   - Protocol branch: when the server negotiates h2 and HTTP2.Enabled is true,
//     use the h2fp transport to send custom SETTINGS/WINDOW_UPDATE/pseudo-headers.
//     Otherwise fall back to HTTP/1.1 request forwarding.
func (s *Server) handleConnect(clientConn net.Conn, req *http.Request, deps connDeps) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	cert, err := s.ca.CertForHost(host)
	if err != nil {
		log.Printf("cert(%s): %v", host, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}

	upstreamName, base := s.upstreamMgr.Current()
	ctx, cancel := context.WithTimeout(context.Background(), s.upstreamMgr.DialTimeout())
	serverConn, err := deps.dialer.Dial(ctx, base, host, addr)
	cancel()
	if err != nil {
		log.Printf("dial(%s) via upstream=%s: %v", addr, upstreamName, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer serverConn.Close()

	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	clientTLS := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client handshake(%s): %v", host, err)
		return
	}
	defer clientTLS.Close()

	log.Printf("CONNECT %s  proto=%s preset=%s upstream=%s", addr, serverConn.Proto, deps.preset, upstreamName)

	if serverConn.Proto == "h2" && deps.h2cfg.Enabled {
		s.tunnelH2(clientTLS, serverConn, host, deps)
	} else {
		s.tunnelH1(clientTLS, serverConn, deps)
	}
}

// tunnelH2 forwards HTTP requests over an HTTP/2 connection with the configured
// SETTINGS, WINDOW_UPDATE, and pseudo-header order.
func (s *Server) tunnelH2(clientTLS *tls.Conn, serverConn *fp.Conn, host string, deps connDeps) {
	h2conn, err := h2fp.Dial(serverConn, deps.h2cfg, deps.rewriter.Order())
	if err != nil {
		log.Printf("h2 dial(%s): %v", host, err)
		return
	}

	clientBR := bufio.NewReader(clientTLS)
	for {
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		deps.rewriter.Apply(req)

		resp, err := h2conn.RoundTrip(req)
		if err != nil {
			log.Printf("h2 roundtrip(%s): %v", host, err)
			return
		}
		closeAfter := req.Close
		if err := resp.Write(clientTLS); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		if closeAfter {
			return
		}
	}
}

// tunnelH1 forwards HTTP/1.1 requests, applying header rewriting and ordering.
func (s *Server) tunnelH1(clientTLS *tls.Conn, serverConn *fp.Conn, deps connDeps) {
	clientBR := bufio.NewReader(clientTLS)
	serverBR := bufio.NewReader(serverConn)
	for {
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		deps.rewriter.Apply(req)

		if err := writeRequest(req, serverConn, deps.rewriter.Order()); err != nil {
			return
		}
		resp, err := http.ReadResponse(serverBR, req)
		if err != nil {
			return
		}
		closeAfter := resp.Close || req.Close
		if err := resp.Write(clientTLS); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		if closeAfter {
			return
		}
	}
}

// handleHTTP forwards plain-HTTP proxy requests, looping to serve further
// requests pipelined over the same client connection (HTTP/1.1 keep-alive)
// until the client or origin signals Connection: close. Each request may
// target a different Host, so a fresh server connection is dialed per request.
func (s *Server) handleHTTP(clientConn net.Conn, clientBR *bufio.Reader, req *http.Request, deps connDeps) {
	for {
		host := req.Host
		if !strings.Contains(host, ":") {
			host += ":80"
		}
		_, base := s.upstreamMgr.Current()
		ctx, cancel := context.WithTimeout(context.Background(), s.upstreamMgr.DialTimeout())
		serverConn, err := base.DialContext(ctx, "tcp", host)
		cancel()
		if err != nil {
			fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}

		req.RequestURI = req.URL.RequestURI()
		for _, h := range hopByHopHeaders {
			req.Header.Del(h)
		}
		deps.rewriter.Apply(req)

		if err := writeRequest(req, serverConn, deps.rewriter.Order()); err != nil {
			serverConn.Close()
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(serverConn), req)
		if err != nil {
			serverConn.Close()
			return
		}

		log.Printf("HTTP  %s %s → %d", req.Method, req.URL, resp.StatusCode)
		closeAfter := resp.Close || req.Close
		writeErr := resp.Write(clientConn)
		resp.Body.Close()
		serverConn.Close()
		if writeErr != nil {
			return
		}
		if closeAfter {
			return
		}

		req, err = http.ReadRequest(clientBR)
		if err != nil {
			return
		}
	}
}

// writeRequest writes req to w with headers emitted in order first, then the rest.
// This controls the header order seen by the server (JA4H).
func writeRequest(req *http.Request, w io.Writer, order []string) error {
	bw := bufio.NewWriter(w)

	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", req.Method, uri)

	written := make(map[string]bool)

	emit := func(name string) {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "Host" {
			fmt.Fprintf(bw, "Host: %s\r\n", req.Host)
			written["Host"] = true
			return
		}
		vs := req.Header[canonical]
		if len(vs) == 0 {
			return
		}
		for _, v := range vs {
			fmt.Fprintf(bw, "%s: %s\r\n", canonical, v)
		}
		written[canonical] = true
	}

	for _, h := range order {
		emit(h)
	}
	if !written["Host"] {
		fmt.Fprintf(bw, "Host: %s\r\n", req.Host)
		written["Host"] = true
	}
	for k, vs := range req.Header {
		if written[k] {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(bw, "%s: %s\r\n", k, v)
		}
	}

	fmt.Fprintf(bw, "\r\n")

	if req.Body != nil && req.Body != http.NoBody {
		io.Copy(bw, req.Body)
	}

	return bw.Flush()
}

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailers", "Transfer-Encoding", "Upgrade",
}
