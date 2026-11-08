package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"sync"

	"impersonate-proxy/config"
	"impersonate-proxy/filter"
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
	filter      *filter.Matcher   // which hosts get impersonated; nil means all
	upstreamMgr *upstream.Manager // independent lifecycle: not rebuilt when TLS/HTTP settings change
}

// New builds a Server. It fails if cfg.Filter is invalid.
func New(cfg *config.Config, ca *mitm.CA, dialer *fp.Dialer, upstreamMgr *upstream.Manager) (*Server, error) {
	f, err := filter.New(cfg.Filter.Mode, cfg.Filter.Hosts)
	if err != nil {
		return nil, fmt.Errorf("filter config: %w", err)
	}
	cfg.Filter.Mode = f.Mode()
	return &Server{
		cfg:         cfg,
		ca:          ca,
		dialer:      dialer,
		rewriter:    rewrite.New(cfg.HTTP, upstreamMgr),
		filter:      f,
		upstreamMgr: upstreamMgr,
	}, nil
}

// connDeps is a snapshot of the mutable per-connection dependencies taken at
// connection start so that mid-flight config updates don't affect in-progress requests.
type connDeps struct {
	dialer   *fp.Dialer
	rewriter *rewrite.Rewriter
	filter   *filter.Matcher
	h2cfg    config.HTTP2Config
	preset   string
}

func (s *Server) snap() connDeps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return connDeps{
		dialer:   s.dialer,
		rewriter: s.rewriter,
		filter:   s.filter,
		h2cfg:    h2fp.Resolve(s.cfg.TLS.Preset, s.cfg.HTTP2),
		preset:   s.cfg.TLS.Preset,
	}
}

// GetActiveConfig returns the currently active mutable settings.
func (s *Server) GetActiveConfig() config.ActiveConfig {
	s.mu.RLock()
	tls := s.cfg.TLS
	http := s.cfg.HTTP
	listen := s.cfg.Listen
	flt := s.cfg.Filter
	fetchAllow := s.cfg.FetchAllowHosts
	h2 := h2fp.Resolve(s.cfg.TLS.Preset, s.cfg.HTTP2)
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

		FilterMode:  flt.Mode,
		FilterHosts: slices.Clone(flt.Hosts),

		FetchAllowHosts: slices.Clone(fetchAllow),

		HTTP2Fingerprint: h2fp.Fingerprint(h2),
	}
}

// UpdateConfig applies a partial update to the runtime-mutable settings. A
// nil field in patch leaves that setting unchanged — this lets a caller
// flip only upstream_enabled, say, via curl without having to know (and
// resend) the current TLS preset or User-Agent.
//
// TLS preset / custom_hello, the host filter and upstream enabled/select are
// independent lifecycles: the TLS dialer is only rebuilt when TLSPreset or
// CustomHello is present in the patch, the filter only when a filter field is,
// and upstream changes go straight to upstreamMgr (which has its own locking)
// without touching s.dialer at all. New connections pick up every change
// immediately; in-flight connections are unaffected.
//
// Everything that can fail (TLS dialer, filter, upstream_select) is checked
// before anything is applied, and upstream_select — the one step that takes
// effect on its own — runs last, so a rejected patch changes nothing.
func (s *Server) UpdateConfig(patch config.ConfigPatch) error {
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

	newFilterCfg := s.cfg.Filter
	var newFilter *filter.Matcher
	filterChanged := patch.FilterMode != nil || patch.FilterHosts != nil
	if filterChanged {
		if patch.FilterMode != nil {
			newFilterCfg.Mode = *patch.FilterMode
		}
		if patch.FilterHosts != nil {
			newFilterCfg.Hosts = slices.Clone(*patch.FilterHosts)
		}
		f, err := filter.New(newFilterCfg.Mode, newFilterCfg.Hosts)
		if err != nil {
			return err
		}
		newFilter = f
		newFilterCfg.Mode = f.Mode()
	}

	if patch.UpstreamSelect != nil {
		if err := s.upstreamMgr.Select(*patch.UpstreamSelect); err != nil {
			return err
		}
	}

	s.cfg.TLS = newTLS
	s.cfg.HTTP = newHTTP
	if newDialer != nil {
		s.dialer = newDialer
	}
	if filterChanged {
		s.cfg.Filter = newFilterCfg
		s.filter = newFilter
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
		s.handleConnect(conn, br, req, deps)
	} else {
		s.handleHTTP(conn, br, req, deps)
	}
}

// handleConnect intercepts HTTPS CONNECT tunnels. Hosts the filter excludes
// from impersonation are tunnelled through untouched instead (see passthrough).
//   - Client-facing: MITM TLS with a dynamically generated leaf cert from our CA.
//   - Server-facing: uTLS with the configured fingerprint preset.
//   - Protocol branch: when the server negotiates h2 and HTTP2.Enabled is true,
//     use the h2fp transport to send custom SETTINGS/WINDOW_UPDATE/pseudo-headers.
//     Otherwise fall back to HTTP/1.1 request forwarding.
func (s *Server) handleConnect(clientConn net.Conn, clientBR *bufio.Reader, req *http.Request, deps connDeps) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	// Decided before a certificate is minted or a ClientHello is built: a host
	// that is not impersonated needs neither, and the client keeps seeing the
	// origin's real certificate.
	if !deps.filter.Impersonate(host) {
		s.passthrough(clientConn, clientBR, addr)
		return
	}

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
		// WebSocket needs HTTP/1.1, which this h2 connection cannot provide, so
		// the h2 tunnel opens a second, h1-only connection when one is asked for.
		dialH1 := func() (*fp.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), s.upstreamMgr.DialTimeout())
			defer cancel()
			return deps.dialer.DialH1(ctx, base, host, addr)
		}
		s.tunnelH2(clientTLS, serverConn, host, deps, dialH1)
	} else {
		s.tunnelH1(clientTLS, serverConn, deps)
	}
}

// passthrough answers a CONNECT by relaying raw bytes between the client and
// the target, without terminating TLS: no certificate is presented, headers are
// not rewritten, and the client's own TLS fingerprint reaches the server. The
// connection still goes out through the current upstream proxy, if one is
// enabled. clientR is the reader the CONNECT request was parsed from, in case
// the client already sent bytes after it. Works for non-TLS targets too.
func (s *Server) passthrough(clientConn net.Conn, clientR io.Reader, addr string) {
	upstreamName, base := s.upstreamMgr.Current()
	ctx, cancel := context.WithTimeout(context.Background(), s.upstreamMgr.DialTimeout())
	serverConn, err := base.DialContext(ctx, "tcp", addr)
	cancel()
	if err != nil {
		log.Printf("dial(%s) via upstream=%s: %v", addr, upstreamName, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer serverConn.Close()

	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	log.Printf("PASSTHROUGH %s  upstream=%s", addr, upstreamName)
	relayRaw(clientConn, clientR, serverConn)
}

// relayRaw copies bytes both ways until both directions have finished. When one
// direction ends, the write side of its destination is closed so the peer sees
// EOF while data may still flow the other way (a client that shuts down its
// send side must still receive the reply). Unlike relayUpgraded, which ends at
// the first closed direction, this must not truncate a response.
func relayRaw(client net.Conn, clientR io.Reader, server net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst net.Conn, src io.Reader) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(server, clientR)
	go pipe(client, server)
	<-done
	<-done
}

// tunnelH2 forwards HTTP requests over an HTTP/2 connection with the configured
// SETTINGS, WINDOW_UPDATE, and pseudo-header order. Requests are plain h2
// except WebSocket upgrades, which go over a separate HTTP/1.1 connection from
// dialH1 (nil disables that, leaving upgrades to h2 where they are dropped).
func (s *Server) tunnelH2(clientTLS *tls.Conn, serverConn *fp.Conn, host string, deps connDeps, dialH1 h1Dialer) {
	h2conn, err := h2fp.Dial(serverConn, deps.h2cfg)
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
		if err := handleExpect(req, clientTLS); err != nil {
			return
		}
		deps.rewriter.Apply(req, deps.preset)

		if dialH1 != nil && isWebSocketUpgrade(req) {
			h1Conn, err := dialH1()
			if err != nil {
				log.Printf("h1 dial for upgrade(%s): %v", host, err)
				fmt.Fprintf(clientTLS, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
				return
			}
			log.Printf("UPGRADE %s %s  proto=http/1.1 (separate connection)", host, req.URL.RequestURI())
			if !upgradeOverH1(clientTLS, clientBR, h1Conn, req, deps.rewriter.Order()) {
				return
			}
			continue
		}

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
		if err := handleExpect(req, clientTLS); err != nil {
			return
		}
		deps.rewriter.Apply(req, deps.preset)

		if err := writeRequest(req, serverConn, deps.rewriter.Order()); err != nil {
			return
		}
		resp, err := readFinalResponse(serverBR, req, clientTLS)
		if err != nil {
			return
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			relayUpgraded(clientTLS, clientBR, serverConn, serverBR, resp)
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
		// A WebSocket handshake is meaningless without Connection/Upgrade.
		isUpgrade := isWebSocketUpgrade(req)
		for _, h := range hopByHopHeaders {
			if isUpgrade && (h == "Connection" || h == "Upgrade") {
				continue
			}
			req.Header.Del(h)
		}
		if err := handleExpect(req, clientConn); err != nil {
			serverConn.Close()
			return
		}
		// Hosts outside the filter are forwarded as they are: no header
		// rewriting and no configured header order. Each request is judged on
		// its own because one client connection may carry requests for several hosts.
		order := deps.rewriter.Order()
		if deps.filter.Impersonate(req.Host) {
			deps.rewriter.Apply(req, deps.preset)
		} else {
			order = nil
		}

		if err := writeRequest(req, serverConn, order); err != nil {
			serverConn.Close()
			return
		}
		serverBR := bufio.NewReader(serverConn)
		resp, err := readFinalResponse(serverBR, req, clientConn)
		if err != nil {
			serverConn.Close()
			return
		}

		log.Printf("HTTP  %s %s → %d", req.Method, req.URL, resp.StatusCode)
		if resp.StatusCode == http.StatusSwitchingProtocols {
			relayUpgraded(clientConn, clientBR, serverConn, serverBR, resp)
			return
		}
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

// h1Dialer opens a fresh upstream connection that speaks only HTTP/1.1.
type h1Dialer func() (*fp.Conn, error)

// isWebSocketUpgrade reports whether req asks to switch to the WebSocket protocol.
func isWebSocketUpgrade(req *http.Request) bool {
	return headerHasToken(req.Header, "Connection", "upgrade") &&
		headerHasToken(req.Header, "Upgrade", "websocket")
}

// headerHasToken reports whether any value of the named comma-separated header
// contains token (case-insensitive).
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// upgradeOverH1 sends the upgrade request req over serverConn (closed on
// return) and relays the result to the client. It reports whether the client
// connection can carry on with further requests: false once the connection was
// taken over by an upgraded protocol, or on any error or Connection: close.
func upgradeOverH1(client net.Conn, clientBR *bufio.Reader, serverConn net.Conn, req *http.Request, order []string) bool {
	defer serverConn.Close()
	serverBR := bufio.NewReader(serverConn)
	if err := writeRequest(req, serverConn, order); err != nil {
		return false
	}
	resp, err := readFinalResponse(serverBR, req, client)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		relayUpgraded(client, clientBR, serverConn, serverBR, resp)
		return false
	}
	// The server declined the upgrade; pass its answer on as an ordinary response.
	closeAfter := resp.Close || req.Close
	err = resp.Write(client)
	resp.Body.Close()
	return err == nil && !closeAfter
}

// relayUpgraded forwards the 101 response, then copies bytes both ways without
// interpreting them (WebSocket frames, extensions and all). clientR and serverR
// are the bufio readers the HTTP exchange used: they may already hold bytes
// sent right after the handshake, so reading the raw conns would lose them.
// It returns, with both conns closed, once either direction ends.
func relayUpgraded(client io.ReadWriteCloser, clientR io.Reader, server io.ReadWriteCloser, serverR io.Reader, resp *http.Response) {
	// Not resp.Write: it would add framing headers that a 101 must not carry.
	var head bytes.Buffer
	fmt.Fprintf(&head, "HTTP/1.1 %s\r\n", resp.Status)
	resp.Header.Write(&head)
	head.WriteString("\r\n")
	if _, err := client.Write(head.Bytes()); err != nil {
		client.Close()
		server.Close()
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(server, clientR); done <- struct{}{} }()
	go func() { io.Copy(client, serverR); done <- struct{}{} }()
	// Upgraded protocols end with their own close handshake followed by a TCP
	// close, so the first direction to finish ends the whole relay.
	<-done
	client.Close()
	server.Close()
	<-done
}

// writeRequest writes req to w with headers emitted in order first, then the rest.
// This controls the header order seen by the server (JA4H).
func writeRequest(req *http.Request, w io.Writer, order []string) error {
	bw := bufio.NewWriter(w)

	// http.ReadRequest moves Transfer-Encoding out of Header and decodes the
	// body, so the framing must be restored or the server can't find its end.
	chunked := len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked"
	if chunked {
		req.Header.Set("Transfer-Encoding", "chunked")
	}

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

	if chunked {
		if err := writeChunkedBody(bw, req.Body); err != nil {
			return err
		}
		return bw.Flush()
	}

	if req.Body != nil && req.Body != http.NoBody {
		io.Copy(bw, req.Body)
	}

	return bw.Flush()
}

// writeChunkedBody re-encodes body with chunked framing, flushing after every
// chunk so a slowly produced body reaches the server as it arrives. If body
// fails, the terminating chunk is withheld so the server can't mistake a
// truncated body for a complete one. Trailers are not forwarded.
func writeChunkedBody(bw *bufio.Writer, body io.Reader) error {
	cw := httputil.NewChunkedWriter(bw)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := cw.Write(buf[:n]); werr != nil {
				return werr
			}
			if werr := bw.Flush(); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := cw.Close(); err != nil {
		return err
	}
	_, err := bw.WriteString("\r\n")
	return err
}

// handleExpect answers Expect: 100-continue on the proxy itself and strips the
// header, so the client starts sending its body and the server never sees a
// header that browsers don't send. Other Expect values are forwarded untouched.
func handleExpect(req *http.Request, client io.Writer) error {
	if !strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
		return nil
	}
	req.Header.Del("Expect")
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	_, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n")
	return err
}

// readFinalResponse reads from br until a non-informational response arrives,
// relaying any 1xx responses to client along the way. http.ReadResponse returns
// them like any other response, which would otherwise be mistaken for the final
// one. 101 is final because it ends the HTTP exchange on the connection.
func readFinalResponse(br *bufio.Reader, req *http.Request, client io.Writer) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		resp.Body.Close()
		// Not resp.Write: it adds a Content-Length, which 1xx must not carry.
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "HTTP/1.1 %s\r\n", resp.Status)
		resp.Header.Write(&buf)
		buf.WriteString("\r\n")
		if _, err := client.Write(buf.Bytes()); err != nil {
			return nil, err
		}
	}
}

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailers", "Transfer-Encoding", "Upgrade",
}
