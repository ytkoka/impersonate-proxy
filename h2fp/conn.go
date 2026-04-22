// Package h2fp provides an HTTP/2 client connection whose SETTINGS frame,
// WINDOW_UPDATE increment, and pseudo-header order can be freely configured.
// This allows impersonating the HTTP/2 fingerprint of
// specific browsers for WAF bot-detection testing.
package h2fp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"impersonate-proxy/config"
)

// clientPreface is the fixed HTTP/2 connection preface (RFC 7540 §3.5).
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Conn is a single HTTP/2 connection to a server.
// It is not safe for concurrent RoundTrip calls; the proxy serialises requests
// per upstream connection via its own loop.
type Conn struct {
	raw    net.Conn
	fr     *http2.Framer
	enc    *hpack.Encoder
	dec    *hpack.Decoder
	encBuf bytes.Buffer
	cfg    config.HTTP2Config
	nextID uint32 // next client-initiated stream ID (odd, starting at 1)
	mu     sync.Mutex
}

// Dial performs the HTTP/2 connection setup over raw:
//  1. Sends the client connection preface (magic + custom SETTINGS + WINDOW_UPDATE)
//  2. Reads and acknowledges the server's SETTINGS
func Dial(raw net.Conn, cfg config.HTTP2Config) (*Conn, error) {
	c := &Conn{
		raw:    raw,
		fr:     http2.NewFramer(raw, raw),
		cfg:    cfg,
		nextID: 1,
	}
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.dec = hpack.NewDecoder(65536, nil)

	if err := c.sendPreface(); err != nil {
		return nil, fmt.Errorf("h2 send preface: %w", err)
	}
	if err := c.recvServerPreface(); err != nil {
		return nil, fmt.Errorf("h2 recv server preface: %w", err)
	}
	return c, nil
}

// sendPreface writes the three-part client preface:
// connection magic → SETTINGS frame (in configured order) → WINDOW_UPDATE.
func (c *Conn) sendPreface() error {
	if _, err := io.WriteString(c.raw, clientPreface); err != nil {
		return err
	}

	settings := make([]http2.Setting, 0, len(c.cfg.Settings))
	for _, s := range c.cfg.Settings {
		settings = append(settings, http2.Setting{
			ID:  http2.SettingID(s.ID),
			Val: s.Val,
		})
	}
	if err := c.fr.WriteSettings(settings...); err != nil {
		return err
	}

	if c.cfg.WindowUpdate > 0 {
		if err := c.fr.WriteWindowUpdate(0, c.cfg.WindowUpdate); err != nil {
			return err
		}
	}
	return nil
}

// recvServerPreface reads frames until it receives the server's SETTINGS,
// then sends SETTINGS_ACK.
func (c *Conn) recvServerPreface() error {
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			f.ForeachSetting(func(s http2.Setting) error {
				if s.ID == http2.SettingHeaderTableSize {
					c.enc.SetMaxDynamicTableSize(s.Val)
				}
				return nil
			})
			return c.fr.WriteSettingsAck()
		case *http2.WindowUpdateFrame:
			// Server may send WINDOW_UPDATE before SETTINGS; ignore.
		default:
			return fmt.Errorf("unexpected frame %T during server preface", f)
		}
	}
}

// RoundTrip sends req over this connection and returns the response.
// The pseudo-header order and regular headers follow the configured policy.
func (c *Conn) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	sid := c.nextID
	c.nextID += 2
	c.mu.Unlock()

	if err := c.writeHeaders(req, sid); err != nil {
		return nil, err
	}
	if err := c.writeBody(req, sid); err != nil {
		return nil, err
	}
	return c.readResponse(req, sid)
}

// writeHeaders encodes and sends the HEADERS frame.
// Pseudo-headers are emitted in the configured order; regular headers follow.
func (c *Conn) writeHeaders(req *http.Request, sid uint32) error {
	c.encBuf.Reset()

	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}

	for _, ph := range c.cfg.PseudoHeaderOrder {
		switch ph {
		case "method":
			c.enc.WriteField(hpack.HeaderField{Name: ":method", Value: req.Method})
		case "authority":
			c.enc.WriteField(hpack.HeaderField{Name: ":authority", Value: req.Host})
		case "scheme":
			c.enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		case "path":
			c.enc.WriteField(hpack.HeaderField{Name: ":path", Value: uri})
		}
	}

	hasBody := req.Body != nil && req.Body != http.NoBody
	for k, vs := range req.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			c.enc.WriteField(hpack.HeaderField{
				Name:  strings.ToLower(k),
				Value: v,
			})
		}
	}

	return c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      sid,
		BlockFragment: c.encBuf.Bytes(),
		EndStream:     !hasBody,
		EndHeaders:    true,
	})
}

// writeBody sends a DATA frame if the request has a body.
func (c *Conn) writeBody(req *http.Request, sid uint32) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	defer req.Body.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, req.Body); err != nil {
		return err
	}
	return c.fr.WriteData(sid, true, buf.Bytes())
}

// readResponse reads frames until the response for sid is complete.
func (c *Conn) readResponse(req *http.Request, sid uint32) (*http.Response, error) {
	resp := &http.Response{
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     make(http.Header),
		Request:    req,
	}

	var body bytes.Buffer
	headersOK := false

	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return nil, err
		}

		switch f := f.(type) {

		case *http2.HeadersFrame:
			if f.StreamID != sid {
				continue
			}
			fields, err := c.dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return nil, fmt.Errorf("hpack decode: %w", err)
			}
			for _, hf := range fields {
				if hf.Name == ":status" {
					code, err := strconv.Atoi(hf.Value)
					if err != nil {
						return nil, fmt.Errorf("bad :status %q", hf.Value)
					}
					resp.StatusCode = code
					resp.Status = hf.Value + " " + http.StatusText(code)
				} else {
					resp.Header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
				}
			}
			headersOK = true
			if f.StreamEnded() {
				resp.Body = io.NopCloser(&body)
				resp.ContentLength = int64(body.Len())
				return resp, nil
			}

		case *http2.DataFrame:
			if f.StreamID != sid {
				continue
			}
			body.Write(f.Data())
			// Return flow-control credits to avoid stalling the server.
			if n := uint32(len(f.Data())); n > 0 {
				c.fr.WriteWindowUpdate(0, n)
				c.fr.WriteWindowUpdate(sid, n)
			}
			if f.StreamEnded() {
				if !headersOK {
					return nil, fmt.Errorf("DATA before HEADERS on stream %d", sid)
				}
				resp.Body = io.NopCloser(&body)
				resp.ContentLength = int64(body.Len())
				return resp, nil
			}

		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.fr.WriteSettingsAck()
			}

		case *http2.WindowUpdateFrame:
			// Server is granting us send quota; no action needed here.

		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("GOAWAY from server: %v", f.ErrCode)

		case *http2.RSTStreamFrame:
			if f.StreamID == sid {
				return nil, fmt.Errorf("RST_STREAM on stream %d: %v", sid, f.ErrCode)
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				c.fr.WritePing(true, f.Data)
			}
		}
	}
}

func isHopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-connection",
		"te", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
