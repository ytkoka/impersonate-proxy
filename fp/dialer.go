package fp

import (
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var presets = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
	"random":  utls.HelloRandomized,
	"golang":  utls.HelloGolang,
}

func PresetNames() string {
	names := make([]string, 0, len(presets))
	for k := range presets {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// Conn wraps a net.Conn with the ALPN protocol negotiated during the TLS handshake.
type Conn struct {
	net.Conn
	Proto string // "h2" or "http/1.1"
}

type Dialer struct {
	helloID utls.ClientHelloID
}

func NewDialer(preset string) (*Dialer, error) {
	id, ok := presets[preset]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q (available: %s)", preset, PresetNames())
	}
	return &Dialer{helloID: id}, nil
}

// Dial opens a TCP connection to addr, performs a uTLS handshake as host,
// and returns the connection together with the negotiated ALPN protocol.
func (d *Dialer) Dial(host, addr string) (*Conn, error) {
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(rawConn, &utls.Config{ServerName: host}, d.helloID)
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", host, err)
	}
	proto := uconn.ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = "http/1.1"
	}
	return &Conn{Conn: uconn, Proto: proto}, nil
}
