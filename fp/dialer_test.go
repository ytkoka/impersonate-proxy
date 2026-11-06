package fp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"impersonate-proxy/config"
)

const (
	extALPN  = 16
	extALPS  = 17513 // application_settings (old codepoint)
	extALPSn = 17613 // application_settings (new codepoint)
)

// pipeDialer hands out one end of an in-memory pipe; the test reads the
// ClientHello from the other end.
type pipeDialer struct{ server chan net.Conn }

func (p *pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	p.server <- s
	return c, nil
}

// clientHello is the part of a ClientHello these tests look at.
type clientHello struct {
	exts []uint16 // extension IDs in wire order
	alpn []string
}

// captureHello runs dial against a pipe, reads the ClientHello it sends, and
// aborts the handshake.
func captureHello(t *testing.T, dial func(base *pipeDialer) error) clientHello {
	t.Helper()
	base := &pipeDialer{server: make(chan net.Conn, 1)}
	errc := make(chan error, 1)
	go func() { errc <- dial(base) }()

	var srv net.Conn
	select {
	case srv = <-base.server:
	case <-time.After(5 * time.Second):
		t.Fatal("dialer never connected")
	}
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))

	var rec [5]byte
	if _, err := io.ReadFull(srv, rec[:]); err != nil {
		t.Fatalf("read record header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(rec[3:5]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	srv.Close()
	<-errc // handshake fails once the pipe is closed

	// handshake header(4) version(2) random(32) session_id cipher_suites compression extensions
	p := 4 + 2 + 32
	p += 1 + int(body[p])
	p += 2 + int(binary.BigEndian.Uint16(body[p:]))
	p += 1 + int(body[p])
	end := p + 2 + int(binary.BigEndian.Uint16(body[p:]))
	p += 2

	var h clientHello
	for p < end {
		id := binary.BigEndian.Uint16(body[p:])
		n := int(binary.BigEndian.Uint16(body[p+2:]))
		data := body[p+4 : p+4+n]
		h.exts = append(h.exts, id)
		if id == extALPN {
			for q := 2; q < len(data); {
				l := int(data[q])
				h.alpn = append(h.alpn, string(data[q+1:q+1+l]))
				q += 1 + l
			}
		}
		p += 4 + n
	}
	return h
}

func (h clientHello) hasALPS() bool {
	return slices.Contains(h.exts, extALPS) || slices.Contains(h.exts, extALPSn)
}

func TestDialH1RestrictsALPN(t *testing.T) {
	custom := config.TLSConfig{Preset: "custom", CustomHello: config.CustomHello{
		CipherSuites: []uint16{0x1301, 0xc02b},
		Curves:       []string{"X25519", "P256"},
		Versions:     []string{"1.2", "1.3"},
		Extensions:   []uint16{0, 10, 11, 13, 16, 43, 51},
	}}
	cases := []struct {
		name   string
		cfg    config.TLSConfig
		wantH2 bool // whether the plain Dial hello offers h2
		runs   int
	}{
		{"chrome", config.TLSConfig{Preset: "chrome"}, true, 1},
		{"firefox", config.TLSConfig{Preset: "firefox"}, true, 1},
		{"safari", config.TLSConfig{Preset: "safari"}, true, 1},
		{"edge", config.TLSConfig{Preset: "edge"}, true, 1},
		{"custom", custom, true, 1},
		// The golang preset sends no ALPN at all, so it never negotiates h2 and
		// never reaches DialH1 in practice; it must still be left alone.
		{"golang", config.TLSConfig{Preset: "golang"}, false, 1},
		// Randomised hellos vary per connection; repeat to cover the variants.
		{"random", config.TLSConfig{Preset: "random"}, false, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDialerFromConfig(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()

			for i := 0; i < tc.runs; i++ {
				def := captureHello(t, func(b *pipeDialer) error {
					_, err := d.Dial(ctx, b, "example.test", "example.test:443")
					return err
				})
				h1 := captureHello(t, func(b *pipeDialer) error {
					_, err := d.DialH1(ctx, b, "example.test", "example.test:443")
					return err
				})

				if tc.wantH2 && !slices.Contains(def.alpn, "h2") {
					t.Errorf("Dial ALPN = %v, want it to offer h2", def.alpn)
				}
				if slices.Contains(h1.alpn, "h2") || h1.hasALPS() {
					t.Errorf("DialH1 hello still offers h2/ALPS: alpn=%v exts=%v", h1.alpn, h1.exts)
				}
				// Where the hello speaks ALPN at all, DialH1 narrows it to http/1.1.
				if slices.Contains(h1.exts, extALPN) {
					if want := []string{"http/1.1"}; !slices.Equal(h1.alpn, want) {
						t.Errorf("DialH1 ALPN = %v, want %v", h1.alpn, want)
					}
				}
				// Deterministic presets must keep the same extensions otherwise
				// (random draws a different hello per connection, so skip it).
				if tc.runs == 1 && slices.Contains(def.exts, extALPN) != slices.Contains(h1.exts, extALPN) {
					t.Errorf("DialH1 changed whether ALPN is sent: Dial %v, DialH1 %v", def.exts, h1.exts)
				}
				if tc.name == "chrome" && !def.hasALPS() {
					t.Errorf("Dial ClientHello lost ALPS for chrome: %v", def.exts)
				}
			}
		})
	}
}
