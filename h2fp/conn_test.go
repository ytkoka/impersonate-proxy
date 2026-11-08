package h2fp

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"impersonate-proxy/config"
)

// wire is what a server observed from the client.
type wire struct {
	settings        []http2.Setting
	windowUpdate    uint32
	priorityFrames  []http2.PriorityFrame
	headerFields    []hpack.HeaderField
	headersPriority http2.PriorityParam
	headersHadFlag  bool
	streamID        uint32
}

// observe runs Dial + one GET against a minimal in-memory HTTP/2 server and
// reports the frames the client sent.
func observe(t *testing.T, cfg config.HTTP2Config) wire { return observeWith(t, cfg, nil) }

// observeWith is observe with extra request headers.
func observeWith(t *testing.T, cfg config.HTTP2Config, extra http.Header) wire {
	t.Helper()
	// Loopback TCP rather than net.Pipe: its buffering lets the server answer
	// with its own SETTINGS while the client is still writing the preface.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan wire, 1)
	go func() {
		var w wire
		magic := make([]byte, len(clientPreface))
		if _, err := io.ReadFull(server, magic); err != nil || string(magic) != clientPreface {
			t.Errorf("bad client preface: %v %q", err, magic)
			done <- w
			return
		}
		fr := http2.NewFramer(server, server)
		dec := hpack.NewDecoder(4096, nil)
		serverSettingsSent := false
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Errorf("server read: %v", err)
				done <- w
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() {
					continue
				}
				f.ForeachSetting(func(s http2.Setting) error { w.settings = append(w.settings, s); return nil })
				if !serverSettingsSent {
					serverSettingsSent = true
					fr.WriteSettings() // lets the client finish Dial
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					w.windowUpdate = f.Increment
				}
			case *http2.PriorityFrame:
				w.priorityFrames = append(w.priorityFrames, *f)
			case *http2.HeadersFrame:
				w.headerFields, _ = dec.DecodeFull(f.HeaderBlockFragment())
				w.streamID = f.StreamID
				w.headersHadFlag = f.HasPriority()
				w.headersPriority = f.Priority
				var buf []byte
				enc := hpack.NewEncoder(nopWriter{&buf})
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: buf, EndStream: true, EndHeaders: true})
				done <- w
				return
			}
		}
	}()

	conn, err := Dial(client, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	u, _ := url.Parse("https://example.test/p?q=1")
	req := &http.Request{Method: "GET", URL: u, Host: "example.test", Header: http.Header{
		"User-Agent":      {"x"},
		"Accept":          {"*/*"},
		"Accept-Language": {"en"},
		"Accept-Encoding": {"gzip"},
		"Sec-Fetch-Site":  {"none"},
		"Sec-Fetch-Mode":  {"navigate"},
		"Sec-Fetch-Dest":  {"document"},
		"X-Unlisted":      {"1"}, // not in any browser profile
	}}
	for k, v := range extra {
		req.Header[k] = v
	}
	if _, err := conn.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	return <-done
}

type nopWriter struct{ b *[]byte }

func (w nopWriter) Write(p []byte) (int, error) { *w.b = append(*w.b, p...); return len(p), nil }

// settingsString renders SETTINGS entries in the order they were sent.
func settingsString(ss []http2.Setting) string {
	var parts []string
	for _, s := range ss {
		parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Val))
	}
	return strings.Join(parts, ";")
}

// regularOrder returns the non-pseudo header names in the order sent.
func regularOrder(fs []hpack.HeaderField) []string {
	var out []string
	for _, f := range fs {
		if len(f.Name) > 0 && f.Name[0] != ':' {
			out = append(out, f.Name)
		}
	}
	return out
}

func pseudoOrder(fs []hpack.HeaderField) []string {
	var out []string
	for _, f := range fs {
		if len(f.Name) > 0 && f.Name[0] == ':' {
			out = append(out, f.Name)
		}
	}
	return out
}

func TestWireMatchesProfile(t *testing.T) {
	for _, tc := range []struct {
		preset     string
		settings   string // SETTINGS entries in the order sent
		wu         uint32
		pseudo     []string
		hasHdrPrio bool
		stream     uint32
		headers    []string // regular headers in the order the preset's browser sends them
	}{
		{"chrome", "1:65536;2:0;4:6291456;6:262144", 15663105, []string{":method", ":authority", ":scheme", ":path"}, true, 1,
			[]string{"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language", "x-unlisted"}},
		{"firefox", "1:65536;2:0;4:131072;5:16384", 12517377, []string{":method", ":path", ":authority", ":scheme"}, false, 15,
			[]string{"user-agent", "accept", "accept-language", "accept-encoding", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-unlisted"}},
		{"safari", "2:0;4:4194304;3:100", 10485760, []string{":method", ":scheme", ":path", ":authority"}, false, 1,
			[]string{"accept", "sec-fetch-site", "accept-encoding", "sec-fetch-mode", "user-agent", "accept-language", "sec-fetch-dest", "x-unlisted"}},
		{"ios", "2:0;4:2097152;3:100", 10485760, []string{":method", ":scheme", ":path", ":authority"}, false, 1,
			[]string{"accept", "sec-fetch-site", "accept-encoding", "sec-fetch-mode", "user-agent", "accept-language", "sec-fetch-dest", "x-unlisted"}},
	} {
		t.Run(tc.preset, func(t *testing.T) {
			w := observe(t, Resolve(tc.preset, config.HTTP2Config{Enabled: true}))
			if got := settingsString(w.settings); got != tc.settings {
				t.Errorf("SETTINGS (in order) = %q, want %q", got, tc.settings)
			}
			if w.windowUpdate != tc.wu {
				t.Errorf("WINDOW_UPDATE = %d, want %d", w.windowUpdate, tc.wu)
			}
			if len(w.priorityFrames) != 0 {
				t.Errorf("unexpected PRIORITY frames: %d", len(w.priorityFrames))
			}
			if got := pseudoOrder(w.headerFields); !equal(got, tc.pseudo) {
				t.Errorf("pseudo-header order = %v, want %v", got, tc.pseudo)
			}
			if got := regularOrder(w.headerFields); !equal(got, tc.headers) {
				t.Errorf("header order = %v, want %v", got, tc.headers)
			}
			if w.streamID != tc.stream {
				t.Errorf("first stream ID = %d, want %d", w.streamID, tc.stream)
			}
			if w.headersHadFlag != tc.hasHdrPrio {
				t.Errorf("HEADERS priority flag = %v, want %v", w.headersHadFlag, tc.hasHdrPrio)
			}
			if tc.hasHdrPrio {
				// Chrome: exclusive, depends on 0, displayed weight 256 = wire 255.
				if p := w.headersPriority; !p.Exclusive || p.StreamDep != 0 || p.Weight != 255 {
					t.Errorf("HEADERS priority = %+v", p)
				}
			}
		})
	}
}

func TestStandalonePriorityFramesAreSent(t *testing.T) {
	cfg := Resolve("firefox", config.HTTP2Config{
		Enabled: true,
		Priorities: []config.H2Priority{
			{StreamID: 3, DependsOn: 0, Weight: 201},
			{StreamID: 5, DependsOn: 0, Weight: 101},
			{StreamID: 7, DependsOn: 3, Weight: 1, Exclusive: true},
		},
	})
	w := observe(t, cfg)
	if len(w.priorityFrames) != 3 {
		t.Fatalf("got %d PRIORITY frames, want 3", len(w.priorityFrames))
	}
	want := []struct {
		id, dep uint32
		weight  uint8
		excl    bool
	}{{3, 0, 200, false}, {5, 0, 100, false}, {7, 3, 0, true}}
	for i, p := range w.priorityFrames {
		if p.StreamID != want[i].id || p.StreamDep != want[i].dep || p.Weight != want[i].weight || p.Exclusive != want[i].excl {
			t.Errorf("PRIORITY[%d] = stream %d %+v, want %+v", i, p.StreamID, p.PriorityParam, want[i])
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHeaderOrderOverride(t *testing.T) {
	cfg := Resolve("ios", config.HTTP2Config{Enabled: true, HeaderOrder: []string{"Accept-Language", "User-Agent"}, FirstStreamID: 7})
	w := observe(t, cfg)
	want := []string{"accept-language", "user-agent", "accept", "accept-encoding", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-unlisted"}
	if got := regularOrder(w.headerFields); !equal(got, want) {
		t.Errorf("header order = %v, want %v", got, want)
	}
	if w.streamID != 7 {
		t.Errorf("stream ID = %d, want 7", w.streamID)
	}
}

func TestTEHeaderOnlyPassesAsTrailers(t *testing.T) {
	for _, tc := range []struct {
		te   string
		want bool
	}{{"trailers", true}, {"Trailers", true}, {"gzip", false}, {"gzip, trailers", false}} {
		w := observeWith(t, Resolve("firefox", config.HTTP2Config{Enabled: true}), http.Header{"Te": {tc.te}})
		var got bool
		for _, f := range w.headerFields {
			if f.Name == "te" {
				got = true
				if f.Value != tc.te {
					t.Errorf("TE value changed: %q", f.Value)
				}
			}
		}
		if got != tc.want {
			t.Errorf("TE %q forwarded = %v, want %v", tc.te, got, tc.want)
		}
	}
	// Other hop-by-hop headers are still dropped.
	w := observeWith(t, Resolve("chrome", config.HTTP2Config{Enabled: true}), http.Header{"Connection": {"keep-alive"}, "Upgrade": {"x"}})
	for _, f := range w.headerFields {
		if f.Name == "connection" || f.Name == "upgrade" {
			t.Errorf("hop-by-hop header %q was forwarded", f.Name)
		}
	}
}
