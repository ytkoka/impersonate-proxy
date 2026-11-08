package proxy

import (
	"testing"

	"impersonate-proxy/config"
	"impersonate-proxy/h2fp"
	"impersonate-proxy/upstream"
)

func newH2TestServer(t *testing.T, h2 config.HTTP2Config) *Server {
	t.Helper()
	mgr, err := upstream.New(config.UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&config.Config{TLS: config.TLSConfig{Preset: "chrome"}, HTTP2: h2}, nil, nil, mgr)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func setPreset(t *testing.T, s *Server, preset string) {
	t.Helper()
	if err := s.UpdateConfig(config.ConfigPatch{TLSPreset: &preset}); err != nil {
		t.Fatalf("UpdateConfig(%s): %v", preset, err)
	}
}

const (
	chromeH2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	iosH2    = "2:0;4:2097152;3:100|10485760|0|m,s,p,a"
)

// Switching the TLS preset at runtime switches the HTTP/2 fingerprint used for
// new connections, and the management API reports it.
func TestHTTP2FingerprintFollowsPreset(t *testing.T) {
	s := newH2TestServer(t, config.HTTP2Config{Enabled: true})

	if got := s.GetActiveConfig().HTTP2Fingerprint; got != chromeH2 {
		t.Errorf("chrome: %s", got)
	}
	setPreset(t, s, "ios")
	if got := s.GetActiveConfig().HTTP2Fingerprint; got != iosH2 {
		t.Errorf("ios: %s", got)
	}
	if got := h2fp.Fingerprint(s.snap().h2cfg); got != iosH2 {
		t.Errorf("new connections use %s, want %s", got, iosH2)
	}
	setPreset(t, s, "chrome")
	if got := h2fp.Fingerprint(s.snap().h2cfg); got != chromeH2 {
		t.Errorf("back to chrome: %s", got)
	}
}

func TestPinnedHTTP2ConfigAppliesToEveryPreset(t *testing.T) {
	s := newH2TestServer(t, config.HTTP2Config{
		Enabled:  true,
		Settings: []config.H2Setting{{ID: 4, Val: 1234}},
	})
	for _, preset := range []string{"chrome", "ios", "firefox"} {
		setPreset(t, s, preset)
		if got := s.GetActiveConfig().HTTP2Fingerprint; got[:6] != "4:1234" {
			t.Errorf("%s: pinned settings lost: %s", preset, got)
		}
	}
}

func TestHTTP2EnabledFlagIsKept(t *testing.T) {
	s := newH2TestServer(t, config.HTTP2Config{Enabled: false})
	if s.snap().h2cfg.Enabled {
		t.Error("http2.enabled=false must still disable the h2 path")
	}
}
