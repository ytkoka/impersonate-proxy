package rewrite

import (
	"net/http"
	"testing"

	"impersonate-proxy/config"
)

func TestApplyUserAgentAuto(t *testing.T) {
	r := New(config.HTTPConfig{UserAgent: "auto"}, nil)
	for preset, want := range presetUserAgents {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		r.Apply(req, preset)
		if got := req.Header.Get("User-Agent"); got != want {
			t.Errorf("preset %s: got %q, want %q", preset, got, want)
		}
	}
	for _, preset := range []string{"random", "golang", "custom"} {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		r.Apply(req, preset)
		if got := req.Header.Get("User-Agent"); got != "curl/8.0" {
			t.Errorf("preset %s: UA should pass through, got %q", preset, got)
		}
	}
}
