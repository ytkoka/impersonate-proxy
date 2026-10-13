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

func TestIsPublicIPv4(t *testing.T) {
	tests := []struct {
		name       string
		a, b, c, d int
		wantPublic bool
	}{
		{"public 8.8.8.8", 8, 8, 8, 8, true},
		{"public 1.1.1.1", 1, 1, 1, 1, true},
		{"public 172.32.0.1", 172, 32, 0, 1, true},
		{"public 172.15.0.1", 172, 15, 0, 1, true},
		{"public 11.0.0.1", 11, 0, 0, 1, true},
		{"this-network 0.0.0.0", 0, 0, 0, 0, false},
		{"private 10.0.0.1", 10, 0, 0, 1, false},
		{"shared 100.64.0.1", 100, 64, 0, 1, false},
		{"loopback 127.0.0.1", 127, 0, 0, 1, false},
		{"link-local 169.254.1.1", 169, 254, 1, 1, false},
		{"private 172.16.0.1", 172, 16, 0, 1, false},
		{"private 172.31.255.255", 172, 31, 255, 255, false},
		{"test-net-1 192.0.2.1", 192, 0, 2, 1, false},
		{"private 192.168.1.1", 192, 168, 1, 1, false},
		{"benchmark 198.18.0.1", 198, 18, 0, 1, false},
		{"benchmark 198.19.255.255", 198, 19, 255, 255, false},
		{"test-net-2 198.51.100.1", 198, 51, 100, 1, false},
		{"test-net-3 203.0.113.1", 203, 0, 113, 1, false},
		{"multicast 224.0.0.1", 224, 0, 0, 1, false},
		{"reserved 240.0.0.1", 240, 0, 0, 1, false},
		{"broadcast 255.255.255.255", 255, 255, 255, 255, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPublicIPv4(tt.a, tt.b, tt.c, tt.d); got != tt.wantPublic {
				t.Errorf("isPublicIPv4(%d, %d, %d, %d) = %v, want %v", tt.a, tt.b, tt.c, tt.d, got, tt.wantPublic)
			}
		})
	}
}
