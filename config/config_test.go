package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped configs must not pin HTTP/2 values: pinned values apply to every
// TLS preset and would stop the HTTP/2 fingerprint following the preset.
func TestShippedConfigsLeaveHTTP2ToThePreset(t *testing.T) {
	for _, f := range []string{"../config.yaml", "../config.docker.yaml"} {
		cfg, err := Load(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		h := cfg.HTTP2
		if !h.Enabled {
			t.Errorf("%s: http2 should be enabled", f)
		}
		if len(h.Settings) != 0 || h.WindowUpdate != 0 || len(h.PseudoHeaderOrder) != 0 || len(h.Priorities) != 0 || h.HeadersPriority != nil {
			t.Errorf("%s pins HTTP/2 values: %+v", f, h)
		}
	}
}

func TestDefaultsEnableHTTP2WithoutPinnedValues(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HTTP2.Enabled || len(cfg.HTTP2.Settings) != 0 {
		t.Errorf("defaults: %+v", cfg.HTTP2)
	}
}

func TestHTTP2OverridesParse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(`
http2:
  settings:
    - { id: 4, val: 65535 }
  window_update: 123
  pseudo_header_order: [method, path]
  priorities:
    - { stream_id: 3, depends_on: 0, weight: 201, exclusive: true }
  headers_priority: { depends_on: 0, weight: 256, exclusive: true }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.HTTP2
	if !h.Enabled { // a partial http2 block keeps the default
		t.Error("enabled should stay true when the block doesn't mention it")
	}
	if len(h.Settings) != 1 || h.Settings[0].ID != 4 || h.WindowUpdate != 123 || len(h.PseudoHeaderOrder) != 2 {
		t.Errorf("overrides not parsed: %+v", h)
	}
	if len(h.Priorities) != 1 || h.Priorities[0] != (H2Priority{StreamID: 3, Weight: 201, Exclusive: true}) {
		t.Errorf("priorities = %+v", h.Priorities)
	}
	if h.HeadersPriority == nil || h.HeadersPriority.Weight != 256 || !h.HeadersPriority.Exclusive {
		t.Errorf("headers_priority = %+v", h.HeadersPriority)
	}
}
