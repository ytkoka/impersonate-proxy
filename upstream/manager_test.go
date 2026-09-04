package upstream

import (
	"context"
	"strings"
	"testing"

	"impersonate-proxy/config"
)

func TestNew_directWhenDisabled(t *testing.T) {
	m, err := New(config.UpstreamConfig{Enabled: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	name, d := m.Current()
	if name != "direct" {
		t.Errorf("name = %q, want direct", name)
	}
	if _, ok := d.(DirectDialer); !ok {
		t.Errorf("dialer = %T, want DirectDialer", d)
	}
}

func TestNew_directWhenNoProxiesConfigured(t *testing.T) {
	m, err := New(config.UpstreamConfig{Enabled: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	name, _ := m.Current()
	if name != "direct" {
		t.Errorf("name = %q, want direct (enabled but no proxies)", name)
	}
}

func TestNew_rejectsUnsupportedScheme(t *testing.T) {
	_, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{{Name: "p1", URL: "https://user:pass@host:8080"}},
	})
	if err == nil {
		t.Fatal("expected error for https scheme, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error = %v, want it to mention the rejected scheme", err)
	}
}

func TestNew_rejectsEmptyName(t *testing.T) {
	_, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{{Name: "", URL: "socks5://host:1080"}},
	})
	if err == nil {
		t.Fatal("expected error for empty proxy name, got nil")
	}
}

func TestNew_rejectsDuplicateName(t *testing.T) {
	_, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{
			{Name: "dup", URL: "socks5://host1:1080"},
			{Name: "dup", URL: "socks5://host2:1080"},
		},
	})
	if err == nil {
		t.Fatal("expected error for duplicate proxy name, got nil")
	}
}

func TestNew_rejectsUnknownInitialSelect(t *testing.T) {
	_, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{{Name: "p1", URL: "socks5://host:1080"}},
		Select:  "does-not-exist",
	})
	if err == nil {
		t.Fatal("expected error for unknown initial select, got nil")
	}
}

func TestCurrent_selectByName(t *testing.T) {
	m, err := New(config.UpstreamConfig{
		Enabled: true,
		Proxies: []config.UpstreamProxy{
			{Name: "a", URL: "socks5://hostA:1080"},
			{Name: "b", URL: "http://hostB:8080"},
		},
		Select: "b",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	name, _ := m.Current()
	if name != "b" {
		t.Errorf("name = %q, want b", name)
	}
}

func TestCurrent_emptySelectUsesFirstProxy(t *testing.T) {
	m, err := New(config.UpstreamConfig{
		Enabled: true,
		Proxies: []config.UpstreamProxy{
			{Name: "first", URL: "socks5://hostA:1080"},
			{Name: "second", URL: "socks5://hostB:1080"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	name, _ := m.Current()
	if name != "first" {
		t.Errorf("name = %q, want first", name)
	}
}

func TestCurrent_rotateCyclesThroughAllProxies(t *testing.T) {
	m, err := New(config.UpstreamConfig{
		Enabled: true,
		Proxies: []config.UpstreamProxy{
			{Name: "a", URL: "socks5://hostA:1080"},
			{Name: "b", URL: "socks5://hostB:1080"},
			{Name: "c", URL: "socks5://hostC:1080"},
		},
		Select: "rotate",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		name, _ := m.Current()
		seen[name] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !seen[want] {
			t.Errorf("rotate never selected %q over 6 calls: %v", want, seen)
		}
	}
}

func TestSelect_rejectsUnknownName(t *testing.T) {
	m, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{{Name: "p1", URL: "socks5://host:1080"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Select("nope"); err == nil {
		t.Fatal("expected error selecting unknown proxy name, got nil")
	}
	// A rejected Select must not change the active selection.
	if got := m.Selection(); got != "" {
		t.Errorf("Selection() = %q after rejected Select, want unchanged \"\"", got)
	}
}

func TestSelect_acceptsRotateRandomAndName(t *testing.T) {
	m, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{{Name: "p1", URL: "socks5://host:1080"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, mode := range []string{"rotate", "random", "p1", ""} {
		if err := m.Select(mode); err != nil {
			t.Errorf("Select(%q): %v", mode, err)
		}
	}
}

func TestSuppressIPHeaders(t *testing.T) {
	cases := []struct {
		name     string
		enabled  bool
		proxies  int
		suppress bool
		want     bool
	}{
		{"disabled never suppresses", false, 1, true, false},
		{"enabled with no proxies never suppresses", true, 0, true, false},
		{"enabled + configured suppresses", true, 1, true, true},
		{"enabled but suppress=false", true, 1, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.UpstreamConfig{
				Enabled:                     tc.enabled,
				SuppressIPHeadersWhenActive: tc.suppress,
			}
			if tc.proxies > 0 {
				cfg.Proxies = []config.UpstreamProxy{{Name: "p1", URL: "socks5://host:1080"}}
			}
			m, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := m.SuppressIPHeaders(); got != tc.want {
				t.Errorf("SuppressIPHeaders() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestList_namesOnlyNoCredentials(t *testing.T) {
	m, err := New(config.UpstreamConfig{
		Proxies: []config.UpstreamProxy{
			{Name: "residential", URL: "socks5://user:hunter2@host:1080"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := m.List()
	if len(names) != 1 || names[0] != "residential" {
		t.Fatalf("List() = %v, want [residential]", names)
	}
	for _, n := range names {
		if strings.Contains(n, "hunter2") {
			t.Fatalf("List() leaked credentials: %v", names)
		}
	}
}

func TestBuildProxy_masksPasswordInLoggableForm(t *testing.T) {
	p, err := buildProxy("p1", "http://user:hunter2@proxy.example:8080")
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}
	if strings.Contains(p.maskedURL, "hunter2") {
		t.Errorf("maskedURL leaked the password: %s", p.maskedURL)
	}
	if !strings.Contains(p.maskedURL, "user:***@") {
		t.Errorf("maskedURL = %q, want it to contain masked user:***@", p.maskedURL)
	}
}

func TestDirectDialer_dialsLoopback(t *testing.T) {
	ln := mustListen(t)
	defer ln.Close()
	go acceptOnce(ln)

	var d DirectDialer
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
}
