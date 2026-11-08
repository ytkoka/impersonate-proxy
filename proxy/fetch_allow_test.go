package proxy

import (
	"slices"
	"testing"

	"impersonate-proxy/config"
	"impersonate-proxy/upstream"
)

// fetch_allow_hosts is informational for the management API: it is reported by
// GetActiveConfig, but nothing a client can send through ConfigPatch changes it.
func TestFetchAllowHostsIsReadOnlyAtRuntime(t *testing.T) {
	mgr, err := upstream.New(config.UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&config.Config{FetchAllowHosts: []string{"a.test", "b.test"}}, nil, nil, mgr)
	if err != nil {
		t.Fatal(err)
	}

	got := s.GetActiveConfig().FetchAllowHosts
	if !slices.Equal(got, []string{"a.test", "b.test"}) {
		t.Fatalf("fetch_allow_hosts = %v", got)
	}
	got[0] = "evil.test" // the returned slice must be a copy
	if s.GetActiveConfig().FetchAllowHosts[0] != "a.test" {
		t.Error("mutating GetActiveConfig's result leaked into the server")
	}

	ip, ua := "203.0.113.1", "x"
	if err := s.UpdateConfig(config.ConfigPatch{ClientIP: &ip, UserAgent: &ua}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.GetActiveConfig().FetchAllowHosts, []string{"a.test", "b.test"}) {
		t.Errorf("an unrelated patch changed fetch_allow_hosts: %v", s.GetActiveConfig().FetchAllowHosts)
	}
}
