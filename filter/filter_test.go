package filter

import "testing"

func mustNew(t *testing.T, mode string, hosts ...string) *Matcher {
	t.Helper()
	m, err := New(mode, hosts)
	if err != nil {
		t.Fatalf("New(%q, %v): %v", mode, hosts, err)
	}
	return m
}

func TestImpersonateModes(t *testing.T) {
	hosts := []string{"target.test"}
	cases := []struct {
		name string
		m    *Matcher
		host string
		want bool
	}{
		{"nil matcher impersonates", nil, "anything.test", true},
		{"off ignores the list", mustNew(t, "off", hosts...), "other.test", true},
		{"empty mode is off", mustNew(t, "", hosts...), "other.test", true},
		{"include: listed", mustNew(t, "include", hosts...), "target.test", true},
		{"include: unlisted", mustNew(t, "include", hosts...), "other.test", false},
		{"include with empty list impersonates nothing", mustNew(t, "include"), "target.test", false},
		{"exclude: listed", mustNew(t, "exclude", hosts...), "target.test", false},
		{"exclude: unlisted", mustNew(t, "exclude", hosts...), "other.test", true},
		{"exclude with empty list impersonates everything", mustNew(t, "exclude"), "target.test", true},
		{"mode is case-insensitive", mustNew(t, " Include ", hosts...), "target.test", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.m.Impersonate(tc.host); got != tc.want {
				t.Errorf("Impersonate(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestMatching(t *testing.T) {
	m := mustNew(t, "include",
		"example.com", "*.cdn.example.com", "203.0.113.7", "::1", "API.Example.ORG")
	cases := []struct {
		host string
		want bool
	}{
		// exact
		{"example.com", true},
		{"example.com:443", true},
		{"EXAMPLE.com", true},
		{"example.com.", true},
		{"example.com.:8443", true},
		{"www.example.com", false}, // exact patterns do not cover subdomains
		{"notexample.com", false},
		{"example.com.evil.test", false},
		// pattern case is normalized too
		{"api.example.org", true},
		// wildcard: any depth below, never the apex or a lookalike
		{"a.cdn.example.com", true},
		{"a.b.cdn.example.com:443", true},
		{"cdn.example.com", false},
		{"xcdn.example.com", false},
		{".cdn.example.com", false},
		// IP literals
		{"203.0.113.7", true},
		{"203.0.113.7:80", true},
		{"203.0.113.8", false},
		{"::1", true},
		{"[::1]", true},
		{"[::1]:443", true},
		{"::2", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := m.Impersonate(tc.host); got != tc.want {
			t.Errorf("Impersonate(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	bad := []struct {
		name  string
		mode  string
		hosts []string
	}{
		{"unknown mode", "allow", nil},
		{"empty pattern", "include", []string{""}},
		{"blank pattern", "include", []string{"   "}},
		{"bare star", "include", []string{"*"}},
		{"star not leading", "include", []string{"foo.*"}},
		{"star mid-label", "include", []string{"f*o.example.com"}},
		{"double wildcard", "include", []string{"*.*.example.com"}},
		{"wildcard without domain", "include", []string{"*."}},
		{"port", "include", []string{"example.com:443"}},
		{"wildcard with port", "include", []string{"*.example.com:443"}},
		{"url path", "include", []string{"example.com/path"}},
		{"cidr", "include", []string{"10.0.0.0/8"}},
		{"leading dot", "include", []string{".example.com"}},
		{"empty label", "include", []string{"a..example.com"}},
		{"wildcard on ip", "include", []string{"*.203.0.113.7"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.mode, tc.hosts); err == nil {
				t.Errorf("New(%q, %q) succeeded, want an error", tc.mode, tc.hosts)
			}
		})
	}
}

// An invalid list is rejected even when the mode is off, so a typo can't hide
// until someone later switches the mode on.
func TestNewValidatesWhenOff(t *testing.T) {
	if _, err := New("off", []string{"foo.*"}); err == nil {
		t.Error("New(off, [foo.*]) succeeded, want an error")
	}
}
