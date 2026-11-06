// Package filter decides, per target host, whether the proxy impersonates a
// browser or leaves the connection alone.
package filter

import (
	"fmt"
	"net"
	"strings"
)

// Filter modes.
const (
	ModeOff     = "off"     // impersonate every host (default)
	ModeInclude = "include" // impersonate only the listed hosts
	ModeExclude = "exclude" // impersonate every host except the listed ones
)

// Matcher answers whether a host should be impersonated. A nil *Matcher
// impersonates everything, so callers that never configure a filter need no
// special case. A Matcher is immutable and safe for concurrent use.
type Matcher struct {
	mode     string
	exact    map[string]struct{}
	suffixes []string // ".example.com" for each "*.example.com" pattern
}

// New builds a Matcher. mode is "off", "include" or "exclude" ("" means off).
// Each host pattern is either an exact host name or IP literal ("example.com",
// "203.0.113.7", "::1"), or "*.example.com", which matches any subdomain of
// example.com but not example.com itself. Patterns are case-insensitive and
// must not carry a port.
func New(mode string, hosts []string) (*Matcher, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "":
		mode = ModeOff
	case ModeOff, ModeInclude, ModeExclude:
	default:
		return nil, fmt.Errorf("unknown filter mode %q (use %s, %s or %s)", mode, ModeOff, ModeInclude, ModeExclude)
	}

	m := &Matcher{mode: mode, exact: make(map[string]struct{}, len(hosts))}
	for _, p := range hosts {
		wild, host, err := parsePattern(p)
		if err != nil {
			return nil, err
		}
		if wild {
			m.suffixes = append(m.suffixes, "."+host)
		} else {
			m.exact[host] = struct{}{}
		}
	}
	return m, nil
}

// Mode returns the effective mode ("off" for a nil Matcher).
func (m *Matcher) Mode() string {
	if m == nil {
		return ModeOff
	}
	return m.mode
}

// Impersonate reports whether traffic to host (a bare host or host:port, as in
// a CONNECT target or a Host header) should be impersonated.
func (m *Matcher) Impersonate(host string) bool {
	if m == nil {
		return true
	}
	switch m.mode {
	case ModeInclude:
		return m.matches(host)
	case ModeExclude:
		return !m.matches(host)
	default:
		return true
	}
}

func (m *Matcher) matches(host string) bool {
	h := normalize(host)
	if _, ok := m.exact[h]; ok {
		return true
	}
	for _, s := range m.suffixes {
		// len check: ".example.com" alone (empty label) is not a subdomain.
		if len(h) > len(s) && strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

// normalize lower-cases host, drops any port and brackets, and drops a
// trailing dot, so "Example.COM.:443" and "example.com" compare equal.
func normalize(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// parsePattern validates one host pattern and returns its normalized host and
// whether it was a "*." wildcard.
func parsePattern(p string) (wild bool, host string, err error) {
	orig := p
	p = strings.TrimSpace(p)
	if p == "" {
		return false, "", fmt.Errorf("filter host pattern is empty")
	}
	if strings.Contains(p, "/") {
		return false, "", fmt.Errorf("filter host pattern %q: paths and CIDR ranges are not supported", orig)
	}
	if _, _, splitErr := net.SplitHostPort(p); splitErr == nil {
		return false, "", fmt.Errorf("filter host pattern %q: ports are not supported, list the host only", orig)
	}

	if rest, ok := strings.CutPrefix(p, "*."); ok {
		wild = true
		p = rest
	}
	if strings.Contains(p, "*") {
		return false, "", fmt.Errorf("filter host pattern %q: '*' is only allowed as a leading '*.'", orig)
	}
	host = normalize(p)
	if host == "" || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return false, "", fmt.Errorf("filter host pattern %q is not a valid host name", orig)
	}
	if wild && net.ParseIP(host) != nil {
		return false, "", fmt.Errorf("filter host pattern %q: wildcards cannot be used with an IP address", orig)
	}
	return wild, host, nil
}
