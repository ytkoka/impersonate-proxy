package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// blockedPrefixes are destinations fetch_url never reaches: loopback, private,
// link-local and similar internal ranges. The first block is the required set;
// the rest close the same holes for IPv6 and for ranges that are internal in
// practice (0.0.0.0/8, CGNAT, unique-local).
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128",
		"0.0.0.0/8", "100.64.0.0/10", "::/128", "fc00::/7", "fe80::/10",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// blockedAddr reports whether a is an internal destination. IPv4-mapped IPv6
// addresses (::ffff:10.0.0.1) are judged as the IPv4 address they carry.
func blockedAddr(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if a.IsMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// targetGuard decides whether fetch_url may contact a URL's host.
type targetGuard struct {
	// lookup resolves a hostname; net.DefaultResolver when nil.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

func (g targetGuard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.lookup != nil {
		return g.lookup(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// check returns an error when u must not be fetched. allow is the proxy's
// fetch_allow_hosts (empty = any host). The host is checked by name against the
// allowlist and by every resolved IP against the blocked ranges, so a public
// name that points at an internal address is refused as well.
//
// Limit: the proxy resolves the name again when it connects, so a resolver that
// answers differently the second time (DNS rebinding) is not stopped here.
func (g targetGuard) check(ctx context.Context, u *url.URL, allow []string) error {
	host := normalizeHost(u.Hostname())
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	if !hostAllowed(host, allow) {
		return fmt.Errorf("host %q is not in fetch_allow_hosts", host)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("host %q is a loopback name; fetch_url does not reach loopback or private addresses", host)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if blockedAddr(ip) {
			return fmt.Errorf("address %s is loopback, private or link-local; fetch_url does not reach those", ip.Unmap())
		}
		return nil
	}

	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("DNS lookup for %q returned no addresses", host)
	}
	for _, a := range addrs {
		if blockedAddr(a) {
			return fmt.Errorf("host %q resolves to %s, which is loopback, private or link-local; fetch_url does not reach those", host, a.Unmap())
		}
	}
	return nil
}

// normalizeHost lowercases a host and drops a trailing root dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// hostAllowed reports whether host equals an allowlist entry or is a subdomain
// of one. An empty allowlist allows everything. Entries may be written with a
// leading "*." or "." — both mean the same as the bare name.
func hostAllowed(host string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	host = normalizeHost(host)
	for _, e := range allow {
		e = normalizeHost(strings.TrimLeft(strings.TrimSpace(e), "*."))
		if e == "" {
			continue
		}
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}
