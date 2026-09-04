package upstream

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// socks5Dialer adapts golang.org/x/net/proxy's SOCKS5 client to BaseDialer.
// Both "socks5" and "socks5h" are treated identically here: the target host
// is passed through as a hostname (never pre-resolved), so the SOCKS5
// server always does the DNS resolution — i.e. every socks5 upstream in
// this package behaves like socks5h.
type socks5Dialer struct {
	inner proxy.ContextDialer
}

func newSocks5Dialer(proxyAddr, user, pass string) (*socks5Dialer, error) {
	var auth *proxy.Auth
	if user != "" || pass != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		// Unreachable with the golang.org/x/net version this is pinned to
		// (proxy.SOCKS5 always returns a *socks.Dialer, which implements
		// DialContext) — kept as a guard in case that ever changes upstream.
		return nil, fmt.Errorf("SOCKS5 dialer does not support DialContext")
	}
	return &socks5Dialer{inner: cd}, nil
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.inner.DialContext(ctx, network, addr)
}
