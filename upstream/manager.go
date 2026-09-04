package upstream

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"impersonate-proxy/config"
)

// Proxy is one configured upstream proxy entry. The parsed URL (which may
// carry credentials) is kept private — Manager.List and the management API
// only ever expose Name.
type Proxy struct {
	Name      string
	scheme    string
	dialer    BaseDialer
	maskedURL string // credentials redacted; safe for logs
}

// Manager resolves which BaseDialer a new outbound connection should use,
// based on runtime-mutable enabled/select state. All fields that change
// after construction are guarded by mu; New() and its callers must not
// mutate a Manager except through the exported setters.
type Manager struct {
	mu                sync.RWMutex
	enabled           bool
	proxies           []*Proxy
	byName            map[string]*Proxy
	selection         string // proxy name | "rotate" | "random" | ""
	rr                uint64 // atomic round-robin counter for "rotate"
	dialTimeout       time.Duration
	suppressIPHeaders bool // static config value; combine with enabled in SuppressIPHeaders()
}

// New builds a Manager from config, parsing and validating every proxy URL
// up front so a typo in config.yaml fails at startup rather than on the
// first request that happens to need it.
func New(cfg config.UpstreamConfig) (*Manager, error) {
	m := &Manager{
		enabled:           cfg.Enabled,
		byName:            make(map[string]*Proxy, len(cfg.Proxies)),
		selection:         cfg.Select,
		suppressIPHeaders: cfg.SuppressIPHeadersWhenActive,
	}

	timeoutMS := cfg.DialTimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 15000
	}
	m.dialTimeout = time.Duration(timeoutMS) * time.Millisecond

	for _, p := range cfg.Proxies {
		if p.Name == "" {
			return nil, fmt.Errorf("upstream proxy entry has an empty name")
		}
		if _, dup := m.byName[p.Name]; dup {
			return nil, fmt.Errorf("upstream proxy name %q is defined more than once", p.Name)
		}
		proxy, err := buildProxy(p.Name, p.URL)
		if err != nil {
			return nil, fmt.Errorf("upstream proxy %q: %w", p.Name, err)
		}
		m.byName[p.Name] = proxy
		m.proxies = append(m.proxies, proxy)
	}

	if err := m.validateSelection(m.selection); err != nil {
		return nil, err
	}

	return m, nil
}

func buildProxy(name, rawURL string) (*Proxy, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	var d BaseDialer
	switch u.Scheme {
	case "socks5", "socks5h":
		d, err = newSocks5Dialer(u.Host, user, pass)
		if err != nil {
			return nil, err
		}
	case "http":
		d = newConnectProxyDialer(u.Host, user, pass)
	case "https":
		return nil, fmt.Errorf("scheme %q is not supported: TLS-terminating upstream proxies would strip the uTLS ClientHello (planned for a later phase)", u.Scheme)
	default:
		return nil, fmt.Errorf("unsupported scheme %q (use socks5, socks5h, or http)", u.Scheme)
	}

	return &Proxy{
		Name:      name,
		scheme:    u.Scheme,
		dialer:    d,
		maskedURL: maskCredentials(u),
	}, nil
}

// maskCredentials renders a proxy URL with any password redacted, safe to
// put in logs or error messages. Built by hand rather than via url.URL.User
// + String(), which percent-encodes "*" (not in the userinfo-safe set) into
// "%2A" and defeats a simple substring check for the mask.
func maskCredentials(u *url.URL) string {
	host := u.Host
	if u.User == nil {
		return fmt.Sprintf("%s://%s%s", u.Scheme, host, u.Path)
	}
	user := u.User.Username()
	if _, hasPass := u.User.Password(); hasPass {
		return fmt.Sprintf("%s://%s:***@%s%s", u.Scheme, user, host, u.Path)
	}
	return fmt.Sprintf("%s://%s@%s%s", u.Scheme, user, host, u.Path)
}

// Current resolves the BaseDialer a new outbound connection should use right
// now. It is called once per outbound TCP dial (once per CONNECT tunnel,
// or once per request for plain HTTP), so "rotate"/"random" only rotate
// across distinct outbound connections — a client reusing one keep-alive
// tunnel will keep using whichever upstream (or direct) was picked when
// that tunnel was established.
func (m *Manager) Current() (name string, d BaseDialer) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled || len(m.proxies) == 0 {
		return "direct", DirectDialer{}
	}

	switch m.selection {
	case "":
		return m.proxies[0].Name, m.proxies[0].dialer
	case "rotate":
		i := atomic.AddUint64(&m.rr, 1) - 1
		p := m.proxies[i%uint64(len(m.proxies))]
		return p.Name, p.dialer
	case "random":
		p := m.proxies[rand.N(len(m.proxies))]
		return p.Name, p.dialer
	default:
		if p, ok := m.byName[m.selection]; ok {
			return p.Name, p.dialer
		}
		// Select() validates before storing, so this should be unreachable;
		// fail safe to direct rather than silently using the wrong proxy.
		return "direct", DirectDialer{}
	}
}

func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *Manager) SetEnabled(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = v
}

// Select changes which proxy new connections use. nameOrMode must be a
// registered proxy name, "rotate", "random", or "" (first configured
// proxy) — anything else is rejected so a typo surfaces immediately as an
// error instead of silently falling back to direct.
func (m *Manager) Select(nameOrMode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateSelectionLocked(nameOrMode); err != nil {
		return err
	}
	m.selection = nameOrMode
	return nil
}

func (m *Manager) validateSelection(nameOrMode string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validateSelectionLocked(nameOrMode)
}

func (m *Manager) validateSelectionLocked(nameOrMode string) error {
	switch nameOrMode {
	case "", "rotate", "random":
		return nil
	default:
		if _, ok := m.byName[nameOrMode]; !ok {
			return fmt.Errorf("unknown upstream proxy or mode %q (want a configured proxy name, \"rotate\", or \"random\")", nameOrMode)
		}
		return nil
	}
}

func (m *Manager) Selection() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.selection
}

// List returns configured proxy names in config order — never URLs or
// credentials.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, len(m.proxies))
	for i, p := range m.proxies {
		names[i] = p.Name
	}
	return names
}

// SuppressIPHeaders reports whether IP-spoofing headers (X-Forwarded-For /
// True-Client-IP) should be skipped: true only when an upstream is actually
// active and configured to suppress them, so a stale toggle can't leave a
// contradictory "clean IP + spoofed XFF" request going out under direct
// dial.
func (m *Manager) SuppressIPHeaders() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled && len(m.proxies) > 0 && m.suppressIPHeaders
}

func (m *Manager) DialTimeout() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dialTimeout
}
