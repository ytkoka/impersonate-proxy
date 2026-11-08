package h2fp

import (
	"fmt"
	"slices"
	"strings"

	"impersonate-proxy/config"
)

// Per-preset HTTP/2 fingerprints.
//
// Each profile is the HTTP/2 connection setup a real browser sends: the SETTINGS
// frame (values and order), the connection-level WINDOW_UPDATE, optional PRIORITY
// data, and the pseudo-header order. They are reported by tls.peet.ws as an
// "akamai_fingerprint" of the form
//
//	SETTINGS | WINDOW_UPDATE | PRIORITY frames | pseudo-header order
//
// The values are taken from observed browser traffic, not guessed. Each profile
// says whether it was measured here or taken from a published source, and
// which browser version it describes. The versions follow the User-Agents the
// proxy sends for `user_agent: "auto"` (see package rewrite), so the layers do
// not contradict each other. When a profile is updated, update that User-Agent
// and the TLS preset together.
//
// Sources:
//   - [measured] Google Chrome 156.0.8078.80 (macOS), run headless with
//     `--dump-dom https://tls.peet.ws/api/all` on 2026-11-08.
//   - [tls-client] github.com/bogdanfinn/tls-client, profiles/
//     internal_browser_profiles.go and contributed_browser_profiles.go (profiles
//     built from captured browser traffic; Chrome_152 in it matches [measured]).
//   - [curl-impersonate] github.com/lexiforest/curl-impersonate, bin/curl_*
//     wrapper scripts (--http2-settings, --http2-window-update,
//     --http2-pseudo-headers-order).
var profiles = map[string]config.HTTP2Config{
	// Chrome / Chromium. [measured] Chrome 156: SETTINGS 1:65536;2:0;4:6291456;6:262144,
	// WINDOW_UPDATE 15663105, pseudo-headers m,a,s,p, and every HEADERS frame
	// carries priority {depends_on 0, weight 256, exclusive}. [tls-client]
	// Chrome_131 and Chrome_152 give the same SETTINGS/WINDOW_UPDATE/order.
	"chrome": {
		Settings:          []config.H2Setting{{ID: 1, Val: 65536}, {ID: 2, Val: 0}, {ID: 4, Val: 6291456}, {ID: 6, Val: 262144}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: []string{"method", "authority", "scheme", "path"},
		HeadersPriority:   &config.H2Priority{DependsOn: 0, Weight: 256, Exclusive: true},
	},

	// Firefox 133-148: 1:65536;2:0;4:131072;5:16384 | 12517377 | 0 | m,p,a,s.
	// [tls-client] Firefox_133, _135, _147 and _148 agree on all of it. Firefox up
	// to about 123 also sent PRIORITY frames (streams 3,5,7,9,11); current
	// versions don't. Not measured here (no Firefox on the build machine), and
	// the sources disagree about a HEADERS priority, so none is sent.
	"firefox": {
		Settings:          []config.H2Setting{{ID: 1, Val: 65536}, {ID: 2, Val: 0}, {ID: 4, Val: 131072}, {ID: 5, Val: 16384}},
		WindowUpdate:      12517377,
		PseudoHeaderOrder: []string{"method", "path", "authority", "scheme"},
	},

	// Safari 17 on macOS: 2:0;4:4194304;3:100 | 10485760 | 0 | m,s,p,a.
	// [curl-impersonate] curl_safari170. Not measured here. Note the order is
	// ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_CONCURRENT_STREAMS.
	//
	// Newer Safari differs: 18.4 and 26 send 2:0;3:100;4:2097152;9:1 | 10420225 |
	// 0 | m,s,a,p ([curl-impersonate] curl_safari184 / curl_safari260 and
	// [tls-client] Safari_IOS_18_5 / _26_0). It is not used because the
	// User-Agent this proxy sends for the preset is Safari 17.2.
	"safari": {
		Settings:          []config.H2Setting{{ID: 2, Val: 0}, {ID: 4, Val: 4194304}, {ID: 3, Val: 100}},
		WindowUpdate:      10485760,
		PseudoHeaderOrder: []string{"method", "scheme", "path", "authority"},
	},

	// Safari on iOS 17: 2:0;4:2097152;3:100 | 10485760 | 0 | m,s,p,a. Two
	// independent sources agree: [curl-impersonate] curl_safari172_ios and
	// [tls-client] Safari_IOS_17_0. Not measured here (no iOS device or Simulator
	// available). It differs from macOS Safari 17 in INITIAL_WINDOW_SIZE. iOS 18.4+
	// uses the newer values described under "safari".
	"ios": {
		Settings:          []config.H2Setting{{ID: 2, Val: 0}, {ID: 4, Val: 2097152}, {ID: 3, Val: 100}},
		WindowUpdate:      10485760,
		PseudoHeaderOrder: []string{"method", "scheme", "path", "authority"},
	},
}

func init() {
	// Edge is Chromium: same network stack, same HTTP/2 connection setup as
	// Chrome (the `edge` TLS preset is Chrome's ClientHello for the same reason).
	profiles["edge"] = profiles["chrome"]
}

// defaultProfile is used for presets that don't imitate one browser: custom
// (whose ClientHello is user-defined), random and golang.
const defaultProfile = "chrome"

// Resolve returns the HTTP/2 configuration to use for a connection made with
// the given TLS preset. Fields set in user override the preset's profile;
// empty fields follow it. Enabled always comes from user.
func Resolve(preset string, user config.HTTP2Config) config.HTTP2Config {
	base, ok := profiles[preset]
	if !ok {
		base = profiles[defaultProfile]
	}
	out := config.HTTP2Config{
		Enabled:           user.Enabled,
		Settings:          slices.Clone(base.Settings),
		WindowUpdate:      base.WindowUpdate,
		PseudoHeaderOrder: slices.Clone(base.PseudoHeaderOrder),
		Priorities:        slices.Clone(base.Priorities),
	}
	if base.HeadersPriority != nil {
		hp := *base.HeadersPriority
		out.HeadersPriority = &hp
	}
	if len(user.Settings) > 0 {
		out.Settings = user.Settings
	}
	if user.WindowUpdate > 0 {
		out.WindowUpdate = user.WindowUpdate
	}
	if len(user.PseudoHeaderOrder) > 0 {
		out.PseudoHeaderOrder = user.PseudoHeaderOrder
	}
	if len(user.Priorities) > 0 {
		out.Priorities = user.Priorities
	}
	if user.HeadersPriority != nil {
		out.HeadersPriority = user.HeadersPriority
	}
	return out
}

// Fingerprint renders cfg the way tls.peet.ws reports it ("akamai_fingerprint"):
// SETTINGS|WINDOW_UPDATE|PRIORITY frames|pseudo-header order. PRIORITY frames
// are written stream:exclusive:depends_on:weight.
func Fingerprint(cfg config.HTTP2Config) string {
	settings := make([]string, 0, len(cfg.Settings))
	for _, s := range cfg.Settings {
		settings = append(settings, fmt.Sprintf("%d:%d", s.ID, s.Val))
	}
	prio := "0"
	if len(cfg.Priorities) > 0 {
		ps := make([]string, 0, len(cfg.Priorities))
		for _, p := range cfg.Priorities {
			ex := 0
			if p.Exclusive {
				ex = 1
			}
			ps = append(ps, fmt.Sprintf("%d:%d:%d:%d", p.StreamID, ex, p.DependsOn, p.Weight))
		}
		prio = strings.Join(ps, ",")
	}
	letters := make([]string, 0, len(cfg.PseudoHeaderOrder))
	for _, ph := range cfg.PseudoHeaderOrder {
		switch ph {
		case "method":
			letters = append(letters, "m")
		case "authority":
			letters = append(letters, "a")
		case "scheme":
			letters = append(letters, "s")
		case "path":
			letters = append(letters, "p")
		}
	}
	return fmt.Sprintf("%s|%d|%s|%s", strings.Join(settings, ";"), cfg.WindowUpdate, prio, strings.Join(letters, ","))
}
