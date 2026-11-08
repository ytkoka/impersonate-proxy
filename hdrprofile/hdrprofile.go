// Package hdrprofile holds the request headers real browsers send, per TLS
// preset: which headers, with what default values, in which order.
//
// Two consumers share it: the proxy orders the headers of HTTP/2 requests the
// way the preset's browser does, and the MCP server's fetch_url sends the same
// headers a browser sends for a top-level page load, so a fetched page looks
// like a browser navigation and not like a bare Go client.
//
// The data is a top-level navigation GET, copied from captures of the real
// browsers in github.com/lexiforest/curl-impersonate, tests/signatures/:
//
//	chrome / edge  chrome_131.0.6778.86.yaml (macOS)
//	firefox        firefox_133.0.3_linux.yaml, firefox_135.0.1_linux.yaml,
//	               firefox_144.0.0_linux.yaml (same headers in all three)
//	safari         safari_17.0_macOS.yaml
//	ios            safari_17.2_iOS.yaml
//
// Versions follow the User-Agents the proxy sends for `user_agent: "auto"`
// (Chrome 131, Edge 131, Firefox 132, Safari 17.2, iOS 17.1); the captures are
// the nearest published ones. Edge has no 131 capture: it is Chrome 131's header
// set with Edge's brand in sec-ch-ua (Chromium derives the rest of that header
// from the major version), which is derived, not captured.
package hdrprofile

import "strings"

// Header is one request header. Name is lower-case, as sent over HTTP/2.
type Header struct {
	Name  string
	Value string // empty: not a fixed default (user-agent is the proxy's job)
}

const chromeAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

var chrome = []Header{
	{"sec-ch-ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
	{"sec-ch-ua-mobile", "?0"},
	{"sec-ch-ua-platform", `"macOS"`},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"accept", chromeAccept},
	{"sec-fetch-site", "none"},
	{"sec-fetch-mode", "navigate"},
	{"sec-fetch-user", "?1"},
	{"sec-fetch-dest", "document"},
	{"accept-encoding", "gzip, deflate, br, zstd"},
	{"accept-language", "en-US,en;q=0.9"},
	{"priority", "u=0, i"},
}

var firefox = []Header{
	{"user-agent", ""},
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{"accept-language", "en-US,en;q=0.5"},
	{"accept-encoding", "gzip, deflate, br, zstd"},
	{"upgrade-insecure-requests", "1"},
	{"sec-fetch-dest", "document"},
	{"sec-fetch-mode", "navigate"},
	{"sec-fetch-site", "none"},
	{"sec-fetch-user", "?1"},
	{"priority", "u=0, i"},
	{"te", "trailers"},
}

// Safari 17 on macOS and iOS send the same headers in the same order.
var safari = []Header{
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{"sec-fetch-site", "none"},
	{"accept-encoding", "gzip, deflate, br"},
	{"sec-fetch-mode", "navigate"},
	{"user-agent", ""},
	{"accept-language", "en-US,en;q=0.9"},
	{"sec-fetch-dest", "document"},
}

var profiles = map[string][]Header{
	"chrome":  chrome,
	"edge":    edge(),
	"firefox": firefox,
	"safari":  safari,
	"ios":     safari,
}

// edge is Chrome's header set with Edge's brand list and its Windows platform
// (the Edge User-Agent the proxy sends is Windows).
func edge() []Header {
	out := make([]Header, len(chrome))
	copy(out, chrome)
	for i := range out {
		switch out[i].Name {
		case "sec-ch-ua":
			out[i].Value = `"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`
		case "sec-ch-ua-platform":
			out[i].Value = `"Windows"`
		}
	}
	return out
}

// For presets that don't imitate one browser (custom, random, golang) Chrome's
// profile is used, as for HTTP/2.
func profile(preset string) []Header {
	if p, ok := profiles[preset]; ok {
		return p
	}
	return chrome
}

// Order is the order, lower-case, in which the preset's browser sends request
// headers. Headers the browser doesn't send are simply absent from a request;
// ones not listed here are sent after the listed ones.
func Order(preset string) []string {
	p := profile(preset)
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = h.Name
	}
	return out
}

// Navigation returns the default headers of a top-level page load, in wire
// order, without user-agent (set by the proxy's user_agent setting).
func Navigation(preset string) []Header {
	var out []Header
	for _, h := range profile(preset) {
		if h.Value != "" {
			out = append(out, h)
		}
	}
	return out
}

// Has reports whether headers (any case) contains name.
func Has(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}
