package hdrprofile

import (
	"slices"
	"strings"
	"testing"
)

func TestOrderPerPreset(t *testing.T) {
	for preset, want := range map[string][]string{
		"ios":     {"accept", "sec-fetch-site", "accept-encoding", "sec-fetch-mode", "user-agent", "accept-language", "sec-fetch-dest"},
		"safari":  {"accept", "sec-fetch-site", "accept-encoding", "sec-fetch-mode", "user-agent", "accept-language", "sec-fetch-dest"},
		"firefox": {"user-agent", "accept", "accept-language", "accept-encoding", "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "priority", "te"},
		"chrome": {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"},
	} {
		if got := Order(preset); !slices.Equal(got, want) {
			t.Errorf("%s order = %v\nwant %v", preset, got, want)
		}
	}
}

func TestEdgeIsChromeWithEdgeBrand(t *testing.T) {
	if !slices.Equal(Order("edge"), Order("chrome")) {
		t.Error("edge and chrome send headers in the same order")
	}
	var ua, platform string
	for _, h := range Navigation("edge") {
		switch h.Name {
		case "sec-ch-ua":
			ua = h.Value
		case "sec-ch-ua-platform":
			platform = h.Value
		}
	}
	if !strings.Contains(ua, "Microsoft Edge") || strings.Contains(ua, "Google Chrome") || platform != `"Windows"` {
		t.Errorf("edge sec-ch-ua=%q platform=%q", ua, platform)
	}
	for _, h := range Navigation("chrome") { // chrome must be untouched by edge()
		if h.Name == "sec-ch-ua" && !strings.Contains(h.Value, "Google Chrome") {
			t.Errorf("chrome's sec-ch-ua was changed: %q", h.Value)
		}
	}
}

func TestUnknownPresetsUseChrome(t *testing.T) {
	for _, p := range []string{"custom", "random", "golang", ""} {
		if !slices.Equal(Order(p), Order("chrome")) {
			t.Errorf("%q should use Chrome's headers", p)
		}
	}
}

func TestNavigationHasValuesAndNoUserAgent(t *testing.T) {
	for _, p := range []string{"chrome", "edge", "firefox", "safari", "ios"} {
		hs := Navigation(p)
		if len(hs) == 0 {
			t.Fatalf("%s: no default headers", p)
		}
		for _, h := range hs {
			if h.Value == "" || h.Name == "user-agent" || h.Name != strings.ToLower(h.Name) {
				t.Errorf("%s: bad default %+v", p, h)
			}
		}
		if len(hs) != len(Order(p))-1 { // everything but user-agent
			t.Errorf("%s: %d defaults for %d ordered headers", p, len(hs), len(Order(p)))
		}
	}
	// The iOS Safari 17.2 capture: Accept-Encoding includes br, but not zstd.
	for _, h := range Navigation("ios") {
		if h.Name == "accept-encoding" && h.Value != "gzip, deflate, br" {
			t.Errorf("ios accept-encoding = %q", h.Value)
		}
	}
}

func TestHas(t *testing.T) {
	if !Has(map[string]string{"Accept": "x"}, "accept") || Has(map[string]string{"X": "y"}, "accept") {
		t.Error("Has is case-insensitive membership")
	}
}
