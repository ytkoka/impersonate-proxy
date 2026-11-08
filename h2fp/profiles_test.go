package h2fp

import (
	"slices"
	"testing"

	"impersonate-proxy/config"
)

// The expected strings are what tls.peet.ws reports for the real browsers; see
// the sources listed in profiles.go.
func TestProfileFingerprints(t *testing.T) {
	for preset, want := range map[string]string{
		"chrome":  "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"edge":    "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"firefox": "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		"safari":  "2:0;4:4194304;3:100|10485760|0|m,s,p,a",
		"ios":     "2:0;4:2097152;3:100|10485760|0|m,s,p,a",
		// No single browser behind these: they use Chrome's.
		"custom": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"random": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"golang": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"":       "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
	} {
		if got := Fingerprint(Resolve(preset, config.HTTP2Config{Enabled: true})); got != want {
			t.Errorf("preset %q: fingerprint = %s, want %s", preset, got, want)
		}
	}
}

func TestSwitchingPresetAndBackRestoresChrome(t *testing.T) {
	user := config.HTTP2Config{Enabled: true}
	chrome := Fingerprint(Resolve("chrome", user))
	if Fingerprint(Resolve("ios", user)) == chrome {
		t.Fatal("ios must differ from chrome")
	}
	if got := Fingerprint(Resolve("chrome", user)); got != chrome {
		t.Errorf("chrome after ios = %s, want %s", got, chrome)
	}
}

func TestResolveUserOverridesWinPerField(t *testing.T) {
	user := config.HTTP2Config{
		Enabled:           true,
		Settings:          []config.H2Setting{{ID: 4, Val: 1}},
		PseudoHeaderOrder: []string{"method", "path"},
		Priorities:        []config.H2Priority{{StreamID: 3, Weight: 201}},
	}
	got := Resolve("firefox", user)
	if !slices.Equal(got.Settings, user.Settings) || !slices.Equal(got.PseudoHeaderOrder, user.PseudoHeaderOrder) {
		t.Errorf("settings/order not overridden: %+v", got)
	}
	if got.WindowUpdate != 12517377 {
		t.Errorf("window_update should follow the preset when unset, got %d", got.WindowUpdate)
	}
	if want := "4:1|12517377|3:0:0:201|m,p"; Fingerprint(got) != want {
		t.Errorf("fingerprint = %s, want %s", Fingerprint(got), want)
	}
}

func TestResolveKeepsEnabledFromUserAndDoesNotAlias(t *testing.T) {
	if Resolve("chrome", config.HTTP2Config{Enabled: false}).Enabled {
		t.Error("enabled must come from the user's config")
	}
	a := Resolve("chrome", config.HTTP2Config{Enabled: true})
	a.Settings[0].Val = 1
	a.HeadersPriority.Weight = 1
	b := Resolve("chrome", config.HTTP2Config{Enabled: true})
	if b.Settings[0].Val != 65536 || b.HeadersPriority.Weight != 256 {
		t.Error("mutating a resolved config changed the shared profile")
	}
}

func TestEdgeIsNotTheSameSliceAsChrome(t *testing.T) {
	// profiles["edge"] starts as a copy of Chrome's struct; make sure it still
	// resolves independently.
	e := Resolve("edge", config.HTTP2Config{Enabled: true})
	e.Settings[0].Val = 7
	if Resolve("chrome", config.HTTP2Config{Enabled: true}).Settings[0].Val != 65536 {
		t.Error("edge and chrome share state")
	}
}

func TestFingerprintFormatsPriorityFrames(t *testing.T) {
	cfg := config.HTTP2Config{
		Settings:          []config.H2Setting{{ID: 1, Val: 65536}},
		WindowUpdate:      12517377,
		PseudoHeaderOrder: []string{"method", "path", "authority", "scheme"},
		Priorities: []config.H2Priority{
			{StreamID: 3, Weight: 201},
			{StreamID: 5, DependsOn: 3, Weight: 101, Exclusive: true},
		},
	}
	if got, want := Fingerprint(cfg), "1:65536|12517377|3:0:0:201,5:1:3:101|m,p,a,s"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
