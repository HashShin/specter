package impersonate_test

import (
	"testing"

	"specter/impersonate"
)

// TestNormalize verifies that browser aliases resolve to their canonical targets.
func TestNormalize(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"chrome", impersonate.DefaultChrome},
		{"edge", impersonate.DefaultEdge},
		{"safari", impersonate.DefaultSafari},
		{"safari_ios", impersonate.DefaultSafariIOS},
		{"chrome_android", impersonate.DefaultChromeAndroid},
		{"firefox", impersonate.DefaultFirefox},
		{"tor", impersonate.Tor145},
		// Deprecated aliases
		{"safari15_3", impersonate.Safari153},
		{"safari15_5", impersonate.Safari155},
		{"safari17_0", impersonate.Safari170},
		{"safari17_2_ios", impersonate.Safari172iOS},
		{"safari18_0", impersonate.Safari180},
		{"safari18_0_ios", impersonate.Safari180iOS},
		// Already canonical — must pass through unchanged
		{"chrome146", impersonate.Chrome146},
		{"firefox147", impersonate.Firefox147},
		{"unknown_target", "unknown_target"},
	}

	for _, tc := range cases {
		got := impersonate.Normalize(tc.input)
		if got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestLookup verifies that every canonical target has a registered profile.
func TestLookup(t *testing.T) {
	targets := []string{
		impersonate.Chrome99,
		impersonate.Chrome100,
		impersonate.Chrome101,
		impersonate.Chrome104,
		impersonate.Chrome107,
		impersonate.Chrome110,
		impersonate.Chrome116,
		impersonate.Chrome119,
		impersonate.Chrome120,
		impersonate.Chrome123,
		impersonate.Chrome124,
		impersonate.Chrome131,
		impersonate.Chrome133a,
		impersonate.Chrome136,
		impersonate.Chrome142,
		impersonate.Chrome145,
		impersonate.Chrome146,
		impersonate.Chrome99Android,
		impersonate.Chrome131Android,
		impersonate.Edge99,
		impersonate.Edge101,
		impersonate.Safari153,
		impersonate.Safari155,
		impersonate.Safari170,
		impersonate.Safari172iOS,
		impersonate.Safari180,
		impersonate.Safari180iOS,
		impersonate.Safari184,
		impersonate.Safari260,
		impersonate.Safari260iOS,
		impersonate.Safari2601,
		impersonate.Firefox133,
		impersonate.Firefox135,
		impersonate.Firefox144,
		impersonate.Firefox147,
		impersonate.Tor145,
	}

	for _, target := range targets {
		profile, ok := impersonate.Lookup(target)
		if !ok {
			t.Errorf("Lookup(%q): not found", target)
			continue
		}
		if profile.DefaultUA == "" {
			t.Errorf("Lookup(%q): empty DefaultUA", target)
		}
		if len(profile.H2Settings) == 0 {
			t.Errorf("Lookup(%q): no H2Settings", target)
		}
		if profile.H2WindowUpdate == 0 {
			t.Errorf("Lookup(%q): H2WindowUpdate is 0", target)
		}
		if len(profile.H2PseudoHeaders) == 0 {
			t.Errorf("Lookup(%q): no H2PseudoHeaders", target)
		}
	}
}

// TestLookupUnknown verifies that unknown targets return ok=false.
func TestLookupUnknown(t *testing.T) {
	_, ok := impersonate.Lookup("definitely_not_a_browser")
	if ok {
		t.Error("Lookup of unknown target should return ok=false")
	}
}

// TestLookupViaAlias verifies that Lookup resolves aliases internally.
func TestLookupViaAlias(t *testing.T) {
	aliases := []string{"chrome", "firefox", "safari", "edge", "tor"}
	for _, alias := range aliases {
		_, ok := impersonate.Lookup(alias)
		if !ok {
			t.Errorf("Lookup(%q) via alias should succeed", alias)
		}
	}
}

// TestProfileH2PseudoHeaders verifies pseudo-header values are valid.
func TestProfileH2PseudoHeaders(t *testing.T) {
	valid := map[string]bool{
		"method": true, "authority": true, "scheme": true, "path": true,
	}
	profile, _ := impersonate.Lookup(impersonate.Chrome146)
	for _, h := range profile.H2PseudoHeaders {
		if !valid[h] {
			t.Errorf("Chrome146 has unexpected pseudo-header %q", h)
		}
	}
	if len(profile.H2PseudoHeaders) != 4 {
		t.Errorf("Chrome146 should have 4 pseudo-headers, got %d", len(profile.H2PseudoHeaders))
	}
}
