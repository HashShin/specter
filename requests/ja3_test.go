package requests

import (
	"testing"
)

// TestBuildSpecFromJA3_Valid verifies that a well-formed JA3 string parses correctly.
func TestBuildSpecFromJA3_Valid(t *testing.T) {
	// Chrome 133 JA3 (real browser fingerprint)
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"

	spec, err := BuildSpecFromJA3(ja3)
	if err != nil {
		t.Fatalf("BuildSpecFromJA3: %v", err)
	}
	if spec == nil {
		t.Fatal("spec is nil")
	}

	// Should have 15 cipher suites (not counting GREASE which isn't in JA3 field 2)
	if len(spec.CipherSuites) != 15 {
		t.Errorf("expected 15 cipher suites, got %d", len(spec.CipherSuites))
	}

	// Extensions list should be non-empty
	if len(spec.Extensions) == 0 {
		t.Error("expected non-empty extensions list")
	}

	// TLS version range
	if spec.TLSVersMin == 0 {
		t.Error("TLSVersMin should not be 0")
	}
	if spec.TLSVersMax == 0 {
		t.Error("TLSVersMax should not be 0")
	}

	// Compression
	if len(spec.CompressionMethods) == 0 {
		t.Error("expected at least one compression method")
	}
}

// TestBuildSpecFromJA3_InvalidFormat verifies error handling for malformed JA3 strings.
func TestBuildSpecFromJA3_InvalidFormat(t *testing.T) {
	cases := []struct {
		name string
		ja3  string
	}{
		{"empty", ""},
		{"only 4 fields", "771,4865,0,29"},
		{"too many fields", "771,4865,0,29,0,extra"},
		{"bad version", "abc,4865,0,29,0"},
		{"bad ciphers", "771,ZZZZ,0,29,0"},
		{"bad extensions", "771,4865,ZZZZ,29,0"},
		{"bad curves", "771,4865,0,ZZZZ,0"},
		{"bad point formats", "771,4865,0,29,ZZZZ"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildSpecFromJA3(tc.ja3)
			if err == nil {
				t.Errorf("expected error for ja3=%q, got nil", tc.ja3)
			}
		})
	}
}

// TestBuildSpecFromJA3_EmptyExtensions verifies JA3 with no extensions.
func TestBuildSpecFromJA3_EmptyExtensions(t *testing.T) {
	ja3 := "771,47,,29-23,0"
	spec, err := BuildSpecFromJA3(ja3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Extensions) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(spec.Extensions))
	}
}

// TestBuildSpecFromJA3_EmptyCurves verifies JA3 with no elliptic curves.
func TestBuildSpecFromJA3_EmptyCurves(t *testing.T) {
	ja3 := "771,47,10,,0"
	_, err := BuildSpecFromJA3(ja3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestIsGREASE verifies GREASE ID detection.
func TestIsGREASE(t *testing.T) {
	greaseIDs := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
		0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, id := range greaseIDs {
		if !isGREASE(id) {
			t.Errorf("isGREASE(0x%04x) = false, want true", id)
		}
	}

	nonGREASE := []uint16{0x0000, 0x0010, 0x0023, 0x1234, 0xFFFF, 771, 4865}
	for _, id := range nonGREASE {
		if isGREASE(id) {
			t.Errorf("isGREASE(0x%04x) = true, want false", id)
		}
	}
}

// TestJA3TLSRange verifies TLS version mapping.
func TestJA3TLSRange(t *testing.T) {
	cases := []struct {
		wire     uint16
		wantMin  uint16
		wantMax  uint16
	}{
		{0x0301, 0x0301, 0x0304}, // TLS 1.0
		{0x0302, 0x0302, 0x0304}, // TLS 1.1
		{0x0303, 0x0303, 0x0304}, // TLS 1.2 (most common)
		{0x0304, 0x0304, 0x0304}, // TLS 1.3
		{0x0000, 0x0303, 0x0304}, // unknown → default TLS 1.2
	}
	for _, tc := range cases {
		min, max := ja3TLSRange(tc.wire)
		if min != tc.wantMin || max != tc.wantMax {
			t.Errorf("ja3TLSRange(0x%04x) = (0x%04x, 0x%04x), want (0x%04x, 0x%04x)",
				tc.wire, min, max, tc.wantMin, tc.wantMax)
		}
	}
}
