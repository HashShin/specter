// Package impersonate maps browser target strings to utls ClientHelloIDs,
// enabling TLS fingerprint-level browser impersonation with no C dependencies.
package impersonate

import (
	utls "github.com/refraction-networking/utls"
)

// Target is a browser identifier string (same naming as curl_cffi Python).
type Target = string

// Supported browser targets (aliases resolve via Normalize).
const (
	// Edge
	Edge99  Target = "edge99"
	Edge101 Target = "edge101"

	// Chrome
	Chrome99         Target = "chrome99"
	Chrome100        Target = "chrome100"
	Chrome101        Target = "chrome101"
	Chrome104        Target = "chrome104"
	Chrome107        Target = "chrome107"
	Chrome110        Target = "chrome110"
	Chrome116        Target = "chrome116"
	Chrome119        Target = "chrome119"
	Chrome120        Target = "chrome120"
	Chrome123        Target = "chrome123"
	Chrome124        Target = "chrome124"
	Chrome131        Target = "chrome131"
	Chrome133a       Target = "chrome133a"
	Chrome136        Target = "chrome136"
	Chrome142        Target = "chrome142"
	Chrome145        Target = "chrome145"
	Chrome146        Target = "chrome146"
	Chrome99Android  Target = "chrome99_android"
	Chrome131Android Target = "chrome131_android"

	// Safari
	Safari153    Target = "safari153"
	Safari155    Target = "safari155"
	Safari170    Target = "safari170"
	Safari172iOS Target = "safari172_ios"
	Safari180    Target = "safari180"
	Safari180iOS Target = "safari180_ios"
	Safari184    Target = "safari184"
	Safari184iOS Target = "safari184_ios"
	Safari260    Target = "safari260"
	Safari260iOS Target = "safari260_ios"
	Safari2601   Target = "safari2601"

	// Firefox
	Firefox133 Target = "firefox133"
	Firefox135 Target = "firefox135"
	Firefox144 Target = "firefox144"
	Firefox147 Target = "firefox147"
	Tor145     Target = "tor145"

	// Aliases (resolved by Normalize)
	Chrome        Target = "chrome"
	Edge          Target = "edge"
	Safari        Target = "safari"
	SafariIOS     Target = "safari_ios"
	ChromeAndroid Target = "chrome_android"
	Firefox       Target = "firefox"
	Tor           Target = "tor"
)

// defaults for aliases
const (
	DefaultChrome        = Chrome146
	DefaultEdge          = Edge101
	DefaultSafari        = Safari2601
	DefaultSafariIOS     = Safari260iOS
	DefaultChromeAndroid = Chrome131Android
	DefaultFirefox       = Firefox147
)

// Normalize resolves browser aliases to their canonical target string.
func Normalize(target Target) Target {
	switch target {
	case "chrome":
		return DefaultChrome
	case "edge":
		return DefaultEdge
	case "safari":
		return DefaultSafari
	case "safari_ios":
		return DefaultSafariIOS
	case "chrome_android":
		return DefaultChromeAndroid
	case "firefox":
		return DefaultFirefox
	case "tor":
		return Tor145
	// deprecated aliases from Python curl_cffi
	case "safari15_3":
		return Safari153
	case "safari15_5":
		return Safari155
	case "safari17_0":
		return Safari170
	case "safari17_2_ios":
		return Safari172iOS
	case "safari18_0":
		return Safari180
	case "safari18_0_ios":
		return Safari180iOS
	default:
		return target
	}
}

// Profile holds the TLS ClientHelloID and HTTP/2 settings for a browser.
type Profile struct {
	// HelloID is the utls TLS fingerprint to use.
	HelloID utls.ClientHelloID

	// H2Settings are the HTTP/2 SETTINGS frame values to send.
	// These match what the real browser sends in its HTTP/2 preface.
	H2Settings []H2Setting

	// H2WindowUpdate is the connection-level WINDOW_UPDATE increment.
	H2WindowUpdate uint32

	// H2PseudoHeaders is the pseudo-header order (e.g. ["method","authority","scheme","path"]).
	// Standard HTTP/2 clients use different orderings.
	H2PseudoHeaders []string

	// DefaultUA is the User-Agent string for this browser profile.
	DefaultUA string
}

// H2Setting is one HTTP/2 SETTINGS parameter.
type H2Setting struct {
	ID  uint16
	Val uint32
}

// HTTP/2 SETTINGS IDs (from RFC 9113).
const (
	h2SettingHeaderTableSize      uint16 = 0x1
	h2SettingEnablePush           uint16 = 0x2
	h2SettingInitialWindowSize    uint16 = 0x4
	h2SettingMaxFrameSize         uint16 = 0x5
	h2SettingMaxHeaderListSize    uint16 = 0x6
)

// Lookup returns the browser Profile for a given (already-normalized) target.
// Returns false if the target is not known.
func Lookup(target Target) (Profile, bool) {
	target = Normalize(target)
	p, ok := profiles[target]
	return p, ok
}

// profiles maps canonical target strings to browser Profile objects.
var profiles = map[Target]Profile{
	// ---- Chrome ----
	// Chrome 99-107: Chrome 96 TLS profile
	Chrome99: {
		HelloID:         utls.HelloChrome_96,
		H2Settings:      chrome96H2Settings,
		H2WindowUpdate:  15663105,
		H2PseudoHeaders: []string{"method", "authority", "scheme", "path"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
	},
	Chrome100: {
		HelloID:         utls.HelloChrome_100,
		H2Settings:      chrome100H2Settings,
		H2WindowUpdate:  15663105,
		H2PseudoHeaders: []string{"method", "authority", "scheme", "path"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
	},
	Chrome101: {
		HelloID:         utls.HelloChrome_100,
		H2Settings:      chrome100H2Settings,
		H2WindowUpdate:  15663105,
		H2PseudoHeaders: []string{"method", "authority", "scheme", "path"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
	},
	Chrome104: chromeProfile(utls.HelloChrome_102, "104.0.5112.81", chrome100H2Settings),
	Chrome107: chromeProfile(utls.HelloChrome_106_Shuffle, "107.0.5304.107", chrome100H2Settings),
	Chrome110: chromeProfile(utls.HelloChrome_106_Shuffle, "110.0.5481.177", chrome100H2Settings),
	Chrome116: chromeProfile(utls.HelloChrome_112_PSK_Shuf, "116.0.5845.96", chrome100H2Settings),
	Chrome119: chromeProfile(utls.HelloChrome_112_PSK_Shuf, "119.0.6045.159", chrome100H2Settings),
	Chrome120: chromeProfile(utls.HelloChrome_120, "120.0.6099.109", chrome120H2Settings),
	Chrome123: chromeProfile(utls.HelloChrome_120, "123.0.6312.58", chrome120H2Settings),
	Chrome124: chromeProfile(utls.HelloChrome_120, "124.0.6367.78", chrome120H2Settings),
	Chrome131: chromeProfile(utls.HelloChrome_131, "131.0.6778.70", chrome120H2Settings),
	Chrome133a: chromeProfile(utls.HelloChrome_133, "133.0.6943.54", chrome120H2Settings),
	Chrome136: chromeProfile(utls.HelloChrome_133, "136.0.7103.48", chrome120H2Settings),
	Chrome142: chromeProfile(utls.HelloChrome_133, "142.0.7371.0", chrome120H2Settings),
	Chrome145: chromeProfile(utls.HelloChrome_133, "145.0.7400.0", chrome120H2Settings),
	Chrome146: chromeProfile(utls.HelloChrome_133, "146.0.7440.0", chrome120H2Settings),
	Chrome99Android: {
		HelloID:         utls.HelloAndroid_11_OkHttp,
		H2Settings:      chrome100H2Settings,
		H2WindowUpdate:  15728640,
		H2PseudoHeaders: []string{"method", "path", "authority", "scheme"},
		DefaultUA:       "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36",
	},
	Chrome131Android: {
		HelloID:         utls.HelloAndroid_11_OkHttp,
		H2Settings:      chrome120H2Settings,
		H2WindowUpdate:  15728640,
		H2PseudoHeaders: []string{"method", "path", "authority", "scheme"},
		DefaultUA:       "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.39 Mobile Safari/537.36",
	},

	// ---- Edge ----
	Edge99: {
		HelloID:         utls.HelloEdge_85,
		H2Settings:      chrome100H2Settings,
		H2WindowUpdate:  15663105,
		H2PseudoHeaders: []string{"method", "authority", "scheme", "path"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36 Edg/99.0.1150.55",
	},
	Edge101: {
		HelloID:         utls.HelloEdge_106,
		H2Settings:      chrome100H2Settings,
		H2WindowUpdate:  15663105,
		H2PseudoHeaders: []string{"method", "authority", "scheme", "path"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53",
	},

	// ---- Firefox ----
	Firefox133: firefoxProfile(utls.HelloFirefox_120, "133.0"),
	Firefox135: firefoxProfile(utls.HelloFirefox_120, "135.0"),
	Firefox144: firefoxProfile(utls.HelloFirefox_120, "144.0"),
	Firefox147: firefoxProfile(utls.HelloFirefox_Auto, "147.0"),
	Tor145: {
		HelloID:         utls.HelloFirefox_Auto,
		H2Settings:      firefox120H2Settings,
		H2WindowUpdate:  12517377,
		H2PseudoHeaders: []string{"method", "path", "authority", "scheme"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
	},

	// ---- Safari ----
	Safari153:    safariProfile(utls.HelloSafari_Auto, "15.3"),
	Safari155:    safariProfile(utls.HelloSafari_Auto, "15.5"),
	Safari170:    safariProfile(utls.HelloSafari_Auto, "17.0"),
	Safari180:    safariProfile(utls.HelloSafari_Auto, "18.0"),
	Safari184:    safariProfile(utls.HelloSafari_Auto, "18.4"),
	Safari260:    safariProfile(utls.HelloSafari_Auto, "26.0"),
	Safari2601:   safariProfile(utls.HelloSafari_Auto, "26.0.1"),
	Safari172iOS: safariIOSProfile("17.2"),
	Safari180iOS: safariIOSProfile("18.0"),
	Safari184iOS: safariIOSProfile("18.4"),
	Safari260iOS: safariIOSProfile("26.0"),
}

// --- helper constructors ---

func chromeProfile(helloID utls.ClientHelloID, ver string, h2s []H2Setting) Profile {
	return Profile{
		HelloID:         helloID,
		H2Settings:      h2s,
		H2WindowUpdate:  15663105,
		H2PseudoHeaders: []string{"method", "authority", "scheme", "path"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ver + " Safari/537.36",
	}
}

func firefoxProfile(helloID utls.ClientHelloID, ver string) Profile {
	return Profile{
		HelloID:         helloID,
		H2Settings:      firefox120H2Settings,
		H2WindowUpdate:  12517377,
		H2PseudoHeaders: []string{"method", "path", "authority", "scheme"},
		DefaultUA:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + ver + ") Gecko/20100101 Firefox/" + ver,
	}
}

func safariProfile(helloID utls.ClientHelloID, ver string) Profile {
	return Profile{
		HelloID:         helloID,
		H2Settings:      safari16H2Settings,
		H2WindowUpdate:  10551295,
		H2PseudoHeaders: []string{"method", "scheme", "path", "authority"},
		DefaultUA:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + ver + " Safari/605.1.15",
	}
}

func safariIOSProfile(ver string) Profile {
	return Profile{
		HelloID:         utls.HelloIOS_Auto,
		H2Settings:      safari16H2Settings,
		H2WindowUpdate:  10551295,
		H2PseudoHeaders: []string{"method", "scheme", "path", "authority"},
		DefaultUA:       "Mozilla/5.0 (iPhone; CPU iPhone OS " + ver + " like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + ver + " Mobile/15E148 Safari/604.1",
	}
}

// --- HTTP/2 SETTINGS per browser (from empirical observation) ---

// Chrome 96 H2 settings
var chrome96H2Settings = []H2Setting{
	{h2SettingHeaderTableSize, 65536},
	{h2SettingMaxConcurrentStreams, 1000},
	{h2SettingInitialWindowSize, 6291456},
	{h2SettingMaxHeaderListSize, 262144},
}

// Chrome 100+ H2 settings
var chrome100H2Settings = []H2Setting{
	{h2SettingHeaderTableSize, 65536},
	{h2SettingMaxConcurrentStreams, 1000},
	{h2SettingInitialWindowSize, 6291456},
	{h2SettingMaxHeaderListSize, 262144},
}

// Chrome 120+ H2 settings
var chrome120H2Settings = []H2Setting{
	{h2SettingHeaderTableSize, 65536},
	{h2SettingEnablePush, 0},
	{h2SettingInitialWindowSize, 6291456},
	{h2SettingMaxHeaderListSize, 262144},
}

// Firefox 120 H2 settings
var firefox120H2Settings = []H2Setting{
	{h2SettingHeaderTableSize, 65536},
	{h2SettingInitialWindowSize, 131072},
	{h2SettingMaxFrameSize, 16384},
}

// Safari 16 H2 settings (MAX_CONCURRENT_STREAMS=100, not MAX_HEADER_LIST_SIZE)
var safari16H2Settings = []H2Setting{
	{h2SettingHeaderTableSize, 4096},
	{h2SettingEnablePush, 0},
	{h2SettingMaxConcurrentStreams, 100},
	{h2SettingInitialWindowSize, 2097152},
	{h2SettingMaxFrameSize, 16384},
}

// extra setting ID not in the base consts
const h2SettingMaxConcurrentStreams uint16 = 0x3
