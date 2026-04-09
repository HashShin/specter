package requests

import (
	"time"

	"github.com/HashShin/specter/impersonate"
)

// Options configures a single HTTP request.
// All fields are optional; zero values use sensible defaults.
type Options struct {
	// --- Browser fingerprinting ---

	// Impersonate sets a browser fingerprint for this request.
	// Overrides the session-level Impersonate setting.
	// Example: impersonate.Chrome146, "firefox147", "safari"
	Impersonate impersonate.Target

	// DefaultHeaders controls whether browser-default headers (User-Agent, Accept, etc.)
	// are automatically added. nil = use session default (true).
	DefaultHeaders *bool

	// --- Request ---

	// Params are URL query parameters appended to the URL.
	Params map[string]string

	// Headers are additional/override request headers.
	Headers map[string]string

	// Body is the raw request body (takes precedence over JSON and Form).
	Body []byte

	// JSON is a raw JSON string sent as the request body.
	// Automatically sets Content-Type: application/json.
	// Example: `{"key": "value"}`
	JSON string

	// Form is a URL-encoded string sent as the request body.
	// Automatically sets Content-Type: application/x-www-form-urlencoded.
	// Example: "key=value&foo=bar"
	Form string

	// Cookies are per-request cookies (session cookies from the jar are also sent).
	Cookies map[string]string

	// Auth is HTTP Basic Authentication [username, password].
	Auth [2]string

	// --- Network ---

	// Proxy overrides the session proxy for this request.
	// Format: "http://host:port", "socks5://host:port"
	Proxy string

	// Verify controls SSL certificate verification for this request.
	// true/nil = verify, false = skip, string = path to CA bundle.
	Verify interface{} // bool or string (overrides session Verify)

	// CertFile is the path to a client certificate (PEM).
	CertFile string

	// KeyFile is the path to the client certificate private key.
	KeyFile string

	// Interface is the network interface to bind to (not yet implemented).
	Interface string

	// --- Behavior ---

	// Timeout is the total request timeout (0 = use session timeout).
	Timeout time.Duration

	// AllowRedirects controls redirect following (nil = true).
	AllowRedirects *bool

	// MaxRedirects overrides the session max redirects.
	MaxRedirects int

	// AcceptEncoding overrides the Accept-Encoding header.
	// nil = use default ("gzip, deflate, br, zstd").
	// &"" = disable Accept-Encoding entirely.
	AcceptEncoding *string

	// Referer sets the Referer request header.
	Referer string

	// MaxRecvSpeed is not yet implemented (placeholder for future rate limiting).
	MaxRecvSpeed int64

	// --- Streaming & errors ---

	// Stream controls whether the response body is returned as an open io.Reader.
	// When true, Response.BodyStream is set and must be closed by the caller.
	// Response.Body will be nil.
	Stream bool

	// RaiseForStatus automatically calls resp.RaiseForStatus() and returns the
	// HTTPError if the response status is 4xx or 5xx.
	RaiseForStatus bool

	// ContentType sets the Content-Type header when Body (raw bytes) is used.
	// Defaults to "application/octet-stream" when Body is set without ContentType.
	ContentType string

	// JA3 is a custom JA3 fingerprint string for this request.
	// Overrides both the session-level JA3 and the Impersonate TLS fingerprint.
	JA3 string

	// Retry is the retry strategy for this request.
	// Overrides the session-level Retry setting.
	Retry *RetryStrategy
}

// boolPtr returns a pointer to b. Useful for setting *bool fields inline.
func boolPtr(b bool) *bool { return &b }

// strPtr returns a pointer to s. Useful for setting *string fields inline.
func strPtr(s string) *string { return &s }
