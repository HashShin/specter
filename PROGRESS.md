# curl_cffi_go — Progress Tracker

> **Purpose**: Port of Python `curl_cffi` to Go — a browser-impersonating HTTP client.
> This file tracks completed work, architecture decisions, and what's next.
> Any agent continuing this work should read this first.

---

## Architecture Decision: Pure Go (no CGO, no libcurl)

We initially tried CGO bindings to `libcurl-impersonate.so`, but abandoned it because:
- `libcurl-impersonate.so` was compiled for glibc; Android/Bionic libc doesn't have `__errno_location`, `explicit_bzero`, `getservbyport_r`
- Static linking (.a) required C++ runtime (`__cxa_begin_catch`, vtables) compiled with Zig's libc++ — not compatible with Android
- Go's CGO LDFLAGS security check blocks `--export-dynamic-symbol=X` flags needed to export stub symbols

**Solution**: Pure Go using `refraction-networking/utls` + `bogdanfinn/fhttp`:
- `utls` is a fork of `crypto/tls` that gives byte-level control over TLS ClientHello (JA3)
- `fhttp` is a fork of `net/http` + `x/net/http2` with full H2 SETTINGS/WINDOW_UPDATE/pseudo-header control (Akamai)
- No CGO, no C libraries, cross-platform single binary

---

## What "browser impersonation" actually does

Bot detection systems check three fingerprint layers:

| Layer | What's checked | How we handle it |
|-------|---------------|-----------------|
| **TLS (JA3)** | Cipher suites, extensions, EC curves, GREASE, ordering in ClientHello | `refraction-networking/utls` generates exact browser ClientHello |
| **HTTP/2 (Akamai)** | SETTINGS frame values, WINDOW_UPDATE size, pseudo-header order | `bogdanfinn/fhttp/http2.Transport` with per-profile settings |
| **HTTP headers** | User-Agent, Accept, Accept-Language, ordering | Set from `Profile.DefaultUA` and default headers |

---

## Project Structure

```
curl_cffi_go/
├── cmd/
│   └── curl-cffi/
│       └── main.go         # CLI tool: curl-cffi [get|post|...] <url> --impersonate chrome
├── impersonate/
│   └── impersonate.go      # Browser targets → Profile (utls HelloID + H2 settings + UA)
│   └── impersonate_test.go # Unit tests for profile lookup and normalization
├── requests/
│   ├── session.go          # Session: cookie jar + HTTP client + request building + retry
│   ├── options.go          # Options struct for per-request config (Stream, Retry, JA3, ...)
│   ├── response.go         # Response struct (status, headers, body, BodyStream, cookies)
│   ├── transport.go        # fhttpBridge: net/http ↔ fhttp/http2 adapter with utls TLS
│   ├── proxy.go            # HTTP CONNECT tunnel + SOCKS5 proxy dialers (pure Go)
│   ├── requests.go         # Package-level convenience functions (Get/Post/etc.)
│   ├── ja3.go              # JA3 fingerprint string → utls ClientHelloSpec parser
│   ├── ja3_test.go         # Unit tests for JA3 parsing and GREASE detection
│   ├── session_test.go     # Unit tests for session, body building, retry strategy
│   └── dns.go              # Auto-sets GODEBUG=netdns=go for Android DNS compatibility
├── examples/
│   └── basic/main.go       # Working example with all 5 use cases
├── go.mod                  # Module: curl_cffi_go, Go 1.25+
├── go.sum
└── PROGRESS.md             # This file
```

**Dependencies:**
- `github.com/refraction-networking/utls v1.8.2` — TLS fingerprinting (JA3)
- `github.com/bogdanfinn/fhttp v0.6.8` — HTTP/2 fingerprinting (Akamai H2 settings)
- `github.com/bogdanfinn/utls v1.7.7-barnius` — required by fhttp (not used for TLS dialing)
- `golang.org/x/net v0.52.0` — transitive (HTTP/2 base)
- `golang.org/x/crypto` — crypto primitives (transitive)
- `golang.org/x/text` — IDNA (transitive)

---

## ✅ Completed

### Phase 1: Core HTTP + Impersonation
- [x] `impersonate` package: all browser targets from curl_cffi Python (Chrome 99–146, Firefox 133–147, Safari 153–2601, Edge 99/101, Tor 145, Android variants)
- [x] `Browser Profile` struct: maps target → utls HelloID + H2 Settings + Window Update + Pseudo-header order + Default UA
- [x] `Session` type: persistent cookie jar (net/http/cookiejar), connection pooling, rebuilds transport on impersonate change
- [x] All HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- [x] Package-level convenience functions: `requests.Get()`, `requests.Post()`, etc.
- [x] Request options: URL params, custom headers, JSON body, form body, raw bytes
- [x] Response type: status, headers, cookies, body, elapsed time, proto
- [x] Basic auth support
- [x] Cookie management (session-level jar + per-request cookies)
- [x] SSL verification control (verify bool, skip verification, custom CA path)
- [x] Redirect control (AllowRedirects, MaxRedirects)
- [x] Timeout support (per-request context timeout)
- [x] Proxy support: HTTP CONNECT tunnel + SOCKS5 (pure Go)
- [x] DNS fix for Android/Termux (auto-sets GODEBUG=netdns=go)

### Phase 2: HTTP/2 Fingerprint Fidelity (Akamai)
- [x] Replaced `golang.org/x/net/http2` with `bogdanfinn/fhttp/http2` for H2 transport
- [x] `fhttpBridge`: wraps fhttp/http2.Transport as net/http.RoundTripper (request/response conversion)
- [x] Full H2 SETTINGS: INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, ENABLE_PUSH, MAX_HEADER_LIST_SIZE, MAX_CONCURRENT_STREAMS, HEADER_TABLE_SIZE
- [x] Connection-level WINDOW_UPDATE size (`ConnectionFlow` per profile)
- [x] Pseudo-header order (`:method`, `:authority`, `:scheme`, `:path` ordering per browser)
- [x] TLS dialing: still uses `refraction-networking/utls` (not bogdanfinn/utls) for wider browser profile support
- [x] Custom JA3 spec support: `BuildSpecFromJA3()` → `uconn.ApplyPreset()`

### Phase 3: Custom JA3 Fingerprints
- [x] `ja3.go`: `BuildSpecFromJA3(string) (*utls.ClientHelloSpec, error)` — parses JA3 into utls spec
- [x] Maps all standard TLS extension IDs to utls TLSExtension implementations
- [x] GREASE detection and correct GREASE extension insertion
- [x] `Session.JA3` field: session-level custom JA3
- [x] `Options.JA3` field: per-request custom JA3 (overrides session)
- [x] Fixed GREASE detection bug (was only matching 0xaaaa; now matches all 0x?a?a values)

### Phase 4: Advanced Features
- [x] **Streaming**: `Options.Stream = true` → `Response.BodyStream io.ReadCloser` (caller must close)
- [x] **Retry strategy**: `RetryStrategy{Count, Delay, Jitter, Backoff, RetryOn}` at session and request level
  - Linear and exponential backoff
  - Random jitter
  - Custom `RetryOn` callback or default (error or 5xx)
- [x] **Custom CA bundle**: `Options.Verify = "/path/to/ca.pem"` — loads PEM bundle via `loadCACerts()`
- [x] **RaiseForStatus**: `Options.RaiseForStatus = true` auto-returns HTTPError for 4xx/5xx
- [x] **ContentType override**: `Options.ContentType` for raw Body requests

### Phase 5: CLI Tool
- [x] `cmd/curl-cffi/main.go` — full-featured CLI
  - Subcommands: `get`, `post`, `put`, `patch`, `delete`, `head` (default: GET)
  - `--impersonate` / `-i`: browser target (chrome, firefox, safari, edge, ...)
  - `--ja3`: custom JA3 string
  - `--header` / `-H`: add headers (repeatable)
  - `--data` / `-d`: raw body
  - `--json` / `-j`: JSON body
  - `--form` / `-F`: form fields (repeatable)
  - `--proxy`: proxy URL
  - `--no-verify`: skip TLS verification
  - `--cacert`: custom CA bundle
  - `--timeout`: request timeout (e.g. `30s`, `1m`)
  - `--output` / `-o`: write body to file
  - `--head` / `-I`: HEAD request
  - `--include`: include response headers in output
  - `--no-follow`: disable redirect following
  - `--max-redirects`: max redirect count
  - `--verbose` / `-v`: verbose output (request headers)
  - `--silent` / `-s`: suppress status line
  - `--retry`: retry count
  - `--retry-delay`: base retry delay
  - `--list-targets`: list all supported impersonation targets

### Phase 6: Testing
- [x] Unit tests for `impersonate` package:
  - `TestNormalize`: all alias → canonical mappings
  - `TestLookup`: all canonical targets have valid profiles
  - `TestLookupUnknown`: unknown targets return ok=false
  - `TestLookupViaAlias`: aliases resolve through Lookup
  - `TestProfileH2PseudoHeaders`: pseudo-header values are valid
- [x] Unit tests for `requests` package:
  - `TestBuildSpecFromJA3_Valid`: Chrome 133 JA3 parses correctly
  - `TestBuildSpecFromJA3_InvalidFormat`: error cases for malformed JA3
  - `TestBuildSpecFromJA3_EmptyExtensions/EmptyCurves`: edge cases
  - `TestIsGREASE`: all 16 GREASE values detected, non-GREASE rejected
  - `TestJA3TLSRange`: TLS version mapping
  - `TestNewSession`, `TestBuildURL`, `TestBuildBody`, `TestMergeCookies`
  - `TestRetryStrategy`: linear and exponential backoff delays
  - `TestRetryStrategy_ShouldRetry`: default retry decision logic
  - `TestSessionClosed`: closed session returns error

---

## Known Issues / Limitations

1. **DNS on Android/Termux**: Go's default DNS resolver doesn't work on Android without `GODEBUG=netdns=go`. Fixed via `requests/dns.go` `init()` — sets this automatically.

2. **fhttp DialTLS has no context**: `fhttp/http2.Transport.DialTLS` doesn't take a `context.Context`, so request cancellation during TLS handshake in H2 mode won't propagate perfectly. Workaround: per-request `Timeout` uses `context.WithTimeout` on the HTTP layer.

3. **Transport rebuilt on each Request()**: `rebuildClient()` is called every request, even if nothing changed. This causes connection pool reset on every request. Fix: cache the last (profile, ja3, proxy, verify) tuple and skip rebuild if unchanged.

4. **No integration tests against live servers**: The tests in Phase 6 are unit tests only. Live TLS fingerprint verification against tls.peet.ws or h2.peet.ws is manual only (see "How to Verify" below).

---

## How to Verify TLS + H2 Fingerprints

```go
resp, _ := requests.Get("https://tls.peet.ws/api/all", requests.Options{
    Impersonate: impersonate.Chrome146,
})
fmt.Println(resp.Text()) // Shows ja3, ja3_hash, akamai, http2 fingerprints
```

Compare `ja3` field to Chrome's known JA3:
- Chrome 133: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0`

Compare `http2` → `akamai_fingerprint` to Chrome's known Akamai:
- Chrome: `1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p`

CLI verification:
```bash
go run ./cmd/curl-cffi https://tls.peet.ws/api/all --impersonate chrome
```

---

## Building & Running

```bash
# In /root/curl_cffi_go/
go build ./...                                  # Compile everything
go test ./...                                   # Run all unit tests
go run examples/basic/main.go                   # Run example
go run ./cmd/curl-cffi https://httpbin.org/get  # CLI

# Build CLI binary
go build -o curl-cffi ./cmd/curl-cffi/

# Cross-compile for Linux amd64
GOOS=linux GOARCH=amd64 go build ./...

# Android/ARM64
GOOS=android GOARCH=arm64 go build ./...
```

---

## Environment Notes

- Developed on: Android/ARM64 (Termux), Go 1.26.1
- Pure Go — no CGO, no C dependencies
- utls version: v1.8.2 (HelloChrome_Auto = Chrome 133, HelloFirefox_Auto = Firefox 120)
- fhttp version: v0.6.8
