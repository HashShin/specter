// Package requests provides a high-level HTTP client with browser-level TLS and
// HTTP/2 fingerprinting, built purely in Go using utls (no CGO, no libcurl).
package requests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"specter/impersonate"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/publicsuffix"
)

// Session is a reusable HTTP client that maintains cookies, connections, and
// browser fingerprint state across multiple requests.
//
// Session is safe for concurrent use from multiple goroutines.
type Session struct {
	mu     sync.RWMutex
	closed bool

	client *http.Client
	jar    *cookiejar.Jar

	// --- Session-level defaults (overridable per request) ---

	// Impersonate sets the default browser fingerprint for all requests.
	Impersonate impersonate.Target

	// JA3 is a custom JA3 fingerprint string applied to all requests.
	// When set, overrides the TLS part of Impersonate.
	JA3 string

	// DefaultHeaders are merged with every request's headers.
	DefaultHeaders map[string]string

	// DefaultCookies are sent with every request.
	DefaultCookies map[string]string

	// Proxy is the default proxy URL ("http://host:port", "socks5://host:port").
	Proxy string

	// Timeout is the default total request timeout (0 = no timeout).
	Timeout time.Duration

	// Verify controls SSL certificate verification.
	// true = verify (default), false = skip, string = path to CA bundle file.
	Verify interface{} // bool or string

	// MaxRedirects is the maximum number of redirects (default 30).
	MaxRedirects int

	// Retry is the default retry strategy for all requests (nil = no retry).
	Retry *RetryStrategy
}

// RetryStrategy configures automatic request retrying on failure.
type RetryStrategy struct {
	// Count is the maximum number of retry attempts (not counting the first try).
	Count int

	// Delay is the base delay between retries.
	Delay time.Duration

	// Jitter adds random noise to the delay to avoid thundering herd.
	Jitter time.Duration

	// Backoff controls how the delay grows: "linear" or "exponential".
	Backoff string // "linear" or "exponential"

	// RetryOn is an optional function that decides whether to retry given the response.
	// If nil, retries on any error or 5xx response.
	RetryOn func(resp *Response, err error) bool
}

// retryDelay computes the delay before retry attempt n (0-indexed).
func (rs *RetryStrategy) retryDelay(attempt int) time.Duration {
	base := rs.Delay
	switch rs.Backoff {
	case "exponential":
		base = time.Duration(float64(base) * math.Pow(2, float64(attempt)))
	default: // linear
		base = time.Duration(float64(base) * float64(attempt+1))
	}
	if rs.Jitter > 0 {
		base += time.Duration(rand.Int63n(int64(rs.Jitter)))
	}
	return base
}

// shouldRetry returns true if the request should be retried.
func (rs *RetryStrategy) shouldRetry(resp *Response, err error) bool {
	if rs.RetryOn != nil {
		return rs.RetryOn(resp, err)
	}
	// Default: retry on any error or 5xx
	if err != nil {
		return true
	}
	return resp != nil && resp.StatusCode >= 500
}

// NewSession creates a new Session. Call Close() when done.
func NewSession() (*Session, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	s := &Session{
		jar:          jar,
		Verify:       true,
		MaxRedirects: 30,
	}
	if err := s.rebuildClient(nil, nil); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases resources held by the session.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

// rebuildClient recreates the http.Client with the given profile and options.
func (s *Session) rebuildClient(profile *impersonate.Profile, ja3Spec *utls.ClientHelloSpec) error {
	var proxyURL *url.URL
	if s.Proxy != "" {
		var err error
		proxyURL, err = url.Parse(s.Proxy)
		if err != nil {
			return fmt.Errorf("invalid proxy URL %q: %w", s.Proxy, err)
		}
	}

	skipVerify := false
	caFile := ""
	switch v := s.Verify.(type) {
	case bool:
		skipVerify = !v
	case string:
		caFile = v
	}

	transport := buildTransport(profile, &transportOpts{
		skipVerify:  skipVerify,
		caFile:      caFile,
		proxyURL:    proxyURL,
		dialTimeout: s.Timeout,
		ja3Spec:     ja3Spec,
	})

	maxRedirs := s.MaxRedirects
	if maxRedirs <= 0 {
		maxRedirs = 30
	}

	s.client = &http.Client{
		Transport: transport,
		Jar:       s.jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirs {
				return fmt.Errorf("stopped after %d redirects", maxRedirs)
			}
			return nil
		},
		Timeout: s.Timeout,
	}
	return nil
}

// --- HTTP verb shortcuts ---

func (s *Session) Get(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("GET", rawURL, opts...)
}
func (s *Session) Post(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("POST", rawURL, opts...)
}
func (s *Session) Put(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("PUT", rawURL, opts...)
}
func (s *Session) Patch(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("PATCH", rawURL, opts...)
}
func (s *Session) Delete(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("DELETE", rawURL, opts...)
}
func (s *Session) Head(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("HEAD", rawURL, opts...)
}
func (s *Session) Options(rawURL string, opts ...Options) (*Response, error) {
	return s.Request("OPTIONS", rawURL, opts...)
}

// Request executes an HTTP request with the given method and options.
// It handles impersonation, retries, and response parsing.
func (s *Session) Request(method, rawURL string, opts ...Options) (*Response, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, fmt.Errorf("session is closed")
	}
	s.mu.RUnlock()

	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	// Resolve browser profile
	target := opt.Impersonate
	if target == "" {
		target = s.Impersonate
	}
	target = impersonate.Normalize(target)

	var profile *impersonate.Profile
	if target != "" {
		p, ok := impersonate.Lookup(target)
		if !ok {
			return nil, fmt.Errorf("unknown browser target %q", target)
		}
		profile = &p
	}

	// Resolve JA3
	ja3str := opt.JA3
	if ja3str == "" {
		ja3str = s.JA3
	}
	var ja3Spec *utls.ClientHelloSpec
	if ja3str != "" {
		spec, err := BuildSpecFromJA3(ja3str)
		if err != nil {
			return nil, fmt.Errorf("JA3 parse: %w", err)
		}
		ja3Spec = spec
	}

	// Rebuild transport for this request's settings
	s.mu.Lock()
	if err := s.rebuildClient(profile, ja3Spec); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	client := s.client
	s.mu.Unlock()

	// Determine retry strategy
	retry := opt.Retry
	if retry == nil {
		retry = s.Retry
	}

	// Execute with retry
	return s.executeWithRetry(client, method, rawURL, profile, &opt, retry)
}

// executeWithRetry runs the request, retrying according to the strategy.
func (s *Session) executeWithRetry(
	client *http.Client,
	method, rawURL string,
	profile *impersonate.Profile,
	opt *Options,
	retry *RetryStrategy,
) (*Response, error) {
	maxAttempts := 1
	if retry != nil && retry.Count > 0 {
		maxAttempts = 1 + retry.Count
	}

	var lastResp *Response
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := retry.retryDelay(attempt - 1)
			if delay > 0 {
				time.Sleep(delay)
			}
		}

		lastResp, lastErr = s.doRequest(client, method, rawURL, profile, opt)

		// Check if we should retry
		if retry == nil || !retry.shouldRetry(lastResp, lastErr) {
			break
		}
		if attempt == maxAttempts-1 {
			break // exhausted retries
		}
	}

	return lastResp, lastErr
}

// doRequest performs a single HTTP request attempt.
func (s *Session) doRequest(
	client *http.Client,
	method, rawURL string,
	profile *impersonate.Profile,
	opt *Options,
) (*Response, error) {
	req, err := s.buildRequest(method, rawURL, profile, opt)
	if err != nil {
		return nil, err
	}

	// Handle redirect override for this request
	actualClient := client
	if opt.AllowRedirects != nil && !*opt.AllowRedirects {
		c := *client
		c.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		actualClient = &c
	}

	// Per-request timeout context
	ctx := context.Background()
	if opt.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
	}
	req = req.WithContext(ctx)

	start := time.Now()

	if opt.Stream {
		// Streaming mode: return without reading body
		return s.doStream(actualClient, req, rawURL, start)
	}

	httpResp, err := actualClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, rawURL, err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	resp := buildResponse(httpResp, respBody, rawURL, elapsed)

	if opt.RaiseForStatus {
		if err := resp.RaiseForStatus(); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

// doStream returns a Response with an open Body reader for streaming.
func (s *Session) doStream(client *http.Client, req *http.Request, rawURL string, start time.Time) (*Response, error) {
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream %s: %w", rawURL, err)
	}
	elapsed := time.Since(start)

	resp := buildResponse(httpResp, nil, rawURL, elapsed)
	resp.BodyStream = httpResp.Body // caller must close
	return resp, nil
}

// buildRequest constructs an *http.Request from method, URL, and options.
func (s *Session) buildRequest(method, rawURL string, profile *impersonate.Profile, opt *Options) (*http.Request, error) {
	method = strings.ToUpper(method)

	finalURL, err := buildURL(rawURL, opt.Params)
	if err != nil {
		return nil, err
	}

	bodyBytes, contentType, err := buildBody(opt)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = strings.NewReader(string(bodyBytes))
	}

	req, err := http.NewRequest(method, finalURL, bodyReader)
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) > 0 {
		req.ContentLength = int64(len(bodyBytes))
	}

	// Browser default headers from profile
	setDefaultHeaders := opt.DefaultHeaders == nil || *opt.DefaultHeaders
	if profile != nil && setDefaultHeaders {
		req.Header.Set("User-Agent", profile.DefaultUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if opt.AcceptEncoding == nil {
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		}
	}

	// Accept-Encoding override
	if opt.AcceptEncoding != nil {
		if *opt.AcceptEncoding == "" {
			req.Header.Del("Accept-Encoding")
		} else {
			req.Header.Set("Accept-Encoding", *opt.AcceptEncoding)
		}
	}

	// Content-Type for body
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Session-level default headers
	for k, v := range s.DefaultHeaders {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// Per-request headers (highest priority)
	for k, v := range opt.Headers {
		if v == "" {
			req.Header.Del(k) // empty string = remove header
		} else {
			req.Header.Set(k, v)
		}
	}

	// Referer
	if opt.Referer != "" {
		req.Header.Set("Referer", opt.Referer)
	}

	// Suppress Expect header (avoids 100-continue round-trip)
	req.Header.Set("Expect", "")

	// Session cookies + per-request cookies (jar handles domain matching)
	allCookies := mergeCookies(s.DefaultCookies, opt.Cookies)
	for name, value := range allCookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	// Basic auth
	if opt.Auth[0] != "" {
		req.SetBasicAuth(opt.Auth[0], opt.Auth[1])
	}

	// Client certificate (TLS mutual auth)
	// Note: client cert is wired at the utls level in the dialer, not here.
	// We store it in opt and the transport reads it. (Future: pass through opts.)

	return req, nil
}

// buildResponse constructs a Response from net/http types.
func buildResponse(r *http.Response, body []byte, requestURL string, elapsed time.Duration) *Response {
	cookies := make([]*Cookie, 0, len(r.Cookies()))
	for _, c := range r.Cookies() {
		cookies = append(cookies, &Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
		})
	}

	effectiveURL := r.Request.URL.String()
	if effectiveURL == "" {
		effectiveURL = requestURL
	}

	return &Response{
		URL:           effectiveURL,
		StatusCode:    r.StatusCode,
		Status:        r.Status,
		OK:            r.StatusCode >= 200 && r.StatusCode < 400,
		Proto:         r.Proto,
		Headers:       r.Header,
		Cookies:       cookies,
		Body:          body,
		ContentLength: r.ContentLength,
		Elapsed:       elapsed,
	}
}

// --- Helpers ---

func buildURL(rawURL string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildBody(opt *Options) ([]byte, string, error) {
	if len(opt.Body) > 0 {
		ct := opt.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		return opt.Body, ct, nil
	}
	if opt.JSON != nil {
		b, err := json.Marshal(opt.JSON)
		if err != nil {
			return nil, "", err
		}
		return b, "application/json", nil
	}
	if len(opt.Form) > 0 {
		vals := url.Values{}
		for k, v := range opt.Form {
			vals.Set(k, v)
		}
		return []byte(vals.Encode()), "application/x-www-form-urlencoded", nil
	}
	return nil, "", nil
}

func mergeCookies(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
