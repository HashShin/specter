package requests

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/HashShin/specter/impersonate"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttp2 "github.com/bogdanfinn/fhttp/http2"
	butls "github.com/bogdanfinn/utls"
	utls "github.com/refraction-networking/utls"
)

// transportOpts holds connection-level options for building a transport.
type transportOpts struct {
	skipVerify  bool
	caFile      string
	proxyURL    *url.URL
	dialTimeout time.Duration
	// ja3Spec is set when a custom JA3 fingerprint overrides the profile HelloID.
	ja3Spec *utls.ClientHelloSpec
}

// buildTransport creates an http.RoundTripper that:
// - Uses refraction-networking/utls for TLS (browser fingerprint via HelloID or custom JA3)
// - Uses bogdanfinn/fhttp http2.Transport for HTTP/2 with full H2 SETTINGS fingerprinting
// - Falls back to HTTP/1.1 for plain HTTP
func buildTransport(profile *impersonate.Profile, opts *transportOpts) http.RoundTripper {
	dialer := &browserDialer{
		profile:     profile,
		skipVerify:  opts.skipVerify,
		caFile:      opts.caFile,
		proxyURL:    opts.proxyURL,
		dialTimeout: opts.dialTimeout,
		ja3Spec:     opts.ja3Spec,
	}

	if profile != nil || opts.ja3Spec != nil {
		return buildFHTTPBridge(dialer, profile)
	}
	return buildH1Transport(dialer)
}

// buildFHTTPBridge creates an http.RoundTripper that uses bogdanfinn/fhttp for HTTP/2
// with full H2 SETTINGS fingerprinting (INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, ENABLE_PUSH,
// pseudo-header order) while using refraction-networking/utls for TLS dialing.
func buildFHTTPBridge(dialer *browserDialer, profile *impersonate.Profile) http.RoundTripper {
	// Build the fhttp/http2 transport with our custom TLS dialer and H2 settings.
	t2 := &fhttp2.Transport{
		// DialTLS injects our refraction-networking/utls dialer.
		// We ignore the bogdanfinn/utls config (cfg) since we manage TLS ourselves.
		DialTLS: func(network, addr string, _ *butls.Config) (net.Conn, error) {
			return dialer.dial(context.Background(), network, addr)
		},
	}

	if profile != nil {
		applyH2Settings(t2, profile)
	}

	return &fhttpBridge{
		h2:     t2,
		dialer: dialer,
	}
}

// applyH2Settings applies a browser profile's H2 fingerprint to an fhttp2.Transport.
func applyH2Settings(t2 *fhttp2.Transport, profile *impersonate.Profile) {
	settings := make(map[fhttp2.SettingID]uint32)
	settingsOrder := make([]fhttp2.SettingID, 0, len(profile.H2Settings))

	for _, s := range profile.H2Settings {
		id := fhttp2.SettingID(s.ID)
		switch id {
		case fhttp2.SettingHeaderTableSize:
			// Must be set directly on the transport, not in the Settings map
			t2.HeaderTableSize = s.Val
		case fhttp2.SettingInitialWindowSize:
			// Must be set directly on the transport, not in the Settings map
			t2.InitialWindowSize = s.Val
		default:
			settings[id] = s.Val
			settingsOrder = append(settingsOrder, id)
		}
	}

	if len(settings) > 0 {
		t2.Settings = settings
		t2.SettingsOrder = settingsOrder
	}

	// Connection-level WINDOW_UPDATE increment (Akamai fingerprint)
	if profile.H2WindowUpdate > 0 {
		t2.ConnectionFlow = profile.H2WindowUpdate
	}

	// Pseudo-header order (:method, :authority, :scheme, :path ordering)
	if len(profile.H2PseudoHeaders) > 0 {
		ph := make([]string, len(profile.H2PseudoHeaders))
		for i, h := range profile.H2PseudoHeaders {
			ph[i] = ":" + h // "method" → ":method"
		}
		t2.PseudoHeaderOrder = ph
	}
}

// buildH1Transport creates an http.Transport backed by our utls dialer (no H2).
func buildH1Transport(dialer *browserDialer) http.RoundTripper {
	return &http.Transport{
		DialTLSContext:      dialer.DialTLSH1,
		DisableCompression:  false,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// fhttpBridge wraps bogdanfinn/fhttp's http2.Transport and implements net/http.RoundTripper.
// It converts between net/http and fhttp request/response types, allowing the rest of the
// codebase to use the standard net/http.Client while gaining full H2 fingerprinting.
type fhttpBridge struct {
	h2     *fhttp2.Transport
	dialer *browserDialer
}

// RoundTrip satisfies net/http.RoundTripper.
func (b *fhttpBridge) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		// Use the fhttp h2 transport for HTTPS (handles H1 fallback via ALPN)
		freq := toFHTTPRequest(req)
		fresp, err := b.h2.RoundTrip(freq)
		if err != nil {
			return nil, err
		}
		return fromFHTTPResponse(fresp, req), nil
	}

	// Plain HTTP: use a standard TCP transport
	plain := &http.Transport{
		DialContext:        b.dialer.DialTCP,
		DisableCompression: false,
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
	}
	return plain.RoundTrip(req)
}

// toFHTTPRequest converts a *net/http.Request to *fhttp.Request.
// The two types are structurally identical; only the named types differ.
func toFHTTPRequest(req *http.Request) *fhttp.Request {
	freq := &fhttp.Request{
		Method:           req.Method,
		URL:              req.URL,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           fhttp.Header(req.Header),
		Body:             req.Body,
		GetBody:          req.GetBody,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            req.Close,
		Host:             req.Host,
		Trailer:          fhttp.Header(req.Trailer),
		RequestURI:       req.RequestURI,
	}
	if req.Form != nil {
		freq.Form = req.Form
	}
	if req.PostForm != nil {
		freq.PostForm = req.PostForm
	}
	if req.MultipartForm != nil {
		freq.MultipartForm = req.MultipartForm
	}
	if req.Context() != nil {
		freq = freq.WithContext(req.Context())
	}
	return freq
}

// fromFHTTPResponse converts a *fhttp.Response to *net/http.Response.
func fromFHTTPResponse(fresp *fhttp.Response, origReq *http.Request) *http.Response {
	resp := &http.Response{
		Status:           fresp.Status,
		StatusCode:       fresp.StatusCode,
		Proto:            fresp.Proto,
		ProtoMajor:       fresp.ProtoMajor,
		ProtoMinor:       fresp.ProtoMinor,
		Header:           http.Header(fresp.Header),
		Body:             fresp.Body,
		ContentLength:    fresp.ContentLength,
		TransferEncoding: fresp.TransferEncoding,
		Close:            fresp.Close,
		Uncompressed:     fresp.Uncompressed,
		Request:          origReq,
	}
	if fresp.Trailer != nil {
		resp.Trailer = http.Header(fresp.Trailer)
	}
	return resp
}

// browserDialer dials TCP connections and wraps them with utls for TLS,
// producing a browser-like TLS ClientHello.
type browserDialer struct {
	profile     *impersonate.Profile
	skipVerify  bool
	caFile      string
	proxyURL    *url.URL
	dialTimeout time.Duration
	ja3Spec     *utls.ClientHelloSpec
}

// DialTLSH1 satisfies http.Transport.DialTLSContext (for H1 fallback).
func (d *browserDialer) DialTLSH1(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

// DialTCP is used for plain HTTP (non-TLS) connections.
func (d *browserDialer) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout()}).DialContext(ctx, network, addr)
}

func (d *browserDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	serverName, _, err := net.SplitHostPort(addr)
	if err != nil {
		serverName = addr
	}

	var rawConn net.Conn
	if d.proxyURL != nil {
		rawConn, err = d.dialThroughProxy(ctx, network, addr)
	} else {
		rawConn, err = (&net.Dialer{Timeout: d.timeout()}).DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	tlsCfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: d.skipVerify,
	}

	// Load custom CA bundle if specified
	if d.caFile != "" && !d.skipVerify {
		pool, err := loadCACerts(d.caFile)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("load CA bundle %q: %w", d.caFile, err)
		}
		tlsCfg.RootCAs = pool
	}

	// Determine TLS HelloID
	helloID := utls.HelloChrome_Auto
	if d.profile != nil {
		helloID = d.profile.HelloID
	}

	uconn := utls.UClient(rawConn, tlsCfg, helloID)

	// Apply custom JA3 spec if provided (overrides the HelloID preset)
	if d.ja3Spec != nil {
		if err := uconn.ApplyPreset(d.ja3Spec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("apply JA3 spec: %w", err)
		}
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", serverName, err)
	}
	return uconn, nil
}

func (d *browserDialer) dialThroughProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyDialer, err := proxyFromURL(d.proxyURL, &net.Dialer{Timeout: d.timeout()})
	if err != nil {
		return nil, err
	}
	return proxyDialer.DialContext(ctx, network, addr)
}

func (d *browserDialer) timeout() time.Duration {
	if d.dialTimeout > 0 {
		return d.dialTimeout
	}
	return 30 * time.Second
}

// proxyFromURL creates a proxy dialer for the given URL scheme.
func proxyFromURL(proxyURL *url.URL, forward *net.Dialer) (contextDialer, error) {
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		return newSOCKS5Dialer(proxyURL, forward), nil
	case "http", "https":
		return newHTTPProxyDialer(proxyURL, forward), nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %q", proxyURL.Scheme)
	}
}

// loadCACerts loads a PEM CA bundle from a file into an x509.CertPool.
func loadCACerts(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}
	return pool, nil
}

type contextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

