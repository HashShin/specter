package requests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
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
	ja3Spec     *utls.ClientHelloSpec
}

// buildTransport creates an http.RoundTripper.
// Without a browser profile or custom JA3, it returns a standard Go transport that
// handles HTTP/1.1 and HTTP/2 via ALPN automatically.
// With a profile, it returns an fhttpBridge that uses utls for TLS fingerprinting and
// routes to HTTP/2 or HTTP/1.1 based on the ALPN-negotiated protocol.
func buildTransport(profile *impersonate.Profile, opts *transportOpts) http.RoundTripper {
	if profile == nil && opts.ja3Spec == nil {
		return buildStandardTransport(opts)
	}
	dialer := &browserDialer{
		profile:     profile,
		skipVerify:  opts.skipVerify,
		caFile:      opts.caFile,
		proxyURL:    opts.proxyURL,
		dialTimeout: opts.dialTimeout,
		ja3Spec:     opts.ja3Spec,
	}
	return buildFHTTPBridge(dialer, profile)
}

// buildStandardTransport returns a plain net/http transport with standard Go TLS.
// It handles HTTP/1.1 and HTTP/2 via ALPN automatically — no browser fingerprinting.
func buildStandardTransport(opts *transportOpts) http.RoundTripper {
	tlsCfg := &tls.Config{InsecureSkipVerify: opts.skipVerify}
	if opts.caFile != "" && !opts.skipVerify {
		if pool, err := loadCACerts(opts.caFile); err == nil {
			tlsCfg.RootCAs = pool
		}
	}
	t := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DisableCompression:  false,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if opts.proxyURL != nil {
		t.Proxy = http.ProxyURL(opts.proxyURL)
	}
	return t
}

// negotiatedConn wraps a utls connection and exposes the ALPN-negotiated protocol.
type negotiatedConn struct {
	net.Conn
	proto string // "h2", "http/1.1", or "" (no ALPN)
}

// fhttpBridge routes HTTPS requests to HTTP/2 (fhttp2 with H2 fingerprinting) or
// HTTP/1.1 based on the ALPN protocol negotiated by the utls TLS handshake.
type fhttpBridge struct {
	t2     *fhttp2.Transport // configured with browser H2 SETTINGS
	dialer *browserDialer
}

// buildFHTTPBridge creates an fhttpBridge with browser H2 settings applied.
func buildFHTTPBridge(dialer *browserDialer, profile *impersonate.Profile) http.RoundTripper {
	// t2 is used only for NewClientConn (its DialTLS is never called directly).
	t2 := &fhttp2.Transport{
		DialTLS: func(network, addr string, _ *butls.Config) (net.Conn, error) {
			return dialer.dial(context.Background(), network, addr)
		},
	}
	if profile != nil {
		applyH2Settings(t2, profile)
	}
	return &fhttpBridge{t2: t2, dialer: dialer}
}

// applyH2Settings applies a browser profile's H2 fingerprint to an fhttp2.Transport.
func applyH2Settings(t2 *fhttp2.Transport, profile *impersonate.Profile) {
	settings := make(map[fhttp2.SettingID]uint32)
	settingsOrder := make([]fhttp2.SettingID, 0, len(profile.H2Settings))

	for _, s := range profile.H2Settings {
		id := fhttp2.SettingID(s.ID)
		switch id {
		case fhttp2.SettingHeaderTableSize:
			t2.HeaderTableSize = s.Val
		case fhttp2.SettingInitialWindowSize:
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

	if profile.H2WindowUpdate > 0 {
		t2.ConnectionFlow = profile.H2WindowUpdate
	}

	if len(profile.H2PseudoHeaders) > 0 {
		ph := make([]string, len(profile.H2PseudoHeaders))
		for i, h := range profile.H2PseudoHeaders {
			ph[i] = ":" + h
		}
		t2.PseudoHeaderOrder = ph
	}
}

// RoundTrip satisfies net/http.RoundTripper.
// For HTTPS: pre-dials with utls, checks ALPN, routes to H2 or H1.
// For HTTP: uses a plain TCP transport.
func (b *fhttpBridge) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		plain := &http.Transport{DialContext: b.dialer.DialTCP}
		return plain.RoundTrip(req)
	}

	// Pre-dial to determine ALPN-negotiated protocol.
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	conn, err := b.dialer.dial(req.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	nc := conn.(*negotiatedConn)

	if nc.proto == "h2" {
		return b.roundTripH2(req, nc.Conn)
	}
	return b.roundTripH1(req, nc.Conn)
}

// roundTripH2 uses fhttp2.Transport.NewClientConn to establish an HTTP/2 connection
// on the pre-dialed utls conn, preserving the configured H2 SETTINGS fingerprint.
func (b *fhttpBridge) roundTripH2(req *http.Request, conn net.Conn) (*http.Response, error) {
	cc, err := b.t2.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("h2 client conn: %w", err)
	}
	freq := toFHTTPRequest(req)
	fresp, err := cc.RoundTrip(freq)
	if err != nil {
		return nil, err
	}
	return fromFHTTPResponse(fresp, req), nil
}

// roundTripH1 sends an HTTP/1.1 request over the pre-dialed utls connection.
func (b *fhttpBridge) roundTripH1(req *http.Request, conn net.Conn) (*http.Response, error) {
	var used int32
	t := &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			if atomic.CompareAndSwapInt32(&used, 0, 1) {
				return conn, nil
			}
			return nil, fmt.Errorf("connection already used")
		},
		DisableKeepAlives: true,
	}
	resp, err := t.RoundTrip(req)
	if err != nil {
		conn.Close()
	}
	return resp, err
}

// toFHTTPRequest converts a *net/http.Request to *fhttp.Request.
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

// browserDialer dials TCP connections and wraps them with utls for TLS fingerprinting.
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
	conn, err := d.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return conn.(*negotiatedConn).Conn, nil
}

// DialTCP is used for plain HTTP (non-TLS) connections.
func (d *browserDialer) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout()}).DialContext(ctx, network, addr)
}

// dial establishes a TLS connection using utls and returns a negotiatedConn
// that exposes the ALPN-negotiated protocol ("h2", "http/1.1", or "").
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

	if d.caFile != "" && !d.skipVerify {
		pool, err := loadCACerts(d.caFile)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("load CA bundle %q: %w", d.caFile, err)
		}
		tlsCfg.RootCAs = pool
	}

	helloID := utls.HelloChrome_Auto
	if d.profile != nil {
		helloID = d.profile.HelloID
	}

	uconn := utls.UClient(rawConn, tlsCfg, helloID)

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

	proto := uconn.ConnectionState().NegotiatedProtocol
	return &negotiatedConn{Conn: uconn, proto: proto}, nil
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
