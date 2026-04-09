package requests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Cookie holds a single HTTP cookie from a response.
type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Expires  time.Time
	Secure   bool
	HTTPOnly bool
}

// Response represents a completed HTTP response.
type Response struct {
	// URL is the final URL (after redirects).
	URL string

	// StatusCode is the HTTP status code (200, 404, etc.).
	StatusCode int

	// Status is the full status text ("200 OK", "404 Not Found", etc.).
	Status string

	// OK is true when StatusCode is in [200, 400).
	OK bool

	// Proto is the HTTP version used ("HTTP/1.1", "HTTP/2.0", etc.).
	Proto string

	// Headers are the response headers.
	Headers http.Header

	// Cookies are the response cookies parsed from Set-Cookie headers.
	Cookies []*Cookie

	// Body is the response body as a string.
	// Empty when Stream is true (use BodyStream instead).
	Body string

	// BodyStream is the open response body reader when Stream was true.
	// The caller MUST close this when done.
	BodyStream io.ReadCloser

	// ContentLength is the declared content length (-1 if unknown).
	ContentLength int64

	// Elapsed is the total time from request start to body read complete.
	Elapsed time.Duration
}

// Text returns the response body as a string (same as Body).
func (r *Response) Text() string {
	return r.Body
}

// JSON unmarshals the response body into v.
func (r *Response) JSON(v interface{}) error {
	return json.Unmarshal([]byte(r.Body), v)
}

// RaiseForStatus returns an HTTPError if StatusCode >= 400, nil otherwise.
func (r *Response) RaiseForStatus() error {
	if r.StatusCode >= 400 {
		return &HTTPError{StatusCode: r.StatusCode, Status: r.Status, URL: r.URL}
	}
	return nil
}

// ContentType returns the Content-Type header value.
func (r *Response) ContentType() string {
	return r.Headers.Get("Content-Type")
}

// Cookie returns the named cookie from the response, or nil if not found.
func (r *Response) Cookie(name string) *Cookie {
	for _, c := range r.Cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// HTTPError is returned by RaiseForStatus for 4xx/5xx responses.
type HTTPError struct {
	StatusCode int
	Status     string
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d %s for %s", e.StatusCode, e.Status, e.URL)
}
