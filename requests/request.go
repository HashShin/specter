package requests

import (
	"strings"
	"time"

	"github.com/HashShin/specter/impersonate"
)

// Headers is a list of raw "Key: Value" header strings.
//
//	Headers{
//	    "Content-Type: application/json",
//	    "User-Agent: Mozilla/5.0 ...",
//	}
type Headers []string

// toMap converts Headers into a map for use with Options.
func (h Headers) toMap() map[string]string {
	m := make(map[string]string, len(h))
	for _, raw := range h {
		k, v, ok := strings.Cut(raw, ":")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// Request describes a single HTTP request in a struct-literal style.
//
//	req := requests.Request{
//	    Method: "GET",
//	    URL:    "https://httpbin.org/get",
//	    Headers: requests.Headers{
//	        "Accept: application/json",
//	        "X-Custom: value",
//	    },
//	    Impersonate: impersonate.Chrome146,
//	}
//	resp, err := sess.Send(req)
type Request struct {
	Method string // GET, POST, PUT, PATCH, DELETE, HEAD (default: GET)
	URL    string

	// Fingerprinting
	Impersonate impersonate.Target
	JA3         string

	// Headers as "Key: Value" strings
	Headers Headers

	// Query parameters appended to the URL
	Params map[string]string

	// Body — use one at a time
	Body []byte      // raw bytes
	JSON interface{} // marshalled to JSON
	Form map[string]string

	// Auth & cookies
	Auth    [2]string         // [username, password] for Basic Auth
	Cookies map[string]string

	// Network
	Proxy   string
	Verify  interface{} // bool or path string to CA bundle
	Timeout time.Duration

	// Behaviour
	AllowRedirects *bool
	MaxRedirects   int
	Stream         bool
	RaiseForStatus bool
	Retry          *RetryStrategy
}

// toOptions converts a Request into the internal Options type.
func (r Request) toOptions() Options {
	opt := Options{
		Impersonate:    r.Impersonate,
		JA3:            r.JA3,
		Params:         r.Params,
		Body:           r.Body,
		JSON:           r.JSON,
		Form:           r.Form,
		Auth:           r.Auth,
		Cookies:        r.Cookies,
		Proxy:          r.Proxy,
		Verify:         r.Verify,
		Timeout:        r.Timeout,
		AllowRedirects: r.AllowRedirects,
		MaxRedirects:   r.MaxRedirects,
		Stream:         r.Stream,
		RaiseForStatus: r.RaiseForStatus,
		Retry:          r.Retry,
	}
	if len(r.Headers) > 0 {
		opt.Headers = r.Headers.toMap()
	}
	return opt
}

// Send executes the Request using this Session.
//
//	resp, err := sess.Send(requests.Request{
//	    Method: "POST",
//	    URL:    "https://httpbin.org/post",
//	    Headers: requests.Headers{
//	        "Content-Type: application/json",
//	    },
//	    JSON: map[string]any{"key": "value"},
//	    Impersonate: impersonate.Chrome146,
//	})
func (s *Session) Send(req Request) (*Response, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	return s.Request(method, req.URL, req.toOptions())
}

// Send executes a one-shot Request without a persistent session.
func Send(req Request) (*Response, error) {
	sess, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.Send(req)
}
