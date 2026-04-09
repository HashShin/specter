package requests

import (
	"strings"
	"testing"
	"time"
)

// TestNewSession verifies that NewSession creates a functional session.
func TestNewSession(t *testing.T) {
	sess, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if sess.client == nil {
		t.Error("session.client should not be nil")
	}
	if sess.jar == nil {
		t.Error("session.jar should not be nil")
	}
}

// TestBuildURL verifies URL construction with query parameters.
func TestBuildURL(t *testing.T) {
	cases := []struct {
		rawURL string
		params map[string]string
		want   string
	}{
		{"https://example.com", nil, "https://example.com"},
		{"https://example.com", map[string]string{"a": "1"}, "https://example.com?a=1"},
		{"https://example.com?x=y", map[string]string{"a": "1"}, "https://example.com?a=1&x=y"},
	}

	for _, tc := range cases {
		got, err := buildURL(tc.rawURL, tc.params)
		if err != nil {
			t.Errorf("buildURL(%q): %v", tc.rawURL, err)
			continue
		}
		// Order of params may vary; check for presence
		for k, v := range tc.params {
			kv := k + "=" + v
			if !strings.Contains(got, kv) {
				t.Errorf("buildURL(%q, %v) = %q, missing %q", tc.rawURL, tc.params, got, kv)
			}
		}
	}
}

// TestBuildBody verifies request body construction.
func TestBuildBody(t *testing.T) {
	t.Run("raw body", func(t *testing.T) {
		opt := &Options{Body: []byte("hello"), ContentType: "text/plain"}
		body, ct, err := buildBody(opt)
		if err != nil {
			t.Fatalf("buildBody: %v", err)
		}
		if string(body) != "hello" {
			t.Errorf("body = %q, want %q", body, "hello")
		}
		if ct != "text/plain" {
			t.Errorf("content-type = %q, want %q", ct, "text/plain")
		}
	})

	t.Run("raw body default content-type", func(t *testing.T) {
		opt := &Options{Body: []byte("data")}
		_, ct, err := buildBody(opt)
		if err != nil {
			t.Fatalf("buildBody: %v", err)
		}
		if ct != "application/octet-stream" {
			t.Errorf("content-type = %q, want %q", ct, "application/octet-stream")
		}
	})

	t.Run("JSON body", func(t *testing.T) {
		opt := &Options{Body: []byte(`{"key":"value"}`), ContentType: "application/json"}
		body, ct, err := buildBody(opt)
		if err != nil {
			t.Fatalf("buildBody: %v", err)
		}
		if ct != "application/json" {
			t.Errorf("content-type = %q, want %q", ct, "application/json")
		}
		if !strings.Contains(string(body), "key") {
			t.Errorf("JSON body missing key: %q", body)
		}
	})

	t.Run("form body", func(t *testing.T) {
		opt := &Options{Body: []byte("foo=bar&baz=qux"), ContentType: "application/x-www-form-urlencoded"}
		body, ct, err := buildBody(opt)
		if err != nil {
			t.Fatalf("buildBody: %v", err)
		}
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q, want %q", ct, "application/x-www-form-urlencoded")
		}
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "foo=bar") || !strings.Contains(bodyStr, "baz=qux") {
			t.Errorf("form body = %q, missing expected fields", bodyStr)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		opt := &Options{}
		body, ct, err := buildBody(opt)
		if err != nil {
			t.Fatalf("buildBody: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("expected empty body, got %q", body)
		}
		if ct != "" {
			t.Errorf("expected empty content-type, got %q", ct)
		}
	})
}

// TestMergeCookies verifies cookie merging behavior.
func TestMergeCookies(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		out := mergeCookies(nil, nil)
		if len(out) != 0 {
			t.Errorf("expected empty map, got %v", out)
		}
	})

	t.Run("merge", func(t *testing.T) {
		a := map[string]string{"session": "abc", "shared": "from-a"}
		b := map[string]string{"csrf": "xyz", "shared": "from-b"}
		out := mergeCookies(a, b)
		if out["session"] != "abc" {
			t.Errorf("session cookie missing")
		}
		if out["csrf"] != "xyz" {
			t.Errorf("csrf cookie missing")
		}
		// b overrides a for shared keys
		if out["shared"] != "from-b" {
			t.Errorf("shared cookie: got %q, want %q", out["shared"], "from-b")
		}
	})
}

// TestRetryStrategy verifies retry delay calculation.
func TestRetryStrategy(t *testing.T) {
	t.Run("linear backoff", func(t *testing.T) {
		rs := &RetryStrategy{Delay: 100 * time.Millisecond, Backoff: "linear"}
		d0 := rs.retryDelay(0)
		d1 := rs.retryDelay(1)
		d2 := rs.retryDelay(2)
		if d0 != 100*time.Millisecond {
			t.Errorf("linear attempt 0: %v, want 100ms", d0)
		}
		if d1 != 200*time.Millisecond {
			t.Errorf("linear attempt 1: %v, want 200ms", d1)
		}
		if d2 != 300*time.Millisecond {
			t.Errorf("linear attempt 2: %v, want 300ms", d2)
		}
	})

	t.Run("exponential backoff", func(t *testing.T) {
		rs := &RetryStrategy{Delay: 100 * time.Millisecond, Backoff: "exponential"}
		d0 := rs.retryDelay(0)
		d1 := rs.retryDelay(1)
		d2 := rs.retryDelay(2)
		if d0 != 100*time.Millisecond {
			t.Errorf("exp attempt 0: %v, want 100ms", d0)
		}
		if d1 != 200*time.Millisecond {
			t.Errorf("exp attempt 1: %v, want 200ms", d1)
		}
		if d2 != 400*time.Millisecond {
			t.Errorf("exp attempt 2: %v, want 400ms", d2)
		}
	})
}

// TestRetryStrategy_ShouldRetry verifies default retry decision logic.
func TestRetryStrategy_ShouldRetry(t *testing.T) {
	rs := &RetryStrategy{}

	// Should retry on error
	if !rs.shouldRetry(nil, errTest) {
		t.Error("should retry on error")
	}

	// Should retry on 5xx
	resp5xx := &Response{StatusCode: 500}
	if !rs.shouldRetry(resp5xx, nil) {
		t.Error("should retry on 500")
	}

	// Should NOT retry on 4xx
	resp4xx := &Response{StatusCode: 404}
	if rs.shouldRetry(resp4xx, nil) {
		t.Error("should not retry on 404")
	}

	// Should NOT retry on 2xx
	resp2xx := &Response{StatusCode: 200}
	if rs.shouldRetry(resp2xx, nil) {
		t.Error("should not retry on 200")
	}
}

// errTest is a sentinel error for testing.
type testError string

func (e testError) Error() string { return string(e) }

var errTest testError = "test error"

// TestSessionClosed verifies that a closed session returns an error.
func TestSessionClosed(t *testing.T) {
	sess, err := NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	sess.Close()

	_, err = sess.Get("https://example.com")
	if err == nil {
		t.Error("expected error from closed session, got nil")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("error should mention 'closed', got %q", err.Error())
	}
}
