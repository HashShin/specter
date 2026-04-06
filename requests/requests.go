package requests

// Package-level convenience functions that create a one-shot Session per call.
// For multiple requests, prefer Session directly to reuse connections and cookies.

func Get(rawURL string, opts ...Options) (*Response, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Get(rawURL, opts...)
}

func Post(rawURL string, opts ...Options) (*Response, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Post(rawURL, opts...)
}

func Put(rawURL string, opts ...Options) (*Response, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Put(rawURL, opts...)
}

func Patch(rawURL string, opts ...Options) (*Response, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Patch(rawURL, opts...)
}

func Delete(rawURL string, opts ...Options) (*Response, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Delete(rawURL, opts...)
}

func Head(rawURL string, opts ...Options) (*Response, error) {
	s, err := NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Head(rawURL, opts...)
}
