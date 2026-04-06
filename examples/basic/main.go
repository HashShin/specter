// Example: specter — pure-Go browser fingerprinting HTTP client (no CGO, no libcurl).
package main

import (
	"fmt"
	"log"

	"specter/impersonate"
	"specter/requests"
)

func main() {
	// --- Example 1: one-shot GET with Chrome 146 TLS fingerprint ---
	fmt.Println("=== Example 1: GET with Chrome 146 impersonation ===")
	resp, err := requests.Get("https://httpbin.org/get", requests.Options{
		Impersonate: impersonate.Chrome146,
	})
	if err != nil {
		log.Fatalf("GET failed: %v", err)
	}
	fmt.Printf("Status:  %s\n", resp.Status)
	fmt.Printf("Proto:   %s\n", resp.Proto)
	fmt.Printf("Elapsed: %s\n", resp.Elapsed)
	fmt.Printf("Body:    %.300s\n\n", resp.Text())

	// --- Example 2: Session with POST + JSON body ---
	fmt.Println("=== Example 2: Session POST JSON ===")
	s, err := requests.NewSession()
	if err != nil {
		log.Fatalf("create session: %v", err)
	}
	defer s.Close()

	s.Impersonate = impersonate.Chrome146

	resp, err = s.Post("https://httpbin.org/post", requests.Options{
		JSON: map[string]interface{}{
			"hello": "world",
			"n":     42,
		},
	})
	if err != nil {
		log.Fatalf("POST failed: %v", err)
	}
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body:   %.400s\n\n", resp.Text())

	// --- Example 3: Firefox fingerprint ---
	fmt.Println("=== Example 3: Firefox 147 fingerprint ===")
	resp, err = requests.Get("https://httpbin.org/headers", requests.Options{
		Impersonate: impersonate.Firefox147,
		Headers: map[string]string{
			"X-Custom": "curl_cffi_go",
		},
	})
	if err != nil {
		log.Fatalf("GET failed: %v", err)
	}
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body:   %.500s\n\n", resp.Text())

	// --- Example 4: Safari fingerprint ---
	fmt.Println("=== Example 4: Safari 26 fingerprint ===")
	resp, err = requests.Get("https://httpbin.org/get", requests.Options{
		Impersonate: impersonate.Safari2601,
	})
	if err != nil {
		log.Fatalf("GET failed: %v", err)
	}
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("UA:     %s\n\n", resp.Headers.Get("Content-Type"))

	// --- Example 5: Skip SSL verification ---
	fmt.Println("=== Example 5: Skip SSL verification ===")
	resp, err = requests.Get("https://httpbin.org/get", requests.Options{
		Verify: false,
	})
	if err != nil {
		log.Fatalf("GET failed: %v", err)
	}
	fmt.Printf("Status: %s (SSL skipped)\n", resp.Status)
}
