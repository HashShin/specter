package requests

// On Android/Termux, Go's automatic DNS resolver selection may fail.
// Setting GODEBUG=netdns=go at init time forces the pure-Go resolver,
// which reads /etc/resolv.conf and works correctly.
//
// This is set via the environment so it affects the entire program.
// Users can override it by setting GODEBUG explicitly before importing.

import "os"

func init() {
	if v := os.Getenv("GODEBUG"); v == "" {
		os.Setenv("GODEBUG", "netdns=go")
	} else if v != "" && !containsNetdns(v) {
		os.Setenv("GODEBUG", v+",netdns=go")
	}
}

func containsNetdns(godebug string) bool {
	for _, part := range splitComma(godebug) {
		if len(part) >= 7 && part[:7] == "netdns=" {
			return true
		}
	}
	return false
}

func splitComma(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return parts
}
