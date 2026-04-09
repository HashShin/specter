// specter is a command-line HTTP client with browser TLS fingerprinting.
//
// Usage:
//
//	specter [flags] <url>
//	specter get   [flags] <url>
//	specter post  [flags] <url>
//
// Examples:
//
//	specter https://httpbin.org/get
//	specter --impersonate chrome https://tls.peet.ws/api/all
//	specter post --json '{"key":"value"}' https://httpbin.org/post
//	specter --header "X-Foo: bar" --proxy socks5://127.0.0.1:1080 https://example.com
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/HashShin/specter/impersonate"
	"github.com/HashShin/specter/requests"
)

const usage = `specter - HTTP client with browser TLS fingerprinting

Usage:
  specter [flags] <url>          GET request (default)
  specter get [flags] <url>      GET request
  specter post [flags] <url>     POST request

Flags:
  -i, --impersonate <target>   Browser to impersonate (chrome, firefox, safari, edge, ...)
      --ja3 <string>           Custom JA3 fingerprint string
  -H, --header <key:value>     Add request header (repeatable)
  -d, --data <body>            Raw request body
  -j, --json <json>            JSON request body (sets Content-Type: application/json)
  -F, --form <key=value>       Form field (repeatable)
      --proxy <url>            Proxy URL (http://, https://, socks5://)
      --no-verify              Skip TLS certificate verification
      --cacert <path>          Path to CA bundle file
      --timeout <duration>     Request timeout (e.g. 30s, 1m)
  -o, --output <file>          Write response body to file
  -I, --head                   Send HEAD request, show headers only
      --include                Include response headers in output
      --no-follow              Do not follow redirects
      --max-redirects <n>      Maximum redirects (default 30)
  -v, --verbose                Verbose output (show request headers)
  -s, --silent                 Silent — suppress status line
      --retry <n>              Retry failed requests N times
      --retry-delay <duration> Base delay between retries (e.g. 1s, 500ms)
      --list-targets           List all supported impersonation targets
  -h, --help                   Show this help

Supported targets:
  chrome, chrome146, chrome131, chrome120, chrome119, ...
  firefox, firefox147, firefox144, firefox135, firefox133
  safari, safari2601, safari260, safari184, safari180, safari170, ...
  edge, edge101, edge99
  tor, tor145
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	// Check for subcommand
	method := "GET"
	args := os.Args[1:]
	switch strings.ToLower(args[0]) {
	case "get":
		method = "GET"
		args = args[1:]
	case "post":
		method = "POST"
		args = args[1:]
	case "put":
		method = "PUT"
		args = args[1:]
	case "patch":
		method = "PATCH"
		args = args[1:]
	case "delete":
		method = "DELETE"
		args = args[1:]
	case "head":
		method = "HEAD"
		args = args[1:]
	case "--list-targets", "-list-targets":
		listTargets()
		return
	case "--help", "-h", "help":
		fmt.Print(usage)
		return
	}

	fs := flag.NewFlagSet("specter", flag.ExitOnError)
	fs.Usage = func() { fmt.Print(usage) }

	var (
		impersonateFlag  = fs.String("impersonate", "", "Browser to impersonate")
		impersonateShort = fs.String("i", "", "Browser to impersonate (shorthand)")
		ja3Flag          = fs.String("ja3", "", "Custom JA3 fingerprint string")
		headers          multiFlag
		dataFlag         = fs.String("data", "", "Raw request body")
		dataShort        = fs.String("d", "", "Raw request body (shorthand)")
		jsonFlag         = fs.String("json", "", "JSON request body")
		jsonShort        = fs.String("j", "", "JSON request body (shorthand)")
		formFields       multiFlag
		proxyFlag        = fs.String("proxy", "", "Proxy URL")
		noVerify         = fs.Bool("no-verify", false, "Skip TLS verification")
		cacert           = fs.String("cacert", "", "CA bundle path")
		timeoutFlag      = fs.String("timeout", "", "Request timeout")
		outputFile       = fs.String("output", "", "Output file path")
		outputShort      = fs.String("o", "", "Output file path (shorthand)")
		headFlag         = fs.Bool("head", false, "HEAD request")
		headShort        = fs.Bool("I", false, "HEAD request (shorthand)")
		includeHeaders   = fs.Bool("include", false, "Include response headers in output")
		noFollow         = fs.Bool("no-follow", false, "Don't follow redirects")
		maxRedirects     = fs.Int("max-redirects", 30, "Max redirects")
		verbose          = fs.Bool("verbose", false, "Verbose output")
		silent           = fs.Bool("silent", false, "Silent mode")
		retryCount       = fs.Int("retry", 0, "Retry count")
		retryDelay       = fs.String("retry-delay", "1s", "Retry delay")
		listFlag         = fs.Bool("list-targets", false, "List supported targets")
	)

	fs.Var(&headers, "header", "Add request header")
	fs.Var(&headers, "H", "Add request header (shorthand)")
	fs.Var(&formFields, "form", "Add form field")
	fs.Var(&formFields, "F", "Add form field (shorthand)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *listFlag {
		listTargets()
		return
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "error: URL required")
		os.Exit(1)
	}
	targetURL := remaining[0]

	// HEAD flag
	if *headFlag || *headShort {
		method = "HEAD"
	}

	// Resolve shorthand flags
	impersonateTarget := coalesce(*impersonateFlag, *impersonateShort)
	rawData := coalesce(*dataFlag, *dataShort)
	jsonData := coalesce(*jsonFlag, *jsonShort)
	outFile := coalesce(*outputFile, *outputShort)

	// Build options
	opt := requests.Options{
		Proxy: *proxyFlag,
	}

	if impersonateTarget != "" {
		opt.Impersonate = impersonate.Normalize(impersonateTarget)
	}
	if *ja3Flag != "" {
		opt.JA3 = *ja3Flag
	}

	// Verify / CA
	if *noVerify {
		opt.Verify = false
	} else if *cacert != "" {
		opt.Verify = *cacert
	}

	// Headers
	if len(headers) > 0 {
		opt.Headers = make(map[string]string, len(headers))
		for _, h := range headers {
			k, v, ok := strings.Cut(h, ":")
			if !ok {
				fmt.Fprintf(os.Stderr, "error: invalid header %q (must be Key: Value)\n", h)
				os.Exit(1)
			}
			opt.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}

	// Body
	if rawData != "" {
		opt.Body = []byte(rawData)
	} else if jsonData != "" {
		if !json.Valid([]byte(jsonData)) {
			fmt.Fprintf(os.Stderr, "error: invalid JSON\n")
			os.Exit(1)
		}
		opt.Body = []byte(jsonData)
		opt.ContentType = "application/json"
	} else if len(formFields) > 0 {
		vals := url.Values{}
		for _, f := range formFields {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "error: invalid form field %q (must be key=value)\n", f)
				os.Exit(1)
			}
			vals.Set(k, v)
		}
		opt.Body = []byte(vals.Encode())
		opt.ContentType = "application/x-www-form-urlencoded"
		if method == "GET" {
			method = "POST"
		}
	}

	// Timeout
	if *timeoutFlag != "" {
		d, err := parseDuration(*timeoutFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid timeout %q: %v\n", *timeoutFlag, err)
			os.Exit(1)
		}
		opt.Timeout = d
	}

	// Redirect
	if *noFollow {
		f := false
		opt.AllowRedirects = &f
	}
	opt.MaxRedirects = *maxRedirects

	// Retry
	if *retryCount > 0 {
		d, _ := parseDuration(*retryDelay)
		opt.Retry = &requests.RetryStrategy{
			Count: *retryCount,
			Delay: d,
		}
	}

	// Execute request
	sess, err := requests.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()

	if *verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", method, targetURL)
		for k, v := range opt.Headers {
			fmt.Fprintf(os.Stderr, "> %s: %s\n", k, v)
		}
	}

	resp, err := sess.Request(method, targetURL, opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Output
	if !*silent {
		fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
	}

	if *includeHeaders {
		for k, vs := range resp.Headers {
			for _, v := range vs {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
		fmt.Println()
	}

	if method != "HEAD" {
		if outFile != "" {
			if err := os.WriteFile(outFile, []byte(resp.Body), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
				os.Exit(1)
			}
			if !*silent {
				fmt.Fprintf(os.Stderr, "Written to %s\n", outFile)
			}
		} else {
			fmt.Print(resp.Body)
		}
	}

	// Exit with error code for 4xx/5xx
	if resp.StatusCode >= 400 {
		os.Exit(resp.StatusCode / 100)
	}
}

// multiFlag is a flag.Value that accumulates repeated flag values.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// coalesce returns the first non-empty string.
func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseDuration accepts Go duration strings or bare integers as seconds.
func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}
	var n int
	if _, scanErr := fmt.Sscan(s, &n); scanErr == nil {
		return time.Duration(n) * time.Second, nil
	}
	return 0, err
}

// listTargets prints all supported impersonation targets.
func listTargets() {
	targets := []string{
		"chrome (→ chrome146)",
		"chrome146", "chrome145", "chrome142", "chrome136", "chrome133a",
		"chrome131", "chrome124", "chrome123", "chrome120", "chrome119",
		"chrome116", "chrome110", "chrome107", "chrome104", "chrome101",
		"chrome100", "chrome99",
		"chrome_android (→ chrome131_android)",
		"chrome131_android", "chrome99_android",
		"",
		"firefox (→ firefox147)",
		"firefox147", "firefox144", "firefox135", "firefox133",
		"tor (→ tor145)", "tor145",
		"",
		"safari (→ safari2601)",
		"safari2601", "safari260", "safari184", "safari180", "safari172",
		"safari170", "safari155", "safari153",
		"safari_ios (→ safari260_ios)",
		"safari260_ios", "safari180_ios", "safari172_ios",
		"",
		"edge (→ edge101)",
		"edge101", "edge99",
	}
	fmt.Println("Supported impersonation targets:")
	for _, t := range targets {
		if t == "" {
			fmt.Println()
		} else {
			fmt.Printf("  %s\n", t)
		}
	}
}
