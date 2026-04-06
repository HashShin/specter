# Specter

A pure-Go HTTP client that bypasses bot detection by cloning the exact TLS and HTTP/2 fingerprints of real browsers like Chrome, Firefox, and Safari.

No CGO. No C dependencies. Works on Linux, macOS, Windows, Android.

---

## Install

```bash
go get github.com/HashShin/specter@latest
```

> If you get a network timeout on `proxy.golang.org`, use direct mode:
> ```bash
> GOPROXY=direct go get github.com/HashShin/specter@latest
> ```

---

## Usage

### Simple request

```go
package main

import (
    "fmt"

    "github.com/HashShin/specter/impersonate"
    "github.com/HashShin/specter/requests"
)

func main() {
    resp, err := requests.Get("https://httpbin.org/get", requests.Options{
        Impersonate: impersonate.Chrome146,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(resp.StatusCode) // 200
    fmt.Println(resp.Text())
}
```

### Session (persists cookies across requests)

```go
sess, _ := requests.NewSession()
defer sess.Close()

sess.Impersonate = impersonate.Firefox147

// Login
sess.Post("https://example.com/login", requests.Options{
    Form: map[string]string{
        "username": "alice",
        "password": "hunter2",
    },
})

// Follow-up request uses the same cookies
resp, _ := sess.Get("https://example.com/dashboard")
fmt.Println(resp.Text())
```

### POST with JSON

```go
resp, err := requests.Post("https://httpbin.org/post", requests.Options{
    Impersonate: impersonate.Chrome146,
    JSON: map[string]any{
        "name": "Alice",
        "age":  30,
    },
})
```

### Custom headers

```go
resp, _ := requests.Get("https://httpbin.org/headers", requests.Options{
    Impersonate: impersonate.Safari2601,
    Headers: map[string]string{
        "X-API-Key":    "secret",
        "Accept":       "application/json",
    },
})
```

### Proxy

```go
resp, _ := requests.Get("https://httpbin.org/ip", requests.Options{
    Impersonate: impersonate.Chrome146,
    Proxy:       "socks5://127.0.0.1:1080",
    // Proxy:    "http://127.0.0.1:8080",
})
```

### Skip TLS verification / custom CA

```go
// Skip verification
resp, _ := requests.Get("https://self-signed.example.com", requests.Options{
    Verify: false,
})

// Custom CA bundle
resp, _ = requests.Get("https://internal.example.com", requests.Options{
    Verify: "/path/to/ca-bundle.pem",
})
```

### Timeout

```go
resp, err := requests.Get("https://example.com", requests.Options{
    Impersonate: impersonate.Chrome146,
    Timeout:     10 * time.Second,
})
```

### Retry with backoff

```go
resp, err := requests.Get("https://flaky.example.com", requests.Options{
    Impersonate: impersonate.Chrome146,
    Retry: &requests.RetryStrategy{
        Count:   3,
        Delay:   time.Second,
        Backoff: "exponential", // or "linear"
    },
})
```

### Streaming response

```go
resp, err := requests.Get("https://example.com/large-file", requests.Options{
    Stream: true,
})
if err != nil {
    panic(err)
}
defer resp.BodyStream.Close()

io.Copy(os.Stdout, resp.BodyStream)
```

### Custom JA3 fingerprint

```go
resp, _ := requests.Get("https://tls.peet.ws/api/all", requests.Options{
    JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
})
```

---

## Supported browsers

| Alias | Resolves to |
|---|---|
| `chrome` | `chrome146` |
| `firefox` | `firefox147` |
| `safari` | `safari2601` |
| `edge` | `edge101` |
| `tor` | `tor145` |
| `safari_ios` | `safari260_ios` |
| `chrome_android` | `chrome131_android` |

Specific versions: `chrome99`–`chrome146`, `firefox133`–`firefox147`, `safari153`–`safari2601`, `edge99`/`edge101`, and more.

---

## CLI

```bash
go install github.com/HashShin/specter/cmd/specter@latest
```

```bash
# GET with Chrome fingerprint
specter https://httpbin.org/get --impersonate chrome

# POST JSON
specter post --json '{"key":"value"}' https://httpbin.org/post

# Custom header + proxy
specter -H "X-API-Key: secret" --proxy socks5://127.0.0.1:1080 https://example.com

# Save to file
specter -o output.html https://example.com

# List all supported browser targets
specter --list-targets
```

---

## How it works

Bot detection services like Cloudflare and Akamai fingerprint every HTTP connection at two layers:

- **TLS (JA3)** — the cipher suites, extensions, and elliptic curves in the TLS `ClientHello`. A plain Go `http.Get` has a different fingerprint from Chrome.
- **HTTP/2 (Akamai)** — the `SETTINGS` frame values, connection `WINDOW_UPDATE` size, and pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`).

Specter clones both layers exactly for each browser profile using:
- [`refraction-networking/utls`](https://github.com/refraction-networking/utls) for TLS fingerprinting
- [`bogdanfinn/fhttp`](https://github.com/bogdanfinn/fhttp) for HTTP/2 fingerprinting
