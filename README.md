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

### Request style (recommended)

```go
package main

import (
    "fmt"

    "github.com/HashShin/specter/impersonate"
    "github.com/HashShin/specter/requests"
)

func main() {
    sess, _ := requests.NewSession()
    defer sess.Close()

    resp, err := sess.Send(requests.Request{
        Method: "GET",
        URL:    "https://httpbin.org/get",
        Headers: requests.Headers{
            "Accept: application/json",
            "X-Custom: value",
        },
        Impersonate: impersonate.Chrome146,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(resp.StatusCode)
    fmt.Println(resp.Text())
}
```

### One-shot (no session)

```go
resp, err := requests.Send(requests.Request{
    Method:      "GET",
    URL:         "https://httpbin.org/get",
    Impersonate: impersonate.Chrome146,
})
```

### POST with JSON

```go
resp, _ := sess.Send(requests.Request{
    Method: "POST",
    URL:    "https://httpbin.org/post",
    Headers: requests.Headers{
        "Content-Type: application/json",
    },
    JSON:        map[string]any{"name": "Alice", "age": 30},
    Impersonate: impersonate.Chrome146,
})
```

### POST form data

```go
resp, _ := sess.Send(requests.Request{
    Method: "POST",
    URL:    "https://example.com/login",
    Form: map[string]string{
        "username": "alice",
        "password": "hunter2",
    },
    Impersonate: impersonate.Firefox147,
})
```

### Session (persists cookies across requests)

```go
sess, _ := requests.NewSession()
defer sess.Close()

sess.Impersonate = impersonate.Chrome146

// Login — cookies saved automatically
sess.Send(requests.Request{
    Method: "POST",
    URL:    "https://example.com/login",
    Form:   map[string]string{"username": "alice", "password": "hunter2"},
})

// Next request sends cookies automatically
resp, _ := sess.Send(requests.Request{
    Method: "GET",
    URL:    "https://example.com/dashboard",
})
fmt.Println(resp.Text())
```

### Proxy

```go
resp, _ := sess.Send(requests.Request{
    Method:      "GET",
    URL:         "https://httpbin.org/ip",
    Proxy:       "socks5://127.0.0.1:1080",
    Impersonate: impersonate.Chrome146,
})
```

### Timeout + retry

```go
resp, _ := sess.Send(requests.Request{
    Method:      "GET",
    URL:         "https://flaky.example.com",
    Timeout:     10 * time.Second,
    Impersonate: impersonate.Chrome146,
    Retry: &requests.RetryStrategy{
        Count:   3,
        Delay:   time.Second,
        Backoff: "exponential",
    },
})
```

### Skip TLS / custom CA

```go
// Skip verification
resp, _ := sess.Send(requests.Request{
    Method: "GET",
    URL:    "https://self-signed.example.com",
    Verify: false,
})

// Custom CA bundle
resp, _ = sess.Send(requests.Request{
    Method: "GET",
    URL:    "https://internal.example.com",
    Verify: "/path/to/ca-bundle.pem",
})
```

### Streaming response

```go
resp, _ := sess.Send(requests.Request{
    Method: "GET",
    URL:    "https://example.com/large-file",
    Stream: true,
})
defer resp.BodyStream.Close()
io.Copy(os.Stdout, resp.BodyStream)
```

### Custom JA3 fingerprint

```go
resp, _ := sess.Send(requests.Request{
    Method: "GET",
    URL:    "https://tls.peet.ws/api/all",
    JA3:    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
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
