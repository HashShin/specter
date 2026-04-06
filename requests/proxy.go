package requests

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
)

// --- HTTP CONNECT proxy dialer ---

type httpProxyDialer struct {
	proxyURL *url.URL
	forward  *net.Dialer
}

func newHTTPProxyDialer(proxyURL *url.URL, forward *net.Dialer) *httpProxyDialer {
	return &httpProxyDialer{proxyURL: proxyURL, forward: forward}
}

func (d *httpProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := d.proxyURL.Host
	conn, err := d.forward.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy %s: %w", proxyAddr, err)
	}

	// Send CONNECT request
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if user := d.proxyURL.User; user != nil {
		creds := base64.StdEncoding.EncodeToString([]byte(user.String()))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	// Read response
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	// Expect "HTTP/1.x 200 ..."
	if len(statusLine) < 12 || statusLine[9:12] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT: %s", statusLine)
	}
	// Drain remaining headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, nil
}

// --- SOCKS5 proxy dialer ---

type socks5Dialer struct {
	proxyURL *url.URL
	forward  *net.Dialer
}

func newSOCKS5Dialer(proxyURL *url.URL, forward *net.Dialer) *socks5Dialer {
	return &socks5Dialer{proxyURL: proxyURL, forward: forward}
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := d.proxyURL.Host
	conn, err := d.forward.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// SOCKS5 greeting
	authMethods := []byte{0x00} // no auth
	if d.proxyURL.User != nil {
		authMethods = []byte{0x00, 0x02} // no auth + username/password
	}
	greeting := append([]byte{0x05, byte(len(authMethods))}, authMethods...)
	if _, err := conn.Write(greeting); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version %d", resp[0])
	}

	// Auth if required
	if resp[1] == 0x02 && d.proxyURL.User != nil {
		user := d.proxyURL.User.Username()
		pass, _ := d.proxyURL.User.Password()
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, []byte(user)...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, []byte(pass)...)
		if _, err := conn.Write(auth); err != nil {
			conn.Close()
			return nil, err
		}
		authResp := make([]byte, 2)
		if _, err := conn.Read(authResp); err != nil {
			conn.Close()
			return nil, err
		}
		if authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 auth failed")
		}
	} else if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: no acceptable auth method")
	}

	// Connect request
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Connect response (variable length)
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		conn.Close()
		return nil, err
	}
	if header[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: code %d", header[1])
	}
	// Drain bound addr
	switch header[3] {
	case 0x01: // IPv4
		io4 := make([]byte, 4+2)
		conn.Read(io4)
	case 0x03: // Domain
		n := make([]byte, 1)
		conn.Read(n)
		dom := make([]byte, int(n[0])+2)
		conn.Read(dom)
	case 0x04: // IPv6
		io6 := make([]byte, 16+2)
		conn.Read(io6)
	}

	return conn, nil
}
