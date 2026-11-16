package proxyprobe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// socks5HandshakeServer starts a minimal SOCKS5 server: after the handshake it
// echoes the request back as an HTTP response. It verifies that the client really
// goes through the SOCKS tunnel instead of silently connecting directly.
func socks5HandshakeServer(t *testing.T, seen *string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				methods := make([]byte, head[1])
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				c.Write([]byte{0x05, 0x00}) // choose "no authentication"
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 0x01:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 0x03:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					b := make([]byte, l[0])
					io.ReadFull(c, b)
					host = string(b)
				case 0x04:
					b := make([]byte, 16)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				}
				portBuf := make([]byte, 2)
				io.ReadFull(c, portBuf)
				port := int(binary.BigEndian.Uint16(portBuf))
				if seen != nil {
					*seen = net.JoinHostPort(host, itoa(port))
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				buf := make([]byte, 1024)
				c.Read(buf)
				body := "SOCKS-OK"
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " + itoa(len(body)) +
					"\r\nConnection: close\r\n\r\n" + body))
			}(c)
		}
	}()
	return ln
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// socks5:// must establish a SOCKS tunnel.
// Regression background: the code used only http.ProxyURL, and feeding it socks5://
// yielded "unsupported protocol scheme" — the user set a socks proxy but downloads
// still failed.
func TestProbeSocks5UsesTunnel(t *testing.T) {
	var seen string
	ln := socks5HandshakeServer(t, &seen)
	res := Probe(context.Background(), "socks5://"+ln.Addr().String(),
		"http://example.test/whatever", "")
	if !res.OK {
		t.Fatalf("should be judged reachable through a socks5 proxy: %s", res.Error)
	}
	if !strings.HasPrefix(seen, "example.test:") {
		t.Errorf("the SOCKS server should see target host name example.test, saw %q", seen)
	}
	if res.Scheme != "socks5" {
		t.Errorf("scheme should be socks5, got %q", res.Scheme)
	}
}

// socks5h must go through SOCKS too (h = delegate DNS resolution to the proxy as well).
func TestProbeSocks5hUsesTunnel(t *testing.T) {
	var seen string
	ln := socks5HandshakeServer(t, &seen)
	res := Probe(context.Background(), "socks5h://"+ln.Addr().String(), "http://example.test/x", "")
	if !res.OK {
		t.Fatalf("should be judged reachable through a socks5h proxy: %s", res.Error)
	}
	if !strings.HasPrefix(seen, "example.test:") {
		t.Errorf("socks5h should hand the host name to the proxy unchanged, saw %q", seen)
	}
}

// An http proxy still uses CONNECT; adding the socks branch must not break it.
func TestClientForHTTPProxySetsProxy(t *testing.T) {
	c, err := ClientFor("http://127.0.0.1:1/", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("wrong transport type")
	}
	if tr.Proxy == nil {
		t.Error("an http proxy should set tr.Proxy")
	}
	u, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "x.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil || u.Host != "127.0.0.1:1" {
		t.Errorf("the http proxy should take effect, got %v", u)
	}
}

// Normalize turns the casual forms users type into a standard URL.
func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"10.0.0.14:7897":            "http://10.0.0.14:7897",
		"10.0.0.14:7897/":           "http://10.0.0.14:7897",
		"http://10.0.0.14:7897":     "http://10.0.0.14:7897",
		"socks5://h:1080":           "socks5://h:1080",
		"socks5h://h:1080":          "socks5h://h:1080",
		"  http://u:p@h:1080  ":     "http://u:p@h:1080",
		"\"http://10.0.0.14:7897\"": "http://10.0.0.14:7897",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// Validate rejects unknown schemes and addresses without a port.
func TestValidate(t *testing.T) {
	if _, err := Validate(""); err != nil {
		t.Errorf("an empty string should pass (direct connection): %v", err)
	}
	for _, ok := range []string{
		"http://10.0.0.14:7897",
		"https://h:443",
		"socks5://h:1080",
		"socks5h://h:1080",
		"http://user:pass@10.0.0.14:7897",
	} {
		if _, err := Validate(ok); err != nil {
			t.Errorf("Validate(%q) should pass: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"ss://h:1080",      // unsupported scheme
		"vless://h:1080",   // unsupported scheme
		"http://h",         // missing port
		"http://:7897",     // missing host
		"http://h:7897\nx", // contains a newline (an argv injection surface)
	} {
		if _, err := Validate(bad); err == nil {
			t.Errorf("Validate(%q) should fail", bad)
		}
	}
}

// An unreachable proxy must not hang: fail fast with an actionable hint.
func TestProbeUnreachableProxyFailsFast(t *testing.T) {
	start := time.Now()
	res := Probe(context.Background(), "socks5://127.0.0.1:1", "http://x.test/", "")
	if res.OK {
		t.Error("an unreachable proxy should be judged unavailable")
	}
	if res.Error == "" {
		t.Error("should report an error message")
	}
	if res.Hint == "" {
		t.Error("should give a remediation hint")
	}
	if time.Since(start) > 25*time.Second {
		t.Errorf("probe took too long: %v", time.Since(start))
	}
}

// Empty proxy = direct connection: judged reachable, with an explanation.
func TestProbeEmptyProxyIsDirect(t *testing.T) {
	res := Probe(context.Background(), "", "", "")
	if !res.OK {
		t.Error("an empty proxy should be judged reachable (direct)")
	}
	if res.Hint == "" {
		t.Error("should state that this is a direct connection")
	}
}
