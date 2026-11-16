// Package proxyprobe: connectivity self-test for egress proxies.
//
// Why a separate package: a proxy has two consumers — install.sh at install time
// (through curl) and runtime (through Go's http.Client). Both sides must agree on
// "what counts as reachable", otherwise you get the split where "install said it
// worked but runtime cannot connect". The verdict rules live here, in one place.
//
// The probe target is the GitHub API: the install flow has to reach it anyway, so
// the self-test and the real use share the same origin. HTTP 200/301/302 all count
// as reachable (403 is GitHub rate limiting — the link itself is fine).
package proxyprobe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Result is the outcome of one proxy self-test.
type Result struct {
	OK        bool   `json:"ok"`
	Proxy     string `json:"proxy"`
	Scheme    string `json:"scheme"`
	LatencyMS int64  `json:"latency_ms"`
	Status    int    `json:"status"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// DefaultProbeURL is the default probe target: GitHub's release API (the install
// flow has to reach it anyway).
const DefaultProbeURL = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"

// Validate checks the proxy URL format. Empty string = direct connection, returns nil.
//
// Only http/https/socks5/socks5h are allowed: those are the intersection understood
// by hostd's downloader, apt's Acquire proxy and curl's -x. Anything else (e.g.
// ss:// or vless://) cannot be used by any component, and a silent failure is worse
// than an error.
func Validate(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.ContainsAny(raw, "\n\r\t ") {
		return "", fmt.Errorf("proxy address contains illegal whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("cannot parse proxy address: %v", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme: %q (supported: http/https/socks5/socks5h)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("proxy address is missing host:port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", fmt.Errorf("proxy address is missing host:port")
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("proxy address is missing host:port")
	}
	return u.String(), nil
}

// Normalize turns the casual forms users type into a standard URL:
//
//	"10.0.0.14:7897"        → http://10.0.0.14:7897 (local proxies are usually mixed http ports)
//	"10.0.0.14:7897/"       → same as above
//	"socks5://h:1080"       → unchanged
//
// An empty string is returned unchanged (= direct connection).
func Normalize(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.Trim(s, "\"'")
	s = strings.TrimRight(s, "/")
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	return s
}

// ClientFor builds an HTTP client that goes through the proxy according to the
// scheme. Exported so hostd's downloader can reuse it, ensuring "install-time
// download" and "runtime self-test" share the same proxy semantics.
//
// socks5 must go through x/net/proxy's SOCKS5 dialer: net/http's ProxyURL only
// understands HTTP CONNECT proxies, and feeding it socks5:// yields "unsupported
// protocol scheme" — which looks like "I set a socks proxy but downloads still
// fail", with no hint to the user that the scheme is the mismatch.
func ClientFor(proxyURL string, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "socks5", "socks5h":
			d, err := newSocksDialer(u)
			if err != nil {
				return nil, err
			}
			tr.Proxy = nil // SOCKS already applies at the dial layer
			tr.DialContext = d.DialContext
		default:
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// clientFor is the in-package alias for ClientFor.
func clientFor(proxyURL string, timeout time.Duration) (*http.Client, error) {
	return ClientFor(proxyURL, timeout)
}

type socksDialer struct{ d proxy.Dialer }

func (s *socksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.d.Dial(network, addr)
}

// newSocksDialer turns a socks5 URL into a dialer (with authentication).
// socks5h and socks5 are equivalent here: DNS resolution is delegated to the proxy
// side (h = let the proxy resolve the hostname).
func newSocksDialer(u *url.URL) (*socksDialer, error) {
	var auth *proxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return &socksDialer{d: d}, nil
}

// Probe makes one real request through a proxy and reports reachability plus
// diagnostics.
//
// An empty probeURL uses DefaultProbeURL. A non-empty exitIPURL triggers one extra
// request to fetch the egress IP (in SOCKS5 setups users care most about "did it
// actually go through the proxy").
func Probe(ctx context.Context, proxyURL, probeURL, exitIPURL string) Result {
	res := Result{Proxy: proxyURL}
	if proxyURL == "" {
		res.OK = true
		res.Hint = "No proxy configured, connecting directly"
		return res
	}
	if u, err := url.Parse(proxyURL); err == nil {
		res.Scheme = u.Scheme
	}
	if probeURL == "" {
		probeURL = DefaultProbeURL
	}

	c, err := clientFor(proxyURL, 20*time.Second)
	if err != nil {
		res.Error = err.Error()
		res.Hint = hintFor(res.Scheme, res.Error)
		return res
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Hint = hintFor(res.Scheme, res.Error)
		return res
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	res.Status = resp.StatusCode

	switch {
	case resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302:
		res.OK = true
	case resp.StatusCode == 403:
		// GitHub rate limiting: the link is fine, it is just being throttled. Not a
		// failure, but worth stating.
		res.OK = true
		res.Hint = "GitHub returned 403 (rate limited): the link works but is currently throttled"
	default:
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		res.Hint = "The proxy connects but the target returned an abnormal status code; the proxy may be rewriting the response or the request is being blocked"
	}

	if res.OK && exitIPURL != "" {
		if ip, err := fetchExitIP(ctx, c, exitIPURL); err == nil {
			res.ExitIP = ip
		}
	}
	return res
}

// fetchExitIP reads the egress IP once. Failure does not affect the overall verdict
// (many egress points do not offer this service).
func fetchExitIP(ctx context.Context, c *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	// Some services return JSON such as {"ip":"1.2.3.4"}
	if i := strings.Index(ip, `"ip"`); i >= 0 {
		rest := ip[i+4:]
		if j := strings.Index(rest, `"`); j >= 0 {
			ip = rest[:j]
		}
	}
	if len(ip) > 64 {
		ip = ip[:64]
	}
	return strings.Trim(ip, `"`), nil
}

// hintFor turns the error text into an actionable remediation hint.
func hintFor(scheme, errMsg string) string {
	low := strings.ToLower(errMsg)
	switch {
	case strings.Contains(low, "unsupported protocol scheme"):
		return "Proxy scheme does not match the components: apt only understands http proxies, configure socks5 separately"
	case strings.Contains(low, "no such host"), strings.Contains(low, "dns"):
		return "Cannot resolve the proxy host name; check that the address is correct"
	case strings.Contains(low, "connection refused"):
		return "Nothing is listening on the proxy port; check the port number"
	case strings.Contains(low, "timeout"), strings.Contains(low, "deadline exceeded"):
		return "Proxy connection timed out: possibly blocked or the port needs changing"
	case strings.Contains(low, "certificate"), strings.Contains(low, "tls"):
		return "TLS handshake failed: an https proxy needs a certificate, or switch to http://"
	case strings.Contains(low, "407"):
		return "The proxy requires authentication: use the form http://user:pass@host:port"
	case strings.Contains(low, "permission denied"):
		return "Not authorized to use this proxy; credentials may be required"
	}
	if scheme == "socks5" || scheme == "socks5h" {
		return "SOCKS5 proxy unavailable; check the port and whether authentication is required"
	}
	return "Proxy unavailable; check the address, port and credentials"
}
