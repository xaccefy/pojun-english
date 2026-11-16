package vulnintel

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// fallbackTransport falls back to a direct connection when the proxy transport fails.
//
// Why it is needed: an egress proxy is not all-powerful. Measured (2026-10-21) with proxy
// 10.10.70.14:7897: fine (200) for api.github.com, but for www.cisa.gov /
// services.nvd.nist.gov it "completes CONNECT, then gets unexpected eof during the TLS
// handshake" — the tunnel is established but no data is forwarded. So within one sync round
// the GitHub source succeeded while the NVD/KEV sources all failed with EOF.
//
// Yet a direct connection to those two sources works (NVD 200 in 0.9s, CISA 200 in 2.2s). In
// other words the proxy is not only useless here, it blocks a direct route that would have
// worked.
//
// It only falls back on **transport-layer failures** (connection refused/reset/EOF/timeout).
// HTTP-layer errors (404/403/429) do not fall back — that is the source's own problem and a
// different route gives the same answer, so falling back would turn one request into two and
// only add quota consumption and rate-limit risk.
type fallbackTransport struct {
	proxy   http.RoundTripper
	direct  http.RoundTripper
	enabled bool
}

// parseProxyURL parses and validates a proxy address. Shared by three clients (NVD/KEV,
// GitHub, PoC).
func parseProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("vulnintel: bad proxy url: %w", err)
	}
	return u, nil
}

func newFallbackTransport(proxyURL string) (http.RoundTripper, error) {
	direct := http.DefaultTransport.(*http.Transport).Clone()
	// A direct connection must really be direct. http.DefaultTransport reads the HTTP_PROXY /
	// HTTPS_PROXY environment variables — the service process starts with them set (systemd's
	// Environment=), so the cloned transport still carries the proxy and "fall back to direct"
	// lands on the same broken proxy, i.e. no fallback at all. Explicitly clearing Proxy is
	// what makes it truly direct.
	direct.Proxy = nil
	t := strings.TrimSpace(proxyURL)
	if t == "" {
		return direct, nil
	}
	u, err := parseProxyURL(t)
	if err != nil {
		return nil, err
	}
	proxied := http.DefaultTransport.(*http.Transport).Clone()
	proxied.Proxy = http.ProxyURL(u)
	return &fallbackTransport{proxy: proxied, direct: direct, enabled: true}, nil
}

func (t *fallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.proxy.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	if !t.enabled || !isTransportFailure(err) {
		return resp, err
	}
	// Proxy failed → retry once directly. The request body has already been consumed by the
	// proxy (if it was streaming), so replaying it may be incomplete; but every intelligence
	// source is a GET with no body, so this is safe.
	if req.Body != nil && req.GetBody == nil {
		return resp, err
	}
	if req.GetBody != nil {
		body, gerr := req.GetBody()
		if gerr != nil {
			return resp, err
		}
		req.Body = body
	}
	return t.direct.RoundTrip(req)
}

// isTransportFailure reports whether the error belongs to the "another route might just work"
// class. HTTP status code errors are not in it (that is the source's problem, not the route's).
func isTransportFailure(err error) bool {
	if err == nil {
		return false
	}
	// A 502 (Bad Gateway) returned by the proxy is also a route problem: the proxy itself did not
	// get a response from upstream.
	var proxyErr interface{ StatusCode() int }
	if errors.As(err, &proxyErr) && proxyErr.StatusCode() == http.StatusBadGateway {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, m := range []string{
		"eof",                // peer disconnects during the TLS handshake/read (the classic symptom of a proxy tunnel not forwarding)
		"connection reset",   // reset by the target or an intermediary device
		"connection refused", // nothing listening on the port
		"broken pipe",
		"no route to host",
		"network is unreachable",
		"i/o timeout",
		"tls handshake timeout",
		"unexpected eof",
		"proxyconnect",
		"transport connection broken",
	} {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}
