package vulnintel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Must fall back to a direct connection when the proxy transport layer fails.
//
// Regression background (verified 2026-10-21): the egress proxy 10.10.70.14:7897 works
// for api.github.com (200), but for www.cisa.gov / services.nvd.nist.gov it produces
// "CONNECT returns 200, then the TLS handshake gets unexpected eof" — the tunnel is built
// but no data is forwarded. In the same sync round, the GitHub source succeeded while the
// NVD/KEV sources all failed, even though connecting directly to those two sources worked.
// Here the proxy is not just useless — it also blocks the route that would have worked.
func TestFallbackTransportFallsBackToDirect(t *testing.T) {
	// Direct target: an httptest server that normally returns 200.
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("direct-ok"))
	}))
	defer direct.Close()

	// Proxy: CONNECT succeeds but then immediately disconnects — reproduces the shape of the real failure.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Ordinary proxy request: also disconnect.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	tr, err := newFallbackTransport(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}

	resp, err := client.Get(direct.URL)
	if err != nil {
		t.Fatalf("fallback did not reach the direct server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// HTTP-layer errors **must not** fall back: 404/403/429 are problems with the source
// itself, and switching routes gives the same answer; falling back only turns one request
// into two, wasting quota (NVD anonymous allows only 5 requests / 30 seconds).
func TestFallbackTransportDoesNotRetryHTTPErrors(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer proxy.Close()

	tr, err := newFallbackTransport(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: tr}

	resp, err := client.Get("http://example.invalid/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (proxy answer must pass through)", resp.StatusCode)
	}
}

// Transport error classification must be accurate: only those where "switching routes
// might help" should fall back.
func TestIsTransportFailure(t *testing.T) {
	fatal := []string{
		`Get "https://x": EOF`,
		`Get "https://x": unexpected EOF`,
		`dial tcp 1.2.3.4:443: connect: connection refused`,
		`read tcp: connection reset by peer`,
		`net/http: TLS handshake timeout`,
		`Get "https://x": i/o timeout`,
	}
	for _, msg := range fatal {
		if !isTransportFailure(errString(msg)) {
			t.Errorf("should be a transport failure: %s", msg)
		}
	}
	benign := []string{
		`Get "https://x": 404 Not Found`,
		`unexpected status 403`,
		`Get "https://x": 429 Too Many Requests`,
		`invalid character 'x'`,
	}
	for _, msg := range benign {
		if isTransportFailure(errString(msg)) {
			t.Errorf("should NOT be a transport failure: %s", msg)
		}
	}
	if isTransportFailure(nil) {
		t.Error("nil must not be a transport failure")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// Empty proxy = direct connection; no extra layer should be introduced.
func TestFallbackTransportWithoutProxyIsDirect(t *testing.T) {
	tr, err := newFallbackTransport("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tr.(*fallbackTransport); ok {
		t.Error("empty proxy should not build a fallback transport")
	}
	// It also should not error or return nil
	if tr == nil {
		t.Fatal("nil transport")
	}
}

// "Fall back to direct" must mean a real direct connection.
//
// http.DefaultTransport reads the environment variables HTTP_PROXY / HTTPS_PROXY, and the
// service process starts with these variables set (systemd Environment=), so a cloned
// transport still carries the proxy — meaning "fall back to direct" goes right back to the
// same broken proxy, i.e. no fallback at all. This has bitten us in practice: the unit tests
// are all green (the test process lacks these environment variables) while production still gets EOF.
func TestFallbackDirectIgnoresEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://10.255.255.1:1")
	t.Setenv("HTTPS_PROXY", "http://10.255.255.1:1")
	t.Setenv("http_proxy", "http://10.255.255.1:1")
	t.Setenv("https_proxy", "http://10.255.255.1:1")

	tr, err := newFallbackTransport("http://10.10.70.14:7897")
	if err != nil {
		t.Fatal(err)
	}
	fb, ok := tr.(*fallbackTransport)
	if !ok {
		t.Fatalf("expected *fallbackTransport, got %T", tr)
	}
	direct, ok := fb.direct.(*http.Transport)
	if !ok {
		t.Fatalf("direct transport should be *http.Transport, got %T", fb.direct)
	}
	if direct.Proxy != nil {
		t.Error("direct transport must not carry the environment proxy")
	}
	// The proxy route, on the other hand, must carry the proxy
	proxied, ok := fb.proxy.(*http.Transport)
	if !ok {
		t.Fatalf("proxy transport should be *http.Transport, got %T", fb.proxy)
	}
	if proxied.Proxy == nil {
		t.Error("proxy transport must carry the configured proxy")
	}
}
