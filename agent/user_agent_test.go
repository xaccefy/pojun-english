package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// The UA override has to be applied inside the transport: norma builds the HTTP
// requests (including its own retries), so this is the only layer every model
// request passes through.
func TestUserAgentInjectedByTransport(t *testing.T) {
	base := &fakeRT{}
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	rt := quotaAwareTransport{base: base, userAgent: ua}
	if _, err := rt.RoundTrip(newReq(context.Background())); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := base.seen.Header.Get("User-Agent"); got != ua {
		t.Fatalf("User-Agent = %q, want configured UA", got)
	}
}

func TestUserAgentEmptyKeepsDefault(t *testing.T) {
	base := &fakeRT{}
	rt := quotaAwareTransport{base: base} // no UA configured = historical behaviour
	if _, err := rt.RoundTrip(newReq(context.Background())); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := base.seen.Header.Get("User-Agent"); got != "" {
		t.Fatalf("User-Agent = %q, want untouched when unconfigured", got)
	}
}

func TestSanitizeUserAgent(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"  Mozilla/5.0  ", "Mozilla/5.0"},
		{"Mozilla/5.0\r\nX-Injected: 1", "Mozilla/5.0  X-Injected: 1"},
		{"Cur\u0000l", "Cur l"},
	}
	for _, c := range cases {
		if got := sanitizeUserAgent(c.in); got != c.want {
			t.Fatalf("sanitizeUserAgent(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// End-to-end through the SDK: a real model request issued by TestConnection must
// carry the configured UA. Non-streaming keeps the mock response trivial.
func TestTestConnectionSendsConfiguredUserAgent(t *testing.T) {
	const ua = "Pojun-UA-Test/1.0"
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("User-Agent"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-test","object":"chat.completion","model":"test",
			"choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
		}`))
	}))
	defer srv.Close()

	cfg := Config{
		Format:    llm.FormatOpenAI,
		BaseURL:   srv.URL,
		APIKey:    "test-key",
		Model:     "test",
		Stream:    false,
		UserAgent: ua,
	}
	_, reply, err := TestConnection(context.Background(), cfg)
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if reply == "" {
		t.Fatal("empty reply")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("mock server saw no request")
	}
	for i, got := range seen {
		if got != ua {
			t.Fatalf("request %d User-Agent = %q, want %q", i, got, ua)
		}
	}
}
