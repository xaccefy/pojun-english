package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// This file covers doJSON's HTTP-layer error classification.
//
// Why test it alone: each channel adapter handles only its platform's business error codes
// (DingTalk errcode, Feishu code, Telegram ok field), while **HTTP-layer** classification is
// doJSON's unified job — two separate lines of defense. Without it, a transit gateway's 503
// gets judged permanent and gives up retrying; a 403 gets retried three wasted rounds.

func replyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoJSONClassifiesHTTPStatus(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		permanent bool
	}{
		{"200 success is no error", 200, false},
		{"429 rate-limit retriable", 429, false},
		{"408 request-timeout retriable", 408, false},
		{"500 server-error retriable", 500, false},
		{"502 gateway-error retriable", 502, false},
		{"503 unavailable retriable", 503, false},
		{"400 bad-params permanent", 400, true},
		{"401 auth-failure permanent", 401, true},
		{"403 forbidden permanent", 403, true},
		{"404 not-found permanent", 404, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := replyServer(t, tc.status, `{"detail":"upstream says no"}`)
			_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("2xx shouldn't error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("non-2xx should error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("HTTP %d permanent verdict wrong: want %v got %v (%v)",
					tc.status, tc.permanent, got, err)
			}
			// The status code must appear in the error — else the user can't tell 'I misconfigured'
			// from 'the peer is down'. Assert the digits, not Go's StatusText: digits are the
			// language-agnostic, stable part to assert.
			if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("error should carry HTTP status %d, got %v", tc.status, err)
			}
		})
	}
}

// TestDoJSONIncludesResponseSnippet covers snippet: the peer's error text must come back —
// else users only know 'it failed', not why the peer refused.
func TestDoJSONIncludesResponseSnippet(t *testing.T) {
	srv := replyServer(t, 400, `{"error":"invalid webhook token"}`)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "invalid webhook token") {
		t.Errorf("error should carry the peer's explanation, got %v", err)
	}
}

// TestDoJSONSnippetIsSingleLineAndBounded constrains snippet's shape: peer responses land
// verbatim in the last_error column and the frontend table — multi-line/oversize wrecks
// layout and payload.
func TestDoJSONSnippetIsSingleLineAndBounded(t *testing.T) {
	// A response carrying newlines, tabs and 5000 chars of padding.
	long := strings.Repeat("x", 5000)
	srv := replyServer(t, 500, "line1\nline2\r\n\tline3 "+long)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("error should be squeezed to one line, got %q", msg)
	}
	// snippet caps at 200 chars + a fixed prefix — far smaller than the raw response.
	if len(msg) > 400 {
		t.Errorf("error too long (%d bytes) — should be snippet-truncated: %q", len(msg), msg)
	}
}

// TestDoJSONRejectsOversizedResponse confirms the read is capped: a misbehaving peer's
// huge response must not be read fully into memory (every delivery-history row stores a
// last_error copy).
func TestDoJSONRejectsOversizedResponse(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // 1 MiB
	srv := replyServer(t, 400, huge)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 400 {
		t.Errorf("oversized response should be capped-read and truncated, error length %d", len(err.Error()))
	}
}
