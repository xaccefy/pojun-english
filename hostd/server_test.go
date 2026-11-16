package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Regression: a job's parent ctx must come from the process lifecycle and must **not** be
// an HTTP request ctx. r.Context() used to be passed into Start, so the ctx was canceled
// as soon as the handler returned and queued jobs turned cancelled immediately (measured
// while installing hashcat on a real machine).
func TestJobNotCancelledByRequestContext(t *testing.T) {
	// Empty PATH: every tool is detected as "missing" and even a real execution cannot
	// resolve an executable, so the job fails quickly to failed — independent of what the
	// host has installed and with no side effects.
	t.Setenv("PATH", "")

	srv := NewServer(context.Background(), log.New(io.Discard, "", 0))
	mux := srv.Handler()

	// A request ctx that is already done, simulating the state after the handler returns.
	reqCtx, cancelReq := context.WithCancel(context.Background())
	body, _ := json.Marshal(map[string]string{"tool_id": "masscan"})
	req := httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(body)).WithContext(reqCtx)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	// Cancel the request ctx before calling: if the implementation wrongly used the request
	// ctx, the job is necessarily canceled immediately
	cancelReq()
	mux.ServeHTTP(w, req)

	if len(srv.jobs) == 0 {
		t.Fatalf("the job should be accepted but none exists; response=%s", w.Body.String())
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, j := range srv.List() {
			j.mu.Lock()
			st := j.State
			j.mu.Unlock()
			if st == StateCancelled {
				t.Fatalf("job canceled by the request ctx (regression): state=%s log=%q", st, j.Log)
			}
			if st == StateDone || st == StateFailed {
				return // terminal state that is not cancelled, as expected
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the job did not reach a terminal state within 10s")
}

// healthz is the liveness contract; the frontend uses it to decide whether to show the
// "install" button.
func TestHealthz(t *testing.T) {
	srv := NewServer(context.Background(), log.New(io.Discard, "", 0))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz should be 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "pojun-hostd") {
		t.Errorf("abnormal healthz response: %s", w.Body.String())
	}
}
