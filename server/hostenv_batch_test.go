package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// startFakeHostd spins up a minimal hostd stand-in on a temp unix socket:
//   - POST /jobs: tool_id=="sqlmap" returns 400 (simulating an 'already installed'
//     refusal), everything else returns 200 + {"id":"job-N"};
//   - other paths 404.
func startFakeHostd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "hostd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var seq atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST /jobs", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ToolID string `json:"tool_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ToolID == "sqlmap" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("sqlmap already installed"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"id":"job-%d"}`, seq.Add(1))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})
	return sock
}

// Batch install: valid items forward one by one to the helper and carry back job ids;
// unknown items and helper-refused items go to skipped with reasons; duplicates
// dedupe.
func TestHostenvInstallBatch(t *testing.T) {
	sock := startFakeHostd(t)
	t.Setenv("POJUN_HOSTD_SOCKET", sock)
	s := &Server{}

	body, _ := json.Marshal(map[string]any{
		"ids": []string{"nmap", "sqlmap", "no-such-tool", "nmap", "ffuf"},
	})
	w := httptest.NewRecorder()
	s.hostenvInstallBatch(w, httptest.NewRequest("POST", "/api/hostenv/install-batch", strings.NewReader(string(body))))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Started []struct {
			JobID  string `json:"job_id"`
			ToolID string `json:"tool_id"`
		} `json:"started"`
		Skipped []struct {
			ToolID string `json:"tool_id"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Started) != 2 {
		t.Fatalf("started=%v, expected nmap and ffuf", res.Started)
	}
	gotTools := map[string]bool{}
	for _, j := range res.Started {
		gotTools[j.ToolID] = true
		if j.JobID == "" {
			t.Fatalf("started item missing job_id: %+v", j)
		}
	}
	if !gotTools["nmap"] || !gotTools["ffuf"] {
		t.Fatalf("started should contain nmap/ffuf: %+v", res.Started)
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("skipped=%v, expected sqlmap and no-such-tool", res.Skipped)
	}
	reasons := map[string]string{}
	for _, sk := range res.Skipped {
		reasons[sk.ToolID] = sk.Reason
	}
	if reasons["no-such-tool"] != "unknown tool" {
		t.Fatalf("no-such-tool skip reason=%q", reasons["no-such-tool"])
	}
	if reasons["sqlmap"] == "" {
		t.Fatal("a helper-refused sqlmap should come back with a reason")
	}
}

// Empty and over-long lists 400 directly without touching the helper.
func TestHostenvInstallBatchValidation(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.hostenvInstallBatch(w, httptest.NewRequest("POST", "/api/hostenv/install-batch", strings.NewReader(`{"ids":[]}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty list should 400, got %d", w.Code)
	}
	w2 := httptest.NewRecorder()
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = "x"
	}
	b, _ := json.Marshal(map[string]any{"ids": ids})
	s.hostenvInstallBatch(w2, httptest.NewRequest("POST", "/api/hostenv/install-batch", strings.NewReader(string(b))))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("over-long list should 400, got %d", w2.Code)
	}
}
