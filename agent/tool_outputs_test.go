package agent

import (
	"context"
	"strings"
	"testing"
)

// v0.4.29 (P0b #2): verbatim evidence re-verification — valid evidence lines must trace to this run's tool echoes.
func TestToolOutputLedgerVerifyEvidence(t *testing.T) {
	l := NewToolOutputLedger()
	l.Add("HTTP/1.1 200 OK\nServer: nginx/1.25.3 (Ubuntu)\n\n{\"total\":63631,\"data\":[...]}\nX-Powered-By: PHP/8.1.2")
	l.Add("$ id\nuid=0(root) gid=0(root)")

	// both lines found verbatim (whitespace-diff normalized).
	ev := "  Server: nginx/1.25.3 (Ubuntu)   \n  \"total\":63631,\"data\":[...]  \nuid=0(root) gid=0(root)"
	matched, total := l.VerifyEvidence(ev)
	if matched != 3 || total != 3 {
		t.Fatalf("matched=%d total=%d want 3/3 (ev=%q)", matched, total, ev)
	}
	if v := evidenceVerdict(matched, total); v != "good" {
		t.Fatalf("verdict=%s want good", v)
	}

	// all paraphrase → none.
	ev = "the endpoint returned 60k+ patient records without authorization — proving unauthenticated access."
	matched, total = l.VerifyEvidence(ev)
	if matched != 0 || total != 1 { // a single long line counts toward denominator but missed
		t.Fatalf("matched=%d total=%d want 0/1", matched, total)
	}
	if v := evidenceVerdict(matched, total); v != "good" {
		// total<2 is undecidable → good (don't disturb)
		t.Fatalf("verdict=%s want good for undecidable evidence", v)
	}

	// two+ lines with zero provenance → none.
	ev = "first paraphrased conclusion sits here supporting the vuln judgment.\nsecond paraphrased conclusion keeps describing the impact scope."
	matched, total = l.VerifyEvidence(ev)
	if matched != 0 || total != 2 {
		t.Fatalf("matched=%d total=%d want 0/2", matched, total)
	}
	if v := evidenceVerdict(matched, total); v != "none" {
		t.Fatalf("verdict=%s want none", v)
	}

	// partial hits → partial (under half).
	ev = "Server: nginx/1.25.3 (Ubuntu)\na pure paraphrase absent from tool output.\nanother paraphrased line also absent from tool output."
	matched, total = l.VerifyEvidence(ev)
	if matched != 1 || total != 3 {
		t.Fatalf("matched=%d total=%d want 1/3", matched, total)
	}
	if v := evidenceVerdict(matched, total); v != "partial" {
		t.Fatalf("verdict=%s want partial", v)
	}

	// short lines (<20 bytes) don't count toward the denominator.
	matched, total = l.VerifyEvidence("id\nls\nthis is a paraphrased sentence long enough to test whether the denominator ignores short lines.")
	if total != 1 {
		t.Fatalf("total=%d want 1 (short lines must be ignored)", total)
	}
}

// ANSI control sequences must not affect matching.
func TestToolOutputLedgerANSI(t *testing.T) {
	l := NewToolOutputLedger()
	l.Add("\x1b[31mERROR: access denied for user admin\x1b[0m")
	if matched, total := l.VerifyEvidence("ERROR: access denied for user admin"); matched != 1 || total != 1 {
		t.Fatalf("matched=%d total=%d want 1/1", matched, total)
	}
}

// ctx attach/read.
func TestToolOutputsContext(t *testing.T) {
	l := NewToolOutputLedger()
	ctx := WithToolOutputs(context.Background(), l, EvidenceVerifyBlock)
	got, mode := ToolOutputsFromContext(ctx)
	if got != l || mode != EvidenceVerifyBlock {
		t.Fatalf("got ledger=%p mode=%v", got, mode)
	}
	if led, m := ToolOutputsFromContext(context.Background()); led != nil || m != EvidenceVerifyOff {
		t.Fatalf("empty ctx must yield nil/off, got %v/%v", led, m)
	}
	// tier parsing
	for in, want := range map[string]EvidenceVerifyMode{
		"off": EvidenceVerifyOff, "block": EvidenceVerifyBlock, "warn": EvidenceVerifyWarn,
		"": EvidenceVerifyWarn, "strict": EvidenceVerifyBlock, "0": EvidenceVerifyOff,
	} {
		if got := EvidenceVerifyModeFromString(in); got != want {
			t.Fatalf("mode(%q)=%v want %v", in, got, want)
		}
	}
}

// Ledger rolls out oldest entries past the cap.
func TestToolOutputLedgerRolling(t *testing.T) {
	l := NewToolOutputLedger()
	for i := 0; i < toolOutputLedgerMaxEntries+10; i++ {
		l.Add(strings.Repeat("x", 32))
	}
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n > toolOutputLedgerMaxEntries {
		t.Fatalf("entries=%d must be capped at %d", n, toolOutputLedgerMaxEntries)
	}
}
