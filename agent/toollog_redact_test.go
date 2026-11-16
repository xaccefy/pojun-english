package agent

import (
	"strings"
	"testing"
)

// Since v0.4.37 the activity log's command summary keeps the original text (first-party evidence needs traceability — no more masking).
func TestCmdHeadKeepsPlaintext(t *testing.T) {
	cases := []struct {
		in      string
		wantHas string
	}{
		{"sshpass -p 'dolphin!@#' ssh root@10.0.0.1", "dolphin!@#"},
		{"mysql -uroot -p'S3cret!' -h127.0.0.1", "S3cret!"},
		{"curl -H 'Authorization: Bearer abc123XYZ' http://x", "abc123XYZ"},
	}
	for _, c := range cases {
		got := cmdHead(c.in)
		if !strings.Contains(got, c.wantHas) {
			t.Errorf("command text was rewritten: in=%q got=%q want-containing %q", c.in, got, c.wantHas)
		}
	}
}

// The summary takes only the first line, length-capped — avoids dumping whole multi-line scripts into the activity stream.
func TestCmdHeadFirstLineAndTruncate(t *testing.T) {
	got := cmdHead("echo one\necho two")
	if strings.Contains(got, "echo two") || !strings.Contains(got, "echo one") {
		t.Fatalf("cmdHead must keep only first line, got %q", got)
	}
	long := strings.Repeat("A", 200)
	got = cmdHead(long)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) > 97 {
		t.Fatalf("cmdHead must truncate with ellipsis, got len=%d", len([]rune(got)))
	}
}
