package vulnintel

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// newNucleiTree builds a minimal template tree (.git + one CVE template) so BuildNucleiCmd's
// availability os.Stat and FindNucleiTemplates both pass; no real clone, so the test touches no
// network and runs no nuclei.
func newNucleiTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmplDir := filepath.Join(dir, "http", "cves", "2021")
	if err := os.MkdirAll(tmplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmplDir, "CVE-2021-41773.yaml"), []byte("id: CVE-2021-41773\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// CountTemplates is the criterion for template-tree self-healing: after a clone/pull failure, "not a single
// yaml in the directory" = corrupted leftovers, clean up and re-clone; templates present = just a network
// hiccup, keep the directory for the next pull.
func TestCountTemplates(t *testing.T) {
	dir := t.TempDir()
	if n := CountTemplates(dir); n != 0 {
		t.Fatalf("empty dir: got %d, want 0", n)
	}
	// build a nuclei-templates-shaped tree: subdir + .yaml, plus a .yml/.txt that should not be counted
	y := filepath.Join(dir, "http", "cves", "2026")
	if err := os.MkdirAll(y, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(y, "a.yaml"), []byte("id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(y, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.yaml"), []byte("id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nope.yml"), []byte("id: y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := CountTemplates(dir); n != 2 {
		t.Fatalf("got %d, want 2 (.yml and non-yaml not counted)", n)
	}
}

// TestNormalizeNucleiProxy locks the normalization rules: empty=direct, http:// added only when the
// scheme is missing, allowlist http/https/socks5, comma fail-closed, credentials and the strict-egress
// sentinel byte-for-byte unchanged.
func TestNormalizeNucleiProxy(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr string // non-empty: the error message must contain this substring
	}{
		{"empty string", "", "", ""},
		{"whitespace only", "   ", "", ""},
		{"bare host:port gets http", "127.0.0.1:8788", "http://127.0.0.1:8788", ""},
		{"http already present, unchanged", "http://127.0.0.1:8788", "http://127.0.0.1:8788", ""},
		{"socks5 with credentials, unchanged", "socks5://u:p@h:1080", "socks5://u:p@h:1080", ""},
		{"strict-egress sentinel byte-for-byte unchanged", "http://127.0.0.1:1", "http://127.0.0.1:1", ""},
		{"leading/trailing space trimmed", "  http://h:1  ", "http://h:1", ""},
		{"unsupported scheme", "ftp://h:21", "", "scheme"},
		{"missing host", "http://", "", "host"},
		{"missing port (with scheme)", "http://proxy.internal", "", "port"},
		{"missing port (bare host)", "proxy.internal", "", "port"},
		{"contains a comma", "http://a,b:1", "", "comma"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeNucleiProxy(c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("normalizeNucleiProxy(%q) err=%v, want it to contain %q", c.in, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeNucleiProxy(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("normalizeNucleiProxy(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestEffectiveTimeout locks the total-timeout normalization: 0/negative→10m, >30m clamped to 30m,
// values in between unchanged. The agent side derives its GNU timeout seconds from this — both must
// use one rule set.
func TestEffectiveTimeout(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, 10 * time.Minute},
		{-time.Minute, 10 * time.Minute},
		{5 * time.Minute, 5 * time.Minute},
		{10 * time.Minute, 10 * time.Minute},
		{30 * time.Minute, 30 * time.Minute},
		{45 * time.Minute, 30 * time.Minute},
	}
	for _, c := range cases {
		if got := EffectiveTimeout(c.in); got != c.want {
			t.Fatalf("EffectiveTimeout(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestBuildNucleiCmdProxy proves -proxy really is emitted as two separate argv elements, and that the
// default command is unchanged item by item with no proxy (zero regression).
func TestBuildNucleiCmdProxy(t *testing.T) {
	dir := newNucleiTree(t)
	const target = "https://example.com"
	base := []string{"nuclei", "-target", target, "-t", dir, "-jsonl", "-silent", "-no-color", "-disable-update-check"}

	// No proxy: the command equals the baseline item by item, and -proxy never appears.
	cmd, cancel, err := BuildNucleiCmd(context.Background(), dir, ScanArgs{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cmd.Args, base) {
		t.Fatalf("no-proxy args = %v, want %v", cmd.Args, base)
	}
	cancel()

	// With a proxy: -proxy and its value come out as the last two separate elements.
	cmd, cancel, err = BuildNucleiCmd(context.Background(), dir, ScanArgs{Target: target, Proxy: "http://127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	n := len(cmd.Args)
	if n < 2 || cmd.Args[n-2] != "-proxy" || cmd.Args[n-1] != "http://127.0.0.1:8788" {
		t.Fatalf("proxy args tail = %v", cmd.Args)
	}
	cancel()

	// The CVE/severity branch combined with -proxy: -proxy still appears exactly once with its value
	// right after, and -t carries the full tree dir plus the matched CVE template as two entries.
	cmd, cancel, err = BuildNucleiCmd(context.Background(), dir, ScanArgs{
		Target:   target,
		Proxy:    "http://127.0.0.1:8788",
		CVEID:    "CVE-2021-41773",
		Severity: "critical,high",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyCount, sevCount, tmplCount := 0, 0, 0
	for i, a := range cmd.Args {
		switch a {
		case "-proxy":
			proxyCount++
			if i+1 >= len(cmd.Args) || cmd.Args[i+1] != "http://127.0.0.1:8788" {
				t.Fatalf("-proxy must be immediately followed by the proxy value, args=%v", cmd.Args)
			}
		case "-severity":
			sevCount++
			if i+1 >= len(cmd.Args) || cmd.Args[i+1] != "critical,high" {
				t.Fatalf("-severity must be immediately followed by the severity, args=%v", cmd.Args)
			}
		case "-t":
			tmplCount++
		}
	}
	if proxyCount != 1 || sevCount != 1 {
		t.Fatalf("-proxy/-severity must each appear once, got proxy=%d sev=%d: %v", proxyCount, sevCount, cmd.Args)
	}
	if tmplCount != 2 {
		t.Fatalf("-t must be the full tree plus the CVE template (two entries), got %d: %v", tmplCount, cmd.Args)
	}
	cancel()

	// Contains a comma: refuse to build a split argv (cmd is nil, no half-built result).
	badCmd, badCancel, badErr := BuildNucleiCmd(context.Background(), dir, ScanArgs{Target: target, Proxy: "http://a,b:1"})
	if badCancel != nil {
		badCancel()
	}
	if badErr == nil || badCmd != nil {
		t.Fatalf("a comma proxy must return err with cmd==nil, got cmd=%v err=%v", badCmd, badErr)
	}

	// A target containing & stays a single argv element (the injection surface doesn't regress because of the proxy change).
	cmd, cancel, err = BuildNucleiCmd(context.Background(), dir, ScanArgs{Target: "https://t/api?a=1&b=2"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Args[2] != "https://t/api?a=1&b=2" {
		t.Fatalf("target must stay a single element, got %q", cmd.Args[2])
	}
	cancel()
}
