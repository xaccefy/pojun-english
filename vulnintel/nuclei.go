package vulnintel

// nuclei-templates tree management and scan tool support:
// - EnsureTemplates: git clone --depth 1 when the tree is absent, git pull (fast-forward)
//   when it is present
// - The template tree directory defaults to <data>/nuclei-templates and is passed in by the
//   server
// - FindNucleiTemplates (see poc.go) finds the template path by CVE
//
// go-git is deliberately not used: the git CLI is guaranteed available in the runtime image
// (the Dockerfile installs git), and a --depth 1 shallow clone is most direct on the command
// line.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TemplatesDir is the template tree location (default nuclei-templates/ next to the
// executable).
func TemplatesDir(dataDir string) string {
	return filepath.Join(dataDir, "nuclei-templates")
}

// EnsureTemplates clones or updates the template tree. Best-effort: returns
// error but callers log it — scan_with_nuclei degrades to "templates
// unavailable" messaging rather than failing the sync.
//
// proxy is an optional egress proxy (http/https/socks5; empty = direct). The template tree
// lives on github.com, and a direct connection from mainland China or a campus network
// inevitably times out — without a proxy all this can report is "clone failed", so callers
// must feed in the platform-configured install/global proxy and share the same egress as
// update pulls.
//
// Self-healing semantics (v0.3.96): on clone/pull failure, clean up the half-built
// directory — a .git shell left behind by an interrupted git makes the directory "present but
// without templates", so the status page shows 0 templates forever and never heals (measured
// on Kali). After a success it verifies the yaml template count >0; an empty tree is likewise
// treated as a failure and cleaned so the next round re-clones.
func EnsureTemplates(ctx context.Context, dir, proxy string) error {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_HTTP_LOW_SPEED_LIMIT=1000", "GIT_HTTP_LOW_SPEED_TIME=30")
	if proxy != "" {
		// git honors http_proxy/https_proxy (both cases are set because different versions read
		// different ones), and a socks5 proxy only works through ALL_PROXY.
		env = append(env,
			"http_proxy="+proxy, "https_proxy="+proxy, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy,
			"ALL_PROXY="+proxy, "all_proxy="+proxy)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// update: fetch + fast-forward only, ignore local drift
		cmd := exec.CommandContext(ctx, "git", "-C", dir, "pull", "--ff-only", "--quiet")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Pull failures fall into two classes: network/timeout (keep the directory and pull
			// again next time) and a corrupt repository (repeated pulls never fix it; deleting and
			// re-cloning is the real self-heal). This is conservative: only a directory with not a
			// single yaml is treated as corrupt and cleaned.
			if CountTemplates(dir) == 0 {
				os.RemoveAll(dir)
				return fmt.Errorf("nuclei templates pull failed and the directory has no templates (leftovers cleaned, re-clone next round): %v: %s",
					err, strings.TrimSpace(string(out)))
			}
			return fmt.Errorf("nuclei templates pull: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return verifyTemplates(dir)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--single-branch", "--quiet",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		// A failed clone always leaves a half-built result (.git or a partial work tree) — if it
		// is not cleaned, the next round sees .git, takes the pull branch and pulls against a
		// broken repository, which never heals (measured on Kali: stuck for 14 hours).
		os.RemoveAll(dir)
		return fmt.Errorf("nuclei templates clone (leftovers cleaned, retry next round): %v: %s", err, strings.TrimSpace(string(out)))
	}
	return verifyTemplates(dir)
}

// verifyTemplates checks the content after a successful clone/pull: a template tree with not
// a single yaml is invalid (an error page from a proxy, a full disk and similar scenarios have
// produced an empty work tree), so it is treated as a failure and cleaned.
func verifyTemplates(dir string) error {
	if n := CountTemplates(dir); n == 0 {
		os.RemoveAll(dir)
		return fmt.Errorf("nuclei templates verification failed: the directory has no yaml templates (leftovers cleaned, retry next round)")
	}
	return nil
}

// CountTemplates recursively counts the .yaml template files under a directory (.yaml, not
// .yml — the nuclei-templates repository uses .yaml throughout).
func CountTemplates(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees without aborting the count
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".yaml") {
			n++
		}
		return nil
	})
	return n
}

// NucleiInstalled reports whether the nuclei binary is on PATH.
func NucleiInstalled() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// ScanArgs is scan_with_nuclei's validated input.
type ScanArgs struct {
	Target       string        // URL/host to scan
	CVEID        string        // optional: restrict to templates mentioning this CVE
	Severity     string        // optional: comma list critical,high,medium,low
	TimeoutTotal time.Duration // whole-run ceiling (default 10m, cap 30m)
	// Proxy is the egress proxy URL (may be empty). Empty = direct, and -proxy never appears in the
	// command — nuclei's -proxy is a string[], and an empty entry breaks proxy parsing.
	Proxy string
}

// EffectiveTimeout normalizes the whole-run ceiling: <=0 becomes 10m, >30m is clamped to 30m.
// BuildNucleiCmd and the agent-side GNU timeout wrapper share this rule so the two clamps can't drift.
func EffectiveTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 10 * time.Minute
	}
	if d > 30*time.Minute {
		return 30 * time.Minute
	}
	return d
}

// normalizeNucleiProxy normalizes the ToolSet egress proxy into the form nuclei's -proxy accepts.
// Same rule as the agent-side buildHTTPClient: http:// is added only when the scheme is missing and never
// unconditionally (production values always carry http:// via traffic.ProxyAddr, so unconditional prefixing
// would produce http://http://…). Empty/whitespace = direct, the caller emits no -proxy. Any comma is refused:
// -proxy is a string[] and a comma is read as a multi-proxy separator, silently splitting a URL whose password
// contains one (under -silent that looks like "no hits"). No percent-encoding here — the proxy may not accept
// encoded userinfo, so an explicit error is better.
// A port is mandatory: nuclei v3.11.1 does a TCP liveness check on Hostname():Port() at startup and calls
// Logger.Fatal without one, so the tool layer must error early to give a readable reason.
func normalizeNucleiProxy(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	if strings.Contains(p, ",") {
		return "", fmt.Errorf("proxy address contains a comma (%q): nuclei reads -proxy as a multi-proxy list, use an address without one", p)
	}
	if !strings.Contains(p, "://") {
		p = "http://" + p
	}
	u, err := url.Parse(p)
	if err != nil {
		return "", fmt.Errorf("proxy address cannot be parsed (%q): %v", p, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("unsupported proxy scheme (%q): only http/https/socks5 are accepted", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("proxy address has no host (%q)", p)
	}
	if u.Port() == "" {
		return "", fmt.Errorf("proxy address has no port (%q): nuclei probes host:port at startup and exits without one", p)
	}
	return p, nil
}

// BuildNucleiCmd assembles the nuclei invocation. Templates restricted to the
// local tree (-t <dir>) so we never trigger nuclei's own template download
// (offline-friendly, version-pinned); -silent keeps output parseable; JSONL
// output goes to stdout for the agent to read. The returned cancel MUST be
// called by the caller after the run (it bounds the whole-run ceiling).
func BuildNucleiCmd(ctx context.Context, templatesDir string, a ScanArgs) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(a.Target) == "" {
		return nil, nil, fmt.Errorf("target must not be empty")
	}
	if _, err := os.Stat(filepath.Join(templatesDir, ".git")); err != nil {
		return nil, nil, fmt.Errorf("template tree unavailable (%s): wait for the synchronizer to finish initializing", templatesDir)
	}
	timeout := EffectiveTimeout(a.TimeoutTotal)
	runCtx, cancel := context.WithTimeout(ctx, timeout)

	args := []string{
		"-target", a.Target,
		"-t", templatesDir,
		"-jsonl",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	// Egress proxy: traffic capture / global proxy / the strict-egress sentinel all flow in through
	// ToolSet.egressProxy. It must be emitted here: scan_with_nuclei only assembles the command and Bash runs
	// nuclei, and "nuclei's env support is unstable" can't be enforced by the prompt alone.
	if prox, perr := normalizeNucleiProxy(a.Proxy); perr != nil {
		cancel()
		return nil, nil, perr
	} else if prox != "" {
		args = append(args, "-proxy", prox)
	}
	if cve := strings.TrimSpace(a.CVEID); cve != "" {
		templates := FindNucleiTemplates(templatesDir, cve)
		if len(templates) == 0 {
			cancel()
			return nil, nil, fmt.Errorf("no template in the tree matches %s (the tree may be stale; wait for the next sync)", cve)
		}
		for _, rel := range templates {
			args = append(args, "-t", filepath.Join(templatesDir, filepath.FromSlash(rel)))
		}
	}
	if sev := strings.TrimSpace(a.Severity); sev != "" {
		args = append(args, "-severity", sev)
	}
	return exec.CommandContext(runCtx, "nuclei", args...), cancel, nil
}
