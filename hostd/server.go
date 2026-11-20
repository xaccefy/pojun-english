package hostd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chu0119/pojun/hosttools"
	"github.com/chu0119/pojun/proxyprobe"
	"github.com/chu0119/pojun/selfupdate"
)

// State is a job state.
// scriptInstallTimeout is the wall-clock limit for script-type installs. It leaves room
// for slow networks (download + extract + compile) but never allows an unbounded hang:
// on timeout the job is marked failed and the queue moves on to the next item.
const scriptInstallTimeout = "900"

type State string

const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StateDone      State = "done"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

const (
	maxLogBytes = 256 << 10 // max log kept per job (truncated beyond that)
	binDir      = "/usr/local/bin"
)

// Job is one install job.
type Job struct {
	ID        string    `json:"id"`
	ToolID    string    `json:"tool_id"`
	ToolName  string    `json:"tool_name"`
	State     State     `json:"state"`
	ExitCode  int       `json:"exit_code"`
	Err       string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Log       string    `json:"log"`

	mu     sync.Mutex
	buf    bytes.Buffer
	cancel context.CancelFunc
}

func (j *Job) append(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf.WriteString(line)
	if j.buf.Len() > maxLogBytes {
		// Drop the first half and keep the tail (the reason an install failed is usually at
		// the end)
		b := j.buf.Bytes()
		keep := b[len(b)-maxLogBytes:]
		j.buf.Reset()
		j.buf.WriteString("…(earlier log truncated)…\n")
		j.buf.Write(keep)
	}
	j.Log = j.buf.String()
}

func (j *Job) setState(s State) {
	j.mu.Lock()
	j.State = s
	j.mu.Unlock()
}

func (j *Job) setErr(err error) {
	if err == nil {
		return
	}
	j.mu.Lock()
	j.Err = err.Error()
	j.mu.Unlock()
}

// Server is the job manager plus the HTTP interface.
type Server struct {
	mu     sync.Mutex
	jobs   map[string]*Job
	sem    chan struct{} // serialized execution: apt/dpkg do not allow concurrency
	pkgMgr PkgMgr
	logger *log.Logger
	// base is the parent ctx for jobs. An HTTP request ctx must **never** be used: it is
	// canceled as soon as the handler returns, and queued jobs turn into cancelled on the
	// spot (we hit this in practice).
	base context.Context

	// Version is the helper's build version and SelfPath is its own executable (injected by
	// main). The helper is installed in root-owned /usr/local/bin and the main service is
	// locked out by ProtectSystem=strict, so "upgrading the helper itself" can only be done
	// by the helper.
	Version  string
	SelfPath string

	upgrading atomic.Bool
}

// NewServer constructs a Server. base is a process-level lifecycle ctx (canceled when the
// daemon exits); nil means Background.
func NewServer(base context.Context, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	if base == nil {
		base = context.Background()
	}
	return &Server{
		jobs:   map[string]*Job{},
		sem:    make(chan struct{}, 1),
		pkgMgr: DetectPkgMgr(),
		logger: logger,
		base:   base,
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Start kicks off one install. toolID must hit the hosttools whitelist or it is refused.
// parent must be a process-level ctx, never an HTTP request ctx (see the Server.base
// comment).
func (s *Server) Start(parent context.Context, toolID, proxy string) (*Job, error) {
	return s.start(parent, toolID, proxy, InstallSources{})
}

func (s *Server) start(parent context.Context, toolID, proxy string, sources InstallSources) (*Job, error) {
	if err := sources.Validate(); err != nil {
		return nil, err
	}
	tool, ok := hosttools.Lookup(toolID)
	if !ok {
		return nil, fmt.Errorf("unknown tool id: %q (not on the whitelist)", toolID)
	}
	if tool.Kind == hosttools.KindManual {
		return nil, fmt.Errorf("%s only ships an interactive installer upstream, one-click install is not supported", tool.Name)
	}
	cleanProxy, err := ValidateProxy(proxy)
	if err != nil {
		return nil, err
	}
	if tool.AvailableInPath() {
		return nil, fmt.Errorf("%s is already installed", tool.Name)
	}

	ctx, cancel := context.WithCancel(parent)
	j := &Job{
		ID: newID(), ToolID: tool.ID, ToolName: tool.Name,
		State: StateQueued, StartedAt: time.Now(), cancel: cancel,
	}
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()

	s.logger.Printf("[audit] install start job=%s tool=%s proxy=%q", j.ID, tool.ID, cleanProxy)
	go func() {
		defer cancel()
		s.sem <- struct{}{}
		defer func() { <-s.sem }()
		if ctx.Err() != nil {
			j.setState(StateCancelled)
			j.append("[cancel] job canceled while queued\n")
			return
		}
		j.setState(StateRunning)
		code, err := s.run(ctx, j, tool, cleanProxy, sources)
		j.mu.Lock()
		j.ExitCode = code
		j.EndedAt = time.Now()
		j.mu.Unlock()
		switch {
		case ctx.Err() != nil:
			j.setState(StateCancelled)
			j.append("[cancel] canceled\n")
		case err != nil:
			j.setErr(err)
			j.setState(StateFailed)
			j.append(fmt.Sprintf("[fail] %v\n", err))
		default:
			j.setState(StateDone)
			j.append("[ok] install complete\n")
		}
		s.logger.Printf("[audit] install end job=%s tool=%s state=%s exit=%d err=%v",
			j.ID, tool.ID, j.State, code, err)
	}()
	return j, nil
}

// Get returns a job snapshot.
func (s *Server) Get(id string) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	return j, ok
}

// List returns all jobs (newest first).
func (s *Server) List() []*Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, j)
	}
	return out
}

// Cancel cancels a job.
func (s *Server) Cancel(id string) bool {
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		return false
	}
	if j.cancel != nil {
		j.cancel()
		return true
	}
	return false
}

// ── Execution ────────────────────────────────────

// run executes the recipe and returns the exit code and error.
func (s *Server) run(ctx context.Context, j *Job, tool hosttools.Tool, proxy string, sources InstallSources) (int, error) {
	switch tool.Kind {
	case hosttools.KindApt:
		return s.runApt(ctx, j, tool, proxy, sources.APT)
	case hosttools.KindGitHub:
		return s.runGitHub(ctx, j, tool, proxy)
	case hosttools.KindPip:
		return s.runPip(ctx, j, tool, proxy, sources.PyPI)
	case hosttools.KindScript:
		// Every script-type install gets a uniform wall-clock timeout: the catalog scripts
		// include GitHub/mirror downloads, and with a poor network window curl (which has no
		// built-in timeout) waits forever and jams the serial install queue (measured: the
		// jadx release download blocked install-all for over 15 minutes).
		// The timeout command comes from coreutils and is shipped by default on
		// Debian/Kali; when absent, fall back to no timeout.
		limit := scriptInstallTimeout
		if _, err := exec.LookPath("timeout"); err == nil {
			return s.execLogged(ctx, j, "timeout", []string{limit, "/bin/sh", "-c", tool.Script}, proxyEnv(proxy))
		}
		return s.execLogged(ctx, j, "/bin/sh", []string{"-c", tool.Script}, proxyEnv(proxy))
	}
	return 1, fmt.Errorf("unsupported install kind: %s", tool.Kind)
}

// execLogged runs one command, appending its output to the job log in real time.
func (s *Server) execLogged(ctx context.Context, j *Job, name string, argv []string, env []string) (int, error) {
	j.append(fmt.Sprintf("$ %s %s\n", name, strings.Join(argv, " ")))
	cmd := exec.CommandContext(ctx, name, argv...)
	cmd.Env = append(os.Environ(), env...)
	w := &logWriter{j: j}
	cmd.Stdout, cmd.Stderr = w, w
	err := cmd.Run()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if err == nil {
		return 0, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), fmt.Errorf("%s exited with code %d", name, ee.ExitCode())
	}
	return 1, err
}

type logWriter struct{ j *Job }

func (w *logWriter) Write(p []byte) (int, error) {
	w.j.append(string(p))
	return len(p), nil
}

func (s *Server) runApt(ctx context.Context, j *Job, tool hosttools.Tool, proxy, preset string) (int, error) {
	if s.pkgMgr == PkgNone {
		return 1, fmt.Errorf("no apt/dnf detected on this host")
	}
	var sourceArgs []string
	if s.pkgMgr == PkgApt && preset != "" {
		args, cleanup, err := aptSourceArgs("/etc/apt", preset)
		if err != nil {
			return 1, fmt.Errorf("preparing the APT mirror: %w", err)
		}
		defer cleanup()
		sourceArgs = args
		j.append(fmt.Sprintf("[*] APT mirror: %s\n", preset))
	}
	// Refresh the index first; a failure is not fatal (it may just be an unreachable
	// source), so keep trying the install
	update := aptUpdateArgv(s.pkgMgr, proxy)
	updateArgs := update[1:]
	if len(sourceArgs) > 0 {
		// Keep the host's default index files available after this job.
		updateArgs = append(updateArgs, "-o", "APT::Get::List-Cleanup=false")
		updateArgs = append(updateArgs, sourceArgs...)
	}
	env := []string{"DEBIAN_FRONTEND=noninteractive"}
	if code, err := s.execLogged(ctx, j, update[0], updateArgs, env); err != nil {
		j.append(fmt.Sprintf("[warn] index refresh failed (exit code %d), continuing with the install\n", code))
	}
	argv, err := aptArgv(tool, s.pkgMgr, proxy)
	if err != nil {
		return 1, err
	}
	return s.execLogged(ctx, j, argv[0], append(sourceArgs, argv[1:]...), env)
}

func (s *Server) runPip(ctx context.Context, j *Job, tool hosttools.Tool, proxy, preset string) (int, error) {
	argv := pipArgv(tool, proxy)
	env := proxyEnv(proxy)
	if index := pypiIndex(preset); index != "" {
		env = append(env, "PIP_INDEX_URL="+index)
		j.append(fmt.Sprintf("[*] PyPI mirror: %s\n", preset))
	}
	code, err := s.execLogged(ctx, j, argv[0], argv[1:], env)
	if err == nil {
		return code, nil
	}
	// Two layers of retry for network flakiness:
	// 1) retry once unchanged (PyPI connection resets are routine — measured: kube-hunter
	//    succeeded on the second manual attempt, while the old implementation only retried
	//    once with --ignore-installed and missed the install when it landed in the flaky
	//    window);
	// 2) if that still fails, switch to --ignore-installed (Debian/Ubuntu dist-packages
	//    have no RECORD file, so the pip uninstall reports uninstall-no-record-file).
	for attempt := 1; attempt <= 2; attempt++ {
		j.append(fmt.Sprintf("[warn] pip install failed, retrying in %ds (attempt %d/2)\n", attempt*5, attempt))
		select {
		case <-ctx.Done():
			return code, err
		case <-time.After(time.Duration(attempt*5) * time.Second):
		}
		code, err = s.execLogged(ctx, j, argv[0], argv[1:], env)
		if err == nil {
			return code, nil
		}
	}
	j.append("[warn] pip still failing, retrying with --ignore-installed\n")
	argv = appendIgnoreInstalled(argv)
	return s.execLogged(ctx, j, argv[0], argv[1:], env)
}

// appendIgnoreInstalled inserts --ignore-installed after pip's install subcommand.
func appendIgnoreInstalled(argv []string) []string {
	out := make([]string, 0, len(argv)+1)
	for _, a := range argv {
		out = append(out, a)
		if a == "install" {
			out = append(out, "--ignore-installed")
		}
	}
	return out
}

// proxyEnv injects the validated proxy into the child environment for curl/git/pip/gem
// and other scripts.
func proxyEnv(proxy string) []string {
	env := []string{
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
		"DEBIAN_FRONTEND=noninteractive",
		// hostd's ProtectHome=true makes /root unwritable; pip/gem write their cache to HOME
		// by default.
		"HOME=/var/lib/pojun-hostd",
		"XDG_CACHE_HOME=/var/cache/pojun-hostd",
		"PIP_CACHE_DIR=/var/cache/pojun-hostd/pip",
	}
	if proxy == "" {
		return env
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+proxy)
	}
	return append(env, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
}

// runGitHub fetches a single-file binary from a GitHub Release and installs it to
// /usr/local/bin.
func (s *Server) runGitHub(ctx context.Context, j *Job, tool hosttools.Tool, proxy string) (int, error) {
	client := httpClient(proxy)

	j.append(fmt.Sprintf("[*] Resolving the latest version of %s…\n", tool.Repo))
	tag, err := latestTag(ctx, client, GitHubAPITagURL(tool))
	if err != nil {
		return 1, fmt.Errorf("failed to resolve the latest version (configure an install proxy and retry): %w", err)
	}
	// The asset name supports "candidate1||candidate2": upstream asset naming shifts by version
	// and architecture (feroxbuster ships arm64 as .zip only from v2.14), so each candidate is
	// tried in turn on a 404.
	var urls []string
	for _, tmpl := range strings.Split(tool.AssetTmpl, "||") {
		if tmpl = strings.TrimSpace(tmpl); tmpl != "" {
			urls = append(urls, GitHubAssetURL(tool, tmpl, tag))
		}
	}
	if len(urls) == 0 {
		urls = []string{GitHubAssetURL(tool, tool.AssetTmpl, tag)}
	}

	var blob []byte
	var lastErr error
	for _, u := range urls {
		j.append(fmt.Sprintf("[*] Downloading %s\n", u))

		for attempt := 1; attempt <= 3; attempt++ {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			req.Header.Set("User-Agent", "pojun-hostd")
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				blob, err = io.ReadAll(io.LimitReader(resp.Body, 128<<20))
				resp.Body.Close()
				if err == nil && len(blob) > 0 {
					lastErr = nil
					break
				}
			} else if err == nil {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
				resp.Body.Close()
			}
			lastErr = err
			if attempt < 3 {
				j.append(fmt.Sprintf("[warn] download failed (%v), retrying in %d seconds…\n", err, attempt*2))
				select {
				case <-ctx.Done():
					return 1, ctx.Err()
				case <-time.After(time.Duration(attempt*2) * time.Second):
				}
			}
		}
		if len(blob) > 0 {
			break // this candidate downloaded successfully
		}
		// every retry failed → move to the next candidate asset (on a 404 there is no point
		// in another URL either, but the loop just ends)
	}
	if lastErr != nil {
		return 1, fmt.Errorf("download failed: %w", lastErr)
	}
	j.append(fmt.Sprintf("[*] Downloaded %.1f MB, extracting…\n", float64(len(blob))/(1<<20)))

	// Archive formats differ per project: ProjectDiscovery ships .zip, gitleaks/chisel/amass
	// ship .tar.gz or .gz, feroxbuster ships .tar.gz. The extraction path is chosen by
	// sniffing the content rather than guessing from the asset name suffix (a wrong suffix
	// means the install simply fails).
	return installFromArchive(j, blob, tool)
}

// installFromArchive extracts the target binary from the archive and installs it to
// /usr/local/bin. Supports zip / tar(.gz) / single-file gz.
func installFromArchive(j *Job, blob []byte, tool hosttools.Tool) (int, error) {
	if tool.Raw {
		return installBinary(j, tool, blob)
	}
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	// zip: PK\x03\x04
	if len(blob) > 4 && blob[0] == 'P' && blob[1] == 'K' {
		zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			return 1, fmt.Errorf("cannot parse the zip archive: %w", err)
		}
		return installFromZip(j, zr, tool)
	}
	// gzip: \x1f\x8b
	if len(blob) > 2 && blob[0] == 0x1f && blob[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return 1, fmt.Errorf("cannot parse gzip: %w", err)
		}
		defer gr.Close()
		// Either a single-file gz (the binary itself) or a tar.gz
		raw, err := io.ReadAll(io.LimitReader(gr, 256<<20))
		if err != nil {
			return 1, err
		}
		// It may be a tar.gz (several entries) or a single-file gz (the binary itself).
		// Distinguish by "can the target file be found in the tar stream": if found, install
		// that one from the tar; if not, treat the whole decompressed result as the binary.
		if data, ok := findInTar(raw, tool); ok {
			return installBinary(j, tool, data)
		}
		return installBinary(j, tool, raw)
	}
	// Plain tar
	if data, ok := findInTar(blob, tool); ok {
		return installBinary(j, tool, data)
	}
	return 1, fmt.Errorf("unrecognized archive format")
}

// findInTar looks for the target binary's content inside a tar (or decompressed tar.gz).
// ok=false means it was not found — the caller then falls back to "the whole file is the
// binary".
func findInTar(blob []byte, tool hosttools.Tool) ([]byte, bool) {
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, false
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != want {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return nil, false
		}
		return data, true
	}
}

// installBinary atomically installs the binary content to /usr/local/bin.
func installBinary(j *Job, tool hosttools.Tool, data []byte) (int, error) {
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	dst := tool.DestPath
	if dst == "" {
		dst = filepath.Join(binDir, tool.Bin)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 1, fmt.Errorf("failed to create directory: %w", err)
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return 1, fmt.Errorf("failed to write %s: %w", tmp, err)
	}
	if _, err := out.Write(data); err != nil {
		out.Close()
		os.Remove(tmp)
		return 1, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return 1, err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return 1, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return 1, err
	}
	j.append(fmt.Sprintf("[ok] %s → %s\n", want, dst))
	return 0, nil
}

func installFromZip(j *Job, zr *zip.Reader, tool hosttools.Tool) (int, error) {
	want := tool.BinInZip
	if want == "" {
		want = tool.Bin
	}
	for _, f := range zr.File {
		if path.Base(f.Name) != want || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return 1, err
		}
		defer rc.Close()
		dst := tool.DestPath
		if dst == "" {
			dst = filepath.Join(binDir, tool.Bin)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return 1, fmt.Errorf("failed to create directory: %w", err)
		}
		tmp := dst + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return 1, fmt.Errorf("failed to write %s: %w", tmp, err)
		}
		if _, err := io.Copy(out, io.LimitReader(rc, 256<<20)); err != nil {
			out.Close()
			os.Remove(tmp)
			return 1, err
		}
		if err := out.Close(); err != nil {
			os.Remove(tmp)
			return 1, err
		}
		if err := os.Chmod(tmp, 0o755); err != nil {
			os.Remove(tmp)
			return 1, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return 1, err
		}
		j.append(fmt.Sprintf("[ok] %s → %s\n", want, dst))
		return 0, nil
	}
	return 1, fmt.Errorf("binary %q not found in the archive", want)
}

// ── Helpers ──────────────────────────────────────

// httpClient builds an HTTP client that goes through the proxy.
//
// socks5 must go through golang.org/x/net/proxy's SOCKS5 dialer: http.ProxyURL only
// understands HTTP CONNECT proxies, and feeding it socks5:// yields "unsupported
// protocol scheme" — which looks like "I set a socks proxy but downloads still fail",
// with no hint to the user that the scheme is the mismatch.
//
// Client construction goes through the proxyprobe package: the runtime self-test API uses
// the same logic, so there is no split where "install said the proxy works but runtime
// cannot connect".
func httpClient(proxy string) *http.Client {
	c, err := proxyprobe.ClientFor(proxy, 10*time.Minute)
	if err != nil {
		// Fall back to a direct connection when the proxy string is invalid: let the install
		// continue and have the caller report the error in the log, rather than failing to
		// build a client at all.
		return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	return c
}

func latestTag(ctx context.Context, client *http.Client, apiURL string) (string, error) {
	// Channel 1: the GitHub API. Shared egress IPs are often 403 rate limited (measured on
	// Kali: 5 ProjectDiscovery tools all failed here).
	tag, apiErr := latestTagViaAPI(ctx, client, apiURL)
	if apiErr == nil && tag != "" {
		return tag, nil
	}
	// Channel 2: the 302 Location of releases/latest — the same path a browser takes, which
	// does not consume API quota.
	// apiURL looks like https://api.github.com/repos/<owner>/<repo>/releases/latest.
	if repo, ok := strings.CutPrefix(apiURL, "https://api.github.com/repos/"); ok {
		repo, _ = strings.CutSuffix(repo, "/releases/latest")
		if repo != "" {
			if tag, err := latestTagViaRedirect(ctx, client, "https://github.com/"+repo+"/releases/latest"); err == nil && tag != "" {
				return tag, nil
			}
		}
	}
	return "", apiErr
}

func latestTagViaAPI(ctx context.Context, client *http.Client, apiURL string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pojun-hostd")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", err
	}
	if payload.TagName == "" {
		return "", fmt.Errorf("no tag_name in the response")
	}
	return payload.TagName, nil
}

// latestTagViaRedirect does not follow redirects and takes the tag from the end of the
// Location path.
func latestTagViaRedirect(ctx context.Context, client *http.Client, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "pojun-hostd")
	// Do not follow: the 302 Location is all we need (following it lands on the release page
	// HTML).
	noFollow := *client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("HTTP %d with no Location", resp.StatusCode)
	}
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		tag := strings.TrimSuffix(loc[i+len("/tag/"):], "/")
		if tag != "" {
			return tag, nil
		}
	}
	return "", fmt.Errorf("no tag in the Location: %s", loc)
}

// ── HTTP ─────────────────────────────────────────

// Handler returns the mux served on the Unix socket.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"ok": true, "service": "pojun-hostd",
			"version": s.Version,
			"pkg_mgr": string(s.pkgMgr),
			"tools":   len(hosttools.Inventory()),
		})
	})

	// /version lets the main service align versions: after upgrading itself the main program
	// knocks with its own version, and the helper replaces itself when it finds it is behind
	// (see the UpgradeSelf comment: only the helper can do this).
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"service": "pojun-hostd", "version": s.Version, "install_sources": true})
	})

	mux.HandleFunc("POST /self-upgrade", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tag   string `json:"tag"`
			Proxy string `json:"proxy"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "request body is not valid JSON"})
			return
		}
		if !ValidVersionTag(req.Tag) {
			writeJSON(w, 400, map[string]any{"error": "invalid version format: " + req.Tag})
			return
		}
		// Audit B9: reject downgrades. Installing a lower version is only allowed explicitly by
		// re-running install.sh — the version-alignment request comes from the main program, which
		// may itself have been manually downgraded/rolled back; dragging the helper down too would
		// silently revert a known fix.
		if cmp, comparable := selfupdate.CompareVersions(s.Version, req.Tag); comparable && cmp > 0 {
			writeJSON(w, 400, map[string]any{"error": fmt.Sprintf("downgrade refused: helper is at %s, higher than the target %s; re-run install.sh to downgrade", s.Version, req.Tag)})
			return
		}
		cleanProxy, err := ValidateProxy(req.Proxy)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		if !s.upgrading.CompareAndSwap(false, true) {
			writeJSON(w, 409, map[string]any{"error": "a self-upgrade is already in progress"})
			return
		}
		writeJSON(w, 202, map[string]any{"ok": true, "target": req.Tag})
		// Use the process-level ctx: a request ctx is canceled as soon as it returns and the
		// download aborts on the spot (the same lesson, learned once).
		go func() {
			if err := s.UpgradeSelf(s.base, req.Tag, cleanProxy); err != nil {
				log.Printf("[hostd] self-upgrade failed: %v", err)
				s.upgrading.Store(false)
				return
			}
			log.Printf("[hostd] swapped in %s, exiting so systemd restarts us", req.Tag)
			// Leave a moment to flush the logs before exiting; Restart=always brings the new
			// version up.
			time.Sleep(300 * time.Millisecond)
			os.Exit(0)
		}()
	})

	mux.HandleFunc("GET /tools", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"tools": hosttools.Inventory()})
	})

	startJob := func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ToolID  string         `json:"tool_id"`
			Proxy   string         `json:"proxy"`
			Sources InstallSources `json:"sources"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"error": "request body is not valid JSON"})
			return
		}
		job, err := s.start(s.base, req.ToolID, req.Proxy, req.Sources)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 201, job)
	}
	mux.HandleFunc("POST /jobs", startJob)
	// With a selected mirror, old helpers must reject the job instead of silently
	// ignoring the preset and downloading from the default source.
	mux.HandleFunc("POST /jobs/with-sources", startJob)

	mux.HandleFunc("GET /jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		job, ok := s.Get(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "job not found"})
			return
		}
		writeJSON(w, 200, job)
	})

	mux.HandleFunc("POST /jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !s.Cancel(r.PathValue("id")) {
			writeJSON(w, 404, map[string]any{"error": "job not found"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	return mux
}

// Listen creates the Unix socket and sets permissions (readable/writable only by owner
// and group, so no other local user can trigger an install).
func Listen(socketPath string, mode os.FileMode, group string) (net.Listener, error) {
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, mode); err != nil {
		ln.Close()
		return nil, err
	}
	if group != "" {
		if g, err := lookupGID(group); err == nil {
			if err := os.Chown(socketPath, 0, g); err != nil {
				ln.Close()
				return nil, err
			}
		} else {
			ln.Close()
			return nil, fmt.Errorf("group %q not found: %w", group, err)
		}
	}
	return ln, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// lookupGID resolves a group name to a gid.
func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
