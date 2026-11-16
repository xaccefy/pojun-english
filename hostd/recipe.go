// Package hostd: POJUN's privileged install helper (pojun-hostd).
//
// Why it is needed: the main service's systemd unit carries NoNewPrivileges=true +
// ProtectSystem=strict + CapabilityBoundingSet=CAP_NET_BIND_SERVICE, so the process
// cannot gain privileges and /usr is read-only — which makes "one-click install"
// impossible for the web service itself. hostd runs as root permanently, accepts
// requests only over a Unix socket, and **only recognizes tool ids on the hosttools
// whitelist**, never a free-form command.
//
// Attack surface is narrowed: no TCP port (AF_UNIX only); the socket is 0600/0660 and
// owned by the runtime user; every action is assembled from fixed argv in the catalog,
// proxy addresses are URL-validated, and every executed command goes to the audit log.
package hostd

import (
	"fmt"
	"net/url"
	"os"
	"os/user"
	"strings"

	"github.com/chu0119/pojun/hosttools"
)

// PkgMgr is a system package manager.
type PkgMgr string

const (
	PkgApt  PkgMgr = "apt"
	PkgDnf  PkgMgr = "dnf"
	PkgNone PkgMgr = ""
)

// DetectPkgMgr probes the local package manager (only these two are recognized; other
// distributions use the GitHub/pip recipes).
func DetectPkgMgr() PkgMgr {
	for _, p := range []struct {
		mgr  PkgMgr
		path string
	}{{PkgApt, "/usr/bin/apt-get"}, {PkgApt, "/usr/local/bin/apt-get"}, {PkgDnf, "/usr/bin/dnf"}} {
		if st, err := os.Stat(p.path); err == nil && !st.IsDir() {
			return p.mgr
		}
	}
	return PkgNone
}

// ValidateProxy validates a proxy address. Only http/https/socks5 are allowed and a
// host:port is required — the proxy string is passed to apt/child processes as
// argv/env, so newlines/spaces and other injection surfaces must be blocked.
func ValidateProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.ContainsAny(raw, "\n\r\t ") {
		return "", fmt.Errorf("proxy address contains illegal whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("cannot parse proxy address: %v", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("proxy only supports http/https/socks5, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("proxy address is missing host:port")
	}
	return raw, nil
}

// APTProxyArgs turns the proxy into apt Acquire options (no global apt.conf, to avoid
// persistent pollution).
func APTProxyArgs(proxy string) []string {
	if proxy == "" {
		return nil
	}
	return []string{
		"-o", "Acquire::http::Proxy=" + proxy,
		"-o", "Acquire::https::Proxy=" + proxy,
	}
}

// aptArgv builds the apt install command. pkg comes from the catalog (not user input)
// and proxy is already validated.
func aptArgv(tool hosttools.Tool, mgr PkgMgr, proxy string) ([]string, error) {
	var pkg string
	switch mgr {
	case PkgApt:
		pkg = tool.Apt
	case PkgDnf:
		pkg = tool.Dnf
	default:
		return nil, fmt.Errorf("%s needs a system package manager (apt/dnf), none detected on this host", tool.Name)
	}
	if pkg == "" {
		return nil, fmt.Errorf("%s has no package name for this host's package manager", tool.Name)
	}
	// One tool may map to several system packages (e.g. the three LibreOffice
	// components), so the package field may be space-separated.
	pkgs := strings.Fields(pkg)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s has no package name for this host's package manager", tool.Name)
	}
	if mgr == PkgApt {
		argv := append([]string{"apt-get"}, APTProxyArgs(proxy)...)
		argv = append(argv, "install", "-y")
		return append(argv, pkgs...), nil
	}
	argv := []string{"dnf"}
	if proxy != "" {
		argv = append(argv, "--setopt=proxy="+proxy)
	}
	argv = append(argv, "install", "-y")
	return append(argv, pkgs...), nil
}

// aptUpdateArgv refreshes the apt index (apt sources go stale over time, so update once
// before installing).
func aptUpdateArgv(mgr PkgMgr, proxy string) []string {
	if mgr == PkgApt {
		argv := append([]string{"apt-get"}, APTProxyArgs(proxy)...)
		return append(argv, "update")
	}
	return []string{"dnf", "makecache"}
}

// pipArgv builds the pip install command.
//
// Two modes:
//
//   - **pure library** (tool.PipLibrary=true): use `python3 -m pip install`. pipx cannot
//     install a pure library — it reports "No apps associated with package X ... pipx
//     should not be used" (measured on Kali 2026-10-22: gmqtt/pika/pymongo/zeep all fail
//     this way). --break-system-packages is used to bypass PEP668's externally-managed
//     restriction (the system Python on Debian/Ubuntu/Kali all carry that marker).
//
//   - **has a CLI entry** (default): prefer pipx. An isolated environment that does not
//     pollute the system Python is exactly what we want; without pipx, fall back to pip.
//
// tool.Pip may be **several space-separated packages** (middleware tools often need a set
// of libraries). Split on spaces into separate argv elements — otherwise "pika amqpstorm"
// is treated as one package name and nothing installs.
func pipArgv(tool hosttools.Tool, proxy string) []string {
	pkgs := strings.Fields(tool.Pip)
	if len(pkgs) == 0 {
		pkgs = []string{tool.Name}
	}
	if !tool.PipLibrary {
		if _, err := os.Stat("/usr/bin/pipx"); err == nil {
			argv := []string{"pipx", "install"}
			// As root, --global is mandatory: otherwise the entry scripts land in
			// /root/.local/bin, which the pojun service user can neither traverse nor find on
			// PATH (the same trap as install.sh).
			if runningAsRoot() {
				argv = append(argv, "--global")
			}
			pipArgs := "--no-cache-dir"
			if proxy != "" {
				pipArgs += " --proxy=" + proxy
			}
			argv = append(argv, "--pip-args="+pipArgs)
			return append(argv, pkgs...)
		}
	}
	argv := []string{"python3", "-m", "pip", "install", "--break-system-packages", "--no-cache-dir"}
	if proxy != "" {
		argv = append(argv, "--proxy", proxy)
	}
	return append(argv, pkgs...)
}

// GitHubAssetURL assembles the download URL from the asset template. tag looks like
// v3.4.10 and the asset name carries no v.
//
// Template placeholders:
//
//	{ver}   version (without v), e.g. 3.4.10
//	{verv}  version (with v), e.g. v3.4.10
//	{arch}  architecture, amd64 / arm64 (Go's GOARCH spelling)
//	{arch2} architecture, x86_64 / aarch64 (some projects use this, e.g. gitleaks/amass)
//	{arch3} architecture, x86 / arm (yet another set, e.g. some chisel assets)
//	{arch4} architecture, x64 / arm64 (what gitleaks uses)
//	{arch5} architecture, 64bit / ARM64 (what trivy uses)
//
// Asset naming varies a lot across projects (architecture first or last, version with or
// without v, extension .zip/.tar.gz/.gz), so the template must cover those differences;
// otherwise "one-click install" only works for half the projects.
func GitHubAssetURL(tool hosttools.Tool, tag string) string {
	ver := strings.TrimPrefix(tag, "v")
	asset := strings.ReplaceAll(tool.AssetTmpl, "{ver}", ver)
	asset = strings.ReplaceAll(asset, "{verv}", tag)
	asset = strings.ReplaceAll(asset, "{arch}", hosttools.Arch())
	asset = strings.ReplaceAll(asset, "{arch2}", hosttools.ArchAlt())
	asset = strings.ReplaceAll(asset, "{arch3}", hosttools.ArchShort())
	asset = strings.ReplaceAll(asset, "{arch4}", hosttools.ArchX64())
	asset = strings.ReplaceAll(asset, "{arch5}", hosttools.ArchLong())
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", tool.Repo, tag, asset)
}

// GitHubAPITagURL returns the API URL for the latest tag.
func GitHubAPITagURL(tool hosttools.Tool) string {
	return fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", tool.Repo)
}

// runningAsRoot reports whether the host process is root. hostd is started by systemd as
// root; when not root, pipx gets no --global (keeping user-level install semantics).
func runningAsRoot() bool {
	u, err := user.Current()
	return err == nil && u.Uid == "0"
}
