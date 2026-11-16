package hostd

import (
	"strings"
	"testing"

	"github.com/chu0119/pojun/hosttools"
)

// ValidateProxy is the only entry point that accepts an "external string", so injection
// surfaces must be blocked outright.
func TestValidateProxy(t *testing.T) {
	good := []string{
		"",
		"http://10.0.0.14:7897",
		"https://user:pass@proxy.example.com:443",
		"socks5://127.0.0.1:1080",
		"socks5h://127.0.0.1:1080",
	}
	for _, s := range good {
		if _, err := ValidateProxy(s); err != nil {
			t.Errorf("should accept %q but errored: %v", s, err)
		}
	}

	bad := []string{
		"ftp://1.2.3.4:21",              // unsupported scheme
		"http://",                       // missing host
		"not-a-url",                     // no scheme
		"http://a:1\nAcquire::x=y",      // newline injection
		"http://a:1 -o Foo::Bar=/tmp/x", // space injection (would slip arguments to apt)
		"http://a:1\ttab",               // tab
	}
	for _, s := range bad {
		if _, err := ValidateProxy(s); err == nil {
			t.Errorf("should reject %q but it passed", s)
		}
	}
}

// The whitelist is the core of the privilege boundary: any id not in the catalog must not
// be found.
func TestLookupAllowlist(t *testing.T) {
	if _, ok := hosttools.Lookup("nmap"); !ok {
		t.Error("nmap should be on the whitelist")
	}
	for _, bad := range []string{
		"", "rm", "sh", "/bin/sh", "../../etc/passwd",
		"nmap; rm -rf /", "nmap$(id)", "NMAP",
	} {
		if _, ok := hosttools.Lookup(bad); ok {
			t.Errorf("%q should not be on the whitelist", bad)
		}
	}
}

// The command must be fixed argv with package names only from the catalog — nothing goes
// through a shell, so there is no concatenation injection.
func TestAptArgvUsesCatalogPackage(t *testing.T) {
	nmap, _ := hosttools.Lookup("nmap")

	argv, err := aptArgv(nmap, PkgApt, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got != "apt-get install -y nmap" {
		t.Errorf("wrong apt argv: %s", got)
	}

	// The proxy should only appear as -o Acquire::* options, never become a standalone
	// command
	argv, _ = aptArgv(nmap, PkgApt, "http://10.0.0.14:7897")
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "Acquire::http::Proxy=http://10.0.0.14:7897") {
		t.Errorf("proxy not injected as Acquire options: %s", joined)
	}
	if strings.Count(joined, "install") != 1 {
		t.Errorf("abnormal argv structure: %s", joined)
	}

	// dnf uses a different package name table
	argv, _ = aptArgv(nmap, PkgDnf, "")
	if got := strings.Join(argv, " "); got != "dnf install -y nmap" {
		t.Errorf("wrong dnf argv: %s", got)
	}
}

func TestAptArgvNoPkgMgr(t *testing.T) {
	nmap, _ := hosttools.Lookup("nmap")
	if _, err := aptArgv(nmap, PkgNone, ""); err == nil {
		t.Error("it should error when there is no package manager")
	}
}

func TestGitHubAssetURL(t *testing.T) {
	nuclei, ok := hosttools.Lookup("nuclei")
	if !ok {
		t.Fatal("the catalog should contain nuclei")
	}
	u := GitHubAssetURL(nuclei, "v3.4.10")
	want := "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_"
	if !strings.HasPrefix(u, want) {
		t.Errorf("wrong asset URL prefix: %s", u)
	}
	if strings.Contains(u, "vv") {
		t.Errorf("the v prefix was not stripped from the version: %s", u)
	}
	if !strings.HasSuffix(u, ".zip") {
		t.Errorf("should be a zip asset: %s", u)
	}
}

func TestPipArgvIncludesProxy(t *testing.T) {
	w, ok := hosttools.Lookup("wafw00f")
	if !ok {
		t.Fatal("the catalog should contain wafw00f")
	}
	argv := pipArgv(w, "")
	if argv[len(argv)-1] != "wafw00f" {
		t.Errorf("the package name should be last: %v", argv)
	}
	argv = pipArgv(w, "http://10.0.0.14:7897")
	if !strings.Contains(strings.Join(argv, " "), "10.0.0.14:7897") {
		t.Errorf("proxy was not passed through: %v", argv)
	}
}

// manual-type tools must not be one-click installable, or hostd would execute a recipe
// that does not exist.
func TestManualToolNotInstallable(t *testing.T) {
	msf, ok := hosttools.Lookup("msfconsole")
	if !ok {
		t.Fatal("the catalog should contain msfconsole")
	}
	// v0.4.68: msfconsole installs via script (an outer repo script); the catalog has no
	// manual entries left.
	if !msf.Installable {
		t.Error("msfconsole should be marked one-click installable (script)")
	}
	if msf.Kind != hosttools.KindScript {
		t.Errorf("msfconsole kind should be script, got %q", msf.Kind)
	}
}

// The added ProjectDiscovery tools (naabu/dnsx/katana/tlsx) must be shaped like the three
// existing ones: asset name {tool}_{ver}_linux_{arch}.zip (no v prefix).
// A wrong template shows up as "download 404" while the user only sees "install failed",
// with no hint that the asset name is misspelled.
func TestAssetURLForProjectDiscoveryFamily(t *testing.T) {
	for _, id := range []string{"nuclei", "httpx", "subfinder", "naabu", "dnsx", "katana", "tlsx"} {
		tool, ok := hosttools.Lookup(id)
		if !ok {
			t.Fatalf("%s is not in the catalog", id)
		}
		if tool.Kind != hosttools.KindGitHub {
			t.Errorf("%s kind should be github, got %q", id, tool.Kind)
		}
		u := GitHubAssetURL(tool, "v1.2.3")
		want := "https://github.com/projectdiscovery/" + id +
			"/releases/download/v1.2.3/" + id + "_1.2.3_linux_"
		if !strings.HasPrefix(u, want) {
			t.Errorf("%s URL is wrong: %s", id, u)
		}
		if !strings.HasSuffix(u, ".zip") {
			t.Errorf("%s URL suffix is wrong: %s", id, u)
		}
	}
}

// Pure libraries (no CLI entry) must go through pip, not pipx.
//
// Regression background (measured on Kali 2026-10-22): the middleware protocol tools are
// all pure libraries (gmqtt/pika/pymongo/zeep...) and pipx **can only install
// applications with a CLI entry** — installing a pure library with pipx fails outright:
//
//	No apps associated with package gmqtt or its dependencies. If you are
//	attempting to install a library, pipx should not be used.
//
// That time all 6 packages failed on this path and not one got installed.
func TestPipLibraryUsesPipNotPipx(t *testing.T) {
	w, ok := hosttools.Lookup("gmqtt")
	if !ok {
		t.Fatal("the catalog should contain gmqtt")
	}
	if !w.PipLibrary {
		t.Fatal("gmqtt is a pure library and should be marked PipLibrary")
	}
	argv := pipArgv(w, "")
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "pipx") {
		t.Errorf("a pure library must not go through pipx (pipx cannot install pure libraries): %v", argv)
	}
	if !strings.Contains(joined, "pip") {
		t.Errorf("a pure library should go through pip: %v", argv)
	}
	// PEP668's externally-managed restriction must be bypassed or Debian-family hosts cannot
	// install it.
	if !strings.Contains(joined, "--break-system-packages") {
		t.Errorf("the pip install needs --break-system-packages (PEP668): %v", argv)
	}
}

// Tools with a CLI entry keep going through pipx (the isolated environment does not
// pollute the system Python).
func TestCLIToolStillUsesPipx(t *testing.T) {
	w, ok := hosttools.Lookup("wafw00f")
	if !ok {
		t.Fatal("the catalog should contain wafw00f")
	}
	if w.PipLibrary {
		t.Fatal("wafw00f has a CLI entry and should not be marked a pure library")
	}
	argv := pipArgv(w, "")
	// Use pipx when present, otherwise fall back to pip — both must carry the package name.
	if !strings.Contains(strings.Join(argv, " "), "wafw00f") {
		t.Errorf("package name was not included: %v", argv)
	}
}

// A multi-package recipe must split into separate argv elements — "pika amqpstorm" as one
// package name does not install.
func TestPipArgvSplitsMultiplePackages(t *testing.T) {
	tool := hosttools.Tool{Name: "mq", Pip: "pika amqpstorm", PipLibrary: true}
	argv := pipArgv(tool, "")
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "pika") || !strings.Contains(joined, "amqpstorm") {
		t.Errorf("multi-package recipe was not split: %v", argv)
	}
	// They must be two separate elements, not one element containing a space.
	found := 0
	for _, a := range argv {
		if a == "pika" || a == "amqpstorm" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("the multi-package recipe should split into two separate argv elements, got %d: %v", found, argv)
	}
}
