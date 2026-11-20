// Package hosttools: host tool inventory + install recipes.
//
// In the binary deployment form POJUN runs directly on the operating system —
// whatever pentest tools the host has installed, a worker can call directly
// through the Bash tool. This package probes a catalog of common tools with
// exec.LookPath (available/missing + install hint), injects it into
// graph_overview so the model knows what it has when dispatching intents, and
// exposes it to the frontend via /api/tools/inventory.
//
// The same catalog also drives "one-click install": each tool carries a Kind plus
// a recipe (apt package name / GitHub Release asset template / pip package /
// manual only), executed by the privileged helper pojun-hostd. **The inventory and
// the installer share this one catalog**, so there is no drift where "the page
// lists it but the installer cannot install it".
//
// LookPath only scans PATH and takes microseconds per call, so no caching.
package hosttools

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind is the install method. manual = upstream only offers an interactive
// installer, so there is no one-click path.
type Kind string

const (
	KindApt    Kind = "apt"    // system package manager (apt/dnf)
	KindGitHub Kind = "github" // single file from a GitHub Release
	KindPip    Kind = "pip"    // pip / pipx
	KindScript Kind = "script" // fixed install script kept in this catalog (git clone / download+extract / gem, ...)
	KindManual Kind = "manual" // no one-click install
)

// Category is the attack-surface grouping. Kind says "how to install", Category says
// "what it is for and where it is used" — the catalog holds 39 tools, and a flat
// table is unreadable: the user wants to answer "which tools do I have for the web
// side", not "there are 39 rows". The page groups by Category; the model-side list
// is unaffected.
type Category string

const (
	CatNetwork Category = "network" // port scanning / connectivity / basic networking
	CatWeb     Category = "web"     // web-side probing, brute force, scanning
	CatDNS     Category = "dns"     // asset mapping and domain enumeration
	CatCred    Category = "cred"    // online brute force, offline cracking, lateral movement
	CatCode    Category = "code"    // source/secret leaks, code audit
	CatPivot   Category = "pivot"   // internal pivoting, proxy forwarding
	CatOOB     Category = "oob"     // out-of-band channels, notifications
	CatExploit Category = "exploit" // framework and binary exploitation
	// CatMobile is mobile reverse engineering (v0.6): APK unpacking/decompiling/
	// repacking/dynamic hooking. Grey-market distribution often ships only an APK or
	// installer, so this non-web side has to be taken apart by ourselves.
	CatMobile   Category = "mobile"   // mobile reverse engineering (APK/Android)
	CatMaterial Category = "material" // wordlists, corpora
	CatRuntime  Category = "runtime"  // scripting, certificates, HTTP and other basics
	// CatMiddleware holds middleware-protocol-specific tools.
	//
	// Why a separate class (2026-10-22 research): of the CVSS>=9.0 vulnerabilities on
	// NVD in the last 30 days, middleware accounted for a large share —
	// apache/http_server, apache/cxf (SOAP), mariadb, rabbitmq_server, moquette
	// (MQTT), gitlab, splunk, f5/big-ip, fortinet/fortimail... — while general-purpose
	// scanners (nmap/nuclei) either do not recognize this **protocol-type** middleware
	// or only run generic probes against it.
	//
	// The tools here are **protocol client libraries** — not "one-click hole punching"
	// exploiters, but the means for the Agent to talk to the middleware directly:
	// enumerate config, read queues, subscribe to topics, call admin APIs. "How to
	// attack" is still decided by the Agent together with vulnerability intel.
	CatMiddleware Category = "middleware" // middleware protocol specials (MQTT/AMQP/DB/SOAP/devices, ...)
)

// categoryOrder decides the grouping order on the page — laid out along the attack
// flow: map the surface first (network/DNS) → then strike (web/credentials) → go
// deeper (code/exploit) → supporting (tunneling/OOB/materials/runtime).
var categoryOrder = []Category{
	CatNetwork, CatDNS, CatWeb, CatCred, CatCode,
	CatExploit, CatMobile, CatMiddleware, CatPivot, CatOOB, CatMaterial, CatRuntime,
}

// CategoryLabel is the human-readable label of a category (shown on the page).
func CategoryLabel(c Category) string {
	switch c {
	case CatNetwork:
		return "Network & Host"
	case CatWeb:
		return "Web Applications"
	case CatDNS:
		return "Subdomains & DNS"
	case CatCred:
		return "Credentials & Passwords"
	case CatCode:
		return "Code & Secrets"
	case CatPivot:
		return "Internal Network & Tunneling"
	case CatOOB:
		return "OOB & Callbacks"
	case CatExploit:
		return "Exploitation"
	case CatMobile:
		return "Mobile Reverse Engineering"
	case CatMiddleware:
		return "Middleware Protocols"
	case CatMaterial:
		return "Materials & Wordlists"
	case CatRuntime:
		return "General & Runtime"
	default:
		return "Other"
	}
}

// Tool is one inventory entry plus its install recipe.
type Tool struct {
	ID   string `json:"id"`   // stable identifier (same as Bin)
	Name string `json:"name"` // tool name (for display)
	Bin  string `json:"bin"`  // binary name probed on PATH

	Available   bool     `json:"available"`
	Installable bool     `json:"installable"`       // whether one-click install is possible
	Purpose     string   `json:"purpose"`           // what it is for (shown to the model)
	Install     string   `json:"install,omitempty"` // install hint shown when missing
	Kind        Kind     `json:"kind"`
	Category    Category `json:"category"` // attack-surface category (page grouping)

	// kind=apt: package names per package manager
	Apt string `json:"-"`
	Dnf string `json:"-"`

	// kind=github: owner/repo + asset name template ({ver} without the v, {arch} = amd64|arm64)
	// + the binary name inside the archive (empty = same as Bin).
	// AssetTmpl supports "candidate1||candidate2": each is tried in turn on a 404 (for tools whose
	// upstream asset naming shifts by version/architecture, e.g. feroxbuster serving only .zip for
	// arm64 from v2.14).
	Repo      string `json:"-"`
	AssetTmpl string `json:"-"`
	BinInZip  string `json:"-"`

	// kind=pip
	Pip string `json:"-"`

	// kind=script: a fixed install script (maintained in this catalog, never taken
	// from user input). The host helper runs it with /bin/sh -c; the script usually
	// does a git clone, download+extract, gem/pip install and symlinks.
	Script string `json:"-"`

	// Detect specifies how to probe availability for tools that are not on PATH:
	//   path:/opt/xxx       available if the file exists
	//   dir:/opt/SecLists   available if the directory exists
	//   python:module       available if python3 can import the module (pure library)
	// Empty means use exec.LookPath on Bin.
	Detect string `json:"-"`

	// Raw means the GitHub Release asset is itself a single file (not zip/tar/gz),
	// e.g. pspy64 / linpeas_linux_amd64 / ysoserial-all.jar.
	Raw bool `json:"-"`

	// DestPath is the absolute install target; empty installs to /usr/local/bin/<Bin>.
	// Used for assets such as jars or Windows exes that do not belong in a bin dir.
	DestPath string `json:"-"`

	// PipLibrary marks this pip package as a **pure library** (no command-line entry).
	//
	// Why the distinction is needed (measured 2026-10-22): pipx can only install
	// "applications with a CLI entry point"; installing a pure library fails outright
	// with:
	//
	//	No apps associated with package gmqtt or its dependencies. If you are
	//	attempting to install a library, pipx should not be used.
	//
	// The middleware protocol tools (gmqtt/pika/pymongo/zeep...) are all pure
	// libraries — they are meant to be imported by the Agent inside scripts, not run
	// as command-line tools. Installing them must go through pip.
	//
	// The ones that do have a CLI (wafw00f/netexec/semgrep/pwntools) keep going through
	// pipx: the isolated environment does not pollute the system Python, which is
	// exactly what we want.
	PipLibrary bool `json:"-"`
}

// catalog is the common pentest tool catalog. Self-contained install methods are
// preferred: if a single GitHub Release file works, do not depend on go install (the
// host may not have a Go toolchain).
var catalog = []Tool{
	{Name: "nmap", Purpose: "port scanning / service fingerprinting", Kind: KindApt, Category: CatNetwork, Apt: "nmap", Dnf: "nmap"},
	{Name: "masscan", Purpose: "large-scale fast port sweep", Kind: KindApt, Category: CatNetwork, Apt: "masscan", Dnf: "masscan"},
	{Name: "sqlmap", Purpose: "SQL injection detection and exploitation", Kind: KindApt, Category: CatWeb, Apt: "sqlmap", Dnf: "sqlmap"},
	{Name: "imagemagick", Bin: "magick", Purpose: "evidence image processing: montage/watermark/redaction (required for photo evidence in reports)", Kind: KindApt, Category: CatRuntime, Apt: "imagemagick", Dnf: "ImageMagick",
		Detect: "any:path:/usr/bin/magick,path:/usr/bin/convert,path:/usr/local/bin/magick,path:/usr/local/bin/convert"},
	{Name: "libreoffice", Purpose: "document evidence preview: Word/Excel/PPT→PDF (attachment thumbnails and report previews)", Kind: KindApt, Category: CatRuntime, Apt: "libreoffice-writer libreoffice-calc libreoffice-impress", Dnf: "libreoffice-writer libreoffice-calc libreoffice-impress"},
	{Name: "poppler", Bin: "pdftoppm", Purpose: "PDF to image (required for document evidence preview)", Kind: KindApt, Category: CatRuntime, Apt: "poppler-utils", Dnf: "poppler-utils"},
	{Name: "ffuf", Purpose: "directory/parameter fuzzing", Kind: KindApt, Category: CatWeb, Apt: "ffuf", Dnf: "ffuf"},
	{Name: "gobuster", Purpose: "directory/DNS/vhost brute force", Kind: KindApt, Category: CatWeb, Apt: "gobuster", Dnf: "gobuster"},
	{Name: "nikto", Purpose: "web server common-issue scanning", Kind: KindScript, Category: CatWeb,
		Script: `if ! command -v nikto >/dev/null 2>&1; then rm -rf /opt/nikto && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && chmod +x /opt/nikto/program/nikto.pl && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && nikto -Version >/dev/null 2>&1; fi`},
	{Name: "whatweb", Purpose: "web fingerprinting", Kind: KindApt, Category: CatWeb, Apt: "whatweb", Dnf: "whatweb"},
	{Name: "hydra", Purpose: "online password brute force (ssh/login forms, etc.)", Kind: KindApt, Category: CatCred, Apt: "hydra", Dnf: "hydra"},
	{Name: "john", Purpose: "offline password cracking", Kind: KindApt, Category: CatCred, Apt: "john", Dnf: "john"},
	{Name: "hashcat", Purpose: "GPU password cracking", Kind: KindApt, Category: CatCred, Apt: "hashcat", Dnf: "hashcat"},
	{Name: "curl", Purpose: "HTTP requests and debugging", Kind: KindApt, Category: CatRuntime, Apt: "curl", Dnf: "curl"},
	{Name: "openssl", Purpose: "TLS certificate inspection/encryption", Kind: KindApt, Category: CatNetwork, Apt: "openssl", Dnf: "openssl"},
	{Name: "python3", Purpose: "script execution/custom PoCs", Kind: KindApt, Category: CatRuntime, Apt: "python3", Dnf: "python3"},
	{Name: "nc", Purpose: "TCP/UDP connect and listen (reverse-shell interaction)", Kind: KindApt, Category: CatNetwork, Apt: "netcat-openbsd", Dnf: "nmap-ncat"},
	{Name: "dig", Purpose: "DNS queries", Kind: KindApt, Category: CatDNS, Apt: "dnsutils", Dnf: "bind-utils"},
	{Name: "ssh", Purpose: "login validation/tunneling", Kind: KindApt, Category: CatNetwork, Apt: "openssh-client", Dnf: "openssh-clients"},
	{Name: "testssl.sh", Bin: "testssl", Purpose: "TLS misconfiguration scanning", Kind: KindApt, Category: CatNetwork, Apt: "testssl.sh", Dnf: "testssl"},
	// nodejs is installed together with npx: MCP starts the browser server with
	// `npx @playwright/mcp`, and without node on the machine that MCP can never
	// connect (measured: every worker start reported
	// "npx: executable file not found in $PATH").
	{Name: "nodejs", Bin: "node", Purpose: "Node runtime (npx comes with it, for MCP servers)", Kind: KindApt, Category: CatRuntime, Apt: "nodejs", Dnf: "nodejs"},

	{Name: "nuclei", Purpose: "template-based vulnerability scanning (wired to vulnerability intel)", Kind: KindGitHub, Category: CatWeb,
		Repo: "projectdiscovery/nuclei", AssetTmpl: "nuclei_{ver}_linux_{arch}.zip"},
	{Name: "httpx", Purpose: "bulk web liveness/fingerprint probing (projectdiscovery version)", Kind: KindGitHub, Category: CatWeb,
		Repo: "projectdiscovery/httpx", AssetTmpl: "httpx_{ver}_linux_{arch}.zip"},
	{Name: "subfinder", Purpose: "subdomain enumeration", Kind: KindGitHub, Category: CatDNS,
		Repo: "projectdiscovery/subfinder", AssetTmpl: "subfinder_{ver}_linux_{arch}.zip"},
	// Four more ProjectDiscovery tools: naabu (port scan), dnsx (DNS resolve/brute),
	// katana (crawler), tlsx (TLS certificate probing). Their asset naming is the same
	// shape as the three above ({tool}_{ver}_linux_{arch}.zip), so one AssetTmpl
	// template suffices.
	{Name: "naabu", Purpose: "fast port scanning (pairs with httpx to filter live hosts)", Kind: KindGitHub, Category: CatNetwork,
		Repo: "projectdiscovery/naabu", AssetTmpl: "naabu_{ver}_linux_{arch}.zip"},
	{Name: "dnsx", Purpose: "DNS resolution/brute force/record extraction", Kind: KindGitHub, Category: CatDNS,
		Repo: "projectdiscovery/dnsx", AssetTmpl: "dnsx_{ver}_linux_{arch}.zip"},
	{Name: "katana", Purpose: "web crawler (deep paths and parameters)", Kind: KindGitHub, Category: CatWeb,
		Repo: "projectdiscovery/katana", AssetTmpl: "katana_{ver}_linux_{arch}.zip"},
	{Name: "tlsx", Purpose: "TLS certificate info extraction (cert / SAN / expiry)", Kind: KindGitHub, Category: CatNetwork,
		Repo: "projectdiscovery/tlsx", AssetTmpl: "tlsx_{ver}_linux_{arch}.zip"},

	// ── Mobile reverse engineering (v0.6): static chain (apktool/aapt/jadx) + dynamic
	// chain (adb/frida/objection) ──
	// Without a real device on the server, use the dynamic chain as "adb direct when a
	// device is present, static + traffic simulation when not".
	{Name: "java", Purpose: "JVM runtime (needed by apktool/jadx)", Kind: KindApt, Category: CatMobile, Apt: "openjdk-17-jre-headless", Dnf: "java-17-openjdk-headless"},
	{Name: "apktool", Purpose: "APK unpacking/repacking (resources + smali)", Kind: KindApt, Category: CatMobile, Apt: "apktool", Dnf: "apktool"},
	{Name: "aapt", Purpose: "APK manifest/resource table parsing", Kind: KindApt, Category: CatMobile, Apt: "aapt", Dnf: "android-tools"},
	{Name: "adb", Purpose: "direct Android device access: install/pull/logs/port forwarding", Kind: KindApt, Category: CatMobile, Apt: "adb", Dnf: "android-tools"},
	{Name: "jadx", Purpose: "APK→Java decompilation (endpoints/keys/business logic)", Kind: KindScript, Category: CatMobile,
		Script: `set -e
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 https://api.github.com/repos/skylot/jadx/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 > /tmp/jadx.tag
TAG=$(cat /tmp/jadx.tag); VER=${TAG#v}
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/${TAG}/jadx-${VER}.zip"
rm -rf /opt/jadx && mkdir -p /opt/jadx && unzip -q -o /tmp/jadx.zip -d /opt/jadx
ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui 2>/dev/null || true
`},
	{Name: "frida", Bin: "frida", Purpose: "dynamic hooking (SSL pinning/encryption/anti-bot bypass)", Kind: KindPip, Category: CatMobile, Pip: "frida-tools"},
	{Name: "objection", Purpose: "Frida wrapper: one-shot bypass of pinning/root detection", Kind: KindPip, Category: CatMobile, Pip: "objection"},

	{Name: "wafw00f", Purpose: "WAF identification", Kind: KindPip, Category: CatWeb, Pip: "wafw00f"},
	// impacket: SMB/NTLM/ticket toolset (smbexec/wmiexec/secretsdump, ...).
	// Note (measured 2026-11): apt's python3-impacket ships the examples commands only on
	// Kali, Debian has just the library; and PyPI's wheel/sdist register no commands in
	// either 0.11 or 0.12+. So the inventory checks the impacket-smbexec command; when
	// missing, the Install recipe below generates wrappers from the installed package's
	// examples directory (the Docker image build already does this).
	{Name: "impacket", Bin: "impacket-smbexec", Purpose: "SMB/NTLM protocol toolset (smbexec/wmiexec/secretsdump, etc.)", Kind: KindScript, Category: CatCred,
		Script: `set -e
python3 -m pip install --break-system-packages impacket
EX=$(python3 -c 'import impacket,os;print(os.path.join(os.path.dirname(impacket.__file__),"examples"))')
for f in "$EX"/*.py; do b=$(basename "$f" .py); printf '#!/bin/sh\nexec python3 "%s/%s.py" "$@"\n' "$EX" "$b" > "/usr/local/bin/impacket-$b"; chmod +x "/usr/local/bin/impacket-$b"; done
ln -sfn "$EX" /opt/impacket-examples
ln -sf /usr/local/bin/smbexec.py /usr/local/bin/impacket-smbexec
for b in psexec wmiexec secretsdump atexec smbclient; do [ -f "/usr/local/bin/$b.py" ] && ln -sf "/usr/local/bin/$b.py" "/usr/local/bin/impacket-$b"; done
`},
	// AD advanced (v0.7): certificate services, BloodHound collection, LDAP enumeration
	// and prerequisites for password spraying.
	{Name: "certipy", Bin: "certipy", Purpose: "AD CS enumeration and exploitation (ESC1-ESC17, certificate request/relay)", Kind: KindPip, Category: CatCred, Pip: "certipy-ad"},
	{Name: "bloodhound-python", Purpose: "BloodHound data collection (ACL/delegation/session paths)", Kind: KindPip, Category: CatCred, Pip: "bloodhound"},
	{Name: "ldapdomaindump", Purpose: "bulk LDAP domain export (users/groups/policies)", Kind: KindPip, Category: CatCred, Pip: "ldapdomaindump"},
	{Name: "adidnsdump", Purpose: "ADIDNS record enumeration (internal host name discovery)", Kind: KindPip, Category: CatCred, Pip: "adidnsdump"},
	{Name: "kerbrute", Purpose: "Kerberos username enumeration/spraying (lockout-aware)", Kind: KindGitHub, Category: CatCred,
		Repo: "ropnop/kerbrute", AssetTmpl: "kerbrute_linux_{arch}", Raw: true},
	{Name: "winpeas", Purpose: "Windows privilege escalation enumeration (PEASS family)", Kind: KindScript, Category: CatCred,
		Detect: "path:/opt/winpeas/winPEASx64.exe",
		Script: `set -e
mkdir -p /opt/winpeas
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o /opt/winpeas/winPEASx64.exe https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe
chmod +x /opt/winpeas/winPEASx64.exe
`},
	// SecLists is the largest general wordlist set (corpora for directory brute force /
	// parameter fuzzing). There is no stable apt package name, so it can only be cloned
	// from GitHub; detection is by directory existence.
	{Name: "seclists", Purpose: "general wordlist set (corpora for directory/parameter/username brute force)", Kind: KindScript, Category: CatMaterial,
		Detect: "dir:/opt/SecLists",
		Script: `set -e
if [ ! -d /opt/SecLists/.git ]; then rm -rf /opt/SecLists; git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists; fi
`},

	// ── Projects whose asset naming differs from the above ──
	// Release asset naming is very inconsistent across projects (architecture first or
	// last, version with or without v, extension .zip/.tar.gz/.gz), so each template has
	// to be written against the measured asset name.
	// Every asset name here was measured against the GitHub API in 2026-10, not guessed.

	// gitleaks: the asset name uses x64 (not x86_64) and is a .tar.gz.
	{Name: "gitleaks", Purpose: "secret scanning in code/config (detects hard-coded credentials)", Kind: KindGitHub, Category: CatCode,
		Repo: "gitleaks/gitleaks", AssetTmpl: "gitleaks_{ver}_linux_{arch4}.tar.gz"},
	// ── v0.7 arsenal fill-in: advanced web / exploitation / cloud native / recon ──
	// Kept on manual (with the official URL): these projects' release asset names are
	// irregular and a hard-coded one-click recipe easily installs the wrong version;
	// first guarantee "the inventory is visible + the install path is explicit", then
	// verify each recipe by hand later.
	{Name: "arjun", Purpose: "HTTP parameter discovery (hidden parameter enumeration)", Kind: KindPip, Category: CatWeb, Pip: "arjun"},
	{Name: "jwt_tool", Purpose: "JWT testing (alg confusion/kid injection/key brute force)", Kind: KindScript, Category: CatWeb,
		Script: `set -e
if [ ! -d /opt/jwt_tool/.git ]; then rm -rf /opt/jwt_tool; git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool; fi
ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
chmod +x /opt/jwt_tool/jwt_tool.py
`},
	{Name: "ysoserial", Purpose: "Java deserialization payload generation (pick the chain per target classpath)", Kind: KindGitHub, Category: CatExploit,
		Repo: "frohoff/ysoserial", AssetTmpl: "ysoserial-all.jar", Raw: true,
		DestPath: "/opt/ysoserial.jar", Detect: "path:/opt/ysoserial.jar"},
	{Name: "ysoserial.net", Purpose: ".NET deserialization/ViewState payload generation (runs on the Windows side)", Kind: KindScript, Category: CatExploit,
		Detect: "dir:/opt/ysoserial.net",
		Script: `set -e
mkdir -p /opt/ysoserial.net
API=$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 https://api.github.com/repos/pwntester/ysoserial.net/releases/latest)
URL=$(printf '%s' "$API" | grep -o '"browser_download_url": *"[^"]*\.zip"' | head -1 | cut -d'"' -f4)
[ -n "$URL" ] && curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o /tmp/ysnet.zip "$URL" && unzip -q -o /tmp/ysnet.zip -d /opt/ysoserial.net
`},
	{Name: "searchsploit", Purpose: "local ExploitDB search (component/CVE to PoC)", Kind: KindScript, Category: CatExploit,
		Script: `set -e
if [ ! -d /opt/exploitdb/exploits ]; then rm -rf /opt/exploitdb; git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; fi
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o /usr/local/bin/searchsploit https://gitlab.com/exploit-database/exploitdb/-/raw/main/searchsploit
chmod +x /usr/local/bin/searchsploit
`},
	{Name: "trivy", Purpose: "image/dependency/IaC vulnerability and secret scanning", Kind: KindGitHub, Category: CatCode,
		Repo: "aquasecurity/trivy", AssetTmpl: "trivy_{ver}_Linux-{arch5}.tar.gz"},
	{Name: "kubectl", Purpose: "K8s cluster operations and RBAC probing", Kind: KindScript, Category: CatNetwork,
		Script: `set -e
VER=$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 https://dl.k8s.io/release/stable.txt)
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${VER}/bin/linux/amd64/kubectl"
chmod +x /usr/local/bin/kubectl
`},
	{Name: "kube-hunter", Purpose: "K8s attack-surface probing (remote/in-cluster)", Kind: KindPip, Category: CatNetwork, Pip: "kube-hunter"},
	{Name: "awscli", Bin: "aws", Purpose: "AWS credential validation and resource enumeration (read-only)", Kind: KindApt, Category: CatNetwork, Apt: "awscli", Dnf: "awscli"},
	{Name: "gau", Purpose: "passive URL collection (wayback/commoncrawl/otx)", Kind: KindGitHub, Category: CatDNS,
		Repo: "lc/gau", AssetTmpl: "gau_{ver}_linux_{arch}.tar.gz"},
	{Name: "waybackurls", Purpose: "Wayback historical URL extraction", Kind: KindGitHub, Category: CatDNS,
		Repo: "tomnomnom/waybackurls", AssetTmpl: "waybackurls-linux-{arch}-{ver}.tgz"},
	// chisel: internal pivoting/tunneling tool (SOCKS and reverse tunnels rely on it).
	{Name: "chisel", Purpose: "internal pivoting and tunneling (TCP/UDP/SOCKS tunnels)", Kind: KindGitHub, Category: CatPivot,
		Repo: "jpillora/chisel", AssetTmpl: "chisel_{ver}_linux_{arch}.gz"},
	// amass: subdomain enumeration (OWASP). The asset name carries **no version**, so the
	// template has no {ver}.
	{Name: "amass", Purpose: "subdomain enumeration (OWASP, active + passive resolution)", Kind: KindGitHub, Category: CatDNS,
		Repo: "OWASP/Amass", AssetTmpl: "amass_linux_{arch}.tar.gz"},
	// dalfox: XSS scanning and exploitation. The asset name has a v prefix and uses
	// x86_64/aarch64 for the architecture.
	{Name: "dalfox", Purpose: "XSS scanning and exploitation (reflected/stored/DOM)", Kind: KindGitHub, Category: CatWeb,
		Repo: "hahwul/dalfox", AssetTmpl: "dalfox-{verv}-linux-{arch2}.tar.gz"},
	// feroxbuster: directory/file brute force (a Rust replacement for gobuster).
	// Note its asset name puts the **architecture first**, and uses x86_64 for amd64 and
	// aarch64 for arm64; from v2.14 arm64 ships .zip only (amd64 has both) — the asset name
	// lists candidates separated by || and the downloader tries them in turn on a 404 (both
	// hostd and install.sh's table-driven path implement that semantics).
	{Name: "feroxbuster", Purpose: "directory/file brute force (Rust, multi-threaded and recursive)", Kind: KindGitHub, Category: CatWeb,
		Repo: "epi052/feroxbuster", AssetTmpl: "{arch2}-linux-feroxbuster.zip||{arch2}-linux-feroxbuster.tar.gz"},
	// ── Red-team post-exploitation fill-in (2026-10-30): persistence/lateral/tunneling/
	// credentials ──
	// socat: the all-purpose replacement for nc (bidirectional pipes, TLS, forwarding),
	// the standard way to stabilize a reverse shell.
	{Name: "socat", Purpose: "multi-purpose network relay (reverse shell stabilization/port forwarding)", Kind: KindApt, Category: CatPivot,
		Apt: "socat", Dnf: "socat"},
	// proxychains4: lets any TCP tool go through a SOCKS tunnel (paired with a
	// chisel/ligolo tunnel endpoint).
	{Name: "proxychains4", Bin: "proxychains4", Purpose: "run any TCP tool through a SOCKS proxy (tunnel egress)", Kind: KindApt, Category: CatPivot,
		Apt: "proxychains4", Dnf: "proxychains-ng"},
	// evil-winrm: WinRM landing shell on Windows targets (the standard lateral-movement
	// foothold). The GitHub release only has sources (no binary), so Kali/Debian use the
	// apt package.
	{Name: "evil-winrm", Purpose: "WinRM landing shell (Windows lateral foothold)", Kind: KindScript, Category: CatPivot,
		Script: `set -e
if command -v apt-get >/dev/null 2>&1; then apt-get update -qq || true; apt-get install -y ruby-dev build-essential libreadline-dev libedit-dev libssl-dev; fi
gem install evil-winrm --no-document
`},
	// ligolo-ng: TUN-style reverse proxy (a smoother direct route into internal networks
	// than SOCKS). Asset name measured 2026-10-30:
	// ligolo-ng_proxy_<ver>_linux_amd64.tar.gz (the official repo is
	// nicocha30/ligolo-ng — guessing a fork name yields 404).
	{Name: "ligolo-ng", Purpose: "TUN reverse proxy (direct internal access/dual bind)", Kind: KindGitHub, Category: CatPivot,
		Repo: "nicocha30/ligolo-ng", AssetTmpl: "ligolo-ng_proxy_{ver}_linux_{arch}.tar.gz", BinInZip: "proxy"},
	// responder: LLMNR/NBT-NS poisoning (credential capture on Windows networks). No
	// GitHub release; Kali/Debian have an apt package (the upstream source is a
	// directory layout, which a GitHub recipe cannot install).
	{Name: "responder", Purpose: "LLMNR/NBT-NS poisoning (internal credential capture)", Kind: KindScript, Category: CatCred,
		Script: `set -e
if [ ! -d /opt/Responder/.git ]; then rm -rf /opt/Responder; git clone --depth 1 https://github.com/lgandx/Responder /opt/Responder; fi
python3 -m pip install --break-system-packages -r /opt/Responder/requirements.txt
ln -sf /opt/Responder/Responder.py /usr/local/bin/responder
chmod +x /opt/Responder/Responder.py
`},
	// tcpdump: packet capture on internal networks (the evidence surface for traffic
	// forensics/credential sniffing).
	{Name: "tcpdump", Purpose: "network packet capture (traffic forensics)", Kind: KindApt, Category: CatNetwork,
		Apt: "tcpdump", Dnf: "tcpdump"},
	// pspy: unprivileged process monitoring (finds cron/service-style persistence
	// points). The asset name is fixed as pspy64/pspy32 (measured 2026-10-30, no
	// version and the repo is archived, i.e. the last version will not change).
	{Name: "pspy", Bin: "pspy64", Purpose: "unprivileged process monitoring (finds persistence points)", Kind: KindGitHub, Category: CatExploit,
		Repo: "DominicBreuker/pspy", AssetTmpl: "pspy64", Raw: true},
	// linpeas: Linux privilege escalation enumeration (the industry-standard first
	// post-exploitation script). Measured asset: linpeas_linux_amd64 (no extension, so
	// the arch template matches).
	{Name: "linpeas", Bin: "linpeas", Purpose: "Linux privilege escalation enumeration (PEASS family)", Kind: KindGitHub, Category: CatExploit,
		Repo: "peass-ng/PEASS-ng", AssetTmpl: "linpeas_linux_{arch}", Raw: true},
	// sshuttle: SSH pivoting (pulls the remote subnet into the local routing table).
	{Name: "sshuttle", Purpose: "SSH tunnel straight into the remote subnet (routing-level pivot)", Kind: KindApt, Category: CatPivot,
		Apt: "sshuttle", Dnf: "sshuttle"},

	// notify: OOB/callback data receiver (DNS/HTTP/TLS channels).
	{Name: "notify", Purpose: "OOB data receiver (multi-channel DNS/HTTP/TLS)", Kind: KindGitHub, Category: CatOOB,
		Repo: "projectdiscovery/notify", AssetTmpl: "notify_{ver}_linux_{arch}.zip"},
	// interactsh-client: client for interactive OOB probing (works with nuclei's oob
	// templates).
	{Name: "interactsh-client", Bin: "interactsh-client", Purpose: "OOB callback client (works with nuclei's oob templates)", Kind: KindGitHub, Category: CatOOB,
		Repo: "projectdiscovery/interactsh", AssetTmpl: "interactsh-client_{ver}_linux_{arch}.zip"},
	// netexec: SMB/Windows protocol lateral movement (the modern CrackMapExec
	// replacement). Note (measured 2026-11): after commercializing, NetExec pulled all
	// distribution files from PyPI (/simple/netexec returns 404), so a pip recipe always
	// fails — the inventory honestly reports it missing; install it from source at
	// https://github.com/Pennyw0rth/NetExec when needed (uv/pipx + git).
	{Name: "netexec", Bin: "netexec", Purpose: "SMB/WinRM lateral movement and credential spraying (modern CrackMapExec; pulled from PyPI, needs a source install)", Kind: KindScript, Category: CatCred,
		Script: `set -e
python3 -m pip install --break-system-packages "git+https://github.com/Pennyw0rth/NetExec.git"
`},
	// semgrep: SAST rule scanning (matches rules against downloaded source).
	{Name: "semgrep", Purpose: "static rule scanning of source code (SAST)", Kind: KindPip, Category: CatCode, Pip: "semgrep"},
	// pwntools: exploit scripting framework (used by the agent when writing exploits).
	{Name: "pwntools", Bin: "pwn", Purpose: "exploit scripting framework (for writing exploits)", Kind: KindPip, Category: CatExploit, Pip: "pwntools"},

	// ── Middleware protocol specials (added from 2026-10-22 research) ─────────────
	//
	// Basis: middleware accounts for a large share of the CVSS>=9.0 vulnerabilities on
	// NVD in the last 30 days (apache/http_server, apache/cxf, mariadb, rabbitmq_server,
	// moquette (MQTT), gitlab, splunk, f5/big-ip, fortinet/fortimail...), while
	// general-purpose scanners (nmap/nuclei) either do not recognize this
	// protocol-type middleware or only run generic probes.
	//
	// These are **protocol client libraries**, not "one-click hole punching" exploiters:
	// they let the Agent talk to the middleware directly — enumerate config, read queues,
	// subscribe to topics, call admin APIs. "How to attack" is decided by the Agent
	// together with vulnerability intel (search_vulns / search_recent_critical).
	//
	// Every package name was verified to exist through the PyPI API (2026-10-22). Two
	// easy traps:
	//   - the MQTT package is **paho-mqtt** (not paho — that does not exist on PyPI, and
	//     a similar-looking same-name package is a common supply-chain poisoning entry);
	//   - the PostgreSQL driver must be **psycopg2-binary** (psycopg2 is a pure sdist, so
	//     a one-click install degrades into a source build and fails outright on many
	//     machines).

	// MQTT: broker enumeration, topic subscribe/publish.
	{Name: "gmqtt", Purpose: "MQTT protocol client (enumerate/subscribe/publish on a broker)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "gmqtt", Detect: "python:gmqtt"},
	{Name: "paho-mqtt", Purpose: "MQTT protocol client (for scripts, supports v3.1.1/v5)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "paho-mqtt", Detect: "python:paho"},
	// Message queues: AMQP / Kafka / multi-protocol.
	{Name: "pika", Purpose: "RabbitMQ AMQP protocol client (read queues/publish)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "pika", Detect: "python:pika"},
	{Name: "amqpstorm", Purpose: "RabbitMQ management API + AMQP client", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "amqpstorm", Detect: "python:amqpstorm"},
	{Name: "confluent-kafka", Purpose: "Kafka protocol client (read topics/consumer groups)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "confluent-kafka", Detect: "python:confluent_kafka"},
	{Name: "kombu", Purpose: "multi-protocol message queue client (AMQP/Redis/SQS, etc.)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "kombu", Detect: "python:kombu"},
	// Database protocols: direct-connect enumeration and data reads.
	{Name: "pymongo", Purpose: "MongoDB protocol client (enumerate databases/read collections)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "pymongo", Detect: "python:pymongo"},
	{Name: "pymysql", Purpose: "MySQL protocol client (enumerate databases/read tables)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "pymysql", Detect: "python:pymysql"},
	{Name: "psycopg2-binary", Purpose: "PostgreSQL protocol client (enumerate databases/read tables)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "psycopg2-binary", Detect: "python:psycopg2"},
	{Name: "redis-py", Bin: "redis", Purpose: "Redis protocol client (enumerate keys/read config)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "redis", Detect: "python:redis"},
	// SOAP/XML middleware: protocol client for SOAP services such as Apache CXF.
	{Name: "zeep", Purpose: "SOAP client (enumerate WSDL/call operations, works with CXF etc.)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "zeep", Detect: "python:zeep"},
	// Code hosting platform: GitLab's REST/GraphQL API.
	{Name: "python-gitlab", Purpose: "GitLab API client (enumerate projects/users/pipelines)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "python-gitlab", Detect: "python:gitlab"},
	// Network devices: switch/router CLI interaction and automation.
	{Name: "netmiko", Purpose: "network device CLI interaction (multi-vendor SSH)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "netmiko", Detect: "python:netmiko"},
	{Name: "napalm", Purpose: "multi-vendor network device automation (fetch config/routing table)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "napalm", Detect: "python:napalm"},
	// Logging/SIEM: Splunk's REST API.
	{Name: "splunk-sdk", Purpose: "Splunk API client (search/enumerate)", Kind: KindPip, Category: CatMiddleware, PipLibrary: true, Pip: "splunk-sdk", Detect: "python:splunklib"},

	{Name: "msfconsole", Purpose: "Metasploit framework (exploit/encoder)", Kind: KindScript, Category: CatExploit,
		Script: `set -e
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o /tmp/msfinstall https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb
chmod +x /tmp/msfinstall
/tmp/msfinstall
`},
}

// normalize fills in derived fields and prepares path probing.
func normalize(t Tool) Tool {
	if t.Bin == "" {
		t.Bin = t.Name
	}
	t.ID = t.Bin
	if t.BinInZip == "" {
		t.BinInZip = t.Bin
	}
	t.Installable = t.Kind != KindManual
	return t
}

// humanInstall generates a human-readable install hint for a missing entry (falls
// back to the system package name when there is no recipe).
func humanInstall(t Tool) string {
	switch t.Kind {
	case KindApt:
		return "apt install " + t.Apt
	case KindGitHub:
		return "GitHub Release: https://github.com/" + t.Repo + "/releases"
	case KindPip:
		return "pip install " + t.Pip
	case KindScript:
		return "one-click script install (git clone / download+extract / gem, etc.)"
	}
	if t.Install != "" {
		return t.Install
	}
	return ""
}

// Catalog returns a copy of the catalog (derived fields filled in, availability not
// probed).
func Catalog() []Tool {
	out := make([]Tool, len(catalog))
	for i, t := range catalog {
		out[i] = normalize(t)
	}
	return out
}

// Lookup fetches a recipe by id; ok=false means it is not on the whitelist — this is
// the privileged helper's only input validation: any id not found here is refused
// outright.
func Lookup(id string) (Tool, bool) {
	for _, t := range catalog {
		n := normalize(t)
		if n.ID == id {
			return n, true
		}
	}
	return Tool{}, false
}

// AvailableInPath reports whether the tool is currently available. Detection prefers
// Detect (file/directory/Python module), otherwise it looks up PATH.
//
// Detect supports the multi-candidate prefix "any:", comma separated, where any hit
// counts as available (used when the same tool has different command names across
// distributions: ImageMagick 7 is magick, Debian 6.x only has convert).
func (t Tool) AvailableInPath() bool {
	if t.Detect != "" {
		if rest, ok := strings.CutPrefix(t.Detect, "any:"); ok {
			for _, cand := range strings.Split(rest, ",") {
				cand = strings.TrimSpace(cand)
				if cand == "" {
					continue
				}
				if detectOne(cand) {
					return true
				}
			}
			return false
		}
		return detectOne(t.Detect)
	}
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

// detectOne evaluates a single detection expression (path:/dir:/python:).
func detectOne(detect string) bool {
	kind, target, ok := strings.Cut(detect, ":")
	if !ok || target == "" {
		return false
	}
	switch kind {
	case "path", "dir":
		_, err := os.Stat(target)
		return err == nil
	case "python":
		return pythonModuleAvailable(target)
	}
	return false
}

// pythonModuleAvailable probes whether a pure library is available with
// python3 -c import. Pure libraries have no PATH entry, so exec.LookPath never finds
// them; the cost of forking per entry is amortized by a 60s cache (the host
// environment page and prompt injection call Inventory repeatedly).
var (
	pythonProbeMu    sync.Mutex
	pythonProbeCache = map[string]pythonProbeEntry{}
)

type pythonProbeEntry struct {
	ok      bool
	expires time.Time
}

func pythonModuleAvailable(module string) bool {
	pythonProbeMu.Lock()
	defer pythonProbeMu.Unlock()
	if e, ok := pythonProbeCache[module]; ok && time.Now().Before(e.expires) {
		return e.ok
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		return false
	}
	code := "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec(" + strconv.Quote(module) + ") else 1)"
	err = exec.Command(py, "-c", code).Run()
	ok := err == nil
	pythonProbeCache[module] = pythonProbeEntry{ok: ok, expires: time.Now().Add(60 * time.Second)}
	return ok
}

// Inventory probes every catalog entry (in catalog order).
func Inventory() []Tool {
	out := make([]Tool, len(catalog))
	for i, t := range catalog {
		n := normalize(t)
		n.Available = false
		if n.AvailableInPath() {
			n.Available = true
			n.Install = ""
		} else {
			n.Install = humanInstall(n)
		}
		out[i] = n
	}
	return out
}

// Summary is the compact form injected into graph_overview / the API:
// available is the list of directly callable binary names; missing carries install
// hints; hint gives the model a one-line usage convention.
//
// Every available entry carries its **purpose** ("name: purpose"), not just a name.
// The reason is practical: the catalog now holds 30+ tools, and a model that sees
// only names (chisel / dalfox / feroxbuster...) cannot tell which one fits which
// situation, so it either guesses blindly or skips them entirely. With the purpose
// attached, "pick the means when dispatching intents based on what is installed"
// actually holds.
func Summary() map[string]any {
	inv := Inventory()
	avail := make([]string, 0, len(inv))
	missing := make([]string, 0, len(inv))
	for _, t := range inv {
		if t.Available {
			if t.Purpose != "" {
				avail = append(avail, t.Bin+": "+t.Purpose)
			} else {
				avail = append(avail, t.Bin)
			}
		} else {
			// Missing entries only get a name — install hints are for humans (the host
			// environment page); the model cannot install anything and does not need to know
			// how, so handing it 27 install commands just burns context every turn.
			missing = append(missing, t.Name)
		}
	}
	return map[string]any{
		"available": avail,
		"missing":   missing,
		"hint":      "available lists tools callable directly via Bash from this host's PATH, formatted as \"command name: purpose\" — when dispatching intents and picking means, choose by purpose instead of recognizing names only; missing lists tools this host does not have, do not assume they exist. When a missing tool is needed, mention the install command to the user in the intent/summary; do not install it yourself.",
	}
}

// SummaryText is the plain-text form (for prompt injection): one available tool per
// line, with its purpose.
//
// Only [available] tools are listed: the model cannot call a missing tool and it
// should not take up room in the prompt (dozens of "not installed" lines in a single
// worker run's system prompt is a pure waste of context). The purpose must be
// included — with names only the model cannot tell which tool fits which situation
// (chisel / dalfox / feroxbuster are the clearest examples).
//
// This function once existed with no caller: the tool list only reached the planner's
// wake-up prompt, while the worker that actually does the work never saw it — so a
// whole batch of newly installed tools was never used once.
func SummaryText() string {
	var b strings.Builder
	avail := 0
	for _, t := range Inventory() {
		if !t.Available {
			continue
		}
		avail++
		if t.Purpose != "" {
			b.WriteString("✓ " + t.Bin + " —— " + t.Purpose + "\n")
		} else {
			b.WriteString("✓ " + t.Bin + "\n")
		}
	}
	if avail == 0 {
		return ""
	}
	return strconv.Itoa(avail) + " tools available (all callable directly via Bash from this host's PATH):\n" + b.String() +
		"\nBefore starting, consider whether these tools already solve the problem — do not rebuild from scratch with python3, " +
		"and do not ignore a tool just because its name is unfamiliar. If a tool this host lacks is genuinely needed, " +
		"state clearly in the intent/summary what should be installed; do not install it yourself."
}

// Arch normalizes to the architecture name used in release assets.
func Arch() string {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH
	default:
		return runtime.GOARCH
	}
}

// ArchAlt returns another architecture naming: amd64→x86_64, arm64→aarch64.
//
// Asset naming is not uniform across GitHub projects: ProjectDiscovery uses
// amd64/arm64, gitleaks/amass use x86_64/aarch64, and some chisel assets use x86/arm.
// The templates use {arch}/{arch2}/{arch3} for those three sets.
func ArchAlt() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

// ArchShort returns the shorter architecture naming: amd64→x86, arm64→arm.
func ArchShort() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86"
	case "arm64":
		return "arm"
	default:
		return runtime.GOARCH
	}
}

// ArchLong returns the naming trivy uses: amd64→64bit, arm64→ARM64, 386→32bit.
func ArchLong() string {
	switch runtime.GOARCH {
	case "amd64":
		return "64bit"
	case "arm64":
		return "ARM64"
	case "386":
		return "32bit"
	default:
		return runtime.GOARCH
	}
}

// ArchX64 returns the naming gitleaks uses: amd64→x64, arm64→arm64.
//
// This is the fourth naming set — gitleaks assets were measured as
// gitleaks_8.30.1_linux_x64.tar.gz and ..._linux_arm64.tar.gz, i.e. amd64 is called
// x64 while arm64 stays arm64.
func ArchX64() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	default:
		return runtime.GOARCH
	}
}
