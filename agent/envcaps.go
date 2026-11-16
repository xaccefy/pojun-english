package agent

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// envCapNote is the code-side note of 'what privileged network ops this process can do', appended to the
// Bash tool's description (so only agents actually holding Bash see it). It lives here rather than in the
// prompt because it depends on deployment shape: root in the Docker image, non-root + capability bits under
// systemd binary deployment — the commands the model should type differ. Judged purely from runtime facts (euid + CapEff), no config.
//
// Why it's worth a dedicated note: in an old sandbox the agent burned a dozen rounds figuring out why
// 'masscan reports PF_PACKET not supported' / 'nmap -sS says it needs root', ending in a hand-rolled Python
// scanner. Stating these environment facts once is far cheaper than letting the model probe repeatedly.
var (
	envCapOnce sync.Once
	envCapText string
)

// EnvCapabilityNote returns the code-owned environment capability block (empty on
// non-Linux, where the /proc and capability model don't apply).
func EnvCapabilityNote() string {
	envCapOnce.Do(func() { envCapText = buildEnvCapNote() })
	return envCapText
}

// capBit reports whether the effective capability set includes the given CAP_* bit
// number (CAP_NET_RAW=13, CAP_NET_ADMIN=12, CAP_NET_BIND_SERVICE=10 on Linux).
func capBit(caps uint64, bit uint) bool { return caps&(1<<bit) != 0 }

// effectiveCaps parses CapEff out of /proc/self/status (hex, no 0x prefix).
// Returns 0 when unavailable — callers then just describe the degraded case.
func effectiveCaps() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return 0
}

func buildEnvCapNote() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	caps := effectiveCaps()
	root := os.Geteuid() == 0
	raw := root || capBit(caps, 13)   // CAP_NET_RAW
	admin := root || capBit(caps, 12) // CAP_NET_ADMIN
	// This host's capabilities toward targets. Written 'conclusion first, alternatives second' — the model
	// reads facts about THIS machine, not suggestions.
	var b strings.Builder
	b.WriteString("\n\n**Local network capabilities** (runtime-environment facts — pick commands directly, don't re-probe):\n")
	switch {
	case root:
		b.WriteString("- The process runs as **root**: `nmap -sS/-sU/-O/-PR`, `masscan`, `ping` and other privileged scans work directly — no `--privileged`, no sudo.\n")
	case raw && admin:
		b.WriteString("- The process is **not root** (uid=" + strconv.Itoa(os.Geteuid()) + "), but CAP_NET_RAW + CAP_NET_ADMIN are granted: raw sockets work — `masscan`, `ping`, `hping3` etc. run directly.\n")
		b.WriteString("- **`nmap` exception**: it checks euid, not capability bits, so privileged scans like `-sS`/`-sU`/`-O`/`-PR` need **explicit `--privileged`** (e.g. `nmap --privileged -sS -Pn -n -p- <target>`). **Don't use sudo** (no interactive password — guaranteed to hang).\n")
	case raw:
		b.WriteString("- The process is not root, CAP_NET_RAW only: `masscan`/`ping` work; nmap's privileged scans need explicit `--privileged` (it checks euid), and need CAP_NET_ADMIN to send raw packets properly — fall back to `-sT` on failure.\n")
	default:
		b.WriteString("- The process has **no CAP_NET_RAW**: `masscan`, `nmap -sS`, `nmap -sU`, ARP/`-PR` scans are **unavailable** (they report PF_PACKET not supported or requires root privileges).\n")
		b.WriteString("- Alternative: `nmap -sT` (TCP connect scan — unprivileged, equally accurate, just slower), `nmap -sT -sV` for service identification. **Don't** write a scanner or try sudo to work around it.\n")
	}
	b.WriteString("- `nuclei`, `sqlmap`, `httpx`, `curl` etc. need no privileges — usable directly.\n")
	return b.String()
}
