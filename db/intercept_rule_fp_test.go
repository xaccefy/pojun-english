package db

import (
	"regexp"
	"testing"
)

// False-positive rate of the built-in rules on **real penetration commands**.
//
// Previous measured run: after changing all built-in rules to judge, 11 real invocations were denied directly by rules,
// all false positives:
//
//	rm -f /tmp_out.$$                       → hit "Delete system critical directories" (bare / branch)
//	for p in /api/.../reboot ...            → hit "Shutdown / reboot" (reboot in the path)
//	touch /usr/share/nmap/... && rm -f ...  → hit "Delete system critical directories"
//
// Root cause: the rules run regexes on the **raw command text**, and the agent's normal probing text contains these
// words all over the place. The point of a rule is to "pick out calls worth judging and hand them to the model", not to "decide itself";
// once the action is deny/ask, a false positive becomes a task interruption.
//
// Here we pin the real commands as a regression baseline: these commands are **legitimate penetration actions**,
// no "deterministic destruction" rule should hit them.
func TestBuiltinRulesDoNotFalsePositiveOnRealCommands(t *testing.T) {
	// Real commands taken from the production interception history (all legitimate probes that were falsely blocked).
	real := []struct {
		name string
		cmd  string
	}{
		{"Temp file cleanup", `cd /opt/pojun/data/tasks/3/i348/ && curl -s -o /tmp_out.$$ "http://10.10.42.18:8161/x"; rm -f /tmp_out.$$`},
		{"Device management path enumeration", `for p in /getPreLoginData/ /login.cgi /webacs/ /reboot /reset /getVersion; do code=$(curl -s -o /dev/null -w "%{http_code}" "https://172.24.0.14$p"); done`},
		{"Clear proxy environment", `unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy; curl -sk https://172.16.105.2:9000/`},
		{"REST path enumeration", `for path in /api/ /api/users /api/login /api/status /api/config /api/health /api/version; do curl -s -o /dev/null -w "%{http_code}" "http://10.10.47.11:6969$path"; done`},
		{"Cloud platform API enumeration", `for action in GetZones QueryZone CreateVm StartVm StopVm RebootVm DestroyVm; do curl -s "http://10.10.47.11:8080/?Action=$action"; done`},
		{"nmap script directory probing", `touch /usr/share/nmap/scripts/_t.nse 2>&1 && echo WRITABLE && rm -f /usr/share/nmap/scripts/_t.nse`},
		{"Port connectivity probing", `for ip in 10.10.70.1 10.10.70.254; do timeout 3 ping -c1 -W1 $ip >/dev/null 2>&1 && echo "$ip up"; done`},
		{"Windows host interface probing", `for p in /getPreLoginData/ /login.cgi /webacs/; do curl -s "https://172.24.0.14$p"; done`},
	}

	// Only assert "deterministic destruction" rules: these block directly when hit (deny),
	// a false positive = task interruption. Candidate-screening rules (HTTP path enumeration) are delegated to the model for judgment,
	// a hit there doesn't count as a false positive.
	hard := map[string]string{
		"Recursive force-delete":          `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		"Delete system critical directories": `\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		"Clear system critical directories":  `\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		"Shutdown / reboot":               `(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		"Disk format":                     `\bmkfs\b`,
		"Disk wipe":                       `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
		"Disk overwrite":                  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
		"Fork bomb":                       `:\(\)\s*\{[^}]*:\|:`,
		"Kill all processes":              `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
		"Clear firewall":                  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
	}

	for _, r := range real {
		for name, pat := range hard {
			re, err := regexp.Compile(pat)
			if err != nil {
				t.Fatalf("regex compile failed for rule %q: %v", name, err)
			}
			if re.MatchString(r.cmd) {
				t.Errorf("rule %q false-positived on a legitimate command (fragment %q):\n  scenario=%s\n  cmd=%s",
					name, re.FindString(r.cmd), r.name, r.cmd)
			}
		}
	}
}

// After narrowing, genuinely destructive behavior must still be caught by the rules — otherwise that's a false negative.
func TestBuiltinRulesStillCatchRealDanger(t *testing.T) {
	hard := map[string]string{
		"Recursive force-delete":            `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		"Delete system critical directories": `\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		"Clear system critical directories":  `\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		"Shutdown / reboot":                 `(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		"Disk format":                       `\bmkfs\b`,
		"Disk wipe":                         `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
	}
	danger := []struct {
		rule string
		cmd  string
	}{
		{"Recursive force-delete", `rm -rf /var/www/html`},
		{"Recursive force-delete", `rm -rf --no-preserve-root /`},
		{"Delete system critical directories", `rm -rf /etc/`},
		{"Clear system critical directories", `rm -rf /var/lib/*`},
		{"Clear system critical directories", `rm -rf /etc/*`},
		{"Delete system critical directories", `rm -rf /usr`},
		{"Shutdown / reboot", `sudo shutdown -h now`},
		{"Shutdown / reboot", `reboot`},
		{"Shutdown / reboot", `cd /tmp && poweroff`},
		{"Disk format", `mkfs.ext4 /dev/sdb1`},
		{"Disk wipe", `shred -v /dev/sda`},
	}
	for _, d := range danger {
		pat, ok := hard[d.rule]
		if !ok {
			t.Fatalf("unknown rule %q", d.rule)
		}
		re := regexp.MustCompile(pat)
		if !re.MatchString(d.cmd) {
			t.Errorf("rule %q missed %q", d.rule, d.cmd)
		}
	}
}
