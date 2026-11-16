package db

import "testing"

func TestNormalizeVulnClass(t *testing.T) {
	cases := []struct{ in, want string }{
		// // Alias table: both Chinese and English variants fold to the standard class
		{"SQLi", "Injection"}, {"sql_injection", "Injection"}, {"SQLInjection", "Injection"},
		{"idor", "Unauthorized Access"}, {"IDOR", "Unauthorized Access"}, {"horizontal privilege escalation", "Unauthorized Access"},
		{"WeakPassword", "Weak Password"}, {"default credentials", "Weak Password"},
		{"path traversal", "Arbitrary File Read"}, {"LFI", "Arbitrary File Read"},
		{"RCE", "RCE"}, {"remote code execution", "RCE"}, {"cmd_injection", "Injection"},
		{"SSRF", "SSRF"}, {"eternal blue", "Known Vulnerability"}, {"CVE-2017-0144", "Known Vulnerability"},
		// // Case / whitespace / separator insensitive
		{"XSS", "XSS"}, {" xss ", "XSS"},
		// // An allowlist member returns itself (standard spelling)
		{"Injection", "Injection"}, {"Unauthorized Access", "Unauthorized Access"}, {"Other", "Other"},
		// // Miss: the TrimSpace original is preserved (no information destroyed)
		{"Eternal Blue Screen", "Eternal Blue Screen"}, {"custom category", "custom category"},
		// // Empty
		{"", ""}, {"  ", ""},
	}
	for _, c := range cases {
		if got := NormalizeVulnClass(c.in); got != c.want {
			t.Errorf("NormalizeVulnClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
