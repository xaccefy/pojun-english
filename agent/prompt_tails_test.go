package agent

import (
	"strings"
	"testing"
)

// Hard-tail guard test (v0.4.63): scanner-first and the vuln coverage matrix are code-injected
// prompt sections — UI edits can't drop them; lock the key anchors so later refactors don't lose them.
func TestScannerAndCoverageTails(t *testing.T) {
	w := workerSystem("", "", "/tmp", "/tmp/run")
	for _, want := range []string{"Scanner-first", "ffuf -u", "/opt/SecLists", "nuclei -u", "sqlmap -u", "Skill routing"} {
		if !strings.Contains(w, want) {
			t.Errorf("worker system prompt missing %q", want)
		}
	}
	p := plannerSystem("goal", "/tmp", "/tmp/run")
	for _, want := range []string{"Vuln coverage matrix", "SQL injection", "SSRF/callback", "File upload", "weak creds", "ffuf/gobuster", "Authorization boundary"} {
		if !strings.Contains(p, want) {
			t.Errorf("planner system prompt missing %q", want)
		}
	}
}
