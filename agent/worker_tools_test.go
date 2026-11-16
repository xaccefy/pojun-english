package agent

import (
	"strings"
	"testing"

	"github.com/chu0119/pojun/hosttools"
)

// The worker's system prompt must carry the host-tool inventory.
//
// Regression background: the tool inventory originally only went into the planner's wake prompt
// (for 'picking means when dispatching intents'), while the workers doing the actual work couldn't
// see it — a freshly installed toolset (dalfox/feroxbuster/chisel/gitleaks…) never got used once;
// agents only knew python3 + curl + ssh.
func TestWorkerSystemIncludesHostTools(t *testing.T) {
	sys := workerSystem("127.0.0.1:8788", "", "/opt/pojun/data", "/tmp/run")
	if !strings.Contains(sys, "Tools available on this machine") {
		t.Fatal("worker's system prompt should carry the host-tool inventory")
	}
}

// The inventory must not bloat the prompt — it's in every worker run's system prompt.
func TestWorkerToolListStaysCompact(t *testing.T) {
	txt := hosttools.SummaryText()
	if txt == "" {
		t.Skip("no usable tools on this machine — skipping size assertion")
	}
	if len(txt) > 4000 {
		t.Errorf("tool inventory is %d bytes — too big (enters system prompt every round)", len(txt))
	}
	// every line needs a purpose
	for _, line := range strings.Split(txt, "\n") {
		if !strings.HasPrefix(line, "✓ ") {
			continue
		}
		if !strings.Contains(line, "——") {
			t.Errorf("available items must carry a purpose: %q", line)
		}
	}
}

// mainagent also has Bash and verifies things itself — needs the inventory too.
func TestMainAgentSystemIncludesHostTools(t *testing.T) {
	sys := mainAgentSystem("take the target down", "/opt/pojun/data", "/tmp/run")
	if !strings.Contains(sys, "Tools available on this machine") {
		t.Fatal("mainagent's system prompt should carry the host-tool inventory")
	}
}
