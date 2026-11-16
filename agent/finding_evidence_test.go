package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// TestValidateFindingEvidence v0.4.5 evidence bar: critical/high must reach minimum length,
// medium/low have no bar. Thresholds are character counts; boundaries are pinned per level.
func TestValidateFindingEvidence(t *testing.T) {
	long := strings.Repeat("a", 200)
	mid := strings.Repeat("a", 120)
	cases := []struct {
		name     string
		severity string
		evidence string
		wantErr  bool
	}{
		{"critical-empty", "critical", "", true},
		{"critical-short", "critical", strings.Repeat("a", 199), true},
		{"critical-exact", "critical", long, false},
		{"high-short", "high", strings.Repeat("a", 119), true},
		{"high-exact", "high", mid, false},
		{"high-uppercase", " HIGH ", mid, false},
		{"medium-short", "medium", "one-line description", false},
		{"low-empty", "low", "", false},
		{"unknown-passthrough", "unknown", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := validateFindingEvidence(c.severity, c.evidence)
			if (msg != "") != c.wantErr {
				t.Fatalf("severity=%q len=%d: got %q, wantErr=%v", c.severity, len([]rune(c.evidence)), msg, c.wantErr)
			}
			// Rejection messages must offer two actionable paths (add evidence / downgrade) so the model can self-correct.
			if msg != "" && !strings.Contains(msg, "to medium") {
				t.Fatalf("rejection missing downgrade guidance: %q", msg)
			}
		})
	}
}

// TestEvidenceGuidanceInjected: evidence discipline goes via tool guidance — injected under
// both traffic-switch states (reporters still pass the evidence bar with auto-binding off);
// reporter additionally gets the report-structure supplement; agents without report tools get none.
func TestEvidenceGuidanceInjected(t *testing.T) {
	oldPolicy := FindingTrafficBindingEnabled
	t.Cleanup(func() { FindingTrafficBindingEnabled = oldPolicy })
	ts := NewToolSet(nil, "fixture")
	findingTool := []actool.CoreTool{ts.addFinding()}

	for _, enabled := range []bool{false, true} {
		FindingTrafficBindingEnabled = func() bool { return enabled }
		_, g := findingWorkflowTools("worker", findingTool)
		if !strings.Contains(g, "L3") || !strings.Contains(g, "external operational constraint") || !strings.Contains(g, "Observation ≠ inference") {
			t.Fatalf("binding=%v: evidence discipline missing: %q", enabled, g)
		}
	}
	FindingTrafficBindingEnabled = func() bool { return true }
	// The reporter's structure supplement injects only when it has update_finding_report.
	fakeUpdate := writeTool("update_finding_report", "fake", map[string]any{"type": "object", "properties": map[string]any{}},
		func(context.Context, json.RawMessage) (actool.Result, error) { return actool.Text("ok"), nil })
	_, reporterG := findingWorkflowTools("reporter", append(append([]actool.CoreTool{}, findingTool...), fakeUpdate))
	if !strings.Contains(reporterG, "Prerequisites") || !strings.Contains(reporterG, "Impact Proof") {
		t.Fatalf("reporter annex missing: %q", reporterG)
	}
	_, noneG := findingWorkflowTools("worker", nil)
	if strings.Contains(noneG, "L3") || strings.Contains(noneG, "Prerequisites") {
		t.Fatalf("guidance leaked to agents without reporting tools: %q", noneG)
	}
}
