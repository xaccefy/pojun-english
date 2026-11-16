package agent

// Attack-chain auto follow-up (v0.7.0): after report_finding succeeds, auto-dispatch a
// 'break it through' intent per vuln class — pushing 'vuln exists' to 'impact obtained'.
//
// ## Why it exists
//
// The core customer-reported flaw was 'gives up at bottlenecks — won't find its own way to exploit'. Field facts:
// workers confirm vulns (267 report_findings) but after confirmation there's **no next step** —
// the planner next round sees 'already have a vuln' and drifts to filling coverage instead of exploiting it.
//
// This makes continuation deterministic: a high-sev vuln entering the store immediately spawns a follow-up
// intent (dimension = next hop) anchored on the finding node. The planner still owns the big picture
// (can steer/kill/re-orchestrate), but 'from existence to impact' no longer depends on the model remembering.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// chainNext returns the next-hop dimension and goal description for a dimension (empty = no follow-up).
func chainNext(dim string) (string, string) {
	switch dim {
	case dimInjection:
		return dimDataExport, "use the confirmed injection point to export data/credentials (read-only evidence): land deliverable table/account/config evidence and assess impact scope"
	case dimUpload, dimRCE:
		return dimCredReuse, "use the confirmed command-exec/upload point to collect credentials and config on the target host (read-only), confirming privilege level and intranet reachability"
	case dimAuthz:
		return dimDataExport, "use the confirmed privesc point to read back others' data (limited to proof needs), and verify the business impact of changing state/price"
	case dimSSRF:
		return dimRecon, "use SSRF to probe intranet services and cloud metadata, finding the next hittable service"
	case dimCredReuse:
		return dimLateral, "use the obtained credentials to attempt lateral movement to the next system (confirm targets inside the authorization boundary first)"
	case dimPayment:
		return dimDataExport, "verify how much real impact the tampered payment/order state machine can produce (test orders, amounts, callbacks); stop after evidence"
	case dimPrivesc:
		return dimDataExport, "post-privesc read-only evidence: confirm accessible sensitive data and persistence spots — no destructive ops"
	default:
		return "", ""
	}
}

// dispatchChainIntent spawns the follow-up intent. Returns (intentID, note); intentID<=0 → note explains why.
// missing holds the SRC evidence-review gaps; with gaps, the follow-up goal prioritizes filling impact proof over a generic 'keep breaking'.
func (t *ToolSet) dispatchChainIntent(vulnclass, name, summary, severity string, assetIDs []int64, findingNodeID, intentID int64, missing []string) (int64, string) {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev != "critical" && sev != "high" {
		return 0, ""
	}
	dim := inferDimension(vulnclass + " " + name + " " + summary)
	nextDim, goal := chainNext(dim)
	if nextDim == "" {
		if len(missing) == 0 {
			return 0, ""
		}
		// The dimension isn't in the follow-up table (e.g. info-disclosure/unknown), but the evidence gap is clear:
		// still dispatch a data-pull/impact-proof intent so the high-sev finding doesn't stall at existence.
		nextDim = dimDataExport
		goal = "fill in this vuln's complete harm evidence"
	}
	// Evidence gaps first: when a high/critical vuln only has 'existence', the follow-up's first goal is completing harm proof.
	if len(missing) > 0 {
		goal = "fill in this vuln's complete harm evidence: " + strings.Join(missing, ", ") +
			"; requires raw request/response, real data counts and sensitive fields, privilege matrix or self-created-object write test read-back, unmasked; if unfillable, record the blocker explicitly."
	}
	// The summary must be specific: carry the vuln name and dimension — avoids dedupe collisions with other intents.
	// name may be empty (model only gave summary) — fall back to the summary's first 40 chars.
	label := strings.TrimSpace(name)
	if label == "" {
		label = trimForSummary(strings.TrimSpace(summary), 40)
	}
	sum := fmt.Sprintf("break through via \"%s\": %s", trimForSummary(label, 40), goal)
	it := intentItem{Summary: sum, Dimension: nextDim, Priority: 8}
	for _, id := range assetIDs {
		if raw, err := json.Marshal(id); err == nil {
			it.AssetIDs = append(it.AssetIDs, raw)
		}
	}
	if findingNodeID > 0 {
		if raw, err := json.Marshal(findingNodeID); err == nil {
			it.ParentIDs = append(it.ParentIDs, raw)
		}
	}
	id, err := t.addOneIntent(it)
	if err != nil {
		return 0, "attack-chain follow-up not dispatched: " + err.Error()
	}
	return id, fmt.Sprintf("auto-dispatched follow-up intent #%d (dimension=%s): pushing 'vuln exists' to 'impact obtained'.", id, nextDim)
}

func trimForSummary(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
