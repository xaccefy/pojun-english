package agent

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/chu0119/pojun/db"
)

// validateFindingEvidence: high-severity evidence bar (v0.4.5, borrowing Shannon's L3 bar):
// critical/high must carry verifiable evidence above a minimum length — blocks 'one-line critical reports'.
// medium/low get no bar — low-sev findings are often legitimately one-liners; over-validating blocks normal reports.
// Empty return = pass; otherwise it's the corrective nudge fed back to the model (it can add evidence or downgrade in-session).
func validateFindingEvidence(severity, evidence string) string {
	n := utf8.RuneCountInString(strings.TrimSpace(evidence))
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		if n < 200 {
			return "Evidence can't support critical: evidence needs at least 200 chars of verifiable raw evidence (raw request/response, command output, echo fragments). Complete the evidence and call report_finding again; if you actually only reached L2 (proved input affects backend logic but got no real impact), downgrade severity to medium and state the exploitation conditions."
		}
	case "high":
		if n < 120 {
			return "Evidence can't support high: evidence needs at least 120 chars of verifiable raw evidence (raw request/response, command output or echo fragments). Complete it and call report_finding again; if it's only indirect inference, downgrade severity to medium and note it."
		}
	}
	return ""
}

// ═══ v0.4.52: mechanical-verification credentials (borrowing raptor's epistemic gate + CVEngine triage triple-squeeze) ═══

// EvidenceGrade is evidence's certainty level (floor: decided by tool output — the AI can't rank above it).
type EvidenceGrade int

const (
	EvidenceNone      EvidenceGrade = iota // no mechanical-verification credential
	EvidenceVersion                        // only version/banner match (unreliable: distro backports don't bump version)
	EvidenceBehavior                       // behavior-level verification (nuclei hit/HTTP 200+signature/CVSS trigger)
	EvidenceReplay                         // reproducible replay (curl command+response, screenshot, traffic ID)
)

// hasMechanicalVerification checks whether evidence contains mechanically reproducible credentials.
// Credential definition (borrowed from raptor [GATES]'s 'tool output is the verdict'):
//   1. Contains an HTTP status code + response signature (e.g. "200", "403", "HTTP/1.1 200 OK")
//   2. Contains curl/httpx/nuclei/sqlmap command output (tool name + key output lines)
//   3. Contains base64/hex/hash/JSON structured data
//   4. Contains file path + size/MD5 (download evidence)
// These are deterministic signals — an LLM fabricating evidence can hardly fake all forms at once.
func hasMechanicalVerification(evidence string) bool {
	lower := strings.ToLower(evidence)
	signals := []string{
		"http/1.", "http/2",                      // raw HTTP response line
		"curl -", "curl ",                        // curl commands
		"sqlmap",                                 // sqlmap output
		"nuclei",                                 // nuclei template hits
		"status: 200", "status: 403", "status: 301", "status: 302", // status codes
		"\"code\":", "\"status\":",              // JSON response fields
		"location:", "set-cookie:", "content-type:", // HTTP response header fields
	}
	for _, sig := range signals {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// hasVersionOnlyEvidence checks for version-match-only evidence (borrowing CVEngine match_policy's
// 'version ≠ vulnerability' rule — distro backports don't bump version numbers).
func hasVersionOnlyEvidence(evidence string) bool {
	lower := strings.ToLower(evidence)
	versionSignals := []string{"version", "banner", "server:", "x-powered-by", "powered-by"}
	hasVersion := false
	hasExploit := false
	for _, sig := range versionSignals {
		if strings.Contains(lower, sig) {
			hasVersion = true
			break
		}
	}
	exploitSignals := []string{"curl -", "200", "403", "http/1.", "response", "output"}
	for _, sig := range exploitSignals {
		if strings.Contains(lower, sig) {
			hasExploit = true
			break
		}
	}
	return hasVersion && !hasExploit
}

// validateMechanicalEvidence: mechanical-verification credential check (v0.4.52, borrowing raptor's epistemic gate):
// critical/high vulns must carry mechanically reproducible verification credentials (HTTP response/curl output/tool output).
// Pure version matching can't be vuln evidence (CVEngine match_policy: distro backports don't bump versions).
// Empty return = pass; otherwise it's the corrective nudge fed back to the model.
func validateMechanicalEvidence(severity, evidence string) string {
	if strings.TrimSpace(evidence) == "" {
		return "" // empty evidence is handled by validateFindingEvidence
	}
	lower := strings.ToLower(severity)
	if lower != "critical" && lower != "high" {
		return "" // no mechanical-verification check for medium/low
	}
	if hasMechanicalVerification(evidence) {
		return "" // has mechanical credentials — pass
	}
	if hasVersionOnlyEvidence(evidence) {
		return "Evidence has only version/banner matching, no behavior-level verification — distro backport patches don't bump version numbers; version match ≠ vuln. " +
			"Send real requests to the target via http_probe or curl and write the HTTP status/response signature/command output into evidence. " +
			"If it's only a version match without verification, downgrade to medium and note 'version match, behavior unverified'."
	}
	return "critical/high evidence lacks mechanically reproducible credentials (HTTP status/curl command output/tool hit results). " +
		"Actually trigger the target with tools and write the returned status code/response headers/key fields into evidence — " +
		"'may exist' is not a finding; 'actually obtained' is. Or downgrade to medium."
}

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

const findingTrafficGuidance = "\n\n**Vuln traffic evidence (optional)**: when reporting via report_finding, if you have reviewed HTTP request/response records that support the vuln conclusion, bind them by real ID via traffic_refs in reproduction order; domains and times are only for candidate filtering — don't presume attribution. For non-HTTP vulns like TCP, uncollected or no-exact-match cases, omit or pass [] — keep other verifiable evidence in evidence (command output, logs) and note why unbound. Don't guess IDs and don't re-probe just to fill bindings."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
