package agent

// Full-verification evidence review (v0.9.30)
//
// The goal isn't 'was evidence written' but 'can the evidence support the harm conclusion and pass SRC acceptance'.
// A plain-text rule pass gives an explainable checklist review: auto-attached to the report_finding receipt,
// and callable proactively by worker/reporter via evidence_check.
//
// Rules only suggest and score — never block storage (blocking would shut real vulns out); but for high/critical
// missing core evidence, gaps are listed explicitly and auto-follow-up intents carry them to be filled.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

type EvidenceCheck struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	OK       bool   `json:"ok"`
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
}

type EvidenceReview struct {
	Score       int             `json:"score"`
	SRCReady    bool            `json:"src_ready"`
	Checks      []EvidenceCheck `json:"checks"`
	Missing     []string        `json:"missing,omitempty"`
	Suggestions []string        `json:"suggestions,omitempty"`
}

var (
	evRawRequestRE = regexp.MustCompile(`(?mi)^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+`)
	evResponseRE   = regexp.MustCompile(`(?i)(HTTP/\d(?:\.\d)?|Status:\s*\d{3}|status code\s*[::]?\s*\d{3}|"status"\s*:\s*\d{2,3})`)
	evURLRE        = regexp.MustCompile(`https?://[^\s"'<>]+`)
	evIPRE         = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	evTimeRE       = regexp.MustCompile(`(20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}:\d{2}:\d{2})`)
	evMaskRE       = regexp.MustCompile(`(\*{3,}|\[redacted\]|desensitized|pixelated|masked|x{4,})`)
	evCountRE      = regexp.MustCompile(`(?i)(?:altogether|grand total|sum total|total|count|rows?|records?)?\s*(\d{2,})\s*(?:entries|lines|pieces|records?|rows?|users?|orders?|items?)`)
	evCmdExecRE    = regexp.MustCompile(`(?i)(uid=\d+|whoami|hostname|/etc/passwd|nt authority\\system|root@|administrator|command execution output|id\s*[:=]\s*\d+)`)
)

func hasAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func countSignal(s string) (int, bool) {
	m := evCountRE.FindStringSubmatch(s)
	if len(m) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// ReviewEvidence runs an SRC-completeness review on a vuln's evidence. severity is case-insensitive;
// vulnclass decides what the class must prove (data read / write op / privilege / command exec).
func ReviewEvidence(severity, vulnclass, evidence string) EvidenceReview {
	sev := strings.ToLower(strings.TrimSpace(severity))
	vc := strings.ToLower(strings.TrimSpace(vulnclass))
	text := strings.TrimSpace(evidence)
	lower := strings.ToLower(text)

	rawReq := evRawRequestRE.MatchString(text) || strings.Contains(lower, "curl ")
	resp := evResponseRE.MatchString(text)
	identity := hasAny(lower, "cookie:", "authorization:", "token", "session", "account", "username", "uid=", "role", "identity", "logged-in")
	repro := hasAny(lower, "curl ", "sqlmap", "nuclei", "python ", "python3 ", "reproduction steps", "reproduction command")
	if !repro {
		repro = regexp.MustCompile(`(?m)^\s*\d+[.).]\s*`).MatchString(text)
	}
	target := evURLRE.MatchString(text) || evIPRE.MatchString(text) || hasAny(lower, "target", "host", "domain")
	stamp := evTimeRE.MatchString(text)
	noMask := !evMaskRE.MatchString(text)
	artifact := regexp.MustCompile(`artifact:\d+|save_evidence|sha256`).MatchString(lower)
	traffic := hasAny(lower, "traffic_refs", "traffic_id", "baseline", "proof", "traffic #", "traffic#")

	num, hasCount := countSignal(lower)
	fullExport := hasAny(lower, "full export", "complete export", "export all pages", "all records", "total count", "total", "export endpoint")
	dataVolume := (hasCount && num >= 10) || fullExport
	sensitive := hasAny(lower, "identity proof", "phone number", "mobile", "email", "address", "order", "balance", "password", "token", "secret", "id card", "bank card", "credential", "personal data")
	impactRead := dataVolume && sensitive
	writeTest := hasAny(lower, "write test", "write", "create new", "create", "modify", "update", "delete", "read back", "before", "after", "test write", "insert", "new record", "update record", "write-back")
	writeReadback := hasAny(lower, "read back", "query again", "readback", "read back", "consistent comparison", "consistent", "before", "after")
	permission := hasAny(lower, "privilege escalation", "horizontal", "vertical", "unauthorized", "anonymous", "regular user", "low privilege", "administrator", "admin", "idor", "permission matrix", "identity matrix", "two accounts", "two identities", "different user")
	cmdExec := evCmdExecRE.MatchString(lower)
	impact := impactRead || (writeTest && writeReadback) || permission || cmdExec

	mk := func(id, label string, ok bool, required bool, detail string) EvidenceCheck {
		return EvidenceCheck{ID: id, Label: label, OK: ok, Required: required, Detail: detail}
	}
	checks := []EvidenceCheck{
		mk("raw_request", "raw request/command (method/path/headers or the actual command)", rawReq || cmdExec, true, "paste the actual request line and key headers, or the actual executed command; without raw text it can't be reviewed"),
		mk("response", "raw response/command output", resp || cmdExec, true, "paste the actual response status code and key body, or the command echo; 'returned success' alone doesn't count"),
		mk("identity", "identity and permission context", identity, sev == "critical" || sev == "high", "state which account/role/Cookie/token was used; authorization-bypass cases need two identities"),
		mk("reproduction", "reproducible command or step-by-step procedure", repro, true, "give the curl/sqlmap/nuclei command or numbered steps so someone else can reproduce it"),
		mk("target", "target address/host", target, true, "write the full URL, Host or IP"),
		mk("timestamp", "verification time", stamp, false, "record verification time — for re-testing and evidence freshness"),
		mk("no_mask", "data unmasked (original values kept)", noMask, true, "no ***, [redacted], masked or blurred fields in evidence; first-party SRC submission needs original values"),
		mk("impact", "actual harm proof (read/write/privilege/command)", impact, sev == "critical" || sev == "high", "prove at least one real impact: data read, write-test read-back, privilege difference, or command echo"),
		mk("data_volume", "data volume & sensitive fields", impactRead, strings.Contains(vc, "disclosure") || strings.Contains(vc, "leak") || strings.Contains(vc, "privesc") || strings.Contains(vc, "injection") || strings.Contains(vc, "data") || strings.Contains(vc, "idor") || strings.Contains(vc, "leakage") || strings.Contains(vc, "privilege abuse") || strings.Contains(vc, "injection flaw") || strings.Contains(vc, "dataset"), "at least 10 deduped records or full set/total, listing sensitive fields; 1 record doesn't count"),
		mk("write_test", "write test (self-created object + read-back + cleanup)", writeTest && writeReadback, strings.Contains(vc, "upload") || strings.Contains(vc, "write") || strings.Contains(vc, "logic") || strings.Contains(vc, "payment") || strings.Contains(vc, "tamper") || strings.Contains(vc, "file upload") || strings.Contains(vc, "write-in") || strings.Contains(vc, "business logic") || strings.Contains(vc, "payments") || strings.Contains(vc, "tampering"), "write tests may only modify self-created test objects — record before/after values and read back; never touch production business data"),
		mk("permission", "privilege matrix/privesc comparison", permission, strings.Contains(vc, "privesc") || strings.Contains(vc, "unauthorized") || strings.Contains(vc, "permission") || strings.Contains(vc, "idor") || strings.Contains(vc, "privilege abuse") || strings.Contains(vc, "unauthorized access") || strings.Contains(vc, "permissions"), "list response differences for anonymous/regular/admin identities on the same endpoint"),
		mk("artifact", "evidence artifact/hash", artifact, false, "register large datasets/screenshots via save_evidence with sha256 + artifact id"),
		mk("traffic", "traffic evidence binding (baseline/proof)", traffic, false, "HTTP vulns should bind baseline and proof — two real traffic records"),
	}

	requiredCount, passedRequired := 0, 0
	missing := make([]string, 0, 4)
	suggestions := make([]string, 0, 4)
	for _, c := range checks {
		if c.Required {
			requiredCount++
			if c.OK {
				passedRequired++
			} else {
				missing = append(missing, c.Label)
			}
		}
	}
	score := 0
	if len(checks) > 0 {
		passed := 0
		for _, c := range checks {
			if c.OK {
				passed++
			}
		}
		score = passed * 100 / len(checks)
	}
	// SRC-ready = all required items pass AND total ≥55. Low-sev still needs raw request/response,
	srcReady := requiredCount > 0 && passedRequired == requiredCount && score >= 55
	if !noMask {
		suggestions = append(suggestions, "restore masked/redacted fields to original values — first-party SRC submission needs complete evidence; masking counts as insufficient.")
	}
	if !impactRead && !cmdExec && !permission && !(writeTest && writeReadback) {
	}
	if !artifact && (impactRead || writeTest) {
		suggestions = append(suggestions, "land the full dataset/samples to disk and register via save_evidence (kind=data, note the record count and fields), then cite the artifact id in the report.")
	}
	if !traffic && (rawReq || resp) {
		suggestions = append(suggestions, "bind baseline (normal request) and proof (exploit request) via traffic_refs for easier review.")
	}
	return EvidenceReview{Score: score, SRCReady: srcReady, Checks: checks, Missing: missing, Suggestions: suggestions}
}

// evidenceCheck is the read-only tool for agents' proactive review: it can review an evidence text directly,
// or read a registered vuln node's payload via finding_node_id (summary/evidence.poc).
func (t *ToolSet) evidenceCheck() actool.CoreTool {
	return readTool("evidence_check",
		"review whether the vulnerability evidence supports the harm conclusion and passes SRC acceptance (raw request/response, reproduction command, identity, data volume/sensitive fields, privilege or write test, masking, artifact/traffic binding). Run it once before reporting and fill the gaps named in missing; high/critical should not end while a core item is missing.",
		obj(map[string]any{
			"evidence":        str("evidence text to review (optional; use alone or together with finding_node_id — evidence wins when both given)"),
			"finding_node_id": idp("optional: exploration node ID of a registered vuln; reads summary/evidence.poc/vulnclass/severity from its payload"),
			"severity":        str("critical|high|medium|low (optional, defaults to node's value or medium)"),
			"vulnclass":       str("vuln class (optional — decides which items the class must fill)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Evidence      string `json:"evidence"`
				FindingNodeID int64  `json:"finding_node_id"`
				Severity      string `json:"severity"`
				VulnClass     string `json:"vulnclass"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			source := "input"
			if strings.TrimSpace(a.Evidence) == "" && a.FindingNodeID > 0 {
				if t.ts == nil {
					return actool.Errorf("this agent has no task exploration-graph context; pass the evidence text to the evidence param directly"), nil
				}
				n, err := t.ts.GetNode(a.FindingNodeID)
				if err != nil || n == nil {
					return actool.Errorf("finding_node_id doesn't exist or isn't readable"), nil
				}
				var p struct {
					VulnClass string `json:"vulnclass"`
					Name      string `json:"name"`
					Severity  string `json:"severity"`
					Summary   string `json:"summary"`
					Evidence  struct {
						PoC string `json:"poc"`
					} `json:"evidence"`
				}
				_ = json.Unmarshal(n.Payload, &p)
				if a.VulnClass == "" {
					a.VulnClass = p.VulnClass
				}
				if a.Severity == "" {
					a.Severity = p.Severity
				}
				if strings.TrimSpace(a.Evidence) == "" {
					a.Evidence = strings.TrimSpace(p.Summary + "\n" + p.Evidence.PoC)
				}
				source = fmt.Sprintf("finding_node:%d", a.FindingNodeID)
			}
			if strings.TrimSpace(a.Evidence) == "" {
				return actool.Errorf("needs evidence text or finding_node_id"), nil
			}
			if a.Severity == "" {
				a.Severity = "medium"
			}
			review := ReviewEvidence(a.Severity, a.VulnClass, a.Evidence)
			return jsonResult(map[string]any{"source": source, "review": review})
		})
}
