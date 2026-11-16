package server

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// Coverage-matrix gap nudge (v0.4.63).
//
// Retrospective (tasks #5/#6): the planner prompt already spells out a 10-class vuln
// coverage matrix, but weak models still dispatch only their favorite classes — of task
// #6's 16 intents, sqli 0, xss 0, rce 0, while authz took 13. Prompts can't enforce it,
// so the engine adds a deterministic nudge: when a class is never mentioned by any
// intent, wake the planner once and call it out (once per class per task — no spam).
var coverageClasses = []struct {
	key   string
	label string
	re    string // matched in intent text = already covered
	tip   string
}{
	{"sqli", "SQL injection", `sql injection|sqli|sqlmap|sql injection`, "On parameterized interfaces (GET params / POST forms / JSON fields), run read-only probes with sqlmap --batch --level=2 --risk=1, covering at least one login/query/detail endpoint each."},
	{"xss", "XSS/template injection", `xss|cross-site|template injection|template injection|cross-site`, "On pages and interfaces that reflect user input, verify reflected/stored XSS with dalfox or hand-crafted payloads."},
	{"ssrf", "SSRF/connect-back", `ssrf|server-side request forgery|connect-back|connect-back|server-side request`, "Check URL params, image proxies, webhooks, export callbacks; verify connect-back with a listener."},
	{"upload", "File upload/parsing", `upload|upload|file upload`, "Find upload interfaces; test type/extension/content/path bypasses (prove capability only — no backdoors)."},
	{"rce", "Command execution/deserialization", `command execution|rce|deserialization|code execution|command execution|deserialization|code execution`, "Look up CVEs by component fingerprint (framework/middleware version) and actually trigger; with no component clues, skip and say why."},
	{"dirscan", "Directory/path discovery", `directory|path brute|ffuf|gobuster|dirsearch|directory brute|path brute`, "Run ffuf + /opt/SecLists wordlists once against the main site/admin/gateway (-rate 30) and write results back to assets."},
}

// missingCoverageClasses returns class keys not yet covered by any intent text (in
// declaration order).
func missingCoverageClasses(intentTexts []string) []string {
	joined := strings.ToLower(strings.Join(intentTexts, "\n"))
	var out []string
	for _, c := range coverageClasses {
		if !regexp.MustCompile(c.re).MatchString(joined) {
			out = append(out, c.key)
		}
	}
	return out
}

func coverageClassByKey(key string) (label, tip string, ok bool) {
	for _, c := range coverageClasses {
		if c.key == key {
			return c.label, c.tip, true
		}
	}
	return "", "", false
}

// nudgeCoverageGaps runs after a planner round: when a class is never mentioned, wake
// the planner once. Once per class per task; no nudge when the task has no assets yet
// (not at the vuln stage).
func (e *Engine) nudgeCoverageGaps(t *Task) {
	if e.m.pg == nil || t == nil || t.Store == nil {
		return
	}
	var assets int
	tid := t.ID
	_ = e.m.pg.QueryRow(`SELECT count(*) FROM task_asset_links WHERE task_id=$1`, tid).Scan(&assets)
	if assets == 0 {
		return
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 1000)
	if err != nil || len(goals) == 0 {
		return
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 1000)
	if err != nil || len(intents) < 5 {
		// too few intents (just started / test scenario) → skip: not at the 'coverage gap'
		// stage yet.
		return
	}
	texts := make([]string, 0, len(intents))
	for _, n := range intents {
		texts = append(texts, string(n.Payload))
	}
	for _, key := range missingCoverageClasses(texts) {
		settingKey := fmt.Sprintf("coverage_nudge_%s_%s", t.ID, key)
		if v, ok, _ := e.m.pg.GetSetting(settingKey); ok {
			// nudged within 6 hours → skip; old versions stored "1" which fails to parse
			// → treat as long ago, nudge again.
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil && time.Since(time.Unix(ts, 0)) < 6*time.Hour {
				continue
			}
		}
		label, tip, ok := coverageClassByKey(key)
		if !ok {
			continue
		}
		msg := fmt.Sprintf("Coverage-matrix gap: this task has no [%s] intent so far. Dispatch one intent dedicated to that class — %s"+
			" State the target endpoint and tools/criteria in the summary; if the class clearly doesn't apply to this target, dispatch a minimal confirmation intent or have a worker record a fact explaining why — never skip silently.",
			label, tip)
		t.trigMu.Lock()
		t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "coverage_gap", Detail: msg})
		t.trigMu.Unlock()
		_ = e.m.pg.SetSetting(settingKey, strconv.FormatInt(time.Now().Unix(), 10))
		log.Printf("[coverage] task %s gap nudge: %s", t.ID, label)
		t.Notify()
	}
}
