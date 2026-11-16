package agent

import (
	"strings"

	"github.com/chu0119/pojun/db"
)

// constraintBlock renders this task's operation constraints (task_constraints) as a
// high-priority block appended to the planner/worker system prompt. allow/deny are
// grouped; empty string when there are no constraints (or ts is nil). The framing
// deliberately puts these ABOVE the exploration/expansion heuristics so a declared
// boundary wins the tug-of-war against "chase another entry surface".
func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	var allow, deny []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else {
			deny = append(deny, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Operational constraints (highest priority — override every exploration/expansion heuristic below; before generating any intent or executing any action, self-check for violation first — if violated, do NOT proceed)]: ")
	if len(allow) > 0 {
		b.WriteString("\nAllowed operations:\n")
		b.WriteString(strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("\nForbidden operations:\n")
		b.WriteString(strings.Join(deny, "\n"))
	}
	b.WriteString("\n(Discovering a new target/port/host outside the constraints is NOT authorization: unless it falls inside the allowed scope above, record it as an out-of-scope fact and skip — do not spawn intents or act on it.)")
	return b.String()
}
