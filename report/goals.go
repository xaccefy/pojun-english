package report

import (
	"encoding/json"

	"github.com/chu0119/pojun/db"
)

// GoalLine is one task objective in the report plus whether it was met (v0.6.31).
//
// Background: a task may complete only some of its objectives, and the old report only
// carried the raw Goal text, so the reader could not tell "which objectives were proven
// met and which were not done". Markdown/docx now list each objective with its state and
// flag it explicitly when not all were met, so the deliverable does not look like
// "everything completed".
type GoalLine struct {
	Text     string
	State    string // open | met (the goal node's state)
	Criteria string // verifiable acceptance criteria (may be empty)
}

// Met means this objective was proven item by item by prove_goal.
func (g GoalLine) Met() bool { return g.State == "met" }

// GoalLines turns goal nodes into report rows; nil/empty input returns nil (the report
// omits that section).
func GoalLines(nodes []*db.Node) []GoalLine {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]GoalLine, 0, len(nodes))
	for _, n := range nodes {
		var p struct {
			Text     string `json:"text"`
			Criteria string `json:"criteria"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if p.Text == "" {
			continue
		}
		out = append(out, GoalLine{Text: p.Text, State: n.State, Criteria: p.Criteria})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// GoalTally returns (met, total).
func GoalTally(goals []GoalLine) (met, total int) {
	for _, g := range goals {
		total++
		if g.Met() {
			met++
		}
	}
	return met, total
}
