package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// renderBacklogHygiene lists 'queued too long' or 'premise seemingly refuted' open intents into this
// round's planner input, asking the planner to rule on each (keep / retire_intent / re-dispatch on new facts).
//
// Why needed (2026-11-13 task-20 audit): the planner had already read new conclusions (124/124 intents
// anchored to existing facts), but no tool could withdraw 'already-queued old intents' — #5225/#5226 stayed
// open 6 hours after their targets were disproven; workers would eventually run them for nothing. This only
// nudges — retirement stays an explicit model call with traceable reasons; no auto-kill.
func renderBacklogHygiene(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	items, err := ts.OpenIntentHygiene(2*time.Hour, 40)
	if err != nil || len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Backlog hygiene (must handle this round)]: the following queued intents have waited over 2 hours, or their anchor facts were refuted by later conclusions.")
	b.WriteString("Rule on each: still valid → keep; premise invalidated / direction ruled out → call retire_intent (reason must cite which fact/finding refuted it);")
	b.WriteString("for duplicates → retire_intent must carry superseded_by pointing at a live replacement intent (open/running/done), never at a retired one;")
	b.WriteString("retire at most 6 per round — handle the rest next round; confirm replacements first, don't gut a whole capability class just to clear the backlog.")
	const maxShow = 5
	for i, it := range items {
		if i == maxShow {
			fmt.Fprintf(&b, "\n- …%d more similar backlog items (see graph_overview)", len(items)-maxShow)
			break
		}
		fmt.Fprintf(&b, "\n- #%d (queued %.1f h, priority %d): %s", it.ID, it.AgeHours, it.Priority, clampForPrompt(it.Summary, 70))
		for _, w := range it.Warnings {
			b.WriteString("\n  ⚠ " + clampForPrompt(w, 100))
		}
	}
	return b.String()
}

// clampForPrompt truncates long text in prompts (by rune, keeps the meaningful head).
func clampForPrompt(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
