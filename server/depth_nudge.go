package server

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// Depth-gap nudge (v0.4.63).
//
// Production retrospective (task #8): assets went 34 → 241 in two hours while
// high/critical findings stayed 0 — the planner was diligent at 'spreading surface' but
// weak at 'driving verified leads through to L3 evidence'. The goals say 'own the
// server / exfiltrate data / gain privileges'; spreading surface alone never gets there.
//
// Prompts can't fully enforce this (weak models stay recon-biased), so the engine adds a
// deterministic check: when assets are plentiful and high-severity findings are 0, send
// the planner a trigger to 'stop spreading and drive 1-2 verified leads through'. At
// most once per task per 3 hours — no spam.
const (
	depthNudgeMinAssets = 50
	depthNudgeThrottle  = 3 * time.Hour
)

// needsDepthNudge is a pure predicate: many assets, zero high-sev output.
func needsDepthNudge(assets, highFindings int) bool {
	return assets >= depthNudgeMinAssets && highFindings == 0
}

// nudgeDepthGaps is called after an intent ends (same timing as the coverage nudge).
func (e *Engine) nudgeDepthGaps(t *Task) {
	if e.m.pg == nil || t == nil || t.Store == nil {
		return
	}
	if !e.m.pg.GetBool("depth_nudge_enabled", true) {
		return
	}
	tid := t.ID
	var assets int
	_ = e.m.pg.QueryRow(`SELECT count(*) FROM task_asset_links WHERE task_id=$1`, tid).Scan(&assets)
	var high int
	_ = e.m.pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND severity IN ('critical','high')`, tid).Scan(&high)
	if !needsDepthNudge(assets, high) {
		return
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 1000)
	if err != nil || len(goals) == 0 {
		return
	}
	key := fmt.Sprintf("depth_nudge_%s", tid)
	if v, ok, _ := e.m.pg.GetSetting(key); ok {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil && time.Since(time.Unix(ts, 0)) < depthNudgeThrottle {
			return
		}
	}
	_ = e.m.pg.SetSetting(key, strconv.FormatInt(time.Now().Unix(), 10))
	msg := fmt.Sprintf("Depth gap: this task registered %d assets but still has 0 high/critical findings — the goals' control/exfil/privilege objectives have no L3 evidence yet. "+
		"This round **stop spreading new surface** (at most 1 new direction); pick 1–2 existing leads among unauthorized access, config leaks, weak passwords, object storage, debug/admin interfaces and drive them through: "+
		"obtain one of data-extraction samples / successful admin login / command output echo / accessible uploaded file, and write it as a finding (with request-response or command-output evidence). "+
		"Only when every confirmed lead genuinely can't be pushed further may you resume spreading — and first record a fact explaining why each one is stuck.", assets)
	t.trigMu.Lock()
	t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "depth_gap", Detail: msg})
	t.trigMu.Unlock()
	log.Printf("[depth] task %s depth-gap nudge: %d assets, 0 high-sev — demanding convergence and follow-through", tid, assets)
	t.Notify()
}
