package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// autopilot goal refill (v0.6.7).
//
// Production issue (2026-11-07, task #5): after the planner prove_goal'd all 8 goals,
// goal_met triggered settle and the task finished in 2 hours — while 47 in-scope
// assets were still untested and 4 high findings had only 'verified exists', no data
// extraction / impact proof. Autopilot's intent is 'keep going until there's nothing
// left', not 'finish this fixed goal batch and wrap up'.
//
// Refill rules (all must hold):
//  1. task has autopilot on and `autopilot_extend_waves` (default 3, 0=off) not used up;
//  2. deadline not reached (5-minute margin);
//  3. real work remains: untested in-scope assets, or registered high/critical findings.
//
// Refill action: auto-append 1–2 next-layer goals (cover untested assets / high-sev
// exploit chains and impact proof), attach under the task root, wake the planner;
// running workers are not cancelled and no settle happens this round.
const (
	settingAutopilotExtendWaves  = "autopilot_extend_waves"
	defaultAutopilotExtendWaves  = 10
	autopilotExtendDeadlineGrace = 5 * time.Minute
)

func (e *Engine) maybeExtendAutopilot(t *Task) bool {
	if t == nil || !t.AutopilotEnabled() || e.m.pg == nil {
		return false
	}
	pg := e.m.pg
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	waves, ok := settingInt(pg, settingAutopilotExtendWaves)
	if !ok {
		waves = defaultAutopilotExtendWaves
	}
	if waves <= 0 || waves > 10 {
		if waves <= 0 {
			return false
		}
		waves = 10
	}
	waveKey := fmt.Sprintf("autopilot_wave_%d", taskID)
	used, _ := settingInt(pg, waveKey)
	if used >= waves {
		return false
	}
	if dl := t.lifecycleSnapshot().DeadlineAt; dl > 0 && time.Now().Add(autopilotExtendDeadlineGrace).Unix() >= dl {
		return false
	}

	untested := 0
	if e.m.assets != nil {
		if _, total, err := e.m.assets.ListUntestedAssetsWithSources(taskID, "", 1, 0); err == nil {
			untested = total
		}
	}
	var highFindings int
	_ = pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND severity IN ('critical','high')`, taskID).Scan(&highFindings)
	if untested == 0 && highFindings == 0 {
		return false
	}

	// progress gate: no new facts/findings since the last refill means 'refilled but
	// nothing came out' — stop refilling. This is the line between 'don't stop until
	// the goal' and 'spinning forever' (users want no budget cap, but not running in
	// place).
	var facts, findings int
	_ = pg.QueryRow(`SELECT
	  (SELECT count(*) FROM exploration_nodes WHERE kind='fact' AND exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)),
	  (SELECT count(*) FROM findings WHERE task_id=$1)`, taskID).Scan(&facts, &findings)
	markKey := fmt.Sprintf("autopilot_ext_mark_%d", taskID)
	mark := fmt.Sprintf("f%d|n%d", facts, findings)
	// the progress gate only applies when there are NO untested assets: as long as
	// anything in scope is untested, there is 'still something to do' — the user asked
	// to continue (even if the last wave produced nothing, that just means the approach
	// was wrong — switch tactics, don't quit). High findings don't decay over time
	// either, so they alone can't justify a refill.
	if used > 0 && untested == 0 {
		if prev, ok, _ := pg.GetSetting(markKey); ok && prev == mark {
			return false
		}
	}
	_ = pg.SetSetting(markKey, mark)

	// refill ladder: each refill advances one stage, so we don't keep adding the same
	// 'high-sev exploit chain' goal and immediately judging it done.
	ladder := []string{
		"Complete exploit chains and impact proof for registered high/critical findings: without damaging the business, perform data extraction / privilege escalation / lateral-reachability verification, and attach one impact proof per finding (request-response or command output + impact description)",
		"Maximize the opened data surface: on interfaces already proven reachable, do pagination / time-window / full-export forensics (read-only, rate-limited, persisted batch by batch with hashes registered)",
		"Same-family spread: apply the verified mechanism to other assets in the same cluster/framework/batch (same C block, same delivery domain, same backend template), verifying each and reporting",
		"Zero out uncovered surface: for in-scope assets still untested, test each vuln-matrix class (unauth / authz-bypass / SQLi / XSS / SSRF / upload / command exec / weak passwords / CVE / logic)",
		"Dig one layer deeper from confirmed footholds: from current privileges/credentials, try lateral movement, persistence reachability, and higher-value data (within authorization bounds, read-only first)",
	}
	stage := ladder[len(ladder)-1]
	if used < len(ladder) {
		stage = ladder[used]
	}
	txt := fmt.Sprintf("%s (refill wave %d: %d registered high-sev, %d untested assets)", stage, used+1, highFindings, untested)
	texts := []string{txt}

	of, _ := t.Store.OriginFactID()
	added := 0
	for _, txt := range texts {
		id, err := t.Store.AddGoal(map[string]any{"text": txt}, "autopilot")
		if err != nil {
			log.Printf("[autopilot] task %d failed to write refill goals: %v", taskID, err)
			continue
		}
		if of > 0 && id > 0 {
			_ = t.Store.Link(of, db.RelSpawns, id)
		}
		added++
	}
	if added == 0 {
		return false
	}
	_ = pg.SetSetting(waveKey, fmt.Sprintf("%d", used+1))
	_ = pg.InsertAutopilotEvent(t.ID, "extend_goals",
		fmt.Sprintf("post-goal refill wave %d/%d: %d untested assets, %d high-sev findings, %d next-layer goals added",
			used+1, waves, untested, highFindings, added))
	t.NotifyGoal(texts)
	log.Printf("[autopilot] task %d goals met -> refill wave %d/%d (%d untested assets, %d high-sev, %d new goals)",
		taskID, used+1, waves, untested, highFindings, added)
	return true
}

// autopilotRelentlessFromPG reads the 'never stop short' switch (default on).
// On: workers get no per-round wall-clock budget, no stall-based wrap-up, no intent
// token-budget notices; autopilot's auto_rounds wrap-up is also suppressed, and at
// goal_met the task auto-refills while work remains.
func autopilotRelentlessFromPG(pg interface {
	GetSetting(string) (string, bool, error)
}) bool {
	if pg == nil {
		return true
	}
	v, ok, err := pg.GetSetting("autopilot_relentless")
	if err != nil || !ok {
		return true
	}
	return v != "false" && v != "0"
}

// autopilotIntentMaxHoursFromPG reads the per-intent backstop wall clock (hours,
// default 0 = unlimited). relentless removes all 'no-progress' gates; tasks needing
// limits can configure this explicitly in settings.
func autopilotIntentMaxHoursFromPG(pg interface {
	GetSetting(string) (string, bool, error)
}) int {
	if pg == nil {
		return 0
	}
	v, ok, err := pg.GetSetting("autopilot_intent_max_hours")
	if err != nil || !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	if n > 24 {
		return 24
	}
	return n
}

// autopilotExtendWavesFromPG reads the refill wave cap (default 10, 0 = off).
func autopilotExtendWavesFromPG(pg *db.DB) int {
	if n, ok := settingInt(pg, settingAutopilotExtendWaves); ok {
		if n < 0 {
			return 0
		}
		if n > 10 {
			return 10
		}
		return n
	}
	return defaultAutopilotExtendWaves
}

// autopilotExtendWave reads the current used-wave count (for admin/debug).
func (e *Engine) autopilotExtendWave(taskID int64) int {
	n, _ := settingInt(e.m.pg, fmt.Sprintf("autopilot_wave_%d", taskID))
	return n
}
