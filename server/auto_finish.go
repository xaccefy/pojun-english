package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

// Auto-wrap-up settings (v0.5.0). Global; 0 disables that criterion (coverage/max).
const (
	settingAutoFinishEnabled    = "auto_finish_enabled"
	settingAutoFinishIdleRounds = "auto_finish_idle_rounds"
	settingAutoFinishMinRounds  = "auto_finish_min_rounds"
	settingAutoFinishCoverage   = "auto_finish_coverage_pct"
	settingAutoFinishMaxRounds  = "auto_finish_max_rounds"

	defaultAutoFinishIdleRounds = 3
	defaultAutoFinishMinRounds  = 5
	defaultAutoFinishCoverage   = 0
	defaultAutoFinishMaxRounds  = 80
)

type autoFinishConfig struct {
	Enabled     bool
	IdleRounds  int
	MinRounds   int
	CoveragePct int
	MaxRounds   int
}

// autoFinishConfigFromPG reads global settings, clamped to safe ranges. Read failure
// falls back to defaults — a settings query error must never wedge tasks at 'never wrap
// up'.
func autoFinishConfigFromPG(pg *db.DB) autoFinishConfig {
	c := autoFinishConfig{
		Enabled:     true,
		IdleRounds:  defaultAutoFinishIdleRounds,
		MinRounds:   defaultAutoFinishMinRounds,
		CoveragePct: defaultAutoFinishCoverage,
		MaxRounds:   defaultAutoFinishMaxRounds,
	}
	if pg == nil {
		return c
	}
	if v, ok, err := pg.GetSetting(settingAutoFinishEnabled); err == nil && ok {
		c.Enabled = v == "true" || v == "1"
	}
	if n, ok := settingInt(pg, settingAutoFinishIdleRounds); ok {
		c.IdleRounds = clampInt(n, 2, 20)
	}
	if n, ok := settingInt(pg, settingAutoFinishMinRounds); ok {
		c.MinRounds = clampInt(n, 1, 50)
	}
	if n, ok := settingInt(pg, settingAutoFinishCoverage); ok {
		c.CoveragePct = clampInt(n, 0, 100)
	}
	if n, ok := settingInt(pg, settingAutoFinishMaxRounds); ok {
		c.MaxRounds = clampInt(n, 0, 500)
	}
	return c
}

func settingInt(pg *db.DB, key string) (int, bool) {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// evaluateAutoFinish is a pure predicate (for testing). active means open/running
// intents exist; coveragePct is 0..100, 0 = coverage unavailable/off.
//
// Priority: max rounds (hard cap, may wrap while intents exist) → coverage →
// consecutive zero-progress. idle/coverage both require active=false so actively
// advancing tasks aren't harvested by mistake.
func evaluateAutoFinish(round int64, idle int, active bool, coveragePct int, cfg autoFinishConfig) (reason, detail string, ok bool) {
	if !cfg.Enabled {
		return "", "", false
	}
	if cfg.MaxRounds > 0 && round >= int64(cfg.MaxRounds) {
		return "auto_rounds", fmt.Sprintf("reached the max planner rounds %d", cfg.MaxRounds), true
	}
	if round < int64(cfg.MinRounds) {
		return "", "", false
	}
	if active {
		return "", "", false
	}
	if cfg.CoveragePct > 0 && idle >= 1 && coveragePct >= cfg.CoveragePct {
		return "auto_coverage", fmt.Sprintf("asset coverage %d%% ≥ %d%% (and %d consecutive rounds with no additions)", coveragePct, cfg.CoveragePct, idle), true
	}
	if idle >= cfg.IdleRounds {
		return "auto_idle", fmt.Sprintf("%d consecutive rounds with no additions (round %d)", idle, round), true
	}
	return "", "", false
}

// freshDirection tells whether this round's trigger carries user-added goals/hints; if
// so the wrap-up counters reset, so a just-added goal isn't harvested by stale idle
// counts.
func freshDirection(triggers []agent.TriggerEvent) bool {
	for _, ev := range triggers {
		switch ev.Kind {
		case "goal", "goal_edited", "goal_deleted", "hint":
			return true
		}
	}
	return false
}

// recordAndEvaluateAutoFinish records progress and registers a wrap-up reason after a
// regular planner round. Registration only — no settle: the caller (plannerLoop) wraps
// up after this round's inflight drains.
func (e *Engine) recordAndEvaluateAutoFinish(t *Task, round int64, triggers []agent.TriggerEvent) {
	pg := e.m.pg
	if pg == nil || t.ExpID <= 0 || t.Store == nil {
		return
	}
	cfg := autoFinishConfigFromPG(pg)
	if !cfg.Enabled {
		return
	}
	facts, findings, err := pg.CountExplorationProgress(t.ExpID)
	if err != nil {
		log.Printf("[auto-finish] task %s progress read failed: %v", t.ID, err)
		return
	}
	tested := int64(0)
	coveragePct := 0
	if t.CoverageEnabled {
		if taskID, err := strconv.ParseInt(t.ID, 10, 64); err == nil && e.m.assets != nil {
			if cov, err := e.m.assets.TaskCoverageWithSources(taskID); err == nil && cov != nil {
				tested = int64(cov.Tested)
				if cov.Pct != nil {
					coveragePct = clampInt(int(*cov.Pct*100+0.5), 0, 100)
				}
			}
		}
	}
	idle, err := pg.RecordTaskProgress(t.ID, round, facts, findings, tested)
	if err != nil {
		log.Printf("[auto-finish] task %s progress record failed: %v", t.ID, err)
		return
	}
	if freshDirection(triggers) {
		if err := pg.ResetTaskProgress(t.ID); err == nil {
			idle = 0
		}
	}
	active := true
	if a, err := t.Store.HasActiveIntent(); err == nil {
		active = a
	} else {
		log.Printf("[auto-finish] task %s frontier read failed — skipping judgment: %v", t.ID, err)
		return
	}
	reason, detail, ok := evaluateAutoFinish(round, idle, active, coveragePct, cfg)
	if !ok {
		return
	}
	log.Printf("[auto-finish] task %s triggering wrap-up: %s (round=%d idle=%d active=%v coverage=%d%%)",
		t.ID, detail, round, idle, active, coveragePct)
	t.requestSettle(reason, detail)
}

// maybePendingSettle executes a pending wrap-up inside plannerLoop. true means wrap-up
// started. goal_met requires "open+running intents = 0" (drain the frontier first);
// auto_rounds is a hard round cap and may wrap with intents still open (settle drains
// itself); idle/coverage are guaranteed active=false by the predicate — re-checked here
// against concurrent intent additions.
func (e *Engine) maybePendingSettle(ctx context.Context, t *Task) bool {
	reason, detail := t.peekSettle()
	if reason == "" {
		return false
	}
	if e.IsPaused(t.ID) || e.IsDeleting(t.ID) || e.isSettling(t.ID) || t.Store == nil {
		return false
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		return false
	}
	if reason != "auto_rounds" {
		active, err := t.Store.HasActiveIntent()
		if err != nil {
			return false
		}
		if active {
			log.Printf("[settle] task %s pending wrap-up (%s) waiting for running intents to finish", t.ID, reason)
			return false
		}
	}
	// goal_met 是 planner 基于「当时」的目标集下的判定，而新增目标先落库、再由
	// NotifyGoal 追加内存触发，两者之间有窗口；按旧目标集收尾会把刚加的目标连同
	// 任务一起终结（settleTaskWithReason 会用 taskGoalProgress 重算达成情况）。
	// 这里以数据库为准复核一次：仍有 open 目标 → 撤销挂起收尾，交回规划轮重判。
	if reason == "goal_met" {
		open, err := t.Store.HasOpenGoal()
		if err != nil {
			return false // 读库失败：宁可不收尾，等下一次唤醒
		}
		if open {
			t.clearSettle()
			log.Printf("[settle] task %s goal_met wrap-up revoked: the goal set changed, unachieved goals remain", t.ID)
			return false
		}
	}
	e.settleTaskWithReason(ctx, t, reason, detail)
	return true
}
