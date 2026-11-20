package server

import (
	"context"
	"errors"
	"testing"

	"github.com/chu0119/pojun/agent"
)

// TestHandlePlannerRoundOutcomeRegistersSettleBeforeCancelExec 钉住收尾判据的
// 登记顺序：cancelExec 取消的就是本轮 ectx，若先取消再检查 ectx.Err()，goal_met
// 收尾在 met 轮永远登记不上（任务只能等心跳/超时结束）。
func TestHandlePlannerRoundOutcomeRegistersSettleBeforeCancelExec(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t1"}
	ectx := e.execContextFor(context.Background(), task.ID)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, reason: "all goals met"}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "goal_met" {
		t.Fatalf("挂起收尾 reason=%q，期望 goal_met（登记被 cancelExec 遮掉了）", reason)
	}
	if ectx.Err() == nil {
		t.Fatal("判定目标达成后在跑 worker 未被取消")
	}
	if code, _, _, ok := agent.AbortReason(ectx); !ok || code != "goal_met" {
		t.Fatalf("取消原因 code=%q ok=%v，期望 goal_met", code, ok)
	}
}

// TestHandlePlannerRoundOutcomeSkipsSettleAfterExternalCancel 本轮已被外部取消
// （pause / 收尾硬取消）时不得登记收尾：否则 pause 期间攒下的 goal_met 会在
// resume 后立刻把任务收掉。
func TestHandlePlannerRoundOutcomeSkipsSettleAfterExternalCancel(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t2"}
	ectx := e.execContextFor(context.Background(), task.ID)
	e.Pause(task.ID, agent.AbortPausedByUser)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, reason: "all goals met"}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("外部取消后仍登记了收尾 %q", reason)
	}
}

// TestHandlePlannerRoundOutcomeIgnoresGoalMetOnPlannerError 半成功的轮不能用来
// 收尾：Plan 可能在 prove_goal 置位 GoalMet 之后才因 LLM/传输错误返回非 nil err
// （agent/planner.go 直接透传 tsx.GoalMet），此时既不该登记收尾，也不该杀 worker。
func TestHandlePlannerRoundOutcomeIgnoresGoalMetOnPlannerError(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t3"}
	ectx := e.execContextFor(context.Background(), task.ID)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, err: errors.New("llm down")}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("规划出错却登记了收尾 %q", reason)
	}
	if ectx.Err() != nil {
		t.Fatal("规划出错却取消了在跑 worker")
	}
}

// TestMaybePendingSettleRechecksGoalsBeforeGoalMet 钉住 goal_met 收尾前的数据库
// 复核：planner 判定「目标达成」依据的是**当时**的目标集，而新增目标先落库、再由
// NotifyGoal 追加内存触发，两者之间存在窗口。若这期间多了一个 open 目标，按旧
// 目标集收尾会把刚加进来的目标连同任务一起终结（settleTaskWithReason 会用
// taskGoalProgress 重算达成情况，等于用旧判据关掉新目标）。
func TestMaybePendingSettleRechecksGoalsBeforeGoalMet(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	task, err := m.CreateTask("settle recheck", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if task.Store == nil {
		t.Fatal("task.Store 为 nil")
	}
	// 仍有一个未达成目标。
	if _, err := task.Store.AddNode("goal", map[string]any{"text": "still open"}, 0, "open", "test", nil); err != nil {
		t.Fatal(err)
	}

	task.requestSettle("goal_met", "planner 判定目标达成")

	e := NewEngine(m)
	if e.maybePendingSettle(context.Background(), task) {
		t.Fatal("仍有 open 目标却执行了收尾")
	}
	// 复核不通过要撤销挂起收尾，交回规划轮重判；否则下一次唤醒会再试一次。
	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("复核撤销后仍留有挂起收尾 %q", reason)
	}
}

// TestMaybePendingSettleSettlesGoalMetWhenAllGoalsMet 是上一条的正向对照：
// 全部目标已 met 时，goal_met 收尾应当被消费并落终态 done——这是「目标达成后
// 立即收尾」这条链路的终点，缺了它上一条只剩半个断言。
func TestMaybePendingSettleSettlesGoalMetWhenAllGoalsMet(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()

	task, err := m.CreateTask("settle all met", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if task.Store == nil {
		t.Fatal("task.Store 为 nil")
	}
	id, err := task.Store.AddNode("goal", map[string]any{"text": "done"}, 0, "open", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetNodeState(id, "met"); err != nil {
		t.Fatal(err)
	}

	task.requestSettle("goal_met", "planner 判定目标达成")

	e := NewEngine(m)
	if !e.maybePendingSettle(context.Background(), task) {
		t.Fatal("全部目标已 met 却未执行收尾")
	}
	if got := task.lifecycleSnapshot().Status; got != "done" {
		t.Fatalf("终态=%q，期望 done", got)
	}
}
