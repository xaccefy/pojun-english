package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestGoalRequiresCapabilityEvidence(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"获取 RCE", true},
		{"拿到后台管理员控制权", true},
		{"验证高危业务数据越权泄露", true},
		{"获取敏感数据", true},
		{"确认是否存在 RCE", false},
		{"排查命令执行入口", false},
		{"验证 SQL 注入", false},
		{"收集管理员登录页与端口", false},
		{"whether the target is vulnerable to RCE", false},
	}
	for _, c := range cases {
		if got := goalRequiresCapabilityEvidence(c.text); got != c.want {
			t.Errorf("goalRequiresCapabilityEvidence(%q)=%v, want %v", c.text, got, c.want)
		}
	}
}

func TestProveGoalCapabilityGate(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	task, err := d.CreateTask("prove_goal capability gate", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := d.Exploration(task.ExplorationID)

	goalID, err := ts.AddNode(db.KindGoal, map[string]any{"text": "获取 RCE / 命令执行权限"}, 0, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	factID, err := ts.AddNode(db.KindFact, map[string]any{"summary": "未发现入口"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	lowID, err := ts.AddNode(db.KindFinding, map[string]any{"severity": "low", "name": "信息泄露"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	highID, err := ts.AddNode(db.KindFinding, map[string]any{"severity": "high", "name": "RCE"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	tset := &ToolSet{ts: ts, worker: "planner"}
	prove := func(evidence int64) {
		_, _ = tset.proveGoal().Call(ctx, json.RawMessage(fmt.Sprintf(
			`{"goal_id":%d,"evidence_id":%d,"reason":"test"}`, goalID, evidence)), nil)
	}

	prove(factID)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "open" {
		t.Fatalf("否定性 fact 不应把能力型目标标 met，state=%v", n)
	}
	if tset.GoalMet {
		t.Fatal("fact 证明后 GoalMet 不应为 true")
	}

	prove(lowID)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "open" {
		t.Fatalf("low finding 不应把能力型目标标 met，state=%v", n)
	}

	prove(highID)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "met" {
		t.Fatalf("high finding 应能把能力型目标标 met，state=%v", n)
	}
	if !tset.GoalMet {
		t.Fatal("全部目标 met 后 GoalMet 应为 true")
	}
}

// 「确认是否存在」类目标用否定性 fact 证明是合法的，不能被能力门槛误伤。
func TestProveGoalNegativeGoalAllowsFact(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	task, err := d.CreateTask("prove_goal negative goal", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := d.Exploration(task.ExplorationID)

	goalID, err := ts.AddNode(db.KindGoal, map[string]any{"text": "确认是否存在 RCE 入口"}, 0, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	factID, err := ts.AddNode(db.KindFact, map[string]any{"summary": "已遍历公开入口，未发现 RCE"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	tset := &ToolSet{ts: ts, worker: "planner"}
	_, _ = tset.proveGoal().Call(ctx, json.RawMessage(fmt.Sprintf(
		`{"goal_id":%d,"evidence_id":%d,"reason":"已排查"}`, goalID, factID)), nil)
	if n, _ := ts.GetNode(goalID); n == nil || n.State != "met" {
		t.Fatalf("存在性排查目标应允许 fact 证明，state=%v", n)
	}
}
