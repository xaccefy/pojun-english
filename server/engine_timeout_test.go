package server

import "testing"

// TestSettleTerminalStatus 覆盖收尾终态的真值表。
//
// 关键格是「有目标、全部 met、reason=timeout、终局轮未再次证明」——旧实现把它
// 判成 timeout（目标全部达成却记为未完成），新实现以数据库为准判 done。其余
// 组合的输出与旧实现逐格一致。
func TestSettleTerminalStatus(t *testing.T) {
	cases := []struct {
		name          string
		metGoals      int
		totalGoals    int
		reason        string
		finalRoundMet bool
		want          string
	}{
		// 无目标：沿用旧语义，由终局轮判定。
		{"goalless-timeout-not-proven", 0, 0, "timeout", false, "timeout"},
		{"goalless-timeout-proven", 0, 0, "timeout", true, "done"},
		{"goalless-goal-met", 0, 0, "goal_met", true, "done"},
		{"goalless-auto-idle", 0, 0, "auto_idle", false, "done"},

		// 有目标且全部 met：数据库即事实，终局轮不再有否决权。
		{"all-met-timeout-not-proven", 5, 5, "timeout", false, "done"},
		{"all-met-timeout-proven", 5, 5, "timeout", true, "done"},
		{"all-met-auto-idle", 5, 5, "auto_idle", false, "done"},
		{"all-met-auto-rounds", 5, 5, "auto_rounds", false, "done"},
		{"all-met-goal-met", 5, 5, "goal_met", true, "done"},

		// 有未达成目标：一律 timeout，终局轮的 met 不能翻案。
		{"partial-timeout-not-proven", 2, 5, "timeout", false, "timeout"},
		{"partial-timeout-proven", 2, 5, "timeout", true, "timeout"},
		{"partial-auto-rounds", 4, 5, "auto_rounds", false, "timeout"},
		{"partial-goal-met-should-not-happen", 1, 3, "goal_met", true, "timeout"},

		// 目标存在但一个都没达成（含 abandoned 口径：非 met 一律按未达成计）。
		{"none-met-timeout-proven", 0, 3, "timeout", true, "timeout"},
		{"none-met-auto-coverage", 0, 3, "auto_coverage", false, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := settleTerminalStatus(tc.metGoals, tc.totalGoals, tc.reason, tc.finalRoundMet); got != tc.want {
				t.Fatalf("settleTerminalStatus(%d, %d, %q, %v) = %q, want %q",
					tc.metGoals, tc.totalGoals, tc.reason, tc.finalRoundMet, got, tc.want)
			}
		})
	}
}
