package db

import (
	"context"
	"testing"
)

// 事故复现：同一资产上的四类互不相同的漏洞，证据里第一个 URL 都是裸资产基址。
// 修复前它们会全部命中 endpoint:<host>/ 强键、被合并进同一 findings 行，
// 各自的报告随后互相覆盖。修复后必须是四条独立记录。
func TestRecordFindingSameAssetDifferentVulnClassCreatesSeparateRows(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("dedup vulnclass test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain)
VALUES ('service','api.dedup-vc.test','dedup-vc.test') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })

	cases := []struct {
		vulnClass string
		name      string
		evidence  string
	}{
		{"权限提升", "订单对象级授权缺失（IDOR）", "目标 http://203.0.113.10:8091 ，自建账号可读取他人订单 /orders/1"},
		{"认证绕过", "JWT 签名校验缺失", "目标 http://203.0.113.10:8091 ，接受 alg=none 的令牌并取得任意身份"},
		{"信息泄露", "找回密码接口用户枚举", "目标 http://203.0.113.10:8091 ，/reset-password 响应差异可枚举用户名"},
		{"SSRF", "PUT /menu 服务端取图", "目标 http://203.0.113.10:8091 ，image_url 可由服务端出站取图"},
	}

	seen := make(map[int64]string, len(cases))
	for _, c := range cases {
		in := RecordFindingInput{
			TaskID:        task.ID,
			ExplorationID: task.ExplorationID,
			VulnClass:     c.vulnClass,
			Name:          c.name,
			Severity:      "high",
			Summary:       c.name,
			Evidence:      c.evidence,
			Worker:        "work#1",
			AssetIDs:      []int64{assetID},
		}
		rec, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if rec.Duplicate {
			t.Fatalf("%s 被错误合并（duplicate=true，命中 finding %d）——同一资产的不同漏洞必须各自成行",
				c.name, rec.FindingID)
		}
		if prev, ok := seen[rec.FindingID]; ok {
			t.Fatalf("%s 与 %s 落到同一 finding %d", c.name, prev, rec.FindingID)
		}
		seen[rec.FindingID] = c.name
	}

	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != len(cases) {
		t.Fatalf("findings 行数=%d，期望 %d", rows, len(cases))
	}
}

// 同一端点、不同漏洞类别也不得合并：端点是位置，不是身份。
func TestRecordFindingSameEndpointDifferentVulnClassDoesNotMerge(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("dedup endpoint test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain)
VALUES ('service','api.dedup-ep.test','dedup-ep.test') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })

	base := RecordFindingInput{
		TaskID:        task.ID,
		ExplorationID: task.ExplorationID,
		Severity:      "high",
		Worker:        "work#1",
		AssetIDs:      []int64{assetID},
	}

	first := base
	first.VulnClass = "SSRF"
	first.Name = "SSRF via image_url"
	first.Summary = first.Name
	first.Evidence = "PUT http://203.0.113.10:8091/menu 的 image_url 可出站取图"
	r1, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, first)
	if err != nil {
		t.Fatal(err)
	}

	second := base
	second.VulnClass = "信息泄露"
	second.Name = "菜单接口泄露内部路径"
	second.Summary = second.Name
	second.Evidence = "GET http://203.0.113.10:8091/menu 返回内部文件路径"
	r2, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Duplicate || r1.FindingID == r2.FindingID {
		t.Fatalf("同端点不同漏洞被合并：finding %d", r1.FindingID)
	}
}

// 显式声明同一根因时，跨端点仍应合并——收紧位置键不能连正当的根因归并一起关掉。
func TestRecordFindingExplicitRootCauseKeyMergesAcrossEndpoints(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	task, err := d.CreateTask("dedup rootcause test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain)
VALUES ('service','api.dedup-rc.test','dedup-rc.test') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })

	base := RecordFindingInput{
		TaskID:        task.ID,
		ExplorationID: task.ExplorationID,
		VulnClass:     "认证绕过",
		Severity:      "critical",
		Worker:        "work#1",
		AssetIDs:      []int64{assetID},
		RootCauseKey:  "jwt-alg-none",
	}

	first := base
	first.Name = "JWT alg=none 绕过（/orders）"
	first.Summary = first.Name
	first.Evidence = "GET http://203.0.113.10:8091/orders 接受 alg=none 令牌"
	r1, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, first)
	if err != nil {
		t.Fatal(err)
	}

	second := base
	second.Name = "JWT alg=none 绕过（/profile）"
	second.Summary = second.Name
	second.Evidence = "PATCH http://203.0.113.10:8091/profile 接受 alg=none 令牌"
	r2, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Duplicate || r2.FindingID != r1.FindingID {
		t.Fatalf("显式 root_cause_key 相同应合并到 finding %d，实际 finding=%d duplicate=%v",
			r1.FindingID, r2.FindingID, r2.Duplicate)
	}
}

// 跨任务即使端点相同也不能合并。
func TestRecordFindingCrossTaskSameEndpointDoesNotMerge(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()

	mkTask := func() *Task {
		tk, err := d.CreateTask("cross task dedup", "goal", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.DeleteTask(tk.ID) })
		return tk
	}
	t1, t2 := mkTask(), mkTask()

	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets (type, domain, root_domain)
VALUES ('service','api.dedup-xt.test','dedup-xt.test') RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })

	report := func(tk *Task) *RecordedFinding {
		in := RecordFindingInput{
			TaskID:        tk.ID,
			ExplorationID: tk.ExplorationID,
			VulnClass:     "信息泄露",
			Name:          "调试端点泄露",
			Severity:      "high",
			Summary:       "调试端点泄露",
			Evidence:      "GET http://203.0.113.10:8091/debug 返回数据库凭据",
			Worker:        "work#1",
			AssetIDs:      []int64{assetID},
		}
		r, err := d.Exploration(tk.ExplorationID).RecordFinding(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	r1 := report(t1)
	r2 := report(t2)
	if r2.Duplicate || r1.FindingID == r2.FindingID {
		t.Fatalf("跨任务被合并：finding %d", r1.FindingID)
	}
}
