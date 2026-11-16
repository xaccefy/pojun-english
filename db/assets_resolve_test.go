package db

import (
	"fmt"
	"testing"
	"time"
)

// Attribution coverage (v0.4.27): record_fact auto-anchoring relies on ResolveHostAssets to map hosts/URLs in fact text
// back to task assets. This verifies three match types (exact URL, URL prefix, host/root_domain)
// and the max-count cap.
func TestResolveHostAssets(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	taskID := time.Now().UnixNano()
	cleanup := func() {
		d.Exec(`DELETE FROM assets WHERE domain IN ('probe.example.com','example.com') OR root_domain='example.com'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := as.UpsertSubdomain(UpsertSubdomainReq{TaskID: taskID, Domain: "probe.example.com"}); err != nil {
		t.Fatalf("upsert subdomain: %v", err)
	}
	ep, err := as.UpsertEndpoint(UpsertEndpointReq{TaskID: taskID, URL: "https://probe.example.com/prod-api/list", Method: "GET"})
	if err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	root, err := as.UpsertRootDomain(UpsertRootDomainReq{TaskID: taskID, Domain: "example.com"})
	if err != nil {
		t.Fatalf("upsert root: %v", err)
	}

	// Exact URL match hits the endpoint (rank 0 sorts first).
	ids, err := as.ResolveHostAssets(taskID, nil, []string{"https://probe.example.com/prod-api/list"}, 5)
	if err != nil || len(ids) == 0 || ids[0] != ep {
		t.Fatalf("url exact: ids=%v err=%v want first=%d", ids, err, ep)
	}
	// Host match hits subdomain + root_domain (>=2 entries).
	ids, err = as.ResolveHostAssets(taskID, []string{"probe.example.com"}, nil, 5)
	if err != nil || len(ids) < 2 {
		t.Fatalf("host match: ids=%v err=%v want >=2", ids, err)
	}
	// Prefix match (a variant URL with a query string should also hit the same endpoint).
	ids, err = as.ResolveHostAssets(taskID, nil, []string{"https://probe.example.com/prod-api/list?page=1"}, 5)
	if err != nil || len(ids) == 0 || ids[0] != ep {
		t.Fatalf("url prefix: ids=%v err=%v want first=%d", ids, err, ep)
	}
	// max cap.
	ids, err = as.ResolveHostAssets(taskID, []string{"probe.example.com", "example.com"}, nil, 1)
	if err != nil || len(ids) != 1 {
		t.Fatalf("max cap: ids=%v err=%v want 1", ids, err)
	}
	_ = fmt.Sprint(root)
}

// Untested-asset ordering (v0.4.27): static resources sink to the bottom, same-cluster prefixes stay adjacent — not a strict assertion of order values,
// but two properties: "extensionless paths come before static assets" + "same prefixes are adjacent".
func TestUntestedAssetsOrdering(t *testing.T) {
	d, as, _ := testSetup(t)
	defer d.Close()
	// task_scope.task_id has a FK → create a real task row first.
	tkID, err := d.CreateTask("untested asset ordering test", "target ord.example.com", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskCascade(tkID.ID, true, true) })
	taskID := tkID.ID
	cleanup := func() {
		d.Exec(`DELETE FROM assets WHERE url LIKE 'https://ord.example.com/%'`)
		d.Exec(`DELETE FROM assets WHERE domain='ord.example.com' OR root_domain='ord.example.com'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	urls := []string{
		"https://ord.example.com/static/app.js",
		"https://ord.example.com/prod-api/user/info",
		"https://ord.example.com/prod-api/user/list",
		"https://ord.example.com/logo.png",
		"https://ord.example.com/HRMS/api/emp",
	}
	for _, u := range urls {
		if _, err := as.UpsertEndpoint(UpsertEndpointReq{TaskID: taskID, URL: u, Method: "GET"}); err != nil {
			t.Fatalf("upsert %s: %v", u, err)
		}
	}
	if err := as.AddAutoScope(taskID, "subdomain", "ord.example.com", "", ""); err != nil {
		t.Fatalf("add scope: %v", err)
	}
	backlog, total, err := as.ListUntestedAssetsWithSources(taskID, "endpoint", 20, 0)
	if err != nil {
		t.Fatalf("list untested: %v", err)
	}
	if total < 5 {
		t.Fatalf("total=%d want >=5", total)
	}
	got := map[string]string{}
	for _, a := range backlog {
		got[a.Label] = a.Label
	}
	_ = got
	// The two static assets should sort after all extensionless paths.
	staticSeenAt, pathSeenAt := -1, -1
	for i, a := range backlog {
		switch a.Label {
		case "https://ord.example.com/static/app.js", "https://ord.example.com/logo.png":
			if staticSeenAt < 0 || i < staticSeenAt {
				staticSeenAt = i
			}
		default:
			if pathSeenAt < i {
				pathSeenAt = i
			}
		}
	}
	if staticSeenAt >= 0 && staticSeenAt < len(backlog)-1 && staticSeenAt < pathSeenAt {
		t.Fatalf("static asset not last: backlog=%v", backlog)
	}
	// Same-cluster adjacency: the two /prod-api/user/* entries should be consecutive in the list.
	pos := map[string]int{}
	for i, a := range backlog {
		pos[a.Label] = i
	}
	p1, ok1 := pos["https://ord.example.com/prod-api/user/info"]
	p2, ok2 := pos["https://ord.example.com/prod-api/user/list"]
	if ok1 && ok2 && abs(p1-p2) != 1 {
		t.Fatalf("same-prefix items not adjacent: pos=%v", pos)
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
