package vulnintel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTechTokensAndVersionish(t *testing.T) {
	cases := []struct {
		in   string
		want string // joined expectation for readable failure output
	}{
		{"Apache httpd 2.4.49", "apache httpd http_server"},
		{"nginx/1.24", "nginx"},
		{"v12 framework", "framework"}, // leading v + digits stripped
		{"http-server", "http-server http server httpserver http_server"},
		{"Tomcat", "tomcat apache_tomcat"},
	}
	for _, tc := range cases {
		got := techTokens(tc.in)
		if strings.Join(got, " ") != tc.want {
			t.Errorf("techTokens(%q) = %v want [%s]", tc.in, got, tc.want)
		}
	}
	if !isVersionish("1.24.3") || !isVersionish("v12") || isVersionish("httpd") || isVersionish("v") {
		t.Error("isVersionish classification wrong")
	}
	// Real scenario: tech "httpd" must match CPE product "http_server" (bidirectional alias).
	techSet := map[string]bool{}
	for _, tok := range techTokens("Apache httpd 2.4.49") {
		techSet[tok] = true
	}
	cpeSet := map[string]bool{}
	for _, tok := range cpeTokens("http_server") {
		cpeSet[tok] = true
	}
	hit := false
	for tok := range techSet {
		if cpeSet[tok] {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("httpd vs http_server no intersection: tech=%v cpe=%v", techSet, cpeSet)
	}
}

func TestFormatHint(t *testing.T) {
	score := 9.8
	m := []AssetVulnMatch{
		{CVEID: "CVE-2099-0001", Severity: "CRITICAL", Score: &score, KEV: true},
		{CVEID: "CVE-2099-0002", Severity: "HIGH"},
		{CVEID: "CVE-2099-0001", Severity: "CRITICAL", Score: &score, KEV: true}, // dedup'd
	}
	got := FormatHint(m, 42)
	if !strings.Contains(got, "asset(id=42)") || !strings.Contains(got, "2 known vulns") {
		t.Fatalf("missing summary: %s", got)
	}
	if !strings.Contains(got, "CVE-2099-0001(CRITICAL 9.8,KEV exploited in the wild)") {
		t.Fatalf("kev formatting broken: %s", got)
	}
	if !strings.Contains(got, "get_vuln") || !strings.Contains(got, "get_poc") {
		t.Fatalf("missing next-step guidance: %s", got)
	}
	// More than 8 matches: truncated with self-service hint.
	many := []AssetVulnMatch{}
	for i := 0; i < 12; i++ {
		many = append(many, AssetVulnMatch{CVEID: "CVE-2099-" + strings.Repeat("0", i/10) + string(rune('0'+i%10))})
	}
	gotMany := FormatHint(many, 1)
	if !strings.Contains(gotMany, "and 12 more") {
		t.Fatalf("truncation note missing: %s", gotMany)
	}
}

func TestEndToEnd(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const cveID = "CVE-9000-0006"
	const assetID int64 = 901

	// insert two assets with matching fingerprints (service tech "Apache httpd 2.4.49" matches http_server)
	t.Cleanup(func() {
		_, _ = st.db.Exec(`DELETE FROM vuln_cves WHERE cve_id=$1`, cveID)
		_, _ = st.db.Exec(`DELETE FROM vuln_cpe_products WHERE cve_id=$1`, cveID)
		_, _ = st.db.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	})
	if _, err := st.db.Exec(`INSERT INTO assets (type, domain, root_domain, technologies, task_ids)
		VALUES ('service', 'svc.test', 'test.invalid', $1, '{}')`,
		[]string{"Apache httpd 2.4.49"}); err != nil {
		t.Fatal(err)
	}
	var realAsset int64
	if err := st.db.QueryRow(`SELECT id FROM assets WHERE domain='svc.test' AND type='service'`).Scan(&realAsset); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE assets SET technologies=$1 WHERE id=$2`, []string{"Apache httpd 2.4.49"}, realAsset); err != nil {
		t.Fatal(err)
	}

	if err := st.UpsertCVE(ctx, cve(cveID, "apache", "http_server", "2.4.49", 9.8)); err != nil {
		t.Fatal(err)
	}
	// The fixture's modified_at is an old 2024 value; the real hit path requires either KEV or a recent sync —
	// mark KEV to enter the candidate pool (also covers the coexistence path of MarkKEV with NVD upsert).
	if err := st.MarkKEV(ctx, cveID, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Task linking: Matches are generated per (asset × task); assets with no task only go into MatchedAssets.
	task, err := st.db.CreateTask("intel link test", "verify asset-vuln linking", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.db.Exec(`DELETE FROM task_asset_links WHERE task_id=$1`, task.ID) })
	t.Cleanup(func() { _ = st.db.DeleteTask(task.ID) })
	if _, err := st.db.Exec(`INSERT INTO task_asset_links(task_id, asset_id, source, source_summary)
		VALUES ($1,$2,'agent','test fixture')`, task.ID, realAsset); err != nil {
		t.Fatal(err)
	}

	got, err := st.LinkAssetsToVulns(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range got.Matches {
		if m.CVEID == cveID && m.TaskID == task.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected match for %s task=%d, got %+v (scanned=%d matched=%d)", cveID, task.ID, got.Matches, got.ScannedAssets, got.MatchedAssets)
	}
}
