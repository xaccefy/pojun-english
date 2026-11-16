package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

func TestDocxStructure(t *testing.T) {
	d := NewDocx()
	d.H1("Penetration Test Report — Test Task")
	d.P("Generated at:2026-10-18")
	d.H2("X,Overview")
	d.Table([]string{"Asset type", "Count"}, [][]string{{"IP", "770"}, {"Service", "712"}})
	d.Bullet("Key point one")
	d.Code("curl http://target/ -H 'X-Test: 1'")
	d.H3("3.1 Subtitle <special characters> & quotes")
	d.PageBreak()
	d.H2("X,Finding details")
	d.P("X & angle brackets < > paragraph")

	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty docx")
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	want := map[string]bool{
		"[Content_Types].xml":          false,
		"_rels/.rels":                  false,
		"word/document.xml":            false,
		"word/styles.xml":              false,
		"word/_rels/document.xml.rels": false,
	}
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing part: %s", name)
		}
	}

	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		rc.Close()
		doc := b.String()
		for _, frag := range []string{
			"Penetration Test Report — Test Task",
			"&lt;special characters&gt; &amp; quotes",
			"X-Test: 1",
			"<w:tbl>",
			`w:type="page"`,
			"Heading2",
		} {
			if !strings.Contains(doc, frag) {
				t.Errorf("document.xml missing %q", frag)
			}
		}
		if strings.Contains(doc, "<w:t>unclosed") {
			t.Error("escaping broken")
		}
	}
}

func TestBuildTaskDocxAndFindingDocx(t *testing.T) {
	f := &db.DBFinding{
		ID: 42, VulnClass: "Unauthorized Access", Name: "Admin console exposed",
		Severity: "critical", Summary: "console reachable", Evidence: "curl /admin → 200",
		Worker: "work#1", AssetIDs: []int64{5, 2}, CreatedAt: time.Now(),
		Report: "## Reproduction steps\\n1. Open /admin\\n```\\ncurl -i http://x/admin\\n```\\n### Impact\\nfull takeover",
	}
	in := TaskDocxInput{
		Title: "T", Goal: "G", GeneratedAt: time.Now(),
		AssetCounts: map[string]int{"ip": 3},
		Findings:    []*db.DBFinding{f},
		AssetNames:  map[int64]string{5: "10.0.0.5", 2: "admin.example.com"},
		Retests: map[int64][]*db.FindingRetest{
			42: {{FindingID: 42, Verdict: "reproduced", Summary: "PoC reproduced successfully", CreatedAt: time.Now()}},
		},
		Customer:       "Example Client",
		AppendixAssets: map[string][]string{"ip": {"10.0.0.5", "10.0.0.6"}},
	}
	var buf bytes.Buffer
	if err := BuildTaskDocx(in).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty task docx")
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, zf := range zr.File {
		if zf.Name == "word/document.xml" {
			rc, _ := zf.Open()
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			doc = b.String()
		}
	}
	for _, frag := range []string{
		"Affected assets: 10.0.0.5, admin.example.com", // A8 readable names
		"Latest retest: Reproduced",                    // A9 retest section
		"<w:color w:val=\"C00000\"/>",                  // A2 critical heading colouring
	} {
		if !strings.Contains(doc, frag) {
			t.Errorf("document.xml missing %q", frag)
		}
	}
	if strings.Contains(doc, "Affected asset id:") {
		t.Error("legacy Impactasset id: X(A8 not effective)")
	}

	for _, frag := range []string{"Client: Example Client", "Appendix A Asset inventory", "internal classification"} {
		_ = frag
	}
	if !strings.Contains(doc, "Client: Example Client") {
		t.Error("missing cover customer line (A12)")
	}
	if !strings.Contains(doc, "Appendix A Asset inventory") {
		t.Error("missing appendix A (A16)")
	}
	if !strings.Contains(doc, "10.0.0.6") {
		t.Error("appendix asset rows missing")
	}
	buf.Reset()
	if err := BuildFindingDocx(FindingDocxInput{
		Finding:      f,
		GeneratedAt:  time.Now(),
		AssetNameMap: map[int64]string{5: "10.0.0.5"},
	}).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty finding docx")
	}
}

func TestDocxBulletNumbering(t *testing.T) {
	d := NewDocx()
	d.Bullet("Key point one")
	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		rc.Close()
		found[f.Name] = b.String()
	}
	num, ok := found["word/numbering.xml"]
	if !ok {
		t.Fatal("missing word/numbering.xml(bullet willXrender)")
	}
	if !strings.Contains(num, `<w:num w:numId="1">`) {
		t.Error("numbering.xml missing <w:num w:numId=1>")
	}
	rels := found["word/_rels/document.xml.rels"]
	if !strings.Contains(rels, "numbering.xml") {
		t.Error("document.xml.rels missing numbering relationship")
	}

	for name, body := range found {
		if !strings.HasSuffix(name, ".xml") && !strings.HasSuffix(name, ".rels") {
			continue
		}
		if err := xml.Unmarshal([]byte(body), new(any)); err != nil {
			t.Errorf("part %s is not well-formed XML: %v", name, err)
		}
	}
}

func TestWriteMarkdownishRich(t *testing.T) {
	d := NewDocx()
	md := "## Reproduction steps\n- Open **/admin** panel\n\n| Field | Value |\n|---|---|\n| path | /admin |\n| auth | none |\n"
	writeMarkdownish(d, md)
	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			doc = b.String()
		}
	}
	for _, frag := range []string{
		"<w:tbl>",  // table is real OOXML
		"<w:b/>",   // bold run
		"Heading2", // ## -> official-document level-2 KaiTi heading (no longer flattened to H3)
		"w:numId",  // bullet numbering reference
	} {
		if !strings.Contains(doc, frag) {
			t.Errorf("document.xml missing %q", frag)
		}
	}

	if strings.Contains(doc, "---") {
		t.Error("table separator row leaked into document")
	}
}

func TestTaskDocxAggregation(t *testing.T) {
	mk := func(id int64, class, sev string) *db.DBFinding {
		return &db.DBFinding{
			ID: id, VulnClass: class, Name: "MS17-010", Severity: sev,
			Summary: "smb reachable", Evidence: "nmap -p445",
			AssetIDs: []int64{id * 10}, CreatedAt: time.Now(),
		}
	}
	findings := []*db.DBFinding{
		mk(1, "eternal blue", "high"), mk(2, "CVE-2017-0144", "high"), mk(3, "Known Vulnerability", "high"),
		mk(4, "SQLi", "critical"), mk(5, "sql injection", "medium"),
		mk(6, "Unauthorized Access", "low"),
	}
	in := TaskDocxInput{Title: "T", GeneratedAt: time.Now(), Findings: findings}
	var buf bytes.Buffer
	if err := BuildTaskDocx(in).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			doc = b.String()
		}
	}
	if doc == "" {
		t.Fatal("no document.xml")
	}

	for _, frag := range []string{
		"3.1 Known Vulnerability (3 items)", "3.2 Injection (2 items)", "3.3 Unauthorized Access (1 items)",
		"Finding class distribution", "Assets affected",
	} {
		if !strings.Contains(doc, frag) {
			t.Errorf("document.xml missing %q", frag)
		}
	}
}
