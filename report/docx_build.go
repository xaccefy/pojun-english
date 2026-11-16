package report

// docx assembly for report export: the task-wide report plus the single-finding report.
// The data comes from the findings table (ListFindingsForExport/GetFinding, including the
// report body and evidence); this file only handles layout. The two built-in layouts are
// BuildTaskDocx / BuildFindingDocx.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
)

// TaskDocxInput is the input of the task-wide report.
type TaskDocxInput struct {
	TaskID      int64
	Title       string
	Goal        string
	GeneratedAt time.Time
	AssetCounts map[string]int
	Findings    []*db.DBFinding
	// Goals holds each task objective and whether it was met (red-team edition v0.6.31);
	// nil = the report omits "Objective attainment".
	Goals []GoalLine
	// AssetNames maps asset id → readable name (domain/IP/URL). nil/missing entries fall back
	// to "id:N" (A8).
	AssetNames map[int64]string
	// Retests maps finding id → retest records (newest first). The report carries a "Retest
	// records" section (A9).
	Retests map[int64][]*db.FindingRetest
	// Customer is the commissioning party (company names, comma separated; empty = the cover
	// omits that line). A12
	Customer string
	// TestWindow describes the testing window (e.g. "2026-10-29 ~ 2026-10-31"; empty = only the
	// generation time is shown). A12
	TestWindow string
	// AppendixAssets is the appendix asset inventory: type → readable name list (A16; nil = no
	// appendix).
	AppendixAssets map[string][]string
	// Classification is the classification/usage placeholder (empty = the default "Internal ·
	// authorized parties only"). A12
	Classification string
	// PageHeader is the header text (empty = "Penetration Test Report").
	PageHeader string
	// ArtifactImage is the evidence attachment image resolver (v0.5.0): ![caption](artifact:<id>)
	// in Markdown is embedded as an image; nil = degrade to a text description.
	ArtifactImage func(id int64) (data []byte, caption string, ok bool)
}

func sevRankKey(f *db.DBFinding) int {
	switch strings.ToLower(f.Severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// BuildTaskDocx renders the task-wide report:
// cover page (centered title/client/classification/date) → table-of-contents page (TOC
// field) → 1. Assessment overview → 2. Scope and methodology → 3. Finding details (grouped
// by class, colored, with retests and traffic evidence) → 4. Remediation priority roadmap →
// Appendix A asset inventory.
// The same vulnerability reported against many hosts is folded at the class level.
func BuildTaskDocx(in TaskDocxInput) *Docx {
	d := NewDocx()
	embedGongwenFonts(d) // the official-document fonts are embedded with the document (GB/T 9704 end to end)
	d.SetArtifactImageResolver(in.ArtifactImage)
	if in.PageHeader != "" {
		d.SetHeaderText(in.PageHeader)
	}

	// ── Cover page (A3): centered large title + metadata, replacing the old first-line H1 ──
	for i := 0; i < 6; i++ {
		d.CoverLine("", 0, false) // vertical padding
	}
	d.CoverLine(in.Title, 52, true)
	d.CoverLine("", 0, false)
	if in.Customer != "" {
		d.CoverLine("Client: "+in.Customer, 28, false)
	}
	classification := in.Classification
	if classification == "" {
		classification = "Internal · authorized parties only"
	}
	d.CoverLine(classification, 24, false)
	d.CoverLine("", 0, false)
	d.CoverLine("Report generated at: "+FormatTimeUTC(in.GeneratedAt), 24, false)
	d.CoverLine(fmt.Sprintf("Total findings: %d (critical %d / high %d / medium %d / low %d)",
		len(in.Findings), countSev(in.Findings, "critical"), countSev(in.Findings, "high"),
		countSev(in.Findings, "medium"), countSev(in.Findings, "low")), 24, false)
	d.PageBreak()

	// ── Table-of-contents page (A4): TOC field, refreshed automatically by settings.xml
	// updateFields when opened ──
	d.TOC()
	d.PageBreak()

	// ── 1. Assessment overview ──
	d.H1("1. Assessment overview")
	if len(in.AssetCounts) > 0 {
		types := make([]string, 0, len(in.AssetCounts))
		for k := range in.AssetCounts {
			types = append(types, k)
		}
		sort.Strings(types)
		rows := make([][]string, 0, len(types))
		total := 0
		for _, ty := range types {
			rows = append(rows, []string{assetTypeCN(ty), fmt.Sprint(in.AssetCounts[ty])})
			total += in.AssetCounts[ty]
		}
		d.Table([]string{"Asset type", "Count"}, rows)
		d.P(fmt.Sprintf("Total assets: %d", total))
	}
	// Severity distribution table (row fill follows the severity, A2)
	d.H2("Finding severity distribution")
	rows := make([][]string, 0, 4)
	fills := make([]string, 0, 4)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		n := countSev(in.Findings, sev)
		if n > 0 {
			rows = append(rows, []string{SeverityCN(sev), fmt.Sprint(n)})
			fills = append(fills, SeverityHexSoft(sev))
		}
	}
	d.TableFills([]string{"Severity", "Count"}, rows, fills)

	// Finding class distribution (the same class reported against many hosts is folded into one
	// row here — "EternalBlue × 16 hosts" is a single number in the overview, no need to page
	// through 16 pages of detail)
	if groups := groupByClass(in.Findings); len(groups) > 0 {
		d.H2("Finding class distribution")
		rows := make([][]string, 0, len(groups))
		for _, g := range groups {
			rows = append(rows, []string{g.class, fmt.Sprint(len(g.items)), fmt.Sprint(len(g.assets))})
		}
		d.Table([]string{"Finding class", "Count", "Assets affected"}, rows)
	}
	d.PageBreak()

	// ── 2. Scope and methodology (A14: the data is all there, just assemble the chapter) ──
	d.H1("2. Scope and methodology")
	if in.Goal != "" {
		d.H2("Task objectives")
		d.P(in.Goal)
	}
	// Objective attainment (red-team edition v0.6.31): list whether each objective was proven,
	// and flag it explicitly when not all were met.
	if len(in.Goals) > 0 {
		met, total := GoalTally(in.Goals)
		d.H2("Objective attainment")
		if met < total {
			d.P(fmt.Sprintf("%d task objectives in total, %d proven met; objectives not met are recorded as they are, and this task is archived as incomplete.", total, met))
		} else {
			d.P(fmt.Sprintf("%d task objectives in total, all proven met by reproducible evidence.", total))
		}
		rows := make([][]string, 0, len(in.Goals))
		for _, g := range in.Goals {
			state := "not met"
			if g.Met() {
				state = "met"
			}
			rows = append(rows, []string{g.Text, state, nz(g.Criteria, "—")})
		}
		d.Table([]string{"Objective", "State", "Acceptance criteria"}, rows)
	}
	d.H2("Testing window")
	if in.TestWindow != "" {
		d.P("Testing window: " + in.TestWindow)
	}
	d.P("Report generated at: " + FormatTimeUTC(in.GeneratedAt))
	if len(in.AssetCounts) > 0 {
		d.H2("Testing scope")
		d.P("This test covered the following asset types (see Appendix A for details):")
		types := make([]string, 0, len(in.AssetCounts))
		for k := range in.AssetCounts {
			types = append(types, k)
		}
		sort.Strings(types)
		parts := make([]string, 0, len(types))
		for _, ty := range types {
			parts = append(parts, fmt.Sprintf("%s ×%d", assetTypeCN(ty), in.AssetCounts[ty]))
		}
		d.Bullet(strings.Join(parts, "; "))
	}
	d.H2("Methodology")
	d.P("This assessment was performed by POJUN, an autonomous multi-agent penetration testing " +
		"platform: the planning agent dispatched testing intents based on the objectives and asset " +
		"situation, the execution agents used real tools (nmap/httpx/nuclei/ffuf/sqlmap, etc.) to " +
		"complete reconnaissance, vulnerability verification and exploitation, and all traffic was " +
		"recorded through the recording proxy; every finding conclusion requires reproducible " +
		"evidence (PoC commands / request-response) and critical/high findings are recommended for " +
		"independent re-verification per the retest records.")
	d.P("Severity is rated against CVSS v3.1 and manually calibrated with business impact; see chapter 4 for remediation priority advice.")
	d.PageBreak()

	// ── 3. Finding details: grouped and folded by class (severity descending inside a class),
	// classes by count descending ──
	d.H1("3. Finding details")
	groups := groupByClass(in.Findings)
	for gi, g := range groups {
		d.H2(fmt.Sprintf("3.%d %s (%d items)", gi+1, g.class, len(g.items)))
		for fi, f := range g.items {
			// Severity coloring (A2): the heading color follows the level for instant triage
			if hex := SeverityHex(f.Severity); hex != "" {
				d.headingColored(fmt.Sprintf("3.%d.%d [%s] %s", gi+1, fi+1, SeverityCN(f.Severity), findingTitle(f)), 3, hex)
			} else {
				d.H3(fmt.Sprintf("3.%d.%d [%s] %s", gi+1, fi+1, SeverityCN(f.Severity), findingTitle(f)))
			}
			d.P(fmt.Sprintf("Finding class: %s", nz(f.VulnClass, "unclassified")))
			if len(f.AssetIDs) > 0 {
				d.P(fmt.Sprintf("Affected assets: %s", assetNames(f.AssetIDs, in.AssetNames)))
			}
			d.P(fmt.Sprintf("Found at: %s · Found by: %s", FormatTimeUTC(f.CreatedAt), nz(f.Worker, "-")))
			if strings.TrimSpace(f.Summary) != "" {
				d.H4("Summary")
				d.P(f.Summary)
			}
			if body := strings.TrimSpace(f.Report); body != "" {
				d.H4("Detailed report")
				writeMarkdownish(d, body)
			}
			if ev := strings.TrimSpace(f.Evidence); ev != "" {
				d.H4("Evidence / PoC")
				d.Code(ev)
			}
			writeTrafficEvidenceDocx(d, f)
			writeRetestDocx(d, f, in.Retests)
			d.P("")
		}
	}
	d.PageBreak()

	// ── 4. Remediation priority roadmap (A15: immediate/planned/opportunistic tiers) ──
	d.H1("4. Remediation priority roadmap")
	writeRemediationRoadmap(d, in.Findings)

	// ── Appendix A: asset inventory (A16) ──
	if len(in.AppendixAssets) > 0 {
		d.PageBreak()
		d.H1("Appendix A Asset inventory")
		types := make([]string, 0, len(in.AppendixAssets))
		for k := range in.AppendixAssets {
			types = append(types, k)
		}
		sort.Strings(types)
		const appendixCap = 200 // list at most 200 per type; beyond that, point at the platform
		for _, ty := range types {
			names := in.AppendixAssets[ty]
			if len(names) == 0 {
				continue
			}
			d.H2(assetTypeCN(ty) + fmt.Sprintf(" (%d)", len(names)))
			shown := names
			if len(shown) > appendixCap {
				shown = shown[:appendixCap]
			}
			rows := make([][]string, 0, len(shown))
			for i, n := range shown {
				rows = append(rows, []string{fmt.Sprint(i + 1), n})
			}
			d.Table([]string{"#", "Asset"}, rows)
			if len(names) > appendixCap {
				d.P(fmt.Sprintf("(%d more omitted; see the platform's Assets page for the full list.)", len(names)-appendixCap))
			}
		}
	}
	return d
}

// writeRemediationRoadmap is the three-tier remediation priority table (A15).
// v1 takes the "list + general guidance" form — each finding's specific remediation advice is
// already in the "Remediation advice" section of its detailed report; what this solves is the
// ordering question of "which to fix first".
func writeRemediationRoadmap(d *Docx, fs []*db.DBFinding) {
	tiers := []struct {
		title  string
		sevs   []string
		advice string
	}{
		{"Immediate remediation (within 7 days)", []string{"critical", "high"},
			"At risk of direct exploitation or data leakage; schedule a fix immediately and apply temporary mitigation (WAF rules / take offline / tighten access control).",
		},
		{"Near-term plan (within 30 days)", []string{"medium"},
			"Needs specific conditions to exploit or has limited impact; fold into the regular release cycle and verify with a retest after fixing.",
		},
		{"Opportunistic", []string{"low", "info"},
			"Low risk or a hardening suggestion; handle with normal release iterations, and configuration items can be adjusted right away.",
		},
	}
	for _, tier := range tiers {
		var items []*db.DBFinding
		for _, f := range fs {
			for _, s := range tier.sevs {
				if strings.EqualFold(f.Severity, s) {
					items = append(items, f)
					break
				}
			}
		}
		d.H2(tier.title)
		if len(items) == 0 {
			d.P("Nothing in this tier.")
			continue
		}
		d.P(tier.advice)
		sort.SliceStable(items, func(i, j int) bool { return sevRankKey(items[i]) < sevRankKey(items[j]) })
		rows := make([][]string, 0, len(items))
		for i, f := range items {
			rows = append(rows, []string{fmt.Sprint(i + 1), findingTitle(f), SeverityCN(f.Severity), statusCN(f.Status)})
		}
		d.TableFills([]string{"#", "Finding", "Severity", "Current status"}, rows, nil)
	}
}

// statusCN is the display label of a triage status (used in the roadmap table).
func statusCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pending":
		return "Pending"
	case "in_progress":
		return "In progress"
	case "confirmed":
		return "Confirmed"
	case "resolved":
		return "Resolved"
	case "fixed":
		return "Fixed"
	case "false_positive":
		return "False positive"
	case "ignored":
		return "Ignored"
	case "duplicate":
		return "Duplicate"
	case "risk_accepted":
		return "Risk accepted"
	default:
		return nz(s, "-")
	}
}

// assetNames maps an asset id list to readable names (A8). Missing mappings fall back to
// "id:N".
func assetNames(ids []int64, names map[int64]string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := names[id]; ok && strings.TrimSpace(n) != "" {
			parts = append(parts, n)
			continue
		}
		parts = append(parts, fmt.Sprintf("id:%d", id))
	}
	return strings.Join(parts, ", ")
}

// retestVerdictCN is the display label of a retest verdict (A9).
func retestVerdictCN(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "reproduced":
		return "Reproduced"
	case "fixed":
		return "Fixed"
	case "inconclusive":
		return "Inconclusive"
	default:
		return nz(v, "-")
	}
}

// writeRetestDocx renders the retest records section (A9): the latest verdict first, with a
// note on the number of earlier ones.
func writeRetestDocx(d *Docx, f *db.DBFinding, retests map[int64][]*db.FindingRetest) {
	rs := retests[f.ID]
	if len(rs) == 0 {
		return
	}
	latest := rs[0]
	d.H4("Retest records")
	line := fmt.Sprintf("Latest retest: %s · %s", retestVerdictCN(latest.Verdict), FormatTimeUTC(latest.CreatedAt))
	if s := strings.TrimSpace(latest.Summary); s != "" {
		line += " · " + s
	}
	d.P(line)
	if len(rs) > 1 {
		d.P(fmt.Sprintf("%d earlier retests (see the whole history under Findings → Retests in the platform).", len(rs)))
	}
}

// trafficRoleCN is the display label of a traffic evidence role (A10).
func trafficRoleCN(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "baseline":
		return "Baseline"
	case "proof":
		return "Proof of vulnerability"
	case "verification":
		return "Supporting verification"
	case "supporting":
		return "Corroborating evidence"
	default:
		return nz(role, "-")
	}
}

// writeTrafficEvidenceDocx renders the traffic evidence section (A10): the md export
// (report/findings.go) already has this logic, and it is presented isomorphically on the Word
// side — binding metadata plus request/response header code blocks. Message bodies are bulky
// and may be binary, so the deliverable keeps the headers and snapshot metadata (bodies go
// through the attachment files of the md export).
func writeTrafficEvidenceDocx(d *Docx, f *db.DBFinding) {
	if len(f.TrafficBindings) == 0 {
		return
	}
	stale := f.Report != "" && f.EvidenceVersion != f.ReportEvidenceVersion
	d.H4("Linked traffic evidence")
	d.P(fmt.Sprintf("Evidence version: %d · %d bindings", f.EvidenceVersion, len(f.TrafficBindings)))
	if stale {
		d.P("⚠ The evidence has changed; the detailed report is pending an update.")
	}
	for i, b := range f.TrafficBindings {
		d.P(fmt.Sprintf("%d. evidence #%d · %s — %s %s · status %d",
			i+1, b.ID, trafficRoleCN(b.Role), nz(b.Snapshot.Method, "GET"), b.Snapshot.URL, b.Snapshot.Status))
		if n := strings.TrimSpace(b.Note); n != "" {
			d.PRich("   Note: " + n)
		}
		if h := strings.TrimSpace(b.Snapshot.ReqHead); h != "" {
			d.P("Request headers:")
			d.Code(h)
		}
		if h := strings.TrimSpace(b.Snapshot.RespHead); h != "" {
			d.P("Response headers:")
			d.Code(h)
		}
	}
}

// classGroup aggregates findings of the same vulnerability class (with a deduplicated asset
// set).
// Normalization uses db.NormalizeVulnClass: new records are already normalized at the write
// layer, and historical variants (SQLi vs injection) are folded on the read side too, so the
// task-wide report does not show a gap because of old data.
type classGroup struct {
	class  string
	items  []*db.DBFinding
	assets map[int64]struct{}
}

func groupByClass(fs []*db.DBFinding) []classGroup {
	idx := map[string]*classGroup{}
	var order []string
	for _, f := range fs {
		c := db.NormalizeVulnClass(f.VulnClass)
		if c == "" {
			c = "unclassified"
		}
		g, ok := idx[c]
		if !ok {
			g = &classGroup{class: c, assets: map[int64]struct{}{}}
			idx[c] = g
			order = append(order, c)
		}
		g.items = append(g.items, f)
		for _, a := range f.AssetIDs {
			g.assets[a] = struct{}{}
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		gi, gj := idx[order[i]], idx[order[j]]
		// count descending; equal counts ordered by class name for stability
		if len(gi.items) != len(gj.items) {
			return len(gi.items) > len(gj.items)
		}
		return gi.class < gj.class
	})
	out := make([]classGroup, 0, len(order))
	for _, c := range order {
		g := idx[c]
		sort.SliceStable(g.items, func(i, j int) bool { return sevRankKey(g.items[i]) < sevRankKey(g.items[j]) })
		out = append(out, *g)
	}
	return out
}

// FindingDocxInput is the input of the single-finding report (v0.4.0: cover page/header on
// par with the task-wide report).
type FindingDocxInput struct {
	Finding *db.DBFinding
	// ArtifactImage is the evidence attachment image resolver (v0.5.0, see
	// TaskDocxInput.ArtifactImage).
	ArtifactImage  func(id int64) (data []byte, caption string, ok bool)
	GeneratedAt    time.Time
	AssetNameMap   map[int64]string
	Retests        []*db.FindingRetest
	Customer       string // commissioning party (empty = omit that line)
	Classification string // classification placeholder (empty = the default "Internal · authorized parties only")
}

// BuildFindingDocx renders the single-finding report (a self-contained document with
// reproduction steps/evidence/remediation advice).
// v0.4.0: adds a real cover page (centered title/client/classification/date) plus a header
// (the finding name) — the same delivery standard as the task-wide report; the
// request/response/retest sections in the body keep the v0.3.93 rendering.
func BuildFindingDocx(in FindingDocxInput) *Docx {
	f := in.Finding
	generatedAt := in.GeneratedAt
	d := NewDocx()
	embedGongwenFonts(d) // the official-document fonts are embedded with the document (GB/T 9704 end to end)
	d.SetArtifactImageResolver(in.ArtifactImage)
	d.SetHeaderText("Penetration Test Report — " + findingTitle(f))

	// Cover page (same layout as the task-wide report)
	for i := 0; i < 6; i++ {
		d.CoverLine("", 0, false)
	}
	if hex := SeverityHex(f.Severity); hex != "" {
		d.CoverLineColored(fmt.Sprintf("[%s] %s", SeverityCN(f.Severity), findingTitle(f)), 44, hex, true)
	} else {
		d.CoverLine(fmt.Sprintf("[%s] %s", SeverityCN(f.Severity), findingTitle(f)), 44, true)
	}
	d.CoverLine("", 0, false)
	if in.Customer != "" {
		d.CoverLine("Client: "+in.Customer, 28, false)
	}
	classification := in.Classification
	if classification == "" {
		classification = "Internal · authorized parties only"
	}
	d.CoverLine(classification, 24, false)
	d.CoverLine("", 0, false)
	d.CoverLine("Report generated at: "+FormatTimeUTC(generatedAt), 24, false)
	d.PageBreak()

	// Table-of-contents page (same as the task-wide report: TOC field, refreshed automatically
	// by settings updateFields when opened)
	d.TOC()
	d.PageBreak()

	d.P(fmt.Sprintf("Finding class: %s · Severity: %s · Status: %s", nz(f.VulnClass, "unclassified"), SeverityCN(f.Severity), statusCN(f.Status)))
	if len(f.AssetIDs) > 0 {
		d.P(fmt.Sprintf("Affected assets: %s", assetNames(f.AssetIDs, in.AssetNameMap)))
	}
	d.P(fmt.Sprintf("Found at: %s · Found by: %s", FormatTimeUTC(f.CreatedAt), nz(f.Worker, "-")))
	if s := strings.TrimSpace(f.Summary); s != "" {
		d.Hei1("1. Finding overview")
		d.P(s)
	}
	if body := strings.TrimSpace(f.Report); body != "" {
		d.Hei1("2. Detailed report")
		writeMarkdownish(d, body)
	}
	if ev := strings.TrimSpace(f.Evidence); ev != "" {
		d.Hei1("3. Evidence / PoC")
		d.Code(ev)
	}
	// 4. Traffic evidence / 5. Retest records — same source as the task-wide report (A9/A10)
	writeTrafficEvidenceDocx(d, f)
	if len(in.Retests) > 0 {
		d.Hei1("Retest records")
		latest := in.Retests[0]
		line := fmt.Sprintf("Latest retest: %s · %s", retestVerdictCN(latest.Verdict), FormatTimeUTC(latest.CreatedAt))
		if s := strings.TrimSpace(latest.Summary); s != "" {
			line += " · " + s
		}
		d.P(line)
		if len(in.Retests) > 1 {
			d.P(fmt.Sprintf("%d earlier retests.", len(in.Retests)))
		}
	} else {
		// Not-retested marker (v0.4.27): a finding that is pending with no retest record is
		// marked explicitly as "awaiting manual review" in the report, so readers do not take the
		// model's conclusion as verified fact.
		if strings.EqualFold(f.Status, "pending") {
			d.P("Retest records: not retested (awaiting manual review)")
		}
	}
	return d
}

// writeMarkdownish lays out finding.report's Markdown in Word (A5 rich rendering):
//   - '# '/'## '/'### ' → H3/H4/H4 (the finding title is already H3, so body subsections are no
//     longer flattened)
//   - '- '/'* ' → bullets (actually rendered now that numbering.xml is fixed)
//   - '```' fences → code blocks
//   - '| |' table blocks → real OOXML tables (the second separator row is dropped automatically)
//   - '**bold**' → rich-text runs (supported in both paragraphs and list items)
//
// Everything else is a paragraph. Full Markdown fidelity is not the goal — the report body is
// model output, so covering the common subset is enough.
func writeMarkdownish(d *Docx, md string) {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	inCode := false
	// Table block collection: consecutive lines starting with |
	var tableBuf []string
	flushTable := func() {
		if len(tableBuf) == 0 {
			return
		}
		rows := make([][]string, 0, len(tableBuf))
		for _, ln := range tableBuf {
			cells := splitMarkdownRow(ln)
			if isTableSeparator(cells) {
				continue // |---|---| separator row
			}
			rows = append(rows, cells)
		}
		if len(rows) > 0 {
			header := rows[0]
			body := rows[1:]
			if len(body) == 0 {
				// A degenerate table with only a header row is printed as an ordinary paragraph
				d.P(strings.Join(header, " | "))
			} else {
				d.Table(header, body)
			}
		}
		tableBuf = tableBuf[:0]
	}
	// Fenced code block collection: the whole block becomes one Code paragraph (w:br between
	// lines) — one paragraph per line splits a long JSON/curl into dozens of separate
	// paragraphs piled together (v0.4.1).
	var codeBuf []string
	flushCode := func() {
		if len(codeBuf) > 0 {
			d.Code(strings.Join(codeBuf, "\n"))
			codeBuf = codeBuf[:0]
		}
	}
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "```") {
			flushTable()
			flushCode()
			inCode = !inCode
			continue
		}
		if inCode {
			codeBuf = append(codeBuf, ln)
			continue
		}
		if strings.HasPrefix(trimmed, "|") && strings.HasSuffix(trimmed, "|") {
			tableBuf = append(tableBuf, trimmed)
			continue
		}
		flushTable()
		// Evidence attachment image: ![caption](artifact:<id>) → embedded screenshot + caption
		// (v0.5.0).
		if artRe.MatchString(trimmed) {
			m := artRe.FindStringSubmatch(trimmed)
			alt, rawID := strings.TrimSpace(m[1]), m[2]
			id, _ := strconv.ParseInt(rawID, 10, 64)
			inserted := false
			if id > 0 && d.artifactImage != nil {
				if data, caption, ok := d.artifactImage(id); ok {
					if caption == "" {
						caption = alt
					}
					inserted = d.Image(data, caption)
				}
			}
			if !inserted {
				// Attachment missing/not an image/unsupported environment: degrade to a one-line
				// note without aborting the report.
				d.P("(evidence image: " + alt + "; attachment missing or not embeddable)")
			}
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "### "):
			d.H4(strings.TrimPrefix(trimmed, "### "))
		case strings.HasPrefix(trimmed, "## "):
			// Official-document level-2 heading: KaiTi size 3 (v0.4.3, aligned with the reference)
			d.Kai2(strings.TrimPrefix(trimmed, "## "))
		case strings.HasPrefix(trimmed, "# "):
			// Official-document level-1 heading: SimHei size 3 (v0.4.3, aligned with the reference)
			d.Hei1(strings.TrimPrefix(trimmed, "# "))
		case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* "):
			// Nested lists: every 2 leading spaces is one level (the reporter often writes
			// two-level lists); ilvl is left to numbering.xml's multi-level definition, since
			// flattening would lose the hierarchy entirely (v0.4.0).
			indent := len(ln) - len(strings.TrimLeft(ln, " 	"))
			lvl := indent / 2
			if lvl > 2 {
				lvl = 2
			}
			fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:numPr><w:ilvl w:val="%d"/><w:numId w:val="1"/></w:numPr><w:ind w:firstLine="0" w:left="%d"/><w:jc w:val="both"/></w:pPr>`, lvl, 720+lvl*360)
			d.buf.WriteString(runsXML(parseRich(strings.TrimPrefix(strings.TrimPrefix(trimmed, "- "), "* "))))
			d.buf.WriteString(`</w:p>`)
		case trimmed == "":
			// Blank line between paragraphs; spacing already comes from the style, so skip it
		default:
			// Official-document numbered-heading detection (v0.4.3, aligned with the reference):
			// reporter bodies often contain Chinese-style numbered headings ("<numeral>, <title>",
			// SimHei level 1) and ("(<numeral>)<title>.", KaiTi level 2); short lines are laid out as headings while long lines stay body text
			// (so paragraphs with content are not affected).
			if gongwenHeiRe.MatchString(trimmed) && len([]rune(trimmed)) <= 40 {
				d.Hei1(trimmed)
				continue
			}
			if gongwenKaiRe.MatchString(trimmed) && len([]rune(trimmed)) <= 30 {
				d.Kai2(trimmed)
				continue
			}
			d.PRich(trimmed)
		}
	}
	flushTable()
	flushCode()
}

// Official-document numbered-heading detection: lines starting with a Chinese numeral followed by ", "
// (SimHei level 1) or wrapped in "()" (KaiTi level 2).
// It only applies to a [whole-line phrase] — paragraphs carrying body content are left alone.
// Numbered-heading detection matches English ordinal words in parentheses or followed by a separator.
var (
	gongwenHeiRe = regexp.MustCompile(`^(?:one|two|three|four|five|six|seven|eight|nine|ten)[.)]\s`)
	gongwenKaiRe = regexp.MustCompile(`^\((?:one|two|three|four|five|six|seven|eight|nine|ten)\)`)
	// artRe matches an evidence image reference in the report: ![caption](artifact:12)
	artRe = regexp.MustCompile(`^!\[(.*?)\]\(artifact:(\d+)\)$`)
)

// splitMarkdownRow splits a line | a | b | → [a, b].
func splitMarkdownRow(ln string) []string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ln), "|"), "|")
	parts := strings.Split(trimmed, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// isTableSeparator recognizes a |---|:---:| separator row.
func isTableSeparator(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		t := strings.TrimSpace(c)
		if t == "" {
			return false
		}
		for _, r := range t {
			if r != '-' && r != ':' && r != ' ' {
				return false
			}
		}
	}
	return true
}

func countSev(fs []*db.DBFinding, sev string) int {
	n := 0
	for _, f := range fs {
		if strings.EqualFold(f.Severity, sev) {
			n++
		}
	}
	return n
}

// assetTypeCN is the display label of an asset type (used in the overview table).
func assetTypeCN(ty string) string {
	switch ty {
	case "root_domain":
		return "Root domain"
	case "subdomain":
		return "Subdomain"
	case "ip":
		return "IP"
	case "service":
		return "Service"
	case "endpoint":
		return "Endpoint"
	case "app":
		return "Application"
	default:
		return ty
	}
}
