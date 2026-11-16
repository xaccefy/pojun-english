// Report export API: whole-task report (docx/md) and single-finding report (docx).
// Content comes from the findings table (report body/evidence); docx is rendered by
// the report package's built-in template.
// Since v0.3.93: deliverables exclude false-positive/duplicate/ignored/risk-accepted
// by default (A7); readable asset names (A8), retest records (A9), and traffic
// evidence (A10) are wired into Word too.
package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/report"
)

// exportExcludeStatuses are the triage statuses excluded from deliverables by
// default. false_positive/duplicate/ignored/risk_accepted are 'must not appear before
// the customer' states; pending/in_progress/confirmed/resolved/fixed ship normally.
var exportExcludeStatuses = []string{
	db.FindingFalsePositive, db.FindingDuplicate, db.FindingIgnored, db.FindingRiskAccepted,
}

// reportAssetNames batch-resolves asset ids to readable names (domain/IP/URL, A8).
func (s *Server) reportAssetNames(findings []*db.DBFinding) map[int64]string {
	seen := map[int64]bool{}
	var ids []int64
	for _, f := range findings {
		for _, a := range f.AssetIDs {
			if a > 0 && !seen[a] {
				seen[a] = true
				ids = append(ids, a)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	list, err := s.m.pg.Assets().GetByIDs(ids)
	if err != nil {
		return nil
	}
	out := make(map[int64]string, len(list))
	for _, a := range list {
		out[a.ID] = assetDisplayName(a)
	}
	return out
}

// assetDisplayName picks the most identifying field per asset type as the readable
// name.
func assetDisplayName(a *db.Asset) string {
	switch a.Type {
	case "endpoint", "app", "service":
		if a.URL != "" {
			return a.URL
		}
		if a.Domain != "" && a.Port != nil {
			return fmt.Sprintf("%s:%d", a.Domain, *a.Port)
		}
		if a.IP != "" && a.Port != nil {
			return fmt.Sprintf("%s:%d", a.IP, *a.Port)
		}
	case "subdomain", "root_domain":
		if a.Domain != "" {
			return a.Domain
		}
	case "ip":
		if a.IP != "" {
			return a.IP
		}
	}
	// fallback: try each type's populated fields in order
	if a.URL != "" {
		return a.URL
	}
	if a.Domain != "" {
		return a.Domain
	}
	if a.IP != "" {
		return a.IP
	}
	if a.RootDomain != "" {
		return a.RootDomain
	}
	return ""
}

// reportRetests batch-fetches each finding's retest records (A9; newest first —
// ListFindingRetests already orders id DESC).
func (s *Server) reportRetests(findings []*db.DBFinding) map[int64][]*db.FindingRetest {
	out := make(map[int64][]*db.FindingRetest)
	for _, f := range findings {
		rs, err := s.m.pg.ListFindingRetests(f.ID)
		if err != nil || len(rs) == 0 {
			continue
		}
		out[f.ID] = rs
	}
	return out
}

// exportTaskDocx exports the whole-task report (Word).
func (s *Server) exportTaskDocx(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	findings, err := s.m.pg.ListFindingsForExport(db.FindingFilter{TaskID: t.ID, ExcludeStatuses: exportExcludeStatuses}, nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts := map[string]int{}
	appendix := map[string][]string{}
	for _, ty := range []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"} {
		ns, _ := s.m.Assets().QueryByType(ty, 100000, 0)
		if len(ns) == 0 {
			continue
		}
		counts[ty] = len(ns)
		names := make([]string, 0, len(ns)) // Appendix A asset list (A16)
		for _, a := range ns {
			if n := assetDisplayName(a); n != "" {
				names = append(names, n)
			}
		}
		appendix[ty] = names
	}
	goals, _ := t.Store.ListByKind(db.KindGoal, 1000)
	doc := report.BuildTaskDocx(report.TaskDocxInput{
		Title:          fmt.Sprintf("Penetration Test Report — %s", t.Description),
		Goal:           t.Goal,
		GeneratedAt:    time.Now(),
		AssetCounts:    counts,
		Findings:       findings,
		Goals:          report.GoalLines(goals),
		AssetNames:     s.reportAssetNames(findings),
		Retests:        s.reportRetests(findings),
		Customer:       s.taskCustomerNames(t),
		TestWindow:     taskTestWindow(t),
		AppendixAssets: appendix,
		PageHeader:     fmt.Sprintf("Penetration Test Report — %s", t.Description),
		ArtifactImage:  s.artifactImageResolver(t.ID, 0),
	})
	name := fmt.Sprintf("pojun-report-task%s-%s.docx", t.ID, time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", attachmentDisposition(name))
	w.WriteHeader(200)
	_ = doc.Encode(w)
}

// artifactImageResolver builds the evidence-attachment image resolver (v0.5.0): only
// resolves image attachments inside this task — non-image/cross-task/missing files all
// return ok=false (the report degrades to a text note).
func (s *Server) artifactImageResolver(taskID string, onlyFindingID int64) func(int64) ([]byte, string, bool) {
	if taskID == "" {
		return nil
	}
	return func(id int64) ([]byte, string, bool) {
		pg := s.m.PG()
		if pg == nil {
			return nil, "", false
		}
		a, err := pg.GetTaskArtifact(id)
		if err != nil || a == nil || a.TaskID != taskID {
			return nil, "", false
		}
		// the single-finding report embeds only 'this finding's images': material owned
		// by other findings or task-level items is never embedded — no mismatched
		// evidence.
		if onlyFindingID > 0 && a.FindingID != onlyFindingID {
			return nil, "", false
		}
		data, ok := s.artifactImageData(a)
		caption := a.Note
		if caption == "" {
			caption = a.Name
		}
		// document attachments (v0.4.21): referencing a doc embeds its page-1 preview
		// so the report can 'show' it.
		if !ok && a.PreviewState == "ready" && a.PreviewPages > 0 {
			p := filepath.Join(s.previewDir(a.TaskID, a.ID), "page-1.jpg")
			if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
				data, ok = b, true
				caption = caption + " (document page-1 preview)"
			}
		}
		if !ok {
			return nil, "", false
		}
		// big images shrink to 1600px JPEG first — dropping a 20MB original into docx
		// would bloat the report to tens of MB.
		if len(data) > 2<<20 {
			if small, ok := s.shrinkDocxImage(data); ok {
				data = small
			}
		}
		return data, caption, true
	}
}

// shrinkDocxImage shrinks a large image to a 1600px-long-edge JPEG; on failure
// returns false so the caller uses the original.
func (s *Server) shrinkDocxImage(data []byte) ([]byte, bool) {
	f, err := os.CreateTemp("", "pojun-embed-*.img")
	if err != nil {
		return nil, false
	}
	src := f.Name()
	defer os.Remove(src)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, false
	}
	if err := f.Close(); err != nil {
		return nil, false
	}
	dst := src + ".jpg"
	defer os.Remove(dst)
	if err := writeThumbnail(src, dst, 1600); err != nil {
		return nil, false
	}
	out, err := os.ReadFile(dst)
	if err != nil || len(out) == 0 || len(out) >= len(data) {
		return nil, false
	}
	return out, true
}

// taskCustomerNames resolves the task's linked company names (cover 'client' row;
// A12).
func (s *Server) taskCustomerNames(t *Task) string {
	if len(t.CompanyIDs) == 0 {
		return ""
	}
	names := make([]string, 0, len(t.CompanyIDs))
	for _, id := range t.CompanyIDs {
		c, err := s.m.pg.Companies().GetCompany(id)
		if err != nil || c == nil {
			continue
		}
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

// taskTestWindow describes the test window (cover / methodology section; A12).
func taskTestWindow(t *Task) string {
	if t.FirstRunAt <= 0 {
		return ""
	}
	start := time.Unix(t.FirstRunAt, 0).UTC().Format("2006-01-02 15:04 UTC")
	if t.CompletedAt > 0 {
		return start + " ~ " + time.Unix(t.CompletedAt, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	return start + " onwards (task not wrapped up; data as of report generation)"
}

// exportFindingDocx exports a single-finding report (Word).
func (s *Server) exportFindingDocx(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	names := s.reportAssetNames([]*db.DBFinding{f})
	retests, _ := s.m.pg.ListFindingRetests(f.ID)
	customer := ""
	classification := ""
	if f.TaskID != nil && *f.TaskID > 0 {
		if t := s.m.ResolveTask(strconv.FormatInt(*f.TaskID, 10)); t != nil {
			customer = s.taskCustomerNames(t)
			classification = "Internal — authorized parties only"
		}
	}
	doc := report.BuildFindingDocx(report.FindingDocxInput{
		Finding:        f,
		GeneratedAt:    time.Now(),
		AssetNameMap:   names,
		Retests:        retests,
		Customer:       customer,
		Classification: classification,
		ArtifactImage: func() func(int64) ([]byte, string, bool) {
			if f.TaskID == nil || *f.TaskID <= 0 {
				return nil
			}
			// single-finding reports strictly embed only this finding's images
			// (v0.4.20): no fallback to task-level images; historical photos can be
			// re-assigned in bulk under the task's 'evidence attachments'.
			return s.artifactImageResolver(strconv.FormatInt(*f.TaskID, 10), f.ID)
		}(),
	})
	name := fmt.Sprintf("pojun-finding-%d-%s.docx", f.ID, time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", attachmentDisposition(name))
	w.WriteHeader(200)
	_ = doc.Encode(w)
}
