package server

// Smart association (v0.4.42): task-level data/log evidence auto-assigned to vulns.
//
// Data survey (5 tasks): ~25% of data/log evidence had no finding attached — the worker
// stored evidence before the vuln was reported, and nobody back-filled later. This
// auto-attaches by 'host intersection': extract domains from the evidence's
// name/note/source_url/storage and intersect with the domains/urls of vuln-anchored
// assets —
// · exactly 1 vuln hit → auto-bind (source marked auto-bind; ownership can be changed
//   manually);
// · multiple hits → skip (ambiguous — better not to touch);
// · zero hits → skip.
// Only finding_id is ever written, content untouched; users can revert to task-level
// from the evidence card anytime.

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/chu0119/pojun/db"
)

var hostInTextRe = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::\d+)?`)

func extractHosts(text string) map[string]bool {
	out := map[string]bool{}
	for _, m := range hostInTextRe.FindAllStringSubmatch(text, 24) {
		h := strings.ToLower(m[1])
		if h != "" && strings.Contains(h, ".") {
			out[h] = true
		}
	}
	return out
}

func (s *Server) autoBindArtifacts(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	pg := s.m.pg
	arts, err := pg.ListTaskArtifacts(t.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	findings, err := pg.ListFindingsForExport(db.FindingFilter{TaskID: t.ID}, nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	// vuln → host set (anchored assets + hosts in report/evidence text)
	findingHosts := map[int64]map[string]bool{}
	findingInfo := map[int64]string{}
	for _, f := range findings {
		if f.ID == 0 {
			continue
		}
		hosts := map[string]bool{}
		text := f.Name + "\n" + f.Summary + "\n" + f.Evidence
		for h := range extractHosts(text) {
			hosts[h] = true
		}
		findingHosts[f.ID] = hosts
		findingInfo[f.ID] = f.Name
	}

	bound := 0
	skipped := 0
	details := []string{}
	for _, a := range arts {
		if a.FindingID != 0 || (a.Kind != "data" && a.Kind != "log") {
			continue
		}
		text := a.Name + "\n" + a.Note + "\n" + a.SourceURL + "\n" + a.Storage
		hosts := extractHosts(text)
		if len(hosts) == 0 {
			skipped++
			continue
		}
		matches := []int64{}
		for fid, fhosts := range findingHosts {
			for h := range hosts {
				if fhosts[h] {
					matches = append(matches, fid)
					break
				}
			}
		}
		if len(matches) != 1 {
			skipped++
			continue
		}
		fid := matches[0]
		if _, err := pg.UpdateTaskArtifactFinding(a.ID, fid); err != nil {
			skipped++
			continue
		}
		bound++
		details = append(details, fmt.Sprintf("%s → #%d %s", a.Name, fid, truncateRunes(findingInfo[fid], 40)))
	}
	sort.Strings(details)
	writeJSON(w, 200, map[string]any{"bound": bound, "skipped": skipped, "details": details})
}

func truncateRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
