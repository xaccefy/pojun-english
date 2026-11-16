package vulnintel

// Asset-graph linkage: synced CVEs reverse-match assets (service-type technologies
// fingerprints), producing a hit list the caller (server) uses to attach hints to
// affected tasks. This file deliberately avoids depending on the agent package (pkg
// cycles): persisting hints is done via a server-side callback.
//
// Matching is deliberately broad: naming gaps between technologies ("Apache httpd
// 2.4.49") and CPE products ("http_server") are bridged by token normalization
// (lowercase/strip versions/split words/hyphen forms) intersecting; better to over-report
// for the planner to judge than silently miss. Batched per task×component to avoid hint
// storms.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// AssetVulnMatch records one asset-CVE hit.
type AssetVulnMatch struct {
	CVEID    string   `json:"cve_id"`
	AssetID  int64    `json:"asset_id"`
	TaskID   int64    `json:"task_id"`
	Severity string   `json:"severity"`
	KEV      bool     `json:"kev"`
	Score    *float64 `json:"cvss_score,omitempty"`
	Product  string   `json:"product"`
}

// AssetLinkResult is one linkage run's statistics.
type AssetLinkResult struct {
	ScannedAssets int
	MatchedAssets int
	Matches       []AssetVulnMatch
}

// techTokens normalizes a technology fingerprint into stems: strip version numbers,
// split on spaces and common separators (slashes/parens/underscores, hyphens kept
// first), add merged hyphen forms. "Apache httpd 2.4.49" →
// [apache httpd]; "nginx/1.24" → [nginx]; "http-server" → [http-server http server httpserver].
func techTokens(s string) []string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("/", " ", "_", " ", "(", " ", ")", " ").Replace(s)
	raw := strings.Fields(s)
	toks := make([]string, 0, len(raw)*3)
	for _, f := range raw {
		f = strings.Trim(f, ".,:;!?")
		if len(f) < 2 || f == "v" || isVersionish(f) {
			continue
		}
		toks = append(toks, f)
	}
	// hyphen forms get three namings: as-is + spaced (http server) + merged (httpserver).
	for _, f := range append([]string{}, toks...) {
		if strings.Contains(f, "-") {
			if spaced := strings.ReplaceAll(f, "-", " "); len(strings.TrimSpace(spaced)) > 0 {
				toks = append(toks, spaced)
			}
			if alt := strings.ReplaceAll(f, "-", ""); len(alt) >= 2 {
				toks = append(toks, alt)
			}
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		for _, sub := range strings.Fields(t) { // split the spaced alias once more
			if !seen[sub] {
				seen[sub] = true
				out = append(out, sub)
			}
		}
	}
	// alias table: every tech-side token also carries common CPE product forms (an
	// underscore-bearing product enters whole; otherwise it's word-split).
	for _, tok := range append([]string{}, out...) {
		for _, alt := range techAliases[tok] {
			alts := []string{strings.ToLower(alt)}
			if !strings.Contains(alt, "_") {
				alts = strings.Fields(strings.ToLower(alt))
			}
			for _, sub := range alts {
				if !seen[sub] {
					seen[sub] = true
					out = append(out, sub)
				}
			}
		}
	}
	return out
}

// isVersionish: two digits plus a dot or v-prefix → "1.24", "v12", "2.4.49".
func isVersionish(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 2 && (strings.Contains(s, ".") || strings.HasPrefix(s, "v"))
}

// cpeTokens: product segment + underscore-merged form + common abbreviation aliases.
// The alias map is essential: real-world fingerprints say "httpd" while CPE products say
// "http_server" — a pure token intersection would always be empty. Accumulated from real
// asset inventories, maintained incrementally.
var techAliases = map[string][]string{
	"httpd":           {"http_server"},
	"http":            {"http_server"},
	"iis":             {"internet_information_services"},
	"exchange":        {"exchange_server"},
	"sqlserver":       {"sql_server"},
	"activedirectory": {"active_directory"},
	"win":             {"windows"},
	"winserver":       {"windows"},
	"cent":            {"centos"},
	"ubuntu":          {"ubuntu_linux"},
	"debian":          {"debian_linux"},
	"vmwareesxi":      {"esxi"},
	"tomcat":          {"apache_tomcat"},
	"struts":          {"apache_struts"},
	"log4j":           {"apache_log4j"},
	"spring":          {"vmware_Spring", "pivotal_Spring", "spring_framework"},
	"nginx":           {"nginx"},
}

// cpeTokens: product segment + underscore-merged form + common abbreviation aliases.
func cpeTokens(product string) []string {
	product = strings.ToLower(product)
	toks := []string{product}
	if compact := strings.ReplaceAll(product, "_", ""); compact != product && len(compact) >= 2 {
		toks = append(toks, compact)
	}
	for _, alt := range techAliases[product] {
		toks = append(toks, strings.ToLower(alt))
	}
	// reverse: when product equals some alias's value, add the key ("http_server" →
	// "httpd"/"http") so tech-side "httpd" and CPE-side "http_server" hit equally.
	for key, vals := range techAliases {
		for _, v := range vals {
			if v == product {
				toks = append(toks, key)
			}
		}
	}
	// reverse: when product's head segment (token before _) is an alias key, add its
	// aliases ("apache_tomcat" → "tomcat") — tech says "tomcat", CPE says
	// "apache_tomcat".
	if head, _, ok := strings.Cut(product, "_"); ok {
		if alts, found := techAliases[head]; found {
			for _, alt := range alts {
				toks = append(toks, strings.ToLower(alt))
			}
			toks = append(toks, head)
		}
	}
	return toks
}

// LinkAssetsToVulns joins candidates against service assets' technologies and
// returns per-task matches. The caller (server) owns hint creation via its own
// exploration stores.
func (s *Store) LinkAssetsToVulns(ctx context.Context, since time.Time) (*AssetLinkResult, error) {
	// candidate CVEs: newly synced; KEV first, then score. Counts anchored to a
	// completable magnitude.
	cveRows, err := s.db.QueryContext(ctx, `
SELECT c.cve_id, c.severity, c.cvss_score, c.kev, p.product
FROM vuln_cves c
JOIN vuln_cpe_products p ON p.cve_id = c.cve_id
WHERE c.kev = true OR c.modified_at > $1 OR c.kev_date_added > $1
ORDER BY c.kev DESC, COALESCE(c.cvss_score, 0) DESC
LIMIT 500`, since)
	if err != nil {
		return nil, fmt.Errorf("query candidate cves: %w", err)
	}
	type cveRow struct {
		CVEID, Severity string
		Score           *float64
		KEV             bool
		Product         string
	}
	cves := []cveRow{}
	for cveRows.Next() {
		var c cveRow
		if err := cveRows.Scan(&c.CVEID, &c.Severity, &c.Score, &c.KEV, &c.Product); err == nil {
			cves = append(cves, c)
		}
	}
	cveRows.Close()
	if len(cves) == 0 {
		return &AssetLinkResult{Matches: []AssetVulnMatch{}}, nil
	}

	// pull all assets at once (service rows are bounded; fingerprint matching is done in
	// Go).
	type assetRow struct {
		ID    int64
		Techs []string
		Tasks []int64
	}
	aRows, err := s.db.QueryContext(ctx, `
SELECT a.id, COALESCE(array_to_json(a.technologies)::text, '[]'),
       COALESCE((SELECT array_to_json(array_agg(DISTINCT l.task_id)) FROM task_asset_links l WHERE l.asset_id = a.id), '[]')
FROM assets a WHERE a.type='service'`)
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	assets := []assetRow{}
	for aRows.Next() {
		var r assetRow
		var techs, tasks []byte
		if err := aRows.Scan(&r.ID, &techs, &tasks); err == nil {
			_ = json.Unmarshal(techs, &r.Techs)
			_ = json.Unmarshal(tasks, &r.Tasks)
			assets = append(assets, r)
		}
	}
	aRows.Close()

	res := &AssetLinkResult{ScannedAssets: len(assets), Matches: []AssetVulnMatch{}}
	// token → CVE rows matching that token. One index build, O(1) lookups during asset
	// matching.
	//
	// This used to be an O(assets × tech × product) triple-nested scan, recomputing
	// cpeTokens(product) for every product each round. Measured on 4966 assets: 28s and
	// 32k debug lines into the journal — drowning the agent's log signal (see
	// [[pojun-obs-loop]]). The inverted index drops it to O(CVE × token + assets ×
	// token).
	tokIndex := map[string][]cveRow{}
	for _, c := range cves {
		for _, pt := range cpeTokens(c.Product) {
			tokIndex[pt] = append(tokIndex[pt], c)
		}
	}
	// a product may have several cpeTokens, so one CVE can hit the same asset through
	// multiple tokens → dedupe per asset (by CVEID), else res.Matches gets duplicate
	// rows and wastes writes. Note seenCVE must be fresh **per asset**: CVEs are an
	// asset×CVE relation — cross-asset dedupe would hide the same CVE from the second
	// asset.
	for _, a := range assets {
		var hitCVEs []cveRow
		seenCVE := map[string]bool{}
		for _, tech := range a.Techs {
			for _, tok := range techTokens(tech) {
				for _, c := range tokIndex[tok] {
					if seenCVE[c.CVEID] {
						continue
					}
					seenCVE[c.CVEID] = true
					hitCVEs = append(hitCVEs, c)
				}
			}
		}
		if len(hitCVEs) == 0 {
			continue
		}
		res.MatchedAssets++
		for _, c := range hitCVEs {
			for _, taskID := range a.Tasks {
				res.Matches = append(res.Matches, AssetVulnMatch{
					CVEID: c.CVEID, AssetID: a.ID, TaskID: taskID,
					Severity: c.Severity, KEV: c.KEV, Score: c.Score, Product: c.Product,
				})
			}
		}
	}
	log.Printf("[vulnintel] asset link: scanned=%d matched=%d matches=%d cve=%d",
		res.ScannedAssets, res.MatchedAssets, len(res.Matches), len(cves))
	return res, nil
}

// FormatHint assembles one hint text (multiple CVEs for one asset aggregate into one;
// kev first).
func FormatHint(m []AssetVulnMatch, assetID int64) string {
	// dedup cves (one asset may match several cves)
	seen := map[string]bool{}
	list := []AssetVulnMatch{}
	for _, x := range m {
		if !seen[x.CVEID] {
			seen[x.CVEID] = true
			list = append(list, x)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[intel link] asset(id=%d) component fingerprint matched %d known vulns:", assetID, len(list))
	for i, x := range list {
		if i >= 8 { // context budget: beyond this, the planner chases the rest via search_vulns
			fmt.Fprintf(&b, " and %d more (use search_vulns(product) for the rest)", len(list))
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s(%s", x.CVEID, x.Severity)
		if x.Score != nil {
			fmt.Fprintf(&b, " %.1f", *x.Score)
		}
		if x.KEV {
			b.WriteString(",KEV exploited in the wild")
		}
		fmt.Fprintf(&b, ")")
	}
	b.WriteString(". Use get_vuln(cve_id) for affected ranges and get_poc(cve_id) for ready-made exploits, then decide whether it's worth dispatching an intent to verify.")
	return b.String()
}
