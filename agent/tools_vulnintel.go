package agent

// Vuln-intel tools (vulnintel): after a worker/planner/mainagent identifies a target component,
// search_vulns looks up public known vulns (CISA KEV prioritized), and get_vuln fetches one entry's detail
// (full description + CPE criteria version ranges + reference links) to decide the exploit path.
// The intel store is globally shared and read-only to agents, so it uses package-level injection (same
// pattern as the ToolResolve hooks) — the server Sets it once at startup; nil = tool works but reports not enabled (consistent with asset tools' guard).

import (
	"context"
	"encoding/json"
	"net"
	"runtime"
	"regexp"
	"os/exec"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/chu0119/pojun/selfupdate"
	"github.com/chu0119/pojun/vulnintel"
)

// vulnintelStore is process-wide (set once at server startup); safe for
// concurrent ToolSets because the store is read-only from the agent's side.
var vulnintelStore *vulnintel.Store

// SetVulnIntelStore wires the shared intel store; nil disables the tools.
func SetVulnIntelStore(s *vulnintel.Store) { vulnintelStore = s }

// nucleiTemplatesDir is the local nuclei-templates checkout (empty = scan tool
// unavailable). Set alongside the store at startup.
var nucleiTemplatesDir string

// SetNucleiTemplatesDir wires the template tree path; empty disables scan tool.
func SetNucleiTemplatesDir(dir string) { nucleiTemplatesDir = dir }

// cweSkillIndex maps a CWE number to the methodology skill (dir name) tagged tags.cwe.
// Built at server startup from SKILL.md frontmatter in the skills dir (server.BuildCweSkillIndex);
// when not injected (nil/empty), related_skills never appears in tool output — the linkage is purely additive.
// This is the final link of capability-comparison M1: 'looked up a CVE → auto-suggest the matching methodology skill'.
var cweSkillIndex atomic.Value // map[string][]string

// SetCweSkillIndex wires the CWE→skills mapping.
func SetCweSkillIndex(idx map[string][]string) { cweSkillIndex.Store(idx) }

// relatedSkillsFor returns the deduped skill list covering any of the given CWEs.
func relatedSkillsFor(cwes []string) []string {
	raw, _ := cweSkillIndex.Load().(map[string][]string)
	if len(raw) == 0 || len(cwes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range cwes {
		for _, s := range raw[strings.ToUpper(strings.TrimSpace(c))] {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// vulnDetailWithSkills attaches the skill-linkage fields onto VulnDetail
// (embedded flat serialization — fields absent without linkage, shape identical to before).
type vulnDetailWithSkills struct {
	*vulnintel.VulnDetail
	RelatedSkills []string `json:"related_skills,omitempty"`
	SkillNote     string   `json:"skill_note,omitempty"`
}

// searchVulns exposes product-keyed CVE retrieval. Version matching against
// NVD criteria is intentionally returned as raw material (criteria text + a
// coarse "version seen" flag) — the LLM judges applicability, structured CPE
// range math is a later batch.
func (t *ToolSet) searchVulns() actool.CoreTool {
	return readTool(
		"search_vulns",
		"Searches the [public known-vuln] store by component name (NVD + GitHub Advisory Database + CISA KEV exploited-in-the-wild list). "+
			"After identifying a target component (web middleware/framework/service/firmware etc.) check here first: kev flag = exploited in the wild, prioritize it; "+
			"cvss_score and severity in results are for ranking.\n"+
			"Pass version for version checking:\n"+
			"  - version_in_range=true → the target version **falls inside the affected range** (worth hitting)\n"+
			"  - version_in_range=false → the target version is **not** in the affected range (usually not worth it)\n"+
			"  - field absent → no structured range; judge affectedness yourself (get_vuln shows the cpe_criteria version-range syntax)\n"+
			"**version_in_range=false doesn't mean safe** — some records have wrong or missing ranges; "+
			"when unsure, get_vuln for the raw ranges and reference links.\n"+
			"The source field marks whether the entry comes from nvd or ghsa: GHSA's version ranges are required (higher confidence), "+
			"NVD often leaves them blank on newly disclosed CVEs.\n"+
			"Result count is limited — raise limit or add vendor to narrow when there are many hits.",
		obj(map[string]any{
			"product": str("component name, e.g. httpd / nginx / thinkphp / tomcat / weblogic; % wildcards supported"),
			"vendor":  str("vendor filter (optional), e.g. apache / oracle — distinguishes same-named components"),
			"version": str("target version (optional, e.g. 2.4.49): results whose CPE range matched it get marked version_seen_in_criteria"),
			// limit is an integer param. It was once wrongly written as obj(...) (a nested object), so the validator required
			// the model to pass `limit: {}` — measured: all 41 calls errored
			// "invalid tool input: limit: expected object" — the tool was half-dead.
			"limit":   intp("return cap (default 20, max 50)"),
		}, "product"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("search_vulns not enabled: vuln intel store not initialized"), nil
			}
			var a struct {
				Product string `json:"product"`
				Vendor  string `json:"vendor"`
				Version string `json:"version"`
				Limit   int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Product) == "" {
				return actool.Errorf("product must not be empty"), nil
			}
			hits, err := vulnintelStore.SearchVulns(context.Background(), a.Vendor, a.Product, a.Version, a.Limit)
			if err != nil {
				return actool.Errorf("vuln search failed: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return jsonResult(map[string]any{
					"count": 0,
					"note":  "no hits for this component name in the intel store (its spelling may differ from the CPE naming — try common abbreviations like httpd/IIS; or the component has no known vulns recently)",
				})
			}
			kev := 0
			for _, h := range hits {
				if h.KEV {
					kev++
				}
			}
			res := map[string]any{
				"count":           len(hits),
				"kev_count":       kev,
				"vulnerabilities": hits,
				"note":            "kev=true means CISA confirmed in-the-wild exploitation — highest value; next use get_vuln for the single entry's details (affected version ranges/reference links)",
			}
			// CWE→skill linkage: entries carrying a CWE suggest the corresponding methodology skill.
			var allCWEs []string
			for _, h := range hits {
				allCWEs = append(allCWEs, h.Cwes...)
			}
			if skills := relatedSkillsFor(allCWEs); len(skills) > 0 {
				res["related_skills"] = skills
			}
			return jsonResult(res)
		},
	)
}

// getVuln exposes the full record for one CVE.
func (t *ToolSet) getVuln() actool.CoreTool {
	return readTool(
		"get_vuln",
		"Fetches one known vuln's full details: original English description, CVSS score and vector, KEV or not, "+
			"cpe_criteria (NVD's affected-range source text — cpe:2.3:a:vendor:product:version:... strings "+
			"with versionEndExcluding / versionStartIncluding etc. range fields expressing the affected scope), "+
			"references (exploit/advisory/patch links). Use it to judge whether the target version is hit and where to find ready-made exploits.",
		obj(map[string]any{
			"cve_id": str("CVE id, e.g. CVE-2021-41773"),
		}, "cve_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("get_vuln not enabled: vuln intel store not initialized"), nil
			}
			var a struct {
				CVEID string `json:"cve_id"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.CVEID) == "" {
				return actool.Errorf("cve_id must not be empty"), nil
			}
			d, err := vulnintelStore.GetVuln(context.Background(), a.CVEID)
			if err != nil {
				return actool.Errorf("vuln query failed: " + err.Error()), nil
			}
			if d == nil {
				return actool.Errorf(a.CVEID + " is not in the intel store (it only indexes publicly synced sources)"), nil
			}
			if skills := relatedSkillsFor(d.Cwes); len(skills) > 0 {
				return jsonResult(vulnDetailWithSkills{
					VulnDetail:    d,
					RelatedSkills: skills,
					SkillNote:     "these methodology skills are tagged with this vuln's CWE — before deepening verification, load the matching dimension via the Skill tool (privesc/injection/race etc. verification steps and evidence requirements)",
				})
			}
			return jsonResult(d)
		},
	)
}

// searchRecentCritical exposes "what critical CVEs came out recently".
//
// Division of labor vs search_vulns:
//   - search_vulns queries by **component** ('this is nginx — what vulns does nginx have');
//   - this tool queries by **time** ('what criticals were disclosed in the last 7 days') — no need to know
//     component names or CVE ids first.
//
// Why it exists (2026-10-22 research): after a worker scans an asset, its fingerprint is usually
// 'PHP/8.1.2' shaped — it knows to query PHP, but **doesn't know what was just disclosed** — and a
// critical vuln's value window is the first days after disclosure. With this tool, identifying a component
// means directly asking 'what criticals came out for PHP recently'.
//
// version_undetermined=true means NVD hasn't filled the affected range — it **doesn't mean the target
// version is unaffected**; those entries are worth prioritizing (fresh criticals usually lack ranges).
func (t *ToolSet) searchRecentCritical() actool.CoreTool {
	return readTool(
		"search_recent_critical",
		"Queries [recently disclosed critical vulns] (CVSS≥9.0 or CISA KEV exploited-in-the-wild). "+
			"Usage: after scanning a component/asset (fingerprints shaped like PHP/8.1.2, Apache httpd 2.4.49), "+
			"ask 'what criticals came out in this direction recently' — no CVE id needed beforehand. "+
			"The products field in results holds the affected products (vendor/product) — compare it against your target's "+
			"fingerprint; version_undetermined=true means NVD hasn't filled the affected range — "+
			"[it does NOT mean your version is unaffected] — such fresh vulns usually lack version info; prioritize "+
			"checking the vendor advisory (get_vuln's refs carry GHSA/security-advisory links) to confirm affected versions, "+
			"then verify via scan_with_nuclei or hand-built payloads.",
		obj(map[string]any{
			"days":  intp("look-back days (default 7, max 90). For just-disclosed vulns a small value (3~14) suffices"),
			"limit": intp("return cap (default 20, max 100)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("search_recent_critical not enabled: vuln intel store not initialized"), nil
			}
			var a struct {
				Days  int `json:"days"`
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Days < 0 {
				return actool.Errorf("days must not be negative"), nil
			}
			if a.Days > 90 {
				a.Days = 90
			}
			hits, err := vulnintelStore.SearchRecentCritical(context.Background(), a.Days, a.Limit)
			if err != nil {
				return actool.Errorf("recent-critical query failed: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return jsonResult(map[string]any{
					"count": 0,
					"note":  "no new criticals in the recent window (the fast lane indexes CVSS≥9.0 or KEV; the store only indexes publicly synced sources)",
				})
			}
			undet := 0
			for _, h := range hits {
				if h.VersionUndetermined {
					undet++
				}
			}
			return jsonResult(map[string]any{
				"count":                   len(hits),
				"version_undetermined":   undet,
				"vulnerabilities":         hits,
				"note":                    "version_undetermined=true entries mean NVD hasn't filled the affected range — not 'unaffected'; check vendor advisories first",
			})
		},
	)
}

// getPoc exposes aggregated PoC/EXP entries for one CVE.
func (t *ToolSet) getPoc() actool.CoreTool {	return readTool(
		"get_poc",
		"Fetches the ready-made [PoC/exploit] aggregation for one known vuln: public GitHub repos referencing the CVE, "+
			"sorted by stars. First confirm the vuln exists via search_vulns, then get_poc for ready ammunition; it returns "+
			"repo addresses and descriptions — it doesn't execute for you: clone/analyze the repo with Bash and build the exploit per its docs. "+
			"No hits only means no public ready-made code — not that the vuln is unexploitable.",
		obj(map[string]any{
			"cve_id": str("CVE id, e.g. CVE-2021-41773"),
		}, "cve_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if vulnintelStore == nil {
				return actool.Errorf("get_poc not enabled: vuln intel store not initialized"), nil
			}
			var a struct {
				CVEID string `json:"cve_id"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.CVEID) == "" {
				return actool.Errorf("cve_id must not be empty"), nil
			}
			hits, err := vulnintelStore.GetPoCs(context.Background(), a.CVEID)
			if err != nil {
				return actool.Errorf("PoC query failed: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count": len(hits),
				"pocs":  hits,
			})
		},
	)
}


// nucleiSeverityRE constrains the severity param's shape — arbitrary text mustn't reach the command line.
var nucleiSeverityRE = regexp.MustCompile(`^(?i)(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$`)

// shellJoinArgs single-quotes each argv item into a shell-ready command line.
// A plain strings.Join won't do: & ; $() backticks in target get interpreted by the shell
// (measured: https://t/api?id=1&x=2 treats & as a background marker — the scan only ran halfway).
func shellJoinArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, quoteShell(a))
	}
	return strings.Join(out, " ")
}

// scanWithNuclei assembles a nuclei command for the worker's Bash tool. The
// tool deliberately does NOT execute nuclei itself: Bash runs it through the
// recording proxy + approval gates like every other command, keeping audit
// semantics uniform. What this tool adds is template selection (CVE-keyed)
// and a correct, version-pinned command line.
func (t *ToolSet) scanWithNuclei() actool.CoreTool {
	return readTool(
		"scan_with_nuclei",
		"Assembles a [nuclei template scan] command for Bash to run (this tool only builds the command, never executes). "+
			"Good for batch template verification after the target is confirmed reachable and search_vulns found the CVE. "+
			"With cve_id, only templates matching that CVE run (recommended — fast and focused); without it the whole template tree runs "+
			"(slow — use carefully, narrow with severity). The template tree auto-updates with intel syncs. "+
			"Output is JSONL results — one finding per line; no output = no template hits.",
		obj(map[string]any{
			"target":   str("scan target URL, e.g. https://example.com"),
			"cve_id":   str("CVE id (optional, recommended): only run templates matching this CVE, e.g. CVE-2021-41773"),
			"severity": str("severity filter (optional): comma-combination of critical,high,medium,low"),
		}, "target"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if nucleiTemplatesDir == "" {
				return actool.Errorf("scan_with_nuclei not enabled: template path not configured"), nil
			}
			if !vulnintel.NucleiInstalled() {
				return actool.Errorf("nuclei not installed (this runtime lacks the binary; the Docker image has it built in)"), nil
			}
			var a struct {
				Target   string `json:"target"`
				CVEID    string `json:"cve_id"`
				Severity string `json:"severity"`
			}
			_ = json.Unmarshal(in, &a)
			// target/severity come from the model (possibly re-injected via a target's response): validate semantics first,
			// then single-quote each arg when building the shell command — so &/;/$() can't change its meaning.
			u, uerr := url.Parse(strings.TrimSpace(a.Target))
			if uerr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return actool.Errorf("target must be an http(s) URL"), nil
			}
			if a.Severity != "" && !nucleiSeverityRE.MatchString(strings.TrimSpace(a.Severity)) {
				return actool.Errorf("severity only allows a comma-combination of critical/high/medium/low/info"), nil
			}
			cmd, cancel, err := vulnintel.BuildNucleiCmd(context.Background(), nucleiTemplatesDir, vulnintel.ScanArgs{
				Target:       a.Target,
				CVEID:        a.CVEID,
				Severity:     a.Severity,
				TimeoutTotal: 10 * time.Minute,
			})
			if err != nil {
				return actool.Errorf("failed to build the scan command: " + err.Error()), nil
			}
			defer cancel()
			run := shellJoinArgs(cmd.Args)
			// Total timeout: wrap in GNU timeout when present (Linux production has it by default); otherwise rely on the Bash tool's own timeout.
			if tp, terr := exec.LookPath("timeout"); terr == nil && runtime.GOOS != "windows" {
				run = quoteShell(tp) + " 600 " + run
			}
			return jsonResult(map[string]any{
				"run_with_bash": run,
				"note": "run the command above with the Bash tool (default 10-min timeout — output truncates past it); " +
					"output is JSONL, one template hit per line; empty output = no hits. After finding a real vuln, report normally via report_finding.",
			})
		},
	)
}

// netContext outputs the current runtime's network context (NICs/routes/user-configured callback info),
// for LHOST/LPORT decisions in reverse shell / bind shell / MSF.
// Deliberately doesn't exec `ip` (iproute2 isn't guaranteed in the image) — native Go enumeration instead.
//
// The explanation has two variants by deployment form: binary deployment = the machine's NICs are usable addresses,
// ready for intranet pentest; container deployment = the local IP is the container's internal address, targets
// probably can't reach back — must use the configured host/public reachable address.
func (t *ToolSet) netContext() actool.CoreTool {
	inDocker := selfupdate.InDocker()
	desc := "Fetches this machine's network context: all NIC IPs, plus the platform-configured [callback-reachable addresses]. "
	if inDocker {
		desc += "Currently running in a container: the local IP is the container's internal address — targets probably can't reach it. " +
			"Before starting a reverse shell / MSF handler [must] check this tool first — use the configured host/public-reachable address as LHOST and a port inside the mapped range."
	} else {
		desc += "Binary (host) deployment: interfaces are the machine's real NICs — for intranet pentest use the machine's IP on the target's segment as LHOST directly; " +
			"bind/reverse shells need no extra port-mapping config."
	}
	return readTool(
		"net_context",
		desc,
		obj(map[string]any{}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			type iface struct {
				Name string   `json:"name"`
				IPs  []string `json:"ips"`
			}
			var ifaces []iface
			addrs, err := net.Interfaces()
			if err == nil {
				for _, a := range addrs {
					if a.Flags&net.FlagUp == 0 {
						continue
					}
					addrs2, err := a.Addrs()
					if err != nil || len(addrs2) == 0 {
						continue
					}
					it := iface{Name: a.Name, IPs: []string{}}
					for _, ad := range addrs2 {
						it.IPs = append(it.IPs, ad.String())
					}
					ifaces = append(ifaces, it)
				}
			}
			var hint, portMap string
			if vulnintelStore != nil {
				hint = vulnintelStore.EgressHint(ctx)
				portMap = vulnintelStore.EgressPortMap(ctx)
			}
			note := ""
			if inDocker {
				note = "interfaces are from [inside the container] — probably unreachable externally: a reverse shell's LHOST must use a host/externally reachable address " +
					"(egress_hint if any), and the listen port must be inside the port_map-declared mapped range. " +
					"Both empty means the platform isn't configured — request it from a human via add_hint; don't blindly call back to a container IP."
			} else {
				note = "This is a host binary deployment: interfaces are the machine's real NICs — for intranet pentest use the machine's IP on the target's segment as LHOST directly, " +
					"bind any port without mapping. For a public or cross-segment target, pick whichever address reaches it. " +
					"Empty egress_hint / port_map doesn't affect direct local dialing; when unsure which address reaches the target, ask via add_hint."
			}
			return jsonResult(map[string]any{
				"interfaces":      ifaces,
				"egress_hint":     hint,
				"egress_port_map": portMap,
				"deploy_mode":     map[bool]string{true: "docker", false: "host"}[inDocker],
				"note":            note,
			})
		},
	)
}
