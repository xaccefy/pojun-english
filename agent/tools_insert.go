package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/chu0119/pojun/db"
)

// assetInterceptCandidates extracts the domain/IP/URL candidate strings from an asset item to be inserted, for asset-interception matching.
// A URL's host is split out and classified, so service/endpoint assets that only carry a URL can still be hit by domain/IP rules.
func assetInterceptCandidates(item assetInputItem) (domains, ips, urls []string) {
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	add(&domains, item.Domain)
	for _, d := range item.BoundDomains {
		add(&domains, d)
	}
	add(&ips, item.IP)
	add(&ips, item.ServiceIP)
	add(&urls, item.URL)
	if item.URL != "" {
		if u, err := url.Parse(item.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					add(&ips, h)
				} else {
					add(&domains, h)
				}
			}
		}
	}
	return domains, ips, urls
}

// identityHint compresses the candidate strings into a one-line identity hint for the model (max 3).
func identityHint(domains, ips, urls []string) string {
	parts := make([]string, 0, 3)
	for _, d := range domains {
		if len(parts) < 3 {
			parts = append(parts, d)
		}
	}
	for _, u := range urls {
		if len(parts) < 3 {
			parts = append(parts, u)
		}
	}
	for _, ip := range ips {
		if len(parts) < 3 {
			parts = append(parts, ip)
		}
	}
	return strings.Join(parts, ",")
}

// assetInputLabel returns a short label for an asset item to be inserted, used in interception notices.
func assetInputLabel(item assetInputItem) string {
	typ := strings.TrimSpace(item.Type)
	var target string
	switch {
	case strings.TrimSpace(item.Domain) != "":
		target = strings.TrimSpace(item.Domain)
	case strings.TrimSpace(item.URL) != "":
		target = strings.TrimSpace(item.URL)
	case strings.TrimSpace(item.IP) != "":
		target = strings.TrimSpace(item.IP)
	case strings.TrimSpace(item.ServiceIP) != "":
		target = strings.TrimSpace(item.ServiceIP)
	default:
		target = "(unknown)"
	}
	if typ != "" {
		return fmt.Sprintf("[%s] %s", typ, target)
	}
	return target
}

// =====================================================================
// Unified asset insertion tools
// =====================================================================

// SetAssetStore wires the asset store and company store onto this ToolSet
// so the insert_assets, add_company_scope, and list_assets tools are active.
func (t *ToolSet) SetAssetStore(as *db.AssetStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
}

// assetInputItem is one element of the insert_assets "assets" array.
type assetInputItem struct {
	Type string `json:"type"` // root_domain|ip|subdomain|app|service|endpoint

	// ---- root_domain / subdomain ----
	Domain      string   `json:"domain"`
	ICP         string   `json:"icp"`
	RecordType  string   `json:"record_type"`
	RecordValue []string `json:"record_value"`

	// ---- ip ----
	IP           string           `json:"ip"`
	BoundDomains []string         `json:"bound_domains"`
	OpenPorts    []db.PortService `json:"open_ports"`

	// ---- app ----
	AppName     string `json:"app_name"`
	BundleID    string `json:"bundle_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	AppICP      string `json:"app_icp"`
	CompanyID   *int64 `json:"company_id"` // explicit company link (app only; others auto-attribute via scope)

	// ---- service (http) ----
	URL           string           `json:"url"`
	Technologies  []string         `json:"technologies"`
	StatusCode    *int             `json:"status_code"`
	ContentLength *int64           `json:"content_length"`
	PageTitle     string           `json:"page_title"`
	FaviconMMH3   string           `json:"favicon_mmh3"`
	Auth          []map[string]any `json:"auth"`
	ServiceName   string           `json:"service_name"`
	ServiceIP     string           `json:"service_ip"` // optional enrichment IP

	// ---- service (other) ----
	Port  int    `json:"port"`
	Proto string `json:"proto"`

	// ---- endpoint ----
	Method string           `json:"method"`
	Params []map[string]any `json:"params"`
}

// insertAssets is the unified insert_assets agent tool.
func (t *ToolSet) insertAssets() actool.CoreTool {
	return writeTool(
		"insert_assets",
		"Batch-registers newly discovered assets — mixed types allowed in one call (see the type enum).\n"+
			"Required fields per type: root_domain→domain; ip→ip (must be IPv4/IPv6, not a hostname); subdomain→domain; app→app_name; service(HTTP)→url; service(non-HTTP)→service_name+port (at least one of ip/domain); endpoint→url+method. Other fields are explained individually.\n"+
			"auth/technologies/params are appended (append), not overwritten.\n"+
			"Returns: {results:[{index,id,type}], errors:[{index,error}]}",
		obj(map[string]any{
			// task_id isn't exposed to the model: which task a worker belongs to is authoritatively set by the program via SetTaskID (see handler).
			"assets": map[string]any{
				"type":        "array",
				"description": "asset array — each element is one asset record",
				"items": obj(map[string]any{
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"},
						"description": "asset type",
					},
					// root_domain / subdomain
					"domain":      str("root domain or subdomain (required for root_domain/subdomain)"),
					"icp":         str("ICP registration number (optional)"),
					"record_type": str("DNS record type: A/AAAA/CNAME/MX etc. (subdomain, optional)"),
					"record_value": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "DNS resolution values (subdomain, optional — e.g. [\"1.2.3.4\",\"2.3.4.5\"])",
					},
					// ip
					"ip": str("IP address — must be IPv4/IPv6, not a hostname (hostnames go into a type=subdomain domain field); required for ip type; optional for service/endpoint to link the IP"),
					"bound_domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "domain list bound to this IP (ip type, optional)",
					},
					"open_ports": map[string]any{
						"type":        "array",
						"description": "open port list (ip type, optional)",
						"items": obj(map[string]any{
							"port":    intp("port number"),
							"service": str("service name, e.g. http/ssh/mysql (optional)"),
						}, "port"),
					},
					// app
					"app_name":    str("app name (required for app type)"),
					"bundle_id":   str("Bundle ID (app type, optional)"),
					"category":    str("app category (optional)"),
					"description": str("app description (optional)"),
					"app_icp":     str("app ICP registration (optional)"),
					"company_id":  intp("owning company id (app type, optional; an app can't be auto-attributed via scope and must be specified explicitly — the id comes from add_company_scope)"),
					// service (http)
					"url":         str("full URL incl. scheme and port (required for HTTP services; service_type auto-set to http)"),
					"status_code": intp("HTTP response status code, e.g. 200/301/403/404 (optional)"),
					"content_length": map[string]any{
						"type":        "integer",
						"description": "HTTP response body bytes (optional)",
					},
					"page_title":   str("page <title> content (optional)"),
					"favicon_mmh3": str("favicon MMH3 hash (optional)"),
					"technologies": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "fingerprint/tech-stack list, e.g. [\"Nginx\",\"Vue\",\"Bootstrap\"] (optional)",
					},
					"auth": map[string]any{
						"type":        "array",
						"description": "discovered auth info list — each entry has type/username/password etc. fields (optional, append not overwrite)",
						"items":       map[string]any{"type": "object"},
					},
					// service (other, non-HTTP)
					"service_name": str("service name, e.g. ssh/mysql/redis (required for non-HTTP service)"),
					"port":         intp("port number (required for non-HTTP service)"),
					// endpoint
					"method": str("HTTP method: GET/POST/PUT/PATCH/DELETE etc. (required for endpoint)"),
					"params": map[string]any{
						"type":        "array",
						"description": "request-parameter list — each entry has location(query/body/header/path)/name/value/type (optional, append not overwrite)",
						"items":       map[string]any{"type": "object"},
					},
				}, "type"),
			},
		}, "assets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_assets not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				Assets []assetInputItem `json:"assets"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			// task_id is authoritatively assigned by the program (worker: SetTaskID) and doesn't come from the model — avoiding
			// assets going unassigned or mis-assigned when the model omits/mispasses it. Callers without task context (auto/pentest/chat) get t.taskID=0.
			taskID := t.taskID

			type result struct {
				Index int    `json:"index"`
				ID    int64  `json:"id"`
				Type  string `json:"type"`
			}
			type errEntry struct {
				Index int    `json:"index"`
				Error string `json:"error"`
			}

			var results []result
			var errs []errEntry

			// Asset-gate rules loaded once; read failure skips the check (doesn't block insertion).
			// Intercept rules = global ∪ task-level block; allow rules = task-level allow.
			blockRules, _ := t.as.ListAssetInterceptRules()
			var allowRules []db.AssetInterceptRule
			if t.taskID > 0 {
				if tb, ta, err := t.as.TaskInterceptRulesSplit(t.taskID); err == nil {
					blockRules = append(blockRules, tb...)
					allowRules = ta
				}
			}

			for i, item := range a.Assets {
				// Asset gate: intercept first, then allow — refused assets are forbidden from insertion (skip Upsert and later side-effects).
				domains, ips, urls := assetInterceptCandidates(item)
				if d := db.EvaluateAssetGate(blockRules, allowRules, domains, ips, urls); !d.Allowed {
					errs = append(errs, errEntry{
						Index: i,
						Error: fmt.Sprintf("asset %s %s — insertion forbidden", assetInputLabel(item), d.Reason),
					})
					continue
				}

				typ := strings.TrimSpace(item.Type)
				var id int64
				var err error

				// Authorization-boundary guard (v0.4.63): check identity before inserting/claiming —
				// if the asset already exists, was registered by another task, and isn't in this task's own scope, skip it —
				// preventing 'touch = auto-claim' from quietly pulling other tasks' assets into this one.
				if t.ScopeWriteGuard && taskID > 0 {
					gd, gi, gu := assetInterceptCandidates(item)
					if fid, owners, ferr := t.as.FindForeignAssetForTask(taskID, gd, gi, gu); ferr == nil && fid > 0 {
						errs = append(errs, errEntry{
							Index: i,
							Error: fmt.Sprintf("asset %s %s already belongs to another task (task %s) and isn't in this task's own scope — registration skipped to "+
								"prevent cross-task asset bleed. If it's genuinely within this task's authorization, add it via add_task_scope first, then retry.",
								assetInputLabel(item), identityHint(gd, gi, gu), owners),
						})
						continue
					}
				}

				switch typ {
				case "root_domain":
					id, err = t.as.UpsertRootDomain(db.UpsertRootDomainReq{
						Domain: item.Domain,
						ICP:    item.ICP,
						TaskID: taskID,
					})

				case "ip":
					id, err = t.as.UpsertIP(db.UpsertIPReq{
						IP:           item.IP,
						BoundDomains: item.BoundDomains,
						OpenPorts:    item.OpenPorts,
						TaskID:       taskID,
					})

				case "subdomain":
					id, err = t.as.UpsertSubdomain(db.UpsertSubdomainReq{
						Domain:      item.Domain,
						RecordType:  item.RecordType,
						RecordValue: item.RecordValue,
						ICP:         item.ICP,
						TaskID:      taskID,
					})

				case "app":
					id, err = t.as.UpsertApp(db.UpsertAppReq{
						Name:        item.AppName,
						BundleID:    item.BundleID,
						Category:    item.Category,
						Description: item.Description,
						ICP:         item.AppICP,
						CompanyID:   item.CompanyID,
						TaskID:      taskID,
					})

				case "service":
					// distinguish HTTP vs other by presence of url
					if item.URL != "" {
						// agent may send "ip" or "service_ip" for the enrichment IP; accept both
						svcIP := item.ServiceIP
						if svcIP == "" {
							svcIP = item.IP
						}
						id, err = t.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
							URL:           item.URL,
							Technologies:  item.Technologies,
							StatusCode:    item.StatusCode,
							ContentLength: item.ContentLength,
							PageTitle:     item.PageTitle,
							FaviconMMH3:   item.FaviconMMH3,
							Auth:          item.Auth,
							IP:            svcIP,
							TaskID:        taskID,
						})
					} else {
						id, err = t.as.UpsertOtherService(db.UpsertOtherServiceReq{
							Domain:      item.Domain,
							IP:          item.IP,
							Port:        item.Port,
							ServiceName: item.ServiceName,
							Auth:        item.Auth,
							TaskID:      taskID,
						})
					}

				case "endpoint":
					id, err = t.as.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    item.URL,
						Method: item.Method,
						Params: item.Params,
						IP:     item.ServiceIP,
						TaskID: taskID,
					})

				default:
					errs = append(errs, errEntry{Index: i, Error: "unknown type: " + typ})
					continue
				}

				if err != nil {
					errs = append(errs, errEntry{Index: i, Error: err.Error()})
					continue
				}
				results = append(results, result{Index: i, ID: id, Type: typ})
				t.writes.Assets++
				t.anchorOwner(id)
				if taskID > 0 {
					var sourceNodeID *int64
					if t.ownerNode > 0 {
						nodeID := t.ownerNode
						sourceNodeID = &nodeID
					}
					summary := "Registered by the Agent via insert_assets"
					if t.ownerNode > 0 {
						summary = fmt.Sprintf("Registered by worker intent #%d via insert_assets", t.ownerNode)
					}
					_ = t.as.SetTaskAssetSource(taskID, id, "agent", summary, sourceNodeID)
				}
				// Auto-add to test scope (source='auto'): only for the worker's top-level explicitly inserted item, scoped
				// conservatively by its type; side-effect-derived assets don't pass through here, so scope doesn't blindly widen. No-op when taskID=0.
				// Independent of the coverage toggle: task_scope is the task's scope boundary (the filter base of list/query),
				// while the coverage toggle only decides whether to use it as the metric denominator — not whether scope itself accumulates.
				{
					svcIP := item.ServiceIP
					if svcIP == "" {
						svcIP = item.IP
					}
					_ = t.as.AddAutoScope(taskID, typ, item.Domain, item.URL, svcIP)
				}
			}

			return jsonResult(map[string]any{
				"results": results,
				"errors":  errs,
			})
		},
	)
}

// addCompanyScope writes to company_scope table and triggers asset attribution.
func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"Adds domains/IPs/CIDRs/ICP registrations/company keywords into a company's [asset scope] — domains, networks and ICPs auto-claim matching assets; keywords only serve as scope hints for the Agent.\n"+
			"Company names are unique: a nonexistent company is created, an existing one is reused (scope is merged in).\n"+
			"scope: one entry per line, auto-recognized: root domain / URL / single IP / CIDR range / ICP registration / company keyword.\n"+
			"Always give a reason citing attribution grounds (whois/cert/ASN etc.).\n"+
			"Guardrails: bare TLDs and over-wide ranges are refused (IPv4 prefixes must be /16-/32, IPv6 /32-/128); illegal lines are skipped and returned in errors.",
		obj(map[string]any{
			"company": str("company name (created if nonexistent, reused if exists; names are unique)"),
			"scope":   str("asset scope, one per line: domain / URL / IP / CIDR / ICP registration / company keyword"),
			"reason":  str("attribution grounds (evidence/source) — required"),
			"logo":    str("company icon URL (optional; only effective when creating a company)"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope not enabled: CompanyStore not initialized"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company must not be empty"), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("failed to create/get company: " + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

// addTaskScope lets the plan agent add test scope to THE CURRENT TASK — the coverage
// denominator and the task's authorization edge. Worker discoveries are auto-scoped
// (precise host) by insertAssets; this tool is for DELIBERATELY WIDENING: pull a whole
// root domain or whole company into scope, or add a specific subdomain / ip.
func (t *ToolSet) addTaskScope() actool.CoreTool {
	return writeTool(
		"add_task_scope",
		"Adds test scope to [this task] — this is the task's authorization boundary and the asset-test coverage denominator.\n"+
			"kind supports: company (all assets under a company) / root_domain (a whole root domain incl. all subdomains) / subdomain (one exact subdomain) / ip / cidr / icp / keyword.\n"+
			"Note: hosts a worker touches one by one are [auto]-added to scope by the system (exact subdomains); this tool is for [proactively widening] — pulling in a whole root domain/company, or specifying a subdomain/IP.\n"+
			"value: company takes a name or id (the company must exist); root_domain/subdomain take a domain; ip/cidr take an IP or range; icp/keyword take a registration number or company keyword.\n"+
			"Always give a reason citing grounds (auditable). Multiple entries via the entries array.",
		obj(map[string]any{
			"entries": map[string]any{"type": "array", "description": "batch: [{kind, value}]. kind∈company/root_domain/subdomain/ip/cidr/icp/keyword.", "items": map[string]any{"type": "object"}},
			"kind":    str("[single] company / root_domain / subdomain / ip / cidr / icp / keyword"),
			"value":   str("[single] company name or id / domain / IP / CIDR / ICP / keyword"),
			"reason":  str("grounds for adding (for audit) — required"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("add_task_scope not enabled: AssetStore not initialized"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("add_task_scope requires task context (no task currently)"), nil
			}
			type scopeEntry struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			var a struct {
				Entries    []scopeEntry `json:"entries"`
				scopeEntry              // single mode
				Reason     string       `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			items := a.Entries
			if len(items) == 0 {
				items = []scopeEntry{a.scopeEntry}
			}
			var added []map[string]any
			errs := map[string]string{}
			for i, e := range items {
				ts, err := t.as.AddAgentScope(t.taskID, strings.TrimSpace(e.Kind), e.Value, a.Reason, "agent")
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				added = append(added, map[string]any{"kind": ts.Kind, "domain": ts.Domain, "net": ts.Net, "value": ts.Value, "company_id": ts.CompanyID})
			}
			out := map[string]any{"added": added}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		},
	)
}

// listUntestedAssets lets the plan agent pull the current + directly inherited
// scope's not-yet-tested assets on demand (filter by type, paginated).
func (t *ToolSet) listUntestedAssets() actool.CoreTool {
	return readTool(
		"list_untested_assets",
		"Queries assets inside [this task's and directly related tasks'] scope not yet covered by fact anchors (related scope is read-only — it informs your own decision on what to fill, it doesn't decide for you).\n"+
			"Optional asset-type filter: root_domain/subdomain/service/app/endpoint/ip.\n"+
			"Pagination: page starts at 1, page_size defaults to 10. Returns {assets:[{id,type,label}], total, page, page_size}. Task context only.",
		obj(map[string]any{
			"type":      str("asset-type filter (optional): root_domain/subdomain/service/app/endpoint/ip"),
			"page":      intp("page number, starting at 1 (default 1)"),
			"page_size": intp("items per page (default 10)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_untested_assets not enabled: AssetStore not initialized"), nil
			}
			if t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("list_untested_assets requires task context"), nil
			}
			var a struct {
				Type     string `json:"type"`
				Page     int    `json:"page"`
				PageSize int    `json:"page_size"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Page <= 0 {
				a.Page = 1
			}
			if a.PageSize <= 0 {
				a.PageSize = 10
			}
			offset := (a.Page - 1) * a.PageSize
			assets, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, strings.TrimSpace(a.Type), a.PageSize, offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"assets": assets, "total": total, "page": a.Page, "page_size": a.PageSize,
			})
		},
	)
}

// dslHint turns a DSL error into an actionable correction. The DSL error text
// alone leaves the agent guessing the same wrong syntax again (observed: 42
// failed list_assets calls, most of them the same "ip doesn't support >="
// mistake, because nothing told it that CIDR lookups go through cidr=...).
func dslHint(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "does not support operator"):
		return "hint: string fields (ip/domain/url etc.) only support = == != (fuzzy/exact/exclude) — not > >= < <=; " +
			"to compare numerically use numeric fields (port/status_code); to query a range use cidr=10.10.0.0/16."
	case strings.Contains(errMsg, "DSL syntax error"):
		return "hint: expressions look like field=value, combined with AND/OR and grouped with parens; no spaces between field and operator; " +
			"quote values containing spaces or special chars."
	case strings.Contains(errMsg, "unknown field"):
		return "hint: available fields: domain, root_domain, ip, cidr, url, page_title, icp, service_name, " +
			"app_name, method, service_type, record_type, technology, port, status_code, company_id, task_id."
	case strings.Contains(errMsg, "requires an integer value"):
		return "hint: port/status_code/company_id are integers — write port==443 (use == or =, no quotes)."
	case strings.Contains(errMsg, "cidr"):
		return "hint: cidr must be a range, e.g. 10.10.0.0/16."
	}
	return "hint: DSL looks like field=value; multiple conditions joined by AND/OR. The field list is in this tool's description."
}

// listAssets lets an agent query the asset table.
func (t *ToolSet) listAssets() actool.CoreTool {
	return readTool(
		"list_assets",
		"Queries the asset store: DSL-expression search, or direct fetch by id/ids; paginated. Only returns assets inside [this task's and directly related tasks'] test scope.\n"+
			"DSL: field=value fuzzy (ILIKE) | field==value exact | field!=value exclude | numeric fields support > >= < <= | bare word = full-text fuzzy; AND/OR combine (AND binds tighter), parens group. Asset type uses the separate type param, not DSL.\n"+
			"Without id/ids, dsl must be non-empty (unconditional full queries are refused).\n"+
			"Available fields: domain (root/sub/service domains), root_domain, ip, cidr (a range like 10.10.0.0/16), url, page_title, icp, service_name, app_name, method (e.g. GET/POST), service_type (http|other), record_type (e.g. A/CNAME), technology (array — = fuzzy, == exact), port/status_code/company_id (integers).\n"+
			"**For a range query use cidr=10.10.0.0/16, not ip>=10.0.0.0** (ip is a string field — no ordering comparisons).\n"+
			"**For empty values use field==\"\"** (exact match — covers both '' and NULL); = is fuzzy and can't find empties. "+
			"To find 'registered but untested' assets, use list_untested_assets (typed pagination — easier than hand-building DSL).\n"+
			"Examples: cidr=10.10.0.0/16 ; status_code>=400 AND technology=shiro ; (port==80 OR port==443) AND technology=nginx ; service_name==\"\"",
		obj(map[string]any{
			"dsl":    str(`DSL query expression (syntax/fields in the tool description). Must be non-empty without id/ids.`),
			"type":   str("asset-type filter: root_domain|ip|subdomain|app|service|endpoint (standalone field, stackable with dsl; a bare type isn't enough — dsl is still required)"),
			"id":     intp("fetch one asset by id directly (optional, mutually exclusive with dsl/type)"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "fetch multiple assets by ids directly (optional, mutually exclusive with dsl/type)"},
			"limit":  intp("return cap, default 10 (optional)"),
			"offset": intp("pagination offset, default 0 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_assets not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var assets []*db.Asset
			var err error
			switch {
			case a.ID > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				assets, err = t.as.QueryDSLInScope(a.DSL, a.Type, t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("without id/ids, dsl must not be empty: unconditional full-asset queries aren't allowed — provide query conditions"), nil
			}
			if err != nil {
				// DSL errors must be **actionable**: replying only 'DSL error: string field ip doesn't support operator >='
				// makes the agent guess the same wrong syntax again (measured: 42 such errors). Appending a
				// 'correct spelling' hint lets the agent self-correct.
				return actool.Errorf("DSL error: " + err.Error() + "\n" + dslHint(err.Error())), nil
			}
			return jsonResult(map[string]any{
				"count":  len(assets),
				"assets": assets,
			})
		},
	)
}

// listCompanies lets an agent enumerate companies with their scope + asset count.
func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"Lists the [companies] in the asset store with their asset scope and attributed-asset counts. For viewing companies "+
			"and getting company_id (used by insert_assets linking apps and list_assets filtering by company_id). "+
			"Optional search fuzzy-filters by company name (case-insensitive); empty returns all.",
		obj(map[string]any{
			"search": str("fuzzy-filter by company name (optional, case-insensitive); empty returns all"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies not enabled: CompanyStore not initialized"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("failed to query companies: " + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID         int64    `json:"id"`
				Name       string   `json:"name"`
				AssetCount int      `json:"asset_count"`
				Scope      []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, AssetCount: c.AssetCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

// splitLines splits a multi-line string into non-empty trimmed lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// WorkerTools returns the tool set for a work agent.
func (t *ToolSet) WorkerTools() []actool.CoreTool {
	return []actool.CoreTool{
		// list_findings kept: check this task's confirmed vulns before reporting, avoiding duplicate reports.
		t.listFindings(),
		t.addFinding(), t.recordFact(),
		// asset management (handlers guard nil store internally).
		// add_company_scope not for workers: defining company asset scope is planning/main-control/Auto's job — workers only execute explorations.
		t.insertAssets(), t.listAssets(),
		// cross-work look-back: workers can also reuse other works' observations, avoiding duplicate labor.
		// search_all_worker_traces: no need to know intent_id — keyword-dredges hit steps globally;
		// get_worker_trace: after locking a work, lists steps / searches in place / fetches full content.
		t.searchAllWorkerTraces(), t.getWorkerTrace(),
		// node_detail: a worker with an intent_id/node id can query that node's full details (pairs with the look-back above).
		t.nodeDetail(),
		// expand_digest (v0.4.50): a worker can expand cold-zone-folded nodes' full content —
		// previously workers only saw title/summary, with folded content invisible to them.
		t.expandDigest(),
		// list_untested_assets (v0.4.50): workers should also know which assets are untested —
		// fills gaps on its own during asset-traversal intents.
		t.listUntestedAssets(),
		// list_goals (v0.4.50): a worker knowing goal progress helps judge whether a direction is worth deepening.
		t.listGoals(),
		// search_vulns / get_vuln: after identifying the target component+version, query known vulns and
		// affected ranges directly — public intel beats inventing payloads.
		t.searchVulns(), t.getVuln(), t.getPoc(), t.scanWithNuclei(), t.netContext(),
		// listener_*: reverse-connection receivers (red-team C2 front-end) — start/stop go through ask approval, sessions is read-only.
		t.listenerStart(), t.listenerStop(), t.listenerSessions(),
		// http_probe (v0.4.27): batch probing domain tool — replaces hand-written curl (task 5 measured
		// Bash at 57% of tool_use, 2750 curl calls); one round-trip for a whole batch of compact digests.
		t.httpProbe(),
		// js_audit (v0.4.59): SPA/webpack frontend source-leak audit — task 18 (a Vue site) measured
		// complete missing of .js.map leaks; sourcemap restore = original source + keys + endpoint list.
		t.jsAudit(),
		// auth_request: assemble an authenticated request using credentials registered on the asset (prerequisite for lateral/privesc verification).
		t.authRequest(),
		// evidence_check (v0.4.71): re-verify whether high/critical vuln evidence supports the impact conclusion (13 checks + src_ready).
		t.evidenceCheck(),
		// native HTTP executor + session reuse (red-team v0.7.0 delegation): send requests directly for structured results,
		// login state lands in the task-level cookie jar, reused across intents — 'login → privesc → readback' becomes a base capability.
		t.httpRequest(), t.sessionLogin(),
		// PoC scaffolding (red-team v0.7.0 delegation): generates runnable verification skeletons by class.
		t.pocScaffold(),
		// task-level background jobs (red-team v0.7.0 delegation): long scans survive across intents.
		t.jobStart(), t.jobStatus(), t.jobOutput(), t.jobStop(),
		// task-level shared scripts (red-team v0.7.0 delegation): login scripts/PoCs reused across intents.
		t.saveScript(), t.runScript(),
		// diff_responses: compare two responses' structural differences (common base for privesc/enumerable/state-machine classes).
		t.diffResponses(),
		// api_contract: read the API contract files a target exposes — a more precise endpoint list than crawling.
		t.apiContractTool(),
		// search_recent_critical: query recently disclosed critical vulns by [time] (no need to know the component/CVE first).
		t.searchRecentCritical(),
		// save_evidence / list_artifacts: evidence attachments (v0.5.0) — screenshots/data samples/logs
		// persisted and registered, exported as an evidence bundle with the report; referenced in reports via ![caption](artifact:<id>).
		t.saveEvidence(), t.listArtifacts(),
		// The following tools still [don't go to] workers — planner/main only (reading context and cross-work review are planning duties;
		// a worker only executes and writes back a single intent): list_facts / list_companies / list_worker_traces.
	}
}

// MainAgentTools returns the human-interface tool set.
func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.expandDigest(), // cold-digest §6.1
		// list_worker_traces: work index (intent_id+summary+state) — discover first, then read via
		// get_worker_trace — planner/main's cross-work review entry (not for workers, see below).
		t.listWorkerTraces(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),
		// steer_work: a human can inject live course-correction into a running intent (work) — no interruption, no lost progress.
		t.steerWorkTool(),
		// set_goals: a human can add a new final goal to this task at runtime (the planner re-judges attainment accordingly).
		t.setGoals(),
		// set_constraints: a human can add/edit operation constraints (allow/deny) for this task at runtime — bounds planner/worker exploration.
		t.setConstraints(),
		// asset management (handlers guard nil store internally)
		t.insertAssets(), t.addCompanyScope(), t.listAssets(),
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),
		// list_untested_assets: query this task's in-scope untested assets on demand (typed + paginated) and decide what to fill.
		t.listUntestedAssets(),
		// search_vulns / get_vuln: a human in the loop can also query public known-vuln intel directly.
		t.searchVulns(), t.getVuln(), t.getPoc(), t.scanWithNuclei(), t.netContext(),
		// http_probe (v0.4.27): batch probing domain tool (same for mainagent and worker).
		t.httpProbe(),
		// js_audit (v0.4.59): SPA/webpack source-leak audit (same for mainagent and worker).
		t.jsAudit(),
		// listener_*: reverse-connection receivers (red-team C2 front-end) — start/stop go through ask approval, sessions is read-only.
		t.listenerStart(), t.listenerStop(), t.listenerSessions(),
		// auth_request: assemble an authenticated request using credentials registered on the asset (prerequisite for lateral/privesc verification).
		t.authRequest(),
		t.httpRequest(), t.sessionLogin(),
		t.diffResponses(),
		// api_contract: read the API contract files a target exposes — a more precise endpoint list than crawling.
		t.apiContractTool(),
		// search_recent_critical: query recently disclosed critical vulns by [time] (no need to know the component/CVE first).
		t.searchRecentCritical(),
	}
}

// AllDomainTools returns the union of all domain tools across all agent types,
// deduped by name (mainagent order wins). Used by the server to build a registry
// for injecting domain tools into agents (Auto, custom) that don't own a per-task
// ToolSet. The caller provides real stores; tools are callable at taskID=0 scope.
func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}
