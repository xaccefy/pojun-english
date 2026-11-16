# ARTEX Full Product Health Report (2026-10-31)

> Four parallel lines of research: (1) 25 frontend pages + 10 task tabs (2) 285 backend HTTP APIs (3) the whole agent chain
> (4) reconciliation against five historical PM documents. This document is this round's summary and action list, **with file:line evidence**,
> complementary to (not replacing) [Product Optimization List 2026-10-29](product-optimization-list-2026-10-29.md) / [Red Team Capability Building 2026-10-30](red-team-capability-building-2026-10-30.md).

## 1. Conclusion at a glance

| Dimension | Findings |
|---|---|
| P0 defects | **11** (§2; all small fixes, recommend closing them in one release) |
| New feature opportunities | **15+** (§3, red team main line first) |
| Experience optimizations | **14** (§4) |
| Redundancy cleanup | **10 categories** (§5, including 6719 lines of leftover mock code) |
| Security flags | 6 (§6, recorded, not urgent) |
| Document reconciliation | none of the five historical documents makes a false claim; 3 facts are stale and need fixing (§7) |

**What is done well (spot-checked, to avoid only listing faults)**: bcrypt + two-tier login rate limiting, JWT key rotation on password change,
MaxBytesReader + path sanitization + zip whitelist on the upload surface, fully parameterized SQL, masked echo of C2/intel credentials,
no race gap in CAS intent claiming/terminal transitions, and the five PM documents are highly consistent with the code.

---

## 2. P0 defect list (must-fix next release)

### Frontend (3)

| # | Defect | Location | Fix |
|---|---|---|---|
| F1 | **No confirmation family for B2-level deletes**: deleting an MCP server/LLM config/custom tool/notification channel is all single-click | `web/src/app/(main)/system/mcp/page.tsx:202`, `system/llm/page.tsx:872`, `system/tools/page.tsx:646`, `system/notify/page.tsx:215` | Add a confirmation dialog uniformly (aligning with tasks/vulnerabilities/assets) |
| F2 | **Login failure reasons swallowed**: network down/500/account lock all misreport as "wrong username or password" | `web/src/app/(auth)/login/page.tsx:79-80` | Differentiate copy by HTTP status/error body (including remaining lock time) |
| F3 | **llm-records filter changes do not reset the page number**: the comment says to reset but the dependency array is empty | `web/src/app/(main)/function/llm-records/page.tsx:191-193` | Add the dependency |

### Agent chain (5)

| # | Defect | Location | Fix |
|---|---|---|---|
| A1 | **`list_worker_traces` is registered in none of the three tool lists** — the same class of bug as the v0.3.87 listener missing registration (implementation/docs/lists mutually exclusive) | `agent/tools.go:2214`; lists at tools.go:2268 / tools_insert.go:673,706 | Decide ownership (mainagent side), register it, and sync BuiltinToolSeeds (toolcatalog.go:34) |
| A2 | **`expand_digest`, a pure-read tool, registered with writeExpTool**: loses the ReadOnly/Concurrent flags and gets serialized by the scheduler | `agent/tools_digest.go:121` | Switch to readExpTool |
| A3 | **The stall wrap-up hint steers the model to call a non-existent `finish_task`** (it is actually `goal_met`) — eating a tool error exactly at wrap-up time | `agent/tools.go:2323` | One-line copy change |
| A4 | **The planner prompt promises a non-existent overview field `sites_without_endpoints`**, and list_assets' parameter description is stale (q/company_id vs the actual dsl/type/ids) | `agent/planner.go:309,313` | Align with graphOverviewData's actual output |
| A5 | **The final planning round has no wall clock**: `runFinalPlannerRound` calls Plan synchronously with no deadline in fctx — a hang from the same source leaves settleTask stuck in settling forever (same class as the already-fixed plannerRoundTimeout) | `server/engine_timeout.go:270` vs `engine.go:845/972-1002` | Reuse runPlannerRound's goroutine + timeout wrapper |

### Backend (3)

| # | Defect | Location | Fix |
|---|---|---|---|
| S1 | **C2 config writes fail silently**: `_ = s.m.pg.SetSetting(...)` swallows the error | `server/c2_relay.go:271-277` | Return 500 + log |
| S2 | **ask approvals can wait forever**: when a rule declares no timeout, HandleAsk blocks indefinitely, so an absent operator leaves the worker hung until task timeout | `intercept/intercept.go:788-796` | Add a global default (e.g. blocked after 6h plus a notification), overridable in system settings |
| S3 | **`goal_met` passes through with zero control**: one sentence ends the entire task, and it is not in the interception tool set | `agent/tools.go:1351`; `intercept/intercept.go:144-149` | Add it to the configurable interception tool set + a built-in judge rule "wrap-up must check quantified acceptance" (default allow, giving an audit hook) |

---

## 3. New feature suggestions (ordered by red team value x implementation cost)

### 3.1 Red team main line (aligned with the "sharper and sharper" direction)

| # | Feature | Notes | Cost | Value |
|---|---|---|---|---|
| N1 | **Listener & C2 management page** | All 6 backend APIs exist (4 listeners + 2 c2, server.go:864-869) but **the frontend has zero entry points** — core red team capability is completely invisible in the UI. Page: listener list/start-stop/session capture viewing + a three-shape C2 egress form (masked echo) | Low (frontend only) | Extremely high |
| N2 | **scope-aware interception rules** | ruleMatches is pure string matching today (intercept/intercept.go:690-701); passing task_scope/the asset table into Match would allow rules like "deny any out-of-scope domain" — and also closes the window where "tightening the authorization boundary mid-task does not re-check running intents" (tools.go:1187 only gates at write time) | Medium | High |
| N3 | **`http_replay` domain tool** | Pick a recorded request from traffic_* and replay it with changed parameters/identity — the atomic operation of authz testing, reusing auth_request/diff_responses' "assemble commands and go through Bash" pattern and the approval chain | Medium | High |
| N4 | **api-authz skill** | Chain api_contract (get the inventory) -> auth_request (two identities) -> diff_responses (judge the difference) into a methodology; the CWE->skill index (tools_vulnintel.go:41) is ready, so tagging CWE-862/639 links it up | Low | Medium-high |
| N5 | **Guard.Attributions fed back to planner** | guard/guard.go:189 already counts blocked/error/ok but never feeds it back — fold it into graph_overview's stall block so the planner can see "blocked by WAF 40 times" and change tactics (the last mile of the half-finished Observer) | Low | High |
| N6 | **Post-exploitation chain intent template** (red team roadmap 1) | The planner todolist already supports serial chains — add a "get a shell -> privesc enumeration -> credentials -> lateral" template for semi-automatic attack-chain unfolding | Medium | High |
| N7 | **Intent-level token budget** | TokenStatsByWorker already has per-intent accounting (db/exploration.go:1544); wire it into idleStop criteria (currently only rounds + wall clock) to plug "high-frequency low-yield rounds" | Medium | Medium |

### 3.2 Next batch (information surface / delivery surface / original roadmap)

| # | Feature | Notes |
|---|---|---|
| N8 | Cost-per-unit-discovery view (PM P1 / M19) | An efficiency panel of token spend x findings count; add a card to the dashboard |
| N9 | frontier aging | Under a fixed priority DESC ordering low-priority intents can starve indefinitely (db/exploration.go:1264); add an age term |
| N10 | stopped-intent audit window | graph_overview only collects done/blocked/exhausted (tools.go:499), so killed ones vanish from the overview — add a killed count window so kill_work stop-losses can be reviewed |
| N11 | Retest conclusions in the Word report (PM P2) | report/ currently does not consume retests |
| N12 | Interception rule hit statistics (PM P5) | Aggregate hits per rule so the approvals page shows directly which rule is blocking |
| N13 | Task retrospective timeline (PM P4) | Replay intents/facts/findings along a timeline |
| N14 | MCP egress M25 | Expose the hostd tool catalog as an MCP server so external AI agents can drive ARTEX |
| N15 | Windows post-exploitation pack / sliver bridge / red team report template | Original roadmap 2/3/5 |

---

## 4. Experience optimization list

**Process level (P1)**

| # | Item | Location |
|---|---|---|
| O1 | **No cold-start guidance**: the first login shows an empty task list with no "configure an LLM first" hint; creating a task allows submitting with an empty LLM config chain and only fails once running | tasks/page.tsx:3167, llm/page.tsx:449 |
| O2 | **8+ independent save buttons on the settings page**: no dirty indication, invisible to each other, very easy to miss a save | system/settings/page.tsx:85-268 |
| O3 | **The interception entry point has three names in three places**: sidebar "approval records" / task tab "interception approvals" / embedded in chat — the same component under three titles | sidebar-items.ts:98, detail/page.tsx:60 |
| O4 | **dashboard pulls everything**: api.findings() is unpaginated, so first paint slows down as findings grow | dashboard/page.tsx:191 |
| O5 | **Uploads have no progress/retry** (workspace/chat/task attachments) | workspace:148, chat:716, tasks:3158 |
| O6 | **Sync creates a data source in two stages**: create an empty source then backfill, and "activation conditions not yet met" does not explain what is missing | sync/page.tsx:112-127 |
| O7 | After changing the proxy pool you must manually "save and hot-apply" (it even toasts you to do so) | proxypool/page.tsx:173 |
| O8 | **Mobile is essentially unadapted**: the four big table pages have zero responsive classes | tasks/findings/traffic/dashboard |
| O9 | Empty/loading states are inconsistent: only 3 pages have a Skeleton, findings has no empty-state copy | site-wide |
| O10 | Polling pile-up: approvals badge 5s + dashboard + tasks 10s + job 1.2s all coexisting with no backoff | nav-main.tsx:176 etc. |

**Backend support (P1/P2)**

| # | Item |
|---|---|
| O11 | GET /api/tasks, /api/companies, /api/conversations are all unpaginated (findings/intercept already paginate and can be aligned) |
| O12 | The proxy pool health-check 3 keys (proxypool_check_target etc.) are read by the backend but have no write entry point at all (proxypool_api.go:29-31) |
| O13 | "Active task" has no explicit switch entry: POST /api/active has no UI, and multiple tasks are resolved implicitly via URL ?task= |
| O14 | Overview lineage is silently truncated: after Edges(5000)/Intent(300) limits the planner has no way to know (tools.go:462,493) — at minimum log it |

---

## 5. Redundancy cleanup list

| # | Item | Volume | Disposition |
|---|---|---|---|
| R1 | **The whole mock suite**: lib/mock/data.ts+handler.ts, only enabled by NEXT_PUBLIC_MOCK but all bundled into the production artifact | 6719 lines | Delete or exclude at build time (mock preview value vs a clean artifact) |
| R2 | 16 methods defined in api.ts with zero references (gc/audit/frontier/findingStats/tokenDaily/agentVariables etc.) | ~16 spots | Either wire them up (some correspond to §3 features) or delete |
| R3 | Dead components: date-range-picker, event-calendar-views, nav-documents/nav-secondary (already commented out), sidebar-support-card (containing a third-party template author link) + **about 20 unreferenced shadcn components** | ~25 files | Delete |
| R4 | fmtTokens x7 / fmtBytes x6 / fmtDuration x2 duplicate implementations | — | Move down into lib/format.ts |
| R5 | Two chat input implementations (the chat page Composer vs sessions-tab InputGroup), with send/stop/upload logic evolving in parallel | — | Unify into one component |
| R6 | Two user menus: top-bar AccountSwitcher (always single-user; the multi-user UI is decoration) + sidebar NavUser | — | Delete AccountSwitcher, keep the sidebar |
| R7 | Legacy APIs: GET/POST /api/llm (superseded by profiles), GET /api/logs (superseded by history+stream), 5 partially overlapping token-statistics endpoints | — | Mark deprecated, delete next release |
| R8 | Agent internals: intp/idp are the same body (tools.go:352-357), lineage edge classification switch duplicated field by field in two places (tools.go:462-474 vs 776-788), redundant relatedTaskOverviews queries (tools.go:812-828), defaultUnbound dead config + stale comment (toolcatalog.go:52-60) | — | Small refactor |
| R9 | Stale docs: tool count 54->63 (capability comparison §1), three duplicate statements that CWE is not stored (all completed by 0.3.84), wrong provenance for M25 (it comes from the vulnerability-hunting capability comparison, not the PM list) | — | Fix the docs |
| R10 | The not-found page is entirely in English + a leftover all-English support card | — | Localize; delete the third-party link |

---

## 6. Security flags (recorded, not release-blocking)

1. JWT accepts being passed in a URL query and **applies to all endpoints** (auth.go:265, to serve SSE) — recommend restricting it to SSE paths so tokens stay out of access logs
2. No CSP / HSTS (securityHeaders, server.go:4016-4028; when HTTPS terminates upstream, HSTS is added by the reverse proxy)
3. JWT double storage (localStorage + a non-HttpOnly cookie, api.ts:107-110) — risk becomes manageable once CSP exists
4. Strong-capability endpoints (custom tools = arbitrary code, hostenv package installs, update/apply, listeners start/stop) are expected to be usable under the single-admin model, but deserve a second confirmation in the UI (same batch as F1)
5. hostd enqueue deduplication only does an in-request `seen` (hostenv_api.go:189); cross-request queued/running for the same tool is not deduplicated (PM B6)
6. /api/auth/status echoes initialization state without authentication (the code comment acknowledges this; low risk, retained)

---

## 7. Reconciliation conclusions against historical PM documents

| Document | Completion | Notes |
|---|---|---|
| Product Optimization List 10-29 | 35% | 5 landed, 2 partial, 10 untouched (the whole B series of frontend experience is outstanding) |
| Red Team Capability Building 10-30 | 50% | 5/5 of the landing list delivered; 0/5 of the roadmap started |
| Project Assessment Report 10-29 | 62% | P1-P4 all fixed; most planned items untouched |
| Vulnerability Hunting Capability Comparison | 20% | First batch M1/M2/M3/M10/M14 all delivered; second/third batches untouched |
| Public Deployment Security Hardening 10-29 | 100% | All delivered |

**Three reconciliation conclusions**: (1) not a single false claim; every undelivered item is a to-do the document itself listed; (2) the red team document §4.1 did not disclose the release defect where 0.3.87's listener was not registered (fixed in 0.3.88) — future "completed" descriptions should attach verification evidence; (3) two document facts are stale (see R9) and need fixing.

---

## 8. Recommended execution batches

| Batch | Content | Output | Status |
|---|---|---|---|
| **Batch 1 (P0)** | the 11 defects in §2 | v0.3.89 | ✅ released |
| **Batch 2 (red team main line)** | N1 listener/C2 management page + S3 interception hardening + N5 Attributions feedback | v0.3.90 | ✅ released (N2 scope-aware deferred) |
| **Batch 3 (UX)** | O1 cold-start guidance + O3 naming unification + O4 dashboard pagination | v0.3.91 | ✅ released (O2/O5/O9/O10 deferred) |
| **Batch 4 (cleanup)** | R3/R6/R10 quick deletes | v0.3.92 | ✅ released (R1/R2/R4/R7/R8 deferred) |
| **Batch 5 (big features)** | N3/N4 http_replay+api-authz, N6 post-exploitation chain, N8 cost view, then N14 MCP egress | per iteration | Not started (including the deferred N2 scope-aware) |

**Release record**: v0.3.89 -> v0.3.90 -> v0.3.91 -> v0.3.92 (the four health-check batches) -> v0.3.93/94 (deep optimization phase 1 · reports) ->
v0.3.95 (deep optimization phase 2 · agent judgment). All released after passing the tsc + next build + go test (real PG) gate.
Subsequent execution follows the status table in [deep optimization plan](deep-optimization-plan-2026-10-31.md) §4.
