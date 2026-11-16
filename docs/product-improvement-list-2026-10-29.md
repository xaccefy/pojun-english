# Product Optimization List (PM view)

> 2026-10-29 (around v0.3.86). Sources: a full-repo audit (designed but not implemented / not wired / never ran)
> + a tool-installation-path investigation + a product-view inventory of additions, removals and changes. This document
> is a roadmap, not a change log (see CHANGELOG for the change log).

## 1. Landed this round (v0.3.86)

| Category | Item | Notes |
|---|---|---|
| Optimization | **One-click install of all host tools** | Backend `POST /api/hostenv/install-batch` (per-item validation, rejected items carry a reason, helper queues serially) + frontend "Install all missing (N)" / per-group "Install this group" / multi-task tab progress panel. Previously only one at a time |
| Removal | listener dead-code chain | The `listener/` placeholder stub (never bound a port) + built-in rules that could never match + derived variables + seed whitelist injection |
| Removal | Orphan settings keys | `web_shell_enabled`, `c2_enabled` (the Manager has read/write functions but zero consumers and zero UI, never wired) |

## 2. Found by the audit but not done (ordered by value)

### A. Should be implemented (designed but never ran)

| # | Item | Current state | Recommendation |
|---|---|---|---|
| A1 | **Reverse-connection listener** | Placeholder stub deleted | Reverse-shell callbacks are a real need for a pentest platform, but it deserves a **proper design** rather than a 52-line stub: listening ports/protocols (TCP/SMB/LDAP), sessions attributed per task, the relationship with firewall/Docker port mapping, a session interaction UI. Design the interception rules and approval flow before building it (exactly what the original ask rule wanted to govern). Schedule after the G series |
| A2 | **GHSA CWE stored but skill linkage only in tool output** | v0.3.84 added `related_skills` injection, but the planner prompt never mentions the field | Add one line to the worker/planner prompts: "when search_vulns/get_vuln returns related_skills, load the corresponding skill before digging deeper" — one sentence of cost to close the last inch |

### B. Should be optimized (implemented, but experience/efficiency has rough edges)

| # | Item | Current state | Recommendation |
|---|---|---|---|
| B1 | **Install-proxy required-ness experience** | On machines in China without a proxy, apt installs fine but every GitHub-hosted tool fails, with the failure buried in task logs | When hostenvInstall handles a github-type tool and the proxy is empty, warn up front: "no install proxy configured, GitHub downloads will most likely fail" |
| B2 | **Batch-install failure retry** | After a batch run, failed items can only be retried by clicking through another round | Put a "Retry failed items" button in the completion toast (the data is all in skipped/failed) |
| B3 | **Health page only shows presence, not version** | `available=true` but a stale version (e.g. nuclei templates not updated in six months) is invisible | Add a `version` field to the Tool DTO and show it on the health page; when the template tree exists, show the last commit date |
| B4 | **No preview of a task template's interception rules** | Rules take effect immediately after choosing a template; you cannot see what will be blocked | Show a rule summary where the template is selected |
| B5 | **No memory of notification-channel test-button state** | Test send success/failure is not recorded in history | Deliveries history already exists; add a "most recent test result" column |
| B6 | **hostd enqueue does not deduplicate** | Measured on Kali: the batch endpoint fired twice by accident and 52 tasks for the same tool were enqueued (apt/pip are idempotent so harmless, but it doubles the time) | On Start(), look for a queued/running task with the same tool_id and return the existing job |

### C. Should be removed (redundant)

| # | Item | Reason |
|---|---|---|
| C1 | Leftover `listener_*` in `intercept_enabled_tools` on deployed instances | The tool no longer exists, so the whitelist entry is dead config. **Not touching it** (modifying users' persisted data violates migration discipline); recorded only |
| C2 | Two flaky tests in the server package (ChatMention timing / TempDir race) | Occasionally red on full runs, requiring manual re-checks every time. Worth half an hour each on timing hardening (wider deadline / temp-dir retry) to remove the ongoing mental tax |

## 3. PM view: new feature suggestions (ordered by marginal cost given data/capabilities the platform already has)

| # | Feature | Why it's worth it | Marginal cost |
|---|---|---|---|
| P1 | **Cost-per-unit-discovery view** | llm_usage already aggregates full data by intent; all that's missing is a report of "how many tokens/money each finding cost". The most intuitive metric for proving platform value to a boss or client | Low |
| P2 | **Finding retest reports in the Word export** | The retest loop's (present before v0.3.83) historical conclusions are only visible online; client delivery needs Word. All the data is in finding_retests | Low |
| P3 | **Expiry reminder for the asset auth field** | `auth_request` depends on credentials registered on the asset; after a credential change the agent fails repeatedly and wastes turns. Tag auth data "likely stale" based on recent failure counts | Low |
| P4 | **Task retrospective page (timeline)** | The dual-graph data is complete; what's missing is a compact "time x intent/fact/finding" timeline so "what this task did and where it got stuck" is visible at a glance | Medium |
| P5 | **Interception rule hit statistics** | The interception history data is all there; what's missing is hit counts aggregated by rule — users should know which rule blocks every day (tighten it or allow it) | Low |
| P6 | **Second batch of the M list** (capability comparison doc §5) | Tri-state closure (M11) remains the biggest credibility gap; LLM loop detection (M4) treats "writes back but spins in place" | Medium-high |

## 4. Deliberately not doing (recorded decisions)

- **Reimplementing listener**: see A1 — worth doing, but do it right (proper design), not a half-product.
- **Cleaning up `listener_*` whitelist leftovers on deployed instances**: modifying users' persisted data violates migration discipline.
- **Frontend lint in CI**: the 75 existing errors are behavioural fixes (empty catch/await), worth a dedicated effort rather than being fixed in passing (large blast radius, high regression risk).
