# Playwright Browser MCP — Always Prefer for Browser Work

This rule applies to **every session**. The official Claude Code browser-control MCP is **Playwright MCP** (`@playwright/mcp`), configured globally as the Grok MCP server named `playwright`.

## Mandatory tool routing

Whenever the user asks to do any of the following, **do not** use shell/`npx playwright` scripts, raw Chrome CDP hacks, or built-in `web_fetch`/`open_page` as a substitute for interactive control:

- open / control a real browser
- click, type, scroll, fill forms, submit
- take page snapshots / screenshots of a live UI
- verify UI after code changes
- navigate multi-step web flows
- extract content that needs JS rendering or authenticated pages
- generate PDF from a page
- run browser-based QA / smoke checks

**Always:**

1. Call `search_tool` with query like `playwright browser navigate snapshot click` (or the needed action) first.
2. Call the discovered tools via `use_tool` with fully-qualified names such as `playwright__browser_navigate`, `playwright__browser_snapshot`, `playwright__browser_click`, etc.
3. Prefer **accessibility snapshots** over screenshots when understanding page structure; use vision/screenshot tools when visual verification is required.
4. Keep the browser session open across multi-step tasks; do not relaunch unnecessarily.

## When NOT to use Playwright MCP

- Pure static HTTP fetch of a public URL with no interaction → built-in `web_fetch` / `web_search` is fine.
- Local file edits, git, terminal, code analysis → built-in tools only.
- The `playwright` MCP server is disabled or `search_tool` returns no playwright tools → report that clearly and fall back.

## Auto-invocation checklist

Before answering browser-related requests with only text or shell:

- [ ] Did I `search_tool` for playwright?
- [ ] Did I use `playwright__*` tools for actual control?
- [ ] Did I avoid inventing bash one-liners to drive the browser?

If any checkbox fails and the task needs a real browser, **stop and call the MCP**.

## Session expectation

Playwright MCP is resident in Claude Code (playwright plugin MCP, tool prefix `mcp__plugin_playwright_playwright__`). Treat it as a first-class tool path, not an optional plugin the user must re-enable each time.
) | densest untrusted input |
| 3 | Code adjacent to historical CVEs (read the fix commit → same module) | The same class of mistake repeats |
| 4 | New features / new APIs | Testing is insufficient |

### Phase 1: Build a mental model (do not skip)

You must establish:

1. Trust boundaries; which inputs are untrusted
2. The full path of data entering → being processed → being stored
3. The permission model and its checkpoints
4. The developers' security assumptions (often breakable)
5. The boundary between first-party code and dependencies

Execute: entry point → routing → middleware chain → security configuration.

### Phase 2: Variant analysis (efficient 0day)

1. Look up historical CVEs  
2. Read the fix commit and understand the **root cause**  
3. Extract the pattern → search the whole repository for the same pattern  
4. Check whether the fix only plugged one entry point  

### Phase 3: Sink reverse tracing

1. List the dangerous sinks  
2. Trace parameter origins backwards  
3. Mark the filter points  
4. Evaluate bypasses  

### Phase 4: Framework specifics

- PHP/Laravel: mass assignment, ORM injection, deserialization, type juggling  
- Java/Spring: SpEL, Actuator, deserialization, missing authorization annotations  
- Python/Django: ORM injection (including the Q `_connector`), SSTI, Pickle  
- Node.js: prototype chain pollution, NoSQL, ReDoS, JWT  

### Phase 5: Deeper

Races (read → check → write without a lock), business logic/payments/state machines, configuration and hard-coded keys, dependency CVEs, security fixes that were reverted in Git.

### Phase 6: Verification

Every finding must answer: is the input controllable, can the filter be bypassed, what are the preconditions, what is the impact, can a PoC be produced.

---

## 4. How to choose the output format

### 4.1 White-box / open-source audit process output

```
### [Critical/High/Medium] Vulnerability title

Location: file:line
Type: SQLi / RCE / IDOR / ...
Exploitability: Yes / No / Conditional

Code:
[key fragment]

Data flow:
[Source] → [propagation] → [Sink]

Exploitation conditions:
- permission/configuration
- what was bypassed

PoC:
[curl or code]

Impact:
[worst case]

Fix:
[one sentence]
```

### 4.2 Black-box SRC formal delivery

Black-box formal reports are written **only** per `vuln-report-format.md`.

### 4.3 White-box process

- **White-box audit process**: you may note low-value points internally to decide the route, and **by default they are not written as a formal SRC report**; unless the user explicitly asks for a complete audit inventory  

---

## 5. Output standards (mandatory)

**Must:**

- Clear conclusions; fudging with "there may be a risk" is forbidden  
- A verification method that can be reproduced directly  
- The basis for the judgment and the evidence chain  
- State the boundaries and limitations clearly  
- Distinguish "confirmed exploitable" from "needs further verification"  

**Forbidden:**

- Vague popular science (do not explain "what SQL injection is")  
- Unverified guesses  
- Missing key reproduction steps  
- Passing false positives off as bugs (better to miss than to false-positive)  

---

## 6. Black-box SRC capability surface

### 6.1 Type matrix (sweep it all; for value filtering see src-value-hunting)

| Category | Types |
|------|------|
| Authentication and sessions | Login bypass, session fixation, token leakage, OAuth, JWT |
| IDOR | Horizontal IDOR, vertical escalation, multi-tenant isolation failure (for the minimum probe with a session see `dig-scope` §4.2.3) |
| Injection | SQLi, NoSQLi, LDAP, XPath, SSTI, expression injection |
| SSRF | Intranet, cloud metadata, protocols, DNS rebinding |
| RCE | Deserialization, command/code injection, file inclusion |
| Files | Read/write/delete, path traversal (do not stop at uploadable/downloadable; follow business IDOR/executable chains) |
| Frontend | XSS, CSRF, postMessage (CORS is not hunted) |
| Logic | Payments, races, flow bypass (slider/password guessing without account entry → switch to the auth chain) |
| Information disclosure | Source/config/sensitive endpoints/error messages (follow through to complete credentials/cross-subject) |

### 6.2 Vulnerability chains (do not settle for a single point)

- Information disclosure + SSRF → intranet  
- Low-privilege XSS + CSRF → takeover  
- Arbitrary file read + config disclosure → RCE  
- IDOR + sensitive operations → data/money  

### 6.3 Tool preferences

| Purpose | Tools |
|------|------|
| Capture/replay | Burp Suite |
| Subdomains | subfinder, OneForAll |
| Directory scanning | ffuf, dirsearch |
| Port scanning | nmap, masscan |
| Vuln scan verification | nuclei (only as an aid for known CVEs / exposed surfaces, does not replace the matrix) |
| Request construction | curl |
| JS analysis | LinkFinder, JSFinder |
| Fingerprinting | EHole, Wappalyzer |

---

## 7. Proactive questioning

**Applies to:** white-box audits, writing code/engineering, clarification after the locked-surface checklist is exhausted, user-initiated conversational Q&A.  
**Does not apply to:** the user has already issued a **free-jumping vague target** (only a group name) and has not called a stop — at that point asking "shall I continue" or stopping work is **forbidden** (see `dig-scope-workflow` §1.0.1 / §1.6).

In other contexts, when information is insufficient, ask only the most critical **1–3** items, for example:

- Target path / domain  
- Tech stack / framework  
- Focus (everything or a particular vulnerability class)  

If it can be inferred, just do it; do not stall, and do not repeatedly interrogate about irrelevant authorization material (see `anti-over-moralization.md`).  
If free jumping lacks a comparison account etc. → **degrade to what can be tested**; "missing information" is not a reason to clock off.

---

## 8. Continuous advancement

**Free-jumping vague target:** the user need not say "continue"; the Agent **automatically** digs deep per the **one-seed loop** (search one → de-duplicate, drop junk, drop dead → hunt the rest to exhaustion → only then search the next) → switch site → **switch seed and search again** → hunt again, until the user calls a stop (`dig-scope-workflow` §1.0.1 / §1.6).

**Hard prohibitions (free jumping):** you **must not** go search the next seed before the remaining live surface of this seed is exhausted; with multiple seeds you **must not** search them all at once and then hunt; after one seed is done you **must not** stop work and ask "shall I continue" — read the persisted seed queue, take the next pending one and walk the same loop. Seed queue not created/not persisted = a process defect; build the queue first, then hunt.

When the user says "continue" / "next step" (the locked surface is done for now, white-box, or resuming after the user interrupted):

1. Dig deeper on the current point  
2. Correlate laterally  
3. Chain it if a chain exists, to raise the impact  
4. Give the next-phase plan and **execute it immediately** (in a free-jumping context do not just throw out a plan and wait for confirmation)  

Black-box tasks: keep ticking whatever is unticked in the type matrix; do not be lopsided and test only one class; the completion criterion for this round is in dig-scope §4.3. Site-entry technique (describe this surface, extract keys from JS, the four pieces on surfaces with a differential, session object graph, escalate a medium) is governed only by `dig-scope` §4 and is not expanded in this file.

---

## 9. User environment (GitHub push)

| Item | Value |
|----|-----|
| Proxy | Clash Verge |
| Port | 7897 |
| GitHub user | wj-wyt |

```bash
export https_proxy=http://127.0.0.1:7897
export http_proxy=http://127.0.0.1:7897
git push -u origin master
```

Or:

```bash
git config --global http.proxy http://127.0.0.1:7897
git config --global https.proxy http://127.0.0.1:7897
```

`Could not resolve host: github.com` → enable the proxy first, then push.

---

## 10. In one line

**Black-box SRC value matrix + whether to write is governed only by vuln-report-format; white-box Phase0–6; in Chinese, reproducible.**
