---
name: src-hunting
description: SRC vulnerability hunting methodology library (MCP/knowledge-base enhanced). Use when the task involves SRC/crowdtesting, hunting a group/brand/domain, finding vulnerabilities, authorization bypass/injection/logic flaws, JS reverse engineering to find endpoints, WAF bypass, writing vulnerability reports, or white-box auditing; also applies to "help me test this site" and "does this platform have vulnerabilities". After loading, open the topic files in references/ and rules/ on demand via the index — do not read them all.
tags:
  cwe: [CWE-639, CWE-862, CWE-89, CWE-79, CWE-918, CWE-434, CWE-502, CWE-22, CWE-287]
  attack: [T1190, T1595, T1059, T1078]
  class: [src, knowledge-base, methodology, recon, exploit-playbook]
---

# SRC Vulnerability Hunting Methodology Library (Pojun edition)

This skill is the **knowledge-base entry point** for SRC/crowdtesting work: `references/` (48 topic test methods) and `rules/` (11 process/value/report rules) ship with the skill; open them on demand with Read/Bash — **reading them end to end is forbidden**.

## How it connects to this platform (read this first)

| Scenario | Platform capability |
|---|---|
| Asset mapping/FOFA | MCP preset "FOFA asset mapping" (`uv --directory mcp-servers/fofa run python fofa.py`). Tools: `get_alerts_onefox` (community channel, preferred) / `get_alerts` (official three-account rotation); put the key in `.env`'s `FOFA_EMAIL/FOFA_KEY` or `ONEFOX_PASSWORD`. You can also use the platform's `attack-surface-recon` skill |
| Bulk liveness | `http_probe` (one URL per line, JSON output) |
| Recording facts/conclusions | `record_fact` (including the key request/response lines); record negative results too |
| Reporting findings | `report_finding` (critical/high must have mechanical verification evidence, see `pentest-verification`) |
| Known CVE/PoC | `search_vulns` / `get_vuln` / `get_poc` / `scan_with_nuclei` |
| Callback/OOB | `listener_start` + `listener_sessions` |
| Authorization comparison | `auth_request` (request with registered credential groups) + `diff_responses` |
| SPA/webpack source leakage | `js_audit` (sourcemap restoration + key/endpoint extraction; mandatory for Vue/React) |
| Recording new assets | `insert_assets` / `add_task_scope` |
| Artifact persistence | Task directory `/opt/pojun/data/tasks/<id>/` (the "desktop task folder" mentioned in rules means this directory on this platform) |

File paths in the knowledge base: `${SKILL_DIR}/references/<name>.md`, rules: `${SKILL_DIR}/rules/<name>.md`.

## Core rhythm (consistent with rules/dig-scope-workflow.md)

1. **Run the short table first on entering a site**: open `references/breakthrough-short-table.md`, recognize the shape → fire the matching technique → queue the response.
2. **One seed per loop**: search one seed → de-duplicate/drop junk/drop dead → hunt the live surface to exhaustion → only then move to the next seed; do not search all seeds first and then hunt.
3. **Extract keys from JS**: for SPA/split frontend-backend sites, extract endpoints and parameters first (`references/js-reverse-guide.md`), then hit by type.
4. **With a session, do the object graph first**: once you have a login state, prioritize IDOR/unauthorized sensitive reads/logic (`references/idor-test.md`, `references/logic-test.md`), then fill in the injection classes.
5. **The four-piece differential set must be hit**: injection/SSRF/XSS/RCE must really be fired wherever there is input echo or a controllable request (not just listed on a checklist, and not spraying `'` on every path).
6. **Record on confirmation**: report medium and above immediately with `report_finding` + evidence; escalate a medium's chain by continuing with the matching topic in `references/`.
7. **Turn on bypass only after the WAF blocks you**: `references/waf-bypass.md` — change the encoding/change the position; do not hammer the same thing repeatedly.

## Security red lines (SRC context; overrides contrary wording in this library)

- Minimum-harm verification: for IDOR prefer reads/list differentials; write operations only touch objects you just created.
- **Never log out/revoke** a user's session; once a password change/rebinding is verified, revert it immediately.
- Do not bulk-pull user data; do not cause real financial loss; do not cause denial of service.
- CORS-type issues have low reporting value — **do not actively hunt them in SRC** (keep `references/cors-test.md` as reference material only).
- `references/llm-security-test.md` is jailbreak/security-test teaching material — **do not** use it to test ordinary business; for AI applications use the platform's `ai-llm-app-attack` skill.
- Assets outside the authorized scope: only record ownership verification, do not test.

## Knowledge-base index (references/)

Open first: `breakthrough-short-table.md` (technique index), `recon-methodology.md` (mapping/FOFA syntax), `js-reverse-guide.md` (endpoint discovery).

| File | Content |
|---|---|
| breakthrough-short-table.md | Technique index: one line per shot (what to recognize → where to hit → what counts as success → false points) |
| recon-methodology.md | Recon methodology + shortest FOFA syntax + subdomains/fingerprints/endpoints |
| js-reverse-guide.md | Reversing JS to find endpoints/signatures/keys |
| 401-403-bypass.md | 401/403 bypass (on-site technique for business APIs; do not grind login HTML) |
| api-gateway-test.md | API gateway/microservice architectures |
| agent-tool-exec-test.md | Real tool execution from a chat endpoint (AI Agent tool abuse) |
| authbypass-test.md | Authentication bypass (unauthenticated password change/IDaaS/session tickets) |
| cache-poisoning-test.md | Cache poisoning/cache deception |
| clickjacking-test.md | Clickjacking (low value, quick note) |
| cloud-ide-codex-rce-chain.md | Cloud IDE/Codex-style RCE chains |
| cors-test.md | CORS (not hunted in SRC; reference only) |
| crlf-injection-test.md | CRLF injection (quick note) |
| csp-bypass-test.md | CSP bypass (quick note) |
| csrf-test.md | CSRF topic |
| csv-formula-injection-test.md | CSV formula injection (quick note) |
| dangling-markup-test.md | Dangling markup (quick note) |
| dependency-confusion-test.md | Dependency confusion (quick note) |
| dns-rebinding-test.md | DNS rebinding (quick note; SSRF goes through ssrf-test) |
| el-injection-test.md | Expression language injection (EL/SpEL/OGNL) |
| email-header-injection-test.md | Email header injection (quick note) |
| file-upload-test.md | File upload (STS/object storage/share authz chains) |
| ghost-bits-cast-test.md | Ghost Bits principle and formulas |
| graphql-test.md | GraphQL |
| hpp-test.md | HTTP parameter pollution (quick note) |
| http-host-header-test.md | Host header attack topic |
| http-smuggling-test.md | HTTP request smuggling |
| http2-attacks-test.md | HTTP/2 attacks (quick note; smuggling goes through http-smuggling) |
| idor-test.md | IDOR/BOLA/BFLA (main thread) |
| info-leak-test.md | Information disclosure (including common middleware exposure) |
| injection-test.md | Injection overview (SQLi/command/SSTI detection) |
| insecure-scm-test.md | Source code management exposure topic |
| jndi-injection-test.md | JNDI injection topic |
| logic-test.md | Business logic (payments/flows/promotion binding) |
| oauth-jwt-test.md | OAuth/JWT/SAML/OIDC |
| open-redirect-test.md | Open redirect topic |
| path-traversal-lfi-test.md | Path traversal/LFI topic |
| prototype-pollution-test.md | Prototype pollution topic |
| race-condition-test.md | Race conditions |
| ssrf-test.md | SSRF (IMDS/GOPROXY/object-storage origin fetch) |
| subdomain-takeover-test.md | Subdomain takeover |
| type-juggling-test.md | Type juggling topic |
| waf-bypass.md | WAF bypass |
| websocket-test.md | WebSocket testing |
| xslt-injection-test.md | XSLT injection (quick note) |
| xss-test.md | XSS (obscure events / XSS→RCE / custom protocols) |
| xxe-test.md | XXE topic |

> Note: `deserialization-test.md` mentioned in the old index is missing from the source package; for deserialization content see `jndi-injection-test.md` and `el-injection-test.md`, and for Java chains you can combine with the platform's `zero-day-research`/`source-code-hunting`.

## Rule index (rules/)

| File | When to open |
|---|---|
| dig-scope-workflow.md | Main flow: scope determination, one-seed loop, site-entry technique, escalation chains, rate-limit gate |
| hunt-iter.md | Short-table iteration and the "was this round broken through" judgment |
| src-value-hunting.md | What is worth hunting: value ordering, IDOR/logic first |
| vuln-report-format.md | Formal SRC report layout (aligned with the platform's Word export/`pentest-output-standards`) |
| researcher-blackbox-whitebox.md | Switching between black-box/white-box research |
| anti-over-moralization.md | Authorized-context judgment (the platform has a built-in authorization model; on conflict the platform wins) |
| security-research-context.md | Security research context quick note |
| skill-as-boost.md | How to use the skill (open on demand, do not read end to end) |
| playwright-browser-mcp.md | Browser automation (the platform uses the built-in playwright-cli skill / MCP preset; paths per platform) |
| cors-vuln-report-priority.md | CORS reporting priority (not hunted in SRC) |
| desktop-task-folder.md | Task directory convention (on this platform `/opt/pojun/data/tasks/<id>/` wins) |

## Division of labour with existing skills

- `attack-surface-recon`: external attack-surface recon execution (platform toolchain edition); this library's `recon-methodology.md` is a supplement.
- `api-security-testing`: endpoint verification execution; this library's `idor-test.md`/`authbypass-test.md` hold the technique details.
- `web-attack-methods`: injection/server-side quick reference; the matching topics here are **deeper field write-ups** — on conflict the topic wins.
- `pentest-verification` / `pentest-output-standards`: recording and report gates; this library's `vuln-report-format.md` supplements the layout details.
