package agent

// Job hard-tails (v0.4.63):
// injected by code at the end of worker/planner system prompts — they don't disappear when the UI text is edited.
//
// Production retro: installed scanners (ffuf/gobuster/nuclei/sqlmap + SecLists) were never named in the prompts,
// so weak models just curl'd the homepage / read JS; the planner's coverage matrix lived only in the framework,
// never checked per-class, so dispatched intents concentrated on the few classes it knew. Here 'when to use
// which scanner, where the wordlists are, what commands look like' + 'the vuln-class coverage checklist' are baked
// in as non-editable hard tails.
// scannerFirstGuidance is the worker's 'scan first, verify after' hard tail (always on).
const scannerFirstGuidance = `
[Scanner-first (installed on this machine; judging from only a homepage curl / JS read = not acceptable)]
- **Directory/path discovery**: on **confirmed-live, non-purely-static** HTTP services (main site/admin/gateway — pick 3–5 high-value
  targets first, don't blanket every subdomain) run one directory brute-force, then eyeball results:
  ` + "`ffuf -u <base>/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 10 -rate 30 -timeout 10 -mc 200,204,301,302,401,403 -o ffuf.json -of json`" + `
  (or ` + "`gobuster dir -u <base> -w same-wordlist -t 10 --delay 200ms`" + `). Focus on 401/403 and unusual 200s — admin panels/APIs often hide there.
- **Components/known CVEs**: first ` + "`search_vulns`" + ` for the component's CVEs, then
  ` + "`nuclei -u <url> -severity critical,high -rate-limit 30 -jsonl -o out.jsonl ${EGRESS_PROXY:+-proxy \"$EGRESS_PROXY\"}`" + `
  (or build the command via scan_with_nuclei, which adds -proxy per the platform egress automatically — don't add it twice).
  When an egress proxy is configured (i.e. $EGRESS_PROXY is non-empty in Bash), a hand-typed nuclei command must add ` + "`-proxy \"$EGRESS_PROXY\"`" + `;
  the ` + "`${EGRESS_PROXY:+...}`" + ` form in the example is omitted entirely when unset, so no empty -proxy is left behind.
  Empty output = no hits, not a failure; any hit must be re-verified, then report_finding.
- **Endpoints with params**: injection only matters on input points — GET/POST params, JSON fields, cookies. First run
  ` + "`sqlmap -u \"<url>\" --batch --level=2 --risk=1 --timeout 10 --flush-session [--data=... --cookie=...]`" + `
  a read-only probe (level 2 / risk 1 — no writes); take minimal proof only after injectability is confirmed.
- **Login/admin**: try ≤5 default credential pairs (admin/admin, admin/123456, administrator/admin etc.) minimally,
  stop on failure; never run a big-wordlist brute force against production.
- **Per-scan discipline**: rate-limit (-rate 30 / -rate-limit 30 / --delay), timeout, land output to disk (out.json*) then grep a summary;
  write back immediately after: new endpoint/service → insert_assets; hit → report_finding (with command+response evidence);
  no hits → record_fact one-line negative (what was scanned, with what, empty result).
- **Endpoints must enter the asset graph**: every accessible path extracted via js_audit / dir-bruteforce / frontend chunks goes
  to insert_assets in bulk (type=endpoint, with source + status code) — don't leave it only in fact text: an endpoint
  not in the asset graph can't get a vuln-class intent dispatched against it by the planner.
- **Scanners aren't omnipotent**: they only spread the surface — confirmation and exploitation still need adversarial self-check per intent.
`

// skillRoutingGuidance is the worker's skill-routing tail (code-injected).
// All skill names are platform built-in skills.
const skillRoutingGuidance = `
[Skill routing (load the matching methodology BEFORE acting — don't freestyle from memory)]
- Web vuln playbooks (injection/XSS/upload/SSRF/privesc/logic) → Skill("web-attack-methods")
- Unknown-surface mining (privesc/logic/race/state-machine when no CVE exists) → Skill("vuln-hunting")
- API surface (REST/GraphQL/auth chains) → Skill("api-security-testing") or Skill("api-recon")
- Recon surface (subdomains/ports/fingerprints/dirs) → Skill("attack-surface-recon")
- APK/mobile → Skill("binary-mobile-reversing")
- Report writing standards → Skill("pentest-output-standards")
- SRC methodology library (48-piece knowledge base, load on demand) → Skill("src-hunting")
Rule: when an intent involves the scenarios above, **load the matching skill as step one** before acting; skill command templates beat commands you improvise.
`

// coverageMatrixPlannerGuidance is the planner's 'vuln coverage matrix' hard tail (code-injected).
const coverageMatrixPlannerGuidance = `
[Vuln coverage matrix (hard constraint: check line-by-line BEFORE dispatching — fill whichever class is missing)]
For every in-scope registered endpoint/service worth attacking, check whether each class below already has intent coverage
(open / running / recent_done all count). Dispatch at least 1 intent per missing class this round; the summary states class name,
target endpoint, tool and criteria (e.g. 'SQLi: class #3 /api/item?id= param spot, sqlmap level2').
  1 Unauthorized access: anonymous direct pull of admin/data endpoints (no credentials)
  2 Privesc/IDOR: switch identity, switch object id, horizontal & vertical privesc
  3 SQL injection: param spots/JSON fields/cookies; sqlmap --batch --level=2 --risk=1
  4 XSS/template injection: reflected/stored/DOM; dalfox or manual payloads
  5 SSRF/callback: URL params, webhooks, image proxies, export callbacks; listener verifies callback
  6 File upload/parsing: type/extension/content/path bypass (prove capability only — no dropped backdoors)
  7 Command exec/deserialization/component exploit: CVE per component fingerprint, actually triggered
  8 Weak creds/auth bypass: ≤5 default pairs; JWT/signature/captcha/password-reset logic
  9 Known-CVE batch: search_vulns / search_recent_critical + nuclei per-component scans
 10 Business logic/race: state-machine jumps, duplicate submits, concurrent deduction, amount/permission field tampering (read-only verify preferred)
Rules:
- When untested endpoints exist and the matrix has gaps, **don't spend the whole round's budget on one line**; keep at least 1 for a gap class.
- When a class is **clearly inapplicable** (pure static page, no params, no upload entry etc.), dispatch one minimal confirmation intent or have the worker
  record_fact a one-line 'class inapplicable: basis' — don't silently skip, or the delivery report can't show what was covered.
- Scanners carry the surface-spread: dir brute-force (ffuf/gobuster + /opt/SecLists), nuclei templates, low-risk sqlmap probes
  must all be named in intent summaries — don't write 'test it a bit deeper'.

[Depth-first (converge when assets are many and L3 is 0)]
- When this task has >50 registered assets and high/critical findings = 0: **stop opening new surface**, keep at most 1 new direction;
  spend the rest of the budget picking 1–2 confirmed leads from 'unauthorized / config leak / weak creds / object storage / debug-management endpoints' and breaking them through:
  land a data sample, admin login, command echo or accessible uploaded file — write it as a finding (with request-response/command output).
- Only when confirmed leads all prove unbreakable may you expand surface again — and have the worker fact-note first why each couldn't be broken.
`

// scopeVerifyPlannerGuidance is the planner's 'authorization boundary + verify-first' hard tail (v0.4.63):
// attribution/ownership facts get verified before attack intents (paired with the write-back scope guard).
const scopeVerifyPlannerGuidance = `
[Authorization boundary and verify-first (hard constraint)]
- **Ownership-class facts must be verified first**: for cross-domain ownership claims like 'domain A points to/relates to/shares origin with domain B' or 'A is B's admin',
  the next intent must be a [verification intent] — collect evidence on both domains (curl a file/endpoint each,
  confirm 200 + consistent content), and write both raw responses into a fact. Verification fails (404/mismatch) →
  immediately record_fact a negative and drop that chain; no attack/exploit intents before verification completes.
- **Check scope origin carefully**: list_assets entries may come from this task's scope or from source/inherited tasks (read-only shared).
  Prefer this task's own-scope assets for intents; source-task assets must first have ownership verified and the hypothesis must state
  'verified on both domains' — or the engine's scope guard rejects the write-back.
- **The write-back guard is hard**: record_fact / report_finding anchored to non-own-scope assets gets rejected outright — rather than bouncing,
  cement ownership and declare scope per the two rules above first.
`

// execFaceWorkerGuidance is the worker's 'execution surface' hard tail (red-team batch demotion, v0.7.0).
const execFaceWorkerGuidance = `
[Execution surface (native executors beat hand-written curl)]
- Login-state chains: session_login logs in once (credentials preferentially from the asset via asset_id+auth_index); later http_request(session=same-name) carries cookies automatically — two identities = two sessions for privesc comparison. auth_request/session_request only when the command must go through Bash.
- Verification scripts needed: poc_scaffold generates runnable Python skeletons by class (sqli/ssti/lfi/ssrf/idor/jwt/upload/cmdi/race) — baseline/diff payload tables/hit criteria pre-filled, just change params and run.
- Long scans/brute-force/bulk exports: job_start moves them to task-level background jobs (process keeps running after the run ends), job_status/job_output fetch results — don't redo long tasks because of a single intent's wall clock.
- Shell/credentials obtained: record_fact immediately and dispatch/work the next hop (credentials→lateral, shell→config & data).
`

// execFacePlannerGuidance is the planner's 'execution-surface orchestration' hard tail (red-team batch demotion, v0.7.0).
const execFacePlannerGuidance = `
[Execution-surface orchestration (background jobs and attack chains)]
- Every round first checks job_status: fetch results of finished background jobs (job_output) and write them back to fact/finding.
- Attack-chain next hops auto-dispatch follow-up intents (chain_intent_id in the report_finding receipt) — don't re-dispatch the same dimension; for variants, change params or entry point.
- list_facts(q=credentials/token/shell) reuses ammo already obtained; ≥2 zero-yield rounds on the same asset+dimension → switch dimension.
`
