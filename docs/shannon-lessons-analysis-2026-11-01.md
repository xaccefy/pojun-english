# Shannon (KeygraphHQ) Borrowing Analysis — 2026-11-01

> Subject: [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) (AGPL-3.0, ~53k lines of TS, 50k stars)
> Local source: `D:\xiangmu\aiai\shannon` (already cloned; grep the originals directly)
> Method: three parallel deep reads (all 80 prompt files / 168 worker-orchestration files / CLI+Docker+docs); key quotations were re-checked against the originals.

## 0. One-line conclusion

Shannon's edge is not "multi-agent" but that it **compiles security methodology into a state machine**: one flat schema per vuln class (queue JSON), one state transition per stage, one executable question attached to every judgment, and exactly one structured tool exit per artifact. Roughly 30–35% of its prompt is prohibitions/false-positive lists, 15% is self-check, 20% is output schema, and the actual "methodology" is only 25% — that ratio is itself the design.

Its overall positioning also differs from ARTEX: **Shannon = white-box (reads source) + single scan + local CLI with no UI**; **ARTEX = black-box first + resident platform + dual-graph situational picture + real SRC work**. So it can't be copied wholesale — extract mechanisms only.

---

## 1. Positioning differences at a glance

| Dimension | Shannon | ARTEX | Conclusion |
|---|---|---|---|
| Testing mode | White-box (source + live target), proof-by-exploitation | Mostly black-box (asset mapping + probing), vulnintel intel | Different scenarios; the white-box recon approach can be an optional mode |
| Orchestration | Temporal workflows (workers in Docker, 5 vuln classes in parallel) | Self-built Go Manager + PG + dual graph + intent state machine | Don't adopt Temporal; borrow its fault-tolerance semantics |
| Entry point | CLI (setup/start/status/scans/resume) | Web platform (tasks/findings/assets/traffic/reports) | ARTEX's shape is more product-like; borrow the state contract |
| Prompt | Standalone txt + @include + handlebars | Embedded in code + DB-editable (promptcatalog.go) | ARTEX has better editability; borrow the methodology skeleton |
| Reports | Markdown (evidence narrative + optional SARIF) | Word (official-document format v0.4.4) + traffic evidence | Borrow the evidence narrative structure, don't switch formats |
| Auth testing | Full modelling of login_type/TOTP/email login + pre-validation | No structured credential model | **Explicit gap, worth filling for SRC scenarios** |
| Cost | Per-agent tokens+costUsd accounting (not shown in the CLI) | llm_usage table already has tokens, no money conversion | Just add amount + display |
| Sandbox | One ephemeral Docker per scan (read-only repo) | Monolith run directly + hostd | Big change, direction only |

---

## 2. Mechanisms worth borrowing (by theme, P0 highest)

### A. Prompt methodology (P0, zero dependencies, biggest payoff)

**A1. The 12-section skeleton of the vuln analysis prompt** (`apps/worker/prompts/vuln-*.txt`, each 233–324 lines, five classes aligned section by section):

```
role/objective (success criteria written as "artifact shape") → four critical formulations (including phase isolation) →
starting_context (single source of truth = upstream deliverable) → system_architecture (who is before and after me) →
definitions (first define "what counts as a vuln") → data_format_specifications (field-by-field JSON output example) →
methodology (each item carries If failed → classify → suggested attack) →
proof_obligation_criteria (evidence threshold) → false_positives_to_avoid (class-specific false-positive list) →
confidence ("when uncertain, round down") → negative_results_documentation (safe paths must be recorded too) →
deliverable_tools + conclusion_trigger (single exit + STOP)
```

**A2. Slot classification reduces "is there an injection" to a decidable question** (`vuln-injection.txt:143-145`): `SQL-val/like/num/enum/ident | CMD-argument/part-of-string | FILE-path/include | TEMPLATE-expression | DESERIALIZE-object | PATH-component` plus a "protection-context match table" (bind for val, allowlist for enum/ident; **a concat performed after sanitization counts as "unprotected"**). Original:

> "If concat occurred **after** sanitization, treat that sanitization as **non-effective** for this path."

**A3. The tri-state decision question** (`exploit-injection.txt:234`) — when blocked, one executable question separates a false positive from blocked:

> "Is this preventing factor a security implementation designed to stop this attack, or an external operational constraint?" (a security mechanism = false positive; an external constraint = blocked)

**A4. The L1–L4 evidence ladder** (`exploit-injection.txt:209-229`): L1 injection point confirmed / L2 structure controllable / L3 data exfiltration or takeover / L4 critical impact; **only L3 may be marked exploited and must be ≥low**, L1–L2 can only be blocked. Quantitative floors: ≥3 payloads for initial confirmation, 8–10 variants when blockage is suspected, and more than 10–12 tool calls on a single vuln must escalate to a script; no classification before the `Bypass Exhaustion Protocol` is exhausted.

**A5. A sentence-level boundary between observation and inference** (`shared/exploitation/_reporting-standards.txt:9`):

> "Make claims only about what you directly observed. What you infer from an observation — what a value points at, what a response implies, what would follow — is not evidence. Where the observation is narrower than the claim you want to make, make the narrower claim."

**A6. No consequence means no rating + self-referential contradiction detection** (`shared/exploitation/_severity-reasoning.txt`):

> "If nobody ends up holding anything they should not … then the finding has no consequence to rate, and there is no tier low enough to be correct."
> "**Your own rationale must not refute your finding.** If the sentence you wrote for severity_rationale contains the reason the attack does not matter… you have written the argument for closing the finding, not for rating it."

**A7. Information isolation in adversarial review** (`sast/capella/review.prompt.hbs`):

> "Assume every finding is a false positive by default… Explicitly ignore the original finder's prose reasoning and justification, as they may be hallucinated."

**Where this lands in ARTEX**: `agent/promptcatalog.go` (the three default prompts for worker/reporter/goals are all DB-editable). Recommendation: inject the verbatim-level wording of A3/A4/A5/A6 into the worker's and reporter's discipline sections; fold A2's slot table into the worker's "parameter-level probing" hints (the black-box case can be simplified into a "parameter position vs filter strength" matrix). **No new dependency needed — one prompt iteration ships it.**

---

### B. Report and evidence narrative (P0, continuing the v0.4.4 official-document work)

Shannon's report structure (`sample-reports/shannon-report-crapi.md`, 934 lines):

- Executive Summary + **Summary by Vulnerability Type** (one paragraph per class; even "found nothing" states why: XSS "exploitation attempts were blocked by framework-level protections")
- Per-class chapters of **Exploitation Evidence**, with a uniform structure for every vuln:
  `Summary (Vulnerable location / Overview / Impact / Severity) → Prerequisites → Exploitation Steps (numbered curl + real responses) → Proof of Impact (numbered evidence) → Notes (observation details such as verify=False)`
- The report only assembles evidence **committed to git** (`reporting.ts readCommittedFile`); empty classes render a placeholder, so a "skipped class isn't mistaken for clean"
- report-executive.txt is a **persistence tool**, not a writer: `set-report-meta` once + `add_finding` once per entry, with Markdown generated by the renderer — **no free prose to improvise with**
- Title rules: "names the defect and where it lives, and **never a consequence**"; "only ever makes a title more precise, **never louder**"; hedge words (Theoretical/Potential) are banned
- "Not found" still gets a negative record: `negative_results_documentation` requires safe paths (already checked and fine) to be recorded too, proving coverage and preventing duplicate testing

**Where this lands in ARTEX**: the `ReporterDefaultPrompt` in `agent/promptcatalog.go` already has structure (overview/impact/reproduction/evidence/PoC/root cause/fix); the gap is in three places:
1. Missing **Prerequisites** (exploitation preconditions: what account/config/network position is needed) — what SRC review cares about most
2. Missing a **numbered Proof of Impact list** ("what was actually achieved", item by item tied to evidence)
3. Missing a **"not found / verified safe" section** — today the report only writes confirmed vulns, with no coverage statement that "this class was tested and is safe"
4. Add the "titles carry no consequence and no hedging" rule
Plus, in `report/docx_build.go`'s `writeMarkdownish`: recognize new subsections such as `### Prerequisites` so they come out as proper headings in Word.

---

### C. Structured submission + validation feedback loop (P0–P1, high engineering ROI)

Shannon's hard guardrails (an order of magnitude more reliable than prompt wording):

- `add_exploit` is a **discriminated union** `exploited | blocked`, re-validated by `Type.Union`; `vulnerability_id` must hit a queue entry of this class, otherwise it returns the **list of legal IDs** — "you either typo'd an ID or imagined one"
- Validation failures come back as a `retryable:true` tool error, so the model **corrects locally** in the same session instead of re-running the whole stage
- Unprocessed queue IDs render as `## Unprocessed Vulnerabilities` — omissions are visible
- Mandatory evidence checklist: payload, DB fingerprint, current user/schema, all table names, first 5 rows of the most sensitive table — one item short and it isn't exploited
- False positives **must not** go through the delivery tool; they only go to a private `*_false_positives.md` file

**Where this lands in ARTEX**: the `report_finding` tool (`agent/worker.go`) already has required params; we could add:
1. A **combined check** of `finding_severity` and `evidence` (critical/high requires a real response fragment/HTTP status/command output inside evidence — otherwise downgrade to inferred or reject and retry)
2. Return structured errors + the legal enum (vulnclass's existing list) so the model can self-correct
3. The report may only cite traffic evidence already bound to that finding (a traffic binding mechanism exists; the reporter prompt can enforce "verify existence when citing a binding_id")

---

### D. Orchestration and fault tolerance (P1)

| Mechanism | Source/file | Portability |
|---|---|---|
| Content-addressed artifacts | `reconciliation/contracts.ts` `ArtifactRef{path,artifactKind,sha256,inputs,counts}`; re-read the producer queue and compare hashes before publishing | Medium: ARTEX dual-graph nodes can carry `sha256` lineage, preventing "shipping after the input was swapped" |
| per-agent git checkpoint | each agent commits only its own files (`agent-git-paths.ts`); resume = `reset --hard` + `clean -e <completed paths>` | Low-medium: ARTEX checkpoints are largely covered by the PG state machine; borrow the "commit only your own scope" discipline to avoid parallel contamination |
| Closed degradation codes | `PartialReasonCode` with 8 codes + `ReportProgress` three states; the terminal state is decided by the reason set; all display surfaces share a safe-message projection | High: ARTEX task state can add `partial_reasons[]` (e.g. llm_unavailable/timeout/guard_denied) and render it uniformly in the frontend |
| Unknown means error | `ActivityMirrorError`; a stale CLI version gets an explicit upgrade prompt | High: version the ARTEX SSE/frontend contract so unknown events raise an explicit alarm instead of being silent |
| Layered timeout/cancel | agent 2h+ heartbeat, durable `WAIT_CANCELLATION_COMPLETED` vs agent `TRY_CANCEL` | Medium: ARTEX already has timeouts; borrow "layered cancellation semantics" (persistence steps wait for cancellation to complete) |
| Single derived state | `derive.ts` is the only state derivation, shared by `render.ts` and `status-json.ts` | High: the frontend task detail page/SSE all consume the same derived snapshot |

---

### E. Authentication and rules of engagement (P1, an explicit gap for real SRC)

`configs/config-schema.json`:

- `authentication.login_type ∈ form|sso|api|basic`; `credentials{username,password,totp_secret}` (Base32 validated) + `credentials.email_login{address,password,totp_secret}`; `login_flow: string[]` (1–20 entries, each ≤500); `success_condition.type ∈ url_contains|element_present|url_equals_exactly|text_contains`
- Login execution: `$username/$password/$totp` are **literally substituted** in the prompt and TOTP is computed on the fly (`generate-totp.ts`); the `validate-authentication` pre-step runs it once in a real browser and produces `submit_auth_result{login_success, failure_point}` — **wrong credentials are known before the scan starts**
- `rules.avoid[] / rules.focus[]` (≤50 entries each, `type ∈ url_path|subdomain|domain|method|header|parameter|code_path`); `rules_of_engagement` free text ≤1000 characters injected into every prompt; `report{min_severity,min_confidence,sarif}`
- Note the limits: **only code_path is technically enforced** (translated into permission deny rules); the other types are merely rendered into the prompt; **rate limiting is a written convention only**, with no code-level throttling

**Where this lands in ARTEX**: add a structured auth block to task creation/target config (form login / API token / Cookie / TOTP / custom header + success determination), and run a **login self-check** (HTTP probe or browser) before the worker starts; on failure report "credentials unusable" instead of letting the worker probe blindly. This is the key step that lets ARTEX genuinely hunt "post-login vulnerabilities".

---

### F. Cost and observability (P1–P2)

- Shannon records `AgentMetrics{durationMs,inputTokens,outputTokens,cacheRead/WriteTokens,costUsd,numTurns,model}` per agent → aggregates `totalCostUsd` + `usageAccountingComplete` (explicitly flagged when accounting is incomplete)
- Status quo: **the CLI doesn't display cost** (a ready-made gap)
- **Where this lands in ARTEX**: `llmrec` already has the `llm_usage` table (profile/worker/status/input/output tokens) — add a model price table → a `cost_usd` column/view → show "this task's spend + distribution by agent + whether accounting is complete" on the task detail page and the global usage page. That table is a ready-made data source; the change is small.

---

### G. Sandboxing and distribution (P2, direction only, not recommended near-term)

- Shannon: one ephemeral Docker per scan; the repo mounted read-only + 4 writable overlays (`.shannon/deliverables`/`scratchpad`/playwright); non-root (UID remapping); `--shm-size 2gb`; images gated by a `worker-protocol` label; Temporal as the control plane, bind-mounted logs as the data plane
- Its isolation is **process + filesystem level, not network level** (safety.md only constrains with "don't hit production")
- ARTEX's monolith + hostd shape differs, so the cost/benefit of full containerization needs a separate evaluation; **if we do it**, at minimum cover what Shannon lacks: default-deny egress + a target allowlist
- Distribution: npx + multi-arch Docker Hub + cosign; ARTEX already has releases + a LAN local source + one-click update, so the equivalent capability is covered

---

## 3. Not recommended to copy wholesale

1. **Temporal**: ARTEX's PG state machine + intent CAS is sufficient; adopting Temporal brings operational complexity disproportionate to the gain.
2. **The "hand-copied types in the CLI" outside Temporal**: Shannon's own comment in `scan/pipeline.ts` admits the types drift — a cautionary example; in Go, sharing types within the same module is enough.
3. **The wholesale white-box assumption**: its vuln/exploit prompts assume heavily that "source is readable, file:line can be given". The ARTEX black-box case can only borrow the "slot/protection matching" idea, not reuse its source-location instructions.
4. **Ephemeral containers**: ARTEX's hostd/traffic proxy/MITM already depend deeply on the host network stack; full containerization is an architecture-level change and shouldn't be done casually for one feature.
5. **npx-style distribution**: different shape, unnecessary.

---

## 4. Recommended execution path (three batches, each shippable independently)

**Batch 1 (P0, prompt-only + report structure, 1 release)**
1. Upgrade the reporter template: add `Prerequisites` and a numbered `Proof of Impact` list to every vuln; add a "tested and not found" coverage statement at the end of the report; title rules (no consequence, no hedging).
2. Inject into the worker/reporter prompts: the observation-vs-inference boundary (A5 verbatim), no-consequence-no-rating + self-referential contradiction detection (A6), and the tri-state decision question (A3).
3. `report_finding` evidence-strength validation: high severity requires a real response fragment, otherwise reject and retry.

**Batch 2 (P1, engineering hardening, 2–3 releases)**
4. Auth configuration + a pre-scan login self-check (E).
5. Add `partial_reasons[]` to task state + cost display (D's closed degradation codes + F).
6. Version the frontend/SSE contract + alarm on unknown events (D).

**Batch 3 (P2, as needed)**
7. Turn the coverage matrix into an "executable capability registry" (class → agent → detection case → latest benchmark evidence) rather than Shannon's hand-maintained table, which rots.
8. Content addressing/lineage (`ArtifactRef`) for tracing dual-graph node inputs.
9. Evaluate the sandboxing direction (egress allowlist before full containerization).

---

## Appendix: original locations that can be used directly

| Topic | File |
|---|---|
| 12-section vuln analysis skeleton | `apps/worker/prompts/vuln-injection.txt` (five classes, isomorphic) |
| exploit evidence ladder/decision question | `apps/worker/prompts/exploit-injection.txt:209-234` |
| observation vs inference | `apps/worker/prompts/shared/exploitation/_reporting-standards.txt:9` |
| severity self-referential contradiction | `apps/worker/prompts/shared/exploitation/_severity-reasoning.txt` |
| exploitation precondition accounting | `apps/worker/prompts/shared/exploitation/_exploit-scope.txt` |
| adversarial review | `apps/worker/prompts/sast/capella/review.prompt.hbs` |
| report samples (3 real ones) | `sample-reports/*.md` |
| auth/rules-of-engagement schema | `apps/worker/configs/config-schema.json` |
| state derivation/JSON contract | `apps/cli/src/scan/derive.ts`, `status-json.ts` |
| sandbox recipe | `apps/cli/src/docker.ts:424-531` |
