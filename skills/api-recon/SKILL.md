---
name: api-recon
description: Use this skill when collecting a website's API endpoints.
tags:
  cwe: [CWE-200]
  attack: [T1595.002]
  class: [recon, api-surface]
---

# API Recon (Frontend Interface Reconnaissance)

Under **authorized** conditions, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI feature triggers** (tabs, modals, table actions, etc.).

---

## Boundaries and Prohibitions (Agent Must Read · Violating Is Out of Bounds)

This skill **only performs API / parameter-surface reconnaissance**; it is not a vulnerability-hunting or exploitation stage.

### Task Boundaries

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI triggers | SQLi/XSS/access control bypass/brute force/fuzzing for vulnerabilities, packet-modification attacks, destructive operations |
| **Authentication** | Hook + stub/mock to bypass the **client-side** login gate | Ask the user for or guess account credentials; attempt real login form submissions |
| **Runtime** | Hook endpoints without credentials and use mock responses to let the SPA enter the post-login shell | Flows that require a real backend session to proceed |

### Credential-Free Dynamic Analysis (Default for Phase 3)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** bootstrap endpoints for login, permissions, menus, etc.;
2. Return mock bodies to business query endpoints with **correct structure, success business code, and optionally empty data**;
3. Let the frontend render post-login pages even without a backend or under 401, thereby triggering more XHR/fetch/WebSocket traffic;
4. **Empty data, blank tables, and placeholder UIs are expected** — do not switch to real login or vulnerability testing because of them.

**In one sentence**: use mocks to open up frontend routes and component mounting, and **record only outbound requests**; what the backend returns does not matter — what matters is **which additional endpoints the frontend will call**.

### Hard Prohibitions

| Prohibited | Alternative |
|---|---|
| Before Phase 1 completes, grep/curl/Read the main entry `index-*.js` to extract API paths | Run `OUTDIR/harvest_static.py` |
| Hand-write `extract_apis.py` or other scripts to replace harvest | Modify `OUTDIR/harvest_static.py` and rerun |
| Repeat the same grep/command after it fails ≥2 times | Change strategy: read tool_logs, modify harvest, consult reference |
| Skip Gate A/B and run the original `scripts/` directly | Copy into OUTDIR and adapt to the target |
| Real username/password, OTP, OAuth, or other authentication | stub/mock (see above) |
| Skip stubs under the pretext of "getting real data" and perform access-control/injection tests | Record outbound only; that is within recon boundaries |
| Irreversible operations such as deletion, exporting sensitive data, or bulk writes | The same applies to coverage clicks |
| Claim all pages and endpoints were obtained without completing runtime + dynamic enumeration | See "Definition of Done" or note limitations |
| Claim all parameters are known without completing the parameter-trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Infer required/optional from a single runtime sample | Multi-sample diff, or infer from validation rules/errors |

---

## Two-Layer Model + Runtime Modes

| Layer | Output | Limits |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, route drafts, payload-field candidates | No HTTP methods; parameters require Phase 1b; misses runtime-concatenated URLs |
| **Runtime** (live session) | Methods + bodies + responses + dynamic URLs + WS/SSE; multi-sample diff completes parameters | Requests are only sent if the page actually renders; a single sample cannot determine required/optional |

| Runtime mode | Engine | Best for |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Click tabs/modals/tables for deeper feature-point coverage |
| **both** | depth first, then coverage | Most complete, longest running |

**Parameter methodology** (no universal script): use harvest/regex for paths; for parameters use **anchor-based window expansion + UI binding chains + multi-sample diff + error-based inference** (see section J of [reference.md](reference.md) for grep recipes).

---

## Definition of Done

Recon can be declared complete only when all of the following are satisfied:

- [ ] **Static**: Phase 1 harvest produced `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: at least one of depth or coverage; coverage/both require **hook active + dynamic enumeration loop**
- [ ] **Post-login shell**: visiting business paths does not land on `/login` (watch for hash routing)
- [ ] **Parameters**: coverage/both completed the parameter-trigger matrix + `param_samples.json`; Phase 5 merged `params_merged.json`
- [ ] **Depth** (if module pages are blank): reconstruct the permission tree in Phase 4 and rerun until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: all Phase 5 outputs are present (see the Phase 5 output table); `insert_assets` has written service and endpoint assets

---

## Scripts and Gates

`scripts/` are reference templates only; **do not** run the originals directly and treat the results as final.

**Rule**: read first → adapt to the target → write into `OUTDIR` (e.g. `recon/`) → record in `CHANGES.md`; if there is no match, rewrite following the methodology, borrowing only the structure.

| Gate | When | Reference script → OUTDIR copy | Common required changes |
|---|---|---|---|
| **A (Static)** | After Phase 0, **before the first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | **Most sites work with the default regex**; only change endpoint regex, webpack/Vite `publicPath`, MPA exclude/cookie when the manifest/dialect does not match |
| **B (Runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success values, stubs, login regex, API prefix, hash/history |

**Mandatory SPA order** (cannot be swapped; Phase numbers take precedence over "explore first, script later"):

| Step | Must | Must not |
|---|---|---|
| After Phase 0 completes | Next Bash = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy the script → make minor edits as needed → **run immediately** | Manually extract APIs first, then decide whether to harvest |
| Before Phase 1 completes | Verify output with `wc -l`; on 404, fix harvest and retry | Hand-write extract scripts; repeatedly grep URLs that were not downloaded |
| From Phase 1b on | grep only `OUTDIR/js/*.js` | Use the main bundle instead of harvest |

- ✅ Copy `harvest_static.py` → (optional) edit regex → **run immediately**
- ❌ curl the main bundle → grep repeatedly → write a temporary extract → harvest only at the end
- **MPA**: after Phase 0, the next Bash = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and Output Constraints

| Constraint | Description |
|---|---|
| Large files | `index-*.js` over 100KB **must not** be Read/grepped into context; batch-process with OUTDIR scripts |
| grep output | must use `\| head -20` or `-m 5`; keep only path summaries in the conversation, do not paste bundle snippets |
| Verification | use `wc -l`, `ls \| wc -l`; do not Read whole directories |
| regex probing | optional, ≤1 time, only on ≤50KB small chunks or HTML; harvest is authoritative for formal static analysis |
| reference | see [reference.md](reference.md) for recipes/templates/troubleshooting; do not inline the full text again |

---

## Execution Roadmap

```
Phase 0 Classification + OUTDIR
  → Gate A → Phase 1 harvest (★ run immediately ★)
  → Phase 1b parameter reverse engineering
  → Phase 2 three authentication gates → config.json
  → Gate B → Phase 3 runtime + parameter matrix
  → Phase 4 permission tree (if needed) → rerun Phase 3
  → Phase 5 merge report + insert_assets bulk-inserts all discovered service and endpoint API assets; under no circumstances may discovered assets be omitted
```

Check off in order; **do not proceed to the next Phase until the previous item is complete**.

1. [ ] **Phase 0**: probe SPA/MPA; create `OUTDIR` → [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: copy script → **immediately** harvest → verify with `wc -l` → [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: anchor window expansion + binding layer → `param_candidates.json` → [Phase 1b](#phase-1b--parameter-reverse-engineering)
4. [ ] **Phase 2**: three authentication gates → `config.json` → [Phase 2](#phase-2--three-authentication-gates)
5. [ ] **Gate B**: adjust runtime scripts → [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm the post-login shell; parameter-trigger matrix → `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree → patch stubs → rerun Phase 3 → [Phase 4](#phase-4--permission-tree-reconstruction)
8. [ ] **Phase 5**: merged outputs + report + `insert_assets` → [Phase 5](#phase-5--merge-and-report)

---

## Phase 0 — Classification

Fetch the entry HTML, **create `OUTDIR`** (do not modify `scripts/` inside the skill):

- **SPA**: empty shell + `<div id=app>` + chunks → Phase 1–5
- **MPA**: SSR + `<form>`, no endpoint bundle → after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt`, `api_inline.txt`. If an SPA has forms ≈ 0 → switch to Phase 1.

---

## Phase 0b — API Contract (try this first; it may eliminate Phase 1 entirely)

**Try contract files before crawling JS.** Contracts (OpenAPI/Swagger/Postman) directly state "which endpoints the backend supports, which parameters, which methods, and which require authentication" — more accurate than crawlers and faster than static analysis (one GET vs downloading all chunks). When the target exposes `/swagger-ui/` or `/api-docs`, the contract is often **all you need**.

Use the `api_contract` tool (it probes common contract paths and parses an inventory):

```
api_contract(base_url="https://target.example.com")
```

**Once you have the contract**:
- Endpoint inventory in the contract → go straight to Phase 4 (permission tree reconstruction) and parameter analysis; **Phase 1/3 can be skipped**;
- `auth_required` flags in the contract → **the endpoints requiring authentication are the core targets for access-control testing**; list them separately;
- Endpoints absent from the contract (supported by the backend but undocumented) → still need to be filled in via Phase 1/3.

**Not finding a contract is common** (many sites do not expose one) → go straight to Phase 1 and do not waste time here.

> A contract is an **endpoint inventory, not a vulnerability**. Whether and how to attack after obtaining the inventory is left to vuln-hunting methodology.

---

## Phase 1 — Static

Follow [Scripts and Gates](#scripts-and-gates) · [Tool and Output Constraints](#tool-and-output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parse HTML scripts → webpack/Vite manifest → download all lazy chunks → produce `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- chunk count vs manifest: on 404, fix harvest and retry; do not manually curl chunks one by one
- Too few entries in `api_static.txt` → loosen the endpoint regex inside OUTDIR and rerun (see reference)

### Phase 1b — Parameter Reverse Engineering

Paths come from Phase 1; parameter fields must be recon'd separately. See [Tool and Output Constraints](#tool-and-output-constraints) for grep rules.

**Completion criteria**: for important endpoints you can answer — field names, transport location, inferred types, whether required, sample values, confidence.

#### 1b.0 — Transport Shapes

| Shape | Where parameters live | Check statically first |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` next to the path anchor |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameter | `/user/:id` | route table + `useParams` / `$route.params` |
| Encrypted/signed | packed into `sign`/`data` | hook the encryption function's arguments (reference section D) |

Output: annotate each endpoint with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — Anchor Window Expansion

Using a known path as the anchor, expand the window to find the payload-building object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clues |
|---|---|
| axios instance | `data` / `params` |
| unified request | interceptor injects global fields |
| OpenAPI client | generated method signatures |
| React Query / SWR | second argument of the hook |
| Vue composable | composable arguments |

Type residue: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

→ `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — Binding Layer

```
Form field → onFinish/handleSubmit → transform → API payload
```

| Binding source | Technique |
|---|---|
| Form submit | follow submit → transform → API |
| Table search | `getFieldsValue()` → `params` |
| Route | `:id` / `?tab=` |
| Interceptor | global `tenantId`, pagination, sign |
| Enum select | `options` → API enum values |

Trace upward from `fetch`/`XHR.send` in the DevTools call stack to the payload-building function.

#### 1b.3 — Three Payload Questions (≠ Phase 2 Authentication Gates)

| Question | What to answer |
|---|---|
| **Assembly** | where the payload is built, transform traces |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

The interceptor gate (Phase 2) also picks up globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 — Handoff to Phase 3

Candidate fields come from the static/binding layer; **required/optional/conditional dependencies** require the Phase 3 parameter matrix + diff + Phase 5 error-based inference.

---

## Phase 2 — Three Authentication Gates

grep in `OUTDIR/js/` (with `head`) and write to `config.json` (see reference for recipes):

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | How to detect a logged-in state? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers a redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Do not treat localStorage key names as credentials — confirm them from chunks/request chains.

**Exit = Gate B**: record conclusions in `config.json` and modify `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b — API Observation (optional)

Use `preload.js` inside OUTDIR to confirm session key names, Authorization, and nested API URLs:

| Setting | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | header observation |
| `extractUrlsFromResponse: true` | sub-APIs inside responses |
| `observe.storageReads/cookieReads: true` | backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

Each coverage round exports: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — Runtime

Gate B must have been passed; follow [Boundaries and Prohibitions](#boundaries-and-prohibitions-agent-must-read--violating-is-out-of-bounds) · credential-free mock strategy.

`config.json` sets `"runtimeMode": "depth" | "coverage" | "both"` (see reference for the template).

### Hooks and Stubs (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 precise | auth/permission/bootstrap stubs | pass first-screen authentication |
| L2 negative correction | all JSON responses | not-logged-in codes → success |
| L3 fallback | `/api` etc. not matched by L1 | empty success body to open up the UI |

- **depth**: fake auth + `forward` to patch business codes + `stubs`; traverse `routes` (hash/history); produce `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or a userscript)

Verify: `window.__API_RECON_PRELOAD__` exists; business paths do not redirect to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — coverage Dynamic Enumeration (required)

1. Main nav/sidebar — click each item, wait 1–3s for network activity
2. Tabs — `role=tab`, `.ant-tabs-tab`
3. Tables — view/edit/details on the first row
4. Toolbars — export, filter, create (**avoid irreversible deletion**)
5. On entering each module — merge APIs/routes
6. SPA — controlled `pushState` for paths not covered by `routes.txt` (prohibited for MPA)

**Parameter-trigger matrix** (required): record once per operation type in each module, and **diff multiple samples**:

| Operation | Parameters usually added |
|---|---|
| Initial list view | pagination + default filters |
| Click search | keyword, filter |
| Advanced filter | more optional fields |
| Create/edit | full entity |
| Bulk/export/sort | `ids[]`, `exportType`, `sortField` |

**Under stubs, outbound bodies/headers are still real** — treat the request as authoritative. Record to `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: 3a depth first, then 3b coverage

---

## Phase 4 — Permission Tree Reconstruction

**Trigger**: blank module pages / only bootstrap per route (e.g. locale) → the content gate was not passed.

| Symptom | Meaning |
|---|---|
| Post-login shell reached | render gate + interceptor gate passed |
| Missing sidebar items / blank on click | stub shape or permission codes incomplete |
| Same and very few APIs on every route | `v-if permission` not passed |
| `routes.txt` far smaller than the bundle | must be completed from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) → `getResultTree` → `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Stub checks: outer `response_code` consistent with the interceptor gate; flat codes aligned with the tree; `routes` covering all links in `route_map`.

After updating `config.json`, **rerun Phase 3**. For large SPAs you can tune `waitUntil`, `routeTimeout`, `perRouteMs` (see reference sections A3/I).

---

## Phase 5 — Merge and Report

### Output Table

| File | Phase | Contents |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | static bundle and paths |
| `param_candidates.json` | 1b | static parameter-field candidates |
| `config.json` | 2 | three gates + runtime config |
| `runtime_api.json` | 3a | detailed depth recording (including WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | multiple samples, click logs, details |
| `route_map.json`, etc. | 4 | permission-tree intermediate files (if performed) |
| `params_merged.json` | 5 | merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | routes, APIs, params, feature points, limitations |
| **insert_assets** | 5 | write all service and endpoint assets into the asset store |

### 5b — Parameter Merge

Diff from `param_samples.json`; **there is no universal merge script**. See reference J7 for confidence rules (high/medium/low/pending-trigger).

### 5c — Error-Based Inference

Within the authorized scope you may send incomplete requests to read 400 responses (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Mind `data` wrapping, `variables`, and `bizData` before encryption.

The report must state: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary of differences from the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

See [reference.md](reference.md) for more fields and grep recipes.

---

## General Notes

- **Framework-agnostic**: webpack/Vite/Angular lazy-loading methods are the same
- **Transports**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetch can be recorded; RSC/Server Actions are not fully enumerable
- **Blind spots**: JSVMP, WASM, HMAC/mTLS strong validation → static analysis + note limitations
- **Parameter blind spots**: conditional interdependencies, hidden params, WASM payload building → "pending-trigger" / "unreachable"
- **Static is the safety net**: when runtime is blocked, static analysis can still enumerate endpoints

---

## Additional Resources

- Grep recipes, `config.json` template, troubleshooting, hooks, parameter reverse engineering section J, site_map template: **[reference.md](reference.md)**
- See the [Scripts and Gates](#scripts-and-gates) table for reference script paths

## Webpack/Sourcemap Source Leakage (js_audit tool, mandatory for SPAs)

Vue/React SPA dist builds often ship sourcemaps alongside the bundle — the
`sourcesContent` field in `.js.map` is the **full original source** (Vue SFC components, API wrappers, hardcoded secrets),
constituting CWE-540 source code information disclosure.

**Use the platform tool `js_audit`** (1–6 entry URLs, automates the full chain):

1. Given the entry HTML (or a known .js) → script-extract `<script src>` and chunks;
2. For each JS, detect `//# sourceMappingURL=` (external/inline base64) + fallback probe `<js>.map`;
3. On a hit, restore sourcesContent to the task directory `jsmap/` (preserving .vue/.env structure);
4. Simultaneously scan for secrets (Alibaba Cloud LTAI/AKID, AWS AKIA, private keys, JWTs, AK-SK key pairs, internal network ranges)
   and endpoint/route inventories (http URLs, `/api/**`, vue-router paths).

**Verdict criteria**:
- map hit and sourcesContent restorable = CWE-540 **high** (L3: original source obtained);
- restored content contains **real, usable credentials** (AK/SK that work, private keys that decrypt) = **critical**;
- only minified JS with no map: extract `baseURL`/`/api/**`/routes from chunks into the contract inventory
  (hand off to `api_contract` / `api-security-testing`).

False positives: a `.map` request returning 200 whose body is SPA fallback HTML (not JSON) does not count as a hit;
`sources` containing only the webpack runtime with no business files does not count.
