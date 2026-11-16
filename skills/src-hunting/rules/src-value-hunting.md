# SRC value-driven hunting rules (mandatory experience)

> Source: a retrospective on list-injection field work.  
> Responsibility: make sure every conventional vulnerability type is covered and no endpoint parameter is missed, while only pushing the points that carry real impact. Whether something is written, and how, is governed only by `vuln-report-format.md`.  
> Site-entry cadence (describe this surface, extract keys from JS, find surfaces with a differential, session object graph, escalate a medium) is governed by `dig-scope-workflow` §4; this file governs "what to hunt, the minimum probe per class, how to allocate effort (§1.1)".

---

## 1. What to hunt: real value first

Valuable = reaching the high/critical tier: cross-tenant/cross-user read or write, unauthenticated access to business-sensitive data, low privilege up to platform administrator, injection returning another subject's data, a complete chain (cross-user write, account entry, command running). How to allocate effort and what to hit first on entering a site are governed only by §1.1 below. A matrix with an entry point is still ticked or N/A; do not delete types.

**The semantics of "administrator" (easy to misread — make sure you get it right):**
- When the user says to watch "administrator", it means watch whether **official/platform-level administrator privileges** are reachable, plus the escalation chain
- It is **not** "the current identity is tenant ADMIN, so anything it can see is not a bug"
- Tenant ADMIN is a **springboard perspective**: use your own tenant baseline (e.g. session total=2) to compare whether injection/IDOR turns it into a huge volume/another tenant

### 1.1 How to allocate effort (hit what is more likely high/critical first)

Do not delete types, do not add a fifth piece, **XSS is chased as hard as injection/SSRF/RCE**. Site-entry order is governed by `dig-scope` §4; this table only governs where effort goes first.

| Hit first | Notes |
|------|------|
| Unauthenticated access to another person/subject | Lists/details/attachments without login. **Once unauthenticated access passes, swap ids (no field-name restriction)** (`dig-scope` §4.2.3). If a file channel opens, pivot to business; do not stop at uploadable/downloadable |
| Authentication takeover | Session issuance / reset / rebinding / ticket exchange; only counts if you enter the account or change the password (`dig-scope` §4.2.2) |
| Id swapping (no field-name restriction) | No account: swap once unauthenticated access passes. With an account: swap with the session (`dig-scope` §4.2.3). Another subject appearing = broken through |
| Writes/logic with an account | Add `role`, change amounts/status, skip review, coupon/inventory races; watch whether the tenant identity can reach **platform/official** administrator |
| All four pieces hard | Injection where there is a count/echo; SSRF where it fetches a URL; XSS where there is an echo/storage; RCE where there is a command/template. Injection must return another subject or a stable differential |
| JS keys | salts, hard-coded keys, demo accounts |

**No account:** once unauthenticated access passes, swap ids (no field-name restriction) → auth endpoints → JS keys → the four pieces on surfaces with a differential (including XSS).  
**With an account:** swap ids with the session (no field-name restriction) → add fields/skip steps/money → the four pieces on those business parameters that already returned data (including XSS).

**Still test if there is an entry point, but not as the main line:** CSRF that only harms yourself (still follow a successful cross-user write), uploadable/downloadable with no chain, weak passwords on the login form.  
**Already in the checklist** — GraphQL / upload / XML / WebSocket / XXE / deserialization: finish them on this site or write N/A; they are just not inserted ahead of id swapping and takeover. This is not "go looking for these endpoints at every site"; but once you dig one up you may not pretend you did not see it.

---

## 2. When you hit these, do not stop halfway (how to test)

Whether it is written and at what severity is governed only by `vuln-report-format.md`. This section only says how to keep hunting:

- A file channel opens → pivot immediately to business APIs, executable/path/SSRF chains  
- The code-sending endpoint passes → follow the auth chain: does the response contain the code, is the code bound to the number, does reset swap the user (`dig-scope` §4.2.2)  
- The slider passed / password guessing is possible → stop on the form shell and hit empty passwords, step skipping, reset, rebinding  
- A DSN/config with only a host and no credentials → keep looking for complete credentials; with credentials/AKSK treat them as keys: prove production accepts them with a fake-value control, the key-recognition shot must produce an identity or a list, then hit a read-only example that does not affect production (if the first shot already produced one, switch to a different kind of read-only). After a human account produces a session, hit a read-only example the same way; grading follows format. Disproven = no key. Stopping to submit as soon as you copy it = forbidden. Phone-number encryption keys do not count as keys (whether it is written follows format)  
- CORS is **not hunted** (see `cors-vuln-report-priority.md`)  
- Readable by design, public static, endpoint 200 with JSON → pivot to cross-user/injection/escalation  
- An id / download URL / token / internal host pops out of a response → queue it for this site and hit it (`dig-scope` §4.1.3)  
- **A medium is recorded, then escalate the chain before switching sites**: the same object has not yet reached writes / cross-user / takeover / executable, so follow it first (`dig-scope` §4.3)  

## 2.2 Hunting preference prohibitions (permanent)

- **Forbidden** to hunt CORS  
- **Forbidden** to pin session effort on unauthenticated reads/isomorphic lists for several days without touching **injection / SSRF / XSS / RCE** (details in `dig-scope-workflow` §4.2.1).
- **You must** advance through the §3 type matrix: unauthenticated, IDOR (with a session it is as hard as the four pieces, see `dig-scope` §4.2.3), injection, SSRF, RCE chains, credential leaks, weak passwords (bare middleware defaults; **weak passwords on the login form are not mandatory**, see `dig-scope` §4.1.1; **demo accounts in JS/pages count as keys**), sensitive paths, XSS, upload, traversal, CSRF, privilege escalation, logic, **auth/arbitrary login/takeover** (see `dig-scope` §4.2.2) — **hunt all of them** (the union with `dig-scope-workflow` §4.2; **excluding CORS**).
- After an unauthenticated read returns a batch → **immediately** run the §3 injection parameter table + SSRF URL parameters + XSS echo/storage + RCE sinks against the same batch of endpoints (see dig-scope §4.2.1, hit on surfaces with a differential); switching sites right after the unauthenticated read with zero four-piece payloads is forbidden.
- With a session, spraying only `'` is forbidden: object graph / id swapping / adding fields / step skipping per `dig-scope` §4.2.3.

---

## 3. Full coverage: type matrix (cover at least once per round)

For the current target's endpoint inventory, tick by type; **you may not test only information disclosure**.  
Site-entry order is governed by `dig-scope-workflow` §4 (describe this surface first, then extract keys, build the inventory, then test; switch sites when this round is done).

| Type | Probe requirement (finish it where there is an entry point; N/A + reason where there is none) |
|------|----------|
| Unauthenticated | Key reads/writes with `credentials:omit`. Once it passes, swap ids (next row) |
| IDOR | **Finish it where there is an entry point.** No account: swap ids once unauthenticated access passes. With an account: baseline → neighbouring ids / ids copied from responses / `0`/`-1`/empty → attachment export, see `dig-scope` §4.2.3. Do not stop work to get a second account. |
| Injection | On any endpoint where you can see the count or content change, or which fetches a URL: test **every** query/filter/sort/keyword parameter above (baseline → probe → differential, details in §4). If it only returns "please log in" with no business fields → the whole segment is N/A; do not drop `'` on each one. An empty list / error / timeout is not "please log in"; for the control see `dig-scope` §4.1.2; stop when there is no differential. **Pick probes by stack**: JSON/Mongo → operators; search box → ES or list OR+total; Java → HQL/SpEL; template → SSTI; SQL surface still uses `'`/boolean/delay/WAF encoding. If blocked, change position (query/json/header/path). Username/password boxes are not business parameters; `tenant` / `corpId` / `moduleId` on a login endpoint are hit if present (`dig-scope` §4.1.1). |
| SSRF | Every URL/callback/webhook/file/fetch/import/preview/proxy parameter: intranet/metadata/exfiltration |
| RCE / code execution chain | Follow command/expression/template/deserialization/dangerous-upload sinks to execution or disproof |
| Credential/key leakage | After copying a token/AKSK/private key/connection string: fake-value control, the key-recognition shot must produce an identity or a list, then hit a read-only example that does not affect production. A human backend login producing a session is graded per format. Placeholders/expired/real and fake giving the same error, no reachable key-verification endpoint, phone-number encryption keys → N/A (not written; per format). |
| Weak passwords / default endpoints | Bare middleware/component defaults are visible at a glance; hit until a real session. Weak passwords on the login form are not mandatory (`dig-scope` §4.1.1). **Hard-coded demo accounts and test tenants in JS/pages are used as keys.** |
| Sensitive paths | Swagger/Actuator/debug/heapdump/env etc.; if there are keys, keep digging |
| XSS | Reflected (parameter echo with tags/events) + stored (write point then read back); consider whether it is readable without login |
| Upload | Type bypass, path, executable/SSRF chain; do not stop at uploadable/downloadable |
| Traversal | fileKey/path/filename |
| CSRF/auth parameters | No ctoken / bad ctoken + Cookie attributes; whether the write succeeds |
| Escalation / logic | **Finish it where there is an entry point, at the same density as injection.** Add `role` / `isAdmin` / `amount` / `status` / `vip` to write endpoints (only change what you can change back); skip steps in multi-step flows; change money/coupons/inventory smaller, negative, fractional; fire one concurrency shot wherever claiming/review is seen. No such endpoint → N/A. With a session see `dig-scope` §4.2.3. |
| Auth / arbitrary login / takeover | If the inventory has session issuance / reset / rebinding / ticket exchange / 2FA → tick them off per `dig-scope` §4.2.2. Username/password boxes are not part of the four pieces |
| CORS | **N/A · not hunted** |
| Other on-site surfaces | On-site surfaces not named by the matrix are still tested; auth endpoints follow the previous row |

---

## 4. Endpoints and parameters: no missed fields

1. Open the real page → capture the **complete** request (query + body)
2. List every filter/id field, and **test short enum fields too** (e.g. `vote`, `answerType`, `status`)
3. On endpoints with a differential, the minimum matrix per filter parameter (endpoints that only return "please log in" are excluded; username/password boxes are not business parameters, see §3 and `dig-scope` §4.1.1):
   - normal value / empty / illegal value
   - pick probes by stack: SQL surface `'` / boolean; JSON surface operators; search box ES/OR+total; Java HQL/SpEL; template SSTI
   - delay (by database type)
   - WAF encoding: `%0a` `%0d` double-write comments case mixing; **and change position** (query / json / header / path)
4. **The differential is the hard evidence**: your own tenant's baseline total/count vs the total/another subject's fields after the payload

**Lesson example (list filter fields):**
- `vote`: the user hinted injection existed; currently mostly 405, possibly fixed, but still needs regression
- `keyword=1%0aor%0a1`: WAF bypassable, total went from 2 → tens of millions, cross-tenant metadata → **a real SRC point**
- Why it was missed: only "is there data" was checked, the "full-parameter injection matrix" was not run

---

## 5. Execution cadence

1. **Complete the asset set**: domains, login state, menu routes, APIs extracted from JS (including salts/encrypted ids/hidden routes/demo accounts), the real request parameter table; add ids/urls from responses into the inventory  
2. **Value ordering**: per §1.1, hit unauthenticated other-subject / authentication takeover / id swapping / the four pieces (including XSS) first; information disclosure goes later and is described in downgraded terms  
3. **Full type sweep + full parameter sweep** (surfaces with a differential first); test new endpoints as soon as they are queued; with a session do the object graph before spraying parameters; CSRF/uploadable-downloadable/login-form weak passwords are not the main line  
4. **Keep only reviewable evidence** (requests, differential tables, key fields); do not pile up useless "gains"  
5. Once broken through, write to disk per `vuln-report-format`; escalate the same object's medium chain first; dig does not replace the body text

---

## 6. Self-check (before submitting a conclusion)

- [ ] On endpoints with a differential, did every filter parameter get an injection/IDOR differential? Did you mis-spray any that only return "please log in"?  
- [ ] Was unauthenticated access tested with omit (business endpoints)?  
- [ ] Was cross-tenant/other-user tested (not just what your own tenant ADMIN can read)? With a single account, did you use ids from responses/lists rather than giving up?  
- [ ] With a session, were the object graph / id swapping / adding fields / step skipping hit (`dig-scope` §4.2.3)?  
- [ ] Was upload followed to executable/SSRF/business IDOR, not stopped at uploadable-downloadable?  
- [ ] After code sending/slider, was the auth chain hit per `dig-scope` §4.2.2?  
- [ ] Was "administrator" misjudged as "within permissions so not a bug"?  
- [ ] After a WAF 405, did you change encoding/parameter position and retry? Was the injection probe chosen by stack?  
- [ ] **Did you mistakenly hunt CORS?** (not hunted)
- [ ] **Was this round lopsided, hunting only unauthenticated reads?** Did you just spray `'` on every path to tick the four pieces?  
- [ ] **Injection**: on query/filter parameters with a differential, did you do baseline + probe + differential?  
- [ ] **SSRF / XSS / RCE**: were URL-type parameters, echo/storage points and exec-type sinks really hit, or N/A + reason? Any multi-day gap?  
- [ ] After recording a medium, did you escalate the same object's chain first? Did response clues enter the inventory?  
- [ ] Were copied credentials fake-value controlled, did the key-recognition shot produce an identity or a list, and is there a read-only example that does not affect production? Did you write a phone-number encryption key as a bug? Did a human account entry have a read-only example?  

---

## 7. In one line

**Cover every type and every parameter; allocate effort per §1.1 to what is more likely high/critical (unauthenticated other-subject / takeover / id swapping / the four pieces including XSS); hit the four pieces on surfaces with a differential and pick probes by stack; with a session, IDOR/logic is as hard as the four pieces; auth endpoints are ticked off per `dig-scope` §4.2.2; CORS is not hunted; prove cross-privilege/injection with a baseline differential. Escalate a medium's chain first. Whether it is written is governed only by `vuln-report-format`.**
