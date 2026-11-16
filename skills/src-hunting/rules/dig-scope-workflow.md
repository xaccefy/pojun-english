# Vuln Hunting Scope · Locked Scope / Free Jump (Permanent)

> **Always augment, never hard-limit** (same spirit as `skill-as-boost`).  
> **Users should not have to rely on "no new reports for a long time" to notice idling** — the Agent must self-check and correct course; it is forbidden to fake busyness with queues/logs.  
> **Per-site type matrix** is consistent with `src-value-hunting.md`; this file does not reduce types.  
> **On-site tactics** (§4.0 explain this site / §4.1 extract keys / §4.1.3 response clues / §4.2.1 differential surfaces / §4.2.3 session object graph / medium-severity chain escalation / fat-thin): Section 4 of this file is authoritative; type probe density follows `src-value` §3.  
> **Free jump: keep hunting until the user explicitly calls a stop; do not ask "should we continue" midway.**  
> **Single-seed closed loop (2026-08-16): all seeds follow "search one → dedup, remove duds, remove dead → finish hunting the rest → only then search the next"; searching all seeds at once is forbidden.**

---

## 0. Determine mode first

| User instruction | Mode | Behavior summary |
|----------|------|----------|
| Vague target (only a group name, no URL list), no fixed URL list | **Free jump** | Prepare as many seeds as possible → persist queue → **single-seed closed loop (search one → dedup, remove duds, remove dead → finish hunting the rest → only then search the next)**; **searching all seeds at once is forbidden**; resume old folder, skip already-hunted/already-searched; all done → random/rescan for additions (§1) |
| Fixed site / fixed URL / documentation URL / URL list | **Locked scope** | **Do not proactively FOFA outside the scope**; multiple hosts within the asset cluster, business-flow subdomains, multiple paths on the same host **must all be hunted** |

Principle: **no scope specified = free jump; site/document/list specified = locked scope.** The current instruction takes precedence (saying "lock it down / don't jump yet" on the spot → overrides the default).

### 0.1 Locked-scope definition (avoid locking too tight · user 2026-08-06)

What is locked is **"don't secretly turn into free jump and FOFA the whole group"**, not nailing down the entry string.

| Locked (forbidden) | Not locked (must hunt) |
|------------|------------------|
| FOFA/brute-force scanning the whole group, unrelated business units before entering the site | Multiple hosts included/loaded by the entry → hunt them all |
| Arbitrarily jumping to side domains unrelated to the current asset | Subdomains, gateways, API domain switches after login/clicking functions → follow the business flow |
| Using documentation as a free-jump seed to expand the group | Fully expand multiple paths/endpoints on the same host; **same-product business hosts** surfaced by JS/config are included in this round |

**Within locked scope:** user entry host; business hosts in page/JS/config/responses; subdomains/gateways naturally reached via business flow; multiple hosts in the same asset cluster.  
**Outside scope:** FOFA-ing the whole brand before entering the site; attacking unrelated product lines merely because they "seem like the same company".  
**Forbidden misinterpretation:** locked scope ≠ only test when hostname literally matches; ≠ only test that one path in the docs; ≠ stop as soon as the subdomain changes; documentation defaults to locked scope — only when the user separately says to hunt a certain group is it free jump.

**Locked-scope end:** after finishing this round's matrix for the current asset cluster you may stop or give a short report; it is not infinite free jump.

**Locked-scope list order (hard · avoid grinding on "one" at a login wall, leaving "important" for last):**

| Do | Don't |
|----|------|
| User themselves marked "important asset / priority" → **attack that group first** | Treat "one, two, three" as having to clear the first section top-to-bottom |
| "Hunt them all" = every one gets its turn in the rotation; keep only 2–3 representatives for same-skin (§3.3) | Grind out CAPTCHA/default credentials on login wall #1 before touching CDP / BI / LIMS |
| Login shell same-skin → no need to re-hunt the login form. What the representative site did in §4.2.2, sibling does a glance-diff (any new reset / rebind / token-exchange path); no new endpoints → no separate full matrix. Still compare `jump` / `service=` / `moduleId` to see if it's another business surface (if so, go hunt it) | Open a fresh full matrix for every same-skin host; skip the whole batch based only on comparing login shells |

It is forbidden to read §1.0.1's "don't pick premium surfaces and throw away the rest of the live URLs" (free-jump single-seed) as meaning locked scope must run the full matrix in the original text order.

### 0.2 Collaboration ruling (overrides researcher's "wait for continue")

| Context | Behavior |
|------|------|
| Free-jump vague target | **Do not stop, do not ask to continue**; missing comparison account → downgrade to test what you can, record as you hunt |
| Locked scope / white-box / writing code | May report per each file's convention when the list is exhausted or before a run |
| Truly missing the only technical prerequisite and cannot downgrade | After a very short issue report, still hunt huntable surfaces; **forbidden** to use a question as a reason to stop work |

---

## 1. Free jump

### 1.0 One diagram (must pass at the start)

```
Vague target
  ├─ Desktop has {target}_SRC-hunt and not cleaned?
  │     Yes → resume: read seed queue + covered_hosts + reports/ + dig STATE
  │           skip done/cold seeds and covered hosts; start from pending
  │     No → new: create task root; prepare as many seeds as possible and persist; order may be shuffled
  │
  ├─ Knowledge base has matching `*src-lessons.md`? Only open if present; absence is not a deficiency
  │     Yes → open alongside the short list; also open in a new window. Special article = criteria/dead-end clusters, not this site's list, does not replace the matrix
  │
  ├─ Take seed S (pending first; P2 filings liveness-screen first)
  │     → Search only this one S (FOFA/pool-refill revolves only around S; this seed's results may be paginated)
  │     → URLs produced: dedup → remove duds → remove dead → 100% ownership gate
  │     → All remaining live surfaces get full on-site matrix (§4) → successes persist to `reports/` per format
  │     → Search domain R surfaced by premium surfaces only feeds back into queue; do not search R until this seed's remaining live surfaces are finished (§1.1.1)
  │     → All this seed's remaining live surfaces finished (or all dud/dead) → mark done → only then search next pending (don't ask to continue)
  │
  └─ Queue all done / covered mostly filled and user hasn't called a stop?
        → Randomly add keywords and search again  or  rescan old seeds, only picking up new hosts relative to covered
        → Once business-registration/SRC is available, incrementally add level-4 and new business names
```

### 1.0.1 Single-seed closed loop (hard · user 2026-08-16)

> **All seeds follow this, without exception.**  
> **Forbidden** to search all seeds in the queue at once before hunting.

```
Take one seed S
  → Search only this one S (FOFA/pool-refill revolves only around S; this seed's results may be paginated)
  → URLs produced: dedup → remove duds (§3.1) → remove dead → ownership gate (§3.2.0)
  → Finish hunting all remaining live surfaces (each site passes §4.3, or record dud/dead/same-skin-skip/already covered)
  → Only then mark this seed done → only then allowed to search the next seed
```

**Forbidden:**

| Forbidden | Explanation |
|------|------|
| Searching multiple seeds in a row / all at once | FOFA the queue once to stockpile a big pool, then go back and hunt |
| Switching to a new seed while live surfaces remain | After cleaning this seed, unhunted live URLs remain, so start the next seed or FOFA the back-fed R |
| Misreading "batched FOFA" | "Batched" refers only to pagination of **this one seed's** results, not searching multiple seeds in a row |

**What "finished hunting" is / is not:**

| Is | Is not |
|----|------|
| After cleaning, every `host:port` worth hunting has passed §4.3 (list + matrix + four-piece set on differential surfaces + §4.2.2; with session also §4.2.3; thin surfaces falsified at a glance), or recorded dud/dead/same-skin representative done/same-gate glance-diff (§4.1.2)/globally covered | Universe-level exhaustive digging of every historical path; spraying `'` once at each of 80 empty shells |
| Discover dead shell, 403 idling, same-skin only after entering → record and may skip that entry, counts as handled | Pick two or three "premium surfaces" for a matrix, leave the rest of the live URLs to go search the next seed |
| After cleaning the pool is empty (all dud/all dead) → mark this seed done immediately, search the next entry right away | Having the FOFA count for this seed in hand counts as "search finished, can switch seed" |

**Remove non-live (mandatory after searching this seed, discard before hunting):**  
Unreachable / timeout / parking page / no business response = non-live, do not hunt.  
401 / 403 / login wall / admin console challenge page = **live**, do not discard as a dead site.  
**Live ≠ grinding on the login form.** See §4.1.1: first find the business API / business host after redirect; with no session, focus main effort on unauthenticated hunting. For issue-session / reset / rebind / token-exchange, if there is an entry follow §4.2.2, no entry → N/A, do not grind on the form. For same-skin see §3.3.

**Still allowed within this seed's closed loop:**

- Paginate this seed's FOFA to collect all of this seed's results  
- Persist premium search domain R as pending (§1.1.1), but do **not search R** until this seed's remaining live surfaces are finished  
- Quota exhausted: stop searching, hunt what's already stored for this seed

### 1.1 Prepare as many seeds as possible (hard · user 2026-08-06)

**Forbidden:** FOFA only the user's original term; cap seed count at "at most N"; treat writing one batch as completing the queue; never refill the queue because Qichacha is down; **search all seeds at once before hunting**.  
**Required:** after layering, strictly follow the **single-seed closed loop (§1.0.1)**: search S → clean (dedup, remove duds, remove dead, ownership gate) → finish hunting all remaining live surfaces → only then search the next. For a single site, §4.3 is enough to switch to the next host within this seed; "finished hunting" ≠ universe-level checking off every path.

| Dimension | Requirement |
|------|------|
| **Business name / product / sub-brand** | List as many as possible (payments/finance/cloud/blockchain/mobility/digital-tech/international/internal lines…); everything scannable from SRC, official sites, news, business registration public names goes into the queue |
| **Wholly-owned levels 1–4** | child → grandchild → great-grandchild → great-great-grandchild **dig as deep as level 4**; entity name, former names, public brands/root domains all count as seeds; **minority stakes excluded** (§3.2.0) |
| **Wholly-owned root domains / filing primary domains** | Big companies often have far more than 15; list as many as you can; P2 long-tail liveness-screen before FOFA |
| **SRC official scope** | Business lines, domains, product lists **scan in full into the queue (P0)** |

**Quantity: no upper limit.** Business names, wholly-owned levels 1–4, root domains/filings, SRC scope, back-fed R — list as many as possible. Some SRCs are inherently large; dozens to hundreds is normal and required; **forbidden** to cut down to a fixed count.  
"At least persist one batch before starting to hunt" only guards against lazily writing just the user's original term; **no count is a target, let alone an upper limit.** Tool down → first write known ones and start hunting; once available, **incrementally refill the queue**.

| Source | Explanation |
|------|------|
| User's original term | Entry point, not the only one |
| Business name / sub-brand | As many as possible, no cap |
| SRC official site | Scan in full into queue, P0 |
| Wholly-owned equity levels 1–4 | 100% chain; minority stakes excluded |
| Filing/root domain | List as many as possible; P2 liveness-screen first |
| **Premium-surface back-fed root domain** | Valid premium assets confirmed by FOFA/on-site → extract **registered root domain (second-level domain)** as a new seed to search again (§1.1.1) |

**Layering (who gets FOFA first):**

| Priority | Seed type | Strategy |
|--------|----------|------|
| **P0** | User-named business, SRC-published domains/business lines, in-use well-known product root domains | Can FOFA directly; still need to remove duds |
| **P1** | Domains common on Qichacha/certificates, whose titles/org often collide with the brand | Only FOFA after second-level liveness check passes |
| **P2** | Large batches of ICP primary domains, historical shell domains | **Must liveness-screen with §1.2 first**; fail → not sent to FOFA |
| **Dud/cold** | Dead filings, pure parking, no DNS | Do not touch this round |

Finish P0/P1 via the single-seed closed loop before scanning P2; **forbidden** to FOFA hundreds of unscreened filings one by one from the start. The queue may list many P2 up front (no upper limit), but sending to FOFA requires liveness-screening first, and searching only one at a time.

### 1.1.1 Back-feed premium asset root domains as seeds (hard · user 2026-08-07)

> Free jump: FOFA/on-site encounters a **valid premium surface** → **immediately** write the corresponding **search-domain keyword usable with `domain=`** into the seed queue.  
> Only when it's time to jump — **after all this seed's remaining live surfaces are finished** — **prioritize** using that keyword to FOFA the whole domain; if there are new hosts relative to covered, hunt them, otherwise jump to another seed.  
> Purpose: don't nail the search to the single user original term; root domains of premium business clusters should roll into the keyword pool for further expansion.  
> **No course change:** back-feed ≠ immediately go search R; until this seed's closed loop is complete, starting a new search for R is forbidden.

**Semantics (understand the concept; the rules don't hardcode example domains)**

| Concept | Meaning |
|------|------|
| **Business host** | A specific site (multi-level subdomain / entry with path), enters covered, gets a matrix |
| **Search domain R** | The layer **reduced upward** from a premium host, suitable for `domain="R"` (business cluster root / independent brand root, not every leaf host) |
| **When to persist** | **Persist as soon as a premium huntable surface is confirmed** (pending), **no need to wait** for universe-level completion of that site |

**Reduction principles**

- Leaf subdomain → reduce to its **business cluster root** before searching (multiple level-3 hosts under the same cluster map to only **one** R)  
- Already a business cluster root / independent brand root → R is itself  
- Under a large group, don't just back-feed one already-queued group-wide root and call it done; **newly appearing product/business cluster roots** must each be able to enter the queue separately and get `domain=`  
- **Forbidden** to treat every full host string as a new seed to brute-FOFA

**When to back-feed (all conditions must hold)**

1. Source: this task's FOFA **or** on-site/JS/response host (already passed §3.2.0)  
2. **Premium**: large business surface / lots of JS·endpoints / login backend / business API / Swagger·admin console, etc., matrix can continue  
3. R can be reduced, and R is **not yet** in the seed queue  
4. Ownership passes the gate; minority stake / CDN / third party / dud shell **not back-fed**

**Do not back-feed**

| Don't write to queue | Explanation |
|--------|------|
| Dud shell / Hello / pure-SEO same-skin | No business matrix value |
| CDN / image host / third-party library | Noise |
| R already in queue | Prevent infinite loop |
| Multiple hosts in same cluster but R already pending/done | Add R only once |
| Minority stake / outsourced / out-of-scope | Ownership gate |

**Persist-and-research rhythm**

1. **Confirm premium → immediately** add a row to `seed_queue.md`: seed=`R`, P0/P1, **pending**, note "back-feed · source host=…"  
2. **Keep hunting the current host** (§4.3); keep hunting this seed's remaining live surfaces; can run in parallel with persisting  
3. **Only when this seed's remaining live surfaces are all finished and it's time to switch seeds**: prioritize taking the back-fed pending → `domain="R"` search only this one R (results may be paginated) → dedup, remove duds, remove dead + ownership gate → **finish hunting the rest** before searching the next  
4. **If there are** new hosts/surfaces relative to covered → **prioritize finishing them**; **if not** → immediately jump to next pending (don't ask to continue)  
5. No quota: persist first, hunt what's already stored for this seed; when quota is available and this seed is finished, then search R

**Forbidden:** brute-FOFA every leaf host; for premium only record the host without back-feeding R; after back-feed, not doing full hunting without removing duds/dead; idly searching R again after it's already searched; **going to FOFA that R while this seed still has live surfaces**.

**In one sentence:** premium hosts are for hunting; the **search domain R** reduced upward goes into the seed pool immediately; **only after this seed is finished** prioritize FOFA-ing the whole R to scoop new assets, if nothing new then jump.

### 1.2 Filing long-tail · live-domain screening (hard)

**Filed ≠ huntable.** Cheaply screen the long tail first, FOFA only if live, skip directly if dead.

| Dead/cold (skip) | Live/worth FOFA |
|---------------|--------------|
| Root domain has no DNS **and** crt/passive also have no useful host | Root or **subdomain** resolves (businesses often only hang api/admin) |
| Root + www + known-subdomain probes are all parking/default pages | Any host has real business (login/API/admin console) |
| FOFA `domain=` count probe size=0 or all park (when quota available) | Already seeing multiple hosts/ports/title differences |
| Zero title/certificate/redirect association with the brand | Certificate SAN carries business name; or root domain surfaced by a confirmed live site |

**Forbidden to judge dead on a single signal:** root/www unreachable → must also check crt/passive subdomains; only 401/403/login wall = **counts as live**; with no FOFA quota, liveness screening relies only on DNS+HTTP+crt, **forbidden to re-brush FOFA for empty screening**.

```
Filed long-tail d
  1) Root DNS? None → don't judge dead immediately, do 3) first
  2) Root/www short-timeout probe 80/443 → business vibe upgrade to live; parking/unreachable → go to 3)
  3) crt/passive subdomains → useful subdomain upgrade to live; 0 and root/www dead → cold
  4) Quota available → optional domain count probe; no quota → skip
  5) Passed → formal FOFA → remove duds → hunt
```

**Quickly discard even after FOFA:** empty/very few and all CDN default pages; homogeneous parking titles; only mail/irrelevant ports; totally unrelated to the brand → **switch to the next entry for this seed immediately**, forbidden to dig stubbornly.

| Stage | Blocks what |
|------|--------|
| §1.2 liveness screen | Dead filings at the domain-field level |
| §3.1 dud removal | Host noise scooped from live domains |
| §3.2 Hummingbird | Only doubtful ownership |
| §3.2.0 ownership gate | Minority stake / non-100% entity |

### 1.3 Task folder: resume / new / all done before (hard · user 2026-08-06)

**In one sentence:** with an old folder, first skip already-hunted/already-searched; if cleared, start new with multiple seeds in shuffled order; if all done before, randomly search again or rescan for additions.

**A. Old folder still exists (resume)** — when the same vague target is called again:

| Do | Don't |
|----|------|
| **Enter the existing** `Desktop\{target}_SRC-hunt\` | Create another "{target}2_SRC-hunt" or treat as a brand-new task |
| Read at start: `assets/covered_hosts.txt`, `assets/seed_queue.md`, `reports/`, dig STATE | Ignore covered and run a full matrix again on an already-done site |
| Prioritize pending, uncovered hosts, new FOFA uncovered surfaces | Re-run done/cold seeds as P0 for nothing |
| Same host **new path/new port/new application** still tested (§3.1.1) | Interpret "skip already hunted" as not even touching new endpoints on the same host |

**B. User cleaned the task folder (new)**

No covered/old queue to rely on → create new directories and queue; seeds still follow §1.1; **order may be shuffled**; forbidden to stubbornly stick to the user's original term in a fixed order forever.

**C. Mostly all done but no stop called**

Seeds almost all done/cold, hosts almost all covered → **forbidden to ask to continue, forbidden to idle-wait**. Prioritize 1; rescanning is spot-checking, not an assembly line.

1. **Random re-hunt (default first)**: add business name/product/domain keywords, FOFA in shuffled order, only enter uncovered new hosts  
2. **Rescan old seeds (spot-check)**: for previously done ones, **one glance** at FOFA/crt/homepage again, **only care about additions relative to covered** (new host, same host new path/new port/new application, build number changed and surfaced new APIs)

**Rescan qualification gate (hard · prevent rescan factory):**

| Enter site only with prior evidence | Switch immediately, full matrix forbidden |
|----------------|-------------------|
| New host relative to covered | umi/build number unchanged, and no new path |
| Same host **new** path / new port / another application | Only confirming "same shell as Txx" |
| JS hash changed **and** new API extracted | Only to re-confirm a bug already in `reports/` (chain escalation, new path, new type don't count) |

- Rescan deliverable only writes: list of new surfaces, or a line `0 new`. `0 new` **does not count as progress**.  
- **Two consecutive** rescans this round both `0 new` → next slot **must** go with random new business name, forbidden to start another "XX rescan". Count resets across tasks / after the user opens a new window.  
- Forbidden to rotate threads over already-done seeds like Fortune/Ant Shield/Morse/Chain to brush covered.

Still obey: 100% ownership, §1.5 quota, §3.1.1 dedup. The experience article's "forbidden to report fake findings" ≠ "root domain permanently banned" (see corresponding `*src-lessons.md`).

### 1.4 Seed queue persistence + round-end gate (hard)

**Failure mode:** stop after one round of searching + ask "should we continue" + not switch brand/domain; **or search all seeds at once before hunting**.  
Use **persisted queue + round gate + single-seed closed loop (§1.0.1)** to block it.

**Path (prefer short path):** `Desktop\{task}_SRC-hunt\assets\seed_queue.md` (or `{name}_dig/seed_queue.md`)

| Seed | Type | Status | Notes |
|------|------|------|------|
| Business name / SRC domain / wholly-owned subdomain… | P0/P1/P2 | pending / doing / done / cold | When to FOFA, pool size, why cold; on resume done=already searched, skip first |

**Start:**  
- New → write queue (business names to the fullest + wholly-owned levels 1–4 + SRC/filings; list as many as possible, no upper limit; may shuffle)  
- Resume → **read** queue+covered+reports, start from pending or §1.3-C; **forbidden** to overwrite history with an empty queue; may incrementally add level 4 and new business names

**Forbidden:** queue containing only the user's original term; writing a fixed count and treating it as complete; only listing verbally without persisting; on resume pretending not to see the old queue.

```
pending → doing → search only this one S → dedup, remove duds, remove dead + ownership gate → finish hunting all remaining live surfaces → done / cold
This seed's remaining live surfaces not finished → forbidden to take next pending to FOFA
Within the same tool loop where this seed turns done/cold → immediately take next pending → doing → run the same closed loop again
Forbidden: after done, end this round and wait for user to say "continue"
Forbidden: search all seeds at once before hunting
All done and no stop called → §1.3-C (random/rescan), not work stoppage
```

**Term disambiguation (idiot-proofing):**

| Wording | Correct | Wrong (forbidden) |
|------|------|--------------|
| This seed wrapped up / this round complete | Only ends the current seed or current site; seed wrapped up = remaining live surfaces finished, immediately switch to next pending and run the loop again | Whole free-jump session ended, can ask the user |
| One round of FOFA finished | This seed's search results fully collected, enter cleaning+hunting; **cannot search the next seed yet** | Whole group finished hunting; or switch to next seed right after searching |
| All searching | Queue all done → still follow §1.3-C, still don't ask to continue | Stop after searching |
| Batched FOFA | Pagination of this one seed's results | Searching multiple seeds in a row / all at once |

**Self-check before sending the final reply (hitting any of these forbids wrapping up and stopping):**

1. Still pending? → forbidden to end; mark next as doing and continue  
2. Just finished a seed? → forbidden to ask to continue; start the next at the same pace  
3. All done and covered filled? → follow §1.3-C + §1.5; only truly stop when the user calls a stop  
4. Last sentence is "should we continue / switch brand / please instruct next step"? → **violation**, delete the question and switch seed

**Blacklist endings (free jump = bug):** "This round's search is done, continue?" "Should we also hunt other brands?" "Let's stop here, your instructions?" "Need me to switch seeds?"  
**Legitimate true stop:** user calls stop/cleans/switches target/explicitly locks scope; locked-scope cluster finished; entire environment unusable and a very short issue report after trying alternate lines.

**After compression/resume:** prioritize reading `seed_queue` + `covered` + `reports/`, continue from the first pending or incomplete doing; forbidden to only remember the user's original term after compression.

### 1.5 FOFA quota and pool refill

- **Quota available:** search only **this one current** seed (this seed's results may be paginated) → dedup, remove duds, remove dead + light ownership (§3.2) → **finish hunting remaining live surfaces** → only then search the next. Forbidden to search all seeds in a row just because quota is available.  
- **No quota (820041/429, etc.):** **stop idle FOFA brushing** (including liveness count probes); hunt what's already stored for this seed; P2 liveness screening switches to DNS+HTTP+crt; when quota is available and this seed is finished, take the next undone seed  
- **Empty results / API down / quota exhausted and pool empty:** pool refill still requires dud removal + dead removal + light ownership + ownership gate  
  - crt.sh, subfinder, user's existing `assets/`, **in-scope** business hosts extracted from on-site JS  
  - SRC/Qichacha new business names into queue; new filings into P2 must be liveness-screened  
- Missing tools → switch lines, **do not stop work**; successes persist per `vuln-report-format`

### 1.6 Surface expansion · opening move · continuous hunting

| Do | Explanation |
|----|------|
| Main expansion | **Single-seed closed loop (§1.0.1)**: search one → dedup, remove duds, remove dead → finish hunting the rest → only then search the next (+§1.5); Hummingbird only for doubtful cases |
| **Premium root-domain back-feed** | Valid premium surfaces confirmed by FOFA/on-site → new **registered root domain** into seed queue; **only search again after this seed is finished** (§1.1.1) |
| JS/config/response hosts | Same-product business hosts enter queue only after the entry site has passed **§3.2.0**; **hosts surfaced by minority-stake sites don't roll in**; new root domains also go through §1.1.1 |
| Fake domains / business keys / third-party library domains | Do not enter queue, do not send to FOFA |
| JS after entering site | Mainly responsible for this site's endpoint discovery (§4.1: path + keys); real business hosts enter queue per the row above |
| Opening priority | Business JSON / backend / admin console / Swagger / Actuator / debug ports. **Having a login only means there's a business surface behind it** (§4.1.1), not that you grind the login form; weak password on login form is not an opening move. Not grinding the form as opening ≠ not hitting auth endpoints (§4.2.2) |
| Seed-level rotation | After cleaning this seed, all remaining live surfaces §4.3 / recorded dud → only then switch to next seed and search; P2 must be liveness-screened first |
| Continuous hunting | Site complete → switch to next live site in this seed; this seed's remaining finished → search next seed; report written **don't wrap up**; if tools fail, switch lines yourself |
| Forbidden | Search only user's original term; **search all seeds at once before hunting**; open next seed's FOFA while this seed still has live surfaces; stuck on "Qichacha must be complete" without starting to hunt; ask whether to continue; treat one round of FOFA as task end; premium new root domain only record host without back-feeding and re-searching; **idle-brush new keywords in FOFA while unhunted live surfaces remain** (§2.1) |
| Deep-dive priority | See **§2.1**; expansion serves entering sites, counts aren't progress; **do not reduce** seed breadth or matrix depth |

SRC/Qichacha down → **does not block starting the hunt**; use whatever seeds you have, refill the queue when it's back.  
Progress may be briefly noted as "seed X remaining live surfaces finished / site Y report persisted", **must not stop ending with a question**.

---

## 2. Idling detection (correct on hit · self-triggered)

**User hard rule (2026-08-07): jump on idling.**  
Idling hit → **immediately** switch to this seed's next live URL (or record that entry as dud); forbidden to keep piling probes on 403 shells, credential-less health checks, already-covered login form shells, or already-reported same bugs. Having clicked the login form ≠ §4.2.2 checked off; once auth endpoints are checked, don't hit them again.  
**Still digging redirects / JS to find business surfaces = not idling.** Hitting issue-session / reset / rebind / token-exchange per §4.2.2 = not idling. Grinding CAPTCHA / default credentials / retrying same-skin login = idling.  
**Fat surface** (lots of JS / backend / business JSON) still extracting chunks, restoring signatures, writing those §4.0 lines, building object graph → counts as working, **not** idling. **Thin shell** (403, no business script, same gate) only jumps after 15–20 minutes with no leads.  
**This seed's remaining live surfaces not finished → forbidden** to use idling as a pretext to open new seed FOFA.

| Signal | Meaning |
|------|------|
| `reports/` not growing for a long time + only piling up 403/health/repeated paths | **Idling → switch to this seed's next live host** (not open a new seed search) |
| Child thread/this thread >15–20 min with no lead for a formal report, only noise | **Thin shell** kill this line, switch to this seed's next live URL; **fat surface** still extracting JS / building object graph doesn't count. Remaining not finished → forbidden to switch seeds and search new words |
| Stop after one seed/one round of FOFA + ask to continue | Illegal wrap-up (§1.4); FOFA finished should enter cleaning+hunting, not stop, nor immediately search the next seed |
| Search all seeds at once / open next seed's FOFA while this seed still has live surfaces | Violates single-seed closed loop (§1.0.1) |
| Old folder still exists but starting from zero, not skipping covered | Violates §1.3-A |
| Idle-waiting after all done / no random, no rescan | Violates §1.3-C |
| Repeatedly rescanning already-done seeds this round, umi unchanged but still full matrix / only brushing covered | **Rescan factory** (§1.3-C gate); next slot switch to random new business name |
| Queue not persisted or only user's original term | Will definitely miss brands/domains |
| Reply ends with "should we continue/switch brand" | Blacklist phrasing |
| Search only user's original term, don't even create buildable seeds | Missed surfaces (§1.1) |
| Muddle multiple seeds together, switch seed and run full matrix again on covered | Violates §3.1.1 |
| Hummingbird on every entry / mindless FOFA on every filing | Violates §3.2 / §1.2 |
| Digging minority-stake companies as group assets | Violates §3.2.0 |
| Still brushing FOFA at 820041/429 | Quota-exhausted idle banging (§2.1 gate D) |
| Still opening new seed FOFA while this seed has unhunted live surfaces | Expansion fake progress (§1.0.1 / §2.1 gate A) |
| Attacking new keyword mapping before site passes §4.3 | Violates deep-dive priority (§2.1 gate B) |
| Dropping current matrix to only FOFA when a premium keyword appears | Violates back-feed-only-no-course-change (§2.1 gate C) |
| All threads on FOFA/probing, nobody building the list | Double FOFA factory (§2.1 gate E) |
| Blind sweeping with frontend but no endpoint list; only testing two or three types | Fake progress / one-sided |
| Stuck waiting for JS to fully extract | Misuse of §4.1 |
| Same-skin login wall repeatedly CAPTCHA/default credentials; user marked important surface but first clearing section-one shells | Locked-scope order/same-skin misread (§0.1 / §3.3 / §4.1.1) |
| Seeing a login page and switching to the next company, business API not yet hunted | Violates §4.1.1 |
| List has issue-session / reset / rebind / token-exchange, but switching sites with zero payload | **Missed test** (§4.2.2) → add probes first, not idle-jump sites |
| Business endpoints extracted, all same login code, still opening full matrix on next host of same product | **Same-gate repeated grinding** (§4.1.2) → close out this host, sibling glance-diff, switch to genuinely unhunted business surface |
| Reports not growing for a long time, only expansion probing | Hard-metric idling |
| Full matrix on each same-skin mirror; re-confirming a bug already in `reports/` as a new bug | Repeated idle runs |

**Not progress:** FOFA counts, blacklists, liveness counts, fake middleware/pure file channel, re-confirming what's already persisted, CORS (not hunted); **checking off the four-piece set on pure login code / "please log in again" / NotLogin / "product under upgrade"**; spraying `'` at every path but no differential surface.  
**Counts as progress:** §4.0's few lines explaining this site, endpoint list (or legitimate downgrade), response clues entered into this site's queue, full-type matrix on business JSON, four-piece set on differential surfaces, §4.2.2 entry checked or no-entry N/A, with session §4.2.3 object graph/ID swap, formal report persisted, **unauthenticated exception broken through or falsified**.  
**In locked scope:** idling correction only switches paths within scope; forbidden to use idling as a pretext to go outside scope.

### 2.1 Deep-dive priority gate (correcting "only expanding surface, never entering sites" · user 2026-08-07)

> **Positioning (same spirit as `skill-as-boost`):** this section saves **rhythm/idling**, not a capability ceiling.  
> **Only corrects:** FOFA counts as progress, stockpiling keywords without hunting, both threads searching, dropping a half-done site to brush mapping as soon as a premium keyword appears.  
> **Never cut:** preparing as many seeds as possible, full-type matrix, injection/SSRF/XSS/RCE depth, JS-followed hosts, vulnerability chains, new attack surfaces, tool line-switching, user current-instruction escalations.  
> Watchword: **search one seed → clean → finish hunting remaining live surfaces → only then switch seed FOFA**; within a seed, list before matrix, matrix before switching sites; premium only back-feeds, no course change; rate-limited → only hunt the pool.  
> Relation to §2 "jump on idling": **jumping on dead-shell/403 noise (switch to next live URL within this seed)** = correct; **opening new seed FOFA while this seed still has unhunted live surfaces** = wrong (see §1.0.1 / gate B).

#### 2.1.0 Capability boundary (avoid misreading as cutting capability)

| What this section constrains (rhythm only) | **This absolutely does NOT mean** |
|----------------------|----------------------|
| When this seed still has unhunted live sites, don't search the next seed yet | Build fewer seeds, cap seeds at "at most N". Seed count has no upper limit, list as many as possible |
| Current site's matrix not done → forbidden to use "FOFA another batch / finish searching seeds first" as progress | Forbidden to follow JS new hosts, forbidden multiple paths, forbidden to break through high-value leads |
| Both threads not all FOFA factories | Forbidden for 2 threads to deep-dive two hosts simultaneously |
| Back-feed premium keywords by persisting first | Forbidden to re-search back-fed R, forbidden to add level-4/new business names |
| Rate-limited → stop idle banging | Backup accounts also can't be used; empty pool can't be refilled either |
| Same-gate stop: one login-code family closes out, sibling no separate full matrix (§4.1.2) | Seeing a login page → switch; business API needn't be extracted; unauthenticated exceptions (public list surfacing others' entities, list still returned without params) also not hit; new path / response code changed with data also not followed |
| This seed's fat-thin layering: thin shell glance, fat surface deep-dive (§4.3) | Fat surface killed too if no report in 15 min; thin shell treated as fat surface, open thread and spray four-piece set |

When rules conflict with the field, or would create a gap: **breakthrough and evidence take precedence**, this section's discipline yields to output; afterward you may note why the gate was broken.

#### 2.1.1 Gate A — this seed still has unhunted live surfaces → stop opening new seed FOFA

**Hit any condition → this round forbids FOFA-ing new seeds/new keywords, only hunt this seed's already-cleaned remainder:**

1. After cleaning, the current seed still has **live hosts not §4.3 / not recorded dud**  
2. Or the last 15 min mostly spent on expansion/probing, while **endpoint list not built and `reports/` not growing**

**FOFA/expansion still allowed:** pagination of this seed's results (still collecting this seed); this seed's remaining live surfaces all finished/recorded dud and switching seed; user explicitly names a switch; site all dead/human-bot hard block recorded dud; §1.3-C random/rescan after all done.

#### 2.1.2 Gate B — without "this round complete", forbidden to pad with new-keyword FOFA

When the current doing host **hasn't reached §4.3**, or this seed still has unhunted live surfaces:

- **Forbidden** to make "FOFA a bit more / search a wave of keywords / finish searching seeds first then come back" the main action  
- **Required** first: §4.0 explain this site → full JS (path + keys, or legitimate downgrade) → list (response clues added anytime) → matrix (§4.2.1 + §4.2.2 on differential surfaces; with session add §4.2.3, no entry N/A) → successes persisted per format or falsified; medium severity same object escalate chain first; then switch to this seed's next live URL (thin surface one glance is enough)  
- High-value leads (stable injection/RCE/cross-tenant/unauthorized sensitive read/usable credential (recognized key + non-production-affecting capability example, not just copied string)/arbitrary login into account/takeover password change) **break through before switching sites** (consistent with §4.3)

Opening a new seed without meeting the bar = **expansion fake progress**, hits §2 correction.

#### 2.1.3 Gate C — premium keywords / search domain R: back-feed only, no course-change spree

Align with §1.1.1, and nail down the rhythm:

1. Premium keyword or reduced search domain R → **immediately** write to `seed_queue.md` pending (note source host)  
2. **Keep the current host's matrix going**, keep hunting this seed's remaining live surfaces, don't interrupt a half-done deep-dive for a new keyword, don't go search R  
3. **Only when** this seed's remaining live surfaces are all finished / must switch line / gate A allows searching, prioritize `domain=R` or that keyword for FOFA again, and run the §1.0.1 closed loop again  
4. **Forbidden:** brute-FOFA every leaf host; only mention good keywords in chat without persisting; after persisting never search nor mark cold; go search R while this seed still has live surfaces

#### 2.1.4 Gate D — FOFA 429 / rate limit / 820041 → force hunting the pool

- Main account rate-limited → may switch to **backup key** (see fofa three accounts: main → backup → backup2) to fill the **current gap** (missing pages for this seed/this R), not swapping syntax to keep banging  
- All three accounts limited or already enough to hunt → **no more FOFA this whole round**, only hit what's stored + JS/crt-refilled hosts  
- **Forbidden** to idle-wait, idle-bang, or treat "switch account to brush counts" as progress when rate-limited

#### 2.1.5 Gate E — multithreading: deep-dive primary, double FOFA factory forbidden

When the user wants N threads (e.g. 2 threads), default:

| Thread role | Only does | Forbidden |
|----------|----------|------|
| Deep-dive thread (default all/vast majority) | Assigned host: §4.0→JS (path+keys)→list→matrix (four-piece set on differential surfaces + §4.2.2; with session §4.2.3)→report; high severity write DONE planned-entry/planned-supplement/no-entry per hunt-iter | Open new FOFA keywords as its main job; **directly start modifying the break-through short list**; full matrix on thin shell |
| Optional 1 surface-fill | Deep-dive next premium host in queue, or host surfaced by same-cluster JS | Frantically brushing FOFA at the same time as deep-dive threads |

FOFA is **short-triggered** by the main controller (pagination of this seed's results / switch seed only after this seed finished / back-fed R prioritized for scooping new): after results enter queue, threads **immediately return to deep-diving this seed's remainder**.  
**Forbidden** for all N threads to be on FOFA/probing while 0 build the list.  
**Forbidden** for surface-fill thread to search the next seed.  
Short list written only by main controller (or single window); child threads' planned entries see `hunt-iter`. Spawn deliverables must include iteration.

#### 2.1.6 Persistence and covered (so faked busyness has nowhere to hide)

Suggested for doing sites (better for self-check if present, **does not replace** real hunting):

```
{task}_dig/{host}/endpoints.md   # endpoint list
{task}_dig/{host}/matrix.md      # type matrix; four-piece set checked or N/A+reason
js/{host}/                       # full JS extraction (when frontend exists)
```

- **Writing `covered_hosts`** = has passed §4.3, not "curl'd the homepage / seen in FOFA"  
- Three progress hard-metrics (heartbeat within 15–20 min): ① JS+list advancing (fat surface includes object graph / signature restoration) ② four-piece set on differential surfaces has real payload or N/A; with session §4.2.3 has ID swap ③ report added or this site's matrix closed out  
- None of the three but only FOFA/probing counts → **force gate A**, return to unfinished sites

---

## 3. Dud removal · Ownership · Equity gate

**After FOFA/pool-refill scooping, must clean; forbidden to hunt everything as-is.**

### 3.1 Dedup / dud removal — do not remove business paths

| Remove | Don't remove |
|------|--------|
| Duplicate entries of the same host:port | Different paths/endpoints under the same host |
| Fake TLDs, business keys treated as domains | `/api/a` and `/api/b` |
| CDN/static/third-party library domains | Same host different ports if business differs |
| Internal IPs, unrelated sites | Different business hosts of the same brand |
| Blank/garbled/pure-static no-endpoint shells, long-dead pages | **401/403/login wall/admin console challenge pages often have surfaces; don't discard whole site because of 4xx** |

**Forbidden:** "dedup by same host" = only hunt the homepage, discard endpoint paths.

### 3.1.1 Global dedup across the whole task (hard)

Within the same `*_SRC-hunt`, multiple seeds inevitably collide — **forbidden** to treat as new assets and run full matrix again.

| Level | Handling |
|------|------|
| Same URL (normalized host+port+path) already in assets/queue/covered | Skip |
| Same host:port already §4.3 complete | Scooped again → skip deep-dive |
| Same host **new path/new endpoint** | **Do not skip** |
| Same host **new port** or another application | Treat as new surface |
| True same-skin mirror (§3.3), representative already done in family | Others skip full matrix |
| Bug already persisted in this task's `reports/` | Don't resubmit as new bug (identical; whether to write only follows format). Same type different URL, same URL different type still tested |

Suggested state to persist in dig: `assets/`, covered/done hosts, cold/black, this site's endpoint list.  
After switching seeds **dedup against existing asset table before hunting**; duplicate counts aren't progress.

### 3.2 Ownership (light by default · Hummingbird only for doubt)

Before deep scanning: dud removal → **§3.2.0** → light ownership → enter pool. **Hummingbird is not a default step.**

#### 3.2.0 Equity-scope gate (hard · prevent mistaken hunting of minority stakes)

> Lesson: a minority-stake company's own domain = not 100% owned, not 100% controlled; no matter how many bugs, it doesn't count as this group's SRC.

| Default can enter pool | Default not enter pool |
|------------|------------|
| Group itself, **100% controlled** child/grandchild/great-grandchild/great-great-grandchild (aim for level 4; beyond level 4 still 100% may keep following) | **Minority stake**, strategic/financial investment, joint venture not 100%, associate |
| Brands/domains explicitly listed on SRC scope page | FOFA-ing a whole domain merely because "received investment from XX" |
| Known wholly-owned brand root domains and business subdomains | Portfolio companies' own domains (minority-stake type) |

**User-named exception:** minority stake/affiliate **only when the user explicitly says this time** "hunt XX / also hunt this minority stake" enters the pool; not named → however fat the surface, it doesn't enter the current group task, skip to cold pool.

| Signal | Action |
|------|------|
| SRC/known wholly-owned brand/root domain | Can pass |
| Business-registration holding &lt;100%, minority stake, strategic investment | Cold pool (unless user names it) |
| Filing entity is another independent company, only investment relation | Cold pool |
| Ownership unclear and not SRC/known wholly-owned domain | Shallow probe; confirmed not 100% → stop deep-dive, don't write this group's report |
| Already found a bug on the wrong entity | Mark not-this-group / don't submit to that SRC; stop expanding that cluster within the task |

**Forbidden:** treating "received investment" as wholly-owned subsidiary; rolling the whole family from a minority-stake site's JS; when scope is wrong still "break through first" because surface is fat; FOFA-ing Qichacha's entire "related companies" table.

#### 3.2.1 Skip Hummingbird by default

Surfaces that look enough like the target's **wholly-owned/SRC scope** (known root-domain subdomains, cert/title strongly related to wholly-owned brand, FOFA within this seed's scope, hosts surfaced from confirmed in-scope sites) → **skip Hummingbird**, enter site/shallow probe.  
Minority stake/not 100% → cold pool, doesn't enter this section. Fake domains/CDN/third parties already cut by dud removal → directly discard, no Hummingbird either.

#### 3.2.2 Hummingbird only for doubt

Title/certificate/domain conflict; doesn't look like known root domain and no brand corroboration; looks like another company/outsourced/shared shell; mid-deep-dive looks like minority stake of another company → then Hummingbird once or cross-check certificate/WHOIS.  
**Forbidden** to Hummingbird every entry; if Hummingbird is down switch to certificate/title/shallow probe, don't get stuck; overseas/no ICP doesn't block Hummingbird; having a filing entity still must pass §3.2.0.

```
Doubtful host → certificate/title/known suffix (seconds) → still unclear → Hummingbird once
  → down/no ICP → WHOIS/org or shallow probe → business/fat components upgrade to deep scan; dead shell discard pool
```

**Good asset:** in-scope + public-live + login/business API/backend/component surface.  
**Bad asset:** fake domain, third party, empty shell, pure health check; unauthorized pure file up/down not counted as a bug.

### 3.3 Same-skin / IP ranges

Only when **fingerprints are substantially isomorphic** (title/skeleton/build hash/API prefix/login chain): **2–3 representatives** in the family get full matrix; the rest only probes (homepage + JS hash + one or two business endpoints), no differential → **skip full matrix**.  
**Same host ≠ same skin**; multiple paths on the same host are always expanded.  
**Same-gate proven (§4.1.2) overrides this article's "find 2–3 more representatives":** after the first one's list + unauthenticated exceptions are clicked and the rest of the endpoints are the same login code → sibling glance-diff is enough, no need to scrape up two more full matrices. If response code changed or new path extracted, escalate again.

**Login shell same-skin** → no need to re-hunt the login form. What the representative site did in §4.2.2, sibling glance-diff (any new reset / rebind / token-exchange path); no new endpoint → no separate §4.2.2. Still check `jump` / `service=` / `moduleId` to see if it's another business surface; if so, go hunt that surface.

**Not a differential (forbidden to open full matrix again):** only entry 200 vs 403; whether the same SPA can be opened; same gateway prefix + same login wall + identical JS hash; retrying weak password/CAPTCHA once more.  
**Counts as differential:** new path / new port / another application / new business API; same-skin login but redirects to another business surface.

Within this seed separate fat and thin (§4.3): same-skin/same-gate thin surfaces falsified at a glance is enough; don't open a thread for every leftover host to spray a round of the four-piece set.

---

## 4. Single-site main path

On-site watchword (details below, not rewritten here): explain this site → extract path+keys → effort per `src-value` §1.1 → don't spray at "please log in", empty list must be tested, stop if no differential → no account: after unauthorized works then swap id (any field name), with account: carry session and swap id (any field name) → follow medium severity first → fat deep, thin glance.

### 4.0 Explain this site first on entering (hard · prevent blind scanning)

Before the list, write clearly in 3–5 lines (not an essay):

- Who uses it (consumer / merchant / operations)
- Core objects (orders, tickets, coupons, documents…)
- Which fields hold money, authority, state
- Which layer is reachable without login

If you can't explain it, capture packets first to fill in; not allowed to start scanning empty. Later parameter changes revolve around these things.

Seeing mini-program / APP / client / GraphQL / WebSocket / bulk export / Agent tools / template preview / file conversion / command RPC → follow as **this site's surface**, not an incidental "other field surface". The `appId` / mini-program gateway / client salt in packets behind the H5 wall are used as this site's keys.

### 4.1 Build the endpoint list first

**With frontend:** open business page → extract JS in full → `js/` → analyze API/params/auth → capture packets to complete → list → §4.2.

JS **extracts more than paths**. If present write into the list, if absent write "none":

| What you extract | What to do |
|----------|--------|
| `/api/` paths | Enter the list as usual |
| Signature salt, hardcoded key | Compute yourself, hit endpoints needing "only sign, no Cookie" |
| Ciphertext id + frontend public key | Encrypt a neighboring number yourself then swap (see `idor-test.md`) |
| Async chunks, sourcemap, hidden/admin in routes | Even if not shown on page, directly hit the corresponding API |
| Hardcoded demo accounts, test tenants, trial entries | **Use as keys**. This is not the same as spraying `admin/admin` at the login box |
| Runs commands / renders templates / expressions / file conversion / RPC with commands / Agent tools | If present write into list and open the corresponding module (chat tools see `agent-tool-exec-test.md`); **if absent write "none"**. Examples aren't a whitelist; execution surfaces outside the list are hunted too |

"Weak password not mandatory" only concerns login-box dictionaries. Credentials/demo tenants in JS/pages are not prohibited.

**Downgrade (don't get stuck):**

| Scenario | Approach |
|------|------|
| Pure API / almost no business JS | Swagger/OpenAPI, packet capture, response links, common gateway paths |
| Opens to a login page | **Per §4.1.1**: first find business surface, focus on unauthenticated hunting. For the login form, if visible surfaces are broken through or falsified, stop. Issue-session / reset / rebind / token-exchange in the list follow **§4.2.2**, don't grind on the form |
| JS download fails / CDN blocks | Packet capture + HTML inline + known paths, **forbidden to idle-wait for full extraction** |
| No comparison account | No account: after unauthorized works then swap id (§4.2.3). With account follow §4.2.3 by session. Don't grind registration for a second account. Forbidden to stop at login form to "log in first" |

Having a frontend but empty list then blindly dir-bruting = forbidden; no JS then stopping the whole site = forbidden.

### 4.1.1 Opens to a login page (hard · free jump defaults to unauthenticated)

**Forbidden to read as "ignore everything login-related".** What you ignore is the form's CAPTCHA, default credentials, infinite retries. Empty password, step skipping, response modification, JS keys, `tenant`/`moduleId` on the login endpoint, lists/details exposed nearby — if visible, hit them.

Opens to a login page → first find business API / business host after redirect → focus **main effort** on unauthenticated and four-piece set on differential surfaces there. Once in a session (user-provided account / JS demo account / empty-password breakthrough) → immediately move to §4.2.3, don't keep spraying quotes at business endpoints.  
Login form: if visible surfaces broken through or falsified, stop; don't spend on cumbersome verification / others' identity pages / same-skin shells. What you don't spend on is others' login skin; own token-exchange / callback / binding only hit if in the list (§4.2.2), otherwise N/A.  
**Seeing a login page is not a reason to switch assets.** Only if no business surface found does it count as an empty shell. Same when locked scope has no credentials given. If the user provides an account on the spot, supplement with post-login testing.

The business surface may be another host, or the **gateway/API behind the login on this host**. Hunt unauthenticated against the business API, not against the login form. Not finding another domain ≠ this site is gone.  
The login may be first-party or someone else's (SSO / CAS / OAuth / unified authentication, and any third-party identity page). Others' login pages themselves are not audited — the criterion is "the login page owner isn't this site's business", not by product name list. Follow back to this site's business surface.

**How to find the business surface (without logging in):**  
`service=` / `redirect_uri=` / `callback=` / `returnUrl=` / `jumpUrl=` / `next=`; JS / `env.js` / `baseURL` / `apiHost` / `/prod-api`; 302 Location; `X-Frame-Options: ALLOW-FROM`; same-brand `api` / `admin` / `gateway` / product hosts.

The login form **can be tested, but not ground infinitely**:

| If visible, hit it; if broken through or falsified, stop | Don't hit / not progress |
|---------------------------|----------------|
| Empty password, skip password step, modify response to get in | CAPTCHA OCR, slider, default-credential dictionary, infinite password tries |
| JS hardcoded keys | Pouring injection into username/password fields to fill the four-piece set |
| Extra business fields on login endpoint (`tenant` / `corpId` / `moduleId`) hit as injection | Re-hunting the same-skin login form |
| Business paths already exposed next to login (list / detail / stats) hit unauthorized | Opening `401-403-bypass` to grind login HTML; auditing others' IdP itself |
| Middleware exposed default ports (nacos, etc.) one glance | — |

**The four-piece set goes on the business parameters of the business API.** Username/password fields are not business parameters (not injection four-piece entry). Empty password / step skipping / login injection on the same field pair that yields a session count as **arbitrary login**, see §4.2.2. Business endpoints all require tokens, no params before login → four-piece set N/A (write the reason clearly), don't invent params.  
Form shell broken through or falsified then stop ≠ auth endpoints needn't be hit. Issue-session / reset / rebind / own token-exchange / 2FA per §4.2.2.  
**Only** when not a single business surface can be extracted from redirects/JS/config, no unauthenticated business endpoint nearby, and the list has no §4.2.2-type endpoints → then record empty shell and switch to the next entry. Having a business surface but stopping at the login form or switching directly = violation.

### 4.1.2 Business endpoints all the same login code (same-gate stop · 2026-08-18)

> **Only corrects rhythm, doesn't cut capability.** Lesson: reading "deep-dive each domain independently / extract JS fully" as opening a thread and full matrix for every FOFA leftover 403 and every login shell; list done, four-piece set checked off on the same login code, reports not growing, then open the next host of the same product.

**Do first (capability not cut):** extract JS, build list, label METHOD; click through unauthenticated exceptions (public enumeration, static JSON, business JSON still returned without params, list/detail/stats). Compare responses per below, don't treat "no data yet" as "please log in".

| What the response looks like | Counts as | What to do |
|--------------|--------|--------|
| Entirely just one line "please log in / NotLogin", no list, total, names, details | Login gate | Whole four-piece-set section N/A, don't throw `'` |
| Has list / total / business fields, even if `total=0`, array empty | Differential surface | Still must test (swap params, swap id, injection) |
| Error, 500, timeout, or length/duration obviously different from normal requests | Differential surface | Still must test |
| Missing a param yet spits out list/details | Unauthenticated exception | Hit per §4.2.1 |

**An empty list is "structure returned, count is 0", not "please log in".** Only when the whole page is the same login code and no list can be scraped nearby, then skip the whole section.  
**Stop:** after hitting with swapped params, total still 0 and no stable error/time difference → falsify and switch to the next, not allowed to grind until data appears. Occasional 500/timeout compare once or twice, if difference isn't stable stop, don't retry until it works.

**Same gate = all of these hold simultaneously:**

1. Business paths already extracted from JS/gateway  
2. Unauthenticated exceptions already clicked through  
3. Remaining business endpoints are **same-family response codes** (login failed / please log in again / NotLogin / product under upgrade / system busy with no count or time difference)  
4. **No** unauthenticated surfacing of others' entity data, and no list/details returned after missing params

**Then stop this gate, no more full matrix:** the four-piece set against the same login code can stop. If the list still has issue-session / reset / rebind / token-exchange and **§4.2.2 not checked**, close out this group before marking done — don't pour injection at "please log in". If the next host of the same product still has the same `baseURL` + same response code → **one-glance diff** (extract JS to see if new paths / response code changed), no new exception → no separate full matrix. FOFA **403 + homepage no business script + Apache/TAPISIX forbidden directory** → one endpoint falsified, mark cold, no thread.

**Forbidden misreading:** seeing a login page and switching (still violates §4.1.1); business API needn't be extracted; unauthenticated exceptions not hit either; response code changed with data / new path / new business host not followed; **auth endpoints (login/reset/rebind/token-exchange) not hit either**; treating empty list / error / timeout as "please log in" and skipping the whole section. Checking off the four-piece set again at the gate, opening sibling threads again, grinding an empty list until data appears = idling, not deep-dive.

### 4.1.3 Treat responses as clues (hard)

Newly appearing **id / download URLs / tokens / internal hosts / role fields** in responses → immediately enter this site's list and hit again, don't treat as garbage or discard when switching sites.  
After the list passes, still take a shot at attachments and export (parent object passed auth, child object often didn't).

### 4.2 Full-type matrix (no one-sidedness)

Where to spend effort first follows `src-value-hunting.md` §1.1 (unauthenticated others' entity / auth takeover / ID swap / four-piece set including XSS all same tier, hit first). This section only constrains type probes, doesn't write a separate priority.

Take the union with `src-value-hunting.md`, at minimum: unauthorized, privilege escalation/IDOR (**with session as hard as the four-piece set, see §4.2.3**), injection, SSRF, RCE chain, credentials (with credentials keep hunting; usable = recognized key + non-production-affecting capability example, whether to record follows format), weak password (login form not mandatory, see §4.1.1; JS demo account as key), sensitive paths, XSS/CSRF, upload (don't stop at can-upload-can-download), traversal, privilege escalation/logic (with session see §4.2.3), **auth/session (arbitrary login / account takeover see §4.2.2)**, JWT/OAuth and other field surfaces (**CORS not hunted**). Whether to record only follows `vuln-report-format.md`.

#### 4.2.1 The hard four-piece set must not have day-after-day empty windows (user 2026-08-07 · no empty talk)

> User specifically named: don't just pile up unauthorized reads/isomorphic lists; **injection, SSRF, XSS, RCE** must be genuinely tested.  
> **Forbidden** to write hand-wavy phrases like "do the minimum action" in rules; the following are **probes each of the four types must fully run when entering a site's matrix** (if there's an entry, hit it; only no entry → N/A + reason).

| Type | Probes that must be run (when there's an entry) | N/A only if no entry |
|------|--------------------------|----------------|
| **Injection** | Endpoints where you can see count changes, content changes, or that go fetch a URL: test **every** query/filter/sort/keyword parameter above (baseline → probe → differential). Only returns "please log in", no business fields → whole section N/A, don't throw `'` one by one. **Choose probes by stack**, don't just hit SQL single quote at every site: JSON/Mongo use operators (`$ne`/`$gt`); search box use ES DSL or list OR+total; Java use HQL/SpEL; with template use SSTI. SQL surfaces still use `'` / boolean / time-delay (per DB) → WAF encoding. If blocked, switch location (query / json / header / path). Data or stable time difference → break through and write report. Username/password fields aren't business params; `tenant` / `corpId` / `moduleId` on login endpoint hit if present (§4.1.1) | Pure static page, no query/body business params at all; only login box with no other business fields; response only login code, no business fields (§4.1.2) |
| **SSRF** | All URL/callback/webhook/file/fetch/import/preview/proxy-type params: internal network, cloud metadata, out-of-band DNS/HTTP; see whether it follows the request, reflects, hits your listener | **Zero** URL-fetch/proxy-type fields in list and packet capture |
| **XSS** | Reflected: hit tags/events at param reflection points; stored: writable nickname/remark/message/filename then read back; combined with whether readable without login | No reflection, no user-controllable write point at all (record reason) |
| **RCE chain** | With command/expression/template/deserialization/debug-execution/dangerous-upload entry, follow to see if executable or falsify; a half chain keep following | **List + packet capture + response** all lack such Sinks. Not finding the word on homepage doesn't count; if tool/template/exec surfaces in later responses, immediately add the hit |

| Hard forbidden | Explanation |
|------|------|
| **Day-after-day empty window** | Multiple consecutive rounds / across calendar days, process and reports only have unauthorized reads/lists/configs, four-piece set **never sent payload at real params with differential surfaces** → illegal one-sidedness; next round supplement the four-piece set first |
| **Fake progress** | findings write "tested/N/A" but the parameter table is empty; only scan unauthorized 200 then switch site; **sprayed `'` at every path but no differential surface** |
| **One-sided rhythm** | After writing the unauthorized list switch Host/seed, injection/SSRF/XSS/RCE of the same batch of endpoints not touched at all |

**Checked off = params with differentials broken through or falsified**, not spraying `'` at every path. Prioritize: params with `total`/count, that spit input back, that go fetch a URL, that have template/expression. Only returns "please log in" and no business fields → N/A, write reason "response code is only a login gate". Empty list / error / timeout compare per §4.1.2, not "please log in"; if no differential, stop.

Detailed parameter matrix consistent with src-value §3–§4; **the standard is the parameter table with differential surfaces checked off, not "did it a bit".**

Deliverable: successes persist per `vuln-report-format`.

#### 4.2.2 Arbitrary login / account takeover (check off if entry exists · prevent idling)

> **Not a fifth piece.** The four-piece set is still injection / SSRF / XSS / RCE. This article hangs under "auth/session": if entry exists hit it fully, no entry → N/A + reason. The table is a **floor**; new endpoints in the list are still followed; forbidden to read as "with an account only these shots allowed".  
> **Doesn't overlap §4.1.1:** 4.1.1 handles the form shell (CAPTCHA UI, default-credential dictionary, same-skin login HTML, others' identity pages). This article handles issue-session, reset, rebind, own token-exchange/callback, 2FA — these **endpoints**. Form shell stopped ≠ these endpoints needn't be hit.  
> After getting past code-sending and slider: whether response has a code, whether code is bound to an account, reset to another person, empty-password into an account — still hit. Details see `authbypass-test.md`, `logic-test.md` account section.

**No account** (free-jump default, locked scope with no account given) — one shot each, if you get in or it's clearly impossible, move to the next item:

- **Arbitrary login:** empty password / delete `password` from request; skip password step, directly hit the endpoint that actually issues Cookie/token; modify response `success` and see if a real session appears; login injection only to see if a session can be produced (not counted as four-piece set); JWT `none` / hardcoded key / client-side forged token; own token-exchange, callback, binding with modified `uid` / `openid` (others' identity pages themselves not audited, see §4.1.1)  
- **Takeover:** whether reset / verification-code responses contain a token or code; if so use it to log in or go through the last reset step; at the last step swap `uid` / `email` / `phone` to someone else's or a neighboring number; when two identities can be constructed, put A's code into B

**With account** (user provided account, got in, already has session) — still hit auth endpoints per this article "own session + switch to others' identity", don't treat clicking through the profile center as progress. **Privilege escalation/logic on business objects goes to §4.2.3**, don't stop at these few shots of rebind/password change.

**User session must not be kicked out:** forbidden to call `/logout`, `/signout`, `/revoke` and any logout/sign-out/revocation. Don't test "whether session still valid after logout" (that shot requires logging out). Rebind/password change only see whether it passes without old verification; if passes, immediately change back to original value. If can't change back (don't know original password/email), just see whether the response accepts and stop; don't leave the user's account changed to a new password or attacker's email. Don't really change the email on the user's account to test an old reset token.

- Rebind phone/email: remove old password, old-number verification (if passes, change back)  
- Password change: without `oldPassword` (if passes, change back; if can't change back, stop at the response)  
- Reset to the last step, swap identity to someone else's (touch someone else's uid, not changing the user's own password)  
- Keep own Cookie unchanged, swap `uid` in rebind / password change / profile package to someone else's  
- Password passes, 2FA not completed — can the session hit rebind, password change, business writes  
- Arbitrary login remaining: low-privilege token modify `role` / switch to high-privilege token; entering a page you could already enter doesn't count

Single account: swap `uid` to a neighboring number or one copied from a list; only counts if it matches someone else; if not, record missing comparison account. **Forbidden** to go back and grind registration/CAPTCHA to get a comparison account.

**Stop (tested, not idling):** no such endpoints (N/A + reason); or every shot in the table above has been negated.  
**Idling (stop right away):** CAPTCHA OCR, default-credential dictionary, spraying same-skin form again, pouring four-piece set at "please log in", grinding registration for a second account.

#### 4.2.3 ID swap / object graph (no session ≠ no ID swap)

ID swap = swap every param that can select who, which record, which tenant, which file, **any field name**. One param or a bunch of complex params both count.  
**No account: swap id only after unauthorized works.** If business data already comes out without login, then swap to see if others' comes out. If unauthorized didn't work, don't swap.  
**With account** (Cookie / token / demo account / JS key) follow this section's table: swap while carrying the session. Main effort is privilege escalation/logic, not continuing to spray quotes at business endpoints. The four-piece set goes on these **business params**.

| Hit fully if present | N/A only if no entry |
|----------|----------------|
| **Object graph**: list → detail → attachment/export/approval, swap id at every layer (any field name) | Pure login wall, no object extractable |
| **Params that select people/counts**: neighboring number / copied from response / `0`/`-1`/empty / those that select people in complex packages | Not a single swappable one in responses and lists (with single account also copy first, **not allowed** to give up directly) |
| **Write endpoints** add `role` / `isAdmin` / `amount` / `status` / `vip` (if over-privileged assignment works then break through; only change what can be changed back) | No write endpoints |
| **Multi-step flow skipping**; claim / inventory / coupon / approval → concurrency shot | No such endpoints |

Forbidden to grind registration to get a second account. Missing comparison: use neighboring numbers and ids from responses. Details see `idor-test.md`, `logic-test.md`.

### 4.3 This site's "this round complete" = minimum to switch sites

Can't wait for universe-level checking off before switching sites. Satisfying these is enough to switch:

1. §4.0's few lines written (or confirmed no business object extractable before recording empty shell)  
2. Endpoint list built (default or downgrade; JS extracted the key table, if none write "none")  
3. Type matrix per §4.2 / §4.2.1 / **§4.2.2** / **with session then §4.2.3** **probes checked off** (no entry → N/A + reason, no empty talk; four-piece set checked by differential surfaces, not sprayed at every path)  
4. High-value endpoint parameter matrix covered (injection see parameter table with differential surfaces)  
5. Successes persisted per `vuln-report-format` (no bugs → no empty report)  
6. Not spent on same-skin mirrors / already-covered IP ranges  
7. **Opens to a login page** (§4.1.1): business surface found and hunted unauthenticated (or confirmed not extractable before recording empty shell). For the login form, visible surfaces broken through or falsified is enough, don't grind  
8. **Same gate** (§4.1.2): unauthenticated exceptions clicked, remaining endpoints same login code → four-piece set closed out. If the list still has §4.2.2 endpoints, check them off before marking done. Same-product sibling one-glance diff with no new exception → record, doesn't count as "seed still has unhunted live surfaces"  
9. **Auth endpoints** (§4.2.2, don't write into §4.1.1): list has issue-session / reset / rebind / token-exchange / 2FA → probes checked off or N/A + reason. Endpoint with zero payload = missed test, doesn't count as this round complete  
10. **Medium severity persisted**, same object hasn't reached "can write / can see others / can takeover / can execute" → **escalate chain first, don't switch sites**. If file channel works, switch to business  
11. **This seed's fat-thin:** fat surface (lots of JS / backend / business JSON) hit to object graph + differential params (with session also §4.2.3); thin surface (403 empty shell, same gate, same-skin no new path) falsified at a glance and recorded, doesn't fill 15 minutes, no full-matrix thread

When there's a high-severity report, before switching sites write one line planned-entry/planned-supplement/no-entry per `hunt-iter` (half a minute; even if it can't be written, counts as done). **Merging the short list is not a condition for switching sites**, the main controller merges later. No high severity = no planned entry.  
**Break through high-value leads before switching sites:** stable injection/RCE chain/cross-tenant/unauthorized sensitive read/usable credential (recognized key + non-production-affecting capability example, not just copied string)/arbitrary login into account/takeover password-change-rebind — verify and write report or falsify first.  
**Medium severity is not a switch-site order:** if the same object's chain escalation isn't finished, follow it first.  
**Must switch line:** site unreachable, human-bot hard block with no alternate Host, pure dud shell — record and switch sites, don't ask and stop. Seeing a login page is **not** a reason to switch line.

### 4.4 Site-level rhythm

1. Determine locked scope or free jump  
2. **Free jump:** §1.0 + **§1.0.1 single-seed closed loop** (resume/new → prepare many seeds → liveness screen → search only this one S → dedup, remove duds, remove dead → ownership gate → finish hunting all remaining live surfaces → only then search the next → all done then random/rescan)  
3. **Locked scope:** multiple hosts in asset cluster / business-flow subdomains / multiple paths on same host; no proactive FOFA outside scope  
4. §4.0 explain this site → extract JS (path + keys) → list (response clues added anytime) → effort per `src-value` §1.1: no account, after unauthorized works then swap id, then auth endpoints/four-piece set; with account, carry session to swap id/add fields then hit four-piece set (including XSS) → this round complete  
5. Successes persist per `vuln-report-format`; medium severity same object escalate chain first  
6. Reports not growing for a long time → self-check §2; thin shell switch sites, fat surface supplement unchecked types

---

## 5. Heartbeat self-check (go through once each round)

- [ ] Locked scope or free jump? In locked scope, did you lock too tight or fail to follow multiple hosts / wrongly FOFA outside scope?  
- [ ] Only open `*src-lessons.md` alongside the short list if it exists on disk; absence is not a deficiency, not less matrix hunting  
- [ ] Seeds prepared to the fullest (business names + wholly-owned levels 1–4 + root domains/filings), no upper limit? Any mistaken cut to a fixed count?  
- [ ] Did FOFA/on-site premium surfaces back-feed **new registered root domains** into the seed queue (only search after this seed finished, §1.1.1)?  
- [ ] **Single-seed closed loop (§1.0.1):** search one → dedup, remove duds, remove dead → finish hunting the rest → only then search the next? Any searching all seeds at once?  
- [ ] Queue persisted? pending/doing/done updated? On resume, did you skip done/covered first?  
- [ ] P2 liveness-screened first? Dead filings marked cold?  
- [ ] Hummingbird on every entry? Any minority-stake company dug as a group?  
- [ ] All done before — did you **first** go random new business name, and rescan only with prior evidence of additions? **This round** two consecutive `0 new` already switched to random? Any rescan factory brushing covered?  
- [ ] Untested paths on same host mistakenly cut? List/matrix advancing?  
- [ ] Just marked this seed done — did you open the next entry? Any continue-type question in the final reply?  
- [ ] FOFA quota exhausted — stopped brushing and switched to hunting what's stored? Is progress being padded with counts?  
- [ ] **§2.1:** still opening new seed FOFA while this seed has unhunted live surfaces? Using mapping as padding before §4.3? Premium keywords only back-fed without course change? Multithreading a double FOFA factory?  
- [ ] Last 15–20 min: list / four-piece-set payload on differential surfaces / ID swap with session / report — is at least one advancing? (Fat surface JS/object graph counts as advancing; none of three + only expansion → force back to deep-dive)  
- [ ] **This site's injection parameter table / SSRF·URL params / XSS reflection-write / RCE Sinks hit on differential surfaces per §4.2.1?** Any day-after-day piling of unauthorized reads only? Any spraying `'` at every path to fill the checkoff?  
- [ ] When it opens to a login page: did you find and hunt the business surface (this host's gateway or the host after redirect)? Any infinite grinding on the login form? (§4.1.1)  
- [ ] When the list has issue-session / reset / rebind / token-exchange / 2FA, is §4.2.2 checked off or N/A? Endpoint with zero payload is a missed test; grinding form / default credentials is idling  
- [ ] With session, did you hit §4.2.3 object graph / ID swap / add fields? Any grinding registration for a second account?  
- [ ] Did ids/urls/tokens from responses enter this site's list? After the list passed, did you hit attachments/export?  
- [ ] Did JS only extract paths, with salt/ciphertext id/hidden routes/demo accounts not glanced at?  
- [ ] Medium severity landed — did you escalate the chain on the same object first? Did this seed treat a thin shell as a fat surface and spray full matrix?  
- [ ] Business endpoints already same gate (same login code, unauthenticated exceptions clicked) but still opening full matrix on same-product sibling? (§4.1.2) If auth endpoints not yet hit, did you close out §4.2.2 first?  
- [ ] Has this section's discipline been misread as hunt less/search less/fewer types? (If so, correct per §2.1.0, capability has no ceiling)

---

## 6. In one sentence

Determine locked scope/free jump first.  
**Free jump:** prepare seeds to the fullest (business names + wholly-owned levels 1–4 + root domains/filings, **no upper limit**, dozens to hundreds normal for big SRCs) → persist queue → resume old folder skipping already-hunted/already-searched → **single-seed closed loop (§1.0.1): search one seed → dedup, remove duds, remove dead → finish hunting the rest → only then search the next** (P2 liveness-screen first; **searching all seeds at once forbidden**) → 100% ownership (Hummingbird only for doubt) → **full on-site matrix (deep-dive priority §2.1)** → **premium surfaces only back-feed, no course change (§1.1.1)** → one seed's remainder finished, immediately next entry (no asking to continue) → all done then random re-search or rescan for additions.  
**Locked scope:** follow multiple hosts / business flow in the asset cluster to the end, no FOFA outside scope.  
Successes persist per `vuln-report-format`; self-correct idling.  
**Opens to a login page:** first find the business surface, focus on unauthenticated hunting; for the login form, visible surfaces broken through or falsified then stop. Seeing a login page is not a reason to switch assets (§4.1.1). Business endpoints all the same login code and unauthenticated exceptions already clicked → same-gate stop, sibling one-glance diff, no separate full matrix (§4.1.2).  
**Auth endpoints** (issue-session / reset / rebind / token-exchange / 2FA) with entry check off per §4.2.2, no entry N/A; don't grind the form shell. Only after breaking into an account or changing others' password/binding then persist per format.  
**On-site tactics:** first §4.0 explain this site; JS extracts keys not just paths; response clues enter this site's queue. Effort per `src-value` §1.1: no account, after unauthorized works then swap id; with account, carry session to swap id then hit four-piece set (including XSS, no downgrade). Medium severity same object escalate chain first. Fat surface deep-dive, thin shell one glance.  
**Injection/SSRF/XSS/RCE per §4.2.1 hit on differential surfaces, no day-after-day empty windows**; all four types pushed equally; choose probes by stack; forbidden to only pile unauthorized reads; forbidden to spray `'` at every path to fill the checkoff.  
**Rhythm watchword:** search one seed→clean→finish hunting remaining live surfaces→only then switch seed FOFA; within a seed list before matrix, matrix before switching sites; rate-limited only hunt the pool. This section's discipline only prevents expansion idling, **does not cut** seed breadth, type depth, and breakthrough capability.
