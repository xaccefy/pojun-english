---
name: vuln-hunting
description: Use for proactive vulnerability hunting in an authorized pentest — find new vulnerabilities from the target's actual behaviour without relying on known CVEs (authorization bypass, logic flaws, races, wrong resource assumptions, chained exploitation). Use when the planner wants to dispatch a "dig deep for unknown vulnerabilities in this feature/endpoint" intent, or when a worker finds suspicious behaviour but cannot find a known CVE.
tags:
  cwe: [CWE-269, CWE-284, CWE-862, CWE-639, CWE-362, CWE-841, CWE-200, CWE-20, CWE-330, CWE-670]
  attack: [T1190]
  class: [authz, idor, race, enumeration, state-machine, logic, input-validation, combination]
---

# Vuln Hunting (Proactive Vulnerability Hunting Methodology)

Under the premise of **authorization**, find **vulnerabilities with no public CVE** from the target's **actual behaviour**.

This skill is not a "vulnerability checklist" — it is **a mental model of changing dimensions**: ask the same feature from a different angle, and the answer may differ.

---

## Boundaries and Prohibitions (Required Reading for Agents · Violating Means Crossing the Line)

| Allowed | Prohibited |
|---|---|
| Perform **low-impact verification** within the scope of authorization (read your own data, modify your own test data) | Destructive operations (delete data, format, modify others' data) |
| Use **two identities** for comparison (your own low-privilege account vs. your own high-privilege account) | Escalate privileges to accounts you do not own, change others' passwords |
| Use **small scale** for concurrency/race verification (2–5 concurrent) | Large-scale stress testing, denial of service, flooding |
| Read data you are authorized to access to prove unauthorized access | Bulk database dumping, large-scale reading of unrelated data |

**Criterion**: your verification should be "**prove existence**", not "**cause damage**".

---

## Core Principle: Change the Dimension, Not the Payload

The same endpoint and the same feature will yield different problems when **viewed from a different dimension**. When hunting, don't just think "swap the payload and hit it again" — that is going in circles within the same dimension.

**Seven dimensions** (each with specific techniques below):

### Dimension 1: Object Substitution — What happens if you call as a different identity/role?

**Core question**: this operation succeeds when "you are you"; what happens if **you are someone else**?

Specific techniques:
- **Horizontal privilege escalation**: replace the object ID in the request with **another object under your own account** (`user_id=1002` → `1003`). Success = unauthorized access.
- **Vertical privilege escalation**: change the role/permission field in the request to **higher privileges** (`role=user` → `role=admin`). Success = privilege escalation.
- **Unauthorized call**: **completely remove** the authentication header/cookie and call the endpoint directly. Success = missing authentication.
- **Object type confusion**: change the type of the ID in the URL (`/order/123` → `/order/abc`, negative numbers, very large numbers, `0`).

**Verification point**: both accounts must be **your own** (low privilege + high privilege); prove it with the difference.

**How to compute the difference**: use the `diff_responses` tool — it compares the **structural differences** between two responses (status code, JSON key set, value differences) and automatically filters out noise such as timestamps/trace ids/random strings. **Extra keys are often the data obtained through unauthorized access**.
Usage: save each of the two responses to a file with `curl -i` (in the current intent's working directory), then pass `file_a`/`file_b` to `diff_responses`.
**The difference itself is not a vulnerability** — the tool tells you "what is different"; whether it is a vulnerability requires semantic judgment (for example, a different `role` field is privilege escalation, while a different `email` is just different data).

### Dimension 2: Flow Decomposition — What happens if you skip a step?

**Core question**: a normal business flow has three steps A→B→C; what happens if you **only do C**?

Specific techniques:
- **Skip validation**: registration requires email verification; call the "set password" step directly
- **Skip payment**: placing an order requires payment; call the "ship" endpoint directly
- **Skip review**: content must be reviewed; call the "publish" endpoint directly
- **Call a later endpoint directly**: pick a "final step" from the captured front-end traffic and call it directly
- **Replay**: resend a successful request verbatim (see whether it is idempotent — may cause duplicate charges/duplicate shipments)

**Verification point**: find the step where "the front end calls it but the back end does not validate the prerequisite state".

### Dimension 3: State Machine — Does the same endpoint behave differently in different states?

**Core question**: orders/tickets/approvals have lifecycles; what happens if you call them **in a state where it should not be allowed**?

Specific techniques:
- **Illegal state transition**: confirm receipt before payment, publish before review, cancel an already-cancelled order
- **State rollback**: go through a completed flow again (roll back an approval, revoke a refund)
- **Race condition**: **concurrently** submit the same operation (2–5 concurrent), and see whether duplicate processing occurs
  - Typical: concurrent order placement causing overselling, concurrent coupon redemption, concurrent transfers
  - Technique: send N copies of the same request **simultaneously** (using `for i in $(seq 5); do curl ... & done; wait`)
  - Key point: **first check whether there is a uniqueness constraint** — races with a unique index are mostly unexploitable; don't waste time

**How to compute the difference**: take one response from the same endpoint in a "legal state" and one in an "illegal state", and compare with the `diff_responses` tool — **a different status code or response body structure** means the server took a different branch for the illegal state (possibly no validation, possibly only blocked on the front end).

### Dimension 4: Data Boundaries — Where does data come from, pass through whom, and go to?

**Core question**: **which inputs are attacker-controllable** yet treated as trusted data by the system?

Specific techniques:
- **Trust boundary**: does the back end trust fields in the front-end JS (`isAdmin`, `price`, `userId`)?
- **Hidden parameters**: change a parameter that does not appear in the UI (`role`, `is_vip`, `status`) and see whether the back end accepts it
- **Injection points**: everywhere input flows into SQL/command/template/LDAP/expressions
  - Finding points: `grep` the source code (if available), or look at errors and parameter reflection
- **Second-order injection**: store it first (comment/nickname/remark), then have it parsed elsewhere

**Verification point**: **proving controllability** is more important than "finding a suspicious parameter" — you must see it affect the result.

### Dimension 5: Resource Assumptions — What does the service assume?

**Core question**: what happens if this assumption does not hold?

| Assumption | How to break it | Consequence |
|---|---|---|
| **Uniqueness** | two submissions at the same time | overselling, duplicate issuance, duplicate redemption |
| **Ordering** | skip intermediate steps and go straight to the last step | bypass review, bypass payment |
| **Concurrency** | operate on the same resource simultaneously | race overwrite (TOCTOU) |
| **Limits** | exceed the limit/bypass the counter | bypass rate limits, free-riding |
| **Size/length** | overly long/oversized input | truncation bypass, DoS, resource exhaustion |
| **Existence** | reference a non-existent object | null pointer, default allow |

**Verification point**: find places where "the system assumed something but did not validate it".

### Dimension 6: Error Paths — How does the system handle errors?

**Core question**: the normal path has been tested; what happens **when something goes wrong**?

Specific techniques:
- **Error leakage**: change a parameter to an illegal value and see whether the error contains paths/table names/keys/internal addresses/SQL fragments
- **Exception swallowing**: if a step fails, does the flow continue? (do the following steps use default values?)
- **Insecure defaults**: on failure, default to allow, default to admin, default to skipping validation
- **Error code differences**: the same endpoint returns different results for "not found" and "no permission" → **enumerable**
  - Technique: scan IDs incrementally from 1, comparing status code/response length/response body differences
  - **Use `diff_responses` to compare the "exists" and "does not exist" responses**: a different status code or different JSON key set → enumerable existence
  - **Prerequisite**: the two responses must have the **same identity and same parameter shape** (change only one ID value), otherwise the difference is noise, not signal

### Dimension 7: Combination — What if two individually harmless operations are combined?

**Core question**: each one is normal on its own, but **combined** they are not.

Specific techniques:
- **Privilege escalation chain**: low privilege can edit a profile → the profile contains a field that can escalate privileges → editing it escalates privileges
- **Stored XSS**: write it in (comment/upload) → triggered when someone else views it → steal a high-privilege cookie
- **Cache poisoning**: change content but the cache is not cleared → others see yours
- **Upload + parsing**: upload a file → the back end parses it → the parser has a vulnerability (XXE, path traversal, SSRF)
- **Replay + parameter swap**: call once normally to obtain a token/ticket, then use the token on a different object

---

## Hunting Workflow (Follow It; Don't Skip Steps)

```
Step 0  Select target feature —— a specific endpoint/page/flow (not "the whole site")
Step 1  Establish baseline     —— use it once normally, capture complete traffic (traffic_search / browser packet capture)
Step 2  Draw this feature's    —— what roles are there? what states? what steps? what parameters?
        "state and role map"   ★ this step cannot be skipped; skipping it means blind attacking
Step 3  Go through each        —— follow the 7 dimensions above, asking yourself the core question for each dimension
        dimension
Step 4  Find the "difference   —— the difference between the success/failure outcomes (response code/length/content/side effects)
        point"
Step 5  Minimize verification  —— reproduce with the fewest steps, confirm it is not accidental
Step 6  Reproduce via a        —— hit it again with different parameter order/different client/different identity
        different path            (★ adversarial self-check: falsification and confirmation are equally valuable)
Step 7  Write back             —— actually triggered + reproducible evidence + passed Step 6 → report_finding
                                otherwise → record_fact (record an inferred entry: the point of suspicion + why it was not confirmed)
```

---

## Difference from "Known Vulnerabilities"

| | Look up CVE | Hunt 0day |
|---|---|---|
| Basis | public vulnerability databases | **the target's own behaviour** |
| Starting point | "what vulnerabilities does this component have" | "what is abnormal about this feature" |
| Tools | `search_vulns` / `search_recent_critical` | traffic review + parameter comparison + concurrency scripts |
| Output | "possibly affected" → needs actual triggering | directly "a real defect that has been triggered" |

**The two are complementary, not substitutes**: first use CVE intelligence to hit the "known surface" (fast), then use this methodology to hit the "unknown surface" (slow but potentially high-value).

---

## Common Failure Modes (Self-Check)

| Failure mode | Symptom | Correction |
|---|---|---|
| **Blind attacking** | guess parameters without looking at traffic | Step 1 must capture baseline traffic first |
| **Going in circles in one dimension** | repeatedly swap SQL payloads and encodings | stop and go through all 7 dimensions |
| **Treating a "version match" as a vulnerability** | report a finding as soon as a CVE is found | must **actually trigger** it to have a finding |
| **Reporting without reproducibility** | record a finding after succeeding once manually | must reproduce once via a different path |
| **Crossing the line** | delete data, stress test, escalate to others' accounts | only use **your own two accounts** for comparison |
| **Large-scale reading** | a script dumps the entire database | proving unauthorized access only needs reading **one** unauthorized object |

---

## Supporting Tools (Local Machine)

| Purpose | Tool |
|---|---|
| View real requests/responses | `traffic_search` / `traffic_get` / `traffic_blob` (check traffic first, don't repeat curl) |
| Get the endpoint list | `api_contract` tool (read the target's OpenAPI/Swagger contract — more accurate than a crawler); without a contract, use katana / `api-recon` skill |
| Modify and replay packets | `curl` / `python3` scripts (write to the current intent's working directory) |
| Concurrency/race verification | `python3` scripts (2–5 concurrent, small scale) |
| Parameter difference comparison | `diff_responses` tool (structured diff of two responses, automatically filters noise such as timestamps/trace ids) |
| Directory/parameter enumeration | `ffuf` / `feroxbuster` / `gobuster` |
| Endpoint enumeration | `katana` / `api-recon` skill |
| Web fingerprinting | `whatweb` / `httpx` / `wafw00f` |
| Host/service side | `nmap` / `naabu` |

**Middleware protocol specials** (MQTT/AMQP/Mongo/MySQL/PostgreSQL/Redis/SOAP/GitLab/network devices) — see the "Middleware Protocols" group on the "Host Environment" page; once installed, you can talk to the target directly with the corresponding libraries.

---

## References

`reference.md` — detailed checklists for each dimension, common payload shapes, and evidence recording templates.
