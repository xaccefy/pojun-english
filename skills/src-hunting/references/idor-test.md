> Whether to write a report is governed solely by `~/.grok/rules/vuln-report-format.md`. For the minimum probes when you enter a site with a session, see `dig-scope` §4.2.3 (object graph, id swapping, sentinel values); for a single account, use other people's ids found in lists/responses, and never grind through registration just to get a second account. By default, prove cross-user / cross-tenant access with read/list differentials first. Write-IDOR still must be tested, but **not** by modifying/deleting someone else's existing data. Ordering is in "How to hit write-IDOR" below. Batch modify/delete is forbidden, real financial loss is forbidden.
> Search short-table pointers by heading. The English BOLA encyclopedia has been cut; how to hit write-IDOR is still in the upper half.

## 1. Legacy knowledge base

# IDOR / Authorization Bypass Test Manual

> **Minimum harm:** default to read/list differentials. Write-IDOR must be tested, following "add your own first → then delete what you added". Do not read "read-only" as "write-IDOR is not tested or reported".

### How to hit write-IDOR (add first, clean up after)

If the read differential is enough to close the loop, do not write. When reads are not enough and you need to prove "I can change someone else's stuff":

1. **Test add first.** Use your own account (or no login) to call the create endpoint and see whether you can attach the object to someone else's name / someone else's store / someone else's tenant. Success = write-IDOR proven.  
2. **Then delete the row you just added.** Clear it with the same endpoint or the matching delete endpoint; leave no dirty data.  
3. **Do not** modify other people's existing orders, change other people's passwords/roles, or delete other people's existing addresses/coupons/products. Those cannot be cleaned up and are not minimum proof.  
4. If there is no create endpoint on site and only modify/delete of existing objects: change one test field **you can change back**, hit once and stop. Password change / role change / rebinding are **probe-able** per `dig-scope` §4.2.2 and `authbypass-test.md` (drop the old credential and see whether it still passes); change back immediately once it passes; if you cannot change it back, stop at the response and do not leave someone else's password, role, or email behind.  
5. To prove financial loss: only touch test amounts/status **you can revert**, hit once and revert immediately. Do not actually transfer production money, do not clear someone else's inventory, do not move someone else's existing order into an unrecoverable state. This is **not** "payment / write-IDOR is not tested". Batch operations forbidden, test-deleting production master data forbidden. This paragraph is about minimum harm, **not** "write-IDOR / takeover / adding fields is not tested".

## Concept distinction

- **Horizontal privilege escalation**: same privilege level, accessing another user's resources (A accesses B's order)
- **Vertical privilege escalation**: a low-privilege account calls a high-privilege endpoint (a normal user calls an admin API)
- **Unauthenticated access**: accessing an endpoint that requires auth without logging in

---

## Test flow

### Step 1: Find the user identifier parameter

Look for user/resource identifiers in the following places:

```
URL path:     /api/user/12345/info
URL query:    ?userId=12345&orderId=ABC
Request body: {"uid": 12345, "target_id": "user_abc"}
Response body: {"id": 12345, "created_by": 67890}  ← collect these IDs
```

**High-value endpoint characteristics**:
- Paths containing `user`, `account`, `profile`, `order`, `bill`, `message`
- Responses containing other people's phone numbers, emails, real names, ID card numbers
- Mutation endpoints: `update`, `edit`, `delete`, `change`

### Step 2: Object id (two accounts is better, but do not grind registration if you have none)

```
With a control account: log in as account A to get a token, use account B's resource ID as the control.
Single account / no account: use lists, responses, neighbouring ids, `0`/`-1`/empty as the other party's id (`dig-scope` §4.2.3). Grinding registration just to get a second account is forbidden.
```

### Step 3: Replace the identifier and test

```python
# Horizontal IDOR test example
# Use A's token to access B's resource

import requests

token_a = "Bearer eyJ..."
victim_user_id = "B's user ID"

# Original request (accessing yourself)
r1 = requests.get(
    "https://target.com/api/user/info",
    params={"userId": "A's ID"},
    headers={"Authorization": token_a}
)

# Escalated request (accessing B)
r2 = requests.get(
    "https://target.com/api/user/info",
    params={"userId": victim_user_id},
    headers={"Authorization": token_a}
)

# Compare responses
print("self:", r1.json())
print("other:", r2.json())
# If r2 successfully returns B's data → horizontal IDOR
```

### Step 4: Vertical escalation test

```bash
# Call the admin endpoint with a normal user's token
# First capture traffic under the admin account to find the admin endpoint
ADMIN_ENDPOINT="https://target.com/api/admin/users/list"
USER_TOKEN="normal user's token"

curl -X GET "$ADMIN_ENDPOINT" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json"

# 200 success → vertical escalation
# 403 Forbidden → access control exists
```

### Step 5: Unauthenticated access test

```bash
# Drop the Authorization header and request directly
curl -X GET "https://target.com/api/user/info?userId=12345"

# Or replace it with an invalid token
curl -X GET "https://target.com/api/user/info?userId=12345" \
  -H "Authorization: Bearer invalid_token_123"
```

---

## Common bypass techniques

### ID guessing
```
Numeric IDs: try ±1, ±10, 0, -1, 999999
Tenant/app fields in lists: when someone else's real ID is blocked, try 0 / -1 / empty / omitted (see "Sentinel tenant" below)
UUID: other users' UUIDs may leak from responses or JS
Phone number: some endpoints use the phone number itself as the identifier
```

### Parameter pollution
```
# Submit the same parameter multiple times
POST /api/user/info?userId=A_ID&userId=B_ID
POST body: userId=A_ID   + URL: ?userId=B_ID
```

### Path traversal
```
/api/user/A_ID/orders  →  /api/user/B_ID/orders
/api/order/123         →  /api/order/124, 125...
```

### Encoding bypass
```
userId=12345         → userId=0x3039 (hex)
userId=12345         → userId=%31%32%33%34%35 (URL-encoded)
```

---

## PoC evidence collection

```
Must save:
1. Full request content (including token, headers)
2. Full response content (including the victim's data)
3. Comparison screenshots (A's normal response vs the escalated response)
4. Proof of the mapping between the victim account ID and the data
```

---

### Encrypted ID (short-table pointer)

Recognize: the request id for changing/reading an address, order, or profile is a long ciphertext; the plaintext small number is visible in the response or list; JS has `RSAUtils` / `JSEncrypt` / `security.js`, or a hard-coded `modulus` + `exponent`.

Hit: ciphertext is not a wall. Anyone can use a public key.

1. Hit your own row first, compare against the plaintext id in the response  
2. Use the same frontend crypto to encrypt neighbouring numbers yourself (plaintext ±1, then further out)  
3. Swap only this ciphertext id, leave the session untouched  

Counts as: after swapping, **someone else's** name/phone/address comes out. Merely proving your own ciphertext decrypts to your own plaintext → does not count.

False positives: the server filters by session so even correct encryption returns only your own; the key is for signature verification and arbitrary ciphertext is rejected outright. If a single site misses, do not delete this row from the short table. Key material and any site's `security.js` link do not go into the knowledge base — copy them from the current site's JS on the spot.

### Sentinel tenant (short-table pointer)

Recognize: ticket / qualification / session lists carry `appId`, `tenantId`, `orgId`; the response contains attachment URLs (`sign` + `file_name` + yet another tenant field).

Hit (swapping in someone else's real ID is the existing horizontal IDOR; this is an extra shot):

1. Try `0`, `-1`, empty string, and omitted for the tenant field — the backend often treats a sentinel as "do not filter"  
2. Only counts as broken if `total` / row count balloons relative to your own tenant baseline; increasing `pageSize` or paging through `page` just pulls the full volume, **not a bug**  
3. Try `0` / `-1` on type fields (`serviceType` and the like) too — it may switch to a different business document set  
4. Signed downloads in the list: opening them as-is often returns 403; **leave `sign` / `file_name` untouched and change only the tenant in the URL to your own** (the signature does not cover that field). Details in the presigned-URL section of `file-upload-test.md`  

Counts as: another tenant's ticket body / support conversation appears in the list, or an attachment really downloads to their licence. The main point is cross-tenant business reads.

False positives: `0` still returns only your own; switching tenant on download gives 403; only a file channel exists with no business list. If the sentinel value misses → do not delete this row; still try list filtering at the next site.

### Registry catalog does not filter by tenant (short-table pointer)

Recognize: container / cloud function / mini-program cloud; you can `docker login` or see a Registry / Harbor / `/v2/`.

Hit: this is list IDOR, not unauthenticated file download.

1. Log in to the registry **with your own account**  
2. `GET /v2/_catalog` (Harbor also has a project-list style endpoint — same shot)  
3. If repository names in the response match **another tenant** → `/v2/<repo>/tags/list`, then `docker pull` one of them  

Counts as: the catalog contains another tenant's private repos and the image can actually be pulled (the layers are their application/config). Merely proving you can log in and pull official public images → does not count.

False positives: the catalog returns only your own; names are listed but pull gives 403; it is a public registry anyway. If a single site misses, do not delete this row from the short table.

This is a different shot from anonymous fileId download and from a fully open OSS bucket policy: this one is **after login, the catalog hands over the whole site's private repos**.

### Login-prefix twin (short-table pointer)

Recognize: the business H5 puts its login RPC under `/fapi/d/` (or a similar login-required prefix); the same gateway also has `/fapi/n/` (or n / unlogin / guest) as an unauthenticated prefix. Hitting only the `d` endpoint from JS makes the whole segment look login-required.

Hit (no login):

1. The `d` endpoint should demand login / a ticket — that is the control  
2. Change the `d` in the path to `n`, same RPC, same object id, hit again  
3. Swap in neighbouring ids; open the ID-photo URL that comes back  

Counts as: another person's ID card / ID photo / phone without login.

False positives: `n` still demands login; `n` only serves public config; only the supplementary document you just submitted. If a single site misses, do not delete this row from the short table.

### Numeric RPC neighbouring cmd (short-table pointer)

Recognize: the business page's JS calls a numeric RPC gateway (`/data/{number}/forward` and the like). The page usually hard-codes only one cmd (invoice/ads etc.). Neighbouring numbers may be another internal list/write endpoint — do not stop at the hard-coded one. `numeric RPC gateway` is a common wrapper name; hit it even without that name.

Hit (no login):

1. Copy the forward address from JS and change the number in the path to neighbouring values  
2. Send an empty `{"req":{}}` first to see the list; the hard-coded cmd should be a different business set  
3. Once internal records appear in the list, take an id to the neighbouring write endpoint (use a fake id / an already-empty id first). If it passes and you can revert, revert  

Counts as: internal publishing/operator text, or a field really changes.

False positives: neighbouring numbers are the same public API; only a public software catalogue. Key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Identity-domain account CRUD (short-table pointer)

Recognize: the same product's business frontend account CRUD endpoint returns a login gate (`AuthFailure.NoLogin`); there is a separate `*-ids` identity subdomain where the same `/api/ms-account/` does not want a Cookie. GET list may 404; only POST returns data.

Hit (no login):

1. The same list on the business frontend should return a login gate — that is the control  
2. Switch to the ids subdomain `POST /api/ms-account/user/list`, try both an empty body and `Offset+Limit`  
3. Once through: `generate` → `reset-pwd` with only the Id (without the Id it should be a parameter error) → `delete` to clean up the probe account  

Counts as: the roster contains phones/corporate emails; you can create accounts, change passwords without verifying the old one, and delete by Ids.

False positives: only hitting the business frontend and concluding there is no bug; list returns data but Mail/Phone are all empty and the write endpoints are also gated. If a single site misses, do not delete this row from the short table.

### List filters but detail is not gated (short-table pointer)

Recognize: the public list only shows published/public items; detail, hidden, tab, preview/export use the same business id. Or the list has a visibility query parameter that filters hidden rows by default. Or the list needs login / an empty body while detail needs only a numeric id + business key (workid etc.). Or the public detail blanks the contact/phone while the review/approval detail uses the same business id. Or the docs CMS frontend hard-codes the public `area` / `terminal` / `channel` and the API does not authenticate. Or the public search endpoint has a material-type parameter (`materialType` / `tab`) defaulting to the public value. Or the onboarding/review query with only a business id returns an empty shell. Or the same product's full list endpoint takes no visibility parameter and each row already carries unpublished/offline body text, while public search and showcase detail are still gated. Or the browse page/catalogue says visitors must log in, yet the same site's search API still returns internal/proprietary document bodies without login.

Hit (no login):

1. Note the public list ids; feed ids that are absent from the list into detail / hidden / tab; if detail is 403, follow up with preview / export  
2. Add `status=hidden` / `all` / `private` (or a similar visibility parameter) to the list endpoint yourself. Control: without the parameter the list is empty or public-only; if the same id still says "no permission" on detail, do not stop — the gate may be attached only to detail  
3. **If this list endpoint is 401 / login-required / returns an empty shell, do not stop.** Switch to another guest query in the same product and look at `hidden` / `is_public` / `isHidden` in the response. If public contents 404s, hit hidden/contents with the same id. Detail that only needs a numeric id + business key is still worth hitting. If `is_secret=1` still returns the full text, do not stop at the title.  
4. **If detail returns 200 and the JSON already contains unpublished content / wants login / `canAnswer=false`, do not stop.** Check whether `savedConfigDraft` or similar draft fields in the same payload hold the unpublished body. The block message and the draft can live in the same JSON.  
5. **If the public detail blanks contact / mobile / email, do not stop.** Hit the review / approval / audit detail with the same id; the gate may be attached only to the public presentation endpoint.  
6. **If the work/project has `period=edit|publish` (or a similar status parameter), do not stop at publish.** Hit the content endpoint with `period=edit` without logging in. Control: publish on the same id says it does not exist / was deleted, and info blocks with "no permission to read someone else's". Only counts if edit still returns the body.  
7. **If a JSON list filter field is null / a missing field reports Unknown / a parameter error, do not stop.** Change that field to an empty array `[]` and hit again. Backends often treat an empty array as "do not filter", leaking delisted rows / the whole table anonymously; a missing parameter or null blocks instead. Control: `null` or deleting the key should error or return empty, and only `[]` returns delisted bodies.
8. **If the docs CMS frontend hard-codes the public `area` / `terminal` / `channel`, do not stop at the default.** Without login, change the parameter to an internal area (commonly 1 vs 2, oa vs public). Control: the onboarding/hardening/intranet algorithm bodies absent from the default public list must appear in the list or detail after the change.  
9. **If the public search endpoint has `materialType` (or a similar material type), do not stop at the frontend default public value.** Control against the public spec / showcase types, then switch to internal marketplace materials, marketing specs and the like. If the path missing `/v2/` reports `auth failed`, do not stop — apply the frontend replacement rule and hit again. Counts as: internal material rosters / direct file links behind an SSO wall with `isLimitAuth=1`.  
10. **If the self-service onboarding/review query with only a store number/business id returns an empty shell, do not stop.** Add review status = approved (`baseInfoStatus` and the like) and hit again. Follow the returned `uid` immediately into the email/contact endpoint. Control: without the status it should be an empty shell or have no phone.  

11. **If the licence-image JSON has no idNo, do not stop.** Once detail returns a trademark registration certificate / licence scan, open it: the registrant row often concatenates the ID card number after the name. Counts if the image matches the person; do not just scan JSON fields.  
12. **If the export task list with `pageNum=0` is empty, do not assume there is no data.** Change to `pageNum=1` and hit again — it often returns the whole site's other users' exports. Take the `fileName` / key and hit download.
13. **If the detail telephone / mobile field is masked, do not stop.** Unpublished details' `requirement` / remarks / free text often contain the full 11-digit phone; the API only strips the structured fields.
14. **Hit the full list endpoint even without a visibility parameter.** Read unpublished / offline / rejected detail bodies straight from the rows. Control: public search for that id gives total=0, and the showcase detail a human opens says it does not exist. Do not conclude "no bug" from only the public search and detail page.
15. **If the browse page/catalogue says visitors must log in, do not stop.** The same site's search API (Keyword+Page+PageSize) may still return internal/proprietary document bodies and detail URLs without login. If the detail page JSON has `isLogined=false` but still returns the full text, do not stop. Control: the catalogue page a human opens says visitors must log in to view.
16. **If the detail endpoint says already supplemented / project does not exist, do not stop.** The same site's visit-log / tracking / doc-add-visit-log may still return OA/internal full text given just the numeric article number. Control: the original detail endpoint with the same business id should already be blocked.
17. **If the catalogue says visitors must log in to view/download, do not stop.** The same site's file list endpoint (`getHomeCosFileList` and the like, `solution_id`+`version_id`+`folder_id=0`) may still return training videos/whitepapers/manual rosters without login. Feed the list's `file_id` into the privilege endpoint (`getFilePrivilege`) and look at `PreviewUrl` / signed download. Control: the catalogue page a human opens says visitors must log in to view and to download.
18. **If the content SPA picks the Color/gateway domain by `location.host` regex, do not hit the wrong TLD.** JS commonly has `.*\\.jd\\.hk` → the content gateway domain; hitting the wrong content gateway domain makes it look like there is no endpoint. The technique is still, without login, floor queryContents + previewContentDetail. Control: the public detail should not exist / return 1414.
19. **If the docs site's public itemList / catalogue only shows external products, do not stop.** Without login, change `item` (or a similar project number) to a plain auto-incrementing number and hit detail/page. The body may be compressed markdown — decompress it the same way the frontend does. Only counts when it reaches a "for internal / not yet external / not for external release" library absent from the public itemList.
20. **If a collection-form / questionnaire fill-in detail JSON has a relative / linked table pointing at an answer sheet, do not stop.** What a human opens is the fill-in page; the answer sheet may have a different id. Hit the answer sheet detail/opendoc without login. Control: the fill-in page only has the questions; only the answer sheet exposes ID card/phone cells.
21. **If the content preview endpoint needs only a numeric contentId and the response says `isDelete=1` / deleted / unpublished, do not stop.** Control: the public showcase should not have this piece. Only counts if it returns the full H5 page or editor JSON; do not just look at the title.

Counts as: unpublished business body comes out of the list (not a public showcase title); or another subject's phone / ID; or a licence image with the ID number printed on the registrant row; or unpublished/delisted work source text.

False positives: adding the visibility parameter still returns only public drafts; only titles with no body; concluding "no bug" because the list is 401; edit and publish return the same already-published body; the empty array and the missing parameter return the same published draft; `materialType` still only returns the public showcase; concluding "no bug" from an empty shell with only a business id and not adding the review status; concluding "no bug" from only the public search/showcase detail; concluding "no bug" because the browse page says log in; the numeric item still being the same few public documents. Hitting the wrong Color domain is not a false positive (it just means no endpoint was found). If a single site misses, do not delete this row from the short table.

### Cross the gateway without an auth header (short-table pointer)

Recognize: logistics / open gateway (`lop-proxy` and the like) frontend JS hard-codes `Auth-Control: no-auth` + `LOP-DN` (business domain). Other business endpoints demand login, yet the roster/waybill endpoint still returns data with this header set.

Hit (no login):

1. Copy `LOP-DN` and `Auth-Control: no-auth` from JS (or a similar gateway auth-bypass header)  
2. Hit the site/roster endpoint with empty paging; then swap in an enumerable `siteId` and hit waybill/detail  
3. Control: without the header it should demand login or report the Host as unregistered  

Counts as: another person's phone / address / site contact, not a public track-and-trace.

False positives: the header passes but the business still demands login; only public tracking with no PII. If a single site misses, do not delete this row from the short table.

### Anonymous session reads the signup table (short-table pointer)

Recognize: BaaS anonymous session; the list endpoint does not verify admin. The page hard-codes a few admin IDs and the backend redirects to login. Appwrite / Weavefox / TablesDB are common wrappers; hit it even without those names. Frontends commonly have `Client().setEndpoint`, `X-Appwrite-Project`, `POST /v1/account/sessions/anonymous`; signup/activity tables go through `tablesDB.listRows`.

Hit (no login, no admin account):

1. Without a Cookie, hit `GET /v1/tablesdb/{db}/tables/{table}/rows` first — the baseline should be `total=0` / empty rows (the system does block guests)  
2. `POST /v1/account/sessions/anonymous` with body `{}`, the same `X-Appwrite-Project` header, and capture `Set-Cookie: a_session_…`  
3. Hit the same listRows again with this anonymous session  

Counts as: after the anonymous session, `total` balloons relative to the empty session and the rows contain **other people's** phones / emails / signup bodies. The admin allow-list lives only in the browser and was never applied to the list endpoint.

False positives: no session already returns the whole table (that is fully unauthenticated — record it separately); the anonymous session is still empty or only contains the row you just filled; DELETE on someone else's row returns 401, which only shows writes are off while reads still count; a public marketing roster. If a single site misses, do not delete this row from the short table.

This is not the same shot as "CRUD without even a Project key or an anonymous session": the key here is that **the anonymous session is treated as logged-in and admin is not verified**.

### Cloud-development anonymous user table (short-table pointer)

Recognize: cloud development has anonymous login enabled and exposes a low-code data source function. The environment id can be copied from the console or the frontend. This is neither the proxy `targetUrl` already in the short table nor the BaaS `sessions/anonymous`.

Hit (no login):

1. `POST https://{envId}.api.<cloud-dev-gateway>/auth/v1/signin/anonymously` with the `x-device-id` header and body `{}` to get a JWT  
2. `POST /v1/functions/lowcode-datasource` with `Authorization: Bearer` that ticket, body `dataSourceName=sys_user`, `methodName=wedaGetRecords` (`getRecords` is the same origin)  
3. Control: the same gateway's `GET /auth/v1/user/query` should block anonymous; the data source name `users` usually fails row permissions — **do not stop**, `sys_user` is the system user table  
4. If the HTTP gateway (commonly `/web?env=`) returns `LOGIN_TYPE_DISABLED`, **do not stop**: switch to `POST /web?env=`, `auth.signInAnonymously` → `auth.getUserInfo` to get `jwt;expire` (**do not strip the semicolon suffix**) → `functions.invokeFunction`, and hit `sys_user` / `wedaGetRecords` the same way  
5. If an old HS256 ticket sent to `/v1/functions` reports `KID_INVALID` → this shot failed; switch to the step-4 gateway ticket and do not treat it as "data source does not exist"  
6. If `sys_user` row permissions fail, **do not stop**: with the same `/web` anonymous ticket switch to `database.countDocument` / `database.queryDocument` with `collectionName=users` (the user table persisted by federated login, not the data source name `users`)  

Counts as: the records contain **other people's** phones / emails / uin / super-admin flags, not an empty account you just created anonymously.

False positives: row permissions reject anonymous and the `/web` users collection is also empty; the data source does not exist; only demo todo/sales come out; treating an old HS256 ticket's `KID_INVALID` as no bug. An HTTP gateway `LOGIN_TYPE_DISABLED` is not a false positive. A failure on the data source name `users` does not count as a false positive. If a single site misses, do not delete this row from the short table. Key material and any particular JWT do not go into the knowledge base.

### Copy openid from detail, then hit the mailbox (short-table pointer)

Recognize: the recruitment/specified-user detail carries `specifyUsers` or openid; the H5 hard-codes a SHA256 request signature; or the invite page URL already has `?openid=`.

Hit (no login):

1. Call detail and copy the openid  
2. Compute the Signature with the key and hit `/msg/message/list/`  
3. If the URL already has openid, also hit the unsigned `get_invite_code` / `count` / `detail`, and feed the roster `uid` back in  

Counts as: the mailbox or invite code/roster changes with the openid, showing the other party's points-expiry notice or a masked phone/nickname.

False positives: the list is identical for everyone because it is a site-wide broadcast; the endpoint really needs login/a signature; a fake openid yields no invite code; a public marketing roster. If a single site misses, do not delete this row from the short table.

### Knowledge-base nodeId unauthenticated full-text read (short-table pointer)

Recognize: the publish page's conversation-data artifactMap has a knowledge-base `nodeId`; the main site's `/space/d/` requires login.

Hit (no login): hit the publish domain `POST /space/api/page/share/query/pagechunk` (body=`pageId=nodeId`). Control: the share page's own pageId should be "not shareable".

Counts as: pulling another person's full document (title/character card/outline, `role=editor`).

False positives: only an already-published HTML snapshot is read; pagechunk returns 12607 for the knowledge base too; the body is already inside the conversation snapshot. If a single site misses, do not delete this row from the short table.

### Anonymous CSRF header reads detail (short-table pointer)

Recognize: the anonymous CSRF/temp token endpoint hands out a token directly; the business detail verifies only this header, not login; the numeric id in the query and `data.id` in the response need not be the same number. This is not the assistant `GetHistoryList` optional login header (that shot is in "Assistant history reads other people's tasks unauthenticated").

Hit (no login):

1. Hit the csrf/token endpoint to get the header  
2. Swap the detail to numeric ids (1, 2, 13); **if the query id does not match the response id, do not stop**  
3. Control: without the header it should fail; a nonexistent id should say "does not exist"  

Counts as: unpublished/test training scripts or internal conversation bodies (cardMap/full dialogue, not titles).

False positives: only a public plaza; the token passes but the result is still empty. If a single site misses, do not delete this row from the short table.

### Custom identity header as session (short-table pointer)

Recognize: the admin SPA request interceptor treats a custom header (`User-Id` / `employeeId` / `X-User-Id` and the like) as the login identity and does not want a Cookie. Without login, the roster endpoint often returns only numeric employee/BD numbers with no phones.

Hit (no login):

1. Copy the header name from the JS interceptor  
2. Hit the roster without login (empty params / headquarters filter). If it only returns numeric numbers, **do not stop**  
3. Swap the header to that number and hit the current-person info endpoint. Control: without the header or with `1` it should return nothing  

Counts as: another person's name + 11-digit phone.

False positives: the header passes but the result is still empty; the roster already returns phones (that is a different shot). If a single site misses, do not delete this row from the short table.

This is not the same as "anonymous CSRF header reads detail": that one is a temp token header, this one is **an identity number in the header**. Nor is it the same as "onboarding H5 empty params leak the BD directory": that one leaks phones for the whole table with an empty category, while here the roster has no phones and you need one more shot with the header as identity.

### Customer detail endpoint also accepts phone (short-table pointer)

Recognize: the CRM / enterprise IM customer detail endpoint's frontend only writes the external contact id (`externalUserId` / `contactId`). With only this id it returns an empty shell. The backend also accepts `phone`, and usually needs `tagShow` / `udfShow` to expose internal fields.

Hit (no login):

1. Control: with only the external contact id it should be an empty shell  
2. Add the 11-digit `phone` to the body and turn on `tagShow` / `udfShow` (or similar expand fields)  
3. An empty or random number should give an empty shell; a different number must give a different person  

Counts as: another person's name / company / internal UDF comes out, and the lookup is for that exact full number.

False positives: phone is always empty or only the same test number comes out. An empty ID-card slot is not a false positive. If a single site misses, do not delete this row from the short table.

### Assistant history reads other people's tasks unauthenticated (short-table pointer)

Recognize: the assistant/Agent frontend has `GetHistoryList`; the login state lives only in an optional header. This is not conversation-tool execution (that shot is in `agent-tool-exec-test.md`).

Hit (no login): call the list and swap guids to check whether it is the same batch; then feed `session_id` to `GetHistory`. Page with `last_ts`+`direct=back`.

Counts as: **other people's** task text (downloads, subscriptions, conversation cards) appears in the list/detail, not a public plaza.

False positives: only the plaza `GetSquareTasks`/`share_id` comes out; swapping the guid makes the list empty or leaves only your own. If a single site misses, do not delete this row from the short table.

### Hard-coded appKey hits business tables (short-table pointer)

Recognize: the frontend `AV.init` / LeanCloud hard-codes `appId`+`appKey` (or `X-LC-Id`/`X-LC-Key`); or the nocode/supabase landing page hard-codes a `role=anon` JWT.

Hit (no login): with these two headers, hit `/1.1/classes/*`: `_User` first as the control should 403, then scan business tables with count/limit; if writes are allowed, change a probe field and delete it back. For supabase, use `apikey`+`Authorization: Bearer` against the tables listed by `/rest/v1/` swagger. **If rest tables 403 / only public marketing config is exposed, do not stop**: switch to `POST /storage/v1/object/{bucket}/{official prefix}` with the `x-upsert:true` header (see `file-upload-test.md` STS step 9).

Counts as: a business table `count` is huge or contains **other people's** drafts/emails/phones; PUT on someone else's `objectId` succeeds.

False positives: both `_User` and the business tables 403; you can only read what you just created; you can only LIST public marketing config. If a single site misses, do not delete this row from the short table. Key material does not go into the knowledge base.

### Form model ships the standard answers (short-table pointer)

Recognize: the questionnaire/quiz form-model endpoint; the frontend hard-codes the business id or an allow-list (`FORM_WHITE_LISTS` / a demo encryptFormId and the like); the response schema carries the `answer` standard answers or internal review questions/sample images. This is not a public signup form title, nor an already-submitted answer list.

Hit (no login):

1. Hit getModel / schema / getFormModel from the JS allow-list/demo id; do not stop at the form title  
2. Open the sample image preview/imgUrl from the schema  
3. Hit the admin list/export/fillList separately; if there are no fill records, do not invent answer sheets  

Counts as: internal quiz body + standard answers, or ID/licence sample images really downloaded.

False positives: only the public signup form title; the schema has no answer; only the answer sheet you just filled. If a single site misses, do not delete this row from the short table.

### Unauthenticated internal knowledge text (short-table pointer)

Recognize: the customer-support/developer support portal umi has `getKnowledgeList.json` + `getKnowledgeInfo.json`; or the hall/help HTML detail endpoint takes a numeric article number; or the public bulletin JSON (bulletin / getbulletin and the like) uses `callname` + `callcontent` as an RPC while the page only calls public menus (`getKnowledgeByMenuId`); or the unauthenticated CMS `siteList` / `contentList` / `content` can list non-official sites and the channel names carry "Internal Knowledge Base"; or the customer-support/IT chatbot's unauthenticated search endpoint (menu id + fuzzy searchText) keeps the body in `buttonList`/`searchList`'s `behavior.value`, not in the title `content`. Do not recognize only that umi json set.

Hit (no login): `queryUserInfo`/`queryFeedbackList` should deny — that is the control. Try the list `categoryId` from 1, then feed `id` to Info. **Even without a json list, hit the HTML detail** (`showKnowledgeInfo.htm?knowledgeId=` / `help_detail.htm?help_id=`) with a modern UA (IE may hit netd). Bulletin endpoint: when the public menu comparison returns very few rows, change `callname` to `getKnowledgeList` (`callcontent` handles paging), then hit `getKnowledge` with the detail id. CMS: first `siteList` to copy a non-official siteId, then `contentList` to inspect channel names, then swap the siteId and hit `content` detail; the default official-site Banner is not this shot. If the gateway reports `loginMode is null`, do not stop — add the `loginMode: 0` header; if siteList still fails for a missing siteId, hit contentList directly with the internal siteId. content also needs the siteId; without it there is no body. chatbot: if the `chat_dir_id`-style directory endpoint returns 401, do not stop — switch to the search endpoint (`search_recommend` and the like), fill `searchText` with common characters and `id` with the menu number; read the body from `behavior.value`.

Counts as: the list `pager.items` is in the thousands or count is huge, and Info/HTML/detail/`behavior.value` returns **internal** scripts/investigation notices/SMS/operations knowledge-base bodies, not a public FAQ / external agreement.

False positives: only public help articles/error codes/external agreements/official-site Banners; Info returns only the title; the ticket endpoint also lets you in (that is another shot); only the default official site was hit; stopping when the dir node returns 401; the search endpoint returns only title content. If a single site misses, do not delete this row from the short table.

### Open-payment fake-signature appId enumeration (short-table pointer)

Recognize: the open-payment / merchant-onboarding gateway body has `appId`+`sign` (optionally plus `random`/`merchantId`). With a fake signature a live app returns `MERCHANT_NOT_EXIST` or `SUCCESS`, while a dead app returns `SIGN_ERROR` / `APP_NOT_FOUND`. This is not the "salt hard-coded in JS, compute it yourself" row, nor copying a real AppSecret out of the docs.

Hit (no login):

1. Put a fake value in `sign` (32 `a`s and the like) and sweep `appId`, comparing response codes  
2. For live ones, hit the merchant query (`query` / `query/v2`) with a swapped `merchantId` (documentation sample numbers, neighbouring numbers)  
3. With the same fake signature, hit the signing/agreement endpoint and only check whether the response is accepted; do not batch-sign, do not change the settlement card  

4. **If the ST / demo cashier pre-order with a fake or node-signed signature still reaches the production gateway**: POST `/api/precreate` or `/demoapi/precreate` without login, `sign` fake + live appId + someone else's merchantId. If the site's own order query 404s, do not stop — hit production `/api/pay/query`.

Counts as: another merchant's ID card / bank card / phone comes out; or the production order query returns `ORDER_NEW` with another merchant's transaction number.

False positives: a fake signature always gives `SIGN_ERROR`; `SUCCESS` but all ID/card numbers are empty; the documentation sample appId is dead; only `channelPayerNo` comes back and the production order query finds nothing; it can only attach to the demo store. If a single site misses, do not delete this row from the short table. Real key material does not go into the knowledge base.

### Short link 302 query carries the phone (short-table pointer)

Recognize: an SMS/marketing short-link resolver; a guessed short code 302s to a landing page whose query carries `phone` / `name` / amount in plaintext. The home page may be an OpenResty welcome page, 302 to the brand site, or an `index.html` with only Hello — **do not judge the whole site dead from `/` alone**.

Hit (no login):

1. `/open` `/app` `/s/` `/www` plus a small dictionary (`aaaaa`, `1`, `1234`)  
2. Look only at the 302 target query; do not follow into the landing business domain  
3. Control: non-matching codes should give an expired page with no phone number  

Counts as: the redirect URL carries **someone else's** phone/name.

False positives: an expired page; public marketing with no PII; the short code needs a real SMS to resolve. A Welcome home page / 302 to the official site / a Hello shell is not a false positive. If a single site misses, do not delete this row from the short table.

### Privacy number falls back to the real number (short-table pointer)

Recognize: order/store/logistics H5 calls a privacy-number or virtual-number (AXB) endpoint; without login it needs only the business appid + an enumerable object number. On failure the response hands back the real 11-digit phone and the copy still says acquiring the privacy number failed and the real number will be dialled. Do not dismiss it as just a virtual-number endpoint.

Hit (no login):

1. Copy the functionId / privacy-number path from the frontend, and hit the object number from 0, 2, and neighbours  
2. Control: a non-numeric object number should be a parameter error with no phone  
3. Only if the number changes with the swapped number does it count as bulk  
4. If the gateway returns `cross-origin 403` for an empty Origin or the site's own Origin, **do not stop** — switch to a business-domain Origin (order / cart / H5 domains, without pinning one host) and hit again  

Counts as: the response is **someone else's** real phone.

False positives: only a virtual/intermediate number comes out; login is required; swapping the number does not change the number; treating an empty-Origin 403 as no endpoint. If a single site misses, do not delete this row from the short table.

### Onboarding H5 empty params leak the BD directory (short-table pointer)

Recognize: the onboarding H5 has a business-development contact page; other settle endpoints in the same set 302 when not logged in. JS contains an RPC that looks up BD by category (queryBd / bdInfo and the like); when industry/category is empty the body is empty. The page may only display the 400 hotline.

Hit (no login):

1. Copy the gateway `/api` and functionId from the business-development contact page's JS  
2. Hit it with the category field empty (`body={}`). Control: filling a fixed numeric category number usually returns an empty array  
3. Do not treat a 302 on the other settle endpoints in the same set as the whole site having no endpoint  

Counts as: the full table of internal BD names + 11-digit phones + corporate emails.

False positives: filling a fixed numeric category returns an empty array and you call it no endpoint; mistaking the page's public 400 hotline for this shot. If a single site misses, do not delete this row from the short table.

### Onboarding H5 hard-coded token swaps a pin (short-table pointer)

Recognize: the onboarding H5 / mini-program bundle hard-codes the token for the OCR / company-info endpoint. The JSON endpoint needs only a pin (or similar account) + a non-empty token, no Cookie. Control: leaving the token empty or omitted returns empty data only.

Hit (no login):

1. Copy the hard-coded token and the company-info path from the onboarding chunk  
2. The empty-token control should give empty data  
3. With the hard-coded token, hit pins like `admin` / `test` / `0` / short account names  
4. Once the hard-coded string passes, also send an arbitrary non-empty string as the control (if it passes, the token content is not validated)  

Counts as: swapping the pin returns the matching real phone.

False positives: empty token also returns data (fully unauthenticated — a different shot); the token passes but only returns the record you just onboarded. If a single site misses, do not delete this row from the short table. Real key material does not go into the knowledge base.

### Company name / invoice-title autocomplete (short-table pointer)

Recognize: signup/onboarding/invoice-title autocomplete; the page dropdown only shows company names; the endpoint goes through a business-registry/D&B Match or a title suggest. The frontend may mark that endpoint `auth:true` while the server still does not verify login.

Hit (no login):

1. POST the name + country code, or hit the title endpoint. The suggest field may be `prefix` (filling `title` reports "keyword cannot be empty", which looks like no entry point)  
2. If suggest reports an empty keyword, do not stop: the same product also has a special-invoice/business-registry completion endpoint whose field really is `title`; hit it even though the frontend marks it `auth:true`  
3. Control against the page dropdown: the page only has company names, so only extra phones/cards/addresses in the response count  

Counts as: the response contains the person in charge or the invoicing phone/address/bank account, and it matches a real person.

False positives: both the dropdown and the endpoint return only company names; login is required; a public company directory with no phones; treating the frontend `auth` flag as "no bug". If a single site misses, do not delete this row from the short table.


### Mass Assignment / hidden writable fields (short-table pointer)

Recognize: the register / update-profile / create-user JSON has more fields than the page controls; Swagger, the admin "create user" form, or frontend comments expose `role` / `isAdmin` / `verified` / `tenantId` / `balance` / `permissions`.

Hit:

1. Compare admin create-user vs your own register/update-profile, and inject only the fields that differ. Without a control, copy them from Swagger / JS.  
2. Inject only once against your own account; revert immediately if it passes. Do not change the role of someone else's existing account.  
3. Also try `__proto__` / nested `user.role`; this is not the same as the PP template RCE (for PP see `prototype-pollution-test.md`).

Counts as: your own account becomes high-privilege, or the balance/verification state really changes. If the field is accepted but permissions do not change → not a hit.

False positives: you can only change the display name; a public operations toggle; the server-side allow-list swallows extra keys. If a single site misses, do not delete this row from the short table. Do not invent fields when there is no register/update-profile endpoint.

## 12. QUICK IDOR CHECKLIST

```
□ A control account is better; with a single account use lists/responses/neighbouring ids, never grind registration for a second account
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint (writes: POST to add first, then delete the row you added; never delete someone else's existing object)
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own)
□ Ciphertext ids: if JS has the public key, encrypt adjacent numbers yourself (see "Encrypted ID")
□ Try 0 / -1 / empty for the list tenant field (also try after someone else's real ID is blocked; see "Sentinel tenant")
□ With a Registry/`/v2/`: hit `_catalog` with your own account and see whether other tenants' images can be listed and pulled (see "Registry catalog")
□ After a BaaS anonymous session, listRows again and compare against the empty table with no Cookie (see "Anonymous session reads the signup table")
□ After cloud-development anonymous login, hit `lowcode-datasource`'s `sys_user`/`wedaGetRecords`; do not stop at HTTP gateway `LOGIN_TYPE_DISABLED` (see "Cloud-development anonymous user table")
□ Detail carries specifyUsers/openid: copy the openid and hit the mailbox (see "Copy openid from detail, then hit the mailbox")
□ Hit pagechunk with the nodeId from the publish page artifactMap (see "Knowledge-base nodeId unauthenticated full-text read")
□ Assistant GetHistoryList optional header: call list/detail without login (see "Assistant history reads other people's tasks unauthenticated")
□ Frontend hard-codes LeanCloud/supabase anon: hit business tables (see "Hard-coded appKey hits business tables")
□ Knowledge list + detail returns internal scripts without login (see "Unauthenticated internal knowledge text")
□ Open-payment onboarding gateway fake-signature appId enumeration, then swap merchantId on live apps (see "Open-payment fake-signature appId enumeration")
□ Do not stop at an SMS short-link Welcome home page / 302 to the official site / Hello shell; guess /open /app /s/ /www and look for phones in the 302 query (see "Short link 302 query carries the phone")
□ On an unauthenticated privacy/virtual-number endpoint failure, check whether the real phone is actually delivered and whether the object number is enumerable (see "Privacy number falls back to the real number")
□ Signup/onboarding/invoice-title autocomplete: hit suggest (prefix) and the special-invoice/business-registry completion endpoint (title) without login; hit it even when the frontend marks auth (see "Company name / invoice-title autocomplete")
□ Onboarding H5 BD contact page: hit the JS BD lookup with an empty category; do not fill a fixed number (see "Onboarding H5 empty params leak the BD directory")
□ Admin SPA treats the `User-Id` header as identity: do not stop when the roster has only numeric numbers — swap the header to that number and hit the current-person info endpoint (see "Custom identity header as session")
□ Do not stop when the browse page/catalogue says visitors must log in; hit the same site's search (Keyword+Page) without login and follow the detail URLs (see "List filters but detail is not gated" step 15)
□ Do not stop when the catalogue says log in to download; hit the same site's file list endpoint + privilege endpoint PreviewUrl without login (see "List filters but detail is not gated" step 17)
□ Change the public search endpoint's `materialType`/`tab` to internal types; do not stop when a path missing v2 reports auth failed (see "List filters but detail is not gated" step 9)
□ When the onboarding/review query with only a business id returns an empty shell, add review status = approved and follow the response uid into the email endpoint (see "List filters but detail is not gated" step 10)
□ Do not stop when the docs site's public itemList only has external products; hit detail/page with a plain numeric item (see "List filters but detail is not gated" step 19)
□ Do not stop when a collection-form/questionnaire fill-in detail's relative points at an answer sheet; hit the answer sheet without login (see "List filters but detail is not gated" step 20)
□ supabase anon JWT: beyond rest tables, hit Storage REST + x-upsert to overwrite the official prefix (see file-upload STS step 9)
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status: only your own order / a test field you can revert
□ Merchant binding promotions/coupons: change productId to attach to someone else's goods; only counts if the consumer-side price drops (see logic-test.md §1.4)
```

---


Merchant binding a promotion/coupon to a SKU: only the coupon ownership is checked, not the product ownership → your own coupon + someone else's productId; only counts if the consumer-side price drops. Details in logic-test.md §1.4.

## Public directory endpoint dumps whole rows including attachments (short-table pointer)

Recognize: a directory/catalogue/member-list style public endpoint (no auth, `pageSize` can be enlarged) whose response is the whole database row — besides the published columns it also has file path fields (commonly bmbfj/attachment/fileUrl/icon) plus phone, legal representative and other columns.

Hit:
1. Pull the full set with `pageSize=500` without login, and reconcile against `count` (so pages are not missed);
2. Scan all fields: count rows where file-type fields are non-empty, and regex `1[3-9]\d{9}` for phone rows;
3. Concatenate the file relative path with imagePre/the image-host base (the `imagePre` in app.js, or the absolute URL in the response), URL-encode it and GET directly, and verify the magic bytes (jpeg/pdf/zip) to confirm it is the real object and not a placeholder;
4. One sample is enough to count; quantify the rest with field statistics (N attachments, M phones).

Counts as: downloading the actual stamped document / signup form, or bulk-exporting phones + names.
False positives: attachments 404 / require signature auth; all fields are placeholders (e.g. 0000@qq.com); the endpoint only returns the published columns and has no file fields.
