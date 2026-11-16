> Whether to write it up or not is determined only by `~/.grok/rules/vuln-report-format.md`. This article is about testing methods: don't stop at "can upload, can download"—follow through to executable/path/SSRF/cross-user business objects.
> For short-table pointers, search by title. PHP webshells / GIFAR / ImageTragick / English attachments have been cut; without object storage, don't waste shots on cross-bucket attacks.

# File Upload Vulnerability Testing Manual

## Test Flow (Opening)

Find the upload point (avatar/attachment/import/richtext) → first upload a normal file to see the path, whether it's renamed, whether it lands on CDN/OSS or local disk, and whether it can be opened directly. Don't stop at "can upload, can download": follow through to overwriting others' objects, signed reads, executable/path/SSRF. For extension/Content-Type/parsing bypasses, adapt on-site to the stack.

### STS / Object Key Wildcard Overwrite (short table has pointer)

Recognize: object storage (BOS/OSS/S3/TOS type) requires requesting STS/presigned URL before upload; object key is often the file's md5; bucket names increment by date or batch. Or an assumerole-type credential-issuing endpoint, where `filename` / `Action` in the request gets used to assemble the Policy. The xluser / AES / `1.jpg` below are common facades, **wildcard attacks still apply without these words**.

Attack:

1. When the credential-requesting `identifier` / `key` / `object` / `prefix` / `filename` has **no length validation**, try `*`, `**`, then try **empty** and `/` (some implementations treat empty prefix = whole bucket)  
2. A single `*` may land in an empty bucket; **two or more** may hit the current business bucket, turning the credential `key` into a wildcard for the current bucket  
3. For path / `actionName` / path parameters assembled into the Policy, try `../../../`, `../../../&/../../`, see if the signed scope expands to root  
4. Others' object keys are often md5: open the document page, search JS/endpoints for `md5sum` / `md5`, no download or payment needed  
5. Use the just-obtained STS, set the upload path to that md5 of the other party, overwrite the object  
6. Fire another shot at assumerole: `filename=*-*` (or `*`), `Action=*`. Some implementations have **later Policy overriding earlier**, turning the key into the whole bucket. Once it works, first `list_objects`, then delete/overwrite the listed keys. **Don't stop at List/Delete 403**: do GET/PUT on arbitrary keys. Also try the credential-issuing XHR without a login header. **A sibling drive's anonymous ticket returning `illegal user id` doesn't mean this gateway rejects it too**: the STS endpoint where an anonymous xluser ticket passes the gate is still worth attacking. When query `upload_dir`/`dir` goes verbatim into the OSS Policy, fill in `*`. When the page goes through CDN, force-refresh or wait for cache expiry before verifying  
7. During PUT, try headers `x-cos-acl: public-read`, `x-cos-grant-full-control: id="your UIN"` (equivalent headers for OSS/S3 are the same). Only counts if the **object actually becomes public-read, or control transfers to your UIN**; a 200 alone doesn't count as takeover
8. When there's no "file exists" oracle, still guess short original filenames (`1.jpg`/`2.png`/`5.jpg`) and anonymously GET the CDN. If the token endpoint hardcodes AES/salt in the frontend, compute sign yourself without login; `filename=*` often directly returns appId+bucket, and assembling the CDN prefix lets you download **others' ID photos**  
9. **When the landing page hardcodes a supabase / nocode `role=anon` JWT, REST table CRUD is not the end.** With `apikey` + `Authorization: Bearer`, attack `POST /storage/v1/object/{bucket}/{official-prefix/probe-key}`. Official covers/case images are often under prefixes like `use-cases/`, `covers/`. First POST your own probe file; POST again with the same object name, adding header `x-upsert: true`, changing the body to a different marker string. Public `GET /storage/v1/object/public/{bucket}/{key}` compares the two bodies. **Do not actually overwrite official operational images**—being able to overwrite your own just-uploaded file in the same prefix means the official same-prefix objects can be overwritten too. After attacking, DELETE the probe file. Don't stop at REST `/rest/v1/` 403, storage REST is often separately open.
10. **When the credential-issuing endpoint is anonymously callable, don't bother with wildcards first (added 2026-09-22)**: when the `temp.secret`, `sts`, `getToken`-type XHRs that fire on upload/registration page load (visible at a glance in browser network) return credentials even without login, **just obtain the default credential as-is** and attack: false-value control (forged SecretId → `InvalidAccessKeyId`) → use the real credential to `PutObject` to the returned bucket (arbitrary key + custom Content-Type, also try nested paths) → anonymously GET the bucket domain to read back the written content and you're done. Parameterizing `filename`/`Action` wildcards is a supplementary shot, not a prerequisite. The returned bucket name may differ each time (multi-bucket rotation), attack according to that instance's `bucketName`.

Count as success: reopening/downloading **that document/image of the other party** shows content changed to what you uploaded; or listing others' keys and being able to delete/overwrite; or `x-upsert` on an official prefix overwriting your probe file with the second marker (same key for official objects in the same prefix); or anonymously-obtained default credential PutObject writing to an arbitrary key then **anonymous read-back on the bucket domain** (write-through is success, doesn't require List/Delete to also be open). Only proving you can upload to your own key → false positive.

False positives: `*` only signs a junk bucket; wildcarded but overwrite returns 403; changed your own object; policy hardcoded server-side can't be overwritten; only your own prefix works; CDN never refreshes so it looks like it wasn't overwritten; **anonymously-obtained credential is also rejected for PutObject (only a signature string with no usable permission)**. If a single site doesn't hit, don't remove this row from the short table.

Not the same as S3 presigned "change your own Content-Type", "signed URL change tenant to read others' files", or the below "bucket policy open to anonymous", "signature not bound to Host", "signature overrides Content-Type": this one is **credential scope wildcarded to the whole bucket, overwriting or clearing others' objects**.

### Signature Not Bound to Host (short table has pointer)

Recognize: COS / OSS / S3 signed URLs; query has `q-header-list`, `SignedHeaders`, `X-Amz-SignedHeaders` **without host**. Only attack if object storage with signing exists, otherwise don't waste time swapping domains.

Attack:

1. See which headers are signed in the signature parameters. Only proceed if there's no `host`.  
2. Swap the URL's host to the domain of **another bucket under the same account** (copy from cert SAN, errors, console, JS), leave path and signature query untouched for now.  
3. Then add `?uploads` (or `&uploads` after existing query) to attack ListMultipartUploads; also try GET on objects if possible.

Count as success: list or read objects in **another bucket**. If swapping domain still hits your own bucket → failed.

False positives: signature covers Host; swapped domain returns 403; only your own bucket. If a single site doesn't hit, don't remove this row from the short table.

Not the same as STS `*` (key scope wildcarded) or signed URL changing only the tenant field: this one is **Host not in signature, same signature can hit other buckets**.

### Signature Overrides Content-Type (short table has pointer)

Recognize: you control the object content (uploaded by you or overwritable via STS); the object's Content-Type is locked (image/jpeg type); you hold a temporary key or can generate a new presigned URL.

Attack:

1. Still fire the "change CT during upload" shot (`text/HtMl`, `text/html,image/png`). That's the "CT wasn't signed" case.  
2. **Re-sign after the fact**: use the temporary key to generate a GET for the **existing object** with `response-content-type=text/html` (COS/OSS support signature overriding response headers).  
3. Open this newly signed URL in a browser, don't just look at curl's Content-Type.

Count as success: browser executes it as HTML (stored XSS). Download is still attachment/original CT → failed.

False positives: signing endpoint rejects this parameter; can only modify your own unreachable object; `X-Content-Type-Options: nosniff` and CT is still an image. If a single site doesn't hit, don't remove this row from the short table. Without object storage or a temporary key, don't waste shots signing.

Not the same as "change Content-Type during upload PUT": that one changes the type **at write time**; this one is **using a signature at read time to override the response header to HTML**.

### webpack Plaintext Object Storage Permanent Keys (short table has pointer)

Recognize: admin console / operations backend webpack bundles production `accessKeyId`+`secretAccessKey` (MSS / S3 type permanent keys) into JS. Or Weblogic `/console/login/LoginForm.jsp` inlining `SRV_` keys like `_reportCfg`. Upload signing `getUploadSign` is frontend HMAC-SHA1 computing the policy, not going through a post-login STS endpoint. In the policy, `starts-with $key` is often an empty string.

Attack (no login):

1. Copy the online/prod AK/SK (real values only go in the report)  
2. Compute the POST policy yourself, extend expiration, keep `starts-with $key` exactly as in JS (empty stays empty)  
3. POST the bucket: control with fake signature `SignatureDoesNotMatch`, no signature `conditions has no signature`  
4. PUT to arbitrary key then CDN GET; DELETE your just-uploaded file to prove the key can write. Try overwriting objects already referenced by official pages  
5. Don't stop at List/PUT 403: first `GetBucketLocation`. Control with fake AK `InvalidAccessKeyId`. If the page's bucket name is misspelled (staic/static), try neighbors  

Count as success: complete permanent cloud key can sign (real signature PUT 200 or GetBucketLocation returns region). Being able to overwrite existing official objects is stronger.

False positives: InvalidAccessKeyId; can only upload to a fixed prefix; getUploadSign is actually an SSO endpoint with no local key; key expired. Real key values don't go into the DB. If a single site doesn't hit, don't remove this row from the short table.

Not the same as STS wildcard (request temporary ticket first), bucket policy open to anonymous (no key needed), or viewer XOR hiding COS permanent key (need to decode then ask AccountId): this one is **webpack plaintext permanent key + frontend computes signature itself**.

### Bucket Policy Open to Anonymous (short table has pointer)

Recognize: official site/console images, usage guides, agreements are hosted directly on OSS / cloudrun-type bucket domains; bucket root or `?policy` / GetBucketPolicy / equivalent policy endpoint can be opened up, statements are full Allow.

Attack:

1. View the policy if possible; then do LIST on the bucket (no AK)  
2. Try PUT/overwrite on **objects already referenced by the official site** (don't modify the bucket policy itself)  
3. Prioritize guides, agreements, site images; after overwriting, open with the original official URL to verify  

Count as success: the content of that official guide/agreement/image changed to what you uploaded. Only proving anonymous LIST, or only uploading to a new key nobody references → false positive.

False positives: policy read-only can't write; PUT can only land in your own prefix; what you downloaded was already a public static page. If a single site doesn't hit, don't remove this row from the short table.

Not the same as STS `*` (need to request credentials first, key wildcarded), filename `../` traversing tenant directories, or Azure container-level SAS: this one is **bucket policy open to anonymous, no credentials needed**.

### Storage Proxy sign key=/ (short table has pointer)

Recognize: business gateway proxies object storage as `/api/storage/sign` (or similar sign), query only takes `key`. `key=/` or `key=.` returns S3 `ListBucketResult` XML, not a STS request.

Attack (no login):

1. GET `?key=/` (then try `.`). Control: random key should give `NoSuchKey` / 400  
2. Copy business prefixes from the list (`images/`, `editor-` type) then GET the same endpoint  
3. See if the objects are non-public materials, don't stop at official-site banners  

Count as success: list and read the raw content of others' non-public objects.

False positives: only app-static public statics; `filename=` 400 mistaken for no endpoint. If a single site doesn't hit, don't remove this row from the short table. Not the same as STS wildcard (obtain key first) or bucket policy open to anonymous (attack bucket domain directly): this one is **the business gateway itself acting as List/Get proxy**.


### Artifact Download Detail Uses Presence of uin as Login Gate (short table has pointer)

Recognize: software/private cloud/materials download center; detail JSON has `DownloadURL`; frontend copies `uin`/`skey` from Cookie to assemble query. With empty identity, URL is an empty string and the page redirects to login.

Attack: GET the detail without login, fill the identity field with a non-empty fake value (`uin=1`), no skey. Control with empty uin. Range GET the first few dozen bytes of the returned signed URL to check for ELF/PK.

Count as success: real file of private cloud installer/internal deployment doc. If empty uin also returns a URL → completely unauthenticated (a different finding). Signed 403 / only public manuals → failed.

### Onboarding JS Hardcodes fileKey (short table has pointer)

Recognize: onboarding/qualification SPA bundles JS with mock or demo formData hardcoding a long encrypted `fileKey`. Site root 301s to a new domain, **the old host's download endpoint may still be alive**. Don't discard the mock as a placeholder, and don't treat the 301 as the whole site being dead.

Attack (no login):

1. Follow the new domain's chunk to copy `fileKey`  
2. Attack the old host `/json/view/file/downloadFile?fileKey=` (or similar)  
3. Control: random fileKey should be empty/error, real key returns an image  

Count as success: actually download the original license/ID image from the private bucket.

False positives: treating the 301 new domain as whole site dead; mock fileKey as a placeholder and random filling also returns the same image. If a single site doesn't hit, don't remove this row from the short table. Real key values and complete JS don't go in this article.

### Share Auth false Still Downloads Media (short table has pointer)

Recognize: cloud recording share; auth endpoint has `download_enable`/`view_minutes_enable`. Or the meeting JSON gateway has no `permission/auth` at all (don't stop at 404).

Attack (no login):

1. Attack both `download-multi-record-file` **and** `sign-multi-record-file` (need `auth_share_id`+`resource_type`). The international JSON gateway missing `sharing_id` only returns `2710500 invalid parameter`, `auth_share_id` and `sharing_id` must be sent together to issue MP4; missing them makes it look like no bug. **Don't stop when POST JSON reports "recording id cannot be empty"; switch to GET query, putting record_id / auth_share_id in the URL.**  
2. If there's no auth endpoint, don't treat it as no entry: directly attack `public/record-detail/download-multi-record-file`.  
3. For summary/timeline `get-full-summary` / `query-timeline`, also try filling only `record_id`, don't assume share must be included.  
4. A COS 403 with no Referer **is not the end**: GET again with the share page's Referer.  
5. `permission/get-cfg` see if it leaks other records from the same meeting.  
6. Only getting the URL but no MP4 via GET counts as half a finding, keep following.  

Count as success: auth written as false still pulls real MP4 (ftypisom+size); or just record_id returns the full summary text (not just the title).

False positives: auth actually blocks, can't download the file; only public manuals; summary only has title without body. If a single site doesn't hit, don't remove this row from the short table.

### Password Share Response Contains Plaintext Extraction Code (short table has pointer)

Recognize: share detail JSON on one side has `need_pwd` / `auth_level` (or similar) indicating an extraction code is required, while the auth object puts the plaintext extraction code in `pass_word` (or similar). Or the landing HTML / `syncData` inlines the same plaintext code.

Attack (no login):

1. First attack the view endpoint with empty extraction code. Control: file list should be empty, gate field should require code.  
2. Copy the plaintext code from the same response, fill it back into the view endpoint. Control: empty code → empty list, filled → `file_id` appears.  
3. **If the landing HTML / `syncData` already has plaintext `pass_word`, just copy it directly**, no need to hit View CGI first.  
4. Use `file_id` and this code to attack the download endpoint, follow through to the real file header (PDF/ZIP type body), don't stop at JSON having the code.

Count as success: obtained the extraction code and downloaded the password-share body, not empty code directly returning a file list.

False positives: `pass_word` is a hash that can't be used when copied; empty-code View already returns files (that's a share without extraction code, not this shot). If a single site doesn't hit, don't remove this row from the short table.
Real key values and complete JS don't go in this article.

## temp Upload Without Whitelist + HTML Hosting on Same Domain (short table has pointer)

**Form**: business upload endpoint (photos/materials) is on the interceptor's anonymous whitelist, layui frontend `exts: 'jpg|jpeg'` is frontend-only behavior, server doesn't validate extensions; landing directory is under the app's own static prefix (e.g. `/cdn/data/temp/<uuid>.<ext>`), directly GETtable on the same domain.

**Attack method**:
1. Without login, multipart direct-upload `.txt` to probe server-side filtering (accepted = no whitelist).
2. Then upload `.html`, GET the landing path to check `Content-Type`: `text/html` inline rendering = **phishing page hosting on official domain** (a more valuable characterization than arbitrary file read).
3. Upload `.jsp/.jspx` to verify whether it's parsed (upload succeeds but GET 404/raw bytes = not parsed, no RCE, report honestly).
4. Note whether rate limiting/capacity/expiry mechanisms exist; UUID renaming of files = can't overwrite others' files.

**Pass threshold**: 200 text/html rendering of your uploaded page under the official domain (phishing hosting established).
**Fail**: upload endpoint requires login; server rejects non-image extensions; landing forced download as octet-stream.
