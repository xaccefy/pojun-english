> Whether to write it up is decided only by `~/.grok/rules/vuln-report-format.md`. This piece tests: version/framework/health/no-credential shell/fingerprint → continue digging for full credentials, keys, cross-entity business data. For copied credentials/cloud keys/tokens: must have a fake-value control, confirm the key proves out identity or a list, then hit a read-only instance that doesn't affect production before submitting; phone numbers plus decryption keys are not written up.
> Structure: this piece is short, can be opened in full. Middleware ports are attacked only when seen (§5), don't scan ports on every site first.

# Information Disclosure Testing Manual

## I. Common Disclosure Points

### 1.1 Excessive fields in API responses

```bash
# Test whether login/user-info APIs return sensitive fields
curl "https://target.com/api/user/info" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Fields to watch:
# password, passwordHash, salt
# idCard, bankCard, realName
# phone (not masked), email
# secretKey, apiKey, token
# internal fields: is_admin, role, balance_internal
```

### 1.2 Error message disclosure

```bash
# Send malformed requests to trigger errors
curl "https://target.com/api/user?id='"
curl "https://target.com/api/user?id[]=1"

# Watch the response for:
# Database errors (SQL statements exposed)
# Stack trace (code paths exposed)
# Internal IP addresses
# Framework/version information
```

---

## II. File/Directory Disclosure

### 2.1 Common sensitive paths

```bash
# Leftover development files
/.git/config
/.git/HEAD
/.svn/entries
/.DS_Store
/.env
/.env.local
/.env.production
/config.php
/config.yml
/application.properties
/application.yml
/web.config

# Backup files
/index.php.bak
/index.php~
/backup.zip
/backup.tar.gz
/www.zip
/site.tar.gz
/db.sql
/database.sql

# API docs (may leak the API list)
/swagger-ui.html
/api-docs
/v2/api-docs
/swagger.json
/openapi.json
/doc.html
/redoc

# Monitoring/ops endpoints
/actuator
/actuator/env
/actuator/mappings
/actuator/beans
/metrics
/health
/info
```

### 2.2 Automated scanning

```bash
# ffuf batch detection
ffuf -u "https://target.com/FUZZ" \
  -w sensitive_paths.txt \
  -mc 200,301,302,403 \
  -t 30 -o leaks.json -of json

# Filter 403s from ffuf results (may have content but blocked, worth digging into)
cat leaks.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data['results']:
    print(f\"{r['status']} {r['url']} ({r['length']} bytes)\")
"
```

---

## III. JS File Information Disclosure

```bash
# Extract sensitive info from JS files
# After downloading all JS, search:
grep -rE "(apiKey|api_key|secret|password|token|ak|sk)\s*[=:]\s*['\"][^'\"]{8,}" *.js

# AK/SK leakage (cloud service credentials)
grep -E "AKID[A-Za-z0-9]{16,}" *.js       # cloud vendor AK prefix
grep -E "LTAI[A-Za-z0-9]{16,}" *.js       # cloud vendor AK prefix
grep -E "AKIA[A-Za-z0-9]{16,}" *.js       # AWS
grep -E "[a-zA-Z0-9+/]{40}=" *.js         # suspected Base64 key

# GitHub PAT (docs/community sites often bundle contributor-plugin keys)
grep -oE "ghp_[A-Za-z0-9]{20,}" *.js
grep -oE "github_pat_[A-Za-z0-9_]{20,}" *.js

```

### 3.1 GitHub PAT on documentation sites

Open-source docs/community frontends, to pull GitHub org, contributors, and star counts, often bundle `ghp_` / `github_pat_` into the packaged JS.

Copy it from the JS without logging in:

```bash
curl -s "https://api.github.com/user" -H "Authorization: token $PAT"
# Control: without the header it should return 401
curl -s "https://api.github.com/user/repos?affiliation=owner&per_page=5" -H "Authorization: token $PAT"
```

Counts as: "me" is a real person's login/name, and `permissions.admin=true` on that account's repo (can act as this GitHub account). Even if official org repos only have pull, still write the personal-repo admin into the impact.

False positives: key revoked; `/user` returns 401; it's only a GitHub App installation token reading a public org. Real key values go only into the formal report, not this piece.

### Viewer JS XOR-hidden object storage permanent key (short table has a pointer)

Recognize: landing page/viewer JS has `usePrivateCode` (or a similar function name), `COS_TOKEN`'s SECRET_ID/SECRET_KEY isn't a plaintext AKID. Encoding: the first 16 characters are a repeating XOR key, the following hex block decodes to the permanent AK/SK. Grepping only for `AKID` would make you think there's no key.

Attack (without login): after decoding, sign `cloud STS API` **GetCallerIdentity**, then `cloud CAM API` **GetUserAppId**. Don't stop at a ListBuckets 403.

Counts as: AccountId/Uin/AppId obtained. A long-term key, not a temporary token expiring in a few minutes.

False positives: decoded key calling the cloud API returns AuthFailure; `exampleValue` decodes to a `hello_world` placeholder. Real key values go only into the formal report, not this piece. If a single site doesn't hit, don't delete this row from the short table.

### Admin console JS hardcoded CI repo key (short table has a pointer)

Recognize: admin console frontend JS hardcodes CI's `pipelineId` + base64 `auth`, and there's an unauthenticated trigger endpoint.

Attack (without login): copy the auth and call `Git hosting open API` open-api `DescribeMyDepots`; the site's own trigger is only a control.

Counts as: listing another team's private repo names/HttpsUrl/ProjectId, or the key's scope includes `depot_read` and the open API accepts the key.

False positives: key expired; repo is public; only the trigger returns "product offline" with no proof the key can still list private repos. Real key values go only into the formal report, not this piece. If a single site doesn't hit, don't delete this row from the short table.

### Real ID-document samples in documentation chunks (short table has a pointer)

Recognize: open-platform documentation center; page document/category endpoints return 401; the entry script has DocPage's dynamic `import()` of `technical-document` (or a similar doc chunk). Not the "debug docs hardcode AppSecret" row.

Attack (without login): don't stop at the doc API 401. Follow the homepage script → DocPage `import()` → doc chunk. Extract ID card numbers, phone numbers, and names from sample request/response messages. Only continue if they pass the checksum.

Counts as: a checksum-valid ID card + name/phone that match a real person.

False positives: "Zhang San"/110101 placeholders; fabricated numbers with wrong checksums; empty `appliIdNo` templates; only public product manuals with no sample messages. If a single site doesn't hit, don't delete this row from the short table. Real ID values go only into the formal report.

### Connection config inside an anonymous signed-download package (short table has a pointer)

Recognize: enterprise software center opens to a login page; alternatively there's a signed object-storage download endpoint that doesn't require cookies; or the same site's `/download/` + software filename doesn't require cookies; the archive contains Navicat `ncx` files (connection name, Host, account, `SavePassword` ciphertext). When the homepage 302s to a login wall, **the signing function inlined in the 302 response body also counts as an entry point**, don't just look at the landing login page.

Attack (without login): use the signing endpoint to get the signed URL, then Range GET the real zip. **If there's no signing endpoint / it requires login, don't stop**: take a filename from the 302 body or homepage software list and directly `GET /download/{filename}` on the same site (random filenames often 302 back to the homepage; only the correct name returns 200). Extract `*.ncx`. Decrypt Password with Navicat 12's fixed key `libcckeylibcckey` and IV `libcciv libcciv` using AES-128-CBC, then strip PKCS7.

Counts as: internal DB Host + account + decrypted plaintext password. Real key values go only into the formal report.

False positives: the package contains only a public client with no connection config; ciphertext won't decrypt. If a single site doesn't hit, don't delete this row from the short table.

### Distributed file system master unauthorized user keys (short table has a pointer)

Recognize: public HTTP `/version` returns `"Model":"master"` (distributed file cluster). The admin interface doesn't require login.

Attack (without login):

1. `GET /user/list` to get `access_key`+`secret_key`
2. Control: a fake 16-char ak hitting `GET /user/akInfo?ak=` should return `access key not exists`; a real ak reveals `user_id`/user_type
3. `GET /admin/getVol?name=` to view another user's business volume (Owner / InodeCount)

Counts as: complete AK/SK and the real key reveals identity/another user's business volume.

False positives: only version/cluster name returned, no keys; empty list; real and fake keys return the same message; only your own empty test volume. Real key values go only into the formal report, not this piece. If a single site doesn't hit, don't delete this row from the short table.

```bash
# Internal address leakage
grep -oE "192\.168\.[0-9]{1,3}\.[0-9]{1,3}" *.js
grep -oE "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" *.js
grep -oE "172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}" *.js
```

---

## IV. Special Endpoint Disclosure

### 4.1 Pagination boundary bypass

```bash
# Use a large page number to get all data
?page=99999&pageSize=1000
?offset=0&limit=99999

# Export endpoints without quantity limits
/api/export/users?format=csv
/api/export/orders?startTime=2020-01-01&endTime=2026-01-01
```

### 4.2 Search endpoint wildcards

```bash
# Fuzzy search to get all data
?keyword=%         # URL-encoded %, SQL LIKE wildcard
?keyword=*
?keyword=.         # some systems
?q=               # empty search returns everything
```

### 4.3 GraphQL introspection

```bash
# GraphQL endpoint leaks schema
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# If the full schema is returned → may leak undisclosed endpoints and fields
```

---

## V. How to Attack Middleware Ports When You See Them

> **Attack only when seen.** Don't nmap all ports on every site first. Only when FOFA/entry/response headers have already exposed these ports or consoles, follow the table. Once broken through, write up per `vuln-report-format`; for health/version shells, keep chasing credentials, don't stop at PONG.

| What you see | Where to attack | What counts as success | False positives / where to pivot |
|--------|------|------------|-------------|
| `:6379` Redis, no password `PING`→`PONG` | Write webshell / crontab / `authorized_keys` (directory must be the real web root or cron). For SSRF reaching this port use `gopher://`, see `ssrf-test.md` | Commands execute, or business DB is read | Has `requirepass`; `CONFIG` renamed; only `PING` works |
| `:873` rsync anonymous `rsync host::` lists modules | Download business files; if a module is writable, check whether cron can be written | Pulled keys/business data | Empty modules; read-only and all public static files |
| `:9000` PHP-FPM/FastCGI directly exposed | FastCGI packet against an existing `.php` (`PHP_VALUE=auto_prepend_file=php://input`). For SSRF use gopherus fastcgi | Specified PHP executed | Unix socket only, external 9000 isn't FPM |
| `:8009` AJP | Ghostcat to read `/WEB-INF/web.xml`. See `path-traversal-lfi-test.md` §21 | Read web.xml / class | `secretRequired`; port isn't AJP |
| `:8088` Hadoop YARN UI | `POST /ws/v1/cluster/apps/new-application` then submit an app with `commands` | Your command ran in the cluster | Only a UI login wall; submission 401 |
| `:2375` Docker API | `GET /v1.24/containers/json`; if create works, mount `/:/host` | Listed containers or read host files | TLS 2376 without client cert; only version |
| `/h2-console` | JDBC URL JNDI or `CREATE ALIAS`. See `jndi-injection-test.md` "H2 Console" | Commands execute | Only openable locally |

Attacking the public interface directly and attacking the internal network via SSRF are the same set of sinks; only the entry point differs. If these ports aren't present, don't scan just for the sake of this table.
