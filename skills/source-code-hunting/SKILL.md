---
name: source-code-hunting
description: Use when target source code or a repository is available (white-box or leaked source) for code audit — dangerous sink location, framework pattern recognition, git history mining, dependency CVEs, semgrep/gitleaks usage and the path from code to exploitability verification.
tags:
  cwe: [CWE-89, CWE-78, CWE-502, CWE-22, CWE-798, CWE-287]
  attack: [T1552.001, T1213]
  class: [whitebox, code-audit, sast, secrets]
---

# Source Code Audit Methodology

## Do three things first (10x faster than reading line by line)

1. **Survey the repository**: language/framework/entry files/route table/dependency manifests (pom.xml/package.json/go.mod/requirements.txt);
2. **Find secrets**: `gitleaks detect --source . -v`, `semgrep --config p/secrets`; `.env`/configs/hard-coded AK;
3. **git history**: `git log --oneline --all | head -50`, `git log -p -- .env` (keys that were deleted and re-committed are still in history).

## Sink-driven audit (work backwards from dangerous functions to inputs)

| Type | Language | Sink keywords |
|---|---|---|
| SQLi | Java/PHP/Py/Go | `Statement.execute*`, `${}` concatenation, `db.Raw`, `cursor.execute(f"` |
| Command injection | all | `Runtime.exec`, `ProcessBuilder`, `os.system`, `subprocess(...,shell=True)`, `exec.Command("sh","-c"` |
| Deserialization | Java | `ObjectInputStream`, `readObject`, Fastjson `JSON.parse*`, XStream |
| SSRF | all | `http.Get(req.Param`, `requests.get(`, `urllib`, `new URL(input)` |
| Files | all | `../` concatenation, `os.path.join(base, user)`, `FileInputStream(user)`, `sendFile` |
| Template injection | Java/Py | `Template.process`, `render_template_string`, `new Template(input)` |
| IDOR | all | querying the database directly with the request id (no owner check), `findById(param)` without comparing the current user |

## Framework patterns (common in domestic stacks)

- RuoYi: missing `@PreAuthorize`, `/common/download?fileName=` (path traversal), SQL injection in the `gen` module;
- Spring Boot: `@RequestMapping` wildcards, exposed Actuator, SpEL injection points (`#{...}`);
- ThinkPHP: `input()` straight into `whereRaw`, `invokeFunction`, LFI via the multi-language `lang` parameter;
- JeecgBoot: `/jmreport/*`, Freemarker template injection, `queryTableData` SQL;
- Laravel: `unserialize`, `.env` exposure, `Debugbar`;
- Django: `raw()`/`extra()`, `mark_safe`, `DEBUG=True`.

## From code to exploitability

1. Confirm the entry point is reachable (is it blocked by a route/auth filter);
2. Confirm the parameter is controllable (who passes it in, is there validation);
3. Start the service locally to verify, or construct a request identical to production (`http_probe`/curl against the real target);
4. Code-level evidence + actual response = high confidence; code inference only → medium at most, marked "code audit, unverified".

## semgrep / dependencies

- `semgrep --config auto .` for quick volume; focus on high-confidence items;
- Dependencies: `mvn dependency:tree`/`npm audit`/`gosum` + `search_vulns` version matching;
- Dependency hits also need behavioural verification (version match ≠ vulnerability).

## Output

- For each candidate, write a fact: file:line, sink, input source, reachable or not, verification status;
- Once confirmed, `report_finding` evidence includes the code snippet + the actual request/response;
- Fix recommendations should be function-level (parameterization/allow-list/encoding).
