# Knowledge base index

Field methodology / test checklists / scenario matrices. Used together with the `SKILL.md` flow.

## Usage conventions

- On entering a site read `breakthrough-short-table.md` first; if it matches, open the matching module for details. If the file is short, open it whole; for very long ones open the named section first and continue if it is not enough. Reading this whole directory at every site is forbidden
- Only open a dedicated article if `*src-experience.md` exists on disk; its absence is not a deficiency. Opening `SKILL.md` no longer drags in the group diary
- The short table and "injection/SSRF/XSS/RCE" are not ceilings. Cover the full type matrix on this site; hit the four pieces on surfaces with a differential (to avoid gaps), but that is neither "test only these four classes" nor "spray `'` on every path". With a session, IDOR/logic is as hard as the four pieces (`dig-scope` §4.2.3)
- Convenience and capability first; saving tokens is a side effect and must not block opening modules
- Search short-table-named techniques by heading. Fat articles that have pointers keep only the field write-up + pointer section; articles that are forbidden to open / almost never submitted have been collapsed to one line. Technique rows are not deleted and the success criterion is not lowered.
- In-article jumps have been changed to real files in this directory (`idor-test.md` and the like); do not follow `../xxx/SKILL.md` any more
- On conflict with `~/.grok/rules`, **rules win** (what to hunt `src-value`; CORS not hunted `cors-vuln-report-priority`; whether to write `vuln-report-format`)
- **`cors-test.md` / `llm-security-test.md`: not hunted / do not open the jailbreak material.** `401-403-bypass.md` does not grind login HTML.
- Formal SRC reports: `~/.grok/rules/vuln-report-format.md`

## File list

| File | Notes |
|------|------|
| `breakthrough-short-table.md` | Hunting technique index (one line/pointer; the body stays in the modules) |
| `401-403-bypass.md` | **Do not open to grind login HTML** (collapsed to one line); hit business API 401 on the spot yourself |
| `api-gateway-test.md` | API gateways |
| `agent-tool-exec-test.md` | Real tool execution from a chat endpoint (not jailbreak, not cloud IDE RPC) |
| `authbypass-test.md` | Authentication bypass (unauthenticated password change/IDaaS + short-table pointers; the English dictionary has been cut) |
| `cache-poisoning-test.md` | Cache poisoning/deception (original + supplements) |
| `clickjacking-test.md` | Missing headers are not written up (collapsed to one line) |
| `cloud-ide-codex-rce-chain.md` | Cloud IDE/Codex family: weak password → RPC RCE → cluster/API Key chain (short-table pointer) |
| `cors-test.md` | **Not hunted, do not open** (collapsed to one line) |
| `crlf-injection-test.md` | Almost never submitted (collapsed to one line) |
| `csp-bypass-test.md` | Almost never submitted (collapsed to one line); XSS goes through `xss-test.md` |
| `csrf-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `csv-formula-injection-test.md` | Almost never submitted (collapsed to one line) |
| `dangling-markup-test.md` | Almost never submitted (collapsed to one line) |
| `dependency-confusion-test.md` | Almost never submitted (collapsed to one line) |
| `deserialization-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `dns-rebinding-test.md` | Almost never submitted (collapsed to one line); SSRF goes through `ssrf-test.md` |
| `el-injection-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `email-header-injection-test.md` | Almost never submitted (collapsed to one line) |
| `file-upload-test.md` | File upload (STS/bucket listing/share authz pointers) |
| `ghost-bits-cast-test.md` | Ghost Bits principle + common characters + formulas; the two per-byte tables have been cut |
| `graphql-test.md` | GraphQL (original + supplements) |
| `hpp-test.md` | Almost never submitted (collapsed to one line) |
| `http-host-header-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `http-smuggling-test.md` | Request smuggling (original + supplements) |
| `http2-attacks-test.md` | Almost never submitted (collapsed to one line); smuggling goes through `http-smuggling-test.md` |
| `idor-test.md` | IDOR (main thread + short-table pointers) |
| `info-leak-test.md` | Information disclosure |
| `injection-test.md` | Injection (OR+total / email subscription iframe / SSTI detection; the English encyclopedia has been cut) |
| `insecure-scm-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `jndi-injection-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `js-reverse-guide.md` | JS reversing |
| `llm-security-test.md` | **Do not open the jailbreak material** (collapsed to one line); for chat tools go through `agent-tool-exec-test.md` |
| `logic-test.md` | Business logic (payments/flows + merchant promotion binding) |
| `oauth-jwt-test.md` | OAuth/JWT/SAML/OIDC (original + multi-source supplements) |
| `open-redirect-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `path-traversal-lfi-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `prototype-pollution-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `race-condition-test.md` | Races (original + supplements) |
| `recon-methodology.md` | Recon methodology |
| `ssrf-test.md` | SSRF (IMDS path differences / GOPROXY / object-storage origin fetch) |
| `subdomain-takeover-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `type-juggling-test.md` | Topic knowledge (imported or merged from hack-skills) |
| `waf-bypass.md` | WAF bypass |
| `websocket-test.md` | WebSocket (original + supplements) |
| `xslt-injection-test.md` | Almost never submitted (collapsed to one line) |
| `xss-test.md` | XSS (opener + obscure events + XSS→RCE / custom protocols) |
| `xxe-test.md` | Topic knowledge (imported or merged from hack-skills) |

**Total: 48 knowledge files** (excluding this README). The SRC report layout is not in this library: see `~/.grok/rules/vuln-report-format.md`. Severity grading is governed only by format; this library does not grade.
