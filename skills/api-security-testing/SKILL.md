---
name: api-security-testing
description: Use when an endpoint inventory, traffic or APIs found in frontend JS are available and API security testing is needed — contract extraction (api_contract), two-identity comparison (auth_request), response diffing (diff_responses), and verification paths for authorization bypass/unauthenticated access/parameter pollution. Use when the intent involves "test an API / authorization bypass / unauthenticated access / API".
tags:
  cwe: [CWE-639, CWE-862, CWE-306, CWE-284, CWE-915]
  attack: [T1190, T1078]
  class: [api-security, idor, broken-authz, contract, differential]
---

# API Security Testing (built around the platform's three endpoint tools)

## How the platform tools fit together

| Tool | Purpose |
|---|---|
| `api_contract` | Extract the endpoint contract from frontend JS / traffic (path/method/parameters/whether auth is required) |
| `auth_request` | Assemble an authenticated request command using **credentials already registered on the asset** (it only builds the command; Bash executes it) |
| `diff_responses` | Compare the structure/field differences of two responses (the criterion for IDOR and information leaks) |

## Flow

1. **Build the contract inventory**: `api_contract` extracts endpoints; without a frontend, add them by hand from traffic/JS;
2. **Classify and tag**: public / login-required / privileged / internal (judge from response characteristics and the JS call context);
3. **Two-identity comparison**:
   - Identity A (low privilege / no credentials) → identity B (another account or registered credentials);
   - Request the same resource as each, then use `diff_responses` to see whether the data is identical / whether fields leak;
4. **Verify four defect classes**:
   - Unauthenticated access: 200 with business data and no token;
   - Horizontal IDOR: A's token reads B's object;
   - Vertical escalation: a low-privilege account hits a high-privilege endpoint (returns 200, or is only hidden in the frontend);
   - Parameter pollution / mass assignment: send extra `role/isAdmin/tenantId/userId` and see whether they are accepted.

## Decision criteria (for reports)

- **L3 evidence**: the response bodies differ between identities (including another person's data fields), or business data is obtained without authorization;
- A 200 with no business data → not IDOR; at most record "the endpoint exists";
- Hidden in the frontend ≠ validated in the backend: you must call the endpoint directly to confirm;
- In the `diff_responses` result, point out the specific differing fields (timestamps/IDs/names etc.); do not just say "there are differences".

## Common bypasses

- Path: `/api/v1/user/1` vs `/api/v1/user/1/` (trailing slash), case, `//`, `%2e`;
- Method: swap GET↔POST, `X-HTTP-Method-Override`, OPTIONS to probe Allow;
- Parameter location: try query↔body↔header all three (many backends validate only one);
- Bulk/paging: `size=1000`, `page=0`, `fields=*`, `expand=all` to pull the full set;
- Signature/timestamp: parameter ordering, empty values, replay inside the time window (see whether the server only checks for non-emptiness).

## Traffic and evidence

- Confirm every verification request is recorded by the MITM proxy (every HTTP request gets a traffic ID);
- `report_finding` binds both traffic kinds: baseline (normal request) / proof (escalated request);
- Take only the minimum sample of sensitive data (one record); no bulk pulling.

## Division of labour with recon

- Endpoint **discovery** belongs to `api-recon` (frontend routes/JS/parameters); this skill handles **verification** once you have the inventory;
- `record_fact` any new endpoint/parameter you stumble on, for later intents to reuse.
