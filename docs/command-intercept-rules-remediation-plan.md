# Command Intercept Rule Review and Remediation

> First review 2026-10-21; redone 2026-10-22 against the **actual state of the code**.
> Goal: truly separate "outright forbidden" from "hand to the Agent for judgement" at the **rule layer**,
> and fix the misleading bug where "the timeout fields on a rule are dead fields".
> **The core intercept architecture is untouched** (still rules → judge → allow/ask/deny three branches).

---

## 1. Review conclusions (including one important self-correction)

### The first version's premise was wrong

The first review (2026-10-21) said "21 built-in rules: 20 judge + 1 deny". **That is not the case**:

| | What the first document said | Actual state of the code |
|---|---|---|
| Built-in rule count | 21 | 22 (including v3 delete-endpoint paths and v4 listener) |
| Action distribution | 20 judge + 1 deny | **All deny** (21 deny + 1 ask) |

The basis is not memory, it is **the code**: in the four seed functions in `db/db.go` (`seedDefaultInterceptRules`
V1/V2/V3/V4), every rule's `action` is hardcoded to `deny` (v4's listener is `ask`).
The ARTEX-upstream snapshot is all deny as well.

This correction matters because it flips the whole conclusion: it is not "rules were mistakenly set to judge, causing false positives",
but rather **"the rule layer decides every category of call, so the model never gets a chance to look at these commands"**.

### Historical lesson (commit 39d5516, 2026-10-20)

Historically the 21 rules on the test machine were manually **changed to judge wholesale** and run against a real task, which exposed three problems:

1. **Verdicts failed 100% of the time** — the verdict request hardcoded `thinking.type=disabled`, so a model like MiniMax-M3.1
   that forces adaptive thinking returned 400 immediately. **Fixed** (no longer sends the thinking field).
2. **Failure policy was allow** — a dead model silently letting things through = the gate wide open. **Fixed** (changed to ask).
3. **Rule false positives blocked legitimate probing to death** — 11 real calls were denied outright. **Fixed** (narrowed the patterns of
   two rules and left a regression baseline at `db/intercept_rule_fp_test.go`).

So "change everything to judge" **has already been tried once and left scars**. This remediation is not
repeating that mistake; it layers things on **the already-fixed basis**, with justification.

### Problems that still exist

| # | Severity | Problem | Consequence |
|---|---|---|---|
| **P0** | High | `timeout_enabled` / `timeout_seconds` / `timeout_action` on a rule **are dead fields** — only stored and read by CRUD; the verdict path (`intercept.judge()`) never reads them | The UI shows every rule as "timeout 60s / deny on timeout" while what actually applies is "global 180s / ask". **What the user sees differs from what happens**, which is worse than not having the field at all |
| **P1** | High | All rules deny uniformly, so "outright forbidden" and "hand to the Agent for judgement" are not separated at the rule layer | A legitimate operation like "drop the test table I created" is blocked outright and the task is interrupted; and the model's verdict capability (the prompt is written out in full) **is never used by the built-in rules** |
| **P2** | Medium | The "data exfiltration pipe" rule is **disabled** by default, and its pattern false-positives on normal callbacks (`curl target \| nc your own callback listener`) | It doesn't stop what it should (POSTing credentials out) and tries to stop what it shouldn't |
| **P3** | Low | `rm -rf <any path>` can only be caught by the fallback judge | Depends on the LLM being available; a flaky model lets it slip |

---

## 2. Remediation plan

### A. Draw the line between "outright forbidden" and "hand to the Agent for judgement"

The criterion uses **two axes**, consistent with the verdict prompt (`intercept/prompt.go` D1–D6 / A1–A6):

```
irreversibility × what it acts on
```

- **Irreversible AND the object is context-independent** → **outright forbidden** (`deny`, no model call)
- **Irreversible BUT the object depends on context** → **hand to the Agent for judgement** (`judge`)
- **Unrelated to the target asset, only changes the platform itself** → **human confirmation** (`ask`)

"Outright forbidden" is defined **conservatively**: it must be irreversible in **any** context and have no legitimate pentest use.
Merely "usually dangerous" does not justify a hard ban — a hard ban removes the ability to verify vulnerabilities such as "unauthorized deletion".

> Note: the seeded built-in rule names are Chinese in the source (e.g. `[Built-in] Disk formatting mkfs`, `[Built-in] Data exfiltration pipeline`, `[Built-in] Start/stop connect-back receiver`); they are translated below for readability.

#### A1. Outright forbidden (10 rules, `deny`)

| Rule | Reason |
|---|---|
| Disk formatting mkfs | Formatting any block device is irreversible; testing doesn't need it |
| Overwrite disk device dd of=/dev/X | Same as above |
| Disk wipe shred / wipe /dev/X | Same as above |
| Fork bomb | Inevitably takes the host down; no legitimate use |
| Kill every process kill -9 -1 / killall -9 | Irreversibly interrupts every service; testing doesn't need it |
| Flush firewall rules iptables -F / nft flush | Wipes the host security policy; unrelated to the target asset |
| Shutdown / reboot (system level) | Interrupts the host and all tasks (verdict D5) |
| Redis FLUSHALL / FLUSHDB | Flushes the entire cache/persistence set |
| SQL DROP DATABASE / SCHEMA | The whole database/structure is irreversible; DROP TABLE is enough to verify injection |
| Emptying system critical directories | A host critical directory tree is emptied, which necessarily destroys the host |

#### A2. Hand to the Agent for judgement (12 rules, `judge`)

Recursive forced deletion rm -rf, deleting system critical directories, SQL DROP TABLE/INDEX/VIEW, SQL TRUNCATE,
MongoDB drop, curl/wget DELETE, Python HTTP client DELETE, DELETE declared in a script,
bulk flush/clear endpoint paths, delete-class endpoint paths, destructive system commands (catch-all), data exfiltration pipe.

**Reason**: the object being deleted/changed **depends on context** — it may be the test table this run created
(legitimate cleanup) or production data (destructive, corresponding to D4). The verdict policy's literal examples are exactly
`rm -rf /var/www/html`, `DELETE /api/orders/8821`, `DROP TABLE users_bak_0921`
— the rule layer cannot see the difference, while the model sees the full arguments.

#### A3. Human confirmation (1 rule, `ask`)

listener start/stop of the callback receiver: opening a listening port is a change to the **platform capability boundary** and to resource usage,
not "will the target asset be destroyed". Letting the model decide "should this port be opened" is a category error.

### B. Make a rule's own timeout actually take effect (fixes P0)

1. `judge()` gains a rule-level timeout override parameter.
2. Rule-level `timeout_enabled=false` → use the global `llm_judge_timeout_seconds` +
   global `llm_judge_fail_action`.
3. Rule-level `timeout_enabled=true` → use the rule's own `timeout_seconds` +
   `timeout_action` (**the rule author's explicit declaration**, taking precedence over the global).
4. Judgement-class rules uniformly declare `timeout_enabled=true, 90s, allow` —
   **allow by default rather than deny**: the operation hit by a judgement rule **may itself be legitimate**, and a model timeout
   only means "no answer came back", so treating it as a denial means any model hiccup harms a legitimate operation. The genuinely dangerous classes
   have already been carved out as hard bans, and those are where "timeout means deny" applies.

### C. The coverage gap for `rm -rf <any path>` (fixes P3)

**No new generic rule** — that would false-positive on a lot of normal cleanup (`rm -f /tmp/out.$$`,
`rm -rf ./workdir`). This class of operation is covered by the **fallback judge** (the verdict policy D4's literal
example is `rm -rf /var/www/html`). If leaks are observed later, design something separately.

### D. Redesign the "data exfiltration pipe" pattern (fixes P2)

Old pattern (false-positives on normal callbacks, which is why the rule stayed disabled for a long time):

```
(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))
```

New pattern (only blocks "@file upload"; pipe callbacks no longer match):

```
(?i)\b(curl|wget)\b[^|;&\n]{0,200}(?:-d|--data(?:-binary|-raw)?|-F|--form|--upload-file|--post-file)(?:\s*=\s*|\s+)?[^|;&\n]{0,100}?[\s"'=]@(?:"[^"\n]{0,80}"|'[^'\n]{0,80}'|[^\s;|&"']{1,80})
```

The discriminator is **the character before the `@`**: in the file-reference form the `@` is necessarily preceded by whitespace, a quote or
an equals sign (`@file`, `"@file"`, `name=@file`), whereas an `@` appearing elsewhere is preceded by an ordinary character
(an email `a@b.com`). Anchoring on `[\s"'=]@` covers all five shapes at once without misjudging an email address.

The rule goes from `enabled=false` to `enabled=true`.

### E. Two small fixes along the way

- `server/intercept.go`'s `validateInterceptRuleReq` validates that `timeout_action`
  ∈ allow|deny (the field really takes effect now; writing an arbitrary value would make "allow or deny after timeout"
  undefined behaviour).
- The UI rule list shows "this rule's timeout policy" (before the fix, the value it displayed didn't match what actually applied; the frontend still renders this as `timeout 60s → allow` or `use global config on timeout`).

### F. Three nil-db crash points fixed along the way

`intercept.loadLocked` / `Log` / `HandleAsk` dereference and panic when `i.db == nil`.
All three sit on the **synchronous path of tool calls** — a panic kills the whole agent process.

---

## 3. Change list

| File | Change |
|---|---|
| `db/intercept_builtin_rules.go` (new) | **Single source of truth for built-in rules**: the 22 rule definitions + classification + rationale |
| `db/intercept_builtin_migration.go` (new) | One-shot migration: move a deployed instance's rule actions to the new three-way split |
| `db/db.go` | The four seed functions now take their content from the single source of truth; register the new migration |
| `db/intercept.go` | — (no change needed) |
| `intercept/intercept.go` | `judge()` supports rule-level timeout overrides; adds `RuleTimeout` / `JudgeRuleWithTimeout`; fixes the three nil-db crash points; adds `SetRulesInMemory` (for tests) |
| `guard/guard.go` | When a rule hit goes to judge, pass the rule's timeout declaration to the verdict engine |
| `server/intercept.go` | `timeout_action` validation + positive-number validation for `timeout_seconds` |
| `web/src/app/(main)/system/intercept/page.tsx` | The rule list shows "this rule's timeout policy" |

**Data migration**: built-in rules are a first-insert-only seed, so changing the code has no effect on deployed instances.
A new one-shot migration `intercept_builtin_rule_actions_v1` decides "the user never touched it" by the "old default fingerprint" (action +
timeout triple + pattern) — rules whose action/pattern/timeout the user changed **are never touched**.

---

## 4. Verification

1. **Classification tests** (`db/intercept_builtin_rules_test.go`): each of the 10 outright-forbidden rules catches
   its command; the 12 judgement-class rules must have action judge; every rule has a classification rationale;
   names are unique; the regex compiles.
2. **Exfiltration pattern tests**: 5 upload shapes match, 8 normal callbacks/ordinary POSTs don't match,
   and the email `a@b.com` is not a false positive.
3. **Migration tests** (`db/intercept_builtin_migration_test.go`): placeholder numbering is contiguous,
   the placeholder count matches the parameter count, the criterion includes the "user never touched it" fingerprint, and every rule has a migration statement.
4. **Rule-level timeout tests** (`intercept/rule_timeout_test.go`): a rule-level timeout
   overrides the global, enabled=false falls back to the global, the failure action follows the rule declaration, and nothing leaks into the global.
5. **End-to-end routing tests** (`guard/intercept_e2e_test.go`): outright forbidden → denied and
   **the model is not called**; judgement → **the model is called** and its verdict governs; the rule-level timeout really reaches the verdict engine.
6. **Validation tests** (`server/intercept_rule_validation_test.go`): `timeout_action`
   only accepts allow/deny; seconds must be positive when the timeout is enabled.
7. **Regression**: `go build ./...` + `go vet ./...` + `go test ./...`.
   The failure set is **exactly the same** as the pre-remediation baseline (23, all of them the two pre-existing environment issues
   "missing database configuration" and "Windows path separator"), with zero new failures.
8. **Frontend**: `npx tsc --noEmit` + `NEXT_EXPORT=1 npx next build`.

## 5. What we are not doing

- ❌ Not changing the intercept architecture (rules → judge → allow/ask/deny three branches stay)
- ❌ Not changing the judge prompt (the D1–D6 / A1–A6 policy itself is well written)
- ❌ Not deleting any rule (only changing action / pattern)
- ❌ Not adding a generic rule for `rm -rf <any path>` (would false-positive on normal cleanup; covered by the fallback judge)
- ❌ Not touching user-created rules
- ❌ Not changing every rule to judge (a path already proven to go wrong)
