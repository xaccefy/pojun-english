---
name: src-acceptance
description: Use before submitting to SRC or a client for acceptance — check from the receiver's perspective whether the vulnerability is "evidence-complete, impact-verifiable, unmasked, reproducible", list the gaps that would cause a rejection, and give the actions to close them.
tags:
  cwe: []
  attack: []
  class: [acceptance, evidence, src, quality-gate]
---

# SRC Acceptance Standards (quality gate before submission)

> The receiver only accepts "reproducible real impact". Every item below is a hard reason for rejection; check each one before submitting.

## 1. Required materials (missing one means rejection)

1. **Vulnerability title**: system + feature + defect + impact; do not write "suspected/may exist";
2. **Target**: full URL/Host/IP, port, method, parameters;
3. **Identity and preconditions**: anonymous/normal user/administrator, account, Cookie/token, network position;
4. **Reproduction steps**: numbered steps, each executable; include the raw request (request line + headers + Cookie + body);
5. **Response evidence**: status code, key response headers, full response body or dataset;
6. **Impact proof**: how many records/which fields were read, which test object was written and read back, permission differences, command echo;
7. **Data volume**: ≥10 de-duplicated records or the full set/total; 1 record only is not accepted;
8. **Unmasked**: original target data values; `***`/`[redacted]`/"masked"/redaction boxes mean no data was obtained;
9. **Reproduction commands**: curl/sqlmap/nuclei/python that run directly, noting the expected output signature;
10. **Attachments**: screenshots containing the URL/key fields; dataset artifact id + sha256; traffic baseline/proof;
11. **Verification time**; 12. **Fix recommendation**; 13. **Unverified scope** (if any).

## 2. Acceptance thresholds by severity

| Level | Minimum evidence |
|---|---|
| critical | unauthenticated/low-barrier RCE or admin takeover; bulk sensitive data (≥1000 records or full set + fields + samples); fund/order tampering readable back; command echo + privilege level |
| high | IDOR reading other people's sensitive data (≥10 records or full set), arbitrary file read/write proof, restricted command execution, backend administrator privileges; two-identity comparison |
| medium | IDOR/injection requiring preconditions, information disclosure containing sensitive fields, stored XSS affecting administrators; raw request/response available |
| low | minor information disclosure/configuration issue; reproducible request and impact statement |

## 3. Immediate rejection items (red lines)

- Only a version/banner/CVE match with no behavioural verification;
- Only 1 record/1 screenshot, with no total/fields;
- Evidence masked with `***`, `[redacted]`, redaction boxes, or overwritten;
- No raw request/response, only text saying "returned success / vulnerability exists";
- IDOR with only one identity and no permission matrix;
- Writes with no own test object/read-back/cleanup, or touching production data;
- Reproduction commands that do not run or disagree with the actual evidence;
- Writing "suspected/possible/theoretically" as confirmed;
- Report content that does not match the finding evidence/traffic.

## 4. Gap-closing actions (by gap)

- Missing data volume → take the full set via paging/time window/export endpoints, count totals and fields, save the raw response;
- Missing permissions → build a matrix over the same endpoint with the four identities anonymous/A/B/administrator;
- Missing write proof → create a unique-marker test object, write it, read it back, record before/after values and clean up;
- Missing command execution → prove privilege with `id`/`whoami`/`hostname` + the first lines of a sensitive file;
- Missing reproduction → paste the commands actually executed verbatim, noting the expected output;
- Missing attachments → `save_evidence` the dataset/screenshots, recording sha256 and artifact id;
- Missing traffic → `traffic_refs` bind baseline and proof.

## 5. Pre-submission self-check

- [ ] `evidence_check` returns `src_ready=true`, or every missing item is explained
- [ ] Every vulnerability has "raw request/response + reproduction commands + impact proof"
- [ ] Data-type findings have total/fields/unmasked samples; IDOR findings have an identity matrix; writes have read-back
- [ ] The report matches the finding evidence, traffic and artifacts
- [ ] Unverified scope stated honestly; nothing undone is written as confirmed
