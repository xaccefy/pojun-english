---
name: zero-day-research
description: Use when doing patch diffing, crash/stack analysis, protocol fuzzing, or pushing from anomalous behaviour to a 0day — hypothesis-driven research paths, patch comparison methods, minimal reproduction and impact-surface expansion.
tags:
  cwe: [CWE-20, CWE-787, CWE-125, CWE-416]
  attack: [T1203, T1211]
  class: [0day, patch-diff, fuzzing, research]
---

# 0day Research Path (within scope)

## Research loop

```
observe anomaly → form hypothesis → minimal verification → judge impact surface → record / iterate
```

- Write each hypothesis as one sentence ("parameter X is not length-validated → heap overflow → crash") and judge true/false after verification;
- Record failures as facts too (hypothesis, method, result) so the research is not repeated.

## Patch diffing (the fastest route to a bug)

1. Find the old/new binary or source (vendor historical releases, Docker image layers, distro patches);
2. Compare:
   - Source: `git log --oneline v1.0..v1.1`, `git diff v1.0 v1.1 -- <key directory>`;
   - Binary: `bindiff`/`radiff2 -C`, function signatures and string differences;
3. See what validation the patch changed (bounds/permissions/signatures) → reverse-engineer the unvalidated input;
4. Start the old version locally to verify the crash/bypass, then do minimal verification on the authorized target.

## Behavioural anomaly clues

- Error messages leaking internal paths/parameter names (the backend is concatenating directly);
- The same parameter returning different results under different encodings (parser differences);
- State-machine skips (skipping a verification step still succeeds);
- Timing differences (out-of-bounds / large objects handled slowly);
- Response length differences (truncation/swallowed bytes → parser boundary issues).

## Fuzz minimization

- Use real requests as seeds (HTTP/protocol/file format);
- Lightweight first: `ffuf -w payloads.txt -u <url> -mc 500 -fs <normal length>` to filter anomalies;
- Save crash/anomaly samples immediately (`save_evidence`) and record the environment;
- Do not run large concurrency (production targets require the minimum number of requests); a single-threaded small dictionary is enough to locate direction.

## Impact determination

- Crashes → possibly DoS (low value, use caution);
- Can read out-of-bounds data / bypass auth → high;
- Can execute code → critical;
- An anomaly whose impact cannot be proven → write only a research fact, do not report a vulnerability.

## Reporting wording

- 0day-class findings include: trigger conditions, minimal PoC, affected versions, root-cause analysis (code/disassembly snippets);
- State the boundary explicitly: "not expanded to verification on real business data";
- Reproduction steps must let a third party verify independently.
