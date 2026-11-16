---
name: redteam-opsec
description: Use when you need to control operational footprint and noise (authorized red team exercises, blue team engagements, avoiding bans/WAF/EDR) — identity and infrastructure isolation, traffic pacing, logging and footprint discipline.
tags:
  cwe: []
  attack: [TA0005]
  class: [opsec, stealth, red-team]
---

# Operational Security (OPSEC) Cheat Sheet

## Core principles

- **Every action must be explainable by its origin**: even in-scope test traffic should be as quiet as possible, to avoid collateral damage to the business;
- Once blocked by a WAF/EDR/ban, stop and analyse first; do not switch IPs and force it through (that widens your exposure).

## Identity and infrastructure

- Do not mix identities: different engagements/targets get different egress and UA;
- The platform already provides an egress proxy pool (proxypool) and a MITM logging proxy — route test traffic through them;
- Do not stand up your own internet-facing C2 and do not leave a persistent trusted backdoor on the target (when an authorized exercise has its own rules, follow those).

## Traffic pacing

- Probe in small steps: single request → small group → batch; confirm you will not trip risk controls before batching;
- Rate-limit login/SMS/payment endpoints (≥2s per request), no concurrency;
- Large dictionary brute force only when authorized and explicitly permitted; check the lockout policy first.

## Traces and logs

- Record the paths of uploaded tools/scripts and clean them up before the engagement ends (within scope);
- Do not write plaintext markers on the target; where a marker is necessary, use a harmless, explainable filename;
- Every action has a traffic/command record (the platform logs automatically); reports cite only real records.

## Alerts and abort

- On a target alert / captcha escalation / connection block → record the symptom, pause that class of request, change direction;
- On a blue-team response (ban/honeypot) → record a fact and report it to the operator; do not counter-engage on your own;
- Honeypot recognition: paths that are too easy, services that are abnormally open, data that does not match the business → verify before going deeper.
