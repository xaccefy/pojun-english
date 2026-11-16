---
name: component-vuln-intel
description: Use when you have a component fingerprint or version number and need to decide whether a known CVE exists, find a PoC, or judge whether it is worth attacking — standard usage of the platform's built-in vulnerability intel (search_vulns/get_vuln/get_poc/scan_with_nuclei), version-range judgment and false-positive avoidance. Use when the intent involves "known vulnerability / CVE / version match / PoC".
tags:
  cwe: [CWE-1104, CWE-1395, CWE-1035]
  attack: [T1190, T1203]
  class: [vuln-intel, cve, fingerprint, exploit-selection]
---

# Component Vulnerability Intel (use the platform's built-in capability, do not report CVEs from memory)

## Why use the tool instead of your head

CVE version ranges in model memory are frequently wrong and frequently stale. The platform's intel
database (NVD + CISA KEV + GHSA + PoC aggregation) is the only trustworthy source:
**`search_vulns` first, then decide whether to attack**.

## Standard flow

1. **Nail the fingerprint**: component name + exact version (`Server: nginx/1.18.0`, `X-Powered-By`,
   `/actuator/info`, favicon, static asset hash, version number on the error page). If the version is
   uncertain, work out a way to nail it first;
2. `search_vulns` query: returns the CVE, CVSS, KEV (exploited in the wild) and a three-state `version_in_range`;
3. `get_vuln` for details and the affected-range description; `get_poc` for public PoCs / exploit links;
4. After a hit you **must verify behaviourally**: `scan_with_nuclei` or a hand-built request — only when you
   get the response characteristic does it count as a vulnerability;
5. In `report_finding` state: component+version, CVE id, verification method, real response evidence.

## Three pitfalls of version-range judgment

- **Distro backports**: RedHat/Debian backport patches onto old version numbers, so a version match ≠ vulnerable;
  the evidence must show "behavioural verification" — a bare version number gets bounced by the platform's
  mechanical verification gate;
- **Version numbers are untrustworthy**: many products change or hide versions (`Server: nginx` with no version,
  `X-Powered-By: PHP`); then you can only test behaviourally (does the endpoint exist, what is the error signature);
- When `version_in_range` returns "possibly affected": record a fact marked "version possibly affected,
  behaviour unverified", then decide whether to invest in verification; do not report the vulnerability directly.

## Using nuclei correctly

- Confirm template coverage first: `nuclei -t <matching template/tag> -u <url> -severity high,critical -stats`;
- The platform tool `scan_with_nuclei` assembles the command and keeps traffic; when running it yourself, write
  results to a file and then `save_evidence`;
- Template hit ≠ vulnerability: check whether the request/response really triggers it (some templates only match a version banner);
- For high-risk templates (RCE etc.), first confirm the target is authorized and the business will not be affected, then run.

## PoC usage discipline

- Public PoCs often contain callback/write-file behaviour: read the code first and confirm it will not damage the
  target (no rm / no encryption / no bulk operations);
- When OOB is needed, use the platform's listener (`listener_start` or interactsh) to keep evidence;
- Record failures as facts too (which step failed, what the error signature was) so the next person does not re-run it.

## High-frequency component priority list (look at these first)

- Web containers/frameworks: Tomcat, WebLogic, Spring(Boot), Struts2, ThinkPHP, RuoYi, JeecgBoot;
- Middleware/reverse proxies: Nginx, Apache, IIS, Kong, Nacos, Consul;
- Ops surfaces: Jenkins, GitLab, Zabbix, Grafana, Kibana, Druid, Actuator;
- Components: Fastjson, Log4j2, Shiro, XXL-JOB, RabbitMQ, Redis, Elasticsearch, MinIO;
- Office/OA: Seeyon, Weaver, Tongda, Landray (high frequency on domestic SRC).

## Reporting wording

- The title states "component+version+CVE+impact"; evidence includes request/response or nuclei output;
- A KEV hit must be specially marked "exploited in the wild";
- A version match without real impact: medium + "version match, behaviour unverified", plus reproduction steps.
