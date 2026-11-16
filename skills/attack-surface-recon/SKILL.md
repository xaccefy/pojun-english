---
name: attack-surface-recon
description: Use at task start or when entering a new asset domain to perform external attack-surface reconnaissance — filing/certificate/whois/ASN attribution checks, subdomain and port enumeration, fingerprint and sensitive-file discovery, asset recording and coverage planning. Use when the intent involves "recon / asset discovery / subdomain / fingerprint / port scan".
tags:
  cwe: [CWE-200]
  attack: [T1595, T1590, T1592, T1596]
  class: [recon, asset-discovery, fingerprint, attack-surface]
---

# Attack Surface Recon Methodology

## Deliverables (every recon must produce)

1. New assets with clear ownership (domain/IP/service/endpoint) — confirmed via a filing/certificate/whois/ASN evidence chain, then `insert_assets`;
2. A fingerprint for each asset (status code/title/Server/tech stack/CDN/WAF);
3. The untested asset list (input to `list_untested_assets`);
4. One fact stating coverage and conclusions (including failures, to prevent repeated scanning).

## 1. Ownership verification (prove ownership before talking about testing)

- ICP filing: query the MIIT filing system to confirm the registrant entity;
- Certificate transparency: `crt.sh` / `certspotter` for certificate SANs (one of the most reliable subdomain sources);
- whois / ASN: `whois <ip>`, `whois -h whois.radb.net <ip>` to confirm IP ownership and netblock;
- Reverse DNS, favicon hash (`mmh3`/`whatweb`), page copyright/filing number;
- **Sharing an IP alone is not grounds for ownership**: third-party business on the same IP must not be brought into scope (write a fact noting "same IP, not this entity").

## 2. Subdomain and domain surface

- Passive: crt.sh, `subfinder -d domain -all`, `amass enum -passive -d domain`;
- Active: liveness checks with `dnsx`/`naabu`, virtual-host enumeration with `ffuf -w <wordlist> -u https://FUZZ.domain`;
- Wildcard detection: check whether a random subdomain resolves (to avoid false positives);
- Wildcard certificates can mask real subdomains; watch the SAN list for **other domains** (often old domains/alias domains).

## 3. Ports and services

- Fast full-port scan: `nmap -p- --min-rate 2000 -T4 <ip>`; service detection `nmap -sV -sC -p<ports> <ip>`;
- masscan to narrow large netblocks: confirm the authorized netblock first, `masscan -p80,443,8080,8443 <cidr> --rate 1000`;
- Non-standard ports to prioritize: `8080/8443/8888/7001(WebLogic)/9200(ES)/6379(Redis)/27017(Mongo)/2375(Docker)/9090`;
- Direct service evidence: unauthenticated Redis `redis-cli -h ip info`, ES `curl ip:9200/_cat/indices`.

## 4. HTTP fingerprinting (batch, keep evidence)

- Platform tool: `http_probe` probes a batch of URLs and returns one JSON line each (status/bytes/ms/title/server/ct/redirect);
- Supplements: `whatweb -a3 <url>`, `httpx -title -tech-detect -status-code -web-server`;
- Look at: framework (Spring/Vue/React/ThinkPHP/RuoYi), middleware (Tomcat/Nginx/IIS),
  WAF/CDN (response headers/block page characteristics), debug endpoints (`/actuator`, `/druid`, `/swagger-ui`);
- favicon hash reverse lookups on Shodan/FOFA can serve as same-origin fingerprints (use the matching tool/API when needed).

## 5. Sensitive files and information disclosure

- Common: `/robots.txt`, `/sitemap.xml`, `/.git/config`, `/.svn/entries`, `/.env`,
  `/backup.zip`, `/www.zip`, `/db.sql`, `/.DS_Store`, `/phpinfo.php`;
- Swagger/OpenAPI: `/swagger-ui.html`, `/v2/api-docs`, `/openapi.json` (an endpoint panorama the moment you get it);
- Spring: `/actuator`, `/actuator/env`, `/actuator/heapdump` (contains keys; high-severity evidence);
- Frontend bundles: API prefixes, AK/SK, test-environment domains and sourcemaps (`.map` restores the source directly) inside `.js`.

## 6. Coverage and recording

- Record new assets with `insert_assets` (type/name/owning company); out-of-scope items are recorded but not tested;
- Use `list_untested_assets` to find untested assets, and pick the next batch by "cluster by shared prefix + leave static ones for last";
- For coverage see `graph_overview`'s coverage; do not re-scan already-tested assets just to reach 100%;
- Task constraints (registered via `set_constraints`) take precedence over any scan plan: only scan the permitted ports/netblocks.

## Discipline

- Passive before active, light before heavy (avoid triggering a ban with full-port scans plus big dictionaries from the start);
- Record every failed probe as a fact too ("subdomain X does not resolve", "port Y filtered"), to reduce duplication;
- Stop immediately and record when you identify third-party assets/cloud-hosting boundaries.
