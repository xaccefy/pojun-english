# Public-Internet Deployment Security Hardening

> 2026-10-29 (v0.3.85). This document records the security hardening done for public-internet
> deployments, the items deployers must take care of, and the known boundaries.

## 1. What this round hardened

| Item | Content |
|---|---|
| Login brute-force protection | `/api/auth/login` and `/api/auth/init`: 5 failures per IP within 10 minutes -> 15-minute lock; 30 failures globally per minute -> 5-minute global lock (a backstop against XFF spoofing); failure responses have a fixed 300ms delay and log the source IP |
| Liveness endpoint fingerprint removal | `/api/health` only returns `{"ok":true,"status":"ok"}` — no longer exposing the service name and exact version (the easiest body fingerprint for internet-wide scanning). Version queries go through the **authenticated** `/api/version` |
| Password change revokes sessions | A successful password change **rotates the JWT signing key**, immediately invalidating every old token (previously a leaked token stayed valid until it naturally expired after 7 days) |
| Security response headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`; `/api/*` always `Cache-Control: no-store` |
| CORS allowance removed | The frontend and API are deployed same-origin, so `Access-Control-Allow-Origin:*` only had the effect of relaxing cross-site reads; removed entirely |
| Product-name fingerprints removed from the auth surface | The login/initialization pages were rebuilt (single centered card, inline geometric mark replacing the image logo, neutral copy); the document titles for the root path / 404 / login / initialization now read "Console"; the favicon became a neutral icon with no recognizable pattern. The export was verified: zero product-name occurrences on unauthenticated-reachable pages |

**Design boundary (deliberately not done)**: the product name and sidebar logo inside the post-login UI (already past authentication) stay as they are — seeing them presupposes having authenticated, so they are not an unauthenticated fingerprint.

## 2. What deployers must take care of

1. **The reverse proxy must overwrite `X-Forwarded-For`** (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`). Login rate limiting counts by that header: without overwriting it, a client can spoof the header to bypass per-IP locking (the global threshold still backstops, but the per-IP dimension stops working). The nginx example in the README already includes it.
2. **HTTPS is mandatory** (nginx TLS termination is enough). The JWT travels through the `Authorization` header and the `pojun_token` cookie, which is equivalent to sending it in the clear over plain HTTP.
3. **Strong password**: the password is the only authentication boundary for a public deployment (this system can execute commands on the server). A minimum of 8 characters is a floor, not a recommendation.
4. **Configuring authorization credentials for real targets on a public instance is not advised** (the asset `auth` field) unless you accept the risk — anyone who gains platform access can read them through `auth_request`.

## 3. Known boundaries

- Rate limiting is process-memory state: it resets when the service restarts (this affects the attacker's waiting time, not correctness).
- The global threshold backstops XFF spoofing, but distributed low-and-slow brute force (many IPs each making 4 attempts) fundamentally cannot be cured by single-node rate limiting — public instances should add a WAF/CDN rate limit layer on top.
- Unauthenticated-reachable surface: `/api/auth/*` (status/init/login/change-password — change carries its own token check) and `/api/health` (now genericized). Every route was checked one by one; there are no other exemptions.
