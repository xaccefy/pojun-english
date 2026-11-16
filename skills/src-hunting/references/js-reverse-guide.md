# JS Reversing for Endpoint Discovery Guide

> For the mandatory site-entry steps see `dig-scope` §4.1: **do not only extract `/api/` paths**. Salts, ciphertext-id public keys, hidden/admin routes and hard-coded demo accounts go into the inventory if present, otherwise write "none". Demo accounts are used as keys, not as a login-form dictionary.

## When to use

- The page's endpoints carry encrypted parameters that cannot be replayed directly with curl
- You need to discover hidden API endpoints from the frontend JS
- You need to understand the signature/token generation logic in order to construct arbitrary requests
- Hidden/admin entries in the route table, webpack async chunks, hard-coded demo accounts/test tenants

---

## Flow 1: Endpoint discovery

### 1. Inspect network requests

Using the js-reverse MCP tools (with the target page already open in the browser):

```
action: list_network_requests()
filter: resourceTypes=["xhr", "fetch"]
look at: endpoints carrying user data (/user/, /api/, /order/, /account/)
```

### 2. Bulk-extract endpoints from JS source

```javascript
// Run inside evaluate_script to extract every XHR path on the page
() => {
  const scripts = Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src);
  return scripts;
}
```

```bash
# Download every JS file and grep the endpoint paths
for url in $(cat js_files.txt); do
  curl -s "$url" | grep -oP '"(/api/[^"]+)"' | tr -d '"'
done | sort -u > discovered_apis.txt

# Keyword search
grep -E "(userId|uid|token|sign|order|payment)" discovered_apis.txt
```

### 3. Search with search_in_sources

```
search_in_sources("userId")          // find endpoints related to user IDs
search_in_sources("/api/")           // find every API path
search_in_sources("Authorization")   // find where the token is set
search_in_sources("signature")       // find the signature parameters
```

---

## Flow 2: Encrypted parameter analysis

Applies when a request carries encrypted parameters such as `sign`/`_token`/`x-sign`.

### Step 1: Locate it with an XHR breakpoint

```
1. break_on_xhr("/api/target-endpoint")
2. Trigger the matching action on the page
3. Once execution pauses: get_paused_info()
4. Inspect the call stack and find the function that sets the encrypted parameter
```

### Step 2: Analyse the call stack

```
get_paused_info() sample return:
  Frame 0: setRequestHeader (XMLHttpRequest)
  Frame 1: signRequest (utils.js:342)     ← look here
  Frame 2: sendApiRequest (api.js:89)
  Frame 3: onClick (page.js:234)
```

Once you have located Frame 1, read the source:

```
get_script_source(url="utils.js", startLine=335, endLine=355)
```

### Step 3: Extract the signing logic

Common signing algorithm patterns:

```javascript
// Pattern 1: sorted parameters + MD5
function signRequest(params) {
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  return md5(sorted + SECRET_KEY);
}

// Pattern 2: timestamp + nonce + HMAC
function sign(data) {
  const ts = Date.now();
  const nonce = Math.random().toString(36).substr(2);
  return hmacSha256(ts + nonce + JSON.stringify(data), APP_SECRET);
}

// Pattern 3: fixed salt concatenation
const sign = md5(userId + ':' + timestamp + ':' + SALT);
```

### Step 4: Execute the signing function in the browser

```javascript
// evaluate_script can call the page's signing function directly
() => {
  // if the function is in global scope
  return window.signRequest({userId: "victim_id", action: "getInfo"});
}
```

### Step 5: Reproduce the signature in Python

```python
import hashlib
import hmac
import time
import random
import string

# MD5 signature reproduction
def sign_request(params: dict, secret_key: str) -> str:
    sorted_str = '&'.join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.md5((sorted_str + secret_key).encode()).hexdigest()

# HMAC-SHA256 signature reproduction
def sign_hmac(data: str, app_secret: str) -> str:
    ts = str(int(time.time() * 1000))
    nonce = ''.join(random.choices(string.ascii_lowercase, k=8))
    msg = ts + nonce + data
    return hmac.new(app_secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

# Verify: the Python result must match the browser's JS execution result
```

---

## Flow 3: Hidden endpoint discovery

### Extract from webpack chunks

```bash
# Find the chunk files
curl -s "https://target.com" | grep -oP 'chunk\.[a-z0-9]+\.js'

# Download every chunk
for chunk in $(curl -s "https://target.com" | grep -oP '"/static/js/[^"]+\.js"' | tr -d '"'); do
  curl -s "https://target.com$chunk" >> all_js.txt
done

# Extract paths
grep -oP '"(/[a-z]+){1,5}"' all_js.txt | sort -u | grep -v node_modules
```

### Extract from route configuration

```bash
# Vue/React route configuration
grep -oP 'path:\s*["\x27][^"'\'']+' all_js.txt
grep -oP '"route":\s*["\x27][^"'\'']+' all_js.txt

# Axios base URL
grep -oP 'baseURL:\s*["\x27][^"'\'']+' all_js.txt
grep -oP 'BASE_API\s*=\s*["\x27][^"'\'']+' all_js.txt
```

---

## Flow 4: API parameter enumeration

Once endpoints are found, enumerate their parameters to look for IDOR/injection points:

```python
import requests

# Test each discovered endpoint
discovered_apis = [
    "/api/v1/user/info",
    "/api/v1/order/list",
    "/api/v2/account/profile",
]

session = requests.Session()
session.headers.update({"Authorization": "Bearer YOUR_TOKEN"})

for api in discovered_apis:
    r = session.get(f"https://target.com{api}")
    print(f"[{r.status_code}] {api} - {len(r.text)} bytes")
    if r.status_code == 200:
        # Record the ID fields in the response for later IDOR testing
        data = r.json()
        print(f"  response fields: {list(data.keys()) if isinstance(data, dict) else 'array'}")
```
