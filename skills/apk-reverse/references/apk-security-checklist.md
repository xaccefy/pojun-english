# APK Security Testing Quick Reference

> Compiled based on OWASP MASTG (Mobile Application Security Testing Guide).
> Covers six major dimensions: static analysis, dynamic analysis, network communication, data storage, authentication/authorization, and code protection.

---

## Static Analysis Checklist

### Manifest Audit

```text
□ android:debuggable="true" → debuggable (should not appear in production)
□ android:allowBackup="true" → data can be backed up and extracted
□ components with android:exported="true" → exposed Activity/Service/Receiver/Provider
□ custom permission protectionLevel → is it normal (should be signature)
□ scheme in intent-filter → can custom deeplinks be hijacked
□ android:usesCleartextTraffic="true" → allows cleartext HTTP
□ minSdkVersion too low → may lack security features
```

### Key Code Audit Points

```text
□ Hardcoded keys/Tokens (search for "key", "secret", "password", "api_key")
□ Insecure random numbers (java.util.Random instead of SecureRandom)
□ Insecure encryption (ECB mode, DES, MD5 used for passwords)
□ WebView configuration (setJavaScriptEnabled + addJavascriptInterface = RCE risk)
□ SQL injection (rawQuery concatenating user input)
□ Path traversal (ContentProvider's openFile doesn't validate path)
□ Log leakage (Log.d/Log.i output sensitive information)
□ Clipboard leakage (ClipboardManager stores sensitive data)
□ Implicit Intent leakage (sendBroadcast without specifying package name)
```

### Third-Party Library Audit

```text
□ Outdated OkHttp/Retrofit versions (known vulnerabilities)
□ Outdated WebView kernel
□ SDKs with known vulnerabilities (check CVEs)
□ Ad SDK data collection scope
□ Push SDK configuration (does it leak tokens)
```

---

## Dynamic Analysis Checklist

### Priority Frida Hook Targets

| Target | Hook Point | Purpose |
|------|---------|------|
| Login authentication | `LoginActivity.login()` | Observe credential handling |
| Signature generation | `*Sign*`, `*sign*`, `*encrypt*` | Reconstruct signature algorithm |
| SSL Pinning | `CertificatePinner.check` | Bypass traffic interception |
| Root detection | `*root*`, `*su*`, `*magisk*` | Bypass detection |
| Crypto operations | `javax.crypto.Cipher` | Extract key/IV |
| Token storage | `SharedPreferences.getString` | Observe token read/write |
| Network requests | `OkHttpClient.newCall` | Observe request construction |

### Common One-Line Frida Commands

```bash
# Trace all crypto operations
frida-trace -U -f com.target.app -j '*Cipher*!*'

# Trace all HTTP requests
frida-trace -U -f com.target.app -j '*OkHttp*!*'

# Trace SharedPreferences read/write
frida-trace -U -f com.target.app -j '*SharedPreferences*!*'

# Trace all native function calls
frida-trace -U -f com.target.app -i 'Java_*'
```

### Quick Objection Commands

```bash
# Connect
objection -g com.target.app explore

# Common commands
android hooking list activities
android hooking list services
android sslpinning disable
android root disable
android clipboard monitor
env                              # view app directory
sqlite connect <db_path>         # connect to database
```

---

## Network Communication Security

### Traffic Interception Setup

```text
Method 1: System proxy + Burp/mitmproxy
- Set WiFi proxy → Burp listening address
- Install CA certificate on device
- Android 7+ requires network_security_config or Frida bypass

Method 2: VPN mode (recommended)
- Use HttpCanary / Packet Capture
- No root needed, no proxy configuration needed
- But cannot decrypt SSL Pinning traffic

Method 3: Frida + r2frida
- Intercept network calls directly in-process
- Not limited by proxy/VPN
```

### Checklist

```text
□ Whether HTTPS is used (all API calls)
□ Whether SSL Pinning (certificate pinning) is present
□ Whether certificate validation is correct (doesn't accept self-signed)
□ Whether Certificate Transparency (CT) checks are present
□ Whether API keys are transmitted in cleartext in requests
□ Whether tokens have an expiration mechanism
□ Whether request signing prevents tampering
□ Whether replay attack protection exists (nonce/timestamp)
□ Whether WebSocket is encrypted
□ Whether sensitive data is in URL parameters (will be logged)
```

---

## Data Storage Security

### Locations to Check

| Location | Risk | Check Command |
|------|------|---------|
| SharedPreferences | cleartext token/password storage | `adb shell cat /data/data/pkg/shared_prefs/*.xml` |
| SQLite database | unencrypted sensitive data | `adb pull /data/data/pkg/databases/` |
| External storage | readable by any app | `adb shell ls /sdcard/Android/data/pkg/` |
| App logs | leak debug information | `adb logcat \| grep pkg` |
| Backup files | allowBackup=true | `adb backup -f backup.ab pkg` |
| Keyboard cache | input history | Check whether `inputType` is `textPassword` |
| Screenshot protection | sensitive screens can be screenshotted | Check `FLAG_SECURE` |

### Encrypted Storage Scheme Comparison

| Scheme | Security | Notes |
|------|------|------|
| SharedPreferences cleartext | ❌ | directly readable after root |
| EncryptedSharedPreferences | ✓ | AndroidX Security library |
| SQLCipher | ✓ | encrypted SQLite |
| Android Keystore | ✓✓ | hardware-level key protection |
| Custom AES encryption | ⚠️ | depends on key management |

---

## Authentication and Authorization

### Common Vulnerabilities

| Vulnerability | Test Method |
|------|---------|
| Weak password policy | try 123456, password, etc. |
| No lockout mechanism | brute-force the login endpoint |
| Token doesn't expire | replay old token after logout |
| Unauthorized access | modify `user_id` in request |
| SMS code brute-forceable | 4/6 digits with no rate limit |
| OAuth misconfiguration | `redirect_uri` tamperable |
| Biometric auth bypass | Hook BiometricPrompt |
| Device binding bypass | modify `device_id` |

### Test Payloads

```bash
# Unauthorized access test
curl -H "Authorization: Bearer USER_A_TOKEN" \
     "https://api.target.com/users/USER_B_ID/profile"

# Token replay
# 1. Log in normally to get token
# 2. Log out
# 3. Request with old token → should return 401

# SMS code brute force
for code in $(seq 0000 9999); do
    curl -X POST "https://api.target.com/verify" \
         -d "phone=13800138000&code=$code"
done
```

---

## Code Protection Assessment

| Protection Measure | Detection Method | Bypass Difficulty |
|---------|---------|---------|
| ProGuard obfuscation | jadx check if class names are a/b/c | Low (just renaming) |
| String encryption | search for decrypt functions, Hook to get plaintext | Medium |
| Anti-debugging | try attaching debugger | Medium (Frida can bypass) |
| Root detection | run on rooted device | Medium (generic scripts bypass) |
| Emulator detection | run on emulator | Low-Medium |
| Integrity check | modify APK then install | Medium (patch check function) |
| Packing/shell | check entry class and .so | Medium-High (requires unpacking) |
| Native protection | core logic in .so | High (requires IDA analysis) |
| VMP virtualization | code executed virtualized | Extremely high |

---

## Quick Testing Flow (30 minutes)

```text
1. [5min] Unpack + Manifest audit
   apktool d app.apk
   Check debuggable/allowBackup/exported/cleartext

2. [10min] Quick code audit
   jadx -d out app.apk
   Search: password, key, secret, token, http://

3. [5min] Network testing
   Configure proxy → operate the app → check for cleartext/weak encryption

4. [5min] Storage check
   adb shell → check shared_prefs and databases

5. [5min] Dynamic verification
   Frida hook key functions → confirm findings
```
