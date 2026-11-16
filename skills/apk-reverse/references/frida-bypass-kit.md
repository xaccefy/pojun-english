# Frida Bypass Kit — A general-purpose Android security bypass framework

> Source: [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit) (2025)
> Use case: when dynamic APK analysis requires bypassing root detection, SSL pinning, emulator detection, and anti-debugging

## Overview

FridaBypassKit is a Frida script that integrates four major bypass capabilities. No per-app customization is needed — it works out of the box.

## Four bypass capabilities

### 1. Root detection bypass

- Hook `File.exists()` to hide the su binary
- Intercept `Runtime.exec()` root-check calls
- Hide root-related packages (Magisk, SuperSU, etc.) from PackageManager
- Modify system properties so the device appears non-rooted

### 2. SSL pinning bypass

- Hook `TrustManagerImpl.verifyChain()`
- Hook `TrustManagerImpl.checkTrustedRecursive()`
- Bypass certificate chain validation
- Return an empty certificate chain to avoid verification
- Compatible with OkHttp, Retrofit, and custom implementations

### 3. Emulator detection bypass

- Forge TelephonyManager return values
- Return fake phone numbers and carrier names
- Modify Build properties

### 4. Anti-debugging bypass

- Hook `Debug.isDebuggerConnected()`
- Prevent debugger detection
- Bypass anti-debugging checks

## Usage

```bash
# Prerequisites
pip install frida-tools
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c /data/local/tmp/frida-server &

# Inject the target app
frida -U -f com.example.app -l FridaBypassKit.js
```

## Other recommended Frida bypass scripts

| Project | Features | Link |
|------|------|------|
| httptoolkit/frida-interception-and-unpinning | MitM all HTTPS traffic directly | [GitHub](https://github.com/httptoolkit/frida-interception-and-unpinning) |
| 0xCD4/SSL-bypass | General-purpose, non-customized SSL bypass | [GitHub](https://github.com/0xCD4/SSL-bypass) |
| incogbyte/ssl-bypass gist | Bypass common SSL pinning methods | [Gist](https://gist.github.com/incogbyte/1e0e2f38b5602e72b1380f21ba04b15e) |
| Zero3141/Frida-OkHttp-Bypass | Specifically targets OkHttp CertificatePinner | [GitHub](https://github.com/Zero3141/Frida-OkHttp-Bypass) |

## Integration with this package

In the `apk-reverse` workflow, use it when encountering the following situations:

1. App detects root and refuses to run → enable Root Detection Bypass
2. HTTPS requests show no plaintext when packet-capturing → enable SSL Pinning Bypass
3. App detects an emulator and refuses to run → enable Emulator Detection Bypass
4. App crashes after attaching Frida → enable Debug Detection Bypass

Recommended to use in combination: run the full FridaBypassKit first, then adjust as needed.
