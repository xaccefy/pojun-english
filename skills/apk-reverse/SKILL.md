---
name: apk-reverse
description: Android APK reverse engineering. Use when the target is only an APK/installer package, or when you need to analyse an app's endpoints, signing algorithm, hardcoded secrets, risk controls/certificate pinning/root detection, or repackaging, Frida dynamic hooking and .so triage. Covers the complete jadx/apktool/aapt/adb/frida/objection static+dynamic chain; when no real device is available it gives an alternative static + traffic-simulation path.
tags:
  cwe: [CWE-312, CWE-321, CWE-295, CWE-489, CWE-798, CWE-926, CWE-1104]
  attack: [T1409, T1426, T1430, T1516, T1521]
  class: [mobile, android, reverse, forensics]
---

# APK Reverse Engineering · Internal Working Spec

Black/gray-market distribution often provides only a single APK / installer package. This skill tears the package apart to reach the underlying artifacts:
**endpoints, signing algorithms, keys, and risk-control logic**, and fixes them in place as evidence.

## Integration with this platform (read this first)

| Scenario | Platform capability to use |
|---|---|
| The sample itself is evidence | `save_evidence` archives the original APK and registers its SHA-256 (hash first, then unpack) |
| Endpoints / keys / conclusions | `record_fact` stores them in the database (class name, method, algorithm, key location) |
| Backend endpoint testing | Once endpoints are recovered, move to `http_probe` / `auth_request` / `diff_responses` |
| Traffic reconstruction | Platform traffic capture (on by default) or mitmproxy; view requests in `traffic` |
| Known-component CVEs | `search_vulns` / `scan_with_nuclei` (server-side) |

## Environment facts (server form)

- The toolchain is installed via `install.sh` / the Docker image / the host environment page: `java`, `apktool`, `aapt`,
  `adb`, `jadx`, `frida`, `objection`.
- **The server usually has no real device/emulator**:
  - Device present (USB/remote adb, e.g. `adb connect 127.0.0.1:7555`) → follow the real-device dynamic chain;
  - No device → **static-first + traffic simulation**: read logic with jadx/apktool, verify endpoints with platform traffic capture/proxy,
    skip hooks that require a real device (state clearly "requires a device to complete").
- Do not install an emulator on the server; when dynamic verification is needed, ask the user for a device or an authorized environment.

## Bundled scripts (use these first)

| Script | Purpose |
|---|---|
| `scripts/decode.sh` | Runs jadx + apktool in one pass, outputs a package/java_files/smali_dirs/so_files summary |
| `scripts/frida-run.sh` | Device/process listing, spawn/attach injection, avoids `-f/-n/-U` mix-up errors |
| `scripts/rebuild-sign-install.sh` | `apktool b` → zipalign → apksigner → optional `adb install` |

```bash
bash scripts/decode.sh -ApkPath /data/sample/app.apk -Clean
bash scripts/frida-run.sh -Usb -ListProcesses
bash scripts/rebuild-sign-install.sh -ProjectDir apktool_out -Install -Reinstall -DeviceSerial 127.0.0.1:7555
```

Call one-liners directly, no need to wrap them: `adb devices`, `adb logcat`, `frida-ps -U`,
`jadx --version`, `apktool --version`.

## Workflow

### 1. Triage (classify first, don't act yet)

1. Hash the original package first with `sha256sum app.apk` → `save_evidence` (start of the evidence chain).
2. `jadx -d jadx_out app.apk` for Java; `apktool d app.apk -o apktool_out` for smali + resources.
3. Look first at: `AndroidManifest.xml` (permissions/exported components/main entry/debuggable/allowBackup),
   `package`, `application`, whether `lib/**/*.so` exists, and the package name and signature (`apksigner verify --print-certs`).
4. Threat-shape quick check: transparent/hidden icon (check label/icon with `aapt dump badging`),
   Magisk/scripted-wipe traits, persistence paths (`service.d`/`priv-app`) — **record characteristics and URLs as evidence, do not execute**.

### 2. Java logic (jadx)

Read from `jadx_out`: MainActivity/Application, login, networking, crypto, risk control, SDK initialization.
Keywords: `login` `sign` `encrypt` `cipher` `token` `root` `certificate` `trust`
`okhttp` `retrofit` `webview` `baseUrl` `api` `secret` `accessKey`.

Produce three things: an **endpoint list** (full URL/path/parameters), **signature/encryption algorithms** (recovered at smali level to the point of being reproducible),
and **hardcoded credentials** (AK/SK/token/appSecret, logged in full to facts, masked in the report).

### 3. Smali and resource layer (apktool)

Switch to `apktool_out` when jadx is incomplete, obfuscation is heavy, or a patch is needed: `smali*/`, `res/values/strings.xml`,
`AndroidManifest.xml`. Patchable items: `android:exported`, `debuggable`, root-detection return values,
login checks, certificate-validation branches.

### 4. Repackaging (only when needed)

```bash
apktool b apktool_out -o rebuilt.apk
# align + sign + install (debug keystore auto-generated and reused)
bash scripts/rebuild-sign-install.sh -ProjectDir apktool_out -Install -Reinstall
```

**Boundary**: repackaging is only for **analysis and verification** of an authorized sample; the modified artifact must not be used for delivery or redistribution.

### 5. Dynamic hooking (only with a device)

Java layer first, then native:
- Hook login/signing/encryption: `javax.crypto`, `MessageDigest`, `OkHttp`/`Retrofit` interceptors;
- Bypasses: root detection, SSL pinning, debug detection (try objection first with one command:
  `objection -g com.example.app explore` → `android sslpinning disable`);
- Principle: print parameters and return values first, then decide whether to modify return values.

Scripts and reusable script templates are in `references/frida-cookbook.md` and `references/frida-bypass-kit.md`.

### 6. `.so` triage

Java is only a JNI wrapper / the core signature is in native / logic disappears after `System.loadLibrary()` / checks live in `.so`
→ switch to native immediately: quick triage with `strings`, `readelf -s`, radare2; for deeper decompilation use
`ida-reverse` or Ghidra. `.so` files inside the APK can be extracted with `unzip -j` and archived separately.

### 7. Backend endpoint verification (the main arena)

Reverse engineering only gets you the key. Once you have endpoints, use platform tools to attack the authorized domain directly:
unauthorized/privilege-escalation (swap id/token)/injection/logic; once the signing algorithm is reproducible, construct requests yourself.
Per the forensics standard you **may export samples and data**, but do it in controlled batches and register hashes (`save_evidence` computes SHA-256 automatically).

## Output requirements

State at minimum: package name and signature, entry components, which layer (Java/smali/`.so`) holds the key logic,
endpoint list, signature/encryption algorithms, hardcoded credentials (masked), confirmed sensitive points
(login/signing/root/SSL/WebView/JNI), the specific patch or hook locations, and **what was not accomplished**
(e.g. dynamic verification not done because no device was available).

## Prohibited

- Don't start by modifying smali; look at the manifest and main entry first.
- Don't treat incomplete jadx decompilation as "logic cannot be analysed" (switch to smali/another tool before concluding).
- Don't grind away at the Java layer when `.so` clearly carries the core logic.
- Don't reverse/test apps outside authorization; don't bypass payment or copyright protection for non-testing purposes.
- Don't execute any command/script inside the sample (`curl|sh`, wipe commands) — only extract characteristics as evidence.

## Reference files (open as needed, do not read straight through)

| File | Contents |
|---|---|
| `references/apk-security-checklist.md` | Checklist for packaging/components/storage/network/crypto |
| `references/frida-cookbook.md` | Common hook scripts (Java/native/network/crypto) |
| `references/frida-bypass-kit.md` | Anti-debug/anti-root/SSL pinning bypass collection |
| `references/android-advanced.md` | Advanced topics: packing, dynamic loading, JNI, unpacking, etc. |

## Completion self-check

- [ ] Original APK hashed and `save_evidence` called
- [ ] Manifest/entry/exported components reviewed
- [ ] Endpoint list, signing algorithm, key locations logged to facts
- [ ] With a device: hook verification done; without: missing device and alternative verification documented
- [ ] Patch/hook locations and purposes written clearly (reproducible)
