---
name: binary-mobile-reversing
description: Use when the target has an app (APK/IPA) or desktop client, or binary reversing is needed to find endpoints/secrets/vulnerabilities — static analysis, Jadx/apktool, common mobile vulnerabilities (hardcoded secrets, exported components, certificate-pinning bypass, WebView), and the path from reverse-engineering results back to server-side testing.
tags:
  cwe: [CWE-798, CWE-312, CWE-926, CWE-295]
  attack: [T1409, T1552.001]
  class: [mobile, reverse, apk, ipa, binary]
---

# Mobile / Binary Reversing Cheat Sheet

## APK static analysis

1. `apktool d app.apk -o out/`: resources, `AndroidManifest.xml` (exported components/permissions/deep-links);
2. `jadx -d src/ app.apk`: Java source recovery;
3. Find secrets (write them to a fact in full):
   ```bash
   grep -rnE "https?://|api[_-]?key|secret|token|password|AKID|accessKey" src/ | head -50
   gitleaks detect --source src/ 2>/dev/null
   ```
4. Extract endpoints: `okhttp`/`retrofit` annotations, `/api/` constants, the encryption-parameter construction logic (signing algorithm);
5. Exported components: `adb shell dumpsys package <pkg> | grep -A2 exported`; exportable `activity`/`service`/`receiver` → launch-parameter injection.

## IPA / desktop

- Unpack the IPA with `unzip app.ipa`; use `strings`/`otool` on the Mach-O; for Flutter look for `flutter_engine` signatures;
- Electron: unpack `app.asar` (`npx asar extract`) → find the preload and the IPC surface;
- Binaries: `strings -n8` to find URLs/keys; `radare2/Cutter`, `ghidra` to decompile (install host tools as needed).

## Common mobile vulnerability verification

| Vulnerability | Verification method |
|---|---|
| Hard-coded keys | Extract AK/SK/token from the package → call the API directly (L3 if you can list data / call endpoints) |
| Unauthenticated / IDOR APIs | Take the endpoint from reversing → call it without a token → business data returned |
| Exported components | `adb shell am start -n pkg/.Activity --es key value` to verify it launches and accepts parameters |
| Certificate-pinning bypass | Only against your own test build (Frida/objection), never a third party's production; proving MITM is enough |
| WebView injection | A deep-link parameter reaching `loadUrl`/`addJavascriptInterface` → build the URL to verify |
| Backup/debug | `android:allowBackup=true` → `adb backup` to export data; `debuggable=true` |

## From the client back to the server

- The endpoints/parameters/signing algorithm recovered from reversing are **the key to testing the server**:
  reproduce the signature in a script → hit the API directly for IDOR/injection (far faster than tapping in the app);
- Client-side checks (signature/encryption) are usually not enforced on the server — the point is to verify whether the server really checks;
- Record the endpoint inventory as a fact and hand it to `api-security-testing`.

## Tools and boundaries

- Tools: jadx/apktool/frida/objection/radare2/ghidra (install as needed on the host environment page);
- Reverse only authorized targets' packages; do not crack paywalls/copyright protection for non-testing purposes;
- Certificate-pinning bypass only against your own test environment; on production targets do only the minimal proof of "can read the traffic".
