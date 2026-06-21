---
name: mobile-app-instrumentation
description: Dynamic instrumentation of iOS/Android apps via Frida, Objection, r2frida, and Introspy; runtime SSL pinning bypass, jailbreak/root detection bypass, native library hooking, and runtime secrets extraction.
origin: github-trending-2026
version: 1.0.0
compatibility: Claude Code, Claude Agent SDK
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
metadata:
  domain: mobile-deep
  category: mobile-deep
  tool_count: 13
  guide_count: 1
  mitre: "T1623-Mobile Adware, T1518-Software Discovery, T1406-Defacement, T1627.001-Adversary-in-the-Mobile-Device, T1437-Application Layer Protocol"
  keywords: [frida, objection, r2frida, introspy, instrumentation, ssl-pinning-bypass, jailbreak-detection, keychain, keystore, ios, android]
---

# Skill: Mobile App Instrumentation — Runtime Exploitation of iOS/Android Applications

> **Supplementary Files**:
> - `payloads.md` — 18 instrumentation sections with 60+ Frida JS scripts, Objection CLI one-liners, r2frida bridges, and runtime manipulation recipes (SSL pinning bypass, jailbreak/root detection bypass, anti-debug bypass, keychain/keystore dumping, native lib instrumentation, crypto tracing, WebView manipulation, anti-Frida evasion, and blue-side detection patterns)
> - `test-cases.md` — 12 structured test cases (TC-MI-001 .. TC-MI-012) covering environment bring-up, iOS/Android app acquisition, Frida SSL pinning bypass, Objection runtime exploration, keychain/keystore dumping, jailbreak detection bypass, anti-debug bypass, r2frida native lib analysis, crypto tracing, and anti-Frida detection bypass
> - `guides/mobile-app-instrumentation-playbook.md` — End-to-end operational playbook (iOS/Android runtime model, instrumentation lab build-out on jailbroken iOS / Magisk-rooted Android, instrumentation workflow, real-world case studies of Instagram cookie hijack, Snapchat jailbreak detection history, Uber cert pinning evolution, TikTok keystore bypass, and defense patterns including Play Integrity API and iOS App Attest)

## Summary

Mobile app instrumentation is the **runtime** counterpart to static mobile-app analysis. Where `mobile-security` reads the `Info.plist`, the `AndroidManifest.xml`, the binary's strings, and the Smali bytecode to discover *what the app could do*, this skill attaches a live Frida/Objection/r2frida bridge to a running process and observes *what the app actually does* at execution time — then forces it to behave otherwise. The operator spins up a jailbroken iOS device (checkm8 on A7-A11 or newer arm64e on A12+ with appropriate exploits) or a Magisk-rooted Android device (Android 13/14/15), acquires the app binary (decrypted IPA on iOS via Clutch/iPAA/bfinject; APK pull on Android via `adb shell pm path`), performs static triage with `jadx`/`apktool`/`radare2`/`ghidra` to locate the classes and functions of interest, then attaches Frida to hook arbitrary Java/Kotlin methods, Objective-C/Swift methods, and native exported functions. With those hooks in place, the operator can dump the iOS keychain (`ios keychain dump`), enumerate and manipulate the Android Keystore (`android keystore`), bypass SSL pinning at runtime (Frida's `bypass_ssl_pinning.js` lineage or Objection's `android sslpinning disable` / `ios sslpinning disable`), defeat jailbreak/root detection by hooking the detection routines to return `false`, defeat anti-debug routines (ptrace, sysctl, `debug-trace`), trace cryptographic operations (CC/CryptoKit on iOS; `javax.crypto.*` on Android), exploit WebView JavaScript bridges by invoking private bridge methods at runtime, and extract secrets (tokens, OAuth refresh tokens, biometric-gated keys) that the app would otherwise never write to disk. The discipline maps to MITRE ATT&CK Mobile T1623 (Mobile Adware), T1518 (Software Discovery), T1406 (Defacement), and T1627.001 (Adversary-in-the-Mobile-Device). Real-world engagements include bypassing Instagram certificate pinning to hijack session cookies, defeating Snapchat's evolving jailbreak detection lineage, bypassing Uber's multi-layer certificate pinning, and extracting TikTok's Keystore-attested secrets. Reference implementations: Frida (~19.7k stars, industry-standard), Objection (SensePost), r2frida (radare2 + Frida bridge), Introspy (iOS/Android tracer), Cycript (legacy iOS), iPAA/Clutch/bfinject (iOS decryption), jtool2, radare2, ghidra, jadx, apktool.

**Tools**: Frida, Objection, r2frida, Introspy, Cycript, iPAA, Clutch, bfinject, jtool2, radare2, ghidra, jadx, apktool

**Domain**: mobile-deep

**Mappings**: MITRE ATT&CK Mobile T1623 (Mobile Adware), T1518 (Software Discovery), T1406 (Defacement), T1627.001 (Adversary-in-the-Mobile-Device — Device Administrator), T1437 (Application Layer Protocol — TLS interception); OWASP MASVS V6 (Cryptography), V7 (User Authentication), V8 (Network Communication), V9 (Platform Interaction); OWASP MA5 (Insecure Communication — pinning); OWASP MASTG MASVS-NETWORK-1, MASVS-RESILIENCE-1..13

## Differentiation

This skill is **explicitly distinct** from `mobile-security`. Both deal with iOS/Android application assessment, but the operating mode is completely different.

| Aspect | `mobile-security` (existing skill) | `mobile-app-instrumentation` (this skill) |
|------|--------------------------------------|--------------------------------------------|
| **Operating mode** | Static — reads config, manifest, bytecode | Runtime — attaches to live process |
| **Primary inputs** | `Info.plist`, `AndroidManifest.xml`, Smali, strings, entitlements | Live process memory, method invocations, native calls |
| **Tooling** | `jadx`, `apktool`, `mob-sf`, `iGoat`, static analyzers | `frida`, `objection`, `r2frida`, `introspy` |
| **What it proves** | *What the app could do* (potential weakness) | *What the app actually does* at runtime (live exploitation) |
| **Typical finding** | "Hardcoded API key in `strings.xml`" or "Cleartext traffic allowed" | "Bypassed SSL pinning and exfiltrated the session cookie in real time" |
| **Device requirement** | None — analysis is offline | Jailbroken iOS / rooted Android device |
| **Defender signal** | Build-time config / lint | Runtime self-checks, SafetyNet, App Attest |
| **MITRE mapping** | MASVS static violations | T1627.001 — Adversary-in-the-Mobile-Device |

**Coexistence model**: The two skills compose. A typical engagement starts with `mobile-security` static triage to identify candidates (which classes handle SSL pinning? which native lib implements anti-debug?), then transitions to this skill to actually bypass and exploit those candidates at runtime. Use `mobile-security` to scope; use this skill to demonstrate.

**Difference from `reverse-engineering`**: `reverse-engineering` covers the binary-reversing discipline in general (ELF, PE, Mach-O, JVM bytecode). This skill is the mobile-runtime specialization — we lean on `jadx`/`ghidra`/`radare2` for static triage, but the deliverable here is a *runtime* finding produced by an instrumented hook, not a static disassembly.

**Difference from `network-sniffing-mitm`**: That skill intercepts wire traffic with mitmproxy/Burp as a network element. When the app implements certificate pinning, that interception fails — and that is precisely when you pivot to this skill: instrument the app to disable pinning at runtime, then `network-sniffing-mitm` resumes. The skills form the standard two-step attack chain against any pinned mobile backend.

## Use Cases

- **SSL pinning bypass for MITM interception**: When a target mobile app pins its backend TLS certificate (the modern default for banking, social, and enterprise apps), network-layer interception via mitmproxy/Burp fails with a TLS handshake error. Instrument the app at runtime to disable pinning — either with a generic Frida script that hooks all known pinning implementations (`AFSecurityPolicy`, `NSURLSessionDelegate`, `TrustKit` on iOS; `OkHttp CertificatePinner`, `X509TrustManager`, `Network Security Config` on Android) or with the Objection one-liner `android sslpinning disable` / `ios sslpinning disable`. Pairs directly with `network-sniffing-mitm`.
- **Jailbreak / root detection bypass**: Modern apps refuse to run (or silently degrade functionality) if they detect a jailbreak or root. Instrument the detection routines — typically `fcntl(path, F_GETPATH)` checks against `/Applications/Cydia.app`, `fork()` probes, `dyld` env-var checks on iOS; `RootBeer`, `/system` writable checks, `su` binary probes, `ro.debuggable`, `Magisk Hide`/`Zygisk` detection on Android — and force them to return the clean-device answer. This is the entry gate to all other instrumentation on a real device.
- **In-app crypto tracing**: Trace every cryptographic primitive the app invokes — `CCCrypt`, `CC_MD5`, `CCHmac`, `CryptoKit.SHA256` on iOS; `javax.crypto.Cipher`, `javax.crypto.Mac`, `java.security.MessageDigest` on Android — and dump the plaintext, key, IV, and ciphertext for every operation. Recovers protocol-level secrets (signed-request HMACs, encrypted local-storage blobs, DRMs) without needing the source.
- **iOS Keychain extraction**: Use Objection's `ios keychain dump` or `keychain-dumper` to enumerate every keychain item the app has stored, including OAuth refresh tokens, biometric-gated keys (if `kSecAttrAccessibleWhenUnlocked` rather than `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`), and proprietary session secrets. Pairs with `ios nsuserdefaults get` and `ios nsurlsession grab` for a complete at-rest-and-in-flight secret inventory.
- **Android Keystore manipulation**: Hook `android.security.keystore` and `java.security.KeyStore` to inspect entries, force key export (when the app does not enforce hardware attestation), bypass biometric gates (force `BiometricPrompt` callbacks to return `AUTHENTICATION_SUCCESSFUL`), and trace every signing/decryption operation. Used to recover keys protected only by software attestation and to demonstrate biometric bypasses.
- **Native library reversing via r2frida**: For apps that offload secrets or anti-debug logic to a native `.so` / `.dylib` (common in DRM, mobile-game telemetry, and ad-fraud SDKs), attach r2frida to enumerate exports (`iE`), seek into native memory (`s`), decompile (`pdg`), and place Frida `Interceptor.attach` hooks on exported symbols. Bridges the Java/Kotlin surface and the C/C++ surface into a single live session.
- **Anti-debug / anti-tamper bypass**: Apps that call `ptrace(PT_DENY_ATTACH)` on iOS or check `/proc/self/status` for `TracerPid` on Android refuse to run under Frida or a debugger. Hook `ptrace` to return 0, hook `sysctl` to hide the parent PID, hook the `TracerPid` string read to return `0`. The standard prelude to any deeper instrumentation on hardened apps.
- **Runtime API hooking for arbitrary methods**: The primitive that underlies everything else — pick any Java class (`Java.use("com.example.LoginManager").login.implementation = ...`), any Objective-C class (`ObjC.classes.LoginController["- login:"](args[2])`), any native export (`Module.findExportByName(null, "open")`) and replace its implementation, log arguments and return values, or replay with mutated inputs. Enables every other use case above.

## Core Tools

| Tool | Purpose | Command / Usage |
|------|---------|-----------------|
| **Frida** | Industry-standard dynamic instrumentation toolkit (JavaScript bridge to a live process on iOS/Android/Windows/Linux/macOS). ~19.7k stars. | `frida -U -f com.example.app -l hook.js --no-pause`; `frida-ps -Uai`; `frida-trace -U -i "open*" -f com.example.app` |
| **Objection** (SensePost) | Runtime exploration toolkit on top of Frida — provides a REPL with high-level commands for SSL pinning, keychain, keystore, hooking, etc. | `objection -g com.example.app explore`; then `android sslpinning disable`, `ios keychain dump`, `android hooking list activities`, etc. |
| **r2frida** | radare2 ↔ Frida bridge — drive r2 commands against a live process; inspect and hook native code in-process. | `r2 'frida://spawn/attach/com.example.app'` then `iE` (exports), `dc` (continue), `=!?` (help) |
| **Introspy** (iSEC Partners) | iOS/Android black-box tracer — generates a Frida-based hook set that logs every crypto/IPC/keychain call and produces a database + visualizer. | `introspy-cli -p com.example.app -o trace.db`; `introspy-ui trace.db` (web viewer) |
| **Cycript** (saurik, legacy iOS) | Objective-C++ introspection runtime — injects into a process and lets you evaluate ObjC expressions live. Predates Frida on iOS; still useful on legacy iOS < 13. | `cycript -p SpringBoard` then `UIApp.keyWindow.recursiveDescription().toString()` |
| **iPAA** (iOS App Extractor) | iOS app decryption / IPA extraction — pulls the FairPlay-decrypted binary from memory on a jailbroken device. | `iPAA` (interactive on device) → select app → produces decrypted `.app` bundle |
| **Clutch** (Khelandros / NinjaRIP) | iOS app decryption — decrypts apps in-memory using `PT_TRACE` and produces a decrypted IPA suitable for class-dump and Frida. | `Clutch -d com.example.app` or `Clutch -i` (interactive) |
| **bfinject** (Barnacle Nguyen) | iOS tweak injection + app decryption — older but still cited; used for Cycript/Frida injection on iOS 11 era. | `bfinject -p com.example.app -l frida-cycript` |
| **jtool2** (Stefan Esser / Oren) | Modern Mach-O analysis CLI — replaces `otool` and `class-dump-z` for iOS binary triage; reads LC segments, ObjC metadata, entitlements, codesign blobs. | `jtool2 -L AppBinary`; `jtool2 -objc AppBinary`; `jtool2 --ent AppBinary` |
| **radare2** | Cross-platform reverse-engineering framework — disassembles iOS Mach-O and Android ELF (.so) binaries; combined with r2frida for live analysis. | `r2 -A libNative.so`; `aaa; afl; s sym.Java_com_example_Native_doStuff; pdf` |
| **ghidra** | NSA reverse-engineering suite — decompiler for large iOS/Android native binaries; produces readable C-like pseudocode for `sub_XXXX` routines. | `ghidraRun` → import binary → Auto-Analyze → open in CodeBrowser |
| **jadx** | Android Dex → Java decompiler — the de-facto starting point for any APK triage; reads multidex, smali, resources. | `jadx -d out/ app.apk`; `jadx --show-bad-code app.apk` |
| **apktool** | Android APK decode/rebuild — extracts `AndroidManifest.xml`, smali, and `res/`; used to patch apps pre-instrumentation (e.g., to add a `debuggable=true` flag). | `apktool d app.apk -o out/`; `apktool b out/ -o patched.apk` |

## Methodology

### Phase 1 — App Acquisition

Before any instrumentation, the operator needs the app binary on disk:

- **iOS**: The App Store delivers FairPlay-encrypted binaries. On a jailbroken device, use `Clutch -d <bundle-id>` or `iPAA` to dump the decrypted binary from memory into a usable `.app` bundle. For development-signed apps (TestFlight, sideloaded), no decryption is needed. Document the iOS version (iOS 16/17/18), jailbreak used (palera1n / checkra1n / Dopamine), and whether the app uses arm64e.
- **Android**: `adb shell pm path com.example.app` returns the path to the base.apk + any split APKs. Pull each with `adb pull`. For obfuscated/packed apps (Bangcle, Jiagu, DEX protector), dump from memory at runtime or use `frida-dexdump`.

### Phase 2 — Environment Preparation

- **iOS device**: Jailbroken (checkm8 for A7-A11 via palera1n/checkra1n; arm64e via Dopamine on A12-A17 / iOS 15-18). Install `frida-server` matching the device architecture; confirm with `frida-ps -U` (should list device processes).
- **Android device**: Magisk-rooted (or LineageOS rooted); `frida-server` started as root in background. Android 13/14/15 may also need `Zygisk` + `LSPosed` for in-process injection. Confirm with `frida-ps -U`.
- **Host**: Python 3.11+, `pip install frida-tools objection`. Optional: `radare2`, `ghidra`, `jadx`.

### Phase 3 — Static Triage

Run the binary through `jadx` (Android) or `jtool2` / `ghidra` (iOS) to identify:

- **SSL pinning implementations** — search for `CertificatePinner`, `X509TrustManager`, `AFSecurityPolicy`, `TrustKit`, `SecTrustEvaluate`.
- **Jailbreak/root detection** — search for `Cydia`, `sbin`, `/su`, `RootBeer`, `fcntl F_GETPATH`.
- **Anti-debug** — search for `ptrace`, `sysctl`, `TracerPid`, `debug-trace`.
- **Crypto primitives** — search for `CCCrypt`, `Cipher.getInstance`, `MessageDigest`.
- **Native libraries** — list `.so` / `.dylib` in `lib/`, note JNI exports.

Triage output is a target list — not yet findings, but a hook candidate list.

### Phase 4 — Instrumentation

Attach Frida (or Objection) and load the hook candidates:

- `frida -U -f com.example.app -l hook.js --no-pause` for spawn-and-attach.
- `objection -g com.example.app explore` for the REPL workflow with high-level commands.
- `r2 'frida://spawn/com.example.app'` for native-symbol-driven work.

Iterate over candidates: pinning, jailbreak, anti-debug, crypto, keychain. Each hook logs to a file (Frida `send()` + Python sink) for later replay and evidence capture.

### Phase 5 — Runtime Manipulation

With hooks in place, manipulate the live process:

- **Disable pinning** → re-launch mitmproxy and capture the TLS-decrypted traffic.
- **Bypass jailbreak** → trigger gated features (e.g., banking transfers on jailbroken iOS).
- **Dump keychain / keystore** → harvest tokens, biometric-gated keys, OAuth refresh tokens.
- **Force crypto keys** → replay requests offline with extracted HMAC/AES keys.
- **Replay JWTs** extracted from the keychain against the backend with `curl` for a clean client-to-server compromise chain.

Document every step: hook script, log output, screenshot, and the downstream consequence (decrypted HTTPS, extracted token, bypassed gate). This evidence packet is the deliverable.

## Practical Steps

### Example 1 — Frida SSL Pinning Bypass (Generic Script)

Save as `bypass_ssl_pinning.js`:

```javascript
// bypass_ssl_pinning.js
// Generic SSL pinning bypass covering common iOS and Android pinning APIs.
// Usage: frida -U -f com.example.app -l bypass_ssl_pinning.js --no-pause

setTimeout(function () {
  // ---- Android: OkHttp CertificatePinner ----
  if (Java.available) {
    Java.perform(function () {
      try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
          console.log('[+] OkHttp CertificatePinner.check() bypassed');
          return;
        };
      } catch (e) { console.log('[-] OkHttp not present: ' + e); }

      // ---- Android: X509TrustManager ----
      try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
          name: 'org.owasp.TrustAll',
          implements: [X509TrustManager],
          methods: {
            checkClientTrusted: function () {},
            checkServerTrusted: function () {},
            getAcceptedIssuers: function () { return []; }
          }
        });
        SSLContext.init.overload(
          '[Ljavax.net.ssl.KeyManager;',
          '[Ljavax.net.ssl.TrustManager;',
          'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
          console.log('[+] SSLContext.init() replaced with trust-all');
          this.init(km, [TrustManager.$new()], sr);
        };
      } catch (e) { console.log('[-] X509TrustManager hook failed: ' + e); }
    });
  }

  // ---- iOS: SecTrustEvaluate ----
  if (ObjC.available) {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        // Force kSecTrustResultProceed = 1
        Memory.writePointer(result, ptr(1));
        console.log('[+] SecTrustEvaluate() forced to proceed');
        return 0; // errSecSuccess
      }, 'int', ['pointer', 'pointer']));
    }
    // Also hook the Swift-level URLSessionDelegate if present (left as exercise).
  }
}, 0);
```

Run with `frida -U -f com.example.app -l bypass_ssl_pinning.js --no-pause`. All TLS errors should disappear — re-arm mitmproxy and the traffic flows decrypted.

### Example 2 — Objection Runtime Exploration

```bash
# Spawn the target under objection's REPL
objection -g com.example.app explore

# Inside the REPL — explore the app surface:
android hooking list classes
android hooking search classes keyword
android hooking list activities
android hooking list services
android hooking watch class_method com.example.LoginManager.login --dump-args --dump-return

# Disable SSL pinning in-process
android sslpinning disable
ios sslpinning disable

# Dump secrets at rest
ios keychain dump
ios nsuserdefaults get
android keystore list
android root disable

# Bypass biometrics
android biometric disable
```

Objection is the fastest path from "I have the app" to "I have the runtime surface" — use it for triage, drop down to raw Frida for custom hooks.

### Example 3 — r2frida Native Library Analysis

```bash
# Launch r2 against the live process
r2 'frida://spawn/com.example.app'

# Inside r2 — enumerate native modules:
[0x00000000]> iE~libnative
# Seek into the native lib and list exports:
[0x00000000]> s sym.Java_com_example_Native_nativeSign
[0xdeadbeef]> pdf   # disassemble
[0xdeadbeef]> =?/ip # inject a Frida hook for this export via the bridge

# Detach and resume:
[0x00000000]> dc
```

r2frida lets you do static and dynamic analysis in one session — invaluable for understanding a native routine before you commit to a Frida hook.

### Example 4 — Android Keystore Hook for Crypto Tracing

```javascript
// trace_keystore.js — log every Cipher.init + doFinal with key + plaintext
Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');

  Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    console.log('[Cipher.init] mode=' + mode + ' key=' + key.getEncoded());
    return this.init(mode, key);
  };

  Cipher.doFinal.overload('[B').implementation = function (input) {
    var out = this.doFinal(input);
    console.log('[Cipher.doFinal] in=' + bytesToHex(input) + ' out=' + bytesToHex(out));
    return out;
  };

  function bytesToHex(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
    return s;
  }
});
```

## Defense Perspective

Defenders should assume any non-server-side check is bypassable with sufficient time. The mitigation strategy is layered runtime defenses and server-side attestation:

- **iOS App Attest / DeviceCheck**: Server validates an Apple-signed attestation that the request originated from a genuine app instance on a non-jailbroken device. Defeats runtime instrumented replays.
- **Android Play Integrity API** (successor to SafetyNet): Server validates a Google-signed integrity verdict covering app authenticity, device integrity (CTS-passing, no known root), and account licensing. Combined with `Standard` or `Strong` integrity tiers, defeats most Frida bypasses.
- **Multi-layer jailbreak / root detection**: Combine `fcntl`/`dyld`/`fork` checks on iOS and `RootBeer` + `/proc/self/maps` + `/system/bin/su` + `Magisk Hide` detection on Android. Detect Frida by scanning `/proc/self/maps` (Android) or `dyld_image_count` (iOS) for `frida-agent` / `libfrida`.
- **Runtime self-integrity checks**: Periodically checksum the app's `.text` section and detect Frida stalker / interceptor trampolines by walking `dyld` / dlopen tables.
- **Hardware-attested keys**: On Android, generate keys inside the hardware-backed Keystore (`setUserAuthenticationRequired(true)` + `setAttestationChallenge`) so even a hooked Cipher cannot export them.
- **Certificate pinning with multiple pins + fallback**: Pin the leaf, intermediate, and CA; ship a pin rotation channel; have a documented fail-closed policy (the app must abort on pin failure rather than degrade to system trust).
- **Defense-in-depth logging**: Report integrity failures back to the server; rate-limit or revoke compromised sessions even if the client-side gate is bypassed.

A thorough mobile-app red-team deliverable should be paired with a mitigation mapping table: each finding → corresponding MASVS-RESILIENCE control → recommended runtime defense. See `guides/mobile-app-instrumentation-playbook.md` Section "Defense Patterns" for the full mapping.

## References

- Frida documentation — https://frida.re/docs/home/
- Objection wiki (SensePost) — https://github.com/sensepost/objection/wiki
- r2frida — https://github.com/nowsecure/r2frida
- NowSecure Frida tutorials — https://www.nowsecure.com/blog/
- @dki Frida iOS bootcamp (YouTube + GitHub)
- Apple Platform Security Guide — https://support.apple.com/guide/security/welcome/web
- Android Security Team blog — https://security.googleblog.com/
- OWASP MASTG (Mobile Application Security Testing Guide) — https://mas.owasp.org/MASTG/
- MITRE ATT&CK for Mobile — https://attack.mitre.org/matrices/enterprise/cloud/
- AppSec Santa 2026 — Frida deep dive (annual review)
