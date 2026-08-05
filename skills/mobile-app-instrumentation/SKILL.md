---
name: mobile-app-instrumentation
description: Dynamic instrumentation of iOS/Android apps via Frida, Objection, r2frida, and Introspy; runtime SSL pinning bypass, jailbreak/root detection bypass, native library hooking, and runtime secrets extraction.
origin: github-trending-2026
version: "0.2.0.2"
compatibility: Claude Code, Claude Agent SDK
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
metadata:
  domain: mobile-deep
  category: mobile-deep
  tool_count: 13
  guide_count: 2
  mitre: "T1623-Mobile Adware, T1518-Software Discovery, T1406-Defacement, T1627.001-Adversary-in-the-Mobile-Device, T1437-Application Layer Protocol"
  keywords: [frida, objection, r2frida, introspy, instrumentation, ssl-pinning-bypass, jailbreak-detection, keychain, keystore, ios, android]
  last_reviewed: "2026-07-26"
---

# Skill: Mobile App Instrumentation — Runtime Exploitation of iOS/Android Applications

> **Supplementary Files**:
> - `payloads.md` — 18 instrumentation sections with 60+ Frida JS scripts, Objection CLI one-liners, r2frida bridges, and runtime manipulation recipes (SSL pinning bypass, jailbreak/root detection bypass, anti-debug bypass, keychain/keystore dumping, native lib instrumentation, crypto tracing, WebView manipulation, anti-Frida evasion, and blue-side detection patterns)
> - `test-cases.md` — 12 structured test cases (TC-MI-001 .. TC-MI-012) covering environment bring-up, iOS/Android app acquisition, Frida SSL pinning bypass, Objection runtime exploration, keychain/keystore dumping, jailbreak detection bypass, anti-debug bypass, r2frida native lib analysis, crypto tracing, and anti-Frida detection bypass
> - `guides/mobile-app-instrumentation-playbook.md` — End-to-end operational playbook (iOS/Android runtime model, instrumentation lab build-out on jailbroken iOS / Magisk-rooted Android, instrumentation workflow, real-world case studies of Instagram cookie hijack, Snapchat jailbreak detection history, Uber cert pinning evolution, TikTok keystore bypass, and defense patterns including Play Integrity API and iOS App Attest)
> - `guides/mobile-app-instrumentation-ios-android-deep.md` — Advanced deep dive: iOS instrumentation internals (frida-server / frida-gadget / USBMUXD, SSL Kill Switch 3, BoringSSL bypass, Shadow / A-Bypass / Liberty / Choicy jailbreak detection defeat, Keychain dump, URL scheme hijack, App Attest bypass research, PAC on A12+, CoreTrust CVE-2023-41974 / kfd exploit chain), Android instrumentation (Frida gadget injection modes, Magisk + Zygisk + LSPosed, RASP bypass recipe for PGY / Promon / Arxan, Flutter reverse via reflutter + BoringSSL, React Native / Hermes via hbctool), high-value CVE targets (CVE-2024-0044 run-as sandbox escape, Play Integrity bypass via pif), the full SSL Pinning Bypass Catalog decision matrix (15+ libraries mapped to bypass technique), modern obfuscation defeat (OLLVM string deobfuscation, control-flow flattening via angr / HexRaysDeob / ghidra-emotet, radare2 native arm64 flow), and lab setup (Corellium, Android Studio Emulator + Frida, Genymotion, Objection tunneling)

## Summary

Mobile app instrumentation is the **runtime** counterpart to static mobile-app analysis. Where `mobile-security` reads the `Info.plist`, the `AndroidManifest.xml`, the binary's strings, and the Smali bytecode to discover *what the app could do*, this skill attaches a live Frida/Objection/r2frida bridge to a running process and observes *what the app actually does* at execution time — then forces it to behave otherwise. The operator spins up a jailbroken iOS device (checkm8 on A7-A11 or newer arm64e on A12+ with appropriate exploits) or a Magisk-rooted Android device (Android 13/14/15), acquires the app binary (decrypted IPA on iOS via Clutch/iPAA/bfinject; APK pull on Android via `adb shell pm path`), performs static triage with `jadx`/`apktool`/`radare2`/`ghidra` to locate the classes and functions of interest, then attaches Frida to hook arbitrary Java/Kotlin methods, Objective-C/Swift methods, and native exported functions. With those hooks in place, the operator can dump the iOS keychain (`ios keychain dump`), enumerate and manipulate the Android Keystore (`android keystore`), bypass SSL pinning at runtime (Frida's `bypass_ssl_pinning.js` lineage or Objection's `android sslpinning disable` / `ios sslpinning disable`), defeat jailbreak/root detection by hooking the detection routines to return `false`, defeat anti-debug routines (ptrace, sysctl, `debug-trace`), trace cryptographic operations (CC/CryptoKit on iOS; `javax.crypto.*` on Android), exploit WebView JavaScript bridges by invoking private bridge methods at runtime, and extract secrets (tokens, OAuth refresh tokens, biometric-gated keys) that the app would otherwise never write to disk. The discipline maps to MITRE ATT&CK Mobile T1623 (Mobile Adware), T1518 (Software Discovery), T1406 (Defacement), and T1627.001 (Adversary-in-the-Mobile-Device). Real-world engagements include bypassing Instagram certificate pinning to hijack session cookies, defeating Snapchat's evolving jailbreak detection lineage, bypassing Uber's multi-layer certificate pinning, and extracting TikTok's Keystore-attested secrets. Reference implementations: Frida (~19.7k stars, industry-standard), Objection (SensePost), r2frida (radare2 + Frida bridge), Introspy (iOS/Android tracer), Cycript (legacy iOS), iPAA/Clutch/bfinject (iOS decryption), jtool2, radare2, ghidra, jadx, apktool.

**Tools**: Frida, Objection, r2frida, Introspy, Cycript, iPAA, Clutch, bfinject, jtool2, radare2, ghidra, jadx, apktool

**Domain**: mobile-deep

**Mappings**: MITRE ATT&CK Mobile T1623 (Mobile Adware), T1518 (Software Discovery), T1406 (Defacement), T1627.001 (Adversary-in-the-Mobile-Device — Device Administrator), T1437 (Application Layer Protocol — TLS interception); OWASP MASVS V6 (Cryptography), V7 (User Authentication), V8 (Network Communication), V9 (Platform Interaction); OWASP MA5 (Insecure Communication — pinning); OWASP MASTG MASVS-NETWORK-1, MASVS-RESILIENCE-1..13

## Detection Methods

### Mobile App Tampering
- **Frida server presence**: Process running on port 27042; `frida-server` binary in `/data/local/tmp/`.
- **Jailbreak detection bypass**: Apps detecting jailbreak / root; bypass attempts logged.
- **Runtime instrumentation**: Process with injected library (`frida-gadget`, `Xposed`).
- **SSL pinning bypass**: Apps accepting user-supplied CA; bypass of cert pinning.

### SIEM Detection Rules
- **Splunk SPL (mobile)**: `index=mobile sourcetype=frida | stats count by process | sort -count`
- **Mobile Threat Defense (MTD)**: Lookout, Zimperium, Pradeo MTD detection.

## Defense Evasion Techniques

### Frida Stealth
- **Random port**: Run Frida on non-default port (not 27042).
- **Magisk Hide / Zygisk**: Hide Frida from package managers; defeats basic detection.
- **Strong/weak modes**: Frida strong mode bypasses most detection (slower, harder to detect).
- **Gadget mode**: Use `frida-gadget` as embedded library; no frida-server process.

### Jailbreak Stealth
- **Root hide**: Magisk DenyList; hide root from specific apps.
- **Systemless root**: No modification to /system partition; harder to detect.
- **ShadowFlutter / Liberty Lite** (iOS): Bypass popular jailbreak detection libraries.

### SSL Pinning Bypass Stealth
- **Objection**: Automate pinning bypass; uses Frida under hood.
- **Custom trust manager**: Inject custom `X509TrustManager`; allows any cert.
- **Network proxy with pinning bypass**: Burp + mobile companion app; bypasses pinning transparently.

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

### iOS Instrumentation Stack

The iOS instrumentation stack spans multiple layers — the operator must know which layer a given app uses to choose the right bypass. This stack is documented in detail in `guides/mobile-app-instrumentation-ios-android-deep.md`.

- **Frida runtime variants**: `frida-server` (daemon, requires jailbreak, exposes `127.0.0.1:27042` via USBMUXD); `frida-gadget` (`FridaGadget.dylib` patched into the app's `.app` bundle and re-signed — works on non-jailbroken devices and evades `frida-server` detection). On A12+ arm64e devices, only the arm64e build of `frida-server` / `frida-gadget` can attach to native arm64e apps; PAC (Pointer Authentication Codes) forces this architecture match.
- **SSL Kill Switch 3** (https://github.com/nicklama/ssl-kill-switch3) — system-wide pinning bypass at `SecTrustEvaluate` + `NSURLSession`. Lowest-effort bypass for iOS 15-17, but does NOT cover BoringSSL, custom `URLSessionDelegate`, or `Network.framework`-based pins. Install via Chariz repo on Dopamine jailbreak.
- **BoringSSL / libssl bypass** — Flutter iOS apps and any app using `cronet`/`grpc` ship a static-linked BoringSSL. Bypass via `Interceptor.replace` on `SSL_set_custom_verify` / `SSL_CTX_set_custom_verify` / `SSL_verify_peer_chain` after pattern-scanning `libflutter.so` for the BoringSSL API pointer table.
- **objection advanced patterns** — `ios hooking set return_value "-[SecurityManager isJailbroken]" false` is the most powerful jailbreak-detection bypass primitive; `ios hooking watch class UrlSessionDelegate` enumerates a class's full method surface; `ios bundles list_frameworks` confirms whether `TrustKit`, `AFNetworking`, or `CryptoKit` is linked.
- **Jailbreak detection bypass tools** (per-app, configurable):
  - **Shadow** (opa334) — full environment simulation; the operator's default for hardened apps. Replaces the entire userspace environment the app sees (hides `/Applications`, blocks `dyld` injection, fakes `sysctl` returns, scrubs `task_get_exception_ports`).
  - **A-Bypass** (repo.co.kr, paid) — hooks every known JB-detection syscall (`fork`, `stat`, `access`, `lstat`, `open`, `dlopen`, `sysctl`, `ptrace`, `task_get_exception_ports`, `dyld_image_count`, `getppid`).
  - **Liberty Lite / Liberty Duo** (level3tjg.xyz, free) — covers iOS 13-16 banking apps.
  - **Choicy** (opa334) — selectively disable tweaks per-app; many banking apps detect any injected tweak, so you disable everything except Shadow/A-Bypass for the target app.
- **iOS high-value targets** — Keychain dump (`keychain-dumper` root-run via `SecItemCopyMatching` or objection's `ios keychain dump`), URL scheme hijack (`Info.plist` `CFBundleURLTypes` + openURL validation), App Attest partial bypass (replay / dev-tier acceptance — the cryptographic chain is NOT bypassable as of 2026), PAC constraints on A12+ (use arm64e builds of frida-server), CoreTrust bypass via CVE-2023-41974 / kfd exploit chain (iOS 16.5-16.6.1 only).

### Android Instrumentation Stack

The Android stack has its own dynamics — gadget injection for non-rooted devices, Magisk + Zygisk + LSPosed as a Frida-invisible alternative, and a separate RASP-bypass discipline.

- **Frida gadget injection modes** — patch `libfrida-gadget.so` into `lib/<abi>/` of a decompiled APK via apktool + LIEF, configure via `libfrida-gadget.config.so`:
  - `"listen"` — binds `127.0.0.1:27042`, connect via `frida -H` after `adb forward`. Default, most flexible.
  - `"script"` — auto-loads `libfrida-gadget.script.so` (a JS file with `.so` suffix to fool APK packers). Stealth: no listening port.
  - `"connect"` — connects out to a remote frida-server. Useful for device-farm labs.
  Gadget injection is the operator's default for non-rooted engagements (corporate-managed devices) and for stealth against RASP that detects `frida-server`.
- **Magisk + Zygisk + LSPosed** — modern root stack. Magisk (root + Zygisk injection); Zygisk "Enforce DenyList" hides root from specified apps; LSPosed (modern Xposed) provides a Frida-invisible Java/Kotlin hooking path. Many RASP products (PGY, Promon) detect Frida by port/process/maps but not Xposed/LSPosed — when Frida is detected, drop to LSPosed module development.
- **RASP bypass recipe** (covers PGY, Promon, Arxan, DexGuard, Verimatrix):
  1. Port-shift Frida: `./frida-server -l 0.0.0.0:13371` (defeats the `27042` port check).
  2. Rename the binary (defeats `/proc/<pid>/exe` name check).
  3. Scrub `/proc/self/maps` and `/proc/self/status` via `fopen` interceptor (defeats the `frida-agent` / `libfrida` maps scan).
  4. Rename Frida threads via `pthread_setname_np` interceptor (defeats the `gmain` / `gdbus` / `gum-js-loop` thread-name scan).
  5. Hook `Debug.isDebuggerConnected` to return `false` (defeats the debugger check).
- **Android high-value targets** — KeyStore abuse (CVE-2024-0044 `run-as` sandbox escape on Android 12-13), Play Integrity bypass via `pif` (PlayIntegrityFix) Magisk module + `MagiskHidePropsConf` for `MEETS_DEVICE_INTEGRITY` (no public bypass for `MEETS_STRONG_INTEGRITY`), content provider confusion (Drozer enumeration + Frida query logging), Intent redirection patterns (Frida hook on `startActivity` to detect nested Intents — CVE-2020-7663 Slack lineage).
- **Flutter app reverse** — `reflutter` (https://github.com/Impact-I/reflutter) patches the APK to disable BoringSSL verify and route through mitmproxy; `frida-dexdump` dumps DEX; `doldrums` / `Blutter` parsers recover Dart class hierarchy from `_kDartIsolateSnapshotInstructions`. Standard OkHttp / X509TrustManager bypass scripts do NOT work on Flutter apps because no Java network layer is involved — must bypass BoringSSL inside `libflutter.so`.
- **React Native reverse** — `apktool d` extracts `assets/index.android.bundle`; for Hermes bytecode (React Native 0.70+) use `hbctool disasm` to recover the instruction stream and string table. Runtime: hook `com.facebook.hermes.reactexecutor.HermesExecutor.callJSCallback` to log every JS → native call.

### SSL Pinning Bypass Catalog

Modern mobile apps pin TLS at multiple layers. The decision matrix below maps each pinning library to its bypass technique. Use it as the first lookup when triaging an app.

| Library / Mechanism | Platform | Detection Signature | Bypass Technique |
|---|---|---|---|
| `OkHttp CertificatePinner` | Android | `okhttp3.CertificatePinner.check` | Objection `android sslpinning disable` or hook `check()` to no-op |
| `X509TrustManager` (custom) | Android | Class implements `javax.net.ssl.X509TrustManager` | Replace with trust-all `TrustManager` via `Java.registerClass` |
| `X509TrustManagerExtensions.checkServerTrusted` | Android | `android.net.http.X509TrustManagerExtensions` | Hook `checkServerTrusted` to return empty list |
| `Network Security Config` (`<pin-set>`) | Android | `network_security_config.xml` | Hook Conscrypt's `TrustManagerImpl.checkTrustedRecursive` |
| `Conscrypt` (Play Services BoringSSL) | Android | `com.google.android.gms.conscrypt` / `com.android.org.conscrypt.TrustManagerImpl` | Hook `TrustManagerImpl.checkTrustedRecursive` |
| `BoringSSL` (Flutter `libflutter.so`) | Android/iOS | `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` in `libflutter.so` | Pattern-scan for the API and `Interceptor.replace` to disable verify |
| `BoringSSL` (cronet / grpc) | iOS/Android | Static-linked into native lib | Same Flutter pattern — pattern-scan + `Interceptor.replace` |
| `AFSecurityPolicy` (AFNetworking) | iOS | `- setSSLPinningMode:` / `- evaluateServerTrust:` | Hook `evaluateServerTrust:` to return `YES` |
| `TrustKit` (iOS) | iOS | `TSKPinningValidator.validateTrust` | Hook `validateTrust` to return success |
| `NSURLSessionDelegate` (custom) | iOS | `- URLSession:didReceiveChallenge:completionHandler:` | Hook delegate method to call completion with `useCredential` |
| `URLSession` (Swift async/await) | iOS 15+ | Swift wrapper over `URLSessionDelegate` | Same as `NSURLSessionDelegate` |
| `Network.framework` (`nw_protocol_options`) | iOS 14+ | `nw_protocol_options_create_tls` + `sec_protocol_options_set_verify_block` | Hook verify block to call `handler(true)` |
| `SecureTransport` (legacy iOS) | iOS < 13 | `SSLHandshake` / `SSLSetSessionOption` | SSL Kill Switch 3 covers system-wide |
| `WebViewClient.onReceivedSslError` | Android | Custom `WebViewClient` calls `handler.cancel()` | Hook to call `handler.proceed()` |
| `WKWebView didReceiveServerTrustChallenge` | iOS | `- webView:didReceiveServerTrustChallenge:completionHandler:` | Hook to call completion with `useCredential` |
| Custom pinning (in-house) | Both | Vendor-specific | Static triage (`jadx` / `jtool2 -objc`) → targeted Frida hook |

**Operator workflow**: identify the pinning library (search the disassembled app), match against the matrix, apply the bypass technique, verify via mitmproxy. Modern banking apps stack 2-4 pinning layers (HTTP client + OS + native SDK) — the operator must bypass all layers; bypass scripts compose without conflict. See `guides/mobile-app-instrumentation-ios-android-deep.md` Section 6 for the full decision matrix and the stacked-pinning case study.

### Modern Obfuscation Defeat

Modern mobile native libraries (banking, gaming, DRM, anti-cheat) are protected by **OLLVM** (Obfuscator-LLVM) descendants. The same techniques that appear in desktop malware (Emotet, Conti, TrickBot) appear in mobile `libNative.so` / `Native.dylib`.

- **OLLVM string deobfuscation** — encrypted strings with per-string keys, decrypted in a global constructor. Detect via Ghidra/IDA: functions with a long XOR loop over `.bss`. Bypass strategies: runtime dump via Frida `Memory.scan` of `.bss` after app launch; IDA Python / Ghidra script that pattern-matches the XOR-decryptor; hook the decryption function (`sub_XXXX`) to log decrypted plaintext.
- **Control-flow flattening (CFF)** — function body reassembled under a `switch` dispatcher with a state variable. Detect in IDA graph view: "bicycle wheel" shape. Bypass strategies: symbolic execution via [angr](https://angr.io/) recovers the original CFG; [HexRaysDeob](https://github.com/RolfRolles/HexRaysDeob) IDA plugin (Rolf Rolles) transforms CFF back to structured form in the decompiler; [ghidra_emotet](https://github.com/Avast/ghidra-emotet) Akamai script auto-reconstructs any CFF'd function.
- **IDA Python / Ghidra scripts** — for IDA Pro: identify large functions (`>0x400` bytes), count `cmp+jcc` patterns to flag dispatcher candidates. For Ghidra: use the Jython interface to scan for `XOR` instructions in long functions (string-decryptor heuristic).
- **Native arm64 reverse via radare2** — `r2 -A libNative.so`; `afl~Java_` to list JNI exports; `pdf @ sym.Java_com_example_Native_nativeSign` to disassemble; `axt @ <addr>` for cross-references; `/x` for pattern scanning. Bridge to live analysis via `=+frida://spawn/<pkg>`.
- **Virtualization-based protections** (Themis, VMProtect mobile, Inside Secure) — the function is compiled into a custom bytecode interpreter; full reversal requires identifying the interpreter's opcode table and writing a devirtualizer. Research-grade; outside the scope of a typical engagement.

See `guides/mobile-app-instrumentation-ios-android-deep.md` Section 7 for full worked examples (Frida `.bss` dump script, angr CFF recovery, IDA Python dispatcher finder, radare2 JNI flow).

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

### Defense Perspective

Defenders should assume any non-server-side check is bypassable with sufficient time. The mitigation strategy is layered runtime defenses and server-side attestation:

- **iOS App Attest / DeviceCheck**: Server validates an Apple-signed attestation that the request originated from a genuine app instance on a non-jailbroken device. Defeats runtime instrumented replays. Pair with per-session server nonce binding to prevent assertion replay; reject dev-tier attestations in production.
- **Android Play Integrity API** (successor to SafetyNet): Server validates a Google-signed integrity verdict covering app authenticity, device integrity (CTS-passing, no known root), and account licensing. Demand `MEETS_STRONG_INTEGRITY` for high-value operations (no public bypass exists as of 2026); `MEETS_DEVICE_INTEGRITY` is the realistic baseline but is bypassable via `pif` / Magisk Hide.
- **Multi-layer jailbreak / root detection**: Combine `fcntl`/`dyld`/`fork` checks on iOS and `RootBeer` + `/proc/self/maps` + `/system/bin/su` + `Magisk Hide` detection on Android. Detect Frida by scanning `/proc/self/maps` (Android) or `dyld_image_count` (iOS) for `frida-agent` / `libfrida`. Be aware of the bypass recipe (port-shift, binary rename, `/proc/self/maps` scrub, thread-rename, `Debug.isDebuggerConnected` hook) and ship counter-measures for each: monitor for renamed frida processes, scrub-resistant maps via `readlink("/proc/self/exe")` cross-checks, additional checks for Zygisk modules.
- **Runtime self-integrity checks**: Periodically checksum the app's `.text` section and detect Frida stalker / interceptor trampolines by walking `dyld` / dlopen tables. Detect objection by scanning for the `FRIDA_SCRIPT_AGENT` symbol or unusual `Java.use` patterns in ART.
- **Hardware-attested keys**: On Android, generate keys inside the hardware-backed Keystore (`setUserAuthenticationRequired(true)` + `setAttestationChallenge`) so even a hooked Cipher cannot export them. Verify the attestation certificate chain server-side against the Google Hardware Attestation root. On iOS, generate attestation keys via `DCAppAttestService` so keys live in the Secure Enclave.
- **Certificate pinning with multiple pins + fallback + native-layer enforcement**: Pin the leaf, intermediate, and CA; ship a pin rotation channel; have a documented fail-closed policy (the app must abort on pin failure rather than degrade to system trust). Stack pinning at multiple layers — HTTP client (`OkHttp CertificatePinner` / `AFSecurityPolicy`), OS (`X509TrustManager` / `SecTrustEvaluate`), and native (`BoringSSL SSL_set_custom_verify` inside a packed `libNative.so` with OLLVM control-flow flattening). Each layer raises bypass cost independently.
- **Mobile app hardening (build-time + runtime)**:
  - **Obfuscation** — apply R8/ProGuard (Android) and Swift symbol stripping + LLVM obfuscation (iOS) to slow static triage. Apply OLLVM control-flow flattening to native libraries holding secrets.
  - **Anti-tamper** — sign the APK with v2/v3 scheme; verify the signature at app startup and inside native code (detect `apktool` rebuilds that resign with a different cert). On iOS, embed `dlsym` checks for non-Apple frameworks and abort on unknown dylib load.
  - **Anti-debug** — call `ptrace(PT_DENY_ATTACH)` on iOS (defeats lldb; bypassable but raises the bar); check `/proc/self/status` `TracerPid` on Android; integrate a commercial anti-debug SDK (Promon, Arxan, Guardsquare) for high-value targets.
  - **RASP** — Runtime Application Self-Protection SDKs (Promon SHIELD, Guardsquare DexGuard, Verimatrix, PGY/Pangu) combine anti-tamper, anti-debug, anti-Frida, root/JB detection, and method-swizzling protection into a single vendor library. Be realistic about their limits — every commercial RASP has been bypassed publicly within 6-12 months of release.
  - **String encryption** — encrypt API keys, OAuth client secrets, and HMAC keys in the binary; decrypt only inside native code at runtime. Slows Frida `strings`-based secret extraction.
  - **Screenshot / screen-recording protection** — flag sensitive screens with `FLAG_SECURE` (Android) / `isProtected` (iOS) to block screenshot/Mirroring-based exfiltration.
  - **Tapjacking / overlay protection** — reject touches when an overlay is detected (Android `filterTouchesWhenObscured`).
- **Defense-in-depth logging**: Report integrity failures back to the server; rate-limit or revoke compromised sessions even if the client-side gate is bypassed. Correlate client integrity signals (App Attest / Play Integrity verdict, device fingerprint, behavioral biometrics) for high-value operations.
- **Server-side rate-limiting and anomaly detection**: Client-side checks always fail eventually; the server must detect anomalous patterns (a single user making thousands of API calls per minute, requests from unusual geolocations, replayed nonces) and revoke.

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
