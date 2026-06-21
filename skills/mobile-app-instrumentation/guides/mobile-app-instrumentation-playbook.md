# Mobile App Instrumentation Playbook

> Companion to `SKILL.md`, `payloads.md`, and `test-cases.md` in the `mobile-app-instrumentation` skill.
> Deep-dive operational guide: runtime model, lab build-out, workflow, real-world case studies, and defense patterns for iOS/Android dynamic instrumentation.

## Introduction

This playbook is the **operational manual** for runtime instrumentation of iOS and Android applications. It assumes you already know *what* an app does at a static level (from `mobile-security` triage) and now need to prove *what it actually does at runtime* — and force it to behave otherwise. The discipline is built on three pillars: (1) a properly prepared device (jailbroken iOS or rooted Android); (2) a runtime instrumentation bridge (`Frida` / `Objection` / `r2frida`); and (3) a target list of methods, exports, and crypto primitives that the operator hooks to observe or mutate behavior. The deliverable is an evidence packet — hook scripts, runtime logs, screenshots, downstream consequences — that proves the weakness and feeds directly into the engagement report. The playbook walks through the iOS and Android runtime model, builds out an instrumentation lab, defines the engagement workflow, and grounds the material in four real-world case studies (Instagram cookie hijack, Snapchat jailbreak detection, Uber cert pinning evolution, TikTok keystore bypass). It closes with defense patterns: how the blue team should respond, what server-side attestation closes each bypass, and where the operator should expect friction as runtime defenses mature.

## iOS / Android Runtime Model

A mobile app is not just a process — it runs inside a multi-layered runtime that constrains what the app can see, who it can talk to, and how it persists state. Understanding the model is the prerequisite for instrumenting it.

### iOS Runtime Model

- **Sandbox**: every third-party app runs in its own sandboxed container at `/var/mobile/Containers/Data/Application/<UUID>/`. The app can read/write its own container but cannot access other apps' containers or system paths outside its entitlements. Files outside the container (e.g., `/var/protected/var/Keychains/`) are accessed only through dedicated APIs (`SecItemCopyMatching`, `NSUserDefaults`, `FileManager` with the right container URL).
- **Code signing**: every executable page on iOS must be backed by a valid code signature. Apple issues the signing identity; the kernel enforces it at `mmap`/`exec` time. On a jailbroken device (checkm8 or KFD-based), the kernel's enforcement is bypassed via kernel patches (e.g., AMFI loader hooks) — this is why a jailbreak is required to inject `frida-server` or `FridaGadget.dylib`.
- **FairPlay DRM**: App Store binaries are additionally encrypted with a per-device AES key derived during download. The kernel decrypts pages on demand at runtime. Static analysis of the raw binary is therefore impossible without a decryption pass (Clutch, iPAA, bfinject dump the decrypted pages from memory).
- **Keychain**: backed by `securityd`, storing items in `/var/protected/var/Keychains/keychain-2.db` (encrypted with a device-unique key derived from the UID and passcode). Items carry an `accessible` attribute (`WhenUnlocked`, `WhenUnlockedThisDeviceOnly`, `WhenPasscodeSetThisDeviceOnly`) that governs when they can be read.
- **Entitlements**: a signed plist embedded in the binary declaring capabilities (keychain-access-groups, app-groups, iCloud, associated-domains, App Attest capability). Inspect with `jtool2 --ent`.
- **Runtime integrity**: iOS apps may call `ptrace(PT_DENY_ATTACH)` to refuse debugger attachment; `sysctl` with `KERN_PROC` to inspect the `P_TRACED` flag; or check `dyld` for loaded Frida / Substrate dylibs. None of these are insurmountable — but they are the first wall.

### Android Runtime Model

- **Sandbox via UID**: each app runs under a unique Linux UID. Files under `/data/data/<pkg>/` are owned by that UID; SELinux policies further constrain cross-app access.
- **APK structure**: a ZIP containing `AndroidManifest.xml`, `classes.dex` (Dalvik bytecode, possibly multidex), `lib/<abi>/*.so` (native libs), `res/`, `assets/`, and `META-INF/` (signing). Split APKs separate base, architecture-specific (e.g., `split_config.arm64_v8a.apk`), density (`xxhdpi`), and language (`en`) — all must be pulled for a complete analysis.
- **ART runtime**: starting Android 5.0, apps run on ART (Ahead-of-Time + Just-In-Time compilation). DEX is compiled to native code at install or run time. Hooks via `Java.use()` work against the ART-loaded classes; for JIT-compiled hot paths, additional work may be needed.
- **AndroidManifest**: declares permissions, components (activities/services/receivers/providers), `networkSecurityConfig`, `debuggable`, `usesCleartextTraffic`. Static review identifies candidate sinks.
- **Keystore**: the `android.security.keystore` API; keys may be software-backed (extractable in principle) or hardware-backed (TEE on most devices; StrongBox on Pixel 6+ and modern flagships). Hardware-backed keys cannot be exported even with root — only used for sign/decrypt in-place.
- **Runtime integrity**: Android apps may check `/proc/self/status` for `TracerPid`; `/proc/self/maps` for `frida-agent`; package manager for Magisk / SuperSU; `Build.TAGS` for `test-keys`; or `SafetyNet` / `Play Integrity` verdict from Google.
- **Root**: the `su` binary and `Magisk` daemon provide root via a modified boot image. `Zygisk` enables per-process code injection (used by `DenyList` to hide root from target apps) and is the basis for `LSPosed` (a modern Xposed alternative).

### Shared Concerns

- **TLS pinning**: both platforms ship rich pinning primitives (OkHttp, Conscrypt, AFSecurityPolicy, TrustKit). Apps that care about MITM resistance pin — and pinning is the single biggest reason an engagement needs runtime instrumentation in the first place.
- **Jailbreak / root detection**: a defense-in-depth layer; bypassable but raises the bar.
- **Anti-Frida / anti-tamper**: a third layer scanning for instrumentation tools themselves. Defeatable via port-hopping, gadget injection, or maps-scrubbing — but again, raises the bar.
- **Server-side attestation**: the only layer that cannot be bypassed client-side. The operator should always assume a hardened target will challenge the app via App Attest / Play Integrity — and that the bypass is then to capture and replay a valid token, not to defeat the local check.

## Building an Instrumentation Lab

### iOS Lab

**Hardware options**:

- **iPhone Xs / XR / 11** (A12, A13) on iOS 15-16.x — jailbreak via **Dopamine** (semi-untethered, arm64e). Current sweet spot for iOS 15/16 engagement work.
- **iPhone 7 / 8** (A10) on iOS 14-16.x — jailbreak via **palera1n checkm8** (untethered). Best for checkm8 work because the exploit survives reboot.
- **iPhone 12-15** (A14-A16) on iOS 17-18.x — jailbreak via **palera1n** for A11; **Dopamine** for newer on iOS 15.x only; for iOS 17/18, **kfd**-based exploits (Landbreak, etc.) — moving target; consult current jailbreak community status before each engagement.
- **iPad**: same lineage as iPhone; useful when testing tablet-only apps.

**Software stack**:

- Jailbreak: palera1n / checkra1n (checkm8) or Dopamine (arm64e on iOS 15).
- SSH: `openssh` from Cydia/Sileo/Zebra; default `root` password `alpine` (CHANGE IT).
- Frida: install via Sileo repo `https://build.frida.re`. Installs `re.frida.server`; launchctl starts it.
- Decryption: `Clutch` (Khelandros), `iPAA`, `bfinject` (older iOS 11-era).
- Static triage: `jtool2` on host (Mach-O parser), `ghidra` for decompilation, `class-dump-z` for ObjC headers.
- IDEs: optional `Cycript` for legacy iOS, otherwise Frida JS is the lingua franca.

**Operational notes**:

- Disable auto-lock and passcode auto-wipe during engagement.
- Use a dedicated Apple ID (or no Apple ID) for the device — do not use a personal account.
- Document iOS version, jailbreak, device model, and `frida-server` version in every report.
- If engaging with App Store apps, install them fresh; do not reuse an account with prior installs (avoids per-account server-side flags).

### Android Lab

**Hardware options**:

- **Pixel 6 / 7 / 8** (Google Tensor) — first-class Magisk + StrongBox support. Best for Keystore / StrongBox testing.
- **Pixel 4a / 5** — cheaper, supports TEE-only Keystore (no StrongBox).
- **OnePlus / Xiaomi flagships** — wide Magisk support but some have custom integrity checks.
- Avoid Samsung Knox devices unless explicitly targeting Knox (eFuse triggers).

**Software stack**:

- Android 13/14/15 (latest stable + one version back).
- **Magisk** (latest stable) — root + Zygisk.
- **Zygisk** enabled → **LSPosed** installed (modern Xposed; useful when Frida is detected but LSPosed is not).
- **frida-server** matching host frida version; push to `/data/local/tmp/frida-server`; start as root.
- **mitmproxy** on host for TLS interception (paired with SSL pinning bypass).
- **apktool + jadx** on host for static triage.
- **adb** configured for the device; `adb root` where supported.

**Operational notes**:

- Disable Google Play Protect (or exclude frida-server from scans).
- Use a dedicated Google account (or skip account setup entirely).
- Enable Developer Mode + USB Debugging; install the host's ADB key.
- Document Android version, security patch level, Magisk version, device model, and `frida-server` version in every report.

### Lab Network Topology

- Dedicated Wi-Fi SSID isolated from corporate/home network.
- MITM host (`mitmproxy` / Burp) on the same Wi-Fi; device Wi-Fi proxy pointed at it.
- Optional VPN tunnel to a controlled egress for capturing backend responses.
- Optional DNS server (`dnsmasq` / `pi-hole`) to redirect target endpoints to a controlled backend for replay.

### Engagement Hygiene

- Time-box each app to a fixed window (e.g., 2-3 hours) — instrumentation can sprawl.
- Maintain a `targets.md` with hook candidates; check off as each is tested.
- Save every Frida script with a meaningful name (`bypass_ssl_v1.js`, `trace_login.js`); version them.
- Capture screenshots at every meaningful step (jailbreak bypass working, keychain dump, decrypted HTTPS).
- Keep the evidence packet reproducible: anyone re-running the same Frida scripts on the same device version should see the same results.

## Instrumentation Workflow

The workflow has five phases, mirroring the methodology in `SKILL.md` but expanded with operational detail.

### Phase 1 — Acquisition

- **iOS**: confirm bundle ID via `frida-ps -Uai`; decrypt with `Clutch -d <bundle-id>` or `iPAA`; pull the decrypted `.app` bundle via `scp`.
- **Android**: locate via `adb shell pm path <pkg>`; pull base + split APKs; for packed apps, plan a runtime DEX dump via `frida-dexdump`.

Deliverable: app binary on host disk, ready for static triage.

### Phase 2 — Environment Preparation

- Confirm `frida-server` running on device.
- Confirm `frida-ps -U` lists device processes.
- Prepare proxy (if MITM is in scope) and install CA on device.
- Prepare objection REPL on standby.

Deliverable: working Frida + Objection + r2frida channels to the device.

### Phase 3 — Static Triage

- `jadx -d out_jadx/ base.apk split_config.arm64_v8a.apk` (Android).
- `jtool2 -L` + `jtool2 -objc` + `jtool2 --ent` (iOS).
- `ghidraRun` for native lib decompilation (both platforms).
- Target lists:
  - Pinning classes (`CertificatePinner`, `X509TrustManager`, `AFSecurityPolicy`, `TrustKit`, etc.).
  - Jailbreak / root detection (`fcntl F_GETPATH` paths, `RootBeer`, `su` probes).
  - Anti-debug (`ptrace`, `sysctl`, `TracerPid`).
  - Crypto (`CCCrypt`, `Cipher.getInstance`, `Mac`).
  - JNI exports (`Java_*` symbols in `.so` / `.dylib`).

Deliverable: `targets.md` — a prioritized list of hook candidates with file:line references.

### Phase 4 — Instrumentation

Iterate over the target list:

1. **Spawn-and-attach**: `frida -U -f <pkg> -l hook.js --no-pause`.
2. **Objection REPL** for fast exploration: `objection -g <pkg> explore`.
3. **r2frida session** for native analysis: `r2 'frida://spawn/<pkg>'`.

Each hook writes to a log file (Frida `send()` + Python sink on host). Capture the log per-hook for evidence.

Deliverable: per-target hook scripts + runtime logs.

### Phase 5 — Runtime Manipulation

With hooks in place, drive the app to exercise the targeted functionality:

- **Pin bypass** → trigger a network request → capture decrypted flow in mitmproxy.
- **Jailbreak bypass** → trigger gated feature (banking transfer, DRM playback) → screenshot success.
- **Keychain dump** → save the dump → grep for high-value tokens.
- **Crypto trace** → trigger signing → replay signature against backend with `curl`.
- **Native hook** → trigger native call → capture input/output bytes.

Deliverable: the evidence packet — hook scripts, runtime logs, mitmproxy flow exports, screenshots, replayed backend requests.

### Reporting

The final report should contain:

1. **Executive summary**: 1-2 paragraphs; what was found, business impact, recommended fix.
2. **Methodology**: phases 1-5 with tools used and time spent.
3. **Findings**: one section per finding (pinning bypass, jailbreak bypass, keychain exposure, crypto weakness, etc.) with severity (CRITICAL / HIGH / MEDIUM / LOW), evidence, and remediation.
4. **Mitigation mapping table**: each finding → MASVS control → recommended runtime defense.
5. **Appendix**: full Frida scripts, runtime logs, mitmproxy flows, device and tool versions.

## Real-World Case Studies

### Case Study 1 — Instagram Cookie Hijack via Frida (2019-2021)

**Context**: Instagram (iOS) used certificate pinning on its API endpoints. Researchers wanted to capture the session cookie to demonstrate that the same cookie could be replayed from a non-Instagram client.

**Approach**:

1. Jailbroken iPhone on iOS 12-13; `frida-server` installed via Sileo.
2. Decrypted IPA via `Clutch -d com.burbn.instagram`.
3. Static triage identified the pinning implementation as a custom `URLSessionDelegate` plus `TrustKit`.
4. Frida hook on `SecTrustEvaluateWithError` (iOS 13+) forced `true`; simultaneously hooked the custom delegate's `urlSession:didReceiveChallenge:completionHandler:` to call the completion handler with `.useCredentials` and a dummy credential.
5. With pinning disabled, mitmproxy captured the full session including the `sessionid` cookie.
6. The cookie was replayed against Instagram's web API from `curl` — full account access from a non-mobile client.

**Outcome**: demonstrated that mobile-app session security depended entirely on the pinned channel; once pinning was bypassed, the cookie was as portable as any web session.

**Defense lesson**: server-side session validation should include device attestation (App Attest) so a captured session cookie alone is insufficient.

### Case Study 2 — Snapchat Jailbreak Detection History (2014-2022)

**Context**: Snapchat has been one of the most aggressive detectors of jailbroken iOS. The lineage is instructive: each round of detection was eventually bypassed, prompting Snapchat to layer additional checks.

**Evolution**:

- **2014**: simple `fork()` probe (fork returns -1 on stock iOS, succeeds on jailbreak). Bypass: hook `fork` to return -1.
- **2016**: `dyld` enumeration for `MobileSubstrate`, `SubstrateBootstrap`, `CydiaSubstrate`. Bypass: hook `dyld_image_count` / `_dyld_get_image_name` to filter those names.
- **2018**: `fcntl(path, F_GETPATH)` against a list of jailbreak file paths (`/Applications/Cydia.app`, `/usr/sbin/sshd`, `/bin/bash`). Bypass: hook `fcntl` to substitute fake paths.
- **2020**: scan `/var/containers/Bundle/Application/` for jailbreak artifacts. Bypass: hook `opendir` to filter the listing.
- **2022**: combined server-side checks (device fingerprint from telemetry) + client-side runtime checks. Bypass requires server-side replay — substantially harder.

**Outcome**: each detection layer raised the bar; the pattern is that bypasses exist for every client-side check, but server-side attestation (App Attest) closes the loop.

**Defense lesson**: do not rely on client-side jailbreak detection alone; pair with App Attest / Play Integrity for the verdict the client cannot forge.

### Case Study 3 — Uber Cert Pinning Evolution (2017-2023)

**Context**: Uber was an early adopter of multi-layer certificate pinning. Researchers tracked the evolution of their pinning stack.

**Evolution**:

- **2017**: single-layer pinning on OkHttp's `CertificatePinner`. Bypass: Frida hook on `CertificatePinner.check`.
- **2019**: dual-layer pinning (OkHttp + a custom `X509TrustManager`); fallback pinning in `Conscrypt`. Bypass: hook both layers plus `TrustManagerImpl.verifyChain`.
- **2021**: native pinning in `libssl` (BoringSSL) via `SSL_CTX_set_custom_verify`; the Java layers became decoys. Bypass: hook the native BoringSSL call (`SSL_CTX_set_custom_verify`) by enumerating `libssl.so` exports.
- **2023**: pinning tied to attestation — the server challenges the client for an App Attest / Play Integrity token alongside the TLS handshake. The cert pin is no longer the only gate; the bypass now requires capturing a valid attestation token from a genuine device.

**Outcome**: the engagement had to evolve from a single Frida hook to a multi-layer bypass; ultimately the attestation challenge forced a different technique (capturing and replaying a token from a genuine device).

**Defense lesson**: layer pinning across Java, native, and protocol layers; tie the pin to server-side attestation so client-side bypass alone is insufficient.

### Case Study 4 — TikTok Keystore Bypass (2020-2022)

**Context**: TikTok used the Android Keystore to protect signing keys for its API requests. Researchers wanted to recover the signing key to demonstrate that the API could be called from a non-app client.

**Approach**:

1. Rooted Pixel on Android 11-12 with Magisk + Zygisk DenyList on `com.zhiliaoapp.musically`.
2. Static triage identified the signing routine as a `Cipher` operation with a Keystore-backed key.
3. Frida hook on `javax.crypto.Cipher.init` revealed the key bytes — the key was **software-backed** (extractable).
4. Frida hook on `Cipher.doFinal` captured every plaintext + ciphertext pair.
5. The extracted key was replayed against TikTok's web API from a Python script — full API access without the app.

**Outcome**: demonstrated that the app's signing scheme depended entirely on a software-backed Keystore key that was extractable with root.

**Defense lesson**: use **hardware-backed** Keystore keys (`setIsStrongBoxBacked(true)` on StrongBox-capable devices, or at minimum rely on TEE); combine with attestation so the server can verify the key is hardware-backed.

## Defense Patterns

The defense playbook mirrors the offense playbook — every offensive technique has a corresponding defense, and the strongest defenses are layered.

### Layer 1 — Robust Certificate Pinning

- Pin **leaf + intermediate + CA**; rotate pins via a server-provided pin catalog.
- Use **native pinning** (BoringSSL `SSL_CTX_set_custom_verify` on Android; `SecTrustEvaluateWithError` override or `TrustKit` on iOS) in addition to Java-level pinning.
- **Fail closed**: on pin failure, abort the connection; do not fall back to system trust.
- Document a pin-rotation channel so a compromised CA does not lock the app out.

### Layer 2 — Jailbreak / Root Detection (Layered)

- **iOS**: combine `fcntl F_GETPATH` against a list of jailbreak paths, `fork` probe, `dyld` enumeration for Substrate / Frida, `sysctl` P_TRACED check.
- **Android**: combine `RootBeer` library, `/system/bin/su` and `/system/xbin/su` probes, `Magisk Hide` detection via `/proc/self/maps` for `magisk` strings, `Build.TAGS` for `test-keys`, and `/proc/self/status` for `TracerPid`.
- Run detection at multiple points: at app launch, at every sensitive action, and asynchronously to detect runtime injection.

### Layer 3 — Anti-Frida / Anti-Tamper

- Scan `/proc/self/maps` (Android) or `dyld` (iOS) for `frida-agent`, `gum-js-loop`, `pool-frida`, `linjector`.
- Scan local TCP ports 27000-27100 for `frida-server`.
- Scan thread names for `gum-js-loop`, `gmain`, `pool-frida`.
- Periodically checksum the app's `.text` section to detect Frida stalker / interceptor trampolines.
- Run detection in native code (harder to hook than Java code).

### Layer 4 — Hardware-Backed Keys (Android)

- Use `KeyGenParameterSpec.Builder` with `setIsStrongBoxBacked(true)` (Pixel 6+, modern flagships) or rely on TEE.
- Set `setUserAuthenticationRequired(true)` for biometric-gated operations.
- Set `setAttestationChallenge(...)` so the server can verify the key's attestation chain against Google's root.

### Layer 5 — Server-Side Attestation (The Closes-the-Loop Layer)

**iOS App Attest**:

- Server generates a nonce (challenge).
- Client calls `DCAppAttestService.shared.attestKey(...)` and returns the attestation object.
- Server verifies the attestation against Apple's App Attest root.
- Server binds the attested key to the session; subsequent sensitive operations are signed with the key.

**Android Play Integrity API** (successor to SafetyNet):

- Server generates a nonce.
- Client requests a `StandardIntegrityToken` with the nonce.
- Server decrypts the token via the Google Play Integrity API and verifies:
  - **App integrity** — the request came from the genuine app package, signed by Google Play.
  - **Device integrity** — `MEETS_DEVICE_INTEGRITY` (CTS-passing, no known root) or `MEETS_STRONG_INTEGRITY` (genuine hardware, recent security patch).
  - **Account licensing** — the user account has licensed the app via Play.
- Server binds the verdict to the session; subsequent requests must carry a fresh verdict.

### Layer 6 — Backend Anomaly Detection

Even with full client-side bypass, the backend can detect anomalies:

- **Rate anomalies** — a single session issuing requests faster than humanly possible.
- **Geographic anomalies** — session originating from a new country.
- **Device fingerprint anomalies** — the User-Agent / TLS fingerprint does not match the device claimed by the app.
- **Behavioral anomalies** — the request sequence deviates from the app's normal pattern.

These signals feed a risk-scoring engine that can challenge, throttle, or revoke the session.

### Mitigation Mapping Table

| Finding (offense) | Defense Layer | Recommended Defense |
|------|------|------|
| SSL pinning bypass | Layer 1 | Multi-layer pinning (Java + native); fail-closed policy |
| Jailbreak / root bypass | Layer 2 + Layer 5 | Layered detection + App Attest / Play Integrity |
| Anti-debug bypass | Layer 3 + Layer 5 | Native checks + server-side attestation |
| Keychain / Keystore extraction | Layer 4 | Hardware-backed keys; biometric-gated; attested |
| Frida detection bypass | Layer 3 + Layer 5 | Native self-checks + Play Integrity verdict |
| Hardcoded signing key | Layer 4 | Move to hardware-backed Keystore; rotate keys |
| Cookie / token replay | Layer 5 + Layer 6 | Bind session to attestation; backend anomaly detection |

## References

- **Frida documentation** — https://frida.re/docs/home/
- **Objection wiki (SensePost)** — https://github.com/sensepost/objection/wiki
- **r2frida** — https://github.com/nowsecure/r2frida
- **Introspy** — https://github.com/iSECPartners/Introspy-iOS and `/Introspy-Android`
- **NowSecure blog** — https://www.nowsecure.com/blog/
- **@dki Frida iOS bootcamp** — https://github.com/dki Frida-bootcamp (and YouTube playlist)
- **Frida CodeShare** — https://codeshare.frida.re/ (community-contributed hook scripts)
- **Apple Platform Security Guide** — https://support.apple.com/guide/security/welcome/web
- **Android Security Team blog** — https://security.googleblog.com/
- **OWASP MASTG (Mobile Application Security Testing Guide)** — https://mas.owasp.org/MASTG/
- **OWASP MASVS** — https://mas.owasp.org/MASVS/ (especially MASVS-NETWORK and MASVS-RESILIENCE)
- **MITRE ATT&CK for Mobile** — https://attack.mitre.org/matrices/mobile/
- **Google Play Integrity API** — https://developer.android.com/google/play/integrity
- **Apple App Attest** — https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
- **Magisk** — https://github.com/topjohnwu/Magisk
- **palera1n** — https://palera.in/
- **Dopamine** — https://github.com/opa334/Dopamine
- **AppSec Santa 2026 — Frida deep dive** — annual review at AppSec California
- **SensePost Objection release notes** — https://github.com/sensepost/objection/releases
- **Radare2 book** — https://book.rada.re/
- **Ghidra** — https://ghidra-sre.org/

## Appendix — Sample Engagement Day Plan

A typical one-day engagement on a mobile app:

| Time | Activity |
|------|---------|
| 09:00 | Phase 1 — Acquisition: pull APK / decrypt IPA |
| 09:30 | Phase 3 — Static triage with jadx / jtool2 + ghidra; populate `targets.md` |
| 10:30 | Phase 2 — Environment prep (frida-server, mitmproxy, objection) |
| 11:00 | Phase 4 — SSL pinning bypass (TC-MI-004) |
| 12:00 | Lunch |
| 13:00 | Phase 4 — Jailbreak / root detection bypass (TC-MI-008) |
| 14:00 | Phase 4 — Anti-debug bypass (TC-MI-009) |
| 14:30 | Phase 5 — Keychain dump (TC-MI-006) / Keystore trace (TC-MI-007) |
| 15:30 | Phase 5 — Crypto trace (TC-MI-011) + replay against backend |
| 16:30 | Phase 5 — Native lib instrumentation (TC-MI-010) if applicable |
| 17:00 | Reporting: findings draft, evidence packet |
| 18:00 | Wrap-up; plan for follow-up |

For longer engagements, add a day for: WebView JS bridge exploitation, anti-Frida evasion (TC-MI-012), and deeper native lib analysis with ghidra decompilation.
