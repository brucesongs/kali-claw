# Mobile App Instrumentation — Test Cases

> Companion to `SKILL.md` and `payloads.md`. 12 structured test cases (TC-MI-001 .. TC-MI-012) for executing an end-to-end mobile-app instrumentation engagement.
> All commands assume authorized scope: signed engagement, owned device, or controlled lab.
> Set `IOS_DEVICE` (jailbroken), `ANDROID_DEVICE` (rooted), `TARGET_PKG_IOS`, `TARGET_PKG_ANDROID`, and `MITM_PROXY` before running.

---

## Statistics

| Category | Count | Difficulty Range |
|------|------|-----------|
| A. Environment & Acquisition | 3 | EASY - MEDIUM |
| B. Runtime Hooking & Pinning Bypass | 3 | MEDIUM - HIGH |
| C. Secrets & Keystore | 2 | MEDIUM - HIGH |
| D. Detection Bypass | 2 | HIGH |
| E. Native & Crypto Tracing | 2 | HIGH |
| **Total** | **12** | **EASY - HIGH** |

---

## A. Environment & Acquisition

### TC-MI-001: Frida Environment Bring-Up (iOS + Android)

| Field | Value |
|------|-----|
| **ID** | TC-MI-001 |
| **Name** | Frida Environment Bring-Up (iOS + Android) |
| **Objective** | Confirm Frida toolchain is installed on the host and frida-server is running on both iOS and Android target devices, ready for runtime instrumentation. |
| **Tools** | frida, frida-tools, objection, pip, adb, ssh, frida-server |
| **Steps** | 1. On host: `python3 -m venv ~/frida-venv && source ~/frida-venv/bin/activate && pip install frida frida-tools objection && frida --version` (confirm 16.x or 17.x)<br>2. iOS: `ssh root@${IOS_DEVICE} "echo 'deb https://build.frida.re ./' >> /etc/apt/sources.list.d/frida.list && apt-get update -y && apt-get install -y re.frida.server"` then `ssh root@${IOS_DEVICE} "nohup re.frida-server >/dev/null 2>&1 &"`<br>3. Android: `FRIDA_VER=$(frida --version); wget https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-arm64.xz && unxz frida-server-${FRIDA_VER}-android-arm64.xz && adb root && adb push frida-server-${FRIDA_VER}-android-arm64 /data/local/tmp/frida-server && adb shell "chmod 755 /data/local/tmp/frida-server"`<br>4. Android: `adb shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"`<br>5. Verify both: `frida-ps -U \| head` (lists device processes) and `frida-ps -Uai \| grep -iE 'SpringBoard\|launcher'` |
| **Expected Result** | `frida --version` returns a 16.x or 17.x version; `frida-ps -U` lists processes from both iOS and Android devices (whichever is plugged in); no errors in `frida-server` startup. |
| **Mitre** | T1627.001 — Adversary-in-the-Mobile-Device (prerequisite for T1518 Software Discovery) |
| **Difficulty** | EASY |
| **Tags** | environment, setup, frida, ios, android |

### TC-MI-002: iOS App Acquisition (Clutch / iPAA Decryption)

| Field | Value |
|------|-----|
| **ID** | TC-MI-002 |
| **Name** | iOS App Acquisition (Clutch / iPAA Decryption) |
| **Objective** | Acquire a FairPlay-decrypted `.app` bundle of the target iOS app from a jailbroken device so it can be statically triaged and instrumented. |
| **Tools** | Clutch, iPAA, scp, jtool2, ssh |
| **Steps** | 1. List installed apps: `ssh root@${IOS_DEVICE} "Clutch -i"` (interactive picker) or `frida-ps -Uai \| grep ${TARGET_PKG_IOS}`<br>2. Decrypt via Clutch: `ssh root@${IOS_DEVICE} "Clutch -d ${TARGET_PKG_IOS}"` (outputs decrypted bundle path under `/var/containers/Bundle/Application/`)<br>3. Alternative: `ssh root@${IOS_DEVICE} "iPAA"` then interactively select the app and choose Export<br>4. Pull to host: `scp -r root@${IOS_DEVICE}:/var/containers/Bundle/Application/<UUID>/<AppName>.app ./decrypted/`<br>5. Verify decryption: `jtool2 -L ./decrypted/<AppName>.app/<AppName> \| grep -i crypt` — cryptid should be 0<br>6. Triage: `jtool2 -objc ./decrypted/<AppName>.app/<AppName> > classes.txt && grep -iE 'login\|auth\|pin\|trust\|crypto' classes.txt` |
| **Expected Result** | A decrypted `.app` bundle on host with `cryptid=0`; an `Objective-C` class list showing the app's structure; entry points for pinning, jailbreak detection, and crypto identified for later hooks. |
| **Cleanup** | None — acquisition is non-invasive. |
| **Mitre** | T1606-Forge Web Credentials (analogous: FairPlay decryption enables subsequent runtime forgery) |
| **Difficulty** | EASY |
| **Tags** | ios, acquisition, clutch, ipaa, decryption |

### TC-MI-003: Android APK Pull + jadx Triage

| Field | Value |
|------|-----|
| **ID** | TC-MI-003 |
| **Name** | Android APK Pull + jadx Static Triage |
| **Objective** | Pull the target Android app's APK (base + split APKs), decode with apktool, decompile DEX with jadx, and produce a target list of SSL-pinning / root-detection / crypto candidates. |
| **Tools** | adb, apktool, jadx, grep |
| **Steps** | 1. Locate: `adb shell pm path ${TARGET_PKG_ANDROID}` (returns `/data/app/.../base.apk` plus any `split_*.apk`)<br>2. Pull each: `adb pull /data/app/~~<hash>==/${TARGET_PKG_ANDROID}-<hash>==/base.apk ./base.apk` and any `split_config.arm64_v8a.apk`<br>3. Decode manifest + smali: `apktool d base.apk -o decoded/ && cat decoded/AndroidManifest.xml \| grep -E 'debuggable\|networkSecurityConfig\|usesCleartextTraffic'`<br>4. Decompile: `jadx -d out_jadx/ --show-bad-code base.apk split_config.arm64_v8a.apk`<br>5. Pinning candidates: `grep -rE 'CertificatePinner\|X509TrustManager\|SSLContext\|TrustKit' out_jadx/sources/ \| head -20`<br>6. Root-detection candidates: `grep -rEi 'RootBeer\|/system/bin/su\|magisk\|busybox\|/sbin/.magisk' out_jadx/sources/ \| head`<br>7. Crypto candidates: `grep -rE 'Cipher\.getInstance\|MessageDigest\.getInstance\|javax\.crypto' out_jadx/sources/ \| head`<br>8. JNI exports: `find decoded/lib -name '*.so' \| head` then `nm -D --defined-only decoded/lib/arm64-v8a/libNative.so \| grep Java_` |
| **Expected Result** | Complete `out_jadx/` decompile; a `targets.md` listing 3+ pinning classes, 2+ root-detection methods, 5+ crypto call sites, and 1+ native JNI exports. Each entry becomes a hook candidate for later test cases. |
| **Cleanup** | None. |
| **Mitre** | T1518-Software Discovery |
| **Difficulty** | EASY |
| **Tags** | android, acquisition, apktool, jadx, triage |

---

## B. Runtime Hooking & Pinning Bypass

### TC-MI-004: Frida SSL Pinning Bypass (Scripted)

| Field | Value |
|------|-----|
| **ID** | TC-MI-004 |
| **Name** | Frida SSL Pinning Bypass (Scripted) |
| **Objective** | Bypass the target app's TLS certificate pinning at runtime using a Frida hook script, then capture decrypted traffic via a paired mitmproxy instance. |
| **Tools** | frida, mitmproxy, the `bypass_ssl_pinning.js` script from payloads.md Section 8 |
| **Steps** | 1. Prepare mitmproxy on host: `mitmproxy --mode regular -p 8080 &` and configure device Wi-Fi proxy to `127.0.0.1:8080`; install mitmproxy CA on device (Settings → Profile Downloaded → Install)<br>2. Confirm baseline failure: launch `${TARGET_PKG}` on device → app should fail TLS handshake against pinned endpoints<br>3. Spawn-and-attach with the bypass script: `frida -U -f ${TARGET_PKG_ANDROID} -l bypass_ssl_pinning.js --no-pause`<br>4. Watch console for `[+] OkHttp CertificatePinner.check() bypassed` / `[+] SSLContext.init() replaced with trust-all` / `[+] SecTrustEvaluate forced proceed` (iOS) messages<br>5. Trigger a network request from the app (refresh feed, log in, sync)<br>6. Verify in mitmproxy: decrypted HTTPS traffic now visible; capture the request/response for the target endpoint<br>7. If no pinning classes match, fall back to Objection: `objection -g ${TARGET_PKG} explore --startup-command "android sslpinning disable"` |
| **Expected Result** | mitmproxy shows decrypted HTTPS request/response pairs for the pinned endpoint; Frida console shows at least one bypass log line per pinning API hit. Evidence packet includes hook log + mitmproxy flow export (`mitmdump -w traffic.mitm`). |
| **Cleanup** | Disable device Wi-Fi proxy; remove mitmproxy CA profile. |
| **Mitre** | T1557-Man-in-the-Middle; T1627.001-Adversary-in-the-Mobile-Device |
| **Difficulty** | MEDIUM |
| **Tags** | ssl-pinning, frida, mitm, network |

### TC-MI-005: Objection Runtime Exploration (Hooking List)

| Field | Value |
|------|-----|
| **ID** | TC-MI-005 |
| **Name** | Objection Runtime Exploration |
| **Objective** | Use Objection's REPL to enumerate classes, activities, services, and watch a high-value method with argument and return-value dumping. |
| **Tools** | objection |
| **Steps** | 1. Spawn the target under Objection: `objection -g ${TARGET_PKG_ANDROID} explore`<br>2. In the REPL: `android hooking list classes` (capture class inventory)<br>3. `android hooking search classes Login` (find login-related classes)<br>4. `android hooking list activities` and `android hooking list services` (capture exported components)<br>5. Watch a high-value method: `android hooking watch class_method com.example.LoginManager.login --dump-args --dump-return --dump-backtrace`<br>6. Trigger the method by performing a login in the app UI<br>7. Capture the dumped args (username/password), return value (auth token), and backtrace |
| **Expected Result** | A populated class/activity/service inventory; a captured Login invocation showing the plaintext credentials and the returned token. This proves the app's auth surface is fully observable at runtime. |
| **Cleanup** | None — observation is read-only. |
| **Mitre** | T1056-Input Capture; T1552-Unsecured Credentials |
| **Difficulty** | MEDIUM |
| **Tags** | objection, runtime, hooking, discovery |

### TC-MI-006: iOS Keychain Dump

| Field | Value |
|------|-----|
| **ID** | TC-MI-006 |
| **Name** | iOS Keychain Dump via Objection |
| **Objective** | Dump every keychain item accessible to the target iOS app and identify high-value secrets (OAuth refresh tokens, biometric-gated keys, session tokens). |
| **Tools** | objection, keychain-dumper (optional) |
| **Steps** | 1. `objection -g ${TARGET_PKG_IOS} explore`<br>2. In REPL: `ios keychain dump` (default dump; prints all accessible Generic + Internet password items)<br>3. Save full output: `ios keychain dump > keychain_raw.txt` (or redirect from objection log file)<br>4. Filter for high-value: `grep -iE 'refresh_token\|access_token\|bearer\|oauth\|mfa\|session' keychain_raw.txt`<br>5. Note the `accessible` attribute for each entry (`kSecAttrAccessibleWhenUnlocked` vs `WhenUnlockedThisDeviceOnly` vs `WhenPasscodeSetThisDeviceOnly`) — entries with `WhenUnlocked` are extractable from a lock-screen-bypassed device<br>6. Cross-reference against `jtool2 --ent` output: confirm the app's keychain-access-groups; items outside the group should not be visible (a finding if they are)<br>7. Optional: cross-validate with `ssh root@${IOS_DEVICE} "keychain-dumper -a"` |
| **Expected Result** | A `keychain_filtered.txt` with 1+ extractable token; an `accessible` classification showing whether biometric-only (`WhenPasscodeSetThisDeviceOnly`) is enforced or whether weaker policies are used. |
| **Cleanup** | None. |
| **Mitre** | T1552-Unsecured Credentials; T1555-Credentials from Password Stores |
| **Difficulty** | MEDIUM |
| **Tags** | ios, keychain, secrets, objection |

---

## C. Secrets & Keystore

### TC-MI-007: Android Keystore Manipulation

| Field | Value |
|------|-----|
| **ID** | TC-MI-007 |
| **Name** | Android Keystore Manipulation |
| **Objective** | Hook `javax.crypto.Cipher` and `java.security.KeyStore` to log every key-loading and crypto operation, recovering plaintext keys where hardware attestation is not enforced. |
| **Tools** | frida, the `trace_keystore.js` script from payloads.md Section 12.2 |
| **Steps** | 1. Spawn-and-attach: `frida -U -f ${TARGET_PKG_ANDROID} -l trace_keystore.js --no-pause`<br>2. Trigger a Keystore-using operation in the app (encrypt local storage, sign a request, biometric unlock)<br>3. Capture `[KeyStore.getEntry] alias=...` (which key alias is loaded)<br>4. Capture `[Cipher.init] algo=AES/GCM/NoPadding mode=1 key=<hex>` (key bytes if software-backed)<br>5. Capture `[Cipher.doFinal] in=<hex> out=<hex>` (plaintext + ciphertext)<br>6. If the key bytes are `<opaque>`, the key is hardware-backed (StrongBox / TEE) and cannot be exported — note as a defensive finding<br>7. Optional: install `setAttestationChallenge` hook from Section 12.4 to capture the attestation chain for analysis |
| **Expected Result** | A `keystore_trace.log` showing the alias name, algorithm, and — if software-backed — the raw key bytes; if hardware-backed, clear evidence that the app uses TEE/StrongBox (a positive defensive finding). |
| **Cleanup** | None. |
| **Mitre** | T1552-Unsecured Credentials; T1606-Forge Web Credentials |
| **Difficulty** | HIGH |
| **Tags** | android, keystore, crypto, frida |

### TC-MI-008: Jailbreak / Root Detection Bypass

| Field | Value |
|------|-----|
| **ID** | TC-MI-008 |
| **Name** | Jailbreak / Root Detection Bypass |
| **Objective** | Bypass the target app's jailbreak (iOS) or root (Android) detection so gated functionality becomes available for further instrumentation. |
| **Tools** | frida, `ios_jailbreak_bypass.js` (Section 9.1) or `android_root_bypass.js` (Section 9.2), `bypass_rootbeer.js` (Section 9.3) |
| **Steps** | 1. Confirm baseline: launch the app on jailbroken iOS / rooted Android → app should refuse to run or display a "device not supported" warning<br>2. Identify detection class via static triage (TC-MI-002 / TC-MI-003) — common patterns: `fcntl F_GETPATH`, `/Applications/Cydia.app`, `fork`, `sysctl P_TRACED` (iOS); `RootBeer`, `/system/bin/su`, `/proc/self/maps` for Magisk (Android)<br>3. iOS: `frida -U -f ${TARGET_PKG_IOS} -l ios_jailbreak_bypass.js --no-pause`<br>4. Android: `frida -U -f ${TARGET_PKG_ANDROID} -l android_root_bypass.js --no-pause` (combine with `bypass_rootbeer.js` if RootBeer is detected)<br>5. Watch console for `[jb-bypass]` / `[root-bypass]` log lines<br>6. Re-trigger the gated feature (e.g., banking transfer, DRM playback, payment init); feature should now succeed<br>7. Document the detection methods that fired and which were bypassed |
| **Expected Result** | App launches successfully and the gated feature works; Frida console shows every detection routine being intercepted. Evidence packet includes hook log + screenshots of the gated feature working. |
| **Cleanup** | None. |
| **Mitre** | T1627.001-Adversary-in-the-Mobile-Device; T1218-System Binary Proxy Execution (analogous) |
| **Difficulty** | HIGH |
| **Tags** | jailbreak, root, detection, bypass |

---

## D. Detection Bypass

### TC-MI-009: Anti-Debug Bypass via Frida

| Field | Value |
|------|-----|
| **ID** | TC-MI-009 |
| **Name** | Anti-Debug Bypass via Frida |
| **Objective** | Bypass `ptrace(PT_DENY_ATTACH)` (iOS) and `TracerPid` (Android) checks so the app can be instrumented under Frida without crashing. |
| **Tools** | frida, `bypass_ptrace.js` (Section 10.1) + `bypass_tracerpid.js` (Section 10.2) |
| **Steps** | 1. Confirm baseline: spawn the app under Frida → app crashes immediately or after a short delay with `ptrace: Operation not permitted` or `Debugger detected` toast<br>2. iOS: `frida -U -f ${TARGET_PKG_IOS} -l bypass_ptrace.js --no-pause` — script hooks `ptrace` to return 0 and clears `P_TRACED` in `sysctl` results<br>3. Android: `frida -U -f ${TARGET_PKG_ANDROID} -l bypass_tracerpid.js --no-pause` — script scrubs the `TracerPid:` line in `/proc/self/status` reads<br>4. Combine with `bypass_frida_detect.js` (Section 10.3) if the app also scans `/proc/self/maps` for frida strings<br>5. Verify: app now survives spawn under Frida and can be hooked<br>6. Document which anti-debug primitives the app used (ptrace / sysctl / TracerPid / debug-trace / maps scan) |
| **Expected Result** | App runs successfully under Frida; bypass log shows each anti-debug check being intercepted. Findings document the primitives used and recommended mitigations (Apple App Attest / Play Integrity). |
| **Cleanup** | None. |
| **Mitre** | T1627.001-Adversary-in-the-Mobile-Device |
| **Difficulty** | HIGH |
| **Tags** | anti-debug, ptrace, tracerpid, bypass |

### TC-MI-010: Native Library Instrumentation with r2frida

| Field | Value |
|------|-----|
| **ID** | TC-MI-010 |
| **Name** | Native Library Instrumentation with r2frida |
| **Objective** | Use r2frida to enumerate and hook native library exports (JNI functions) so opaque crypto / signing operations can be observed. |
| **Tools** | r2frida, radare2, frida |
| **Steps** | 1. Identify the target native lib: `find decoded/lib -name 'libNative.so'` (from TC-MI-003) or `jtool2 -L <AppName> \| grep dylib` (iOS)<br>2. Launch r2frida against the live process: `r2 'frida://spawn/${TARGET_PKG_ANDROID}'`<br>3. Inside r2: `il` (list loaded libraries) and `iE~libNative` (exports of libNative)<br>4. Seek to the JNI export: `s sym.Java_com_example_Native_nativeSign`<br>5. Disassemble: `pdf` — note the algorithm shape (HMAC? AES? custom?)<br>6. Decompile if ghidra plugin available: `pdg`<br>7. Set a hook via the bridge: `=?!/is` (inject Interceptor script) or switch to host-side Frida with `hook_native.js` from Section 13.2<br>8. Trigger the native call from the app UI; capture input bytes and return bytes |
| **Expected Result** | Disassembly of the JNI export showing the algorithm structure; a runtime hook log showing inputs and outputs of the native call; identification of any hidden signing scheme (e.g., HMAC-SHA256 of request body with a hardcoded key in the lib). |
| **Cleanup** | None. |
| **Mitre** | T1059-Automated Command Execution (analogous: native code path); T1518-Software Discovery |
| **Difficulty** | HIGH |
| **Tags** | r2frida, native, jni, reverse |

---

## E. Native & Crypto Tracing

### TC-MI-011: Crypto Tracing (javax.crypto / CC)

| Field | Value |
|------|-----|
| **ID** | TC-MI-011 |
| **Name** | Crypto Tracing — javax.crypto and CommonCrypto |
| **Objective** | Trace every cryptographic operation the app performs to recover HMAC keys, AES keys, and signed-request schemes. |
| **Tools** | frida, `trace_javax_crypto.js` (Section 14.2) and/or `trace_cc.js` (Section 14.1) |
| **Steps** | 1. Android: `frida -U -f ${TARGET_PKG_ANDROID} -l trace_javax_crypto.js --no-pause`<br>2. iOS: `frida -U -f ${TARGET_PKG_IOS} -l trace_cc.js --no-pause`<br>3. Trigger a crypto-using operation (log in, refresh feed, sign a request)<br>4. Capture the log: `[Cipher.doFinal] algo=AES/GCM/NoPadding in=<hex> out=<hex>` and `[Mac.doFinal] algo=HmacSHA256 in=<hex> out=<hex>`<br>5. Cross-reference captured keys with the static analysis: do they match a `byte[] KEY = ...` in jadx? (hardcoded key finding)<br>6. Replay the captured signature against the backend with `curl` to confirm the scheme<br>7. Document the algorithm, key source (hardcoded / Keystore / server-provided), and any weaknesses (ECB mode, hardcoded IV, weak key derivation) |
| **Expected Result** | A `crypto_trace.log` showing algorithm + key + plaintext + ciphertext for every operation; at least one replayed request against the backend succeeds. If a hardcoded key is found, document as a CRITICAL finding. |
| **Cleanup** | None. |
| **Mitre** | T1552-Unsecured Credentials; T1573-Encrypted Channel (analysis of) |
| **Difficulty** | HIGH |
| **Tags** | crypto, cipher, hmac, trace |

### TC-MI-012: Anti-Frida Detection Bypass (Magisk Hide / Scrub)

| Field | Value |
|------|-----|
| **ID** | TC-MI-012 |
| **Name** | Anti-Frida Detection Bypass (Magisk Hide / Scrub) |
| **Objective** | Evade the target app's Frida-specific runtime detection (port scan, /proc/self/maps scan, thread-name scan) so instrumentation can proceed. |
| **Tools** | frida, objection patchapk, Magisk + Zygisk, `scrub_maps.js` (Section 16.5) |
| **Steps** | 1. Confirm baseline: spawn under Frida → app detects instrumentation and exits / reports tampering<br>2. Identify detection vector: port scan (27042 open), `/proc/self/maps` (frida-agent string), thread name (`gum-js-loop`)<br>3. Mitigation 1 — Magisk DenyList: in Magisk app, enable Zygisk, add `${TARGET_PKG_ANDROID}` to DenyList; verify with `adb shell "su -c 'magisk --denylist ls'"`<br>4. Mitigation 2 — Non-default port: `adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:24601 &'"` and `adb forward tcp:24601 tcp:24601` then `frida -H 127.0.0.1:24601 -n ${TARGET_PKG_ANDROID} -l hook.js`<br>5. Mitigation 3 — Gadget injection: `objection patchapk -s base.apk && apksigner sign --ks REPLACE_WITH_YOUR_KEYSTORE.jks base.objection.apk && adb install base.objection.apk` (no frida-server needed; gadget embedded in app)<br>6. Mitigation 4 — Maps scrub: `frida -U -f ${TARGET_PKG_ANDROID} -l scrub_maps.js --no-pause` (rewrites `/proc/self/maps` reads to hide frida strings)<br>7. Verify: app now runs under Frida without detection; document which mitigations were required |
| **Expected Result** | App runs under Frida without detection; log shows which detection vectors the app used and which mitigations were sufficient. Recommend Play Integrity API as the backend-side defense that closes the gap regardless of client bypass. |
| **Cleanup** | Stop non-default frida-server; uninstall patched APK if no longer needed. |
| **Mitre** | T1627.001-Adversary-in-the-Mobile-Device; T1036-Masquerading (analogous) |
| **Difficulty** | HIGH |
| **Tags** | anti-frida, evasion, magisk, gadget |

---

## Mapping Summary

| Test Case | Skill Section | Primary Tool | Difficulty |
|------|------|------|------|
| TC-MI-001 | 1 | frida / frida-server | EASY |
| TC-MI-002 | 2 | Clutch / iPAA | EASY |
| TC-MI-003 | 3 | adb / apktool / jadx | EASY |
| TC-MI-004 | 8 | frida + mitmproxy | MEDIUM |
| TC-MI-005 | 7 | objection | MEDIUM |
| TC-MI-006 | 11 | objection (ios keychain) | MEDIUM |
| TC-MI-007 | 12 | frida | HIGH |
| TC-MI-008 | 9 | frida | HIGH |
| TC-MI-009 | 10 | frida | HIGH |
| TC-MI-010 | 13 | r2frida | HIGH |
| TC-MI-011 | 14 | frida | HIGH |
| TC-MI-012 | 16 | frida + Magisk + objection | HIGH |
