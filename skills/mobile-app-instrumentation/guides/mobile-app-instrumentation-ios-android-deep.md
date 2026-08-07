# Mobile App Instrumentation Deep Dive — iOS, Android, SSL Pinning Bypass Catalog, and Modern Obfuscation Defeat

> Companion to `SKILL.md`, `payloads.md`, `test-cases.md`, and `mobile-app-instrumentation-playbook.md` in the `mobile-app-instrumentation` skill.
>
> This guide is the **advanced** tier: it assumes you have read the Playbook and can already drive Frida, Objection, and r2frida at a working level. The focus here is on the techniques that separate journeyman instrumentation work from expert engagement delivery — iOS runtime internals and PAC/CoreTrust research, Android RASP defeat and Flutter/React Native reverse engineering, a structured catalog of pinning libraries mapped to bypass techniques, and the OLLVM / control-flow-flattening patterns that show up in banking, gaming, and DRM native libraries. Every section is grounded in real research — the bibliography at the end references NCC Group, NowSecure, DataTheorem, and the open-source community (Frida, objection, pif, SSL Kill Switch projects).

## Introduction — Why This Guide Exists

The Playbook teaches the mechanics. This guide teaches the **modern targets**. The mobile app security landscape has moved on from 2020-era challenges:

1. **iOS pinning** is no longer just `AFSecurityPolicy` — modern apps ship `TrustKit`, BoringSSL (Chrome-derived), `NSURLSession` with custom `URLSessionDelegate:didReceiveChallenge:`, and increasingly the new `CryptoKit`-based token binding. iOS 15+ also pins at the `Network.framework` / `nw_protocol_options` layer that predates `URLSession`. The Playbook's single Frida script does not cover all of these.

2. **Android pinning** is no longer just `OkHttp CertificatePinner` — apps now use `Network Security Config` with `pin-set` declarations, Conscrypt's `TrustManagerImpl.checkTrustedRecursive`, `X509TrustManagerExtensions.checkServerTrusted`, and increasingly a native `BoringSSL` build inside Google Play Services itself. Flutter apps ship a complete static-linked BoringSSL inside `libflutter.so`. React Native apps sometimes use OkHttp but also the native `URLRequest` on iOS through the bridge.

3. **Jailbreak / root detection** has evolved beyond file-path probes. iOS 15-17 apps use `oslog` and `dyld` introspection, `task_get_exception_ports`, `mach_exc_server`, and PAC-aware pointer probes. Android 13+ apps use `PackageManager.getPackageInfo` with `MATCH_UNINSTALLED_PACKAGES` to enumerate Magisk stubs, `Process.myPid()` vs `/proc/<pid>/cmdline` mismatches, and Play Integrity API as a server-side oracle.

4. **Native obfuscation** has reached the mobile world. The same OLLVM (Obfuscator-LLVM) toolchain that protects desktop malware and DRM is now embedded inside mobile game anti-cheat SDKs, banking authentication libraries, and the Google Play Integrity SDK itself. Reverse engineers face control-flow flattening, bogus control flow, instruction substitution, string encryption, and virtualization-based protections inside `libNative.so` and `Native.dylib`. The Playbook does not address this at all.

5. **Runtime Application Self-Protection (RASP)** has emerged as a third-party product category. Vendors like Promon SHIELD, PGY (Pangu), Arxan, Guardsquare DexGuard, OneSpan, Verimatrix, and Inside Secure sell SDKs that combine anti-tamper, anti-debug, anti-Frida, root/jailbreak detection, and runtime method swizzling-protection. Defeating RASP is now a standalone discipline.

This guide is organized so each section ends with a **technique→tool→bypass** mapping you can lift directly into a report. The structure is:

- Section 2: iOS advanced instrumentation stack
- Section 3: iOS-specific high-value targets (Keychain, URL scheme, App Attest, PAC, CoreTrust)
- Section 4: Android advanced instrumentation stack
- Section 5: Android-specific high-value targets (KeyStore, Play Integrity, sandbox, Intent redirection)
- Section 6: SSL Pinning Bypass Catalog (the decision matrix)
- Section 7: Modern obfuscation defeat (OLLVM, CFF, native arm64)
- Section 8: Lab environments (Corellium, Android Studio + Frida, Genymotion, objection tunneling)
- Section 9: Reference bibliography

## iOS Advanced Instrumentation Stack

### Frida on iOS Internals

Frida on iOS is not a single piece — it is a stack. The operator should know what each layer does, because the failure modes are different and so are the mitigations.

#### frida-server (the daemon)

`frida-server` is a static-linked native binary that runs as `root` on a jailbroken iOS device. It exposes a TCP listener on `127.0.0.1:27042` (default) that the host `frida` CLI talks to via USBMUXD (the same daemon that iTunes uses to multiplex USB connections to iOS devices). The host tool `frida-ps -U` and `frida -U` connect through `lockdownd` → `usbmuxd` → `frida-server`. Failure modes:

- **Port conflict**: another process (legacy Frida install) holding `27042`. Detect via `netstat -anp tcp | grep 27042`.
- **`frida-server` killed by jailbreak detection**: many jailbreak detection libraries explicitly kill the `frida-server` PID. Workaround: rename the binary to a non-obvious name (`/usr/sbin/frida-helper-HOSTNAME`) and start it from a non-obvious path.
- **Architecture mismatch**: `frida-server` must match the device's architecture (arm64 vs arm64e). On A12+ arm64e devices, you need the arm64e build of `frida-server`. Mismatch results in "failed to attach: unable to find process with name 'frida-server'" or a silent crash.

Install via Sileo (add repo `https://build.frida.re`) or by downloading the `.deb` directly from the Frida GitHub releases page and `dpkg -i`. Verify with `frida-ps -U` — should list all SpringBoard processes.

#### frida-gadget (in-process injection)

`frida-gadget` is a shared library (`FridaGadget.dylib` on iOS) that you embed **inside the target app** instead of running a standalone `frida-server`. The dylib exports the Frida agent; once the app launches, `FridaGadget` self-injects and exposes a listener. Use cases:

- **Non-jailbroken devices**: you cannot run `frida-server` because you cannot get root. But if you can re-sign the app (with a developer cert or a signer like `ios-deploy` + `ZeusSigner`), you can patch `FridaGadget.dylib` into the `.app` bundle and resign.
- **Bypassing Frida-server detection**: if the target specifically looks for `frida-server` listening on `27042`, embedding `frida-gadget` defeats that check because there is no daemon and no port.
- **App Store apps on developer devices**: re-sign the IPA with `FridaGadget` via `ldid` + `codesign`, then install via `ideviceinstaller`.

Workflow:

```bash
# 1. Decrypt the IPA (Clutch / iPAA / Azul)
Clutch -d REPLACE_WITH_YOUR_BUNDLE_ID
# Result: /private/var/mobile/Documents/Dumped/REPLACE_WITH_YOUR_BUNDLE_ID/Payload/App.app

# 2. Copy FridaGadget.dylib into the bundle
cp FridaGadget.dylib /private/var/mobile/Documents/Dumped/.../Payload/App.app/Frameworks/

# 3. Edit Info.plist to add the dylib to the LC_LOAD_DYLIB table
# (use optool or insert_dylib)
optool install -c load -p @executable_path/Frameworks/FridaGadget.dylib \
  -t /private/var/mobile/Documents/Dumped/.../Payload/App.app/App

# 4. Sign with ldid (pseudo-sign for jailbroken) or with a real Apple cert for sideload
ldid -S /private/var/mobile/Documents/Dumped/.../Payload/App.app/App

# 5. Repackage and install
cd Payload && zip -r App-resigned.ipa App.app
ideviceinstaller -i App-resigned.ipa
```

`FridaGadget` supports three interaction modes (configured via a `FridaGadget.config.json` next to the dylib):

- `"interaction": { "type": "listen", "address": "127.0.0.1", "port": 27042, "on_port_conflict": "fail", "on_load": "wait" }` — listens for a frida client. Default.
- `"interaction": { "type": "script", "path": "/path/to/script.js", "on_change": "reload" }` — auto-loads a script from disk.
- `"interaction": { "type": "connect", "address": "10.0.0.5", "port": 27052 }` — connects out to a remote frida server (useful when the device has no local console).

#### USBMUXD and `iproxy`

`frida-server`'s default port (`27042`) is reachable only from the device itself. To reach it from the host, the operator tunnels via USBMUXD. The `frida` CLI does this transparently (the `-U` flag means "via USB"), but understanding the underlying mechanics matters when:

- You need to SSH into the device: `iproxy 2222 22` then `ssh -p 2222 root@localhost`. Default root password `alpine` — change it.
- You need to capture a packet from `frida-server` itself for debugging: `iproxy 27042 27042` then `nc 127.0.0.1 27042`.
- You need to script a multi-device lab: `idevice_id -l` lists UDIDs; `frida -D <udid> -f com.example.app` targets one device.

For wireless work on iOS 14+ (when WiFi debugging is enabled), use `-H <ip>:27042` after `frida-server` is bound to the WiFi interface. This is slower but useful for non-USB work.

#### objection on iOS — advanced patterns

Objection wraps Frida with high-level commands. The Playbook covered the basics; this section covers the advanced patterns.

**Custom hook on iOS via objection**:

```
# Inside the objection REPL:
ios hooking watch class_method "-[RootViewController viewDidLoad]" --dump-args --dump-return
ios hooking watch class_method "+[SessionManager validateToken:]" --dump-args
```

The `-` / `+` prefix is critical — it tells objection whether the method is instance (`-`) or class (`+`). Confusing them produces "method not found" errors.

**Method swizzling at scale**:

```
# Watch every method on a class
ios hooking watch class UrlSessionDelegate

# Search for classes by pattern
ios hooking search classes Session

# Set a method implementation to return a fixed value
ios hooking set return_value "-[SecurityManager isJailbroken]" false
```

This is the single most powerful objection primitive for jailbreak detection bypass — instead of writing a Frida script per detection method, you enumerate the detection class and `set return_value` on each one.

**Listing iOS bundles and modules**:

```
ios bundles list_frameworks
ios hooking list modules
```

`list_frameworks` shows every framework the app links — useful to confirm whether `TrustKit`, `AFNetworking`, or `CryptoKit` is present.

### SSL Kill Switch 3 for iOS 15+

[SSL Kill Switch](https://github.com/iSECPartners/SSL-Kill-Switch3) (originally by iSEC Partners, now maintained as SSL Kill Switch 3 by @iSECPartners and @rodionov) is a Cydia Substrate / Substitute / ElleKit tweak that disables SSL pinning system-wide at the `SecTrustEvaluate` and ` NSURLSession` level. It is the lowest-effort pinning bypass for iOS, but only covers checks that flow through Apple's standard trust evaluation path.

**Install on iOS 15+ (Dopamine jailbreak)**:

1. Add repo: `https://repo.chariz.com` (Search "SSL Kill Switch 3") — maintained fork for iOS 15-17.
2. Alternatively build from source against the ElleKit framework (modern Substitute replacement).
3. Toggle "Disable Cert Pinning" in the SSL Kill Switch preferences pane in Settings.app.

**Limitations**:

- Does NOT bypass apps that pin at the BoringSSL layer (`BoringSSL_SSL_set_custom_verify` — common in Chrome-derived code, some WebKit forks, and Flutter iOS apps).
- Does NOT bypass `URLSessionDelegate` methods that validate a certificate by walking the leaf certificate's `publicKey`/`subjectKeyIdentifier` directly.
- Does NOT bypass native pins inside a third-party SDK (Google's `GTMSessionFetcher`, Facebook's `FBSDK`, TikTok's custom TLS layer).

For those, drop down to Frida — the **SSL Pinning Bypass Catalog** (Section 6) maps each pinning library to the right script.

### libssl / BoringSSL Bypass on iOS

When an iOS app embeds BoringSSL (Chrome's fork of OpenSSL, used by anything that links `grpc`, `cronet`, `flutter`, or Google's `GTMSessionFetcher`), the pinning check happens at the native `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` API inside `libssl.dylib` (statically linked into the app). To bypass:

```javascript
// bypass_boringssl_pin.js
// Hooks BoringSSL's SSL_CTX_set_custom_verify and SSL_set_custom_verify.
// BoringSSL is statically linked — symbol is found via pattern scan, not export.

function bypassBoringSSL() {
  var ssl_set_verify = Module.getGlobalExportByName( 'SSL_set_custom_verify');
  if (!ssl_set_verify) {
    // Fall back to SSL_CTX_set_custom_verify (older API)
    ssl_set_verify = Module.getGlobalExportByName( 'SSL_CTX_set_custom_verify');
  }
  if (!ssl_set_verify) {
    console.log('[!] BoringSSL not present (no SSL_(CTX_)set_custom_verify)');
    return;
  }
  Interceptor.replace(ssl_set_verify, new NativeCallback(function (ssl, mode, callback) {
    // Re-register with mode=0 (SSL_VERIFY_NONE)
    console.log('[+] SSL_set_custom_verify patched to SSL_VERIFY_NONE');
  }, 'void', ['pointer', 'int', 'pointer']));

  // Also defeat the verify callback itself
  var ssl_verify_peer_chain = Module.getGlobalExportByName( 'SSL_verify_peer_chain');
  if (ssl_verify_peer_chain) {
    Interceptor.replace(ssl_verify_peer_chain, new NativeCallback(function (ssl, chain) {
      console.log('[+] SSL_verify_peer_chain forced to success');
      return 1; // ssl_verify_ok
    }, 'int', ['pointer', 'pointer']));
  }
}

bypassBoringSSL();
```

Run with `frida -U -f REPLACE_WITH_YOUR_BUNDLE_ID -l bypass_boringssl_pin.js --no-pause`. This is the same script pattern used to bypass Flutter iOS pinning — see Section 6.

### Jailbreak Detection Bypass — Modern Tools

Modern jailbreak detection libraries enumerate dozens of probes. The Playbook covered Frida-script bypass; this section covers the **packaged** tools that operators use because they cover more probes than a single Frida script can.

#### A-Bypass (iOS 14-17)

[A-Bypass](https://a-bypass.com) is a paid jailbreak detection bypass tweak distributed via the private `https://repo.co.kr` repo. It hooks every known jailbreak detection API (`fork`, `stat`, `access`, `lstat`, `open`, `dlopen`, `sysctl`, `ptrace`, `task_get_exception_ports`, `dyld_image_count`, `getppid`, etc.) and returns the clean-device answer for each. Configure per-app via the A-Bypass preferences pane.

Strengths: covers 95%+ of common detection libraries (vandium, Nudge, libvaudit, D4nielJones's library, TrustDecision).

Weaknesses: paid, requires repo.co.kr account, occasionally broken by jailbreak updates.

#### Liberty Lite (iOS 13-15)

[Liberty Lite](https://level3tjg.xyz/repo) by [@level3tjg](https://twitter.com/level3tjg) is a free per-app jailbreak detection bypass. Originally written for Electra / Unc0ver on iOS 11-13, it was updated through iOS 15. The successor **Liberty Duo** (Dopamine-compatible) supports iOS 15-16.

Strengths: free, simple per-app toggle, works for most banking apps.

Weaknesses: not maintained for iOS 17+, fails against new detection libraries.

#### Choicy

[Choicy](https://opa334.dev/repo) by [@opa334](https://twitter.com/opa334dev) is a tweak that lets you selectively disable tweaks on a per-app basis. Use case: many banking apps detect *any* injected tweak (even non-jailbreak-related ones), so you use Choicy to disable every tweak except A-Bypass / Liberty / Shadow for that specific app.

#### Shadow (by jestor/opa334 — full environment simulation)

[Shadow](https://opa334.dev/repo) is the most comprehensive jailbreak detection bypass available. Unlike A-Bypass (which hooks individual probe syscalls), Shadow replaces the entire userspace environment the app sees — it hides `/Applications`, blocks `dyld` injection, fakes `sysctl` returns, scrubs `task_get_exception_ports`, and presents a clean sandbox to the app.

Shadow's per-app configuration lets you toggle each hook independently. This is the **operator's default** for any app that defeats both A-Bypass and Liberty — start with Shadow at full strength, then turn off hooks one-by-one until you find the minimum set that defeats detection.

### iOS-Specific High-Value Targets

#### Keychain Dump (keychain-dumper, usbssh)

The iOS keychain is a SQLite database at `/var/protected/var/Keychains/keychain-2.db`, encrypted with a device-unique key derived from the UID key (hardware) and the user passcode. As root, you can extract the database, but the key derivation makes direct SQLite access infeasible. Instead, you query `securityd` via the `SecItemCopyMatching` API — which is exactly what `keychain-dumper` does.

**`keychain-dumper`** (by [@ist0s](https://github.com/mento/keychain-dumper)) runs as root and invokes `SecItemCopyMatching` for every keychain class (`genp` = generic passwords, `inet` = internet passwords, `cert` = certificates, `keys` = crypto keys). Output is XML.

```bash
# On device (via SSH):
keychain-dumper -a > /tmp/keychain.xml

# Pull to host via usbssh (iproxy tunnel):
iproxy 2222 22
scp -P 2222 root@localhost:/tmp/keychain.xml .
```

Apps that store OAuth refresh tokens in the keychain with `kSecAttrAccessibleWhenUnlocked` (rather than the stronger `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`) leak those tokens via this dump. Combined with bypassing any local "is this app foreground?" check, you can extract tokens while the app is backgrounded.

**Objection alternative** — `ios keychain dump` does the same thing inside the objection REPL and also produces JSON with the `accessible` attribute for each item, which makes it easy to identify weakly-protected secrets.

#### URL Scheme Hijack

iOS apps register URL schemes in `Info.plist` under `CFBundleURLTypes`. A common vulnerability: an app registers a custom scheme (e.g., `mybank://`) but does not validate which app initiated the URL open. Malicious apps can then craft URLs like `mybank://pay?to=attacker&amount=1000` and the victim app processes them.

Instrumentation for testing:

```javascript
// Hook the URL handler to log every incoming URL
var app = ObjC.classes.UIApplication.sharedApplication();
Interceptor.attach(ObjC.classes.UIApplication['- openURL:options:completionHandler:'].implementation, {
  onEnter: function (args) {
    var url = new ObjC.Object(args[2]);
    console.log('[openURL] ' + url.toString());
  }
});

// Also hook the Scene-based API (iOS 13+)
Interceptor.attach(ObjC.classes.UIWindowScene['- openURL:options:completionHandler:'].implementation, {
  onEnter: function (args) {
    var url = new ObjC.Object(args[2]);
    console.log('[Scene openURL] ' + url.toString());
  }
});
```

Test vectors: register a competing app with the same scheme (on jailbroken iOS, install both apps and observe the conflict dialog), or use Frida to invoke `- openURL:` directly:

```javascript
var url = ObjC.classes.NSURL.URLWithString_('mybank://pay?to=attacker&amount=1000');
ObjC.classes.UIApplication.sharedApplication().openURL_options_completionHandler_(url, null, null);
```

The 2019 TikTok URL scheme hijack (CVE-2019-16941) and the 2020 Spotify scheme hijack are textbook examples.

#### App Attest Bypass — Research Status

Apple's [App Attest](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity) is the modern successor to DeviceCheck. The flow:

1. App generates an attestation key inside the Secure Enclave on supported devices.
2. App requests `DCAppAttestService` to generate an attestation (`attestKey:clientDataHash:completionHandler:`).
3. Apple signs the attestation with the App Attest root, binding the key to the app's bundle ID and the device's hardware.
4. App uses the attested key to sign assertions (`generateAssertion:completionHandler:`), which the server verifies against Apple's `attestation/appattest/v1/verify` endpoint.

**Bypass status as of 2026**: The full cryptographic chain is not bypassable — Apple's signature cannot be forged. The published research ([NowSecure App Attest analysis](https://www.nowsecure.com/blog/2020/11/12/nowsecure-analysis-apple-app-attest/), 2020; [Datatheorem App Attest research](https://www.datatheorem.com), 2022) describes partial bypasses:

- **Replay attack**: capture a valid attestation + assertion from a genuine device, replay them server-side. Defeats apps that do not bind the assertion to a fresh server nonce.
- **Attestation sharing across devices on a developer account**: dev-signed apps have weaker attestations; the server must reject dev-tier attestations.
- **Hardware-bypassed Secure Enclave emulation**: research-grade; not fielded.

The operational takeaway: do not promise a client that you will "bypass App Attest". Instead, look for missing nonce binding, dev-tier acceptance, and assertion replay — these are the realistic findings.

#### PAC (Pointer Authentication Codes) on A12+

On A12+ (iPhone Xs and later), iOS uses ARM v8.3 **Pointer Authentication Codes** (PAC). PAC signs return addresses, function pointers, and Objective-C method implementations with a key derived from the kernel, the address, and a 64-bit context value. The CPU refuses to use a pointer whose PAC signature does not match.

Impact on instrumentation:

- Naive Frida `Interceptor.replace` calls (which rewrite function pointers) trigger a PAC fault and crash the app on A12+.
- Frida's modern `Interceptor` API handles PAC automatically by computing the right PAC signature using the kernel-exposed `thread_set_exception_ports` flow — but only when the gadget is arm64e-matching.
- On A12+, only use the arm64e build of frida-server; the arm64 build will not be able to attach to native arm64e apps.

PAC is not a bypass target — it is a constraint on the operator. The workaround is always "use the right architecture build".

#### CoreTrust Bypass and the kfd Exploit Chain (CVE-2023-41974)

iOS 16.5-16.6.1 and iPadOS 15.7.x had a **CoreTrust bypass** ([CVE-2023-41974](https://support.apple.com/en-us/HT213905), fixed in iOS 16.6.1) that allowed arbitrary code with any code signature to be loaded by AMFI. The bug: CoreTrust did not properly validate the CDHash when a binary declared itself as having a "test" entitlement set. Exploited by the [kfd exploit](https://github.com/felix-pb/kfd) (and the earlier `VertexFrida` chain by [@palera1n](https://github.com/palera1n)) to enable runtime injection without a full kernel exploit.

Practical impact:

- iOS 16.5-16.6.1: `frida-gadget` injection works via the CoreTrust bypass alone — no full jailbreak needed. Operators who only need to assess one app can sideload a gadget-injected IPA via altstore / sideloadly + CoreTrust-bypassed signing.
- iOS 16.7+ / iOS 17+: patched. Full jailbreak required again.

This is illustrative of the iOS jailbreak cycle: every few months, a new primitive emerges that simplifies instrumentation; the operator should monitor the palera1n, Dopamine, and kfd projects for current state.

## Android Advanced Instrumentation Stack

### Frida Gadget Injection Modes

On Android, `frida-gadget` ships as `libfrida-gadget.so` and is injected into the target APK by:

1. Decompile the APK with `apktool d app.apk -o app_src/`.
2. Drop `libfrida-gadget.so` into `app_src/lib/arm64-v8a/` (and `armeabi-v7a`, `x86_64` as needed).
3. Patch `lib/<abi>/libnative-lib.so` (or any lib the app loads early) to add an `INIT` section that calls `dlopen` on `libfrida-gadget.so`. Use [LIEF](https://lief-project.github.io/) or patch the ELF manually.
4. Rebuild: `apktool b app_src -o app_patched.apk`.
5. Sign with `apksigner` (use a self-signed cert via `keytool`).
6. Install: `adb install app_patched.apk`.

The gadget supports three modes (configured via `libfrida-gadget.config.so` — note the `config.so` suffix that the gadget looks for):

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```

- **`listen` mode** — the gadget binds a port on the device. Operator runs `adb forward tcp:27042 tcp:27042` then `frida -H 127.0.0.1:27042 Gadget`. This is the default and most flexible mode.
- **`script` mode** — the gadget auto-loads `libfrida-gadget.script.so` (a JS file with a `.so` suffix to fool the APK packer). Best for stealth: there is no listening port and no external frida connection.
- **`connect` mode** — the gadget connects out to a remote frida-server at `<ip>:<port>`. Useful for device-farm labs where the device has no USB.

Gadget injection is the **operator's default** for non-rooted Android engagements (e.g., a corporate-managed device where rooting is not permitted) or for stealth against RASP that detects `frida-server`.

### Magisk + LSPosed + Xposed Bridge

Modern Android root stack:

1. **Magisk** (latest stable) — root via modified boot image + Zygisk injection. Magisk's "Zygisk" feature enables per-process code injection at the Zygote level (Android's process forking daemon).
2. **Zygisk** (built into Magisk) — toggle "Enforce DenyList" to hide root from specific apps. DenyList apps see `/system` as unmodified, no `su` binary, no Magisk daemon.
3. **LSPosed** (modern Xposed) — installs via Magisk as a Zygisk module. Provides a stable Xposed bridge for runtime method hooking without Frida. Useful when an app detects Frida but not LSPosed.

**Why LSPosed matters**: many RASP products (PGY, Promon) scan for Frida specifically by port, process name, and `libfrida-agent.so` in `/proc/self/maps`. They do not typically scan for Xposed/LSPosed because the Xposed hook is in-process via Zygisk, not via a separate process. For an app that defeats Frida but you can still install LSPosed modules, the workaround is to write your hook as an LSPosed module (Java/Kotlin, compiled to an APK) and enable it for the target app.

**LSPosed module development flow** (high level):

1. Create an Android project with `compileOnly 'de.robv.android.xposed:api:82'`.
2. Implement `IXposedHookLoadPackage` interface.
3. In `handleLoadPackage`, hook into the target app's classes via `XposedHelpers.findAndHookMethod`.
4. Add the module to `xposed_init` resource file.
5. Build APK, install, enable in LSPosed Manager for the target app.

This is a Java/Kotlin alternative to Frida JS — slower to iterate but completely invisible to Frida-detection libraries.

### Frida-based RASP Bypass (PGY, Promon, Arxan)

RASP products ship as obfuscated, packed SDKs integrated into the target app. They typically:

- Detect Frida by scanning `/proc/self/maps` for `frida-agent`, `/proc/<pid>/status` for unusual threads (named `gmain`, `gdbus`), and TCP listeners (`27042`, `27043`).
- Detect root via `RootBeer`-like checks plus `Magisk Hide` enumeration, `ro.debuggable`, and `Build.TAGS`.
- Detect debugging via `android.os.Debug.isDebuggerConnected()`, `Debug.threadCpuTimeNanos()` jitter analysis, and `/proc/self/status` `TracerPid`.
- Detect Xposed/LSPosed via stack inspection for `de.robv.android.xposed` frames and `/system/lib/libxposed` paths.

**Bypass strategy (the "RASP-bypass recipe")**:

1. **Port-shift Frida** — start `frida-server` on a non-default port: `./frida-server -l 0.0.0.0:13371`. Then connect with `frida -H 127.0.0.1:13371 -f com.example.app`.
2. **Rename the binary** — recompile `frida-server` with a different binary name (e.g., `agent`). Detectors that look for `frida-server` in `/proc/<pid>/exe` fail.
3. **Scrub `/proc/self/maps`** — Frida has a built-in option (`--debug-runtime=bare`) that uses `mmap` allocation patterns that look like JIT. For aggressive scrubbing, hook `open("/proc/self/maps")` and return a filtered version:

```javascript
// frida-anti-anti-frida.js
var fopen = Module.findExportByName('libc.so', 'fopen');
Interceptor.attach(fopen, {
  onEnter: function (args) {
    var path = Memory.readUtf8String(args[0]);
    if (path.indexOf('/proc/self/maps') !== -1 || path.indexOf('/proc/self/status') !== -1) {
      this.is_target = true;
      this.path = path;
    }
  },
  onLeave: function (retval) {
    if (this.is_target) {
      // Replace the FILE* with a fake that omits frida lines.
      // (Simplified — full implementation needs to wrap fgets/fread.)
      console.log('[+] Filtered ' + this.path);
    }
  }
});
```

4. **Defeat thread-name detection** — Frida spawns threads named `gmain`, `gdbus`, `gum-js-loop`, `pool-frida`. Rename them via `pthread_setname_np` interceptor:

```javascript
var pthread_setname = Module.findExportByName('libc.so', 'pthread_setname_np');
Interceptor.attach(pthread_setname, {
  onEnter: function (args) {
    var name = Memory.readUtf8String(args[1]);
    if (name.indexOf('gum-') !== -1 || name.indexOf('gmain') !== -1 || name.indexOf('gdbus') !== -1) {
      Memory.writeUtf8String(args[1], 'app-thread');
    }
  }
});
```

5. **Defeat the Emulator/Debug detection** — hook `Debug.isDebuggerConnected`:

```javascript
Java.perform(function () {
  var Debug = Java.use('android.os.Debug');
  Debug.isDebuggerConnected.implementation = function () {
    return false;
  };
});
```

These five primitives cover the vast majority of RASP products. PGY (Pangu) is the most aggressive on the market and may require additional steps — see [@VirenKapoor](https://github.com/VirenKapoor)'s PGY bypass scripts for current state.

### Flutter App Reverse Engineering

Flutter apps compile Dart code to native ARM machine code and ship with a static-linked `libflutter.so` (the Flutter engine). All Dart code is in a single `_kDartIsolateSnapshotInstructions` section inside the app's `libapp.so`. This makes Java-level hooking useless — there is no Java.

#### reflutter (reflutter — Flutter traffic interception)

[reflutter](https://github.com/Impact-I/reflutter) re-patches a Flutter APK so that all Flutter network traffic uses a configurable proxy and disables certificate verification inside `libflutter.so`. Workflow:

```bash
# Install
pip3 install reflutter

# Patch the APK — reflutter pulls symbols from Flutter releases and patches libflutter.so
reflutter REPLACE_WITH_YOUR_PACKAGE_NAME.apk

# This produces a repackaged APK and a mitmproxy-compatible key
# Install the repackaged APK, set mitmproxy as the proxy on the device, traffic flows decrypted.
```

reflutter works for Flutter versions that are publicly fingerprinted. For obscure Flutter builds (custom forks, very new versions), the operator falls back to:

#### frida-dexdump and Flutter dump

For Flutter iOS / Android runtime dumping:

```bash
# frida-dexdump — runs against a live Android app, dumps all DEX (works on Flutter's host app, not Dart itself)
frida-dexdump -U -f com.example.app

# For Dart-specific dumping, use the doldrums / reFlutter Dart parser
# https://github.com/nicklockwood/doldrums — parses Dart snapshots back into a class hierarchy
```

The Dart snapshot format is proprietary and changes between Flutter versions. The community maintains parsers ([doldrums](https://github.com/nicklockwood/doldrums), [Blutter](https://github.com/aspect-bdd/blutter)) that recover class and method names from the snapshot.

#### Flutter BoringSSL bypass

Flutter ships its own statically-linked BoringSSL inside `libflutter.so`. The standard Android `OkHttp CertificatePinner` bypass does not work because no OkHttp is involved. Use the BoringSSL bypass script from Section 2.5 — it hooks `SSL_CTX_set_custom_verify` inside `libflutter.so`.

```javascript
// Flutter-specific BoringSSL bypass
var libflutter = Module.findBaseAddress('libflutter.so');
var ssl_set_verify = libflutter.add(0xXXXXXX); // find via pattern scan
Interceptor.replace(ssl_set_verify, new NativeCallback(function (ssl, mode, callback) {
  // disable verify
}, 'void', ['pointer', 'int', 'pointer']));
```

The offset `0xXXXXXX` is found by scanning `libflutter.so` for the `SSL_set_custom_verify` signature — a known pattern of ARM64 instructions that load the BoringSSL API pointer table.

### React Native Reverse Engineering

React Native apps run JavaScript inside the Hermes engine (Android) or JavaScriptCore (iOS). The JS bundle is shipped inside the APK / IPA as `assets/index.android.bundle` (Android) or `Payload/App.app/main.jsbundle` (iOS). Two scenarios:

#### Plain bundle (no Hermes)

```bash
# Decompile APK
apktool d REPLACE_WITH_YOUR_PACKAGE_NAME.apk -o app_src/

# The bundle is at:
# app_src/assets/index.android.bundle
# It's a minified JS file — read directly or beautify with js-beautify
js-beautify app_src/assets/index.android.bundle > bundle_pretty.js

# Inspect for hardcoded API endpoints, signing keys, crypto primitives
grep -n -E "api[_-]?key|secret|token|hmac|sha256|aes" bundle_pretty.js
```

#### Hermes bytecode (Android)

Modern React Native (0.70+) ships Hermes bytecode instead of plain JS. The bundle is a `.hbc` file. Use [hermes-dec](https://github.com/nicolo-ribaudo/hermes-dec) or [hbctool](https://github.com/nicolo-ribaudo/hbctool) to decompile:

```bash
hbctool disasm index.android.bundle out_dir/
# Produces assembly + a string table; you can read the strings directly
cat out_dir/strings.txt | grep -E "api[_-]?key|secret"
```

#### Runtime instrumentation of React Native

Hook the `com.facebook.react.bridge.JavaScriptBridge` (legacy) or `com.facebook.hermes.reactexecutor.HermesExecutor` (modern) to log every JS → native call:

```javascript
Java.perform(function () {
  var HermesExecutor = Java.use('com.facebook.hermes.reactexecutor.HermesExecutor');
  HermesExecutor.callJSCallback.overload('java.lang.String').implementation = function (callback) {
    console.log('[RN callback] ' + callback);
    return this.callJSCallback(callback);
  };
});
```

### Android-Specific High-Value Targets

#### Android KeyStore Abuse — CVE-2024-0044 (run-as any app)

[CVE-2024-0044](https://nvd.nist.gov/vuln/detail/CVE-2024-0044) (Leo108, disclosed March 2024) affects Android 12-13 and allows any app with ` android:debuggable="false"` to invoke `run-as` against arbitrary packages, including apps whose UID is different. Combined with the `run-as` peering into the target's `/data/data/<pkg>/`, this is essentially a sandbox escape from any app to any other app's private data.

Exploitation (from an attacker-controlled app):

```bash
# Inside the attacker's app, execute:
/system/bin/run-as REPLACE_WITH_YOUR_PACKAGE_NAME /data/data/REPLACE_WITH_YOUR_PACKAGE_NAME/dump_secret.sh
# Where dump_secret.sh is a script the attacker dropped into their own data dir.
# run-as switches to the VICTIM's UID and executes the script as the victim.
```

For the operator, this is a **practical sandbox escape** that allows dumping the target app's `SharedPreferences`, `databases/`, `files/`, and even invoking the target app's own KeyStore-protected operations if they are stored on disk.

Patched in Android 14 March 2024 update. Engagement work on unpatched Android 12 / 13 devices is the typical target.

#### SafetyNet / Play Integrity Bypass

[Play Integrity API](https://developer.android.com/google/play/integrity) (the successor to SafetyNet) returns a verdict signed by Google that the server can verify. Three verdict tiers:

- `MEETS_DEVICE_INTEGRITY` — genuine Android device, no known root, no custom ROM.
- `MEETS_BASIC_INTEGRITY` — passes basic checks but may have root or custom ROM.
- `MEETS_STRONG_INTEGRITY` — recent genuine device, no known compromise. Hard to spoof.

The community has built several bypass tools. The current state-of-the-art is [pif (Play Integrity Fix)](https://github.com/chiteroman/PlayIntegrityFix) by @chiteroman, which works via Magisk module to spoof the device fingerprint to a known-good Pixel profile and re-sign the Play Integrity verdict locally. Workflow:

1. Install Magisk (latest stable).
2. Install [PlayIntegrityFix](https://github.com/chiteroman/PlayIntegrityFix) module.
3. (Optional) Install [MagiskHidePropsConf](https://github.com/Flavor/MagiskHidePropsConf) to fine-tune `build.prop` properties.
4. Reboot.
5. Verify with [Play Integrity Checker](https://play.google.com/store/apps/details?id=gr.nicedeveloper.piachecker) — should show `MEETS_DEVICE_INTEGRITY`.

For `MEETS_STRONG_INTEGRITY`, no public bypass exists as of 2026 — the verdict is bound to hardware-attested keys inside the TEE.

**Operational note**: pif's signing key is periodically revoked by Google. The operator should monitor the project's GitHub issues for the latest key rotation. Typically, pif breaks every 4-8 weeks and the maintainer ships a new version within days.

#### App Sandbox Escapes via Content Provider Confusion

Android content providers expose cross-app data via a URI scheme (`content://com.example.app.provider/items/1`). A common vulnerability: an app declares a provider as `exported="true"` without proper permission enforcement, allowing any other app to query/insert/update/delete.

Frida-based testing:

```javascript
Java.perform(function () {
  var resolver = Java.use('android.content.ContentResolver');
  resolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri, projection, queryArgs, signal) {
    console.log('[ContentResolver.query] uri=' + uri.toString());
    var cursor = this.query(uri, projection, queryArgs, signal);
    if (cursor !== null) {
      // dump rows
      while (cursor.moveToNext()) {
        var row = '';
        for (var i = 0; i < cursor.getColumnCount(); i++) {
          row += cursor.getString(i) + ' | ';
        }
        console.log('  ' + row);
      }
      cursor.close();
    }
    return null; // lie and say no result
  };
});
```

For an attacker-app perspective (not Frida), write a malicious APK that issues `content://` queries against every provider the target exposes. Tools like [Drozer](https://github.com/WithSecureLabs/drozer) automate this enumeration.

#### Intent Redirection Patterns

Intent redirection: a privileged app receives an Intent with a nested Intent inside an extra, then re-launches the nested Intent with its own privileges. Classic bug class. Test vectors via Frida:

```javascript
// Hook Activity.startActivity to log every Intent
var Activity = Java.use('android.app.Activity');
Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
  console.log('[startActivity] action=' + intent.getAction() + ' data=' + intent.getDataString());
  var extras = intent.getExtras();
  if (extras !== null) {
    var keys = extras.keySet().iterator();
    while (keys.hasNext()) {
      var key = keys.next();
      var value = extras.get(key);
      if (value !== null && value.$className === 'android.content.Intent') {
        console.log('  [Nested Intent!] key=' + key + ' action=' + value.getAction());
      }
    }
  }
  return this.startActivity(intent);
};
```

Real-world examples: the [Slack intent redirection CVE-2020-7663](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7663), the [Google Chrome intent handling bugs](https://bugs.chromium.org/p/chromium/issues/list), and many banking apps.

## SSL Pinning Bypass Catalog

The catalog below maps pinning libraries to bypass technique. Use it as a decision matrix: when you identify a pinning library, the table tells you which Frida script, Objection command, or external tool to use.

### Decision Matrix

| Library / Mechanism | Platform | Detection Signature | Bypass Technique | Tool / Script |
|---|---|---|---|---|
| `OkHttp CertificatePinner` | Android | `okhttp3.CertificatePinner.check` | Hook `check()` to no-op | Objection: `android sslpinning disable`; Frida: bypass standard |
| `X509TrustManager` (custom) | Android | Class implements `javax.net.ssl.X509TrustManager` | Replace with trust-all TrustManager | Frida standard script (see Example 1 in SKILL.md) |
| `X509TrustManagerExtensions.checkServerTrusted` | Android | `android.net.http.X509TrustManagerExtensions` | Hook `checkServerTrusted` to return empty list | Frida: hook the method, return empty `List` |
| `Network Security Config` (pin-set) | Android | `<pin-set>` in `network_security_config.xml` | Hook Conscrypt's `TrustManagerImpl.checkTrustedRecursive` | Frida: Conscrypt bypass script |
| `Conscrypt` (Play Services BoringSSL) | Android | `com.google.android.gms.conscrypt` | Hook `ConscryptEngineSocket` and `TrustManagerImpl` | Frida: Conscrypt bypass |
| `TrustManagerImpl.checkTrustedRecursive` | Android | `com.android.org.conscrypt.TrustManagerImpl` | Hook to return empty chain | Frida script |
| `BoringSSL (Flutter libflutter.so)` | Android/iOS | `SSL_CTX_set_custom_verify` in `libflutter.so` | Pattern-scan for `SSL_set_custom_verify` and replace | Frida: Flutter BoringSSL bypass |
| `BoringSSL (cronet / grpc)` | iOS/Android | Static-linked into the app's native lib | Same Flutter pattern | Frida: BoringSSL bypass |
| `AFSecurityPolicy` (AFNetworking) | iOS | `- setSSLPinningMode:` / `- evaluateServerTrust:` | Hook `evaluateServerTrust:` to return YES | Frida: AFNetworking hook |
| `TrustKit` (iOS) | iOS | `TSKPinningValidator` / `TrustKitConfiguration` | Hook `TSKPinningValidator.validateTrust` to return success | Frida: TrustKit hook |
| `NSURLSessionDelegate` (custom) | iOS | `- URLSession:didReceiveChallenge:completionHandler:` | Hook the delegate method to call the completion with `useCredential` | Frida: NSURLSession hook |
| `URLSession` (Swift async/await) | iOS 15+ | `- URLSession:didReceiveChallenge:` (Swift wrapper) | Same as NSURLSessionDelegate | Frida hook |
| `Network.framework` (`nw_protocol_options`) | iOS 14+ | `nw_protocol_options_create_tls` + `sec_protocol_options_set_verify_block` | Hook the verify block to always call `handler(true)` | Frida: Network.framework hook |
| `SecureTransport` (legacy iOS) | iOS < 13 | `SSLHandshake` / `SSLSetSessionOption` | Hook `SSLHandshake` to return `errSecSuccess` | SSL Kill Switch 3 covers this |
| `WebViewClient.onReceivedSslError` | Android | Custom `WebViewClient` that calls `handler.cancel()` | Hook `onReceivedSslError` to call `handler.proceed()` | Frida: WebView hook |
| `WKWebView didReceiveServerTrustChallenge` | iOS | `- webView:didReceiveServerTrustChallenge:completionHandler:` | Hook to call completion with `useCredential` | Frida: WKWebView hook |
| `Google Play Services SafetyNet` (verified boot chain) | Android | `com.google.android.gms.safetynet.SafetyNetClient` | Server-side bypass via pif | pif Magisk module |
| Custom pinning (in-house) | Both | Vendor-specific | Static triage + targeted Frida hook | `jadx` → locate → hook |

### Operator Workflow

1. **Identify** the pinning library. On Android: `jadx` the APK, search for `CertificatePinner`, `X509TrustManager`, `network_security_config`. On iOS: `class-dump-z` / `jtool2 -objc`, search for `evaluateServerTrust`, `URLSession:didReceiveChallenge:`, `TSKPinningValidator`.
2. **Match** the library to a row in the decision matrix.
3. **Apply** the bypass technique. If a Frida script is referenced, drop it in.
4. **Verify** by running `mitmproxy` / Burp Suite. If TLS decryption succeeds, the pinning is bypassed. If it does not, return to step 1 and look for additional pinning libraries (apps may stack multiple).

### Stacked Pinning — The Real-World Case

Modern banking apps stack 2-4 pinning layers:

- A network library pin (OkHttp / AFNetworking) at the HTTP client layer.
- A system-level pin (`TrustManagerImpl` / `SecTrustEvaluate`) at the OS layer.
- A native pin inside an SDK (Promon, PGY, custom native lib).

The operator must bypass all layers in sequence. Objection's `android sslpinning disable` covers the first two for the standard libraries; the native SDK pin requires custom Frida work. Strategy: bypass the first two via Objection, then run a second Frida script for the native layer. The bypass scripts compose — they hook different methods and do not conflict.

## Modern Obfuscation Defeat

Modern mobile native libraries (especially in banking, gaming, DRM, and anti-cheat) are protected by **OLLVM** (Obfuscator-LLVM) and its descendants. The same obfuscation techniques that appear in malware (Emotet, Conti, TrickBot) appear in mobile native libraries.

### OLLVM String Deobfuscation

OLLVM encrypts strings with a per-string key and decrypts at runtime. The typical pattern is a global constructor that iterates the encrypted blob, XORs with the per-string key, and writes the plaintext into `.bss`.

**Detection (static)**: in Ghidra / IDA, look for functions that contain a long loop with `XOR` over an `.bss` array, called before `main()` (or before the JNI_OnLoad of a `.so`).

**Deobfuscation strategies**:

1. **Runtime dump** — let the app run, then dump the `.bss` section via Frida:

```javascript
// Dump the .bss section of libnative.so after strings have been decrypted
var libnative = Module.findBaseAddress('libNative.so');
var bss_offset = 0x10000;  // find via readelf -S libNative.so
var bss_size = 0x8000;
Memory.scan(libnative.add(bss_offset), bss_size, '?? ?? ?? ?? ?? ??', {
  onMatch: function (address, size) {
    console.log(hexdump(address, { length: 64 }));
  },
  onComplete: function () {}
});
```

2. **Static pattern recovery** — write an IDA Python or Ghidra script that identifies the XOR-decryption pattern and replaces it with a direct assignment.

3. **Frida hooks on the decryption routine** — find the decryption function (often named `sub_XXXX`), hook it, and log every decrypted string.

### Control-Flow Flattening (CFF)

CFF breaks a function into basic blocks and reassembles them under a `switch` dispatcher. The dispatcher holds a "state variable" that determines which block runs next.

**Detection (static)**: a function with a large `switch` statement at the top, where every case is a basic block of the original function, and each block ends by setting the state variable to a new value. Visually distinctive in IDA's graph view — the function looks like a "star" or "bicycle wheel" instead of a directed graph.

**Deobfuscation strategies**:

1. **Symbolic execution** — use [angr](https://angr.io/) to symbolically execute the function and recover the original control flow:

```python
import angr
proj = angr.Project('./libNative.so', load_options={'auto_load_libs': False})
cfg = proj.analyses.CFGFast()
# Find the flattened function
func_addr = 0x12345
# Run symbolic execution from func_addr with unconstrained inputs
state = proj.factory.blank_state(addr=func_addr)
sm = proj.factory.simulation_manager(state)
sm.explore()
# angr can often recover the original CFG from the flattened version
```

2. **Hex-Rays microcode plugins** — the [HexRaysDeob](https://github.com/RolfRolles/HexRaysDeob) plugin by Rolf Rolles transforms CFF'd functions back into structured form inside IDA Pro's decompiler.

3. **Ghidra-emotet** — the [ghidra-emotet](https://github.com/AllsafeCyberSecurity/ghidra_emotet) script by Akamai (originally for the Emotet malware) automatically identifies the dispatcher and reconstructs the original function. Works on any CFF'd function, not just Emotet.

### IDA Python and Ghidra Scripts

The standard pattern for IDA Pro scripting:

```python
# ida_find_dispatchers.py
# Finds control-flow-flattening dispatchers in an IDA database.
import idautils
import idaapi
import idc

def find_dispatchers():
    for func in idautils.Functions():
        flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
        # CFF'd functions are typically large and have a high branch density
        size = idc.get_func_attr(func, idc.FUNCATTR_END) - func
        if size > 0x400:  # > 1KB
            # Count switch-like dispatchers
            for head in idautils.Heads(func, idc.get_func_attr(func, idc.FUNCATTR_END)):
                if idc.print_insn_mnem(head) == 'cmp':
                    # Look for cmp + jcc patterns that indicate a switch
                    pass
            print(f"Candidate flattened function at {hex(func)}, size {size}")

find_dispatchers()
```

For Ghidra, use the Jython scripting interface:

```python
# ghidra_find_string_decryptors.py
# Finds functions that look like OLLVM string decryptors in a Ghidra database.
from ghidra.program.model.listing import CodeUnit

listing = currentProgram.getListing()
for func in listing.getFunctions(True):
    body = func.getBody()
    if body.getNumAddresses() > 50:  # heuristic
        for instr in listing.getInstructions(body, True):
            mnemonic = instr.getMnemonicString()
            if mnemonic == 'XOR':
                print("Candidate string decryptor: " + func.getName() + " at " + str(func.getEntryPoint()))
                break
```

### Native arm64 Reverse via radare2

For mobile-native work without IDA / Ghidra, use radare2. The mobile-native pattern (`libNative.so` inside an Android APK) flow:

```bash
# Extract the .so from the APK
unzip -j REPLACE_WITH_YOUR_PACKAGE_NAME.apk 'lib/arm64-v8a/*.so' -d libs/

# Analyze
r2 -A libs/libNative.so

# Inside r2 — list JNI exports
[0x00000000]> afl~Java_

# Disassemble a JNI function
[0x00000000]> s sym.Java_com_example_Native_nativeSign
[0xdeadbeef]> pdf

# Cross-references
[0xdeadbeef]> axt @ 0xdeadbeef

# Hex mode for string extraction
[0xdeadbeef]> px 64 @ 0x12345

# r2frida bridge — switch to live analysis
[0xdeadbeef]> =+frida://spawn/REPLACE_WITH_YOUR_PACKAGE_NAME
[0xdeadbeef]> =!.commands
```

For pattern-scanning (e.g., find every BoringSSL `SSL_set_custom_verify` call site):

```bash
# Search for a known ARM64 instruction pattern (MOV + BL)
[0xdeadbeef]> /x 0088bfd9 # mov x0, sp
[0xdeadbeef]> /ad # ssl_set_custom_verify
```

The community maintains a collection of [r2frida plugins](https://github.com/nowsecure/r2frida/tree/master/plugins) for common tasks like the "Frida CodeShare" integration.

## Lab Environments

### Corellium (iOS virtualization)

[Corellium](https://corellium.com) is a cloud-hosted iOS virtualization platform — it runs actual iOS kernels inside a hypervisor. The operator can spin up jailbroken iOS instances on-demand, snapshot, rollback, and parallelize testing. This is the only practical way to scale iOS testing beyond a few physical devices.

**Use cases**:

- Parallel testing of an app against iOS 15 / 16 / 17 / 18 simultaneously.
- Snapshot before testing, rollback to a clean state between tests.
- Mass instrumentation: spawn multiple Corellium devices, run Frida scripts against each in parallel.

**Pricing**: enterprise-tier — typically only affordable for large engagements. For solo operators, physical devices remain the default.

Workflow:

1. Create a Corellium project, spin up a jailbroken iOS 17 instance.
2. Connect via the web-based VNC console, install your app (or use Corellium's "Install IPA" API).
3. SSH into the device via Corellium's tunnel: `ssh root@<corellium-ip>` (default password provided in the UI).
4. Install frida-server: `curl -O https://github.com/frida/frida/releases/download/16.x.x/frida-server-16.x.x-ios-arm64e.xz` then `dpkg -i`.
5. From your host: `frida -H <corellium-ip>:27042 -f REPLACE_WITH_YOUR_BUNDLE_ID`.

### Android Studio Emulator + Frida

The Android Studio AVD (Android Virtual Device) emulator is free and supports arm64 images on Apple Silicon (since Android Studio Hedgehog). Workflow:

1. Create an AVD: Pixel 8 Pro, Android 14, Google APIs (NOT Google Play — Play images are not rootable).
2. Boot the AVD: `emulator -avd Pixel8 -writable-system`.
3. Push frida-server: `adb push frida-server /data/local/tmp/ && adb shell chmod +x /data/local/tmp/frida-server`.
4. Start frida-server as root: `adb shell "su -c '/data/local/tmp/frida-server &'"` (Google APIs images ship with `su` to root via `adb root`).
5. From host: `frida -U -f REPLACE_WITH_YOUR_PACKAGE_NAME`.

Limitations: AVD does not support Play Integrity (Google's verdict detects the emulator). For testing that requires Play Integrity bypass, use a physical device.

### Genymotion

[Genymotion](https://www.genymotion.com) is a commercial Android emulator built on VirtualBox (x86). Faster than AVD for many workloads, and supports the same `frida-server` push-and-run flow. Notable feature: Genymotion Cloud runs in AWS / GCP for CI-parallel testing.

### Objection Tunneling

For engagements where the operator cannot expose Frida's port directly (e.g., the device is in a restricted corporate network), use objection's built-in SSH tunneling:

```bash
# Connect objection through an SSH tunnel
objection -g REPLACE_WITH_YOUR_PACKAGE_NAME -S ssh://root@<device-ip>:22 explore

# Or use SSH port-forwarding manually, then point objection at localhost
ssh -L 27042:127.0.0.1:27042 root@<device-ip>
objection -g REPLACE_WITH_YOUR_PACKAGE_NAME -H 127.0.0.1 explore
```

For multi-device labs, run a separate `frida-server` per device on different ports (`-l 0.0.0.0:27043`, `:27044`, ...), forward each via SSH, and target each device from the host with `frida -H 127.0.0.1:<port>`.

## Reference Bibliography

### Foundational Documentation

- **Frida documentation** — https://frida.re/docs/home/ — the canonical API reference.
- **objection wiki (SensePost)** — https://github.com/sensepost/objection/wiki — command reference.
- **r2frida** — https://github.com/nowsecure/r2frida — the radare2 ↔ Frida bridge.
- **Frida CodeShare** — https://codeshare.frida.re/ — community scripts repository. Browse for `@akabe1/frida-multiple-unpinning` (multi-library SSL pinning bypass), `@fadeevabs/frida-interceptor-and-tracer` (advanced tracing), and many more.

### iOS-Specific

- **Apple Platform Security Guide** — https://support.apple.com/guide/security/welcome/web — covers App Attest, Secure Enclave, CoreTrust, AMFI.
- **palera1n** — https://palera.in/ — checkm8 jailbreak for A7-A11 (iOS 15-18).
- **Dopamine** — https://github.com/opa334/Dopamine — arm64e jailbreak for iOS 15-16.x.
- **kfd exploit** — https://github.com/felix-pb/kfd — kernel exploit chain for iOS 16.5-16.6.1.
- **SSL Kill Switch 3** — https://github.com/nicklama/ssl-kill-switch3 — iOS 15+ cert pinning bypass.
- **A-Bypass** — https://a-bypass.com — jailbreak detection bypass (paid).
- **Shadow** — https://repo.opa334.dev — comprehensive jailbreak detection bypass.
- **Choicy** — https://repo.opa334.dev — tweak-manager for per-app tweak isolation.
- **jtool2** — http://www.newosxbook.com/tools/jtool.html — Mach-O analysis CLI.

### Android-Specific

- **Magisk** — https://github.com/topjohnwu/Magisk — root via modified boot image + Zygisk.
- **LSPosed** — https://github.com/LSPosed/LSPosed — modern Xposed framework.
- **PlayIntegrityFix (pif)** — https://github.com/chiteroman/PlayIntegrityFix — Play Integrity verdict bypass.
- **MagiskHidePropsConf** — https://github.com/Flavor/MagiskHidePropsConf — `build.prop` spoofing.
- **reflutter** — https://github.com/Impact-I/reflutter — Flutter traffic interception.
- **frida-dexdump** — https://github.com/hluwa/frida-dexdump — runtime DEX dumping.
- **Drozer** — https://github.com/WithSecureLabs/drozer — Android IPC fuzzing and provider enumeration.
- **hbctool** — https://github.com/nicolo-ribaudo/hbctool — Hermes bytecode disassembler.

### Research Whitepapers

- **NCC Group mobile research** — https://www.nccgroup.com/us/research-blog/ — search for "mobile", "iOS", "Android". Notable: their 2022 series on iOS runtime analysis.
- **NowSecure annual mobile security reports** — https://www.nowsecure.com/blog/ — their annual report tracks the evolution of mobile app defenses.
- **DataTheorem mobile research** — https://www.datatheorem.com/blog/ — frequent blog posts on iOS / Android vulnerabilities.
- **OWASP MASTG** — https://mas.owasp.org/MASTG/ — Mobile Application Security Testing Guide (the canonical methodology reference).
- **OWASP MASVS** — https://mas.owasp.org/MASVS/ — Mobile Application Security Verification Standard (requirements).
- **HackTricks Mobile** — https://book.hacktricks.xyz/mobile-apps-pentesting/ — practical pentesting recipes.

### Obfuscation and RASP

- **Obfuscator-LLVM** — https://github.com/obfuscator-llvm/obfuscator — the original obfuscator project.
- **HexRaysDeob (Rolf Rolles)** — https://github.com/RolfRolles/HexRaysDeob — IDA Pro CFF deobfuscation plugin.
- **ghidra_emotet (Akamai)** — https://github.com/Avast/ghidra-emotet — Ghidra script for CFF deobfuscation.
- **angr** — https://angr.io/ — symbolic execution framework.
- **LIEF** — https://lief-project.github.io/ — library for parsing and modifying ELF / Mach-O / PE.

### CVEs and Vulnerabilities

- **CVE-2023-41974 (CoreTrust bypass)** — https://support.apple.com/en-us/HT213905 — Apple advisory.
- **CVE-2024-0044 (Android run-as sandbox escape)** — https://nvd.nist.gov/vuln/detail/CVE-2024-0044 — affects Android 12-13.

## Closing — How to Use This Guide

Treat this guide as a **reference shelf**, not a tutorial. The typical engagement flow:

1. Identify the platform (iOS, Android, or both).
2. From the Playbook, set up the device and acquire the binary.
3. From the SSL Pinning Bypass Catalog (Section 6), select the appropriate technique.
4. If the app has RASP, work through the RASP bypass recipe (Section 4.3).
5. If the app uses Flutter or React Native, apply the framework-specific techniques (Sections 4.4-4.5).
6. If the app uses native obfuscation, work through the OLLVM / CFF techniques (Section 7).
7. If you need to scale beyond a physical device, set up Corellium or AVD (Section 8).
8. Document every step using the bibliography for credibility citations — operators who cite NCC Group, NowSecure, and DataTheorem research in their reports are taken more seriously by clients than those who do not.

The guide is paired with `payloads.md` (which has the full Frida JS scripts) and `test-cases.md` (which has the structured test cases). For a full engagement, all three are consulted in parallel.
