---
name: mobile-security
description: "Mobile security covers the complete attack/defense chain of Android/iOS application security testing, APK/IPA reverse engineering, runtime manipulation, certificate pinning bypass, and mobile data protection."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: mobile
  tool_count: 6
  guide_count: 5
---




# Skill: Mobile Security

> **Supplementary Files**:
> - `payloads.md` — Complete mobile security attack/defense chain payloads (APK/IPA analysis, Frida hooks, SSL bypass, storage extraction, Intent attacks, etc.)
> - `test-cases.md` — Structured test cases (static analysis, dynamic analysis, runtime manipulation, network testing, data protection)

## Summary

Mobile Security skill domain covering mobile operations.

**Tools**: frida, objection, apktool, jadx, mobsf, drozer

**Domain**: mobile

## Description

Mobile security covers the complete attack/defense chain of Android/iOS application security testing, APK/IPA reverse engineering, runtime manipulation, certificate pinning bypass, and mobile data protection. The core objective is to identify security flaws in mobile applications, assess client-side defense strength, extract sensitive data, and develop hardening strategies.

Mastering this skill requires a deep understanding of Android APK structure (DEX, Manifest, Resources), iOS IPA structure (Mach-O, Info.plist), mobile sandbox mechanisms, Keychain/Keystore secure storage, and Frida dynamic instrumentation. The agent can comprehensively use tools such as apktool, jadx, Frida, objection, and MobSF to complete the full workflow from application decompilation to runtime manipulation.

---

## Use Cases

1. **Android/iOS Application Penetration Testing** - Perform security assessments on target mobile applications, discovering vulnerabilities such as data leakage, insecure storage, and exposed components
2. **APK Reverse Engineering and Code Audit** - Decompile Android applications, auditing source code for hardcoded credentials, insecure API calls, and logic flaws
3. **SSL Pinning Bypass** - Bypass application certificate pinning mechanisms to intercept and analyze encrypted HTTPS traffic
4. **Runtime Hooking and Data Extraction** - Use Frida for dynamic instrumentation of running applications, hooking encryption functions, bypassing security checks, and extracting sensitive data from memory
5. **Mobile Malware Analysis** - Analyze behavioral characteristics of suspicious APKs/IPAs, extract IoCs, and assess threat levels

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **frida** | Dynamic instrumentation framework, runtime hooks, function tracing, memory read/write | `frida -U -f com.target.app -l hook.js` |
| **objection** | Frida-based mobile runtime exploration toolkit | `objection -g com.target.app explore` |
| **apktool** | APK decompilation and repackaging, restoring Manifest and smali | `apktool d app.apk -o app_source` |
| **jadx** | DEX decompilation to readable Java source code | `jadx app.apk -d app_java` |
| **mobsf** | Mobile application automated security analysis framework (static + dynamic) | `docker run -p 8000:8000 opensecurity/mobsf` |
| **drozer** | Android IPC vulnerability scanning and exploitation framework | `drozer console connect` |

---

## Methodology

### Attack Chain

```
App Decompilation     Static Analysis       Dynamic Analysis     Runtime Manipulation
(apktool, jadx)     (Code audit, Manifest) (Proxy, traffic)   (Frida, objection)
      |                 |                 |                |
      v                 v                 v                v
Information          Vulnerability      Communication        Data Extraction
Collection           Identification     Analysis             & Exploitation
(Package name,      (Hardcoded         (API endpoints,     (Sensitive data
 components,         credentials,       authentication       export,
 permissions, SDK)   exported            mechanisms,         auth bypass,
                       components,       SSL Pinning)        security check
                       insecure                              bypass)
                       storage)
```

1. **App Decompilation** - apktool restores Manifest and smali code, jadx decompiles to readable Java, obtaining complete application structure
2. **Static Analysis** - Audit AndroidManifest.xml (exported components, permissions, debuggable flag), scan for hardcoded credentials and API keys
3. **Dynamic Analysis** - Configure proxy to intercept network traffic, analyze API communication patterns and authentication mechanisms, identify certificate pinning implementations
4. **Runtime Manipulation** - Use Frida to hook key functions (encryption, authentication, checks), bypass security protections, extract runtime sensitive data
5. **Data Extraction and Exploitation** - Export plaintext data from SharedPreferences/SQLite, exploit exported component vulnerabilities, construct Intent attack chains

### Defense Perspective

| Defense Measure | Purpose | Bypass Approach |
|-----------------|---------|-----------------|
| **Code Obfuscation** | ProGuard/R8 obfuscate code, increasing reverse engineering difficulty | Spend time analyzing obfuscation mappings, dynamically hook to bypass static protections |
| **Certificate Pinning** | Pin server certificate fingerprints, preventing MITM attacks | Frida hook TrustManager / OkHttp CertificatePinner |
| **Root/Jailbreak Detection** | Detect whether device is rooted/jailbroken, blocking dangerous environments | Frida hook detection function return values, modify file existence checks |
| **Anti-Tampering** | Detect APK integrity, prevent repackaging | Modify signature verification logic, bypass integrity checks |
| **Secure Storage** | Use Android Keystore / iOS Keychain for sensitive data storage | Hook encryption functions to intercept plaintext before encryption / after decryption |
| **Anti-Debug** | Detect debugger attachment, preventing dynamic analysis | Modify anti-debugging flags, use Frida spawn mode to bypass |

---

## Practical Steps

### 1. APK Decompilation and Static Analysis

Decompile APK to obtain Manifest and smali code, scan for hardcoded credentials and insecure storage patterns.

### 2. Frida Hook Basics

Use Frida Java.perform to hook login methods for credential interception, hook encryption functions to intercept plaintext data.

### 3. SSL Pinning Bypass

Bypass certificate pinning through Frida hooking OkHttp CertificatePinner or replacing TrustManager. Shortcut: `objection -g com.target.app explore` -> `android sslpinning disable`.

### 4. Data Storage Analysis

Check SharedPreferences plaintext storage, SQLite database contents, external storage leakage, exploit allowBackup to extract application data.

### 5. Intent Exploitation and Component Attacks

Use drozer to discover exported components, construct malicious Intents via adb to attack exported Activities, Content Providers, Broadcast Receivers, and Deep Links.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

---

### Cross-Platform Mobile Testing

Modern mobile apps increasingly use cross-platform frameworks that introduce unique attack surfaces:

| Framework | Key Attack Surface | Primary Tools |
|-----------|-------------------|---------------|
| React Native | JS bundle extraction, WebView bridges, AsyncStorage | jadx, Frida, Burp |
| Flutter | Dart snapshot, libapp.so, platform channels | Ghidra, Frida, reFlutter |
| Xamarin | DLL extraction, AOT compilation | dnSpy, ILDasm |
| Capacitor/Ionic | WebView exposure, plugin API | Chrome DevTools, Burp |

See `guides/react-native-flutter-security.md` for framework-specific testing methodology.

### Mobile-Cloud Integration Testing

Mobile apps connect to cloud backends (Firebase, AWS Amplify, custom APIs). Key test areas:

1. **Backend API exposure**: Enumerate and test all API endpoints accessible from the app
2. **Cloud service misconfiguration**: Firebase rules, Cognito pools, Storage buckets
3. **Authentication flow**: OAuth 2.0/OIDC implementation flaws on mobile
4. **Third-party SDK security**: Data collection, tracking, insecure defaults

See `guides/mobile-api-security-testing.md` and `guides/mobile-cloud-integration.md`.

---

## Orchestration

### ECC Loop Pattern
- **Pattern**: Sequential Pipeline
- **Rationale**: Mobile security testing follows a sequential approach — decompile → analyze → hook → verify — where each phase builds on the previous
- **Integration**: codebase-onboarding (app structure understanding), browser-qa (WebView testing), verification-loop (finding confirmation)

### Cross-Skill Pipeline
```
codebase-onboarding → mobile-security → verification-loop → article-writing
```

### Quality Gate
- Pre-condition: Target APK/IPA available, testing environment configured
- Post-condition: All attack surfaces documented, findings independently verified
- Verification: Use verification-loop Phase 4 (independent confirmation with different tool)

---

## Hacker Laws

| Law | Application in Mobile Security |
|-----|--------------------------------|
| **First Principles** | Don't rely on tools for one-click results; understand APK internal structure (DEX, Manifest, Resources) and Android runtime mechanisms. Only by understanding the underlying principles of Frida instrumentation can you write precise hook scripts |
| **Trust but Verify** | All client-side security checks can be bypassed. Root Detection, SSL Pinning, and Anti-Debug are delays, not barriers, to attackers. Defense design must assume the client has been fully compromised |
| **Minimize Attack Surface** | Every exported=true component is an entry point. Follow the principle of least privilege: disable unnecessary exported components, remove debuggable flags, prohibit cleartext traffic, and implement Certificate Pinning |

---

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md
  **Related skills**: skills/binary-reverse/SKILL.md, skills/web-xss/SKILL.md
  **External resources**:
  - [OWASP MSTG](https://owasp.org/www-project-mobile-security-testing-guide/) - Authoritative mobile security testing standard
  - [Frida Official Documentation](https://frida.re/docs/home/) - Complete reference for Frida dynamic instrumentation
  - [MobSF GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile security automated analysis framework
  - [HackTricks - Mobile Pentesting](https://book.hacktricks.xyz/mobile-pentesting) - Mobile penetration techniques collection
