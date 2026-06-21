---
name: macos-security
description: macOS red team and security assessment — SIP/TCC bypass, Endpoint Security framework, Apple Silicon/T2/M-series attacks, Mach-O analysis, Keychain extraction, MDM bypass, LaunchAgents/Daemons persistence, and macOS-native malware analysis.
origin: github-trending-2026
version: 1.0.0
compatibility: Claude Code, Agent SDK
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
metadata:
  domain: macos
  category: macos
  tool_count: 13
  guide_count: 1
  mitre: TA0005-Defense Evasion, T1547-Boot or Logon Autostart, T1555-Credentials from Password Stores
  keywords: [macos, sip, tcc, endpoint-security, mach-o, keychain, apple-silicon, m2, launchd, mdm, knockknock, lulu]
---

# Skill: macOS Security Assessment

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for macOS red team and malware analysis: 18 sections covering recon, SIP/TCC bypass, ESF event logging, LaunchAgents/Daemons persistence, Keychain extraction, Cookies.binarycookies, Apple Silicon (arm64e, PAC, sealed snapshots), MDM profile analysis, Mach-O analysis (otool, jtool2, machOView), code signing/notarization, process/memory analysis, network analysis, persistence enumeration, defense bypass (AMFI, sandbox), Objective-See tools (KnockKnock, LuLu, BlockBlock, OverSight), and a cheat sheet. 60+ code blocks with real macOS CLI syntax.
> - `test-cases.md` — Structured test cases (TC-MO-001..012): system profiling, SIP status check, TCC.db audit, LaunchAgents/Daemons enumeration, Keychain extraction via `security`, Cookies.binarycookies parsing, MDM profile analysis, Mach-O analysis, code signing verification, KnockKnock persistence scan, ESF event logging, Apple Silicon PAC check.
> - `guides/macos-security-playbook.md` — End-to-end operational playbook: macOS security architecture (SIP/TCC/AMFI/sandbox/ESF/Secure Boot), Apple Silicon specifics (arm64e, PAC, Rosetta 2, sealed system snapshots), building a macOS test lab, red team methodology, real-world macOS threats (XCSpy, Shlayer, Bundlore, Silver Sparrow, NodeStealer), defense patterns, and references.

## Summary

macOS security assessment skill covering Apple's desktop/laptop platform from a red team and malware analyst perspective. This skill addresses the modern macOS attack surface: System Integrity Protection (SIP/rootless), Transparency Consent and Control (TCC), Endpoint Security framework (ESF), Apple Silicon (M1/M2/M3/M4 with arm64e and Pointer Authentication Codes), T2 chip on Intel Macs, code signing + notarization enforcement, LaunchAgents/LaunchDaemons persistence, Keychain credential stores, MDM profile abuse, and Mach-O binary analysis.

**Tools**: Objective-See suite (KnockKnock, LuLu, BlockBlock, OverSight, TaskExplorer, What's Your Sign?), sindresorhus/Equity, mSCP (macOS Security Compliance Project), machOView, Hopper Disassembler, Ghidra (Mach-O plugin), jtool2, ldid, plus native CLI (`system_profiler`, `csrutil`, `tccutil`, `security`, `codesign`, `otool`, `nm`, `vmmap`, `lldb`, `profiles`, `airport`).

**Domain**: macos

**MITRE ATT&CK**: T1547-Boot or Logon Autostart (LaunchAgents/Daemons, login items), T1555-Credentials from Password Stores (Keychain, Cookies.binarycookies), T1059-Command and Scripting Interpreter (zsh, osascript), T1068-Exploitation for Privilege Escalation (SIP bypass, SUID abuse), T1106-Native API (Mach APIs, launchd), T1620-Reflective Code Loading (DYLD injection), TA0005-Defense Evasion (AMFI bypass, notarization abuse, TCC bypass).

## Description

macOS is no longer a niche enterprise endpoint. As of 2026 it commands roughly a quarter of the U.S. enterprise laptop market, is the default developer machine at most Fortune 500 technology companies, and is increasingly the executive laptop of choice. It is also a strange target: it runs a Darwin/BSD core (so it has UNIX permissions, file flags, chroot, `seatbelt` sandbox profiles), but it is wrapped in a sophisticated proprietary security architecture (System Integrity Protection, Apple Mobile File Integrity / AMFI, TCC privacy consent, Secure Boot, sealed system snapshots on Apple Silicon, and the Endpoint Security framework). Most offensive techniques ported from Linux work, but the interesting bugs and persistence mechanisms are macOS-specific — and the defenders have a 10-year head start via Patrick Wardle's research, the Objective-See tooling, Apple's Platform Security Guide, and the macOS Security Compliance Project (mSCP).

This skill is the macOS counterpart to `av-edr-evasion` (which focuses on Windows Defender / commercial EDR) and `binary-reverse` (which is platform-agnostic but mostly ELF/PE-flavored). Where those skills cover Windows and Linux, this skill covers the macOS-specific attack surface: `csrutil`/`nvram` for SIP, `tccutil` + `TCC.db` for privacy, `security` CLI for Keychain, `codesign`/`spctl` for signing and notarization, `otool -L` and `jtool2` for Mach-O introspection, `profiles` for MDM, and the `EndpointSecurity` framework for the same event stream that commercial EDR (Falcon, SentinelOne, Jamf Protect, Microsoft Defender for Endpoint) subscribes to.

Eight things distinguish macOS attacks from generic UNIX attacks:

1. **SIP (System Integrity Protection) is the new root** — On 2015+ macOS, even root cannot write to `/System`, `/usr`, `/bin`, `/sbin`, certain protected subdirs of `/Library`, or the TCC database by default. Processes that try must be Apple-signed with the right entitlements, or SIP itself must be disabled (recovery-mode `csrutil disable`). Modern macOS attacks either work within SIP (persistence in user-writable locations, TCC.db manipulation under granted entitlements) or seek SIP bypasses (CVE-2019-8805, CVE-2020-3837, CVE-2023-32434 — the latter a memory corruption in the boot ROM image parser, unpatchable by software on Apple Silicon).

2. **TCC (Transparency, Consent, and Control) is the new permission gate** — Every macOS app that wants to read user data (location, camera, microphone, contacts, calendars, reminders, photos, Mail, Safari history, Messages, full disk access, accessibility control, automation) must request consent at first use, recorded in `/Library/Application Support/com.apple.TCC/TCC.db` (system) and `~/Library/Application Support/com.apple.TCC/TCC.db` (user). TCC bypass is the macOS analog of a Windows UAC bypass — historically via DYLD insertion into a TCC-entitled binary (`Xcode.app`, `swift`), via env-var abuse, or via direct SQLite manipulation when SIP is weakened.

3. **The Endpoint Security framework (ESF) is the EDR's eyes — and yours** — Introduced in macOS 10.15 Catalina (2019) and hardened repeatedly since, ESF is the only supported API for monitoring process exec, file writes, endpoint disk I/O, mount/unmount, opendirectory lookups, and (on Monterey+) login/logout. Commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint, Jamf Protect) is required by Apple to subscribe to ESF — and a red team operator who can run `eslogger` or build their own ESF client gets the same telemetry, for free, on any Mac they have admin on.

4. **Apple Silicon changes the rules — PAC, sealed snapshots, Rosetta 2** — On M-series Macs, the kernel runs arm64e with Pointer Authentication Codes (PAC) on every function pointer and return address — most classic ROP/JOP chains fail. The system volume is a cryptographically sealed APFS snapshot (`/System/Volumes/Data` is mutable, `/`/`/System` are read-only and hash-checked at every boot). Kernel extensions are effectively dead for third parties; the only supported path is System Extensions (user-land) and DriverKit. Rosetta 2 (x86_64 emulation) is an entire second ABI with its own historical bugs (CVE-2021-30717 — Rosetta translation bypass of code signing checks). Apple Silicon also brought **Silver Sparrow** (2021), the first malware family observed shipping an arm64 payload alongside x86_64.

5. **Code signing and notarization are mandatory, but gameable** — On macOS 10.15+ the Gatekeeper default rejects any downloaded binary that isn't signed by a Developer ID and notarized by Apple. But ad-hoc signed binaries (signed locally with `codesign -s -`) execute fine if run from a path that bypasses Gatekeeper (anything not quarantined — e.g., extracted from an installer, run by a binary that already has the same permissions). And historically notarization was bypassed via signed-and-notarized "conduit" binaries (the classic Shlayer model: a notarized dropper that fetches and unpacks the actual payload at runtime).

6. **LaunchAgents and LaunchDaemons are the persistence layer** — The single most abused macOS persistence mechanism is `~/Library/LaunchAgents/<bundle-id>.plist` (user) and `/Library/LaunchDaemons/<bundle-id>.plist` (system). Each plist tells `launchd` (PID 1) to spawn a binary on a schedule, on login, on network change, or on a watched path. KnockKnock enumerates ~50 of these locations. macOS malware (Bundlore, Shlayer, XCSpy, CoinMiner) almost always adds a LaunchAgent. There are also login items (`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/`), Spotlight importers, QuickLook plugins, Internet plug-ins, browser extensions, and the legacy `/etc/periodic/` and `crontab`.

7. **Keychain and Cookies.binarycookies are the credential prize** — macOS stores user secrets in `~/Library/Keychains/login.keychain-db` (user) and `/Library/Keychains/System.keychain` (system): Safari passwords, Wi-Fi PSKs, application tokens, certificates. The `security` CLI can dump it after prompting for the user's login password (or with no prompt if the calling binary is signed and entitled), and `KeychainDump`/`chainbreaker` extract password hashes for offline cracking. Safari cookies live in `~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies` — a non-standard binary plist format that several tools parse.

8. **MDM is the enterprise control plane — and a target** — macOS in enterprise is typically enrolled in Mobile Device Management (Jamf, Kandji, Microsoft Intune, Workspace ONE). MDM profiles can push restrictions, configure FileVault, deploy System Extensions, and remotely wipe. The `profiles` CLI lists installed profiles and can install new ones (with admin). MDM profile abuse includes: extracting an enrollment identity from a compromised host to enroll rogue devices, bypassing MDM via beta OS profiles, or exploiting profile signing weaknesses. Apple's Platform Security Guide treats the MDM as a privileged trust boundary.

**Difference from `mobile-security`**: mobile-security is iOS/Android — app review bypass, certificate pinning, APK/IPA reverse engineering, mobile data protection at the application layer. THIS skill is macOS desktop/laptop specifically — SIP/TCC/ESF, LaunchAgents/Daemons persistence, Mach-O (not ELF/PE), Keychain (not Android Keystore), MDM profile analysis as an enterprise control plane. The platforms share a kernel (Darwin) and code signing (codesign + ldid) but the attack surfaces are otherwise distinct. iOS additionally has its own sandbox and entitlement system that differs in detail.

**Difference from `av-edr-evasion`**: av-edr-evasion covers Windows Defender, commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint), and bypass techniques for those. THIS skill covers the macOS-specific defense stack: AMFI, Gatekeeper, XProtect, MRT (Malware Removal Tool), TCC, and the macOS-native EDR surface (System Extensions, ESF). Where av-edr-evasion might cover direct syscalls and process doppelgänging on Windows, this skill covers signed-and-notarized droppers, TCC bypass via entitlement inheritance, and persistence in LaunchAgents.

**Difference from `binary-reverse`**: binary-reverse covers static/dynamic analysis broadly — PE, ELF, and Mach-O. THIS skill narrows to Mach-O specifically: `otool`, `nm`, `jtool2`, machOView, Ghidra Mach-O plugin, disassembling arm64/arm64e with PAC-aware tooling, dumping entitlements, walking the load commands. The Mach-O format, the Objective-C runtime metadata, and the Swift symbol mangling are macOS-specific.

**Difference from `digital-forensics`**: digital-forensics covers IR artifacts broadly (logs, file system timeline, memory). THIS skill covers macOS-specific forensic artifacts: the unified log (`log show`), FSEvents, Spotlight metadata, TCC.db audit, Keychain access history, Spotlight importers, and the securenotes table in the user keychain. Where digital-forensics might describe Windows event log analysis, this skill covers `log show --predicate 'subsystem == "com.apple.securityd"'`.

**Difference from `container-security` and `cloud-security`**: those cover Linux containers and cloud IaaS. macOS has its own containerization model (per-app sandbox via `sandboxd`, hardened runtime via entitlements, App Sandbox container directories at `~/Library/Containers/<bundle-id>/`). The macOS container model is per-process and enforced by the kernel, not by a container runtime.

## Use Cases

- **SIP/TCC bypass for red team**: Identify the running SIP configuration (`csrutil status`), enumerate the TCC-protected resources the foothold user can access, look for entitlement-rich binaries (Xcode, Mail, Safari) that can be used as proxies via DYLD insertion or `osascript` automation, and document paths to bypass TCC where present.
- **Keychain, cookies, and Safari data extraction**: Once on a Mac with the user logged in, dump `~/Library/Keychains/login.keychain-db` via the `security` CLI, extract Safari cookies from `Cookies.binarycookies`, parse Safari history from `History.db`, and recover saved Wi-Fi PSKs via `security find-generic-password`.
- **MDM profile analysis and abuse**: Enumerate installed configuration profiles (`profiles list -output user`), reverse-engineer the payload of each profile to find enterprise restrictions, identify the MDM vendor, locate the enrollment identity, and document paths to MDM bypass (DEP re-enrollment race, beta OS profile, supervised-mode downgrade).
- **Persistence via LaunchAgents/Daemons**: Install a LaunchAgent plist in `~/Library/LaunchAgents/` (user scope) or `/Library/LaunchDaemons/` (system scope, requires root), enumerate competing persistence via KnockKnock, and identify the 50+ persistence locations macOS exposes (login items, Spotlight importers, QuickLook, browser extensions, loginwindow hooks).
- **macOS-native malware analysis**: Take an unknown Mach-O binary, identify its architecture (`file`, `otool -h`), enumerate load commands and linked libraries (`otool -L`, `jtool2 -l`), dump entitlements (`codesign -d --entitlements -`), walk the Objective-C class metadata (`otool -ov`), disassemble in Hopper/Ghidra, and trace its behavior with `fs_usage`, `opensnoop`, `dtrace`, and an ESF logger.
- **Apple Silicon-specific attacks**: On M-series Macs, detect PAC enforcement (`sysctl kern.bootargs`), inspect the sealed system snapshot (`mount`, `csrutil authenticated-root status`), test for Rosetta 2 escape paths, and reason about the absence of classic kext-based persistence (System Extensions are user-land).
- **Endpoint Security framework instrumentation**: Build a minimal ESF client (or use `eslogger` / `esf-client`) to subscribe to process-exec, file-write, and login events, and produce a process-tree timeline of attacker behavior on a target Mac — useful both as an attacker (knowing what the defender sees) and a defender (operationalizing ESF for free).
- **macOS incident response and threat hunting**: Parse the unified log for security-relevant events (`log show --predicate 'subsystem == "com.apple.securityd"'`), audit TCC.db for unexpected grants, scan all LaunchAgents/Daemons with KnockKnock, list installed System Extensions (`systemextensionsctl list`), and triage a suspect Mach-O binary with What's Your Sign? and TaskExplorer.

## Core Tools

### Objective-See Suite (free, open-source, the de facto standard)

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **KnockKnock** | Enumerate ~50 macOS persistence locations (LaunchAgents, LaunchDaemons, login items, browser extensions, Spotlight importers, kernel extensions, System Extensions) | `KnockKnock.app/Contents/MacOS/KnockKnock -h` (or click "Scan") |
| **LuLu** | Free open-source macOS firewall — block outbound by bundle ID / binary path | `sudo /Objects/LuLu.app/Contents/MacOS/LuLu` (mode 2 = block-by-default) |
| **BlockBlock** | Persistence monitor — alerts when anything installs a LaunchAgent, login item, or kernel extension | BlockBlock.app (GUI monitor) |
| **OverSight** | Camera + microphone monitor — alerts when an app accesses the camera or mic | OverSight.app |
| **TaskExplorer** | Process explorer with code-signing info, VT lookups, file/path context | TaskExplorer.app |
| **What's Your Sign?** | Finder extension showing code-signing details (cert chain, notarization status) | Right-click → Services → What's Your Sign? |

### Analysis + Compliance

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **sindresorhus/Equity** | Open-source Gatekeeper / notarization / TCC GUI inspector | `Equity.app` (drag-drop a binary to see signing/notarization details) |
| **mSCP (macOS Security Compliance Project)** | NIST + Apple baseline configuration profiles + audit scripts | `python3 bin/mSCP.py -s baseline/macos_15_1.yaml` |
| **machOView** | GUI Mach-O browser — load commands, segments, sections, Objective-C classes | `machOView.app` (open a Mach-O binary) |
| **Hopper Disassembler** | Native macOS disassembler/decompiler (commercial, with demo) | `hopper <binary>` |
| **Ghidra (Mach-O plugin)** | NSA's open-source reverse-engineering suite with Mach-O loader | `analyzeHeadless . proj -import <binary>` |
| **jtool2** | The Swiss-army knife for Mach-O introspection (by Elias Limneos) — replaces many `otool` workflows | `jtool2 -l <binary>` (load commands); `jtool2 -arch arm64e -L <fat>` |
| **ldid** | Alternative to `codesign` for ad-hoc signing with entitlements (Cydia/Telesphoreo origin) | `ldid -S<entitlements.plist> <binary>` |

## Methodology

### macOS Red Team Five-Phase Workflow

```
Phase 1          Phase 2          Phase 3          Phase 4          Phase 5
Recon &       →  Privilege &   →  Persistence   →  Credential     →  Defense Bypass
Footold          TCC Posture      (LaunchAgents)    Extraction       & ESF Audit
   │                │                │                │                │
   ▼                ▼                ▼                ▼                ▼
 system_profiler   csrutil status   ~/Library/       security         AMFI bypass,
 sw_vers, uname    tccutil reset    LaunchAgents/     dump-keychain   sandbox profile
 hardware arch     TCC.db audit     LaunchDaemons/    Cookies.        escapes, notarization
 loginwindow       accessibility    login items       binarycookies   conduit abuse,
 MDM profiles      Full Disk Acc    Spotlight imp.    Safari          ESF self-audit
                                                                    via eslogger
```

**Phase 1: Recon & Foothold** — Determine the macOS version (`sw_vers`), hardware architecture (`uname -m` → `arm64`/`arm64e` for Apple Silicon, `x86_64` for Intel), system model (`system_profiler SPHardwareDataType`), FileVault status (`fdesetup status`), and the user's full name + UID + admin group membership (`id`, `groups`). Enumerate installed MDM profiles (`profiles list -output user`) and the MDM vendor. Identify what security software is running (Look for `falcon`, `sentinelone`, `jamfProtect`, `Microsoft Defender` processes). Establish a foothold via the engagement scope (existing user creds, a delivered payload, a browser exploit).

**Phase 2: Privilege & TCC Posture** — Determine SIP status (`csrutil status`), TCC state (`tccutil reset All` clears — but only as user; system TCC.db requires root + SIP weakened), and the current process's own TCC grants (via the `tccutil` reads or by parsing `~/Library/Application Support/com.apple.TCC/TCC.db`). Identify entitlement-rich binaries that grant indirect TCC access: Xcode (`com.apple.dt.Xcode`), Safari (`com.apple.Safari`), Mail (`com.apple.Mail`), Terminal with Full Disk Access already granted. Document which TCC-protected resources the user has already granted (the easiest path to credentials and history).

**Phase 3: Persistence** — Install a LaunchAgent at `~/Library/LaunchAgents/com.example.helper.plist` (user scope, runs at user login) or `~/Library/LaunchDaemons/com.example.helper.plist` (system scope, runs at boot, requires root + `sudo`). For wider persistence, consider: login items via `LSSharedFileListInsertItemURL`, Spotlight importers (`~/Library/Spotlight/`), QuickLook plugins (`~/Library/QuickLook/`), browser extensions (`~/Library/Application Support/Google/Chrome/Default/Extensions/`), the legacy `/etc/periodic/daily/` dropboxes, and `cron`. On Apple Silicon, all of these work — kernel extensions do not.

**Phase 4: Credential Extraction** — Dump the login keychain via `security dump-keychain -d ~/Library/Keychains/login.keychain-db` (prompts for user password), enumerate generic passwords (`security find-generic-password -l`), extract saved Wi-Fi PSKs (`security find-generic-password -ga "SSID" -w`), parse Safari cookies from `~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies` (use `binarycookies-reader` or python script), and read Safari history from `~/Library/Safari/History.db` (Full Disk Access required). Document each credential source and the TCC entitlement required to reach it.

**Phase 5: Defense Bypass & ESF Audit** — Identify what the defender sees: run `eslogger` (or build an ESF client) and observe your own actions; understand that ESF is the same data commercial EDR uses. If a specific defender (Falcon, Defender for Endpoint) is running, identify its ESF subscription and any network callouts it makes. Document anti-analysis: AMFI (`amfid`) checks every exec against the trust cache; sandbox profiles restrict syscalls; Gatekeeper enforces notarization on quarantined files. Document bypasses used: running from non-quarantined paths (no `com.apple.quarantine` extended attribute), DYLD insertion into TCC-entitled binaries (when SIP permits), entitlement inheritance via signed-and-notarized conduits.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Just got user shell on a Mac | `sw_vers`, `uname -m`, `id`, `csrutil status`, `profiles list` | `system_profiler SPHardwareDataType` |
| Need to read user documents | Check `~/Library/Application Support/com.apple.TCC/TCC.db` for granted Full Disk Access; if absent, look for a TCC-entitled binary to abuse | `osascript` automation of Finder/TextEdit with prior automation grant |
| Need credentials | `security dump-keychain -d` (prompts for user password); `security find-generic-password -ga <SSID> -w` | `chainbreaker` for offline hash extraction |
| Need Safari history | Read `~/Library/Safari/History.db` (FDA required) | Parse `Cookies.binarycookies` for session tokens |
| Need persistence | LaunchAgent at `~/Library/LaunchAgents/com.example.helper.plist` with `RunAtLoad=true` | Login items via `osascript -e 'tell application "System Events" to make login item ...'` |
| Need system-level persistence | `/Library/LaunchDaemons/com.example.helper.plist` (requires root + signed binary) | System Extension (high detection — not recommended for red team) |
| Analyzing a Mach-O | `file`, `otool -h` (arch), `otool -L` (libs), `codesign -dvvv` (signing), `jtool2 -l` (load commands) | `machOView` for GUI browsing, Hopper/Ghidra for disassembly |
| Detecting SIP-bypassed host | `csrutil status`, `nvram boot-args`, `mount \| grep System` | `csrutil authenticated-root status` (Apple Silicon) |
| Enumerating persistence | Run KnockKnock (GUI), or script: `ls -l ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/` | `launchctl list` for currently-loaded services |
| Auditing MDM | `profiles list -output user`; `profiles show -output open-command -identifier <UUID>` | `/var/db/ConfigurationProfiles/` (system) — needs root |
| Want to see what EDR sees | `sudo eslogger exec,open,write --run foreground` | Build an ESF client with `EndpointSecurity.framework` |
| Checking notarization | `spctl --assess --type execute --verbose <binary>`; `codesign -dv --verbose=4 <binary>` | Drag-drop into Equity GUI |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **SIP enabled** | `csrutil status` should report "fully enabled". Disable only for development. SIP-protected directories (`/System`, `/usr`, `/bin`, `/sbin`, preinstalled apps) cannot be modified even by root. |
| **FireVault on + PRK escrow** | `fdesetup status` → "FileVault is On." Recovery key escrowed to MDM or printed and stored. Without FileVault, all on-disk secrets are readable by anyone with physical access. |
| **TCC audit** | Quarterly review of `/Library/Application Support/com.apple.TCC/TCC.db` and `~/Library/Application Support/com.apple.TCC/TCC.db`. Alert on any new Full Disk Access or Accessibility grant to a non-Apple binary. |
| **Gatekeeper + notarization enforcement** | `spctl --status` → "assessments enabled." macOS 11+ blocks all downloaded non-notarized apps by default. Users must override explicitly via System Settings → Privacy & Security. |
| **XProtect + MRT active** | `systemextensionsctl list` should show `com.apple.XProtect.framework.ScanService` and `com.apple.MRT`. Apple pushes background signature updates silently. |
| **Endpoint Security framework subscription** | At least one ESF-based EDR (Jamf Protect, CrowdStrike Falcon, Defender for Endpoint, SentinelOne) deployed via MDM. Apple does not ship a macOS-native EDR — third party is required. |
| **MDM enrollment + restricted profiles** | Device supervised via Apple Business/School Manager; MDM profile installed at DEP time; restricted system extensions (only allow-listed team IDs); Gatekeeper and SIP policy enforced via `configurationProfile`. |
| **Software Update enforcement** | `softwareupdate --schedule-on`; max N-day lag from Apple release; critical security updates auto-installed within 72h. |
| **System Volume sealed snapshot** | On Apple Silicon, `/System/Volumes/SSV` is a sealed snapshot — verify with `mount \| grep sealed` and `csrutil authenticated-root status`. Tampering here is a hardware-level indicator. |
| **Hardened Runtime for in-house apps** | All in-house macOS binaries built with Hardened Runtime (`--options runtime` to `codesign`), proper entitlements, and notarized via Xcode Organizer or `notarytool`. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Enumerate LaunchAgents and LaunchDaemons

```bash
# User-scope LaunchAgents (run at login as the user)
ls -l ~/Library/LaunchAgents/ 2>/dev/null
# System-scope LaunchAgents (run at login for any user)
ls -l /Library/LaunchAgents/ 2>/dev/null
# System-scope LaunchDaemons (run at boot as root — highest-impact persistence)
ls -l /Library/LaunchDaemons/ 2>/dev/null
# Apple's own LaunchAgents/Daemons (informational, do not touch)
ls -l /System/Library/LaunchAgents/ /System/Library/LaunchDaemons/ 2>/dev/null

# Inspect one plist
plutil -p ~/Library/LaunchAgents/com.example.helper.plist
# Key fields: Label, ProgramArguments, RunAtLoad, KeepAlive, StartInterval, WatchPaths

# List currently-loaded services
launchctl list | head -20
launchctl list | grep -i example

# Find services that auto-restart (KeepAlive=true)
for f in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
  [ -f "$f" ] || continue
  plutil -p "$f" 2>/dev/null | grep -q "KeepAlive = 1" && echo "KEEPALIVE: $f"
done
```

### Exercise 2: Extract Keychain Items (with user prompt)

```bash
# Show the user's keychains
security list-keychains

# Show all generic-password entries (no secret values)
security dump-keychain ~/Library/Keychains/login.keychain-db | grep -E '"svce"|"acct"|"desc"'

# Dump one item WITH the password (prompts user for keychain unlock)
security find-generic-password -ga "Wi-Fi SSID Name" -d ~/Library/Keychains/login.keychain-db -w
# → password: <WPA-PSK>

# Dump everything (prompts repeatedly for the keychain password)
security dump-keychain -d ~/Library/Keychains/login.keychain-db

# Saved Wi-Fi networks (system keychain)
sudo security find-generic-password -ga "SSID" /Library/Keychains/System.keychain -w

# List certificates (e.g., MDM enrollment identity)
security find-certificate -a /Library/Keychains/System.keychain
```

### Exercise 3: Check SIP and TCC Status

```bash
# SIP status (must be run as the logged-in user; shows config)
csrutil status
# Expected on a hardened host: "System Integrity Protection status: enabled."

# Apple Silicon: authenticated-root status (sealed system snapshot)
csrutil authenticated-root status

# TCC: list current grants via the tccutil (limited; full audit requires sqlite3)
tccutil reset All   # DANGEROUS: resets all user TCC grants — only for testing

# Read user TCC.db (sqlite3, requires Full Disk Access for the terminal)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access ORDER BY service;"
# auth_value: 0=denied, 2=allowed, 3=limited

# System TCC.db (requires root)
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access ORDER BY service;"

# Which services exist (Apple's documented list — see Apple Platform Security Guide)
# kTCCServiceSystemPolicyAllFiles (Full Disk Access)
# kTCCServiceAccessibility (Accessibility)
# kTCCServiceSystemPolicySysAdminFiles (Administrator files)
# kTCCServiceSystemPolicyDesktopFolder (Desktop)
# kTCCServiceSystemPolicyDocumentsFolder (Documents)
# kTCCServiceSystemPolicyDownloadsFolder (Downloads)
# kTCCServiceCamera, kTCCServiceMicrophone, kTCCServiceLocation, ...
```

### Exercise 4: Mach-O Static Analysis with otool and jtool2

```bash
# Architecture (fat binary? single arch?)
file /Applications/Safari.app/Contents/MacOS/Safari
# → Mach-O 64-bit executable [arm64e] (Apple Silicon) or [x86_64]

# Header
otool -h /bin/ls
otool -hv /bin/ls                       # verbose

# Linked libraries
otool -L /bin/ls
# Lists LC_LOAD_DYLIB entries — the dylibs this binary depends on

# Load commands (one line each)
otool -l /bin/ls | head -50
# Or jtool2 (cleaner output):
jtool2 -l /bin/ls

# Symbol table
nm -p /bin/ls | head -20

# Objective-C class metadata (if the binary is Objective-C)
otool -ov /Applications/Safari.app/Contents/MacOS/Safari 2>/dev/null | head -100

# Code-signing details
codesign -dvvv /Applications/Safari.app
codesign -d --entitlements - /Applications/Safari.app
# Look for: Authority (Developer ID / Apple Mac OS Application Signing),
# TeamIdentifier, and entitlements like com.apple.security.cs.* (Hardened Runtime)

# Sections (better in machOView GUI)
jtool2 -section /bin/ls

# Disassemble (Hopper for GUI, jtool2 -d for CLI; arm64e disassembly needs PAC-aware tools)
jtool2 -d --arch arm64e /Applications/Safari.app/Contents/MacOS/Safari
```

### Exercise 5: Enumerate MDM Profiles

```bash
# List installed configuration profiles (user-installable)
profiles list -output user

# List all profiles (system; requires admin)
sudo profiles list

# Show details of a specific profile (by identifier)
sudo profiles show -identifier com.example.restrictions

# Show the payload as a plist
sudo profiles show -output open-command -identifier com.example.restrictions > /tmp/profile.plist
plutil -p /tmp/profile.plist

# Where profiles are stored on disk (system)
sudo ls -l /var/db/ConfigurationProfiles/Setup/
sudo ls -l /var/db/ConfigurationProfiles/Settings/

# What's the MDM enrollment identity?
sudo security find-certificate -a -c "Profile" /Library/Keychains/System.keychain
sudo security find-certificate -a -c "MDM" /Library/Keychains/System.keychain
```

## Common Pitfalls

- **Treating macOS like Linux**: macOS is UNIX-flavored but its security model is layered — SIP protects system volumes, TCC gates user data, AMFI validates every binary at exec, Gatekeeper blocks downloads, and notarization is mandatory. A payload that works on Kali may be silently killed by AMFI on macOS.
- **Forgetting about the unified log**: every TCC grant, every exec, every network connection is logged to the unified log (`log show`). Defense teams will see your actions even if no commercial EDR is installed. Tailor your footprint accordingly.
- **Assuming SIP is unbreakable**: historical CVEs (2019-2024) include SIP bypasses via NFS export (CVE-2019-8805), the `crontab` DAC override (CVE-2020-3837), and the now-patched `writeconfig` exploit chain. Always check `csrutil status` on the target before assuming SIP is enforced.
- **Misreading TCC auth_value**: `0=denied`, `2=allowed`, `3=limited`. A row with `auth_value=2` means the binary HAS the grant — a `0` means the binary was explicitly denied (a useful indicator for "user clicked Don't Allow"). `3` means the grant is scoped (e.g., "limited Photos access").
- **Confusing ad-hoc and Developer ID signing**: `codesign -s -` (ad-hoc) is fine for local execution but will NOT pass Gatekeeper on a downloaded file. For a payload delivered via DMG/ZIP, Developer ID + notarization is required. Ad-hoc signing bypasses Gatekeeper only via a non-quarantined delivery path.
- **Ignoring Apple Silicon entirely**: on M-series Macs, classic ROP/JOP chains often fail because of PAC. Kernel extensions are dead. Rosetta 2 has its own historical bugs. Treat Apple Silicon as a separate target from Intel.
- **Assuming `csrutil disable` is required for everything**: most persistence (LaunchAgents/Daemons, login items) and most TCC bypass (DYLD into entitled binaries when SIP is partial) work without disabling SIP. Disabling SIP is a loud, detectable, irreversible-without-reboot action — avoid unless required.
- **Forgetting that the user's terminal needs TCC grants**: a freshly-spawned reverse shell has no Full Disk Access, no Accessibility, no Automation. The defender's Terminal (or iTerm2) probably has those grants — but the attacker's payload doesn't. Inherit them by spawning into a TCC-entitled binary, or trick the user into granting.

## Safety Notes

- **Production Macs**: any action that writes to `/Library/LaunchDaemons/`, modifies `TCC.db`, or enrolls a new MDM profile has blast radius on the user's daily-driver machine. Use a test Mac (or a VMware Fusion / Parallels VM, with snapshots enabled) for active exploitation.
- **SIP disabling**: `csrutil disable` requires reboot into Recovery Mode, makes the host vulnerable to much more than the engagement intended, and persists until explicitly re-enabled. Document the change; re-enable before handoff.
- **Keychain dump**: `security dump-keychain -d` repeatedly prompts the user for their login password. On a production machine this immediately tips off the user. Capture once, in a controlled test environment.
- **Cookies.binarycookies extraction**: these cookies include live session tokens for banking, SSO, and email. Treat them as credentials: store encrypted, do not commit to git, discard post-engagement.
- **ESF logging**: a custom ESF client generates substantial log noise and consumes the client's MDM-allowed ESF slot (only one ESF subscriber per process per Apple's policy, though multiple processes can subscribe). Confirm with the customer before installing one on a production Mac.
- **MDM profile installation**: installing a malicious profile on a customer-managed Mac may conflict with the existing MDM and trigger Jamf/Intune alerts. Document and use a test machine.
- **Code signing certificate handling**: never commit a Developer ID certificate + private key to a repo. Use Apple's `notarytool` with an app-specific password stored in the macOS keychain (`xcrun notarytool store-credentials`), not in env vars.

## Hacker Laws

- **Trust but Verify** — `csrutil status` reports "enabled" but on some hosts the authenticated-root is not sealed, or a single SIP-protected path has been weakened. Verify with `csrutil authenticated-root status`, `mount | grep sealed`, and by attempting a write to `/System`.
- **Defense in Depth** — SIP, TCC, AMFI, sandbox, Gatekeeper, notarization, XProtect, MRT, ESF-based EDR, FileVault, Secure Boot. No single layer stops a determined attacker; the stack slows them and produces telemetry at each layer.
- **Assume Breach** — Design your monitoring assuming the attacker has user-level access. The unified log records every TCC grant, every exec, every network connection — but only if you forward it to a SIEM and alert on anomalies. Apple ships the data; the operationalization is your job.
- **Least Privilege** — A user should not have Full Disk Access to every app. A binary should not run with `com.apple.security.cs.disable-library-validation` unless absolutely required. Every entitlement is an attack surface. Audit `codesign -d --entitlements -` on every binary in `~/Library/LaunchAgents/`.
- **Supply Chain Trust** — Every macOS binary in the trust cache, every Developer ID certificate, every notarization ticket, every MDM-pushed configuration profile is a supply chain link. A revoked Developer ID (e.g., Apple's 2019 revocation of Facebook's and Google's enterprise certs) propagates instantly to every Mac that has checked revocation.
- **Minimize Attack Surface** — Disable Java in the browser (gone in modern Safari but still enforced via MDM), block unsigned extensions, restrict System Extensions to allow-listed team IDs, disable the root account (`dsenableroot -d`), disable SSH unless needed, disable Remote Login and Screen Sharing.
- **Information Wants to Be Free** — Keychain contents, Cookies.binarycookies, Safari History.db, the unified log, `~/Library/Application Support/` — these are credentials and history in plain sight on every Mac. FileVault protects them at rest only; a logged-in user is a wide-open book.
- **Weakest Link Is Human** — Most macOS compromises start with a fake Flash update (Shlayer's classic lure), a pirated app DMG (Bundlore), a malicious Office macro (OfficeMacros are rare but exist), or a socially-engineered notarized dropper. User education, Gatekeeper enforcement, and blocking known-malicious Developer IDs via MDM are the defenses.

## Differentiation

- **vs `mobile-security`** — mobile-security is iOS/Android at the *application* layer: app review, certificate pinning bypass, APK/IPA reverse engineering, mobile data protection. THIS skill is macOS desktop/laptop at the *OS and platform* layer: SIP/TCC/AMFI/ESF, LaunchAgents/Daemons persistence, Mach-O analysis, Keychain (desktop variant), MDM as enterprise control plane. The Apple Silicon transition (2020-2022) further differentiates the two: macOS on M-series is a desktop Unix with arm64e + PAC + sealed snapshots; iOS has had arm64e longer and has additional sandbox restrictions (no shell, no Terminal, no `osascript`).
- **vs `av-edr-evasion`** — av-edr-evasion focuses on Windows Defender and commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint) with techniques like direct syscalls, process doppelgänging, and DLL hollowing. THIS skill focuses on the macOS-specific defense stack (AMFI, Gatekeeper, XProtect, MRT, TCC, sandbox profiles) and the macOS-native EDR surface (ESF, System Extensions). Where av-edr-evasion covers Windows API abuse, this skill covers Mach API abuse, entitlement inheritance, and signed-and-notarized dropper patterns.
- **vs `binary-reverse`** — binary-reverse covers PE, ELF, and Mach-O statically and dynamically — broadly platform-agnostic. THIS skill narrows to Mach-O specifically and the macOS-binary ecosystem: entitlements, Objective-C metadata, Swift symbol mangling, arm64/arm64e disassembly (with PAC-aware tooling), the `LC_LOAD_DYLIB` chains, the trust cache, and the interaction between code signing and AMFI at exec time.
- **vs `digital-forensics`** — digital-forensics covers IR artifacts broadly. THIS skill covers macOS-specific artifacts: the unified log (`log show`), FSEvents (`/.fseventsd`), Spotlight metadata (`.metadata_core`), TCC.db audit, Keychain access history, secure notes, and Safari history/cookies. The macOS forensic surface is unusually rich but uniquely structured.
- **vs `anti-forensics`** — anti-forensics covers cleanup broadly. THIS skill's anti-forensics is macOS-specific: clearing the unified log (requires root + SIP weakened), removing specific persistence locations, clearing Cookies.binarycookies, rotating Keychain access timestamps, and managing TCC.db entries.
- **vs `cloud-security`** / **vs `container-security`** — those cover cloud IaaS and Linux containers. macOS has its own containerization model (per-app sandbox via `sandboxd`, container directories at `~/Library/Containers/<bundle-id>/`, Hardened Runtime via entitlements). The macOS container model is per-process and kernel-enforced, not a separate runtime.

## Cross-References

- **`skills/mobile-security/SKILL.md`** — iOS/Android application security. Shares code-signing concepts (codesign, ldid, entitlements) but the attack surface is otherwise different.
- **`skills/binary-reverse/SKILL.md`** — Static/dynamic analysis broadly. The Mach-O sections there are the platform-agnostic version; this skill provides macOS-specific tooling (otool, jtool2, machOView, codesign, etc.).
- **`skills/av-edr-evasion/SKILL.md`** — AV/EDR evasion (Windows-centric). The macOS analog is here: AMFI, Gatekeeper, XProtect, MRT, TCC, ESF.
- **`skills/digital-forensics/SKILL.md`** — Forensic artifact analysis broadly. The macOS-specific artifacts (unified log, FSEvents, TCC.db, Keychain, Cookies.binarycookies) live in this skill.
- **`skills/anti-forensics/SKILL.md`** — Cleanup techniques. The macOS-specific cleanup (LaunchAgent removal, TCC reset, keychain item rotation) lives in this skill.
- **`skills/post-exploitation/SKILL.md`** — General post-exploitation activities. The macOS-specific persistence (LaunchAgents/Daemons, login items, Spotlight importers) is here.
- **`skills/pentest-reporting/SKILL.md`** — Structuring the deliverable. macOS findings map to MITRE ATT&CK for macOS (which is a fully-supported platform in ATT&CK).
- **`skills/scada-ics-security/SKILL.md`** — Industrial control systems. Not directly related, but some Mac-based engineering workstations in OT environments warrant macOS-specific hardening (rare).
- **`skills/identity-attack/SKILL.md`** (if present) — Cross-platform identity attacks. macOS-bound identities (Keychain certificates, MDM enrollment identity, CloudKit) are covered here.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/macos-security-playbook.md` — end-to-end operational playbook covering macOS security architecture, Apple Silicon specifics, building a test lab, red team methodology, real-world macOS threats (XCSpy, Shlayer, Bundlore, Silver Sparrow, NodeStealer, CoinMiner), defense patterns, and references.
- **Reference repositories** (the inspirations for this skill):
  - Objective-See tools (KnockKnock, LuLu, BlockBlock, OverSight, TaskExplorer, What's Your Sign?): [github.com/objective-see](https://github.com/objective-see)
  - macOS-Security-and-Privacy-Guide (drduh, 20k+ stars): [github.com/drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
  - macOS Security Compliance Project (mSCP, NIST + Apple): [github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)
  - sindresorhus/Equity (Gatekeeper/notarization inspector): [github.com/sindresorhus/Equity](https://github.com/sindresorhus/Equity)
  - How-to-Use-Your-Security-Tools-on-macOS: various community guides
  - machOView: [github.com/gdbinit/machOView](https://github.com/gdbinit/machOView)
  - jtool2 (Elias Limneos): [newosxbook.com/tools/jtool.html](http://www.newosxbook.com/tools/jtool.html)
  - ldid (Jay Freeman / saurik): [github.com/saurik/ldid](https://github.com/saurik/ldid)
  - ESF demos (0xcpu gist): gist of a minimal ESF client in C
- **External resources**:
  - Apple Platform Security Guide: [support.apple.com/guide/security/welcome/web](https://support.apple.com/guide/security/welcome/web)
  - Apple Developer — Code Signing Guide: [developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide)
  - Apple Developer — Endpoint Security Framework: [developer.apple.com/documentation/endpointsecurity](https://developer.apple.com/documentation/endpointsecurity)
  - Apple Developer — Hardened Runtime: [developer.apple.com/documentation/security/hardened_runtime](https://developer.apple.com/documentation/security/hardened_runtime)
  - Objective-See blog (Patrick Wardle's research): [objective-see.org/blog.html](https://objective-see.org/blog.html)
  - Patrick Wardle's talks (DEF CON, OBTS, Black Hat): [objective-see.org/downloads.html](https://objective-see.org/downloads.html) — "The Cost of Insecurity", "Death by 1000 Installers", "Bypassing Bounds Checker", etc.
  - mSCP documentation: [apple.github.io/federation-core/mSCP.html](https://apple.github.io/federation-core/mSCP.html)
  - MITRE ATT&CK for macOS: [attack.mitre.org/matrices/enterprise/macos](https://attack.mitre.org/matrices/enterprise/macos)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
