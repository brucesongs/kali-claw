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
| **Total** | **12** | **LOW - CRITICAL** |

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
