# macOS Security Assessment Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command targets macOS 13+ (Ventura/Sonoma/Sequoia) on either Apple Silicon (arm64e, M-series chips) or Intel (x86_64 with T2).
> Placeholder convention: `<bundle-id>` (e.g., `com.example.helper`), `<user>` (the macOS short username), `<SSID>` (Wi-Fi network name), `<profile-id>` (a configuration profile identifier). Replace before running.
> **Scope**: all commands assume explicit written authorization for the target macOS host. Run on a test Mac or a VMware/Parallels VM (with snapshots) whenever possible.

---

## 0. Environment Setup

```bash
# ─── Built-in macOS CLI tools (no install needed) ───
# sw_vers, uname, system_profiler, csrutil, tccutil, profiles, security, codesign,
# spctl, xcrun, otool, nm, lldb, vmmap, leak, fs_usage, opensnoop, dtrace, log,
# launchctl, plutil, defaults, airport, defaults, networksetup, fdesetup,
# systemextensionsctl, sysadminctl, dscl, pmset, softwareupdate, xattr

# ─── Xcode Command Line Tools (required for codesign, xcrun, notarytool) ───
xcode-select --install
# Or: download from developer.apple.com/download/more/

# ─── Homebrew (the de facto macOS package manager) ───
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew --version

# ─── Objective-See tools (all free, all open-source) ───
# KnockKnock — persistence scanner
brew install --cask knockknock
# LuLu — firewall
brew install --cask lulu
# BlockBlock — persistence monitor
brew install --cask blockblock
# OverSight — camera/mic monitor
brew install --cask oversight
# TaskExplorer — process explorer with code-signing info
brew install --cask taskexplorer
# What's Your Sign? — Finder extension for code signing
brew install --cask whatsyoursign

# Or download from objective-see.org/products.html

# ─── Equity (Gatekeeper/notarization inspector GUI) ───
brew install --cask equity

# ─── mSCP (macOS Security Compliance Project) ───
git clone https://github.com/usnistgov/macos_security /opt/mSCP
cd /opt/mSCP
python3 -m pip install -r requirements.txt

# ─── Mach-O analysis ───
brew install --cask machoview            # GUI Mach-O browser
brew install hopper                     # Hopper Disassembler (demo)
# Ghidra (NSA, open-source) — download from https://ghidra-sre.org/
brew install --cask ghidra
# jtool2 — download the latest from newosxbook.com (or build from source)
curl -L http://www.newosxbook.com/tools/jtool2.tgz -o /tmp/jtool2.tgz
tar xzf /tmp/jtool2.tgz -C /tmp/
sudo mv /tmp/jtool2 /usr/local/bin/

# ─── ldid (alternative codesign with entitlements) ───
brew install ldid

# ─── Auxiliary (Forensic + RE) ───
brew install jq
brew install sqlite3
brew install binwalk
brew install radare2
brew install imhex
brew install cookie-reader             # Cookies.binarycookies parser (community)

# ─── Notarization (free Apple Developer account required) ───
# Sign in at developer.apple.com, generate an app-specific password at appleid.apple.com
xcrun notarytool store-credentials "AC_PASSWORD" \
  --apple-id "you@example.com" \
  --team-id "ABCDE12345" \
  --password "REPLACE_WITH_YOUR_APP_SPECIFIC_PASSWORD"
# Credentials stored in the macOS keychain under "AC_PASSWORD"

# ─── ESF (Endpoint Security Framework) tooling ───
# eslogger ships with macOS 13+
which eslogger
# esf-client: third-party CLI ESF subscriber (compile from source)
git clone https://github.com/yoav-yadin/esf-client /tmp/esf-client
# Build with Xcode; signing with ESF entitlements required to run

# ─── Python (for parsing Cookies.binarycookies, TCC.db, etc.) ───
brew install python@3.11
python3 -m pip install biplist          # binary plist parser
python3 -m pip install apsw             # sqlite wrapper
```

---

## 1. Recon — System Profile, Architecture, OS Version

```bash
# macOS version + build number
sw_vers
# ProductName:    macOS
# ProductVersion: 14.5
# BuildVersion:   23F79

uname -a
# Darwin hostname 23.5.0 Darwin Kernel Version 23.5.0 ... arm64

# Hardware architecture (Apple Silicon vs Intel)
uname -m
# arm64      → Apple Silicon (M1/M2/M3/M4) — Rosetta 2 may be installed
# x86_64     → Intel-based Mac

# Detailed hardware profile (model ID, chip, serial, RAM, boot ROM)
system_profiler SPHardwareDataType
system_profiler SPHardwareDataType | grep -E "Model|Chip|Memory|Serial"

# Is Rosetta 2 installed? (Apple Silicon only)
/usr/bin/pgrep oahd >/dev/null && echo "Rosetta 2 present" || echo "Rosetta 2 absent"

# Boot ROM and SMC version (firmware indicators)
system_profiler SPHardwareDataType | grep -E "Boot ROM"

# Kernel caches on Apple Silicon (sealed system snapshot)
mount | grep -E "sealed|read-only"
# /dev/disk1s5s1 on / (apfs, sealed, local, read-only)
# /dev/disk1s4 on /private/var/vm (apfs, local, ...)
# /dev/disk1s5 on /System/Volumes/Data (apfs, local, read-only)

# Authenticated root status (Apple Silicon)
csrutil authenticated-root status
# Authenticated Root status: enabled (or disabled)

# Active user + UID + admin membership
id
groups
whoami

# All local users (more readable than /etc/passwd on macOS)
dscl . list /Users UniqueID
# Or via sysadminctl (admin)
sudo sysadminctl -listUsers

# Currently-logged-in GUI user
stat -f '%Su' /dev/console
# Or:
defaults read /Library/Preferences/com.apple.loginwindow lastUserName

# Hostname variants (each can matter for MDM / SMB / Bonjour)
scutil --get ComputerName
scutil --get LocalHostName
scutil --get HostName
```

```bash
# Disk and FileVault status
diskutil list
diskutil apfs list
fdesetup status
# FileVault is On. (or Off)

# Active network interfaces
ifconfig | grep -E "^[a-z]" | awk -F: '{print $1}'
networksetup -listallhardwareports

# Sleep / wake / power events (forensic — when was the Mac last unlocked?)
pmset -g log | grep -E "Wake|Sleep|DarkWake" | tail -50
pmset -g log | grep "Display is turned on" | tail -20
```

```bash
# Software inventory (installed apps)
ls /Applications
system_profiler SPApplicationsDataType | grep -E "Location:|Version:"

# System Extensions (Apple Silicon / modern macOS — replaces kexts)
systemextensionsctl list

# Kernel extensions (legacy; mostly Apple)
kextstat | grep -v com.apple

# Software update pending
softwareupdate -l
defaults read /Library/Preferences/com.apple.SoftwareUpdate | grep -E "Last|Critical"
```

```bash
# Find security software (Falcon, Defender, SentinelOne, Jamf Protect)
ps aux | grep -iE "falcon|sentinel|defender|jamfProtect|cylance|carbon|crowdstrike"
launchctl list | grep -iE "falcon|sentinel|defender|jamf"
# Common paths
ls /Applications/Falcon.app/Contents/MacOS/ 2>/dev/null
ls /Library/Application\ Support/Microsoft/ 2>/dev/null
```

---

## 2. SIP Status & Bypass

```bash
# ─── Check SIP status ───
csrutil status
# System Integrity Protection status: enabled.
# (or) Custom Configuration:
#   Apple Internal: disabled
#   Kext Signing: enabled
#   Filesystem Protections: enabled
#   Debugging Restrictions: enabled
#   DTrace Restrictions: enabled
#   NVRAM Protection: enabled
#   BaseSystem Verification: enabled
#   Boot-arg Restrictions: enabled
#   Kernel CTRR: enabled

# Boot arguments (debug, kext-dev-mode, etc.)
nvram boot-args
# Should be empty on a production host.

# Apple Silicon: authenticated-root status
csrutil authenticated-root status
# Authenticated Root status: enabled

# Verify system volume is read-only + sealed
mount | grep "on / "
# /dev/disk1s5s1 on / (apfs, sealed, local, read-only)

# Inspect the APFS snapshot for the system volume
diskutil apfs list
# Look for "Snapshot" entries under the System volume

# ─── Disabling SIP (TEST MAC ONLY — not for production) ───
# 1. Reboot into Recovery Mode:
#    - Apple Silicon: hold power button until "Loading startup options" appears
#    - Intel: hold Cmd+R at boot
# 2. Open Terminal (Utilities menu)
# 3. Run:
csrutil disable
# 4. Reboot normally
# 5. After reboot, verify:
csrutil status
# Should now report "disabled."

# Re-enable SIP (mandatory before handoff):
# Reboot into Recovery, then:
csrutil enable

# ─── Partial SIP (debug config — historical CVEs sometimes target specific layers) ───
# In Recovery, run with arguments (advanced, off-by-default):
csrutil enable --without fs --without debug --without dtrace
# Reads as: enable SIP but disable filesystem and debug protections
# Used for development; almost never seen on production hosts.

# ─── Apple Silicon: disabling authenticated-root (sealed snapshot) ───
# Requires SIP already disabled. In Recovery, after `csrutil disable`:
csrutil authenticated-root disable
# After reboot, the system volume is no longer sealed and can be modified.
# To re-seal (restores to factory snapshot):
csrutil authenticated-root enable
```

```bash
# ─── Reading NVRAM (protected since 10.13; SIP limits variables) ───
nvram                                  # all variables (limited without SIP disabled)
sudo nvram -x                          # XML output
sudo nvram boot-args                   # specific var
sudo nvram firmlinks                   # APFS firmlink config (system ↔ data volume)
# Common interesting vars:
sudo nvram prev-lang:kbd               # keyboard layout
sudo nvram fmm-computer-name           # Find My Mac name
sudo nvram back-light-level

# ─── SIP-protected paths (cannot be written even as root when SIP is on) ───
ls -lO /System /usr /bin /sbin | head -20
# Look for the "restricted" flag (schg — system immutable)
# Touch one to verify (will fail when SIP is on):
sudo touch /System/test 2>&1
# → Operation not permitted

# ─── SIP-protected TCC.db (system) ───
sudo ls -l /Library/Application\ Support/com.apple.TCC/TCC.db
# → Should be -rw-r--r-- ... restricted (when SIP is on, sqlite writes blocked)
```

```bash
# ─── Historical SIP-bypass CVEs (informational — patched) ───
# CVE-2019-8805: NFS export config bypass (macOS 10.15.0)
# CVE-2020-3837: crontab DAC override (macOS 10.15.4)
# CVE-2020-9839: TCC bypass via FDisk (macOS 10.15.4)
# CVE-2023-32434: boot ROM memory corruption (Apple Silicon, partly HW-fixed)
# CVE-2023-41990: NE	rd interrupt (M-series boot ROM)
# Detection: check softwareupdate for out-of-date hosts, scan for "Custom Configuration" SIP
```

---

## 3. TCC — Transparency, Consent, and Control

```bash
# ─── Read user TCC.db (Full Disk Access required for the calling process) ───
# Location:
ls -l ~/Library/Application\ Support/com.apple.TCC/TCC.db
# System TCC.db (root + SIP weakened to write; root readable):
ls -l /Library/Application\ Support/com.apple.TCC/TCC.db

# Read all grants (user TCC.db)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, client_type, auth_value, auth_reason, last_modified
   FROM access ORDER BY service;"

# auth_value decoding:
#   0 = denied
#   2 = allowed
#   3 = limited  (e.g., limited Photos access)
# client_type:
#   0 = bundle ID (Icon Creator, "com.apple.Safari")
#   1 = absolute path (rare; usually only system binaries)

# Service name reference (kTCCService*):
#   kTCCServiceSystemPolicyAllFiles          → Full Disk Access
#   kTCCServiceAccessibility                 → Accessibility
#   kTCCServiceSystemPolicySysAdminFiles     → Administrator files
#   kTCCServiceSystemPolicyDesktopFolder     → Desktop folder
#   kTCCServiceSystemPolicyDocumentsFolder   → Documents folder
#   kTCCServiceSystemPolicyDownloadsFolder   → Downloads folder
#   kTCCServiceSystemPolicyNetworkVolumes    → Network volumes
#   kTCCServiceSystemPolicyRemovableVolumes  → Removable volumes
#   kTCCServiceCamera                        → Camera
#   kTCCServiceMicrophone                    → Microphone
#   kTCCServiceLocation                      → Location Services
#   kTCCServiceContacts                      → Contacts
#   kTCCServiceCalendar                      → Calendar
#   kTCCServiceReminders                     → Reminders
#   kTCCServicePhotos                        → Photos
#   kTCCServicePostEvent                     → Calendar event creation
#   kTCCServiceAppleEvents                   → Automation (AppleScript)
#   kTCCServiceScreenCapture                 → Screen recording

# Filter for high-impact grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client FROM access
   WHERE service IN ('kTCCServiceSystemPolicyAllFiles',
                     'kTCCServiceAccessibility',
                     'kTCCServiceAppleEvents',
                     'kTCCServiceScreenCapture')
     AND auth_value = 2;"
```

```bash
# ─── System TCC.db (root required; SIP must NOT block writes for some rows) ───
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access ORDER BY service;"

# ─── tccutil (the only Apple-supported way to modify TCC.db without sqlite) ───
# Reset all user TCC grants (DESTRUCTIVE — only for testing):
tccutil reset All
# Reset a specific service:
tccutil reset SystemPolicyAllFiles
tccutil reset Camera
tccutil reset Microphone

# ─── Inject a grant manually (requires SIP weakened + root) ───
# This is what red teamers do on test Macs to simulate a "misconfigured" host.
# Pattern:
sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "INSERT OR REPLACE INTO access
   (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier_type, indirect_object_identifier, flags, last_modified)
   VALUES ('kTCCServiceSystemPolicyAllFiles', '/usr/local/bin/mybinary', 1, 2, 0, 1, 0, 'UNUSED', 0, strftime('%s','now'));"
# Then the binary /usr/local/bin/mybinary has Full Disk Access without user prompt.
# This is the simplest TCC bypass — but requires write access to TCC.db (which SIP normally blocks).
```

```bash
# ─── TCC bypass via DYLD_INSERT_LIBRARIES on entitled binaries ───
# Apple-signed binaries with the system's own TCC grants can be hijacked
# IF SIP allows DYLD insertion (most modern SIP configs block this on system binaries).
# Pattern: launch a TCC-entitled binary with DYLD_INSERT_LIBRARIES set to attacker dylib.
# Example (DOES NOT WORK on modern macOS — historical CVE territory):
# DYLD_INSERT_LIBRARIES=./evil.dylib /Applications/Safari.app/Contents/MacOS/Safari
# Modern SIP config blocks DYLD insertion into Apple-signed binaries with hardened runtime.
# Detection: check codesign flags — com.apple.security.cs.disable-library-validation is required
codesign -d --entitlements - /Applications/Safari.app 2>&1 | grep -i dyld

# ─── TCC bypass via Apple Events (Automation) ───
# If a binary has kTCCServiceAppleEvents granted, it can drive another app
# (e.g., Safari, Mail) via AppleScript, inheriting the target app's TCC grants.
# Example: drive Safari to read its own cookies
osascript -e 'tell application "Safari" to get URL of front document'
# This works IF the calling process has been granted Automation over Safari.
# Defenders: audit kTCCServiceAppleEvents grants carefully.

# ─── TCC bypass via /usr/bin/osascript + Finder ───
# Finder is Apple-signed and has Full Disk Access by default.
# If a binary has Automation over Finder, it can read anywhere via Finder.
osascript -e 'tell application "Finder" to get files of (path to documents folder)'
```

---

## 4. Endpoint Security Framework (ESF)

```bash
# ─── ESF basics ───
# The Endpoint Security framework is the only supported API for monitoring
# process exec, file writes, disk I/O, mount, login, etc. on macOS 10.15+.
# Apple ships `eslogger` CLI as of macOS 13 (Ventura).

# Available event types
eslogger --list-events

# Stream a few common event types (foreground, until Ctrl+C)
sudo eslogger exec | grep -E "executable_path|ppid"
sudo eslogger open | head -50
sudo eslogger write | head -50
sudo eslogger exit | head -50
sudo eslogger authentication | head -50    # OD auth events
sudo eslogger login_logout | head -50

# Combine multiple events
sudo eslogger exec open write close | jq -c .

# Filter to a specific binary path (using jq)
sudo eslogger exec | jq 'select(.event.exec.target.executable.path | contains("Safari"))'

# Filter to non-Apple binaries
sudo eslogger exec | jq -r 'select(.event.exec.target.executable.path | startswith("/Applications/") or startswith("/usr/local/") or startswith("/Users/")) | .event.exec.target.executable.path' | sort -u

# Pipe to a log file for later analysis
sudo eslogger exec open write > /tmp/esf.log &
ESFPID=$!
# ... do work ...
kill $ESFPID
wc -l /tmp/esf.log
```

```bash
# ─── Writing a minimal ESF client (C) ───
# Required: a binary signed with:
#   com.apple.developer.endpoint-security.client (Apple-issued entitlement — developer account required)
# Without this entitlement, esf-client / your custom ESF binary will fail at subscribe time.
# Educational gist: https://gist.github.com/objective-see/01cf1c8c1c2c3d4e5f6072288999aaaa

# Skeleton (excerpt — see the gist for the full implementation):
# #include <EndpointSecurity/EndpointES.h>
# int main() {
#     es_client_t *client = NULL;
#     es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
#         if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
#             printf("exec: %s\n", msg->event.exec.target->executable->path.data);
#         }
#     });
#     es_subscribe(client, (es_event_type_t[]){ES_EVENT_TYPE_NOTIFY_EXEC}, 1);
#     dispatch_main();
#     return 0;
# }

# Compile + sign (requires Apple ESF entitlement)
# clang -framework EndpointSecurity -framework Foundation esf_client.m -o esf_client
# codesign --sign "Developer ID Application: Your Name (TEAM_ID)" \
#           --entitlements esf_entitlements.plist \
#           --options runtime \
#           esf_client

# Entitlements plist (esf_entitlements.plist):
# <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
#   <key>com.apple.developer.endpoint-security.client</key>
#   <true/>
# </dict>
# </plist>

# This entitlement is approved by Apple on a per-developer basis (commercial EDR vendors).
# For research: apply at developer.apple.com/contact/request/endpoint-security-client-entitlement/
```

```bash
# ─── ESF as a defender: building a process-tree timeline ───
# On a Mac under attack, capture all exec events for 60s and build a tree.
sudo eslogger exec > /tmp/execs.jsonl &
ESFPID=$!
sleep 60
kill $ESIPID

# Build a tree (quick jq-based approach):
jq -r '[.event.exec.target.executable.path, .event.exec.target.audit_token.process_id,
        .event.exec.parent.executable.path, .event.exec.parent.audit_token.process_id]
       | @tsv' /tmp/execs.jsonl | sort -u | head -50

# Pipe to a tool like `process_tree.py` (community) for a visual tree.

# ─── ESF detection of TCC.db writes ───
sudo eslogger write | jq 'select(.event.write.target.path | contains("TCC.db"))'
# This is exactly what commercial EDR uses to detect TCC.db tampering attempts.

# ─── ESF detection of LaunchDaemon installation ───
sudo eslogger write | jq 'select(.event.write.target.path | test("/Library/(LaunchAgents|LaunchDaemons)/.*\\.plist$"))'
```

```bash
# ─── What the defender's EDR sees (knowing the field) ───
# Falcon, SentinelOne, Defender for Endpoint, Jamf Protect all subscribe to ESF.
# Identify which one is running:
launchctl list | grep -iE "falcon|sentinel|defender|jamf"

# Look at their ESF subscription by enumerating System Extensions:
systemextensionsctl list
# Typical output:
# --- extension activity ---
# com.crowdstrike.falcon.Agent ( CrowdStrike Falcon )       [active]
# com.microsoft.defender.T1083                              [active]

# Each of these has the ESF entitlement and is subscribed to a subset of event types.
# Defenders see EVERYTHING you do via ESF — assume full visibility.
```

---

## 5. LaunchAgents & LaunchDaemons

```bash
# ─── Persistence locations (the Big List) ───
# User-scope LaunchAgents (most common — runs at user login)
ls -l ~/Library/LaunchAgents/
# System-scope LaunchAgents (runs at any user login)
ls -l /Library/LaunchAgents/
# System-scope LaunchDaemons (runs at boot as root — highest-impact)
ls -l /Library/LaunchDaemons/
# Apple-bundled (informational — usually safe, do not modify)
ls -l /System/Library/LaunchAgents/ /System/Library/LaunchDaemons/

# ─── LaunchAgent plist structure ───
# User LaunchAgent template (com.example.helper.plist):
# <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
#   <key>Label</key>
#   <string>com.example.helper</string>
#
#   <key>ProgramArguments</key>
#   <array>
#     <string>/Users/REPLACE_WITH_YOUR_USER/.local/bin/helper</string>
#     <string>--background</string>
#   </array>
#
#   <key>RunAtLoad</key>
#   <true/>
#
#   <key>KeepAlive</key>
#   <true/>
#
#   <key>StandardOutPath</key>
#   <string>/tmp/helper.log</string>
#
#   <key>StandardErrorPath</key>
#   <string>/tmp/helper.err</string>
# </dict>
# </plist>
```

```bash
# ─── Install a user LaunchAgent ───
PLIST=~/Library/LaunchAgents/com.example.helper.plist

# Write via plutil (safer than heredoc)
plutil -create xml1 "$PLIST"
plutil -insert Label -string "com.example.helper" "$PLIST"
plutil -insert ProgramArguments -array "$PLIST"
plutil -insert ProgramArguments.0 -string "/Users/REPLACE_WITH_YOUR_USER/.local/bin/helper" "$PLIST"
plutil -insert RunAtLoad -bool true "$PLIST"
plutil -insert KeepAlive -bool true "$PLIST"

# Verify
plutil -p "$PLIST"

# Load it now (without reboot):
launchctl load "$PLIST"
# Modern syntax (launchctl bootstrap — preferred on macOS 10.10+):
launchctl bootstrap gui/$(id -u) "$PLIST"

# Verify it's running
launchctl list | grep com.example
# Status 0 = running fine; non-zero = check the StandardErrorPath

# Unload
launchctl unload "$PLIST"
launchctl bootout gui/$(id -u) "$PLIST"

# ─── LaunchDaemon (system, root) ───
# Same plist structure, but the ProgramArguments binary MUST be owned by root:wheel
# and have mode 0755. Place at:
#   /Library/LaunchDaemons/com.example.helper.plist
# Load:
sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.helper.plist
# Verify:
sudo launchctl list | grep com.example
```

```bash
# ─── Enumerate currently-loaded services (the live set) ───
launchctl list | head -20
# Columns: PID, Status, Label
# PID of "-" = not currently running (loaded but not active)

# Service info for a specific label
launchctl print gui/$(id -u)/com.example.helper
launchctl print system/com.example.helper 2>/dev/null   # system daemon (root)

# Find all loaded services from LaunchAgents/Daemons in our standard locations
for path in ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons; do
  for f in "$path"/*.plist; do
    [ -f "$f" ] || continue
    label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$f" 2>/dev/null)
    pid=$(launchctl list "$label" 2>/dev/null | grep -E "PID" | head -1)
    echo "$f → $label ($pid)"
  done
done
```

```bash
# ─── The 50+ persistence locations KnockKnock covers ───
# (From objective-see/KnockKnock source — informational)
#
# LaunchAgents (user):           ~/Library/LaunchAgents/*.plist
# LaunchAgents (system):         /Library/LaunchAgents/*.plist
# LaunchDaemons (system):        /Library/LaunchDaemons/*.plist
# Login Items (LSSharedFileList): ~/Library/Application Support/com.apple.backgroundtaskmanagementagent
# Login Items (newer SMAppService): Managed by launchctl / ServiceManagement
# ATLogin (legacy):              /etc/rc.common, /etc/periodic/{daily,weekly,monthly}/
# Spotlight Importers:           ~/Library/Spotlight/*.mdimporter
# QuickLook Plugins:             ~/Library/QuickLook/*.qlgenerator
# Internet Plugins:              ~/Library/Internet Plug-Ins/
# Audio Plugins:                 ~/Library/Audio/Plug-Ins/{Components,HAL}/
# Mail Plugins (legacy):         ~/Library/Mail/Bundles/
# Screensavers:                  ~/Library/Screen Savers/*
# Login Window:                  /Library/Preferences/LoginWindow.plist
# Cron:                          ~/Library/crontab, /etc/crontab
# Browser Extensions:            ~/Library/Application Support/Google/Chrome/Default/Extensions/
#                                ~/Library/Application Support/Firefox/Profiles/*/extensions/
#                                ~/Library/Safari/Extensions/
# Kernel Extensions (legacy):    /Library/Extensions/, /System/Library/Extensions/
# System Extensions:             via systemextensionsctl list
# LoginHook (legacy):            /usr/sbin/defaults read /Library/Preferences/com.apple.loginwindow LoginHook
# LogoutHook:                    /usr/sbin/defaults read /Library/Preferences/com.apple.loginwindow LogoutHook
# AppleScript Folder Actions:    ~/Library/Workflows/Applications/Folder Actions/

# List login items (newer SMAppService approach)
osascript -e 'tell application "System Events" to get the name of every login item'

# Spotlight importers
ls ~/Library/Spotlight/ /Library/Spotlight/ 2>/dev/null

# QuickLook plugins
ls ~/Library/QuickLook/ /Library/QuickLook/ 2>/dev/null

# Kernel extensions (legacy; usually Apple-only on modern macOS)
kextstat | grep -v com.apple
ls /Library/Extensions/ 2>/dev/null

# System Extensions (modern macOS)
systemextensionsctl list
```

---

## 6. Keychain Extraction

```bash
# ─── Keychain locations ───
ls -l ~/Library/Keychains/
# login.keychain-db       — user's login keychain (unlocked at login)
ls -l /Library/Keychains/
# System.keychain         — system-wide certs, WiFi PSKs
ls -l /Library/Keychains/FileVaultMaster.keychain
ls -l /Library/Apple/Internal/Enterprise/  2>/dev/null

# List all configured keychains for the user
security list-keychains
# Default: ~/Library/Keychains/login.keychain-db

# ─── Enumerate keychain entries (no secrets) ───
# All generic-password entries
security dump-keychain ~/Library/Keychains/login.keychain-db | head -100

# Or just the "key" lines (svce, acct, desc):
security dump-keychain ~/Library/Keychains/login.keychain-db | \
  grep -E '"svce"|"acct"|"desc"|"cdat"|"mdat"'

# Find by service name (Wi-Fi, website, app name)
security find-generic-password -l "Wi-Fi SSID Name"
security find-generic-password -s "com.example.app.token"

# Count entries
security dump-keychain ~/Library/Keychains/login.keychain-db | grep -c "keychain: "

# ─── List certificates (often reveals MDM identity, dev certs) ───
security find-certificate -a ~/Library/Keychains/login.keychain-db | head -50
security find-certificate -a /Library/Keychains/System.keychain | head -50
# Find Apple Developer Program certs (red flag if unexpected)
security find-certificate -a /Library/Keychains/System.keychain | grep -i "Apple Developer"
# Find MDM / SCEP certs
security find-certificate -a /Library/Keychains/System.keychain | grep -iE "MDM|SCEP|Profile"
```

```bash
# ─── Extract a secret (prompts for keychain password) ───
# -w = "write the password to stdout" (vs just metadata)
# -g = also print via Security command
# For a Wi-Fi password:
security find-generic-password -ga "REPLACE_WITH_YOUR_SSID" -d ~/Library/Keychains/login.keychain-db -w
# Output: password: "<WPA-PSK>"

# For a saved website password (Safari stores in keychain):
security find-internet-password -s "example.com" -w
# (this will prompt the user; on macOS 13+ the UI dialog appears even in Terminal)

# Dump ALL keychain items WITH secrets (prompts repeatedly for keychain password):
security dump-keychain -d ~/Library/Keychains/login.keychain-db > /tmp/keychain_dump.txt
wc -l /tmp/keychain_dump.txt
# This is the canonical macOS keychain extraction technique.
# Defenders: macOS 10.13+ requires a per-call user prompt by default unless the
# calling binary is signed with the keychain-access-groups entitlement.

# ─── Offline hash extraction (chainbreaker / KeychainDump) ───
# If you've copied the keychain file out of the host, tools like chainbreaker
# can extract entries given the user's login password (for PBKDF2-based decryption).
# chainbreaker -f ~/Library/Keychains/login.keychain-db -p REPLACE_WITH_YOUR_PASSWORD --dump-all
# KeychainDump (older): extracts user keychain entries by hooking securityd in memory.
```

```bash
# ─── Saved Wi-Fi networks and PSKs (system keychain) ───
# List known networks (preferences plist)
sudo defaults read /Library/Preferences/com.apple.wifi.known-networks | head -50

# Or via airport CLI (deprecated in macOS 15 but still on older versions)
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s

# Extract a network's PSK (system keychain)
sudo security find-generic-password -ga "REPLACE_WITH_YOUR_SSID" /Library/Keychains/System.keychain -w
# Output: password: "<WPA-PSK>"

# ─── iCloud / Apple ID tokens ───
# Stored in the keychain; extraction requires user password.
security find-generic-password -s "iCloud" -w 2>/dev/null
security find-generic-password -s "com.apple.account" -w 2>/dev/null
```

```bash
# ─── Hardened extraction via Apple Events ───
# If the user is logged in but you don't have their keychain password,
# you can sometimes drive the Keychain Access app via AppleScript.
# Requires prior Automation (kTCCServiceAppleEvents) grant to your binary over "Keychain Access".
osascript -e 'tell application "Keychain Access" to get name of every keychain'

# More commonly: extract secrets via the owning app (Safari, Mail) via AppleScript.
# Example: read Safari's saved password for a site (requires Safari's own keychain access)
# This is harder than it sounds; modern macOS prompts the user explicitly.
```

---

## 7. Cookies & Safari Data

```bash
# ─── Safari cookie file ───
COOKIES=~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies
ls -l "$COOKIES"
# This file is a non-standard binary plist format (NOT XML).
# Reading it requires Full Disk Access for the calling process.

# ─── Parse Cookies.binarycookies (community Python parser) ───
# Method 1: cookie-reader (brew install cookie-reader)
cookie-reader "$COOKIES"

# Method 2: Python (one of many community parsers; example structure):
python3 << 'EOF'
import struct, sys, datetime
path = "/Users/REPLACE_WITH_YOUR_USER/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"
with open(path, "rb") as f:
    magic = f.read(4)
    assert magic == b"cook", f"not a binarycookies file: {magic!r}"
    num_pages = struct.unpack(">I", f.read(4))[0]
    page_sizes = [struct.unpack(">I", f.read(4))[0] for _ in range(num_pages)]
    for ps in page_sizes:
        page = f.read(ps)
        # ... parse cookie records (each is a struct with url/name/value/path/expires)
        # See community parsers: https://github.com/as0ler/BinaryCookieReader
EOF

# ─── Safari history (SQLite) ───
HIST=~/Library/Safari/History.db
ls -l "$HIST"
sqlite3 "$HIST" ".tables"
# history_items, history_visits
sqlite3 "$HIST" "SELECT url, visit_time FROM history_items ORDER BY visit_time DESC LIMIT 20;"
# visit_time is "seconds since 2001-01-01 00:00:00 UTC" (Apple epoch)
# Convert to human-readable:
sqlite3 "$HIST" \
  "SELECT url, datetime(visit_time + 978307200, 'unixepoch', 'localtime') AS visit_dt
   FROM history_items JOIN history_visits ON history_items.id = history_visits.history_item
   ORDER BY visit_time DESC LIMIT 50;"
```

```bash
# ─── Safari form data, downloads, bookmarks ───
ls -l ~/Library/Safari/
# Bookmarks.plist, Form Values (encrypted), Downloads.plist, TopSites.plist, ...

# Bookmarks (binary plist)
plutil -p ~/Library/Safari/Bookmarks.plist | head -100

# Downloads history (binary plist)
plutil -p ~/Library/Safari/Downloads.plist

# Recently-closed tabs
plutil -p ~/Library/Safari/LastSession.plist

# ─── Chrome data (if user uses Chrome) ───
ls ~/Library/Application\ Support/Google/Chrome/Default/
# Cookies (SQLite), History (SQLite), Login Data (encrypted), Local State (master key)

# Chrome cookies (encrypted with key from macOS keychain)
sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Cookies \
  "SELECT host_key, name, encrypted_value FROM cookies LIMIT 10;"

# Chrome master key (stored in keychain under "Chrome Safe Storage")
security find-generic-password -w -s "Chrome Safe Storage"
# This AES key decrypts the per-cookie values.

# ─── Firefox data ───
ls ~/Library/Application\ Support/Firefox/Profiles/*/
# key4.db (master password + logins), logins.json (encrypted), cookies.sqlite

# Firefox cookies
sqlite3 ~/Library/Application\ Support/Firefox/Profiles/*/cookies.sqlite \
  "SELECT host, name, value FROM moz_cookies LIMIT 20;"
```

```bash
# ─── Notes.app (often stores sensitive info) ───
NOTES=~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite
ls -l "$NOTES"
# Note bodies are Zipped protobuf inside ZDATA_BLOB; use a community parser.
# Or use `notesapp` (Python wrapper around AppleScript).

# ─── Messages.app (iMessage history) ───
CHAT=~/Library/Messages/chat.db
ls -l "$CHAT"
sqlite3 "$CHAT" ".tables"
sqlite3 "$CHAT" \
  "SELECT datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime') AS msg_time, text
   FROM message ORDER BY date DESC LIMIT 20;"

# ─── Mail.app ───
ls ~/Library/Mail/V*/MailData/
# Envelope Index (SQLite), Flags.plist, ...
# Mail bodies are at ~/Library/Mail/V*/Mailboxes/
```

---

## 8. Apple Silicon Specifics

```bash
# ─── Architecture detection ───
uname -m
# arm64      → Apple Silicon (userland)
# x86_64     → Intel
# arm64e     → Apple Silicon with PAC (kernel/system binaries; userland usually reports as arm64)

# Check whether the system booted arm64e (PAC-active)
sysctl -n hw.optional.armv8_3_jscvt   # JSCVT (JavaScript convert)
sysctl -n hw.optional.armv8_4_fhm     # FHM (half-precision)
# PAC-related sysctl
sysctl -n hw.optional.arm64e          # 1 = arm64e available

# Rosetta 2 installed?
[ -f /Library/Apple/usr/share/rosetta/rosetta ] && echo "Rosetta 2 installed"
/usr/bin/pgrep -x oahd >/dev/null && echo "Rosetta 2 running"

# List Rosetta 2 processes (running x86_64 binaries on Apple Silicon)
ps -A -o pid,comm,arch | awk '$3 == "i386"'   # arch column shows i386 for x86_64 on macOS

# ─── Sealed System Snapshot (SSV) ───
# Apple Silicon (and Intel T2) boot from a sealed APFS snapshot of the System volume.
mount | grep "^/" | head -10
# /dev/disk1s5s1 on / (apfs, sealed, local, read-only)       ← System snapshot (read-only)
# /dev/disk1s5   on /System/Volumes/Data (apfs, local, ...)  ← Data volume (read-write)
# /dev/disk1s4   on /private/var/vm (apfs, ...)              ← Swap

# Authenticated-root status (must be enabled; if disabled, snapshot is bypassed)
csrutil authenticated-root status

# Inspect the snapshot
diskutil apfs list
# Look for "Snapshot" entries under the System volume (e.g., com.apple.battery.2024-01-01-08-00-00.UTC)

# Firmlinks (the magic that joins System and Data volumes into one tree)
cat /usr/share/firmlinks 2>/dev/null
# Each line: /system/path  /data/path
# E.g.:  /etc  /private/etc
```

```bash
# ─── Pointer Authentication Codes (PAC) ───
# PAC signs every function pointer and return address with a cryptographic
# signature derived from the pointer value, the calling context, and a per-process key.
# Result: classic ROP/JOP chains that overwrite return addresses on the stack fail.

# Detection (sysctl):
sysctl -n hw.optional.arm64e     # 1 = PAC enabled

# ARM v8.3 instructions (PACIA, PACIB, AUTIA, AUTIB, RETAA, BLRAA) appear in disassembly.
# Disassemble a function with jtool2 / Hopper and look for "pacia", "autia" mnemonics.
# Example:
#   _foo:
#     pacibsp           ; sign LR with B-key (stack pointer context)
#     stp x29, x30, [sp, #-16]!
#     ...
#     ldp x29, x30, [sp], #16
#     retab             ; authenticate LR and return
# PAC-aware tools: Hopper (since 5.x), Ghidra (since 10.x with arm64e plugin), jtool2.

# ─── Bypassing PAC (advanced — research territory) ───
# Known academic bypasses:
#   - Pointer substitution (find a signed pointer to a similar function)
#   - Side-channel attacks (BLRAA timing)
#   - PPL/JOP via signing gadgets (rare; requires deep RE)
# In practice, most red team operators do NOT bypass PAC directly; they use
# legitimate signed-and-notarized code execution (Apple Events, osascript,
# entitlement inheritance) instead of memory-corruption exploitation.

# ─── Apple Silicon boot ROM ───
# Boot ROM is on-die in the M-series chip and is NOT field-updateable.
# Historical boot ROM bugs: CVE-2023-32434 (memory corruption in image4 parser),
# CVE-2023-38606 (Memory Read/Write primitive via GPU). Apple addressed via
# boot ROM updates in hardware revision — old M1 chips may remain vulnerable.
# Detection: check chip model + boot ROM version.
system_profiler SPHardwareDataType | grep -E "Chip|Boot ROM"
```

```bash
# ─── Rosetta 2 caveats ───
# Rosetta 2 translates x86_64 binaries to arm64 at runtime.
# Historical bug: CVE-2021-30717 — Rosetta-translated binaries bypassed code
# signing checks because the translated arm64 binary had no signature at all.
# Patched in macOS 11.4.
# Detection: ensure macOS version >= 11.4.

# List Rosetta-translated processes currently running
ps -A -o pid,comm,arch | awk '$3 == "i386" {print $1, $2}'
# Or via TaskExplorer (GUI).

# Force a binary to run under Rosetta 2 (testing):
# Right-click app → Get Info → "Open using Rosetta"
# Or via `arch`:
arch -x86_64 /bin/ls

# ─── Kernel extensions vs System Extensions ───
# On Apple Silicon, third-party kernel extensions are effectively dead.
# Apple requires System Extensions (user-land) and DriverKit for hardware drivers.
systemextensionsctl list
# Typical entries:
# --- extension activity ---
# com.apple-driver.AmericanMegatrends ( AMI Virtual Serial )        [approved]
# com.crowdstrike.falcon.Agent ( CrowdStrike Falcon Sensor )       [active]

# Inspect a System Extension
systemextensionsctl inspect com.example.myExtension

# Red team note: System Extensions require a Developer ID with the appropriate
# entitlement; they cannot be installed ad-hoc. Persistence via SE is rare.
```

```bash
# ─── T2 chip (Intel Macs with T2, 2018-2020) ───
# T2 is the predecessor of Apple Silicon's integrated secure enclave.
# T2 controls: Secure Boot, Touch Bar, SMC, audio, camera (hardware kill), SSD encryption.
# T2 has its own kernel (bridgeOS) and historically was exploitable via checkm8
# (CVE-2019-8900 family — USB DFU exploit, allowing bridgeOS downgrade).

# Check for T2:
system_profiler SPiBridgeDataType
# Model Name: iBridge
# Model Identifier: bridgeOS-...

# T2 features accessible from userland:
# - Secure Enclave (Touch ID, Apple Pay secrets)
# - FileVault key storage
# - Encrypted SSD (hardware AES-XTS)
# - DRM (FairPlay)

# ─── Apple Configurator 2 (for DFU-mode T2 recovery) ───
# On a second Mac, install Apple Configurator 2 (free from App Store).
# Connect the target Mac via USB-C cable in DFU mode (specific key combo).
# Use Configurator → Advanced → Erase / Restore to flash bridgeOS.
```

---

## 9. MDM Profile Analysis

```bash
# ─── profiles CLI ───
# List installed profiles (user-installable)
profiles list -output user

# List all profiles (admin required)
sudo profiles list
# Output columns: profileIdentifier, profileUUID, displayName, scope, installDate

# Show details of one profile
sudo profiles show -identifier com.example.restrictions

# Dump the full payload as a plist (open in Xcode or plutil -p)
sudo profiles show -output open-command -identifier com.example.restrictions > /tmp/profile.plist
plutil -p /tmp/profile.plist

# Where profiles live on disk (system)
sudo ls -l /var/db/ConfigurationProfiles/
sudo ls -l /var/db/ConfigurationProfiles/Setup/
sudo ls -l /var/db/ConfigurationProfiles/Settings/
# Files like: .xml.sign, .meta, profile.data (encrypted blobs)

# User-scope profiles
ls -l ~/Library/ConfigurationProfiles/
```

```bash
# ─── MDM enrollment identity ───
# When a Mac enrolls in MDM (DEP or user-initiated), an enrollment identity
# certificate is installed in the System keychain.
sudo security find-certificate -a /Library/Keychains/System.keychain | grep -iE "labl|MDM|Profile"

# Specifically the MDM identity:
sudo security find-certificate -a -c "MDM" /Library/Keychains/System.keychain
sudo security find-certificate -a -c "Profile" /Library/Keychains/System.keychain

# The MDM vendor:
sudo defaults read /Library/Preferences/com.apple.mdm 2>/dev/null
sudo defaults read /Library/Managed\ Preferences/com.apple.mdm 2>/dev/null
# Look for: EnrollmentID, EnrollmentURL, ServerURL, Topic (APNs)

# ─── DEP (Device Enrollment Program) detection ───
# If the Mac is DEP-enrolled, it will re-enroll in MDM on next setup.
profiles show -type enrollment
# DEP Status: Enrolled (or Not Enrolled)

# ─── Listing pushed restrictions (PayloadType=Configuration) ───
sudo profiles list | awk '/^com\.apple\./{print $1}' | sort -u
# Common restriction profiles:
#   com.apple.applicationaccess.new    → Allow / disallow apps
#   com.apple.security.FDE            → FileVault config
#   com.apple.security.firewall       → Application Firewall config
#   com.apple.screentime              → Screen Time config
#   com.apple.systempolicy.control    → Software Update restrictions
```

```bash
# ─── Bypass / downgrade (research) ───
# In supervised mode (DEP), profiles cannot be removed via System Settings.
# The classic bypass (works only on unsupervised Macs):
sudo profiles remove -identifier com.example.restrictions
# On supervised Macs: "This profile cannot be removed." (or similar)

# Beta OS profile bypass (CVE-2018-4193, patched): historically, installing
# a beta iOS/iPadOS/macOS profile would unsupervise the device.
# Modern: not applicable, but worth checking OS version.

# ─── Enrollment identity theft ───
# If the MDM enrollment identity (cert + private key) can be extracted,
# an attacker can enroll a rogue device that impersonates the legitimate Mac.
# Requires: read of /var/db/ConfigurationProfiles + System keychain.
sudo security find-identity /Library/Keychains/System.keychain | grep -i mdm
# Defenders: enroll identity should be tied to device serial; MDM should reject
# re-enrollment from a different device.

# ─── MDM network calls (what to monitor) ───
# MDM check-ins go to the MDM vendor's server (e.g., *.jamfcloud.com, *.manage.microsoft.com)
# via HTTPS with the enrollment cert as client auth.
# Sniff (on the host — needs sudo):
sudo tcpdump -i en0 -nn -A 'tcp port 443 and host REPLACE_WITH_YOUR_MDM_HOST'
# Identify the MDM host from profiles / ServerURL
```

---

## 10. Mach-O Analysis

```bash
# ─── Architecture and header ───
file /bin/ls
# /bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
# /bin/ls (for architecture x86_64):   Mach-O 64-bit executable x86_64
# /bin/ls (for architecture arm64e):   Mach-O 64-bit executable arm64e

# Show the fat header (universal binary) info
lipo -info /bin/ls
lipo -detailed_info /bin/ls

# Single-arch header
otool -hv /bin/ls
# Mach header
#       magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
# 0xfeedfacf 16777223          2  0x00      EXECUTE    19       1568   0x00200085

# Show all load commands
otool -l /bin/ls | head -100
# Key load commands:
#   LC_SEGMENT_64          → segments (__TEXT, __DATA, __LINKEDIT)
#   LC_LOAD_DYLIB          → linked dylib (libSystem.B.dylib, etc.)
#   LC_CODE_SIGNATURE      → offset of embedded code signature
#   LC_UUID                → build UUID (for symbolication)
#   LC_MAIN                → entry point (main())
#   LC_RPATH               → runtime search path (@rpath, @loader_path)
#   LC_VERSION_MIN_MACOSX  → minimum macOS version
#   LC_BUILD_VERSION       → modern build version (platform, SDK, min OS)

# Or jtool2 (cleaner output)
jtool2 -l /bin/ls | head -50
jtool2 -L /bin/ls       # just linked libraries

# ─── Linked libraries (LC_LOAD_DYLIB entries) ───
otool -L /bin/ls
# /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1311.100.3)
# /usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
# ...

# Find non-system libraries (red flag on a third-party binary)
otool -L /Applications/SomeApp.app/Contents/MacOS/SomeApp | grep -v "/usr/lib/"
```

```bash
# ─── Symbol table ───
nm -p /bin/ls | head -20
# Or with jtool2 (cleaner)
jtool2 -S /bin/ls | head -50

# Undefined symbols (external, resolved at load time)
nm -u /bin/ls

# Defined external symbols (exported)
nm -g /bin/ls | head -20

# ─── Objective-C class metadata ───
# Objective-C binaries store class names, method names, and ivar layouts as
# metadata in __objc_classlist, __objc_protolist, etc.
otool -ov /Applications/Safari.app/Contents/MacOS/Safari 2>/dev/null | head -100
# Or jtool2:
jtool2 -objc /Applications/Safari.app/Contents/MacOS/Safari 2>/dev/null | head -50
# Look for class names like "SFOperation", "BrowserController" — useful for hooking.

# ─── Swift symbol mangling ───
# Swift symbols are mangled (e.g., "$s10SomeModule4SomeC6methodyyF").
# Demangle with:
xcrun swift-demangle '$s10SomeModule4SomeC6methodyyF'
# Or in Hopper / Ghidra with the Swift plugin.
```

```bash
# ─── Sections (segments) ───
otool -hv /bin/ls && echo "---" && otool -l /bin/ls | grep -A5 "LC_SEGMENT_64"
# Or with jtool2:
jtool2 -segment /bin/ls
jtool2 -section /bin/ls

# __TEXT segment contains:
#   __text, __stubs, __stub_helper, __cstring, __objc_classname, __objc_methname,
#   __objc_methtype, __objc_classlist, __objc_protolist, __objc_imageinfo,
#   __unwind_info, __eh_frame, __code_signature
# __DATA segment contains:
#   __nl_symbol_ptr, __la_symbol_ptr, __objc_const, __objc_selrefs, __objc_classrefs,
#   __objc_superrefs, __objc_ivar, __objc_data, __data, __bss, __common
# __LINKEDIT segment contains:
#   symbol table, string table, code signature

# Inspect strings (security-sensitive strings)
strings /Applications/SomeApp.app/Contents/MacOS/SomeApp | grep -iE "key|secret|password|api[-_]?key|token"
# Better: use radare2 / imhex for hex view + cross-reference.

# ─── Code signature inspection ───
codesign -dvvv /Applications/Safari.app
# Identifier=          "com.apple.Safari"
# TeamIdentifier=      not set (Apple Mac OS Application Signing)
# Authority=           Software Signing
# Authority=           Apple Code Signing Certification Authority
# Authority=           Apple Root CA
# CodeDirectory v=     20400
# ...

codesign -d --entitlements - /Applications/Safari.app
# Look for entitlements like:
#   com.apple.security.cs.allow-jit
#   com.apple.security.cs.disable-library-validation
#   com.apple.security.cs.disable-executable-page-protection
#   com.apple.security.device.camera
#   com.apple.security.device.microphone
#   com.apple.security.network.client
#   com.apple.security.network.server

# Verify signature
codesign --verify --verbose /Applications/Safari.app
# /Applications/Safari.app: valid on disk
# /Applications/Safari.app: satisfies its Designated Requirement

# Deep verify (also checks nested code)
codesign --verify --deep --verbose /Applications/SomeApp.app
```

```bash
# ─── Disassembly ───
# arm64/arm64e disassembly via jtool2:
jtool2 -d --arch arm64e /Applications/Safari.app/Contents/MacOS/Safari 2>/dev/null | head -50

# Or with Hopper (GUI):
# Open binary in Hopper → arm64 or arm64e disassembly → look for main(), objc_msgSend calls

# Or with Ghidra:
# 1. Create new project, import the Mach-O
# 2. Analyze (default options)
# 3. For arm64e: install the Apple arm64e processor module (community plugin)
# 4. Symbolicate via dSYM if available

# GDB-style debugging with lldb:
lldb /Applications/Safari.app
(lldb) target create "/Applications/Safari.app/Contents/MacOS/Safari"
(lldb) b main
(lldb) run
(lldb) register read
(lldb) x/10i $pc
# Note: debugging Apple-signed binaries requires disabling SIP (or specific entitlements).
```

---

## 11. Code Signing & Notarization

```bash
# ─── Ad-hoc signing (for local execution; no Developer ID required) ───
codesign -s - --force --options runtime /tmp/mybinary
# -s -            → ad-hoc (sign with no identity)
# --force         → overwrite existing signature
# --options runtime → Hardened Runtime (required for notarization)

# ─── Developer ID signing (for distribution) ───
codesign --sign "Developer ID Application: Your Name (ABCDE12345)" \
         --options runtime \
         --entitlements my_entitlements.plist \
         --force --deep \
         /tmp/MyApp.app
# --deep: recursively sign nested code (deprecated since macOS 11; sign individually now)

# ─── Entitlements plist example (my_entitlements.plist) ───
# <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
#   <key>com.apple.security.cs.allow-jit</key>
#   <true/>
#   <key>com.apple.security.cs.disable-library-validation</key>
#   <true/>
#   <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
#   <true/>
#   <key>com.apple.security.network.client</key>
#   <true/>
#   <key>com.apple.security.device.camera</key>
#   <true/>
# </dict>
# </plist>

# ─── Verify a signature ───
codesign -dvvv /tmp/MyApp.app
codesign --verify --verbose=4 /tmp/MyApp.app
# --verbose=4 prints the cert chain.

# ─── Check Gatekeeper assessment (what the OS thinks of a downloaded binary) ───
xattr /tmp/MyApp.app                  # show extended attributes
# com.apple.quarantine (if downloaded via Safari/Mail)
xattr -l /tmp/MyApp.app               # value of the quarantine attribute

spctl --assess --type execute --verbose /tmp/MyApp.app
# /tmp/MyApp.app: accepted (or rejected)
# source=Notarized Developer ID (or Developer ID, or GarageBand)

# Remove the quarantine attribute (often used by users to "fix" apps that won't open)
xattr -d com.apple.quarantine /tmp/MyApp.app
# Defenders: monitor for `xattr -d com.apple.quarantine` — a classic social engineering step.
```

```bash
# ─── Notarization (requires Apple Developer account, $99/yr) ───
# Step 1: Zip / DMG the signed app
ditto -c -k --keepParent /tmp/MyApp.app /tmp/MyApp.zip
# Or build a DMG:
hdiutil create -volname MyApp -srcfolder /tmp/MyApp.app -ov -format UDZO /tmp/MyApp.dmg

# Step 2: Submit to Apple for notarization (uses stored credentials from setup)
xcrun notarytool submit /tmp/MyApp.zip \
  --keychain-profile "AC_PASSWORD" \
  --wait
# Output:
#   id: abcdef12-3456-7890-abcd-ef1234567890
#   status: Accepted (after a few minutes)

# Step 3: Check notarization history
xcrun notarytool history --keychain-profile "AC_PASSWORD" | head -10

# Step 4: Staple the notarization ticket to the binary (so offline machines can verify)
xcrun stapler staple /tmp/MyApp.app
xcrun stapler staple /tmp/MyApp.dmg

# Step 5: Verify
spctl --assess --type execute --verbose /tmp/MyApp.app
# source=Notarized Developer ID
xcrun stapler validate /tmp/MyApp.app

# ─── Notarization failures (debug) ───
xcrun notarytool log <submission-id> --keychain-profile "AC_PASSWORD"
# JSON log of why Apple rejected (e.g., unsigned nested binary, missing Hardened Runtime).
```

```bash
# ─── Bypassing Gatekeeper (NOT for production — historical CVEs) ───
# CVE-2021-1810: Gatekeeper bypass via file:// URL in Pages (patched macOS 11.3)
# CVE-2021-30995: Gatekeeper bypass via DMG (patched macOS 12.1)
# CVE-2022-42821: Gatekeeper bypass via "named fork" (patched macOS 13.1)

# Modern bypass (legitimate path): run from a non-quarantined location.
# Any binary extracted from a zip without the quarantine attr, or run by another
# binary that already has the necessary TCC grants, bypasses Gatekeeper.
# This is the Shlayer model: a notarized dropper fetches the actual payload
# at runtime, avoiding Gatekeeper check on the payload.

# Detect signed-and-notarized "conduit" binaries (red flag if unexpected):
# Scan /Applications for binaries signed by unknown Developer IDs:
for app in /Applications/*.app; do
  team_id=$(codesign -dvvv "$app" 2>&1 | grep "TeamIdentifier" | awk '{print $2}')
  [ -z "$team_id" ] && continue
  echo "$app $team_id"
done | sort -k2 | uniq -c -f1 | sort -rn | head -20

# ─── ldid (alternative signing for cross-platform / jailbreak-style code) ───
ldid -S/tmp/entitlements.plist /tmp/mybinary
# Equivalent to: codesign -s - --entitlements /tmp/entitlements.plist /tmp/mybinary
# Useful for binaries built outside Xcode.
```

---

## 12. Process & Memory Analysis

```bash
# ─── Process listing ───
ps -A -o pid,ppid,user,uid,%cpu,%mem,rss,vsz,start,time,command | head -30
# Sort by CPU:
ps -A -o pid,%cpu,command -r | head -10
# Sort by memory:
ps -A -o pid,rss,command -m | head -10

# Top (continuous)
top -o cpu -n 20 -s 5 -l 0    # -l 0 = infinite; -s 5 = sample every 5s

# Process ancestry (tree view)
ps -A -o pid,ppid,command | awk '$2==1 {print "ROOT: "$0}; $2>1 {print $0}' | head -50

# ─── File descriptors / open files ───
lsof -p <PID>
lsof -p $(pgrep Safari) | head -20
# Files open by user:
lsof -u <USER>
# Listening sockets:
lsof -i -P | grep LISTEN
# Network connections:
lsof -i -P | head -20

# ─── Memory map ───
vmmap <PID> | head -50
vmmap --summary <PID>            # one-line summary per region type

# Heap (requires developer tools)
leaks <PID> | head -20
heap <PID> | head -20

# ─── Strings of memory (live capture) ───
# Use lldb (debugger) to read process memory:
lldb -p <PID>
(lldb) process attach --pid <PID>
(lldb) memory read --size 4 --format x --count 32 0xADDRESS
(lldb) memory find -s "password" --string 0xSTART 0xEND
```

```bash
# ─── Dynamic tracing (dtrace) ───
# macOS ships DTrace (Sun-origin, ported). Requires SIP weakened or disabled for many probes.
# List available probes:
sudo dtrace -l | head -20
sudo dtrace -l | wc -l     # ~30k probes on a typical Mac

# Trace all exec:
sudo dtrace -n 'proc:::exec-success { trace(stringof(args[0]->fi_path)); }'

# Trace open() by Safari:
sudo dtrace -n 'syscall::open*:entry /pid == 1234/ { trace(copyinstr(arg0)); }'

# Note: AMFI blocks dtrace attachment to system binaries with SIP on.
# To trace Apple-signed processes, must disable SIP (test Mac only).

# ─── fs_usage (file system activity) ───
sudo fs_usage -w -f filesys | head -50
sudo fs_usage -w -f filesys | grep Safari

# ─── opensnoop (open() trace, simpler than dtrace) ───
sudo opensnoop | head -20
sudo opensnoop -n Safari | head -20

# ─── taskpolicy (process policy info) ───
taskpolicy -c                      # current process policy
taskpolicy -p <PID>                # info about a process
taskpolicy -B -p <PID>             # mark as background
```

```bash
# ─── lldb advanced (debugging) ───
lldb /tmp/mybinary
(lldb) b main
(lldb) run
(lldb) bt                          # backtrace
(lldb) frame variable              # local variables
(lldb) register read
(lldb) image list                  # loaded images (dylibs)
(lldb) image lookup -r -n "main"   # find symbol
(lldb) expr -- (int)printf("hi\n") # evaluate C expression

# Attach to running process (must have permission; SIP blocks attaching to system binaries)
sudo lldb -p $(pgrep -f mybinary)

# ─── sysdiagnose (full system snapshot — for forensic collection) ───
sudo sysdiagnose -f /tmp/sysdiagnose -A -v
# Produces a ~50MB tar.gz with: ps, lsof, spindump, top, network state, dmesg,
# the unified log tail, kextstat, system_profiler, and more.
# Useful for IR capture.
```

---

## 13. Network Analysis

```bash
# ─── Network interfaces ───
ifconfig
networksetup -listallhardwareports
networksetup -getinfo Wi-Fi

# Routing table
netstat -rn | head -20

# ARP cache
arp -a

# Listening sockets
lsof -i -P | grep LISTEN
netstat -an | grep LISTEN

# Established connections
lsof -i -P | grep ESTABLISHED
netstat -an | grep ESTABLISHED

# ─── Wi-Fi ───
airport -I                          # current network
airport -s                          # scan nearby networks
sudo airport -z                     # disassociate
sudo airport -cCHANNEL              # set channel
# Note: airport binary deprecated in macOS 15; use system_profiler SPNetworkLocationDataType

# ─── DNS ───
scutil --dns
sudo defaults read /Library/Preferences/com.apple.networkd

# ─── Network Extension (modern macOS app-level network filtering) ───
# Apps can register Network Extensions (content filter, packet tunnel, etc.)
neutil list
# Or via System Extensions:
systemextensionsctl list | grep -i network
# LuLu firewall uses Network Extension. So does Little Snitch, Lulu, Radio Silence.

# ─── Capture traffic ───
sudo tcpdump -i en0 -nn -X 'tcp port 80'
sudo tcpdump -i en0 -nn -A 'tcp port 443 and host example.com'

# Tshark (Wireshark CLI) — install via brew:
brew install wireshark
tshark -i en0 -Y 'http' -T fields -e http.host -e http.request.uri

# ─── Burp Suite / Charles Proxy ───
# Set system proxy:
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080
networksetup -setproxybypassdomains Wi-Fi '*.local' '169.254/16'
# Clear:
networksetup -setwebproxystate Wi-Fi off
networksetup -setsecurewebproxystate Wi-Fi off
```

```bash
# ─── Bluetooth ───
system_profiler SPBluetoothDataType
# Historical tools (mostly removed in modern macOS): Bluetooth Explorer.app (additional tools for Xcode)
# List paired devices:
defaults read /Library/Preferences/com.apple.Bluetooth
# System_profiler is the modern read path.

# ─── USB ───
system_profiler SPUSBDataType
ioreg -p IOUSB -l
# Insert a USB device that the OS recognizes as a keyboard (rubber-ducky style)
# Modern macOS may prompt "Allow keyboard to access?" via System Settings → Privacy & Security

# ─── AirDrop / AirPlay ───
# Discovery:
dns-sd -B _airdrop._tcp
dns-sd -B _airplay._tcp
dns-sd -B _googlecast._tcp
```

---

## 14. Persistence & Malware Analysis

```bash
# ─── All persistence locations (revisited — comprehensive scan) ───
echo "=== User LaunchAgents ==="; ls -l ~/Library/LaunchAgents/ 2>/dev/null
echo "=== System LaunchAgents ==="; ls -l /Library/LaunchAgents/ 2>/dev/null
echo "=== System LaunchDaemons ==="; ls -l /Library/LaunchDaemons/ 2>/dev/null
echo "=== Apple LaunchAgents ==="; ls -l /System/Library/LaunchAgents/ 2>/dev/null | head -10
echo "=== Login Items (BGTask) ==="; ls ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/ 2>/dev/null
echo "=== Login Items (LSSharedFileList) ==="; plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/BTMTasks.plist 2>/dev/null
echo "=== Spotlight Importers ==="; ls -l ~/Library/Spotlight/ /Library/Spotlight/ 2>/dev/null
echo "=== QuickLook Plugins ==="; ls -l ~/Library/QuickLook/ /Library/QuickLook/ 2>/dev/null
echo "=== Internet Plug-Ins (legacy) ==="; ls -l ~/Library/Internet\ Plug-Ins/ /Library/Internet\ Plug-Ins/ 2>/dev/null
echo "=== Audio Plugins ==="; ls ~/Library/Audio/Plug-Ins/Components/ 2>/dev/null
echo "=== Mail Bundles (legacy) ==="; ls ~/Library/Mail/Bundles/ 2>/dev/null
echo "=== Screensavers ==="; ls ~/Library/Screen\ Savers/ 2>/dev/null
echo "=== LoginHook ==="; defaults read /Library/Preferences/com.apple.loginwindow LoginHook 2>/dev/null
echo "=== LogoutHook ==="; defaults read /Library/Preferences/com.apple.loginwindow LogoutHook 2>/dev/null
echo "=== Cron (user) ==="; crontab -l 2>/dev/null
echo "=== Cron (system) ==="; cat /etc/crontab 2>/dev/null
echo "=== Periodic ==="; ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null
echo "=== Browser Extensions (Chrome) ==="; ls ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ 2>/dev/null
echo "=== Browser Extensions (Firefox) ==="; ls ~/Library/Application\ Support/Firefox/Profiles/*/extensions/ 2>/dev/null
echo "=== Browser Extensions (Safari) ==="; ls ~/Library/Safari/Extensions/ 2>/dev/null
echo "=== Kernel Extensions (legacy) ==="; ls /Library/Extensions/ 2>/dev/null
echo "=== System Extensions ==="; systemextensionsctl list 2>/dev/null
echo "=== Folder Actions ==="; ls ~/Library/Workflows/Applications/Folder\ Actions/ 2>/dev/null
```

```bash
# ─── Triaging a suspect Mach-O binary ───
# Step 1: Identify
file /tmp/suspicious_binary
shasum -a 256 /tmp/suspicious_binary
codesign -dvvv /tmp/suspicious_binary
codesign -d --entitlements - /tmp/suspicious_binary

# Step 2: Static
otool -L /tmp/suspicious_binary           # dependencies
otool -l /tmp/suspicious_binary | head -50  # load commands
nm -p /tmp/suspicious_binary | head -50    # symbols
strings /tmp/suspicious_binary | grep -iE "http|api|key|token|password|curl|wget|/bin/|/usr/" | head -50

# Step 3: Sandbox-trace behavior (sandbox-exec — limited but useful for quick test)
sandbox-exec -p '(version 1)(allow default)(deny network*)' /tmp/suspicious_binary
# Runs the binary with network denied. If it crashes / hangs / calls exit, it likely needs network.

# Step 4: Dynamic trace (test Mac only; SIP weakened for Apple-signed binaries)
sudo fs_usage -w -f filesys | grep suspicious_binary &
sudo opensnoop -n suspicious_binary &
sudo dtrace -n 'syscall:::entry /pid == 1234/ { @[probefunc] = count(); }' &
# Run the binary and observe.

# Step 5: Submit to VirusTotal (CAUTION: this shares the binary with vendors)
shasum -a 256 /tmp/suspicious_binary   # search VT by hash first
# curl -X GET "https://www.virustotal.com/api/v3/files/<hash>" -H "x-apikey: REPLACE_WITH_YOUR_VT_API_KEY"

# Step 6: Detonate in a VM (recommended)
# VMware Fusion / Parallels / UTM with macOS snapshot.
# Pre-snapshot. Run. Post-snapshot. Diff /Library/LaunchDaemons, ~/Library/LaunchAgents, etc.
```

```bash
# ─── Known macOS malware families — IOCs ───
# Shlayer (2018-present): notarized dropper, delivered via fake Flash updates.
#   - Drops a LaunchAgent at ~/Library/LaunchAgents/com.<random>.plist
#   - Fetches additional payload from a C2 over HTTPS.
#   - IOC: LaunchAgent with a random-looking Label in the user scope.
#
# Bundlore (2019-2023): adware/bundle installer, distributed via pirate software DMGs.
#   - Modifies Safari homepage, installs browser extensions.
#   - Persistence via ~/Library/LaunchAgents/com.<vendor>.<random>.plist.
#
# XCSpy / XCSSET (2020-2021): macOS malware via Excel macros, targets Safari cookies.
#   - Drops a LaunchAgent AND modifies Safari via osascript.
#   - Exfiltrates Cookies.binarycookies.
#   - IOC: LaunchAgent with osascript in ProgramArguments.
#
# Silver Sparrow (2021): first malware observed shipping an arm64 (Apple Silicon) payload.
#   - Persistence via ~/Library/LaunchAgents/init_agent.plist
#   - Distributed via AWS S3 + Akamai.
#   - IOC: init_agent.plist + ~/.agentbg or ~/.cargo_bg
#
# CoinMiner (various, ongoing): XMRig miner wrapped in a macOS binary.
#   - Drops ~/Library/LaunchAgents/com.<random>.miner.plist
#   - Connects to a mining pool over TCP 3333/14444.
#   - IOC: launch agent referencing an XMRig binary; high sustained CPU.
#
# NodeStealer (2023): steals cookies from Chrome / Firefox / Safari.
#   - Distributed as a fake Adobe Flash / OpenVPN installer.
#   - Exfiltrates cookies and passwords.
#   - IOC: launches a Node.js script that reads cookie DBs.

# ─── Quick YARA-style scan for known patterns ───
# Find LaunchAgents that reference osascript, curl, or a binary in /tmp/:
for f in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
  [ -f "$f" ] || continue
  grep -l -iE "osascript|curl|/tmp/|/var/tmp/" "$f" 2>/dev/null
done

# Find binaries in unusual locations (suspicious indicators):
find /Users/REPLACE_WITH_YOUR_USER -type f -perm +111 -not -path "*/.Trash/*" 2>/dev/null | \
  xargs -I{} sh -c 'echo "$(codesign -dv "{}" 2>&1 | grep Identifier || echo unsigned) {}"' 2>/dev/null | \
  grep -i "unsigned\|REPLACE_WITH_UNKNOWN_DEVID" | head -20
```

---

## 15. Apple Wireless / Bluetooth

```bash
# ─── Wi-Fi ───
# Scan for nearby networks
system_profiler SPAirPortDataType | head -30
# Old airport CLI (deprecated macOS 15):
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I

# Current BSSID and signal strength:
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | grep -E "ssid|bssid|agrCtlRSSI"

# Join a specific network (CLI)
networksetup -setairportnetwork en0 REPLACE_WITH_YOUR_SSID REPLACE_WITH_YOUR_PASSWORD

# ─── Bluetooth ───
system_profiler SPBluetoothDataType
# Paired devices:
defaults read /Library/Preferences/com.apple.Bluetooth 2>/dev/null | head -50

# ─── NFC ───
# macOS does not expose NFC reader via CLI (unlike iOS CoreNFC).
# Some Macs (2020+) have an NFC reader for Apple Pay only.

# ─── Bluetooth侦察 / sniffing (research) ───
# macOS does not support monitor mode on the built-in Bluetooth radio.
# Use an external USB BT adapter (e.g., ESP32 with HCI firmware) + Kismet on Linux.

# ─── Wireless Interface Card promiscuous mode ───
# Most Mac Wi-Fi cards (Broadcom) do NOT support monitor mode.
# Use an external USB adapter (Alfa AWUS036ACH or similar) + an external sniffer.
```

---

## 16. Defense Bypass — AMFI, Sandbox, Notarization

```bash
# ─── AMFI (Apple Mobile File Integrity) ───
# AMFI validates every process at exec() against:
#   1. The code signature (must be valid or ad-hoc with SIP-allowed flags)
#   2. The trust cache (a list of CDHashes Apple trusts)
#   3. The entitlements (must match what was signed)
# Failure: SIGKILL, "killed: 9", or EXC_BAD_ACCESS.

# Check whether a binary would be AMFI-approved:
codesign --verify --verbose /tmp/mybinary

# AMFI boot-args (developer machines only):
# sudo nvram boot-args="amfi_get_out_of_my_way=1"  # disables AMFI entirely
# sudo nvram boot-args="amfi_unrestricted_task_for_pid=1"  # allows lldb on system binaries
# (Both require SIP disabled. Not for production.)

# ─── Sandbox profiles ───
# Every Apple binary has a sandbox profile (Seatbelt / sandboxd).
# Inspect:
sandbox-exec -p '(dump (sandbox-cache))' /bin/ls 2>&1 | head -20

# Apply a custom sandbox:
sandbox-exec -f /tmp/my_profile.sb /tmp/mybinary
# Example sandbox profile (/tmp/my_profile.sb):
# (version 1)
# (allow default)
# (deny network*)
# (deny process-exec*)
# (allow process-exec (subpath "/bin/echo"))

# List built-in sandbox profiles:
ls /usr/share/sandbox/
# e.g., qtx.sandbox, SafariBinder.sb, SafariNetwork.sb

# ─── Sandbox escapes (research) ───
# Historical CVEs: CVE-2019-8805 (NFS), CVE-2020-3837 (crontab), CVE-2022-46650 (Mail)
# All patched; useful as case studies.

# ─── Notarization abuse ───
# Pattern: legitimate Developer ID + notarization ticket for a "dropper" binary.
# The dropper fetches the actual payload at runtime and runs it from a
# non-quarantined path (e.g., ~/Library/Application Support/MyApp/), bypassing
# Gatekeeper on the payload entirely.
# Detection (defender side):
#   - Alert on any LaunchAgent that references a binary in ~/Library/Application Support/
#   - Alert on binaries that call curl/wget with a URL containing known C2 patterns
#   - Alert on Developer IDs that have been reported as malicious (Apple revokes them;
#     check status via `spctl --assess` — revoked binaries will report "rejected").

# ─── TCC bypass via entitlement inheritance ───
# Modern macOS checks entitlements strictly. But signed-and-notarized binaries
# with `com.apple.security.cs.disable-library-validation` CAN load unsigned dylibs,
# which then inherit the parent's entitlements (TCC grants).
# This is the documented mechanism for plugins (e.g., Safari extensions, Spotlight importers).
# Red team use: deliver a notarized host binary + unsigned dylib that does the work.

# Detection:
codesign -d --entitlements - /Applications/SomeApp.app/Contents/MacOS/SomeApp | grep -i disable-library-validation
# Defenders: alert on Developer ID binaries with disable-library-validation that
# load dylibs from user-writable paths.
```

```bash
# ─── Defense evasion summary ───
# 1. Run from a non-quarantined path (no com.apple.quarantine xattr)
# 2. Avoid Gatekeeper check by being executed by an existing signed binary
# 3. Use legitimate signed-and-notarized code paths (osascript, Apple Events)
# 4. For persistence, prefer user-scope LaunchAgents over root daemons
# 5. Avoid kernel extensions (dead) and System Extensions (high detection)
# 6. Encrypt C2 traffic to look like normal HTTPS to a CDN
# 7. Minimize unified log footprint (don't prompt user for keychain access)

# ─── Anti-analysis ───
# Detect debugger:
#   if sysctl(KERN_PROC, ...) shows P_TRACED flag → debugger attached → exit.
# Detect VM:
#   system_profiler | grep "Model Name" → "Virtual Mac" or "VMware"
# Detect ESF:
#   launchctl list | grep -iE "falcon|sentinel|defender|jamf" → EDR present.
# Use:
sysctl kern.bootargs                # boot ROM debug args
sysctl -a | grep -i debug
ioreg -l | grep -iE "VirtualBox|VMware|Parallels"
```

---

## 17. Objective-See Tools Usage

```bash
# ─── KnockKnock (persistence scanner) ───
# GUI: open KnockKnock.app, click "Scan".
# CLI (less common):
# /Applications/KnockKnock.app/Contents/MacOS/KnockKnock -scan

# KnockKnock covers ~50 persistence locations and shows:
#   - Item name, path, signed/notarized status
#   - "Apple" (green), "Popular 3rd Party" (yellow), "Unknown" (red)

# Output is a JSON at:
cat ~/Library/Application\ Support/com.objectiveSee.KnockKnock/Results.json 2>/dev/null | jq '.[] | {name, path, signed}' | head -50

# ─── LuLu (firewall) ───
# Mode 1 (default): allow outgoing unless explicitly blocked
# Mode 2: block outgoing unless explicitly allowed (paranoid mode)
# Toggle via LuLu GUI or:
sudo defaults write /Library/Preferences/com.objective-see.lulu.plist mode -int 2
sudo launchctl kickstart -k system/com.objective-see.lulu.daemon

# Rules are at:
sudo defaults read /Library/Preferences/com.objective-see.lulu.rules

# ─── BlockBlock (persistence monitor) ───
# Background daemon that alerts when anything installs a LaunchAgent, login item, etc.
# GUI shows the alert; user approves / denies.
# No CLI; just keep it running.

# ─── OverSight (camera / mic monitor) ───
# Alerts when an app accesses the camera or microphone.
# Useful for red team awareness: if OverSight is running, you cannot silently activate the camera.

# ─── TaskExplorer (process explorer with VT lookup) ───
# GUI: open TaskExplorer.app.
# Per-process: code signing info, VT detections, open files, loaded dylibs.
# Right-click → "VirusTotal Lookup".

# ─── What's Your Sign? (code signing inspector) ───
# Finder extension: right-click any file → "What's Your Sign?" → shows
# code signing details (cert chain, Team ID, notarization).

# Or via CLI:
codesign -dvvv /Applications/SomeApp.app
codesign -d --entitlements - /Applications/SomeApp.app
spctl --assess --type execute --verbose /Applications/SomeApp.app
```

```bash
# ─── Equity (Gatekeeper / notarization GUI) ───
# Drag-drop any binary into Equity.
# Shows: signed / unsigned, Developer ID, Team ID, notarization status, bundle ID, entitlements.

# Or via CLI equivalent:
spctl --assess --verbose=4 /Applications/SomeApp.app
codesign -dv --verbose=4 /Applications/SomeApp.app
xcrun stapler validate /Applications/SomeApp.app
```

---

## 18. Quick Reference Cheat Sheet

```bash
# ─── One-shot host inventory ───
echo "===== macOS Host Recon ====="
sw_vers
uname -a
uname -m
csrutil status
fdesetup status
profiles list 2>/dev/null | head -5
launchctl list | wc -l
systemextensionsctl list 2>/dev/null
ps aux | grep -iE "falcon|sentinel|defender|jamf" | head -5
echo "===== Network ====="
ifconfig | grep inet
lsof -i -P | grep LISTEN
echo "===== Persistence ====="
ls ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null
echo "===== Users ====="
id
groups
dscl . list /Users UniqueID | head -10
```

```bash
# ─── Key macOS CLI commands by purpose ───
# Recon:
#   sw_vers, uname -m, system_profiler, ifconfig, networksetup
# Disk + firmware:
#   diskutil, csrutil, csrutil authenticated-root, mount, nvram
# Processes:
#   ps, launchctl, lsof, fs_usage, opensnoop, dtrace, lldb
# Code signing:
#   codesign -dvvv, codesign --verify, spctl --assess, xcrun stapler
# Notarization:
#   xcrun notarytool submit/wait/log/history, xcrun stapler
# Keychain:
#   security list-keychains, security dump-keychain -d, security find-generic-password
# TCC:
#   sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db, tccutil reset
# Persistence:
#   ls ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/
#   launchctl load/bootstrap/bootout, systemextensionsctl list, kextstat
# Mach-O:
#   file, otool -hv, otool -L, otool -l, nm, codesign -d, jtool2 -l
# Network:
#   lsof -i -P, netstat -rn, networksetup, sudo tcpdump
# Forensics:
#   log show --predicate, sysdiagnose, pmset -g log
# MDM:
#   profiles list/show/remove, /var/db/ConfigurationProfiles/
```

```bash
# ─── MITRE ATT&CK (macOS) — common techniques ───
# T1547.001   Registry Run Keys (Windows analog) → LaunchAgents/Daemons
# T1547.007   Netsh Helper (Windows analog)      → loginwindow hooks (legacy)
# T1547.011   Plist Modification                  → ~/Library/LaunchAgents/*.plist
# T1059.004   Unix Shell                          → zsh, bash, osascript
# T1059.002   AppleScript                         → osascript
# T1068       Exploitation for Priv Esc           → SIP/TCC/sandbox bypass
# T1555.001   Keychain                            → security CLI, chainbreaker
# T1555.003   Credentials from Web Browsers       → Cookies.binarycookies, History.db
# T1106       Native API                          → Mach APIs, EndpointSecurity.framework
# T1620       Reflective Code Loading             → DYLD_INSERT_LIBRARIES (where SIP allows)
# T1519       Embedded Hooks                      → AppleScript Folder Actions
# T1218.009   Signed Binary Proxy Execution       → notarized dropper pattern
# T1027.002   Software Packing                    → UPX on Mach-O
# T1055       Process Injection                   → dylib injection, mach injection
# T1564.001   Hidden Files and Directories        → chflags hidden (UF_HIDDEN)
# T1070.002   Clear Linux/Mac System Logs         → rm -rf /var/log/, log erase (requires root)
```

---

## Appendix: Test Environment Setup

For reproducible testing, set up isolated macOS environments:

- **VMware Fusion Pro 13+**: Free for personal use; full Apple Silicon support as of Fusion 13.
  - Create a VM from the macOS Restore IPA (`./ipsw` file from Apple's IPSW downloads).
  - Snapshot before each engagement for instant rollback.
- **Parallels Desktop**: Commercial; excellent performance on Apple Silicon.
- **UTM**: Free, open-source, supports both QEMU and Apple's native virtualization.
- **Bare-metal test Mac**: An old MacBook Air or Mac mini dedicated to testing.
  - Install fresh from Recovery, snapshot via `diskutil apfs createSnapshot`.
- **Apple Business Manager + free MDM**: For MDM-specific testing.
  - Jamf Now (free for 3 devices), Kandji free trial, or Microsoft Intune trial.

Run all destructive tests (TCC.db modification, LaunchDaemon installation, SIP disabling) in a VM snapshot, never on a production Mac.
