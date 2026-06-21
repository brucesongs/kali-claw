# macOS Security Assessment Playbook — End-to-End Operational Guide

> Deep-dive companion to `skills/macos-security/SKILL.md`.
>
> Audience: red team operators, malware analysts, and security engineers who know what `csrutil` and `codesign` are, and want a battle-tested playbook for assessing macOS hosts — from system profiling through persistence installation, credential extraction, ESF-based defender instrumentation, and Apple Silicon-specific reasoning — without missing the architectural details that distinguish macOS from any other Unix.

---

## Introduction

macOS is the second-most-deployed enterprise laptop operating system in 2026 (after Windows), the default developer machine in most technology companies, and a frequent target of both red team engagements and real-world malware (Shlayer, Bundlore, XCSpy, Silver Sparrow, NodeStealer, CoinMiner). It is also a strange target: it is UNIX-flavored (so offensive techniques from Linux often port), but it is wrapped in a sophisticated proprietary security architecture (System Integrity Protection, Apple Mobile File Integrity, the Transparency Consent and Control privacy layer, the Endpoint Security framework, code signing + notarization, the Hardened Runtime, Secure Boot, and — on Apple Silicon — sealed APFS system snapshots, arm64e Pointer Authentication Codes, and the death of third-party kernel extensions). This playbook walks through the full operational chain: architecture primer, Apple Silicon specifics, test lab setup, red team methodology (recon → persistence → credential extraction → lateral → exfiltration), real-world macOS threat case studies, defense patterns, and references.

---

## 1. macOS Security Architecture

macOS security is layered. Each layer protects a specific trust boundary and produces telemetry that defenders (and attackers) can read.

### 1.1 System Integrity Protection (SIP / "rootless")

Introduced in OS X 10.11 El Capitan (2015), SIP restricts even the root user from modifying certain system locations:

- `/System`, `/usr`, `/bin`, `/sbin` — system binaries and resources.
- Pre-installed Apple apps at `/Applications/Safari.app`, `/Applications/Mail.app`, etc.
- The system TCC database at `/Library/Application Support/com.apple.TCC/TCC.db`.
- NVRAM variables (protected via a separate allow-list).
- Kernel extension loading (requires User-Approved MDM or boot-args).

Check status: `csrutil status`. On a production host this should report "enabled." SIP can be partially disabled for development (`csrutil enable --without fs --without debug`) but this is rarely seen in production. Full disable requires rebooting into Recovery Mode (`Cmd+R` Intel, hold power button Apple Silicon) and running `csrutil disable`.

SIP-bypass CVEs are the most-watched category of macOS security research. Notable historical examples: CVE-2019-8805 (NFS export), CVE-2020-3837 (crontab DAC), CVE-2020-9839 (FDisk TCC bypass), CVE-2023-32434 (Apple Silicon boot ROM memory corruption in image4 parser — partly hardware-fixed).

### 1.2 Transparency, Consent, and Control (TCC)

Introduced in OS X 10.14 Mojave (2018), TCC gates access to user-sensitive resources. Every app that wants to read user data — location, camera, microphone, contacts, calendars, reminders, photos, Mail, Messages, Safari history, the Desktop / Documents / Downloads folders, full disk access, accessibility control (for Apple Events), automation (AppleScript over another app), and screen recording — must request consent at first use.

Consent records live in two SQLite databases:

- User: `~/Library/Application Support/com.apple.TCC/TCC.db`
- System: `/Library/Application Support/com.apple.TCC/TCC.db` (requires root + SIP weakened to write)

Schema: `access(service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier_type, indirect_object_identifier, flags, last_modified)`. Key fields:

- `service` — the protected resource (e.g., `kTCCServiceSystemPolicyAllFiles` for Full Disk Access).
- `client` — the bundle ID (e.g., `com.apple.Safari`) or absolute path.
- `auth_value` — `0 = denied`, `2 = allowed`, `3 = limited`.
- `client_type` — `0 = bundle ID`, `1 = absolute path`.

The Apple-supported way to modify TCC.db without sqlite is `tccutil reset <service>` (reset only; cannot grant). Direct sqlite INSERT requires SIP weakened (because the database file is SIP-protected on the system path).

### 1.3 Apple Mobile File Integrity (AMFI)

AMFI is a kernel component that validates every process at `exec()` time. It checks:

1. **Code signature** — the binary must have a valid signature (Developer ID, ad-hoc, or Apple-trusted).
2. **Trust cache** — a kernel-resident list of CDHashes Apple trusts (for system binaries).
3. **Entitlements** — must match what was signed.
4. **Library validation** — dylibs loaded via `LC_LOAD_DYLIB` must be signed by the same Team ID as the main binary, unless the main binary has `com.apple.security.cs.disable-library-validation` entitlement (Hardened Runtime).

AMFI failure: `SIGKILL` ("killed: 9") or `EXC_BAD_ACCESS`. To disable AMFI for development: `sudo nvram boot-args="amfi_get_out_of_my_way=1"` (requires SIP disabled). Not for production.

### 1.4 Sandbox (seatbelt / sandboxd)

macOS applies a per-process sandbox (called "seatbelt", implemented by `sandboxd` and the kernel's TrustedBSD MAC policy modules). Every Apple binary ships with a sandbox profile that restricts its syscalls — Safari cannot write to `/etc`, Mail cannot read `/var/log`, etc.

Apple-shipped sandbox profiles are at `/usr/share/sandbox/` (e.g., `qtx.sandbox`, `SafariBinder.sb`). Third-party apps using App Sandbox are restricted to their container directory (`~/Library/Containers/<bundle-id>/`).

Custom sandboxes can be applied via `sandbox-exec -f profile.sb binary` (deprecated but functional). This is useful for detonating suspicious binaries with restricted permissions.

### 1.5 Endpoint Security framework (ESF)

Introduced in macOS 10.15 Catalina (2019) and hardened repeatedly since, ESF is the only supported API for monitoring process exec, file writes, disk I/O, mount/unmount, OpenDirectory lookups, and (on Monterey+) login/logout events. Apple requires commercial EDR vendors (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Jamf Protect, Cisco Secure Client, Kandji EDR) to subscribe to ESF.

ESF ships with a built-in CLI as of macOS 13 Ventura: `eslogger`. Common event types:

- `exec`, `exit` — process start / end.
- `open`, `write`, `close`, `rename`, `unlink` — file operations.
- `mount`, `unmount` — disk events.
- `authentication` — OpenDirectory auth events.
- `login_logout` — login session events.

A custom ESF client (e.g., for research) requires the `com.apple.developer.endpoint-security.client` entitlement, which Apple approves per-developer. For most red team / IR work, `eslogger` is sufficient.

The key insight: ESF is symmetric. The data commercial EDR sees is the same data an attacker with admin can see via `eslogger`. Assume your actions are visible.

### 1.6 Code Signing + Notarization + Gatekeeper

macOS 10.15 Catalina (2019) introduced mandatory notarization for downloaded apps. As of macOS 11 Big Sur, the default Gatekeeper posture is:

- Apps downloaded via browser / mail have the `com.apple.quarantine` extended attribute.
- When the user double-clicks a quarantined app, Gatekeeper checks:
  1. Is it signed by a Developer ID? (Notarized Developer ID, ideally.)
  2. Is the signature valid? (Hasn't been tampered with.)
  3. Is the notarization ticket valid? (Stapled or fetched live from Apple.)
- If any check fails: the user sees "App cannot be opened because Apple cannot check it for malicious software." The user must explicitly override via System Settings → Privacy & Security.

Bypasses:

- **Run from a non-quarantined path.** Extract the zip without the quarantine attr, or run from `/usr/local/bin/`. No Gatekeeper check.
- **Inherit from a parent.** A signed-and-notarized dropper binary executes the payload as a child; the child inherits no quarantine check.
- **Ad-hoc signing + developer tools.** Ad-hoc signed binaries (`codesign -s -`) execute fine for local development; Gatekeeper doesn't check non-quarantined paths.
- **Historical CVEs.** CVE-2021-1810 (Pages file:// URL bypass), CVE-2021-30995 (DMG bypass), CVE-2022-42821 (named fork bypass).

### 1.7 Secure Boot and FileVault

- **Secure Boot** (Intel T2 + Apple Silicon): verifies the chain from boot ROM → kernel → kernel extensions / System Extensions. Configurable in Recovery Mode (Full / Medium / Off). Apple Silicon adds `boot-policy-tool` for per-OS-policy control.
- **FileVault** (FDE): AES-XTS disk encryption with the key escrowed to the user's password (and to iCloud / MDM for recovery). Check status with `fdesetup status`. Without FileVault, all on-disk secrets (Keychain, Cookies.binarycookies, History.db, Messages) are readable by anyone with physical access.
- **Personal Recovery Key (PRK)**: a 28-character code shown at FileVault setup. Should be escrowed to MDM.

### 1.8 Hardened Runtime

A code-signing option (`--options runtime` to `codesign`) that opts the binary into additional kernel-level protections:

- **W^X memory** — pages cannot be both writable and executable.
- **Library validation** — dylibs must be signed by the same Team ID (unless `disable-library-validation` entitlement).
- **Debugger restrictions** — `task_for_pid` requires `get-task-allow` entitlement.
- **JIT restrictions** — requires `allow-jit` entitlement.

All in-house binaries built for distribution should use Hardened Runtime. Notarization requires it.

### 1.9 XProtect and MRT (Malware Removal Tool)

- **XProtect**: Apple's signature-based malware scanner. Runs at file quarantine time and daily in the background. Signatures pushed silently via `update_dyld_shared_cache`. Check status via `systemextensionsctl list | grep XProtect`.
- **MRT**: removes known malware after detection. Runs as a LaunchDaemon (`com.apple.mrt`).
- **Both are signature-based** — they catch well-known families (Shlayer, Bundlore) but not novel or low-prevalence malware. A determined attacker who can buy a new Developer ID can stay ahead.

---

## 2. Apple Silicon Specifics

Apple Silicon (M1, 2020; M2, 2022; M3, 2023; M4, 2024) fundamentally changed macOS. Five architectural shifts matter for offensive work:

### 2.1 arm64e and Pointer Authentication Codes (PAC)

Apple Silicon's userland is `arm64`; the kernel and system binaries use `arm64e`, which adds **Pointer Authentication Codes** (ARM v8.3). Every function pointer and return address is cryptographically signed with a key derived from the pointer value, the calling context, and a per-process key.

Result: classic return-oriented-programming (ROP) and jump-oriented-programming (JOP) chains that overwrite return addresses on the stack fail. Each `ret` becomes `retab` (return with authentication); if the signature doesn't match, the CPU traps.

Bypasses (research territory): pointer substitution (find a signed pointer to a similar function), side-channel attacks (BLRAA timing), PPL/JOP via signing gadgets. In practice, most red team operators **do not** bypass PAC directly; they use legitimate signed-and-notarized code execution (Apple Events, `osascript`, entitlement inheritance) instead of memory-corruption exploitation.

Detect: `sysctl -n hw.optional.arm64e` should be `1` on M1+. Disassemble with `jtool2 -d` or Hopper and look for `pacia`, `pacib`, `autia`, `autib`, `retaa`, `retab`, `braa`, `blraa` instructions.

### 2.2 Sealed System Snapshot (SSV)

Apple Silicon (and Intel T2) boot from a sealed APFS snapshot of the System volume. The boot process verifies the snapshot's cryptographic seal against a value stored in the boot ROM (and re-verified at each kernel extension load). If the seal doesn't match, the Mac refuses to boot.

This means the entire `/System`, `/usr`, `/bin`, `/sbin`, and pre-installed Apple apps are **read-only at the hardware level**, even with SIP disabled. To modify them you must `csrutil authenticated-root disable` (which defeats the seal), reboot, make changes, and re-seal.

Check: `mount | grep "on / "` — should show `apfs,sealed,local,read-only`. `csrutil authenticated-root status` — should report "enabled."

### 2.3 System Volume vs Data Volume (firmlinks)

macOS 11+ splits the disk into two APFS volumes:

- **System volume** (`/System/Volumes/SSV` mounted at `/`): sealed, read-only, contains OS files.
- **Data volume** (`/System/Volumes/Data` mounted via firmlinks at `/Users`, `/Library`, `/Applications`, etc.): read-write, contains user data.

The two volumes are joined into a single tree via **firmlinks** — symbolic links at the kernel level that map a System path to a Data path. The firmlink configuration is at `/usr/share/firmlinks` (Apple-controlled). Each line pairs a System path with a Data path (e.g., `/etc /private/etc`, `/Users /System/Volumes/Data/Users`).

### 2.4 Kernel Extensions are Dead; System Extensions are the Future

On Apple Silicon, third-party kernel extensions (`kext`s) are effectively dead. Apple requires vendors to migrate to:

- **System Extensions** — user-land daemons that subscribe to the Endpoint Security framework (for security tools), Network Extension framework (for VPNs / firewalls), or DriverKit (for hardware drivers).
- **DriverKit** — a user-land driver framework for specific device classes.

Enumerate: `systemextensionsctl list`. System Extensions require a Developer ID with the appropriate entitlement; they cannot be installed ad-hoc.

For red team operators, this means:

- Persistence via kext is no longer viable (was rare anyway).
- Persistence via System Extension is theoretically possible but requires a Developer ID and triggers a user consent prompt — high detection.
- Stick to LaunchAgents / LaunchDaemons / login items / browser extensions.

### 2.5 Rosetta 2 (x86_64 emulation)

Apple Silicon includes Rosetta 2 to translate x86_64 binaries to arm64 at runtime. Detection: `pgrep oahd`. Translated processes show `i386` in `ps -A -o arch`.

Historical bug: CVE-2021-30717 — Rosetta-translated binaries bypassed code signing checks because the translated arm64 binary had no signature at all. Patched in macOS 11.4. Ensure macOS version >= 11.4 on any host under assessment.

### 2.6 T2 Chip (Intel Macs, 2018-2020)

The T2 chip is the predecessor of Apple Silicon's integrated secure enclave. It controls: Secure Boot, the SMC, the camera (with a hardware kill switch), audio DSP, SSD encryption (hardware AES-XTS), Touch Bar, and Touch ID.

T2 runs its own OS (bridgeOS). Historically, T2 was exploitable via `checkm8` (CVE-2019-8900 family — USB DFU exploit allowing bridgeOS downgrade). Apple addressed this in later hardware revisions.

Check for T2: `system_profiler SPiBridgeDataType` (shows Model Identifier like `bridgeOS-18.16.14631.0.0,0`).

### 2.7 Implications for Red Team

1. **Memory corruption exploitation is harder** — PAC frustrates ROP/JOP. Most operators use signed-and-notarized code execution instead of exploitation.
2. **Persistence is user-land only** — kexts are dead; System Extensions are loud. Use LaunchAgents / LaunchDaemons / login items.
3. **TCC bypass requires entitlement abuse** — DYLD insertion is mostly blocked; abuse Apple-signed binaries with `disable-library-validation` or use Apple Events / Automation grants.
4. **AMFI is strict** — every binary must be signed or ad-hoc signed. Unsigned binaries are killed at exec.
5. **Boot ROM bugs are unpatchable in software** — historical CVEs (CVE-2023-32434, CVE-2023-41990) may remain exploitable on older hardware revisions.

---

## 3. Building a macOS Test Lab

For active exploitation and malware detonation, use a dedicated test environment.

### 3.1 Bare-Metal Test Mac

Best for fidelity (real hardware, real Secure Boot, real Apple Silicon):

- A used Mac mini M1 (2020) — ~$500 as of 2026, excellent for testing.
- Or a used MacBook Air M1.
- Install fresh from Recovery (`Cmd+R` Intel, hold power button Apple Silicon).
- Before each test cycle, snapshot the System volume:
  ```bash
  sudo diskutil apfs createSnapshot / "test-$(date +%Y%m%d)"
  ```
  Or use Time Machine for a full-system rollback.

### 3.2 VMware Fusion Pro

VMware Fusion 13+ (free for personal use since May 2023) supports Apple Silicon VMs:

- Download a macOS Restore IPSW from Apple (`ipsw` file).
- Create a VM from the IPSW via `xcrun simctl create` or Fusion's GUI.
- Snapshot before each test.
- Note: Apple Silicon VMs can only run macOS 12+ (Monterey, Ventura, Sonoma, Sequoia).
- Intel-on-Apple-Silicon VMs (Windows, Linux) require Rosetta or HVF.

### 3.3 Parallels Desktop

Commercial; excellent performance on Apple Silicon. Supports both macOS and Linux / Windows VMs. Snapshot support built in.

### 3.4 UTM

Free, open-source, supports both QEMU (slow, cross-architecture) and Apple's native hypervisor (fast, same-architecture). Good for ad-hoc testing.

### 3.5 Apple Business Manager + MDM Trial

For MDM-specific testing:

- **Jamf Now**: free for up to 3 devices.
- **Kandji / Addigy / Mosyle**: free trials (typically 14-30 days).
- **Microsoft Intune trial**: requires Azure AD / Entra ID tenant.
- **Apple Business Manager** (ABM): free with a D-U-N-S number; enables DEP (auto-enrollment) and supervised mode.

### 3.6 Snapshot Workflow

For any of the above environments:

1. **Pre-snapshot**: install macOS, run software update, set up user account, snapshot.
2. **Test**: install persistence, dump keychain, modify TCC.db, etc.
3. **Roll back**: restore the pre-snapshot state.

On bare metal:
```bash
# Take a snapshot
sudo diskutil apfs createSnapshot / "before-test"
# List snapshots
diskutil apfs listSnapshots /
# Roll back (reboot into Recovery, then):
diskutil apfs deleteSnapshot / -name before-test
```

---

## 4. Red Team Methodology

### 4.1 Phase 1 — Recon & Foothold

Establish what the target Mac is and how you're on it.

```bash
sw_vers
uname -m
system_profiler SPHardwareDataType
csrutil status
csrutil authenticated-root status
fdesetup status
profiles list -output user
sudo profiles list
id; groups
ps aux | grep -iE "falcon|sentinel|defender|jamf"
launchctl list | grep -iE "falcon|sentinel|defender|jamf"
systemextensionsctl list
```

Establish your foothold context (per engagement scope): existing user shell, delivered payload, browser exploit, MDM enrollment abuse, etc.

### 4.2 Phase 2 — Privilege & TCC Posture

Determine what your current context can and cannot do.

```bash
# What TCC grants does the current user have?
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value FROM access WHERE auth_value = 2 ORDER BY service;"

# Look for high-impact grants you can inherit (via Apple Events / automation):
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service = 'kTCCServiceAppleEvents' AND auth_value = 2;"

# Find entitlement-rich binaries you can abuse:
codesign -d --entitlements - /Applications/Xcode.app 2>&1 | grep -i disable-library-validation
codesign -d --entitlements - /Applications/Safari.app 2>&1 | grep -i disable-library-validation

# Is SIP weakened? (If yes, TCC bypass via direct sqlite write becomes possible)
sudo touch /System/test 2>&1
```

If Full Disk Access is granted to Terminal/iTerm2 (common for power users), the foothold has full read access to user data.

### 4.3 Phase 3 — Persistence

Install persistence in user-scope (lowest detection) first, escalate to system-scope only if needed.

```bash
# User LaunchAgent
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.example.helper.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.helper</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/REPLACE_WITH_YOUR_USER/.local/bin/helper</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>/tmp/helper.err</string>
</dict>
</plist>
EOF

# Make the helper executable
chmod +x /Users/REPLACE_WITH_YOUR_USER/.local/bin/helper
# Ad-hoc sign (avoid Gatekeeper issues)
codesign -s - --force --options runtime /Users/REPLACE_WITH_YOUR_USER/.local/bin/helper

# Load it now (without reboot)
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.helper.plist
launchctl print gui/$(id -u)/com.example.helper | head -20
```

For broader coverage, also install: a Spotlight importer (`~/Library/Spotlight/`), a QuickLook plugin (`~/Library/QuickLook/`), a browser extension (`~/Library/Application Support/Google/Chrome/Default/Extensions/`), or a login item (via `osascript -e 'tell application "System Events" to make login item ...'`).

### 4.4 Phase 4 — Credential Extraction

```bash
# Keychain dump
security dump-keychain -d ~/Library/Keychains/login.keychain-db > /tmp/kc.txt
grep -c "password:" /tmp/kc.txt

# Wi-Fi PSK
security find-generic-password -ga "REPLACE_WITH_YOUR_SSID" -d ~/Library/Keychains/login.keychain-db -w

# Safari cookies
cookie-reader ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies > /tmp/cookies.txt

# Safari history
sqlite3 ~/Library/Safari/History.db \
  "SELECT url, datetime(visit_time + 978307200, 'unixepoch', 'localtime') FROM history_items JOIN history_visits ON history_items.id = history_visits.history_item ORDER BY visit_time DESC LIMIT 50;"

# Messages
sqlite3 ~/Library/Messages/chat.db \
  "SELECT datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime'), text FROM message ORDER BY date DESC LIMIT 50;"

# Notes.app (NoteStore.sqlite — body is zipped protobuf; use a community parser)
ls ~/Library/Group\ Containers/group.com.apple.notes/
```

### 4.5 Phase 5 — Lateral Movement (Limited on macOS)

macOS is less of a lateral-movement target than Windows:

- **No SMB shares by default** — sharing must be enabled.
- **No remote registry / WMI analog** — `launchd` is local only.
- **SSH** — if enabled, can pivot via SSH to other Macs.
- **Apple Remote Desktop** — if enabled, can drive other Macs via VNC.
- **Back to My Mac / iCloud** — deprecated for remote access; replaced by Universal Control and Sidecar.

Lateral movement via cloud identity is more common: steal cookies for `*.okta.com` / `login.microsoftonline.com`, pivot to corporate SaaS.

### 4.6 Phase 6 — Exfiltration

macOS routes outbound HTTPS via the standard BSD socket layer. Commercial EDR (Falcon, SentinelOne, Defender for Endpoint) monitors outbound connections via ESF. Defenses:

- **Encrypt** — TLS to a CDN (Cloudflare Workers, AWS CloudFront). Looks like normal web traffic.
- **Chunk** — split exfil into small chunks to avoid bandwidth anomaly detection.
- **DNS exfil** — possible but loud (most EDR alerts on DNS exfil patterns).
- **Steganography** — embed exfil in images uploaded to a public service (Imgur, S3 bucket).

### 4.7 Phase 7 — Defense Evasion

- **Run from non-quarantined paths.** Avoid `com.apple.quarantine` xattr.
- **Use signed-and-notarized conduit binaries.** A legitimate Developer ID is $99 from Apple.
- **Avoid kernel extensions.** They're dead anyway.
- **Prefer LaunchAgents over LaunchDaemons** (user-scope, less noisy).
- **Minimize keychain prompts.** `security dump-keychain -d` prompts repeatedly; defenders see this.
- **Operate via AppleScript / Automation.** If you have an Automation grant over Safari/Finder, drive those apps instead of doing work yourself.
- **Avoid SIP disable.** It's loud (visible in `csrutil status`), persistent, and requires reboot. Almost everything you need can be done with SIP enabled.

### 4.8 Phase 8 — Detection Footprint & Cleanup

Every action leaves traces in:

- **Unified log** (`log show --predicate 'subsystem == "com.apple.securityd"'`) — TCC grants, AMFI failures, exec events.
- **Bash history** (`~/.zsh_history`) — every command.
- **Filesystem atime / mtime** — when files were touched.
- **Spotlight index** (`mdfind`) — content of all indexed files.
- **FSEvents** (`/.fseventsd`) — every file system event.
- **Keychain access log** (per-item) — when each item was read.
- **ESF / EDR logs** — exec, file, network events.

Cleanup (post-engagement):

- Remove all installed LaunchAgents / Daemons.
- Remove any installed browser extensions / Spotlight importers.
- Restore TCC.db (if modified).
- Clear bash history (`history -c && rm ~/.zsh_history`).
- Optionally clear unified log (requires root + SIP weakened — usually not worth the noise).

---

## 5. Real-World macOS Threats

### 5.1 Shlayer (2018-present)

The dominant macOS malware family of the late 2010s. Delivered via fake "Flash Player update" pop-ups on legitimate-but-compromised websites. The dropper is signed (initially with a legitimate Developer ID, later with stolen / fraudulent IDs) and notarized. It fetches additional payloads from a C2 over HTTPS.

Persistence: `~/Library/LaunchAgents/com.<random>.plist`. Impact: adware, additional payload installation.

Detection: LaunchAgent with a random-looking Label; outbound HTTPS to non-CDN IPs.

### 5.2 Bundlore (2019-2023)

Adware / bundle installer distributed via pirate software DMGs. Modifies Safari homepage, installs browser extensions, displays pop-up ads.

Persistence: `~/Library/LaunchAgents/com.<vendor>.<random>.plist`. Impact: adware.

Detection: Changes to Safari homepage preferences; unexpected browser extensions.

### 5.3 XCSpy / XCSSET (2020-2021)

Macros embedded in Excel spreadsheets. Used `osascript` to drive Safari, exfiltrate Cookies.binarycookies, and modify Safari preferences to enable "develop" menu.

Persistence: LaunchAgent with `osascript` in ProgramArguments. Impact: cookie / credential theft; in some variants, ransomware-style file encryption.

Detection: LaunchAgent referencing osascript; unexpected osascript executions in ESF logs.

### 5.4 Silver Sparrow (2021)

The first widely-observed macOS malware to ship an arm64 (Apple Silicon) payload alongside x86_64. Distributed via AWS S3 and Akamai. The malware itself was relatively benign (no observed second-stage payload), but the cross-architecture distribution was significant.

Persistence: `~/Library/LaunchAgents/init_agent.plist` plus `~/.cargo_bg` or `~/.agentbg`. Impact: adware / dropper; second stage never observed.

Detection: LaunchAgent named `init_agent.plist`; binary at `~/.cargo_bg` or `~/.agentbg`.

### 5.5 CoinMiner (various, ongoing)

XMRig cryptocurrency miner wrapped in a macOS binary. Distributed via pirated software, fake Adobe Flash updates, and malicious npm packages.

Persistence: `~/Library/LaunchAgents/com.<random>.miner.plist`. Connects to a mining pool over TCP 3333 or 14444. Impact: high sustained CPU, fan noise, shortened battery life.

Detection: LaunchAgent referencing an XMRig binary; sustained high CPU; outbound TCP to known mining pools.

### 5.6 NodeStealer (2023)

Steals cookies from Chrome, Firefox, and Safari. Distributed as a fake Adobe Flash installer or OpenVPN installer. Exfiltrates cookies and saved passwords via Telegram bots (C2).

Persistence: drops a Node.js script + LaunchAgent. Impact: cookie / password theft, account takeover.

Detection: Node.js process reading browser cookie DBs; outbound HTTPS to Telegram API.

### 5.7 MacStealer / Atomic (2023-2024)

Sold-as-service macOS infostealer. Extracts Keychain, Cookies.binarycookies, browser passwords, crypto wallets (Electrum, Exodus, MetaMask extension), and Telegram. Distributed via phishing pages.

Persistence: typically none (one-shot exfil). Impact: full credential and wallet theft.

Detection: high-rate reads of browser SQLite DBs and Keychain via `security` CLI.

---

## 6. Defense Patterns

### 6.1 Apple Platform Security Guide

Apple publishes the [Platform Security Guide](https://support.apple.com/guide/security/welcome/web) (200+ pages, updated with each major macOS release). It is the authoritative reference for the security architecture. Required reading for any macOS defender.

Key sections:

- Secure Boot chain.
- System Integrity Protection.
- FileVault.
- Code signing and notarization.
- Endpoint Security framework.
- Apple Silicon specifics (PAC, sealed snapshot, etc.).

### 6.2 ESF-Based EDR

Apple does not ship a macOS-native EDR. Third-party is required, and it must use ESF. Commercial options:

- **CrowdStrike Falcon** — industry leader; ESF subscriber; broad detection.
- **Microsoft Defender for Endpoint** — included with Microsoft 365 E5; ESF subscriber.
- **SentinelOne** — ESF subscriber; good behavior-based detection.
- **Jamf Protect** — built specifically for Jamf-managed Macs; ESF subscriber; integrates with Jamf Pro MDM.
- **Cisco Secure Client (formerly AMP for Endpoints)** — ESF subscriber.

Choose based on existing stack (Defender if Microsoft shop; Jamf Protect if Jamf shop; Falcon otherwise).

### 6.3 mSCP (macOS Security Compliance Project)

NIST + Apple collaboration: a baseline of macOS security settings, expressed as a YAML config and enforced via configuration profiles. Available at [github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security).

Use mSCP to:

- Generate a security-hardened baseline configuration profile.
- Audit an existing Mac against the baseline (`python3 bin/mSCP.py -s baseline/macos_15_1.yaml`).
- Document compliance for auditors (FedRAMP, NIST 800-53, CIS).

### 6.4 MDM Hardening

Jamf, Kandji, Intune, Addigy, Mosyle — all support enforcing macOS hardening via MDM:

- **Restrict System Extensions** to allow-listed Team IDs.
- **Enforce Gatekeeper** (no user override).
- **Enforce FileVault** + escrow PRK to MDM.
- **Block Safari extensions** except allow-listed.
- **Block unsigned apps** (via `spctl --enable` policy).
- **Require software updates** within N days.
- **Disable SSH, Screen Sharing, Remote Apple Events** unless explicitly needed.
- **Restrict Spotlight** indexing of sensitive directories.

### 6.5 TCC.db Audit

Quarterly review of both TCC databases:

- Alert on any new Full Disk Access grant to a non-Apple binary.
- Alert on any Accessibility grant to a non-Apple binary.
- Alert on any Automation (Apple Events) grant.
- Audit via `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db`.

### 6.6 Notarization Enforcement

- All in-house binaries built for distribution should be Developer ID signed + notarized + Hardened Runtime.
- Use `notarytool` (replaces the deprecated `altool`) for submission.
- Staple tickets via `xcrun stapler staple`.
- Audit third-party binaries via `spctl --assess` and `codesign -dvvv`.

### 6.7 Unified Log Forwarding

Forward macOS unified logs to a SIEM (Splunk, Elastic, Sentinel):

```bash
# Stream security-relevant subsystems
sudo log stream --predicate 'subsystem == "com.apple.securityd" OR
  subsystem == "com.apple.TCC" OR
  subsystem == "com.apple.mdm"' --style syslog
```

Pipe to a forwarder (`filebeat`, `splunkforwarder`, `nxlog`). Alert on:

- New LaunchAgent / LaunchDaemon installation.
- TCC.db modification.
- `csrutil disable` (visible in NVRAM / unified log).
- `security dump-keychain -d` (per-item access prompts).
- ESF-reported file writes to `~/Library/LaunchAgents/`.
- Outbound connections to known-bad domains.

### 6.8 User Education

- Don't install apps from outside the App Store unless from a known vendor.
- Don't override Gatekeeper warnings ("Open Anyway") unless certain.
- Don't enter the keychain password for unexplained prompts.
- Don't grant Full Disk Access to unfamiliar apps.
- Keep software updated.

---

## 7. References

### 7.1 Apple Documentation

- **Apple Platform Security Guide**: [support.apple.com/guide/security/welcome/web](https://support.apple.com/guide/security/welcome/web) — the authoritative reference. Updated with each major macOS release.
- **Endpoint Security Framework**: [developer.apple.com/documentation/endpointsecurity](https://developer.apple.com/documentation/endpointsecurity) — Apple's developer documentation for ESF.
- **Hardened Runtime**: [developer.apple.com/documentation/security/hardened_runtime](https://developer.apple.com/documentation/security/hardened_runtime) — entitlements reference.
- **Code Signing Guide**: [developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide) — code signing and entitlements.
- **Notarizing macOS Software Before Distribution**: [developer.apple.com/documentation/security/notarizing_macos_software_before_distribution](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution) — notarytool workflow.
- **System Extensions**: [developer.apple.com/system-extensions](https://developer.apple.com/system-extensions) — System Extension and DriverKit documentation.

### 7.2 mSCP (macOS Security Compliance Project)

- [github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security) — NIST + Apple baseline configuration.
- Documentation: [apple.github.io/federation-core/mSCP.html](https://apple.github.io/federation-core/mSCP.html)

### 7.3 Objective-See

- Tools: [objective-see.org/products.html](https://objective-see.org/products.html) — KnockKnock, LuLu, BlockBlock, OverSight, TaskExplorer, What's Your Sign?, and others (all free).
- Blog: [objective-see.org/blog.html](https://objective-see.org/blog.html) — Patrick Wardle's macOS security research (the de facto reference for macOS malware analysis).
- Talks: [objective-see.org/downloads.html](https://objective-see.org/downloads.html) — DEF CON, Black Hat, OBTS, MacDevOps talks by Patrick Wardle and others.
- Books: *"The Art of Mac Malware: The Guide to Analyzing Malicious Software"* (Patrick Wardle, 2022, free online at [taomm.org](https://taomm.org)) — the canonical macOS malware analysis textbook.

### 7.4 Community Resources

- **drduh/macOS-Security-and-Privacy-Guide** (20k+ stars): [github.com/drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide) — community hardening guide.
- **MITRE ATT&CK for macOS**: [attack.mitre.org/matrices/enterprise/macos](https://attack.mitre.org/matrices/enterprise/macos) — full matrix of techniques mapped to macOS.
- **sindresorhus/Equity**: [github.com/sindresorhus/Equity](https://github.com/sindresorhus/Equity) — Gatekeeper / notarization GUI inspector.
- **jtool2** (Elias Limneos): [newosxbook.com/tools/jtool.html](http://www.newosxbook.com/tools/jtool.html) — Mach-O Swiss-army knife.
- **machOView**: [github.com/gdbinit/machOView](https://github.com/gdbinit/machOView) — GUI Mach-O browser.
- **ldid**: [github.com/saurik/ldid](https://github.com/saurik/ldid) — alternative signing tool with entitlements.
- **coreSigma ESF pipeline (Nebulock)**: community research on building production ESF pipelines.

### 7.5 Conferences and Talks

- **DEF CON**: Patrick Wardle's annual macOS talks (e.g., "The Cost of Insecurity", "Death by 1000 Installers", "Bypassing Bounds Checker").
- **Black Hat USA**: macOS-specific research talks (Wardle, Beer, Levin).
- **Objective by the Sea (OBTS)**: the premier macOS security conference, hosted by Patrick Wardle in Hawaii / Europe / Japan. Recordings on YouTube.
- **MacDevOps YVR**: macOS-focused ops and security conference in Vancouver. Recordings on YouTube.

### 7.6 CVE References

- **CVE-2019-8805** — SIP bypass via NFS export configuration (macOS 10.15.0).
- **CVE-2020-3837** — crontab DAC override SIP bypass (macOS 10.15.4).
- **CVE-2021-30717** — Rosetta 2 code-signing bypass (macOS 11.4).
- **CVE-2021-1810** — Gatekeeper bypass via file:// URL in Pages (macOS 11.3).
- **CVE-2022-42821** — Gatekeeper bypass via "named fork" (macOS 13.1).
- **CVE-2023-32434** — Apple Silicon boot ROM memory corruption in image4 parser (partly HW-fixed).
- **CVE-2023-38606** — Memory Read/Write primitive via GPU (M-series).
- **CVE-2023-41990** — NErd interrupt (M-series boot ROM).

### 7.7 Research Blogs

- **Patrick Wardle's blog** ([objective-see.org/blog.html](https://objective-see.org/blog.html)) — the single most authoritative source for macOS malware and security research.
- **Microsoft Defender for Endpoint research blog** ([microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog)) — frequently covers macOS malware (XCSSET, NodeStealer, MacStealer).
- **Jamf Threat Labs** ([jamf.com/blog](https://www.jamf.com/blog/)) — research on macOS malware in enterprise.
- **ESET WeLiveSecurity** ([welivesecurity.com](https://www.welivesecurity.com)) — covers macOS malware (CloudMensis, etc.).
- **SentinelOne Labs** ([sentinelone.com/labs](https://www.sentinelone.com/labs/)) — macOS malware research.

### 7.8 Internal References

- **This skill's supplementary files**: `SKILL.md`, `payloads.md`, `test-cases.md`.
- **Cross-referenced skills**: `mobile-security` (iOS/Android — shares code-signing concepts but different attack surface), `binary-reverse` (platform-agnostic RE), `av-edr-evasion` (Windows-centric EDR bypass — the macOS analog is in this skill), `digital-forensics` (broad forensic artifacts — macOS-specific artifacts are here), `anti-forensics` (broad cleanup — macOS-specific cleanup is here), `post-exploitation` (general post-exploitation — macOS persistence is here).
