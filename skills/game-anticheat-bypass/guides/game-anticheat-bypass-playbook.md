# Game Anti-Cheat Bypass Playbook (Security Research)

> A deep-dive operational guide for researchers studying game anti-cheat systems (EAC, BattlEye, Vanguard, Ricochet, FACEIT). Covers kernel-mode driver architecture, BYOVD methodology, telemetry research, and defense-side engineering. **Strictly for security research and anti-cheat developer education.** Do not apply these techniques against production game clients or live matches.

## Introduction

This playbook is written for security researchers, anti-cheat engineers, and red team operators studying the integrity-protection stack used by modern competitive games. Every technique is framed for an **isolated research lab** running game-neutral training targets, public LOLDrivers samples, and academic references. It is explicitly **not** a guide for deploying functional game cheats: production cheats violate game terms of service, harm competition integrity, and frequently cross legal lines (DMCA anti-circumvention, CFAA, computer-misuse statutes in multiple jurisdictions).

The value of this research is twofold. First, it produces detection engineering guidance for anti-cheat developers (blue side). Second, it produces documented, responsibly-disclosed flaws that raise the floor of the entire ecosystem. Every researcher using this playbook is expected to follow coordinated disclosure when an anti-cheat flaw is discovered, and to refuse requests to build or distribute tooling intended for production cheating.

Throughout the playbook, expect references to public, peer-reviewed sources: gmh5225/awesome-game-security, s4dbrd.github.io's "How Kernel Anti-Cheats Work: A Deep Dive", the magicsword-io/LOLDrivers catalog, Microsoft's BYOVD documentation, and UnKnoWnCheaTs research threads.

---

## 1. Anti-Cheat Architecture Refresher

Modern commercial anti-cheat products share a three-component design. Understanding the division of labor between these components is the foundation for any serious research.

### Component 1: User-Mode Service

```
Service (e.g. EasyAntiCheat_launcher.exe, BEService.exe, vgc.exe)
  - Runs as a Windows service (often with high privileges)
  - Handles: update, heartbeat to backend, license check, launcher integration
  - Communicates with the kernel driver via IOCTLs and shared memory sections
  - Communicates with the game backend via TLS
```

The service is the bridge between the kernel and the network. It cannot see raw kernel activity itself, but the driver hands it pre-processed telemetry that the service then ships to the backend.

### Component 2: Kernel-Mode Driver

```
Driver (e.g. EasyAntiCheat.sys, BEDaisy.sys, vgk.sys)
  - Registered callbacks:
      · ObRegisterCallbacks (pre/post op on handle open / duplicate)
      · PsSetCreateProcessNotifyRoutineEx (process creation)
      · PsSetLoadImageNotifyRoutine (module load)
      · Minifilter callbacks (file I/O on protected paths)
  - Performs: memory protection on the game process,
              code-section integrity checks,
              telemetry collection,
              anti-tamper on itself
  - Exports: none (callbacks only); speaks IOCTLs with the service
```

The driver is where the real protection lives. It runs at IRQL `PASSIVE_LEVEL` or `APC_LEVEL` for most of its logic, registers callbacks at driver load time, and uses `MmGetSystemRoutineAddress` to locate undocumented kernel APIs.

### Component 3: In-Game Module

```
In-game module (DLL injected by the launcher)
  - Loaded into the game process address space
  - Performs: anti-debug, heap integrity, code integrity (CRC of .text),
              capture of behavioral signals (input timing, view matrix),
              reports to the driver via a shared section
  - Often obfuscated (VM-based bytecode, control-flow flattening)
```

The in-game module is the most accessible component to a researcher because it lives in the same address space as the game, but it is also the most heavily obfuscated.

### Telemetry Pipeline

```
Game process (in-game module)
    │
    │  shared memory section / IOCTL
    ▼
Kernel driver (BEDaisy.sys / vgk.sys / EasyAntiCheat.sys)
    │
    │  IOCTL + shared section
    ▼
User-mode service (BEService / vgc / EasyAntiCheat_launcher)
    │
    │  TLS
    ▼
Backend (behavioral analysis, hardware ban list, signature distribution)
```

The pipeline is layered. A single client-side signal rarely triggers a ban; instead the backend correlates multiple weak signals over time. This is why defeating the client alone is insufficient --- the backend will still flag anomalous behavior even if every client-side signal is spoofed.

### Why Anti-Cheat Moved to the Kernel

User-mode anti-cheat was defeated comprehensively in the 2010s by kernel-level cheat tools that could simply overwrite the in-game module's memory from outside the game process. The only defense against a kernel attacker is a kernel defender, which is why every major competitive title now ships a kernel-mode anti-cheat driver. The trade-off is significant: a kernel driver has full system access, runs at all times (Vanguard is boot-start), and a bug in the driver can crash the entire OS (BSOD) or open a local privilege escalation hole for any attacker.

---

## 2. Building a Research Lab

A safe research lab is the single most important asset in this domain. Without isolation, research becomes liability.

### Hardware / Host Requirements

- A dedicated research workstation, ideally not your daily driver.
- CPU with VT-x / AMD-V support and EPT (for Hyper-V nested virt).
- Minimum 32 GB RAM (the VM needs 8-16 GB).
- A separate physical disk for the VM (avoids corrupting host data if a kernel bug fires).
- A network adapter that can be physically disabled or moved to an isolated VLAN.

### VM Configuration

```
Hypervisor:        Hyper-V (preferred), VMware Workstation, or VirtualBox
Guest OS:          Windows 10 22H2 or Windows 11 (matches production anti-cheat support)
RAM:               8192 MB minimum
Disk:              120 GB dynamically expanding, on a dedicated physical disk
Network:           "Internal" / "Host-only" switch --- NO default-switch internet access
Snapshot:          Take a "clean install + tools" snapshot before any experimentation
Display:           Enhanced session / VMware Tools installed for clipboard / file transfer
```

### Enabling Test-Signing and Kernel Debugging

```powershell
# Enable test-signing (so you can load unsigned research drivers if needed)
bcdedit /set testsigning on

# Enable kernel debugging over named pipe (VMware) or net (Hyper-V)
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Reboot for changes to take effect
shutdown /r /t 0
```

After reboot, the desktop shows a "Test Mode" watermark in the corner. This is expected and **required** for loading your own research drivers.

### Host-Side Kernel Debugger

```
Install WinDbg (Classic or Preview) on the host.
Configure symbol path:
  _NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
Attach to the VM via the named pipe configured above (\\.\pipe\com_1).
Break into the debugger with Ctrl+Break when the VM is running.
```

### Lab Software Inventory

| Tool | Install Path | Purpose |
|------|--------------|---------|
| WinDbg Preview | `C:\Program Files\WinDbg\` | Kernel debugging, `!process`, `!devobj`, `!fltkd` |
| Cheat Engine | `C:\CE\` | Memory scanning research |
| ScyllaHide | `C:\ScyllaHide\` | Anti-anti-debug |
| ReClass.NET | `C:\ReClass\` | Class reconstruction |
| x64dbg | `C:\x64dbg\` | User-mode debugging |
| HxD | `C:\HxD\` | Hex editor |
| Process Hacker 2 | `C:\ProcessHacker\` | Live object inspection |
| PE-bear | `C:\PE-bear\` | PE / signature inspection |
| Detect It Easy | `C:\DIE\` | Packer / compiler ID |
| PEview | `C:\PEview\` | Quick PE walk |
| IDA Pro / Ghidra | host-side | Static analysis (large binaries) |

### Snapshot Discipline

```
Snapshot 1:  Clean Windows install + all updates
Snapshot 2:  + Test-signing + kernel debug enabled
Snapshot 3:  + Lab tools installed (the working baseline)
Snapshot 4:  + Target anti-cheat product installed (per product)

Before every experimentation session:
  - Revert to Snapshot 3 or 4
  - Confirm no host network path is reachable
  - Confirm kernel debugger is attached and responsive
```

If anything goes wrong (suspected infection, anti-cheat ban-wave risk, kernel panic), revert to the snapshot and investigate offline.

---

## 3. BYOVD Methodology

BYOVD (Bring Your Own Vulnerable Driver) is the dominant technique studied in anti-cheat research because it abuses the fact that **WHQL-signed drivers load normally** on production Windows. An attacker (or researcher) drops a known-vulnerable but legitimately-signed driver onto the system, loads it via normal `NtLoadDriver` / `sc start`, and then exploits the driver's vulnerability to gain kernel read/write primitives.

### Step 1: Catalog Selection

```powershell
# Pull the LOLDrivers catalog (magicsword-io)
git clone https://github.com/magicsword-io/LOLDrivers.git C:\research\LOLDrivers

# Enumerate entries with arbitrary-write primitives
Get-ChildItem C:\research\LOLDrivers\drivers\*.json |
  ForEach-Object { $_ | Select-Object -ExpandProperty FullName } |
  Select-String -Pattern 'MmMapIoSpace\|arbitrary.*write\|arbitrary.*r/w' -SimpleMatch:$false

# Cross-reference CVE list
# Educational shortlist (each is a textbook case):
#   capcom.sys        CVE-2018-8120   arbitrary kernel code execution via IOCTL
#   dbutil_2_3.sys    CVE-2021-21551  arbitrary kernel R/W via IOCTL
#   gdrv.sys          CVE-2018-19320  arbitrary kernel R/W + physical memory map
#   RTCore64.sys      CVE-2019-16098  arbitrary R/W via MSR + memory
#   MsIo64.sys        various         physical memory read via IOCTL
```

### Step 2: Signature Verification

```powershell
# Verify the sample is still WHQL-signed (so it loads normally)
Get-AuthenticodeSig -FilePath C:\research\samples\RTCore64.sys

# Expected:
#   Status        : Valid
#   Signer        : "Micro-Star International Co., Ltd."
#   TimeStamper   : (valid timestamp CA)
```

If the signature has been revoked or the driver added to the Microsoft vulnerable driver blocklist, the sample may not load on a fully-patched system. For research, disable the blocklist temporarily:

```powershell
# Registry path for the blocklist policy (research VM only!)
HKLM\SYSTEM\CurrentControlSet\Control\CI\Config
VulnerableDriverBlocklistEnable = 0 (DWORD)

# Reboot required; re-enable immediately after the experiment.
```

### Step 3: Load the Driver

```powershell
# Create and start a service for the sample driver
sc.exe create RTCore type= kernel binPath= "C:\research\samples\RTCore64.sys"
sc.exe start RTCore

# Verify the driver loaded
driverquery /si | Select-String 'RTCore'

# In WinDbg
lm m RTCore*
```

### Step 4: Build the Exploit Primitive

Educational pattern (conceptual only, not a working exploit):

```c
// Conceptual R/W primitive via IOCTL (NOT a working exploit)
// The exact IOCTL code and buffer layout depend on the target driver.

HANDLE hDevice = CreateFileW(
    L"\\\\.\\RTCore",
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    0,
    NULL);

// Read primitive: driver takes (target_va, &out_buffer)
// Write primitive: driver takes (target_va, value)

// Use the primitive to:
//   1. Locate the EPROCESS of the protected process
//   2. Strip its protection bits (zero the PsProtectedSigner / debug flags)
//   3. Or: read/modify the anti-cheat driver's in-memory state

CloseHandle(hDevice);
```

### Step 5: Anti-Cheat Bypass Demonstration (Lab Only)

In the lab, with a research target (NOT a production game), demonstrate:

1. Before BYOVD: `OpenProcess` on the protected PID returns `STATUS_ACCESS_DENIED` (anti-cheat callback blocks it).
2. Load the vulnerable driver.
3. Use the kernel R/W primitive to walk `PsActiveProcessHead`, locate the target `EPROCESS`, and zero the `ProcessSignature` / `Protection` fields.
4. After: `OpenProcess` succeeds; `ReadProcessMemory` / `WriteProcessMemory` succeed.

Document the full call chain in WinDbg with breakpoints on `nt!MmCopyVirtualMemory`, `nt!NtOpenProcess`, and the anti-cheat's `PreOperation` callback. This documentation is the **research output**.

### Step 6: Mitigation Notes

```
Defense against BYOVD (for anti-cheat developers):
  1. Subscribe to the Microsoft vulnerable driver blocklist; enforce WDAC policy.
  2. Hash-block known-bad driver samples (capcom.sys, dbutil_2_3.sys, ...).
  3. Monitor for service creation with kernel binPath from untrusted callers.
  4. Register a PsSetLoadImageNotifyRoutine callback to flag known-bad drivers
     the moment they load into the kernel.
  5. Server-side: if a known-bad driver hash is observed in the client's
     loaded module list, ban the hardware ID and revoke the account.
```

---

## 4. Anti-Cheat Telemetry Research

Client-side signals are only the first layer. The harder problem --- and the more interesting research target --- is the server-side behavioral analysis layer.

### Server-Side Signals

Modern backends correlate signals that are **impossible to fake client-side** because they describe the player's behavior over time:

| Signal | Why It Matters |
|--------|----------------|
| Aim accuracy distribution | A human's hit-rate over time has a specific shape; an aimbot produces a sharp spike in headshot percentage with abnormally low variance. |
| Reaction time distribution | Legitimate reaction times follow a log-normal distribution centered around 200-300ms; trigger bots produce sub-50ms reactions consistently. |
| Mouse movement cadence | Human aim has micro-correction jitter; aim-assisted movement is too smooth. FFT of mouse delta shows distinct frequency peaks. |
| Click timing | Auto-clickers produce metronome-regular clicks; humans have natural jitter. |
| Crosshair placement | Wallhacks produce statistically anomalous crosshair placement toward enemies through walls. |
| Movement patterns | Speed hacks, fly hacks, and teleport detection are purely server-side (position deltas validated). |

### Hardware ID Binding

```
HWID composite (collected client-side, hashed, sent to backend):
  - Disk serial (SMART / WMI Win32_DiskDrive)
  - MAC address (primary NIC)
  - SMBIOS / motherboard serial (Win32_BaseBoard)
  - CPU ID (CPUID instruction)
  - TPM EK certificate hash (TPM 2.0 attestation)
  - GPU serial (where exposed via DXGI)

Backend:
  - Store HWID hash per account.
  - On ban, blacklist the HWID hash.
  - On new login from same HWID but different account, flag for review.
```

HWID spoofing research is a separate subdomain; the takeaway for defenders is that **no single hardware identifier is reliable**, but the *composite* hash is hard to spoof without leaving traces (e.g. TPM attestation proves the boot chain integrity).

### Why Multi-Layer Detection Matters

```
Layer 1 (client driver):      blocks the easy attacks (memory R/W on game PID)
Layer 2 (in-game module):     detects injected modules, anti-debug triggers
Layer 3 (service / launcher): validates heartbeat, scans known-bad driver list
Layer 4 (backend behavioral): catches aim/wall/reaction-time anomalies
Layer 5 (backend statistical): ML model on long-term player behavior
Layer 6 (hardware binding):   survives account re-creation

An attacker who defeats layers 1-3 still gets caught by 4-6.
An attacker who defeats all 6 layers has, in effect, become indistinguishable
from a top-tier human player --- at which point the competitive impact is
bounded by human skill ceilings.
```

---

## 5. Defense Recommendations

For anti-cheat developers and platform engineers, this section consolidates the defense-side takeaways from the research.

### Signature Rotation

- Rotate the in-game module's code layout every N days. The attacker's static pointer tables break on every rotation.
- Rotate the kernel driver's IOCTL codes and shared-section names per build. Even if the driver's binary is leaked, the IOCTL interface is unstable.
- Re-hash the driver's `.text` section at runtime and compare against a signed expected hash stored in the service. Detect tampering.

### Telemetry Correlation

- Define a `two-of-three` rule: an event must fire in at least two of {kernel driver, in-game module, backend} to escalate to a ban. This defeats single-layer evasion.
- Maintain a server-side ledger of every client-reported event; cross-check the ledger against observed behavior. A client that reports "no anomalies" while backend statistics show anomalies is itself a signal.

### Hardware Binding

- Bind account identity to a TPM-attested hardware composite. Require re-verification on hardware change.
- Persist ban state in TPM NV storage (where supported) so the ban survives disk wipes.
- Cross-reference new accounts against HWIDs of known-banned accounts; require manual review for matches.

### AI-Driven Detection

- Train models on per-player behavioral features: aim delta FFT, reaction time histogram, click cadence entropy.
- Run inference both client-side (low-latency, low-coverage) and server-side (high-latency, high-coverage).
- Ship models with the in-game module but keep the **decision threshold** server-side; this forces attackers to defeat the model AND evade threshold checks.

### Driver Hygiene (for the anti-cheat developer)

- Treat your own kernel driver as a primary attack surface. Fuzz it relentlessly.
- Enforce `PGlobalFlags` and `PoolTag` discipline so memory corruption is detectable.
- Ship with HVCI (Hypervisor-Protected Code Integrity) compatibility; HVCI blocks unsigned kernel code execution even when your driver has a bug.
- Coordinate with Microsoft to add your known-bad driver hashes to the blocklist (mutual defense).

### Coordinated Disclosure

```
When a researcher discovers a flaw in an anti-cheat product:
  1. Do NOT publish immediately.
  2. Locate the vendor's security contact (usually security@<vendor>, a
     bug bounty program, or a dedicated disclosure portal).
  3. Provide a written report with reproduction steps in an isolated lab
     (no production client involved).
  4. Allow 90 days for remediation (industry standard).
  5. Coordinate publication after the fix ships.
  6. Do NOT publish full exploit code; publish only the conceptual write-up.
```

---

## 6. Legal & Ethical Considerations

This playbook is explicitly scoped to **security research and anti-cheat developer education**. The following lines must not be crossed.

### In Scope

- Studying how anti-cheat drivers are structured and what they protect.
- Reproducing public BYOVD CVEs in an isolated lab for learning.
- Publishing conceptual write-ups of detection mechanisms.
- Reporting anti-cheat flaws via coordinated disclosure.
- Contributing detection engineering guidance to the open anti-cheat research community (awesome-game-security, UnKnoWnCheaTs research subforums).

### Out of Scope

- Deploying functional cheats against production game servers or live matches.
- Distributing evasion tooling to players for use in live titles.
- Bypassing EULAs or ToS on production games.
- Reverse-engineering anti-cheat for the purpose of selling cheat subscriptions.
- Doxxing anti-cheat developers or competitive players.

### Legal Frameworks (Awareness Only, Not Legal Advice)

- **DMCA Section 1201 (anti-circumvention)** in the US may apply to reverse-engineering technical protection measures, even for research. Researchers should consult the DMCA exemptions (e.g. security testing exemption) and seek legal counsel before publishing.
- **Computer Fraud and Abuse Act (CFAA)** and analogous computer-misuse statutes in the UK, Germany, and Australia may apply to unauthorized access, even on a multiplayer service.
- **EU Directive 2009/24/EC** on the legal protection of computer programs recognizes interoperability and security research carve-outs in some jurisdictions.
- **End User License Agreements** are contractually binding; violating them can result in account termination and civil suits even when no criminal statute applies.

This playbook does **not** constitute legal advice. Researchers must obtain their own counsel before any activity that might fall outside clearly-protected research carve-outs.

### Ethical Commitment

```
As a researcher using this playbook:
  - I work only in an isolated lab, never against production clients.
  - I respect the terms of service of every game I do not own.
  - I report flaws via coordinated disclosure before publishing.
  - I refuse requests to build or distribute tooling for active cheating.
  - I cite the public research community and contribute back.
```

---

## 7. References

- **gmh5225/awesome-game-security** -- curated index of anti-cheat research covering EAC, BattlEye, Vanguard, FACEIT, and ESEA. The single best entry point.
- **s4dbrd.github.io** -- "How Kernel Anti-Cheats Work: A Deep Dive", a long-form technical primer on the three-component architecture.
- **magicsword-io/LOLDrivers** -- Living Off The Land Drivers catalog; the canonical reference for BYOVD research.
- **Microsoft Learn** -- "Driver compatibility and blocking", "HVCI", "WDAC policy", and the Microsoft Vulnerable Driver Blocklist documentation.
- **UnKnoWnCheaTs forum** -- multi-game anti-cheat research subforums; the largest community research index. Use the search function before asking.
- **Real CVEs (for teaching)**:
  - CVE-2018-8120 (capcom.sys)
  - CVE-2021-21551 (dbutil_2_3.sys)
  - CVE-2018-19320 (GDRV.SYS)
  - CVE-2019-16098 (RTCore64.sys)
- **WinDbg Documentation** -- `!process`, `!devobj`, `!fltkd`, `!peb`, `!handle`, `bp`, `ba`, `!for_each_module`.
- **IDA Pro / Ghidra Documentation** -- for static analysis of kernel drivers.
- **Cheat Engine Forum** -- memory scanning methodology and pointer scanning tutorials.
- **ScyllaHide Repository** -- anti-anti-debug profile documentation.
