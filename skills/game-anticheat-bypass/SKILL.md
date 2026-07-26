---
name: game-anticheat-bypass
description: "Security research on game anti-cheat systems (EAC/BattlEye/Vanguard/Ricochet) — kernel-mode driver architecture, BYOVD attacks, memory access interception, integrity check evasion, and defense-side anti-cheat engineering."
origin: github-trending-2026
version: "0.2.0.2"
compatibility:
  - claude-code
  - agent-sdk
  - openclaw
allowed-tools:
  - Bash
  - Read
  - Edit
  - Write
  - Glob
  - Grep
  - WebSearch
  - WebFetch
metadata:
  domain: game-security
  category: game-security
  tool_count: 13
  guide_count: 1
  mitre: "TA0005-Defense Evasion, T1068-Exploitation for Privilege Escalation, T1547-Boot or Logon Autostart"
  keywords:
    - anti-cheat
    - eac
    - battleye
    - vanguard
    - byovd
    - kernel-driver
    - game-security
    - cheat-engine
    - scyllahide
    - reclass
  last_reviewed: "2026-07-26"
---

# Skill: Game Anti-Cheat Bypass (Security Research)

> **Supplementary Files**:
> - `payloads.md` -- Anti-cheat ecosystem reference, kernel-mode driver architecture, driver enumeration commands, BYOVD exploitation methodology, EAC/BattlEye/Vanguard internals, detection engineering patterns, and a quick-reference cheat sheet (18 sections, 60+ code blocks).
> - `test-cases.md` -- 12 structured test cases (TC-GA-001..012) covering driver enumeration, signed driver verification, BYOVD catalog scanning, capcom.sys analysis, Cheat Engine workflow, ScyllaHide profiling, memory R/W interception, minifilter enumeration, EAC/BattlEye/Vanguard architecture review, and detection engineering.

## Summary

Game anti-cheat bypass, positioned strictly as **security research and anti-cheat developer education**, covers the architecture of modern commercial anti-cheat systems (Easy Anti-Cheat, BattlEye, Riot Vanguard, Activision Ricochet, FACEIT AC), the kernel-mode driver model they rely on, and the offensive techniques studied in academic and red-team contexts to defeat them. The domain emphasizes understanding how detection works (signature, integrity, telemetry, behavioral) so defenders can harden their products and so researchers can responsibly disclose flaws through coordinated disclosure.

This is **not** a domain for deploying functional game cheats in production titles. All techniques are documented for lab/research environments using game-neutral test binaries, sample vulnerable drivers from the public LOLDrivers catalog, and academic references (s4dbrd.github.io, gmh5225/awesome-game-security, Microsoft BYOVD documentation, UnKnoWnCheaTs research threads). Research outputs feed back into anti-cheat engineering: signature rotation, telemetry correlation, hardware binding, and AI-driven detection.

**Tools**: WinDbg, Cheat Engine, ScyllaHide, ReClass.NET, HxD, API Monitor, Process Hacker, IDA Pro, Ghidra, PE-bear, Detect It Easy, PEview, awesome-game-security reference

**Domain**: game-security

**MITRE ATT&CK**: TA0005-Defense Evasion, T1068-Exploitation for Privilege Escalation, T1547-Boot or Logon Autostart

---

## Ethical Framing

### In Scope (this skill supports)

- **Academic / security research**: studying how anti-cheat drivers are structured, what kernel callbacks they register, and what telemetry they emit.
- **Anti-cheat developer insights**: reverse-engineering existing products to understand weak points so new anti-cheat features are harder to bypass.
- **Red team methodology**: applying BYOVD (Bring Your Own Vulnerable Driver) and memory R/W analysis in isolated labs to test detection coverage.
- **Educational case studies**: walking through public CVEs (capcom.sys CVE-2018-8120, dbutil CVE-2021-21551, GDRV.SYS CVE-2018-19320) as teaching examples.
- **Coordinated disclosure**: reporting anti-cheat flaws to vendors through responsible channels.

### Out of Scope (this skill does NOT support)

- Deploying functional cheats against **production** game servers or live matches.
- Distributing evasion tooling to players for use against live titles.
- Bypassing end-user license agreements (EULAs) or terms of service on production games.
- Generating account credentials, license keys, or working game-specific cheat binaries.
- Harassment of other players or circumvention of competition integrity (esports).

Every command, payload, and worked example in this skill is written for a **controlled research lab** (Windows VM with kernel debugging, test-signing enabled, isolated network, snapshots). If a technique cannot be reproduced in such an environment without violating a vendor's ToS, it is not included.

---

## Use Cases

1. **Anti-Cheat Architecture Review** -- Enumerate the components (user service, kernel driver, in-game module) of a target anti-cheat product and document the responsibilities of each.
2. **Kernel Driver Analysis** -- Use WinDbg and IDA Pro to identify kernel callbacks (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutine, minifilter callbacks) registered by an anti-cheat driver.
3. **BYOVD Vulnerability Research** -- Walk through the public LOLDrivers catalog, select a known vulnerable signed driver, and demonstrate kernel memory R/W in a lab VM for educational purposes.
4. **Detection Engineering (blue side)** -- Design detection signals that catch common bypass patterns (direct syscalls, manual mapping, hardware breakpoints) and document telemetry correlation rules.
5. **Integrity Check Testing** -- Study how anti-cheat products hash code sections, validate IATs, and enforce driver signature requirements, then test detection coverage in a lab.
6. **Memory Access Pattern Analysis** -- Observe how anti-cheat drivers respond to memory R/W attempts on protected processes and document the protection model.
7. **Anti-Cheat Telemetry Research** -- Map the telemetry pipeline (client driver → user service → backend behavioral analysis → hardware bans) and identify where detection signals are correlated server-side.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **WinDbg** | Kernel-mode debugging of anti-cheat drivers and live memory inspection | `!process 0 0` / `lm` / `!devobj` / `bp nt!MmCopyVirtualMemory` |
| **Cheat Engine** | Memory scanning (value, pointer, signature), structured memory class reconstruction, research-grade analysis of protected processes | Scan type: `Exact Value` / `Unknown initial value` then `Increased/decreased` |
| **ScyllaHide** | Anti-anti-debug toolkit that hides debugger artifacts (PEB BeingDebugged, NtGlobalFlag, heap flags, thread hide-from-debugger) during driver analysis | Apply the `VEH Extreme` profile before attaching a debugger |
| **ReClass.NET** | Reconstruct C++ class layouts from raw memory pointers (player entity, world state, network structures) | Bind pointer → add `PlayerEntity` class → add fields at offsets |
| **HxD** | Hex editor and disk editor for inspecting driver binaries, memory dumps, and saved game state | Open `.sys` file → search for `MZ`/`PE` headers / entropy analysis |
| **API Monitor** | Trace API calls (Nt* syscalls, kernel callbacks via user-mode reflection) and log parameters during anti-cheat interaction | Hook `Process and Thread` / `Memory management` categories on the game process |
| **Process Hacker** | Inspect handles, threads, memory regions, and kernel objects of protected processes; identify minifilter altitudes | `Handles` tab → filter by `\Device\` or `\Driver\` namespace |
| **awesome-game-security** | gmh5225's curated reference of anti-cheat research (EAC, BE, Vanguard, FACEIT) and reverse engineering notes | Browse the repo for vendor-specific research threads and CVEs |
| **IDA Pro** | Disassemble and decompile anti-cheat drivers; identify registered callbacks, IRP handlers, and crypto routines | Load `EasyAntiCheat.sys` → `Exports` tab → `Ctrl+F` for `DriverEntry` |
| **Ghidra** | Open-source disassembler/decompiler alternative to IDA; supports collaborative analysis of large drivers | `File` → `Import File` → `Analysis...` → `Auto Analyze` all options |
| **PE-bear** | Inspect PE headers, imports, exports, resources, and digital signatures of anti-cheat driver files | Drag `.sys` into PE-bear → `Imports` → identify `MmGetSystemRoutineAddress`, `IoCreateDevice` |
| **Detect It Easy (DIE)** | Identify packers, compilers, and obfuscators used by anti-cheat modules and loaders | DIE on `BEDaisy.sys` → entropy / signature scan |
| **PEview** | Lightweight PE structure viewer for quickly walking IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and section table | Open `.sys` → `IMAGE_NT_HEADERS` → `OptionalHeader` → check `ImageBase`, `Subsystem` |

---

## Methodology

### Research Pipeline

```
[1] Recon                 [2] Driver Analysis       [3] Memory Pattern Mapping
  - Enumerate services     - Load driver in IDA       - Identify protected
    (sc query)               / Ghidra / WinDbg           processes & handles
  - List loaded drivers    - Identify DriverEntry      - Trace ObRegisterCallbacks
    (lm, driverquery)        and IRP handlers            - Map minifilter callbacks
  - Verify signatures      - Catalog callbacks:        - Catalog protected
    (sigverif,              · ObRegisterCallbacks         memory regions
     Get-AuthenticodeSig)   · PsSetCreateProcess*
                            · minifilter PortMgr
       |                        |                        |
       v                        v                        v
[4] Detection Bypass      [5] Defense Recommendation
  - Test in lab VM          - Document weak points
  - BYOVD demonstration     - Propose signature
  - Direct syscall test       rotation, telemetry
  - Manual mapping test       correlation, HW bans
  - Hardware breakpoint      - AI-driven detection
    research                  guidance
```

**Phase Details**:

1. **Recon** -- Enumerate running services and drivers to map which anti-cheat product is active. Use `sc query`, `driverquery /si`, WinDbg `lm`, and `Get-AuthenticodeSig` to verify driver signatures and catalog file references. This phase answers "what is running, who signed it, where does it live."
2. **Driver Analysis** -- Load the target driver in IDA Pro or Ghidra and identify `DriverEntry`, IRP major function handlers, and kernel callbacks. Catalog which `ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx`, and minifilter callbacks are registered. This phase answers "what does the driver actually do in the kernel."
3. **Memory Pattern Mapping** -- In the lab VM, observe which processes are protected (open handle returns `STATUS_ACCESS_DENIED`), which memory regions are watched, and which minifilter altitudes are involved. This phase answers "what does the driver monitor at runtime."
4. **Detection Bypass Testing** -- Using public LOLDrivers samples and educational bypass techniques (direct syscalls, manual mapping, hardware breakpoints), measure how the anti-cheat reacts. All tests run in an isolated VM with no production game client or live match in scope.
5. **Defense Recommendation** -- Translate findings into detection engineering guidance for anti-cheat developers: rotate signatures, correlate telemetry across components, bind identity to hardware, and add AI/ML layers that flag behavioral anomalies even when client-side signals are spoofed.

### Defense Perspective

| Defense Measure | Description | Bypass Techniques Studied |
|-----------------|-------------|---------------------------|
| Signature enforcement (PatchGuard, driver signing) | Only WHQL-signed drivers may load in normal mode; CI checks catalog hashes | BYOVD (signed but vulnerable drivers), CVE-based primitives |
| Kernel callbacks (ObRegisterCallbacks, PsSet*) | Driver receives callbacks for handle open, process create, thread create | Direct syscalls, manual mapping, callback unregistration |
| Minifilter file system callbacks | Driver monitors file I/O on protected paths (game binaries, configuration) | Custom I/O completion, layered filter bypass |
| Integrity checks (code section hashing, IAT validation) | Periodic self-hash of `.text`, import address table validation, CRC of critical structs | Hardware breakpoint on hash routine, memory shadowing |
| Server-side behavioral analysis | Statistical models on player inputs (aim accuracy, reaction time, click cadence) | AI-driven detection that cannot be defeated client-side |
| Hardware ID binding | Disk serial, MAC, SMBIOS, TPM attestation used to bind accounts to devices | HWID spoofing research (educational only) |
| Telemetry correlation | Signals from driver + service + in-game module + server cross-checked | Multi-layer evasion research |

---

## Practical Steps

### Example 1: Enumerate Anti-Cheat Services and Drivers

```powershell
# List services related to common anti-cheat products
Get-Service | Where-Object { $_.Name -match 'EasyAntiCheat|BEService|BEDaisy|vgc|vgk|Ricochet|FACEIT' }

# List all loaded kernel drivers
driverquery /si | Select-String -Pattern 'Easy|Battle|Vanguard|vgk|FACEIT'

# In WinDbg (kernel mode), enumerate loaded drivers
lm t n
!for_each_module

# Verify signature on a driver file
Get-AuthenticodeSig -FilePath 'C:\Windows\System32\drivers\vgk.sys'
```

### Example 2: BYOVD Catalog Scan (Educational)

```powershell
# Pull the LOLDrivers catalog (public research dataset)
# Repo: https://github.com/magicsword-io/LOLDrivers
git clone https://github.com/magicsword-io/LOLDrivers.git C:\research\LOLDrivers

# Search the catalog for known vulnerable signed drivers
Get-ChildItem C:\research\LOLDrivers\drivers\*.json |
  Select-String -Pattern 'capcom|dbutil|gdrv|RTCore|procexp152' |
  Select-Object -First 10

# Verify a sample vulnerable driver is authenticode-signed (so it loads normally)
Get-AuthenticodeSig -FilePath 'C:\research\samples\RTCore64.sys'
```

### Example 3: Cheat Engine Memory Scan Methodology

```
Lab target: a research / training binary (NOT a production game client)

1. Attach Cheat Engine to the training binary.
2. First scan: Exact Value = <known starting value, e.g. 100 health>.
3. Change the value in-game (take damage to 87).
4. Next scan: Exact Value = 87 → narrows the candidate list.
5. Repeat until 1-4 addresses remain.
6. Right-click → "Find out what writes to this address" → attach debugger.
7. Pointer scan: right-click → "Pointer scan for this address" → set max level = 7.
8. Document the offset chain (e.g. "game.exe"+0x12345 +0x10 +0x4).
```

### Example 4: ScyllaHide Profile for Driver Analysis

```
When attaching WinDbg or x64dbg to an anti-cheat-protected research target:

1. Launch ScyllaHide x64 as Administrator.
2. Select profile: "VEH Extreme" (hooks via Vectored Exception Handler, hides more artifacts).
3. Start the research target.
4. Attach debugger; ScyllaHide auto-applies its profile on attach.
5. Verify PEB.BeingDebugged == 0 and NtGlobalFlag == 0 in the target's PEB.
6. Document which anti-debug checks the target performs before and after profile application.
```

---

## Differentiation

This domain is unique within the workspace:

- **Closest sibling**: `binary-reverse` -- covers general static/dynamic binary analysis. This skill is *specialized* for anti-cheat drivers, kernel callbacks, and the BYOVD threat model.
- **Adjacent**: `av-edr-evasion` -- covers AV/EDR evasion broadly. This skill applies similar kernel-mode concepts (direct syscalls, callback unregistration, hardware breakpoints) but in the game anti-cheat context with telemetry-heavy backend correlation.
- **Adjacent**: `kernel-exploitation` (if present) -- covers general kernel exploitation. This skill focuses on *signed* vulnerable drivers (BYOVD), not unsigned kernel exploits.
- **Adjacent**: `windows-internals` (if present) -- covers Windows kernel concepts. This skill applies those concepts to the specific vertical of game integrity protection.

No other skill in the workspace covers the anti-cheat ecosystem, BYOVD methodology, or detection engineering guidance specific to game security.

---

## Detection Methods

### Anti-Cheat Telemetry
- **Process anomalies**: Unknown process reading game memory (signature injection).
- **API hooking**: Game function prologue modified (signature of inline hooks).
- **Driver loaded**: Unauthorized kernel driver loaded (signature of BYOVD).
- **Network anomalies**: Game client connecting to non-game server (C2 signature).

### SIEM Detection Rules
- **EAC (Easy Anti-Cheat)**: Kernel-mode telemetry; signature + behavioral detection.
- **BattlEye**: Client-side + server-side validation.
- **Vanguard (Riot)**: Boot-time driver; deep system integrity check.
- **VAC (Valve)**: Server-side statistical detection.

## Defense Evasion Techniques

### User-Mode Stealth
- **Direct syscalls**: Bypass user-mode hooks (SysWhispers, HellsGate).
- **Hardware breakpoints**: Use DR0-DR3 for stealth hooks; not in process memory.
- **Process hollowing**: Inject into legitimate process; inherits anti-cheat whitelist.

### Kernel-Mode Stealth
- **BYOVD (Bring Your Own Vulnerable Driver)**: Load vulnerable signed driver (`RTCore64.sys`); gain kernel R/W.
- **DKOM (Direct Kernel Object Manipulation)**: Hide process from anti-cheat enumeration.
- **Callback removal**: Remove `PsSetCreateProcessNotifyRoutine` callbacks; blind anti-cheat.

### Network-Level Evasion
- **Local proxy**: Route game traffic through local proxy; manipulate packets client-side.
- **Man-in-the-middle**: MITM between client and server; modify game state.
- **Server-side emulation**: Use private server; full control of game state.

### Anti-Cheat Bypass Techniques
- **AMSI/ETW bypass**: Disable Windows telemetry before payload execution.
- **Sleep obfuscation**: Encrypt memory during sleep (Ekko, Foliage); evade memory scanners.
- **Module stomping**: Load legitimate DLL, overwrite with payload; appears as legitimate module.

## References

- gmh5225/awesome-game-security -- curated anti-cheat research index
- s4dbrd.github.io -- "How Kernel Anti-Cheats Work: A Deep Dive"
- magicsword-io/LOLDrivers -- Living Off The Land Drivers catalog
- Microsoft -- "Driver compatibility and blocking" / BYOVD documentation
- UnKnoWnCheaTs forum -- multi-game anti-cheat research threads
- Real CVEs referenced for teaching: CVE-2018-8120 (capcom.sys), CVE-2021-21551 (dbutil), CVE-2018-19320 (GDRV.SYS)
