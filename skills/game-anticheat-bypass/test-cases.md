# Game Anti-Cheat Bypass Test Cases

> Structured test cases covering anti-cheat driver enumeration, signed driver verification, BYOVD catalog analysis, kernel callback identification, EAC/BattlEye/Vanguard architecture review, and detection engineering. Each test case is reproducible in an isolated research lab and includes clear pass/fail criteria.

---

## Statistics

| Category | Count | Difficulty Range |
|----------|-------|------------------|
| A. Driver Enumeration & Signature | 2 | Beginner - Intermediate |
| B. BYOVD Research | 2 | Intermediate |
| C. Memory & Anti-Debug Tooling | 3 | Intermediate |
| D. Anti-Cheat Architecture Review | 3 | Intermediate - Advanced |
| E. Detection Engineering | 2 | Advanced |
| **Total** | **12** | **Beginner - Advanced** |

---

## A. Driver Enumeration & Signature

### TC-GA-001: Anti-Cheat Driver Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-GA-001 |
| **Title** | Enumerate anti-cheat services and loaded kernel drivers |
| **Objective** | Map which anti-cheat product is active on a research VM and identify the kernel driver(s) it loads |
| **Steps** | 1. Run `Get-Service \| Where-Object { $_.Name -match 'EasyAntiCheat\|BEService\|BEDaisy\|vgc\|vgk\|FACEIT' }` and record matches.<br>2. Run `driverquery /si` and grep for `Easy\|Battle\|Vanguard\|vgk\|FACEIT` to find loaded kernel drivers with signatures.<br>3. Open WinDbg in local kernel mode and run `lm t n` to enumerate all loaded modules; filter for the anti-cheat driver.<br>4. For each identified driver, record `ImagePath` via `sc qc <service>` and `Get-ItemProperty` on the file.<br>5. Cross-reference the driver list against the gmh5225/awesome-game-security vendor list to confirm the product family. |
| **Expected Result** | At least one anti-cheat service and its corresponding kernel driver are identified; the driver path, signer, and service start type are documented; the product family (EAC, BattlEye, Vanguard, Ricochet, FACEIT) is confirmed. |
| **Tools** | PowerShell, driverquery, WinDbg, awesome-game-security reference |
| **MITRE** | T1082 - System Information Discovery, T1068 - Exploitation for Privilege Escalation |
| **Difficulty** | Beginner |
| **Tags** | recon, driver, enumeration, kernel |

### TC-GA-002: Signed Driver Verification

| Field | Value |
|------|-----|
| **ID** | TC-GA-002 |
| **Title** | Verify Authenticode signature and catalog on an anti-cheat driver |
| **Objective** | Confirm that a target anti-cheat driver is properly WHQL-signed and validate its catalog chain |
| **Steps** | 1. Locate the driver file (e.g. `C:\Windows\System32\drivers\vgk.sys`) from TC-GA-001 output.<br>2. Run `Get-AuthenticodeSig -FilePath <driver.sys>` and record `Status`, `SignerCertificate.Subject`, and `TimeStamperCertificate`.<br>3. Open the driver in PE-bear and inspect the `Security Directory` (WIN_CERTIFICATE) entry; record the catalog file GUID.<br>4. Use `Get-AuthenticodeSig -FilePath <driver.sys> -VerifyCat` (Windows 10 21H2+) or `sigverif /v` to confirm catalog-based signing.<br>5. Cross-check the signer subject against the vendor's known CA (e.g. "Riot Games, Inc.", "Bungie, Inc.", "BattlEye Innovations") in the awesome-game-security reference. |
| **Expected Result** | `Get-AuthenticodeSig` returns `Valid`; signer matches the expected vendor entity; the catalog GUID resolves to an OS-trusted `.cat` file; PE-bear shows a non-empty Security Directory. |
| **Tools** | PowerShell, PE-bear, sigverif |
| **MITRE** | T1082 - System Information Discovery, T1027 - Obfuscated Files or Information |
| **Difficulty** | Beginner |
| **Tags** | signature, authenticode, catalog, driver |

---

## B. BYOVD Research

### TC-GA-003: BYOVD Vulnerable Driver Catalog Scan

| Field | Value |
|------|-----|
| **ID** | TC-GA-003 |
| **Title** | Scan the LOLDrivers catalog for known vulnerable signed drivers |
| **Objective** | Build a list of BYOVD candidates suitable for educational kernel exploitation research |
| **Steps** | 1. Clone the LOLDrivers catalog: `git clone https://github.com/magicsword-io/LOLDrivers.git C:\research\LOLDrivers`.<br>2. Inventory the JSON entries: `Get-ChildItem C:\research\LOLDrivers\drivers\*.json \| Measure-Object`.<br>3. Filter for categories of interest: `Select-String -Pattern 'capcom\|dbutil\|gdrv\|RTCore\|procexp152\|MsIo'`.<br>4. For each candidate, extract the CVE, IOCTL primitive type (arbitrary R/W, MmMapIoSpace, etc.), and signature signer.<br>5. Verify each candidate is authenticode-signed using `Get-AuthenticodeSig` on a retrieved sample; if a sample is missing, record the SHA-256 and document the gap. |
| **Expected Result** | A documented shortlist of 5-10 BYOVD candidates with CVE, primitive type, signer, and SHA-256; all candidates are confirmed to carry valid signatures so they would load normally without test-signing. |
| **Tools** | git, PowerShell, LOLDrivers, Get-AuthenticodeSig |
| **MITRE** | T1068 - Exploitation for Privilege Escalation, T1547 - Boot or Logon Autostart |
| **Difficulty** | Intermediate |
| **Tags** | byovd, loldrivers, signed-driver, kernel |

### TC-GA-004: capcom.sys Analysis (Educational)

| Field | Value |
|------|-----|
| **ID** | TC-GA-004 |
| **Title** | Statically analyze capcom.sys for the arbitrary code execution IOCTL primitive |
| **Objective** | Understand the textbook BYOVD primitive behind CVE-2018-8120-style exploitation |
| **Steps** | 1. Open `capcom.sys` in IDA Pro / Ghidra and locate `DriverEntry`.<br>2. Identify the IRP major function table and find the `IRP_MJ_DEVICE_CONTROL` handler.<br>3. Walk the IOCTL dispatch switch to find the vulnerable code path (typically `IOCTL 0xAA012044`).<br>4. Document the primitive: the driver takes a user-supplied buffer and calls a function pointer in ring 0 at `PASSIVE_LEVEL`, effectively running arbitrary kernel code.<br>5. Cross-reference findings with public write-ups (s4dbrd.github.io, awesome-game-security) to confirm the primitive matches the canonical description.<br>6. Document mitigations: Microsoft's vulnerable driver blocklist, WDAC policy that hashes capcom.sys. |
| **Expected Result** | A documented analysis showing the IOCTL handler, the function pointer call site, the user-controlled buffer layout, and the mitigations that block this driver on modern Windows. No live exploitation is performed in this test case. |
| **Tools** | IDA Pro, Ghidra, awesome-game-security reference, Microsoft blocklist docs |
| **MITRE** | T1068 - Exploitation for Privilege Escalation, T1211 - Exploitation for Defense Evasion |
| **Difficulty** | Intermediate |
| **Tags** | byovd, capcom, static-analysis, ioctl |

---

## C. Memory & Anti-Debug Tooling

### TC-GA-005: Cheat Engine Memory Scan Workflow

| Field | Value |
|------|-----|
| **ID** | TC-GA-005 |
| **Title** | Demonstrate Cheat Engine value + pointer scanning on a research training binary |
| **Objective** | Reproduce the canonical memory scan methodology used in anti-cheat research, against a game-neutral training target |
| **Steps** | 1. Launch a research training binary (NOT a production game client) in the lab VM.<br>2. Attach Cheat Engine; perform an `Unknown initial value` first scan on the health/ammo field.<br>3. In the training binary, change the value (take damage, fire a shot); in Cheat Engine run `Increased value` / `Decreased value` / `Exact Value` scans iteratively until 1-4 addresses remain.<br>4. Right-click a candidate → "Find out what writes to this address"; record the instruction and offset.<br>5. Right-click → "Pointer scan for this address"; set `max level = 7`, `max offset = 0x2000`; allow the scan to complete.<br>6. Restart the training binary and re-resolve the pointer chain to confirm stability across launches. |
| **Expected Result** | A reproducible pointer chain (e.g. `"trainee.exe"+0x12345 +0x10 +0x4`) is documented; the chain resolves correctly across at least 3 relaunches of the training binary; the methodology is transferable to a write-up of how anti-cheat products might detect memory scanning (handle open to protected process, repeated VirtualQueryEx). |
| **Tools** | Cheat Engine, research training binary, lab VM |
| **MITRE** | T1055 - Process Injection, T1574 - Hijack Execution Flow |
| **Difficulty** | Intermediate |
| **Tags** | cheat-engine, memory-scan, pointer-scan, methodology |

### TC-GA-006: ScyllaHide Profile Analysis

| Field | Value |
|------|-----|
| **ID** | TC-GA-006 |
| **Title** | Apply and document ScyllaHide anti-anti-debug profiles during driver analysis |
| **Objective** | Demonstrate which anti-debug artifacts ScyllaHide hides and how a research target reacts |
| **Steps** | 1. Launch ScyllaHide x64 as Administrator; review the built-in profiles (`Normal`, `VEH Extreme`, `Stealth`).<br>2. Without ScyllaHide, attach x64dbg to a research target that calls `IsDebuggerPresent` / `CheckRemoteDebuggerPresent`; record detection result.<br>3. Detach, then apply the `VEH Extreme` profile and re-attach.<br>4. Verify in the target's PEB (via WinDbg `!peb` from a local kernel session or x64dbg memory view) that `BeingDebugged == 0` and `NtGlobalFlag == 0`.<br>5. Document which user-mode anti-debug checks still pass vs. fail with the profile applied; identify any kernel-mode checks (e.g. `EPROCESS.Flags` `DebugActive`) that ScyllaHide cannot hide. |
| **Expected Result** | User-mode anti-debug checks (`IsDebuggerPresent`, heap flags, `OutputDebugString` anomalies) are defeated; documented residual kernel-mode signals (DebugActive flag, debug object handles) remain visible to a kernel anti-cheat; the gap motivates the kernel-mode architecture covered in TC-GA-009..011. |
| **Tools** | ScyllaHide, x64dbg, WinDbg |
| **MITRE** | T1622 - Debugger Evasion, T1055 - Process Injection |
| **Difficulty** | Intermediate |
| **Tags** | anti-debug, scyllahide, peb, kernel |

### TC-GA-007: Memory R/W Interception Testing

| Field | Value |
|------|-----|
| **ID** | TC-GA-007 |
| **Title** | Observe how an anti-cheat driver responds to remote memory access attempts |
| **Objective** | Document the protection model when `OpenProcess` / `ReadProcessMemory` / `WriteProcessMemory` target a protected process |
| **Steps** | 1. In the lab VM, start the anti-cheat-protected research target and wait for the driver to register its callbacks.<br>2. From a separate PowerShell session, attempt `OpenProcess` on the protected PID via the `[DllImport("kernel32")]` pattern or `psapi` module; record the handle return value.<br>3. If a handle is returned, attempt `ReadProcessMemory` on a non-sensitive region; record the result.<br>4. Attempt `WriteProcessMemory` on the same region; expect `STATUS_ACCESS_DENIED` from the kernel callback.<br>5. In WinDbg local kernel mode, set `bp nt!MmCopyVirtualMemory` and `bp nt!NtOpenProcess` to observe the callback-driven denials; capture the call stack. |
| **Expected Result** | `OpenProcess` is denied or returns a restricted handle; `WriteProcessMemory` fails with `STATUS_ACCESS_DENIED`; the WinDbg breakpoint shows the anti-cheat's `PreOperation` callback in the call stack; documented behavior matches the ObRegisterCallbacks model. |
| **Tools** | PowerShell, WinDbg, Process Hacker |
| **MITRE** | T1056 - Input Capture, T1106 - Native API |
| **Difficulty** | Intermediate |
| **Tags** | memory, obregistercallbacks, protection, kernel |

---

## D. Anti-Cheat Architecture Review

### TC-GA-008: Driver Minifilter Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-GA-008 |
| **Title** | Enumerate minifilter instances and altitudes registered by anti-cheat drivers |
| **Objective** | Map which file-system operations the anti-cheat monitors |
| **Steps** | 1. Run `fltmc instances` in an elevated prompt; record the filter name, altitude, and volume.<br>2. Run `fltmc filters` to list all loaded minifilters; identify the anti-cheat entry (e.g. `EasyAntiCheat`, `BEDaisy`).<br>3. Note the altitude value (anti-cheat products typically occupy the 389000-389999 / 460000-460999 altitude ranges).<br>4. In WinDbg, run `!fltkd.filters` and `!fltkd.frames <volume>` for deeper structural detail.<br>5. Cross-reference the registered `PreOperation` / `PostOperation` callbacks (via `!fltkd.filter <addr>`) against the IRP_MJ_* major functions to understand which file operations trigger callbacks. |
| **Expected Result** | The anti-cheat minifilter name, altitude, and callback table are documented; the set of monitored `IRP_MJ_*` codes (typically `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`, `IRP_MJ_CLEANUP`) is recorded; the protection scope (which file paths are watched) is inferred. |
| **Tools** | fltmc, WinDbg, !fltkd extension |
| **MITRE** | T1082 - System Information Discovery, T1057 - Process Discovery |
| **Difficulty** | Intermediate |
| **Tags** | minifilter, altitude, fltmc, file-system |

### TC-GA-009: EAC Architecture Review

| Field | Value |
|------|-----|
| **ID** | TC-GA-009 |
| **Title** | Document the three-component architecture of Easy Anti-Cheat |
| **Objective** | Map EAC's user service, kernel driver, and in-game module responsibilities |
| **Steps** | 1. From TC-GA-001 output, confirm the service names: `EasyAntiCheat` (service) and the runtime client launched by the game.<br>2. Identify the kernel driver: historically `EasyAntiCheat.sys`, loaded via the service; verify with `lm` in WinDbg.<br>3. Identify the in-game module injected by the launcher: typically a DLL with obfuscated exports.<br>4. Catalog responsibilities: service handles update / heartbeat and backend communication; driver handles memory protection, integrity checks, and telemetry collection; in-game module handles anti-debug, code integrity, and reporting back to the driver via shared sections.<br>5. Document the telemetry flow: in-game module → driver → service → EAC backend.<br>6. Reference public research (awesome-game-security) to validate the architecture. |
| **Expected Result** | A documented diagram of the three components, their IPC mechanism (shared sections / IOCTLs), the registered kernel callbacks (ObRegisterCallbacks, minifilter, PsSetCreateProcessNotifyRoutineEx), and the backend telemetry pipeline. |
| **Tools** | WinDbg, Process Hacker, awesome-game-security reference |
| **MITRE** | T1082 - System Information Discovery, T1547 - Boot or Logon Autostart |
| **Difficulty** | Intermediate |
| **Tags** | eac, architecture, telemetry, kernel |

### TC-GA-010: BattlEye BEDaisy.sys Analysis

| Field | Value |
|------|-----|
| **ID** | TC-GA-010 |
| **Title** | Analyze BattlEye's BEDaisy.sys driver and BEService user-mode component |
| **Objective** | Document BattlEye's kernel driver architecture and its dynamic scanning mechanism |
| **Steps** | 1. Confirm service `BEService` is running; record its path and command-line arguments.<br>2. Confirm `BEDaisy.sys` is loaded (`lm` in WinDbg); record ImageBase and size.<br>3. Load `BEDaisy.sys` in IDA Pro / Ghidra; locate `DriverEntry`, the IRP dispatch table, and the minifilter `OperationRegistration` array.<br>4. Identify the "BEService → BEDaisy" IPC channel (typically a shared section and IOCTLs); document the IOCTL codes.<br>5. Note the dynamic scan mechanism: BattlEye is known for shipping bytecode that runs in an in-driver VM; reference public research describing the VM and how scans are pushed from the backend at runtime.<br>6. Document detection signals the driver emits to BEService (handle opens on protected process, foreign module load in game address space, abnormal CPU usage on protected threads). |
| **Expected Result** | Documented architecture: `BEService` (user-mode, networked) ↔ shared section + IOCTL ↔ `BEDaisy.sys` (kernel-mode, minifilter + callbacks + VM bytecode); the dynamic scan delivery model is described; backend telemetry signals are listed. |
| **Tools** | IDA Pro, Ghidra, WinDbg, awesome-game-security reference |
| **MITRE** | T1082 - System Information Discovery, T1057 - Process Discovery |
| **Difficulty** | Advanced |
| **Tags** | battleye, bedaisy, dynamic-scan, kernel |

### TC-GA-011: Vanguard vgk.sys Boot-Time Analysis

| Field | Value |
|------|-----|
| **ID** | TC-GA-011 |
| **Title** | Analyze Riot Vanguard's boot-time driver load (`vgk.sys`) via the `vgc` service |
| **Objective** | Understand how Vanguard achieves early-boot presence and what that means for detection coverage |
| **Steps** | 1. Confirm the `vgc` service `StartType` is `SERVICE_BOOT_START` (0); record via `sc qtype vgc`.<br>2. Confirm `vgk.sys` loads at boot (before user logon) by checking `driverquery /si` after a clean reboot with the game not running.<br>3. Load `vgk.sys` in Ghidra; locate `DriverEntry` and identify the callbacks registered at boot (`ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`).<br>4. Document the protection model: because Vanguard is boot-start, it can observe and block driver loads that occur after boot, making BYOVD attempts more likely to be flagged.<br>5. Note that `vgk.sys` communicates with the Riot Client (`vgc.exe` / Riot service) which then forwards telemetry to Riot's backend.<br>6. Document mitigations an attacker would need to bypass: kernel-mode anti-tamper on the driver itself, server-side validation of client telemetry, hardware binding. |
| **Expected Result** | Documented boot-start configuration; callback table; IPC channel to Riot Client; explanation of why early-boot presence strengthens detection (BYOVD loads happen later and can be observed); list of mitigations. |
| **Tools** | sc, driverquery, Ghidra, WinDbg |
| **MITRE** | T1547 - Boot or Logon Autostart, T1068 - Exploitation for Privilege Escalation |
| **Difficulty** | Advanced |
| **Tags** | vanguard, vgk, boot-start, kernel |

---

## E. Detection Engineering

### TC-GA-012: Detection Engineering for Anti-Cheat

| Field | Value |
|------|-----|
| **ID** | TC-GA-012 |
| **Title** | Design detection signals that catch common bypass patterns |
| **Objective** | Produce defense-side detection guidance for anti-cheat developers based on findings from TC-GA-001..011 |
| **Steps** | 1. Consolidate findings: list every client-side signal observed (handle open denied, memory write denied, abnormal minifilter activity, foreign module in process).<br>2. Design correlation rules: e.g. "process X attempted `OpenProcess` on the game PID N times in 60s, then a foreign module loaded into the game address space" → high-confidence flag.<br>3. Propose signature rotation: every N days, the in-game module's code section is re-laid-out and re-hashed to break static pointer tables built by attackers.<br>4. Propose telemetry correlation: cross-check kernel callback data (driver-side) with in-game module reports and backend behavioral analytics; any two-of-three should escalate.<br>5. Propose hardware binding: bind account identity to TPM attestation + SMBIOS + disk serial; require re-verification on hardware change.<br>6. Document AI-driven detection guidance: train models on mouse movement cadence, aim accuracy distribution, click timing jitter; flag outliers even when no client-side signal fired.<br>7. Document coordinated disclosure pathway for anti-cheat flaws discovered during research. |
| **Expected Result** | A detection engineering document with: (a) correlation rules, (b) signature rotation cadence recommendation, (c) multi-layer telemetry correlation matrix, (d) hardware binding spec, (e) AI model feature list, (f) coordinated disclosure template. |
| **Tools** | Documentation tooling, awesome-game-security reference |
| **MITRE** | T1068 - Exploitation for Privilege Escalation, T1622 - Debugger Evasion |
| **Difficulty** | Advanced |
| **Tags** | detection, blue-team, telemetry, ai, hardware-binding |

---

## Test Case Index

| ID | Title | Difficulty | Tags |
|----|-------|-----------|------|
| TC-GA-001 | Anti-Cheat Driver Enumeration | Beginner | recon, driver |
| TC-GA-002 | Signed Driver Verification | Beginner | signature, authenticode |
| TC-GA-003 | BYOVD Vulnerable Driver Catalog Scan | Intermediate | byovd, loldrivers |
| TC-GA-004 | capcom.sys Analysis (Educational) | Intermediate | byovd, capcom, static-analysis |
| TC-GA-005 | Cheat Engine Memory Scan Workflow | Intermediate | cheat-engine, memory-scan |
| TC-GA-006 | ScyllaHide Profile Analysis | Intermediate | anti-debug, scyllahide, kernel |
| TC-GA-007 | Memory R/W Interception Testing | Intermediate | memory, obregistercallbacks |
| TC-GA-008 | Driver Minifilter Enumeration | Intermediate | minifilter, altitude, fltmc |
| TC-GA-009 | EAC Architecture Review | Intermediate | eac, architecture, telemetry |
| TC-GA-010 | BattlEye BEDaisy.sys Analysis | Advanced | battleye, bedaisy, dynamic-scan |
| TC-GA-011 | Vanguard vgk.sys Boot-Time Analysis | Advanced | vanguard, vgk, boot-start |
| TC-GA-012 | Detection Engineering for Anti-Cheat | Advanced | detection, blue-team, ai |
