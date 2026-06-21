# Game Anti-Cheat Bypass Payloads

> A reference collection of commands, methodologies, and worked examples for **security research and anti-cheat developer education**. Covers the anti-cheat ecosystem, kernel-mode driver architecture, BYOVD methodology, EAC / BattlEye / Vanguard internals, detection engineering, and a quick-reference cheat sheet. All examples target a controlled research lab and game-neutral training binaries. Do not apply against production game clients or live matches.

---

## Table of Contents

1. [Anti-Cheat Ecosystem Overview](#1-anti-cheat-ecosystem-overview)
2. [Kernel-Mode Driver Architecture](#2-kernel-mode-driver-architecture)
3. [Driver Enumeration](#3-driver-enumeration)
4. [Memory R/W Interception](#4-memory-rw-interception)
5. [BYOVD (Bring Your Own Vulnerable Driver)](#5-byovd-bring-your-own-vulnerable-driver)
6. [BYOVD Exploitation](#6-byovd-exploitation)
7. [Cheat Engine in Research](#7-cheat-engine-in-research)
8. [ScyllaHide Anti-Anti-Debug](#8-scyllahide-anti-anti-debug)
9. [ReClass.NET Memory Class Reconstruction](#9-reclassnet-memory-class-reconstruction)
10. [API Monitor & Detection](#10-api-monitor--detection)
11. [Signature & Integrity Checks](#11-signature--integrity-checks)
12. [Detection Evasion Research](#12-detection-evasion-research)
13. [EAC Architecture Analysis](#13-eac-architecture-analysis)
14. [BattlEye Architecture Analysis](#14-battleye-architecture-analysis)
15. [Vanguard (Riot) Architecture](#15-vanguard-riot-architecture)
16. [Anti-Cheat Telemetry Research](#16-anti-cheat-telemetry-research)
17. [Detection Engineering (Blue Side)](#17-detection-engineering-blue-side)
18. [Quick Reference Cheat Sheet](#18-quick-reference-cheat-sheet)

---

## 1. Anti-Cheat Ecosystem Overview

### 1.1 Major Products at a Glance

| Product | Vendor | Kernel Driver | Service | Boot-Start? | Notable Games |
|---------|--------|--------------|---------|-------------|---------------|
| **Easy Anti-Cheat (EAC)** | Epic Games | `EasyAntiCheat.sys` | `EasyAntiCheat.exe` | No (on-demand) | Fortnite, Apex Legends, Rust, Fall Guys |
| **BattlEye (BE)** | BattlEye Innovations | `BEDaisy.sys` | `BEService.exe` | No (on-demand) | PUBG, Rainbow Six Siege, DayZ, Arma 3 |
| **Vanguard** | Riot Games | `vgk.sys` | `vgc.exe` (via `vgc` service) | **Yes** (boot-start) | VALORANT, League of Legends |
| **Ricochet** | Activision / Treyarch | Driver (per-title) | `bootstrapper.exe` | Yes (per-title) | Call of Duty: Warzone, MW2/MW3 |
| **FACEIT AC** | FACEIT Limited | FACEIT Anti-Cheat driver | FACEIT AC client | No (on-demand) | CS:GO / CS2 community matches |
| **ESEA AC** | ESEA (ESL) | ESEA Client driver | ESEA Client | No | CS:GO community matches |

### 1.2 Product Categories

```
Ring 0 (kernel)   : EAC, BattlEye, Vanguard, Ricochet, FACEIT, ESEA
Ring 3 (user-mode): VAC (Valve Anti-Cheat), EasyAntiCheat older, PunkBuster (legacy)
Hybrid            : VAC + Overwatch (CS2 server-side review), FACEIT (hybrid)
Server-side only  : VACnet (CS2 deep learning), custom backends per publisher
```

### 1.3 Reference Resources

```bash
# gmh5225 curated research index (the canonical starting point)
# Repo: https://github.com/gmh5225/awesome-game-security
# Sections: EAC, BattlEye, Vanguard, FACEIT, ESEA, VAC, hardware ID, general
git clone https://github.com/gmh5225/awesome-game-security.git C:\research\refs\awesome-game-security

# s4dbrd's long-form primer
# URL: https://s4dbrd.github.io/
# Title: "How Kernel Anti-Cheats Work: A Deep Dive"
# Use WebFetch or curl to mirror locally for offline lab use
curl -sL https://s4dbrd.github.io/ -o C:\research\refs\s4dbrd-deep-dive.html

# LOLDrivers (BYOVD catalog)
git clone https://github.com/magicsword-io/LOLDrivers.git C:\research\refs\LOLDrivers

# Microsoft vulnerable driver blocklist documentation
# URL: https://learn.microsoft.com/en-us/windows/security/threat-protection/
#      windows-defender-application-control/microsoft-recommended-driver-block-rules
```

### 1.4 Ecosystem Timeline (Context)

```
2000s     : PunkBuster, VAC, early server-side only
2010-2014 : User-mode anti-cheat dominant; cheats move to kernel
2014-2018 : EAC and BattlEye move to kernel (PUBG, Rust, R6)
2020      : Riot Vanguard launches with VALORANT (boot-start, controversial)
2021      : Activision Ricochet launches for Warzone (kernel + server-side)
2022-2026 : Convergence on three-component architecture (driver+service+module)
           AI-driven server-side detection becomes standard
           HWID binding + TPM attestation on Windows 11
```

---

## 2. Kernel-Mode Driver Architecture

### 2.1 The Three-Component Design

```
[Game process]
  └─ In-game module (DLL injected by launcher)
       │  - Anti-debug, code-integrity, behavioral capture
       │  - Reports via shared section / IOCTL
       ▼
[Kernel driver (.sys)]
  └─ Registered callbacks
       │  - ObRegisterCallbacks (handle open / duplicate)
       │  - PsSetCreateProcessNotifyRoutineEx (process creation)
       │  - PsSetLoadImageNotifyRoutine (module load)
       │  - Minifilter callbacks (file I/O)
       │  - MmProtectDriverMemory / CI checks on itself
       │  - Communicates with service via IOCTL + shared section
       ▼
[User-mode service]
  └─ Heartbeat, update, license, launcher integration
       │  - Communicates with backend via TLS
       ▼
[Backend]
  └─ Behavioral analysis, HWID blacklist, signature distribution
```

### 2.2 DriverEntry Skeleton (Conceptual)

```c
// Conceptual skeleton of an anti-cheat DriverEntry (educational)
// NOT a working driver; illustrates the structure of registration.

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING deviceName, symLink;
    PDEVICE_OBJECT deviceObj;
    
    RtlInitUnicodeString(&deviceName, L"\\Device\\ResearchAC");
    RtlInitUnicodeString(&symLink, L"\\??\\ResearchAC");
    
    IoCreateDevice(DriverObject, 0, &deviceName,
                   FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObj);
    IoCreateSymbolicLink(&symLink, &deviceName);
    
    // Set IRP dispatch table
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = ResearchAcDispatch;
    }
    DriverObject->DriverUnload = ResearchAcUnload;
    
    // Register protection callbacks
    OB_OPERATION_REGISTRATION opReg[2] = {
        { PsProcessType, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
          ResearchAcPreOp, ResearchAcPostOp },
        { PsThreadType,  OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
          ResearchAcPreOp, ResearchAcPostOp }
    };
    OB_CALLBACK_REGISTRATION cbReg = {
        .Version = OB_FLT_REGISTRATION_VERSION,
        .OperationRegistrationCount = 2,
        .OperationRegistration = opReg
    };
    RtlInitUnicodeString(&cbReg.Altitude, L"389000");
    ObRegisterCallbacks(&cbReg, &g_CallbackHandle);
    
    // Register process notify
    PsSetCreateProcessNotifyRoutineEx(ResearchAcProcNotify, FALSE);
    
    // Register image load notify
    PsSetLoadImageNotifyRoutine(ResearchAcImgNotify);
    
    return STATUS_SUCCESS;
}
```

### 2.3 IRP Dispatch Table (Conceptual)

```c
NTSTATUS ResearchAcDispatch(PDEVICE_OBJECT Device, PIRP Irp) {
    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    
    switch (io->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            // Service is opening/closing the device
            break;
        case IRP_MJ_DEVICE_CONTROL:
            status = ResearchAcIoctl(Device, Irp, io);
            break;
        default:
            status = STATUS_NOT_SUPPORTED;
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
```

### 2.4 Callback Responsibilities

```
ObRegisterCallbacks (Pre-Operation):
  - Inspect OpenProcess / DuplicateHandle calls
  - For target PIDs (protected game process), strip rights
    (PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION)
  - Or deny outright with STATUS_ACCESS_DENIED

PsSetCreateProcessNotifyRoutineEx:
  - Log new process creation; cross-check against allow-list
  - For unexpected processes launched by the game, flag for review
  - Capture parent PID, command line, image path

PsSetLoadImageNotifyRoutine:
  - Log every DLL / driver load system-wide
  - For loads into the game process, validate the module against
    a known-good list (whitelist of expected modules)
  - For unknown modules, capture image base + size and report

Minifilter callbacks:
  - Pre/Post operation on IRP_MJ_CREATE, IRP_MJ_WRITE,
    IRP_MJ_SET_INFORMATION, IRP_MJ_CLEANUP
  - For protected paths (game binaries, save data, config),
    deny write access from non-game processes
```

### 2.5 Self-Protection

```c
// Anti-tamper on the driver itself
// Pattern: register callbacks that prevent handle open on the driver's
// device object, the service process, and the kernel driver image.

// (Conceptual; real implementations hash the .text section and
// compare against a signed expected value at runtime.)

// 1. Block handle open on the service process (via ObRegisterCallbacks).
// 2. Block handle open on the driver's device object.
// 3. Periodically MmProtectDriverMemory on the driver's image.
// 4. Walk PsLoadedModuleList and verify the driver is still present
//    and unmodified.
```

---

## 3. Driver Enumeration

### 3.1 Service Enumeration (PowerShell)

```powershell
# Enumerate services related to anti-cheat products
Get-Service | Where-Object {
    $_.Name -match 'EasyAntiCheat|BEService|BEDaisy|vgc|vgk|Ricochet|FACEIT|ESEA'
} | Format-Table Name, Status, StartType -AutoSize

# Inspect service configuration (binary path, start type, dependencies)
sc.exe qc EasyAntiCheat
sc.exe qc BEService
sc.exe qc vgc
```

### 3.2 Driver Enumeration (driverquery)

```cmd
:: List all loaded drivers with signature info
driverquery /si | findstr /I "Easy Battle Vanguard vgk FACEIT"

:: List all drivers (full)
driverquery /v > C:\research\drivers.txt

:: CSV export for analysis
driverquery /fo csv > C:\research\drivers.csv
```

### 3.3 WinDbg lm (Loaded Modules)

```
// In WinDbg local kernel mode
lm t n                 // list all loaded modules with timestamps
lm m Easy*             // filter modules starting with "Easy"
lm m BE*               // filter BattlEye
lm m vg*               // filter Vanguard
!for_each_module       // iterate every loaded module

// Detailed info on a specific driver
!dh EasyAntiCheat -f   // dump headers
lm vm BEDaisy          // verbose module info: base, size, timestamp
```

### 3.4 Signed Driver Verification (PowerShell)

```powershell
# Verify Authenticode signature on a driver file
Get-AuthenticodeSig -FilePath 'C:\Windows\System32\drivers\vgk.sys'

# Output fields of interest:
#   Status              : Valid
#   StatusMessage       : Signature verified.
#   SignerCertificate.Subject : CN=Riot Games, Inc....
#   TimeStamperCertificate.Subject : CN=<timestamp CA>
#   Path                : C:\Windows\System32\drivers\vgk.sys

# Batch-verify multiple drivers
$drivers = @(
    'C:\Windows\System32\drivers\vgk.sys',
    'C:\Program Files (x86)\EasyAntiCheat\EasyAntiCheat.sys',
    'C:\Program Files (x86)\Common Files\BattlEye\BEDaisy.sys'
)
$drivers | ForEach-Object {
    $sig = Get-AuthenticodeSig -FilePath $_
    [PSCustomObject]@{
        Path   = $_
        Status = $sig.Status
        Signer = $sig.SignerCertificate.Subject
    }
} | Format-Table -AutoSize
```

### 3.5 Catalog-Based Signing Verification

```cmd
:: Microsoft sigverif GUI tool
sigverif /v

:: For catalog-based signed drivers (most modern drivers)
:: Use Get-AuthenticodeSig with -VerifyCat on Windows 10 21H2+
:: Note: catalog-based signing means the driver file itself contains a
:: Security Directory entry pointing to a .cat file with the signature.
```

### 3.6 PE Header Inspection (PE-bear / PEview)

```
Load driver .sys in PE-bear:
  1. IMAGE_DOS_HEADER   → e_lfanew points to IMAGE_NT_HEADERS
  2. IMAGE_NT_HEADERS   → OptionalHeader.ImageBase, Subsystem (NATIVE for drivers)
  3. IMAGE_DIRECTORY_ENTRY_SECURITY (index 4) → Security Directory
     - dwLength           : size of WIN_CERTIFICATE
     - wRevision          : WIN_CERT_REVISION_2_0
     - wCertificateType   : WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002)
  4. Section table       → .text, .data, .rdata, .pdata, .init
                          → entropy of .text (high entropy = packed)
  5. Imports             → ntoskrnl.exe imports (MmGetSystemRoutineAddress,
                          IoCreateDevice, ObRegisterCallbacks, etc.)
```

---

## 4. Memory R/W Interception

### 4.1 ObRegisterCallbacks Pre-Operation

```c
// Conceptual Pre-Operation callback (educational)
// Real anti-cheats register these to filter OpenProcess/DuplicateHandle.

OB_PREOP_CALLBACK_STATUS ResearchAcPreOp(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    PEPROCESS targetProc = (PEPROCESS)OperationInfo->Object;
    HANDLE targetPid = PsGetProcessId(targetProc);
    
    // If the target is our protected game PID
    if (targetPid == g_ProtectedGamePid) {
        PEPROCESS callerProc = PsGetCurrentProcess();
        HANDLE callerPid = PsGetProcessId(callerProc);
        
        // If caller is NOT the anti-cheat service
        if (callerPid != g_ServicePid) {
            // Strip dangerous access rights
            OperationInfo->Parameters->CreateHandleInformation
                .DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE |
                                    PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION);
            // Or deny outright:
            // OperationInfo->Parameters->CreateHandleInformation
            //     .DesiredAccess = 0;
        }
    }
    return OB_PREOP_SUCCESS;
}
```

### 4.2 Process Notify Routine

```c
// Conceptual PsSetCreateProcessNotifyRoutineEx callback
VOID ResearchAcProcNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL) {
        // Process creation
        UNICODE_STRING img = CreateInfo->ImageFileName;
        // Log: PID, parent PID, image path, command line
        ResearchLogEvent(EVENT_PROC_CREATE, ProcessId,
                         CreateInfo->ParentProcessId, &img);
    } else {
        // Process exit
        ResearchLogEvent(EVENT_PROC_EXIT, ProcessId, 0, NULL);
    }
}
```

### 4.3 Image Load Notify Routine

```c
// Conceptual PsSetLoadImageNotifyRoutine callback
VOID ResearchAcImgNotify(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    // Log every DLL/driver load system-wide
    ResearchLogEvent(EVENT_IMG_LOAD, ProcessId, 0, FullImageName);
    
    // If image loaded into the protected game process
    if (ProcessId == g_ProtectedGamePid) {
        // Validate against known-good list
        if (!IsModuleAllowed(FullImageName)) {
            // Flag: unexpected module in game address space
            ResearchFlagAnomaly(ANOMALY_FOREIGN_MODULE, FullImageName);
        }
    }
}
```

### 4.4 Minifilter Registration (Conceptual)

```c
// Conceptual minifilter registration
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      ResearchAcPreCreate, NULL },
    { IRP_MJ_WRITE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      ResearchAcPreWrite, NULL },
    { IRP_MJ_SET_INFORMATION,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      ResearchAcPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          // Flags
    NULL,                       // Context
    Callbacks,                  // OperationRegistration
    ResearchAcUnload,           // FilterUnloadCallback
    ResearchAcInstanceSetup,    // InstanceSetupCallback
    NULL, NULL, NULL            // ... other callbacks
};

// Register with altitude in the 389000-460000 range
FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
```

### 4.5 Minifilter Enumeration (fltmc)

```cmd
:: List all loaded minifilters and their altitudes
fltmc filters

:: Sample output (annotated):
:: Filter Name      Frame  Altitude  Instance Name
:: EasyAntiCheat    0      389120    EasyAntiCheat
:: BEDaisy          0      389200    BEDaisy
:: luafv            0      135000    luafv
:: FileInfo         0      45000     FileInfo

:: List instances per volume
fltmc instances

:: Attach to a volume manually (if a minifilter is not auto-attaching)
fltmc attach BEDaisy C:
```

### 4.6 WinDbg Kernel Callback Inspection

```
// Break on the protected operations
bp nt!NtOpenProcess         // handle open attempts
bp nt!NtDuplicateObject     // handle duplication
bp nt!MmCopyVirtualMemory   // actual R/W primitive (if used)
bp nt!NtReadVirtualMemory
bp nt!NtWriteVirtualMemory

// Dump the ObCallback registration list
!obcallback                // (if the extension is available)

// Walk the minifilter registration
!fltkd.filters             // list all registered minifilters
!fltkd.filter <addr>       // details on a specific filter
!fltkd.instances <addr>    // instances of a filter
!fltkd.frames              // minifilter frames
```

---

## 5. BYOVD (Bring Your Own Vulnerable Driver)

### 5.1 LOLDrivers Catalog

```powershell
# Pull the catalog
git clone https://github.com/magicsword-io/LOLDrivers.git C:\research\LOLDrivers

# Inventory entries
Get-ChildItem C:\research\LOLDrivers\drivers\*.json | Measure-Object | Select Count

# Count entries by category
Get-ChildItem C:\research\LOLDrivers\drivers\*.json |
  ForEach-Object { (Get-Content $_.FullName | ConvertFrom-Json).Category } |
  Group-Object | Sort-Object Count -Descending

# Filter for known-bad samples
Get-ChildItem C:\research\LOLDrivers\drivers\*.json |
  Select-String -Pattern 'capcom|dbutil|gdrv|RTCore|procexp152|MsIo|DirectIO' |
  Select-Object -First 20
```

### 5.2 Educational CVE Reference

| Driver | CVE | Primitive | Signer |
|--------|-----|-----------|--------|
| `capcom.sys` | CVE-2018-8120 | Arbitrary kernel code execution via IOCTL | Capcom Co., Ltd. |
| `dbutil_2_3.sys` | CVE-2021-21551 | Arbitrary kernel R/W via IOCTL | Dell Inc. |
| `gdrv.sys` | CVE-2018-19320 | Arbitrary R/W + physical memory map | GIGABYTE Technology Co. |
| `RTCore64.sys` | CVE-2019-16098 | Arbitrary R/W via MSR + memory | Micro-Star International Co. |
| `MsIo64.sys` | various | Physical memory read via IOCTL | (multiple OEMs) |
| `procexp152.sys` | CVE-????-???? | Kernel R/W primitive (older Process Explorer) | Sysinternals |
| `DirectIO64.sys` | various | Physical memory R/W | (multiple OEMs) |

### 5.3 Sample Signature Verification

```powershell
# Confirm sample is still validly signed
Get-AuthenticodeSig -FilePath C:\research\samples\RTCore64.sys

# Expected:
#   Status   : Valid
#   Signer   : Micro-Star International Co., Ltd.

# Confirm sample hash matches catalog entry
Get-FileHash -Algorithm SHA256 C:\research\samples\RTCore64.sys
# Compare against LOLDrivers JSON entry
$entry = Get-Content C:\research\LOLDrivers\drivers\<RTCore-entry>.json | ConvertFrom-Json
$entry.hashes.SHA256
```

### 5.4 Microsoft Vulnerable Driver Blocklist

```powershell
# Blocklist is enforced via WDAC (Windows Defender Application Control)
# Registry location (research VM; do NOT modify on production systems):
HKLM\SYSTEM\CurrentControlSet\Control\CI\Config
VulnerableDriverBlocklistEnable : REG_DWORD
  0 = disabled (research mode)
  1 = enabled (production default on Win11 22H2+)

# To check current state
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
                 -Name VulnerableDriverBlocklistEnable

# To temporarily disable (research only; re-enable before any production use)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
                 -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord
# Reboot required for the change to take effect.
```

### 5.5 WDAC Policy (Recommended for Production)

```xml
<!-- Conceptual WDAC policy snippet that blocks a known-bad driver by hash -->
<Rule>
  <RuleProvider>Microsoft</RuleProvider>
  <RuleType>Deny</RuleType>
  <FileReference>
    <Hash> REPLACE_WITH_YOUR_SHA256_HASH_OF_CAPCOM_SYS </Hash>
    <Hash> REPLACE_WITH_YOUR_SHA256_HASH_OF_DBUTIL_SYS </Hash>
    <Hash> REPLACE_WITH_YOUR_SHA256_HASH_OF_GDRV_SYS </Hash>
  </FileReference>
</Rule>
```

---

## 6. BYOVD Exploitation

### 6.1 Loading the Driver

```powershell
# Create a service for the sample driver
sc.exe create RTCore type= kernel start= demand binPath= "C:\research\samples\RTCore64.sys"

# Start the service (loads the driver)
sc.exe start RTCore

# Confirm it loaded
driverquery /si | findstr /I "RTCore"

# In WinDbg
lm m RTCore*

# Stop and remove (cleanup)
sc.exe stop RTCore
sc.exe delete RTCore
```

### 6.2 IOCTL Interface (Conceptual)

```c
// Conceptual user-mode client that opens the driver and sends IOCTLs
// NOT a working exploit; illustrates the pattern.

#include <windows.h>

HANDLE OpenResearchDriver() {
    return CreateFileW(
        L"\\\\.\\RTCore",                // device symlink exposed by driver
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
}

BOOL ResearchReadKernel(HANDLE hDev, ULONG64 kva, PVOID outBuf, ULONG outLen) {
    ULONG bytesReturned = 0;
    BYTE inBuf[16] = { 0 };
    *(PULONG64)inBuf       = kva;        // target kernel virtual address
    *(PULONG)(inBuf + 8)   = outLen;     // read length
    
    return DeviceIoControl(
        hDev,
        0x80002048,                     // REPLACE_WITH_YOUR_TARGET_IOCTL
        inBuf, sizeof(inBuf),
        outBuf, outLen,
        &bytesReturned,
        NULL);
}

// In main():
HANDLE hDev = OpenResearchDriver();
BYTE outBuf[8] = { 0 };
if (ResearchReadKernel(hDev, 0xFFFFF80512345000ull, outBuf, sizeof(outBuf))) {
    // outBuf now contains kernel memory (research output)
}
CloseHandle(hDev);
```

### 6.3 EPROCESS Walk (Conceptual)

```c
// Conceptual: use the R/W primitive to walk PsActiveProcessHead
// and locate a target EPROCESS.

// 1. Resolve the kernel symbol PsActiveProcessHead
//    (via NtQuerySystemInformation(SystemModuleInformation) on Win7-era
//     or via registry / KdDebuggerDataBlock on modern systems).

// 2. Use ResearchReadKernel() to walk the ActiveProcessLinks list.

// 3. For each EPROCESS, compare ImageFileName against the target.

// 4. When the target EPROCESS is found:
//    - Zero EPROCESS.Protection (signal level)
//    - Or zero EPROCESS.SignerLevel
//    - Or modify EPROCESS.Flags (DebugActive bit)

// Educational note: on modern Windows with PsProtectedProcess-Lite,
// these fields are checked by the kernel on every OpenProcess.
// Zeroing them in EPROCESS memory (with the R/W primitive) bypasses
// the protection until the next callback fires that re-asserts it.
```

### 6.4 WinDbg Breakpoints for Exploit Tracing

```
// Set breakpoints before triggering the exploit
bp nt!NtOpenProcess          "!process @rcx 0; g"    // log open attempts
bp nt!MmCopyVirtualMemory    ".printf \"MmCopyVirtualMemory src=%p dst=%p\\n\", @rcx, @rdx; g"
bp nt!ObpCallPreOperationCallbacks  ".printf \"PreOp\\n\"; g"

// Trigger the exploit from the user-mode client, then inspect:
//   .framergn  // current stack frame region
//   kvn        // stack trace with frame numbers
//   !thread    // current thread details
//   !process 0 0 <target.exe>   // target EPROCESS details
```

### 6.5 Detection by Anti-Cheat (Counterpoint)

```
Defense (how an anti-cheat catches BYOVD):

1. PsSetLoadImageNotifyRoutine fires when the vulnerable driver loads.
   The anti-cheat's image-load callback captures the SHA-256 of the
   loaded driver and compares against its internal blocklist.

2. If matched, the anti-cheat can:
   (a) Report to backend (silent; flag for HWID ban)
   (b) Crash the game / refuse to launch (user-visible)
   (c) Trigger kernel anti-tamper that unloads the offending driver
       (only possible if the anti-cheat itself has higher privilege)

3. Server-side: client reports "I saw RTCore64.sys load" to backend.
   Backend cross-references HWID; if multiple reports from same HWID,
   escalate to permanent ban.
```

---

## 7. Cheat Engine in Research

### 7.1 Value Scan Methodology

```
Lab target: research / training binary (NOT a production game client)

1. Launch the training binary (e.g. a "find the value" trainer).
2. Launch Cheat Engine; click the "computer + magnifying glass" icon.
3. Select the training binary's process from the list.
4. First Scan:
     Scan Type:  Exact Value
     Value Type: 4 Bytes (default for integers)
     Value:      <known starting value, e.g. 100>
     Click "First Scan"
5. In the training binary, change the value (e.g. fire a shot; ammo 100→99).
6. Next Scan:
     Scan Type:  Exact Value
     Value:      99
     Click "Next Scan"
7. Repeat steps 5-6 until 1-4 addresses remain in the left panel.
8. Double-click an address to add it to the address list below.
9. Right-click → "Find out what writes to this address" (attaches debugger).
```

### 7.2 Unknown Initial Value Methodology

```
Use when the target value is not visible (e.g. cooldown timer):

1. First Scan:
     Scan Type:  Unknown initial value
     Value Type: Float (for timers)
     Click "First Scan"   (returns a huge candidate list)
2. In the training binary, change the value indirectly (wait 1s).
3. Next Scan:  Scan Type = Decreased value
4. Wait; change again.
5. Next Scan:  Scan Type = Increased value (or Decreased, Changed, Unchanged)
6. Repeat until the candidate list narrows.
```

### 7.3 Pointer Scan Methodology

```
Once a stable address is found, find the pointer chain that resolves it:

1. Right-click the address → "Pointer scan for this address".
2. Configure:
     Maximum level:          7
     Maximum offset value:   0x2000
     Only find paths with a static address: Yes
     Address:                <training.exe>+<offset>
3. Click OK; wait for scan to complete.
4. Restart the training binary; re-find the target address.
5. Right-click the new address → "Pointer scan for this address"
   with "Compare results with other saved pointermap".
6. Load the saved pointermap from step 3; the intersection narrows candidates.
7. Repeat across 3-5 relaunches until the pointer chain resolves reliably.
```

### 7.4 Signature Scan Methodology

```
Use when the target value has no stable pointer (float-backed aim angles):

1. In the training binary, identify a unique byte pattern adjacent to
   the target value (e.g. 4 bytes of health followed by a known magic).
2. In Cheat Engine: Memory View → Tools → Pointer scanner (or
   "AOB Injection" via the auto-assembler).
3. Define an AOB pattern:
     ?? ?? ?? ?? 4D 5F 48 45 41 4C 54 48    // _HEALTH magic
4. Scan for the pattern; record the address+offset to the value.
5. Use the auto-assembler to inject a small code cave that reads the value
   at every game tick; pipe the output to a console.
```

### 7.5 Anti-Cheat Detection of Cheat Engine

```
How an anti-cheat detects Cheat Engine specifically:

1. Image load callback flags Cheat Engine's DLLs injected into the game
   process (ceserver, etc.).
2. Window enumeration callback scans for "Cheat Engine" window class.
3. OpenProcess callback from Cheat Engine on the game PID triggers denial.
4. Process enumeration callback flags the Cheat Engine parent process.
5. Handle duplication attempts on the game PID are flagged server-side.
6. Memory access pattern: rapid VirtualQueryEx over large VA ranges
   is itself a behavioral signature.

Defenders: any of these signals, fired in isolation, is weak.
Correlated across N seconds with N attempts, they become high-confidence.
```

---

## 8. ScyllaHide Anti-Anti-Debug

### 8.1 Profiles

```
Built-in ScyllaHide profiles:

  Normal         : basic PEB patching (BeingDebugged, NtGlobalFlag)
  VEH            : hooks via Vectored Exception Handler; hides more
  VEH Extreme    : VEH + advanced techniques; use for protected research targets
  Stealth        : minimal hooks; lower coverage, lower detection by anti-debug
  Custom         : per-technique toggles (advanced users)
```

### 8.2 Anti-Debug Checks Defeated

```
ScyllaHide addresses these user-mode anti-debug checks:

  IsDebuggerPresent          PEB.BeingDebugged zeroed
  CheckRemoteDebuggerPresent NtQueryInformationProcess(ProcessDebugPort) hooked
  NtQueryInformationProcess  ProcessDebugObjectHandle, ProcessDebugFlags, ProcessDebugPort
  OutputDebugString          LastError preserved; no "debugger present" trail
  Heap flags                 PEB.NtGlobalFlag zeroed; heap flags cleaned
  Heap protection            PEB.ProcessHeaps flags cleaned
  TLS callbacks              ScyllaHide intercepts the callback execution
  DebugActiveProcess         Hooked to return failure silently
  KdSystemDebugControl       Hooked
  NtSetInformationThread     ThreadHideFromDebugger respected (transparent)
  NtClose                    Invalid handle close hooked to not raise exception
```

### 8.3 Applying ScyllaHide

```
1. Launch ScyllaHide x64 as Administrator (needs SeDebugPrivilege).
2. Select profile: "VEH Extreme" from the dropdown.
3. Click "Start" (ScyllaHide now monitors process creation).
4. Launch the research target (it should auto-attach).
5. Verify in x64dbg or WinDbg:
     PEB.BeingDebugged  == 0
     PEB.NtGlobalFlag   == 0
     PEB.ProcessHeaps   heap flags zeroed
6. In x64dbg: attach to the target (ScyllaHide injects hooks).
```

### 8.4 Residual Kernel-Mode Signals (Cannot Be Hidden by ScyllaHide)

```
ScyllaHide works in user-mode. It CANNOT hide these kernel-visible signals:

  EPROCESS.Flags & PS_FLAGS_DEBUG_ACTIVE
  EPROCESS.Flags2 & PS_FLAGS2_DEBUG_ACTIVE
  PspCidTable references
  Debug object handles (DBG_OBJECT) held by the kernel
  KdDebuggerEnabled (system-wide)
  KdSystemDebugControl activity
  Kernel callbacks (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx)

This is the fundamental reason anti-cheat moved to the kernel: any
user-mode anti-debug defeat can be observed from kernel-mode.
```

### 8.5 ScyllaHide Configuration File

```
ScyllaHide ships with an XML profile file. Structure:

<ScyllaHideConfig>
  <Profile name="VEH Extreme">
    <PEB>
      <BeingDebugged action="zero" />
      <NtGlobalFlag action="zero" />
      <HeapFlags action="clean" />
      <HeapForceFlags action="clean" />
    </PEB>
    <Hooks>
      <NtQueryInformationProcess action="hook" />
      <NtQuerySystemInformation action="hook" />
      <NtClose action="hook" />
      <OutputDebugStringA action="hook" />
      <DebugActiveProcess action="hook" />
    </Hooks>
    <VEH enabled="true" />
  </Profile>
</ScyllaHideConfig>
```

---

## 9. ReClass.NET Memory Class Reconstruction

### 9.1 Basic Workflow

```
Once a stable pointer to a player entity is found via Cheat Engine:

1. Copy the hex address from Cheat Engine (e.g. 0x12345678).
2. Launch ReClass.NET; attach to the research target process.
3. In ReClass: right-click the root node → "Add Class" → name it "PlayerEntity".
4. Right-click the new class → "Add Pointer" → paste 0x12345678.
5. The hex view shows memory at that address.
6. Add fields:
     - Right-click a row → "Add Float"  → guess: health
     - Right-click → "Add Int32"       → guess: ammo
     - Right-click → "Add Vector3"     → guess: position
7. Iterate: change values in-game, watch which field updates in ReClass.
```

### 9.2 Class Layout Example

```csharp
// ReClass.NET generates C# definitions that can be exported:
public class PlayerEntity {
    public Int32   Health;          // offset 0x000
    public Int32   MaxHealth;       // offset 0x004
    public Int32   Armor;           // offset 0x008
    public Int32   AmmoPrimary;     // offset 0x00C
    public Vector3 Position;        // offset 0x010  (float x, y, z)
    public Vector3 Velocity;        // offset 0x01C
    public Single  Yaw;             // offset 0x028
    public Single  Pitch;           // offset 0x02C
    public Byte[]  Padding1;        // offset 0x030 - 0x03F
    public IntPtr  pWeaponTable;    // offset 0x040
    public Int32   TeamId;          // offset 0x048
}

// Pointer chain:
//   ModuleBase("trainee.exe") + 0x12345 → pLocalPlayer
//   pLocalPlayer + 0x10                    → Position
```

### 9.3 ReClass.NET Hotkeys

```
Ctrl + Arrow keys   : move the cursor by 1 byte
Ctrl + Shift + Arr  : move by 16 bytes
N                   : add new class
P                   : add pointer to current class
E                   : add enum
Ctrl + 1..9         : change current row data type (int, float, vec3, ...)
Ctrl + E            : export to C# / C++ / Python
F2                  : rename current field
```

### 9.4 Network Structure Reconstruction

```
For research into game network protocol (separate from anti-cheat):

1. Identify the network buffer pointer via Cheat Engine (scan for the
   "received packet" pattern).
2. Open in ReClass.NET.
3. Add a "Custom Type" for packet header (opcode + length + sequence).
4. Document the packet layout.
5. (Optional) Generate a C# / Python parser via ReClass export.

Note: this is research into the protocol, not active cheating.
A protocol parser alone does not produce an exploit.
```

---

## 10. API Monitor & Detection

### 10.1 API Monitor Setup

```
1. Launch API Monitor v2 (x64).
2. Select API categories to monitor:
     Memory Management      : NtAllocateVirtualMemory, NtProtectVirtualMemory,
                              NtWriteVirtualMemory, NtReadVirtualMemory
     Process and Thread     : NtOpenProcess, NtCreateThreadEx,
                              NtSetInformationThread, NtQueryInformationProcess
     Handle and Object      : NtDuplicateObject, NtClose
     File Management        : NtCreateFile, NtWriteFile, NtReadFile
     Registry               : NtCreateKey, NtSetValueKey
     Network (Winsock)      : WSASend, WSARecv, connect, sendto
3. Attach to the research target process (NOT the game client).
4. Run the scenario (e.g. attempt OpenProcess on game PID).
5. Review the captured API calls with parameters.
```

### 10.2 Hook Detection Signatures

```
An anti-cheat detects that its API calls are being hooked via:

1. Inline hook: read the first 16 bytes of the API function via
   NtReadVirtualMemory on the local process; compare against a stored
   pristine copy from ntdll.dll on disk. Mismatch → hooked.

2. IAT hook: walk the Import Address Table of the loaded module; verify
   each entry points into the legitimate DLL's export range.

3. Hardware breakpoint: check DR0-DR7 for non-zero values in any thread
   of the protected process. Non-zero DR registers → hardware BP set.

4. SSDT hook (legacy x86): compare SSDT entries against known-good table.
   Modern x64 with PatchGuard blocks this.

5. ETW hook: ETW providers (esp. Microsoft-Windows-Kernel-* and
   Microsoft-DotNETFramework-CLR) cannot be hooked in user-mode without
   detection. Patching EtwNotificationRegister is detectable.
```

### 10.3 ETW Telemetry Signatures

```
ETW providers monitored by anti-cheats:

  Microsoft-Windows-Kernel-Process        : process/thread create, image load
  Microsoft-Windows-Kernel-File           : file I/O
  Microsoft-Windows-Kernel-Registry       : registry writes
  Microsoft-Windows-Kernel-Network        : outbound connections
  Microsoft-Windows-Kernel-Image          : module load
  Microsoft-Windows-Threat-Intelligence   : Ti mode (kernel-only consumer)
  Microsoft-DotNETFramework-CLR           : .NET assembly load (Event 4104)
  Microsoft-Windows-PowerShell            : script block logging

Anti-cheats register as ETW consumers (kernel-mode, via
EtwNotificationRegister) and receive real-time events.

Defeating ETW from user-mode is hard:
  - Patch the ETW provider's EtwGuidEnableInfo bits to disable.
  - Unhook the user-mode EtwpEventRegisterFull.
  - Both are detectable: the kernel still has the events.
```

### 10.4 Telemetry Signal Inventory

```
Per-event signals the anti-cheat ships to the backend:

  Process events   : PID, parent PID, image path, command line, integrity level
  Image load       : module name, base, size, hash, signer
  Handle events    : target PID, access mask, caller PID
  Memory events    : RWX allocation, WriteProcessMemory, ProtectVirtualMemory
  Thread events    : remote thread creation, thread context manipulation
  Network events   : remote IP, port, protocol, bytes sent/received
  Registry events  : key path, value, operation type
  File events      : path, operation, bytes
  Driver events    : driver load, signer, hash, image path

Backend correlates all of the above against:
  - Known-bad driver hashes
  - Known-bad process names
  - HWID history
  - Account history
  - Statistical behavioral baselines per player
```

---

## 11. Signature & Integrity Checks

### 11.1 Code Section Hashing

```c
// Conceptual: anti-cheat periodically hashes its own .text section
// and compares against a signed expected hash.

VOID ResearchAcSelfHashCheck(PVOID ImageBase, ULONG imageSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            UCHAR hash[32] = { 0 };
            ResearchSha256((PUCHAR)ImageBase + sec[i].VirtualAddress,
                           sec[i].Misc.VirtualSize, hash);
            
            if (!RtlEqualMemory(hash, g_ExpectedTextHash, 32)) {
                // Tamper detected
                ResearchReportTamper(TAMPER_TEXT_HASH);
            }
        }
    }
}
```

### 11.2 IAT Validation

```c
// Conceptual: walk the Import Address Table and verify each entry
// points within the legitimate DLL's export range.

VOID ResearchAcIatCheck(PVOID ImageBase) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
    
    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)ImageBase +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    for (; imp->Name; imp++) {
        // For each imported function, verify the IAT entry points within
        // the DLL's loaded image range.
        PVOID dllBase = GetModuleBaseFromName((PCSTR)ImageBase + imp->Name);
        PVOID iatEntry = (PVOID)((PUCHAR)ImageBase + imp->FirstThunk);
        
        while (*(PVOID*)iatEntry) {
            PVOID target = *(PVOID*)iatEntry;
            if (!IsWithinRange(target, dllBase, GetImageSize(dllBase))) {
                ResearchReportTamper(TAMPER_IAT);
            }
            iatEntry = (PVOID)((PUCHAR)iatEntry + sizeof(PVOID));
        }
    }
}
```

### 11.3 Driver Signature Enforcement

```
Windows enforces driver signing via Code Integrity (CI.dll):

  Normal mode       : only WHQL-signed drivers load
  Test signing mode : test-signed drivers also load (shows desktop watermark)
  WHQL only         : only drivers that passed WHQL (no test certs)

Anti-cheat leverages CI:
  - Calls NtQuerySystemInformation(SystemCodeIntegrityInformation) to
    read CI state.
  - If test signing is on, anti-cheat may refuse to launch.
  - Anti-cheat may verify the CI policy in effect (WDAC XML).

Detection of test-signing:
  HKLM\BCD\Objects\{guid}\Elements\16000010 : "TestSigning" element
  If TestSigning == TRUE → anti-cheat flags.

Detection of debug mode:
  HKLM\System\CurrentControlSet\Control\Session Manager\Debug Print Filter
  KdDebuggerEnabled (system-wide flag)
  If KdDebuggerEnabled → anti-cheat flags.
```

### 11.4 CRC / Checksum Variants

```
Anti-cheats use multiple integrity algorithms in parallel:

  SHA-256         : cryptographic hash; used for code sections
  CRC32           : fast; used for hot-path checks
  FNV-1a          : fast non-crypto hash; used for telemetry
  Adler-32        : fast checksum for small structures
  Custom rolling  : ad-hoc rolling hash over volatile structures

Detection by attacker (research):
  - Identify the hash routine in IDA Pro (look for SHA-256 constants
    0x6A09E667, 0xBB67AE85; CRC32 polynomial 0xEDB88320).
  - Hardware-breakpoint on the hash routine; modify the input/output
    buffer to defeat the check.
  - Note: this is a known attack; defenders respond by running the
    hash from multiple locations with different code paths.
```

---

## 12. Detection Evasion Research

### 12.1 Direct Syscalls

```asm
; Conceptual direct-syscall stub (x64, Windows 10/11)
; NOT for production use; educational only.

myNtAllocateVirtualMemory PROC
    mov r10, rcx              ; syscall ABI: first arg via r10
    mov eax, 18h              ; syscall number for NtAllocateVirtualMemory (varies by Win version)
    syscall                   ; transition to kernel
    ret                       ; return value in rax
myNtAllocateVirtualMemory ENDP

; By avoiding calls through ntdll.dll, this stub bypasses inline hooks
; placed by EDR/AV on Nt* exports. The syscall still reaches the kernel,
; where ObRegisterCallbacks callbacks (anti-cheat) still fire.
; Direct syscalls are NOT a complete evasion; they only bypass user-mode hooks.
```

### 12.2 Manual Mapping

```
Manual mapping: load a DLL into a process without using the loader.

Conceptual steps:
1. Allocate RWX memory in the target process (NtAllocateVirtualMemory).
2. Write the DLL's PE sections to that memory.
3. Resolve imports (walk import table, resolve via LoadLibrary/GetProcAddress
   equivalent).
4. Apply relocations.
5. Call DllMain with DLL_PROCESS_ATTACH.
6. The DLL does NOT appear in PEB.Ldr (loader's module list).

Detection:
  - PsSetLoadImageNotifyRoutine does NOT fire (loader bypassed).
  - But: memory scanning of the process reveals the unmapped module.
  - And: the module's threads still appear in the process thread list.
  - And: ETW kernel-process provider still sees the thread start address
    pointing into RWX memory (anomalous).
```

### 12.3 Hardware Breakpoints

```c
// Conceptual: set a hardware breakpoint via SetThreadContext on a
// thread of the protected process.
// 4 hardware breakpoints (DR0-DR3) are available per thread.

CONTEXT ctx = { 0 };
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);

ctx.Dr0 = targetAddress;           // breakpoint address
ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1;  // enable DR0, break on execution
ctx.Dr7 &= ~(0x3 << 16);           // length 1 byte, break on execute

SetThreadContext(hThread, &ctx);

// Vectored Exception Handler catches the single-step exception (EXCEPTION_SINGLE_STEP)
// when the breakpoint fires, allowing inspection.
```

```
Detection of hardware breakpoints:
  - Periodic check of DR0-DR7 in the protected process threads.
  - If non-zero, flag for hardware BP tampering.
  - On detection: zero the debug registers and ban the HWID.
```

### 12.4 DKOM (Direct Kernel Object Manipulation)

```
DKOM: directly modify kernel data structures using a kernel R/W primitive.

Examples (research / conceptual):
  - Unlink a process from PsActiveProcessHead (hide from PsList).
  - Modify EPROCESS.Token to escalate privileges.
  - Zero EPROCESS.Protection to bypass OpenProcess filtering.
  - Modify the SSDT entry for a syscall to redirect to attacker code.

Detection:
  - Periodic walk of PsActiveProcessHead vs. the CID table; mismatch → DKOM.
  - Periodic hash of EPROCESS structures; mismatch → tampering.
  - PatchGuard (KPP) detects SSDT / IDT / GDT / MSRs modifications on x64.
  - HVCI blocks unsigned kernel code execution entirely.
```

### 12.5 Hypervisor-Based Research

```
A hypervisor (Intel VT-x / AMD-V) sits below the kernel and can observe
all kernel activity transparently.

Research hypervisors (open source):
  - HyperBone (minimal VT-x hypervisor for research)
  - hvpp (modern VT-x research hypervisor)
  - DdiMon (hypervisor-based kernel monitoring)

Use cases:
  - Stealth EPT hooks (invisible from kernel's perspective)
  - System call logging without kernel modifications
  - Memory access monitoring via EPT violations
  - CPUID-based detection of the hypervisor itself

Detection:
  - timing-based (RDTSC deltas)
  - CPUID-based (some hypervisors leak via CPUID.1:ECX[31])
  - MSR-based (certain MSRs read differently under a hypervisor)
  - INVD / WBINVD timing
  - #VE (virtualization exception) when EPT violations occur
```

---

## 13. EAC Architecture Analysis

### 13.1 Component Map

```
EasyAntiCheat (EAC)

[Launcher / Service]
  - EasyAntiCheat.exe
  - EasyAntiCheat_Setup.exe (one-time setup)
  - Communicates with backend over HTTPS
  - Loads the kernel driver on game launch

[Kernel Driver]
  - EasyAntiCheat.sys
  - Registered via NtLoadDriver from the service
  - Callbacks: ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx,
    PsSetLoadImageNotifyRoutine, minifilter (altitude 389120-389999)
  - Communicates with service via shared section + IOCTLs

[In-game module]
  - Injected by the launcher into the game process
  - Performs: anti-debug, code integrity, behavioral capture
  - Reports to driver via shared section

[Backend]
  - Behavioral analysis
  - HWID blacklist
  - Signature distribution (pushes new scan code to clients)
```

### 13.2 Driver Internals (Static Analysis)

```
Load EasyAntiCheat.sys in IDA Pro / Ghidra:

1. Locate DriverEntry.
   - Often called via the export name or via the PE entry point.
   - Modern EAC may use obfuscated entry points; check .text entropy.

2. Identify IoCreateDevice + IoCreateSymbolicLink.
   - The device name is typically "\Device\EasyAntiCheat" or similar.
   - The symlink is "\??\EasyAntiCheat" or similar.

3. Identify ObRegisterCallbacks.
   - Look for the OB_CALLBACK_REGISTRATION structure initialization.
   - Note the altitude string (e.g. "389120").
   - Identify PreOperation / PostOperation callbacks.

4. Identify PsSetCreateProcessNotifyRoutineEx.
   - Look for the routine passed as argument.
   - This is the process-creation callback.

5. Identify PsSetLoadImageNotifyRoutine.
   - Look for the image-load callback.

6. Identify minifilter registration.
   - Look for FltRegisterFilter call.
   - Note the OperationRegistration array (which IRP_MJ_* codes).

7. Identify the IOCTL handler.
   - In the IRP_MJ_DEVICE_CONTROL dispatch:
     look up the IOCTL codes and their handlers.
   - Note the shared-section IOCTL (used by the service to read
     telemetry from the driver).
```

### 13.3 Telemetry Pipeline

```
EAC telemetry flow:

Game process (in-game module)
    │  shared memory section
    │  (Module writes events; driver reads them)
    ▼
EasyAntiCheat.sys (kernel driver)
    │  IOCTL + shared section
    │  (Service reads events from driver)
    ▼
EasyAntiCheat.exe (service)
    │  HTTPS POST
    │  (Service ships events to backend)
    ▼
EAC Backend
    │
    │  Behavioral analysis
    │  HWID check
    │  Signature distribution (pushes new scan bytecode)
    ▼
  Ban / no-ban decision
```

### 13.4 Research References

```
gmh5225/awesome-game-security EAC section:
  - Multiple research threads on driver internals
  - IOCTL reverse engineering
  - Minifilter altitude references
  - Behavioral capture methodology

s4dbrd.github.io:
  - "How Kernel Anti-Cheats Work: A Deep Dive"
  - Section on EAC three-component architecture
  - Diagrams of the telemetry pipeline
```

---

## 14. BattlEye Architecture Analysis

### 14.1 Component Map

```
BattlEye (BE)

[Service]
  - BEService.exe
  - Runs as a Windows service
  - Handles: update, heartbeat, backend communication

[Kernel Driver]
  - BEDaisy.sys
  - Loaded via NtLoadDriver from the service
  - Registered callbacks (similar to EAC)
  - Unique feature: BEDaisy ships a VM-based bytecode interpreter
    that runs scan logic delivered from the backend at runtime

[In-game module]
  - Injected by the launcher
  - Performs: anti-debug, integrity, behavioral capture

[Backend]
  - Dynamic scan distribution
  - Behavioral analysis
  - HWID blacklist
```

### 14.2 The BEService ↔ BEDaisy IPC

```
Communication channel:

1. Shared memory section created by the driver.
2. Service maps the section into its address space via NtMapViewOfSection.
3. IOCTLs from service to driver trigger scans / state queries.
4. IOCTLs from driver to service (via inverted call model) deliver telemetry.

Common BE IOCTL codes (research-derived; vary by version):
  - IOCTL_BESERVICE_REGISTER_PROCESS
  - IOCTL_BESERVICE_PUSH_SCAN_CODE
  - IOCTL_BESERVICE_FETCH_TELEMETRY
  - IOCTL_BESERVICE_HEARTBEAT
```

### 14.3 Dynamic Scan Mechanism

```
BEDaisy's defining feature:

1. Backend compiles scan logic into BEDaisy bytecode.
2. Backend pushes bytecode to client via the service.
3. BEDaisy.sys loads the bytecode into a VM (in-driver).
4. The VM executes the bytecode, performing arbitrary scans.
5. Scan results flow back to the backend.

Research implications:
  - Static analysis of BEDaisy.sys reveals the VM dispatcher,
    not the actual scan logic.
  - To understand current scans, the bytecode itself must be captured
    and analyzed.
  - Bytecode changes daily / weekly, so static write-ups age quickly.
  - Capture methodology: hook the IOCTL_BESERVICE_PUSH_SCAN_CODE
    path in BEService.exe (user-mode) to log bytecode as it arrives.
```

### 14.4 Detection Signals

```
BEDaisy emits these signals to the backend:

  - OpenProcess attempts on the game PID (denied by callback)
  - DuplicateHandle attempts targeting the game PID
  - Foreign modules loaded into the game address space
  - Remote thread creation in the game process
  - Memory region protections changes (RWX) in the game process
  - Driver loads system-wide (via PsSetLoadImageNotifyRoutine)
  - Process creation system-wide (via PsSetCreateProcessNotifyRoutineEx)
  - File system activity on protected paths (via minifilter)
  - Anti-debug triggers from the in-game module
  - Behavioral anomalies flagged by dynamic scan bytecode
```

### 14.5 Research References

```
gmh5225/awesome-game-security BattlEye section:
  - BEDaisy.sys reverse engineering write-ups
  - BEService IOCTL documentation
  - Dynamic scan bytecode analysis threads
  - VM dispatcher research

UnKnoWnCheaTs forum:
  - BattlEye research subforum
  - Multi-year thread history documenting VM evolution
```

---

## 15. Vanguard (Riot) Architecture

### 15.1 Boot-Start Configuration

```
Riot Vanguard is unique among major anti-cheats in that it loads at boot.

vgc service configuration:
  StartType      : SERVICE_BOOT_START (0)
  - Loaded by winload.exe during early boot, before user logon.
  - This means vgk.sys is active from the moment Windows starts,
    regardless of whether the user has launched VALORANT.

Verify with:
  sc.exe qtype vgc
  sc.exe qc vgc

Expected output (annotated):
  SERVICE_NAME: vgc
  TYPE               : 1  KERNEL_DRIVER
  START_TYPE         : 0   BOOT_START
  ERROR_CONTROL      : 1   NORMAL
  BINARY_PATH_NAME   : \SystemRoot\System32\drivers\vgk.sys
```

### 15.2 Why Boot-Start Matters

```
A boot-start driver observes everything that loads after it:

1. Other drivers that load later (via PsSetLoadImageNotifyRoutine).
   - BYOVD attempts: the vulnerable driver loads AFTER vgk.sys, so
     vgk can flag it.
2. User-mode processes (via PsSetCreateProcessNotifyRoutineEx).
3. Module loads into any process (via PsSetLoadImageNotifyRoutine).
4. File system activity (via minifilter, registered at boot).

Implication for attackers:
  - Unloading vgk.sys requires admin privileges and is detectable
    (the Riot Client checks for driver presence on launch).
  - Loading a vulnerable driver before vgk.sys is impossible (vgk is
    loaded by winload at boot; vulnerable drivers load via user-mode
    NtLoadDriver much later).
  - The only way to defeat boot-start is to disable the service and
    reboot, which the Riot Client detects ("Vanguard not running").
```

### 15.3 Component Map

```
Riot Vanguard

[vgc service]
  - Type: KERNEL_DRIVER
  - StartType: BOOT_START
  - Binary: \SystemRoot\System32\drivers\vgk.sys

[Riot Client]
  - vgc.exe (user-mode companion to the kernel driver)
  - Launched on user logon
  - Communicates with vgk.sys via shared section + IOCTLs
  - Ships telemetry to Riot backend via TLS

[In-game module (VALORANT)]
  - Loaded into VALORANT.exe
  - Performs: anti-debug, integrity, behavioral capture
  - Reports to vgk.sys

[Backend]
  - Behavioral analysis (aim, reaction, click cadence)
  - HWID blacklist with TPM attestation
  - Signature distribution
```

### 15.4 Static Analysis of vgk.sys

```
Load vgk.sys in Ghidra:

1. Locate DriverEntry.
2. Identify callback registrations:
   - ObRegisterCallbacks (handle protection)
   - PsSetCreateProcessNotifyRoutineEx (process creation)
   - PsSetLoadImageNotifyRoutine (module load)
   - FltRegisterFilter (minifilter)
3. Identify the IOCTL interface used by vgc.exe.
4. Identify self-protection:
   - vgk.sys registers itself as protected (PsProtectedProcess-Lite-Windows).
   - Attempts to open a handle to the Riot Client or vgk.sys itself
     are denied by the callbacks.
5. Note obfuscation:
   - Heavy use of control-flow flattening.
   - String obfuscation (encrypted strings).
   - Indirect calls via function pointer arrays.
```

### 15.5 Controversy & Mitigations

```
Vanguard was controversial at launch (2020) because:

1. Boot-start kernel driver is always-on (privacy concern).
2. Driver bugs could BSOD the entire system.
3. The driver runs at highest privilege.

Riot's mitigations:
1. Vanguard only activates telemetry when a Riot game is running.
2. vgk.sys is WHQL-signed and reviewed by Microsoft.
3. The driver is reviewed by external security firms periodically.
4. Bug bounty program for Vanguard-specific findings.

Researcher obligations:
1. Report Vanguard flaws via Riot's security contact.
2. Coordinated disclosure with 90-day window.
3. Do NOT publish full exploit code.
```

---

## 16. Anti-Cheat Telemetry Research

### 16.1 Telemetry Signal Catalog

```
Client-side signals (what the driver captures):

Process events:
  - PID, parent PID, image path, command line, integrity level
  - Process creation / exit timestamp
  - Thread creation / exit per process

Image load events:
  - Module name, base address, size
  - Module SHA-256 hash
  - Module signer certificate subject
  - Loaded into which PID

Handle events:
  - OpenProcess / OpenThread attempts on protected PIDs
  - Access mask requested
  - Caller PID and image path
  - Outcome (allowed / stripped / denied)

Memory events:
  - NtAllocateVirtualMemory with RWX
  - NtProtectVirtualMemory changing to RWX
  - WriteProcessMemory / ReadProcessMemory on protected PIDs
  - Module base + size for any newly-mapped memory

Thread events:
  - NtCreateThreadEx on remote process
  - Thread start address (anomalous if pointing into RWX memory)
  - APC injection (NtQueueApcThread)

File events:
  - Writes to game binary paths
  - Writes to save game data
  - Writes to anti-cheat installation paths

Registry events:
  - Writes to anti-cheat registry keys
  - Writes to driver service keys

Network events:
  - Outbound connections from non-game processes
  - Inbound connections to game-related ports
```

### 16.2 Backend Correlation

```
Backend receives the above signals and correlates:

1. Cross-signal correlation:
   - Process A opened a handle on the game PID
   - Then module X loaded into the game
   - Then thread Y started in the game with anomalous start address
   - → High-confidence flag

2. Temporal correlation:
   - Same HWID produced N handle-open attempts over T seconds
   - → Flag for review

3. Account correlation:
   - Same HWID seen on multiple accounts
   - → Flag for ban evasion

4. Statistical correlation:
   - Player accuracy distribution shifted by +N sigma over T games
   - → Flag for aim assist

5. Hardware correlation:
   - HWID hash matches a previously-banned hardware
   - → Auto-ban
```

### 16.3 Hardware ID (HWID)

```
HWID composite (collected client-side):

  - Disk serial (SMART / WMI Win32_DiskDrive)
  - MAC address (primary NIC, per adapter)
  - SMBIOS / motherboard serial (Win32_BaseBoard)
  - BIOS serial (Win32_BIOS)
  - CPU ID (CPUID instruction)
  - TPM EK certificate hash (TPM 2.0 attestation)
  - GPU serial (where exposed via DXGI)
  - Display EDID (where exposed)
  - Battery serial (on laptops)

Backend hashing:
  - Each identifier is normalized, hashed (SHA-256), and stored.
  - A composite HWID hash is computed by combining all sub-hashes.
  - On ban, the composite hash is added to a blacklist.
  - On new login, the composite hash is compared to the blacklist.

Spoofing research (educational):
  - Most identifiers can be spoofed by intercepting WMI / SMBIOS calls.
  - TPM EK is the hardest: it requires breaking TPM hardware or
    obtaining a fraudulent TPM certificate.
  - The composite hash is hard to spoof without leaving traces.
```

### 16.4 TPM Attestation

```
Windows 11 + TPM 2.0 enables remote attestation:

1. TPM has an Endorsement Key (EK) certificate burned in at manufacturing.
2. The TPM can sign a PCR (Platform Configuration Register) quote.
3. The quote proves the boot chain integrity (UEFI, bootloader, kernel).
4. The anti-cheat backend can verify the quote using the EK certificate.

Implications:
  - An attacker cannot fake PCR values without breaking TPM hardware.
  - Disabling TPM / Secure Boot is detectable (quote fails to verify).
  - Modifying the boot chain (e.g. to load a malicious hypervisor
    before Windows) breaks the PCR values, detectable via attestation.

Counter-research:
  - DMA attacks (PCIe cards with direct memory access) bypass TPM
    attestation because they operate after the boot chain.
  - FPGA-based PCIe spoofers exist but are expensive and detectable
    via timing analysis.
```

### 16.5 Server-Side Behavioral Detection

```
Even with perfect client-side evasion, the server still sees behavior.

Behavioral signals:
  - Aim accuracy: distribution over time
  - Reaction time: histogram
  - Mouse movement cadence: FFT of mouse delta
  - Click timing: jitter entropy
  - Crosshair placement: angle to nearest enemy
  - Movement speed: position delta per tick
  - Loot pickup patterns
  - Communication patterns (voice / chat cadence)

Server-side models:
  - Logistic regression baseline (cheap, fast)
  - Gradient-boosted trees (XGBoost, LightGBM) for tabular features
  - CNN / LSTM on time-series features (mouse movement, click stream)
  - Per-player baseline + deviation score

Key insight:
  - Client-side evasion cannot defeat behavioral models because
    the models observe the *output* of player behavior, not the
    input (cheat tool) that produced it.
  - An aimbot that perfectly mimics human jitter is indistinguishable
    from a human; at that point the competitive impact is bounded.
```

---

## 17. Detection Engineering (Blue Side)

### 17.1 Detection Signal Design

```
For each offensive technique catalogued in this payloads file, design
a corresponding detection signal:

Offensive                      Detection
---------                      ---------
Cheat Engine memory scan       - Rapid OpenProcess attempts
                               - Window enumeration: "Cheat Engine"
                               - Image load: CE DLLs in game PID

BYOVD load                     - PsSetLoadImageNotifyRoutine fires
                               - Driver SHA-256 in blocklist
                               - Service creation with kernel binPath

Direct syscall stub            - Memory region marked X but not in any
                                 loaded module
                               - Thread start address in unmapped memory

Manual mapping                 - Thread start address in RWX region
                                 not in PEB.Ldr
                               - Memory region with RWX protection
                                 and no file backing

Hardware breakpoint            - DR0-DR7 non-zero in any thread
                               - VEH registered with EXCEPTION_SINGLE_STEP
                                 filter

DKOM                           - PsActiveProcessHead walk vs CID table
                               - EPROCESS hash mismatch
                               - Token Privileges anomaly

Hypervisor                     - Timing anomalies (RDTSC delta)
                               - CPUID.1:ECX[31] set
                               - MSR read anomalies
```

### 17.2 Signature Rotation Cadence

```
Recommended cadence for anti-cheat developers:

In-game module:
  - Re-lay-out code section every 7-14 days
  - Rotate exported function names every release
  - Obfuscate control flow (control-flow flattening)
  - String encryption with per-build keys

Kernel driver:
  - Rotate IOCTL codes every release
  - Rotate shared-section names every release
  - Rotate altitude within the 389000-389999 range per major release
  - Hash-sign the driver's .text section; verify at runtime

Backend:
  - Rotate scan bytecode daily for VM-based products (BattlEye model)
  - Rotate server-side detection model weights weekly
  - A/B test new detection rules before full rollout

Why rotation matters:
  - Static analysis write-ups age quickly
  - Pointer tables built by attackers break on every rotation
  - Detection rules deployed server-side don't have to ship to clients,
    so they can change daily without client updates
```

### 17.3 Telemetry Correlation Matrix

```
Define a two-of-three rule: an event must fire in at least two of:

  { kernel driver, in-game module, backend behavioral }

to escalate to a ban.

Example correlation matrix:

  Event                            Driver   Module   Backend
  -------------------------------  ------   ------   -------
  Cheat Engine attached            X        -        -
  Foreign module loaded into game  X        X        -
  Aim accuracy spike               -        -        X
  Reaction time anomaly            -        -        X
  Known-bad driver hash loaded     X        -        -
  HWID match to banned account     -        -        X
  OpenProcess stripped by callback X        -        -

Two-of-three escalation triggers:
  - Cheat Engine attached (driver) + foreign module in game (driver + module)
    → escalate
  - Aim accuracy spike (backend) + reaction time anomaly (backend)
    → escalate (both backend; consider as one strong signal)
  - Known-bad driver loaded (driver) + HWID match (backend)
    → escalate immediately
```

### 17.4 Hardware Binding Spec

```
For new anti-cheat deployments:

1. Collect HWID composite on first launch (after user consent).
2. Store HWID hash on backend, bound to account.
3. On every login, recompute HWID hash; compare.
4. If hash changes:
   - Allow login but flag for review
   - Require additional authentication (email, SMS, authenticator)
5. On ban:
   - Add HWID hash to blacklist
   - Block future logins from any account with same HWID hash
   - After 30 days, allow appeal process
6. TPM attestation (Windows 11+):
   - Request PCR quote on every launch
   - Verify via EK certificate
   - If quote fails, downgrade trust and require additional factors
```

### 17.5 AI-Driven Detection Guidance

```
Feature engineering (per-player, per-match):

  Mouse:
    - Delta FFT (frequency spectrum of mouse movement)
    - Acceleration histogram
    - Micro-correction count per second
    - Smoothness score (jitter / total movement)

  Aim:
    - Crosshair-to-enemy angle over time
    - Time-to-target distribution
    - Headshot rate per weapon
    - Aim accuracy vs distance

  Click:
    - Click timing entropy
    - Click-to-target latency distribution
    - Burst pattern (multi-click spacing)

  Movement:
    - Position delta per tick
    - Velocity profile
    - Path regularity (straight-line vs jittered)

Model architecture (per signal class):

  Tabular features (aim accuracy, reaction time):
    - XGBoost / LightGBM classifier
    - Per-player baseline; deviation score as primary feature

  Time-series (mouse movement, click stream):
    - 1D CNN or LSTM
    - Window size: 5-30 seconds
    - Output: probability of automated input

Decision threshold:
  - Keep threshold server-side; rotate weekly
  - Require high-confidence (>0.95) for auto-ban
  - Medium-confidence (0.7-0.95) for manual review queue
  - Low-confidence (<0.7) for telemetry-only logging
```

### 17.6 Coordinated Disclosure Pathway

```
When a researcher discovers an anti-cheat flaw:

1. Do NOT publish immediately.
2. Locate the vendor's security contact:
   - Riot Games: security@riotgames.com, https://hackerone.com/riot
   - Epic Games (EAC): security@epicgames.com
   - BattlEye: support@battleye.com (security tag)
   - FACEIT: security@faceit.com
   - Activision: activision.com/legal/security
3. Write a report with:
   - Affected product and version
   - Reproduction steps in an isolated lab
   - Conceptual write-up (no full exploit code)
   - Suggested remediation
4. Allow 90 days for remediation (industry standard).
5. Coordinate publication after the fix ships.
6. Publish only the conceptual write-up, not full exploit code.
7. Credit the vendor for fast remediation where deserved.

Templates:
   - Use the HackerOne or Bugcrowd report template if available.
   - Otherwise, follow the CERT/CC vulnerability disclosure template.
```

---

## 18. Quick Reference Cheat Sheet

### 18.1 Enumeration Commands

```powershell
# Services
Get-Service | Where-Object { $_.Name -match 'Easy|Battle|vgc|vgk|FACEIT|ESEA' }

# Driver signatures
driverquery /si | findstr /I "Easy Battle Vanguard vgk FACEIT"

# Driver file signatures
Get-AuthenticodeSig -FilePath 'C:\Windows\System32\drivers\vgk.sys'

# Minifilters
fltmc filters
fltmc instances

# Service config
sc.exe qc vgc
sc.exe qtype vgc
```

### 18.2 WinDbg Quick Commands

```
// Modules
lm t n                    // list all loaded modules
lm m Easy*                // filter
lm vm BEDaisy             // verbose info on a module

// Processes
!process 0 0              // list all processes (brief)
!process 0 7              // list all processes (verbose)
!process 0 0 game.exe     // find a process by name

// Objects and handles
!handle                   // handle table of current process
!object \Device\*         // list device objects
!devobj <addr>            // device object details

// Minifilter
!fltkd.filters            // all registered minifilters
!fltkd.filter <addr>      // filter details
!fltkd.frames             // frames

// Callbacks (conceptual)
bp nt!NtOpenProcess
bp nt!MmCopyVirtualMemory
bp nt!ObpCallPreOperationCallbacks

// Process / thread info
!peb                      // current process PEB
!teb                      // current thread TEB
!thread                   // current thread details

// Memory
!address                  // virtual address space summary
!virtual <addr>           // VAD entry for an address
!pte <addr>               // page table entry

// Symbols
.reload /f                // reload symbols
x nt!*CreateProcess*      // find symbols matching pattern
```

### 18.3 PowerShell Quick Patterns

```powershell
# Open handle on a protected PID (will be denied if anti-cheat active)
$proc = Get-Process -Name "research_target"
try {
    $handle = [Kernel32]::OpenProcess(0x10, $false, $proc.Id)  # PROCESS_VM_READ
    if ($handle -eq 0) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "OpenProcess failed: Win32 error $err"
    }
} catch {
    Write-Host "Exception: $_"
}

# Enumerate loaded modules in kernel
Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } |
    Select-Object Name, Path, State | Format-Table -AutoSize

# Verify a driver's catalog signature (Windows 10 21H2+)
$sig = Get-AuthenticodeSig -FilePath 'C:\Windows\System32\drivers\vgk.sys' -VerifyCat
$sig | Format-List *
```

### 18.4 BYOVD Cheat Sheet

```powershell
# Clone the catalog
git clone https://github.com/magicsword-io/LOLDrivers.git C:\research\LOLDrivers

# Find candidates
Get-ChildItem C:\research\LOLDrivers\drivers\*.json |
  Select-String -Pattern 'capcom|dbutil|gdrv|RTCore' |
  Select-Object -First 10

# Load a sample
sc.exe create RTCore type= kernel start= demand binPath= "C:\research\samples\RTCore64.sys"
sc.exe start RTCore
driverquery /si | findstr /I "RTCore"

# Cleanup
sc.exe stop RTCore
sc.exe delete RTCore
```

### 18.5 Cheat Engine Quick Workflow

```
1. Attach to research target (NOT production game).
2. First Scan: Exact Value = <starting value>.
3. Change value in target.
4. Next Scan: Exact Value = <new value>.
5. Repeat until 1-4 candidates remain.
6. Right-click → "Find out what writes to this address".
7. Right-click → "Pointer scan" → max level 7, max offset 0x2000.
8. Restart target; re-resolve pointer chain.
```

### 18.6 ScyllaHide Quick Workflow

```
1. Launch ScyllaHide x64 as Administrator.
2. Select profile: VEH Extreme.
3. Click Start.
4. Launch research target.
5. Attach x64dbg.
6. Verify: PEB.BeingDebugged == 0, NtGlobalFlag == 0.
7. Note residual kernel-mode signals (DebugActive flag, debug objects).
```

### 18.7 Anti-Cheat Quick Reference

| Product | Driver | Service | Start | Notable Feature |
|---------|--------|---------|-------|------------------|
| EAC | `EasyAntiCheat.sys` | `EasyAntiCheat.exe` | On-demand | Minifilter altitude 389120 |
| BattlEye | `BEDaisy.sys` | `BEService.exe` | On-demand | VM-based dynamic scans |
| Vanguard | `vgk.sys` | `vgc.exe` | **Boot-start** | TPM attestation, always-on |
| Ricochet | (per-title) | `bootstrapper.exe` | Boot-start | Server-side + kernel hybrid |
| FACEIT | (custom) | FACEIT AC client | On-demand | Community match integration |
| ESEA | (custom) | ESEA Client | On-demand | Community match integration |

### 18.8 Mitre Mapping

| Technique | MITRE ID |
|-----------|----------|
| BYOVD (signed driver abuse) | T1068 (Exploitation for Privilege Escalation) |
| Kernel driver autostart (boot-start) | T1547 (Boot or Logon Autostart) |
| Defense evasion (callback stripping, anti-debug) | TA0005 (Defense Evasion) |
| Process injection (manual mapping) | T1055 (Process Injection) |
| Debugger evasion | T1622 (Debugger Evasion) |
| Direct syscalls | T1106 (Native API) |
| Hardware breakpoint | T1055 (Process Injection) |
| DKOM | T1562 (Impair Defenses) |
| Hypervisor-based | T1055 (Process Injection, sub-technique VM context) |

### 18.9 Educational References

```
gmh5225/awesome-game-security
  URL: https://github.com/gmh5225/awesome-game-security
  The canonical starting point for anti-cheat research.

s4dbrd.github.io
  URL: https://s4dbrd.github.io/
  Title: "How Kernel Anti-Cheats Work: A Deep Dive"
  Long-form technical primer.

magicsword-io/LOLDrivers
  URL: https://github.com/magicsword-io/LOLDrivers
  BYOVD catalog. Updated regularly.

Microsoft Learn
  URL: https://learn.microsoft.com/en-us/windows/security/
  Sections: WDAC, HVCI, vulnerable driver blocklist.

UnKnoWnCheaTs forum
  URL: https://www.unknowncheats.me/
  Multi-game anti-cheat research subforums.

CVEs referenced:
  - CVE-2018-8120   capcom.sys
  - CVE-2021-21551  dbutil_2_3.sys
  - CVE-2018-19320  gdrv.sys
  - CVE-2019-16098  RTCore64.sys
```

### 18.10 Ethical Commitment (Reiterated)

```
As a researcher using this payloads reference:

  - I work only in an isolated lab.
  - I never target production game clients or live matches.
  - I respect the terms of service of every game I do not own.
  - I report flaws via coordinated disclosure before publishing.
  - I refuse requests to build or distribute tooling for active cheating.
  - I cite the public research community and contribute back.

This payloads reference documents techniques for the explicit purpose
of enabling security research and improving anti-cheat engineering.
It is not a guide for deploying functional game cheats.
```
