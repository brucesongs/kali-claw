# AV/EDR Evasion: Kernel Bypass Deep Dive

## Overview

Modern EDR products place most of their detection logic in the Windows kernel: minifilter file system drivers, `PsSetCreateProcessNotifyRoutine` callbacks, ETW-TI (Event Tracing for Windows Threat Intelligence) providers, and Object Callbacks via `ObRegisterCallbacks`. Bypassing these mechanisms requires kernel-mode code execution, which itself is gated by Driver Signature Enforcement (DSE) on modern 64-bit Windows. This guide walks through the major classes of kernel bypass used by both red teams and adversaries, the supported attack primitives, and how to reproduce them responsibly in a lab.

The references at the end link to Microsoft documentation, the EDR-Rules repo, and authoritative write-ups from mandiant, CrowdStrike, and academic researchers.

## Prerequisites

To experiment with kernel bypass you need:

- A lab VM running Windows 10 22H2 or Windows 11 23H2 with kernel debugging enabled (msconfig > Boot > Advanced > Debug).
- WinDbg Preview installed on a separate host attached via named pipe or network.
- Test-signing enabled (`bcdedit /set testsigning on`) for unsigned driver work.
- A snapshot. Kernel-mode bugs will BSOD the host. Always roll back.

Never run kernel bypass code on production endpoints or on hosts with sensitive data. Defensive teams should also lab-reproduce these techniques to validate coverage.

## Direct Kernel Object Manipulation (DKOM)

DKOM directly modifies kernel objects in memory without using documented APIs. The classic example is hiding a process by unlinking its `EPROCESS` entry from the `ActiveProcessLinks` doubly-linked list.

Steps:

1. Resolve the kernel base address of `ntoskrnl.exe` using `NtQuerySystemInformation(SystemModuleInformation)`.
2. Find the PID of the process to hide via `NtQuerySystemInformation(SystemProcessInformation)`.
3. Locate that process's `EPROCESS` structure by walking the list.
4. Calculate the offset of `ActiveProcessLinks` (varies per OS build; use the symbols or `dt _EPROCESS` in WinDbg).
5. unlink: `entry->Blink->Flink = entry->Flink; entry->Flink->Blink = entry->Blink;`

Modern EDRs detect DKOM by walking the list separately using `PsActiveProcessHead` cross-references and by querying the CSRSS process list. PatchGuard also flags certain kernel structure modifications.

Hands-on PoC structure (kernel driver):

```c
// Hide current process via DKOM
PLIST_ENTRY entry = (PLIST_ENTRY)((PUCHAR)currentEprocess + activeProcessLinksOffset);
entry->Blink->Flink = entry->Flink;
entry->Flink->Blink = entry->Blink;
entry->Flink = entry->Blink = entry;
```

Validate using Task Manager, `tasklist`, and `Process Explorer`. A hidden process will not appear but its threads and handles remain valid. EDR vendors (Elastic, SentinelOne) cross-check the PspCidTable against the ActiveProcessLinks and will alert.

## SSDT Hooking on Modern OSes

The System Service Descriptor Table (SSDT) was the classic Windows XP-era hook target. Microsoft hardened this with PatchGuard (Kernel Patch Protection) on x64 in Vista+, making SSDT hooking unstable and short-lived.

However, adversaries still use SSDT restoration analysis for red-teaming. The pattern:

1. Read the current SSDT via `__readmsr(0xC0000082)` to locate `KiSystemCall64`.
2. Walk to `KeServiceDescriptorTable`.
3. Compare entries to the original kernel SSDT snapshot.
4. Re-monkey-patch entries that an EDR may have hooked (legitimate EDRs do NOT hook SSDT anymore — they use minifilters and callbacks — so finding an SSDT hook suggests malware).

This technique is now mostly educational. Hands-on: use SysInternals' `SSDTView` (community) to enumerate the SSDT and validate PatchGuard integrity. Avoid patching SSDT in production labs because PatchGuard will BSOD within minutes.

## Callback Unregistering (PsSetCreateProcessNotifyRoutine)

EDR products register process-creation callbacks via `PsSetCreateProcessNotifyRoutineEx`. When `CreateProcess` fires, the callback receives parent PID, image path, and command line. Adversaries disable these callbacks by:

1. Locating the `PspCreateProcessNotifyRoutine` array inside `ntoskrnl.exe` (find via signature scan after `PsSetCreateProcessNotifyRoutineEx`).
2. Replacing each non-null entry with `NULL`.

Hands-on driver code skeleton:

```c
// Find and disable process notify routines
PVOID *routines = (PVOID *)((PUCHAR)ntoskrnlBase + pspNotifyRoutineOffset);
for (int i = 0; i < 64; i++) {
    if (routines[i] != NULL) {
        InterlockedExchangePointer(&routines[i], NULL);
    }
}
```

EDR defense: Microsoft added `PsSetCreateProcessNotifyRoutineEx2` callback verification that cross-validates against an internal allowlist. SentinelOne and Elastic publish blogs noting that nulling callbacks is now detected by their own kernel-mode telemetry that survives this tampering.

## Minifilter Bypass

EDR file-system detection runs as a minifilter (`FltRegisterFilter`). Adversaries bypass by:

- Direct filesystem access via NtCreateFile on `\\.\C:` with FILE_READ_DATA, skipping the normal path the minifilter inspects.
- Using `NtCreateFile` with `FILE_OPEN_FOR_BACKUP_INTENT` to bypass certain filter logic.
- Directly invoking `FltCreateFile` from a loaded minifilter of your own (requires PPL or admin).

Red-team PoC: compile `pass-through` minifilter from Microsoft WDK sample, install it at a higher altitude than the EDR's, and intercept `IRP_MJ_CREATE` to log file access the EDR cannot see. The altitude ordering determines filter precedence.

Hands-on command sequence:

```cmd
fltmc instances
fltmc unload <EDR_filter_name>   # requires SYSTEM
fltmc load <redteam_filter_name>
```

Real-world example: The Turla "TinyTurla" backdoor (September 2021, Cisco Talos) used a kernel driver to disable Microsoft Defender file inspections.

## ETW and ETWTI Tampering

Event Tracing for Windows (ETW) is the backbone of Defender for Endpoint and many EDRs. The Threat Intelligence provider (ETW-TI, also called `EtwTi`) exposes kernel security events to user-mode subscribers like MsMpEng.exe.

Tampering techniques:

1. Patch `EtwNotificationRegister` to no-op.
2. Remove the ETW-TI provider GUID registration in the kernel.
3. Patch `NtTraceEvent` to return immediately.

The popular 2021 research "Tampering with ETW" by David Wells (and many follow-ups) showed that patching `EtwTraceEvent` in the kernel stops ETW flow.

Hands-on (user-mode ETW bypass, less risky):

```c
// Patch ntdll!EtwEventWrite to return immediately
PVOID etwWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
DWORD oldProtect;
VirtualProtect(etwWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
*(PUCHAR)etwWrite = 0xC3; // ret
VirtualProtect(etwWrite, 1, oldProtect, &oldProtect);
```

ETWTI (the kernel provider) requires a kernel driver to patch. SentinelOne and Elastic publish detections for this tampering pattern.

## PPL (Protected Process Light) Bypass

Protected Process Light, introduced in Windows 8.1, restricts what processes can attach to, read, or write to other PPL processes. Defender (MsMpEng.exe) and LSASS run as PPL.

Common bypasses:

- The 2018 "PPLDump" technique (using a forged system-trust EKU certificate and a vulnerable PPL-signed driver). Patched in subsequent builds.
- BYOVD (Bring Your Own Vulnerable Driver): load an old signed driver with a known CVE (e.g., `gdrv.sys` from Gigabyte, `RTCore64.sys` from Micro-Star, `dbutil_2_3.sys` from Dell) to perform arbitrary kernel R/W and then disable PPL.

Hands-on: Use `PPLDump.exe` (now patched, but instructive) or `PPLKiller` (offline with BYOVD). Validate that Microsoft Defender (MsMpEng) cannot be terminated or memory-dumped.

## Hyperhide and VM Detection Evasion

Many malware families detect VMs via timing (CPUID with `RDTSC` delta), via registry checks (HKLM\HARDWARE\DESCRIPTION\System\BIOS entries mentioning VMware/VirtualBox), or via checking MAC address OUIs.

The Hyperhide project (F-Secure, 2022) demonstrated that even nested virtualization can be detected via timing anomalies in CPUID leaves 0x40000000-0x40000100.

Hands-on evasion:

- Patch CPUID results in your hypervisor (custom KVM/QEMU hooks).
- Strip VMware Tools strings from registry and binaries.
- Use `Set-NICustomizer` style tooling to spoof MAC OUIs.

References: F-Secure Hyperhide (https://github.com/br-sn/Hyperhide), VMware hardening guides.

## DSE Bypass / BYOVD Attacks

Driver Signature Enforcement requires all kernel drivers to be signed by Microsoft. BYOVD attacks sidestep this by abusing previously-signed drivers that contain vulnerabilities. Notorious examples:

- `RTCore64.sys` (Micro-Star Afterburner, CVE-2019-16098): arbitrary kernel R/W via IOCTL.
- `dbutil_2_3.sys` (Dell BIOS Utility, CVE-2021-21551): arbitrary kernel R/W.
- `gdrv.sys` (Gigabyte): arbitrary kernel R/W.
- `ProcExp152.sys` (Sysinternals Process Explorer): older versions allow R/W.

The "loldrivers.io" project (living-off-the-land drivers) catalogues these. The Microsoft Vulnerable Driver Blocklist (HVCI blocklist) lists known-bad drivers; bypass requires using a driver not yet on the blocklist or disabling the blocklist via group policy (admin required).

Hands-on: Download a known-vulnerable signed driver from loldrivers.io, load via `sc create`, and use a wrapper like `KDMapper` (manual mapper, no signature required) for unsigned drivers in test mode.

Real-world: Lazarus used `RTCore64.sys` in 2022 to disable Microsoft Defender (CrowdStrike report). Microsoft added `RTCore64.sys` to its blocklist in October 2022.

## Bringing It Together: A Kernel Bypass Workflow

A complete kernel bypass chain:

1. Drop a signed vulnerable driver (BYOVD) on disk.
2. Load it as a service.
3. Use the driver's R/W primitives to find `ntoskrnl.exe` base and callback arrays.
4. Disable process and thread notify routines.
5. Disable ETW-TI provider registration.
6. Patch `EtwEventWrite` in `ntdll.dll` (user-mode side).
7. Load your payload with no telemetry reaching the EDR.

Defenders should monitor for: service creation of unusual driver names, registry writes to `HKLM\SYSTEM\CurrentControlSet\Services` for new driver binaries, and the Microsoft Vulnerable Driver Blocklist events under Event ID 3023 from CodeIntegrity.

## Object Callback Unregistering (ObRegisterCallbacks)

Beyond process and thread notify routines, EDRs also use `ObRegisterCallbacks` to intercept handle operations on protected processes. The callback receives a `OB_PRE_OPERATION_INFORMATION` structure when `OpenProcess` is invoked against MsMpEng, LSASS, or other PPL-protected targets, allowing the EDR to strip access rights (e.g., remove `PROCESS_VM_READ`).

To bypass:

1. Locate the `CallbackListHead` global inside `ntoskrnl.exe` for both `PsProcessType` and `PsThreadType`.
2. Walk the doubly-linked list, identifying each entry by `ObCallback->Operations` and `ObCallback->PreOperation`.
3. Identify the entries registered by your target EDR (you can match by comparing the callback address against the EDR driver's loaded image range).
4. Unlink or zero out the `PreOperation` and `PostOperation` pointers.

Hands-on driver code:

```c
// Walk ObCallback list for PsProcessType
POB_CALLBACK_ENTRY pEntry = (POB_CALLBACK_ENTRY)callbackListHeadFlink;
while (pEntry != (POB_CALLBACK_ENTRY)callbackListHead) {
    if (pEntry->PreOperation && isEDRDriver((PVOID)pEntry->PreOperation)) {
        InterlockedExchangePointer((PVOID*)&pEntry->PreOperation, NULL);
        InterlockedExchangePointer((PVOID*)&pEntry->PostOperation, NULL);
    }
    pEntry = (POB_CALLBACK_ENTRY)pEntry->CallbackListEntry.Flink;
}
```

SentinelOne, Elastic, and Microsoft Defender for Endpoint all publish detection logic for this tampering. Microsoft added cross-checks in 22H2 that scan the ObCallback list against a snapshot taken at boot; mismatches trigger PatchGuard-equivalent BSODs in hardened configurations.

## KdReferences and Anti-Anti-Debug

EDRs sometimes attach kernel debuggers or rely on `KdRefreshDebuggerNotPresent` to detect debugging. Adversaries flip `KdDebuggerEnabled` in the kernel and `NtGlobalFlag` in PEB to mislead EDRs that think they are running in a debug environment.

Hands-on (user mode):

```cpp
// Clear NtGlobalFlag heap-debug flags
PPEB peb = (PPEB)__readgsqword(0x60);
#ifdef _WIN64
    DWORD_PTR* gflag = (DWORD_PTR*)((PUCHAR)peb + 0xBC);
#else
    DWORD_PTR* gflag = (DWORD_PTR*)((PUCHAR)peb + 0x68);
#endif
*gflag &= ~0x70; // clear FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE
```

This tricks naive EDR checks that gate behavior on debug flags.

## Real-world Kernel Driver Examples

- **RTCore64.sys** (Micro-Star Afterburner, CVE-2019-16098): Exposes IOCTL 0x80002048 that maps physical memory. Used by Lazarus in 2022. Microsoft blocklisted October 2022.
- **dbutil_2_3.sys** (Dell BIOS Utility, CVE-2021-21551): IOCTL-based arbitrary kernel R/W. Used by multiple ransomware affiliates in 2022-2023.
- **gdrv.sys** (Gigabyte): Classic R/W primitive used by Capcom rootkit and later by multiple Chinese-state groups.
- **iqvw64e.sys** (Intel, CVE-2015-2291): Packed with arbitrary R/W and unsigned code execution. Used by RobbinHood ransomware (2019) and Lazarus (2022).
- **ProcExp152.sys** (older Sysinternals Process Explorer): Allowed R/W before being deprecated.
- **rtkio.sys** (Realtek): Used by BlackCat in 2023 to disable Defender.

Hands-on: Download `RTCore64.sys` from loldrivers.io, then write a minimal C++ loader that calls `DeviceIoControl(hDevice, 0x80002048, ...)` to read physical memory. Print the result to validate primitive access. Always snapshot your VM first.

## Detection and Defense

Defenders should layer the following:

- **Microsoft Vulnerable Driver Blocklist** (enabled by default on new Windows installs): Blocks known-bad drivers from loading. Validate via `wdac` policies.
- **HVCI (Hypervisor Code Integrity)**: Forces kernel code integrity under VBS, blocking unsigned drivers even with admin rights. Pair with Credential Guard.
- **Driver file event monitoring**: Alert on any new file dropped into `\Windows\System32\drivers\` outside of approved installers.
- **Service creation telemetry**: Event ID 7045 ("Service installed") for any service binary path containing `.sys` outside the standard path.
- **ObCallback list integrity checks**: Custom cross-checks against a boot snapshot, raising an alert on any mismatch.

EDR-Rules (https://github.com/VT-SEC-LAB/EDR-Rules) maintains a community-curated set of detection rules for kernel tampering patterns. Integrate these into your SIEM.

## Hands-on Lab Setup

```cmd
:: Enable test signing (reboot required)
bcdedit /set testsigning on

:: Enable kernel debugging
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

:: Verify driver signature enforcement state
bcdedit /enum | findstr "testsigning nointegritychecks"
```

Attach WinDbg via named pipe (VMware: `\\.\pipe\com_1`) or via TCP. Use `lm vm nt` to dump `ntoskrnl.exe` symbols. Resolve `PsSetCreateProcessNotifyRoutineEx` to find the `PspCreateProcessNotifyRoutine` array offset.

For BYOVD practice, use `RTCore64.sys` (signed, no test-mode needed, present in blocklist). Disable blocklist on lab host via GPO to test.

## References

1. Microsoft kernel callbacks documentation - https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/
2. Microsoft Vulnerable Driver Blocklist - https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
3. loldrivers.io catalogue - https://www.loldrivers.io/
4. Elastic protections rules GitHub - https://github.com/elastic/protections
5. Mandiant BYOVD research - https://www.mandiant.com/resources/blog/blog-post/arcanus-security-cobra-strike
6. CrowdStrike Lazarus BYOVD report (RTCore64.sys) - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-intrusion/
7. SentinelOne ETW tampering write-up - https://www.sentinelone.com/labs/
8. Hyperhide project (F-Secure) - https://github.com/br-sn/Hyperhide
9. PPLDump research - https://github.com/mattifestation/PPLDump
10. Microsoft minifilter WDK sample - https://github.com/microsoft/Windows-driver-samples/tree/main/filesys/miniFilter/passThrough
11. EDR-Rules community repository - https://github.com/VT-SEC-LAB/EDR-Rules
12. VX-Underground kernel driver collection - https://www.vx-underground.org/
13. Microsoft PatchGuard / KPP documentation - https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing
14. `dbutil_2_3.sys` CVE-2021-21551 advisory - https://www.dell.com/support/kbdoc/en-us/000186050/dsa-2021-088-dell-client-platform-security-update-for-dell-driver-improper-access-control-vulnerability
15. CVE-2019-16098 (RTCore64.sys) - https://nvd.nist.gov/vuln/detail/CVE-2019-16098
