# embedded-rtos-security — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-09 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **83/100 (Excellent)** | **Findings**: P0:0 P1:0 P2:1 P3:2
> **Wave 1 Batch 1** (4th SKILL assessed)

## Quick Assessment Dashboard

| Dimension | Score (1-5) | Rationale |
|-----------|-------------|-----------|
| 1. Compliance | **5** | 0/0/0 |
| 2. Content Completeness | **5** | payloads 2891 lines + test-cases 256 lines + 3 guides; 18 H2 + 37 H3 (highest subsection count in batch) |
| 3. Command Syntax | **4** | 6/10 commands available on VM (binwalk/sasquatch/ghidra analyzeHeadless); qemu/firmwalker/jefferson missing |
| 4. References | **5** | 16 URLs + 13 CVEs — best in batch |
| 5. MITRE/OWASP Alignment | **4** | 6 ATT&CK T-codes (T1049/T1055/T1068/T1210/T1499/T1548); frontmatter only T1548 |
| 6. Usability | **4** | Strong RTOS coverage (VxWorks/QNX/FreeRTOS/ThreadX/Zephyr); commercial-tool barrier |
| **Weighted Total** | **83/100** | **Excellent** — top of Wave 1 Batch 1 |

## Usage Instructions

### What this SKILL does
RTOS exploitation across major embedded operating systems: VxWorks (Wind River), QNX (BlackBerry), FreeRTOS, ThreadX, Zephyr, RIOT-OS. Covers firmware extraction → static RE → dynamic emulation → exploit.

### When to use it
1. IoT device pentest with custom RTOS (not Linux)
2. ICS/SCADA device audit (most PLCs run VxWorks or proprietary RTOS)
3. Medical device security (many run QNX or VxWorks 653)
4. Automotive ECU reverse engineering (AUTOSAR Classic often on RTOS)
5. Aerospace / DO-178C safety-critical software review

### How to start
1. **Extract firmware**: `binwalk -e firmware.bin` (or `binwalk -X` for raw extract)
2. **Identify RTOS**: look for strings "VxWorks", "QNX", "FreeRTOS", version markers in extracted filesystem
3. **Static RE in Ghidra**: load firmware with correct processor (ARM/MIPS), use Ghidra's RTOS loaders if available
4. **Emulate with QEMU**: `qemu-system-arm -M vexpress-a9 -kernel firmware.bin` (RTS-specific emulation may need custom QEMU configs)
5. **Hunt for known CVEs**: cross-reference SKILL's 13 CVE table against extracted version

### Common pitfalls
- **VxWorks WINDML debug agent** (port 17185): often left enabled on production; allows memory read/write
- **QNX Qconn** (port 8000): similar debug backdoor
- **FreeRTOS stack canaries**: weak by default; use `--disable-stack-protector` flag detection
- **ThreadX trace FIFO**: useful forensics if extracted intact
- **Zephyr Kconfig**: misconfigurations often leave debug shell enabled

### Cross-references
- `firmware-reverse` (firmware analysis with Linux focus) — switch when device runs Linux
- `binary-reverse` (general binary RE) — switch when binaries extracted and need disassembly
- `hardware-security` (UART/JTAG) — switch for hardware debug interface access
- `ics-fieldbus-attack` — switch when RTOS device is in OT context
- `automotive-vehicle-security` — switch when targeting AUTOSAR ECUs

## Capability Assessment Detail

### D1: 5/5 | D2: 5/5 (3 guides + rich subsection coverage)

### D3: 4/5
- **6/10 commands PASS**: binwalk ✓, sasquatch ✓, Ghidra analyzeHeadless ✓, Python numpy/scipy ✓
- **4/10 missing**: qemu-system-arm, qemu-system-mips, firmwalker, jefferson
- **Evidence**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 5/5
- 16 URLs + 13 CVEs (best reference density in batch)
- References include: CVE-2019-12260 (VxWorks), CVE-2019-11890 (FreeRTOS), etc.

### D5: 4/5
- 6 ATT&CK T-codes in body; frontmatter `T1548-Abuse Elevation Control Mechanism` captures only 1 of 6
- Should expand to include T1049 System Network Connections, T1055 Process Injection, T1068 Exploitation for Privilege Escalation, T1210 Exploitation of Remote Services, T1499 Endpoint Denial of Service

### D6: 4/5
- Strengths: 18 H2 sections, 5 RTOS covered separately
- Weaknesses: commercial tools (VxWorks Workbench, QNX Momentics) are not installable on Kali; payloads should note this clearly

## Findings & Priorities

| ID | Priority | Description | Recommended Fix |
|----|----------|-------------|-----------------|
| F-001 | P2 | qemu-system-arm / qemu-system-mips missing in Kali 2026.1 default | Add `apt install qemu-system-arm qemu-system-mips` to payloads prerequisites |
| F-002 | P2 | firmwalker / jefferson missing | Add `pip install jefferson` + clone `firmwalker` from github.com/craigz28/firmwalker |
| F-003 | P3 | Frontmatter mitre field narrow (1 of 6 T-codes) | Expand to enumerate all 6 T-codes |
| F-004 | P3 | Test cases thin (256 lines vs 2891 payload lines, ratio 8.8%) | Add ≥15 test cases |

## Validation Evidence

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off
- Reviewer: Claude (Wave 1 Batch 1, SKILL 2/5)
- Approved by: _______________ Date: _______
