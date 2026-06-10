---
name: hardware-security
description: "Hardware and embedded system security testing covering physical interface exploitation, firmware extraction and analysis, side-channel attacks, RFID/NFC cloning, and fault injection."
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
  domain: hardware
  tool_count: 0
  guide_count: 5
---




# Skill: Hardware Security

> **Supplementary Files**:
> - `payloads.md` — Hardware attack commands, debug interface payloads, firmware extraction one-liners, and RFID/NFC cloning commands organized by attack phase
> - `test-cases.md` — Structured test cases for UART root shell access, SPI firmware extraction, JTAG memory dump, firmware secret scanning, and RFID card cloning
> - `guides/` — Deep-dive methodology guides for embedded firmware analysis and hardware assessment

## Summary

Hardware Security skill domain covering hardware operations.

**Domain**: hardware

## Description

Hardware and embedded system security testing covering physical interface exploitation, firmware extraction and analysis, side-channel attacks, RFID/NFC cloning, and fault injection. This skill addresses the full lifecycle of hardware penetration testing: from physical reconnaissance of an unknown device through debug interface access, firmware acquisition, static analysis, and exploitation.

Runtime context: Kali Linux 2025-2 (ARM64). Physical hardware tools (UART adapters, logic analyzers, SPI flash programmers, Proxmark3) are required for active engagement phases.

Difference from `binary-reverse`: binary-reverse focuses on analyzing binaries already in hand (reverse engineering, decompilation, patching). This skill handles the upstream problem of physically acquiring firmware from a target device and identifying hardware-level attack vectors before binary analysis begins.

## Use Cases

- IoT device security assessment (routers, smart home devices, IP cameras)
- Embedded firmware audit for proprietary devices without public firmware
- RFID/NFC security testing (access cards, smart cards, key fobs)
- Industrial control system (ICS/SCADA) hardware security review
- Hardware-based authentication bypass (JTAG debug, UART shell)
- Supply chain hardware integrity verification (detecting implants, backdoors)
- Bootloader security assessment (secure boot bypass, U-Boot exploitation)
- Medical device security testing

## Methodology

### Phase 1: Physical Reconnaissance

**Goal**: Identify all external interfaces and collect device intelligence before applying probes.

- Photograph all PCB surfaces; annotate visible chip markings
- Look up FCC ID on fcc.gov to obtain internal photos, test reports, and sometimes full schematics
- Identify chip families from markings: SoC, flash chip, EEPROM, RF modules
- Map all exposed connectors: USB, UART headers, JTAG/SWD pads, SPI test points, I2C headers
- Note unpopulated PCB footprints — these often hide debug headers removed for production
- Record chip datasheets for pinout reference

**Tools**: Multimeter, magnification lens, logic analyzer, FCC ID database (fcc.gov), Shodan for firmware version fingerprinting

### Phase 2: Debug Interface Access

**Goal**: Establish a communication channel with the device at a privileged level.

**UART (Universal Asynchronous Receiver/Transmitter):**
- Probe candidate pins with multimeter for 3.3 V or 5 V idle-high TX line
- Try common baud rates: 115200, 57600, 38400, 19200, 9600
- Connect with USB-to-UART adapter (CP2102, CH340, FTDI FT232R)
- Many devices expose a root shell or U-Boot console on UART

**JTAG/SWD (Joint Test Action Group / Serial Wire Debug):**
- Identify JTAG pins (TDI, TDO, TCK, TMS, TRST, GND) using JTAGulator or UrJTAG
- Connect OpenOCD with appropriate target configuration
- Use JTAG to halt the CPU, dump memory, and read/write registers

**SPI/I2C:**
- Attach logic analyzer to candidate bus lines during device boot to capture traffic
- Identify clock, data, chip-select lines
- Use Bus Pirate or Raspberry Pi to replay or intercept transactions

### Phase 3: Firmware Extraction

**Goal**: Obtain a complete binary image of the device firmware for offline analysis.

Methods in preference order:
1. **JTAG readout** — halt CPU, dump flash memory ranges via OpenOCD `dump_image`
2. **SPI flash direct read** — desolder or clip onto SPI NOR/NAND flash chip, use `flashrom` with CH341A programmer
3. **UART bootloader** — interrupt U-Boot at startup, use `md` (memory display) or TFTP to extract
4. **Firmware update interception** — capture OTA update via MITM proxy or download from vendor
5. **Filesystem from update package** — vendor-supplied `.bin` or `.zip` update files often contain the full filesystem

Verify extracted image: `md5sum firmware.bin`, compare with known-good hash if available.

### Phase 4: Firmware Analysis

**Goal**: Unpack the firmware and identify vulnerabilities in the embedded system.

```
firmware.bin
  ↓ binwalk -B (signature scan)
  ↓ binwalk -e (extract embedded filesystems)
  ↓ unsquashfs / jefferson / cramfsck (mount filesystem)
  ↓ strings + grep (find secrets, hardcoded credentials)
  ↓ find . -name "*.conf" -o -name "*.sh" (audit configs and scripts)
  ↓ radare2 / Ghidra (reverse engineer key binaries)
  ↓ semgrep / custom patterns (vulnerability pattern scan)
```

Key targets: `/etc/passwd`, `/etc/shadow`, web server configs, init scripts, private keys, API tokens, hardcoded IPs.

### Phase 5: Exploitation

**Goal**: Demonstrate impact of identified vulnerabilities with working proof-of-concept.

- **UART root shell**: If bootloader drops to root shell, document full system access
- **Bootloader bypass**: Interrupt U-Boot, set `bootargs` to single-user mode or disable secure boot checks
- **RFID cloning**: Use Proxmark3 to read and emulate access cards
- **Credential reuse**: Use extracted credentials against web interface, SSH, Telnet
- **Command injection**: Exploit web interface vulnerabilities identified through firmware code review
- **Fault injection**: Voltage or clock glitching to bypass secure boot (specialized hardware required)

## Tools

| Tool | Purpose |
|------|---------|
| binwalk | Firmware signature scanning and filesystem extraction |
| flashrom | SPI/parallel flash chip read and write via programmer |
| openocd | JTAG/SWD debugging interface for ARM, MIPS, AVR |
| proxmark3 | RFID/NFC card reading, cloning, and emulation |
| sigrok / pulseview | Logic analyzer capture and protocol decoding |
| avrdude | AVR microcontroller programming and flash read |
| JTAGulator | Automated JTAG/UART pin discovery |
| Bus Pirate | Universal serial interface for SPI, I2C, UART, JTAG |
| radare2 | Command-line binary reverse engineering framework |
| strings / grep | Static string analysis in firmware binaries |
| jefferson | JFFS2 filesystem extraction |
| sasquatch | Extended squashfs extraction (non-standard compressions) |
| firmwalker | Automated firmware filesystem vulnerability scanner |
| minicom / picocom | Serial terminal for UART communication |

## Orchestration

**ECC Loop Pattern**: Sequential Pipeline

**Rationale**: Hardware security testing follows a strict physical dependency chain. You cannot extract firmware without first identifying debug interfaces, and you cannot perform meaningful vulnerability analysis without firmware in hand. Each phase gates on the success of the previous one — skipping reconnaissance leads to missed interfaces, and skipping extraction leaves analysis working on assumptions. The Sequential Pipeline enforces this physical causality.

**Integration**:
- Feeds into: `binary-reverse` (deep binary analysis of extracted firmware), `security-review` (audit firmware configs, secrets, and services), `chronicle` (document findings and evidence)
- Consumes from: `search-first` (device CVEs, known firmware vulnerabilities, FCC database), `repo-scan` (when vendor source code is available)

**Cross-Skill Pipeline**:
```
search-first → [device CVEs, known vulnerabilities, FCC database lookup]
     ↓
hardware-security → [Phase 1: physical interface identification and chip mapping]
     ↓
hardware-security → [Phase 2-3: debug access + firmware extraction + hash verification]
     ↓
binary-reverse → [deep binary analysis: decompilation, vulnerability discovery]
     ↓
security-review → [audit firmware configs, hardcoded secrets, network services]
     ↓
verification-loop → [confirm exploitability of identified issues with PoC]
     ↓
chronicle → [archive findings, evidence, and final report]
```

**Quality Gate**: Before marking a hardware assessment complete —
1. All external physical interfaces identified and documented with photos
2. At least one debug interface accessed (UART, JTAG, or SPI)
3. Firmware extracted and MD5/SHA256 hash recorded
4. Filesystem successfully unpacked and inventoried
5. Secrets and credential scan completed with findings documented
6. Network services in firmware identified (telnetd, httpd, sshd, ftpd)
7. Exploitation path or proof-of-concept documented for each critical finding

## Report Template

```markdown
# Hardware Security Assessment Report
*Target: [device make/model/firmware version] | Date: [date] | Scope: [physical access level]*

## Executive Summary
[Overall risk rating, key findings summary, physical access requirements]

## Device Intelligence
- FCC ID: [if applicable]
- Processor: [SoC make/model]
- Flash: [chip make/model/capacity]
- Interfaces identified: [UART / JTAG / SPI / I2C / USB]

## Findings

### [SEVERITY] [Title]
- **CWE**: [CWE-ID]
- **Interface**: [UART / JTAG / SPI / Firmware / RFID]
- **Location**: [pin / binary path / register]
- **Description**: [what was found]
- **Evidence**: [reproduction steps, commands used]
- **Impact**: [what attacker with physical access can achieve]
- **Remediation**: [how to fix — disable debug port, secure boot, credential rotation]

## Summary Statistics
| Severity | Count |
|----------|-------|
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Info | N |
```
