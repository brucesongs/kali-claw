---
name: firmware-reverse
description: "Firmware reverse engineering covers the full pipeline from raw firmware image acquisition through filesystem extraction, static and dynamic analysis, full-system emulation, and vulnerability/backdoor detection."
origin: openclaw
version: "0.1.19"
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
  domain: firmware
  tool_count: 18
  guide_count: 3
  mitre: "TA0002-Execution"
---

# Firmware Reverse Engineering

> **Supplementary Files**:
> - `payloads.md` -- Firmware extraction, analysis, emulation, and vulnerability scanning commands organized by phase (6 sections, 25+ code blocks)
> - `test-cases.md` -- Structured test case templates (8 cases covering extraction, filesystem analysis, emulation, backdoor detection, and firmware diffing)
> - `guides/` -- Deep-dive methodology guides for extraction, Firmadyne emulation, and vulnerability/backdoor analysis

## Summary

Firmware Reverse skill domain covering firmware operations.

**Tools**: binwalk, unblob, sasquatch, jefferson, firmadyne, firmwalker, qemu-system, yara (+10 more)

**Domain**: firmware

**MITRE ATT&CK**: TA0002-Execution

## Description

Firmware reverse engineering covers the full pipeline from raw firmware image acquisition through filesystem extraction, static and dynamic analysis, full-system emulation, and vulnerability/backdoor detection. The core objective is to unpack proprietary firmware images, reconstruct the embedded filesystem, analyze binaries and configurations for security flaws, and emulate the firmware to perform dynamic testing.

This skill sits between `hardware-security` (which covers physical firmware dumping from flash chips and debug interfaces) and `binary-reverse` (which covers general-purpose disassembly and exploit development). Firmware reverse engineering focuses on the unique challenges of embedded firmware: non-standard filesystem formats, multi-architecture binaries (ARM, MIPS, PowerPC), monolithic firmware images with interleaved bootloaders/kernels/rootfs, and the need for full-system emulation to test network-accessible services.

Runtime context: Kali Linux 2025-2 (ARM64). Firmware samples may come from vendor download pages, OTA update interception, or hardware extraction (see `hardware-security` skill).

---

## Use Cases

1. **Router Firmware Audit** -- Extract router firmware, analyze web server binaries, find hardcoded credentials and command injection vulnerabilities
2. **IoT Device Security Assessment** -- Unpack IoT firmware images, enumerate services, identify backdoors and insecure default configurations
3. **IP Camera Firmware Analysis** -- Extract and analyze camera firmware for hardcoded credentials, remote access backdoors, and stream authentication bypasses
4. **Full-System Firmware Emulation** -- Use Firmadyne/QEMU to boot extracted firmware in an emulated environment for dynamic analysis
5. **Firmware Diffing for Patch Analysis** -- Compare old and new firmware versions to identify security patches and understand vulnerability root causes
6. **Embedded Backdoor Detection** -- Scan firmware for known backdoor patterns, suspicious binaries, and unauthorized remote access mechanisms
7. **Supply Chain Firmware Verification** -- Validate firmware integrity and detect unauthorized modifications or implants
8. **Compliance Audit** -- Verify firmware meets security baselines (no default credentials, no cleartext protocols, proper cryptographic implementations)

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **binwalk** | Firmware signature scanning, entropy analysis, and filesystem extraction | `binwalk -Me firmware.bin` |
| **unblob** | Multi-format firmware extraction with recursive unpacking | `unblob -e /tmp/out firmware.bin` |
| **sasquatch** | Non-standard SquashFS extraction (handles vendor-modified compressions) | `sasquatch squashfs.img` |
| **jefferson** | JFFS2 filesystem extraction from raw NAND flash images | `jefferson jffs2.img -d /tmp/jffs2-root/` |
| **firmadyne** | Automated firmware emulation framework using QEMU | `./sources/extractor/extractor.sh -b firmware.bin -sql &` |
| **firmwalker** | Automated firmware filesystem scanning for vulnerabilities and secrets | `bash firmwalker.sh /tmp/squashfs-root/ report.txt` |
| **qemu-system** | Full-system and user-mode emulation of ARM, MIPS, and other architectures | `qemu-system-arm -M versatilepb -kernel zImage -nographic` |
| **yara** | Pattern-matching engine for backdoor and malware detection in firmware | `yara -r backdoor_rules.yar /tmp/squashfs-root/` |
| **firmware-mod-kit** | Firmware extraction, analysis, and repacking toolkit | `extract-firmware.sh firmware.bin` |

---

## Methodology

### Attack Chain

```
Acquisition          Extraction            Analysis             Emulation            Vulnerability Research
(OTA/vendor/hw)  (binwalk/unblob)    (strings/firmwalker)  (firmadyne/qemu)     (yara/diffing/exploit)
      |                  |                    |                    |                      |
      v                  v                    v                    v                      v
  firmware.bin    squashfs-root/       secrets, configs,     running firmware,     CVE matching,
                  kernel, bootloader   binaries, scripts     network services      backdoor detection,
                                                                           exploit PoC
```

**Phase Details**:

1. **Firmware Acquisition** -- Obtain firmware image from vendor website, OTA update interception, or hardware extraction (see `hardware-security`). Verify image integrity with SHA256 hash.

2. **Filesystem Extraction** -- Use `binwalk` to scan for embedded signatures (SquashFS, JFFS2, CramFS, UBIFS, cpio). Extract with `binwalk -Me` for recursive extraction. When binwalk fails on vendor-modified filesystems, use `sasquatch` (SquashFS), `jefferson` (JFFS2), or `unblob` for multi-format extraction.

3. **Static Analysis** -- Scan extracted filesystem with `firmwalker` for automated vulnerability detection. Manually inspect `/etc/passwd`, `/etc/shadow`, init scripts, web server configs, and binary components. Use `strings` and `grep` to find hardcoded credentials, API keys, private keys, and suspicious URLs.

4. **Emulation** -- Use `firmadyne` for automated firmware ingestion, network configuration, and QEMU-based emulation. For manual emulation, use `qemu-system-arm`/`qemu-system-mips` with appropriate kernel and rootfs. Emulated firmware enables dynamic testing of web interfaces, network services, and authentication mechanisms.

5. **Vulnerability Research** -- Use `yara` rules to scan for backdoor patterns, shell metacharacters in CGI scripts, and known malicious binaries. Diff firmware versions to identify patched vulnerabilities. Cross-reference binary versions against known CVEs.

---

## Practical Steps

> **For detailed commands and payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. Firmware Extraction Workflow

```bash
# Step 1: Signature scan
binwalk firmware.bin

# Step 2: Recursive extraction
binwalk -Me -C /tmp/firmware_extracted firmware.bin

# Step 3: Handle non-standard SquashFS
sasquatch /tmp/firmware_extracted/*/squashfs.img

# Step 4: Handle JFFS2
jefferson /tmp/firmware_extracted/*/jffs2.img -d /tmp/jffs2-root/

# Step 5: Fallback to unblob for stubborn images
unblob -e /tmp/unblob_out firmware.bin
```

### 2. Automated Firmware Scanning

```bash
# firmwalker scan
bash firmwalker/firmwalker.sh /tmp/squashfs-root/ /tmp/report.txt

# Manual credential hunting
grep -r -i "password\s*=" /tmp/squashfs-root/ --include="*.conf" --include="*.sh"
find /tmp/squashfs-root/ -name "*.pem" -o -name "*.key" -o -name "id_rsa"
```

### 3. Firmadyne Emulation

```bash
# Extract and import firmware into Firmadyne
./sources/extractor/extractor.sh -b firmware.bin -sql

# Build network configuration
./scripts/snarfinterfaces.py

# Boot firmware in QEMU
./scripts/run.armel.sh <image_id>
```

### 4. YARA Backdoor Detection

```bash
# Scan extracted filesystem with custom rules
yara -r firmware_backdoors.yar /tmp/squashfs-root/ > /tmp/yara-findings.txt
```

---

## Defense Perspective

| Vulnerability Category | Firmware Manifestation | Detection Method |
|------------------------|----------------------|------------------|
| **Hardcoded Credentials** | Default passwords in `/etc/passwd`, web admin credentials in binaries | `grep -r`, firmwalker |
| **Command Injection** | CGI scripts passing user input to `system()` | strings + radare2 analysis |
| **Backdoors** | Undocumented Telnet/SSH access, hidden web endpoints | YARA rules, service enumeration |
| **Cleartext Protocols** | HTTP admin panels, Telnet enabled, unencrypted MQTT | Config file analysis, network emulation |
| **Outdated Components** | BusyBox 1.x, OpenSSL 1.0.x, outdated kernel | Version string extraction, CVE lookup |
| **Insecure Update** | No signature verification, HTTP-only updates, no rollback | Update script analysis, MITM testing |
| **Information Disclosure** | Debug strings, stack traces, verbose logging | strings extraction, emulation observation |
| **Weak Crypto** | DES, RC4, MD5 password hashes, hardcoded keys | Binary analysis, crypto pattern detection |

---

## Hacker Laws

| Law | Manifestation in Firmware Reverse Engineering |
|------|---------------------------------------------|
| **First Principles** | Understand the firmware image format at the binary level: bootloader offset, kernel load address, rootfs compression type. Tools like binwalk automate signature matching, but understanding *why* a signature matches at a given offset requires knowing the hardware memory map. |
| **Divergent Thinking First** | When standard extraction fails (vendor-modified SquashFS, custom compression), try alternative tools: sasquatch for modified SquashFS, unblob for multi-format, manual dd with offsets from entropy analysis. |
| **Trust but Verify** | Firmadyne emulation may not perfectly replicate hardware. Verify findings against the actual device when possible. Emulation can produce false negatives (service fails to start) or false positives (different memory layout changes exploit behavior). |
| **Skill Over Credentials** | Firmware analysis requires breadth across filesystems, CPU architectures, network protocols, and web technologies. The most effective analysts combine embedded Linux knowledge with web security intuition. |

---

## Common Pitfalls

1. **Assuming binwalk extracts everything** -- Many vendors use custom or modified filesystem formats that binwalk cannot parse. Always verify extraction completeness by checking file counts against expected filesystem size.

2. **Ignoring non-standard SquashFS** -- Vendors frequently modify SquashFS compression algorithms (custom LZMA parameters, non-standard block sizes). Standard `unsquashfs` will fail silently. Use `sasquatch` which patches unsquashfs to handle these variants.

3. **Emulation without network context** -- Booting firmware in QEMU without configuring the correct network interfaces will cause services to fail. Use Firmadyne's automated network setup or manually configure tap interfaces matching the firmware's expected network topology.

4. **Skipping entropy analysis** -- Firmware images with high entropy throughout are likely encrypted or packed. Attempting binwalk extraction on encrypted firmware wastes time. Run `binwalk -E` first to identify encrypted regions and focus extraction on unencrypted sections.

5. **Neglecting multi-architecture binaries** -- Embedded firmware often contains binaries for multiple architectures (ARM little-endian, MIPS big-endian, PowerPC). Use `file` on every extracted binary to identify the correct architecture before attempting analysis or emulation.

6. **Overlooking update mechanisms** -- The firmware update script is one of the highest-value analysis targets. It reveals signature verification logic, encryption keys, and update URLs. Analyzing update scripts often yields more actionable findings than analyzing application binaries.

---

## Cross-Skill Integration

- **`hardware-security`** -- Provides physical firmware extraction from flash chips (SPI, NAND, eMMC) via flashrom, OpenOCD, and UART. Firmware reverse engineering consumes the binary images produced by hardware extraction.
- **`binary-reverse`** -- Provides deep binary analysis of individual firmware executables using radare2, Ghidra, and GDB. Firmware reverse engineering produces the extracted binaries that binary-reverse then analyzes in detail.
- **`exploit-development`** -- Takes firmware vulnerabilities discovered during reverse engineering and develops reliable exploit code. Firmware analysis identifies the attack surface; exploit-development builds the weapon.
- **`web-sqli`** / **`web-xss`** / **`web-auth-bypass`** -- Many firmware devices expose web interfaces. After emulation, standard web application testing skills apply to the firmware's HTTP services.

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` -- Complete command collection (6 phases, 25+ code blocks)
- `test-cases.md` -- Structured test cases (8 case templates with prerequisites and expected results)

**Extended learning materials (guides/)**:
- `guides/firmware-extraction-filesystem.md` -- Deep dive into firmware extraction tools and filesystem analysis
- `guides/firmadyne-emulation.md` -- Complete Firmadyne setup, configuration, and dynamic analysis workflow
- `guides/firmware-vuln-backdoor.md` -- Vulnerability scanning, YARA rule writing, and backdoor detection methodology

**Related skills**:
- `skills/hardware-security/SKILL.md` -- Physical firmware extraction and hardware interface exploitation
- `skills/binary-reverse/SKILL.md` -- Binary disassembly, debugging, and exploit development
- `skills/exploit-development/SKILL.md` -- Exploit writing for discovered firmware vulnerabilities

**External resources**:
- [Firmadyne](https://github.com/firmadyne/firmadyne) -- Automated firmware emulation framework
- [unblob](https://github.com/onekey-sec/unblob) -- Multi-format firmware extraction tool
- [OWASP Firmware Security Testing Guide](https://owasp.org/www-project-firmware-security-testing-guide/)
- [Attacking Network Protocols (James Forshaw)](https://nostarch.com/networkprotocols) -- Relevant for analyzing proprietary firmware network services
