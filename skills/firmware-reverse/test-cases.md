# Firmware Reverse Engineering Test Cases

> This file is a companion to `SKILL.md`, providing structured firmware analysis test case templates.
> Purpose: Check each item during firmware security assessments to ensure no critical analysis steps are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-FWxxx | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [TC-FW001: Firmware Extraction and Filesystem Recovery](#tc-fw001-firmware-extraction-and-filesystem-recovery)
- [TC-FW002: Filesystem Structure and Inventory Analysis](#tc-fw002-filesystem-structure-and-inventory-analysis)
- [TC-FW003: Automated Vulnerability Scan with firmwalker](#tc-fw003-automated-vulnerability-scan-with-firmwalker)
- [TC-FW004: QEMU Firmware Emulation and Dynamic Analysis](#tc-fw004-qemu-firmware-emulation-and-dynamic-analysis)
- [TC-FW005: YARA Backdoor and Malware Detection](#tc-fw005-yara-backdoor-and-malware-detection)
- [TC-FW006: unblob Multi-Format Extraction](#tc-fw006-unblob-multi-format-extraction)
- [TC-FW007: Firmware Version Diffing for Patch Analysis](#tc-fw007-firmware-version-diffing-for-patch-analysis)
- [TC-FW008: Hardcoded Credential and Secret Extraction](#tc-fw008-hardcoded-credential-and-secret-extraction)

---

## TC-FW001: Firmware Extraction and Filesystem Recovery

- **Severity**: HIGH
- **Prerequisites**: Firmware binary obtained (vendor download, OTA interception, or hardware extraction)
- **Test Steps**:
  1. `file firmware.bin` -- identify raw image format
  2. `binwalk firmware.bin` -- scan for embedded signatures (SquashFS, JFFS2, CramFS, uImage, cpio)
  3. `binwalk -E firmware.bin` -- entropy analysis to identify encrypted vs. compressible regions
  4. `binwalk -Me -C /tmp/fw_extracted firmware.bin` -- recursive extraction to target directory
  5. If SquashFS extraction fails: `sasquatch squashfs.img` -- handle non-standard vendor compressions
  6. If JFFS2 detected: `jefferson jffs2.img -d /tmp/jffs2-root/` -- extract JFFS2 filesystem
  7. Verify extraction: `find /tmp/fw_extracted -type f | wc -l` -- confirm non-trivial file count (>100)
  8. Identify architecture of extracted binaries: `find /tmp/fw_extracted -type f -exec file {} \; | grep -E "ARM|MIPS"`
- **Expected Results**: Complete filesystem extracted with recognizable directory structure (`/bin`, `/etc`, `/usr`, `/var`). Architecture of embedded binaries identified (ARM/MIPS/PowerPC). No encrypted regions blocking extraction (if encrypted, note for remediation).
- **Reference**: payloads.md Sections 2.1--2.4

---

## TC-FW002: Filesystem Structure and Inventory Analysis

- **Severity**: HIGH
- **Prerequisites**: Firmware filesystem successfully extracted to `$FWROOT`
- **Test Steps**:
  1. `ls -la "$FWROOT/"` -- list top-level directory structure
  2. `find "$FWROOT" -type f | wc -l` -- count total files
  3. `find "$FWROOT" -type f -executable -exec file {} \; | grep -E "ARM|MIPS"` -- identify all executables and their architecture
  4. `cat "$FWROOT/etc/passwd"` -- check user accounts
  5. `cat "$FWROOT/etc/shadow"` -- check password hashes
  6. `find "$FWROOT" -perm -4000` -- find SUID binaries
  7. `find "$FWROOT" -name "*.sh" -path "*/init.d/*" -o -name "*.sh" -path "*/rc.d/*"` -- find init scripts
  8. `grep -r "telnetd\|sshd\|httpd\|ftpd\|dropbear" "$FWROOT/etc/"` -- enumerate enabled network services
  9. `find "$FWROOT" -name "*.cgi"` -- find CGI scripts (command injection targets)
  10. `strings "$FWROOT/bin/busybox" | grep "BusyBox v"` -- identify BusyBox version for CVE lookup
- **Expected Results**: Full inventory of executables, services, and configurations documented. Architecture confirmed for all binary components. Network services enumerated with configuration details. BusyBox and library versions recorded for CVE cross-referencing.
- **Reference**: payloads.md Section 3

---

## TC-FW003: Automated Vulnerability Scan with firmwalker

- **Severity**: HIGH
- **Prerequisites**: Extracted firmware filesystem available at known path
- **Test Steps**:
  1. `git clone https://github.com/craigz28/firmwalker.git` (if not already available)
  2. `bash firmwalker/firmwalker.sh "$FWROOT" /tmp/firmwalker-report.txt` -- run automated scan
  3. `cat /tmp/firmwalker-report.txt` -- review findings
  4. Cross-reference findings with manual analysis from TC-FW002
  5. Prioritize findings by severity:
     - CRITICAL: hardcoded credentials, private keys, backdoor indicators
     - HIGH: cleartext protocols, outdated software versions, CGI scripts with system() calls
     - MEDIUM: debug interfaces, verbose logging, information disclosure
  6. Validate top findings manually (verify false positives)
- **Expected Results**: firmwalker report generated covering: `/etc/shadow` and `/etc/passwd` contents, all shell scripts and binaries, web server configurations, hardcoded IPs and URLs, SSL/TLS certificates, and email addresses. Manual validation confirms at least 70% of automated findings as genuine.
- **Reference**: payloads.md Section 5.1

---

## TC-FW004: QEMU Firmware Emulation and Dynamic Analysis

- **Severity**: CRITICAL
- **Prerequisites**: Extracted firmware with identified architecture (ARM/MIPS), QEMU installed, kernel image and rootfs accessible
- **Test Steps**:
  1. Identify firmware architecture: `file "$FWROOT/bin/busybox"`
  2. **User-mode emulation (single binary testing)**:
     ```bash
     qemu-arm-static -L "$FWROOT" "$FWROOT/bin/busybox" --list
     qemu-arm-static -L "$FWROOT" "$FWROOT/bin/httpd"
     ```
  3. If user-mode fails (missing hardware dependencies), proceed to full-system emulation
  4. **Full-system emulation with Firmadyne**:
     ```bash
     # Extract and import
     python3 ./sources/extractor/extractor.py -b firmware.bin -sql -np -nk "firmware.bin" images
     # Identify architecture
     python3 ./scripts/getArch.py images/<id>.tar.gz
     # Build image
     python3 ./scripts/makeImage.sh <id>
     # Infer network
     python3 ./scripts/inferNetwork.sh <id>
     # Boot
     ./scripts/run.armel.sh <id>
     ```
  5. **Manual QEMU full-system emulation** (if Firmadyne fails):
     ```bash
     qemu-system-arm -M versatilepb -kernel zImage \
       -drive file=rootfs.ext2,if=ide -nographic \
       -append "root=/dev/sda console=ttyAMA0"
     ```
  6. After boot, enumerate running services: `netstat -tlnp` or `ss -tlnp`
  7. Scan emulated system from host: `nmap -sV -p- <emulated_ip>`
  8. Test web interface: `curl http://<emulated_ip>/` or open in browser
  9. Attempt default credentials against discovered services
- **Expected Results**: Firmware boots in QEMU (at least partially -- console prompt or network services accessible). At least one network service responds (HTTP, Telnet, SSH). Web interface accessible for dynamic testing. Default credentials tested against all running services.
- **Reference**: payloads.md Section 4

---

## TC-FW005: YARA Backdoor and Malware Detection

- **Severity**: CRITICAL
- **Prerequisites**: Extracted firmware filesystem, custom YARA rules for firmware backdoor patterns
- **Test Steps**:
  1. Create or obtain YARA rules targeting firmware backdoor patterns (see payloads.md Section 6.2 for rule templates):
     - Hidden Telnet/SSH backdoors
     - Reverse shell patterns
     - Hardcoded credentials
     - Command injection in CGI scripts
     - Debug interfaces in production
  2. `yara -r firmware_backdoors.yar "$FWROOT" > /tmp/yara-findings.txt` -- scan entire filesystem
  3. `yara -r -s firmware_backdoors.yar "$FWROOT" | tee /tmp/yara-detailed.txt` -- scan with string matching details
  4. Review findings and categorize:
     - Matched rules with matched strings = high confidence finding
     - Matched rules without matched strings = investigate further
  5. For each confirmed finding, document:
     - File path and type (binary, script, config)
     - Matched pattern and context
     - Severity assessment
  6. Validate findings: for binary matches, use `strings` or radare2 to confirm context (see `binary-reverse` skill)
- **Expected Results**: YARA scan completes across entire extracted filesystem. Any backdoor patterns flagged with file path and matched rule. False positive rate documented. Confirmed backdoor findings reported with severity and remediation guidance.
- **Reference**: payloads.md Section 6.1--6.2

---

## TC-FW006: unblob Multi-Format Extraction

- **Severity**: MEDIUM
- **Prerequisites**: Firmware image where binwalk extraction failed or produced incomplete results
- **Test Steps**:
  1. `pip install unblob` (if not already installed)
  2. `unblob --show-chunks firmware.bin` -- list detected chunks without extracting
  3. `unblob -e /tmp/unblob_out firmware.bin` -- extract all detected formats
  4. `unblob -e /tmp/unblob_out -v firmware.bin` -- verbose extraction with debug output
  5. Compare unblob results with previous binwalk extraction:
     ```bash
     diff -rq /tmp/fw_extracted/squashfs-root/ /tmp/unblob_out/squashfs-root/ 2>/dev/null
     ```
  6. Count extracted files: `find /tmp/unblob_out -type f | wc -l`
  7. Verify key directories present: `ls /tmp/unblob_out/*/squashfs-root/{bin,etc,usr} 2>/dev/null`
- **Expected Results**: unblob detects and extracts filesystem components that binwalk missed. File count in unblob output >= binwalk output. Key system directories (`/bin`, `/etc`, `/usr`) present and populated. Recursive extraction handles nested firmware containers (firmware within firmware).
- **Reference**: payloads.md Section 2.5

---

## TC-FW007: Firmware Version Diffing for Patch Analysis

- **Severity**: HIGH
- **Prerequisites**: Two firmware images (old version and patched version) for the same device
- **Test Steps**:
  1. Extract both versions:
     ```bash
     binwalk -e -C /tmp/fw_v1 old_firmware.bin
     binwalk -e -C /tmp/fw_v2 new_firmware.bin
     ```
  2. Compare directory trees: `diff -rq /tmp/fw_v1/squashfs-root/ /tmp/fw_v2/squashfs-root/ > /tmp/fw_diff.txt`
  3. Find modified files: `grep "^Files " /tmp/fw_diff.txt`
  4. Find added files (potential new security features): `grep "^Only in /tmp/fw_v2" /tmp/fw_diff.txt`
  5. Find removed files (potential backdoors removed): `grep "^Only in /tmp/fw_v1" /tmp/fw_diff.txt`
  6. Compare critical config files:
     ```bash
     diff -u /tmp/fw_v1/squashfs-root/etc/passwd /tmp/fw_v2/squashfs-root/etc/passwd
     diff -u /tmp/fw_v1/squashfs-root/etc/shadow /tmp/fw_v2/squashfs-root/etc/shadow
     ```
  7. Binary diff key executables (use `binary-reverse` skill for detailed analysis):
     ```bash
     r2 -A /tmp/fw_v1/bin/httpd -c "aflj" -q > /tmp/v1_funcs.json
     r2 -A /tmp/fw_v2/bin/httpd -c "aflj" -q > /tmp/v2_funcs.json
     diff /tmp/v1_funcs.json /tmp/v2_funcs.json
     ```
  8. Focus on security-relevant changes: added bounds checks, removed dangerous function calls, new authentication logic
- **Expected Results**: All added, removed, and modified files documented. Security-relevant changes identified (new bounds checks, removed hardcoded credentials, updated library versions). Function-level binary diff identifies patched vulnerability functions. Patch analysis reveals which CVE(s) the update addresses.
- **Reference**: payloads.md Section 6.3

---

## TC-FW008: Hardcoded Credential and Secret Extraction

- **Severity**: CRITICAL
- **Prerequisites**: Extracted firmware filesystem available at `$FWROOT`
- **Test Steps**:
  1. `cat "$FWROOT/etc/passwd"` -- enumerate user accounts
  2. `cat "$FWROOT/etc/shadow"` -- extract password hashes
  3. Filter crackable hashes: `grep -v "^[^:]*:[\*!]:" "$FWROOT/etc/shadow" > /tmp/fw-hashes.txt`
  4. Attempt hash cracking: `john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/fw-hashes.txt`
  5. Search config files for hardcoded passwords:
     ```bash
     grep -r -i "password\s*=" "$FWROOT" --include="*.conf" --include="*.cfg" --include="*.sh"
     ```
  6. Search for private keys:
     ```bash
     find "$FWROOT" -name "*.pem" -o -name "*.key" -o -name "id_rsa"
     grep -rl "BEGIN.*PRIVATE KEY" "$FWROOT"
     ```
  7. Search for API tokens:
     ```bash
     grep -r -E "(api_key|apikey|secret_key|access_token)\s*[:=]" "$FWROOT" -i
     ```
  8. Search binary executables for embedded credentials:
     ```bash
     find "$FWROOT" -type f -executable | while read f; do
       strings "$f" | grep -iE "password|admin|root|secret" && echo "  ^ in: $f"
     done 2>/dev/null
     ```
  9. Attempt discovered credentials against emulated firmware services (TC-FW004)
- **Expected Results**: All user accounts documented. Password hashes extracted and cracking attempted. At least one hardcoded password found in configuration files or binaries. Private keys and API tokens catalogued. Discovered credentials validated against emulated services.
- **Reference**: payloads.md Section 3.2

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Firmware Extraction | 2 | 0 | 2 | 0 | 0 |
| B. Vulnerability Scanning | 3 | 2 | 1 | 0 | 0 |
| C. Emulation & Dynamic Analysis | 1 | 1 | 0 | 0 | 0 |
| D. Backdoor Detection & Diffing | 2 | 1 | 1 | 0 | 0 |
| **Total** | **8** | **4** | **4** | **0** | **0** |

---

## Pass Criteria Checklist

- [ ] Firmware binary identified and entropy analysis completed
- [ ] Filesystem fully extracted with all directories and files intact
- [ ] Architecture of embedded binaries correctly identified
- [ ] Filesystem inventory documented (executables, services, configs)
- [ ] Hardcoded credentials and private keys catalogued
- [ ] Automated vulnerability scan (firmwalker) completed and findings validated
- [ ] Firmware successfully emulated in QEMU (at least partially)
- [ ] YARA backdoor scan completed with false positive rate documented
- [ ] Version diffing identifies security-relevant changes between firmware versions
- [ ] All findings documented with severity, reproduction steps, and remediation
