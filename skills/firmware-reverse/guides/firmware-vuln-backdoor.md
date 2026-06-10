# Firmware Vulnerability Analysis and Backdoor Detection

> Techniques for systematically scanning firmware for vulnerabilities, writing YARA rules to detect backdoor patterns, performing static analysis of hardcoded credentials, and comparing firmware versions to identify security patches.

## Introduction and Objectives

After extracting firmware and optionally emulating it, the vulnerability analysis phase systematically identifies security flaws across the firmware's configuration, binaries, and services. This guide combines automated scanning, manual inspection, and comparative analysis to build a comprehensive picture of the firmware's security posture, with specialized techniques for detecting intentional backdoor functionality.

**Learning objectives**:

- Run firmwalker for automated scanning of extracted firmware filesystems
- Write custom YARA rules to detect backdoor patterns in firmware binaries and scripts
- Perform multi-level hardcoded credential analysis (configuration files, binary strings, hash cracking)
- Diff firmware versions to identify security patches and their root causes
- Combine all techniques into a comprehensive analysis workflow

**Prerequisites**: An extracted firmware filesystem (see `firmware-extraction-filesystem.md`). Optionally, two firmware versions for diffing analysis. Understanding of common embedded device vulnerabilities and YARA rule syntax.

## Overview

After extracting and optionally emulating firmware, the vulnerability analysis phase identifies security flaws in the firmware's configuration, binaries, and services. This phase combines automated scanning (firmwalker, YARA), manual inspection (grep, strings, binary analysis), and comparative analysis (firmware diffing) to build a comprehensive picture of the firmware's security posture.

Backdoor detection is a specialized subset of vulnerability analysis focused on identifying intentional malicious functionality hidden in firmware. This includes undocumented remote access mechanisms, hardcoded credentials that cannot be changed, reverse shell listeners, and diagnostic interfaces left active in production builds.

## firmwalker Automated Scanning

firmwalker is a Bash-based scanner that searches extracted firmware filesystems for common vulnerability indicators. It checks for sensitive files, dangerous configurations, and potential backdoor indicators across the entire filesystem tree.

```bash
# Install firmwalker
git clone https://github.com/craigz28/firmwalker.git

# Run scan
bash firmwalker/firmwalker.sh /tmp/squashfs-root/ /tmp/firmwalker-report.txt

# Review findings
less /tmp/firmwalker-report.txt
```

firmwalker automatically searches for:

- `/etc/shadow` and `/etc/passwd` files with password hashes
- Shell scripts (`.sh`, `.py`, `.lua`, `.php`) that may contain credentials or dangerous commands
- Web server configurations and CGI scripts
- Hardcoded IP addresses and domain names
- SSL/TLS certificate files
- Binary executables (flagged for further analysis)
- Email addresses embedded in scripts or configs
- Common backdoor indicators (debug interfaces, hidden services)

**Customizing firmwalker**: The `firmwalker/firmwalker` data file contains the search patterns. Add custom patterns for specific device types or known backdoor signatures:

```bash
# Add custom search patterns to firmwalker data file
echo "backdoor" >> firmwalker/firmwalker
echo "debug_mode" >> firmwalker/firmwalker
echo "hidden_service" >> firmwalker/firmwalker
echo "reverse_shell" >> firmwalker/firmwalker
```

## YARA Rule Writing for Backdoor Patterns

YARA provides powerful pattern matching for detecting malicious code patterns in firmware binaries and scripts. Writing effective firmware-specific YARA rules requires understanding common backdoor techniques in embedded devices.

### Rule Template Structure

```yaml
rule DescriptiveRuleName {
    meta:
        description = "What this rule detects"
        severity = "critical|high|medium|low"
        author = "analyst name"
        reference = "CVE-XXXX-XXXX or advisory URL"
    strings:
        $s1 = "pattern1" ascii nocase
        $s2 = /regex_pattern/
        $hex1 = { 90 90 90 E8 [4] }   # hex pattern with wildcards
    condition:
        uint16(0) == 0x457f and     # ELF magic bytes
        filesize < 10MB and
        2 of ($s1, $s2, $hex1)
}
```

### Key Backdoor Patterns in Firmware

**Hidden Telnet/SSH Backdoors**: Some firmware images contain Telnet or SSH daemons that listen on non-standard ports or accept hardcoded credentials. These are sometimes added by manufacturers for remote support or by supply chain attackers.

```yaml
rule HiddenTelnetBackdoor {
    meta:
        description = "Detects hidden Telnet backdoor listening on non-standard ports"
        severity = "critical"
    strings:
        $s1 = "telnetd -p " ascii
        $s2 = "telnetd -l /bin/sh" ascii
        $s3 = "Authorization: Backdoor" ascii nocase
        $s4 = "X-Help-Command" ascii nocase
    condition:
        uint16(0) == 0x457f and
        any of ($s1, $s2, $s3, $s4)
}
```

**Command Injection in CGI Scripts**: Many embedded web servers pass HTTP parameters directly to shell commands via `system()` or `popen()` without sanitization. This is the most common vulnerability class in embedded web interfaces.

```yaml
rule CommandInjectionCGI {
    meta:
        description = "Detects CGI scripts that pass user input to shell commands"
        severity = "high"
    strings:
        $cgi1 = "QUERY_STRING" ascii
        $cgi2 = "REQUEST_URI" ascii
        $cgi3 = "CONTENT_LENGTH" ascii
        $danger1 = "system(" ascii
        $danger2 = "popen(" ascii
        $danger3 = "exec" ascii
    condition:
        any of ($cgi1, $cgi2, $cgi3) and
        any of ($danger1, $danger2, $danger3)
}
```

**Reverse Shell Patterns**: Firmware implants may initiate outbound connections to attacker-controlled servers, providing persistent remote access.

```yaml
rule ReverseShellPatterns {
    meta:
        description = "Detects reverse shell connection patterns"
        severity = "critical"
    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "nc -e /bin/sh" ascii nocase
        $s3 = "bash -i >& /dev/tcp" ascii
        $s4 = "socat exec:'bash -li' tcp" ascii nocase
        $s5 = "python -c 'import socket" ascii
        $s6 = "mkfifo /tmp/" ascii
    condition:
        any of ($s1, $s2, $s3, $s4, $s5, $s6)
}
```

### Running YARA Scans

```bash
# Scan entire extracted filesystem recursively
yara -r firmware_rules.yar /tmp/squashfs-root/ > /tmp/yara-results.txt

# Scan with matched string details
yara -r -s firmware_rules.yar /tmp/squashfs-root/

# Scan only ELF binaries
find /tmp/squashfs-root/ -type f -exec file {} \; | grep ELF | cut -d: -f1 | \
  xargs yara firmware_rules.yar

# Count matches per rule
yara -r -c firmware_rules.yar /tmp/squashfs-root/
```

## Static Analysis of Hardcoded Credentials

Hardcoded credentials are the most consistently found vulnerability in embedded firmware. The analysis targets multiple locations where credentials may be embedded.

**Level 1: Configuration Files**

```bash
FWROOT="/tmp/squashfs-root"

# Standard password files
cat "$FWROOT/etc/passwd"     # user accounts
cat "$FWROOT/etc/shadow"     # password hashes

# Configuration files with credentials
grep -r -i "password\s*=" "$FWROOT" --include="*.conf" --include="*.cfg" -l
grep -r -i "admin\s*=" "$FWROOT" --include="*.conf" --include="*.cfg" -l

# WiFi credentials
grep -r -i "wpa_passphrase\|wpa_psk\|wifi_key" "$FWROOT"

# Database credentials
grep -r -i "db_pass\|mysql_pass\|psql_pass" "$FWROOT"
```

**Level 2: Binary Analysis**

Credentials embedded in compiled binaries require `strings` extraction or disassembly:

```bash
# Extract strings from HTTP daemon (common target)
strings -n 8 "$FWROOT/bin/httpd" | grep -iE "password|admin|root|secret|key"
strings -n 8 "$FWROOT/bin/httpd" | grep -E "^.{6,20}$" | sort -u > /tmp/httpd_passwords.txt

# Check for base64-encoded credentials
strings "$FWROOT/bin/httpd" | grep -E "^[A-Za-z0-9+/]{16,}={0,2}$" | base64 -d 2>/dev/null

# Use radare2 for deeper analysis (see binary-reverse skill)
r2 -A "$FWROOT/bin/httpd"
iz~password     # search strings for "password"
axt @ sym.imp.system   # find all system() calls
```

**Level 3: Hash Cracking**

```bash
# Extract crackable hashes (exclude locked accounts)
grep -v "^[^:]*:[\*!]:" "$FWROOT/etc/shadow" > /tmp/fw-hashes.txt

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/fw-hashes.txt
john --show /tmp/fw-hashes.txt

# Crack with hashcat (faster for large hash sets)
# First identify hash format: $1$ = MD5, $5$ = SHA256, $6$ = SHA512
hashcat -m 500 /tmp/fw-hashes.txt /usr/share/wordlists/rockyou.txt    # MD5-crypt
hashcat -m 1800 /tmp/fw-hashes.txt /usr/share/wordlists/rockyou.txt   # SHA512-crypt
```

## Firmware Diffing for Update Analysis

Comparing two firmware versions (before and after a security patch) reveals exactly what the vendor fixed. This technique is valuable for understanding vulnerability root causes and developing 1-day exploits.

### Directory-Level Diffing

```bash
# Extract both versions
binwalk -e -C /tmp/fw_old old_firmware.bin
binwalk -e -C /tmp/fw_new new_firmware.bin

# Compare directory trees
diff -rq /tmp/fw_old/squashfs-root/ /tmp/fw_new/squashfs-root/

# Find changed files
diff -rq /tmp/fw_old/squashfs-root/ /tmp/fw_new/squashfs-root/ | grep "^Files "

# Find files only in old version (removed)
diff -rq /tmp/fw_old/squashfs-root/ /tmp/fw_new/squashfs-root/ | grep "^Only in /tmp/fw_old"

# Find files only in new version (added)
diff -rq /tmp/fw_old/squashfs-root/ /tmp/fw_new/squashfs-root/ | grep "^Only in /tmp/fw_new"
```

### Binary Diffing

For binary executables, directory-level diffing only shows that the file changed, not what changed inside. Binary diffing (using radare2, BinDiff, or Diaphora) reveals function-level changes:

```bash
# Quick function-level comparison using radare2
r2 -A /tmp/fw_old/bin/httpd -c "aflj" -q > /tmp/old_funcs.json
r2 -A /tmp/fw_new/bin/httpd -c "aflj" -q > /tmp/new_funcs.json

# Compare function lists
python3 -c "
import json
old = set(f['name'] for f in json.load(open('/tmp/old_funcs.json')))
new = set(f['name'] for f in json.load(open('/tmp/new_funcs.json')))
print('Added:', new - old)
print('Removed:', old - new)
print('Common:', len(old & new))
"

# Focus on security-relevant changes
# Added functions: new security checks, validation routines
# Removed functions: removed dangerous functionality
# Changed functions (same name, different size): patched vulnerabilities
```

### Interpreting Patch Differences

Security patches in firmware typically follow these patterns:

| Change Type | Security Implication |
|-------------|---------------------|
| Added bounds checking before buffer operations | Buffer overflow was fixed |
| Replaced `strcpy`/`sprintf` with `strncpy`/`snprintf` | Buffer overflow remediation |
| Added authentication check to CGI handler | Authentication bypass was fixed |
| Updated BusyBox or library version | Known CVE patched via component update |
| Changed password hash from MD5 to SHA256 | Weak crypto remediation |
| Added input validation to web form handler | Command injection or XSS fixed |
| Modified firewall rules in init scripts | Network exposure reduced |
| Added HTTPS redirect to web server config | Cleartext protocol remediation |

## Combining Techniques for Comprehensive Analysis

The most effective firmware security assessments combine all techniques in sequence:

1. **Extract** with binwalk/sasquatch/unblob
2. **Inventory** the filesystem structure and identify key binaries
3. **Auto-scan** with firmwalker for known vulnerability patterns
4. **YARA scan** with custom backdoor detection rules
5. **Manual grep/strings** for hardcoded credentials
6. **Diff** against previous firmware version (if available) to identify patches
7. **Emulate** with Firmadyne/QEMU for dynamic validation
8. **Cross-reference** binary versions against CVE databases

Each technique covers gaps in the others. firmwalker catches configuration issues, YARA catches binary-level backdoors, diffing reveals what the vendor already knows is broken, and emulation confirms findings dynamically.

## Hands-on Exercise: Firmware Vulnerability Analysis

Practice firmware vulnerability analysis and backdoor detection:

**Setup**:

```bash
# Install analysis tools
git clone https://github.com/craigz28/firmwalker.git
pip install yara-python
# Use an extracted firmware filesystem from the previous exercise
FWROOT="/tmp/squashfs-root"
```

**Exercise steps**:

1. Run firmwalker against the extracted filesystem and review the findings report
2. Add custom search patterns to firmwalker for device-specific backdoor indicators
3. Write three YARA rules: one for hidden Telnet backdoors, one for command injection in CGI scripts, and one for reverse shell patterns
4. Run YARA scan against all ELF binaries and scripts in the firmware
5. Perform Level 1 credential analysis: grep all configuration files for password strings
6. Perform Level 2 credential analysis: extract strings from the HTTP daemon binary
7. If password hashes are found, attempt cracking with john or hashcat using default wordlists
8. If two firmware versions are available, diff them and interpret the security implications of changes

**Validation criteria**: Identify at least three security findings across different vulnerability classes (credentials, configuration issues, binary-level patterns). Write YARA rules that produce no false positives on known-clean firmware files. Document all findings with severity ratings and remediation recommendations.

## References and Resources

- [firmwalker GitHub Repository](https://github.com/craigz28/firmwalker)
- [YARA Documentation](https://yara.readthedocs.io/)
- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)
- [Firmware Security Testing Methodology](https://github.com/scriptingxss/OWASP-IoT-Security-Verification-Standard-ISVS)
- [BinDiff for Binary Comparison](https://www.zynamics.com/bindiff.html)
- [CVE Details - Embedded Device Vulnerabilities](https://www.cvedetails.com/)
