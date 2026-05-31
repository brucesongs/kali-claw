# Firmware Extraction and Analysis Guide

> Techniques for dumping firmware from flash memory chips, unpacking firmware images, and performing binary analysis to discover vulnerabilities, backdoors, and hardcoded secrets.

## 1. Flash Memory Identification and Dumping

```bash
# Identify flash chip on PCB
# Common packages: SOIC-8 (SPI NOR), TSOP-48 (parallel NAND), BGA
# Read markings: manufacturer + part number (e.g., W25Q128 = Winbond 128Mbit SPI)

# Dump SPI flash with flashrom + CH341A programmer
sudo apt install flashrom
# Connect CH341A clip to SPI flash chip (while powered off or desoldered)
flashrom -p ch341a_spi -r firmware_dump.bin

# Verify dump integrity (read twice and compare)
flashrom -p ch341a_spi -r firmware_dump2.bin
md5sum firmware_dump.bin firmware_dump2.bin
# Both hashes must match

# For larger NAND flash, use SNANDer
git clone https://github.com/McMCCRU/SNANDer.git
cd SNANDer && make
./SNANDer -r firmware_nand.bin
```

## 2. Firmware Unpacking with Binwalk

```bash
# Initial analysis - identify embedded content
binwalk firmware_dump.bin

# Example output:
# DECIMAL    HEXADECIMAL  DESCRIPTION
# 0          0x0          uImage header, size: 1843200
# 64         0x40         LZMA compressed data
# 1843264    0x1C2000     Squashfs filesystem, little endian, version 4.0
# 3932160    0x3C0000     JFFS2 filesystem, little endian

# Extract all identified components
binwalk -e firmware_dump.bin

# For encrypted/obfuscated firmware, try entropy analysis
binwalk -E firmware_dump.bin
# High entropy (>0.9) throughout = likely encrypted
# Mixed entropy = compressed sections identifiable

# Manual extraction when binwalk fails
dd if=firmware_dump.bin of=kernel.lzma bs=1 skip=64 count=1843200
unlzma kernel.lzma

# Extract squashfs filesystem
dd if=firmware_dump.bin of=rootfs.squashfs bs=1 skip=1843264 count=2088896
unsquashfs rootfs.squashfs
ls squashfs-root/
```

## 3. Filesystem Analysis

```bash
# After extraction, analyze the root filesystem
cd squashfs-root/

# Find hardcoded credentials
grep -rn "password\|passwd\|secret\|key\|token" etc/ 2>/dev/null
cat etc/shadow
cat etc/passwd

# Find configuration files with sensitive data
find . -name "*.conf" -o -name "*.cfg" -o -name "*.ini" | \
  xargs grep -l "pass\|key\|secret" 2>/dev/null

# Identify web application files
find . -name "*.cgi" -o -name "*.php" -o -name "*.lua" -o -name "*.asp"

# Check for SSH keys
find . -name "id_rsa" -o -name "*.pem" -o -name "authorized_keys"

# Find startup scripts (persistence mechanisms, backdoors)
cat etc/init.d/rcS
cat etc/inittab
find . -name "*.sh" -exec grep -l "telnet\|dropbear\|ssh" {} \;

# Check for hardcoded API endpoints and keys
strings usr/bin/* | grep -iE "(api|http|key|token|aws|azure)" | sort -u
```

## 4. Binary Analysis with Ghidra

```bash
# Determine architecture for proper disassembly
file usr/bin/httpd
# Output: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1, dynamically linked

readelf -h usr/bin/httpd | grep -E "(Machine|Entry)"

# Launch Ghidra for reverse engineering
ghidraRun &
# Import binary: File > Import File > select binary
# Set correct processor: MIPS:LE:32:default (or ARM:LE:32:v7, etc.)
# Auto-analyze: Analysis > Auto Analyze

# Command-line analysis with Ghidra headless
analyzeHeadless /tmp/ghidra_project project_name \
  -import usr/bin/httpd \
  -processor MIPS:LE:32:default \
  -postScript FindCryptoConstants.java \
  -postScript ExportFunctions.py
```

```python
# Automated vulnerability pattern search with angr
import angr
import claripy

# Load the binary
proj = angr.Project('./usr/bin/httpd', auto_load_libs=False)

# Find dangerous function calls (command injection candidates)
cfg = proj.analyses.CFGFast()
for func_addr in cfg.kb.functions:
    func = cfg.kb.functions[func_addr]
    for block in func.blocks:
        for insn in block.capstone.insns:
            # Look for calls to system(), popen(), execve()
            if insn.mnemonic == 'jal':  # MIPS call instruction
                target = insn.operands[0].imm
                if target in cfg.kb.functions:
                    name = cfg.kb.functions[target].name
                    if name in ['system', 'popen', 'execve', 'doSystemCmd']:
                        print(f'Dangerous call at 0x{insn.address:08x}: {name}()')
```

## 5. Emulating Firmware with QEMU

```bash
# Full system emulation for dynamic analysis
# For MIPS little-endian firmware:
sudo apt install qemu-system-mips qemu-user-static

# User-mode emulation (single binary)
cp $(which qemu-mipsel-static) squashfs-root/usr/bin/
sudo chroot squashfs-root /usr/bin/qemu-mipsel-static /usr/bin/httpd

# Full system emulation with FirmAE
git clone https://github.com/pr0v3rbs/FirmAE.git
cd FirmAE
./init.sh

# Run firmware in emulated environment
sudo ./run.sh -r mips ./firmware_dump.bin
# This sets up networking, NVRAM, and boots the firmware
# Access emulated device at assigned IP

# Using Firmadyne for automated emulation
git clone https://github.com/firmadyne/firmadyne.git
cd firmadyne
./sources/extractor/extractor.py -b vendor -sql 127.0.0.1 \
  -np -nk ../firmware_dump.bin images
./scripts/getArch.sh ./images/1.tar.gz
./scripts/makeImage.sh 1
./scripts/inferNetwork.sh 1
./scripts/run.sh 1
```

## 6. Cryptographic Key Extraction

```bash
# Find crypto constants and keys in binary
# AES S-box detection
python3 << 'EOF'
import struct

AES_SBOX_START = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])

with open('firmware_dump.bin', 'rb') as f:
    data = f.read()

# Search for AES S-box (indicates AES implementation location)
offset = data.find(AES_SBOX_START)
while offset != -1:
    print(f'AES S-box found at offset 0x{offset:08x}')
    # Keys are often stored near the S-box or in .data section
    # Check surrounding memory for key-like patterns
    nearby = data[max(0, offset-256):offset]
    for i in range(0, len(nearby)-16, 4):
        candidate = nearby[i:i+16]
        entropy = len(set(candidate)) / 16.0
        if 0.6 < entropy < 1.0:  # Key-like entropy
            print(f'  Potential key at 0x{offset-256+i:08x}: {candidate.hex()}')
    offset = data.find(AES_SBOX_START, offset + 1)
EOF

# Extract certificates and private keys
find squashfs-root/ -name "*.pem" -o -name "*.crt" -o -name "*.key" | \
  while read f; do
    echo "=== $f ==="
    openssl x509 -in "$f" -text -noout 2>/dev/null || \
    openssl rsa -in "$f" -check 2>/dev/null
  done
```

## 7. Vulnerability Discovery Patterns

```bash
# Common firmware vulnerability patterns to search for:

# 1. Command injection in CGI handlers
grep -rn "system\|popen\|exec" squashfs-root/usr/lib/cgi-bin/ 2>/dev/null

# 2. Buffer overflows - strcpy/sprintf without bounds
strings -a usr/bin/httpd | grep -c "strcpy\|sprintf\|strcat\|gets"

# 3. Backdoor accounts
grep -E ":\\\$[0-9]\\\$|:!:" squashfs-root/etc/shadow
# Check for accounts with known default passwords

# 4. Debug interfaces left enabled
grep -rn "telnetd\|gdbserver\|uart\|console" squashfs-root/etc/ 2>/dev/null

# 5. Insecure network services
find squashfs-root/ -name "*.conf" -exec grep -l "0.0.0.0\|INADDR_ANY" {} \;

# 6. Outdated libraries with known CVEs
find squashfs-root/ -name "*.so*" -exec strings {} \; | \
  grep -oE "(OpenSSL|libcurl|busybox) [0-9]+\.[0-9]+\.[0-9]+" | sort -u
```

## 8. Firmware Modification and Reflashing

```bash
# Modify firmware (add backdoor for testing, patch vulnerabilities)
# WARNING: Only on devices you own and in authorized testing

# Repack squashfs with modifications
mksquashfs squashfs-root/ new_rootfs.squashfs \
  -comp xz -b 131072 -no-xattrs

# Rebuild full firmware image
# Calculate correct offsets from original binwalk output
dd if=firmware_dump.bin of=header.bin bs=1 count=1843264
cat header.bin new_rootfs.squashfs > modified_firmware.bin

# Pad to original size if needed
original_size=$(stat -c%s firmware_dump.bin)
truncate -s $original_size modified_firmware.bin

# Recalculate checksums if firmware has integrity checks
python3 -c "
import struct, zlib
with open('modified_firmware.bin', 'rb') as f:
    data = bytearray(f.read())
# Update CRC32 at known offset (device-specific)
crc = zlib.crc32(data[64:]) & 0xFFFFFFFF
struct.pack_into('<I', data, 60, crc)
with open('modified_firmware.bin', 'wb') as f:
    f.write(data)
"

# Flash modified firmware back
flashrom -p ch341a_spi -w modified_firmware.bin
```
