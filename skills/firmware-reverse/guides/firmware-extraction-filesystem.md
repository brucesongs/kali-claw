# Firmware Extraction and Filesystem Analysis

> Techniques for extracting filesystem images from firmware binaries, handling non-standard vendor formats, and analyzing the resulting directory structures for security assessment.

## Introduction and Objectives

Firmware extraction is the first and often most critical step in embedded device security assessment. Without successful extraction, all subsequent analysis (vulnerability scanning, backdoor detection, dynamic testing) is impossible. This guide covers the complete extraction toolkit, from automated signature scanning with binwalk to specialized tools for vendor-modified filesystem formats.

**Learning objectives**:

- Use binwalk for signature scanning, entropy analysis, and automated extraction
- Handle non-standard SquashFS variants with sasquatch when stock unsquashfs fails
- Extract JFFS2 filesystem images from NAND flash devices using jefferson
- Apply unblob as a fallback for exotic firmware formats
- Follow the extraction decision tree to systematically approach unknown firmware
- Validate extraction completeness by checking for essential filesystem elements

**Prerequisites**: A firmware binary image (obtained from vendor download, hardware flash dump, or firmware capture). Kali Linux with binwalk and extraction tools installed. Understanding of common embedded filesystem types (SquashFS, JFFS2, UBIFS, CramFS).

## Overview

Firmware extraction is the foundational step in firmware security analysis. Most embedded devices store their operating system in a monolithic firmware image that interleaves the bootloader, kernel, and root filesystem into a single binary blob. The extraction process identifies the boundaries of each component using magic byte signatures, extracts compressed filesystem images, and decompresses them into browsable directory trees.

The primary challenge is vendor diversity: each manufacturer may use different filesystem types (SquashFS, JFFS2, UBIFS, CramFS, ext2), different compression algorithms (LZMA, XZ, gzip, Zstandard), and sometimes custom modifications to standard formats that defeat stock extraction tools.

## binwalk: Signature Scanning and Extraction

binwalk is the primary firmware analysis tool. It scans binary files for known magic byte signatures to identify embedded filesystems, compressed data, bootloaders, and firmware headers. The signature database covers hundreds of known formats.

**Basic Workflow**:

```bash
# Step 1: Scan for signatures
binwalk firmware.bin
# Output shows decimal offset, hex offset, and description of each match

# Step 2: Entropy analysis to validate scan results
binwalk -E firmware.bin
# Spikes in entropy correspond to compressed/encrypted regions
# Flat low entropy = padding or plaintext
# Flat high entropy = encrypted or random data

# Step 3: Extract identified components
binwalk -e firmware.bin          # single-pass extraction
binwalk -Me firmware.bin         # recursive extraction (nested images)

# Step 4: Manual extraction when automatic fails
# Use offsets from scan output with dd
dd if=firmware.bin of=squashfs.img bs=1 skip=$((0x200000)) count=$((0x300000))
```

**When binwalk fails**: Vendor-modified filesystem formats are the most common failure mode. The magic bytes match (binwalk detects the filesystem), but the extraction tool (unsquashfs, etc.) fails because the vendor used non-standard compression parameters. In these cases, switch to specialized tools.

## sasquatch: Non-Standard SquashFS Extraction

SquashFS is the most common filesystem in embedded Linux devices (routers, cameras, IoT devices). Many vendors modify the SquashFS superblock or use custom LZMA parameters that the standard `unsquashfs` tool cannot handle. sasquatch is a patched version of unsquashfs that handles these non-standard variants.

```bash
# When standard unsquashfs fails with "Can't find a valid SQUASHFS superblock"
# or "LZMA decompression failed", use sasquatch

# Build sasquatch from source
git clone https://github.com/devttys0/sasquatch.git
cd sasquatch
./build.sh

# Extract non-standard SquashFS
sasquatch -d /tmp/squashfs-root extracted_squashfs.img

# If extraction still fails, try specifying endianness explicitly
sasquatch -be squashfs.img    # big-endian (MIPS, PowerPC)
sasquatch -le squashfs.img    # little-endian (ARM, x86)
```

Common scenarios requiring sasquatch: TP-Link routers with custom LZMA dictionaries, Netgear firmware with modified block sizes, and devices using Zstandard compression not yet in mainline unsquashfs.

## jefferson: JFFS2 Filesystem Extraction

JFFS2 (Journaling Flash Filesystem version 2) is used on NAND flash-based devices. Unlike SquashFS (which is read-only), JFFS2 is a writable filesystem optimized for flash memory with wear leveling. Raw JFFS2 images extracted from flash dumps often contain out-of-band (OOB) data that must be stripped before extraction.

```bash
# Install jefferson
pip install jefferson

# Extract JFFS2 filesystem image
jefferson jffs2.img -d /tmp/jffs2-root/

# For NAND flash dumps, you may need to strip ECC/OOB data first
# The exact method depends on the NAND chip and controller

# Verify extraction completeness
find /tmp/jffs2-root/ -type f | wc -l
ls -la /tmp/jffs2-root/etc/ 2>/dev/null
```

JFFS2 is common in older routers, NAS devices, and industrial control systems that use raw NAND flash instead of eMMC or SPI NOR.

## unblob: Multi-Format Extraction

unblob is a modern extraction tool designed to handle the wide variety of firmware formats that binwalk may not fully support. It uses a modular extraction system where each format has a dedicated handler. unblob also performs recursive extraction automatically, handling firmware-within-firmware scenarios common in multi-stage bootloaders.

```bash
# Install unblob
pip install unblob

# Extract all embedded formats
unblob -e /tmp/unblob_out firmware.bin

# Verbose mode for debugging
unblob -e /tmp/unblob_out -v firmware.bin

# Control recursion depth
unblob -e /tmp/unblob_out -d 3 firmware.bin

# Preview what would be extracted
unblob --show-chunks firmware.bin
```

Use unblob as a fallback when binwalk extraction is incomplete. unblob handles formats like AVM DL, D-Link Encrypted, ENGENIUS, and Ubiquiti firmware that binwalk may only detect but not extract.

## firmware-mod-kit: Extraction and Repacking

firmware-mod-kit provides both extraction and repacking capabilities. The repacking feature is useful for creating modified firmware images to test on actual hardware (e.g., adding a debug shell, modifying configuration defaults, or inserting test instrumentation).

```bash
# Install firmware-mod-kit
git clone https://github.com/rampageX/firmware-mod-kit.git
cd firmware-mod-kit
./install.sh

# Extract firmware
./extract-firmware.sh firmware.bin

# Modify extracted filesystem
# cp custom_script.sh /tmp/squashfs-root/usr/bin/
# chmod +x /tmp/squashfs-root/usr/bin/custom_script.sh

# Repack modified firmware
./build-firmware.sh
```

**Caution**: Only flash modified firmware to devices you own and have explicitly designated as test devices. Modified firmware can brick devices permanently.

## Extraction Decision Tree

When approaching an unknown firmware image, follow this decision sequence:

1. **Run `binwalk firmware.bin`** -- If signatures are found, proceed with `binwalk -Me`. This handles 70%+ of consumer firmware.

2. **If SquashFS extraction fails** -- Switch to `sasquatch`. This handles most vendor-modified SquashFS variants.

3. **If JFFS2 is detected** -- Use `jefferson` instead of binwalk's built-in JFFS2 handler.

4. **If binwalk detects but cannot extract** -- Use `unblob` as a fallback for exotic formats.

5. **If entropy is uniformly high** -- The firmware may be encrypted. Look for encryption keys in the bootloader (often extracted separately) or search for the vendor's decryption routine in the U-Boot environment.

6. **If all automated tools fail** -- Manual analysis with `hexdump`, entropy plots, and dd-based extraction using known offsets from similar devices or vendor documentation.

## Post-Extraction Validation

After extraction, validate completeness by checking for essential filesystem elements:

- `/bin/` or `/sbin/` contains executables (busybox, httpd, dropbear)
- `/etc/` contains configuration files (passwd, shadow, init.d)
- `/lib/` contains shared libraries matching the binary architecture
- `/dev/` may contain device node definitions
- File count is reasonable for the device type (typically 200-5000 files for consumer firmware)

If the extracted filesystem is missing key directories, the extraction is likely incomplete. Check binwalk output for additional filesystem signatures at higher offsets that may not have been extracted recursively.

## Hands-on Exercise: Firmware Extraction

Practice firmware extraction techniques using real firmware images:

**Setup**:

```bash
# Install all extraction tools
sudo apt install binwalk squashfs-tools
pip install jefferson unblob
git clone https://github.com/devttys0/sasquatch.git && cd sasquatch && ./build.sh
```

**Exercise steps**:

1. Download two different firmware images (e.g., a TP-Link router and a Netgear router)
2. Run `binwalk firmware1.bin` on each and compare the signatures found
3. Perform entropy analysis with `binwalk -E` and identify compressed vs encrypted regions
4. Extract with `binwalk -Me` and verify the extracted filesystem structure
5. If SquashFS extraction fails, apply sasquatch with the appropriate endianness flag
6. Validate extraction completeness using the post-extraction checklist
7. Attempt extraction with unblob on a firmware where binwalk produced incomplete results
8. Document which tools succeeded for each firmware type and any manual intervention required

**Validation criteria**: Successfully extract filesystems from both firmware images with complete directory trees (bin, etc, lib directories present). Identify at least one case where sasquatch or unblob was needed over standard binwalk extraction.

## References and Resources

- [binwalk GitHub Repository](https://github.com/ReFirmLabs/binwalk)
- [sasquatch - Modified unsquashfs](https://github.com/devttys0/sasquatch)
- [jefferson - JFFS2 Extraction](https://github.com/sviehb/jefferson)
- [unblob GitHub Repository](https://github.com/onekey-sec/unblob)
- [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [OWASP Firmware Analysis Guide](https://owasp.org/www-project-iot-security-verification-standard/)
