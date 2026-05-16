# Hardware Security -- Test Cases

> This file is a companion to `SKILL.md`, providing structured test cases for hardware security assessment methodology.
> Purpose: Systematic verification of hardware attack surface coverage — debug interfaces, firmware acquisition, credential extraction, and RFID cloning.
> Each case includes objective, prerequisites, physical equipment, steps, expected results, and verification.
> All tests are intended solely for authorized hardware security assessments on devices you own or have explicit written permission to test.

---

## Index

- [TC-HS-001: UART Interface Discovery and Root Shell Access](#tc-hs-001-uart-interface-discovery-and-root-shell-access)
- [TC-HS-002: Firmware Extraction via SPI Flash Chip](#tc-hs-002-firmware-extraction-via-spi-flash-chip)
- [TC-HS-003: JTAG Debug Port Access and Memory Dump](#tc-hs-003-jtag-debug-port-access-and-memory-dump)
- [TC-HS-004: Firmware Secrets and Credential Extraction](#tc-hs-004-firmware-secrets-and-credential-extraction)
- [TC-HS-005: RFID Card Cloning Attack](#tc-hs-005-rfid-card-cloning-attack)

---

## TC-HS-001: UART Interface Discovery and Root Shell Access

**Objective**: Identify an unpublished UART debug interface on the target device, determine the correct baud rate, and achieve an interactive shell — demonstrating that physical access to a UART header grants full operating system access without authentication.

**Target**: Embedded Linux device (consumer router, IP camera, smart hub, or similar IoT device) with an exposed or unpopulated UART header on the PCB.

**Prerequisites**:
- Device powered on and booted normally
- PCB accessible with UART header pins identified (minimum 3 pins: TX, RX, GND)
- USB-to-UART adapter connected to Kali Linux host

**Equipment**:
- Multimeter (voltage probing for TX/RX identification)
- USB-to-UART adapter (CP2102, CH340, or FTDI FT232R)
- Jumper wires or SOIC/pin probe clips
- Optional: logic analyzer for baud rate confirmation

### Steps

1. With device powered off, photograph PCB and identify all 3–6 pin headers near the SoC.
2. Power on device; probe candidate pins with multimeter set to DC voltage.
   - Pin held at 3.3 V or 5 V at idle = TX (UART output from device)
   - Pin at 0 V = GND
   - Pin floating or with no stable reading = RX
3. Connect USB-to-UART adapter: device TX → adapter RX, device RX → adapter TX, GND → GND. Do **not** connect VCC from adapter to device VCC — power the device from its own supply.
4. Open terminal at 115200 baud: `picocom -b 115200 /dev/ttyUSB0`
5. Power-cycle the device and observe boot output. If garbled output appears, try next baud rate (57600, 38400, 9600) until readable boot log appears.
6. When readable output appears, capture full boot log to file: `picocom -b 115200 /dev/ttyUSB0 | tee /tmp/uart-boot.log`
7. Observe whether device drops to a login prompt or root shell. Press Enter when boot completes.
8. If a login prompt appears, attempt default credentials: `root`/`root`, `root`/`admin`, `admin`/`admin`, `root`/(empty).
9. If U-Boot countdown appears, press any key to interrupt. At U-Boot prompt, run `printenv` to enumerate boot environment.
10. Document full shell access with: `id; uname -a; cat /etc/passwd; ifconfig`

### Expected Results

| Check | Expected Finding | Severity if Fails |
|-------|-----------------|-------------------|
| UART TX pin identified | Pin holds 3.3 V at idle | High |
| Boot log readable | ASCII boot messages at correct baud rate | High |
| Shell or prompt appears | Device outputs login prompt or root shell | Critical |
| Default credentials accepted | `root`/`root` or similar grants access | Critical |
| Root shell obtained | `id` returns `uid=0(root)` | Critical |
| Sensitive data accessible | `/etc/shadow`, `/etc/passwd`, config files readable | Critical |

### Verification

- Run `id` in obtained shell — output must show `uid=0(root)` for Critical-severity finding.
- Run `cat /proc/version` to confirm kernel version for additional CVE research.
- Confirm no authentication was required between UART connection and root shell.

**Severity**: Critical

**Phase**: Phase 2 — Debug Interface Access

---

## TC-HS-002: Firmware Extraction via SPI Flash Chip

**Objective**: Read the complete firmware image directly from the SPI NOR flash chip, produce a verified binary dump, and confirm the extracted image is a complete and consistent firmware image by identifying embedded filesystem signatures.

**Target**: Device with identified SPI NOR flash chip (common packages: SOIC-8, SOIC-16, WSON-8). Chip markings will be in the format W25Q64, MX25L3206, GD25Q128, or similar.

**Prerequisites**:
- Device powered off and PCB accessible
- SPI flash chip identified and datasheet obtained for pinout
- flashrom installed on Kali host: `apt-get install -y flashrom`

**Equipment**:
- CH341A USB programmer (primary) or Bus Pirate
- SOIC-8 clip (for in-circuit reading without desoldering) or hot-air station for desoldering
- Jumper wires
- Multimeter (verify VCC/GND before connection)

### Steps

1. Power off target device completely. Disconnect power supply.
2. Identify SPI flash chip on PCB using markings; look up datasheet to confirm SOIC-8 pinout: CS#, MISO, WP#, GND, MOSI, CLK, HOLD#, VCC.
3. Attach SOIC-8 clip to flash chip. Connect clip wires to CH341A programmer following pinout.
4. Connect CH341A to Kali Linux host via USB. Verify device appears: `dmesg | grep ch341`
5. Probe chip identity: `flashrom -p ch341a_spi`
   - Note reported chip name and capacity.
6. Read chip three times for integrity verification:
   ```bash
   flashrom -p ch341a_spi -r /tmp/dump1.bin
   flashrom -p ch341a_spi -r /tmp/dump2.bin
   flashrom -p ch341a_spi -r /tmp/dump3.bin
   ```
7. Compare hashes: `md5sum /tmp/dump{1,2,3}.bin` — all three must match exactly.
8. Scan extracted image: `binwalk /tmp/dump1.bin`
9. Extract embedded content: `binwalk -e -C /tmp/firmware-extracted/ /tmp/dump1.bin`
10. Record SHA256 of final dump: `sha256sum /tmp/dump1.bin > /tmp/firmware.sha256`

### Expected Results

| Check | Expected Finding | Severity if Fails |
|-------|-----------------|-------------------|
| flashrom detects chip | Chip make/model reported correctly | High |
| Three reads match | Identical MD5 hashes for all three dumps | High |
| binwalk finds signatures | LZMA, squashfs, gzip, or kernel signatures present | High |
| Extraction succeeds | Filesystem directory tree populated in output dir | High |
| File count reasonable | Extracted directory contains >100 files | Medium |

### Verification

- `file /tmp/dump1.bin` — should report "data" or specific filesystem type, not empty.
- `binwalk /tmp/dump1.bin | grep -i 'squashfs\|jffs2\|cramfs\|ext2'` — must find at least one filesystem.
- `ls /tmp/firmware-extracted/` — must contain subdirectories or image files.

**Severity**: High

**Phase**: Phase 3 — Firmware Extraction

---

## TC-HS-003: JTAG Debug Port Access and Memory Dump

**Objective**: Identify JTAG pins on an embedded device using JTAGulator, establish an OpenOCD connection, halt the CPU, and dump a memory region — demonstrating that debug ports enable full memory access without any software-level authentication.

**Target**: Embedded device with an ARM Cortex or MIPS SoC. JTAG/SWD header may be labeled, unpopulated, or hidden as test points.

**Prerequisites**:
- PCB physically accessible with candidate JTAG header or test points identified
- JTAGulator connected to Kali host (or manual pin mapping already known)
- OpenOCD installed: `apt-get install -y openocd`
- JTAG adapter available (FTDI-based, Bus Pirate, or Raspberry Pi GPIO)

**Equipment**:
- JTAGulator (for unknown pinout) or known JTAG wiring
- JTAG adapter (Olimex ARM-USB-OCD, FTDI FT2232H, or Bus Pirate)
- Jumper wires or fine-pitch probes for test points
- Multimeter (confirm 3.3 V logic levels)

### Steps

1. Power on device. Identify candidate JTAG header (common: 2x10 pin, 2x7 pin, or 4-pin SWD).
2. If pinout unknown, connect JTAGulator to up to 24 candidate pins; open terminal at 115200 baud and run JTAG discovery scan (`J` command in JTAGulator).
3. Record JTAGulator output: TCK=CHx, TMS=CHy, TDI=CHz, TDO=CHw, GND confirmed.
4. Wire JTAG adapter: TDI→TDI, TDO→TDO, TCK→TCK, TMS→TMS, GND→GND.
5. Start OpenOCD with appropriate interface and target config:
   ```bash
   openocd -f interface/ftdi/olimex-arm-usb-ocd.cfg -f target/cortex_m.cfg
   ```
6. Confirm OpenOCD output shows: `Examined ARM core`, `JTAG tap: ... enabled`.
7. Connect to OpenOCD telnet: `telnet localhost 4444`
8. Halt the CPU: `halt` — confirm response `target halted`.
9. Read registers: `reg` — confirm PC, SP, and other registers are readable.
10. Dump flash memory to file: `dump_image /tmp/jtag-memory.bin 0x08000000 0x00080000`
11. Resume CPU: `resume` — confirm device continues operating normally.
12. Analyze dump: `binwalk /tmp/jtag-memory.bin`

### Expected Results

| Check | Expected Finding | Severity if Fails |
|-------|-----------------|-------------------|
| JTAGulator identifies pins | TCK/TMS/TDI/TDO reported with channel numbers | High |
| OpenOCD connects | "Examined ARM core" message in OpenOCD output | High |
| CPU halted successfully | `halt` command returns target state as halted | Critical |
| Registers readable | `reg` output shows CPU register values | Critical |
| Memory dump created | `/tmp/jtag-memory.bin` non-zero size | Critical |
| binwalk finds content | Code or filesystem signatures in dump | High |

### Verification

- `ls -lh /tmp/jtag-memory.bin` — file size matches requested dump size (512 KB in this case).
- `strings /tmp/jtag-memory.bin | head -30` — readable ASCII strings confirm real firmware content.
- CPU resumes cleanly after `resume` — device did not crash from JTAG interaction.

**Severity**: Critical

**Phase**: Phase 2 — Debug Interface Access / Phase 3 — Firmware Extraction

---

## TC-HS-004: Firmware Secrets and Credential Extraction

**Objective**: From a previously extracted firmware filesystem, systematically locate hardcoded credentials, private keys, API tokens, and sensitive configuration data — demonstrating that embedded firmware routinely contains secrets that enable further compromise.

**Target**: Extracted firmware filesystem in a local directory (output from binwalk extraction or flashrom + unsquashfs pipeline).

**Prerequisites**:
- Firmware binary previously extracted and stored at `/tmp/firmware.bin`
- binwalk installed: `apt-get install -y binwalk`
- firmwalker available: `git clone https://github.com/craigz28/firmwalker.git`
- Extracted filesystem available (or extract now)

**Equipment**: Kali Linux host (no physical hardware required for this phase)

### Steps

1. Extract firmware if not already done:
   ```bash
   binwalk -e -C /tmp/fw-extracted/ /tmp/firmware.bin
   ```
2. Set variable for ease: `FWROOT=$(find /tmp/fw-extracted -name "squashfs-root" -type d | head -1)`
3. Run firmwalker automated scan:
   ```bash
   bash firmwalker/firmwalker.sh "$FWROOT" /tmp/firmwalker-report.txt
   cat /tmp/firmwalker-report.txt
   ```
4. Check password files:
   ```bash
   cat "$FWROOT/etc/passwd"
   cat "$FWROOT/etc/shadow"
   ```
5. Search for hardcoded passwords:
   ```bash
   grep -r -i "password\s*=" "$FWROOT" --include="*.conf" --include="*.sh" --include="*.lua" --include="*.json"
   ```
6. Search for private keys:
   ```bash
   find "$FWROOT" -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null
   grep -r "BEGIN.*PRIVATE KEY" "$FWROOT" -l 2>/dev/null
   ```
7. Search for API tokens and credentials:
   ```bash
   grep -r -E "(api_key|secret|token|password)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/]{16,}" "$FWROOT" -i | head -20
   ```
8. Identify running network services from init scripts:
   ```bash
   grep -r "telnetd\|ftpd\|sshd\|httpd\|dropbear" "$FWROOT/etc/" | head -20
   ```
9. Extract password hashes for cracking:
   ```bash
   cat "$FWROOT/etc/shadow" | grep -v "^.*:\*:" | grep -v "^.*:!:" > /tmp/fw-hashes.txt
   john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/fw-hashes.txt
   ```
10. Document all findings with exact file paths and line numbers.

### Expected Results

| Check | Expected Finding | Severity if Found |
|-------|-----------------|-------------------|
| /etc/passwd readable | User accounts including root visible | High |
| /etc/shadow readable | Password hashes present | Critical |
| Hardcoded passwords in configs | Plaintext passwords in config files | Critical |
| Private keys found | SSH host keys or TLS private keys in filesystem | Critical |
| API tokens in scripts | Cloud service tokens in init/update scripts | High |
| Telnetd/ftpd in services | Cleartext protocols enabled by default | High |
| Default web credentials | Admin panel credentials hardcoded | Critical |

### Verification

- Cross-reference any found credentials against device's web interface or SSH: attempt login.
- Verify password hashes crack successfully against common wordlists.
- Confirm telnetd/ftpd services confirmed running by connecting to device IP post-boot.

**Severity**: Critical (likely to find at minimum High-severity issues in consumer firmware)

**Phase**: Phase 4 — Firmware Analysis

---

## TC-HS-005: RFID Card Cloning Attack

**Objective**: Read an EM4100 or MIFARE Classic access card using Proxmark3, clone its identity to a blank writable card, and demonstrate that the cloned card is accepted by the access reader — proving that the access control system is vulnerable to replay attacks requiring no cryptographic attack.

**Target**: Physical access control system using 125 kHz EM4100 proximity cards or 13.56 MHz MIFARE Classic cards. Obtain a card from the card holder (authorized tester) or use your own test card.

**Prerequisites**:
- Proxmark3 device (Proxmark3 RDV4 or Easy) connected to Kali host via USB
- Proxmark3 client installed: `apt-get install -y proxmark3` or build from source
- Blank writable card available: T5577 (for 125 kHz EM4100) or CUID/GEN1a magic card (for MIFARE Classic)
- Written authorization to test the specific access control system

**Equipment**:
- Proxmark3 RDV4 or Proxmark3 Easy
- USB cable (Micro-USB or USB-C depending on model)
- T5577 blank card (for LF cloning) and/or MIFARE magic card (for HF cloning)
- Target access card (from authorized user)

### Steps

**Part A: Card Reading**

1. Connect Proxmark3 to Kali host. Start client: `pm3`
2. Place target card on Proxmark3 antenna.
3. Run automatic card detection:
   ```
   lf search    # for 125 kHz cards
   hf search    # for 13.56 MHz cards
   ```
4. Record card type, UID, and all reported details.

**For EM4100 (125 kHz):**

5. Read card data: `lf em 410x read`
6. Record 5-byte EM4100 ID (e.g., `1234567890`).

**For MIFARE Classic (13.56 MHz):**

5. Run autopwn to extract all sector keys and data:
   ```
   hf mf autopwn
   ```
6. After autopwn completes, dump card: `hf mf dump --file /tmp/card-dump.bin`
7. Record UID, ATQA, SAK values from `hf mf info` output.

**Part B: Card Cloning**

**For EM4100:**

8. Place T5577 blank card on antenna.
9. Clone EM4100 ID to T5577:
   ```
   lf em 410x clone --id 1234567890
   ```
10. Verify clone: `lf em 410x read` should return same ID.

**For MIFARE Classic:**

8. Place CUID/GEN1a magic card on antenna.
9. Restore dump to magic card: `hf mf restore --file /tmp/card-dump.bin`
10. Verify: `hf mf info` should show identical UID and sector data.

**Part C: Access Verification**

11. Present cloned card to target access reader.
12. Document whether reader grants access (photograph LED indicator, log door release sound).

### Expected Results

| Check | Expected Finding | Severity if True |
|-------|-----------------|------------------|
| Card type identified | EM4100 or MIFARE Classic reported | Info |
| EM4100 UID read | 5-byte ID extracted in under 5 seconds | High |
| MIFARE autopwn succeeds | All 16 sectors decrypted with default or cracked keys | Critical |
| Clone completes | T5577 / magic card programmed successfully | High |
| Cloned card accepted | Reader grants access with cloned card | Critical |

### Verification

- Read cloned card again after programming — UID must match original exactly.
- Present cloned card to reader a minimum of 3 times to confirm consistent access grant.
- Confirm original card still works (cloning does not destroy the original).

**Severity**: Critical (access control bypass without cryptographic attack)

**Phase**: Phase 5 — Exploitation
