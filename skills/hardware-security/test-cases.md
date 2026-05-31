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
- [TC-HS-006: Side-Channel Power Analysis on AES Implementation](#tc-hs-006-side-channel-power-analysis-on-aes-implementation)
- [TC-HS-007: Fault Injection via Voltage Glitching](#tc-hs-007-fault-injection-via-voltage-glitching)
- [TC-HS-008: IoT Device Firmware Over-The-Air Intercept](#tc-hs-008-iot-device-firmware-over-the-air-intercept)
- [TC-HS-009: Hardware Debug Interface Enumeration on Medical Device](#tc-hs-009-hardware-debug-interface-enumeration-on-medical-device)
- [TC-HS-010: CAN Bus Sniffing and Injection on Automotive ECU](#tc-hs-010-can-bus-sniffing-and-injection-on-automotive-ecu)

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

**Remediation**: Disable or physically obscure UART headers on production devices; enforce authentication on all debug consoles; remove root login or require strong passwords; configure U-Boot with bootdelay=0 and password protection.

**Pass Criteria**:
- [ ] UART TX pin identified with stable 3.3 V idle reading
- [ ] Boot log captured at correct baud rate with readable ASCII output
- [ ] Root shell or login prompt obtained without authentication
- [ ] `id` command returns `uid=0(root)`
- [ ] `/etc/passwd` and `/etc/shadow` contents documented

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

**Remediation**: Disable in-circuit programming on production devices via efuse or lock bits; encrypt firmware stored in flash; use secure boot to verify firmware integrity at startup; epoxy or shield flash chips to deter physical access.

**Pass Criteria**:
- [ ] flashrom detects and reports correct chip make/model
- [ ] Three sequential reads produce identical MD5 hashes
- [ ] binwalk identifies at least one embedded filesystem (squashfs, jffs2, cramfs, ext2)
- [ ] Extracted directory contains 100+ files
- [ ] SHA256 hash of final dump recorded for evidence chain

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

**Remediation**: Disable JTAG/SWD interfaces in production via efuse or firmware configuration; enable JTAG lockout after initial programming; use hardware security modules (HSMs) for key storage; enforce read-out protection (RDP) on ARM Cortex devices.

**Pass Criteria**:
- [ ] JTAGulator identifies TCK/TMS/TDI/TDO pin assignments
- [ ] OpenOCD connects and reports "Examined ARM core"
- [ ] CPU halts and resumes cleanly without device crash
- [ ] CPU register values readable via `reg` command
- [ ] Memory dump file non-empty and matches requested size
- [ ] binwalk or strings finds readable content in dump

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

**Remediation**: Remove hardcoded credentials from firmware images; store secrets in secure elements or TPMs; use encrypted filesystems for sensitive configuration; disable telnetd/ftpd and use SSH with key-based auth only; implement firmware encryption and obfuscation to raise extraction cost.

**Pass Criteria**:
- [ ] `/etc/passwd` and `/etc/shadow` readable with documented user accounts
- [ ] At least one hardcoded password found in configuration files
- [ ] At least one private key or certificate found in filesystem
- [ ] Network service configurations documented (telnetd, ftpd, sshd)
- [ ] firmwalker report generated with all findings catalogued

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

**Remediation**: Upgrade from EM4100 to encrypted card protocols (MIFARE DESFire, SEOS); deploy card readers that validate cryptographic challenges rather than relying on static UIDs; implement additional authentication factors (PIN, biometric); enable card-to-reader mutual authentication.

**Pass Criteria**:
- [ ] Target card type and UID successfully identified
- [ ] EM4100 ID read or MIFARE autopwn completed with all sectors decrypted
- [ ] Cloned card programmed and verified with matching UID
- [ ] Cloned card accepted by access reader on 3+ consecutive attempts
- [ ] Original card confirmed still functional after cloning

**Severity**: Critical (access control bypass without cryptographic attack)

**Phase**: Phase 5 — Exploitation

---

## TC-HS-006: Side-Channel Power Analysis on AES Implementation

**Objective**: Capture power consumption traces from a target microcontroller during AES encryption operations and use Correlation Power Analysis (CPA) to recover the secret key, demonstrating that power side-channels enable key extraction without invasive attacks.

**Severity**: Critical

**Prerequisites**:
- Target device with known AES-128 implementation running on an 8-bit or 32-bit microcontroller
- ChipWhisperer-Lite or ChipWhisperer-Pro connected to Kali host
- ChipWhisperer software installed: `pip install chipwhisperer`
- Target firmware configured to accept plaintext input and perform AES encryption on demand
- oscilloscope calibration completed and trigger signal identified

**Steps**:
1. Connect ChipWhisperer to target device: measure shunt resistor voltage on VCC line; connect trigger GPIO to capture scope.
2. Open ChipWhisperer Capture software and configure ADC clock to match target clock frequency (typically 7.37 MHz for XMEGA targets).
3. Program target with AES test firmware if not already present.
4. Acquire 5,000 to 10,000 power traces with random plaintext inputs:
   ```python
   import chipwhisperer as cw
   scope = cw.scope()
   target = cw.target(scope)
   scope.adc.samples = 2400
   scope.adc.offset = 0
   ktp = cw.ktp.Basic()
   trace_array = []
   textin_array = []
   for i in range(5000):
       key, text = ktp.next()
       trace = cw.capture_trace(scope, target, text, key)
       if trace:
           trace_array.append(trace)
           textin_array.append(text)
   ```
5. Run Correlation Power Analysis using Hamming weight leakage model:
   ```python
   import chipwhisperer.analyzer as cwa
   attack = cwa.CPA()
   attack.set_analysis_algorithm(cwa.leakage_models.sbox_output_leakage)
   results = attack.run(trace_array)
   ```
6. Inspect correlation output for each key byte: the highest-correlation hypothesis should match the actual key byte.
7. Validate recovered key by encrypting a known plaintext and comparing output.

**Expected**:
| Check | Expected Finding | Severity if Found |
|-------|-----------------|-------------------|
| Power traces captured | 5,000+ clean traces with visible AES round structure | High |
| CPA recovers key bytes | All 16 key bytes recovered with >0.9 correlation | Critical |
| Key validated | Recovered key produces correct ciphertext for test inputs | Critical |
| Attack requires <10k traces | Full key recovery economically feasible | High |

**Remediation**: Implement constant-time AES implementations that avoid key-dependent memory accesses; use hardware AES accelerators with built-in DPA countermeasures; apply masking schemes to randomize intermediate values; add random delays and dummy operations to increase trace count requirements.

**Pass Criteria**:
- [ ] 5,000+ power traces captured with clean trigger alignment
- [ ] CPA correlation plots show clear peaks for all 16 key bytes
- [ ] At least 14 of 16 key bytes recovered with >0.8 correlation coefficient
- [ ] Recovered key validated against known plaintext/ciphertext pair

---

## TC-HS-007: Fault Injection via Voltage Glitching

**Objective**: Bypass secure boot verification or authentication checks on a target microcontroller by injecting precise voltage glitches during critical instruction execution, causing the processor to skip security-critical branch instructions.

**Severity**: Critical

**Prerequisites**:
- ChipWhisperer-Lite or custom glitch hardware connected to Kali host
- Target microcontroller with secure boot or authentication mechanism (ARM Cortex-M, STM32, or similar)
- Target firmware analyzed to identify approximate glitch window (instruction timing from reset vector or authentication check)
- ChipWhisperer glitch module configured with appropriate shunt resistor

**Steps**:
1. Analyze target firmware to identify the authentication check or secure boot verification routine. Determine the approximate clock cycle count from reset or trigger to the branch instruction.
2. Set up ChipWhisperer for voltage glitching:
   ```python
   import chipwhisperer as cw
   scope = cw.scope()
   scope.glitch.clk_src = "clkgen"
   scope.glitch.output = "glitch_only"
   scope.glitch.trigger_src = "ext_trigger"
   scope.glitch.repeat = 1
   scope.glitch.width = 10
   scope.glitch.offset = 0
   ```
3. Run parameter sweep over glitch offset and width:
   ```python
   for offset in range(-20, 20):
       for width in range(1, 15):
           scope.glitch.offset = offset
           scope.glitch.width = width
           # Reset target and trigger glitch
           target.reset()
           response = target.read()
           if "authentication bypassed" in response.lower() or "root" in response.lower():
               print(f"GLITCH SUCCESS: offset={offset}, width={width}")
   ```
4. Document successful glitch parameters (offset, width, repeat count).
5. Repeat successful glitch 10 times to measure reliability percentage.
6. If secure boot is bypassed, dump the device memory using the glitched state.

**Expected**:
| Check | Expected Finding | Severity if Found |
|-------|-----------------|-------------------|
| Glitch parameters found | Specific offset/width combination bypasses check | Critical |
| Authentication bypassed | Device grants access without valid credentials | Critical |
| Secure boot skipped | Device boots unsigned/modified firmware | Critical |
| Reliability >30% | Attack is repeatable and practical | High |

**Remediation**: Implement multiple redundant security checks rather than a single branch instruction; use glitch detectors that monitor voltage and clock integrity; deploy hardware glitch detection circuits; use lock-step processor cores to compare results; implement firmware execution from encrypted storage.

**Pass Criteria**:
- [ ] At least one offset/width combination causes observable fault in execution flow
- [ ] Authentication or secure boot check bypassed with documented parameters
- [ ] Successful glitch repeatable with >20% reliability over 10 attempts
- [ ] Device memory accessible after successful glitch

---

## TC-HS-008: IoT Device Firmware Over-The-Air Intercept

**Objective**: Intercept an over-the-air (OTA) firmware update from an IoT device by performing a man-in-the-middle attack on the update channel, capture the firmware binary, and verify whether the update is transmitted without encryption or integrity protection.

**Severity**: High

**Prerequisites**:
- IoT device configured to check for and download firmware updates
- Network access on the same LAN segment as the target device (or ability to ARP poison)
- Wireshark and mitmproxy installed on Kali host
- DNS or HTTP interception capability (dnsspoof, Bettercap, or burp proxy)
- Known update server URL or ability to discover it via traffic analysis

**Steps**:
1. Identify the update mechanism: start Wireshark capture on the interface connected to the target device LAN.
   ```bash
   sudo wireshark -i eth0 -k -f "host <target-device-ip>"
   ```
2. Trigger firmware update check on the IoT device (via app, button, or scheduled update).
3. Analyze captured traffic: identify the update server URL, protocol (HTTP/HTTPS), and update request format.
4. If HTTPS is used, test for certificate pinning:
   ```bash
   # ARP spoof to position as MITM
   sudo arpspoof -i eth0 -t <target-device-ip> <gateway-ip>
   # Run mitmproxy with custom certificate
   mitmproxy --mode transparent --ssl-insecure
   ```
5. If certificate validation is weak, intercept and capture the firmware download.
6. If HTTP is used, intercept directly:
   ```bash
   bettercap -T <target-device-ip> -X --proxy --proxy-module injectjs
   ```
7. Save the intercepted firmware binary: extract from mitmproxy or Wireshark stream.
8. Analyze the captured firmware: check for encryption, signatures, or integrity hashes.
   ```bash
   binwalk intercepted_firmware.bin
   openssl dgst -sha256 intercepted_firmware.bin
   ```
9. Attempt to modify the firmware, repackage, and serve the modified version to test if the device accepts tampered updates.

**Expected**:
| Check | Expected Finding | Severity if Found |
|-------|-----------------|-------------------|
| Update traffic captured | Firmware download URL and protocol identified | High |
| No TLS/encryption | Firmware transmitted over plaintext HTTP | Critical |
| Certificate pinning absent | MITM succeeds with self-signed certificate | Critical |
| Firmware unencrypted | binwalk extracts readable filesystem from OTA payload | Critical |
| Modified firmware accepted | Device installs tampered firmware image | Critical |

**Remediation**: Enforce TLS with certificate pinning for all firmware update channels; sign firmware images with a secure key stored in a hardware security module; verify firmware signature on-device before installation; use encrypted firmware containers; implement rollback protection.

**Pass Criteria**:
- [ ] OTA update request and response traffic captured and analyzed
- [ ] Update server URL, protocol, and request format documented
- [ ] Encryption status of firmware download determined (encrypted or plaintext)
- [ ] Firmware binary extracted and analyzed with binwalk
- [ ] Integrity/signature verification status confirmed

---

## TC-HS-009: Hardware Debug Interface Enumeration on Medical Device

**Objective**: Systematically enumerate all hardware debug interfaces on a medical device PCB (SWD, JTAG, UART, I2C, SPI), document which interfaces are active and accessible, and determine which provide unauthorized access to patient data or device configuration.

**Severity**: Critical

**Prerequisites**:
- Medical device with written authorization for security assessment
- Device powered and operational in a test environment (not connected to patients)
- PCB accessible with all connectors and test points identified via high-resolution PCB photographs
- JTAGulator, multimeter, logic analyzer, and USB-to-UART adapters available
- Safety approval from facility biomedical engineering department

**Steps**:
1. Photograph the PCB at high resolution (both sides). Label all headers, test points, and unpopulated pads.
2. Use multimeter to identify power rails (3.3V, 5V, 1.8V) and GND pins on all headers.
3. Identify UART interfaces: probe remaining pins for idle voltage levels (TX holds 3.3V, RX floats).
4. Test each UART candidate at common baud rates (115200, 57600, 38400, 9600, 4800):
   ```bash
   for baud in 115200 57600 38400 9600; do
     echo "Testing baud: $baud"
     picocom -b $baud /dev/ttyUSB0 | tee /tmp/uart-${baud}.log &
     sleep 3 && kill %1
   done
   ```
5. Connect JTAGulator to all unidentified multi-pin headers and run JTAG scan:
   ```
   JTAGulator> J
   ```
6. Connect logic analyzer to I2C and SPI bus candidates; capture bus traffic during device operation.
7. For each discovered interface, document:
   - Interface type, pinout, and location on PCB
   - Active/inactive status (does it respond to communication?)
   - Data accessible (boot logs, configuration, patient data, calibration settings)
8. Attempt to access patient data storage via any active debug interface.
9. Document all findings with interface maps and screenshot evidence.

**Expected**:
| Check | Expected Finding | Severity if Found |
|-------|-----------------|-------------------|
| UART interfaces found | At least one UART provides boot log or console | High |
| JTAG/SWD accessible | Debug port allows CPU halt and memory access | Critical |
| I2C/SPI bus traffic captured | Patient configuration or calibration data on bus | High |
| Unauthenticated console access | Shell access without password on UART | Critical |
| Patient data accessible | Protected health information readable via debug port | Critical |

**Remediation**: Disable all debug interfaces on production medical devices via efuse or firmware configuration; implement physical tamper detection that erases sensitive data on case opening; encrypt patient data at rest and in transit on internal buses; comply with IEC 62304 and FDA cybersecurity guidance for medical device development.

**Pass Criteria**:
- [ ] All headers and test points on PCB documented with photographs
- [ ] UART interfaces tested at all common baud rates
- [ ] JTAGulator scan completed on all multi-pin headers
- [ ] I2C/SPI traffic captured and decoded with logic analyzer
- [ ] Each discovered interface classified as active/inactive with accessible data documented

---

## TC-HS-010: CAN Bus Sniffing and Injection on Automotive ECU

**Objective**: Connect to the CAN bus of a target vehicle's electronic control unit (ECU), capture and decode CAN frames to understand message structure, and demonstrate the ability to inject arbitrary CAN frames that affect vehicle behavior (door locks, instrument cluster, or other non-safety-critical systems).

**Severity**: Critical

**Prerequisites**:
- Target vehicle with OBD-II port accessible (test vehicle owned or with explicit written authorization)
- CANable, PCAN-USB, or SocketCAN-compatible adapter connected to Kali host
- can-utils installed: `sudo apt-get install can-utils`
- Vehicle ignition in ON position (engine may be off for safety)
- Test plan reviewed and approved, limiting injection to non-safety-critical systems only

**Steps**:
1. Connect CAN adapter to OBD-II port (pin 6 = CAN-High, pin 14 = CAN-Low).
2. Configure SocketCAN interface:
   ```bash
   sudo ip link set can0 type can bitrate 500000
   sudo ip link set up can0
   ```
3. Capture raw CAN traffic:
   ```bash
   candump can0 -t a -c can_capture.log
   ```
4. While capturing, perform specific vehicle actions to correlate CAN IDs with functions:
   - Lock/unlock doors (each action 3 times)
   - Turn on/off headlights
   - Press brake pedal
   - Roll down/up windows
5. Analyze captured traffic to identify message patterns:
   ```bash
   # Identify unique CAN IDs
   cat can_capture.log | awk '{print $3}' | sort -u
   # Find messages that appear only during door lock
   cansniffer can0 -c can_sniff.log
   ```
6. Replay captured frames to verify vehicle response:
   ```bash
   # Replay door lock frame
   cansend can0 123#0102030405060708
   ```
7. For identified functions, test modified payloads:
   ```bash
   # Brute-force specific byte positions for door unlock
   for i in $(seq 0 255); do
     cansend can0 123#$(printf '%02x' $i)02030405060708
     sleep 0.1
   done
   ```
8. Document all successful CAN ID and payload combinations.
9. Verify that injected frames produce the expected physical response in the vehicle.

**Expected**:
| Check | Expected Finding | Severity if Found |
|-------|-----------------|-------------------|
| CAN traffic captured | Valid CAN frames decoded at 500 kbps | High |
| Message-function mapping | CAN IDs correlated with door lock, lights, windows | Critical |
| Frame replay succeeds | Replayed CAN frame produces same vehicle response | Critical |
| Arbitrary injection works | Modified payload changes vehicle behavior | Critical |
| No authentication on bus | CAN frames accepted without source validation | Critical |

**Remediation**: Implement message authentication codes (MAC) on CAN bus messages using AUTOSAR SecOC; deploy CAN bus encryption for critical messages; use gateway ECUs to validate and filter messages between bus segments; implement intrusion detection systems (IDS) on the CAN bus; migrate to CAN-FD or Ethernet-based architectures with built-in security.

**Pass Criteria**:
- [ ] CAN bus traffic captured and decoded at correct bitrate
- [ ] At least 3 CAN IDs correlated with specific vehicle functions
- [ ] Replayed CAN frames produce the same physical response as original
- [ ] At least one injected modified payload produces observable vehicle behavior change
- [ ] No message authentication detected on any CAN frame
