---
name: automotive-vehicle-security
description: CAN/CAN-FD bus analysis, UDS diagnostics, IVI pentest, OBD-II exploitation, key fob replay/relay attacks, GNSS spoofing, EV charging station (ISO 15118), and connected vehicle red team operations.
origin: github-trending-2026
version: "0.2.0.2"
compatibility: Claude Code, Claude Agent SDK
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
metadata:
  domain: automotive
  category: automotive
  tool_count: 13
  guide_count: 2
  mitre: TA0001-Initial Access, TA0040-Detection, T1557-Adversary-in-the-Middle
  keywords: [can, can-fd, uds, obd-ii, automotive, vehicle, key-fob, gnss-spoofing, iso-15118, ecu, ivi]
  last_reviewed: "2026-07-26"
---




# Skill: Automotive & Vehicle Security

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for SocketCAN setup, can-utils (candump/cansend/cansniffer), cantools DBC reversing, CAN-FD, UDS (ISO 14229) enumeration, KWP2000, OBD-II PIDs, ECU firmware extraction, IVI pentest (Android Automotive/QNX), CANToolz framework, Scapy automotive (XCP/UDS/GMLAN), key fob replay/relay (HackRF/Flipper), GNSS spoofing, EV charging (ISO 15118 V2G/PLC), CAN injection methodology, and CAN-IDS detection — 18 sections with real CLI flags and incident references (Jeep 2015, Tesla 2017, BMW, VW, UK CAN injection thefts).
> - `test-cases.md` — Structured test cases (SocketCAN lab bring-up, passive CAN sniffing, DBC reversing, UDS enumeration, CAN-FD capture, CANToolz analysis, IVI recon, OBD-II PID readout, rolling-code capture, GNSS spoofing PoC, ISO 15118 fuzzing, CAN-IDS tuning) — 12 cases across 6 categories.
> - `guides/automotive-vehicle-security-playbook.md` — End-to-end red team playbook: bus recon → DBC reverse → UDS enum → ECU compromise → physical-effect validation. Includes CAN architecture refresher, automotive lab build (virtual + hardware tiers), CAN bus reverse engineering methodology, key fob attack workflow (rolling code + PKES relay), real-world incident case studies, and legal/ethical considerations.
> - `guides/automotive-ecu-firmware-and-uds-deep-dive.md` — Deep dive on ECU firmware extraction (boot mode, JTAG, NAND/eMMC desoldering, OTA package parsing, UDS 0x34/0x36 dump) and the full UDS service matrix (0x10-0x3E) with security access (0x27) seed-key analysis, routine control (0x31), ECU programming (0x34/0x36/0x37), firmware update attacks, secure boot bypass attempts, and signature verification analysis.

## Summary

Automotive & vehicle security skill domain covering CAN (ISO 11898) / CAN-FD bus analysis, UDS (ISO 14229-1) diagnostic exploitation, OBD-II (ISO 15031) PID enumeration, in-vehicle infotainment (IVI) pentest of Android Automotive / QNX / automotive Linux, key fob rolling-code and PKES relay attacks, GNSS spoofing of connected navigation/ADAS, and EV charging station attacks against ISO 15118 Vehicle-to-Grid (V2G) Plug & Charge. The skill spans the full vehicle attack surface: from physical OBD-II port through internal CAN buses to telematics control units (TCU), the cloud-connected back-end, and the consumer mobile companion app.

**Tools**: can-utils (candump/cansend/cansniffer), python-can, cantools (DBC), Savvy-CAN, GVRET, CANToolz, Scapy automotive layer, OpenXC, CANBadger, Macchina M2, USBTin, Kaya CAN-USB, HackRF One (key fob RF)

**Domain**: automotive

**MITRE ATT&CK**: TA0001-Initial Access (OBD-II/TCU entry), TA0040-Detection (CAN-IDS evasion), T1557-Adversary-in-the-Middle (relay, GNSS spoofing), T1557.001-LLMNR/NBT-NS (vehicle V2G MiTM), T1530-Data from Information Repositories (firmware/DBC)

## Description

Modern vehicles are networks on wheels. A 2025-era mid-segment car contains 70–150 Electronic Control Units (ECUs) interconnected by 3–8 CAN buses (powertrain, chassis, body, infotainment, ADAS, gateway), supplemented by LIN for low-cost body nodes, FlexRay for drive-by-wire, and MOST/FD for infotainment multimedia. The gateway ECU arbitrates inter-bus traffic; the Telematic Control Unit (TCU) provides the cellular/Wi-Fi uplink. Every rolling chassis is therefore an OT network with a routable path to the public internet through its TCU — and every ECU on it was designed for the deterministic world of CAN, not for adversarial input. This skill covers the exploitation of that stack.

The defining properties of the automotive threat model are:

1. **CAN has no authentication, no encryption, and no source identifier.** ISO 11898 specifies a broadcast multi-master bus: any ECU can transmit any CAN identifier (arbitration ID) at any time, and every other ECU receives every frame. There is no sender address, no signature, and no replay protection. The bus is secured by physical access to the wires — and the OBD-II port mandated since 2008 (US EPA, EU EOBD) is a standardized physical entry point. Once an attacker has bus write access — via the OBD-II port, a compromised TCU, or a telematics app vulnerability — they can inject any CAN frame and any ECU will act on it. The Jeep Cherokee hack (Miller & Valasek, DEF CON 23, 2015) demonstrated remote CAN injection through the Uconnect head unit: brakes, steering, transmission, at highway speed.

2. **UDS (ISO 14229-1) is the management plane, and it's almost always enabled in production.** Unified Diagnostic Services is the diagnostic protocol mechanics use for fault codes, ECU flashing, and component initialization. It runs over CAN (ISO 15765-3 / DoCAN) or K-Line (ISO 14230 / KWP2000) and exposes 26 service IDs (0x10 DiagnosticSessionControl through 0x3E TesterPresent). Service 0x27 SecurityAccess lets you unlock privileged modes — firmware upload (0x34/0x36/0x37), ECU reset (0x11), routine activation (0x31), and read-memory-by-address (0x23). Many production ECUs ship with UDS enabled and with weak or seed-only security. A successful 0x27 brute-force or seed-reuse attack leads to arbitrary memory read/write on the ECU — the canonical pre-exploitation step before CAN injection.

3. **DBC files are the rosetta stone of the vehicle bus.** A `.dbc` file maps each CAN arbitration ID to its constituent signals (e.g., ID 0x201 = EngineRPM bits 0-15, ThrottlePosition bits 16-23). The OEM's proprietary DBC is typically extracted from: leaked firmware images, ECU calibration files (WinOLS/Bosch), or by side-channel correlation (capture CAN while physically changing a known state — depress the brake pedal, decode which bits changed). Reverse a DBC and you have the write-semantics of every controllable actuator on the vehicle.

4. **The IVI is an attack pivot, not just a target.** Android Automotive, QNX, or MontaVista-based head units run full Linux/Android stacks with cellular modems, Wi-Fi, Bluetooth, GPS, USB, and a CAN connection to the vehicle bus. A single IVI RCE gives the attacker a remote, internet-facing foothold directly on the CAN bus. The Jeep Cherokee (2015), Tesla Model S (Tencent Keen Lab, 2017), BMW ConnectedDrive (2015), and multiple modern EVs all share this architecture. IVI pentest is web/mobile pentest with a CAN bus as the prize.

5. **The TCU is the remote compromise path.** The telematics unit is the only ECU with a routable internet connection, which makes it the highest-value remote target. Attack paths: cellular modem RCE, OTA update mechanism abuse, MQTT/HTTPS API compromise of the OEM's cloud, supply-chain compromise of third-party apps (Uber, Spotify, etc. running on the IVI), or — as in the 2015 Jeep — the cellular network SSH/telenet debug interface left open.

6. **Keyless entry (PKES / passive keyless entry and start) is broken by relay.** Modern key fobs wake when they receive a Low-Frequency (125 kHz) challenge from the vehicle, then respond on UHF (433/868 MHz). The Tesla/BMW/Audi PKES design is vulnerable to a two-thief relay attack: one stands at the fob (outside the restaurant), one stands at the car (driveway); the LF challenge is relayed from car to fob, the UHF response relayed from fob to car; vehicle unlocks and starts. Rolling-code 433 MHz remotes (older designs, garage doors, aftermarket alarms) are vulnerable to RollJam/RollBack captures with HackRF or a Flipper Zero. Both classes of attack have produced real-world vehicle thefts across the UK (2023, Khan/Sullivan), Europe, and the US.

7. **GNSS spoofing is cheap and effective against connected vehicles.** With a HackRF One and an external antenna, an attacker can broadcast a forged GPS L1 C/A signal that overpowers the genuine signal (the receiver locks to the strongest PRN). The result: arbitrary position/time drift, navigation redirected, and — critically for ADAS Level 2/3 — geofenced features disabled or enabled inappropriately. Tesla Autopilot, Mercedes Drive Pilot, and commercial fleet telematics all trust GNSS position to some degree.

8. **ISO 15118 (Vehicle-to-Grid) is the new EV attack surface.** Modern EVs and DC fast chargers (CCS / CharIN) use Power Line Communication (PLC) for the charging interface, with ISO 15118-20 mandating TLS and Plug & Charge (PnC) certificates. Vulnerabilities in certificate handling, Exi (Efficient XML Interchange) parsing, or the TLS stack itself allow billing fraud, charging disruption, or — in extreme cases — battery/BMS manipulation.

**Difference from `iot-pentest`**: IoT-pentest covers consumer/industrial smart devices (MQTT, CoAP, AWS IoT). Automotive-vehicle-security covers vehicle-specific buses (CAN/CAN-FD/LIN/FlexRay), vehicle-specific protocols (UDS, KWP2000, OBD-II, ISO 15118), and the vehicle threat model (60+ ECUs on a deterministic broadcast bus with no authentication). The overlap is the TCU's MQTT/HTTPS cloud back-end — automotive covers the vehicle side, iot-pentest covers the cloud side.

**Difference from `sdr-rf-attack`**: SDR covers the general RF signal layer (capture, demodulate, replay 433/868 MHz, ADS-B, AIS). Automotive-vehicle-security applies SDR techniques specifically to key fob rolling code, PKES relay amplification, GNSS spoofing (GPS L1, Galileo E1, BeiDou B1I), and the V2X DSRC/IEEE 802.11p spectrum.

**Difference from `hardware-security`**: Hardware-security covers generic chip-level attacks (JTAG/UART/SWD/glitching/power analysis). Automotive-vehicle-security applies those techniques to ECUs (boot mode pin strap, NAND readout, JTAG over the diagnostic connector) and adds the bus-protocol layer on top.

**Difference from `binary-reverse`**: Binary-reverse covers general disassembly/decompilation (Ghidra/IDA/BinaryNinja). Automotive-vehicle-security applies binary-reverse to ECU firmware (MPC5xxx, RH850, ARM Cortex-R), with automotive-specific concerns: calibration data (WinOLS/A2L files), DBC recovery, UDS service identification, and secure-boot bypass.

**Difference from `scada-ics-security`**: SCADA covers industrial control protocols (Modbus, DNP3, S7comm, OPC UA). Automotive covers vehicle protocols (CAN, UDS, KWP2000, LIN, FlexRay). The architectural overlap is minimal but the methodology (deterministic bus, broadcast medium, no authentication) is identical.

**Difference from `mobile-security`**: Mobile covers iOS/Android apps generally. Automotive covers Android Automotive OS (AAOS), QNX, and the in-vehicle app ecosystem with the additional surface of the CAN bus pivot.

## Use Cases

- **Pre-engagement vehicle security audit**: Given a target vehicle (or a fleet), map its full attack surface: OBD-II diagnostic port, internal CAN bus topology, UDS-exposed services per ECU, IVI/TCU remote attack surface, key fob RF profile, and OEM cloud connectivity — before an adversary does.
- **CAN bus reverse engineering**: From a captured CAN trace (candump) and/or an extracted DBC, decode every signal on the bus: engine RPM, throttle, brake pressure, steering angle, gear, speed. Produce a working DBC the red team can use to craft injection frames.
- **UDS enumeration and exploitation**: Walk every ECU on the diagnostic bus, enumerate UDS services (0x10-0x3E), test 0x27 SecurityAccess seed/key, attempt firmware readout (0x23 ReadDataByIdentifier / 0x34-0x37 RequestDownload/Transfer/Exit), and document any ECU that accepts unauthenticated privileged services.
- **IVI / head unit pentest**: Treat the Android Automotive / QNX head unit as a mobile device with a cellular modem and a CAN pivot. Test: OTA update signature validation, Bluetooth/Wi-Fi pairing, USB attack surface, web browser sandboxing, and the IVI-to-CAN gateway ECU's filtering rules.
- **Keyless entry attack**: Capture and replay a 433 MHz rolling-code key fob (HackRF/Flipper), or perform a PKES relay attack against a Tesla / BMW / Audi / Mercedes. Document time-to-unlock, range, and detection footprint.
- **GNSS spoofing PoC (lab / closed-course only)**: Demonstrate position drift, time drift, or geofence bypass on a target vehicle's navigation and ADAS subsystem using a HackRF-based GPS L1 spoofer.
- **EV charging station (ISO 15118) assessment**: Capture PLC V2G traffic between a CCS vehicle and a DC fast charger, test the TLS/Plug & Charge certificate handling, fuzz the Exi message decoder, and document billing/authentication bypass findings.
- **Connected vehicle red team**: Combine multiple vectors (TCU cellular RCE → IVI app pivot → CAN injection → physical effect) into a full kill-chain demonstration, following the methodology established by Miller & Valasek (Jeep, 2015) and Tencent Keen Lab (Tesla, 2017).

## Core Tools

### Bus Analysis & Sniffing

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **can-utils** (Linux Foundation) | Reference SocketCAN userland: candump, cansend, cansniffer, cangen | `candump -L can0` (timestamped capture) |
| **python-can** | Python library for SocketCAN / Kvaser / Vector / PCAN / serial | `python-can.interfaces.socketcan.SocketcanBus(interface='can0')` |
| **cantools** (Python) | DBC file parse, encode/decode, plot, replay | `cantools decode dbc.dbc frame.data` |
| **Savvy-CAN** (Collin Kidder) | Cross-platform GUI: live trace, DBC editing, frame graphing, replay, send | Savvy-CAN GUI (Qt) |
| **GVRET / ESP32-CAN-Transceiver** | Open-source CAN sniffing firmware (Comma.ai compatible) | Serial over USB, used with Savvy-CAN |

### Hardware Interfaces

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **CANBadger** (Wolf Goats) | Purpose-built CAN attack tool (ESP32, 2x CAN, Ethernet) | CANBadger web UI / scripts |
| **Macchina M2 / mk2** | Open-source automotive dev board (Arduino-based, CAN/LIN) | Arduino sketch with CAN library |
| **USBTin** | Affordable CAN-USB adapter (~$50) for SocketCAN | `slcand -o /dev/ttyACM0 -s 500000 can0` |
| **Kaya CAN-USB / Kvaser / PCAN-USB / Vector VN1630** | Commercial CAN interfaces (OEM-grade) | Vendor driver → SocketCAN |

### Frameworks & Protocol Layers

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **CANToolz** (eik00d, Black Hat EU 2016) | Black-box CAN analysis framework (fuzz, send, mine) | `cantoolz -c can0 -b 500000` |
| **Scapy automotive** | Scapy with UDS, ISO-TP, GMLAN, XCP layers | `sr1(UDS()/UDS_DiagnosticSessionControl(...))` |
| **OpenXC** (Ford) | Reference platform for vehicle data APIs (mobile/VI) | `openxc-hardware` + `openxc-python` |

## Methodology

### Five-Phase Automotive Red Team Workflow

```
Phase 1           Phase 2           Phase 3            Phase 4            Phase 5
Recon & Setup  →  Bus Sniffing   →  Protocol Reversing→  ECU Compromise →  Physical Effect
(OBD-II pinout,   (candump,         (DBC decode,        (UDS enum,          (replay, injection,
 hardware bringup, cansniffer,       ISO-TP/UDS,         0x27 seed/key,      brake / steer /
 IVI surface)      python-can)       KWP2000)            firmware readout)   dashboard PoC)
   │                 │                 │                   │                   │
   ▼                 ▼                 ▼                   ▼                   ▼
 Pin 6/14 CAN-H/L,  Passive trace     DBC from leak or   UDS service map,    Replay captured
 ground, OBD-II     over test drive,  side-channel       0x27 brute/reuse,   actuator frames,
 adapter bringup,   identify ECUs,    correlation        boot mode, NAND     fuzz arbitration
 IVI recon          ISO-TP discovery  (depress pedal →   readout              IDs, safety-
                    on 0x7DF/0x7E0    signal bits                             critical PoC
                                                                            requires explicit
                                                                            authorization
```

**Phase 1: Recon & Setup** — Bring up the hardware and map the physical/IVI attack surface. Identify OBD-II pinout (CAN-H pin 6, CAN-L pin 14, GND pin 4/5, 12V pin 16). Bring up a SocketCAN interface (`slcand` for USBTin; kernel driver for Kvaser/PCAN; `ip link set can0 type can bitrate 500000`). Probe the IVI: enumerate Bluetooth (BD_ADDR, services), Wi-Fi (hidden SSIDs), USB (ECU reflash modes), and the head-unit's app catalogue (Android Automotive intents, QNX resource manager nodes).

**Phase 2: Bus Sniffing** — Passive capture only; never transmit on a vehicle bus without explicit authorization. Standard workflow: `candump -L can0 > trace.asc` (ASC format for Vector compatibility); `cansniffer -c can0` (live per-arbitration-ID view showing which IDs are changing). Identify ECU tiers by arbitration ID range (SAE J1939 PGN ranges; ISO 11783 agricultural; standard 11-bit vs extended 29-bit IDs). Probe ISO-TP / UDS on the functional address 0x7DF and each physical address 0x7E0-0x7E7.

**Phase 3: Protocol Reversing** — Turn raw CAN IDs into named signals. Start with any leaked/extracted DBC (open-source DBCs for some Tesla/Hyundai/Kia/Nissan models on GitHub; OpenDBC project by Comma.ai). If no DBC exists, perform side-channel correlation: capture CAN while manipulating a single known state (key on, brake depressed, steering at 0°, then 90°), diff the bus to identify which bits in which arbitration IDs changed. Decode ISO-TP multi-frame messages with `isotp_send`/`isotp_recv`. Identify UDS service support per ECU via the 0x22 (ReadDataByIdentifier) calls.

**Phase 4: ECU Compromise** — Walk the UDS service matrix per ECU. Enumerate 0x10 DiagnosticSessionControl (default 0x01, programming 0x02, extended 0x03). Probe 0x27 SecurityAccess (request seed on subfunction 0x01, send key on 0x02). Brute-force weak seed/key implementations (often 16-bit seed, 24-bit key, deterministic XOR/LFSR). On successful 0x27, attempt 0x23 ReadMemoryByAddress, 0x34 RequestDownload, 0x36 TransferData to read out firmware. Boot-mode extraction via ECU-specific pin strap (e.g., MPC5xxx BOOTS signal, RH850 debug-mode strap). NAND readout via desoldering / JTAG (see `hardware-security`).

**Phase 5: Physical Effect Validation** — With the DBC decoded and UDS mapped, demonstrate a CAN injection that produces a measurable physical effect. Standard demo vectors (with explicit authorization, on a closed course, with a safety driver): instrument cluster spoofing (RPM, speedo), steering-wheel button injection (volume up), body control (lights, wipers), brake/steering at speed (the Miller-Valasek Jeep vector — requires a vehicle with the gateway removed or with documented debug access). Every safety-critical injection must be authorized in writing by the vehicle owner and by the OEM. CAN fuzzing: `cangen can0 -g 10 -n 1000` to send random frames; `CANToolz` module-based fuzz for targeted arbitration ID ranges.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| CAN-H/CAN-L bring-up | `slcand -o /dev/ttyACM0 -s 500000 can0 && ip link set up can0` | kernel driver for Kvaser/PCAN |
| Passive trace | `candump -L can0 trace.asc` | `cansniffer -c can0` (live delta view) |
| DBC decode | `cantools dump dbc.dbc` then `cantools decode dbc.dbc 0x201#01020304` | Savvy-CAN DBC editor |
| UDS service enum | `scapy` UDS `DiagnosticSessionControl` on 0x7E0 | `python-can` + raw ISO-TP |
| UDS 0x27 brute | Scapy UDS scanner loop | CANToolz `fuzz` module |
| OBD-II PID read | `cansend can0 7DF#02010F0000000000` (mode 01 PID 0x0F catalyst temp) | Savvy-CAN OBD-II pane |
| CAN injection | `cansend can0 201#01020304` | Scapy `sendp(...)` over SocketCAN |
| IVI OTA check | `adb shell pm list packages` + decompile APK with jadx | QNX: `ls /proc` + memory dump |
| Key fob capture (433 MHz) | HackRF `hackrf_transfer -r fob.cs8 -f 433920000` | Flipper Zero SubGHz record |
| PKES relay | Two Yagi antennas + amplifier, no SDR needed | Custom LF/UHF relay hardware |
| GNSS spoof | HackRF + GPS-SDR-SIM, replay forged ephemeris | bladeRF / USRP B210 |
| EV V2G capture | PLC sniffer (HomePlug AV2) between CCS port and charger | ISO 15118 test tool from Vector |

## Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Automotive ISAC (Auto-ISAC)** | Industry threat-intel sharing for OEMs and Tier-1s; the canonical clearinghouse for coordinated vulnerability disclosure and IoC sharing. [automotiveisac.com](https://automotiveisac.com) |
| **UNECE WP.29 R155 (Cybersecurity Management System)** | Mandatory since July 2022 for new vehicle type approvals in UNECE 1958 signatory countries (EU, Japan, Korea, UK). Requires OEMs to operate a CSMS, perform TARA, detect/respond to incidents, and report critical vulnerabilities within 4 months. |
| **UNECE WP.29 R156 (Software Update Management System)** | Companion to R155; governs OTA updates. Requires SUMS, update integrity verification, rollback capability, and per-update risk assessment. |
| **ISO/SAE 21434 (Road vehicles — Cybersecurity engineering)** | The automotive SDLC standard. Maps to R155 CSMS requirements; covers threat analysis & risk assessment (TARA), cybersecurity goals, validation, and post-development monitoring. The reference framework every OEM audit committee references. |
| **SAE J3061 (Cybersecurity Guidebook for Cyber-Physical Vehicle Systems)** | Predecessor to ISO 21434; still widely cited for the TARA methodology and the vehicle V-model cybersecurity overlay. |
| **Gateway ECU filtering** | The inter-bus gateway should not route safety-critical messages (brake, steer) from infotainment-side buses to powertrain-side buses. Default-deny inter-bus ACL; explicit allowlist per message ID. |
| **CAN message authentication (AUTOSAR SecOC)** | SecOC (Secure Onboard Communication) adds a truncated MAC to each CAN frame, providing freshness and integrity. Adoption has been slow (5–10% of 2024 production vehicles) but is increasing with R155 pressure. |
| **Hardware Security Module (HSM) per ECU** | EVITA HSM (light/medium/full) or SHE (Secure Hardware Extension) on each safety-critical ECU. Stores keys, performs MAC, protects secure boot. Required for SecOC. |
| **UDS 0x27 hardening** | Per-ECU unique seed/key with strong PRNG; rate-limit the 0x27 service; lock 0x27 in default session; disable 0x27 on production ECUs where possible (move to JTAG/boot-mode only). |
| **CAN-IDS (intrusion detection)** | Per-ECU or gateway-resident IDS that flags: new arbitration IDs, out-of-range signal values, message-rate anomalies, UDS service anomalies. Vendors: Karamba, GuardKnox, Towersec (HP), Argus (now part of NXP). Forward events to OEM SOC via TCU. |
| **Telematics segmentation** | The TCU's cellular interface must be in a separate security domain from the CAN backbone; inter-domain traffic flows through an automotive firewall with DPI on ISO-TP/UDS/SOME-IP. |
| **PKES relay mitigation** | Time-of-flight ranging on UHF response (impossible to relay without detectable latency); motion sensors in the fob (sleep when stationary); multi-band challenges (LF + BLE + UWB ranging). Modern BMW/Audi have moved to UWB (IEEE 802.15.4z) for this reason. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: SocketCAN + can-utils Bring-up on Linux

Goal: bring up a SocketCAN interface on Kali Linux and capture live CAN frames from a bench ECU or a vircar virtual CAN simulator.

```bash
# 1. Install can-utils (Linux Foundation reference SocketCAN userland)
sudo apt-get install -y can-utils
# verify
candump --version

# 2a. Option A: Real hardware via USBTin (~$50 USB-to-CAN adapter)
#    slcand creates a SocketCAN interface from a serial CAN adapter
sudo slcand -o /dev/ttyACM0 -s 500000 -S 500000 can0
sudo ip link set up can0
ip -details link show can0
#   can0: <NOARP,UP,LOWER_UP> mtu 16 qdisc ...

# 2b. Option B: Virtual CAN (no hardware, lab-only) — great for learning
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 3. Passive capture (timestamped, ASC format for Vector compatibility)
candump -L vcan0 > trace.asc &
CANDUMP_PID=$!

# 4. From another terminal, send a test frame: arbitration ID 0x123, 8 bytes
cansend vcan0 123#DEADBEEFCAFEBABE

# 5. Stop capture and review
kill $CANDUMP_PID
head -5 trace.asc
#   (1609487127.521379) vcan0 123#DEADBEEFCAFEBABE

# 6. Live delta view — show which arbitration IDs are changing (and how)
cansniffer -c vcan0
#   Each CAN ID is a column; bit changes flash. Press 'q' to quit.
```

### Exercise 2: DBC Reversing with cantools

Goal: decode raw CAN frames using a known-good DBC (OpenDBC example), then craft an encoded frame.

```bash
# 1. Install cantools
pip3 install cantools

# 2. Clone OpenDBC (Comma.ai's open DBC repository — many makes/models)
git clone https://github.com/commaai/opendbc
cd opendbc/dbc
ls   # acura, bmw, ford, gm, hyundai, kia, nissan, tesla, toyota, vw, ...

# 3. Dump a DBC to confirm structure
cantools dump ../opendbc/dbc/hyundai/hyundai_generic.dbc | head -30

# 4. Decode a single frame: ID 0x379, data 0x00 0x80 0x00 0x00 ...
cantools decode ../opendbc/dbc/hyundai/hyundai_generic.dbc 379#0080000000
#   {('SPEED', 0), ('STEERING', 0), ...}

# 5. Encode a frame for injection
cantools encode ../opendbc/dbc/hyundai/hyundai_generic.dbc SPEED 100 STEERING 50

# 6. Live decode a candump trace
candump -L vcan0 | cantools dump --dbc ../opendbc/dbc/hyundai/hyundai_generic.dbc

# 7. Side-channel correlation: capture baseline, then manipulate one state
#    (e.g., turn steering wheel 90°), capture again, diff the trace
candump -L vcan0 > baseline.asc
#   <rotate steering wheel>
candump -L vcan0 > rotated.asc
#   Diff: which arbitration IDs changed? Which bits?
diff <(awk '{print $2}' baseline.asc | sort -u) <(awk '{print $2}' rotated.asc | sort -u)
```

### Exercise 3: UDS Enumeration with Scapy Automotive

Goal: walk every ECU on the diagnostic bus, enumerate supported UDS services, and probe for 0x27 SecurityAccess.

```python
#!/usr/bin/env python3
# udscan.py — UDS service enumeration over ISO-TP
import can
from scapy.all import *
from scapy.contrib.automotive.uds import *

# 1. Bring up SocketCAN (real or vcan0)
bus = can.interface.Bus(interface='socketcan', channel='can0', bitrate=500000)

# 2. UDS functional broadcast address is 0x7DF; physical 0x7E0-0x7E7
#    ISO-TP single-frame wrap: 8 bytes, first nibble = PCI (0 = single frame),
#    second nibble = data length
TARGET = 0x7E0

def uds_request(svc, sub=0x00, data=b''):
    """Send a UDS request and return the response."""
    msg = can.Message(
        arbitration_id=TARGET,
        data=bytes([svc, sub]) + data + b'\x00' * (6 - len(data)),
        is_extended_id=False
    )
    bus.send(msg)
    resp = bus.recv(timeout=1.0)
    return resp

# 3. Enumerate UDS services 0x10-0x3E
print(f"UDS service scan on 0x{TARGET:03X}")
for svc in range(0x10, 0x3F):
    if svc == 0x3E:  # TesterPresent — skip
        continue
    resp = uds_request(svc, 0x00)
    if resp and len(resp.data) >= 2:
        # Positive response: first byte = svc + 0x40
        if resp.data[0] == svc + 0x40:
            print(f"  0x{svc:02X} supported — positive response: {resp.data.hex()}")
        # Negative response: 0x7F, svc, NRC
        elif resp.data[0] == 0x7F:
            nrc = resp.data[2]
            print(f"  0x{svc:02X} rejected — NRC 0x{nrc:02X}")

# 4. Open extended diagnostic session
resp = uds_request(0x10, 0x03)  # extended diagnostic
print(f"DiagnosticSessionControl 0x03 → {resp.data.hex() if resp else 'no response'}")

# 5. Probe SecurityAccess (request seed, subfunc 0x01)
resp = uds_request(0x27, 0x01)
if resp and resp.data[0] == 0x67:
    seed = resp.data[2:]
    print(f"SecurityAccess seed: {seed.hex()}")
else:
    print("SecurityAccess unavailable in current session")

# 6. Read ECU identification (0x22 ReadDataByIdentifier)
#    DID 0xF190 = VIN, 0xF180 = Boot Software ID
for did in [0xF190, 0xF180, 0xF187]:
    resp = uds_request(0x22, (did >> 8) & 0xFF, bytes([did & 0xFF]))
    if resp and resp.data[0] == 0x62:
        print(f"  DID 0x{did:04X}: {resp.data[3:].hex()} / {resp.data[3:].decode('ascii', errors='replace')}")
```

### Exercise 4: OBD-II Standard PIDs Readout

Goal: read the mandated OBD-II PIDs (mode 0x01-0x0A) using raw CAN.

```bash
# 1. Mode 0x01 PID 0x0C — Engine RPM
#    Request: functional broadcast 0x7DF, payload 02 01 0C 00 00 00 00 00
#             (02 = ISO-TP single frame, 2 data bytes; 01 = mode; 0C = PID)
cansend can0 7DF#02010C0000000000
# Response comes from engine ECU on 0x7E8:
candump -L can0 -n 1
#   (1609487127.521379) can0 7E8#04410C1F88000000
#   04 = single frame, 4 data bytes; 41 = mode+0x40; 0C = PID; 1F88 = data
#   RPM = (0x1F88 / 4) = 2024.5 RPM

# 2. Mode 0x01 PID 0x0D — Vehicle Speed (km/h, single byte)
cansend can0 7DF#02010D0000000000
candump -L can0 -n 1
#   7E8#03410D3200000000  →  speed = 0x32 = 50 km/h

# 3. Mode 0x01 PID 0x05 — Engine Coolant Temperature (°C, offset -40)
cansend can0 7DF#0201050000000000
#   7E8#0341055C00000000  →  coolant = 0x5C = 92°C (actual = 92, signed offset -40 means raw 0x5C = 92)

# 4. Mode 0x03 — Read stored DTCs (Diagnostic Trouble Codes)
cansend can0 7DF#02030000000000
candump -L can0 -n 5   # response may be multi-frame ISO-TP

# 5. Mode 0x09 PID 0x02 — VIN (5 frames, ISO-TP multi-frame)
cansend can0 7DF#0209020000000000
candump -L can0 -n 6
#   First frame: 0x7E8#10 14 49 02 01 30 30 30  (ISO-TP first frame, len=0x014=20)
#   Then flow control + consecutive frames contain VIN ASCII

# 6. Loop all PIDs via a small script
for pid in 04 05 0B 0C 0D 0E 0F 10 11 1F 21 2F 33 42 46 5C; do
    cansend can0 7DF#0201${pid}0000000000
    sleep 0.1
    candump -L can0 -n 1
done
```

## Common Pitfalls

- **Transmitting on a vehicle CAN bus without explicit authorization.** Unlike a network pentest, sending CAN frames into a moving vehicle can trigger airbag deployment, ABS intervention, transmission shifts, or steering torque changes. Every CAN write — even a "harmless" 0x7DF OBD-II read — should be authorized in writing by the vehicle owner AND verified against the engagement scope. The standard safety pattern is: bench ECU on the lab floor first → dyno / lifted vehicle with transmission in park → closed course with a safety driver → never on public roads.
- **Assuming arbitration IDs map to physical ECUs 1:1.** A single ECU can transmit on multiple IDs; multiple ECUs can share a logical function (redundant brake ECUs). The arbitration ID is a message identifier, not an ECU address. Use UDS physical addressing (0x7E0-0x7E7) to walk ECUs directly; use functional broadcast (0x7DF) for "all ECUs respond."
- **Treating a leaked DBC as authoritative for production firmware.** OEMs change signal layouts across model years, option codes, and even mid-production software updates. A 2019 Tesla Model 3 DBC is not a 2024 DBC. Always validate the DBC against a captured trace by cross-checking at least 2-3 known signals (RPM against tachometer, speed against GPS, brake light against pedal sensor) before trusting it for injection.
- **Confusing ISO-TP (transport) with UDS (application).** ISO 15765-2 (ISO-TP) is the transport layer that segments UDS PDUs across multiple CAN frames (single frame ≤7 bytes, first frame + consecutive frames for >7). UDS is the application protocol on top. A `cansend 7DF#02010C0000000000` is ISO-TP single-frame carrying a UDS ReadDataByIdentifier request. You need to handle ISO-TP reassembly in code; raw candump output will show individual CAN frames, not the reassembled UDU.
- **Forgetting that CAN-FD changes the physical layer.** CAN-FD (ISO 11898-1:2015) allows 64-byte payloads (vs 8-byte classic) and dual bit-rates (arbitration at 500 kbps, data phase at 2-5 Mbps). Older can-utils versions (pre-2018) and older adapters (Lawicel CANUSB, early PCAN-USB) do not support CAN-FD. Set the interface explicitly: `ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on`.
- **Assuming PKES relay requires breaking crypto.** Relay attacks do not break the cryptographic challenge-response between fob and car. They relay the physical layer (LF challenge from car → fob, UHF response from fob → car) at the speed of light; the fob believes it's next to the car and the car believes the fob is next to it. No amount of cryptographic hardening on the fob fixes this; the fix is physical-layer: time-of-flight ranging (UWB IEEE 802.15.4z) or motion-sensor gating in the fob.
- **Trusting a HackRF GNSS spoof to "just work."** GPS L1 C/A spoofing requires: ephemeris data for the spoofed constellation, accurate timing (the receiver will reject signals that disagree with its own clock by more than ~10 ms unless you spoof cold-start), a clean RF environment (you need to overpower the genuine signal at the target antenna, typically +10 dB), and a slow ramp (an instantaneous jump of position is detectable by most modern receivers; a gradual drift is not). Use GPS-SDR-SIM for the signal generation and start with a "cold-start" target (receiver powered off for >30 min).
- **Treating CAN-IDS as a defense you can't evade.** Most CAN-IDS implementations look for: (1) new arbitration IDs, (2) message-rate anomalies, (3) signal-value out-of-range. A targeted replay of a valid arbitration ID, at the natural rate, with in-range values, will evade most production IDS. The defense against this is SecOC (cryptographic authentication) — not IDS.

## Safety Notes

- **Safety-critical injections require explicit authorization AND a closed course AND a safety driver.** Demonstrations that affect brake, steering, powertrain, airbag, or ADAS functions on a moving vehicle are regulated under NHTSA / UNECE and carry criminal and civil liability. The 2015 Jeep Cherokee demonstration took Miller & Valasek 14 months and was conducted on a closed airfield with explicit Chrysler authorization.
- **OBD-II port access on a vehicle you do not own** may violate state law (e.g., California Vehicle Code §10851 for tampering), DMV inspection rules, and (for fleet vehicles) the company's acceptable-use policy. The standard for engagement: written authorization from the registered owner AND the manufacturer.
- **Key fob capture/replay on vehicles not your own** is a federal crime in the US (18 USC §1029 access device fraud; the rolling code IS an access device). Even research-only capture requires authorization from the fob owner and, ideally, the vehicle owner. UK courts have convicted on PKES relay possession alone (Khan/Sullivan, 2023).
- **GNSS spoofing is illegal** under FCC Part 97 (US), Ofcom (UK), and equivalent regulators worldwide. There is no legal carve-out for security research on GNSS in most jurisdictions. Conduct GNSS spoofing only in an RF-shielded enclosure or with an explicit STA (Special Temporary Authorization) from the regulator.
- **EV charging station testing** must be done on stations you own or operate. Charging-network operators (ChargePoint, Electrify America, IONITY) have explicit anti-tampering clauses; PLC interception on a public charger may violate state computer-fraud statutes.
- **Firmware extraction from a production ECU** typically requires desoldering the NAND flash, which is destructive and voids the ECU warranty. Always obtain a second/spare ECU for destructive testing.
- **OTA update interception** against a vehicle enrolled in OTA updates may cause it to fail an update mid-cycle, bricking the ECU. Never interrupt an OTA update in production.

## Detection Methods

### CAN Bus Anomaly Detection
- **Message ID Whitelisting**: CAN-IDS (Intrusion Detection System) on ECU rejects messages from unauthorized CAN IDs.
- **Periodic message timing**: Each ECU sends specific CAN messages at known intervals (e.g., 10ms, 100ms); deviations indicate injection.
- **CAN frame structure validation**: DLC (Data Length Code) mismatch; CAN ID outside known whitelist; signal value out of range.
- **Replay attack detection**: Repeated sequence of messages with identical timestamp patterns; protocol-aware IDS detects this.
- **CAN bus errors**: Sudden spike in error frames; ECU dominating bus (DoS signature).

### UDS Diagnostic Detection
- **Diagnostic session control**: Unauthorized `$10 03` (Extended Diagnostic) request from non-diagnostic source.
- **Security access failure**: Repeated `$27` (SecurityAccess) failures; brute force attempts on seed-key.
- **Firmware download anomaly**: `$34` (RequestDownload) from non-programmer ECU; unexpected `$37` (RequestTransferExit) requests.
- **Communication control**: `$28` (CommunicationControl) disabling other ECUs; potential attacker isolating target.

### Key Fob / RF Detection
- **Rolling code replay**: Same rolling code received twice; key fob message with timestamp earlier than last seen.
- **PKES relay attack**: Key fob signal strength anomaly (too strong for distance); signal seen by multiple antennas with suspicious timing offset.
- **Relay attack indicator**: Time-of-flight between challenge and response inconsistent with physical distance.

### GNSS / Positioning Detection
- **GNSS spoofing signatures**: Sudden jump in satellite pseudorange; carrier-to-noise ratio anomaly (too strong for environment); fix jumping between two locations.
- **Multiple signal sources**: Receiver detecting same satellite from different directions (real + spoofed).
- **Cross-validation**: IMU/odometer vs GNSS position mismatch (e.g., vehicle stationary but GNSS shows movement).

### SIEM / Vehicle Telemetry Detection
- **OEM telematics backend**: Anomaly detection on vehicle telemetry; CAN error rate spike; unexpected diagnostic codes (DTCs).
- **Splunk SPL**: `index=vehicle sourcetype=can vehicle_id=* | stats count by arbitration_id | where count > 100000`
- **Custom CAN-IDS**: Tools like CANalyzat0r, CANgue, CANdevStudio for protocol-aware monitoring.

## Defense Evasion Techniques

### CAN Injection Stealth
- **Bus flooding**: Saturate bus with high-priority CAN IDs (lowest arbitration number) to disable other ECUs (DoS) before injection.
- **Mimic legitimate ECU timing**: Send injected messages at exact periodicity of legitimate ECU; evade timing-based IDS.
- **Avoid DLC/range anomalies**: Match DLC of legitimate message; use signal values within valid range.
- **Target isolated ECUs**: Choose ECUs not monitored by CAN-IDS (legacy components without security).
- **Single-shot injection**: Send malicious payload once (one CAN frame); many IDS only catch sustained patterns.

### Diagnostic Session Stealth
- **Use already-unlocked sessions**: If vehicle is in extended diagnostic mode (workshop setting), skip SecurityAccess.
- **Seed prediction**: Some weak security implementations have predictable seeds; offline analysis reveals algorithm.
- **Distribute brute force**: Spread seed-key attempts across multiple sessions; below lockout threshold.
- **Use programmer credentials**: Compromise OEM workshop credentials; access via authorized channel.

### Key Fob Attack Stealth
- **Rolling code prediction**: Capture multiple key fob transmissions; reverse engineer PRNG; predict next code without replay.
- **Relay attack with timing compensation**: Use directional antennas and signal amplifiers to minimize timing offset; defeat ToF-based detection.
- **Multi-frequency**: Use 433MHz / 868MHz / 315MHz based on regional norm; choose least monitored.
- **Capture off-hours**: Roll back codes during low-activity windows (night); reduces detection probability.

### GNSS Spoofing Stealth
- **Gradual drift**: Slowly drift spoofed location (1-2 m/s²) to avoid sudden jump detection.
- **Match C/N0**: Match spoofed signal strength to expected (avoid "too strong" signature).
- **Single satellite spoofing**: Spoof only 1-2 satellites rather than full constellation; harder to detect via multi-antenna receivers.
- **Receiver-specific attacks**: Target GNSS chipsets known to lack anti-spoofing (older u-blox, NEO-M8 series).

### EV Charging (ISO 15118) Stealth
- **Use legitimate charging credentials**: Steal EV owner's billing credentials; charge appears legitimate.
- **V2G protocol abuse**: Exploit bidirectional charging protocols; reverse energy flow at off-peak hours.
- **PLC anomaly**: Power Line Communication attacks via mains; bypass wireless monitoring.
- **Slow charging attack**: Pace attacks below billing threshold; evade fraud detection.

## Hacker Laws

- **Trust but Verify** — The OEM claims SecOC on the brake bus. Verify by capturing a brake-command frame and replaying it — if the receiver acts on the replay, SecOC is either absent or improperly implemented. The CAN bus is ground truth; the architecture diagram is a marketing artifact.
- **Defense in Depth** — SecOC + gateway ACL + HSM + CAN-IDS + OTA update integrity. No single layer can be trusted on a vehicle bus. A 2015 Jeep had OTA + cellular modem + gateway but no filtering between the IVI bus and the powertrain bus — the single missing layer was the kill chain.
- **Assume Breach** — Design vehicle networks assuming one ECU (the TCU, the IVI, the OBD-II port) has already been compromised. Per-ECU SecOC keys, gateway default-deny ACLs, CAN-IDS signatures for cross-bus traffic. The kill chain length from "remote" to "physical effect" should be maximally long.
- **Least Privilege** — An ECU should only transmit on the arbitration IDs in its specification. A gateway should not route safety-critical messages across security domains. An OBD-II diagnostic request should not unlock programming mode in default session. Every unnecessary permission is a CAN injection vector.
- **Supply Chain Trust** — Every ECU transits from SoC vendor (NXP, Infineon, Renesas), to Tier-1 (Bosch, Continental, Denso), to OEM, to dealer, to user. The SecOC keys may have been provisioned at any step. The firmware may have been backdoored at the Tier-1. The diagnostic seed/key algorithm is frequently shared across multiple OEM platforms from the same Tier-1.
- **Minimize Attack Surface** — Disable UDS 0x27 on production ECUs where possible. Close the cellular debug interface. Require physical presence (OBD-II) for programming mode. Disable Bluetooth discoverability after pairing. Every disabled surface is one fewer vector.
- **Information Wants to Be Free** — A captured CAN trace contains the timing of every brake event, every steering input, every door open/close. A captured key fob code contains the rolling-code state. Treat every captured artifact as sensitive; redact vehicle identification before publishing.
- **Weakest Link Is Human** — Most vehicle compromises start with a Tier-1 who reused a seed/key algorithm across platforms, an OEM who left the cellular debug port open, or a dealer who shared the diagnostic tool. The supply chain, not the ECU, is the typical initial access.

## Differentiation

This is the **only** automotive-focused skill in the workspace. Adjacent skills cover overlapping layers but not the vehicle-specific stack:

- **`skills/iot-pentest/`** — General embedded/consumer IoT (MQTT, CoAP, AWS IoT). Overlap: the TCU's cloud backend (MQTT/HTTPS) is iot-pentest territory; the vehicle side of that link is automotive.
- **`skills/sdr-rf-attack/`** — General RF signal layer. Overlap: key fob capture/replay, GNSS spoofing, PKES relay amplification all use SDR; automotive applies SDR to vehicle-specific RF.
- **`skills/hardware-security/`** — Generic chip-level attacks (JTAG/UART/SWD/glitching). Overlap: ECU boot-mode straps, NAND readout, glitch attacks on secure boot.
- **`skills/binary-reverse/`** — General disassembly/decompilation. Overlap: ECU firmware analysis (Ghidra on MPC5xxx/RH850/ARM Cortex-R).
- **`skills/firmware-reverse/`** — Generic firmware extraction. Overlap: ECU firmware extraction via binwalk/flashrom.
- **`skills/scada-ics-security/`** — Industrial OT protocols. Architecturally similar (deterministic broadcast bus, no auth) but different protocols (CAN vs Modbus).
- **`skills/mobile-security/`** — iOS/Android apps. Overlap: Android Automotive head-unit pentest.
- **`skills/exploit-development/`** — Exploit dev methodology. Overlap: ECU exploit chains, IVI RCE → CAN injection kill chain.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guides**:
  - `guides/automotive-vehicle-security-playbook.md` — CAN architecture refresher, automotive lab build, ECU attack methodology, CAN bus reverse engineering methodology, key fob attack workflow, real-world incident case studies, and legal/ethical considerations.
  - `guides/automotive-ecu-firmware-and-uds-deep-dive.md` — ECU firmware extraction methods (boot mode, JTAG, NAND/eMMC, UDS dump), full UDS service matrix with security access seed-key analysis, ECU programming workflow, firmware update attacks, and secure boot bypass.
- **Reference repositories** (the inspirations for this skill):
  - `linux-can/can-utils` (Linux Foundation): reference SocketCAN userland
  - `hardbyte/python-can`: Python CAN library (SocketCAN, Kvaser, PCAN, Vector)
  - `cantools/cantools`: DBC encode/decode in Python
  - `commaai/opendbc`: open-source DBCs for many makes/models
  - `collin80/SavvyCAN`: cross-platform CAN GUI
  - `commaai/rednose` / `openpilot`: Comma.ai's open-source ADAS (CAN-heavy)
  - `eik00d/CANToolz`: black-box CAN analysis framework
  - `openxc/openxc-platform`: Ford's open vehicle platform
  - `globbottom/automotive-security` / `iDoka/awesome-canbus`: curated automotive security resources
- **External resources**:
  - ISO 11898-1:2015 (CAN / CAN-FD data link layer)
  - ISO 14229-1 (UDS) / ISO 15765-3 (DoCAN) / ISO 14230 (KWP2000)
  - ISO 15031-5 (OBD-II PIDs) / SAE J1979 (equivalent)
  - ISO/SAE 21434:2021 (Road vehicles — Cybersecurity engineering)
  - UNECE WP.29 R155 (CSMS) and R156 (SUMS) regulations
  - SAE J3061 (Cybersecurity Guidebook for Cyber-Physical Vehicle Systems)
  - Auto-ISAC (Automotive Information Sharing and Analysis Center): [automotiveisac.com](https://automotiveisac.com)
  - Miller & Valasek, "Remote Exploitation of an Unaltered Passenger Vehicle" (DEF CON 23, 2015): [illmatics.com/Remote%20Car%20Hacking.pdf](http://illmatics.com/Remote%20Car%20Hacking.pdf)
  - Tencent Keen Lab, "Experimental Security Assessment of BMW Cars" (2017), "Experimental Security Assessment of Tesla Models" (2017)
  - Ken Tindell, "Controller Area Network (CAN) Bus: Implications of the UK CAN Bus Thefts" (2023): analysis of PKES relay and CAN injection thefts
  - IEEE Spectrum "Hackers Remotely Attack a Tesla" (2017)
  - DEF CON Car Hacking Village archives (annual since 2014)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
