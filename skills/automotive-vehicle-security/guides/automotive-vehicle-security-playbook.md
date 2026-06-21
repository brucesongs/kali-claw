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
