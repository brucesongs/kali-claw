# Automotive & Vehicle Security — Quick Reference Card

> One-page-ish reference for vehicle security red teamers. Pin to the wall above the bench.
>
> Companion to `automotive-vehicle-security-playbook.md`, `automotive-ecu-firmware-and-uds-deep-dive.md`, and `real-world-incident-case-studies.md`.

---

## Overview

This card collects the numbers, pinouts, and service IDs you use every day on the bench but can never quite remember. Sources: ISO 11898, ISO 14229-1, ISO 13400, J1962, J1939, AUTOSAR SecOC, FCC Part 15/ETSI EN 300 220, OEM service manuals, DEF CON Car Hacking Village handouts.

---

## Objective

Reduce trips to Google by 80%. If you remember the section headings, you remember the card exists.

---

## OBD-II Connector (J1962) Pinout

16-pin D-shell, type A (12V) or type B (24V, modified keying). Female on the vehicle, male on the tester.

```
        ┌─────────────────────┐
        │  1  2  3  4  5  6  7  8 │
        │  9 10 11 12 13 14 15 16 │
        └─────────────────────┘
            (vehicle-facing)
```

| Pin | Signal | Notes |
|-----|--------|-------|
| 1 | Vendor-specific | Often OEM diagnostic enable |
| 2 | J2284 CAN-H (high-speed) | Ford / GM / PSA |
| 3 | Vendor-specific | |
| 4 | Chassis ground | Always |
| 5 | Signal ground | Always |
| 6 | ISO 15765-4 CAN-H (HS-CAN) | Mandatory since 2008 (OBD-II mandate) |
| 7 | ISO 9141-2 / K-line | Legacy |
| 8 | Vendor-specific | |
| 9 | Vendor-specific | |
| 10 | J2284 CAN-L (high-speed) | Ford / GM / PSA |
| 11 | Vendor-specific | |
| 12 | Vendor-specific | Often MS-CAN / CAN-L for medium-speed |
| 13 | Vendor-specific | Often MS-CAN / CAN-H |
| 14 | ISO 15765-4 CAN-L (HS-CAN) | Mandatory since 2008 |
| 15 | ISO 9141-2 / L-line | Legacy |
| 16 | Vehicle battery (+12V or +24V) | Always on; 8A max draw |

**Common CAN buses on J1962:**

- Pins 6/14 — HS-CAN (high-speed, 500 kbps), the OBD-II mandated bus.
- Pins 3/11 — MS-CAN (medium-speed, 125 kbps), Ford/PSA body bus.
- Pins 12/13 — SW-CAN (single-wire, 33.3 kbps), GM GMLAN low-speed.

**CAN-H vs CAN-L on the wire:**

- CAN-H idle: 2.5V. Dominant: 3.5V.
- CAN-L idle: 2.5V. Dominant: 1.5V.
- Differential (CAN-H − CAN-L): idle 0V, dominant 2V.
- Common-mode: 2.5V (terminate 120Ω at each end, 60Ω measured across with both terminators in circuit).

---

## CAN Frame Structure (ISO 11898)

### Classic CAN (11-bit ID)

```
┌─────┬──────┬────┬──────────┬─────┬───────┬─────────┬─────┬───┬──────┬─────────┐
│ SOF │ ID11 │RTR│ IDE │ r0 │ DLC │ Data0-7 │ CRC │CRCd│ ACK │EOF │ IFS │
│  1b │ 11b  │ 1b│ 1b  │ 1b │  4b  │ 0-64b   │ 15b │ 1b │ 1b  │ 7b │  3b │
└─────┴──────┴────┴──────────┴─────┴───────┴─────────┴─────┴───┴──────┴─────────┘
```

### Extended CAN (29-bit ID)

```
SOF | ID11 | SRR (=1) | IDE (=1) | ID18 | RTR | r1 | r0 | DLC | Data | CRC | ACK | EOF | IFS
 1b | 11b  |    1b    |    1b    | 18b  | 1b  | 1b | 1b |  4b | 0-64 | 15b | 1b  | 7b  | 3b
```

**Fields:**

- **SOF**: start of frame, dominant bit.
- **ID**: arbitration ID. Lower number = higher priority. Bitwise AND-ed across all transmitters; non-destructive arbitration.
- **RTR**: remote transmission request (1 = request frame, 0 = data frame). Almost never used in modern vehicles.
- **IDE**: identifier extension (1 = 29-bit ID).
- **r0, r1**: reserved bits, dominant.
- **DLC**: data length code (0-8 for classic CAN; 0-15 means 12/16/20/24/32/48/64 for CAN-FD).
- **Data**: 0-8 bytes classic, 0-64 bytes CAN-FD.
- **CRC**: 15-bit classic, 17-bit CAN-FD up to 16 bytes, 21-bit CAN-FD above 16 bytes.
- **ACK**: dominant bit transmitted by any receiver that successfully decoded the frame.
- **EOF**: 7 recessive bits, marks end of frame.

### Arbitration Example

Three ECUs transmit simultaneously:

- ECU A: ID 0x100
- ECU B: ID 0x200
- ECU C: ID 0x080

Winner: **ECU C** (lowest numeric ID). A and B back off and retransmit after EOF + IFS.

---

## UDS (ISO 14229-1) Service ID Cheatsheet

UDS service IDs (SID) are 1 byte. Request SID is `0x10-0x3E`. Response SID is `request + 0x40`. Negative response SID is `0x7F`.

| SID | Service | Purpose | Notes |
|-----|---------|---------|-------|
| 0x10 | DiagnosticSessionControl | Switch session (default, programming, extended) | Sub: 0x01 default, 0x02 programming, 0x03 extended |
| 0x11 | ECUReset | Hard / soft / key-off reset | Sub: 0x01 hard, 0x02 key-off, 0x03 soft |
| 0x14 | ClearDiagnosticInformation | Clear DTCs | |
| 0x19 | ReadDTCInformation | Read stored DTCs | Sub-function controls mask, status, snapshot |
| 0x22 | ReadDataByIdentifier | Read parameter by DID | Most-used service |
| 0x23 | ReadMemoryByAddress | Read arbitrary memory (programming only) | |
| 0x24 | ReadScalingDataByIdentifier | Read scaling metadata | |
| 0x27 | SecurityAccess | Seed-key exchange | Sub: odd = request seed, even = send key |
| 0x28 | CommunicationControl | Enable/disable Rx/Tx | |
| 0x2A | ReadDataByPeriodicIdentifier | Periodic data push | |
| 0x2C | DynamicallyDefineDataIdentifier | Build composite DID at runtime | |
| 0x2E | WriteDataByIdentifier | Write parameter by DID | Often requires SecurityAccess |
| 0x2F | InputOutputControlByIdentifier | Actuator control (e.g., turn on fan) | IOCT |
| 0x31 | RoutineControl | Run/stop vendor routine | Sub: 0x01 start, 0x02 stop, 0x03 request result |
| 0x34 | RequestDownload | Initiate ECU flash | |
| 0x35 | RequestUpload | Initiate ECU memory dump | |
| 0x36 | TransferData | Block-by-block transfer | |
| 0x37 | RequestTransferExit | Close transfer | |
| 0x38 | RequestFileTransfer | File-system aware transfer | |
| 0x3D | WriteMemoryByAddress | Write arbitrary memory | |
| 0x3E | TesterPresent | Keep session alive | Send every 4s default |

**Negative Response Codes (NRC, 3rd byte of 0x7F response):**

| NRC | Meaning |
|-----|---------|
| 0x10 | General reject |
| 0x11 | Service not supported |
| 0x12 | Sub-function not supported |
| 0x13 | Incorrect message length or invalid format |
| 0x14 | Response too long |
| 0x21 | BusyRepeatRequest |
| 0x22 | Conditions not correct |
| 0x24 | Request sequence error |
| 0x31 | Request out of range |
| 0x33 | Security access denied |
| 0x35 | Invalid key |
| 0x36 | Exceeded number of attempts |
| 0x37 | Required time delay not expired |
| 0x70 | Upload/download not accepted |
| 0x71 | Transfer data suspended |
| 0x72 | General programming failure |
| 0x73 | Wrong block sequence counter |
| 0x78 | Response pending (requestCorrectlyReceivedResponsePending) |
| 0x7E | Sub-function not supported in active session |
| 0x7F | Service not supported in active session |

---

## DBC File Format Quick-Start

A DBC (Database CAN) file describes the signals on a CAN bus. Created by Vector CANdb++ or `cantools` (OSS).

```dbc
VERSION ""

NS_ :
    NS_DESC_
    CM_
    BA_DEF_
    BA_
    VAL_
    CAT_DEF_
    CAT_
    FILTER
    BA_DEF_DEF_
    EV_DATA_
    ENVVAR_DATA_
    SGTYPE_
    SGTYPE_VAL_
    BA_DEF_SGTYPE_
    BA_SGTYPE_
    SIG_TYPE_REF_
    VAL_TABLE_
    SIG_GROUP_
    SIG_VALTYPE_
    SIGTYPE_VALTYPE_
    BO_TX_BU_
    BA_DEF_REL_
    BA_REL_
    BA_DEF_DEF_REL_
    BU_SG_REL_
    BU_EV_REL_
    BU_BO_REL_
    SG_MUL_VAL_

BS_:

BU_: Engine BCM ABS Gateway TCU

BO_ 256 EngineStatus: 8 Engine
 SG_ EngineRPM : 0|16@1+ (0.25,0) [0|16383.75] "rpm" Gateway,BCM
 SG_ EngineTemp : 16|8@1+ (1,-40) [-40|215] "degC" Gateway
 SG_ ThrottlePosition : 24|8@1+ (0.4,0) [0|100] "%" Gateway,ABS

BO_ 512 BrakeStatus: 8 ABS
 SG_ BrakePressure : 0|14@1+ (0.1,0) [0|1638.3] "kPa" Gateway,Engine
 SG_ ABSActive : 14|1@1+ (1,0) [0|1] "" Gateway

CM_ BO_ 256 "Engine ECU broadcast, 100ms cycle";
CM_ SG_ 256 EngineRPM "Range 0-16383.75 rpm with 0.25 rpm resolution";

BA_DEF_ BO_ "GenMsgCycleTime" INT 0 100000;
BA_DEF_ BO_ "GenMsgSendType" ENUM "Cyclic","Event","NoMsgSendType";
BA_ "GenMsgCycleTime" BO_ 256 100;
BA_ "GenMsgCycleTime" BO_ 512 20;
BA_ "GenMsgSendType" BO_ 256 Cyclic;
```

**Key syntax:**

- `BO_ <id> <name>: <len> <sender>` — message definition.
- `SG_ <name> : <start_bit>|<length>@<byte_order><sign> (<factor>,<offset>) [<min>|<max>] "<unit>" <receivers>` — signal definition.
- Byte order: `@1` = little-endian (Intel), `@0` = big-endian (Motorola).
- Sign: `+` unsigned, `-` signed.

**Python tooling:**

```python
import cantools
db = cantools.database.load_file('hs-can.dbc')
msg = db.get_message_by_name('EngineStatus')
print(msg.frame_id)              # 256
decoded = msg.decode(b'\x01\x02\x03\x04\x05\x06\x07\x08')
print(decoded['EngineRPM'])      # e.g. 1340.25 rpm
```

**Reverse-engineering a DBC:**

1. Capture 30+ minutes of traffic at idle, then at various RPM/load.
2. Use `canalyzer` or `savvy-can` to identify candidate signals by signal frequency.
3. Use **frequency clustering**: an engine RPM signal updates at 10 ms, a coolant temp at 1 s.
4. Match signal value changes to known actuations (e.g., rev engine to 3000 rpm, find signal that goes from 0x0FA0 to 0x1C20).
5. Validate by replaying attacker-chosen values via `python-can`.

---

## Key Fob RF Reference

### Frequencies

| Region | Frequency | Modulation | Use |
|--------|-----------|------------|-----|
| North America | 315 MHz | ASK / OOK / FSK | Key fob, tire pressure |
| Europe | 433.92 MHz | ASK / FSK | Key fob |
| Europe | 868 MHz | FSK | Aftermarket alarms |
| Asia / Japan | 426 MHz / 429 MHz / 434 MHz | Various | Key fob |
| Global | 315 MHz / 433.92 MHz | FSK | TPMS (tire pressure) |
| Global | 2.4 GHz | BLE / GFSK | Modern PEPS / PKES |

### Modulation

- **ASK (Amplitude Shift Keying)**: amplitude changes (on/off). Simple, low-cost, vulnerable to replay.
- **OOK (On-Off Keying)**: special case of ASK (full on/off). Common on older Toyota / GM fobs.
- **FSK (Frequency Shift Keying)**: frequency deviation (e.g., ±25 kHz). More robust, used on European and newer Asian fobs.

### Common Cipher Suites

| Cipher | Used By | Status |
|--------|---------|--------|
| **Hitag-2** | Older Honda / VW / Fiat | **Broken** (2008+); do not use |
| **Hitag-AES (v3)** | Renault, Honda post-2015 | Weak, side-channel attacks |
| **Keeloq** | Many GM / Chrysler / Toyota | **Broken** (rolling-code attack, 2008+) |
| **Keeloq+** | Updated Keeloq | Side-channel vulnerable |
| **AUT64** | VW group (2005+) | **Broken** (2016+) |
| **XTS-AES / RSA-1024 seed-key** | Modern PEPS / PKES | Current best practice; relay-attack resistant if UWB |

### PKES / PASE Protocol References

- **Bosch PEPS 3rd gen** — distance bounding via UWB (2020+).
- **Continental PASE 2.0** — BLE + UWB hybrid.
- **Marquardt** — Tesla fob supplier, BLE + UWB on Model 3 Refresh.
- **Hella** — BMW / Mercedes supplier.

### Relay Attack Hardware

| Tool | Cost | Capability |
|------|------|------------|
| HackRF One | $330 | Full SDR, 1 MHz – 6 GHz, RX + TX |
| RTL-SDR (RTL2832U) | $25 | RX only, 25 MHz – 1.7 GHz |
| ESP32 + nRF52 | $15 | BLE relay (custom firmware) |
| Proxmark3 RDV4 | $400 | RFID + LF/HF, classic PEPS relay |
| Yagi antenna + LNA | $40 | Signal boost for relay |

---

## OEM Diagnostics over IP (DoIP) Reference

ISO 13400. DoIP runs on TCP 13400, UDP 13400.

| OEM | DoIP Port | Notes |
|-----|-----------|-------|
| BMW | 13400/tcp | Standard ISO 13400; EGW (Electric Gateway) handles routing |
| Mercedes-Benz | 13400/tcp | EGW (Central Gateway); HU and ECU behind it |
| VW Group (VW / Audi / Porsche) | 13400/tcp | On 2018+ MQB-evo / MLB-evo platforms |
| GM Global A | 13400/tcp | GMLAN over IP |
| Ford CPI | 13400/tcp | Common Platform Architecture |
| Tesla | 13400/tcp (debug mode only) | CID-bridged, normally disabled |
| Toyota TSIP | 13400/tcp (Toyota-specific) | TNGA platform |

**DoIP discovery:**

```bash
# Send a DoIP Vehicle Identification Request (UDP broadcast to 255.255.255.255:13400)
echo -ne '\x02\xfd\x00\x01\x00\x00\x00\x00' | socat - UDP-DATAGRAM:255.255.255.255:13400,broadcast
```

**DoIP logical address ranges:**

- 0x0000-0x07FF: reserved.
- 0x0E00-0x0FFF: VIN-synced logical address.
- 0x1000-0x1FFF: BMW-specific.
- 0x2000-0x2FFF: Mercedes-specific.
- 0x3000-0x3FFF: VW Group-specific.

---

## IVI OS Platforms and Identifiers

| Platform | Vendor | Identifiers |
|----------|--------|-------------|
| Android Automotive OS (AAOS) | Google | `android.automotive.*` package namespace; SurfaceFlinger + CarService |
| QNX CAR / QNX Neutrino | BlackBerry | `.qnx.*` paths; Photon micro-GUI |
| Automotive Grade Linux (AGL) | Linux Foundation | `/etc/agl-version` |
| webOS Auto | LG | `webos-automotive` |
| Linux + Qt (Genivi / COVESA) | Industry consortium | `/etc/os-release` |
| WinCE / Windows Embedded | Microsoft (legacy) | `\Windows\` paths |
| proprietary RTOSes (VxWorks, OSEK, AUTOSAR Classic) | Various | — |

**Common filesystem artifacts for forensic fingerprinting:**

- Android Automotive: `/system/etc/automotive/manifest.xml`, `/vendor/etc/automotive/vehicle/2.0/types.hal`
- QNX: `/etc/system/config/*.cfg`, `/proc/qnx/*`
- AGL: `/etc/os-release`, `/etc/agl/`

---

## Top 10 Automotive CVEs (2020-2026)

| CVE | Year | Affected | Summary |
|-----|------|----------|---------|
| CVE-2023-29189 | 2023 | Tesla Model 3 (HW3) | Synacktiv Pwn2Own chain; CID to CAN |
| CVE-2022-38766 | 2022 | Multiple BMW (most) | USB descriptor RCE → CAN |
| CVE-2022-27254 | 2022 | Honda (multiple) | Remote engine start via rolling-code replay |
| CVE-2021-3538 | 2021 | Hyundai (Bluelink) | Cloud API JWT bypass |
| CVE-2021-21551 | 2021 | Dell BIOS (used in many IVI bases) | Heap overflow in dbutil_2_3.sys |
| CVE-2021-33026 | 2021 | Realtek SDK (used in IVI Wi-Fi) | Buffer overflow in association |
| CVE-2020-27190 | 2020 | Honda key fob | Hitag-2 cipher plaintext recovery |
| CVE-2020-12753 | 2020 | Mitsubishi Outlander PHEV | Wi-Fi access point with hardcoded password |
| CVE-2024-23652 | 2024 | Tesla Model S (HW4) | CID GPU bridge — follow-up to 2023 chain |
| CVE-2024-39929 | 2024 | Mercedes-Benz W213 | UDS seed-key replay across 9 ECUs |

**Where to search for new CVEs:**

- NVD: `https://nvd.nist.gov/vuln/search/results?cpe_version=cpe:/h`
- ICS-CERT: `https://www.cisa.gov/news-events/cybersecurity-advisories`
- Auto-ISAC: `https://automotiveisac.com/` (members only)
- OEM PSIRT pages (see `real-world-incident-case-studies.md` References).

---

## Response Playbook — Suspected CAN Injection (5 Steps)

If your fleet SOC detects CAN injection (frames that the OEM did not originate):

1. **Capture** — Tap the bus via OBD-II, record 5+ minutes of traffic to `.asc` / `.pcap`. Note timestamp, ignition state, vehicle location. Use `canalyzer`, `savvy-can`, or `python-can` to file.
2. **Diff vs Baseline** — Compare to your fleet DBC baseline. Flag IDs with >2σ frequency deviation, IDs that don't appear in baseline, or known-good signal values out of range.
3. **Isolate** — If vehicle in motion: do **not** cut the bus (safety risk). Move to a controlled area. Then disconnect the suspected ECU's connector or pull the relevant CAN fuse.
4. **Forensic Capture** — Pull ECU firmware (UDS 0x22 ReadDataByIdentifier, F1A0 = "ECU Manufacturing Data"), read DTCs (UDS 0x19), pull TCU logs (cellular, GPS). Capture all before the ECU is power-cycled (which may clear RAM).
5. **Report** — Contact OEM PSIRT via Auto-ISAC (24 h SLA). If safety implication, file NHTSA Office of Defects Investigation report (USA) or equivalent in your jurisdiction. Do not publish details until 90-day coordinated disclosure window expires.

---

## Field-Tested `python-can` Snippets

```python
import can

# Setup (Linux SocketCAN, after `ip link add dev can0 type can` etc.)
bus = can.interface.Bus(channel='can0', interface='socketcan')

# Read 30s of traffic
import time
start = time.time()
msgs = []
while time.time() - start < 30:
    msg = bus.recv(timeout=1.0)
    if msg:
        msgs.append(msg)

# Find IDs by frequency
from collections import Counter
id_counts = Counter(m.arbitration_id for m in msgs)
for aid, count in id_counts.most_common(10):
    print(f"0x{aid:04X}: {count} frames ({count/len(msgs)*100:.1f}%)")

# Inject a test frame
bus.send(can.Message(arbitration_id=0x123, data=[0x01, 0x02, 0x03], is_extended_id=False))
```

---

## Useful Hardware

| Tool | Purpose | Cost |
|------|---------|------|
| **PCAN-USB** (Peak System) | CAN adapter, drivers on all platforms | $300 |
| **Kvaser Leaf Light v2** | CAN adapter, Linux native | $400 |
| **CANalyst-II** | Cheap clone, $15 | $15 |
| **OpenPort 2.0** | J2534 passthrough, Subaru/Mitsubishi | $180 |
| **Macchina M2** | Open-source OBD-II dev board | $100 |
| **HackRF One** | SDR for key fob / TPMS work | $330 |
| **Proxmark3 RDV4** | LF/HF RFID, classic PEPS | $400 |
| **Aardvark I2C/SPI** | ECU firmware extraction | $300 |
| **Shikra + JTAGulator** | JTAG / UART discovery on ECUs | $200-$400 |

---

## References and Resources

### Standards Bodies

- **ISO** (International): ISO 11898 (CAN), ISO 14229 (UDS), ISO 13400 (DoIP), ISO 17987 (LIN), ISO 17458 (FlexRay), ISO/SAE 21434 (Cybersec Engineering), ISO 15118 (EV charging).
- **SAE** (USA): J1962 (OBD-II connector), J1939 (heavy-duty CAN), J2602 (LIN), J3061 (Cybersec Guidebook).
- **AUTOSAR**: AP R19-11 / Classic R4.x specifications (SecOC, CryptoStack, Diagnostics).
- **UNECE**: R155 (CSMS), R156 (SUMS).
- **IEEE**: 802.3bp (100/1000BASE-T1), 802.15.4z (UWB distance bounding).

### Communities

- **DEF CON Car Hacking Village** — defcon.org
- **Black Hat Automotive** — blackhat.com
- **I Am The Cavalry** — iamthecavalry.org
- **Auto-ISAC** — autoisac.com
- **OWASP Internet of Things Project** — Automotive sections
- **OpenGarages** — opengarages.org (Craig Smith's community)
- **CANbus Node** — forum.canbusnode.com

### Tool Documentation

- **python-can** — `python-can.readthedocs.io`
- **cantools** — `cantools.readthedocs.io`
- **udsoncan** — `udsoncan.readthedocs.io`
- **SavvyCAN** — `github.com/collin80/SavvyCAN`
- **can-utils** — `github.com/linux-can/can-utils`
- **Open Vehicle Monitoring System (OVMS)** — `github.com/openvehicles/Open-Vehicle-Monitoring-System-3`

### Books

- *The Car Hacker's Handbook* — Craig Smith (No Starch, 2016).
- *2014 Car Hacker's Handbook* — Craig Smith.
- *A Comprehensible Guide to Controller Area Network* — Wilfried Voss.
- *Embedded Networking with CAN and CAN-FD* — Wilfried Voss.
- *ISO/SAE 21434: A Cybersafety Field Guide* — Wayne Statham (2022).
- *Hacking the Tesla* — Nie, Liu, Du (2017).

### CVD Programs

- I Am The Cavalry — *Coordinated Disclosure for Connected Vehicles* (2015, revised 2020).
- Auto-ISAC Best Practices — security.autoisac.com/best-practices.

---

## Practice Exercise

Reproduce the **DBC reverse-engineering** workflow on a development vehicle:

1. Capture 30 minutes of HS-CAN traffic via PCAN-USB.
2. Save to `.log` / `.asc`.
3. Load into SavvyCAN or `cantools`.
4. Identify the engine RPM signal (frequency ~10 Hz, value increases with engine speed).
5. Identify the vehicle speed signal (similar frequency, value matches speedometer).
6. Validate by replaying attacker-controlled values via `python-can`.
7. Write a one-page DBC and submit to your team's CVD database.

This is the foundation of every vehicle security engagement: **know thy bus**.

---

*Last updated: 2026-07. Cross-reference `real-world-incident-case-studies.md` for the case studies that produced these references.*
