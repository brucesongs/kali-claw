# Automotive & Vehicle Security Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a bench ECU / dyno / closed-course environment, or a virtual CAN simulator (vcan). Never run active exploitation against a moving production vehicle without explicit written authorization from the owner AND the manufacturer.

## Prerequisites

Before executing any test case in this catalogue, verify the following pre-conditions are met:

1. **Authorization**: Written authorization from the vehicle owner AND the manufacturer covering the specific vehicle VIN, the specific ECU parts, and the specific test scope. For closed-course tests, additional authorization from the facility operator and the insurance underwriter.
2. **Hardware**: The appropriate CAN adapter (USBTin, PCAN-USB, Kvaser, Vector VN1630), a bench ECU or salvaged ECU for destructive tests, and (for GNSS tests) a Faraday cage or shielded enclosure.
3. **Software**: `can-utils`, `python-can`, `cantools`, `scapy` (with automotive layers), `OpenOCD`, `flashrom` (see `payloads.md` §1 for install commands).
4. **Safety**: For any test that transmits on a vehicle CAN bus, a closed course with a safety driver is mandatory. Safety-critical injections (brake, steer, powertrain, airbag) require explicit additional authorization beyond the general scope.
5. **Legal review**: For tests involving key fob capture/replay, GNSS transmission, or PLC interception on charging stations, the engagement must be reviewed by legal counsel. 18 USC §1029 (US), Fraud Act 2006 (UK), and equivalent national laws apply.

---

## Verification Checklist

After executing each test case, verify the following pass criteria before marking the test complete:

- [ ] **Captured evidence**: ASC/pcap trace saved with timestamp; screenshots of GUI tools (Savvy-CAN, inspectrum, u-center).
- [ ] **Reproducibility**: The test was run at least twice with consistent results; documented any intermittent failures.
- [ ] **Scope compliance**: No CAN frames transmitted outside the engagement scope; no safety-critical message IDs targeted without explicit authorization.
- [ ] **Post-test cleanup**: All UDS extended sessions closed; all test DTCs cleared (`cansend can0 7DF#02040000000000`); any modified ECU calibration restored.
- [ ] **Documentation**: Finding documented with severity, MITRE ATT&CK mapping, tool list, and remediation guidance.
- [ ] **Safety check**: For moving-vehicle tests, the safety driver confirms no unintended physical effect occurred outside the planned test vector.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Lab Setup & Bus Sniffing | 2 | INFO - LOW |
| B. DBC Reversing & UDS | 2 | MEDIUM - HIGH |
| C. CAN-FD & Black-Box Frameworks | 2 | MEDIUM - HIGH |
| D. IVI & OBD-II | 2 | MEDIUM - HIGH |
| E. RF / Key Fob / GNSS | 2 | HIGH - CRITICAL |
| F. EV Charging & Detection | 2 | HIGH - CRITICAL |
| **Total** | **12** | **INFO - CRITICAL** |

---

## A. Lab Setup & Bus Sniffing

### TC-AV-001: SocketCAN + can-utils Lab Bring-up

| Field | Value |
|------|-----|
| **ID** | TC-AV-001 |
| **Title** | SocketCAN + can-utils Lab Bring-up (Virtual CAN and USBTin) |
| **Objective** | Stand up a working SocketCAN environment on Kali Linux using both a virtual CAN interface (vcan0, no hardware) and a real USBTin USB-to-CAN adapter, then verify with candump/cansend loopback. |
| **Steps** | 1. `sudo apt-get install -y can-utils` and verify `candump --version`.<br>2. Bring up a virtual CAN: `sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0`.<br>3. Confirm interface: `ip -details link show vcan0` (should show `can` kind).<br>4. Run loopback test in two terminals: `candump -L vcan0` in one, `cansend vcan0 123#DEADBEEFCAFEBABE` in another; verify the frame appears in the capture.<br>5. Repeat with USBTin: `sudo slcand -o /dev/ttyACM0 -s 500000 -S 500000 can0 && sudo ip link set up can0`, then run the same candump/cansend loopback against a bench ECU. |
| **Expected Result** | Both vcan0 and the physical can0 interface come up cleanly; the candump terminal receives the sent frame with a timestamp. CAN-H/CAN-L pinout (OBD-II pin 6 / 14) is verified by reading engine RPM PID 0x0C from a connected ECU. |
| **Tools** | can-utils (candump, cansend, slcand), iproute2 (ip), vcan kernel module, USBTin adapter |
| **MITRE** | N/A (environment setup) |
| **Difficulty** | 1 - Beginner |
| **Tags** | lab, socketcan, vcan, usbtin, bringup |

### TC-AV-002: CAN Bus Passive Sniffing

| Field | Value |
|------|-----|
| **ID** | TC-AV-002 |
| **Title** | CAN Bus Passive Sniffing with candump and cansniffer |
| **Objective** | Capture a live CAN trace from a target vehicle / bench ECU without transmitting any frames, identify the active arbitration IDs, and produce an inventory of observed message rates and ECU tiers. |
| **Steps** | 1. With explicit authorization and the vehicle ignition ON (engine off), connect the CAN adapter to OBD-II pins 6 (CAN-H), 14 (CAN-L), 4 (GND), 16 (12V).<br>2. Verify bitrate: most passenger vehicles use 500 kbps; some (notably older GM) use 33.3 kbps (single-wire CAN, GMLAN); heavy-duty uses 250 kbps (J1939).<br>3. Passive capture: `candump -L can0 > trace.asc` — never transmit during capture.<br>4. Live delta view: `cansniffer -c can0` — observes which arbitration IDs are changing and at what rate.<br>5. After a 5-minute capture, count unique arbitration IDs: `awk '{print $2}' trace.asc \| sort -u \| wc -l`, and group by ID range (0x000-0x7FF standard, 0x80000000+ extended). |
| **Expected Result** | A complete inventory of active arbitration IDs with their message rates (typically 10–100 ms periodic for powertrain, 100–1000 ms for body). Identifies ECU tiers by ID range and reveals diagnostic bus addresses (0x7E0-0x7E7 physical, 0x7DF functional broadcast). |
| **Tools** | can-utils (candump, cansniffer), SocketCAN, USBTin or equivalent adapter |
| **MITRE** | TA0007-Discovery (T1046 — network service discovery analog for CAN bus enumeration) |
| **Difficulty** | 2 - Easy |
| **Tags** | can, sniffing, passive, arbitration-id, ecu-inventory |

---

## B. DBC Reversing & UDS

### TC-AV-003: DBC File Reversing with cantools

| Field | Value |
|------|-----|
| **ID** | TC-AV-003 |
| **Title** | DBC File Reversing with cantools and Side-Channel Correlation |
| **Objective** | Decode observed CAN frames using a known-good DBC (OpenDBC), validate the DBC against captured frames via side-channel correlation, and identify candidate signals for follow-on injection. |
| **Steps** | 1. `pip3 install cantools` and clone OpenDBC: `git clone https://github.com/commaai/opendbc`.<br>2. Dump the structure: `cantools dump opendbc/dbc/hyundai/hyundai_generic.dbc \| head -30`.<br>3. Decode a single captured frame: `cantools decode opendbc/dbc/hyundai/hyundai_generic.dbc 379#0080000000`.<br>4. Side-channel validation: capture a baseline trace (`candump -L can0 > baseline.asc`), then manipulate a single known state (key on, brake pedal depressed, steering wheel at 0° then 90°), and capture again (`rotated.asc`). Diff the two to find which arbitration IDs and bit positions changed.<br>5. Cross-reference changed bits with the DBC signal definitions; confirm RPM, speed, steering angle, brake pressure match the known physical state. |
| **Expected Result** | Validated DBC with at least 3 known-good signals (RPM against tachometer, speed against GPS, brake against pedal). Any mismatch between DBC and observed behavior is documented as a calibration/model-year mismatch — the DBC must not be trusted for injection until reconciled. |
| **Tools** | cantools (Python), OpenDBC repository, can-utils (candump) |
| **MITRE** | TA0007-Discovery (T1082 — system information discovery analog for signal layout enumeration) |
| **Difficulty** | 3 - Medium |
| **Tags** | dbc, cantools, opendbc, side-channel, signal-reversing |

### TC-AV-004: UDS Enumeration with scapy

| Field | Value |
|------|-----|
| **ID** | TC-AV-004 |
| **Title** | UDS (ISO 14229-1) Service Enumeration and SecurityAccess Probe |
| **Objective** | Walk every ECU on the diagnostic bus (0x7E0-0x7E7) and the functional broadcast (0x7DF), enumerate supported UDS services (0x10-0x3E), open extended diagnostic sessions, and probe 0x27 SecurityAccess for seed exposure. |
| **Steps** | 1. Confirm ISO-TP reachability: `cansend can0 7DF#02010F0000000000` (mode 0x01 PID 0x0F) and capture the response on 0x7E8.<br>2. Open extended diagnostic session on each physical address 0x7E0-0x7E7: `cansend can0 7E0#0210030000000000` (UDS 0x10 subfunc 0x03).<br>3. Enumerate services 0x10-0x3E: for each, send `cansend can0 7E0#02<svc>0000000000` and capture response. Positive responses start with `svc+0x40`; negative responses start with `0x7F svc NRC`.<br>4. For ECUs that expose 0x27 (SecurityAccess), request the seed: `cansend can0 7E0#0227010000000000` — capture the seed bytes, document seed length (typically 2 or 4 bytes).<br>5. Document any ECU where 0x27 is exposed in default session (HIGH severity), where the seed length is 1-2 bytes (brute-forceable in minutes), or where 0x23 (ReadMemoryByAddress) is exposed. |
| **Expected Result** | Per-ECU service matrix: which UDS services are supported, in which sessions, with what authentication requirements. HIGH/CRITICAL findings: 0x27 in default session, weak seed length, 0x23/0x34-0x37 exposed without authentication, 0x11 ECUReset reachable. |
| **Tools** | scapy (with automotive.uds layer), python-can, can-utils (cansend, candump), Savvy-CAN |
| **MITRE** | TA0007-Discovery (T1046), TA0009-Collection (T1602 — data from configuration repository analog for ECU memory readout) |
| **Difficulty** | 4 - Hard |
| **Tags** | uds, iso-14229, securityaccess, seed-key, ecu-enumeration |

---

## C. CAN-FD & Black-Box Frameworks

### TC-AV-005: CAN-FD Capture and Decode

| Field | Value |
|------|-----|
| **ID** | TC-AV-005 |
| **Title** | CAN-FD Bus Capture, Decode, and Replay Validation |
| **Objective** | Bring up a CAN-FD interface on Linux, capture CAN-FD frames (up to 64-byte payloads, dual bit-rate), and validate the captured trace against a known-good signal set. |
| **Steps** | 1. Confirm adapter supports CAN-FD (PCAN-USB FD, Kvaser Hybrid, Vector VN1630, Lawicel CANUSB-FD, ESP32 with TWAI FD).<br>2. Configure the interface with dual bit-rate: `sudo ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on && sudo ip link set up can0`.<br>3. Verify MTU: `ip link show can0` should show `mtu 72` (CAN-FD frame maximum).<br>4. Passive capture: `candump -L can0 fd trace-fd.asc` (the `-f` / fd flag enables FD-aware dumping).<br>5. Decode with cantools using a CAN-FD-aware DBC (`cantools dump --fd dbcfdf.dbc`) — verify at least 2 known signals match physical state.<br>6. Confirm FD flags (BRS = bit-rate switch, ESI = error state indicator) are set as expected by the OEM. |
| **Expected Result** | CAN-FD interface up at 500 kbps arbitration / 2 Mbps data; captured frames show 64-byte payloads and BRS flag set. DBC decode matches physical state for at least 2 signals. |
| **Tools** | can-utils (with CAN-FD support), SocketCAN (kernel 4.8+), python-can (>=3.0), cantools, FD-capable adapter |
| **MITRE** | TA0007-Discovery (T1046) |
| **Difficulty** | 3 - Medium |
| **Tags** | can-fd, iso-11898-1-2015, brs, esi, 64-byte, dbitrate |

### TC-AV-006: CANToolz Black-Box Analysis

| Field | Value |
|------|-----|
| **ID** | TC-AV-006 |
| **Title** | CANToolz Black-Box CAN Analysis (Capture, Fuzz, Mine) |
| **Objective** | Use the CANToolz framework (eik00d, BH EU 2016) to perform black-box CAN analysis: capture, period/frequency mining, fuzz injection, and DBC inference without any prior knowledge of the bus. |
| **Steps** | 1. Install: `git clone https://github.com/CANToolz/CANToolz && cd CANToolz && pip3 install -r requirements.txt`.<br>2. Configure modules: capture (candump), mine (period/frequency), send (injection), protect (whitelist).<br>3. Capture a baseline for 60 seconds using the `capture` module; pipe to the `mine` module to identify periodic frames.<br>4. Use the `fuzz` module to inject random 8-byte payloads on identified arbitration IDs and observe vehicle behavior (only on a bench ECU or closed course with explicit authorization).<br>5. Use the `send` module to replay captured frames; document any physical effect (dashboard needle movement, light activation).<br>6. Use the `protect` module to build a whitelist of "known good" arbitration IDs — a baseline for CAN-IDS detection tuning (TC-AV-012). |
| **Expected Result** | Per-arbitration-ID message-rate map; identified candidate actuator IDs from fuzzing (frames that produced visible effect); baseline whitelist for IDS tuning. Any fuzz finding that produced a physical effect is HIGH/CRITICAL and requires immediate scope re-confirmation. |
| **Tools** | CANToolz framework, SocketCAN, python-can, bench ECU or closed-course vehicle |
| **MITRE** | TA0007-Discovery (T1046), TA0040-Detection (T1518 — tool discovery analog for fuzz-triggered ECU responses) |
| **Difficulty** | 4 - Hard |
| **Tags** | cantoolz, black-box, fuzz, mining, period-detection |

---

## D. IVI & OBD-II

### TC-AV-007: IVI Android Automotive Recon

| Field | Value |
|------|-----|
| **ID** | TC-AV-007 |
| **Title** | IVI Android Automotive Recon and CAN Pivot Mapping |
| **Objective** | Treat the in-vehicle infotainment (IVI) head unit as an Android device with a CAN connection. Enumerate installed apps, exposed intents, USB services, Bluetooth profiles, and the IVI-to-CAN gateway ECU's filtering rules. |
| **Steps** | 1. Identify the IVI Android Automotive OS version: Settings → About, or `adb shell getprop ro.build.version.release` (with explicit owner authorization and ADB enabled).<br>2. List installed packages: `adb shell pm list packages -f` — look for OEM-specific apps (e.g., `com.ford.sync`, `com.toyota.ivi`, `com.gm.cue`), media apps, third-party apps.<br>3. Decompile the OEM IVI apps with jadx: `jadx -d out/ com.example.ivi.apk` — extract hardcoded API endpoints, MQTT broker URLs, OTA update URLs.<br>4. Enumerate Bluetooth: `adb shell bluetoothctl devices` and `hcitool lescan` from a host — discover the IVI's BD_ADDR and BLE GATT services.<br>5. Map the CAN pivot: identify the gateway ECU between the IVI bus (typically a body/infotainment CAN) and the powertrain bus. The gateway's filtering rules are the critical control — a default-deny rule between IVI and powertrain is the standard R155 expectation.<br>6. Test the OTA update mechanism: extract the OTA URL from the IVI app, check signature validation (RSA / ECDSA over a CMS container), test downgrade prevention. |
| **Expected Result** | Complete IVI app inventory with API endpoints extracted; IVI Bluetooth/Wi-Fi/USB attack surface mapped; CAN pivot (IVI bus → gateway → powertrain) documented with the gateway's filtering rules. HIGH/CRITICAL findings: missing OTA signature validation, gateway with allow-all filtering, IVI app with hardcoded credentials, ADB enabled in production. |
| **Tools** | adb, jadx, mitmproxy, Frida, hcitool, bluetoothctl, can-utils (for gateway verification) |
| **MITRE** | TA0007-Discovery (T1082), TA0009-Collection (T1602), T1190-Exploit Public-Facing App (IVI OTA/cloud) |
| **Difficulty** | 4 - Hard |
| **Tags** | ivi, android-automotive, aaos, qnx, ota, can-pivot, gateway |

### TC-AV-008: OBD-II Standard PID Readout

| Field | Value |
|------|-----|
| **ID** | TC-AV-008 |
| **Title** | OBD-II (ISO 15031 / SAE J1979) Standard PID Readout |
| **Objective** | Read the mandated OBD-II PIDs (mode 0x01-0x0A) using raw CAN frames, validate the responses against physical observation (tachometer, GPS speed), and enumerate supported PIDs per mode. |
| **Steps** | 1. Functional broadcast mode 0x01 PID 0x00 (supported PIDs 0x01-0x20): `cansend can0 7DF#0201000000000000` — response on 0x7E8 returns a 4-byte bitmask of supported PIDs.<br>2. Engine RPM (PID 0x0C): `cansend can0 7DF#02010C0000000000` — response `(A*256+B)/4` in RPM.<br>3. Vehicle speed (PID 0x0D): `cansend can0 7DF#02010D0000000000` — single byte in km/h.<br>4. Coolant temp (PID 0x05): `cansend can0 7DF#0201050000000000` — byte in °C with -40 offset.<br>5. Throttle position (PID 0x11): `cansend can0 7DF#0201110000000000` — `(A*100)/255` in %.<br>6. VIN (mode 0x09 PID 0x02): multi-frame ISO-TP response — `cansend can0 7DF#0209020000000000` and reassemble the 17-character VIN from consecutive frames.<br>7. Mode 0x03 (stored DTCs) and mode 0x07 (pending DTCs): `cansend can0 7DF#02030000000000` — read any active diagnostic trouble codes. |
| **Expected Result** | Engine RPM matches the tachometer (±2%); vehicle speed matches GPS (±2 km/h); VIN matches the registration; DTCs match what a professional OBD-II scanner reports. Any mismatch indicates a non-standard OBD-II implementation (HIGH finding for emissions/regulatory compliance). |
| **Tools** | can-utils (cansend, candump), SocketCAN, optionally python-OBD for cross-validation |
| **MITRE** | TA0007-Discovery (T1082), TA0040-Detection (T1518) |
| **Difficulty** | 2 - Easy |
| **Tags** | obd-ii, iso-15031, sae-j1979, pid, mode-01, vin, dtc |

---

## E. RF / Key Fob / GNSS

### TC-AV-009: Rolling-Code Capture (HackRF / Flipper Zero)

| Field | Value |
|------|-----|
| **ID** | TC-AV-009 |
| **Title** | Key Fob Rolling-Code Capture (433/868 MHz, HackRF/Flipper) |
| **Objective** | Capture a 433 MHz (or 868 MHz EU) key fob rolling-code transmission using SDR, identify the modulation (OOK / ASK / FSK), the protocol family (fixed-code, KeeLoq, Microchip HCS200/300, rolling-code), and assess vulnerability to RollJam or RollBack capture. |
| **Steps** | 1. Confirm jurisdiction: 433.92 MHz is legal for capture (receive-only) under FCC Part 15 in the US; 868 MHz variants in EU; verify before transmitting.<br>2. Set up HackRF: `hackrf_info` confirms device, then `hackrf_transfer -r fob.cs8 -f 433920000 -s 2000000 -l 16 -g 40` to capture at 433.92 MHz, 2 MS/s, 16 dB IF / 40 dB RF gain.<br>3. Press the key fob button 5+ times in sequence; capture each press to a separate file.<br>4. Decode with `inspectrum` (waterfall) or `rtl_433 -r fob.cs8 -A` (auto-detect protocol). Common protocols: Microchip HCS301/KeeLoq (66-bit frame), fixed-code (24-bit Princeton, EV1527).<br>5. For rolling-code fobs: assess RollJam feasibility — capture two consecutive codes (one jammed, one captured), replay the jammed code later. Document time-window of code validity.<br>6. Alternative: Flipper Zero SubGHz → "Read RAW" → save .sub file; analyze with `subparse` or Universal Radio Hacker. |
| **Expected Result** | Modulation identified (typically OOK at 433.92 MHz); protocol family identified; for fixed-code fobs, document replay feasibility; for rolling-code, document RollJam/RollBack feasibility and time-to-capture. CRITICAL for fixed-code; HIGH for vulnerable rolling-code implementations. |
| **Tools** | HackRF One (or Flipper Zero, or RTL-SDR), inspectrum, rtl_433, Universal Radio Hacker, URH |
| **MITRE** | TA0006-Credential Access (T1552 — unsecured credentials analog for rolling-code capture), T1020 exfiltration analog |
| **Difficulty** | 4 - Hard |
| **Tags** | key-fob, rolling-code, keeloq, hackrf, flipper-zero, rolljam, rollback, 433-mhz, 868-mhz |

### TC-AV-010: GNSS Spoofing PoC (Lab / Shielded Only)

| Field | Value |
|------|-----|
| **ID** | TC-AV-010 |
| **Title** | GNSS (GPS L1 C/A) Spoofing Proof-of-Concept in Shielded Enclosure |
| **Objective** | Demonstrate position and time drift on a target GNSS receiver using a HackRF-based GPS L1 spoofer with GPS-SDR-SIM, in a Faraday cage or shielded enclosure only. NEVER transmit GNSS in unlicensed spectrum — this is illegal under FCC Part 97 (US), Ofcom (UK), and equivalent worldwide. |
| **Steps** | 1. Conduct ONLY in a Faraday cage or shielded test chamber with explicit STA (Special Temporary Authorization) where required.<br>2. Install GPS-SDR-SIM: `git clone https://github.com/osqzlar/GPS-SDR-SIM && cd GPS-SDR-SIM && gcc gpssim.c -lm -O3 -o gps-sdr-sim`.<br>3. Download current ephemeris (brdc), generate the forged signal for a chosen location/time: `./gps-sdr-sim -e brdc3540.23n -l 37.7749,-122.4194,100 -d 60` produces `gpssim.bin` (IF signal).<br>4. Transmit via HackRF: `hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 47` (1.57542 GHz L1, 2.6 MS/s, TX amp on, 47 dB VGA).<br>5. Place target receiver (u-blox EVK, phone, or test vehicle's navigation) in the cage; observe position jump to the spoofed coordinates.<br>6. For drift PoC: generate a slow-walking trajectory file (`-T` motion file) showing the receiver being moved along a path it is not physically traversing.<br>7. Document time-to-lock (~30-60 seconds cold start, ~5 seconds warm start) and the detection footprint (modern multi-band receivers with anti-spoofing may reject L1-only spoof). |
| **Expected Result** | Target receiver reports spoofed coordinates (e.g., 37.7749 N, 122.4194 W while physically in lab). Time drift detectable if the spoofed time differs from the receiver's internal clock. Receivers with multi-band (L1+L5) and anti-spoofing features (Galileo OS-NMA, BeiDou) resist simple L1-only spoof. |
| **Tools** | HackRF One, GPS-SDR-SIM, brdc ephemeris files, shielded enclosure, u-blox EVK or test receiver |
| **MITRE** | T1557-Adversary-in-the-Middle (T1557.002 — ARP cache poisoning analog for GNSS MiTM), TA0040-Detection evasion |
| **Difficulty** | 5 - Expert |
| **Tags** | gnss, gps-l1, spoofing, gps-sdr-sim, hackrf, faraday, adas, geofence |

---

## F. EV Charging & Detection

### TC-AV-011: ISO 15118 V2G Message Fuzzing

| Field | Value |
|------|-----|
| **ID** | TC-AV-011 |
| **Title** | ISO 15118 (Vehicle-to-Grid) Exi Message Capture and Fuzzing |
| **Objective** | Capture PLC (Power Line Communication) V2G traffic between a CCS-equipped vehicle and a DC fast charger (EVSE), decode the Exi (Efficient XML Interchange) messages, and fuzz the message decoder on either the vehicle or the charger. |
| **Steps** | 1. Confirm authorization: testing must be on a charger the operator owns; public charging networks (ChargePoint, IONITY, Electrify America) have explicit anti-tampering clauses.<br>2. PLC physical layer: HomePlug AV2 over the CCS pilot/PE pins. Capture with a PLC sniffer (Spirent C50, or a QCA7500-based PLC adapter in monitor mode) bridged between the vehicle port and the EVSE.<br>3. ISO 15118 transport: TCP port 15118 over the PLC link; capture with `tcpdump -i plc0 port 15118 -w v2g.pcap`.<br>4. Decode Exi: use `v2g-exi` (open-source decoder) or the official ISO 15118 schema — `exi2xml v2g-msg.exi v2g-msg.xml`.<br>5. Enumerate the V2G state machine: SessionSetup → ServiceDiscovery → PaymentServiceSelection → Authorization → ChargeParameterDiscovery → PowerDelivery → ChargingStatus → SessionStop.<br>6. For ISO 15118-20 (mandatory TLS + Plug & Charge): capture the TLS handshake, extract the contract certificate chain, attempt certificate chain validation bypass.<br>7. Fuzz the Exi decoder: use Scapy with `contrib.is15118` layer (or a custom Exi generator) to craft malformed messages — oversized integers, recursive references, schema violations. Target the EVSE first (less risk of bricking the vehicle). |
| **Expected Result** | Full V2G state machine capture; Exi message decode; Plug & Charge certificate chain documented. HIGH/CRITICAL findings: Exi parser crash (DoS), certificate chain validation bypass (billing fraud), Plug & Charge cert reuse across vehicles. |
| **Tools** | PLC sniffer (QCA7500-based or Spirent), tcpdump, v2g-exi decoder, Scapy (with ISO 15118 contrib layer), Vector CANoe.Mobility (commercial alternative) |
| **MITRE** | TA0007-Discovery (T1046), T1190-Exploit Public-Facing App (V2G interface), T1557-Adversary-in-the-Middle (PLC MiTM) |
| **Difficulty** | 5 - Expert |
| **Tags** | iso-15118, v2g, ev-charging, ccs, plc, exi, plug-and-charge, tls, billing-fraud |

### TC-AV-012: CAN-IDS Detection Tuning

| Field | Value |
|------|-----|
| **ID** | TC-AV-012 |
| **Title** | CAN-IDS (Intrusion Detection System) Baseline and Detection Tuning |
| **Objective** | From the defender's perspective: build a per-arbitration-ID whitelist baseline from a known-good vehicle CAN trace, define rate and value-range thresholds, and validate detection against common CAN attack patterns (injection, fuzz, replay). |
| **Steps** | 1. Collect a baseline: 30+ minutes of normal driving on a closed course, capturing every arbitration ID, its period (ms), and signal-value ranges.<br>2. Build the whitelist: a CSV of `(arbitration_id, expected_period_ms, period_jitter_ms, signal_min, signal_max)` per ID.<br>3. Deploy the IDS: open-source options include `cantools` + custom rules, `canusr` IDS scripts, or commercial (Karamba, GuardKnox, Argus/NXP). The IDS can be ECU-resident, gateway-resident, or TCU-resident.<br>4. Test detection against (a) new arbitration ID injection: `cansend can0 FFF#01020304` (an ID never seen in baseline); (b) message-rate anomaly: `cangen can0 -g 5 -n 1000 -I 0x123` (flooding a valid ID); (c) signal-value out-of-range: encode an RPM signal of 25000 (well above physical max).<br>5. Document detection latency (target <100 ms for safety-critical injections) and false-positive rate (target <1 alert per 100 km of normal driving).<br>6. Forward high-severity events to the OEM SOC via the TCU (MQTT/HTTPS) — the R155 requirement for incident detection and response. |
| **Expected Result** | A working CAN-IDS baseline with documented detection coverage for injection / fuzz / replay / out-of-range. Detection latency under 100 ms for safety-critical IDs; false-positive rate under 1/100 km. Identified gaps in coverage (e.g., replay attacks with valid ID/rate/values that evade pure behavioral IDS — SecOC is the only robust defense here). |
| **Tools** | can-utils (candump, cangen, cansend), cantools, custom Python IDS scripts, optional commercial CAN-IDS appliance |
| **MITRE** | TA0040-Detection (defender-side); validates against TA0001-Initial Access (CAN injection), T1071-Application Layer Protocol (CAN), T1499-Endpoint DoS (CAN flood) |
| **Difficulty** | 4 - Hard |
| **Tags** | can-ids, defense, baseline, whitelist, detection-tuning, r155, soc-forwarding |

---

## Severity Calibration

| Severity | Example TC-AV Findings |
|------|------|
| INFO | Lab bring-up, passive sniffing with no findings, standard OBD-II readout confirming normal behavior |
| LOW | DBC mismatches indicating model-year drift; minor rate anomalies with no physical effect |
| MEDIUM | UDS service exposure in default session; missing rate limits on non-safety-critical messages |
| HIGH | 0x27 SecurityAccess exposed in default session; weak seed length (1-2 bytes); Exi parser DoS; missing OTA signature validation |
| CRITICAL | Valid CAN injection producing a physical effect (brake/steer/light); key fob rolling-code replay that unlocks the vehicle; GNSS spoof affecting ADAS; billing-fraud cert bypass on ISO 15118 |

---

## References

- `skills/automotive-vehicle-security/SKILL.md` — full skill definition
- `skills/automotive-vehicle-security/payloads.md` — per-section command catalogues
- `skills/automotive-vehicle-security/guides/automotive-vehicle-security-playbook.md` — end-to-end red team playbook
- UNECE WP.29 R155/R156 regulations
- ISO/SAE 21434:2021, ISO 14229-1, ISO 11898-1:2015, ISO 15031-5, ISO 15118-2/-20
- Auto-ISAC best practices
