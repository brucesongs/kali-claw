---
name: uav-drone-security
description: UAV/drone security testing — PX4/ArduPilot autopilot attacks, MAVLink protocol fuzzing, RF link hijacking (2.4GHz control / 5.8GHz video), GPS spoofing/jamming, DroneSploit framework, DJI hardware reversing, and counter-UAS methodologies.
origin: github-trending-2026
version: 1.0.0
compatibility: Claude Code, Agent SDK
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
metadata:
  domain: aerial
  category: aerial
  tool_count: 13
  guide_count: 1
  mitre: TA0040-Detection, T1557-Adversary-in-the-Middle, TA0001-Initial Access
  keywords: [drone, uav, px4, ardupilot, mavlink, hackrf, dronesploit, djid, gps-spoofing, counter-uas, fpv, 5.8ghz]
---

# Skill: UAV & Drone Security

> **Supplementary Files**:
> - `payloads.md` — Complete payload collection organized by attack type (drone ecosystem map, RF spectrum recon 2.4 GHz/5.8 GHz, DJI DroneID decoding, MAVLink protocol/capture/fuzzing, PX4 & ArduPilot attack surface, GPS spoofing/jamming, control-link hijacking, video-link interception, DroneSploit framework, firmware extraction, flight log forensics, counter-UAS methodology, blue-team detection, quick reference cheat sheet — 18 major categories, 60+ code blocks with real `mavproxy.py`, `tshark`, `hackrf_transfer`, GPS-SDR-SIM, and DroneSploit CLI flags, plus incident references: RQ-170 Iran 2011, DJI tracking 2017, Apache Vegas 2020, CISA PX4 advisory).
> - `test-cases.md` — Structured test cases (RF spectrum survey, DJI DroneID decode, MAVProxy capture, MAVLink fuzzing, PX4 param dump, ArduPilot GCS enumeration, GPS spoofing lab with HackRF + GPS-SDR-SIM, 2.4 GHz FHSS capture, 5.8 GHz video interception, DroneSploit module run, DJI firmware extraction, flight log analysis for `.ulg`/`.bin`) — 12 cases across 6 categories.
> - `guides/uav-drone-security-playbook.md` — End-to-end drone pentest playbook: RF recon → DroneID decode → MAVLink capture → autopilot exploitation → countermeasure validation. Includes drone ecosystem architecture, PX4 SITL lab build, MAVLink 1 vs 2 deep dive, real-world incidents, and legal/ethical considerations (FAA Part 107, FCC Part 15, counter-UAS restrictions).

## Summary

UAV/drone security skill domain covering the full aerial vehicle attack surface: open-source autopilot stacks (PX4, ArduPilot), the MAVLink (Micro Air Vehicle Link) telemetry/control protocol, ground control station software (QGroundControl, MAVProxy), RF control links (2.4 GHz FHSS — FrSky, FlySky, CRSF/ELRS — plus DJI OcuSync and Walksnail digital links), 5.8 GHz analog/digital video links, GPS/GNSS dependency, and the DJI closed ecosystem. The domain covers both offensive testing of drone systems (authorized pentests, fleet security audits, vendor red team) and defensive counter-UAS (CUAS) operations: detection, classification, tracking, and (where legally authorized) interdiction. The threat surface includes mavlink hijacking on serial, UDP, and TCP links, GPS spoofing/meaconing, control-link replay/jamming, video-link interception, firmware extraction, and OTA-update attacks. Real-world incidents range from the 2011 Iran RQ-170 GPS spoof through the 2017 US Army DJI data-leakage ban, the 2020 Apache helicopter Vegas drone-swatter incident, and the 2023-2024 CISA advisories on PX4/Pixhawk autopilot flaws.

**Tools**: DroneSploit, PX4-Autopilot (SITL), ArduPilot (SITL), MAVProxy, QGroundControl, HackRF One, Universal Radio Hacker (URH), DroneID (DJI dissector), Crazyradio PA, inspectrum, GQRX, GPS-SDR-SIM, Wireshark (MAVLink dissector)

**Domain**: aerial

**MITRE ATT&CK**: TA0040-Detection (autopilot telemetry fingerprinting for blue team evasion), T1557-Adversary-in-the-Middle (MAVLink injection, GPS spoof, video-link relay), TA0001-Initial Access (RF control link, GPS dependency, firmware update channels), T1565-Data Manipulation (autopilot parameter tampering)

## Description

A drone is a flying embedded system. The flight controller (a Pixhawk-class STM32 board running PX4 or ArduPilot) reads IMU + barometer + magnetometer + GPS sensors 1 000+ times per second, runs a cascade of PID controllers per axis, mixes the result into motor PWM/DShot outputs, and accepts high-level setpoints from a ground control station (GCS) over MAVLink. Three RF links surround the aircraft: (1) a 2.4 GHz control link between RC transmitter and receiver for pilot sticks, typically FHSS with proprietary hopping sequences (FrSky D16, FlySky AFHDS, CRSF/ELRS); (2) a 5.8 GHz video link — analog NTSC/PAL over FM, or digital (DJI OcuSync/O3, Walksnail, HDZero, FatShark Sharkbyte) for First Person View (FPV); and (3) a telemetry/control uplink running MAVLink over 915 MHz (USA/AU), 433 MHz (EU), or 2.4 GHz. Most commercial drones also embed a GPS/GNSS receiver that is implicitly trusted by the autopilot for position hold, return-to-launch, and geofencing. Each link is a separate attack surface and most have been broken publicly: MAVLink has no authentication by default, 2.4 GHz FHSS sequences have been recovered with SDR, DJI DroneID leaks persistent identification, GPS C/A-code spoofing is well-documented, and firmware images have been unpacked from DJI products and modified. This skill covers the offensive side (how to test these layers ethically and legally) and the defensive side (counter-UAS detection, classification, and where authorized, interdiction).

**Core Attack Surfaces**:

- **MAVLink Protocol (v1/v2)**: Micro Air Vehicle Link — default-unauthenticated, plaintext, broadcast-friendly. Attackers on the same RF or network segment can sniff, replay, and inject commands: arm (`CMD_LONG`/`MAV_CMD_COMPONENT_ARM_DISARM`), takeoff, change mode, upload mission, dump parameters, or trigger `PREFLIGHT_REBOOT_SHUTDOWN`. MAVLink 2 added optional signing (RFC 4120-inspired) but most production deployments ship it disabled or unsigned.
- **Autopilot Stacks (PX4, ArduPilot)**: open-source flight-control firmware. Attack surface includes the parameter store (`param set`), mixer tables (`.mix` files), uORB message bus (PX4), MAVLink service handlers, file server (FTP over MAVLink), and OTA update channels. Misconfigured `COM_OBS_AVOID_TILT` / `COM_RC_OVERRIDE` / `COM_OF_LOSS` parameters can allow flight-mode takeover.
- **RF Control Link (2.4 GHz FHSS)**: FrSky, FlySky, ELRS/CRSF, DJI. Attack vectors include FHSS sequence recovery (requires capturing full 32-channel hops over multiple SDR captures), jamming, and replay of unencrypted frames. The Crazyradio PA (nRF24LU1+) is a popular hardware tool for nRF-based protocols.
- **Video Link (5.8 GHz)**: Analog NTSC FPV is trivially received (any 5.8 GHz receiver). Digital links (DJI OcuSync, Walksnail, HDZero) require protocol-specific decryption research; published attacks include SDR waterfall fingerprinting and pairing-record extraction.
- **GPS/GNSS Dependency**: drones trust GPS for RTL, geofencing, position hold. GPS-SDR-SIM + HackRF can spoof a stationary aircraft by feeding it an attacker-chosen trajectory. Meaconing (replay of recorded GPS samples) is lower-effort but less flexible.
- **DJI Closed Ecosystem**: largest commercial vendor. DroneID (a periodic RF broadcast at 900/2.4 GHz) leaks serial number, operator location, and aircraft position — used by DJI AeroScope for law-enforcement tracking and independently decodable with SDR + the open DroneID wireshark dissector. DJI firmware images (`*.bin` / `dji_system.bin`) have been unpacked, AUAV modules run busybox Linux, and the DJI Go mobile app has been MITM-ed.
- **Firmware Update Channels**: PX4 `.px4` files, ArduPilot `.apj` files, and DJI OTA updates are all attack targets. A compromised ground control station or a malicious OTA server can deliver trojanized firmware.
- **Counter-UAS (CUAS)**: defensive discipline covering passive RF detection (DroneID, RF fingerprinting), radar classification, acoustic signature matching, electro-optical tracking, and (where legally authorized) RF interdiction (jamming, protocol-aware takeover). This skill covers the detection/analysis half; active interdiction is heavily regulated.

**Related Skills**:
- `skills/sdr-rf-attack/SKILL.md` — General SDR fundamentals, HackRF usage, GNURadio, URH, ISM-band protocol reversing. This skill is the drone-specific application of those SDR skills.
- `skills/iot-pentest/SKILL.md` — General embedded/IoT pentest (firmware extraction, UART/JTAG, debug interfaces). Drone hardware builds on these techniques.
- `skills/hardware-security/SKILL.md` — Glitching, side-channel, JTAG/SWD exploitation of flight controllers (Pixhawk STM32 boards).
- `skills/wifi-pentest/SKILL.md` — Some drones expose WiFi management interfaces (DJI, Skydio); WiFi-specific attacks go through this skill.
- `skills/automotive-vehicle-security/SKILL.md` — Drone GNSS spoofing shares methodology with automotive GNSS spoofing; the underlying GPS-SDR-SIM + HackRF lab is the same.

---

## Use Cases

1. **MAVLink Protocol Fuzzing**: Authorized red team against a drone fleet's telemetry uplink — capture MAVLink 1/2 traffic over UDP 14550, build a scapy MAVLink layer, inject malformed heartbeat/command-long packets, and identify which autopilot versions crash or accept unauthorized commands. Used by PX4/ArduPilot vendors for hardening before release.
2. **RF Control Link Hijacking**: Assess a drone fleet's 2.4 GHz FHSS receiver (FrSky/FlySky/ELRS) by capturing full 32-channel hopping sequences with HackRF, identifying non-cryptographic sync words, and demonstrating replay/takeover in a Faraday cage.
3. **GPS Spoofing / Meaconing Lab**: Stand up an authorized GPS-SDR-SIM + HackRF range test in a Faraday cage, demonstrate that the autopilot accepts attacker-chosen coordinates, and report the firmware-level mitigations needed (multi-constellation, IMU cross-check, ADS-B cross-reference).
4. **Autopilot Exploitation**: Penetration test of a PX4/ArduPilot-based commercial drone — enumerate parameters, abuse MAVLink FTP, deliver a trojanized `.px4` firmware via a compromised ground station, and document the resulting persistent autopilot compromise.
5. **Drone Forensics**: Post-incident forensic analysis of a recovered drone — extract `.ulg` (PX4) or `.bin` (ArduPilot) flight logs, decode DAT files, reconstruct the flight path, and identify anomalous commands (mode changes, parameter writes) that indicate takeover.
6. **Counter-UAS Detection**: Build a passive detection capability for a facility — DroneID listener, RF fingerprint database, RTL-SDR-based spectrum watcher, ADS-B cross-correlation to reject manned aircraft, and a triage workflow for security operations.
7. **Firmware / Hardware Reversing**: Vendor security assessment of a DJI or Parrot drone — extract firmware from a physical UART/SWD port, unpack the AUAV Linux image, decompose the DJI encrypted firmware blobs, and report any hardcoded credentials, signing keys, or backdoor channels.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **DroneSploit** | Drone-focused pentest framework (Metasploit-style) — modules for drone discovery, default-password login, MAVLink replay | `dronesploit` → `use auxiliary/scanner/dji/aeroscope_listener` → `set INTERFACE wlan0` → `run` |
| **PX4-Autopilot (SITL)** | Open-source autopilot stack with SITL (Software-In-The-Loop) simulator — lab for MAVLink/params/uORB attacks | `make px4_sitl jmavsim` → autopilot boots on TCP 4560 with MAVLink |
| **ArduPilot (SITL)** | Open-source autopilot alternative — SITL build for MAVLink/GCS fuzzing | `sim_vehicle.py -v ArduCopter -f quad --map --console` |
| **MAVProxy** | Command-line ground control station and MAVLink router/inspector — Python, scriptable | `mavproxy.py --master=tcp:127.0.0.1:5760 --console --map` |
| **QGroundControl** | Cross-platform GUI ground control station (Windows/mac/Linux) — parameter upload, mission planner | `qgroundcontrol` → connect to `udp:14550` → Parameters tab |
| **HackRF One** | 1 MHz–6 GHz half-duplex SDR — wideband capture of 2.4 GHz control and 5.8 GHz video links, GPS spoofing TX | `hackrf_transfer -t gps_iq.bin -f 1575420000 -s 2600000 -x 10 -R` |
| **Universal Radio Hacker (URH)** | Interactive protocol reverse engineering — modulation auto-detect, frame alignment, replay | `urh` → File → Open `drone_capture.complex` → Auto-detect modulation → Assign labels |
| **DroneID** | Open-source DJI drone identification decoder (wireshark dissector + python lib) — serial, operator, aircraft position | `tshark -i wlan0 -f "ether proto 0x8898" -X lua_script:droneid.lua` |
| **Crazyradio PA** | nRF24LU1+ 2.4 GHz USB dongle for Crazyflie / nRF protocol replay — pair, replay, hijack | `crazyradio` → scan 80 channels → pair target → inject command |
| **inspectrum** | Offline captured signal visualization with spectrogram + symbol layers | `inspectrum drone_video.raw -r 20000000 -f 5740000000` |
| **GQRX** | Real-time spectrum + waterfall display (GNURadio-based) — drone signal discovery | `gqrx` → Device=HackRF → Freq=2440 MHz → Sample rate=8 MSPS → Record |
| **GPS-SDR-SIM** | Software GPS signal generator — produces I/Q samples for L1 C/A-code spoofing with HackRF | `gpssim -e brdc3540.24n -l 30.28650,120.03240,100 -b 8 -d 300` |
| **Wireshark (MAVLink dissector)** | MAVLink packet capture and dissection over UDP/TCP/serial | `wireshark -k -i any -f "udp port 14550" -d "udp.port==14550,mavlink"` |

---

## Methodology

### Phase 1: Reconnaissance — RF Spectrum Survey + DroneID

1. Set up SDR hardware (HackRF/RTL-SDR) and verify with `hackrf_info` / `rtl_test`.
2. Wideband scan of drone bands: 2.4 GHz ISM (`hackrf_sweep -f 2400:2500`), 5.8 GHz FPV (`hackrf_sweep -f 5725:5875`), 900 MHz telemetry (`hackrf_sweep -f 902:928`), 433 MHz telemetry (EU).
3. Identify active drone signals: FHSS bursts in 2.4 GHz, continuous analog FM in 5.8 GHz, periodic DroneID beacons.
4. Listen for DroneID with the open DroneID wireshark dissector to identify DJI aircraft (serial, operator location, aircraft position) without any cooperation from the operator.
5. Document spectrum survey heatmap and identified signals with frequency, modulation, bandwidth, and duty cycle.

### Phase 2: Link Capture

1. Lock onto the strongest drone signal and capture raw I/Q samples at ≥4x the signal bandwidth.
2. For FHSS control links, capture the full 2.4 GHz band at 20 MSPS for ≥30 s to recover hopping pattern.
3. For MAVLink over telemetry radio, capture UDP 14550 / 14551 with `tshark -f "udp port 14550"` or use MAVProxy in master mode.
4. For analog FPV video, demodulate FM at 5.8 GHz to NTSC and save frames.
5. Verify captures with `inspectrum` (RF) or Wireshark (MAVLink).

### Phase 3: Protocol Analysis

1. Demodulate captured RF in URH / inspectrum to extract symbol rate, modulation type (FSK/GFSK/OOK), preamble, sync word, payload structure.
2. For MAVLink, decode every packet with Wireshark's `mavlink` dissector (UDP 14550/14551, TCP 5760/5762) and correlate heartbeat/sysid/compid against known autopilots.
3. Cross-reference observed MAVLink messages with the official message set (`HEARTBEAT`, `COMMAND_LONG`, `MISSION_ITEM`, `PARAM_SET`, `SET_MODE`).
4. Identify authentication posture: MAVLink 1 (no auth), MAVLink 2 unsigned (most common), MAVLink 2 signed (rare — check for `MAVLINK_IFLAG_SIGNED`).
5. Build a target model: autopilot vendor, version, link technology, GPS dependency, geofencing posture.

### Phase 4: Autopilot Exploitation

1. If MAVLink is reachable: enumerate parameters (`PARAM_REQUEST_LIST`), check for dangerous ones (`COM_RC_OVERRIDE`, `NAV_RCL_ACT`), attempt `SET_MODE` to AUTO/RTL/GUIDED, attempt `COMMAND_LONG(MAV_CMD_COMPONENT_ARM_DISARM)`.
2. If MAVLink FTP is enabled (`MAVFTP`): attempt directory listing, fetch `/fs/microsd/etc/extras.txt`, drop a payload that runs on boot.
3. If firmware is in scope: extract via UART/SWD on the Pixhawk (STM32F427/F767), unpack `.px4`/`.apj`/`dji_system.bin`, look for hardcoded keys, debug backdoors, and OTA update channels.
4. If GPS is in scope: stand up GPS-SDR-SIM + HackRF in a Faraday cage, demonstrate that the autopilot accepts the spoofed trajectory, and report the firmware mitigations required.
5. If RF control link is in scope: replay captured FHSS frames, jam a single channel to force failsafe, or demonstrate a takeover of a non-cryptographic protocol.

### Phase 5: Countermeasure Validation

1. Document every finding with reproduction steps, captured artifacts, and severity per the engagement rubric.
2. For defenders: build a DroneID listener + RF fingerprint database; tune a spectrum anomaly detector; tune a MAVLink anomaly detector (non-whitelisted sysid/compid, unexpected `SET_MODE`, unsigned MAVLink 2).
3. For firmware: implement MAVLink 2 signing on all production links; enable multi-constellation GPS cross-check (GPS+Galileo+BeiDou); add IMU-vs-GPS divergence detection.
4. Validate mitigations by re-running the engagement test cases and confirming they fail (attack blocked) or trigger alerts (detection works).
5. Produce a written report with legal framing (FAA Part 107 compliance, FCC Part 15 transmission limits, counter-UAS restrictions).

---

## Practical Steps

### Step 1: Stand up a PX4 SITL Lab (no hardware required)

```bash
# Clone PX4-Autopilot and build SITL with jMAVSim simulator
git clone https://github.com/PX4/PX4-Autopilot.git --recursive
cd PX4-Autopilot
make px4_sitl jmavsim

# In another terminal, attach MAVProxy to the SITL autopilot
pip3 install pymavlink mavproxy
mavproxy.py --master=tcp:127.0.0.1:4560 --console --map

# Inside MAVProxy console, dump parameters and check for dangerous ones
param show COM_*
param show NAV_*
param show MAV_*
mode
status
```

### Step 2: Capture MAVLink over UDP 14550 with tshark

```bash
# Identify the MAVLink version and endpoints
tshark -i any -f "udp port 14550" -Y "mavlink" -T fields \
  -e mavlink.msgid -e mavlink.sysid -e mavlink.compid \
  -e mavlink.heartbeat.type -e mavlink.heartbeat.autopilot 2>&1 | head -50

# Save the full capture for offline analysis
tshark -i any -f "udp port 14550 or udp port 14551 or tcp port 5760" \
  -w mavlink_capture.pcap

# Decode the pcap later with the MAVLink dissector
tshark -r mavlink_capture.pcap -Y "mavlink.msgid == 76" \
  -T fields -e mavlink.command_long.command -e mavlink.command_long.param1
```

### Step 3: Decode DJI DroneID over the air

```bash
# Install the DroneID dissector (trendmicro/DroneID-timeline or loosebianky/DroneID)
git clone https://github.com/trendmicro/DroneID-timeline.git
cd DroneID-timeline

# Capture DroneID on 2.4 GHz with HackRF for 10 seconds
hackrf_transfer -r droneid_2400.raw -f 2440000000 -s 20000000 -l 32 -g 30 -n 200000000

# Demodulate with GNURadio and feed DroneID decoder
# (see DroneID wireshark dissector for the gr-demod flowgraph)
gnuradio-companion droneid_demod.grc

# Inspect with wireshark
wireshark -k -r droneid_decoded.pcap -X lua_script:droneid.lua

# Extract serial, operator, aircraft position from the dissector output
tshark -r droneid_decoded.pcap -Y "droneid" -V | \
  grep -E "Serial|Operator|Drone (Lat|Lon)|Home (Lat|Lon)"
```

### Step 4: GPS Spoofing Lab with GPS-SDR-SIM + HackRF (Faraday cage only)

```bash
# Download a recent GPS ephemeris (BRDC file from NASA CDDIS)
wget https://cddis.nasa.gov/archive/gnss/data/daily/2024/brdc/BRDC00IGS_R_20241550000_01D_MN.rnx.gz
gunzip BRDC00IGS_R_20241550000_01D_MN.rnx.gz

# Clone and build GPS-SDR-SIM
git clone https://github.com/osqzssp/GPS-SDR-SIM.git
cd GPS-SDR-SIM && make

# Generate a static spoof trajectory at a chosen location, 100 m altitude
gpssim -e brdc3550.24n -l 30.28650,120.03240,100 -b 8 -d 300 -o spoof_static.bin

# Transmit via HackRF INSIDE A FARADAY CAGE ONLY — never on open spectrum
hackrf_transfer -t spoof_static.bin -f 1575420000 -s 2600000 -a 1 -x 10 -R

# Verify spoof success on a reference receiver (u-blox NEO-M8N)
# Position should read the chosen lat/lon when lock is acquired.
```

### Step 5: DroneSploit Framework Workflow

```bash
# Install DroneSploit (dstemmerk or DatabaseCoordinate variants)
git clone https://github.com/dronesploit/dronesploit.git
cd dronesploit && pip3 install -r requirements.txt
python3 dronesploit.py

# Inside dronesploit prompt
msf > use auxiliary/scanner/dji/aeroscope_listener
msf auxiliary(aeroscope_listener) > set INTERFACE wlan0mon
msf auxiliary(aeroscope_listener) > run

# When a DJI drone is detected, pivot to MAVLink enumeration
msf > use auxiliary/scanner/mavlink/heartbeat_scanner
msf auxiliary(heartbeat_scanner) > set RHOSTS 192.168.1.0/24
msf auxiliary(heartbeat_scanner) > set RPORT 14550
msf auxiliary(heartbeat_scanner) > run
```

---

## Defense Perspective

### Counter-UAS Detection Stack

- **Passive RF**: continuous monitoring of 2.4 GHz / 5.8 GHz / 900 MHz / 433 MHz bands; detect FHSS bursts, DroneID beacons, and known drone RF fingerprints (DJI, Parrot, Skydio, Autel, Yuneec).
- **DroneID sensors**: deploy DJI AeroScope or open DroneID listeners at facility perimeter to identify DJI aircraft by serial number and operator location.
- **Radar**: short-range (1–5 km) Ku/Ka band radar for non-cooperative drones; cross-correlate with ADS-B to filter manned aircraft.
- **Acoustic**: spectrogram of rotor RPM harmonics for low-altitude detection (≤300 m) where RF/visual methods are degraded.
- **Electro-optical / IR**: thermal imaging for night and obscured-weather tracking.

### Hardening Recommendations

- Enable MAVLink 2 signing on all production telemetry/control links (`MAVLink` 2.0 section-signing with a shared secret rotated every 90 days).
- Default-deny MAVLink commands: build an allowlist of sysid/compid/msgid tuples per vehicle and reject everything else.
- Disable MAVLink FTP on production aircraft; allow only signed firmware updates verified against the vendor's attestation key.
- Cross-check GPS against IMU velocity (Kalman filter divergence detection) and against ADS-B ground speed; alarm on divergence > threshold.
- Use ELRS or CRSF (cryptographically authenticated FHSS) for 2.4 GHz control links; never rely on FrSky D8 or fixed-code protocols.
- Encrypt video links where supported (DJI O3 with PIN pairing, custom FPV with AES).
- Geofence every mission with a no-fly-zone database (FAA LAANC, DJI GEO); fail safe to RTL if geofence is violated.

### Compliance Considerations

- **FAA Part 107**: commercial drone operations in the USA require a Remote Pilot Certificate; testing in controlled airspace requires LAANC authorization.
- **FCC Part 15**: intentional RF transmission (GPS spoofing, jamming, RF replay) outside ISM bands or above EIRP limits is illegal in the USA without experimental authorization.
- **Counter-UAS law**: in the USA, 18 U.S.C. § 32 makes it a felony to interfere with any aircraft, including drones; only DHS, DOJ, and DoD have explicit authority for active interdiction. State-level CUAS statutes vary widely.
- **MAVLink interception**: sniffing unencrypted MAVLink on shared networks is generally legal; injecting commands into an aircraft you do not own is a felony in most jurisdictions.
- **DroneID/ADS-B reception**: passive reception of broadcast RF is generally legal in the USA and EU; re-transmitting the data may be restricted.

### Countermeasures by Attack Type

| Attack Vector | Countermeasure | Implementation Difficulty |
|---------------|----------------|--------------------------|
| MAVLink Injection | MAVLink 2 signing, default-deny msgid allowlist | Medium |
| MAVLink FTP Abuse | Disable FTP service; allow only signed firmware | Low |
| GPS Spoofing | Multi-constellation cross-check, IMU divergence detection, ADS-B cross-reference | High |
| GPS Jamming | Inertial dead-reckoning fallback, jamming detector with RTL on jamming alarm | Medium |
| 2.4 GHz FHSS Replay | Cryptographically authenticated FHSS (ELRS/CRSF) with session keys | Medium |
| 2.4 GHz FHSS Jamming | Spread-spectrum, frequency agility, failsafe RTL | Medium |
| 5.8 GHz Video Intercept | Encrypt video link (DJI O3 pairing, AES); switch to digital with pairing record | High |
| Firmware Update Hijack | Signed updates, attestation keys, secure boot on Pixhawk | High |
| DroneID Privacy | Operate in test/research mode where legal; know that DroneID is always on | N/A |
| CUAS Takeover (legal) | Federal authority only (DHS/DOJ/DoD); commercial CUAS systems are passive-only in the USA | N/A |

## Differentiation

This skill is **drone-specific** — it does not duplicate general SDR/IoT content.

- **vs `sdr-rf-attack`**: `sdr-rf-attack` covers general RF attack methodology (HackRF fundamentals, ISM-band reversing, cellular, RFID, keyfobs). This skill applies that SDR foundation to drones specifically: drone RF bands (2.4 GHz control, 5.8 GHz video, 900/433 MHz telemetry), drone protocols (MAVLink, DroneID, FHSS sequences), and drone hardware (Pixhawk, DJI, Crazyflie). Where `sdr-rf-attack` is "any RF signal," this is "RF signals that make a drone fly."
- **vs `iot-pentest`**: `iot-pentest` covers general embedded/IoT attack (firmware extraction, UART/JTAG, BLE, Zigbee). This skill uses those techniques on drones: Pixhawk STM32 SWD, DJI firmware unpacking, AUAV Linux shell access, OTA update abuse. The drone-specific layer (autopilot firmware, MAVLink, flight control PIDs, mission planning) is not in scope for `iot-pentest`.
- **vs `automotive-vehicle-security`**: shares GNSS spoofing methodology (GPS-SDR-SIM, HackRF) but applied to aerial vehicles, not ground vehicles. Drone-specific: MAVLink (not CAN), autopilot params (not UDS), control link (not key fob), DroneID (not OBD-II).
- **vs `wifi-pentest`**: this skill focuses on the dedicated drone RF links (2.4 GHz FHSS, 5.8 GHz video, 900 MHz telemetry); WiFi-based drone management interfaces (DJI Osmo Pocket WiFi, Skydio WiFi setup) defer to `wifi-pentest`.

## Legal and Ethical Framing

Drone attacks can have catastrophic consequences — a hijacked drone is a falling 1–10 kg object at 10–120 m altitude. Every test case in this skill assumes:

1. **Faraday cage or shielded range** for any active RF transmission (GPS spoof, RF replay, jamming).
2. **Written authorization** from the drone owner, the autopilot vendor (for vendor pentests), and the property owner of the test range.
3. **FAA Part 107 compliance** in the USA (Remote Pilot Certificate, LAANC authorization, daylight-only VLOS for most tests).
4. **FCC Part 15 compliance** for RF transmissions — ISM band only, EIRP limits, no interference to licensed services.
5. **No active interdiction** of any aircraft you do not own and have not been explicitly authorized to test — this is a felony under 18 U.S.C. § 32 in the USA and equivalent statutes in other jurisdictions.
6. **Ethical disclosure** for any vendor vulnerabilities found — follow the vendor's coordinated disclosure policy (DJI, PX4, ArduPilot all have public security disclosure processes).
