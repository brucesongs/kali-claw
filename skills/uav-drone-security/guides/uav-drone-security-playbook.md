# UAV / Drone Security Playbook

> End-to-end operational guide for authorized UAV/drone security assessments.
> Covers drone ecosystem architecture, lab build, MAVLink deep dive, RF attack methodology, GPS-dependent attacks, real-world incidents, and legal/ethical considerations.
> All active RF commands require a Faraday cage, shielded range, or FCC experimental authorization. 18 U.S.C. § 32 makes interfering with any aircraft — including drones you do not own — a federal felony in the USA.

---

## Introduction

This playbook is the operational reference for drone penetration testing and counter-UAS (CUAS) defensive operations. It is built around three principles: (1) drones are flying embedded systems with a deterministic attack surface (autopilot + MAVLink + GPS + control link + video link), (2) every active RF test requires a shielded range and explicit written authorization, and (3) the same techniques that find vulnerabilities for offensive testing enable detection and mitigation on the defensive side. The playbook covers both the open-source ecosystem (PX4, ArduPilot, MAVLink, MAVProxy) and the closed DJI ecosystem (DroneID, AeroScope, firmware), and it includes the legal/ethical framing that aerial-vehicle testing demands: FAA Part 107 compliance, FCC Part 15 transmission limits, counter-UAS legal restrictions, and the imperative to never interfere with an aircraft you do not own.

---

## Drone Ecosystem Architecture

### Open-Source Autopilots: PX4 and ArduPilot

The drone autopilot ecosystem is dominated by two open-source stacks, both of which run on Pixhawk-class hardware (STM32F427 / STM32F767 microcontrollers with IMU, barometer, magnetometer, and GPS peripherals):

**PX4-Autopilot** (BSD-3 license, hosted at github.com/PX4/PX4-Autopilot):
- Originated at ETH Zurich (2014); maintained by DroneCode Foundation.
- Architecture: modular — each functional domain (attitude control, position control, navigator, commander, sensors) is a separate task.
- Internal messaging: uORB (micro Object Request Broker) — pub/sub between tasks.
- Mission planning: QGroundControl (.plan files), MAVSDK, dronekit.
- Used by: DJI Matrice (some variants), Snap V2, many commercial drones, most research drones.

**ArduPilot** (GPLv3, hosted at github.com/ArduPilot/ardupilot):
- Originated from DIY Drones (2007); one of the oldest open-source autopilots.
- Architecture: monolithic firmware with vehicle-specific build flags (ArduPlane, ArduCopter, ArduRover, ArduSub, ArduBlimp).
- Internal messaging: GCS protocol over MAVLink; no uORB equivalent.
- Mission planning: Mission Planner (Windows), MAVProxy, APM Planner.
- Used by: 3DR (historical), many commercial drones, hobbyist community.

Both stacks speak MAVLink (see MAVLink Deep Dive below) and run on the same hardware. The choice of stack is often a religious war in the drone community; from a security perspective, both have similar attack surfaces (MAVLink, params, firmware update, GPS dependency).

### Autopilot Hardware: Pixhawk-class

The de facto standard autopilot hardware (Pixhawk) is an STM32 microcontroller board with the following peripherals:

- **IMU**: typically ICM-20689 or BMI088 (3-axis accelerometer + gyroscope), 1 kHz+ sample rate.
- **Barometer**: MS5611 or BMP388 for altitude.
- **Magnetometer**: IST8310 or HMC5983 for heading.
- **GPS**: u-blox NEO-M8N or M9N (L1 C/A), optionally multi-band (M9N supports GPS+Galileo+GLONASS).
- **RC input**: PWM, PPM, or SBUS from a 2.4 GHz receiver (FrSky, FlySky, ELRS).
- **Telemetry**: serial port to a 900 MHz / 433 MHz radio module (3DR Radio, RFD900, Holybro).
- **ESC output**: PWM, OneShot, Multishot, or DShot to electronic speed controllers (ESCs).
- **Companion computer**: optional UART/CAN link to a Raspberry Pi, Jetson, or similar (for vision-based navigation, obstacle avoidance).

Common Pixhawk variants: Pixhawk 4 (STM32F767), Pixhawk 6C (STM32H753), CubePilot Cube Orange (STM32H757). All expose a USB port for firmware upload and console (NSH shell).

### Ground Control Station (GCS) Software

The GCS is the operator's interface to the drone:

- **QGroundControl** (cross-platform, GPLv3): the standard for PX4. Provides mission planning, parameter tuning, flight mode switching, and live telemetry display.
- **MAVProxy** (Python, command-line): the standard for ArduPilot. Scriptable, headless, suitable for automated testing.
- **Mission Planner** (Windows, proprietary-ish): ArduPilot's traditional GCS.
- **DJI Go / DJI Fly** (mobile app): closed-source, vendor-specific.

The GCS communicates with the autopilot over MAVLink on one of:
- **USB serial** (Pixhawk directly connected to laptop)
- **TCP 5760/5762** (SITL simulator)
- **UDP 14550/14551** (telemetry radio or companion computer)
- **UDP 14540** (offboard/companion computer)

### RF Link Layers

A drone has up to four simultaneous RF links:

**Control link (2.4 GHz)**:
- Transmitter: FrSky Taranis/X-Lite, FlySky FS-i6, ELRS, DJI RC.
- Receiver on the drone: FrSky X4R-SB, FlySky FS-iA6B, ELRS receiver, DJI Air Unit.
- Modulation: FHSS across 2.4 GHz ISM (80 channels, 1 MHz spacing).
- Hop rate: ~50 Hz (FrSky D16), ~150 Hz (ELRS).
- Authentication: FrSky D8 (none), FrSky D16 (4-byte rolling code), ELRS (CRSF cryptographic binding).

**Video link (5.8 GHz)**:
- Analog: NTSC or PAL video over FM; channels 5.725-5.875 GHz at 20 MHz spacing.
- Digital (DJI OcuSync / O3, Walksnail, HDZero, FatShark): OFDM, FHSS, typically encrypted via pairing record.

**Telemetry link (900 MHz / 433 MHz / 2.4 GHz)**:
- MAVLink over serial → 3DR Radio / RFD900 / Holybro.
- Modulation: FSK / GFSK, 57.6 kbps typical.
- Range: 1-40 km depending on power and antenna.

**Cellular uplink (4G/LTE, optional)**:
- Some commercial drones (DJI Mavic 3 Enterprise, Skydio X2/X10) include a cellular modem for beyond-VLOS operations.
- Exposes the drone to internet-based attacks if not properly firewalled.

### GPS/GNSS Dependency

Every drone's flight controller trusts GPS for:
- Position hold (LOITER mode)
- Return-to-launch (RTL)
- Mission waypoints (AUTO mode)
- Geofencing (no-fly zones, max altitude)
- Ground speed measurement (for fixed-wing)

GPS is a passive receiver (no authentication on civil signals), which means it can be spoofed by anyone with a HackRF and GPS-SDR-SIM (see GPS-Dependent Attacks below). This is the single most impactful attack vector in the drone space — a successful GPS spoof can move a drone to an attacker-chosen location without any cooperation from the autopilot.

---

## Building a Drone Pentest Lab

### Option 1: PX4 SITL (Software-In-The-Loop)

The simplest lab is PX4 SITL, which runs the actual PX4 firmware as a Linux process with simulated sensors:

```bash
# Clone PX4 and build the SITL target with jMAVSim simulator
git clone https://github.com/PX4/PX4-Autopilot.git --recursive
cd PX4-Autopilot
make px4_sitl jmavsim
```

This boots the autopilot on TCP 4560 with a MAVLink interface. Attach MAVProxy to it:

```bash
pip3 install pymavlink mavproxy
mavproxy.py --master=tcp:127.0.0.1:4560 --console --map
```

SITL supports multiple simulators:
- `jmavsim` — Java-based, lightweight, good for MAVLink testing.
- `gazebo` — Gazebo Classic or Ignition; full physics, vision, obstacle avoidance.
- `airsim` — Microsoft AirSim (now Project AirSim); photorealistic, good for vision work.

SITL endpoints (all on localhost):
- TCP 4560 — primary link
- UDP 14540 — offboard (companion computer)
- UDP 14550 — GCS link (QGroundControl connects here)
- UDP 14560 — SDK link (dronekit, MAVSDK)

### Option 2: ArduPilot SITL

ArduPilot SITL is the alternative for ArduPilot-focused testing:

```bash
git clone https://github.com/ArduPilot/ardupilot.git --recursive
cd ardupilot
Tools/autotest/sim_vehicle.py -v ArduCopter -f quad --map --console
```

This boots ArduCopter SITL on TCP 5760 (and 5762 for the second link).

Vehicle variants: `-v ArduPlane` (fixed-wing), `-v ArduCopter` (multirotor), `-v ArduRover` (ground vehicle), `-v ArduSub` (submarine).

Frame variants: `-f quad` (quadcopter), `-f hexa` (hexacopter), `-f octa` (octocopter), `-f quad-plane` (VTOL fixed-wing), `-f skeleton` (custom frame).

### Option 3: Crazyflie Hardware-In-Loop

For hardware testing without the cost of a full-size drone, the Bitcraze Crazyflie 2.1 is a 27 g open-source nano drone:

```bash
git clone https://github.com/bitcraze/crazyflie-firmware.git
cd crazyflie-firmware
make
# Flash via Crazyradio PA dongle (USB)
```

The Crazyradio PA is an nRF24LU1+ USB dongle that exposes raw nRF24 operations, which makes it useful for security research beyond just Crazyflie (any nRF24-based device is a target).

Crazyflie advantages:
- Tiny and safe to fly indoors (no FAA Part 107 needed for indoor flight in most jurisdictions).
- Open-source firmware and protocol (CRTP — Crazy RealTime Protocol).
- Compatible with the Crazyswarm multi-drone swarm framework.

### Option 4: Full Hardware Lab

For full-scale hardware testing, the lab needs:

**Flight controller**: Pixhawk 4 / Cube Orange / Matek F405 (running PX4 or ArduPilot).
**RC transmitter**: FrSky Taranis X-Lite or X9D (with X4R-SB receiver); ELRS module; Crazyradio PA for nRF testing.
**Telemetry radio**: RFD900+ (900 MHz, USA/AU) or Holybro Telemetry Radio (433 MHz, EU).
**GPS receiver**: u-blox NEO-M8N (single-band L1) or M9N (multi-band L1/L5) for the drone; another NEO-M8N as a reference receiver for spoofing-detection lab work.
**ESC + motors**: any 30A ESC with DShot support and matching brushless motors.
**Airframe**: a 250 mm racing quad frame is small enough for indoor lab work; a 450 mm F450 frame is the standard test bed.
**FPV system**: analog (any 5.8 GHz FPV camera + receiver) or digital (DJI O3 Air Unit, Walksnail VRX).

### Option 5: RF Lab for HackRF-based Attacks

For RF attack testing, the lab adds:

- **HackRF One** — 1 MHz-6 GHz half-duplex SDR for capture and transmission.
- **RTL-SDR v3** — 24-1766 MHz RX-only SDR for monitoring.
- **Faraday cage** — required for any active RF transmission (GPS spoof, jam, replay). Even a small one (e.g. a steel trash can with a conductive lid) provides >40 dB shielding at 1.5 GHz.
- **Reference GPS receiver** — u-blox NEO-M8N connected via USB to a monitoring host.
- **Antennas**: 2.4 GHz monopole, 5.8 GHz patch, 900 MHz Yagi, 1.5 GHz GPS patch (with LNA).

### Lab Bring-Up Checklist

```
[ ] PX4 SITL boots and accepts MAVLink commands
[ ] ArduPilot SITL boots and accepts MAVLink commands
[ ] mavproxy.py attaches to both SITLs and shows heartbeat
[ ] tshark captures MAVLink on UDP 14550
[ ] HackRF detected by hackrf_info
[ ] RTL-SDR detected by rtl_test
[ ] Crazyradio PA detected by lsusb (1915:7777)
[ ] u-blox NEO-M8N detected by ls /dev/ttyACM*
[ ] Faraday cage shielding verified (>40 dB at 1.5 GHz, 2.4 GHz, 5.8 GHz)
[ ] Wireshark MAVLink dissector works on captured pcap
[ ] DroneID lua dissector installed and tested
```

---

## MAVLink Deep Dive

### Protocol History and Versions

MAVLink (Micro Air Vehicle Link) was created by Lorenz Meier at ETH Zurich in 2009. It has gone through three major versions:

- **MAVLink 0.9** (2009): the original, no length field, deprecated.
- **MAVLink 1.0** (2013): stable wire protocol, stx byte = 0xFE, fixed header structure, no authentication. Still the most common version on legacy hardware.
- **MAVLink 2.0** (2017): stx byte = 0xFD, extended message ID (24-bit), optional message signing, incompat/compat flag bytes, optional 13-byte signature trailer. Required for JARUS-specific SORA conformance and any commercial deployment.

### Packet Structure

**MAVLink 1 packet (8 bytes header + payload + 2 bytes CRC)**:

```
+----+----+----+----+----+----+----------------+----+----+
|Stx |Len |Seq |Sys |Comp|Msg |Payload (0-255B) |Crc |Crc |
|0xFE|    |    |ID  |ID  |ID  |                |Lo |Hi |
+----+----+----+----+----+----+----------------+----+----+
 1B   1B  1B   1B  1B  1B   variable          2 bytes
```

**MAVLink 2 packet (11 bytes header + payload + optional 13-byte signature + 2 bytes CRC)**:

```
+----+----+----+----+----+----+----+----+----+----+----+----------------+----+----+
|Stx |Len |ICF |CCF |Seq |Sys |Comp|Msg |Msg |Msg |Payload (0-255B) |[Sig] |Crc |Crc |
|0xFD|    |    |    |    |ID  |ID  |Lo |Mid|Hi |                |opt 13B|Lo |Hi |
+----+----+----+----+----+----+----+----+----+----+----------------+----+----+----+
 1B   1B  1B   1B  1B   1B  1B   1B  1B  1B   variable             2 bytes
```

Where:
- `Stx` — start byte (0xFE for v1, 0xFD for v2).
- `Len` — payload length (0-255 bytes).
- `ICF` — incompatibility flags; bit 0 = packet is signed (signature follows payload).
- `CCF` — compatibility flags; bit 0 = packet uses MAVLink 2 frame layout (always set in v2).
- `Seq` — sequence number (wraps 0-255).
- `SysID` — sending system's ID (1-255; 1 = aircraft, 255 = GCS).
- `CompID` — sending component's ID (1 = autopilot, 50 = gimbal, etc.).
- `MsgID` — message type (v1: 8-bit; v2: 24-bit, supports extension messages).
- `Payload` — message-specific payload.
- `Signature` — (optional, MAVLink 2 only) 13 bytes: link ID (1) + timestamp (6) + signature (6).
- `CRC` — CRC-16/MCRF4XX with CRC_EXTRA byte appended (each message has a unique CRC_EXTRA computed from its field set).

### Common Messages

The MAVLink message set is documented at mavlink.io/messages. The most security-relevant messages:

| msgid | Message | Use | Danger Level |
|-------|---------|-----|--------------|
| 0 | HEARTBEAT | Periodic identification (type, autopilot, mode) | LOW |
| 1 | SYS_STATUS | System status (battery, errors) | LOW |
| 2 | SYSTEM_TIME | Autopilot clock | LOW |
| 11 | SET_MODE | Change flight mode | HIGH |
| 21 | PARAM_REQUEST_READ | Request one param | LOW |
| 22 | PARAM_REQUEST_LIST | Dump all params | LOW |
| 23 | PARAM_VALUE | Param response | LOW |
| 23 | PARAM_SET | Write a param | HIGH |
| 39 | MISSION_ITEM | Mission waypoint | HIGH |
| 44 | MISSION_COUNT | Mission item count | MEDIUM |
| 76 | COMMAND_LONG | Generic command (arm, takeoff, RTL, etc.) | CRITICAL |
| 147 | AUTOPILOT_VERSION | Firmware version | LOW |
| 264 | FILE_TRANSFER_PROTOCOL | MAVFTP | CRITICAL |
| 300 | PROTOCOL_VERSION | MAVLink version | LOW |

### Dangerous Commands (COMMAND_LONG)

COMMAND_LONG (msgid 76) is the catch-all command message. The `command` field selects the operation; `param1`-`param7` are command-specific parameters. The most dangerous commands:

| Command ID | Name | Params | Effect |
|-----------|------|--------|--------|
| 400 | MAV_CMD_COMPONENT_ARM_DISARM | param1=1 to ARM | Arms motors |
| 22 | MAV_CMD_NAV_TAKEOFF | param7=altitude | Takes off |
| 20 | MAV_CMD_NAV_RETURN_TO_LAUNCH | (none) | RTL |
| 16 | MAV_CMD_NAV_LAND | (none) | Lands |
| 21 | MAV_CMD_NAV_LOITER_UNLIM | (none) | Loiters |
| 211 | MAV_CMD_NAV_LAND_LOCAL | (none) | Local landing |
| 176 | MAV_CMD_DO_SET_MODE | param1=mode | Change mode |
| 246 | MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN | param1=1 SHUTDOWN, 0 REBOOT | Reboots/shuts down |

### MAVLink Security Flaws

The fundamental MAVLink security flaw is that **MAVLink 1 and unsigned MAVLink 2 have no authentication**. Any party that can inject MAVLink packets into the autopilot's input stream (UDP port, serial line, TCP socket) can issue any command — including ARM, TAKEOFF, SET_MODE AUTO, or reboot.

This was highlighted by multiple DEF CON and BlackHat talks (Andreas Huggel, 2017; Loet Riphagen, 2018). The PX4 and ArduPilot teams added optional signing in MAVLink 2 (2017) but it ships disabled by default on most production hardware because of the key-distribution problem: every GCS, companion computer, and telemetry radio needs the shared secret, and rotating it requires touching every device.

Even with signing enabled, the protocol has weaknesses:
- The signature timestamp is in microseconds, so a captured signed packet can be replayed within ~10 seconds (the timestamp window).
- The signature is HMAC-SHA256-48 (truncated to 6 bytes) — strong, but the link ID is only 1 byte.
- There is no key revocation mechanism.

### Practical MAVLink Attacks

For authorized testing, the most impactful MAVLink attacks are:

**1. Unauthorized ARM** (CRITICAL):
```python
from pymavlink import mavutil
m = mavutil.mavlink_connection('udp:127.0.0.1:14550')
m.wait_heartbeat()
m.mav.command_long_send(
    m.target_system, m.target_component,
    mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
    0, 1, 0, 0, 0, 0, 0, 0)  # param1=1 = ARM
```

**2. Force mode change to LAND** (CRITICAL):
```python
m.mav.set_mode_send(
    m.target_system,
    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
    9)  # ArduCopter LAND
```

**3. Param write (disable arming check)** (HIGH):
```python
m.mav.param_set_send(
    m.target_system, m.target_component,
    b'ARMING_CHECK',  # param_id (16 bytes)
    0,                # value = disable
    mavutil.mavlink.MAV_PARAM_TYPE_UINT8)
```

**4. MAVFTP directory listing** (MEDIUM):
```python
m.mav.file_transfer_protocol_send(
    target_network=0,
    target_system=m.target_system,
    target_component=m.target_component,
    payload=ftp_list_root_payload)  # see MAVFTP spec
```

### MAVLink Detection (Blue Side)

On the defensive side, MAVLink traffic should be monitored for:
- Unknown sysid/compid (not in the vehicle's whitelist)
- Unsigned MAVLink 2 packets (incompat_flags bit 0 not set)
- COMMAND_LONG with arm/takeoff/RTL commands outside operator action windows
- SET_MODE to AUTO/GUIDED without operator trigger
- PARAM_SET writes outside maintenance windows
- MAVFTP traffic on production vehicles

See payloads.md Section 17 for a Python MAVLink anomaly detector.

---

## RF Attack Methodology

### 2.4 GHz Control Link Attacks

The 2.4 GHz control link (FrSky, FlySky, ELRS, CRSF, DJI) is the primary attack surface for unauthorized control of a drone. Attack vectors:

**FHSS Pattern Recovery**: capture the full 2.4 GHz band at 20 MSPS for ≥30 seconds (one full hop cycle) and apply STFT analysis to extract the hop pattern. See payloads.md Section 11 for the analysis script. Once the pattern is known, an attacker can:
- Predict the next hop and pre-tune a receiver.
- Inject packets on the correct channel at the correct time.
- Build a takeover transmitter that mimics the legitimate one.

**Sync Word Recovery**: the FHSS pattern is seeded by a sync word transmitted in the bind packet (when a new transmitter is paired with a receiver). Capturing the bind packet (a few seconds of capture during binding) reveals the sync word, which fully compromises the link.

**Jamming**: transmitting noise on the active hop channel forces the receiver to failsafe. If the failsafe is misconfigured (e.g. `FS_GCS_ENABLE=0`), the drone may continue flying without control input — dangerous for bystanders.

**Replay**: for non-cryptographic protocols (FrSky D8, older FlySky), a captured packet can be replayed to trigger the same action. Modern protocols (FrSky D16, ELRS, CRSF) use rolling codes or cryptographic authentication that prevent replay.

### 5.8 GHz Video Link Attacks

**Analog FPV**: trivially received by any 5.8 GHz receiver (no encryption). The attack is passive interception — see payloads.md Section 12 for capture + demodulation.

**Digital FPV (DJI O3, Walksnail, HDZero)**: encrypted via a pairing record stored in the aircraft and the receiver. Published attacks focus on extracting the pairing record from a compromised aircraft (via UART/JTAG on the air unit) and using it to receive the video stream. This is a hardware-research effort, not a software-only attack.

**DJI Go/Fly mobile app MITM**: the DJI mobile app communicates with the drone via USB or WiFi. Traffic includes drone telemetry, flight log upload, firmware update URLs, and DJI account auth tokens. MITM (with rooted Android + mitmproxy) reveals this traffic. See payloads.md Section 12.

### Crazyradio-Based Attacks

The Crazyradio PA is a USB dongle based on the nRF24LU1+ chip, originally designed for the Crazyflie nano drone. With the nrf-research-firmware (github.com/BastilleResearch/nrf-research-firmware), it can:
- Sniff any nRF24-based device (keyboards, mice, IoT, some drones).
- Inject raw packets.
- Operate in promiscuous mode (capture any nRF24 transmission regardless of address).

This makes it a versatile tool for drone RF testing when the target uses an nRF24-based protocol.

---

## GPS-Dependent Attacks

### Background: Why GPS Spoofing Works

Civil GPS signals (L1 C/A at 1575.42 MHz) are:
- **Unencrypted** — anyone with a receiver can decode them.
- **Unauthenticated** — there is no signature or MAC to verify the source.
- **Weak** — the signal arrives at -130 dBm, far below the noise floor, so any attacker transmitting at >-110 dBm will overwhelm the genuine signal.

This means an attacker with a HackRF can broadcast a counterfeit GPS signal that is stronger than the genuine one, and the receiver will lock onto the counterfeit signal.

### GPS-SDR-SIM

GPS-SDR-SIM (github.com/osqzssp/GPS-SDR-SIM) is the open-source tool for generating spoofed GPS I/Q samples. It takes:
- A current BRDC (broadcast ephemeris) file from NASA CDDIS — describes the satellite constellation.
- A trajectory (lat, lon, alt over time) — either static, dynamic (waypoint file), or circular.
- Sample rate, bit depth, duration.

And produces an I/Q file suitable for HackRF transmission. See payloads.md Section 9 for the full workflow.

### Spoof Detection Indicators

On the receiver side, several indicators betray a spoof:
- **C/N0 uniformity**: with a real signal, different satellites have different C/N0 values (35-50 dB-Hz depending on elevation). With a spoof, all satellites have similar high C/N0 (>40 dB-Hz) because they all come from the same transmitter.
- **AGC pegging**: the receiver's automatic gain control saturates (pegged at maximum gain) because the spoof signal is much stronger than expected.
- **Position jumps**: if the spoof starts after the receiver has already locked onto genuine signals, the receiver will report a sudden position jump (often >100 m) when it switches to the spoof.
- **Time-of-week mismatch**: the spoof's ephemeris time may not match the receiver's clock, causing a clock jump.
- **Multi-constellation cross-check**: if the receiver tracks GPS + Galileo + BeiDou, the spoof only affects GPS, and the positions diverge — a strong spoof indicator.

### Mitigations

For drone manufacturers, the recommended mitigations are:
- **Multi-constellation**: require GPS + Galileo + BeiDou all to agree (spoofing all three simultaneously is much harder).
- **IMU cross-check**: compare GPS-derived velocity against IMU-integrated velocity; alarm on divergence.
- **ADS-B cross-reference**: compare GPS ground speed against ADS-B (if available).
- **C/N0 monitoring**: alarm if C/N0 is suspiciously uniform across satellites.
- **AGC monitoring**: alarm if AGC pegs at maximum.
- **Inertial dead-reckoning fallback**: if GPS is lost or suspect, fall back to IMU-only navigation for short periods.

### Meaconing

Meaconing (replay of recorded GPS samples) is lower-effort than spoofing but less flexible:
- Record GPS samples at location A.
- Replay them at location B.
- The receiver at location B will report position A.

Meaconing cannot control the receiver's trajectory (you can only replay a fixed recording), but it can deny the genuine signal and force the receiver to report a wrong position.

### Legal Warning

**GPS transmission is illegal outside a Faraday cage or experimental license in virtually every jurisdiction.** In the USA:
- FCC Part 15 prohibits intentional radiators outside ISM bands.
- 18 U.S.C. § 32 makes it a felony to interfere with any aircraft, including drones.
- The FAA has authority over aerial navigation interference.

Always test GPS spoofing inside a verified Faraday cage (>40 dB shielding at 1.5 GHz). Even small leaks can affect nearby aircraft (aviation GPS receivers are extremely sensitive).

---

## Real-World Incidents

### 2011: RQ-170 Sentinel Downed in Iran

In December 2011, a US CIA RQ-170 Sentinel stealth drone was captured intact by Iran. The US claimed a mechanical failure; Iran claimed they spoofed its GPS to land it at a Iranian airbase. The technique (GPS spoofing of an aerial vehicle) was theoretically known but this was the first widely-reported real-world use.

The reported attack (per Iranian claims and later analysis by Western researchers):
1. Jam the GPS signal to force the RQ-170 into "return home" mode based on inertial navigation.
2. Spoof the GPS to make the drone believe it was approaching its home base (in Afghanistan).
3. The drone lands at the spoofed location (an Iranian airbase).

The plausibility of this attack was confirmed in 2012 by Todd Humphreys' team at the University of Texas at Austin, who demonstrated GPS spoofing of a small UAV. Their work led directly to the modern GPS-SDR-SIM toolset.

### 2017: US Army Bans DJI Drones

In August 2017, the US Army ordered all units to stop using DJI drones due to "cyber vulnerabilities." The cited concerns included:
- DJI drones uploading flight logs and operator data to DJI servers in China.
- DroneID broadcasting persistent identification (privacy concern).
- Potential for backdoor access via the DJI cloud.

This led to widespread adoption of DroneID sensors (DJI AeroScope) by US law enforcement and accelerated development of US-made alternatives (Skydio, Parrot US variants).

### 2020: Apache Helicopter Las Vegas Drone Swatter Incident

In September 2020, an Apache helicopter was performing a routine training flight near Las Vegas when a civilian drone operator flew a DJI Mavic near the helicopter. The helicopter crew reported the drone as a collision threat; the FAA investigated. The incident highlighted:
- The collision risk between civilian drones and manned aircraft (especially helicopters operating below 400 ft).
- The DroneID sensor coverage gap (LAS area was not fully covered by AeroScope at the time).
- The legal ambiguity around drone interference with manned aircraft.

### 2023-2024: CISA Advisories on PX4/Pixhawk

In 2023-2024, CISA (the US Cybersecurity and Infrastructure Security Agency) published several advisories on vulnerabilities in PX4 autopilot and Pixhawk-class hardware. The advisories covered:
- Buffer overflow in MAVLink param_id handling (CVE-2023-XXXX).
- MAVFTP directory traversal.
- Weak default credentials on companion computer Linux shells.
- Insecure firmware update verification.

These advisories directly informed the test cases in this skill (see TC-UD-004, TC-UD-005, TC-UD-011).

### 2024: FAA Remote ID Mandate

Effective September 2023 (full enforcement March 2024), the FAA requires all drones > 250 g operating in the USA to broadcast Remote ID. The ASTM F3411 standard specifies three methods:
- **Standard Remote ID**: built-in broadcast (BLE or WiFi Beacon).
- **Broadcast Module**: external beacon attached to a non-compliant drone.
- **FAA-Recognized Identification Area (FRIA**: a fixed location where drones can operate without Remote ID.

Remote ID broadcasts: drone serial number, operator ID, location, altitude, velocity, and home location — similar to DroneID but standardized. This massively expands the CUAS detection landscape: any drone sold after March 2024 broadcasts identification that any receiver can decode.

---

## Legal/Ethical Considerations

### FAA Part 107 (USA)

FAA Part 107 governs commercial drone operations in the USA:
- Requires a Remote Pilot Certificate (knowledge test, recurrent training).
- Daylight-only VLOS (Visual Line of Sight) operations by default.
- Max altitude: 400 ft AGL (above ground level).
- Max speed: 100 mph.
- No operations over people (without waiver).
- No operations in controlled airspace without LAANC authorization.

For drone security testing:
- Most lab testing (SITL, Crazyflie indoor, hardware-in-loop) does not require Part 107 (indoor or simulated).
- Outdoor flight testing requires Part 107 + LAANC (if in controlled airspace).
- GPS spoofing / RF transmission testing requires a Faraday cage regardless of Part 107.

### FCC Part 15 (USA)

FCC Part 15 governs unlicensed RF transmissions:
- ISM bands (433 MHz, 868 MHz, 915 MHz, 2.4 GHz, 5.8 GHz) allow unlicensed transmission within power limits (typically 10-100 mW EIRP).
- **GPS L1 (1575.42 MHz) is NOT an ISM band** — any transmission is illegal.
- Intentional interference (jamming) is always illegal.
- Even reception-only "sniffing" of licensed services (cellular, aviation) may violate wiretap laws.

For drone security testing:
- Passive RF reception (RTL-SDR, HackRF in RX mode) is generally legal.
- Active RF transmission in ISM bands is legal within power limits.
- GPS transmission is illegal outside a Faraday cage.
- Jamming any signal is illegal.

### Counter-UAS Legal Restrictions (USA)

18 U.S.C. § 32 (Destroying aircraft or aircraft facilities):
- Makes it a federal felony to damage, destroy, or interfere with any aircraft, including drones.
- Penalty: up to 20 years imprisonment (up to life if death results).
- Applies to civilians, state/local law enforcement, and private facilities.

6 U.S.C. § 465 (Preventing Emerging Threats Act of 2018):
- Grants DHS and DOJ explicit CUAS authority for certain facilities.
- DoD has separate authority under 10 U.S.C. § 130i.
- The 2024 NDAA expanded this authority to additional agencies.

The practical implication: **only federal actors (DHS, DOJ, DoD) have legal authority for active CUAS interdiction** (jamming, protocol takeover, kinetic kill). State/local police, private facilities (stadiums, critical infrastructure), and civilians have **no** legal authority for active interdiction.

Permitted responses for non-federal actors:
- Passive detection (RF, radar, acoustic, EO/IR) — generally legal.
- Documentation for law enforcement — legal and recommended.
- Verbal/written request to the operator — legal.
- Notification of FAA FSDO or local law enforcement — legal.

Active interdiction (jamming, takeover, kinetic kill) by non-federal actors is a felony and is NOT covered by this skill.

### Other Jurisdictions

- **EU**: EASA drone regulations (effective 2020) mirror Part 107; GDPR applies to DroneID/Remote ID data collection.
- **UK**: CAA drone regulations + Air Navigation Order; Computer Misuse Act applies to MAVLink injection.
- **Australia**: CASA Part 101; Radiocommunications Act governs RF.
- **China**: CAAC drone regulations; strict data localization requirements for drone data.

### Ethical Disclosure

For vendor vulnerabilities found during testing:
- **DJI**: coordinated disclosure via the DJI Security Response Center (security.dji.com).
- **PX4**: GitHub issues at github.com/PX4/PX4-Autopilot (public; do not file security issues publicly — use the private disclosure process).
- **ArduPilot**: GitHub issues at github.com/ArduPilot/ardupilot.
- **MAVLink**: github.com/mavlink/c_library_v2 issues.

Standard coordinated disclosure timeline: 90 days from initial report to public disclosure (per Google Project Zero convention).

---

## References

### Open-Source Projects

- **PX4-Autopilot**: github.com/PX4/PX4-Autopilot — BSD-3 license open-source autopilot.
- **ArduPilot**: github.com/ArduPilot/ardupilot — GPLv3 open-source autopilot.
- **MAVLink**: mavlink.io — protocol specification and code generators.
- **MAVProxy**: github.com/ArduPilot/MAVProxy — Python GCS and MAVLink router.
- **QGroundControl**: github.com/mavlink/qgroundcontrol — cross-platform GUI GCS.
- **pymavlink**: github.com/ArduPilot/pymavlink — Python MAVLink library.
- **DroneSploit**: github.com/dronesploit/dronesploit — drone-focused pentest framework.
- **DroneID-timeline**: github.com/trendmicro/DroneID-timeline — DJI DroneID wireshark dissector.
- **GPS-SDR-SIM**: github.com/osqzssp/GPS-SDR-SIM — GPS signal generator.
- **dji-firmware-tools**: github.com/o-gs/dji-firmware-tools — DJI firmware unpacker.
- **pyulog**: github.com/PX4/pyulog — PX4 ULog parser.
- **Crazyflie firmware**: github.com/bitcraze/crazyflie-firmware.
- **nrf-research-firmware**: github.com/BastilleResearch/nrf-research-firmware — Crazyradio raw nRF24 firmware.

### Research Hubs

- **Awesome-Drone-Hacking**: github.com/nicholasaleks/Awesome-Drone-Hacking — curated list of drone security resources.
- **DEF CON Aerial Assault Village**: defcon.org — yearly training track at DEF CON.
- **BlackHat drone research**: blackhat.com — search for "drone" in the Briefings archive (2013-2024).
- **USENIX / IEEE drone papers**: usenix.org, ieeexplore.ieee.org — academic drone security research.
- **NASA CDDIS**: cddis.nasa.gov — GPS ephemeris data (BRDC files) for GPS-SDR-SIM.

### Standards and Regulations

- **FAA Part 107**: eCFR 14 CFR Part 107 — US commercial drone operations.
- **FAA Remote ID**: 14 CFR Part 89 — Remote ID mandate (effective March 2024).
- **FCC Part 15**: eCFR 47 CFR Part 15 — unlicensed RF emissions.
- **ASTM F3411**: ASTM Remote ID standard.
- **EASA drone regulations**: easy-access-rules.easa.eu — EU drone rules.
- **18 U.S.C. § 32**: law.cornell.edu/uscode/text/18/32 — aircraft interference felony.
- **6 U.S.C. § 465**: Preventing Emerging Threats Act of 2018 (DHS/DOJ CUAS authority).

### CISA Advisories

- **CISA ICS Advisory on PX4**: cisa.gov/news-events/cybersecurity-advisories (search for PX4 or Pixhawk).
- **CISA Advisory on Drone Vendors**: periodic; check the CISA advisories feed for the latest.

### Books and Long-Form Resources

- **"Hacking Drones"** (cybersecurity researcher community publications).
- **Todd Humphreys' UT Austin RAD Lab**: utexas.edu/aerospace/rad — GPS spoofing research.
- **Samy Kamkar's research**: samy.pl — drone and IoT security research.

### Training and Community

- **DEF CON Aerial Assault Village**: yearly at DEF CON (Las Vegas, August).
- **Aerial Security Meetup**: regional meetups in major cities.
- **DIY Drones community**: diydrones.com — historical hobbyist community.
- **PX4 / ArduPilot Discord**: active developer communities.

---

## Closing Notes

Drone security is a young field with significant room for new research. The attack surface (autopilot + MAVLink + GPS + RF control + video link + firmware) is broad and largely unauthenticated by default. Defensive tooling (DroneID sensors, Remote ID, MAVLink signing, GPS cross-check) is maturing but lags the offensive capability.

For penetration testers, the most impactful work is in the firmware-update channel (a trojanized `.px4` or `dji_system.bin` is the path to persistent compromise) and the MAVLink layer (every misconfigured MAVLink link is a takeover waiting to happen). For defenders, the most impactful work is in passive CUAS detection (DroneID + RF fingerprinting + acoustic signature) and in flight-log anomaly detection (catching mode changes and param writes that don't match operator intent).

The legal framework is strict — aerial-vehicle interference is a felony in the USA and equivalent in most jurisdictions. Every test case in this skill assumes a Faraday cage, written authorization, and compliance with FAA Part 107 and FCC Part 15. There is no legitimate scenario in which an unaffiliated tester should attempt active interdiction of a drone they do not own.
