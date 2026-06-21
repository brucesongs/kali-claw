---
name: hf-vhf-radio-attack
description: Licensed HF/VHF/UHF radio attack — ADS-B 1090 MHz, AIS, ACARS, VDL Mode 2, POCSAG/FLEX pagers, APRS, NDB, ATC/maritime VHF, DSC, weather fax, MLAT
origin: kali-claw
version: 1.0
compatibility:
  - Claude Code
  - Claude Sonnet 4.5+
  - openclaw
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: hf-vhf-radio-attack
  category: lowfreq-radio
  tool_count: 13
  guide_count: 2
  mitre: T1557-Adversary-in-the-Middle
  keywords:
    - SDR
    - HF
    - VHF
    - UHF
    - ADS-B
    - AIS
    - ACARS
    - pager
    - aviation
    - maritime
    - POCSAG
    - FLEX
    - APRS
    - NDB
    - DSC
---


# Skill: Licensed HF/VHF/UHF Radio Attack

> **Supplementary Files**:
> - `payloads.md` -- Complete payload collection organized by licensed radio service (ADS-B, AIS, ACARS, VDL Mode 2, HFDL, POCSAG/FLEX/APOC pagers, APRS, NDB, weather fax, DSC, ATC/maritime VHF voice, MLAT/TIS-B/UAT, Inmarsat/Iridium L-band) -- 18 sections covering RX hardware setup, decoding chains, TX-side spoofing with HackRF/BladeRF, replay attacks, OPSEC for engagements, and red-team aviation/maritime scenarios.
> - `test-cases.md` -- Structured test case templates (12 cases TC-LF-001..TC-LF-012): hardware verification, ADS-B aircraft tracking, AIS maritime decode, ACARS airline comms, VDL Mode 2 digital link, HFDL oceanic intercept, POCSAG pager decode, FLEX pager decode, APRS position reporting, NDB beacon tracking, weather fax reception, DSC maritime distress decode.
> - `guides/hf-vhf-radio-attack-playbook.md` -- Comprehensive playbook: SDR hardware tier table (RX-only, TX/RX, full-duplex), decoding matrix (which tool for which band), real-world research (Povolny ADS-B spoofing 2012, Trend Micro maritime AIS, DEF CON ACARS/POCSAG talks), antenna design basics for HF/VHF/UHF, ITU region licensing and FCC Part 15 vs Part 97 red-team rules of engagement, lab setup with HackRF + GQRX + multimon-ng + dump1090-mutability.

## Summary

HF/VHF/UHF licensed radio attack covers the spectrum **above** Sub-GHz ISM (handled in `sdr-rf-attack`) and **below** cellular operator bands (handled in `5g-telecom-attack`). This skill targets **licensed radio services** in the 9 kHz - 1500 MHz range that have safety-of-life or commercial licensing implications: aircraft ADS-B broadcasts at 1090 MHz, maritime AIS at 161.975/162.025 MHz, airline ACARS data link at 131.550 MHz, VDL Mode 2 at 136.975 MHz, HFDL oceanic comms across multiple HF bands, POCSAG/FLEX/APOC pager networks, amateur radio APRS position reporting, aviation NDB beacons (190-535 kHz, 1750 kHz AM), weather fax, maritime DSC distress on Channel 70, ATC voice (118-137 MHz AM), maritime VHF voice (Channel 16 / 156.8 MHz), and ADS-B MLAT / TIS-B / UAT on 978 MHz. Inmarsat and Iridium L-band (1.5/1.6 GHz) are included briefly for context as the upper edge of this spectrum and the lower edge of satellite work.

The defining property of these services is that **they are public broadcast or licensed point-to-point services that are trivially receivable with a $30 RTL-SDR dongle and a basic antenna**, but **transmitting on them requires explicit licensing (FCC Part 87 aviation, Part 80 maritime, Part 97 amateur) and unauthorized transmission is a federal crime in most jurisdictions**. The red-team value is asymmetric: receivers can map aircraft, vessels, pagers, and tactical voice traffic without transmitting a single photon, while transmitters (spoofers, jammers) require Faraday-cage containment and explicit legal authorization. This skill emphasizes the **receive-side intelligence, OPSEC, and protocol-security research** that dominates licensed-band assessment work, with transmit-side attacks documented as research context only.

**Tools**: HackRF One, BladeRF 2.0 micro, RTL-SDR (rtl-sdr.com V3), PlutoSDR (ADALM-PLUTO), AirSpy R2/Mini/HF+ Discovery, GNU Radio, GQRX/SDR#/SDRangel/CubicSDR, dump1090-mutability/readsb, dump978 (UAT), AIS-catcher/rtl-ais/ShipXplorer, multimon-ng (POCSAG/FLEX), ACARSDeco/dumpvdl2/dumphfdl, URH (Universal Radio Hacker).

**Domain**: hf-vhf-radio-attack

**MITRE ATT&CK**: T1595-Active Scanning (RF), T1592-Gather Victim Host Info (RF fingerprinting), T1557-Adversary-in-the-Middle (RF relay), T1580-Cloud Infrastructure Discovery (RF telemetry exfil), T1499-Endpoint Denial of Service (RF jamming, authorized research only).

## Differentiation

This skill is explicitly bounded to avoid overlap with two adjacent RF skills:

### vs. `sdr-rf-attack` (Sub-GHz ISM and unlicensed radio)

`sdr-rf-attack` covers **unlicensed ISM band** devices: 315/433/868/915 MHz keyfobs, garage door openers, wireless doorbells, weather stations, Sub-GHz IoT (Zigbee/LoRa raw radios at 868/915), plus RFID/NFC at 125 kHz and 13.56 MHz, GSM/LTE cellular, and 2.4 GHz BLE/Zigbee. Those are devices you own, test, and replay at will within ISM band rules.

This skill (`hf-vhf-radio-attack`) covers **licensed services above the ISM band** -- aviation, maritime, pager, and amateur radio infrastructure where the transmitters are operated under FCC/ITU licenses and the receivers are anyone with an SDR. The frequencies and protocols are entirely different (1090 MHz ADS-B, 162 MHz AIS, 131.550 MHz ACARS, etc.) and the legal posture is different: receiving is mostly unrestricted, transmitting without a license is a crime.

### vs. `5g-telecom-attack` (cellular operator infrastructure)

`5g-telecom-attack` covers the **operator-side cellular stack**: 5G Core (AMF/SMF/UPF), RAN, and signaling protocols (NGAP/PFCP/GTP/Diameter/SS7), IMSI catchers, and O-RAN security. Those are the carrier network components between the UE and the internet.

This skill does **not** cover cellular operator infrastructure. It covers licensed non-cellular services: aircraft transponders, ship AIS, airline ACARS data links, pagers, amateur radio APRS, aviation beacons, and maritime distress. Even where there is overlap in frequency (e.g., both 5G and AIS are in the 1.5-2 GHz region for satellite AIS), the protocols, threat models, and tooling are distinct.

### Quick frequency map for orientation

| Band | Frequency | Covered in |
|------|-----------|------------|
| LF (NDB aviation beacons) | 190-535 kHz, 1750 kHz | **this skill** |
| MF (AM broadcast) | 530-1710 kHz | out of scope (broadcast) |
| HF (amateur, marine, aviation, HFDL) | 3-30 MHz | **this skill** |
| VHF ATC voice | 118-137 MHz AM | **this skill** |
| VHF maritime voice | 156-174 MHz FM (Ch 16 = 156.8 MHz) | **this skill** |
| VHF AIS | 161.975 / 162.025 MHz | **this skill** |
| 2m amateur APRS | 144.39 MHz (US), 144.64 MHz (EU) | **this skill** |
| VHF ACARS | 131.550 MHz AM | **this skill** |
| VDL Mode 2 | 136.975 MHz | **this skill** |
| Sub-GHz ISM (keyfobs, IoT) | 315/433/868/915 MHz | `sdr-rf-attack` |
| UAT (978 MHz) | 978 MHz | **this skill** |
| ADS-B | 1090 MHz | **this skill** |
| Inmarsat / Iridium L-band | 1525-1660 MHz | **this skill (briefly, context only)** |
| GSM/LTE/5G | 700/850/1800/2100/2600/3500 MHz | `5g-telecom-attack` and `sdr-rf-attack` |
| WiFi/BLE | 2.4 GHz, 5 GHz, 6 GHz | `sdr-rf-attack`, `wifi-pentest`, `bluetooth-rfid-nfc` |
| GNSS (GPS/Galileo/GLONASS) | 1575.42 MHz, etc. | `sdr-rf-attack` (gps-spoofing-guide) |

## Description

Licensed HF/VHF/UHF radio attack encompasses a broad range of receive-side intelligence and (with proper authorization) active RF testing against radio services operated under aviation, maritime, paging, and amateur radio licenses. This skill covers the complete assessment lifecycle from hardware selection and antenna matching through signal capture, protocol decode, anomaly detection, and authorized spoofing/injection research in controlled environments.

**Core Attack Surfaces**:

- **Aircraft Tracking (ADS-B 1090 MHz, UAT 978 MHz)**: Receive Mode S extended squitters from any aircraft within line of sight; decode ICAO 24-bit address, callsign, position, velocity, altitude, and trajectory intent. Detect spoofed aircraft, MLAT/TIS-B injection, and ghost aircraft. Map real-time air traffic over a 300+ nm radius with a $30 RTL-SDR and a 1090 MHz collinear antenna.
- **Maritime Vessel Tracking (AIS 161.975/162.025 MHz)**: Decode Class A and Class B AIS position reports, static voyage data, and SAR aircraft positions. Detect "dark targets" (vessels with AIS off), spoofed MMSIs, and aid-to-navigation manipulation. AIS is unencrypted by design -- the security question is not "can you read it" but "can you trust what you read."
- **Airline Communications (ACARS 131.550 MHz, VDL Mode 2 136.975 MHz, HFDL)**: Decode aircraft-to-ground data link messages including airline operational comms (AOC), air traffic control (ATC) uplinks, and oceanic position reports. ACARS is partially unencrypted and reveals aircraft intent, ETA, fuel state, and crew messages on many operators. VDL Mode 2 is the VHF digital link successor; HFDL is the HF oceanic counterpart.
- **Pager Networks (POCSAG 512/1200/2400 bps, FLEX 1600/3200/6400, APOC)**: Decode pager messages from public safety, hospital, utility, and enterprise pager fleets. POCSAG and FLEX are unencrypted in nearly all deployments and routinely expose sensitive patient data, dispatch codes, and infrastructure alerts. Pager security research (Andrea Barisani, DEF CON 18) showed nationwide pager fleet coverage from a single rooftop.
- **Amateur Radio APRS (144.39 MHz US, 144.64 MHz EU)**: Decode automatic position reporting system packets from amateur operators, including position, status, messages, weather, and telemetry. Useful for OPSEC assessment of ham radio infrastructure and for understanding AX.25/KISS RF data links.
- **Aviation NDB (190-535 kHz, 1750 kHz AM)**: Track non-directional beacons used for aviation navigation. Continuous wave AM Morse code identification. Useful as a calibration signal and for assessing legacy aviation infrastructure.
- **Weather Fax (HF)**: Decode radiofax images broadcast by meteorological services (NOAA, DWD Germany, JMA Japan) on HF bands for maritime and aviation weather briefings. Demonstrates HF image transmission protocols.
- **Maritime DSC (Digital Selective Calling)**: Decode distress, urgency, safety, and routine calls on VHF Channel 70 (156.525 MHz), MF 2187.5 kHz, and HF 4/6/8/12/16 MHz DSC channels. Reveals maritime distress infrastructure and the unencrypted nature of DSC messaging.
- **ATC Voice (118-137 MHz AM)**: Monitor air traffic control voice communications between pilots and controllers. AM modulation, 25 kHz (or 8.33 kHz in Europe) channel spacing. Critical context for aviation security assessment and red-team OPSEC.
- **Maritime VHF Voice (Ch 16 = 156.8 MHz, Ch 13 = 156.65 MHz)**: Monitor international maritime distress, safety, and bridge-to-bridge communications. NBFM modulation, 25 kHz channel spacing.
- **MLAT / TIS-B / UAT (978 MHz)**: Decode Mode U transponders, Traffic Information Service-Broadcast (TIS-B), and Automatic Dependent Surveillance-Broadcast (ADS-B) on the UAT frequency used primarily in US airspace. Complements 1090 MHz ADS-B reception.
- **Satellite L-band (Inmarsat / Iridium 1525-1660 MHz)**: Brief coverage for context -- Inmarsat STD-C (fleet messaging), Iridium bursty transmissions, and the limits of consumer SDR in this band. Full satellite exploitation is out of scope; see `sdr-rf-attack/satellite-signal-analysis-guide.md` for complementary NOAA/AIS/ADS-B satellite work.

**Privacy and OPSEC Implications**:

- **Aircraft and vessel tracking**: Any SDR receiver within line of sight can track aircraft and vessels in real time. This is the basis of Flightradar24, FlightAware, MarineTraffic, and VesselFinder. There is no radio-level privacy on ADS-B or AIS; the privacy question is whether the data is being aggregated and resold.
- **Pager interception**: Hospital pagers routinely transmit patient PHI (name, room, attending physician, diagnosis). Public safety pagers transmit dispatch codes and addresses. This is unencrypted broadcast data and represents one of the largest unaddressed PHI-leak surfaces in healthcare.
- **ACARS intercept**: Airline operational communications can reveal aircraft mechanical issues, crew names, diversion decisions, and ATC coordination -- commercially sensitive data that is broadcast in the clear on 131.550 MHz.
- **DSC false alerts**: Maritime DSC distress false alarms are a real operational problem. Receivers can characterize the local DSC traffic to assess how easily a false distress alert could be injected.

**Red-Team Engagement Context**:

- **Maritime facility assessment**: A red team assessing a port or vessel operator can use AIS reception to map vessel traffic patterns, identify dark targets, and characterize the local maritime RF environment before any active testing.
- **Aviation facility assessment**: ADS-B and ACARS reception at an airport-adjacent facility reveals aircraft callsigns, routes, and operational comms without any active RF emissions.
- **Hospital pager audit**: Passive reception of POCSAG pagers can document PHI exposure as part of a HIPAA security assessment.
- **Critical infrastructure RF survey**: Wideband HF/VHF/UHF survey of a facility perimeter can identify unauthorized pager, voice, or telemetry traffic that should not be present.

**Related Skills**:
- `skills/sdr-rf-attack/SKILL.md` -- Sub-GHz ISM band devices (keyfobs, IoT, weather stations) and RFID/NFC radio-layer attacks
- `skills/5g-telecom-attack/SKILL.md` -- Cellular operator infrastructure (5G Core, RAN, signaling)
- `skills/bluetooth-rfid-nfc/SKILL.md` -- BLE and RFID/NFC protocol-layer attacks
- `skills/wifi-pentest/SKILL.md` -- WiFi at 2.4/5/6 GHz
- `skills/hardware-security/SKILL.md` -- Hardware attack vectors including glitching, bus sniffing
- `skills/physical-security-testing/SKILL.md` -- Physical security assessment context for RF surveillance

---

## Use Cases

1. **ADS-B Aircraft Tracking and Anomaly Detection**: Deploy a passive ADS-B receiver to map all aircraft within 300+ nm of an engagement site. Detect spoofed aircraft (ghost aircraft with mismatched ICAO 24-bit addresses or impossible trajectories), identify state aircraft (military, government, VIP), and document the air traffic baseline for OPSEC assessment of an aviation-adjacent facility.
2. **Maritime AIS Vessel Tracking and Dark Target Detection**: Receive AIS position reports to map vessel traffic at a port or coastal engagement site. Identify vessels with AIS disabled (dark targets), detect MMSI spoofing (vessels broadcasting another vessel's MMSI), and characterize fishing, commercial, and military vessel patterns.
3. **Airline ACARS Data Link Interception**: Passively receive ACARS messages at 131.550 MHz to document the airline operational communications visible from an engagement site. Useful for assessing whether a facility's location near a flight corridor creates information disclosure exposure for client airline operations.
4. **Hospital/Healthcare Pager PHI Audit**: As part of a HIPAA security assessment, receive POCSAG and FLEX pager messages from a hospital or clinic and document the extent of patient health information being broadcast in the clear. Provide remediation recommendations for migration to encrypted paging or secure messaging.
5. **Public Safety Pager Fleet Characterization**: For emergency services clients, document the dispatch codes, addresses, and operational data visible in their pager fleet. Useful for OPSEC review of dispatch infrastructure and assessment of pager reliance for sensitive operations.
6. **VDL Mode 2 and HFDL Oceanic Comms Research**: Decode the modern VHF digital link (VDL Mode 2 at 136.975 MHz) and HF oceanic data link (HFDL across multiple HF bands) to assess the security posture of next-generation aircraft communications and to characterize oceanic position reporting.
7. **Amateur Radio APRS OPSEC Review**: For amateur radio operators or organizations relying on ham radio for emergency communications, decode APRS traffic to assess OPSEC exposure of position, status, and message data broadcast on 144.39 MHz.
8. **ATC Voice Monitoring for Aviation Red Team**: As part of an authorized airport or aviation facility assessment, monitor ATC voice traffic on 118-137 MHz AM to characterize traffic flow, identify operational patterns, and document information disclosure risks.
9. **Maritime DSC Distress Infrastructure Characterization**: Receive DSC calls on VHF Channel 70 and HF DSC frequencies to document the local maritime distress infrastructure, characterize routine DSC traffic, and assess the feasibility of false alert injection (research context only, never transmit).
10. **Critical Infrastructure RF Perimeter Survey**: Wideband survey of HF/VHF/UHF bands at a critical infrastructure perimeter (substation, water plant, data center) to identify unexpected pager, voice, telemetry, or amateur radio traffic that could indicate unauthorized RF devices or operational leakage.
11. **Aviation NDB Beacon Calibration and Tracking**: Receive NDB beacons (190-535 kHz AM) as a calibration signal for SDR hardware, and to characterize the legacy aviation navigation infrastructure still in use at many smaller airports.
12. **Weather Fax Reception for Maritime Assessment**: Decode weather fax broadcasts from meteorological services to support maritime engagement situational awareness and document the data available to vessels in the engagement area.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **HackRF One** | TX/RX SDR for wideband capture and (authorized) transmission from 1 MHz to 6 GHz | `hackrf_transfer -r capture.raw -f 1090000000 -s 2000000 -l 32 -g 40` |
| **BladeRF 2.0 micro** | Full-duplex TX/RX SDR from 47 MHz to 6 GHz, 56 MHz bandwidth, suitable for protocol emulation | `bladerf-cli -f firmware_latest.r3 -l fpga_*.rbf -i script.txt` |
| **RTL-SDR (rtl-sdr.com V3)** | Low-cost RX-only dongle, 24-1766 MHz, 2.4 MHz bandwidth, ideal for ADS-B/AIS/pager | `rtl_sdr -f 1090000000 -s 2000000 -g 40 -n 2000000 adsb.raw` |
| **PlutoSDR (ADALM-PLUTO)** | TX/RX learning SDR from 325 MHz to 3.8 GHz, extensible to 70 MHz - 6 GHz with mod | `iio_attr -u ip:pluto.local -c -o ad9361-phy test_atten 10` |
| **AirSpy R2 / Mini / HF+ Discovery** | High-dynamic-range RX SDRs; AirSpy HF+ Discovery optimized for HF (9 kHz - 31 MHz, 110 dB dynamic range) | `airspy_rx -f 1090 -r adsb.air -g mixervga -b 10000000` |
| **GNU Radio** | Block-based signal processing framework for custom decoders and protocol implementations | `gnuradio-companion` -> Osmocom Source -> Demod -> Sink |
| **GQRX / SDR# / SDRangel / CubicSDR** | GUI SDR receivers for real-time spectrum monitoring, signal identification, and audio demodulation | `gqrx` -> Set device -> Tune frequency -> Adjust FFT -> Record |
| **dump1090-mutability / readsb** | ADS-B decoder for Mode S extended squitters at 1090 MHz, web GUI with live map | `dump1090 --net --net-ro-port 30003 --gain 40 --ppm 0` |
| **dump978** | UAT decoder for 978 MHz ADS-B (US airspace), complementary to dump1090 | `dump978 -f 978000000 -s 2000000 -g 40 -t gaincontrol` |
| **AIS-catcher / rtl-ais / ShipXplorer** | AIS decoders for 161.975/162.025 MHz maritime vessel tracking | `AIS-catcher -u 12345 -v -T` or `rtl_ais -T -p` |
| **multimon-ng** | Multi-protocol decoder for POCSAG, FLEX, APOC, ZVEI, EAS, and other low-rate RF protocols | `multimon-ng -t rtl -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX` |
| **ACARSDeco / dumpvdl2 / dumphfdl** | Aircraft data link decoders: ACARS (131.550 MHz), VDL Mode 2 (136.975 MHz), HFDL (HF bands) | `acarsdeco -r 0:131550000 -g 40` or `dumpvdl2 --gain 40 --corrupted-messages --output decoded:text:file:stdout` |
| **URH (Universal Radio Hacker)** | Interactive protocol reverse engineering for unknown RF signals with auto-modulation detection | `urh` -> Load capture -> Auto-detect modulation -> Assign labels -> Replay |

---

## Methodology

### Phase 1: Reconnaissance -- Licensed Band Survey

1. Conduct wideband spectrum scan across the HF/VHF/UHF range relevant to the engagement scope using `rtl_power` or `hackrf_sweep`
2. Identify active licensed services (aviation, maritime, paging, amateur) by their characteristic frequencies and modulations
3. Document the baseline RF environment at the engagement site including expected and unexpected signals
4. Identify the specific licensed services in scope for the assessment (e.g., AIS at a port, ADS-B at an airport)

### Phase 2: Receive-Side Intelligence (Passive)

1. Configure SDR hardware for the target licensed service with appropriate antenna (1090 MHz collinear for ADS-B, VHF marine for AIS, etc.)
2. Launch the appropriate decoder (dump1090 for ADS-B, AIS-catcher for AIS, multimon-ng for POCSAG, dumpvdl2 for VDL Mode 2)
3. Collect traffic for the assessment period (typically hours to days for traffic pattern analysis)
4. Decode and aggregate data into structured form (vessel list, aircraft list, pager message log, etc.)
5. Identify anomalies: spoofed aircraft, dark targets, PHI leakage in pagers, unexpected vessel callsigns

### Phase 3: Protocol Security Analysis

1. Capture raw I/Q samples of the target protocol for offline analysis
2. Examine the protocol for authentication, integrity, and encryption mechanisms (most licensed services have none)
3. Document the data exposure: what sensitive information is broadcast in the clear
4. Cross-reference decoded data with public databases (FAA aircraft registry for ICAO addresses, ITU for MMSI allocations)

### Phase 4: Active Testing (Authorized Research Only)

1. **CRITICAL**: Active RF testing on licensed bands requires explicit written authorization and typically must be conducted in a Faraday cage or shielded enclosure
2. Verify all transmissions are contained (no leakage to live spectrum)
3. Test replay attacks against captured signals in the shielded environment
4. Test spoofing/injection (e.g., ghost ADS-B aircraft) only with the target receiver also in the shielded enclosure
5. Document findings for protocol security research without impacting live services

### Phase 5: Reporting and OPSEC Recommendations

1. Document all licensed services observed at the engagement site
2. Quantify sensitive data exposure (e.g., "X patient names observable per hour from hospital pager fleet")
3. Provide remediation recommendations: encrypted paging alternatives, AIS/ADS-B trust verification, etc.
4. Include spectrum analysis evidence, decoded traffic samples (redacted of PHI), and timeline of activities
5. Highlight any unauthorized or unexpected RF signals that may indicate rogue devices or operational security gaps

---

## Practical Steps

### Step 1: Hardware Setup and Verification

```bash
# Verify HackRF One is detected and report capabilities
hackrf_info

# Check RTL-SDR v3 dongle and report tuner type
rtl_test -t

# Calibrate HackRF PPM offset against a known reference signal (e.g., WWV at 10 MHz)
hackrf_transfer -r /dev/null -f 10000000 -s 8000000 -l 32 -g 20 -n 8000000

# Verify AirSpy HF+ Discovery is detected (ideal for HF bands)
airspy_rx --help 2>&1 | head -5

# List all SDR devices connected via USB
lsusb | grep -i "realtek\|hackrf\|nuand\|airspy\|analog"
```

### Step 2: ADS-B Aircraft Tracking

```bash
# Start dump1090-mutability with web GUI on port 8080
dump1090 --net --net-ro-port 30003 --net-sbs-port 30003 \
  --gain 40 --ppm 0 --aggressive --interactive

# Alternative: readsb (more modern, higher performance)
readsb --net --gain 40 --device-type rtlsdr --write-json /run/readsb

# Capture raw ADS-B I/Q for offline analysis
rtl_sdr -f 1090000000 -s 2000000 -g 40 -n 20000000 adsb_raw.raw

# Decode ADS-B from raw capture
dump1090 --ifile adsb_raw.raw --fix --aggressive

# Feed ADS-B data to a local FlightAware PiAware instance
# (PiAware consumes dump1090 on port 30005 and forwards to FlightAware)
```

### Step 3: AIS Maritime Vessel Tracking

```bash
# Start AIS-catcher with UDP output to a chartplotter or aggregator
AIS-catcher -u 12345 -v -T -g 40

# Alternative: rtl_ais (simpler, two-channel RTL-SDR decoder)
rtl_ais -T -p -h 127.0.0.1 -P 12345

# Capture raw AIS I/Q on 161.975 MHz for offline analysis
rtl_sdr -f 161975000 -s 250000 -g 40 -n 2500000 ais1.raw

# Decode AIS from raw capture
AIS-catcher --input ais1.raw --output decoded.json

# Forward AIS to OpenCPN network data source (NMEA-0183 over UDP)
AIS-catcher -u 127.0.0.1:10110 -v
```

### Step 4: POCSAG/FLEX Pager Decoding

```bash
# Decode POCSAG at 512/1200/2400 bps from a live SDR via rtl_fm
rtl_fm -f 157.775e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX -

# Decode POCSAG directly from RTL-SDR via the multimon-ng rtl backend
multimon-ng -t rtl --rtl-frequency 157775000 --rtl-gain 40 \
  -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX

# Capture pager I/Q for offline analysis
rtl_sdr -f 157775000 -s 250000 -g 40 -n 25000000 pager.raw

# Decode from a captured WAV file (multimon-ng expects 22050 Hz mono)
sox pager.raw -r 22050 -c 1 -e signed-integer -b 16 pager.wav
multimon-ng -t wav -a POCSAG1200 -a FLEX pager.wav
```

### Step 5: ACARS and VDL Mode 2 Aircraft Comms

```bash
# Decode ACARS at 131.550 MHz AM
acarsdeco -r 0:131550000 -g 40 --silence-level 5

# Decode VDL Mode 2 at 136.975 MHz
dumpvdl2 --gain 40 --corrupted-messages --output decoded:text:file:stdout

# Capture ACARS I/Q for offline analysis (AM-modulated)
rtl_sdr -f 131550000 -s 250000 -g 40 -n 25000000 acars.raw

# Decode HFDL across multiple HF bands (requires HF-capable SDR like AirSpy HF+ Discovery)
dumphfdl --gain 40 --output decoded:text:file:stdout \
  2941000 5455000 8927000 11306000 15025000 17922000
```

### Step 6: APRS Amateur Radio Position Reporting

```bash
# Decode APRS at 144.39 MHz (US) using multimon-ng
rtl_fm -f 144.39e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a AFSK1200 -

# Alternative: direwolf (full-featured AX.25/KISS TNC)
direwolf -t 0 -r 22050 -b 16

# Pipe rtl_fm to direwolf for live APRS decode
rtl_fm -f 144.39e6 -s 48000 -g 40 - | \
  direwolf -r 48000 -b 16 -
```

### Step 7: ATC Voice and Maritime VHF Voice Monitoring

```bash
# Listen to ATC voice (e.g., tower at 118.300 MHz AM)
rtl_fm -M am -f 118.3e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# Listen to maritime VHF Channel 16 (156.8 MHz NBFM)
rtl_fm -M fm -f 156.8e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# Record ATC voice to a WAV file for OPSEC review
rtl_fm -M am -f 121.5e6 -s 12000 -r 12000 -g 40 - | \
  sox -t s16 -r 12000 -c 1 - atc_guard.wav
```

---

## Defense Perspective

### Detection and Monitoring

- **RF perimeter monitoring**: Deploy dedicated receivers at critical facilities to detect unauthorized ADS-B/AIS/pager transmissions or rogue devices in restricted bands
- **AIS/ADS-B anomaly detection**: Cross-reference received position reports with known vessel/aircraft registries to detect spoofed identifiers or impossible trajectories
- **Pager fleet auditing**: Continuously monitor enterprise pager fleets to detect PHI leakage and unexpected message content
- **Direction-finding for rogue transmitters**: Use multiple SDR receivers with time-difference-of-arrival (TDOA) or rotating directional antennas to locate unauthorized RF sources

### Hardening Recommendations

- **Migrate pagers to encrypted paging or secure messaging**: Replace unencrypted POCSAG/FLEX with encrypted protocols or move to end-to-end encrypted mobile messaging (e.g., Wickr, Signal) for sensitive dispatch
- **AIS trust verification**: Cross-reference received AIS positions with radar tracks, satellite AIS, and visual confirmation; flag mismatches as potential spoofing
- **ADS-B authentication (future)**: Support ADS-B authentication proposals (e.g., the FAA's proposed cryptographic authentication of ADS-B messages) as they become available
- **Aviation facility RF zoning**: Design airport-adjacent facilities to minimize information disclosure from ACARS, ATC voice, and ADS-B reception by third parties
- **VDL Mode 2 security upgrade**: Where ACARS security is critical, migrate to Secured VDL Mode 2 (SVDL) or future CPDLC over secured links

### Compliance Considerations

- **Receiving licensed broadcast signals**: In most jurisdictions, receiving ADS-B, AIS, ATC voice, ACARS, and POCSAG transmissions is legal because they are unencrypted broadcasts. However, acting on the information received (e.g., disclosing PHI from pagers) may be regulated.
- **Transmitting on licensed bands**: Transmitting on aviation, maritime, paging, or amateur radio frequencies without an appropriate license is a criminal offense in virtually all jurisdictions. In the US, this is enforced by the FCC (Part 87 aviation, Part 80 maritime, Part 97 amateur) and can result in substantial fines and imprisonment.
- **Amateur radio license requirement**: Transmitting on amateur radio bands (including APRS at 144.39 MHz) requires an amateur radio license. Reception is unrestricted.
- **Maritime and aviation facility testing**: RF testing at or near ports, airports, or other licensed-service facilities requires explicit coordination with facility operators and relevant regulators (FAA, USCG, local port authority).
- **PHI and dispatch data handling**: Decoded pager messages containing PHI or law enforcement dispatch data must be handled in compliance with HIPAA, CJIS, or equivalent regulations. Redact before including in reports.

### Countermeasures by Attack Vector

| Attack Vector | Countermeasure | Implementation Difficulty |
|---------------|----------------|--------------------------|
| ADS-B Spoofing | Cryptographic authentication (ADS-B Sec), multilateration verification | High (requires standards change) |
| AIS Spoofing / Dark Targets | Radar cross-reference, satellite AIS backup, behavior anomaly detection | Medium |
| Pager PHI Leakage | Encrypted paging, migration to secure mobile messaging | Medium |
| ACARS Interception | Migration to VDL Mode 3 (encrypted) or secured ACARS over VPN | High |
| ATC Voice Interception | Encrypted ATC voice (TETRA, P25 Phase II) -- currently not deployed | Very High (standards change) |
| DSC False Distress Alerts | Operator training, geolocation of false alert sources, regulatory enforcement | Medium |
| APRS OPSEC | Operator awareness, periodic position obfuscation for sensitive operations | Low |

---

## SDR Hardware Comparison (HF/VHF/UHF Focus)

| Platform | Frequency Range | Bandwidth | TX/RX | Sample Rate | Approx. Cost | Best For |
|----------|----------------|-----------|-------|-------------|--------------|----------|
| **RTL-SDR v3** | 24-1766 MHz (HF via Q-branch direct sampling) | 2.4 MHz | RX only | 2.4 MSPS | $30 | ADS-B, AIS, POCSAG, ACARS, ATC voice -- all receive-only licensed-band work |
| **AirSpy HF+ Discovery** | 9 kHz - 31 MHz (HF) and 60-260 MHz | 768 kHz (HF) | RX only | 768 kSPS (HF) | $170 | HF band: NDB, weather fax, HFDL, HF amateur, DSC on MF/HF |
| **AirSpy R2 / Mini** | 24-1800 MHz | 10 MHz | RX only | 10 MSPS | $170/$100 | Wideband VHF/UHF receive with high dynamic range |
| **HackRF One** | 1 MHz - 6000 MHz | 20 MHz | TX + RX (half-duplex) | 20 MSPS | $330 | Authorized TX testing, ADS-B/AIS replay research (Faraday cage only) |
| **BladeRF 2.0 micro a4** | 47 MHz - 6000 MHz | 56 MHz | TX + RX (full-duplex) | 61 MSPS | $480 | Full-duplex protocol emulation, VDL Mode 2 research, MIMO |
| **PlutoSDR (ADALM-PLUTO)** | 325-3800 MHz (default), 70-6000 MHz (mod) | 20 MHz | TX + RX | 20 MSPS | $200 | Learning platform, ADS-B/UAT band, custom decoders via GNU Radio |
| **SDRplay RSPdx** | 1 kHz - 2 GHz (with notch filters) | 10 MHz | RX only | 10 MSPS | $200 | Wideband HF/VHF receive, HF + VHF + UHF coverage from one device |

**Selection Guidelines**:

- **ADS-B / AIS / POCSAG reception**: RTL-SDR v3 is the workhorse -- $30 gets you a fully functional receiver. Add a 1090 MHz collinear or VHF marine antenna.
- **HF band (NDB, weather fax, HFDL, MF DSC)**: AirSpy HF+ Discovery is the best-in-class for HF dynamic range. RTL-SDR v3 in direct sampling mode is a budget alternative.
- **Wideband VHF/UHF with high dynamic range**: AirSpy R2 (10 MHz bandwidth) is preferred for environments with strong adjacent-channel signals.
- **Authorized TX research (Faraday cage)**: HackRF One for replay testing; BladeRF 2.0 micro for full-duplex protocol emulation.
- **Custom decoders**: PlutoSDR or HackRF with GNU Radio for flowgraph-based decoders when off-the-shelf tools don't support a protocol.

---

## Licensed Band Decoding Matrix

Quick reference for which tool decodes which licensed service. All tools are available on Kali Linux (most via `apt install` or by building from source).

| Licensed Service | Frequency | Modulation | Tool | Hardware (RX) |
|------------------|-----------|------------|------|---------------|
| ADS-B Mode S Long Squitter | 1090 MHz | PPM | dump1090-mutability, readsb | RTL-SDR + 1090 MHz antenna |
| UAT / ADS-B | 978 MHz | GFSK | dump978 | RTL-SDR + 978 MHz antenna |
| AIS Class A/B | 161.975 / 162.025 MHz | GMSK | AIS-catcher, rtl_ais | RTL-SDR + VHF marine antenna |
| ACARS | 131.550 MHz | AM MSK | ACARSDeco, acarsdec | RTL-SDR + VHF air antenna |
| VDL Mode 2 | 136.975 MHz | D8PSK | dumpvdl2 | RTL-SDR + VHF air antenna |
| HFDL | 2941, 5455, 8927, 11306, 15025, 17922 kHz | DPSK | dumphfdl | AirSpy HF+ Discovery |
| POCSAG | 138-174 MHz, 440-470 MHz, 929-932 MHz | FSK 512/1200/2400 bps | multimon-ng | RTL-SDR + band-appropriate antenna |
| FLEX | 929-932 MHz, 161-166 MHz | 1600/3200/6400 4-FSK | multimon-ng, flex-decoder | RTL-SDR + band-appropriate antenna |
| APRS | 144.39 MHz (US), 144.64 MHz (EU) | AFSK 1200 bps Bell 202 | multimon-ng, direwolf | RTL-SDR + 2m amateur antenna |
| NDB | 190-535 kHz, 1750 kHz | AM MCW | GQRX (CW/AM mode), GNURadio | AirSpy HF+ Discovery, RTL-SDR (HF mode) |
| Weather Fax | HF (various, e.g., 4.625, 8.074, 11.082 MHz) | FM subcarrier on AM | fldigi, multimon-ng, jvx | AirSpy HF+ Discovery |
| DSC VHF | 156.525 MHz (Ch 70) | GFSK | rtl-dsc, multimon-ng | RTL-SDR + VHF marine antenna |
| DSC MF/HF | 2187.5, 4207.5, 6312, 8414.5, 12577, 16804.5 kHz | GFSK | rtl-dsc, dscdecoder | AirSpy HF+ Discovery |
| ATC Voice | 118-137 MHz (25 kHz) / 118-136.975 (8.33 kHz EU) | AM | GQRX, SDR#, rtl_fm | RTL-SDR + VHF air antenna |
| Maritime VHF Voice | 156-174 MHz (Ch 16 = 156.8 MHz, Ch 13 = 156.65 MHz) | NBFM | GQRX, SDR#, rtl_fm | RTL-SDR + VHF marine antenna |
| Inmarsat STD-C | 1530-1545 MHz | TDMA 600 bps | Open Source Inmarsat decoder (research) | AirSpy R2, HackRF + L-band antenna |
| Iridium | 1616-1626.5 MHz | TDMA QPSK | iridium-toolkit | HackRF, AirSpy + L-band antenna |

---

## RF Attack Categories (Licensed Band Specific)

| Category | Objective | Example Technique | Typical Targets |
|----------|-----------|--------------------|-----------------|
| **Passive Receive** | Intelligence from licensed broadcasts | ADS-B tracking, AIS decode, pager intercept | Aircraft, vessels, pagers, ATC voice |
| **Anomaly Detection** | Identify spoofing or unexpected behavior | Ghost aircraft detection, dark vessel tracking | ADS-B, AIS |
| **Replay (Authorized)** | Re-transmit previously captured signals in Faraday cage | Pager message replay, ACARS frame replay | Pager networks, aircraft data link (research) |
| **Spoofing (Authorized)** | Inject counterfeit signals in shielded environment | Ghost ADS-B aircraft, fake AIS vessel | ADS-B receivers, AIS base stations (research) |
| **Jamming Research** | Document protocol resistance to denial-of-service | CW jamming, swept jamming against licensed receivers | All licensed services (research only) |
| **Protocol Reverse Engineering** | Reverse undocumented licensed protocols | Capture and analyze proprietary paging protocols | Pager fleets, custom telemetry |
| **Privacy Audit** | Quantify data exposure from licensed broadcasts | Hospital pager PHI audit, ACARS content analysis | Pager fleets, aircraft comms |
| **OPSEC Review** | Document client RF exposure from licensed services | "What can an attacker learn from a rooftop SDR?" | Aviation, maritime, healthcare facilities |
| **Threat Intelligence** | Monitor licensed services for adversary activity | Dark vessel tracking, military aircraft identification | Maritime, aviation, public safety |

---

## Legal and Ethical Framework

### ITU Region Licensing

Radio frequencies are allocated internationally by the International Telecommunication Union (ITU) and administered by national regulators. The three ITU regions are:

- **Region 1**: Europe, Africa, Middle East, Northern Asia (e.g., ETSI standards)
- **Region 2**: Americas (e.g., FCC rules)
- **Region 3**: Asia-Pacific (e.g., MIC Japan, ACMA Australia)

Most licensed services (aviation, maritime) have internationally harmonized frequencies because aircraft and vessels cross regions. Amateur radio allocations vary slightly by region.

### FCC Part Numbers (US, Region 2 reference)

| Part | Service | Relevance |
|------|---------|-----------|
| **Part 15** | Unlicensed ISM devices | `sdr-rf-attack` scope -- not this skill |
| **Part 80** | Maritime stations | AIS, maritime VHF voice, DSC |
| **Part 87** | Aviation stations | ADS-B, ACARS, VDL Mode 2, ATC voice, NDB |
| **Part 90** | Private land mobile (police, fire, EMS) | Public safety pagers (often on Part 90 frequencies) |
| **Part 97** | Amateur radio | APRS, amateur VHF/UHF voice and data |

Transmitting without a license under these parts is a violation of the Communications Act and can result in FCC enforcement actions (fines, equipment seizure) and criminal prosecution.

### Red-Team Rules of Engagement

For engagements that involve licensed band assessment:

1. **Receive-only is generally permitted**: Passive reception of unencrypted licensed broadcasts (ADS-B, AIS, ATC voice, ACARS, POCSAG) is legal in most jurisdictions. Document the legal basis in the engagement letter.
2. **Active transmission requires explicit authorization**: Any transmission on licensed bands requires either (a) the operator holding the appropriate license (FCC Part 80/87/97 in the US) or (b) explicit coordination with the licensee and conduct within a Faraday cage.
3. **No interference with safety services**: Aviation, maritime distress (DSC), and public safety communications are safety-of-life services. Active testing that risks interference is strictly prohibited.
4. **PHI and PII handling**: Decoded pager messages containing patient data, names, or addresses must be handled as PHI under HIPAA. Redact before including in reports.
5. **Coordination with facility operators**: For assessments at or near airports, ports, hospitals, or public safety facilities, coordinate with the facility operator before any RF testing.
6. **Incident reporting**: Any unintended interference with licensed services must be reported immediately to the FCC (in the US) and to the affected service operator.

### Jurisdiction-Specific Notes

- **United States**: FCC regulations govern radio transmissions. 47 USC 605 prohibits unauthorized interception and disclosure of radio communications. ECPA may apply to intercepted communications.
- **European Union**: ETSI standards and national telecommunications laws apply. GDPR applies to any personal data in decoded traffic.
- **United Kingdom**: Wireless Telegraphy Act 2006 prohibits unauthorized reception of certain transmissions. Ofcom enforces radio regulations.
- **Australia**: Radiocommunications Act 1992 governs radio operations. ACMA is the regulator.
- **International waters**: Maritime communications are governed by the ITU Radio Regulations and SOLAS (Safety of Life at Sea) convention. Vessels flagged to specific nations are subject to that nation's telecommunications law.

---

## Quick Reference: Lab Setup

A basic HF/VHF/UHF licensed band lab requires:

- **Hardware**: RTL-SDR v3 ($30), HackRF One ($330) for TX research, AirSpy HF+ Discovery ($170) for HF
- **Antennas**: 1090 MHz collinear (ADS-B), VHF marine (AIS, maritime VHF), VHF air band discone (ATC, ACARS), HF wire dipole or magnetic loop (NDB, weather fax, HFDL)
- **Software**: Kali Linux with `dump1090-mutability`, `AIS-catcher`, `multimon-ng`, `dumpvdl2`, `dumphfdl`, `acarsdeco`, `direwolf`, `gqrx`, `gnuradio`, `urh`
- **Reference data**: FAA aircraft registry (for ICAO 24-bit address lookup), ITU MMSI database, local pager frequency lists

See `guides/hf-vhf-radio-attack-playbook.md` for the full lab setup and engagement workflow.
