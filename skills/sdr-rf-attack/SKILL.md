---
name: sdr-rf-attack
description: "Software Defined Radio and RF signal attacks encompass a broad range of offensive techniques targeting wireless communication systems."
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: security
  tool_count: 7
  guide_count: 8
  mitre: "T1557-Adversary-in-the-Middle, T1040-Network Sniffing, T1200-Hardware Additions, T1095-Non-Application Layer Protocol"
  last_reviewed: "2026-07-26"
---


# Skill: SDR and RF Signal Attacks

> **Supplementary Files**:
> - `payloads.md` -- Complete payload collection organized by attack type (SDR setup, spectrum scanning, GSM/LTE analysis, RFID exploitation, keyfob replay, protocol reverse engineering, GNURadio development -- 11 major categories)
> - `test-cases.md` -- Structured test case templates (8 cases covering hardware setup, spectrum scanning, GSM interception, LTE analysis, RFID capture, keyfob replay, protocol reverse engineering, and GNURadio flowgraph development)
> - `guides/sdr-signal-capture-analysis-guide.md` -- SDR fundamentals: hardware setup, frequency scanning, signal capture, spectrum analysis, and waterfall visualization
> - `guides/gsm-lte-basestation-attack-guide.md` -- GSM/LTE attacks: gr-gsm configuration, network discovery, SMS/call capture, IMSI catcher concepts, and lawful interception methodology
> - `guides/rfid-rf-replay-attack-guide.md` -- RF replay attacks: RFID capture/replay, keyfob rolling code analysis, garage door testing, urh protocol analysis, and custom GNURadio replay
> - `guides/gps-spoofing-guide.md` -- GPS signal structure, spoofing attacks, detection methods, practical HackRF examples
> - `guides/zigbee-ble-sdr-guide.md` -- ZigBee and BLE SDR analysis, packet capture, replay attacks, key extraction, RF fingerprinting
> - `guides/rfid-nfc-deep-dive-guide.md` -- RFID/NFC protocol analysis, MIFARE Classic/DESfire attacks, NFC relay attacks, cloning countermeasures
> - `guides/sub-ghz-iot-attack-guide.md` -- Sub-GHz IoT protocols (433MHz/868MHz), weather station attacks, garage door replay, smart home device manipulation
> - `guides/satellite-signal-analysis-guide.md` -- Satellite signal capture, AIS ship tracking, ADS-B aircraft monitoring, NOAA weather satellite decoding

## Summary

Sdr Rf Attack skill domain covering security operations.

**Tools**: gnuradio, gr-gsm, hackrf, rtl-sdr, urh, gqrx, inspectrum

**Domain**: security

## Description

Software Defined Radio and RF signal attacks encompass a broad range of offensive techniques targeting wireless communication systems. This skill domain covers the complete attack lifecycle from hardware setup and spectrum reconnaissance through signal capture, protocol reverse engineering, and targeted exploitation of radio systems including GSM cellular networks, LTE/4G infrastructure, RFID/NFC devices, automotive keyfobs, garage door openers, and IoT protocols (Zigbee, LoRa).

**Core Attack Surfaces**:

- **SDR Hardware Exploitation**: HackRF One and RTL-SDR dongle configuration for wideband signal capture, frequency calibration, and sample rate optimization for various radio protocols.
- **Spectrum Reconnaissance**: Systematic scanning and monitoring of the RF spectrum to identify active transmissions, frequency allocations, and modulation characteristics of target systems.
- **Cellular Network Attacks**: GSM network discovery, base station identification, traffic interception using gr-gsm, SMS and call capture, LTE attach/detach procedure analysis, and IMSI catcher concepts.
- **RFID/NFC Radio-Layer Attacks**: Radio-frequency signal capture from 125 kHz LF RFID and 13.56 MHz HF RFID/NFC systems, protocol analysis at the physical layer, and replay attack execution.
- **Keyfob and Rolling Code Attacks**: Capture and analysis of automotive keyfob transmissions (typically 315 MHz / 433 MHz), rolling code implementation analysis, and replay attack vectors against fixed-code and vulnerable rolling-code systems.
- **Protocol Reverse Engineering**: Automated and manual reverse engineering of unknown radio protocols using Universal Radio Hacker (urh), signal demodulation, frame structure analysis, and bit-level decoding.
- **IoT Protocol Analysis**: Interception and analysis of Zigbee (2.4 GHz), LoRa (sub-GHz), and other IoT radio protocols to identify authentication weaknesses and data leakage.
- **GNURadio Custom Development**: Building custom signal processing flowgraphs for specialized attack scenarios including demodulation chains, protocol decoders, and replay transmitters.

**Related Skills**:
- `skills/bluetooth-rfid-nfc/SKILL.md` -- Complementary Bluetooth and RFID/NFC exploitation at the protocol layer (this skill focuses on the radio/physical layer)
- `skills/hardware-security/SKILL.md` -- Hardware attack vectors including glitching, bus sniffing, and JTAG/SWD exploitation
- `skills/wifi-pentest/SKILL.md` -- WiFi-specific attacks at 2.4/5 GHz (this skill covers non-WiFi RF)

---

## Use Cases

1. **Cellular Network Security Assessment**: Authorized GSM/LTE network penetration testing to evaluate interception resistance, test encryption implementation (A5/1, A5/3), and assess vulnerability to IMSI catcher attacks in controlled environments.
2. **RFID Access Control Testing**: Evaluate physical access control systems that rely on RFID badges by capturing and analyzing radio transmissions, testing for replay vulnerabilities, and verifying encryption implementation.
3. **Automotive Keyfob Security Audit**: Test vehicle entry systems for susceptibility to relay attacks, rolling code implementation flaws, and signal replay vulnerabilities under authorized engagement scope.
4. **IoT Wireless Protocol Assessment**: Analyze custom and standard IoT radio protocols (Zigbee, LoRa, proprietary sub-GHz) for authentication bypass, data exfiltration, and injection vulnerabilities.
5. **Spectrum Monitoring and Compliance**: Conduct authorized spectrum surveys to identify unauthorized transmissions, detect rogue devices, and verify RF emission compliance.
6. **Radio Protocol Reverse Engineering**: Reverse engineer proprietary or undocumented radio protocols to identify security weaknesses in industrial control systems, building automation, or custom wireless links.
7. **GNURadio Custom Tool Development**: Build specialized SDR tools for unique engagement requirements including custom demodulators, protocol-specific decoders, and automated replay systems.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **gnuradio** | Graphical signal processing flowgraph design and execution for custom SDR applications | `gnuradio-companion` -> Drag Osmocom Source -> Demod -> File Sink -> Execute |
| **gr-gsm** | GSM network interception, decode, and analysis using GNURadio blocks | `grgsm_scanner` -> `grgsm_capture` -> `grgsm_decode` for full GSM traffic analysis |
| **hackrf** | HackRF hardware control for wideband signal capture and transmission (1 MHz - 6 GHz) | `hackrf_transfer -r capture.raw -f 433920000 -s 8000000 -l 32 -g 20` |
| **rtl-sdr** | Low-cost SDR reception using RTL2832U dongles, spectrum power measurements | `rtl_power -f 433M:434M:1k -i 10 -e 60 power.csv` for spectrum survey |
| **urh** | Universal Radio Hacker for interactive protocol reverse engineering and replay | `urh` -> Load capture -> Auto-detect modulation -> Assign labels -> Replay |
| **gqrx** | Real-time spectrum visualization and signal monitoring with waterfall display | `gqrx` -> Set device -> Tune frequency -> Adjust FFT -> Record signal |
| **inspectrum** | Offline captured signal visualization with spectrogram and layer analysis | `inspectrum capture.raw -r 8000000 -f 433920000` for signal analysis |

---

## Methodology

### Phase 1: Reconnaissance -- Spectrum Survey

1. Identify target frequency band using gqrx for real-time monitoring
2. Perform wideband spectrum scan with rtl_power to map active frequencies
3. Record signal activity patterns and timing characteristics
4. Identify modulation type and bandwidth of target signals
5. Document frequency allocations and correlate with known services

### Phase 2: Signal Capture and Analysis

1. Configure SDR hardware for target frequency (center frequency, sample rate, gain)
2. Capture raw I/Q samples using hackrf_transfer or GNURadio flowgraph
3. Analyze captured signals in inspectrum for modulation and framing
4. Identify signal structure: preamble, sync word, payload, checksum

### Phase 3: Protocol Reverse Engineering

1. Load captured signals into urh for interactive analysis
2. Auto-detect modulation parameters (ASK, FSK, PSK, OOK)
3. Decode bitstream and identify protocol fields
4. Map field values to protocol functions (address, command, checksum)
5. Validate protocol understanding against multiple captures

### Phase 4: Exploitation

1. Craft targeted transmissions based on reverse-engineered protocol
2. Test replay attacks against fixed-code systems
3. Analyze rolling code implementation for weaknesses
4. Execute authorized exploitation within engagement scope

### Phase 5: Reporting

1. Document all findings with frequency and modulation details
2. Record proof-of-concept captures and replay demonstrations
3. Provide remediation recommendations for identified vulnerabilities
4. Include spectrum analysis evidence and timeline of activities

---

## Practical Steps

### Step 1: Hardware Setup and Verification

```bash
# Verify HackRF One is detected
hackrf_info

# Check RTL-SDR dongle
rtl_test -t

# Calibrate HackRF using GPSDO or known signal
hackrf_transfer -r /dev/null -f 100000000 -s 8000000 -l 32 -g 20
```

### Step 2: Spectrum Reconnaissance

```bash
# Wideband scan of sub-GHz ISM band (433 MHz region)
rtl_power -f 433000000:434000000:1000 -i 1 -e 60 ism_scan.csv

# Visualize spectrum data
python3 -c "
import numpy as np
data = np.loadtxt('ism_scan.csv', delimiter=',')
print(f'Frequencies scanned: {data.shape[0]}')
print(f'Max power: {data.max():.1f} dB')
print(f'Min power: {data.min():.1f} dB')
"

# Monitor specific frequency in real-time
rtl_fm -f 433920000 -s 200000 -r 48000 - | play -r 48000 -t s16 -L -c 1 -
```

### Step 3: Signal Capture

```bash
# Capture keyfob transmission at 433.92 MHz
hackrf_transfer -r keyfob_capture.raw -f 433920000 -s 8000000 -l 32 -g 20 -n 80000000

# Capture RFID reader transmission at 13.56 MHz
hackrf_transfer -r rfid_capture.raw -f 13560000 -s 8000000 -l 32 -g 20 -n 80000000

# Analyze captured signal with inspectrum
inspectrum keyfob_capture.raw -r 8000000
```

### Step 4: Protocol Analysis with urh

```bash
# Launch urh with captured signal
urh keyfob_capture.raw

# Or use urh CLI for automated analysis
urh_cli -p keyfob_capture.raw -mod auto -s 8000000
```

### Step 5: GSM Network Analysis

```bash
# Scan for GSM base stations
grgsm_scanner -b GSM900

# Capture GSM downlink
grgsm_capture -f 935000000 -s 8000000 -g 40 -c 80000000 gsm_capture.raw

# Decode captured GSM data
grgsm_decode -m MC -t gsm_capture.raw
```

---

### Defense Perspective

### Detection and Monitoring

- Deploy RF monitoring systems to detect unauthorized SDR transmissions in restricted areas
- Implement spectrum sensing to identify rogue base stations (IMSI catchers)
- Monitor for anomalous signal patterns indicating replay attacks on access control systems
- Use direction-finding equipment to locate unauthorized RF transmitters

### Hardening Recommendations

- Migrate RFID access control from legacy 125 kHz systems to encrypted 13.56 MHz (DESFire, SEOS)
- Implement AES-128 encryption on all sub-GHz IoT device communications
- Use rolling code algorithms with sufficient entropy (minimum 32-bit counters) for keyfobs
- Deploy frequency-hopping spread spectrum (FHSS) for critical radio links
- Implement mutual authentication between radio devices before data exchange

### Compliance Considerations

- All SDR transmissions require proper licensing or must operate within ISM band regulations
- GSM/LTE interception is illegal without explicit legal authorization or law enforcement warrant
- RFID system testing requires written authorization from the system owner
- Automotive security testing requires explicit vehicle owner consent and manufacturer authorization
- Spectrum monitoring for compliance purposes must follow local telecommunications regulations

### Countermeasures by Attack Type

| Attack Vector | Countermeasure | Implementation Difficulty |
|---------------|----------------|--------------------------|
| RFID Replay | Encrypted challenge-response (DESFire EV2/EV3) | Medium |
| Keyfob Replay | Rolling codes with 40+ bit counters, Time-based authentication | High |
| GSM Interception | A5/4 encryption, network-level IMSI catcher detection | Very High |
| IoT Protocol Sniffing | AES-128 link-layer encryption, frequency hopping | Medium |
| Signal Jamming | Spread spectrum, adaptive frequency agility | High |
| IMSI Catcher | Network-based detection, mutual authentication (EAP-AKA) | Very High |

## SDR Hardware Comparison

Understanding the capabilities and limitations of different SDR hardware platforms is essential for selecting the right tool for each assessment scenario. The following comparison covers the most commonly used platforms in security testing.

| Platform | Frequency Range | Bandwidth | TX/RX | Sample Rate | Approx. Cost | Best For |
|----------|----------------|-----------|-------|-------------|--------------|----------|
| **RTL-SDR v3** | 24-1766 MHz | 2.4 MHz | RX only | 2.4 MSPS | $30 | Receive-only tasks: spectrum monitoring, ADS-B, AIS, NOAA, GSM downlink |
| **HackRF One** | 1-6000 MHz | 20 MHz | TX + RX | 20 MSPS | $330 | Wideband TX/RX: replay attacks, signal generation, protocol testing |
| **BladeRF 2.0 micro** | 47-6000 MHz | 56 MHz | TX + RX | 61 MSPS | $480 | Full-duplex GSM/LTE testing, MIMO applications |
| **USRP B210** | 70-6000 MHz | 56 MHz | TX + RX | 61 MSPS | $1200 | Professional-grade research, wideband MIMO, high-fidelity capture |
| **LimeSDR** | 100 kHz-3.8 GHz | 30 MHz | TX + RX | 30 MSPS | $300 | Cost-effective full-duplex, GSM base station emulation |
| **PlutoSDR** | 325-3800 MHz | 20 MHz | TX + RX | 20 MSPS | $200 | Learning platform, WiFi/Bluetooth band testing |
| **YardStick One** | 281-960 MHz | Limited | TX + RX | Limited | $100 | Sub-GHz IoT testing, Keyfob cloning, specific protocol testing |

**Selection Guidelines**:

- **Spectrum monitoring / passive analysis**: RTL-SDR is sufficient and cost-effective for all receive-only tasks.
- **Signal replay / active testing**: HackRF One provides the best balance of cost and capability for most active testing scenarios.
- **Cellular network testing**: BladeRF or USRP with appropriate front-end filters for GSM/LTE base station emulation.
- **Sub-GHz IoT testing**: YardStick One or HackRF with appropriate antennas for 315/433/868 MHz bands.
- **Professional engagements**: USRP B210 for highest fidelity and reliability in production testing.

## Signal Identification Workflow

Efficiently identifying unknown signals is a core skill for SDR security assessment. This workflow provides a systematic approach to signal identification, from initial discovery through protocol classification.

### Step 1: Wideband Spectrum Survey

Use `rtl_power` or `hackrf_sweep` to identify active frequencies across the target band. Look for power peaks above the noise floor and note their frequencies, bandwidths, and duty cycles.

### Step 2: Signal Capture

Tune to identified frequencies and capture raw I/Q samples at sufficient sample rate (at least 2x the signal bandwidth, preferably 4-8x). Use `hackrf_transfer` or `rtl_sdr` for capture.

### Step 3: Visual Analysis

Open captured signals in `inspectrum` to identify modulation type visually. OOK appears as discrete amplitude levels, FSK shows frequency displacement, and PSK shows constant envelope with phase changes.

### Step 4: Automated Modulation Detection

Use URH (Universal Radio Hacker) to auto-detect modulation parameters. URH can identify OOK, ASK, FSK, PSK, and QAM modulations along with symbol rate and center frequency offset.

### Step 5: Protocol Decoding

Once modulation is identified, decode the bitstream and look for protocol structures: preambles, sync words, headers, payloads, and checksums. Cross-reference with known protocol databases (Flipper Zero Sub-GHz database, SigIDWiki).

### Step 6: Protocol Fingerprinting

Match captured signal characteristics against known protocol signatures including frequency, modulation, baud rate, preamble pattern, and frame structure.

## RF Attack Categories

SDR-based attacks can be categorized by their objective and technique. Understanding these categories helps assessment planning and scope definition.

| Category | Objective | Example Techniques | Typical Targets |
|----------|-----------|--------------------|-----------------|
| **Reconnaissance** | Gather intelligence from RF emissions | Spectrum scanning, signal intercept, protocol decode | All wireless systems |
| **Eavesdropping** | Capture and decode private communications | GSM interception, WiFi sniffing, RFID reading | Cellular, WiFi, RFID, IoT |
| **Replay** | Re-transmit previously captured signals | Keyfob replay, garage door replay, IoT command replay | Fixed-code systems, IoT devices |
| **Spoofing** | Transmit counterfeit signals to deceive receivers | GPS spoofing, ADS-B injection, AIS ghost vessels | Navigation, tracking systems |
| **Jamming** | Deny service by overwhelming the receiver | CW jamming, swept jamming, protocol-aware jamming | All wireless systems |
| **Relay** | Forward signals between two parties in real-time | NFC relay, keyfob relay, Bluetooth relay | Access control, automotive |
| **Cryptanalysis** | Break encryption protecting RF communications | KEEX attack, KeeLoq cryptanalysis, CRYPTO1 recovery | Encrypted RF protocols |
| **Protocol Exploitation** | Exploit protocol-level vulnerabilities | Authentication bypass, command injection, firmware update hijack | IoT devices, industrial systems |
| **Side-Channel** | Extract secrets from RF emanations | TEMPEST, EM emanation analysis, power analysis | Computing equipment, HSMs |
| **Supply Chain** | Compromise devices through RF components | Malicious SDR firmware, backdoor radio channels | Critical infrastructure |

## Counter-Surveillance

Counter-surveillance with SDR involves detecting, locating, and neutralizing unauthorized radio surveillance devices. This defensive application of SDR technology is relevant to physical security assessments and TSCM (Technical Surveillance Countermeasures) operations.

### Detection Techniques

1. **Spectrum monitoring**: Continuously scan for unauthorized transmissions across all accessible frequency bands. Look for signals that appear during sensitive activities or meetings.
2. **Non-linear junction detection (NLJD)**: Detect semiconductor junctions in electronic devices by illuminating them with RF energy and detecting harmonic reflections.
3. **Correlation analysis**: Compare signal timing with known activities to identify surveillance devices that activate in response to movement or conversation.
4. **Thermal imaging**: Complement RF detection with thermal imaging to locate devices based on heat signatures.
5. **RF direction finding**: Use multiple SDR receivers or a rotating directional antenna to triangulate the source of suspicious transmissions.

### Common Surveillance Device Signatures

| Device Type | Frequency | Modulation | Detection Method |
|-------------|-----------|------------|------------------|
| Audio bug (analog) | 300-900 MHz | FM/NFM | Wideband FM scan with audio demodulation |
| Audio bug (digital) | 2.4 GHz | GFSK/OFDM | WiFi band monitoring, protocol analysis |
| GPS tracker | 1575.42 MHz (receive) | N/A | Detect GSM/cellular uplink for data exfil |
| Camera (wireless) | 2.4/5.8 GHz | OFDM | WiFi scanner, video signal detection |
| Cellular interceptor | 900/1800/2100 MHz | GSM/LTE | IMSI catcher detection apps, SDR analysis |

## SDR Legal Considerations

Operating SDR equipment for security assessment requires awareness of applicable laws and regulations. The legal framework varies significantly by jurisdiction, but the following principles are broadly applicable.

### Transmission Regulations

- **Licensed bands only with authorization**: Transmitting on licensed frequencies (cellular, aviation, maritime, broadcast) requires explicit authorization. Violations can result in criminal prosecution.
- **ISM band restrictions**: Unlicensed transmission is generally permitted in ISM bands (433 MHz, 868 MHz, 2.4 GHz) subject to power limits (typically 10-100 mW EIRP depending on jurisdiction).
- **Intentional interference prohibited**: Jamming or interfering with any licensed radio service is illegal in virtually all jurisdictions regardless of intent.

### Interception Laws

- **Own equipment only**: Testing RFID tags, keyfobs, and IoT devices you own is generally legal. Intercepting others' communications may violate wiretapping laws.
- **Cellular interception**: Intercepting cellular communications (GSM, LTE, 5G) without authorization is illegal in most countries, even for research purposes.
- **AIS and ADS-B**: Receiving AIS and ADS-B signals is legal in most jurisdictions as these are unencrypted public safety broadcasts. Transmitting false data is illegal.

### Authorization Requirements

- **Written authorization required**: All security testing of systems you do not own requires written authorization from the system owner.
- **Scope definition**: Authorization must clearly define which frequencies, devices, and techniques are permitted.
- **Incident reporting**: Any unintended interference with legitimate services must be reported immediately to relevant authorities.

### Jurisdiction-Specific Notes

- **United States**: FCC regulations govern radio transmissions. FCC Part 15 covers unlicensed devices. CALEA prohibits unauthorized cellular interception.
- **European Union**: ETSI standards and national telecommunications laws apply. GDPR may apply to intercepted personal data.
- **United Kingdom**: Wireless Telegraphy Act and Computer Misuse Act govern SDR operations. RIPA covers interception.
- **Australia**: Radiocommunications Act and Telecommunications (Interception and Access) Act apply.
## Detection Methods

### RF Spectrum Monitoring
- **Unauthorized transmissions**: Transmit on licensed frequencies without authorization.
- **ADS-B anomalies** (1090 MHz): Aircraft position reports with impossible geometry.
- **POCSAG pager anomalies**: Pager messages with malformed capcodes.
- **AIS anomalies** (marine VHF): Ship position reports with impossible speed.

### SIEM Detection Rules
- **Splunk SPL (RF)**: `index=rf | where freq_band="1090MHz" AND speed > 1500`
- **SDR monitoring**: Continuous spectrum recording; alert on reserved-band transmissions.

## Defense Evasion Techniques

### Transmission Stealth
- **Low power**: Use minimum TX power; reduces detection range.
- **Brief transmissions**: <5 second bursts; below triangulation threshold.
- **Frequency hopping**: Spread across many channels; per-channel threshold not exceeded.
- **Directional antennas**: Limit RF footprint to target only.

### ADS-B Spoofing Stealth
- **Match legitimate aircraft**: Use real Mode S address; mimic flight profile.
- **Gradual drift**: Slowly drift spoofed position; avoids sudden jump detection.

