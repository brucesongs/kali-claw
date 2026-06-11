---
name: sdr-rf-attack
description: "Software Defined Radio and RF signal attacks encompass a broad range of offensive techniques targeting wireless communication systems."
origin: openclaw
version: "0.1.21"
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
  guide_count: 5
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

## Defense Perspective

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
