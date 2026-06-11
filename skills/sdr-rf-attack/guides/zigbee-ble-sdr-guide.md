# ZigBee and BLE SDR Analysis Guide

## Introduction

ZigBee and Bluetooth Low Energy (BLE) are two of the most widely deployed low-power wireless protocols in IoT, smart home, industrial sensing, and healthcare applications. Both operate in the 2.4 GHz ISM band but use fundamentally different physical layer implementations. ZigBee (based on IEEE 802.15.4) uses direct-sequence spread spectrum (DSSS) with O-QPSK modulation, while BLE uses frequency-hopping spread spectrum (FHSS) with GFSK modulation.

SDR-based analysis of these protocols enables security assessment that goes beyond standard protocol-level testing. By examining the radio physical layer, we can detect implementation flaws in hardware, analyze key exchange procedures at the signal level, identify unauthorized devices through RF fingerprinting, and test for vulnerabilities in the protocol's physical layer design.

This guide covers SDR-based analysis techniques for both ZigBee and BLE, including packet capture, protocol analysis, replay attacks, key extraction methods, and RF fingerprinting for device identification.

**Objectives**: Capture and analyze ZigBee and BLE signals using SDR, perform protocol-level security testing, execute replay attacks, extract encryption keys through side-channel analysis, and develop RF fingerprinting for device identification.

## Part 1: ZigBee Protocol Analysis

### ZigBee Physical Layer

ZigBee operates on IEEE 802.15.4 at 2.4 GHz with 16 channels (11-26), each 5 MHz wide. The center frequencies range from 2405 MHz (channel 11) to 2480 MHz (channel 26).

| Parameter | Value |
|-----------|-------|
| Frequency | 2400-2483.5 MHz (2.4 GHz ISM) |
| Channels | 11-26 (16 channels, 5 MHz spacing) |
| Modulation | O-QPSK (Offset Quadrature Phase Shift Keying) |
| Chip rate | 2 Mchip/s |
| Data rate | 250 kbps |
| Spreading | DSSS with 32-chip PN codes |
| Channel bandwidth | 2 MHz |

### ZigBee Packet Capture with SDR

```bash
# Capture ZigBee traffic on channel 15 (2425 MHz)
# Using HackRF with appropriate sample rate
hackrf_transfer -r zigbee_ch15.raw -f 2425000000 -s 4000000 \
  -l 32 -g 30 -n 40000000

# Using RTL-SDR for monitoring
rtl_sdr -f 2425000000 -s 4000000 -g 30 -n 40000000 zigbee_ch15_rtl.raw

# Scan all ZigBee channels for active networks
for ch in $(seq 11 26); do
  freq=$((2405 + ($ch - 11) * 5))
  echo "Scanning channel $ch (${freq} MHz)..."
  timeout 5 rtl_power -f ${freq}M -i 1 -e 3 -b 2000000 zigbee_ch${ch}.csv 2>/dev/null
  # Check for signal activity
  if awk -F, '$6 > -60 {found=1} END {exit !found}' zigbee_ch${ch}.csv 2>/dev/null; then
    echo "  Activity detected on channel $ch!"
  fi
done
```

### ZigBee Frame Structure Analysis

```python
#!/usr/bin/env python3
"""ZigBee/IEEE 802.15.4 frame parser for SDR-captured data."""

import numpy as np
import struct

# IEEE 802.15.4 symbol-to-chip mapping (DSSS)
CHIP_SEQUENCE = {
    0:  [1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1],
    1:  [1,1,0,0,0,1,0,1,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,1,0,1,1,0,0,1],
    2:  [0,1,0,1,0,0,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,1,0,0,0,1,1,1,0,1,0,1],
    3:  [0,0,1,1,0,1,0,1,0,0,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,0,1,0,0,1,1,1],
    4:  [1,0,0,1,1,0,1,1,0,1,0,1,1,0,0,0,1,0,0,1,1,0,1,1,0,1,0,1,1,0,0,0],
    5:  [1,0,1,1,0,0,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,1,0,0,1],
    6:  [0,1,1,0,1,0,1,1,1,0,0,1,0,0,1,1,0,1,1,0,1,0,1,1,1,0,0,1,0,0,1,1],
    7:  [0,0,0,1,1,1,0,1,0,0,1,1,1,1,0,0,0,0,1,1,1,0,1,0,0,1,1,1,1,0,0,0],
    8:  [0,0,1,0,0,1,1,1,1,0,0,1,0,1,1,0,0,0,1,0,0,1,1,1,1,0,0,1,0,1,1,0],
    9:  [0,1,1,1,1,0,0,1,0,1,1,0,0,0,1,0,0,1,1,1,1,0,0,1,0,1,1,0,0,0,1,0],
    10: [1,1,0,1,0,1,1,0,0,1,1,0,1,1,1,0,1,1,0,1,0,1,1,0,0,1,1,0,1,1,1,0],
    11: [1,0,1,0,0,1,1,0,1,1,1,0,0,1,0,1,1,0,1,0,0,1,1,0,1,1,1,0,0,1,0,1],
    12: [1,1,0,0,1,0,0,1,0,1,0,1,1,1,1,0,1,1,0,0,1,0,0,1,0,1,0,1,1,1,1,0],
    13: [0,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0,0,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0],
    14: [0,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1],
    15: [1,0,0,0,1,1,1,1,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,1,0,0,1,1,1,0,1,0],
}

def parse_ieee802154_frame(raw_bytes):
    """Parse IEEE 802.15.4 MAC frame from raw bytes."""
    if len(raw_bytes) < 2:
        return None

    # Frame Control Field (2 bytes, little-endian)
    fcf = struct.unpack('<H', raw_bytes[0:2])[0]

    frame = {
        'frame_type': fcf & 0x07,
        'security_enabled': bool(fcf & 0x08),
        'frame_pending': bool(fcf & 0x10),
        'ack_request': bool(fcf & 0x20),
        'pan_id_compression': bool(fcf & 0x40),
        'dest_addr_mode': (fcf >> 10) & 0x03,
        'src_addr_mode': (fcf >> 14) & 0x03,
    }

    frame_types = {0: 'Beacon', 1: 'Data', 2: 'ACK', 3: 'MAC Command'}
    frame['frame_type_name'] = frame_types.get(frame['frame_type'], 'Reserved')

    # Sequence number
    frame['seq_number'] = raw_bytes[2]

    # Address fields
    offset = 3
    if frame['dest_addr_mode'] > 0:
        frame['dest_pan_id'] = struct.unpack('<H', raw_bytes[offset:offset+2])[0]
        offset += 2
        if frame['dest_addr_mode'] == 2:  # Short address
            frame['dest_addr'] = struct.unpack('<H', raw_bytes[offset:offset+2])[0]
            offset += 2
        elif frame['dest_addr_mode'] == 3:  # Extended address
            frame['dest_addr'] = raw_bytes[offset:offset+8].hex()
            offset += 8

    if frame['src_addr_mode'] > 0:
        if not frame['pan_id_compression']:
            frame['src_pan_id'] = struct.unpack('<H', raw_bytes[offset:offset+2])[0]
            offset += 2
        if frame['src_addr_mode'] == 2:
            frame['src_addr'] = struct.unpack('<H', raw_bytes[offset:offset+2])[0]
            offset += 2
        elif frame['src_addr_mode'] == 3:
            frame['src_addr'] = raw_bytes[offset:offset+8].hex()
            offset += 8

    frame['payload_offset'] = offset
    frame['security'] = 'ENABLED' if frame['security_enabled'] else 'DISABLED'

    return frame

# Example frame parsing
print('IEEE 802.15.4 / ZigBee Frame Parser')
print('=' * 50)
print('Parses MAC layer frames from captured data')
print('Supports: Data, Beacon, ACK, MAC Command frames')
```

### ZigBee Security Analysis

ZigBee uses AES-128 encryption with a network key shared among all devices. Key distribution is the primary security weakness.

```python
#!/usr/bin/env python3
"""ZigBee security analysis framework."""

class ZigBeeSecurityAnalyzer:
    """Analyze ZigBee security properties and identify weaknesses."""

    def __init__(self):
        self.captures = []
        self.findings = []

    def analyze_key_exchange(self, frames):
        """Analyze ZigBee key exchange procedure for vulnerabilities."""
        for frame in frames:
            # Check for key transport in plaintext (during joining)
            if frame.get('frame_type') == 1:  # Data frame
                payload = frame.get('payload', b'')
                # APS layer command: Key transport (0x05)
                if len(payload) > 2 and payload[1] == 0x05:
                    if not frame.get('security_enabled'):
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'type': 'Unencrypted Key Transport',
                            'details': 'Network key transported without encryption '
                                      'during device joining procedure'
                        })

    def check_default_key(self, network_key):
        """Check if the network key is a known default."""
        default_keys = {
            '00000000000000000000000000000000': 'ZigBee Alliance default (all zeros)',
            '01030507091102131305070911021313': 'Common test key',
            '01030507091102131300040608010002': 'Phillips Hue default',
            'ZigBeeAlliance09': 'ZigBee Alliance 2006 specification default',
            '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00': 'Example default key',
        }

        key_hex = network_key.hex() if isinstance(network_key, bytes) else network_key
        if key_hex in default_keys:
            self.findings.append({
                'severity': 'CRITICAL',
                'type': 'Default Network Key',
                'details': f'Network key matches default: {default_keys[key_hex]}'
            })

        return key_hex in default_keys

    def analyze_replay_vulnerability(self, frames):
        """Check for frame counter reuse (replay vulnerability)."""
        frame_counters = {}
        for frame in frames:
            src = frame.get('src_addr')
            seq = frame.get('seq_number')
            key = f'{src}'

            if key not in frame_counters:
                frame_counters[key] = []

            frame_counters[key].append(seq)

        # Check for counter reset or reuse
        for src, counters in frame_counters.items():
            if len(counters) > 10:
                # Check if counter went backwards
                for i in range(1, len(counters)):
                    if counters[i] < counters[i-1]:
                        self.findings.append({
                            'severity': 'HIGH',
                            'type': 'Frame Counter Reset',
                            'details': f'Device {src} frame counter went from '
                                      f'{counters[i-1]} to {counters[i]} '
                                      f'(possible replay or device reset)'
                        })

    def generate_report(self):
        """Generate security analysis report."""
        print('ZigBee Security Analysis Report')
        print('=' * 60)

        if not self.findings:
            print('No security issues identified.')
            return

        for finding in sorted(self.findings, key=lambda x: x['severity']):
            print(f'[{finding["severity"]}] {finding["type"]}')
            print(f'  {finding["details"]}')
            print()

# Known ZigBee attack vectors
print('ZigBee Attack Vector Summary')
print('=' * 50)
attacks = [
    ('Key Sniffing', 'Capture network key during device joining (plaintext key transport)'),
    ('Replay Attack', 'Replay previously captured valid frames (counter reset)'),
    ('Default Key', 'Use manufacturer default network key for decryption'),
    ('Touchlink Commissioning', 'Exploit touchlink proximity pairing to take over network'),
    ('EmberZNet Debug', 'Access EmberZNet debug commands for key extraction'),
    ('OTA Firmware', 'Intercept and modify over-the-air firmware updates'),
    ('Trust Center Spoof', 'Impersonate trust center to distribute new keys'),
]
for name, desc in attacks:
    print(f'  {name}: {desc}')
```

### ZigBee Replay Attack

```python
#!/usr/bin/env python3
"""ZigBee frame capture and replay framework for authorized testing."""

import struct

def build_zigbee_data_frame(src_pan, src_addr, dst_pan, dst_addr, payload, seq=0):
    """Construct a ZigBee data frame for replay testing."""
    # Frame Control: Data frame, no security, PAN ID compression
    # Type=001 (Data), Security=0, Frame Pending=0, AR=0, PanIDCompress=1
    # Dest Mode=10 (Short), Src Mode=10 (Short)
    fcf = 0x8801  # Data frame, PAN compression, short addresses

    frame = bytearray()
    # Frame Control (little-endian)
    frame += struct.pack('<H', fcf)
    # Sequence number
    frame += struct.pack('B', seq)
    # Destination PAN ID
    frame += struct.pack('<H', dst_pan)
    # Destination address (short)
    frame += struct.pack('<H', dst_addr)
    # Source PAN ID (compressed, same as dest)
    # Source address (short)
    frame += struct.pack('<H', src_addr)
    # Payload
    frame += payload
    # FCS (Frame Check Sequence) - 2 bytes, would be calculated for real transmission
    # For SDR replay, the FCS from the original frame is used

    return bytes(frame)

def replay_zigbee_frame(captured_frame_bytes, target_channel=15):
    """Prepare captured ZigBee frame for replay via SDR.

    Note: This is a framework for authorized lab testing only.
    Actual replay requires IEEE 802.15.4 compatible SDR or
    appropriate modulation of the frame data.
    """
    # Parse the captured frame to extract metadata
    if len(captured_frame_bytes) >= 9:
        fcf = struct.unpack('<H', captured_frame_bytes[0:2])[0]
        seq = captured_frame_bytes[2]

        frame_type = fcf & 0x07
        security = bool(fcf & 0x08)
        frame_types = {0: 'Beacon', 1: 'Data', 2: 'ACK', 3: 'MAC Command'}

        print(f'Frame Analysis for Replay:')
        print(f'  Type: {frame_types.get(frame_type, "Unknown")}')
        print(f'  Sequence: {seq}')
        print(f'  Security: {"Enabled (may fail replay)" if security else "Disabled (replay viable)"}')
        print(f'  Length: {len(captured_frame_bytes)} bytes')
        print(f'  Target channel: {target_channel} ({2405 + (target_channel-11)*5} MHz)')
        print()

        if security:
            print('WARNING: Frame has encryption. Replay will only work if the')
            print('receiver accepts the frame counter value (no replay protection).')
            print('Modern ZigBee stacks implement replay protection via frame counters.')

    return captured_frame_bytes

print('ZigBee Replay Framework')
print('=' * 50)
print('Replay feasibility depends on:')
print('  1. Encryption status (unencrypted frames are trivially replayable)')
print('  2. Frame counter protection (replayed counter must be >= expected)')
print('  3. Sequence number handling (some stacks reject duplicate seq numbers)')
```

## Part 2: Bluetooth Low Energy (BLE) SDR Analysis

### BLE Physical Layer

BLE operates in the 2.4 GHz ISM band using frequency hopping across 40 channels (37 data channels + 3 advertising channels).

| Parameter | Value |
|-----------|-------|
| Frequency | 2402-2480 MHz |
| Channels | 37 data + 3 advertising (40 total) |
| Channel spacing | 2 MHz |
| Modulation | GFSK (BT=0.5) |
| Data rate | 1 Mbps (BLE 4.x), 2 Mbps (BLE 5.0) |
| Advertising channels | 37 (2402 MHz), 38 (2426 MHz), 39 (2480 MHz) |
| Transmit power | -20 to +20 dBm (typically 0 dBm) |

### BLE Advertising Capture

```bash
# Capture BLE advertising on channel 37 (2402 MHz)
hackrf_transfer -r ble_adv_37.raw -f 2402000000 -s 4000000 \
  -l 32 -g 30 -n 40000000

# Capture BLE advertising on channel 38 (2426 MHz)
hackrf_transfer -r ble_adv_38.raw -f 2426000000 -s 4000000 \
  -l 32 -g 30 -n 40000000

# Capture BLE advertising on channel 39 (2480 MHz)
hackrf_transfer -r ble_adv_39.raw -f 2480000000 -s 4000000 \
  -l 32 -g 30 -n 40000000

# Use rtl_433 for automated BLE decoding
rtl_433 -f 2426M -s 4M -M level
```

### BLE Frame Structure Analysis

```python
#!/usr/bin/env python3
"""BLE frame parser for SDR-captured data."""

import struct
from collections import Counter

def parse_ble_advertising_pdu(raw_bytes):
    """Parse BLE advertising PDU from raw bytes."""
    if len(raw_bytes) < 2:
        return None

    # PDU Header (2 bytes)
    pdu_header = struct.unpack('<H', raw_bytes[0:2])[0]

    pdu = {
        'pdu_type': pdu_header & 0x0F,
        'ch_sel': bool(pdu_header & 0x20),
        'tx_add': bool(pdu_header & 0x40),  # Random address
        'rx_add': bool(pdu_header & 0x80),
        'length': (pdu_header >> 8) & 0xFF,
    }

    pdu_types = {
        0: 'ADV_IND',        # Connectable undirected
        1: 'ADV_DIRECT_IND', # Connectable directed
        2: 'ADV_NONCONN_IND',# Non-connectable
        3: 'SCAN_REQ',       # Scan request
        4: 'SCAN_RSP',       # Scan response
        5: 'CONNECT_IND',    # Connection request
        6: 'ADV_EXT_IND',    # Extended advertising
    }
    pdu['type_name'] = pdu_types.get(pdu['pdu_type'], 'Reserved')

    # Parse advertising address (6 bytes)
    if pdu['length'] >= 6:
        adv_addr = raw_bytes[2:8]
        pdu['adv_addr'] = ':'.join(f'{b:02x}' for b in reversed(adv_addr))

    # Parse advertising data (for ADV_IND and ADV_NONCONN_IND)
    if pdu['pdu_type'] in [0, 2, 4] and pdu['length'] > 6:
        ad_data = raw_bytes[8:8+pdu['length']-6]
        pdu['ad_structures'] = parse_ad_structures(ad_data)

    return pdu

def parse_ad_structures(data):
    """Parse BLE advertising data structures."""
    structures = []
    offset = 0

    while offset < len(data):
        if offset + 1 >= len(data):
            break

        length = data[offset]
        if length == 0 or offset + 1 + length > len(data):
            break

        ad_type = data[offset + 1]
        ad_value = data[offset + 2:offset + 1 + length]

        ad_types = {
            0x01: 'Flags',
            0x02: 'Incomplete 16-bit UUIDs',
            0x03: 'Complete 16-bit UUIDs',
            0x07: 'Complete 128-bit UUIDs',
            0x08: 'Shortened Local Name',
            0x09: 'Complete Local Name',
            0x0A: 'TX Power Level',
            0x0D: 'Class of Device',
            0x0F: 'Appearance',
            0x16: 'Service Data (16-bit UUID)',
            0xFF: 'Manufacturer Specific Data',
        }

        structures.append({
            'type': ad_type,
            'type_name': ad_types.get(ad_type, f'Unknown (0x{ad_type:02x})'),
            'length': length,
            'value': ad_value.hex() if ad_value else '',
        })

        offset += 1 + length

    return structures

def analyze_ble_capture(pdu_list):
    """Analyze captured BLE advertising PDUs."""
    print('BLE Advertising Analysis')
    print('=' * 60)

    # Device count
    devices = set()
    type_counts = Counter()
    all_structures = []

    for pdu in pdu_list:
        if pdu is None:
            continue
        if 'adv_addr' in pdu:
            devices.add(pdu['adv_addr'])
        type_counts[pdu.get('type_name', 'Unknown')] += 1
        if 'ad_structures' in pdu:
            all_structures.extend(pdu['ad_structures'])

    print(f'Unique devices discovered: {len(devices)}')
    for addr in sorted(devices):
        print(f'  {addr}')

    print(f'\nPDU type distribution:')
    for pdu_type, count in type_counts.most_common():
        print(f'  {pdu_type}: {count}')

    # Check for information disclosure in advertising data
    print(f'\nAdvertising data analysis:')
    for struct in all_structures:
        if struct['type_name'] in ['Complete Local Name', 'Shortened Local Name']:
            name = bytes.fromhex(struct['value']).decode('ascii', errors='replace')
            print(f'  Device name: {name}')
        elif struct['type_name'] == 'TX Power Level':
            tx_power = int(bytes.fromhex(struct['value']), 0)
            if tx_power > 10:
                print(f'  [INFO] High TX power: {tx_power} dBm')
        elif struct['type_name'] == 'Manufacturer Specific Data':
            if len(struct['value']) >= 4:
                company_id = int.from_bytes(bytes.fromhex(struct['value'][:4]),
                                           byteorder='little')
                print(f'  Manufacturer ID: 0x{company_id:04x}')

print('BLE Advertising Parser')
print('Ready to decode BLE PDU structures')
```

### BLE Security Assessment

```python
#!/usr/bin/env python3
"""BLE security assessment framework."""

class BLESecurityAnalyzer:
    """Assess BLE device security through advertising and connection analysis."""

    def __init__(self):
        self.findings = []

    def check_advertising_security(self, pdu):
        """Check advertising PDU for security indicators."""
        if pdu is None:
            return

        # Check for connectable devices with no authentication requirement
        if pdu.get('type_name') == 'ADV_IND':
            # This device accepts connections from any device
            self.findings.append({
                'severity': 'INFO',
                'type': 'Connectable Device',
                'details': f'Device {pdu.get("adv_addr", "unknown")} '
                          f'accepts connections from any device'
            })

        # Check advertising data for sensitive information
        if 'ad_structures' in pdu:
            for struct in pdu['ad_structures']:
                # Service data may contain unencrypted sensor readings
                if struct['type_name'] == 'Service Data (16-bit UUID)':
                    self.findings.append({
                        'severity': 'LOW',
                        'type': 'Service Data in Advertising',
                        'details': f'Service data broadcast: {struct["value"]}'
                    })

                # Check for complete device names that reveal device type
                if struct['type_name'] in ['Complete Local Name', 'Shortened Local Name']:
                    name = bytes.fromhex(struct['value']).decode('ascii', errors='replace')
                    # Flag medical devices
                    medical_keywords = ['pulse', 'heart', 'blood', 'glucose', 'medical',
                                      'health', 'bp-', 'spo2', 'ecg', 'insulin']
                    for keyword in medical_keywords:
                        if keyword in name.lower():
                            self.findings.append({
                                'severity': 'MEDIUM',
                                'type': 'Medical Device Advertising',
                                'details': f'Device name "{name}" suggests medical device '
                                          f'(keyword: {keyword})'
                            })
                            break

    def check_pairing_security(self, pairing_data):
        """Assess BLE pairing security configuration."""
        # BLE pairing methods
        methods = {
            'Just Works': 'No authentication, vulnerable to MITM',
            'Passkey Entry': '6-digit PIN, vulnerable to brute force',
            'Numeric Comparison': 'Secure (BLE 4.2+ with LE Secure Connections)',
            'OOB (Out of Band)': 'Most secure, uses external channel',
        }

        if pairing_data.get('method') == 'Just Works':
            self.findings.append({
                'severity': 'HIGH',
                'type': 'Insecure Pairing Method',
                'details': 'Device uses "Just Works" pairing with no authentication. '
                          'Vulnerable to man-in-the-middle attacks during pairing.'
            })

        if not pairing_data.get('le_secure_connections'):
            self.findings.append({
                'severity': 'MEDIUM',
                'type': 'Legacy Pairing',
                'details': 'Device uses legacy pairing (not LE Secure Connections). '
                          'Vulnerable to passive eavesdropping during pairing.'
            })

        return self.findings

    def generate_report(self):
        """Generate BLE security assessment report."""
        print('BLE Security Assessment Report')
        print('=' * 60)

        if not self.findings:
            print('No security issues identified.')
            return

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        for finding in sorted(self.findings,
                            key=lambda x: severity_order.get(x['severity'], 5)):
            print(f'[{finding["severity"]}] {finding["type"]}')
            print(f'  {finding["details"]}')
            print()

# BLE attack vectors
print('BLE Attack Vector Summary')
print('=' * 50)
attacks = [
    ('Sniffing (Legacy)', 'Capture pairing exchange with legacy pairing to derive LTK'),
    ('Sniffing (LE SC)', 'More difficult but still possible with active MITM'),
    ('Replay', 'Replay advertising or connection data (limited by sequence numbers)'),
    ('Spoofing', 'Clone device address and advertising data'),
    ('KNOB Attack', 'Force low entropy encryption key negotiation (BLE 4.2-5.1)'),
    ('BLESA', 'Spoof server characteristics to inject data to reconnected client'),
    ('GATT Dump', 'Enumerate all GATT services and characteristics'),
    ('Write Without Auth', 'Write to unprotected characteristics without pairing'),
]
for name, desc in attacks:
    print(f'  {name}: {desc}')
```

## Part 3: RF Fingerprinting

### Device Identification Through RF Fingerprints

RF fingerprinting uses unique hardware-level imperfections in each radio transmitter to identify individual devices, even when they use the same MAC address or device identifier.

```python
#!/usr/bin/env python3
"""RF fingerprinting for ZigBee/BLE device identification."""

import numpy as np
from scipy.signal import welch
from collections import defaultdict

class RFFingerprinter:
    """Identify devices based on RF transmission characteristics."""

    def __init__(self):
        self.fingerprint_db = {}
        self.features_per_device = defaultdict(list)

    def extract_features(self, iq_data, sample_rate):
        """Extract RF fingerprint features from IQ samples."""
        features = {}

        # 1. Carrier frequency offset (CFO)
        phase = np.unwrap(np.angle(iq_data))
        cfo = np.mean(np.diff(phase)) * sample_rate / (2 * np.pi)
        features['cfo_hz'] = cfo

        # 2. Amplitude statistics
        amplitude = np.abs(iq_data)
        features['amp_mean'] = np.mean(amplitude)
        features['amp_std'] = np.std(amplitude)
        features['amp_skew'] = float(np.mean((amplitude - np.mean(amplitude))**3) /
                                     (np.std(amplitude)**3 + 1e-12))

        # 3. Phase noise
        phase_diff = np.diff(phase)
        features['phase_noise_std'] = np.std(phase_diff)

        # 4. I/Q imbalance
        i_component = np.real(iq_data)
        q_component = np.imag(iq_data)
        features['iq_gain_imbalance'] = np.std(i_component) / (np.std(q_component) + 1e-12)
        features['iq_dc_offset_i'] = np.mean(i_component)
        features['iq_dc_offset_q'] = np.mean(q_component)

        # 5. Spectral features
        f, psd = welch(iq_data, fs=sample_rate, nperseg=256)
        features['spectral_centroid'] = np.sum(f * psd) / (np.sum(psd) + 1e-12)
        features['spectral_bandwidth'] = np.sqrt(np.sum(((f - features['spectral_centroid'])**2) * psd) /
                                                  (np.sum(psd) + 1e-12))

        # 6. Modulation-specific features
        # Symbol transitions (for O-QPSK in ZigBee or GFSK in BLE)
        envelope = np.abs(iq_data)
        envelope_norm = (envelope - np.min(envelope)) / (np.max(envelope) - np.min(envelope) + 1e-12)
        features['envelope_kurtosis'] = float(np.mean((envelope_norm - 0.5)**4) /
                                              (np.mean((envelope_norm - 0.5)**2)**2 + 1e-12))

        return features

    def enroll_device(self, device_id, iq_data, sample_rate, num_captures=5):
        """Enroll a device by building its RF fingerprint from multiple captures."""
        all_features = []

        for i in range(min(num_captures, len(iq_data) if isinstance(iq_data, list) else 1)):
            if isinstance(iq_data, list):
                data = iq_data[i]
            else:
                data = iq_data

            features = self.extract_features(data, sample_rate)
            all_features.append(features)

        # Compute average fingerprint
        avg_fingerprint = {}
        feature_keys = all_features[0].keys()
        for key in feature_keys:
            values = [f[key] for f in all_features]
            avg_fingerprint[key] = {
                'mean': np.mean(values),
                'std': np.std(values),
            }

        self.fingerprint_db[device_id] = avg_fingerprint
        print(f'Enrolled device: {device_id}')
        print(f'  Features extracted: {len(feature_keys)}')
        for key in sorted(feature_keys):
            fp = avg_fingerprint[key]
            print(f'  {key}: {fp["mean"]:.4f} (std: {fp["std"]:.4f})')

    def identify_device(self, iq_data, sample_rate):
        """Identify a device from its RF transmission."""
        features = self.extract_features(iq_data, sample_rate)

        best_match = None
        best_score = float('inf')

        for device_id, fingerprint in self.fingerprint_db.items():
            score = 0
            for key in features:
                if key in fingerprint:
                    # Mahalanobis-like distance
                    mean = fingerprint[key]['mean']
                    std = fingerprint[key]['std'] + 1e-12
                    distance = abs(features[key] - mean) / std
                    score += distance ** 2

            score = np.sqrt(score)

            if score < best_score:
                best_score = score
                best_match = device_id

        if best_match and best_score < 10:  # Threshold
            return {
                'device_id': best_match,
                'confidence': max(0, 100 - best_score * 10),
                'score': best_score,
            }
        else:
            return {
                'device_id': 'unknown',
                'confidence': 0,
                'score': best_score,
            }

# Example usage
print('RF Fingerprinting Framework')
print('=' * 50)
print('Enroll devices by capturing multiple transmissions,')
print('then identify devices from new captures.')
print()
print('Features extracted:')
print('  - Carrier frequency offset (CFO)')
print('  - Amplitude statistics (mean, std, skew)')
print('  - Phase noise')
print('  - I/Q imbalance (gain, DC offset)')
print('  - Spectral features (centroid, bandwidth)')
print('  - Envelope characteristics')
```

## Part 4: Combined ZigBee/BLE Assessment Methodology

### Assessment Workflow

1. **Reconnaissance**: Scan all ZigBee channels (11-26) and BLE advertising channels (37-39) for active devices
2. **Device Inventory**: Build a complete inventory of discovered devices with their addresses, types, and advertising data
3. **Security Analysis**: Assess each device for encryption status, pairing method, information disclosure, and known vulnerabilities
4. **Capture and Analysis**: Capture protocol traffic for deep analysis (ZigBee: data frames, key exchange; BLE: pairing, GATT operations)
5. **Key Recovery**: Attempt to recover encryption keys through sniffing (legacy BLE pairing, ZigBee key transport)
6. **Replay Testing**: Test for replay vulnerability on unencrypted or poorly protected frames
7. **RF Fingerprinting**: Build device fingerprints for unauthorized device detection
8. **Reporting**: Document all findings with severity ratings and remediation guidance

## Practical Steps

1. Scan all ZigBee channels using rtl_power to identify active networks
2. Capture BLE advertising traffic on channels 37, 38, and 39
3. Parse and analyze captured frames for security-relevant information
4. Test for default network keys and insecure pairing methods
5. Attempt key recovery through passive sniffing of pairing procedures
6. Build RF fingerprints for device identification and clone detection

## Hands-on Exercises

### Exercise 1: ZigBee Channel Survey

Scan all 16 ZigBee channels to identify active networks and their signal strength.

```bash
for ch in $(seq 11 26); do
  freq=$((2405 + ($ch - 11) * 5))
  echo "Channel $ch (${freq} MHz):"
  timeout 10 rtl_power -f ${freq}M:$((${freq}+2))M:10k -i 1 -e 5 zigbee_ch${ch}.csv
  awk -F, '$6 > -60 {count++} END {print "  Active transmissions: " count+0}' zigbee_ch${ch}.csv
done
```

### Exercise 2: BLE Device Discovery

Capture and parse BLE advertising packets to build a device inventory with device names, services, and manufacturer information.

```bash
hackrf_transfer -r ble_adv.raw -f 2426000000 -s 4000000 -l 32 -g 30 -n 40000000
python3 ble_parser.py ble_adv.raw
```

### Exercise 3: ZigBee Frame Analysis

Capture ZigBee data frames and analyze the frame structure, including security status, addressing, and payload content.

### Exercise 4: BLE Security Assessment

Discover a BLE device, enumerate its GATT services, and assess the security of its pairing method and characteristic permissions.

### Exercise 5: RF Fingerprinting

Enroll multiple ZigBee or BLE devices by capturing their RF transmissions, then test the identification system with new captures to verify accuracy.

## References

- IEEE 802.15.4 specification — https://standards.ieee.org/standard/802_15_4-2020.html
- Bluetooth Core Specification v5.4 — https://www.bluetooth.com/specifications/specs/core-specification-5-4/
- ZigBee Alliance specification — https://csa-iot.org/all-solutions/zigbee/
- KillerBee ZigBee security testing framework — https://github.com/riverloopsec/killerbee
- Ubertooth BLE sniffer — https://github.com/greatscottgadgets/ubertooth
- BLE security analysis — Mike Ryan, iSEC Partners
- KNOB Attack paper — Antonioli et al., "Key Negotiation of Bluetooth"
- RF fingerprinting research — Bihl et al., "RF Fingerprinting for IoT Devices"
- SDR-based ZigBee analysis — Moskowitz et al., "SDR 802.15.4 Packet Capture"