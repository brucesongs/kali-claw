# GSM/LTE Base Station Attack Guide

## Introduction

Cellular networks (GSM, UMTS, LTE) use radio interfaces that can be monitored and analyzed using SDR equipment. While modern 4G/5G networks employ sophisticated encryption and mutual authentication, legacy GSM networks remain vulnerable to interception and impersonation attacks. This guide covers the methodology for identifying, capturing, and analyzing GSM and LTE signals for authorized security assessment purposes.

GSM networks are particularly interesting from a security perspective because the A5/1 and A5/3 encryption algorithms used to protect over-the-air traffic have known weaknesses. With the right SDR equipment and software, it is possible to passively monitor GSM transmissions and, in some cases, decrypt the traffic. LTE networks are significantly more secure but can still be analyzed for information leakage through metadata and signaling patterns.

**Objectives**: Identify cellular base stations using SDR, capture and analyze GSM/LTE signals, understand base station impersonation concepts, and assess cellular network security.

## GSM Network Discovery

### Base Station Scanning

Before any analysis can begin, you must identify active GSM base stations in your area. Each GSM cell broadcasts on specific frequencies determined by its ARFCN (Absolute Radio Frequency Channel Number).

```bash
# Scan for GSM900 base stations with gr-gsm
grgsm_scanner -b GSM900 -g 40

# Scan for GSM1800 base stations
grgsm_scanner -b DCS1800 -g 40

# Scan for GSM850 (used in Americas)
grgsm_scanner -b GSM850 -g 40

# Live monitoring of GSM cell
python3 /usr/share/gr-gsm/grgsm_livemon -f 935.4M -g 40
```

### ARFCN to Frequency Mapping

Understanding the relationship between ARFCN numbers and actual frequencies is essential for targeting specific cells.

```bash
# Calculate GSM900 downlink frequencies
# ARFCN 1-124: 935.2 + 0.2*(n-1) MHz
for arfcn in $(seq 1 124); do
  freq=$(echo "935.2 + 0.2 * ($arfcn - 1)" | bc)
  echo "ARFCN $arfcn: ${freq} MHz"
done

# Calculate DCS1800 downlink frequencies
# ARFCN 512-885: 1805.2 + 0.2*(n-512) MHz
for arfcn in $(seq 512 530); do
  freq=$(echo "1805.2 + 0.2 * ($arfcn - 512)" | bc)
  echo "ARFCN $arfcn: ${freq} MHz"
done
```

## GSM Signal Capture and Decoding

### BCCH Capture

The Broadcast Control Channel (BCCH) carries system information that all phones in the cell must read. This data contains cell identity, location area code, and neighbor cell information.

```bash
# Capture GSM BCCH at specific frequency
grgsm_capture -f 935.4M -s 2000000 -g 40 -c 100

# Decode captured GSM messages
grgsm_decode -c capture.cfile -t 0 -s 2000000

# Decode specific channel type
grgsm_decode -c gsm_capture.cfile -s 1625000/6 -t 0 -m BCCH

# Extract system information messages
grgsm_decode -c gsm_capture.cfile -t 0 | grep -i "SYSINFO\|SI1\|SI2\|SI3\|SI4"
```

### GSM Traffic Analysis

```bash
# Decode GSM SMS and signaling messages
grgsm_decode -c gsm_capture.cfile -s 1625000/6 -t 0 | \
  grep -i "SMS\|paging\|identity\|assignment"

# Extract IMSI from paging requests
grgsm_decode -c gsm_capture.cfile -t 0 -m PCH | \
  grep -i "IMSI\|TMSI\|paging"

# Monitor for cell reselection parameters
grgsm_decode -c gsm_capture.cfile -t 0 -m BCCH | \
  grep -i "reselect\|cell\|barred"
```

## LTE Signal Analysis

### LTE Cell Search

LTE cells broadcast synchronization signals (PSS/SSS) that can be detected with SDR equipment. The Physical Cell ID (PCI) derived from these signals helps identify individual cells.

```bash
# Capture LTE signal at known eNodeB frequency
hackrf_transfer -r lte_capture.raw -f 1840000000 -s 10000000 -l 40 -g 30 -n 100000000

# Analyze LTE signal for cell identification
python3 -c "
import numpy as np
data = np.fromfile('lte_capture.raw', dtype=np.complex64)
power = np.abs(data)**2
print(f'Samples: {len(data)}')
print(f'Avg power: {np.mean(power):.2f}, Peak: {np.max(power):.2f}')
print(f'Dynamic range: {10*np.log10(np.max(power)/np.mean(power)):.1f} dB')
"

# Scan LTE bands for active cells
rtl_power -f 1800M:1900M:100k -i 5 -e 120 lte_band.csv

# Visual analysis with inspectrum
inspectrum lte_capture.raw
```

### LTE MIB/SIB Decoding

The Master Information Block (MIB) and System Information Blocks (SIBs) contain essential network configuration data.

```bash
# Extract LTE MIB information
# Requires srsRAN or OpenLTE
srsran/src/upper/test/nr/test_nr -i lte_capture.raw

# Analyze LTE bandwidth and configuration
python3 -c "
import numpy as np
data = np.fromfile('lte_capture.raw', dtype=np.complex64)
# Compute spectrogram for bandwidth estimation
fft_size = 2048
spectrogram = np.abs(np.fft.fftshift(np.fft.fft(data[:fft_size*100].reshape(-1, fft_size), axis=1), axes=1))
mean_power = np.mean(spectrogram, axis=0)
# Find occupied bandwidth
threshold = np.max(mean_power) * 0.1
occupied = np.where(mean_power > threshold)[0]
bw = (occupied[-1] - occupied[0]) / fft_size * 10e6  # Approximate
print(f'Estimated bandwidth: {bw/1e6:.1f} MHz')
"
```

## IMSI Catcher Concepts

### Understanding IMSI Catcher Detection

IMSI catchers (also known as cell-site simulators or Stingrays) operate by impersonating legitimate base stations to force mobile devices to connect to them. Understanding how these systems work is essential for both offensive testing and defensive detection.

```bash
# Detect potential IMSI catchers by monitoring cell parameters
grgsm_scanner -b GSM900 -g 40 | grep -i "LAC\|CID\|MCC\|MNC\|ARFCN\|BSIC"

# Monitor for suspicious cell reselection patterns
python3 /usr/share/gr-gsm/grgsm_livemon -f 935.4M -g 40 2>&1 | \
  grep -i "SYSINFO\|reselect\|cell_bar\|access"

# Compare observed cells against known cell database
grgsm_scanner -b GSM900 -g 40 > observed_cells.txt
diff known_cells.txt observed_cells.txt
```

### Defensive Cell Monitoring

```bash
# Continuous GSM monitoring for unauthorized base stations
while true; do
  grgsm_scanner -b GSM900 -g 40 2>/dev/null | grep -i "CID\|LAC" >> cell_log.txt
  sleep 60
done

# Alert on new or changed cell parameters
grgsm_scanner -b GSM900 -g 40 | awk '/CID/ {cid=$0} /LAC/ {lac=$0} /ARFCN/ {arfcn=$0} END {print cid, lac, arfcn}'
```

## Hands-on Exercises

### Exercise 1: GSM Cell Discovery

Scan for all GSM cells in your area and document their parameters (ARFCN, LAC, CID, signal strength).

```bash
grgsm_scanner -b GSM900 -g 40 | tee gsm_scan_results.txt
```

### Exercise 2: BCCH Decoding

Capture and decode the BCCH of the strongest cell to extract system information messages.

```bash
grgsm_capture -f 935.4M -s 2000000 -g 40 -c 100
grgsm_decode -c capture.cfile -t 0 -s 2000000 | grep -i "SYSINFO"
```

### Exercise 3: LTE Signal Analysis

Capture an LTE signal and analyze its bandwidth, cell ID, and signal quality.

```bash
hackrf_transfer -r lte.raw -f 1840000000 -s 10000000 -l 40 -g 30 -n 100000000
inspectrum lte.raw
```

### Exercise 4: Cell Parameter Monitoring

Set up continuous monitoring to detect changes in cell parameters that might indicate unauthorized base station activity.

```bash
grgsm_scanner -b GSM900 -g 40 > baseline_scan.txt
```

## Practical Steps

### Step 1: GSM Network Architecture for Security Testing

Understanding GSM architecture is essential for targeted testing. The GSM network consists of the Base Station Subsystem (BSS), Network and Switching Subsystem (NSS), and the Um radio interface that SDR equipment can monitor.

```
Mobile Station (MS) <--Um Radio Interface--> Base Transceiver Station (BTS)
                                                      |
                                               Base Station Controller (BSC)
                                                      |
                                               Mobile Switching Center (MSC)
                                                    /       \
                                        VLR (Visitor LR)  HLR (Home LR)
                                                      |
                                               PSTN / Other Networks
```

Key GSM security elements:

- **IMSI (International Mobile Subscriber Identity)**: Unique 15-digit identifier (MCC+MNC+MSIN). Sent in cleartext during initial attach on unencrypted networks.
- **TMSI (Temporary Mobile Subscriber Identity)**: Temporary identifier assigned after authentication to prevent IMSI tracking.
- **Ki**: 128-bit individual subscriber authentication key stored on SIM and AuC. Never transmitted over the air.
- **A3/A8**: Authentication and key generation algorithms (COMP128 variants). Some implementations have known weaknesses.
- **A5/1, A5/3**: Over-the-air encryption algorithms. A5/1 is crackable with rainbow tables. A5/3 (KASUMI) has theoretical weaknesses.

### Step 2: Advanced GSM Capture Techniques

```bash
# Continuous GSM monitoring with gr-gsm live monitor
# This provides real-time decode of GSM channels
grgsm_livemon -f 935.4M -g 40 -s 2000000

# Capture GSM with precise frequency targeting
# Use kalibrate to find exact frequency offsets first
kal -s GSM900 -g 40
kal -s DCS1800 -g 40

# Long-duration GSM capture for statistical analysis
timeout 3600 hackrf_transfer -r gsm_1hour.raw -f 935400000 -s 2000000 -l 40 -g 30

# Multi-ARFCN capture (capture multiple GSM channels simultaneously)
# Requires wider bandwidth or multiple SDR devices
hackrf_transfer -r gsm_wideband.raw -f 940000000 -s 10000000 -l 40 -g 30 -n 100000000
```

### Step 3: GSM Decryption Concepts

The A5/1 encryption used in GSM has been broken using time-memory trade-off attacks. Understanding the decryption process is important for assessing GSM network security posture.

```bash
# Check encryption level advertised by the network
grgsm_decode -c gsm_capture.cfile -t 0 -m BCCH | grep -i "encrypt\|cipher\|A5"

# Extract the encryption mode from system information
# SI6 contains cipher mode setting
grgsm_decode -c gsm_capture.cfile -t 0 | grep "SI6\|cipher"

# A5/1 decryption workflow (conceptual):
# 1. Capture GSM traffic including the initial L2 framing
# 2. Extract the known plaintext (system information messages)
# 3. Derive the A5/1 session key from Ki using COMP128 (requires SIM access)
#    OR use rainbow table attack on captured ciphertext with known plaintext
# 4. Decrypt subsequent traffic using the recovered key

# Note: A5/1 rainbow tables require ~2TB of storage
# Reference: Kraken A5/1 decryption project
```

### Step 4: GSM Protocol Analysis Deep Dive

```python
#!/usr/bin/env python3
"""Parse GSM Layer 3 messages from gr-gsm decoded output."""

import re
import sys
from collections import Counter

def parse_gsm_messages(log_file):
    """Parse and categorize GSM messages from gr-gsm output."""
    message_types = Counter()
    imsis = set()
    tmsis = set()
    lac_cids = {}  # LAC -> set of CIDs

    with open(log_file, 'r') as f:
        current_msg = {}
        for line in f:
            line = line.strip()

            # Extract IMSI
            imsi_match = re.search(r'IMSI[:\s]+(\d{15})', line)
            if imsi_match:
                imsis.add(imsi_match.group(1))

            # Extract TMSI
            tmsi_match = re.search(r'TMSI[:\s]+([0-9A-Fa-f]{8})', line)
            if tmsi_match:
                tmsis.add(tmsi_match.group(1))

            # Extract LAC and CID
            lac_match = re.search(r'LAC[:\s]+(\d+)', line)
            cid_match = re.search(r'CID[:\s]+(\d+)', line)
            if lac_match:
                lac = lac_match.group(1)
                if lac not in lac_cids:
                    lac_cids[lac] = set()
            if cid_match and lac_match:
                lac_cids[lac_match.group(1)].add(cid_match.group(1))

            # Categorize messages
            for msg_type in ['SYSINFO', 'PAGING', 'ASSIGNMENT',
                           'IDENTITY', 'LOCATION UPDATING',
                           'CM SERVICE', 'SMS', 'SETUP', 'ALERTING']:
                if msg_type in line.upper():
                    message_types[msg_type] += 1

    # Report
    print('GSM Protocol Analysis Report')
    print('=' * 50)
    print(f'\nMessage Distribution:')
    for msg_type, count in message_types.most_common():
        print(f'  {msg_type}: {count}')

    print(f'\nUnique IMSIs detected: {len(imsis)}')
    for imsi in sorted(imsis):
        # Mask middle digits for privacy
        masked = imsi[:3] + '*' * 9 + imsi[-3:]
        print(f'  {masked}')

    print(f'\nUnique TMSIs detected: {len(tmsis)}')
    print(f'\nLocation Areas:')
    for lac, cids in sorted(lac_cids.items()):
        print(f'  LAC {lac}: {len(cids)} cell(s) - CIDs: {sorted(cids)}')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        parse_gsm_messages(sys.argv[1])
    else:
        print('Usage: python3 gsm_parser.py <grgsm_decode_output.txt>')
```

### Step 5: LTE Security Assessment

LTE (4G) provides significantly stronger security than GSM through mutual authentication (EPS-AKA), stronger encryption (AES-based EEA1/EEA2), and integrity protection (EIA1/EIA2). However, security assessment still has value.

```bash
# LTE signal capture and basic analysis
# LTE uses OFDMA with variable bandwidth (1.4, 3, 5, 10, 15, 20 MHz)
hackrf_transfer -r lte_band7.raw -f 2650000000 -s 15000000 -l 40 -g 30 -n 150000000

# Analyze LTE signal properties
python3 -c "
import numpy as np

data = np.fromfile('lte_band7.raw', dtype=np.complex64)
print(f'LTE Signal Analysis:')
print(f'  Samples: {len(data):,}')
print(f'  Duration: {len(data)/15e6:.3f} seconds')

# Power spectral density
fft_size = 2048
num_ffts = len(data) // fft_size
psd = np.zeros(fft_size)
for i in range(min(num_ffts, 1000)):
    chunk = data[i*fft_size:(i+1)*fft_size] * np.hanning(fft_size)
    spectrum = np.fft.fftshift(np.fft.fft(chunk))
    psd += np.abs(spectrum) ** 2
psd /= min(num_ffts, 1000)
psd_db = 10 * np.log10(psd + 1e-12)

# Estimate occupied bandwidth
threshold = np.max(psd_db) - 20
occupied = np.where(psd_db > threshold)[0]
freq_res = 15e6 / fft_size
bw = (occupied[-1] - occupied[0]) * freq_res
print(f'  Estimated bandwidth: {bw/1e6:.1f} MHz')
print(f'  Peak power: {np.max(psd_db):.1f} dB')
print(f'  Noise floor: {np.median(psd_db):.1f} dB')
print(f'  SNR estimate: {np.max(psd_db) - np.median(psd_db):.1f} dB')
"

# LTE cell search using srsRAN
# srsRAN can decode LTE MIB and SIB messages
srsran/src/upper/test/phy_test -i lte_band7.raw

# Capture LTE RRC signaling for analysis
# RRC messages reveal network configuration and security parameters
tshark -r lte_capture.pcap -Y "lte-rrc" -T fields \
  -e lte-rrc.msg_type -e lte-rrc.physCellId 2>/dev/null
```

### Step 6: IMSI Catcher Detection Methodology

Defending against IMSI catchers requires understanding their operational signatures. This section covers detection techniques for authorized security assessment.

```python
#!/usr/bin/env python3
"""IMSI catcher detection through cell parameter analysis."""

import json
import time
from collections import defaultdict

def detect_anomalous_cells(observed_cells, known_cells_db):
    """Compare observed cells against known baseline to detect anomalies."""
    alerts = []

    for cell in observed_cells:
        cell_id = (cell['mcc'], cell['mnc'], cell['lac'], cell['cid'])

        if cell_id not in known_cells_db:
            alerts.append({
                'severity': 'HIGH',
                'type': 'Unknown Cell',
                'details': f'Cell CID={cell[\"cid\"]} LAC={cell[\"lac\"]} '
                          f'MCC={cell[\"mcc\"]} MNC={cell[\"mnc\"]} not in database',
                'data': cell
            })

        # Check for mismatched LAC (common IMSI catcher indicator)
        for known in known_cells_db:
            if known[2] != cell['lac'] and known[0] == cell['mcc'] and known[1] == cell['mnc']:
                alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'LAC Mismatch',
                    'details': f'CID={cell[\"cid\"]} has unexpected LAC={cell[\"lac\"]}',
                    'data': cell
                })

        # Check for unusually strong signal (closer than expected)
        if cell.get('signal_dbm', -100) > -60:
            alerts.append({
                'severity': 'LOW',
                'type': 'Strong Signal',
                'details': f'CID={cell[\"cid\"]} at {cell[\"signal_dbm\"]} dBm (unusually strong)',
                'data': cell
            })

    return alerts

# Example cell scan results
observed = [
    {'mcc': 310, 'mnc': 260, 'lac': 356, 'cid': 21415, 'arfcn': 152, 'signal_dbm': -75},
    {'mcc': 310, 'mnc': 260, 'lac': 356, 'cid': 99999, 'arfcn': 987, 'signal_dbm': -45},  # Suspicious
]

known = {
    (310, 260, 356, 21415): {'arfcn': 152},
    (310, 260, 356, 21416): {'arfcn': 155},
}

alerts = detect_anomalous_cells(observed, known)
for alert in alerts:
    print(f'[{alert[\"severity\"]}] {alert[\"type\"]}: {alert[\"details\"]}')
```

## Hands-on Exercises

### Exercise 1: GSM Cell Discovery

Scan for all GSM cells in your area and document their parameters (ARFCN, LAC, CID, signal strength).

```bash
grgsm_scanner -b GSM900 -g 40 | tee gsm_scan_results.txt
```

### Exercise 2: BCCH Decoding

Capture and decode the BCCH of the strongest cell to extract system information messages.

```bash
grgsm_capture -f 935.4M -s 2000000 -g 40 -c 100
grgsm_decode -c capture.cfile -t 0 -s 2000000 | grep -i "SYSINFO"
```

### Exercise 3: LTE Signal Analysis

Capture an LTE signal and analyze its bandwidth, cell ID, and signal quality.

```bash
hackrf_transfer -r lte.raw -f 1840000000 -s 10000000 -l 40 -g 30 -n 100000000
inspectrum lte.raw
```

### Exercise 4: Cell Parameter Monitoring

Set up continuous monitoring to detect changes in cell parameters that might indicate unauthorized base station activity.

```bash
grgsm_scanner -b GSM900 -g 40 > baseline_scan.txt
```

### Exercise 5: GSM Traffic Analysis

Capture 10 minutes of GSM traffic and analyze the message distribution, identifying paging requests, assignment messages, and system information broadcasts.

```bash
timeout 600 grgsm_livemon -f 935.4M -g 40 2>&1 | tee gsm_traffic.log
python3 gsm_parser.py gsm_traffic.log
```

## References

- gr-gsm project — https://github.com/ptrkrysk/gr-gsm
- srsRAN project — https://github.com/srsRAN/srsRAN
- RFC 3310 — GSM and 3GPP authentication
- GSM 05.02 specification — Multiplexing and multiple access
- LTE security analysis — NIST SP 800-187
- SDR wireless testing methodology — PTES Technical Guidelines
- 3GPP TS 33.102 — Security architecture (2G/3G)
- 3GPP TS 33.401 — Security architecture (LTE/SAE)
- A5/1 decryption project — http://srlabs.de/decrypting_gsm
- IMSI catcher detection — https://github.com/Oros42/IMSI-catcher
