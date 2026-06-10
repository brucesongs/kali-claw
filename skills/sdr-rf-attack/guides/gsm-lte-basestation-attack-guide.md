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

## References

- gr-gsm project — https://github.com/ptrkrysk/gr-gsm
- srsRAN project — https://github.com/srsRAN/srsRAN
- RFC 3310 — GSM and 3GPP authentication
- GSM 05.02 specification — Multiplexing and multiple access
- LTE security analysis — NIST SP 800-187
- SDR wireless testing methodology — PTES Technical Guidelines
