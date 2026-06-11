# GPS Spoofing and SDR Signal Analysis Guide

## Introduction

The Global Positioning System (GPS) is a satellite-based navigation system that provides position, velocity, and timing information to receivers worldwide. GPS signals are exceptionally weak at the Earth's surface (below the noise floor) and use a well-documented spread-spectrum modulation, making them vulnerable to spoofing attacks where an attacker transmits counterfeit GPS signals that override the legitimate satellite signals.

GPS spoofing is relevant to security testing because many critical systems rely on GPS for timing synchronization (telecommunications networks, power grid phasor measurement units, financial trading systems) and navigation (autonomous vehicles, maritime vessels, aircraft). Testing GPS receiver resilience to spoofing is an authorized security assessment activity in controlled environments.

This guide covers GPS signal structure, spoofing techniques, detection methods, and practical SDR-based GPS testing using HackRF One and software-defined GPS transmitters.

**Objectives**: Understand GPS signal structure, implement GPS spoofing for authorized testing, develop GPS spoofing detection techniques, and assess GPS receiver resilience.

## Part 1: GPS Signal Structure

### GPS Signal Overview

GPS satellites transmit on multiple frequencies. The most commonly targeted for security testing is L1 (1575.42 MHz) which carries the C/A (Coarse/Acquisition) code used by civilian receivers.

| Parameter | Value |
|-----------|-------|
| Frequency (L1) | 1575.42 MHz |
| Modulation | BPSK (Binary Phase Shift Keying) |
| PRN code rate | 1.023 MHz (C/A code) |
| PRN code length | 1023 chips (1 ms period) |
| Data rate | 50 bps (navigation message) |
| Signal power at surface | -130 dBm (below thermal noise floor) |
| Bandwidth | 2.046 MHz (main lobe) |

### GPS Signal Components

Each GPS satellite transmits a signal consisting of three components:

1. **Carrier**: A 1575.42 MHz sinusoidal wave
2. **PRN Code (C/A)**: A unique 1023-chip Gold code that identifies each satellite (PRN 1-32). The code repeats every 1 millisecond.
3. **Navigation Message**: 50 bps data stream containing satellite ephemeris, clock corrections, almanac data, and health status.

```python
#!/usr/bin/env python3
"""GPS C/A code generator for PRN codes 1-32."""

import numpy as np

# GPS C/A code generation parameters
# Each satellite uses a unique combination of two 10-bit PRN generators (G1 and G2)
# The G2 tap selection determines the PRN number

G2_TAPS = {
    1: [2, 6],    2: [3, 7],    3: [4, 8],    4: [5, 9],
    5: [1, 9],    6: [2, 10],   7: [1, 8],    8: [2, 9],
    9: [3, 10],   10: [2, 3],   11: [3, 4],   12: [5, 6],
    13: [6, 7],   14: [7, 8],   15: [8, 9],   16: [9, 10],
    17: [1, 4],   18: [2, 5],   19: [3, 6],   20: [4, 7],
    21: [5, 8],   22: [6, 9],   23: [1, 3],   24: [4, 6],
    25: [5, 7],   26: [6, 8],   27: [7, 9],   28: [8, 10],
    29: [1, 6],   30: [2, 7],   31: [3, 8],   32: [4, 9],
}

def generate_ca_code(prn):
    """Generate C/A code for given PRN number (1-32)."""
    if prn not in G2_TAPS:
        raise ValueError(f'Invalid PRN: {prn}. Must be 1-32.')

    # G1 generator polynomial: X^10 + X^3 + 1
    # G2 generator polynomial: X^10 + X^9 + X^8 + X^6 + X^3 + X^2 + 1
    code_length = 1023
    g1 = np.ones(10, dtype=int)
    g2 = np.ones(10, dtype=int)

    ca_code = np.zeros(code_length, dtype=int)
    tap1, tap2 = G2_TAPS[prn]

    for i in range(code_length):
        # G1 output
        g1_out = g1[-1]
        # G2 output (XOR of selected taps)
        g2_out = g2[tap1 - 1] ^ g2[tap2 - 1]

        # C/A code chip
        ca_code[i] = g1_out ^ g2_out

        # Update G1 shift register
        g1_feedback = g1[2] ^ g1[9]
        g1 = np.roll(g1, 1)
        g1[0] = g1_feedback

        # Update G2 shift register
        g2_feedback = g2[1] ^ g2[2] ^ g2[5] ^ g2[7] ^ g2[8] ^ g2[9]
        g2 = np.roll(g2, 1)
        g2[0] = g2_feedback

    # Map from {0, 1} to {-1, +1} for BPSK modulation
    return 2 * ca_code - 1

# Generate and display C/A codes for a few PRNs
for prn in [1, 2, 3]:
    code = generate_ca_code(prn)
    print(f'PRN {prn}: {code_length} chips, first 20: {code[:20]}')
    print(f'  Code balance (sum): {np.sum(code)} (should be -1 for C/A codes)')
```

### GPS Navigation Message Structure

The navigation message is a 1500-bit frame transmitted at 50 bps (30 seconds per frame). It consists of five subframes:

| Subframe | Content | Duration |
|----------|---------|----------|
| 1 | Week number, satellite health, clock correction | 6 seconds |
| 2 | Ephemeris (orbital parameters) | 6 seconds |
| 3 | Ephemeris (orbital parameters continued) | 6 seconds |
| 4 | Almanac and ionosphere data (page 1-25) | 6 seconds |
| 5 | Almanac data (page 1-25) | 6 seconds |

## Part 2: GPS Signal Capture and Analysis

### Capturing GPS Signals with HackRF

GPS signals are extremely weak and require either an active GPS antenna with built-in LNA or a high-gain antenna positioned with clear sky view.

```bash
# Capture GPS L1 signal at 1575.42 MHz
# Use active GPS antenna connected through bias tee
hackrf_transfer -r gps_capture.raw -f 1575420000 -s 8000000 \
  -l 32 -g 30 --amp-enable -n 80000000

# Alternative: Use RTL-SDR with bias tee for GPS capture
# Requires rtl-sdr v3 with bias tee support
rtl_sdr -f 1575420000 -s 2048000 -g 49.0 -n 20480000 gps_raw.raw

# Verify GPS signal presence by checking power spectral density
python3 -c "
import numpy as np

data = np.fromfile('gps_capture.raw', dtype=np.complex64)
print(f'GPS Capture Analysis:')
print(f'  Samples: {len(data):,}')
print(f'  Duration: {len(data)/8e6:.3f} seconds')

# Compute power spectral density
fft_size = 4096
psd = np.zeros(fft_size)
num_ffts = min(len(data) // fft_size, 1000)
for i in range(num_ffts):
    chunk = data[i*fft_size:(i+1)*fft_size]
    spectrum = np.fft.fftshift(np.fft.fft(chunk))
    psd += np.abs(spectrum)**2
psd /= num_ffts
psd_db = 10 * np.log10(psd + 1e-12)

# GPS signal should appear as a bump ~2 MHz wide centered in the band
center_power = np.mean(psd_db[fft_size//2 - 50 : fft_size//2 + 50])
edge_power = np.mean(np.concatenate([psd_db[:100], psd_db[-100:]]))
snr = center_power - edge_power
print(f'  Center power: {center_power:.1f} dB')
print(f'  Edge power: {edge_power:.1f} dB')
print(f'  SNR estimate: {snr:.1f} dB')
if snr > 3:
    print('  GPS signal detected!')
else:
    print('  WARNING: GPS signal not clearly visible')
    print('  Ensure active antenna is connected with sky view')
"
```

### GPS Signal Acquisition

GPS signal acquisition is the process of detecting which satellites are visible and determining the carrier frequency offset and code phase for each.

```python
#!/usr/bin/env python3
"""GPS signal acquisition using parallel code phase search."""

import numpy as np

def acquire_satellite(iq_data, sample_rate, prn, freq_offset=0):
    """Acquire a specific GPS satellite from captured IQ data."""
    ca_code = generate_ca_code(prn)  # From previous code

    # Resample C/A code to match sample rate
    samples_per_chip = int(sample_rate / 1.023e6)
    code_samples = np.repeat(ca_code, samples_per_chip)
    code_length_samples = len(code_samples)

    # Search over a range of frequency offsets (Doppler)
    freq_search_range = np.arange(freq_offset - 5000, freq_offset + 5000, 500)

    best_corr = 0
    best_freq = 0
    best_phase = 0

    # Take 1ms of data for acquisition
    num_samples = min(code_length_samples, len(iq_data))
    signal_segment = iq_data[:num_samples]

    for freq in freq_search_range:
        # Mix with local oscillator to remove carrier
        t = np.arange(num_samples) / sample_rate
        mixed = signal_segment * np.exp(-2j * np.pi * freq * t)

        # Circular cross-correlation using FFT (parallel code phase search)
        signal_fft = np.fft.fft(mixed, code_length_samples)
        code_fft = np.fft.fft(code_samples[:code_length_samples], code_length_samples)
        correlation = np.abs(np.fft.ifft(signal_fft * np.conj(code_fft)))

        # Find peak correlation
        peak_idx = np.argmax(correlation)
        peak_val = correlation[peak_idx]

        if peak_val > best_corr:
            best_corr = peak_val
            best_freq = freq
            best_phase = peak_idx

    # Compute acquisition metric (peak-to-average ratio)
    avg_corr = np.mean(np.abs(np.fft.ifft(
        np.fft.fft(signal_segment, code_length_samples) *
        np.conj(code_fft)
    )))
    acquisition_metric = best_corr / (avg_corr + 1e-12)

    return {
        'prn': prn,
        'acquired': acquisition_metric > 2.5,  # Threshold
        'frequency_offset': best_freq,
        'code_phase': best_phase,
        'metric': acquisition_metric,
        'correlation_peak': float(best_corr)
    }

# Scan all GPS satellites
print('GPS Satellite Acquisition')
print('=' * 60)
print('Load captured GPS data and scan for visible satellites')
```

## Part 3: GPS Spoofing Techniques

### GPS Spoofing Principles

GPS spoofing works because the spoofed signal is typically much stronger than the authentic GPS signal (which is below the noise floor). A GPS receiver tracks the strongest correlation peak, so a signal that is only 3-4 dB stronger than the authentic signal will capture the receiver's tracking loops.

The spoofing process involves:

1. **Initial synchronization**: Transmit a GPS-like signal that aligns with the authentic signals in time and frequency
2. **Lift-off**: Gradually increase the spoofer's signal power above the authentic signal
3. **Pull-off**: Once the receiver is tracking the spoofed signal, slowly change the pseudorange (timing) to manipulate the computed position

### Software-Defined GPS Transmitter

```python
#!/usr/bin/env python3
"""
GPS signal generator for authorized security testing.
Generates I/Q samples for transmission via HackRF.

IMPORTANT: GPS signal transmission is regulated by law in most countries.
This code is for authorized laboratory security testing only.
Transmitting GPS signals without proper authorization is illegal.
"""

import numpy as np
import struct

class GPSSignalGenerator:
    """Generate GPS L1 C/A signals for software-defined transmission."""

    SAMPLE_RATE = 2.6e6  # HackRF minimum stable sample rate for GPS
    L1_FREQ = 1575.42e6
    CA_CODE_RATE = 1.023e6
    DATA_RATE = 50  # bps

    def __init__(self):
        self.satellites = {}

    def add_satellite(self, prn, doppler_hz=0, code_phase=0, power_db=0):
        """Add a satellite to the simulation."""
        ca_code = generate_ca_code(prn)
        self.satellites[prn] = {
            'ca_code': ca_code,
            'doppler': doppler_hz,
            'code_phase': code_phase,
            'power_db': power_db
        }

    def generate_navigation_bits(self, num_bits=300):
        """Generate simplified navigation message bits."""
        # Preamble (8 bits): 10001011
        preamble = [1, 0, 0, 0, 1, 0, 1, 1]
        # Fill remaining with test data
        bits = preamble + [0] * (num_bits - len(preamble))
        return np.array(bits, dtype=int)

    def generate_signal(self, duration_seconds, output_file):
        """Generate composite GPS signal for all configured satellites."""
        num_samples = int(self.SAMPLE_RATE * duration_seconds)
        composite = np.zeros(num_samples, dtype=np.complex64)

        samples_per_ca_code = int(self.SAMPLE_RATE / self.CA_CODE_RATE)
        chips_per_data_bit = int(self.CA_CODE_RATE / self.DATA_RATE)
        samples_per_data_bit = samples_per_ca_code * chips_per_data_bit

        for prn, params in self.satellites.items():
            ca_code = params['ca_code']
            doppler = params['doppler']
            code_phase = params['code_phase']
            power = 10 ** (params['power_db'] / 20)

            # Generate navigation data
            nav_bits = self.generate_navigation_bits(
                int(duration_seconds * self.DATA_RATE) + 1
            )

            # Generate satellite signal
            t = np.arange(num_samples) / self.SAMPLE_RATE

            # Carrier with Doppler
            carrier = np.exp(2j * np.pi * doppler * t)

            # C/A code repeated with code phase offset
            ca_extended = np.tile(ca_code, samples_per_ca_code * len(ca_code) // len(ca_code) + 2)
            code_indices = (np.arange(num_samples) + code_phase) % (samples_per_ca_code)
            chip_indices = (code_indices * len(ca_code)) // samples_per_ca_code
            chip_indices = chip_indices % len(ca_code)
            code_signal = ca_code[chip_indices].astype(float)

            # Navigation data modulation (20 C/A code periods per data bit)
            data_indices = np.arange(num_samples) // samples_per_data_bit
            data_indices = data_indices % len(nav_bits)
            nav_signal = (2 * nav_bits[data_indices] - 1).astype(float)

            # Combine: carrier * code * data * power
            satellite_signal = carrier * code_signal * nav_signal * power
            composite += satellite_signal

        # Normalize to prevent clipping
        max_val = np.max(np.abs(composite))
        if max_val > 0:
            composite = composite / max_val * 0.9

        # Save as complex64 IQ file
        composite.tofile(output_file)
        print(f'Generated GPS signal: {output_file}')
        print(f'  Duration: {duration_seconds}s')
        print(f'  Satellites: {list(self.satellites.keys())}')
        print(f'  Samples: {num_samples:,}')
        print(f'  File size: {num_samples * 8 / 1024 / 1024:.1f} MB')

        return composite

# Example: Generate a simple GPS test signal
print('GPS Signal Generator for Authorized Testing')
print('=' * 60)
print('This tool generates GPS signals for receiver resilience testing.')
print('Transmitting GPS signals requires explicit legal authorization.')
print()
print('Typical test scenario:')
print('  1. Generate signal with known satellite configuration')
print('  2. Transmit via HackRF in shielded lab environment')
print('  3. Observe receiver behavior under spoofed signal conditions')
```

### HackRF GPS Transmission Setup

```bash
# Transmit generated GPS signal using HackRF
# CRITICAL: This must only be done in a shielded RF enclosure or faraday cage
# Unauthorized GPS transmission is a criminal offense in most jurisdictions

# Verify HackRF is ready
hackrf_info

# Transmit GPS signal (in shielded enclosure only!)
# hackrf_transfer -t gps_test.raw -f 1575420000 -s 2600000 -x 0 -a 1
# -x 0: Minimum TX gain (start with lowest power)
# -a 1: Enable TX amplifier

# Gradually increase power for lift-off testing
# hackrf_transfer -t gps_test.raw -f 1575420000 -s 2600000 -x 10 -a 1
# hackrf_transfer -t gps_test.raw -f 1575420000 -s 2600000 -x 20 -a 1

# Monitor transmitted signal with second SDR
rtl_sdr -f 1575420000 -s 2048000 -g 0 -n 20480000 monitor.raw
```

## Part 4: GPS Spoofing Detection

### Receiver-Side Detection Techniques

GPS receivers can implement several detection mechanisms to identify spoofing attacks:

```python
#!/usr/bin/env python3
"""GPS spoofing detection framework."""

import numpy as np
from collections import deque

class GPSSpoofingDetector:
    """Detect GPS spoofing through multiple indicators."""

    def __init__(self):
        self.position_history = deque(maxlen=100)
        self.satellite_history = deque(maxlen=50)
        self.timing_history = deque(maxlen=50)
        self.alerts = []

    def check_signal_power_anomaly(self, cn0_values):
        """Check for abnormally high C/N0 values."""
        # Normal GPS C/N0 range: 30-50 dB-Hz
        # Spoofed signals typically show > 45 dB-Hz consistently
        mean_cn0 = np.mean(cn0_values)
        max_cn0 = np.max(cn0_values)

        if mean_cn0 > 48:
            self.alerts.append({
                'severity': 'HIGH',
                'type': 'Abnormally High Signal Power',
                'details': f'Mean C/N0 = {mean_cn0:.1f} dB-Hz '
                          f'(normal range 30-50, spoofing suspected > 48)'
            })

        if max_cn0 > 55:
            self.alerts.append({
                'severity': 'CRITICAL',
                'type': 'Extremely High Signal Power',
                'details': f'Max C/N0 = {max_cn0:.1f} dB-Hz '
                          f'(indicates powerful nearby transmitter)'
            })

    def check_satellite_constellation(self, visible_sats, elevations, azimuths):
        """Check for unrealistic satellite configurations."""
        # Too many satellites at high elevation
        high_elev = sum(1 for e in elevations if e > 75)
        if high_elev > 6:
            self.alerts.append({
                'severity': 'MEDIUM',
                'type': 'Unusual Satellite Distribution',
                'details': f'{high_elev} satellites above 75 elevation '
                          f'(typically max 3-4)'
            })

        # All satellites at similar power (spoofed signal from single source)
        cn0_spread = np.std([s['cn0'] for s in visible_sats])
        if cn0_spread < 2.0:
            self.alerts.append({
                'severity': 'HIGH',
                'type': 'Uniform Signal Power',
                'details': f'C/N0 standard deviation = {cn0_spread:.1f} '
                          f'(authentic GPS has ~5-8 dB spread)'
            })

    def check_position_jump(self, lat, lon, alt):
        """Check for sudden position jumps indicating spoofing takeover."""
        self.position_history.append((lat, lon, alt))

        if len(self.position_history) >= 2:
            prev = self.position_history[-2]
            curr = self.position_history[-1]

            # Calculate position change in meters
            dlat = (curr[0] - prev[0]) * 111000  # ~111 km per degree latitude
            dlon = (curr[1] - prev[1]) * 111000 * np.cos(np.radians(curr[0]))
            dalt = curr[2] - prev[2]

            distance = np.sqrt(dlat**2 + dlon**2 + dalt**2)

            # Position jump > 100m between 1-second updates is suspicious
            if distance > 100:
                self.alerts.append({
                    'severity': 'HIGH',
                    'type': 'Position Jump Detected',
                    'details': f'{distance:.0f}m position change '
                              f'(expected < 10m for stationary receiver)'
                })

    def check_timing_anomaly(self, gps_time, utc_time):
        """Check for timing discrepancies between GPS and reference clock."""
        offset_ms = abs(gps_time - utc_time) * 1000
        self.timing_history.append(offset_ms)

        # GPS timing offset should be < 100ns for disciplined clocks
        # Offset > 1 microsecond indicates potential spoofing
        if offset_ms > 0.001:  # 1 microsecond
            self.alerts.append({
                'severity': 'MEDIUM',
                'type': 'GPS Timing Offset',
                'details': f'{offset_ms*1000:.1f} microsecond offset '
                          f'(expected < 0.1 us for disciplined clock)'
            })

    def check_pseudorange_consistency(self, pseudoranges, satellite_positions):
        """Check pseudorange consistency across satellites."""
        if len(pseudoranges) < 4:
            return

        # Compute residuals from position solution
        # Large residuals indicate inconsistent measurements (possible spoofing)
        pr_array = np.array(list(pseudoranges.values()))
        pr_mean = np.mean(pr_array)
        residuals = np.abs(pr_array - pr_mean)
        max_residual = np.max(residuals)

        # Normal residuals: 0-10 meters
        # Spoofed residuals can exceed 100 meters due to timing errors
        if max_residual > 50:
            self.alerts.append({
                'severity': 'HIGH',
                'type': 'Pseudorange Inconsistency',
                'details': f'Max residual: {max_residual:.0f}m '
                          f'(expected < 10m for authentic signals)'
            })

    def get_report(self):
        """Generate spoofing detection report."""
        print('GPS Spoofing Detection Report')
        print('=' * 60)

        if not self.alerts:
            print('No spoofing indicators detected.')
            return

        for alert in sorted(self.alerts, key=lambda x: x['severity']):
            print(f'[{alert["severity"]}] {alert["type"]}')
            print(f'  {alert["details"]}')
            print()

# Initialize detector
detector = GPSSpoofingDetector()
print('GPS Spoofing Detection Framework')
print('Monitors: signal power, constellation, position, timing, pseudorange')
```

### Multi-Receiver Consistency Check

```python
#!/usr/bin/env python3
"""Multi-receiver GPS consistency check for spoofing detection."""

def check_multi_receiver_consistency(receiver_positions):
    """Compare positions from multiple receivers to detect spoofing."""
    if len(receiver_positions) < 2:
        print('Need at least 2 receivers for consistency check')
        return

    lats = [r[0] for r in receiver_positions]
    lons = [r[1] for r in receiver_positions]

    # Under spoofing, all receivers report same (spoofed) position
    # Under normal operation, receivers report their true positions
    lat_spread = max(lats) - min(lats)
    lon_spread = max(lons) - min(lons)

    # If receivers are physically separated but report same position
    # that indicates spoofing
    print(f'Position spread: {lat_spread:.6f} lat, {lon_spread:.6f} lon')
    print(f'Distance spread: ~{lat_spread * 111000:.0f}m x {lon_spread * 111000:.0f}m')

    if lat_spread < 0.00001 and lon_spread < 0.00001:
        print('ALERT: All receivers report identical position (spoofing suspected)')
    else:
        print('Receivers report distinct positions (consistent with normal operation)')
```

## Practical Steps

1. **Capture authentic GPS signals** to establish baseline signal characteristics
2. **Analyze signal properties** including C/N0 distribution, satellite constellation, and pseudorange consistency
3. **Generate GPS test signals** in a shielded lab environment for receiver resilience testing
4. **Test receiver behavior** under gradually increasing spoofed signal power
5. **Implement detection mechanisms** based on power analysis, consistency checks, and multi-receiver comparison
6. **Document findings** including minimum spoofing power required for takeover and detection effectiveness

## Hands-on Exercises

### Exercise 1: GPS Signal Capture

Capture GPS L1 signals using HackRF with an active GPS antenna and analyze the signal properties.

```bash
hackrf_transfer -r gps_l1.raw -f 1575420000 -s 2600000 -l 40 -g 30 --amp-enable -n 26000000
python3 gps_analyzer.py gps_l1.raw
```

### Exercise 2: Satellite Acquisition

Implement a GPS satellite acquisition algorithm and identify which satellites are visible in the captured signal.

### Exercise 3: Spoofing Detection

Simulate GPS data (normal and spoofed) and run the spoofing detection framework to identify anomalous indicators.

### Exercise 4: Receiver Resilience Testing

In a shielded lab environment, transmit a GPS test signal at gradually increasing power levels and document the receiver takeover threshold.

## References

- GPS Interface Specification IS-GPS-200 — https://www.gps.gov/technical/icwg/
- GPS spoofing research — Humphreys et al., University of Texas at Austin
- Software-defined GPS receiver — https://github.com/gps-sdr/gps-sdr
- GPS-SDR-SIM GPS signal generator — https://github.com/osqzss/gps-sdr-sim
- HackRF GPS tutorial — https://greatscottgadgets.com/hackrf/
- NIST SP 800-187: Guide to LTE and 5G security (includes GPS dependency)
- ICD-GPS-200: GPS Interface Control Document
- Bhatti, J.: GPS Spoofing and Detection, Proceedings of the IEEE
- Khan, F.: GPS Spoofing Attack Detection Techniques, IEEE Security & Privacy