# SDR Signal Capture and Analysis Guide

## Introduction

Software Defined Radio (SDR) transforms radio frequency signals into digital data that can be analyzed, decoded, and manipulated using software. This capability has revolutionized wireless security testing by making it possible to examine protocols that were previously only accessible with expensive specialized equipment. This guide covers the fundamentals of SDR signal capture, processing, and analysis using common hardware like RTL-SDR and HackRF One.

SDR-based security testing requires understanding of radio fundamentals including frequency, modulation, sample rate, and signal-to-noise ratio. Each of these parameters affects what you can capture and how accurately you can decode the transmitted data. The two most common SDR platforms for security testing are the inexpensive RTL-SDR (receive-only, suitable for monitoring and analysis) and the HackRF One (capable of both transmit and receive, enabling replay attacks).

**Objectives**: Set up SDR hardware, capture and analyze RF signals, identify modulation schemes, and extract data from unknown protocols.

## Hardware Setup and Calibration

### RTL-SDR Setup

The RTL-SDR is an affordable USB dongle based on the Realtek RTL2832U chip that can receive signals from 24MHz to 1.7GHz. While limited to receive-only operation, it is excellent for signal reconnaissance and analysis.

```bash
# Verify RTL-SDR device is recognized
rtl_test -t

# Check USB device enumeration
lsusb | grep -i "realtek\|rtl"

# Test basic reception on a known frequency (FM radio)
rtl_fm -f 100.0e6 -M fm -s 200k -r 32k -l 320 -g 40 | aplay -r 32000 -f S16_LE

# Set specific gain value (higher gain = more sensitivity but more noise)
rtl_fm -f 162.400e6 -s 22050 -g 20 - | aplay -r 22050 -f S16_LE
```

### HackRF Setup

The HackRF One operates from 1MHz to 6GHz with both transmit and receive capability, making it the primary tool for active SDR testing including signal replay and injection.

```bash
# Verify HackRF device and firmware version
hackrf_info

# Check HackRF hardware capabilities
hackrf_transfer --version

# Set sample rate and gain parameters
hackrf_transfer -s 10000000 --amp -l 32 -g 30
```

## Spectrum Scanning and Monitoring

### Wideband Scanning

Before targeting specific frequencies, perform wideband spectrum scanning to identify active signals in the target environment. This reconnaissance step helps identify unexpected transmissions and maps the RF landscape.

```bash
# Scan FM broadcast band (88-108MHz)
rtl_power -f 88M:108M:100k -i 10 -e 60 fm_band.csv

# Scan 433MHz ISM band (common for IoT devices)
rtl_power -f 433M:434M:1k -i 1 -e 300 433mhz_band.csv

# Generate visual heatmap from scan data
python3 -m urh.heatmap fm_band.csv

# HackRF wideband sweep for 2.4GHz band
hackrf_sweep -f 2400:2500 -l 32 -g 30 -w 1000000
```

### Targeted Frequency Monitoring

```bash
# Continuous monitoring of a specific band with high resolution
rtl_power -f 300M:900M:10k -i 5 -e 3600 wideband_scan.csv

# Detect active transmissions in European ISM band
rtl_power -f 868M:869M:1k -i 1 -e 60 ism_868.csv
awk -F, '$6 > -50 {print $4,$5,$6}' ism_868.csv

# Monitor 315MHz band (common for automotive keyfobs in US)
rtl_power -f 314M:316M:1k -i 1 -e 300 keyfob_315.csv
```

## Signal Capture Techniques

### Raw IQ Capture

IQ (In-phase and Quadrature) data represents the raw complex signal samples captured by the SDR. This format preserves all signal information for later analysis and processing.

```bash
# Capture raw IQ data with HackRF at 433MHz
hackrf_transfer -r capture_433.raw -f 433920000 -s 8000000 -l 40 -g 30 -n 80000000

# Capture with RTL-SDR at lower sample rate
rtl_sdr -f 433920000 -s 2048000 -g 30 -n 20480000 capture_433.raw

# Capture specific signal for replay
hackrf_transfer -r doorbell.raw -f 315000000 -s 8000000 -l 40 -g 30 -n 800000000

# Continuous capture with timestamp for correlation
hackrf_transfer -r "capture_$(date +%s).raw" -f 315000000 -s 8000000 -l 40 -g 30
```

### Signal Conversion and Processing

```bash
# Convert raw IQ to WAV for audio analysis
sox -r 8000000 -e unsigned-integer -b 8 -c 2 capture_433.raw output.wav

# Frequency hopping capture (multiple channels)
for freq in 433.42M 433.62M 433.92M; do
  hackrf_transfer -r "capture_${freq}.raw" -f ${freq} -s 2000000 -l 40 -g 30 -n 20000000
done
```

## Signal Analysis with urh

The Universal Radio Hacker (urh) is the primary tool for analyzing and decoding unknown wireless protocols. It provides automated modulation detection, signal comparison, and protocol analysis capabilities.

```bash
# Record signal with urh CLI
urh -r -f 433.92e6 -s 2e6 -g 30 --device rtl_sdr -d 5 signal_recording.complex16s

# Analyze recorded signal
urh -i signal_recording.complex16s -f 433.92e6 -s 2e6

# Auto-detect modulation and protocol parameters
urh --auto-detect -i signal_recording.complex16s

# Decode with custom parameters
urh -i signal_recording.complex16s --demod OOK --bit-length 100 --sample-rate 2e6
```

## Hands-on Exercises

### Exercise 1: FM Radio Capture

Capture and demodulate an FM radio signal to verify SDR hardware is working correctly.

```bash
rtl_fm -f 100.1e6 -M fm -s 200k -r 32k -g 40 - | aplay -r 32000 -f S16_LE
```

### Exercise 2: ISM Band Survey

Perform a comprehensive survey of the 433MHz ISM band to identify all active transmitters in your environment.

```bash
rtl_power -f 433M:434M:100 -i 1 -e 60 ism_survey.csv
awk -F, '$6 > -50 {print $4,$5,$6}' ism_survey.csv | sort -u
```

### Exercise 3: Signal Replay

Capture a signal from a remote control device and replay it to verify the capture was successful.

```bash
hackrf_transfer -r remote.raw -f 433920000 -s 8000000 -l 40 -g 30
hackrf_transfer -t remote.raw -f 433920000 -s 8000000 -x 40
```

### Exercise 4: Protocol Analysis

Use urh to analyze an unknown signal, determine its modulation scheme, and decode the transmitted bits.

```bash
urh --auto-detect -i unknown_signal.complex16s
```

## Practical Steps

### Step 1: GNURadio Flowgraph Development

GNU Radio Companion (GRC) provides a graphical interface for building custom SDR signal processing pipelines. Understanding flowgraph development is essential for creating specialized capture and analysis tools that go beyond what pre-built tools offer.

```bash
# Launch GNU Radio Companion
gnuradio-companion &

# Verify GNU Radio installation and available blocks
python3 -c "
import gnuradio
print(f'GNU Radio version: {gnuradio.version()}')

# List available OOT (Out-of-Tree) modules
import importlib
modules = ['gnuradio.gr', 'gnuradio.analog', 'gnuradio.digital',
           'gnuradio.filter', 'gnuradio.blocks', 'gnuradio.fft']
for mod in modules:
    try:
        m = importlib.import_module(mod)
        print(f'  {mod}: loaded')
    except ImportError as e:
        print(f'  {mod}: NOT FOUND ({e})')
"
```

### Building a Custom OOK Receiver Flowgraph

On-Off Keying (OOK) is the simplest modulation scheme and is used by many consumer devices (weather stations, doorbells, remote controls). Building a custom OOK receiver in GNU Radio teaches fundamental SDR concepts.

```python
#!/usr/bin/env python3
"""Custom OOK receiver using GNU Radio for 433.92 MHz ISM band."""

import numpy as np
from gnuradio import gr, analog, blocks, filter, audio

class OOKReceiver(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "OOK Receiver")

        # Parameters
        sample_rate = 2e6
        center_freq = 433.92e6
        audio_rate = 48000

        # Signal source: RTL-SDR or file source
        # For file source (offline analysis):
        self.source = blocks.file_source(
            gr.sizeof_gr_complex, 'capture_433.raw', False
        )

        # Low-pass filter to isolate target signal
        self.lpf = filter.fir_filter_ccf(
            1,  # decimation
            filter.firdes.low_pass(
                1,           # gain
                sample_rate, # sampling freq
                200e3,       # cutoff freq
                100e3,       # transition width
                filter.firdes.WIN_HAMMING
            )
        )

        # Complex to magnitude (envelope detection for OOK)
        self.c2mag = blocks.complex_to_mag()

        # Threshold for binary decision
        self.threshold = blocks.threshold(0.1, 0.05, 0)

        # Float to short for binary output
        self.f2s = blocks.float_to_short(1, 1)

        # File sink for captured data
        self.sink = blocks.file_sink(gr.sizeof_short, 'ook_output.bin')
        self.sink.set_unbuffered(True)

        # Connect blocks
        self.connect(self.source, self.lpf)
        self.connect(self.lpf, self.c2mag)
        self.connect(self.c2mag, self.threshold)
        self.connect(self.threshold, self.f2s)
        self.connect(self.f2s, self.sink)

if __name__ == '__main__':
    tb = OOKReceiver()
    tb.run()
```

### Step 2: Signal Demodulation Techniques

Different modulation schemes require different demodulation approaches. Understanding these techniques is critical for analyzing unknown signals.

**ASK/OOK Demodulation**: The simplest form. Convert complex IQ samples to magnitude, then apply a threshold.

```python
#!/usr/bin/env python3
"""ASK/OOK demodulator for captured IQ data."""

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def demodulate_ook(iq_data, sample_rate, bit_duration_samples):
    """Demodulate OOK signal from complex IQ samples."""
    # Compute magnitude (envelope)
    magnitude = np.abs(iq_data)

    # Apply moving average filter for noise reduction
    window_size = max(1, bit_duration_samples // 4)
    filtered = np.convolve(magnitude, np.ones(window_size) / window_size, mode='same')

    # Automatic threshold using Otsu's method
    histogram, bin_edges = np.histogram(filtered, bins=256)
    bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2

    total = np.sum(histogram)
    sum_total = np.sum(bin_centers * histogram)
    weight_bg = 0
    sum_bg = 0
    max_variance = 0
    threshold = 0

    for i in range(256):
        weight_bg += histogram[i]
        if weight_bg == 0:
            continue
        weight_fg = total - weight_bg
        if weight_fg == 0:
            break
        sum_bg += bin_centers[i] * histogram[i]
        mean_bg = sum_bg / weight_bg
        mean_fg = (sum_total - sum_bg) / weight_fg
        variance = weight_bg * weight_fg * (mean_bg - mean_fg) ** 2
        if variance > max_variance:
            max_variance = variance
            threshold = bin_centers[i]

    # Binary decision
    bits = (filtered > threshold).astype(int)

    # Sample at bit centers
    bit_centers = np.arange(
        bit_duration_samples // 2,
        len(bits),
        bit_duration_samples
    )
    sampled_bits = bits[bit_centers]

    return sampled_bits, threshold, filtered, magnitude

# Load and process captured data
iq_data = np.fromfile('capture_433.raw', dtype=np.complex64)
sample_rate = 2e6
bit_rate = 2000  # Estimated bit rate
bit_duration = int(sample_rate / bit_rate)

bits, threshold, filtered, magnitude = demodulate_ook(iq_data, sample_rate, bit_duration)
print(f'Signal length: {len(iq_data)} samples ({len(iq_data)/sample_rate:.3f}s)')
print(f'Threshold: {threshold:.4f}')
print(f'Decoded bits: {len(bits)}')
print(f'Bit string: {"".join(map(str, bits[:100]))}')
```

**FSK Demodulation**: Frequency Shift Keying uses two or more frequencies to represent data. Demodulation involves measuring instantaneous frequency.

```python
#!/usr/bin/env python3
"""FSK demodulator for 2-FSK (GFSK) signals."""

import numpy as np

def demodulate_fsk(iq_data, sample_rate, freq_deviation, bit_rate):
    """Demodulate 2-FSK signal using instantaneous frequency."""
    # Compute instantaneous frequency using phase difference
    phase = np.angle(iq_data)
    inst_freq = np.diff(phase) * sample_rate / (2 * np.pi)

    # Append to match original length
    inst_freq = np.append(inst_freq, inst_freq[-1])

    # Low-pass filter the frequency signal
    window = max(1, int(sample_rate / bit_rate / 4))
    filtered_freq = np.convolve(
        np.abs(inst_freq),
        np.ones(window) / window,
        mode='same'
    )

    # Decision: positive frequency deviation = 1, negative = 0
    bits = (filtered_freq > np.mean(filtered_freq)).astype(int)

    # Sample at bit centers
    bit_samples = int(sample_rate / bit_rate)
    bit_centers = np.arange(bit_samples // 2, len(bits), bit_samples)
    sampled_bits = bits[bit_centers]

    return sampled_bits, filtered_freq

# Example usage
iq_data = np.fromfile('fsk_capture.raw', dtype=np.complex64)
bits, freq_signal = demodulate_fsk(iq_data, sample_rate=2e6, freq_deviation=19e3, bit_rate=9600)
print(f'Decoded {len(bits)} FSK bits')
print(f'First 100 bits: {"".join(map(str, bits[:100]))}')
```

### Step 3: Signal Identification and Classification

When analyzing an unknown signal, systematic identification helps determine the modulation type, symbol rate, and protocol parameters.

```python
#!/usr/bin/env python3
"""Automatic signal identification from captured IQ data."""

import numpy as np
from scipy.signal import welch

def identify_signal(iq_data, sample_rate):
    """Analyze signal characteristics to identify modulation type."""
    results = {}

    # Compute power spectral density
    f, psd = welch(iq_data, fs=sample_rate, nperseg=4096, return_onesided=False)
    f = np.fft.fftshift(f)
    psd = np.fft.fftshift(psd)

    # Estimate signal bandwidth
    threshold_db = np.max(10 * np.log10(psd + 1e-12)) - 20  # 20dB bandwidth
    above_threshold = psd > 10 ** (threshold_db / 10)
    bandwidth = np.sum(above_threshold) * (f[1] - f[0])
    results['bandwidth_hz'] = abs(bandwidth)
    results['bandwidth_khz'] = abs(bandwidth) / 1000

    # Compute instantaneous amplitude, phase, and frequency
    amplitude = np.abs(iq_data)
    phase = np.unwrap(np.angle(iq_data))
    inst_freq = np.diff(phase) * sample_rate / (2 * np.pi)

    # Amplitude statistics (for ASK/OOK detection)
    amp_mean = np.mean(amplitude)
    amp_std = np.std(amplitude)
    amp_cv = amp_std / (amp_mean + 1e-12)  # Coefficient of variation
    results['amplitude_cv'] = amp_cv

    # Phase statistics (for PSK detection)
    phase_std = np.std(np.diff(phase))
    results['phase_diff_std'] = phase_std

    # Frequency statistics (for FSK detection)
    freq_std = np.std(inst_freq)
    results['freq_std_hz'] = freq_std

    # Modulation classification heuristic
    if amp_cv > 0.5:
        results['likely_modulation'] = 'ASK/OOK'
        results['confidence'] = 'High' if amp_cv > 0.8 else 'Medium'
    elif freq_std > 1e4:
        results['likely_modulation'] = 'FSK/GFSK'
        results['confidence'] = 'High' if freq_std > 5e4 else 'Medium'
    elif phase_std > 1.0:
        results['likely_modulation'] = 'PSK/BPSK/QPSK'
        results['confidence'] = 'High' if phase_std > 2.0 else 'Medium'
    else:
        results['likely_modulation'] = 'Unknown (possibly constant envelope)'
        results['confidence'] = 'Low'

    # Print results
    print('Signal Identification Report')
    print('=' * 40)
    for key, value in results.items():
        print(f'{key}: {value}')

    return results

# Analyze captured signal
iq_data = np.fromfile('unknown_signal.raw', dtype=np.complex64)
identify_signal(iq_data, sample_rate=2e6)
```

### Step 4: Spectrogram Analysis and Visualization

Spectrograms (waterfall displays) reveal signal patterns that are invisible in frequency-domain plots alone. Time-frequency analysis is essential for identifying frequency-hopping signals, burst transmissions, and multi-channel protocols.

```python
#!/usr/bin/env python3
"""Generate spectrogram from captured IQ data."""

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def generate_spectrogram(iq_data, sample_rate, fft_size=1024, overlap=512):
    """Generate and save spectrogram from complex IQ samples."""
    # Compute STFT
    num_segments = (len(iq_data) - fft_size) // (fft_size - overlap) + 1
    spectrogram = np.zeros((fft_size // 2, num_segments))

    window = np.hanning(fft_size)
    for i in range(num_segments):
        start = i * (fft_size - overlap)
        segment = iq_data[start:start + fft_size] * window
        spectrum = np.fft.fftshift(np.fft.fft(segment))
        spectrogram[:, i] = np.abs(spectrum[:fft_size // 2]) ** 2

    # Convert to dB
    spectrogram_db = 10 * np.log10(spectrogram + 1e-12)

    # Create time and frequency axes
    time_axis = np.arange(num_segments) * (fft_size - overlap) / sample_rate
    freq_axis = np.linspace(-sample_rate / 2, sample_rate / 2, fft_size // 2) / 1e6

    # Plot
    fig, ax = plt.subplots(figsize=(14, 6))
    im = ax.imshow(
        spectrogram_db,
        aspect='auto',
        extent=[time_axis[0], time_axis[-1], freq_axis[0], freq_axis[-1]],
        origin='lower',
        cmap='viridis',
        vmin=np.percentile(spectrogram_db, 10),
        vmax=np.percentile(spectrogram_db, 99)
    )
    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Frequency (MHz)')
    ax.set_title(f'Spectrogram (FFT={fft_size}, Overlap={overlap})')
    plt.colorbar(im, ax=ax, label='Power (dB)')
    plt.tight_layout()
    plt.savefig('spectrogram.png', dpi=150)
    print(f'Spectrogram saved to spectrogram.png')
    print(f'Time range: 0 - {time_axis[-1]:.3f}s')
    print(f'Frequency range: {freq_axis[0]:.3f} - {freq_axis[-1]:.3f} MHz')

# Generate spectrogram from captured data
iq_data = np.fromfile('capture_433.raw', dtype=np.complex64)
generate_spectrogram(iq_data, sample_rate=2e6, fft_size=2048, overlap=1024)
```

### Step 5: Multi-Capture Signal Comparison

When analyzing protocols, comparing multiple captures reveals the static (address, sync word) and dynamic (payload, rolling code) portions of the transmitted data.

```python
#!/usr/bin/env python3
"""Compare multiple signal captures to identify protocol structure."""

import numpy as np

def compare_captures(file_pattern, num_captures, sample_rate, bit_rate):
    """Compare multiple captures to find static vs dynamic bits."""
    bit_duration = int(sample_rate / bit_rate)
    all_bit_strings = []

    for i in range(num_captures):
        try:
            data = np.fromfile(f'{file_pattern}_{i}.raw', dtype=np.complex64)
            magnitude = np.abs(data)
            threshold = np.mean(magnitude) + 2 * np.std(magnitude)
            bits = (magnitude > threshold).astype(int)

            # Sample at bit centers
            centers = np.arange(bit_duration // 2, len(bits), bit_duration)
            sampled = bits[centers]
            bit_string = ''.join(map(str, sampled[:200]))  # First 200 bits
            all_bit_strings.append(bit_string)
        except FileNotFoundError:
            print(f'Capture {i} not found, skipping')

    if len(all_bit_strings) < 2:
        print('Need at least 2 captures for comparison')
        return

    # Find positions where bits differ between captures
    min_len = min(len(s) for s in all_bit_strings)
    static_bits = []
    dynamic_bits = []

    for pos in range(min_len):
        bits_at_pos = [s[pos] for s in all_bit_strings]
        if len(set(bits_at_pos)) == 1:
            static_bits.append(pos)
        else:
            dynamic_bits.append(pos)

    print(f'Total bit positions analyzed: {min_len}')
    print(f'Static positions: {len(static_bits)}')
    print(f'Dynamic positions: {len(dynamic_bits)}')
    print()
    print('Static bit pattern (likely address/sync):')
    static_pattern = ''.join(all_bit_strings[0][pos] for pos in static_bits[:50])
    print(f'  {static_pattern}...')
    print()
    print('Dynamic positions (likely payload/rolling code):')
    print(f'  {dynamic_bits[:30]}...')
    print()
    # Show per-capture dynamic bits
    for i, bs in enumerate(all_bit_strings):
        dynamic_vals = ''.join(bs[pos] for pos in dynamic_bits[:50])
        print(f'Capture {i} dynamic bits: {dynamic_vals}...')

# Example: compare 5 keyfob captures
compare_captures('keyfob_press', num_captures=5, sample_rate=8e6, bit_rate=2000)
```

## Hands-on Exercises

### Exercise 1: FM Radio Capture

Capture and demodulate an FM radio signal to verify SDR hardware is working correctly.

```bash
rtl_fm -f 100.1e6 -M fm -s 200k -r 32k -g 40 - | aplay -r 32000 -f S16_LE
```

### Exercise 2: ISM Band Survey

Perform a comprehensive survey of the 433MHz ISM band to identify all active transmitters in your environment.

```bash
rtl_power -f 433M:434M:100 -i 1 -e 60 ism_survey.csv
awk -F, '$6 > -50 {print $4,$5,$6}' ism_survey.csv | sort -u
```

### Exercise 3: Signal Replay

Capture a signal from a remote control device and replay it to verify the capture was successful.

```bash
hackrf_transfer -r remote.raw -f 433920000 -s 8000000 -l 40 -g 30
hackrf_transfer -t remote.raw -f 433920000 -s 8000000 -x 40
```

### Exercise 4: Protocol Analysis

Use urh to analyze an unknown signal, determine its modulation scheme, and decode the transmitted bits.

```bash
urh --auto-detect -i unknown_signal.complex16s
```

### Exercise 5: Custom GNURadio Flowgraph

Build a custom GNURadio flowgraph that captures a 433.92 MHz OOK signal, demodulates it, and saves the decoded bits to a file.

```bash
gnuradio-companion
# Create: Osmocom Source -> Low Pass Filter -> Complex to Mag -> Threshold -> File Sink
# Set frequency to 433.92 MHz, sample rate to 2 MSps
# Adjust threshold until clean binary output is achieved
```

### Exercise 6: Signal Classification

Capture an unknown signal and use the signal identification script to determine its modulation type, bandwidth, and likely protocol.

```bash
hackrf_transfer -r unknown.raw -f 433920000 -s 2000000 -l 40 -g 30 -n 20000000
python3 signal_identifier.py
```

## References

- RTL-SDR documentation — https://www.rtl-sdr.com
- HackRF One documentation — https://greatscottgadgets.com/hackrf/
- Universal Radio Hacker — https://github.com/jopohl/urh
- GNU Radio project — https://www.gnuradio.org
- GNU Radio Companion tutorials — https://wiki.gnuradio.org/index.php/Tutorials
- SDR signal processing fundamentals — https://pysdr.org
- matplotlib spectrogram documentation — https://matplotlib.org/stable/api/_as_gen/matplotlib.pyplot.specgram.html
- Digital Signal Processing for SDR — Lyndon Hill, ISBN 978-1630818938
