# RF Fingerprinting and Device Identification Guide

## Introduction and Overview

RF fingerprinting is the process of identifying and classifying wireless devices based on unique characteristics of their radio frequency emissions. Every transmitter has subtle imperfections in its hardware (oscillator drift, phase noise, amplifier nonlinearities) that create a distinctive "fingerprint" in the emitted signal. This guide covers techniques for capturing, analyzing, and exploiting RF fingerprints for device identification, tracking, and security assessment.

RF fingerprinting serves both offensive and defensive purposes. From a security testing perspective, it enables identification of unauthorized devices, tracking of target communications, and verification of wireless infrastructure integrity. Understanding these techniques is essential for comprehensive wireless security assessments.

## Prerequisites

- RTL-SDR, HackRF, or USRP SDR hardware
- Kali Linux with GNU Radio installed
- Python 3 with numpy, scipy, scikit-learn
- Basic understanding of digital signal processing

## RF Fingerprint Fundamentals

### Transmitter Imperfections

Each radio transmitter has unique hardware imperfections that create distinguishable signal characteristics:

- **Phase noise**: Random phase fluctuations from imperfect oscillators
- **Frequency offset**: Slight carrier frequency deviations from nominal
- **I/Q imbalance**: Amplitude and phase differences between I and Q channels
- **Amplifier nonlinearities**: Distortion patterns specific to each power amplifier
- **Transition timing**: Symbol transition timing jitter unique to each transmitter

```python
# Extract RF fingerprint features from captured IQ data
import numpy as np
from scipy import signal

def extract_rf_fingerprint(iq_data, sample_rate=2.048e6):
    """Extract distinguishing features from IQ samples."""
    features = {}

    # Phase noise estimation
    instantaneous_phase = np.unwrap(np.angle(iq_data))
    phase_diff = np.diff(instantaneous_phase)
    features['phase_noise_std'] = np.std(phase_diff)

    # Frequency offset estimation
    freq_offset = np.mean(phase_diff) * sample_rate / (2 * np.pi)
    features['freq_offset'] = freq_offset

    # I/Q imbalance
    i_component = np.real(iq_data)
    q_component = np.imag(iq_data)
    features['iq_amplitude_imbalance'] = np.std(i_component) / np.std(q_component)
    features['iq_dc_offset_i'] = np.mean(i_component)
    features['iq_dc_offset_q'] = np.mean(q_component)

    # Spectral features
    f, psd = signal.welch(iq_data, fs=sample_rate, nperseg=1024)
    features['spectral_centroid'] = np.sum(f * psd) / np.sum(psd)
    features['spectral_bandwidth'] = np.sqrt(np.sum(((f - features['spectral_centroid'])**2) * psd) / np.sum(psd))

    return features
```

### Device Classification Pipeline

```python
# Build a device classifier using RF fingerprints
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

class RFDeviceClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_names = []

    def extract_features_batch(self, iq_segments, sample_rate=2.048e6):
        """Extract features from multiple IQ segments."""
        feature_list = []
        for segment in iq_segments:
            features = extract_rf_fingerprint(segment, sample_rate)
            feature_list.append(features)
        return feature_list

    def train(self, features_list, labels):
        """Train the classifier on extracted features."""
        X = np.array([[f[k] for k in sorted(features_list[0].keys())]
                       for f in features_list])
        self.feature_names = sorted(features_list[0].keys())

        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=0.2, random_state=42)

        self.model.fit(X_train, y_train)
        accuracy = self.model.score(X_test, y_test)
        print(f"Classification accuracy: {accuracy:.2%}")
        print(classification_report(y_test, self.model.predict(X_test)))
        return accuracy

    def identify_device(self, iq_data, sample_rate=2.048e6):
        """Identify a device from its RF emission."""
        features = extract_rf_fingerprint(iq_data, sample_rate)
        X = np.array([[features[k] for k in self.feature_names]])
        prediction = self.model.predict(X)[0]
        confidence = np.max(self.model.predict_proba(X))
        return prediction, confidence

    def save(self, path):
        with open(path, 'wb') as f:
            pickle.dump({'model': self.model, 'features': self.feature_names}, f)

    def load(self, path):
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.feature_names = data['features']
```

## Signal Capture for Fingerprinting

### WiFi Device Fingerprinting

```bash
# Capture WiFi signals for device fingerprinting
# Set monitor mode on WiFi adapter
sudo airmon-ng start wlan0
sudo iwconfig wlan0mon channel 6

# Capture raw WiFi frames with SDR
hackrf_transfer -r wifi_capture.raw -f 2.437e9 -s 20000000 -l 32 -g 30 -n 200000000

# Process with GNU Radio for IQ extraction
python3 -c "
import numpy as np
data = np.fromfile('wifi_capture.raw', dtype=np.int8)
iq = data[0::2] + 1j * data[1::2]
iq = iq / 128.0  # Normalize

# Segment into bursts using energy detection
window_size = 1000
energy = np.convolve(np.abs(iq)**2, np.ones(window_size)/window_size, mode='same')
threshold = np.mean(energy) + 3 * np.std(energy)

# Find burst boundaries
above = energy > threshold
transitions = np.diff(above.astype(int))
starts = np.where(transitions == 1)[0]
ends = np.where(transitions == -1)[0]

print(f'Found {len(starts)} signal bursts')
for i, (s, e) in enumerate(zip(starts[:10], ends[:10])):
    segment = iq[s:e]
    features = extract_rf_fingerprint(segment)
    print(f'Burst {i}: duration={len(segment)} samples, freq_offset={features[\"freq_offset\"]:.1f} Hz')
"
```

### Bluetooth Device Fingerprinting

```bash
# Capture BLE advertisements for device fingerprinting
# BLE channel 37 (2402 MHz), 38 (2426 MHz), 39 (2480 MHz)
hackrf_transfer -r ble_ch37.raw -f 2.402e9 -s 4000000 -l 32 -g 30 -n 40000000

# Extract BLE advertisement features
python3 -c "
import numpy as np
from scipy.signal import butter, filtfilt

def demod_ble_gfsk(iq_data, sample_rate=4e6, symbol_rate=1e6):
    demod = np.angle(iq_data[1:] * np.conj(iq_data[:-1]))
    b, a = butter(5, symbol_rate/2/(sample_rate/2))
    filtered = filtfilt(b, a, demod)
    bits = (filtered > 0).astype(int)
    return bits

data = np.fromfile('ble_ch37.raw', dtype=np.int8)
iq = (data[0::2] + 1j * data[1::2]) / 128.0

# Detect BLE preamble (01010101 or 10101010)
access_addr = [0,1,1,0,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,1,1,0,1]
print(f'Captured {len(iq)} IQ samples')
print('Scanning for BLE advertisement packets...')

# Energy-based burst detection
energy = np.convolve(np.abs(iq)**2, np.ones(100)/100, mode='same')
threshold = np.percentile(energy, 99)
bursts = np.where(energy > threshold)[0]
if len(bursts) > 0:
    print(f'Detected {len(np.diff(np.where(np.diff(bursts) > 1000)[0]))+1} bursts')
"
```

### IoT Device Protocol Identification

```python
# Identify IoT device protocols from RF emissions
class ProtocolIdentifier:
    PROTOCOL_SIGNATURES = {
        'ZigBee': {'freq': 2.4e9, 'bw': 2e6, 'modulation': 'O-QPSK'},
        'LoRa': {'freq_range': (863e6, 870e6), 'bw': [125e3, 250e3, 500e3], 'modulation': 'CSS'},
        'Z-Wave': {'freq': 868.42e6, 'bw': 300e3, 'modulation': 'GFSK'},
        'BLE': {'freq': 2.4e9, 'bw': 2e6, 'modulation': 'GFSK'},
        'WiFi': {'freq': 2.4e9, 'bw': 20e6, 'modulation': 'OFDM'},
        'Sub-GHz OOK': {'freq_range': (300e6, 928e6), 'bw': 200e3, 'modulation': 'OOK'},
    }

    def identify(self, iq_data, center_freq, sample_rate):
        # Compute power spectral density
        from scipy.signal import welch
        f, psd = welch(iq_data, fs=sample_rate, nperseg=1024)

        # Estimate bandwidth
        threshold = np.max(psd) * 0.1  # -10dB bandwidth
        bw_samples = np.sum(psd > threshold)
        bandwidth = bw_samples * sample_rate / len(psd)

        # Classify based on frequency and bandwidth
        candidates = []
        for proto, sig in self.PROTOCOL_SIGNATURES.items():
            score = 0
            if 'freq' in sig and abs(center_freq - sig['freq']) < 50e6:
                score += 2
            if 'freq_range' in sig and sig['freq_range'][0] <= center_freq <= sig['freq_range'][1]:
                score += 2
            if 'bw' in sig:
                if isinstance(sig['bw'], list):
                    if any(abs(bandwidth - b) < 100e3 for b in sig['bw']):
                        score += 1
                elif abs(bandwidth - sig['bw']) < 500e3:
                    score += 1
            candidates.append((proto, score))

        candidates.sort(key=lambda x: -x[1])
        return candidates[0] if candidates[0][1] > 0 else ('Unknown', 0)
```

## Hands-on Exercise: Device Tracking and Identification

### Exercise Setup

```bash
# 1. Survey the RF environment to identify active devices
# Scan common IoT frequencies
for freq in 433920000 868000000 915000000 2402000000; do
    echo "Scanning $freq Hz..."
    timeout 5 hackrf_transfer -r scan_${freq}.raw -f $freq -s 4000000 -l 32 -g 30 -n 20000000 2>/dev/null
done

# 2. Analyze captured signals
python3 << 'PYEOF'
import numpy as np
import os

for freq in [433.92e6, 868e6, 915e6, 2402e6]:
    fname = f'scan_{int(freq)}.raw'
    if os.path.exists(fname):
        data = np.fromfile(fname, dtype=np.int8)
        iq = (data[0::2] + 1j * data[1::2]) / 128.0
        energy = np.mean(np.abs(iq)**2)
        peak = np.max(np.abs(iq))
        print(f'{freq/1e6:.1f} MHz: avg_power={10*np.log10(energy):.1f}dB, peak={peak:.3f}, samples={len(iq)}')
PYEOF
```

### Device Tracking Across Sessions

```python
# Track a specific device across multiple capture sessions
import hashlib
import json
from datetime import datetime

class DeviceTracker:
    def __init__(self, db_path='device_fingerprints.json'):
        self.db_path = db_path
        self.database = self._load_db()

    def _load_db(self):
        try:
            with open(self.db_path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {'devices': {}}

    def _save_db(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.database, f, indent=2)

    def register_device(self, name, fingerprint_features):
        """Register a known device with its RF fingerprint."""
        device_hash = hashlib.sha256(
            str(sorted(fingerprint_features.items())).encode()
        ).hexdigest()[:16]
        self.database['devices'][name] = {
            'hash': device_hash,
            'features': fingerprint_features,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'sightings': 1
        }
        self._save_db()
        return device_hash

    def lookup_device(self, fingerprint_features):
        """Find a matching device in the database."""
        best_match = None
        best_score = float('inf')

        for name, info in self.database['devices'].items():
            score = sum(
                abs(fingerprint_features.get(k, 0) - info['features'].get(k, 0))
                for k in set(fingerprint_features) | set(info['features'])
            )
            if score < best_score:
                best_score = score
                best_match = name

        if best_match and best_score < 100:  # Threshold for match
            self.database['devices'][best_match]['last_seen'] = datetime.now().isoformat()
            self.database['devices'][best_match]['sightings'] += 1
            self._save_db()
            return best_match, best_score

        return None, best_score
```

## Defense Perspective

### Detecting RF Fingerprinting

Security teams can detect when their devices are being fingerprinted by monitoring for:

1. **Extended signal capture**: SDR devices capturing for prolonged periods near wireless infrastructure
2. **Frequency scanning**: Rapid frequency hopping behavior indicating survey mode
3. **Signal analysis patterns**: Multiple captures at the same frequency with varying gain settings

### Countermeasures

- **Transmitter randomization**: Implement frequency hopping and power variation to complicate fingerprinting
- **Signal normalization**: Use signal processing to normalize RF emissions before transmission
- **Physical security**: Detect and locate unauthorized SDR devices in the vicinity

## References and Resources

- "Physical-Layer Authentication in Wireless Networks" - IEEE Transactions on Information Forensics and Security
- "Deep Learning Based RF Fingerprinting for IoT Security" - USENIX Security Symposium
- GNU Radio Wiki: https://wiki.gnuradio.org/
- RTL-SDR Documentation: https://www.rtl-sdr.com/
- "RF-DNA Fingerprinting for IoT Device Authentication" - IEEE Internet of Things Journal
- HackRF One Documentation: https://greatscottgadgets.com/hackrf/
- URH (Universal Radio Hacker): https://github.com/jopohl/urh
