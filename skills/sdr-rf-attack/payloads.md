# SDR/RF Attack Payloads

## 1. SDR Hardware Setup and Calibration

```bash
# Check RTL-SDR device
rtl_test -t

# Check HackRF device info
hackrf_info

# Set HackRF sample rate
hackrf_transfer -s 10000000 --amp -l 32 -g 30

# Calibrate RTL-SDR frequency offset
rtl_fm -f 162.400e6 -s 22050 -g 20 - | aplay -r 22050 -f S16_LE
```

```bash
# List available SDR devices
lsusb | grep -i "realtek\|hackrf\|nuand"

# Install SDR tools on Kali
sudo apt install gnuradio gr-gsm hackrf rtl-sdr urh gqrx inspectrum

# Verify hackrf driver
hackrf_transfer --version

# Set RTL-SDR gain
rtl_fm -f 100.0e6 -M fm -s 200k -r 32k -l 320 -g 40
```

## 2. Spectrum Scanning and Monitoring

```bash
# Wideband spectrum scan with rtl_power
rtl_power -f 88M:108M:100k -i 10 -e 60 fm_band.csv

# Generate heatmap from scan data
python3 -m urh.heatmap fm_band.csv

# HackRF sweep for wideband scanning
hackrf_sweep -f 2400:2500 -l 32 -g 30 -w 1000000

# Monitor specific frequency band
rtl_power -f 433M:434M:1k -i 1 -e 300 433mhz_band.csv
```

```bash
# GQRX CLI spectrum monitoring
gqrx -c default.conf -s 2400000 -f 433920000

# Continuous spectrum monitoring with rtl_power
rtl_power -f 300M:900M:10k -i 5 -e 3600 wideband_scan.csv

# Detect active transmissions in ISM band
rtl_power -f 868M:869M:1k -i 1 -e 60 ism_868.csv && \
  awk -F, '$6 > -50 {print $4,$5,$6}' ism_868.csv
```

## 3. Signal Capture and Recording

```bash
# Capture raw IQ data with HackRF
hackrf_transfer -r capture_433.raw -f 433920000 -s 8000000 -l 40 -g 30 -n 80000000

# Capture with RTL-SDR
rtl_sdr -f 433920000 -s 2048000 -g 30 -n 20480000 capture_433.raw

# Replay captured signal
hackrf_transfer -t capture_433.raw -f 433920000 -s 8000000 -x 40

# Capture specific duration
hackrf_transfer -r doorbell.raw -f 315000000 -s 8000000 -l 40 -g 30 -n 800000000
```

```bash
# Convert raw IQ to WAV for analysis
sox -r 8000000 -e unsigned-integer -b 8 -c 2 capture_433.raw output.wav

# Capture multiple frequency hops
for freq in 433.42M 433.62M 433.92M; do
  hackrf_transfer -r "capture_${freq}.raw" -f ${freq} -s 2000000 -l 40 -g 30 -n 20000000
done

# Continuous capture with timestamps
hackrf_transfer -r "capture_$(date +%s).raw" -f 315000000 -s 8000000 -l 40 -g 30
```

## 4. GSM Network Analysis (gr-gsm)

```bash
# Scan for GSM base stations
grgsm_scanner -b GSM900 -g 40

# Capture GSM BCCH
grgsm_capture -f 935.4M -s 2000000 -g 40 -c 100

# Decode GSM messages
grgsm_decode -c capture.cfile -t 0 -s 2000000

# Monitor GSM cell information
python3 /usr/share/gr-gsm/grgsm_livemon -f 935.4M -g 40
```

```bash
# GSM ARFCN to frequency conversion
# ARFCN 1-124 = GSM900 downlink: 935.2 + 0.2*(n-1) MHz

# Scan all GSM900 channels
for arfcn in $(seq 1 124); do
  freq=$(echo "935.2 + 0.2 * ($arfcn - 1)" | bc)
  echo "ARFCN $arfcn: ${freq} MHz"
done

# Decode GSM SMS and signaling
grgsm_decode -c gsm_capture.cfile -s 1625000/6 -t 0 | \
  grep -i "SMS\|paging\|identity"

# Extract GSM cell reselection parameters
grgsm_decode -c gsm_capture.cfile -t 0 -m BCCH
```

## 5. LTE/4G Signal Analysis

```bash
# LTE cell search with srsRAN
srsran/src/phy/phych/test/pdcch_test -f 1840M -s 2000000

# Capture LTE signal
hackrf_transfer -r lte_capture.raw -f 1840000000 -s 10000000 -l 40 -g 30 -n 100000000

# Decode LTE MIB/SIB
srsran/src/upper/test/nr/test_nr -i lte_capture.raw

# Monitor LTE downlink with srslte
srsran_eNb -f 1840.0M -s 10000000
```

```bash
# Scan LTE bands with rtl_power
rtl_power -f 1800M:1900M:100k -i 5 -e 120 lte_band.csv

# Identify LTE cell IDs
# Look for PSS/SSS peaks in captured data
python3 -c "
import numpy as np
data = np.fromfile('lte_capture.raw', dtype=np.complex64)
power = np.abs(data)**2
print(f'Avg power: {np.mean(power):.2f}, Peak: {np.max(power):.2f}')
"

# Extract LTE bandwidth info from waterfall
inspectrum lte_capture.raw
```

## 6. RFID/NFC Radio-Layer Attacks

```bash
# Capture 125kHz LF RFID signal via HackRF (requires antenna swap)
hackrf_transfer -r lf_rfid.raw -f 125000000 -s 8000000 -l 40 -g 30 -n 80000000

# Capture 13.56MHz HF RFID/NFC
hackrf_transfer -r hf_rfid.raw -f 13560000 -s 8000000 -l 40 -g 30 -n 80000000

# Analyze RFID signal with urh
urh -i hf_rfid.raw -f 13.56e6 -s 8e6

# Decode captured RFID data
python3 -c "
import numpy as np
data = np.fromfile('hf_rfid.raw', dtype=np.complex64)
# Check for ASK modulation at 13.56MHz subcarrier
envelope = np.abs(data)
print(f'Samples: {len(data)}, Peak amplitude: {np.max(envelope):.2f}')
"
```

```bash
# RTL-SDR as simple RFID detector (125kHz via upconverter)
rtl_fm -f 125e3 -M raw -s 200k -g 30 - | sox -t raw -r 200k -e unsigned -b 8 -c 1 - output.wav

# NFC signal analysis with urh
urh -i nfc_capture.complex16s -f 13.56e6 -s 2M --demod ASK

# Extract UID from captured NFC signal
urh --decode nfc_capture.complex16s --protocol NFC
```

## 7. Keyfob and Garage Door Replay Attacks

```bash
# Capture keyfob signal at 315MHz
hackrf_transfer -r keyfob_315.raw -f 315000000 -s 8000000 -l 40 -g 30

# Capture keyfob signal at 433MHz
hackrf_transfer -r keyfob_433.raw -f 433920000 -s 8000000 -l 40 -g 30

# Replay captured keyfob signal
hackrf_transfer -t keyfob_315.raw -f 315000000 -s 8000000 -x 40

# Analyze keyfob rolling code with urh
urh -i keyfob_315.raw -f 315e6 -s 8e6
```

```bash
# Capture multiple keyfob presses for rolling code analysis
for i in $(seq 1 5); do
  hackrf_transfer -r "keyfob_press_${i}.raw" -f 315000000 -s 8000000 -l 40 -g 30 -n 80000000
  sleep 2
done

# Compare captures for rolling code analysis
python3 -c "
import numpy as np
for i in range(1, 6):
    data = np.fromfile(f'keyfob_press_{i}.raw', dtype=np.int8)
    print(f'Press {i}: {len(data)} samples, unique patterns detected')
"

# Garage door signal capture and classification
hackrf_transfer -r garage.raw -f 390000000 -s 8000000 -l 40 -g 30
urh -i garage.raw -f 390e6 -s 8e6 --auto-detect
```

## 8. Radio Protocol Reverse Engineering (urh)

```bash
# Record signal with urh CLI
urh -r -f 433.92e6 -s 2e6 -g 30 --device rtl_sdr -d 5 signal_recording.complex16s

# Analyze recorded signal
urh -i signal_recording.complex16s -f 433.92e6 -s 2e6

# Auto-detect modulation and protocol
urh --auto-detect -i signal_recording.complex16s

# Decode with custom parameters
urh -i signal_recording.complex16s --demod OOK --bit-length 100 --sample-rate 2e6
```

```bash
# URH protocol analysis workflow
# Step 1: Record signal
urh -r -f 433.92e6 -s 2e6 -g 30 --device hackrf -d 3 unknown_signal.complex

# Step 2: Auto-detect modulation
urh --auto-detect -i unknown_signal.complex

# Step 3: Extract message bits
urh -i unknown_signal.complex --demod OOK --center 0 --bit-length 500 --tolerance 50

# Step 4: Compare multiple captures
urh --compare signal1.complex signal2.complex signal3.complex
```

## 9. GNURadio Flowgraph Development

```bash
# Create FM radio receiver flowgraph
cat > fm_receiver.grc << 'GRC'
<?xml version='1.0' encoding='utf-8'?>
<flow_graph>
  <block>
    <key>rtl_sdr_source</key>
    <param><key>freq</key><value>100e6</value></param>
    <param><key>samp_rate</key><value>2e6</value></param>
    <param><key>gain</key><value>30</value></param>
  </block>
</flow_graph>
GRC

# Run GNURadio flowgraph
gnuradio-companion fm_receiver.grc

# Execute Python flowgraph directly
python3 fm_receiver.py
```

```python
# GNURadio Python script for signal capture
from gnuradio import gr, analog, blocks, filter
import osmosdr

class signal_capture(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self)
        self.source = osmosdr.source(args="hackrf=0")
        self.source.set_sample_rate(2e6)
        self.source.set_center_freq(433.92e6)
        self.source.set_gain(30)
        self.sink = blocks.file_sink(gr.sizeof_gr_complex, "captured.complex")
        self.connect(self.source, self.sink)

tb = signal_capture()
tb.run()
```

```bash
# GNURadio WBFM receiver
grcc -o fm_rx.py /usr/share/gnuradio/examples/audio/dial_tone.grc

# Custom OOK demodulator in GNURadio
python3 -c "
from gnuradio import gr, analog, blocks
import numpy as np

class ook_demod(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(self, name='OOK Demod', in_sig=[np.complex64], out_sig=[np.float32])
    def work(self, input_items, output_items):
        output_items[0][:] = np.abs(input_items[0])
        return len(output_items[0])
"
```

## 10. Zigbee/LoRa IoT Signal Analysis

```bash
# Capture Zigbee signal (2.4GHz, channel 11-26)
hackrf_transfer -r zigbee.raw -f 2405000000 -s 8000000 -l 40 -g 30

# Capture LoRa signal (868MHz)
hackrf_transfer -r lora_868.raw -f 868000000 -s 8000000 -l 40 -g 30

# Analyze Zigbee with urh
urh -i zigbee.raw -f 2.405e9 -s 8e6 --demod OQPSK

# LoRa signal detection
rtl_power -f 863M:870M:10k -i 5 -e 60 lora_band.csv
```

```bash
# Zigbee channel scanning (channels 11-26)
for ch in $(seq 11 26); do
  freq=$(echo "2405 + 5 * ($ch - 11)" | bc)
  echo "Channel $ch: ${freq} MHz"
  rtl_power -f "${freq}M:${freq}M:10k" -i 2 -e 5 "zigbee_ch${ch}.csv"
done

# LoRa spreading factor detection
python3 -c "
import numpy as np
data = np.fromfile('lora_868.raw', dtype=np.complex64)
# Compute spectrogram for chirp detection
fft_size = 1024
spectrogram = np.abs(np.fft.fft(data[:fft_size*100].reshape(-1, fft_size), axis=1))
print(f'Spectrogram shape: {spectrogram.shape}')
print(f'Max power: {np.max(spectrogram):.2f}')
"
```

## 11. Spectrum Compliance and Detection Avoidance

```bash
# Measure transmission power
hackrf_transfer -t test_signal.raw -f 433920000 -s 8000000 -x 20

# Check regulatory power limits for ISM band
# FCC Part 15: 433MHz ISM = max 1W ERP (with restrictions)

# Spectrum mask verification
rtl_power -f 433M:435M:100 -i 1 -e 10 spectrum_mask.csv

# Detect frequency hopping patterns
rtl_power -f 2.4G:2.5G:100k -i 0.5 -e 60 fhss_detect.csv
```

```bash
# Monitor for unauthorized transmissions
rtl_power -f 88M:108M:1k -i 1 -e 300 monitor_fm.csv

# Low-power transmission test (verify minimum detectable signal)
hackrf_transfer -t tone.raw -f 433920000 -s 8000000 -x 10 -n 8000000

# Spectrum occupancy analysis
python3 -c "
import csv
with open('wideband_scan.csv') as f:
    reader = csv.reader(f)
    for row in reader:
        if float(row[6]) > -60:
            print(f'Active: {row[4]} Hz, Power: {row[6]} dB')
"
```

## 12. TPMS and Tire Pressure Sensor Attacks

```bash
# Capture TPMS signals at 315MHz
hackrf_transfer -r tpms_315.raw -f 315000000 -s 4000000 -l 40 -g 30 -n 40000000

# Capture TPMS signals at 433MHz
hackrf_transfer -r tpms_433.raw -f 433920000 -s 4000000 -l 40 -g 30 -n 40000000

# Analyze TPMS protocol with urh
urh -i tpms_315.raw -f 315e6 -s 4e6 --auto-detect
```

```bash
# Decode TPMS Manchester-encoded data
python3 -c "
import numpy as np
data = np.fromfile('tpms_315.raw', dtype=np.complex64)
envelope = np.abs(data)
threshold = np.mean(envelope) + 2 * np.std(envelope)
peaks = np.where(envelope > threshold)[0]
print(f'Peak detections: {len(peaks)}, first peak at sample {peaks[0] if len(peaks) > 0 else 0}')
"

# Monitor TPMS for fleet tracking
rtl_power -f 314M:316M:1k -i 0.5 -e 600 tpms_monitor.csv
awk -F, '$6 > -40 {print $4,$5,$6}' tpms_monitor.csv | sort -u
```

## 13. Weather Station and Sensor Sniffing

```bash
# Capture weather station at 433MHz
hackrf_transfer -r weather.raw -f 433920000 -s 2000000 -l 40 -g 30 -n 20000000

# Continuous weather sensor monitoring
rtl_fm -f 433.92e6 -M raw -s 200k -g 30 - | sox -t raw -r 200k -e unsigned -b 8 -c 1 - weather.wav

# Decode weather station protocol
urh -i weather.raw -f 433.92e6 -s 2e6 --demod OOK --bit-length 500
```

```bash
# Temperature sensor data extraction
python3 -c "
import numpy as np
from scipy.signal import find_peaks

data = np.fromfile('weather.raw', dtype=np.complex64)
envelope = np.abs(data)
peaks, properties = find_peaks(envelope, height=np.mean(envelope) + 3*np.std(envelope), distance=100)
print(f'Detected {len(peaks)} signal bursts')
for i, peak in enumerate(peaks[:10]):
    print(f'Burst {i}: sample {peak}, amplitude {envelope[peak]:.2f}')
"

# Scan for multiple weather station protocols
for freq in 433.42M 433.62M 433.92M 868.00M 868.30M; do
  rtl_power -f ${freq} -i 1 -e 10 "sensor_${freq}.csv" 2>/dev/null
  echo "Scanned $freq"
done
```

## 14. Drone RF Signal Analysis

```bash
# Capture drone control signal at 2.4GHz
hackrf_transfer -r drone_ctrl.raw -f 2440000000 -s 10000000 -l 40 -g 30 -n 100000000

# Capture drone GPS telemetry
hackrf_transfer -r drone_gps.raw -f 1575420000 -s 8000000 -l 40 -g 30 -n 80000000

# Analyze drone communication protocol
urh -i drone_ctrl.raw -f 2.44e9 -s 10e6 --auto-detect
```

```bash
# Detect drone RF fingerprint
python3 -c "
import numpy as np
data = np.fromfile('drone_ctrl.raw', dtype=np.complex64)
power = np.abs(data)**2
window = 10000
rolling_power = np.convolve(power, np.ones(window)/window, mode='valid')
print(f'Signal bursts detected above noise floor')
print(f'Max power: {np.max(rolling_power):.2f}')
print(f'Avg noise: {np.mean(rolling_power):.2f}')
print(f'SNR: {10*np.log10(np.max(rolling_power)/np.mean(rolling_power)):.1f} dB')
"

# Monitor drone video downlink at 5.8GHz
hackrf_transfer -r drone_video.raw -f 5725000000 -s 20000000 -l 40 -g 30 -n 200000000
```

## 15. AIS Ship Tracking via SDR

```bash
# Capture AIS signals at 162MHz
rtl_fm -f 162.025e6 -M fm -s 48k -r 48k -g 30 - | python3 ais_decode.py

# Dual-channel AIS capture (AIS1=161.975MHz, AIS2=162.025MHz)
rtl_fm -f 161.975e6 -M fm -s 48k -r 48k -g 30 ais_ch1.raw &
rtl_fm -f 162.025e6 -M fm -s 48k -r 48k -g 30 ais_ch2.raw &
wait

# Decode AIS messages
python3 -c "
import struct
# HDLC deframing for AIS messages
def decode_ais(raw_bytes):
    # NRZI decode, remove stuffing, extract payload
    pass
print('AIS decoder ready')
"
```

```bash
# Continuous AIS monitoring with vessel tracking
rtl_fm -f 162.025e6 -M fm -s 48k -r 48k -g 30 - | sox -t raw -r 48k -e signed -b 16 -c 1 - ais_monitor.wav &

# Build vessel database from AIS captures
python3 -c "
import json
vessels = {}
# Process decoded AIS messages
# Track MMSI, position, speed, heading
msg_types = {1: 'position', 2: 'position', 3: 'position', 5: 'static_data', 18: 'class_b_pos'}
print(f'Tracking {len(vessels)} vessels')
for mmsi, info in vessels.items():
    print(f'  MMSI {mmsi}: {info}')
"
```

## 16. Satellite Signal Analysis

```bash
# Capture NOAA weather satellite APT signal (137MHz)
rtl_fm -f 137.1e6 -s 55000 -g 40 - | sox -t raw -r 55000 -e signed -b 16 -c 1 - noaa_apt.wav

# Capture NOAA 19 APT pass
rtl_fm -f 137.1e6 -M fm -s 55000 -r 11025 -g 40 - | sox -t raw -r 11025 -e signed -b 16 -c 1 - noaa19.wav

# Decode APT weather image
python3 -c "
import numpy as np
from PIL import Image
data = np.fromfile('noaa_apt.raw', dtype=np.int16)
# APT sync pattern detection and image reconstruction
width = 2080
height = len(data) // width
img_data = data[:height*width].reshape(height, width)
img = Image.fromarray(img_data.astype(np.uint8))
img.save('weather_image.png')
print(f'Decoded image: {img.size}')
"
```

```bash
# Track satellite pass schedule with gpredict
# Monitor Inmarsat-C signals at 1.5GHz
hackrf_transfer -r inmarsat.raw -f 1545000000 -s 8000000 -l 40 -g 30 -n 80000000

# GPS L1 signal capture for spoofing analysis
hackrf_transfer -r gps_l1.raw -f 1575420000 -s 8000000 -l 40 -g 30 -n 80000000

# Analyze GPS signal structure
python3 -c "
import numpy as np
data = np.fromfile('gps_l1.raw', dtype=np.complex64)
power = np.abs(data)**2
print(f'GPS L1 samples: {len(data)}')
print(f'Power: avg={np.mean(power):.4f}, peak={np.max(power):.2f}')
# GPS C/A code acquisition requires 1ms correlation
ca_len = 1023
print(f'CA code length: {ca_len} chips')
"
```

## 17. FM/AM Radio Station Analysis

```bash
# Capture FM broadcast for RDS data extraction
rtl_fm -f 100.1e6 -M fm -s 200k -r 48k -g 40 - | python3 -c "
import sys, struct
# RDS subcarrier at 57kHz, extract group data
data = sys.stdin.buffer.read(4096)
print(f'Read {len(data)} bytes from FM audio')
"

# Scan entire FM band for station identification
rtl_power -f 88M:108M:10k -i 2 -e 30 fm_stations.csv
awk -F, '$6 > -30 {print $4/1e6 " MHz: " $6 " dB"}' fm_stations.csv | sort -t: -k2 -rn | head -20

# AM broadcast band scanning (530-1710kHz requires upconverter)
rtl_power -f 530e3:1710e3:1k -i 2 -e 30 am_band.csv
```

```bash
# RDS/RBDS data extraction from FM stations
rtl_fm -f 97.3e6 -M fm -s 200k -r 48k -g 40 - | redsea --input-raw -

# Capture NOAA Weather Radio (162.4-162.55MHz)
rtl_fm -f 162.4e6 -M fm -s 22050 -r 22050 -g 30 - | aplay -r 22050 -f S16_LE

# Decode pager signals (POCSAG/FLEX at 152/157MHz)
rtl_fm -f 152.240e6 -M fm -s 22050 -r 22050 -g 40 - | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -
```

## 18. Bluetooth Low Energy SDR Analysis

```bash
# Capture BLE advertising on channel 37 (2402MHz)
hackrf_transfer -r ble_ch37.raw -f 2402000000 -s 4000000 -l 40 -g 30 -n 40000000

# Capture BLE on channel 38 (2426MHz)
hackrf_transfer -r ble_ch38.raw -f 2426000000 -s 4000000 -l 40 -g 30 -n 40000000

# Capture BLE on channel 39 (2480MHz)
hackrf_transfer -r ble_ch39.raw -f 2480000000 -s 4000000 -l 40 -g 30 -n 40000000
```

```bash
# Scan BLE advertising channels for devices
for ch in 2402 2426 2480; do
  hackrf_transfer -r "ble_${ch}.raw" -f "${ch}000000" -s 4000000 -l 40 -g 30 -n 40000000 2>/dev/null
  echo "Scanned BLE channel at ${ch}MHz"
done

# Analyze BLE GFSK modulation
python3 -c "
import numpy as np
data = np.fromfile('ble_ch37.raw', dtype=np.complex64)
# BLE uses GFSK with BT=0.5, data rate 1Mbps
power = np.abs(data)**2
threshold = np.mean(power) + 3*np.std(power)
active = np.sum(power > threshold) / len(power) * 100
print(f'BLE channel activity: {active:.1f}%')
"
```

## 19. Ham Radio and Emergency Service Monitoring

```bash
# Monitor VHF amateur band (144-148MHz)
rtl_fm -f 146.52e6 -M fm -s 200k -r 32k -g 30 - | aplay -r 32000 -f S16_LE

# Scan UHF amateur band (420-450MHz)
rtl_power -f 420M:450M:5k -i 2 -e 60 uhf_ham.csv

# Monitor NOAA Weather Radio SAME alerts
rtl_fm -f 162.4e6 -M fm -s 22050 -r 22050 -g 30 - | multimon-ng -t raw -a EAS -
```

```bash
# Monitor emergency service frequencies (public safety bands)
# VHF High band (150-174MHz)
rtl_power -f 150M:174M:5k -i 2 -e 60 ems_vhf.csv

# UHF public safety band (450-470MHz)
rtl_power -f 450M:470M:5k -i 2 -e 60 ems_uhf.csv

# Decode P25 digital voice signals
rtl_fm -f 854.0e6 -s 48k -r 48k -g 30 - | dsd -i - -o /dev/dsp
```

## 20. Signal Classification and Machine Learning

```bash
# Extract signal features for classification
python3 -c "
import numpy as np
data = np.fromfile('unknown_signal.raw', dtype=np.complex64)
power = np.abs(data)**2
# Compute signal statistics
print(f'Mean power: {np.mean(power):.4f}')
print(f'Peak power: {np.max(power):.4f}')
print(f'Power std: {np.std(power):.4f}')
# Compute spectral features using FFT
fft = np.fft.fft(data[:4096])
spectral_centroid = np.sum(np.abs(fft) * np.arange(len(fft))) / np.sum(np.abs(fft))
print(f'Spectral centroid: {spectral_centroid:.1f}')
# Compute instantaneous frequency
phase = np.unwrap(np.angle(data))
inst_freq = np.diff(phase) / (2 * np.pi)
print(f'Freq deviation: {np.std(inst_freq):.4f}')
print(f'Freq range: {np.min(inst_freq):.4f} to {np.max(inst_freq):.4f}')
"
```

```bash
# Batch signal classification across multiple captures
python3 -c "
import numpy as np, os, glob

def classify_signal(filepath):
    data = np.fromfile(filepath, dtype=np.complex64)
    power = np.abs(data)**2
    peak_to_avg = np.max(power) / np.mean(power)
    # OOK: high peak-to-average ratio
    if peak_to_avg > 20:
        return 'OOK (On-Off Keying)'
    # FSK: moderate variation
    elif peak_to_avg > 5:
        return 'FSK/GFSK'
    # Constant envelope: FM/PM
    else:
        return 'Constant Envelope (FM/PSK/QAM)'

for f in glob.glob('*.raw'):
    sig_type = classify_signal(f)
    print(f'{os.path.basename(f)}: {sig_type}')
"
```

## 21. Radio Teletype and Digital Mode Decoding

```bash
# Decode RTTY (Radioteletype) signals
rtl_fm -f 14.1e6 -M usb -s 22050 -r 22050 -g 30 - | \
  multimon-ng -t raw -a RTTY -

# Decode CW/Morse code
rtl_fm -f 7.0e6 -M usb -s 22050 -r 22050 -g 30 - | \
  multimon-ng -t raw -a CW -

# Decode APRS packets at 144.39MHz (US)
rtl_fm -f 144.39e6 -M fm -s 22050 -r 22050 -g 30 - | \
  multimon-ng -t raw -a AFSK1200 -
```

```bash
# Decode DMR digital voice signals
rtl_fm -f 446.0e6 -s 48k -r 48k -g 30 - | dsd -i - -o /dev/dsp -fd

# Decode YSF (Yaesu System Fusion)
rtl_fm -f 442.0e6 -s 48k -r 48k -g 30 - | dsd -i - -o /dev/dsp -fy

# Decode NXDN digital voice
rtl_fm -f 460.0e6 -s 48k -r 48k -g 30 - | dsd -i - -o /dev/dsp -fn
```

## 22. Power Line Communication Analysis

```bash
# Capture power line communication signals (requires coupling circuit)
rtl_fm -f 100e3 -s 22050 -r 22050 -g 30 - | \
  sox -t raw -r 22050 -e signed -b 16 -c 1 - plc_signal.wav

# Analyze PLC modulation characteristics
python3 -c "
import numpy as np
data = np.fromfile('plc_signal.raw', dtype=np.int16)
spectrum = np.abs(np.fft.fft(data[:8192]))
freqs = np.fft.fftfreq(8192, 1/22050)
# Find dominant frequency components
peaks = np.argsort(spectrum[:4096])[-5:]
for p in peaks:
    print(f'Peak at {freqs[p]:.0f} Hz: amplitude {spectrum[p]:.2f}')
"
```

```bash
# Monitor smart meter RF emissions (900MHz band)
rtl_power -f 902M:928M:10k -i 1 -e 60 smart_meter.csv

# Detect HomePlug AV power line signals
# HomePlug uses 2-28MHz spectrum
rtl_power -f 2M:30M:10k -i 1 -e 30 homeplug.csv
awk -F, '$6 > -50 {print $4,$5,$6}' homeplug.csv | sort -u
```

## 23. RF Watermarking and Device Fingerprinting

```bash
# Capture multiple devices for RF fingerprinting
for i in $(seq 1 3); do
  echo "Activate device $i..."
  hackrf_transfer -r "device_${i}.raw" -f 433920000 -s 8000000 -l 40 -g 30 -n 80000000
done

# Extract device-specific RF fingerprint features
python3 -c "
import numpy as np
for i in range(1, 4):
    data = np.fromfile(f'device_{i}.raw', dtype=np.complex64)
    phase = np.angle(data[:1000])
    amp = np.abs(data[:1000])
    # Device fingerprint based on phase noise and amplitude transients
    print(f'Device {i}: phase_std={np.std(phase):.4f}, amp_skew={np.mean(amp):.4f}')
"
```

```bash
# RF fingerprint database construction
python3 -c "
import numpy as np, os

def extract_fingerprint(filepath):
    data = np.fromfile(filepath, dtype=np.complex64)
    envelope = np.abs(data[:5000])
    features = {
        'mean_amp': float(np.mean(envelope)),
        'std_amp': float(np.std(envelope)),
        'skew': float(np.mean((envelope - np.mean(envelope))**3) / np.std(envelope)**3),
        'turn_on_slope': float(np.mean(np.diff(envelope[:100]))),
    }
    return features

# Build fingerprint database for device identification
for f in ['device_1.raw', 'device_2.raw', 'device_3.raw']:
    if os.path.exists(f):
        fp = extract_fingerprint(f)
        print(f'{f}: amp={fp[\"mean_amp\"]:.4f}, slope={fp[\"turn_on_slope\"]:.4f}')
"
```

## 24. Radio Astronomy and Deep Space Monitoring

```bash
# Capture Hydrogen Line signal at 1420.405MHz (radio astronomy)
hackrf_transfer -r hydrogen_line.raw -f 1420405000 -s 8000000 -l 40 -g 30 -n 80000000

# Analyze Hydrogen Line spectrum
python3 -c "
import numpy as np
data = np.fromfile('hydrogen_line.raw', dtype=np.complex64)
fft_result = np.fft.fftshift(np.fft.fft(data[:65536]))
power_spectrum = np.abs(fft_result)**2
freqs = np.fft.fftshift(np.fft.fftfreq(65536, 1/8e6)) + 1420.405e6
peak_idx = np.argmax(power_spectrum)
print(f'Peak frequency: {freqs[peak_idx]/1e6:.3f} MHz')
print(f'Red shift indicates velocity: {(freqs[peak_idx]-1420.405e6)/1420.405e6*3e5:.1f} km/s')
"
```

```bash
# Monitor Jupiter radio emissions at 20.1MHz
rtl_fm -f 20.1e6 -M usb -s 22050 -r 22050 -g 40 - | sox -t raw -r 22050 -e signed -b 16 -c 1 - jupiter.wav

# Solar radio burst monitoring at 10.7cm (2800MHz)
hackrf_transfer -r solar.raw -f 2800000000 -s 8000000 -l 40 -g 30 -n 80000000
python3 -c "
import numpy as np
data = np.fromfile('solar.raw', dtype=np.complex64)
power = np.abs(data)**2
window = 100000
mean_power = np.convolve(power, np.ones(window)/window, mode='valid')
print(f'Solar flux: {np.mean(mean_power):.4f}')
print(f'Burst detected: {np.max(mean_power) > 5*np.mean(mean_power)}')
"
```

## 25. SDR Calibration and Signal Quality Verification

```bash
# Measure SDR frequency accuracy using known broadcast stations
rtl_test -t 2>&1 | grep "supported\|gain"
rtl_fm -f 100.1e6 -M fm -s 200k -r 32k -g 40 - | sox -t raw -r 32k -e signed -b 16 -c 1 - test_fm.wav

# HackRF calibration against GPS disciplined oscillator
hackrf_info | grep -i "serial\|firmware\|board"

# Verify sample rate accuracy with known test signal
hackrf_transfer -r calibration.raw -f 100.0e6 -s 10000000 -l 40 -g 30 -n 10000000
python3 -c "
import numpy as np
data = np.fromfile('calibration.raw', dtype=np.complex64)
# Verify center frequency by checking for DC offset
dc_offset = np.mean(data)
print(f'DC offset: {np.abs(dc_offset):.6f} (lower = better)')
print(f'Signal quality: {10*np.log10(np.var(data)/np.abs(dc_offset)**2):.1f} dB')
"
```
