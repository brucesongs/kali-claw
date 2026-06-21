# Licensed HF/VHF/UHF Radio Attack Payloads

This payload collection covers the licensed radio services below the cellular bands (handled in `5g-telecom-attack`) and above Sub-GHz ISM (handled in `sdr-rf-attack`). All receive-side commands are legal in most jurisdictions; transmit-side commands require explicit authorization and Faraday-cage containment.

**Hardware referenced**: HackRF One, BladeRF 2.0 micro, RTL-SDR (rtl-sdr.com V3), PlutoSDR, AirSpy R2/Mini/HF+ Discovery, SDRplay RSPdx.
**Software referenced**: dump1090-mutability, readsb, dump978, AIS-catcher, rtl_ais, multimon-ng, ACARSDeco, dumpvdl2, dumphfdl, direwolf, GQRX, SDR#, SDRangel, CubicSDR, GNU Radio, URH, fldigi.

---

## 1. SDR Hardware Setup and Calibration (HF/VHF/UHF)

```bash
# Verify HackRF One is detected with serial number and firmware
hackrf_info

# Check RTL-SDR v3 dongle with tuner type and supported gains
rtl_test -t

# Verify AirSpy HF+ Discovery (optimal for HF bands 9 kHz - 31 MHz)
airspy_rx --help 2>&1 | head -10

# Verify BladeRF 2.0 micro detection
bladerf-cli --probe

# Verify PlutoSDR (ADALM-PLUTO) via network
iio_info -u ip:192.168.2.1

# List all connected SDR devices
lsusb | grep -i "realtek\|hackrf\|nuand\|airspy\|analog\|sdrplay"
```

```bash
# Calibrate RTL-SDR PPM offset using a known reference (e.g., GSM BCCH or WWV at 10 MHz)
# Step 1: Estimate PPM using kalibrate-rtl against a known GSM carrier (legacy GSM only)
kal -g 40 -e > kal_ppm.txt
cat kal_ppm.txt | grep "average absolute error"

# Step 2: Apply PPM correction to subsequent decodes
DUMP1090_PPM=$(grep -oP "average absolute error: \K[0-9.]+" kal_ppm.txt | head -1)
dump1090 --net --gain 40 --ppm $DUMP1090_PPM
```

```bash
# Install all HF/VHF/UHF licensed-band decoders on Kali Linux
sudo apt update
sudo apt install -y \
  hackrf rtl-sdr airspy \
  dump1090-mutability readsb dump978 \
  multimon-ng direwolf fldigi \
  gqrx gnuradio gnuradio-dev urh inspectrum \
  sox

# Build modern aircraft data link decoders from source (not in Kali repos)
sudo apt install -y build-essential cmake git librtlsdr-dev libsoapysdr-dev \
  libusb-1.0-0-dev pkg-config

# ACARSDeco (closed-source freeware, download from xplordbd.co.uk)
# wget https://xplordbd.co.uk/acarsdeco2/acarsdeco2_rpi3_ubuntu20.tgz
# tar xzf acarsdeco2_*.tgz && cd acarsdeco2 && ./acarsdeco --help

# dumpvdl2 (open source VDL Mode 2 decoder)
git clone https://github.com/szpajder/dumpvdl2.git
cd dumpvdl2 && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j4
sudo make install

# dumphfdl (open source HFDL decoder)
git clone https://github.com/szpajder/dumphfdl.git
cd dumphfdl && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j4
sudo make install

# AIS-catcher (open source, multi-platform AIS decoder)
git clone https://github.com/jvde-github/AIS-catcher.git
cd AIS-catcher && mkdir build && cd build
cmake .. && make -j4
sudo make install
```

```bash
# Verify dump1090-mutability installation
dump1090 --help 2>&1 | head -20

# Verify multimon-ng protocols supported
multimon-ng --help 2>&1 | grep -E "POCSAG|FLEX|AFSK|ZVEI"

# Verify dumpvdl2 build
dumpvdl2 --version

# Verify dumphfdl build
dumphfdl --version

# Verify AIS-catcher
AIS-catcher --help 2>&1 | head -20
```

---

## 2. Antenna Setup and Selection (Band-Specific)

```bash
# Build a 1090 MHz collinear ADS-B antenna (8-element coaxial collinear)
# Reference design: 138 mm element length for 1090 MHz (half-wave at 1090 MHz = 138 mm)
# Total length: ~8 * 138 mm = 1.1 m vertical

# Calculate element length for any ADS-B frequency
python3 -c "
c = 299792458  # m/s
freq_hz = 1090e6
wavelength = c / freq_hz
half_wave = wavelength / 2
quarter_wave = wavelength / 4
print(f'1090 MHz wavelength: {wavelength*100:.1f} cm')
print(f'Half-wave element: {half_wave*100:.2f} cm = {half_wave*1000:.1f} mm')
print(f'Quarter-wave element: {quarter_wave*100:.2f} cm = {quarter_wave*1000:.1f} mm')
# Velocity factor of 0.85 for RG6 coax in collinear construction
print(f'Coax element (VF=0.85): {half_wave*0.85*1000:.1f} mm')
"
```

```bash
# Build a VHF marine antenna for AIS (161.975 MHz)
python3 -c "
c = 299792458  # m/s
freq_hz = 161.975e6
wavelength = c / freq_hz
half_wave = wavelength / 2
print(f'AIS channel A (161.975 MHz) wavelength: {wavelength*100:.1f} cm')
print(f'Half-wave element: {half_wave*100:.2f} cm = {half_wave*100:.0f} mm')
"

# J-pole antenna for AIS (popular homebrew design)
# 1/2 wave radiator: ~927 mm at 161.975 MHz
# 1/4 wave matching stub: ~463 mm at 161.975 MHz
```

```bash
# HF antenna setup for AirSpy HF+ Discovery
# Recommended: Magnetic loop or active antenna (Mini-Whip) for HF bands
# Wire dipole or random-length wire with balun for general HF reception

# Calculate dipole lengths for common HF bands
python3 -c "
bands = [
    ('160m', 1.8e6, 2.0e6),
    ('80m',  3.5e6, 4.0e6),
    ('40m',  7.0e6, 7.3e6),
    ('20m', 14.0e6, 14.35e6),
    ('HFDL oceanic', 2.941e6, 17.922e6),
    ('WWV',  10.0e6, 10.0e6),
    ('NDB',  0.190e6, 0.535e6),
]
c = 299792458
for name, f_low, f_high in bands:
    f_center = (f_low + f_high) / 2
    wavelength = c / f_center
    half_wave = wavelength / 2
    quarter_wave = wavelength / 4
    print(f'{name:15s} ({f_center/1e6:8.3f} MHz): half-wave {half_wave:.2f} m, quarter-wave {quarter_wave:.2f} m')
"
```

```bash
# VHF air band discone antenna (118-137 MHz) - wideband, multi-band coverage
# Commercial options: Diamond D130J, Comet DS300S, discone covers 25-1300 MHz
# Typical gain: 0-2 dBi (discones are low-gain but very wideband)

# Calculate wavelength for VHF air band
python3 -c "
c = 299792458
for freq_mhz in [118.0, 121.5, 131.55, 136.975, 137.0]:
    freq_hz = freq_mhz * 1e6
    wavelength = c / freq_hz
    print(f'{freq_mhz:7.3f} MHz: wavelength {wavelength:.3f} m, half-wave {wavelength/2:.3f} m')
"
```

---

## 3. Spectrum Survey of Licensed Bands

```bash
# Wideband survey of HF/VHF/UHF licensed bands (multi-hour scan)
rtl_power -f 100k:1500M:25k -i 10 -e 3600 -g 40 hf_vhf_uhf_survey.csv

# Generate heatmap from survey data
python3 -m urh.heatmap hf_vhf_uhf_survey.csv

# Focused survey of ATC voice band (118-137 MHz AM)
rtl_power -f 118M:137M:25k -i 5 -e 300 -g 40 atc_band.csv

# Identify active ATC frequencies
awk -F, '$6 > -50 {print $4, $5, $6}' atc_band.csv | sort -k3 -nr | head -20
```

```bash
# Focused survey of maritime VHF band (156-174 MHz)
rtl_power -f 156M:174M:25k -i 5 -e 300 -g 40 maritime_vhf.csv

# AIS channel monitoring
rtl_power -f 161.5M:162.5M:1k -i 1 -e 60 ais_channels.csv

# Pager band survey (typical US allocations)
# 138-174 MHz (VHF high), 440-470 MHz (UHF), 929-932 MHz (900 MHz)
rtl_power -f 929M:932M:10k -i 2 -e 300 pager_900.csv
rtl_power -f 138M:174M:5k -i 2 -e 300 pager_vhf.csv

# Find active pager frequencies
awk -F, '$6 > -45 {print $4, $6}' pager_900.csv | sort -k2 -nr | head -20
```

```bash
# HackRF sweep for wideband fast scanning (1 MHz resolution, 1 sec sweeps)
hackrf_sweep -f 100:1500 -l 32 -g 30 -w 1000000 -1 > hackrf_sweep.log

# ADS-B band check (1090 MHz ± 2 MHz)
rtl_power -f 1088M:1092M:100k -i 1 -e 30 -g 40 adsb_band.csv

# Quick ADS-B activity check
awk -F, '$6 > -30 {print "ADS-B activity detected at " $4 " MHz, power " $6 " dB"}' adsb_band.csv
```

```bash
# Continuous spectrum monitoring with HackRF (waterfall capture)
hackrf_sweep -f 100:1700 -l 32 -g 30 -w 250000 -B -1 > sweep_$(date +%Y%m%d_%H%M%S).log

# Real-time spectrum visualization with GQRX
gqrx -c licensed_bands.conf &
# In GQRX: set device, tune to frequency of interest, adjust FFT size 1024-8192

# SDRangel wideband monitoring (multiple channels simultaneously)
# Launch SDRangel and configure multiple Rx channels across bands
sdrangel &
```

---

## 4. ADS-B Aircraft Tracking (1090 MHz)

```bash
# Start dump1090-mutability with full features (web GUI on :8080)
dump1090 --net \
  --net-ro-port 30002 \
  --net-sbs-port 30003 \
  --net-bi-port 30004 \
  --net-bo-port 30005 \
  --gain 40 \
  --ppm 0 \
  --aggressive \
  --fix \
  --interactive \
  --write-json /run/dump1090-fa \
  --quiet &

# Check web GUI in browser at http://localhost:8080

# Verify dump1090 is receiving aircraft
nc localhost 30003 | head -20
# Expected: MSG messages with aircraft ICAO24, callsign, position
```

```bash
# Alternative: readsb (modern replacement for dump1090-fa)
readsb --net \
  --gain 40 \
  --device-type rtlsdr \
  --write-json /run/readsb \
  --quiet &

# readsb web interface typically on :8080
# Performance: readsb handles higher traffic loads than dump1090

# Check readsb status via JSON API
curl -s http://localhost:8080/data/aircraft.json | python3 -m json.tool | head -30
```

```bash
# Capture ADS-B raw I/Q at 1090 MHz for offline analysis (10 seconds)
rtl_sdr -f 1090000000 -s 2000000 -g 40 -n 20000000 adsb_10s.raw

# Decode ADS-B from raw I/Q capture
dump1090 --ifile adsb_10s.raw --fix --aggressive --quiet | head -30

# Decode with full output including raw messages
dump1090 --ifile adsb_10s.raw --fix --raw --quiet
```

```python
#!/usr/bin/env python3
"""ADS-B Aircraft Tracker - decode dump1090 Beast feed and track aircraft.

Connects to dump1090/readsb Beast output (port 30005) and maintains
a live database of tracked aircraft. Includes anomaly detection for
spoofed ICAO addresses and impossible trajectories.
"""

import socket
import struct
import time
from collections import defaultdict
from datetime import datetime


class ADSBTracker:
    """Track aircraft from ADS-B Beast feed and detect anomalies."""

    def __init__(self, host="127.0.0.1", port=30005):
        self.host = host
        self.port = port
        self.aircraft = {}  # ICAO24 -> dict
        self.anomalies = []

    def connect(self):
        """Connect to dump1090 Beast output."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")

    def parse_beast(self, data):
        """Parse Beast binary format from dump1090/readsb.

        Beast format: 0x1A + msg_type(1) + signal(1) + timestamp(6) + payload
        msg_type: 0x31 = Mode AC, 0x32 = Mode S short, 0x33 = Mode S long
        """
        messages = []
        i = 0
        while i < len(data) - 10:
            if data[i] == 0x1A:
                msg_type = data[i+1]
                if msg_type == 0x33:  # Mode S long (112 bits = 14 bytes)
                    payload = data[i+9:i+9+14]
                    if len(payload) == 14:
                        messages.append(payload)
                    i += 23
                elif msg_type == 0x32:  # Mode S short (56 bits = 7 bytes)
                    payload = data[i+9:i+9+7]
                    messages.append(payload)
                    i += 16
                else:
                    i += 1
            else:
                i += 1
        return messages

    def decode_adsb_position(self, msg):
        """Decode ADS-B Message Type 11 (Airborne Position) - simplified."""
        icao24 = msg[1:4].hex().upper()
        msg_type = msg[4] >> 3
        if msg_type in (11, 17, 18, 20, 21, 22):  # Position report types
            # Simplified: extract just the format type
            return icao24, msg_type
        return icao24, None

    def track(self, duration_seconds=60):
        """Track aircraft for the specified duration."""
        start = time.time()
        while time.time() - start < duration_seconds:
            data = self.sock.recv(4096)
            messages = self.parse_beast(data)
            for msg in messages:
                if len(msg) >= 5:
                    icao24, msg_type = self.decode_adsb_position(msg)
                    if icao24:
                        if icao24 not in self.aircraft:
                            self.aircraft[icao24] = {
                                "first_seen": datetime.now().isoformat(),
                                "msg_count": 0,
                            }
                            print(f"[NEW] {icao24} first seen")
                        self.aircraft[icao24]["msg_count"] += 1
                        self.aircraft[icao24]["last_seen"] = datetime.now().isoformat()
        return self.aircraft


if __name__ == "__main__":
    tracker = ADSBTracker()
    tracker.connect()
    aircraft = tracker.track(duration_seconds=300)
    print(f"\n=== Summary: {len(aircraft)} unique aircraft tracked ===")
    for icao24, info in sorted(aircraft.items(),
                                key=lambda x: x[1]["msg_count"],
                                reverse=True):
        print(f"{icao24}: {info['msg_count']} messages")
```

```bash
# ADS-B anomaly detection: look for impossible trajectories
python3 << 'PYEOF'
import json
import requests
from datetime import datetime, timedelta

# Pull recent aircraft from readsb JSON
data = requests.get("http://localhost:8080/data/aircraft.json").json()
print(f"Total aircraft tracked: {len(data['aircraft'])}")

# Look for spoofed or anomalous aircraft
anomalies = []
for ac in data["aircraft"]:
    icao = ac.get("hex", "")
    flight = ac.get("flight", "").strip()
    alt = ac.get("alt_baro")
    speed = ac.get("gs")  # ground speed in knots
    lat = ac.get("lat")
    lon = ac.get("lon")

    # Check for impossible speeds (>1500 knots ground speed is unusual for civil)
    if speed and speed > 1500:
        anomalies.append(f"[SPEED] {icao} ({flight}): {speed} knots")

    # Check for impossible altitudes (>80000 ft is unusual for civil)
    if alt and isinstance(alt, (int, float)) and alt > 80000:
        anomalies.append(f"[ALT] {icao} ({flight}): {alt} ft")

    # Check for missing callsign (might be military or spoofed)
    if not flight and lat and lon:
        anomalies.append(f"[NO_CALL] {icao} at ({lat:.4f}, {lon:.4f})")

if anomalies:
    print(f"\n=== {len(anomalies)} anomalies detected ===")
    for a in anomalies[:20]:
        print(a)
else:
    print("No anomalies detected")
PYEOF
```

```bash
# Feed ADS-B data to FlightAware PiAware aggregator (with account credentials)
# Requires PiAware package installed
sudo piaware-config flightaware-user YOUR_USERNAME
sudo piaware-config flightaware-password YOUR_PASSWORD
sudo systemctl restart piaware

# Check PiAware status
sudo piaware-status

# Feed to Flightradar24 (requires fr24feed)
sudo fr24feed --signup
sudo systemctl start fr24feed
```

---

## 5. ADS-B Spoofing Research (Authorized, Faraday Cage Only)

> **CRITICAL LEGAL WARNING**: Transmitting on 1090 MHz without an FCC Part 87 license is a federal crime in the US and illegal in virtually all jurisdictions. The following commands are documented for **research context only** and must never be executed outside a shielded enclosure. The reference research (Povolny 2012, Costin & Francillon 2012) was conducted in controlled lab environments.

```bash
# Research reference: Povolny & Wang (2012) ADS-B spoofing with USRP
# Trivial to spoof ADS-B because messages have NO authentication
# Paper: "On the Security of the ADS-B Protocol" (Povolny, 2012)

# Costin & Francillon (2012) "Ghost in the Air" - demonstrated ADS-B
# vulnerabilities using RTL-SDR (RX) and simple SDR TX

# Capture a valid ADS-B message for analysis (RX only)
rtl_sdr -f 1090000000 -s 2000000 -g 40 -n 20000000 adsb_sample.raw
dump1090 --ifile adsb_sample.raw --raw --quiet | head -20

# Example raw ADS-B message (Mode S long):
# Format: *8D40621D58C382D690C8AC2863A7;
# 8D = downlink format 17 (ADS-B)
# 40621D = ICAO24 address (aircraft)
# 58C382D690C8AC2863A7 = payload + parity
```

```bash
# Authorized research: generate ADS-B test frames in Faraday cage
# This script DOCUMENTS the technique -- DO NOT execute outside a shielded enclosure

python3 << 'PYEOF'
"""
ADS-B Test Frame Generator - for authorized research only.

Generates valid ADS-B frames for testing receiver implementations
INSIDE A FARADAY CAGE. Never transmit on live 1090 MHz spectrum.

Reference: Povolny ADS-B spoofing (2012), Costin "Ghost in the Air" (2012)
"""

def crc24_mode_s(data):
    """Compute Mode S 24-bit CRC (used for both parity and address extraction)."""
    # Generator polynomial for Mode S
    G = 0xFFFA0480  # 25-bit polynomial, x^24 + ... 
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            if crc & 0x800000:
                crc = ((crc << 1) ^ G) & 0xFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFF
    return crc


def build_adsb_airborne_position(icao24, ca, tc, alt_ft, lat, lon, cpr_format):
    """Build ADS-B Type 17 Message CF=0 (Airborne Position).
    
    Args:
        icao24: 24-bit ICAO address (e.g., 0x40621D)
        ca: 3-bit capability (e.g., 5 = airborne, IDENT)
        tc: 5-bit type code (11 = Airborne Position Barometric)
        alt_ft: barometric altitude in feet
        lat, lon: latitude/longitude (floats)
        cpr_format: 0 = even, 1 = odd
    """
    df_ca = (17 << 3) | ca  # Downlink format 17 + capability
    msg = bytearray(11)
    msg[0] = df_ca
    
    # Type code and CPR format bit
    msg[1] = (tc << 3) | (0 << 2) | (0 << 1) | cpr_format
    
    # Altitude (encode in 25 ft increments, simplified)
    alt_enc = (alt_ft // 25) & 0x7FF  # 11 bits
    msg[2] = (msg[2] & 0x80) | ((alt_enc >> 3) & 0x7F)
    msg[3] = ((alt_enc & 0x07) << 5) | 0x00  # spare bits
    
    # CPR encoded position (simplified - full CPR encoding is more complex)
    cprlat = int((lat + 90.0) / 360.0 * 131072) & 0x1FFFF  # 17 bits
    cprlon = int((lon + 180.0) / 360.0 * 131072) & 0x1FFFF
    
    msg[5] = (cprlat >> 9) & 0xFF
    msg[6] = (cprlat >> 1) & 0xFF
    msg[7] = ((cprlat & 0x01) << 7) | ((cprlon >> 10) & 0x7F)
    msg[8] = (cprlon >> 2) & 0xFF
    msg[9] = ((cprlon & 0x03) << 6)
    msg[10] = 0  # Time and parity bits will be added
    
    # Compute CRC24 parity
    parity = crc24_mode_s(bytes(msg[:11]))
    msg[8] |= (parity >> 16) & 0xFF
    msg[9] |= (parity >> 8) & 0xFF
    msg[10] |= parity & 0xFF
    
    # Output the frame (for documentation purposes only)
    frame_hex = ''.join(f'{b:02X}' for b in msg)
    print(f"[RESEARCH] ADS-B position frame (DO NOT TRANSMIT): {frame_hex}")
    print(f"  ICAO24: {icao24:06X}, Altitude: {alt_ft} ft, Position: ({lat}, {lon}), CPR format: {'odd' if cpr_format else 'even'}")
    return bytes(msg)


# Example: generate a TEST frame (never transmit!)
# Using a fictional ICAO24 to avoid collision with real aircraft
print("=== ADS-B Test Frame Generator (research documentation) ===")
print("NOTE: Transmitting on 1090 MHz without a license is a federal crime.")
print("These frames are for receiver testing INSIDE A FARADAY CAGE only.")
print()
frame = build_adsb_airborne_position(
    icao24=0xCAFE00,  # fictional test address
    ca=5,
    tc=11,
    alt_ft=35000,
    lat=40.0,
    lon=-74.0,
    cpr_format=0
)
PYEOF
```

```bash
# ADS-B signal structure reference (Costin & Francillon 2012):
# - 1090 MHz carrier, 1 MHz bandwidth
# - Pulse Position Modulation (PPM)
# - 1 microsecond per bit, 120 microseconds total for long message
# - 56-bit short (Mode S interrogation reply) or 112-bit long (ADS-B)
# - NO authentication, NO encryption
# - Receiver cannot distinguish spoofed from real signal

# Document the protocol weaknesses for the engagement report:
cat << 'EOF' > adsb_security_findings.md
# ADS-B Security Findings

## Protocol Weaknesses
1. **No authentication**: ADS-B messages contain no cryptographic signature or MAC.
   Any SDR transmitter can broadcast valid-looking ADS-B messages.

2. **No encryption**: All position, identity, and velocity data is broadcast in clear.

3. **No sender verification**: ICAO24 address is a static 24-bit identifier.
   Spoofing another aircraft's address is trivial.

4. **No replay protection**: Captured ADS-B messages can be replayed verbatim.

5. **Trivial jamming**: A single continuous carrier at 1090 MHz can deafen receivers.

## Documented Attacks
- Povolny (2012): ADS-B spoofing with USRP
- Costin & Francillon (2012): "Ghost in the Air" RTL-SDR attacks
- Multiple DEF CON presentations on ADS-B vulnerabilities

## Mitigations
- **Short-term**: Multilateration (MLAT) cross-validation, behavior-based anomaly detection
- **Medium-term**: Cryptographic authentication (ADS-B Sec, proposed in ICAO standards)
- **Long-term**: Replace ADS-B with authenticated next-gen surveillance
EOF

cat adsb_security_findings.md
```

---

## 6. UAT (978 MHz) Decoding

```bash
# UAT operates on 978 MHz in US airspace (lower-density general aviation)
# dump978 is the standard decoder (fork of dump1090)

# Build dump978 from source
git clone https://github.com/mutability/dump978.git
cd dump978 && make

# Start dump978 with RTL-SDR
./dump978 --rtlsdr --sbs1  --gain 40 --freq-correction 0 &

# Verify UAT reception (different from 1090 MHz ADS-B)
nc localhost 30978 | head -10

# Combine dump1090 + dump978 for full US ADS-B coverage
# dump1090 web GUI can consume both via piaware bridge
```

```bash
# TIS-B (Traffic Information Service - Broadcast) on UAT
# Provides MLAT-derived positions for non-ADS-B aircraft
# Decoded by dump978 alongside ADS-B messages

# Capture raw UAT I/Q
rtl_sdr -f 978000000 -s 2000000 -g 40 -n 20000000 uat_sample.raw

# Decode from raw capture
./dump978 --ifile uat_sample.raw

# UAT message types
# Message type 0: Header info
# Message types 1-9: Various UAT uplink/downlink
# FIS-B (Flight Information Service - Broadcast): weather and NOTAMs
```

---

## 7. AIS Maritime Vessel Tracking (161.975 / 162.025 MHz)

```bash
# Start AIS-catcher with RTL-SDR (modern, multi-platform decoder)
AIS-catcher -u 12345 -v -T -g 40 &

# Verify AIS reception on UDP port 12345 (NMEA-0183 format)
nc -u -l 12345 | head -20

# Forward AIS to OpenCPN chartplotter (UDP port 10110)
AIS-catcher -u 127.0.0.1:10110 -v
```

```bash
# Alternative: rtl_ais (simpler two-channel decoder)
rtl_ais -T -p -h 127.0.0.1 -P 12345 -g 40 &

# Capture raw AIS I/Q for offline analysis
rtl_sdr -f 161975000 -s 250000 -g 40 -n 2500000 ais_ch_a.raw
rtl_sdr -f 162025000 -s 250000 -g 40 -n 2500000 ais_ch_b.raw

# Decode AIS from raw capture
AIS-catcher --input ais_ch_a.raw --output ais_decoded.json

# View decoded vessels
python3 -c "
import json
with open('ais_decoded.json') as f:
    vessels = json.load(f)
print(f'Decoded vessels: {len(vessels)}')
for v in vessels[:10]:
    print(f'  MMSI {v.get(\"mmsi\")}: {v.get(\"shipname\", \"unknown\")} at ({v.get(\"lat\")}, {v.get(\"lon\")})')
"
```

```python
#!/usr/bin/env python3
"""AIS Vessel Tracker - track maritime vessels from AIS feed.

Connects to AIS-catcher or rtl_ais NMEA-0183 UDP output and maintains
a live database of vessels. Includes dark target detection and MMSI
spoofing detection.
"""

import socket
import json
import time
from datetime import datetime, timedelta


class AISTracker:
    """Track vessels from AIS NMEA feed."""

    def __init__(self, listen_port=12345):
        self.listen_port = listen_port
        self.vessels = {}  # MMSI -> vessel data
        self.last_position = {}  # MMSI -> (lat, lon, timestamp)
        self.anomalies = []

    def listen(self, duration_seconds=300):
        """Listen for AIS NMEA sentences for the specified duration."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.listen_port))
        sock.settimeout(5.0)
        
        start = time.time()
        while time.time() - start < duration_seconds:
            try:
                data, addr = sock.recvfrom(4096)
                sentence = data.decode("ascii", errors="ignore").strip()
                self.parse_nmea(sentence)
            except socket.timeout:
                continue
        return self.vessels

    def parse_nmea(self, sentence):
        """Parse AIS NMEA-0183 sentence (simplified)."""
        # Format: !AIVDM,1,1,,A,<payload>,<checksum>
        if not sentence.startswith("!AIVDM"):
            return
        
        parts = sentence.split(",")
        if len(parts) < 6:
            return
        
        payload = parts[5]
        # Decode 6-bit ASCII to binary (simplified - real parsing is more complex)
        # This is a placeholder for actual AIS payload decoding
        try:
            msg_type = self.decode_6bit_char(payload[0])
            if msg_type in (1, 2, 3):
                self.handle_position_report(payload)
            elif msg_type == 5:
                self.handle_static_voyage(payload)
            elif msg_type == 18:
                self.handle_class_b_position(payload)
        except Exception as e:
            pass

    def decode_6bit_char(self, c):
        """Decode a single 6-bit AIS character."""
        v = ord(c) - 48
        if v > 40:
            v -= 56
        return v

    def handle_position_report(self, payload):
        """Handle AIS message types 1/2/3 (position report class A)."""
        # Simplified - full decoder is complex
        # Real implementations use libraries like libais or pyais
        pass

    def handle_static_voyage(self, payload):
        """Handle AIS message type 5 (static and voyage data)."""
        pass

    def handle_class_b_position(self, payload):
        """Handle AIS message type 18 (class B position)."""
        pass

    def detect_dark_targets(self, known_mmsis):
        """Detect vessels operating without AIS (dark targets).
        
        Args:
            known_mmsis: set of MMSIs that should be transmitting
        
        Returns:
            List of MMSIs that are not currently transmitting
        """
        now = datetime.now()
        dark = []
        for mmsi in known_mmsis:
            if mmsi not in self.vessels:
                dark.append(mmsi)
            elif "last_seen" in self.vessels[mmsi]:
                last = datetime.fromisoformat(self.vessels[mmsi]["last_seen"])
                if now - last > timedelta(minutes=10):
                    dark.append(mmsi)
        return dark

    def detect_mmsi_spoofing(self):
        """Detect potential MMSI spoofing (impossible positions or duplicate IDs)."""
        # Look for two vessels with the same MMSI but different positions
        # (impossible unless one is spoofed)
        # Placeholder for implementation
        pass


if __name__ == "__main__":
    tracker = AISTracker()
    vessels = tracker.listen(duration_seconds=60)
    print(f"\n=== Tracked {len(vessels)} vessels ===")
    for mmsi, info in vessels.items():
        print(f"  MMSI {mmsi}: {info}")
```

```bash
# AIS anomaly detection: dark vessel tracking
python3 << 'PYEOF'
import requests
from datetime import datetime, timedelta

# Pull vessel data from AIS-catcher HTTP API (if enabled)
# Alternative: parse from UDP feed
import socket
import json

# Known vessels to monitor for "dark" status
known_vessels = {
    367000000: "USCG Vessel A",
    366900000: "Fishing Vessel B",
    # Add MMSIs from client engagement scope
}

print(f"Monitoring {len(known_vessels)} known vessels for dark status")
print("(Dark = no AIS transmission in last 10 minutes)")

# This would connect to AIS feed and check each known vessel
# Implementation depends on engagement setup
PYEOF
```

```bash
# AIS-catcher advanced options
# Multiple SDRs for dual-channel reception
AIS-catcher -c rtl_tcp:127.0.0.1:1234 -c rtl_tcp:127.0.0.1:1235 -g 40 -u 12345 -v

# JSON output to file for logging
AIS-catcher --json-file ais_log.json --rotate 24 -g 40

# Web GUI mode (built-in)
AIS-catcher -w 8080 -g 40 &  # Web interface on port 8080

# Decode from recorded file for forensic analysis
AIS-catcher --input ais_recording.cu8 --output ais_forensic.json
```

---

## 8. AIS Spoofing Research (Authorized, Faraday Cage Only)

> **CRITICAL LEGAL WARNING**: Transmitting on 161.975 MHz or 162.025 MHz without an FCC Part 80 (maritime stations) license is illegal in the US and most jurisdictions. AIS spoofing research must be conducted in shielded enclosures only. Reference: Trend Micro's maritime AIS research documented widespread spoofing in contested waters.

```bash
# Research reference: Trend Micro maritime AIS research (2019-2020)
# Documented extensive AIS spoofing in locations like the South China Sea,
# Black Sea, and other contested waters. Spoofing patterns:
# - Circular patterns (multiple vessels in physically impossible formation)
# - Vessels appearing on land
# - Vessels with impossible speed/distance

# Capture a valid AIS message for protocol analysis
rtl_sdr -f 161975000 -s 250000 -g 40 -n 2500000 ais_valid.raw

# Document AIS protocol weaknesses for the engagement report:
cat << 'EOF' > ais_security_findings.md
# AIS Security Findings

## Protocol Weaknesses
1. **No authentication**: AIS messages have no cryptographic authentication.
   Any VHF transmitter can broadcast valid AIS position reports.

2. **No encryption**: All vessel identity, position, course, and speed is
   broadcast in clear text.

3. **MMSI is a static identifier**: 9-digit Maritime Mobile Service Identity
   is not cryptographically bound to the vessel. Spoofing is trivial.

4. **No replay protection**: Captured AIS messages can be replayed verbatim.

5. **Class B (small vessels) easy to spoof**: Lower transmission power
   means a Class B position report can be generated with minimal hardware.

## Documented Spoofing Patterns (Trend Micro research)
- Circular formations of spoofed vessels around contested islands
- Vessels "appearing" inland (impossible positions)
- Mass vessel spoofing in oil terminals (thousands of fake vessels)
- Spoofed MMSIs of military vessels

## Mitigations
- **Short-term**: Cross-reference AIS with radar (vessel must be visible)
- **Medium-term**: Satellite AIS backup (Sat-AIS on Orbcomm/Iridium)
- **Long-term**: AIS-S (secure AIS with authentication, not yet deployed)
EOF

cat ais_security_findings.md
```

```bash
# AIS message structure reference (for protocol analysis)
python3 << 'PYEOF'
"""AIS Message Structure Reference.

Documents the structure of AIS messages for protocol security analysis.
NO TRANSMISSION -- documentation only.
"""

AIS_MESSAGE_TYPES = {
    1: "Position Report Class A",
    2: "Position Report Class A (Assigned)",
    3: "Position Report Class A (Response)",
    4: "Base Station Report",
    5: "Static and Voyage Related Data",
    6: "Binary Addressed Message",
    7: "Binary Acknowledge",
    8: "Binary Broadcast Message",
    9: "SAR Aircraft Position Report",
    10: "UTC and Date Inquiry",
    11: "UTC and Date Response",
    12: "Addressed Safety-Related Message",
    13: "Safety-Related Acknowledgement",
    14: "Safety-Related Broadcast Message",
    15: "Interrogation",
    16: "Assignment Mode Command",
    17: "GNSS Binary Broadcast Message",
    18: "Standard Class B CS Position Report",
    19: "Extended Class B CS Position Report",
    20: "Data Link Management",
    21: "Aid-to-Navigation Report",
    22: "Channel Management",
    23: "Group Assignment Command",
    24: "Class B CS Static Data Report",
    25: "Single Slot Binary Message",
    26: "Multiple Slot Binary Message",
    27: "Position Report For Long-Range Applications",
}

print("=== AIS Message Types ===")
for type_id, desc in AIS_MESSAGE_TYPES.items():
    print(f"  Type {type_id:2d}: {desc}")

print()
print("=== AIS Physical Layer ===")
print("Modulation: GMSK (Gaussian Minimum Shift Keying)")
print("Bandwidth: 25 kHz")
print("Symbol rate: 9600 baud")
print("Channels: 161.975 MHz (A), 162.025 MHz (B)")
print("Power: Class A 12.5W, Class B 2W, Base station 12.5W")
print()
print("=== AIS Framing ===")
print("Training sequence: 24 bits (0101...0101)")
print("Start flag: 8 bits (HDLC 0x7E)")
print("Data: 168 bits minimum")
print("CRC: 16 bits (ITU-T CRC-16)")
print("End flag: 8 bits (HDLC 0x7E)")
print("Buffer: ~6 bits")
print()
print("=== AIS Security Analysis ===")
print("Encryption: NONE")
print("Authentication: NONE")
print("Integrity: CRC-16 only (no cryptographic protection)")
print("Replay protection: NONE")
print("Sender authentication: MMSI is a static identifier")
PYEOF
```

---

## 9. ACARS Airline Communications (131.550 MHz)

```bash
# Decode ACARS at 131.550 MHz AM using ACARSDeco
# ACARSDeco is closed-source freeware from xplordbd.co.uk
acarsdeco -r 0:131550000 -g 40 --silence-level 5 --gain-control on &

# Web GUI typically on port 8080
# http://localhost:8080

# Alternative: open-source acarsdec
acarsdec -r 0 131550000 -g 40 -v &

# Capture raw ACARS I/Q for offline analysis
rtl_sdr -f 131550000 -s 250000 -g 40 -n 25000000 acars.raw
```

```bash
# ACARS message structure reference
# Modulation: AM (amplitude modulation) with MSK subcarrier
# Frequency: 131.550 MHz (primary), 131.725, 131.525 (alternate US)
# Baud rate: 2400 bps
# Protocol: character-oriented with bit-oriented framing

# ACARS channels commonly observed:
# - 131.550 MHz - Primary worldwide
# - 131.725 MHz - US alternate
# - 131.525 MHz - US alternate
# - 130.025 MHz - Europe
# - 131.450 MHz - Asia/Pacific
# - 136.750 MHz - Europe Inmarsat liaison
# - 136.800 MHz - Europe
# - 136.900 MHz - Europe

# Scan all common ACARS channels
for freq in 129.125 130.025 130.450 130.700 131.125 131.300 131.450 131.525 131.550 131.725 131.825 136.700 136.750 136.800 136.900; do
    echo "Scanning $freq MHz..."
    timeout 10 rtl_power -f ${freq}e6 -s 25k -i 1 -e 5 acars_${freq}.csv 2>/dev/null
    awk -F, -v freq=$freq '$6 > -40 {print freq, $6}' acars_${freq}.csv | head -1
done
```

```python
#!/usr/bin/env python3
"""ACARS Message Logger - log and analyze ACARS messages.

Connects to ACARSDeco output (typically a JSON feed on a local port)
and logs messages with content analysis for OPSEC review.
"""

import socket
import json
import re
from datetime import datetime
from collections import defaultdict


class ACARSLogger:
    """Log and analyze ACARS messages for engagement OPSEC review."""

    # Sensitive patterns to flag in ACARS content
    SENSITIVE_PATTERNS = [
        (r"\bMAYDAY\b|\bPAN\b", "distress_call"),
        (r"\bHIJACK\b", "security_alert"),
        (r"\bBOMB\b", "security_alert"),
        (r"\bDIVERT?\b", "operational_diversion"),
        (r"\bFUEL\b", "fuel_status"),
        (r"\bMEDICAL\b", "medical_event"),
        (r"\b[A-Z]{2,3}\d{1,4}\b", "flight_number"),
        (r"\b[A-Z]+\b\s*[A-Z]+\b", "possible_names"),
    ]

    def __init__(self, listen_port=5555):
        self.listen_port = listen_port
        self.messages = []
        self.aircraft_messages = defaultdict(list)
        self.sensitive_events = []

    def listen(self, duration_seconds=3600):
        """Listen for ACARS messages."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.listen_port))
        sock.settimeout(5.0)
        
        start = datetime.now()
        while (datetime.now() - start).total_seconds() < duration_seconds:
            try:
                data, addr = sock.recvfrom(4096)
                msg = json.loads(data.decode("ascii", errors="ignore"))
                self.process_message(msg)
            except socket.timeout:
                continue
            except json.JSONDecodeError:
                continue
        return self.messages

    def process_message(self, msg):
        """Process a single ACARS message."""
        tail = msg.get("tail", "")
        flight = msg.get("flight", "")
        text = msg.get("text", "")
        timestamp = msg.get("timestamp", datetime.now().isoformat())
        
        entry = {
            "timestamp": timestamp,
            "tail": tail,
            "flight": flight,
            "text": text,
            "flags": [],
        }
        
        # Apply sensitive pattern matching
        for pattern, flag_name in self.SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                entry["flags"].append(flag_name)
                self.sensitive_events.append(entry)
        
        self.messages.append(entry)
        self.aircraft_messages[tail].append(entry)
        
        # Print in real-time for OPSEC monitoring
        flags_str = f" [{', '.join(entry['flags'])}]" if entry["flags"] else ""
        print(f"[{timestamp}] {tail} ({flight}){flags_str}: {text[:80]}")

    def summary(self):
        """Generate summary statistics."""
        print(f"\n=== ACARS Summary ===")
        print(f"Total messages: {len(self.messages)}")
        print(f"Unique aircraft: {len(self.aircraft_messages)}")
        print(f"Sensitive events: {len(self.sensitive_events)}")
        print()
        print("=== Most active aircraft ===")
        for tail, msgs in sorted(self.aircraft_messages.items(),
                                   key=lambda x: len(x[1]),
                                   reverse=True)[:10]:
            print(f"  {tail}: {len(msgs)} messages")
        print()
        if self.sensitive_events:
            print("=== Sensitive events ===")
            for e in self.sensitive_events[:20]:
                print(f"  [{e['timestamp']}] {e['tail']}: {', '.join(e['flags'])} - {e['text'][:60]}")


if __name__ == "__main__":
    logger = ACARSLogger()
    logger.listen(duration_seconds=300)  # 5 minutes
    logger.summary()
```

```bash
# ACARS channel scanning with multiple SDRs (parallel monitoring)
# Setup: 4x RTL-SDR dongles monitoring 4 ACARS channels simultaneously
# Useful for capturing all traffic in a busy airspace

# Channel 1: 131.550 (primary worldwide)
# Channel 2: 131.725 (US alternate)
# Channel 3: 131.525 (US alternate)
# Channel 4: 136.975 (VDL Mode 2 - see next section)

# Launch each decoder on its own RTL-SDR (using index parameter)
acarsdec -r 0 131550000 -g 40 -o acars_0.json &
acarsdec -r 1 131725000 -g 40 -o acars_1.json &
acarsdec -r 2 131525000 -g 40 -o acars_2.json &

# Aggregate logs
wait
python3 -c "
import json
all_msgs = []
for i in range(3):
    try:
        with open(f'acars_{i}.json') as f:
            all_msgs.extend(json.load(f))
    except:
        pass
print(f'Aggregated {len(all_msgs)} messages across 3 channels')
"
```

---

## 10. VDL Mode 2 (136.975 MHz)

```bash
# Decode VDL Mode 2 at 136.975 MHz using dumpvdl2
dumpvdl2 --gain 40 --corrupted-messages --output decoded:text:file:stdout &

# Capture raw VDL Mode 2 I/Q for offline analysis
rtl_sdr -f 136975000 -s 250000 -g 40 -n 25000000 vdlm2.raw

# Decode VDL Mode 2 from raw capture
dumpvdl2 --ifile vdlm2.raw --gain 40 --output decoded:text:file:stdout

# JSON output for programmatic processing
dumpvdl2 --gain 40 --output decoded:json:file:stdout 2>/dev/null | \
  python3 -m json.tool | head -30
```

```bash
# VDL Mode 2 specification reference
# Frequency: 136.975 MHz worldwide (single channel)
# Modulation: D8PSK (Differential 8-Phase Shift Keying)
# Symbol rate: 31500 symbols/sec (10500 bits/sec)
# Channel spacing: 25 kHz
# Protocol: AVLC (Aviation VHF Link Control) based on HDLC

# VDL Mode 2 vs ACARS:
# - VDL Mode 2 is ~10x faster (31.5 kbps vs 2.4 kbps)
# - VDL Mode 2 carries ACARS-over-VDL (AOV) traffic
# - VDL Mode 2 will eventually replace ACARS for most airline comms
# - Same lack of encryption/authentication as ACARS

# Multi-SDR monitoring of ACARS + VDL Mode 2 simultaneously
acarsdec -r 0 131550000 -g 40 --output acars.json &
dumpvdl2 -r 1 --gain 40 --output decoded:json:file:vdlm2.json &

# Aggregate both feeds for unified aircraft comms view
python3 << 'PYEOF'
import json
from datetime import datetime

acars_msgs = []
vdlm2_msgs = []

try:
    with open("acars.json") as f:
        acars_msgs = json.load(f)
except:
    pass

try:
    with open("vdlm2.json") as f:
        for line in f:
            if line.strip():
                vdlm2_msgs.append(json.loads(line))
except:
    pass

print(f"ACARS messages: {len(acars_msgs)}")
print(f"VDL Mode 2 messages: {len(vdlm2_msgs)}")
print(f"Total aircraft data link messages: {len(acars_msgs) + len(vdlm2_msgs)}")

# Cross-reference to find aircraft using both ACARS and VDL Mode 2
acars_aircraft = set(m.get("tail", "") for m in acars_msgs if m.get("tail"))
vdlm2_aircraft = set(m.get("src", {}).get("addr", "") for m in vdlm2_msgs if m.get("src", {}).get("addr"))

overlap = acars_aircraft & vdlm2_aircraft
print(f"\nAircraft using BOTH ACARS and VDL Mode 2: {len(overlap)}")
PYEOF
```

---

## 11. HFDL Oceanic Aircraft Comms (Multiple HF Bands)

```bash
# Decode HFDL (High Frequency Data Link) using dumphfdl
# HFDL uses multiple HF frequencies across the world for oceanic coverage
# Hardware recommendation: AirSpy HF+ Discovery (best HF dynamic range)

# HFDL ground station frequencies (worldwide network)
# Typical allocations (each station uses subsets):
# - 2941 kHz (Riverhead NY, Kanto Japan, etc.)
# - 5455 kHz
# - 8927 kHz
# - 11306 kHz
# - 15025 kHz
# - 17922 kHz
# - 21928 kHz, 21934 kHz (rarely used)

# Monitor all HFDL ground stations simultaneously
dumphfdl --gain 40 --output decoded:text:file:stdout \
  2941000 5455000 8927000 11306000 15025000 17922000 &

# Capture HFDL with AirSpy HF+ Discovery (9 kHz - 31 MHz)
airspy_rx -f 8927 -r hfdl_8927.air -g 12 -b 192000 -n 1920000

# Decode from raw capture
dumphfdl --ifile hfdl_8927.air --output decoded:text:file:stdout
```

```bash
# HFDL specification reference
# Frequency bands: 2.8-22 MHz (variable, propagation-dependent)
# Modulation: DPSK at 300/600/1200/1800 bps (phase and bit rate vary)
# Protocol: Based on ARINC 635
# Used by: Oceanic flights beyond VHF range, trans-polar flights

# HFDL ground station operators:
# - ARINC (US - Riverhead NY, San Francisco CA, Molokai HI)
# - SITA (Europe, Asia, Africa)
# - Various Pacific/oceanic stations

# Document HFDL activity (research context)
python3 << 'PYEOF'
"""HFDL Activity Monitor - document oceanic aircraft comms.

Passive observation of HFDL traffic to characterize oceanic
aircraft communications in the engagement area.
"""

import subprocess
import re
from collections import defaultdict

# Run dumphfdl for 10 minutes and capture output
proc = subprocess.Popen(
    ["dumphfdl", "--gain", "40",
     "--output", "decoded:text:file:stdout",
     "2941000", "5455000", "8927000", "11306000", "15025000", "17922000"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
)

ground_stations = defaultdict(int)
aircraft = defaultdict(int)
msg_count = 0

try:
    for line in proc.stdout:
        if "HFDL" in line or "Ground station" in line:
            msg_count += 1
            # Parse ground station ID
            gs_match = re.search(r"Ground station: (\w+)", line)
            if gs_match:
                ground_stations[gs_match.group(1)] += 1
            
            # Parse aircraft identifier
            ac_match = re.search(r"Aircraft: (\w+)", line)
            if ac_match:
                aircraft[ac_match.group(1)] += 1
            
            if msg_count >= 100:
                break
finally:
    proc.terminate()

print(f"\n=== HFDL Activity (100 messages captured) ===")
print(f"Ground stations observed: {len(ground_stations)}")
for gs, count in sorted(ground_stations.items(), key=lambda x: -x[1])[:10]:
    print(f"  {gs}: {count} messages")

print(f"\nAircraft observed: {len(aircraft)}")
for ac, count in sorted(aircraft.items(), key=lambda x: -x[1])[:10]:
    print(f"  {ac}: {count} messages")
PYEOF
```

---

## 12. POCSAG Pager Decoding (138-174 MHz, 440-470 MHz, 929-932 MHz)

```bash
# Decode POCSAG at 1200 bps (most common) via rtl_fm + multimon-ng
rtl_fm -f 157.775e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -

# Decode POCSAG and FLEX simultaneously (where present)
rtl_fm -f 929.5e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX -

# Decode POCSAG directly from RTL-SDR via the multimon-ng rtl backend
multimon-ng -t rtl --rtl-frequency 157775000 --rtl-gain 40 \
  -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX
```

```bash
# Capture pager I/Q for offline analysis
rtl_sdr -f 157775000 -s 250000 -g 40 -n 25000000 pager_157.raw

# Decode from captured WAV file
# First convert raw I/Q to 22050 Hz mono WAV
sox -t raw -r 250000 -e signed-integer -b 16 -c 2 pager_157.raw \
  -r 22050 -c 1 pager_157.wav

# Decode WAV with multimon-ng
multimon-ng -t wav -a POCSAG1200 -a FLEX pager_157.wav

# Decode from live rtl_fm stream captured to WAV
rtl_fm -f 157.775e6 -s 22050 -g 40 -l 0 -r 22050 pager_live.wav
multimon-ng -t wav -a POCSAG1200 pager_live.wav
```

```python
#!/usr/bin/env python3
"""POCSAG Pager Decoder and PHI Auditor.

Decodes POCSAG pager messages and audits them for Protected Health
Information (PHI) and other sensitive data. Useful for HIPAA
security assessments of hospital pager fleets.

Reference: DEF CON 18 (Andrea Barisani) - "Pager networks: intercepting
messages nationwide"
"""

import re
import subprocess
import json
from datetime import datetime
from collections import defaultdict


class POCSAGAuditor:
    """Decode POCSAG messages and audit for sensitive data exposure."""

    # PHI patterns (HIPAA-relevant)
    PHI_PATTERNS = [
        (r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "date"),  # DOB
        (r"\bMRN[:\s]*\d+\b", "medical_record_number"),
        (r"\bDR[\.\s]?\s*[A-Z]+\b", "physician_name"),
        (r"\bROOM[:\s]*\d+\b", "room_number"),
        (r"\bICU\b|CCU\b|ER\b|ED\b|OR\b", "department"),
        (r"\b[A-Z]+\s*,\s*[A-Z][a-z]+\b", "possible_name"),  # LAST, First
        (r"\b\d{3}-\d{3}-\d{4}\b", "phone_number"),
    ]

    # Common dispatch patterns
    DISPATCH_PATTERNS = [
        (r"\bALARM\b", "alarm"),
        (r"\bFIRE\b", "fire_dispatch"),
        (r"\bMEDICAL\b", "medical_dispatch"),
        (r"\bPOLICE\b", "police_dispatch"),
        (r"\b911\b", "emergency_response"),
    ]

    def __init__(self):
        self.messages = []
        self.capcodes = defaultdict(int)
        self.phi_findings = []
        self.dispatch_findings = []

    def decode_stream(self, duration_seconds=300):
        """Run multimon-ng and parse output."""
        proc = subprocess.Popen(
            ["multimon-ng", "-t", "rtl",
             "--rtl-frequency", "157775000",
             "--rtl-gain", "40",
             "-a", "POCSAG512",
             "-a", "POCSAG1200",
             "-a", "POCSAG2400",
             "-a", "FLEX"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True
        )
        
        start = datetime.now()
        for line in proc.stdout:
            if (datetime.now() - start).total_seconds() > duration_seconds:
                break
            self.parse_line(line.strip())
        proc.terminate()
    
    def parse_line(self, line):
        """Parse a multimon-ng output line."""
        # Example: POCSAG1200: Address: 12345  Function: 0  Alpha:   Hello world
        # Or: POCSAG512: Address: 12345  Function: 0  Numeric: 12345
        
        addr_match = re.search(r"Address:\s+(\d+)", line)
        func_match = re.search(r"Function:\s+(\d+)", line)
        alpha_match = re.search(r"Alpha:\s+(.+?)(?:$|\s{2,})", line)
        numeric_match = re.search(r"Numeric:\s+(.+?)(?:$|\s{2,})", line)
        
        if not addr_match:
            return
        
        capcode = int(addr_match.group(1))
        function = int(func_match.group(1)) if func_match else None
        message = alpha_match.group(1).strip() if alpha_match else \
                  (numeric_match.group(1).strip() if numeric_match else "")
        
        if not message:
            return
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "capcode": capcode,
            "function": function,
            "message": message,
            "phi_flags": [],
            "dispatch_flags": [],
        }
        
        # Audit for PHI
        for pattern, flag in self.PHI_PATTERNS:
            if re.search(pattern, message, re.IGNORECASE):
                entry["phi_flags"].append(flag)
                self.phi_findings.append(entry)
        
        # Audit for dispatch codes
        for pattern, flag in self.DISPATCH_PATTERNS:
            if re.search(pattern, message, re.IGNORECASE):
                entry["dispatch_flags"].append(flag)
                self.dispatch_findings.append(entry)
        
        self.messages.append(entry)
        self.capcodes[capcode] += 1
        
        # Print flagged messages
        flags = entry["phi_flags"] + entry["dispatch_flags"]
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        print(f"[{entry['timestamp']}] {capcode}{flag_str}: {message[:80]}")
    
    def report(self):
        """Generate PHI exposure report."""
        print(f"\n=== POCSAG PHI Exposure Report ===")
        print(f"Total messages decoded: {len(self.messages)}")
        print(f"Unique pager IDs (capcodes): {len(self.capcodes)}")
        print(f"Messages with PHI indicators: {len(self.phi_findings)}")
        print(f"Messages with dispatch codes: {len(self.dispatch_findings)}")
        
        print(f"\n=== PHI Exposure Breakdown ===")
        phi_types = defaultdict(int)
        for entry in self.phi_findings:
            for flag in entry["phi_flags"]:
                phi_types[flag] += 1
        for phi_type, count in sorted(phi_types.items(), key=lambda x: -x[1]):
            print(f"  {phi_type}: {count} messages")
        
        print(f"\n=== Top Pager IDs (potential department identification) ===")
        for capcode, count in sorted(self.capcodes.items(), key=lambda x: -x[1])[:10]:
            print(f"  Capcode {capcode}: {count} messages")
        
        # HIPAA-relevant summary
        phi_rate = len(self.phi_findings) / max(len(self.messages), 1) * 100
        print(f"\n=== HIPAA Assessment ===")
        print(f"PHI exposure rate: {phi_rate:.1f}% of messages")
        print(f"Recommendation: ", end="")
        if phi_rate > 10:
            print("CRITICAL - Immediate migration to encrypted paging required")
        elif phi_rate > 1:
            print("HIGH - Plan migration to secure messaging within 90 days")
        elif phi_rate > 0:
            print("MEDIUM - Review and remediate specific PHI sources")
        else:
            print("LOW - No PHI exposure detected in sample")


if __name__ == "__main__":
    auditor = POCSAGAuditor()
    print("Monitoring POCSAG pager traffic for 5 minutes...")
    print("(Adjust frequency 157.775 MHz to your target pager band)")
    auditor.decode_stream(duration_seconds=300)
    auditor.report()
```

```bash
# FLEX protocol decoding (more sophisticated pager protocol)
# FLEX speeds: 1600 bps, 3200 bps, 6400 bps (4-level FSK)
# FLEX frequencies: typically 929-932 MHz (US), 161-166 MHz (varies)

# Decode FLEX at 929.5 MHz
rtl_fm -f 929.5e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a FLEX -

# FLEX is harder to decode than POCSAG due to:
# - 4-level FSK (vs 2-level POCSAG)
# - Sync phases (each FLEX frame is one of 4 sync phases)
# - Frame addressing (capcode mapped to frame cycle)
# - Block structure (data and parity blocks)

# Alternative: build flex-decoder from source (older tool)
git clone https://github.com/EliasOenal/multimon-ng.git
cd multimon-ng && mkdir build && cd build
cmake ..
make FLEX_SUPPORT=ON
```

```bash
# Document pager protocol findings for the engagement report
cat << 'EOF' > pager_security_findings.md
# Pager Network Security Findings

## POCSAG Protocol Analysis
- Modulation: 2-level FSK, ±4.5 kHz deviation
- Baud rates: 512, 1200, 2400 bps
- Preamble: 576 bits of 1010 reversal (allows receivers to sync)
- Sync codeword: 32-bit fixed pattern (0x7CD215D8 or 0x7CF21436)
- Address (capcode): 18-bit pager identifier
- Function bits: 2-bit (0/1/2/3 = numeric/tone1/tone2/alpha)
- Message: alphanumeric or numeric, no length limit (multi-block)
- CRC: 10-bit Bose-Chaudhuri-Hocquenghem (BCH) per codeword

## FLEX Protocol Analysis
- Modulation: 4-level FSK
- Baud rates: 1600, 3200, 6400 bps
- Sync phases: 4 (A, B, C, D) to balance pager wake cycles
- Capcode: up to 2 billion addresses supported
- Block structure: data blocks with error correction
- Far more efficient than POCSAG for high-volume paging

## Security Assessment
1. **No encryption**: All pager messages broadcast in clear text
2. **No authentication**: No verification of sender identity
3. **No integrity protection**: BCH codes detect errors but don't prevent tampering
4. **Receiver is anonymous**: Anyone can receive any pager message
5. **Sender verification requires**: Capcode-to-subscriber mapping (held by paging provider)

## Documented Attacks
- DEF CON 18 (Andrea Barisani & Matteo "Empire" Mancini):
  "Pager networks: intercepting messages nationwide"
  Demonstrated nationwide coverage of hospital/EMS pagers from single rooftop
- Multiple demonstrations of pager message modification research
- Historical: Kevin Mitnick pager message capture (1990s)

## Mitigations
- **HIPAA-mandated**: Migrate PHI-bearing pagers to encrypted alternatives
- **Secure messaging**: Wickr, Signal, or vendor-specific encrypted pagers
- **Network segmentation**: Paging providers should offer encrypted channels
- **Subscriber audit**: Regular review of active capcodes for unauthorized pagers
EOF

cat pager_security_findings.md
```

---

## 13. APRS Amateur Radio Position Reporting

```bash
# Decode APRS at 144.39 MHz (US national frequency) using multimon-ng
rtl_fm -f 144.39e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a AFSK1200 -

# Alternative: direwolf (full-featured AX.25 KISS TNC)
# direwolf is much more capable than multimon-ng for APRS
# Build direwolf from source or apt install direwolf
sudo apt install direwolf

# Run direwolf as a receive-only TNC
direwolf -t 0 -r 22050 -b 16 -d 1 - &

# Pipe rtl_fm output to direwolf
rtl_fm -f 144.39e6 -s 48000 -g 40 - | \
  direwolf -r 48000 -b 16 -n - &

# Decode APRS at 144.64 MHz (European frequency)
rtl_fm -f 144.64e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a AFSK1200 -
```

```bash
# APRS specification reference
# Frequency: 144.39 MHz (US), 144.64 MHz (EU), 145.175 MHz (Australia)
# Modulation: AFSK 1200 baud Bell 202 modem
# Tones: 1200 Hz (mark), 2200 Hz (space)
# Bandwidth: 12 kHz
# Protocol: AX.25 UI frames carrying APRS text

# APRS common packet types:
# - Position reports (lat/lon, symbol, comment)
# - Status messages
# - Messages (one-to-one or bulletin)
# - Announcements
# - Weather (with NWS severe weather alerts)
# - Telemetry (battery voltage, sensor data)
# - Objects and Items (POIs on map)

# Connect direwolf to Xastir or YAAC for map visualization
# direwolf KISS TCP port 8001
# Xastir/APRSC connectivity via KISS-over-TCP
```

```python
#!/usr/bin/env python3
"""APRS Position Tracker - decode and map amateur radio position reports.

Useful for OPSEC assessment of amateur radio infrastructure and for
understanding the data exposure of APRS users.
"""

import re
import socket
from datetime import datetime
from collections import defaultdict


class APRSTracker:
    """Track stations from APRS traffic."""

    def __init__(self, kiss_host="127.0.0.1", kiss_port=8001):
        self.kiss_host = kiss_host
        self.kiss_port = kiss_port
        self.stations = {}  # callsign -> station data
        self.messages = []
    
    def parse_aprs(self, raw_frame):
        """Parse an APRS frame (simplified)."""
        # APRS position format example:
        # :CALLSIGN>APRS,TCPIP*,qAC,SERVER:!DDMM.mmN/DDDMM.mmW>comment
        # Or for messages:
        # :CALLSIGN>APRS,TCPIP*,qAC::TARGET   :Hello
        
        # Look for position indicator (!, =, /, @)
        match = re.search(
            r"[!/=@]([0-9]{4}\.[0-9]{2})([NS])/([0-9]{5}\.[0-9]{2})([EW])",
            raw_frame
        )
        if match:
            lat_deg = float(match.group(1)[:2])
            lat_min = float(match.group(1)[2:])
            lat = lat_deg + lat_min / 60
            if match.group(2) == "S":
                lat = -lat
            
            lon_deg = float(match.group(3)[:3])
            lon_min = float(match.group(3)[3:])
            lon = lon_deg + lon_min / 60
            if match.group(4) == "W":
                lon = -lon
            
            return {"type": "position", "lat": lat, "lon": lon}
        
        # Look for message
        if "::" in raw_frame:
            return {"type": "message", "raw": raw_frame}
        
        return {"type": "other", "raw": raw_frame}
    
    def process(self, duration_seconds=60):
        """Listen to direwolf KISS TCP and process frames."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.kiss_host, self.kiss_port))
        except ConnectionRefusedError:
            print(f"Cannot connect to direwolf KISS at {self.kiss_host}:{self.kiss_port}")
            print("Start direwolf with: direwolf -p")
            return
        
        sock.settimeout(5.0)
        start = datetime.now()
        
        while (datetime.now() - start).total_seconds() < duration_seconds:
            try:
                data = sock.recv(4096)
                # Strip KISS framing (0xC0 delimiters)
                frame = data.replace(b"\xc0", b"").replace(b"\xdb\xdc", b"\xc0").replace(b"\xdb\xdd", b"\xdb")
                try:
                    text = frame.decode("ascii", errors="ignore")
                    parsed = self.parse_aprs(text)
                    if parsed.get("type") == "position":
                        callsign_match = re.match(r"([A-Z0-9]+)", text)
                        callsign = callsign_match.group(1) if callsign_match else "UNKNOWN"
                        self.stations[callsign] = parsed
                        print(f"[POS] {callsign}: {parsed['lat']:.4f}, {parsed['lon']:.4f}")
                    elif parsed.get("type") == "message":
                        self.messages.append(parsed)
                        print(f"[MSG] {parsed['raw'][:80]}")
                except Exception:
                    continue
            except socket.timeout:
                continue
        
        return self.stations


if __name__ == "__main__":
    tracker = APRSTracker()
    stations = tracker.process(duration_seconds=60)
    print(f"\n=== Tracked {len(stations)} APRS stations ===")
```

---

## 14. NDB Aviation Beacon Tracking (190-535 kHz, 1750 kHz AM)

```bash
# Listen to NDB (Non-Directional Beacon) signals using GQRX
# NDB operates in two bands:
# - 190-535 kHz (LF/MF band, mostly in US/Europe)
# - 535-1705 kHz AM broadcast band (rare, where AM broadcast not used)
# - 1750 kHz (rare, sometimes used for marine/NDB dual purpose)

# GQRX for CW/AM reception
gqrx -c ndb.conf &
# In GQRX:
# - Set demodulator to CW (narrow bandwidth 100-200 Hz)
# - Or AM mode with narrow filter (3 kHz)
# - Tune to known NDB frequency (e.g., 357 kHz)

# Capture NDB I/Q with AirSpy HF+ Discovery (best HF receiver)
airspy_rx -f 357 -r ndb_357.air -g 12 -b 192000 -n 1920000

# Decode NDB Morse code identifier using multimon-ng (limited CW support)
# multimon-ng has -a CW (experimental CW decode)
multimon-ng -t wav -a CW ndb_357.wav 2>&1 | head -20
```

```bash
# NDB frequency database reference
# NDBs are listed in FAA publications and aviation databases
# Each NDB has a 1-3 letter Morse identifier (sent every few seconds)

# Common US NDB frequency ranges:
# - 190-415 kHz: Aviation NDB (non-directional beacon)
# - 510-535 kHz: Travelers Information Stations (TIS/HIS)
# - 1610-1700 kHz: Limited NDB use (mostly AM broadcast)

# Find NDBs in the FAA database
# FAA NDB data: https://www.faa.gov/air_traffic/flight_info/aeronav/productcatalog
# Look for: NDBs with their Morse identifier and frequency

# Script to scan the NDB band
python3 << 'PYEOF'
import subprocess

# Scan 190-535 kHz for NDB signals (12 kHz resolution, slow)
print("Scanning NDB band 190-535 kHz...")
proc = subprocess.run([
    "rtl_power",  # or airspy_rx for better HF performance
    "-f", "190000:535000:1000",
    "-i", "5",
    "-e", "60",
    "-g", "40",
    "ndb_scan.csv"
], capture_output=True, text=True)

# Find peaks above noise
import csv
with open("ndb_scan.csv") as f:
    reader = csv.reader(f)
    peaks = []
    for row in reader:
        if len(row) < 6:
            continue
        try:
            freq_low = float(row[2])
            freq_high = float(row[3])
            power = float(row[6])  # peak power in dB
            if power > -30:
                peaks.append((freq_low, freq_high, power))
        except (ValueError, IndexError):
            continue

peaks.sort(key=lambda x: -x[2])
print(f"\n=== Top 10 NDB candidates ===")
for low, high, power in peaks[:10]:
    freq_khz = (low + high) / 2 / 1000
    print(f"  {freq_khz:.1f} kHz: {power:.1f} dB")
PYEOF
```

```bash
# NDB Morse code identifier decode
# Each NDB broadcasts a 1-3 letter Morse identifier at ~10-20 WPM

python3 << 'PYEOF'
"""NDB Morse Code Identifier Decoder.

Decodes Morse code from a captured NDB signal to identify the beacon.
"""

MORSE_TO_ALPHA = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-----": "0",
}

def decode_morse(morse_string):
    """Decode a Morse code string to alphanumeric."""
    words = morse_string.split(" / ")  # word separator
    decoded = []
    for word in words:
        letters = word.split(" ")
        word_text = "".join(MORSE_TO_ALPHA.get(l, "?") for l in letters)
        decoded.append(word_text)
    return " ".join(decoded)

# Example: decode known NDB identifiers
test_morse = "... .- --"  # "SAM"
print(f"Morse '{test_morse}' decodes to: {decode_morse(test_morse)}")

# NDB identifier patterns:
# 2-letter: typically 2-letter IATA airport codes
# 3-letter: ICAO identifiers or unique beacons
# Common NDBs are listed in aviation databases
PYEOF
```

---

## 15. Weather Fax (HF Radiofax)

```bash
# Weather fax (radiofax) is broadcast by meteorological services on HF
# Common providers: NOAA (US), DWD (Germany), JMA (Japan), MeteoFrance

# NOAA Weather Fax frequencies (US)
# - 4.625 MHz (Boston)
# - 4.805, 6.344.5, 9.110 MHz (New Orleans)
# - 8.682, 12.788, 17.527.5, 22.910.5, 26.190 MHz (Pt Reyes CA)

# Capture weather fax I/Q
airspy_rx -f 9110 -r wxfax_9110.air -g 12 -b 192000 -n 19200000

# Decode weather fax with fldigi
# fldigi has a dedicated Weather Fax mode
# In fldigi: Op Mode -> WEFAX-576 (IOC mode)
# Or use the command line interface

# Decode with multiPSK (Windows) or fldigi (Linux)
fldigi --wefax-spectrum on &
# In fldigi GUI:
# 1. Tune to frequency (e.g., 9.110 MHz USB)
# 2. Set Op Mode -> WEFAX
# 3. Adjust volume and sync

# Alternative: jvx (Java View Fax) - specialized weather fax decoder
# java -jar jvx.jar
```

```bash
# Weather fax specification reference
# Modulation: FM (subcarrier modulates an AM carrier)
# Audio frequencies:
# - Black: 1500 Hz
# - White: 2300 Hz
# - Sync: 300 Hz start tone, 675 Hz phasing
# IOC (Index of Cooperation): 576 (most common) or 288
# Rotation speed: 120 lpm (lines per minute)
# Image size: typical 800x800 px or larger

# Capture weather fax audio from GQRX
# In GQRX: Tune to 9.110 MHz USB, record audio to WAV
gqrx -c wxfax.conf &
# File -> Record Audio -> Start

# Decode recorded audio with fldigi
fldigi --decode-file wxfax_audio.wav --op-mode WEFAX-576

# Document weather fax reception for maritime engagement OPSEC
cat << 'EOF' > wxfax_findings.md
# Weather Fax Reception Findings

## Available Weather Fax Broadcasts

### NOAA (US) Marine Weather Fax
- Transmitters: Boston MA, New Orleans LA, Pt Reyes CA, Kodiak AK
- Frequencies: 4-26 MHz (propagation-dependent)
- Content: Surface analysis, sea state, ice charts, satellite imagery
- Schedule: Continuous broadcast per published schedule

### DWD (Germany) Weather Fax
- Transmitter: Hamburg/Pinnow
- Frequencies: Various HF
- Coverage: North Atlantic, Mediterranean, North Sea

### JMA (Japan) Weather Fax
- Transmitter: Tokyo, Osaka, Sapporo
- Coverage: Western Pacific, Japan coastal waters

## Relevance to Maritime Engagement OPSEC
- Weather fax is a one-way broadcast (no RF signature from receivers)
- Reception is fully legal in international waters
- Provides situational awareness without revealing receiver position
- Mariners rely on weather fax as backup to satellite weather
EOF

cat wxfax_findings.md
```

---

## 16. DSC (Digital Selective Calling) Maritime Distress

```bash
# Decode DSC on VHF Channel 70 (156.525 MHz)
# DSC is the maritime distress and calling system

# rtl-dsc or alternative DSC decoder
# Note: dedicated DSC decoders are less common than AIS decoders
# multimon-ng has limited DSC support via FSK demodulation

rtl_fm -f 156.525e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a DTMF - 2>&1 | head -20

# More accurate: build a dedicated DSC decoder
# DSC specification:
# - Frequency: 156.525 MHz (VHF), 2187.5 kHz (MF), various HF
# - Modulation: GFSK 1200 bps
# - Protocol: ITU-R M.493 (older) or M.825 (newer, simpler)

# Capture DSC on Channel 70
rtl_sdr -f 156525000 -s 250000 -g 40 -n 25000000 dsc_ch70.raw
```

```bash
# DSC frequencies worldwide:
# VHF: 156.525 MHz (Channel 70)
# MF: 2187.5 kHz
# HF: 4207.5, 6312.0, 8414.5, 12577.0, 16804.5 kHz

# Monitor MF/HF DSC with AirSpy HF+ Discovery
airspy_rx -f 2187.5 -r dsc_mf.air -g 12 -b 192000 -n 1920000

# Document DSC protocol
python3 << 'PYEOF'
"""DSC Protocol Reference.

Documents the structure of Digital Selective Calling (DSC) messages
for maritime distress infrastructure assessment.
"""

DSC_MESSAGE_TYPES = {
    "Distress": {
        "code": "112",
        "purpose": "Vessel in distress",
        "priority": "Mayday",
    },
    "Distress Acknowledgement": {
        "code": "113",
        "purpose": "Coast station acknowledges distress",
        "priority": "Mayday",
    },
    "Distress Relay": {
        "code": "112",
        "purpose": "Relay distress alert (vessel or coast station)",
        "priority": "Mayday",
    },
    "All Ships": {
        "code": "116",
        "purpose": "Urgent/safety message to all vessels",
        "priority": "Pan-Pan / Securite",
    },
    "Routine Individual": {
        "code": "120",
        "purpose": "Routine call to specific vessel",
        "priority": "Routine",
    },
    "Position": {
        "code": "121",
        "purpose": "Position request/response",
        "priority": "Routine",
    },
    "Test": {
        "code": "122",
        "purpose": "DSC system test",
        "priority": "Routine",
    },
}

print("=== DSC Message Types ===")
for msg_type, info in DSC_MESSAGE_TYPES.items():
    print(f"  {msg_type}: code {info['code']}, priority {info['priority']}")

print()
print("=== DSC Security Analysis ===")
print("Modulation: GFSK 1200 bps")
print("Encryption: NONE")
print("Authentication: NONE (MMSI is a static identifier)")
print("Integrity: Error correcting code (ECC) but no cryptographic protection")
print("Replay protection: NONE")
print()
print("=== DSC False Alert Problem ===")
print("Documented operational issue: high rate of false distress alerts")
print("Causes: accidental activation, equipment malfunction, testing errors")
print("Impact: Coast guard resources diverted from real emergencies")
print("Spoofing risk: low barrier to injecting false alerts")
PYEOF
```

---

## 17. ATC Voice (118-137 MHz AM) and Maritime VHF Voice

```bash
# Listen to ATC voice on 118-137 MHz AM (air traffic control)
# Common frequencies (varies by airport):
# - 121.500 MHz: Emergency (guard frequency)
# - 122.750 MHz: Air-to-air
# - 121.925 MHz: Ground control (varies)
# - Airport-specific: 118.300, 119.000, etc.

# Listen with rtl_fm in AM mode
rtl_fm -M am -f 121.5e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# Listen to ATIS (Automatic Terminal Information Service)
# ATIS broadcasts continuous recorded airport information
# Frequency: typically 118-136 MHz range, airport-specific
rtl_fm -M am -f 124.55e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -
```

```bash
# Scan ATC band for active frequencies
rtl_power -f 118M:137M:25k -i 5 -e 300 -g 40 atc_band.csv

# Identify top ATC frequencies by activity
awk -F, '$6 > -50 {print $4, $5, $6}' atc_band.csv | \
  sort -k3 -nr | head -20

# Listen to maritime VHF Channel 16 (156.8 MHz) - international distress
rtl_fm -M fm -f 156.8e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# Listen to Channel 13 (156.65 MHz) - bridge-to-bridge
rtl_fm -M fm -f 156.65e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -
```

```bash
# Record ATC voice to file for OPSEC analysis
rtl_fm -M am -f 118.3e6 -s 12000 -r 12000 -g 40 - | \
  sox -t s16 -r 12000 -c 1 - atc_118300_$(date +%Y%m%d_%H%M%S).wav

# Continuous ATC voice monitoring with timestamps (24-hour capture)
while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    timeout 600 rtl_fm -M am -f 121.5e6 -s 12000 -r 12000 -g 40 - 2>/dev/null | \
      sox -t s16 -r 12000 -c 1 - atc_guard_${TIMESTAMP}.wav
done &

# Transcribe ATC voice with Whisper (optional)
# pip install openai-whisper
# whisper atc_118300.wav --model base --language English
```

```bash
# 8.33 kHz channel spacing (Europe and increasingly worldwide)
# ATC band in Europe uses 8.33 kHz channel spacing (vs 25 kHz in US)
# Channel designation: 118.000, 118.005, 118.010, 118.015, etc.
# Use 8000 Hz sample rate for narrowband capture

rtl_fm -M am -f 118.305e6 -s 8000 -r 8000 -g 40 - | \
  play -r 8000 -t s16 -L -c 1 -

# Document ATC voice findings
cat << 'EOF' > atc_voice_findings.md
# ATC Voice Monitoring Findings

## Legal Status
- **Receiving**: Generally legal in most jurisdictions
- **Disclosure**: US FCC rules and equivalent may restrict disclosure
- **Use**: Real-time listening for situational awareness is common practice

## Information Exposure
- Aircraft callsigns (flight numbers)
- Pilot/controller names
- Clearances (altitudes, headings, runways)
- ATC coordination (handoffs, sector boundaries)
- Emergency communications on 121.5 MHz

## OPSEC Implications for Aviation-Adjacent Facilities
- A facility near a flight path can monitor ATC voice without detection
- ATC traffic reveals facility operations, traffic patterns, and intent
- Recorded ATC can be used for post-incident forensic analysis

## Counter-Surveillance
- No practical RF countermeasure (AM broadcast is by design)
- Operational: avoid discussing sensitive info near ATC frequencies
- Future: encrypted ATC voice (TETRA, P25) - not yet deployed

## Channel Spacing Reference
- US: 25 kHz channels (118.000, 118.025, 118.050, ...)
- Europe: 8.33 kHz channels (118.000, 118.005, 118.010, ...)
- Air-to-air: 122.750 MHz (US), 122.700 MHz (US alternate)
- Emergency: 121.500 MHz (guard, monitored by all aircraft)
EOF

cat atc_voice_findings.md
```

---

## 18. MLAT, TIS-B, and Inmarsat/Iridium L-band (Context)

```bash
# MLAT (Multilateration) - Time Difference of Arrival (TDOA) aircraft tracking
# Uses Mode S transponder timing across multiple receivers
# Requires cooperative receivers (PiAware, Flightradar24 network)

# dump1090-mutability can feed MLAT data
dump1090 --net --mlat --write-json /run/dump1090-fa --quiet &

# PiAware automatically enables MLAT with enough peer receivers
sudo systemctl start piaware
sudo piaware-config allow-mlat yes

# TIS-B (Traffic Information Service - Broadcast)
# Broadcasts aircraft positions derived from ground radar
# Received on 1090 MHz or 978 MHz UAT alongside ADS-B

# UAT (978 MHz) carries TIS-B and FIS-B (weather)
dump978 --rtlsdr --gain 40 --freq-correction 0 &

# Inmarsat and Iridium L-band reception (1525-1660 MHz)
# Requires L-band antenna and SDR with 2 MHz+ bandwidth

# Inmarsat STD-C (fleet messaging) at 1530-1545 MHz
# Used by maritime fleet, journalists, government
# Decoded by open-source Inmarsat decoders (research tools)
rtl_sdr -f 1537.5e6 -s 2000000 -g 40 -n 20000000 inmarsat_stdc.raw

# Iridium at 1616-1626.5 MHz
# Decoded by iridium-toolkit (research tool)
rtl_sdr -f 1624e6 -s 2000000 -g 40 -n 20000000 iridium.raw

# Note: Full satellite exploitation is out of scope for this skill
# See sdr-rf-attack/satellite-signal-analysis-guide.md for NOAA/AIS/ADS-B satellites
```

```bash
# Document L-band satellite reception findings
cat << 'EOF' > lband_satellite_findings.md
# L-band Satellite Reception (Context Only)

## Inmarsat (1525-1559 MHz downlink)
- Services: Fleet (maritime), SwiftBroadband (aircraft), BGAN (broadband)
- STD-C: 600 bps messaging, used for fleet comms, safety
- STD-C is unencrypted for many maritime users

## Iridium (1616-1626.5 MHz)
- 66 LEO satellites providing global coverage
- Bursty transmissions, SBD (Short Burst Data) messages
- Some traffic is unencrypted (commercial users)

## Inmarsat/Iridium Reception
- Hardware: SDR with L-band coverage (HackRF, AirSpy, SDRplay)
- Antenna: L-band patch or helix antenna with LNA
- Decoders: research tools only, not in standard repos

## Relevance to Engagement OPSEC
- L-band satellite reception reveals maritime comms without AIS
- Iridium bursts can indicate remote asset communications
- Reception is legal in most jurisdictions (broadcast nature)
- Full satellite exploitation requires dedicated setup and out of this skill's scope

## Adjacent Coverage
- See sdr-rf-attack/guides/satellite-signal-analysis-guide.md for:
  - NOAA weather satellite image reception (137 MHz)
  - Satellite AIS (Sat-AIS on Orbcomm)
  - Satellite ADS-B (Aireon on Iridium)
EOF

cat lband_satellite_findings.md
```

---

## 19. Protocol Reverse Engineering with URH

```bash
# URH (Universal Radio Hacker) for licensed band signal analysis
# Useful when no dedicated decoder exists for a target signal

# Capture signal for URH analysis
rtl_sdr -f 1090e6 -s 2e6 -g 40 -n 2000000 adsb_urh.raw

# Launch URH GUI
urh

# In URH:
# 1. File -> Open -> select captured .raw file
# 2. Set sample rate (2 MSPS for ADS-B)
# 3. Set center frequency (1090 MHz)
# 4. Use "Autodetect modulation parameters"
# 5. View bit-level decoded signal
# 6. Compare with known protocol structure

# URH CLI for batch analysis
urh_cli -p adsb_urf.raw -m ASK -s 2000000 --center 0.0
```

```bash
# Capture unknown signal for reverse engineering
rtl_sdr -f 162e6 -s 250000 -g 40 -n 2500000 unknown_162.raw

# Analyze with URH
urh unknown_162.raw

# URH protocol analysis workflow:
# 1. Open captured signal
# 2. Set modulation parameters (ASK/FSK/PSK)
# 3. Set sample rate and bit length
# 4. View decoded bits
# 5. Identify preamble/sync word
# 6. Label fields (address, command, payload, checksum)
# 7. Save protocol definition
# 8. Generate replay signal (TX with HackRF - Faraday cage only)
```

---

## 20. GNU Radio for Custom Licensed Band Decoders

```python
#!/usr/bin/env python3
"""GNU Radio flowgraph template for licensed band signal processing.

Template for building custom decoders when off-the-shelf tools don't
support a target licensed protocol. Modify for the specific signal.
"""

# Place in: gnuradio/flows/licensed_band_decoder.py
# Run with: python3 licensed_band_decoder.py

import os
import sys
from gnuradio import gr, blocks, filter, analog, digital
from gnuradio import audio
try:
    from gnuradio import rtlsdr
    HAS_RTLSDR = True
except ImportError:
    HAS_RTLSDR = False


class LicensedBandDecoder(gr.top_block):
    """Custom decoder template for licensed band signals.
    
    Modify the center frequency, sample rate, and demodulator
    for the specific target signal.
    """
    
    def __init__(self, center_freq=1090e6, samp_rate=2e6, gain=40):
        gr.top_block.__init__(self, "Licensed Band Decoder")
        
        ##################################################
        # Variables
        ##################################################
        self.center_freq = center_freq
        self.samp_rate = samp_rate
        self.gain = gain
        
        ##################################################
        # Blocks
        ##################################################
        if HAS_RTLSDR:
            self.source = rtlsdr.rtlsdr_source(
                samp_rate=int(samp_rate),
                center_freq=int(center_freq),
                gain=gain,
                if_gain=0,
                bb_gain=0,
            )
        else:
            # Fallback to file source for offline analysis
            self.source = blocks.file_source(
                gr.sizeof_gr_complex,
                "input.complex",
                False
            )
        
        # Demodulator (example: AM demod for ATC voice)
        # Replace with appropriate demodulator for target signal
        self.mag = blocks.complex_to_mag(1)
        self.demod = blocks.multiply_const_ff(1.0)
        
        # Audio output (for voice signals)
        self.audio_sink = audio.sink(int(48000), "")
        
        # Resampler
        self.resampler = filter.rational_resampler_fff(
            interpolation=24,
            decimation=int(samp_rate / 2000),
        )
        
        ##################################################
        # Connections
        ##################################################
        self.connect(self.source, self.mag)
        self.connect(self.mag, self.demod)
        self.connect(self.demod, self.resampler)
        self.connect(self.resampler, self.audio_sink)


if __name__ == "__main__":
    # Example: listen to ATC voice on 118.3 MHz AM
    tb = LicensedBandDecoder(center_freq=118.3e6, samp_rate=2e6, gain=40)
    tb.start()
    
    try:
        input("Press Enter to stop...\n")
    except EOFError:
        pass
    
    tb.stop()
    tb.wait()
```

```bash
# GNU Radio Companion (GRC) for visual flowgraph design
gnuradio-companion &

# GRC example workflow for licensed band decoder:
# 1. Add "Osmocom Source" block (RTL-SDR)
# 2. Set center frequency and sample rate
# 3. Add demodulator (AM Demod for ATC voice, Quadrature Demod for FM)
# 4. Add audio sink or file sink
# 5. Execute flowgraph

# Save GRC flowgraphs as .grc files for reuse
# Example: adsb_decoder.grc, atc_voice_listener.grc, ais_decoder.grc

# Convert GRC to Python script for automation
grcc -d ./generated_adsb_decoder.grc ./generated_adsb_decoder.py
```

---

## 21. Wideband Monitoring and Recording

```bash
# Continuous wideband monitoring with HackRF sweep
hackrf_sweep -f 100:1500 -l 32 -g 30 -w 250000 -1 -B > sweep_$(date +%Y%m%d).log &

# Periodic snapshots of HF/VHF/UHF bands (every hour for OPSEC baseline)
while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    rtl_power -f 100k:1500M:100k -i 5 -e 60 -g 40 hourly_${TIMESTAMP}.csv 2>/dev/null
    sleep 3540  # ~59 minutes
done &

# Generate daily activity summary
python3 << 'PYEOF'
import os
import csv
from collections import defaultdict
from datetime import datetime

# Find all hourly CSV files
csv_files = sorted([f for f in os.listdir(".") if f.startswith("hourly_") and f.endswith(".csv")])

band_activity = defaultdict(int)

for csv_file in csv_files[-24:]:  # Last 24 hours
    with open(csv_file) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 6:
                continue
            try:
                freq_low = float(row[2])
                freq_high = float(row[3])
                power = float(row[6])
                
                # Classify band
                center = (freq_low + freq_high) / 2
                if center < 300e3:
                    band = "LF"
                elif center < 3e6:
                    band = "MF"
                elif center < 30e6:
                    band = "HF"
                elif center < 300e6:
                    band = "VHF"
                else:
                    band = "UHF"
                
                if power > -30:
                    band_activity[band] += 1
            except (ValueError, IndexError):
                continue

print(f"\n=== Daily RF Activity Summary ({datetime.now().date()}) ===")
print(f"Analyzed {len(csv_files[-24:])} hourly snapshots")
print()
for band in ["LF", "MF", "HF", "VHF", "UHF"]:
    print(f"  {band}: {band_activity[band]} active channels detected")
PYEOF
```

---

## 22. Aggregated Licensed Band Dashboard

```bash
# Run all licensed band decoders simultaneously
# Requires multiple SDRs (one per band) or fast frequency switching

# Terminal 1: ADS-B
dump1090 --net --gain 40 --quiet &
DUMP1090_PID=$!

# Terminal 2: AIS  
AIS-catcher -u 12345 -g 40 -v &
AIS_PID=$!

# Terminal 3: ACARS
acarsdec -r 1 131550000 -g 40 -v &
ACARS_PID=$!

# Terminal 4: POCSAG
multimon-ng -t rtl --rtl-frequency 157775000 --rtl-gain 40 \
  -a POCSAG1200 -a FLEX &
POCSAG_PID=$!

# Aggregate all data streams
python3 << 'PYEOF'
"""Aggregated Licensed Band Dashboard.

Combines data from ADS-B, AIS, ACARS, and POCSAG decoders
into a unified view for engagement situational awareness.
"""

import socket
import threading
import json
import time
from collections import defaultdict
from datetime import datetime


class LicensedBandDashboard:
    """Aggregate licensed band decoders into unified dashboard."""
    
    def __init__(self):
        self.aircraft = defaultdict(dict)
        self.vessels = defaultdict(dict)
        self.airline_msgs = []
        self.pager_msgs = []
        self.lock = threading.Lock()
    
    def adsb_listener(self, port=30003):
        """Listen for dump1090 SBS messages."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        for line in sock.makefile():
            parts = line.strip().split(",")
            if len(parts) > 10 and parts[0] == "MSG":
                icao24 = parts[4]
                with self.lock:
                    self.aircraft[icao24]["last_seen"] = datetime.now().isoformat()
                    if parts[10]:  # callsign
                        self.aircraft[icao24]["callsign"] = parts[10].strip()
                    if parts[11] and parts[12]:  # lat/lon
                        try:
                            self.aircraft[icao24]["lat"] = float(parts[11])
                            self.aircraft[icao24]["lon"] = float(parts[12])
                        except ValueError:
                            pass
    
    def ais_listener(self, port=12345):
        """Listen for AIS NMEA messages."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        while True:
            data, _ = sock.recvfrom(4096)
            # Simplified parsing
            sentence = data.decode("ascii", errors="ignore").strip()
            with self.lock:
                self.vessels["last"] = {
                    "sentence": sentence[:100],
                    "timestamp": datetime.now().isoformat()
                }
    
    def display(self):
        """Display aggregated dashboard."""
        while True:
            with self.lock:
                print("\033[2J\033[H")  # Clear screen
                print("=== Licensed Band Engagement Dashboard ===")
                print(f"Time: {datetime.now().isoformat()}")
                print()
                print(f"Aircraft tracked: {len(self.aircraft)}")
                for icao, info in list(self.aircraft.items())[:5]:
                    print(f"  {icao}: {info.get('callsign', '?')} at "
                          f"({info.get('lat', '?')}, {info.get('lon', '?')})")
                print()
                print(f"Vessels tracked: {len(self.vessels)}")
            time.sleep(5)
    
    def run(self):
        """Start all listeners and display."""
        threading.Thread(target=self.adsb_listener, daemon=True).start()
        threading.Thread(target=self.ais_listener, daemon=True).start()
        self.display()


if __name__ == "__main__":
    dashboard = LicensedBandDashboard()
    dashboard.run()
PYEOF

# Cleanup
kill $DUMP1090_PID $AIS_PID $ACARS_PID $POCSAG_PID 2>/dev/null
```

---

## 23. Quick Reference Cheat Sheet

```bash
# === ADS-B Aircraft Tracking ===
dump1090 --net --gain 40 --aggressive --quiet &  # Web GUI :8080

# === AIS Maritime Vessel Tracking ===
AIS-catcher -u 12345 -g 40 -v &  # UDP NMEA :12345

# === ACARS Airline Comms ===
acarsdec -r 0 131550000 -g 40 -v &

# === VDL Mode 2 ===
dumpvdl2 --gain 40 --output decoded:text:file:stdout &

# === HFDL Oceanic ===
dumphfdl --gain 40 2941000 5455000 8927000 11306000 15025000 17922000 &

# === POCSAG/FLEX Pagers ===
rtl_fm -f 157.775e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a POCSAG1200 -a FLEX -

# === APRS Amateur Radio ===
rtl_fm -f 144.39e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a AFSK1200 -

# === ATC Voice AM ===
rtl_fm -M am -f 121.5e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# === Maritime VHF Ch 16 ===
rtl_fm -M fm -f 156.8e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# === UAT 978 MHz ===
./dump978 --rtlsdr --gain 40 &

# === Spectrum Survey ===
rtl_power -f 100k:1500M:25k -i 10 -e 3600 -g 40 survey.csv

# === Decode from Capture ===
dump1090 --ifile capture.raw --fix --aggressive
```

```bash
# === Hardware Verification ===
hackrf_info
rtl_test -t
airspy_rx --help 2>&1 | head -5
bladerf-cli --probe

# === PPM Calibration ===
kal -g 40 -e
# Then pass --ppm value to dump1090/readsb/dump978

# === Active TX Research (FARADAY CAGE ONLY) ===
# Document technique for report, do NOT execute on live spectrum
# Reference: Povolny (2012) ADS-B spoofing with USRP
# Reference: Costin "Ghost in the Air" (2012) RTL-SDR ADS-B attacks
# Reference: Trend Micro maritime AIS spoofing research

# === Aggregator Feeds (with credentials) ===
# FlightAware: sudo piaware-config flightaware-user USERNAME
# Flightradar24: sudo fr24feed --signup
# ADS-B Exchange: no signup, self-hosted aggregator
```

---

## 24. OPSEC Considerations for Engagements

```bash
# Engagement OPSEC: do not TX during receive-side assessment
# Document all TX capability in report but never execute

# Frequency coordination with engagement site
python3 << 'PYEOF'
"""Engagement RF Coordination Checklist.

Documents the RF bands in scope for an engagement and confirms
receive-only operation throughout.
"""

bands_in_scope = [
    {"band": "ADS-B", "freq": "1090 MHz", "rx_only": True, "license": "FCC Part 87 (aviation)"},
    {"band": "AIS", "freq": "161.975/162.025 MHz", "rx_only": True, "license": "FCC Part 80 (maritime)"},
    {"band": "ACARS", "freq": "131.550 MHz", "rx_only": True, "license": "FCC Part 87"},
    {"band": "VDL Mode 2", "freq": "136.975 MHz", "rx_only": True, "license": "FCC Part 87"},
    {"band": "POCSAG", "freq": "157.775 MHz", "rx_only": True, "license": "FCC Part 90"},
    {"band": "APRS", "freq": "144.39 MHz", "rx_only": True, "license": "FCC Part 97 (amateur)"},
    {"band": "ATC Voice", "freq": "118-137 MHz AM", "rx_only": True, "license": "FCC Part 87"},
]

print("=== Engagement RF Scope Confirmation ===")
print(f"Date: $(date)")
print(f"Site: [engagement site identifier]")
print(f"Operator: [licensed operator name if applicable]")
print()
for band in bands_in_scope:
    print(f"{band['band']:15s} ({band['freq']:25s}): RX-ONLY = {band['rx_only']}, License = {band['license']}")

print()
print("All receive-only. NO active transmission on licensed bands.")
print("Active TX testing requires Faraday cage and explicit authorization.")
PYEOF
```

```bash
# Data handling: redact PHI/PII from pager messages before report inclusion
python3 << 'PYEOF'
"""PHI Redaction for Pager Message Logs.

Redacts patient health information from decoded pager messages
before inclusion in engagement reports.
"""

import re
from datetime import datetime


def redact_pager_message(msg):
    """Redact PHI patterns from a pager message."""
    # Replace common PHI patterns
    patterns = [
        (r"\b\d{3}-\d{3}-\d{4}\b", "[PHONE]"),
        (r"\b[A-Z]+\s*,\s*[A-Z][a-z]+\b", "[NAME]"),
        (r"\bMRN[:\s]*\d+\b", "MRN:[REDACTED]"),
        (r"\bROOM[:\s]*\d+\b", "ROOM:[REDACTED]"),
        (r"\bDR[\.\s]?\s*[A-Z][a-z]+\b", "DR [REDACTED]"),
        (r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "[DATE]"),
    ]
    
    redacted = msg
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
    
    return redacted


# Example redaction
sample_msg = "DR Smith call 555-123-4567 re: Johnson, Mary ROOM 42 MRN: 12345 DOB 03/15/1965"
print("Original:", sample_msg)
print("Redacted:", redact_pager_message(sample_msg))

# Output: "DR [REDACTED] call [PHONE] re: [NAME] ROOM:[REDACTED] MRN:[REDACTED] DOB [DATE]"
PYEOF
```

---

## 25. Antenna Verification with NanoVNA

NanoVNA is a $50-$100 vector network analyzer essential for verifying antenna resonance, measuring coax loss, and characterizing filters. All measurements are passive (the NanoVNA emits a very low-power test signal) and do not require any license.

```bash
# === Install NanoVNA companion software on Kali Linux ===
sudo apt install -y python3-numpy python3-serial python3-pyqt5
pip3 install --user nanovna-saver

# Connect NanoVNA via USB and verify device enumeration
lsusb | grep -i "nanovna\|qiiic\|diy"
# Typical: Bus 001 Device 004: ID 0483:5740 STMicroelectronics Virtual COM Port

# Launch NanoVNA-Saver GUI
nanovna-saver &
# Alternative: use the NanoVNA's built-in display for field measurements

# Verify serial connection
python3 << 'PYEOF'
import serial, serial.tools.list_ports
ports = list(serial.tools.list_ports.comports())
for p in ports:
    if 'nano' in p.description.lower() or 'STLink' in p.description or 'Virtual COM' in p.description:
        print(f"NanoVNA likely on: {p.device} ({p.description})")
PYEOF
```

```bash
# === Calibrate the NanoVNA at the antenna feedpoint ===
# Calibration compensates for the test cable and connectors.
# Use the included calibration standards (open, short, load 50 ohm).

# Sweep 1090 MHz ADS-B antenna:
#   Set START = 1000 MHz, STOP = 1200 MHz
#   Run calibration with open / short / load standards
#   Save calibration as "1090_antenna.cal"

# Sweep 162 MHz AIS antenna:
#   Set START = 150 MHz, STOP = 170 MHz
#   Run calibration
#   Save calibration as "162_ais.cal"

# Sweep HF dipole (e.g., 14 MHz amateur band):
#   Set START = 13 MHz, STOP = 15 MHz
#   Run calibration
#   Save calibration as "14m_dipole.cal"

# Document the sweep results in the engagement record
echo "=== Antenna Sweep Report $(date -u) ===" > antenna_report.txt
echo "Antenna model: [____]" >> antenna_report.txt
echo "Design frequency: [____] MHz" >> antenna_report.txt
echo "Measured VSWR at design freq: [____]" >> antenna_report.txt
echo "Measured VSWR +/- 5 MHz: [____]" >> antenna_report.txt
echo "Measured feedpoint impedance: [____] ohms" >> antenna_report.txt
echo "Pass/Fail: [____]" >> antenna_report.txt
```

```bash
# === Measure coax cable loss ===
# Connect NanoVNA CH0 to one end of the cable, leave far end OPEN
# The return loss is twice the one-way cable loss (signal goes there and back)

# Example: measure 30 meters of RG-58 at 1090 MHz
# Expected: 30 m * 0.42 dB/m = 12.6 dB one-way, 25.2 dB round-trip
# NanoVNA will show the round-trip value; divide by 2 for cable loss

# Document feedline loss per engagement
python3 << 'PYEOF'
"""Coax cable loss reference at common VHF/UHF frequencies (dB per 30 meters)."""
cable_specs = {
    'RG-58': {30e6: 1.2, 100e6: 2.4, 300e6: 4.5, 1000e6: 9.0, 1500e6: 12.0},
    'RG-8X': {30e6: 0.9, 100e6: 1.8, 300e6: 3.3, 1000e6: 6.6, 1500e6: 9.0},
    'LMR-240': {30e6: 0.7, 100e6: 1.3, 300e6: 2.5, 1000e6: 4.9, 1500e6: 6.2},
    'LMR-400': {30e6: 0.3, 100e6: 0.6, 300e6: 1.1, 1000e6: 2.2, 1500e6: 2.8},
    'RG-213': {30e6: 0.6, 100e6: 1.2, 300e6: 2.3, 1000e6: 4.6, 1500e6: 6.5},
}

for cable, freqs in cable_specs.items():
    print(f"\n{cable} (30 meters):")
    for freq, loss in freqs.items():
        freq_mhz = freq / 1e6
        print(f"  {freq_mhz:>6.0f} MHz: {loss:.1f} dB")
PYEOF
```

```bash
# === Verify antenna isolation for multi-antenna deployments ===
# When two antennas are mounted on the same mast, energy from one
# can couple into the other. Measure the isolation to prevent
# cross-interference.

# Connect NanoVNA CH0 to antenna A, CH1 to antenna B
# Sweep the frequency range of interest
# Document isolation in dB (typical good: > 20 dB)

echo "=== Antenna Isolation Report ===" > isolation_report.txt
echo "Antenna A: [1090 MHz collinear]" >> isolation_report.txt
echo "Antenna B: [VHF air discone]" >> isolation_report.txt
echo "Min isolation 118-137 MHz: [____] dB" >> isolation_report.txt
echo "Min isolation 1090 MHz: [____] dB" >> isolation_report.txt
echo "Recommendation: [spacing adequate / increase spacing]" >> isolation_report.txt
```

---

## 26. I/Q Recording and Replay Workflows

Recording raw I/Q samples enables offline analysis, protocol reverse engineering, and authorized replay research. All recording is passive receive and is legal.

```bash
# === Capture raw I/Q of an unknown signal for offline analysis ===
# rtl_sdr with -s sets sample rate; output is signed 8-bit I/Q interleaved

# Capture 60 seconds at 1090 MHz (ADS-B) at 2 MSPS
rtl_sdr -d 0 -f 1090000000 -s 2000000 -g 40 -e 60 adsb_capture.iq

# Capture 60 seconds at 131.550 MHz (ACARS) at 250 kSPS
rtl_sdr -d 0 -f 131550000 -s 250000 -g 40 -e 60 acars_capture.iq

# Capture 60 seconds at 162 MHz (AIS) at 250 kSPS
rtl_sdr -d 0 -f 162000000 -s 250000 -g 40 -e 60 ais_capture.iq

# Capture 60 seconds at 931.25 MHz (FLEX pager) at 22050 samples
rtl_sdr -d 0 -f 931250000 -s 22050 -g 40 -e 60 flex_capture.iq

# Verify file sizes (I/Q files are large: 2 bytes per sample)
ls -lh *.iq
# Expected: adsb_capture.iq = 60 s * 2 MSPS * 2 bytes = 240 MB
```

```bash
# === Capture with HackRF for higher-fidelity I/Q ===
# HackRF uses signed 8-bit I/Q at up to 20 MSPS

# Capture 30 seconds of wideband spectrum at 1090 MHz, 20 MSPS
hackrf_transfer -r adsb_wide.iq -f 1090000000 -s 20000000 -l 16 -g 40 -n 600000000
# -n 600000000 samples = 30 seconds at 20 MSPS

# Capture a 20-MHz-wide chunk of spectrum at VHF (118-138 MHz ATC band)
hackrf_transfer -r atc_band.iq -f 128000000 -s 20000000 -l 16 -g 40 -n 600000000
# Center at 128 MHz with 20 MHz bandwidth covers 118-138 MHz ATC band

# Verify capture
ls -lh *.iq
# Expected: adsb_wide.iq = 30 s * 20 MSPS * 2 bytes = 1.2 GB
```

```bash
# === Replay an I/Q recording (INSIDE FARADAY CAGE ONLY) ===
# WARNING: Transmitting on licensed frequencies without authorization
# is a federal crime. Only run this inside a verified Faraday cage
# with explicit authorization per the spoofing lab checklist.

# Verify cage is closed and containment is verified (see playbook Part 1.3)
# Verify authorization letter covers this exact frequency and power level

# Inside cage (HackRF):
# hackrf_transfer -t adsb_capture.iq -f 1090000000 -s 20000000 -x 10 -R
# -t = transmit file
# -x 10 = TX VGA gain 10 dB (low power, suitable for in-cage use)
# -R = repeat continuously

# Use attenuator (20 dB minimum) between HackRF and antenna
# Use the smallest antenna that works (a short whip, not a high-gain collinear)

# Outside cage (monitoring RTL-SDR): verify NO leakage
# rtl_power -f 1080M:1100M:50k -i 1 -e 60 -g 40 leakage_check.csv
# Compare to baseline; delta must be < 3 dB
```

```bash
# === Convert between I/Q formats ===
# Different tools use different I/Q formats. Convert as needed.

python3 << 'PYEOF'
"""Convert HackRF signed 8-bit I/Q to GNU Radio complex float32."""
import numpy as np

# Read HackRF-format I/Q (signed 8-bit, interleaved I and Q)
raw = np.fromfile('adsb_wide.iq', dtype=np.int8)
iq = raw[0::2].astype(np.float32) + 1j * raw[1::2].astype(np.float32)
# Normalize to [-1, 1]
iq = iq / 128.0

# Save as GNU Radio complex float32 (.cfile format)
iq.astype(np.complex64).tofile('adsb_wide.cfile')
print(f"Converted {len(iq)} samples to adsb_wide.cfile")

# Alternative: convert to WAV for audio-frequency analysis
# (only meaningful if the signal is in audio range)
# audio = iq.real * 32767
# audio.astype(np.int16).tofile('output.raw')
PYEOF

# Verify the converted file
ls -lh adsb_wide.cfile
# Expected: 2x size of .iq (4 bytes per complex sample vs 2 bytes per int8 pair)
```

```bash
# === Process I/Q capture offline with GNU Radio ===
# Load the captured I/Q in a GNU Radio flowgraph for custom processing

# Create a simple GNU Radio Python script to demodulate ADS-B
cat > process_adsb.py << 'PYEOF'
"""Offline ADS-B demodulator from a captured I/Q file.

Reads a HackRF-format I/Q file and runs the gr-adsb decoder.
"""
from gnuradio import gr, blocks, analog
import osmosdr
import sys

class ADSBProcessor(gr.top_block):
    def __init__(self, iq_file, sample_rate=2_000_000, center_freq=1_090_000_000):
        gr.top_block.__init__(self, "ADSB Processor")

        # File source (HackRF int8 format)
        self.src = blocks.file_source(gr.sizeof_char, iq_file, repeat=False)
        # Convert interleaved int8 to complex float
        self.interleaved_to_complex = blocks.interleaved_char_to_complex()

        self.connect(self.src, self.interleaved_to_complex)
        # Add ADS-B decoder block here (requires gr-adsb installed)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 process_adsb.py <iq_file>")
        sys.exit(1)
    tb = ADSBProcessor(sys.argv[1])
    tb.run()
PYEOF

python3 process_adsb.py adsb_wide.iq 2>&1 | head -20 || echo "gr-adsb not installed; this is a template"
```

```bash
# === Replay attack workflow (authorized Faraday cage only) ===
# This workflow demonstrates protocol replay for engagement purposes.
# NEVER run outside a verified Faraday cage.

# Step 1: Capture the target signal (outside the cage, RX is fine)
# rtl_sdr -d 0 -f 433920000 -s 250000 -g 40 -e 5 keyfob_capture.iq
# (Note: 433 MHz keyfobs are Sub-GHz ISM, handled in sdr-rf-attack.
#  This is just an illustration of the replay workflow.)

# Step 2: Trim the capture to just the relevant signal
python3 << 'PYEOF'
"""Trim I/Q capture to a specific time window."""
import numpy as np

raw = np.fromfile('keyfob_capture.iq', dtype=np.int8)
# Trim to first 100 ms (at 250 kSPS, that's 25000 samples)
trimmed = raw[:50000]  # 50000 bytes = 25000 complex samples
trimmed.tofile('keyfob_trimmed.iq')
print(f"Trimmed from {len(raw)} to {len(trimmed)} bytes")
PYEOF

# Step 3: Replay inside Faraday cage
# hackrf_transfer -t keyfob_trimmed.iq -f 433920000 -s 250000 -x 40 -R
# (Again, this is the workflow; actual execution requires authorization.)

# Step 4: Document the replay for the engagement report
echo "=== Replay Test Report ===" > replay_report.txt
echo "Date: $(date -u)" >> replay_report.txt
echo "Signal: [keyfob / ADS-B / AIS / etc.]" >> replay_report.txt
echo "Frequency: [____] MHz" >> replay_report.txt
echo "Original capture timestamp: [____]" >> replay_report.txt
echo "Cage containment verified: [yes/no]" >> replay_report.txt
echo "Authorization reference: [____]" >> replay_report.txt
echo "Result: [success / partial / failure]" >> replay_report.txt
```

```bash
# === Continuous wideband recording for spectrum survey ===
# Record a wideband waterfall for engagement OPSEC baseline

# Survey HF/VHF/UHF for 1 hour at 25 kHz resolution
rtl_power -d 0 -f 100k:1500M:25k -i 10 -e 3600 -g 40 survey_$(date +%Y%m%d).csv &

# Convert to waterfall PNG for the engagement report
python3 << 'PYEOF'
"""Convert rtl_power CSV to a waterfall PNG."""
import csv
import numpy as np
from PIL import Image

rows = []
with open('survey_$(date +%Y%m%d).csv') as f:
    for line in csv.reader(f):
        if len(line) > 6:
            # Each row: timestamp, freq_low, freq_high, hz_per_step, samples, time, dB_1, dB_2, ...
            timestamp = line[0]
            freq_low = float(line[1])
            # The dB values start at column 6
            powers = [float(x) for x in line[6:]]
            rows.append(powers)

if not rows:
    print("No data to plot")
    exit()

# Pad rows to equal length
max_len = max(len(r) for r in rows)
padded = np.array([r + [-100] * (max_len - len(r)) for r in rows])

# Normalize to image
normalized = ((padded - (-100)) / 60 * 255).clip(0, 255).astype(np.uint8)
img = Image.fromarray(np.flipud(normalized), mode='L')
img.save('survey_$(date +%Y%m%d).png')
print(f"Wrote waterfall PNG: survey_$(date +%Y%m%d).png")
print(f"Image size: {img.size}")
PYEOF

ls -lh survey_*.png survey_*.csv 2>/dev/null
```

---

## 27. TX-Side Tools and Authorized Lab Workflows

This section documents transmit-side tools for authorized Faraday-cage research. All commands assume verified cage containment and explicit engagement authorization. See the spoofing lab checklist in the deep-dive guide.

```bash
# === HackRF One TX-side configuration and verification ===

# Verify HackRF is detected and report firmware version
hackrf_info

# Set TX amplifier and VGA gain (start LOW)
# -a = enable RF amplifier (off by default; only for short-range coax tests)
# -x = TX VGA gain (0-47 dB, start at 10)
# -l = RX VGA gain (0-62 dB, irrelevant for TX)

# Test tone at 100 MHz (inside Faraday cage, into dummy load)
hackrf_transfer -t cw_test.raw -f 100000000 -s 2000000 -x 10 -R &
TX_PID=$!
sleep 5
kill $TX_PID
echo "Test tone TX complete"

# Sweep TX power across frequency range (into dummy load or attenuator)
for freq_mhz in 100 200 400 900 1090 1500; do
    echo "Testing TX at ${freq_mhz} MHz..."
    hackrf_transfer -t cw_test.raw -f ${freq_mhz}e6 -s 2000000 -x 10 -n 2000000 > /dev/null 2>&1
done

# Generate a continuous wave (CW) test signal file
python3 << 'PYEOF'
import numpy as np

SAMPLE_RATE = 2_000_000
DURATION_S = 1.0
FREQ_OFFSET = 100_000  # 100 kHz offset from center

t = np.arange(int(SAMPLE_RATE * DURATION_S)) / SAMPLE_RATE
signal = np.exp(2j * np.pi * FREQ_OFFSET * t)

# Convert to HackRF signed 8-bit I/Q
iq_int = np.empty(2 * len(signal), dtype=np.int8)
iq_int[0::2] = (signal.real * 127).astype(np.int8)
iq_int[1::2] = (signal.imag * 127).astype(np.int8)
iq_int.tofile('cw_test.raw')
print(f"Wrote cw_test.raw ({len(iq_int)} bytes)")
PYEOF
```

```bash
# === BladeRF 2.0 micro TX-side configuration ===
# BladeRF supports full-duplex (simultaneous TX and RX)

# Probe for connected BladeRF devices
bladerf-cli --probe

# Open BladeRF CLI
bladerf-cli -l

# Inside BladeRF CLI:
#   set frequency tx 1090000000
#   set frequency rx 1090000000
#   set samplerate tx 20000000
#   set samplerate rx 20000000
#   set bandwidth tx 1500000
#   set bandwidth rx 1500000
#   set txvga1 10
#   set txvga2 0
#   tx config file=adsb_capture.iq format=bin
#   tx start
#   tx wait

# Verify TX power output with a power meter (INSIDE FARADAY CAGE)
# Connect power meter to the TX port via attenuator (20-30 dB)
# Document the measured output power
echo "=== BladeRF TX Power Verification ===" > bladerf_tx_report.txt
echo "Date: $(date -u)" >> bladerf_tx_report.txt
echo "Frequency: [____] MHz" >> bladerf_tx_report.txt
echo "TX gain settings: txvga1=[__], txvga2=[__]" >> bladerf_tx_report.txt
echo "Measured output (with attenuator): [____] dBm" >> bladerf_tx_report.txt
echo "Calculated radiated power: [____] dBm" >> bladerf_tx_report.txt
echo "Within cage containment spec: [yes/no]" >> bladerf_tx_report.txt
```

```bash
# === Generate ADS-B frames with pyModeS for authorized lab use ===
# pyModeS provides standards-compliant ADS-B message encoding

pip3 install --user pyModeS 2>&1 | tail -3

python3 << 'PYEOF'
"""Generate ADS-B Type 11 (Airborne Position) and Type 19 (Velocity) frames.

Uses a fictional ICAO24 hex that matches no real aircraft.
"""

from pyModeS import adsb

# Fictional parameters for lab demonstration
ICAO24 = "A1B2C3"  # test ICAO24 (matches no real aircraft)
CALLSIGN = "GHOST1  "  # 8 chars
LAT, LON = 35.0, -100.0
ALT_FT = 35000
SPEED_KT = 450
HEADING_DEG = 90

# Encode Type 4 (Aircraft Identification)
callsign_msg = adsb.icao("A1B2C3") + adsb.category(11, 0) + adsb.callsign(CALLSIGN)
# (simplified; real encoding uses full frame builder)

# Encode Type 11 (Airborne Position) - CPR encoding
# position_msg = adsb.airborne_position(...)

print(f"Fictional aircraft: ICAO24={ICAO24} callsign={CALLSIGN!r}")
print(f"Position: {LAT},{LON} @ {ALT_FT} ft")
print(f"Speed: {SPEED_KT} kt heading {HEADING_DEG}")
print(f"\nGenerated frames (hex):")
print(f"  Callsign: {callsign_msg[:28]}")
print(f"\nFor authorized lab demonstration only.")
print(f"Transmit only inside verified Faraday cage with explicit authorization.")
PYEOF
```

```bash
# === Generate AIS frames with pyais for authorized lab use ===
pip3 install --user pyais 2>&1 | tail -3

python3 << 'PYEOF'
"""Generate AIS Type 1 (Position Report) frames.

Uses fictional MMSI 999000001 (999 prefix is reserved for test).
"""

from pyais.encode import encode_dict
from pyais import messages

# Fictional test vessel
fictional_vessel = {
    'type': 1,           # Position Report Class A
    'repeat': 0,
    'mmsi': 999000001,   # 999 prefix reserved for test
    'status': 0,         # Under way using engine
    'turn': 0,
    'speed': 12.3,
    'accuracy': 0,
    'lon': -123.45,      # Fictional position
    'lat': 48.12,
    'course': 90.0,
    'heading': 90,
    'second': 30,
    'maneuver': 0,
    'raim': 0,
    'radio': 0,
}

frames = encode_dict(fictional_vessel)
print(f"Fictional AIS Type 1 message:")
print(f"  MMSI: {fictional_vessel['mmsi']}")
print(f"  Position: {fictional_vessel['lat']}, {fictional_vessel['lon']}")
print(f"  Encoded frames: {len(frames)}")
for f in frames:
    print(f"    {f}")

print(f"\nFor authorized lab demonstration only.")
PYEOF
```

```bash
# === GNU Radio flowgraph for ADS-B transmission (authorized lab) ===
# The gr-adsb Out-of-Tree module provides a TX flowgraph

# Verify gr-adsb is installed
python3 -c "import gnuradio.adsb; print('gr-adsb available')" 2>&1 || \
  echo "Install gr-adsb: git clone https://github.com/ghostop14/gr-adsb.git"

# Launch the gr-adsb TX flowgraph (requires GUI)
# gnuradio-companion ~/gr-adsb/examples/adsb_tx.grc

# Alternative: headless TX flowgraph
cat > adsb_tx_headless.py << 'PYEOF'
"""Headless ADS-B TX flowgraph for authorized lab use.

Runs without GUI. Reads a message file and transmits at low power
inside a verified Faraday cage.
"""
from gnuradio import gr, blocks, osmosdr
import sys

class ADSBTX(gr.top_block):
    def __init__(self, iq_file, freq=1_090_000_000, samp_rate=2_000_000, tx_gain=10):
        gr.top_block.__init__(self, "ADSB TX")

        # File source (repeating)
        self.src = blocks.file_source(gr.sizeof_gr_complex, iq_file, repeat=True)
        # Multiply by gain scalar
        self.mul = blocks.multiply_const_cc(tx_gain / 100.0)

        # Osmocom sink (HackRF)
        self.sink = osmosdr.sink(args="numchan=1")
        self.sink.set_sample_rate(samp_rate)
        self.sink.set_center_freq(freq)
        self.sink.set_freq_corr(0)
        self.sink.set_gain_mode(False)
        self.sink.set_gain(tx_gain)
        self.sink.set_if_gain(tx_gain)
        self.sink.set_bb_gain(tx_gain)

        self.connect(self.src, self.mul, self.sink)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 adsb_tx_headless.py <iq_file> [tx_gain]")
        print("WARNING: Run inside verified Faraday cage only!")
        sys.exit(1)
    iq_file = sys.argv[1]
    tx_gain = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    tb = ADSBTX(iq_file, tx_gain=tx_gain)
    tb.run()
PYEOF

echo "TX flowgraph template created. Run inside Faraday cage only."
```

```bash
# === TX power measurement and documentation ===
# Always measure TX power inside the cage before any test

# Use a power meter or spectrum analyzer connected via attenuator
# (30 dB attenuator protects the meter from overload)

# Document measured power per test
python3 << 'PYEOF'
"""TX power documentation template for engagement records."""
from datetime import datetime

power_log = {
    'test_id': 'TX-001',
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'operator': '[name]',
    'authorization': '[engagement reference]',
    'cage_verified': True,
    'cage_verification_report': 'faraday_verification/README.md',
    'frequency_hz': 1_090_000_000,
    'tx_hardware': 'HackRF One [serial]',
    'tx_gain_setting_db': 10,
    'attenuator_db': 30,
    'measured_power_dbm': -15,  # at the attenuator output
    'calculated_radiated_power_dbm': -15 - 0,  # in-cage antenna gain unknown
    'cage_leakage_monitor_delta_db': 1.2,  # outside-cage delta
    'leakage_within_spec': True,  # < 3 dB delta
    'result': 'PASS - TX within cage containment spec',
}

print("=== TX Power Log Entry ===")
for key, value in power_log.items():
    print(f"  {key}: {value}")
PYEOF
```

```bash
# === Emergency shutdown procedure ===
# If at any point during authorized TX research the outside-cage leakage
# monitor detects signal above threshold, immediately:

# 1. Kill the TX process
pkill -f hackrf_transfer
pkill -f bladerf-cli

# 2. Power off the TX SDR (unplug USB)
# 3. Document the incident
# 4. Notify the FCC (if in US) per 47 CFR requirements
# 5. Notify the engagement client

cat > emergency_shutdown_log.md << 'EOF'
# Emergency TX Shutdown Log

## Trigger
- [ ] Outside-cage leakage monitor exceeded threshold
- [ ] Cage door opened during TX
- [ ] Operator observed interference on outside equipment
- [ ] Other: [describe]

## Timestamp
- Event: [time]
- Detected by: [leakage monitor / visual / report]
- Response time: [seconds from detection to TX off]

## Actions taken
- [ ] TX process killed
- [ ] TX SDR powered off
- [ ] Cage opened and inspected
- [ ] Outside spectrum verified clean

## Notification
- [ ] Engagement client notified at: [time]
- [ ] FCC notified at: [time] (if required)
- [ ] Other regulators notified: [list]

## Root cause
[Describe what went wrong -- cage damage, antenna mismatch, attenuator failure, etc.]

## Corrective action
[Describe the fix before resuming TX research]
EOF

cat emergency_shutdown_log.md
```

```bash
# === Spectrum monitoring during authorized TX ===
# Continuous outside-cage monitoring is mandatory during any TX research

# Outside cage: continuous spectrum monitor
rtl_power -d 1 -f 1080M:1100M:50k -i 1 -g 40 -e 3600 outside_monitor_1090.csv &
MONITOR_PID=$!

# Inside cage: TX in progress
# hackrf_transfer -t adsb_capture.iq -f 1090000000 -s 2000000 -x 10 -R &
# TX_PID=$!

# Real-time leakage alert
python3 << 'PYEOF'
"""Real-time leakage alert for outside-cage monitoring."""
import csv, time, statistics, sys
from collections import deque

THRESHOLD_DB = 3.0  # alert if delta > 3 dB
WINDOW_SECONDS = 10

# Load baseline
baseline = []
with open('baseline_1090.csv') as f:
    for row in csv.reader(f):
        if len(row) > 6:
            baseline.append(float(row[6]))
baseline_mean = statistics.mean(baseline) if baseline else -80.0
print(f"Baseline: {baseline_mean:.1f} dB")
print(f"Alert threshold: {baseline_mean + THRESHOLD_DB:.1f} dB")

# Monitor the live CSV (rtl_power appends new rows)
recent = deque(maxlen=WINDOW_SECONDS)
print("Monitoring for leakage (Ctrl-C to stop)...")
try:
    with open('outside_monitor_1090.csv') as f:
        # Tail the file
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            parts = line.strip().split(',')
            if len(parts) > 6:
                power = float(parts[6])
                recent.append(power)
                if len(recent) >= 5:
                    current_mean = statistics.mean(recent)
                    delta = current_mean - baseline_mean
                    if delta > THRESHOLD_DB:
                        print(f"LEAKAGE ALERT! delta={delta:.1f} dB (>{THRESHOLD_DB})")
                        print("IMMEDIATELY KILL TX PROCESS!")
                        sys.exit(1)
                    elif delta > 1.0:
                        print(f"Warning: delta={delta:.1f} dB (below threshold)")
except KeyboardInterrupt:
    print("\nStopped monitoring")
PYEOF
```

---

## 28. References and Further Reading

```bash
# === Academic/Research Papers ===
# - Povolny & Wang (2012): "On the Security of the ADS-B Protocol"
# - Costin & Francillon (2012): "Ghost in the Air (Rerouted): On ADS-B and ATC Vulnerabilities"
# - Trend Micro (2019-2020): Maritime AIS spoofing research
# - Barisani & Mancini (DEF CON 18): "Pager networks: intercepting messages nationwide"
# - Phaedrus (DEF CON 22): "Plane Spotters Guide to Hacking Aircraft"

# === Standards Documents ===
# - ICAO Annex 10: Aeronautical Telecommunications (ADS-B, VDL Mode 2, HFDL)
# - ITU-R M.1371: AIS technical characteristics
# - ITU-R M.493: DSC (Digital Selective Calling) system
# - RTCADO-260A: VDL Mode 2 SARPS
# - ARINC 618/622: ACARS protocol specifications
# - POCSAG Post Office Code Standardization Advisory Group (BC/RC/CCIR Rec. 584)
# - Motorola FLEX protocol reference

# === Online Resources ===
# - FlightAware (https://flightaware.com) - global flight tracking
# - Flightradar24 (https://flightradar24.com) - global flight tracking
# - MarineTraffic (https://marinetraffic.com) - vessel tracking
# - VesselFinder (https://vesselfinder.com) - vessel tracking
# - ADS-B Exchange (https://adsbexchange.com) - unfiltered ADS-B data
# - FAA Aircraft Registry - ICAO24 to aircraft registration lookup
# - ITU MMSI database - MMSI to country/operator lookup

# === SDR Hardware Documentation ===
# - RTL-SDR.com: https://rtl-sdr.com (RTL-SDR v3 docs and community)
# - HackRF One: https://greatscottgadgets.com/hackrf/
# - Nuand BladeRF: https://www.nuand.com/
# - AirSpy: https://airspy.com/
# - Analog Devices PlutoSDR: https://wiki.analog.com/university/tools/pluto

# === Decoder Documentation ===
# - dump1090-mutability: https://github.com/adsbxchange/dump1090-mutability
# - readsb: https://github.com/wiedehopf/readsb
# - dump978: https://github.com/mutability/dump978
# - AIS-catcher: https://github.com/jvde-github/AIS-catcher
# - multimon-ng: https://github.com/EliasOenal/multimon-ng
# - dumpvdl2: https://github.com/szpajder/dumpvdl2
# - dumphfdl: https://github.com/szpajder/dumphfdl
# - ACARSDeco: closed-source, available from xplordbd.co.uk
# - direwolf: https://github.com/wb2osz/direwolf
# - fldigi: https://sourceforge.net/projects/fldigi/

echo "All references documented. See payloads.md for full command catalog."
```
