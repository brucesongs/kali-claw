# ICS Network Security Assessment Guide

## Overview

ICS network security assessment goes beyond protocol-level testing to evaluate the overall security architecture of industrial networks. This includes network segmentation, traffic analysis, anomaly detection, honeypot deployment, OPC UA security testing, and defense-in-depth implementation. The goal is to verify that the OT network follows established frameworks (Purdue Model, IEC 62443) and that security controls effectively prevent unauthorized access to industrial processes.

This guide covers the full network assessment methodology for ICS environments.

## Part 1: Network Architecture Analysis

### The Purdue Model

The Purdue Enterprise Reference Architecture (ISA-95 / IEC 62443) defines six levels of industrial network segmentation:

| Level | Zone | Purpose | Security Boundary |
|-------|------|---------|-------------------|
| 5 | Enterprise | Business networks, ERP, email | IT firewall |
| 4 | Site Operations | Plant-wide historian, MES, OPC servers | Industrial DMZ |
| 3.5 | IDMZ | Industrial Demilitarized Zone | Dual firewalls |
| 3 | Operations | HMI, engineering workstations, OPC UA | OT firewall |
| 2 | Control | PLCs, RTUs, DCS controllers | Control network switch |
| 1 | Field Devices | Sensors, actuators, I/O modules | Fieldbus boundary |
| 0 | Process | Physical process equipment | Physical isolation |

### Segmentation Verification

Test each boundary to verify that firewalls and access control lists are properly configured:

```bash
# From IT network, attempt to reach OT Level 2 devices directly
nmap -sT -p 502,102,44818 10.0.2.0/24

# From OT Level 2, attempt to reach IT resources
nmap -sT -p 80,443,3389,22 192.168.100.0/24

# Verify IDMZ isolation — attempt direct IT-to-OT without going through DMZ
nmap -sT -p 502,102 --source-port 53 10.0.2.0/24

# Test for dual-homed hosts bridging zones
arp-scan -l | sort
# Cross-reference ARP tables from IT and OT to find hosts with interfaces on both
```

Document every successful cross-zone connection as a finding with severity based on the Purdue level crossed.

### Identifying Unauthorized Pathways

Beyond firewall testing, look for these common segmentation failures:

- **USB network adapters** on engineering workstations bridging IT and OT
- **Wireless access points** deployed without authorization in OT zones
- **VPN connections** from vendor networks directly to PLC subnets (bypassing DMZ)
- **Remote desktop** connections from IT workstations directly to HMI/SCADA servers
- **Shared VLANs** between IT and OT due to switch misconfiguration

```bash
# Check for wireless networks in the OT area
iwlist wlan0 scan | grep -E "ESSID|Encryption"

# Look for unexpected routing between zones
traceroute -n 10.0.2.1
# Compare expected route (through DMZ) with actual route

# Check ARP tables for devices with multiple interface IPs
arp -a | awk '{print $2}' | sort | uniq -c | sort -rn | head -20
```

## Part 2: Protocol Anomaly Detection

### Baseline Establishment

Before testing for anomalies, establish a baseline of normal ICS network traffic:

```bash
# Capture 24 hours of baseline traffic
tcpdump -i eth0 -w baseline_24h.pcap -G 86400 -W 1 'port 502 or port 102 or port 44818 or port 4840 or port 20000'

# Extract communication patterns
tshark -r baseline_24h.pcap -Y "tcp.port == 502" -T fields -e ip.src -e ip.dst -e modbus.funccode | sort | uniq -c | sort -rn > modbus_baseline.txt

# Identify normal master-slave pairs
tshark -r baseline_24h.pcap -Y "tcp.port == 102" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn > s7comm_baseline.txt
```

### Anomaly Detection Techniques

Compare live traffic against the baseline to detect unauthorized activity:

```bash
# Monitor for new Modbus masters (IPs not in baseline)
tshark -i eth0 -f "port 502" -T fields -e ip.src 2>/dev/null | while read ip; do
  grep -q "$ip" modbus_baseline.txt || echo "ALERT: Unknown Modbus master $ip"
done

# Watch for Modbus write function codes (5, 6, 15, 16) from non-HMI sources
tshark -i eth0 -f "port 502" -Y "modbus.funccode >= 5" -T fields -e ip.src -e modbus.funccode

# Detect S7comm sessions from unexpected IPs
tshark -i eth0 -f "port 102" -Y "s7comm" -T fields -e ip.src -e ip.dst | while read pair; do
  grep -q "$pair" s7comm_baseline.txt || echo "ALERT: Unauthorized S7comm session $pair"
done

# Monitor for EtherNet/IP session registrations from new sources
tshark -i eth0 -f "port 44818" -Y "enip.command == 0x65" -T fields -e ip.src
```

### Detecting Protocol-Level Attacks

Set up specific detection rules for known ICS attack patterns:

```bash
# Detect Modbus register scan patterns (sequential reads across wide ranges)
tshark -i eth0 -f "port 502" -Y "modbus.funccode == 3" -T fields -e ip.src -e modbus.regnum 2>/dev/null | \
  awk '{if ($2 > 100) print "ALERT: Large register read from", $1, "count:", $2}'

# Detect S7comm CPU stop commands
tshark -i eth0 -f "port 102" -Y "s7comm.func == 0x08" -T fields -e ip.src

# Detect DNP3 warm restart commands
tshark -i eth0 -f "port 20000" -Y "dnp3.func == 0x0d" -T fields -e ip.src
```

## Part 3: Honeypot Deployment with conpot

### Why ICS Honeypots Matter

ICS honeypots serve as early warning systems. When an attacker scans the OT network, they will discover the honeypot before reaching real devices. Interaction with the honeypot generates alerts that provide early detection of unauthorized access.

### Deploying conpot

`conpot` is a modular ICS honeypot that emulates Modbus TCP, IPMI, SNMP, HTTP, and other protocols:

```bash
# Deploy with the default Modbus template
conpot -f --template default

# Deploy with the Kamstrup meter template (for smart grid scenarios)
conpot -f --template kemel --host 192.168.1.200

# Deploy with custom configuration and logging
conpot -f --template default --config /etc/conpot/conpot.cfg --logfile /var/log/conpot.log

# Run in background and monitor for connections
conpot -f --template default >> /var/log/conpot.log 2>&1 &
tail -f /var/log/conpot.log | grep --line-buffered "connection"
```

### Honeypot Placement Strategy

For effective detection, deploy honeypots at strategic network positions:

1. **Unused IPs in PLC subnet** — Catches attackers scanning the control network
2. **DMZ IP space** — Detects lateral movement attempts from IT to OT
3. **Historian subnet** — Catches attackers targeting data collection systems
4. **Management VLAN** — Detects unauthorized access to engineering workstations

### Verifying Honeypot Effectiveness

After deployment, verify the honeypot responds realistically:

```bash
# Test Modbus response
modbus-cli read -a 192.168.1.200 -s 1 -r 0 -n 10 -t holding

# Test HTTP interface (many ICS devices have web management)
curl -v http://192.168.1.200/

# Check that the interaction was logged
grep "$(date +%Y-%m-%d)" /var/log/conpot.log | tail -20
```

## Part 4: OPC UA Security Testing with python-opcua

### OPC UA Security Model

OPC UA supports multiple security levels:

| Security Mode | Description | Risk if Allowed |
|---------------|-------------|-----------------|
| None | No encryption, no signing | Critical |
| Sign | Messages signed but not encrypted | High |
| SignAndEncrypt | Full TLS-like protection | Low (if configured correctly) |

### Endpoint Security Audit

```bash
# Enumerate endpoints and their security policies
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
endpoints = client.get_endpoints()
for ep in endpoints:
    mode = str(ep.SecurityMode)
    policy = ep.SecurityPolicyUri.split('#')[-1] if '#' in ep.SecurityPolicyUri else ep.SecurityPolicyUri
    url = ep.EndpointUrl
    print(f'{url} | Mode: {mode} | Policy: {policy}')
"
```

Flag any endpoint with `SecurityMode=None` as a critical finding. The `None` policy transmits all data in cleartext, including credentials and process data.

### Authentication Testing

```bash
# Test anonymous access
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
try:
    client.connect()
    root = client.get_root_node()
    children = root.get_children()
    print(f'CRITICAL: Anonymous access accepted. Root has {len(children)} children.')
    # Try to read process variables
    objects = client.get_objects_node()
    for node in objects.get_children():
        for var in node.get_variables():
            try:
                val = var.get_value()
                print(f'  Read {var.get_browse_name().Name} = {val}')
            except:
                pass
    client.disconnect()
except Exception as e:
    print(f'GOOD: Anonymous access rejected: {e}')
"

# Test certificate handling
python3 -c "
import opcua
from opcua.crypto import security_policies
client = opcua.Client('opc.tcp://192.168.1.40:4840')
endpoints = client.get_endpoints()
for ep in endpoints:
    cert = ep.ServerCertificate
    if cert:
        print(f'Certificate present: {len(cert)} bytes')
    else:
        print('WARNING: No server certificate — connection may be unencrypted')
"
```

### OPC UA Write Access Testing

Test whether process variables can be modified without proper authorization:

```bash
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
client.connect()
objects = client.get_objects_node()
writable_vars = []
for node in objects.get_children():
    for var in node.get_variables():
        try:
            old = var.get_value()
            # Test with a non-destructive write (same value)
            var.set_value(old)
            writable_vars.append(var.get_browse_name().Name)
        except Exception as e:
            pass  # Write blocked — good
print(f'Writable variables (no auth): {len(writable_vars)}')
for v in writable_vars:
    print(f'  - {v}')
client.disconnect()
"
```

## Part 5: Defense-in-Depth for Industrial Networks

### Recommended Architecture

A properly secured ICS network implements multiple defensive layers:

1. **Perimeter Firewall (IT/OT Boundary)** — Stateful inspection firewall between enterprise IT and the Industrial DMZ. Blocks all direct IT-to-OT communication.

2. **Industrial DMZ (IDMZ)** — Contains data historians, OPC UA gateways, and mirror servers. All data flows from OT to IT must pass through the DMZ using unidirectional replication.

3. **OT Firewall** — Protocol-aware firewall between DMZ and OT control network. Enforces allowlists for Modbus function codes, S7comm operations, and EtherNet/IP CIP commands.

4. **Network Monitoring** — Passive ICS-aware IDS/IPS monitoring all OT traffic. Uses protocol-specific signatures to detect unauthorized commands, malformed packets, and anomalous communication patterns.

5. **Endpoint Protection** — Application whitelisting on HMI and engineering workstations. USB device control. Host-based intrusion detection on all Windows systems in OT.

6. **Access Control** — Multi-factor authentication for all remote access. Role-based access for HMI and engineering software. Privileged access management for PLC programming.

### Continuous Monitoring Checklist

Implement these ongoing monitoring activities:

- Monitor for new devices on the OT network (unauthorized device detection)
- Alert on Modbus write commands from any IP not in the authorized master list
- Alert on S7comm session establishment from non-engineering workstation IPs
- Monitor OPC UA certificate changes and new endpoint registrations
- Track EtherNet/IP session counts and alert on sudden increases
- Log all conpot honeypot interactions and integrate with SIEM
- Review firewall logs daily for blocked cross-zone connection attempts
- Monitor for ICS protocol traffic on non-standard ports (tunneling detection)

## Part 6: ICS Network Traffic Forensics

### Full-Session Traffic Capture and Analysis

Comprehensive traffic capture during ICS assessments provides evidence for findings and enables post-engagement analysis. Proper capture techniques ensure all protocol layers are preserved.

```bash
# Full-packet capture with ring buffer (1GB files, keep 10)
tcpdump -i eth0 -w ics_forensics.pcap -W 10 -C 1000 \
  'port 502 or port 102 or port 44818 or port 4840 or port 20000 or udp port 47808 or ether proto 0x88b8'

# Extract TCP streams for individual device sessions
tshark -r ics_forensics.pcap -Y "tcp.port==502 && ip.addr==192.168.1.10" \
  -T fields -e frame.time -e ip.src -e ip.dst -e modbus.funccode -e modbus.transid

# Generate protocol distribution report
tshark -r ics_forensics.pcap -T fields -e frame.protocols | \
  tr ',' '\n' | sort | uniq -c | sort -rn | head -30
```

### Modbus Session Reconstruction

```bash
# Extract complete Modbus request-response pairs
python3 -c "
import subprocess
from collections import defaultdict

# Extract Modbus traffic with transaction IDs
result = subprocess.run([
    'tshark', '-r', 'ics_forensics.pcap', '-Y', 'modbus',
    '-T', 'fields', '-e', 'frame.time', '-e', 'ip.src',
    '-e', 'ip.dst', '-e', 'modbus.transid', '-e', 'modbus.funccode',
    '-e', 'tcp.flags'
], capture_output=True, text=True)

sessions = defaultdict(list)
for line in result.stdout.strip().split('\n'):
    fields = line.split('\t')
    if len(fields) >= 6:
        time, src, dst, tid, fc, flags = fields
        sessions[tid].append({
            'time': time, 'src': src, 'dst': dst,
            'fc': fc, 'flags': flags
        })

# Identify request-response pairs
for tid, msgs in sorted(sessions.items()):
    if len(msgs) == 2:
        req, resp = msgs[0], msgs[1]
        print(f'TID={tid} | {req[\"src\"]}->{resp[\"src\"]} FC={req[\"fc\"]} ({req[\"time\"]})')
    elif len(msgs) > 2:
        print(f'TID={tid} | MULTI-PART ({len(msgs)} messages)')
"
```

### Anomaly Detection Through Statistical Analysis

```bash
# Compute traffic volume statistics per protocol
python3 -c "
import subprocess
from collections import Counter

result = subprocess.run([
    'tshark', '-r', 'ics_forensics.pcap',
    '-T', 'fields', '-e', 'frame.time_relative', '-e', 'tcp.dstport'
], capture_output=True, text=True)

# Count packets per port per minute
port_minute = Counter()
for line in result.stdout.strip().split('\n'):
    fields = line.split('\t')
    if len(fields) >= 2:
        rel_time = float(fields[0])
        port = fields[1]
        minute = int(rel_time / 60)
        port_minute[(port, minute)] += 1

# Report traffic patterns
for (port, minute), count in sorted(port_minute.items()):
    proto = {'502': 'Modbus', '102': 'S7comm', '44818': 'ENIP', '4840': 'OPC-UA', '20000': 'DNP3'}.get(port, port)
    print(f'Minute {minute:4d} | {proto:8s} | {count:5d} packets')
"
```

## Part 7: ICS Network Hardening Assessment

### Firewall Rule Audit

```bash
# Test specific firewall rules by source/destination port combinations
# Verify Modbus write commands are blocked at the IT/OT boundary
nmap -sT -p 502 --script modbus-discover --script-args modbus-discover.unitid=1 \
  --source-port 1024 10.0.2.0/24

# Test for protocol tunneling through allowed ports
# Check if ICS protocols are encapsulated in HTTP/HTTPS
nmap -sT -p 80,443,8080 -sV --version-intensity 5 10.0.2.0/24

# Verify no SSH tunnels exist from IT to OT
nmap -sT -p 22 -sV 10.0.2.0/24
```

### VLAN Segmentation Verification

```bash
# Enumerate VLANs visible from the OT network
# Using DTP (Dynamic Trunking Protocol) where applicable
python3 -c "
# Check 802.1Q VLAN tags in captured traffic
from scapy.all import *
packets = rdpcap('ics_forensics.pcap')
vlans = set()
for pkt in packets:
    if pkt.haslayer(Dot1Q):
        vlans.add(pkt[Dot1Q].vlan)
print(f'VLANs observed: {sorted(vlans)}')
if len(vlans) > 1:
    print('WARNING: Multiple VLANs visible from current position')
    print('VLAN separation may not be properly enforced')
"

# Test for VLAN hopping via double-tagging
# This requires specific switch configurations to be vulnerable
python3 -c "
from scapy.all import *
# Craft double-tagged 802.1Q frame
# Outer VLAN (native/allowed) + Inner VLAN (target)
inner_frame = Ether()/Dot1Q(vlan=100)/IP(dst='10.0.2.10')/TCP(dport=502)
outer_frame = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst='10.0.2.10')/TCP(dport=502)
print('Double-tagged frame crafted (for lab testing only)')
"
```

### Data Diode Verification

Data diodes (unidirectional security gateways) are used in high-security ICS environments to ensure data flows only from OT to IT. Verification ensures the diode is properly enforcing unidirectionality.

```bash
# From IT side, attempt to reach OT devices (should fail)
# From OT side, attempt to send data to IT side (should succeed for reads only)
nmap -sT -p 502,102,44818 <ot_device_ip>  # Should show filtered/no response

# Verify data replication works in the allowed direction
# Check historian in DMZ is receiving data from OT historian
python3 -c "
import opcua
# Connect to DMZ historian
client_dmz = opcua.Client('opc.tcp://dmz-historian:4840')
client_dmz.connect()
# Read a value that should be replicated from OT
node = client_dmz.get_node('ns=2;s=Process.Temperature')
value = node.get_value()
print(f'DMZ historian temperature: {value}')
client_dmz.disconnect()
print('Data replication verified in OT->IT direction')
"
```

## Part 8: Compliance and Framework Mapping

### IEC 62443 Compliance Assessment

Map findings to IEC 62443 security levels and requirements:

```bash
# IEC 62443-3-3 System Security Requirements mapping
python3 -c "
requirements = {
    'SR 1.1': 'Human User Identification - verify unique user accounts on all HMI/SCADA',
    'SR 1.2': 'SW Process Identification - verify application whitelisting on OT systems',
    'SR 2.1': 'Authorization Enforcement - verify RBAC on OPC UA, HMI access',
    'SR 2.4': 'Mobile Code - verify no unauthorized code execution on OT devices',
    'SR 3.1': 'Communication Integrity - verify protocol encryption (OPC UA TLS, no Modbus-in-clear)',
    'SR 4.1': 'Information Confidentiality - verify encrypted storage of PLC programs',
    'SR 5.1': 'Network Segmentation - verify Purdue Model compliance',
    'SR 5.2': 'Zone Boundary Protection - verify firewall rules at each zone boundary',
    'SR 5.3': 'General Purpose Person-to-Person Communication Restrictions - verify no direct IT-to-OT comms',
    'SR 6.1': 'Audit Log Accessibility - verify centralized logging for all OT devices',
    'SR 7.1': 'DoS Protection - verify rate limiting on protocol-facing interfaces',
    'SR 7.2': 'Resource Management - verify PLC resource limits (connections, memory)',
}

for req_id, description in sorted(requirements.items()):
    print(f'{req_id}: {description}')
"
```

### NERC CIP Assessment (Electric Utilities)

For electric utility environments subject to NERC CIP (Critical Infrastructure Protection) standards, specific compliance requirements apply:

```bash
# NERC CIP-005: Electronic Security Perimeter
# Verify all external connections to the ESP are documented
# Test that all access points through the ESP require authentication
nmap -sT -p 22,80,443,502,102,4840,44818,20000 <esp_boundary_ip>

# NERC CIP-007: System Security Management
# Verify patch levels on all systems within the ESP
# Check for default credentials
nmap --script default-credentials -p 22,80,443 <hmi_ip>

# NERC CIP-010: Configuration Change Management
# Verify baseline configurations exist and are monitored
# Check for unauthorized changes to PLC programs
python3 -c "
import hashlib
# Compare current PLC program hash against baseline
current_hash = 'abc123...'  # Would be computed from actual program dump
baseline_hash = 'abc123...'  # From configuration management system
match = current_hash == baseline_hash
print(f'Configuration integrity: {\"PASS\" if match else \"FAIL - unauthorized change detected\"}')
"
```

## References

- IEC 62443: Industrial Automation and Control Systems Security — https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- NIST SP 800-82 Rev. 3: Guide to Operational Technology (OT) Security — https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- NERC CIP Standards — https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx
- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- Purdue Enterprise Reference Architecture (ISA-95) — https://www.isa.org/standards-and-publications/isa-standards/isa-95
- CISA ICS-CERT Advisories — https://www.cisa.gov/news-events/cybersecurity-advisories
- conpot ICS honeypot — https://github.com/mushorg/conpot
- Dragos ICS threat intelligence — https://www.dragos.com
