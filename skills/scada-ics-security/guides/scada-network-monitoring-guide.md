# SCADA Network Monitoring and Protocol Anomaly Detection Guide

## Introduction

Passive network monitoring is the cornerstone of ICS security assessment and defense. Unlike active scanning that interacts with devices, passive monitoring captures and analyzes network traffic without sending any packets to the target devices. This makes it safe for production ICS environments where active testing could disrupt critical processes. Protocol anomaly detection builds on passive monitoring by establishing baselines of normal communication patterns and alerting on deviations.

This guide covers passive ICS network monitoring techniques, protocol-specific anomaly detection, traffic analysis methodology, and the integration of monitoring into ICS security assessments. All techniques are designed to be non-intrusive and safe for deployment in production OT environments during authorized engagements.

**Objectives**: Establish passive ICS network monitoring, develop protocol anomaly detection rules, perform traffic baseline analysis, and create automated monitoring scripts for ICS security assessment.

## Part 1: Passive ICS Network Monitoring Setup

### Network Tap and SPAN Configuration

Before monitoring can begin, you need access to the network traffic. In ICS environments, this is typically achieved through SPAN (Switched Port Analyzer) ports on managed switches or network TAPs placed at strategic monitoring points.

```bash
# Verify SPAN port is receiving traffic
tcpdump -i eth0 -c 100 -nn
# Should see ICS protocol traffic (ports 502, 102, 44818, 4840, 20000)

# Check traffic volume on the monitoring interface
tcpdump -i eth0 -w /dev/null -c 10000 2>&1 | tail -1
# Note packets captured per second for baseline estimation
```

### Comprehensive ICS Traffic Capture

```bash
# Capture all ICS protocol traffic with full packet payload
tcpdump -i eth0 -w ics_full_capture.pcap \
  'port 502 or port 102 or port 44818 or port 4840 or port 20000 or udp port 47808 or ether proto 0x88b8' \
  -G 3600 -W 24 \  # Rotate every hour, keep 24 files (24 hours)
  -Z root

# Capture with packet size limit for long-term storage efficiency
tcpdump -i eth0 -w ics_longterm.pcap -s 256 \
  'port 502 or port 102 or port 44818 or port 4840 or port 20000' \
  -G 86400 -W 7  # Rotate daily, keep 7 days

# Real-time protocol distribution monitoring
tshark -i eth0 -f "port 502 or port 102 or port 44818 or port 4840 or port 20000 or udp port 47808" \
  -T fields -e frame.protocols 2>/dev/null | \
  awk -F',' '{print $NF}' | sort | uniq -c | sort -rn
```

### Multi-Interface Monitoring

For comprehensive coverage, monitor at multiple network positions simultaneously:

```bash
# Monitor at the OT firewall (IT/OT boundary)
tcpdump -i eth0 -w boundary_traffic.pcap 'port 502 or port 102 or port 44818' &

# Monitor at the control network switch (PLC communication)
tcpdump -i eth1 -w control_traffic.pcap 'port 502 or port 102' &

# Monitor at the DMZ (historian/OPC gateway traffic)
tcpdump -i eth2 -w dmz_traffic.pcap 'port 4840 or port 502' &

# Correlate captures by timestamp to trace attack paths
ls -la *.pcap | awk '{print $6, $7, $8, $9}'
```

## Part 2: Protocol-Specific Traffic Analysis

### Modbus TCP Traffic Analysis

Modbus is the most common ICS protocol and produces the most consistent traffic patterns, making it ideal for anomaly detection.

```bash
# Extract Modbus communication summary
tshark -r ics_full_capture.pcap -Y "modbus" -T fields \
  -e frame.time_relative -e ip.src -e ip.dst \
  -e modbus.transid -e modbus.unitid -e modbus.funccode \
  -e modbus.regnum -e modbus.regval16 | head -50

# Modbus master-slave communication map
tshark -r ics_full_capture.pcap -Y "modbus" -T fields \
  -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head -20

# Function code distribution (establish normal pattern)
tshark -r ics_full_capture.pcap -Y "modbus" -T fields \
  -e modbus.funccode | sort | uniq -c | sort -rn

# Register access patterns (which register ranges are normally accessed)
tshark -r ics_full_capture.pcap -Y "modbus.funccode == 3" -T fields \
  -e ip.src -e modbus.regnum | sort | uniq -c | sort -rn

# Polling interval analysis (detect timing anomalies)
tshark -r ics_full_capture.pcap -Y "tcp.port==502 && modbus.funccode==3" -T fields \
  -e frame.time_delta -e ip.src -e ip.dst | head -100
```

### S7comm Traffic Analysis

```bash
# S7comm session overview
tshark -r ics_full_capture.pcap -Y "s7comm" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e s7comm.param.func -e s7comm.param.reqfunc | head -50

# Identify S7comm session establishments
tshark -r ics_full_capture.pcap -Y "s7comm.param.func == 0x02" -T fields \
  -e frame.time -e ip.src -e ip.dst

# Monitor for PLC state changes (CPU stop/start commands)
tshark -r ics_full_capture.pcap -Y "s7comm.param.func == 0x08" -T fields \
  -e frame.time -e ip.src -e ip.dst -e s7comm.param

# Track data block access patterns
tshark -r ics_full_capture.pcap -Y "s7comm.param.func == 0x04" -T fields \
  -e frame.time -e ip.src -e s7comm.param.db | sort | uniq -c | sort -rn

# Detect block upload/download operations (program modification)
tshark -r ics_full_capture.pcap \
  -Y "s7comm.param.func == 0x1a || s7comm.param.func == 0x1b || s7comm.param.func == 0x1c" \
  -T fields -e frame.time -e ip.src -e ip.dst -e s7comm.param.func
```

### EtherNet/IP Traffic Analysis

```bash
# EtherNet/IP session activity
tshark -r ics_full_capture.pcap -Y "enip" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e enip.command -e enip.status -e enip.session | head -50

# Session registration tracking (detect new/unauthorized sessions)
tshark -r ics_full_capture.pcap -Y "enip.command == 0x65" -T fields \
  -e frame.time -e ip.src -e ip.dst -e enip.session

# CIP command distribution
tshark -r ics_full_capture.pcap -Y "enip" -T fields \
  -e enip.command | sort | uniq -c | sort -rn

# Implicit messaging connections (real-time I/O data)
tshark -r ics_full_capture.pcap \
  -Y "enip.command == 0x5a || enip.command == 0x5b" -T fields \
  -e frame.time -e ip.src -e ip.dst
```

### DNP3 Traffic Analysis

```bash
# DNP3 communication summary
tshark -r ics_full_capture.pcap -Y "dnp3" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e dnp3.src -e dnp3.dst -e dnp3.func | head -50

# DNP3 data object analysis
tshark -r ics_full_capture.pcap -Y "dnp3" -T fields \
  -e dnp3.obj.group -e dnp3.obj.variation | sort | uniq -c | sort -rn

# Monitor for DNP3 control commands (Direct Operate, FC 5)
tshark -r ics_full_capture.pcap -Y "dnp3.func == 5" -T fields \
  -e frame.time -e ip.src -e ip.dst
```

## Part 3: Protocol Anomaly Detection

### Baseline Establishment

```python
#!/usr/bin/env python3
"""Establish ICS network traffic baseline for anomaly detection."""

import subprocess
import json
import time
from collections import defaultdict, Counter
from datetime import datetime

class ICSBaselineBuilder:
    """Build behavioral baseline from captured ICS traffic."""

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.baseline = {
            'modbus': {
                'masters': set(),       # IPs that send Modbus requests
                'slaves': set(),        # IPs that receive Modbus requests
                'function_codes': Counter(),
                'register_ranges': defaultdict(set),  # master -> set of (start, count)
                'slave_ids': set(),
                'polling_intervals': defaultdict(list),
            },
            's7comm': {
                'masters': set(),
                'slaves': set(),
                'operations': Counter(),
                'data_blocks': defaultdict(set),
            },
            'enip': {
                'clients': set(),
                'servers': set(),
                'commands': Counter(),
                'sessions': set(),
            }
        }

    def build(self):
        """Parse PCAP and build baseline."""
        # Modbus baseline
        result = subprocess.run([
            'tshark', '-r', self.pcap_file, '-Y', 'modbus',
            '-T', 'fields',
            '-e', 'ip.src', '-e', 'ip.dst',
            '-e', 'modbus.funccode', '-e', 'modbus.unitid',
            '-e', 'modbus.regnum'
        ], capture_output=True, text=True)

        last_time = {}
        for line in result.stdout.strip().split('\n'):
            fields = line.split('\t')
            if len(fields) >= 4:
                src, dst, fc, unitid = fields[0], fields[1], fields[2], fields[3]
                self.baseline['modbus']['masters'].add(src)
                self.baseline['modbus']['slaves'].add(dst)
                self.baseline['modbus']['function_codes'][fc] += 1
                self.baseline['modbus']['slave_ids'].add(unitid)

                if len(fields) >= 5 and fields[4]:
                    key = f'{src}->{dst}'
                    self.baseline['modbus']['register_ranges'][key].add(fields[4])

        # Convert sets to lists for JSON serialization
        for proto in self.baseline:
            if 'masters' in self.baseline[proto]:
                self.baseline[proto]['masters'] = sorted(list(self.baseline[proto]['masters']))
                self.baseline[proto]['slaves'] = sorted(list(self.baseline[proto]['slaves']))

        for key in self.baseline['modbus']['register_ranges']:
            self.baseline['modbus']['register_ranges'][key] = \
                list(self.baseline['modbus']['register_ranges'][key])

        self.baseline['modbus']['slave_ids'] = sorted(list(self.baseline['modbus']['slave_ids']))

        return self.baseline

    def save(self, output_file):
        """Save baseline to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)
        print(f'Baseline saved to {output_file}')

# Build baseline from captured traffic
builder = ICSBaselineBuilder('ics_full_capture.pcap')
baseline = builder.build()
builder.save('ics_baseline.json')

# Print summary
print(f'\nBaseline Summary:')
print(f'  Modbus masters: {len(baseline["modbus"]["masters"])}')
print(f'  Modbus slaves: {len(baseline["modbus"]["slaves"])}')
print(f'  Function codes: {dict(baseline["modbus"]["function_codes"])}')
print(f'  Slave IDs: {baseline["modbus"]["slave_ids"]}')
```

### Real-Time Anomaly Detection

```python
#!/usr/bin/env python3
"""Real-time ICS protocol anomaly detection."""

import subprocess
import json
import time
from collections import Counter

class ICSAnomalyDetector:
    """Detect anomalies in real-time ICS network traffic."""

    def __init__(self, baseline_file):
        with open(baseline_file, 'r') as f:
            self.baseline = json.load(f)
        self.alert_count = 0

    def check_modbus_anomaly(self, src, dst, fc, unitid, regnum=None):
        """Check Modbus traffic against baseline for anomalies."""
        alerts = []

        # Check for unknown master
        if src not in self.baseline['modbus']['masters']:
            alerts.append({
                'severity': 'HIGH',
                'type': 'Unknown Modbus Master',
                'details': f'IP {src} sending Modbus commands (not in baseline)',
                'source': src
            })

        # Check for write function codes
        if fc in ['5', '6', '15', '16']:
            if fc not in self.baseline['modbus']['function_codes']:
                alerts.append({
                    'severity': 'HIGH',
                    'type': 'Unauthorized Modbus Write',
                    'details': f'Function code {fc} from {src} to {dst} '
                              f'(write operations not in baseline)',
                    'source': src
                })

        # Check for unknown slave IDs
        if unitid not in self.baseline['modbus']['slave_ids']:
            alerts.append({
                'severity': 'MEDIUM',
                'type': 'Unknown Modbus Slave ID',
                'details': f'Slave ID {unitid} accessed by {src} '
                          f'(not in baseline)',
                'source': src
            })

        # Check for new register ranges
        if regnum:
            key = f'{src}->{dst}'
            if key in self.baseline['modbus']['register_ranges']:
                if regnum not in self.baseline['modbus']['register_ranges'][key]:
                    alerts.append({
                        'severity': 'MEDIUM',
                        'type': 'New Register Range Access',
                        'details': f'Register range {regnum} accessed by {src} '
                                  f'(not in baseline)',
                        'source': src
                    })

        return alerts

    def run_realtime_detection(self, interface='eth0'):
        """Run continuous real-time anomaly detection."""
        print(f'Starting real-time ICS anomaly detection on {interface}...')
        print(f'Loaded baseline with:')
        print(f'  {len(self.baseline["modbus"]["masters"])} Modbus masters')
        print(f'  {len(self.baseline["modbus"]["slaves"])} Modbus slaves')
        print()

        proc = subprocess.Popen([
            'tshark', '-i', interface, '-f', 'port 502',
            '-Y', 'modbus',
            '-T', 'fields',
            '-e', 'ip.src', '-e', 'ip.dst',
            '-e', 'modbus.funccode', '-e', 'modbus.unitid',
            '-e', 'modbus.regnum'
        ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        for line in proc.stdout:
            fields = line.strip().split('\t')
            if len(fields) >= 4:
                src, dst, fc, unitid = fields[0], fields[1], fields[2], fields[3]
                regnum = fields[4] if len(fields) > 4 else None

                alerts = self.check_modbus_anomaly(src, dst, fc, unitid, regnum)
                for alert in alerts:
                    self.alert_count += 1
                    timestamp = time.strftime('%H:%M:%S')
                    print(f'[{timestamp}] [{alert["severity"]}] '
                          f'{alert["type"]}: {alert["details"]}')

        print(f'\nTotal alerts: {self.alert_count}')

# Example usage (requires baseline to be built first)
# detector = ICSAnomalyDetector('ics_baseline.json')
# detector.run_realtime_detection('eth0')
print('ICS Anomaly Detector initialized')
print('Build baseline first, then run real-time detection')
```

### Suricata ICS Ruleset

```bash
# Create comprehensive ICS-specific Suricata rules
cat > /etc/suricata/rules/ics_anomaly.rules << 'RULES'
# Modbus Anomaly Detection Rules

# Alert on Modbus write operations (FC 5, 6, 15, 16)
alert tcp any any -> any 502 (msg:"ICS MODBUS Write Single Coil (FC05)"; \
  content:"|00 00 00 00 00|"; depth:5; content:"|05|"; offset:7; depth:1; \
  sid:2000001; rev:1; classtype:protocol-command-decode;)

alert tcp any any -> any 502 (msg:"ICS MODBUS Write Single Register (FC06)"; \
  content:"|00 00 00 00 00|"; depth:5; content:"|06|"; offset:7; depth:1; \
  sid:2000002; rev:1; classtype:protocol-command-decode;)

alert tcp any any -> any 502 (msg:"ICS MODBUS Write Multiple Coils (FC15)"; \
  content:"|00 00 00 00 00|"; depth:5; content:"|0F|"; offset:7; depth:1; \
  sid:2000003; rev:1; classtype:protocol-command-decode;)

alert tcp any any -> any 502 (msg:"ICS MODBUS Write Multiple Registers (FC16)"; \
  content:"|00 00 00 00 00|"; depth:5; content:"|10|"; offset:7; depth:1; \
  sid:2000004; rev:1; classtype:protocol-command-decode;)

# Alert on Modbus from external networks
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"ICS MODBUS External Access Attempt"; \
  sid:2000010; rev:1; classtype:attempted-admin;)

# Alert on Modbus exception responses (indicates scanning or errors)
alert tcp $HOME_NET 502 -> any any (msg:"ICS MODBUS Exception Response"; \
  content:"|00 00 00 00 00|"; depth:5; content:"|8"; offset:7; depth:1; \
  sid:2000020; rev:1; classtype:protocol-command-decode;)

# S7comm Anomaly Detection Rules

# Alert on S7comm PLC Stop command
alert tcp any any -> any 102 (msg:"ICS S7COMM PLC Stop Command"; \
  content:"|32|"; offset:0; depth:1; content:"|28|"; offset:17; depth:1; \
  sid:2000030; rev:1; classtype:attempted-dos;)

# Alert on S7comm from non-baseline sources
alert tcp !$S7_MASTERS any -> $S7_SLAVES 102 (msg:"ICS S7COMM Unauthorized Source"; \
  sid:2000031; rev:1; classtype:attempted-admin;)

# Alert on S7comm block download (program modification)
alert tcp any any -> any 102 (msg:"ICS S7COMM Block Download"; \
  content:"|32|"; offset:0; depth:1; content:"|1A|"; offset:17; depth:1; \
  sid:2000032; rev:1; classtype:attempted-admin;)

# EtherNet/IP Anomaly Detection Rules

# Alert on EtherNet/IP session from external network
alert tcp $EXTERNAL_NET any -> $HOME_NET 44818 (msg:"ICS ENIP External Connection"; \
  content:"|65 00|"; offset:0; depth:2; \
  sid:2000040; rev:1; classtype:attempted-admin;)

# Alert on EtherNet/IP ForwardOpen (implicit messaging)
alert tcp any any -> any 44818 (msg:"ICS ENIP ForwardOpen Request"; \
  content:"|5A 00|"; offset:0; depth:2; \
  sid:2000041; rev:1; classtype:protocol-command-decode;)

# GOOSE Anomaly Detection Rules

# Alert on GOOSE messages with anomalous stNum jumps
alert eth any any -> any any (msg:"ICS GOOSE Message Detected"; \
  ether_proto:0x88b8; \
  sid:2000050; rev:1; classtype:protocol-command-decode;)
RULES

# Test rules against captured traffic
suricata -r ics_full_capture.pcap -c /etc/suricata/suricata.yaml \
  -l /tmp/ics_ids_test/

# Review alerts
cat /tmp/ics_ids_test/fast.log
```

## Part 4: Traffic Forensics and Analysis

### Deep Packet Analysis

```python
#!/usr/bin/env python3
"""Deep ICS protocol packet analysis for security assessment."""

from scapy.all import *
from collections import defaultdict
import struct

class ICSDeepAnalyzer:
    """Deep analysis of ICS protocol traffic from PCAP files."""

    def __init__(self, pcap_file):
        self.packets = rdpcap(pcap_file)
        self.findings = []

    def analyze_modbus_sessions(self):
        """Analyze Modbus TCP sessions for security findings."""
        modbus_sessions = defaultdict(list)

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
                if pkt.haslayer(Raw):
                    raw = bytes(pkt[Raw].load)
                    if len(raw) >= 8:
                        tid = struct.unpack('>H', raw[0:2])[0]
                        fc = raw[7]
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst

                        modbus_sessions[(src_ip, dst_ip)].append({
                            'time': float(pkt.time),
                            'tid': tid,
                            'fc': fc,
                            'length': len(raw),
                            'raw': raw
                        })

        # Analyze each session
        for (src, dst), messages in modbus_sessions.items():
            # Check for write operations
            write_fcs = [5, 6, 15, 16]
            writes = [m for m in messages if m['fc'] in write_fcs]
            if writes:
                self.findings.append({
                    'severity': 'HIGH',
                    'type': 'Modbus Write Operations Detected',
                    'source': src,
                    'destination': dst,
                    'details': f'{len(writes)} write operations '
                              f'(FCs: {set(m["fc"] for m in writes)})'
                })

            # Check for sequential register scanning
            reads = [m for m in messages if m['fc'] == 3]
            if len(reads) > 10:
                register_ranges = set()
                for r in reads:
                    if len(r['raw']) >= 12:
                        start = struct.unpack('>H', r['raw'][8:10])[0]
                        count = struct.unpack('>H', r['raw'][10:12])[0]
                        register_ranges.add((start, count))

                if len(register_ranges) > 5:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'type': 'Modbus Register Scanning Pattern',
                        'source': src,
                        'destination': dst,
                        'details': f'{len(register_ranges)} distinct register ranges '
                                  f'accessed from {src}'
                    })

        return self.findings

    def generate_report(self):
        """Generate analysis report."""
        self.analyze_modbus_sessions()

        print('ICS Deep Packet Analysis Report')
        print('=' * 60)
        print(f'Total packets analyzed: {len(self.packets)}')
        print(f'Findings: {len(self.findings)}')
        print()

        for finding in sorted(self.findings, key=lambda x: x['severity']):
            print(f'[{finding["severity"]}] {finding["type"]}')
            print(f'  Source: {finding["source"]} -> Destination: {finding["destination"]}')
            print(f'  Details: {finding["details"]}')
            print()

# Usage
print('ICS Deep Packet Analyzer')
print('Usage: analyzer = ICSDeepAnalyzer("capture.pcap")')
print('       analyzer.generate_report()')
```

### Long-Term Trend Analysis

```bash
# Analyze traffic trends over multiple capture files
for f in ics_full_capture*.pcap; do
  echo "=== $f ==="
  # Packet count per protocol
  tshark -r "$f" -T fields -e frame.protocols 2>/dev/null | \
    grep -oP '(modbus|s7comm|enip|dnp3|bacnet)' | sort | uniq -c | sort -rn
  # Unique IP pairs
  echo "Unique IP pairs:"
  tshark -r "$f" -T fields -e ip.src -e ip.dst 2>/dev/null | \
    sort -u | wc -l
  echo
done

# Generate hourly traffic volume report
python3 -c "
import subprocess
import re
from collections import defaultdict

# Run tshark with timestamp and protocol fields
result = subprocess.run([
    'tshark', '-r', 'ics_full_capture.pcap',
    '-T', 'fields', '-e', 'frame.time_relative',
    '-e', 'tcp.dstport'
], capture_output=True, text=True)

hourly = defaultdict(lambda: defaultdict(int))
for line in result.stdout.strip().split('\n'):
    fields = line.split('\t')
    if len(fields) >= 2:
        try:
            rel_time = float(fields[0])
            port = fields[1]
            hour = int(rel_time / 3600)
            proto = {
                '502': 'Modbus', '102': 'S7comm',
                '44818': 'ENIP', '4840': 'OPC-UA',
                '20000': 'DNP3'
            }.get(port, port)
            hourly[hour][proto] += 1
        except (ValueError, IndexError):
            pass

print('Hourly Traffic Volume Report')
print('=' * 70)
print(f'{\"Hour\":<6} {\"Modbus\":<10} {\"S7comm\":<10} {\"ENIP\":<10} {\"OPC-UA\":<10} {\"DNP3\":<10}')
print('-' * 70)
for hour in sorted(hourly.keys()):
    counts = hourly[hour]
    print(f'{hour:<6} '
          f'{counts.get(\"Modbus\", 0):<10} '
          f'{counts.get(\"S7comm\", 0):<10} '
          f'{counts.get(\"ENIP\", 0):<10} '
          f'{counts.get(\"OPC-UA\", 0):<10} '
          f'{counts.get(\"DNP3\", 0):<10}')
"
```

## Practical Steps

1. **Deploy passive monitoring** using SPAN ports or network TAPs at strategic ICS network positions
2. **Capture baseline traffic** for at least 24 hours (ideally one full operational cycle)
3. **Build behavioral baseline** using the baseline builder script
4. **Deploy IDS rules** based on the Suricata ICS ruleset
5. **Run real-time detection** during the assessment engagement
6. **Perform deep packet analysis** on any anomalous traffic detected
7. **Document findings** with protocol-specific evidence and remediation guidance

## Hands-on Exercises

### Exercise 1: Baseline Capture and Analysis

Capture 1 hour of ICS traffic and build a behavioral baseline using the baseline builder script.

```bash
timeout 3600 tcpdump -i eth0 -w ics_baseline.pcap \
  'port 502 or port 102 or port 44818 or port 4840'
python3 baseline_builder.py ics_baseline.pcap
```

### Exercise 2: Anomaly Detection Setup

Configure Suricata with ICS-specific rules and test against captured traffic.

```bash
suricata -r ics_baseline.pcap -c /etc/suricata/suricata.yaml -l /tmp/ics_ids/
cat /tmp/ics_ids/fast.log
```

### Exercise 3: Real-Time Monitoring

Deploy real-time Modbus anomaly detection and observe alerts during simulated ICS interactions.

```bash
python3 anomaly_detector.py ics_baseline.json eth0
# From another terminal, generate test traffic
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 10 -t holding
```

### Exercise 4: Forensic Analysis

Perform deep packet analysis on a provided PCAP file to identify suspicious ICS protocol activity and generate a findings report.

```bash
python3 deep_analyzer.py suspicious_capture.pcap
```

## References

- Suricata IDS — https://suricata.io/
- Wireshark ICS protocol dissectors — https://wiki.wireshark.org/Protocols
- NIST SP 800-82 Rev. 3: Guide to Operational Technology Security — https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- MITRE ATT&CK for ICS: Discovery techniques — https://attack.mitre.org/tactics/ICS/
- ICS-CERT monitoring guidance — https://www.cisa.gov/topics/cybersecurity-best-practices/industrial-control-systems
- IEC 62443-3-3: System security requirements and security levels
- Scapy documentation — https://scapy.readthedocs.io/
- tshark display filter reference — https://www.wireshark.org/docs/dfref/