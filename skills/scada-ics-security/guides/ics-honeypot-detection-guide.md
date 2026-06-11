# ICS Honeypot Detection and Deception Techniques Guide

## Introduction

ICS honeypots are deceptive security controls that emulate industrial control system devices to detect unauthorized network activity. They serve as early warning systems that reveal intruders before they reach real production equipment. From a penetration testing perspective, understanding honeypot deployment and detection is critical for two reasons: first, to provide realistic assessment outcomes by identifying honeypots rather than treating them as real devices; second, to help defenders improve their honeypot implementations by understanding how attackers identify and evade them.

This guide covers both sides of the honeypot equation: deploying effective ICS honeypots using conpot and other tools, and detecting honeypots during offensive engagements. It also covers advanced ICS deception techniques that go beyond simple honeypot deployment.

**Objectives**: Deploy and configure ICS honeypots, detect honeypot implementations during testing, design deception campaigns, and integrate honeypot alerts with security monitoring.

## Part 1: Conpot Deployment and Configuration

### Basic Conpot Setup

conpot is the most widely used open-source ICS honeypot. It emulates Modbus TCP, IPMI, SNMP, HTTP, and other industrial protocols with configurable device templates.

```bash
# Install conpot and dependencies
pip3 install conpot

# List available templates
ls /usr/share/conpot/templates/

# Deploy with default Modbus template
conpot -f --template default

# Deploy with Kamstrup smart meter template
conpot -f --template kemel --host 192.168.1.200

# Deploy with custom IP and detailed logging
conpot -f --template default --host 192.168.1.200 \
  --logfile /var/log/conpot.log \
  --temp_dir /tmp/conpot

# Deploy in background mode
conpot -f --template default --host 192.168.1.200 \
  >> /var/log/conpot.log 2>&1 &
```

### Custom Conpot Template Development

Default templates may not match the target ICS environment. Custom templates increase honeypot realism by mimicking the specific device types present in the network.

```bash
# Create a custom template directory
mkdir -p /opt/conpot/templates/custom_plc

# Create a custom Modbus template that mimics a specific PLC
cat > /opt/conpot/templates/custom_plc/template.xml << 'TEMPLATE'
<?xml version="1.0" ?>
<session>
  <protocols>
    <modbus>
      <slave id="1">
        <holding_registers>
          <!-- Temperature sensor readings (realistic process values) -->
          <register idx="0">
            <value>725</value>  <!-- 72.5°F temperature -->
          </register>
          <register idx="1">
            <value>450</value>  <!-- 45.0% humidity -->
          </register>
          <register idx="2">
            <value>1200</value>  <!-- 120.0 PSI pressure -->
          </register>
          <!-- Setpoint registers -->
          <register idx="10">
            <value>750</value>  <!-- Temperature setpoint 75.0°F -->
          </register>
          <!-- Alarm registers -->
          <register idx="20">
            <value>0</value>  <!-- No alarms active -->
          </register>
          <!-- Device status -->
          <register idx="30">
            <value>1</value>  <!-- System running -->
          </register>
        </holding_registers>
        <coils>
          <coil idx="0">
            <value>1</value>  <!-- Pump 1 running -->
          </coil>
          <coil idx="1">
            <value>0</value>  <!-- Pump 2 standby -->
          </coil>
          <coil idx="2">
            <value>1</value>  <!-- Valve open -->
          </coil>
        </coils>
      </slave>
    </modbus>
  </protocols>
</session>
TEMPLATE

# Deploy with custom template
conpot -f --template /opt/conpot/templates/custom_plc --host 192.168.1.201
```

### Dynamic Register Simulation

Static register values are a key honeypot indicator. Real PLC registers change over time as the physical process evolves. Dynamic simulation adds realism.

```python
#!/usr/bin/env python3
"""Dynamic Modbus register simulation for conpot honeypot enhancement."""

import time
import math
import random
from datetime import datetime

class ProcessSimulator:
    """Simulate realistic industrial process values for Modbus registers."""

    def __init__(self):
        self.start_time = time.time()
        self.base_temp = 72.5  # Fahrenheit
        self.base_pressure = 120.0  # PSI
        self.base_flow = 450.0  # GPM
        self.pump_states = [True, False, True]  # 3 pumps

    def get_temperature(self):
        """Simulate temperature with slow sinusoidal variation + noise."""
        elapsed = time.time() - self.start_time
        # Slow drift (building thermal dynamics)
        temp = self.base_temp + 2.0 * math.sin(elapsed / 3600)
        # Fast noise (sensor reading jitter)
        temp += random.gauss(0, 0.3)
        return int(temp * 10)  # Fixed-point: 725 = 72.5F

    def get_pressure(self):
        """Simulate pressure with pump-induced oscillation."""
        elapsed = time.time() - self.start_time
        pressure = self.base_pressure
        # Pump-induced ripple (30Hz oscillation)
        pressure += 5.0 * math.sin(elapsed * 30 * 2 * math.pi / 1000)
        # Random load changes
        pressure += random.gauss(0, 2.0)
        return max(0, int(pressure * 10))

    def get_flow_rate(self):
        """Simulate flow rate with step changes."""
        elapsed = time.time() - self.start_time
        flow = self.base_flow
        # Step changes every 5 minutes (valve operations)
        steps = int(elapsed / 300)
        flow += (steps % 3 - 1) * 50
        # Noise
        flow += random.gauss(0, 5.0)
        return max(0, int(flow))

    def get_humidity(self):
        """Simulate humidity with slow seasonal variation."""
        elapsed = time.time() - self.start_time
        humidity = 45.0 + 10.0 * math.sin(elapsed / 7200)
        humidity += random.gauss(0, 1.0)
        return max(0, min(100, int(humidity * 10)))

    def get_all_registers(self):
        """Return all register values as a dictionary."""
        return {
            0: self.get_temperature(),   # Temperature
            1: self.get_humidity(),      # Humidity
            2: self.get_pressure(),      # Pressure
            3: self.get_flow_rate(),     # Flow rate
            10: 750,                      # Temp setpoint
            11: 500,                      # Humidity setpoint
            20: 0,                        # Alarm status
            30: 1,                        # System running
        }

    def get_coils(self):
        """Return coil states."""
        return {
            0: self.pump_states[0],
            1: self.pump_states[1],
            2: self.pump_states[2],
        }

# Run continuous simulation
sim = ProcessSimulator()
print("Dynamic Process Simulation")
print("=" * 50)
for i in range(10):
    regs = sim.get_all_registers()
    coils = sim.get_coils()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
          f"Temp={regs[0]/10:.1f}F  Press={regs[2]/10:.1f}PSI  "
          f"Flow={regs[3]}GPM  Pumps={''.join(str(int(v)) for v in coils.values())}")
    time.sleep(2)
```

## Part 2: Honeypot Detection Techniques

### Network-Level Detection

Before interacting with any ICS device, perform passive reconnaissance to identify potential honeypots through network-level indicators.

```bash
# 1. IP address analysis - honeypots are often placed in unused IP ranges
# Check if the IP is in the expected device address range
nmap -sn 192.168.1.0/24 | grep "Host is up" | wc -l
# Compare against asset inventory

# 2. ARP table analysis - honeypots may have different MAC OUI patterns
arp -a | sort
# Compare MAC OUI prefixes (first 3 bytes) across all devices
# Real PLCs: Siemens (00:1C:06), Rockwell (00:00:BC), Schneider (00:80:F4)
# Honeypots: Standard Linux/VM MACs

# 3. Network behavior analysis - honeypots don't initiate connections
# Real PLCs poll sensors, send traps, and respond to master queries
# Honeypots only respond to incoming requests
timeout 300 tcpdump -i eth0 -c 1000 'host 192.168.1.200' -w honeypot_capture.pcap
# Check if the target ever initiates traffic
tshark -r honeypot_capture.pcap -T fields -e ip.src | sort | uniq -c | sort -rn
```

### Protocol-Level Detection

Honeypot implementations often have subtle protocol-level differences from real devices:

```bash
# 1. TCP/IP stack fingerprinting
nmap -O -sV 192.168.1.200
# Real PLCs: VxWorks, proprietary embedded OS, or custom RTOS
# conpot: Standard Linux kernel (Ubuntu/Debian)

# 2. Service enumeration completeness
nmap -sV -p 1-65535 --version-intensity 5 192.168.1.200
# Real PLCs: Multiple services (SNMP, FTP, HTTP, proprietary management)
# conpot: Only emulated protocol(s), missing auxiliary services

# 3. Modbus response timing analysis
python3 -c "
import socket
import struct
import time
import statistics

target = '192.168.1.200'
port = 502
response_times = []

# Send 20 identical Modbus Read Holding Registers requests
for i in range(20):
    # MBAP header + PDU for FC03 read
    mbap = struct.pack('>HHHB', i, 0, 6, 1)
    pdu = struct.pack('>BHH', 3, 0, 10)
    packet = mbap + pdu

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target, port))

    start = time.perf_counter()
    s.send(packet)
    response = s.recv(1024)
    elapsed = time.perf_counter() - start
    response_times.append(elapsed * 1000)  # Convert to ms

    s.close()
    time.sleep(0.1)

avg = statistics.mean(response_times)
stdev = statistics.stdev(response_times)
print(f'Response time statistics:')
print(f'  Mean: {avg:.3f} ms')
print(f'  Std Dev: {stdev:.3f} ms')
print(f'  Min: {min(response_times):.3f} ms')
print(f'  Max: {max(response_times):.3f} ms')
print(f'  CV: {stdev/avg*100:.1f}%')
print()
if stdev < 0.1:
    print('INDICATOR: Very consistent timing suggests software emulation')
elif stdev < 0.5:
    print('INDICATOR: Low timing variance, possible honeypot')
else:
    print('Timing variance consistent with real PLC processing')
"
```

### Data Realism Analysis

```python
#!/usr/bin/env python3
"""Analyze Modbus register data for honeypot indicators."""

import socket
import struct
import statistics

def analyze_register_realism(target_ip, port=502, num_samples=50, delay=0.5):
    """Collect and analyze register values for realism indicators."""
    import time

    all_reads = {i: [] for i in range(20)}  # Track 20 registers

    for sample in range(num_samples):
        # Read 20 holding registers starting at address 0
        mbap = struct.pack('>HHHB', sample, 0, 6, 1)
        pdu = struct.pack('>BHH', 3, 0, 20)
        packet = mbap + pdu

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, port))
            s.send(packet)
            response = s.recv(1024)

            # Parse register values from response
            if len(response) > 9:
                byte_count = response[8]
                register_data = response[9:9+byte_count]
                for i in range(0, len(register_data), 2):
                    if i//2 < 20:
                        value = struct.unpack('>H', register_data[i:i+2])[0]
                        all_reads[i//2].append(value)
            s.close()
        except Exception as e:
            print(f'Error: {e}')

        time.sleep(delay)

    # Analyze each register
    print('Register Data Analysis')
    print('=' * 60)

    for reg_num, values in sorted(all_reads.items()):
        if not values:
            continue

        unique_count = len(set(values))
        mean_val = statistics.mean(values)
        stdev_val = statistics.stdev(values) if len(values) > 1 else 0

        # Check for static values (zero variance = potential honeypot)
        if unique_count == 1:
            print(f'Reg {reg_num:3d}: STATIC value={values[0]:6d} '
                  f'[HONEYPOT INDICATOR - never changes]')
        elif stdev_val < 0.5:
            print(f'Reg {reg_num:3d}: NEAR-STATIC mean={mean_val:8.1f} '
                  f'std={stdev_val:.2f} [SUSPICIOUS]')
        else:
            print(f'Reg {reg_num:3d}: DYNAMIC  mean={mean_val:8.1f} '
                  f'std={stdev_val:.2f} range={min(values)}-{max(values)} '
                  f'unique={unique_count}')

# Example analysis
print('Honeypot Data Realism Analyzer')
print('Collecting samples for statistical analysis...')
print()
```

## Part 3: Advanced ICS Deception Techniques

### Honeynet Architecture

Deploying multiple interconnected honeypots creates a honeynet that simulates a realistic ICS network segment. This increases the fidelity of deception and provides more detailed attacker behavior analysis.

```bash
# Deploy multiple honeypots with different device profiles

# Honeypot 1: Modbus PLC (192.168.1.200)
conpot -f --template custom_plc --host 192.168.1.200 \
  --logfile /var/log/conpot_plc1.log &

# Honeypot 2: Modbus PLC with different device profile (192.168.1.201)
conpot -f --template custom_plc2 --host 192.168.1.201 \
  --logfile /var/log/conpot_plc2.log &

# Honeypot 3: HMI web interface (192.168.1.202)
# Use a web-based honeypot that emulates a SCADA HMI
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, datetime

class HMIHoneypot(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Emulate HMI dashboard
        html = '''<html><head><title>SCADA HMI - Process Overview</title></head>
        <body><h1>Process Control Dashboard</h1>
        <table border='1'>
        <tr><th>Zone</th><th>Temperature</th><th>Pressure</th><th>Status</th></tr>
        <tr><td>Zone A</td><td>72.5F</td><td>120.0 PSI</td><td>RUNNING</td></tr>
        <tr><td>Zone B</td><td>68.3F</td><td>115.2 PSI</td><td>RUNNING</td></tr>
        <tr><td>Zone C</td><td>74.1F</td><td>122.8 PSI</td><td>ALARM</td></tr>
        </table></body></html>'''

        # Log the interaction
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'source_ip': self.client_address[0],
            'method': 'GET',
            'path': self.path,
            'user_agent': self.headers.get('User-Agent', '')
        }
        print(json.dumps(log_entry))

        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging

print('HMI Honeypot starting on port 8080...')
HTTPServer(('192.168.1.202', 8080), HMIHoneypot).serve_forever()
"
```

### Honeytoken Deployment

Honeytokens are fake credentials, documents, or data placed in the ICS environment to detect unauthorized access. Unlike honeypots that emulate devices, honeytokens are pieces of information that should never be accessed during normal operations.

```python
#!/usr/bin/env python3
"""ICS honeytoken deployment and monitoring framework."""

import json
import hashlib
import time
from datetime import datetime

class ICSHoneytokenManager:
    """Manage honeytokens for ICS environment deception."""

    def __init__(self, token_file='honeytokens.json'):
        self.token_file = token_file
        self.tokens = self._load_tokens()

    def _load_tokens(self):
        """Load existing honeytokens."""
        try:
            with open(self.token_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def create_credential_token(self, description, system_type):
        """Create a fake credential honeytoken."""
        token_id = hashlib.sha256(
            f'{description}{time.time()}'.encode()
        ).hexdigest()[:16]

        token = {
            'id': token_id,
            'type': 'credential',
            'description': description,
            'system': system_type,
            'username': f'maintenance_{token_id[:6]}',
            'password': f'TempPass{token_id[:8]}!',
            'created': datetime.now().isoformat(),
            'triggered': False,
            'trigger_time': None,
            'trigger_source': None
        }

        self.tokens[token_id] = token
        self._save_tokens()

        print(f'Honeytoken created:')
        print(f'  ID: {token_id}')
        print(f'  Username: {token["username"]}')
        print(f'  Password: {token["password"]}')
        print(f'  Deploy to: {description}')

        return token

    def create_network_token(self, description, ip_address):
        """Create a network-based honeytoken (canary IP)."""
        token_id = hashlib.sha256(
            f'{description}{time.time()}'.encode()
        ).hexdigest()[:16]

        token = {
            'id': token_id,
            'type': 'network',
            'description': description,
            'ip_address': ip_address,
            'protocol': 'modbus',
            'port': 502,
            'created': datetime.now().isoformat(),
            'triggered': False
        }

        self.tokens[token_id] = token
        self._save_tokens()

        print(f'Network honeytoken created:')
        print(f'  ID: {token_id}')
        print(f'  IP: {ip_address}')
        print(f'  Protocol: Modbus TCP :502')

        return token

    def create_document_token(self, description, file_path):
        """Create a document honeytoken (fake PLC program or config)."""
        token_id = hashlib.sha256(
            f'{description}{time.time()}'.encode()
        ).hexdigest()[:16]

        token = {
            'id': token_id,
            'type': 'document',
            'description': description,
            'file_path': file_path,
            'content_hash': None,  # Would be computed from actual file
            'created': datetime.now().isoformat(),
            'triggered': False
        }

        self.tokens[token_id] = token
        self._save_tokens()

        print(f'Document honeytoken created:')
        print(f'  ID: {token_id}')
        print(f'  Path: {file_path}')
        print(f'  Description: {description}')

        return token

    def _save_tokens(self):
        """Persist tokens to file."""
        with open(self.token_file, 'w') as f:
            json.dump(self.tokens, f, indent=2)

# Deploy honeytokens
manager = ICSHoneytokenManager()
manager.create_credential_token(
    'Fake PLC maintenance account for engineering workstation',
    'Siemens S7-1200'
)
manager.create_network_token(
    'Fake PLC in unused IP space on control network',
    '192.168.1.250'
)
manager.create_document_token(
    'Fake PLC program backup with tracking beacon',
    '/opt/plc_backups/PLC_CONTROLLER_01_backup_2024.zip'
)
```

## Part 4: Honeypot Monitoring and SIEM Integration

### Real-Time Honeypot Monitoring

```bash
# Monitor conpot logs in real-time
tail -f /var/log/conpot.log | python3 -c "
import sys
import json
from datetime import datetime

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue

    try:
        entry = json.loads(line)
        timestamp = entry.get('timestamp', datetime.now().isoformat())
        source_ip = entry.get('remote', ['unknown'])[0]
        data_type = entry.get('data_type', 'unknown')

        # Color-coded alerting
        if 'connect' in data_type.lower():
            print(f'[CONNECTION] {timestamp} from {source_ip}')
        elif 'modbus' in str(entry.get('data', '')).lower():
            print(f'[MODBUS] {timestamp} from {source_ip} - {entry.get(\"data\", \"\")}')
        elif 'http' in data_type.lower():
            print(f'[HTTP] {timestamp} from {source_ip} - {entry.get(\"data\", \"\")}')
        else:
            print(f'[OTHER] {timestamp} from {source_ip} - {data_type}')
    except json.JSONDecodeError:
        # Plain text log format
        if 'connect' in line.lower():
            print(f'[ALERT] {line}')
        else:
            print(f'[INFO] {line}')
" &
```

### SIEM Integration

```python
#!/usr/bin/env python3
"""Convert conpot logs to SIEM-compatible format (CEF/Syslog)."""

import json
import socket
from datetime import datetime

CEF_HEADER = 'CEF:0|OpenClaw|Conpot|1.0|'

def format_cef(log_entry, severity='Medium'):
    """Format conpot log entry as Common Event Format (CEF)."""
    source_ip = log_entry.get('remote', ['0.0.0.0'])[0]
    source_port = log_entry.get('remote', [0, 0])[1]
    dest_ip = log_entry.get('local', ['0.0.0.0'])[0]
    dest_port = log_entry.get('local', [0, 0])[1]
    data_type = log_entry.get('data_type', 'unknown')

    cef_event = (
        f'{CEF_HEADER}ICS_Honeypot_Activity|ICS Honeypot Interaction Detected|'
        f'{severity}|'
        f'src={source_ip} spt={source_port} '
        f'dst={dest_ip} dpt={dest_port} '
        f'proto={data_type} '
        f'cs1Label=HoneypotType cs1=ICS-Modbus '
        f'cs2Label=InteractionData cs2={json.dumps(log_entry.get("data", {}))} '
        f'end={int(datetime.now().timestamp() * 1000)}'
    )

    return cef_event

def send_to_syslog(cef_message, syslog_server='192.168.1.10', syslog_port=514):
    """Send CEF message to syslog/SIEM server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(cef_message.encode(), (syslog_server, syslog_port))
    sock.close()

# Example: Parse conpot JSON log and forward to SIEM
def process_conpot_log(log_file, syslog_server='192.168.1.10'):
    """Process conpot log file and forward events to SIEM."""
    with open(log_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                cef = format_cef(entry)
                send_to_syslog(cef, syslog_server)
                print(f'Forwarded: {cef[:120]}...')
            except (json.JSONDecodeError, KeyError) as e:
                print(f'Skipping malformed entry: {e}')

print('Conpot-to-SIEM Forwarder')
print('Reads conpot JSON logs and forwards as CEF events')
```

## Practical Steps

1. **Deploy conpot** with a template matching the target ICS environment
2. **Configure dynamic registers** to simulate realistic process values
3. **Integrate with SIEM** using CEF or JSON log forwarding
4. **Deploy honeytokens** (credentials, documents, network canaries)
5. **Test detection** by performing simulated attacks against the honeypot
6. **Verify logging** captures source IP, timestamp, protocol, and operation

## Hands-on Exercises

### Exercise 1: Conpot Deployment and Configuration

Deploy conpot with a custom Modbus template and verify it responds to protocol queries.

```bash
conpot -f --template default --host 192.168.1.200
modbus-cli read -a 192.168.1.200 -s 1 -r 0 -n 10 -t holding
grep "$(date +%Y-%m-%d)" /var/log/conpot.log
```

### Exercise 2: Honeypot Detection Lab

Deploy a conpot honeypot alongside a real PLC (or emulator) and practice identifying which is the honeypot using timing analysis, data realism checks, and TCP/IP fingerprinting.

```bash
# Test device 1 (unknown: real or honeypot?)
nmap -O -sV 192.168.1.10
# Test device 2 (unknown: real or honeypot?)
nmap -O -sV 192.168.1.200
# Compare results
```

### Exercise 3: Honeytoken Deployment

Deploy credential, network, and document honeytokens in a simulated ICS environment and verify they generate alerts when accessed.

### Exercise 4: SIEM Integration

Configure conpot to forward logs to a SIEM system (Splunk, ELK, or syslog) and create alert rules for honeypot interactions.

## References

- conpot ICS honeypot — https://github.com/mushorg/conpot
- GRFICSv2 ICS honeypot — https://github.com/Fortiphyd/GRFICSv2
- Honeytoken deployment guide — Thinkst Canary documentation
- CEF (Common Event Format) specification — https://www.microfocus.com/documentation/arcsight/
- ICS deception techniques — Nozomi Networks deception guide
- MITRE Decept framework — https://attack.mitre.org/tactics/enterprise/
- NIST SP 800-167: Guide to Data-Centric System Threat Information Sharing