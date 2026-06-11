# ICS Protocol Reconnaissance and Enumeration

## Overview

Industrial Control System (ICS) environments run specialized protocols designed for reliability and determinism rather than security. Most ICS protocols — Modbus TCP, S7comm, DNP3, EtherNet/IP, BACnet, and GOOSE — were designed without authentication, encryption, or integrity checking. This makes protocol reconnaissance exceptionally effective: devices respond to queries openly, and the attack surface is often directly exposed at the protocol layer.

This guide covers the full reconnaissance pipeline for ICS environments, from initial network discovery through deep protocol-level device enumeration.

## Phase 1: Network-Level Discovery

Before interacting with ICS protocols, establish which hosts are alive and which ports are open. ICS devices typically listen on well-known protocol ports:

| Protocol | Default Port | Transport |
|----------|-------------|-----------|
| Modbus TCP | 502 | TCP |
| S7comm (Siemens) | 102 | TCP |
| EtherNet/IP | 44818 | TCP |
| OPC UA | 4840 | TCP |
| DNP3 | 20000 | TCP/UDP |
| BACnet | 47808 | UDP |
| GOOSE/IEC 61850 | 102 | TCP |

Start with a targeted port scan covering these ports across the OT network segment:

```bash
nmap -sT -p 502,102,4840,44818,20000,47808 -sV --version-intensity 5 192.168.1.0/24
```

For faster discovery on large networks, use masscan with a targeted port list:

```bash
masscan 192.168.1.0/16 -p502,102,44818,4840,20000 --rate=10000 -oL ics_hosts.txt
```

## Phase 2: PLC Scanning with plcscan

`plcscan` performs network-wide scanning for programmable logic controllers. It sends protocol-specific probes to each IP address and identifies devices that respond with PLC-like behavior.

```bash
# Full subnet scan with 5-second timeout per host
plcscan -i 192.168.1.0/24 -t 5

# Target a specific IP range for deeper scanning
plcscan -i 192.168.1.100-192.168.1.150 -t 10
```

Key information extracted by plcscan includes:
- Device manufacturer and model
- Firmware version and revision
- Module type (CPU, communication module, I/O module)
- Serial number where available

This information is critical for vulnerability research — specific firmware versions may have known CVEs that can be exploited in later phases.

## Phase 3: Siemens S7 Enumeration with s7scan

For environments with Siemens PLCs (which dominate many industrial sectors), `s7scan` provides deep enumeration capabilities specifically for the S7comm protocol.

```bash
# Scan a full subnet for Siemens S7 devices
s7scan -t 192.168.1.0/24

# Extended timeout for networks with high latency
s7scan -t 192.168.1.0/24 -T 10
```

s7scan queries the System Status List (SZL) of each responding PLC to extract:

- **Module Identification (SZL 0x0011):** Hardware model, serial number, module name
- **Component Identification (SZL 0x001C):** Firmware version, hardware revision
- **Protection Level (SZL 0x0232):** Whether the PLC has password protection enabled and what access level is enforced (none, read-only, full protection)
- **CPU State:** Whether the PLC is in RUN, STOP, or STARTUP mode

The protection level is especially important — a PLC with no protection allows full read/write access to its memory, data blocks, and configuration. Even read-only protection provides significant intelligence about the process logic.

## Phase 4: Modbus Device Discovery

Modbus TCP is the most widely deployed ICS protocol. It operates on a master-slave model where each slave has a Unit ID (0-247). Discovery involves finding devices that respond on port 502 and then enumerating valid Unit IDs.

Use `modbus-cli` for targeted enumeration:

```bash
# Read a single holding register to verify device responsiveness
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 1 -t holding

# Scan for valid slave IDs
for i in $(seq 1 247); do
  timeout 2 modbus-cli read -a 192.168.1.10 -s $i -r 0 -n 1 -t holding 2>/dev/null && echo "Slave $i: ACTIVE"
done
```

Use `mbpoll` for continuous monitoring and data type testing:

```bash
# Poll 10 registers every second
mbpoll -t 192.168.1.10 -p 502 -m tcp -r 0 -c 10 -1 1000

# Test different data types (float, integer, long)
mbpoll -t 192.168.1.10 -p 502 -m tcp -r 100 -c 4 -t 3 -F
```

Modbus has no authentication — any device that can reach port 502 can query any slave. The protocol also lacks encryption, making all communication readable via packet capture.

## Phase 5: EtherNet/IP Enumeration with enip-client

EtherNet/IP (based on the Common Industrial Protocol, CIP) is widely used in North American industrial environments, especially with Allen-Bradley/Rockwell Automation equipment. The `enip-client` tool provides enumeration capabilities:

```bash
# Discover all CIP devices on the network
enip-client -i 192.168.1.0/24 --list-identity

# Get detailed attributes from a specific device
enip-client -t 192.168.1.30 --get-attribute-all --class 0x01 --instance 0x01

# List all supported CIP object classes
enip-client -t 192.168.1.30 --list-classes
```

The CIP Identity Object (class 0x01) reveals the vendor ID, device type, product code, revision, status, serial number, and product name. This information maps directly to the device's capabilities and known vulnerabilities.

## Phase 6: Passive Traffic Analysis

Passive reconnaissance is often the safest approach in ICS environments where active scanning could disrupt processes. Capture traffic on ICS ports and analyze communication patterns:

```bash
# Capture all ICS traffic
tcpdump -i eth0 -w ics_traffic.pcap 'port 502 or port 102 or port 44818 or port 4840'

# Extract Modbus function codes to understand command patterns
tshark -r ics_traffic.pcap -Y "tcp.port == 502" -T fields -e modbus.funccode -e ip.src -e ip.dst

# Identify S7comm communication patterns
tshark -r ics_traffic.pcap -Y "tcp.port == 102" -T fields -e s7comm.func -e ip.src -e ip.dst
```

Passive analysis reveals the master-slave communication topology, normal polling intervals, register ranges being accessed, and which IP addresses are authorized to issue commands. This intelligence is invaluable for planning any active testing.

## Phase 7: DNP3 Outstation Discovery

DNP3 (Distributed Network Protocol version 3) is the dominant SCADA protocol in the North American electric utility sector. It operates over TCP port 20000 (or UDP for some serial-to-IP gateways) and follows a master-outstation communication model. DNP3 supports Secure Authentication (SA) but many deployments operate without it, making outstations accessible to any network-connected host.

```bash
# Scan for DNP3 outstations on the standard TCP port
nmap -sT -p 20000 --script dnp3-info 192.168.1.0/24

# Passive DNP3 traffic capture for outstation identification
tcpdump -i eth0 -w dnp3_passive.pcap port 20000

# Extract DNP3 source/destination pairs to identify master-outstation relationships
tshark -r dnp3_passive.pcap -Y "dnp3" -T fields -e ip.src -e ip.dst -e dnp3.func | sort | uniq -c | sort -rn
```

Key DNP3 reconnaissance data points:

- **Data Link Address**: Each DNP3 device has a 16-bit source address (0-65535). Master stations typically use address 1, while outstations use addresses 10-65534.
- **Function Code Analysis**: Identify which function codes the master is issuing (read, write, direct operate, freeze) to understand the operational scope.
- **Data Class Identification**: DNP3 organizes data into Class 0 (all static data), Class 1 (high priority events), Class 2 (medium priority), and Class 3 (low priority). Enumerating Class 0 data reveals the full point map.
- **Fragment Size and Timeout**: DNP3 link layer parameters include maximum fragment size and link timeout values. These vary between vendor implementations and can help fingerprint the outstation device.

### DNP3 Data Object Enumeration

```bash
# Enumerate DNP3 data objects using scapy-crafted requests
python3 -c "
from scapy.all import *
import struct

# DNP3 application layer: Read request for Class 0 data (all static points)
# Application layer header: AC (application control) + FC (function code 0x01 = Read)
# Object header: Group 60, Variation 1 (Class 0 data), Qualifier 0x06 (no prefix, start=stop=0)
dnp3_payload = bytes([
    0xC0,  # AC: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
    0x01,  # FC: Read
    0x3C, 0x01, 0x06,  # Group 60 Var 1, Qualifier 06
    0x00, 0x00   # Start=0, Stop=0
])

# DNP3 data link layer header
dl_header = bytes([0x05, 0x64])  # Start bytes
# Build complete DNP3 frame (simplified for TCP transport)
frame = dl_header + dnp3_payload

# Send via TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('192.168.1.15', 20000))
s.send(frame)
response = s.recv(4096)
print(f'DNP3 response: {response.hex()}')
print(f'Response length: {len(response)} bytes')
s.close()
"

# Analyze DNP3 data objects in captured traffic
tshark -r dnp3_passive.pcap -Y "dnp3" -T fields \
  -e dnp3.func -e dnp3.obj.group -e dnp3.obj.variation -e dnp3.obj.qualifier | sort | uniq -c | sort -rn
```

## Phase 8: BACnet Building Automation Discovery

BACnet (Building Automation and Control Networks) operates over UDP port 47808 and is ubiquitous in commercial building management systems. BACnet devices announce themselves through periodic Who-Is/I-Am broadcasts, making passive discovery extremely effective.

```bash
# Capture BACnet broadcast traffic
tcpdump -i eth0 -w bacnet_broadcast.pcap udp port 47808

# Extract device IDs and IP addresses from I-Am responses
tshark -r bacnet_broadcast.pcap -Y "bacnet && bacapdu.service==0" -T fields \
  -e ip.src -e bacnet.device_id -e bacnet.vendor_id

# Enumerate BACnet object types on a discovered device
tshark -r bacnet_broadcast.pcap -Y "bacnet" -T fields \
  -e bacnet.object_type -e bacnet.object_instance | sort | uniq -c | sort -rn
```

BACnet reconnaissance reveals:

- **Device Object Properties**: Vendor ID maps to specific manufacturers (Trane, Honeywell, Johnson Controls, Siemens). Firmware version indicates potential vulnerabilities.
- **Object Hierarchy**: Each BACnet device contains objects (Analog Input, Analog Output, Analog Value, Binary Input, Binary Output, Binary Value, Multi-state, etc.). The object count indicates the scale of the controlled environment.
- **Communication Configuration**: BACnet devices may have multiple communication bindings (BACnet/IP, BACnet MS/TP, BACnet Ethernet). Each binding is a potential attack surface.
- **APDU Service Support**: The protocol-services-supported property reveals which BACnet services the device can process, indicating what operations are available to an attacker.

## Phase 9: Protocol Correlation and Asset Mapping

After completing individual protocol scans, correlate the results to build a comprehensive asset map of the ICS environment. This map connects device identities across protocols, identifies single points of failure, and reveals undocumented communication paths.

### Cross-Protocol Device Correlation

```bash
# Correlate Modbus and EtherNet/IP results by IP address
python3 -c "
import json

# Load scan results from different protocols
modbus_devices = {
    '192.168.1.10': {'unit_ids': [1, 2, 3], 'model': 'Schneider M340'},
    '192.168.1.20': {'unit_ids': [1], 'model': 'Siemens S7-1200'}
}

enip_devices = {
    '192.168.1.10': {'vendor': 'Schneider Electric', 'product': 'M340 BMXP342020'},
    '192.168.1.30': {'vendor': 'Rockwell Automation', 'product': 'ControlLogix 5580'}
}

# Cross-reference to identify multi-protocol devices
all_ips = set(list(modbus_devices.keys()) + list(enip_devices.keys()))
print('Device Correlation Report:')
print('-' * 60)
for ip in sorted(all_ips):
    print(f'IP: {ip}')
    if ip in modbus_devices:
        print(f'  Modbus: {modbus_devices[ip][\"model\"]} (Units: {modbus_devices[ip][\"unit_ids\"]})')
    if ip in enip_devices:
        print(f'  EtherNet/IP: {enip_devices[ip][\"vendor\"]} {enip_devices[ip][\"product\"]}')
    print()
"
```

### Network Topology Visualization

```bash
# Generate communication matrix from captured traffic
tshark -r ics_traffic.pcap -Y "modbus || s7comm || enip || dnp3 || bacnet" \
  -T fields -e ip.src -e ip.dst -e frame.protocols | \
  sort | uniq -c | sort -rn > communication_matrix.txt

# Extract unique device roles (masters vs. slaves)
tshark -r ics_traffic.pcap -Y "tcp.port==502 && modbus" \
  -T fields -e ip.src -e ip.dst | sort -u | \
  awk '{print $1, \"-> MASTER\"; print $2, \"-> SLAVE\"}' | sort -u
```

### Vulnerability Research Integration

Once the asset inventory is complete, cross-reference each device against vulnerability databases:

```bash
# Search NVD for known vulnerabilities by device model
# Example: Search for Siemens S7-1200 CVEs
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Siemens+S7-1200" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for vuln in data.get('vulnerabilities', [])[:10]:
    cve = vuln['cve']
    cve_id = cve['id']
    desc = cve['descriptions'][0]['value'][:120] if cve['descriptions'] else 'N/A'
    print(f'{cve_id}: {desc}')
"

# Check ICS-CERT advisories for firmware versions discovered during enumeration
# Reference: https://www.cisa.gov/news-events/cybersecurity-advisories
```

## Phase 10: Wireless ICS Device Reconnaissance

Many modern ICS deployments include wireless communication for remote I/O, field device monitoring, and mobile operator interfaces. Wireless adds an additional attack surface that is often overlooked during traditional ICS assessments.

### Industrial WiFi Discovery

```bash
# Scan for wireless networks in the OT area
iwlist wlan0 scan | grep -E "ESSID|Encryption|Frequency|Quality"

# Monitor for industrial wireless protocols
# WirelessHART (IEEE 802.15.4, 2.4GHz)
# ISA100.11a (IEEE 802.15.4, 2.4GHz)
# WLAN-based HMI access points
rtl_power -f 2.4G:2.5G:100k -i 5 -e 60 industrial_wifi.csv

# Identify Rogue access points in OT zones
# Compare discovered APs against authorized AP list
airodump-ng wlan0mon -c 1,6,11 --output-format csv -w ot_wifi_scan
```

### Bluetooth ICS Device Discovery

Some ICS field devices use Bluetooth for local configuration and maintenance access:

```bash
# Scan for Bluetooth devices in the OT area
bluetoothctl scan on

# Identify industrial Bluetooth devices by OUI prefix
# Common industrial OUIs: Siemens (00:1C:06), Rockwell (00:00:BC), Schneider (00:80:F4)
bluetoothctl devices | grep -E "00:1C:06|00:00:BC|00:80:F4"
```

## Operational Considerations

- **Timing is critical:** ICS devices may have watchdog timers that trigger failsafes if communication is disrupted. Space out scan probes and avoid aggressive timing templates.
- **Document everything:** Record the IP, protocol, port, and response for every discovered device. This inventory becomes the foundation for vulnerability assessment.
- **Cross-reference with Shodan/Censys:** ICS devices exposed to the internet are cataloged by search engines. Use these as supplementary intelligence sources during scope-approved engagements.
- **Mind the serial layer:** Not all ICS communication is TCP/IP. Serial connections (RS-232, RS-485) using Modbus RTU or DF1 protocol require physical access and different tooling (serial adapters, specialized clients).
- **Honeypot awareness:** Be alert for ICS honeypots (conpot, GRFICSv2) during reconnaissance. Honeypots often have unrealistic response timing, static register values, or simplified protocol error handling. Document suspected honeypots separately.
- **Protocol version mapping:** Document exact protocol versions and firmware revisions during enumeration. The same protocol name (e.g., "Modbus TCP") can have vastly different security postures depending on the firmware version and configuration of the implementing device.

## References

- NIST SP 800-82: Guide to ICS Security — https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- IEC 62443: Industrial Automation and Control Systems Security — https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- CISA ICS-CERT Advisories — https://www.cisa.gov/news-events/cybersecurity-advisories
- Modbus Protocol Specification — https://modbus.org/specs.php
- DNP3 Users Group — https://www.dnp.org/
- BACnet Protocol Standard (ASHRAE 135) — https://www.bacnet.org/
- IEC 61850 Communication Networks and Systems for Power Utility Automation — https://www.iec.ch/
