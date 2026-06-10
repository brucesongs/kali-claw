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

## Operational Considerations

- **Timing is critical:** ICS devices may have watchdog timers that trigger failsafes if communication is disrupted. Space out scan probes and avoid aggressive timing templates.
- **Document everything:** Record the IP, protocol, port, and response for every discovered device. This inventory becomes the foundation for vulnerability assessment.
- **Cross-reference with Shodan/Censys:** ICS devices exposed to the internet are cataloged by search engines. Use these as supplementary intelligence sources during scope-approved engagements.
- **Mind the serial layer:** Not all ICS communication is TCP/IP. Serial connections (RS-232, RS-485) using Modbus RTU or DF1 protocol require physical access and different tooling (serial adapters, specialized clients).
