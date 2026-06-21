# ICS Fieldbus Attack Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases for industrial fieldbus protocol security assessment in authorized lab environments only.

---

## Statistics

| Category | Cases | Severity Distribution |
|----------|-------|-----------------------|
| A. DNP3 (Power Utility) | 2 | Medium, High |
| B. IEC 60870-5 (Power Utility) | 2 | Medium, High |
| C. IEC 61850 (Substation) | 2 | High, Critical |
| D. PROFINET / EtherCAT (Discrete Mfg) | 2 | Medium, Critical |
| E. Foundation Fieldbus / HART (Process) | 1 | High |
| F. BACnet Deep (Building Automation) | 1 | High |
| G. CC-Link / Fuzzing / Defense | 2 | Medium, Critical |
| **Total** | **12** | **M:3, H:5, C:4** |

---

## A. DNP3 (Power Utility)

### TC-FB-001: DNP3 Unauthenticated Read

**Objective**: Verify DNP3 server responds to read requests without authentication.
**Tool**: nmap dnp3 NSE
**Command**: `nmap -p 20000 --script dnp3-info 192.168.1.10`
**Expected Result**: DNP3 device info returned (vendor, model, firmware) without any credentials.
**Risk**: Unauthorized data access (CVSS 7.5) — attacker can map device inventory and process state.
**Lab Steps**:
1. Run `nmap -p 20000 --script dnp3-info --script-args dnp3-info.timeout=10s <target>`
2. Observe returned vendor name, device name, firmware version, local device address.
3. Cross-reference firmware version against ICS-CERT advisories.
**Remediation**: Enable DNP3 Secure Authentication v5; restrict port 20000 to known master IPs via OT firewall.

### TC-FB-002: DNP3 Direct Operate Without Authentication

**Objective**: Verify whether Direct Operate (FC 5) command executes without Secure Authentication.
**Tool**: OpenDNP3 master CLI
**Command**: `master -c master.config --command binary-output 1:1 --function direct-operate`
**Expected Result**: Either the outstation acknowledges the command (HIGH risk — no auth enforced) OR returns a negative acknowledgment with "authentication required" exception code.
**Risk**: Unauthorized process control (CVSS 9.8) — attacker can directly operate breakers, valves, motors.
**Lab Steps**:
1. Start OpenDNP3 outstation in lab (no SAv configured): `outstation -c unsecure_outstation.config`
2. Connect master: `master -c master.config --command binary-output 1:1 --function direct-operate`
3. Verify state change on emulated binary output.
4. Repeat with SAv5 enabled; confirm auth required response.
**Remediation**: Enable DNP3 SAv5 on all outstations; configure update key per device; rotate keys annually.

---

## B. IEC 60870-5 (Power Utility)

### TC-FB-003: IEC 60870-5-104 Interrogation Without Authentication

**Objective**: Verify IEC 104 server responds to interrogation (ASDU type 100) without authentication.
**Tool**: lib60870 iec104_test_client
**Command**: `iec104_test_client -h 192.168.1.10 -p 2404 --interrogation`
**Expected Result**: Server returns all in-scope ASDUs (single point, double point, measured values) without any auth handshake.
**Risk**: Information disclosure (CVSS 7.5) — attacker obtains full substation telemetry.
**Lab Steps**:
1. Start lib60870 reference server in lab: `iec104_demo_server 2404`
2. Connect client: `iec104_test_client -h 127.0.0.1 -p 2404 --interrogation`
3. Capture all returned ASDUs; identify single points (breakers), measured values (voltages).
4. Verify no STARTDT confirmation is required before data transfer.
**Remediation**: Restrict port 2404 to control-room IP ranges; deploy IEC 62351 secure gateway.

### TC-FB-004: IEC 60870-5-104 Command Injection

**Objective**: Send ASDU type 45 (single command) without authentication and observe breaker state change.
**Tool**: lib60870 client / Scapy with IEC 104 layer
**Command**: `iec104_test_client -h 192.168.1.10 -p 2404 --command single 1:1 --qualifier pulse`
**Expected Result**: Target RTU acknowledges command and executes pulse (HIGH risk) or returns activation-confirmation only without execution (auth enforced).
**Risk**: Unauthorized breaker operation (CVSS 9.0) — power grid manipulation.
**Lab Steps**:
1. Start lab IEC 104 server with emulated breaker.
2. Send single command: type 45, IOA 1, S/E bit = 0 (execute), qu = pulse.
3. Verify breaker state changes in lab simulator.
4. Send qu = long pulse (0x02) and observe timing.
5. Repeat with qu = 0x80 (select only); verify activation-confirmation without execution.
**Remediation**: Enable IEC 62351 authentication on all command ASDUs; deploy protocol-aware firewall with command allowlist.

---

## C. IEC 61850 (Substation)

### TC-FB-005: GOOSE Frame Injection

**Objective**: Forge GOOSE frame with elevated stNum to override legitimate device status.
**Tool**: Scapy with IEC 61850 GOOSE layer
**Command**: `python3 inject_goose.py --interface eth0 --goose-cb "CB_LLn0" --dataset " breaker_pos" --stnum 9999`
**Expected Result**: Subscribing IEDs accept the forged frame as most-recent due to higher stNum, ignoring legitimate updates.
**Risk**: Protection relay malfunction (CVSS 9.5) — can trigger false breaker trips or block legitimate trips.
**Lab Steps**:
1. Capture baseline GOOSE traffic with Wireshark filter `iecgoose`.
2. Identify source MAC, app ID, dataset reference, current stNum/sqNum.
3. Use Scapy to craft frame with stNum = (current + 10000) and desired dataset payload (e.g., breaker closed = 0x01 when actually open).
4. Inject as broadcast/multicast: `sendp(injected_frame, iface="eth0", loop=1, inter=0.001)`.
5. Observe subscribing IEDs in lab using the spoofed value.
**Remediation**: Enable IEC 62351-6 GOOSE security where supported; deploy managed switches with source-MAC lockdown on GOOSE VLANs.

### TC-FB-006: IEC 61850 MMS Server Enumeration and Control

**Objective**: Enumerate logical devices, logical nodes, and execute SetDataValues on control objects.
**Tool**: libiec61850 client / IEDExplorer
**Command**: `iec61850_client -h 192.168.1.20 -p 102 --browse --write "LD0/LLN0.Mod.stVal" 1`
**Expected Result**: Server exposes full logical-device tree without auth; SetDataValues succeeds on control objects (HIGH/CRITICAL risk).
**Risk**: Unauthorized substation control (CVSS 9.8) — IED configuration tampering.
**Lab Steps**:
1. Start libiec61850 server with sample IED model.
2. Browse: `iec61850_client -h 127.0.0.1 -p 102 --browse`
3. Read GetDataValues on `LD0/LLN0.Mod.stVal`.
4. Attempt SetDataValues on a control object: `--write "LD0/CSWI1.Pos.Oper.ctlVal" 1`.
5. Check IEC 62351 authentication (X.509) — many IEDs ship with anonymous default.
**Remediation**: Enable X.509 client authentication on MMS server; deploy IEC 62351-secured gateway; restrict port 102.

---

## D. PROFINET / EtherCAT (Discrete Manufacturing)

### TC-FB-007: PROFINET DCP Device Discovery and Spoofing

**Objective**: Enumerate PROFINET devices via DCP (Discovery and Configuration Protocol) and test for identification spoofing.
**Tool**: Scapy with PROFINET layer / Redpoint Digitals
**Command**: `python3 pn_dcp_identify.py --interface eth0 --broadcast`
**Expected Result**: All PROFINET devices respond with vendor name, device name, vendor ID, device ID, MAC address, IP address, role.
**Risk**: Network reconnaissance (CVSS 5.3) enables targeted attacks.
**Lab Steps**:
1. Send DCP Identify All broadcast on Ethertype 0x8892.
2. Parse responses for vendor (Siemens, Phoenix Contact, etc.), device role (IO Controller, IO Device).
3. Attempt DCP Set (vendor-specific) to change device name: `python3 pn_dcp_set.py --target 00:0A:DE:AD:BE:EF --name "FAKE_DEVICE"`.
4. If successful, observe device drop off PROFINET controller's configured list (DoS via misname).
**Remediation**: Configure DCP write protection on PROFINET devices; segment PROFINET on dedicated VLAN with switch port security.

### TC-FB-008: EtherCAT Mailbox CoE Exploitation

**Objective**: Enumerate EtherCAT slaves via mailbox CoE (CAN application layer over EtherCAT) SDO Info and abuse write access.
**Tool**: Scapy with EtherCAT layer / custom IgH EtherCAT master client
**Command**: `python3 ecat_mailbox_scan.py --interface eth0 --ring-position 0`
**Expected Result**: Each slave responds with SDO Info listing object dictionary; write to OD entry 0x6000:00 to manipulate process output.
**Risk**: Process manipulation (CVSS 9.0) — motion control writes can damage equipment.
**Lab Steps**:
1. Capture EtherCAT frames with Wireshark filter `ecat`.
2. Identify master MAC and slave ring positions.
3. Send SDO Info Upload for OD 0x1000 (device type), 0x1018 (identity).
4. Send SDO Download (write) to OD 0x6000:00 with a non-destructive test value (setpoint = 1).
5. Observe process output change in lab slave emulator.
**Remediation**: Restrict EtherCAT network to dedicated segment with no routable IP; deploy Layer-2 access control (802.1X MACsec).

---

## E. Foundation Fieldbus / HART (Process Automation)

### TC-FB-009: HART Command Fuzzing Over 4-20mA Loop

**Objective**: Send malformed HART commands over the 4-20mA current loop and identify command parsers that crash or behave anomalously.
**Tool**: Custom Python script with USB-HART modem (e.g., Procitec HART USB)
**Command**: `python3 hart_fuzz.py --serial /dev/ttyUSB0 --target-polling-addr 0`
**Expected Result**: Fuzzer identifies HART commands that cause device exception (no response, loop current anomaly, or universal command 0 instability).
**Risk**: DoS of field instrument; potential spurious trip on host DCS (CVSS 7.5).
**Lab Steps**:
1. Connect HART modem to lab field instrument (Rosemount 3051 emulator or actual hardware).
2. Send universal command 0 (read unique identifier) to verify device alive.
3. Fuzz commands 32-127 (device-specific range) with malformed preamble and checksum.
4. Fuzz Burst-mode-enabled command with corrupted LongFrame.
5. Record any device crash, exception code, or loop-current spike.
**Remediation**: Restrict physical access to marshaling cabinets; deploy HART firewall where WirelessHART gateways are used.

---

## F. BACnet Deep (Building Automation)

### TC-FB-010: BACnet Object Model Enumeration and WriteProperty Exploitation

**Objective**: Enumerate all BACnet objects (analog inputs, outputs, binary values) and execute WriteProperty on Present_Value without authentication.
**Tool**: Recondog / YABACT / nmap BACnet NSE
**Command**: `bacnetdiscover -n 192.168.1.0/24` then `bacnetwrite -d 192.168.1.50 -t analogOutput,1 -p present-value -v 75.5`
**Expected Result**: Object list retrieved without auth; WriteProperty to Analog Output Present_Value succeeds, changing physical output (HVAC setpoint, damper position).
**Risk**: Unauthorized building control (CVSS 8.6) — HVAC manipulation, lighting, door access.
**Lab Steps**:
1. Broadcast Who-Is: `bacnetdiscover -n 192.168.1.255 --who-is 0-4194303`.
2. Capture I-Am responses; enumerate device IDs and vendor IDs.
3. Send ReadProperty to device object list: `-d <id> -t device,<inst> -p object-list`.
4. For each Analog Output object, read Present_Value and Description.
5. Write test value: `bacnetwrite -d <id> -t analogOutput,<inst> -p present-value -v 50.0`.
6. Verify physical output change (multimeter on 0-10V output or BAS HMI).
7. Attempt ReinitializeDevice (service 17) — most devices allow it without auth.
**Remediation**: Migrate to BACnet/SC (Secure Connect) with TLS and certificate-based auth; restrict UDP 47808 to operator subnets.

---

## G. CC-Link, Fuzzing, and Defense

### TC-FB-011: CC-Link IE TSN Cyclic Data Frame Injection

**Objective**: Forge CC-Link IE TSN cyclic data frames to manipulate slave outputs in real-time cycle.
**Tool**: Scapy with CC-Link layer / custom TSN-aware tool
**Command**: `python3 cclink_inject.py --interface eth0 --cycle-time 125us --target-mac 00:0A:DE:AD:BE:EF`
**Expected Result**: Forged cyclic frames accepted by slave within 125us cycle, overriding legitimate master outputs.
**Risk**: Real-time process manipulation (CVSS 9.5) — can damage mechanical equipment.
**Lab Steps**:
1. Capture baseline CC-Link IE TSN traffic on Ethertype 0x88E1.
2. Identify master MAC, slave MAC, cycle time, cyclic data layout.
3. Forge cyclic frame with modified RX/TX data (e.g., set servo command = 0xFFFF).
4. Inject via TSN-aware NIC (Intel i210 with hardware timestamp).
5. Observe slave response in lab Mitsubishi amplifier.
**Remediation**: Deploy CC-Link IE TSN Security variant (where supported); use MACsec (802.1AE) on TSN links.

### TC-FB-012: Boofuzz DNP3 and IEC 104 Protocol Fuzzing

**Objective**: Fuzz DNP3 link/transport/application layers and IEC 104 ASDU structure to identify parser crashes.
**Tool**: Boofuzz with custom DNP3/IEC 104 templates
**Command**: `python3 fuzz_dnp3.py --target 192.168.1.10:20000` then `python3 fuzz_iec104.py --target 192.168.1.10:2404`
**Expected Result**: Fuzzer identifies malformed DNP3 or IEC 104 payloads that cause device crash, hang, or unhandled exception.
**Risk**: DoS of RTU/IED (CVSS 8.2) or potential remote code execution if parser bug is exploitable.
**Lab Steps**:
1. Configure Boofuzz with DNP3 protocol template (link layer start bytes 0x0564, function codes 0-23).
2. Start outstation/RTU in lab and verify baseline response.
3. Run fuzzer: `python3 fuzz_dnp3.py --target 192.168.1.10:20000 --iterations 5000`.
4. Monitor device with ping (1s interval) and TCP connect check; flag crashes.
5. Save crash-inducing payloads to /tmp/boofuzz_crashes/.
6. Repeat with IEC 104 template (start byte 0x68, ASDU type 0-127, cause of transmission variations).
7. Reproduce crashes to confirm bug; extract pcap for vendor coordination.
**Remediation**: Apply vendor firmware patches for identified parsing bugs; deploy protocol-aware firewall with strict validation; isolate fuzz-exposed devices from production.

---

## Pass Criteria Checklist

- [ ] All DNP3 outstations enumerated with device attributes and authentication posture assessed
- [ ] DNP3 Direct Operate tested with and without SAv5
- [ ] All IEC 104 servers interrogated without authentication
- [ ] IEC 104 command (ASDU 45) tested for auth enforcement
- [ ] GOOSE injection demonstrated in lab with stNum manipulation
- [ ] MMS server browsed and SetDataValues tested
- [ ] PROFINET DCP enumeration and spoofing tested
- [ ] EtherCAT mailbox CoE access tested
- [ ] HART universal and device-specific commands fuzzed
- [ ] BACnet objects enumerated and WriteProperty tested
- [ ] CC-Link IE TSN frame injection evaluated
- [ ] Boofuzz templates executed for DNP3 and IEC 104 with crash logs preserved

---

## Severity Definitions (Fieldbus-Adjusted)

| Severity | CVSS Range | Fieldbus-Specific Meaning |
|----------|-----------|---------------------------|
| **Low** | 0.1 - 3.9 | Information disclosure only (device fingerprint) |
| **Medium** | 4.0 - 6.9 | Unauthorized read of process state; minor DoS |
| **High** | 7.0 - 8.9 | Unauthorized command execution; partial process disruption |
| **Critical** | 9.0 - 10.0 | Physical process manipulation; safety system impact; potential injury or environmental release |
