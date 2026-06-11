---
name: scada-ics-security
description: "SCADA/ICS security assessment covering industrial control system protocols including Modbus TCP, S7comm (Siemens), DNP3, EtherNet/IP (CIP), OPC UA, BACnet, and GOOSE."
origin: openclaw
version: "0.1.19"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: ics
  tool_count: 8
  guide_count: 5
  mitre: "TA0100-ICS Attack"
---


# SCADA/ICS Security Assessment

> **Supplementary Files**:
> - `payloads.md` — Protocol-specific attack payloads: Modbus, S7comm, EtherNet/IP, OPC UA, and ICS network scanning
> - `test-cases.md` — Structured test cases for PLC enumeration, register manipulation, fingerprinting, and honeypot deployment
> - `guides/ics-protocol-recon.md` — ICS protocol reconnaissance and enumeration deep dive
> - `guides/modbus-s7comm-attack.md` — Modbus and S7comm attack techniques
> - `guides/ics-network-assessment.md` — ICS network security assessment methodology
> - `guides/ics-honeypot-detection-guide.md` — ICS honeypot deployment, detection, and deception techniques
> - `guides/scada-network-monitoring-guide.md` — Passive ICS network monitoring, protocol anomaly detection, and traffic analysis

## Summary

Scada Ics Security skill domain covering ics operations.

**Tools**: conpot, plcscan, s7scan, modbus-cli, mbpoll, enip-client, csric, python-opcua

**Domain**: ics

**MITRE ATT&CK**: TA0100-ICS Attack

## Description

SCADA/ICS security assessment covering industrial control system protocols including Modbus TCP, S7comm (Siemens), DNP3, EtherNet/IP (CIP), OPC UA, BACnet, and GOOSE. Techniques span PLC enumeration, register manipulation, protocol fuzzing, and honeypot deployment for testing critical infrastructure defenses.

## Use Cases

1. **ICS Device Enumeration** — Discover and fingerprint PLCs, RTUs, HMIs, and other industrial devices on a target network segment
2. **Modbus Register Manipulation** — Read and write Modbus holding registers, coils, and input registers to assess protocol-level access controls
3. **Siemens S7 PLC Assessment** — Fingerprint and interact with Siemens S7-300/S7-400/S7-1200/S7-1500 PLCs via S7comm protocol
4. **EtherNet/IP Device Discovery** — Enumerate CIP devices, list identity objects, and assess EtherNet/IP session management
5. **OPC UA Security Testing** — Evaluate OPC UA server endpoints, certificate handling, and access control configurations
6. **ICS Honeypot Deployment** — Deploy conpot honeypots to detect unauthorized ICS network scanning and interaction
7. **Protocol Fuzzing** — Fuzz ICS protocol implementations to identify parsing vulnerabilities in PLC firmware
8. **ICS Network Segmentation Audit** — Verify proper network segmentation between IT and OT zones, assess cross-zone reachability

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **conpot** | ICS/SCADA honeypot emulating Modbus, IPMI, and other industrial protocols | `conpot -f --template default` |
| **plcscan** | Scan networks for PLCs and enumerate device models, firmware versions | `plcscan -i 192.168.1.0/24 -t 5` |
| **s7scan** | Enumerate Siemens S7 PLCs, extract hardware/firmware info, protection level | `s7scan -t 192.168.1.0/24` |
| **modbus-cli** | Interactive Modbus TCP client for reading/writing registers and coils | `modbus-cli read -a 192.168.1.10 -r 0 -n 10` |
| **mbpoll** | Modbus master simulator supporting RTU and TCP, read/write all data types | `mbpoll -t 192.168.1.10 -p 502 -r 1 -c 10` |
| **enip-client** | EtherNet/IP CIP client for device enumeration and attribute reading | `enip-client -i 192.168.1.0/24 --list-identity` |
| **csric** | ICS protocol fuzzer targeting Modbus, DNP3, S7comm, and IEC 61850 | `csric -t 192.168.1.10 -p modbus -f fuzz` |
| **python-opcua** | OPC UA client/server library for security testing and endpoint enumeration | `python3 -m opcua.client.server --url opc.tcp://192.168.1.20:4840` |

---

## Methodology

### Phase 1: Passive Reconnaissance

1. **Network Traffic Capture** — Capture traffic on ICS-typical ports (502/Modbus, 102/S7comm, 44818/EtherNet/IP, 4840/OPC UA, 20000/DNP3) using `tcpdump` or `tshark`
2. **Protocol Identification** — Identify which ICS protocols are in use by analyzing captured traffic patterns and port activity
3. **Topology Mapping** — Map device communication patterns to understand master-slave relationships and network topology

### Phase 2: Active Enumeration

4. **PLC Discovery** — Use `plcscan` and `s7scan` to identify PLC models, firmware versions, and protection states
5. **Modbus Enumeration** — Probe Modbus TCP devices for accessible register ranges, slave IDs, and coil states
6. **EtherNet/IP Discovery** — Enumerate CIP devices via `enip-client`, retrieve identity objects and device profiles
7. **OPC UA Endpoint Enumeration** — Discover OPC UA server endpoints, security policies, and certificate details

### Phase 3: Protocol Interaction

8. **Register Read/Write Testing** — Use `modbus-cli` and `mbpoll` to read registers and test write capabilities (lab only)
9. **S7comm Interaction** — Attempt to read system status lists (SZL) from Siemens PLCs to assess access controls
10. **OPC UA Access Testing** — Connect to OPC UA servers using `python-opcua` to evaluate authentication requirements

### Phase 4: Vulnerability Assessment

11. **Protocol Fuzzing** — Use `csric` to fuzz protocol parsers and identify crash-inducing payloads
12. **Authentication Bypass** — Test for missing authentication on protocol-level operations
13. **Firmware Analysis** — Identify outdated firmware versions with known CVEs from enumeration results

### Phase 5: Reporting and Remediation

14. **Risk Documentation** — Document all findings with ICS-specific risk ratings considering safety implications
15. **Remediation Guidance** — Provide defense-in-depth recommendations: network segmentation, protocol-aware firewalls, monitoring

---

## Defense Perspective

### ICS Security Principles

- **Safety First** — ICS attacks can cause physical damage, environmental harm, or injury. Never test against production systems.
- **Purdue Model** — Enforce proper segmentation following the Purdue Enterprise Reference Architecture (Levels 0-5)
- **Protocol-Aware Firewalls** — Deploy firewalls that understand ICS protocols to enforce command allowlists
- **Defense-in-Depth** — Layer network segmentation, application whitelisting, and continuous monitoring

### Detection Strategies

- Monitor for unexpected Modbus function codes (write operations from unauthorized sources)
- Alert on S7comm session establishment from non-HMI IP addresses
- Detect OPC UA certificate anomalies and unauthorized endpoint connections
- Watch for EtherNet/IP CIP commands outside normal operational patterns
- Deploy ICS-specific IDS rules (Snort/Suricata SCADA rulesets)

### Hardening Measures

- Disable unused protocol services on PLCs and RTUs
- Enable S7comm password protection on Siemens PLCs
- Configure OPC UA with certificate-based authentication and encrypted endpoints
- Implement Modbus TCP gateways with access control instead of direct PLC access
- Keep PLC firmware updated and apply vendor security patches
- Establish a demilitarized zone (DMZ) between IT and OT networks

---

## ICS Attack Matrix

The ICS Attack Matrix maps common attack techniques to the protocols and devices they target. This matrix guides assessment planning by identifying which techniques apply to the specific ICS environment under test.

| Attack Technique | Modbus | S7comm | EtherNet/IP | OPC UA | DNP3 | BACnet | GOOSE | Impact |
|------------------|--------|--------|-------------|--------|------|--------|-------|--------|
| Unauthorized Read | FC 01-04 | SZL Read | GetAttribAll | Browse/Read | Class 0 Read | ReadProperty | GOOSE Sniff | Information Disclosure |
| Unauthorized Write | FC 05-06,15-16 | DB Write | SetAttrib | Write Node | Direct Operate | WriteProperty | GOOSE Inject | Process Manipulation |
| Device Fingerprint | FC 43 | SZL 0x0011 | ListIdentity | GetEndpoints | Device Attributes | Device Obj Read | GOOSE Parsing | Reconnaissance |
| Denial of Service | Rapid FC Storm | CPU Stop | Flood Session | Exhaust Conn | Link Reset | ReinitializeDevice | ST/SQ Flood | Process Disruption |
| Protocol Fuzzing | csric Modbus | csric S7comm | Custom CIP | Python Fuzz | csric DNP3 | Custom BACnet | MMS Fuzz | Firmware Crash |
| Man-in-the-Middle | ARP Spoof + FC Modify | TPKT Hijack | COT Intercept | Proxy Server | Serial Intercept | UDP Intercept | L2 Inject | Full Control |
| Replay Attack | tcpreplay | Block Upload | Session Replay | Cert Clone | Traffic Replay | Request Replay | GOOSE Replay | Command Replay |
| Default Creds | None (no auth) | SYSTEM/S7/00000000 | None (no auth) | Anonymous | None (no auth) | None (no auth) | None | Full Access |

### Attack Chain Scenarios

**Scenario 1: Modbus Process Manipulation Chain**
1. Passive traffic capture identifies Modbus master-slave pairs
2. Register enumeration maps process variables (setpoints, valve states)
3. Unauthorized write to temperature setpoint register (FC 06)
4. Monitor for watchdog timeout or safety system activation

**Scenario 2: Siemens S7 PLC Full Compromise Chain**
1. s7scan identifies unprotected S7-1200 PLC
2. Block list enumeration reveals DB structure
3. Data block read extracts process logic and configuration
4. CPU stop command halts all process execution
5. Block upload extracts complete PLC program for analysis

**Scenario 3: EtherNet/IP to Modbus Gateway Pivot**
1. enip-client discovers CIP gateway device with Modbus bridge
2. Session registration without authentication succeeds
3. CIP Modbus bridge object allows indirect Modbus commands
4. Write commands to downstream Modbus slaves via CIP encapsulation

## Protocol Deep Dive

### Modbus TCP Internals

Modbus TCP frames consist of a 7-byte MBAP header followed by the PDU. The MBAP header includes Transaction ID (2 bytes), Protocol ID (2 bytes, always 0x0000), Length (2 bytes), and Unit ID (1 byte). The PDU contains the Function Code (1 byte) and data. There is no authentication field, no sequence number validation, and no encryption. Any TCP connection to port 502 can issue any function code to any unit ID.

Critical function codes for security testing:

- **FC 01/02**: Read Coils/Discrete Inputs — reveals digital I/O states
- **FC 03/04**: Read Holding/Input Registers — exposes analog process values
- **FC 05/06**: Write Single Coil/Register — modifies individual outputs or setpoints
- **FC 15/16**: Write Multiple Coils/Registers — enables multi-variable manipulation
- **FC 43**: Read Device Identification — fingerprints device make/model/firmware
- **FC 0x80+**: Exception responses indicate rejected commands (useful for access control mapping)

### S7comm Protocol Architecture

S7comm uses a three-layer transport stack: TPKT (RFC 1006) provides packet length framing, COTP (ISO 8073) provides the transport connection, and S7 Communication provides the application-layer protocol. The S7 header includes Protocol ID (0x32), Message Type (Job/Ack/Data/UserData), and a parameter field specifying the operation.

Key S7comm operations:

- **Setup Communication (0xF0)**: Establishes session with parameters (max AMQ, pdu size)
- **Read/Write Var (0x04/0x05)**: Reads from or writes to PLC memory areas (DB, I, Q, M, T, C)
- **Request Download (0x1A)**: Initiates block download to PLC (can replace program logic)
- **Download Block (0x1B)**: Transfers block data during download sequence
- **PLC Control (0x28)**: Start/Stop CPU, copy RAM to ROM
- **Read SZL (0x01)**: System Status List queries for device information

### DNP3 Protocol Structure

DNP3 (Distributed Network Protocol version 3) is widely used in the electric utility sector for SCADA communication between master stations and outstations. The protocol uses a three-layer architecture: Data Link Layer, Transport Layer, and Application Layer. The Data Link Layer handles framing with source/destination addressing. The Transport Layer handles segmentation for large messages. The Application Layer contains function codes and data objects.

DNP3 supports Secure Authentication (SA) versions 2 through 5, but many deployments operate without authentication enabled. Without SA, any device that can reach the DNP3 port can issue commands including Direct Operate (FC 5) which controls physical outputs.

### EtherNet/IP and CIP Architecture

EtherNet/IP encapsulates the Common Industrial Protocol (CIP) over TCP/UDP. The encapsulation layer uses a 24-byte header with Command, Length, Session Handle, Status, Sender Context, and Options fields. CIP provides two messaging models: Explicit Messaging (request-response, TCP port 44818) for configuration and data access, and Implicit Messaging (push model, UDP) for real-time I/O data exchange.

CIP organizes device functionality into object classes. The Identity Object (Class 0x01) provides device metadata. The Message Router Object (Class 0x02) routes requests to target objects. Vendor-specific objects (Class 0x64+) often contain proprietary functionality that may have weaker input validation.

### OPC UA Security Architecture

OPC UA supports a layered security model with three components: Transport Security (encryption at the communication layer), Application Authentication (X.509 certificates), and Authorization (role-based access control). Each OPC UA server exposes multiple endpoints with different security configurations. The security posture depends entirely on which endpoints are enabled and how they are configured.

Common misconfigurations: enabling the None security policy for backward compatibility, using self-signed certificates without proper validation, allowing anonymous access to writable variables, and failing to implement role-based access control on sensitive nodes.

### BACnet Protocol Stack

BACnet (Building Automation and Control Networks) operates over UDP port 47808 and uses a four-layer architecture: Physical, Data Link, Network, and Application. The Application Layer provides services for object access (ReadProperty, WriteProperty), device management (DeviceCommunicationControl, ReinitializeDevice), and alarm/event handling. BACnet devices organize functionality into objects (Analog Input, Analog Output, Binary Value, etc.) with properties.

BACnet has no built-in authentication for standard devices. BACnet Secure Connect (BACnet/SC) adds TLS encryption and authentication but is not widely deployed. Most building automation systems remain vulnerable to unauthorized read/write operations from any device on the network.

### IEC 61850 and GOOSE Protocol

IEC 61850 defines the communication architecture for electrical substations. GOOSE (Generic Object Oriented Substation Event) is a Layer 2 multicast protocol (Ethertype 0x88B8) used for fast horizontal communication between IEDs (Intelligent Electronic Devices). GOOSE messages carry status information (stNum, sqNum) and data values for protection and control functions.

GOOSE has no authentication or encryption at the protocol level. A device on the same VLAN can forge GOOSE messages with incremented stNum values to trigger protection relay operations. This can cause circuit breaker trips and substation isolation events. The time-critical nature of GOOSE (transfer time less than 4ms) makes it resistant to conventional security controls like TLS.

## Safety Considerations

### ICS Safety Philosophy

ICS environments differ fundamentally from IT environments because they control physical processes. A compromised web server may leak data; a compromised PLC can cause explosions, toxic releases, or electrical fires. Safety considerations must govern every phase of an ICS security assessment.

### Pre-Assessment Safety Requirements

Before beginning any ICS security testing, complete these mandatory safety steps:

1. **Obtain written authorization** that explicitly identifies which systems are in scope and which are excluded from testing.
2. **Identify Safety Instrumented Systems (SIS)** and ensure they are excluded from testing scope. SIS are the last line of defense that prevent catastrophic events.
3. **Establish communication protocols** with control room operators. Define a stop-testing signal that operators can use if they observe process anomalies.
4. **Document emergency shutdown procedures** for the specific facility being tested.
5. **Verify isolated lab environment** for any active exploitation (register writes, fuzzing, DoS testing). Never test against production systems.
6. **Review process hazards analysis (PHA)** to understand which process variables could cause harm if manipulated.

### Safety Impact Classification

Classify each planned test by its potential safety impact:

| Classification | Description | Example | Allowed Environment |
|----------------|-------------|---------|---------------------|
| **Informational** | Read-only operations that do not affect the process | Register reads, traffic capture, device fingerprinting | Production (with authorization) or Lab |
| **Low Impact** | Operations that cause minor, reversible changes | Reading diagnostic data, browsing OPC UA nodes | Production (with operator awareness) or Lab |
| **Medium Impact** | Operations that could temporarily affect process behavior | Writing to non-critical registers, session registration | Lab Only |
| **High Impact** | Operations that directly affect process control | Register writes to setpoints, coil operations, PLC stop/start | Lab Only with safety monitoring |
| **Critical Impact** | Operations that could trigger safety systems or cause physical harm | Fuzzing, DoS attacks, PLC program modification, SIS interaction | Lab Only with dedicated safety officer |

### Operational Constraints

- **Maintain process uptime**: ICS environments often require 99.999%+ availability (5 nines). Schedule testing during planned maintenance windows.
- **Avoid watchdog timeouts**: Aggressive scanning can cause PLC watchdog resets. Use conservative scan timing with delays between probes.
- **Preserve communication paths**: Do not disrupt established master-slave polling cycles. Insert test traffic between normal poll intervals.
- **Respect timing constraints**: Real-time control loops operate in millisecond timeframes. Injected traffic must not introduce latency.
- **Monitor for cascading effects**: A change to one register may trigger automated responses in other parts of the process. Understand interdependencies before testing.

### Emergency Procedures

If a test causes an unexpected process response:

1. **Stop all testing immediately** — halt all scanning tools, fuzzers, and active connections
2. **Notify the control room operator** — inform them of the specific operation that triggered the response
3. **Do not attempt remediation** — let operators handle the process recovery using established procedures
4. **Document the event** — record the exact operation, time, observed response, and any error messages
5. **Report to the engagement lead** — escalate for safety review before resuming any testing

## ICS Network Architecture

### Reference Architecture: Purdue Model

The Purdue Enterprise Reference Architecture (ISA-95 / IEC 62443) is the industry standard for ICS network segmentation. Understanding the Purdue Model is essential for both offensive testing (identifying cross-zone attack paths) and defensive assessment (verifying segmentation controls).

```
Level 5: Enterprise Network (ERP, Email, Business Systems)
    |
    [ IT Firewall ]
    |
Level 4: Site Operations (Historian, MES, OPC Servers)
    |
    [ Industrial DMZ (IDMZ) - Dual Firewalls ]
    |
Level 3: Operations (HMI, Engineering Workstations, OPC UA Gateway)
    |
    [ OT Firewall / Protocol-Aware Firewall ]
    |
Level 2: Control (PLCs, RTUs, DCS Controllers)
    |
    [ Control Network Switch / Fieldbus Boundary ]
    |
Level 1: Field Devices (Sensors, Actuators, I/O Modules)
    |
Level 0: Process (Physical Equipment)
```

### Network Zone Testing Methodology

For each Purdue level boundary, test these specific security controls:

**IT/OT Boundary (Level 4-5)**:
- Verify no direct IT-to-OT routing exists
- Test for bypassed DMZ paths (direct VPN, dual-homed hosts)
- Verify all data flows through the IDMZ using replication

**DMZ (Level 3.5)**:
- Verify unidirectional data replication (data diode behavior)
- Test for direct connections through the DMZ
- Verify no traffic can originate from IT and reach OT without passing through DMZ services

**Operations/Control Boundary (Level 2-3)**:
- Verify protocol-aware firewall rules (allowlist of Modbus function codes)
- Test for unauthorized engineering workstation access to PLCs
- Verify HMI-only communication patterns

**Control/Field Boundary (Level 1-2)**:
- Verify fieldbus network isolation
- Test for unauthorized devices on the control network
- Verify multicast traffic containment (GOOSE messages stay within their VLAN)

### Common Architecture Weaknesses

1. **Flat Networks**: Many ICS environments have no internal segmentation beyond a single firewall at the IT boundary. All PLCs, HMIs, and engineering workstations share the same subnet.
2. **Shared Management VLANs**: Engineering workstations used for both IT and OT management create implicit trust bridges between zones.
3. **Inadequate DMZ Implementation**: Some facilities deploy a single firewall instead of dual firewalls for the IDMZ, creating a single point of failure.
4. **Vendor Remote Access**: Vendor maintenance connections that bypass the DMZ using VPNs directly to PLC subnets are a persistent attack vector.
5. **Wireless in OT Zones**: Unauthorized wireless access points deployed for convenience bridge the air gap that many ICS designs assume.
6. **Converged IT/OT Switches**: Network switches that carry both IT and OT traffic without VLAN separation create opportunities for lateral movement.

### Architecture Assessment Tools

```bash
# Map network topology using ARP and routing tables
arp-scan -l | sort

# Verify VLAN segmentation
nmap -sT -p 502,102,44818 <target_subnet> --source-port 53

# Test for dual-homed hosts
for host in $(cat ot_hosts.txt); do
  traceroute -n $host 2>/dev/null | tail -1
done

# Detect unauthorized routing between zones
ip route get <ot_ip>
```

## Honeypot Detection

### Understanding ICS Honeypots

ICS honeypots are decoy systems designed to mimic real industrial devices and attract attackers. They serve as early warning systems for intrusion detection. However, from a penetration testing perspective, identifying honeypots is important for realistic engagement outcomes — interacting with a honeypot wastes time and may trigger defensive alerts.

### Honeypot Indicators in ICS Environments

| Indicator | Real Device | Honeypot | Detection Method |
|-----------|-------------|----------|------------------|
| Response timing | Variable (5-50ms) | Consistent (1-2ms) | Timestamp analysis |
| Register data patterns | Physically realistic | Random or static values | Statistical analysis |
| Protocol error handling | Complex, vendor-specific | Simplified, generic | Malformed request testing |
| TCP/IP stack fingerprint | Embedded OS (VxWorks, Linux RT) | Standard Linux | nmap OS detection |
| Network behavior | Periodic polling, alarm responses | Listens only, no proactive traffic | Baseline comparison |
| Service diversity | Multiple protocols, vendor services | Limited to emulated protocols | Port scan completeness |

### Detecting conpot Honeypots

conpot is the most common ICS honeypot. Detection techniques include:

```bash
# 1. TCP/IP stack fingerprinting - conpot runs on standard Linux
nmap -O 192.168.1.200
# Real PLCs show embedded OS fingerprints (VxWorks, proprietary)
# conpot shows standard Linux kernel

# 2. Register value analysis - check for realistic process data
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='192.168.1.200', port=502, auto_open=True)
regs = c.read_holding_registers(0, 20)
if regs:
    import statistics
    # Real process data has variance; honeypots often use static/random
    print(f'Mean: {statistics.mean(regs):.1f}')
    print(f'Stdev: {statistics.stdev(regs):.1f}')
    print(f'Range: {min(regs)}-{max(regs)}')
    # Low stdev with high range may indicate random fill
    # Zero stdev indicates static values
c.close()
"

# 3. Protocol error handling - send malformed Modbus requests
# Real devices return specific exception codes; honeypots may return generic errors
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='192.168.1.200', port=502, auto_open=True)
# Try reading beyond register limits
result = c.read_holding_registers(65535, 100)
if result is None:
    print('Exception response - check error code specificity')
else:
    print('Returned data for out-of-range request - likely honeypot')
c.close()
"

# 4. Service enumeration - real PLCs have multiple services
nmap -sV -p 21,22,80,443,502,102,161,443,8080 192.168.1.200
# Real PLCs often have FTP, SNMP, or web management
# conpot typically only emulates the configured protocol(s)
```

### Evasion Strategies for Testing

When performing authorized testing, identify and document honeypots without triggering alerts:

1. **Passive observation first**: Monitor traffic to the target IP before active interaction. Honeypots typically receive no legitimate traffic.
2. **Timing analysis**: Measure response times over multiple requests. Consistent sub-millisecond responses indicate software emulation rather than real PLC processing.
3. **Cross-reference with asset inventory**: Compare discovered devices against the official asset inventory provided during engagement scoping.
4. **Physical verification**: In on-site engagements, verify that the IP address corresponds to a physical device in the control cabinet.

## Common Pitfalls

1. **Testing Production Systems** — Never interact with production ICS devices. All testing must occur in isolated lab environments. A single write to the wrong register can shut down a power plant.
2. **Ignoring Safety Systems** — ICS environments have safety instrumented systems (SIS). Attacks that compromise SIS can lead to catastrophic physical consequences.
3. **Protocol Timing Sensitivity** — ICS protocols often have strict timing requirements. Aggressive scanning can cause PLC watchdog timeouts and process interruptions.
4. **Assuming IT Security Maps to OT** — Patching cycles, availability requirements, and risk models differ fundamentally between IT and OT. A 99.9% uptime SLA is unacceptable for a power grid.
5. **Neglecting Serial Connections** — Many ICS environments still use serial (RS-232/RS-485) connections. TCP-only scanning misses these attack surfaces.
6. **Overlooking Legacy Protocols** — Modbus has no built-in authentication or encryption. Do not assume protocol-level access controls exist just because devices respond.
7. **Disregarding Vendor-Specific Implementations** — Siemens S7comm, Allen-Bradley CIP, and other vendor protocols have unique quirks. Generic ICS tools may not cover all variants.
