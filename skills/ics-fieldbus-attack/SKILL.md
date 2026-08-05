---
name: ics-fieldbus-attack
description: Industrial fieldbus protocol penetration testing beyond Modbus — Profibus/PROFINET, EtherCAT, DNP3, IEC 61850 (GOOSE/SV/MMS), IEC 60870-5-101/104, Foundation Fieldbus, HART, CC-Link, BACnet deep dive. Covers power utility, process automation, building automation, and automotive fieldbus attack surfaces.
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - Claude Code
  - Claude Sonnet 4.5+
  - Claude Opus 4.5+
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: ics-fieldbus-attack
  category: fieldbus
  tool_count: 13
  guide_count: 1
  mitre: "T0817-Program Logic Controller Software"
  keywords:
    - ICS
    - SCADA
    - fieldbus
    - DNP3
    - IEC 61850
    - Profibus
    - industrial protocols
    - PROFINET
    - EtherCAT
    - IEC 60870
    - GOOSE
    - HART
    - Foundation Fieldbus
    - CC-Link
    - BACnet
    - power utility
    - substation
    - process automation
  last_reviewed: "2026-07-26"
---


# ICS Fieldbus Protocol Attack Assessment

> **Supplementary Files**:
> - `payloads.md` — Protocol-specific payloads for 12 fieldbus families: DNP3, IEC 60870-5, IEC 61850 (GOOSE/SV/MMS), Profibus/PROFINET, EtherCAT, EtherNet/IP-CIP deep, Foundation Fieldbus, HART/WirelessHART, CC-Link, BACnet deep, Modbus RTU/Plus, and SCADA fuzzing templates
> - `test-cases.md` — 12 structured test cases (TC-FB-001 through TC-FB-012) covering each protocol family
> - `guides/ics-fieldbus-attack-playbook.md` — Comprehensive playbook: fieldbus attack methodology, real-world incidents (Ukraine 2015 BlackEnergy, Industroyer 2016, Triton/Trisis 2017, Florida water 2021), lab setup, and defensive guidance

## Summary

ICS fieldbus protocol penetration testing covering all major industrial protocols BEYOND Modbus TCP. This domain specializes in the protocols that govern power utilities, oil & gas, water treatment, building automation, and discrete manufacturing. The skill targets protocols that `scada-ics-security` either omits or only covers superficially.

**Tools**: wireshark, scapy, plcscan, redpoint, opendnp3, lib60870, iec104attack, profishark, boofuzz, conpot, nmap-nse, ettercap/bettercap, claroty/nozomi

**Domain**: ics-fieldbus-attack

**MITRE ATT&CK ICS**: T0817 - Program Logic Controller Software, T0859 - Valid Accounts, T0866 - Exploitation of Remote Services, T0884 - Connection Proxy, T0890 - Exploit Public-Facing Application, T0807 - Command-Line Interface, T0858 - Change Operating Mode, T0859 - Train Operator

## Description

Industrial fieldbus protocols are the central nervous system of critical infrastructure. Unlike Modbus TCP (covered by `scada-ics-security`), these protocols vary dramatically across industry verticals:

- **Power utilities** use DNP3, IEC 60870-5-101/104, IEC 61850 (GOOSE/SV/MMS), and ICCP/TASE.2 — these protocols were the targets of the Ukraine 2015 (BlackEnergy) and 2016 (Industroyer/CrashOverride) attacks that caused widespread blackouts.
- **Process automation** (oil & gas, chemical) uses Foundation Fieldbus, HART, and PROFIBUS PA for intrinsically-safe instrument communication in hazardous areas.
- **Discrete manufacturing** uses PROFINET, EtherCAT, and EtherNet/IP for sub-millisecond motion control loops that tolerate zero disruption.
- **Building automation** uses BACnet for HVAC, lighting, and physical access control.
- **Automotive and railway** fieldbuses (CAN, LIN, FlexRay, MVBC) are covered in `automotive-vehicle-security` — this skill focuses on plant-side manufacturing and infrastructure.

Each protocol family has its own framing, addressing model, security model (or lack thereof), and exploitation patterns. This skill provides deep-dive testing methodologies for all of them.

## Detection Methods

### Fieldbus Protocol Anomalies
- **Profibus/PROFINET anomalies**: Unauthorized master taking control; DCP write requests.
- **DNP3 anomalies**: Out-of-sequence fragments; unsolicited responses from RTU.
- **EtherNet/IP (CIP) anomalies**: Unauthorized CIP messages; non-engineering workstation sending commands.
- **Modbus anomalies**: Function codes 5/6/15/16 (write) from non-master source.

### SIEM Detection Rules
- **Splunk SPL**: `index=ics sourcetype=modbus | where function_code IN (5,6,15,16) AND src_ip != "engineering_ws"`
- **Dragos / Nozomi Guardian**: Native OT security platform detections.
- **Claroty CTD**: Cyber threat detection for OT environments.

## Defense Evasion Techniques

### Protocol-Level Stealth
- **Mimic legitimate master**: Use engineering workstation IP; match Modbus master timing.
- **Passive reconnaissance**: Sniff fieldbus traffic before injecting; learn legitimate patterns.
- **Single-shot attack**: Send one malicious write (e.g., open breaker); below sustained-pattern detection.
- **Off-hours operation**: Execute during shift change; blends with maintenance.

### Physical Effect Stealth
- **Gradual setpoint change**: Change process setpoint slowly; avoids trip alarms.
- **Sensor spoofing**: Send false sensor values to historian; mask physical effect.
- **Safety bypass**: Disable SIS (Safety Instrumented System) before main attack.

## Differentiation

This skill is **distinct from and complementary to** `scada-ics-security`:

| Aspect | scada-ics-security | ics-fieldbus-attack (this skill) |
|--------|--------------------|---------------------------------|
| **Primary scope** | Modbus TCP, S7comm, EtherNet/IP basic, OPC UA | Fieldbus protocols beyond Modbus |
| **Power utility coverage** | Brief DNP3 mention | Deep DNP3, IEC 60870-5-101/104, IEC 61850 (GOOSE/SV/MMS) |
| **Process automation** | None | Foundation Fieldbus H1/HSE, HART/WirelessHART |
| **Discrete manufacturing** | None | PROFINET RT/IRT, EtherCAT, CC-Link IE |
| **Building automation** | Brief BACnet mention | Deep BACnet object model, BACnet/SC, WriteProperty exploitation |
| **Layer-2 attacks** | GOOSE mention only | Full GOOSE/SV frame injection at Layer 2, multicast spoofing |
| **Real-world incident focus** | Stuxnet reference | BlackEnergy 2015, Industroyer 2016, Triton 2017, Florida water 2021 |
| **Fuzzing** | csric generic | Boofuzz templates per protocol family |
| **Tool depth** | 8 tools, basic usage | 13 tools, protocol-specific dissectors and crafters |
| **Target vertical** | Generic ICS | Power utility, process, manufacturing, building |

If the engagement target is a power utility, water/wastewater, or natural gas distribution facility, **this skill is primary**. If the target uses Modbus TCP or Siemens S7 PLCs in a factory floor, `scada-ics-security` may suffice.

## Use Cases

1. **DNP3 Outstation Assessment** — Enumerate DNP3 outstations, read analog/binary points without authentication, test Direct Operate (FC 5) command authorization
2. **IEC 60870-5-104 (TCP) Replay and Injection** — Capture and replay APDU commands to RTUs, test for ASDU type 45 (command) authorization
3. **IEC 61850 GOOSE Frame Injection** — Forge Layer 2 GOOSE messages with elevated stNum to spoof breaker status or trip protection relays
4. **IEC 61850 MMS Server Assessment** — Enumerate IED logical nodes, read/write SetDataValues, test MMS authentication
5. **PROFINET IRT Real-Time Spoofing** — Inject forged real-time frames into the PROFINET cycle to disrupt motion control
6. **EtherCAT Mailbox Exploitation** — Enumerate slave devices via SDO Info, abuse CoE register access
7. **Foundation Fieldbus H1 Sniffing** — Passively capture LAS schedules and VCR mappings on H1 segments
8. **HART Command Fuzzing** — Send malformed HART commands over 4-20mA current loops (HART FSK) or WirelessHART
9. **BACnet Object Model Deep Dive** — Enumerate all BACnet objects, test WriteProperty to setpoints, trigger ReinitializeDevice
10. **CC-Link IE Frame Injection** — Test cyclic/data exchange frame forgery on CC-Link IE TSN networks
11. **SCADA Honeypot Fieldbus Deployment** — Deploy conpot variants emulating DNP3/IEC 104/BACnet
12. **Protocol-Aware MITM** — Ettercap/Bettercap with custom filters for ICS protocols, ARP poisoning on OT VLANs

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Wireshark** | Full protocol dissection of 30+ fieldbus protocols via built-in dissectors | `tshark -i eth0 -Y "dnp3 || iec60870_104 || goose || pn_rt || ethercat"` |
| **Scapy** | Layered packet crafting with IEC 61850/104, GOOSE, DNP3, PROFINET layers | `python3 -c "from scapy.contrib import dnp3; p=dnp3.DNP3(); sendp(p)"` |
| **plcscan** | Network-wide PLC discovery, identifies Siemens/Modbus/Schneider/AB devices | `plcscan -i 192.168.1.0/24 -t 5` |
| **Redpoint Digitals** | Industrial protocol discovery suite covering CIP, PROFINET, EtherCAT, IEC 61850 | `redpoint scan --protocols ALL 192.168.1.0/24` |
| **OpenDNP3** | Reference DNP3 master/outstation stack for testing and fuzzing | `master -c master.config --command binary-output 1:1` |
| **lib60870** | MZ Automation IEC 60870-5-101 and -104 library for master/slave testing | `iec104_test_client -h 192.168.1.10 -p 2404` |
| **IEC104Attack** | Corelight framework for IEC 104 attack and anomaly generation | `iec104attack --target 192.168.1.10 --type replay` |
| **ProfiShark** | Profibus/PROFINET traffic capture tap with analysis suite | `profishark-cli capture --interface tap0 --duration 300` |
| **Boofuzz** | Protocol-aware fuzzer with fieldbus templates (DNP3, IEC 104, GOOSE, Modbus) | `python3 fuzz_dnp3.py --target 192.168.1.10:20000` |
| **Conpot** | Honeypot emulating ICS protocols including Modbus, S7comm, IEC 104 | `conpot -f --template iec104_honeypot` |
| **Nmap NSE** | Script engine with ICS dissectors: dnp3-info, enip-info, s7-info, BACnet-discover, modbus-stuxnet | `nmap -p 20000 --script dnp3-info 192.168.1.10` |
| **Ettercap / Bettercap** | ARP poisoning and MITM with custom filters for ICS protocol mutation | `bettercap -iface eth0 -caplet IEC104-mitm.cap` |
| **Claroty / Nozomi** (reference) | Commercial passive ICS asset discovery and monitoring — use for client-side validation | (Vendor reference; for comparison only) |

---

## Methodology

### Phase 1: Passive Reconnaissance (Read-Only, Safe)

1. **Traffic Capture Setup** — Configure span port or network tap on OT switch; never introduce active devices into a fieldbus segment without explicit authorization. For PROFIBUS/PROFINET, use a ProfiShark tap.
2. **Protocol Dissection** — Use Wireshark with fieldbus-specific display filters to identify protocols in use: `dnp3`, `iec60870_asdu`, `iecgoose`, `pn_mrp`, `pn_dcp`, `ecat`, `ff_h1`, `hart_ip`, `bacnet`, `cip`.
3. **Master-Slave Topology Mapping** — Map which IPs are masters (pollers) versus slaves (responders) by analyzing request-response patterns. Identify polling intervals and device addresses.
4. **Baseline Traffic Capture** — Record 24+ hours of traffic for anomaly baseline. Fieldbus traffic is highly periodic; deviations indicate either failures or attacks in progress.
5. **Asset Inventory via Passive Fingerprinting** — Extract device identity from protocol responses (DNP3 Device Attributes, IEC 61850 Logical Node names, BACnet vendor IDs, PROFINET device names).

### Phase 2: Active Enumeration (Read-Only, Low Impact)

6. **Nmap NSE ICS Scripts** — Run protocol-specific discovery: `dnp3-info`, `enip-info`, `s7-info`, `BACnet-discover`, `modbus-discover`, `iec61850-mms`. Use conservative timing (`--max-rate 50`).
7. **PLC Discovery with plcscan** — Identify vendor/model/firmware across the network segment.
8. **Redpoint Digitals Sweep** — Multi-protocol discovery for environments mixing CIP, PROFINET, EtherCAT, and IEC 61850.
9. **Protocol-Specific Enumeration**:
   - DNP3: Read Device Attributes (FC 0, Class 0), enumerate data points by variation
   - IEC 104: Send interrogation command (C_IC_NA_1, ASDU type 100), enumerate ASDU types
   - IEC 61850 MMS: Browse logical devices, logical nodes, and data objects
   - BACnet: Send Who-Is/I-Am, enumerate object lists with ReadProperty
   - PROFINET: Send IdentifyAllPDRealDevices, read device vendor and product names
10. **Device Configuration Dump** — For each identified device, dump configuration (setpoints, parameters, addressing) using read-only protocol operations.

### Phase 3: Protocol Interaction (Write Operations, Lab Only)

11. **Command Authorization Testing** — For each protocol, attempt command operations and verify whether authentication is enforced:
    - DNP3: Try Direct Operate (FC 5) without authentication
    - IEC 104: Try ASDU type 45 (single command) without auth
    - IEC 61850 MMS: Try SetDataValues on control objects
    - BACnet: Try WriteProperty to Present_Value on Analog Output objects
    - PROFINET: Try Connect/Release cycle control
12. **Register/Point Enumeration** — Systematically enumerate all readable points to map process state (temperatures, pressures, breaker positions, valve states).
13. **Protocol Behavior Fingerprinting** — Send malformed requests and record exception responses. Each vendor handles malformed input differently — useful for fingerprinting.

### Phase 4: Vulnerability Assessment

14. **CVE Cross-Reference** — Match discovered firmware versions against ICS-CERT, ISA-99, and vendor advisory databases. Note: many ICS CVEs are disclosed years after discovery.
15. **Protocol Fuzzing** — Use Boofuzz with protocol-specific templates to identify parser crashes:
    - DNP3 fuzz template: link layer, transport layer, application layer
    - IEC 104 fuzz template: ASDU structure, cause of transmission, IOA ranges
    - GOOSE fuzz template: Ethertype 0x88B8 frame structure
    - Modbus fuzz template: function code coverage, register range overflow
16. **Authentication Bypass Testing** — Test Secure Authentication Version (SAv) downgrade attacks on DNP3; test certificate bypass on IEC 61850 MMS; test BACnet/SC vs legacy BACnet/IPv4 fallback.
17. **Replay Attack Validation** — Capture legitimate command sequences and replay with tcpreplay. Many protocols accept replays without nonce/timestamp validation.

### Phase 5: MITM and Injection (High Impact, Lab Only with Operator Awareness)

18. **ARP Poisoning** — Use Ettercap or Bettercap to position the attacker between master and slave. Verify with traffic capture.
19. **Custom Filter Development** — Write protocol-aware filters that mutate specific fields (setpoints, breaker commands) while passing other traffic unchanged.
20. **Layer-2 GOOSE/SV Injection** — Forge GOOSE frames with elevated stNum values to override legitimate device status. This is a real-world attack vector used by Industroyer.
21. **Real-Time Cycle Disruption** — For PROFINET IRT and EtherCAT, inject frames into the real-time cycle to test device fault tolerance. WARNING: This can cause physical damage.
22. **Command Injection** — During MITM, inject unauthorized control commands. Use lab replicas of physical processes to assess safety impact.

### Phase 6: Reporting and Remediation

23. **ICS Risk Scoring** — Apply ISA-99 / IEC 62443 risk scoring that accounts for safety implications, not just confidentiality/availability/integrity.
24. **Purdue Model Gap Analysis** — Document segmentation violations, cross-zone paths, and DMZ bypass.
25. **Defense-in-Depth Recommendations** — Provide tiered recommendations: protocol-aware firewalls, unidirectional gateways, ICS-aware IDS/IPS, secure protocol versions (DNP3 SAv5, IEC 62351, BACnet/SC).

---

### Defense Perspective

### Fieldbus Security Fundamentals

- **No Built-in Security by Design** — DNP3, IEC 60870-5, IEC 61850 GOOSE, PROFIBUS, and Foundation Fieldbus H1 were all designed before cybersecurity was a concern. Authentication and encryption are afterthoughts layered on via DNP3 SAv, IEC 62351, and BACnet/SC.
- **Determinism Trumps Security** — Real-time protocols (GOOSE, PROFINET IRT, EtherCAT) prioritize deterministic timing (sub-4ms transfer) over encryption, which adds latency. This is why TLS on GOOSE is impractical for time-critical operations.
- **Long Equipment Lifecycles** — Fieldbus devices deployed 20+ years ago remain in service. Firmware updates are rare, risky, and require planned outages. Patches that break compatibility are unacceptable.
- **Physical Process Risk** — A fieldbus attack is not a data breach — it is a potential physical catastrophe. Industroyer (2016) opened breakers and crashed power grids. Triton (2017) modified Safety Instrumented System logic.

### IEC 62443 Defense Architecture

The IEC 62443 standard defines zones and conduits for OT security:

```
+---------------------------------------------+
| Zone: Enterprise (Level 4-5)                |
|  - ERP, MES, Historian                      |
+---------------------------------------------+
              |  IDMZ  |
+---------------------------------------------+
| Zone: Operations (Level 3)                  |
|  - HMI, Engineering Workstations            |
|  - OPC UA Gateway, Historian Forwarder      |
+---------------------------------------------+
              |  OT Firewall  |
+---------------------------------------------+
| Zone: Control (Level 2)                     |
|  - PLCs, RTUs, DCS Controllers              |
|  - Protocol-Aware Firewall                  |
+---------------------------------------------+
              |  Fieldbus Boundary  |
+---------------------------------------------+
| Zone: Field (Level 1-0)                     |
|  - Sensors, Actuators, I/O                  |
|  - Foundation Fieldbus H1, PROFIBUS PA      |
|  - GOOSE multicast VLAN                     |
+---------------------------------------------+
```

### Detection Strategies per Protocol

| Protocol | What to Monitor | Detection Tool |
|----------|----------------|----------------|
| **DNP3** | Unsolicited Link Reset, Direct Operate from non-master IP, SAv downgrade attempts | Suricata dnp3 rules, Nozomi Guardian |
| **IEC 104** | ASDU type 45 (command) outside operational hours, ASDU type 70 (interrogation) from unknown IPs | Suricata iec60870 rules, Claroty |
| **GOOSE** | stNum jumps >1, sqNum wraparound, new source MAC on multicast group | Wireshark GOOSE analysis,_dragos |
| **MMS** | Unauthorized SetDataValues, new client certificate | IEC 61850 security gateway |
| **PROFINET** | DCP Identify from non-engineering MAC, unexpected RT cycle disruptions | PROFINET diagnostic, Tenable.ot |
| **EtherCAT** | Mailbox overload, slave state transitions outside maintenance windows | EtherCAT diagnostic, Claroty |
| **BACnet** | WriteProperty to Present_Value, ReinitializeDevice, Who-Is floods | Wireshark BACnet analysis, Black Lantern |
| **HART** | Loop current anomalies, WirelessHART join from unknown EUI-64 | HART gateway diagnostics |

### Hardening Measures

- **Upgrade Protocol Versions** — Where supported, migrate to DNP3 Secure Authentication v5, IEC 62351-secured IEC 61850, BACnet/SC.
- **Deploy Protocol-Aware Firewalls** — Use Tofino, Bayshore, or Clarke-Taylor firewalls that decode and validate ICS protocols at Layer 7.
- **Implement Unidirectional Gateways** — For critical zones (generation, transmission), deploy Waterfall or Owl data diodes that physically prevent inbound traffic.
- **Segment Multicast Domains** — GOOSE, PROFINET, and EtherCAT use multicast. Restrict multicast to dedicated VLANs and enforce port security on switch ports.
- **Certificate-Based Authentication** — For MMS, OPC UA, and BACnet/SC, mandate X.509 certificates from a managed CA. Disable anonymous access.
- **Continuous Asset Inventory** — Deploy passive ICS discovery tools (Claroty, Nozomi, Dragos) to maintain real-time asset inventory. Active scanning is too risky for production OT.
- **Operator Training** — Train operators to recognize fieldbus attack indicators: unexplained breaker operations, setpoint changes without operator action, GOOSE stNum anomalies in HMI logs.

---

## ICS Fieldbus Attack Matrix

The matrix below maps attack techniques to fieldbus protocols. Use this to plan engagement scope based on which protocols the target facility operates.

| Attack Technique | DNP3 | IEC 104 | GOOSE | MMS | PROFINET | EtherCAT | Foundation FF | HART | BACnet |
|------------------|------|---------|-------|-----|----------|----------|---------------|------|--------|
| **Device Fingerprint** | Device Attr (FC 0) | Interrogation (Type 100) | Source MAC + Dataset | GetNameList | DCP Identify | SDO Info | LAS schedule | Universal Cmd 0 | I-Am broadcast |
| **Unauthorized Read** | Class 0 Read (FC 1) | Type 1/13 (M_SP_NA) | Sniff multicast | GetDataValues | Read cycle data | Read mailbox | Read VCR | Cmd 3 (read var) | ReadProperty |
| **Unauthorized Write** | Direct Operate (FC 5) | Type 45/46 (command) | Inject w/ high stNum | SetDataValues | Connect + write | CoE Write | Write to DO | Cmd 6 (write) | WriteProperty |
| **Replay** | tcpreplay FC 5 | Replay ASDU 45 | Replay frame | Replay MMS req | Replay RT frame | Replay mailbox | (Not applicable) | (Not applicable) | Replay WriteProperty |
| **MITM** | ARP + filter | ARP + filter | L2 multicast | ARP + cert | ARP + filter | ARP + filter | (Serial only) | (Serial only) | UDP + filter |
| **DoS** | Link Reset flood | StartDT flood | stNum flood | Exhaust session | DCP flood | Mailbox flood | LAS override | Loop current | Who-Is flood |
| **Fuzz** | Boofuzz DNP3 | Boofuzz IEC 104 | Scapy GOOSE | Boofuzz MMS | Boofuzz PN_RT | Boofuzz EtherCAT | Custom Fuzz | Custom Fuzz | Boofuzz BACnet |
| **CVE PoCs** | Triangle D20 | Multiple RTU CVEs | (Concept only) | Siemens IED CVEs | Siemens, Phoenix | Beckhoff CVEs | Emerson CVEs | Pepperl+Fuchs | Schneider, Honeywell |
| **Auth Method** | SAv2-5 optional | None (add IEC 62351) | None (IEC 62351 opt) | X.509 optional | None | None | None | None | None (BACnet/SC opt) |
| **Default Port** | TCP/UDP 20000 | TCP 2404 | Ethertype 0x88B8 | TCP 102 | UDP 34962-34964 | EtherType 0x88A4 | H1: 31.25kbps | HART over 4-20mA | UDP 47808 |

### Real-World Attack Chain Examples

**Scenario 1: Ukraine 2015 BlackEnergy (DNP3 + IEC 104)**
1. Spear-phishing of IT network establishes initial foothold
2. Lateral movement to HMI workstation via stolen VPN credentials
3. Operator screen frozen using KillDisk payload
4. Attacker manually operated breakers via HMI (DNP3 commands to RTUs)
5. UPS systems disabled to prevent recovery power
6. Forensic evidence destroyed via firmware overwrites

**Scenario 2: Industroyer/CrashOverride 2016 (Multi-Protocol Automated)**
1. Compromised HMI workstation hosts the Industroyer framework
2. Framework auto-detects supported protocols: IEC 104, IEC 61850 GOOSE, IEC 60870-5-101 serial, OPC DA
3. Hardcoded ICS payloads execute: open breakers, disable protection relays
4. DoS module floods the upstream communications server
5. Wiper module destroys evidence on exit

**Scenario 3: Triton/Trisis 2017 (Triconex SIS)**
1. Initial access via engineering workstation phishing
2. Attacker gains access to TriStation 1131 SIS programming environment
3. Trojanized firmware deployed to Triconex MP3008 controllers
4. SIS fails to trip on demand during intentional process upset
5. First known malware designed to disable physical safety systems

**Scenario 4: Florida Water Treatment 2021 (Remote HMI)**
1. Compromised TeamViewer credentials (reused password) on HMI
2. Attacker connected remotely and changed sodium hydroxide setpoint
3. Setpoint changed from 100 ppm to 11,100 ppm (100x normal)
4. Operator detected change within 90 seconds and reverted
5. No physical harm, but demonstrated feasibility of remote mass-casualty attack

---

## Safety Considerations

### Fieldbus Safety Doctrine

Fieldbus attacks are qualitatively different from IT penetration tests. A successful write to a holding register or a forged GOOSE frame can:

- **Open circuit breakers** on transmission lines, causing regional blackouts
- **Modify setpoints** on chemical dosing pumps, contaminating water supplies
- **Disable safety instrumented systems**, allowing process upsets to cascade
- **Trigger spurious trips** on protection relays, isolating healthy equipment
- **Disrupt motion control cycles**, damaging multi-million-dollar machinery

### Pre-Assessment Safety Requirements

Before any active testing on a fieldbus network:

1. **Written authorization must explicitly identify in-scope protocols, devices, and zones.** Exclusions must include Safety Instrumented Systems (SIS), emergency shutdown systems, and any device whose failure could cause injury or environmental release.
2. **Operations team must be present** during all active testing. Establish a clear stop signal and abort procedure.
3. **Production system testing is generally prohibited.** All write operations, fuzzing, and DoS testing must occur on lab replicas. Where production testing is unavoidable (rare), it must occur during planned outages.
4. **Identify SIS boundaries** and ensure they are air-gapped or out-of-scope.
5. **Have emergency contacts** for facility safety officer, shift supervisor, and incident response.

### Safety Impact Classification

| Classification | Description | Fieldbus Example | Allowed Environment |
|----------------|-------------|------------------|---------------------|
| **Informational** | Read-only, passive | Sniff GOOSE, read DNP3 points | Production (authorized) |
| **Low Impact** | Active enumeration, read ops | plcscan, nmap NSE ICS scripts | Production (operator aware) or Lab |
| **Medium Impact** | Write operations on non-critical points | Write unused register, write to spare DO | Lab Only |
| **High Impact** | Write operations on process points | Modify setpoint, command breaker, BACnet WriteProperty | Lab with process replica |
| **Critical Impact** | Disrupt real-time cycle, modify SIS | Inject GOOSE, fuzz IEC 104, MITM PROFINET IRT | Lab with safety officer present |

### Operational Constraints

- **Never disrupt real-time cycles** — PROFINET IRT, EtherCAT, GOOSE operate on sub-millisecond cycles. Any introduced latency can cause faults.
- **Respect polling intervals** — DNP3 and IEC 104 masters poll every 1-5 seconds. Injected traffic must fit between polls.
- **Multicast traffic requires care** — GOOSE and PROFINET multicast floods can saturate switch buffers and crash uninvolved devices.
- **Serial protocols have no network control** — Profibus DP, IEC 60870-5-101, HART, Foundation Fieldbus H1 are serial. There is no network-layer filtering — the only defense is physical access control.
- **HART loops carry process current** — HART modulation rides on 4-20mA current loops that represent process values. A malformed HART command may also change loop current, triggering process alarms.

### Emergency Procedures

If an unexpected process response occurs during testing:

1. **Halt all testing** — Kill scan tools, fuzzers, MITM daemons immediately.
2. **Notify the control room operator** in person or by phone (not email).
3. **Provide the exact operation that triggered the response** — protocol, command, target device, timestamp.
4. **Do not attempt remediation** — Let operators handle recovery. Tester interference can worsen outcomes.
5. **Preserve forensic evidence** — Capture pcap files, tool logs, and timestamps for post-incident review.
6. **Engage the facility safety officer** for formal incident review before resuming any work.

---

## Lab Environment

Building a fieldbus test lab is non-trivial because the protocols require specialized hardware. The recommended lab stack combines software simulators with optional hardware taps:

### Software Simulators

| Tool | Protocols | Purpose |
|------|-----------|---------|
| **OpenDNP3** | DNP3 | Reference DNP3 master and outstation |
| **lib60870** | IEC 60870-5-101, IEC 60870-5-104 | MZ Automation reference stack |
| **libiec61850** | IEC 61850 (MMS, GOOSE, SV) | Reference IED implementation |
| **PLCsim** | S7comm, Modbus TCP | Siemens PLC emulator (TIA Portal) |
| **Conpot** | Modbus, S7comm, IEC 104, IPMI | Honeypot that doubles as test target |
| **Recondog** | BACnet | BACnet device emulator |
| **OpENer** | EtherNet/IP, CIP | Open-source EtherNet/IP stack |
| **Softing syGate** | PROFINET, EtherCAT, OPC UA | Commercial simulators with free eval |

### Hardware (Optional)

- **ProfiShark tap** — Capture PROFIBUS DP/PA and PROFINET
- **HART modem** (USB) — Send/receive HART FSK over current loops
- **CAN adapter (PCAN-USB)** — For automotive fieldbus testing (companion skill)
- **USB-to-RS-485 adapter** — For Profibus, IEC 60870-5-101, Modbus RTU
- **Beckhoff EtherCAT coupler** (EL6690) — EtherCAT test bridge
- **Triconex MP3008** (training unit) — For SIS testing (Triton research)

### Lab Setup Script (Reference)

```bash
# Install core fieldbus tooling on Kali
sudo apt update
sudo apt install -y wireshark tshark nmap python3-pip build-essential cmake git

# Python tooling
pip3 install scapy boofuzz python-snappy pyserial

# OpenDNP3 from source
git clone https://github.com/dnp3/opendnp3.git
cd opendnp3 && mkdir build && cd build
cmake -DDNP3_TESTS=OFF -DDNP3_EXAMPLES=ON ..
make -j$(nproc) && sudo make install

# lib60870 (MZ Automation) - reference IEC 60870-5-101/104
git clone https://github.com/mz-automation/lib60870.git
cd lib60870 && mkdir build && cd build
cmake .. -DBUILD_EXAMPLES=ON
make -j$(nproc) && sudo make install

# libiec61850 - IEC 61850 reference stack
git clone https://github.com/mz-automation/libiec61850.git
cd libiec61850 && mkdir build && cd build
cmake .. -DBUILD_EXAMPLES=ON
make -j$(nproc) && sudo make install

# conpot ICS honeypot
pip3 install conpot

# Verify installations
opendnp3-demo-master --help
iec104_demo_server --help
```

---

## Common Pitfalls

1. **Treating OT Like IT** — Standard IT pentest tools (Nessus, Burp, Metasploit) can crash ICS devices. Aggressive port scanning has caused PLC faults and process shutdowns. Use ICS-specific tools with conservative timing.

2. **Assuming Protocol Authentication** — DNP3, IEC 104, GOOSE, BACnet, PROFINET, EtherCAT, and Foundation Fieldbus all lack authentication by default. Do not assume the existence of access controls just because devices respond.

3. **Ignoring Serial Protocols** — Many fieldbus protocols (Profibus DP/PA, IEC 60870-5-101, HART, FF H1, Modbus RTU) are serial. TCP-based scanning misses these entirely. Physical access to terminal servers and protocol gateways is required.

4. **Multicast Negligence** — GOOSE, PROFINET, and EtherCAT use Layer-2 multicast. A poorly configured tap can flood multicast back into the network, causing device crashes. Use one-way taps or span ports configured for ingress-only.

5. **Overlooking Safety Instrumented Systems** — SIS components (Triconex, HIMA, ICS Triplex) must be explicitly excluded from testing scope. Triton/Trisis demonstrated that SIS attacks are possible and potentially catastrophic.

6. **Confusing Vendor Implementations** — "DNP3" varies between Siemens, Schweitzer, ABB, GE, and Motorola implementations. Generic tools may not parse vendor-specific extensions. Test against the actual vendor stack when possible.

7. **Forgetting Time Synchronization** — IEC 61850 Sampled Values (SV) and GOOSE rely on precise time sync via PTP (IEEE 1588). Disrupting PTP can cause SV/GOOSE faults. Many fieldbus attacks operate by disrupting timing infrastructure.

8. **Disregarding Physical Layer Hazards** — Profibus PA and Foundation Fieldbus H1 run on intrinsically-safe segments in hazardous areas (Zone 0/1/2). Test equipment must be rated for the zone. Standard Ethernet taps can ignite explosive atmospheres.

9. **Neglecting Engineering Workstations** — The EWS is often the pivot point between IT and OT. It contains PLC programs, HMI projects, and protocol gateway credentials. Compromising an EWS grants attacker the same protocol access as a legitimate engineer.

10. **Underestimating Long Lifecycles** — A fieldbus device deployed in 2005 may still be in service in 2030. The vendor may no longer exist. Patches are unavailable. Document these as residual risks, not as actionable findings.

---

## Reference: Protocol Quick Reference Table

| Protocol | Industry | Port/Media | Auth | Encryption | Real-Time | Common Vendors |
|----------|----------|-----------|------|------------|-----------|----------------|
| Modbus TCP | Generic ICS | TCP 502 | None | None | No | Schneider, Siemens, AB |
| Modbus RTU | Generic ICS | RS-485 serial | None | None | No | All |
| S7comm | Discrete mfg | TCP 102 | Optional password | None | No | Siemens |
| DNP3 | Power, water | TCP/UDP 20000 | SAv2-5 optional | SAv5 only | No | GE, Schweitzer, ABB |
| IEC 60870-5-101 | Power (serial) | RS-232/485 | None | None | No | Multiple |
| IEC 60870-5-104 | Power (TCP) | TCP 2404 | None | None | No | Multiple |
| IEC 61850 GOOSE | Substations | Ethertype 0x88B8 | None | None (opt IEC 62351) | <4ms | ABB, Siemens, SEL |
| IEC 61850 SV | Substations | Ethertype 0x88BA | None | None | <4ms | ABB, Siemens, SEL |
| IEC 61850 MMS | Substations | TCP 102 | X.509 optional | TLS optional | No | ABB, Siemens, SEL |
| ICCP/TASE.2 | Power inter-utility | TCP 102 | Optional | Optional | No | Multiple |
| PROFINET RT | Discrete mfg | UDP 34962-34964 + L2 | None | None | <1ms | Siemens, Phoenix |
| PROFINET IRT | Discrete mfg | L2 reserved | None | None | <1ms | Siemens |
| Profibus DP | Discrete mfg | RS-485 | None | None | No | Siemens, Phoenix |
| Profibus PA | Process | MBP (31.25 kbps) | None | None | No | Siemens, Emerson |
| EtherCAT | Discrete mfg | Ethertype 0x88A4 | None | None | <100us | Beckhoff |
| EtherNet/IP | Generic ICS | TCP 44818 / UDP 2222 | None (CIP Security opt) | CIP Security opt | No | AB, Rockwell, Omron |
| Foundation FF H1 | Process | 31.25 kbps MBP | None | None | No | Emerson, Yokogawa |
| Foundation FF HSE | Process | TCP/IP | None | None | No | Emerson, Yokogawa |
| HART | Process | 4-20mA FSK | None | None | No | Rosemount, Endress |
| WirelessHART | Process | IEEE 802.15.4 | AES-128 | Yes | No | Emerson, Pepperl+Fuchs |
| ISA100 Wireless | Process | IEEE 802.15.4 | AES-128 | Yes | No | Yokogawa, Honeywell |
| CC-Link | Discrete mfg | RS-485 / Ethernet | None | None | No | Mitsubishi |
| CC-Link IE TSN | Discrete mfg | Ethernet TSN | Optional | Optional | <1ms | Mitsubishi |
| BACnet/IPv4 | Buildings | UDP 47808 | None | None | No | Honeywell, JCI, Schneider |
| BACnet/SC | Buildings | TCP | X.509 | TLS | No | Emerging |
| ICCP / TASE.2 | Power inter-utility | TCP 102 | Optional | TLS optional | No | Multiple |
| OPC UA | Cross-industry | TCP 4840 | X.509 + user | TLS + message | No | Cross-vendor |

---

## Cross-Reference to Related Skills

| Related Skill | Relationship | When to Use Both |
|---------------|--------------|------------------|
| `scada-ics-security` | Parent skill covering Modbus/S7comm basic | Use parent for general ICS, this skill for non-Modbus protocols |
| `automotive-vehicle-security` | CAN/LIN/FlexRay/MOST fieldbuses | Use for in-vehicle networks, plant-side vehicles |
| `network-tunneling-proxy` | Pivot tunnels into OT zones | Use to maintain foothold across segmented OT |
| `privilege-escalation` | Gaining EWS/PLC engineer privileges | Use to escalate to engineering workstation access |
| `digital-forensics` | Post-incident OT forensics | Use for incident response on fieldbus devices |
| `deception-honeypot` | Conpot deployment methodology | Use for decoy ICS deployments |
| `anti-forensics` | (Defensive) Understanding attacker cleanup | Use for red team cleanup awareness only |

---

## Attribution and References

This skill draws on publicly available research, vendor documentation, and ICS-CERT advisories. Key references include:

- **IEC 62443** series — Industrial communication networks security
- **ISA-99** — Industrial Automation and Control Systems Security
- **NIST SP 800-82** — Guide to Industrial Control Systems Security
- **DHS CISA ICS-CERT** advisories
- **Dragos** ICS threat intelligence reports
- **Claroty**, **Nozomi**, **Tenable.ot** research blogs
- **SANS ICS** Summit presentations
- **SCADA StrangeLove** research team publications
- **Moscow-based Positive Technologies** ICS research (公开发表/publications)

All command examples are intended for authorized lab environments only.
