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
  guide_count: 3
  mitre: "TA0100-ICS Attack"
---


# SCADA/ICS Security Assessment

> **Supplementary Files**:
> - `payloads.md` — Protocol-specific attack payloads: Modbus, S7comm, EtherNet/IP, OPC UA, and ICS network scanning
> - `test-cases.md` — Structured test cases for PLC enumeration, register manipulation, fingerprinting, and honeypot deployment
> - `guides/ics-protocol-recon.md` — ICS protocol reconnaissance and enumeration deep dive
> - `guides/modbus-s7comm-attack.md` — Modbus and S7comm attack techniques
> - `guides/ics-network-assessment.md` — ICS network security assessment methodology

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

## Common Pitfalls

1. **Testing Production Systems** — Never interact with production ICS devices. All testing must occur in isolated lab environments. A single write to the wrong register can shut down a power plant.
2. **Ignoring Safety Systems** — ICS environments have safety instrumented systems (SIS). Attacks that compromise SIS can lead to catastrophic physical consequences.
3. **Protocol Timing Sensitivity** — ICS protocols often have strict timing requirements. Aggressive scanning can cause PLC watchdog timeouts and process interruptions.
4. **Assuming IT Security Maps to OT** — Patching cycles, availability requirements, and risk models differ fundamentally between IT and OT. A 99.9% uptime SLA is unacceptable for a power grid.
5. **Neglecting Serial Connections** — Many ICS environments still use serial (RS-232/RS-485) connections. TCP-only scanning misses these attack surfaces.
6. **Overlooking Legacy Protocols** — Modbus has no built-in authentication or encryption. Do not assume protocol-level access controls exist just because devices respond.
7. **Disregarding Vendor-Specific Implementations** — Siemens S7comm, Allen-Bradley CIP, and other vendor protocols have unique quirks. Generic ICS tools may not cover all variants.
