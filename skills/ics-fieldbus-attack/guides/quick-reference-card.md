# ICS Fieldbus Quick Reference Card

> Pocket-sized lookup for fieldbus protocol identification, function codes, ASDU type IDs, top ICS CVEs, and the response playbook for a suspected ICS intrusion.
>
> **Objective**: Provide a single page that an operator or pentester can keep on the wall / in the bag for instant lookup during an engagement or incident.
>
> **Audience**: ICS penetration testers, OT SOC analysts, control system engineers, incident responders.

## Overview

Fieldbus protocols are dense. A Modbus TCP function code 0x10 means nothing on first sight; neither does IEC 104 ASDU type 0x2d, or DNP3 object group 30 variation 6. This card compresses the most-used lookup tables so you do not need to grep through Wireshark dissectors or vendor manuals in the heat of an engagement.

Cite this card alongside `skills/ics-fieldbus-attack/payloads.md` (raw payloads) and `skills/ics-fieldbus-attack/guides/real-world-incident-case-studies.md` (incident context).

---

## 1. Fieldbus Protocol Quick-ID — Port / EtherType / Layer

| Protocol | Transport | Port / EtherType | Wireshark Dissector | Typical Layer |
|----------|-----------|------------------|---------------------|---------------|
| **Modbus TCP** | TCP | 502 | `modbus` | L4 (TCP) |
| **Modbus RTU** | Serial (RS-232/485) | — | `modbus_rtu` | L1/L2 |
| **S7comm (legacy)** | ISO-on-TCP | 102 | `s7comm` | L4 |
| **S7comm-Plus** | TCP | 102 | `s7comm-plus` | L4 |
| **PROFINET RT** | Ethernet | EtherType 0x8892 | `pn_rt` | L2 |
| **PROFINET IRT** | Ethernet | EtherType 0x8892 | `pn_irt` | L2 (TDMA) |
| **Profibus DP/PA** | Serial (RS-485 / MBP) | — | `profibus` | L1/L2 |
| **DNP3 LAN/WAN** | TCP/UDP | 20000 | `dnp3` | L4 |
| **DNP3 Serial** | Serial | — | `dnp3` | L1/L2 |
| **IEC 60870-5-104** | TCP | 2404 | `iec60870_104` | L4 |
| **IEC 60870-5-101 Serial** | Serial | — | `iec60870_asdu` | L1/L2 |
| **IEC 61850 MMS** | TCP | 102 (OSI stack) | `mms` | L4+ |
| **IEC 61850 GOOSE** | Ethernet | EtherType 0x88B8 | `goose` | L2 |
| **IEC 61850 SV** | Ethernet | EtherType 0x88BA | `sv` | L2 |
| **EtherNet/IP** | TCP/UDP | 44818 | `enip` | L4 |
| **CIP** | TCP | 2222 (Class 1) | `cip` | L4 |
| **EtherCAT** | Ethernet | EtherType 0x88A4 | `ecat` | L2 |
| **BACnet/IP** | UDP | 47808 (0xBAC0) | `bacapp` / `bacnet` | L4 |
| **OPC UA Binary** | TCP | 4840 | `opcua` | L4 |
| **OPC DA (DCOM)** | TCP | 135 + 1025-5000 | (custom) | L4 |
| **CC-Link IE** | Ethernet | EtherType 0x88E1 | `cclink_ie` | L2 |
| **HART-IP** | UDP/TCP | 5094 | `hartip` | L4 |
| **Foundation Fieldbus H1** | Serial (MBP) | — | `ff` | L1/L2 |
| **Foundation Fieldbus HSE** | TCP | 1089-1091 | `ff_hse` | L4 |
| **TriStation** | UDP | 1500 | (proprietary dissector) | L4 |
| **Sysmac (Omron)** | TCP | 9600 / 44818 | (custom) | L4 |
| **Unitronics UniStream** | TCP | 20256 | (custom) | L4 |

### Quick Capture Filter Cheat Sheet

```bash
# Common ICS protocols capture filter (tcpdump syntax)
sudo tcpdump -i eth0 -w ics.pcap \
  "port 502 or port 102 or port 2404 or port 44818 or port 4840 or \
   port 20000 or port 47808 or \
   ether proto 0x88b8 or ether proto 0x88ba or \
   ether proto 0x8892 or ether proto 0x88a4 or ether proto 0x88e1"
```

---

## 2. Modbus TCP Function Codes Cheatsheet

| FC (hex) | Function | Read/Write | Notes |
|----------|----------|------------|-------|
| 0x01 | Read Coils | R | 1-bit; e.g., relay state |
| 0x02 | Read Discrete Inputs | R | 1-bit; read-only |
| 0x03 | Read Holding Registers | R | 16-bit; common target |
| 0x04 | Read Input Registers | R | 16-bit; read-only |
| 0x05 | Write Single Coil | W | 1-bit |
| 0x06 | Write Single Register | W | 16-bit |
| 0x07 | Read Exception Status | R | legacy diagnostic |
| 0x08 | Diagnostics | R/W | sub-function 0x00 = echo |
| 0x0B | Get Comm Event Counter | R | |
| 0x0C | Get Comm Event Log | R | |
| 0x0F | Write Multiple Coils | W | bulk 1-bit |
| 0x10 | Write Multiple Registers | W | bulk 16-bit |
| 0x11 | Report Server ID | R | vendor fingerprint |
| 0x14 | Read File Record | R | file-based addressing |
| 0x15 | Write File Record | W | file-based addressing |
| 0x16 | Mask Write Register | W | masked bit ops |
| 0x17 | Read/Write Multiple Registers | R/W | atomic R+W |
| 0x18 | Read FIFO Queue | R | FIFO access |
| 0x2B | Encapsulated Interface Transport | R/W | sub-function 0x0E = CANopen; 0x0D = identity |
| 0x41..0x48 | Schneider UMAS (vendor) | R/W | project management; not public |
| 0x5A..0x5F | Vendor extensions | R/W | varies |

### Modbus Exception Codes

| EC (hex) | Meaning | Diagnostic Hint |
|----------|---------|-----------------|
| 0x01 | Illegal Function | PLC doesn't support FC |
| 0x02 | Illegal Data Address | Register doesn't exist |
| 0x03 | Illegal Data Value | Value out of range |
| 0x04 | Server Device Failure | PLC internal fault |
| 0x05 | Acknowledge | Operation in progress |
| 0x06 | Server Device Busy | Try again later |
| 0x08 | Memory Parity Error | Hardware fault |
| 0x0A | Gateway Path Unavailable | Network issue |
| 0x0B | Gateway Target No Response | Downstream device failure |

---

## 3. DNP3 Object Group Reference

| Group | Variation | Type | Description |
|-------|-----------|------|-------------|
| 1 | 1-2 | Binary Input | Single bit (status), with flags |
| 2 | 1 | Binary Input Change | Event, no time |
| 3 | 1-2 | Binary Input Change | Event, with time |
| 10 | 1-2 | Binary Output | Status (single bit) |
| 12 | 1-3 | Binary Output Command | Control Block (single/double/pulse) |
| 13 | 1 | Binary Output Command Event | Result of command |
| 20 | 1-2 | Counter | 32-bit / 16-bit counter |
| 21 | 1-6 | Counter Change Event | Various widths |
| 22 | 1-2 | Binary Output Event | Status change |
| 30 | 1-6 | Analog Input | 32-bit / 16-bit, with flags |
| 32 | 1-5 | Analog Input Change | Various widths / with time |
| 40 | 1-4 | Analog Output Status | 32-bit / 16-bit |
| 41 | 1-4 | Analog Output Block | Command (setpoint) |
| 50 | 1-4 | Time and Date | Absolute / indexed |
| 51 | 1-3 | Time and Date CTO | Common Time Offset |
| 60 | 1-4 | Class Objects | Class 0/1/2/3 data |
| 70 | 1-6 | File Transport | Block / format spec |
| 80 | 1 | Internal Indications | BIT-string flags |
| 82 | 1 | Device Attributes | Vendor, model, firmware |
| 110 | 0-1 | Octet String Status | Variable-length |
| 111 | 0-1 | Octet String Event | Variable-length |
| 112 | 0-1 | Octet String Command | Variable-length |

### DNP3 Application Function Codes

| FC | Name | Direction |
|----|------|-----------|
| 0 | Confirm | Outstation → Master |
| 1 | Read | Master → Outstation |
| 2 | Write | Master → Outstation |
| 3 | Select | Master → Outstation (pre-write for binary output) |
| 4 | Operate | Master → Outstation (execute selected) |
| 5 | Direct Operate | Master → Outstation (select+operate combined) |
| 6 | Direct Operate No Ack | Master → Outstation (no confirmation) |
| 7 | Immediate Freeze | Master → Outstation |
| 8 | Immediate Freeze No Ack | Master → Outstation |
| 9 | Freeze and Clear | Master → Outstation |
| 10 | Freeze and Clear No Ack | Master → Outstation |
| 13 | Cold Restart | Master → Outstation |
| 14 | Warm Restart | Master → Outstation |
| 20 | Enable Unsolicited | Master → Outstation |
| 21 | Disable Unsolicited | Master → Outstation |
| 22 | Assign Class | Master → Outstation |
| 23 | Delay Measurement | Master → Outstation |
| 24 | Record Current Time | Master → Outstation |
| 129 | Response | Outstation → Master |
| 130 | Unsolicited Response | Outstation → Master |

---

## 4. IEC 60870-5-104 ASDU Type IDs

### Single-letter prefixes: **T**ype, **S**ingle bit, **C**ommand

| Type ID (hex) | Name | Direction | Description |
|---------------|------|-----------|-------------|
| 0x01 | M_SP_NA_1 | M→S | Single-point information |
| 0x02 | M_SP_TA_1 | M→S | Single-point with time tag |
| 0x03 | M_DP_NA_1 | M→S | Double-point information |
| 0x04 | M_DP_TA_1 | M→S | Double-point with time tag |
| 0x05 | M_ST_NA_1 | M→S | Step position information |
| 0x07 | M_BO_NA_1 | M→S | Bitstring (32 bit) |
| 0x09 | M_ME_NA_1 | M→S | Measured value, normalized |
| 0x0B | M_ME_NB_1 | M→S | Measured value, scaled |
| 0x0D | M_ME_NC_1 | M→S | Measured value, short floating point |
| 0x0F | M_IT_NA_1 | M→S | Integrated totals (counter) |
| 0x15 | M_EP_TA_1 | M→S | Protection event with time tag |
| 0x1E | M_EE_NA_1 | M→S | Packed events |
| 0x2D (45) | **C_SC_NA_1** | S→M | **Single command** (most abused) |
| 0x2E (46) | **C_DC_NA_1** | S→M | **Double command** (breaker open/close) |
| 0x2F (47) | C_RC_NA_1 | S→M | Regulating step command |
| 0x30 (48) | C_SE_NA_1 | S→M | Setpoint command, normalized |
| 0x31 (49) | C_SE_NB_1 | S→M | Setpoint command, scaled |
| 0x32 (50) | C_SE_NC_1 | S→M | Setpoint command, short float |
| 0x64 (100) | C_IC_NA_1 | S→M | Interrogation command |
| 0x65 (101) | C_CI_NA_1 | S→M | Counter interrogation command |
| 0x66 (102) | C_RD_NA_1 | S→M | Read command |
| 0x67 (103) | C_CS_NA_1 | S→M | Clock synchronization command |
| 0x68 (104) | C_TS_NA_1 | S→M | Test command |
| 0x69 (105) | C_RP_NA_1 | S→M | Reset process command |
| 0x6A (106) | C_CD_NA_1 | S→M | Delay acquisition command |
| 0x70 (112) | F_FR_NA_1 | S→M | File ready |
| 0x71 (113) | F_SR_NA_1 | S→M | Section ready |
| 0x72 (114) | F_SC_NA_1 | S→M | Call / select file |

### IEC 104 APCI Control Field

| Byte offset | Field | Meaning |
|-------------|-------|---------|
| 0 | Start | Always 0x68 |
| 1 | Length | APDU length |
| 2-3 | Control field 1-2 | I/S/U format selector |
| 4-5 | Control field 3-4 | TX/RX counters (I-format); function (U-format) |

**U-format functions**: 0x07 0x00 = STARTDT act; 0x0B 0x00 = STOPDT act; 0x13 0x00 = TESTFR act.

---

## 5. Profinet IO Device Class Hierarchy

| Class | Role | Layer | Notes |
|-------|------|-------|-------|
| **IO Controller** | Master | L4 | Typically PLC (Siemens S7, Allen-Bradley) |
| **IO Device** | Slave | L4 | Field device (valve, drive, I/O block) |
| **IO Supervisor** | Engineering | L4 | Programming tool, monitoring |
| **PNIO MRP** | Media redundancy | L2 | 200ms ring recovery |
| **PNIO MIB** | Management info base | L4 | SNMP-like for PN |

### PROFINET GSD Files

Each PROFINET device ships with a **GSDML** XML file describing its modules, submodules, and diagnostics. Located at vendor's website or extracted from engineering tool. During pentest, collect GSDML files to identify expected modules per device.

### PROFINET Discovery (LLDP + MRP)

```bash
# Discover PROFINET devices on a link via LLDP
tcpdump -i eth0 -e ether proto 0x88cc -nn -vv

# MRP (Media Redundancy) traffic
tcpdump -i eth0 ether proto 0x88e3 -nn
```

---

## 6. IEC 61850 Logical Node (LN) Classes

| LN Prefix | Domain | Examples |
|-----------|--------|----------|
| **GGIO** | Generic Process I/O | GGIO1 (8 inputs/outputs), GGIO2 |
| **PTOC** | Time Overcurrent | PTOC1, PTOC2 (instantaneous, timed) |
| **PTTR** | Transformer Thermal | PTTR1 (transformer protection) |
| **PTUV** | Undervoltage | PTUV1 (27 function) |
| **PTOV** | Overvoltage | PTOV1 (59 function) |
| **PDIS** | Distance Protection | PDIS1 (21 function) |
| **PSCH** | Protection Scheme | PSCH1 (interlocking) |
| **XCBR** | Circuit Breaker | XCBR1, XCBR2 (each breaker) |
| **XSWI** | Switch / Disconnector | XSWI1, XSWI2 |
| **TCTR** | Current Transformer | TCTR1, TCTR2 |
| **TVTR** | Voltage Transformer | TVTR1 |
| **MMXU** | Measurement Unit | MMXU1 (3-phase voltage, current, power) |
| **MMTN** | Measurement Total | MMTN1 (totals) |
| **CSWI** | Control Switch | CSWI1 (controllable switch) |
| **CILO** | Interlocking | CILO1 |
| **CALH** | Alarm Handling | CALH1 |
| **RDRE** | Disturbance Recorder | RDRE1 |
| **RBRF** | Breaker Failure | RBRF1 |
| **RPSB** | Protection Signal Blocking | RPSB1 |

### IEC 61850 Services

| Service | Purpose | Notes |
|---------|---------|-------|
| **Associate** | Open MMS session | ACSI / MMS / OSI |
| **GetServerDirectory** | List LDs | LD = Logical Device |
| **GetLogicalDeviceDirectory** | List LNs | LN = Logical Node |
| **GetDataValues (Read)** | Read attributes | per-attribute |
| **SetDataValues (Write)** | Write attributes | per-attribute; **abuse vector** |
| **GetDataDirectory** | List data objects | structure discovery |
| **Report** | Spontaneous event | IEC 61850 reporting |
| **GOOSE** | Layer-2 fast message | <4ms; **abuse vector for injection** |
| **Sampled Values (SV)** | IEC 61850-9-2 LE | current/voltage samples |
| **Control (Operate)** | Device control | SBOw (select-before-operate) |

---

## 7. Top 10 ICS CVEs (2020-2026)

| CVE | Vendor / Product | CVSS | Description | Fieldbus Pentest Check |
|-----|------------------|------|-------------|-------------------------|
| **CVE-2022-26261** | Hitachi ABB NuCa / LM P600 | 9.8 | Hardcoded credentials | Verify default account login |
| **CVE-2021-3560** | Polkit (used in OT jump hosts) | 7.8 | Privilege escalation | Check Linux OS on jump hosts |
| **CVE-2021-38751** | Allen-Bradley CompactLogix 5380 | 9.0 | CRLF injection in web UI | Check firmware version |
| **CVE-2022-24795** | Moxa NPort 5110 | 9.8 | Hardcoded telnet password | `telnet <ip>; login: root/moxa` |
| **CVE-2023-21339** | Siemens Siprotec 5 | 9.9 | Buffer overflow in IEC 104 server | Crash test in lab only |
| **CVE-2022-43308** | B&R Automation Power Panel | 9.8 | Code injection | Verify web interface |
| **CVE-2023-29439** | Codesys Control V3 | 9.0 | Authentication bypass | Verify Codesys V3 server |
| **CVE-2023-45852** | Kamstrup Modbus TCP | 9.8 | Hardcoded service credentials | Read register 0x0000-0x0030 |
| **CVE-2024-23383** | Siemens SIMATIC S7-1500 | 9.0 | Memory corruption in PROFINET | Firmware < V3.1 |
| **CVE-2024-3400** | Palo Alto PAN-OS (jump host) | 10.0 | Command injection in web | Verify PAN-OS version |

> **Note**: This list is a snapshot. Subscribe to **CISA ICS-CVE feed** and **vendor security advisories** for ongoing updates. The pentester's job is to map CVE to device inventory before the attacker does.

---

## 8. MITRE ATT&CK for ICS Matrix (Condensed)

### Tactics (left to right = attacker kill chain)

1. **Initial Access** — T0859 Valid Accounts, T0817 Drive-by Compromise, T0811 Exploitation for Defense Evasion
2. **Execution** — T0871 Execution through API, T0853 Block Reporting to Log, T0866 Exploitation of Remote Services
3. **Persistence** — T0859 Valid Accounts, T0858 Modify Program
4. **Privilege Escalation** — T0890 Exploitation for Privilege Escalation
5. **Evasion** — T0807 Command-Line Interface, T0853 Block Reporting to Log, T0806 Standard Application Layer Protocol
6. **Discovery** — T0808 Control System Identification, T0886 Remote System Information Discovery
7. **Lateral Movement** — T0816 Exploitation of Remote Services, T0866 Lateral Tool Transfer
8. **Collection** — T0802 Automated Collection, T0813 Engineering Workstation Compromise
9. **Command and Control** — T0830 Data Obfuscation, T0864 Commonly Used Port
10. **Inhibit Response Function** — T0853 Block Reporting to Log, T0878 Alarm Suppression
11. **Impact** — T0831 Manipulation of Control, T0858 Modify Program, T0892 Attack Process I/O, T0836 Modify Program

### Key Techniques for Fieldbus Pentesters

| Technique | How to Test |
|-----------|-------------|
| **T0858 Modify Program** | Upload modified PLC block (lab only); verify detection |
| **T0888 Control System Interaction** | Send protocol commands; verify operator sees alert |
| **T0892 Attack Process I/O** | Write analog setpoint; observe process variable change |
| **T0808 Control System Identification** | Read device attributes via protocol; verify passive detection |
| **T0853 Block Reporting to Log** | Stop logging on outstation; verify SOC sees log loss |
| **T0816 Lateral Tool Transfer** | Move malware between OT hosts; verify EDR detection |

---

## 9. Response Playbook — Suspected ICS Intrusion (5 Steps)

### Step 1: Verify and Triage (0-15 min)

- [ ] Confirm the alert is not a false positive (verify with second source: HMI, NTA, log)
- [ ] Identify scope: which devices / protocols / hosts are involved?
- [ ] Contact on-call IR lead; activate IR plan
- [ ] Notify operations team — operator must be informed of any investigation activity
- [ ] Document everything in IR ticket: timestamp, observed IOCs, hypotheses

### Step 2: Contain Without Breaking the Process (15-60 min)

- [ ] **Do NOT disconnect PLCs from network without operator approval** — abrupt loss of control can cause physical harm
- [ ] Identify which communication paths are involved; segment via firewall rules (block at OT LAN switch)
- [ ] Disable compromised accounts; reset credentials for adjacent accounts
- [ ] Capture full PCAP from affected segment (mirror port + tcpdump)
- [ ] Image affected hosts (memory + disk) for forensics

### Step 3: Eradicate (Hours-Days)

- [ ] Identify root cause: initial access vector (phishing? VPN? default cred? supply chain?)
- [ ] Patch affected devices (firmware updates; vendor advisory)
- [ ] Rotate ALL passwords on affected OT segment (engineering accounts, project passwords, default creds)
- [ ] Remove attacker artifacts: malicious PLC blocks, trojanized engineering tools, web shells
- [ ] Verify integrity: golden image compare for PLC blocks; firmware attestation

### Step 4: Recover (Days-Weeks)

- [ ] Restore from known-clean backups; verify before deploying
- [ ] Re-deploy modified detection rules (lesson learned)
- [ ] Increase monitoring on affected segment for 30+ days (attacker may return)
- [ ] Operator-driven restart sequence: verify each loop, each interlock, each SIS
- [ ] Resume normal operations only after operator sign-off

### Step 5: Post-Incident (Weeks-Months)

- [ ] Within 72 hours: report to CISA (per TSA Security Directive if applicable)
- [ ] Within 7 days: internal post-incident review (blameless)
- [ ] Within 30 days: external IR firm review (Mandiant, Dragos IR)
- [ ] Within 90 days: implement top 5 corrective actions
- [ ] Within 180 days: full tabletop exercise simulating same incident
- [ ] Update threat model with new attacker capabilities observed

---

## References

- **MITRE ATT&CK for ICS**: https://attack.mitre.org/techniques/ics/
- **CISA ICS Advisories**: https://www.cisa.gov/news-events/cybersecurity-advisories
- **Dragos ICS Threat Intelligence**: https://www.dragos.com/year-in-review/
- **Mandiant ICS Reports**: https://www.mandiant.com/resources/ics-cybersecurity
- **Nozomi Networks Labs**: https://www.nozominetworks.com/labs
- **Schneider Security Advisories**: https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.page
- **Siemens ProductCERT**: https://cert-portal.siemens.com/
- **ABB Cyber Security**: https://global.abb/group/en/technology/cyber-security/alerts-and-notifications
- **Rockwell Automation Security**: https://rockwellautomation.custhelp.com/app/answers/answerview/a_id/1099014

---

## See Also

- `../SKILL.md` — skill definition and methodology
- `../payloads.md` — full attack payloads by protocol
- `../test-cases.md` — structured test case templates
- `./ics-fieldbus-attack-playbook.md` — full methodology and protocol-specific attack chains
- `./real-world-incident-case-studies.md` — 10 landmark ICS incident case studies with MITRE ATT&CK for ICS mappings
