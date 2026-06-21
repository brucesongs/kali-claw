# ICS Fieldbus Attack Playbook

> Comprehensive playbook for penetration testing industrial fieldbus protocols BEYOND Modbus TCP. Covers attack methodology, protocol-specific attack chains, real-world incidents, lab setup, and defensive guidance.
>
> **Audience**: Penetration testers, red teamers, ICS security researchers conducting authorized engagements on power utility, oil & gas, water/wastewater, and discrete manufacturing environments.
>
> **Scope**: DNP3, IEC 60870-5-101/104, IEC 61850 (GOOSE/SV/MMS), Profibus/PROFINET, EtherCAT, Foundation Fieldbus, HART, BACnet, CC-Link.

---

## Table of Contents

1. [Fieldbus Attack Methodology](#1-methodology)
2. [Protocol-Specific Attack Chains](#2-attack-chains)
3. [Real-World Incidents](#3-incidents)
4. [Lab Setup](#4-lab-setup)
5. [Defensive Guidance](#5-defense)

---

## 1. Fieldbus Attack Methodology

Fieldbus penetration testing differs from IT penetration testing in three fundamental ways:

1. **Safety overrides confidentiality** — A successful test that causes physical harm is a failure, regardless of technical findings. The tester's first duty is to do no harm.
2. **Determinism overrides security** — Real-time protocols prioritize timing over encryption. Defensive measures that add latency may be unacceptable to operations.
3. **Long lifecycles override patching** — Fieldbus devices deployed 20+ years ago remain in service. Patches may not exist; the tester's job is to identify compensating controls, not to demand patching.

### 1.1 Six-Phase Methodology

```
Phase 1: Passive Reconnaissance (Read-Only)
    ↓
Phase 2: Active Enumeration (Read-Only)
    ↓
Phase 3: Protocol Interaction (Write Operations, Lab Only)
    ↓
Phase 4: Vulnerability Assessment (CVE Matching, Fuzzing)
    ↓
Phase 5: MITM and Injection (High Impact, Lab Only with Operator)
    ↓
Phase 6: Reporting and Remediation
```

### 1.2 Pre-Engagement Requirements

Before any testing begins:

| Requirement | Description |
|-------------|-------------|
| **Written authorization** | Identifies in-scope protocols, devices, IP ranges, time windows. Explicitly excludes Safety Instrumented Systems (SIS). |
| **Asset inventory** | Operator provides list of all devices, their firmware versions, and operational role. |
| **Process Hazards Analysis (PHA)** | Tester reviews PHA to understand which process variables can cause harm. |
| **Emergency procedures** | Documented stop signal, abort procedure, contact tree. |
| **Operator presence** | Operations team member present during all active testing. |
| **Lab availability** | For any write/fuzz/DoS testing, lab replica of in-scope systems. |
| **Communication plan** | Pre-defined escalation paths; phone numbers for facility safety officer, shift supervisor, IR team. |

### 1.3 Phase 1: Passive Reconnaissance

The goal of passive reconnaissance is to map the OT environment without sending any packets. This is the safest phase and should comprise the majority of an engagement's time.

**Capture Setup**:
- Configure SPAN port or network tap on OT switch. Use one-way taps (Waterfall, Owl) for highest assurance.
- For PROFIBUS/PROFINET, use ProfiShark tap with appropriate bandwidth.
- For serial protocols (IEC 101, HART, FF H1), install serial tap inline.

**Capture Duration**: Minimum 24 hours, ideally 7 days. Fieldbus traffic is periodic; extended capture reveals:
- Daily polling patterns (e.g., DNP3 class 0 polls every 5 seconds)
- Weekly maintenance patterns (e.g., Sunday night firmware updates)
- Seasonal process changes (e.g., heating setpoints in winter vs summer)

**Protocol Identification**:
```bash
# Capture all ICS traffic
sudo tcpdump -i eth0 -w full_capture.pcap \
  "port 502 or port 102 or port 2404 or port 44818 or port 4840 or \
   port 20000 or port 47808 or \
   ether proto 0x88b8 or ether proto 0x88ba or \
   ether proto 0x8892 or ether proto 0x88a4 or ether proto 0x88e1"

# Identify protocol distribution
tshark -r full_capture.pcap -q -z io,phs
```

**Master-Slave Topology Mapping**:
```bash
# Identify polling patterns
tshark -r full_capture.pcap -Y "dnp3 || iec60870_104" -T fields \
  -e ip.src -e ip.dst -e frame.time_relative | \
  awk -F'\t' '{ts=int($3/60); pair=$1"->"$2; count[pair][ts]++} \
    END {for (p in count) for (t in count[p]) print p" min:"t": "count[p][t]" frames"}' | sort
```

**Asset Fingerprinting via Passive**:
```bash
# DNP3 device attributes
tshark -r full_capture.pcap -Y "dnp3.app.funcCode == 0" -T fields \
  -e ip.src -e dnp3.vendorName -e dnp3.deviceName -e dnp3.fwVersion

# IEC 61850 GOOSE publishers
tshark -r full_capture.pcap -Y iecgoose -T fields \
  -e eth.src -e goose.goIDref -e goose.datSet | sort -u

# BACnet vendors
tshark -r full_capture.pcap -Y "bacnet.apdu.serviceChoice == 0" -T fields \
  -e ip.src -e bacnet.vendorID | sort -u
```

### 1.4 Phase 2: Active Enumeration

Active enumeration sends packets to in-scope devices. Use conservative timing:

```bash
# Conservative ICS scan
nmap -sT -p 502,102,2404,44818,4840,20000,47808 \
  --max-rate 50 --max-retries 1 --host-timeout 30m \
  -sV --version-intensity 3 \
  192.168.1.0/24
```

**Why conservative timing matters**:
- ICS devices often have small TCP stacks; aggressive scanning causes connection exhaustion
- Modbus polling cycles are 1-5 seconds; any introduced latency can cause watchdog resets
- PLCs may interpret rapid probes as attack traffic and disable their network interfaces

**Protocol-Specific Enumeration Scripts**: See `payloads.md` sections 1.1 (DNP3), 3.1 (IEC 104), 6.1 (MMS), 7.1 (PROFINET), 12.1 (BACnet) for detailed commands.

### 1.5 Phase 3: Protocol Interaction

In this phase, the tester actively sends protocol commands. **Production testing is strongly discouraged** — use lab replicas.

For each protocol, test these operations:

| Protocol | Read-Only (Production OK with Operator) | Write Operations (Lab Only) |
|----------|------------------------------------------|------------------------------|
| DNP3 | Class 0/1/2/3 reads, Device Attributes | Direct Operate (FC 5), Setpoint |
| IEC 104 | Interrogation (Type 100), Type 1/13 reads | Single Command (Type 45), Setpoint |
| IEC 61850 MMS | GetNameList, GetDataValues | SetDataValues on control object |
| IEC 61850 GOOSE | (Passive only — no read concept) | Inject with elevated stNum |
| BACnet | ReadProperty, ReadPropertyMultiple | WriteProperty, ReinitializeDevice |
| PROFINET | DCP Identify | DCP Set (rename), RT injection |
| EtherCAT | Mailbox SDO Info Upload | SDO Download (write) |
| HART | Universal commands 0-3, 11-13 | Device-specific writes |
| Foundation FF H1 | (Passive only) | LAS spoof (specialized) |

### 1.6 Phase 4: Vulnerability Assessment

**CVE Cross-Reference**:

```bash
# Extract firmware versions
nmap -p 20000 --script dnp3-info 192.168.1.0/24 | grep -i firmware

# Cross-reference against NVD
# https://nvd.nist.gov/vuln/search/results?query=DNP3
# https://nvd.nist.gov/vuln/search/results?query=IEC+61850
# https://nvd.nist.gov/vuln/search/results?query=PROFINET

# Common vulnerable vendors and products to research:
# - Schweitzer Engineering Laboratories (SEL) RTUs
# - Siemens SIPROTEC protective relays
# - ABB RELION IEDs
# - GE Multilin UR series
# - Rockwell Allen-Bradley ControlLogix
# - Schneider Electric Modicon M340/M580
# - Beckhoff TwinCAT / EtherCAT terminals
# - Phoenix Contact FL SWITCH industrial switches
# - Triangle MicroWorks DNP3 stack (widely licensed)
```

**Protocol Fuzzing**:

Fuzzing fieldbus devices requires care:
- Run fuzzer on isolated network segment
- Monitor device with ping + serial console
- Have power switch accessible
- Stop fuzzer immediately on device crash

See `payloads.md` section 18 for Boofuzz templates per protocol.

### 1.7 Phase 5: MITM and Injection

**WARNING**: This phase causes the highest impact. Run only in lab replicas with safety officer present.

**MITM Positioning**:
```bash
# ARP poison master/slave pair
sudo bettercap -iface eth0
set arp.spoof.targets 192.168.1.5 192.168.1.10
set arp.spoof.internal false
arp.spoof on

# Verify position with traceroute
traceroute 192.168.1.10
# Should show attacker as hop

# Capture all ICS traffic transiting through us
set net.sniff.filter "tcp port 20000 or tcp port 2404 or tcp port 102 or udp port 47808"
net.sniff on
```

**Injection Operations**:

Layer-2 injection (GOOSE, SV, PROFINET RT) requires:
- Raw socket capability (`CAP_NET_RAW`)
- Network interface that supports sending custom frames (most Linux interfaces work)
- Sometimes hardware timestamping (for TSN protocols)

Layer-3+ injection (DNP3, IEC 104, BACnet, MMS) requires:
- TCP session establishment
- Protocol-aware payload crafting
- Often requires custom client library (OpenDNP3, lib60870, libiec61850, bacpypes)

### 1.8 Phase 6: Reporting

Fieldbus pentest reports differ from IT reports in critical ways:

**Required Sections**:
1. Executive summary emphasizing safety implications
2. Asset inventory with vendor, model, firmware, role, location
3. Network architecture diagram (Purdue Model levels)
4. Findings sorted by ISA-99 / IEC 62443 risk score
5. Protocol-specific findings (one section per protocol)
6. Recommendations prioritized by operational impact
7. Residual risk (for unpatchable legacy systems)

**Avoid**:
- "Critical" risk ratings without safety context
- Demanding immediate patching of 24/7 systems
- Generic recommendations ("use encryption") without protocol context
- Missing physical-layer considerations (intrinsically safe, hazardous area ratings)

---

## 2. Attack Chains

This section documents complete attack chains for each protocol family. Each chain assumes initial network access (via phishing, pivot, or insider).

### 2.1 DNP3 Replay Attack Chain

**Scenario**: Attacker has access to a utility SCADA network segment and wants to replay a captured breaker command.

```
Step 1: Capture DNP3 traffic
  ├── tcpdump on OT VLAN
  ├── Wait for legitimate Direct Operate (FC 5) command
  └── Save to dnp3_capture.pcap

Step 2: Identify the target command
  ├── tshark filter: dnp3.app.funcCode == 5
  ├── Extract outstation IP, outstation index, value
  └── Note: DNP3 has no nonce/timestamp, so replay is trivial

Step 3: ARP-poison master-outstation pair
  ├── Bettercap: set arp.spoof.targets <master_ip> <outstation_ip>
  ├── Verify MITM with traceroute
  └── Continue until engagement complete

Step 4: (Optional) Mutate command value during replay
  ├── Use Scapy to rewrite outstation index or value
  ├── Forward to outstation
  └── Outstation executes as if from legitimate master

Step 5: Cleanup
  ├── Stop ARP poison
  ├── Restore ARP tables
  └── Preserve pcap for forensic evidence
```

**Mitigation**: DNP3 Secure Authentication v5 (SAv5) prevents replay by requiring a challenge-response with sequence numbers and AES-128-GCM encryption. Test for SAv5 enforcement by sending a Direct Operate without auth wrapper — if it succeeds, SAv5 is not enforced.

### 2.2 IEC 104 Command Injection Chain

**Scenario**: Attacker has TCP access to an IEC 104 RTU on port 2404.

```
Step 1: Identify RTU
  ├── nmap -p 2404 -sV <target>
  ├── Confirm IEC 104 by sending STARTDT act
  └── Verify STARTDT con response

Step 2: Interrogate (read all data)
  ├── Send I-frame with ASDU type 100 (C_IC_NA_1)
  ├── Cause of transmission = 6 (activation)
  ├── Common address = 1 (typical)
  └── Receive all single points (breakers), measured values (voltages)

Step 3: Send single command (breaker trip)
  ├── Build ASDU type 45 (C_SC_NA_1)
  ├── Cause = 6 (activation)
  ├── S/E bit = 0 (execute)
  ├── IOA = target breaker address
  └── Send via I-frame

Step 4: Verify execution
  ├── Interrogate again
  ├── Check target IOA state changed
  └── (In lab) Verify physical breaker operated
```

**Mitigation**: IEC 62351-3 (TLS) and IEC 62351-5 (security for IEC 60870-5) provide authentication and encryption. Deploy IEC 62351-compliant gateways between master and RTU.

### 2.3 IEC 61850 GOOSE Injection Chain

**Scenario**: Attacker has Layer-2 access to a substation process bus (typically via compromised engineering workstation).

```
Step 1: Capture baseline GOOSE traffic
  ├── tcpdump ether proto 0x88b8
  ├── Identify publisher MAC, APPID, dataset reference
  └── Note current stNum (typically <100)

Step 2: Craft forged GOOSE frame
  ├── Source MAC = legitimate IED MAC (spoofed)
  ├── Destination = GOOSE multicast 01-0C-CD-01-XX-XX
  ├── EtherType = 0x88B8
  ├── APPID + length + reserved (0x00000000)
  ├── PDU:
  │   ├── gocbRef = captured value
  │   ├── timeAllowedToLive = 1000ms
  │   ├── datSet = captured value
  │   ├── goID = captured value
  │   ├── t = current time
  │   ├── stNum = 99999 (force highest)
  │   ├── sqNum = 0
  │   ├── simulation = false
  │   └── dataset payload = desired (e.g., breaker closed when actually open)
  └── Send via raw socket

Step 3: Maintain override
  ├── Loop injection every 1ms
  ├── Subscribers receive forged frame, compare stNum
  ├── Forged stNum > legitimate → forged wins
  └── Subscribers act on forged state

Step 4: Trigger protection logic
  ├── Forged "breaker closed" status while actually open
  ├── Protection relay may attempt auto-reclose → fails
  ├── OR: Forged "fault detected" → false trip of healthy breaker
  └── Cascading trips cause substation isolation
```

**Mitigation**: IEC 62351-6 provides GOOSE security via group key management and HMAC. Deploy managed switches with source-MAC lockdown on GOOSE VLANs.

### 2.4 PROFINET Spoofing Chain

**Scenario**: Attacker has Layer-2 access to a PROFINET segment.

```
Step 1: DCP Identify broadcast
  ├── Send Ethertype 0x8892 multicast
  ├── Receive responses from all PROFINET devices
  └── Extract vendor, product, name, IP, MAC

Step 2: DCP Set rename attack
  ├── Target a specific device MAC
  ├── Send DCP Set to change nameOfStation
  ├── Device accepts new name
  └── PROFINET IO Controller can no longer match configured device → drop

Step 3: (Alternative) RT frame injection
  ├── Identify cyclic RT frame ID from baseline capture
  ├── Forge RT frames with same frame ID
  ├── Inject at 1ms interval (matching cycle)
  └── Slave may accept forged output commands

Step 4: IRT cycle disruption (advanced)
  ├── Capture IRT cycle on PROFINET IRT network
  ├── Inject frames outside IRT window
  ├── Cause IRT synchronization loss
  └── All slaves drop → production line stop
```

**Mitigation**: PROFINET System Redundancy (SR) with device-level authentication. Switch-level port security (MAC lockdown, 802.1X). Segment PROFINET on dedicated VLAN.

### 2.5 EtherCAT Mailbox Exploitation Chain

**Scenario**: Attacker has Layer-2 access to EtherCAT ring.

```
Step 1: Capture EtherCAT traffic
  ├── Identify master MAC, slave MACs
  ├── Note ring positions
  └── Map mailbox CoE structure

Step 2: SDO Info Upload (enumeration)
  ├── Send mailbox with SDO Info Upload Request
  ├── Target OD 0x1000 (device type)
  ├── Target OD 0x1018 (identity: vendor, product, serial, revision)
  └── Target OD 0x6000+ (vendor-specific process data)

Step 3: SDO Download (write)
  ├── Identify output OD entry (e.g., 0x6000:00)
  ├── Build SDO Download with desired value
  ├── Send mailbox frame
  └── Slave output changes

Step 4: Process manipulation
  ├── For servo: write setpoint → move to attacker-chosen position
  ├── For I/O: write digital output → trigger relay
  └── For analog output: write voltage → drive actuator
```

**Mitigation**: MACsec (802.1AE) on EtherCAT links where supported. EtherCAT Security extension (Beckhoff TF6510).

### 2.6 BACnet Object Model Attack Chain

**Scenario**: Attacker has UDP access to BACnet network (port 47808).

```
Step 1: Who-Is broadcast
  ├── Send BACnet/IP broadcast to 255.255.255.255:47808
  ├── Or targeted: subnet broadcast x.x.x.255
  └── Receive I-Am from all devices

Step 2: Enumerate device objects
  ├── ReadProperty device,100 object-list
  ├── Get array of (type, instance) tuples
  ├── For analogOutput objects, read Present_Value, Description, Units
  └── Map to physical outputs (HVAC dampers, lighting, etc.)

Step 3: WriteProperty exploitation
  ├── Target analogOutput,1 (HVAC setpoint)
  ├── WriteProperty present-value = 75.5
  ├── Verify physical output change (multimeter on 0-10V)
  └── In lab: verify HVAC goes to full heating

Step 4: Escalate
  ├── ReinitializeDevice (service 17)
  │   └── Most devices accept without auth → warm/cold restart
  ├── DeviceCommunicationControl (service 17 sub-type)
  │   └── Disable BACnet communication for N seconds → DoS
  └── TimeSynchronization (service 6)
      └── Set device time to 1970 → log corruption
```

**Mitigation**: BACnet/SC (Secure Connect) with TLS + X.509. Where BACnet/SC not available, segment BACnet on isolated VLAN with firewall.

---

## 3. Incidents

Real-world ICS incidents provide lessons learned for both offense and defense. This section documents four landmark attacks on industrial protocols.

### 3.1 Ukraine 2015: BlackEnergy

**Date**: December 23, 2015
**Target**: Prykarpattya Oblenergo (regional power distribution utility)
**Impact**: 230,000 customers without power for 1-6 hours

**Attack Chain**:
1. **Initial Access**: Spear-phishing emails to IT staff with malicious Excel attachments containing BlackEnergy 3 malware
2. **Lateral Movement**: From IT network to SCADA network via stolen VPN credentials
3. **Reconnaissance**: Attacker observed operator screens, learned HMI operations
4. **Execution**: Used existing HMI software to operate breakers (legitimate protocol commands — no exploit)
5. **Disablement**: KillDisk wiper malware bricked workstations to prevent operator recovery
6. **Disruption**: Disabled UPS systems to prevent backup power for recovery
7. **Persistence**: Overwrote firmware on serial-to-Ethernet converters to prevent remote reconfiguration

**Protocol-Specific Lessons**:
- Attackers used legitimate DNP3/IEC 104 commands via HMI — protocol-level controls would not have helped
- Authentication failure was at HMI/Windows level, not protocol level
- Remote access to OT was the primary weakness — VPN with weak credentials

**Detection Opportunities**:
- Unusual HMI operator behavior (rapid breaker operations outside shift change)
- Remote VPN sessions from unexpected geographic locations
- File system changes indicating wiper deployment
- Serial converter firmware changes (rare event)

**Reference**: SANS ICS Summit 2016, "Analysis of the Cyber Attack on the Ukrainian Power Grid"

### 3.2 Ukraine 2016: Industroyer / CrashOverride

**Date**: December 17, 2016
**Target**: Ukrenergo (national transmission operator)
**Impact**: 1/5 of Kyiv without power for 1 hour

**Attack Chain**:
1. **Initial Access**: Compromised VPN credentials (likely reused from prior breaches)
2. **Reconnaissance**: 6+ months of network mapping and protocol identification
3. **Tool Development**: Custom framework with protocol-specific payloads for IEC 104, IEC 61850 GOOSE, IEC 60870-5-101 serial, OPC DA
4. **Execution**: Automated command sequences — opened breakers, disabled protection relays
5. **DoS Module**: Flooded upstream communications to prevent operator override
6. **Cleanup**: Wiper module destroyed evidence on exit

**Industroyer Architecture**:
```
Main backdoor
   ├── Determines target environment
   ├── Launches appropriate payload modules:
   │   ├── IEC 104 payload module
   │   ├── IEC 61850 payload module (MMS + GOOSE)
   │   ├── IEC 60870-5-101 payload module (serial)
   │   ├── OPC DA payload module
   │   └── DoS module (against Siemens SIPROTEC DoS CVE-2015-5374)
   └── Wiper module (KillDisk variant)
```

**Protocol-Specific Lessons**:
- First known malware with multi-protocol ICS capability
- Used hardcoded protocol parameters (specific to target facility) — indicates prior reconnaissance
- DoS module targeted specific device families (Siemens SIPROTEC) — protocol-aware DoS
- Demonstrated attacker capability to operate across mixed-protocol environments

**Detection Opportunities**:
- New client certificates on MMS sessions
- Unexpected GOOSE stNum jumps (>1 per event)
- Multiple protocol command bursts from single workstation
- SIPROTEC device reboots (CVE-2015-5374 exploitation indicator)

**Reference**: ESET whitepaper "Industroyer: Biggest threat to industrial control systems since Stuxnet" (2017). Dragos analysis "CRASHOVERRIDE" (2017).

### 3.3 Saudi Arabia 2017: Triton / Trisis

**Date**: August 2017
**Target**: Petrochemical facility (undisclosed operator)
**Impact**: SIS (Safety Instrumented System) tripped twice during production, causing emergency shutdowns. No injuries due to safe failure mode.

**Attack Chain**:
1. **Initial Access**: Likely engineering workstation compromise (specific vector undisclosed)
2. **Persistence**: Trojanized TriStation 1131 framework (Schneider Electric Triconex SIS programming software)
3. **Reconnaissance**: Attacker learned SIS controller firmware and memory layout
4. **Execution**: Deployed malicious firmware to Triconex MP3008 main processors
5. **Failure Mode**: Malicious firmware had a bug causing unexpected reboot; SIS tripped twice
6. **Forensics**: Investigators found attacker had been developing Triton for 1+ year

**Why Triton Matters**:
- First known malware specifically targeting Safety Instrumented Systems
- Demonstrated capability to modify SIS logic — could prevent safety trips during intentional process upsets
- Required deep understanding of Triconex proprietary firmware (no public documentation)
- Attack development time estimated at 12+ months

**Protocol-Specific Lessons**:
- TriStation protocol is Schneider proprietary (not publicly documented)
- Attack required insider knowledge or extensive reverse engineering
- SIS should always be air-gapped from process control — this incident showed the air gap was bypassed
- Even non-public protocols are attackable with sufficient investment

**Detection Opportunities**:
- New firmware images on SIS controllers
- TriStation 1131 software modifications
- Unexpected SIS controller reboots
- Anomalous SIS communication patterns

**Reference**: FireEye/Mandiant report "TRITON Attribution: Russian Government-Owned Lab" (2018). Schneider Electric SEVD-2017-347-01 advisory.

### 3.4 Florida 2021: Oldsmar Water Treatment

**Date**: February 5, 2021
**Target**: City of Oldsmar water treatment facility (Pinellas County, Florida)
**Impact**: Sodium hydroxide (lye) setpoint changed from 100 ppm to 11,100 ppm (111x normal). Operator detected within 90 seconds; no harm.

**Attack Chain**:
1. **Initial Access**: TeamViewer remote desktop on HMI workstation
2. **Credential Failure**: Reused password from prior breach; no MFA
3. **Reconnaissance**: Attacker observed operations via TeamViewer
4. **Execution**: Changed sodium hydroxide dosing setpoint via HMI
5. **Detection**: Operator noticed mouse moving without input; observed setpoint change; reverted
6. **Persistence**: None — attacker disconnected

**Protocol-Specific Lessons**:
- HMI was directly internet-facing — major architecture failure
- Used legitimate SCADA commands via HMI — protocol exploitation was not required
- Demonstrated that "low-tech" attacks (credential reuse) can target critical infrastructure
- Dosing systems have wide valid ranges (100-11100 ppm); no upper-bound alarm triggered automatically

**Detection Opportunities**:
- TeamViewer sessions from non-facility IP addresses
- Out-of-process-hours setpoint changes
- Setpoint changes exceeding normal variance (>3 sigma from rolling average)
- Geographic anomalies in remote access

**Reference**: CISA Alert AA21-042A "Compromise of U.S. Water Treatment Facility" (Feb 2021). State of Massachusetts advisory following similar incident.

---

## 4. Lab Setup

A fieldbus test lab combines software simulators with optional hardware. This section documents the recommended stack.

### 4.1 Hardware Requirements (Minimum)

| Component | Purpose | Estimated Cost |
|-----------|---------|----------------|
| Laptop with Kali Linux | Tester platform | (existing) |
| USB-to-RS-485 adapter | Profibus DP, Modbus RTU, IEC 101 | $30 |
| USB-HART modem | HART command testing | $200-500 |
| ProfiShark 100M tap | PROFINET/PROFIBUS capture | $1500 |
| Managed switch (Cisco SG-300 or equivalent) | Lab VLAN segmentation | $200 |
| Raspberry Pi 4 | Outstation simulator host | $100 |
| Optional: Used PLC (Siemens S7-1200, AB MicroLogix) | Real target testing | $500-2000 |

### 4.2 Software Simulators

| Tool | Protocols | License | Source |
|------|-----------|---------|--------|
| OpenDNP3 | DNP3 | Apache 2.0 | https://github.com/dnp3/opendnp3 |
| lib60870 | IEC 60870-5-101, 104 | GPL-3.0 | https://github.com/mz-automation/lib60870 |
| libiec61850 | IEC 61850 (MMS, GOOSE, SV) | GPL-3.0 | https://github.com/mz-automation/libiec61850 |
| PLCsim Advanced | S7comm, Modbus | Commercial (free eval) | Siemens TIA Portal |
| Conpot | Modbus, S7comm, IEC 104 | GPL-2.0 | https://github.com/mushorg/conpot |
| Recondog | BACnet | MIT | https://github.com/JoelBender/BACnet-Recondog |
| OpENer | EtherNet/IP, CIP | BSD-3 | https://github.com/EIPStackGroup/OpENer |
| YABACT | BACnet | MIT | https://github.com/inflex/yabact |
| pymodbus | Modbus TCP/RTU | BSD-3 | https://github.com/pymodbus-dev/pymodbus |
| Softing syGate | PROFINET, EtherCAT, OPC UA | Commercial | https://www.softing.com |

### 4.3 Lab Installation Script

```bash
#!/bin/bash
# ics-fieldbus-lab-install.sh - Install fieldbus test tools on Kali Linux
set -euo pipefail

echo "[*] Installing ICS fieldbus lab tooling..."

# Base packages
sudo apt update
sudo apt install -y \
    wireshark tshark nmap masscan python3-pip \
    build-essential cmake git libpcap-dev \
    socat tcpdump ettercap-graphical bettercap \
    socat can-utils

# Python tooling
pip3 install --user \
    scapy boofuzz \
    pymodbus pycomm3 \
    bacpypes pyiec61850 \
    python-snappy

# OpenDNP3
echo "[*] Building OpenDNP3..."
cd /tmp
git clone https://github.com/dnp3/opendnp3.git
cd opendnp3
mkdir build && cd build
cmake -DDNP3_TESTS=OFF -DDNP3_EXAMPLES=ON -DDNP3_TLS=OFF ..
make -j"$(nproc)"
sudo make install
sudo ldconfig

# lib60870
echo "[*] Building lib60870..."
cd /tmp
git clone https://github.com/mz-automation/lib60870.git
cd lib60870
mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make -j"$(nproc)"
sudo make install
sudo ldconfig

# libiec61850
echo "[*] Building libiec61850..."
cd /tmp
git clone https://github.com/mz-automation/libiec61850.git
cd libiec61850
mkdir build && cd build
cmake -DBUILD_EXAMPLES=ON ..
make -j"$(nproc)"
sudo make install
sudo ldconfig

# Conpot
echo "[*] Installing Conpot..."
pip3 install --user conpot

# Verify installations
echo "[*] Verification:"
which tshark nmap tcpdump ettercap bettercap
ls /usr/local/bin/master /usr/local/bin/outstation 2>/dev/null || \
    ls /tmp/opendnp3/build/examples/master/*.exe 2>/dev/null || \
    find /tmp -name "master" -executable -type f

echo "[+] Lab installation complete."
echo "[+] Start testing with:"
echo "    OpenDNP3: /tmp/opendnp3/build/examples/master/master_demo"
echo "    IEC 104:  /tmp/lib60870/build/examples/iec104/server/iec104_server_demo"
echo "    IEC 61850: /tmp/libiec61850/build/examples/server_example_61850"
```

### 4.4 Starting Lab Components

```bash
# Terminal 1: Start DNP3 outstation (slave)
/tmp/opendnp3/build/examples/outstation/outstation_demo \
    --config /tmp/dnp3_outstation.config

# Terminal 2: Start DNP3 master (test client)
/tmp/opendnp3/build/examples/master/master_demo \
    --config /tmp/dnp3_master.config

# Terminal 3: Start IEC 104 server
/tmp/lib60870/build/examples/iec104/server/iec104_server_demo

# Terminal 4: Start IEC 104 client
/tmp/lib60870/build/examples/iec104/client/iec104_client_demo 127.0.0.1

# Terminal 5: Start IEC 61850 server
/tmp/libiec61850/build/examples/server_example_61850/server_example_61850

# Terminal 6: Capture all ICS traffic
sudo tshark -i lo -f "port 20000 or port 2404 or port 102" -w lab_capture.pcap
```

### 4.5 Lab Network Topology

```
Internet
    |
[Tester Laptop - Kali]
    |
    +-- eth0: 192.168.100.10/24 (Lab Network)
    |
[Managed Switch with VLANs]
    |
    +-- VLAN 10: DNP3 Lab (192.168.10.0/24)
    |       └── Raspberry Pi running OpenDNP3 outstation
    |
    +-- VLAN 20: IEC 104 Lab (192.168.20.0/24)
    |       └── Raspberry Pi running lib60870 server
    |
    +-- VLAN 30: IEC 61850 Lab (192.168.30.0/24)
    |       └── Raspberry Pi running libiec61850 server
    |
    +-- VLAN 40: BACnet Lab (192.168.40.0/24)
    |       └── VM running Recondog
    |
    +-- VLAN 50: Honeypot (192.168.50.0/24)
            └── Conpot VM
```

### 4.6 Honeypot Deployment

Conpot can emulate multiple ICS protocols simultaneously, serving as both test target and intrusion detection.

```bash
# Install conpot
pip3 install conpot

# Available templates
ls /usr/local/lib/python3.*/dist-packages/conpot/templates/

# Start IEC 104 honeypot
conpot -f --template iec104

# Start Modbus honeypot
conpot -f --template default

# Start with custom config
conpot -f --template kemel --host 192.168.50.10

# Log to syslog for SIEM integration
conpot -f --template default --logfile /var/log/conpot.log --syslog
```

### 4.7 Physical Hardware (Optional, for Realistic Testing)

| Vendor | Product | Protocols | Approximate Cost |
|--------|---------|-----------|------------------|
| Siemens | S7-1200 CPU | S7comm, Modbus TCP, PROFINET, OPC UA | $500-1500 |
| Schneider | Modicon M221 | Modbus TCP, EtherNet/IP | $300-700 |
| Allen-Bradley | MicroLogix 1100 | Modbus TCP, DF-1, EtherNet/IP | $500-1000 |
| Schweitzer | SEL-735 IED | DNP3, IEC 61850, Synchrophasor | $3000-5000 |
| Beckhoff | EK1100 + ELxxxx | EtherCAT | $200-1000 |
| Phoenix Contact | FL SWITCH 2000 series | (Network test target) | $200-500 |
| Triconex | MP3008 (used SIS) | TriStation (research only) | $5000+ (training) |

---

## 5. Defense

Defensive guidance for fieldbus environments, organized by IEC 62443 zones.

### 5.1 IEC 62443 Zone and Conduit Model

The IEC 62443 standard defines a zone-and-conduit model for OT security. Each zone contains devices with similar security requirements; conduits are the controlled paths between zones.

```
+--------------------------------------------------------------+
| ZONE 5: Enterprise DMZ                                       |
|   - Enterprise → Site DMZ forwarder                          |
|   - Conduit: IT firewall, one-way data diode                |
+--------------------------------------------------------------+
                          |
+--------------------------------------------------------------+
| ZONE 4: Site Operations                                      |
|   - Historian, OPC UA gateway, MES forwarder                 |
|   - Conduit: IDMZ with dual firewalls                        |
+--------------------------------------------------------------+
                          |
+--------------------------------------------------------------+
| ZONE 3: Operations (Control Room)                            |
|   - HMI workstations, engineering workstations               |
|   - Operator terminals                                        |
|   - Conduit: OT firewall with protocol-aware rules           |
+--------------------------------------------------------------+
                          |
+--------------------------------------------------------------+
| ZONE 2: Control Network                                      |
|   - PLCs, RTUs, DCS controllers                              |
|   - IEDs (substation)                                         |
|   - Conduit: Protocol-aware firewall, command allowlist      |
+--------------------------------------------------------------+
                          |
+--------------------------------------------------------------+
| ZONE 1: Fieldbus                                             |
|   - Sensors, actuators, I/O                                  |
|   - GOOSE multicast domain                                   |
|   - EtherCAT ring                                            |
|   - Foundation FF H1 segments                                |
|   - Conduit: Managed switch with port security               |
+--------------------------------------------------------------+
                          |
+--------------------------------------------------------------+
| ZONE 0: Process Equipment                                    |
|   - Physical equipment (motors, valves, pumps)               |
|   - No network communication at this level                   |
+--------------------------------------------------------------+
```

### 5.2 Defensive Controls per Zone

**Zone 5 (Enterprise)**:
- IT-grade firewalls, IPS
- Email filtering (anti-phishing) — critical because most ICS attacks start with phishing
- Identity provider with MFA for all remote access
- Privileged access management for engineers

**Zone 4 (Site Operations)**:
- Unidirectional data diodes (Waterfall, Owl) for outbound data
- Dual-firewall IDMZ (no direct IT-to-OT routing)
- Historian replication (read-only copies in DMZ)
- OPC UA gateway with certificate auth

**Zone 3 (Control Room)**:
- Hardened workstations (application whitelisting)
- Jump host for engineering access (no direct PLC access from workstations)
- Session recording (CyberArk, BeyondTrust) for all PLC operations
- HMI with strong authentication, session timeout

**Zone 2 (Control Network)**:
- Protocol-aware firewalls (Clarke-Taylor, Tofino, Bayshore)
- Command allowlists (e.g., permit FC 1/2/3/4 reads; deny FC 5/6/15/16 writes from non-HMI sources)
- VLAN segmentation per process unit
- ICS-aware IDS (Claroty, Nozomi, Dragos, Tenable.ot)

**Zone 1 (Fieldbus)**:
- Managed switches with port security (MAC lockdown)
- 802.1X / MACsec on switch ports
- GOOSE multicast VLAN isolation
- PROFIBUS/PROFINET physical access control (locked cabinets)
- HART loop current monitoring (anomalous load = tampering indicator)

**Zone 0 (Process Equipment)**:
- Physical security (locked cabinets, badge access)
- Intrinsically safe equipment (Ex i rated) in hazardous areas
- Process safety instrumented systems (SIS) air-gapped from BPCS
- Regular safety function testing (proof testing)

### 5.3 Protocol-Aware Firewall Rules

Example rules for protecting DNP3 outstations:

```
# DNP3 Firewall Rules (pseudocode)
rule 1: permit tcp src=192.168.20.5 (master) dst=192.168.10.0/24 port=20000
        dnp3_func_code in (0, 1, 2, 3, 4, 7, 9, 13, 20, 21, 22)  # reads, status
        dnp3_sav=required
        log=info

rule 2: permit tcp src=192.168.20.5 dst=192.168.10.0/24 port=20000
        dnp3_func_code in (5, 6)  # direct operate (commands)
        dnp3_sav=required
        dnp3_sav_version=5
        time_window=mon-fri 06:00-18:00  # business hours only
        log=warn

rule 3: deny tcp src=any dst=192.168.10.0/24 port=20000
        log=crit
        alert=siem
```

Example rules for IEC 104 RTUs:

```
# IEC 104 Firewall Rules
rule 1: permit tcp src=192.168.20.5 dst=192.168.20.0/24 port=2404
        iec104_asdu_type in (1, 3, 9, 13, 30, 100)  # reads and interrogations
        iec104_cause_tx in (1, 3, 20, 37)  # periodic, spontaneous
        log=info

rule 2: permit tcp src=192.168.20.5 dst=192.168.20.0/24 port=2404
        iec104_asdu_type in (45, 46, 50)  # commands
        iec104_se_bit=1  # select only, no direct execute
        time_window=mon-fri 06:00-18:00
        log=warn

rule 3: deny tcp src=any dst=192.168.20.0/24 port=2404
        log=crit
        alert=siem
```

### 5.4 Detection Use Cases

| Detection | Protocol | Indicator | Source |
|-----------|----------|-----------|--------|
| Unauthorized DNP3 master | DNP3 | TCP 20000 from non-HMI IP | NetFlow, Suricata |
| DNP3 SAv downgrade | DNP3 | Application control byte without SAv flag | Suricata custom rule |
| IEC 104 command outside hours | IEC 104 | ASDU type 45 from non-master IP | Suricata, Zeek |
| IEC 104 STARTDT flood | IEC 104 | Many STARTDT act per second | Suricata |
| GOOSE stNum anomaly | GOOSE | stNum jump >1 or source MAC change | Wireshark, Dragos |
| GOOSE simulation bit set | GOOSE | simulation=1 (test mode) | Wireshark |
| MMS new client certificate | MMS | Certificate fingerprint not in inventory | Zeek SSL log |
| PROFINET DCP from non-engineering MAC | PROFINET | DCP Set from non-EWS MAC | Tenable.ot |
| PROFINET name change | PROFINET | nameOfStation changed | Dragos |
| EtherCAT slave state change | EtherCAT | State transition outside maintenance window | Beckhoff TwinCAT |
| BACnet WriteProperty to setpoint | BACnet | WriteProperty to analogOutput present-value | Zeek, Wireshark |
| BACnet ReinitializeDevice | BACnet | Service 17 invocation | Zeek |
| HART loop current anomaly | HART | Loop current outside 4-20mA bounds | HART gateway |
| Modbus function code 8 (diagnostic) | Modbus | FC 8 (Restart Communications) from non-HMI | Suricata |

### 5.5 Suricata Rules for ICS

```yaml
# DNP3 Direct Operate from unauthorized IP
alert tcp $EXTERNAL_NET any -> $HOME_NET 20000 (msg:"DNP3 Direct Operate from unauthorized source"; \
    content:"|05 64|"; depth:2; \
    byte_test:1, &, 0x80, 10, relative; \
    content:"|05|"; distance:0; within:1; \
    classtype:attempted-admin; sid:1000001; rev:1;)

# IEC 104 Single Command
alert tcp any any -> $HOME_NET 2404 (msg:"IEC 60870-5-104 Single Command"; \
    content:"|68|"; depth:1; \
    byte_test:1, >, 0x80, 6, relative; \
    content:"|2D|"; distance:0; within:1; \
    classtype:attempted-admin; sid:1000002; rev:1;)

# GOOSE frame with simulation bit set
alert ether any any -> any any (msg:"GOOSE simulation mode"; \
    etherproto:0x88b8; \
    content:"|83 01 01|"; \
    classtype:attempted-recon; sid:1000003; rev:1;)

# BACnet WriteProperty
alert udp any any -> $HOME_NET 47808 (msg:"BACnet WriteProperty"; \
    content:"|81|"; depth:1; \
    content:"|0F|"; distance:0; within:1; \
    classtype:attempted-admin; sid:1000004; rev:1;)
```

### 5.6 Hardening Checklist

| Control | Priority | Protocol | Effort |
|---------|----------|----------|--------|
| Disable unused protocols on PLCs/RTUs | High | All | Low |
| Enable SAv5 on DNP3 | High | DNP3 | Medium |
| Deploy IEC 62351 secure gateway | High | IEC 104, MMS | High |
| Enable CIP Security on EtherNet/IP | Medium | EtherNet/IP | Medium |
| Migrate BACnet to BACnet/SC | Medium | BACnet | High |
| Restrict GOOSE multicast to dedicated VLAN | High | GOOSE | Medium |
| Implement MACsec on EtherCAT | Medium | EtherCAT | Medium |
| Deploy protocol-aware firewalls | High | All | High |
| Deploy ICS-aware IDS | High | All | Medium |
| Segment OT from IT via IDMZ | Critical | All | High |
| Implement jump host for PLC engineering | High | All | Medium |
| Disable internet access from OT | Critical | All | Low |
| Restrict vendor remote access | High | All | Medium |
| Patch PLC firmware annually (planned outage) | Medium | All | High |
| Operator training on attack indicators | High | All | Low |
| Annual OT tabletop exercise | High | All | Low |

### 5.7 Continuous Monitoring

Passive ICS monitoring tools:

| Tool | Vendor | License | Approach |
|------|--------|---------|----------|
| **Claroty xDome** | Claroty | Commercial | Passive deep packet inspection |
| **Nozomi Guardian** | Nozomi Networks | Commercial | Hybrid passive + active |
| **Dragos Platform** | Dragos | Commercial | Threat intelligence focus |
| **Tenable.ot** | Tenable | Commercial | Vulnerability + asset discovery |
| **Microsoft Defender for IoT** | Microsoft | Commercial | Cloud-integrated |
| **CyberX/XO** | Microsoft (acquired) | Commercial | Behavioral analytics |
| **Rapid7 InsightIDR** | Rapid7 | Commercial | SIEM integration |
| **Wireshark + Zeek** | Open source | Free | Manual analysis |

**Deployment Guidance**:
- Deploy sensors at choke points: IDMZ, OT firewall, control-room distribution switch
- Use SPAN/mirror ports or network taps (do not inline active sensors on critical links)
- Forward alerts to SIEM (Splunk, Elastic, QRadar, Sentinel)
- Tune false positives over 30-day baseline period
- Integrate with SOAR for automated response (e.g., quarantine attacker IP via firewall rule)

### 5.8 Incident Response for Fieldbus Attacks

When an ICS incident is detected:

1. **Activate ICS IR plan** (separate from IT IR plan)
2. **Engage operations** — facility safety officer, shift supervisor, plant manager
3. **Preserve evidence** — capture full pcaps, memory dumps, firmware images BEFORE remediation
4. **Isolate affected zone** — deploy firewall rules blocking all non-essential traffic
5. **Verify SIS integrity** — confirm safety systems are functioning correctly
6. **Coordinate with vendor** — many PLC vendors offer IR support (Schneider CIRT, Rockwell, Siemens PSIRT)
7. **Engage CISA ICS-CERT** — voluntary incident reporting for cross-facility patterns
8. **Conduct forensic timeline** — reconstruct attacker TTPs
9. **Implement hardening** — apply lessons learned to other facilities
10. **Document lessons** — feed back into training and tabletop exercises

### 5.9 Maturity Model

| Level | Description | Example Controls |
|-------|-------------|------------------|
| **L1: Initial** | Ad-hoc, no formal ICS security | Basic firewall, default passwords |
| **L2: Managed** | Documented policies, basic segmentation | IDMZ in place, password policy |
| **L3: Defined** | IEC 62443 alignment, active monitoring | Protocol-aware firewall, IDS deployed |
| **L4: Quantitatively Managed** | Metrics, continuous improvement | KPI tracking, threat intelligence feeds |
| **L5: Optimizing** | Proactive, predictive | Anomaly detection, threat hunting, red team program |

Most utility and manufacturing organizations operate at L2-L3. Critical infrastructure (bulk electric system, large chemical) should target L4-L5.

---

## Cross-References

- **Parent skill**: `skills/scada-ics-security/` — Modbus TCP, S7comm, OPC UA, EtherNet/IP basic
- **Companion skills**: `automotive-vehicle-security` (CAN/LIN/FlexRay), `deception-honeypot` (Conpot methodology)
- **Protocol payloads**: `skills/ics-fieldbus-attack/payloads.md` — per-protocol command references
- **Test cases**: `skills/ics-fieldbus-attack/test-cases.md` — 12 structured test cases
- **Mitre ATT&CK ICS**: T0817 (PLC Software), T0858 (Change Operating Mode), T0859 (Train Operator), T0866 (Exploit Remote Services)

---

## Attribution

This playbook is based on publicly available research, vendor documentation, and standards:

- **IEC 62443** series (industrial communication networks - IT security)
- **ISA-99 / IEC 62443** standards
- **NIST SP 800-82** Revision 3 (Guide to Operational Technology (OT) Security)
- **CISA ICS-CERT** advisories and alerts
- **Dragos** Year in Review reports
- **Claroty, Nozomi, Tenable.ot** research blogs
- **SANS ICS Summit** presentations (2014-2024)
- **DEF CON ICS Village** materials
- **ESET, FireEye/Mandiant, CrowdStrike** threat intelligence reports
- **IEEE Industrial Electronics** standards and research
- **IEEE Power & Energy Society** cybersecurity publications

This document is intended solely for authorized security testing and educational use. Any unauthorized testing of operational ICS environments is illegal and potentially dangerous.
