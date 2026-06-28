# CPS Attack — Real-World Incident Case Studies

> 10 real-world incidents (2010-2025) where Cyber-Physical Systems were the breach vector or the final impact target. Each case includes timeline, attack chain, IOCs, blue-team detection, and lessons learned.

---

## Case 1 — Stuxnet (2010)

### Summary

Stuxnet, attributed to US/Israel, was the first ICS-specific malware. It targeted Iran's Natanz uranium enrichment facility, modifying S7-315 and S7-415 PLCs to over-speed centrifuges while showing operators normal readings.

### Timeline

- 2007-2009: Development
- 2010-06: First detection by VirusBlokAda (Belarus)
- 2010-09: Symantec publishes detailed analysis
- 2010-11: Iranian president acknowledges damage

### Attack Chain

1. **Initial infection**: USB drop via Natanz contractors
2. **Lateral movement**: 4 zero-days (Print Spooler, Server Service, etc.)
3. **WinCC/Step 7 compromise**: stolen certificates from Realtek and JMicron
4. **PLC fingerprint**: identify exact centrifuge configuration
5. **PLC code injection**: inject malicious code blocks (FC1860, FC1861, FC1862, FC1863, FC1865, FC1866, FC1867, DB890, DB891, DB892)
6. **Two-pronged attack**:
   - Pressure transient: over-pressurize centrifuges
   - Speed attack: over-speed to 1410 Hz, then under-speed to 2 Hz
7. **Operator deception**: code intercepts sensor reads, replays "normal" 1064 Hz values

### IOCs

- `~wtr4141.tmp`, `~wtr4142.tmp` files
- `s7otbxdx.dll` replaced on Step 7 systems
- Registry keys: `HKCU\Software\Microsoft\Windows\CurrentVersion\MS\...\Data`
- Network traffic to C2 servers (myrtus, todaysfoot, bestafer)

### Blue-Team Detection

```yaml
title: Stuxnet PLC code block injection
logsource:
  product: siemens
  service: step7
detection:
  selection:
    event: download-block
    block.name|re: FC1860|FC1861|FC1862|FC1863|FC1865|FC1866|FC1867
  condition: selection
level: critical
```

### Lessons Learned

- Air-gaps are insufficient (USB is the new vector)
- PLC code review and comparison is critical
- Code signing on engineering software (Microsoft caught up after Stuxnet)
- ICS-specific malware is real

### Reference

- Symantec — *W32.Stuxnet Dossier* (2011)
- Ralph Langner — *To Kill a Centrifuge* (2013)

---

## Case 2 — Industroyer / CrashOverride (2016, Ukraine)

### Summary

Industroyer was the first malware specifically designed to attack power grids. It was used in the December 2016 Ukraine power outage affecting Kyiv, attributed to Russia's Sandworm.

### Timeline

- 2016-12-17: Ukrenergo Kyiv substation loses power
- 2016-12-18: ESET discovers Industroyer malware
- 2017-06: Dragos publishes analysis
- 2018-10: US DOJ indicts Sandworm operators

### Attack Chain

1. **Initial access**: spear-phishing Ukrenergo employees
2. **Lateral movement**: stolen Windows credentials
3. **OT network reach**: pivot to SCADA network
4. **Protocol modules**: Industroyer includes modules for IEC 60870-5-101, IEC 60870-5-104, IEC 61850, and OLE Process Control (OPC DA)
5. **Direct IED manipulation**: malware uses protocol natively, not through SCADA
6. **Circuit breaker trip**: opens breakers
7. **Concrete cover**: wiper module destroys evidence; UPS attack to delay recovery

### IOCs

- `73.64mb` `3C2DDC.exe` main backdoor
- `.bat` scripts in `C:\ProgramData\MacroVIsion`
- Registry keys under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Main`
- Network traffic to port 4782 (C2)

### Blue-Team Detection

```yaml
title: Industroyer IEC 104 command pattern
logsource:
  product: zeek
  service: iec104
detection:
  selection:
    asdu_type: C_SC_NA_1  # single command
    cause_of_transmission: activation
    burst|re: ^.{50,}$  # 50+ commands in short window
  condition: selection
level: critical
```

### Lessons Learned

- ICS-specific malware targets protocols, not just Windows
- OLE for Process Control (OPC DA) is a vector
- Wiper modules are common for evidence destruction
- UPS itself is a target

### Reference

- Dragos — *CrashOverride* (2017)
- ESET — *Industroyer: A new threat for industrial control systems* (2017)
- Anton Cherepanov (ESET) — *Win32/Industroyer: A complex threat for industrial control systems*

---

## Case 3 — TRITON / TRISIS (2017, Saudi Arabia)

### Summary

TRITON (also called TRISIS) was the first malware to target Safety Instrumented Systems (SIS). It attacked a Saudi petrochemical facility in 2017. The Schneider Electric Triconex SIS is supposed to be physically separate from the Basic Process Control System (BPCS), but TRITON found a path.

### Timeline

- 2017-08-04: Attack initiated
- 2017-12-14: FireEye (Mandiant) publishes analysis
- 2018-10: US CERT attribution to Russia's Central Scientific Research Institute of Chemistry and Mechanics
- 2020-10: US DOJ indictment

### Attack Chain

1. **Initial access**: phishing / watering hole on engineering workstation
2. **Lateral to SIS network**: pivot through historian or maintenance connection
3. **Triconex Tricon credential recovery**: default TriStation password
4. **TRITON framework injected**: masquerades as TriStation 1131
5. **Malicious function 0x60 sent to SIS controller**
6. **SIS controller sanity check fails**: triggers fail-safe, halts plant
7. **Operator investigation reveals attack**

### IOCs

- `TRILogDLL.dll`, `TriLogger.exe`, `hookapoexe.dll`, `TRILOG_FILE.sys`, `inject.bin`, `shellcode.bin`
- Network traffic on port 1502 (TriStation)
- `TriconState` log entries showing MPBP (Main Processor Bypass)

### Blue-Team Detection

```yaml
title: Triconex TrStation protocol from non-engineering workstation
logsource:
  product: zeek
  service: tristation
detection:
  selection:
    func|re: function_0x60|function_0x57
  notEWS:
    src|re: !^10\.0\.0\.10$
  condition: selection and notEWS
level: critical
```

### Lessons Learned

- SIS is not isolated enough — physical separation often violated for maintenance
- TriStation protocol has no authentication
- SIS bypass can cause catastrophic release
- Engineering workstation is highest-value target

### Reference

- FireEye / Mandiant — *TRITON Attack* (2017)
- CISA Alert TA17-350A
- Schneider Electric — *Security Notification SSEF-1801-01*

---

## Case 4 — Pipedream / Incontroller (2022)

### Summary

Pipedream (Dragos name) or Incontroller (Mandiant name) was discovered in 2022 as the fourth-ever ICS-specific malware (after Stuxnet, Industroyer, TRITON). It targeted Schneider Electric and Omron PLCs.

### Timeline

- 2022-03: Dragos discovers Pipedream via darkweb monitoring
- 2022-04: Microsoft / Mandiant discover Incontroller independently
- 2022-04-13: Joint public advisory
- 2022-06: First attempted use (preempted by disclosure)

### Attack Chain

Pipedream includes:
- **Incontroller (Protocol abuse)**: Modbus, Codesys, OPC UA
- **BadOmen (Schneider Modbus attack)**: hides malicious function in standard Modbus
- **Omicron (Omron attack)**: targets Omron NX/NJ controllers

Capabilities:
- Reconnaissance (device fingerprinting)
- Brute force credentials
- Inhibit HMI display
- Modify PLC logic
- Brick devices (firmware corruption)

### IOCs

- Modbus function code 90 (Encapsulated Interface Transport) anomalies
- Codesys protocol unauthorized access
- OPC UA unusual session creation
- Firmware image upload to Schneider / Omron PLCs

### Blue-Team Detection

```yaml
title: Pipedream Modbus function 90 anomaly
logsource:
  product: zeek
  service: modbus
detection:
  selection:
    func: 90  # Encapsulated Interface Transport (Schneider-specific)
    payload|contains: badomen
  condition: selection
level: critical
```

### Lessons Learned

- ICS-specific malware now targets multiple vendors in single framework
- Codesys is a frequent attack surface (third-party PLC SDK)
- OPC UA deployment needs security policy enforcement
- Vendor CERTs critical for rapid patching

### Reference

- Dragos — *Pipedream / Chernovite* (2022)
- Mandiant — *INCONTROLLER / Pipedream* (2022)
- CISA AA22-103A

---

## Case 5 — Industroyer2 (2022, Ukraine)

### Summary

Industroyer2 was a refined Industroyer variant used in 2022 against Ukrainian power infrastructure during the Russia invasion. It targeted IEC 60870-5-104 specifically.

### Timeline

- 2022-04-08: Second wave of attacks on Ukrainian grid
- 2022-04-12: Slovak NBU-CERT analysis
- 2022-04-26: Mandiant attribution to Sandworm

### Attack Chain

1. **Initial access**: previously implanted backdoors (discovered 2022)
2. **Micrometro Putin**: new backdoor variant
3. **Industroyer2 deployment**: targets 104 outstations directly
4. **Specific circuit breakers tripped**: targeting specific substations
5. **Additional wiper (CaddyWiper)**: destroys evidence

### IOCs

- IEC 60870-5-104 control commands from non-master IP
- File `Ismb.exe` on compromised host
- Registry: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IsmB`

### Blue-Team Detection

```yaml
title: Industroyer2 IEC 104 single-command burst
logsource:
  product: zeek
  service: iec104
detection:
  selection:
    asdu_type|re: C_SC_NA_1|C_DC_NA_1|C_RC_NA_1
    cause_of_transmission: 6  # activation
    count: >50
  notLegitMaster:
    src|re: !^10\.0\.0\.1$
  condition: selection and notLegitMaster
level: critical
```

### Lessons Learned

- ICS malware is iterative (Industroyer → Industroyer2)
- Old protocols (IEC 60870-5-104) remain vulnerable
- Wiper modules standard for evidence destruction

### Reference

- Slovak NBU-CERT — *Industroyer2 Analysis* (2022)
- Mandiant — *Industroyer2 Sandworm attribution* (2022)
- CISA AA22-109A

---

## Case 6 — Unitronics PLC Attack (2023, US Water Utilities)

### Summary

In late 2023, Iranian-linked CyberAv3ngers attacked Unitronics PLCs at multiple US water utilities. The PLCs were exposed to the internet with default credentials.

### Timeline

- 2023-11-22: Aliquippa Water Authority (PA) hit
- 2023-11-25: Multiple additional utilities
- 2023-11-28: CISA AA23-335A
- 2023-12: Continuing attacks

### Attack Chain

1. **Recon**: Shodan / Censys for exposed Unitronics PLCs (port 20256)
2. **Default credentials**: Unitronics ships with admin / 987654321
3. **HMI defacement**: "You have been hacked, down with Israel"
4. **PLC out of RUN mode**: pumps offline
5. **No physical damage** but operations disrupted

### IOCs

- Connection to Unitronics PLC port 20256 from non-authorized IP
- Login via admin / 987654321
- HMI screen showing attacker message
- PLC state change from RUN to STOP

### Blue-Team Detection

```yaml
title: Unitronics PLC default credential login
logsource:
  product: unitronics
  service: plc
detection:
  selection:
    event: login-success
    username: admin
  defaultPw:
    auth|contains: 987654321
  condition: selection and defaultPw
level: critical
```

### Lessons Learned

- OT devices should NEVER be internet-facing
- Default credentials MUST be rotated
- Vendor defaults (Unitronics 987654321) are well-known
- Water utilities have lowest security maturity among critical infra

### Reference

- CISA AA23-335A — *Iranian Cyber Actors Targeting PLCs* (Nov 2023)
- Unitronics Security Advisory

---

## Case 7 — Oldsmar, FL Water Treatment Attack (2021)

### Summary

In February 2021, an attacker remote-accessed Oldsmar, FL water treatment plant and increased sodium hydroxide (lye) levels from 100 ppm to 11,100 ppm. Operator noticed cursor moving and reversed change before water was distributed.

### Timeline

- 2021-02-05 14:00 ET: Attacker remote access (TeamViewer)
- 2021-02-05 14:30 ET: Operator notices mouse movement
- 2021-02-05 15:00 ET: Operator reverses change

### Attack Chain

1. **Initial access**: TeamViewer on plant PC with weak password
2. **No MFA on TeamViewer**
3. **Plant SCADA access**: same Windows account
4. **Modify setpoint**: lye concentration
5. **Detection**: operator watching cursor move
6. **Reversal**: operator reset setpoint

### IOCs

- TeamViewer connection from non-authorized IP
- SCADA setpoint change outside normal range
- Mouse movement during non-business hours
- Login to plant PC from remote source

### Blue-Team Detection

```yaml
title: TeamViewer access to plant PC from non-authorized IP
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image|endswith: TeamViewer.exe
    NetworkDns|contains: teamviewer.com
  notAllowed:
    DestinationIp|cidr: !10.0.0.0/8
  condition: selection and notAllowed
level: critical
```

### Lessons Learned

- TeamViewer / remote desktop on OT is a vector
- MFA everywhere (even plant PCs)
- Setpoint range alarms critical (would have flagged)
- Plant PC should not have internet

### Reference

- ABC News — *Oldsmar water attack* (Feb 2021)
- CISA — *Joint Statement on Oldsmar Water Treatment Facility* (2021)

---

## Case 8 — Colonial Pipeline Ransomware (2021)

### Summary

In May 2021, DarkSide ransomware shut down Colonial Pipeline's IT systems. The pipeline itself (OT) was not compromised, but Colonial shut down operations as precaution, causing fuel shortages on US East Coast.

### Timeline

- 2021-05-07: Colonial Pipeline IT systems encrypted
- 2021-05-07: Pipeline shut down (precaution)
- 2021-05-09: US East Coast fuel shortage
- 2021-05-13: Pipeline restart after ransom paid

### Attack Chain

1. **Initial access**: compromised VPN password (reused, found in breach)
2. **No MFA on VPN**
3. **Lateral movement**: IT network
4. **Active Directory compromise**: domain admin
5. **OT network NOT touched** (OT was air-gapped from IT)
6. **Ransomware deployment**: IT systems encrypted
7. **Colonial precautionary shutdown**: because IT controls billing/ops

### IOCs

- VPN login from non-authorized IP
- Lateral movement via PsExec
- Cobalt Strike beacon
- File encryption events

### Blue-Team Detection

```yaml
title: VPN login from non-approved country
logsource:
  product: vpn
detection:
  selection:
    event: login-success
  notApproved:
    src.country|re: !US|CA|MX
  condition: selection and notApproved
level: high
```

### Lessons Learned

- IT compromise can force OT shutdown even without direct OT access
- MFA everywhere
- Strong password policy
- Segregated OT networks prevented worse outcome
- Backup + IR plan critical

### Reference

- CISA AA21-131A — *DarkSide Ransomware*
- FBI Investigation
- Joseph Blount (Colonial CEO) testimony

---

## Case 9 — FrostyGoop (2024)

### Summary

In 2024, Claroty disclosed FrostyGoop — ICS malware targeting Modbus for heating systems. Used in Ukraine attack on municipal heating, leaving civilians without heat in winter.

### Timeline

- 2024-04: Initial discovery
- 2024-06: FrostyGoop deployment in Ukraine
- 2024-06-13: Claroty public disclosure

### Attack Chain

1. **Initial access**: VPN / supply chain compromise
2. **OT network reach via historian**
3. **Modbus TCP enumeration** of heating PLCs
4. **Sensor spoofing + setpoint manipulation**
5. **Heating output**: lowered to render homes unlivable in winter
6. **No alarms tripped**: stealthy

### IOCs

- Modbus TCP write to setpoint register from non-master IP
- Heating output below safe minimum for sustained period
- New Modbus master connection from IT network

### Blue-Team Detection

```yaml
title: FrostyGoop Modbus write to heating setpoint
logsource:
  product: zeek
  service: modbus
detection:
  selection:
    func: write_single_register
    address|re: ^4[0-9]{4}$  # setpoint range
  notLegitMaster:
    src|re: !^10\.0\.0\.1$
  condition: selection and notLegitMaster
level: critical
```

### Lessons Learned

- Modbus remains universal attack vector
- Heating / cooling systems (often forgotten) are critical
- Setpoint changes need audit + alerting
- Modbus gateway with auth critical

### Reference

- Claroty — *FrostyGoop: ICS Malware* (2024)
- Mandiant — *FrostyGoop Analysis* (2024)

---

## Case 10 — Rockwell ControlLogix CVE-2024-6184 Mass Exploitation (2024)

### Summary

In 2024, Rockwell disclosed CVE-2024-6184 affecting ControlLogix 5580, CompactLogix 5380, GuardLogix 5580 — pre-auth project file read. Mass exploitation followed in critical manufacturing.

### Timeline

- 2024-05-14: Rockwell PSIRT advisory
- 2024-05-20: PoC published
- 2024-06-01: Mass exploitation begins
- 2024-07-15: Patches available

### Affected Versions

- ControlLogix 5580 v35.011 and earlier
- CompactLogix 5380 v35.011 and earlier
- GuardLogix 5580 v35.011 and earlier

### Attack Chain

1. **Recon**: Shodan for port 44818
2. **CVE-2024-6184 exploit**: read project file without auth
3. **Project file analysis**: extract PLC program, tag DB, control logic
4. **Craft attack**: based on extracted program
5. **Phase 2**: write access via separate CVE (CVE-2024-6194)

### IOCs

- EtherNet/IP read of project file from non-authorized IP
- Anomalous port 44818 traffic from internet
- Project file size leak (response size matches known project file)

### Blue-Team Detection

```yaml
title: Rockwell CVE-2024-6184 exploitation
logsource:
  product: zeek
  service: enip
detection:
  selection:
    operation: read
    class_id|re: 0x73|0x74  # project file class
    response_size|re: ^[0-9]{5,}$
  notEWS:
    src|re: !^10\.0\.0\.10$
  condition: selection and notEWS
level: critical
```

### Lessons Learned

- Patch within 30 days of CVE disclosure (OT slower than IT but critical)
- Network segmentation: PLCs not reachable from internet
- Project file encryption

### Reference

- Rockwell PSIRT — *CVE-2024-6184 Advisory*
- CISA ICS Advisory ICSA-24-214-01

---

## Cross-Cutting Patterns

Across the 10 cases, the following patterns recur:

### Pattern 1 — OT/IT convergence creates new attack surface

Cases 1, 4, 8 involved OT/IT bridges. Air-gaps are rare; bridges are common.

**Mitigation**:
- Purdue Model adherence
- DMZ jump host with monitoring
- Bridge-mode firewall

### Pattern 2 — ICS-specific malware is iterative

Stuxnet → Industroyer → TRITON → Pipedream → Industroyer2 → FrostyGoop. Each iteration refines techniques.

**Mitigation**:
- Track ICS-specific malware reports
- Test detection rules against new variants
- Industry-wide threat intel sharing

### Pattern 3 — Default credentials persist

Cases 6, 7 involved default credentials (Unitronics 987654321, TeamViewer weak password).

**Mitigation**:
- Force password rotation on init
- Strong password policy
- Vendor default inventory

### Pattern 4 — Internet-exposed OT is the new norm

Cases 6, 10 involved internet-exposed PLCs.

**Mitigation**:
- OT NEVER internet-facing
- Continuous Shodan / Censys monitoring
- Vendor disable remote access by default

### Pattern 5 — Wiper modules standard for evidence destruction

Cases 2, 5 used wipers (CaddyWiper, etc.) to destroy forensic evidence.

**Mitigation**:
- Real-time log forwarding off-host
- WORM (write-once-read-many) logging
- Behavioral detection of file deletion

### Pattern 6 — SIS bypass is rare but catastrophic

Case 3 (TRITON) demonstrated SIS bypass.

**Mitigation**:
- SIS on physically separate network
- No write access from non-SIS hosts
- Periodic SIS logic validation

### Pattern 7 — Vendor CERTs critical

All cases required vendor CERT coordination.

**Mitigation**:
- Subscribe to vendor CERT feeds (Siemens, Rockwell, Schneider)
- Patch within 30 days of CVE
- Test patches in staging

---

## Defensive Quick-Reference Checklist

For defenders hardening CPS estates:

### Network
- [ ] OT NEVER internet-facing
- [ ] Purdue Model adherence (L0-L3 separate from L4)
- [ ] DMZ jump host with monitoring
- [ ] Bridge-mode firewall
- [ ] Per-process VLANs
- [ ] Deny east-west by default

### Authentication
- [ ] Default credentials rotated on init
- [ ] Strong PLC passwords (≥ 20 chars)
- [ ] MFA on all remote access
- [ ] Engineering workstation: no internet, no email

### Protocols
- [ ] OPC UA with SignAndEncrypt
- [ ] DNP3-secure (Aggressive Mode)
- [ ] Modbus gateway with auth
- [ ] IEC 62351 on IEC 61850 / 60870-5
- [ ] CIP Security on EtherNet/IP

### PLCs
- [ ] PLC password protection (level 3 on Siemens)
- [ ] Firmware patched within 90 days
- [ ] Daily PLC program hash
- [ ] Continuous program comparison

### SIS
- [ ] SIS on physically separate network
- [ ] No write access from non-SIS hosts
- [ ] Periodic SIS logic validation
- [ ] SIS firmware isolated

### Detection
- [ ] Passive OT monitoring (Claroty / Dragos / Nozomi)
- [ ] Zeek with industrial analyzers
- [ ] Sigma rules for Modbus write, OPC UA anon, S7 STOP
- [ ] Real-time log forwarding off-host
- [ ] WORM logging

### Incident Response
- [ ] OT-specific IR playbook
- [ ] Vendor CERT contacts established
- [ ] Manual operation fallback trained
- [ ] Safety officer engagement protocol

---

## References

- Symantec — *W32.Stuxnet Dossier* (2011)
- Ralph Langner — *To Kill a Centrifuge* (2013)
- Dragos — *CrashOverride* (2017)
- ESET — *Industroyer Analysis* (2017)
- FireEye / Mandiant — *TRITON Attack* (2017)
- Dragos — *Pipedream / Chernovite* (2022)
- Mandiant — *INCONTROLLER / Pipedream* (2022)
- Slovak NBU-CERT — *Industroyer2 Analysis* (2022)
- CISA AA23-335A — Unitronics PLC Attack (2023)
- CISA AA21-131A — DarkSide Ransomware / Colonial Pipeline
- CISA AA21-040A — Oldsmar Water Treatment
- Claroty — *FrostyGoop* (2024)
- Rockwell PSIRT — *CVE-2024-6184 Advisory*
- CISA ICS Advisories — https://www.cisa.gov/ics-advisories
- MITRE ATT&CK for ICS — https://collaborate.mitre.org/attackics/
- Dragos — *Year in Review* (annual)
- Claroty — *Top 50 ICS Vulnerabilities* (annual)
- Nozomi Networks — *Industrial IoT Threat Landscape* (annual)
- "Industrial Network Security" (Knapp, Langill) 4th Edition 2024
- "Hacking Exposed ICS" (Pidgeon, 2024)
- NIST SP 800-82r3 — ICS Security Guide
- ANSI/ISA-99 / IEC 62443
