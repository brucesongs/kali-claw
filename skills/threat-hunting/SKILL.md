---
name: threat-hunting
description: "Proactive threat hunting — MITRE ATT&CK-mapped hunt hypotheses, Sigma detection engineering, SIEM query authoring (Splunk SPL, KQL, Lucene), and SOC workflow integration."
origin: openclaw
version: "0.1.28"
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
  domain: defense
  tool_count: 12
  guide_count: 1
  mitre: "TA0040-Detection"
---





# Skill: Threat Hunting

> **Supplementary Files**:
> - `payloads.md` — MITRE ATT&CK technique reference, Sigma rule authoring, Splunk SPL / Sentinel KQL / Elastic Lucene / ES|QL query libraries, Sysmon & Windows event ID reference, Zeek log fields, common hunt patterns per tactic, YARA rules, Python ATT&CK-mapping pipelines, MISP/OpenCTI correlation, sigma-cli detection-as-code workflow, and a hunt-documentation template
> - `test-cases.md` — Structured test cases (hunt hypothesis development, detection engineering, telemetry hunts, threat-intel correlation, purple-team validation) with severity ratings and summary tables

## Summary

Threat Hunting skill domain covering defense operations.

**Tools**: MITRE ATT&CK Navigator, MITRE CAR, Sigma, YARA, OSSEM, Sysmon, Zeek, Splunk SPL, Microsoft Sentinel KQL, Elastic Stack, MISP, OpenCTI

**Domain**: defense

**MITRE ATT&CK**: TA0040-Detection

## Description

Proactive threat hunting assumes the adversary is already inside. The hunter forms a hypothesis grounded in MITRE ATT&CK techniques — "an attacker who dumped LSASS would leave Sysmon EID 10 against `lsass.exe` with a non-Microsoft signer" — inventories the telemetry required to test it, authors a query in Sigma or platform-native SIEM languages (Splunk SPL, Sentinel KQL, Elastic Lucene / ES|QL), triages results against known-good baselines, and promotes validated hits into durable detections. Every hunt produces either a detection (good) or a documented gap (also good — gap is now known).

**Difference from `logging-monitoring`**: Logging & monitoring is *infrastructure* — centralized collection, tamper-proof storage, retention, and the OWASP A09 mindset that "events must be recorded at all." Threat hunting is *analytic* — it consumes those logs and asks "given what we collect, where would a specific TTP hide?" You can't hunt what isn't logged; you can log forever and never hunt. They are paired: `logging-monitoring` builds the sensor grid, `threat-hunting` walks it with intent.

**Difference from `digital-forensics`**: DFIR is *post-fact* and *case-scoped* — an incident is declared, evidence is preserved under chain of custody, and the timeline of one specific compromise is reconstructed. Threat hunting is *proactive* and *hypothesis-scoped* — there may be no known incident; the hunter is testing whether a class of activity is present anywhere in the environment. A hunt that finds something becomes an IR trigger; a hunt that finds nothing still produces a documented negative result that constrains future hunts.

**Difference from `incident-response` (engagement-manager adjacent)**: IR follows a runbook after an alert fires. Hunting generates the alerts IR will one day respond to. Hunting is upstream of IR; the Sigma rule you ship today is the alert that pages someone tomorrow.

**Purple-team role**: Threat hunting is the defensive half of a purple-team loop. Red team emulates a TTP (e.g., `T1003.001` LSASS dumping via `comsvcs.dll`); blue team hunts for it, ships a Sigma detection, and the next red-team run either evades it (new detection gap surfaced) or gets caught (detection validated). This skill is the blue half of that loop — every offensive skill in the workspace (`ad-ldap-attack`, `credential-dumping` patterns, `lateral-movement` patterns, `persistence` mechanisms, `exfiltration` channels) becomes a hunt hypothesis.

## Use Cases

- **Hunt for living-off-the-land (LOLBins)**: Adversaries use signed binaries — `certutil.exe`, `rundll32.exe`, `wmic.exe`, `mshta.exe`, `regsvr32 /u /s /i:http://...` — to blend into normal admin activity. Hunt: Sysmon EID 1 process creation where the parent is `winword.exe` and the child is one of the LOLBins list.
- **Hunt for credential dumping**: `T1003` sub-techniques (LSASS via `Mimikatz`/`comsvcs.dll`/`procdump`, SAM/SYSTEM registry hives via `reg save`, NTDS.dit via `ntdsutil` or `Copy-VSS`). Hunt: Sysmon EID 10 process access on `lsass.exe` with `GrantedAccess` 0x1410 / 0x1010 / 0x143a.
- **Hunt for lateral movement**: `T1021` (RDP/SMB/WinRM), `T1550` (pass-the-hash / pass-the-ticket), `T1570` (lateral tool transfer). Hunt: Windows EID 4624 type 3 (network logon) from a non-DHCP source IP at an unusual hour, followed within 5 minutes by EID 4688 process creation of `powershell.exe` or `wmic.exe`.
- **Hunt for C2 beaconing**: `T1071` (application layer protocols — HTTP/HTTPS/DNS), `T1571` (non-standard ports), `T1572` (protocol tunneling), `T1573` (encrypted channels). Hunt: Zeek `conn.log` showing periodic (~60s ±10% jitter) small-payload outbound flows from one host to one destination IP, persistent over 24h.
- **Hunt for persistence mechanisms**: `T1547` (run keys / startup folder / WMI subscriptions), `T1053` (scheduled tasks), `T1546` (event-triggered execution — WMI event consumers), `T1136` (account creation). Hunt: EID 4698 (task creation) where the task author differs from the prior baseline by user, OR `schtasks` invoked by `wscript.exe`/`cscript.exe`/`mshta.exe`.
- **Hunt for data exfiltration**: `T1041` (C2 channel exfil), `T1048` (exfil over alternative protocol — DNS/ICMP), `T1567` (exfil to cloud storage). Hunt: Zeek `dns.log` showing >2KB of base64 in `TXT` queries to one domain over 1h, OR NetFlow showing sustained 95th-percentile upload from one internal host to a cloud object store outside the corporate cloud tenant list.
- **Hunt for supply-chain compromise**: `T1195` (supply-chain compromise — SolarWinds, 3CX, XZ-utils patterns). Hunt: EID 7 (image loaded) where the signer thumbprint of a previously-trusted binary changed in the last 30 days, OR `certutil -hashfile` on signed executables whose hash is not in the SBOM.
- **Hunt for insider threat**: anomalous off-hours access to a sensitive share by a privileged user; `tar`/`7z`/`rar` archiving of `\\fileserver\HR\` followed by USB insertion events; print-spooler spikes at 02:00. Combine host telemetry (Sysmon), network telemetry (Zeek), and identity telemetry (DC EID 4662).

## Core Tools

### Frameworks & Methodologies

| Framework | Purpose | Command / Usage |
|-----------|---------|-----------------|
| **MITRE ATT&CK Enterprise** | Canonical TTP taxonomy — 14 tactics, ~200 techniques, ~400 sub-techniques | Reference `T<id>` (e.g., `T1003.001`) on every hunt hypothesis |
| **MITRE ATT&CK Navigator** | Visualize technique coverage as heatmap layers; diff red-team-emulated vs blue-detected | Upload JSON layer; green = detected, red = not detected, yellow = partially |
| **MITRE CAR** (Cyber Analytics Repository) | Open-source analytics mapped to ATT&CK with pseudocode + implementations | `car-2013-04-002` = "SMB write request" → SPL/ESQL on the page |
| **Sigma** | Vendor-neutral signature format for log detection (the "YARA for logs") | Author `.yml`, ship to `sigma-cli`, translate to Splunk/Sentinel/Elastic/etc. |
| **YARA** | Pattern-matching scanner for files & memory (malware family classification) | `yara -r rules.yar /opt/samples/` or against a process dump |
| **OSSEM** | Open Source Security Events Metadata — common data model across EDR/Sysmon | Field-mapping reference: `process_name` → `Image` (Sysmon) / `ProcessName` (WinEvent) |

### Data Sources (Sensors)

| Source | Coverage | Key Events |
|--------|----------|------------|
| **Sysmon (System Monitor)** | Windows host — process, network, file, registry, image-load, DNS | EID 1 (create), 3 (network), 7 (image load), 8 (remote thread), 10 (process access), 11 (file create), 13 (registry), 22 (DNS) |
| **Zeek (Bro)** | Network — full-session protocol logs | `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`, `x509.log` |
| **Windows Event Logs** | Windows host & DC — auth, object access, task scheduling | EID 4624 (logon), 4625 (failed), 4648 (explicit creds), 4661 (SAM), 4688 (process create), 4698 (task create), 4720 (user created), 5140/5145 (SMB share) |
| **EDR Telemetry** | CrowdStrike / Defender for Endpoint / SentinelOne — process tree, file hash, command line | Vendor APIs — CrowdStrike Falcon `/detects/entities`, Defender `AdvancedHunting`, SentinelOne `threats` API |
| **NetFlow / IPFIX** | Router/switch flow records — volume, direction, conversation | `nfcapd` collector → `nfdump -R . -s srcip/flows` for top-talkers and beacon-shape detection |
| **DNS logs** (Pi-hole, AD DNS, Cisco Umbrella, BlueCat) | Recursive resolver query stream | `qname`, `qtype`, `rcode` — pivot point for `T1071.004` DNS tunneling & DGAs |

### SIEM Platforms

| Platform | Query Language | Example Hunt |
|----------|----------------|--------------|
| **Splunk** | SPL (Search Processing Language) | `index=win EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1010 \| stats count by host, SourceImage` |
| **Microsoft Sentinel** | KQL (Kusto Query Language) | `DeviceProcessEvents \| where FileName =~ "lsass.exe" \| where ActionType == "ProcessAccess" \| where RequestedAccess in ("0x1010","0x1410")` |
| **Elastic Stack / OpenSearch** | Lucene + ES|QL + KQL (Kibana) | `event.code:"10" AND process.name:"lsass.exe" AND winlog.event_data.GrantedAccess:"0x1010"` |
| **IBM QRadar** | AQL (Ariel Query Language) | `SELECT sourceip, destinationip FROM events WHERE eventid = 'ProcessAccess' AND payload CONTAINS 'lsass.exe'` |
| **Sumo Logic** | Sumo CSE / Search | `_sourceCategory=windows/winserver "EventCode=10" "lsass.exe"` |

### Hunting Platforms & Analytics Tools

| Platform | Purpose |
|----------|---------|
| **ThreatHunting-App** (Splunk app) | Pre-built hunts with MITRE mappings, used as a curriculum for SOC analysts |
| **HELK** (Hunting ELK) | Pre-built ELK stack + Sigma + Jupyter notebooks for hunting research |
| **TABI** (Threat ABility Identification) | Maps hunt hypotheses to technique coverage gap analysis |
| **hunters** (Hunters.ai / OpenHunters) | Automated hunt library for data lakes |
| **Apache Spot** (incubator) | Open network-threat detection on NetFlow + DNS |

### Threat Intelligence

| Source | Purpose | API |
|--------|---------|-----|
| **MISP** | Open-source threat intel platform — IOC sharing, galaxy, taxonomies | `POST /events/index` with JSON; `pymisp` Python client |
| **OpenCTI** | Knowledge graph on observables, indicators, intrusion-sets, campaigns | GraphQL; `pycti` Python client |
| **VirusTotal** | File/hash/domain reputation | `GET /api/v3/files/{hash}` — note: rate-limited without enterprise |
| **AlienVault OTX** | Community-sourced pulses (TTPs + IOCs) | `GET /api/v1/indicators/manifest` |
| **Abuse.ch** | MalwareBazaar (samples), URLhaus (malicious URLs), ThreatFox (IOCs) | `POST` to `https://urlhaus-api.abuse.ch/v1/payload/` |

## Methodology

### Threat-Hunting Five-Phase Process

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5
Hypothesis      →  Telemetry       →  Query           →  Triage &        →  Document &
Formation          Inventory           Authoring          Investigate         Detect
   │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼
ATT&CK technique,  What logs do we   Sigma rule +       Filter baseline,   Hunt report +
Pyramid-of-Pain    have? Sysmon,     SIEM-native        enrich with intel, detection rule
elevation target   Zeek, EDR, NetFlow translation      timeline rebuild   (Sigma → SIEM)
```

**Phase 1: Hypothesis Formation**

A hunt without a hypothesis is "staring at logs." A hunt with a hypothesis is testable.

```
Hypothesis: An attacker who performed credential dumping via comsvcs.dll (T1003.001)
            would have invoked rundll32.exe with arguments like:
              C:\Windows\System32\comsvcs.dll MiniDump <pid> <path> full
            Sysmon EID 1 should capture this; Sysmon EID 10 should capture the
            follow-on process-access event against lsass.exe.

Question to test:    Did rundll32.exe spawn with "MiniDump" in its command line
                     on any host in the last 7 days?

Pyramid-of-Pain:     TTP-level hunt (highest pain to adversary if detected).
ATT&CK ID:           T1003.001 — LSASS Memory
Data required:       Sysmon EID 1 (process creation) + EID 10 (process access)
Confidence if hit:   HIGH — comsvcs MiniDump is not used by legitimate software
```

**Phase 2: Telemetry Inventory**

Verify the data exists. Hunting a hypothesis against absent data wastes everyone's time.

```bash
# Splunk: does index=win contain EventCode=1 from Sysmon in the last 24h?
index=win source="*Sysmon*" EventCode=1 earliest=-24h | stats count

# Sentinel: does DeviceProcessEvents have data?
DeviceProcessEvents | summarize count() by bin(TimeGenerated, 1h) | render timechart

# Elastic: does the filebeat-sysmon index have EID 1?
GET filebeat-*/_count
{ "query": { "bool": { "filter": [
  { "term": { "event.code": "1" } },
  { "term": { "winlog.provider_name": "Microsoft-Windows-Sysmon" } }
] } } }
```

If the data is missing, file a sensor gap (this is itself a hunt output).

**Phase 3: Query Authoring**

Write the query in Sigma first (vendor-neutral, future-proof), then translate to the active SIEM via `sigma-cli`.

```yaml
# Sigma rule (vendor-neutral)
title: Suspicious comsvcs.dll MiniDump Invocation
id: 09e5f7d2-25a6-11ee-be56-0242ac120002
status: experimental
description: Detects rundll32 loading comsvcs.dll with MiniDump arguments — T1003.001
author: kali-claw threat-hunting skill
references:
  - https://attack.mitre.org/techniques/T1003/001/
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  condition: selection
level: high
```

```bash
# Translate to Splunk SPL
sigma-cli convert \
  -t splunk \
  -p sysmon \
  sigma/comsvcs-minidump.yml

# Translate to Sentinel KQL
sigma-cli convert -t kibana-ndjson sigma/comsvcs-minidump.yml
# (then to KQL via sentinel-specific backend)
```

**Phase 4: Triage & Investigate**

The first run will over-trigger. Triage by signal-to-noise.

```bash
# Baseline: how often does rundll32 legitimately spawn on this fleet?
index=win EventCode=1 Image="*\\rundll32.exe"
| stats count by host, Image
| sort -count

# Subtract legitimate parent processes (Group Policy, SCCM, in-house tools)
index=win EventCode=1 Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*MiniDump*"
| where NOT match(ParentImage, "(?i)(gpo|sccm|inhouse)")
| stats values(host) as hosts, values(ParentImage) as parents by _time, User
| sort -_time
```

For each surviving hit, enrich: pull process tree, EDR verdict on the parent, hash reputation on the binary, network telemetry in the surrounding 5 minutes. Build a one-page mini-timeline per hit.

**Phase 5: Document & Detect**

Two outputs, every hunt:

1. **Hunt report** — markdown file capturing hypothesis, query, triage table, findings (positive or negative), and recommended follow-on hunts.
2. **Detection rule** — Sigma YAML, tested against historical data, shipped to the SIEM with a documented false-positive rate.

```bash
# Test the Sigma rule against historical data
sigma-cli convert -t splunk sigma/comsvcs-minidump.yml | splunk search -e -30d

# If FP rate < 5%, ship to the detections repo
git add sigma/comsvcs-minidump.yml
git commit -m "feat(detection): T1003.001 comsvcs.dll MiniDump (FP <5% over 30d)"
```

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Know the TTP, want to know if it ever happened | Sigma rule + historical lookback | ATT&CK Navigator coverage layer |
| Suspicious host, want to find what it did | Sysmon EID 1 + 10 timeline reconstruction | EDR process-tree export |
| Suspicious domain, want to find who queried it | Zeek `dns.log` + passive DNS pivot | NetFlow for the resolved IP |
| Red-team emulated `T1003.001`, did we catch it? | Purple-team validation hunt | ATT&CK Evaluations methodology |
| Want to inventory ATT&CK coverage gaps | ATT&CK Navigator layer for detections | MITRE CAR + custom analytics |
| Need a new detection but don't know Sigma | `sigma-cli` + SigmaHQ rule repo | SIEM-native query first, port to Sigma |
| Want to enrich an IOC across the fleet | MISP pivot → Sigma match hunt | OpenCTI knowledge-graph query |
| Hunt for DGA / DNS tunneling | Zeek `dns.log` + entropy/length features | Suricata ET rules + JA3/JA3S |

### Defense Perspective

| Defense Output | Description |
|----------------|-------------|
| **Detection-as-code (Sigma)** | Every validated hunt becomes a Sigma rule checked into Git; CI runs `sigma-cli` to translate to each SIEM backend. The Sigma file is the source of truth — the SIEM queries are generated. |
| **Coverage layer** | ATT&CK Navigator layer (`domain = enterprise`, `scores = 0..100`) showing what is detected vs not. Quarterly review with red team. |
| **Sensor gaps log** | Phase 2 telemetry-inventory failures get filed as "we cannot hunt X because we don't log Y." Drives logging roadmap. |
| **False-positive tuning log** | Every detection ships with a target FP rate and a tuning budget. FPs above threshold are tuned within 1 sprint or the detection is deprecated. |
| **Purple-team cadence** | Red team emulates a TTP → blue team has 1 week to detect → blue team ships a Sigma rule → red team re-runs → loop closes. |
| **Feeding offensive skills** | Hunts produce intelligence on adversary tradecraft that feeds `ad-ldap-attack`, `lateral-movement`, `persistence` skills for red-team emulation. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Build a Hunt Hypothesis for Credential Dumping (T1003.001)

Goal: write a one-paragraph hypothesis grounded in ATT&CK, with explicit data requirements and a confidence rating.

```bash
mkdir -p hunts/t1003-001-lsass-comsvcs
cat > hunts/t1003-001-lsass-comsvcs/hypothesis.md <<'EOF'
# Hunt: T1003.001 — LSASS Memory via comsvcs.dll

## Hypothesis
An attacker who has local-admin on a Windows host may dump LSASS memory using
the built-in comsvcs.dll MiniDump function invoked via rundll32.exe. This
technique requires no tool drop and uses signed binaries, making it attractive
for stealth.

## ATT&CK
- Tactic: TA0006 Credential Access
- Technique: T1003 OS Credential Dumping
- Sub-technique: T1003.001 LSASS Memory

## Pyramid-of-Pain level
TTP — highest pain to adversary; they must change procedure.

## Data required
- Sysmon EID 1 (process creation) with command line
- Sysmon EID 10 (process access) with GrantedAccess mask
- (Optional) Sysmon EID 7 (image load) for comsvcs.dll load events

## Detection logic (Sigma)
See sigma/comsvcs-minidump.yml

## Triage plan
1. Baseline: how often does rundll32 legitimately load comsvcs.dll on this fleet?
2. Filter known-good parents (SCCM, Group Policy, in-house IT tools).
3. For each surviving hit: extract parent process tree, hash the parent,
   query VirusTotal, correlate with Zeek outbound traffic in ±5 min.

## Expected outcome
- POSITIVE: at least one hit. Escalate to IR. The hunt becomes a detection.
- NEGATIVE: zero hits over 30d lookback. The Sigma rule ships as a
  future-facing detection; the environment is currently clean for this TTP.

## Confidence if hit
HIGH — comsvcs.dll MiniDump is not used by any legitimate software.
EOF
```

### Exercise 2: Write a Sigma Rule and Translate to Three SIEMs

Goal: author a Sigma YAML, then convert it to Splunk SPL, Sentinel KQL, and Elastic Lucene.

```bash
# Install sigma-cli
pip3 install sigma-cli

# Create the Sigma rule (see Phase 3 above for full YAML)
cat > sigma/comsvcs-minidump.yml <<'EOF'
title: Suspicious comsvcs.dll MiniDump Invocation
id: 09e5f7d2-25a6-11ee-be56-0242ac120002
status: experimental
description: Detects rundll32 loading comsvcs.dll with MiniDump arguments — T1003.001
references:
  - https://attack.mitre.org/techniques/T1003/001/
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  condition: selection
level: high
EOF

# Translate to Splunk
sigma-cli convert -t splunk -p splunk_windows sigma/comsvcs-minidump.yml

# Translate to Elastic Lucene (via kibana-ndjson backend)
sigma-cli convert -t lucene sigma/comsvcs-minidump.yml

# Translate to Sentinel KQL (via azure-sentinel backend, if available)
sigma-cli convert -t azure-sentinel sigma/comsvcs-minidump.yml
```

### Exercise 3: Hunt LOLBins with Sysmon EID 1

Goal: find any instance of a signed LOLBin spawned by an office application.

```bash
# In Splunk
index=win source="*Sysmon*" EventCode=1
ParentImage IN ("*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\outlook.exe")
Image IN (
  "*\\certutil.exe", "*\\rundll32.exe", "*\\regsvr32.exe",
  "*\\mshta.exe", "*\\wmic.exe", "*\\powershell.exe",
  "*\\cmd.exe", "*\\cscript.exe", "*\\wscript.exe"
)
| stats count by host, ParentImage, Image, CommandLine
| sort -count
```

Expected: zero hits in a clean environment. Any hit is a high-priority lead — pivot to EDR process tree and Zeek outbound network for the host.

### Exercise 4: Hunt C2 Beaconing with Zeek DNS Logs

Goal: detect long-lived, low-volume, periodic outbound flows characteristic of a C2 beacon.

```bash
# In Elastic / OpenSearch (filebeat-zeek index)
# Group by (src_ip, dst_ip, dst_port); compute inter-arrival-time std-dev over 24h
POST filebeat-*/_search
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-24h" } } },
  "aggs": {
    "convos": {
      "composite": {
        "sources": [
          { "src": { "terms": { "field": "zeek.conn.id.orig_h" } } },
          { "dst": { "terms": { "field": "zeek.conn.id.resp_h" } } }
        ]
      },
      "aggs": {
        "flow_count": { "value_count": { "field": "zeek.conn.uid" } },
        "bytes_out": { "sum": { "field": "zeek.conn.orig_ip_bytes" } },
        "first": { "min": { "field": "@timestamp" } },
        "last":  { "max": { "field": "@timestamp" } }
      }
    }
  }
}

# Post-process in Python: compute std-dev of inter-arrival times;
# a "beacon-like" convo has flow_count > 100, std-dev < 10s, bytes_out < 50KB total.
```

### Exercise 5: Hunt Lateral Movement with Windows 4624/4688

Goal: find Type 3 (network) logons from an unusual source that immediately spawned a shell.

```bash
# In Sentinel (KQL)
let threshold = time(5min);
let suspiciousLogons = (
  SecurityEvent
  | where EventID == 4624 and LogonType == 3
  | where TimeGenerated > ago(24h)
  | where IpAddress !in (~knownDHCPRange~)
  | project TimeGenerated, Computer, TargetUserName, IpAddress
);
suspiciousLogons
| join kind=inner (
  SecurityEvent
  | where EventID == 4688
  | where FileName in~ ("powershell.exe", "wmic.exe", "cmd.exe", "psexec.exe")
  | project TimeGenerated as ProcTime, Computer, ParentProcessName, FileName, CommandLine
) on Computer
| where ProcTime between (TimeGenerated .. (TimeGenerated + threshold))
| project TimeGenerated, Computer, TargetUserName, IpAddress, FileName, CommandLine
```

### Exercise 6: Hunt Persistence with Autoruns Data

Goal: enumerate every persistence mechanism on a fleet and flag new ones.

```bash
# Collect Autoruns ARN (CSV) from each host via GPO/SCCM
autorunsc.exe -accepteula -a * -c -h -s -v -vt -o %COMPUTERNAME%.csv

# Ship to SIEM; then hunt for NEW entries in the last 7 days
index=autoruns earliest=-7d
| stats latest(entry) as latest_entry by host, entry, location, signer
| eventstats dc(host) as host_count by entry
| where host_count < 3    # novel — only on 1-2 hosts
| sort -host_count

# Key locations to monitor (per MITRE T1547/T1053/T1546)
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run           T1547.001
# HKLM\SYSTEM\CurrentControlSet\Services                       T1543.003
# Scheduled Tasks                                              T1053.005
# WMI Event Subscriptions                                      T1546.003
# Startup folder                                               T1547.001
```

### Exercise 7: Write a Sentinel KQL Detection Query

Goal: ship a query directly to Sentinel for scheduled alerting.

```kql
// T1003.002 — SAM Registry Hive Dump via reg.exe
// Detection: reg.exe invoked with save on SAM|SECURITY|SYSTEM
DeviceProcessEvents
| where FileName =~ "reg.exe"
| where ProcessCommandLine has_any ("save", "export")
  and ProcessCommandLine has_any ("HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

Ship via `az sentinel alert-rule create` (or the Azure Portal → Analytics rule wizard).

### Exercise 8: Write a Splunk SPL Detection Query

Goal: same logic, shipped to Splunk.

```bash
# Splunk detection (saved search)
index=win source="*Sysmon*" EventCode=1
(Image="*\\reg.exe" OR Image="*\\regedit.exe")
CommandLine IN ("*save*HKLM\\SAM*", "*save*HKLM\\SECURITY*", "*save*HKLM\\SYSTEM*")
| stats count by host, User, Image, CommandLine
| where count > 0
| eval mitre_technique="T1003.002"
| eval severity="high"
| sendalert email to=send_to_soc@company.com
```

### Exercise 9: Python Pipeline — ATT&CK Mapping & Hunt Scoring

Goal: programmatically map a list of process events to ATT&CK techniques and score which hosts show the highest attack-surface concentration.

```python
from collections import defaultdict, Counter
from pathlib import Path
import yaml, json

# Load ATT&CK technique → IOC pattern mapping (your curated file)
mapping = yaml.safe_load(Path("attack_patterns.yaml").read_text())
# Example entry:
#   T1003.001:
#     sigma_ref: sigma/comsvcs-minidump.yml
#     patterns:
#       - field: Image, op: endswith, value: "\\rundll32.exe"
#       - field: CommandLine, op: contains, value: "comsvcs.dll MiniDump"

def matches(event: dict, patterns: list) -> bool:
    for p in patterns:
        v = event.get(p["field"], "")
        if p["op"] == "endswith" and not v.endswith(p["value"]):
            return False
        if p["op"] == "contains" and p["value"] not in v:
            return False
    return True

# Stream events from SIEM export (NDJSON)
scores = defaultdict(Counter)   # host → Counter[technique]
with open("events.ndjson") as f:
    for line in f:
        evt = json.loads(line)
        for tech_id, spec in mapping.items():
            if matches(evt, spec["patterns"]):
                scores[evt["Computer"]][tech_id] += 1

# Rank hosts by technique diversity (not raw count)
ranked = sorted(scores.items(),
                key=lambda kv: len(kv[1]),
                reverse=True)
for host, techs in ranked[:20]:
    print(f"{host}: {len(techs)} techniques — {dict(techs)}")
```

## Safety Notes

- **Scope hunts to authorized networks.** Hunting on a network you don't own (or a tenant you don't administer) is unauthorized access — even if your only intent is to read logs. Confirm scope with the asset owner before any hunt.
- **Avoid alerting real attackers.** If you suspect an active intruder, coordinate with IR before running wide-net hunts. A noisy SIEM query against a host the adversary controls can tip them off and trigger destruction (e.g., `vssadmin delete shadows`). Use EDR stealth-mode collection where available.
- **Preserve evidence chain.** A hunt that finds something becomes an IR trigger the moment you confirm a hit. Preserve the host image, memory, and surrounding logs before further investigation — chain of custody starts now.
- **Data minimization.** SIEM queries return PII (usernames, file paths, sometimes message bodies). Restrict hunt exports to the minimum fields needed; don't ship full event bodies to shared folders.
- **Rate-limit your queries.** A 30d wildcard search across 5TB of Splunk data can peg CPU and cause real detections to miss their latency SLO. Use summary indexes and `tstats` for large lookbacks.
- **Jurisdiction & cross-border data.** EU GDPR, China PIPL, and similar regimes treat SIEM-stored logs as personal data. Cross-border SIEM exports (e.g., a US analyst querying EU-hosted logs) may require SCCs or DPF compliance.
- **Hunt reports are sensitive.** A hunt report describing coverage gaps is a roadmap for an adversary who obtains it. Treat hunt reports, Sigma rules, and ATT&CK coverage layers as confidential; store in a restricted repo, not the public wiki.

## Hacker Laws

- **Trust but Verify** — Sigma rules, SIEM queries, and ATT&CK mappings are all subject to drift. A detection that fired correctly on day one can silently fail when the log schema changes, the EDR updates, or the adversary shifts sub-technique. Every hunt validates a detection; every detection must be re-validated quarterly against known-benign and known-malicious samples.
- **Defense in Depth** — No single sensor catches everything. Sysmon sees the host; Zeek sees the network; EDR sees the process tree; NetFlow sees the volume; identity logs see the user. Hunts that span sensors are more resilient than single-source hunts. Build detections that fuse at least two sources where possible.
- **Assume Breach** — The premise of threat hunting is that the adversary is already inside. Hunt accordingly: don't design detections that assume the perimeter will hold, the EDR will block, or the user will behave. Design detections that ask "if they got this far, what would the trail look like?"
- **First Principles Thinking** — Threat hunting is the application of first-principles reasoning to security telemetry. Instead of asking "what alerts am I getting?", ask "what would an adversary have to do to achieve objective X, and what trace would that leave in the data I collect?" The hypothesis is the first principle; the query is the test.
- **Pyramid of Pain** — IOCs (hashes, IPs, domains) are cheap for the adversary to change. TTPs (procedures, techniques) are expensive. Every hunt should aim as high on the Pyramid of Pain as the data allows — TTP-level detections force the adversary to change tradecraft, which is the most painful outcome you can impose.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/hunt-hypothesis-playbook.md` — end-to-end hunt operations, from hypothesis formation through detection-as-code shipping, with a patterns cookbook and triage matrix
- **Related skills**:
  - `skills/logging-monitoring/SKILL.md` — the sensor infrastructure hunting consumes
  - `skills/digital-forensics/SKILL.md` — post-fact investigation when a hunt finds something
  - `skills/ad-ldap-attack/SKILL.md` — offensive counterpart; every technique here is a hunt hypothesis
  - `skills/av-edr-evasion/SKILL.md` — adversary tradecraft to hunt for
  - `skills/post-exploitation/SKILL.md` — post-compromise behavior patterns to hunt
  - `skills/deep-research/SKILL.md` — synthesizing adversary tradecraft from external sources
  - `skills/security-review/SKILL.md` — code-level detection engineering complement
- **External resources**:
  - MITRE ATT&CK Enterprise Matrix: [attack.mitre.org](https://attack.mitre.org/matrices/enterprise)
  - MITRE ATT&CK Navigator: [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator)
  - MITRE CAR (Cyber Analytics Repository): [car.mitre.org](https://car.mitre.org)
  - Sigma project & SigmaHQ rule repo: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
  - sigma-cli: [github.com/SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli)
  - Splunk Security Essentials & SOC2 hunt app: [splunkbase.splunk.com](https://splunkbase.splunk.com)
  - Microsoft Sentinel hunting queries: [github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
  - Elastic Security Labs detections: [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules)
  - SANS Threat Hunting Summit whitepapers: [sans.org](https://www.sans.org)
  - The Pyramid of Pain (David J. Bianco): [detect-response.blogspot.com/2013/03/the-pyramid-of-pain.html](http://detect-response.blogspot.com/2013/03/the-pyramid-of-pain.html)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
