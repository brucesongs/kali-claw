# Threat Hunting Payloads / Detection & Hunt Reference

> Companion to `SKILL.md`. Every query and rule here is reproducible on a SIEM with the listed data source (Sysmon, Zeek, Windows Event Logs, EDR, NetFlow).
>
> Placeholder convention: `<index>` is your SIEM index, `<host>` is a hostname or IP, `<user>` is an account name, `<sigma-rule>.yml` is a Sigma YAML file.

---

## 1. MITRE ATT&CK Reference

### Tactic Overview

| ID | Tactic | What the Hunter Asks |
|----|--------|----------------------|
| TA0043 | Reconnaissance | "Did anyone gather information about us before the attack?" |
| TA0042 | Resource Development | "Did anyone stand up C2 infra, buy certs, register lookalike domains?" |
| TA0001 | Initial Access | "How did they get a foothold? Phishing? Exploit? Supply chain?" |
| TA0002 | Execution | "What did they run first? powershell? cmd? a LOLBin?" |
| TA0003 | Persistence | "How will they survive a reboot? Run keys? Tasks? WMI?" |
| TA0004 | Privilege Escalation | "Did they go from user to SYSTEM? to Domain Admin?" |
| TA0005 | Defense Evasion | "Did they disable Defender, clear logs, tamper with EDR?" |
| TA0006 | Credential Access | "Did they dump LSASS, dump NTDS, intercept Kerberos?" |
| TA0007 | Discovery | "Did they enumerate AD, scan the subnet, list shares?" |
| TA0008 | Lateral Movement | "Did they pivot? RDP? SMB? WinRM? pass-the-hash?" |
| TA0009 | Collection | "Did they find and stage the data they want?" |
| TA0011 | Command and Control | "Are they beaconing out? Over HTTP? DNS? ICMP?" |
| TA0010 | Exfiltration | "Did data leave? To a cloud bucket? Over DNS? Via SMTP?" |
| TA0040 | Impact | "Did they destroy, ransom, or degrade?" |

### High-Frequency Techniques to Hunt

| ATT&CK ID | Name | Key Log Source | Sigma File Pattern |
|-----------|------|----------------|---------------------|
| T1059.001 | PowerShell | Sysmon EID 1, PowerShell EID 4104 | `win_powershell_*` |
| T1003.001 | LSASS Memory | Sysmon EID 10, WinEvent 4663 | `win_lsass_*` |
| T1003.002 | Security Account Manager | Sysmon EID 1, WinEvent 4661 | `win_sam_dump_*` |
| T1003.003 | NTDS.dit | Sysmon EID 1, WinEvent 4661 | `win_ntds_*` |
| T1071.001 | Web Protocols (C2) | Zeek `http.log`, `ssl.log` | `net_http_c2_*` |
| T1071.004 | DNS (C2 / tunneling) | Zeek `dns.log`, AD DNS | `net_dns_*` |
| T1053.005 | Scheduled Task | WinEvent 4698, Sysmon EID 1 | `win_scheduled_task_*` |
| T1547.001 | Registry Run Keys | Sysmon EID 13, WinEvent 4657 | `win_pers_run_key_*` |
| T1546.003 | WMI Event Subscription | Sysmon EID 19/20/21 | `win_wmi_subscription_*` |
| T1021.002 | SMB/Windows Admin Shares | WinEvent 5140/5145 | `win_smb_*` |
| T1550.002 | Pass the Hash | WinEvent 4624 type 8/9/10 | `win_pth_*` |
| T1486 | Data Encrypted for Impact | Sysmon EID 11 (file writes) | `win_ransomware_*` |

---

## 2. Sigma Rule Authoring

### 2.1 Anatomy of a Sigma Rule

```yaml
title: Suspicious comsvcs.dll MiniDump Invocation
id: 09e5f7d2-25a6-11ee-be56-0242ac120002
status: experimental
description: Detects rundll32 loading comsvcs.dll with MiniDump arguments
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: kali-claw threat-hunting skill
date: 2026/06/16
modified: 2026/06/16
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.credential_dumping
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  filter_legitimate_parent:
    ParentImage|startswith:
      - 'C:\Program Files\Microsoft Monitoring Agent\'
      - 'C:\Program Files\SplunkUniversalForwarder\'
  condition: selection and not filter_legitimate_parent
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate crash-dumping utilities (very rare)
level: high
```

### 2.2 Common `logsource` Mappings

| Log Source | What it targets |
|------------|-----------------|
| `product: windows, category: process_creation` | Sysmon EID 1 / WinEvent 4688 |
| `product: windows, category: process_access` | Sysmon EID 10 (process access — for LSASS) |
| `product: windows, category: network_connection` | Sysmon EID 3 |
| `product: windows, category: file_event` | Sysmon EID 11 |
| `product: windows, category: registry_event` | Sysmon EID 12/13/14 |
| `product: windows, category: dns_query` | Sysmon EID 22 |
| `product: windows, service: sysmon` | Sysmon (any event) |
| `product: windows, service: security` | WinEvent Security log |
| `product: linux, category: process_creation` | auditd / syslog |
| `product: zeek` | Zeek (any log) |

### 2.3 Detection Logic Modifiers

| Modifier | Example | Meaning |
|----------|---------|---------|
| `contains` | `CommandLine\|contains: 'MiniDump'` | Substring match |
| `contains|all` | `X\|contains\|all: ['a','b']` | All substrings present |
| `contains|any` | `X\|contains\|any: ['a','b']` | Any substring present |
| `startswith` | `Image\|startswith: 'C:\\Temp'` | Prefix match |
| `endswith` | `Image\|endswith: '\\rundll32.exe'` | Suffix match |
| `re` (regex) | `Image\|re: '(?i).*\\\\(cmd\|powershell)\.exe$'` | PCRE regex |
| `base64` | `CommandLine\|base64: 'some string'` | Base64-encoded match |
| `cidr` | `DestinationIp\|cidr: '10.0.0.0/8'` | IP CIDR match |
| `gt` / `lt` | `GrantedAccess\|gt: '0x1000'` | Numeric compare |

### 2.4 Translating Sigma via `sigma-cli`

```bash
# Install
pip3 install sigma-cli

# List available backends
sigma-cli plugin list

# Convert to Splunk SPL with the Sysmon pipeline
sigma-cli convert \
  -t splunk \
  -p sysmon \
  sigma/comsvcs-minidump.yml

# Convert to Elastic Lucene
sigma-cli convert -t lucene sigma/comsvcs-minidump.yml

# Convert to ES|QL (newer backend)
sigma-cli convert -t eql sigma/comsvcs-minidump.yml

# Convert to Sentinel KQL (via azure-sentinel backend if installed)
sigma-cli convert -t azure-sentinel sigma/comsvcs-minidump.yml

# Batch-convert a directory
sigma-cli convert -t splunk -p sysmon -r sigma/ -o out/splunk/

# Validate rules before shipping
sigma-cli check sigma/
```

### 2.5 Sigma Repository Workflow

```bash
# Clone the SigmaHQ rule repository as a baseline
git clone https://github.com/SigmaHQ/sigma.git
cd sigma

# Inspect rules per tactic
ls rules/windows/process_creation/ | head -20

# Find rules tagged for a specific technique
grep -rl 'attack.t1003.001' rules/

# Validate a custom rule against the schema
sigma-cli check rules/windows/process_creation/proc_creation_win_lsass_dump_comsvcs.yml
```

---

## 3. Splunk SPL Queries

### 3.1 Foundations — `stats`, `tstats`, `datamodel`

```bash
# tstats — blazing-fast over indexed fields (no raw events)
| tstats count where index=win source="*Sysmon*" EventCode=1 by host, _time span=1h

# datamodel — CIM-aligned queries (faster if datamodel acceleration is on)
| tstats count from datamodel=Endpoint.Processes
where Processes.process_name="rundll32.exe"
by Processes.dest, Processes.user, _time span=5m

# stats — group and aggregate
index=win EventCode=1
| stats count, values(Image) as images, dc(host) as host_count by User
| sort -count
```

### 3.2 Common Hunt Patterns

```bash
# Hunt 1: suspicious parent-child relationships (Office → shell)
index=win source="*Sysmon*" EventCode=1
ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\powerpnt.exe","*\\outlook.exe")
Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\mshta.exe","*\\rundll32.exe")
| stats count by _time, host, User, ParentImage, Image, CommandLine
| sort -_time

# Hunt 2: LSASS memory access (T1003.001)
index=win source="*Sysmon*" EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010","0x1410","0x143a","0x1f0fff")
| stats count by _time, host, SourceImage, SourceUser, GrantedAccess
| sort -_time

# Hunt 3: scheduled task creation by suspicious parent
index=win EventCode=4698
(SubjectUserName!="SYSTEM" AND SubjectUserName!="NETWORK SERVICE")
| stats count by _time, host, SubjectUserName, TaskName, TaskContent
| sort -_time

# Hunt 4: rare outbound destinations per host
index=zeek sourcetype=zeek:conn
| stats dc(id.resp_h) as dst_count by id.orig_h
| where dst_count > 50
| sort -dst_count

# Hunt 5: PowerShell with encoded command
index=win source="*Sysmon*" EventCode=1 Image="*\\powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
| eval decoded=if(isnull(decoded), substr(CommandLine, index(CommandLine, " ")+1), decoded)
| stats count by _time, host, User, CommandLine

# Hunt 6: SMB write to admin share (lateral movement)
index=win (EventCode=5140 OR EventCode=5145) ShareName IN ("\\\\*\\ADMIN$","\\\\*\\C$","\\\\*\\IPC$")
| stats count by _time, host, SubjectUserName, IpAddress, ShareName, RelativeTargetName
| sort -_time
```

### 3.3 Multisource Pivot (Zeek + Sysmon + EDR)

```bash
# Find every host where Sysmon saw lsass.exe access AND Zeek saw an outbound
# connection to a non-corporate IP within 5 minutes
[search index=win source="*Sysmon*" EventCode=10 TargetImage="*\\lsass.exe"
 | rename Computer as host
 | fields _time host SourceUser]
| join host max=0 [
    search index=zeek sourcetype=zeek:conn
    | stats count by _time id.orig_h id.resp_h id.resp_p
    | rename id.orig_h as host
  ]
| where abs(_time - _time) < 300
| table _time host SourceUser id.resp_h id.resp_p
```

---

## 4. Microsoft Sentinel KQL Queries

### 4.1 KQL Foundations

```kql
// let — define reusable variables/tables
let lookback = 24h;
let adminUsers = dynamic(["DOMAIN\\Administrator", "DOMAIN\\Domain Admins"]);
let suspiciousParents = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe"]);

// summarize — group and aggregate
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| summarize count() by DeviceName, AccountName, FileName
| order by count_ desc

// join — combine tables
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| join kind=inner (
    DeviceNetworkEvents
    | where TimeGenerated > ago(1h)
  ) on DeviceName
```

### 4.2 Common Hunt Patterns

```kql
// Hunt 1: Office spawning a shell
let lookback = 24h;
let officeApps = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe"]);
let shells = dynamic(["cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where InitiatingProcessFileName in~ (officeApps)
| where FileName in~ (shells)
| project TimeGenerated, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, ProcessCommandLine
| order by TimeGenerated desc;

// Hunt 2: LSASS access
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ProcessAccess"
| where FileName =~ "lsass.exe"
| where RequestedAccess in ("0x1010","0x1410","0x143a","0x1f0fff")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RequestedAccess
| order by TimeGenerated desc;

// Hunt 3: scheduled task creation
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where AccountName !endswith "$"   // exclude computer accounts
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc;

// Hunt 4: PowerShell encoded command
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has any ("-enc","-EncodedCommand","-e ")
| extend encodedBlob = extract(@"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend decoded = base64_decode_tostring(encodedBlob)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, decoded
| order by TimeGenerated desc;

// Hunt 5: pass-the-hash — logon type 9 (NewCredentials) from unusual source
SecurityEvent
| where EventID == 4624
| where LogonType == 9
| where TimeGenerated > ago(24h)
| where IpAddress !in ("127.0.0.1","::1","-")
| summarize count() by IpAddress, TargetUserName, Computer
| where count_ < 5     // novel
| order by count_ asc;

// Hunt 6: DNS tunneling — high-entropy TXT queries
DnsEvents
| where TimeGenerated > ago(1h)
| where Name has ".txt"
| extend label = tostring(split(Name, ".")[0])
| where string_size(label) > 30
| summarize count(), makeset(Name) by ClientIP
| order by count_ desc;
```

### 4.3 Sentinel Sentinel-Specific Patterns

```kql
// Pack analytic + ship as a scheduled rule
// (Azure Portal → Sentinel → Analytics → Create → Scheduled query rule)
// Paste the KQL; set run-every (e.g., 1h) and look-back (e.g., 1h).

// Entity mapping — surfaces entities in the incident UI
DeviceProcessEvents
| where FileName =~ "mimikatz.exe"
| project TimeGenerated,
          AccountName,
          HostName = DeviceName,
          ProcessCommandLine,
          InitiatingProcessFileName
```

---

## 5. Elastic / OpenSearch Queries

### 5.1 Lucene Query Syntax

```text
# Match field equals value
event.code:"1" AND winlog.provider_name:"Microsoft-Windows-Sysmon"

# Wildcards
process.command_line:*comsvcs.dll*MiniDump*

# Boolean groups
(winlog.event_id:"1" AND process.parent.name:(winword.exe OR excel.exe))
AND process.name:(cmd.exe OR powershell.exe)

# Range
@timestamp:[now-24h TO now]

# NOT filter
event.code:"1" AND process.name:"rundll32.exe"
  AND NOT process.parent.name:"svchost.exe"
```

### 5.2 ES|QL

```text
FROM filebeat-*
| WHERE @timestamp > NOW() - INTERVAL 24 HOUR
| WHERE event.code == "1"
| WHERE process.parent.name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| WHERE process.name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","rundll32.exe")
| STATS count = COUNT(*) BY host.name, process.parent.name, process.name
| SORT count DESC
| LIMIT 100
```

### 5.3 Kibana KQL (Kibana Query Language)

```text
event.code: "1" and process.parent.name: ("winword.exe" or "excel.exe")
  and process.name: ("cmd.exe" or "powershell.exe" or "mshta.exe")
  and not process.parent.path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
```

### 5.4 Aggregation via `_search`

```json
POST filebeat-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "term": { "event.code": "1" } }
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "host.name", "size": 50 },
      "aggs": {
        "by_image": { "terms": { "field": "process.name", "size": 20 } }
      }
    }
  }
}
```

---

## 6. Sysmon Event ID Reference

| EID | Name | What It Captures | Top Hunting Use |
|-----|------|------------------|-----------------|
| 1 | ProcessCreate | Process spawn with command line, parent | LOLBins, suspicious parent-child |
| 2 | FileCreateTime | File creation-time change | Timestomping (T1070.006) |
| 3 | NetworkConnect | Outbound / inbound connection | C2 channel discovery |
| 4 | SysmonServiceState | Service state changes | Tamper detection |
| 5 | ProcessTerminate | Process exit | (rarely hunted) |
| 6 | DriverLoad | Kernel driver load | Rootkit / vulnerable driver |
| 7 | ImageLoad | DLL / driver load | In-memory injection, signed-binary abuse |
| 8 | CreateRemoteThread | Cross-process thread creation | Process injection (T1055) |
| 9 | RawAccessRead | Read via `\\.\` device | Disk / memory raw reads |
| 10 | ProcessAccess | Open process handle | LSASS dumping (T1003.001) |
| 11 | FileCreate | File creation | Staging, ransomware |
| 12 | RegistryEvent (Object create/delete) | Registry object create/delete | Persistence keys |
| 13 | RegistryEvent (Value Set) | Registry value write | Run keys, services |
| 14 | RegistryEvent (Key/Value Rename) | Registry rename | Subtle persistence edits |
| 15 | FileCreateStreamHash | Alternate Data Stream | ADS hide-and-seek |
| 16 | ServiceConfigurationChange | Sysmon config change | Tamper detection |
| 17/18 | PipeCreate / PipeConnect | Named pipes | Cobalt Strike pipe names |
| 19/20/21 | WmiEvent (Filter/Consumer/FilterToConsumer) | WMI subscription | T1546.003 persistence |
| 22 | DNSQuery | DNS resolution | C2, exfil, DGA |
| 23 | FileDelete | File deletion (with archive) | Anti-forensics (T1070.004) |
| 24 | ClipboardChange | Clipboard content | Data staging |
| 25 | ProcessTampering | Image hijack | Process hollowing |
| 26 | FileDeleteDetected | File deletion (no archive) | Anti-forensics |
| 27 | FileBlockExecutable | Executable blocked | Defender-style block |

### Recommended Sysmon Configuration

```xml
<!-- SwiftOnSecurity Sysmon config (community standard baseline) -->
<!-- Download: https://github.com/SwiftOnSecurity/sysmon-config -->

<!-- Or olafhartong's sysmon-modular for finer-grained TTP coverage -->
<!-- https://github.com/olafhartong/sysmon-modular -->

# Install
sysmon.exe -accepteula -i sysmonconfig.xml
# Update later
sysmon.exe -c sysmonconfig.xml
```

---

## 7. Windows Event Log Reference

### 7.1 Security Log (High-Value Event IDs)

| EID | Name | What It Captures |
|-----|------|------------------|
| 4624 | Successful logon | Logon type (2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 networkcleartext, 9 newcredentials, 10 remoteinteractive) |
| 4625 | Failed logon | Brute force, password spraying |
| 4634 | Logoff | End of session |
| 4648 | Explicit credentials logon | Run-as, alternative creds |
| 4661 | SAM object access | SAM hive read — T1003.002 |
| 4663 | Object access | File / registry / kernel object access |
| 4670 | Permissions change | DACL change on object |
| 4672 | Admin-equivalent logon | Privileged user logged in |
| 4688 | Process creation | New process (with command line if enabled) |
| 4697 | Service install | New service (often persistence) |
| 4698 | Scheduled task creation | T1053.005 |
| 4720 | User account created | Insider / adversary persistence |
| 4726 | User account deleted | Cover tracks |
| 4732 | Member added to local group | Privilege escalation |
| 4756 | Member added to global group | Domain escalation |
| 4776 | NTLM auth attempt | Lateral movement signal |
| 4779 | Session disconnected (RDP) | RDP session |
| 5140 | SMB share accessed | Lateral movement |
| 5145 | SMB file access detail | Network file ops — exfil, lateral |
| 5156 | Windows Filtering Platform allow | Network connection (host firewall) |

### 7.2 Enable Command-Line Auditing for EID 4688

```bash
# Group Policy
# Computer Configuration → Administrative Templates → System → Audit Process Creation
#   "Include command line in process creation events" → Enabled

# Or via registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" \
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## 8. Zeek Log Reference

### 8.1 Core Log Files

| Log | One Row Per | Key Fields |
|-----|-------------|------------|
| `conn.log` | Connection (5-tuple) | `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `orig_ip_bytes`, `resp_ip_bytes` |
| `dns.log` | DNS query/response | `query`, `qclass`, `qtype_name`, `rcode_name`, `answers`, `TTLs` |
| `http.log` | HTTP request/response | `method`, `host`, `uri`, `user_agent`, `status_code`, `request_body_len`, `resp_mime_types` |
| `ssl.log` | TLS handshake | `server_name` (SNI), `version`, `cipher`, `curve`, `resumed`, `subject`, `issuer` |
| `files.log` | File transfer over any protocol | `source`, `filename`, `sha1`, `sha256`, `seen.bytes`, `mime_type`, `rx_hosts`, `tx_hosts` |
| `x509.log` | X.509 cert details | `certificate.serial`, `certificate.subject`, `certificate.issuer`, `san.dns` |
| `weird.log` | Protocol anomalies | `name`, `addl`, `source`, `peer` |
| `notice.log` | Raised notice (custom or built-in) | `note`, `msg`, `sub`, `src`, `dst`, `peer` |
| `ntlm.log` | NTLM auth | `username`, `domainname`, `servernb_computer_name`, `success` |
| `kerberos.log` | Kerberos | `request_type`, `client`, `service`, `success`, `error_msg` |
| `smb_files.log` | SMB file ops | `action`, `path`, `name`, `size`, `ts` |
| `rdp.log` | RDP | `client_cert_count`, `ssl`, `result` |

### 8.2 Beacon Detection in `conn.log`

```python
# Python — compute beacon characteristics from conn.log
from collections import defaultdict
import json, statistics, sys

convs = defaultdict(list)  # (src, dst, dst_port) -> [timestamps]

for line in open("conn.log"):
    if line.startswith("#"): continue
    f = line.rstrip().split("\t")
    # Zeek TSV columns: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto ...
    ts, src, dst, dport = float(f[0]), f[2], f[4], f[5]
    convs[(src, dst, dport)].append(ts)

for key, ts_list in convs.items():
    if len(ts_list) < 30:    # need volume to compute periodicity
        continue
    ts_list.sort()
    deltas = [b - a for a, b in zip(ts_list, ts_list[1:])]
    if not deltas: continue
    stdev = statistics.pstdev(deltas)
    mean = statistics.mean(deltas)
    if stdev < 5 and mean < 120 and mean > 30:
        print(f"BEACON? {key}  n={len(ts_list)}  mean_iat={mean:.1f}s  stdev={stdev:.1f}s")
```

### 8.3 DNS Tunneling Hunt

```bash
# In Splunk ingesting Zeek dns.log
index=zeek sourcetype=zeek:dns
| eval label_len = len(mvindex(split(query, "."), 0))
| where label_len > 30
| stats count, values(query) as queries, dc(query) as unique_q by id.orig_h, id.resp_h
| sort -count
```

---

## 9. Common Hunt Patterns per MITRE Tactic

### TA0001 — Initial Access

```bash
# T1566 Phishing — Office macro spawning a shell (see Hunt 1, Splunk section)

# T1190 Exploit Public-Facing App — look for crash + restart of web service
index=web sourcetype=access_combined
| transaction clientip maxspan=5m
| where status IN (500, 502, 503)
| stats count by uri_path, status
| sort -count

# T1133 External Remote Services — VPN logon from new geo
index=vpn
| iplocation src_ip
| stats dc(Country) as country_count, values(Country) as countries by user
| where country_count > 2
```

### TA0002 — Execution

```bash
# T1059.001 PowerShell EncodedCommand (see Hunt 5)

# T1127 MSHTA / T1218 Signed Binary Proxy
index=win source="*Sysmon*" EventCode=1
Image IN ("*\\mshta.exe","*\\regsvr32.exe","*\\rundll32.exe","*\\certutil.exe")
| where NOT match(CommandLine, "(?i)(gpo|sccm|in-house)")
| stats count by _time, host, User, Image, CommandLine
```

### TA0003 — Persistence

```bash
# T1547.001 Run keys
index=win source="*Sysmon*" EventCode=13
TargetObject IN (
  "*\\CurrentVersion\\Run\\*",
  "*\\CurrentVersion\\RunOnce\\*",
  "*\\CurrentVersion\\RunOnceEx\\*"
)
| stats count by _time, host, User, TargetObject, Details

# T1053.005 Scheduled Task (see Hunt 3, Splunk)

# T1546.003 WMI subscription — Sysmon EID 19/20/21
index=win source="*Sysmon*" EventCode IN (19,20,21)
| stats count by _time, host, EventType, Query, Consumer, Filter
```

### TA0005 — Defense Evasion

```bash
# T1562.001 Disable Defender
index=win source="*Sysmon*" EventCode=1
(CommandLine="*Set-MpPreference*" AND CommandLine="*-Disable*")
OR (CommandLine="*Uninstall-WindowsFeature*" AND CommandLine="*Defender*")
| stats count by _time, host, User, CommandLine

# T1070.001 Clear Windows Event Log
index=win EventCode=1102   # Security log cleared
| stats count by _time, host, SubjectUserName
```

### TA0006 — Credential Access

```bash
# T1003.001 LSASS (see Hunt 2)
# T1003.002 SAM dump
index=win source="*Sysmon*" EventCode=1
Image="*\\reg.exe" CommandLine="*save*HKLM\\SAM*"
| stats count by _time, host, User, CommandLine

# T1110 Brute force — 5 failures followed by success
index=win EventCode IN (4625, 4624)
| transaction IpAddress maxspan=5m
| where (eventtype=="4625" AND eventtype=="4624")
| stats count by IpAddress, TargetUserName
| where count > 5
```

### TA0007 — Discovery

```bash
# T1087 Account discovery
index=win source="*Sysmon*" EventCode=1
CommandLine IN ("*net user*","*net group*","*Get-ADUser*","*Get-LocalUser*")
| stats count by _time, host, User, CommandLine

# T1046 Network service discovery
index=win source="*Sysmon*" EventCode=3
| stats dc(id.resp_p) as port_count by id.orig_h, id.resp_h
| where port_count > 10
```

### TA0008 — Lateral Movement

```bash
# T1021.002 SMB admin share write
index=win EventCode=5145 ShareName="\\\\*\\ADMIN$"
| stats count by _time, IpAddress, SubjectUserName, RelativeTargetName

# T1550.002 Pass the Hash — Type 8/9/10 logon
index=win EventCode=4624 LogonType IN (8,9,10) AuthenticationPackageName="NTLM"
| stats count by _time, IpAddress, TargetUserName
```

### TA0010 — Exfiltration

```bash
# T1041 C2 channel exfil — large upload to new destination
index=zeek sourcetype=zeek:conn
| stats sum(orig_ip_bytes) as bytes_out by id.orig_h, id.resp_h
| where bytes_out > 100000000    # >100MB
| join type=outer id.resp_h [
    search index=known_corp_ips | dedup ip
  ]
| search NOT ip=*

# T1048.003 DNS exfil
index=zeek sourcetype=zeek:dns qtype_name="TXT"
| eval label_len = len(mvindex(split(query, "."), 0))
| where label_len > 30
| stats count, sum(label_len) as total_label_bytes by id.orig_h, id.resp_h
```

### TA0040 — Impact

```bash
# T1486 Ransomware — rapid mass file modification
index=win source="*Sysmon*" EventCode=11
| bin(_time) span=10s
| stats dc(TargetFilename) as file_count by _time, host, Image
| where file_count > 100
| sort -file_count

# T1490 Volume Shadow Copy delete
index=win source="*Sysmon*" EventCode=1
CommandLine IN ("*vssadmin delete shadows*","*wmic shadowcopy delete*","*wbadmin delete catalog*")
| stats count by _time, host, User, CommandLine
```

---

## 10. YARA Rules for Memory / File Scanning

```yara
// Mimikatz family
rule mimikatz_memory_strings {
  meta:
    description = "Mimikatz in-memory indicators"
    author      = "kali-claw threat-hunting skill"
    date        = "2026-06-16"
  strings:
    $a = "mimikatz" ascii nocase wide
    $b = "gentilkiwi" ascii nocase
    $c = "sekurlsa::logonpasswords" ascii nocase
    $d = "kerberos::ptt" ascii nocase
    $e = "lsadump::sam" ascii nocase
  condition:
    uint16(0) == 0x5a4d and (3 of ($a,$b,$c,$d,$e))
}

// Cobalt Strike beacon
rule cobalt_strike_beacon {
  meta:
    description = "Cobalt Strike beacon strings"
  strings:
    $a = "%%IMPORT%%" ascii
    $b = "%s as %s\\%s: %d" ascii
    $c = "beacon.dll" ascii nocase
    $d = { 4D 5A (90|00) 03 00 00 00 04 00 00 00 FF FF }
  condition:
    uint16(0) == 0x5a4d and (2 of ($a,$b,$c)) or $d
}

// Run a scan
// yara -r rules.yar /opt/suspicious/
// yara -r rules.yar process_dump.bin
```

---

## 11. Python Pipeline — Query ELK, ATT&CK Map, Score Hunts

```python
"""
hunt_pipeline.py — Pull events from ELK, map to ATT&CK, score hosts.
"""
from __future__ import annotations

import os
import json
import logging
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Iterable
import urllib3
import yaml
from elasticsearch import Elasticsearch

urllib3.disable_warnings()
log = logging.getLogger("hunt")


@dataclass(frozen=True)
class Hit:
    host: str
    technique: str
    timestamp: str
    raw: dict


def fetch_events(client: Elasticsearch, index: str, query: dict,
                 lookback: str = "now-24h") -> Iterable[dict]:
    body = {
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": lookback}}},
            query,
        ]}},
        "sort": [{"@timestamp": "asc"}],
        "size": 5000,
    }
    scroll = client.search(index=index, body=body, scroll="2m")
    sid = scroll["_scroll_id"]
    hits = scroll["hits"]["hits"]
    while hits:
        for h in hits:
            yield h["_source"]
        scroll = client.scroll(scroll_id=sid, scroll="2m")
        sid = scroll["_scroll_id"]
        hits = scroll["hits"]["hits"]


def load_patterns(path: str) -> dict[str, dict]:
    """attack_patterns.yaml: technique_id -> {field, op, value}[]"""
    data = yaml.safe_load(open(path).read())
    if not isinstance(data, dict):
        raise ValueError("attack_patterns.yaml must be a mapping")
    return data


def matches(event: dict, patterns: list[dict]) -> bool:
    for p in patterns:
        v = event.get(p["field"], "")
        if p["op"] == "endswith" and not str(v).endswith(p["value"]):
            return False
        if p["op"] == "contains" and p["value"] not in str(v):
            return False
        if p["op"] == "equals" and str(v) != p["value"]:
            return False
    return True


def hunt(client: Elasticsearch, index: str,
         patterns: dict[str, dict]) -> list[Hit]:
    """Stream all process-creation events from ELK, apply patterns."""
    hits: list[Hit] = []
    query = {"term": {"event.code": "1"}}
    for event in fetch_events(client, index, query):
        host = event.get("host", {}).get("name", "?")
        ts = event.get("@timestamp", "?")
        for tech_id, spec in patterns.items():
            if matches(event, spec.get("patterns", [])):
                hits.append(Hit(host, tech_id, ts, event))
    return hits


def score(hits: list[Hit]) -> dict[str, Counter]:
    """Rank hosts by ATT&CK technique diversity."""
    by_host: dict[str, Counter] = defaultdict(Counter)
    for h in hits:
        by_host[h.host][h.technique] += 1
    return by_host


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    es_url = os.environ["ES_URL"]
    es = Elasticsearch(es_url, verify_certs=False)
    patterns = load_patterns("attack_patterns.yaml")

    log.info("Hunting with %d ATT&CK patterns", len(patterns))
    hits = hunt(es, "filebeat-*", patterns)
    log.info("Found %d hits", len(hits))

    by_host = score(hits)
    ranked = sorted(by_host.items(), key=lambda kv: len(kv[1]), reverse=True)
    for host, techs in ranked[:20]:
        log.info("%s: %d techniques — %s", host, len(techs), dict(techs))


if __name__ == "__main__":
    main()
```

---

## 12. Threat Intelligence Correlation

### 12.1 MISP

```bash
# Install pymisp
pip3 install pymisp

# Configure (place in ~/.misp.cfg or env)
# MISP_URL=https://misp.example.com
# MISP_KEY=<api_key>
```

```python
from pymisp import ExpandedPyMISP, MISPAttribute
import os

misp = ExpandedPyMISP(
    url=os.environ["MISP_URL"],
    key=os.environ["MISP_KEY"],
    ssl=False,
)

# Search events matching an IOC
result = misp.search(controller="attributes",
                     type_attribute=["ip-src","ip-dst","domain","sha256"],
                     value="198.51.100.42")
for event in result.get("response", []):
    print(event["Event"]["info"], event["Event"]["threat_level_id"])

# Push a new indicator (after a successful hunt)
attr = MISPAttribute()
attr.from_dict(type="sha256", category="Payload installation",
               value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               comment="Found via Sigma rule sigma/comsvcs-minidump.yml",
               to_ids=True)
misp.add_attribute(event_id=42, attribute=attr)
```

### 12.2 OpenCTI

```python
from pycti import OpenCTIApiClient
import os

client = OpenCTIApiClient(
    os.environ["OPENCTI_URL"],
    os.environ["OPENCTI_TOKEN"],
)

# Query indicators observable by value
indicators = client.indicator.list(
    filters=[{"key": "observable_value", "values": ["198.51.100.42"]}],
)
for ind in indicators:
    print(ind["name"], ind["pattern_type"], ind["pattern"])

# Pivot from indicator to intrusion set
for ind in indicators:
    rels = client.stix_core_relationship.list(
        filters=[{"key": "fromId", "values": [ind["id"]]}]
    )
    for r in rels:
        print(ind["name"], "->", r["entity_type"], r["to"]["name"])
```

### 12.3 VirusTotal

```bash
# Hash reputation
curl -s -H "x-apikey: $VT_API_KEY" \
  https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  | jq '.data.attributes.last_analysis_stats'
```

---

## 13. Detection Engineering Workflow

### 13.1 The Detection Lifecycle

```
Develop  →  Test (history)  →  Review  →  Deploy  →  Tune  →  (Deprecate)
   │             │                  │            │           │            │
   ▼             ▼                  ▼            ▼           ▼            ▼
Sigma YAML,  Run against      Peer review,  CI ships to  FP triage,   Removal when
threat       historical       ATT&CK tag,   SIEM via     threshold    coverage moves
intelligence data (30d+),     doc, naming   sigma-cli    tuning,      to EDR or it
links, ATT&CK FP rate target                audit log    decay        no longer fires
```

### 13.2 `sigma-cli` Multi-SIEM Translation Pipeline

```bash
# Directory layout
sigma/
├── rules/
│   ├── credential_access/
│   │   └── comsvcs_minidump.yml
│   ├── persistence/
│   │   └── run_key_new_entry.yml
│   └── ...
├── pipelines/
│   ├── splunk-sysmon.yml
│   └── splunk-winevent.yml
└── Makefile

# Makefile
SIGMA := sigma-cli
BACKENDS := splunk lucene eql azure-sentinel

all: $(addprefix out-, $(BACKENDS))

out-%:
	@mkdir -p out/$*
	$(SIGMA) convert -t $* -r sigma/rules/ -o out/$*/ sigma/rules/

check:
	$(SIGMA) check sigma/rules/

test:
	$(SIGMA) check sigma/rules/
	$(MAKE) all
	@echo "Translated rules: $$(find out -name '*.yml' | wc -l)"
```

### 13.3 Sigma Rule Naming & Tagging Convention

| Field | Convention |
|-------|------------|
| `title` | `<verb-phrase>` — "Suspicious comsvcs.dll MiniDump Invocation" |
| `id` | UUID v4 (stable across edits) |
| `status` | `experimental` → `test` → `stable` |
| `level` | `informational` / `low` / `medium` / `high` / `critical` |
| `tags` | Always include `attack.<tactic>` and `attack.t<technique>` |
| `falsepositives` | List of known FPs (drives `filter_*` clauses) |

### 13.4 Detection CI

```yaml
# .github/workflows/sigma-ci.yml
name: Sigma CI
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip3 install sigma-cli
      - run: sigma-cli check sigma/rules/
  translate:
    needs: check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip3 install sigma-cli
      - run: |
          for backend in splunk lucene eql; do
            mkdir -p out/$backend
            sigma-cli convert -t $backend -r sigma/rules/ -o out/$backend/ sigma/rules/
          done
      - uses: actions/upload-artifact@v4
        with: { name: translations, path: out/ }
```

---

## 14. Hunt Documentation Template

```markdown
# Hunt: <ATT&CK ID> — <Technique Name>

**Author**: <name>      **Date**: <YYYY-MM-DD>
**Status**: Planning / Active / Closed
**ATT&CK**: T<id> (<tactic>)      **Pyramid-of-Pain level**: TTP

## 1. Hypothesis
<one paragraph: what an attacker would have done, and what trace it would leave>

## 2. Data Required
| Source | Field(s) | Retention |
|--------|----------|-----------|
| Sysmon EID 1 | Image, CommandLine, ParentImage | 90d |
| Zeek conn.log | id.orig_h, id.resp_h, duration | 30d |

## 3. Query
```bash
<Sigma YAML or SIEM-native query>
```

## 4. Triage Plan
1. Baseline legitimate usage on this fleet.
2. Filter known-good parents / users / hosts.
3. For each surviving hit: enrich (EDR, VT, MISP, surrounding network).

## 5. Findings
- Lookback window: <start> → <end>
- Hosts scanned: <N>
- Total hits: <N>
- True positives: <N>
- False positives: <N>  →  FP rate: <X>%

## 6. Detection Outcome
- [ ] Sigma rule shipped to `sigma/rules/<tactic>/<name>.yml`
- [ ] CI translation pipeline green
- [ ] SIEM detection active with severity = <level>
- [ ] ATT&CK Navigator coverage layer updated

## 7. Follow-on Hunts
- <Next hypothesis generated by this hunt>

## 8. References
- ATT&CK: https://attack.mitre.org/techniques/T<id>/
- Sigma: <repo link>
- Internal IR ticket: <link>
```

---

## 15. Quick-Reference Cheat Sheet

### Sigma Field Modifiers (Most-Used)

| Modifier | When |
|----------|------|
| `contains` | Substring match (most common) |
| `contains|all` | Multiple required substrings |
| `endswith` | File path / process name suffix |
| `startswith` | Path prefix (whitelist legitimate parents) |
| `re` | Regex — use sparingly (slow) |

### Sysmon "Must-Hunt" Event IDs

| EID | For |
|-----|-----|
| 1 | Process creation (LOLBins, suspicious parents) |
| 3 | Network connection (C2 channel) |
| 7 | Image load (signed-binary abuse, in-memory injection) |
| 10 | Process access (LSASS dumping) |
| 11 | File create (staging, ransomware) |
| 13 | Registry value set (persistence) |
| 22 | DNS query (C2, exfil) |

### Splunk SPL "Always Useful"

```bash
# Fast count by field
| stats count by <field>

# Top N
| top limit=20 <field>

# Time-bucket
| bin(_time) span=1h | stats count by _time

# tstats — fastest
| tstats count where index=X by host, _time span=5m

# Join two searches
| join <field> max=0 [ search ... ]
```

### KQL "Always Useful"

```kql
// Time filter
| where TimeGenerated > ago(24h)

// Group + count
| summarize count() by DeviceName, FileName

// Top
| top 20 by count_ desc

// Join
| join kind=inner (OtherTable | where ...) on DeviceName

// Parse a string
| extend user = extract(@"\\(.+)$", 1, AccountName)
```

### Lucene "Always Useful"

```text
# AND / OR / NOT
a:b AND (c:d OR c:e) AND NOT f:g

# Wildcards
file.hash.md5:abc*

# Range
@timestamp:[now-24h TO now]

# Existence
process.parent.name:*
```

---

**Related files**: `SKILL.md`, `test-cases.md`, `guides/hunt-hypothesis-playbook.md`
**External resources**: MITRE ATT&CK, Sigma project, Splunk Security Essentials, Sentinel hunting queries, Elastic Security Labs
