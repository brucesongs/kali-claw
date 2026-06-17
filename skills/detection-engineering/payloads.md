# Detection Engineering Payloads

> Companion to `SKILL.md`. Concrete authoring patterns, command-line recipes, and rule templates for Sigma, YARA, SigmaCLI, yarGen, Loki, Splunk SPL, Kusto KQL, Elastic EQL, hayabusa, zircollo, ATT&CK mapping, detection CI/CD, FP tuning, and the detection-as-code lifecycle.
> All commands assume an authorized environment — own tenant, signed-off engagement, or a controlled lab with EVTX-ATTACK-SAMPLES and a benign EVTX corpus.

---

## Table of Contents

1. [Sigma Rule Anatomy](#1-sigma-rule-anatomy)
2. [Sigma Rule Authoring Patterns](#2-sigma-rule-authoring-patterns)
3. [SigmaCLI Usage](#3-sigmacli-usage)
4. [YARA Rule Anatomy](#4-yara-rule-anatomy)
5. [YARA Rule Authoring Patterns](#5-yara-rule-authoring-patterns)
6. [yarGen — Auto Rule Generation from Samples](#6-yargen--auto-rule-generation-from-samples)
7. [Loki — IOC + YARA Scanner](#7-loki--ioc--yara-scanner)
8. [Splunk SPL Detection Patterns](#8-splunk-spl-detection-patterns)
9. [Kusto KQL Detection Patterns (Sentinel)](#9-kusto-kql-detection-patterns-sentinel)
10. [Elastic EQL / Lucene Detection](#10-elastic-eql--lucene-detection)
11. [hayabusa — Sigma-to-EVTX Fast Scanning](#11-hayabusa--sigma-to-evtx-fast-scanning)
12. [zircollo — Sigma-to-EVTX Offline](#12-zircollo--sigma-to-evtx-offline)
13. [MITRE ATT&CK Mapping](#13-mitre-attck-mapping)
14. [Detection CI/CD (GitHub Actions, GitLab CI)](#14-detection-cicd-github-actions-gitlab-ci)
15. [False-Positive Tuning Methodology](#15-false-positive-tuning-methodology)
16. [Detection-as-Code Lifecycle](#16-detection-as-code-lifecycle)

---

## 1. Sigma Rule Anatomy

Sigma is a vendor-neutral YAML signature format for log detection — "YARA for logs." Author once, translate to any SIEM via SigmaCLI.

### 1.1 Top-Level Structure

```yaml
title: <human-readable title>              # REQUIRED
id: <uuid-v4>                              # REQUIRED — globally unique
related:                                    # OPTIONAL — link to related rules
  - id: <uuid>
    type: derived | obsoletes | renamed | similar
status: experimental | test | stable | deprecated  # REQUIRED
description: >-                             # REQUIRED — 1-3 sentences
  What the rule detects and the TTP covered.
references:                                 # RECOMMENDED — URLs to TI / ATT&CK
  - https://attack.mitre.org/techniques/T1003/001/
  - https://vendor.com/blog/...
author: <name or org>                       # RECOMMENDED
date: YYYY/MM/DD                            # RECOMMENDED — authoring date
modified: YYYY/MM/DD                        # OPTIONAL — last modification
tags:                                       # RECOMMENDED — ATT&CK + custom
  - attack.credential_access                # tactic
  - attack.t1003.001                        # technique.sub-technique
  - attack.t1003.002                        # additional technique
logsource:                                  # REQUIRED — what log to match
  product: windows                          # OS / platform
  category: process_creation                # event category
  service: sysmon                           # OPTIONAL — specific service
detection:                                  # REQUIRED — the matching logic
  selection:                                # named selection block
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'MiniDump'
  filter_legitimate:                        # named filter block
    ParentImage|endswith: '\sccm.exe'
  condition: selection and not filter_legitimate
fields:                                     # OPTIONAL — what to surface in alerts
  - Computer
  - User
  - CommandLine
falsepositives:                             # RECOMMENDED — documented FP causes
  - Authorized admin use
  - SCCM patch deployment
level: informational | low | medium | high | critical  # REQUIRED — severity
```

### 1.2 Logsource Categories

Common `logsource` combinations:

```yaml
# Windows process creation (Sysmon EID 1 or WinEvent 4688)
logsource:
  product: windows
  category: process_creation

# Windows network connection (Sysmon EID 3)
logsource:
  product: windows
  category: network_connection

# Windows file creation (Sysmon EID 11)
logsource:
  product: windows
  category: file_event

# Windows registry (Sysmon EID 13)
logsource:
  product: windows
  category: registry_event

# Windows image load (Sysmon EID 7)
logsource:
  product: windows
  category: image_load

# Windows process access (Sysmon EID 10 — for LSASS access)
logsource:
  product: windows
  category: process_access

# AWS CloudTrail
logsource:
  product: aws
  service: cloudtrail

# Azure Activity
logsource:
  product: azure
  service: activitylogs

# Google Workspace
logsource:
  product: gcp
  service: gcp.audit

# Generic Linux syslog
logsource:
  product: linux
  category: process_creation

# Web proxy
logsource:
  category: proxy
```

### 1.3 Field Modifiers

Sigma supports field-value modifiers that adjust matching semantics:

```yaml
# String modifiers
Image|endswith: '\rundll32.exe'           # substring at end
Image|startswith: 'C:\Windows\'           # substring at start
CommandLine|contains: 'MiniDump'          # substring anywhere
CommandLine|contains|all:                 # all values must be present
  - 'comsvcs.dll'
  - 'MiniDump'
CommandLine|contains|any:                 # any value present
  - 'sekurlsa'
  - 'lsadump'

# Case modifiers
User|contains|re: '(?i)admin'             # case-insensitive regex

# Numeric modifiers
GrantedAccess|eq: 0x1010                  # exact numeric match

# List / OR
Image|endswith:
  - '\mimikatz.exe'
  - '\procdump.exe'

# Base64 modifier (for command-line obfuscation)
CommandLine|base64offset|contains: 'Invoke-Mimikatz'

# Windash modifier (handles - vs / flag prefixes)
CommandLine|windash: '-encodedCommand'
```

### 1.4 Rule ID Generation

Every rule needs a globally-unique UUID v4. Generate one per rule.

```bash
# Python
python3 -c "import uuid; print(uuid.uuid4())"

# Native macOS / Linux
uuidgen

# Online: https://www.uuidgenerator.net/
```

### 1.5 Status Conventions

| Status | Meaning |
|--------|---------|
| `experimental` | Newly authored, not yet soak-tested. Staging only. |
| `test` | In staging soak, FP rate being measured. |
| `stable` | Production-deployed, FP rate below threshold. |
| `deprecated` | Retired (silent > 24 months, or technique obsolete). Kept for auditability. |

---

## 2. Sigma Rule Authoring Patterns

### 2.1 Single-Selection Pattern (Most Common)

```yaml
title: Suspicious comsvcs.dll MiniDump Invocation
id: 09e5f7d2-25a6-11ee-be56-0242ac120002
status: experimental
description: Detects rundll32 loading comsvcs.dll with MiniDump arguments — T1003.001
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

### 2.2 Multi-Selection OR Pattern

```yaml
title: Multiple LOLBins Spawned by Office Application
id: 5f9b2c4d-7e8a-4f1b-9c3d-2a1b3c4d5e6f
status: experimental
description: >-
  Detects Office applications spawning LOLBins commonly used by macro-malware.
  T1059 Execution, T1218 System Binary Proxy Execution.
tags:
  - attack.execution
  - attack.t1059
  - attack.t1218
logsource:
  product: windows
  category: process_creation
detection:
  selection_office_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
  selection_lolbin_child:
    Image|endswith:
      - '\certutil.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\mshta.exe'
      - '\wmic.exe'
      - '\powershell.exe'
      - '\cmd.exe'
      - '\cscript.exe'
      - '\wscript.exe'
  condition: selection_office_parent and selection_lolbin_child
level: high
```

### 2.3 Aggregation Pattern (Threshold / Count)

```yaml
title: Excessive Failed Logins — Brute Force
id: 7b1d3e5c-9a2b-4f1c-8e3d-1a2b3c4d5e6f
status: experimental
description: >-
  Detects more than 5 failed logins (EID 4625) from one source IP within 1 minute.
  T1110 Brute Force.
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 1m
  condition: selection | count() by IpAddress > 5
level: medium
falsepositives:
  - Misconfigured service accounts
  - Stale RDP sessions after password rotation
```

### 2.4 Filter Pattern (Suppress Known-Good)

```yaml
title: PowerShell Encoded Command Execution
id: fb5555e7-83f3-4d8a-8b3b-87a0f4e3a8c1
status: experimental
description: Detects PowerShell invocations with -EncodedCommand / -enc / -e — T1059.001
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - ' -enc '
      - ' -e '
  filter_sccm:
    ParentImage|endswith: '\sccm.exe'
  filter_dsc:
    ParentImage|endswith: '\wmiapriv.exe'
    CommandLine|contains: 'DSC'
  condition: selection and not 1 of filter_*
level: medium
falsepositives:
  - SCCM admin tasks
  - PowerShell DSC configurations
  - In-house IT scripts
```

### 2.5 Near-Wildcard with Anchoring

```yaml
title: Mimikatz Command Line Patterns
id: c6e3dea0-e1a7-4d2e-9f17-c1f3f0d4a7b2
status: experimental
description: Detects canonical Mimikatz module invocations on the command line.
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
logsource:
  product: windows
  category: process_creation
detection:
  selection_mimikatz_image:
    Image|endswith: '\mimikatz.exe'
  selection_mimikatz_commandline:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'sekurlsa::minidump'
      - 'lsadump::sam'
      - 'lsadump::dcsync'
      - 'kerberos::ptt'
      - 'kerberos::golden'
      - 'crypto::capi'
      - 'privilege::debug'
  condition: selection_mimikatz_image or selection_mimikatz_commandline
level: critical
falsepositives:
  - Authorized red-team use (filter by ParentUser)
```

### 2.6 Network Connection Pattern

```yaml
title: Suspicious Outbound RDP Connection
id: 3a2c4e5d-6f7a-4b1c-9d2e-3a4b5c6d7e8f
status: experimental
description: >-
  Detects outbound RDP (port 3389) connections from workstations — T1021.001
  Remote Services: RDP.
tags:
  - attack.lateral_movement
  - attack.t1021.001
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationPort: 3389
    Initiated: 'true'
  filter_admin_jump_hosts:
    SourceImage|endswith:
      - '\mstsc.exe'
    Computer|startswith:
      - 'JUMP-'             # authorized jump host prefix
  condition: selection and not filter_admin_jump_hosts
level: low
falsepositives:
  - Legitimate admin RDP from non-jump hosts (tune to your environment)
```

### 2.7 Cross-Product Correlation Pattern

```yaml
# AWS Console Login from a new geographic location (T1078 Valid Accounts)
title: AWS Console Login from New Geographic Location
id: f0d1a2b3-c4d5-6789-abcd-ef0123456789
status: experimental
description: >-
  Detects AWS Management Console logins from a geographic location not seen
  for this user in the preceding 14 days. T1078 Valid Accounts.
references:
  - https://attack.mitre.org/techniques/T1078/
tags:
  - attack.initial_access
  - attack.t1078
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_console_login:
    eventName: ConsoleLogin
    eventSource: signin.amazonaws.com
    responseElements_ConsoleLogin: Success
  condition: selection_console_login
falsepositives:
  - User travel (legitimate new geo)
  - VPN / corporate egress changes
level: medium
```

### 2.8 AWS CloudTrail Patterns

```yaml
# IAM role assumption via AssumeRoleWithSAML from a new IP
title: AWS AssumeRoleWithSAML from New IP Address
id: 1a2b3c4d-5e6f-4a1b-9c3d-7e8f9a0b1c2d
status: experimental
description: AssumeRoleWithSAML API call from a source IP not seen in the previous 14 days.
tags:
  - attack.privilege_escalation
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: AssumeRoleWithSAML
  condition: selection
level: low
falsepositives:
  - VPN egress changes
  - User travel
```

### 2.9 DNS / DGA Pattern (Zeek)

```yaml
title: High-Entropy DNS Query — Possible DGA
id: 9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d
status: experimental
description: >-
  Detects Zeek dns.log queries where the leftmost label exceeds 20 characters
  with high Shannon entropy — characteristic of DGA domains. T1071.004 DNS.
tags:
  - attack.command_and_control
  - attack.t1071.004
logsource:
  product: network
  service: dns
detection:
  selection:
    query|re: '(?i)^[a-z0-9]{20,}\.'
  condition: selection
level: low
falsepositives:
  - DKIM / SPF selectors
  - CDN asset hostnames
```

---

## 3. SigmaCLI Usage

### 3.1 Installation

```bash
# Install SigmaCLI and the backends you need
pip3 install sigma-cli
pip3 install pySigma-backend-splunk
pip3 install pySigma-backend-elasticsearch
pip3 install pySigma-backend-qradar
pip3 install pySigma-backend-microsoft365defender

# Verify
sigma-cli --version
```

### 3.2 Parse / Validate a Rule

```bash
# Schema validate without converting
sigma-cli parse rule.yml

# Bulk validate every rule in a directory
for f in $(find rules/ -name '*.yml'); do
  echo "Validating $f"
  sigma-cli parse "$f" || exit 1
done
```

### 3.3 Convert to Backend Formats

```bash
# Convert one rule to Splunk SPL
sigma-cli convert -t splunk rule.yml

# Apply a pipeline (e.g., sysmon field-name mapping)
sigma-cli convert -t splunk -p sysmon rule.yml

# Convert to Elastic Lucene
sigma-cli convert -t lucene rule.yml

# Convert to Kibana NDJSON (importable as a detection rule)
sigma-cli convert -t kibana-ndjson rule.yml > kibana-import.ndjson

# Convert to Microsoft 365 Defender KQL
sigma-cli convert -t microsoft-365-defender rule.yml

# Convert to Elastic EQL
sigma-cli convert -t eql rule.yml

# Convert to QRadar AQL
sigma-cli convert -t qradar rule.yml

# Convert a directory of rules
sigma-cli convert -t splunk -r rules/

# Output to file
sigma-cli convert -t splunk rule.yml -o rule.spl
```

### 3.4 List Backends and Pipelines

```bash
# List installed backends
sigma-cli list backends

# List installed pipelines
sigma-cli list pipelines

# List installed outputs
sigma-cli list outputs
```

### 3.5 Back-Translation (Query → Sigma)

```bash
# Beta feature: translate a SIEM-native query back to Sigma
sigma-cli backtranslate -t splunk 'index=win EventCode=1 Image="*\\rundll32.exe"'

# Useful for porting legacy SIEM content to Sigma
```

### 3.6 Common Pipelines

```bash
# Splunk + Sysmon field mapping
sigma-cli convert -t splunk -p splunk_windows rule.yml

# Elastic + ECS (Elastic Common Schema)
sigma-cli convert -t lucene -p ecs-informational rule.yml

# Azure Sentinel + Sysmon
sigma-cli convert -t azure-sentinel -p sysmon rule.yml
```

### 3.7 pySigma (Python Library)

```python
# For programmatic conversion (custom tooling, internal portals)
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

rules = SigmaCollection.load_ruleset("rules/")
backend = SplunkBackend()

for rule in rules:
    splunk_query = backend.convert_rule(rule)[0]
    print(f"# {rule.title}")
    print(splunk_query)
    print()
```

---

## 4. YARA Rule Anatomy

YARA is a pattern-matching engine for files and memory. Used for malware family classification, exploit detection, and threat hunting.

### 4.1 Top-Level Structure

```yara
rule <rule_name> {              // REQUIRED — alphanumeric + underscore
  meta:                         // OPTIONAL — metadata
    description = "..."
    author = "..."
    date = "YYYY-MM-DD"
    reference = "URL"
    malpedia = "win.family_name"
    tlp = "WHITE"               // Traffic Light Protocol
    hash = "sha256-of-sample"

  strings:                      // OPTIONAL — patterns to match
    $name1 = "literal string"
    $name2 = { AB CD EF 01 }    // hex bytes
    $name3 = /regex[0-9]+/      // regex
    $name4 = "wide string" wide ascii

  condition:                    // REQUIRED — boolean expression
    $name1 and $name2 and filesize < 100KB
}
```

### 4.2 String Types

```yara
rule StringTypes {
  strings:
    // Literal string (case-sensitive)
    $text = "VirtualAlloc"

    // Case-insensitive
    $text_nc = "virtualalloc" nocase

    // Wide (UTF-16, useful for Windows API)
    $wide = "VirtualAlloc" wide

    // Wide + ASCII (matches both)
    $wide_ascii = "VirtualAlloc" wide ascii

    // Hex bytes
    $hex = { 56 69 72 74 75 61 6C 41 6C 6C 6F 63 }

    // Hex with wildcards
    $hex_wild = { 56 ?? 72 74 [2-5] 6C 6C 6F 63 }

    // Regex
    $regex = /Virtual(Alloc|Free|Protect)/

    // Regex with case-insensitive flag
    $regex_nc = /virtual(alloc|free|protect)/ nocase

  condition:
    any of them
}
```

### 4.3 Condition Operators

```yara
rule ConditionOperators {
  strings:
    $a = "string1"
    $b = "string2"
    $c = "string3"
    $d = "string4"

  condition:
    # Boolean operators
    $a and $b
    $a or $b
    not $a

    # String counts
    #a > 2                    // $a appears more than 2 times
    #a >= 1                   // equivalent to $a
    #a == 0                   // $a does not appear

    # Any / all
    any of ($a, $b, $c)       // any of these three
    any of them               // any string in this rule
    all of them               // all strings
    2 of them                 // exactly 2 strings

    # Wildcards in string references
    any of ($a*)              // any string starting with $a

    # File attributes
    filesize < 100KB
    filesize > 1MB and filesize < 10MB

    # PE-specific (with 'pe' module)
    uint16(0) == 0x5A4D       // MZ magic (PE file)
    uint32(uint32(0x3C)) == 0x00004550   // PE\0\0 magic

    # Position-based
    $a at 0                   // $a is at offset 0
    $a in (0..100)            // $a is within first 100 bytes
    $a in (entrypoint..entrypoint+200)   // near entrypoint
}
```

### 4.4 PE Module (for Windows Malware)

```yara
import "pe"

rule CobaltStrike_Beacon_PE {
  meta:
    description = "Cobalt Strike beacon — PE characteristics"
  strings:
    $rich = "DanS" wide ascii
    $api_import = "VirtualAlloc" wide ascii
  condition:
    uint16(0) == 0x5A4D and
    pe.number_of_sections > 3 and
    pe.characteristics & 0x2000 == 0 and   // not a DLL
    $rich and $api_import and
    filesize < 500KB
}
```

### 4.5 Modules Reference

```yara
import "pe"           // PE file format
import "elf"          // ELF file format
import "math"         // Math functions (entropy, mean, etc.)
import "hash"         // Hash functions (CRC32, MD5, SHA)
import "cuckoo"       // Cuckoo sandbox results
import "magic"        // libmagic file-type detection
import "dotnet"       // .NET assemblies
import "macho"        // Mach-O file format
```

---

## 5. YARA Rule Authoring Patterns

### 5.1 Malware Family Signature

```yara
rule Mimikatz_Family {
  meta:
    description = "Mimikatz credential dumping tool — family signature"
    author = "kali-claw detection-engineering skill"
    date = "2026-06-17"
    reference = "https://github.com/gentilkiwi/mimikatz"
    malpedia = "win.mimikatz"
    tlp = "AMBER"
  strings:
    // Banner strings
    $banner1 = "mimikatz" wide ascii nocase
    $banner2 = "gentilkiwi" wide ascii nocase
    // Module names
    $sekurlsa = "sekurlsa::logonpasswords" wide ascii
    $lsadump = "lsadump::sam" wide ascii
    $kerberos = "kerberos::golden" wide ascii
    $crypto = "crypto::capi" wide ascii
    // PE import pattern
    $import = "advapi32.dll" wide ascii
  condition:
    uint16(0) == 0x5A4D and
    filesize < 2MB and
    ($banner1 or $banner2) and
    2 of ($sekurlsa, $lsadump, $kerberos, $crypto)
}
```

### 5.2 Living-off-the-Land Binary Pattern

```yara
// Detection of a malicious LOLBin invocation pattern in dropped scripts
rule Suspicious_PowerShell_Download_Cradle {
  meta:
    description = "PowerShell download cradle patterns"
    author = "kali-claw detection-engineering skill"
  strings:
    $net_new = "New-Object System.Net.WebClient" nocase
    $net_wc = "$wc = New-Object System.Net.WebClient" nocase
    $iex = "IEX" nocase
    $download_string = "DownloadString" nocase
    $download_file = "DownloadFile" nocase
    $invoke_expression = "Invoke-Expression" nocase
    $irm = "Invoke-RestMethod" nocase
    $iwr = "Invoke-WebRequest" nocase
  condition:
    2 of ($net_*) and ($iex or $invoke_expression or $download_string or $download_file or $irm or $iwr)
}
```

### 5.3 Web Shell Pattern

```yara
rule PHP_Webshell_Patterns {
  meta:
    description = "Common PHP webshell function patterns"
    author = "kali-claw detection-engineering skill"
  strings:
    $eval = "eval(" nocase
    $assert = "assert(" nocase
    $system = "system(" nocase
    $exec = "exec(" nocase
    $passthru = "passthru(" nocase
    $shell_exec = "shell_exec(" nocase
    $popen = "popen(" nocase
    $proc_open = "proc_open(" nocase
    $base64_decode = "base64_decode(" nocase
    $str_rot13 = "str_rot13(" nocase
    $gzinflate = "gzinflate(" nocase
    $request = "$_REQUEST" nocase
    $post = "$_POST" nocase
    $get = "$_GET" nocase
    $cookie = "$_COOKIE" nocase
  condition:
    filesize < 100KB and
    1 of ($eval, $assert, $system, $exec, $passthru, $shell_exec, $popen, $proc_open) and
    1 of ($request, $post, $get, $cookie) and
    // Obfuscation patterns
    (1 of ($base64_decode, $str_rot13, $gzinflate) or 1 of ($eval, $assert))
}
```

### 5.4 Hex Pattern with Wildcards (for Encoded Variants)

```yara
rule Encoded_Payload_Variants {
  meta:
    description = "Match encoded payloads with byte-level variations"
  strings:
    // XOR loop: bytes 30, 32, 30, 32 ... where ?? is the XOR key
    $xor_loop = { 80 30 ?? 46 49 75 ?? }
    // NOP sled (16+ consecutive 0x90 bytes)
    $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    // GetPC pattern (common in polymorphic shellcode)
    $getpc = { 89 E3 53 53 53 53 5B 5B 5B 5B }
  condition:
    any of them
}
```

### 5.5 Memory-Scanning Rule (Process Dump)

```yara
// Designed for scanning process memory dumps (e.g., during IR triage)
rule CobaltStrike_Beacon_InMemory {
  meta:
    description = "Cobalt Strike beacon in memory (reflective load indicators)"
  strings:
    $beacon_mutex = "Global\\Root\\" wide ascii nocase
    $pipe_name = "\\pipe\\" wide ascii nocase
    $watermark = { 4D 56 43 47 49 48 }    // MVCGIH (CS watermark pattern)
    $reflective_load = { 4D 5A 90 00 03 00 00 00 }   // MZ header in memory
  condition:
    // Memory scans have no filesize; use $ at offset
    any of them and
    not filesize > 0
}
```

### 5.6 Multi-File Composite Rule

```yara
// Use YARA's 'and' / 'or' to compose multiple signals
rule Suspicious_Document_With_Macro {
  meta:
    description = "Document (RTF/DOCX) with embedded macro / OLE object"
  strings:
    // OLE2 magic
    $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
    // Macro marker
    $macro = "VBA" wide ascii nocase
    $autoopen = "AutoOpen" wide ascii nocase
    $autoclose = "AutoClose" wide ascii nocase
    $document_open = "Document_Open" wide ascii nocase
    // Embedded executable
    $mz = { 4D 5A }
  condition:
    $ole_header and
    1 of ($macro, $autoopen, $autoclose, $document_open) and
    $mz
}
```

---

## 6. yarGen — Auto Rule Generation from Samples

yarGen generates YARA rules from a folder of malware samples by extracting strings that do NOT appear in a benign corpus.

### 6.1 Installation

```bash
git clone https://github.com/Neo23x0/yarGen.git
cd yarGen
pip install -r requirements.txt
```

### 6.2 Initial Setup (One-Time, ~1 hour)

```bash
# Build the benign string database (used to filter out generic strings)
python3 yarGen.py --update

# The database ends up in dbs/
ls dbs/
# all.gz, good.gz, sys.gz, goodstrings.gz
```

### 6.3 Basic Rule Generation

```bash
# Generate a rule from a folder of samples
python3 yarGen.py \
  --malware /opt/samples/malware-family-x/ \
  --top 20 \
  --output /tmp/family-x.yar

# Review the generated rule
cat /tmp/family-x.yar
```

### 6.4 Common yarGen Flags

```bash
# Limit to top N most-signal strings
--top 20

# Exclude certain file extensions
--exclude-extensions pdf,docx,zip

# Minimum string score (default 8)
--min-score 10

# Maximum string length
--max-string-length 100

# Identifier prefix (useful for organizing generated rules)
--identifier "FamilyX"

# Don't include the magic / filesize check (for memory scanning)
--no-magic

# Use PE-specific strings
--pe

# Quiet mode (less verbose)
--quiet
```

### 6.5 Generated Rule Example

```yara
rule FamilyX_generated {
  meta:
    description = "Auto-generated by yarGen"
    author = "yarGen"
    date = "2026-06-17"
    yarGen_rule_name = "FamilyX_generated"
    yarGen_score = "15"
  strings:
    $s1 = "dGhpcyBpcyBhIHRlc3Q" fullword ascii
    $s2 = "C:\\Users\\MalwareAuthor\\" fullword wide ascii
    $s3 = "FamilyX_C2_Beacon" fullword ascii
    $s4 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
  condition:
    ( uint16(0) == 0x5A4D and
      filesize < 500KB and
      ( 2 of ($s*) ) )
      or 3 of them
}
```

### 6.6 Review Workflow

```bash
# 1. Read the generated rule
cat /tmp/family-x.yar

# 2. Identify low-signal strings to remove:
#    - Generic strings ("MZ", "This program cannot be run in DOS mode")
#    - Compiler/linker artifacts
#    - Library function names that appear in benign software

# 3. Tighten the condition:
#    - From "3 of them" to "4 of them" or "5 of them"
#    - Add filesize constraints
#    - Add PE-specific constraints

# 4. Test against positive and negative corpora
yara -r /tmp/family-x.yar /opt/samples/malware-family-x/   # expect matches
yara -r /tmp/family-x.yar /opt/samples/benign/             # expect ZERO matches

# 5. If negative corpus produces matches, remove the matching string or
#    tighten the condition.

# 6. Commit
git add /tmp/family-x.yar
git commit -m "feat(yara): FamilyX malware signature (yarGen-generated, hand-tuned)"
```

---

## 7. Loki — IOC + YARA Scanner

Loki is a scanner that applies a curated YARA + IOC database to a host or directory.

### 7.1 Installation

```bash
git clone https://github.com/Neo23x0/Loki.git
cd Loki
pip install -r requirements.txt
```

### 7.2 Update Signature Database

```bash
# Update the bundled signature database (Suricata ET, ThreatFox, YARA)
python3 loki.py --update

# Signatures end up in signature/
ls signature/
# iocs/  yara/  threatfox/  suricata/
```

### 7.3 Basic Scan

```bash
# Scan a directory
python3 loki.py \
  --path /opt/samples \
  --results /tmp/loki-results.txt \
  --alert-level 40 \
  --no-sigs \
  --force

# Scan a single file
python3 loki.py --path /opt/samples/suspicious.exe

# Scan with custom YARA rules
python3 loki.py \
  --path /opt/samples \
  --rules /opt/signatures/custom-yara/ \
  --results /tmp/loki-results.txt
```

### 7.4 Common Loki Flags

```bash
--path <path>               # Target directory or file
--rules <dir>               # Custom YARA rules directory
--results <file>            # Output file
--alert-level <0-100>       # Threshold for alerting (default 40)
--no-sigs                   # Disable Suricata/NIDS signatures
--force                     # Re-scan even if hashes previously clean
--print-all                 # Print all results (including non-alerts)
--debug                     # Debug output
--max-file-size <bytes>     # Skip files larger than this (default 15MB)
--skiped-file-types <list>  # Skip these file extensions
--cluster                   # Apply to a cluster of hosts (remote mode)
--ssh <user@host>           # Scan a remote host via SSH
```

### 7.5 Loki Output Severity Levels

| Score | Severity | Action |
|-------|----------|--------|
| 0-39 | Info / Low | Log for context |
| 40-69 | Medium | Review manually |
| 70-99 | High | Quarantine + IR |
| 100 | Critical | Page on-call IR immediately |

### 7.6 Loki Plus (Commercial Variant)

```bash
# Loki Plus adds: real-time monitoring, scheduled scans, central management
# Discontinued for open-source users; the community Loki is the maintained fork.
```

### 7.7 Integrating Loki with SOC Workflows

```bash
# Forward Loki results to SIEM via syslog
python3 loki.py --path /opt/samples --results /tmp/results.txt
logger -t loki-scan -p local5.warn < /tmp/results.txt

# Or via Filebeat
# /etc/filebeat/inputs.d/loki.yml
- type: log
  paths:
    - /var/log/loki/*.log
  fields:
    source: loki-scanner
    severity: high
```

---

## 8. Splunk SPL Detection Patterns

### 8.1 Process Creation Hunt (Sysmon EID 1)

```splunk
index=win sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
(Image="*\\mimikatz.exe" OR
 (Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*MiniDump*"))
| stats count by _time, host, User, Image, CommandLine, ParentImage
| sort -_time
```

### 8.2 LSASS Access Hunt (Sysmon EID 10)

```splunk
index=win sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10
TargetImage="*\\lsass.exe"
(GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x143a" OR GrantedAccess="0x1f0fff")
| stats count by _time, host, SourceImage, SourceUser, GrantedAccess
| sort -_time
```

### 8.3 tstats (Accelerated Data Model Query)

```splunk
# Fast, accelerated query against the Process data model
| tstats count from datamodel=Endpoint.Processes
  where Processes.process_name=rundll32.exe
    Processes.process="*MiniDump*"
  by _time, Processes.host, Processes.user, Processes.process
| rename Processes.* as *
| sort -_time
```

### 8.4 Data Model Macros

```splunk
# Use the Endpoint.Processes data model
| from datamodel=Endpoint.Processes
| search (process_name="mimikatz.exe" OR
         (process_name="rundll32.exe" process="*comsvcs.dll*MiniDump*"))
| stats count by _time, host, user, process, parent_process_name
| sort -_time
```

### 8.5 Saved Search with Alert Action

```splunk
# Saved search (scheduled alert)
[search]
index=win EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess="0x1*"
| stats count by _time, host, SourceImage, SourceUser
| where count > 0

[scheduling]
cron_schedule = */5 * * * *
dispatch.earliest_time = -5m
dispatch.latest_time = now

[alerting]
alert_type = number of results
alert_threshold = 0
alert.severity = 4
alert.digest_mode = true
alert.suppress = true
alert.suppress.period = 1h
action.email = true
action.email.to = soc-alerts@company.com
action.email.subject = "LSASS Access Detection - $host$"
```

### 8.6 Multi-Event Correlation (transaction)

```splunk
# Brute force followed by successful login
index=win (EventCode=4625 OR EventCode=4624)
| transaction IpAddress maxspan=10m maxevents=50
| where eventcount > 5
| search EventCode=4624
| stats count by _time, IpAddress, TargetUserName, host
```

### 8.7 Lookup for Threat Intel Enrichment

```splunk
# Lookup against a threat intel KV store collection
index=proxy url="*"
| lookup threat_intel url OUTPUT malice_score, threat_actor
| where malice_score > 70
| stats count by _time, src_ip, url, malice_score, threat_actor
```

### 8.8 Statistical Baseline (Anomaly Detection)

```splunk
# Hosts whose DNS query volume is >3 std-dev above their 30-day baseline
index=dns
| bucket _time span=1h
| stats count as queries by host, _time
| eventstats avg(queries) as avg_q, stdev(queries) as std_q by host
| eval z_score = (queries - avg_q) / std_q
| where z_score > 3
```

---

## 9. Kusto KQL Detection Patterns (Sentinel)

### 9.1 Process Creation Hunt

```kql
DeviceProcessEvents
| where FileName =~ "mimikatz.exe"
   or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### 9.2 LSASS Access Hunt

```kql
DeviceProcessEvents
| where ActionType == "ProcessAccess"
| where FileName =~ "lsass.exe"
| where RequestedAccess in ("0x1010", "0x1410", "0x143a", "0x1f0fff")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, RequestedAccess
| order by TimeGenerated desc
```

### 9.3 Multi-Stage Detection with join

```kql
// Lateral movement: suspicious network logon followed by shell execution
let threshold = 5min;
let SuspiciousLogons = (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3
    | where TimeGenerated > ago(24h)
    | where IpAddress !in (~knownDHCPRange~)
    | project TimeGenerated, Computer, TargetUserName, IpAddress
);
SuspiciousLogons
| join kind=inner (
    SecurityEvent
    | where EventID == 4688
    | where FileName in~ ("powershell.exe", "wmic.exe", "cmd.exe", "psexec.exe")
    | project TimeGenerated as ProcTime, Computer, ParentProcessName, FileName, CommandLine
) on Computer
| where ProcTime between (TimeGenerated .. (TimeGenerated + threshold))
| project TimeGenerated, Computer, TargetUserName, IpAddress, FileName, CommandLine
```

### 9.4 Scheduled Analytics Rule

```kql
// T1059.001 — Encoded PowerShell
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", " -e ")
| where ProcessCommandLine !has "DSC"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### 9.5 Sentinel-Specific Functions

```kql
// using inspectstring to detect obfuscation
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| extend decoded = base64_decode_tostring(extract(@"-enc\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine))
| where isnotempty(decoded)
| project TimeGenerated, DeviceName, decoded

// aggregating with summarize
DeviceLogonEvents
| where TimeGenerated > ago(1h)
| where ActionType == "LogonFailed"
| summarize failed_count = count() by AccountName, DeviceName, bin(TimeGenerated, 5m)
| where failed_count > 10
```

### 9.6 Watchlists (Threat Intel Reference)

```kql
// Join against a Sentinel watchlist of known-malicious IPs
let ThreatIntel = _GetWatchlist('MaliciousIPs') | project IP;
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIP in (ThreatIntel)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

---

## 10. Elastic EQL / Lucene Detection

### 10.1 EQL — Process Creation

```eql
process where process.name == "rundll32.exe" and process.command_line == "*comsvcs.dll*MiniDump*"
```

### 10.2 EQL — Sequence (Multi-Event)

```eql
// LSASS access followed by network egress within 5 minutes
sequence
  [ process where process.name == "lsass.exe" and event.action == "ProcessAccess" ]
  [ network where source.port > 0 ]
  by host.name
  with maxspan=5m
```

### 10.3 EQL — Join

```eql
// Process creation + file write with shared PID
join
  [ process where process.name == "cmd.exe" ]
  [ file where file.name == "*.tmp" ]
  by process.pid
```

### 10.4 EQL — Until (Until Predicate)

```eql
// Sequence until a clear event
sequence
  [ process where process.name == "powershell.exe" ]
  [ process where process.name == "rundll32.exe" ]
  until [ process where process.name == "logout.exe" ]
```

### 10.5 Lucene — Field-Level Query

```lucene
event.code:"1" AND process.name:"rundll32.exe" AND process.command_line:*MiniDump*
```

### 10.6 Lucene — Boolean

```lucene
event.code:"1" AND (
  process.name:"mimikatz.exe"
  OR (process.name:"rundll32.exe" AND process.command_line:*comsvcs.dll*MiniDump*)
)
```

### 10.7 ES|QL (Pipe-Based Query Language)

```esql
from logs-system.security-default
| where event.code == "1"
| where process.name == "rundll32.exe"
| where process.command_line LIKE "*MiniDump*"
| keep @timestamp, host.name, user.name, process.name, process.command_line
| sort @timestamp desc
```

### 10.8 Elastic Detection Rule (Kibana NDJSON)

```json
{
  "type": "query",
  "name": "Suspicious comsvcs.dll MiniDump",
  "description": "T1003.001 - rundll32 loading comsvcs.dll with MiniDump args",
  "risk_score": 73,
  "severity": "high",
  "query": "process where process.name == \"rundll32.exe\" and process.command_line == \"*comsvcs.dll*MiniDump*\"",
  "language": "eql",
  "index": ["logs-system.security-default"],
  "tags": ["T1003.001", "Credential Access"],
  "interval": "5m",
  "from": "now-6m"
}
```

---

## 11. hayabusa — Sigma-to-EVTX Fast Scanning

hayabusa is a Rust-based Sigma-to-EVTX scanner. It applies the entire SigmaHQ rule repo to a folder of EVTX files in minutes.

### 11.1 Installation

```bash
# Download the latest release
wget https://github.com/YamatoSecurity/hayabusa/releases/latest/download/hayabusa-2.18.0-linux.zip
unzip hayabusa-2.18.0-linux.zip -d hayabusa
cd hayabusa
chmod +x hayabusa

# Or via Docker
docker pull yamatosecurity/hayabusa:latest
```

### 11.2 Update Rules

```bash
# Update the built-in Sigma rules (SigmaHQ + custom)
./hayabusa update-rules
```

### 11.3 Generate a CSV Timeline

```bash
# Apply every Sigma rule to every EVTX in a directory
./hayabusa csv-timeline \
  -d /opt/evtx/suspect-host/ \
  -o timeline.csv \
  --min-level medium \
  --no-color

# Output: timeline.csv with one row per match, including:
# Timestamp, Computer, EventID, Level, RuleTitle, RuleAuthors, MitreTactics, MitreTags, Details
```

### 11.4 Generate JSON Output

```bash
./hayabusa json-timeline \
  -d /opt/evtx/suspect-host/ \
  -o timeline.jsonl \
  --min-level medium \
  --jsonl
```

### 11.5 Metrics Mode (Summary Counts)

```bash
# Quick summary: count of hits per ATT&CK tactic
./hayabusa metrics \
  -d /opt/evtx/suspect-host/ \
  -o metrics.csv

# Output: one row per ATT&CK tactic, with hit count
```

### 11.6 Level Summary

```bash
# Count of hits per severity level
./hayabusa level-tuning \
  -d /opt/evtx/suspect-host/ \
  -o levels.csv
```

### 11.7 Computer Listing

```bash
# List all computers seen in the EVTX
./hayabusa computer-metrics \
  -d /opt/evtx/ \
  -o computers.csv
```

### 11.8 Live Response Mode

```bash
# Run against the local Windows host's live EVTX
./hayabusa live-response \
  -o timeline.csv \
  --min-level medium
```

### 11.9 Common hayabusa Flags

```bash
-d, --directory <path>     # Target directory of EVTX files
-f, --file <path>          # Target single EVTX file
-o, --output <file>        # Output file
--min-level <level>        # Minimum severity (informational|low|medium|high|critical)
--no-color                 # Disable color output
-r, --rules <dir>          # Custom rules directory (overrides built-in)
--exclude-status <status>  # Exclude rules with this status (e.g., deprecated)
-C, --clobber              # Overwrite output file
--debug                    # Debug output
-v, --verbose              # Verbose output
```

### 11.10 Integration with Sigma Rule Testing

```bash
# Test a single Sigma rule against a positive corpus
./hayabusa csv-timeline \
  -d /opt/evtx-attack-samples/ \
  -r /path/to/my-new-rule.yml \
  -o test-results.csv

# Verify the rule fired on the expected samples
cut -d, -f5 test-results.csv | sort -u   # rule titles that fired
```

---

## 12. zircollo — Sigma-to-EVTX Offline

zircollo is a Python-based Sigma-to-EVTX scanner. It converts Sigma rules to SQLite SQL, then queries EVTX-to-SQLite exports.

### 12.1 Installation

```bash
git clone https://github.com/wagga40/zircollo.git
cd zircollo
pip3 install -r requirements.txt
```

### 12.2 Basic Scan

```bash
python3 zircollo.py \
  --evtx /opt/evtx/suspect-host/ \
  --ruleset rules/sigma/all.yml \
  --outfile matches.json

# Output: matches.json with one entry per rule fire
```

### 12.3 Packaged Ruleset

```bash
# zircollo ships with a prepackaged Sigma ruleset
python3 zircollo.py \
  --evtx /opt/evtx/suspect-host/ \
  --ruleset rules/sigma/all.yml \
  --outfile matches.json \
  --template templates/Excel.tpl \
  --excelout matches.xlsx
```

### 12.4 Common zircollo Flags

```bash
--evtx <path>              # EVTX file or directory
--ruleset <file>           # Packaged Sigma rules file
--outfile <file>           # JSON output
--excelout <file>          # Excel output (with --template)
--template <file>          # Template for Excel output
--engine                   # EVTX parsing engine (evtx_dump | python-evtx)
--keep                     # Keep intermediate SQLite database
--debug                    # Debug output
```

### 12.5 zircollo vs. hayabusa

| Aspect | zircollo | hayabusa |
|--------|----------|----------|
| Language | Python | Rust |
| Speed | Slower (~minutes per GB) | Faster (~seconds per GB) |
| Portability | Pure Python; easy to extend | Pre-built binaries; cross-platform |
| Rule format | Pre-packaged Sigma | Sigma (supports the full SigmaHQ repo directly) |
| Output | JSON, Excel | CSV, JSON |
| Use case | Quick triage with Excel handoff | Large-scale EVTX processing |

---

## 13. MITRE ATT&CK Mapping

Every Sigma rule (and YARA rule, where applicable) should carry ATT&CK tags. Coverage is measured by tag union.

### 13.1 Tag Format

```yaml
tags:
  # Tactic (lowercase, with attack. prefix)
  - attack.initial_access            # TA0001
  - attack.execution                 # TA0002
  - attack.persistence               # TA0003
  - attack.privilege_escalation      # TA0004
  - attack.defense_evasion           # TA0005
  - attack.credential_access         # TA0006
  - attack.discovery                 # TA0007
  - attack.lateral_movement          # TA0008
  - attack.collection                # TA0009
  - attack.command_and_control       # TA0011
  - attack.exfiltration              # TA0010
  - attack.impact                    # TA0040

  # Technique (with sub-technique if applicable)
  - attack.t1003                     # OS Credential Dumping
  - attack.t1003.001                 # LSASS Memory
  - attack.t1003.002                 # Security Account Manager
  - attack.t1059                     # Command and Scripting Interpreter
  - attack.t1059.001                 # PowerShell
  - attack.t1059.003                 # Windows Command Shell
  - attack.t1071                     # Application Layer Protocol
  - attack.t1071.004                 # DNS
  - attack.t1078                     # Valid Accounts

  # Optional group / software / campaign tags
  - attack.g0007                     # APT28
  - attack.g0040                     # Patchwork
  - attack.s0002                     # Net
  - attack.s0001                     # PsExec
```

### 13.2 ATT&CK Tactic IDs (Quick Reference)

| Tactic | ID |
|--------|-----|
| Reconnaissance | TA0043 |
| Resource Development | TA0042 |
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

### 13.3 Common Technique IDs for Detection Engineering

| Technique | Name | Use Case |
|-----------|------|----------|
| T1003.001 | LSASS Memory | Mimikatz, comsvcs MiniDump, procdump -ma lsass |
| T1003.002 | Security Account Manager | reg save HKLM\SAM |
| T1003.003 | NTDS.dit | ntdsutil, Copy-VSS |
| T1059.001 | PowerShell | Encoded command, download cradle |
| T1059.003 | Windows Command Shell | cmd.exe spawned by Office |
| T1059.005 | Visual Basic | WScript, cscript |
| T1071.001 | Web Protocols | HTTP C2 |
| T1071.004 | DNS | DNS tunneling |
| T1078 | Valid Accounts | Suspicious logins |
| T1110 | Brute Force | Excessive 4625 events |
| T1055 | Process Injection | CreateRemoteThread, QueueUserAPC |
| T1547.001 | Registry Run Keys | Persistence |
| T1053.005 | Scheduled Tasks | schtasks persistence |
| T1218.011 | Rundll32 | LOLBin abuse |

### 13.4 Coverage Layer Generation

```python
#!/usr/bin/env python3
# scripts/build-navigator-layer.py
import sys, os, json, yaml
from pathlib import Path

def extract_tags(rules_dir):
    tags = set()
    for path in Path(rules_dir).rglob('*.yml'):
        with open(path) as f:
            try:
                rule = yaml.safe_load(f)
                for t in (rule.get('tags') or []):
                    if t.startswith('attack.t'):
                        tags.add(t.replace('attack.', '').upper())
            except Exception as e:
                print(f"# WARN: {path}: {e}", file=sys.stderr)
    return tags

def main(rules_dir, output_path):
    tags = extract_tags(rules_dir)
    # Count: build a technique → rule-count map
    counts = {}
    for t in tags:
        counts[t] = counts.get(t, 0) + 1
    layer = {
        "name": "Sigma Rule Coverage",
        "domain": "enterprise-attack",
        "versions": {"attack": "15", "navigator": "4.9.0"},
        "techniques": [
            {
                "techniqueID": t,
                "score": c,
                "comment": f"{c} rule(s) cover this technique"
            } for t, c in counts.items()
        ],
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 5
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }
    with open(output_path, 'w') as f:
        json.dump(layer, f, indent=2)
    print(f"# Wrote {output_path} ({len(counts)} techniques)")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
```

```bash
# Usage
python3 scripts/build-navigator-layer.py rules/ -o coverage.json
# Upload to https://mitre-attack.github.io/attack-navigator/ via
# Layer → Open Layer → Upload
```

### 13.5 Coverage Gap Analysis

```python
#!/usr/bin/env python3
# scripts/coverage-gaps.py
import json, sys
from pathlib import Path

def main(layer_path):
    covered = set()
    with open(layer_path) as f:
        layer = json.load(f)
        for tech in layer['techniques']:
            covered.add(tech['techniqueID'])

    # Load ATT&CK Enterprise techniques (one-time download)
    # curl -sL https://github.com/mitre/cti/raw/master/enterprise-attack.json -o /tmp/attack.json
    import stix2
    with open('/tmp/attack.json') as f:
        attack = json.load(f)

    all_techniques = set()
    for obj in attack['objects']:
        if obj.get('type') == 'attack-pattern':
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    all_techniques.add(ref['external_id'])

    uncovered = all_techniques - covered
    print(f"# Covered: {len(covered)} / {len(all_techniques)}")
    print(f"# Uncovered: {len(uncovered)}")
    for t in sorted(uncovered):
        print(t)

if __name__ == '__main__':
    main(sys.argv[1])
```

---

## 14. Detection CI/CD (GitHub Actions, GitLab CI)

### 14.1 GitHub Actions Workflow

```yaml
# .github/workflows/detection-ci.yml
name: Detection CI

on:
  pull_request:
    paths:
      - 'rules/**'
      - 'yara-rules/**'
      - 'test-data/**'
  push:
    branches: [main]
    paths:
      - 'rules/**'

jobs:
  sigma-schema-validate:
    name: Sigma Schema Validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install SigmaCLI
        run: |
          pip install sigma-cli
          pip install pySigma-backend-splunk
          pip install pySigma-backend-elasticsearch
          pip install pySigma-backend-qradar
      - name: Validate every Sigma rule
        run: |
          set -e
          for f in $(find rules/ -name '*.yml'); do
            echo "Validating $f"
            sigma-cli parse "$f"
          done

  attack-tag-coverage:
    name: ATT&CK Tag Coverage Check
    runs-on: ubuntu-latest
    needs: sigma-schema-validate
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Check every rule has an ATT&CK tag
        run: |
          python3 - <<'PY'
          import sys, yaml
          from pathlib import Path
          errors = []
          for path in Path('rules').rglob('*.yml'):
              with open(path) as f:
                  try:
                      rule = yaml.safe_load(f)
                  except Exception as e:
                      errors.append(f"{path}: YAML parse error: {e}")
                      continue
                  tags = rule.get('tags') or []
                  attack_tags = [t for t in tags if t.startswith('attack.t')]
                  if not attack_tags:
                      errors.append(f"{path}: missing attack.tXXXX tag")
              if errors:
                  print('\n'.join(errors), file=sys.stderr)
                  sys.exit(1)
          PY

  backend-translation:
    name: Backend Translation (Splunk, Elastic, KQL)
    runs-on: ubuntu-latest
    needs: sigma-schema-validate
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install SigmaCLI + backends
        run: |
          pip install sigma-cli
          pip install pySigma-backend-splunk pySigma-backend-elasticsearch
          pip install pySigma-backend-microsoft365defender
      - name: Translate every rule to every backend
        run: |
          set -e
          for f in $(find rules/ -name '*.yml'); do
            echo "Translating $f"
            sigma-cli convert -t splunk "$f" > /dev/null
            sigma-cli convert -t lucene "$f" > /dev/null
            sigma-cli convert -t microsoft-365-defender "$f" > /dev/null
          done

  positive-corpus-test:
    name: Positive Corpus Test (rule must fire)
    runs-on: ubuntu-latest
    needs: sigma-schema-validate
    steps:
      - uses: actions/checkout@v4
      - name: Run hayabusa on positive corpus
        run: |
          docker run --rm \
            -v $PWD:/work \
            yamatosecurity/hayabusa:latest \
            csv-timeline \
            -d /work/test-data/positive/ \
            -r /work/rules/ \
            -o /tmp/pos.csv \
            --min-level low
          # Assert output is non-empty
          test -s /tmp/pos.csv

  negative-corpus-test:
    name: Negative Corpus Test (rule must stay silent)
    runs-on: ubuntu-latest
    needs: sigma-schema-validate
    steps:
      - uses: actions/checkout@v4
      - name: Run hayabusa on negative corpus
        run: |
          docker run --rm \
            -v $PWD:/work \
            yamatosecurity/hayabusa:latest \
            csv-timeline \
            -d /work/test-data/negative/ \
            -r /work/rules/ \
            -o /tmp/neg.csv \
            --min-level low
          # Assert that no rule with level >= medium fired
          if grep -E ',(medium|high|critical),' /tmp/neg.csv; then
            echo "FAIL: rule fired on negative corpus"
            cat /tmp/neg.csv
            exit 1
          fi

  navigator-layer-build:
    name: Build ATT&CK Navigator Coverage Layer
    runs-on: ubuntu-latest
    needs: [sigma-schema-validate, attack-tag-coverage]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install pyyaml
      - name: Build coverage layer
        run: python3 scripts/build-navigator-layer.py rules/ -o coverage.json
      - name: Upload coverage layer as artifact
        uses: actions/upload-artifact@v4
        with:
          name: attack-coverage-layer
          path: coverage.json
```

### 14.2 GitLab CI Equivalent

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - test
  - publish

sigma-schema-validate:
  stage: validate
  image: python:3.11-slim
  before_script:
    - pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch
  script:
    - |
      for f in $(find rules/ -name '*.yml'); do
        echo "Validating $f"
        sigma-cli parse "$f"
      done

backend-translation:
  stage: validate
  image: python:3.11-slim
  before_script:
    - pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch pySigma-backend-microsoft365defender
  script:
    - |
      for f in $(find rules/ -name '*.yml'); do
        echo "Translating $f"
        sigma-cli convert -t splunk "$f" > /dev/null
        sigma-cli convert -t lucene "$f" > /dev/null
        sigma-cli convert -t microsoft-365-defender "$f" > /dev/null
      done

positive-corpus-test:
  stage: test
  image: docker:24
  services:
    - docker:24-dind
  script:
    - |
      docker run --rm \
        -v $PWD:/work \
        yamatosecurity/hayabusa:latest \
        csv-timeline \
        -d /work/test-data/positive/ \
        -r /work/rules/ \
        -o /tmp/pos.csv \
        --min-level low
      test -s /tmp/pos.csv

publish-coverage-layer:
  stage: publish
  image: python:3.11-slim
  before_script:
    - pip install pyyaml
  script:
    - python3 scripts/build-navigator-layer.py rules/ -o coverage.json
  artifacts:
    paths:
      - coverage.json
    expire_in: 90 days
  only:
    - main
```

### 14.3 Pre-Commit Hook (Local Validation)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/SigmaHQ/sigma
    rev: v0.23.0
    hooks:
      - id: sigma-rule-validator
        files: '^rules/.*\.yml$'
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-yaml
        files: '^rules/.*\.yml$'
      - id: end-of-file-fixer
      - id: trailing-whitespace
```

```bash
# Install pre-commit
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

### 14.4 Branch Protection Rules

For the detections repo, configure:

```
- Require pull request before merging
- Require approvals: at least 1 (preferably 2 for level=high|critical rules)
- Require status checks: detection-ci.yml must pass
- Require branches to be up to date before merging
- Dismiss stale pull request approvals when new commits are pushed
- Restrict who can push to matching branches (only detection-engineering team)
```

---

## 15. False-Positive Tuning Methodology

### 15.1 FP-Tuning Workflow

```
1. Measure: run the rule against 30 days of historical SIEM data
2. Group hits: stats by (Computer, User, ParentImage, CommandLine signature)
3. Triage: for each cluster, decide benign / suspicious / unknown
4. For each benign cluster:
   a. Identify the common signal (parent process, signer, user, host pattern)
   b. Add a filter clause to the Sigma rule
   c. Re-test against the historical data
   d. Verify FP rate dropped, true-positive rate unchanged
5. If FP cannot be brought below threshold:
   a. Lower the rule level (high → medium → low)
   b. OR retire the rule and file a "we cannot distinguish this TTP from
      benign admin activity with current telemetry" ticket
   c. OR request a new log source (Sysmon EID 7 for image load, etc.)
```

### 15.2 Common FP-Tuning Patterns

#### 15.2.1 Filter by Parent Process

```yaml
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'comsvcs.dll'
  filter_sccm:
    ParentImage|endswith:
      - '\sccm.exe'
      - '\cmmcompiler.exe'
  filter_dsc:
    ParentImage|endswith: '\wmiapriv.exe'
  condition: selection and not 1 of filter_*
```

#### 15.2.2 Filter by Signer

```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  filter_ms_signed:
    SignedBy: 'Microsoft Windows Production'
  filter_org_signed:
    SignedBy|contains: 'Contoso Code Signing'
  condition: selection and not 1 of filter_*
```

#### 15.2.3 Filter by Host Naming Convention

```yaml
detection:
  selection:
    Image|endswith: '\mstsc.exe'
    DestinationPort: 3389
  filter_jump_hosts:
    Computer|startswith:
      - 'JUMP-'
      - 'BASTION-'
  condition: selection and not filter_jump_hosts
```

#### 15.2.4 Anchor CommandLine (Avoid Substring Match)

```yaml
# Bad: matches "-e " anywhere
selection:
  CommandLine|contains: '-e '

# Better: anchored to the encoded-command flag specifically
selection:
  CommandLine|contains:
    - '-EncodedCommand '
    - ' -enc '
    - ' -e '
```

#### 15.2.5 Add a Timeframe Aggregation

```yaml
detection:
  selection:
    EventID: 4625
  timeframe: 1m
  condition: selection | count() by IpAddress > 5
```

#### 15.2.6 Require Multiple Signals (AND vs OR)

```yaml
# Single signal — noisy
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection

# Two signals — more selective
detection:
  selection_cmd:
    Image|endswith: '\cmd.exe'
  selection_office_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
  condition: selection_cmd and selection_office_parent
```

### 15.3 FP-Tuning Dashboard (Splunk Example)

```splunk
# FP dashboard for a rule
index=alerts rule_name="mimikatz-cmdline"
| bucket _time span=1d
| stats count as hits_per_day by _time, Computer, User, ParentImage
| sort -hits_per_day
| eventstats avg(hits_per_day) as avg by Computer, ParentImage
| eval z_score = (hits_per_day - avg) / stdev(hits_per_day)
```

### 15.4 FP-Tuning Decision Matrix

| Hit Cluster Volume | Triaged As | Action |
|--------------------|------------|--------|
| > 50/day | Benign (e.g., SCCM) | Add filter; re-test |
| 10-50/day | Benign | Add filter; re-test |
| 10-50/day | Suspicious | Manual review; if confirmed malicious, escalate to IR |
| < 10/day | Mixed | Promote to staging; soak longer |
| 0/day | (silent) | (None — rule is clean) |

### 15.5 FP-Tuning Failure Modes

- **Over-tuning**: filter so aggressively that true positives are missed. Always re-test against the positive corpus after each filter addition.
- **Stale filters**: a filter added for a 3-year-old admin tool stays in place even after the tool is retired. Periodically review filter relevance.
- **Filter on unstable fields**: filtering by User (which can change with personnel) is fragile; prefer filtering by ParentImage (stable) or Signer (cryptographically stable).

---

## 16. Detection-as-Code Lifecycle

### 16.1 Lifecycle Phases

```
[1] Threat Intel & TTP Intake
   ├─ Vendor reports, CISA advisories, MISP events
   ├─ Red-team debriefs ("we emulated X; did you catch it?")
   ├─ ATT&CK Navigator coverage gap analysis
   ├─ Incident retrospectives
   └─ Community Sigma PRs

[2] Rule Draft Authoring
   ├─ Sigma YAML (source of truth)
   ├─ ATT&CK tags assigned
   ├─ False-positive hypotheses documented
   └─ Author, date, references set

[3] Unit Testing (pos + neg corpus)
   ├─ Positive: EVTX-ATTACK-SAMPLES, atomic-red-team, CALDERA
   ├─ Negative: 30 days of benign production EVTX
   └─ hayabusa / zircollo test harness

[4] CI Validation (PR pipeline)
   ├─ YAML schema validate
   ├─ ATT&CK tag coverage check
   ├─ Backend translation (Sigma → Splunk, Elastic, KQL)
   ├─ Positive corpus test (rule MUST fire)
   └─ Negative corpus test (rule MUST stay silent)

[5] Staging Soak (7-30 days)
   ├─ Deploy to staging SIEM
   ├─ Measure hit rate
   ├─ Triage each hit (benign / suspicious / unknown)
   └─ FP tuning (add filters, re-test)

[6] Production Ship
   ├─ Merge PR to main
   ├─ CI deploys to production SIEM
   ├─ Update ATT&CK Navigator coverage layer
   └─ Set quarterly review reminder

[7] Quarterly Review
   ├─ Rule liveness check (silent for 24m? retire)
   ├─ FP rate re-measure
   ├─ Re-test against fresh positive corpus
   └─ Re-test against fresh negative corpus

[8] Retirement
   ├─ status: stable → deprecated
   ├─ git mv to rules/deprecated/
   ├─ Remove from SIEM import
   └─ Update ATT&CK Navigator coverage layer
```

### 16.2 Detection Engineering Definition of Done

A rule is "done" when:

```
- [ ] YAML schema valid
- [ ] ATT&CK tags assigned (>= 1 attack.tXXXX)
- [ ] Status set (experimental | test | stable)
- [ ] Level set (informational | low | medium | high | critical)
- [ ] Falsepositives field populated
- [ ] References field populated
- [ ] Author and date set
- [ ] Positive corpus test passes (rule fires on known-malicious)
- [ ] Negative corpus test passes (rule silent on known-benign)
- [ ] Backend translation succeeds (Splunk, Elastic, KQL)
- [ ] CI pipeline green
- [ ] Peer review approved
- [ ] Staging soak complete (7-30 days)
- [ ] FP rate documented and below threshold
- [ ] ATT&CK Navigator coverage layer updated
```

### 16.3 Repository Structure

```
detection-engineering-repo/
├── rules/                          # Active Sigma rules
│   ├── credential_access/
│   │   ├── mimikatz-cmdline.yml
│   │   └── comsvcs-minidump.yml
│   ├── execution/
│   │   └── powershell-encoded.yml
│   ├── initial_access/
│   │   └── aws-console-new-geo.yml
│   └── ...
├── yara-rules/                     # Active YARA rules
│   ├── malware-family/
│   │   ├── cobalt-strike.yar
│   │   └── mimikatz.yar
│   └── lolbin/
│       └── powershell-cradle.yar
├── splunk/                         # Splunk SPL (committed generated artifacts)
├── sentinel/                       # Sentinel KQL (committed)
├── elastic/                        # Elastic EQL / Lucene (committed)
├── deprecated/                     # Retired rules (kept for audit)
├── test-data/
│   ├── positive/                   # EVTX-ATTACK-SAMPLES subset
│   └── negative/                   # Benign production EVTX
├── scripts/
│   ├── build-navigator-layer.py
│   ├── check-tags.py
│   └── rule-liveness.py
├── .github/workflows/detection-ci.yml
├── .pre-commit-config.yaml
├── CONTRIBUTING.md
└── README.md
```

### 16.4 CONTRIBUTING.md Template

```markdown
# Contributing Detections

## Authoring a New Detection

1. Pick an ATT&CK technique not yet covered (see `coverage.json`)
2. Draft a Sigma YAML using `templates/rule-template.yml`
3. Generate a UUID: `python3 -c "import uuid; print(uuid.uuid4())"`
4. Add the rule under `rules/<tactic>/`
5. Test against positive and negative corpora:
   - Positive: `hayabusa csv-timeline -d test-data/positive/ -r rules/`
   - Negative: `hayabusa csv-timeline -d test-data/negative/ -r rules/`
6. Open a pull request; CI will validate schema, ATT&CK tags, and corpus behavior
7. After merge, the rule deploys to staging SIEM; FP-tune for 7-30 days
8. After FP-tune, promote `status: experimental → stable`

## Code Review Checklist

- [ ] Schema valid (CI)
- [ ] ATT&CK tags present (CI)
- [ ] Backend translation succeeds (CI)
- [ ] Positive corpus test passes (CI)
- [ ] Negative corpus test passes (CI)
- [ ] Falsepositives field documents expected FPs
- [ ] References field populated (TI / ATT&CK / blog)
- [ ] Peer review by ≥ 1 detection engineer
- [ ] (For level=high|critical) Peer review by ≥ 2 detection engineers

## Retiring a Detection

1. Confirm rule has been silent for 24 months (see `scripts/rule-liveness.py`)
2. `git mv rules/<tactic>/rule.yml deprecated/`
3. Edit the rule: change `status: stable` to `status: deprecated`
4. Open a PR; CI will update the ATT&CK Navigator coverage layer
```

### 16.5 Rule Naming Conventions

```
# Sigma rules: lowercase-kebab-case, descriptive
mimikatz-cmdline.yml
comsvcs-minidump.yml
aws-console-login-new-geo.yml

# YARA rules: PascalCase_With_Underscores
CobaltStrike_Beacon_Loader.yar
Mimikatz_Family.yar
PHP_Webshell_Patterns.yar

# Directories: ATT&CK tactic (lowercase_with_underscores)
credential_access/
initial_access/
command_and_control/
```

### 16.6 Metrics for the Detection Engineering Program

| Metric | Target | Source |
|--------|--------|--------|
| ATT&CK technique coverage | >= 70% of relevant techniques | `scripts/build-navigator-layer.py` |
| Mean time from TI intake to staging | < 14 days | Ticketing system |
| Mean time from staging to production | < 30 days (including soak) | Git history |
| Median rule FP rate | < 1 hit/day per rule | SIEM hit counts |
| Quarterly rule retirement rate | 5-10% (lifecycle is healthy) | `scripts/rule-liveness.py` |
| CI pipeline success rate on main | >= 95% | GitHub Actions / GitLab CI |
| Coverage-layer review cadence | Quarterly | Calendar |

### 16.7 Integration with Threat Hunting

The detection-as-code lifecycle is the supply chain for threat hunting:

```
Threat Hunt finds something →
  detection-engineering work item →
  Sigma rule drafted →
  CI validated →
  staging soak →
  production ship →
  ATT&CK coverage updated →
  Hunt uses the new detection as a building block for the next hunt →
  loop
```

The two disciplines are paired: hunting supplies the empirical truth that detection engineers encode; detection engineers supply the detectors that hunters lean on for breadth. The Sigma rule you ship today is the building block of tomorrow's hunt.
