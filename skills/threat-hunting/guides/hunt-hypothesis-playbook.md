# Hunt Hypothesis Playbook — End-to-End Threat Hunting Operations

> Deep-dive companion to `skills/threat-hunting/SKILL.md`.
>
> Audience: SOC analysts and detection engineers who already know what threat hunting is and want a battle-tested playbook for going from a vague suspicion to a shipped, tuned, ATT&CK-mapped detection — without burning SOC cycles on noise.

---

## 1. Why a Playbook, Not Just a Query Library

Threat hunting is deceptively easy to do badly: open a SIEM, run a query that feels clever, page through hits, ship a detection. The trap is treating that loop as the deliverable. A defensible hunt produces:

1. **A hypothesis** — a single testable statement grounded in ATT&CK, not a vibe.
2. **A telemetry inventory** — a documented answer to "do we even have the data?"
3. **A query in vendor-neutral Sigma** — so the work survives a SIEM migration.
4. **A triage record** — which hits were true positives, which were filtered, and why.
5. **A shipped detection or a documented gap** — both are valuable outputs.

This playbook walks through all five, in order, with the exact artifacts and decision points.

---

## 2. The Pyramid of Pain — Why TTPs > IOCs

David Bianco's Pyramid of Pain ranks indicators by how much pain they cause the adversary when blocked:

```
                       /\                ← TTPs
                      /  \                  HIGHEST PAIN — adversary must change
                     /    \                 tradecraft (procedure/technique)
                    / Tools\              ← adversary must switch tooling
                   /        \              HIGH PAIN
                  / Network   \           ← adversary must re-stage C2
                 /   Artifacts  \          MEDIUM-HIGH PAIN
                /                \
               /    IP Addresses   \      ← adversary must rent new infra
              /                      \     LOW PAIN (cheap, fast)
             /      Hash Values       \   ← adversary must recompile
            /__________________________\  NEAR-ZERO PAIN (automatable)
```

**Implication for hunting**: every hunt should aim as high on the Pyramid as the data allows. A hash-based hunt catches one malware sample; a TTP-based hunt catches the entire family. A Sigma rule on `rundll32.exe` + `comsvcs.dll` + `MiniDump` catches any adversary who uses that procedure, regardless of file hash, destination IP, or domain.

**Counter-example**: a Sigma rule that fires on a single file hash (`sha256: e3b0c44...`) is on the bottom of the Pyramid. It will stop firing the moment the adversary recompiles. Don't waste a detection slot on it unless the hash is irreplaceable (e.g., a nation-state-signed binary).

---

## 3. Phase 1 — Hypothesis Formation

### 3.1 The Hypothesis Statement Template

Every hunt starts with a hypothesis written in this exact shape:

```
An attacker who <achieves objective X> via <technique Y>
              would have left <observable Z>
              in <data source W>.
              I expect to see <baseline frequency B> of <observable Z>
              in normal operations.
              If the hunt returns <count > threshold T>, I will <action A>.
```

### 3.2 Worked Example — T1003.001

```
An attacker who dumps LSASS memory (objective: credential access)
              via comsvcs.dll MiniDump invoked through rundll32.exe (technique: T1003.001)
              would have left a Sysmon EID 1 event with:
                  Image endswith \rundll32.exe
                  CommandLine contains comsvcs.dll
                  CommandLine contains MiniDump
              in Sysmon EID 1 (data source: process creation).
              I expect to see ZERO of these events in normal operations
              (comsvcs.dll MiniDump is not invoked by any legitimate software).
              If the hunt returns count > 0, I will escalate to IR
              and preserve the host's image + memory.
```

### 3.3 Anti-Patterns

| Bad Hypothesis | Why It Fails |
|----------------|--------------|
| "Find suspicious PowerShell" | No technique. No data source. No baseline. Untestable. |
| "Find Mimikatz" | Implies hash/file-name hunt — bottom of the Pyramid. Re-written as `T1003.001 via comsvcs.dll` becomes a TTP hunt. |
| "Find anything weird" | "Weird" is not a hypothesis. You will drown in noise and produce no detection. |
| "Find evidence of compromise" | This is the goal of all hunting, not a specific hypothesis. Decompose into per-technique hypotheses. |

### 3.4 ATT&CK Mapping Discipline

Every hypothesis names exactly ONE ATT&CK sub-technique (e.g., `T1003.001`, not `T1003`). Reasons:

- A sub-technique maps to one observable pattern. A technique maps to many — too broad to test in one hunt.
- The Sigma rule you produce is tagged with the sub-technique. Future analysts searching for coverage of `T1003.001` find it.
- ATT&CK Navigator layers are scored at the sub-technique level for precision.

If a hypothesis genuinely spans multiple sub-techniques (e.g., "credential dumping by any means"), split it into N hypotheses.

---

## 4. Phase 2 — Telemetry Inventory

Before writing a query, confirm the data exists. A hypothesis you can't test is a sensor gap — itself a valuable output.

### 4.1 Data Inventory Checklist

For each (data source, field) the hypothesis needs:

| Question | If No |
|----------|-------|
| Is the source collected? | File a sensor gap; close the hunt with the gap documented. |
| Is the field populated? | File a parser/config gap; same as above. |
| Is the data retained long enough for the lookback? | File a retention gap; or shrink the lookback. |
| Is the query latency acceptable on this volume? | File a performance gap; use `tstats` or summary indexes. |

### 4.2 Inventory Commands

```bash
# Splunk — does index=win contain Sysmon EID 1 in the last 24h?
index=win source="*Sysmon*" EventCode=1 earliest=-24h | stats count

# Sentinel — does DeviceProcessEvents have data?
DeviceProcessEvents | summarize count() by bin(TimeGenerated, 1h) | render timechart

# Elastic — does the filebeat-sysmon index have EID 1?
GET filebeat-*/_count
{ "query": { "bool": { "filter": [
  { "term": { "event.code": "1" } },
  { "term": { "winlog.provider_name": "Microsoft-Windows-Sysmon" } }
] } } }

# Are the fields I need populated?
index=win source="*Sysmon*" EventCode=1
| stats count, count(Image) as image_count, count(CommandLine) as cmdline_count
```

### 4.3 What to Do When Data Is Missing

Two paths, both legitimate:

1. **File a sensor gap** — document the missing (source, field) in a tracking system; close the hunt with "blocked on sensor gap #1234." This is a successful hunt: you now know you cannot detect TTP X.
2. **Use an alternative source** — if Sysmon EID 1 isn't available, can WinEvent 4688 (with command-line auditing enabled) substitute? Document the substitution in the Sigma rule's `logsource` section.

Never silently ship a hunt against absent data — it will appear to pass while detecting nothing.

---

## 5. Phase 3 — Query Authoring

### 5.1 Sigma First, SIEM Second

Author the query in Sigma (vendor-neutral YAML), then translate to the active SIEM. Benefits:

- The Sigma file survives a SIEM migration. The translated query does not.
- The Sigma file is portable across teams with different SIEMs.
- `sigma-cli` automates the translation; you write once, deploy everywhere.
- Sigma enforces structure (fields, tags, logsource) that ad-hoc SIEM queries lack.

### 5.2 The Canonical Sigma Skeleton

```yaml
title: <Verb-phrase, e.g., "Suspicious comsvcs.dll MiniDump Invocation">
id: <UUID v4 — stable across edits>
status: experimental        # → test → stable
description: <one-sentence summary>
references:
  - <ATT&CK URL>
  - <vendor blog / IR report>
author: <name>
date: 2026/06/16
modified: 2026/06/16
tags:
  - attack.<tactic>          # e.g., attack.credential_access
  - attack.t<technique>      # e.g., attack.t1003.001
  - attack.<tactic>          # second tactic if applicable
logsource:
  product: windows
  category: process_creation  # or process_access, network_connection, file_event, etc.
detection:
  selection:
    <field>|<modifier>: <value>
    ...
  filter_legitimate_<name>:
    <field>|<modifier>: <value>
    ...
  condition: selection and not 1 of filter_*
fields:
  - <field>                   # surfaced in the alert
falsepositives:
  - <known FP source>
level: high                   # informational / low / medium / high / critical
```

### 5.3 Translation via sigma-cli

```bash
# Install
pip3 install sigma-cli

# List backends and pipelines
sigma-cli plugin list

# Convert to Splunk SPL (with Sysmon field mappings)
sigma-cli convert -t splunk -p sysmon sigma/rules/credential_access/comsvcs_minidump.yml

# Convert to Elastic Lucene
sigma-cli convert -t lucene sigma/rules/credential_access/comsvcs_minidump.yml

# Convert to ES|QL (Elastic's new piped language)
sigma-cli convert -t eql sigma/rules/credential_access/comsvcs_minidump.yml

# Convert to Sentinel KQL (if azure-sentinel backend installed)
sigma-cli convert -t azure-sentinel sigma/rules/credential_access/comsvcs_minidump.yml

# Validate before shipping
sigma-cli check sigma/rules/credential_access/comsvcs_minidump.yml

# Batch-convert a directory
sigma-cli convert -t splunk -p sysmon -r sigma/rules/ -o out/splunk/
```

---

## 6. ATT&CK Navigator Layer Workflow

The Navigator visualizes technique coverage. A hunt program produces three layers:

1. **Detections layer** — every sub-technique with a shipped Sigma rule scored 100 (covered), 50 (partial), 0 (uncovered).
2. **Red-team-emulated layer** — every sub-technique the red team has emulated in the last 12 months.
3. **Diff layer** — emulated minus detected. This is the gap to close next sprint.

### 6.1 Generating the Detections Layer

```python
"""
generate_coverage_layer.py — scan sigma/rules/, build ATT&CK Navigator layer.
"""
import json, os, re, uuid
from collections import defaultdict
from pathlib import Path

SIGMA_DIR = Path("sigma/rules")
COVERAGE = defaultdict(list)

for path in SIGMA_DIR.rglob("*.yml"):
    text = path.read_text()
    # Extract tags: attack.t<digits>(.<digits>)?
    tags = re.findall(r"- attack\.t(\d{4}(?:\.\d{3})?)", text)
    # Extract status and level
    status_m = re.search(r"^status:\s*(\w+)", text, re.MULTILINE)
    level_m  = re.search(r"^level:\s*(\w+)", text, re.MULTILINE)
    status = status_m.group(1) if status_m else "unknown"
    level  = level_m.group(1) if level_m else "unknown"

    for t in tags:
        COVERAGE[t].append({
            "rule": path.name,
            "status": status,
            "level": level,
        })

def score(entries):
    # 100 if any stable/high; 75 if stable/medium; 50 if experimental; 25 if test
    for e in entries:
        if e["status"] == "stable" and e["level"] in ("high","critical"):
            return 100
    for e in entries:
        if e["status"] == "stable":
            return 75
    for e in entries:
        if e["status"] == "experimental":
            return 50
    return 25

techniques = [
    {
        "techniqueID": f"T{t}",
        "score": score(entries),
        "comment": "; ".join(e["rule"] for e in entries),
    }
    for t, entries in COVERAGE.items()
]

layer = {
    "version": "4.5",
    "name": "Detections coverage",
    "domain": "enterprise-attack",
    "description": "Auto-generated from sigma/rules/",
    "techniques": techniques,
    "gradient": {
        "colors": ["#ff6666","#ffe766","#69ec49"],
        "minValue": 0,
        "maxValue": 100,
    },
    "legendItems": [],
    "metadata": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
}

Path("coverage.json").write_text(json.dumps(layer, indent=2))
print(f"Wrote coverage.json with {len(techniques)} techniques")
```

Upload `coverage.json` to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator) → Open Existing Layer.

---

## 7. Patterns Cookbook — Hunts With Full Queries

The following are ready-to-run hunts. Each maps to one ATT&CK sub-technique and ships as a Sigma rule + SIEM-native query.

### 7.1 T1003.001 — LSASS Memory via comsvcs.dll

```yaml
# Sigma
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
  filter_legitimate_admin:
    ParentImage|startswith:
      - 'C:\Program Files\Microsoft Monitoring Agent\'
      - 'C:\Program Files\SplunkUniversalForwarder\'
  condition: selection and not filter_legitimate_admin
level: high
```

```bash
# Splunk
index=win source="*Sysmon*" EventCode=1 Image="*\\rundll32.exe"
CommandLine="*comsvcs.dll*MiniDump*"
| where NOT match(ParentImage, "(?i)(Monitoring Agent|SplunkUniversalForwarder)")
| stats count by _time, host, User, ParentImage, CommandLine
```

### 7.2 T1059.001 — Encoded PowerShell

```yaml
title: PowerShell Encoded Command Execution
id: fb5524d2-25a7-11ee-be56-0242ac120002
status: experimental
description: Detects PowerShell invoked with -EncodedCommand/-enc — common obfuscation
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-Enc '
      - '-EncodedCommand '
      - '-enc '
      - '-e '
  filter_legitimate_admin:
    ParentImage|startswith:
      - 'C:\Program Files\Microsoft Monitoring Agent\'
      - 'C:\Program Files\SCCM\'
  condition: selection and not filter_legitimate_admin
level: medium
```

### 7.3 T1053.005 — Scheduled Task Creation by Suspicious Parent

```yaml
title: Scheduled Task Created by Scripting Interpreter
id: 1c2b3e4d-25a8-11ee-be56-0242ac120002
status: experimental
description: Detects schtasks /create invoked from wscript/cscript/mshta/powershell — T1053.005
tags:
  - attack.persistence
  - attack.t1053.005
  - attack.privilege_escalation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
    ParentImage|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\powershell.exe'
      - '\cmd.exe'
  condition: selection
level: high
```

### 7.4 T1547.001 — New Run Key Value

```yaml
title: New Run Key Registry Value
id: 2d3f4e5c-25a9-11ee-be56-0242ac120002
status: experimental
description: Detects writes to HKLM/HKCU Run/RunOnce/RunOnceEx keys — T1547.001
tags:
  - attack.persistence
  - attack.t1547.001
  - attack.privilege_escalation
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
      - '\CurrentVersion\RunOnceEx\'
    EventType: SetValue
  filter_legitimate_installer:
    Image|startswith:
      - 'C:\Windows\System32\msiexec.exe'
      - 'C:\Windows\SysWOW64\msiexec.exe'
  condition: selection and not filter_legitimate_installer
level: medium
```

### 7.5 T1071.004 — DNS Tunneling

```yaml
title: Long DNS Label — Potential DNS Tunneling
id: 3e4f5a6b-25aa-11ee-be56-0242ac120002
status: experimental
description: Detects DNS queries with abnormally long leftmost label — T1071.004
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
  - attack.t1048.003
logsource:
  product: zeek
  service: dns
detection:
  selection:
    query|re: '^[A-Za-z0-9+/_=-]{30,}\.'
  condition: selection
fields:
  - id.orig_h
  - id.resp_h
  - query
  - qtype_name
level: medium
```

### 7.6 T1021.002 — SMB Admin Share Write

```yaml
title: File Written to Admin Share via SMB
id: 4f5a6b7c-25ab-11ee-be56-0242ac120002
status: experimental
description: Detects remote file write to ADMIN$/C$/IPC$ — T1021.002
tags:
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName|contains:
      - '\\ADMIN$'
      - '\\C$'
      - '\\IPC$'
  filter_legitimate_admin:
    SubjectUserName|endswith: '$'    # computer accounts
  condition: selection and not filter_legitimate_admin
level: medium
```

### 7.7 T1562.001 — Defender Disable

```yaml
title: Defender Feature Disabled via PowerShell
id: 5a6b7c8d-25ac-11ee-be56-0242ac120002
status: experimental
description: Detects Set-MpPreference -Disable* — T1562.001
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|all:
      - 'Set-MpPreference'
      - '-Disable'
  condition: selection
level: high
```

### 7.8 T1490 — Volume Shadow Copy Deletion

```yaml
title: Volume Shadow Copy Deletion
id: 6b7c8d9e-25ad-11ee-be56-0242ac120002
status: experimental
description: Detects vssadmin/wmic/wbadmin shadow deletion — T1490 (ransomware precursor)
tags:
  - attack.impact
  - attack.t1490
logsource:
  product: windows
  category: process_creation
detection:
  selection_vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_wmic:
    Image|endswith: '\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_wbadmin:
    Image|endswith: '\wbadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'catalog'
  condition: 1 of selection_*
level: critical
```

### 7.9 T1546.003 — WMI Event Subscription

```yaml
title: WMI Event Subscription Creation
id: 7c8d9e0f-25ae-11ee-be56-0242ac120002
status: experimental
description: Detects WMI Filter/Consumer/Binding creation via Sysmon EID 19/20/21 — T1546.003
tags:
  - attack.persistence
  - attack.t1546.003
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 19
  selection_2:
    EventID: 20
  selection_3:
    EventID: 21
  condition: 1 of selection_*
level: high
```

### 7.10 T1486 — Mass File Modification (Ransomware)

```yaml
title: Rapid Mass File Modification — Ransomware Pattern
id: 8d9e0f1a-25af-11ee-be56-0242ac120002
status: experimental
description: Detects >100 file-create events in 10s from one process — T1486
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: windows
  category: file_event
detection:
  selection:
    EventID: 11
  timeframe: 10s
  condition: selection | count() by host, Image > 100
level: critical
```

---

## 8. Phase 4 — Triage & Investigate

### 8.1 Triage Matrix

For each hit, walk this matrix. The goal is to classify each hit in <2 minutes.

| Signal | Likely Benign | Likely Malicious | Inconclusive |
|--------|---------------|------------------|--------------|
| Parent process | SCCM, GPO, in-house IT tool signed by your CA | Office app, email client, browser, unknown binary | Service host with no command-line audit |
| Signer of the binary | Microsoft, CrowdStrike, your CA | Self-signed, unsigned, recently-changed signer | Valid cert but unknown CA |
| User context | Service account with documented purpose | Interactive user with admin rights, especially new admin | Shared account |
| Host context | Server in a known role, jump box, build agent | Workstation, especially developer or executive | New / re-imaged host |
| Network context (Zeek ±5 min) | Flows to known corporate services | Flows to new destination IP/domain, especially recently registered | No network telemetry (sensor gap) |
| Frequency (over 30d) | Daily/regular occurrence | First-time-ever for this host/user/parent combo | Rare but has happened before |

### 8.2 Per-Hit Enrichment Workflow

For every hit that survives the matrix:

1. **Pull process tree from EDR** — what spawned the parent? What did the child spawn next?
2. **Hash the parent binary and check VirusTotal** — is the binary known-benign, known-malicious, or unknown?
3. **Pull Zeek telemetry for the host in ±10 min** — any outbound flows? To where? With what SNI/user-agent?
4. **Check MISP / OpenCTI** — do any of the observed IPs/domains/hashes appear in active threat-intel?
5. **Build a one-page mini-timeline** — events leading up to and following the hit, in chronological order.

If after enrichment the hit is still likely malicious: trigger IR. If benign: document why, add the discriminator to the Sigma rule's `filter_*` clauses, and re-run.

### 8.3 The Tuning Loop

```
Run rule over 30d      →   Classify each hit
   ↑                              ↓
   │                     Add filter_* for each FP
   │                              ↓
Re-run over 30d         ←   Confirm FP rate < 5%
   ↓
Ship rule, set quarterly re-tune
```

---

## 9. Phase 5 — Document & Detect

### 9.1 Two Outputs, Every Hunt

Every hunt produces exactly two artifacts. No exceptions.

1. **Hunt report** — markdown file in `hunts/<technique>/<date>-hunt.md` capturing hypothesis, query, triage table, findings, and follow-on hunts. This is the institutional memory of the hunt program.
2. **Detection rule** — Sigma YAML in `sigma/rules/<tactic>/<name>.yml`, validated, translated, CI-tested, and shipped to the SIEM. This is the durable output.

A hunt that finds nothing still produces both. The hunt report says "negative result over 30d lookback"; the Sigma rule ships as a future-facing detection.

### 9.2 Hunt Report Template

```markdown
# Hunt: <ATT&CK ID> — <Technique Name>

**Author**: <name>      **Date**: <YYYY-MM-DD>
**Status**: Closed      **ATT&CK**: T<id> (<tactic>)
**Pyramid-of-Pain level**: TTP

## 1. Hypothesis
<one paragraph>

## 2. Data Required
| Source | Field(s) | Retention | Status |
|--------|----------|-----------|--------|
| Sysmon EID 1 | Image, CommandLine, ParentImage | 90d | OK |
| Zeek conn.log | id.orig_h, id.resp_h, duration | 30d | OK |

## 3. Query
<Sigma YAML or SIEM-native query>

## 4. Triage
| Time | Host | User | Hit Type | Classification |
|------|------|------|----------|----------------|
| ... | ... | ... | ... | FP — SCCM agent |

## 5. Findings
- Lookback: <start> → <end>
- Hosts scanned: <N>
- Total hits: <N>
- True positives: <N>  (escalated to IR ticket #XYZ)
- False positives: <N>  →  FP rate: <X>%

## 6. Detection Outcome
- [x] Sigma rule shipped: sigma/rules/<tactic>/<name>.yml
- [x] CI translation pipeline green
- [x] SIEM detection active, severity = high
- [x] ATT&CK Navigator layer updated

## 7. Follow-on Hunts
- Pivot to <next hypothesis> — based on the C2 IP observed in TP-2

## 8. References
- ATT&CK: <url>
- Sigma: <repo link>
- IR ticket: <link>
```

---

## 10. Detection Lifecycle

A Sigma rule is not done when it ships. It moves through a lifecycle:

```
Develop  →  Test      →  Review     →  Deploy  →  Tune    →  (Deprecate)
   │             │             │             │            │             │
   ▼             ▼             ▼             ▼            ▼             ▼
Sigma YAML,  Run against   Peer review, CI ships to   FP triage,    Removal when
threat       historical   ATT&CK tag,  SIEM via      threshold     coverage moved
intel links, data (30d+),  doc, naming  sigma-cli     tuning, decay to EDR or it
ATT&CK tag   FP <5% target convention                 audit log     no longer fires
```

### 10.1 Lifecycle Stages

| Stage | Sigma `status` | What Happens | Exit Criteria |
|-------|----------------|--------------|---------------|
| Develop | `experimental` | Author, iterate, internal testing | Schema valid; coverage correct |
| Test | `experimental` | Run against 30d history; tune FP | FP rate <5%; TP test fires |
| Review | `experimental` | Peer review of logic, tags, FP list | Approved by ≥1 other analyst |
| Deploy | `stable` | CI ships translation to all SIEMs | Detection active; alert latency within SLO |
| Tune | `stable` | Quarterly FP re-review; threshold adjustment | FP rate stable; rule still relevant |
| Deprecate | (removed) | Coverage moved to EDR; rule no longer adds value | Documented in CHANGELOG; removed in next sprint |

### 10.2 Quarterly Coverage Review

Every quarter:

1. Re-run the ATT&CK Navigator coverage layer (Section 6).
2. Diff against last quarter. New detections? Newly-deprecated ones?
3. Cross-reference with the red-team emulation log. Which emulated techniques are now covered? Which are still gaps?
4. Pick 3-5 high-priority gaps for next sprint's detection-engineering work.

---

## 11. Integration With Adjacent Skills

### 11.1 `logging-monitoring` (Sensor Infrastructure)

Threat hunting consumes logs. `logging-monitoring` builds the sensors. Hand-off:

- Hunting files a sensor gap → `logging-monitoring` adds the source to the collection pipeline.
- Hunting identifies a field that would unlock detections → `logging-monitoring` enables the parser.
- Hunting finds a log-tampering indicator → triggers `logging-monitoring`'s integrity-verification controls.

### 11.2 `deep-research` (Adversary Tradecraft Synthesis)

`deep-research` reads the latest threat reports, vendor blogs, and CVE write-ups. Its output is "adversary X is using technique Y." Threat hunting turns that into "given technique Y, here is the Sigma rule that detects it in our environment."

### 11.3 `digital-forensics` (Post-Hit Investigation)

A hunt that finds a true positive triggers IR. `digital-forensics` takes over from there:

- Preserve the host image and memory.
- Reconstruct the timeline of compromise.
- Determine scope (which other hosts? how long?).
- Feed lessons learned back into new hunt hypotheses.

### 11.4 Offensive Skills (`ad-ldap-attack`, `lateral-movement`, `persistence`, `credential-dumping` patterns)

Every offensive technique documented in the workspace is a hunt hypothesis. The purple-team loop:

1. Offensive skill documents the TTP.
2. Red team emulates the TTP in a controlled exercise.
3. Blue team (threat hunting) writes a Sigma rule for it.
4. Red team re-runs; either evades (new detection gap surfaced) or is caught (detection validated).
5. Offensive skill is updated with the validated detection as a known defense to evade next time.

---

## 12. Common Pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Hunting without a hypothesis | Endless SIEM scrolling, no detections shipped | Use the hypothesis template in Section 3.1; reject any hunt that can't fill it. |
| Hash-based detections | Detection stops firing after adversary recompiles | Aim higher on the Pyramid of Pain — TTPs, not IOCs. |
| Skipping the telemetry inventory | Detection appears to ship but never fires (data missing) | Run the inventory commands in Section 4.2 before authoring the query. |
| Shipping without FP tuning | SOC drowns in alerts, ignores them all | Iterate the Sigma rule until FP rate <5% over 30d (Section 8.3). |
| Treating Sigma as "yet another config file" | Translations drift from the Sigma source | Make Sigma the source of truth; CI regenerates SIEM-native queries on every PR. |
| Forgetting to file sensor gaps | Same hypothesis re-attempted, fails the same way | Track sensor gaps in a backlog; close hunts with gap documented when blocked. |
| No quarterly coverage review | Coverage layer goes stale; gaps accumulate | Calendar the review; treat it as a recurring meeting, not an aspiration. |
| ATT&CK tags at technique level (T1003) instead of sub-technique (T1003.001) | Coverage layer too coarse; multiple sub-techniques collapsed | Always tag sub-techniques. |
| Detection with no documented FP list | Next analyst can't tell if a hit is a known FP | The `falsepositives:` field is mandatory; list every known FP source. |

---

## 13. Maturity Model

Where is your hunt program? Self-assess quarterly:

| Level | Characteristics |
|-------|-----------------|
| **L0 — Reactive** | No proactive hunting. SOC responds only to alerts from vendor-provided detections. |
| **L1 — Ad-hoc** | Hunting happens occasionally, driven by threat reports. No Sigma repo. No coverage layer. |
| **L2 — Defined** | Hunt cadence (weekly/biweekly). Sigma repo exists. ATT&CK Navigator layer maintained. CI on Sigma rules. |
| **L3 — Measured** | Every hunt ships a Sigma rule or files a sensor gap. FP rates tracked. Detection lifecycle followed. Quarterly coverage review. |
| **L4 — Optimized** | Purple-team loop with red team. Detection-as-code pipeline across multiple SIEMs. Coverage gaps prioritized by threat-intel-driven relevance. Threat-intel (MISP/OpenCTI) feeds hunts automatically. |

Most organizations are at L1. The path from L1 to L3 is mechanical: adopt Sigma, set up CI, start the quarterly cadence. L4 requires a mature red team and a SIEM-agnostic detection pipeline.

---

**Related files**: `SKILL.md`, `payloads.md`, `test-cases.md`
**External resources**: MITRE ATT&CK Navigator, Sigma project, Pyramid of Pain (David Bianco), Elastic Security Labs, Splunk SOC2 hunt app, Microsoft Sentinel hunting queries
