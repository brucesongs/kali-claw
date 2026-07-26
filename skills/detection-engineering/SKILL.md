---
name: detection-engineering
description: Detection-as-code engineering covering Sigma rule authoring, YARA signature development, Splunk SPL / Kusto KQL / Elastic EQL queries, MITRE ATT&CK mapping, detection CI/CD pipelines, false-positive tuning, and rule testing against EVTX-ATTACK-SAMPLES — using SigmaHQ, Yara-Rules, Loki, yarGen, hayabusa, SigmaCLI, and zircollo.
origin: github-trending-2026
version: "0.2.0.2"
compatibility: ">=0.1.30"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: defense
  tool_count: 14
  guide_count: 2
  mitre: "TA0040-Detection (detection engineering discipline); provides coverage across all ATT&CK techniques via Sigma rule taxonomy"
  last_reviewed: "2026-07-26"
---




# Skill: Detection Engineering

> **Supplementary Files**:
> - `payloads.md` — Sigma rule anatomy & authoring patterns, SigmaCLI usage, YARA rule anatomy & patterns, yarGen auto-generation, Loki scanning, Splunk SPL / Kusto KQL / Elastic EQL detection libraries, hayabusa & zircollo Sigma-to-EVTX pipelines, MITRE ATT&CK mapping, GitHub Actions / GitLab CI detection CI/CD, false-positive tuning methodology, and the detection-as-code lifecycle checklist
> - `test-cases.md` — 12 structured test cases (Sigma authoring, YARA authoring, SigmaCLI translation, yarGen generation, Loki scan, hayabusa scan, zircollo offline, ATT&CK mapping, CI pipeline, FP tuning, KQL/SPL/EQL backends, lifecycle) with severity ratings and summary tables
> - `guides/detection-engineering-playbook.md` — End-to-end detection engineering playbook (lifecycle, rule anatomy deep-dives, CI/CD pipeline recipes, FP-tuning matrix, ATT&CK coverage measurement, integration with threat-hunting and logging-monitoring)
> - `guides/soc-playbook-mapping-to-nist-csf-2-0.md` — SOC playbook mapping detections to NIST CSF 2.0 and MITRE ATT&CK (Function mapping for Govern/Identify/Protect/Detect/Respond/Recover, Sigma → ATT&CK → CSF traceability matrix, detection-as-code pipeline, use-case prioritization matrix, detection maturity model DMM, purple-team validation with Atomic Red Team + RTA, and SOC KPIs)

## Summary

Detection Engineering skill domain covering the craft of writing, testing, deploying, and retiring detection rules as code.

**Tools**: SigmaHQ + SigmaCLI, YARA + Yara-Rules, yarGen, Loki, hayabusa, zircollo, Splunk SPL, Microsoft Sentinel KQL, Elastic EQL/Lucene, MITRE ATT&CK, EVTX-ATTACK-SAMPLES, pySigma, sigma-scanner

**Domain**: defense

**MITRE ATT&CK**: TA0040-Detection (detection engineering discipline); rules in this skill provide coverage across every ATT&CK technique via the Sigma taxonomy.

## Description

Detection engineering is the discipline of treating detection content — Sigma rules, YARA signatures, SIEM queries, EDR detections — as first-class software artifacts with version control, peer review, automated tests, staged rollouts, and retirement criteria. The detection engineer reads threat intelligence and red-team tradecraft, drafts a Sigma rule (or YARA signature, or SPL query) that captures the TTP, writes unit tests that assert the rule fires on known-malicious samples from EVTX-ATTACK-SAMPLES and stays silent on known-benign baseline data, ships it through a GitHub Actions / GitLab CI pipeline that validates YAML schema and ATT&CK tag coverage, deploys to staging for a false-positive soak, and only then promotes to production. This is *detection-as-code* and it is what separates a SOC that pages on noise from a SOC that pages on signal.

**Difference from `threat-hunting`**: Threat hunting is the *analytic* practice of forming a hypothesis and walking the telemetry to test whether an adversary is inside. Detection engineering is the *craft* practice of authoring, testing, and shipping the rules that hunting and the SOC rely on. Hunting consumes telemetry; detection engineering *manufactures* the reusable detectors that consume telemetry. A hunt that finds something becomes a detection-engineering work item; a detection that fires becomes a hunt hypothesis for refinement. They are paired: hunting supplies the empirical truth that detection engineers encode, and detection engineers supply the detectors that hunters lean on for breadth.

**Difference from `logging-monitoring`**: Logging & monitoring is *infrastructure* — the sensors, shippers, indexes, retention, and tamper-proof storage that produce the telemetry in the first place. Detection engineering is *content* — the queries and rules that run against that infrastructure. You cannot engineer a detection for an event that is not logged; you can log forever and have zero detections. `logging-monitoring` builds the grid; `detection-engineering` writes what runs on it.

**Difference from `deception-honeypot`**: Deception manufactures high-fidelity telemetry from fake assets — every hit is signal because no legitimate user touches a decoy. Detection engineering trades in *noisy* telemetry — production logs where legitimate admin activity blends with adversary tradecraft — and the craft is in writing rules that suppress the former while catching the latter. The two complement: a honeypot produces a near-zero-FP detection (covered in `deception-honeypot`); detection engineering produces the bulk of SOC detections where FP tuning is the central craft problem.

**Detection engineering lifecycle**: threat intel / TTP → rule draft → unit test against positive and negative corpora → CI validation (schema, ATT&CK tags, syntax) → staging soak → FP tuning → production ship → coverage layer update → quarterly review → retirement. This skill teaches every phase.

## Use Cases

- **Author a Sigma rule for a new TTP**: A threat-intel report describes a Cobalt Strike beacon loading `msxml3.dll` via ` rundll32.exe` (`T1059.001` / `T1129`). The detection engineer drafts a Sigma rule with `logsource: process_creation`, selection on `Image|endswith: \rundll32.exe` and `CommandLine|contains: msxml3.dll`, attaches ATT&CK tags `attack.t1059.001` and `attack.t1129`, and ships through CI to staging.
- **Author a YARA rule for a malware family**: A new loader family is observed with a consistent PE rich-header pattern and a unique XOR-decryption loop. The detection engineer drafts a YARA rule with `condition: uint16(0) == 0x5A4D and $rich and $xor_loop`, test-runs it against a folder of 1000 benign PE files to verify zero FP, and submits to the internal YARA repo.
- **Translate a Sigma rule to three SIEM backends**: One Sigma YAML → Splunk SPL (via the `splunk` backend), Microsoft Sentinel KQL (via the `azure-sentinel` or `microsoft-365-defender` backend), and Elastic EQL (via the `elastalert` or `eql` backend). The Sigma file is the source of truth; the platform queries are generated artifacts.
- **Generate a YARA rule automatically from malware samples**: Run `yarGen.py` against a folder of 30 unique loader samples. yarGen identifies strings that appear in the samples but not in a benign corpus, and emits a draft YARA rule. The engineer reviews, tightens the condition, and ships.
- **Scan a host's EVTX with Sigma offline**: Copy `Security.evtx`, `System.evtx`, and `Microsoft-Windows-Sysmon%4Operational.evtx` from a suspect host, then run `zircollo` or `hayabusa` against the EVTX with the SigmaHQ rule repo. Within minutes, every ATT&CK technique observed in the host's history is enumerated.
- **Scan a directory of files for YARA matches**: Run `loki.py --rules rules/ -p /opt/samples` to apply every YARA rule in `rules/` plus Loki's built-in IOC database (Suricata ET, ThreatFox) against every file. Useful at the IR evidence-collection stage to triage which binaries match known malware families.
- **Build a detection CI/CD pipeline**: A GitHub Actions workflow runs on every pull request to `sigma/rules/`. It validates YAML schema, asserts every rule has `id`, `status`, `tags`, `level`; runs `sigma-cli convert` to each SIEM backend to catch translation errors; runs the rule against EVTX-ATTACK-SAMPLES to confirm it fires on the positive corpus; runs against a benign EVTX corpus to confirm it stays silent on the negative corpus.
- **Tune a noisy detection's false-positive rate**: A detection that fires 200×/day on legitimate SCCM activity. The engineer pulls the hits, identifies the common parent process and signer, adds a filter (`filter: ParentImage|endswith: \sccm.exe`), re-runs against 30 days of historical data, and confirms the new FP rate is <1/day before re-shipping.
- **Measure ATT&CK coverage and identify gaps**: Generate a MITRE ATT&CK Navigator layer from the union of `tags:` across every Sigma rule in the repo. Red cells = no coverage; yellow = partial; green = full. The quarterly review with the red team prioritizes new detections for the red cells.
- **Retire a deprecated detection**: A Sigma rule for a 5-year-old malware family that has not fired in 24 months. The engineer moves it to `rules/deprecated/`, sets `status: deprecated`, files a retirement ticket, and removes it from production SIEM import. Coverage layer is updated.

## Core Tools

### Sigma Ecosystem

| Tool | Purpose | Command / Usage |
|------|---------|-----------------|
| **Sigma** | Vendor-neutral YAML signature format for log detection — the "YARA for logs." Author once, translate to any SIEM. | Author `.yml`; the YAML is the source of truth |
| **SigmaHQ/sigma** | The reference rule repository — 3000+ community Sigma rules mapped to ATT&CK, organized by tactic. | `git clone https://github.com/SigmaHQ/sigma`; consume rules or submit PRs |
| **SigmaCLI (sigma-cli)** | Command-line interface to the pySigma translation engine. Converts Sigma YAML → Splunk, Sentinel, Elastic, QRadar, ArcSight, Logpoint, etc. | `sigma-cli convert -t splunk -p splunk_windows rule.yml` |
| **pySigma** | The Python library underlying SigmaCLI; supports custom backends, pipelines, and validators. | `from sigma.collection import SigmaCollection; from sigma.backends.splunk import SplunkBackend` |

### YARA Ecosystem

| Tool | Purpose | Command / Usage |
|------|---------|-----------------|
| **YARA** | Pattern-matching engine for files and memory — the malware-family classification standard. | `yara -r rules.yar /opt/samples/` |
| **Yara-Rules/rules** | The community YARA rule repository — signature packs for malware families, exploits, and tools. | `git clone https://github.com/Yara-Rules/rules.git` |
| **yarGen** | Auto-generates YARA rules from a set of malware samples by extracting strings that do NOT appear in a benign corpus. | `python3 yarGen.py -m /opt/malware/ -o /tmp/rule.yar --top 20` |
| **Loki** (Neo23x0) | IOC + YARA scanner — Sweeps a host or directory against a curated YARA + IOC database (Suricata ET, ThreatFox, custom). | `python3 loki.py -p /opt/samples --rules /opt/signatures/` |

### EVTX Scanners (Sigma-to-EVTX)

| Tool | Purpose | Command / Usage |
|------|---------|-----------------|
| **hayabusa** (Yamato Security) | Fast Sigma-to-EVTX scanner written in Rust — applies the full SigmaHQ rule set to a folder of `.evtx` files in minutes. | `./hayabusa csv-timeline -d /opt/evtx/ -o timeline.csv -r rules/` |
| **zircollo** | Lightweight Sigma-to-EVTX scanner — converts Sigma rules to SQLite SQL, then queries EVTX-to-SQLite exports. | `python3 zircollo.py -e evtx/ -r rules.yml -o matches.json` |
| **EVTX-ATTACK-SAMPLES** (sbousseaden) | Reference corpus of attack-generated EVTX files mapped to ATT&CK — the positive test corpus for detection testing. | `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git` |

### SIEM Query Languages (Detection Backends)

| Platform | Language | Example Detection |
|----------|----------|-------------------|
| **Splunk** | SPL (Search Processing Language) | `index=win sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 Image="*\\rundll32.exe" CommandLine="*MiniDump*"` |
| **Microsoft Sentinel / Defender** | KQL (Kusto Query Language) | `DeviceProcessEvents \| where FileName =~ "rundll32.exe" \| where ProcessCommandLine has "MiniDump"` |
| **Elastic Stack** | Lucene + EQL (Event Query Language) + ES\|QL | `process where process.name == "rundll32.exe" and process.command_line == "*MiniDump*"` |

### Frameworks & References

| Framework | Purpose |
|-----------|---------|
| **MITRE ATT&CK Enterprise** | Canonical TTP taxonomy — every Sigma rule carries `attack.tXXXX[.XXX]` tags; coverage is measured by tag union. |
| **MITRE ATT&CK Navigator** | Visualizes coverage as a heatmap layer — generated from Sigma rule tags. |
| **OSSEM** | Common data model — used in Sigma field mapping for cross-vendor portability. |
| **SigmaHQ pySigma-pipeline-sysmon** | Field-name mapping pipeline that translates generic Sigma fields to Sysmon-specific names. |

## Methodology

### Detection Engineering Six-Phase Lifecycle

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5            Phase 6
Threat Intel   →   Rule Draft      →  Unit Test      →  CI Validation   →  Staging Soak   →  Production &
& TTP Intake       Authoring          (pos + neg corpus)  (schema + tags +    (FP measurement)    Retirement
   │                  │                  │                  backends)            │                  │
   ▼                  ▼                  ▼                  ▼                    ▼                  ▼
Read TI report,  Draft Sigma YAML  Test rule against   GitHub Actions:     Deploy to staging  Ship to prod,
red-team report, or YARA signature EVTX-ATTACK-       sigma-cli convert   SIEM, observe for  update ATT&CK
or ATT&CK         matching the      SAMPLES (must      to every backend;   7-30 days; FP     Navigator layer;
technique →       technique         fire) + benign     schema validate;   tune below        quarterly review
detection gap                       EVTX (must stay    lint ATT&CK tags   threshold; ship   → retire if silent
                                    silent)                                                  > 24 months
```

**Phase 1: Threat Intel & TTP Intake**

Every detection begins with a TTP (technique, tactic, procedure) drawn from threat intel, red-team findings, or an ATT&CK coverage gap.

```
Intake sources:
- Threat intel reports (vendor blogs, CISA advisories, MISP events)
- Red-team debrief ("we emulated T1003.001 via comsvcs.dll; did you catch it?")
- ATT&CK Navigator coverage layer (red cells = uncovered techniques)
- Incident retrospectives ("we missed X; build a detection for it")
- Community Sigma rule PRs to SigmaHQ/sigma

Output: a one-paragraph "detection design" capturing:
  - ATT&CK ID(s) covered
  - Log source(s) required (Sysmon EID 1, WinEvent 4688, Zeek dns.log, etc.)
  - Hypothesis: "if TTP X happened, we would see Y in log source Z"
  - Expected FP rate (TTP-level hunts have lower FP than IOC-level)
  - Pyramid-of-Pain elevation (TTP-level > behavior-level > IOC-level)
```

**Phase 2: Rule Draft Authoring**

Draft the Sigma YAML (or YARA signature, or SIEM-native query). The Sigma file is the source of truth.

```yaml
# Sigma rule draft — Mimikatz credential dumping (T1003.001)
title: Mimikatz Command Line Patterns
id: c6e3dea0-e1a7-4d2e-9f17-c1f3f0d4a7b2
status: experimental
description: >-
  Detects Mimikatz command-line invocations matching the canonical
  sekurlsa::logonpasswords / lsadump::sam / kerberos::ptt patterns.
  TTP: T1003.001 LSASS Memory, T1003.002 Security Account Manager.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://github.com/gentilkiwi/mimikatz
author: kali-claw detection-engineering skill
date: 2026/06/17
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
logsource:
  product: windows
  category: process_creation
detection:
  selection_mimikatz_image:
    Image|endswith:
      - '\mimikatz.exe'
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
  filter_legitimate_admin:
    ParentImage|endswith:
      - '\sccm.exe'         # SCCM admin tasks
      - '\wsca.exe'         # in-house IT tooling
  condition: selection_mimikatz_image or
             (CommandLine and selection_mimikatz_commandline and not filter_legitimate_admin)
fields:
  - Computer
  - User
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Authorized mimikatz use by the internal red team (filter by ParentUser)
  - Security training exercises (filter by host naming convention)
level: high
```

**Phase 3: Unit Testing (Positive + Negative Corpora)**

A detection without tests is a hypothesis, not a detector. Test on:

```
Positive corpus (rule MUST fire):
  - EVTX-ATTACK-SAMPLES/Windows/.../mimikatz-logonpasswords.evtx
  - Red-team emulation logs (atomic-red-team or CALDERA output)
  - Lab-generated: run mimikatz, capture Sysmon log, ship to corpus

Negative corpus (rule MUST stay silent):
  - 30 days of benign EVTX from production workstations
  - SCCM admin activity
  - Antivirus scans
  - Software-deployment activity

Test command (hayabusa):
  ./hayabusa csv-timeline -d evtx-positive/ -r rule.yml
  # Expect: 1+ match in the positive folder

  ./hayabusa csv-timeline -d evtx-negative/ -r rule.yml
  # Expect: 0 matches in the negative folder
```

**Phase 4: CI Validation**

Every PR to the detections repo runs through a CI pipeline. Failures block merge.

```yaml
# .github/workflows/detection-ci.yml
name: Detection CI
on: [pull_request, push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }

      - name: Install SigmaCLI
        run: pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch

      - name: Schema validate every Sigma rule
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli parse "$f" || exit 1
          done

      - name: ATT&CK tag coverage check
        run: |
          python3 scripts/check-tags.py rules/
          # Asserts every rule has >= 1 attack.tXXXX tag

      - name: Translate to every backend (catch syntax errors)
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli convert -t splunk "$f" > /dev/null || exit 1
            sigma-cli convert -t lucene "$f" > /dev/null || exit 1
            sigma-cli convert -t kibana-ndjson "$f" > /dev/null || exit 1
          done

      - name: Positive corpus test
        run: |
          docker run --rm -v $PWD:/work yamatosecurity/hayabusa:latest \
            csv-timeline -d /work/test-data/positive/ -r /work/rules/ \
            -o /tmp/pos.csv
          test -s /tmp/pos.csv  # must produce non-empty output

      - name: Negative corpus test
        run: |
          docker run --rm -v $PWD:/work yamatosecurity/hayabusa:latest \
            csv-timeline -d /work/test-data/negative/ -r /work/rules/ \
            -o /tmp/neg.csv
          # Expect zero matches for any rule tagged level>=medium
```

**Phase 5: Staging Soak & FP Tuning**

Deploy to the staging SIEM, observe for 7-30 days, measure FP rate. Tune until FP rate < target threshold (typically < 1 hit/day).

```
FP tuning workflow:
1. Pull every hit from staging over the soak period
2. Group by (ParentImage, ParentUser, Computer, CommandLine signature)
3. For each cluster > 5 hits/day: identify if it is benign
4. If benign: add a filter clause, re-test on the historical soak data
5. Re-deploy, observe for another soak period
6. Repeat until FP rate < target OR escalate to "rule is too noisy, redesign"

Common FP-tuning patterns:
- Filter by parent process (SCCM, GPO, in-house tools)
- Filter by signer (Microsoft, the org's code-signing cert)
- Filter by host naming convention (jump hosts, build servers)
- Constrain CommandLine pattern (anchor to start, require exact flag)
- Add a timeframe aggregation (only fire if N hits in T minutes)
```

**Phase 6: Production & Retirement**

Ship to production SIEM. Update the ATT&CK Navigator coverage layer. Set a quarterly review reminder. A rule that goes silent for 24 months is retired.

```bash
# Ship: commit the rule, the PR merges after CI passes
git add rules/credential_access/mimikatz-cmdline.yml
git commit -m "feat(detection): T1003.001 mimikatz cmdline patterns (FP <0.5/day over 30d soak)"

# Update coverage layer
python3 scripts/build-navigator-layer.py rules/ -o coverage.json
# Upload to ATT&CK Navigator

# Quarterly review
python3 scripts/rule-liveness.py --since 90d
# Reports each rule's hit count; rules with 0 hits across all SIEMs
# for 24 months are candidates for retirement
```

### Quick Selection Guide

| Scenario | Primary Tool | Alternative |
|----------|--------------|-------------|
| Author a vendor-neutral log detection | Sigma YAML + SigmaCLI | YARA (if file-based) |
| Translate Sigma to Splunk SPL | `sigma-cli convert -t splunk` | pySigma SplunkBackend |
| Translate Sigma to Sentinel KQL | `sigma-cli convert -t microsoft-365-defender` | Hand-translate using ATT&CK workbooks |
| Translate Sigma to Elastic EQL | `sigma-cli convert -t eql` | pySigma ElasticsearchBackend |
| Auto-generate YARA from malware samples | `yarGen.py -m /opt/samples` | Hand-author after string analysis |
| Scan a host's EVTX with Sigma rules | `hayabusa csv-timeline -d evtx/ -r rules/` | `zircollo.py -e evtx/ -r rules.yml` |
| Scan files for malware family IOCs | `loki.py -p /opt/samples --rules signatures/` | `yara -r rules.yar /opt/samples/` |
| Test a rule against known-malicious EVTX | EVTX-ATTACK-SAMPLES + hayabusa | Atomic Red Team + lab EVTX |
| CI-validate a Sigma rule on every PR | GitHub Actions + sigma-cli | GitLab CI + sigma-cli |
| Build a coverage heatmap | ATT&CK Navigator + Sigma tag union | MITRE CAR coverage mapping |

### Defense Perspective

This skill IS the defense perspective. Detection engineering is the practice of building the reusable detectors that the SOC, threat hunters, and IR all rely on. Quality gates are central:

| Defense Output | Description |
|----------------|-------------|
| **Detection-as-code repository** | A Git repo (Sigma rules, YARA signatures, SPL/KQL/EQL queries) where every rule has: an author, a date, an ATT&CK tag, a status (`experimental`/`stable`/`deprecated`), a level, and a documented FP rate. CI runs on every PR. |
| **Unit-tested detections** | Every rule ships with a positive-corpus test (fires on known-malicious EVTX) and a negative-corpus test (silent on known-benign EVTX). Untested rules do not ship. |
| **CI/CD pipeline** | A GitHub Actions / GitLab CI pipeline that validates YAML schema, ATT&CK tag coverage, backend translation, and positive/negative corpus behavior. Pipeline failures block the merge. |
| **FP-tuning discipline** | Every production rule has a documented FP rate. Hits above threshold trigger a tuning sprint. Rules that cannot be tuned below threshold are deprecated. |
| **Coverage measurement** | An ATT&CK Navigator layer generated from the union of rule tags. Quarterly review with the red team prioritizes new detections for uncovered techniques. |
| **Lifecycle discipline** | Rules move `experimental → stable → deprecated`. Quarterly reviews identify silent rules (24 months without a hit) for retirement. The detections repo does not grow unbounded. |
| **Detection backends** | Sigma is the source of truth; SIEM queries are generated. A rule update propagates to every SIEM via CI; no manual duplication. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Author a Sigma Rule for Mimikatz (T1003.001)

Goal: draft, test, and ship a Sigma rule for Mimikatz command-line invocations.

```bash
mkdir -p detections/t1003-001-mimikatz
cd detections/t1003-001-mimikatz

# Draft the Sigma rule (see Phase 2 above for the full YAML)
$EDITOR mimikatz-cmdline.yml

# Validate the schema
sigma-cli parse mimikatz-cmdline.yml

# Translate to Splunk SPL
sigma-cli convert -t splunk -p sysmon mimikatz-cmdline.yml

# Translate to Elastic Lucene
sigma-cli convert -t lucene mimikatz-cmdline.yml

# Translate to Kibana NDJSON (importable rule)
sigma-cli convert -t kibana-ndjson mimikatz-cmdline.yml > kibana-import.ndjson

# Test against positive corpus (EVTX-ATTACK-SAMPLES)
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git /tmp/evtx-attack
hayabusa csv-timeline -d /tmp/evtx-attack/ -r mimikatz-cmdline.yml -o hits.csv
# Expect: matches in Triggers/ credential-access/ subfolder

# Commit
git add mimikatz-cmdline.yml
git commit -m "feat(detection): T1003.001 mimikatz cmdline patterns"
```

### Exercise 2: Author a YARA Rule for a Malware Family

Goal: write a YARA rule for the Cobalt Strike beacon PE loader.

```bash
mkdir -p yara-rules/malware-family
$EDITOR cobalt_strike_beacon.yar

# cobalt_strike_beacon.yar
# rule CobaltStrike_Beacon_Loader {
#   meta:
#     description = "Cobalt Strike beacon loader - PE rich header pattern"
#     author = "kali-claw detection-engineering skill"
#     date = "2026-06-17"
#     reference = "https://attack.mitre.org/software/S0154/"
#     malpedia = "win.cobalt_strike"
#   strings:
#     $rich1 = { 68 02 00 00 03 00 00 00 }   # DOS stub pattern
#     $rich2 = "DanS" wide ascii              # rich header magic
#     $xor_loop = { 80 30 ?? 46 49 75 ?? }   # XOR decrypt loop
#     $api_resolve = "VirtualAlloc" wide ascii
#   condition:
#     uint16(0) == 0x5A4D and       # PE MZ magic
#     $rich1 and $rich2 and
#     ($xor_loop or $api_resolve) and
#     filesize < 500KB
# }

# Validate syntax
yara cobalt_strike_beacon.yar /tmp/any-file.bin

# Test against positive corpus (known CS beacon samples)
yara -r cobalt_strike_beacon.yar /opt/samples/cobalt-strike/
# Expect: matches on each sample

# Test against negative corpus (benign PE files)
yara -r cobalt_strike_beacon.yar /opt/samples/benign-pe/
# Expect: zero matches

# Commit
git add cobalt_strike_beacon.yar
git commit -m "feat(yara): Cobalt Strike beacon loader signature"
```

### Exercise 3: Translate a Sigma Rule to Three SIEM Backends

Goal: take one Sigma YAML, produce Splunk SPL, Sentinel KQL, and Elastic EQL.

```bash
# Single Sigma rule
cat > rules/aws-console-login-new-geo.yml <<'EOF'
title: AWS Console Login from New Geographic Location
id: f0d1a2b3-c4d5-6789-abcd-ef0123456789
status: experimental
description: >-
  Detects AWS Management Console logins (ConsoleLogin) from a geographic
  location not seen for this user in the preceding 14 days. T1078 Valid Accounts.
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
EOF

# Translate to Splunk SPL
sigma-cli convert -t splunk rules/aws-console-login-new-geo.yml

# Translate to Microsoft Sentinel / Defender KQL
sigma-cli convert -t microsoft-365-defender rules/aws-console-login-new-geo.yml

# Translate to Elastic EQL
sigma-cli convert -t eql rules/aws-console-login-new-geo.yml

# The Sigma file is the source of truth; the platform queries are
# generated artifacts, committed alongside the rule for auditability.
```

### Exercise 4: Generate a YARA Rule with yarGen

Goal: auto-generate a YARA rule from a folder of malware samples.

```bash
# Clone yarGen
git clone https://github.com/Neo23x0/yarGen.git
cd yarGen
pip install -r requirements.txt

# Initialize the benign string database (one-time, ~1 hour)
python3 yarGen.py --update

# Generate a rule from a folder of malware samples
python3 yarGen.py \
  --malware /opt/samples/malware-family-x/ \
  --top 20 \
  --exclude-extensions pdf,docx \
  --output /tmp/family-x.yar

# Review the generated rule
cat /tmp/family-x.yar
# yarGen emits a rule with the highest-signal strings it found;
# the engineer reviews, removes low-signal strings (e.g., "MZ",
# "This program cannot be run in DOS mode"), and tightens the condition.

# Test the generated rule
yara -r /tmp/family-x.yar /opt/samples/malware-family-x/   # expect matches
yara -r /tmp/family-x.yar /opt/samples/benign/             # expect zero matches
```

### Exercise 5: Scan a Host's EVTX with hayabusa

Goal: take a Windows host's EVTX files and enumerate every ATT&CK technique observed.

```bash
# Download hayabusa
wget https://github.com/YamatoSecurity/hayabusa/releases/latest/download/hayabusa-2.18.0-linux.zip
unzip hayabusa-2.18.0-linux.zip -d hayabusa
cd hayabusa

# Update the built-in Sigma rules
./hayabusa update-rules

# Pull EVTX from the suspect host (off-host, no tip-off)
# SCP from the Windows host:
# C:\Windows\System32\winevt\Logs\*.evtx

# Run a full timeline
./hayabusa csv-timeline \
  -d /opt/evtx/suspect-host/ \
  -r rules/ \
  -o timeline.csv \
  --min-level medium \
  --no-color

# Summary: which ATT&CK techniques fired
./hayabusa metrics \
  -d /opt/evtx/suspect-host/ \
  -o metrics.csv

# Output is a CSV timeline; pivot to ATT&CK Navigator for visualization
```

### Exercise 6: Scan Files with Loki (YARA + IOC)

Goal: sweep a directory of binaries against a curated YARA + IOC database.

```bash
# Clone Loki
git clone https://github.com/Neo23x0/Loki.git
cd Loki
pip install -r requirements.txt

# Update the signature database
python3 loki.py --update

# Scan a directory
python3 loki.py \
  --path /opt/samples \
  --rules /opt/signatures/custom-yara/ \
  --results /tmp/loki-results.csv \
  --alert-level 40 \
  --no-sigs \
  --force

# Review alerts
jq -r 'select(.severity >= 70)' /tmp/loki-results.csv | head -50

# Loki flags: --no-sigs disables Suricata-style NIDS rules,
# --force re-scans even if hashes were previously clean
```

### Exercise 7: Build a Detection CI Pipeline (GitHub Actions)

Goal: every PR to `rules/` runs schema validation, backend translation, and corpus tests.

```bash
mkdir -p .github/workflows
$EDITOR .github/workflows/detection-ci.yml
```

```yaml
# .github/workflows/detection-ci.yml (full content in payloads.md §14)
name: Detection CI
on: [pull_request, push]
jobs:
  sigma-validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch
      - name: Parse every rule
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli parse "$f" || exit 1
          done
      - name: Translate to backends
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli convert -t splunk "$f" > /dev/null || exit 1
            sigma-cli convert -t lucene "$f" > /dev/null || exit 1
          done
  corpus-test:
    needs: sigma-validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run hayabusa on positive corpus
        run: |
          docker run --rm -v $PWD:/work \
            yamatosecurity/hayabusa:latest \
            csv-timeline -d /work/test-data/positive/ \
            -r /work/rules/ -o /tmp/pos.csv
          test -s /tmp/pos.csv
```

### Exercise 8: Tune a Noisy Detection's False-Positive Rate

Goal: a Sigma rule is firing 200×/day on legitimate SCCM activity. Tune it.

```bash
# Pull every hit from the last 7 days
index=win sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  EventCode=1 Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*MiniDump*"
| stats count by Computer, User, ParentImage
| sort -count
| outputlookup noisy-detection-hits.csv

# Identify the top FP cluster: SCCM (\sccm.exe parent), running a legit
# crash-dump workflow during patch Tuesday.

# Add a filter to the Sigma rule
$EDITOR rules/credential_access/comsvcs-minidump.yml
# Add to detection:
#   filter_sccm:
#     ParentImage|endswith:
#       - '\sccm.exe'
#       - '\cmmcompiler.exe'
#   condition: selection and not filter_sccm

# Re-test against 30 days of historical data
sigma-cli convert -t splunk rules/comsvcs-minidump.yml | splunk search -e -30d
# Verify FP rate is now < 1/day

# Commit the tuned rule
git add rules/credential_access/comsvcs-minidump.yml
git commit -m "fix(detection): filter SCCM parent for comsvcs minidump (FP 200/d → 0.3/d)"
```

### Exercise 9: Measure ATT&CK Coverage and Identify Gaps

Goal: produce an ATT&CK Navigator layer from the rule repository.

```bash
# Build the coverage layer from every Sigma rule's tags
python3 scripts/build-navigator-layer.py rules/ -o coverage.json
# The script reads every rule, extracts attack.tXXXX[.XXX] tags,
# and emits a Navigator layer where each technique is colored by
# the number of rules covering it.

# Upload to ATT&CK Navigator
# https://mitre-attack.github.io/attack-navigator/
# Layer → Open Layer → Upload coverage.json

# Identify red cells (techniques with zero coverage)
python3 scripts/coverage-gaps.py coverage.json
# Output: list of ATT&CK techniques with no rule, sorted by
# prevalence in current threat intel reports.

# Quarterly review with red team: pick top 5 red cells, file
# detection-engineering tickets for each.
```

### Exercise 10: Retire a Deprecated Detection

Goal: a Sigma rule for a 5-year-old ransomware family has not fired in 24 months. Retire it.

```bash
# Confirm silence
python3 scripts/rule-liveness.py rules/malware/old-ransom-family.yml --since 730d
# Output: 0 hits across all SIEMs in the last 730 days

# Move to deprecated/
mkdir -p rules/deprecated
git mv rules/malware/old-ransom-family.yml rules/deprecated/

# Update the rule's status
$EDITOR rules/deprecated/old-ransom-family.yml
# Change: status: stable → status: deprecated

# Commit
git add -A
git commit -m "chore(detection): retire old-ransom-family rule (silent 24m+)"
# Coverage layer regenerates on next CI run; the technique may now show
# as partially covered (if other rules cover it) or uncovered.
```

## Detection Methods

### Detection Engineering Quality Metrics
- **Rule precision**: (True Positives) / (True Positives + False Positives); target >80%.
- **Rule recall**: (True Positives) / (True Positives + False Negatives); target >70%.
- **Mean Time to Detect (MTTD)**: Target <5 minutes for critical detections.
- **Coverage gaps**: MITRE ATT&CK techniques with no detection rules.

### Detection Rule Validation
- **Unit testing**: Sigma rule validation via `sigma-cli`; log signature matching.
- **Atomic Red Team**: Atomic tests for detection validation.
- **CALDERA / Atomic Red Team / Red Canary Atomic**: Adversary emulation for detection testing.
- **MITRE ATT&CK Evaluations**: Industry-standard detection platform evaluations.

## Defense Evasion Techniques

### Bypass Detection Engineering
- **Use uncovered techniques**: Target MITRE ATT&CK techniques with no detection rules.
- **Timing**: Execute slowly enough to fall below detection threshold.
- **Living off the Land**: Use legitimate admin tools (PowerShell, WMI, PsExec); blends with admin activity.
- **Time-shifted attacks**: Execute during SOC off-hours (nights, weekends).

### Defense Evasion Specific Techniques
- **Obfuscate signatures**: Modify malware signatures to evade YARA rules.
- **Code signing abuse**: Use stolen/leaked code signing certificates; appears legitimate.
- **Process injection**: Inject into legitimate process; inherits its identity and trust.
- **AMSI/ETW bypass**: Disable Windows anti-malware telemetry before payload execution.

### SIEM/Logging Blind Spots
- **Log source gaps**: Operate on systems without log forwarding (legacy apps, IoT devices).
- **Log tampering**: Compromise log forwarder; selectively drop entries.
- **Volume-based DoS**: Flood SIEM with noise; bury real alerts.

## Cross-References

This skill is the craft layer that produces detectors consumed by hunting, IR, and the SOC.

- `skills/threat-hunting/SKILL.md` — hunting consumes telemetry and forms hypotheses; this skill produces the detectors that hunters rely on for breadth. A hunt that finds something becomes a detection-engineering work item.
- `skills/logging-monitoring/SKILL.md` — the sensor and SIEM infrastructure that detection rules run against. Detection engineering is content; logging-monitoring is infrastructure.
- `skills/deception-honeypot/SKILL.md` — deception produces near-zero-FP detections (every honeypot hit is signal); detection engineering produces the bulk of SOC detections where FP tuning is the central craft problem.
- `skills/ad-ldap-attack/SKILL.md` — offensive counterpart; every technique (T1003, T1055, T1071, T1550, T1558) is a Sigma-rule target.
- `skills/chronicle/SKILL.md` — Chronicle SIEM (YARA-L detection language); a sibling detection backend with its own rule format. Detection engineers authoring for Chronicle consume the same TTP intake process.
- `skills/av-edr-evasion/SKILL.md` — adversary tradecraft for evading detections; informs the FP-tuning and rule-design work (what does the adversary do to blend in?).
- `skills/digital-forensics/SKILL.md` — post-fact investigation; uses hayabusa/zircollo as triage tools at the evidence-collection stage.
- `skills/deep-research/SKILL.md` — synthesizing threat intel from external sources; the upstream of the detection intake queue.

## Safety Notes

- **Rules are sensitive.** A Sigma rule that documents detection gaps is a roadmap for an adversary who obtains it. Treat the detections repo as confidential; store in a restricted Git remote, not the public wiki.
- **CI pipelines run untrusted content.** If the detections repo accepts external PRs (e.g., from community Sigma submissions), the CI pipeline executes SigmaCLI and hayabusa against attacker-supplied YAML. Sandbox the CI runners, pin dependency versions, and reject rules that fail schema validation without further inspection.
- **Test corpora may contain real malware.** EVTX-ATTACK-SAMPLES and the negative-corpus benign EVTX are sensitive. Store test-data in a restricted directory; do not commit real malware samples to the detections repo.
- **FP tuning is a slow process.** Do not ship a rule to production without a staging soak. A rule that fires 200×/day pages the SOC into alert fatigue within hours.
- **ATT&CK tags must be accurate.** A rule tagged `attack.t1003.001` that does NOT actually detect T1003.001 produces a false coverage heatmap. Peer review of tags is mandatory.
- **Rule retirement is not deletion.** Deprecated rules stay in `rules/deprecated/` for auditability; they are removed from SIEM import but the YAML is preserved. Re-enablement is a one-line `git mv`.
- **Cross-platform translation may drift.** SigmaCLI backends are community-maintained; the Splunk backend may not perfectly translate every Sigma modifier. Always review generated queries before SIEM import.
- **Detection content has dual-use.** Sigma rules help defenders; they also tell an adversary "here is what we catch — evade this way." Restrict repo access accordingly.

## Hacker Laws

- **Trust but Verify** — A Sigma rule that fired correctly on day one can silently fail when the log schema changes, the EDR updates, or the adversary shifts sub-technique. Every rule is unit-tested on every PR; every rule is re-tested quarterly against fresh positive and negative corpora. Detection drift is real; CI is the only defense.
- **Defense in Depth** — No single rule catches every variation of a TTP. Mimikatz can be invoked as `mimikatz.exe`, as `Invoke-Mimikatz` in PowerShell, as `comsvcs.dll MiniDump`, as `procdump -ma lsass.exe`, as a custom C# PInvoke. Detection engineering ships multiple rules per technique, each catching a different procedure variant.
- **Assume Breach** — The detection engineer writes rules assuming the adversary is already inside and is blending into legitimate admin activity. The rule is not "did X happen?" but "is this instance of X consistent with our admin baseline, or is it the adversary?" FP tuning is the craft of separating the two.
- **Pyramid of Pain** — IOC-level detections (a specific hash, IP, domain) are cheap for the adversary to change. TTP-level detections (the procedure, the technique) are expensive. Detection engineering aims as high on the Pyramid of Pain as the data allows; TTP-level rules force the adversary to change tradecraft.
- **First Principles Thinking** — Detection engineering begins not with "what alerts am I getting?" but "what TTPs does the adversary use, what trace would each TTP leave in our telemetry, and what reusable rule would catch that trace?" The TTP is the first principle; the rule is the implementation; CI is the quality gate.
- **Weakest Link Is Human** — The detection engineer is the link between threat intel and the SOC. If the engineer mis-tags a rule (`attack.t1003.001` for a rule that actually catches `T1003.002`), the coverage heatmap lies. Peer review of tags is the discipline that prevents this.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/detection-engineering-playbook.md` — end-to-end detection operations, from threat-intel intake through retirement, with rule authoring recipes, CI/CD pipeline templates, an FP-tuning matrix, and ATT&CK coverage measurement workflows
- **Related skills** (see Cross-References above)
- **External resources**:
  - Sigma project & SigmaHQ rule repo: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
  - SigmaCLI: [github.com/SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli)
  - pySigma (Python engine): [github.com/SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma)
  - YARA: [virustotal.github.io/yara](https://virustotal.github.io/yara/)
  - Yara-Rules community repo: [github.com/Yara-Rules/rules](https://github.com/Yara-Rules/rules)
  - yarGen: [github.com/Neo23x0/yarGen](https://github.com/Neo23x0/yarGen)
  - Loki scanner: [github.com/Neo23x0/Loki](https://github.com/Neo23x0/Loki)
  - hayabusa: [github.com/YamatoSecurity/hayabusa](https://github.com/YamatoSecurity/hayabusa)
  - zircollo: [github.com/wagga40/zircollo](https://github.com/wagga40/zircollo)
  - EVTX-ATTACK-SAMPLES: [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  - Splunk SPL docs: [docs.splunk.com/SPL](https://docs.splunk.com/Documentation/SCS/current/SearchReference/Overview)
  - Microsoft Sentinel KQL: [learn.microsoft.com/azure/sentinel](https://learn.microsoft.com/azure/sentinel/kusto-query-language)
  - Elastic EQL: [elastic.co/guide/eql](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html)
  - MITRE ATT&CK Enterprise: [attack.mitre.org](https://attack.mitre.org)
  - MITRE ATT&CK Navigator: [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator)
  - OSSEM (common data model): [github.com/OTRF/OSSEM](https://github.com/OTRF/OSSEM)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
