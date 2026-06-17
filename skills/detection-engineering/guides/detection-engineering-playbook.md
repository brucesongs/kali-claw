# Detection Engineering Playbook

> A deep-dive guide for the `detection-engineering` skill. This playbook walks through the full detection-as-code lifecycle with rule-authoring recipes, CI/CD pipeline templates, an FP-tuning matrix, and ATT&CK coverage measurement workflows.
>
> Companion files:
> - `../SKILL.md` — skill overview, use cases, methodology
> - `../payloads.md` — Sigma / YARA / SigmaCLI / yarGen / Loki / Splunk SPL / KQL / EQL / hayabusa / zircollo recipes
> - `../test-cases.md` — 12 structured test cases (TC-DE-001 through TC-DE-012)

---

## Table of Contents

1. [Detection Engineering Foundations](#1-detection-engineering-foundations)
2. [The Six-Phase Lifecycle in Depth](#2-the-six-phase-lifecycle-in-depth)
3. [Sigma Rule Authoring Deep Dive](#3-sigma-rule-authoring-deep-dive)
4. [YARA Rule Authoring Deep Dive](#4-yara-rule-authoring-deep-dive)
5. [SigmaCLI & pySigma Internals](#5-sigmacli--pysigma-internals)
6. [Detection CI/CD Pipeline Recipes](#6-detection-cicd-pipeline-recipes)
7. [FP-Tuning Matrix](#7-fp-tuning-matrix)
8. [ATT&CK Coverage Measurement](#8-attck-coverage-measurement)
9. [Staging Soak & Promotion](#9-staging-soak--promotion)
10. [Rule Retirement & Audit Trail](#10-rule-retirement--audit-trail)
11. [Integration with Sibling Skills](#11-integration-with-sibling-skills)
12. [Common Anti-Patterns](#12-common-anti-patterns)
13. [Reference: ATT&CK Tactic → Sigma Tag Mapping](#13-reference-attck-tactic--sigma-tag-mapping)

---

## 1. Detection Engineering Foundations

### 1.1 What Detection Engineering Is (and Isn't)

Detection engineering is the discipline of treating detection content — Sigma rules, YARA signatures, SIEM queries, EDR detections — as first-class software artifacts with:

- **Version control**: every rule has a git history; every change is a commit
- **Peer review**: every rule is reviewed by at least one other engineer before merging
- **Automated tests**: every rule has a positive-corpus test (fires on known-malicious) and a negative-corpus test (silent on known-benign)
- **CI/CD**: every pull request runs schema validation, backend translation, and corpus tests
- **Staged rollout**: rules deploy to staging first, soak for FP measurement, then promote to production
- **Retirement criteria**: rules silent for 24+ months are deprecated

Detection engineering is NOT:

- Writing one-off SIEM queries without tests
- Copying community Sigma rules into production without tuning
- Letting the SIEM alert volume grow unbounded (alert fatigue)
- Treating detections as static (they drift; CI re-validates them)
- Solely a SOC-analyst responsibility (it's a software engineering discipline)

### 1.2 The Detection Engineer's Role

The detection engineer sits between threat intelligence and the SOC:

```
Threat Intel (TI) ──→ Detection Engineer ──→ SOC
                         ▲                       
                         │                       
Red Team ───────────────┘                       
(debriefs on what was/wasn't caught)             
```

The engineer reads TI reports and red-team debriefs, drafts Sigma/YARA rules, writes tests, ships through CI, tunes FPs in staging, promotes to production, and retires stale detections. The SOC consumes the resulting alerts.

### 1.3 Pyramid of Pain Applied to Detection Design

David Bianco's Pyramid of Pain ranks indicators by how painful they are for the adversary to change:

```
                       ▲
                      / \
                     /   \
                    / TTPs\         ← Most painful (detection goal)
                   /_______\
                  /         \
                 /  Tools    \
                /_____________\
               /               \
              /  Network        \
             /    Artifacts      \
            /_____________________\
           /                       \
          /  Host                   \
         /    Artifacts              \
        /_____________________________\
       /                               \
      /  Domain Names                  \
     /                                  \
    /____________________________________ \
   /                                       \
  /  IP Addresses                          \
 /                                          \
/____________________________________________\
 Hash Values                                  ← Least painful (avoid)
```

Detection engineering aims as high on the pyramid as the data allows:

- **TTP-level detection**: "adversary dumps LSASS via comsvcs.dll" — high pain, the adversary must change procedure
- **Tool-level detection**: "Mimikatz binary present" — medium pain, the adversary switches tools
- **Network artifacts**: "beacon to evil-c2.example.com" — low pain, the adversary rotates domains
- **IOC-level detection**: "match SHA256 abcd..." — minimal pain, the adversary recompiles

The detection engineer drafts TTP-level rules by default and reserves IOC-level rules for short-lived emergency detections during an active IR.

---

## 2. The Six-Phase Lifecycle in Depth

The detection-as-code lifecycle has six phases. Every rule passes through all six (some at accelerated pace for emergency detections, some slowly for novel TTPs).

### Phase 1: Threat Intel & TTP Intake

**Input**: TI reports, red-team debriefs, ATT&CK coverage gap analysis, incident retrospectives

**Output**: a one-paragraph "detection design" capturing:

```
ATT&CK ID(s) covered:     T1003.001 (LSASS Memory)
Tactic:                   TA0006 (Credential Access)
Log source required:      Windows Sysmon EID 1 (process creation)
                          Windows Sysmon EID 10 (process access)
Hypothesis:               "An adversary with local-admin on a Windows host
                           may dump LSASS memory using comsvcs.dll MiniDump
                           invoked via rundll32.exe. Sysmon EID 1 should
                           capture the process creation; EID 10 should
                           capture the follow-on process-access event
                           against lsass.exe."
Expected FP rate:          LOW (comsvcs.dll MiniDump is not used by
                           legitimate software)
Pyramid-of-Pain level:    TTP (highest pain to adversary)
Intake source:            CISA advisory AA22-320A
Ticket:                   DETECT-2026-042
```

The intake is recorded in the ticketing system. The ticket travels with the rule through every subsequent phase.

### Phase 2: Rule Draft Authoring

The Sigma YAML is the source of truth. Author it first; SIEM-native queries are generated artifacts.

**Authoring checklist**:

- [ ] `title` is descriptive and unique within the repo
- [ ] `id` is a freshly-generated UUID v4 (`python3 -c "import uuid; print(uuid.uuid4())"`)
- [ ] `status` is `experimental` (default for new rules)
- [ ] `description` is 1-3 sentences explaining what the rule detects and why
- [ ] `references` includes the ATT&CK URL and any TI source
- [ ] `author` and `date` are set
- [ ] `tags` includes the tactic (`attack.<tactic>`) and at least one technique (`attack.tXXXX[.XXX]`)
- [ ] `logsource` correctly identifies the log source (`product`, `category`, optional `service`)
- [ ] `detection` has at least one selection block and a condition
- [ ] `fields` lists what to surface in the alert
- [ ] `falsepositives` documents known FP causes (even if "None expected")
- [ ] `level` is set (`informational` | `low` | `medium` | `high` | `critical`)

### Phase 3: Unit Testing (Positive + Negative Corpora)

A detection without tests is a hypothesis, not a detector.

**Positive corpus** (rule MUST fire):

- EVTX-ATTACK-SAMPLES: `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git`
- Atomic Red Team: `git clone https://github.com/redcanaryco/atomic-red-team.git` — run the atomic test, capture the Sysmon log
- CALDERA: run an adversary emulation plan, capture the EVTX
- Lab-generated: execute the TTP on a lab Windows host with Sysmon installed, capture the EVTX

**Negative corpus** (rule MUST stay silent):

- 30 days of benign EVTX from production workstations
- Include admin activity: SCCM patch deployment, GPO processing, antivirus scans, software deployments
- Include all software-deployment activity (the most common FP source)

**Test command** (hayabusa):

```bash
# Positive corpus — rule MUST fire
./hayabusa csv-timeline -d /opt/evtx/positive/ -r rules/ -o pos.csv --min-level low
test -s pos.csv  # assert non-empty

# Negative corpus — rule MUST stay silent (for level >= medium rules)
./hayabusa csv-timeline -d /opt/evtx/negative/ -r rules/ -o neg.csv --min-level low
if grep -E ',(medium|high|critical),' neg.csv; then
  echo "FAIL: rule fired on negative corpus"
  exit 1
fi
```

### Phase 4: CI Validation

Every PR runs through the CI pipeline (see §6 below). Failures block the merge.

**CI jobs**:

1. Sigma schema validation (parse every YAML)
2. ATT&CK tag coverage check (every rule has >= 1 `attack.tXXXX` tag)
3. Backend translation (SigmaCLI converts to Splunk, Elastic, KQL — catches syntax errors)
4. Positive corpus test (hayabusa runs; assert output non-empty)
5. Negative corpus test (hayabusa runs; assert no rule with level >= medium fired)
6. ATT&CK Navigator coverage layer build (regenerates `coverage.json`)

### Phase 5: Staging Soak & FP Tuning

Deploy to staging SIEM. Observe for 7-30 days. Measure hit rate. Triage every hit.

**FP-tuning workflow** (see §7 for the full matrix):

```
1. Pull every hit from staging over the soak period
2. Group by (Computer, User, ParentImage, CommandLine signature)
3. For each cluster > 5 hits/day: identify if benign
4. If benign: add a filter clause, re-test on the historical soak data
5. Re-deploy, observe for another soak period
6. Repeat until FP rate < 1/day OR escalate to "rule is too noisy, redesign"
```

### Phase 6: Production & Retirement

Promote to production after FP tuning. Update the ATT&CK Navigator coverage layer.

Set a quarterly review reminder. A rule that goes silent for 24 months is a retirement candidate.

---

## 3. Sigma Rule Authoring Deep Dive

### 3.1 Anatomy of a High-Quality Sigma Rule

```yaml
title: Suspicious comsvcs.dll MiniDump Invocation
id: 09e5f7d2-25a6-11ee-be56-0242ac120002
status: experimental
description: >-
  Detects rundll32.exe loading comsvcs.dll with MiniDump arguments,
  a T1003.001 LSASS memory dumping technique that requires no tool drop.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a
author: kali-claw detection-engineering skill
date: 2026/06/17
modified: 2026/06/17
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
  definition: 'Requirements: Sysmon EID 1 with command-line logging enabled'
detection:
  selection_image:
    Image|endswith: '\rundll32.exe'
  selection_commandline:
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  filter_legitimate_dump:
    ParentImage|endswith:
      - '\procdump.exe'           # Sysinternals procdump -ma lsass.exe is sometimes used by IT
      - '\werfault.exe'           # Windows Error Reporting
  filter_sccm:
    ParentImage|endswith: '\sccm.exe'
  condition: selection_image and selection_commandline and not 1 of filter_*
fields:
  - Computer
  - User
  - Image
  - CommandLine
  - ParentImage
falsepositives:
  - Authorized crash-dump tools (procdump) — filter by ParentImage
  - SCCM admin tasks — filter by ParentImage
level: high
```

### 3.2 Field Modifiers (Sigma's Secret Sauce)

Sigma's value proposition is vendor-neutral rules. Field modifiers make rules portable across SIEMs:

```yaml
# Substring matching
Image|endswith: '\rundll32.exe'         # matches at end of field
Image|startswith: 'C:\Windows\'         # matches at start of field
CommandLine|contains: 'MiniDump'        # matches anywhere

# Case sensitivity
User|contains|re: '(?i)admin'           # case-insensitive regex

# All vs any (for list values)
CommandLine|contains|all:               # ALL values must be present
  - 'comsvcs.dll'
  - 'MiniDump'
CommandLine|contains|any:               # ANY value present
  - 'sekurlsa::'
  - 'lsadump::'

# Numeric
GrantedAccess|eq: 0x1010                # exact hex match

# Base64 (for command-line obfuscation)
CommandLine|base64offset|contains: 'Invoke-Mimikatz'

# Windash (handles - vs / flag prefixes across PowerShell versions)
CommandLine|windash: '-EncodedCommand'

# Combined modifiers
CommandLine|contains|all|re:            # all values + regex
  - '(?i)mimikatz'
  - 'sekurlsa::'
```

### 3.3 Aggregation Patterns (Threshold Detections)

Many detections are inherently count-based (brute force, beaconing, scanning):

```yaml
# Brute force: > 5 failed logins per IP within 1 minute
detection:
  selection:
    EventID: 4625
  timeframe: 1m
  condition: selection | count() by IpAddress > 5

# Beaconing: > 100 connections to one destination within 1 hour
detection:
  selection:
    DestinationPort: 443
  timeframe: 1h
  condition: selection | count() by DestinationIp > 100

# Scanning: > 20 unique destination ports from one source within 5 minutes
detection:
  selection:
    Initiated: 'true'
  timeframe: 5m
  condition: selection | count(DestinationPort) by SourceIp > 20
```

### 3.4 Selection Naming Conventions

Use descriptive selection names. The condition becomes self-documenting:

```yaml
# BAD — opaque selection names
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  selection1:
    CommandLine|contains: 'MiniDump'
  filter:
    ParentImage|endswith: '\sccm.exe'
  condition: selection and selection1 and not filter

# GOOD — descriptive names
detection:
  selection_rundll32_image:
    Image|endswith: '\rundll32.exe'
  selection_minidump_commandline:
    CommandLine|contains: 'MiniDump'
  filter_sccm_parent:
    ParentImage|endswith: '\sccm.exe'
  condition: >
    selection_rundll32_image and
    selection_minidump_commandline and
    not filter_sccm_parent
```

### 3.5 Multi-Rule Composition

Complex TTPs are often best captured by multiple rules, each focused on one variant:

```
T1003.001 LSASS Memory dumping variants:
├── rules/credential_access/mimikatz-cmdline.yml           (mimikatz.exe)
├── rules/credential_access/comsvcs-minidump.yml           (comsvcs.dll via rundll32)
├── rules/credential_access/procdump-lsass.yml             (procdump -ma lsass.exe)
├── rules/credential_access/lsass-access-suspicious.yml    (Sysmon EID 10 with suspicious GrantedAccess)
└── rules/credential_access/powershell-invoke-mimikatz.yml (PS Invoke-Mimikatz)
```

Each rule has a different FP profile; each is tuned independently. The ATT&CK Navigator layer shows 5 rules covering T1003.001 (more coverage = more pain to adversary).

---

## 4. YARA Rule Authoring Deep Dive

### 4.1 YARA vs. Sigma: When to Use Which

| Aspect | Sigma | YARA |
|--------|-------|------|
| Data type | Log events (EVTX, CloudTrail) | Files and memory |
| Typical use | TTP detection in SIEM | Malware family classification |
| Scan location | SIEM (centralized) | Host (file system / memory) |
| Scan time | Real-time (event-driven) | On-demand (batch) |
| Performance | SIEM-indexed (fast) | Linear scan (slow) |
| Example | "Detect LSASS dump" | "Detect Cobalt Strike beacon PE" |

Detection engineers author both. Sigma is for log telemetry; YARA is for file/memory telemetry. A complete detection program covers both.

### 4.2 YARA String Selection Heuristics

High-signal YARA strings are:

- **Specific to the malware family** (function names, error messages, embedded URLs)
- **Stable across variants** (not changed by polymorphism)
- **Non-generic** (not "MZ", "This program cannot be run in DOS mode", or common API names)

Low-signal strings (avoid):

- MZ header (every PE file)
- DOS stub message
- Standard library imports (kernel32.dll, user32.dll)
- Compiler/linker signatures
- Common API names (VirtualAlloc, WriteProcessMemory)

yarGen helps filter low-signal strings automatically by comparing against a benign corpus, but hand-review is still required.

### 4.3 YARA Condition Patterns

```yara
// Pattern 1: PE magic + N signal strings
condition:
  uint16(0) == 0x5A4D and
  3 of ($s1, $s2, $s3, $s4)

// Pattern 2: PE magic + specific strings + filesize constraint
condition:
  uint16(0) == 0x5A4D and
  filesize < 500KB and
  $beacon_mutex and
  $pipe_name

// Pattern 3: Memory scanning (no filesize — memory dumps have no size)
condition:
  any of them and
  not filesize > 0

// Pattern 4: PE-specific (using the pe module)
import "pe"
condition:
  uint16(0) == 0x5A4D and
  pe.number_of_sections > 3 and
  pe.imphash() == "fd1c1e9c2b..."

// Pattern 5: Range-based (string near entrypoint)
condition:
  $payload in (entrypoint..entrypoint+200)
```

### 4.4 YARA Rule Quality Checklist

- [ ] `meta` block has `description`, `author`, `date`, `reference`
- [ ] `strings` are specific to the malware family (not generic)
- [ ] `condition` requires a magic check (`uint16(0) == 0x5A4D`) for PE files
- [ ] `condition` requires multiple signals (not just one weak string)
- [ ] Filesize constraint prevents scanning huge files
- [ ] Tested against positive corpus (matches every known sample)
- [ ] Tested against negative corpus (zero matches on benign files)
- [ ] Performance tested (scanning 10,000 files completes in < 60s)

---

## 5. SigmaCLI & pySigma Internals

### 5.1 SigmaCLI Architecture

SigmaCLI is a thin CLI wrapper around pySigma. pySigma provides:

- **SigmaCollection**: loads Sigma rule files
- **SigmaRule**: parses a single Sigma rule into Python objects
- **Backends**: translate Sigma rules to SIEM-specific query languages
- **Pipelines**: transform field names and modifiers (e.g., Sysmon field mapping)

```python
# Programmatic translation
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.sysmon import sysmon_pipeline

# Load rules
rules = SigmaCollection.load_ruleset("rules/")

# Configure backend with pipeline
backend = SplunkBackend(pipelines=[sysmon_pipeline()])

# Translate each rule
for rule in rules:
    result = backend.convert_rule(rule)
    print(f"# {rule.title}")
    print(result[0].formatted)  # the SPL query
```

### 5.2 Available Backends

| Backend | Package | Output |
|---------|---------|--------|
| Splunk | `pySigma-backend-splunk` | SPL |
| Elasticsearch (Lucene) | `pySigma-backend-elasticsearch` | Lucene query |
| Kibana NDJSON | `pySigma-backend-kibana-ndjson` | Kibana importable rule |
| Microsoft 365 Defender | `pySigma-backend-microsoft365defender` | KQL |
| Azure Sentinel | `pySigma-backend-azuresentinel` | KQL |
| QRadar | `pySigma-backend-qradar` | AQL |
| Elastic EQL | `pySigma-backend-eql` | EQL |
| SQL (generic) | `pySigma-backend-sql` | SQL |
| Splunk Data Model | `pySigma-backend-datamodel` | tstats query |

Install backends individually:

```bash
pip install pySigma-backend-splunk
pip install pySigma-backend-elasticsearch
pip install pySigma-backend-microsoft365defender
pip install pySigma-backend-qradar
```

### 5.3 Pipelines: Field Mapping

Different log sources use different field names for the same concept:

| Concept | Sysmon | WinEvent | Sentinel | Elastic ECS |
|---------|--------|----------|----------|-------------|
| Process name | Image | ProcessName | FileName | process.name |
| Command line | CommandLine | CommandLine | ProcessCommandLine | process.command_line |
| Parent process | ParentImage | ParentProcessName | InitiatingProcessFileName | process.parent.name |

Pipelines translate Sigma's generic field names to backend-specific names:

```bash
# Sysmon pipeline
sigma-cli convert -t splunk -p sysmon rule.yml

# Elastic ECS pipeline
sigma-cli convert -t lucene -p ecs-informational rule.yml

# Splunk Windows pipeline (uses CIM data model)
sigma-cli convert -t splunk -p splunk_windows rule.yml
```

### 5.4 Common SigmaCLI Commands

```bash
# Parse (validate)
sigma-cli parse rule.yml

# Convert to one backend
sigma-cli convert -t splunk rule.yml

# Convert with a pipeline
sigma-cli convert -t splunk -p sysmon rule.yml

# Convert a directory
sigma-cli convert -t splunk -r rules/

# Output to file
sigma-cli convert -t splunk rule.yml -o rule.spl

# List installed backends
sigma-cli list backends

# List installed pipelines
sigma-cli list pipelines
```

---

## 6. Detection CI/CD Pipeline Recipes

### 6.1 Minimal CI (Schema + Tag Check)

For teams just starting with detection-as-code:

```yaml
# .github/workflows/minimal-detection-ci.yml
name: Minimal Detection CI
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install sigma-cli pyyaml
      - name: Parse every rule
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli parse "$f" || exit 1
          done
      - name: Check ATT&CK tags
        run: |
          python3 - <<'PY'
          import yaml, sys
          from pathlib import Path
          for path in Path('rules').rglob('*.yml'):
              rule = yaml.safe_load(path.read_text())
              tags = rule.get('tags') or []
              if not any(t.startswith('attack.t') for t in tags):
                  print(f"FAIL: {path} missing attack.tXXXX tag", file=sys.stderr)
                  sys.exit(1)
          PY
```

### 6.2 Standard CI (Schema + Tags + Translation + Corpus Tests)

For mature detection teams:

```yaml
# .github/workflows/detection-ci.yml
name: Detection CI
on: [pull_request, push]
jobs:
  sigma-schema-validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch pySigma-backend-microsoft365defender
      - name: Parse every rule
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli parse "$f" || exit 1
          done

  attack-tag-coverage:
    needs: sigma-schema-validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install pyyaml
      - name: Check ATT&CK tags
        run: python3 scripts/check-tags.py rules/

  backend-translation:
    needs: sigma-schema-validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch pySigma-backend-microsoft365defender
      - name: Translate to backends
        run: |
          for f in $(find rules/ -name '*.yml'); do
            sigma-cli convert -t splunk "$f" > /dev/null || exit 1
            sigma-cli convert -t lucene "$f" > /dev/null || exit 1
            sigma-cli convert -t microsoft-365-defender "$f" > /dev/null || exit 1
          done

  positive-corpus-test:
    needs: sigma-schema-validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run hayabusa on positive corpus
        run: |
          docker run --rm -v $PWD:/work \
            yamatosecurity/hayabusa:latest \
            csv-timeline -d /work/test-data/positive/ \
            -r /work/rules/ -o /tmp/pos.csv --min-level low
          test -s /tmp/pos.csv

  negative-corpus-test:
    needs: sigma-schema-validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run hayabusa on negative corpus
        run: |
          docker run --rm -v $PWD:/work \
            yamatosecurity/hayabusa:latest \
            csv-timeline -d /work/test-data/negative/ \
            -r /work/rules/ -o /tmp/neg.csv --min-level low
          if grep -E ',(medium|high|critical),' /tmp/neg.csv; then
            echo "FAIL: rule fired on negative corpus"
            cat /tmp/neg.csv
            exit 1
          fi
```

### 6.3 Full CI (Standard + Coverage Layer + Promotion Gate)

For organizations with multiple SIEMs and a strict promotion process:

```yaml
# .github/workflows/full-detection-ci.yml
name: Full Detection CI
on: [pull_request, push]
jobs:
  # ... (all jobs from 6.2)

  navigator-layer-build:
    needs: [sigma-schema-validate, attack-tag-coverage]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install pyyaml
      - run: python3 scripts/build-navigator-layer.py rules/ -o coverage.json
      - uses: actions/upload-artifact@v4
        with:
          name: attack-coverage-layer
          path: coverage.json

  promotion-gate:
    # Only runs when promoting experimental → stable
    if: contains(github.event.pull_request.labels.*.name, 'promotion')
    needs: [sigma-schema-validate, attack-tag-coverage, backend-translation,
            positive-corpus-test, negative-corpus-test, navigator-layer-build]
    runs-on: ubuntu-latest
    steps:
      - name: Verify FP soak complete
        run: |
          # Read the FP soak report from the PR description
          # Assert that the rule has been in staging for >= 7 days
          # Assert that the FP rate is documented and below threshold
          # Assert that the PR description references the staging soak ticket
          echo "Promotion gate passed"
```

### 6.4 GitLab CI Equivalent

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - test
  - publish

variables:
  PYTHON_VERSION: "3.11"

sigma-schema-validate:
  stage: validate
  image: python:${PYTHON_VERSION}-slim
  before_script:
    - pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch
  script:
    - for f in $(find rules/ -name '*.yml'); do sigma-cli parse "$f"; done

attack-tag-coverage:
  stage: validate
  image: python:${PYTHON_VERSION}-slim
  before_script:
    - pip install pyyaml
  script:
    - python3 scripts/check-tags.py rules/

positive-corpus-test:
  stage: test
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker run --rm -v $PWD:/work yamatosecurity/hayabusa:latest
        csv-timeline -d /work/test-data/positive/ -r /work/rules/ -o /tmp/pos.csv --min-level low
    - test -s /tmp/pos.csv

publish-coverage-layer:
  stage: publish
  image: python:${PYTHON_VERSION}-slim
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

---

## 7. FP-Tuning Matrix

A reference matrix of common FP sources and their typical filter patterns.

### 7.1 FP Source → Filter Pattern

| FP Source | Typical Filter | Example |
|-----------|----------------|---------|
| SCCM admin tasks | Filter by ParentImage | `ParentImage\|endswith: '\sccm.exe'` |
| GPO processing | Filter by ParentImage + User | `ParentImage\|endswith: '\svchost.exe' AND User\|contains: 'SYSTEM'` |
| Antivirus scans | Filter by Image + User | `Image\|endswith: '\MsMpEng.exe'` |
| Software deployment | Filter by ParentImage + CommandLine pattern | `ParentImage\|endswith: '\msiexec.exe'` |
| DSC configurations | Filter by ParentImage + CommandLine | `ParentImage\|endswith: '\wmiapriv.exe' AND CommandLine\|contains: 'DSC'` |
| In-house IT tools | Filter by Signer | `SignedBy\|contains: 'Contoso Code Signing'` |
| Build servers | Filter by Computer naming | `Computer\|startswith: 'BUILD-'` |
| Jump hosts | Filter by Computer naming | `Computer\|startswith: 'JUMP-'` |
| Service accounts | Filter by User | `User\|endswith: '-svc$'` |
| Patch Tuesday | Filter by User + day of week | `User\|contains: 'patch-svc' AND _time\|strftime('%a') == 'Wed'` |

### 7.2 FP-Tuning Workflow (Detailed)

```
Step 1: MEASURE
  Run the rule against 30 days of historical SIEM data
  Output: hit count per day, top-10 clusters by volume

Step 2: GROUP
  stats by (Computer, User, ParentImage, CommandLine signature)
  Output: hit clusters; top-3 clusters typically account for 80% of noise

Step 3: TRIAGE
  For each cluster > 5 hits/day: classify as
    - BENIGN (legitimate admin activity; add a filter)
    - SUSPICIOUS (manual review; if confirmed malicious, escalate to IR)
    - UNKNOWN (promote to staging; soak longer)

Step 4: FILTER
  For each BENIGN cluster:
    a. Identify the common signal (parent process, signer, user, host pattern)
    b. Add a filter clause to the Sigma rule
    c. Re-translate to the SIEM backend
    d. Re-test against the historical soak data
    e. Verify FP rate dropped, true-positive rate unchanged (re-run positive corpus)

Step 5: RE-DEPLOY
  Commit the tuned rule; CI re-validates; CD pushes to staging
  Observe for another soak period (typically 7 days)

Step 6: VERIFY
  If FP rate < threshold (typically < 1/day): promote to production
  If FP rate still > threshold: lower rule level (high → medium → low)
                              OR retire the rule
                              OR file a "new log source needed" ticket
```

### 7.3 Common FP-Tuning Failure Modes

| Failure Mode | Description | Mitigation |
|--------------|-------------|------------|
| Over-tuning | Filtering so aggressively that true positives are missed | Always re-test against the positive corpus after each filter |
| Stale filters | A filter added for a 3-year-old admin tool stays in place after retirement | Quarterly review of filter relevance |
| Filter on unstable fields | Filtering by User (changes with personnel) is fragile | Prefer filtering by ParentImage or Signer |
| Copy-paste filters | Copying a filter from one rule to another without verifying it applies | Each filter must be tested against the historical data for that specific rule |
| Tuning to silence one analyst's complaints | An analyst flags FPs; the rule is tuned without measuring the actual FP rate | Always measure first; tune based on data, not opinion |

---

## 8. ATT&CK Coverage Measurement

### 8.1 Coverage Layer Generation

The ATT&CK Navigator visualizes coverage as a heatmap layer. Generate it from the union of Sigma rule tags:

```python
#!/usr/bin/env python3
# scripts/build-navigator-layer.py
import sys, json, yaml
from pathlib import Path
from collections import Counter

def extract_technique_counts(rules_dir):
    counts = Counter()
    for path in Path(rules_dir).rglob('*.yml'):
        with open(path) as f:
            try:
                rule = yaml.safe_load(f)
                for t in (rule.get('tags') or []):
                    if t.startswith('attack.t'):
                        tech_id = t.replace('attack.', '').upper()
                        counts[tech_id] += 1
            except Exception:
                pass
    return counts

def build_layer(counts):
    return {
        "name": "Sigma Rule Coverage",
        "versions": {"attack": "15", "navigator": "4.9.0"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated from {sum(counts.values())} Sigma rule tags",
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
        "legendItems": [
            {"label": "0 rules", "color": "#ff6666"},
            {"label": "1-2 rules", "color": "#ffe766"},
            {"label": "3+ rules", "color": "#8ec843"}
        ],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }

def main(rules_dir, output_path):
    counts = extract_technique_counts(rules_dir)
    layer = build_layer(counts)
    with open(output_path, 'w') as f:
        json.dump(layer, f, indent=2)
    print(f"# Wrote {output_path}: {len(counts)} techniques covered")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
```

### 8.2 Coverage Gap Analysis

Identify which ATT&CK techniques have ZERO coverage:

```python
#!/usr/bin/env python3
# scripts/coverage-gaps.py
import json, sys

def main(layer_path, attack_path):
    with open(layer_path) as f:
        layer = json.load(f)
    covered = {t['techniqueID'] for t in layer['techniques']}

    with open(attack_path) as f:
        attack = json.load(f)

    all_techniques = set()
    technique_names = {}
    for obj in attack['objects']:
        if obj.get('type') == 'attack-pattern':
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    tid = ref['external_id']
                    all_techniques.add(tid)
                    technique_names[tid] = obj.get('name', tid)

    uncovered = all_techniques - covered
    print(f"# Covered: {len(covered)} / {len(all_techniques)}")
    print(f"# Uncovered: {len(uncovered)}")
    for tid in sorted(uncovered):
        print(f"{tid}\t{technique_names.get(tid, '')}")

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
```

```bash
# Download ATT&CK STIX
curl -sL https://github.com/mitre/cti/raw/master/enterprise-attack.json -o /tmp/attack.json

# Build the coverage layer
python3 scripts/build-navigator-layer.py rules/ -o coverage.json

# Find gaps
python3 scripts/coverage-gaps.py coverage.json /tmp/attack.json > gaps.txt

# Prioritize gaps by current threat-intel prevalence
# (manual: cross-reference gaps.txt with current TI reports)
```

### 8.3 Coverage Review Cadence

| Cadence | Activity | Participants |
|---------|----------|--------------|
| Weekly | Review PRs to rules/ | Detection engineers |
| Monthly | Review FP rates for production rules | Detection engineers + SOC |
| Quarterly | Coverage gap analysis + red-team review | Detection engineers + red team |
| Annually | Rule retirement review | Detection engineers + SOC |

The quarterly review is where the program's strategic direction is set:

```
1. Generate the current coverage layer
2. Compare to last quarter's layer (what's new, what's deprecated)
3. Identify the top 5 uncovered techniques by threat-intel prevalence
4. File detection-engineering tickets for each
5. Review FPs from the quarter; tune or retire as needed
6. Review the rule retirement queue; retire silent rules
```

---

## 9. Staging Soak & Promotion

### 9.1 Staging SIEM Setup

The staging SIEM must:

- Receive the same log sources as production
- Have production-equivalent data volumes (otherwise FP rates will be misleading)
- Be isolated from production alerting (don't page SOC on staging hits)
- Retain soak data for at least 90 days (for FP tuning)

### 9.2 Soak Period Duration

| Rule Level | Recommended Soak | Rationale |
|------------|------------------|-----------|
| informational | 1 day | Noisy by design; quick validation only |
| low | 3 days | Enough to catch routine FP sources |
| medium | 7 days | Catch weekly admin cycles (e.g., Monday morning patching) |
| high | 14 days | Catch biweekly cycles |
| critical | 30 days | Catch monthly cycles (Patch Tuesday, payroll runs) |

### 9.3 Promotion Criteria

A rule can promote from `experimental` to `stable` when:

```
- [ ] Soak period complete (per level above)
- [ ] FP rate documented and below threshold:
        - level=informational: N/A (informational rules don't page)
        - level=low: < 5 hits/day
        - level=medium: < 1 hit/day
        - level=high: < 1 hit/week
        - level=critical: < 1 hit/month
- [ ] True-positive rate validated (rule fires on the positive corpus)
- [ ] ATT&CK tags verified accurate
- [ ] Peer review complete (≥ 1 detection engineer)
- [ ] SOC runbook updated (how to triage an alert from this rule)
- [ ] Ticket updated with soak metrics and promotion approval
```

### 9.4 Promotion Workflow

```bash
# 1. Engineer files a promotion PR
git checkout -b promote/mimikatz-cmdline-to-stable
$EDITOR rules/credential_access/mimikatz-cmdline.yml
# Change: status: experimental → status: stable
git add rules/credential_access/mimikatz-cmdline.yml
git commit -m "promote(detection): mimikatz-cmdline experimental → stable

Soak: 14 days (2026-06-01 to 2026-06-14)
FP rate: 0.2/day (filtered SCCM parent)
True-positive rate: 5/5 on EVTX-ATTACK-SAMPLES corpus
Ticket: DETECT-2026-042"

# 2. PR opened; CI re-runs (full validation)
# 3. Peer review by another detection engineer
# 4. PR merged; CD pushes to production SIEM
# 5. ATT&CK Navigator coverage layer regenerated
```

---

## 10. Rule Retirement & Audit Trail

### 10.1 Retirement Criteria

A rule is a retirement candidate when:

- It has produced ZERO hits across all SIEMs in the last 24 months
- The covered TTP is obsolete (e.g., a 10-year-old malware family)
- The log source is being deprecated (e.g., switching from WinEvent 4688 to Sysmon EID 1)
- The rule has been superseded by a more comprehensive rule

### 10.2 Retirement Workflow

```bash
# 1. Confirm silence
python3 scripts/rule-liveness.py rules/malware/old-ransom-family.yml --since 730d
# Output: 0 hits across all SIEMs in the last 730 days

# 2. Move to deprecated/
mkdir -p rules/deprecated
git mv rules/malware/old-ransom-family.yml rules/deprecated/

# 3. Update the rule's status
$EDITOR rules/deprecated/old-ransom-family.yml
# Change: status: stable → status: deprecated
# Add note to description: "DEPRECATED 2026-06-17: silent for 24+ months"

# 4. Commit
git add -A
git commit -m "chore(detection): retire old-ransom-family rule (silent 24m+)

Original: T1486 Ransomware (old-ransom-family)
Reason: 0 hits in last 24 months; family no longer active
Ticket: DETECT-2026-099"

# 5. CD pushes the rule to rules/deprecated/ in the SIEM
#    The SIEM CD pipeline recognizes the path change and removes the rule from active import
# 6. ATT&CK Navigator coverage layer regenerated; the covered technique may now be partially covered or uncovered
```

### 10.3 Audit Trail

The detections repo IS the audit trail. Every rule's complete lifecycle is reconstructable from git history:

```bash
# What was the lifecycle of mimikatz-cmdline.yml?
git log --follow --pretty=format:'%h %ad %s' --date=short rules/credential_access/mimikatz-cmdline.yml

# Output:
# a1b2c3d 2026-06-01 feat(detection): T1003.001 mimikatz cmdline patterns
# d4e5f6a 2026-06-05 fix(detection): filter SCCM parent (FP 50/d → 0.3/d)
# g7h8i9j 2026-06-15 promote(detection): mimikatz-cmdline experimental → stable
# (and eventually)
# k0l1m2n 2027-06-17 chore(detection): retire mimikatz-cmdline (silent 24m+)
```

Each commit message is self-documenting: what changed, why, and the ticket reference.

---

## 11. Integration with Sibling Skills

### 11.1 Threat Hunting (skills/threat-hunting)

Threat hunting forms hypotheses and walks telemetry. Detection engineering produces the detectors that hunters rely on for breadth.

**Integration pattern**:

```
1. Threat hunt forms a hypothesis: "Is LSASS dumping happening via comsvcs.dll?"
2. Hunt runs a one-off query in the SIEM; finds 3 hits over 30 days
3. Hunt documents the findings in a hunt report
4. Hunt files a detection-engineering work item: "ship a Sigma rule for comsvcs.dll MiniDump"
5. Detection engineer drafts the Sigma rule (this skill)
6. Rule ships through CI → staging → production
7. The next hunt can now use the production detection as a building block for the next hypothesis
8. Loop
```

### 11.2 Logging & Monitoring (skills/logging-monitoring)

Logging & monitoring builds the sensor grid. Detection engineering writes what runs on the grid.

**Integration pattern**:

```
1. Logging-monitoring deploys Sysmon with SwiftOnSecurity config to all endpoints
2. Detection engineer authors Sigma rules assuming Sysmon EID 1 + EID 10 are available
3. Logging-monitoring deploys Filebeat to ship EVTX to Splunk
4. Detection engineer translates Sigma rules to Splunk SPL via SigmaCLI
5. Logging-monitoring deploys Splunk index = win sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
6. Detection engineer's translated SPL rules deploy to production Splunk
7. Loop
```

When logging-monitoring adds a new sensor (e.g., Zeek DNS), detection engineering can author new Sigma rules for that source.

### 11.3 Deception & Honeypot (skills/deception-honeypot)

Deception produces near-zero-FP detections (every honeypot hit is signal). Detection engineering produces the bulk of SOC detections where FP tuning is the central craft problem.

**Integration pattern**:

```
1. Deception deploys Cowrie on a non-production IP
2. Deception authors a Sigma rule: "Honeypot Tripwire - Any Interaction"
3. The rule has near-zero FP (no legitimate user touches a honeypot)
4. The rule ships to the SOC's SIEM via the detection-as-code pipeline
5. Detection engineering's noise-tuned detections (FP < 1/day) and deception's noise-free detections (FP = 0) work side-by-side
6. The SOC sees: "high-confidence alerts from deception" + "lower-confidence but actionable alerts from detection engineering"
```

### 11.4 AD/LDAP Attack (skills/ad-ldap-attack)

AD/LDAP attack is the offensive counterpart. Every technique it covers is a Sigma-rule target.

**Integration pattern**:

```
1. AD/LDAP attack documents T1003.003 (NTDS.dit dumping via ntdsutil)
2. Detection engineer reads the technique; drafts a Sigma rule:
   selection:
     Image|endswith: '\ntdsutil.exe'
     CommandLine|contains: '"activate instance ntds"'
3. Rule ships; SOC now detects ntdsutil-based NTDS.dit extraction
4. Red team re-runs the technique; detection fires; loop closes
```

### 11.5 Chronicle (skills/chronicle)

Chronicle SIEM uses YARA-L as its detection language. Sigma rules can be hand-translated to YARA-L for Chronicle deployments.

**Integration pattern**:

```
1. Detection engineer drafts a Sigma rule for AWS API abuse
2. For Chronicle deployments, hand-translate to YARA-L:
   rule aws_console_login_new_geo {
     meta:
       description = "AWS Console Login from New Geographic Location"
       mitre_attack_tactic = "TA0001 Initial Access"
       mitre_attack_technique = "T1078 Valid Accounts"
     events:
       $e.metadata.event_type = "USER_LOGIN"
       $e.metadata.product_name = "AWS CloudTrail"
       $e.security_result.action = "ALLOW"
     condition:
       $e
   }
3. The YARA-L rule ships to Chronicle via its detection-as-code API
```

### 11.6 AV/EDR Evasion (skills/av-edr-evasion)

AV/EDR evasion documents adversary tradecraft for evading detections. Detection engineering uses this as input for FP tuning and rule design.

**Integration pattern**:

```
1. AV/EDR evasion documents " adversary uses Process Ghosting to evade EDR"
2. Detection engineer reads the technique; understands the telemetry gap
3. Detection engineer either:
   a. Files a "new log source needed" ticket (EDR-specific Telemetry)
   b. Drafts a Sigma rule that catches the detectable part (e.g., a marked-for-deletion binary that executes)
4. Rule ships; AV/EDR evasion's next iteration tries to evade the new rule; loop
```

---

## 12. Common Anti-Patterns

Detection engineering has well-known anti-patterns. Avoid these.

### 12.1 The Copy-Paste Rule

```
# BAD: Copying a SigmaHQ rule into production without tuning
curl -O https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_impacket_smbexec.yml
cp proc_creation_win_impacket_smbexec.yml /opt/siem/rules/
```

Why it's bad:

- No adaptation to the local environment (FP sources differ)
- No ATT&CK tag verification for the local SIEM
- No positive/negative corpus test
- No soak period

Fix: route every community rule through the full detection-as-code lifecycle. The SigmaHQ rule is a starting point, not a finished product.

### 12.2 The Untested Rule

```
# BAD: A rule that has never been tested against the positive or negative corpus
```

Why it's bad:

- The rule may not fire on actual malicious activity (silent failure)
- The rule may fire on every legitimate admin action (noisy failure)
- You won't know which until production

Fix: every rule ships with positive and negative corpus tests in CI. Untested rules do not ship.

### 12.3 The Stale Rule

```
# BAD: A rule written 3 years ago that hasn't been reviewed since
```

Why it's bad:

- The rule's log source may have changed (WinEvent 4688 deprecated in favor of Sysmon EID 1)
- The adversary may have shifted sub-technique
- The rule may be silently failing (CI never re-ran against fresh corpus)

Fix: quarterly review of every rule. Re-test against fresh positive and negative corpora. Retire silent rules.

### 12.4 The Filterless Rule

```
# BAD: A rule with selection but no filter
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-e '
  condition: selection
```

Why it's bad:

- " -e " matches millions of legitimate PowerShell invocations
- The SOC is paged 1000 times per day
- Alert fatigue sets in within hours

Fix: every rule ships with documented FP sources and corresponding filter clauses. Soak measurement before promotion.

### 12.5 The Orphaned Rule

```
# BAD: A rule with no author, no ticket, no documentation
title: My Rule
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects stuff
```

Why it's bad:

- When the rule breaks, nobody knows who owns it
- When the rule fires, nobody knows how to triage the alert
- The rule accumulates technical debt indefinitely

Fix: every rule has an `author`, a `date`, a ticket reference, and a SOC runbook entry.

### 12.6 The Untuned Alert Fatigue

```
# BAD: The SOC has 500 detections producing 10000 alerts/day
#      Analysts page through alerts without triaging them
#      Real attacks slip through the noise
```

Why it's bad:

- The SOC stops trusting the detections
- Real attacks are missed
- The detection engineering program is failing silently

Fix: every rule has a documented FP rate. Rules above threshold are tuned or retired. Alert volume is a tracked metric; a sudden spike triggers an engineering review.

---

## 13. Reference: ATT&CK Tactic → Sigma Tag Mapping

| ATT&CK Tactic | Sigma Tag | ATT&CK ID |
|---------------|-----------|-----------|
| Reconnaissance | `attack.reconnaissance` | TA0043 |
| Resource Development | `attack.resource_development` | TA0042 |
| Initial Access | `attack.initial_access` | TA0001 |
| Execution | `attack.execution` | TA0002 |
| Persistence | `attack.persistence` | TA0003 |
| Privilege Escalation | `attack.privilege_escalation` | TA0004 |
| Defense Evasion | `attack.defense_evasion` | TA0005 |
| Credential Access | `attack.credential_access` | TA0006 |
| Discovery | `attack.discovery` | TA0007 |
| Lateral Movement | `attack.lateral_movement` | TA0008 |
| Collection | `attack.collection` | TA0009 |
| Command and Control | `attack.command_and_control` | TA0011 |
| Exfiltration | `attack.exfiltration` | TA0010 |
| Impact | `attack.impact` | TA0040 |

Each Sigma rule should carry at least one tactic tag and at least one technique tag (`attack.tXXXX[.XXX]`). The technique tag is what the ATT&CK Navigator coverage layer counts.

---

## Closing Notes

Detection engineering is a craft. It rewards patience, discipline, and an empirical mindset. The detection engineer who ships 10 well-tested rules per quarter outperforms the one who ships 100 untested rules per sprint.

The lifecycle — intake → draft → test → CI → soak → tune → ship → review → retire — exists to make detection engineering sustainable. Skip phases at your peril; the SOC pays the price in alert fatigue.

Pair this skill with `threat-hunting` (which consumes your detectors), `logging-monitoring` (which builds the grid your rules run on), and `deception-honeypot` (which produces near-zero-FP detections). The four together form a complete defensive detection program.
