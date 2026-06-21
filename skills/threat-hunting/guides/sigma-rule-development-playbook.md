# Sigma Rule Development & Hunt Chain Playbook

> Deep-dive companion to `skills/threat-hunting/SKILL.md` and `guides/hunt-hypothesis-playbook.md`.
>
> Audience: detection engineers and SOC analysts who already know what a Sigma rule is and want a battle-tested playbook for authoring, converting, testing, tuning, and shipping Sigma detections across a multi-vendor SIEM stack — Splunk SPL, Microsoft Sentinel KQL, Elastic Lucene/ES|QL — without the rules going stale in six months.
>
> Scope: Sigma rule anatomy, sigma-CLI conversion, MITRE ATT&CK technique-to-rule mapping, false-positive tuning, threat-hunt hypothesis construction, SigmaHQ contribution standards, and CI testing with sigma-cli test. YARA is covered in `payloads.md`; this guide is Sigma-only.

---

## 1. Why a Detection-as-Code Workflow, Not Just YAML Files

A `sigma/*.yml` directory with 200 hand-written rules produces detections in a week. The trap is treating that directory as the deliverable. A defensible detection engineering program produces:

1. **Schema-valid, vendor-portable rules** — Sigma YAML that converts cleanly to every backend without per-rule backend customization.
2. **MITRE ATT&CK mapped** — every rule carries `tags` linking it to one or more ATT&CK techniques, so coverage can be plotted in Navigator and gaps identified.
3. **Tested against known-benign samples** — every rule has a documented false-positive rate, derived from running it against representative production traffic, not from the analyst's intuition.
4. **Tested against known-malicious samples** — every rule fires on at least one real or reconstructed adversary sample, captured as a unit test.
5. **Tuned over time, not abandoned** — rules have owners, review dates, and a feedback loop from the SOC that handles the alerts.
6. **Version-controlled and CI-tested** — every change goes through pull request, sigma-cli validation, backend-conversion smoke test, and ATT&CK coverage diff before merge.
7. **Documented in a detection catalog** — every rule has a one-paragraph description aimed at the SOC analyst who'll triage the alert, not the engineer who wrote it.

This guide walks through all seven, in order, with the exact commands, decision points, and references.

---

## 2. Sigma Rule Anatomy — The Schema

Sigma is a generic, vendor-neutral signature format for log events, originally authored by Florian Roth. The schema is defined in [SigmaHQ/spec](https://github.com/SigmaHQ/spec).

### 2.1 Minimal valid rule

```yaml
title: Suspicious Certutil Usage — Decode
id: e0a841f0-0338-4d6c-9f3a-4f3b8b8c5c50
status: experimental
description: |
  Detects the use of certutil.exe with the -decode argument, a common
  technique for decoding base64-encoded payloads dropped by initial-access
  stages of multiple ransomware families.
references:
  - https://attack.mitre.org/techniques/T1027/
  - https://www.microsoft.com/en-us/security/blog/2022/09/07/lockbit-3-0/
author: Acme SOC
date: 2026/06/21
modified: 2026/06/21
tags:
  - attack.defense_evasion
  - attack.t1027
logsource:
  product: windows
  service: process_creation
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains: '-decode'
  condition: selection
falsepositives:
  - Legitimate administrative certificate operations (rare)
level: high
```

### 2.2 Field-by-field reference

| Field | Purpose | Notes |
|-------|---------|-------|
| `title` | Short human-readable name | One line; avoid backend-specific verbs ("Alert on...") |
| `id` | UUID v4 | Generate once, never reuse across rules |
| `related` | Forward/backward references to superseded/related rules | Optional but useful for tracking rule evolution |
| `status` | `experimental` / `test` / `stable` / `deprecated` | Promote from experimental → test → stable as FP rate drops |
| `description` | What the rule detects and why it matters | Aimed at the SOC analyst — include triage hints |
| `references` | External context (MITRE, vendor blog, sample hash) | Always include the MITRE technique URL |
| `author` | Who wrote it | For attribution and code review |
| `date` / `modified` | ISO date (YYYY/MM/DD) | Update `modified` on every change |
| `tags` | MITRE ATT&CK + custom | Format: `attack.<tactic>` and `attack.t<technique>` |
| `logsource` | What log this applies to | Most common source of conversion failures |
| `detection` | The actual match logic | See §2.3 |
| `falsepositives` | Known FP scenarios | Mandatory for any `level: medium` or higher |
| `level` | `informational` / `low` / `medium` / `high` / `critical` | Drives SIEM severity routing |
| `fields` | Fields to surface in the alert | Useful for SOC triage templates |

### 2.3 The `detection` block — matchers and conditions

```yaml
detection:
  # A "selection" is a named set of field matchers.
  # All matchers within a selection are AND'd by default.
  selection_basic:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-decode'
      - '-urlcache'
      - '-encode'

  # Use a list to OR within a single field.
  # The above fires if CommandLine contains ANY of the three strings.

  # Multiple selections are combined by the condition.
  selection_filter_out:
    User: 'NT AUTHORITY\SYSTEM'  # common legitimate context

  # Modifiers transform the value before matching.
  selection_with_modifier:
    CommandLine|contains|all:  # `all` requires every list item to be present
      - 'certutil'
      - '-split'
      - 'http'

  condition: selection_basic and not selection_filter_out
```

Sigma field modifiers worth memorizing:

| Modifier | Effect |
|----------|--------|
| `contains` | Substring match |
| `startswith` | Prefix match |
| `endswith` | Suffix match |
| `all` | (with a list) every item must match |
| `re` | Regex match (some backends only) |
| `base64` | Match the base64-encoded form of the value |
| `base64offset` | Match across base64 alignment offsets |
| `lt` / `gt` / `lte` / `gte` | Numeric comparison |
| `cidr` | IP CIDR match |

### 2.4 The `logsource` block — the most error-prone field

`logsource` defines what log type the rule applies to. Most conversion failures stem from a `logsource` that doesn't map cleanly to the target backend's schema.

```yaml
# Common logsource patterns
logsource:
  product: windows
  service: process_creation         # Sysmon EID 1, Windows Security 4688
  # Maps to: Windows process creation telemetry

logsource:
  product: windows
  service: security                  # All Windows Security event log
  definition: 'Process creation with command line (EID 4688)'

logsource:
  product: linux
  service: auditd                    # Linux auditd

logsource:
  product: zeek
  service: dns                       # Zeek DNS log

logsource:
  category: network_connection
  product: windows                   # Sysmon EID 3

# The SigmaHQ pySigma-pipe-splunk backend ships category mappings for
# Splunk's CIM (Common Information Model) — if your Splunk uses CIM,
# the conversion is direct. If not, you need a custom pipeline.
```

### 2.5 Aggregation conditions — counting, time windows

```yaml
detection:
  selection:
    Image|endswith: '\whoami.exe'
  timeframe: 5m
  condition: selection | count(User) by Host > 10
# Fires if more than 10 distinct users ran whoami.exe on a single host
# in a 5-minute window — a classic enumeration signature.
```

Aggregation functions: `count()`, `min()`, `max()`, `avg()`, `sum()`. Grouping via `by <field>`. Not every backend supports every aggregation — document limitations in the rule.

---

## 3. Sigma-CLI — Authoring, Conversion, Validation

### 3.1 Install sigma-cli

```bash
# Recommended: install in a venv (sigma-cli has many sibling packages)
python3 -m venv ~/.venvs/sigma
source ~/.venvs/sigma/bin/activate
pip install sigma-cli

# Backends — install the ones you need
pip install pysigma-backend-splunk     # Splunk SPL
pip install pysigma-backend-elasticsearch  # Elastic Lucene / KQL / ES|QL
pip install pysigma-backend-microsoft    # Sentinel KQL, Defender
pip install pysigma-backend-qradar       # IBM QRadar AQL
pip install pysigma-pipe-sysmon          # Sysmon-specific field normalization
pip install pysigma-pipe-cim             # Splunk CIM normalization

# Verify
sigma --version
```

### 3.2 Convert a rule to a SIEM backend

```bash
# To Splunk SPL (using CIM)
sigma convert -t splunk -p sysmon -p cim \
  -p sigma/pipelines/sysmon.yaml \
  rules/windows/process_creation/certutil_decode.yml

# To Microsoft Sentinel KQL
sigma convert -t kusto \
  rules/windows/process_creation/certutil_decode.yml

# To Elastic Lucene (for Kibana query bar / Detection Engine rules)
sigma convert -t lucene \
  rules/windows/process_creation/certutil_decode.yml

# To Elastic KQL / ES|QL — pick based on your detection rule type
sigma convert -t eql \
  rules/windows/process_creation/certutil_decode.yml

# Bulk convert a directory, one output per rule
sigma convert -t splunk -p cim -d rules/windows/ --output-dir splunk_out/
```

### 3.3 Validate without converting

```bash
# Schema-validate a single rule
sigma check rules/windows/process_creation/certutil_decode.yml

# Validate every rule in a tree
find rules/ -name '*.yml' -exec sigma check {} \;
```

### 3.4 Merge, list, and inspect

```bash
# List all rules with a given tag
sigma list rules/ --tag attack.t1027

# Show all rules' titles and MITRE coverage
sigma list rules/ --format csv \
  --fields title,id,tags \
  > coverage.csv

# Convert to JSON (for ingestion into a catalog tool)
sigma convert -t json -d rules/ --output rules.json
```

---

## 4. MITRE ATT&CK Mapping — Technique-to-Sigma

### 4.1 Mapping discipline

Every Sigma rule should map to at least one ATT&CK technique. The mapping drives Navigator coverage plots and gap analysis. Rules without a mapping are a coverage liability — they detect *something*, but you can't tell if that *something* overlaps with another rule or fills a gap.

```yaml
tags:
  - attack.defense_evasion           # Tactic (snake_case)
  - attack.t1027                     # Obfuscated Files or Information
  - attack.t1027.004                 # Compile After Delivery (sub-technique)
  - attack.t1140                     # Deobfuscate/Decode Files or Information
```

### 4.2 Reverse mapping — technique to candidate rules

To bootstrap a coverage gap ("we have nothing for T1059.001 PowerShell"), pull the SigmaHQ back catalog:

```bash
# Clone SigmaHQ (the upstream rule repository)
git clone --depth=1 https://github.com/SigmaHQ/sigma.git ~/sigma

# Find every community rule for a given technique
grep -rl 'attack.t1059.001' ~/sigma/rules/ | head -20

# Pull titles and review
for f in $(grep -rl 'attack.t1059.001' ~/sigma/rules/ | head -20); do
  echo "=== $f ==="
  grep -E '^(title|description|status):' "$f"
done
```

### 4.3 ATT&CK Navigator integration

```bash
# Generate a Navigator layer from your rule set
python3 - <<'PY'
import yaml, json, glob, collections
counts = collections.Counter()
for f in glob.glob('rules/**/*.yml', recursive=True):
    try:
        doc = yaml.safe_load(open(f))
    except Exception:
        continue
    for tag in doc.get('tags', []):
        if tag.startswith('attack.t') and len(tag) == 12:
            counts[tag.replace('attack.', 'T').upper()] += 1

layer = {
    "version": "4.5",
    "name": "Sigma Coverage",
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": t, "score": c, "comment": f"{c} Sigma rule(s)"}
        for t, c in counts.items()
    ],
}
print(json.dumps(layer, indent=2))
PY > sigma-coverage.json

# Load sigma-coverage.json into MITRE ATT&CK Navigator (attack.mitre.org)
# to visualize coverage gaps and overlaps.
```

---

## 5. False-Positive Tuning Workflow

A new Sigma rule with `status: experimental` is a hypothesis. Promotion to `stable` requires empirical validation against real traffic.

### 5.1 Validation lifecycle

```
experimental  →  test  →  stable
     ↑               |         |
     └───────────────┘         |
     (re-tune if FP rate       |
      increases in prod)       ↓
                          (review annually or on ATT&CK update)
```

### 5.2 The tuning loop

```bash
# 1. Convert rule to target backend, run against historical traffic
sigma convert -t splunk -p cim rules/drafts/susp-powershell-download.yml \
  | tee splunk-query.txt
# Run the converted query in Splunk over the last 30 days. Count hits.

# 2. Sample 50 hits; classify each as TP / FP / unknown
# A spreadsheet works fine. The goal: estimate FP rate.

# 3. If FP rate > 20%:
#    a. Identify the FP pattern (which legitimate tool/user generates the hit?)
#    b. Add an exclusion clause to the rule
#    c. Re-run against the same historical traffic
#    d. Confirm TP count is unchanged

# 4. If FP rate < 5% and TP confirmed: promote to test.
#    In test: route to a tuning queue, not the SOC alert queue, for 2 weeks.

# 5. If test queue stays clean: promote to stable. SOC alert queue goes live.
```

### 5.3 Exclusion patterns — common FP sources

```yaml
# Add to detection block:
detection:
  selection_main:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-'
  # Common legitimate callers — exclude
  filter_known_legit:
    ParentImage|endswith:
      - '\Microsoft Monitoring Agent\Agent\MonitoringHost.exe'  # SCOM
      - '\CCM\CcmExec.exe'                                       # SCCM
      - '\nhsmsvc.exe'                                           # NHS management
    CommandLine|contains:
      - 'Microsoft.EnterpriseManagement.Warehouse'              # SCOM scripts
      - 'CCM\\'                                                  # SCCM scripts
  condition: selection_main and not filter_known_legit
```

### 5.4 The "FP budget" — when to drop a rule

Some rules will never get below 5% FP rate against your specific environment. That's OK — decide a budget:

- If the rule detects a high-severity ATT&CK technique (privilege escalation, credential dumping), accept up to 20% FP if the SOC can absorb the volume.
- If the rule detects a low-severity technique (discovery, recon), require <5% FP before promotion.
- If the rule can't meet either threshold, document why and either demote to `level: informational` (collect-but-don't-alert) or delete.

Stale `experimental` rules older than 90 days are a liability — review them monthly.

---

## 6. Threat Hunt Hypothesis Construction

A Sigma rule is one output of a hunt. The hunt itself starts with a hypothesis.

### 6.1 Hypothesis template

```
Hypothesis:  <adversary> uses <technique> to <effect>, observable via
             <telemetry>, with benign baseline <baseline>.

Technique:   T<number> — <name>
Tactic:      TA<number> — <name>
Telemetry:   <log source(s)>
Baseline:    <what legitimate traffic looks like>
Confidence:  <low / medium / high>  — based on threat intel,
                                   prior incidents, ATT&CK prevalence
Action:      Convert hypothesis to Sigma rule, run against historical
             traffic, triage hits.

Outcome:     [ ] New detection (good)
             [ ] Documented gap in telemetry (also good — now known)
             [ ] Documented FP pattern (good — now tunable)
             [ ] No hits (negative result — record for next hunt cycle)
```

### 6.2 Example — full hunt chain from intel to detection

```
Threat intel:  Microsoft blog (2024-03-12) reports BlackCat ransomware
              affiliates using `fsutil.exe behavior set SymlinkEvaluation`
              to disable symlink evaluation on hosts prior to lateral
              movement.

Hypothesis:  BlackCat affiliates will run fsutil.exe with the specific
             argument on Windows hosts. Sysmon EID 1 should capture it.
             Baseline: fsutil behavior queries are common in enterprise
             management; behavior *set* with that exact argument is rare.

Sigma rule:
  title: Suspicious fsutil.exe Behavior Set SymlinkEvaluation
  logsource:
    product: windows
    service: process_creation
  detection:
    selection:
      Image|endswith: '\fsutil.exe'
      CommandLine|contains|all:
        - 'behavior'
        - 'set'
        - 'SymlinkEvaluation'
    condition: selection
  level: medium
  tags: [attack.defense_evasion, attack.t1562.001]

Test against last 90 days of Sysmon EID 1:
  - 0 hits in our environment → either we weren't targeted, or
    our coverage window doesn't include BlackCat. Promote to stable
    with level: medium; expect low volume.

SOC triage guidance:
  - If alert fires, immediately check for subsequent lateral movement
    (EID 3 network connections, EID 10 process access to lsass).
  - If the host is a domain controller, escalate priority.
```

### 6.3 Prioritization — what to hunt first

| Trigger | Priority | Rationale |
|---------|----------|-----------|
| Active incident with a known TTP | P0 | Convert the TTP to a Sigma rule immediately; use it for scoping |
| Threat intel report naming your industry | P1 | Adversaries targeting your sector will use the techniques |
| ATT&CK technique with zero coverage in Navigator | P1 | Real gap |
| ATT&CK technique with one rule covering it | P2 | Hunt to confirm the rule actually fires |
| Quarterly hunt-athon theme | P3 | Proactive |

---

## 7. SigmaHQ Contribution Standards

Once you have a tuned `stable` rule with broad applicability, contribute it upstream.

### 7.1 Repository layout — match SigmaHQ conventions

```
my-sigma-rules/
├── rules/
│   ├── windows/
│   │   ├── process_creation/
│   │   │   ├── proc_creation_win_susp_certutil_decode.yml
│   │   │   └── ...
│   │   ├── registry_event/
│   │   ├── file_event/
│   │   ├── network_connection/
│   │   └── ...
│   ├── linux/
│   ├── network/                # Zeek, Suricata, firewall logs
│   ├── cloud/                   # AWS, Azure, GCP
│   └── web/                     # Web server access logs
├── rules-emerging-threats/      # 2024+ threat-intel-sourced rules
├── rules-threat-hunting/        # Lower-confidence hunting rules
├── tests/                       # Unit tests (see §8)
└── pipelines/                   # Custom sigma-cli pipelines
```

Naming convention (SigmaHQ):
- `<logsource-short>_win_<short-suffix>.yml`
- Example: `proc_creation_win_susp_certutil_decode.yml`

### 7.2 Quality bar for SigmaHQ merge

SigmaHQ maintainers will reject rules that:

- Lack a unique UUID
- Lack MITRE tags
- Have vague titles ("Suspicious Activity") — be specific
- Have no `falsepositives` field
- Have no `references`
- Duplicate an existing rule (search before submitting)
- Use backend-specific syntax in the detection block

```bash
# Before opening a PR, run all checks locally
sigma check rules/                                 # schema
sigma convert -t splunk -p cim rules/drafts/*.yml  # smoke convert
sigma convert -t kusto   rules/drafts/*.yml
sigma convert -t lucene  rules/drafts/*.yml
# All three conversions must succeed without errors.

# Check for duplicates
grep -rl "$(yq '.title' rules/drafts/my-rule.yml)" ~/sigma/rules/
```

### 7.3 Pull request template

```
## What
- Adds rule proc_creation_win_susp_certutil_decode.yml
- Detects T1027 / T1140 — certutil -decode usage

## Why
- Observed in BlackCat and LockBit intrusions (Microsoft, Mandiant)
- Not currently in SigmaHQ main (search confirmed)

## Testing
- [x] sigma check passes
- [x] Converts cleanly to Splunk SPL, Sentinel KQL, Elastic Lucene
- [x] Tested against 30 days of production Sysmon EID 1 (0 FP, 0 historical TP)
- [x] MITRE tags verified against ATT&CK v15

## References
- https://attack.mitre.org/techniques/T1027/
- https://attack.mitre.org/techniques/T1140/
- https://www.microsoft.com/en-us/security/blog/2022/09/07/lockbit-3-0/
```

---

## 8. CI Testing with sigma-cli test

Every Sigma rule should have a unit test that asserts: "given this log event, the rule fires" (positive) and "given this benign log event, the rule does not fire" (negative).

### 8.1 Test format

SigmaHQ uses `sigma-test` format. Each rule has a corresponding test event file:

```yaml
# tests/proc_creation_win_susp_certutil_decode.yml
title: Test for proc_creation_win_susp_certutil_decode
logs:
  - name: Positive — certutil decode
    input: |
      {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil -decode payload.b64 payload.exe",
        "UtcTime": "2026-06-21T12:00:00.000Z"
      }
    result: true   # rule should fire
  - name: Negative — certutil with no decode arg
    input: |
      {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil -dump cert.pfx",
        "UtcTime": "2026-06-21T12:00:00.000Z"
      }
    result: false  # rule should NOT fire
```

### 8.2 Running tests in CI

```bash
# Install sigma-test (part of sigma-cli)
pip install sigma-cli[test]

# Run all tests against their corresponding rules
sigma test rules/ tests/

# GitHub Actions example
cat > .github/workflows/sigma-ci.yml <<'YAML'
name: Sigma CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install sigma-cli pysigma-backend-splunk pysigma-backend-microsoft pysigma-backend-elasticsearch pysigma-pipe-sysmon pysigma-pipe-cim
      - run: |
          set -e
          # 1. Schema-validate every rule
          find rules/ -name '*.yml' -exec sigma check {} \;
          # 2. Convert every rule to every backend
          sigma convert -t splunk  -p sysmon -p cim -d rules/ --output-dir /tmp/splunk_out/
          sigma convert -t kusto                               -d rules/ --output-dir /tmp/kusto_out/
          sigma convert -t lucene                              -d rules/ --output-dir /tmp/lucene_out/
          # 3. Run unit tests
          sigma test rules/ tests/
YAML
```

### 8.3 Coverage tracking

```bash
# Count rules with / without tests
total=$(find rules/ -name '*.yml' | wc -l)
tested=$(find tests/ -name '*.yml' | wc -l)
echo "Rule coverage: $tested / $total ($(( tested * 100 / total ))%)"

# Target: >= 80% of stable rules have tests
# (experimental rules can skip tests until promoted)
```

---

## 9. Multi-Backend Conversion Gotchas

### 9.1 Aggregation mismatches

```yaml
# This Sigma aggregation:
detection:
  selection: { Image|endswith: '\whoami.exe' }
  timeframe: 5m
  condition: selection | count() by Host > 10
```

Converts to:

| Backend | Conversion result |
|---------|-------------------|
| Splunk SPL | `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational Image="*\\whoami.exe" \| bucket _time span=5m \| stats count AS c by _time, host \| where c > 10` — works |
| Sentinel KQL | `Sysmon \| where Image endswith "\\whoami.exe" \| summarize c=count() by bin(TimeGenerated, 5m), Computer \| where c > 10` — works |
| Elastic EQL | `process where process.name : "whoami.exe" \| bucket 5m \| count() by host.name` — partial; EQL aggregation semantics differ — verify |
| Elastic KQL | No direct support — backend emits a non-aggregating query and notes the limitation in the conversion log |

Document any rule with an aggregation that doesn't convert cleanly, and add a backend-specific override.

### 9.2 Regex support varies

```yaml
# Regex works in Splunk, Elastic, and QRadar
selection:
  CommandLine|re: '(/c\s+.*powershell.*-(e|enc))'
# KQL (Sentinel) does support regex but with different syntax — the
# conversion is approximate. Verify KQL output manually.
```

### 9.3 Base64 modifiers — backend support table

| Modifier | Splunk | Elastic | Sentinel | QRadar |
|----------|--------|---------|----------|--------|
| `base64` | Yes | Yes | Approximate | Yes |
| `base64offset` | Yes | Yes | No | Partial |
| `contains|base64` | Yes | Yes | Approximate | Yes |

### 9.4 Custom pipelines — when to write them

If your Splunk doesn't run CIM, or your Elastic uses a non-ECS schema, write a custom pipeline:

```yaml
# pipelines/acme-ecs.yaml
title: Acme ECS Pipeline
order: 20
vars:
  acme_win_index: "winlogs"
transformations:
  - type: value_placeholders
  - type: field_name_mapping
    mapping:
      Image: process.executable
      CommandLine: process.command_line
      ParentImage: process.parent.executable
      User: user.name
      Host: host.name
```

Apply with:

```bash
sigma convert -t lucene -p pipelines/acme-ecs.yaml rules/windows/process_creation/foo.yml
```

---

## 10. Detection Catalog — Operationalizing the Rule Set

A 500-rule Sigma library is unmanageable from the filesystem alone. Maintain a detection catalog that records, per rule:

- UUID, title, status, level
- Owner (engineer responsible)
- Date created, last reviewed, next review due
- ATT&CK coverage
- Backend deployment status (Splunk: live / Sentinel: live / Elastic: pending)
- FP rate observed in production (rolling 30-day)
- Linked incidents (where this rule fired on a real intrusion)

```python
# scripts/build_catalog.py — extracts catalog entries from rule files
import yaml, glob, json, datetime
catalog = []
for f in glob.glob('rules/**/*.yml', recursive=True):
    doc = yaml.safe_load(open(f))
    catalog.append({
        'id': doc['id'],
        'title': doc['title'],
        'status': doc.get('status', 'unknown'),
        'level': doc.get('level', 'unknown'),
        'tags': doc.get('tags', []),
        'author': doc.get('author'),
        'modified': str(doc.get('modified')),
        'path': f,
    })
print(json.dumps(catalog, indent=2))
```

Feed the catalog into:

- **Navigator** for ATT&CK coverage visualization
- **A review scheduler** — alert owners when a rule hasn't been reviewed in 12 months
- **A deployment pipeline** — only `status: stable` rules deploy to production SIEMs

---

## 11. Closing Checklist

Before marking a Sigma rule production-ready:

- [ ] Schema-valid (`sigma check` passes)
- [ ] MITRE ATT&CK tags present and correct
- [ ] `falsepositives` field populated with real FP scenarios
- [ ] `references` include the MITRE technique URL
- [ ] UUID is unique and stable across versions
- [ ] Converts cleanly to every backend in the stack (Splunk / Sentinel / Elastic)
- [ ] Unit tests cover at least one positive and one negative case
- [ ] Tested against 30+ days of production telemetry
- [ ] FP rate documented and within the rule's FP budget
- [ ] Status promoted `experimental → test → stable` per lifecycle
- [ ] Owner and review date recorded in the catalog
- [ ] SOC triage guidance documented (either in `description` or a linked runbook)
- [ ] If broadly applicable: PR opened against SigmaHQ

---

## 12. References

- **SigmaHQ spec**: [github.com/SigmaHQ/spec](https://github.com/SigmaHQ/spec)
- **SigmaHQ rule repository**: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- **sigma-cli**: [github.com/SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli)
- **pySigma**: [github.com/SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma)
- **pySigma pipeline list**: [github.com/SigmaHQ/pySigma#related-projects](https://github.com/SigmaHQ/pySigma#related-projects)
- **MITRE ATT&CK**: [attack.mitre.org](https://attack.mitre.org)
- **MITRE ATT&CK Navigator**: [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator)
- **Sigma rule tutorial (SigmaHQ wiki)**: [github.com/SigmaHQ/sigma/wiki](https://github.com/SigmaHQ/sigma/wiki)
- **Florian Roth's Sigma posts**: [github.com/Neo23x0](https://github.com/Neo23x0)
- **Splunk Common Information Model (CIM)**: [docs.splunk.com/CIM](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- **Elastic Common Schema (ECS)**: [elastic.co/guide/ecs](https://www.elastic.co/guide/en/ecs/current/index.html)
- **Microsoft Sentinel KQL reference**: [learn.microsoft.com/kusto](https://learn.microsoft.com/kusto/query/)

---

**Related files**: `../SKILL.md`, `../payloads.md`, `../test-cases.md`, `./hunt-hypothesis-playbook.md`
**Integration**: `skills/logging-monitoring/`, `skills/blue-team-ops/`, `skills/chronicle/`, `skills/siem-engineering/`, `skills/threat-intelligence/`, `skills/digital-forensics/`
