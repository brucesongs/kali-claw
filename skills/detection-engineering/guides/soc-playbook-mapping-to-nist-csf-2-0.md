# SOC Playbook — Mapping Detections to NIST CSF 2.0 and MITRE ATT&CK

> Deep-dive companion to `skills/detection-engineering/SKILL.md` and `skills/detection-engineering/guides/detection-engineering-playbook.md`.
>
> Audience: detection engineers, SOC leads, and purple-team operators who already know how to write a Sigma rule or YARA signature and now want a structured framework for **mapping detections to NIST CSF 2.0 (Cybersecurity Framework) and MITRE ATT&CK**, prioritizing use cases, measuring maturity, and validating detections through purple-team exercises.
>
> Scope: CSF 2.0 function/category mapping, Sigma → ATT&CK → CSF traceability, detection-as-code (DaC) pipelines, use-case prioritization, detection maturity model (DMM), and automated testing with Atomic Red Team and Red Team Automation (RTA).

---

## 1. Why a CSF 2.0 Mapping Playbook

The parent `detection-engineering` skill covers the craft of writing Sigma, YARA, SPL, KQL, and EQL rules. That craft is necessary but not sufficient. A SOC that ships 500 detections but cannot answer "what's our coverage of the Identify function?" or "which ATT&CK techniques have zero detections?" is operating blind. The framework layer — NIST CSF 2.0 plus MITRE ATT&CK — is what turns a pile of rules into a defensible detection program.

NIST CSF 2.0 (released February 2024) is the structural backbone: six Functions (Govern, Identify, Protect, Detect, Respond, Recover) that organize every cybersecurity activity. MITRE ATT&CK is the tactical layer: ~600 techniques and sub-techniques that describe specific adversary behaviors. Together they answer:

- **CSF**: "Are we covering all the right functional areas?" (governance and comprehensiveness)
- **ATT&CK**: "Are we detecting the specific adversary behaviors that matter?" (tactical coverage)

A well-engineered SOC maintains a **traceability matrix** that links every detection to both layers. This playbook is the operations manual for building, maintaining, and validating that matrix.

### 1.1 NIST CSF 2.0 at a Glance

CSF 2.0 expanded the original five Functions (Identify, Protect, Detect, Respond, Recover) to six by adding **Govern** as the umbrella function. The structure:

```
Govern    (GV) — strategy, policy, risk, oversight
Identify  (ID) — asset, risk, supply-chain, improvement
Protect   (PR) — identity, data, platform, infrastructure
Detect    (DE) — continuous monitoring, adverse-event recognition
Respond   (RS) — incident management, analysis, mitigation
Recover   (RC) — incident-recovery communication, restoration
```

Each Function contains Categories (e.g., `DE.CM` — Continuous Monitoring), which contain Subcategories (e.g., `DE.CM-01` — "Networks are monitored to detect potential cybersecurity events"), which map to Informative References (specific standards like ISO 27001, NIST 800-53, COBIT).

### 1.2 MITRE ATT&CK at a Glance

ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs). 14 tactics (Enterprise matrix), ~210 techniques, ~410 sub-techniques. Tactics represent the "why" (initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, impact, plus resource development and reconnaissance in the Pre-ATT&CK matrix). Techniques represent the "how" (T1059 Command and Scripting Interpreter, T1059.001 PowerShell).

Every Sigma rule should carry a `tags` field that includes the ATT&CK technique ID (e.g., `attack.t1059.001`). Every SOC dashboard should aggregate detections by tactic to expose coverage gaps.

---

## 2. CSF 2.0 Function Mapping for Detection Engineering

The detection engineer's work spans all six Functions, but the center of gravity is in **Detect**. The other functions constrain and validate what Detect produces.

### 2.1 Govern (GV)

The Govern Function was added in CSF 2.0 to emphasize that cybersecurity strategy, policy, and risk management must be explicit and accountable. For detection engineering, Govern covers:

- **GV.OC — Organizational Context** — what is the business, what are the crown jewels, what is the risk appetite? Drives detection priorities.
- **GV.RM — Risk Management Strategy** — what risks are accepted vs. mitigated vs. transferred? Drives which detections are must-have vs. nice-to-have.
- **GV.RR — Roles, Responsibilities, and Authorities** — who owns each detection? Who is on call when it fires? Who approves changes to the detection suite?
- **GV.PO — Policy** — written policies that the detections enforce (e.g., "no cleartext credentials in logs", "admin actions require MFA").
- **GV.OV — Cybersecurity Supply Chain Risk Management Oversight** — third-party risk that affects detection coverage (e.g., a SaaS vendor that doesn't ship logs).
- **GV.IM — Improvement** — the feedback loop that turns incidents and purple-team exercises into new detections.

Detection-engineering deliverables for Govern:
- A **Detection Strategy** document that names the organization's top threats (ransomware, insider, supply-chain, etc.), the data sources needed to detect them, and the coverage targets per ATT&CK tactic.
- A **RACI matrix** for each detection (Author, Reviewer, Approver, Operator).
- A **policy-to-detection traceability table** showing which policy each detection enforces.

### 2.2 Identify (ID)

Identify answers "what are we protecting, and what could go wrong?" Detection engineering depends on Identify for:

- **ID.AM — Asset Management** — the asset inventory (servers, endpoints, cloud accounts, SaaS apps, IoT devices). A detection that fires on "unknown endpoint" is only useful if the asset inventory is current.
- **ID.RA — Risk Assessment** — threat models that drive which adversary behaviors the SOC must detect.
- **ID.IM — Improvement** — feeds back into Govern.
- **ID.SC — Cybersecurity Supply Chain Risk Management** — third-party risk (vendor breach, malicious update) that may require dedicated detections.

Detection-engineering deliverables for Identify:
- A **data source inventory** — for each log source (EDR, SIEM, cloud trail, network flow), document the fields available, the retention, the latency, and the owner.
- A **threat model** — which adversaries (ransomware crews, APTs, insiders) are likely to target this organization, and which ATT&CK techniques they favor.

### 2.3 Protect (PR)

Protect is about preventing incidents. Detection engineering supports Protect by:

- **PR.AA — Identity Management, Authentication, and Access Control** — detections for MFA bypass, impossible travel, privilege escalation.
- **PR.DS — Data Security** — detections for unauthorized data access, mass file encryption (ransomware indicator), data exfiltration.
- **PR.PS — Platform Security** — detections for configuration drift, unpatched systems, disabled security controls.
- **PR.IR — Infrastructure Resilience** — detections for DDoS, infrastructure outages, backup tampering.

The Protect-to-Detect boundary is fuzzy. A control that blocks PowerShell execution is Protect; a detection that fires when an attacker tries and fails to use PowerShell is Detect. Many detections span both.

### 2.4 Detect (DE)

Detect is the core Function for this skill. Two Categories:

- **DE.CM — Continuous Monitoring** — the steady-state surveillance of networks, endpoints, accounts, and data. Most Sigma rules live here.
- **DE.AE — Adverse Event Analysis** — the correlation, enrichment, and triage of detections into actionable alerts. This is where alert quality, false-positive rates, and triage playbooks matter.

Subcategories worth memorizing:

| Subcategory | Statement |
|-------------|-----------|
| DE.CM-01 | Networks are monitored to detect potential cybersecurity events. |
| DE.CM-02 | Physical environment is monitored. |
| DE.CM-03 | Personnel activity is monitored. |
| DE.CM-06 | Computing hardware and software are monitored. |
| DE.CM-07 | Infrastructure for service delivery is monitored. |
| DE.CM-08 | Improvement opportunities are identified. |
| DE.AE-01 | Potential incidents are correlated. |
| DE.AE-02 | Detected event information is analyzed. |
| DE.AE-03 | Detection data are collected. |
| DE.AE-04 | Impact of incidents is estimated. |
| DE.AE-05 | Improvement opportunities are identified. |

Every Sigma rule the SOC ships should map to one or more of these subcategories.

### 2.5 Respond (RS)

Respond is the incident-handling Function. Detection engineering supports Respond by:

- **RS.MA — Incident Management** — the detections must produce alerts that are actionable, with enough context for the responder to triage without re-investigating from scratch.
- **RS.AN — Incident Analysis** — detections should carry the evidence (process tree, network connections, file hashes) needed for analysis.
- **RS.MI — Incident Mitigation** — detections can drive automated response (isolate endpoint, disable account) via SOAR playbooks.
- **RS.CO — Incident Response Communication** — detections must be routable to the right responder (SOC L1, IR team, legal, executive).

### 2.6 Recover (RC)

Recover is about restoring services after an incident. Detection engineering supports Recover by:

- **RC.RP — Recovery Plan Execution** — detections for backup integrity (ransomware that tampers with backups before encrypting primary data).
- **RC.CO — Recovery Communication** — detections that inform stakeholder updates during recovery.

### 2.7 Mapping Example

A Sigma rule detecting "PowerShell execution with encoded command" maps to:

- **CSF**: `DE.CM-06` (computing hardware and software monitored), `DE.AE-02` (detected event analyzed), `PR.AA-01` (identities verified, indirectly — abuse of valid identity)
- **ATT&CK**: `T1059.001` (PowerShell), `T1027` (Obfuscated Files or Information), `T1140` (Deobfuscate/Decode Files or Information)
- **Policy**: "PowerShell execution requires approval" (organizational policy)
- **Asset class**: Windows endpoints

This four-way mapping (CSF / ATT&CK / Policy / Asset) is the unit of traceability.

---

## 3. Sigma → ATT&CK → CSF Traceability Matrix

The deliverable that ties everything together is the **traceability matrix** — a table that lists every detection and its mappings.

### 3.1 Matrix Schema

```yaml
# detection-traceability.yaml — one entry per detection
- id: DET-0001
  name: "PowerShell Encoded Command Execution"
  sigma_rule: rules/windows/process_creation/posh_encoded.yml
  csf:
    - DE.CM-06
    - DE.AE-02
    - PR.AA-01
  attack:
    - tactic: execution
      technique: T1059
      subtechnique: T1059.001
    - tactic: defense-evasion
      technique: T1027
    - tactic: defense-evasion
      technique: T1140
  policy:
    - POL-WIN-001  # PowerShell requires approval
  data_sources:
    - Windows Security Event 4688
    - Sysmon Event 1
    - EDR process telemetry
  asset_classes:
    - windows-endpoint
  priority: P1
  status: production
  last_validated: 2026-05-15
```

### 3.2 Building the Matrix

Most SOCs start with a spreadsheet and graduate to a YAML or JSON manifest under version control (alongside the Sigma rules). The build process:

```bash
# 1. Extract ATT&CK tags from every Sigma rule in the repo
for rule in rules/**/*.yml; do
  tags=$(yq -r '.tags[] | select(.name == "attack") | .value' "$rule" 2>/dev/null | tr '\n' ',')
  title=$(yq -r '.title' "$rule")
  echo "$rule,$title,$tags"
done > traceability/attack_tags.csv

# 2. Cross-reference against ATT&CK's enterprise-attack.json
curl -s https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack.json \
  | jq '.objects[] | select(.type == "attack-pattern") | {id: .id, name: .name, tactics: [.kill_chain_phases[].phase_name]}' \
  > traceability/attack_reference.json

# 3. Generate coverage gaps — which ATT&CK techniques have no detection?
python3 scripts/coverage_gap_analysis.py \
  --detections traceability/attack_tags.csv \
  --reference traceability/attack_reference.json \
  --output traceability/gaps.md
```

### 3.3 Coverage Dashboard

A simple heatmap by ATT&CK tactic exposes the gaps:

```
Tactic              | Techniques | Covered | Coverage % | Gap
--------------------|------------|---------|------------|----
Reconnaissance      |     18     |    3    |    17%     |  15
Resource Development|     11     |    2    |    18%     |   9
Initial Access      |     14     |    8    |    57%     |   6
Execution           |     17     |   14    |    82%     |   3
Persistence         |     59     |   22    |    37%     |  37
Privilege Escalation|     27     |   11    |    41%     |  16
Defense Evasion     |     86     |   28    |    33%     |  58
Credential Access   |     31     |   13    |    42%     |  18
Discovery           |     37     |   15    |    41%     |  22
Lateral Movement    |     27     |   12    |    44%     |  15
Collection          |     23     |    9    |    39%     |  14
Command and Control |     42     |   17    |    40%     |  25
Exfiltration        |     18     |    7    |    39%     |  11
Impact              |     34     |   14    |    41%     |  20
```

The gaps are not equally important — see Section 5 for prioritization.

### 3.4 CSF Function Coverage

Aggregate the same matrix by CSF Function to expose governance-level gaps:

```python
# scripts/csf_coverage.py
import yaml, collections
counts = collections.Counter()
for det in yaml.safe_load(open('detection-traceability.yaml')):
    for fn in det['csf']:
        # Extract the Function code (e.g., 'DE' from 'DE.CM-06')
        counts[fn.split('.')[0]] += 1
for fn, n in sorted(counts.items()):
    print(f"{fn}: {n} detections")
```

A healthy SOC has 60-70% of detections in `DE`, 15-20% in `PR` (preventive detections that produce alerts), 10-15% in `RS` (response-triggering detections), and small but non-zero counts in `GV`, `ID`, `RC`. Zero detections in any Function is a gap to investigate.

---

## 4. Detection-as-Code (DaC) Pipeline

Detection-as-Code is the practice of treating Sigma rules (and YARA, KQL, SPL, EQL) as first-class software artifacts with version control, code review, CI testing, and staged deployment. The pipeline is the SOC's equivalent of a software release pipeline.

### 4.1 Pipeline Stages

```
Author → Commit → CI Lint → CI Test → Code Review → Stage Deploy → Prod Deploy → Monitor → Retire
  |        |         |         |          |              |              |          |         |
  +--------+---------+---------+----------+--------------+--------------+----------+---------+
                                                                                       |
                                                                                       v
                                                                                  Improvement
                                                                                  (back to Author)
```

### 4.2 Author and Commit

Rules live in a Git repository (`detections/` or `sigma-rules/`). Each rule is a YAML file following the Sigma schema. Naming convention matters — pick one and stick to it:

```
rules/
├── windows/
│   ├── process_creation/
│   │   ├── posh_encoded_command.yml
│   │   ├── certutil_download.yml
│   │   └── ...
│   ├── registry_event/
│   ├── file_event/
│   └── network_connection/
├── linux/
├── macos/
├── cloud/
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── saas/
└── network/
```

### 4.3 CI Lint and Test

A GitHub Actions / GitLab CI pipeline runs on every commit:

```yaml
# .github/workflows/detection-ci.yml
name: Detection CI
on: [push, pull_request]
jobs:
  sigma-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install SigmaCLI
        run: pip install sigmatools
      - name: Lint Sigma rules
        run: |
          for rule in rules/**/*.yml; do
            sigma-parser "$rule" || exit 1
          done
      - name: Validate ATT&CK tags
        run: python3 scripts/validate_attack_tags.py rules/
      - name: Translate to target backends
        run: |
          mkdir -p translated/
          for rule in rules/**/*.yml; do
            sigma-cli convert -t splunk -p sysmon "$rule" \
              >> translated/splunk.spl
            sigma-cli convert -t microsoft-365 "$rule" \
              >> translated/kql.kql
          done
      - name: Run unit tests against EVTX-ATTACK-SAMPLES
        run: |
          git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES evtx-samples
          python3 scripts/test_against_evtx.py \
            --rules rules/ \
            --samples evtx-samples/ \
            --output test_results.json
      - name: Upload test results
        uses: actions/upload-artifact@v4
        with:
          name: detection-test-results
          path: test_results.json
```

### 4.4 Test Against EVTX-ATTACK-SAMPLES

[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) is a curated corpus of Windows event logs from attack recreations. Every Sigma rule in `process_creation`, `registry_event`, `file_event`, `network_connection` categories should be tested against this corpus:

```python
# scripts/test_against_evtx.py
import json, subprocess, glob
def test_rule(rule_path, samples_dir):
    hits = []
    for evtx in glob.glob(f"{samples_dir}/**/*.evtx", recursive=True):
        # Use hayabusa or zircollo to apply the rule to the EVTX
        result = subprocess.run(
            ["hayabusa", "csv-timeline", "-f", evtx, "-r", rule_path, "-o", "/tmp/out.csv"],
            capture_output=True, text=True)
        if "critical" in result.stdout.lower() or "high" in result.stdout.lower():
            hits.append(evtx)
    return {"rule": rule_path, "hits": hits, "hit_count": len(hits)}
```

A rule that produces zero hits across 1000+ attack samples is likely broken. A rule that produces 100% hits (matches every sample, including unrelated ones) is over-broad.

### 4.5 Code Review

Pull requests require review by a second detection engineer. Review checklist:

- [ ] Rule follows the Sigma schema (passes `sigma-parser`)
- [ ] ATT&CK tags are accurate and current
- [ ] CSF mapping is documented
- [ ] Test results show the rule fires on the intended samples
- [ ] False-positive analysis documented (which benign activity would fire this?)
- [ ] Severity and confidence levels set appropriately
- [ ] Description and references populated

### 4.6 Stage and Prod Deploy

Promote to stage, run against the live SOC for a burn-in period (1-2 weeks), measure false-positive rate, then promote to prod:

```bash
# Stage deploy
sigma-cli deploy --env stage rules/

# After burn-in, measure FP rate
python3 scripts/fp_rate.py --rule rules/windows/posh_encoded_command.yml --window 14d

# Prod deploy (requires two-person approval via PR merge)
sigma-cli deploy --env prod rules/
```

### 4.7 Monitor and Retire

Every rule has a lifetime. Track:

- **Last-fired date** — a rule that hasn't fired in 90 days may be obsolete; investigate.
- **False-positive rate** — a rule with >10% FP rate is noise; tune or retire.
- **Coverage** — if the underlying technique is no longer observed in the wild (e.g., a deprecated tool), retire the rule.

```python
# scripts/rule_health.py
import yaml, datetime
for rule in load_all_rules():
    age = datetime.date.today() - rule['last_validated']
    fp_rate = compute_fp_rate(rule['id'], window_days=30)
    if age.days > 180:
        flag_for_review(rule, reason="stale")
    elif fp_rate > 0.10:
        flag_for_review(rule, reason="noisy")
    elif rule['last_fired'] is None:
        flag_for_review(rule, reason="never fired")
```

---

## 5. Use Case Prioritization Matrix

Not every detection is equally valuable. A prioritization matrix balances **impact** (how damaging is the adversary behavior we're trying to catch?) against **feasibility** (how reliably can we detect it with the data we have?).

### 5.1 The 2x2 Matrix

```
                  High Feasibility                Low Feasibility
              ┌─────────────────────────┬─────────────────────────┐
              │                         │                         │
 High Impact  │   QUICK WINS            │   STRATEGIC             │
              │   (build first)         │   (invest in data)      │
              │                         │                         │
              ├─────────────────────────┼─────────────────────────┤
              │                         │                         │
 Low Impact   │   FILL-INS              │   AVOID                 │
              │   (build opportunistically) (skip unless mandated)│
              │                         │                         │
              └─────────────────────────┴─────────────────────────┘
```

### 5.2 Scoring Impact

Impact scoring rubric (1-5):

- **5 — Critical**: Adversary behavior that leads directly to domain compromise, data breach, or ransomware deployment. Examples: LSASS dump, golden ticket, mass file encryption.
- **4 — High**: Behavior that enables follow-on compromise. Examples: credential theft, privilege escalation, persistence installation.
- **3 — Medium**: Behavior that indicates active adversary presence. Examples: discovery commands, lateral movement.
- **2 — Low**: Behavior that may be benign or malicious. Examples: PowerShell execution, remote desktop login.
- **1 — Informational**: Contextual events useful for correlation. Examples: user logon, process start.

### 5.3 Scoring Feasibility

Feasibility scoring rubric (1-5):

- **5 — Trivial**: Direct log source, deterministic pattern. Example: Windows Security 4624 (logon event).
- **4 — Easy**: Multiple log sources, simple correlation. Example: process + network connection.
- **3 — Moderate**: Requires correlation across 3+ sources or entity enrichment. Example: user → asset → IP reputation.
- **2 — Hard**: Requires custom parsing, unstable field names, or low-confidence heuristics. Example: PowerShell script-block logging with obfuscation.
- **1 — Infeasible**: No log source covers the behavior. Example: in-memory .NET assembly execution without ETW.

### 5.4 Prioritization Rules

- **Quick Wins (high impact, high feasibility)** — build first. These are the detections that materially improve the SOC's coverage with minimal effort.
- **Strategic (high impact, low feasibility)** — invest in data sources. If LSASS dump detection is infeasible because Sysmon isn't deployed, deploy Sysmon first.
- **Fill-Ins (low impact, high feasibility)** — build opportunistically, when an engineer has spare cycles. Useful for completeness; do not let them crowd out Quick Wins.
- **Avoid (low impact, low feasibility)** — skip unless mandated by compliance or policy.

### 5.5 Worked Example

Detection: "Mimikatz LSASS dump via `procdump`"

- **Impact**: 5 (LSASS dump → credential theft → domain compromise)
- **Feasibility**: 5 (Sysmon Event 10 process access + target image lsass.exe + source image procdump.exe — deterministic)
- **Quadrant**: Quick Wins → build first

Detection: "Living-off-the-land execution of `certutil` with `-urlcache` flag"

- **Impact**: 4 (file download → potential malware delivery)
- **Feasibility**: 5 (Sysmon Event 1 process creation + command line)
- **Quadrant**: Quick Wins → build first

Detection: "Behavioral anomaly in PowerShell script-block content"

- **Impact**: 4 (script-block injection, LOLBAS abuse)
- **Feasibility**: 2 (requires script-block logging + ML or heuristic + high FP risk)
- **Quadrant**: Strategic → invest in detection algorithm before building

---

## 6. Detection Maturity Model (DMM)

Where is the SOC on the maturity curve? The DMM is a 5-level model adapted from CMMI:

### 6.1 The Five Levels

| Level | Name | Characteristics |
|-------|------|-----------------|
| 1 | **Initial** | Ad-hoc detections, no version control, no testing, no metrics. "We have some Splunk searches." |
| 2 | **Repeatable** | Detections in version control, basic CI lint, manual testing. "We can reproduce a detection." |
| 3 | **Defined** | DaC pipeline with automated testing against EVTX-ATTACK-SAMPLES, ATT&CK/CSF traceability, code review required. |
| 4 | **Managed** | Metrics-driven (FP rate, MTTR, coverage by tactic), purple-team validation, automated tuning. |
| 5 | **Optimizing** | Continuous improvement loop; detections auto-generated from threat-intel feeds; ML-assisted tuning; self-healing FP suppression. |

### 6.2 Self-Assessment Checklist

For each level, score the SOC against the criteria:

```yaml
# dmm-self-assessment.yaml
level_1_initial:
  - detections_in_version_control: false
  - ci_pipeline: false
  - automated_testing: false
  - attack_mapping: false
  - csf_mapping: false
  - metrics_tracking: false
level_2_repeatable:
  - detections_in_version_control: true
  - ci_pipeline: basic
  - automated_testing: false
  - attack_mapping: partial
  - csf_mapping: false
  - metrics_tracking: false
level_3_defined:
  - detections_in_version_control: true
  - ci_pipeline: full
  - automated_testing: evtx_attack_samples
  - attack_mapping: complete
  - csf_mapping: complete
  - metrics_tracking: false
level_4_managed:
  - detections_in_version_control: true
  - ci_pipeline: full
  - automated_testing: evtx_attack_samples
  - attack_mapping: complete
  - csf_mapping: complete
  - metrics_tracking: fp_rate_mttr_coverage
  - purple_team_validation: quarterly
level_5_optimizing:
  - detections_in_version_control: true
  - ci_pipeline: full
  - automated_testing: evtx_attack_samples
  - attack_mapping: complete
  - csf_mapping: complete
  - metrics_tracking: fp_rate_mttr_coverage
  - purple_team_validation: monthly
  - auto_generation_from_threat_intel: true
  - ml_assisted_tuning: true
```

The highest level where all criteria are met is the SOC's maturity level.

### 6.3 Advancing Through the Levels

- **1 → 2**: Get detections into Git. Stand up a basic CI lint. Manual testing on a sample corpus.
- **2 → 3**: Add automated EVTX-ATTACK-SAMPLES testing. Map every rule to ATT&CK and CSF. Require code review.
- **3 → 4**: Instrument metrics. Schedule quarterly purple-team exercises. Begin FP-rate-driven tuning.
- **4 → 5**: Threat-intel-to-detection automation. ML-assisted anomaly detection. Self-healing FP suppression.

Most enterprise SOCs sit at level 2-3. Level 4-5 requires sustained investment and is typically seen only in mature, well-funded programs.

---

## 7. Purple Team Validation

Purple-team exercises are the empirical validation layer. Every detection the SOC ships should be tested by having the red team attempt the technique, and confirming the detection fires.

### 7.1 Exercise Structure

A typical purple-team cycle:

1. **Select techniques** — pick 5-10 ATT&CK techniques that are claimed-covered by detections.
2. **Red team executes** — using Atomic Red Team or RTA, the red team performs each technique on a test endpoint.
3. **Blue team observes** — confirm the detection fired, capture the alert, triage as if it were a real incident.
4. **Compare** — did the detection fire within the expected time window? Was the alert actionable? Was the context sufficient?
5. **Document gaps** — missed detections go into the improvement backlog.

### 7.2 Atomic Red Team

[RedCanaryEO/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) is a library of small, precisely-scoped tests mapped to ATT&CK techniques. Each "atomic" is a single test that performs one technique.

```bash
# Install Atomic Red Team
Invoke-WebRequest https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1 -OutFile install-atomicredteam.ps1
Install-AtomicRedTeam -repoOwner redcanaryco -repoName atomic-red-team

# Execute a specific atomic (Windows PowerShell)
Invoke-AtomicTest T1059.001

# Execute with cleanup
Invoke-AtomicTest T1059.001 -Cleanup

# Execute all atomics for a technique (some have multiple)
Invoke-AtomicTest T1059.001 -ShowDetails
```

### 7.3 Red Team Automation (RTA)

[endgameinc/RTA](https://github.com/endgameinc/RTA) (now Endgame/Elastic) provides Python-based adversary emulation scripts. RTA is less maintained than Atomic Red Team but offers more complex multi-step scenarios.

```bash
# Install RTA
git clone https://github.com/endgameinc/RTA.git
cd RTA
pip install -r requirements.txt

# Run a specific RTA
sudo python rta.py -f RTA/persistence/sch_task.py

# Run a random RTA (good for surprise purple-team testing)
sudo python rta.py -r
```

### 7.4 Validation Script

Automate the full validation cycle:

```python
# scripts/purple_team_validation.py
import subprocess, json, yaml
RESULTS = []
for technique in load_covered_techniques():
    # Run the atomic on the test endpoint
    subprocess.run(["Invoke-AtomicTest", technique['id']], check=True)
    # Wait for detection latency
    import time; time.sleep(300)
    # Query the SIEM for alerts that should have fired
    alerts = query_siem(
        index="alerts",
        query=f"attack.technique:{technique['id']} AND timestamp:[now-5m TO now]")
    RESULTS.append({
        "technique": technique['id'],
        "expected_detections": technique['detections'],
        "actual_alerts": [a['id'] for a in alerts],
        "status": "PASS" if alerts else "FAIL"
    })

with open('validation_results.json', 'w') as f:
    json.dump(RESULTS, f, indent=2)
```

### 7.5 Validation Cadence

- **New detections** — validate immediately after promotion to prod.
- **Quarterly** — run the full suite of covered techniques. Catch regressions from rule edits, log-source changes, or agent updates.
- **Annual** — full ATT&CK evaluation (every technique in the matrix, even uncovered ones, to confirm coverage gaps).

---

## 8. Metrics and KPIs

A defensible detection program measures itself. The KPIs:

### 8.1 Coverage Metrics

- **ATT&CK technique coverage** — percent of techniques (or sub-techniques) with at least one production detection.
- **CSF Function coverage** — distribution of detections across GV/ID/PR/DE/RS/RC.
- **Data source coverage** — percent of identified data sources (from the ID.AM inventory) with at least one detection consuming them.

### 8.2 Quality Metrics

- **False-positive rate** — percent of alerts that are closed as "benign" or "tuning" after triage. Target: <5%.
- **Mean time to detect (MTTD)** — time from adversary action to alert firing. Target: <5 minutes for high-severity detections.
- **Mean time to respond (MTTR)** — time from alert firing to SOC acknowledgment. Target: <15 minutes for high-severity.
- **Detection confidence** — percent of high-severity alerts that are confirmed true positives. Target: >70%.

### 8.3 Operational Metrics

- **Detection lifecycle** — time from rule author to prod deploy. Target: <2 weeks for Quick Wins.
- **Validation cadence** — quarterly purple-team exercises completed on schedule.
- **Rule health** — percent of rules with last-validated <90 days, FP rate <5%, last-fired within retention window.

### 8.4 Reporting

A monthly detection-program report aggregates the KPIs:

```markdown
# Detection Program Report — June 2026

## Coverage
- ATT&CK technique coverage: 142 / 614 (23%) — target 30% by Q4
- CSF Function distribution: GV 2%, ID 5%, PR 12%, DE 64%, RS 12%, RC 5%
- Data source coverage: 28 / 35 (80%)

## Quality
- Average FP rate: 3.2% (target <5%)
- MTTD (high-sev): 4m 12s (target <5m)
- MTTR (high-sev): 11m 38s (target <15m)
- High-sev confidence: 74% (target >70%)

## Operational
- New detections shipped: 12
- Detections retired: 4
- Purple-team validation: 47 / 50 techniques PASS (94%)

## Improvement backlog
- 6 strategic detections pending data-source investment
- 3 detections in FP-tuning sprint
```

---

## 9. Defensive Recommendations (For the Reporting Section)

The detection-engineering findings translate into concrete defensive recommendations:

1. **Adopt NIST CSF 2.0 as the structural framework** — assign Function owners, map every detection to CSF + ATT&CK, report coverage quarterly.
2. **Stand up a Detection-as-Code pipeline** — version control, CI lint, EVTX-ATTACK-SAMPLES testing, code review, staged deploy.
3. **Prioritize by the 2x2 matrix** — build Quick Wins first; invest in data sources for Strategic detections; skip Avoid quadrant unless mandated.
4. **Instrument metrics** — FP rate, MTTD, MTTR, coverage by tactic. Make metrics visible to SOC leadership weekly.
5. **Run quarterly purple-team validation** — Atomic Red Team + RTA against the covered technique set. Backlog every gap.
6. **Track detection health** — retire stale, noisy, or never-fired rules. Treat detections as living artifacts, not set-and-forget.
7. **Invest in strategic data sources** — if a high-impact technique is infeasible due to missing telemetry, prioritize the telemetry investment. Common gaps: Sysmon (Windows), auditd (Linux), ESF (macOS), cloud trail (AWS/Azure/GCP).
8. **Automate where possible** — FP suppression, tuning suggestions, threat-intel-to-detection generation. Level 4-5 maturity requires automation.

---

## 10. Cross-References

- `skills/detection-engineering/SKILL.md` — the parent skill; Sigma, YARA, SPL, KQL, EQL authoring
- `skills/detection-engineering/guides/detection-engineering-playbook.md` — the broader detection-engineering playbook
- `skills/detection-engineering/payloads.md` — Sigma rule anatomy, SigmaCLI usage, hayabusa/zircollo pipelines
- `skills/threat-hunting/SKILL.md` — threat-hunting hypotheses that drive new detections
- `skills/logging-monitoring/SKILL.md` — the data-source layer that detections consume
- `skills/digital-forensics/SKILL.md` — DFIR findings that feed detection improvement
- `skills/incident-response/SKILL.md` — incident learnings that drive new detections
- `skills/purple-team/SKILL.md` — purple-team discipline that validates detections
- **External resources**:
  - NIST CSF 2.0: [nist.gov/cyberframework](https://www.nist.gov/cyberframework)
  - NIST CSF 2.0 Reference Tool: [ncp.nist.gov/csf/reference-tool](https://ncp.nist.gov/csf/reference-tool/)
  - MITRE ATT&CK: [attack.mitre.org](https://attack.mitre.org/)
  - ATT&CK Navigator: [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
  - Atomic Red Team: [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
  - Red Team Automation (RTA): [github.com/endgameinc/RTA](https://github.com/endgameinc/RTA)
  - EVTX-ATTACK-SAMPLES: [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  - SigmaHQ: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
  - SigmaCLI: [github.com/SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli)
  - hayabusa: [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa)
  - zircollo: [github.com/wagga40/Zircolite](https://github.com/wagga40/Zircolite)
  - NIST 800-53: [csrc.nist.gov/projects/risk-management/sp800-53-controls](https://csrc.nist.gov/projects/risk-management/sp800-53-controls)
- **Real-world references**:
  - NIST CSF 2.0 release (February 2026) — Govern Function added
  - MITRE ATT&CK v13-v16 (2023-2026) — technique/sub-technique expansions
  - Sigma as de facto standard for vendor-neutral detection rules
  - Atomic Red Team as the standard purple-team atomic test library
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
