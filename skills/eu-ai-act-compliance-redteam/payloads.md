# EU AI Act Compliance Red Team — Payloads

> Companion file to `SKILL.md`. Practical commands, scripts, and artifacts for each EU AI Act compliance task.

## Table of Contents

1. Annex III Classification Decision Tree
2. Risk Register Population
3. Garak LLM Red Team with Annex IV Evidence Capture
4. Microsoft Counterfit for Multi-Modal Adversarial
5. TextAttack NLP Robustness
6. Aequitas / Fairlearn Bias Audit
7. Audit-ML Transparency Logging
8. Model Card Generation (Annex IV §2(c))
9. Datasheet for Datasets (Annex IV §2(a))
10. Annex IV Technical File Assembly
11. Logging Pipeline (Article 12)
12. Serious Incident Report (Article 73)

---

## 1. Annex III Classification Decision Tree

```python
#!/usr/bin/env python3
"""classify.py — Annex III high-risk classification."""
import json, sys, argparse

ANNEX_III = {
    "IV(a)": "Employment, worker management, self-employment (e.g., resume screening, promotion decisions)",
    "IV(b)": "Access to essential private services (credit scoring, insurance pricing)",
    "IV(c)": "Education / vocational training (admissions, exam evaluation)",
    "IV(d)": "Law enforcement (polygraphs, deepfake detection for evidence, predictive policing)",
    "IV(e)": "Migration, asylum, border control (visa eligibility, asylum risk assessment)",
    "IV(f)": "Administration of justice (judicial decision support)",
    "IV(g)": "Democratic processes (voting intent inference, election disinformation detection)",
    "I":    "Biometrics (remote biometric identification, emotion recognition)",
    "II":   "Critical infrastructure (road traffic, water/gas/electric supply)",
    "III":  "Essential services (healthcare triage, emergency dispatch)"
}

def classify(description: str) -> dict:
    description_lower = description.lower()
    matches = []
    for clause, scope in ANNEX_III.items():
        # Naive keyword match — replace with proper NLU in production
        keywords = scope.lower().split()
        if any(kw in description_lower for kw in keywords if len(kw) > 4):
            matches.append(clause)
    return {
        "annex_iii_clauses": matches[:1] if matches else None,
        "high_risk": bool(matches),
        "all_applicable_clauses": matches,
        "obligations": ["Art.9","Art.10","Art.12","Art.13","Art.14","Art.15"] if matches else []
    }

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--system-description", required=True)
    p.add_argument("--output", default="scope.json")
    args = p.parse_args()
    result = classify(args.system_description)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
```

**Usage**:
```bash
python3 classify.py --system-description "LLM screening resumes for senior engineer role" --output scope.json
```

---

## 2. Risk Register Population

```json
{
  "version": "1.0",
  "system_id": "HR-LLM-001",
  "last_updated": "2026-08-08",
  "risks": [
    {
      "id": "R-AI-2026-001",
      "category": "bias",
      "description": "Model under-ranks resumes with non-EU-sounding names",
      "annex_iv_clause": "Art.9(2)(b) — error-free performance across population groups",
      "severity": "high",
      "likelihood": "medium",
      "test_suite": "aequitas_demographic_parity",
      "test_evidence": "evidence/R-AI-2026-001/aequitas_report_2026-08-08.json",
      "mitigation": "Reweight training data; add adversarial debiasing loss; pre-deploy bias threshold gate (disparate impact < 0.8)",
      "residual_risk": "low",
      "residual_risk_acceptance": "VP-HR signoff 2026-08-08; retest 2026-11-08",
      "retest_cadence": "quarterly",
      "owner": "ml-platform-team@company.eu"
    },
    {
      "id": "R-AI-2026-002",
      "category": "robustness",
      "description": "Model accepts subtly perturbed resume inputs (adversarial)",
      "annex_iv_clause": "Art.15 — resilience to errors, faults, attacks",
      "severity": "medium",
      "likelihood": "medium",
      "test_suite": "textattack_robustness",
      "test_evidence": "evidence/R-AI-2026-002/textattack_report_2026-08-08.json",
      "mitigation": "Adversarial training with TextAttack-generated examples; input sanitization",
      "residual_risk": "low",
      "residual_risk_acceptance": "CISO signoff 2026-08-08; retest per-release",
      "retest_cadence": "per-release",
      "owner": "ml-platform-team@company.eu"
    }
  ]
}
```

---

## 3. Garak LLM Red Team with Annex IV Evidence Capture

```bash
# Install Garak
pip install garak

# Run Article 9 / Article 15 robustness probe suite
# Capture evidence for Annex IV §2(f) — automatic event logging
mkdir -p evidence/$(date +%Y-%m-%d)/

garak \
  --model_type huggingface \
  --model_name "company/hr-llm-v2.3.1" \
  --probe_spec article9_robustness \
  --report_prefix evidence/$(date +%Y-%m-%d)/garak_article9 \
  --seed 42 \
  --generations 10 \
  --eval_threshold 0.5

# Post-process: convert Garak JSON to Annex IV evidence entry
python3 skills/eu-ai-act-compliance-redteam/scripts/garak_to_annex_iv.py \
  --garak-report evidence/$(date +%Y-%m-%d)/garak_article9.json \
  --model-commit $(git rev-parse HEAD:models/hr-llm) \
  --test-suite article9_robustness \
  --output evidence/$(date +%Y-%m-%d)/annex_iv_entry.json

# Annex IV entry includes:
# - Test inputs + expected + actual outputs
# - Pass/fail per Article 9 sub-clause
# - Reproducibility (commit hash, seed, env)
# - Timestamp (for Article 12 logging)
```

**Critical probes for Article 9**:
- `article9_robustness.lex` — lexical perturbation (typos, unicode)
- `article9_robustness.synonym` — semantic-preserving swaps
- `article9_robustness.code_switching` — multilingual EU official languages
- `article9_leakage.PII` — PII leakage (Art.10 data governance)
- `article9_oversight.refuse` — model must yield to human override

---

## 4. Microsoft Counterfit for Multi-Modal Adversarial

```bash
# Install Counterfit
git clone https://github.com/Azure/counterfit.git
cd counterfit
pip install -r requirements.txt

# Target a vision model (e.g., a quality-control classifier for medical devices — Annex III II)
python3 counterfit.py \
  --target medical_qc_vit \
  --attack framework_patches \
  --scenario adversarial_patches \
  --output evidence/$(date +%Y-%m-%d)/counterfit_medical_qc.json

# For each attack: capture (input, perturbation, model_output, success_bool, time_to_attack)
# These become the Article 15 robustness evidence rows in Annex IV
```

---

## 5. TextAttack NLP Robustness

```bash
pip install textattack tensorflow

# Run robustness sweep against HR LLM
python3 skills/eu-ai-act-compliance-redteam/scripts/textattack_sweep.py \
  --model "company/hr-llm-v2.3.1" \
  --dataset hr_resume_eval_set.jsonl \
  --transformations word_swap_embedding,word_swap_masked_lm,word_swap_hownet \
  --constraints repeat_ngram,max_words \
  --attack_num 100 \
  --output evidence/$(date +%Y-%m-%d)/textattack_robustness.json

# Article 15 acceptance criterion:
# - < 5% of examples successfully flipped (robustness threshold)
# - Average perturbation distance > 0.7 (attacker effort)
```

---

## 6. Aequitas / Fairlearn Bias Audit

```python
#!/usr/bin/env python3
"""bias_audit.py — Article 10 data governance + Article 9(2)(b) population-group performance."""
import pandas as pd
from aequitas.group import Group
from aequitas.bias import Bias
from aequitas.fairness import Fairness

# Load model predictions + protected attributes
df = pd.read_csv("model_predictions.csv")  # cols: score, label_value, nationality, gender, age_bucket

# Compute per-group metrics
g = Group()
xtab, _ = g.get_crosstabs(df)

b = Bias()
bdf = b.get_disparity_predefined_groups(xtab, original_df=df, ref_groups_dict={"nationality":"EU-EU","gender":"male","age_bucket":"30-45"})

f = Fairness()
fdf = f.get_group_value_fairness(bdf)

# Article 9(2)(b) acceptance: disparate impact ≥ 0.8 across all groups
disparate_impact_fail = fdf[~fdf["Disparate Impact"]].copy()
if not disparate_impact_fail.empty:
    print(f"FAIL: {len(disparate_impact_fail)} groups fail disparate impact test")
    print(disparate_impact_fail[["attribute_name","attribute_value","Disparate Impact"]])
    # Output goes to Annex IV evidence file; CI gates fail the release
else:
    print("PASS: All groups satisfy disparate impact ≥ 0.8")
```

---

## 7. Audit-ML Transparency Logging

```python
# Production-side transparency logging per Article 13
from auditml import ModelAuditor

auditor = ModelAuditor(
    model=hr_llm,
    attribution_method="shap",  # for Article 13 explanation
    log_path="logs/article13_transparency.jsonl"
)

# Wrap inference call
def predict_with_audit(input_resume):
    result = hr_llm.predict(input_resume)
    audit_record = auditor.audit(
        input=input_resume,
        output=result,
        explanation_threshold=0.3
    )
    # Log structure per Article 12 / Annex IV §2(f):
    # {
    #   "timestamp": "2026-08-08T12:00:00Z",
    #   "input_hash": "...",  # PII-safe hash
    #   "output": {...},
    #   "feature_attribution": {...},
    #   "model_version": "v2.3.1",
    #   "human_override": null
    # }
    return result, audit_record
```

---

## 8. Model Card Generation (Annex IV §2(c))

```bash
# Use Google Model Card Toolkit
pip install model-card-toolkit

# Template: skills/eu-ai-act-compliance-redteam/templates/model_card_template.yaml
python3 skills/eu-ai-act-compliance-redteam/scripts/gen_model_card.py \
  --model-metadata models/hr-llm-v2.3.1/metadata.json \
  --training-data-summary data/training_summary.yaml \
  --evaluation-results evidence/$(date +%Y-%m-%d)/ \
  --intended-use "Resume ranking for senior engineering roles in EU markets" \
  --out-of-scope "Non-engineering roles, non-EU markets, automated rejection decisions" \
  --output model_card.md model_card.json

# Output Model Card maps to Annex IV §2(c):
# - System architecture
# - Model parameters
# - Training data summary
# - Evaluation results (with Article 9 evidence references)
# - Intended use & out-of-scope
```

---

## 9. Datasheet for Datasets (Annex IV §2(a))

```yaml
# data/datasheet.yaml — Gebru et al. 2018 template filled for Annex IV §2(a)
motivation:
  purpose: "Train HR-LLM to rank resumes for engineering roles"
  creators: "Internal HR data team + LinkedIn public dataset (filtered)"
  funding: "Internal"

composition:
  instances: 2500000
  representation: "EU-27 nationals, age 25-65, engineering resumes"
  missing_data: "12% missing home country; imputed via work-permit field"

collection:
  acquisition: "Internal application data 2018-2025 + public LinkedIn"
  sampling: "Stratified by country × seniority × role-family"
  consent: "Internal: employment contract clause; LinkedIn: ToS"

preprocessing:
  cleaning: "Deduplication; PII redaction; non-English filtered"
  labeling: "Seniority labels manually reviewed by 3 HR analysts (kappa=0.82)"
  raw_source: "s3://hr-data/raw/2024-Q4/"

uses:
  recommended: "Resume ranking for engineering roles in EU markets"
  not_recommended: "Non-engineering roles; non-EU markets; automated rejection"
  restrictions: "Per EU AI Act Article 9(2)(b) — must retrain if demographic drift detected"

distribution:
  third_party: false  # Article 9(2)(b) requires this be false for high-risk systems
  license: "Internal-only"

maintenance:
  updates: "Quarterly re-audit; bias recheck on any data addition"
  contact: "ml-platform-team@company.eu"
```

---

## 10. Annex IV Technical File Assembly

```bash
python3 skills/eu-ai-act-compliance-redteam/scripts/annex_iv.py \
  --risk-register risk_register.json \
  --test-evidence-dir evidence/ \
  --model-card model_card.md \
  --datasheet data/datasheet.yaml \
  --quality-management-system qms.md \
  --log-summary evidence/log_summary_2026-08-08.json \
  --output annex_iv_technical_file.md annex_iv_technical_file.json

# Annex IV file structure:
# 1. System description (general)
# 2. (a) Data sources + Datasheet reference
# 3. (b) Data collection + preprocessing
# 4. (c) Model architecture + Model Card reference
# 5. (d) Training methodology
# 6. (e) Compute resources used
# 7. (f) Performance evaluation + test evidence references
# 8. (g) Risk management per Article 9
# 9. (h) Changes since last version
# 10. (i) CE marking + declaration of conformity
# 11. (j) Member State contact for post-market
# 12. (k) Logging reference (Article 12)
# 13. (l) Reference to harmonized standards applied
```

---

## 11. Logging Pipeline (Article 12)

```yaml
# Article 12 logging requirements (mandatory fields per Annex IV §2(f))
article_12_log_schema:
  required_events:
    - training_run:
        fields: [timestamp, model_version, dataset_hash, hyperparams, eval_metrics, commit_hash]
        retention: "lifetime of model + 6 months after retirement"
    - validation_test:
        fields: [timestamp, test_suite, inputs_hash, outputs, metrics, evidence_path]
        retention: "lifetime of model + 6 months"
    - post_market_event:
        fields: [timestamp, event_type, severity, model_version, root_cause, corrective_action]
        retention: "5 years (Article 73)"
    - serious_incident:
        fields: [timestamp, severity, harm_caused, corrective_action, regulator_reported_at]
        retention: "10 years"
        notification_deadline: "15 days from awareness (Article 73)"

# Sigma rule for missing training_run log
title: Model trained without training_run log entry
logsource:
  product: ml-platform
  service: training
detection:
  selection:
    event_type: model_train_complete
    log_present: false
  condition: selection
level: high
```

---

## 12. Serious Incident Report (Article 73)

```python
# skills/eu-ai-act-compliance-redteam/scripts/serious_incident.py
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class SeriousIncident:
    id: str
    detected_at: datetime
    severity: str  # "serious" if causing harm or fundamental rights violation
    description: str
    harm_caused: str
    affected_individuals: int
    corrective_action: str
    reported_to_provider: datetime
    reported_to_aioffice: datetime = None  # Within 15 days of becoming aware

    def is_overdue(self) -> bool:
        if self.reported_to_aioffice is None:
            deadline = self.detected_at + timedelta(days=15)
            return datetime.now() > deadline
        return False

# Article 73 reporting flow:
# 1. Deployer detects incident → notifies provider within 24h
# 2. Provider triages; if "serious" → clock starts
# 3. Provider files initial report with AI Office within 15 days
# 4. Follow-up reports as corrective action unfolds
# 5. Final report when incident closed
```

---

## Common Payloads Appendix

### A. Cross-Walk: EU AI Act ↔ NIST AI RMF

| EU AI Act Article | NIST AI RMF Function |
|-------------------|---------------------|
| Art.9 (Risk management) | GOVERN-GOVMAP-Map |
| Art.10 (Data governance) | MEASURE-MEAS-2.1 |
| Art.12 (Logging) | MANAGE-MANAGE-2.3 |
| Art.13 (Transparency) | GOVERN-GOVRISK-1.3 |
| Art.14 (Human oversight) | MANAGE-MANAGE-2.4 |
| Art.15 (Robustness) | MEASURE-MEAS-2.6 |
| Art.72 (Post-market) | MANAGE-MANAGE-1.4 |

### B. Penalty Tiers (Article 99)

| Violation | Max Fine |
|-----------|----------|
| Prohibited AI practices (Article 5) | €35M or 7% global turnover |
| High-risk obligations (Articles 8-15) | €15M or 3% global turnover |
| Incorrect info to authorities | €7.5M or 1% global turnover |

### C. Notified Body vs Internal Control Conformity

| Path | When | Documentation |
|------|------|---------------|
| Internal control (default Annex III) | All Annex III except those in Article 6(3) | Annex IV + QMS + EU declaration + CE mark |
| Notified Body (Article 6(3)) | Biometrics, certain law enforcement, certain critical infrastructure | Above + Notified Body certificate + design examination |

---

## References

- See `SKILL.md` References section
- `guides/eu-ai-act-article-9-deep-dive.md` — clause-by-clause analysis

---

## MITRE ATT&CK Mapping + Reference Expansion (v0.2.7)

### ATT&CK Mapping (F-EUAI-001)

| ATT&CK Technique | Skill Activity | Detection Hint |
|------------------|----------------|-----------------|
| **T1190 — Exploit Public-Facing Application** | AI-endpoint abuse testing (injection) | WAF: anomalous LLM API payloads |
| **T1595 — Active Scanning** | Authorized AI system probing | API gateway: probe patterns |
| **T1566.003 — Spearphishing via Service** | Synthetic-content abuse scenarios | Mail gateway: deepfake lures |
| **T1059.009 — Cloud API** | Automated abuse of hosted AI APIs | CloudTrail: abnormal inference volume |
| **T1071.001 — Web Protocols** | Model exfil over HTTP channels | DLP: large model-file uploads |
