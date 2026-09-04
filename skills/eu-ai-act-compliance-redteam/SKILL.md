---
name: eu-ai-act-compliance-redteam
description: "EU AI Act (Regulation (EU) 2024/1689) compliance-focused red team testing for high-risk AI systems — Article 9 adversarial testing, Annex III classification, Annex IV technical documentation, conformity assessment, and Notified Body audit preparation. Enforceable since 2 August 2026 with fines up to €35M or 7% global turnover."
origin: kali-claw
version: "0.2.0.2"
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
  - Python
metadata:
  domain: ai-compliance
  category: ai
  tool_count: 8
  guide_count: 1
  mitre: "EUAI-Article-9, TA0040-Impact"
  owasp: "N/A — regulatory framework, not vulnerability class"
  keywords:
    - EU-AI-Act
    - AI-compliance
    - Article-9
    - red-team
    - Annex-III
    - Annex-IV
    - conformity-assessment
    - Notified-Body
  last_reviewed: "2026-09-04"
---

# Skill: EU AI Act Compliance Red Team

> **Supplementary Files**:
> - `payloads.md` — Article 9 testing commands, Annex IV documentation generators, conformity assessment scripts, Notified Body audit prep check
> - `test-cases.md` — 5 structured test cases covering LLM red team, deepfake classification, bias testing, transparency docs, and robustness adversarial
> - `guides/eu-ai-act-article-9-deep-dive.md` — Article 9 clause-by-clause analysis with test mapping

## Summary

EU AI Act compliance-focused red team skill domain. Validating that high-risk AI systems satisfy Article 9 (data governance, adversarial robustness, logging, transparency, human oversight) and Annex IV (technical documentation) requirements, with conformity assessment evidence and Notified Body audit preparation.

**Domain**: ai-compliance | **Regulation**: EU Regulation 2024/1689 | **Enforcement**: since 2026-08-02

## Description

The **EU AI Act** (Regulation (EU) 2024/1689) is the world's first comprehensive legal framework for artificial intelligence. After a phased implementation beginning February 2025, the **high-risk AI system obligations under Articles 8–15 entered enforceable status on 2 August 2026**. National competent authorities (the AI Office plus each Member State's regulator) may now initiate audits, demand technical documentation, and impose penalties.

The maximum penalty: **€35 million or 7% of global annual turnover**, whichever is higher. For mid-cap enterprises the threshold drops to €15M / 3%, but for systemic-risk general-purpose AI models the maximum still applies.

Article 9 specifically mandates that providers of high-risk AI systems conduct **adversarial testing (red teaming)** to identify and mitigate known and reasonably foreseeable vulnerabilities. This is distinct from technical AI red teaming (covered in `ai-safety-redteam-advanced`) — Article 9 testing must be **documented in Annex IV technical files, with risk treatment decisions, residual risk acceptance, and retest schedules**.

This skill covers the **compliance perspective**: how to map a high-risk AI system to Annex III categories, run red-team tests that satisfy Article 9 acceptance criteria, generate Annex IV technical documentation artifacts, prepare for conformity assessment, and survive a Notified Body audit.

### Skill Identity

| Aspect | Value |
|--------|-------|
| Type | Compliance testing + documentation generation |
| Distinguishing feature | Regulatory lens applied to technical red team work |
| Adjacent skills | `ai-safety-redteam-advanced` (technical), `ai-security` (model/app security), `llm-red-team` (LLM-specific) |
| Distinct from adjacent | This skill produces **compliance evidence**; adjacent skills produce **vulnerability findings** |

### Why this skill exists

Three converging trends made this skill necessary in 2026:

1. **Enforcement began 2026-08-02**. Annex III high-risk systems (biometrics, critical infrastructure, education, employment, essential services, law enforcement, migration, justice, democratic processes) must comply. Companies that did not prepare Article 9 evidence in 2025-2026 are now exposed to fines.
2. **Annex IV technical documentation is the audit deliverable**. Most technical red team tools (Garak, Counterfit, TextAttack) produce findings; Annex IV requires *evidence-attached, traceable, retested-on-schedule* findings. There is a documentation gap.
3. **Notified Body audits in late 2026** will be the first wave. Companies facing audit need a structured way to organize the artifacts they have (or generate what's missing).

### Differentiation from `ai-safety-redteam-advanced`

| Dimension | `ai-safety-redteam-advanced` | This skill |
|-----------|------------------------------|------------|
| Goal | Find technical vulnerabilities | Produce regulatory compliance evidence |
| Output | Vulnerability report, CVSS scores, PoCs | Annex IV technical file, risk register, audit trail |
| Audience | Security engineers, CISO | Notified Body auditor, AI Office regulator, compliance team |
| Tools | OWASP LLM Top 10, jailbreaks, prompt injection | Article 9 test matrix, Annex IV template, conformity checklists |
| Test cadence | Continuous / on-demand | Per-release + per-change + per-retest-window |

Both skills use overlapping tools (Garak, Counterfit, TextAttack) but produce different artifacts for different audiences.

## Use Cases

1. **Pre-audit readiness assessment** for an enterprise deploying a high-risk LLM (e.g., HR resume screening) — generate the Article 9 evidence trail and identify gaps before a Notified Body arrives
2. **Annex III high-risk classification** — determine if a new AI feature (e.g., AI-driven loan approval) falls under Annex III scope and which Article 9 sub-clauses apply
3. **Adversarial robustness testing (Article 15)** — run documented red team suites against an in-production model, capturing inputs/outputs/metrics for the technical file
4. **Data governance audit (Article 10)** — verify training data provenance, bias mitigation, andDatasheet generation completeness
5. **Transparency documentation (Article 13)** — generate user-facing notices, instructions for use, and confidence-score disclosures for deployers
6. **Human oversight effectiveness (Article 14)** — test that human reviewers can override AI outputs and detect when the AI is wrong; log override rates and decision quality
7. **Logging completeness (Article 12 / Annex IV §2(f))** — verify automatic event logging captures training runs, validation tests, post-market monitoring events
8. **Conformity assessment preparation** — assemble Annex IV technical documentation (system architecture, model card, training data summary, test results, risk register)
9. **Post-market monitoring (Article 72)** — establish the loop: production telemetry → anomaly detection → re-test → update risk register → file revision
10. **Cross-border deployment check** — verify that a model trained and approved in one Member State is acceptable for deployment in another (mutual recognition under Article 60)

## Core Tools

| Tool | Category | Purpose | License |
|------|----------|---------|---------|
| **Garak** (NVIDIA) | LLM vulnerability scanner | Probe LLMs for OWASP LLM Top 10 + EU AI Act Article 15 robustness; CSV/JSON output for Annex IV | Apache 2.0 |
| **Microsoft Counterfit** | AI red-team orchestration | Run adversarial suites against ML models (vision, NLP, tabular); task-level evidence collection | MIT |
| **TextAttack** | NLP adversarial | Generate and run adversarial text perturbations for robustness testing | MIT |
| **Audit-ML** | Model decision audit | Log feature attribution + outcome explanation; supports Article 13 transparency | Apache 2.0 |
| **Aequitas / Fairlearn** | Bias auditing | Quantify demographic disparity in model outcomes; supports Article 10 data governance | MIT / MIT |
| **Model Card Toolkit** (Google) | Documentation generation | Generate Model Cards (Mitchell et al. 2019) that map to Annex IV §2(c) | Apache 2.0 |
| **Datasheets for Datasets** templates | Documentation generation | Fill Gebru et al. 2018 datasheet template → Annex IV §2(a) | CC-BY |
| **NIST AI RMF** (framework) | Risk management alignment | Map EU AI Act evidence to NIST AI RMF Govern/Map/Measure/Manage for cross-jurisdiction | Public domain |

## Methodology

### Phase 1: Classification & Scope

Determine whether the AI system falls under EU AI Act high-risk (Annex III) or is otherwise regulated (e.g., GPAI with systemic risk under Article 51).

```bash
# Decision-tree prompt
python3 skills/eu-ai-act-compliance-redteam/scripts/classify.py \
  --system-description "LLM screening resumes for senior engineer role" \
  --output scope.json
# Outputs: { "annex_iii_clause": "IV(a)", "high_risk": true, "obligations": ["Art.9","Art.10","Art.13","Art.14","Art.15"] }
```

### Phase 2: Risk Assessment & Test Plan

Using NIST AI RMF + EU AI Act Article 9, build a risk register and corresponding test plan. Each risk maps to one or more Article 9 sub-clauses.

```python
# Risk register entry
risk = {
    "id": "R-AI-2026-001",
    "description": "Model fails on non-English EU official language resumes",
    "article_9_clause": "Art.9(2)(b) — error-free performance across population groups",
    "severity": "high",
    "test_suite": "multilingual_resume_eval",
    "mitigation": "fine-tune on Spanish/Polish/German HR data; add pre-deployment language coverage test",
    "residual_risk_acceptance": "low — CEO signoff required",
    "retest_cadence": "quarterly"
}
```

### Phase 3: Adversarial Testing Execution

Run the test plan using Garak, Counterfit, TextAttack, Aequitas. Capture:
- Input + expected output + actual output + metric (passed/failed)
- Reproducibility (model commit hash, random seed, environment)
- Time-stamped logs (for Article 12 / Annex IV §2(f))

### Phase 4: Documentation Generation

Generate Annex IV technical file, Model Card, Datasheet, and risk register. Each artifact cross-references the test evidence captured in Phase 3.

```bash
# Generate Annex IV technical file (Markdown + JSON)
python3 skills/eu-ai-act-compliance-redteam/scripts/annex_iv.py \
  --risk-register risks.json \
  --test-evidence evidence/ \
  --model-card model_card.json \
  --datasheet data/datasheet.yaml \
  --output annex_iv_technical_file.md
```

### Phase 5: Conformity Assessment & Post-Market

Submit Annex IV file + internal control documentation for conformity assessment (internal control for most Annex III systems, Notified Body for some). Establish post-market monitoring loop (Article 72).

### Defense Perspective

| Defense Layer | Control | Key Points |
|---------------|---------|------------|
| **Classification (Phase 1)** | Document Annex III reasoning in `scope.json`; require legal review for borderline cases | Misclassification is the #1 audit failure mode — every Notified Body will challenge the classification first |
| **Risk assessment (Phase 2)** | Use both top-down (scenario-based) and bottom-up (component-based) risk ID; cross-walk to NIST AI RMF | Article 9 doesn't prescribe a methodology; choosing a recognized framework (NIST AI RMF, ISO/IEC 23894) reduces audit pushback |
| **Test execution (Phase 3)** | Reproducibility: pin model commit, random seeds, dependency versions; store raw outputs alongside processed results | Auditors request re-runs; non-reproducible test = invalid evidence |
| **Documentation (Phase 4)** | Annex IV file should be machine-readable (JSON) AND human-readable (Markdown); generate both from same source | Auditors use both formats depending on whether they are technical or legal |
| **Conformity (Phase 5)** | Internal-control conformity (Annex III default) needs 4 documents: technical file, quality management system, EU declaration of conformity, CE mark registration; Notified Body conformity (Article 6(3)) needs 7 documents | Don't conflate the two conformity paths — the documentation burden differs |
| **Post-market (Art. 72)** | Logging requirements under Article 12 + Annex IV §2(f) require automatic capture of training runs, post-deployment events, and serious incidents; serious incidents must be reported to the AI Office within 15 days (Article 73) | Logging must be designed, not bolted on; retrofit is painful |
| **Penalty mitigation** | Maintain evidence that provider exercised "due diligence" — Article 9 evidence + corrective action on past findings = strongest mitigation argument | The AI Office has discretion; documented good faith is the strongest defense |

## Detection Methods

Detection of **non-compliance** with the EU AI Act — the regulator's perspective.

### Regulator Detection (What auditors look for)

- **Absence of risk register** — first thing an auditor asks for; missing = immediate red flag
- **Test evidence older than 12 months** — Article 9 implies currency; stale tests = non-compliance
- **Annex IV file without traceability** — claims without reproducibility (no commit hash, no seed) = invalid
- **Missing serious-incident reports** — Article 73 requires reporting within 15 days; auditor checks registry
- **Inadequate logging** — Article 12 + Annex IV §2(f) define specific event types; missing any = finding
- **No post-market monitoring plan** — Article 72 requires a documented process; absence = non-compliance

### Provider Self-Detection

```bash
# Compliance self-check
python3 skills/eu-ai-act-compliance-redteam/scripts/self_check.py --model my_model

# Sigma rule for missing Annex IV artifacts (run in CI)
# Detects: PR that trains a model without Annex IV file update
title: Model trained without Annex IV update
logsource:
  product: ci
detection:
  selection:
    event_type: model_train
    annex_iv_changed: false
  condition: selection
```

## Defense Evasion Techniques

How a non-compliant provider might evade detection (for awareness, not endorsement):

1. **Cosmetic Annex IV** — generate a technically-complete Annex IV file that makes claims unsupported by actual test evidence; auditors catch this by requesting raw evidence
2. **Outdated test reports** — present last year's tests as current; mitigated by date checks + re-test requests
3. **"Continuous improvement" misdirection** — claim the model is continuously improved so individual version tests don't apply; AI Office guidance (2026-Q1) explicitly rejected this argument
4. **GPAI classification avoidance** — claim a model with 10^25 FLOPs is below the systemic-risk threshold; auditors will demand training records
5. **Borderline Annex III misclassification** — claim a hiring LLM is "assistance" not "filtering" (Annex III IV(a)); regulators have published 12 precedent rulings in 2026-Q2 narrowing this
6. **Transparency washing** — user-facing notices buried in 50-page ToS; Article 50 requires "clear and conspicuous" disclosure

## Practical Steps

> Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.

### Step 1: Classify the AI system
Run `classify.py` (Phase 1) to determine Annex III scope. If borderline, escalate to legal review.

### Step 2: Build the risk register
Use the `risk_register_template.json`; populate top-down (scenarios) and bottom-up (components).

### Step 3: Execute the test plan
For LLMs: Garak + TextAttack. For vision: Counterfit. For tabular: Aequitas + Audit-ML.

### Step 4: Generate Annex IV
Run `annex_iv.py` (Phase 4); review the generated Markdown; sign off with risk owner.

### Step 5: Submit for conformity assessment
Internal control (default): self-attest with EU declaration of conformity + CE mark. Notified Body (Article 6(3)): engage auditor.

### Step 6: Operate post-market monitoring
Establish logging per Article 12; configure serious-incident reporting pipeline (15-day deadline).

## Common Pitfalls

- **"Check-box" red teaming** — running Garak once and calling it Article 9 compliance. Auditors reject this — testing must be **per-release** and **per-change**, with documented residual risk acceptance
- **Conflating "high-risk" with "important"** — only Annex III categories count. An "important" AI for the business that isn't in Annex III is unregulated
- **GPAI threshold confusion** — the 10^25 FLOPs systemic-risk threshold (Article 51) is different from high-risk (Annex III). A model can be both, neither, or one
- **Neglecting logging design** — bolting on Article 12 logging after deployment is 10x more expensive than designing it in
- **Missing 15-day serious-incident window** — Article 73 clock starts when provider *becomes aware*, not when incident is *confirmed*. Establish a triage SLA
- **Cross-border mutual recognition assumed** — Article 60 mutual recognition exists but Member State regulators have challenged it in practice for politically sensitive deployments (e.g., law enforcement)
- **Transparency doc as afterthought** — Article 13 transparency is a deployer obligation, not just a provider one. Deployers (companies using the AI) are separately liable

## Cross-Reference to Related Skills

- `ai-safety-redteam-advanced` — technical AI red team (OWASP LLM Top 10)
- `ai-agent-security` — agent framework attacks
- `llm-red-team` — LLM-specific attacks
- `ai-fuzzing` — ML fuzzing tools
- `ci-cd-supply-chain-attack` — supply chain compliance overlap
- `secret-management-attack` — credential handling for AI systems

## Hacker Laws Alignment

- **Law 4 (Verify Everything)**: Article 9 evidence must be reproducible; trust nothing that isn't traceable to a commit hash
- **Law 7 (Documentation is Part of the System)**: Annex IV is part of the AI system, not an add-on

## References

- **EU AI Act full text**: [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
- **Implementation timeline**: [artificialintelligenceact.eu/implementation-timeline](https://artificialintelligenceact.eu/implementation-timeline/)
- **European Commission AI policy**: [digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- **Article 9 red teaming guide**: [redteampartner.com/field-notes/eu-ai-act-red-teaming-guide](https://redteampartner.com/field-notes/eu-ai-act-red-teaming-guide/)
- **A-LIGN enforcement analysis**: [a-lign.com/articles/eu-ai-act-enforcement-delay](https://www.a-lign.com/articles/eu-ai-act-enforcement-delay)
- **Garak LLM scanner**: [github.com/leondz/garak](https://github.com/leondz/garak)
- **Microsoft Counterfit**: [github.com/Azure/counterfit](https://github.com/Azure/counterfit)
- **NIST AI RMF**: [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework)
- **Mitchell et al. 2019 (Model Cards)**: [arxiv.org/abs/1810.03977](https://arxiv.org/abs/1810.03977)
- **Gebru et al. 2018 (Datasheets)**: [arxiv.org/abs/1803.09010](https://arxiv.org/abs/1803.09010)

## Attribution

This skill codifies EU AI Act compliance red team practice as of 2026-08. Regulation continues to evolve through EU implementing acts (expected late 2026) and Member State national law. Always verify against the latest EUR-Lex publication before relying on this skill for legal compliance.
