# EU AI Act Article 9 — Deep Dive

> Clause-by-clause analysis of Article 9 (Risk Management System) of EU Regulation 2024/1689. Each clause mapped to testable evidence requirements.

## Article 9 Structure

Article 9 has 11 sub-clauses organized into 3 themes:

```
Article 9 — Risk Management System
├── 9(1)-(3) Risk management system scope
├── 9(4)-(7) Risk identification, estimation, evaluation
└── 9(8)-(11) Risk mitigation, testing, post-market
```

---

## Clause-by-Clause Analysis

### Article 9(1) — Risk Management System Required

> "A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems."

**Testable requirements**:
- Documented risk management process (procedure document)
- Designated risk owner per high-risk system
- Risk management covers entire lifecycle (design → post-market)

**Evidence for Annex IV §2(g)**:
- Risk management procedure document (template: `templates/risk_management_procedure.md`)
- Risk owner assignment record
- Lifecycle phase map showing risk activities

**Common audit failure**: Generic risk procedure that doesn't reference the specific AI system

---

### Article 9(2)(a) — Known and Foreseeable Risks

> "The risks referred to in paragraph 1 [shall include] known and the reasonably foreseeable risks that the high-risk AI system can pose to the health, safety or fundamental rights of natural persons..."

**Testable requirements**:
- Risk identification includes both "known" (literature-based) and "foreseeable" (scenario-based)
- Risks cover health, safety, AND fundamental rights (not just safety)
- Risks tied to specific use context (deployer scenario)

**Evidence**:
- Risk register with both `category: known` and `category: foreseeable` entries
- Each risk references specific scenario (e.g., "Resume ranking for senior engineer roles")
- Fundamental-rights risk included (e.g., discrimination risk)

**Common audit failure**: Only safety risks; missing fundamental rights dimension

---

### Article 9(2)(b) — Population Group Variations

> "...estimation and evaluation of risks ... considering ... possible biases of the high-risk AI system in particular as regards ... performance of the system ... across different population groups..."

**Testable requirements**:
- Bias testing across demographic groups (gender, age, ethnicity, nationality, disability)
- Disparate impact analysis (rate ratio ≥ 0.8)
- Documented population group definitions

**Evidence**:
- Aequitas / Fairlearn report per protected attribute
- Per-group performance metrics
- Acceptance criteria documented (e.g., "disparate impact ≥ 0.8")

**Common audit failure**: Treating "non-EU" as a single group; missing sub-group analysis

---

### Article 9(2)(c) — Distribution Mismatch

> "...[considering] distribution of the high-risk AI system ... [and] change[s] over time..."

**Testable requirements**:
- Distribution-shift detection (training vs production)
- Concept drift monitoring
- Retraining trigger conditions documented

**Evidence**:
- Production telemetry dashboard
- Drift detection alert thresholds
- Retraining decision log

---

### Article 9(3) — Reasonably Foreseeable Misuse

> "Risks ... shall be ... [those] of reasonably foreseeable misuse"

**Testable requirements**:
- Misuse scenario brainstorming session (documented)
- Misuse risks in register (e.g., "deployed for non-engineering roles without retraining")
- Mitigations (e.g., "out-of-scope declaration in user documentation")

**Evidence**:
- Misuse brainstorm session minutes
- Risk register entries with `category: foreseeable_misuse`

---

### Article 9(4) — Risk Estimation & Evaluation

> "Risks shall be ... [estimated and evaluated] taking into consideration ... impact on ..."

**Testable requirements**:
- Quantified risk (severity × likelihood)
- Impact categories: individual harm, societal harm, fundamental rights violation
- Risk matrix (e.g., 5×5 with acceptance thresholds)

**Evidence**:
- Risk register with severity + likelihood
- Risk matrix definition (template: `templates/risk_matrix.md`)

---

### Article 9(5)-(6) — Risk Mitigation Design

> "Risk mitigation measures ... shall give priority to ... inherently safe design measures"

**Testable requirements**:
- Mitigation hierarchy followed: inherent > technical > operational > informative
- Inherent design justifications documented (why can't the risk be designed out?)
- Residual risk explicit + accepted by owner

**Evidence**:
- Risk register: each risk has `mitigation_type: inherent|technical|operational|informative`
- Residual risk acceptance record (signoff)

---

### Article 9(7) — Testing for Purpose & Cross-Environment

> "...shall be tested ... for the purposes of ... checking whether [the system] ... continues to ... perform as intended ... [in] environment(s) different from the one in which [it was developed]"

**Testable requirements**:
- Testing in production-like environment (not just dev/staging)
- Testing across deployment contexts (different Member States, different deployer types)
- Cross-environment reproducibility

**Evidence**:
- Test plan with environment matrix
- Test runs in each environment (separate evidence files)

---

### Article 9(8) — Procedures for Testing

> "Testing ... shall be performed ... in accordance with ... previously defined ... [procedures]"

**Testable requirements**:
- Documented test procedures (not ad-hoc)
- Test procedures versioned
- Test results reproducible (commit hash, seed, environment)

**Evidence**:
- Test procedure documents (one per test suite)
- Reproducibility metadata in evidence files

---

### Article 9(9) — Outcomes Decision

> "Outcomes of the testing ... shall ... result in ... a decision: (a) the system ... [complies]; (b) ... [needs modification]; (c) ... [does not meet objectives]"

**Testable requirements**:
- Decision recorded per test run
- Decision links to next action (release / modify / reject)
- Decision-maker identified

**Evidence**:
- Test report with explicit decision field
- Sign-off chain (test lead → release manager)

---

### Article 9(10) — Comprehensive Post-Market Testing

> "...post-market monitoring system referred to in Article 72 shall ... [include testing] ... against relevant predetermined metrics"

**Testable requirements**:
- Predetermined metrics defined (precision, recall, disparate impact, etc.)
- Post-market test cadence (e.g., weekly drift check, quarterly retest)
- Drift-triggered retest

**Evidence**:
- Post-market test plan
- Monitoring dashboard
- Retraining decision log

---

### Article 9(11) — Frequency of Testing

> "Testing ... shall be carried out periodically throughout the lifecycle, and before being placed on the market or put into service"

**Testable requirements**:
- Test cadence documented (per-release, per-change, quarterly, etc.)
- Pre-market test gate enforced
- Cadence varies by risk severity (high-severity risks = more frequent)

**Evidence**:
- Test cadence policy document
- Pre-market test gate (CI rule)
- Per-risk cadence in risk register

---

## Common Article 9 Findings (Auditor Perspective)

1. **Generic risk procedure** — risk management document doesn't reference the specific AI system
2. **Missing fundamental rights risk** — only safety risks captured
3. **No misuse scenario brainstorm** — foreseeable misuse risks absent
4. **Population groups too coarse** — "non-EU" as single group misses sub-group disparities
5. **Test cadence underspecified** — "annually" without quarterly retest for high-severity risks
6. **Cross-environment testing skipped** — only tested in dev environment
7. **Decision field absent** — test reports list findings but no (a)/(b)/(c) decision
8. **No retest on change** — model updated without retest; previous Article 9 evidence invalidated

---

## Article 9 ↔ Other Articles Cross-Walk

| Article 9 clause | Cross-references |
|------------------|-----------------|
| 9(1) Risk system | Art.17 (QMS), Annex IV §2(g) |
| 9(2)(a) Known risks | Art.10 (data gov), Art.15 (robustness) |
| 9(2)(b) Population groups | Art.10(3) (bias mitigation) |
| 9(2)(c) Distribution | Art.72 (post-market) |
| 9(3) Foreseeable misuse | Art.26 (deployer obligations) |
| 9(4)-(6) Mitigation | Art.13 (transparency), Art.14 (oversight) |
| 9(7) Cross-environment | Art.72 (post-market) |
| 9(8) Test procedures | Annex IV §2(f) (logging) |
| 9(9) Decision | Annex IV §2(h) (changes) |
| 9(10) Post-market metrics | Art.72 |
| 9(11) Test frequency | Annex IV §2(h) |

---

## Practical Implementation Checklist

For a high-risk AI system going through Article 9 compliance:

- [ ] Risk management procedure documented (system-specific, not generic)
- [ ] Risk owner designated
- [ ] Risk register populated with known + foreseeable + misuse categories
- [ ] Population group bias tests run (Aequitas)
- [ ] Robustness tests run (Garak + TextAttack)
- [ ] Test cadence policy documented
- [ ] Test procedures versioned
- [ ] Pre-market test gate enforced (CI rule)
- [ ] Cross-environment testing completed
- [ ] Test decisions recorded per run
- [ ] Post-market monitoring deployed
- [ ] Drift detection + retraining triggers configured
- [ ] Article 73 serious-incident reporting pipeline ready (15-day deadline)
- [ ] Annex IV §2(g) section populated with risk register reference
- [ ] Annex IV §2(f) logging fields include all Article 12 events

Each checklist item maps to specific evidence in the Annex IV technical file.

---

## References

- **EU AI Act Article 9 full text**: [eur-lex.europa.eu](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) — search for "Article 9"
- **Annex IV**: same Regulation, Annex IV (technical documentation)
- **EDPB-EDPS Joint Opinion on AI Act**: provides interpretive guidance
- **AI Office implementing acts (expected late 2026)**: will provide further details on Article 9 implementation

---

## Maintenance

- This guide reflects Article 9 interpretation as of 2026-08
- Implementing acts expected Q4 2026 / Q1 2027 may require updates
- Update `last_reviewed` in SKILL.md frontmatter when this guide is revised
