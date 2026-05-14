# Multi-Perspective Analysis Guide

Deep dive into the theory and practice of structured multi-perspective security analysis. This guide covers the psychological, procedural, and output aspects of council analysis.

---

## Role-Playing Framework: Defining Clear Perspective Boundaries

Effective multi-perspective analysis requires strict adherence to each role. When generating a perspective, fully commit to that mindset for the duration of that analysis phase. Do not hedge, qualify, or cross-reference other perspectives until the cross-validation phase.

### Perspective Boundaries

Each perspective has explicit boundaries that define what it considers in-scope and out-of-scope:

**Attacker Boundary**:
- In-scope: exploit paths, bypass techniques, chaining opportunities, impact maximization
- Out-of-scope: cost of controls, compliance requirements, evidence documentation
- Forbidden: "But the defender would catch this" — that is cross-validation, not attacker analysis

**Defender Boundary**:
- In-scope: control effectiveness, detection coverage, hardening priorities, cost-benefit of controls
- Out-of-scope: compliance mapping, evidence gathering for auditors
- Forbidden: "But this would violate PCI-DSS" — that is auditor territory

**Auditor Boundary**:
- In-scope: compliance mapping, evidence sufficiency, gap analysis, documentation quality
- Out-of-scope: specific exploit techniques, control implementation details
- Forbidden: "But an attacker could exploit this via SQL injection" — that is attacker territory

### Role-Commitment Protocol

Follow this protocol to maintain perspective integrity during analysis:

1. **Declare the role**: Explicitly state "Generating [Attacker/Defender/Auditor] perspective" before beginning
2. **State assumptions**: List 3-5 assumptions this perspective makes about the system
3. **Stay in character**: For the duration of this phase, reason only from this perspective
4. **Flag cross-overs**: If you notice an insight from another perspective, note it but do not develop it. Write: "Cross-over note: [observation] (belongs to [other perspective])"
5. **Close the role**: Summarize the top 3 findings from this perspective, then explicitly exit the role

### Role-Conflict Indicators

Watch for these signs that perspective boundaries are breaking down:

| Indicator | Meaning | Fix |
|-----------|---------|-----|
| Attacker suggests controls | Role contamination | Remove control suggestions, focus on exploits |
| Defender discusses exploits | Role contamination | Remove exploit details, focus on mitigations |
| Auditor evaluates technical feasibility | Scope creep | Focus on evidence, not implementation |
| All perspectives agree on everything | Insufficient separation | Re-generate with stricter boundaries |
| One perspective is much shorter | Incomplete analysis | Ensure equal depth across perspectives |

---

## Bias Mitigation

Cognitive biases distort analysis. Council explicitly identifies and mitigates the biases most dangerous to security decision-making.

### Anchoring Bias

**Definition**: Over-relying on the first piece of information encountered. In security, this often manifests as fixating on the first vulnerability found and evaluating all subsequent findings relative to it.

**Impact on security analysis**:
- The first vulnerability discovered sets the tone for the entire assessment
- Subsequent findings are underrated ("not as bad as the first one")
- Remediation prioritization is distorted by discovery order

**Mitigation in council**:
- Generate all three perspectives independently before comparing
- Use the risk scoring matrix (Impact x Likelihood) for objective comparison
- Explicitly ask: "If I had found this vulnerability first, would I rate it differently?"
- Rotate the order of perspective generation across analyses

**Exercise**: After completing an analysis, reorder the findings from lowest to highest risk score. Does the prioritization feel different? If yes, anchoring bias was present.

### Confirmation Bias

**Definition**: Seeking or interpreting evidence in ways that confirm pre-existing beliefs. In security, this manifests as finding what you expect to find and dismissing contradictory evidence.

**Impact on security analysis**:
- Attacker confirms expected attack paths but misses unconventional ones
- Defender confirms controls are working but misses gaps
- Auditor confirms compliance but misses implementation drift

**Mitigation in council**:
- Each perspective must explicitly state one finding that contradicts its expected outcome
- Cross-validation phase is specifically designed to challenge assumptions
- Require evidence for every claim — "I believe X because I observed Y"
- Ask: "What evidence would make me change my mind?" If none, confirmation bias is active

**Exercise**: Before starting analysis, write down the expected top finding. After analysis, compare. If they match exactly, investigate whether the finding was genuinely the top risk or whether it was confirmation bias.

### Availability Heuristic

**Definition**: Overweighting information that is easily recalled (recent, vivid, or emotionally charged). In security, this manifests as over-focusing on recent CVEs, high-profile breaches, or personally experienced incidents.

**Impact on security analysis**:
- Recent CVEs get disproportionate attention regardless of actual applicability
- Techniques the analyst has used successfully before are over-represented
- Novel or less-publicized attack vectors are under-explored

**Mitigation in council**:
- Use structured checklists (attacker/defender/auditor) to ensure comprehensive coverage
- Reference frameworks (OWASP Top 10, MITRE ATT&CK, CIS Controls) rather than memory
- Require each perspective to include at least one "non-obvious" finding
- Ask: "Am I focusing on this because it is the biggest risk, or because it is the most memorable?"

**Exercise**: After generating the attacker perspective, check it against the MITRE ATT&CK matrix. Are there techniques in the relevant tactic columns that were not considered? Those omissions may indicate availability heuristic.

### Authority Bias

**Definition**: Overweighting opinions from perceived authority figures. In council analysis, this can manifest as the first-perspective-generated being treated as authoritative.

**Mitigation in council**:
- Generate perspectives sequentially but do not re-read earlier perspectives when generating later ones
- Weight findings by evidence quality, not by which perspective produced them
- Rotate which perspective is generated first across different analyses
- Ensure cross-validation challenges all perspectives equally

---

## Dissent Encouragement

Dissent is not disagreement for its own sake. It is the structured identification of weaknesses in the dominant analysis. Council treats dissent as a first-class output, not an afterthought.

### Structured Disagreement Protocol

Follow this protocol when a perspective disagrees with another perspective's finding:

1. **State the disputed finding**: Quote the specific finding being disputed
2. **State the dissenting position**: Clearly state the alternative view
3. **Provide evidence**: What evidence supports the dissenting position?
4. **Assess impact**: If the dissenting position is correct, how does it change the recommendation?
5. **Propose resolution**: What additional information would resolve the disagreement?

### Dissent Format

```markdown
## Dissent Record

**Disputed Finding**: [Quote the finding from another perspective]
**Dissenting Perspective**: [Which perspective disagrees]
**Dissenting Position**: [Alternative view]
**Evidence**: [Supporting evidence for the dissent]
**Impact if Correct**: [How recommendation changes]
**Resolution Method**: [What would settle this disagreement]
**Priority**: [Blocking / Non-blocking]
```

### "Red Team the Red Team"

After generating all three perspectives, perform a meta-analysis:

- Challenge the attacker perspective: "What if the attacker is wrong about the easiest path?"
- Challenge the defender perspective: "What if the controls are less effective than assumed?"
- Challenge the auditor perspective: "What if compliance does not equal security?"

This meta-analysis surfaces blind spots that individual perspectives cannot see from within their own framework.

### When Dissent Should Block a Decision

Dissent is blocking when:
- It challenges the severity classification of the top finding
- It identifies a completely unconsidered attack path or control gap
- It reveals a compliance violation that affects legal or regulatory standing
- It contradicts the fundamental assumption underlying the analysis

Dissent is non-blocking when:
- It represents a difference in risk appetite between perspectives
- It concerns the priority order of medium or low findings
- It identifies an area for further investigation that does not change the immediate decision

---

## Consensus Building

Consensus does not mean unanimity. It means that all perspectives have been heard, their positions documented, and a decision made with clear understanding of disagreements.

### Finding Common Ground

After cross-validation, identify agreement points first:

1. **List all findings where all three perspectives agree** — these have the highest confidence
2. **List findings where two of three agree** — these have moderate confidence
3. **List findings where perspectives disagree** — these need resolution or documented acceptance

### Confidence-Weighted Synthesis

When perspectives disagree on severity or priority:

```
Final Score = weighted average of perspective scores

Weight distribution:
- If evidence supports one perspective more heavily: that perspective gets 2x weight
- If evidence is equal: all perspectives weighted equally (1x)
- If a perspective's finding is self-serving (e.g., attacker rates everything Critical):
  apply skepticism discount
```

### Documenting Disagreements

Every disagreement must be documented, even if it does not block the decision:

```markdown
## Unresolved Disagreement

**Finding**: [What is being debated]
**Perspective A Position**: [Position and reasoning]
**Perspective B Position**: [Position and reasoning]
**Evidence For A**: [Supporting evidence]
**Evidence For B**: [Supporting evidence]
**Decision**: [Which position was adopted and why]
**Dissenting Note**: [Position not adopted, preserved for record]
**Revisit Condition**: [When should this disagreement be re-evaluated]
```

### Escalation Criteria

Escalate a disagreement when:
- It cannot be resolved with available evidence
- The disagreement affects a Critical or High severity finding
- The disagreement involves legal, regulatory, or ethical considerations
- The decision has irreversible consequences (e.g., public disclosure, system shutdown)

---

## Output Formatting

Council produces structured decision documents with clear perspective attribution. Every finding, recommendation, and action item is attributed to the perspective that produced it.

### Standard Output Structure

```markdown
# Council Decision: [Title]

## Executive Summary
[2-3 sentence summary of the decision and key recommendation]

## Scope
[What was analyzed, boundaries, constraints]

## Findings by Perspective

### Attacker Findings
| # | Finding | Severity | Evidence | Confidence |
|---|---------|----------|----------|------------|
| A-1 | [Finding] | [C/H/M/L/I] | [Source] | [H/M/L] |

### Defender Findings
| # | Finding | Severity | Evidence | Confidence |
|---|---------|----------|----------|------------|
| D-1 | [Finding] | [C/H/M/L/I] | [Source] | [H/M/L] |

### Auditor Findings
| # | Finding | Severity | Evidence | Confidence |
|---|---------|----------|----------|------------|
| U-1 | [Finding] | [C/H/M/L/I] | [Source] | [H/M/L] |

## Cross-Validation Results

### Agreement Points
[Finding IDs from different perspectives that agree]

### Disagreement Points
[Finding IDs that contradict, with resolution status]

### Unique Findings
[Finding IDs that only one perspective identified]

## Recommendation
[Primary recommendation with supporting evidence from all perspectives]

## Dissenting Views
[Any documented dissents with attribution]

## Action Items
| # | Action | Priority | Owner | Deadline | Source Finding |
|---|--------|----------|-------|----------|---------------|
| 1 | [Action] | [C/H/M/L] | [Owner] | [Date] | [A-1, D-2] |

## Confidence Assessment
| Aspect | Confidence | Reasoning |
|--------|-----------|-----------|
| Overall | [H/M/L] | [Why] |
| Top Finding | [H/M/L] | [Why] |
| Recommendation | [H/M/L] | [Why] |
```

### Attribution Rules

- Every finding is prefixed with its source perspective (A- for Attacker, D- for Defender, U- for Auditor)
- Recommendations reference the finding IDs that support them (e.g., "Supported by A-1, D-3, U-2")
- Dissenting views reference the perspective and finding ID being disputed

---

## Common Pitfalls

### Groupthink

**Symptom**: All perspectives converge too quickly, producing similar findings with similar severity ratings.

**Detection**: If the three perspectives produce identical top-3 findings with identical severity, groupthink is likely.

**Fix**: Enforce stricter perspective boundaries. Require each perspective to include at least one finding that the others would not naturally produce. Use the "Red Team the Red Team" meta-analysis.

### Authority Bias

**Symptom**: The first perspective generated sets the framing for all subsequent perspectives. Later perspectives echo or react to the first rather than producing independent analysis.

**Detection**: Compare the language and framing of the three perspectives. If Perspective 2 and 3 reference Perspective 1's terminology or structure, they are contaminated.

**Fix**: Generate each perspective without re-reading previous ones. Use a "blind" generation process where each perspective only receives the scope definition, not other perspectives' outputs.

### False Consensus

**Symptom**: Apparent agreement that masks underlying disagreement. Perspectives appear to agree because they use similar language, but mean different things.

**Detection**: When all perspectives "agree" on a finding but describe it differently in their detail sections, false consensus is present.

**Fix**: Require each perspective to define key terms explicitly. When agreement is identified, verify that the three perspectives are describing the same thing in the same way.

### Analysis Paralysis

**Symptom**: Cross-validation and consensus building continue indefinitely without producing a decision. Every finding spawns additional investigation.

**Detection**: If Phase 3 (Cross-Validation) takes longer than Phase 2 (Perspective Generation), analysis paralysis is setting in.

**Fix**: Set explicit timeboxes for each phase. Use the "Quick Start Checklist" from payloads.md for time-constrained analyses. Accept that some open questions will remain and document them for follow-up rather than blocking the decision.

### Single-Dominant Perspective

**Symptom**: One perspective produces significantly more findings or higher-severity ratings than the others, dominating the final recommendation.

**Detection**: Count findings and severity distribution per perspective. If one perspective accounts for more than 50% of Critical/High findings, it may be dominating.

**Fix**: Ensure equal analytical effort per perspective. Verify that the dominant perspective is not simply being more thorough (which is good) but is instead inflating severity (which is bad). Apply the risk scoring matrix objectively to verify ratings.

### Neglecting the Auditor Perspective

**Symptom**: Auditor findings are treated as "paperwork" rather than genuine risks. Compliance gaps are deprioritized in favor of technical findings.

**Detection**: If all auditor findings are classified as Medium or below regardless of actual compliance impact, the perspective is being undervalued.

**Fix**: Remember that compliance failures can have financial penalties, legal consequences, and reputational impact equal to or greater than technical vulnerabilities. A GDPR fine can exceed the cost of a data breach. Treat compliance findings with the same rigor as technical findings.
