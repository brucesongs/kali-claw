# Security Decision Framework Guide

Framework for making, documenting, and reviewing security decisions. This guide covers the quantitative and qualitative methods council uses to transform multi-perspective analysis into actionable decisions.

---

## Risk-Benefit Matrix: Quantifying Security Decisions

Every security decision involves trade-offs. The risk-benefit matrix provides a structured way to evaluate options by comparing the risk reduction of each option against its cost and operational impact.

### Matrix Structure

```
                     Risk Reduction
                     Low        Medium       High
                 +------------+------------+------------+
         Low     |  Consider  |   Favor    |   Strong   |
                 |            |            |   Favor    |
Cost/     -------+------------+------------+------------+
Impact          Medium   |  Avoid     |  Acceptable|   Favor   |
                          |            |            |            |
                 -------+------------+------------+------------+
                 High    |  Reject    |  Negotiate |  Consider  |
                          |            |  Terms     |            |
                 +------------+------------+------------+
```

### Applying the Matrix

For each proposed security action, assess:

1. **Risk Reduction**: How much does this action reduce the overall risk score?
   - Low: Reduces risk score by 1-3 points
   - Medium: Reduces risk score by 4-8 points
   - High: Reduces risk score by 9+ points

2. **Cost/Impact**: What is the total cost (financial, operational, user experience)?
   - Low: Minimal budget, no user impact, less than 1 day to implement
   - Medium: Moderate budget, some user friction, 1-5 days to implement
   - High: Significant budget, major workflow change, more than 5 days to implement

### Decision Rules

| Quadrant | Action | Rationale |
|----------|--------|-----------|
| Strong Favor | Implement immediately | High risk reduction, low cost |
| Favor | Implement soon | Good return on security investment |
| Acceptable | Schedule for next cycle | Worth doing but not urgent |
| Consider | Evaluate alternatives | Low risk reduction for low cost |
| Negotiate Terms | Optimize before implementing | High value but high cost |
| Avoid | Skip this action | Low risk reduction, high cost |

### Example Evaluation

```markdown
## Option Evaluation: Deploy Web Application Firewall

**Risk Reduction**: High (reduces top finding from score 20 to 12)
**Cost/Impact**: Medium ($15K/year, no user impact, 2 days to deploy)
**Quadrant**: Favor
**Decision**: Implement in current sprint

## Option Evaluation: Rewrite Authentication System

**Risk Reduction**: High (eliminates 3 Critical findings)
**Cost/Impact**: High (3 months engineering, migration risk, user retraining)
**Quadrant**: Negotiate Terms
**Decision**: Break into phases. Phase 1 (2 weeks): add MFA and rate limiting.
Phase 2 (6 weeks): migrate to OAuth2. Phase 3 (4 weeks): deprecate legacy auth.
```

---

## Impact Analysis

Before acting on any council recommendation, analyze the broader impact of the proposed action.

### Blast Radius Assessment

For each proposed action, determine what systems, users, and processes are affected:

```markdown
## Blast Radius: [Proposed Action]

### Direct Impact
| Component | Impact Type | Severity | Reversible? |
|-----------|------------|----------|-------------|
| [System A] | [Service disruption] | [C/H/M/L] | [Yes/No] |
| [System B] | [Configuration change] | [C/H/M/L] | [Yes/No] |

### Indirect Impact
| Component | Impact Type | Likelihood |
|-----------|------------|------------|
| [System C] | [Dependency failure] | [H/M/L] |
| [Users] | [Workflow disruption] | [H/M/L] |

### Blast Radius Score: [Small/Medium/Large/Critical]
- Small: 1 system, no user impact, fully reversible
- Medium: 2-3 systems, limited user impact, reversible with effort
- Large: Multiple systems, significant user impact, partially reversible
- Critical: Organization-wide, major user impact, irreversible or costly to reverse
```

### Cascading Effects

Map how the proposed action propagates through the system:

1. **Primary effect**: The direct, intended outcome of the action
2. **Secondary effects**: Changes to dependent systems or processes
3. **Tertiary effects**: Changes to systems that depend on the secondary systems
4. **Emergent effects**: Unintended interactions between changed components

```markdown
## Cascading Effects: [Block outbound traffic from DB server]

Primary: DB server cannot send data externally (intended)
  Secondary: Reporting service cannot push reports to S3
    Tertiary: Daily automated reports fail, stakeholders miss updates
      Emergent: Stakeholders lose confidence in reporting, escalate to management
  Secondary: Monitoring agent cannot reach cloud monitoring endpoint
    Tertiary: No health metrics for DB server during incident
      Emergent: Incident response team has reduced visibility
```

Document cascading effects before taking action. For each cascade, determine whether it is acceptable, requires mitigation, or blocks the action.

---

## Degradation Planning

Every security action should include a plan for what happens if the action causes unintended problems.

### Fallback Options

For each proposed action, define:

```markdown
## Degradation Plan: [Action]

### Success Criteria
[What does "working correctly" look like? Define measurable outcomes.]

### Rollback Trigger
[What specific conditions trigger rollback? Be precise.]
- Example: "Error rate exceeds 5% for 5 consecutive minutes"
- Example: "More than 10 users report inability to access [feature]"

### Rollback Procedure
1. [Step 1: what to do immediately]
2. [Step 2: how to restore previous state]
3. [Step 3: how to verify rollback succeeded]

### Rollback Time Estimate: [minutes/hours]
### Data Loss Risk: [None/Minimal/Moderate/Significant]

### Partial Rollback Options
[Can we roll back only the problematic component while keeping other changes?]
```

### Rollback Strategy Matrix

| Action Type | Rollback Strategy | Maximum Tolerable Downtime |
|-------------|------------------|---------------------------|
| Configuration change | Revert to previous config | 5 minutes |
| Feature toggle | Disable the toggle | 1 minute |
| Infrastructure change | Blue-green or canary rollback | 10 minutes |
| Authentication change | Maintain legacy path as fallback | 15 minutes |
| Network change | Pre-staged revert rule | 5 minutes |
| Data migration | Restore from backup | 1-4 hours |

### Graceful Degradation

When full rollback is not possible, plan for graceful degradation:

1. **Reduced functionality**: Disable the affected feature while keeping the system operational
2. **Manual workaround**: Define manual processes for critical functions while automated systems recover
3. **Communication plan**: Pre-draft user communications for each degradation scenario
4. **Escalation path**: Define who to notify and in what order if degradation occurs

---

## Time-Pressure Decisions

During active incidents, council analysis must be compressed. Use this framework for rapid decision-making under time constraints.

### Triage Framework

When time is limited, use a compressed 3-tier triage:

```
TIER 1: Must decide NOW (0-5 minutes):
  - Is the attacker still active? (Contain vs. Observe)
  - Is data actively being exfiltrated? (Block vs. Monitor)
  - Are critical systems at immediate risk? (Isolate vs. Accept)

TIER 2: Must decide SOON (5-30 minutes):
  - What is the scope of compromise? (Investigate)
  - What evidence must be preserved? (Forensic priority)
  - What are the regulatory notification obligations? (Compliance clock)

TIER 3: Can decide LATER (30+ minutes):
  - Root cause analysis
  - Long-term remediation
  - Process improvements
```

### Rapid Council Protocol

Under time pressure, use this compressed version of the full council methodology:

**Minute 0-5**: Scope the immediate question. One sentence. Assign urgency tier.

**Minute 5-10**: Quick perspective pass (2 minutes each):
- Attacker: What is the adversary doing right now? What will they do next?
- Defender: What is the fastest containment action? What evidence must be preserved?
- Auditor: What are the regulatory clocks? What must be documented immediately?

**Minute 10-15**: Rapid synthesis:
- Is there agreement on the immediate action? If yes, execute.
- Is there disagreement? Escalate to the perspective with the most at stake (usually Defender for containment, Auditor for evidence, Attacker for adversary prediction).

**Minute 15+**: Execute and document in parallel. Assign one person to document while others act.

### Decision Quality Under Pressure

Accept that time-pressured decisions will have lower confidence. Explicitly state:

```markdown
## Rapid Decision Record

**Decision**: [What was decided]
**Time to Decision**: [Minutes from detection to decision]
**Confidence**: [Low/Medium] based on [X] minutes of analysis with [Y] unknowns
**Revisit Trigger**: [When should this decision be re-evaluated]
**Revisit Deadline**: [Maximum time before mandatory review]
```

Rules for time-pressured decisions:
- Prefer reversible actions over irreversible ones
- Prefer containment over observation when data loss is ongoing
- Prefer over-reaction (contain too much) over under-reaction (contain too little)
- Document decisions even if brief: a one-line decision log is better than no log

---

## Decision-Making Under Uncertainty

Security decisions are rarely made with complete information. This framework provides methods for making sound decisions when evidence is incomplete or conflicting.

### Probabilistic Thinking

Replace binary thinking (vulnerable/not vulnerable) with probabilistic assessment:

```markdown
## Probability Assessment: [Finding]

| Scenario | Probability | Impact if True | Expected Value |
|----------|-------------|---------------|----------------|
| Vulnerability is exploitable | 70% | Critical (20) | 14.0 |
| Vulnerability is not exploitable | 30% | None (0) | 0.0 |
| Expected risk | | | 14.0 (Critical) |

Action threshold: If expected value >= 10, treat as High/Critical
regardless of uncertainty.
```

### Confidence Intervals

Express uncertain findings as ranges rather than point estimates:

```markdown
## Confidence Range: [Finding]

**Risk Score Range**: 8-20
- Low estimate (8): If least severe interpretation is correct
- High estimate (20): If most severe interpretation is correct
- Best estimate (14): Weighted average based on available evidence

**Decision Rule**:
- If low estimate >= 10: Act on it (even worst case is high enough)
- If high estimate >= 15 and low estimate < 10: Investigate further
- If high estimate < 10: Low priority, document for future review
```

### Decision Without Complete Evidence

When a decision cannot wait for complete evidence:

1. **State what is known**: Document confirmed facts
2. **State what is assumed**: Document assumptions filling the evidence gaps
3. **State what is unknown**: Document open questions
4. **Choose the robust option**: Prefer the option that performs adequately across all plausible scenarios over the option that is optimal in the most likely scenario but fails in others

```markdown
## Decision Under Uncertainty: [Title]

### Known
- [Confirmed fact 1]
- [Confirmed fact 2]

### Assumed (with reasoning)
- [Assumption 1] because [reasoning]
- [Assumption 2] because [reasoning]

### Unknown (cannot determine before decision deadline)
- [Open question 1]
- [Open question 2]

### Robust Option Analysis
| Option | Best Case | Most Likely | Worst Case | Robust? |
|--------|-----------|-------------|------------|---------|
| Option A | [Outcome] | [Outcome] | [Outcome] | [Yes/No] |
| Option B | [Outcome] | [Outcome] | [Outcome] | [Yes/No] |

### Decision: [Selected option]
### Rationale: [Why this option is most robust across scenarios]
```

---

## Decision Documentation Templates

### Standard Decision Record

```markdown
# Decision Record: [Title]

## Metadata
| Field | Value |
|-------|-------|
| ID | DR-[YYYY]-[NNN] |
| Date | [YYYY-MM-DD] |
| Status | Proposed / Accepted / Rejected / Deferred |
| Decision Maker | [Name or Role] |
| Council Participants | [List perspectives that contributed] |
| Review Date | [YYYY-MM-DD] |

## Context
[What situation requires this decision? Include background, constraints, urgency.]

## Options Considered

### Option A: [Name]
- Risk Score: [score]
- Cost/Impact: [assessment]
- Risk-Benefit Quadrant: [quadrant]
- Blast Radius: [size]
- Rollback: [possible/procedure]

### Option B: [Name]
[Same structure as Option A]

## Council Analysis Summary
- Attacker recommendation: [summary]
- Defender recommendation: [summary]
- Auditor recommendation: [summary]
- Agreement points: [list]
- Disagreement points: [list]

## Decision
[Selected option and key rationale]

## Dissenting Views
[Documented disagreements with perspective attribution]

## Risk Acceptance
[Any residual risks accepted, with justification]

## Action Items
| # | Action | Owner | Deadline | Status |
|---|--------|-------|----------|--------|
| 1 | [Action] | [Owner] | [Date] | [Status] |

## Follow-Up
- Review date: [When to revisit this decision]
- Review trigger: [What events should trigger early review]
- Success metric: [How to measure if the decision was correct]
```

### Incident Decision Record (Compressed)

```markdown
# Incident Decision: [Title]

## Quick Reference
| Field | Value |
|-------|-------|
| Incident ID | INC-[YYYY]-[NNN] |
| Detection Time | [YYYY-MM-DD HH:MM UTC] |
| Decision Time | [YYYY-MM-DD HH:MM UTC] |
| Time to Decision | [X] minutes |
| Confidence | Low / Medium |

## Decision
[One-sentence decision]

## Reasoning (3 bullet points maximum)
- [Reason 1]
- [Reason 2]
- [Reason 3]

## Dissent
[Any disagreement, one sentence maximum]

## Actions Taken
1. [Action] at [HH:MM]
2. [Action] at [HH:MM]

## Revisit By
[YYYY-MM-DD HH:MM UTC] or [event trigger]
```

---

## Retrospective Analysis

After a council decision has been implemented and its outcomes observed, conduct a retrospective to improve future decision-making.

### Retrospective Template

```markdown
# Council Retrospective: [Decision Title]

## Decision Summary
| Field | Value |
|-------|-------|
| Decision ID | DR-[YYYY]-[NNN] |
| Original Date | [YYYY-MM-DD] |
| Retrospective Date | [YYYY-MM-DD] |
| Days Since Decision | [N] |

## Outcome Assessment

### Expected Outcome
[What the council predicted would happen]

### Actual Outcome
[What actually happened]

### Accuracy Assessment
| Prediction | Correct? | Delta |
|------------|----------|-------|
| [Predicted finding 1] | [Yes/No/Partial] | [How far off] |
| [Predicted risk level] | [Yes/No/Partial] | [How far off] |

## Perspective Accuracy

### Attacker Perspective
- Correct predictions: [N]
- Missed findings: [N]
- Over-estimated risks: [N]
- Accuracy score: [percentage]

### Defender Perspective
- Correct predictions: [N]
- Missed controls: [N]
- Over-estimated effectiveness: [N]
- Accuracy score: [percentage]

### Auditor Perspective
- Correct predictions: [N]
- Missed compliance gaps: [N]
- Over-estimated gaps: [N]
- Accuracy score: [percentage]

## Lessons Learned

### What worked well
1. [Success 1]
2. [Success 2]

### What could be improved
1. [Improvement 1]
2. [Improvement 2]

### Process changes for next time
1. [Change 1]
2. [Change 2]

## Decision Quality Score
| Metric | Score (1-5) |
|--------|-------------|
| Information completeness | [N] |
| Perspective coverage | [N] |
| Risk assessment accuracy | [N] |
| Speed of decision | [N] |
| Quality of documentation | [N] |
| Outcome vs. prediction | [N] |
| Overall | [average] |
```

### Retrospective Cadence

- **Critical decisions**: Retrospective within 7 days of outcome observation
- **High decisions**: Retrospective within 30 days
- **Medium decisions**: Include in quarterly review
- **Incident decisions**: Retrospective within 72 hours of incident closure

### Retrospective Repository

Maintain a log of all retrospectives. Patterns in retrospective data reveal systematic biases:

- If the Attacker perspective consistently over-estimates risk, apply a calibration discount
- If the Defender perspective consistently under-estimates attack feasibility, require stronger evidence for "control is effective" claims
- If the Auditor perspective consistently misses compliance gaps, expand the compliance checklist
- If one perspective consistently outperforms the others, study what makes it more accurate and apply those techniques to the weaker perspectives
