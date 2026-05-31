# Council Payloads

Analysis templates, checklists, and decision frameworks for multi-perspective security analysis.

---

## Attacker Perspective Checklist

Use this checklist when generating the attacker viewpoint for any security question.

### Attack Surface Mapping

- [ ] Identify all entry points (network, application, physical, social)
- [ ] Map trust boundaries and data flows between components
- [ ] Catalog exposed services, APIs, and endpoints
- [ ] Identify third-party integrations and supply chain dependencies
- [ ] Document all user roles and their privilege levels
- [ ] Locate admin panels, debug endpoints, and management interfaces

### Entry Point Identification

- [ ] Test authentication mechanisms for bypass opportunities
- [ ] Analyze input validation on all user-controlled data paths
- [ ] Identify file upload functionality and processing pipelines
- [ ] Map deserialization points and object instantiation flows
- [ ] Locate inter-service communication channels (API calls, message queues)
- [ ] Find forgotten or legacy endpoints not covered by current controls

### Exploit Chain Construction

- [ ] Identify individual vulnerabilities and their preconditions
- [ ] Map dependencies between vulnerabilities (A enables B)
- [ ] Construct exploit chains from low-privilege to high-impact
- [ ] Evaluate stealth requirements and detection risk for each step
- [ ] Identify fallback paths if primary chain is blocked
- [ ] Document estimated effort and skill required for each chain

### Impact Maximization

- [ ] Determine the highest-impact asset reachable from each entry point
- [ ] Evaluate lateral movement opportunities post-compromise
- [ ] Assess data exfiltration paths and bandwidth
- [ ] Identify persistence mechanisms available post-exploitation
- [ ] Calculate blast radius for each successful exploit chain
- [ ] Map business impact (revenue, reputation, regulatory consequences)

---

## Defender Perspective Checklist

Use this checklist when generating the defender viewpoint for any security question.

### Asset Inventory

- [ ] Catalog all assets (data, systems, services, credentials)
- [ ] Classify assets by business criticality and sensitivity
- [ ] Map data flows and identify where sensitive data resides
- [ ] Document asset owners and responsible parties
- [ ] Identify shadow IT and unmanaged assets
- [ ] Verify asset inventory is current (no stale entries)

### Control Mapping

- [ ] Map preventive controls to each identified attack path
- [ ] Map detective controls to each identified attack path
- [ ] Map corrective controls to each identified attack path
- [ ] Verify defense-in-depth (multiple controls per critical path)
- [ ] Identify single points of failure in the control architecture
- [ ] Validate control effectiveness (not just presence)

### Detection Gaps

- [ ] Identify attack paths with no detective controls
- [ ] Evaluate log coverage for critical systems and data flows
- [ ] Verify alerting rules cover known attack patterns
- [ ] Test incident response procedures for realistic scenarios
- [ ] Assess mean time to detect (MTTD) for critical attack paths
- [ ] Evaluate blind spots in network and application monitoring

### Hardening Priorities

- [ ] Rank hardening actions by risk reduction per effort unit
- [ ] Identify quick wins (high impact, low effort)
- [ ] Prioritize internet-facing hardening over internal
- [ ] Validate patch management coverage for critical systems
- [ ] Review configuration baselines against CIS or vendor benchmarks
- [ ] Ensure credential hygiene (rotation, complexity, MFA coverage)

---

## Auditor Perspective Checklist

Use this checklist when generating the auditor viewpoint for any security question.

### Compliance Mapping

- [ ] Identify applicable regulatory requirements (GDPR, PCI-DSS, HIPAA, SOC 2)
- [ ] Map each requirement to implemented controls
- [ ] Identify requirements without corresponding controls (gaps)
- [ ] Verify control documentation is complete and current
- [ ] Validate that policy matches actual implementation
- [ ] Check for cross-jurisdictional compliance requirements

### Evidence Requirements

- [ ] Determine what evidence is needed for each control
- [ ] Verify evidence is being collected and retained appropriately
- [ ] Check evidence integrity and chain of custody procedures
- [ ] Validate that evidence covers the full review period
- [ ] Ensure automated evidence collection where possible
- [ ] Document gaps where evidence is manual or inconsistent

### Gap Analysis

- [ ] Compare current state against framework requirements
- [ ] Categorize gaps: missing controls, partially implemented, misconfigured
- [ ] Assess risk of each gap using the risk scoring matrix
- [ ] Identify compensating controls for documented gaps
- [ ] Prioritize remediation by gap severity and compliance deadline
- [ ] Document risk acceptance decisions with business justification

### Remediation Tracking

- [ ] Create remediation plan with owners, deadlines, and verification criteria
- [ ] Assign each remediation item to a responsible party
- [ ] Define clear acceptance criteria for each remediation
- [ ] Establish progress tracking and reporting cadence
- [ ] Plan re-testing to verify remediation effectiveness
- [ ] Document any exceptions with time-bound acceptance and reassessment dates

---

## Risk Scoring Matrix Template

Use this matrix to score and prioritize findings from the council analysis.

### Scoring Guide

**Impact Scale (1-5)**:

| Score | Label | Description |
|-------|-------|-------------|
| 5 | Critical | Complete system compromise, data breach, regulatory violation with fines |
| 4 | Major | Significant data exposure, extended service disruption, partial compliance failure |
| 3 | Moderate | Limited data exposure, brief service impact, minor compliance gap |
| 2 | Minor | No direct data exposure, detectable but recoverable, cosmetic compliance issue |
| 1 | Negligible | Informational, no operational impact, documentation improvement |

**Likelihood Scale (1-5)**:

| Score | Label | Description |
|-------|-------|-------------|
| 5 | Certain | Actively being exploited, publicly known exploit exists, no controls present |
| 4 | Likely | Known vulnerability, exploit available, limited controls in place |
| 3 | Possible | Vulnerability exists, exploit feasible, some controls present |
| 2 | Unlikely | Vulnerability exists, exploit difficult, multiple controls in place |
| 1 | Rare | Theoretical vulnerability, no known exploit, strong defense in depth |

### Risk Score Calculation

```
Risk Score = Impact x Likelihood

Critical: 15-25  -> Immediate remediation
High:     10-14  -> Priority remediation within 72 hours
Medium:    5-9   -> Scheduled remediation within 30 days
Low:       3-4   -> Backlog, remediate within 90 days
Info:      1-2   -> Document only, no remediation required
```

### Example Risk Register Entry

```markdown
| ID | Finding | Perspective | Impact | Likelihood | Score | Severity | Owner | Status |
|----|---------|-------------|--------|------------|-------|----------|-------|--------|
| R-001 | SQL injection in search API | Attacker | 5 | 4 | 20 | Critical | API Team | Open |
| R-002 | No WAF on public endpoints | Defender | 4 | 3 | 12 | High | Infra Team | In Progress |
| R-003 | PCI-DSS gap in logging | Auditor | 4 | 5 | 20 | Critical | SecOps | Open |
| R-004 | CSP header missing on login | Attacker | 3 | 3 | 9 | Medium | Frontend | Planned |
| R-005 | Exception documentation outdated | Auditor | 2 | 2 | 4 | Low | GRC Team | Open |
```

---

## Decision Record Template

Document every council decision for traceability and retrospective analysis.

```markdown
# Decision Record: [Title]

## Metadata

| Field | Value |
|-------|-------|
| Decision ID | DR-[YYYY]-[NNN] |
| Date | [YYYY-MM-DD] |
| Status | Proposed / Accepted / Rejected / Deferred |
| Decision Maker | [Name or Role] |
| Review Date | [YYYY-MM-DD] |

## Context

[What is the situation that requires a decision? Include relevant background,
constraints, and urgency level.]

## Options Analyzed

### Option A: [Name]
- **Attacker View**: [How does this option look from an exploit perspective?]
- **Defender View**: [How does this option look from a hardening perspective?]
- **Auditor View**: [How does this option look from a compliance perspective?]
- **Risk Score**: [Impact x Likelihood for this option]

### Option B: [Name]
- **Attacker View**: [Assessment]
- **Defender View**: [Assessment]
- **Auditor View**: [Assessment]
- **Risk Score**: [Score]

### Option C: [Name]
- **Attacker View**: [Assessment]
- **Defender View**: [Assessment]
- **Auditor View**: [Assessment]
- **Risk Score**: [Score]

## Recommendation

[Selected option with supporting evidence from all three perspectives.]

## Rationale

[Why this option was chosen over alternatives, citing specific perspective
analysis and cross-validation findings.]

## Dissenting Views

[Document any disagreements between perspectives, with reasoning from
each side. Include the perspective attribution for each dissent.]

## Risk Acceptance

[Any risks accepted by choosing this option, with explicit justification
and conditions under which the decision should be revisited.]

## Follow-Up Actions

- [ ] [Action 1] - Owner: [name], Deadline: [date]
- [ ] [Action 2] - Owner: [name], Deadline: [date]
- [ ] Verification: [how to confirm the decision was effective]
```

---

## Consensus Building Templates

### Agreement Points Template

```markdown
## Consensus: Agreed Points

| # | Point | Attacker Confidence | Defender Confidence | Auditor Confidence |
|---|-------|--------------------|--------------------|--------------------|
| 1 | [Agreed finding] | [High/Med/Low] | [High/Med/Low] | [High/Med/Low] |
| 2 | [Agreed finding] | [High/Med/Low] | [High/Med/Low] | [High/Med/Low] |
| 3 | [Agreed finding] | [High/Med/Low] | [High/Med/Low] | [High/Med/Low] |

**Strongest Agreement**: [Point with highest confidence across all perspectives]
**Action**: [What should be done based on this agreement]
```

### Disagreement Points Template

```markdown
## Consensus: Disagreed Points

| # | Point | Attacker Position | Defender Position | Auditor Position | Resolution |
|---|-------|-------------------|-------------------|------------------|------------|
| 1 | [Disputed finding] | [Position + reason] | [Position + reason] | [Position + reason] | [How resolved] |
| 2 | [Disputed finding] | [Position + reason] | [Position + reason] | [Position + reason] | [How resolved] |

**Key Disagreement**: [Most significant disputed point]
**Impact on Decision**: [How does this disagreement affect the recommendation]
**Escalation Needed**: [Yes/No, and why]
```

### Open Questions Template

```markdown
## Consensus: Open Questions

| # | Question | Blocking? | Needed By | Investigation Method |
|---|----------|-----------|-----------|---------------------|
| 1 | [Unresolved question] | Yes/No | [Date] | [How to investigate] |
| 2 | [Unresolved question] | Yes/No | [Date] | [How to investigate] |
| 3 | [Unresolved question] | Yes/No | [Date] | [How to investigate] |

**Decision Without Full Consensus**: [Can a decision be made now, or must
these questions be resolved first? Justify.]
```

---

## Quick Start Checklist

Use this condensed checklist for rapid council analysis when time is limited.

### Setup (5 minutes)

- [ ] Define the specific security question in one sentence
- [ ] Identify the system(s) and data in scope
- [ ] Note any compliance requirements that apply
- [ ] Set a time budget for the analysis

### Attacker Quick Pass (10 minutes)

- [ ] Top 3 most likely attack paths
- [ ] Highest-impact exploit chain
- [ ] Biggest assumption an attacker would exploit
- [ ] One finding the defender might be missing

### Defender Quick Pass (10 minutes)

- [ ] Top 3 most critical controls and their status
- [ ] Biggest detection gap
- [ ] Quickest hardening win
- [ ] One finding the attacker might be overestimating

### Auditor Quick Pass (10 minutes)

- [ ] Top compliance requirement at risk
- [ ] Biggest evidence gap
- [ ] Most urgent remediation item
- [ ] One finding both attacker and defender might be overlooking

### Synthesis (10 minutes)

- [ ] Areas where all three perspectives agree (high confidence)
- [ ] Areas where perspectives disagree (needs investigation)
- [ ] Open questions that block a decision
- [ ] Recommended action with confidence level (High/Medium/Low)

### Output

```markdown
# Quick Council Decision

**Question**: [One-sentence security question]
**Recommendation**: [Recommended action]
**Confidence**: [High/Medium/Low]
**Key Agreement**: [What all perspectives agree on]
**Key Disagreement**: [What perspectives disagree on]
**Next Step**: [Immediate action to take]
```

---

## Structured Decision Schemas

### Council Session JSON Schema

```json
{
  "session_id": "council-2026-05-29-001",
  "question": "Is the API gateway adequately secured against credential stuffing?",
  "scope": {
    "systems": ["api-gateway", "auth-service", "rate-limiter"],
    "compliance": ["SOC2-CC6", "NIST-800-53-AC"],
    "time_budget_minutes": 45
  },
  "perspectives": {
    "attacker": {"status": "complete", "findings": 4, "top_risk": "credential stuffing via distributed IPs"},
    "defender": {"status": "complete", "findings": 3, "top_risk": "rate limiter bypass via header spoofing"},
    "auditor": {"status": "complete", "findings": 2, "top_risk": "missing MFA enforcement documentation"}
  },
  "consensus": {
    "agreed": ["rate limiting insufficient", "MFA not enforced for API access"],
    "disagreed": ["severity of header spoofing bypass"],
    "confidence": 0.8,
    "recommendation": "Deploy distributed rate limiting + enforce MFA on sensitive endpoints"
  }
}
```

### Finding Schema

```json
{
  "finding_id": "F-001",
  "perspective": "attacker",
  "title": "Rate limiter bypass via X-Forwarded-For rotation",
  "description": "Attacker can rotate X-Forwarded-For headers to bypass IP-based rate limiting",
  "impact": 4,
  "likelihood": 4,
  "risk_score": 16,
  "severity": "Critical",
  "evidence": "Tested with 1000 requests using unique X-Forwarded-For values, all succeeded",
  "recommendation": "Implement rate limiting on authenticated session, not source IP",
  "cross_validated_by": ["defender"],
  "disputed_by": []
}
```

### Perspective Comparison Schema

```json
{
  "comparison_id": "CMP-001",
  "finding": "SQL injection in search endpoint",
  "perspectives": {
    "attacker": {
      "severity": "Critical",
      "reasoning": "Unauthenticated, full DB access, exploit chain to RCE via xp_cmdshell",
      "confidence": 0.95
    },
    "defender": {
      "severity": "High",
      "reasoning": "Parameterized queries on 90% of endpoints, this is an outlier",
      "confidence": 0.80
    },
    "auditor": {
      "severity": "Critical",
      "reasoning": "PCI-DSS Req 6.5.1 violation, audit finding regardless of exploitability",
      "confidence": 0.90
    }
  },
  "resolution": {
    "final_severity": "Critical",
    "method": "majority_vote",
    "rationale": "2/3 perspectives rate Critical, compliance requirement makes it non-negotiable"
  }
}
```

---

## Automated Council Scripts

### Multi-Perspective Analysis Runner

```python
import json
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    id: str
    perspective: str
    title: str
    impact: int
    likelihood: int
    evidence: str
    recommendation: str

    @property
    def risk_score(self):
        return self.impact * self.likelihood

    @property
    def severity(self):
        score = self.risk_score
        if score >= 15: return "Critical"
        if score >= 10: return "High"
        if score >= 5: return "Medium"
        return "Low"

def run_council(question, findings):
    by_perspective = {}
    for f in findings:
        by_perspective.setdefault(f.perspective, []).append(f)

    agreements = []
    disagreements = []

    titles = set(f.title for f in findings)
    for title in titles:
        related = [f for f in findings if f.title == title]
        severities = set(f.severity for f in related)
        if len(severities) == 1:
            agreements.append({"title": title, "severity": related[0].severity})
        else:
            disagreements.append({
                "title": title,
                "positions": {f.perspective: f.severity for f in related}
            })

    return {
        "question": question,
        "total_findings": len(findings),
        "by_perspective": {k: len(v) for k, v in by_perspective.items()},
        "agreements": agreements,
        "disagreements": disagreements,
        "confidence": len(agreements) / max(len(titles), 1)
    }
```

### Risk Score Calculator

```python
def calculate_risk_matrix(findings):
    matrix = {}
    for f in findings:
        key = (f.impact, f.likelihood)
        matrix.setdefault(key, []).append(f)

    print("Risk Matrix (Impact x Likelihood):")
    print("     L=1  L=2  L=3  L=4  L=5")
    for impact in range(5, 0, -1):
        row = f"I={impact} "
        for likelihood in range(1, 6):
            count = len(matrix.get((impact, likelihood), []))
            cell = f" {count:2d} " if count else "  . "
            row += cell
        print(row)

    critical = [f for f in findings if f.risk_score >= 15]
    high = [f for f in findings if 10 <= f.risk_score < 15]
    medium = [f for f in findings if 5 <= f.risk_score < 10]
    low = [f for f in findings if f.risk_score < 5]

    return {"critical": len(critical), "high": len(high),
            "medium": len(medium), "low": len(low)}
```

### Consensus Voting Algorithm

```python
def build_consensus(findings_by_topic):
    consensus = []
    for topic, positions in findings_by_topic.items():
        severities = [p["severity"] for p in positions]
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

        if len(set(severities)) == 1:
            consensus.append({
                "topic": topic,
                "status": "agreed",
                "severity": severities[0],
                "confidence": 1.0
            })
        else:
            scores = [severity_order[s] for s in severities]
            avg_score = sum(scores) / len(scores)
            final = next(k for k, v in severity_order.items()
                       if v == round(avg_score))
            consensus.append({
                "topic": topic,
                "status": "majority_vote",
                "severity": final,
                "confidence": 1 - (max(scores) - min(scores)) / 4,
                "dissent": [p for p in positions if p["severity"] != final]
            })
    return consensus
```

### Decision Record Generator

```python
def generate_decision_record(session, consensus, actions):
    record = {
        "decision_id": f"DR-{session['session_id']}",
        "date": session.get("date", "2026-05-29"),
        "question": session["question"],
        "status": "Accepted",
        "consensus_summary": {
            "agreed_count": sum(1 for c in consensus if c["status"] == "agreed"),
            "voted_count": sum(1 for c in consensus if c["status"] == "majority_vote"),
            "avg_confidence": sum(c["confidence"] for c in consensus) / len(consensus)
        },
        "top_findings": sorted(consensus, key=lambda c: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[c["severity"]], reverse=True)[:5],
        "actions": actions,
        "dissenting_views": [c for c in consensus if c.get("dissent")]
    }
    return json.dumps(record, indent=2)
```

---

## Perspective Prompt Templates

### Attacker Perspective Prompt

```markdown
You are a skilled penetration tester analyzing [SYSTEM] from an offensive perspective.

Context: [SYSTEM_DESCRIPTION]

Produce your analysis covering:
1. **Attack Surface**: All entry points and exposed interfaces
2. **Top 3 Attack Paths**: Ranked by feasibility and impact
3. **Exploit Chain**: Most impactful multi-step attack sequence
4. **Blast Radius**: What is reachable if the top attack succeeds?
5. **Assumptions to Exploit**: What does the defender assume that you can violate?

Format each finding as:
- Title: [one line]
- Impact: [1-5]
- Likelihood: [1-5]
- Evidence: [what you observed or tested]
- Recommendation: [what would stop you]
```

### Defender Perspective Prompt

```markdown
You are a senior security engineer defending [SYSTEM] from an operational perspective.

Context: [SYSTEM_DESCRIPTION]

Produce your analysis covering:
1. **Control Inventory**: What preventive/detective/corrective controls exist?
2. **Coverage Gaps**: Which attack paths have no controls?
3. **Detection Capability**: MTTD for top 3 attack scenarios
4. **Hardening Priorities**: Top 5 actions ranked by risk reduction per effort
5. **Blind Spots**: What can the attacker do that you cannot currently detect?

Format each finding as:
- Title: [one line]
- Current State: [what exists today]
- Gap: [what is missing]
- Recommendation: [specific hardening action]
- Effort: [Low/Medium/High]
```

### Auditor Perspective Prompt

```markdown
You are a compliance auditor reviewing [SYSTEM] against [FRAMEWORK].

Context: [SYSTEM_DESCRIPTION]
Framework: [COMPLIANCE_REQUIREMENTS]

Produce your analysis covering:
1. **Control Mapping**: Map framework requirements to implemented controls
2. **Gaps**: Requirements without corresponding controls
3. **Evidence Status**: What evidence exists vs. what is needed
4. **Risk Acceptance**: Any documented exceptions and their validity
5. **Remediation Timeline**: Priority items before next audit deadline

Format each finding as:
- Requirement: [framework reference]
- Control Status: [Implemented/Partial/Missing]
- Evidence: [Available/Incomplete/Missing]
- Gap Description: [what is missing]
- Remediation Priority: [Critical/High/Medium/Low]
```

---

## Cross-Validation Patterns

### Agreement Detection

```python
def detect_agreements(attacker_findings, defender_findings, auditor_findings):
    all_findings = attacker_findings + defender_findings + auditor_findings
    by_component = {}
    for f in all_findings:
        component = f.get("affected_component", "unknown")
        by_component.setdefault(component, []).append(f)

    agreements = []
    for component, findings in by_component.items():
        perspectives = set(f["perspective"] for f in findings)
        if len(perspectives) >= 2:
            avg_impact = sum(f["impact"] for f in findings) / len(findings)
            agreements.append({
                "component": component,
                "perspectives_agreeing": list(perspectives),
                "avg_impact": avg_impact,
                "confidence": len(perspectives) / 3
            })
    return sorted(agreements, key=lambda a: a["avg_impact"], reverse=True)
```

### Disagreement Resolution

```python
def resolve_disagreements(disagreements, resolution_strategy="weighted_vote"):
    resolved = []
    weights = {"attacker": 0.4, "defender": 0.35, "auditor": 0.25}

    for d in disagreements:
        if resolution_strategy == "weighted_vote":
            severity_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            weighted_sum = sum(
                severity_scores[pos["severity"]] * weights[pos["perspective"]]
                for pos in d["positions"]
            )
            final_score = round(weighted_sum)
            final_severity = next(
                k for k, v in severity_scores.items() if v == final_score
            )
        elif resolution_strategy == "max_severity":
            severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            final_severity = max(
                d["positions"], key=lambda p: severity_order[p["severity"]]
            )["severity"]

        resolved.append({
            "topic": d["topic"],
            "final_severity": final_severity,
            "strategy": resolution_strategy,
            "dissenting": [p for p in d["positions"] if p["severity"] != final_severity]
        })
    return resolved
```

---

## Report Output Templates

### Council Summary Report

```markdown
# Council Analysis Report

## Session: [SESSION_ID]
**Date**: [DATE] | **Duration**: [MINUTES] min | **Confidence**: [SCORE]/5

## Question
[One-sentence security question analyzed]

## Key Findings

| # | Finding | Severity | Perspectives | Status |
|---|---------|----------|--------------|--------|
| 1 | [Finding] | Critical | A+D+Au | Agreed |
| 2 | [Finding] | High | A+D | Agreed |
| 3 | [Finding] | High | A vs D | Resolved (weighted vote) |
| 4 | [Finding] | Medium | Au only | Unique insight |

## Recommendation
[2-3 sentence actionable recommendation]

## Immediate Actions
1. [Action] — Owner: [team], Deadline: [date]
2. [Action] — Owner: [team], Deadline: [date]
3. [Action] — Owner: [team], Deadline: [date]

## Dissenting Views
- [Perspective]: [Position and reasoning]

## Open Questions
- [Question requiring further investigation]
```

### Executive Briefing (1-page)

```markdown
# Security Council Briefing — [DATE]

**Risk Level**: [Critical/High/Medium/Low]
**Systems Affected**: [list]
**Recommendation**: [one sentence]

## What We Found
[3 bullet points, non-technical language]

## What It Means
[Business impact in 2-3 sentences]

## What We Recommend
[Prioritized action list, 3 items max]

## Timeline
| Action | Owner | Deadline |
|--------|-------|----------|
| [Action 1] | [Team] | [Date] |
| [Action 2] | [Team] | [Date] |
```
