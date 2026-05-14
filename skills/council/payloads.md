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
