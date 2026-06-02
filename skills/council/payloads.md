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

### Automated Risk Score Calculator

```python
def calculate_severity(impact, likelihood):
    """Calculate risk score and severity classification."""
    score = impact * likelihood
    if score >= 15:
        return score, "Critical"
    elif score >= 10:
        return score, "High"
    elif score >= 5:
        return score, "Medium"
    elif score >= 3:
        return score, "Low"
    else:
        return score, "Info"

def batch_score_findings(findings):
    """Score and categorize a batch of findings."""
    categorized = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
    for f in findings:
        score, severity = calculate_severity(f.get("impact", 1), f.get("likelihood", 1))
        f["risk_score"] = score
        f["severity"] = severity
        categorized[severity].append(f)
    return categorized
```

### Markdown Risk Register Generator

```python
def generate_markdown_risk_table(findings, output_file="risk_register.md"):
    """Generate a markdown risk register table from findings."""
    lines = [
        "# Risk Register",
        "",
        "| ID | Finding | Perspective | Impact | Likelihood | Score | Severity |",
        "|----|---------|-------------|--------|------------|-------|----------|"
    ]
    for idx, f in enumerate(sorted(findings,
            key=lambda x: x.get("impact", 1) * x.get("likelihood", 1), reverse=True), 1):
        impact = f.get("impact", 1)
        likelihood = f.get("likelihood", 1)
        score = impact * likelihood
        severity = "Critical" if score >= 15 else "High" if score >= 10 else \
                   "Medium" if score >= 5 else "Low" if score >= 3 else "Info"
        lines.append(
            f"| R-{idx:03d} | {f.get('title', 'N/A')} | {f.get('perspective', 'N/A')} "
            f"| {impact} | {likelihood} | {score} | {severity} |"
        )

    with open(output_file, "w") as out:
        out.write("\n".join(lines))
    print(f"[+] Risk register written to {output_file}")
```

### Voting Mechanism Implementation

```python
from collections import Counter

def majority_vote(positions):
    """Simple majority vote across perspectives."""
    votes = Counter(p["severity"] for p in positions)
    winner = votes.most_common(1)[0][0]
    margin = votes.most_common(1)[0][1] / len(positions)
    return {"winner": winner, "margin": margin, "is_consensus": margin >= 0.67}

def ranked_choice_voting(positions, severity_order=["Critical", "High", "Medium", "Low", "Info"]):
    """Ranked choice voting with elimination rounds."""
    remaining = list(severity_order)
    votes = [p.get("ranked_preferences", [p["severity"]]) for p in positions]

    while len(remaining) > 1:
        first_choices = Counter()
        for ballot in votes:
            for choice in ballot:
                if choice in remaining:
                    first_choices[choice] += 1
                    break

        total = sum(first_choices.values())
        for choice, count in first_choices.most_common():
            if count / total > 0.5:
                return {"winner": choice, "rounds": len(severity_order) - len(remaining) + 1}

        # Eliminate lowest
        lowest = first_choices.most_common()[-1][0]
        remaining.remove(lowest)

    return {"winner": remaining[0], "rounds": len(severity_order) - len(remaining) + 1}
```

### Advisory Email Template Generator

```python
def generate_advisory_email(session_data, recipients):
    """Generate a formatted advisory email from council session data."""
    findings = session_data.get("findings", [])
    critical = [f for f in findings if f.get("severity") == "Critical"]
    high = [f for f in findings if f.get("severity") == "High"]

    email_body = f"""Subject: [Security Advisory] Council Session {session_data.get('session_id', 'N/A')}

Security Council completed analysis of:
{session_data.get('question', 'N/A')}

CONFIDENCE: {session_data.get('consensus', {}).get('confidence', 0):.0%}

SUMMARY:
- Total findings: {len(findings)}
- Critical: {len(critical)}
- High: {len(high)}

IMMEDIATE ACTIONS REQUIRED:
"""
    for f in sorted(critical + high,
                    key=lambda x: x.get("impact", 0) * x.get("likelihood", 0),
                    reverse=True)[:5]:
        score = f.get("impact", 0) * f.get("likelihood", 0)
        email_body += f"  - [{f.get('severity')}] {f.get('title')} (Score: {score})\n"

    email_body += f"\nFull report available in council session records.\n"
    return email_body
```

### JSON Report Exporter

```python
import json
from datetime import datetime

def export_council_json(session, findings, consensus, filename="council_report.json"):
    """Export complete council analysis as structured JSON."""
    report = {
        "metadata": {
            "session_id": session.get("session_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "question": session.get("question"),
            "duration_minutes": session.get("duration", 0)
        },
        "statistics": {
            "total_findings": len(findings),
            "by_perspective": {},
            "by_severity": {},
            "consensus_confidence": consensus.get("confidence", 0)
        },
        "findings": findings,
        "consensus": consensus,
        "recommendations": [f for f in findings if f.get("recommendation")]
    }

    # Compute perspective breakdown
    for f in findings:
        p = f.get("perspective", "unknown")
        report["statistics"]["by_perspective"][p] = \
            report["statistics"]["by_perspective"].get(p, 0) + 1
        s = f.get("severity", "unknown")
        report["statistics"]["by_severity"][s] = \
            report["statistics"]["by_severity"].get(s, 0) + 1

    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Council report exported to {filename}")
    return report
```

### Stakeholder Impact Matrix

```python
def generate_impact_matrix(findings, stakeholders=None):
    """Map findings to stakeholder impact for communication planning."""
    if stakeholders is None:
        stakeholders = ["Engineering", "Legal", "Executive", "Operations", "Compliance"]

    impact_map = {
        "Engineering": ["exploit", "vulnerability", "code", "patch", "deployment"],
        "Legal": ["breach", "compliance", "regulation", "gdpr", "liability"],
        "Executive": ["revenue", "reputation", "business", "strategy", "risk"],
        "Operations": ["downtime", "availability", "incident", "monitoring", "response"],
        "Compliance": ["audit", "control", "policy", "framework", "evidence"]
    }

    matrix = {s: [] for s in stakeholders}
    for f in findings:
        title_lower = f.get("title", "").lower()
        rec_lower = f.get("recommendation", "").lower()
        text = title_lower + " " + rec_lower

        for stakeholder, keywords in impact_map.items():
            if any(kw in text for kw in keywords):
                matrix[stakeholder].append({
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "action": f.get("recommendation", "Review required")
                })

    return matrix
```

### Finding Age and Trend Tracker

```python
def track_finding_trends(historical_sessions, current_findings):
    """Compare current findings with historical sessions to track trends."""
    trends = []
    for current in current_findings:
        title = current.get("title", "").lower()
        matching_history = []

        for session in historical_sessions:
            for past_f in session.get("findings", []):
                if title in past_f.get("title", "").lower() or \
                   past_f.get("title", "").lower() in title:
                    matching_history.append({
                        "session": session.get("session_id"),
                        "date": session.get("date"),
                        "severity": past_f.get("severity"),
                        "status": past_f.get("status", "open")
                    })

        if matching_history:
            last_status = matching_history[-1].get("status")
            trend = "RECURRING" if last_status == "closed" else "PERSISTENT"
        else:
            trend = "NEW"

        trends.append({
            "title": current.get("title"),
            "trend": trend,
            "occurrences": len(matching_history),
            "history": matching_history
        })

    return sorted(trends, key=lambda t: t["occurrences"], reverse=True)
```

### Remediation Priority Calculator

```python
def calculate_remediation_priority(finding, organization_context=None):
    """Calculate remediation priority based on multiple factors."""
    base_score = finding.get("impact", 1) * finding.get("likelihood", 1)

    # Adjust for exploitability
    exploit_adjustment = 0
    if finding.get("exploit_available"):
        exploit_adjustment += 5
    if finding.get("publicly_known"):
        exploit_adjustment += 3
    if finding.get("actively_exploited"):
        exploit_adjustment += 10

    # Adjust for business context
    business_adjustment = 0
    if organization_context:
        exposed = finding.get("exposed_to_internet", False)
        critical_asset = finding.get("critical_asset", False)
        if exposed and critical_asset:
            business_adjustment += 8
        elif exposed:
            business_adjustment += 4
        elif critical_asset:
            business_adjustment += 3

    # Estimate remediation effort
    effort_map = {"low": 1, "medium": 2, "high": 3}
    effort = effort_map.get(finding.get("remediation_effort", "medium"), 2)

    priority = base_score + exploit_adjustment + business_adjustment

    return {
        "finding": finding.get("title"),
        "priority_score": priority,
        "effort": effort,
        "roi": round(priority / max(effort, 1), 1),
        "recommendation": "IMMEDIATE" if priority >= 20 else
                          "HIGH" if priority >= 15 else
                          "SCHEDULED" if priority >= 8 else "BACKLOG"
    }
```

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

### Quick Council Script

```python
def quick_council_analysis(question, findings_list):
    """Run a rapid council analysis from three perspectives."""
    perspectives = {"attacker": [], "defender": [], "auditor": []}
    for f in findings_list:
        if f.get("perspective") in perspectives:
            perspectives[f["perspective"]].append(f)

    # Find agreements (same finding title across multiple perspectives)
    all_titles = {}
    for f in findings_list:
        title = f.get("title", "")
        all_titles.setdefault(title, []).append(f.get("perspective"))

    agreements = [t for t, ps in all_titles.items() if len(set(ps)) >= 2]
    disagreements = [t for t, ps in all_titles.items() if len(set(ps)) == 1]

    critical_findings = [f for f in findings_list
                        if f.get("impact", 0) * f.get("likelihood", 0) >= 15]

    recommendation = "Immediate action required" if critical_findings else "Schedule review"
    confidence = len(agreements) / max(len(all_titles), 1)

    return {
        "question": question,
        "recommendation": recommendation,
        "confidence": f"{confidence:.0%}",
        "agreements": agreements[:5],
        "disagreements": disagreements[:5],
        "critical_count": len(critical_findings)
    }
```

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

## Additional Council Scripts

### Council Session Timer and Budget Tracker

```python
import time

class CouncilTimer:
    """Track time budget across council analysis phases."""
    def __init__(self, total_minutes=45):
        self.total_seconds = total_minutes * 60
        self.start_time = None
        self.phases = {}

    def start(self):
        self.start_time = time.time()

    def phase(self, name):
        """Record a phase checkpoint."""
        if self.start_time is None:
            self.start()
        elapsed = time.time() - self.start_time
        remaining = self.total_seconds - elapsed
        self.phases[name] = {"elapsed": round(elapsed, 1), "remaining": round(remaining, 1)}
        print(f"[TIMER] {name}: {elapsed:.0f}s elapsed, {remaining:.0f}s remaining")
        return remaining > 0

    def time_left(self):
        if self.start_time is None:
            return self.total_seconds
        return max(0, self.total_seconds - (time.time() - self.start_time))
```

### Council Report HTML Generator

```python
def generate_html_report(session_data, findings, output_file="council_report.html"):
    """Generate an HTML-formatted council report for stakeholder review."""
    severity_colors = {
        "Critical": "#dc3545", "High": "#fd7e14",
        "Medium": "#ffc107", "Low": "#28a745", "Info": "#6c757d"
    }

    rows = ""
    for idx, f in enumerate(sorted(findings,
            key=lambda x: x.get("impact", 1) * x.get("likelihood", 1), reverse=True), 1):
        score = f.get("impact", 1) * f.get("likelihood", 1)
        severity = "Critical" if score >= 15 else "High" if score >= 10 else \
                   "Medium" if score >= 5 else "Low" if score >= 3 else "Info"
        color = severity_colors.get(severity, "#6c757d")
        rows += f"""<tr>
            <td>{idx}</td><td>{f.get('title','')}</td>
            <td style="color:{color};font-weight:bold">{severity}</td>
            <td>{f.get('perspective','')}</td><td>{score}</td>
        </tr>"""

    html = f"""<html><head><title>Council Report</title>
    <style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse;width:100%}}
    th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f5f5f5}}</style>
    </head><body><h1>Council Analysis Report</h1>
    <p><strong>Session:</strong> {session_data.get('session_id','N/A')}</p>
    <p><strong>Question:</strong> {session_data.get('question','N/A')}</p>
    <table><tr><th>#</th><th>Finding</th><th>Severity</th><th>Perspective</th><th>Score</th></tr>
    {rows}</table></body></html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved to {output_file}")
```

### Council Metrics Dashboard Generator

```python
def generate_dashboard(findings, session_info):
    """Generate text-based dashboard metrics for council session."""
    severity_counts = Counter(f.get("severity", "Unknown") for f in findings)
    perspective_counts = Counter(f.get("perspective", "Unknown") for f in findings)

    critical_score = sum(1 for f in findings if f.get("severity") == "Critical")
    total_score = sum(f.get("impact", 1) * f.get("likelihood", 1) for f in findings)
    avg_confidence = session_info.get("consensus", {}).get("confidence", 0)

    dashboard = f"""
    =============================================
    COUNCIL SESSION DASHBOARD
    =============================================
    Session:    {session_info.get('session_id', 'N/A')}
    Question:   {session_info.get('question', 'N/A')}
    Confidence: {avg_confidence:.0%}

    FINDINGS BY SEVERITY
    ---------------------------------
    Critical: {'#' * min(critical_score, 40)} ({critical_score})
    High:     {'#' * min(severity_counts.get('High', 0), 40)} ({severity_counts.get('High', 0)})
    Medium:   {'#' * min(severity_counts.get('Medium', 0), 40)} ({severity_counts.get('Medium', 0)})
    Low:      {'#' * min(severity_counts.get('Low', 0), 40)} ({severity_counts.get('Low', 0)})

    PERSPECTIVE COVERAGE
    ---------------------------------
    Attacker: {perspective_counts.get('attacker', 0)} findings
    Defender: {perspective_counts.get('defender', 0)} findings
    Auditor:  {perspective_counts.get('auditor', 0)} findings

    Aggregate Risk Score: {total_score}
    =============================================
    """
    return dashboard
```

### Action Item Tracker

```python
def track_action_items(findings, owners_map):
    """Generate tracked action items from council findings with deadlines."""
    actions = []
    severity_deadlines = {
        "Critical": 1,   # 1 day
        "High": 3,       # 3 days
        "Medium": 14,    # 2 weeks
        "Low": 30         # 1 month
    }

    for f in sorted(findings,
                    key=lambda x: x.get("impact", 1) * x.get("likelihood", 1),
                    reverse=True):
        severity = f.get("severity", "Low")
        deadline_days = severity_deadlines.get(severity, 30)
        component = f.get("affected_component", "general")
        owner = owners_map.get(component, owners_map.get("default", "Unassigned"))

        actions.append({
            "id": f"A-{len(actions)+1:03d}",
            "finding": f.get("title"),
            "severity": severity,
            "owner": owner,
            "deadline_days": deadline_days,
            "recommendation": f.get("recommendation", "Review required"),
            "status": "Open"
        })

    return actions
```

### Weighted Confidence Scorer

```python
def calculate_weighted_confidence(findings, weights=None):
    """Calculate confidence score based on perspective agreement weights."""
    if weights is None:
        weights = {"attacker": 0.40, "defender": 0.35, "auditor": 0.25}

    from collections import defaultdict
    by_topic = defaultdict(list)
    for f in findings:
        by_topic[f.get("title")].append(f)

    scores = []
    for topic, topic_findings in by_topic.items():
        perspectives_present = set(f.get("perspective") for f in topic_findings)
        coverage = sum(weights.get(p, 0) for p in perspectives_present)

        severities = [f.get("severity") for f in topic_findings]
        severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        severity_values = [severity_map.get(s, 0) for s in severities]
        spread = max(severity_values) - min(severity_values) if severity_values else 0
        agreement_bonus = 1.0 if spread == 0 else max(0, 1.0 - spread * 0.25)

        confidence = coverage * agreement_bonus
        scores.append({"topic": topic, "confidence": round(confidence, 2), "spread": spread})

    return sorted(scores, key=lambda x: x["confidence"], reverse=True)
```

### Executive Summary Generator

```python
def generate_executive_summary(session_data, findings, max_findings=5):
    """Generate a one-page executive summary from council analysis."""
    critical = [f for f in findings if f.get("severity") == "Critical"]
    high = [f for f in findings if f.get("severity") == "High"]
    total_risk = sum(f.get("impact", 1) * f.get("likelihood", 1) for f in findings)

    top = sorted(findings, key=lambda x: x.get("impact", 1) * x.get("likelihood", 1), reverse=True)
    top_findings = top[:max_findings]

    summary = f"""EXECUTIVE SUMMARY
{'=' * 50}
Session: {session_data.get('session_id')}
Date: {session_data.get('date', 'N/A')}
Risk Level: {'CRITICAL' if critical else 'HIGH' if high else 'MODERATE'}

OVERVIEW
--------
Total findings: {len(findings)}
Critical: {len(critical)} | High: {len(high)}
Aggregate risk score: {total_risk}
Confidence: {session_data.get('consensus', {}).get('confidence', 0):.0%}

TOP FINDINGS
------------
"""
    for i, f in enumerate(top_findings, 1):
        score = f.get("impact", 1) * f.get("likelihood", 1)
        summary += f"{i}. [{f.get('severity')}] {f.get('title')} (Score: {score})\n"
        summary += f"   Action: {f.get('recommendation', 'Review needed')}\n"

    summary += f"\nRECOMMENDATION\n{'-' * 50}\n"
    if critical:
        summary += "Immediate remediation required for critical findings.\n"
    elif high:
        summary += "Priority remediation within 72 hours recommended.\n"
    else:
        summary += "Schedule remediation within 30 days.\n"

    return summary
```

### Finding Classification Engine

```python
def classify_finding(finding):
    """Auto-classify a finding into OWASP/SANS category."""
    title = finding.get("title", "").lower()
    categories = {
        "Injection": ["sql", "xss", "command injection", "ldap", "xpath", "ssti"],
        "Broken Auth": ["auth", "session", "password", "login", "token", "jwt"],
        "Sensitive Data": ["encrypt", "crypto", "data exposure", "leak", " pii"],
        "Access Control": ["idor", "privilege", "rbac", "authorization", "bypass"],
        "Misconfig": ["cors", "header", "config", "default", "debug"],
        "Vulnerable Component": ["outdated", "version", "cve", "library", "dependency"]
    }

    for category, keywords in categories.items():
        if any(kw in title for kw in keywords):
            finding["category"] = category
            return category

    finding["category"] = "Other"
    return "Other"
```

### Council Session Comparator

```python
def compare_sessions(session_a, session_b):
    """Compare two council sessions to track progress over time."""
    findings_a = {f.get("title"): f for f in session_a.get("findings", [])}
    findings_b = {f.get("title"): f for f in session_b.get("findings", [])}

    new_findings = [t for t in findings_b if t not in findings_a]
    resolved = [t for t in findings_a if t not in findings_b]
    persistent = [t for t in findings_b if t in findings_a]

    severity_improved = 0
    severity_worsened = 0
    for title in persistent:
        score_a = findings_a[title].get("impact", 1) * findings_a[title].get("likelihood", 1)
        score_b = findings_b[title].get("impact", 1) * findings_b[title].get("likelihood", 1)
        if score_b < score_a:
            severity_improved += 1
        elif score_b > score_a:
            severity_worsened += 1

    return {
        "new_findings": len(new_findings),
        "resolved": len(resolved),
        "persistent": len(persistent),
        "severity_improved": severity_improved,
        "severity_worsened": severity_worsened,
        "trend": "improving" if len(resolved) > len(new_findings) else "degrading"
    }
```

### Compliance Gap Heatmap Generator

```python
def generate_compliance_heatmap(findings, framework_controls):
    """Generate a compliance coverage heatmap from council findings."""
    heatmap = {}
    for control_id, control_desc in framework_controls.items():
        relevant = [f for f in findings
                    if control_id in f.get("mapped_controls", [])]
        if relevant:
            scores = [f.get("impact", 1) * f.get("likelihood", 1) for f in relevant]
            avg_score = sum(scores) / len(scores)
            heatmap[control_id] = {
                "description": control_desc,
                "status": "GAP" if avg_score >= 10 else "PARTIAL" if avg_score >= 5 else "COVERED",
                "finding_count": len(relevant),
                "avg_risk": round(avg_score, 1)
            }
        else:
            heatmap[control_id] = {
                "description": control_desc,
                "status": "UNTESTED",
                "finding_count": 0,
                "avg_risk": 0
            }
    return heatmap
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

### Bias Detection Algorithm

```python
def detect_perspective_bias(perspectives_data):
    """Detect cognitive biases across council perspectives."""
    biases = []

    # Anchoring bias: first finding disproportionately influences others
    for topic, positions in perspectives_data.items():
        if len(positions) < 2:
            continue
        first_severity = positions[0]["severity"]
        agreeing = sum(1 for p in positions[1:] if p["severity"] == first_severity)
        if agreeing == len(positions) - 1:
            biases.append({
                "type": "potential_anchoring",
                "topic": topic,
                "detail": f"All {len(positions)} perspectives share the first perspective's severity"
            })

    # Confirmation bias: defender consistently rates lower than attacker
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for topic, positions in perspectives_data.items():
        attacker = next((p for p in positions if p["perspective"] == "attacker"), None)
        defender = next((p for p in positions if p["perspective"] == "defender"), None)
        if attacker and defender:
            diff = severity_map[attacker["severity"]] - severity_map[defender["severity"]]
            if diff >= 2:
                biases.append({
                    "type": "severity_divergence",
                    "topic": topic,
                    "detail": f"Attacker rates {attacker['severity']}, Defender rates {defender['severity']} (gap={diff})"
                })

    return biases
```

### Conflict Resolution Engine

```python
def resolve_conflicts(disagreements, strategy="weighted_vote"):
    """Resolve disagreements between perspectives using configurable strategies."""
    weights = {"attacker": 0.40, "defender": 0.35, "auditor": 0.25}
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    reverse_map = {v: k for k, v in severity_map.items()}
    resolved = []

    for disagreement in disagreements:
        positions = disagreement["positions"]

        if strategy == "weighted_vote":
            weighted_sum = sum(
                severity_map[p["severity"]] * weights.get(p["perspective"], 0.33)
                for p in positions
            )
            final_score = round(weighted_sum)
            final_severity = reverse_map.get(final_score, "Medium")

        elif strategy == "max_severity":
            final_severity = max(positions, key=lambda p: severity_map[p["severity"]])["severity"]

        elif strategy == "auditor_tiebreak":
            scores = [p["severity"] for p in positions]
            if len(set(scores)) > 1:
                auditor_pos = next((p for p in positions if p["perspective"] == "auditor"), None)
                final_severity = auditor_pos["severity"] if auditor_pos else scores[0]
            else:
                final_severity = scores[0]

        resolved.append({
            "topic": disagreement["topic"],
            "final_severity": final_severity,
            "strategy_used": strategy,
            "dissenting": [p for p in positions if p["severity"] != final_severity]
        })

    return resolved
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

### Finding Deduplication Across Perspectives

```python
def deduplicate_findings(all_findings, similarity_threshold=0.8):
    """Deduplicate similar findings across different perspectives."""
    from difflib import SequenceMatcher

    unique = []
    for finding in all_findings:
        is_duplicate = False
        for existing in unique:
            ratio = SequenceMatcher(
                None,
                finding.get("title", "").lower(),
                existing.get("title", "").lower()
            ).ratio()
            if ratio >= similarity_threshold and finding.get("perspective") != existing.get("perspective"):
                existing["related_perspectives"] = existing.get("related_perspectives", [])
                existing["related_perspectives"].append(finding.get("perspective"))
                is_duplicate = True
                break
        if not is_duplicate:
            unique.append(finding)

    return unique
```

### Finding Correlation Engine

```python
def correlate_findings(findings):
    """Find causal relationships between findings (e.g., A enables B)."""
    correlations = []
    keywords_map = {
        "credential": ["auth", "login", "password", "session"],
        "network": ["firewall", "port", "service", "network"],
        "injection": ["sql", "xss", "command", "injection", "input"],
        "access": ["privilege", "escalation", "permission", "rbac"]
    }

    for i, f1 in enumerate(findings):
        for f2 in findings[i+1:]:
            title1 = f1.get("title", "").lower()
            title2 = f2.get("title", "").lower()
            for category, kws in keywords_map.items():
                if any(kw in title1 for kw in kws) and any(kw in title2 for kw in kws):
                    correlations.append({
                        "finding_a": f1.get("title"),
                        "finding_b": f2.get("title"),
                        "category": category,
                        "relationship": "correlated"
                    })
                    break

    return correlations
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

## Automated Risk Matrix Generation

### Heatmap Data Generation

```python
def generate_risk_heatmap(findings):
    """Generate data for a 5x5 risk heatmap from findings."""
    matrix = [[0]*5 for _ in range(5)]
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

    for f in findings:
        impact = f.get("impact", 1) - 1  # 0-indexed
        likelihood = f.get("likelihood", 1) - 1
        if 0 <= impact < 5 and 0 <= likelihood < 5:
            matrix[4 - impact][likelihood] += 1  # flip so highest impact is top

    print("Risk Heatmap (Impact vs Likelihood):")
    labels = ["Critical", "High", "Medium", "Low", "Negligible"]
    print(f"{'Impact':<12}", end="")
    for i in range(1, 6):
        print(f"  L={i}  ", end="")
    print()
    for row_idx, row in enumerate(matrix):
        print(f"{labels[row_idx]:<12}", end="")
        for cell in row:
            print(f"  [{cell}]  " if cell else "   .   ", end="")
        print()
    return matrix
```

### Risk Register CSV Export

```python
import csv
from datetime import datetime

def export_risk_register(findings, filename="risk_register.csv"):
    """Export findings as a CSV risk register for stakeholder review."""
    headers = [
        "ID", "Finding", "Category", "Perspective",
        "Impact", "Likelihood", "RiskScore", "Severity",
        "Status", "Owner", "Deadline", "Evidence", "Recommendation"
    ]

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for idx, finding in enumerate(findings, 1):
            impact = finding.get("impact", 1)
            likelihood = finding.get("likelihood", 1)
            risk_score = impact * likelihood

            severity = "Critical" if risk_score >= 15 else \
                       "High" if risk_score >= 10 else \
                       "Medium" if risk_score >= 5 else "Low"

            writer.writerow([
                f"R-{idx:03d}",
                finding.get("title", ""),
                finding.get("category", ""),
                finding.get("perspective", ""),
                impact,
                likelihood,
                risk_score,
                severity,
                finding.get("status", "Open"),
                finding.get("owner", ""),
                finding.get("deadline", ""),
                finding.get("evidence", "")[:200],
                finding.get("recommendation", "")
            ])

    print(f"[+] Risk register exported: {filename} ({len(findings)} findings)")
```

### Finding Prioritization Engine

```python
def prioritize_findings(findings, weights=None):
    """Prioritize findings using multi-factor scoring."""
    if weights is None:
        weights = {"risk_score": 0.4, "exploitability": 0.3, "business_impact": 0.3}

    for f in findings:
        risk = f.get("impact", 1) * f.get("likelihood", 1)
        exploit = f.get("exploitability", 5)  # 1=easy, 5=hard -> invert
        business = f.get("business_impact", 3)  # 1-5

        f["priority_score"] = round(
            (risk / 25) * weights["risk_score"] * 100 +
            ((6 - exploit) / 5) * weights["exploitability"] * 100 +
            (business / 5) * weights["business_impact"] * 100,
            1
        )

    return sorted(findings, key=lambda x: x["priority_score"], reverse=True)
```

---

## Advisory Report Templates

### Technical Advisory Template

```markdown
# Technical Security Advisory

**Advisory ID**: ADV-YYYY-NNN
**Date**: YYYY-MM-DD
**Classification**: Confidential

## Summary
[One-paragraph executive summary of the finding]

## Technical Details

### Vulnerability Description
[Detailed technical description]

### Affected Components
- Component: [name], Version: [version]
- Attack Vector: [network/application/local]
- Authentication Required: [yes/no]

### Proof of Concept
[Step-by-step reproduction instructions]

### Impact Assessment
- **Confidentiality**: [None/Partial/Complete]
- **Integrity**: [None/Partial/Complete]
- **Availability**: [None/Partial/Complete]

## Recommendations
1. [Immediate mitigation]
2. [Long-term fix]
3. [Detection enhancement]

## References
- CVE: [CVE-YYYY-NNNNN]
- CWE: [CWE-NNN]
- CVSS: [Score] ([Vector String])
```

### Stakeholder Communication Template

```markdown
# Security Council Communication

**To**: [Stakeholders]
**From**: Security Council
**Date**: YYYY-MM-DD
**Priority**: [Critical/High/Normal]

## Key Decision
[One sentence describing the decision made]

## Background
[2-3 sentences of context, non-technical language]

## Impact to Business
- Revenue: [description]
- Operations: [description]
- Compliance: [description]

## Required Actions
| Action | Owner | Deadline | Status |
|--------|-------|----------|--------|
| [Action 1] | [Team] | [Date] | Pending |
| [Action 2] | [Team] | [Date] | Pending |

## Questions?
Contact: [Security Team] at [email]
```

---

## Validation and Quality Scripts

### Cross-Perspective Validation

```python
def validate_council_output(session_data):
    """Validate that council analysis meets quality thresholds."""
    issues = []

    findings = session_data.get("findings", [])
    if len(findings) < 1:
        issues.append("CRITICAL: No findings generated")

    perspectives = set(f.get("perspective") for f in findings)
    required = {"attacker", "defender", "auditor"}
    missing = required - perspectives
    if missing:
        issues.append(f"HIGH: Missing perspectives: {missing}")

    for f in findings:
        if not f.get("evidence"):
            issues.append(f"MEDIUM: Finding '{f.get('title')}' has no evidence")
        if f.get("impact", 0) < 1 or f.get("impact", 0) > 5:
            issues.append(f"HIGH: Finding '{f.get('title')}' has invalid impact score")
        if f.get("likelihood", 0) < 1 or f.get("likelihood", 0) > 5:
            issues.append(f"HIGH: Finding '{f.get('title')}' has invalid likelihood score")

    consensus = session_data.get("consensus", {})
    confidence = consensus.get("confidence", 0)
    if confidence < 0.5:
        issues.append(f"MEDIUM: Low consensus confidence: {confidence:.0%}")

    return {"valid": len([i for i in issues if i.startswith("CRITICAL")]) == 0,
            "issues": issues, "total_findings": len(findings)}
```

### Council Session Summary Generator

```python
def generate_session_summary(session):
    """Generate a markdown summary from council session data."""
    findings = session.get("findings", [])
    critical = [f for f in findings if f.get("impact", 0) * f.get("likelihood", 0) >= 15]
    high = [f for f in findings if 10 <= f.get("impact", 0) * f.get("likelihood", 0) < 15]

    summary = f"""# Council Session Summary

**Session**: {session.get('session_id', 'N/A')}
**Question**: {session.get('question', 'N/A')}
**Confidence**: {session.get('consensus', {}).get('confidence', 0):.0%}

## Statistics
- Total Findings: {len(findings)}
- Critical: {len(critical)}
- High: {len(high)}
- Perspectives Used: {len(set(f.get('perspective') for f in findings))}

## Top Critical Findings
"""
    for f in sorted(critical, key=lambda x: x.get('impact', 0) * x.get('likelihood', 0), reverse=True)[:5]:
        score = f.get('impact', 0) * f.get('likelihood', 0)
        summary += f"- [{f.get('perspective')}] {f.get('title')} (Score: {score})\n"

    return summary
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
