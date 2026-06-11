# Multi-Agent Escalation Guide

> When and how to escalate findings across agents, including severity-based escalation protocols, cross-domain correlation, and real-world escalation scenarios.

## Introduction

In multi-agent security assessments, individual agents operate within their domain expertise -- one handles web application testing, another focuses on network penetration, and a third assesses cloud infrastructure. While this specialization produces deep findings within each domain, the most critical vulnerabilities often emerge at the boundaries between domains: a web application vulnerability that grants access to cloud credentials, a network misconfiguration that exposes an internal API, or a container escape that pivots to Active Directory compromise.

Multi-agent escalation is the structured process of identifying, communicating, and acting on findings that cross domain boundaries or exceed individual agent handling capacity. This guide covers escalation triggers, severity-based protocols, cross-domain correlation methodology, and real-world scenarios drawn from purple team exercises and incident response operations.

## 1. Escalation Triggers and Classification

### Trigger Taxonomy

Not all findings require escalation. Use this taxonomy to determine when escalation is necessary:

| Trigger Category | Condition | Example | Urgency |
|-----------------|-----------|---------|---------|
| Cross-Domain Impact | Finding affects systems outside the discovering agent's domain | Web RCE exposes database credentials in a different network segment | HIGH |
| Severity Exceeds Threshold | Finding severity exceeds the agent's handling level | Agent discovers Critical (CVSS 9.0+) vulnerability with active exploitation | CRITICAL |
| Chaining Opportunity | Finding can be combined with findings from another domain | Network agent finds open SMB share; web agent found plaintext credentials | HIGH |
| Scope Expansion | Finding reveals systems not in original scope | Cloud agent discovers unmanaged shadow IT infrastructure | MEDIUM |
| Evidence Preservation | Finding requires immediate action to preserve evidence | Active attacker detected; volatile memory capture needed before host reboot | CRITICAL |
| Regulatory Trigger | Finding triggers mandatory notification requirements | PII breach exceeding GDPR 72-hour reporting threshold | CRITICAL |
| Resource Exhaustion | Agent cannot complete assessment within allocated time | Complex Active Directory forest requires more than scheduled window | LOW |

### Severity-Based Escalation Protocol

```python
from dataclasses import dataclass
from enum import Enum

class EscalationLevel(Enum):
    NONE = "none"           # No escalation needed
    ADVISORY = "advisory"   # Notify other agents, no action required
    COORDINATE = "coordinate"  # Schedule joint investigation
    IMMEDIATE = "immediate"    # Real-time coordination required
    EMERGENCY = "emergency"    # Stop all other work, full team response

@dataclass(frozen=True)
class EscalationDecision:
    trigger: str
    severity: float
    affected_domains: list[str]
    level: EscalationLevel
    rationale: str
    time_constraint: str  # "none", "24h", "4h", "immediate"

def classify_escalation(finding: dict, current_domain: str) -> EscalationDecision:
    severity = finding.get("severity", 0.0)
    cross_domain = len(finding.get("affected_domains", [])) > 1
    active_threat = finding.get("active_exploitation", False)
    regulatory_impact = finding.get("regulatory_impact", False)

    if active_threat or (severity >= 9.0 and cross_domain):
        level = EscalationLevel.EMERGENCY
        time_constraint = "immediate"
    elif severity >= 8.0 or (severity >= 7.0 and cross_domain) or regulatory_impact:
        level = EscalationLevel.IMMEDIATE
        time_constraint = "4h"
    elif cross_domain or severity >= 6.0:
        level = EscalationLevel.COORDINATE
        time_constraint = "24h"
    elif severity >= 4.0:
        level = EscalationLevel.ADVISORY
        time_constraint = "none"
    else:
        level = EscalationLevel.NONE
        time_constraint = "none"

    return EscalationDecision(
        trigger=finding.get("title", "unknown"),
        severity=severity,
        affected_domains=finding.get("affected_domains", [current_domain]),
        level=level,
        rationale=f"Severity {severity}, cross_domain={cross_domain}, active={active_threat}",
        time_constraint=time_constraint,
    )
```

## 2. Cross-Domain Correlation

### Correlation Engine

Cross-domain correlation connects findings from different agents to identify compound risks that no single agent could detect alone.

```python
@dataclass(frozen=True)
class CorrelatedFinding:
    finding_ids: list[str]
    domains: list[str]
    compound_severity: float
    attack_chain: list[str]
    recommended_action: str

def correlate_findings(all_findings: dict[str, list[dict]]) -> list[CorrelatedFinding]:
    """Find compound risks by correlating findings across domains."""
    correlations = []

    # Pattern 1: Credential leakage + Service exposure
    # If one agent found credentials and another found an exposed service
    credential_findings = [
        f for findings in all_findings.values() for f in findings
        if f.get("type") == "credential_leak"
    ]
    exposed_services = [
        f for findings in all_findings.values() for f in findings
        if f.get("type") == "exposed_service"
    ]

    for cred in credential_findings:
        for svc in exposed_services:
            if _credentials_match_service(cred, svc):
                correlations.append(CorrelatedFinding(
                    finding_ids=[cred["id"], svc["id"]],
                    domains=[cred["domain"], svc["domain"]],
                    compound_severity=max(cred["severity"], svc["severity"]) * 1.3,
                    attack_chain=[
                        f"Use {cred['title']} from {cred['domain']} domain",
                        f"Authenticate to {svc['title']} in {svc['domain']} domain",
                        "Achieve cross-domain compromise"
                    ],
                    recommended_action="Immediate remediation: rotate credentials AND restrict service access"
                ))

    return sorted(correlations, key=lambda c: c.compound_severity, reverse=True)

def _credentials_match_service(cred: dict, svc: dict) -> bool:
    """Check if leaked credentials could authenticate to exposed service."""
    return (
        cred.get("credential_type") == svc.get("auth_type")
        or cred.get("target_system") == svc.get("service_name")
    )
```

### Correlation Patterns Reference

| Pattern | Agent A Finding | Agent B Finding | Compound Risk |
|---------|----------------|----------------|---------------|
| Credential + Service | AWS keys in GitHub repo | Exposed S3 bucket with sensitive data | Full data breach via cloud pivot |
| Network + Web | Open internal VPN port | SQL injection in web app | VPN access via extracted web DB credentials |
| Cloud + Container | IAM over-permission | Container escape vulnerability | Host compromise via cloud credential theft |
| Physical + Network | Unprotected network jack in lobby | Unsegmented internal network | Physical access to full network |
| Social + Technical | Phishing credential capture | Lateral movement path from user workstation | Full domain compromise from single phishing success |

### Correlation Workflow

1. **Collection**: Each agent publishes findings to a shared correlation queue
2. **Normalization**: Findings are normalized to a common schema (severity, affected_domains, credential_type, target_system)
3. **Pattern Matching**: The correlation engine applies known patterns to find compound risks
4. **Scoring**: Compound severity is calculated (typically 1.2-1.5x the max individual severity)
5. **Escalation**: Correlated findings trigger COORDINATE or IMMEDIATE escalation level
6. **Notification**: All affected agents receive the correlation result with recommended joint action

## 3. Escalation Communication Protocol

### Message Format

All escalation messages follow a standard format for rapid parsing and action:

```markdown
## ESCALATION [LEVEL]: [Title]

**From**: [Agent ID / Domain]
**To**: [Target Agent(s) / All]
**Time**: [ISO 8601 timestamp]
**Finding IDs**: [FID-001, FID-002]
**Severity**: [0.0-10.0]
**Domains Affected**: [web, network, cloud]

### Summary
[2-3 sentence description of the finding and why it requires escalation]

### Impact on Your Domain
[Specific ways this finding affects the receiving agent's domain]

### Requested Action
[What the receiving agent should do: investigate, provide additional data, halt activity]

### Time Constraint
[When action is needed: immediate, 4h, 24h, next sync]

### Evidence
[Relevant evidence snippets, screenshots, tool output]

### Related Findings
[Links to other findings that contribute to this escalation]
```

### Communication Channels by Escalation Level

| Level | Primary Channel | Backup Channel | Response Expectation |
|-------|----------------|----------------|---------------------|
| ADVISORY | Shared document / wiki | Email | Next scheduled sync |
| COORDINATE | Team chat (Slack/Teams) | Email with read receipt | Within 4 hours |
| IMMEDIATE | Direct message + team chat | Phone / video call | Within 1 hour |
| EMERGENCY | Phone / video call | In-person if co-located | Within 15 minutes |

## 4. Real-World Escalation Scenarios

### Scenario 1: Web-to-Cloud Pivot

**Situation**: The web application agent discovers a server-side request forgery (SSRF) vulnerability that can reach the AWS metadata endpoint. The cloud agent has independently mapped extensive IAM permissions.

**Escalation flow**:
1. Web agent classifies as IMMEDIATE (severity 8.5, cross-domain impact)
2. Web agent sends escalation to cloud agent with SSRF details
3. Cloud agent confirms IAM role attached to the vulnerable instance has S3 read access to a bucket containing customer PII
4. Both agents coordinate: web agent demonstrates SSRF PoC, cloud agent confirms data exfiltration path
5. Joint finding produced: "SSRF to AWS metadata to PII exfiltration" -- severity elevated to Critical (9.8)
6. Council review triggered for risk acceptance decision

**Key lesson**: Neither agent alone could demonstrate the full impact. The web agent saw the SSRF but lacked cloud context. The cloud agent saw the IAM permissions but lacked the exploitation path.

### Scenario 2: Network-to-Active-Directory Chain

**Situation**: The network agent discovers an unauthenticated SMB share containing configuration files with embedded credentials. The post-exploitation agent has been mapping Active Directory trust relationships.

**Escalation flow**:
1. Network agent classifies as COORDINATE (severity 7.2, cross-domain credential leak)
2. Network agent shares credential format and context (service account pattern: `svc_backup@corp.local`)
3. Post-exploitation agent cross-references with AD map -- the service account has Domain Admin equivalent privileges
4. Escalation upgraded to IMMEDIATE (compound severity 9.5)
5. Post-exploitation agent uses credentials to demonstrate full domain compromise
6. Joint finding: "Unauthenticated SMB share to Domain Admin compromise"

**Key lesson**: The severity jumped from 7.2 to 9.5 only after cross-domain correlation revealed the credential's AD privileges.

### Scenario 3: Container-to-Host-to-Cloud

**Situation**: The container security agent discovers a privileged container with docker.sock mounted. The cloud agent has mapped the host's IAM instance profile.

**Escalation flow**:
1. Container agent classifies as IMMEDIATE (container escape path confirmed)
2. Container agent demonstrates docker.sock escape to host root
3. Cloud agent identifies the host is an EC2 instance with an IAM role granting `sts:AssumeRole` into the production AWS account
4. Escalation upgraded to EMERGENCY (compound severity 10.0 -- host escape + cloud admin)
5. All agents pause non-critical work for coordinated response
6. Joint finding with immediate CISO notification

**Key lesson**: The container escape alone was serious (8.5). Combined with cloud IAM privileges, it became a maximum-severity finding requiring emergency response.

## 5. Escalation Tracking and Audit Trail

### Escalation Log Format

Every escalation is logged for audit and post-engagement review:

```json
{
  "escalation_id": "ESC-2026-0042",
  "timestamp": "2026-06-10T14:30:00Z",
  "level": "IMMEDIATE",
  "from_agent": "web-agent-01",
  "to_agents": ["cloud-agent-01", "network-agent-02"],
  "finding_ids": ["WEB-0042", "CLD-0015"],
  "severity": 8.5,
  "compound_severity": 9.8,
  "correlation_type": "credential_leak_and_exposed_service",
  "resolution": {
    "status": "resolved",
    "joint_finding_id": "JOINT-001",
    "final_severity": 9.8,
    "resolved_at": "2026-06-10T16:45:00Z",
    "resolution_method": "joint_investigation"
  }
}
```

### Metrics for Escalation Quality

Track these metrics to improve escalation processes over time:

| Metric | Target | Measurement |
|--------|--------|-------------|
| False escalation rate | < 10% | Escalations that did not produce compound findings |
| Escalation response time | Level-dependent | Time from escalation to first response |
| Correlation accuracy | > 80% | Correlated findings that produced valid compound risks |
| Coverage | 100% | Percentage of cross-domain findings that triggered escalation |
| Resolution time | < 4 hours for IMMEDIATE | Time from escalation to joint finding resolution |

## Practical Steps

1. **Set up the escalation communication channels** before the engagement begins. Ensure all agents know their domain boundaries and escalation triggers.
2. **Define correlation patterns** based on the engagement scope. Pre-load common patterns (credential+service, network+web, cloud+container) and add engagement-specific patterns.
3. **Implement the severity-based escalation protocol** using the `classify_escalation` function as a starting point. Customize the thresholds based on the client's risk appetite.
4. **Establish the escalation log** from the first day. Every escalation, even those that resolve as false positives, must be recorded for post-engagement analysis.
5. **Run escalation drills** during the engagement kickoff. Simulate a cross-domain finding and verify that the communication and response protocols work as expected.

## Hands-on Exercises

### Exercise 1: Escalation Classification Drill

Given 20 findings from a multi-agent assessment, classify each using the severity-based escalation protocol. Identify which findings require escalation, to what level, and which other agents should be notified. Include at least 5 findings that require cross-domain correlation.

### Exercise 2: Correlation Pattern Development

Design 3 new correlation patterns for a specific industry (e.g., healthcare: medical device vulnerability + PHI data flow, or finance: API key exposure + transaction system access). Implement the pattern matching logic and test with sample findings.

### Exercise 3: Escalation Communication Practice

Practice writing escalation messages for each of the three real-world scenarios described above. Exchange messages with a partner and evaluate clarity, completeness, and actionability.

## References

- [NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) - Incident escalation framework
- [MITRE ATT&CK: Lateral Movement](https://attack.mitre.org/tactics/TA0008/) - Cross-domain attack techniques
- [SANS: Incident Handler's Handbook](https://www.sans.org/white-papers/33901/) - Practical escalation procedures
- [FIRST: CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document) - Severity scoring standards
- [CISA: Cybersecurity Incident Severity Schema](https://www.cisa.gov/news-events/news/cisa-cybersecurity-incident-severity-schema) - Government escalation model
- [OWASP: Security Incident Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/) - Web incident coordination
