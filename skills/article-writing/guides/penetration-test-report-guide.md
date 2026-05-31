# Penetration Test Report Guide

> Techniques for writing professional penetration test reports including executive summaries, methodology documentation, findings with evidence, risk ratings, and remediation timelines that communicate value to both technical and business audiences.

---

## 1. Report Structure and Executive Summary

The executive summary is the most-read section of any pentest report. It must communicate risk in business terms without requiring technical knowledge to understand.

```markdown
# Penetration Test Report
## Executive Summary

**Client:** Acme Corporation
**Assessment Period:** March 1-15, 2025
**Scope:** External network, web applications, internal pivot
**Classification:** CONFIDENTIAL

### Overall Risk Rating: HIGH

During the authorized penetration test of Acme Corporation's external
infrastructure, the assessment team identified **23 vulnerabilities**
across **4 severity levels**:

| Severity | Count | Examples |
|----------|-------|----------|
| Critical | 3 | Unauthenticated RCE, SQL injection with data access |
| High | 7 | Authentication bypass, privilege escalation |
| Medium | 9 | Information disclosure, missing security headers |
| Low | 4 | Verbose error messages, outdated software versions |

### Key Findings

1. **Complete database compromise** via SQL injection in the customer
   portal (CRITICAL) — attacker can extract all customer records
2. **Domain admin access** achieved within 4 hours of initial foothold
   through credential reuse and Kerberoasting (CRITICAL)
3. **No network segmentation** between DMZ and internal corporate
   network — single compromise leads to full internal access (HIGH)

### Business Impact

An external attacker with no prior access could compromise the entire
Active Directory domain within one business day. This would result in
access to all customer data (~2M records), financial systems, and the
ability to deploy ransomware across all endpoints.
```

---

## 2. Methodology Documentation

```markdown
## Methodology

This assessment followed the PTES (Penetration Testing Execution Standard)
framework with the following phases:

### Phase Overview

| Phase | Duration | Activities |
|-------|----------|------------|
| Reconnaissance | 2 days | OSINT, DNS enumeration, service discovery |
| Vulnerability Analysis | 3 days | Automated scanning, manual testing |
| Exploitation | 5 days | Vulnerability exploitation, pivot attempts |
| Post-Exploitation | 3 days | Privilege escalation, lateral movement |
| Reporting | 2 days | Documentation, evidence compilation |

### Tools Used

| Category | Tools |
|----------|-------|
| Reconnaissance | Nmap, Amass, Subfinder, Shodan |
| Web Testing | Burp Suite Pro, SQLMap, Nuclei |
| Exploitation | Metasploit, custom scripts |
| Post-Exploitation | BloodHound, Mimikatz, CrackMapExec |
| Reporting | Custom templates, Dradis |

### Scope Boundaries

- **In Scope:** 10.0.0.0/16, *.acme.com, AWS account 123456789
- **Out of Scope:** Production database (read-only testing permitted)
- **Rules of Engagement:** No DoS, no social engineering of executives
- **Testing Window:** Business hours (09:00-18:00 EST) for active exploitation
```

---

## 3. Finding Documentation with Evidence

Each finding must include sufficient evidence for the client to reproduce the issue and verify the fix. Screenshots, request/response pairs, and command output provide proof.

```markdown
## Finding: SQL Injection in Customer Portal

### Metadata

| Field | Value |
|-------|-------|
| ID | ACME-2025-001 |
| Severity | CRITICAL |
| CVSS 3.1 | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | CWE-89: SQL Injection |
| Affected Asset | https://portal.acme.com/api/search |
| Status | Open |

### Description

The search endpoint accepts user input in the `query` parameter without
parameterization, allowing an attacker to inject arbitrary SQL statements.
The application uses a MySQL 8.0 backend with the `portal_db` database.

### Proof of Concept

**Request:**
```http
POST /api/search HTTP/1.1
Host: portal.acme.com
Content-Type: application/json

{"query": "test' UNION SELECT username,password,email,NULL FROM users-- -"}
```

**Response (truncated):**
```json
{
  "results": [
    {"name": "admin", "description": "$2b$12$LJ3m4...", "email": "admin@acme.com"},
    {"name": "jsmith", "description": "$2b$12$Kp9x...", "email": "j.smith@acme.com"}
  ]
}
```

### Impact

- Full read access to all database tables (users, orders, payments)
- Write access enables data modification and potential RCE via INTO OUTFILE
- 2.1 million customer records exposed including PII and hashed passwords

### Remediation

1. Implement parameterized queries (prepared statements)
2. Apply input validation with allowlist for search characters
3. Implement WAF rules as immediate mitigation
4. Review all database queries for similar patterns
```

---

## 4. Risk Rating Framework

```python
def calculate_risk_rating(likelihood, impact):
    """Calculate risk rating using likelihood x impact matrix.

    Likelihood: 1 (Unlikely) to 5 (Almost Certain)
    Impact: 1 (Negligible) to 5 (Catastrophic)
    """
    risk_matrix = {
        (5, 5): "CRITICAL", (5, 4): "CRITICAL", (4, 5): "CRITICAL",
        (4, 4): "HIGH",     (5, 3): "HIGH",     (3, 5): "HIGH",
        (3, 4): "HIGH",     (4, 3): "HIGH",     (5, 2): "MEDIUM",
        (3, 3): "MEDIUM",   (4, 2): "MEDIUM",   (2, 4): "MEDIUM",
        (2, 5): "HIGH",     (1, 5): "MEDIUM",   (5, 1): "MEDIUM",
        (2, 3): "MEDIUM",   (3, 2): "MEDIUM",   (4, 1): "LOW",
        (1, 4): "LOW",      (2, 2): "LOW",      (3, 1): "LOW",
        (1, 3): "LOW",      (2, 1): "LOW",      (1, 2): "LOW",
        (1, 1): "INFO",
    }

    rating = risk_matrix.get((likelihood, impact), "UNKNOWN")

    justification = {
        "likelihood": likelihood,
        "likelihood_factors": [
            "Skill level required",
            "Availability of exploit code",
            "Authentication requirements",
            "Network accessibility",
        ],
        "impact": impact,
        "impact_factors": [
            "Data sensitivity",
            "System criticality",
            "Regulatory implications",
            "Recovery difficulty",
        ],
        "overall_risk": rating,
    }

    return justification
```

---

## 5. Remediation Timeline

```yaml
# Remediation plan with prioritized timeline
remediation_plan:
  immediate_actions:  # Within 24-48 hours
    - id: ACME-2025-001
      finding: "SQL Injection in Customer Portal"
      action: "Deploy WAF rule blocking UNION/SELECT in search parameter"
      owner: "Security Operations"
      deadline: "2025-03-17"

    - id: ACME-2025-003
      finding: "Unauthenticated RCE via file upload"
      action: "Disable file upload endpoint until fix deployed"
      owner: "Platform Engineering"
      deadline: "2025-03-17"

  short_term:  # Within 1-2 weeks
    - id: ACME-2025-001
      action: "Implement parameterized queries across all endpoints"
      owner: "Backend Development"
      deadline: "2025-03-29"
      verification: "Retest with SQLMap to confirm fix"

    - id: ACME-2025-005
      finding: "Credential reuse across services"
      action: "Force password reset, implement unique service accounts"
      owner: "Identity & Access Management"
      deadline: "2025-03-29"

  medium_term:  # Within 1-3 months
    - id: ACME-2025-008
      finding: "No network segmentation"
      action: "Implement VLAN segmentation between DMZ and internal"
      owner: "Network Engineering"
      deadline: "2025-05-15"

    - id: ACME-2025-010
      finding: "Missing endpoint detection"
      action: "Deploy EDR solution to all endpoints"
      owner: "Security Operations"
      deadline: "2025-06-01"

  long_term:  # Within 3-6 months
    - finding: "Systemic secure coding gaps"
      action: "Implement SAST/DAST in CI/CD pipeline"
      owner: "DevSecOps"
      deadline: "2025-09-01"
```

---

## 6. Attack Narrative

The attack narrative tells the story of the engagement chronologically, showing how individual vulnerabilities chain together to achieve significant impact.

```markdown
## Attack Narrative

### Initial Access (Day 1)

1. **Reconnaissance** revealed `portal.acme.com` running outdated
   Apache Tomcat 9.0.43 with exposed manager interface.

2. **SQL injection** in the search API (ACME-2025-001) provided
   database credentials stored in the `config` table:
   ```
   db_user: portal_svc
   db_pass: P0rtal$vc2024!
   ```

3. **Credential reuse** — the database password was identical to the
   SSH password for the portal server (10.0.1.15).

### Lateral Movement (Day 2-3)

4. From the portal server, **internal network scanning** revealed
   no segmentation — all 10.0.0.0/16 hosts reachable.

5. **Kerberoasting** against Active Directory yielded 12 service
   account TGS tickets. Offline cracking recovered 4 passwords
   within 6 hours using hashcat with rockyou + rules.

6. Service account `svc_backup` had **Domain Admin** privileges
   (misconfigured group membership).

### Domain Compromise (Day 4)

7. Using Domain Admin access, performed **DCSync** to extract
   all domain password hashes (NTDS.dit equivalent).

8. Verified access to financial systems, HR database, and
   source code repositories — full organizational compromise.

**Time from initial access to domain admin: 3 days, 7 hours**
```

---

## 7. Report Generation Automation

```bash
# Generate pentest report from structured findings data
# Uses pandoc for multi-format output

# Convert YAML findings to formatted markdown report
python3 << 'PYTHON'
import yaml
from datetime import datetime

with open("findings.yaml") as f:
    findings = yaml.safe_load(f)

# Sort by severity
severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

# Generate statistics
stats = {}
for f in findings:
    stats[f["severity"]] = stats.get(f["severity"], 0) + 1

print(f"# Findings Summary")
print(f"\nTotal: {len(findings)} findings")
print(f"Generated: {datetime.now().strftime('%Y-%m-%d')}\n")
print("| Severity | Count |")
print("|----------|-------|")
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
    if sev in stats:
        print(f"| {sev} | {stats[sev]} |")
PYTHON

# Convert to PDF with professional formatting
pandoc report.md -o report.pdf \
  --template=eisvogel \
  --pdf-engine=xelatex \
  -V colorlinks=true \
  -V header-includes="\usepackage{fancyhdr}" \
  --metadata title="Penetration Test Report" \
  --metadata author="Security Assessment Team" \
  --metadata date="$(date +%Y-%m-%d)" \
  --toc --toc-depth=3
```

---

## Summary

| Section | Purpose | Audience |
|---------|---------|----------|
| Executive Summary | Business risk overview | C-suite, board |
| Methodology | Scope and approach documentation | Compliance, legal |
| Findings | Technical vulnerability details | Security engineers |
| Risk Ratings | Prioritization framework | Risk management |
| Remediation Plan | Actionable fix timeline | Engineering teams |
| Attack Narrative | Kill chain demonstration | Security leadership |

Write reports that tell a story: start with business impact, demonstrate the attack path, provide evidence, and end with clear remediation priorities. The report should justify the engagement's value and drive action.
