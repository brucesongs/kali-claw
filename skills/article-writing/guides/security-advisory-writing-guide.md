# Security Advisory Writing Guide

> Techniques for writing professional security advisories including CVE format compliance, CVSS scoring methodology, impact assessment, remediation guidance, and responsible disclosure timelines.

---

## 1. CVE Advisory Structure

A well-structured security advisory follows a standardized format that enables automated parsing, consistent risk communication, and clear remediation paths. The CVE format provides the foundation.

```yaml
# Security Advisory Template (machine-readable YAML front matter)
advisory:
  id: "CVE-2025-XXXXX"
  title: "Remote Code Execution via Deserialization in Widget API"
  severity: CRITICAL
  cvss_v3_1:
    score: 9.8
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cwe: "CWE-502: Deserialization of Untrusted Data"
  affected:
    - vendor: "ExampleCorp"
      product: "Widget Platform"
      versions:
        - ">= 3.0.0, < 3.4.7"
        - ">= 4.0.0, < 4.1.2"
  fixed_versions:
    - "3.4.7"
    - "4.1.2"
  discovery_date: "2025-03-15"
  disclosure_date: "2025-04-15"
  reporter: "Security Research Team"
  references:
    - "https://example.com/security/advisory-2025-001"
    - "https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"
```

---

## 2. CVSS v3.1 Scoring

CVSS scoring requires precise evaluation of attack characteristics. Each metric must be justified with evidence from the vulnerability analysis.

```bash
# CVSS v3.1 metric breakdown for scoring
# Attack Vector (AV): Network (N), Adjacent (A), Local (L), Physical (P)
# Attack Complexity (AC): Low (L), High (H)
# Privileges Required (PR): None (N), Low (L), High (H)
# User Interaction (UI): None (N), Required (R)
# Scope (S): Unchanged (U), Changed (C)
# Confidentiality (C): None (N), Low (L), High (H)
# Integrity (I): None (N), Low (L), High (H)
# Availability (A): None (N), Low (L), High (H)

# Example: Calculate CVSS for an unauthenticated RCE
# AV:N - exploitable over the network
# AC:L - no special conditions required
# PR:N - no authentication needed
# UI:N - no user interaction required
# S:U  - impact limited to vulnerable component
# C:H  - full read access to system data
# I:H  - full write access / code execution
# A:H  - can crash or deny service

# Resulting vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8

# Use cvss library for programmatic calculation
pip install cvss
python3 -c "
from cvss import CVSS3
v = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
print(f'Base Score: {v.base_score}')
print(f'Severity: {v.severities()[0]}')
"
```

---

## 3. Impact Assessment Writing

The impact section must clearly communicate business risk to both technical and non-technical stakeholders. Quantify impact where possible.

```markdown
## Impact Assessment

### Technical Impact

An unauthenticated attacker can execute arbitrary code on the application
server by sending a crafted serialized object to the `/api/v2/widgets`
endpoint. Successful exploitation grants the attacker the same privileges
as the application service account (typically `www-data` or equivalent).

**Demonstrated capabilities:**
- Read/write access to application database (customer PII, credentials)
- Lateral movement to internal services via service mesh
- Exfiltration of environment variables containing API keys and secrets

### Business Impact

| Impact Category | Severity | Description |
|----------------|----------|-------------|
| Data Breach | HIGH | Customer PII accessible (GDPR/CCPA implications) |
| Service Disruption | MEDIUM | Attacker can terminate application processes |
| Reputation | HIGH | Public-facing API, exploitation leaves access logs |
| Financial | HIGH | Regulatory fines, incident response costs |

### Affected Deployments

Based on Shodan/Censys analysis, approximately 2,400 internet-facing
instances run vulnerable versions. Of these, ~800 expose the affected
endpoint without WAF protection.
```

---

## 4. Remediation Guidance

```markdown
## Remediation

### Immediate Mitigation (if patching is not immediately possible)

1. **WAF Rule**: Block requests to `/api/v2/widgets` containing serialized
   Java objects (Content-Type: application/x-java-serialized-object)

   ```nginx
   # Nginx WAF rule
   location /api/v2/widgets {
       if ($content_type ~* "java-serialized") {
           return 403;
       }
   }
   ```

2. **Network Segmentation**: Restrict access to the affected endpoint to
   trusted IP ranges only.

3. **Monitoring**: Deploy detection rule for exploitation attempts:
   ```yaml
   # Sigma detection rule
   title: Widget API Deserialization Attempt
   logsource:
     category: webserver
   detection:
     selection:
       cs-uri-stem|contains: '/api/v2/widgets'
       cs-content-type|contains: 'serialized'
     condition: selection
   level: critical
   ```

### Permanent Fix

Upgrade to patched versions:
- Branch 3.x: upgrade to **3.4.7** or later
- Branch 4.x: upgrade to **4.1.2** or later

Verify the fix:
```bash
# Confirm patched version is deployed
curl -s https://target/api/version | jq '.version'

# Verify deserialization is blocked (should return 400)
curl -X POST https://target/api/v2/widgets \
  -H "Content-Type: application/x-java-serialized-object" \
  -d @payload.bin -o /dev/null -w "%{http_code}"
```
```

---

## 5. Responsible Disclosure Timeline

```markdown
## Disclosure Timeline

| Date | Action |
|------|--------|
| 2025-03-15 | Vulnerability discovered during routine security assessment |
| 2025-03-16 | Initial report sent to vendor security team (security@example.com) |
| 2025-03-17 | Vendor acknowledged receipt, assigned internal tracking ID |
| 2025-03-22 | Vendor confirmed vulnerability, began developing patch |
| 2025-04-01 | Vendor provided patch for review, CVE reserved (CVE-2025-XXXXX) |
| 2025-04-08 | Patch verified by researcher, fix confirmed effective |
| 2025-04-10 | Patched versions released (3.4.7, 4.1.2) |
| 2025-04-15 | Public disclosure (30-day window from initial report) |
| 2025-04-15 | NVD entry published |

### Disclosure Policy

This advisory follows a 90-day coordinated disclosure policy:
- Vendor is given 90 days from initial report to release a fix
- If vendor is unresponsive after 14 days, CERT/CC is contacted
- Public disclosure occurs after patch is available OR 90 days elapsed
- Critical vulnerabilities under active exploitation: 7-day accelerated timeline
```

---

## 6. Advisory Quality Checklist

```python
def validate_advisory(advisory):
    """Validate security advisory completeness before publication."""
    required_fields = [
        "cve_id", "title", "cvss_vector", "cvss_score",
        "cwe_id", "affected_versions", "fixed_versions",
        "description", "impact", "remediation",
        "discovery_date", "disclosure_date", "references"
    ]

    issues = []

    for field in required_fields:
        if field not in advisory or not advisory[field]:
            issues.append(f"MISSING: {field}")

    # Validate CVSS vector format
    cvss = advisory.get("cvss_vector", "")
    if not cvss.startswith("CVSS:3.1/"):
        issues.append("INVALID: CVSS vector must use v3.1 format")

    # Validate score matches vector
    if advisory.get("cvss_score"):
        from cvss import CVSS3
        calculated = CVSS3(cvss).base_score
        if abs(calculated - advisory["cvss_score"]) > 0.1:
            issues.append(f"MISMATCH: stated score {advisory['cvss_score']} != calculated {calculated}")

    # Validate disclosure timeline
    if advisory.get("discovery_date") and advisory.get("disclosure_date"):
        from datetime import datetime
        discovered = datetime.strptime(advisory["discovery_date"], "%Y-%m-%d")
        disclosed = datetime.strptime(advisory["disclosure_date"], "%Y-%m-%d")
        gap = (disclosed - discovered).days
        if gap < 30:
            issues.append(f"WARNING: Only {gap} days between discovery and disclosure")
        if gap > 90:
            issues.append(f"NOTE: {gap} days elapsed (exceeds standard 90-day policy)")

    return {"valid": len(issues) == 0, "issues": issues}
```

---

## 7. Multi-Format Advisory Output

```bash
# Generate advisory in multiple formats for different audiences

# JSON format for automation and vulnerability scanners
cat advisory.yaml | python3 -c "
import yaml, json, sys
data = yaml.safe_load(sys.stdin)
print(json.dumps(data, indent=2))
" > advisory.json

# Markdown format for human readers and GitHub Security Advisories
cat << 'TEMPLATE' > advisory.md
# ${TITLE}

**CVE ID:** ${CVE_ID}
**CVSS Score:** ${CVSS_SCORE} (${SEVERITY})
**Vector:** \`${CVSS_VECTOR}\`

## Summary
${DESCRIPTION}

## Affected Versions
${AFFECTED_TABLE}

## Remediation
${REMEDIATION}

## References
${REFERENCES}
TEMPLATE

# CSAF (Common Security Advisory Framework) for enterprise consumption
# Validates against OASIS CSAF 2.0 schema
pip install csaf-validator
csaf-validator --input advisory-csaf.json --profile mandatory
```

---

## Summary

| Component | Purpose | Audience |
|-----------|---------|----------|
| CVE ID + CVSS | Standardized identification and scoring | Vulnerability management teams |
| Impact assessment | Business risk communication | Executives, risk managers |
| Technical details | Root cause and exploitation path | Security engineers |
| Remediation | Actionable fix guidance | Operations, developers |
| Timeline | Disclosure coordination record | Legal, compliance |

Write advisories that serve all audiences: lead with severity and business impact, provide technical depth for engineers, and include clear remediation steps with verification commands.
