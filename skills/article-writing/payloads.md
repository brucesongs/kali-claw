# Article Writing Payloads

Templates, snippets, and formatting conventions for all article types.

---

## CVSS Calculator Commands

```bash
# Calculate CVSS 3.1 score
# Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# Key:
# AV: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
# AC: Attack Complexity (L=Low, H=High)
# PR: Privileges Required (N=None, L=Low, H=High)
# UI: User Interaction (N=None, R=Required)
# S: Scope (U=Unchanged, C=Changed)
# C: Confidentiality Impact (N=None, L=Low, H=High)
# I: Integrity Impact (N=None, L=Low, H=High)
# A: Availability Impact (N=None, L=Low, H=High)

# Examples:
# SQL Injection (remote, no auth, high impact):
#   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 (Critical)

# Stored XSS (requires auth):
#   CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N → 5.4 (Medium)

# Local Privilege Escalation:
#   CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H → 7.8 (High)

# Use online calculator: https://www.first.org/cvss/calculator/3.1
```

---

## Sanitization Checklist

Before publishing or sharing any report:

```bash
# 1. Replace real IPs with RFC 5737 documentation IPs
# Real: 192.168.1.100 → Sanitized: 203.0.113.42
# Real: 10.0.0.5 → Sanitized: 198.51.100.5

# 2. Replace real domains with example.com
# Real: target.com → Sanitized: target.example.com
# Real: api.target.com → Sanitized: api.example.com

# 3. Redact real credentials
# Real: admin:P@ssw0rd123 → Sanitized: [REDACTED]:[REDACTED]
# Real: AKIA... → Sanitized: [AWS_ACCESS_KEY_REDACTED]

# 4. Anonymize people
# Real: John Smith <john@target.com> → Sanitized: [Admin User] <admin@example.com>

# 5. Remove metadata from screenshots
exiftool -all= screenshot.png

# 6. Check for leaks in code snippets
grep -rn "password\|secret\|key\|token" draft_report.md | grep -v "REDACTED"
```

---

## Severity Classification

| Severity | CVSS Range | Criteria |
|----------|-----------|----------|
| **Critical** | 9.0-10.0 | Unauthenticated remote code execution, complete system compromise, mass data breach |
| **High** | 7.0-8.9 | Authenticated RCE, SQL injection with data access, privilege escalation to admin |
| **Medium** | 4.0-6.9 | XSS, CSRF, information disclosure, auth bypass (limited scope) |
| **Low** | 0.1-3.9 | Minor info leak, self-XSS, low-impact misconfig |
| **Informational** | 0.0 | Best practice violation, no direct exploit path |

---

## Finding Description Templates

### SQL Injection

```markdown
The application is vulnerable to SQL injection in the [location] via the [parameter] parameter. By injecting SQL metacharacters, an attacker can modify the backend query structure, leading to unauthorized data access, modification, or deletion.

**Root Cause**: User input is concatenated directly into SQL queries without parameterization or escaping.

**Proof of Concept**:
```

bash
# Inject single quote to trigger error
curl "https://example.com/search?q=test'"

# Expected: no error
# Actual: MySQL syntax error reveals query structure

# Boolean-based blind SQLi
curl "https://example.com/search?q=1' AND '1'='1"  # True condition
curl "https://example.com/search?q=1' AND '1'='2"  # False condition

# Time-based blind SQLi
curl "https://example.com/search?q=1' AND SLEEP(5)--"
```

**Impact**: Complete database compromise — attacker can read, modify, or delete all data, including user credentials and sensitive records.

**Remediation**:
1. Use parameterized queries (prepared statements)
2. Apply input validation and whitelist allowed characters
3. Use ORM with built-in protections
4. Implement least-privilege database accounts
```

### Cross-Site Scripting (XSS)

```markdown
The application reflects user input without sanitization in the [location], enabling Cross-Site Scripting (XSS) attacks. An attacker can inject malicious JavaScript that executes in the victim's browser, leading to session hijacking, phishing, or defacement.

**Type**: [Reflected / Stored / DOM-based]

**Proof of Concept**:
```

bash
# Reflected XSS
curl "https://example.com/search?q=<script>alert(document.cookie)</script>"

# Payload in response:
# <div>Results for: <script>alert(document.cookie)</script></div>
```

**Impact**: 
- Session token theft via `document.cookie`
- Keylogging via event listeners
- Phishing via fake login forms

**Remediation**:
1. HTML-encode all user input before output
2. Use Content Security Policy (CSP) headers
3. Set `HttpOnly` flag on session cookies
4. Implement output context-aware escaping
```

### Authentication Bypass

```markdown
The application's authentication mechanism can be bypassed by [method], allowing an attacker to gain unauthorized access to [protected resources].

**Root Cause**: [Logic flaw / Missing auth check / Client-side validation only]

**Proof of Concept**:
```

bash
# Bypass via SQL injection in login form
username=' OR '1'='1'-- -
password=[anything]

# Bypass via JWT null signature
# Decode JWT, set alg=none, remove signature, re-encode

# Bypass via direct URL access (missing auth check)
curl "https://example.com/admin/dashboard" -H "Cookie: [no session]"
```

**Impact**: Complete authentication bypass — attacker gains access to protected resources without valid credentials.

**Remediation**:
1. Implement server-side authentication checks on all protected endpoints
2. Use parameterized queries for login validation
3. Validate JWT signature and algorithm
4. Enforce authentication middleware globally
```

---

## Impact Statement Templates

### High Impact

```
This vulnerability allows an unauthenticated remote attacker to:
- Execute arbitrary code on the server
- Access all database records, including user credentials
- Modify or delete production data
- Pivot to internal network systems

The vulnerability affects [X] systems and [Y] user accounts. A successful exploit would result in:
- Complete confidentiality breach (all data exposed)
- Data integrity compromise (attacker can modify records)
- Service disruption (attacker can delete critical data)
```

### Medium Impact

```
This vulnerability allows an authenticated user to:
- Escalate privileges from [user role] to [admin role]
- Access resources belonging to other users
- Inject malicious scripts affecting other users

The attack requires [conditions], limiting exploitation in the wild. However, a successful exploit grants:
- Unauthorized data access within the application
- Potential session hijacking of other users
```

### Low Impact

```
This vulnerability discloses non-sensitive information that could aid further attacks:
- Server version and technology stack
- Internal file paths
- Error messages revealing query structure

While not directly exploitable, this information reduces the cost of reconnaissance for an attacker and should be mitigated as a defense-in-depth measure.
```

---

## Remediation Code Snippets

### SQL Injection Fix (Python)

```python
# BEFORE (vulnerable)
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# AFTER (fixed)
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
```

### XSS Fix (JavaScript/React)

```jsx
// BEFORE (vulnerable)
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// AFTER (fixed)
<div>{userInput}</div>  // React auto-escapes
```

### Auth Check Fix (Go)

```go
// BEFORE (vulnerable - no auth check)
func AdminHandler(w http.ResponseWriter, r *http.Request) {
    // Admin logic here
}

// AFTER (fixed)
func AdminHandler(w http.ResponseWriter, r *http.Request) {
    user := GetCurrentUser(r)
    if !user.IsAdmin {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    // Admin logic here
}
```

---

## Report Metadata

Include at the top of every report:

```yaml
---
report_type: penetration_test
client: Example Corp
engagement_dates: 2026-05-01 to 2026-05-15
version: 1.0
classification: Confidential
authors: [Security Team]
reviewed_by: [Senior Consultant]
---
```

---

## Markdown Conversion Commands

```bash
# Convert Markdown to PDF (using pandoc)
pandoc report.md -o report.pdf \
  --pdf-engine=xelatex \
  --toc \
  --number-sections \
  -V geometry:margin=1in

# With custom template
pandoc report.md -o report.pdf \
  --template=pentest_template.tex \
  --pdf-engine=xelatex

# Convert to DOCX (for client edits)
pandoc report.md -o report.docx

# Convert to HTML
pandoc report.md -o report.html --standalone --toc
```

---

## Style Guide

- **Use active voice**: "The application exposes..." not "It was found that..."
- **Be specific**: "search.php line 34" not "the search functionality"
- **Severity first**: Lead with impact, not technical minutiae
- **Evidence-based**: Every claim backed by screenshot/log/command
- **Action-oriented**: "Fix by..." not "It would be good to consider..."

---

## Automated Report Generation

### Finding Aggregation Script

```python
import json
import glob

def aggregate_findings(evidence_dir):
    findings = []
    for f in glob.glob(f"{evidence_dir}/*.json"):
        with open(f) as fh:
            data = json.load(fh)
            findings.append({
                "id": data["id"],
                "title": data["title"],
                "severity": data["severity"],
                "cvss": data["cvss_score"],
                "affected": data["affected_component"],
                "status": data.get("status", "open")
            })
    return sorted(findings, key=lambda x: x["cvss"], reverse=True)
```

### Markdown Report Builder

```python
def build_report(findings, metadata):
    report = f"# Penetration Test Report\n\n"
    report += f"**Client**: {metadata['client']}\n"
    report += f"**Date**: {metadata['date']}\n\n"
    report += "## Executive Summary\n\n"
    report += f"Identified {len(findings)} vulnerabilities: "
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f['severity'], []).append(f)
    for sev in ['Critical', 'High', 'Medium', 'Low']:
        count = len(by_sev.get(sev, []))
        if count:
            report += f"{count} {sev}, "
    report += "\n\n## Findings\n\n"
    for f in findings:
        report += f"### {f['id']}: {f['title']}\n\n"
        report += f"**Severity**: {f['severity']} (CVSS {f['cvss']})\n\n"
    return report
```

### Evidence Screenshot Automation

```bash
# Capture evidence screenshots with timestamp overlay
screenshot_with_timestamp() {
    local url=$1
    local output=$2
    chromium --headless --screenshot="$output" \
        --window-size=1920,1080 "$url"
    convert "$output" -gravity SouthEast \
        -annotate +10+10 "$(date -u '+%Y-%m-%d %H:%M UTC')" "$output"
}

screenshot_with_timestamp "http://target/vuln-page" "evidence_001.png"
```

### Template Engine Report Pipeline

```python
#!/usr/bin/env python3
"""End-to-end report generation pipeline using Jinja2 templates.
Aggregates findings from multiple sources, applies templates, and outputs final report."""

import json
import glob
import os
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("Install jinja2: pip install jinja2")
    exit(1)

TEMPLATE_DIR = "templates/reports"
OUTPUT_DIR = "output/reports"

def load_findings(evidence_dir):
    """Load and normalize findings from multiple evidence formats."""
    findings = []
    # JSON findings
    for f in sorted(glob.glob(f"{evidence_dir}/**/*.json", recursive=True)):
        with open(f) as fh:
            data = json.load(fh)
            findings.append({
                "id": data.get("id", os.path.basename(f)),
                "title": data["title"],
                "severity": data["severity"],
                "cvss_score": data.get("cvss_score", 0.0),
                "cvss_vector": data.get("cvss_vector", ""),
                "description": data.get("description", ""),
                "impact": data.get("impact", ""),
                "remediation": data.get("remediation", ""),
                "evidence_files": data.get("evidence", []),
                "affected": data.get("affected_component", "Unknown"),
                "status": data.get("status", "open"),
                "source_file": f
            })
    return sorted(findings, key=lambda x: x["cvss_score"], reverse=True)

def generate_report(engagement_id, evidence_dir, template_name="pentest_report.md.j2"):
    """Generate full report from template and findings."""
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(template_name)

    findings = load_findings(evidence_dir)
    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    context = {
        "engagement_id": engagement_id,
        "generated_at": datetime.now().isoformat(),
        "findings": findings,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "critical_count": severity_counts.get("Critical", 0),
        "high_count": severity_counts.get("High", 0),
    }

    output = template.render(**context)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = f"{OUTPUT_DIR}/{engagement_id}-report.md"
    with open(output_path, "w") as f:
        f.write(output)
    print(f"[REPORT] Generated: {output_path} ({len(findings)} findings)")
    return output_path

if __name__ == "__main__":
    import sys
    eng_id = sys.argv[1] if len(sys.argv) > 1 else "ENG-001"
    evidence = sys.argv[2] if len(sys.argv) > 2 else "evidence/"
    generate_report(eng_id, evidence)
```

### Multi-Format Export Pipeline

```bash
#!/bin/bash
# Export generated report to multiple formats (PDF, DOCX, HTML)
# Requires: pandoc, xelatex, wkhtmltopdf

REPORT_MD="${1:-output/reports/ENG-001-report.md}"
BASENAME=$(basename "$REPORT_MD" .md)
OUTPUT_DIR="output/exports"
mkdir -p "$OUTPUT_DIR"

echo "[EXPORT] Converting $REPORT_MD to multiple formats"

# PDF with table of contents and custom margins
pandoc "$REPORT_MD" -o "$OUTPUT_DIR/${BASENAME}.pdf" \
  --pdf-engine=xelatex \
  --toc --toc-depth=3 \
  --number-sections \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  -V colorlinks=true \
  --highlight-style=tango \
  --metadata title="Penetration Test Report"

# DOCX for client editing
pandoc "$REPORT_MD" -o "$OUTPUT_DIR/${BASENAME}.docx" \
  --toc --number-sections \
  --reference-doc=templates/reference.docx 2>/dev/null || \
pandoc "$REPORT_MD" -o "$OUTPUT_DIR/${BASENAME}.docx" --toc

# Standalone HTML with embedded styles
pandoc "$REPORT_MD" -o "$OUTPUT_DIR/${BASENAME}.html" \
  --standalone --toc \
  --css=templates/report-style.css 2>/dev/null || \
pandoc "$REPORT_MD" -o "$OUTPUT_DIR/${BASENAME}.html" --standalone --toc

echo "[EXPORT] Generated:"
ls -la "$OUTPUT_DIR/${BASENAME}".*
echo "[EXPORT] Done. All formats available in $OUTPUT_DIR/"
```

### Findings Deduplication and Merge

```python
def deduplicate_findings(findings, similarity_threshold=0.8):
    """Remove duplicate findings based on title and affected component similarity.
    Merges evidence from duplicates into the primary finding."""
    unique = []
    seen_keys = set()

    for finding in findings:
        # Create dedup key from normalized title + component
        key = f"{finding['title'].lower().strip()}|{finding['affected'].lower().strip()}"
        words = set(key.split())

        is_duplicate = False
        for seen_key in seen_keys:
            seen_words = set(seen_key.split())
            overlap = len(words & seen_words) / max(len(words | seen_words), 1)
            if overlap >= similarity_threshold:
                # Merge evidence into existing finding
                for u in unique:
                    u_key = f"{u['title'].lower().strip()}|{u['affected'].lower().strip()}"
                    if u_key == seen_key:
                        u["evidence_files"].extend(finding.get("evidence_files", []))
                        break
                is_duplicate = True
                break

        if not is_duplicate:
            seen_keys.add(key)
            unique.append(finding)

    removed = len(findings) - len(unique)
    if removed:
        print(f"[DEDUP] Merged {removed} duplicate findings into {len(unique)} unique entries")
    return unique
```

---

## Advisory Bulletin Templates

### CERT-Style Advisory Header

```markdown
## Advisory: [CVE-YYYY-NNNNN] [Vulnerability Title]

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-YYYY-NNNNN |
| **Severity** | Critical (CVSS 9.8) |
| **Affected Product** | Product Name v1.0 - v2.3 |
| **Fixed Version** | v2.4+ |
| **Vendor** | Vendor Name |
| **Published** | YYYY-MM-DD |
| **Last Updated** | YYYY-MM-DD |

### Summary

[One paragraph describing the vulnerability and its impact]

### Affected Versions

| Version Range | Status |
|---------------|--------|
| < 2.4 | Vulnerable |
| >= 2.4 | Fixed |

### Mitigation

[Immediate steps if patching is not possible]

### References

- [Vendor Advisory](https://example.com/advisory)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN)
```

### Internal Security Alert Template

```markdown
## INTERNAL SECURITY ALERT — [SEVERITY]

**Alert ID**: SA-YYYY-NNN
**Date**: YYYY-MM-DD
**Affected Systems**: [list]
**Action Required By**: YYYY-MM-DD

### What Happened

[2-3 sentences describing the issue]

### Who Is Affected

[Teams, services, or user groups impacted]

### What To Do

1. [Immediate action]
2. [Follow-up action]
3. [Verification step]

### Contact

Security Team: security@company.com | Slack: #security-incidents
```

---

## Comparison Article Patterns

### Tool Evaluation Matrix Template

```markdown
| Criteria | Weight | Tool A | Tool B | Tool C |
|----------|--------|--------|--------|--------|
| Detection Rate | 30% | 85% | 92% | 78% |
| False Positive Rate | 25% | 12% | 8% | 22% |
| Scan Speed (1K files) | 15% | 45s | 120s | 30s |
| CI/CD Integration | 15% | Native | Plugin | API only |
| Cost (annual) | 15% | $5K | $12K | Free |
| **Weighted Score** | 100% | **78.5** | **84.2** | **71.0** |
```

### Benchmark Test Script

```bash
#!/bin/bash
# Benchmark security tools against known-vulnerable codebase

VULN_REPO="./benchmark-app"  # Contains 50 known vulns
RESULTS_DIR="./benchmark-results"
mkdir -p "$RESULTS_DIR"

# Tool A
echo "Running Tool A..."
time tool_a scan "$VULN_REPO" --format json > "$RESULTS_DIR/tool_a.json" 2>&1
TOOL_A_FINDINGS=$(jq '.findings | length' "$RESULTS_DIR/tool_a.json")
echo "Tool A: $TOOL_A_FINDINGS findings"

# Tool B
echo "Running Tool B..."
time tool_b analyze "$VULN_REPO" -o "$RESULTS_DIR/tool_b.json" 2>&1
TOOL_B_FINDINGS=$(jq '.results | length' "$RESULTS_DIR/tool_b.json")
echo "Tool B: $TOOL_B_FINDINGS findings"

# Compare against ground truth
echo "=== Detection Rate ==="
echo "Ground truth: 50 vulnerabilities"
echo "Tool A: $TOOL_A_FINDINGS ($(( TOOL_A_FINDINGS * 100 / 50 ))%)"
echo "Tool B: $TOOL_B_FINDINGS ($(( TOOL_B_FINDINGS * 100 / 50 ))%)"
```

### Pros/Cons Summary Template

```markdown
### Tool A — Best for: [use case]

**Strengths**:
- [Specific measurable advantage]
- [Specific measurable advantage]

**Weaknesses**:
- [Specific measurable limitation]
- [Specific measurable limitation]

**Verdict**: Choose when [specific condition]. Avoid when [specific condition].
```

---

## Blog Post Structures

### Hook Patterns

```markdown
# Pattern 1: Shocking statistic
"73% of production JWT implementations we tested used HS256 with a secret shorter than 32 characters."

# Pattern 2: Story opening
"Last Tuesday at 2am, our monitoring flagged an anomaly that led us down a rabbit hole..."

# Pattern 3: Contrarian claim
"The security community's obsession with XSS is misplaced. Here's what actually gets you owned."

# Pattern 4: Question
"What happens when your 'secure' password reset flow meets a determined attacker with $5 of cloud compute?"
```

### Code Walkthrough Format

```markdown
Let's trace the vulnerability from input to impact:

**Step 1**: User input enters at `routes/search.js:14`
[code block showing the entry point]

**Step 2**: Input passes through middleware without sanitization
[code block showing the gap]

**Step 3**: Raw input reaches the database query at `models/product.js:42`
[code block showing the vulnerable query]

**The fix**: Replace string concatenation with parameterized query
[code block showing the fix]
```

### Detection Rule Snippet

```yaml
# Sigma rule for detecting the technique discussed in the blog post
title: JWT HS256 Weak Secret Exploitation
status: experimental
logsource:
    category: webserver
    product: nginx
detection:
    selection:
        cs-uri-query|contains: 'eyJ'  # Base64 JWT prefix
    condition: selection
    timeframe: 1m
    count: 50
level: medium
```

---

## Evidence Formatting

### Terminal Output Capture

```bash
# Use script command for full terminal recording
script -q evidence_session.log
# ... perform exploitation ...
exit

# Or use asciinema for shareable recordings
asciinema rec evidence_session.cast
# ... perform exploitation ...
# Ctrl+D to stop

# Convert to GIF for reports
agg evidence_session.cast evidence_session.gif
```

### HTTP Request/Response Formatting

```markdown
**Request**:
POST /api/login HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"username": "admin' OR '1'='1", "password": "x"}

**Response**:
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "success", "token": "eyJ..."}

**Analysis**: The application accepted a SQL injection payload in the username field and returned a valid authentication token, confirming unauthenticated access.
```

### Timeline Table

```markdown
| Date | Event | Actor |
|------|-------|-------|
| 2026-05-01 | Vulnerability discovered during routine scan | Security Team |
| 2026-05-02 | Initial triage and severity assessment | Security Team |
| 2026-05-03 | Vendor notified via security@vendor.com | Security Team |
| 2026-05-05 | Vendor acknowledges receipt | Vendor |
| 2026-05-15 | Patch released (v2.4.1) | Vendor |
| 2026-05-22 | Public disclosure (90-day policy) | Security Team |
```

### CVSS Vector Breakdown Table

```markdown
| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network (N) | Exploitable remotely via HTTP |
| Attack Complexity | Low (L) | No special conditions required |
| Privileges Required | None (N) | Unauthenticated exploitation |
| User Interaction | None (N) | No victim action needed |
| Scope | Unchanged (U) | Impact limited to vulnerable component |
| Confidentiality | High (H) | Full database access |
| Integrity | High (H) | Can modify all records |
| Availability | High (H) | Can drop tables |
| **Base Score** | **9.8 Critical** | |
```

---

## Vulnerability Description Generators

### Auto-Generate Finding Description from Evidence

```python
#!/usr/bin/env python3
"""Generate structured vulnerability descriptions from raw evidence data."""
import json
import sys

TEMPLATE = """## {title}

**Severity**: {severity} (CVSS {cvss_score})
**Affected Component**: {component}
**Attack Vector**: {attack_vector}

### Description
{description}

### Impact
{impact}

### Remediation
{remediation}
"""

def generate_finding(evidence_file):
    with open(evidence_file) as f:
        data = json.load(f)
    return TEMPLATE.format(
        title=data.get("title", "Untitled Finding"),
        severity=data.get("severity", "Unknown"),
        cvss_score=data.get("cvss_score", "0.0"),
        component=data.get("component", "Unknown"),
        attack_vector=data.get("attack_vector", "Unknown"),
        description=data.get("description", "Pending analysis"),
        impact=data.get("impact", "Pending impact assessment"),
        remediation=data.get("remediation", "Pending remediation guidance"),
    )

if __name__ == "__main__":
    evidence = sys.argv[1] if len(sys.argv) > 1 else "evidence.json"
    print(generate_finding(evidence))
```

### CVSS 3.1 Vector Parser and Score Calculator

```python
#!/usr/bin/env python3
"""Parse CVSS 3.1 vector strings and compute base score."""
import sys

METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},
}

def parse_cvss_vector(vector_str):
    parts = vector_str.replace("CVSS:3.1/", "").split("/")
    values = {}
    for part in parts:
        key, val = part.split(":")
        values[key] = val
    exploitability = 8.22 * METRICS["AV"][values["AV"]] \
        * METRICS["AC"][values["AC"]] \
        * METRICS["PR"][values["PR"]] \
        * METRICS["UI"][values["UI"]]
    iss = 1 - ((1 - METRICS["C"][values["C"]]) \
        * (1 - METRICS["I"][values["I"]]) \
        * (1 - METRICS["A"][values["A"]]))
    if iss <= 0:
        return 0.0
    if values["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    if values["S"] == "U":
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)
    return round(score, 1)

if __name__ == "__main__":
    vector = sys.argv[1] if len(sys.argv) > 1 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = parse_cvss_vector(vector)
    if score >= 9.0: label = "Critical"
    elif score >= 7.0: label = "High"
    elif score >= 4.0: label = "Medium"
    elif score > 0.0: label = "Low"
    else: label = "None"
    print(f"Vector: {vector}")
    print(f"Score:  {score} ({label})")
```

---

## Report Generation Scripts

### Executive Summary Generator

```python
#!/usr/bin/env python3
"""Generate an executive summary from aggregated findings."""
import json
from collections import Counter
from datetime import datetime

def generate_exec_summary(findings, metadata):
    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    counts = Counter(f["severity"] for f in findings)
    total = len(findings)
    critical_high = counts.get("Critical", 0) + counts.get("High", 0)

    summary = f"# Executive Summary\n\n"
    summary += f"**Engagement**: {metadata.get('client', 'N/A')}\n"
    summary += f"**Date**: {metadata.get('date', datetime.now().strftime('%Y-%m-%d'))}\n"
    summary += f"**Scope**: {metadata.get('scope', 'Application Security Assessment')}\n\n"

    summary += f"## Findings Overview\n\n"
    summary += f"A total of **{total}** security findings were identified:\n\n"
    for sev in severity_order:
        if counts.get(sev, 0) > 0:
            summary += f"- **{sev}**: {counts[sev]}\n"
    summary += f"\n**{critical_high}** findings require immediate attention.\n"

    if counts.get("Critical", 0) > 0:
        summary += f"\n## Critical Issues\n\n"
        for f in findings:
            if f["severity"] == "Critical":
                summary += f"- **{f.get('title', 'Untitled')}** ({f.get('component', 'N/A')})\n"

    return summary

if __name__ == "__main__":
    with open("findings.json") as fh:
        findings = json.load(fh)
    print(generate_exec_summary(findings, {"client": "Example Corp"}))
```

### Risk Rating Matrix Generator

```python
#!/usr/bin/env python3
"""Generate a risk rating matrix (Likelihood x Impact) from findings."""
import json

LIKELIHOOD_MAP = {
    "Network": "High", "Adjacent": "Medium", "Local": "Medium", "Physical": "Low"
}
IMPACT_MAP = {"H": "High", "L": "Medium", "N": "Low"}
RISK_MATRIX = {
        ("High", "High"): "Critical", ("High", "Medium"): "High",
        ("High", "Low"): "Medium", ("Medium", "High"): "High",
        ("Medium", "Medium"): "Medium", ("Medium", "Low"): "Low",
        ("Low", "High"): "Medium", ("Low", "Medium"): "Low",
        ("Low", "Low"): "Low",
}

def classify_risk(finding):
    cvss_vector = finding.get("cvss_vector", "")
    parts = dict(p.split(":") for p in cvss_vector.replace("CVSS:3.1/", "").split("/") if ":" in p)
    likelihood = LIKELIHOOD_MAP.get(parts.get("AV", "N"), "Medium")
    impact = IMPACT_MAP.get(parts.get("C", "N"), "Low")
    return RISK_MATRIX.get((likelihood, impact), "Medium")

if __name__ == "__main__":
    with open("findings.json") as f:
        findings = json.load(f)
    for finding in findings:
        risk = classify_risk(finding)
        print(f"[{risk}] {finding.get('title', 'Untitled')}")
```

---

## Markdown Report Formatters

### Markdown Table Generator

```python
#!/usr/bin/env python3
"""Generate formatted Markdown tables from finding data."""
import json
import sys

def findings_table(findings):
    header = "| # | Title | Severity | CVSS | Component | Status |"
    sep =    "|---|-------|----------|------|-----------|--------|"
    rows = []
    for i, f in enumerate(findings, 1):
        title = f.get("title", "Untitled")[:50]
        sev = f.get("severity", "Unknown")
        cvss = f.get("cvss_score", "0.0")
        comp = f.get("component", "N/A")[:30]
        status = f.get("status", "Open")
        rows.append(f"| {i} | {title} | {sev} | {cvss} | {comp} | {status} |")
    return "\n".join([header, sep] + rows)

def remediation_timeline(findings):
    header = "| Finding | Priority | Estimated Effort | Deadline |"
    sep =    "|---------|----------|------------------|----------|"
    rows = []
    for f in findings:
        title = f.get("title", "Untitled")[:40]
        priority = "P1" if f.get("severity") == "Critical" else "P2"
        effort = "2-4 hours" if f.get("severity") in ("Critical", "High") else "4-8 hours"
        deadline = "24-48 hours" if priority == "P1" else "1-2 weeks"
        rows.append(f"| {title} | {priority} | {effort} | {deadline} |")
    return "\n".join([header, sep] + rows)

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        data = json.load(f)
    print("### Findings Summary\n")
    print(findings_table(data))
    print("\n### Remediation Timeline\n")
    print(remediation_timeline(data))
```

### Findings JSON to Markdown Converter

```bash
#!/bin/bash
# Convert JSON findings file to a structured Markdown report
# Usage: ./json2md.sh findings.json > report.md

FINDINGS_FILE="${1:-findings.json}"

echo "# Security Assessment Report"
echo ""
echo "## Findings Summary"
echo ""

# Generate severity counts
echo "| Severity | Count |"
echo "|----------|-------|"
for sev in Critical High Medium Low Informational; do
  count=$(jq -r "[.[] | select(.severity == \"$sev\")] | length" "$FINDINGS_FILE" 2>/dev/null || echo "0")
  [ "$count" -gt 0 ] && echo "| $sev | $count |"
done

echo ""
echo "## Detailed Findings"
echo ""

# Generate individual finding sections
jq -r '.[] | "### \(.title // "Untitled")\n\n" +
  "**Severity**: \(.severity // "Unknown") | **CVSS**: \(.cvss_score // "N/A")\n\n" +
  "**Component**: \(.component // "N/A")\n\n" +
  "**Description**: \(.description // "No description available")\n\n" +
  "**Remediation**: \(.remediation // "No remediation provided")\n\n" +
  "---\n"' "$FINDINGS_FILE"
```

---

## Advisory Templates

### CVE Advisory Body Template

```markdown
## Technical Details

The vulnerability exists in [component name] version [affected versions]. 
The [function/endpoint/feature] at [file:line] does not properly [validate/sanitize/authorize] 
[user input/requests/data], allowing an attacker to [impact description].

### Root Cause Analysis
The root cause is [missing check / incorrect logic / default configuration] in the [module name].
Specifically, the code at [file:line] uses [vulnerable pattern] instead of [secure pattern].

### Proof of Concept
[Step-by-step reproduction instructions with sanitized commands]

### Workaround
[Immediate mitigation steps for users unable to upgrade]

### Credits
Discovered by [researcher name] of [organization] on [date].
```

### Vendor Notification Email Template

```markdown
Subject: [SECURITY] Vulnerability Report: [Title] ([CVE-ID])

Dear [Vendor] Security Team,

We are writing to responsibly disclose a security vulnerability we discovered 
in [Product Name] version [version].

## Summary
- **Vulnerability**: [brief description]
- **Severity**: [CVSS score] ([Critical/High/Medium/Low])
- **Attack Vector**: [Remote/Local/Adjacent]
- **Authentication**: [Required/Not Required]

## Timeline
- [YYYY-MM-DD]: Vulnerability discovered
- [YYYY-MM-DD]: Vendor notified (this email)
- [YYYY-MM-DD + 90]: Planned public disclosure (per our 90-day policy)

We are committed to responsible disclosure and will delay public announcement 
until a patch is available. Please acknowledge receipt within 72 hours.

Please direct all communication to [secure contact method].
```

---

## Vulnerability Severity Report Script

### Severity Distribution Analyzer

```python
#!/usr/bin/env python3
"""Analyze severity distribution across multiple scan reports."""
import json
import sys
from collections import Counter, defaultdict

def analyze_severity_distribution(*report_files):
    severity_counts = Counter()
    by_tool = defaultdict(Counter)
    for report_file in report_files:
        with open(report_file) as f:
            data = json.load(f)
        tool_name = report_file.replace(".json", "").split("/")[-1]
        findings = data if isinstance(data, list) else data.get("results", data.get("findings", []))
        for finding in findings:
            sev = finding.get("severity", finding.get("level", "Unknown")).title()
            severity_counts[sev] += 1
            by_tool[tool_name][sev] += 1
    print("=== Severity Distribution ===")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = severity_counts.get(sev, 0)
        bar = "#" * min(count, 50)
        print(f"  {sev:10s} {count:4d} {bar}")
    print(f"\n  {'Total':10s} {sum(severity_counts.values()):4d}")
    print("\n=== By Tool ===")
    for tool, counts in sorted(by_tool.items()):
        total = sum(counts.values())
        crit = counts.get("Critical", 0)
        high = counts.get("High", 0)
        print(f"  {tool}: {total} total ({crit} Critical, {high} High)")

if __name__ == "__main__":
    analyze_severity_distribution(*sys.argv[1:])
```

### Markdown Section Generator

```bash
#!/bin/bash
# Generate a full pentest report Markdown structure with placeholder sections
# Usage: ./generate-report-structure.sh > report-structure.md

cat << 'STRUCTURE'
# Penetration Test Report

## 1. Executive Summary
<!-- Auto-generated from findings data -->

## 2. Scope and Methodology
### 2.1 Engagement Scope
### 2.2 Testing Methodology
### 2.3 Tools Used

## 3. Findings Summary
<!-- Findings table inserted here -->

## 4. Detailed Findings
<!-- One subsection per finding -->

## 5. Risk Assessment
### 5.1 Risk Matrix
### 5.2 Business Impact Analysis

## 6. Remediation Roadmap
### 6.1 Immediate Actions (P1)
### 6.2 Short-Term Fixes (P2)
### 6.3 Long-Term Improvements (P3)

## 7. Appendices
### A. Tool Output
### B. Raw Evidence
### C. Test Accounts Used
STRUCTURE
```

### Evidence File Naming Convention Script

```bash
#!/bin/bash
# Standardize evidence file naming for audit compliance
# Format: EVD-NNNN-category-timestamp.ext

EVIDENCE_DIR="${1:-./evidence}"
mkdir -p "$EVIDENCE_DIR"

evidence_capture() {
  local category="$1"
  local description="$2"
  local ext="${3:-png}"
  local counter=$(ls "$EVIDENCE_DIR"/EVD-* 2>/dev/null | wc -l | tr -d ' ')
  counter=$((counter + 1))
  local file_id=$(printf "EVD-%04d" "$counter")
  local timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
  local filename="${file_id}-${category}-${timestamp}.${ext}"
  local filepath="$EVIDENCE_DIR/$filename"
  echo "$filepath"
}

# Example: capture a screenshot
EVIDENCE_FILE=$(evidence_capture "screenshot" "login-bypass" "png")
echo "Next evidence file: $EVIDENCE_FILE"
```

### Report Revision Tracker

```python
#!/usr/bin/env python3
"""Track report revisions and maintain version history."""
import json
from datetime import datetime

def create_revision(filename, author, changes):
    """Append a revision entry to the report changelog."""
    try:
        with open(filename) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {"revisions": []}
    data["revisions"].append({
        "version": f"1.{len(data['revisions'])}",
        "date": datetime.now().isoformat(),
        "author": author,
        "changes": changes,
    })
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Revision 1.{len(data['revisions'])-1} recorded: {changes}")

if __name__ == "__main__":
    import sys
    author = sys.argv[1] if len(sys.argv) > 1 else "Security Team"
    changes = sys.argv[2] if len(sys.argv) > 2 else "Initial draft"
    create_revision("report_revisions.json", author, changes)
```

### Cross-Reference Link Generator

```bash
#!/bin/bash
# Generate cross-reference links between findings in a Markdown report
# Creates internal links so findings can reference related findings

python3 << 'PYEOF'
import re
import sys

def generate_cross_refs(markdown_file):
    with open(markdown_file) as f:
        content = f.read()
    # Find all finding headers
    pattern = r'###\s+(FIND-\d+)\s*[:-]\s*(.+)'
    findings = re.findall(pattern, content)
    print("### Cross-Reference Index\n")
    for fid, title in findings:
        anchor = fid.lower().replace(" ", "-")
        print(f"- [{fid}: {title.strip()}](#{anchor})")
    print(f"\nTotal findings: {len(findings)}")

if __name__ == "__main__":
    generate_cross_refs(sys.argv[1] if len(sys.argv) > 1 else "report.md")
PYEOF
```

### Compliance Mapping Table Generator

```python
#!/usr/bin/env python3
"""Map security findings to compliance frameworks (OWASP, CIS, PCI-DSS)."""
import json

OWASP_MAPPING = {
    "SQL Injection": "A03:2021 - Injection",
    "XSS": "A07:2021 - Cross-Site Scripting",
    "Broken Authentication": "A07:2021 - Identification and Authentication Failures",
    "SSRF": "A10:2021 - Server-Side Request Forgery",
    "Sensitive Data Exposure": "A02:2021 - Cryptographic Failures",
    "Broken Access Control": "A01:2021 - Broken Access Control",
    "Security Misconfiguration": "A05:2021 - Security Misconfiguration",
    "Outdated Components": "A06:2021 - Vulnerable and Outdated Components",
}

def map_findings_to_owasp(findings_file):
    with open(findings_file) as f:
        findings = json.load(f)
    print("| Finding | OWASP Top 10 (2021) |")
    print("|---------|---------------------|")
    for f in findings:
        title = f.get("title", "Unknown")
        for keyword, owasp in OWASP_MAPPING.items():
            if keyword.lower() in title.lower():
                print(f"| {title} | {owasp} |")
                break
        else:
            print(f"| {title} | (unmapped) |")

if __name__ == "__main__":
    import sys
    map_findings_to_owasp(sys.argv[1] if len(sys.argv) > 1 else "findings.json")
```

### Report Word Count and Page Estimator

```bash
#!/bin/bash
# Estimate report length and page count for client delivery
# Assumes ~500 words per page with images

REPORT="${1:-report.md}"

WORDS=$(wc -w < "$REPORT")
LINES=$(wc -l < "$REPORT")
CHARS=$(wc -c < "$REPORT")
CODE_BLOCKS=$(grep -c '^\`\`\`' "$REPORT")
IMAGES=$(grep -c '!\[' "$REPORT")

# Estimate pages: ~500 words per page, +1 page per 2 images
EST_PAGES=$(( (WORDS / 500) + (IMAGES / 2) + 1 ))

echo "=== Report Statistics ==="
echo "  Words:        $WORDS"
echo "  Lines:        $LINES"
echo "  Characters:   $CHARS"
echo "  Code blocks:  $((CODE_BLOCKS / 2))"
echo "  Images:       $IMAGES"
echo "  Est. pages:   ~$EST_PAGES"

# Section breakdown
echo ""
echo "=== Section Breakdown ==="
grep "^##" "$REPORT" | while read -r section; do
  echo "  $section"
done
```

### Remediation Priority Matrix Generator

```python
#!/usr/bin/env python3
"""Generate a remediation priority matrix based on severity, exploitability, and business impact."""

PRIORITY_WEIGHTS = {
    "Critical": {"exploitability": 10, "business_impact": 10, "remediation_effort": 1},
    "High":     {"exploitability": 7,  "business_impact": 7,  "remediation_effort": 2},
    "Medium":   {"exploitability": 4,  "business_impact": 4,  "remediation_effort": 3},
    "Low":      {"exploitability": 2,  "business_impact": 2,  "remediation_effort": 4},
}

def calculate_priority(findings):
    scored = []
    for f in findings:
        sev = f.get("severity", "Medium")
        weights = PRIORITY_WEIGHTS.get(sev, PRIORITY_WEIGHTS["Medium"])
        score = (weights["exploitability"] * 0.4 +
                 weights["business_impact"] * 0.4 +
                 weights["remediation_effort"] * 0.2)
        scored.append((score, f))
    return sorted(scored, key=lambda x: -x[0])

if __name__ == "__main__":
    import json, sys
    with open(sys.argv[1]) as fh:
        findings = json.load(fh)
    print("| Priority | Score | Finding | Severity |")
    print("|----------|-------|---------|----------|")
    for i, (score, f) in enumerate(calculate_priority(findings), 1):
        print(f"| P{i} | {score:.1f} | {f.get('title', 'Untitled')[:40]} | {f.get('severity', 'N/A')} |")
```

---

## Markdown Automation Scripts

### Bulk Markdown to PDF Conversion Pipeline

```bash
#!/bin/bash
# Convert a directory of Markdown findings into a combined PDF report
# Requires: pandoc, xelatex

FINDINGS_DIR="${1:-findings/}"
OUTPUT="reports/combined-report-$(date +%Y%m%d).pdf"
TEMP_MD="/tmp/combined-report.md"

echo "# Penetration Test Report - Combined Findings" > "$TEMP_MD"
echo "" >> "$TEMP_MD"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$TEMP_MD"
echo "" >> "$TEMP_MD"

# Concatenate all findings with separators
for f in "$FINDINGS_DIR"/*.md; do
  [ -f "$f" ] || continue
  echo "" >> "$TEMP_MD"
  echo "---" >> "$TEMP_MD"
  echo "" >> "$TEMP_MD"
  cat "$f" >> "$TEMP_MD"
done

# Convert to PDF with professional formatting
pandoc "$TEMP_MD" -o "$OUTPUT" \
  --pdf-engine=xelatex \
  --toc --toc-depth=3 \
  --number-sections \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  -V colorlinks=true \
  -V linkcolor=blue \
  --highlight-style=tango \
  --metadata title="Security Assessment Report"

echo "[REPORT] Combined PDF: $OUTPUT ($(wc -w < "$TEMP_MD") words)"
```

### Markdown Table of Contents Generator

```bash
#!/bin/bash
# Generate a table of contents from Markdown headers
# Usage: ./generate-toc.sh report.md > toc.md

MARKDOWN_FILE="${1:-report.md}"

echo "## Table of Contents"
echo ""

grep -n "^#" "$MARKDOWN_FILE" | while IFS=: read -r linenum header; do
  # Count header level
  level=$(echo "$header" | grep -o "^#" | wc -c)
  indent=$(printf '%*s' $((level * 2 - 2)) '')

  # Extract title text
  title=$(echo "$header" | sed 's/^#* *//')

  # Generate anchor
  anchor=$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g;s/^-//;s/-$//')

  echo "${indent}- [${title}](#${anchor})"
done
```

### Markdown Link Checker

```bash
#!/bin/bash
# Check all external links in a Markdown report for broken references
# Usage: ./check-links.sh report.md

REPORT="${1:-report.md}"
BROKEN=0
CHECKED=0

grep -oE 'https?://[^)\"]+' "$REPORT" | sort -u | while read -r url; do
  CHECKED=$((CHECKED + 1))
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 10 "$url" 2>/dev/null || echo "000")

  if [ "$STATUS" = "200" ]; then
    echo "[OK] $STATUS $url"
  else
    echo "[BROKEN] $STATUS $url"
    BROKEN=$((BROKEN + 1))
  fi
  sleep 0.5
done

echo ""
echo "Checked $CHECKED links, $BROKEN broken"
```

---

## CVSS Calculator Automation

### Interactive CVSS Vector Builder

```python
#!/usr/bin/env python3
"""Interactive CVSS v3.1 vector builder with real-time score calculation."""

import math

METRICS = {
    "AV": {
        "label": "Attack Vector",
        "options": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "weights": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    },
    "AC": {
        "label": "Attack Complexity",
        "options": {"L": "Low", "H": "High"},
        "weights": {"L": 0.77, "H": 0.44}
    },
    "PR": {
        "label": "Privileges Required",
        "options": {"N": "None", "L": "Low", "H": "High"},
        "weights": {"N": 0.85, "L": 0.62, "H": 0.27}
    },
    "UI": {
        "label": "User Interaction",
        "options": {"N": "None", "R": "Required"},
        "weights": {"N": 0.85, "R": 0.62}
    },
    "S": {
        "label": "Scope",
        "options": {"U": "Unchanged", "C": "Changed"},
        "weights": {}
    },
    "C": {
        "label": "Confidentiality",
        "options": {"H": "High", "L": "Low", "N": "None"},
        "weights": {"H": 0.56, "L": 0.22, "N": 0}
    },
    "I": {
        "label": "Integrity",
        "options": {"H": "High", "L": "Low", "N": "None"},
        "weights": {"H": 0.56, "L": 0.22, "N": 0}
    },
    "A": {
        "label": "Availability",
        "options": {"H": "High", "L": "Low", "N": "None"},
        "weights": {"H": 0.56, "L": 0.22, "N": 0}
    }
}

def calculate_score(selections):
    """Calculate CVSS score from metric selections."""
    scope_changed = selections["S"] == "C"
    av = METRICS["AV"]["weights"][selections["AV"]]
    ac = METRICS["AC"]["weights"][selections["AC"]]
    pr = METRICS["PR"]["weights"][selections["PR"]]
    ui = METRICS["UI"]["weights"][selections["UI"]]
    c = METRICS["C"]["weights"][selections["C"]]
    i = METRICS["I"]["weights"][selections["I"]]
    a = METRICS["A"]["weights"][selections["A"]]

    exploitability = 8.22 * av * ac * pr * ui
    isc = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope_changed:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    else:
        impact = 6.42 * isc

    if impact <= 0:
        return 0.0

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    return math.ceil(score * 10) / 10

def build_vector(selections):
    """Build CVSS vector string from selections."""
    parts = [f"{k}:{v}" for k, v in selections.items()]
    return "CVSS:3.1/" + "/".join(parts)

# Example: programmatic usage
example_selections = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
score = calculate_score(example_selections)
vector = build_vector(example_selections)
print(f"Vector: {vector}")
print(f"Score: {score}")
severity = "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"
print(f"Severity: {severity}")
```

### CVSS Vector Batch Processor

```bash
#!/bin/bash
# Batch process CVSS vectors from a file and generate a severity report
# Input file format: one vector per line

VECTORS_FILE="${1:-cvss_vectors.txt}"
OUTPUT="cvss_report_$(date +%Y%m%d).md"

echo "# CVSS Batch Scoring Report" > "$OUTPUT"
echo "" >> "$OUTPUT"
echo "| # | Vector | Score | Severity |" >> "$OUTPUT"
echo "|---|--------|-------|----------|" >> "$OUTPUT"

COUNT=0
while IFS= read -r vector; do
  [ -z "$vector" ] && continue
  COUNT=$((COUNT + 1))

  # Calculate using Python
  RESULT=$(python3 -c "
import math
parts = dict(p.split(':') for p in '$vector'.replace('CVSS:3.1/', '').split('/'))
scope_changed = parts['S'] == 'C'
av = {'N':0.85,'A':0.62,'L':0.55,'P':0.20}[parts['AV']]
ac = {'L':0.77,'H':0.44}[parts['AC']]
pr = {'N':0.85,'L':0.62,'H':0.27}[parts['PR']]
ui = {'N':0.85,'R':0.62}[parts['UI']]
c = {'H':0.56,'L':0.22,'N':0}[parts['C']]
i = {'H':0.56,'L':0.22,'N':0}[parts['I']]
a = {'H':0.56,'L':0.22,'N':0}[parts['A']]
exploitability = 8.22 * av * ac * pr * ui
isc = 1 - ((1-c)*(1-i)*(1-a))
impact = (7.52*(isc-0.029)-3.25*((isc-0.02)**15)) if scope_changed else (6.42*isc)
score = min((1.08*(impact+exploitability) if scope_changed else (impact+exploitability)), 10.0) if impact > 0 else 0.0
score = math.ceil(score*10)/10
sev = 'Critical' if score>=9.0 else 'High' if score>=7.0 else 'Medium' if score>=4.0 else 'Low'
print(f'{score}|{sev}')
")

  SCORE=$(echo "$RESULT" | cut -d'|' -f1)
  SEVERITY=$(echo "$RESULT" | cut -d'|' -f2)
  echo "| $COUNT | \`$vector\` | $SCORE | $SEVERITY |" >> "$OUTPUT"
done < "$VECTORS_FILE"

echo "" >> "$OUTPUT"
echo "Total vectors processed: $COUNT" >> "$OUTPUT"
echo "[CVSS] Report saved to $OUTPUT ($COUNT vectors)"
```

---

## Vulnerability Disclosure Formatting

### Responsible Disclosure Timeline Generator

```python
#!/usr/bin/env python3
"""Generate a responsible disclosure timeline with automated date calculations."""

from datetime import datetime, timedelta
import json

def generate_disclosure_timeline(discovery_date, vendor_contact_date=None,
                                  patch_deadline_days=90, grace_period_days=14):
    """Generate a full disclosure timeline following responsible disclosure practices."""
    discovery = datetime.fromisoformat(discovery_date) if isinstance(discovery_date, str) else discovery_date
    contact = datetime.fromisoformat(vendor_contact_date) if vendor_contact_date else discovery + timedelta(days=1)

    timeline = {
        "discovery_date": discovery.isoformat()[:10],
        "vendor_notification": contact.isoformat()[:10],
        "vendor_ack_deadline": (contact + timedelta(days=7)).isoformat()[:10],
        "initial_patch_deadline": (contact + timedelta(days=patch_deadline_days)).isoformat()[:10],
        "extended_patch_deadline": (contact + timedelta(days=patch_deadline_days + 30)).isoformat()[:10],
        "public_disclosure_date": (contact + timedelta(days=patch_deadline_days + grace_period_days)).isoformat()[:10],
        "milestones": []
    }

    timeline["milestones"] = [
        {"date": discovery.isoformat()[:10], "event": "Vulnerability discovered", "actor": "Researcher"},
        {"date": contact.isoformat()[:10], "event": "Vendor notified via secure channel", "actor": "Researcher"},
        {"date": timeline["vendor_ack_deadline"], "event": "Vendor acknowledgment deadline (7 days)", "actor": "Vendor"},
        {"date": (contact + timedelta(days=45)).isoformat()[:10], "event": "Follow-up if no response", "actor": "Researcher"},
        {"date": timeline["initial_patch_deadline"], "event": "Initial patch deadline (90 days)", "actor": "Vendor"},
        {"date": timeline["public_disclosure_date"], "event": "Planned public disclosure", "actor": "Researcher"},
    ]

    return timeline

# Example
timeline = generate_disclosure_timeline("2026-05-01")
print(json.dumps(timeline, indent=2))
for milestone in timeline["milestones"]:
    print(f"  {milestone['date']}: {milestone['event']} ({milestone['actor']})")
```

### CVE Description Generator

```python
#!/usr/bin/env python3
"""Generate standardized CVE description from vulnerability evidence."""

import json

def generate_cve_description(evidence):
    """Create a NVD-style CVE description from structured evidence data."""
    vuln_type = evidence.get("vulnerability_type", "Unknown")
    component = evidence.get("component", "Unknown")
    version = evidence.get("affected_version", "Unknown")
    attack_vector = evidence.get("attack_vector", "network")
    auth_required = evidence.get("authentication_required", True)
    impact = evidence.get("impact", "Unknown")

    auth_phrase = "an unauthenticated" if not auth_required else "an authenticated"
    vector_phrase = {
        "network": "remotely via the network",
        "adjacent": "via an adjacent network",
        "local": "locally on the affected system",
        "physical": "through physical access"
    }.get(attack_vector, "via an unknown vector")

    description = (
        f"A {vuln_type.lower()} vulnerability exists in {component} version {version}. "
        f"The flaw allows {auth_phrase} attacker to {impact.lower()} {vector_phrase}. "
        f"The vulnerability is due to {evidence.get('root_cause', 'improper input validation')}. "
        f"Successful exploitation could lead to {evidence.get('worst_case_impact', 'complete system compromise')}."
    )

    return {
        "cve_id": evidence.get("cve_id", "CVE-YYYY-NNNNN"),
        "description": description,
        "cvss_vector": evidence.get("cvss_vector", ""),
        "references": evidence.get("references", []),
        "cwe": evidence.get("cwe", "CWE-Unknown"),
        "affected_product": f"{component} {version}",
        "remediation": evidence.get("remediation", "Update to the latest version.")
    }

# Example
evidence = {
    "cve_id": "CVE-2026-1234",
    "vulnerability_type": "SQL Injection",
    "component": "WebApp Framework",
    "affected_version": "prior to 3.2.1",
    "attack_vector": "network",
    "authentication_required": False,
    "impact": "execute arbitrary SQL commands and extract sensitive data",
    "root_cause": "insufficient sanitization of user-supplied input in the search parameter",
    "worst_case_impact": "complete database compromise including credential extraction",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-89",
    "remediation": "Upgrade to version 3.2.1 or later which implements parameterized queries."
}

cve_desc = generate_cve_description(evidence)
print(json.dumps(cve_desc, indent=2))
```

---

## Technical Writing Checklists

### Pre-Publication Quality Gate Script

```bash
#!/bin/bash
# Pre-publication quality gate for security reports
# Checks: word count, severity coverage, evidence links, broken references

REPORT="${1:-report.md}"
ISSUES=0

echo "=== Pre-Publication Quality Gate ==="
echo "Report: $REPORT"
echo ""

# Check 1: Required sections exist
for section in "Executive Summary" "Scope" "Methodology" "Findings" "Remediation"; do
  if grep -qi "## .*$section" "$REPORT"; then
    echo "[PASS] Section found: $section"
  else
    echo "[FAIL] Missing section: $section"
    ISSUES=$((ISSUES + 1))
  fi
done

# Check 2: CVSS scores present for all findings
findings_count=$(grep -ci "cvss" "$REPORT")
if [ "$findings_count" -ge 1 ]; then
  echo "[PASS] CVSS scores present ($findings_count references)"
else
  echo "[FAIL] No CVSS scores found"
  ISSUES=$((ISSUES + 1))
fi

# Check 3: No placeholder text remaining
if grep -qi "TODO\|FIXME\|PLACEHOLDER\|\[INSERT\|TBD" "$REPORT"; then
  echo "[FAIL] Placeholder text still present"
  grep -ni "TODO\|FIXME\|PLACEHOLDER\|\[INSERT\|TBD" "$REPORT"
  ISSUES=$((ISSUES + 1))
else
  echo "[PASS] No placeholder text found"
fi

# Check 4: Evidence references valid
evidence_links=$(grep -oE 'evidence/[^)\"]+' "$REPORT" 2>/dev/null)
for link in $evidence_links; do
  if [ ! -f "$link" ]; then
    echo "[FAIL] Missing evidence file: $link"
    ISSUES=$((ISSUES + 1))
  fi
done
echo "[PASS] Evidence file references checked"

# Check 5: Minimum report length
word_count=$(wc -w < "$REPORT")
if [ "$word_count" -lt 500 ]; then
  echo "[FAIL] Report too short: $word_count words (minimum 500)"
  ISSUES=$((ISSUES + 1))
else
  echo "[PASS] Report length: $word_count words"
fi

# Check 6: Sanitization check for real IPs and credentials
if grep -qE '(?<!\[REDACTED\])\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b' "$REPORT" 2>/dev/null; then
  echo "[WARN] Possible unsanitized private IPs found — review manually"
fi

echo ""
if [ "$ISSUES" -eq 0 ]; then
  echo "=== RESULT: PASS (0 issues) ==="
else
  echo "=== RESULT: FAIL ($ISSUES issues found) ==="
fi
```

### Report Section Completeness Checker

```python
#!/usr/bin/env python3
"""Check a security report for completeness against required elements."""

import re
import sys

REQUIRED_SECTIONS = [
    "Executive Summary",
    "Scope and Methodology",
    "Findings Summary",
    "Detailed Findings",
    "Remediation Recommendations",
    "Risk Assessment"
]

REQUIRED_PER_FINDING = [
    "Description",
    "Impact",
    "Remediation",
    "CVSS",
    "Proof of Concept",
    "Severity"
]

def check_report(filepath):
    with open(filepath) as f:
        content = f.read()

    issues = []

    # Check required sections
    for section in REQUIRED_SECTIONS:
        pattern = re.compile(r'##.*' + re.escape(section), re.IGNORECASE)
        if not pattern.search(content):
            issues.append(f"Missing required section: '{section}'")

    # Count findings
    finding_pattern = re.compile(r'###\s+(FIND-\d+|CVE-\d{4}-\d+|Finding\s+\d+)', re.IGNORECASE)
    findings = finding_pattern.findall(content)

    if not findings:
        issues.append("No findings detected — check formatting")
    else:
        print(f"[OK] Found {len(findings)} findings")

    # Check each finding has required elements
    finding_sections = re.split(r'###\s+(?:FIND-\d+|CVE-\d{4}-\d+|Finding\s+\d+)', content)[1:]
    for i, section in enumerate(finding_sections):
        for element in REQUIRED_PER_FINDING:
            pattern = re.compile(r'\*\*' + re.escape(element) + r'\*\*', re.IGNORECASE)
            if not pattern.search(section):
                issues.append(f"Finding {i+1}: Missing '{element}' element")

    # Check sanitization
    private_ips = re.findall(r'(?<!\d\.)\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', content)
    if private_ips:
        issues.append(f"Possible unsanitized private IPs: {set(private_ips)}")

    if issues:
        print(f"[FAIL] {len(issues)} issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("[PASS] Report meets all completeness requirements")

    return issues

if __name__ == "__main__":
    check_report(sys.argv[1] if len(sys.argv) > 1 else "report.md")
```

---

## Markdown Report Generation Scripts

### Report Skeleton Generator with Auto-Population

```bash
#!/bin/bash
# Generate a complete pentest report skeleton and auto-populate from evidence
# Usage: ./generate-report.sh <engagement_id> <evidence_dir>

ENG_ID="${1:-ENG-001}"
EVIDENCE_DIR="${2:-evidence/}"
OUTPUT="reports/${ENG_ID}-report-$(date +%Y%m%d).md"
mkdir -p reports

# Count findings by severity from evidence JSON files
if ls "$EVIDENCE_DIR"/*.json 1>/dev/null 2>&1; then
  CRITICAL=$(cat "$EVIDENCE_DIR"/*.json 2>/dev/null | jq -s '[.[] | select(.severity=="Critical")] | length' 2>/dev/null || echo 0)
  HIGH=$(cat "$EVIDENCE_DIR"/*.json 2>/dev/null | jq -s '[.[] | select(.severity=="High")] | length' 2>/dev/null || echo 0)
  MEDIUM=$(cat "$EVIDENCE_DIR"/*.json 2>/dev/null | jq -s '[.[] | select(.severity=="Medium")] | length' 2>/dev/null || echo 0)
  LOW=$(cat "$EVIDENCE_DIR"/*.json 2>/dev/null | jq -s '[.[] | select(.severity=="Low")] | length' 2>/dev/null || echo 0)
else
  CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
fi

TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

cat > "$OUTPUT" << REPORT
# Penetration Test Report

**Engagement ID**: $ENG_ID
**Date**: $(date -u +%Y-%m-%d)
**Classification**: Confidential

## Executive Summary

A security assessment identified **${TOTAL}** vulnerabilities:
- **Critical**: ${CRITICAL}
- **High**: ${HIGH}
- **Medium**: ${MEDIUM}
- **Low**: ${LOW}

$([ "$CRITICAL" -gt 0 ] && echo "**WARNING**: ${CRITICAL} critical vulnerabilities require immediate remediation.")

## Findings Summary

| # | Title | Severity | CVSS | Component | Status |
|---|-------|----------|------|-----------|--------|
REPORT

# Auto-populate findings table
COUNT=0
for f in "$EVIDENCE_DIR"/*.json; do
  [ -f "$f" ] || continue
  COUNT=$((COUNT + 1))
  TITLE=$(jq -r '.title // "Untitled"' "$f" 2>/dev/null)
  SEV=$(jq -r '.severity // "Unknown"' "$f" 2>/dev/null)
  CVSS=$(jq -r '.cvss_score // "N/A"' "$f" 2>/dev/null)
  COMP=$(jq -r '.component // "N/A"' "$f" 2>/dev/null)
  STATUS=$(jq -r '.status // "Open"' "$f" 2>/dev/null)
  echo "| $COUNT | $TITLE | $SEV | $CVSS | $COMP | $STATUS |" >> "$OUTPUT"
done

cat >> "$OUTPUT" << FOOTER

## Detailed Findings

<!-- Insert individual finding sections here -->

## Remediation Roadmap

### P1 - Immediate (24-48 hours)
<!-- Critical and high findings -->

### P2 - Short-term (1-2 weeks)
<!-- Medium findings -->

### P3 - Long-term (1-3 months)
<!-- Low findings and best practices -->

## Appendices

### A. Tool Output
### B. Raw Evidence
FOOTER

echo "[REPORT] Generated: $OUTPUT ($TOTAL findings auto-populated)"
```

### Markdown to PDF with Custom Security Template

```bash
#!/bin/bash
# Convert Markdown report to professional PDF with security branding
# Usage: ./report-to-pdf.sh report.md

REPORT="${1:-report.md}"
OUTPUT="${2:-${REPORT%.md}.pdf}"
COMPANY="${3:-Security Team}"

# Create LaTeX header for security report
cat > /tmp/security-header.tex << 'TEX'
\usepackage{fancyhdr}
\usepackage{xcolor}
\definecolor{darkred}{RGB}{139,0,0}
\pagestyle{fancy}
\fancyhead[L]{\textcolor{darkred}{CONFIDENTIAL}}
\fancyhead[R]{\textcolor{darkred}{Security Assessment}}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}
TEX

pandoc "$REPORT" -o "$OUTPUT" \
  --pdf-engine=xelatex \
  --toc --toc-depth=3 \
  --number-sections \
  -H /tmp/security-header.tex \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  -V colorlinks=true \
  -V linkcolor=blue \
  --highlight-style=tango \
  --metadata title="Penetration Test Report" \
  --metadata author="$COMPANY"

echo "[PDF] Generated: $OUTPUT"
```

---

## CVSS Score Calculation Automation

### Batch CVSS Calculator with NVD Lookup

```python
#!/usr/bin/env python3
"""Batch CVSS score calculator that validates against NVD API."""

import json
import math
import time
import urllib.request

def calculate_cvss_v31(vector_string):
    """Calculate CVSS v3.1 base score from vector string."""
    weights = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'N': {'U': 0.85, 'C': 0.85}, 'L': {'U': 0.62, 'C': 0.68}, 'H': {'U': 0.27, 'C': 0.50}},
        'UI': {'N': 0.85, 'R': 0.62},
        'C': {'H': 0.56, 'L': 0.22, 'N': 0},
        'I': {'H': 0.56, 'L': 0.22, 'N': 0},
        'A': {'H': 0.56, 'L': 0.22, 'N': 0}
    }

    parts = dict(p.split(':') for p in vector_string.replace('CVSS:3.1/', '').split('/'))
    scope_changed = parts['S'] == 'C'

    av = weights['AV'][parts['AV']]
    ac = weights['AC'][parts['AC']]
    pr = weights['PR'][parts['PR']]['C' if scope_changed else 'U']
    ui = weights['UI'][parts['UI']]

    exploitability = 8.22 * av * ac * pr * ui
    c, i, a = weights['C'][parts['C']], weights['I'][parts['I']], weights['A'][parts['A']]
    isc = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope_changed:
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    else:
        impact = 6.42 * isc

    if impact <= 0:
        return 0.0

    score = min(1.08 * (impact + exploitability), 10.0) if scope_changed else min(impact + exploitability, 10.0)
    return math.ceil(score * 10) / 10

def lookup_nvd(cve_id):
    """Look up CVSS score from NVD API for validation."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cvss-calc/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            metrics = data.get('vulnerabilities', [{}])[0].get('cve', {}).get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
            return cvss_data.get('baseScore'), cvss_data.get('vectorString')
    except Exception:
        return None, None

def batch_calculate(cve_vectors):
    """Process a batch of CVE-vector pairs."""
    results = []
    for entry in cve_vectors:
        cve_id = entry.get('cve_id', 'Unknown')
        vector = entry.get('vector', '')
        calculated = calculate_cvss_v31(vector) if vector else None
        nvd_score, nvd_vector = lookup_nvd(cve_id)
        match = "MATCH" if calculated and nvd_score and abs(calculated - nvd_score) < 0.1 else "DIFF"
        results.append({
            'cve_id': cve_id,
            'calculated': calculated,
            'nvd_score': nvd_score,
            'match': match,
            'vector': vector
        })
        time.sleep(0.6)  # NVD rate limit
    return results

# Usage:
# entries = [{"cve_id": "CVE-2024-3094", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
# results = batch_calculate(entries)
```

---

## Vulnerability Disclosure Templates

### Coordinated Disclosure Notification Generator

```python
#!/usr/bin/env python3
"""Generate a coordinated vulnerability disclosure notification email."""

import json
from datetime import datetime, timedelta

def generate_disclosure_email(vulnerability, researcher):
    """Generate a formatted disclosure email from vulnerability data."""
    disclosure_date = datetime.now() + timedelta(days=90)

    email = f"""Subject: [SECURITY] Vulnerability Disclosure: {vulnerability.get('title', 'Untitled')}

Dear {vulnerability.get('vendor_security_team', 'Security Team')},

We are writing to responsibly disclose a security vulnerability discovered in
{vulnerability.get('product', 'your product')} version {vulnerability.get('affected_version', 'N/A')}.

## Vulnerability Summary

- **Title**: {vulnerability.get('title', 'N/A')}
- **Type**: {vulnerability.get('type', 'N/A')}
- **Severity**: {vulnerability.get('severity', 'N/A')} (CVSS {vulnerability.get('cvss_score', 'N/A')})
- **Attack Vector**: {vulnerability.get('attack_vector', 'N/A')}
- **Authentication Required**: {vulnerability.get('auth_required', 'Unknown')}
- **CWE**: {vulnerability.get('cwe', 'N/A')}

## Description

{vulnerability.get('description', 'Please see attached advisory for details.')}

## Impact

{vulnerability.get('impact', 'Please see attached advisory for details.')}

## Proof of Concept

{vulnerability.get('poc', 'Available upon request after acknowledgment.')}

## Disclosure Timeline

- **Discovery Date**: {vulnerability.get('discovery_date', datetime.now().strftime('%Y-%m-%d'))}
- **Vendor Notification**: {datetime.now().strftime('%Y-%m-%d')}
- **Acknowledgment Deadline**: {(datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')}
- **Planned Disclosure**: {disclosure_date.strftime('%Y-%m-%d')} (90-day policy)

We are committed to responsible disclosure. Please acknowledge receipt within
72 hours. We will delay public disclosure until a patch is available or 90 days
have elapsed, whichever comes first.

Best regards,
{researcher.get('name', 'Security Researcher')}
{researcher.get('organization', '')}
"""
    return email

# Example usage
vuln = {
    "title": "SQL Injection in Search Endpoint",
    "product": "WebApp Framework",
    "affected_version": "< 3.2.1",
    "type": "SQL Injection",
    "severity": "Critical",
    "cvss_score": "9.8",
    "cwe": "CWE-89"
}
researcher = {"name": "Security Team", "organization": "Security Lab"}
print(generate_disclosure_email(vuln, researcher))
```

---

## Technical Writing Quality Checks

### Report Readability Analyzer

```python
#!/usr/bin/env python3
"""Analyze security report readability and technical writing quality."""

import re
import sys
from pathlib import Path

def analyze_readability(filepath):
    """Score a security report on readability metrics."""
    with open(filepath) as f:
        content = f.read()

    issues = []

    # Check for passive voice
    passive_patterns = [
        r'\bwas\s+\w+ed\b', r'\bwere\s+\w+ed\b', r'\bbeen\s+\w+ed\b',
        r'\bis\s+\w+ed\b', r'\bare\s+\w+ed\b', r'\bwas\s+found\b'
    ]
    for pattern in passive_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if len(matches) > 5:
            issues.append(f"Excessive passive voice: '{pattern}' found {len(matches)} times")

    # Check for vague language
    vague_words = ['some', 'various', 'certain', 'things', 'stuff', 'it appears', 'it seems']
    for word in vague_words:
        count = len(re.findall(r'\b' + word + r'\b', content, re.IGNORECASE))
        if count > 0:
            issues.append(f"Vague language: '{word}' used {count} times")

    # Check sentence length
    sentences = re.split(r'[.!?]+', content)
    long_sentences = [s for s in sentences if len(s.split()) > 30]
    if len(long_sentences) > 5:
        issues.append(f"{len(long_sentences)} sentences exceed 30 words")

    # Check evidence references exist
    evidence_refs = re.findall(r'evidence/[^\s)\"]+', content)
    broken_refs = [ref for ref in evidence_refs if not Path(ref).exists()]
    if broken_refs:
        issues.append(f"Broken evidence references: {broken_refs[:5]}")

    score = max(0, 100 - len(issues) * 10)

    print(f"=== Readability Report: {filepath} ===")
    print(f"Quality Score: {score}/100")
    if issues:
        print(f"\n{len(issues)} issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("No issues found. Report passes all quality checks.")

    return {'score': score, 'issues': issues}

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "report.md"
    analyze_readability(target)
```

---

## Report Formatting Pipelines

### Multi-Format Report Export with Watermarking

```bash
#!/bin/bash
# Export security report to PDF, DOCX, and HTML with CONFIDENTIAL watermark
# Usage: ./export-report.sh report.md

REPORT="${1:-report.md}"
BASENAME=$(basename "$REPORT" .md)
OUTPUT_DIR="exports/$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "[EXPORT] Processing $REPORT..."

# Generate PDF with confidential watermark and TOC
pandoc "$REPORT" -o "$OUTPUT_DIR/${BASENAME}.pdf" \
  --pdf-engine=xelatex \
  --toc --toc-depth=3 \
  --number-sections \
  -V geometry:margin=1in \
  -V fontsize=11pt \
  -V colorlinks=true \
  -V header-includes='\\usepackage{draftwatermark}\\SetWatermarkText{CONFIDENTIAL}\\SetWatermarkScale{0.5}' \
  --highlight-style=tango

# Generate DOCX
pandoc "$REPORT" -o "$OUTPUT_DIR/${BASENAME}.docx" --toc

# Generate standalone HTML
pandoc "$REPORT" -o "$OUTPUT_DIR/${BASENAME}.html" --standalone --toc --self-contained

# Generate summary text file
echo "Report: $BASENAME" > "$OUTPUT_DIR/${BASENAME}-summary.txt"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_DIR/${BASENAME}-summary.txt"
echo "Words: $(wc -w < "$REPORT")" >> "$OUTPUT_DIR/${BASENAME}-summary.txt"
echo "Findings: $(grep -c '###.*FIND-\|###.*CVE-' "$REPORT" 2>/dev/null || echo 0)" >> "$OUTPUT_DIR/${BASENAME}-summary.txt"

echo "[EXPORT] All formats generated in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/${BASENAME}".*
```

### Report Diff Comparison Tool

```bash
#!/bin/bash
# Compare two report versions to track changes between revisions
# Usage: ./report-diff.sh report_v1.md report_v2.md

REPORT_OLD="${1:-report_v1.md}"
REPORT_NEW="${2:-report_v2.md}"
OUTPUT="reports/diff-$(date +%Y%m%d-%H%M%S).md"

echo "# Report Change Log" > "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Comparing: $(basename "$REPORT_OLD") vs $(basename "$REPORT_NEW")" >> "$OUTPUT"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Find added findings
echo "## New Findings" >> "$OUTPUT"
comm -23 \
  <(grep -oP '(?<=### ).*' "$REPORT_NEW" | sort) \
  <(grep -oP '(?<=### ).*' "$REPORT_OLD" | sort) >> "$OUTPUT" 2>/dev/null

echo "" >> "$OUTPUT"

# Find removed findings
echo "## Removed Findings" >> "$OUTPUT"
comm -13 \
  <(grep -oP '(?<=### ).*' "$REPORT_NEW" | sort) \
  <(grep -oP '(?<=### ).*' "$REPORT_OLD" | sort) >> "$OUTPUT" 2>/dev/null

echo "" >> "$OUTPUT"

# Word count comparison
OLD_WORDS=$(wc -w < "$REPORT_OLD")
NEW_WORDS=$(wc -w < "$REPORT_NEW")
DELTA=$((NEW_WORDS - OLD_WORDS))

echo "## Statistics" >> "$OUTPUT"
echo "- Old version: $OLD_WORDS words" >> "$OUTPUT"
echo "- New version: $NEW_WORDS words" >> "$OUTPUT"
echo "- Change: ${DELTA} words" >> "$OUTPUT"

echo "[DIFF] Comparison saved to $OUTPUT"
```
