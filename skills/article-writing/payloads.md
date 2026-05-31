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
