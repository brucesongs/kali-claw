# Pentest Report Structure Best Practices

Standard structure for professional penetration test reports.

## Report Sections (In Order)

### 1. Cover Page
- Client name
- Engagement title
- Date range
- Version number
- Classification (Confidential/Restricted)

### 2. Table of Contents
- Auto-generated with page numbers

### 3. Executive Summary (1-2 pages)
- **Audience**: C-level, non-technical
- **Content**:
  - Brief description of engagement
  - Summary of findings by severity
  - Top 3 risks
  - Recommended priority actions
- **Tone**: Business impact, not technical details

### 4. Scope & Methodology (1 page)
- **In Scope**: URLs, IP ranges, systems tested
- **Out of Scope**: Systems excluded
- **Methodology**: OWASP, PTES, NIST, or custom
- **Tools**: List of primary tools used

### 5. Findings (Main Body)
- **Order**: Critical → High → Medium → Low
- **Each Finding**:
  - Title
  - Severity + CVSS
  - Description
  - Evidence (screenshot, logs, commands)
  - Impact
  - Remediation (short-term + long-term)

### 6. Summary & Recommendations (1 page)
- Overall security posture
- Priority remediation roadmap
- Long-term improvements

### 7. Appendix
- Detailed tool list with versions
- Testing timeline
- Raw scan outputs (if requested)
- References

---

## Page Limits by Report Size

| Engagement Size | Expected Pages |
|-----------------|---------------|
| Small (1-3 days) | 10-20 pages |
| Medium (1-2 weeks) | 20-40 pages |
| Large (2+ weeks) | 40-80 pages |

---

## Formatting Standards

- **Font**: Arial or Calibri, 11-12pt
- **Headings**: Bold, larger font
- **Code/Commands**: Monospace font, gray background
- **Screenshots**: Caption below, reference in text
- **Tables**: Border lines, alternating row colors

---

## Common Mistakes to Avoid

1. **Too much technical detail in executive summary** — save it for findings section
2. **No evidence** — every claim needs proof
3. **Generic remediation** — be specific to the client's tech stack
4. **Missing CVSS scores** — clients expect quantified severity
5. **Unsanitized data** — real IPs/domains/credentials must be redacted

---

## Detailed Section Explanations with Examples

### Cover Page — More Than Just a Title

The cover page sets the professional tone and serves as a legal document boundary. Include:

- **Engagement reference number**: A unique identifier that links to the contract, SOW, and Rules of Engagement. Example: `PT-2026-0042-ACME`
- **Distribution list**: Names and roles of authorized recipients. This establishes chain of custody for sensitive findings.
- **Document version**: Critical for tracking revisions. Use semantic versioning: `v1.0` for initial delivery, `v1.1` for minor corrections, `v2.0` after retest.
- **Legal disclaimer**: Specify that the report is confidential, intended solely for the named recipients, and that unauthorized distribution may violate the engagement contract.

Example:
```
PENETRATION TEST REPORT
Engagement: PT-2026-0042-ACME
Client: ACME Corporation
Title: External Infrastructure Penetration Test — Q2 2026
Date Range: 2026-05-01 to 2026-05-15
Version: 1.0 (Initial Delivery)
Classification: CONFIDENTIAL
Distribution: Jane Smith (CISO), John Doe (VP Engineering), Security Team
```

### Table of Contents — Navigation Matters

Auto-generated TOC is essential for reports exceeding 10 pages. Ensure that:
- Heading levels are consistent (do not skip H2 to H4)
- Page numbers are correct after final formatting
- Include a separate listing for figures, tables, and appendices
- In PDF reports, make TOC entries clickable/hyperlinked

### Executive Summary — The Most Important Page

This section requires a distinct writing approach. Follow this structure:

**Paragraph 1 — Engagement Overview**: What was tested, when, by whom, and under what methodology. One or two sentences.

**Paragraph 2 — Key Findings**: Total findings by severity with a single overall risk rating. Reference the most critical issues by name.

**Paragraph 3 — Business Impact**: Translate technical findings into business consequences. Mention regulatory frameworks (PCI DSS, HIPAA, GDPR) if applicable.

**Paragraph 4 — Recommended Actions**: Top 3 priorities with estimated remediation timeline.

Example of a strong executive summary paragraph:
```
The assessment identified 23 security findings, including 3 critical-severity
vulnerabilities that pose immediate risk of unauthorized data access. The most
significant finding is an unauthenticated SQL injection vulnerability in the
customer portal (F-001), which could allow an attacker to extract the full
customer database containing personally identifiable information. Under GDPR
Article 32, this represents a significant compliance gap requiring immediate
remediation. We recommend addressing all critical findings within 48 hours and
conducting a full retest within 30 days.
```

### Scope and Methodology — Defining the Boundary

This section protects both the tester and the client. Be exhaustive:

**In-Scope**: List every IP range, domain, application, and system with explicit identifiers. Include testing methods authorized (e.g., "authenticated and unauthenticated testing," "denial of service excluded").

**Out-of-Scope**: Explicitly state what was excluded and why. This prevents misunderstandings about incomplete coverage.

**Limitations**: Document anything that limited testing effectiveness — VPN instability, rate limiting, WAF blocking legitimate test traffic, systems that were down during the test window.

**Methodology Reference**: Name the framework (OWASP WSTG v4.2, PTES, NIST SP 800-115) and note any deviations with justification.

---

## Writing Findings for Different Audiences

### Executive Audience

Executives need to understand risk, not mechanism. Write findings in a layered format:

```
**Executive Summary (2-3 sentences)**:
An attacker can bypass the login system without credentials, gaining full
access to all customer records. This vulnerability could lead to a data
breach affecting approximately 500,000 customer accounts, with potential
regulatory fines under GDPR exceeding €10M.

**Technical Details** (separate section, clearly labeled):
The username parameter in the authentication endpoint at /api/v2/auth/login
is vulnerable to union-based SQL injection...
```

### Technical Audience

Developers and security engineers need precise reproduction steps, code references, and fix examples:

```
**Affected Code**: src/api/auth/handlers.py, line 142
**Vulnerable Pattern**: String concatenation in SQL query construction
**Attack Vector**: HTTP POST to /api/v2/auth/login, username parameter
**Required Payload**: ' UNION SELECT 1,2,3,password FROM users--
```

### Compliance and Audit Audience

For organizations with regulatory requirements, frame findings in compliance language:

```
**Regulatory Mapping**:
- PCI DSS v4.0: Requirement 6.5 (Injection Flaws) — Non-compliant
- OWASP Top 10 2021: A03 Injection — Present
- CIS Controls v8: Control 16 (Application Software Security) — Not Implemented
- NIST CSF: DE.CM-8 (Vulnerability Management) — Gap Identified
```

---

## Evidence Presentation Guidelines

### Screenshot Standards

- **Context**: Always include the URL bar, showing the target domain and path
- **Annotation**: Use red rectangles or arrows to highlight the exploit payload or leaked data. Never annotate with vague labels like "See here" — use specific labels: "SQL error message confirming injection"
- **Resolution**: Minimum 1920x1080, PNG format preferred for text clarity
- **Naming**: `F-001_sqli-login-step3-response.png` (finding ID, vulnerability type, step number, content description)
- **Captioning**: Every screenshot gets a numbered caption: "Figure 3: Server response confirming SQL injection — note the database error message revealing MySQL 8.0.28"

### Request/Response Presentation

Format HTTP evidence as clear request-response pairs:

```
Request:
POST /api/v2/auth/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "' OR 1=1--", "password": "anything"}

Response:
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "success", "token": "eyJhbGci...", "role": "admin"}
```

Highlight the payload and the problematic response element. Note the status code and explain why it indicates vulnerability (e.g., "The 200 OK response with an admin token confirms the authentication bypass").

### Data Tables for Scan Results

When presenting large scan outputs, summarize in tables rather than pasting raw output:

| Port | Service | Version | Vulnerability | Severity |
|------|---------|---------|---------------|----------|
| 22 | SSH | OpenSSH 7.4 | CVE-2021-41617 (privilege escalation) | Medium |
| 443 | HTTPS | nginx 1.14.0 | Outdated version, multiple CVEs | Low |
| 3306 | MySQL | 5.7.32 | No TLS, weak authentication | High |

---

## Severity Assessment Methodology

### Beyond CVSS: Contextual Severity

While CVSS provides a standardized base score, the report should also present contextual severity that accounts for the client's environment:

```
Base CVSS Score: 9.8 (Critical)
Environmental Factors:
  - Internet-facing: Yes → No adjustment
  - Authentication required: No → Confirms Critical
  - Sensitive data exposure: Yes (PII) → Confirms Critical
  - Compensating controls: WAF in place → May reduce to High
Contextual Severity: High (with WAF) / Critical (without WAF)
```

### Aggregated Risk Assessment

Provide an overall assessment that goes beyond individual findings:

```
Overall Risk Rating: HIGH

Rationale: While the application has no single Critical finding, the
combination of multiple High-severity issues (authentication weakness,
authorization bypass, and insecure data storage) creates a composite risk
that exceeds the sum of individual parts. An attacker chaining F-002 (auth
bypass) with F-005 (IDOR) and F-008 (unencrypted storage) could achieve
full database exfiltration with minimal effort.
```

---

## Remediation Roadmap Planning

### Phased Approach

Organize remediation into phases with clear timelines and resource estimates:

**Phase 1 — Emergency (0-7 days)**:
- Fix all Critical findings
- Deploy temporary mitigations (WAF rules, access restrictions)
- Rotate any compromised credentials
- Estimated effort: 2-3 senior developers, full-time

**Phase 2 — Priority (1-4 weeks)**:
- Fix all High-severity findings
- Implement missing security controls (authentication hardening, input validation)
- Deploy monitoring and alerting for exploitation attempts
- Estimated effort: 2 developers, 50% allocation

**Phase 3 — Systematic (1-3 months)**:
- Fix Medium and Low findings
- Implement security SDLC practices (code review, SAST/DAST integration)
- Conduct developer security training
- Estimated effort: 1 developer, 25% allocation + security champion support

**Phase 4 — Verification (after each phase)**:
- Retest remediated findings
- Validate that fixes do not introduce new vulnerabilities
- Update risk assessment based on remediation progress

---

## Handling Re-Testing Results

### Retest Report Structure

After the client remediates findings, produce a retest report that clearly maps to the original:

```
## Retest Results Summary

| Original ID | Original Severity | Finding | Retest Result | New Severity |
|-------------|-------------------|---------|---------------|--------------|
| F-001 | Critical | SQL Injection | FIXED | N/A |
| F-002 | High | Stored XSS | NOT FIXED | High |
| F-003 | Medium | Missing HSTS | FIXED | N/A |
| F-004 | Low | Information Disclosure | PARTIALLY FIXED | Informational |
```

### Retest Finding Format

For each retested finding, document:

1. **Original finding reference**: Link back to the original report finding
2. **Remediation applied**: What the client claims to have changed
3. **Retest methodology**: How you verified the fix
4. **Result**: FIXED / NOT FIXED / PARTIALLY FIXED / REGRESSION
5. **Evidence**: New screenshots or captures demonstrating the result
6. **Recommendation**: If not fixed, provide updated remediation guidance

### Handling Regressions

If a fix introduces a new vulnerability or re-introduces a previously fixed issue:

- Mark as REGRESSION with reference to both the original finding and the new behavior
- Assess whether the regression is more or less severe than the original
- Provide targeted guidance on avoiding regression patterns in future development
- Recommend automated testing (unit tests, integration tests) that would catch the regression

---

## Report Versioning and Change Tracking

### Version Control

Every report delivery is a versioned document. Track changes between versions:

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-05-16 | Lead Tester | Initial draft for internal review |
| 0.9 | 2026-05-18 | QA Reviewer | QA review complete, minor corrections |
| 1.0 | 2026-05-20 | Lead Tester | Final delivery to client |
| 1.1 | 2026-05-22 | Lead Tester | Clarified F-003 remediation per client feedback |
| 2.0 | 2026-06-15 | Lead Tester | Retest results added, F-001 and F-003 marked fixed |

### Change Log Format

Include a formal change log at the end of the report or in the appendix:

```
## Change Log

### v1.0 → v1.1 (2026-05-22)
- F-003: Updated remediation code example to match client's Python/Django stack
- Appendix B: Added raw Nikto scan output omitted from v1.0
- Executive Summary: Corrected finding count from 12 to 11 (F-009 merged with F-004)

### v1.1 → v2.0 (2026-06-15)
- Added Section 8: Retest Results
- F-001: Status changed to FIXED (retest confirmed 2026-06-14)
- F-002: Status remains NOT FIXED, updated remediation guidance
- F-003: Status changed to FIXED (retest confirmed 2026-06-14)
- F-010: NEW — Information disclosure discovered during retest (Medium)
```

---

## Appendix Best Practices

### Organization Principles

1. **Alphabetical by topic**: Appendix A (Tool Inventory), Appendix B (Raw Scan Data), Appendix C (Evidence Files), etc.
2. **Cross-referenced from main body**: Every appendix section should be referenced at least once from the findings. Unreferenced appendices are dead weight.
3. **Separate page numbering**: Use A-1, B-1, C-1 format so main body references stay stable across revisions.
4. **Digital delivery format**: For large appendices, provide as separate files or a ZIP archive rather than inflating the main PDF.

### Essential Appendix Contents

- **Tool configurations**: Burp project file settings, nmap command lines, custom script source code
- **Full scan exports**: XML/JSON exports from scanners, not just the summary
- **Testing log**: Timestamped record of all testing activities, useful for dispute resolution
- **Rules of Engagement**: Signed copy of the RoE for reference
- **Credential inventory**: All accounts created or used, with confirmation of cleanup
- **Glossary**: Technical terms defined for non-technical readers
