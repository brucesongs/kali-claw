# OWASP Audit Methodology

> This guide provides a deep-dive methodology for conducting systematic OWASP-based security audits.
> Companion to `SKILL.md` (review workflow), `payloads.md` (commands and payloads), and `test-cases.md` (structured test scenarios).

---

## Index

1. [Audit Planning](#1-audit-planning)
2. [Attack Surface Mapping](#2-attack-surface-mapping)
3. [Priority Ranking](#3-priority-ranking)
4. [Evidence Collection Best Practices](#4-evidence-collection-best-practices)
5. [Report Writing](#5-report-writing)
6. [Common Audit Pitfalls](#6-common-audit-pitfalls)

---

## 1. Audit Planning

### 1.1 Scope Definition

Define audit boundaries before starting. A well-defined scope prevents wasted effort and legal issues.

**Scope document checklist:**
- Target systems (IP ranges, domains, applications)
- Target components (web app, API, mobile app, infrastructure)
- Out-of-scope systems (explicitly excluded)
- Testing types permitted (black-box, gray-box, white-box)
- Restrictions (no DoS, no data exfiltration, time windows)
- Point of contact for emergency situations
- Rules of engagement signed by both parties

**Scope template:**
```
AUDIT SCOPE DOCUMENT
====================
Client:          [Organization Name]
Engagement ID:   [ENG-YYYY-NNN]
Start Date:      YYYY-MM-DD
End Date:        YYYY-MM-DD

IN SCOPE:
  - [Application/domain/system]

OUT OF SCOPE:
  - [Excluded systems]

TESTING TYPE:    [Black-box / Gray-box / White-box]
RESTRICTIONS:    [No DoS, no social engineering, etc.]
CONTACT:         [Name, phone, email]
```

### 1.2 Engagement Types

| Type | Access Level | Approach | Time Estimate |
|------|-------------|----------|---------------|
| Black-box | No internal knowledge | External attacker perspective | 2-4 weeks |
| Gray-box | Limited (user account, docs) | Authenticated user perspective | 1-3 weeks |
| White-box | Full source code, infra access | Developer/security team perspective | 1-2 weeks |
| Red team | No knowledge, full scope | Advanced persistent threat simulation | 4-8 weeks |

### 1.3 Time Estimation

Estimate effort based on application complexity:

| Complexity | Endpoints | Features | Estimated Time |
|-----------|-----------|----------|---------------|
| Small | 1-20 | Basic CRUD | 2-3 days |
| Medium | 20-100 | Auth, payments, file upload | 5-10 days |
| Large | 100-500 | Complex business logic, integrations | 2-3 weeks |
| Enterprise | 500+ | Microservices, multi-tenant | 3-6 weeks |

**Breakdown by phase:**
- Planning and scope: 10% of total time
- Attack surface mapping: 15% of total time
- Active testing: 50% of total time
- Evidence collection: 10% of total time
- Report writing: 15% of total time

### 1.4 Tool Selection

**Essential tools (always have ready):**

| Category | Tools | Purpose |
|----------|-------|---------|
| Proxy | Burp Suite, OWASP ZAP | HTTP interception and modification |
| Scanning | Nmap, Nikto, nuclei | Port scanning, web scanning |
| Secret detection | TruffleHog, Gitleaks | Hardcoded secret discovery |
| Dependency audit | npm audit, pip-audit, Trivy | Known vulnerability scanning |
| Exploitation | sqlmap, Metasploit | Vulnerability exploitation |
| TLS testing | testssl.sh, SSLyze | TLS/SSL configuration audit |
| Documentation | CherryTree, Obsidian | Finding documentation |

**Optional tools (situational):**
- Ghidra / IDA -- binary analysis (white-box)
- Frida / Objection -- mobile app testing
- Cadaver -- WebDAV testing
- Arjun / ffuf -- parameter discovery and fuzzing

---

## 2. Attack Surface Mapping

### 2.1 Entry Point Identification

Systematically identify every way a user or system can interact with the target.

**Web application entry points:**
1. **URL parameters** -- GET query strings
2. **POST bodies** -- Form data, JSON, XML
3. **HTTP headers** -- User-Agent, Referer, Cookie, X-Forwarded-For, Custom headers
4. **File uploads** -- Avatar, document, import features
5. **API endpoints** -- REST, GraphQL, SOAP, WebSocket
6. **Webhooks** -- Callback URLs, event subscriptions
7. **Email addresses** -- User registration, password reset, notification settings
8. **Third-party integrations** -- OAuth callbacks, SAML endpoints, payment webhooks

**Infrastructure entry points:**
1. **Open ports** -- All listening services (nmap scan)
2. **DNS records** -- Subdomains, mail records, TXT records
3. **Cloud services** -- S3 buckets, CDN, load balancers
4. **Administrative interfaces** -- CMS admin, database management, monitoring dashboards

**Enumeration checklist:**
```bash
# Port scanning
nmap -sV -sC -p- target -oN full_scan.txt

# Directory and file discovery
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Subdomain enumeration
subfinder -d target.com -silent | httprobe

# Technology detection
whatweb http://target
wappalyzer http://target

# API endpoint discovery
curl -s http://target/swagger.json
curl -s http://target/api-docs
curl -s http://target/openapi.json
```

### 2.2 Data Flow Mapping

Trace how data moves through the application to identify where validation may be missing.

**Data flow analysis steps:**
1. Identify all data sources (user input, APIs, databases, file system, external services)
2. Map each data flow from source to sink
3. Identify transformation points (parsing, serialization, encoding)
4. Locate storage points (database writes, file system, cache, logs)
5. Identify output points (HTML rendering, API responses, file downloads, emails)

**Critical data flow patterns to trace:**

```
User Input
  -> Parser/Deserializer
    -> Business Logic
      -> Database Query (SQL injection risk)
      -> Command Execution (command injection risk)
      -> Template Rendering (SSTI risk)
      -> File System (path traversal risk)
      -> API Call (SSRF risk)
    -> Output Encoding
      -> HTTP Response (XSS risk)
```

**Trust boundary analysis:**

| Boundary | From | To | Risks |
|----------|------|----|-------|
| Internet to app | Browser | Web server | Input validation, WAF bypass |
| App to database | Application | Database | SQL injection, ORM misuse |
| App to filesystem | Application | Disk | Path traversal, file upload |
| App to external service | Application | Third-party API | SSRF, API key exposure |
| App to user | Application | Browser | XSS, data leakage |
| Internal network | App server | Database server | Lateral movement, MITM |

### 2.3 Trust Boundary Analysis

Identify where trust levels change and validation must occur.

**Trust levels (high to low):**
1. **System level** -- OS kernel, root processes
2. **Application level** -- Server-side application logic
3. **Session level** -- Authenticated user context
4. **Anonymous level** -- Unauthenticated web traffic
5. **External level** -- Third-party services, public APIs

**For each trust boundary, verify:**
- Authentication is required and verified
- Authorization checks exist for the specific operation
- Input validation occurs at the boundary (not just at the UI)
- Output encoding is appropriate for the destination trust level
- Logging records cross-boundary operations

---

## 3. Priority Ranking

### 3.1 Risk-Based Prioritization

Rank findings and testing efforts by risk. Risk = Impact x Likelihood.

**Impact scoring:**

| Impact Level | Criteria | Score |
|-------------|----------|-------|
| Critical | Full system compromise, mass data breach, RCE | 5 |
| High | Privilege escalation, significant data exposure | 4 |
| Medium | Limited data access, service disruption | 3 |
| Low | Information leakage, minor misconfiguration | 2 |
| Info | Best practice deviation, no direct exploit | 1 |

**Likelihood scoring:**

| Likelihood | Criteria | Score |
|-----------|----------|-------|
| Very High | Unauthenticated, easily automated | 5 |
| High | Authenticated user, simple exploit | 4 |
| Medium | Requires specific conditions or chained attacks | 3 |
| Low | Requires insider knowledge or rare conditions | 2 |
| Very Low | Theoretical, requires multiple unlikely conditions | 1 |

**Risk matrix:**

|  | Impact 5 | Impact 4 | Impact 3 | Impact 2 | Impact 1 |
|--|---------|---------|---------|---------|---------|
| **Likelihood 5** | CRITICAL | CRITICAL | HIGH | MEDIUM | LOW |
| **Likelihood 4** | CRITICAL | HIGH | HIGH | MEDIUM | LOW |
| **Likelihood 3** | HIGH | HIGH | MEDIUM | LOW | LOW |
| **Likelihood 2** | MEDIUM | MEDIUM | LOW | LOW | INFO |
| **Likelihood 1** | LOW | LOW | LOW | INFO | INFO |

### 3.2 Quick Wins vs Deep Analysis

**Quick wins (test first, fast results):**

| Test | Time | Common Findings |
|------|------|-----------------|
| Default credentials | 5 min | Admin panels with factory passwords |
| Exposed files (.env, .git) | 10 min | Source code, database credentials |
| Security headers | 5 min | Missing HSTS, CSP, X-Frame-Options |
| TLS configuration | 15 min | Weak ciphers, expired certificates |
| Directory listing | 10 min | Exposed backup files, config files |
| Error handling | 15 min | Stack traces, internal paths in errors |
| Dependency audit | 20 min | Known CVEs in outdated libraries |

**Deep analysis (allocate more time):**

| Test | Time | Skill Required |
|------|------|---------------|
| Business logic flaws | 2-4 hours | Domain knowledge, creative thinking |
| IDOR across all endpoints | 2-3 hours | Methodical testing with multiple accounts |
| Race conditions | 1-3 hours | Concurrent request scripting |
| Authentication bypass chains | 2-4 hours | Understanding of auth protocols |
| Second-order injection | 1-2 hours | Understanding of data persistence |
| Cryptographic weaknesses | 2-4 hours | Crypto knowledge, custom implementation review |

---

## 4. Evidence Collection Best Practices

### 4.1 Screenshot Standards

Every finding must have clear, reproducible evidence.

**Screenshot requirements:**
- Include the URL bar showing the target domain
- Show the full HTTP request and response when relevant
- Use browser developer tools to highlight relevant data
- Include timestamps in the screenshot (system clock visible)
- Annotate screenshots to highlight the vulnerability
- Redact any real user data (PII, credentials) before including in report

**Naming convention:**
```
[ENG-ID]_[SEVERITY]_[FINDING-NUMBER]_[DESCRIPTION].png
Example: ENG-2026-001_HIGH_003_sql-injection-user-search.png
```

### 4.2 HTTP Request/Response Capture

**Burp Suite evidence collection:**
1. Save each finding as a separate issue in Burp
2. Export the specific request/response pair
3. Annotate with description and severity
4. Include the full raw request (headers + body)

**Manual curl capture:**
```bash
# Capture full request and response with timestamps
echo "=== Request ===" > evidence_001.txt
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence_001.txt
echo "Target: http://target/api/users?id=1" >> evidence_001.txt
echo "" >> evidence_001.txt
curl -v http://target/api/users?id=1 2>&1 | tee -a evidence_001.txt

# Capture response headers only
curl -sI http://target/api/users?id=1 > headers_001.txt

# Save response body with sensitive data highlighted
curl -s http://target/api/users?id=1 | jq '.' > response_001.json
```

**What to capture for each finding:**
- Full HTTP request (method, URL, headers, body)
- Full HTTP response (status code, headers, body)
- Modified request demonstrating the vulnerability
- Original (benign) request for comparison
- Any intermediate redirects

### 4.3 Log Preservation

**Preserve testing logs:**
```bash
# Timestamp all testing activities
script -f testing_session_$(date +%Y%m%d_%H%M%S).log

# Save nmap scans in all formats
nmap -sV -sC target -oA scan_$(date +%Y%m%d)

# Save sqlmap output
sqlmap -u "http://target/page?id=1" --batch --output-dir=./sqlmap_results

# Save directory scan results
feroxbuster -u http://target -w wordlist.txt -o feroxbuster_$(date +%Y%m%d).txt
```

**Chain of custody:**
- Hash all evidence files after collection (`sha256sum evidence/* > hashes.txt`)
- Store evidence in a secure, access-controlled location
- Never modify original evidence files (work on copies)
- Maintain a chronological activity log

---

## 5. Report Writing

### 5.1 Executive Summary Template

The executive summary must be understandable by non-technical stakeholders.

```markdown
# Executive Summary

## Engagement Overview
A security assessment of [Application Name] was conducted between
[Start Date] and [End Date]. The assessment covered [scope summary]
using a [Black-box/Gray-box/White-box] testing methodology.

## Overall Risk Rating: [CRITICAL / HIGH / MEDIUM / LOW]

## Key Findings Summary
- [N] Critical findings requiring immediate remediation
- [N] High severity findings requiring urgent attention
- [N] Medium severity findings requiring planned remediation
- [N] Low severity findings and informational notes

## Top 3 Risks
1. [Most critical finding and business impact]
2. [Second most critical finding and business impact]
3. [Third most critical finding and business impact]

## Recommended Immediate Actions
1. [Action for most critical finding]
2. [Action for second critical finding]
3. [Action for third critical finding]
```

### 5.2 Technical Findings Format

Each finding follows a consistent structure:

```markdown
## Finding [NNN]: [Title]

**Severity**: [CRITICAL / HIGH / MEDIUM / LOW / INFO]
**OWASP Category**: [A01-A10 category name]
**CWE**: [CWE-ID] - [CWE Name]
**Location**: [URL / file path / endpoint]
**Status**: [Open / Confirmed / Accepted Risk / Fixed]

### Description
[Clear explanation of the vulnerability, what it is, and why it matters.
Avoid jargon when possible. Include the attack vector.]

### Steps to Reproduce
1. Navigate to [URL]
2. Submit [payload] in [parameter]
3. Observe [result demonstrating the vulnerability]

### Evidence
[Include request/response pairs, screenshots, and tool output.
Redact sensitive data. Reference evidence files by name.]

### Impact
[Describe what an attacker can achieve. Include:
- Confidentiality impact (data exposure)
- Integrity impact (data modification)
- Availability impact (service disruption)
- Business impact (regulatory, financial, reputational)]

### Remediation
[Specific, actionable steps to fix the vulnerability. Include:
- Immediate mitigation (quick fix)
- Long-term fix (proper solution)
- Verification steps (how to confirm the fix works)]

### References
- [OWASP link]
- [CWE link]
- [Vendor advisory or best practice guide]
```

### 5.3 Severity Justification

Always justify severity ratings with objective criteria:

| Factor | Questions to Answer |
|--------|-------------------|
| Attack vector | Network (remote) vs local vs physical? |
| Attack complexity | Simple exploit vs requires specific conditions? |
| Privileges required | None vs low (user) vs high (admin)? |
| User interaction | None vs required (clicking a link)? |
| Confidentiality | None vs partial vs complete data exposure? |
| Integrity | None vs modification vs complete system compromise? |
| Availability | None vs degraded vs complete outage? |
| Scope | Same component vs crosses trust boundary? |
| Business context | Regulatory requirements? PII involved? Financial data? |

### 5.4 Remediation Guidance

**Prioritize remediation:**

| Priority | Timeline | Criteria |
|----------|----------|----------|
| P1 - Immediate | 24-48 hours | RCE, data breach, authentication bypass |
| P2 - Urgent | 1 week | Privilege escalation, significant data exposure |
| P3 - Planned | 1 month | Limited data exposure, configuration issues |
| P4 - Scheduled | 1 quarter | Best practice improvements, informational |

**Remediation verification:**
1. Developer implements fix per guidance
2. Security team retests the specific finding
3. Original reproduction steps followed exactly
4. Confirm vulnerability is no longer exploitable
5. Check for regressions in related functionality
6. Update finding status to Fixed with verification date

---

## 6. Common Audit Pitfalls

### 6.1 Scope Creep

**Problem**: Testing drifts beyond defined boundaries, wasting time and potentially violating authorization.

**Warning signs:**
- Testing systems not listed in scope document
- Spending time on findings outside the engagement
- Investigating vulnerabilities on third-party services

**Prevention:**
- Keep the scope document visible during testing
- Log all systems tested against the scope
- When uncertain, ask the client before proceeding
- Document scope expansion requests separately

**Response:** When scope creep is detected, pause, review the scope document, and redirect effort. If a critical finding is discovered on an out-of-scope system, notify the client immediately but do not pursue further without written authorization.

### 6.2 Confirmation Bias

**Problem**: Finding one vulnerability and subconsciously looking only for evidence that confirms it, while missing other issues.

**Warning signs:**
- Spending disproportionate time on a single finding type
- Ignoring negative test results without documentation
- Focusing only on the technology stack you know best

**Prevention:**
- Follow the OWASP checklist methodically (see SKILL.md)
- Test each category for a fixed amount of time before moving on
- Use the test cases in `test-cases.md` as a forcing function
- Have a peer review your testing approach
- Document negative results (what was tested and not vulnerable)

### 6.3 Tool Reliance

**Problem**: Relying solely on automated scanners and missing vulnerabilities that require manual testing.

**What automated tools miss:**
- Business logic flaws (negative price, skip payment step)
- Multi-step authentication bypasses
- Race conditions and timing attacks
- Authorization issues (IDOR, privilege escalation)
- Context-specific injection (second-order, stored via different path)
- Cryptographic implementation errors

**Prevention:**
- Use tools for reconnaissance and initial scanning only
- Manually verify every finding (avoid false positives in the report)
- Spend at least 60% of testing time on manual exploration
- Combine automated scanning with manual walkthrough of all features
- Test business logic flows end-to-end as a real user would

### 6.4 Missing Business Logic Flaws

**Problem**: Focusing on technical vulnerabilities while missing flaws in the application's business rules.

**Common business logic vulnerabilities:**

| Category | Example |
|----------|---------|
| Price manipulation | Negative quantity, zero-price item, currency mismatch |
| Workflow bypass | Skip payment step, access confirmation page directly |
| Quantity limits | Order unlimited items, exceed account limits |
| Time-based attacks | Use expired coupons, access time-limited features |
| Referral/loyalty abuse | Self-referral, point multiplication via race condition |
| Data inconsistency | Modify hidden fields to change order total |
| State manipulation | Access account settings before email verification |

**Testing approach:**
1. Understand the intended business workflow completely
2. Identify each decision point and validation check
3. Attempt to skip steps or modify intermediate state
4. Test edge cases: negative values, zero, maximum values, concurrent requests
5. Verify server-side enforcement of every business rule
6. Test as both a legitimate user and an attacker would

### 6.5 Poor Communication

**Problem**: Failing to communicate critical findings promptly, leading to extended exposure.

**Communication protocol:**

| Finding Severity | Communication Action | Timeline |
|-----------------|---------------------|----------|
| CRITICAL | Immediate phone call + encrypted email | Within 1 hour |
| HIGH | Encrypted email to primary contact | Within 4 hours |
| MEDIUM | Include in regular status update | Next status meeting |
| LOW/INFO | Include in final report | At engagement end |

**Best practices:**
- Establish communication channels before testing begins
- Use encrypted channels for finding details (PGP email, secure portal)
- Provide actionable interim reports for critical findings
- Schedule regular check-ins (daily or every other day)
- Never disclose findings to unauthorized parties

### 6.6 Insufficient Retesting

**Problem**: Accepting developer claims that a vulnerability is fixed without independent verification.

**Retesting protocol:**
1. Re-execute the exact reproduction steps from the original finding
2. Verify with the same payload that previously demonstrated the issue
3. Test variations of the original attack vector (bypass attempts)
4. Confirm the fix does not introduce new vulnerabilities
5. Document the retest result with evidence (request/response)
6. Only mark finding as "Verified Fixed" after independent confirmation

---

## Appendix: OWASP Top 10 (2021) Quick Reference

| ID | Category | Key Test Areas |
|----|----------|---------------|
| A01 | Broken Access Control | IDOR, privilege escalation, forced browsing, CORS |
| A02 | Cryptographic Failures | Plaintext transmission, weak ciphers, key management |
| A03 | Injection | SQLi, command injection, LDAP injection, SSTI, XSS |
| A04 | Insecure Design | Business logic abuse, threat modeling gaps |
| A05 | Security Misconfiguration | Default configs, open cloud storage, verbose errors |
| A06 | Vulnerable Components | Outdated libraries, known CVEs, unpatched systems |
| A07 | Auth Failures | Brute force, weak passwords, session management |
| A08 | Software and Data Integrity | CI/CD pipeline, insecure deserialization, auto-updates |
| A09 | Logging and Monitoring | Missing security logs, no alerting, log injection |
| A10 | SSRF | Internal network access, cloud metadata, port scanning |
