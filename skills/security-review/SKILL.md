---
name: security-review
description: "Comprehensive security checklist and review patterns for analyzing applications, configurations, and infrastructure. This skill provides structured review methodology to identify vulnerabilities across OWASP Top 10 categories during penetration testing."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Agent
metadata:
  domain: assessment
  tool_count: 0
  guide_count: 5
---




# Skill: Security Review

> **Supplementary Files**:
> - `payloads.md` — Security review commands, test payloads, and audit scripts organized by OWASP category
> - `test-cases.md` — Structured test cases for security review checklists covering secrets, input validation, injection, authentication, and data exposure
> - `guides/` — Deep-dive methodology guides for systematic security auditing

## Summary

This skill provides structured review methodology to identify vulnerabilities across OWASP Top 10 categories during penetration testing.

**Domain**: assessment

## Description

Comprehensive security checklist and review patterns for analyzing applications, configurations, and infrastructure. This skill provides structured review methodology to identify vulnerabilities across OWASP Top 10 categories during penetration testing.

Difference from `security-bounty-hunter`: bounty-hunter focuses on finding single exploitable vulnerabilities for reporting. This skill provides a systematic review framework to audit an entire application or system comprehensively.

## Use Cases

- Pre-engagement security review of target application architecture
- Source code audit during white-box penetration testing
- Configuration review of infrastructure (servers, containers, cloud services)
- Security assessment of authentication and authorization mechanisms
- Reviewing third-party integrations and API security
- Post-exploitation analysis of discovered credentials and secrets

## Methodology

### Security Review Checklist

#### 1. Secrets Management

**Check for:**
- Hardcoded API keys, tokens, passwords in source code
- Secrets in configuration files committed to version control
- Default credentials in services and admin panels
- Exposed `.env`, `.git`, backup files on web servers
- Secrets in client-side JavaScript, mobile app bundles

**Tools:**
```bash
# Scan for secrets in code
trufflehog filesystem /path/to/repo
gitleaks detect --source /path/to/repo

# Check for exposed files on web server
curl -s http://target/.env
curl -s http://target/.git/HEAD
curl -s http://target/backup.sql
curl -s http://target/config.yml.bak
```

#### 2. Input Validation

**Check for:**
- Missing server-side validation (relying on client-side only)
- Unvalidated file uploads (type, size, content)
- Direct use of user input in queries, commands, or templates
- Missing or weak content-type validation
- Insufficient output encoding

#### 3. Injection Flaws

**SQL Injection:**
- String concatenation in SQL queries
- ORM misuse (raw queries with user input)
- NoSQL injection (MongoDB operator injection)

**Command Injection:**
- User input passed to `system()`, `exec()`, `os.popen()`
- Unsanitized filenames in file operations
- Unsafe deserialization (pickle, YAML, JSON with revivers)

**LDAP Injection:**
- User input in LDAP filters without escaping

**Template Injection:**
- User input in template engines (Jinja2, Twig, Freemarker)

#### 4. Authentication & Authorization

**Authentication:**
- Weak password policies (length, complexity, rotation)
- Missing multi-factor authentication for sensitive operations
- Session management flaws (fixation, hijacking)
- Token storage (localStorage vs httpOnly cookies)
- OAuth/SAML misconfiguration

**Authorization:**
- Missing role-based access control
- Insecure direct object references (IDOR)
- Missing authorization checks on API endpoints
- Privilege escalation paths

#### 5. Security Headers & Transport

```bash
# Verify security headers
curl -sI http://target | grep -i "strict-transport\|content-security\|x-frame\|x-content-type\|x-xss"

# Check TLS configuration
nmap --script ssl-enum-ciphers -p 443 target
sslyze --regular target
```

#### 6. API Security

**Check for:**
- Missing rate limiting on API endpoints
- Excessive data in API responses (over-fetching)
- Missing input validation on API parameters
- Improper error handling leaking internal state
- API versioning and deprecation security

#### 7. Dependency Security

```bash
# Audit dependencies
npm audit
pip-audit
cargo audit

# Check for known vulnerabilities
snyk test
grype /path/to/image
trivy image target-image:tag
```

### Review Workflow

**Step 1: Surface Mapping**
- Identify all entry points (web, API, file upload, webhooks)
- Map authentication boundaries
- Identify data flows and storage locations

**Step 2: Prioritized Review**
1. Authentication and session management
2. Authorization and access control
3. Input validation and injection points
4. Secrets and sensitive data handling
5. Security headers and transport
6. Dependencies and third-party components

**Step 3: Evidence Collection**
- Document each finding with: location, severity, reproduction steps
- Capture screenshots and HTTP requests/responses
- Map findings to OWASP Top 10 and CWE classifications

**Step 4: Report**
- Executive summary with risk ratings
- Detailed findings with evidence
- Remediation recommendations prioritized by severity

### Severity Classification

| Level | Criteria | Action |
|-------|----------|--------|
| CRITICAL | Remote code execution, data breach, auth bypass | Immediate remediation |
| HIGH | Significant data exposure, privilege escalation | Remediate before release |
| MEDIUM | Limited data exposure, misconfiguration | Plan remediation |
| LOW | Information leakage, minor misconfiguration | Address when convenient |
| INFO | Best practice deviation, no direct exploit | Document for improvement |

### Defense Perspective

- **Defense in depth**: Each layer should independently prevent unauthorized access
- **Least privilege**: Grant minimum necessary permissions
- **Secure defaults**: Default configurations should be secure, not permissive
- **Fail closed**: Errors should deny access, not grant it

## Orchestration

**ECC Loop Pattern**: Sequential Pipeline

```
surface map → prioritized review → evidence collection → report
```

**Rationale**: Security reviews require systematic coverage following a defined checklist order. Each phase builds on the previous one — surface mapping identifies entry points, prioritized review allocates effort by risk, evidence collection captures reproducible findings, and report generation delivers actionable results.

**Integration**:
- `repo-scan` — codebase classification and attack surface identification (provides input for surface mapping phase)
- `terminal-ops` — evidence capture via curl, nmap, and tool output recording
- `verification-loop` — finding confirmation through independent retesting

**Cross-Skill Pipeline**:
```
repo-scan → security-review → verification-loop → chronicle
```
repo-san classifies the codebase and identifies high-value targets, security-review performs systematic OWASP audit, verification-loop confirms findings independently, chronicle archives the final report.

**Quality Gate**:
- **Pre-condition**: Target scope defined with rules of engagement documented
- **Post-condition**: All OWASP Top 10 categories assessed with findings documented
- **Verification**: Findings independently confirmed through reproduction and retesting

## Report Template

```markdown
# Security Review Report
*Target: [system/application] | Date: [date] | Scope: [boundaries]*

## Executive Summary
[Overall risk rating and key findings]

## Findings

### [SEVERITY] [Title]
- **CWE**: [CWE-ID]
- **OWASP**: [Category]
- **Location**: [file/endpoint]
- **Description**: [what was found]
- **Evidence**: [reproduction steps]
- **Impact**: [what attacker can achieve]
- **Remediation**: [how to fix]

## Summary Statistics
| Severity | Count |
|----------|-------|
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Info | N |
```
