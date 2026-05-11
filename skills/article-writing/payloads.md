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
