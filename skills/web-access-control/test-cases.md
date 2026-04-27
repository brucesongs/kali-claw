# Broken Access Control Test Cases

> This file is a companion to `SKILL.md`, providing structured access control test case templates.
> Purpose: Check each item during penetration testing to ensure no critical test points are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-CXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. IDOR Testing](#a-idor-testing)
- [B. Privilege Escalation](#b-privilege-escalation)
- [C. Path Traversal](#c-path-traversal)
- [D. Forced Browsing & Parameter Tampering](#d-forced-browsing--parameter-tampering)

---

## A. IDOR Testing

### TC-C001 | Horizontal Privilege Escalation — Integer ID Replacement

- **Severity**: CRITICAL
- **Prerequisites**: Have at least two different user credentials (User_A, User_B), known resource IDs
- **Test Steps**:
  1. Use User_A credentials to access `/api/v1/users/{User_A_ID}/profile`
  2. Use User_A credentials to access `/api/v1/users/{User_B_ID}/profile`
  3. Compare both responses
  4. Use ffuf for batch ID replacement (see payloads.md §1)
- **Expected Results**: Step 2 returns 200 with User_B data -> IDOR confirmed
- **Reference**: payloads.md §1 IDOR

### TC-C002 | Horizontal Privilege Escalation — UUID-type ID

- **Severity**: CRITICAL
- **Prerequisites**: API uses UUIDs as resource identifiers
- **Test Steps**:
  1. Collect UUIDs from User_A's API responses (posts, documents, orders, etc.)
  2. Use User_B credentials to access each of these UUID-corresponding resources
  3. Check for predictable UUID patterns (UUID v1 contains timestamp + MAC)
- **Expected Results**: User_B can access User_A's resources -> IDOR confirmed
- **Reference**: payloads.md §1 UUID-type IDOR

### TC-C003 | Multi-Level IDOR

- **Severity**: HIGH
- **Prerequisites**: API has nested resource paths (e.g., `/orgs/{id}/projects/{id}/docs/{id}`)
- **Test Steps**:
  1. Access multi-level resources belonging to User_A
  2. Replace IDs level by level: organization level, project level, document level
  3. Identify which level is missing authorization checks
- **Expected Results**: Still accessible after replacing a certain level's ID -> That level is missing authorization verification
- **Reference**: payloads.md §1 Multi-Level IDOR

---

## B. Privilege Escalation

### TC-C004 | Vertical Privilege Escalation — Direct Admin Endpoint Access

- **Severity**: CRITICAL
- **Prerequisites**: Have regular user credentials
- **Test Steps**:
  1. Use regular user credentials to batch access admin endpoints (see payloads.md §2)
  2. Record endpoints that return 200
  3. Test data modification operations on these endpoints
- **Expected Results**: Regular user can access admin functions -> Vertical privilege escalation
- **Reference**: payloads.md §2 Vertical Privilege Escalation

### TC-C005 | Role Parameter Tampering

- **Severity**: HIGH
- **Prerequisites**: Have regular user credentials, known user update endpoint
- **Test Steps**:
  1. Normal Profile update: `{"name":"Test"}`
  2. Inject `{"name":"Test","role":"admin"}`
  3. Inject `{"name":"Test","is_admin":true}`
  4. Check if fields are modified in the response
- **Expected Results**: `role`/`is_admin` is successfully modified -> Privilege escalation
- **Reference**: payloads.md §2 Role Parameter Tampering

### TC-C006 | JWT Claims Tampering Privilege Escalation

- **Severity**: CRITICAL
- **Prerequisites**: JWT contains role/permission claims, signing key known or alg:none exists
- **Test Steps**:
  1. Decode JWT, check role/permissions claims
  2. Tamper claims: `role: "user"` -> `role: "admin"`
  3. Re-sign (using key brute force/alg:none/algorithm confusion)
  4. Use tampered Token to access admin endpoints
- **Expected Results**: Tampered Token is accepted -> Privilege escalation via JWT tampering
- **Related**: `skills/web-auth-bypass/SKILL.md` JWT Attacks section

---

## C. Path Traversal

### TC-C007 | Basic Path Traversal

- **Severity**: HIGH
- **Prerequisites**: Application accepts filename/path parameters
- **Test Steps**:
  1. Test `../../../etc/passwd`
  2. Check if response contains root:x:0:0 etc.
  3. If filtered, try encoding bypass (see payloads.md §3)
- **Expected Results**: Response contains system file contents -> Path traversal confirmed
- **Reference**: payloads.md §3 Path Traversal

### TC-C008 | URL Encoding Bypass for Path Traversal Filtering

- **Severity**: HIGH
- **Prerequisites**: Basic path traversal is blocked by WAF/filter
- **Test Steps**:
  1. Single URL encoding: `..%2f..%2f..%2fetc/passwd`
  2. Double encoding: `..%252f..%252f..%252fetc/passwd`
  3. Unicode encoding: `..%c0%ae%c0%ae%c0%afetc/passwd`
  4. Mixed bypass: `....//....//....//etc/passwd`
- **Expected Results**: Any variant bypasses filtering -> Path traversal + WAF bypass
- **Reference**: payloads.md §3 URL Encoding Bypass

### TC-C009 | Windows Target Path Traversal

- **Severity**: HIGH
- **Prerequisites**: Target is a Windows server
- **Test Steps**:
  1. `..\\..\\..\\windows\\win.ini`
  2. `..\\..\\..\\inetpub\\wwwroot\\web.config`
  3. Check if response contains `[fonts]` or connection strings
- **Expected Results**: Response contains Windows system file contents

---

## D. Forced Browsing & Parameter Tampering

### TC-C010 | Direct Access to Sensitive Files

- **Severity**: MEDIUM
- **Prerequisites**: Known target web root path
- **Test Steps**:
  1. Probe backup files: backup.sql, dump.sql, users.csv
  2. Probe configuration files: .env, config.yml, application.properties
  3. Probe Git disclosure: .git/HEAD
  4. Check response code for each request
- **Expected Results**: Sensitive files return 200 -> Forced browsing vulnerability
- **Reference**: payloads.md §4 Forced Browsing

### TC-C011 | HTTP Method Tampering to Bypass Access Control

- **Severity**: HIGH
- **Prerequisites**: Known protected admin endpoint (returns 403)
- **Test Steps**:
  1. Use GET to request admin endpoint, record response (assumed 403)
  2. Try POST/PUT/DELETE/PATCH/HEAD/OPTIONS one by one
  3. Record each method's response code
- **Expected Results**: A method returns 200 -> Method-level access control missing
- **Reference**: payloads.md §6 HTTP Method Tampering

### TC-C012 | Header Spoofing to Bypass Access Control

- **Severity**: HIGH
- **Prerequisites**: Admin endpoint returns 403
- **Test Steps**:
  1. Add `X-Original-URL: /admin/dashboard`
  2. Add `X-Custom-IP-Authorization: 127.0.0.1`
  3. Add `X-Forwarded-For: 127.0.0.1`
  4. Combine multiple Headers for testing
- **Expected Results**: Returns 200 after adding Headers -> Header-based bypass
- **Reference**: payloads.md §7 Header Spoofing Bypass

### TC-C013 | URL Encoding Obfuscation to Bypass Route Filtering

- **Severity**: MEDIUM
- **Prerequisites**: Admin path returns 403
- **Test Steps**:
  1. Case obfuscation: `/Admin/Dashboard`
  2. Path parameters: `/admin;/dashboard`
  3. Null byte injection: `/admin%00/dashboard`
  4. URL encoding: `/%61dmin/%64ashboard`
- **Expected Results**: Any variant returns 200 -> Route parsing bypass
- **Reference**: payloads.md §5 Parameter Tampering

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. IDOR Testing | 3 | 2 | 1 | 0 | 0 |
| B. Privilege Escalation | 3 | 2 | 1 | 0 | 0 |
| C. Path Traversal | 3 | 0 | 3 | 0 | 0 |
| D. Forced Browsing & Parameter Tampering | 4 | 0 | 2 | 2 | 0 |
| **Total** | **13** | **4** | **7** | **2** | **0** |
