# Authentication Bypass Test Cases

> This file is a companion to `SKILL.md`, providing structured authentication bypass test case templates.
> Purpose: Check each item during penetration testing to ensure no critical test points are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-BXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Username Enumeration](#a-username-enumeration)
- [B. Brute Force & Credential Stuffing](#b-brute-force--credential-stuffing)
- [C. JWT Security](#c-jwt-security)
- [D. Session Management](#d-session-management)
- [E. MFA Bypass](#e-mfa-bypass)
- [F. OAuth & Password Reset](#f-oauth--password-reset)

---

## A. Username Enumeration

### TC-B001 | Login Response Difference Username Enumeration

- **Severity**: MEDIUM
- **Prerequisites**: Login endpoint accessible, some usernames known
- **Test Steps**:
  1. Submit an existing username + wrong password, record error message
  2. Submit a non-existent username + wrong password, record error message
  3. Compare the two responses: error messages, status codes, response lengths, response times
  4. Use ffuf for batch enumeration (see payloads.md §1)
- **Expected Results**: Different usernames return different error messages or response times -> Valid usernames can be enumerated
- **Reference**: payloads.md §1 Response Difference Enumeration

### TC-B002 | Registration Page Username Existence Detection

- **Severity**: LOW
- **Prerequisites**: Registration endpoint accessible
- **Test Steps**:
  1. Submit registration with a known existing username, record response
  2. Submit registration with a random username, record response
  3. Compare the differences
- **Expected Results**: Existing username returns "Username already taken" -> Can be enumerated

---

## B. Brute Force & Credential Stuffing

### TC-B003 | Login Brute Force Protection Assessment

- **Severity**: HIGH
- **Prerequisites**: Login endpoint accessible, no CAPTCHA or can be bypassed
- **Test Steps**:
  1. Use Hydra to send 50 failed logins (see payloads.md §2)
  2. Check if Rate Limit exists (429 response)
  3. Check if account lockout is triggered
  4. Check if attempts can continue after lockout (whether lockout can be bypassed)
- **Expected Results**: No Rate Limit + No account lockout -> Unlimited brute force possible
- **Reference**: payloads.md §2 Brute Force

### TC-B004 | Default Credential Detection

- **Severity**: CRITICAL
- **Prerequisites**: Known admin panel URL
- **Test Steps**:
  1. Test common default username/password combinations: admin/admin, admin/password, root/root
  2. Test vendor-specific default credentials (check documentation or CVE database)
  3. Test first-installation default passwords
- **Expected Results**: Default credentials can log in -> CRITICAL vulnerability

---

## C. JWT Security

### TC-B005 | JWT alg:none Signature Bypass

- **Severity**: CRITICAL
- **Prerequisites**: API uses JWT authentication, valid Token obtained
- **Test Steps**:
  1. Decode JWT, record Payload
  2. Modify Header `alg` to `none`, clear signature
  3. Use tampered Token to request protected endpoint
  4. If failed, try `None`/`NONE`/`nOnE` variants
- **Expected Results**: Tampered Token is accepted (200) -> Signature verification completely failed
- **Reference**: payloads.md §3 alg:none Signature Bypass

### TC-B006 | JWT Key Brute Force

- **Severity**: HIGH
- **Prerequisites**: JWT uses HS256 algorithm
- **Test Steps**:
  1. Extract JWT Token
  2. Use Hashcat mode 16500 to brute force the key (see payloads.md §3)
  3. Use jwt_tool built-in dictionary to try common weak keys
  4. If key is found, construct valid Tokens with arbitrary Payloads
- **Expected Results**: Key is successfully brute forced -> Can forge arbitrary identity Tokens
- **Reference**: payloads.md §3 JWT Key Brute Force

### TC-B007 | JWT Payload Tampering

- **Severity**: CRITICAL
- **Prerequisites**: JWT key known (via brute force or leak)
- **Test Steps**:
  1. Decode original Token
  2. Tamper with `sub` / `role` / `is_admin` fields
  3. Re-sign with the key
  4. Use new Token to request protected endpoint
  5. Verify if permissions are escalated
- **Expected Results**: Tampered Token is valid and permissions are escalated -> JWT completely compromised
- **Reference**: payloads.md §3 Payload Tampering

### TC-B008 | JWT jku/x5u Header Injection

- **Severity**: HIGH
- **Prerequisites**: JWT Header contains `jku` or `x5u` fields
- **Test Steps**:
  1. Check if JWT Header contains `jku`/`x5u`
  2. Generate own RSA key pair and JWKS
  3. Replace `jku` with attacker-controlled JWKS URL
  4. Sign Token with own private key
- **Expected Results**: Server fetches public key from attacker URL and verification passes -> jku injection successful
- **Reference**: payloads.md §3 jku/x5u Header Injection

---

## D. Session Management

### TC-B009 | Session ID Predictability

- **Severity**: HIGH
- **Prerequisites**: Can repeatedly log in to obtain new Session IDs
- **Test Steps**:
  1. Log in 20 consecutive times, collect all Session IDs (see payloads.md §4)
  2. Analyze patterns: incremental, timestamp, base64 encoded, reversible
  3. Attempt to predict the next Session ID based on patterns
  4. Use predicted Session ID to attempt access
- **Expected Results**: Session ID is predictable or reversible -> Can hijack other user sessions
- **Reference**: payloads.md §4 Session ID Predictability Analysis

### TC-B010 | Session Fixation Attack

- **Severity**: HIGH
- **Prerequisites**: Session ID remains unchanged before and after login
- **Test Steps**:
  1. Visit login page, obtain Session ID (do not log in)
  2. Use that Session ID to complete login
  3. Check if Session ID changes after login
- **Expected Results**: Session ID does not change after login -> Session fixation vulnerability
- **Reference**: payloads.md §4 Session Fixation Attack

### TC-B011 | Missing Cookie Security Attributes

- **Severity**: MEDIUM
- **Prerequisites**: Application uses Cookies to store Session Tokens
- **Test Steps**:
  1. Log in and check Set-Cookie Header (see payloads.md §5)
  2. Verify `HttpOnly` attribute
  3. Verify `Secure` attribute
  4. Verify `SameSite` attribute
- **Expected Results**: Missing any attribute -> Corresponding attack surface increases (XSS theft/HTTP leakage/CSRF)

### TC-B012 | Concurrent Session Control

- **Severity**: MEDIUM
- **Prerequisites**: Can log in to the same account from multiple locations
- **Test Steps**:
  1. Log in from Session A
  2. Log in from Session B (same account)
  3. Check if Session A is still valid
- **Expected Results**: Session A remains valid -> No concurrent session control, cannot detect abnormal logins

---

## E. MFA Bypass

### TC-B013 | MFA Enforcement Verification

- **Severity**: CRITICAL
- **Prerequisites**: Application claims to use MFA protection
- **Test Steps**:
  1. Complete password verification step
  2. Without performing MFA verification, directly access protected pages
  3. Test all sensitive endpoints: /dashboard, /admin, /api/v1/users/me
  4. Check if server has `partial_auth` state validation
- **Expected Results**: Can still access after skipping MFA -> MFA not enforced
- **Reference**: payloads.md §6 Direct Access Bypass

### TC-B014 | TOTP Brute Force

- **Severity**: HIGH
- **Prerequisites**: MFA uses TOTP and has no rate limiting
- **Test Steps**:
  1. Reach MFA verification step
  2. Check if there is an attempt count limit
  3. If no limit, enumerate 6-digit codes within the 30-second window
- **Expected Results**: No rate limiting + enough attempts within 30 seconds -> TOTP can be brute forced
- **Reference**: payloads.md §6 TOTP Brute Force

---

## F. OAuth & Password Reset

### TC-B015 | OAuth Redirect URI Bypass

- **Severity**: HIGH
- **Prerequisites**: Application uses OAuth 2.0 authentication
- **Test Steps**:
  1. Find the OAuth callback endpoint
  2. Tamper `redirect_uri` to an external domain (see payloads.md §7)
  3. Test multiple bypass methods: subdomains, @ symbol, path traversal, URL encoding
  4. Check if authorization code is sent to attacker domain
- **Expected Results**: Authorization code is sent to external domain -> Can steal authorization code
- **Reference**: payloads.md §7 Redirect URI Validation Bypass

### TC-B016 | Password Reset Token Predictability

- **Severity**: HIGH
- **Prerequisites**: Password reset function available
- **Test Steps**:
  1. Request multiple password reset tokens (see payloads.md §8)
  2. Analyze Token patterns
  3. Attempt to predict other users' Tokens based on patterns
- **Expected Results**: Token is predictable -> Can reset any user's password

### TC-B017 | Password Reset Token Reuse

- **Severity**: HIGH
- **Prerequisites**: Password reset function available, have obtained a reset Token
- **Test Steps**:
  1. Request a reset Token
  2. Use the Token to successfully reset password
  3. Attempt to reset again using the same Token (see payloads.md §8)
- **Expected Results**: Used Token is still valid -> Token invalidation mechanism missing

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Username Enumeration | 2 | 0 | 0 | 1 | 1 |
| B. Brute Force & Credential Stuffing | 2 | 1 | 1 | 0 | 0 |
| C. JWT Security | 4 | 2 | 2 | 0 | 0 |
| D. Session Management | 4 | 0 | 2 | 2 | 0 |
| E. MFA Bypass | 2 | 1 | 1 | 0 | 0 |
| F. OAuth & Password Reset | 3 | 0 | 3 | 0 | 0 |
| **Total** | **17** | **4** | **9** | **3** | **1** |
