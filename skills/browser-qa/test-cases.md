# Browser QA Test Cases

## TC-BQ-001: Auth Flow Testing
**Objective**: Test login, session handling, logout
**Severity**: HIGH

**Steps**:
1. Navigate to login page
2. Fill username and password
3. Submit form
4. Verify session cookie set with HttpOnly + Secure flags
5. Navigate to protected page
6. Logout
7. Verify session cookie deleted

**Expected Output**: Session lifecycle verified end-to-end

**Pass Criteria**:
- [ ] Login succeeds with valid creds
- [ ] Session cookie has HttpOnly=true, Secure=true
- [ ] Logout clears session

## TC-BQ-002: CSRF Token Validation
**Objective**: Check CSRF protection on state-changing requests
**Severity**: HIGH

**Steps**:
1. Navigate to form page
2. Extract CSRF token from hidden input
3. Submit form normally
4. Monitor POST request for CSRF token in body/header
5. Repeat without CSRF token (should fail)

**Expected Output**: CSRF protection confirmed present and enforced

**Pass Criteria**:
- [ ] CSRF token present in form
- [ ] Token sent with POST request
- [ ] Request without token is rejected

## TC-BQ-003: XSS via Form Input
**Objective**: Test XSS payloads via form submission
**Severity**: CRITICAL

**Steps**:
1. Fill form with XSS payload: `<script>alert('XSS')</script>`
2. Submit form
3. Check if payload executed (alert fired or DOM contains unescaped payload)
4. Test additional payloads: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`

**Expected Output**: All payloads properly sanitized

**Pass Criteria**:
- [ ] Payload NOT executed (properly escaped/sanitized)
- [ ] No unescaped user input in DOM

## TC-BQ-004: Cookie Security Audit
**Objective**: Verify all cookies have appropriate security flags
**Severity**: MEDIUM

**Steps**:
1. Navigate to target application
2. Authenticate if required
3. Enumerate all cookies via `page.context.cookies()`
4. Check each cookie for HttpOnly, Secure, SameSite attributes
5. Identify session cookies with missing flags

**Expected Output**: Cookie audit report with security flag status

**Pass Criteria**:
- [ ] All session cookies have HttpOnly flag
- [ ] All cookies have Secure flag on HTTPS sites
- [ ] SameSite attribute set (Lax or Strict)
- [ ] No excessive cookie lifetimes (> 1 year)

## TC-BQ-005: Network Request Interception
**Objective**: Intercept and analyze API calls for sensitive data leakage
**Severity**: HIGH

**Steps**:
1. Setup request interception with `page.on("request")`
2. Navigate through application workflow
3. Capture all API requests and responses
4. Analyze for sensitive data in URLs (tokens, passwords)
5. Check for unencrypted requests (HTTP instead of HTTPS)

**Expected Output**: Network traffic analysis report

**Pass Criteria**:
- [ ] No sensitive data in URL parameters
- [ ] All API calls use HTTPS
- [ ] No credentials sent in GET requests
- [ ] Authorization headers not leaked in redirects
