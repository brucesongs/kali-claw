# Browser QA Test Cases

## TC-BQ-001: Auth Flow Testing
**Objective**: Test login, session handling, logout

**Steps**:
1. Navigate to login page
2. Fill username and password
3. Submit form
4. Verify session cookie set with HttpOnly + Secure flags
5. Navigate to protected page
6. Logout
7. Verify session cookie deleted

**Pass Criteria**:
- [ ] Login succeeds with valid creds
- [ ] Session cookie has HttpOnly=true, Secure=true
- [ ] Logout clears session

## TC-BQ-002: CSRF Token Validation
**Objective**: Check CSRF protection on state-changing requests

**Steps**:
1. Navigate to form page
2. Extract CSRF token from hidden input
3. Submit form
4. Monitor POST request for CSRF token in body/header
5. Repeat without CSRF token (should fail)

**Pass Criteria**:
- [ ] CSRF token present in form
- [ ] Token sent with POST request
- [ ] Request without token is rejected

## TC-BQ-003: XSS via Form Input
**Objective**: Test XSS payloads via form submission

**Steps**:
1. Fill form with XSS payload: `<script>alert('XSS')</script>`
2. Submit form
3. Check if payload executed (alert fired or DOM contains unescaped payload)

**Pass Criteria**:
- [ ] Payload NOT executed (properly escaped/sanitized)
