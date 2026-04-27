# API Security Test Cases

> This file is a companion to `SKILL.md`, providing structured API security test case templates.
> Purpose: Check each item during penetration testing to ensure no critical test points are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-XXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Authentication & Authorization](#a-authentication--authorization)
- [B. Input Validation](#b-input-validation)
- [C. Rate Limiting](#c-rate-limiting)
- [D. Data Exposure](#d-data-exposure)
- [E. GraphQL Specific](#e-graphql-specific)
- [F. Configuration & Information Disclosure](#f-configuration--information-disclosure)

---

## A. Authentication & Authorization

### TC-A001 | BOLA — Horizontal Privilege Escalation to Access Other Users' Resources

- **Severity**: CRITICAL
- **Prerequisites**: Have at least two different user tokens (User_A, User_B)
- **Test Steps**:
  1. Use User_A token to request `/api/v1/users/{User_A_ID}/profile`, record response
  2. Use User_A token to request `/api/v1/users/{User_B_ID}/profile`
  3. Replace with UUID-type ID and repeat test (if applicable)
  4. Batch replace IDs using ffuf automation (see payloads.md §2)
- **Expected Results**: Step 2 returns 200 with User_B data -> BOLA confirmed
- **Reference**: payloads.md §2 BOLA (IDOR) Testing

### TC-A002 | BPLA — Modifying Read-Only Attributes

- **Severity**: HIGH
- **Prerequisites**: Have a regular user token, known Profile update endpoint
- **Test Steps**:
  1. Normal PATCH `/api/v1/users/me`, body: `{"name":"Test"}`
  2. PATCH injection `{"name":"Test","role":"admin"}`
  3. PATCH injection `{"name":"Test","is_verified":true,"plan":"premium"}`
  4. PUT full replacement `{"name":"Test","email":"x@x.com","role":"admin"}`
- **Expected Results**: `role`/`is_verified`/`plan` values are successfully modified in the response -> BPLA confirmed
- **Reference**: payloads.md §3 Mass Assignment

### TC-A003 | Mass Assignment — Registration Endpoint Privilege Escalation

- **Severity**: CRITICAL
- **Prerequisites**: Registration endpoint available without invitation code
- **Test Steps**:
  1. Normal registration: `{"username":"test1","password":"P@ss","email":"t1@t.com"}`
  2. Inject role: `{"username":"test2","password":"P@ss","email":"t2@t.com","role":"admin"}`
  3. Inject permissions: `{"username":"test3","password":"P@ss","email":"t3@t.com","permissions":["*"]}`
  4. Log in with the newly registered account, check actual permissions
- **Expected Results**: Injected `role`/`permissions` take effect after login -> Mass Assignment confirmed
- **Reference**: payloads.md §3 Registration Endpoint Privilege Escalation

### TC-A004 | JWT alg:none Signature Bypass

- **Severity**: CRITICAL
- **Prerequisites**: API uses JWT authentication, have obtained a valid token
- **Test Steps**:
  1. Decode the original JWT, record Payload contents
  2. Modify Header: `{"alg":"none","typ":"JWT"}`
  3. Keep Payload unchanged, clear signature: `header.payload.`
  4. Use the tampered token to request a protected endpoint
  5. If failed, try `alg: "None"` / `"NONE"` / `"nOnE"` variants
- **Expected Results**: Tampered token is accepted by the server (200) -> Signature verification completely failed
- **Reference**: payloads.md §5 alg:none Signature Bypass
- **Related Skill**: `skills/web-auth-bypass/SKILL.md` JWT Attacks section

### TC-A005 | Unauthenticated Endpoint Access

- **Severity**: HIGH
- **Prerequisites**: Enumerated API endpoint list
- **Test Steps**:
  1. Request each endpoint without Authorization Header
  2. Record endpoints that return 200 instead of 401/403
  3. Test data modification operations (POST/PUT/DELETE) on these endpoints
- **Expected Results**: Sensitive endpoints (user management, configuration changes) return 200 -> Authentication missing

---

## B. Input Validation

### TC-B001 | Content-Type Abuse — XXE Injection

- **Severity**: HIGH
- **Prerequisites**: API accepts JSON input
- **Test Steps**:
  1. Record baseline response with normal JSON request
  2. Switch `Content-Type: application/xml`, send valid XML
  3. Send XXE payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>`
  4. Check if response contains `/etc/passwd` content
- **Expected Results**: Response contains file contents -> XXE confirmed
- **Reference**: payloads.md §7 Content-Type Abuse

### TC-B002 | Content-Type Bypass — Uploaded File Type Bypass

- **Severity**: MEDIUM
- **Prerequisites**: File upload endpoint available
- **Test Steps**:
  1. Upload a legitimate file (e.g., image.jpg), record response
  2. Upload `.php` file but set `Content-Type: image/jpeg`
  3. Upload `.jsp` file using double extension `shell.jpg.php`
  4. Upload `.html` file to test stored XSS
- **Expected Results**: Malicious file is accepted and accessible via URL -> Upload validation flaw
- **Reference**: payloads.md §7 Content-Type Parameter Pollution

---

## C. Rate Limiting

### TC-C001 | X-Forwarded-For Bypass

- **Severity**: MEDIUM
- **Prerequisites**: Rate Limit exists on login/sensitive endpoint (multiple errors return 429)
- **Test Steps**:
  1. Send 10 failed logins without extra headers, confirm 429 is triggered
  2. Add `X-Forwarded-For: 10.0.0.{N}` (incrementing N each time), send 50 failed logins
  3. Check if 429 is still returned
  4. Try `X-Real-IP` / `X-Originating-IP` / `X-Client-IP` alternatives
- **Expected Results**: Changing headers no longer triggers 429 -> Rate Limit is based on IP Header rather than real IP
- **Reference**: payloads.md §4 X-Forwarded-For IP Spoofing

### TC-C002 | Concurrent Request Sliding Window Bypass

- **Severity**: MEDIUM
- **Prerequisites**: Rate Limit uses sliding window algorithm
- **Test Steps**:
  1. Confirm Rate Limit threshold (e.g., 10 requests/minute)
  2. Use concurrent tools (Turbo Intruder / custom script) to send 50 requests simultaneously
  3. Record the number of successful responses
- **Expected Results**: Requests exceeding the threshold in the concurrent batch still return 200 -> Race condition bypass
- **Reference**: payloads.md §4 Rate Limit Bypass

### TC-C003 | API Version Downgrade Bypass

- **Severity**: MEDIUM
- **Prerequisites**: API has multiple versions (v1, v2)
- **Test Steps**:
  1. Trigger Rate Limit on `/api/v2/endpoint`, record threshold
  2. Send the same number of requests to `/api/v1/endpoint`
  3. Check if v1 has the same limits
- **Expected Results**: v1 has no Rate Limit or a higher threshold -> Inconsistent security policies across versions

---

## D. Data Exposure

### TC-D001 | Excessive Data Exposure in API Response

- **Severity**: HIGH
- **Prerequisites**: Authenticated API endpoint returns user/object data
- **Test Steps**:
  1. Request `/api/v1/users/me`, check response fields
  2. Check if it contains: `password_hash` / `internal_id` / `ssn` / `credit_card` / `api_key`
  3. Request `/api/v1/users/{id}` (after BOLA test passes), check if other user data contains sensitive fields
  4. Check if list endpoint `/api/v1/users` returns complete records
- **Expected Results**: Response contains sensitive fields that should not be returned -> Excessive data exposure
- **Related**: Often combined with TC-A001 BOLA to amplify impact

### TC-D002 | Error Information Disclosure

- **Severity**: MEDIUM
- **Prerequisites**: API endpoint accessible
- **Test Steps**:
  1. Send malformed JSON body
  2. Send invalid type parameter (string instead of integer)
  3. Send overly long string (10000+ characters)
  4. Send invalid ID (`abc` instead of number)
  5. Check if error response contains stack traces, SQL statements, internal paths
- **Expected Results**: Error response contains `Traceback` / `SQL` / `/var/www/` etc. internal information -> Information disclosure
- **Reference**: payloads.md §8 Error Information Disclosure

### TC-D003 | Pagination Parameter Abuse

- **Severity**: MEDIUM
- **Prerequisites**: List endpoint supports pagination parameters
- **Test Steps**:
  1. Request `/api/v1/users?page=1&limit=10`, record response
  2. Modify `limit=10000`, check if accepted
  3. Modify `limit=-1` or `limit=0`, check for abnormal behavior
  4. Remove pagination parameters, check if all data is returned by default
- **Expected Results**: `limit=10000` is accepted and returns large amounts of data -> Missing pagination upper limit validation

---

## E. GraphQL Specific

### TC-E001 | Introspection Schema Disclosure

- **Severity**: MEDIUM
- **Prerequisites**: GraphQL endpoint accessible
- **Test Steps**:
  1. Send Introspection Query (see payloads.md §6)
  2. Check if complete Schema is returned (all Types / Queries / Mutations / Subscriptions)
  3. Extract all Query and Mutation names from the Schema
  4. Check if Introspection should be disabled in production
- **Expected Results**: Production environment returns complete Schema -> Information disclosure
- **Reference**: payloads.md §6 Introspection Query

### TC-E002 | Deeply Nested Query DoS

- **Severity**: HIGH
- **Prerequisites**: GraphQL endpoint accessible, Schema known (via Introspection)
- **Test Steps**:
  1. Construct 5-level nested query, record response time
  2. Construct 10-level nested query, record response time
  3. Construct 15+ level nested query, check for timeout or server error
- **Expected Results**: Response time grows exponentially with depth, no depth limit on server -> DoS risk
- **Reference**: payloads.md §6 Deeply Nested DoS

### TC-E003 | Batch Query Rate Limit Bypass

- **Severity**: MEDIUM
- **Prerequisites**: GraphQL Rate Limit is calculated by request count
- **Test Steps**:
  1. Send a single query, confirm normal response
  2. Send Batch Array (100 queries in a single request)
  3. Check if all are executed and return results
- **Expected Results**: All queries in the batch request are executed -> Rate Limit is based on request count, not operation count
- **Reference**: payloads.md §6 Batch Query Brute Force Enumeration

### TC-E004 | Unauthorized Mutation Execution

- **Severity**: CRITICAL
- **Prerequisites**: Schema contains sensitive Mutations (e.g., updateUser, deleteAccount)
- **Test Steps**:
  1. Send Mutation request without authentication
  2. Send admin-level Mutation using regular user token
  3. Test `updateUser(id: OTHER_ID, role:"admin")` type Mutation
- **Expected Results**: Unauthorized/low-privilege user can execute sensitive Mutations -> Authorization flaw
- **Reference**: payloads.md §6 Unauthorized Mutation Testing

---

## F. Configuration & Information Disclosure

### TC-F001 | Unauthorized API Documentation Access

- **Severity**: MEDIUM
- **Prerequisites**: API documentation path unknown
- **Test Steps**:
  1. Probe Swagger/OpenAPI documentation paths (see payloads.md §1)
  2. Check if authentication is required
  3. Extract all endpoints, parameters, and authentication methods from documentation
  4. Check if documentation contains internal/test environment endpoints
- **Expected Results**: Documentation is accessible without authentication -> Information disclosure, lowering the attack barrier
- **Reference**: payloads.md §1 Swagger/OpenAPI Documentation Disclosure

### TC-F002 | Hardcoded API Key Disclosure

- **Severity**: CRITICAL
- **Prerequisites**: Target has frontend JavaScript files
- **Test Steps**:
  1. Download all JS files
  2. Search for API Key patterns (see payloads.md §8 JavaScript File Search)
  3. Verify if found Keys are valid (test by calling the API directly)
  4. Check Key permission scope
- **Expected Results**: Frontend JS contains valid API Keys -> Credential disclosure
- **Reference**: payloads.md §8 API Key Disclosure Detection

### TC-F003 | CORS Misconfiguration

- **Severity**: MEDIUM
- **Prerequisites**: API endpoint accessible
- **Test Steps**:
  1. Send `Origin: https://evil.com` Header
  2. Check if response `Access-Control-Allow-Origin` is `*` or reflects the Origin
  3. Check `Access-Control-Allow-Credentials: true`
  4. If both `ACAO: *` and `ACAC: true` exist, check if they can be exploited together
- **Expected Results**: `ACAO` reflects any Origin and `ACAC: true` -> CORS misconfiguration, can steal authenticated user data

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Authentication & Authorization | 5 | 3 | 2 | 0 | 0 |
| B. Input Validation | 2 | 0 | 1 | 1 | 0 |
| C. Rate Limiting | 3 | 0 | 0 | 3 | 0 |
| D. Data Exposure | 3 | 0 | 1 | 2 | 0 |
| E. GraphQL Specific | 4 | 1 | 1 | 2 | 0 |
| F. Configuration & Information Disclosure | 3 | 1 | 0 | 2 | 0 |
| **Total** | **20** | **5** | **5** | **10** | **0** |
