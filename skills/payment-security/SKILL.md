---
name: payment-security
description: "Payment systems security — PCI-DSS compliance testing, payment API security (Stripe/Adyen/PayPal), EMV chip/PIN, 3-D Secure, mobile wallets (Apple Pay/Google Pay), and fraud system assessment."
origin: openclaw
version: "0.1.28"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: financial
  tool_count: 12
  guide_count: 1
  mitre: "T1566-Phishing (credential harvesting) + domain-specific"
---




# Skill: Payment Systems Security

> **Supplementary Files**:
> - `payloads.md` — PCI-DSS 4.0 requirement map, Stripe/Adyen/PayPal API test patterns, 3-D Secure 2.x challenge flow probing, card testing / BIN attack detection, recurring billing manipulation, mobile wallet Frida hooks (Apple Pay / Google Pay), EMV L2/L3 review, fraud system (Sift / Forter) feature probing, Python pipeline for Stripe CLI / webhook replay / card-test bot detection
> - `test-cases.md` — Structured test cases (PCI scope validation, ASV scan, Stripe webhook signature, 3DS challenge bypass, Apple Pay token interception, Google Pay SDK, Frida runtime hook, Sift feature probe, card test pattern detection, EMV replay, contactless relay, terminal config review) with severity and summary tables

## Summary

Payment Systems Security skill domain covering financial operations.

**Tools**: Stripe CLI, Burp Suite (payment extensions), OWASP ZAP, mitmproxy, Postman, Frida, objection, MobSF, Nessus/Qualys (ASV), PCI-DSS Quick Reference, EMVCo test cards (+3 more)

**Domain**: financial

**MITRE ATT&CK**: T1566-Phishing (credential harvesting) + domain-specific

## Description

Payment systems security covers the full cardholder-data lifecycle and the regulated ecosystem around it: PCI-DSS 4.0 compliance scoping and gap assessment, payment gateway API security (Stripe, Adyen, PayPal, Braintree), 3-D Secure 2.x authentication flows, mobile wallet tokenization (Apple Pay, Google Pay, Samsung Pay), EMV chip & contactless terminal review, recurring billing and subscription abuse, refund/chargeback fraud, and behavioral fraud-system assessment (Sift Science, Forter, Riskified, custom ML).

This is **not** generic API security. The distinction matters because payment systems sit inside a regulated perimeter (PCI-DSS 4.0, PSD2 in the EU, Reg E in the US, card-scheme operating regulations from Visa/Mastercard/Amex), touch a defined Cardholder Data Environment (CDE), and depend on cryptographic primitives (EMV cryptograms, 3-D Secure SDKs, network tokenization, device account numbers) that have no equivalent in a vanilla REST API. A single misconfiguration in scope delineation can pull an entire datacenter into PCI scope; a single leaked webhook signing secret can let an attacker mint successful payment confirmations; a single bypassed 3DS challenge shifts fraud liability back onto the merchant.

**Difference from `api-security`**: API security covers generic REST/GraphQL concerns (BOLA, broken auth, mass assignment). Payment-security applies those same concerns to a specific regulated domain — cardholder data minimization, PCI-DSS requirement traceability, processor sandbox-vs-production rules, 3DS challenge mechanics, and EMV cryptogram validation. The toolset adds Stripe CLI, Adyen test cards, EMVCo reference cards, and fraud-system test modes.

**Difference from `web-auth-bypass`**: Auth bypass targets session and access control logic (JWT, OAuth, cookie tampering). Payment security uses those techniques to probe payment-specific authorization: idempotency-key reuse on PaymentIntents, webhook replay with stale signatures, 3DS frictionless-vs-challenge routing, and refund authorization on already-captured charges.

**Difference from `mobile-security`**: Mobile security covers app-level concerns (certificate pinning, rooted/jailbroken detection, local data). Payment security targets the wallet integration layer inside the app: `PKPaymentAuthorizationViewController` delegate hooks on iOS, Google Pay `PaymentsClient` tokenization, device account number (DAN) interception, and the cryptographic handoff to the payment gateway.

## Use Cases

- **PCI-DSS 4.0 gap assessment**: Map the client's cardholder data environment, validate scope delineation (segmentation, tokenization), and produce a requirement-by-requirement gap report against the 12 PCI-DSS 4.0 requirement families.
- **Payment gateway API pentest**: Stripe / Adyen / PayPal / Braintree — test webhook signature validation, idempotency keys, PaymentIntent lifecycle manipulation, and customer object data leakage in test mode (and, with explicit authorization, in production).
- **3-D Secure 2.x bypass testing**: Probe the frictionless-vs-challenge routing, SDK fingerprinting, and authentication-value (CAVV/ECI) handling to find flows where strong customer authentication can be skipped in violation of PSD2 SCA requirements.
- **Fraud system assessment**: Test Sift Science / Forter / Riskified in their sandbox/test modes to understand feature-set inferences, decision thresholds, and what behavioral signals an attacker can probe without tripping the model.
- **Mobile wallet integration review**: Apple Pay (PassKit / `PKPaymentAuthorizationViewController`) and Google Pay (`PaymentsClient` / `TokenizationSpecification`) — review device account number handling, dynamic cryptogram validation, and the in-app token lifecycle.
- **EMV chip & contactless terminal review**: Terminal L2/L3 kernel configuration, contactless (CL-T / paywave / PayPass) relay-attack resistance, and on-device cryptogram validation.
- **Recurring billing & subscription abuse**: Plan-swap attacks, proration abuse, cancel/resume state-machine bugs, trial-period farming via card rotation, and metered-billing backdating.
- **Marketplace / split-payment review**: Stripe Connect, Adyen Marketplace, PayPal for Marketplaces — review platform-fee handling, connected-account authorization scope, and funds-release (escrow) logic.

## Core Tools

### Interception & Proxying

| Capability | Command Example |
|------------|-----------------|
| Capture Stripe / Adyen / PayPal API traffic | Configure Burp upstream proxy, install Burp CA on test device |
| Inspect mobile wallet (Apple Pay / Google Pay) traffic | `mitmproxy --mode transparent --showhost` + SSL pinning bypass via Frida |
| Replay payment webhook with modified payload | Burp Repeater on `/webhooks/stripe` endpoint |
| Match-and-replace PAN in transit | Burp match/replace rule to detect raw card data leakage |

### API Testing — Processors

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Stripe CLI** | Local webhook forwarding, event triggering, signature verification | `stripe listen --forward-to localhost:8000/webhooks` |
| **stripe trigger** | Generate synthetic events (payment_intent.succeeded, etc.) | `stripe trigger payment_intent.succeeded` |
| **Postman** | Stripe / Adyen / PayPal API collections | Import `Stripe API.postman_collection.json` |
| **Bruno** | Git-backed API client for team-shared payment collections | `bruno run stripe-tests/` |
| **Adyen test cards** | Deterministic test PANs that route to specific decline codes | Use `4111 1111 4555 4522` for "Refused" in Adyen test mode |
| **PayPal Sandbox** | Buyer/seller sandbox accounts with mock balances | `https://api-m.sandbox.paypal.com` |

### Compliance & Scanning

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **PCI-DSS Quick Reference** | 12-requirement summary for scope mapping | Reference card, not a tool — `https://www.pcisecuritystandards.org` |
| **Nessus (ASV mode)** | External PCI-DSS vulnerability scan (ASV-certified) | `nessuscli scan PCI-DSS-External --target <scope>` |
| **Qualys Web Application Scanning** | ASV-approved external scan + internal CDE scan | `qualys was launch --pci-template` |
| **PCI SAQ templates** | Self-Assessment Questionnaire (A, B, C, D, P2PE, etc.) | Match SAQ to merchant flow (eCom → SAQ A or A-EP) |
| **OpenSCAP** | Internal host config baseline against PCI hardening refs | `oscap xccdf eval --profile pci-dss ssg-rhel9-ds.xml` |

### Mobile Wallets

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Frida** | Runtime instrumentation of Apple Pay / Google Pay app code | `frida -U -f com.app -l applepay_hook.js` |
| **objection** | SSL pinning bypass, keychain dump, runtime exploration | `objection -g com.app explore` |
| **MobSF** | Static + dynamic mobile app analysis (PassKit usage, etc.) | `mobsfscan ios/` or `docker run -p 8000:8000 opensecurity/mobsf` |
| **jailbreak / root detection testing** | Confirm wallet app refuses to run on compromised devices | Use `Shadow (iOS)` / `Magisk Hide (Android)` to verify detection |
| **Apple Pay crypto inspector** | Hook `PKPaymentAuthorizationViewController` to inspect token packet | See `payloads.md` Section 9 |
| **Google Pay token inspector** | Hook `loadPaymentData` / `PaymentsClient` | See `payloads.md` Section 9 |

### Card Testing & BIN Attack Patterns

| Capability | Command Example |
|------|---------|-----------------|
| Detect card-test bot velocity | `grep -c 'POST /v1/payment_intents' access.log \| sort` over time windows |
| BIN-range enumeration detection | Cluster declined `/v1/charges` by BIN prefix; flag > 50 declines per BIN/hour |
| CAPTCHA / rate-limit test | `for i in $(seq 1 100); do curl -X POST .../checkout; done` (with authorization) |
| Test-mode card cyclcing | Use Stripe's deterministic test cards (`4000 0027 6000 3184` → "insufficient funds") |

### EMV

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **EMVCo test card set** | Reference contact + contactless cards for L2/L3 certification | Physical cards (Visa VTS, Mastercard MCHIP, Amex, JSmart) |
| **Terminal emulator** | Replay EMV cryptograms against terminal-under-test | Custom / vendor-specific (e.g., ICC Solutions E3) |
| **Smart card reader (ACR122, etc.)** | Read EMV tags (9F26 AC, 9F10 IAD, 9F36 ATC) | `pcsc-tools`, `scriptor` |
| **ISO 14443 analyzer** | Inspect contactless frames (Type A/B, FeliCa) | Proxmark3 / custom SDR |

### Fraud Systems (Test Mode Only)

| Tool / Vendor | Test Capability | Notes |
|---------------|-----------------|-------|
| **Sift Science** | Sandbox score API; send synthetic events | `https://api.sift.com/v205/events` with test API key |
| **Forter** | Sandbox mode; mock transaction payloads | Test tenant per account |
| **Riskified** | Test-mode review of order decisions | Returns approved/declined/manual-review |
| **Custom ML model** | Feature-set inference via decision-boundary probing | See `payloads.md` Section 11 |

## Methodology

### Payment Pentest Six-Phase Process

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5            Phase 6
Scope & PCI        Compliance         API & Flow         Mobile Wallet      Fraud System       Report
Delineation    →   Check          →   Testing        →   Review         →   Assessment     →   & SAQ Mapping
   │                  │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼                  ▼
Identify CDE,      Map 12 reqs,       Stripe/Adyen       Frida hooks on     Sift/Forter test   PCI gap report,
tokenization,      ASV scans,          API, webhooks,     PassKit /          mode, feature      API findings,
segmentation       SAQ selection       3DS, idempotency   PaymentsClient     probing            wallet findings,
                                                                                               fraud recs
```

**Phase 1: Scope & PCI Delineation**

Before any active testing, define what is and is not in the Cardholder Data Environment.

```
CDE In-Scope:                Out-of-Scope (if properly segmented):
- Cardholder data stores      - Merchandising CMS
- Payment gateway integration - Marketing analytics
- 3DS / MPI servers           - Internal HR systems
- Terminal management system  - Public marketing site
- Tokenization vault          - Post-tokenization order mgmt (sometimes)
```

**Phase 2: Compliance Check**

Map the client's controls to PCI-DSS 4.0's 12 requirement families and run ASV-approved external scans.

```bash
# External ASV scan (PCI-DSS mandated quarterly)
nessuscli scan PCI-DSS-External --target payments.example.com,api.example.com --policy "PCI Quarterly External"

# Internal CDE scan (PCI-DSS req 11.3)
qualys scan launch --title "PCI Internal CDE" --option "PCI-DSS-Internal"

# OpenSCAP host hardening baseline (req 2.2)
oscap xccdf eval --profile pci-dss --results scan.xml /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

**Phase 3: API & Flow Testing**

With processor sandbox credentials, exercise the full payment lifecycle.

```bash
# Stripe CLI — forward webhooks to local dev server
stripe listen --forward-to localhost:8000/webhooks --events payment_intent.succeeded,charge.failed

# In another terminal, trigger synthetic events
stripe trigger payment_intent.succeeded
stripe trigger charge.failed
stripe trigger invoice.payment_failed

# Replay attack — capture a webhook, modify amount, replay
# (legitimate Stripe sigs include a timestamp; verify the server rejects stale)
```

**Phase 4: Mobile Wallet Review**

Instrument the iOS / Android wallet integration.

```bash
# iOS Frida hook on Apple Pay authorization
frida -U -f com.example.app -l applepay_hook.js --no-pause

# Android Frida hook on Google Pay
frida -U -f com.example.app -l googlepay_hook.js --no-pause

# Inspect device account number (DAN) vs real PAN
# Should NEVER see raw PAN in the app — DAN is tokenized on-device by the wallet OS
```

**Phase 5: Fraud System Assessment**

Probe fraud systems in their test mode to understand decision boundaries — never trip a real fraud alert in production.

```bash
# Sift sandbox — send synthetic events
curl -X POST 'https://api.sift.com/v205/events' \
  -H "Content-Type: application/json" \
  -d "{
    \"\$api_key\": \"$SIFT_SANDBOX_KEY\",
    \"\$user_id\": \"test_user_001\",
    \"\$type\": \"\$create_order\",
    \"\$order_id\": \"order_test_001\",
    \"\$amount\": 5000000
  }"
```

**Phase 6: Report & SAQ Mapping**

Produce a PCI-DSS-aligned report that maps every finding to a specific requirement number.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| New client PCI scoping | Walk through 12 reqs + segmentation test | Hire QSA for formal ROC |
| Stripe webhook security | `stripe listen` + replay attacks | Burp on `/webhooks/stripe` |
| 3DS challenge bypass | Replay SCA-exempt transactions | Test frictionless routing logic |
| Apple Pay token interception | Frida hook `PKPaymentAuthorizationViewController` | Static analysis via MobSF |
| Card test bot detection | Cluster declines by BIN + velocity | Custom Sigma rule on access logs |
| Recurring billing abuse | Probe plan-swap + proration endpoints | Manually walk state machine |
| Fraud system probing | Sandbox-mode feature inference | (no production equivalent) |
| EMV terminal review | L2/L3 kernel config + contactless relay test | Use EMVCo test cards |
| Refund/chargeback fraud | Replay refund webhook with modified amount | Burp Repeater |
| Hand to executive | Map findings to PCI-DSS req numbers | SAQ-A / A-EP letter |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Tokenization everywhere** | Replace PAN with gateway tokens (Stripe customer objects, Adyen recurring detail, network tokens). The less PAN you store, the smaller your CDE. |
| **Network segmentation** | Isolate the CDE so systems that don't touch PAN are demonstrably out of scope (PCI-DSS req 1.2 / 1.3 / 12.5.5 in 4.0). |
| **Webhook signature verification** | Always verify `Stripe-Signature` (and equivalents) on every webhook; reject stale timestamps (> 5 min). |
| **Idempotency enforcement** | Use `Idempotency-Key` on every state-changing Stripe/Adyen call; server must dedupe by key. |
| **3DS 2.x SCA enforcement** | Apply Strong Customer Authentication per PSD2 rules; do not force frictionless flow to optimize conversion. |
| **Card testing defenses** | Velocity limits per BIN per hour, CAPTCHA after 3 declines, AVS/CVV enforcement, block datacenter IPs on checkout. |
| **EMV over magstripe** | Never fall back to magstripe on chip cards; terminal must enforce chip priority. |
| **Behavioral fraud detection** | Layer Sift/Forter/Riskified on top of rules; tune thresholds in test mode first. |
| **PCI-DSS 4.0 controls** | Apply the 12 requirements explicitly — don't assume compliance, audit for it. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: PCI-DSS Scope Mapping

Goal: identify what is and is not in scope, so the client knows what must meet PCI requirements.

```bash
# Inventory: which systems store, process, or transmit PAN?
# Walk through each component and answer:
#   - Does it store PAN? (database, log, backup)
#   - Does it process PAN? (payment gateway, fraud service)
#   - Does it transmit PAN? (TLS channel to gateway)

# Output: a CDE boundary map like:
#
#   Customer browser ─ TLS ─> Checkout API ─> Stripe ─> Card network
#                                  │
#                                  └──> Order DB (tokenized card_id, NOT PAN)
#
#   In-scope: Checkout API, Stripe integration, any system that can see PAN pre-tokenization
#   Out-of-scope (if segmented): Order DB (stores token), fulfillment, CRM

# Verify segmentation (PCI req 1.2/1.3):
nmap -p1-65535 -sV --reason <out-of-scope-system> --script=firewalk --traceroute
# If a path exists from out-of-scope to CDE without a firewall/ACL, segmentation is broken
```

### Exercise 2: Stripe CLI Webhook Testing

Goal: verify the client's webhook handler validates signatures and rejects replays.

```bash
# Install Stripe CLI
# https://stripe.com/docs/stripe-cli
stripe login

# Forward webhooks to local dev server
stripe listen --forward-to localhost:8000/webhooks \
  --events payment_intent.succeeded,charge.failed,invoice.payment_succeeded

# In another terminal, trigger synthetic events
stripe trigger payment_intent.succeeded
stripe trigger charge.failed
stripe trigger invoice.payment_succeeded

# Capture the raw webhook payload + signature, then replay with modified amount
# (See payloads.md Section 2 for the full replay attack)
```

### Exercise 3: 3DS Challenge Bypass Testing

Goal: find flows where Strong Customer Authentication can be skipped.

```bash
# Test the 3DS routing logic on the checkout API
curl -X POST https://api.example.com/checkout/3ds-route \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 2900,
    "currency": "usd",
    "card": "4000 0027 6000 3184",
    "merchant_category": "low_value"
  }'

# Variations to test:
# 1. Amount just under low-value exemption threshold (PSD2: €30, €100 cumulative)
# 2. Trusted beneficiary list manipulation
# 3. Corporate card (B2B) exemption abuse
# 4. Recurring transaction exemption on first payment
```

### Exercise 4: Mobile Wallet Frida Hooking

Goal: confirm the app never sees raw PAN — only the tokenized DAN.

```javascript
// applepay_hook.js — hook the Apple Pay authorization delegate
Interceptor.attach(ObjC.classes.PKPaymentAuthorizationViewController['- paymentAuthorizationViewController:didAuthorizePayment:completion:'].implementation, {
  onEnter: function(args) {
    const payment = new ObjC.Object(args[3]);
    const token = payment.token();
    const paymentData = token.paymentData();
    console.log("[+] Apple Pay token intercepted:");
    console.log("    DAN (device account number):", token.transactionIdentifier().toString());
    console.log("    paymentData:", paymentData.toString());
    // paymentData contains: applicationPrimaryAccountNumber (DAN, NOT real PAN),
    //                       applicationCryptogram, paymentDataType, etc.
  }
});
```

### Exercise 5: Card Testing Pattern Detection

Goal: detect (or simulate) a card-testing bot sweeping BIN ranges.

```bash
# Simulate card test (with authorization, in sandbox only)
for i in $(seq 1 20); do
  pan="4111 1111 $(printf '%04d' $i) $(printf '%04d' $((i*7%10000)))"
  curl -X POST https://api.example.com/checkout \
    -H "Content-Type: application/json" \
    -d "{\"card\": \"$pan\", \"amount\": 100, \"currency\": \"usd\"}"
done

# Detection (defense side):
# Aggregate checkout requests by BIN prefix per hour
awk '/POST \/checkout/ {print $1, $5}' /var/log/nginx/access.log \
  | grep -oE '[0-9]{4} [0-9]{4}' \
  | sort | uniq -c | sort -rn | head -20

# Alert threshold: > 50 declines per BIN per hour = card testing in progress
```

### Exercise 6: Recurring Billing Manipulation

Goal: find subscription state-machine bugs that grant free service or unwanted upgrades.

```bash
# Probe plan-swap endpoints for proration bugs
curl -X POST https://api.example.com/subscriptions/sub_123/swap \
  -H "Content-Type: application/json" \
  -d '{"new_plan": "enterprise_annual", "prorate": false}'

# Probe trial-period farming
# Cancel trial, immediately re-subscribe — should NOT grant a new trial
curl -X POST https://api.example.com/subscriptions/sub_123/cancel
curl -X POST https://api.example.com/subscriptions \
  -d '{"plan": "pro_monthly", "trial_days": 14}'  # should be rejected

# Probe pause/resume state for backdated billing
curl -X POST https://api.example.com/subscriptions/sub_123/pause \
  -d '{"until": "2020-01-01"}'  # backdated pause = refund abuse
```

### Exercise 7: Fraud System Testing

Goal: probe Sift / Forter sandbox to understand feature inference without tripping production.

```bash
# Sift sandbox — send events with escalating risk signals
# (NEVER test against production fraud systems without explicit authorization)

# Legitimate-looking order
curl -X POST https://api.sift.com/v205/events \
  -H "Content-Type: application/json" \
  -d "{
    \"\$api_key\": \"$SIFT_SANDBOX_KEY\",
    \"\$user_id\": \"u_normal\",
    \"\$type\": \"\$create_order\",
    \"\$amount\": 4999
  }"

# Same user, suddenly high-risk signals
curl -X POST https://api.sift.com/v205/events \
  -d "{
    \"\$api_key\": \"$SIFT_SANDBOX_KEY\",
    \"\$user_id\": \"u_normal\",
    \"\$type\": \"\$create_order\",
    \"\$amount\": 50000000,
    \"\$ip\": \"185.220.101.5\",
    \"\$billing_address\": {\"\$country\": \"RU\"}
  }"
```

### Exercise 8: EMV L2/L3 Terminal Review

Goal: review terminal configuration for cryptogram validation and contactless relay resistance.

```bash
# Read EMV tags from a card via PC/SC reader
scriptor <<EOF
00A4040007A000000004101000
80A8000002830000
EOF

# Key tags to inspect:
# 9F26 (AC, Application Cryptogram) — must be verified by terminal/issuer
# 9F10 (IAD, Issuer Application Data) — contains CVR, CID
# 9F36 (ATC, Application Transaction Counter) — must be monotonically increasing
# 95 (TVR, Terminal Verification Results) — records what checks failed

# L2 kernel config review (vendor-specific):
# - Is CDA (Combined DDA/Application Cryptogram Generation) enabled?
# - Are online PIN and signature fallbacks configured per card scheme rules?
# - Is contactless CL-T limit enforced per region (e.g., €50 in EU)?
```

### Exercise 9: PCI-DSS Audit Report Assembly

Goal: produce a deliverable that maps every finding to a PCI requirement.

```markdown
# PCI-DSS 4.0 Gap Assessment — Example Corp

## Finding 1: Webhook signature not verified
- PCI-DSS 4.0 req: 6.5.1 (web application security), 10.2 (audit logging)
- Severity: HIGH
- Risk: Attacker can forge payment success notifications
- Remediation: Verify Stripe-Signature on /webhooks/stripe with 5-min tolerance
```

## Safety Notes

- **Authorization is non-negotiable**: Never test production payment systems without a signed Statement of Work that explicitly names the cardholder data environment, the processor accounts, and the test window. PCI-DSS violations carry fines (per-incident, monthly, or card-scheme-level termination) and many jurisdictions criminalize unauthorized access to financial systems.
- **Use sandbox credentials**: Stripe (test mode `sk_test_...`), Adyen (test merchant account), PayPal (sandbox at `api-m.sandbox.paypal.com`) all offer full-featured test environments. Use them for everything except final authorized production validation.
- **PCI scope delineation**: Stay inside the agreed scope. Probing systems the client has declared out-of-scope (e.g., a marketing CMS) without re-confirmation can pull them into scope and trigger remediation costs.
- **Cardholder data minimization**: Never log full PAN, CVV, or track data in your test artifacts. Use masked test cards (`4111 1111 XXXX 1111`) and redact PAN in Burp logs (configure match-and-replace). PCI-DSS req 3.4 mandates PAN masking.
- **Fraud system test mode only**: NEVER send synthetic events to a production fraud system (Sift/Forter/Riskified) without explicit authorization — a single high-risk event can flag your IP, taint the merchant's risk profile, or trigger card-scheme monitoring.
- **EMV terminal testing**: Use only EMVCo reference cards or client-provided test cards on the terminal-under-test. Live cards on a non-certified terminal can void the merchant's certification.
- **Legal/regulatory liability**: PSD2 (EU), Reg E (US), card-scheme operating regulations, and local financial-services laws all apply. When in doubt, ask the client's legal counsel — not your pentest lead.
- **Non-disclosure**: Payment system details (processor account IDs, signing secrets, merchant IDs) are NDA-protected. Encrypt at rest, shred on engagement close.

## Hacker Laws

- **Trust but Verify** — Payment webhooks are unauthenticated until proven otherwise. Verify the signature, the timestamp tolerance, and the idempotency. Stripe's `Stripe-Signature` header includes `t=` (timestamp) and `v1=` (signature); missing timestamp checks open replay windows measured in hours.
- **Defense in Depth** — A payment system that relies on a single control (e.g., "the gateway rejects bad cards") will fail when that control is bypassed. Layer gateway-side checks with your own server-side amount/quantity validation, fraud-system scoring, and human review for high-value outliers.
- **Least Privilege — Cardholder Data Minimization** — Every system that can see PAN is in PCI scope. The strongest payment design is one where PAN never touches your servers — Stripe Elements / Adyen Drop-in / PayPal Smart Buttons tokenize client-side and your backend only ever sees a token. This is PCI-DSS req 3 (protect stored cardholder data) applied as architecture.
- **Assume Breach** — When (not if) an attacker gets into your network, what can they do with payment data? Tokenization limits blast radius. Network segmentation prevents lateral movement into the CDE. Encrypted-at-rest PAN (with HSM-backed key management) prevents mass exfiltration. Audit logging (req 10) gives you the trail to reconstruct what happened.
- **Information Wants to Be Free** — Cardholder data, like all data, leaks. The question is whether it leaks as raw PAN (catastrophic) or as an opaque token (acceptable). Tokenization is the architectural answer to this law.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/payment-pentest-playbook.md` — end-to-end payment pentest from scoping through PCI delineation, API testing, mobile wallet review, fraud system probing, EMV terminal review, and report assembly
- **Related skills**:
  - `skills/api-security/SKILL.md` — generic REST/GraphQL API testing (payment APIs are a subset)
  - `skills/web-auth-bypass/SKILL.md` — auth flow testing (3DS, idempotency, webhook auth build on this)
  - `skills/mobile-security/SKILL.md` — mobile app analysis (PassKit, PaymentsClient, Frida hooks)
  - `skills/crypto-attacks/SKILL.md` — cryptographic primitives (EMV cryptograms, 3DS CAVV/ECI, tokenization crypto)
  - `skills/pentest-reporting/SKILL.md` — report assembly and SAQ mapping
  - `skills/engagement-manager/SKILL.md` — scoping and authorization for regulated engagements
- **External resources**:
  - PCI Security Standards Council: [pcisecuritystandards.org](https://www.pcisecuritystandards.org)
  - PCI-DSS 4.0 Quick Reference: [PCISSC document library](https://www.pcisecuritystandards.org/document_library)
  - Stripe docs (security section): [stripe.com/docs/security](https://stripe.com/docs/security)
  - Stripe CLI: [stripe.com/docs/stripe-cli](https://stripe.com/docs/stripe-cli)
  - Adyen docs: [docs.adyen.com](https://docs.adyen.com)
  - PayPal Developer: [developer.paypal.com](https://developer.paypal.com)
  - EMVCo specifications: [emvco.com](https://www.emvco.com)
  - 3-D Secure 2.x spec: [EMVCo 3DS](https://www.emvco.com/specifications/)
  - Apple Pay developer: [developer.apple.com/apple-pay](https://developer.apple.com/apple-pay/)
  - Google Pay developer: [developers.google.com/pay/api](https://developers.google.com/pay/api)
  - OWASP API Security Top 10: [owasp.org/API-Security](https://owasp.org/API-Security/)
  - PSD2 SCA guidance (EBA): [eba.europa.eu](https://eba.europa.eu)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
