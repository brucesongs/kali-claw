# Payment Security Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume a sandbox / test-mode environment and lawful authorization (engagement scope, signed SoW naming the CDE). Production testing requires explicit per-test approval.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Compliance & PCI Scope | 3 | MEDIUM - HIGH |
| B. API Security | 3 | HIGH - CRITICAL |
| C. Mobile Wallets | 3 | MEDIUM - HIGH |
| D. Fraud & Risk | 2 | MEDIUM - HIGH |
| E. EMV & Terminal | 2 | MEDIUM - HIGH |
| **Total** | **13** | **MEDIUM - CRITICAL** |

---

## A. Compliance & PCI Scope

### TC-PS-001: PCI-DSS Scope Delineation Validation

| Field | Value |
|------|-----|
| **ID** | TC-PS-001 |
| **Name** | PCI-DSS Scope Delineation Validation |
| **Severity** | HIGH |
| **Category** | Compliance & PCI Scope |
| **Objective** | Verify that systems declared "out of scope" (e.g., marketing CMS, analytics) cannot reach the Cardholder Data Environment (CDE). Broken segmentation pulls out-of-scope systems into PCI scope and triggers remediation cost. |
| **Prerequisites** | Signed SoW naming the CDE boundary; network diagram showing declared in/out-of-scope systems; testing window from an out-of-scope host. |
| **Test Steps** | 1. From an out-of-scope host (e.g., marketing CMS subnet), enumerate CDE systems: `nmap -p1-65535 -sV --reason --traceroute --script=firewalk 10.0.1.5` (payment gateway)<br>2. Capture inter-zone traffic: `tcpdump -i any -w seg.pcap host 10.0.5.20 and host 10.0.1.5`<br>3. Test reachability to each CDE component (payment gateway proxy, 3DS server, tokenization vault)<br>4. For each reachable port, document the full network path (L3 hops, intermediate switches/firewalls)<br>5. Inspect firewall ACLs: `iptables -L -n -v` on declared segmentation devices |
| **Expected Results** | Out-of-scope hosts have zero reachable paths to any CDE component; tcpdump shows no packets; firewall logs show DENY for all inter-zone attempts. |
| **False Positive Risk** | LOW — segmentation is binary (reachable or not). Risk: a system that legitimately needs one-port access for tokenized data only may be mis-flagged as "in scope"; review the actual data flow before reclassifying. |
| **Remediation (defense)** | Enforce default-deny ACLs between out-of-scope and CDE subnets; document each approved exception with PCI-DSS compensating control; re-run segmentation pen-test quarterly (PCI req 11.4 / 12.5.5). |
| **Related Tools** | nmap, tcpdump, iptables |

### TC-PS-002: ASV External PCI-DSS Vulnerability Scan

| Field | Value |
|------|-----|
| **ID** | TC-PS-002 |
| **Name** | ASV External PCI-DSS Vulnerability Scan |
| **Severity** | MEDIUM |
| **Category** | Compliance & PCI Scope |
| **Objective** | Run an ASV-approved external vulnerability scan against internet-facing payment components to satisfy PCI-DSS req 11.3.2 (quarterly external scan by Approved Scanning Vendor). |
| **Prerequisites** | Nessus (ASV mode) or Qualys WAS PCI template; signed ASV attestation form; scope list of external IPs/hostnames. |
| **Test Steps** | 1. Define scope: `payments.example.com`, `api.example.com`, `checkout.example.com`<br>2. Launch ASV scan: `nessuscli scan new --template "PCI-DSS External Network" --targets payments.example.com,api.example.com --name "Q2 PCI External"`<br>3. Wait for scan completion (typically 2-6 hours depending on scope)<br>4. Triage findings: focus on CVSS 4.0+ (CRITICAL/HIGH) first<br>5. Re-scan after remediation; PCI requires "clean" (no CRITICAL) attestation |
| **Expected Results** | Zero CRITICAL vulnerabilities; HIGH findings documented with remediation plan; attestation report signed by ASV. |
| **False Positive Risk** | MEDIUM — banners, version strings, andTLS cipher "weaknesses" may flag without exploitable risk. ASV attestation requires the ASV to confirm or override each finding. |
| **Remediation (defense)** | Patch identified vulnerabilities; if a "CRITICAL" is a false positive, document justification and request ASV override; submit clean attestation quarterly. |
| **Related Tools** | Nessus, Qualys WAS |

### TC-PS-003: Internal CDE Vulnerability Scan

| Field | Value |
|------|-----|
| **ID** | TC-PS-003 |
| **Name** | Internal CDE Vulnerability Scan |
| **Severity** | MEDIUM |
| **Category** | Compliance & PCI Scope |
| **Objective** | Run an authenticated internal vulnerability scan against CDE systems to satisfy PCI-DSS req 11.3.1 (quarterly internal scan, with re-scan after fixes showing no CRITICAL). |
| **Prerequisites** | Nessus or Qualys scanner with credentials for CDE hosts; testing window in CDE maintenance slot. |
| **Test Steps** | 1. Define CDE subnet scope (e.g., 10.0.1.0/24)<br>2. Launch authenticated scan: `nessuscli scan new --template "Basic Network Scan" --targets 10.0.1.0/24 --credentials ssh://user:pass@10.0.1.5 --name "PCI Internal Q2"`<br>3. For web apps in CDE: run authenticated web app scan against internal-only endpoints<br>4. Triage by CVSS; fix all CRITICAL/HIGH<br>5. Re-scan; PCI requires no CRITICAL on rescan for compliance |
| **Expected Results** | After remediation, internal CDE scan shows zero CRITICAL findings; HIGH findings have documented remediation or compensating control. |
| **False Positive Risk** | MEDIUM — authenticated scans are more accurate than unauthenticated, but service banners and patch-version detection can still mis-flag. |
| **Remediation (defense)** | Patch systems per scan findings; enforce patch SLA (e.g., CRITICAL within 7 days, HIGH within 30 days); integrate scanner into change-management process so new systems are scanned before CDE admission. |
| **Related Tools** | Nessus, Qualys, OpenVAS |

---

## B. API Security

### TC-PS-004: Stripe Webhook Signature Validation & Replay Protection

| Field | Value |
|------|-----|
| **ID** | TC-PS-004 |
| **Name** | Stripe Webhook Signature Validation & Replay Protection |
| **Severity** | CRITICAL |
| **Category** | API Security |
| **Objective** | Verify the client's `/webhooks/stripe` handler (a) verifies the `Stripe-Signature` HMAC, (b) enforces a 5-minute timestamp tolerance to prevent replay attacks, and (c) rejects mismatched signatures. A bypass lets an attacker forge payment-success events and grant goods/services without a real payment. |
| **Prerequisites** | Stripe CLI installed (`stripe login`); client dev server running locally; webhook signing secret (`whsec_...`); test-mode Stripe key (`sk_test_...`). |
| **Test Steps** | 1. Start webhook forwarder: `stripe listen --forward-to localhost:8000/webhooks`<br>2. Trigger a legitimate event: `stripe trigger payment_intent.succeeded` — confirm server processes it (200 OK)<br>3. Capture the raw webhook payload + signature from the Stripe CLI output<br>4. Replay the exact captured request via `curl` — confirm server returns 200 (idempotency expected) but does NOT double-process<br>5. Modify the timestamp to 1 hour ago and re-sign: `t=<old>,v1=<forged>` — confirm server rejects with 400<br>6. Modify the body (e.g., change amount from 1000 to 999999) with the original signature — confirm server rejects (400, signature mismatch)<br>7. Send a forged signature with a forged body — confirm 400 |
| **Expected Results** | Server returns 400 for: stale timestamps (> 5 min), signature mismatches, forged signatures. Server returns 200 only for valid recent signatures with unmodified bodies. |
| **False Positive Risk** | LOW — signature verification is deterministic. Risk: a server might cache webhook IDs for idempotency and return 200 on a duplicate `evt_xxx` even with a stale signature — verify the server rejects based on signature, not on ID cache. |
| **Remediation (defense)** | Use Stripe's official `stripe.Webhook.constructEvent(payload, sig, secret, tolerance=300)` SDK function; never skip tolerance check; log every webhook with verification outcome for audit trail (PCI req 10). |
| **Related Tools** | stripe CLI, curl, openssl |

### TC-PS-005: 3-D Secure Challenge Bypass via SCA Exemption Misuse

| Field | Value |
|------|-----|
| **ID** | TC-PS-005 |
| **Name** | 3-D Secure Challenge Bypass via SCA Exemption Misuse |
| **Severity** | HIGH |
| **Category** | API Security |
| **Objective** | Identify flows where Strong Customer Authentication (SCA, PSD2) is incorrectly skipped via exemption misuse (low-value, trusted beneficiary, corporate card, recurring). Bypassing SCA shifts fraud liability back onto the merchant and violates PSD2. |
| **Prerequisites** | Test-mode credentials for Stripe/Adyen; test cards that route to specific 3DS outcomes; understanding of PSD2 SCA exemption rules. |
| **Test Steps** | 1. Submit a normal transaction above the low-value threshold (e.g., €35) — confirm challenge is triggered<br>2. Submit the same transaction with `merchant_category=low_value` exemption flag — confirm server still triggers challenge if cumulative threshold exceeded<br>3. Submit a transaction marked as `recurring=true` on the first payment (should NOT be recurring — first payment always requires SCA) — confirm challenge still triggered<br>4. Submit with `corporate=true` exemption on a personal card BIN (4111...) — confirm challenge triggered<br>5. Submit with `trusted_beneficiary=true` for an untrusted merchant — confirm challenge triggered<br>6. For each bypass found, document the request, response, and which exemption was abused |
| **Expected Results** | All exemption types are validated server-side; bypass attempts return 402 or trigger challenge regardless of client-supplied exemption flags. |
| **False Positive Risk** | MEDIUM — some exemptions (true low-value, true recurring) legitimately skip challenge. Verify each test against the actual exemption rules, not the client-supplied flag. |
| **Remediation (defense)** | Server-side exemption validation based on issuer responses, not client-supplied flags; cumulative low-value tracking per cardholder; trusted-beneficiary confirmation flow with issuer. |
| **Related Tools** | stripe CLI, curl, Adyen test cards |

### TC-PS-006: Idempotency Key Abuse on PaymentIntent

| Field | Value |
|------|-----|
| **ID** | TC-PS-006 |
| **Name** | Idempotency Key Abuse on PaymentIntent |
| **Severity** | HIGH |
| **Category** | API Security |
| **Objective** | Verify the server enforces idempotency on state-changing payment calls. Missing idempotency enables double-charges on retry; weak idempotency (server trusts client-supplied keys without caching) enables the same key with different bodies. |
| **Prerequisites** | Test-mode Stripe key; access to the client's payment API endpoint (or direct Stripe API in test mode). |
| **Test Steps** | 1. Create a PaymentIntent with `Idempotency-Key: K1`: amount=1000<br>2. Create another with the SAME key `K1` but amount=999999<br>3. Verify Stripe returns the original PaymentIntent (Stripe's idempotency cache is keyed on the key + body hash, so different bodies with same key return the cached original)<br>4. Test the client's own idempotency layer (if implemented): submit the same key with different body to the client API<br>5. Test retry path: simulate network timeout on client, retry with same key — confirm only ONE charge posts<br>6. Test missing key path: submit POST without Idempotency-Key, simulate retry — confirm server generates key from (user, intent) tuple |
| **Expected Results** | Same key → same response (cached); different body with same key → original cached result; retry with same key → single charge; missing key → server generates a key or rejects. |
| **False Positive Risk** | LOW — idempotency is well-defined by Stripe. Risk: a server-side idempotency cache with TTL too short (e.g., 60s) may allow replay after expiry; verify the cache lifetime matches Stripe's (30 days). |
| **Remediation (defense)** | Always send `Idempotency-Key` on POST /v1/payment_intents, /v1/charges, /v1/refunds; server-side cache keyed on (key, body-hash) with 30-day TTL; reject missing keys on retry-prone endpoints. |
| **Related Tools** | stripe CLI, curl |

---

## C. Mobile Wallets

### TC-PS-007: Apple Pay Token (DAN) Interception via Frida

| Field | Value |
|------|-----|
| **ID** | TC-PS-007 |
| **Name** | Apple Pay Token (DAN) Interception via Frida |
| **Severity** | HIGH |
| **Category** | Mobile Wallets |
| **Objective** | Confirm that the Apple Pay token packet (delivered to the merchant app via `PKPaymentAuthorizationViewController`) contains a Device Account Number (DAN) and per-transaction cryptogram — never the real PAN. Tokenization breakdown would expose raw PAN to the app layer. |
| **Prerequisites** | Jailbroken iOS device (or jailbroken emulator) with Frida server running; merchant iOS app installed; Apple Pay configured with a test card. |
| **Test Steps** | 1. Start Frida: `frida-server &` on device<br>2. Hook the merchant app: `frida -U -f com.example.app -l applepay_hook.js --no-pause`<br>3. Initiate an Apple Pay checkout in the app<br>4. Authorize with Touch ID / Face ID<br>5. Inspect the console output for the `applicationPrimaryAccountNumber` (DAN) and `applicationCryptogram`<br>6. Verify the DAN does NOT match the real card's PAN (DAN should be 4XXX-XXXX-XXXX-XXXX but a different number)<br>7. Verify the `transactionIdentifier` is unique per transaction<br>8. Verify `eciIndicator` is "05" (fully authenticated) for 3DS-authenticated transactions |
| **Expected Results** | `applicationPrimaryAccountNumber` is a tokenized DAN (not the real PAN); cryptogram is present; transaction ID is unique; ECI indicates authentication level. |
| **False Positive Risk** | LOW — DAN vs PAN is a binary check. Risk: confusing the `transactionIdentifier` (Apple's transaction ID, not the PAN) with the DAN — verify the JSON field name carefully. |
| **Remediation (defense)** | Apple Pay tokenization is enforced by Apple's Secure Enclave — there is no app-side fix for tokenization breakdown (would be an Apple-side bug). App-side: forward the entire token packet (including cryptogram) to the gateway unchanged; never log the DAN. |
| **Related Tools** | Frida, Frida-Cycript, jailbroken iOS device |

### TC-PS-008: Google Pay SDK Tokenization Test

| Field | Value |
|------|-----|
| **ID** | TC-PS-008 |
| **Name** | Google Pay SDK Tokenization Test |
| **Severity** | MEDIUM |
| **Category** | Mobile Wallets |
| **Objective** | Verify the Android app's Google Pay integration uses the correct `TokenizationSpecification` (gateway tokenization via Stripe/Adyen, or direct network token) and that the result token is forwarded to the gateway unchanged. Misuse of `DIRECT` tokenization without proper gateway setup exposes the token to misuse. |
| **Prerequisites** | Rooted Android device or emulator with Magisk; Frida server running; merchant Android app installed; Google Pay configured. |
| **Test Steps** | 1. Hook `com.google.android.gms.wallet.PaymentsClient.loadPaymentData` via Frida<br>2. Initiate a Google Pay checkout in the app<br>3. Inspect the `PaymentData` result via `AutoResolveHelper`<br>4. Extract `paymentMethodToken.getToken()` — this is the gateway-specific token (e.g., Stripe token `tok_...` or bank token)<br>5. Verify the `TokenizationSpecification` configured in the `PaymentMethodTokenizationParameters`: should be `PAYMENT_GATEWAY` (not `DIRECT` unless PCI-DSS-compliant direct integration)<br>6. Confirm the token is sent to the merchant's backend, not directly to a third party<br>7. Verify the backend forwards it to the gateway for charge |
| **Expected Results** | `TokenizationSpecification` is `PAYMENT_GATEWAY` (Stripe/Adyen/etc.); token is a gateway-format string (e.g., `tok_xxx`, `pf_xxx`); token never leaves the merchant-backend → gateway path. |
| **False Positive Risk** | MEDIUM — `DIRECT` tokenization is legitimate for PCI-DSS Level 1 merchants handling their own tokenization, but rare. Verify the merchant's PCI status before flagging `DIRECT` as a finding. |
| **Remediation (defense)** | Use `PAYMENT_GATEWAY` tokenization by default; reserve `DIRECT` for PCI-DSS Level 1 merchants with audited tokenization infrastructure; never expose the raw token to analytics or third-party SDKs. |
| **Related Tools** | Frida, Magisk, Android emulator |

### TC-PS-009: Frida Runtime Hook of Payment Delegate

| Field | Value |
|------|-----|
| **ID** | TC-PS-009 |
| **Name** | Frida Runtime Hook of Payment Delegate |
| **Severity** | MEDIUM |
| **Category** | Mobile Wallets |
| **Objective** | Verify the app's payment delegate methods cannot be hooked to bypass local validation (e.g., hook `paymentAuthorizationViewController:didAuthorizePayment:completion:` to always call `completion(PKPaymentAuthorizationStatusSuccess)` regardless of actual authorization). |
| **Prerequisites** | Jailbroken iOS device with Frida; merchant app installed; understanding of Objective-C delegate method signatures. |
| **Test Steps** | 1. Write a Frida hook that replaces the `completion:` callback to always return success: `Interceptor.replace(ObjC.classes...['...'].implementation, new NativeCallback(...))`<br>2. Attach the hook and initiate checkout<br>3. Observe whether the app proceeds to "order confirmed" without a valid Apple Pay authorization<br>4. Verify the backend independently validates the gateway charge — a successful hook on the client should NOT result in goods shipped if the backend verifies the gateway token<br>5. Repeat for Google Pay on Android |
| **Expected Results** | Client-side hook succeeds (client thinks payment authorized) but backend rejects the missing/invalid gateway token; no goods shipped. If goods are shipped based on client state alone, this is a CRITICAL finding. |
| **False Positive Risk** | HIGH — client-side hooks always work on jailbroken devices (jailbreak detection is the mitigation). The real test is whether the backend verifies the gateway token; a "successful" client hook without backend verification is the actual vulnerability. |
| **Remediation (defense)** | Backend must independently verify the gateway token (e.g., call Stripe's `payment_intents/retrieve`); jailbreak/root detection should refuse to run wallet on compromised devices (defense-in-depth, not relied upon); client-side success state is never trusted for fulfillment. |
| **Related Tools** | Frida, jailbroken iOS, rooted Android |

---

## D. Fraud & Risk

### TC-PS-010: Card Testing Pattern (BIN Attack) Detection

| Field | Value |
|------|-----|
| **ID** | TC-PS-010 |
| **Name** | Card Testing Pattern (BIN Attack) Detection |
| **Severity** | HIGH |
| **Category** | Fraud & Risk |
| **Objective** | Verify the client's fraud/abuse detection catches card-testing bots (rapid declines clustered by BIN and IP). A bot can validate thousands of stolen cards in hours if undetected, costing the merchant processor fees and chargebacks. |
| **Prerequisites** | Test-mode API access; authorization to simulate card testing; client's fraud detection in active mode. |
| **Test Steps** | 1. Simulate a card-testing bot: `for i in $(seq 1 100); do curl -X POST https://api.example.com/checkout -d "{\"card\": \"4111 1111 1111 $i\", \"amount\": 100}"; done` (all 100 should decline in test mode)<br>2. Distribute across 5 BINs (4111..., 5555..., 5101..., 4000..., 3782...) to mimic real card-testing<br>3. Vary IP via Tor: `--socks5-hostname 127.0.0.1:9050`<br>4. Observe server responses: should rate-limit (429), show CAPTCHA, or block the IP after threshold<br>5. Confirm the client's fraud system (Sift/Forter/custom) flagged the pattern<br>6. Verify the client's alerting notifies on-call when threshold hit |
| **Expected Results** | After 5-10 declines from same IP, server responds with CAPTCHA or 429; after 20+ declines from same BIN, fraud system flags; IP is blocked; on-call alerted. |
| **False Positive Risk** | MEDIUM — legitimate users with multiple failed cards (e.g., gift cards) may trigger false positives. Tune threshold by IP + BIN clustering, not just decline count. |
| **Remediation (defense)** | Velocity limits per IP and per BIN per hour; CAPTCHA after 3 declines; AVS/CVV enforcement; block datacenter IPs on checkout; integrate Sift/Forter/Riskified for behavioral scoring; alert on-call at threshold. |
| **Related Tools** | curl, tor, Sift sandbox |

### TC-PS-011: Sift Science Feature Probe (Sandbox Only)

| Field | Value |
|------|-----|
| **ID** | TC-PS-011 |
| **Name** | Sift Science Feature Probe (Sandbox Only) |
| **Severity** | MEDIUM |
| **Category** | Fraud & Risk |
| **Objective** | Understand the Sift Science fraud model's decision boundaries by sending synthetic events with escalating risk signals in sandbox mode. NEVER run this against production — a single high-risk event can taint the merchant's risk profile. |
| **Prerequisites** | Sift sandbox API key; explicit authorization to probe the model; understanding that production probing is prohibited. |
| **Test Steps** | 1. Send baseline event: `$create_order` with US billing, $50 amount, US IP — record score<br>2. Escalate amount: $5000, $50000, $500000 — observe score change<br>3. Change billing country to high-risk (RU, NG, VN) — observe score<br>4. Change IP to datacenter (185.220.101.5 = Tor exit) — observe score<br>5. Add velocity signal: same user, 10 orders in 1 minute — observe score<br>6. Add mismatched billing/shipping countries — observe score<br>7. Map feature importance by varying one feature at a time and recording score delta |
| **Expected Results** | Score increases monotonically with each risk signal; thresholds identifiable (e.g., score > 70 = decline, 50-70 = challenge, < 50 = frictionless). Feature importance inferred from score deltas. |
| **False Positive Risk** | LOW — sandbox mode is isolated from production. Risk: confusing sandbox score with production behavior — sandbox models may differ slightly from production; treat inferred thresholds as approximate. |
| **Remediation (defense)** | (Defender perspective) Sift is the defense; this test maps its decision boundary so the merchant understands what an attacker learns. Tune custom rules to close identified gaps; combine Sift with hard velocity limits (defense-in-depth). |
| **Related Tools** | curl, Sift sandbox |

---

## E. EMV & Terminal

### TC-PS-012: EMV Chip Transaction Replay Test

| Field | Value |
|------|-----|
| **ID** | TC-PS-012 |
| **Name** | EMV Chip Transaction Replay Test |
| **Severity** | MEDIUM |
| **Category** | EMV & Terminal |
| **Objective** | Verify the terminal and issuer reject replayed EMV cryptograms (a captured AC from a prior transaction should not be accepted for a new transaction). EMV's per-transaction cryptogram + monotonic ATC is the core replay defense. |
| **Prerequisites** | EMVCo test cards (Visa VTS, Mastercard MCHIP); smart card reader (ACR122U or similar); `pcsc-tools` + `scriptor`; terminal-under-test in test mode. |
| **Test Steps** | 1. Read a card's tags: `echo "00A4040007A000000004101000" \| scriptor` (select Visa app)<br>2. Capture an AC (Application Cryptogram, tag 9F26) and ATC (9F36) from a legitimate transaction<br>3. Replay the same AC on a new transaction attempt — verify terminal rejects (cryptogram is one-time-use)<br>4. Test ATC monotonicity: capture ATC, attempt a transaction with a lower ATC — verify rejection<br>5. Verify the terminal sends the cryptogram to the issuer for online authorization (most chip transactions are online)<br>6. For offline-capable terminals (rare in US, common in EU small-merchant): verify CVR (Card Verification Results) in IAD (9F10) is checked |
| **Expected Results** | Replayed AC rejected; ATC must be greater than the last seen ATC; terminal always sends cryptogram online for issuer validation (for online terminals); CVR checks enforced for offline terminals. |
| **False Positive Risk** | LOW — EMV cryptogram validation is deterministic. Risk: test cards may behave differently from live cards; verify with EMVCo reference cards. |
| **Remediation (defense)** | Terminal must verify AC with issuer (online) or via card's RSA public key (offline CDA); enforce ATC tracking; reject CVR mismatches. L2 kernel configuration must match card scheme rules. |
| **Related Tools** | pcsc-tools, scriptor, ACR122U reader, EMVCo test cards |

### TC-PS-013: Contactless Payment Relay Test

| Field | Value |
|------|-----|
| **ID** | TC-PS-013 |
| **Name** | Contactless Payment Relay Test |
| **Severity** | HIGH |
| **Category** | EMV & Terminal |
| **Objective** | Verify the contactless terminal has some defense against relay attacks (attacker reads victim's card in one location, relays the EMV exchange to a terminal elsewhere). Most terminals lack distance bounding — confirm whether latency or other checks exist. |
| **Prerequisites** | Two NFC readers (Proxmark3 or custom); victim test card; terminal-under-test; controlled lab environment. |
| **Test Steps** | 1. Set up a relay: reader A near the victim card, reader B near the terminal-under-test<br>2. Relay the EMV exchange from terminal → reader B → reader A → card → back<br>3. Measure the additional latency introduced by the relay<br>4. Attempt the relayed transaction — observe if terminal accepts<br>5. If accepted, document the latency tolerance of the terminal (e.g., < 500 ms accepts relay)<br>6. Test with extended relay latency (1s, 5s) to find the rejection threshold<br>7. Document whether the terminal implements any distance bounding (rare) |
| **Expected Results** | Most terminals accept relayed transactions (distance bounding is rare). The finding should document the absence of distance bounding as a known industry gap, with the mitigation being reliance on EMV's per-transaction cryptogram (which makes replay, not relay, the harder attack). |
| **False Positive Risk** | HIGH — relay attacks "succeed" on most terminals; this is an industry-wide gap, not a per-terminal bug. Document as a residual risk with industry context, not as a critical per-merchant finding. |
| **Remediation (defense)** | (Industry) Deploy NFC distance bounding (EMV distance bounding spec, rare as of 2026); (Merchant) lower contactless transaction limit (CL-T) to minimize relay incentive; monitor for relay-attack patterns in transaction logs (geographic mismatch between card-present and cardholder location). |
| **Related Tools** | Proxmark3, custom NFC relay, EMVCo reference cards |

---

## Summary Table

| ID | Name | Severity | Category |
|------|------|----------|----------|
| TC-PS-001 | PCI-DSS Scope Delineation Validation | HIGH | Compliance |
| TC-PS-002 | ASV External PCI-DSS Vulnerability Scan | MEDIUM | Compliance |
| TC-PS-003 | Internal CDE Vulnerability Scan | MEDIUM | Compliance |
| TC-PS-004 | Stripe Webhook Signature Validation & Replay Protection | CRITICAL | API Security |
| TC-PS-005 | 3-D Secure Challenge Bypass via SCA Exemption Misuse | HIGH | API Security |
| TC-PS-006 | Idempotency Key Abuse on PaymentIntent | HIGH | API Security |
| TC-PS-007 | Apple Pay Token (DAN) Interception via Frida | HIGH | Mobile Wallets |
| TC-PS-008 | Google Pay SDK Tokenization Test | MEDIUM | Mobile Wallets |
| TC-PS-009 | Frida Runtime Hook of Payment Delegate | MEDIUM | Mobile Wallets |
| TC-PS-010 | Card Testing Pattern (BIN Attack) Detection | HIGH | Fraud & Risk |
| TC-PS-011 | Sift Science Feature Probe (Sandbox Only) | MEDIUM | Fraud & Risk |
| TC-PS-012 | EMV Chip Transaction Replay Test | MEDIUM | EMV & Terminal |
| TC-PS-013 | Contactless Payment Relay Test | HIGH | EMV & Terminal |

---

**Related files**: `SKILL.md`, `payloads.md`, `guides/payment-pentest-playbook.md`
**PCI SSC**: [pcisecuritystandards.org](https://www.pcisecuritystandards.org) | **Stripe**: [stripe.com/docs/security](https://stripe.com/docs/security) | **EMVCo**: [emvco.com](https://www.emvco.com)
