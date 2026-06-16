# Payment Security Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command assumes lawful authorization, an executed NDA, and (for active payment API calls) processor **test mode** credentials. Production testing requires a separate Statement of Work naming the cardholder data environment and test window.
>
> Placeholder convention: `<merchant_id>` (Stripe/Adyen), `<webhook_secret>` (`whsec_...`), `<sandbox_key>` (`sk_test_...` / test API key), `< PAN>` is a 16-digit card number (always test-mode).

---

## 1. PCI-DSS 4.0 Reference

### 1.1 The 12 Requirement Families

| Req | Family | What to Test |
|-----|--------|--------------|
| 1 | Install and maintain network security controls | Firewall rules between CDE and out-of-scope; segmentation tests (req 1.2 / 1.3 / 12.5.5) |
| 2 | Apply secure configurations to network devices | Default passwords, unnecessary services, SNMP community strings |
| 3 | Protect stored account data | PAN masking (display + logs), encryption at rest (req 3.5), key management (req 3.6 / 3.7) |
| 4 | Protect cryptographic keys used for account data | HSM usage, key rotation, dual control |
| 5 | Protect all systems and networks from malicious software | Anti-malware on CDE systems (req 5.2), including POS terminals |
| 6 | Develop and maintain secure systems and software | Vulnerability scan monthly (req 11.3), pentest annually (req 11.4), secure SDLC |
| 7 | Restrict access to system components and account data by business need to know | RBAC, least privilege, access request workflow |
| 8 | Identify users and authenticate access to system components | MFA (req 8.4), password policy, session management |
| 9 | Restrict physical access to cardholder data | Badge access, visitor logs, terminal tamper detection |
| 10 | Log and monitor all access to system components and cardholder data | Centralized logging, audit trail review (req 10.4), time sync (req 10.6) |
| 11 | Test security of systems and networks regularly | Wireless scans (req 11.2), internal/external vuln scans, annual pentest, change-detection (FIM) |
| 12 | Support information security with organizational policies and programs | Security policy, incident response, training (req 12.6) |

### 1.2 Scope Delineation Test

```bash
# Identify the Cardholder Data Environment (CDE) boundary
# Walk every system and answer: does it store / process / transmit PAN?

# Inventory template
cat <<EOF > cde_inventory.tsv
component	ip	stores_pan	processes_pan	transmits_pan	in_scope
checkout-api	10.0.1.5	no	no	yes-pre-tokenization	yes
payment-gw-proxy	10.0.1.6	no	yes	yes	yes
order-db	10.0.2.10	no	no	no-tokenized	only-if-reaches-cde
marketing-cms	10.0.5.20	no	no	no	no
EOF

# Verify segmentation between out-of-scope and CDE
nmap -p1-65535 -sV --reason 10.0.2.10 --script=firewalk --traceroute
# If a reachable path exists from out-of-scope → CDE without a firewall, segmentation is broken

# Capture traffic between suspected out-of-scope and CDE to confirm no PAN transit
tcpdump -i any -w segmentation.pcap host 10.0.5.20 and host 10.0.1.5
tshark -r segmentation.pcap -Y "data contains \"4" | head
```

---

## 2. Stripe API Testing Patterns

### 2.1 Setup & Webhook Forwarding

```bash
# Install: https://stripe.com/docs/stripe-cli
stripe login

# Forward webhooks to local dev server (with event filtering)
stripe listen --forward-to localhost:8000/webhooks \
  --events payment_intent.succeeded,charge.failed,invoice.payment_succeeded,customer.subscription.deleted

# In another terminal, trigger synthetic events
stripe trigger payment_intent.succeeded
stripe trigger charge.failed
stripe trigger invoice.payment_succeeded
stripe trigger customer.subscription.deleted
```

### 2.2 Webhook Signature Bypass Attempts

```bash
# Capture the raw webhook + signature header
# (stripe listen prints the signing secret: whsec_...)

# Replay attack: capture, modify amount, replay
# Legitimate Stripe webhook signature includes a timestamp:
#   Stripe-Signature: t=1700000000,v1=abc123...
# The server must reject timestamps older than ~5 minutes

# Manual replay with stale timestamp
WEBHOOK_BODY='{"id":"evt_test","type":"payment_intent.succeeded","data":{"object":{"amount":9999}}}'
TIMESTAMP=1700000000  # old
SIGNED_PAYLOAD="${TIMESTAMP}.${WEBHOOK_BODY}"
SIGNATURE=$(echo -n "$SIGNED_PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')

curl -X POST http://localhost:8000/webhooks \
  -H "Stripe-Signature: t=${TIMESTAMP},v1=${SIGNATURE}" \
  -H "Content-Type: application/json" \
  -d "$WEBHOOK_BODY"

# Expected: 400 Bad Request — timestamp too old
# Vulnerable: 200 OK — replay window accepted

# Replay attack: use a valid recent signature with modified body
# (Will fail signature verification on a correct server)
MODIFIED_BODY='{"id":"evt_test","type":"payment_intent.succeeded","data":{"object":{"amount":1}}}'
curl -X POST http://localhost:8000/webhooks \
  -H "Stripe-Signature: t=1700000060,v1=forged_signature" \
  -d "$MODIFIED_BODY"
# Expected: 400 — signature mismatch
# Vulnerable: 200 — signature not verified
```

### 2.3 Idempotency Key Abuse

```bash
# Stripe idempotency: same key on POST /v1/charges should return cached result
# Test: use the same idempotency key with different request bodies

KEY="client_generated_uuid_123"

curl -X POST https://api.stripe.com/v1/payment_intents \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" \
  -H "Idempotency-Key: $KEY" \
  -d amount=1000 -d currency=usd -d "payment_method_types[]=card"

# Second request with SAME key but DIFFERENT amount
curl -X POST https://api.stripe.com/v1/payment_intents \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" \
  -H "Idempotency-Key: $KEY" \
  -d amount=999999 -d currency=usd -d "payment_method_types[]=card"

# Expected: Stripe returns the FIRST PaymentIntent (cached), ignores second body
# Vulnerable (if server implements its own idempotency cache): may process both

# Missing idempotency key on retry path — network blip → double charge
# Test by simulating a flaky network: retry without the same key
```

### 2.4 PaymentIntent Lifecycle Manipulation

```bash
# Create a PaymentIntent
PI=$(curl -s -X POST https://api.stripe.com/v1/payment_intents \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" \
  -d amount=1000 -d currency=usd | jq -r .id)

# Attempt to confirm with a test card that should fail
curl -X POST "https://api.stripe.com/v1/payment_intents/$PI/confirm" \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" \
  -d "payment_method=pm_card_chargeDeclinedInsufficientFunds"

# Try to capture a PaymentIntent that was never authorized
curl -X POST "https://api.stripe.com/v1/payment_intents/$PI/capture" \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" \
  -d amount_to_capture=1000

# Try to refund a PaymentIntent that wasn't captured
curl -X POST https://api.stripe.com/v1/refunds \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" \
  -d "payment_intent=$PI"
```

### 2.5 Customer Object Data Leakage

```bash
# Retrieve a customer object — should NOT include full PAN
curl -s https://api.stripe.com/v1/customers/cus_test_123 \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" | jq '.sources.data[].last4'
# OK: returns last4 only
# BAD: any field exposing full PAN

# List payment methods attached to a customer
curl -s "https://api.stripe.com/v1/payment_methods?customer=cus_test_123&type=card" \
  -H "Authorization: Bearer $STRIPE_TEST_KEY" | jq '.data[].card'
# Should show brand, last4, exp_month, exp_year, fingerprint — NOT full PAN
```

---

## 3. Adyen API Testing Patterns

### 3.1 Adyen Test Cards (Deterministic Declines)

| Test PAN | Result |
|----------|--------|
| `4111 1111 4555 4522` | Refused (generic) |
| `5101 1800 0000 0007` | Refused (not enrolled in 3DS) |
| `4111 1111 1111 1111` | Authorized (Visa) |
| `5555 4444 3333 1111` | Authorized (Mastercard) |
| `3700 0000 0000 002` | Authorized (Amex) |
| `4977 9494 9494 9497` | Refused (referred) |
| `4000 0000 0000 0002` | Refused (declined) |

### 3.2 Adyen Webhook HMAC Verification

```bash
# Adyen webhooks use HMAC signature over a "notification" payload
# Verify with the HMAC key from the Customer Area

PAYLOAD='{"live":"false","notificationItems":[{"NotificationRequestItem":{"amount":{"value":1000,"currency":"USD"},"eventCode":"AUTHORISATION","merchantAccountCode":"TestMerchant","pspReference":"test_REF","success":"true"}}]}'

# Adyen computes HMAC over the escaped JSON, base64-encoded
HMAC_SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$ADYEN_HMAC_KEY" -binary | base64)

# Server-side check: compare incoming HMAC signature header
# Vulnerable server: skips verification → attacker can forge AUTHORISATION events
# → grant order without real payment
```

### 3.3 Adyen 3DS Routing

```bash
# Submit a payment with 3DS data and verify the server enforces challenge for high-risk
curl -X POST https://checkout-test.adyen.com/v68/payments \
  -H "X-API-KEY: $ADYEN_TEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "merchantAccount": "TestMerchant",
    "amount": {"value": 999999, "currency": "USD"},
    "paymentMethod": {"type": "scheme", "number": "4111111145554522", "expiryMonth": "03", "expiryYear": "2030", "holderName": "Test"},
    "returnUrl": "https://example.com/return",
    "additionalData": {"executeThreeD": "true"}
  }'
```

---

## 4. PayPal API Testing Patterns

### 4.1 PayPal Sandbox Setup

```bash
# Sandbox endpoints
# API base: https://api-m.sandbox.paypal.com
# Login: https://www.sandbox.paypal.com

# Get access token (client credentials)
curl -X POST https://api-m.sandbox.paypal.com/v1/oauth2/token \
  -u "$PAYPAL_CLIENT_ID:$PAYPAL_SECRET" \
  -d "grant_type=client_credentials"

# Use the returned access_token as Bearer
```

### 4.2 Order Capture Replay

```bash
# Create order
ORDER_ID=$(curl -s -X POST https://api-m.sandbox.paypal.com/v2/checkout/orders \
  -H "Authorization: Bearer $PAYPAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "intent": "CAPTURE",
    "purchase_units": [{"amount": {"currency_code": "USD", "value": "10.00"}}]
  }' | jq -r .id)

# Capture the order
curl -X POST "https://api-m.sandbox.paypal.com/v2/checkout/orders/$ORDER_ID/capture" \
  -H "Authorization: Bearer $PAYPAL_TOKEN"

# Replay capture (PayPal should reject — already captured)
curl -X POST "https://api-m.sandbox.paypal.com/v2/checkout/orders/$ORDER_ID/capture" \
  -H "Authorization: Bearer $PAYPAL_TOKEN"
# Vulnerable custom layer: may grant order fulfillment twice for one payment
```

### 4.3 Webhook Signature Verification

```bash
# PayPal webhook headers:
#   PAYPAL-TRANSMISSION-ID, PAYPAL-TRANSMISSION-TIME, PAYPAL-TRANSMISSION-SIG, PAYPAL-CERT-URL

# Verify via PayPal's API
curl -X POST https://api-m.sandbox.paypal.com/v1/notifications/verify-webhook-signature \
  -H "Authorization: Bearer $PAYPAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_algo": "SHA256withRSA",
    "cert_url": "...",
    "transmission_id": "...",
    "transmission_sig": "...",
    "transmission_time": "...",
    "webhook_id": "...",
    "webhook_event": {...}
  }'
# Vulnerable server: trusts headers without verification → forged PAYMENT.CAPTURE.COMPLETED events
```

---

## 5. 3-D Secure 2.x Testing

### 5.1 3DS 2.x Flow Overview

```
1. Cardholder checks out
        │
2. Merchant → 3DS Server: init authentication (AReq)
        │
3. 3DS Server → Directory Server (Visa/MC/Amex) → Issuer ACS
        │
4. ACS risk decision:
        ├── Frictionless (low risk) → returns CAVV/ECI directly
        └── Challenge (high risk) → returns challenge URL
                │
                ├── App-based: SDK handles challenge natively
                ├── Browser-based: redirects to issuer URL
                └── 3RI (recurring): uses stored auth
        │
5. Merchant completes payment with CAVV/ECI → liability shift to issuer
```

### 5.2 Test Scenarios

| Scenario | Expected Behavior | Bypass to Find |
|----------|-------------------|----------------|
| High-value transaction (> €30) | Challenge required | Merchant forces frictionless via trx_type=R |
| First recurring payment | SCA required | Merchant marks as recurring=recurring to skip |
| Trusted beneficiary | Optional SCA | Beneficiary list manipulation |
| Low-value exemption (< €30) | Frictionless allowed | Amount manipulation to stay under threshold |
| Corporate card (B2B) | Exemption possible | Personal card marked as corporate |
| Anonymous prepaid | Challenge required | Marked as non-anonymous |

### 5.3 SDK Fingerprinting Test

```javascript
// Stripe 3DS2 SDK exposes a fingerprint (deviceCollect) to the issuer ACS
// Test: what signals does the SDK collect?

// Hook the Stripe 3DS2 SDK on iOS (Frida)
Interceptor.attach(ObjC.classes.STPThreeDS2Service['- beginDeviceCollectionForMessageVersion:completion:'].implementation, {
  onEnter: function(args) {
    console.log("[+] 3DS2 device collection started");
  }
});

// Manipulate the device fingerprint to look like a known-good device
// (anti-fraud evasion — only test with authorization)
```

---

## 6. Card Testing / BIN Attack Patterns

### 6.1 Card Testing Mechanics

```
Attacker goal: validate stolen card numbers (from a breach dump)
                without tripping fraud detection

Pattern:
1. Submit small donations / purchases (~$1) to test cards
2. Successful → card is live, save it
3. Failed → discard, try next

Detection signals:
- Velocity: > X declines per IP per hour
- BIN clustering: many cards from same BIN range
- Amount: suspiciously consistent ($1, $0.50)
- Time: rapid-fire requests (bot)
- Source IP: datacenter / Tor exit / VPN
- Email: disposable domains (mailinator, 10minutemail)
- AVS/CVV mismatch patterns
```

### 6.2 Velocity Detection Script (Defense Side)

```python
#!/usr/bin/env python3
"""Detect card testing by BIN-prefix clustering."""
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Parse access log lines for checkout POST + outcome
def parse_line(line: str) -> dict | None:
    m = re.search(r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*POST /checkout.*" (\d+)', line)
    if not m:
        return None
    return {
        "ip": m.group(1),
        "ts": datetime.strptime(m.group(2).split()[0], "%d/%b/%Y:%H:%M:%S"),
        "status": int(m.group(3)),
    }

def detect_card_testing(logfile: str, window_min: int = 60, threshold: int = 50) -> None:
    bins: dict[str, deque] = defaultdict(deque)
    declines_per_bin: dict[str, int] = defaultdict(int)

    with open(logfile) as f:
        for line in f:
            entry = parse_line(line)
            if not entry or entry["status"] != 402:  # payment required / declined
                continue
            # Extract BIN from card log (if logged — often NOT for PCI reasons)
            # In practice, you key by IP not BIN since you shouldn't log BIN
            bin_key = entry["ip"]
            declines_per_bin[bin_key] += 1
            bins[bin_key].append(entry["ts"])
            # Trim to window
            cutoff = entry["ts"] - timedelta(minutes=window_min)
            while bins[bin_key] and bins[bin_key][0] < cutoff:
                bins[bin_key].popleft()
            if len(bins[bin_key]) >= threshold:
                print(f"[ALERT] Card testing suspected: {bin_key} "
                      f"{len(bins[bin_key])} declines in {window_min} min")

if __name__ == "__main__":
    detect_card_testing(sys.argv[1])
```

### 6.3 CAPTCHA / Rate Limit Testing

```bash
# With authorization, probe the rate limit
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.example.com/checkout \
    -d "card=4111111111111111&amount=100&currency=usd"
done | sort | uniq -c
# Expected: 200s early, then 429 (rate limit) or 403 (CAPTCHA / block)
# Vulnerable: 100x 200 — no rate limit
```

---

## 7. Recurring Billing Manipulation

### 7.1 Plan Swap / Proration Abuse

```bash
# Legitimate plan swap with proration
curl -X POST https://api.example.com/subscriptions/sub_123/swap \
  -d '{"new_plan": "pro_monthly"}'
# Server charges prorated difference immediately

# Bug hunt: prorate=false from client
curl -X POST https://api.example.com/subscriptions/sub_123/swap \
  -d '{"new_plan": "enterprise_annual", "prorate": false}'
# Expected: server ignores client-supplied prorate flag
# Vulnerable: server honors flag → free upgrade, no proration charge

# Downgrade then immediately cancel (refund abuse)
curl -X POST https://api.example.com/subscriptions/sub_123/swap \
  -d '{"new_plan": "free_tier"}'
curl -X POST https://api.example.com/subscriptions/sub_123/cancel
# If cancel computes refund based on free_tier's $0 amount, you get $0 refund
# for what was a paid plan → no refund owed to the user (defense) OR
# If cancel refunds "unused" amount from the OLD plan, you get a windfall refund (vuln)
```

### 7.2 Trial Period Farming

```bash
# Cancel trial then immediately re-subscribe
curl -X POST https://api.example.com/subscriptions/sub_123/cancel
curl -X POST https://api.example.com/subscriptions \
  -d '{"plan": "pro_monthly", "trial_days": 14}'
# Expected: server tracks device/email/card and rejects new trial
# Vulnerable: infinite free trials by churning

# Card rotation to defeat fingerprinting
# (defeated by Stripe Radar / fraud system — see Section 11)
```

### 7.3 Pause/Resume Backdating

```bash
# Backdate a pause to extract a refund for already-rendered service
curl -X POST https://api.example.com/subscriptions/sub_123/pause \
  -d '{"until": "2024-01-15"}'  # backdated — today is 2024-06-16
# Expected: server rejects backdated pause
# Vulnerable: server applies retroactive pause + refunds prior period
```

---

## 8. Refund / Chargeback Fraud Patterns

### 8.1 Refund Webhook Forgery

```bash
# Forge a refund success webhook to grant refund fulfillment without real refund
# (Works if the server doesn't verify processor-side state)

curl -X POST http://localhost:8000/webhooks/stripe \
  -H "Stripe-Signature: forged" \
  -d '{"type":"charge.refunded","data":{"object":{"id":"ch_old_charge","amount_refunded":9999}}}'

# Mitigation: server should call Stripe API to confirm refund exists
```

### 8.2 Chargeback Response Tampering

```bash
# Chargeback represents a customer dispute; merchant responds with evidence
# Test: can the merchant's "evidence submitted" flag be tampered client-side?
curl -X POST https://api.example.com/chargebacks/cb_123/evidence \
  -d '{"submitted": true, "evidence_text": ""}'
# Expected: server requires actual evidence files + processor-side submission
# Vulnerable: server marks "submitted=true" without processor call
# → merchant thinks they responded but actually lost by default
```

---

## 9. Mobile Wallet Testing — Apple Pay / Google Pay

### 9.1 Apple Pay Frida Hook

```javascript
// applepay_hook.js
// Hook the Apple Pay authorization delegate to inspect the token packet
// The DAN (device account number) is a tokenized PAN — NEVER the real PAN

if (ObjC.available) {
  const PKPDelegate = ObjC.classes.PKPaymentAuthorizationViewController;
  const method = PKPDelegate['- paymentAuthorizationViewController:didAuthorizePayment:completion:'];
  Interceptor.attach(method.implementation, {
    onEnter: function(args) {
      const payment = new ObjC.Object(args[3]);  // PKPayment
      const token = payment.token();              // PKPaymentToken
      const paymentData = token.paymentData();    // NSData (JSON)
      const transactionId = token.transactionIdentifier();
      const paymentMethod = payment.paymentMethod();
      const displayName = paymentMethod.displayName();
      const network = paymentMethod.network();

      console.log("[+] Apple Pay payment authorized:");
      console.log("    Network:", network.toString());
      console.log("    Display name:", displayName.toString());
      console.log("    Transaction ID (DAN-derived):", transactionId.toString());

      // Parse the JSON payment data
      const error = Memory.alloc(Process.pointerSize);
      const json = ObjC.classes.NSJSONSerialization.JSONObjectWithData_options_error_(paymentData, 0, error);
      if (!error.readPointer().isNull()) {
        console.log("    [!] Failed to parse payment data");
        return;
      }
      const dan = json.objectForKey_("applicationPrimaryAccountNumber");
      console.log("    DAN:", dan ? dan.toString() : "(missing)");
      // CRITICAL: DAN should NEVER match the user's real PAN
      // If it does, tokenization is broken — escalate immediately

      const cryptogram = json.objectForKey_("applicationCryptogram");
      console.log("    Cryptogram:", cryptogram ? cryptogram.toString() : "(missing)");
      const eci = json.objectForKey_("eciIndicator");
      console.log("    ECI:", eci ? eci.toString() : "(missing)");
    }
  });
}
```

### 9.2 Google Pay Frida Hook

```javascript
// googlepay_hook.js
// Hook Google Pay's loadPaymentData to inspect the tokenization result

Java.perform(function() {
  const PaymentsClient = Java.use("com.google.android.gms.wallet.PaymentsClient");
  PaymentsClient.loadPaymentData.implementation = function(request) {
    console.log("[+] Google Pay loadPaymentData called");
    const task = this.loadPaymentData(request);
    // Result comes back via OnCompleteListener — hook that separately
    return task;
  };

  // Hook the result handler
  const AutoResolveHelper = Java.use("com.google.android.gms.wallet.AutoResolveHelper");
  // Result is in Intent extras: "com.google.android.gms.wallet.EXTRA_PAYMENT_DATA"
  // Parse PaymentData.getPaymentMethodToken().getToken()
  // → contains a gateway-specific token (e.g., Stripe token)
});
```

### 9.3 Token Lifecycle Sanity Check

```bash
# Apple Pay token fields (paymentData JSON):
# - applicationPrimaryAccountNumber: DAN (tokenized PAN, 16 digits, NOT real PAN)
# - applicationExpirationDate: DAN expiry (different from real card expiry)
# - applicationCryptogram: per-transaction cryptogram
# - paymentDataType: "3DSecure" or "EMV"
# - eciIndicator: "05" (fully authenticated) / "06" (attempted) / "07" (failed)

# Test: confirm the merchant's backend forwards the cryptogram to the gateway
# The gateway verifies the cryptogram with the card network
# Bypass attempt: tamper the cryptogram → gateway rejects with 402
```

---

## 10. EMV Chip & Contactless Testing Patterns

### 10.1 Reading EMV Tags via PC/SC

```bash
# Install tools
sudo apt install pcsc-tools pcscd libccid

# Read card tags via scriptor (APDU scripting)
echo "00A4040007A000000004101000" | scriptor
# Selects Visa application (AID A0000000041010)

# Get Processing Options
echo "80A8000002830000" | scriptor
# Returns application interchange profile + AFL

# Read key tags from card
# Tag 9F26 (AC): Application Cryptogram (must verify with issuer)
# Tag 9F10 (IAD): Issuer Application Data (CVR, CID)
# Tag 9F36 (ATC): Application Transaction Counter (monotonic)
# Tag 95 (TVR): Terminal Verification Results
```

### 10.2 Terminal Configuration Review

| Check | Why It Matters |
|-------|----------------|
| CDA (Combined DDA/AC Gen) enabled | Prevents magstripe-style skimming |
| Online PIN threshold | High-value requires online PIN, not just signature |
| Terminal Action Codes (TAC) | Defines what TVR bits force decline/online |
| Contactless CL-T limit | Per-region limit (€50 EU, $100 US, etc.) |
| MSD vs qVSDC contactless | MSD (legacy magstripe data over NFC) is weaker |
| Relay attack resistance | Distance bounding (rare); at minimum, latency check |

### 10.3 Contactless Relay Test

```bash
# Relay attack: attacker reads victim's card in one location,
# relays the EMV exchange to a terminal in another location via radio
# (e.g., subway gate payment)

# Defense (rare): distance bounding (NFC-T, EMV distance bounding)
# Most terminals DO NOT implement distance bounding

# Test setup (academic — use only on cards you own):
# - Two Proxmark3 / NFC shields
# - One acts as terminal, one as card
# - Measure round-trip latency; if terminal doesn't enforce < 50ms, relay works
```

---

## 11. Fraud System Assessment

### 11.1 Sift Science Sandbox Probing

```bash
# Sandbox API: same endpoint, test API key
# Send synthetic events to map decision boundaries

# Baseline (legitimate-looking)
curl -X POST https://api.sift.com/v205/events \
  -H "Content-Type: application/json" \
  -d "{
    \"\$api_key\": \"$SIFT_SANDBOX_KEY\",
    \"\$user_id\": \"u_baseline\",
    \"\$type\": \"\$create_order\",
    \"\$order_id\": \"o_1\",
    \"\$amount\": 4999,
    \"\$currency_code\": \"USD\",
    \"\$billing_address\": {\"\$country\": \"US\"}
  }"

# Escalating risk signals
curl -X POST https://api.sift.com/v205/events \
  -d "{
    \"\$api_key\": \"$SIFT_SANDBOX_KEY\",
    \"\$user_id\": \"u_baseline\",
    \"\$type\": \"\$create_order\",
    \"\$order_id\": \"o_2\",
    \"\$amount\": 99999999,
    \"\$ip\": \"185.220.101.5\",
    \"\$billing_address\": {\"\$country\": \"RU\"},
    \"\$shipping_address\": {\"\$country\": \"NG\"}
  }"

# Get the score
curl -s "https://api.sift.com/v205/scores/u_baseline?api_key=$SIFT_SANDBOX_KEY" | jq .
# Score 0-100: 0 = benign, 100 = fraudulent
# Compare scores across feature variations to infer feature importance
```

### 11.2 Forter / Riskified Test Mode

```bash
# Forter sandbox: send a transaction, get decision
# (Vendor-specific endpoint; see Forter docs)

# Riskified test mode: send order, get approved/declined/manual-review
# Useful to understand what an attacker can probe without tripping production
```

### 11.3 Custom ML Model Probing

```python
#!/usr/bin/env python3
"""Probe a custom fraud model's decision boundary.

NEVER run this against a production fraud system. Use test/staging only.
"""
import requests

def probe_boundary(base_url: str, token: str, amount: int, country: str) -> dict:
    """Send a synthetic transaction and observe the decision."""
    resp = requests.post(
        f"{base_url}/api/fraud/score",
        headers={"Authorization": f"Bearer {token}"},
        json={"amount": amount, "country": country, "ip": "1.1.1.1"},
        timeout=10,
    )
    return resp.json()

# Map the threshold: at what amount does a US-origin tx get flagged?
for amt in [100, 500, 1000, 5000, 10000, 50000, 100000]:
    result = probe_boundary(STAGING_URL, TOKEN, amount=amt, country="US")
    print(f"${amt}: score={result.get('score')}, decision={result.get('decision')}")
```

---

## 12. PCI-DSS Scope Validation

### 12.1 ASV External Scan

```bash
# PCI-DSS req 11.3.2 — quarterly external scan by ASV
# Use Nessus / Qualys in PCI mode

# Nessus PCI-DSS external scan
nessuscli scan new --template "PCI-DSS External Network" \
  --targets payments.example.com,api.example.com,checkout.example.com \
  --name "Q2 2024 PCI External Scan"

# Qualys WAS PCI template
qualys was launch --template PCI-DSS-External --target payments.example.com
```

### 12.2 Internal CDE Scan

```bash
# PCI-DSS req 11.3.1 — quarterly internal scan
# After fixes, must show no CRITICAL vulnerabilities

nmap -p1-65535 -sV --script vuln 10.0.1.0/24  # CDE subnet
# Capture to file, then triage by severity

# For authenticated internal scans
nessuscli scan new --template "Basic Network Scan" \
  --targets 10.0.1.0/24 \
  --credentials ssh://user:pass@10.0.1.5 \
  --name "PCI Internal Q2"
```

### 12.3 Segmentation Penetration Test

```bash
# PCI-DSS req 11.4 / 12.5.5 — verify segmentation controls
# From out-of-scope system, attempt to reach CDE

# Test from marketing CMS (out-of-scope) to payment gateway (in-scope)
nmap -p1-65535 -sV --reason --traceroute \
  --script=firewalk,broadcast-ping \
  10.0.1.5  # payment gateway

# If ANY port responds, segmentation is broken
# Document the path: marketing-cms → switch → payment-gateway
# Recommend: ACL / firewall rule denying the path
```

---

## 13. Python Pipeline — Stripe Webhook Replay & Card Test Detection

```python
#!/usr/bin/env python3
"""Stripe webhook replay + card testing detector.

Components:
1. Webhook signature validator (rejects replays > 5 min)
2. Card testing detector (clusters declines by IP + velocity)
"""
import hashlib
import hmac
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

# ─── 1. Webhook Signature Verification ───

STRIPE_TOLERANCE_SECONDS = 300  # 5 minutes


def verify_stripe_signature(
    payload: bytes,
    signature_header: str,
    secret: str,
    tolerance: int = STRIPE_TOLERANCE_SECONDS,
) -> bool:
    """Verify Stripe webhook signature; reject stale timestamps (replay protection)."""
    elements = {p.split("=", 1)[0]: p.split("=", 1)[1] for p in signature_header.split(",")}
    timestamp = int(elements.get("t", "0"))
    provided_sig = elements.get("v1", "")

    if abs(time.time() - timestamp) > tolerance:
        return False  # replay

    signed_payload = f"{timestamp}.".encode() + payload
    expected_sig = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected_sig, provided_sig)


# ─── 2. Card Testing Detector ───

class CardTestDetector:
    """Detect card-testing bots by IP velocity + BIN clustering."""

    def __init__(self, window_min: int = 60, ip_threshold: int = 50) -> None:
        self.window_min = window_min
        self.ip_threshold = ip_threshold
        self._ip_declines: dict[str, deque] = defaultdict(deque)
        self._alerts: list[dict[str, Any]] = []

    def record_decline(self, ip: str, ts: datetime | None = None) -> dict[str, Any] | None:
        ts = ts or datetime.utcnow()
        dq = self._ip_declines[ip]
        dq.append(ts)

        cutoff = ts - timedelta(minutes=self.window_min)
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self.ip_threshold:
            alert = {
                "type": "card_testing_suspected",
                "ip": ip,
                "decline_count": len(dq),
                "window_min": self.window_min,
                "ts": ts.isoformat(),
            }
            self._alerts.append(alert)
            return alert
        return None


# ─── Usage ───
if __name__ == "__main__":
    # Webhook check
    secret = "whsec_test_..."
    payload = b'{"id":"evt_test","type":"payment_intent.succeeded"}'
    sig = "t=1700000000,v1=forged"
    assert not verify_stripe_signature(payload, sig, secret), "Should reject stale timestamp"

    # Card test check
    detector = CardTestDetector(window_min=60, ip_threshold=50)
    for _ in range(60):
        alert = detector.record_decline("203.0.113.5")
    assert alert, "Should fire card testing alert"
    print(f"Alert fired: {alert}")
```

---

## 14. Tokenization Review

### 14.1 Network Tokens (Visa Token Service / Mastercard Digital Card)

```
Real PAN (FPAN) ─ network token vault ─ Network Token (TPAN)
                                          │
                                          └── device-bound (lifecycle-managed)
                                              - per-device provisioning
                                              - revocable per device
                                              - re-provisioned on card reissue

Lifecycle:
1. Cardholder adds card to Apple Pay
2. Apple → network (Visa/MC) → token request
3. Network issues TPAN, returns to Apple
4. Apple stores TPAN in Secure Enclave as DAN
5. Per-transaction cryptogram derived from DAN + transaction details
```

### 14.2 Gateway Tokens (Stripe customer / Adyen recurring detail)

```bash
# Stripe: customer object holds a payment method (pm_xxx), never PAN
curl -s https://api.stripe.com/v1/customers/cus_123 \
  -H "Authorization: Bearer $STRIPE_KEY" | jq '.invoice_settings.default_payment_method'
# Returns pm_xxx — token, not PAN

# Adyen: recurringDetail holds a recurringDetailReference
curl -s https://checkout-test.adyen.com/v68/payments \
  -d '{"merchantAccount":"Test","recurring":{"recurringDetailReference":"831442..."}}'
# Uses reference, not PAN
```

### 14.3 Tokenization Vault Review

```
PAN     ──HSM-encrypt──> vault ──token lookup──> token (format-preserved or random)

Review checklist:
- [ ] PAN at rest encrypted with HSM-managed key (PCI req 3.4 / 3.5 / 3.6)
- [ ] Token-to-PAN mapping accessible only via audited service (req 7.1)
- [ ] Key rotation per PCI req 3.6.1 (annually for symmetric keys)
- [ ] Dual control for key access (req 3.6.2 / 3.7)
- [ ] Token cannot be reversed without the vault (not a deterministic hash)
- [ ] PAN never logged (req 3.3 masking + req 10 logging)
```

---

## 15. Quick-Reference Cheat Sheet

```bash
# ─── PCI scope delineation ───
nmap -p1-65535 --script=firewalk --traceroute <out-of-scope> → <cde>
tcpdump -w seg.pcap host <out-of-scope> and host <cde>

# ─── Stripe webhook forward + trigger ───
stripe listen --forward-to localhost:8000/webhooks
stripe trigger payment_intent.succeeded

# ─── Stripe webhook signature check ───
# t=<unix_ts>,v1=<hmac>
# Reject abs(now - t) > 300

# ─── Adyen test cards ───
# 4111 1111 4555 4522 → Refused
# 4111 1111 1111 1111 → Authorized (Visa)
# 5555 4444 3333 1111 → Authorized (Mastercard)

# ─── PayPal sandbox ───
curl -X POST https://api-m.sandbox.paypal.com/v1/oauth2/token \
  -u "$CLIENT_ID:$SECRET" -d "grant_type=client_credentials"

# ─── Apple Pay Frida hook ───
frida -U -f com.example.app -l applepay_hook.js
# Hook: - paymentAuthorizationViewController:didAuthorizePayment:completion:

# ─── Card testing detection ───
# > 50 declines / IP / hour → alert
# Cluster by BIN prefix; flag repeated same-BIN declines

# ─── PCI-DSS 4.0 quick refs ───
# Req 3: protect stored account data (PAN masking, encryption)
# Req 4: protect cryptographic keys (HSM, rotation)
# Req 6: secure dev (pentest annually, vuln scan monthly)
# Req 10: logging & monitoring
# Req 11: testing (wireless, internal/external scans, FIM)
# Req 12: security policy & program

# ─── Fraud system (sandbox only!) ───
curl -X POST https://api.sift.com/v205/events \
  -d '{"\$api_key":"<SANDBOX>","\$type":"\$create_order",...}'

# ─── EMV tags ───
# 9F26 (AC), 9F10 (IAD), 9F36 (ATC), 95 (TVR)
echo "00A4040007A000000004101000" | scriptor
```

---

**Related files**: `SKILL.md`, `test-cases.md`, `guides/payment-pentest-playbook.md`
**PCI SSC**: [pcisecuritystandards.org](https://www.pcisecuritystandards.org) | **Stripe**: [stripe.com/docs/security](https://stripe.com/docs/security) | **EMVCo**: [emvco.com](https://www.emvco.com)
