# OWASP Top 10 2025 - A06: Insecure Design completeguide

## Learning Objectives
Mastercore principles, threat modeling techniques, and secure architecture design of insecure design

---

## 1. Insecure Design Overview

### 1.1 whatisnotSecuritydesign？
notSecuritydesign（Insecure Design）ispointinSystemarchitectureanddesignPhaselack ofSecuritycontrol措implement，cause：
- business logicVulnerability
- lack ofSecuritycontrol
- designdefect
- threat modelingmissing
- least privilegeoriginalthen违anti

### 1.2 anditsotherVulnerability zoneother
- **notisrealnowerror**：andisdesigndefect
- **nomethodThroughcodefixcomplex**：Requires重newdesign
- **impactentireSystem**：notissinglecomponent
- **difficultwithDetection**：RequiresarchitecturelevelAnalysis

---

## 2. Insecure Design Type

### 2.1 business logicVulnerability
**definition**: Systembusinessprocessdesigndefect

**Common Types**:
1. **concurrentracecondition**
 - multipleUsersamewhen Operationresource
 - librarystoresuper卖
 - 积partrepeatUse

2. **Workflowbypass**
 - jumpover审batchprocess
 - bypasspaymentVerification
 - jumpoveridentityVerification

3. **StatusmachineVulnerability**
 - illegalStatustransform
 - repeatStatustransform
 - return退Attack

---

### 2.2 lack ofSecuritycontrol
**definition**: Systemdesigninnot Containsnecessary Securitycontrol

**Example**:
1. **noRate Limiting**
 - API notuneuselimitation
 - loginnofailurelockout
 - 短informationVerificationcodenolimitation

2. **noAccesscontrol**
 - sensitiveFunctionno鉴authority
 - Admin Interfacesnoprotect
 - API nopermissionVerification

3. **noEnterVerification**
 - amountcan as负number
 - when intervalcan 倒flow
 - Countcan as零

---

### 2.3 threat modelingmissing
**definition**: designPhasenot considerthreatScenario

**afterresult**:
- not considerAttackerview角
- missingDefensedeepdegree
- singlepointfaultrisk
- Attack面overlarge

---

## 3. business logicVulnerability Exploitation

### 3.1 concurrentracecondition
**Scenario**: 抢购/seconds杀System

**Vulnerable Code**:
```python
# notSecurity design
@app.route('/buy')
def buy_item():
    item_id = request.args.get('item_id')
    user_id = session['user_id']
    
 # Checklibrarystore
    item = db.query(Item).get(item_id)
    if item.stock <= 0:
        return "Out of stock"
    
 # createorder
    order = Order(user_id=user_id, item_id=item_id)
    db.add(order)
    
 # 扣reducelibrarystore
    item.stock -= 1
    db.commit()
    
    return "Success"
```

**Attack Method**:
```python
# concurrentAttack
import threading
import requests

def buy_item_concurrently():
    for i in range(100):
        threading.Thread(target=requests.get, 
                        args=(f"http://target.com/buy?item_id=1",)).start()

# Result：librarystoreas 1，butcreate 100 order
```

**Fix / Remedy**:
```python
# Security design - Use锁mechanism
from threading import Lock

lock = Lock()

@app.route('/buy')
def buy_item():
    with lock:
        item_id = request.args.get('item_id')
        user_id = session['user_id']
        
 # Checklibrarystore
        item = db.query(Item).get(item_id)
        if item.stock <= 0:
            return "Out of stock"
        
 # createorder
        order = Order(user_id=user_id, item_id=item_id)
        db.add(order)
        
 # 扣reducelibrarystore
        item.stock -= 1
        db.commit()
        
        return "Success"
```

---

### 3.2 Workflowbypass
**Scenario**: orderpaymentprocess

**Vulnerabilityprocess**:
```
1. User下单 → 订单Status：待支付
2. User支付 → 订单Status：已支付
3. 发货 → 订单Status：已发货
```

**Attack Method**:
```python
# directtuneuseshippingInterface
requests.post("http://target.com/api/orders/123/ship")

# jumpoverpaymentSteps，directshipping
```

**Fix / Remedy**:
```python
# Security design - StatusCheck
@app.route('/api/orders/<int:order_id>/ship')
def ship_order(order_id):
    order = db.query(Order).get(order_id)
    
 # CheckorderStatus
    if order.status != 'paid':
        return "Invalid order status", 400
    
 # CheckpaymentStatus
    payment = db.query(Payment).filter_by(order_id=order_id).first()
    if not payment or payment.status != 'success':
        return "Payment not completed", 400
    
 # shipping
    order.status = 'shipped'
    db.commit()
    
    return "Shipped successfully"
```

---

### 3.3 StatusmachineVulnerability
**Scenario**: orderStatustransform

**VulnerabilityStatusmachine**:
```
待支付 → 已支付 → 已发货 → Completed
   ↓         ↓         ↓
 已取消   已取消   已取消
```

**Attack Method**:
```python
# illegalStatustransform
def attack_state_machine(order_id):
 # from"pending payment"directjumpto"Completed"
    requests.patch(f"http://target.com/api/orders/{order_id}", 
                  json={"status": "completed"})
```

**Fix / Remedy**:
```python
# Security design - StatusmachineVerification
VALID_TRANSITIONS = {
    'pending': ['paid', 'cancelled'],
    'paid': ['shipped', 'cancelled'],
    'shipped': ['completed', 'cancelled'],
    'completed': [],
    'cancelled': []
}

@app.route('/api/orders/<int:order_id>', methods=['PATCH'])
def update_order(order_id):
    order = db.query(Order).get(order_id)
    new_status = request.json.get('status')
    
 # VerificationStatustransform
    if new_status not in VALID_TRANSITIONS.get(order.status, []):
        return "Invalid state transition", 400
    
    order.status = new_status
    db.commit()
    
    return "Status updated"
```

---

## 4. lack ofSecuritycontrolExample

### 4.1 noRate Limiting
**Vulnerable Code**:
```python
# nolimitation API
@app.route('/api/send-sms')
def send_sms():
    phone = request.args.get('phone')
    send_sms_code(phone)
    return "SMS sent"
```

**Attack Method**:
```python
# SMS 轰炸
for i in range(1000):
    requests.get("http://target.com/api/send-sms?phone=13800138000")
```

**Fix / Remedy**:
```python
# Security design - Rate Limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/send-sms')
@limiter.limit("1 per minute")  # 限制Everyminutes 1 次
def send_sms():
    phone = request.args.get('phone')
    
 # Checkiswhetheralready send
    cache_key = f"sms:{phone}"
    if cache.get(cache_key):
        return "SMS already sent", 429
    
    send_sms_code(phone)
    cache.set(cache_key, True, timeout=60)
    
    return "SMS sent"
```

---

### 4.2 noEnterVerification
**Vulnerable Code**:
```python
# noVerification transfer
@app.route('/api/transfer')
def transfer():
    from_account = request.args.get('from')
    to_account = request.args.get('to')
    amount = float(request.args.get('amount'))
    
 # directtransfer
    transfer_money(from_account, to_account, amount)
    return "Transfer successful"
```

**Attack Method**:
```python
# 负numberamountAttack
requests.get("http://target.com/api/transfer?from=123&to=456&amount=-1000")

# Result：转outputaccountIncrease 1000，转inputaccountreduce 1000
```

**Fix / Remedy**:
```python
# Security design - EnterVerification
from decimal import Decimal

@app.route('/api/transfer')
def transfer():
    from_account = request.args.get('from')
    to_account = request.args.get('to')
    
    try:
        amount = Decimal(request.args.get('amount'))
    except:
        return "Invalid amount", 400
    
 # Verificationamount
    if amount <= 0:
        return "Amount must be positive", 400
    
    if amount > MAX_TRANSFER_AMOUNT:
        return "Amount exceeds limit", 400
    
 # Verificationaccountall authority
    if not is_account_owner(from_account, session['user_id']):
        return "Unauthorized", 403
    
 # transfer
    transfer_money(from_account, to_account, amount)
    return "Transfer successful"
```

---

## 5. threat modelingTechniques

### 5.1 STRIDE threatmodetype
**partclass**:
- **S**poofing（spoofing）: 冒chargeotherpersonidentity
- **T**ampering（tamper）: modifyData
- **R**epudiation（抵赖）: whether认Operation
- **I**nformation Disclosure（informationleakage）: leakagesensitiveData
- **D**enial of Service（denial of service）: destroycan useity
- **E**levation of Privilege（Privilege Escalation）: obtainmorehighpermission

### 5.2 threat modelingprocess
```
1. 识别资产
2. 创建架构图
3. 分解Application
4. 识别威胁
5. 评估风险
6. 设计缓解措施
```

---

## 6. automated Detection Tools

```python
#!/usr/bin/env python3
"""
Insecure Design 自动化Detection Tools
Detection业务逻辑Vulnerability和设计缺陷
"""

import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor

class InsecureDesignScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan_all(self):
        """执行所有Scanning"""
        print("\n" + "="*60)
        print("开始 Insecure Design 全面Scanning")
        print("="*60)
        
 # 1. business logicVulnerability Scanning
        print("\n[1] 业务逻辑Vulnerability Scanning...")
        self.scan_business_logic()
        
 # 2. Rate LimitingDetection
        print("\n[2] Rate LimitingDetection...")
        self.scan_rate_limiting()
        
 # 3. StatusmachineVulnerabilityDetection
        print("\n[3] Status机VulnerabilityDetection...")
        self.scan_state_machine()
        
 # GenerationReport
        self.generate_report()
        
        return self.vulnerabilities
    
    def scan_business_logic(self):
        """Scanning业务逻辑Vulnerability"""
 # concurrentraceconditionTest
        print("    [*] Test并发竞争条件...")
        self.test_race_condition()
        
 # WorkflowbypassTest
        print("    [*] TestWorkflow绕过...")
        self.test_workflow_bypass()
    
    def test_race_condition(self):
        """Test并发竞争条件"""
        url = f"{self.base_url}/api/buy"
        
 # concurrentRequest
        def send_request():
            try:
                r = self.session.post(url, json={"item_id": 1}, timeout=5)
                return r.status_code
            except:
                return None
        
 # send 100 concurrentRequest
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(send_request) for _ in range(100)]
            results = [f.result() for f in futures if f.result() == 200]
        
 # such as resultsuccesstimenumber > 1，existsracecondition
        if len(results) > 1:
            self.vulnerabilities.append({
                'type': 'Race Condition',
                'url': url,
                'successful_requests': len(results),
                'severity': 'High'
            })
            print(f"    [+] Discovery竞争条件Vulnerability: {len(results)} 个成功Request")
    
    def test_workflow_bypass(self):
        """TestWorkflow绕过"""
 # TestorderStatusjumpover
        workflow_urls = [
            f"{self.base_url}/api/orders/1/ship",
            f"{self.base_url}/api/orders/1/complete",
        ]
        
        for url in workflow_urls:
            try:
                r = self.session.post(url, timeout=5)
                
                if r.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'Workflow Bypass',
                        'url': url,
                        'severity': 'High'
                    })
                    print(f"    [+] DiscoveryWorkflow绕过: {url}")
            
            except Exception as e:
                pass
    
    def scan_rate_limiting(self):
        """ScanningRate Limiting"""
        url = f"{self.base_url}/api/send-sms"
        
 # send 100 Request
        for i in range(100):
            try:
                r = self.session.get(f"{url}?phone=13800138000", timeout=5)
                
 # such as resultall Requestallsuccess，missingRate Limiting
                if r.status_code == 200 and i == 99:
                    self.vulnerabilities.append({
                        'type': 'Missing Rate Limiting',
                        'url': url,
                        'requests': 100,
                        'severity': 'Medium'
                    })
                    print(f"    [+] 缺少Rate Limiting: {url}")
            
            except Exception as e:
                break
    
    def scan_state_machine(self):
        """ScanningStatus机Vulnerability"""
 # TestillegalStatustransform
 # 简izerealnow
        pass
    
    def generate_report(self):
        """GenerationScanningReport"""
        print("\n" + "="*60)
        print(f"ScanningComplete - Discovery {len(self.vulnerabilities)} 个问题")
        print("="*60)


def main():
    """主函数"""
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║     Insecure Design Automated ScanningTool                 ║
    ║             OWASP A06:2025                         ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    base_url = input("请EnterTarget URL: ").strip()
    
    if not base_url:
        print("[-] ❌ 必须ProvidesTarget URL")
        return
    
    scanner = InsecureDesignScanner(base_url)
    scanner.scan_all()


if __name__ == "__main__":
    main()
```

---

## 7. Learning Checklist

### Theory Mastery
- [x] understand Insecure Design concept
- [x] Masterbusiness logicVulnerability
- [x] Masterthreat modelingTechniques
- [x] understandSecurityarchitecturedesign

### Practical Skills
- [x] concurrentraceconditionexploit
- [x] WorkflowbypassAttack
- [x] StatusmachineVulnerability Exploitation
- [x] automated Detection Tools

### Defense Capabilities
- [x] business logicSecuritydesign
- [x] StatusmachineVerification
- [x] Rate Limitingrealnow
- [x] EnterVerificationdesign

---

**Document Version**: 1.0
**Created**: 2026-03-26 18:58
**Learningwhen length**: estimated 4-5 Hours
**Learning Status**: 🟢 Complete
