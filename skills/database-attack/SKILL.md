---
name: database-attack
description: "Direct attacks against database servers at the protocol level — distinct from web-based SQL injection (covered by web-sqli). This skill targets database listeners, authentication mechanisms, stored procedures, and protocol-level misconfigurations."
origin: openclaw
version: "0.1.19"
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
  domain: database
  tool_count: 8
  guide_count: 5
  mitre: "TA0006-Credential Access"
---

# Database Attack

> **Supplementary Files**:
> - `payloads.md` — Attack payloads organized by database type: Oracle, MySQL/MariaDB, PostgreSQL, MSSQL/Sybase, Redis, MongoDB, and multi-protocol brute force
> - `test-cases.md` — Structured test case templates (8 cases covering enumeration, exploitation, brute-force, and post-exploitation across 6 database types)
> - `guides/oracle-database-attack.md` — Oracle database attack deep dive: TNS listener, odat exploitation, privilege escalation
> - `guides/redis-mongodb-unauth.md` — Redis and MongoDB unauthenticated access, misconfiguration exploitation, and data exfiltration
> - `guides/database-bruteforce.md` — Database protocol brute-forcing with hydra, ncrack, and patator

## Summary

This skill targets database listeners, authentication mechanisms, stored procedures, and protocol-level misconfigurations.

**Tools**: odat, oscanner, sqsh, redis-tools, mongoaudit, patator, ncrack, hydra

**Domain**: database

**MITRE ATT&CK**: TA0006-Credential Access

## Description

Direct attacks against database servers at the protocol level — distinct from web-based SQL injection (covered by web-sqli). This skill targets database listeners, authentication mechanisms, stored procedures, and protocol-level misconfigurations. Covers Oracle TNS, MySQL, PostgreSQL, MSSQL/Sybase, Redis, and MongoDB.

While web-sqli exploits application-layer vulnerabilities to inject SQL through HTTP, this skill attacks the database server directly: brute-forcing credentials over the wire, exploiting default configurations, abusing stored procedures for OS command execution, and exfiltrating data through native database protocols.

## Use Cases

1. **Database server enumeration** — Discover database listeners on the network, fingerprint DBMS type and version, identify running services and configuration weaknesses
2. **Authentication brute-force** — Test database credentials against Oracle TNS, MySQL, PostgreSQL, MSSQL, and other database protocols using targeted wordlists
3. **Oracle exploitation** — Exploit Oracle TNS listener misconfigurations, leverage odat for SID enumeration, credential extraction, file read/write, and OS command execution
4. **NoSQL misconfiguration abuse** — Exploit unauthenticated Redis and MongoDB instances, read/write files, execute Lua scripts, exfiltrate data
5. **MSSQL post-authentication exploitation** — Leverage xp_cmdshell and stored procedures for OS command execution after gaining database credentials
6. **PostgreSQL privilege escalation** — Exploit misconfigured roles, abuse COPY/lo_import for file access, leverage PL/Python or PL/Perl for code execution

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **odat** | Oracle database attack toolkit — SID guessing, credential brute-force, file read/write, OS command exec | `odat all -s 192.168.1.100 -d ORCL` |
| **oscanner** | Oracle TNS listener scanning and enumeration | `oscanner -s 192.168.1.100` |
| **sqsh** | Sybase/MSSQL interactive shell with command pipelining | `sqsh -S 192.168.1.100 -U sa -P ''` |
| **redis-tools** | Redis CLI client for unauthenticated access and exploitation | `redis-cli -h 192.168.1.100 INFO` |
| **mongoaudit** | MongoDB security auditing tool for misconfiguration detection | `mongoaudit -h 192.168.1.100 -p 27017` |
| **patator** | Multi-protocol brute-forcer with modular design | `patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1` |
| **ncrack** | High-speed network authentication cracking (SSH/RDP/database protocols) | `ncrack -p 3306 192.168.1.100 -u root -P passwords.txt` |
| **hydra** | Online brute-force supporting 50+ protocols including database modules | `hydra -l root -P passwords.txt mysql://192.168.1.100` |

## Methodology

### Attack Chain

```
Recon & Discovery → Service Enumeration → Authentication Testing → Exploitation → Post-Exploitation
   (nmap/oscanner)    (odat/SID guess)     (hydra/ncrack/patator)   (odat/sqsh)     (xp_cmdshell/file ops)
```

**Phase 1: Recon and Discovery**

- Port scan common database ports: Oracle (1521), MySQL (3306), PostgreSQL (5432), MSSQL (1433), Redis (6379), MongoDB (27017)
- Identify database type and version via banner grabbing or protocol probing
- Detect default or misconfigured instances (empty passwords, anonymous access)

**Phase 2: Service Enumeration**

- Oracle: enumerate SIDs with odat, scan TNS listener with oscanner, identify valid database names
- MSSQL/Sybase: enumerate databases and server properties with sqsh
- Redis: test unauthenticated access with redis-cli, enumerate keys and configuration
- MongoDB: test unauthenticated access, enumerate databases and collections with mongoaudit

**Phase 3: Authentication Testing**

- Brute-force database credentials with hydra, ncrack, or patator
- Test default credentials: Oracle (sys/change_on_install), MySQL (root/empty), MSSQL (sa/empty), PostgreSQL (postgres/postgres)
- Use database-specific wordlists and username patterns (dba, admin, backup, replication)

**Phase 4: Exploitation**

- Oracle: exploit with odat — read/write files via UTL_FILE, execute OS commands via DBMS_SCHEDULER, extract credentials from DB links
- MSSQL: enable and use xp_cmdshell for OS command execution, extract hashes from sys.sql_logins
- PostgreSQL: abuse COPY for file read, exploit PL/Python/PL/Perl for code execution, use lo_import for binary file access
- Redis: write SSH authorized_keys or web shells via CONFIG SET dir/dbfilename, load malicious modules
- MongoDB: exploit NoSQL injection, abuse eval/MapReduce for code execution

**Phase 5: Post-Exploitation**

- Extract all credentials and hashes from database system tables
- Pivot to other database instances using discovered DB links or replication credentials
- Establish persistence via database jobs, triggers, or stored procedures
- Cover tracks by purging audit logs and database logs

### Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| Network segmentation | Database servers on isolated VLANs, no direct internet access | CRITICAL |
| Strong authentication | Enforce password policies, disable default accounts, use multi-factor where supported | CRITICAL |
| Encryption in transit | TLS for all database connections, disable plaintext protocols | HIGH |
| Least privilege roles | Application accounts with minimal required permissions, no DBA privileges | HIGH |
| Disable dangerous features | Turn off xp_cmdshell, disable UTL_FILE, restrict DBMS_SCHEDULER | HIGH |
| Audit logging | Enable and monitor database audit logs for brute-force attempts | MEDIUM |
| Intrusion detection | Network IDS rules for known database attack patterns | MEDIUM |

## Practical Steps

> **See payloads.md for detailed commands, and test-cases.md for complete test checklists.** Below is a summary of core operations at each stage.

### Step 1: Discover and Fingerprint Database Services

```bash
# Scan common database ports
nmap -sV -p 1521,3306,5432,1433,6379,27017 192.168.1.0/24

# Oracle-specific scan with oscanner
oscanner -s 192.168.1.100

# Quick Redis unauthenticated access test
redis-cli -h 192.168.1.100 INFO server

# MongoDB connection test
mongo --host 192.168.1.100 --port 27017 --eval "db.adminCommand('listDatabases')"
```

### Step 2: Enumerate and Test Authentication

```bash
# Oracle SID enumeration with odat
odat sidguesser -s 192.168.1.100 -p 1521

# Oracle password brute-force
odat passwordguesser -s 192.168.1.100 -d ORCL

# MySQL brute-force with hydra
hydra -L users.txt -P passwords.txt mysql://192.168.1.100

# MSSQL connection test with sqsh (empty sa password)
sqsh -S 192.168.1.100 -U sa -P '' -C "SELECT @@version"
```

### Step 3: Exploit and Escalate

```bash
# Oracle full exploitation with odat
odat all -s 192.168.1.100 -d ORCL -U sys -P change_on_install

# MSSQL OS command execution via xp_cmdshell
sqsh -S 192.168.1.100 -U sa -P password -C "xp_cmdshell 'whoami'"

# Redis write SSH authorized_keys
redis-cli -h 192.168.1.100 CONFIG SET dir /root/.ssh
redis-cli -h 192.168.1.100 CONFIG SET dbfilename authorized_keys
```

## Common Pitfalls

- Attempting to brute-force database accounts without checking for lockout policies first — can cause denial of service
- Ignoring Oracle SID enumeration — without the correct SID, no Oracle exploitation is possible
- Treating Redis and MongoDB as authenticated services — many deployments run with no authentication by design
- Forgetting to check for database links and replication channels — these are lateral movement paths
- Running aggressive brute-force against production databases — use low thread counts and extended delays
- Overlooking database file permissions — SQLite databases, MySQL data files, and PostgreSQL data directories may be readable by the OS user

## Integration with Other Skills

- **web-sqli**: SQL injection through web applications — database-attack complements this by attacking the DB server directly
- **password-attack**: Generic brute-force techniques — database-attack specializes in database protocol brute-force with DB-specific defaults
- **post-exploitation**: Credential harvesting and lateral movement using database access
- **network-pentest**: Database service discovery during network enumeration
- **privilege-escalation**: Using database access to escalate OS-level privileges

## Legal and Ethical Considerations

Direct database attacks carry severe legal risk — database servers often contain regulated data (PII, financial records, health information). Always confirm database attacks are within authorized scope. Brute-force attacks against production databases risk account lockouts and performance degradation. Data exfiltration must be minimized and documented; extract only enough to prove the vulnerability exists. Destroy all extracted data after the engagement unless retention is explicitly authorized.

## Database Attack Categories

Database attacks can be classified into five major categories based on the attack vector and the layer being targeted:

1. **Protocol-Level Attacks** — Direct interaction with database listeners over their native wire protocols (TNS for Oracle, MySQL protocol, PostgreSQL wire protocol, TDS for MSSQL). These attacks bypass application-layer defenses entirely and target authentication, configuration, and service enumeration.

2. **Authentication Attacks** — Brute-forcing credentials, testing default accounts, exploiting weak password policies, and abusing trust-based authentication (PostgreSQL `pg_hba.conf` trust entries, MySQL empty root passwords, Redis no-auth deployments). Authentication attacks are often the first successful vector against database servers.

3. **Privilege Escalation** — After gaining initial database access with a low-privilege account, attackers escalate through SQL injection in stored procedures, exploiting public package grants (Oracle DBMS_SCHEDULER), abusing GRANT OPTION chains, and leveraging misconfigured role hierarchies. Many databases ship with privilege escalation paths built into their default configurations.

4. **Data Exfiltration** — Extracting data through database-native export tools (mysqldump, pg_dump, mongoexport), file read capabilities (LOAD_FILE, COPY, UTL_FILE), and covert channels like DNS tunneling from within stored procedures. The goal is to prove access to sensitive data while minimizing forensic footprint.

5. **Post-Exploitation** — Using database access as a pivot point: executing OS commands via xp_cmdshell, PL/Python, DBMS_SCHEDULER; writing files for persistence (SSH keys, cron jobs, web shells); and harvesting credentials from database links and replication configurations for lateral movement.

## Credential Harvesting from Databases

Database servers are credential goldmines in enterprise environments. They store credentials for applications, other databases, and external services in multiple locations:

**Direct Credential Storage**:
- MySQL: `mysql.user` table stores authentication strings (SHA256 or caching_sha2_password)
- PostgreSQL: `pg_authid` catalog stores role passwords
- MSSQL: `sys.sql_logins` stores password hashes (SHA-512 with salt since SQL Server 2012)
- Oracle: `SYS.USER$` table stores password hashes (DES-based and SHA-256)

**Embedded Credentials**:
- Database links (Oracle DB_LINKS, MSSQL Linked Servers) contain cleartext or hashed credentials for remote database instances
- Application connection strings stored in configuration tables
- SSIS packages, stored procedures, and agent jobs often embed credentials
- Replication configurations contain distributor and subscriber credentials

**Harvesting Commands**:

```bash
# MySQL credential extraction
mysql -u root -e "SELECT user, host, authentication_string FROM mysql.user"

# PostgreSQL credential extraction
psql -U postgres -c "SELECT rolname, rolpassword FROM pg_authid WHERE rolpassword IS NOT NULL"

# MSSQL credential extraction
sqsh -S target -U sa -C "SELECT name, password_hash FROM sys.sql_logins"

# Oracle credential extraction via odat
odat passwordstealer -s 192.168.1.100 -d ORCL -U sys -P password
```

**Cracking Database Hashes**:
- MySQL 5.x+: hashcat mode 300 (SHA1), mode 3000 (LM)
- MSSQL 2012+: hashcat mode 1731 (SHA-512)
- PostgreSQL MD5: hashcat mode 11 (or custom mode with `md5` prefix)
- Oracle 11g+: hashcat mode 112 (Oracle 11g)

## Data Exfiltration Techniques

Extracting data from compromised databases requires different approaches depending on the database type, available privileges, and network restrictions:

**Bulk Export Tools**: Use native database export tools for maximum efficiency — `mysqldump` for MySQL, `pg_dump` for PostgreSQL, `mongoexport`/`mongodump` for MongoDB, `expdp` for Oracle. These tools handle character encoding, binary data, and schema relationships automatically.

**Targeted Extraction**: When bulk export is too noisy or time-consuming, extract specific high-value data: user tables, credit card columns, PII fields, authentication tokens. Use `SELECT INTO OUTFILE` (MySQL), `COPY TO` (PostgreSQL), or scripted extraction through query interfaces.

**Covert Exfiltration Channels**: When network monitoring blocks direct data transfer, use covert channels: encoding data into DNS queries via stored procedures, writing data to files accessible through web servers, using database replication to copy data to attacker-controlled replicas, or leveraging database backup mechanisms to exfiltrate through scheduled backup jobs.

**Anti-Forensic Considerations**: Minimize audit trail by understanding what the target database logs: MySQL general_log and slow_query_log, PostgreSQL pg_stat_activity and custom audit extensions, Oracle unified auditing, MSSQL SQL Server Audit. Avoid SELECT * in favor of targeted column extraction to reduce log verbosity.

## Database Hardening Checklist

| Category | Control | Priority |
|----------|---------|----------|
| **Network** | Database on isolated VLAN with no internet access | CRITICAL |
| **Network** | Firewall rules restricting source IPs to application servers | CRITICAL |
| **Network** | TLS encryption for all connections | HIGH |
| **Authentication** | Strong password policies enforced | CRITICAL |
| **Authentication** | All default accounts disabled or removed | CRITICAL |
| **Authentication** | Multi-factor authentication for DBA access | HIGH |
| **Authentication** | Account lockout after N failed attempts | HIGH |
| **Authorization** | Least-privilege role assignments | HIGH |
| **Authorization** | No application accounts with DBA/superuser privileges | HIGH |
| **Authorization** | Regular access reviews and certification | MEDIUM |
| **Configuration** | Dangerous features disabled (xp_cmdshell, UTL_FILE, DBMS_SCHEDULER) | HIGH |
| **Configuration** | File system access restricted to database data directories only | HIGH |
| **Configuration** | Module loading disabled | HIGH |
| **Audit** | Comprehensive audit logging enabled | HIGH |
| **Audit** | Real-time alerting on privilege escalation events | MEDIUM |
| **Audit** | Regular log review and anomaly detection | MEDIUM |
| **Patching** | Database server patched within 30 days of critical CVE | CRITICAL |
| **Patching** | Quarterly patch assessment for non-critical updates | MEDIUM |
| **Backup** | Encrypted backups with tested restore procedures | HIGH |
| **Monitoring** | Database activity monitoring (DAM) solution deployed | MEDIUM |

## Privilege Escalation in Databases

Database privilege escalation follows distinct paths depending on the DBMS:

**MySQL Privilege Escalation**:
1. Check `SHOW GRANTS FOR CURRENT_USER()` for available privileges
2. If `FILE` privilege: read/write OS files via `LOAD_FILE()` and `INTO OUTFILE`
3. If `GRANT OPTION`: escalate other users or create new admin accounts
4. If `SUPER` privilege: load custom UDF libraries for OS command execution
5. If `CREATE ROUTINE` with `EXECUTE`: create SUID routines that execute with definer privileges

**PostgreSQL Privilege Escalation**:
1. Check `pg_roles` for role attributes (`SUPERUSER`, `CREATEROLE`, `CREATEDB`)
2. If `CREATEROLE`: create a superuser account directly
3. If `CREATE EXTENSION`: load `plpython3u` or `plperlu` for code execution
4. If superuser: `COPY TO PROGRAM` for OS command execution
5. Large object functions (`lo_import`, `lo_export`) for file system access

**MSSQL Privilege Escalation**:
1. Check `IS_SRVROLEMEMBER('sysadmin')` and `IS_MEMBER('db_owner')`
2. If `db_owner` on a database: create stored procedures with `EXECUTE AS OWNER`
3. If `IMPERSONATE` permission: use `EXECUTE AS LOGIN` to elevate
4. If `sysadmin`: enable `xp_cmdshell` for direct OS command execution
5. Abuse `OPENROWSET` and `OPENDATASOURCE` for cross-server queries with delegated credentials

**Oracle Privilege Escalation**:
1. Query `DBA_SYS_PRIVS` and `SESSION_PRIVS` for current privilege set
2. Exploit `PUBLIC` grants on packages like `DBMS_SCHEDULER`, `UTL_FILE`
3. SQL injection in Oracle-supplied PL/SQL packages (version-specific CVEs)
4. `CREATE ANY PROCEDURE` privilege allows executing code in SYS schema
5. Database link escalation: traverse DB links to reach higher-privilege instances

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Guides**: `guides/oracle-database-attack.md`, `guides/redis-mongodb-unauth.md`, `guides/database-bruteforce.md`, `guides/nosql-attack-guide.md`, `guides/database-lateral-movement-guide.md`
- **Related skills**: `skills/web-sqli/SKILL.md`, `skills/password-attack/SKILL.md`
- **odat GitHub**: [github.com/quentinhardy/odat](https://github.com/quentinhardy/odat)
- **HackTricks - Databases**: [book.hacktricks.xyz/network-services-pentesting](https://book.hacktricks.xyz/network-services-pentesting)
- **Redis Security**: [redis.io/topics/security](https://redis.io/topics/security)
- **MongoDB Security Checklist**: [mongodb.com/docs/manual/administration/security-checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)
