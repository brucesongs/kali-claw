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
