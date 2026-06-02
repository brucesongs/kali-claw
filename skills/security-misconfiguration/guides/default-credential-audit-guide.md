# Default Credential Audit Guide

## Introduction

Default credentials remain one of the most exploited attack vectors. Administrators frequently deploy services without changing factory credentials, creating easy entry points. This guide covers methodology for auditing default credentials across network services, web applications, and IoT devices.

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

## References

- [Default Password Database (CIRT.net)](https://cirt.net/passwords)
- [SecLists — Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
