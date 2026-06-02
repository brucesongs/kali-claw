# Corporate Reconnaissance Techniques Guide

## Introduction

Corporate reconnaissance maps an organization's digital footprint: domains, subdomains, IP ranges, employee profiles, technology stack, and business relationships. This guide covers passive and semi-passive techniques for building comprehensive target profiles.

## Practical Steps

### 1. Domain and Subdomain Enumeration

```bash
# Passive subdomain enumeration via certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u > subdomains.txt

# DNS brute force with resolved IPs
subfinder -d target.com -silent | \
  httpx -silent -status-code -title -tech-detect | \
  column -t -s' '

# Reverse DNS on known IP ranges
for ip in $(seq 1 254); do
  host 10.0.1.$ip 2>/dev/null | grep "domain name pointer"
done
```

### 2. Technology Fingerprinting

```bash
# Web technology detection
whatweb -v https://target.com

# Wappali CLI for bulk detection
wappalyzer https://target.com | jq '.technologies[].name'

# Header analysis for security posture
curl -sI https://target.com | grep -iE \
  "server:|x-powered-by:|x-frame|x-content|strict-transport|content-security"
```

### 3. Employee and Role Mapping

```python
# LinkedIn-derived org chart (OSINT, no scraping)
ROLE_KEYWORDS = [
    "IT Administrator", "DevOps Engineer", "Security Analyst",
    "System Administrator", "Network Engineer", "CTO", "CISO",
]

def build_org_profile(employees):
    """Map key personnel and their technology exposure."""
    profiles = []
    for emp in employees:
        role_tech_map = infer_tech_stack(emp.get("role", ""))
        profiles.append({
            "name": emp["name"],
            "role": emp["role"],
            "likely_access": role_tech_map,
            "social_accounts": find_social_handles(emp["name"]),
        })
    return profiles
```

### 4. Business Relationship Mapping

```bash
# Third-party and vendor discovery
# Check DNS MX records for email providers
dig +short target.com MX

# SPF records reveal authorized senders (often third-party)
dig +short target.com TXT | grep spf

# Analyze TLS certificates for related domains
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

### 5. Data Aggregation Template

```python
RECON_TEMPLATE = {
    "organization": "target.com",
    "domains": [],
    "subdomains": {"count": 0, "live": [], "technologies": {}},
    "ip_ranges": [],
    "email_patterns": "{first}.{last}@target.com",
    "key_personnel": [],
    "tech_stack": {"frontend": [], "backend": [], "infrastructure": []},
    "third_parties": [],
    "security_posture": {
        "spf": False, "dmarc": False, "dkim": False,
        "security_headers": {}, "csp_domains": [],
    },
}
```

### 6. Code Repository Discovery

```bash
# Find organization's public repositories
github-dorks -u targetorg -o results.txt

# Search for leaked secrets in repos
trufflehog github --org=targetorg --only-verified

# Find related repositories by email domain
curl -s "https://api.github.com/search/users?q=target.com+in:email" | \
  jq '.items[].login'
```

## References

- [OWASP — Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [MITRE — Reconnaissance Tactics](https://attack.mitre.org/tactics/TA0043/)
- [Subfinder Documentation](https://github.com/projectdiscovery/subfinder)
- [crt.sh — Certificate Transparency](https://crt.sh/)
