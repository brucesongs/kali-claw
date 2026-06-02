# Dark Web Intelligence Collection Guide

## Introduction

Dark web intelligence gathering monitors underground forums, marketplaces, and paste sites for leaked credentials, breach data, threat actor chatter, and emerging threats targeting your organization. This guide covers safe access, collection methodology, and analysis techniques.

## Practical Steps

### 1. Safe Access Setup

```bash
# Install Tor with security-focused configuration
sudo apt install tor torbrowser-launcher

# Configure Tor for operational security
cat >> /etc/tor/torrc << 'EOF'
SocksPort 9050
SocksPort 9051
ControlPort 9052
HashedControlPassword [hashed-password]
AvoidDiskWrites 1
EOF

# Verify Tor circuit
torsocks curl -s https://check.torproject.org/api/ip
```

**Operational Security Checklist:**
- Use a dedicated VM or container — never browse from your host
- Route all traffic through Tor — no accidental clearnet leaks
- Disable JavaScript in Tor Browser (Security Level: Safest)
- Never use personal accounts or real identities
- Use separate identities for different operations

### 2. Source Monitoring

**Paste Sites:**
```python
import requests
import re
from datetime import datetime

PASTE_SOURCES = [
    "https://pastebin.com/raw/{id}",
    "https://paste.ee/r/{id}",
]

KEYWORDS = ["@target.com", "targetcorp", "internal.target.com"]

def monitor_pastes(keywords, session=None):
    """Check paste sites for organization-related leaks."""
    findings = []
    for source in PASTE_SOURCES:
        for paste_id in get_recent_pastes(source):
            content = fetch_paste(source, paste_id)
            for kw in keywords:
                if kw.lower() in content.lower():
                    findings.append({
                        "source": source,
                        "id": paste_id,
                        "keyword": kw,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
    return findings
```

### 3. Credential Leak Monitoring

```bash
# Search breach databases for corporate email patterns
# Using hibp-style API (authorized access only)
curl -s -H "hibp-api-key: $HIBP_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/test@target.com"

# Check for domain appearances in breach data
curl -s "https://haveibeenpwned.com/api/v3/breachdomain/target.com"
```

### 4. Forum Intelligence

```python
def analyze_forum_post(post, org_keywords):
    """Extract actionable intelligence from forum posts."""
    indicators = {
        "mentions_org": any(kw in post["content"].lower()
                           for kw in org_keywords),
        "has_credentials": bool(re.search(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\S+',
            post["content"]
        )),
        "has_internal_refs": bool(re.search(
            r'10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|internal\.',
            post["content"]
        )),
        "threat_level": classify_threat(post["content"]),
    }
    return indicators
```

### 5. Data Analysis and Reporting

```python
def generate_intel_report(findings):
    """Produce structured intelligence report."""
    return {
        "summary": {
            "total_findings": len(findings),
            "credential_leaks": sum(1 for f in findings if f["type"] == "cred"),
            "internal_exposure": sum(1 for f in findings if f["type"] == "internal"),
            "threat_mentions": sum(1 for f in findings if f["type"] == "threat"),
        },
        "critical": [f for f in findings if f.get("severity") == "critical"],
        "recommendations": generate_recs(findings),
    }
```

## References

- [Tor Project — Official Documentation](https://www.torproject.org/docs/documentation.html)
- [OWASP — OSINT Guide](https://owasp.org/www-community/attacks/Open_Source_Intelligence_(OSINT))
- [MITRE — Collection Technique](https://attack.mitre.org/tactics/TA0042/)
- [First — Threat Intelligence Sharing](https://www.first.org/global/sigs/ti/)
