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
- Use a dedicated VM or container -- never browse from your host
- Route all traffic through Tor -- no accidental clearnet leaks
- Disable JavaScript in Tor Browser (Security Level: Safest)
- Never use personal accounts or real identities
- Use separate identities for different operations

## Tor Setup and Safety

### Dedicated Research Environment

```bash
# Create an isolated Tor research VM using Docker
docker run -d --name tor-research \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -v tor-data:/var/lib/tor \
  -p 9050:9050 \
  -p 9052:9052 \
  gold/tor-gateway

# Verify all traffic routes through Tor container
docker exec tor-research curl -s https://check.torproject.org/api/ip | jq '.IsTor'
# Must return: true
```

### Multi-Hop Tor Configuration

For sensitive research, configure Tor to use entry guards in specific jurisdictions and route through multiple circuits:

```bash
# Configure strict entry nodes for enhanced isolation
cat >> /etc/tor/torrc << 'EOF'
# Use specific entry guards
EntryNodes {us},{de},{nl}
ExitNodes {ch},{ro},{se}
StrictNodes 1

# Rotate circuits frequently for high-risk operations
NewCircuitPeriod 120
MaxCircuitDirtiness 300

# Disable features that could leak information
AllowSingleHopCircuits 0
DisableDebuggerAttachment 1
EOF
```

### Identity Management

Maintain separate operational identities for different research activities:

```python
class ResearchIdentity:
    """Manage distinct research identities with compartmentalized state."""

    def __init__(self, identity_name, purpose):
        self.name = identity_name
        self.purpose = purpose
        self.tor_port = allocate_unique_port()
        self.created = datetime.utcnow()
        self.bookmarks = []
        self.cookies = None
        self.session_history = []

    def rotate_identity(self):
        """Signal newnym to get a fresh Tor circuit."""
        import stem
        from stem import Signal
        from stem.control import Controller

        with Controller.from_port(port=9052) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
```

### Leak Prevention Verification

```bash
# Comprehensive leak check script
torsocks curl -s https://ipleak.net/json/ | jq '{
  ip: .ip,
  country: .country,
  dns: .dns
}'

# Check for DNS leaks
torsocks dig @resolver1.opendns.com myip.opendns.com +short

# Verify WebRTC is not leaking real IP (test in browser)
# about:webrtc in Tor Browser should show no local candidates

# Test for accidental clearnet exposure
timeout 10 tcpdump -i any 'not (dst port 9050 or src port 9050)' -c 5 2>/dev/null
# Any packets captured indicate potential leaks
```

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

## Dark Web Search Engines

### Primary Search Platforms

Dark web search engines index .onion services and provide keyword-based discovery without directly browsing dangerous sites:

```python
DARK_WEB_SEARCH_ENGINES = {
    "ahmia": {
        "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
        "clearnet_api": "https://ahmia.fi/search/",
        "supports": "keyword search, .onion discovery",
    },
    "torch": {
        "url": "http://xmh57jrzrnw6insl.onion",
        "supports": "keyword search, broad .onion index",
    },
    "notevil": {
        "url": "http://hss3uro2hsxfogfq.onion",
        "supports": "keyword search with filtering",
    },
    "darksearch": {
        "url": "https://darksearch.io/api/search",
        "supports": "API access, automated queries",
        "clearnet_api": True,
    },
}

def search_dark_web(query, engines=None):
    """Search multiple dark web search engines for a query."""
    engines = engines or list(DARK_WEB_SEARCH_ENGINES.keys())
    results = []

    for engine_name in engines:
        engine = DARK_WEB_SEARCH_ENGINES[engine_name]
        try:
            response = tor_request(f"{engine['url']}?q={query}")
            parsed = parse_search_results(response, engine_name)
            results.extend(parsed)
        except Exception as e:
            log_error(f"Search engine {engine_name} failed: {e}")

    return deduplicate_results(results)
```

### Onion Service Discovery

```bash
# Discover .onion services related to target keywords
torsocks curl -s "https://ahmia.fi/search/?q=target+corp+leak" | \
  grep -oP 'http[s]?://[a-z2-7]{16}\.onion[^\s"]*' | sort -u

# Build a directory of relevant onion services
cat << 'EOF' > onion_directory.txt
# Marketplaces
http://example1.onion - General marketplace
http://example2.onion - Data/credential marketplace
# Forums
http://example3.onion - Cybercrime forum
http://example4.onion - Breach discussion forum
# Paste sites
http://example5.onion - Dark web paste site
EOF
```

## Marketplace Monitoring

### Automated Marketplace Scanning

```python
def monitor_marketplace(marketplace_url, target_keywords, interval=3600):
    """Periodically check marketplaces for target-related listings."""
    findings = []

    listing_data = tor_request(f"{marketplace_url}/api/listings")
    if not listing_data:
        return findings

    for listing in parse_listings(listing_data):
        listing_text = f"{listing['title']} {listing['description']}".lower()

        for keyword in target_keywords:
            if keyword.lower() in listing_text:
                findings.append({
                    "marketplace": marketplace_url,
                    "listing_id": listing["id"],
                    "keyword_match": keyword,
                    "title": listing["title"],
                    "category": listing.get("category"),
                    "price": listing.get("price"),
                    "vendor": listing.get("vendor"),
                    "discovered": datetime.utcnow().isoformat(),
                    "severity": assess_severity(listing, keyword),
                })

    return findings
```

### Credential Leak Database Monitoring

```python
def check_credential_leaks(domain, breach_databases):
    """Search multiple breach databases for organizational credentials."""
    leaked_credentials = []

    for db_name, db_config in breach_databases.items():
        results = query_breach_db(
            db_config["endpoint"],
            domain=domain,
            api_key=db_config.get("api_key"),
        )

        for result in results:
            leaked_credentials.append({
                "database": db_name,
                "email": result.get("email"),
                "breach_name": result.get("breach"),
                "breach_date": result.get("date"),
                "data_types": result.get("data_classes", []),
                "password_hash": result.get("hash", "REDACTED"),
                "is_plaintext": result.get("plaintext", False),
            })

    return rank_by_severity(leaked_credentials)
```

## Forum Intelligence Gathering

### Thread Monitoring and Analysis

```python
def analyze_forum_thread(thread_url, org_keywords):
    """Extract intelligence from forum threads discussing the target."""
    content = tor_request(thread_url)
    if not content:
        return None

    thread_data = parse_forum_thread(content)

    intel = {
        "thread_title": thread_data.get("title"),
        "author": thread_data.get("author"),
        "post_date": thread_data.get("date"),
        "reply_count": thread_data.get("reply_count"),
        "target_mentions": [],
        "threat_indicators": [],
        "actor_profiles": [],
    }

    for post in thread_data.get("posts", []):
        post_text = post.get("content", "").lower()

        for keyword in org_keywords:
            if keyword.lower() in post_text:
                intel["target_mentions"].append({
                    "keyword": keyword,
                    "author": post.get("author"),
                    "date": post.get("date"),
                    "context": extract_context(post_text, keyword, window=100),
                })

        # Detect threat indicators
        threats = detect_threats(post_text)
        if threats:
            intel["threat_indicators"].extend(threats)

    return intel
```

### Threat Actor Profiling

```python
def profile_threat_actor(actor_name, forum_posts):
    """Build a profile of a threat actor based on forum activity."""
    profile = {
        "username": actor_name,
        "post_count": len(forum_posts),
        "first_seen": min(p["date"] for p in forum_posts),
        "last_seen": max(p["date"] for p in forum_posts),
        "topics": [],
        "specialization": None,
        "associated_iocs": [],
        "language_indicators": [],
    }

    # Analyze topics of interest
    all_text = " ".join(p["content"] for p in forum_posts)
    topic_keywords = {
        "ransomware": ["ransom", "encrypt", "locker", "decrypt"],
        "credential_theft": ["stealer", "logs", "credentials", "password"],
        "exploitation": ["exploit", "0day", "vulnerability", "rce"],
        "fraud": ["carding", "fullz", "dumps", "cvv"],
        "infrastructure": ["c2", "botnet", "panel", "admin"],
    }

    for topic, keywords in topic_keywords.items():
        matches = sum(1 for kw in keywords if kw in all_text.lower())
        if matches > 0:
            profile["topics"].append({"topic": topic, "mentions": matches})

    if profile["topics"]:
        profile["specialization"] = max(
            profile["topics"], key=lambda t: t["mentions"]
        )["topic"]

    return profile
```

## Operational Security for Dark Web Research

### Compartmentalization Rules

1. **Separate VMs per operation** -- Never mix research on different threat actors or targets in the same environment
2. **No cross-contamination** -- Do not access clearnet resources from your Tor research VM
3. **Time-based isolation** -- Perform dark web research at different times than normal work
4. **Credential separation** -- Research identities must have no connection to real identities
5. **Physical isolation** -- Consider using a dedicated air-gapped machine for the most sensitive research

### Evidence Preservation

```python
def preserve_evidence(url, content, metadata):
    """Securely preserve dark web evidence with chain of custody."""
    evidence = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat(),
        "tor_exit_ip": get_tor_exit_ip(),
        "content_hash_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "screenshot_path": None,
        "html_path": None,
        "metadata": metadata,
        "collector": "automated_monitor",
        "chain_of_custody": [{
            "action": "collected",
            "timestamp": datetime.utcnow().isoformat(),
            "method": "tor_fetch",
        }],
    }

    # Save raw HTML
    evidence_path = f"evidence/{evidence['content_hash_sha256'][:16]}"
    with open(f"{evidence_path}.html", "w") as f:
        f.write(content)

    return evidence
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

## Data Breach Analysis

### Breach Data Triage

```python
def triage_breach_data(breach_data, target_domain):
    """Triage and prioritize breach data findings."""
    triaged = {
        "critical": [],    # Active credentials, internal systems
        "high": [],        # Recent credentials, sensitive data
        "medium": [],      # Older credentials, partial data
        "low": [],         # Public info, outdated data
    }

    for entry in breach_data:
        severity = assess_entry_severity(entry, target_domain)

        if severity == "critical":
            triaged["critical"].append(entry)
        elif severity == "high":
            triaged["high"].append(entry)
        elif severity == "medium":
            triaged["medium"].append(entry)
        else:
            triaged["low"].append(entry)

    return triaged

def assess_entry_severity(entry, target_domain):
    """Assess the severity of a breach data entry."""
    score = 0

    # Fresh credentials are highest priority
    if entry.get("plaintext_password"):
        score += 4
    if entry.get("breach_date") > (datetime.now() - timedelta(days=90)).isoformat():
        score += 3

    # Internal system access is critical
    if any(domain in entry.get("email", "") for domain in [
        "admin@", "root@", "postmaster@", "security@", "it@", "devops@"
    ]):
        score += 3

    # Sensitive data types
    sensitive_types = {"password", "credit_card", "ssn", "api_key", "private_key"}
    if set(entry.get("data_types", [])) & sensitive_types:
        score += 2

    if score >= 7:
        return "critical"
    elif score >= 5:
        return "high"
    elif score >= 3:
        return "medium"
    return "low"
```

### Credential Analysis and Reporting

```python
def analyze_leaked_credentials(credentials, target_domain):
    """Analyze leaked credentials for password patterns and risk assessment."""
    analysis = {
        "total_leaked": len(credentials),
        "unique_accounts": len(set(c["email"] for c in credentials)),
        "password_patterns": {},
        "reuse_detected": False,
        "high_value_accounts": [],
        "password_strength_distribution": {"weak": 0, "medium": 0, "strong": 0},
    }

    # Detect password reuse across accounts
    email_to_hash = {}
    for cred in credentials:
        email = cred["email"]
        pwd_hash = cred.get("password_hash", "")
        if pwd_hash in email_to_hash:
            analysis["reuse_detected"] = True
        email_to_hash.setdefault(pwd_hash, []).append(email)

    # Identify high-value accounts
    high_value_patterns = ["admin", "root", "security", "it", "devops", "ciso"]
    for cred in credentials:
        local_part = cred["email"].split("@")[0]
        if any(p in local_part.lower() for p in high_value_patterns):
            analysis["high_value_accounts"].append(cred["email"])

    return analysis
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

## Hands-on Exercises

Practice the techniques described in this guide against authorized targets or lab environments. Document your findings and methodology for each exercise.
## References

- [Tor Project -- Official Documentation](https://www.torproject.org/docs/documentation.html)
- [OWASP -- OSINT Guide](https://owasp.org/www-community/attacks/Open_Source_Intelligence_(OSINT))
- [MITRE -- Collection Technique](https://attack.mitre.org/tactics/TA0042/)
- [First -- Threat Intelligence Sharing](https://www.first.org/global/sigs/ti/)
- [Ahmia -- Tor Search Engine](https://ahmia.fi/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
