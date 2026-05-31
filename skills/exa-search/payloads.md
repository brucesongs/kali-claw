# Exa Search Payloads

## Setup
```bash
export EXA_API_KEY="your_api_key_here"
EXA_BASE="https://api.exa.ai"
```

## Basic Search
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "CVE-2024 affecting nginx",
    "num_results": 10,
    "use_autoprompt": true
  }'
```

## Search Types

### Neural Search (Semantic)
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "techniques for bypassing web application firewalls",
    "type": "neural",
    "num_results": 10
  }'
```

### Keyword Search (Exact Match)
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "CVE-2024-3094 xz backdoor",
    "type": "keyword",
    "num_results": 10
  }'
```

### Auto Search (Let Exa Decide)
```bash
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Log4Shell exploitation techniques in the wild",
    "type": "auto",
    "num_results": 10
  }'
```

## Date Filtering
```bash
# Only results from last 30 days
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Spring Boot vulnerabilities",
    "num_results": 10,
    "start_published_date": "2024-04-01"
  }'

# Results within a specific window
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "zero day exploits disclosed",
    "start_published_date": "2024-01-01",
    "end_published_date": "2024-06-30",
    "num_results": 20
  }'
```

## Domain Filtering
```bash
# Search only security-focused sites
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "JWT security best practices",
    "num_results": 10,
    "include_domains": ["github.com", "portswigger.net", "owasp.org"]
  }'

# Exclude noise domains
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SQL injection prevention",
    "num_results": 10,
    "exclude_domains": ["stackoverflow.com", "medium.com", "reddit.com"]
  }'
```

## Content Extraction
```bash
# Get full text content with search
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Log4Shell exploitation techniques",
    "num_results": 5,
    "contents": {
      "text": true
    }
  }'

# Get highlighted snippets only
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SSRF cloud metadata exploitation",
    "num_results": 10,
    "contents": {
      "highlights": true
    }
  }'

# Get both text and highlights with length limit
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "container escape techniques",
    "num_results": 5,
    "contents": {
      "text": {"max_characters": 3000},
      "highlights": {"num_sentences": 3}
    }
  }'
```

## Find Similar Pages
```bash
# Find pages similar to a known security writeup
curl -X POST "$EXA_BASE/find_similar" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://portswigger.net/research/top-10-web-hacking-techniques-of-2023",
    "num_results": 10
  }'

# Find similar with domain filter
curl -X POST "$EXA_BASE/find_similar" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "num_results": 10,
    "exclude_domains": ["github.com"]
  }'
```

## Get Contents by URL
```bash
# Extract content from known URLs
curl -X POST "$EXA_BASE/contents" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ids": [
      "https://blog.example.com/cve-2024-writeup",
      "https://security.example.com/advisory-001"
    ],
    "text": true
  }'
```

## Security Research Query Examples

### CVE Research
```bash
# Recent critical CVEs
"CVE-2024 affecting AWS services"
"critical vulnerabilities container runtimes 2024"
"zero day exploit disclosed this week"
"CVE proof of concept github"

# Specific product research
"nginx vulnerability remote code execution"
"kubernetes RBAC privilege escalation"
"chrome V8 type confusion exploit"
```

### Exploit Techniques
```bash
# Attack methodology
"SSRF bypass in cloud metadata services"
"SQL injection in GraphQL implementations"
"OAuth 2.0 redirect_uri validation bypass"
"deserialization exploit Java Spring"
"prototype pollution to RCE Node.js"

# Bypass techniques
"WAF bypass techniques 2024"
"CSP bypass using JSONP endpoints"
"AMSI bypass PowerShell latest"
```

### Tool Research
```bash
# Discovery
"best open-source SAST tools for Go"
"automated exploit frameworks 2024"
"subdomain enumeration tools comparison"
"cloud security posture management open source"

# Configuration
"nuclei custom templates writing guide"
"burp suite extension development"
"metasploit module development tutorial"
```

### Threat Intelligence
```bash
# Actor research
"APT groups targeting financial sector"
"ransomware campaigns healthcare 2024"
"nation state cyber operations attribution"

# Campaign tracking
"supply chain attack npm packages"
"cryptomining malware cloud environments"
"initial access brokers dark web"
```

## Python SDK Integration

```python
from exa_py import Exa

exa = Exa(api_key="your_api_key")

# Basic search with contents
results = exa.search_and_contents(
    "remote code execution vulnerabilities in popular CMS",
    type="neural",
    num_results=10,
    text=True,
    highlights=True,
    start_published_date="2024-01-01"
)

for result in results.results:
    print(f"Title: {result.title}")
    print(f"URL: {result.url}")
    print(f"Score: {result.score}")
    print(f"Text: {result.text[:200]}...")
    print("---")
```

### Batch Research Pipeline
```python
queries = [
    "CVE-2024 nginx remote code execution",
    "nginx configuration hardening guide",
    "nginx WAF bypass techniques",
]

all_results = []
for query in queries:
    results = exa.search(query, num_results=5, type="auto")
    all_results.extend(results.results)

# Deduplicate by URL
unique = {r.url: r for r in all_results}
print(f"Found {len(unique)} unique results from {len(queries)} queries")
```

### Continuous Monitoring
```python
import time
from datetime import datetime, timedelta

def monitor_new_vulns(keyword, interval_hours=6):
    last_check = datetime.now() - timedelta(hours=interval_hours)
    results = exa.search(
        f"{keyword} vulnerability disclosed",
        start_published_date=last_check.strftime("%Y-%m-%d"),
        num_results=20,
        type="auto"
    )
    return results.results

# Check every 6 hours for new findings
new_findings = monitor_new_vulns("kubernetes")
for finding in new_findings:
    print(f"[NEW] {finding.title}: {finding.url}")
```

## Vulnerability Disclosure Monitoring

### Track New CVE Advisories
```bash
# Monitor NVD and vendor advisories for a specific product
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "security advisory critical vulnerability disclosed",
    "type": "neural",
    "num_results": 20,
    "start_published_date": "2024-06-01",
    "include_domains": ["nvd.nist.gov", "github.com/advisories", "cve.org"],
    "contents": {
      "text": {"max_characters": 2000},
      "highlights": {"num_sentences": 3}
    }
  }'
```

### CVE-to-Exploit Pipeline Tracker
```python
from exa_py import Exa
from datetime import datetime, timedelta

exa = Exa(api_key="your_api_key")

def track_cve_exploit_timeline(cve_id):
    """Track a CVE from disclosure to public exploit availability."""
    stages = {
        "advisory": f"{cve_id} security advisory",
        "analysis": f"{cve_id} root cause analysis technical details",
        "poc": f"{cve_id} proof of concept exploit code",
        "detection": f"{cve_id} detection rule YARA sigma snort",
        "patch": f"{cve_id} patch fix mitigation"
    }
    
    timeline = {}
    for stage, query in stages.items():
        results = exa.search_and_contents(
            query,
            type="auto",
            num_results=5,
            text=True
        )
        timeline[stage] = [
            {"title": r.title, "url": r.url, "date": r.published_date}
            for r in results.results
        ]
    return timeline

# Example: Track Log4Shell lifecycle
timeline = track_cve_exploit_timeline("CVE-2021-44228")
for stage, entries in timeline.items():
    print(f"\n[{stage.upper()}]")
    for entry in entries:
        print(f"  {entry['date']} - {entry['title']}")
```

### Vendor Advisory Aggregator
```bash
# Aggregate advisories from multiple vendors
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "security bulletin patch tuesday critical remote code execution",
    "type": "neural",
    "num_results": 15,
    "start_published_date": "2024-05-01",
    "include_domains": [
      "msrc.microsoft.com",
      "security.googleblog.com",
      "support.apple.com",
      "access.redhat.com",
      "ubuntu.com/security"
    ],
    "contents": {"highlights": {"num_sentences": 5}}
  }'
```

### Exploit Release Monitoring
```python
def monitor_exploit_releases(products, days_back=7):
    """Monitor for new public exploits targeting specific products."""
    date_threshold = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    
    exploit_sources = [
        "exploit-db.com", "packetstormsecurity.com",
        "github.com", "seclists.org"
    ]
    
    findings = []
    for product in products:
        results = exa.search_and_contents(
            f"{product} exploit proof of concept 0day",
            type="auto",
            num_results=10,
            start_published_date=date_threshold,
            include_domains=exploit_sources,
            text=True
        )
        for r in results.results:
            findings.append({
                "product": product,
                "title": r.title,
                "url": r.url,
                "snippet": r.text[:500] if r.text else ""
            })
    return findings

# Monitor critical infrastructure
targets = ["Apache Struts", "VMware vCenter", "Fortinet FortiOS", "Citrix NetScaler"]
exploits = monitor_exploit_releases(targets, days_back=14)
for e in exploits:
    print(f"[{e['product']}] {e['title']}\n  {e['url']}")
```

## Exposed Credential Discovery

### Leaked Database Search
```bash
# Search for references to leaked credential databases
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "database leak dump credentials exposed 2024",
    "type": "neural",
    "num_results": 15,
    "exclude_domains": ["reddit.com", "twitter.com"],
    "contents": {
      "text": {"max_characters": 1500},
      "highlights": {"num_sentences": 3}
    }
  }'
```

### Exposed Configuration Files
```python
def find_exposed_configs(target_domain):
    """Search for accidentally exposed configuration files."""
    config_queries = [
        f'"{target_domain}" exposed .env file database password',
        f'"{target_domain}" configuration leak api key secret',
        f'"{target_domain}" git repository exposed credentials',
        f'"{target_domain}" docker-compose secrets environment variables'
    ]
    
    exposed = []
    for query in config_queries:
        results = exa.search_and_contents(
            query,
            type="keyword",
            num_results=10,
            text=True
        )
        for r in results.results:
            if any(indicator in (r.text or "").lower() 
                   for indicator in ["password", "api_key", "secret", "token"]):
                exposed.append({
                    "query": query,
                    "title": r.title,
                    "url": r.url,
                    "evidence": r.text[:300]
                })
    return exposed

findings = find_exposed_configs("example.com")
```

### Paste Site Monitoring
```bash
# Monitor paste sites for credential dumps mentioning a target
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "paste dump email password list breach",
    "type": "keyword",
    "num_results": 20,
    "start_published_date": "2024-05-01",
    "include_domains": ["pastebin.com", "ghostbin.com", "dpaste.org"],
    "contents": {"text": {"max_characters": 5000}}
  }'
```

### Cloud Storage Exposure Detection
```python
def detect_cloud_exposure(org_name):
    """Find exposed cloud storage buckets and blobs."""
    queries = [
        f'"{org_name}" s3 bucket public listing',
        f'"{org_name}" azure blob storage exposed',
        f'"{org_name}" google cloud storage open bucket',
        f'"{org_name}" firebase database exposed .json'
    ]
    
    exposures = []
    for query in queries:
        results = exa.search_and_contents(
            query, type="auto", num_results=10, text=True
        )
        exposures.extend([
            {"source": query, "title": r.title, "url": r.url}
            for r in results.results
        ])
    return exposures

# Scan for org exposure
cloud_leaks = detect_cloud_exposure("Acme Corp")
print(f"Found {len(cloud_leaks)} potential cloud exposures")
```

## Attack Surface Mapping

### Subdomain and Infrastructure Discovery
```bash
# Discover subdomains and related infrastructure via search
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "site:*.target.com",
    "type": "keyword",
    "num_results": 50,
    "contents": {"text": false}
  }'
```

### Shadow IT Discovery
```python
def discover_shadow_it(org_domain, org_name):
    """Find unauthorized or forgotten services associated with an org."""
    shadow_queries = [
        f'"{org_name}" staging environment login',
        f'"{org_name}" internal portal dashboard',
        f'"{org_name}" dev server test environment',
        f'"{org_name}" jenkins gitlab jira confluence login',
        f'"{org_domain}" admin panel management console'
    ]
    
    shadow_services = []
    for query in shadow_queries:
        results = exa.search(
            query, type="auto", num_results=15
        )
        for r in results.results:
            if org_domain not in r.url:
                shadow_services.append({
                    "title": r.title,
                    "url": r.url,
                    "query_matched": query
                })
    
    # Deduplicate by domain
    seen_domains = set()
    unique_services = []
    for svc in shadow_services:
        domain = svc["url"].split("/")[2]
        if domain not in seen_domains:
            seen_domains.add(domain)
            unique_services.append(svc)
    
    return unique_services

shadow = discover_shadow_it("target.com", "Target Corp")
for s in shadow:
    print(f"[SHADOW IT] {s['url']} — {s['title']}")
```

### Technology Stack Fingerprinting
```bash
# Identify technologies used by a target via job postings and docs
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "target.com engineering team tech stack infrastructure",
    "type": "neural",
    "num_results": 15,
    "include_domains": ["linkedin.com", "glassdoor.com", "stackshare.io", "builtwith.com"],
    "contents": {
      "text": {"max_characters": 2000}
    }
  }'
```

### Related Domain and Acquisition Mapping
```python
def map_related_infrastructure(org_name):
    """Map acquisitions, subsidiaries, and related domains."""
    results = exa.search_and_contents(
        f'"{org_name}" acquired subsidiary brand domain',
        type="neural",
        num_results=20,
        text=True,
        include_domains=["crunchbase.com", "techcrunch.com", "sec.gov"]
    )
    
    # Find similar pages to the main org site
    similar = exa.find_similar(
        f"https://www.{org_name.lower().replace(' ', '')}.com",
        num_results=20
    )
    
    return {
        "acquisitions": [{"title": r.title, "url": r.url} for r in results.results],
        "similar_sites": [{"title": r.title, "url": r.url} for r in similar.results]
    }

infra_map = map_related_infrastructure("Example Corp")
```

## Threat Actor Intelligence

### APT Group Tracking
```bash
# Research specific APT group TTPs and campaigns
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "APT29 Cozy Bear campaign techniques indicators compromise 2024",
    "type": "neural",
    "num_results": 15,
    "include_domains": [
      "mandiant.com", "crowdstrike.com", "microsoft.com",
      "securelist.com", "unit42.paloaltonetworks.com"
    ],
    "contents": {
      "text": {"max_characters": 3000},
      "highlights": {"num_sentences": 5}
    }
  }'
```

### IOC Extraction Pipeline
```python
import re

def extract_iocs_from_research(threat_actor):
    """Search for threat intel reports and extract IOCs."""
    results = exa.search_and_contents(
        f"{threat_actor} indicators of compromise IOC malware infrastructure",
        type="neural",
        num_results=15,
        text=True,
        start_published_date="2024-01-01"
    )
    
    ioc_patterns = {
        "ipv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "domain": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "url": r'https?://[^\s<>"{}|\\^`\[\]]+'
    }
    
    all_iocs = {"ipv4": set(), "domain": set(), "sha256": set(), "md5": set(), "url": set()}
    
    for result in results.results:
        text = result.text or ""
        for ioc_type, pattern in ioc_patterns.items():
            matches = re.findall(pattern, text)
            all_iocs[ioc_type].update(matches)
    
    return {k: list(v) for k, v in all_iocs.items() if v}

iocs = extract_iocs_from_research("Lazarus Group")
for ioc_type, values in iocs.items():
    print(f"\n[{ioc_type.upper()}] ({len(values)} found)")
    for v in values[:10]:
        print(f"  {v}")
```

### Malware Campaign Tracker
```bash
# Track active malware campaigns and their evolution
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "ransomware campaign new variant analysis technical report",
    "type": "neural",
    "num_results": 20,
    "start_published_date": "2024-04-01",
    "include_domains": [
      "therecord.media", "bleepingcomputer.com",
      "securelist.com", "trellix.com", "sentinelone.com"
    ],
    "contents": {"text": {"max_characters": 2500}}
  }'
```

### MITRE ATT&CK Technique Mapping
```python
def map_actor_to_attack(threat_actor):
    """Map a threat actor's known techniques to MITRE ATT&CK."""
    results = exa.search_and_contents(
        f"{threat_actor} MITRE ATT&CK techniques tactics procedures TTP",
        type="neural",
        num_results=10,
        text=True,
        include_domains=["attack.mitre.org", "mandiant.com", "crowdstrike.com"]
    )
    
    # Extract technique IDs (T####.###)
    technique_pattern = r'T\d{4}(?:\.\d{3})?'
    techniques = set()
    
    for r in results.results:
        text = r.text or ""
        matches = re.findall(technique_pattern, text)
        techniques.update(matches)
    
    return {
        "actor": threat_actor,
        "techniques": sorted(techniques),
        "sources": [{"title": r.title, "url": r.url} for r in results.results]
    }

ttp_map = map_actor_to_attack("APT41")
print(f"Mapped {len(ttp_map['techniques'])} techniques for {ttp_map['actor']}")
```

## Supply Chain Risk Assessment

### Dependency Vulnerability Tracking
```bash
# Find vulnerabilities in popular packages and dependencies
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "npm package vulnerability malicious supply chain attack",
    "type": "neural",
    "num_results": 20,
    "start_published_date": "2024-01-01",
    "include_domains": [
      "github.com/advisories", "snyk.io", "socket.dev",
      "blog.phylum.io", "jfrog.com/blog"
    ],
    "contents": {
      "text": {"max_characters": 2000},
      "highlights": {"num_sentences": 4}
    }
  }'
```

### Package Typosquatting Detection
```python
def detect_typosquatting(legitimate_packages, registry="npm"):
    """Search for reports of typosquatting attacks on known packages."""
    findings = []
    
    for package in legitimate_packages:
        results = exa.search_and_contents(
            f'"{package}" typosquatting malicious package {registry} supply chain',
            type="auto",
            num_results=5,
            text=True
        )
        for r in results.results:
            if "typosquat" in (r.text or "").lower() or "malicious" in (r.text or "").lower():
                findings.append({
                    "legitimate_package": package,
                    "report_title": r.title,
                    "url": r.url,
                    "snippet": r.text[:400] if r.text else ""
                })
    
    return findings

# Check popular packages for known typosquatting
packages = ["lodash", "express", "react", "axios", "chalk"]
typosquats = detect_typosquatting(packages)
for t in typosquats:
    print(f"[ALERT] {t['legitimate_package']}: {t['report_title']}")
```

### Build Pipeline Compromise Research
```bash
# Research CI/CD and build pipeline attack vectors
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "CI/CD pipeline compromise attack GitHub Actions supply chain poisoning",
    "type": "neural",
    "num_results": 15,
    "contents": {
      "text": {"max_characters": 2500},
      "highlights": {"num_sentences": 4}
    }
  }'
```

### Open Source Maintainer Risk Assessment
```python
def assess_maintainer_risk(package_name, ecosystem="npm"):
    """Assess supply chain risk based on maintainer activity and trust signals."""
    queries = [
        f'"{package_name}" {ecosystem} maintainer compromised account takeover',
        f'"{package_name}" {ecosystem} abandoned unmaintained deprecated',
        f'"{package_name}" {ecosystem} ownership transfer suspicious',
        f'"{package_name}" dependency tree transitive vulnerabilities'
    ]
    
    risk_signals = []
    for query in queries:
        results = exa.search_and_contents(
            query, type="auto", num_results=5, text=True
        )
        for r in results.results:
            risk_signals.append({
                "signal": query.split(package_name)[1].strip(),
                "title": r.title,
                "url": r.url,
                "published": r.published_date
            })
    
    return {
        "package": package_name,
        "ecosystem": ecosystem,
        "risk_signals": risk_signals,
        "signal_count": len(risk_signals)
    }

risk = assess_maintainer_risk("event-stream")
print(f"Risk signals for {risk['package']}: {risk['signal_count']}")
```

## Dark Web Intelligence Gathering

### Forum and Marketplace Monitoring
```bash
# Search for dark web leak reports and marketplace activity
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "dark web marketplace data breach sale stolen credentials",
    "type": "neural",
    "num_results": 20,
    "start_published_date": "2024-03-01",
    "include_domains": [
      "krebsonsecurity.com", "therecord.media",
      "bleepingcomputer.com", "darkreadng.com",
      "flashpoint.io", "recordedfuture.com"
    ],
    "contents": {
      "text": {"max_characters": 2000},
      "highlights": {"num_sentences": 4}
    }
  }'
```

### Ransomware Leak Site Tracking
```python
def track_ransomware_leaks(industry=None, days_back=30):
    """Monitor reporting on ransomware leak site postings."""
    date_threshold = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    
    query = "ransomware leak site victim data published"
    if industry:
        query += f" {industry} sector"
    
    results = exa.search_and_contents(
        query,
        type="neural",
        num_results=25,
        start_published_date=date_threshold,
        text=True,
        include_domains=[
            "therecord.media", "bleepingcomputer.com",
            "techcrunch.com", "databreaches.net"
        ]
    )
    
    leaks = []
    for r in results.results:
        leaks.append({
            "title": r.title,
            "url": r.url,
            "date": r.published_date,
            "summary": r.text[:500] if r.text else ""
        })
    
    return leaks

# Track healthcare sector ransomware activity
healthcare_leaks = track_ransomware_leaks(industry="healthcare")
print(f"Found {len(healthcare_leaks)} ransomware reports (healthcare)")
```

### Initial Access Broker Monitoring
```bash
# Track initial access broker activity reports
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "initial access broker selling corporate network access VPN RDP",
    "type": "neural",
    "num_results": 15,
    "start_published_date": "2024-01-01",
    "include_domains": [
      "kela.io", "flashpoint.io", "ke-la.com",
      "krebsonsecurity.com", "intel471.com"
    ],
    "contents": {"text": {"max_characters": 2000}}
  }'
```

### Underground Economy Trend Analysis
```python
def analyze_underground_trends(timeframe_days=90):
    """Analyze trends in underground economy based on threat intel reports."""
    date_threshold = (datetime.now() - timedelta(days=timeframe_days)).strftime("%Y-%m-%d")
    
    trend_queries = [
        "underground forum selling zero day exploit price",
        "dark web stolen data pricing trends",
        "cybercrime as a service malware subscription",
        "botnet rental DDoS service underground",
        "stolen credit card fullz market dark web"
    ]
    
    trend_data = {}
    for query in trend_queries:
        results = exa.search_and_contents(
            query,
            type="neural",
            num_results=10,
            start_published_date=date_threshold,
            text=True
        )
        category = query.split()[0:3]
        trend_data[" ".join(category)] = [
            {"title": r.title, "url": r.url, "date": r.published_date}
            for r in results.results
        ]
    
    return trend_data

trends = analyze_underground_trends(timeframe_days=60)
for category, reports in trends.items():
    print(f"\n[{category.upper()}] — {len(reports)} reports")
    for r in reports[:3]:
        print(f"  {r['date']} | {r['title']}")
```

## Vendor Advisory Aggregation

### Multi-Vendor Patch Tuesday Monitor
```python
from exa_py import Exa
from datetime import datetime, timedelta

def monitor_patch_tuesday(vendors, days_back=14):
    """Monitor vendor patch releases (Patch Tuesday style)."""
    exa = Exa(api_key="your_api_key")
    date_threshold = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    vendor_domains = {
        "microsoft": ["msrc.microsoft.com"],
        "adobe": ["helpx.adobe.com"],
        "oracle": ["oracle.com"],
        "redhat": ["access.redhat.com"],
        "apple": ["support.apple.com"],
        "google": ["chromereleases.googleblog.com", "security.googleblog.com"],
        "mozilla": ["mozilla.org"],
        "apache": ["lists.apache.org"],
        "vmware": ["broadcom.com"],
    }

    all_patches = []
    for vendor in vendors:
        domains = vendor_domains.get(vendor, [])
        results = exa.search_and_contents(
            f"{vendor} security update patch advisory critical",
            type="neural",
            num_results=10,
            start_published_date=date_threshold,
            include_domains=domains,
            text={"max_characters": 2000},
            highlights={"num_sentences": 3}
        )
        for r in results.results:
            all_patches.append({
                "vendor": vendor,
                "title": r.title,
                "url": r.url,
                "date": r.published_date,
                "summary": r.text[:500] if r.text else ""
            })

    return sorted(all_patches, key=lambda x: x.get("date", ""), reverse=True)

patches = monitor_patch_tuesday(["microsoft", "adobe", "oracle"])
for p in patches:
    print(f"[{p['vendor'].upper()}] {p['title']}")
```

### Advisory Version Extraction
```python
import re

def extract_version_info(advisory_text):
    """Extract affected and patched version numbers from advisory text."""
    patterns = {
        "version_ranges": r'(\d+\.[\d.]+)\s*(?:to|through|-|–)\s*(\d+\.[\d.]+)',
        "affected": r'(?:affected|vulnerable|impacted)\s*(?:versions?)?:?\s*([^\n]+)',
        "patched": r'(?:fixed|patched|resolved|remediated)\s*(?:in|versions?)?:?\s*([^\n]+)',
        "cve_ids": r'CVE-\d{4}-\d{4,7}',
        "cwe_ids": r'CWE-\d+',
    }

    extracted = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, advisory_text, re.IGNORECASE)
        extracted[name] = matches if matches else []

    return extracted

# Process advisory results from Exa
text = "This update addresses CVE-2024-1234 affecting versions 1.0 to 3.2.1. Fixed in version 3.2.2."
info = extract_version_info(text)
print(f"CVEs: {info['cve_ids']}")
print(f"Versions: {info['version_ranges']}")
```

## CVE Rapid Assessment Pipeline

### Automated CVE Triage
```python
from exa_py import Exa
import re
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class CVETriage:
    cve_id: str
    cvss_score: Optional[float]
    exploit_available: bool
    poc_available: bool
    detection_rules: bool
    patch_available: bool
    risk_score: int
    priority: str

def triage_cve(cve_id, exa_client):
    """Perform rapid triage on a single CVE across intelligence sources."""
    # Check exploit availability
    exploit_results = exa_client.search(
        f"{cve_id} exploit proof of concept PoC code github",
        type="neural", num_results=5,
        include_domains=["github.com", "exploit-db.com", "packetstormsecurity.com"]
    )
    exploit_available = len(exploit_results.results) > 0

    # Check detection rules
    detection_results = exa_client.search(
        f"{cve_id} YARA Sigma Snort Suricata detection rule",
        type="neural", num_results=5,
        include_domains=["github.com", "rules.emergingthreats.net"]
    )
    detection_available = len(detection_results.results) > 0

    # Check patch status
    patch_results = exa_client.search(
        f"{cve_id} patch fix update remediation advisory",
        type="keyword", num_results=5
    )
    patch_available = any("patch" in (r.title or "").lower() or
                          "update" in (r.title or "").lower()
                          for r in patch_results.results)

    # Calculate risk score (0-10)
    score = 0
    if exploit_available: score += 4
    score += min(3, len(exploit_results.results))
    if not patch_available: score += 2
    if detection_available: score -= 1

    priority = "IMMEDIATE" if score >= 7 else "SCHEDULED" if score >= 4 else "MONITOR"

    return CVETriage(
        cve_id=cve_id,
        cvss_score=None,
        exploit_available=exploit_available,
        poc_available=exploit_available,
        detection_rules=detection_available,
        patch_available=patch_available,
        risk_score=score,
        priority=priority
    )

# Batch triage
exa = Exa(api_key="your_api_key")
cves = ["CVE-2024-3094", "CVE-2024-21762", "CVE-2024-3400"]
for cve in cves:
    triage = triage_cve(cve, exa)
    print(f"[{triage.priority}] {triage.cve_id} (score: {triage.risk_score})")
    print(f"  Exploit: {triage.exploit_available}, Detection: {triage.detection_rules}")
```

### CVE-to-Exploit Timeline Builder
```python
def build_exploit_timeline(cve_id, exa_client):
    """Build a timeline from CVE disclosure to exploit availability."""
    stages = [
        ("disclosure", f"{cve_id} disclosed reported CVE advisory"),
        ("analysis", f"{cve_id} technical analysis root cause writeup"),
        ("poc", f"{cve_id} proof of concept exploit PoC"),
        ("weaponized", f"{cve_id} exploit kit mass exploitation in the wild"),
        ("patched", f"{cve_id} patch fix update mitigation"),
        ("detected", f"{cve_id} YARA Sigma Snort IDS detection"),
    ]

    timeline = []
    for stage_name, query in stages:
        results = exa_client.search_and_contents(
            query, type="auto", num_results=3, text=True
        )
        for r in results.results:
            if r.published_date:
                timeline.append({
                    "stage": stage_name,
                    "date": r.published_date,
                    "title": r.title,
                    "url": r.url
                })
                break

    return sorted(timeline, key=lambda x: x.get("date", ""))

timeline = build_exploit_timeline("CVE-2021-44228", exa)
for event in timeline:
    print(f"  {event['date']} [{event['stage']}] {event['title']}")
```

## API Cost Optimization

### Cached Exa Search Wrapper
```python
import hashlib
import json
import time
from pathlib import Path
from exa_py import Exa

class CachedExaSearch:
    """Exa search wrapper with file-based caching to reduce API costs."""

    def __init__(self, api_key, cache_dir="exa_cache", default_ttl=86400):
        self.exa = Exa(api_key=api_key)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.default_ttl = default_ttl
        self.stats = {"cache_hits": 0, "cache_misses": 0, "api_calls": 0}

    def _cache_key(self, method, **kwargs):
        params = json.dumps({"method": method, **kwargs}, sort_keys=True)
        return hashlib.sha256(params.encode()).hexdigest()

    def search(self, query, ttl=None, **kwargs):
        key = self._cache_key("search", query=query, **kwargs)
        cached = self._get_cache(key, ttl)
        if cached:
            self.stats["cache_hits"] += 1
            return cached

        self.stats["api_calls"] += 1
        self.stats["cache_misses"] += 1
        results = self.exa.search(query, **kwargs)
        self._set_cache(key, [r.__dict__ for r in results.results])
        return results

    def search_and_contents(self, query, ttl=None, **kwargs):
        key = self._cache_key("search_and_contents", query=query, **kwargs)
        cached = self._get_cache(key, ttl)
        if cached:
            self.stats["cache_hits"] += 1
            return cached

        self.stats["api_calls"] += 1
        self.stats["cache_misses"] += 1
        results = self.exa.search_and_contents(query, **kwargs)
        self._set_cache(key, [r.__dict__ for r in results.results])
        return results

    def _get_cache(self, key, ttl=None):
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < (ttl or self.default_ttl):
                return json.loads(cache_file.read_text())
        return None

    def _set_cache(self, key, data):
        cache_file = self.cache_dir / f"{key}.json"
        cache_file.write_text(json.dumps(data))

    def get_stats(self):
        total = self.stats["cache_hits"] + self.stats["cache_misses"]
        hit_rate = self.stats["cache_hits"] / total if total > 0 else 0
        return {**self.stats, "hit_rate": f"{hit_rate:.1%}"}

# Usage
cached_exa = CachedExaSearch(api_key="your_api_key")
results = cached_exa.search("CVE-2024 nginx vulnerability")
print(f"Stats: {cached_exa.get_stats()}")
```

### Query Deduplication and Batching
```python
class QueryOptimizer:
    """Deduplicate and batch similar Exa queries to reduce API usage."""

    def __init__(self, similarity_threshold=0.8):
        self.queries = {}
        self.threshold = similarity_threshold

    def normalize_query(self, query):
        """Normalize query text for deduplication."""
        normalized = query.lower().strip()
        # Remove extra whitespace
        normalized = " ".join(normalized.split())
        # Sort words for order-independent matching
        words = sorted(normalized.split())
        return " ".join(words)

    def check_duplicate(self, query):
        """Check if a similar query has already been executed."""
        normalized = self.normalize_query(query)
        for existing_key in self.queries:
            existing_normalized = self.normalize_query(existing_key)
            if normalized == existing_normalized:
                return existing_key
            # Simple word overlap similarity
            words_a = set(normalized.split())
            words_b = set(existing_normalized.split())
            if words_a and words_b:
                similarity = len(words_a & words_b) / len(words_a | words_b)
                if similarity >= self.threshold:
                    return existing_key
        return None

    def register_query(self, query, results):
        """Register a query and its results for future deduplication."""
        self.queries[query] = results

# Usage: check before making API calls
optimizer = QueryOptimizer()
query = "nginx CVE 2024 vulnerability"
duplicate_of = optimizer.check_duplicate(query)
if duplicate_of:
    print(f"Skipping '{query}' - similar to existing query: '{duplicate_of}'")
```

## Dark Web Intelligence via Surface Web

### Breach Report Aggregator
```bash
# Search surface-web reporting for dark web breach activity
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "data breach database leak stolen records dark web marketplace",
    "type": "neural",
    "num_results": 20,
    "start_published_date": "2024-01-01",
    "include_domains": [
      "krebsonsecurity.com", "therecord.media",
      "bleepingcomputer.com", "haveibeenpwned.com",
      "databreaches.net", "vigilance.fr"
    ],
    "contents": {
      "text": {"max_characters": 2000},
      "highlights": {"num_sentences": 3}
    }
  }'
```

### Ransomware Victim Tracker
```python
def track_ransomware_targets(industry=None, days_back=30):
    """Track ransomware group activities via surface-web reporting."""
    date_threshold = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    query = "ransomware group claimed victim leak site data published"
    if industry:
        query += f" {industry}"

    results = exa.search_and_contents(
        query,
        type="neural",
        num_results=25,
        start_published_date=date_threshold,
        text=True,
        include_domains=[
            "therecord.media", "bleepingcomputer.com",
            "techcrunch.com", "darkreading.com",
            "securityaffairs.co", "ransomwatch.org"
        ]
    )

    victims = []
    for r in results.results:
        victims.append({
            "title": r.title,
            "url": r.url,
            "date": r.published_date,
            "summary": (r.text or "")[:500]
        })

    return sorted(victims, key=lambda x: x.get("date", ""), reverse=True)

# Track healthcare sector ransomware activity
healthcare_victims = track_ransomware_targets(industry="healthcare")
for v in healthcare_victims:
    print(f"[{v.get('date', 'N/A')[:10]}] {v['title']}")
```

### Initial Access Broker Activity Monitor
```bash
# Monitor IAB activity through threat intel reporting
curl -X POST "$EXA_BASE/search" \
  -H "X-API-Key: $EXA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "initial access broker selling VPN credentials RDP access corporate network",
    "type": "neural",
    "num_results": 15,
    "start_published_date": "2024-03-01",
    "include_domains": [
      "kela.io", "flashpoint.io", "intel471.com",
      "recordedfuture.com", "krebsonsecurity.com"
    ],
    "contents": {
      "text": {"max_characters": 1500},
      "highlights": {"num_sentences": 4}
    }
  }'
```

### Stealer Log Detection for Organization
```python
def detect_stealer_logs(org_domain, org_name):
    """Search for reports of stealer logs containing org credentials."""
    queries = [
        f'"{org_domain}" stealer log credentials infostealer',
        f'"{org_name}" redline raccoon vidar stealer infected',
        f'"{org_domain}" credential dump breach stealer malware'
    ]

    findings = []
    for query in queries:
        results = exa.search_and_contents(
            query, type="keyword", num_results=10,
            text={"max_characters": 1500}
        )
        for r in results.results:
            text = (r.text or "").lower()
            if any(kw in text for kw in ["stealer", "infostealer", "redline", "raccoon"]):
                findings.append({
                    "query": query,
                    "title": r.title,
                    "url": r.url,
                    "relevance": "HIGH" if org_domain in (r.text or "") else "MEDIUM"
                })

    return sorted(findings, key=lambda x: x["relevance"], reverse=True)

# Check for stealer logs mentioning the organization
stealer_findings = detect_stealer_logs("example.com", "Example Corp")
for f in stealer_findings:
    print(f"[{f['relevance']}] {f['title']}")
```
```
