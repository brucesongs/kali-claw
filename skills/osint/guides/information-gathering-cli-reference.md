# Information Gathering Command Line Tools Detailed Reference

## Introduction

This guide provides a comprehensive command-line reference for the most widely used OSINT information gathering tools available on Kali Linux. Each tool section covers installation verification, basic and advanced usage, key options, and realistic scenarios you will encounter during penetration testing engagements. The goal is to serve as a quick yet deep reference you can consult before and during engagement recon phases.

All tools discussed here operate within the OSINT and passive/semi-passive reconnaissance categories. Active scanning tools such as Nmap are covered separately in the network pentest skill domain. The tools are presented in a recommended workflow order: email and host harvesting, subdomain enumeration, DNS reconnaissance, and port scanning for service discovery.

### When to Use Each Tool

| Tool | Primary Use Case | Noise Level | API Key Required |
|------|-----------------|-------------|-----------------|
| theHarvester | Email, host, and URL harvesting | Low | Optional (improves results) |
| Sublist3r | Subdomain enumeration via search engines | Low | No |
| Amass | Deep attack surface mapping | Low-Medium | Optional (improves results) |
| DNSRecon | DNS record enumeration and zone transfers | Low | No |
| Masscan | Ultra-fast port scanning | High | No |

## 1. theHarvester - OSINTinformation gathering

### Basic Usage
```bash
# Basic domain information gathering
theHarvester -d example.com -b google,bing

# Use multiple data sources
theHarvester -d example.com -b baidu,duckduckgo,github-code,securityTrails

# Enable DNS resolution and brute force
theHarvester -d example.com -r -c -n

# Save results to file
theHarvester -d example.com -f results.xml

# Enable Shodan queries
theHarvester -d example.com -s
```

### Main Options
- `-d, --domain`: Target domain or company name
- `-b, --source`: Specify data sources (50+ sources supported)
- `-l, --limit`: Limit search results (default 500)
- `-r, --dns-resolve`: DNS resolution for subdomains
- `-c, --dns-brute`: Perform DNS brute force
- `-n, --dns-lookup`: Enable DNS server lookup
- `-s, --shodan`: Use Shodan to query discovered hosts
- `-f, --filename`: Save results to XML/JSON file

### Practical Examples
```bash
# Comprehensive information gathering
theHarvester -d target.com -b all -r -c -n -f target_recon

# Collect emails and hosts only
theHarvester -d target.com -b hunter,haveibeenpwned -l 1000
```

### Advanced theHarvester Techniques

#### Multi-Target Harvesting Script
```bash
#!/bin/bash
# harvest_multi.sh - Run theHarvester against multiple domains
DOMAINS_FILE="targets.txt"
RESULTS_DIR="harvest_results_$(date +%Y%m%d)"

mkdir -p "$RESULTS_DIR"

while IFS= read -r domain; do
    echo "[*] Harvesting: $domain"
    theHarvester -d "$domain" -b google,bing,duckduckgo,crtsh,linkedin_links \
        -l 500 -f "$RESULTS_DIR/${domain}.json" 2>/dev/null
    
    # Extract and summarize
    EMAILS=$(jq -r '.emails[]?' "$RESULTS_DIR/${domain}.json" 2>/dev/null | wc -l)
    HOSTS=$(jq -r '.hosts[]?' "$RESULTS_DIR/${domain}.json" 2>/dev/null | wc -l)
    echo "[+] $domain: $EMAILS emails, $HOSTS hosts"
done < "$DOMAINS_FILE"

# Aggregate all results
cat "$RESULTS_DIR"/*.json | jq -s 'add' > "$RESULTS_DIR/combined.json"
```

#### Email Pattern Analysis
```python
"""Analyze harvested emails to determine corporate naming conventions."""
import re
from collections import Counter

def analyze_email_patterns(emails: list[str]) -> dict:
    """Determine the dominant email naming pattern from harvested addresses."""
    patterns = Counter()
    for email in emails:
        local = email.split("@")[0]
        if re.match(r'^[a-z]+\.[a-z]+$', local):
            patterns["firstname.lastname"] += 1
        elif re.match(r'^[a-z]+_[a-z]+$', local):
            patterns["firstname_lastname"] += 1
        elif re.match(r'^[a-z]{1}[a-z]+$', local):
            patterns["flastname"] += 1
        elif re.match(r'^[a-z]+\.[a-z]{1}$', local):
            patterns["firstname.l"] += 1
        elif re.match(r'^[a-z]{2}[a-z]+$', local):
            patterns["firstlast"] += 1
        else:
            patterns["unknown"] += 1

    dominant = patterns.most_common(1)[0] if patterns else ("none", 0)
    return {
        "pattern_counts": dict(patterns),
        "dominant_pattern": dominant[0],
        "confidence": dominant[1] / max(len(emails), 1),
    }
```

## 2. Sublist3r - subdomain enumeration

### Basic Usage
```bash
# Basic subdomain enumeration
sublist3r -d example.com

# Enable brute force module
sublist3r -d example.com -b

# Specify search engines
sublist3r -d example.com -e google,bing,yahoo

# Scan discovered subdomain ports
sublist3r -d example.com -p 80,443,8080

# Save results
sublist3r -d example.com -o subdomains.txt
```

### Main Options
- `-d, --domain`: Target domain
- `-b, --bruteforce`: Enable subbrute brute force module
- `-p, --ports`: Scan specified TCP ports on discovered subdomains
- `-e, --engines`: Specify search engines (comma-separated)
- `-o, --output`: Save results to text file
- `-t, --threads`: Brute force thread count
- `-v, --verbose`: Enable verbose output

### Practical Examples
```bash
# Quick subdomain discovery
sublist3r -d target.com -e crtsh,securityTrails,virustotal

# Full enumeration with port scanning
sublist3r -d target.com -b -p 21,22,25,80,443,3389 -o full_scan.txt
```

### Sublist3r Output Analysis
```python
"""Parse Sublist3r output and correlate with DNS records."""
import json
import subprocess
from dataclasses import dataclass

@dataclass(frozen=True)
class SubdomainResult:
    subdomain: str
    ip_address: str | None
    ports: list[int]
    source: str

def parse_sublist3r_output(output_file: str) -> list[SubdomainResult]:
    """Read Sublist3r output and structure into data objects."""
    results = []
    with open(output_file) as f:
        for line in f:
            subdomain = line.strip()
            if not subdomain:
                continue
            results.append(SubdomainResult(
                subdomain=subdomain,
                ip_address=None,
                ports=[],
                source="sublist3r",
            ))
    return results

def categorize_subdomains(subdomains: list[SubdomainResult]) -> dict:
    """Categorize discovered subdomains by type."""
    categories = {
        "admin": [], "api": [], "staging": [],
        "dev": [], "internal": [], "other": [],
    }
    keywords = {
        "admin": ["admin", "manage", "console", "cpanel", "backend"],
        "api": ["api", "rest", "graphql", "endpoint", "openapi"],
        "staging": ["stage", "staging", "stg", "uat", "pre"],
        "dev": ["dev", "development", "test", "testing", "ci", "jenkins"],
        "internal": ["internal", "intranet", "vpn", "mail", "git", "jira"],
    }
    for sub in subdomains:
        name = sub.subdomain.lower()
        matched = False
        for cat, kws in keywords.items():
            if any(kw in name for kw in kws):
                categories[cat].append(sub)
                matched = True
                break
        if not matched:
            categories["other"].append(sub)

    return categories
```

## 3. Amass - Attackssurface mapping

### Basic Usage（Requires API key configuration）
```bash
# Passive enumeration
amass enum -d example.com -passive

# Active enumeration
amass enum -d example.com -active

# Use configuration file
amass enum -d example.com -config ~/.amass-config.ini

# Save results
amass enum -d example.com -o amass_results.txt
```

### Main Options
- `enum`: Enumerate subdomains
- `-d`: Target domain
- `-passive`: Use only passive data sources
- `-active`: Perform active probing
- `-o`: Output file
- `-config`: Configuration file path
- `-brute`: Enable brute force
- `-ip`: Show IP addresses

### Practical Examples
```bash
# Passive information gathering
amass enum -d target.com -passive -o passive_enum.txt

# Active attack surface mapping
amass enum -d target.com -active -brute -ip -o attack_surface.txt
```

### Amass Database and Visualization
```bash
# Store results in Amass graph database for relationship analysis
amass enum -d target.com -active -config ~/.amass.ini -o results.txt

# Query the Amass database for previously collected data
amass db -show

# Enumerate across multiple domains from a file
amass enum -df domains.txt -passive -o multi_domain_results.txt

# Track changes between scans
amass track -d target.com -last 2
```

### Amass Configuration Best Practices
```ini
# ~/.amass.ini - Example configuration
[datasources]
# Add API keys for enhanced data sources
[data.shodan]
apikey = YOUR_SHODAN_KEY

[data.securitytrails]
apikey = YOUR_ST_KEY

[data.censys]
apikey = YOUR_CENSYS_ID
secret = YOUR_CENSYS_SECRET

[network]
# Timeout settings for reliability
timeout = 10
max_dns_queries = 200
```

## 4. DNSRecon - DNSenumeration and reconnaissance

### Basic Usage
```bash
# Standard enumeration
dnsrecon -d example.com -t std

# Zone transfer test
dnsrecon -d example.com -t axfr

# Brute force subdomains
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt

# Reverse DNS lookup
dnsrecon -r 192.168.1.0/24 -t rvl

# CRT.sh enumeration
dnsrecon -d example.com -t crt
```

### Main Enumeration Types
- `std`: SOA, NS, A, AAAA, MX, SRV records
- `axfr`: Test zone transfer on all NS servers
- `brt`: Brute force domains and hosts using dictionary
- `rvl`: Reverse lookup for CIDR or IP ranges
- `crt`: Search subdomains via crt.sh
- `zonewalk`: DNSSEC zone walk using NSEC records

### Output Options
- `-x`: Save as XML file
- `-c`: Save as CSV file  
- `-j`: Save as JSON file
- `--db`: Save to SQLite3 database

### Practical Examples
```bash
# Comprehensive DNS reconnaissance
dnsrecon -d target.com -t std,axfr,brt,crt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -j dns_results.json

# Internal IP range reverse lookup
dnsrecon -r 10.0.0.0/24 -t rvl -c internal_hosts.csv
```

### DNS Record Analysis for Security Assessment
```python
"""Analyze DNS records for security-relevant findings."""
from dataclasses import dataclass

@dataclass(frozen=True)
class DNSFinding:
    record_type: str
    hostname: str
    value: str
    risk: str  # "low", "medium", "high"
    recommendation: str

def analyze_dns_records(records: list[dict]) -> list[DNSFinding]:
    """Analyze DNS records and identify security issues."""
    findings = []

    for rec in records:
        rtype = rec.get("type", "").upper()
        value = rec.get("value", "")
        hostname = rec.get("name", "")

        # Check for zone transfer success (critical)
        if rtype == "AXFR" and rec.get("transfer_success"):
            findings.append(DNSFinding(
                record_type="AXFR",
                hostname=hostname,
                value=value,
                risk="high",
                recommendation="Disable DNS zone transfers to untrusted servers",
            ))

        # Check for missing DMARC
        if rtype == "TXT" and hostname.startswith("_dmarc") and not value:
            findings.append(DNSFinding(
                record_type="DMARC",
                hostname=hostname,
                value="MISSING",
                risk="medium",
                recommendation="Configure DMARC policy (p=reject or p=quarantine)",
            ))

        # Check for internal IP exposure in public DNS
        if rtype in ("A", "AAAA") and is_private_ip(value):
            findings.append(DNSFinding(
                record_type=rtype,
                hostname=hostname,
                value=value,
                risk="medium",
                recommendation="Review DNS records exposing internal IP addresses",
            ))

        # Flag wildcard DNS configurations
        if rtype == "A" and hostname.startswith("*"):
            findings.append(DNSFinding(
                record_type="WILDCARD",
                hostname=hostname,
                value=value,
                risk="low",
                recommendation="Wildcard DNS detected; may produce false positives in subdomain enumeration",
            ))

    return findings

def is_private_ip(ip: str) -> bool:
    """Check if IP address is in a private range."""
    private_prefixes = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.",
    ]
    return any(ip.startswith(p) for p in private_prefixes)
```

## 5. Masscan - ultra-fast port scanner

### Basic Usage
```bash
# Basic port scan
masscan 192.168.1.0/24 -p80,443 --rate=1000

# Scan all ports
masscan 10.0.0.0/8 -p0-65535 --rate=100000

# Enable service identification
masscan 192.168.1.1 -p1-65535 --banners --rate=1000

# Read targets from file
masscan -iL targets.txt -p80,443,8080 --rate=5000
```

### Main Options
- `-p`: Specify ports (supports ranges: 8000-8100)
- `--rate`: Scan rate (packets/second)
- `--banners`: Get service banner information
- `-iL`: Read target list from file
- `-oX`: Save as XML format
- `-oJ`: Save as JSON format
- `--exclude`: Exclude specific IPs
- `--ping`: Enable ICMP ping scan

### Performance Tuning
- Small networks: `--rate=1000`
- Medium networks: `--rate=10000`  
- Large networks: `--rate=100000+`
- Note: Excessively high rates may cause packet loss

### Practical Examples
```bash
# Quick web service discovery
masscan 10.0.0.0/24 -p80,443,8080,8443 --rate=5000 --banners -oJ web_services.json

# Full port scan (use with caution)
masscan 192.168.1.1 -p0-65535 --rate=10000 --banners -oX full_scan.xml
```

### Masscan to Nmap Handoff Script
```bash
#!/bin/bash
# masscan_to_nmap.sh - Use masscan for discovery, nmap for deep service enumeration
TARGET_RANGE="$1"
MASSCAN_OUTPUT="/tmp/masscan_discover.json"
NMAP_OUTPUT="nmap_deep_scan"

# Phase 1: Fast discovery with masscan
echo "[*] Phase 1: Masscan fast discovery on $TARGET_RANGE"
masscan "$TARGET_RANGE" -p1-65535 --rate=10000 -oJ "$MASSCAN_OUTPUT"

# Phase 2: Extract open ports per host
echo "[*] Phase 2: Extracting discovered services"
declare -A HOST_PORTS

for entry in $(jq -c '.[]' "$MASSCAN_OUTPUT" 2>/dev/null); do
    ip=$(echo "$entry" | jq -r '.ip')
    port=$(echo "$entry" | jq -r '.ports[0].port')
    HOST_PORTS["$ip"]="${HOST_PORTS[$ip]:-},$port"
done

# Phase 3: Deep service enumeration with nmap
echo "[*] Phase 3: Nmap service/version detection"
for ip in "${!HOST_PORTS[@]}"; do
    ports="${HOST_PORTS[$ip]#,}"
    echo "  [+] Scanning $ip ports: $ports"
    nmap -sV -sC -p "$ports" "$ip" -oA "${NMAP_OUTPUT}_${ip}" 2>/dev/null
done

echo "[+] Complete. Results in ${NMAP_OUTPUT}_*"
```

### Masscan Performance Optimization Table

| Target Size | Recommended Rate | Time Estimate | Packet Loss Risk |
|------------|-----------------|---------------|-----------------|
| /24 (254 hosts) | 1,000 pps | ~1 minute | Very low |
| /16 (65K hosts) | 10,000 pps | ~10 minutes | Low |
| /8 (16M hosts) | 100,000 pps | ~1-2 hours | Medium |
| Internet-scale | 1,000,000+ pps | Variable | High (tune carefully) |

## Tool Comparison Matrix

| Feature | theHarvester | Sublist3r | Amass | DNSRecon | Masscan |
|---------|-------------|-----------|-------|----------|---------|
| Email harvesting | Yes | No | No | No | No |
| Subdomain discovery | Limited | Yes | Yes | Yes | No |
| DNS zone transfer | No | No | No | Yes | No |
| Port scanning | No | Limited | No | No | Yes |
| Active probing | Limited | Limited | Yes | Yes | Yes |
| Passive only mode | Yes | No | Yes | No | No |
| Multi-target | Yes | No | Yes | No | Yes |
| API integration | Yes | No | Yes | No | No |
| Graph database | No | No | Yes | No | No |

## Tool Combination Strategy

### 1. Information Gathering Workflow
```bash
# Step 1: Domain information gathering
theHarvester -d target.com -b all -r -c -n -f phase1

# Step 2: Subdomain enumeration  
sublist3r -d target.com -b -e crtsh,securityTrails -o subdomains.txt

# Step 3: Deep DNS reconnaissance
dnsrecon -d target.com -t std,axfr,brt,crt -D wordlist.txt -j dns_deep.json

# Step 4: IP range discovery and scanning
# Extract IPs from previous results, then use masscan
masscan [IP_LIST] -p1-65535 --rate=10000 --banners -oJ port_scan.json
```

### 2. Passive vs Active Reconnaissance
- **Passive Reconnaissance**: theHarvester (some sources), Amass (passive mode)
- **Active Reconnaissance**: Sublist3r (brute force), DNSRecon (all modes), Masscan

### 3. Data Integration
- All tools support multiple output formats (JSON/XML/CSV)
- Scripts can be written to automatically integrate results from different tools
- Recommended to establish unified data storage and analysis workflow

## Best Practices and Considerations

### 1. Legal and Ethics
- Always obtain authorization before scanning
- Comply with target system's robots.txt and terms of use
- Control scan rates to avoid impacting the target

### 2. Technical Best Practices
- Use latest wordlist files (SecLists recommended)
- Configure API keys to improve data source coverage
- Combine passive and active reconnaissance methods
- Verify and deduplicate discovered results

### 3. Performance Optimization
- Adjust scan rates based on network environment
- Use multi-threading to improve efficiency
- Allocate system resources appropriately
- Monitor network bandwidth usage

### 4. Result Verification
- Manually verify key findings
- Cross-validate results from different tools
- Record scan time and environment information
- Save raw data for subsequent analysis

## Integration Script: Full Recon Pipeline

```bash
#!/bin/bash
# full_recon_pipeline.sh - End-to-end reconnaissance pipeline
set -euo pipefail

TARGET_DOMAIN="$1"
OUTPUT_DIR="recon_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

mkdir -p "$OUTPUT_DIR"/{harvest,subdomains,dns,ports,tech}

echo "=========================================="
echo "  Full Reconnaissance Pipeline"
echo "  Target: $TARGET_DOMAIN"
echo "  Output: $OUTPUT_DIR"
echo "=========================================="

# Phase 1: Email and host harvesting
echo "[Phase 1] Email and host harvesting with theHarvester..."
theHarvester -d "$TARGET_DOMAIN" -b all -l 500 \
    -f "$OUTPUT_DIR/harvest/harvester.json" 2>/dev/null || true

# Phase 2: Subdomain enumeration from multiple sources
echo "[Phase 2] Subdomain enumeration..."
subfinder -d "$TARGET_DOMAIN" -silent > "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null || true
amass enum -passive -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null || true
curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" \
    | jq -r '.[].name_value' 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/crtsh.txt" || true
sublist3r -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/subdomains/sublist3r.txt" 2>/dev/null || true

# Merge and deduplicate
sort -u "$OUTPUT_DIR/subdomains/"*.txt > "$OUTPUT_DIR/subdomains/all_unique.txt" 2>/dev/null || true
echo "[+] Unique subdomains: $(wc -l < "$OUTPUT_DIR/subdomains/all_unique.txt" 2>/dev/null || echo 0)"

# Phase 3: DNS deep reconnaissance
echo "[Phase 3] DNS reconnaissance..."
dnsrecon -d "$TARGET_DOMAIN" -t std,axfr,crt -j "$OUTPUT_DIR/dns/dnsrecon.json" 2>/dev/null || true

# Phase 4: Resolve live hosts
echo "[Phase 4] Resolving live hosts..."
dnsx -l "$OUTPUT_DIR/subdomains/all_unique.txt" -silent -a \
    > "$OUTPUT_DIR/subdomains/resolved.txt" 2>/dev/null || true

# Phase 5: Technology fingerprinting
echo "[Phase 5] Technology fingerprinting..."
httpx -l "$OUTPUT_DIR/subdomains/all_unique.txt" -silent \
    -status-code -title -tech-detect -server \
    -json -o "$OUTPUT_DIR/tech/technologies.json" 2>/dev/null || true

# Phase 6: Port scanning (top ports only for speed)
echo "[Phase 6] Port scanning top ports..."
httpx -l "$OUTPUT_DIR/subdomains/resolved.txt" -silent \
    | masscan -iL - -p21,22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,8080,8443 \
    --rate=5000 -oJ "$OUTPUT_DIR/ports/masscan.json" 2>/dev/null || true

# Generate summary
echo ""
echo "=========================================="
echo "  Reconnaissance Complete"
echo "=========================================="
echo "[+] Subdomains: $(wc -l < "$OUTPUT_DIR/subdomains/all_unique.txt" 2>/dev/null || echo 0)"
echo "[+] Resolved:   $(wc -l < "$OUTPUT_DIR/subdomains/resolved.txt" 2>/dev/null || echo 0)"
echo "[+] Tech stack:  $(jq -r '.tech[]?' "$OUTPUT_DIR/tech/technologies.json" 2>/dev/null | sort -u | wc -l || echo 0) technologies"
echo "[+] Results:    $OUTPUT_DIR"
echo "=========================================="
```
## Hands-on Exercises

Practice the techniques described in this guide against authorized targets or lab environments. Document your findings and methodology for each exercise.
## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- PTES Technical Guidelines — http://www.pentest-standard.org/
