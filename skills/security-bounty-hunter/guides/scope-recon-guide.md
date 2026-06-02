# Scope Reconnaissance Guide

## Introduction

Effective reconnaissance within bug bounty scope boundaries is the foundation of every successful submission. Unlike broad penetration testing, bug bounty reconnaissance requires strict adherence to the program scope while maximizing coverage of in-scope assets. A disciplined recon pipeline systematically discovers subdomains, fingerprints technologies, maps the attack surface, and identifies scope boundaries before any active testing begins.

This guide provides a structured reconnaissance methodology tailored for bug bounty programs, covering subdomain enumeration, technology identification, attack surface mapping, and scope boundary validation. Each step includes practical commands you can integrate into your automated recon pipeline.

## Practical Steps

### 1. Subdomain Enumeration

Build a comprehensive list of in-scope subdomains using multiple passive and active sources:

```bash
# Passive enumeration with subfinder (aggregates from 30+ sources)
subfinder -d target.com -all -o subfinder_results.txt

# Certificate transparency log search
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crt_results.txt

# DNS brute force with assetfinder
assetfinder --subs-only target.com > assetfinder_results.txt

# Combine and deduplicate all results
cat subfinder_results.txt crt_results.txt assetfinder_results.txt | sort -u > all_subdomains.txt

# Resolve subdomains to live hosts
cat all_subdomains.txt | httpx -silent -status-code -title -tech-detect -o live_hosts.txt
```

### 2. Technology Fingerprinting

Identify the technology stack to guide your vulnerability research:

```bash
# Web technology detection with whatweb
whatweb -v -a 3 https://target.com

# Wappali CLI for batch scanning
cat live_hosts.txt | cut -d' ' -f1 | wappalyzer --url-file=/dev/stdin

# HTTP header analysis for server fingerprinting
for host in $(cat live_hosts.txt | cut -d' ' -f1); do
  curl -sI "$host" | grep -iE "server:|x-powered-by:|x-aspnet-version:"
done

# JavaScript file discovery for API endpoints
cat live_hosts.txt | cut -d' ' -f1 | hakrawler -js -depth 2 | grep -E "\.js$" | sort -u > js_files.txt

# Extract endpoints from JavaScript files
cat js_files.txt | httpx -silent | nuclei -t /Templates/exposure/ -o js_exposure.txt
```

### 3. Attack Surface Mapping

Map out the full attack surface including ports, services, and hidden paths:

```bash
# Port scanning with nmap (top 1000 ports)
nmap -sV -sC -iL live_hosts.txt -oN port_scan_results.txt

# Quick service detection with rustscan for speed
rustscan -a "$(cat live_hosts.txt | cut -d' ' -f1 | tr '\n' ',')" -- -sV

# Directory and file discovery
cat live_hosts.txt | cut -d' ' -f1 | feroxbuster --stdin -x php,asp,aspx,jsp,html,json -o dir_results.txt

# API endpoint discovery
cat live_hosts.txt | cut -d' ' -f1 | hakrawler -depth 3 -scope y | sort -u > endpoints.txt

# Find hidden parameters with arjun
for url in $(cat endpoints.txt | head -50); do
  arjun -u "$url" -oJ arjun_results.json
done
```

### 4. Scope Boundary Identification

Verify that discovered assets fall within the bug bounty program scope:

```bash
# Extract scope from the bounty platform (HackerOne example)
# Use the program's scope definition file
curl -s "https://hackerone.com/programs/TargetCompany" | grep -oE 'scope.*pattern'

# Resolve IPs and check ASN ownership
for sub in $(cat all_subdomains.txt); do
  ip=$(dig +short "$sub" | tail -1)
  if [ -n "$ip" ]; then
    asn=$(whois -h whois.radb.net "$ip" | grep -i origin | head -1)
    echo "$sub -> $ip -> $asn"
  fi
done > scope_verification.txt

# Check for out-of-scope CDNs and third-party services
cat live_hosts.txt | httpx -silent -cdn -o cdn_hosts.txt

# Use amass for ASN-based scope discovery
amass intel -org "Target Company" -active
amass enum -asn AS12345
```

### 5. Automated Recon Pipeline

Tie everything together into a repeatable pipeline:

```bash
#!/bin/bash
TARGET="$1"
echo "[*] Starting recon for: $TARGET"

# Phase 1: Subdomain discovery
subfinder -d "$TARGET" -all -silent | sort -u > subs.txt

# Phase 2: Live host detection
cat subs.txt | httpx -silent -status-code -title -tech-detect > live.txt

# Phase 3: Port scanning
cat live.txt | cut -d' ' -f1 | nmap -sV -iL - -oN ports.txt

# Phase 4: Directory brute force
cat live.txt | cut -d' ' -f1 | feroxbuster --stdin -x php,asp,json -o dirs.txt

# Phase 5: Vulnerability scanning
nuclei -l live.txt -t /Templates/ -severity critical,high -o vulns.txt

echo "[+] Recon complete. Review subs.txt, live.txt, ports.txt, dirs.txt, vulns.txt"
```

## References

- Subfinder: https://github.com/projectdiscovery/subfinder
- HTTPX: https://github.com/projectdiscovery/httpx
- Hakrawler: https://github.com/hakluke/hakrawler
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- Bug Bounty Recon Methodology: https://github.com/KingOfBugbounty/KingOfBugBountyTips
