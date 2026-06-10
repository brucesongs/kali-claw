# Scope Reconnaissance Guide

## Introduction

Effective reconnaissance within bug bounty scope boundaries is the foundation of every successful submission. Unlike broad penetration testing, bug bounty reconnaissance requires strict adherence to the program scope while maximizing coverage of in-scope assets. A disciplined recon pipeline systematically discovers subdomains, fingerprints technologies, maps the attack surface, and identifies scope boundaries before any active testing begins.

This guide provides a structured reconnaissance methodology tailored for bug bounty programs, covering subdomain enumeration, technology identification, attack surface mapping, and scope boundary validation. Each step includes practical commands you can integrate into your automated recon pipeline.

**Recon investment principle**: Spend 70% of your total bounty hunting time on reconnaissance. The most impactful vulnerabilities are found on forgotten subdomains, undocumented APIs, and staging environments that the internal security team has overlooked. A thorough recon phase turns a mediocre hunting session into a highly productive one.

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

**Advanced subdomain techniques:**

```bash
# Permutation-based discovery (finds dev-api, api-staging, etc.)
gotator -sub all_subdomains.txt \
  -perm /usr/share/seclists/Discovery/DNS/dns-prefixes.txt \
  -depth 1 | puredns resolve -r resolvers.txt > permuted_subs.txt

# DNS zone transfer attempt (sometimes misconfigured DNS allows it)
dig axfr target.com @ns1.target.com

# Reverse DNS lookup on target IP ranges
for ip in $(prips 10.0.0.0/24); do
  host "$ip" 2>/dev/null | grep "pointer" | cut -d' ' -f5
done

# Google dorking for subdomains
site:target.com -www
site:*.target.com
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

**Technology-to-vulnerability mapping:**

| Detected Technology | High-Value Vulnerability Classes |
|--------------------|----------------------------------|
| WordPress | Plugin vulnerabilities, XSS, CSRF, auth bypass |
| Django | SSTI, debug mode exposure, path traversal |
| Spring Boot | Actuator exposure, deserialization, SpEL injection |
| Laravel | Ignition debug mode, mass assignment, SQLi via Eloquent |
| Express.js | prototype pollution, SSRF, path traversal |
| Next.js/React | SSRF in getServerSideProps, XSS in dangerouslySetInnerHTML |
| Apache Struts | OGNL injection, RCE chains |

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

**Scope boundary edge cases to document:**

| Asset Type | Scope Question | Action |
|-----------|---------------|--------|
| CDN origin IP | Behind Cloudflare but direct IP accessible | Ask program; may be in scope |
| Third-party subdomain | `checkout.target.com` pointing to Stripe | Usually out of scope |
| Mobile API | `api.target.com/v2/mobile/` | Check if same scope as web |
| Subdomain takeover | CNAME to deleted GitHub Pages/Heroku | Most programs accept these |
| Cloud storage | `s3://target-assets-public/` | Check if listed in scope |
| Email infrastructure | SPF/DKIM/DMARC records | Usually out of scope |

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

**Continuous monitoring setup:**

```bash
# Schedule recon to run weekly and detect new assets
# crontab -e
# 0 2 * * 0 /opt/recon/monitor-recon.sh target.com

# monitor-recon.sh — detects new subdomains and alerts
LAST_SUBS="/opt/recon/target/baseline_subs.txt"
CURRENT_SUBS="/tmp/current_subs.txt"

subfinder -d "$1" -all -silent | sort -u > "$CURRENT_SUBS"
NEW=$(comm -13 "$LAST_SUBS" "$CURRENT_SUBS")

if [ -n "$NEW" ]; then
  echo "New subdomains detected:" | tee -a /opt/recon/alerts.log
  echo "$NEW" | tee -a /opt/recon/alerts.log
  # Auto-probe new assets
  echo "$NEW" | httpx -silent -title -tech-detect >> /opt/recon/new_assets.log
fi

# Update baseline
cp "$CURRENT_SUBS" "$LAST_SUBS"
```

## Hands-on Exercises

1. **Exercise 1**: Build a recon pipeline for a HackerOne public program that discovers all in-scope subdomains, fingerprints the technology stack, and outputs a prioritized target list sorted by likelihood of vulnerabilities
2. **Exercise 2**: Set up a scope monitoring system that runs weekly, detects new subdomains, and sends an alert when new assets appear
3. **Exercise 3**: Perform technology fingerprinting on a target and map each detected technology to its most common vulnerability classes, creating an attack plan

## Prioritization and Triage of Recon Results

After recon completes, you will have hundreds or thousands of URLs. Effective triage separates the high-value targets from noise.

**Automated triage pipeline:**

```bash
# Step 1: Filter out CDNs and static hosts
cat live_hosts.txt | httpx -silent -cdn | grep -v "cdn\|cloudfront\|cloudflare" > non_cdn_hosts.txt

# Step 2: Identify hosts with interesting technologies
cat non_cdn_hosts.txt | httpx -silent -tech-detect -json | \
  jq -r 'select(.tech != null) | select(.tech[] | test("php|wordpress|tomcat|jenkins|spring|django"; "i")) | .url' > interesting_hosts.txt

# Step 3: Run high-value nuclei templates
nuclei -l interesting_hosts.txt \
  -t cves/ \
  -t vulnerabilities/ \
  -t misconfiguration/ \
  -t exposures/ \
  -severity critical,high \
  -o nuclei_critical.txt

# Step 4: Check for subdomain takeover candidates
nuclei -l all_subdomains.txt -t takeovers/ -o takeover_candidates.txt

# Step 5: Extract all endpoints from interesting hosts
cat interesting_hosts.txt | hakrawler -depth 3 | sort -u > all_endpoints.txt

# Step 6: Find endpoints with parameters (injection targets)
grep -E "\?|=" all_endpoints.txt > parameterized_endpoints.txt
```

**Manual triage checklist for each target:**

| Priority | Indicator | Action |
|----------|-----------|--------|
| Critical | Admin panel with default credentials | Test immediately with Hydra |
| Critical | Exposed database (MongoDB, Redis, Elasticsearch) | Verify no auth, document |
| High | Outdated CMS with known CVEs | Search exploit-db, test PoC |
| High | API documentation (Swagger, GraphQL introspection) | Map all endpoints, test auth |
| High | File upload functionality | Test upload bypass techniques |
| Medium | Login form without rate limiting | Test credential stuffing |
| Medium | Search functionality (injection vectors) | Test XSS, SQLi, SSTI |
| Low | Static content only | Skip or deprioritize |

## References

- Subfinder: https://github.com/projectdiscovery/subfinder
- HTTPX: https://github.com/projectdiscovery/httpx
- Hakrawler: https://github.com/hakluke/hakrawler
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- Bug Bounty Recon Methodology: https://github.com/KingOfBugbounty/KingOfBugBountyTips
- Amass: https://github.com/owasp-amass/amass
- Arjun: https://github.com/s0md3v/Arjun
