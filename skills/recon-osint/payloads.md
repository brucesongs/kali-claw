# Payloads: Information Gathering & OSINT / Recon & OSINT

This file contains all reconnaissance and OSINT related commands and payloads, organized by category.

---

## 1. Passive Reconnaissance

### 1.1 WHOIS Domain Information Query

```bash
# Basic domain registration information
whois example.com

# Query a specific registrar (e.g., GoDaddy)
whois -h whois.godaddy.com example.com

# Extract key fields (registrant, email, DNS servers)
whois example.com | grep -E "Registrant|Name Server|Email"
```

### 1.2 DNS Record Enumeration

```bash
# Query all DNS record types
dig any example.com @8.8.8.8

# Query specific record types
dig A example.com +short
dig MX example.com +short
dig TXT example.com +short
dig NS example.com +short
dig CNAME www.example.com +short

# DNS zone transfer attempt (if allowed, leaks all records)
dig axfr example.com @ns1.example.com

# Reverse DNS lookup
dig -x 192.168.1.1 @8.8.8.8

# DNS cache probing
dig example.com @8.8.8.8 +trace
```

### 1.3 Search Engine Intelligence

```bash
# Google site-restricted search
site:example.com

# Find specific file types
site:example.com filetype:pdf
site:example.com filetype:xls OR filetype:xlsx

# Find directory listings
intitle:"index of" site:example.com

# Find login pages
site:example.com inurl:login OR inurl:admin

# Find exposed configuration files
site:example.com filetype:env OR filetype:conf OR filetype:ini

# Find error message disclosures
site:example.com "sql syntax" OR "warning" OR "error"

# Bing search complement
site:example.com filetype:docx
```

### 1.4 Certificate Transparency Log Query

```bash
# Query SSL certificate history using crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Get certificate information using openssl
openssl s_client -connect example.com:443 -showcerts 2>/dev/null | openssl x509 -noout -text
```

---

## 2. Active Reconnaissance

### 2.1 Host Discovery

```bash
# ICMP ping scan (quickly discover live hosts)
nmap -sn 192.168.1.0/24 -oG hosts.txt

# ARP scan (more reliable on the same network segment)
nmap -sn -PR 192.168.1.0/24

# No ping scan (bypass ICMP filtering)
nmap -Pn -sn 192.168.1.0/24

# Fast discovery using masscan
masscan 192.168.1.0/24 --ping-only --rate 1000
```

### 2.2 Port Scanning

```bash
# SYN half-open scan (stealthy)
nmap -sS -p- target

# Full connect scan (accurate)
nmap -sT -p- target

# UDP port scan
nmap -sU --top-ports 100 target

# Service version detection
nmap -sV -sC target

# Full port deep scan (comprehensive)
nmap -sS -sV -sC -O -p- -oA full_scan target

# Common ports quick scan
nmap -sS -sV --top-ports 1000 target

# High-speed scan using masscan
masscan -p1-65535 192.168.1.0/24 --rate 10000 -oL masscan_results.txt
```

### 2.3 Operating System Identification

```bash
# TCP/IP fingerprinting
nmap -O target

# Aggressive OS detection
nmap -O --osscan-guess target

# TTL-based estimation
ping -c 1 target  # Linux TTL~64, Windows TTL~128
```

### 2.4 Advanced Network Probing (hping3)

```bash
# SYN scan specific port
hping3 -S -p 80 -c 1 target

# FIN scan (bypass some firewalls)
hping3 -F -p 80 -c 1 target

# NULL scan
hping3 -0 -p 80 -c 1 target

# TCP Window scan
hping3 -W -p 80 -c 1 target
```

### 2.5 CIDR Range Discovery and Asset Mapping

```bash
# Discover ASN and IP ranges for a target organization
whois -h whois.radb.net -- '-i origin AS12345' | grep route

# Enumerate all IPs in a CIDR range
prips 192.168.1.0/24 | head -20

# Map IP ranges to cloud providers
for ip in $(cat resolved_ips.txt | head -20); do
  whois "$ip" 2>/dev/null | grep -iE "OrgName|Organization|netname" | head -1 | sed "s/^/$ip: /"
done
```

---

## 3. Subdomain Enumeration

### 3.1 Multi-Tool Subdomain Enumeration

```bash
# sublist3r -- search engine + DNS brute force
sublist3r -d example.com -t 50 -o subs_sublist3r.txt

# assetfinder -- multi-source aggregation
assetfinder --subs-only example.com > subs_assetfinder.txt

# dnsenum -- DNS enumeration + dictionary brute force
dnsenum -v example.com
dnsenum -f /usr/share/wordlists/subdomains-top1mil-20000.txt example.com

# fierce -- DNS brute force
fierce --domain example.com

# amass -- deep subdomain discovery
amass enum -d example.com -o subs_amass.txt
```

### 3.2 Subdomain Merging and Validation

```bash
# Merge multi-tool results and deduplicate
sort -u subs_*.txt > all_subdomains.txt

# Liveness validation (httpx)
cat all_subdomains.txt | httpx -silent -status-code -title -o live_subs.txt

# Resolve IP addresses
for sub in $(cat all_subdomains.txt); do dig +short "$sub" A; done | sort -u > sub_ips.txt

# Find unique IP ranges
cat sub_ips.txt | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u
```

### 3.3 DNS Dictionary Brute Force

```bash
# Using SecLists dictionary
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# DNS brute force using ffuf
ffuf -u https://FUZZ.example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### 3.4 Permutation-Based Subdomain Discovery

```bash
# Generate subdomain permutations for discovery
# Uses dnsgen to create permutations from known subdomains
cat all_subdomains.txt | dnsgen - | dnsx -r 8.8.8.8,1.1.1.1 -a -silent | sort -u

# Custom permutation generation
python3 -c "
import itertools
domain = 'example.com'
prefixes = ['dev', 'staging', 'api', 'admin', 'test', 'internal', 'vpn', 'mail',
            'cdn', 'git', 'ci', 'jenkins', 'jira', 'wiki', 'docs', 'app']
subs = [f'{p}.{domain}' for p in prefixes]
subs += [f'{a}-{b}.{domain}' for a, b in itertools.combinations(prefixes[:6], 2)]
print('\n'.join(subs))
" | dnsx -silent -a | sort -u
```

---

## 4. Technology Fingerprinting

### 4.1 Web Fingerprinting

```bash
# whatweb comprehensive identification
whatweb -v http://target

# Batch identification
whatweb -i live_subs.txt -v

# Identify specific information
whatweb http://target --color=never | grep -E "CMS|Framework|Server"
```

### 4.2 CMS-Specific Scanning

```bash
# WordPress comprehensive scan
wpscan --url http://target --enumerate u,p,t --api-token [TOKEN]

# Drupal detection
droopescan scan drupal -u http://target

# Joomla detection
joomscan -u http://target
```

### 4.3 HTTP Header Analysis

```bash
# Get server headers
curl -I http://target

# Get full response headers
curl -sI http://target | head -n 20

# Detect security headers
curl -sI http://target | grep -iE "X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy"
```

### 4.4 Wappalyzer / Manual Fingerprinting

```bash
# Identify framework based on favicon hash
curl -s http://target/favicon.ico | md5sum

# Check robots.txt
curl -s http://target/robots.txt

# Check sitemap.xml
curl -s http://target/sitemap.xml

# Check common path disclosures
for path in /.git/HEAD /.svn/entries /.env /wp-config.php /config.php /server-status; do
  echo -n "$path: "
  curl -s -o /dev/null -w "%{http_code}" "http://target$path"
  echo
done
```

### 4.5 JavaScript File Analysis for Hidden Endpoints

```bash
# Download and analyze JavaScript files for API endpoints and secrets
curl -s http://target/app.js | grep -oP '(https?://[^\s"'\''<>]+|/api/[^\s"'\''<>]+)' | sort -u

# Extract API keys from JavaScript using regex patterns
curl -s http://target/app.js | grep -oP '(api[_-]?key|token|secret|password|bearer)\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]' -i

# Batch download JS files from target and search for sensitive data
for js_url in $(curl -s http://target | grep -oP 'src="[^"]*\.js[^"]*"' | cut -d'"' -f2); do
  echo "=== $js_url ==="
  curl -s "http://target${js_url}" | grep -iE "api.key|secret|token|password|endpoint"
done
```

---

## 5. Email Harvesting

### 5.1 theHarvester

```bash
# Harvest from all search engines
theHarvester -d example.com -b all

# Specify search engines
theHarvester -d example.com -b google,bing,linkedin

# DNS brute force mode
theHarvester -d example.com -b dns

# Export results
theHarvester -d example.com -b all -f results.html
```

### 5.2 Email Format Guessing

```bash
# Common email formats
# firstname.lastname@example.com
# f.lastname@example.com
# firstnamel@example.com
# flastname@example.com

# Using hunter.io API
curl "https://api.hunter.io/v2/email-finder?domain=example.com&api_key=[API_KEY]"
```

### 5.3 Email Verification and SMTP Enumeration

```bash
# Verify email existence via SMTP VRFY/RCPT TO commands
python3 -c "
import smtplib, sys

server = smtplib.SMTP(timeout=10)
server.connect('mail.example.com', 25)
server.ehlo()

# Try VRFY command (often disabled but worth testing)
code, msg = server.veriy('admin@example.com')
print(f'VRFY: {code} {msg.decode()}')

# Try RCPT TO enumeration
server.mail('test@example.com')
code, msg = server.rcpt('target@example.com')
if code == 250:
    print('[+] Email exists (RCPT TO accepted)')
elif code == 550:
    print('[-] Email does not exist (RCPT TO rejected)')
else:
    print(f'[?] Unexpected response: {code} {msg.decode()}')
server.quit()
"

---

## 6. Social Media OSINT

### 6.1 Social Media Search

```bash
# LinkedIn employee enumeration
theHarvester -d example.com -b linkedin

# Google social media search
site:linkedin.com/company "example.com"
site:twitter.com "example.com"

# GitHub code leak detection
site:github.com "example.com" password OR secret OR api_key
site:github.com "example.com" .env OR config

# Pastebin leak detection
site:pastebin.com "example.com"
```

### 6.2 recon-ng Social Media Module

```bash
recon-ng
> marketplace install all
> use recon/profiles-profiles/profiler
> set source example.com
> run
```

### 6.3 LinkedIn Employee Enumeration via Google Dorks

```bash
# Find employees by role at target company
site:linkedin.com/in "Example Corp" "engineer"
site:linkedin.com/in "Example Corp" "administrator"
site:linkedin.com/in "Example Corp" "CTO" OR "CISO" OR "IT Manager"

# Find email patterns from LinkedIn profiles
site:linkedin.com/in "Example Corp" "@example.com"
```

### 6.4 Twitter/X Intelligence Collection

```bash
# Search tweets mentioning target domain from employees
twscrape -u "example.com" --search "password OR internal OR vpn"

# Use snscrape for historical tweet collection
snscrape --json twitter-search "from:example.com OR about:example.com" > tweets.json

# Find employees sharing internal information
site:twitter.com "example.com" "new job" OR "excited to join"
```

---

## 7. Metadata Extraction

### 7.1 Document Metadata Analysis

```bash
# Use metagoofil to download and analyze documents
metagoofil -d example.com -t pdf,doc,xls,ppt -l 50 -n 20 -o /tmp/metadata/

# Use exiftool to extract metadata
exiftool /tmp/metadata/*.pdf

# Extract specific fields
exiftool -Creator -Author -Producer -LastModifiedBy /tmp/metadata/*.pdf
```

### 7.2 Image Metadata

```bash
# EXIF information extraction
exiftool image.jpg

# GPS coordinate extraction
exiftool -gps:all image.jpg

# Camera serial number extraction (link images to specific devices)
exiftool -SerialNumber -InternalSerialNumber -Model image.jpg
```

### 7.3 Bulk Metadata Extraction and Correlation

```bash
# Download documents from target domain and extract metadata
metagoofil -d example.com -t pdf,doc,xls,ppt -l 100 -n 50 -o /tmp/meta/

# Extract all author names from downloaded documents
exiftool -r -Creator -Author -LastModifiedBy /tmp/meta/ | grep -v "^$" | sort -u

# Extract software versions used internally
exiftool -r -Producer -Creator -Generator /tmp/meta/ | sort | uniq -c | sort -rn
```

---

## 8. Google Dorks Collection

### 8.1 Information Disclosure

```
# Directory listings
intitle:"index of" site:example.com

# Exposed database files
site:example.com filetype:sql OR filetype:db OR filetype:mdb

# Configuration file disclosure
site:example.com filetype:env OR filetype:ini OR filetype:conf OR filetype:yml

# Log file disclosure
site:example.com filetype:log

# Backup files
site:example.com filetype:bak OR filetype:old OR filetype:swp
```

### 8.2 Authentication Bypass

```
# Login pages
inurl:login OR inurl:admin site:example.com

# phpMyAdmin
inurl:phpmyadmin site:example.com

# WordPress admin
inurl:wp-admin OR inurl:wp-login site:example.com
```

### 8.3 Sensitive Data

```
# Email addresses
site:example.com intext:"@example.com"

# Internal IP addresses
site:example.com intext:"192.168." OR intext:"10.0." OR intext:"172.16."

# Password files
site:example.com intext:"password" filetype:txt OR filetype:csv

# API keys
site:example.com intext:"api_key" OR intext:"apikey" OR intext:"API_KEY"
```

### 8.4 Cameras / IoT Devices

```
# Webcams
intitle:"Live View / - AXIS" site:example.com
inurl:/view.shtml site:example.com

# Printers
intitle:"HP LaserJet" site:example.com
```

---

## 9. Directory Brute-forcing

### 9.1 gobuster

```bash
# Basic directory brute force
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# Specify extensions
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x .php,.html,.txt,.bak

# Use large dictionary
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50

# Brute force with authentication
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -U admin -P password

# Output to file
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -o gobuster_results.txt
```

### 9.2 dirb

```bash
# Basic scan
dirb http://target /usr/share/dirb/wordlists/common.txt

# With extensions
dirb http://target /usr/share/dirb/wordlists/common.txt -X .php,.html,.txt

# Output to file
dirb http://target /usr/share/dirb/wordlists/common.txt -o dirb_results.txt

# Use proxy
dirb http://target -p http://127.0.0.1:8080
```

### 9.3 ffuf

```bash
# Basic directory fuzzing
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Specify extensions
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt

# Filter by response code
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 403,404

# Filter by response size
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 1234

# Multi-threaded high-speed scan
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 100
```

---

## 10. Deep Crawling & Correlation

### 10.1 photon Crawler

```bash
# Comprehensive crawl of target website
photon -u http://target -t 50 -d 3 -e pdf,doc,xls,xlsx,pptx

# Crawl through proxy (for Caido/Burp analysis)
photon -u http://target -p http://127.0.0.1:8080 -t 30

# Extract only specific types
photon -u http://target --only-urls
```

### 10.2 recon-ng Automated Reconnaissance

```bash
# Start recon-ng
recon-ng

# Install all modules
> marketplace install all

# Domain to host
> use recon/domains-hosts/google_domain_scraper
> set source example.com
> run

# Email harvesting
> use recon/domains-contacts/email-harvester
> set source example.com
> run

# Host to IP
> use recon/hosts-hosts/resolve
> run

# Display results
> show hosts
> show contacts
```

### 10.3 Automated Recon with Final Report Generation

```bash
#!/usr/bin/env bash
# One-command recon with HTML report output
DOMAIN="${1:?Usage: $0 <domain>}"
OUT="evidence/recon-$DOMAIN-$(date +%Y%m%d)"
mkdir -p "$OUT"

echo "[*] Subdomain discovery..."
subfinder -d "$DOMAIN" -silent | sort -u > "$OUT/subdomains.txt"

echo "[*] Live host check..."
httpx -l "$OUT/subdomains.txt" -silent -status-code -title -tech-detect > "$OUT/live.txt"

echo "[*] Port scanning live hosts..."
cat "$OUT/live.txt" | awk '{print $1}' | sort -u | httpx -silent -ports 22,80,443,8080,8443

echo "[*] Generating report..."
python3 -c "
subdomains = open('$OUT/subdomains.txt').read().strip().split('\n')
live = open('$OUT/live.txt').read().strip().split('\n')
print(f'<html><body><h1>Recon Report: $DOMAIN</h1>')
print(f'<h2>Summary</h2><p>Subdomains: {len(subdomains)} | Live: {len(live)}</p>')
print(f'<h2>Live Hosts</h2><pre>{chr(10).join(live)}</pre></body></html>')
" > "$OUT/report.html"
echo "[+] Report: $OUT/report.html"
```

### 10.3 Maltego Visual Correlation

```
GUI operation workflow:
1. New graph -> add Domain entity (example.com)
2. Domain -> To DNS Names (expand subdomains)
3. DNS Name -> To IP Address (resolve IPs)
4. IP Address -> To AS Number (correlate ASN)
5. Domain -> Email Address (correlate emails)
6. Email Address -> Person (correlate people)
7. Person -> Social Media Profile (social media profiling)
```

---

## 11. Shodan & Censys Queries

### 11.1 Shodan Service Discovery

```bash
# Discover all services for an organization
shodan search "org:Example Corp" --fields ip_str,port,product,os

# Find exposed databases
shodan search "port:3306 product:MySQL org:Example Corp"
shodan search "port:5432 product:PostgreSQL org:Example Corp"
shodan search "port:27017 product:MongoDB org:Example Corp"

# Find exposed management interfaces
shodan search "port:8080 http.title:\"Dashboard\" org:Example Corp"
shodan search "port:9090 product:Cockpit org:Example Corp"
```

### 11.2 Censys Certificate Search

```bash
# Find all certificates for a domain
curl -s "https://search.censys.io/api/v2/certificates/search" \
  -H "Authorization: Bearer $CENSYS_TOKEN" \
  -d '{"q":"parsed.names: example.com","per_page":100}'

# Find expired or self-signed certificates
# Web UI: https://search.censys.io/certificates?q=parsed.names:example.com AND tags:untrusted
```

---

## 12. DNS Interrogation Deep Dive

### 12.1 DNSSEC Validation

```bash
# Check if domain uses DNSSEC
dig example.com DNSKEY +short
dig example.com DS +short

# Validate DNSSEC chain
dig +dnssec example.com @8.8.8.8
# Look for RRSIG records in response
```

### 12.2 DNS Zone Walking (NSEC)

```bash
# Walk DNS zone using NSEC records (if DNSSEC is enabled with NSEC)
dig example.com NSEC @ns1.example.com +trace

# Use ldns-walk for automated zone walking
ldns-walk example.com
```

### 12.3 Advanced DNS Reconnaissance with dnsrecon

```bash
# Comprehensive DNS reconnaissance
dnsrecon -d example.com -t std
dnsrecon -d example.com -t axfr
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Cache snooping
dnsrecon -t snoop -n 8.8.8.8 --dictionary /usr/share/seclists/Discovery/DNS/namelist.txt
```

---

## 13. Email OSINT & Breach Analysis

### 13.1 Email Pattern Discovery

```bash
# Discover email format using Hunter.io API
curl -s "https://api.hunter.io/v2/email-finder?domain=example.com&api_key=$HUNTER_KEY" | jq '.data.pattern'

# Verify email deliverability
python3 -c "
import dns.resolver
domain = 'example.com'
records = dns.resolver.resolve(domain, 'MX')
for r in records:
    print(f'MX: {r.exchange} priority={r.preference}')
"
```

### 13.2 Breach Data Correlation

```bash
# Check email against Have I Been Pwned
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com" \
  -H "hibp-api-key: $HIBP_KEY" -H "user-agent: OSINT-Research" | jq '.[].Name'

# Password breach check (k-anonymity model - only sends first 5 chars of hash)
echo -n "password123" | sha1sum | awk '{print $1}'
HASH_PREFIX=$(echo -n "password123" | sha1sum | cut -c1-5)
curl -s "https://api.pwnedpasswords.com/range/$HASH_PREFIX" | grep -i "$(echo -n "password123" | sha1sum | cut -c6-40)"
```

---

## 14. Image OSINT & Geolocation

### 14.1 Reverse Image Search

```bash
# Extract unique image identifiers for reverse search
exiftool -ImageUniqueID -DocumentID image.jpg

# Generate perceptual hash for image correlation
phash image.jpg

# Check image against Google reverse search (open in browser)
echo "https://images.google.com/searchbyimage?image_url=IMAGE_URL"
```

### 14.2 Geolocation from EXIF GPS Data

```python
# Convert GPS coordinates from EXIF to decimal degrees
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def get_gps_coordinates(image_path):
    image = Image.open(image_path)
    exif_data = image._getexif()
    if not exif_data:
        return None

    gps_info = {}
    for tag, value in exif_data.items():
        name = TAGS.get(tag, tag)
        if name == "GPSInfo":
            for gps_tag in value:
                gps_name = GPSTAGS.get(gps_tag, gps_tag)
                gps_info[gps_name] = value[gps_tag]

    def convert_to_degrees(value):
        return float(value[0]) + float(value[1]) / 60 + float(value[2]) / 3600

    if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
        lat = convert_to_degrees(gps_info["GPSLatitude"])
        lon = convert_to_degrees(gps_info["GPSLongitude"])
        if gps_info.get("GPSLatitudeRef", "N") == "S":
            lat = -lat
        if gps_info.get("GPSLongitudeRef", "E") == "W":
            lon = -lon
        return (lat, lon)
    return None

coords = get_gps_coordinates("target_image.jpg")
if coords:
    print(f"Location: {coords[0]:.6f}, {coords[1]:.6f}")
    print(f"Google Maps: https://maps.google.com/?q={coords[0]},{coords[1]}")
```

---

## 15. WHOIS Deep Analysis

### 15.1 Bulk WHOIS with Registration Pattern Analysis

```bash
# Bulk WHOIS for related domains and extract registration patterns
for domain in $(cat related_domains.txt); do
  whois "$domain" 2>/dev/null | grep -E "Registrant|Creation|Expir|Name Server" | \
    sed "s/^/$domain: /"
  sleep 2
done > whois_bulk_report.txt

# Extract registrant email addresses across multiple domains
grep -h "Registrant Email\|Admin Email" whois_bulk_report.txt | sort | uniq -c | sort -rn
```

### 15.2 WHOIS Historical Analysis

```bash
# Check domain age and registration changes via whois history
# Using DomainTools or whoisrequest.com (web-based)

# Parse WHOIS dates to determine domain lifecycle
python3 -c "
import subprocess, re
from datetime import datetime

domain = 'example.com'
whois_data = subprocess.run(['whois', domain], capture_output=True, text=True).stdout

for pattern in [r'Creation Date:\s*(.+)', r'Registry Expiry Date:\s*(.+)', r'Updated Date:\s*(.+)']:
    match = re.search(pattern, whois_data)
    if match:
        date_str = match.group(1).strip().split('T')[0]
        print(f'{pattern.split(\":\")[0]}: {date_str}')

# Calculate domain age
created = re.search(r'Creation Date:\s*(.+?)(?:\n|T)', whois_data)
if created:
    created_date = datetime.strptime(created.group(1).strip()[:10], '%Y-%m-%d')
    age_days = (datetime.utcnow() - created_date).days
    print(f'Domain age: {age_days} days ({age_days/365:.1f} years)')
"
```

---

## 16. Automated Reconnaissance Correlation

### 16.1 Full Recon Pipeline with Reporting

```python
#!/usr/bin/env python3
"""Correlate all reconnaissance results into a single intelligence report."""

import json
import subprocess
from pathlib import Path

def run_recon_correlation(domain, output_dir):
    """Run multi-tool recon and correlate results."""
    results_dir = Path(output_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    report = {"domain": domain, "findings": {}}

    # Subdomain enumeration
    subs = set()
    for tool_output in results_dir.glob("subs-*.txt"):
        for line in tool_output.read_text().splitlines():
            if domain in line:
                subs.add(line.strip())

    # Certificate transparency
    try:
        ct_raw = subprocess.run(
            ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json"],
            capture_output=True, text=True, timeout=30
        ).stdout
        ct_domains = set(e["name_value"] for e in json.loads(ct_raw)) if ct_raw else set()
        subs.update(ct_domains)
    except Exception:
        pass

    report["findings"]["total_subdomains"] = len(subs)
    report["findings"]["subdomains"] = sorted(subs)[:100]

    # Write report
    report_path = results_dir / "correlation_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"[+] Report: {report_path} ({len(subs)} subdomains found)")
    return report
```
