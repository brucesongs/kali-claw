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
