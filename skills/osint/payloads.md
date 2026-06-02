# OSINT Payloads / attackpayloadlargeall

> thisfileis `SKILL.md` Supplementary Files，containsall OSINT commandandattackpayload，byclassotherorganization。

---

## 1. domain name / WHOIS reconnaissance / Domain & WHOIS Reconnaissance

```bash
# basic WHOIS query
whois example.com

# queryregister商information
whois -H example.com | grep -i "registrar\|name server\|creation\|expir"

# reverse WHOIS（throughregisterpersonfinditsotherdomain name）
# useonlineTool：whois.domaintools.com or viewdns.info

# WHOIS historyrecord
# DomainTools WHOIS History or whoisrequest.com
```

```bash
# domain name年龄andstatuscheck
whois example.com | grep -E "Creation Date|Expiry Date|Domain Status"
```

---

## 2. DNS Enumerate / DNS Enumeration

```bash
# queryall DNS record
dig any example.com @8.8.8.8

# queryspecificrecordtype
dig a example.com +short
dig mx example.com +short
dig ns example.com +short
dig txt example.com +short
dig soa example.com +short

# DNS zone transferattempt（oftenbydisablebutValue得attempt）
dig axfr example.com @ns1.example.com

# use dnsx batchamountsolveanalysis
dnsx -d example.com -a -silent
dnsx -d example.com -a -aaaa -cname -mx -ns -txt -silent

# reverse DNS query
dig -x <IP> @8.8.8.8
```

```bash
# DNS cachedetect
dig example.com +trace

# DNSSEC check
dig example.com DNSKEY +short
dig example.com DS +short
```

---

## 3. subdomain enumeration / Subdomain Enumeration

### subfinder

```bash
# basic bydynamicEnumerate
subfinder -d example.com -o subs_subfinder.txt

# enableall datasource
subfinder -d example.com -all -o subs_all.txt

# recursiveEnumerate
subfinder -d example.com -recursive -o subs_recursive.txt

# bandpart辨rateverify
subfinder -d example.com -o subs.txt && dnsx -l subs.txt -a -silent
```

### amass

```bash
# bydynamicEnumeratemode
amass enum -passive -d example.com -o subs_amass.txt

# maindynamicEnumerate（with DNS solveanalysis）
amass enum -active -d example.com -o subs_amass_active.txt

# brute forcemode
amass enum -brute -d example.com -o subs_amass_brute.txt

# usefromdefinitiondictionary
amass enum -brute -d example.com -w /path/to/wordlist.txt -o subs_custom.txt

# onlydisplaysolveanalysis subdomain name
amass enum -passive -d example.com -o subs.txt && amass track -d example.com
```

### gobuster dns

```bash
# DNS brute force
gobuster dns -d example.com -w /usr/share/wordlists/subdomains-top1mil-20000.txt

# bandsolveanalysisandspeedratecontrol
gobuster dns -d example.com -w /usr/share/wordlists/subdomains-top1mil-20000.txt -t 50 --delay 100ms

# usefromdefinition resolver
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8,1.1.1.1
```

### multipleToolcrossEnumerate

```bash
# mergededuplicateandverify
subfinder -d example.com -o subs_subfinder.txt
amass enum -passive -d example.com -o subs_amass.txt
sort -u subs_*.txt | httpx -silent -status-code -title

# complete flow水line
subfinder -d example.com -silent | dnsx -silent | httpx -silent -status-code -title -tech-detect
```

---

## 4. Google Dorking 运calculatecharacter / Google Dorking Operators

### basic 运calculatecharacter

```
site:example.com                    # 限定目标域名
inurl:admin                         # URL 中包含关键词
intitle:"index of"                  # 页面标题包含关键词
filetype:pdf                        # 搜索特定文件类型
intext:"password"                   # 页面正文包含关键词
cache:example.com                   # 查看缓存页面
link:example.com                    # 链接到目标的页面
related:example.com                 # 相似网站
```

### informationleakage Dork

```
# exposure directorylist
site:example.com intitle:"index of" "parent directory"

# exposure configurationfile
site:example.com filetype:env OR filetype:yml OR filetype:ini "password"

# exposure databasefile
site:example.com filetype:sql OR filetype:db OR filetype:mdb

# exposure logfile
site:example.com filetype:log inurl:"log"

# exposure backupfile
site:example.com filetype:bak OR filetype:backup OR filetype:old

# loginpage
site:example.com inurl:login OR inurl:admin OR inurl:dashboard
```

### credentialssearch Dork

```
# publicdocumentationin sensitiveinformation
site:example.com filetype:xlsx OR filetype:csv "password" OR "username"

# GitHub on leakage
"example.com" password OR secret OR api_key site:github.com

# Paste sitepointleakage
site:pastebin.com "example.com"
site:paste.ee "example.com"
```

---

## 5. email addresscollect / Email Harvesting

### theHarvester

```bash
# alldatasourceemail addresscollect
theHarvester -d example.com -b all

# specificdatasource
theHarvester -d example.com -b google
theHarvester -d example.com -b bing
theHarvester -d example.com -b linkedin
theHarvester -d example.com -b twitter
theHarvester -d example.com -b hunter
theHarvester -d example.com -b crtsh

# export HTML report
theHarvester -d example.com -b all -f recon_report.html

# use DNS solveanalysis
theHarvester -d example.com -b all -n
```

### h8mail

```bash
# singleemail addressleakagecheck
h8mail -t target@email.com

# entiredomain nameleakagecheck
h8mail -t @targetdomain.com -l local

# fromfilebatchamountcheck
h8mail -t @targetdomain.com -l local -o leaks.json

# specifydatasource
h8mail -t user@example.com -c config.ini
```

### Holehe

```bash
# checkemail addressin 120+ service registersituation
holehe user@example.com

# batchamountcheck
for email in user1@example.com user2@example.com; do
  holehe "$email"
done
```

### PGP keysearch

```bash
# through PGP keyserversearchemail address
gpg --search-keys user@example.com

# useonline PGP search
# https://keys.openpgp.org/
# https://keyserver.ubuntu.com/
```

---

## 6. social mediaintelligence / Social Media Intelligence

### Sherlock - crossplatformusernamesearch

```bash
# singleusernamesearch
sherlock username

# multipleusernamesearch
sherlock user1 user2 user3

# JSON output
sherlock username --json

# outputtofile
sherlock user1 user2 user3 --json -o social_accounts.json

# specifysitepoint
sherlock username --site twitter --site github
```

### theHarvester socialexchangesearch

```bash
# LinkedIn employeesearch
theHarvester -d "Company Name" -b linkedin

# Twitter related
theHarvester -d example.com -b twitter
```

### PhoneInfoga - phone numberintelligence

```bash
# singlenumbercodeScan
phoneinfoga -n +1234567890 -s all

# batchamountScan
phoneinfoga -i numbers.txt -s all -o results.json

# Web interfacemode
phoneinfoga serve -p 8080
```

---

## 7. metadata extraction / Metadata Extraction

### exiftool

```bash
# Extractfilemetadata
exiftool document.pdf
exiftool image.jpg

# batchamountExtractdirectoryinall file metadata
exiftool -r /path/to/files/

# ExtractspecificField
exiftool -Creator -Author -Producer -LastModifiedBy document.pdf

# GPS coordinatesExtract
exiftool -gps:all image.jpg

# deletemetadata（defensePurpose）
exiftool -all= document.pdf
exiftool -all= image.jpg

# Extract Word documentationfix订history
exiftool -LastModifiedBy -Creator -ModifyDate document.docx
```

### FOCA（Windows GUI Tool）

```
# throughsearchenginebatchamountExtractdocumentationmetadata
# searchtargetdomain name .pdf, .docx, .xlsx file
# Extractusername、printmachinename、path、softwarepieceversionetc.information
```

### mat2（metadata匿nameize）

```bash
# viewmetadata
mat2 -s document.pdf

# clearmetadata
mat2 document.pdf
```

---

## 8. Shodan / Censys query / Shodan & Censys Queries

### Shodan

```bash
# initialize API Key
shodan init <API_KEY>

# searchorganizationasset
shodan search "org:Example Corp"

# view IP details
shodan host <IP>

# searchspecificportandservice
shodan search "port:3389 org:Example Corp"
shodan search "port:22 org:Example Corp"
shodan search "port:443 ssl.cert.subject.cn:example.com"

# searchspecificdevice
shodan search "product:Apache httpd"
shodan search "product:nginx version:1.18"

# searchexposure service
shodan search "port:3306 mysql"
shodan search "port:5432 postgresql"
shodan search "port:27017 mongodb"
shodan search "port:6379 redis"

# searchvulnerabilitydevice
shodan search "vuln:CVE-2021-44228"
shodan search "vuln:CVE-2023-44487"

# statisticssearchresult
shodan count "org:Example Corp"
shodan stats "org:Example Corp"

# facilitysearch
shodan search "net:<CIDR>"

# exportsearchresult
shodan download results "org:Example Corp" --limit 100
shodan parse --fields ip_str,port,org,hostnames results.json.gz
```

### Censys

```bash
# searchcertificate（Web UI）
# https://search.censys.io/certificates?q=parsed.names:example.com

# searchhost
# https://search.censys.io/hosts?q=services.tls.certificates.leaf.names:example.com

# oftenuse Censys querysyntax
# services.port:443 AND services.tls.certificates.leaf.names:example.com
# services.software.product:nginx AND location.country_code:CN
# services.port:3389 AND autonomous_system.name:EXAMPLE-CORP
```

---

## 9. techniquefingerprinting / Technology Fingerprinting

### whatweb

```bash
# singletargetIdentify
whatweb example.com

# 聚combinelevelotherScan
whatweb -a 3 example.com

# batchamountScan
whatweb -i urls.txt -o results.txt

# detailed output
whatweb -v example.com

# JSON output
whatweb example.com --output json -o results.json

# searchspecifictechnique
whatweb -s "WordPress,PHP,nginx" example.com
```

### Wappalyzer（browsetoolextension + CLI）

```bash
# CLI use（wappalyzer-cli）
wappalyzer https://example.com

# browsetoolextension：directaccesstargetwebsiteviewDetectresult
```

### httpx techniqueDetect

```bash
# batchamounttechniqueDetect
httpx -l subdomains.txt -silent -tech-detect -status-code -title

# complete fingerprint
httpx -l subdomains.txt -silent -tech-detect -status-code -title -server -content-length -web-server
```

### HTTP responseheadanalysis

```bash
# HTTP responseheadanalysis
curl -sI https://example.com | grep -i "server\|x-powered-by\|x-aspnet"

# Cookie characteristicanalysis
curl -sI https://example.com | grep -i "set-cookie"
```

---

## 10. GitHub codeleakagesearch / GitHub Code Leak Search

```bash
# searchorganizationsensitivefile
curl -s "https://api.github.com/search/code?q=org:target+filename:.env" | jq '.items[].html_url'
curl -s "https://api.github.com/search/code?q=org:target+password+in:file" | jq '.items[].html_url'

# batchamountsearchcriticalcredentialscritical词
for keyword in password secret api_key token private_key aws_access_key; do
  curl -s "https://api.github.com/search/code?q=org:target+${keyword}+in:file" | jq '.items[].html_url'
done

# searchspecificrepositorylibraryin sensitiveinformation
curl -s "https://api.github.com/search/code?q=repo:owner/repo+secret+in:path" | jq '.items[].html_url'

# downloadcan suspiciousrepositorylibrarydeep analysis
git-dumper https://github.com/target/suspicious-repo /tmp/audit
grep -rn "password\|api_key\|secret\|token\|aws_" /tmp/audit/ --include="*.yml" --include="*.env" --include="*.json"

# leakagedatabasequery
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>" -H "hibp-api-key: <KEY>"
```

---

## 11. SpiderFoot allautomated Scan / SpiderFoot Automated Scanning

```bash
# bydynamicmodeScan（not接触target）
spiderfoot -s example.com -t INTERNET_NAME,DNS_ANY,SUBDOMAIN_HTTPS -u passive

# allmoduleScan
spiderfoot -s example.com -t ALL -u passive -o json > full_osint.json

# Web UI mode
spiderfoot -l 127.0.0.1:5001
```

---

## 12. Recon-ng automated flow水line / Recon-ng Automated Pipeline

```bash
# startandcreateworkworkzone
recon-ng
[recon-ng] > workspaces create target_recon

# addtargetdomain name
[recon-ng] > add domains example.com

# subdomain enumerationmodulechain
[recon-ng] > use recon/domains-hosts/brute_hosts
[recon-ng] > run
[recon-ng] > use recon/hosts-hosts/resolve
[recon-ng] > run

# email addresscollect
[recon-ng] > use recon/domains-contacts/email-harvester
[recon-ng] > set source example.com
[recon-ng] > run

# exportresult
[recon-ng] > show hosts
[recon-ng] > show contacts
[recon-ng] > export csv /tmp/recon_results.csv
```

---

## 13. certificatetransparentdegreequery / Certificate Transparency

```bash
# crt.sh query
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value' | sort -u

# through theHarvester query
theHarvester -d example.com -b crtsh

# use certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true" | jq '.[].dns_names[]'
```

---

## 14. GitHub OSINT

```bash
# Search for leaked credentials in repos
gh search code "target.com password" --limit 20
gh search code "target.com api_key" --limit 20
gh search code "target.com secret" --limit 20

# Find employee accounts
gh search users "target-company" --limit 50

# Search commit messages for sensitive info
gh search commits "fix password" --owner target-org --limit 20

# Trufflehog for secret scanning
trufflehog github --org=target-org --only-verified
```

---

## 15. Infrastructure Fingerprinting

```bash
# Shodan CLI queries
shodan search "hostname:target.com" --fields ip_str,port,org,os
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,product
shodan search "http.title:target" --fields ip_str,port,http.title

# Censys search
censys search "services.tls.certificates.leaf.subject.common_name: target.com" --index-type hosts

# DNS zone transfer attempt
dig axfr target.com @ns1.target.com

# ASN lookup and IP range discovery
whois -h whois.radb.net -- '-i origin AS12345' | grep route
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix'
```

---

## 16. People OSINT

```bash
# Email format discovery
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_KEY" \
  | jq '{pattern: .data.pattern, emails: [.data.emails[].value]}'

# LinkedIn enumeration (via Google)
site:linkedin.com/in "target company" "security engineer"
site:linkedin.com/in "target company" "DevOps"

# Breach data check (ethical - only for authorized testing)
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/target@target.com" \
  -H "hibp-api-key: $HIBP_KEY" | jq '.[].Name'

# Social media correlation
sherlock targetusername --print-found --output sherlock_results.txt
```

---

## 17. Automated OSINT Pipeline

```python
import subprocess
import json
from pathlib import Path

def run_osint_pipeline(domain, output_dir="./osint_results"):
    Path(output_dir).mkdir(exist_ok=True)
    results = {}

    # Phase 1: DNS & Subdomains
    subs = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True, text=True
    ).stdout.strip().split("\n")
    results["subdomains"] = subs
    Path(f"{output_dir}/subdomains.txt").write_text("\n".join(subs))

    # Phase 2: WHOIS
    whois_data = subprocess.run(
        ["whois", domain], capture_output=True, text=True
    ).stdout
    results["whois"] = whois_data
    Path(f"{output_dir}/whois.txt").write_text(whois_data)

    # Phase 3: Certificate Transparency
    import requests
    ct_resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    ct_domains = list(set(e["name_value"] for e in ct_resp.json())) if ct_resp.ok else []
    results["ct_domains"] = ct_domains

    # Phase 4: Technology detection
    tech = subprocess.run(
        ["httpx", "-l", f"{output_dir}/subdomains.txt", "-tech-detect", "-silent", "-json"],
        capture_output=True, text=True
    ).stdout
    results["technologies"] = [json.loads(l) for l in tech.strip().split("\n") if l]

    return results
```

---

## 18. Metadata Extraction

```bash
# Image EXIF data extraction
exiftool image.jpg | grep -iE "gps|date|camera|software|author"

# PDF metadata
exiftool document.pdf | grep -iE "author|creator|producer|create date|modify"
pdfinfo document.pdf

# Office document metadata
exiftool document.docx | grep -iE "author|company|manager|created|modified"

# Bulk metadata extraction from downloaded files
find ./downloads -type f \( -name "*.pdf" -o -name "*.docx" -o -name "*.jpg" \) \
  -exec exiftool -csv {} + > metadata_report.csv
```

---

## 19. Dark Web & Leak Monitoring

```bash
# IntelX API search
curl -s "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"term\":\"target.com\",\"maxresults\":20,\"media\":0}" | jq '.records[].systemid'

# Dehashed API (credential leak search)
curl -s "https://api.dehashed.com/search?query=domain:target.com" \
  -u "$DEHASHED_EMAIL:$DEHASHED_KEY" | jq '.entries[] | {email, password: .hashed_password}'

# Google dorking for leaked data
site:pastebin.com "target.com"
site:trello.com "target.com" password
site:docs.google.com "target.com" confidential
```

---

## 20. Source Verification & Data Correlation

### Cross-Reference OSINT Data Sources

```python
#!/usr/bin/env python3
"""Correlate findings from multiple OSINT sources and deduplicate."""

import json
from collections import defaultdict

def correlate_osint_sources(*source_files):
    """Merge and correlate results from multiple OSINT tool outputs."""
    all_domains = defaultdict(lambda: {"sources": [], "ips": set(), "status": set()})

    for filepath in source_files:
        source_name = filepath.split("/")[-1].replace(".txt", "")
        with open(filepath) as f:
            for line in f:
                domain = line.strip().lower()
                if domain:
                    all_domains[domain]["sources"].append(source_name)

    # Domains found by multiple sources have higher confidence
    correlated = []
    for domain, data in sorted(all_domains.items()):
        source_count = len(set(data["sources"]))
        correlated.append({
            "domain": domain,
            "sources": list(set(data["sources"])),
            "source_count": source_count,
            "confidence": "HIGH" if source_count >= 3 else "MEDIUM" if source_count == 2 else "LOW"
        })

    return sorted(correlated, key=lambda x: x["source_count"], reverse=True)
```

### Automated OSINT Monitoring Script

```bash
#!/usr/bin/env bash
# Periodic OSINT monitoring for new subdomains and changes
# Usage: ./osint_monitor.sh <domain> <interval_seconds>

DOMAIN="${1:?Usage: $0 <domain> <interval>}"
INTERVAL="${2:-3600}"
STATE_DIR="evidence/osint-monitor/$DOMAIN"
mkdir -p "$STATE_DIR"

while true; do
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    echo "[MONITOR] $(date -Iseconds) - Running OSINT check for $DOMAIN"

    # Discover subdomains
    subfinder -d "$DOMAIN" -silent | sort -u > "$STATE_DIR/subs-current.txt"

    # Check for new subdomains
    if [ -f "$STATE_DIR/subs-baseline.txt" ]; then
        NEW_SUBS=$(comm -13 "$STATE_DIR/subs-baseline.txt" "$STATE_DIR/subs-current.txt")
        if [ -n "$NEW_SUBS" ]; then
            echo "[ALERT] New subdomains detected:"
            echo "$NEW_SUBS" | tee "$STATE_DIR/new-subs-${TIMESTAMP}.txt"
        fi
    fi

    # Update baseline
    cp "$STATE_DIR/subs-current.txt" "$STATE_DIR/subs-baseline.txt"

    # Certificate transparency check
    curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | \
      jq -r '.[].name_value' | sort -u > "$STATE_DIR/ct-current.txt"

    sleep "$INTERVAL"
done
```

---

## 21. Geolocation & Physical OSINT

### IP Geolocation and ASN Mapping

```bash
# Batch IP geolocation lookup
while IFS= read -r ip; do
    geo=$(curl -s "http://ip-api.com/json/${ip}" 2>/dev/null)
    country=$(echo "$geo" | jq -r '.country // "unknown"')
    city=$(echo "$geo" | jq -r '.city // "unknown"')
    org=$(echo "$geo" | jq -r '.org // "unknown"')
    echo "$ip,$country,$city,$org"
done < ips.txt | tee geolocation_results.csv

# ASN enumeration for target organization
curl -s "https://api.bgpview.io/search?queryTerm=Example+Corp" | \
  jq '.data.asns[] | {asn: .asn, name: .name, description: .description}'

# Reverse IP to domain lookup
for ip in $(cat resolved_ips.txt); do
    curl -s "https://api.hackertarget.com/reverseiplookup/?q=${ip}" 2>/dev/null
    sleep 0.5
done
```

### Wi-Fi Geolocation Database Query

```bash
# Query Wigle.net WiFi geolocation API for BSSID location
curl -s "https://api.wigle.net/api/v2/network/search?ssid=TargetSSID" \
  -u "API_NAME:API_TOKEN" | jq '.results[] | {ssid: .ssid, lat: .trilat, lon: .trilon}'
```

---

## 22. Breach Data Analysis

### Credential Leak Pattern Analysis

```python
#!/usr/bin/env python3
"""Analyze breached credential data for password patterns and policy weaknesses."""

import re
from collections import Counter

def analyze_password_patterns(credential_file):
    """Analyze leaked credentials for password strength patterns."""
    patterns = {
        "length_<8": 0, "length_8-12": 0, "length_12+": 0,
        "has_uppercase": 0, "has_lowercase": 0, "has_digit": 0,
        "has_special": 0, "common_base": Counter(), "seasonal": 0
    }
    total = 0
    common_bases = ["password", "welcome", "admin", "qwerty", "letmein",
                    "monkey", "dragon", "master", "login", "abc123"]
    seasons = ["spring", "summer", "fall", "winter", "2024", "2025", "2026"]

    with open(credential_file) as f:
        for line in f:
            parts = line.strip().split(":", 1)
            if len(parts) < 2:
                continue
            pwd = parts[1]
            total += 1

            if len(pwd) < 8:
                patterns["length_<8"] += 1
            elif len(pwd) <= 12:
                patterns["length_8-12"] += 1
            else:
                patterns["length_12+"] += 1

            if re.search(r'[A-Z]', pwd):
                patterns["has_uppercase"] += 1
            if re.search(r'[a-z]', pwd):
                patterns["has_lowercase"] += 1
            if re.search(r'\d', pwd):
                patterns["has_digit"] += 1
            if re.search(r'[^A-Za-z0-9]', pwd):
                patterns["has_special"] += 1

            pwd_lower = pwd.lower()
            for base in common_bases:
                if base in pwd_lower:
                    patterns["common_base"][base] += 1
            if any(s in pwd_lower for s in seasons):
                patterns["seasonal"] += 1

    print(f"Total credentials analyzed: {total}")
    for key, val in patterns.items():
        if isinstance(val, int):
            print(f"  {key}: {val} ({val*100/max(total,1):.1f}%)")
        elif isinstance(val, Counter):
            for k, v in val.most_common(5):
                print(f"  {key}[{k}]: {v}")
```

---

## 23. Automated OSINT Pipeline (Enhanced)

### Full-Spectrum OSINT with Error Handling

```bash
#!/usr/bin/env bash
# Complete OSINT pipeline with rate limiting and error handling

DOMAIN="${1:?Usage: $0 <domain>}"
OUTPUT="evidence/osint-full-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT"
LOG="$OUTPUT/pipeline.log"

echo "[PIPELINE] Starting full OSINT for $DOMAIN at $(date)" | tee "$LOG"

# Phase 1: WHOIS
echo "[1/8] WHOIS lookup" | tee -a "$LOG"
whois "$DOMAIN" > "$OUTPUT/whois.txt" 2>&1 || echo "[WARN] WHOIS failed" | tee -a "$LOG"
sleep 2

# Phase 2: DNS
echo "[2/8] DNS enumeration" | tee -a "$LOG"
dig any "$DOMAIN" +noall +answer > "$OUTPUT/dns-records.txt" 2>&1
dig axfr "$DOMAIN" @ns1."$DOMAIN" > "$OUTPUT/dns-zone-transfer.txt" 2>&1
sleep 1

# Phase 3: Subdomains
echo "[3/8] Subdomain enumeration" | tee -a "$LOG"
subfinder -d "$DOMAIN" -silent > "$OUTPUT/subs-subfinder.txt" 2>&1 || true
amass enum -passive -d "$DOMAIN" -o "$OUTPUT/subs-amass.txt" 2>/dev/null || true
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u > "$OUTPUT/subs-crtsh.txt" 2>/dev/null || true
sort -u "$OUTPUT"/subs-*.txt > "$OUTPUT/subs-all.txt" 2>/dev/null || true
echo "  Found $(wc -l < "$OUTPUT/subs-all.txt" 2>/dev/null || echo 0) unique subdomains" | tee -a "$LOG"

# Phase 4: Live host check
echo "[4/8] Live host verification" | tee -a "$LOG"
httpx -l "$OUTPUT/subs-all.txt" -silent -status-code -title -tech-detect \
  -o "$OUTPUT/live-hosts.txt" 2>/dev/null || true

# Phase 5: Technology fingerprint
echo "[5/8] Technology fingerprinting" | tee -a "$LOG"
whatweb -i "$OUTPUT/subs-all.txt" -o "$OUTPUT/whatweb.txt" 2>/dev/null || true

# Phase 6: Email harvesting
echo "[6/8] Email harvesting" | tee -a "$LOG"
theHarvester -d "$DOMAIN" -b all -f "$OUTPUT/harvester.html" 2>/dev/null || true

# Phase 7: Shodan lookup
echo "[7/8] Shodan lookup" | tee -a "$LOG"
shodan search "hostname:$DOMAIN" --fields ip_str,port,product 2>/dev/null > "$OUTPUT/shodan.txt" || true

# Phase 8: GitHub leak check
echo "[8/8] GitHub leak search" | tee -a "$LOG"
curl -s "https://api.github.com/search/code?q=${DOMAIN}+password+in:file" | \
  jq '.items[].html_url' > "$OUTPUT/github-leaks.txt" 2>/dev/null || true

echo "[PIPELINE] Complete at $(date)" | tee -a "$LOG"
echo "Results: $OUTPUT/"
```

---

## 24. Advanced Search Operators

### Specialized Google Dork Collections

```bash
# Find exposed Git repositories
site:example.com inurl:".git" HEAD
site:example.com filetype:git

# Find exposed phpMyAdmin installations
inurl:phpmyadmin intitle:"Welcome to phpMyAdmin" site:example.com

# Find exposed Jenkins instances
intitle:"Dashboard [Jenkins]" site:example.com

# Find exposed Kubernetes dashboards
intitle:"Kubernetes Dashboard" site:example.com

# Find exposed Grafana dashboards
intitle:"Grafana" inurl:3000 site:example.com
```

### API-Based Intelligence Gathering

```python
#!/usr/bin/env python3
"""Aggregate intelligence from multiple OSINT APIs."""

import requests
import json

class OSINTAggregator:
    def __init__(self, shodan_key=None, hunter_key=None, hibp_key=None):
        self.shodan_key = shodan_key
        self.hunter_key = hunter_key
        self.hibp_key = hibp_key

    def shodan_host_search(self, query, limit=100):
        """Search Shodan for hosts matching a query."""
        if not self.shodan_key:
            return []
        url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query={query}"
        resp = requests.get(url, timeout=30)
        if resp.ok:
            return [{"ip": m["ip_str"], "port": m["port"],
                     "product": m.get("product", ""), "os": m.get("os", "")}
                    for m in resp.json().get("matches", [])[:limit]]
        return []

    def hunter_domain_search(self, domain):
        """Find email addresses and patterns for a domain."""
        if not self.hunter_key:
            return {}
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.hunter_key}"
        resp = requests.get(url, timeout=30)
        if resp.ok:
            data = resp.json().get("data", {})
            return {"pattern": data.get("pattern"), "emails": [e["value"] for e in data.get("emails", [])]}
        return {}

    def full_recon(self, domain):
        """Run full OSINT recon across all configured APIs."""
        results = {"domain": domain}
        results["shodan"] = self.shodan_host_search(f"hostname:{domain}")
        results["emails"] = self.hunter_domain_search(domain)
        return results
```

---

## 25. Dark Web Research Methods

### Onion Service Enumeration

```bash
# Tor proxy setup for safe dark web research
# Configure tor proxy
echo "SocksPort 9050" | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor

# Verify Tor connectivity
curl --socks5 localhost:9050 https://check.torproject.org/ | grep "Congratulations"

# Search Ahmia (Tor search engine) for mentions of target
curl --socks5-hostname localhost:9050 -s "https://ahmia.fi/search/?q=target.com" | \
  grep -oP 'http[s]?://[a-z2-7]{16}\.onion[^"<>]*'

# Dark web credential monitoring (authorized testing only)
# Use tools like darkdump for .onion site content retrieval
darkdump -s "target.com credentials" -t 10
```

### Paste Site Monitoring

```bash
# Monitor paste sites for target mentions
for site in "pastebin.com" "paste.ee" "justpaste.it" "controlc.com"; do
  echo "[MONITOR] Checking $site for target.com mentions"
  curl -s "https://www.google.com/search?q=site:$site+%22target.com%22+password" \
    -H "User-Agent: Mozilla/5.0" | grep -oP "$site/[a-zA-Z0-9]+" | sort -u
  sleep 2
done

# Automated paste site alert script
PASTEBIN_API_KEY="$PASTE_KEY"
curl -s "https://scrape.pastebin.com/api_scraping.php?api_key=${PASTEBIN_API_KEY}&limit=100" | \
  jq '.[].full_url' | while read url; do
    content=$(curl -s "$url")
    if echo "$content" | grep -qi "target.com"; then
      echo "[ALERT] Target mention found: $url"
    fi
  done
```

---

## 26. Visualization and Reporting

### OSINT Data Visualization with Python

```python
#!/usr/bin/env python3
"""Generate visual reports from OSINT data collection."""

import json
from collections import Counter

def generate_subdomain_heatmap(subdomains_file, output_file="subdomain_report.txt"):
    """Generate a text-based report showing subdomain distribution."""
    with open(subdomains_file) as f:
        subs = [line.strip() for line in f if line.strip()]

    # Count subdomains by second-level grouping
    segments = Counter()
    for sub in subs:
        parts = sub.split(".")
        if len(parts) >= 3:
            segments[parts[0]] += 1
        else:
            segments["(root)"] += 1

    report = ["=" * 60, "Subdomain Distribution Report", "=" * 60, ""]
    max_count = max(segments.values()) if segments else 1
    for prefix, count in segments.most_common(30):
        bar_len = int(count / max_count * 40)
        report.append(f"  {prefix:<20} {'#' * bar_len} ({count})")

    report.append(f"\nTotal: {len(subs)} subdomains, {len(segments)} unique prefixes")
    with open(output_file, "w") as out:
        out.write("\n".join(report))
    print(f"[+] Report saved to {output_file}")
```

### Finding Correlation Timeline

```python
def build_osint_timeline(events, output="timeline_report.txt"):
    """Build a chronological timeline from OSINT findings."""
    sorted_events = sorted(events, key=lambda e: e.get("date", "0000"))

    lines = ["OSINT Investigation Timeline", "=" * 50]
    for event in sorted_events:
        date = event.get("date", "unknown")
        source = event.get("source", "unknown")
        finding = event.get("finding", "no description")
        severity = event.get("severity", "info")
        marker = "[!]" if severity in ("critical", "high") else "[.]"
        lines.append(f"{marker} {date} [{source}] {finding}")

    with open(output, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Timeline saved to {output} ({len(sorted_events)} events)")
```

---

## 27. Source Verification

### Cross-Validate OSINT Findings

```bash
# Verify subdomain findings across multiple sources
comm -23 <(sort subs_subfinder.txt) <(sort subs_amass.txt) | wc -l
echo "Subdomains only in subfinder: $(comm -23 <(sort subs_subfinder.txt) <(sort subs_amass.txt) | wc -l)"
echo "Subdomains only in amass: $(comm -13 <(sort subs_subfinder.txt) <(sort subs_amass.txt) | wc -l)"
echo "Subdomains in both: $(comm -12 <(sort subs_subfinder.txt) <(sort subs_amass.txt) | wc -l)"
```
