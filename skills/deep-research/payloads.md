# Deep Research Payloads / Search Query Templates

> This file is a companion to `SKILL.md`, containing search query templates, OSINT operators, and data-extraction commands organized by research scenario.

---

## 1. Vulnerability Research Queries

### CVE Investigation

```bash
# NVD API lookup by keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx+ingress" | jq '.vulnerabilities[] | {cve_id: .cve.id, description: .cve.descriptions[0].value, severity: .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity}'

# NVD lookup by specific CVE
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-12345" | jq '.vulnerabilities[0].cve'

# Exploit-DB search
searchsploit nginx ingress
searchsploit -x 12345  # Examine specific exploit

# GitHub PoC search
gh search code "CVE-2025-12345 poc" --limit 20
gh search code "CVE-2025-12345 exploit" --limit 20
```

### Affected Software Discovery

```bash
# CPE-based search
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:nginx:ingress:*:*:*:*:*:*:*:*" | jq '.vulnerabilities[] | .cve.id'

# Vendor advisory search
site:nginx.org "security advisory" ingress
site:kubernetes.io "security" "ingress" CVE

# Shodan exposure check
shodan count "http.title:\"Dashboard\" kubernetes"
shodan search "nginx ingress" --limit 10
```

---

## 2. Threat Actor Research Queries

### APT Group Profiling

```bash
# MITRE ATT&CK group lookup
# Web: https://attack.mitre.org/groups/G0007/ (APT28)
# Web: https://attack.mitre.org/groups/G0032/ (Lazarus)

# Threat intelligence report search
"<APT-name>" TTP campaign 2025 2026
"<APT-name>" indicators of compromise
"<APT-name>" MITRE ATT&CK techniques

# IOC collection
"<APT-name>" "indicator" filetype:csv
"<APT-name>" "IOCs" "hash" "IP" "domain"
```

### Campaign Correlation

```bash
# Cross-reference campaigns
"<campaign-name>" vulnerability exploit timeline
"<APT-name>" campaign "<year>" targets victims

# Malware family research
"<malware-name>" analysis capabilities detection
"<malware-name>" YARA rule sigma rule
site:github.com "<malware-name>" detection
```

---

## 3. Attack Technique Research Queries

### Technique Deep-Dive

```bash
# MITRE ATT&CK technique lookup
# Web: https://attack.mitre.org/techniques/T1059/ (Command and Scripting Interpreter)
# Web: https://attack.mitre.org/techniques/T1059/001/ (PowerShell)

# Detection rules
site:github.com sigma-rule "<technique-id>"
site:github.com "detection" "<technique-name>" YARA

# Bypass research
"<technique-name>" bypass detection evasion 2025 2026
"<technique-name>" "new variant" "emerging"

# Defensive guidance
"<technique-name>" mitigation hardening best practices
"<technique-name>" NIST CISA guidance
```

### Tool Analysis

```bash
# Tool capability research
"<tool-name>" capabilities detection signatures
"<tool-name>" OPSEC considerations alternatives

# Living-off-the-land research
"<lolbin-name>" abuse technique detection
site:lolbas-project.github.io "<binary-name>"
site:gtfobins.github.io "<binary-name>"
```

---

## 4. Technology Stack Research Queries

### Web Technology Assessment

```bash
# Version-specific vulnerabilities
"<technology>" "<version>" vulnerability CVE
"<technology>" "security advisory" "<year>"

# Misconfiguration research
"<technology>" misconfiguration exploit common mistakes
"<technology>" hardening guide security checklist

# Default credentials and settings
"<technology>" default password username admin
"<technology>" default configuration exposed
```

### Cloud & Infrastructure Research

```bash
# Cloud service vulnerabilities
"<cloud-service>" vulnerability misconfiguration 2025 2026
"<cloud-service>" "IAM" privilege escalation

# Container security
"<container-tool>" CVE vulnerability escape
"container" "breakout" "escape" technique 2026

# API security research
"<api-framework>" vulnerability authentication bypass
"API" "mass assignment" "IDOR" "<framework>"
```

---

## 5. Compliance & Regulatory Research Queries

```bash
# Industry-specific requirements
"<industry>" cybersecurity compliance requirements 2026
"<industry>" "PCI DSS" OR "HIPAA" OR "SOC 2" security controls

# Geographic regulations
"<country>" data protection law cybersecurity
"<regulation>" penetration testing requirements scope

# Framework mapping
"<framework>" penetration testing methodology
"NIST" "penetration testing" "assessment" guide
```

---

## 6. Google Dork Quick-Reference for Research

### General Research Operators

```
# Exact phrase matching
"exact phrase here"

# Site-specific search
site:github.com "<keyword>"
site:reddit.com/r/netsec "<keyword>"

# File type filtering
filetype:pdf "security assessment" "<keyword>"
filetype:pptx "threat intelligence" "<keyword>"

# Title-focused search
intitle:"security advisory" "<technology>"

# Date-constrained (via search tools)
after:2025-01-01 "<keyword>" vulnerability

# Exclude noise
"<keyword>" -site:pinterest.com -site:facebook.com

# Combined operators
site:github.com "poc" OR "proof-of-concept" "CVE-2025-*" -bot
```

### Security-Specific Dorks

```
# Exposed documents
filetype:xls "password" site:example.com
filetype:env "DB_PASSWORD" site:github.com

# Open directories
intitle:"index of" "/admin" site:example.com
intitle:"directory listing" "backup" site:example.com

# Error messages revealing stack info
"inurl:debug" "stack trace" site:example.com
"sql syntax" "error" site:example.com

# Login portals
inurl:admin/login site:example.com
inurl:wp-admin site:example.com
```

---

## 7. Data Extraction Commands

### API-Based Extraction

```bash
# NVD CVE details (JSON)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<term>&resultsPerPage=20" | jq '.'

# Shodan host lookup
shodan host <IP>

# Censys search
censys search "services.tls.certificate.parsed.names: <domain>" --per-page 10

# GitHub code search
gh search code "<query>" --language python --limit 30 --json path,repository,textMatches

# GitHub repository search
gh search repos "<topic> security" --sort stars --limit 20 --json fullName,description,stargazersCount
```

### Web Scraping Extraction

```bash
# Full page content to markdown
curl -sL "<url>" | html2markdown > output.md

# Extract all links from a page
curl -sL "<url>" | grep -oP 'href="[^"]*"' | sort -u

# Extract text content (strip HTML)
curl -sL "<url>" | lynx -dump -stdin

# Download and extract PDF text
curl -sL "<url>.pdf" | pdftotext - - | head -200
```

### IOC Extraction from Reports

```bash
# Extract IP addresses
grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' report.txt | sort -u

# Extract hashes (MD5/SHA1/SHA256)
grep -oP '\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b' report.txt | sort -u

# Extract domains
grep -oP '\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b' report.txt | sort -u

# Extract CVE IDs
grep -oP 'CVE-\d{4}-\d{4,}' report.txt | sort -u

# Extract URLs
grep -oP 'https?://[^\s<>"\']+' report.txt | sort -u
```

---

## 8. Parallel Research with Subagents

For broad topics, decompose and parallelize:

```
Launch 3 research agents in parallel:
1. Agent 1: Sub-questions 1-2 (e.g., CVE history + misconfigurations)
2. Agent 2: Sub-questions 3-4 (e.g., best practices + breach cases)
3. Agent 3: Sub-question 5 + cross-cutting themes (e.g., audit tools + emerging trends)

Each agent:
- Searches 2-3 engines per sub-question
- Deep-reads 3-5 key sources
- Returns structured findings with citations
```

Main session synthesizes all agent outputs into the final report.

---

## 9. Continuous Monitoring Queries

### CVE Feed Monitoring

```bash
# NVD: new CVEs in the last 24 hours
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$(date -d '1 day ago' +%Y-%m-%dT00:00:00.000)&pubEndDate=$(date +%Y-%m-%dT23:59:59.999)" | jq '.vulnerabilities[] | {id: .cve.id, severity: .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity, description: .cve.descriptions[0].value}'

# NVD: new CVEs for a specific keyword (last 7 days)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<technology>&pubStartDate=$(date -d '7 days ago' +%Y-%m-%dT00:00:00.000)" | jq '.vulnerabilities[] | .cve.id'

# CISA KEV: recently added exploited vulnerabilities
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq '[.vulnerabilities | sort_by(.dateAdded) | reverse | .[:10][] | {cve: .cveID, name: .vulnerabilityName, vendor: .vendorProject, added: .dateAdded}]'

# Exploit-DB: recent additions
searchsploit --update && searchsploit "<technology>" | head -20

# GitHub Security Advisories
gh api "/advisories?per_page=10&sort=published&direction=desc" | jq '.[].summary'
```

### Attack Surface Change Detection

```bash
# Shodan: snapshot and diff target exposure
shodan search "org:<TargetCorp>" --limit 200 --fields ip_str,port,product,version > exposure_$(date +%Y%m%d).json
diff exposure_$(date -d '7 days ago' +%Y%m%d).json exposure_$(date +%Y%m%d).json

# Certificate Transparency: new certificates
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '[sort_by(.not_before) | reverse | .[:10][] | {name: .name_value, issuer: .issuer_name, date: .not_before}]'

# DNS record changes
dig +short target.com A > dns_$(date +%Y%m%d).txt
diff dns_previous.txt dns_$(date +%Y%m%d).txt

# Subdomain discovery delta
subfinder -d target.com -silent > subs_$(date +%Y%m%d).txt
comm -13 <(sort subs_previous.txt) <(sort subs_$(date +%Y%m%d).txt)  # New subdomains only
```

### Code Leak & Paste Monitoring

```bash
# GitHub: recent commits mentioning target
gh search code "<target-keyword>" --sort indexed --order desc --limit 20 --json repository,path,textMatches

# GitHub: new repos mentioning target
gh search repos "<target-keyword>" --sort updated --limit 10 --json fullName,description,updatedAt

# Pastebin search (via psbdmp API)
curl -s "https://psbdmp.ws/api/search/<target-keyword>" | jq '.data[:10]'

# Google Dorking for fresh leaks
"<target-company>" password OR credentials OR api_key after:$(date -d '7 days ago' +%Y-%m-%d)
site:pastebin.com "<target-keyword>"
site:ghostbin.com "<target-keyword>"
```

### Dark Web Mention Monitoring

```bash
# Ahmia (Tor search engine, clearnet gateway)
curl -s "https://ahmia.fi/search/?q=<target-keyword>" | grep -oP 'href="[^"]*"' | head -20

# IntelX (Intelligence X API)
curl -s "https://2.intelx.io/intelligent/search" -H "x-key: <API_KEY>" -d '{"term":"<target-keyword>","maxresults":10}'

# Google Dorking for dark web mirrors
"<target-company>" site:onion.ly OR site:onion.ws
```

---

## 10. Intelligence Correlation Commands

### IOC Extraction from Reports

```bash
# Batch extract all IOC types from a report
extract_iocs() {
  local file="$1"
  echo "=== IPs ===" && grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$file" | sort -u
  echo "=== Domains ===" && grep -oP '\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b' "$file" | sort -u
  echo "=== SHA256 ===" && grep -oP '\b[a-fA-F0-9]{64}\b' "$file" | sort -u
  echo "=== SHA1 ===" && grep -oP '\b[a-fA-F0-9]{40}\b' "$file" | sort -u
  echo "=== MD5 ===" && grep -oP '\b[a-fA-F0-9]{32}\b' "$file" | sort -u
  echo "=== CVEs ===" && grep -oP 'CVE-\d{4}-\d{4,}' "$file" | sort -u
  echo "=== URLs ===" && grep -oP 'https?://[^\s<>"'\'']+' "$file" | sort -u
}
extract_iocs report.txt > extracted_iocs.txt
```

### Cross-Reference IOCs Against Threat Intel

```bash
# AbuseIPDB lookup
check_ip_reputation() {
  while read ip; do
    result=$(curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip" -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json")
    score=$(echo "$result" | jq '.data.abuseConfidenceScore')
    echo "$ip: confidence=$score"
  done < "$1"
}
check_ip_reputation iocs_ip.txt

# VirusTotal hash lookup
check_hash_vt() {
  while read hash; do
    result=$(curl -s "https://www.virustotal.com/api/v3/files/$hash" -H "x-apikey: $VT_API_KEY")
    detections=$(echo "$result" | jq '.data.attributes.last_analysis_stats.malicious')
    echo "$hash: malicious_detections=$detections"
  done < "$1"
}
check_hash_vt iocs_sha256.txt

# Shodan IP enrichment
while read ip; do
  shodan host "$ip" 2>/dev/null | head -5
done < iocs_ip.txt
```

### MITRE ATT&CK Mapping

```bash
# Map observed techniques to ATT&CK IDs
# Input: list of technique descriptions
# Output: ATT&CK ID + technique name

# Search ATT&CK for technique by keyword
curl -s "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" | jq '.objects[] | select(.type=="attack-pattern") | select(.name | test("<keyword>"; "i")) | {id: .external_references[0].external_id, name: .name, description: .description[:200]}'

# Generate ATT&CK Navigator layer from observed techniques
# Input: comma-separated technique IDs
generate_navigator_layer() {
  local techniques="$1"
  cat <<LAYER
{
  "name": "Observed Techniques",
  "versions": {"attack": "15", "navigator": "5.0", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    $(echo "$techniques" | tr ',' '\n' | while read tid; do
      echo "{\"techniqueID\": \"$tid\", \"color\": \"#ff6666\"}"
    done | paste -sd ',')
  ]
}
LAYER
}
generate_navigator_layer "T1059,T1053,T1078" > navigator_layer.json
```

### Multi-Source Entity Correlation

```bash
# Merge IOCs from multiple reports, track source count
merge_iocs() {
  local output="merged_iocs.csv"
  echo "ioc,type,sources,confidence" > "$output"
  for file in reports/*.txt; do
    src=$(basename "$file" .txt)
    grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$file" | while read ioc; do
      echo "$ioc,ip,$src"
    done
    grep -oP 'CVE-\d{4}-\d{4,}' "$file" | while read ioc; do
      echo "$ioc,cve,$src"
    done
  done | sort | uniq -c | sort -rn | awk '{
    count=$1; ioc=$2; type=$3; sources=$4
    if (count >= 3) conf="HIGH"
    else if (count == 2) conf="MEDIUM"
    else conf="LOW"
    print ioc","type","sources","conf
  }' >> "$output"
}
```
