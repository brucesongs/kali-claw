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

---

## 11. Academic & Patent Research

### Paper Discovery

```bash
# Semantic Scholar — search security papers
curl -s "https://api.semanticscholar.org/graph/v1/paper/search?query=web+application+fuzzing&limit=10&fields=title,year,citationCount,authors" \
  | jq '.data[] | {title, year, citations: .citationCount, authors: [.authors[].name]}'

# arXiv — recent security papers
curl -s "http://export.arxiv.org/api/query?search_query=cat:cs.CR+AND+all:fuzzing&start=0&max_results=5" \
  | grep -oP '<title>[^<]+</title>' | sed 's/<[^>]*>//g'

# DBLP — author publication history
curl -s "https://dblp.org/search/publ/api?q=author:john_doe+security&format=json&h=10" \
  | jq '.result.hits.hit[].info | {title, year, venue}'
```

### Patent and Standards Search

```bash
# Google Patents API
curl -s "https://patents.google.com/xhr/query?url=q%3Dcybersecurity+intrusion+detection&num=5" \
  | jq '.results.cluster[0].result[:5] | .[].patent | {title: .title, date: .publication_date, assignee: .assignee}'

# NIST SP search
curl -s "https://csrc.nist.gov/publications?keywords=penetration+testing&sortBy=Recent" | grep -oP 'SP [0-9]+-[0-9]+[A-Z]?' | sort -u

# RFC search
curl -s "https://www.rfc-editor.org/search/rfc_search.php?query=tls+1.3&format=json" 2>/dev/null
```

---

## 12. Threat Landscape Analysis

### Threat Feed Aggregation

```bash
# AlienVault OTX — pulse search
curl -s "https://otx.alienvault.com/api/v1/search/pulses?q=ransomware&limit=10" \
  -H "X-OTX-API-KEY: $OTX_KEY" \
  | jq '.results[] | {name, created, adversary, targeted_countries, indicators_count: (.indicators | length)}'

# MISP — event search
curl -s "$MISP_URL/events/restSearch" \
  -H "Authorization: $MISP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"keyword":"apt28","limit":5}' \
  | jq '.response[].Event | {id, info, date, threat_level_id}'

# Recorded Future (via API)
curl -s "https://api.recordedfuture.com/v2/alert/search" \
  -H "X-RFToken: $RF_TOKEN" \
  -d '{"filter":{"type":"CyberVulnerability"},"limit":10}' \
  | jq '.data.results[:5] | .[].entity'
```

### Trend Analysis

```bash
# CVE publication trends by year/severity
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2025-01-01T00:00:00.000&pubEndDate=2025-12-31T23:59:59.999&cvssV3Severity=CRITICAL" \
  | jq '.totalResults' | xargs -I{} echo "Critical CVEs in 2025: {}"

# Technology-specific vulnerability timeline
for year in 2022 2023 2024 2025; do
  count=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kubernetes&pubStartDate=${year}-01-01T00:00:00.000&pubEndDate=${year}-12-31T23:59:59.999" | jq '.totalResults')
  echo "$year: $count kubernetes CVEs"
done
```

---

## 13. Structured Data Collection

### API Response Normalization

```python
import json
from datetime import datetime

def normalize_nvd_response(raw: dict) -> list[dict]:
    """Extract structured findings from NVD API response."""
    findings = []
    for vuln in raw.get("vulnerabilities", []):
        cve = vuln["cve"]
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        findings.append({
            "id": cve["id"],
            "published": cve.get("published"),
            "severity": cvss.get("baseScore"),
            "vector": cvss.get("vectorString"),
            "description": cve["descriptions"][0]["value"] if cve.get("descriptions") else "",
            "references": [r["url"] for r in cve.get("references", [])],
        })
    return findings

def normalize_github_advisory(raw: dict) -> list[dict]:
    """Extract structured findings from GitHub Advisory API."""
    return [{
        "id": adv["ghsaId"],
        "published": adv["publishedAt"],
        "severity": adv["severity"],
        "description": adv["summary"],
        "references": [r["url"] for r in adv.get("references", [])],
    } for adv in raw.get("data", {}).get("securityAdvisories", {}).get("nodes", [])]
```

### Bulk Data Pipeline

```bash
#!/bin/bash
# bulk-cve-collector.sh — Collect all CVEs for a technology across years
KEYWORD="$1"
OUTPUT_DIR="./cve_data/$KEYWORD"
mkdir -p "$OUTPUT_DIR"

for year in $(seq 2020 2025); do
    echo "Fetching $KEYWORD CVEs for $year..."
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$KEYWORD&pubStartDate=${year}-01-01T00:00:00.000&pubEndDate=${year}-12-31T23:59:59.999&resultsPerPage=100" \
        > "$OUTPUT_DIR/${year}.json"
    sleep 6  # NVD rate limit: 10 requests/minute
done

# Summarize
echo "=== Collection Summary ==="
for f in "$OUTPUT_DIR"/*.json; do
    year=$(basename "$f" .json)
    count=$(jq '.totalResults' "$f")
    echo "  $year: $count CVEs"
done
```

### Report Summarization

```python
def summarize_findings(findings: list[dict], top_n=10) -> str:
    """Generate executive summary from collected findings."""
    critical = [f for f in findings if (f.get("severity") or 0) >= 9.0]
    high = [f for f in findings if 7.0 <= (f.get("severity") or 0) < 9.0]
    
    lines = [
        f"## Research Summary",
        f"- **Total findings**: {len(findings)}",
        f"- **Critical (9.0+)**: {len(critical)}",
        f"- **High (7.0-8.9)**: {len(high)}",
        "",
        "### Top Critical Findings",
    ]
    for f in sorted(critical, key=lambda x: x.get("severity", 0), reverse=True)[:top_n]:
        lines.append(f"- **{f['id']}** (CVSS {f['severity']}): {f['description'][:80]}...")
    
    return "\n".join(lines)
```

---

## 14. Research Workflow Automation

### End-to-End Research Pipeline

```bash
#!/bin/bash
# research-pipeline.sh — Full automated research cycle
TOPIC="$1"
OUTPUT="./research_output/$TOPIC"
mkdir -p "$OUTPUT"

echo "[1/5] Collecting from NVD..."
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$TOPIC&resultsPerPage=20" > "$OUTPUT/nvd.json"

echo "[2/5] Searching ExploitDB..."
searchsploit "$TOPIC" --json > "$OUTPUT/exploitdb.json" 2>/dev/null

echo "[3/5] GitHub code search..."
gh search code "$TOPIC vulnerability" --limit 20 --json repository,path > "$OUTPUT/github_code.json"

echo "[4/5] Extracting IOCs from all sources..."
cat "$OUTPUT"/*.json | grep -oP 'CVE-\d{4}-\d{4,}' | sort -u > "$OUTPUT/cve_list.txt"

echo "[5/5] Generating report..."
{
  echo "# Research Report: $TOPIC"
  echo "**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "## NVD Results"
  jq -r '.vulnerabilities[:10][] | .cve | "- \(.id): \(.descriptions[0].value[:80])..."' "$OUTPUT/nvd.json"
  echo ""
  echo "## ExploitDB Results"
  jq -r '.RESULTS_EXPLOIT[:10][] | "- [\(.EDB_ID)] \(.Title)"' "$OUTPUT/exploitdb.json" 2>/dev/null
  echo ""
  echo "## Unique CVEs Found"
  cat "$OUTPUT/cve_list.txt"
} > "$OUTPUT/REPORT.md"

echo "[+] Report saved to $OUTPUT/REPORT.md"
```

### Scheduled Research Jobs

```bash
# Cron job for daily threat monitoring
# 0 8 * * * /opt/research/research-pipeline.sh "kubernetes" >> /var/log/research.log

# Weekly technology survey
# 0 9 * * 1 /opt/research/research-pipeline.sh "zero-day" >> /var/log/research.log

# On-demand deep dive (triggered by alert)
research_on_alert() {
    local cve_id="$1"
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id" | jq '.vulnerabilities[0].cve | {
        id,
        severity: .metrics.cvssMetricV31[0].cvssData.baseScore,
        vector: .metrics.cvssMetricV31[0].cvssData.vectorString,
        description: .descriptions[0].value,
        references: [.references[].url]
    }'
}
```

---

## 15. Knowledge Graph Construction

### Entity Extraction

```python
import re
from collections import defaultdict

def extract_entities(text: str) -> dict:
    """Extract security-relevant entities from research text."""
    entities = defaultdict(set)
    
    # CVEs
    for m in re.finditer(r'CVE-\d{4}-\d{4,}', text):
        entities["cve"].add(m.group())
    
    # Products/versions
    for m in re.finditer(r'(?:Apache|Nginx|WordPress|Django|Rails|Express)\s+[\d.]+', text):
        entities["product"].add(m.group())
    
    # Technique references
    for m in re.finditer(r'T\d{4}(?:\.\d{3})?', text):
        entities["mitre_technique"].add(m.group())
    
    # Threat actors
    for m in re.finditer(r'(?:APT|FIN|UNC)\d+', text):
        entities["threat_actor"].add(m.group())
    
    return dict(entities)

def build_knowledge_graph(findings: list[dict]) -> dict:
    """Build relationship graph from extracted entities."""
    nodes = set()
    edges = []
    
    for finding in findings:
        entities = extract_entities(finding.get("description", ""))
        finding_id = finding["id"]
        nodes.add(finding_id)
        
        for category, values in entities.items():
            for value in values:
                nodes.add(value)
                edges.append({"from": finding_id, "to": value, "relation": category})
    
    return {"nodes": list(nodes), "edges": edges}
```

### Graph Queries

```bash
# Find all CVEs related to a product
find_related_cves() {
    local product="$1"
    local graph_file="$2"
    jq --arg prod "$product" '
        .edges[] | select(.to == $prod and .relation == "product") | .from
    ' "$graph_file"
}

# Find attack chains (CVE → technique → actor)
find_attack_chains() {
    local graph_file="$1"
    jq '
        [.edges[] | select(.relation == "mitre_technique")] as $tech_edges |
        [.edges[] | select(.relation == "threat_actor")] as $actor_edges |
        $tech_edges[] as $t |
        $actor_edges[] | select(.from == $t.from) |
        {cve: $t.from, technique: $t.to, actor: .to}
    ' "$graph_file"
}
```

---

## 16. Research Quality Metrics

### Completeness Scoring

```python
def assess_research_completeness(report: dict) -> dict:
    """Score how thorough a research investigation was."""
    checks = {
        "nvd_queried": bool(report.get("nvd_results")),
        "exploits_checked": bool(report.get("exploit_results")),
        "github_searched": bool(report.get("code_results")),
        "mitre_mapped": bool(report.get("attack_mapping")),
        "iocs_extracted": bool(report.get("iocs")),
        "timeline_built": bool(report.get("timeline")),
        "sources_cited": len(report.get("sources", [])) >= 3,
        "cross_validated": report.get("corroboration_count", 0) >= 2,
    }
    
    score = sum(checks.values()) / len(checks)
    return {
        "completeness_score": round(score, 2),
        "checks": checks,
        "grade": "A" if score >= 0.9 else "B" if score >= 0.7 else "C" if score >= 0.5 else "D",
    }
```

### Source Diversity Measurement

```bash
# Count unique source types used in research
assess_source_diversity() {
    local report_dir="$1"
    echo "=== Source Diversity ==="
    echo "  NVD data: $([ -s "$report_dir/nvd.json" ] && echo 'YES' || echo 'NO')"
    echo "  ExploitDB: $([ -s "$report_dir/exploitdb.json" ] && echo 'YES' || echo 'NO')"
    echo "  GitHub code: $([ -s "$report_dir/github_code.json" ] && echo 'YES' || echo 'NO')"
    echo "  Academic: $([ -s "$report_dir/papers.json" ] && echo 'YES' || echo 'NO')"
    echo "  Threat feeds: $([ -s "$report_dir/threat_intel.json" ] && echo 'YES' || echo 'NO')"
    
    local count=0
    for f in nvd exploitdb github_code papers threat_intel; do
        [ -s "$report_dir/${f}.json" ] && ((count++))
    done
    echo "  Diversity score: $count/5"
}
```

### Research Velocity Tracking

```bash
# Track research output over time
track_velocity() {
    local output_dir="./research_output"
    echo "=== Research Velocity ==="
    echo "Date       | Reports | CVEs Found | Sources Used"
    echo "-----------|---------|------------|-------------"
    for day_dir in "$output_dir"/*/; do
        date=$(basename "$day_dir")
        reports=$(find "$day_dir" -name "REPORT.md" | wc -l)
        cves=$(cat "$day_dir"/*/cve_list.txt 2>/dev/null | sort -u | wc -l)
        sources=$(find "$day_dir" -name "*.json" | wc -l)
        printf "%-11s| %-7s | %-10s | %s\n" "$date" "$reports" "$cves" "$sources"
    done
}
```

---

## 17. Automated Intelligence Gathering Scripts

### Target Profiling Automation

```bash
#!/bin/bash
# target-profile.sh — Automated target infrastructure profiling
TARGET="$1"
OUTDIR="./intel/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Profiling: $TARGET"

echo "[1/6] DNS enumeration..."
dig +short "$TARGET" A > "$OUTDIR/a_records.txt"
dig +short "$TARGET" MX > "$OUTDIR/mx_records.txt"
dig +short "$TARGET" NS > "$OUTDIR/ns_records.txt"
dig +short "$TARGET" TXT > "$OUTDIR/txt_records.txt"
dig +short "$TARGET" SOA > "$OUTDIR/soa_records.txt"

echo "[2/6] WHOIS information..."
whois "$TARGET" > "$OUTDIR/whois.txt" 2>/dev/null

echo "[3/6] Subdomain enumeration..."
subfinder -d "$TARGET" -silent > "$OUTDIR/subdomains.txt" 2>/dev/null

echo "[4/6] Certificate transparency..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > "$OUTDIR/crt_subdomains.txt"

echo "[5/6] Technology fingerprinting..."
curl -sI "https://$TARGET" > "$OUTDIR/headers.txt" 2>/dev/null

echo "[6/6] Port scan (top 100)..."
nmap -F -T4 "$TARGET" -oN "$OUTDIR/nmap_quick.txt" 2>/dev/null

echo "[+] Profile saved to $OUTDIR/"
```

### Passive Intelligence Harvester

```python
#!/usr/bin/env python3
"""Harvest passive intelligence from multiple OSINT sources."""
import requests
import json
import time

def query_shodan(api_key, query, limit=10):
    """Search Shodan for exposed services matching query."""
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}&limit={limit}"
    resp = requests.get(url, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("matches", [])
    return []

def query_censys(api_id, api_secret, query, per_page=10):
    """Search Censys for hosts matching query."""
    url = "https://search.censys.io/api/v2/hosts/search"
    auth = (api_id, api_secret)
    params = {"q": query, "per_page": per_page}
    resp = requests.get(url, auth=auth, params=params, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("result", {}).get("hits", [])
    return []

def query_virustotal(api_key, domain):
    """Query VirusTotal for domain intelligence."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        return {
            "reputation": data.get("reputation", 0),
            "last_analysis_stats": data.get("last_analysis_stats", {}),
            "whois": data.get("whois", ""),
        }
    return {}

def query_securitytrails(api_key, domain):
    """Query SecurityTrails for historical DNS data."""
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("subdomains", [])
    return []

def harvest_all(domain, config):
    """Run all passive intelligence queries against a domain."""
    results = {}
    if "shodan_key" in config:
        results["shodan"] = query_shodan(config["shodan_key"], f"hostname:{domain}")
        time.sleep(1)
    if "censys_id" in config:
        results["censys"] = query_censys(config["censys_id"], config["censys_secret"], f"names:{domain}")
        time.sleep(1)
    if "vt_key" in config:
        results["virustotal"] = query_virustotal(config["vt_key"], domain)
        time.sleep(1)
    if "st_key" in config:
        results["securitytrails"] = query_securitytrails(config["st_key"], domain)
    return results
```

### Network Range Discovery

```bash
#!/bin/bash
# network-range-discovery.sh — Map target network ranges via public data
TARGET="$1"

echo "[*] Discovering network ranges for: $TARGET"

# Extract ASN from IP
IP=$(dig +short "$TARGET" A | head -1)
echo "[+] Resolved IP: $IP"

# WHOIS to find ASN
ASN=$(whois "$IP" | grep -i "origin" | head -1 | awk '{print $2}')
echo "[+] ASN: $ASN"

# Query ASN for all announced prefixes
if [ -n "$ASN" ]; then
    curl -s "https://api.bgpview.io/prefix/$ASN" | jq '.data.prefixes[] | {prefix: .prefix, name: .name, description: .description}'
    curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | jq '.data.ipv4_prefixes[] | .prefix'
fi

# Reverse DNS sweep of discovered ranges
echo "[+] Performing reverse DNS on discovered ranges..."
curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | jq -r '.data.ipv4_prefixes[].prefix' | while read cidr; do
    echo "  Range: $cidr"
    nmap -sn -R "$cidr" --dns-servers 8.8.8.8 -oG - 2>/dev/null | grep "Host:"
done
```

---

## 18. API-Based Research Automation

### Shodan Automation Scripts

```bash
# Shodan bulk host lookup
shodan_host_bulk() {
    while read ip; do
        echo "=== $ip ==="
        shodan host "$ip" 2>/dev/null | head -15
        sleep 1
    done < "$1"
}

# Shodan exploit search for CVE
shodan_exploit_search() {
    local cve="$1"
    curl -s "https://exploits.shodan.io/api/search?query=$cve" | jq '.matches[] | {cve: .cve, description: .description[:100], references: .references}'
}

# Shodan monitoring setup — track new exposures
shodan_alert_create() {
    local network="$1"
    local alert_name="$2"
    curl -s "https://api.shodan.io/alert?key=$SHODAN_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$alert_name\", \"filters\": {\"ip\": [\"$network\"]}, \"expires\": null}"
}
```

### Censys Enumeration Scripts

```bash
# Censys certificate search for domain
censys_cert_search() {
    local domain="$1"
    curl -s "https://search.censys.io/api/v2/certificates/search" \
        -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"names: $domain\", \"per_page\": 20}" \
        | jq '.result.hits[] | {fingerprint: .fingerprint, names: .names, issuer: .issuer.displayName}'
}

# Censys host enumeration by service
censys_host_search() {
    local service="$1"
    curl -s "https://search.censys.io/api/v2/hosts/search" \
        -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"services.service_name: $service\", \"per_page\": 50}" \
        | jq '.result.hits[] | {ip: .ip, location: .location.country, services: [.services[].service_name]}'
}
```

### HaveIBeenPwned Breach Lookup

```bash
# Check single email for breaches
hibp_breach_check() {
    local email="$1"
    curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" \
        -H "hibp-api-key: $HIBP_API_KEY" \
        -H "user-agent: kali-claw-research" \
        | jq '.[] | {name: .Name, breach_date: .BreachDate, data_classes: .DataClasses, compromised_count: .PwnCount}'
}

# Check domain for all breaches
hibp_domain_breaches() {
    local domain="$1"
    curl -s "https://haveibeenpwned.com/api/v3/breaches?domain=$domain" \
        -H "hibp-api-key: $HIBP_API_KEY" \
        -H "user-agent: kali-claw-research" \
        | jq '.[] | {name: .Name, breach_date: .BreachDate, pwn_count: .PwnCount, data_classes: .DataClasses}'
}

# HIBP paste search for email
hibp_paste_check() {
    local email="$1"
    curl -s "https://haveibeenpwned.com/api/v3/pasteaccount/$email" \
        -H "hibp-api-key: $HIBP_API_KEY" \
        -H "user-agent: kali-claw-research" \
        | jq '.[] | {source: .Source, id: .Id, title: .Title, date: .Date, email_count: .EmailCount}'
}
```

### VirusTotal Batch Analysis

```python
#!/usr/bin/env python3
"""Batch VirusTotal analysis for IPs, domains, and file hashes."""
import requests
import sys
import time
import json

API_KEY = None  # Set via environment variable

def vt_ip_report(ip, api_key):
    """Retrieve VirusTotal report for an IP address."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        return {
            "ip": ip,
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", "Unknown"),
            "as_owner": attrs.get("as_owner", "Unknown"),
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "total_votes": attrs.get("total_votes", {}),
        }
    return {"ip": ip, "error": resp.status_code}

def vt_domain_report(domain, api_key):
    """Retrieve VirusTotal report for a domain."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        return {
            "domain": domain,
            "reputation": attrs.get("reputation", 0),
            "creation_date": attrs.get("creation_date", 0),
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "whois": attrs.get("whois", "")[:500],
        }
    return {"domain": domain, "error": resp.status_code}

def vt_file_report(file_hash, api_key):
    """Retrieve VirusTotal report for a file hash."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        attrs = resp.json()["data"]["attributes"]
        return {
            "hash": file_hash,
            "meaningful_name": attrs.get("meaningful_name", "Unknown"),
            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
            "tags": attrs.get("tags", []),
            "popular_threat_classification": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown"),
        }
    return {"hash": file_hash, "error": resp.status_code}

def batch_analyze(indicators_file, api_key, indicator_type="auto"):
    """Batch analyze a list of indicators from a file."""
    results = []
    with open(indicators_file) as f:
        indicators = [line.strip() for line in f if line.strip()]
    for indicator in indicators:
        if indicator_type == "auto":
            if indicator.count(".") == 3 and all(p.isdigit() for p in indicator.split(".")):
                result = vt_ip_report(indicator, api_key)
            elif len(indicator) in (32, 40, 64) and all(c in "0123456789abcdef" for c in indicator.lower()):
                result = vt_file_report(indicator, api_key)
            else:
                result = vt_domain_report(indicator, api_key)
        results.append(result)
        time.sleep(16)  # Free API: 4 requests per minute
    return results
```

### NIST NVD Batch Collection

```bash
#!/bin/bash
# nvd-batch-collect.sh — Batch collect CVE data from NVD
KEYWORD="$1"
START_YEAR="${2:-2020}"
END_YEAR="${3:-2026}"
OUTPUT="./nvd_data/$KEYWORD"
mkdir -p "$OUTPUT"

echo "[*] Collecting NVD data for: $KEYWORD ($START_YEAR-$END_YEAR)"

for year in $(seq "$START_YEAR" "$END_YEAR"); do
    echo "  Fetching $year..."
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$KEYWORD&pubStartDate=${year}-01-01T00:00:00.000&pubEndDate=${year}-12-31T23:59:59.999&resultsPerPage=200" \
        > "$OUTPUT/${year}.json"
    sleep 6  # NVD rate limit compliance
done

echo "[*] Generating summary..."
{
    echo "# NVD Summary: $KEYWORD"
    echo ""
    echo "| Year | Total CVEs | Critical | High |"
    echo "|------|-----------|----------|------|"
    for year in $(seq "$START_YEAR" "$END_YEAR"); do
        total=$(jq '.totalResults // 0' "$OUTPUT/${year}.json" 2>/dev/null)
        critical=$(jq '[.vulnerabilities[]?.cve.metrics.cvssMetricV31[]? | select(.cvssData.baseScore >= 9.0)] | length' "$OUTPUT/${year}.json" 2>/dev/null)
        high=$(jq '[.vulnerabilities[]?.cve.metrics.cvssMetricV31[]? | select(.cvssData.baseScore >= 7.0 and .cvssData.baseScore < 9.0)] | length' "$OUTPUT/${year}.json" 2>/dev/null)
        echo "| $year | $total | $critical | $high |"
    done
} > "$OUTPUT/SUMMARY.md"

echo "[+] Data saved to $OUTPUT/"
```

---

## 19. Dark Web Research Commands

### Tor Integration for Research

```bash
# Start Tor service
sudo systemctl start tor
sudo tor --SocksPort 9050 &

# Verify Tor connectivity
curl --socks5-hostname localhost:9050 https://check.torproject.org/api/ip | jq '.IsTor'

# Use proxychains with any command through Tor
proxychains4 curl -s "http://duskgytldkxiuqc6.onion" 2>/dev/null

# Configure proxychains for Tor
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 9050
EOF

# Ahmia search via Tor
proxychains4 curl -s "https://ahmia.fi/search/?q=target_keyword" | html2text | head -100
```

### Onion Service Discovery

```bash
#!/bin/bash
# onion-discovery.sh — Discover .onion services related to a keyword
KEYWORD="$1"
TOR_PROXY="socks5-hostname://127.0.0.1:9050"

echo "[*] Searching for: $KEYWORD"

# Ahmia search engine
echo "[1/3] Ahmia search..."
curl --socks5-hostname 127.0.0.1:9050 -s "https://ahmia.fi/search/?q=$KEYWORD" \
    | grep -oP 'href="[^"]*"' | grep -i onion | sort -u > ahmia_onions.txt

# Torch search engine
echo "[2/3] Torch search..."
curl --socks5-hostname 127.0.0.1:9050 -s "http://xmh57jrzrnw6insl.onion/4a1f6b7c/search?q=$KEYWORD" \
    | grep -oP '[a-z2-7]{16}\.onion' | sort -u > torch_onions.txt

# ReconFTW-style onion gathering
echo "[3/3] Aggregating results..."
cat ahmia_onions.txt torch_onions.txt | grep -oP '[a-z2-7]{16}\.onion' | sort -u > all_onions.txt
echo "[+] Found $(wc -l < all_onions.txt) unique onion addresses"

# Verify which onions are live
echo "[*] Verifying live onions..."
while read onion; do
    status=$(curl --socks5-hostname 127.0.0.1:9050 -s -o /dev/null -w "%{http_code}" --max-time 15 "http://$onion")
    if [ "$status" != "000" ]; then
        echo "  [LIVE] $onion (HTTP $status)"
        echo "$onion" >> live_onions.txt
    fi
done < all_onions.txt
```

### Dark Web Marketplace Monitoring

```python
#!/usr/bin/env python3
"""Monitor dark web sources for mentions of target keywords."""
import requests
import time
import json
from datetime import datetime

TOR_PROXIES = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

def ahmia_search(keyword, pages=3):
    """Search Ahmia for keyword mentions on the dark web."""
    results = []
    for page in range(1, pages + 1):
        try:
            url = f"https://ahmia.fi/search/?q={keyword}&page={page}"
            resp = requests.get(url, proxies=TOR_PROXIES, timeout=30)
            if resp.status_code == 200:
                results.append({
                    "source": "ahmia",
                    "keyword": keyword,
                    "page": page,
                    "timestamp": datetime.utcnow().isoformat(),
                    "content_length": len(resp.text),
                })
        except Exception as e:
            results.append({"source": "ahmia", "error": str(e)})
        time.sleep(2)
    return results

def dark_web_monitor(keywords_file, output_file):
    """Continuously monitor dark web for keyword mentions."""
    with open(keywords_file) as f:
        keywords = [line.strip() for line in f if line.strip()]

    all_results = []
    for keyword in keywords:
        print(f"[*] Monitoring: {keyword}")
        results = ahmia_search(keyword)
        all_results.extend(results)
        time.sleep(5)

    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"[+] Results saved to {output_file}")
```

### Dark Web Paste Site Monitoring

```bash
#!/bin/bash
# dark-paste-monitor.sh — Monitor dark web paste sites for keywords
KEYWORD="$1"

echo "[*] Monitoring paste sites for: $KEYWORD"

# Dark web paste site searches (via Tor)
echo "[1/3] Searching dark paste sites..."

# KillNet paste monitoring
curl --socks5-hostname 127.0.0.1:9050 -s "http://paste2vljghmqsep7llpyk torpedo delivery keyword" \
    --max-time 30 2>/dev/null | grep -i "$KEYWORD" && echo "[HIT] Found on paste site" || echo "[MISS] Not found"

# DNStats monitoring for service status
curl --socks5-hostname 127.0.0.1:9050 -s "https://dnstats.net/" --max-time 30 2>/dev/null \
    | html2text | head -50

# IntelX dark web search (API required)
echo "[2/3] Intelligence X search..."
curl -s "https://2.intelx.io/phonebook/search" \
    -H "x-key: $INTELX_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"term\": \"$KEYWORD\", \"maxresults\": 20, \"media\": 0}" \
    | jq '.selectors[] | {selectorvalue, selectorvalue_type}' 2>/dev/null

# Check for leaked credentials
echo "[3/3] Credential leak check..."
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$KEYWORD" \
    -H "hibp-api-key: $HIBP_API_KEY" \
    -H "user-agent: kali-claw-research" 2>/dev/null | jq '.[].Name' 2>/dev/null

echo "[+] Dark web monitoring complete"
```

### Cryptocurrency Trace for Investigations

```bash
# Bitcoin address investigation
btc_investigate() {
    local address="$1"
    echo "=== BTC Address: $address ==="
    curl -s "https://blockchain.info/rawaddr/$address" | jq '{
        address: .address,
        total_received: .total_received,
        total_sent: ._sent,
        balance: .final_balance,
        tx_count: .n_tx,
        first_tx: .txs[0].time
    }'
}

# Ethereum address investigation
eth_investigate() {
    local address="$1"
    echo "=== ETH Address: $address ==="
    curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=$address&sort=desc&apikey=$ETHERSCAN_KEY" \
        | jq '.result[:5] | .[] | {from: .from, to: .to, value: .value, hash: .hash}'
}

# Onion address reputation check
onion_check() {
    local onion="$1"
    echo "=== Onion Check: $onion ==="
    status=$(curl --socks5-hostname 127.0.0.1:9050 -s -o /dev/null -w "%{http_code}" --max-time 20 "http://$onion")
    echo "HTTP Status: $status"
    if [ "$status" != "000" ]; then
        curl --socks5-hostname 127.0.0.1:9050 -s --max-time 20 "http://$onion" | html2text | head -30
    fi
}
```

---

## 20. Metadata Extraction Payloads

### Document Metadata Extraction

```bash
# Extract metadata from PDF documents
exiftool -a -G1 -s sensitive_document.pdf
exiftool -Creator -Producer -Author -LastModified -Keywords document.pdf

# Batch extract metadata from all PDFs in directory
find . -name "*.pdf" -exec exiftool -Author -Creator -Producer -CreateDate -ModifyDate {} \; > pdf_metadata.csv

# Extract metadata from Microsoft Office documents
exiftool -Author -LastModifiedBy -Company -Manager -Comments document.docx
exiftool -Author -LastModifiedBy -Company -Manager -Comments spreadsheet.xlsx
exiftool -Author -LastModifiedBy -Company -Manager -Comments presentation.pptx

# Extract hidden text and revision history from Word docs
python3 -c "
import olefile
ole = olefile.OleFileIO('document.doc')
if ole.exists('WordDocument'):
    print('WordDocument stream found')
    print(ole.openstream('WordDocument').read()[:500])
for stream in ole.listdir():
    print('Stream:', '/'.join(stream))
"

# Extract GPS coordinates from image EXIF data
exiftool -gps:all -n photo.jpg
exiftool -gpslatitude -gpslongitude -gpsaltitude image.jpg
find . -name "*.jpg" -exec exiftool -gps:all -n {} \; 2>/dev/null | grep -E "GPS (Latitude|Longitude)"
```

### Image Steganography Detection

```bash
# Check images for steganography with steghide
steghide info suspect_image.jpg -p ""
steghide extract -sf suspect_image.jpg -p "" -xf hidden_data.txt

# Use stegoveritas for comprehensive analysis
stegoveritas suspect_image.png -meta -extractLSB -extractMSB

# Analyze image with zsteg (PNG specific)
zsteg suspect_image.png
zsteg -a suspect_image.png > zsteg_output.txt

# Check for hidden data with binwalk
binwalk -e suspect_image.jpg
binwalk --dd='.*' suspect_image.jpg

# JPEG quantization table analysis for steganography detection
python3 -c "
from PIL import Image
import struct
img = Image.open('suspect_image.jpg')
print(f'Format: {img.format}')
print(f'Size: {img.size}')
print(f'Mode: {img.mode}')
"
```

### Network Traffic Metadata Extraction

```bash
# Extract HTTP objects from PCAP
tshark -r capture.pcap --export-objects http,./http_objects/

# Extract DNS queries from PCAP
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u

# Extract SSL/TLS certificate information
tshark -r capture.pcap -Y "ssl.handshake.type == 11" -T fields -e x509ce.dNSName | sort -u

# Extract email addresses from SMTP traffic
tshark -r capture.pcap -Y "smtp" -T fields -e smtp.req.parameter | grep "@" | sort -u

# Extract all URLs from PCAP
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sed 's/\t/\//' | sort -u

# Extract user-agent strings for fingerprinting
tshark -r capture.pcap -Y "http.request" -T fields -e http.user_agent | sort | uniq -c | sort -rn | head -20
```

### Source Code Repository Metadata

```bash
# Extract git commit history with author details
git log --all --format="%H %ae %ai %s" > commit_history.txt

# Find sensitive data in git history
git log --all --diff-filter=D --name-only --pretty=format: -- "*.env" "*.key" "*.pem" "*password*" "*secret*" | sort -u

# Extract author email addresses
git log --all --format="%ae" | sort -u > author_emails.txt

# Check for accidentally committed secrets
trufflehog git file://. --json --only-verified
gitleaks detect --source . --report-format json --report-path gitleaks_report.json

# Search GitHub for exposed .env files
gh search code "DB_PASSWORD" --language env --limit 50 --json repository,path,textMatches
gh search code "API_SECRET" --language python --limit 30 --json repository,path

# Docker image metadata extraction
docker inspect target_image:latest --format='{{.Config.Env}}'
docker history target_image:latest --no-trunc
```

### Media File Forensic Analysis

```bash
# Video file metadata extraction
exiftool -Duration -VideoCodec -AudioCodec -Resolution -CreateDate video.mp4
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4 | jq '.streams[] | {codec_type, codec_name, width, height}'

# Audio file analysis
exiftool -Duration -AudioBitRate -SampleRate -Channels audio.mp3
exiftool -all audio.wav

# Batch metadata extraction from mixed media
for ext in jpg png gif pdf docx xlsx mp4 mp3; do
    echo "=== .$ext files ==="
    find . -name "*.$ext" -exec exiftool -short {} \; 2>/dev/null
done | tee all_metadata.txt

# PDF JavaScript extraction
python3 -c "
import PyPDF2
with open('document.pdf', 'rb') as f:
    reader = PyPDF2.PdfReader(f)
    for i, page in enumerate(reader.pages):
        if '/JS' in page or '/JavaScript' in page:
            print(f'Page {i}: JavaScript found')
        if '/AA' in page:
            print(f'Page {i}: Additional Actions found')
"
```

---

## 21. Social Media Intelligence Scripts

### Twitter/X Intelligence Collection

```python
#!/usr/bin/env python3
"""Twitter/X OSINT collection for security research."""
import requests
import json
import time

def search_twitter_api(query, bearer_token, max_results=100):
    """Search Twitter/X using the v2 API."""
    url = "https://api.twitter.com/2/tweets/search/recent"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    params = {
        "query": f"{query} -is:retweet",
        "max_results": min(max_results, 100),
        "tweet.fields": "created_at,author_id,geo,public_metrics,entities",
        "user.fields": "name,username,location,verified,description",
    }
    all_tweets = []
    while len(all_tweets) < max_results:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            break
        data = resp.json()
        all_tweets.extend(data.get("data", []))
        if "next_token" not in data.get("meta", {}):
            break
        params["next_token"] = data["meta"]["next_token"]
        time.sleep(1)
    return all_tweets

def extract_indicators_from_tweets(tweets):
    """Extract IOCs from tweet text content."""
    import re
    indicators = {"ips": set(), "domains": set(), "hashes": set(), "urls": set()}
    for tweet in tweets:
        text = tweet.get("text", "")
        for ip in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text):
            indicators["ips"].add(ip)
        for domain in re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text):
            indicators["domains"].add(domain)
        for h in re.findall(r'\b[a-fA-F0-9]{32,64}\b', text):
            indicators["hashes"].add(h)
        for url in re.findall(r'https?://[^\s]+', text):
            indicators["urls"].add(url)
    return {k: sorted(v) for k, v in indicators.items()}
```

### LinkedIn Professional Intelligence

```bash
# LinkedIn company intelligence gathering (public data)
linkedin_company_intel() {
    local company="$1"
    echo "=== LinkedIn Intelligence: $company ==="

    # Google dork for LinkedIn profiles
    echo "[1/3] Employee discovery via Google..."
    curl -s "https://www.google.com/search?q=site:linkedin.com/in+\"$company\"+security+OR+engineer+OR+admin" \
        -H "User-Agent: Mozilla/5.0" | grep -oP 'linkedin.com/in/[^"&]+'

    # Technology stack hints from job postings
    echo "[2/3] Technology stack from job postings..."
    curl -s "https://www.google.com/search?q=site:linkedin.com/jobs+\"$company\"+\"engineer\"" \
        -H "User-Agent: Mozilla/5.0" | html2text | grep -iE "python|java|kubernetes|docker|aws|azure"

    # Employee count and growth indicators
    echo "[3/3] Company overview..."
    curl -s "https://www.google.com/search?q=site:linkedin.com/company+\"$company\"" \
        -H "User-Agent: Mozilla/5.0" | html2text | head -30
}

# LinkedIn-based phishing target enumeration
linkedin_phishing_targets() {
    local company="$1"
    local role="$2"
    echo "Searching for: $company - $role"
    curl -s "https://www.google.com/search?q=site:linkedin.com/in+\"$company\"+\"$role\"" \
        -H "User-Agent: Mozilla/5.0" | grep -oP 'linkedin.com/in/[^"&]+' | sort -u
}
```

### Social Media Footprint Scanner

```bash
#!/bin/bash
# social-footprint.sh — Check username across multiple platforms
USERNAME="$1"

echo "=== Social Footprint: $USERNAME ==="

# Check username availability across platforms
check_platform() {
    local name="$1"
    local url="$2"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url")
    if [ "$status" = "200" ]; then
        echo "  [FOUND] $name (HTTP $status)"
    elif [ "$status" = "404" ]; then
        echo "  [NOT FOUND] $name"
    else
        echo "  [UNKNOWN] $name (HTTP $status)"
    fi
}

echo "[1] Checking platforms..."
check_platform "Twitter/X" "https://twitter.com/$USERNAME"
check_platform "GitHub" "https://github.com/$USERNAME"
check_platform "Reddit" "https://www.reddit.com/user/$USERNAME"
check_platform "Instagram" "https://www.instagram.com/$USERNAME/"
check_platform "Keybase" "https://keybase.io/$USERNAME"
check_platform "Medium" "https://medium.com/@$USERNAME"
check_platform "GitLab" "https://gitlab.com/$USERNAME"
check_platform "HackerOne" "https://hackerone.com/$USERNAME"
check_platform "Bugcrowd" "https://bugcrowd.com/$USERNAME"

echo ""
echo "[2] Email breach check..."
# Check email variant
hibp_result=$(curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${USERNAME}@gmail.com" \
    -H "hibp-api-key: $HIBP_API_KEY" \
    -H "user-agent: kali-claw-research" -w "%{http_code}")
echo "  Gmail breach status: $hibp_result"

echo ""
echo "[3] Domain registration check..."
whois "$USERNAME.com" 2>/dev/null | grep -E "(Registrant|Creation Date|Expiry)" | head -5
```

### Reddit and Forum Intelligence

```python
#!/usr/bin/env python3
"""Collect intelligence from Reddit and security forums."""
import requests
import json
import re
import time

def reddit_search(query, subreddit="netsec", limit=25):
    """Search Reddit for security-related posts."""
    url = f"https://www.reddit.com/r/{subreddit}/search.json"
    params = {"q": query, "limit": limit, "sort": "new", "t": "month", "restrict_sr": "on"}
    headers = {"User-Agent": "kali-claw-osint/1.0"}
    resp = requests.get(url, params=params, headers=headers, timeout=30)
    if resp.status_code == 200:
        posts = resp.json()["data"]["children"]
        return [{
            "title": p["data"]["title"],
            "url": f"https://reddit.com{p['data']['permalink']}",
            "score": p["data"]["score"],
            "created": p["data"]["created_utc"],
            "selftext": p["data"]["selftext"][:500],
        } for p in posts]
    return []

def extract_technical_indicators(text):
    """Extract technical indicators from forum posts."""
    patterns = {
        "cve": re.compile(r'CVE-\d{4}-\d{4,}'),
        "ip": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        "hash": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "domain": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
        "mitre": re.compile(r'T\d{4}(?:\.\d{3})?'),
    }
    return {k: sorted(set(p.findall(text))) for k, p in patterns.items()}
```

### Instagram and Image Geolocation

```bash
# Extract geolocation data from public Instagram images
instagram_geo() {
    local username="$1"
    echo "=== Instagram Geolocation: $username ==="

    # Download publicly available images
    curl -s "https://www.instagram.com/$username/" \
        -H "User-Agent: Mozilla/5.0" | grep -oP 'https://[^"]+\.jpg' | head -10 > img_urls.txt

    # Extract EXIF data from downloaded images
    while read url; do
        curl -sL "$url" -o /tmp/ig_img_$$.jpg
        lat=$(exiftool -n -GPSLatitude /tmp/ig_img_$$.jpg 2>/dev/null | awk '{print $NF}')
        lon=$(exiftool -n -GPSLongitude /tmp/ig_img_$$.jpg 2>/dev/null | awk '{print $NF}')
        if [ -n "$lat" ] && [ -n "$lon" ]; then
            echo "  [GEO] Lat: $lat, Lon: $lon"
        fi
        rm -f /tmp/ig_img_$$.jpg
    done < img_urls.txt
}
```

---

## 22. Document Analysis Automation

### PDF Forensic Analysis

```python
#!/usr/bin/env python3
"""Forensic PDF analysis for security research."""
import struct
import re
from collections import Counter

def analyze_pdf_structure(filepath):
    """Analyze PDF internal structure for anomalies."""
    with open(filepath, "rb") as f:
        data = f.read()

    results = {
        "file_size": len(data),
        "header": data[:20].decode("latin-1", errors="replace"),
        "has_linearization": b"Linearized" in data,
        "has_javascript": False,
        "has_auto_launch": False,
        "has_embedded_file": False,
        "has_form": False,
        "suspicious_keywords": [],
        "object_count": data.count(b" obj"),
    }

    # Check for dangerous PDF features
    js_patterns = [b"/JS", b"/JavaScript", b"/Launch", b"/SubmitForm", b"/ImportData"]
    for pattern in js_patterns:
        if pattern in data:
            results["suspicious_keywords"].append(pattern.decode())

    if b"/JS" in data or b"/JavaScript" in data:
        results["has_javascript"] = True
    if b"/Launch" in data:
        results["has_auto_launch"] = True
    if b"/EmbeddedFile" in data:
        results["has_embedded_file"] = True
    if b"/AcroForm" in data:
        results["has_form"] = True

    return results

def extract_pdf_urls(filepath):
    """Extract all URLs embedded in a PDF document."""
    import PyPDF2
    urls = set()
    with open(filepath, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text = page.extract_text() or ""
            for url in re.findall(r'https?://[^\s<>"\')\]]+', text):
                urls.add(url)
            annots = page.get("/Annot", [])
            if isinstance(annots, list):
                for annot in annots:
                    if isinstance(annot, dict) and "/A" in annot:
                        uri = annot["/A"].get("/URI", "")
                        if uri:
                            urls.add(uri)
    return sorted(urls)
```

### Office Document Macro Analysis

```bash
# Extract and analyze VBA macros from Office documents
olevba --decode suspicious_document.docm > macros_decoded.txt
olevba --decode suspicious_spreadsheet.xlsm > xl_macros.txt

# Check for suspicious macro patterns
grep -iE "(Shell|CreateObject|WScript|Run|Execute|Download|http|Open|Write)" macros_decoded.txt

# OLE structure analysis
oleid suspicious_document.doc
olemap suspicious_document.doc

# Extract embedded objects from Office documents
oleobj suspicious_document.doc
rtfobj suspicious_document.rtf

# Python-based Office document analyzer
python3 -c "
import olefile
ole = olefile.OleFileIO('suspicious.doc')
print('OLE Streams:')
for stream in ole.listdir():
    path = '/'.join(stream)
    size = ole.get_size(path)
    print(f'  {path} ({size} bytes)')
    if 'macro' in path.lower() or 'vba' in path.lower():
        print(f'    [!] Macro stream detected')
ole.close()
"

# Batch macro extraction
for f in *.docm *.xlsm *.pptm; do
    [ -f "$f" ] && echo "=== $f ===" && olevba "$f" 2>/dev/null | head -50
done
```

### Malware Document Triage

```python
#!/usr/bin/env python3
"""Triage suspicious documents for malware indicators."""
import hashlib
import os
import subprocess
import json

def calculate_hashes(filepath):
    """Calculate file hashes for malware document triage."""
    with open(filepath, "rb") as f:
        data = f.read()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "ssdeep": None,  # Requires ssdeep library
        "file_size": len(data),
        "file_type": subprocess.run(["file", "-b", filepath], capture_output=True, text=True).stdout.strip(),
    }

def check_yara_rules(filepath, rule_dir="/usr/share/yara-rules/"):
    """Check document against YARA rules for malware detection."""
    results = []
    if os.path.isdir(rule_dir):
        for rule_file in os.listdir(rule_dir):
            if rule_file.endswith(".yar"):
                proc = subprocess.run(
                    ["yara", "-r", os.path.join(rule_dir, rule_file), filepath],
                    capture_output=True, text=True
                )
                if proc.stdout.strip():
                    results.append(proc.stdout.strip())
    return results

def extract_iocs_from_document(filepath):
    """Extract IOCs from document text content."""
    import re
    try:
        result = subprocess.run(
            ["pdftotext", filepath, "-"],
            capture_output=True, text=True, timeout=30
        )
        text = result.stdout
    except Exception:
        text = ""

    iocs = {
        "urls": sorted(set(re.findall(r'https?://[^\s<>"\']+', text))),
        "ips": sorted(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text))),
        "emails": sorted(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', text))),
        "domains": sorted(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text))),
    }
    return iocs
```

### Automated Report Generation

```bash
#!/bin/bash
# document-triage-report.sh — Generate triage report for suspicious documents
DOC_DIR="$1"
REPORT="triage_report_$(date +%Y%m%d_%H%M%S).md"

{
    echo "# Document Triage Report"
    echo "**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "**Directory**: $DOC_DIR"
    echo ""

    for doc in "$DOC_DIR"/*.{pdf,doc,docm,xls,xlsm,ppt,pptm,rtf} 2>/dev/null; do
        [ -f "$doc" ] || continue
        echo "## $(basename "$doc")"
        echo "- **Size**: $(stat -f%z "$doc" 2>/dev/null || stat -c%s "$doc" 2>/dev/null) bytes"
        echo "- **Type**: $(file -b "$doc")"
        echo "- **MD5**: $(md5sum "$doc" | awk '{print $1}')"
        echo "- **SHA256**: $(sha256sum "$doc" | awk '{print $1}')"

        # Check for macros
        if echo "$doc" | grep -qE '\.(docm|xlsm|pptm)$'; then
            echo "- **Macros**: $(olevba "$doc" 2>/dev/null | grep -c "VBA" || echo "None detected")"
        fi

        # Check for JavaScript in PDFs
        if echo "$doc" | grep -q '\.pdf$'; then
            js_check=$(python3 -c "
with open('$doc', 'rb') as f:
    data = f.read()
if b'/JavaScript' in data or b'/JS' in data:
    print('DETECTED: JavaScript in PDF')
elif b'/Launch' in data:
    print('DETECTED: Auto-launch action')
elif b'/EmbeddedFile' in data:
    print('DETECTED: Embedded file')
else:
    print('Clean')
" 2>/dev/null)
            echo "- **PDF Analysis**: $js_check"
        fi
        echo ""
    done
} > "$REPORT"

echo "[+] Report saved to $REPORT"
```

---

## 23. Cross-Source Correlation Commands

### Multi-Source IOC Enrichment

```python
#!/usr/bin/env python3
"""Cross-source IOC enrichment and correlation engine."""
import requests
import json
import time
from collections import defaultdict

class IOCCorrelator:
    """Correlate IOCs across multiple threat intelligence sources."""

    def __init__(self, config):
        self.config = config
        self.enrichment_cache = {}

    def enrich_ip(self, ip):
        """Enrich an IP address using multiple sources."""
        enrichment = {"ip": ip, "sources": {}, "risk_score": 0}

        # VirusTotal
        if "vt_key" in self.config:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                resp = requests.get(url, headers={"x-apikey": self.config["vt_key"]}, timeout=30)
                if resp.status_code == 200:
                    attrs = resp.json()["data"]["attributes"]
                    stats = attrs.get("last_analysis_stats", {})
                    enrichment["sources"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "country": attrs.get("country", ""),
                        "as_owner": attrs.get("as_owner", ""),
                    }
                    enrichment["risk_score"] += stats.get("malicious", 0)
            except Exception:
                pass
            time.sleep(1)

        # AbuseIPDB
        if "abuseipdb_key" in self.config:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
                resp = requests.get(url, headers={"Key": self.config["abuseipdb_key"], "Accept": "application/json"}, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()["data"]
                    enrichment["sources"]["abuseipdb"] = {
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                    }
                    enrichment["risk_score"] += data.get("abuseConfidenceScore", 0) / 10
            except Exception:
                pass
            time.sleep(1)

        # Shodan
        if "shodan_key" in self.config:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self.config['shodan_key']}"
                resp = requests.get(url, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    enrichment["sources"]["shodan"] = {
                        "ports": data.get("ports", []),
                        "os": data.get("os", ""),
                        "hostnames": data.get("hostnames", []),
                        "vulns": list(data.get("vulns", [])[:10]),
                    }
            except Exception:
                pass

        return enrichment

    def correlate(self, iocs_file):
        """Correlate a list of IOCs from a file."""
        results = []
        with open(iocs_file) as f:
            iocs = [line.strip() for line in f if line.strip()]
        for ioc in iocs:
            enriched = self.enrich_ip(ioc)
            results.append(enriched)
            time.sleep(2)
        return results
```

### Timeline Correlation Analysis

```bash
#!/bin/bash
# timeline-correlation.sh — Build timeline from multiple intelligence sources
TARGET="$1"
OUTDIR="./timeline/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Building timeline for: $TARGET"

# CVE disclosure timeline
echo "[1/5] CVE timeline..."
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$TARGET&resultsPerPage=100" \
    | jq -r '.vulnerabilities[]?.cve | "\(.published[:10]) CVE \(.id) CVSS:\(.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A")"' \
    | sort > "$OUTDIR/cve_timeline.txt"

# Certificate transparency timeline
echo "[2/5] Certificate timeline..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
    | jq -r '.[] | "\(.not_before[:10]) CERT \(.name_value) \(.issuer_name)"' \
    | sort > "$OUTDIR/cert_timeline.txt"

# Shodan historical timeline
echo "[3/5] Shodan exposure timeline..."
shodan search "hostname:$TARGET" --history --limit 50 --fields ip_str,port,timestamp 2>/dev/null \
    | sort > "$OUTDIR/shodan_timeline.txt"

# Wayback Machine timeline
echo "[4/5] Wayback timeline..."
curl -s "http://archive.org/wayback/available?url=$TARGET" | jq '.'

# Combined timeline
echo "[5/5] Merging timelines..."
cat "$OUTDIR"/*_timeline.txt 2>/dev/null | sort | uniq > "$OUTDIR/combined_timeline.txt"
echo "[+] Timeline saved to $OUTDIR/combined_timeline.txt"
```

### Entity Relationship Mapper

```python
#!/usr/bin/env python3
"""Map relationships between security entities across data sources."""
import json
import re
from collections import defaultdict

class EntityMapper:
    """Build entity relationship graphs from multiple intelligence sources."""

    def __init__(self):
        self.entities = defaultdict(set)
        self.relationships = []

    def add_source(self, source_name, data):
        """Process data from a new source and extract entities."""
        if isinstance(data, str):
            self._extract_from_text(source_name, data)
        elif isinstance(data, dict):
            self._extract_from_dict(source_name, data)

    def _extract_from_text(self, source, text):
        """Extract entities from text content."""
        for cve in re.findall(r'CVE-\d{4}-\d{4,}', text):
            self.entities["cve"].add(cve)
            self.relationships.append({"source": source, "entity": cve, "type": "cve"})
        for ip in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text):
            self.entities["ip"].add(ip)
            self.relationships.append({"source": source, "entity": ip, "type": "ip"})
        for technique in re.findall(r'T\d{4}(?:\.\d{3})?', text):
            self.entities["mitre_technique"].add(technique)
            self.relationships.append({"source": source, "entity": technique, "type": "technique"})
        for actor in re.findall(r'(?:APT|FIN|UNC)\d+', text):
            self.entities["threat_actor"].add(actor)
            self.relationships.append({"source": source, "entity": actor, "type": "actor"})
        for domain in re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text):
            self.entities["domain"].add(domain)
            self.relationships.append({"source": source, "entity": domain, "type": "domain"})

    def _extract_from_dict(self, source, data):
        """Extract entities from structured JSON data."""
        text = json.dumps(data)
        self._extract_from_text(source, text)

    def find_connections(self, entity):
        """Find all entities connected to a given entity through shared sources."""
        sources = set()
        for rel in self.relationships:
            if rel["entity"] == entity:
                sources.add(rel["source"])
        connected = set()
        for rel in self.relationships:
            if rel["source"] in sources and rel["entity"] != entity:
                connected.add((rel["entity"], rel["type"]))
        return sorted(connected)

    def export_graph(self, output_path):
        """Export relationship graph as JSON for visualization."""
        graph = {
            "nodes": [{"id": e, "type": t} for t, entities in self.entities.items() for e in entities],
            "edges": [{"from": r["source"], "to": r["entity"], "type": r["type"]} for r in self.relationships],
        }
        with open(output_path, "w") as f:
            json.dump(graph, f, indent=2, default=str)
```

### Cross-Platform Username Correlation

```bash
#!/bin/bash
# username-correlate.sh — Correlate usernames across platforms
USERNAME="$1"

echo "=== Cross-Platform Correlation: $USERNAME ==="

# Check username on multiple platforms
declare -A platforms
platforms=(
    ["GitHub"]="https://github.com/$USERNAME"
    ["GitLab"]="https://gitlab.com/$USERNAME"
    ["Twitter"]="https://twitter.com/$USERNAME"
    ["Reddit"]="https://www.reddit.com/user/$USERNAME"
    ["Keybase"]="https://keybase.io/$USERNAME"
    ["HackerOne"]="https://hackerone.com/$USERNAME"
    ["Medium"]="https://medium.com/@$USERNAME"
    ["DevTo"]="https://dev.to/$USERNAME"
    ["StackOverflow"]="https://stackoverflow.com/users/?q=$USERNAME"
    ["npm"]="https://www.npmjs.com/~$USERNAME"
)

found_platforms=()
for platform in "${(@k)platforms}"; do
    url="${platforms[$platform]}"
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null)
    if [ "$status" = "200" ]; then
        echo "  [FOUND] $platform: $url"
        found_platforms+=("$platform")
    fi
done

echo ""
echo "=== Correlation Summary ==="
echo "Username found on ${#found_platforms} platforms:"
for p in "${found_platforms[@]}"; do
    echo "  - $p"
done

# Cross-reference for additional identifiers
echo ""
echo "=== Additional Identifiers ==="
for p in "${found_platforms[@]}"; do
    case "$p" in
        "GitHub")
            gh api "users/$USERNAME" --jq '{name, email, company, blog, location, bio, public_repos, created_at}' 2>/dev/null
            ;;
        "Keybase")
            curl -s "https://keybase.io/_/api/1.0/user/lookup.json?username=$USERNAME" | jq '.them.proofs[]?.proof_type' 2>/dev/null
            ;;
    esac
done
```

### Breach Data Cross-Reference

```bash
#!/bin/bash
# breach-crossref.sh — Cross-reference breach data across sources
DOMAIN="$1"

echo "=== Breach Data Cross-Reference: $DOMAIN ==="

# HIBP domain breach enumeration
echo "[1/4] HaveIBeenPwned..."
curl -s "https://haveibeenpwned.com/api/v3/breaches?domain=$DOMAIN" \
    -H "hibp-api-key: $HIBP_API_KEY" \
    -H "user-agent: kali-claw-research" \
    | jq '.[] | {name: .Name, date: .BreachDate, data: .DataClasses, count: .PwnCount}' 2>/dev/null

# Dehashed search for domain
echo "[2/4] DeHashed..."
curl -s "https://api.dehashed.com/search?query=domain:$DOMAIN" \
    -u "$DEHASHED_API_KEY:" \
    -H "Accept: application/json" \
    | jq '.entries[:10] | .[] | {email, username, password, breach}' 2>/dev/null

# Intelligence X breach search
echo "[3/4] Intelligence X..."
curl -s "https://2.intelx.io/phonebook/search" \
    -H "x-key: $INTELX_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"term\": \"@$DOMAIN\", \"maxresults\": 20, \"media\": 0}" \
    | jq '.selectors[] | {value: .selectorvalue, type: .selectorvalue_type}' 2>/dev/null

# GitHub credential leak search
echo "[4/4] GitHub credential leaks..."
gh search code "\"$DOMAIN\" password OR api_key OR secret" --limit 20 \
    --json repository,path,textMatches 2>/dev/null | jq '.[].repository.fullName' 2>/dev/null

echo "[+] Cross-reference complete"
```
