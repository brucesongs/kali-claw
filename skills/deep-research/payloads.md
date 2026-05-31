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
