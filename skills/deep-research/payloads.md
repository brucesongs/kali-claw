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
