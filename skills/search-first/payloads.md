# Search First — Payloads & Commands

> Companion to `SKILL.md`. Contains search templates, command sequences, and evaluation scripts for exploit/tool/technique discovery organized by source.

---

## Quick Start Checklist

```
1. Define need → 2. Parallel search (ExploitDB + GitHub + MSF + Nuclei) → 3. Evaluate → 4. Decide → 5. Execute
```

---

## Exploit-DB Search Templates

### By CVE

```bash
# Search by CVE ID
searchsploit CVE-2025-12345

# View exploit code
searchsploit -x 12345

# Copy exploit to current directory
searchsploit -m 12345

# Search with exact match
searchsploit -e "Apache 2.4.49"
```

### By Service/Version

```bash
# Search by service name and version
searchsploit apache 2.4.49
searchsploit openssh 8.9
searchsploit nginx 1.24
searchsploit wordpress 6.0

# Filter by type
searchsploit --exclude-poc apache 2.4 remote
searchsploit -t remote apache 2.4

# Output as JSON for processing
searchsploit -j apache 2.4 | jq '.RESULTS_EXPLOIT[] | {Title: .Title, Type: .Type, Platform: .Platform}'
```

### By Technique

```bash
# Search by attack technique
searchsploit "path traversal"
searchsploit "remote code execution" php
searchsploit "sql injection" wordpress
searchsploit "privilege escalation" linux
searchsploit "buffer overflow" x86 remote
```

---

## GitHub Search Templates

### Exploit PoC Search

```bash
# Search for CVE PoC repositories
gh search repos "CVE-2025-12345" --sort stars --limit 20
gh search repos "CVE-2025-12345 poc" --sort stars --limit 10

# Search for exploit code
gh search code "CVE-2025-12345" --language python --limit 20
gh search code "CVE-2025-12345" --language exploit --limit 20

# Search specific security researchers
gh search code "CVE-2025-12345" --user=projectdiscovery
gh search code "CVE-2025-12345" --user=ptswarm
```

### Tool Search

```bash
# Search for security tools by capability
gh search repos "subdomain enumeration tool" --sort stars --limit 20
gh search repos "xss scanner" --sort stars --limit 20
gh search repos "active directory enumeration" --sort stars --limit 20
gh search repos "api security testing" --sort stars --limit 20

# Filter by update recency
gh search repos "nuclei templates" --sort updated --limit 20

# Search in specific organizations
gh search repos "exploit" --owner=projectdiscovery --limit 20
gh search repos "exploit" --owner=rapid7 --limit 20
```

### Technique Search

```bash
# Search for attack technique implementations
gh search code "kerberoasting" --language python --limit 20
gh search code "dll injection" --language c --limit 20
gh search code "token impersonation" --language csharp --limit 20
```

---

## Metasploit Search Templates

### Module Search

```bash
# Search exploit modules
msfconsole -q -x "search type:exploit name:apache; exit"

# Search auxiliary modules
msfconsole -q -x "search type:auxiliary name:scanner; exit"

# Search post-exploitation modules
msfconsole -q -x "search type:post name:escalate; exit"

# Search by platform
msfconsole -q -x "search platform:windows type:exploit name:smb; exit"

# Search by CVE
msfconsole -q -x "search cve:CVE-2025-12345; exit"
```

### Module Evaluation

```bash
# Show module details
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show info; exit"

# Check module options
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show options; exit"

# List compatible payloads
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show payloads; exit"
```

---

## Nuclei Template Search

### Template Discovery

```bash
# List all available templates
nuclei -tl | wc -l

# Search templates by keyword
nuclei -tl -tags cve | grep "2025"
nuclei -tl -tags sqli
nuclei -tl -tags xss
nuclei -tl -tags ssrf
nuclei -tl -tags idor

# Search by severity
nuclei -tl -severity critical
nuclei -tl -severity critical,high

# Search by author
nuclei -tl -author pdteam
```

### Custom Template Search

```bash
# Search in nuclei-templates repo
gh search code "CVE-2025" --repo projectdiscovery/nuclei-templates --limit 20

# Search for specific technology templates
nuclei -tl -tags wordpress
nuclei -tl -tags jenkins
nuclei -tl -tags api
```

---

## Kali Package Search

### Tool Availability Check

```bash
# Search Kali package repository
apt search <keyword> 2>/dev/null | grep -i security

# Check if tool is installed
dpkg -l | grep <tool>
which <tool>

# Install missing tool
apt install -y <tool>

# Search by category
apt search "web scanner" 2>/dev/null
apt search "password crack" 2>/dev/null
apt search "network scanner" 2>/dev/null
```

---

## Evaluation Scoring Template

### Result Quality Matrix

```markdown
## Search Result Evaluation: [Need]

| Source | Result | Reliability | Compatibility | OPSEC | Maintenance | Score |
|--------|--------|-------------|---------------|-------|-------------|-------|
| ExploitDB | [ID] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |
| GitHub | [URL] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |
| MSF | [Module] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |
| Nuclei | [Template] | [High/Med/Low] | [Yes/Partial/No] | [Safe/Risky] | [Active/Stale] | [1-10] |

### Decision
- **Action**: [Use as-is / Modify / Compose / Build custom]
- **Selected**: [source/result]
- **Rationale**: [why this choice]
```

### Scoring Criteria

| Factor | Weight | High (3) | Medium (2) | Low (1) |
|--------|--------|----------|------------|---------|
| Reliability | 30% | Verified PoC, multiple reports | Single report, consistent | Unverified, theoretical |
| Compatibility | 25% | Exact version match | Adjacent version | Requires adaptation |
| OPSEC | 20% | Silent/low noise | Moderate detection | Noisy/widely detected |
| Maintenance | 15% | Updated within 30 days | Updated within 1 year | Abandoned/legacy |
| Documentation | 10% | Full docs + examples | Basic README | No documentation |

---

## Decision Templates

### Use As-Is Decision

```markdown
## Decision: Use Existing Tool/Exploit
- **Source**: [ExploitDB/GitHub/MSF/Nuclei]
- **Result**: [ID/URL/Module]
- **Target match**: [exact version/service confirmed]
- **Risk level**: [low/medium/high]
- **Detection risk**: [minimal/moderate/high]
- **Command**: [exact command to execute]
```

### Modify Decision

```markdown
## Decision: Modify Existing Tool/Exploit
- **Source**: [ExploitDB/GitHub]
- **Original**: [what it does]
- **Modification needed**: [what to change]
- **Estimated effort**: [minutes/hours]
- **Risk of modification**: [low/medium/high]
```

### Build Custom Decision

```markdown
## Decision: Build Custom Exploit/Tool
- **Need**: [what capability is needed]
- **Search results**: [N relevant results, none suitable because...]
- **Approach**: [brief implementation plan]
- **Estimated effort**: [hours/days]
- **Dependencies**: [tools/libraries required]
```

---

## Automated Search Pipelines

### Multi-Engine Parallel Search

```bash
#!/bin/bash
# parallel-search.sh — Search multiple sources simultaneously
QUERY="$1"
OUTPUT_DIR="/tmp/search_results_$$"
mkdir -p "$OUTPUT_DIR"

# ExploitDB
searchsploit "$QUERY" --json > "$OUTPUT_DIR/exploitdb.json" 2>/dev/null &

# GitHub repos
gh search repos "$QUERY" --sort stars --limit 20 --json fullName,description,stargazersCount > "$OUTPUT_DIR/gh_repos.json" &

# GitHub code
gh search code "$QUERY" --limit 20 --json repository,path > "$OUTPUT_DIR/gh_code.json" &

# NVD
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$(echo $QUERY | tr ' ' '+')" > "$OUTPUT_DIR/nvd.json" &

wait
echo "[+] Results collected in $OUTPUT_DIR/"
echo "  ExploitDB: $(jq '.RESULTS_EXPLOIT | length' "$OUTPUT_DIR/exploitdb.json" 2>/dev/null || echo 0)"
echo "  GitHub repos: $(jq 'length' "$OUTPUT_DIR/gh_repos.json")"
echo "  GitHub code: $(jq 'length' "$OUTPUT_DIR/gh_code.json")"
echo "  NVD CVEs: $(jq '.totalResults' "$OUTPUT_DIR/nvd.json")"
```

### Search Result Deduplication

```python
from hashlib import md5

def deduplicate_results(results: list[dict]) -> list[dict]:
    """Remove duplicate findings across search sources."""
    seen = {}
    for r in results:
        key = md5(f"{r.get('title','')}{r.get('url','')}".lower().encode()).hexdigest()
        if key not in seen or r.get("reliability", 0) > seen[key].get("reliability", 0):
            seen[key] = r
    return list(seen.values())
```

### Version-Aware Search

```bash
# Search with version constraints
search_by_version() {
    local product="$1"
    local version="$2"
    
    echo "=== Searching for $product $version ==="
    
    # ExploitDB
    searchsploit "$product $version" 2>/dev/null | grep -v "^$"
    
    # NVD with CPE
    local cpe="cpe:2.3:a:*:${product}:${version}:*:*:*:*:*:*:*"
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$cpe" \
      | jq '.vulnerabilities[].cve | {id, severity: .metrics.cvssMetricV31[0].cvssData.baseScore}'
    
    # Nuclei templates
    nuclei -tl -tags "$product" 2>/dev/null | head -10
}
```

---

## Package Registry Search

### npm Security Search

```bash
# Search npm for security tools
npm search security scanner --json | jq '.[:10] | .[].name'

# Check package for known vulnerabilities
npm audit --registry https://registry.npmjs.org --json 2>/dev/null | jq '.vulnerabilities | keys'

# Verify package authenticity
npm view <package> --json | jq '{name, version, maintainers: [.maintainers[].name], repository: .repository.url}'
```

### PyPI Security Tools

```bash
# Search PyPI for security packages
pip search "vulnerability scanner" 2>/dev/null || \
  curl -s "https://pypi.org/search/?q=vulnerability+scanner&o=" | grep -oP 'class="package-snippet__name">[^<]+' | sed 's/.*>//' | head -10

# Check package safety
pip-audit -r requirements.txt --format=json | jq '[.[] | select(.fix_versions != [])]'

# Package metadata inspection
pip show <package> | grep -iE "author|home-page|requires"
```

### Go Module Search

```bash
# Search Go packages
curl -s "https://pkg.go.dev/search?q=security+scanner&m=package" | grep -oP '/[a-z][^"]*' | head -10

# Check module vulnerabilities
govulncheck -json ./... | jq '.vulnerability[] | {id: .osv.id, summary: .osv.summary}'

# Module info
go list -m -json all | jq 'select(.Indirect != true) | {Path, Version}'
```

---

## Exploit Adaptation Workflow

### ExploitDB Adaptation

```bash
# Download and adapt exploit
adapt_exploit() {
    local edb_id="$1"
    local target_ip="$2"
    
    # Download
    searchsploit -m "$edb_id"
    local filename=$(find . -maxdepth 1 -name "${edb_id}*" -newer /tmp -type f)
    
    # Analyze requirements
    echo "=== Dependencies ==="
    grep -iE "^import|^require|^from|^use" "$filename" | sort -u
    
    # Check target parameters
    echo "=== Parameters to modify ==="
    grep -nE "(RHOST|LHOST|target|ip|port)" "$filename"
}
```

### Metasploit Module Customization

```bash
# Clone and modify module
customize_msf_module() {
    local module_path="$1"
    local custom_name="$2"
    
    # Copy to custom modules dir
    cp "/usr/share/metasploit-framework/modules/$module_path" \
       "$HOME/.msf4/modules/exploits/custom/${custom_name}.rb"
    
    echo "[*] Copied to ~/.msf4/modules/exploits/custom/${custom_name}.rb"
    echo "[*] Edit target parameters, then: msfconsole -x 'reload_all'"
}
```

### Nuclei Template Customization

```yaml
# custom-check.yaml — Template adapted from search results
id: custom-version-check

info:
  name: Custom Version Detection
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
      - "{{BaseURL}}/api/info"
    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - '"version"\s*:\s*"[0-9]+\.[0-9]+\.[0-9]+"'
    extractors:
      - type: regex
        regex:
          - '"version"\s*:\s*"([^"]+)"'
        group: 1
```

---

## Search History and Knowledge Base

### Search Session Logger

```bash
#!/bin/bash
# log-search.sh — Record search sessions for future reference
LOG_FILE="$HOME/.search_history/$(date +%Y-%m-%d).log"
mkdir -p "$(dirname "$LOG_FILE")"

log_search() {
    local query="$1"
    local source="$2"
    local result_count="$3"
    local useful="$4"
    
    echo "$(date +%H:%M:%S) | $source | $query | results=$result_count | useful=$useful" >> "$LOG_FILE"
}

# Usage during search
log_search "apache struts rce" "exploitdb" "12" "3"
log_search "CVE-2025-1234" "nvd" "1" "1"
```

### Search Pattern Library

```bash
# Common search patterns by objective
declare -A SEARCH_PATTERNS=(
    ["recon"]="gh search repos 'TARGET recon enumeration' --sort stars"
    ["exploit"]="searchsploit 'TARGET VERSION'"
    ["bypass"]="gh search code 'TARGET bypass WAF evasion' --language python"
    ["postex"]="gh search repos 'TARGET post-exploitation persistence' --sort stars"
    ["privesc"]="searchsploit 'TARGET privilege escalation local'"
)

quick_search() {
    local objective="$1"
    local target="$2"
    local cmd="${SEARCH_PATTERNS[$objective]}"
    eval "${cmd//TARGET/$target}"
}
```

### Search Result Cache

```python
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

CACHE_DIR = Path.home() / ".search_cache"
CACHE_TTL = timedelta(hours=24)

def cached_search(query: str, source: str, search_fn) -> dict:
    """Cache search results to avoid redundant API calls."""
    CACHE_DIR.mkdir(exist_ok=True)
    cache_key = hashlib.md5(f"{source}:{query}".encode()).hexdigest()
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    if cache_file.exists():
        cached = json.loads(cache_file.read_text())
        cached_time = datetime.fromisoformat(cached["timestamp"])
        if datetime.now() - cached_time < CACHE_TTL:
            return cached["results"]
    
    results = search_fn(query)
    cache_file.write_text(json.dumps({
        "query": query,
        "source": source,
        "timestamp": datetime.now().isoformat(),
        "results": results
    }))
    return results
```

---

## Advanced Search Operators

### Google Dorks for Security Research

```bash
# Find exposed admin panels
# site:target.com inurl:admin OR inurl:login OR inurl:dashboard
# site:target.com intitle:"index of" OR intitle:"directory listing"

# Discover sensitive files via Google
# site:target.com filetype:sql OR filetype:env OR filetype:log
# site:target.com filetype:pdf "confidential" OR "internal use only"
# site:target.com ext:xml inurl:sitemap OR inurl:config

# Find exposed credentials and keys
# site:github.com "target.com" password OR secret OR api_key
# "target.com" filetype:yml password OR token
# inurl:".env" "DB_PASSWORD" OR "API_KEY" site:target.com

# Discover subdomains and infrastructure
# site:*.target.com -www
# inurl:target.com intext:"powered by" OR intext:"running on"

# Google dork automation with dorking tool
cat << 'EOF' > dorks.txt
site:TARGET inurl:admin
site:TARGET filetype:sql
site:TARGET filetype:env
site:TARGET intitle:"index of"
site:TARGET ext:bak OR ext:old OR ext:backup
"TARGET" password OR secret site:github.com
site:TARGET inurl:api
EOF
sed -i "s/TARGET/$TARGET/g" dorks.txt
```

### Shodan Queries

```bash
# Basic Shodan searches for target reconnaissance
shodan search "hostname:target.com" --fields ip_str,port,org,os --limit 100

# Find specific services
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,product
shodan search "http.title:target.com" --fields ip_str,port,http.title
shodan search "org:\"Target Corp\"" --fields ip_str,port,product,version

# Vulnerability-focused queries
shodan search "vuln:CVE-2025-12345" --fields ip_str,port,org --limit 50
shodan search "product:apache version:2.4.49" --fields ip_str,port,org
shodan search "port:9200 product:elasticsearch" --fields ip_str,org,data

# Industrial/IoT discovery
shodan search "port:502 country:US" --fields ip_str,org  # Modbus
shodan search "port:47808 country:US" --fields ip_str,org  # BACnet
shodan search "webcam has_screenshot:true country:US" --fields ip_str,org

# Shodan CLI automation
shodan stats --facets port "org:\"Target Corp\""
shodan stats --facets vuln "org:\"Target Corp\""
shodan host <target_ip> | tee evidence/shodan_host.txt
shodan download results "hostname:target.com" --limit 1000
shodan parse results.json.gz --fields ip_str,port,product > evidence/shodan_parsed.csv
```

### Censys Filters

```bash
# Censys search via CLI
censys search "services.tls.certificates.leaf.subject.common_name:target.com" \
  --index-type hosts -o evidence/censys_hosts.json

# Find hosts by certificate
censys search "services.tls.certificates.leaf.issuer.organization:\"Let's Encrypt\" AND \
  services.tls.certificates.leaf.subject.common_name:*.target.com"

# Service-specific queries
censys search "services.service_name:HTTP AND services.http.response.headers.server:nginx AND \
  autonomous_system.name:\"Target Corp\""

# Censys Python SDK for programmatic access
python3 << 'EOF'
from censys.search import CensysHosts
h = CensysHosts()
query = "services.tls.certificates.leaf.subject.common_name:target.com"
for page in h.search(query, per_page=100, pages=5):
    for host in page:
        print(f"{host['ip']}:{','.join(str(s['port']) for s in host.get('services', []))}")
EOF

# FOFA queries (alternative to Shodan/Censys)
# domain="target.com" && status_code="200"
# cert="target.com" && port="443"
# header="X-Powered-By" && domain="target.com"
curl -s "https://fofa.info/api/v1/search/all?email=$FOFA_EMAIL&key=$FOFA_KEY&qbase64=$(echo -n 'domain="target.com"' | base64)" | jq '.results[]'
```

### ZoomEye and Hunter Queries

```bash
# ZoomEye API search
curl -s -H "API-KEY: $ZOOMEYE_KEY" \
  "https://api.zoomeye.org/host/search?query=hostname:target.com&page=1" \
  | jq '.matches[] | {ip, portinfo: .portinfo.port, app: .portinfo.app}'

# Hunter.io for email discovery
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_KEY" \
  | jq '.data.emails[] | {value, type, confidence}'

# SecurityTrails for DNS history
curl -s -H "APIKEY: $SECTRAILS_KEY" \
  "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  | jq '.subdomains[]' | sed "s/$/\.target.com/"

# VirusTotal domain report
curl -s -H "x-apikey: $VT_KEY" \
  "https://www.virustotal.com/api/v3/domains/target.com/subdomains?limit=40" \
  | jq '.data[].id'
```

---

## Multi-Engine Correlation

### Cross-Referencing Results

```bash
#!/bin/bash
# correlate-results.sh — Cross-reference findings across multiple sources
TARGET="$1"
EVIDENCE_DIR="evidence/correlation_$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Collect from multiple sources
shodan search "hostname:$TARGET" --fields ip_str,port > "$EVIDENCE_DIR/shodan.txt" 2>/dev/null &
censys search "services.tls.certificates.leaf.subject.common_name:$TARGET" \
  --index-type hosts 2>/dev/null | jq -r '.[] | "\(.ip):\(.services[].port)"' > "$EVIDENCE_DIR/censys.txt" &
nmap -sT -p- --min-rate 5000 "$TARGET" -oG - | grep "open" > "$EVIDENCE_DIR/nmap.txt" &
wait

# Find IPs confirmed by multiple sources
cat "$EVIDENCE_DIR"/*.txt | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn \
  | awk '$1 >= 2 {print $2, "(confirmed by "$1" sources)"}' > "$EVIDENCE_DIR/confirmed_hosts.txt"

echo "[+] Correlation complete. High-confidence targets:"
cat "$EVIDENCE_DIR/confirmed_hosts.txt"
```

### Confidence Scoring

```python
#!/usr/bin/env python3
"""Score search results by cross-source confirmation and recency."""
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class Finding:
    ip: str
    port: int
    service: str
    source: str
    timestamp: datetime
    raw_data: dict

def calculate_confidence(findings: list[Finding]) -> dict[str, float]:
    """Calculate confidence score (0-1) for each unique target."""
    targets = {}
    for f in findings:
        key = f"{f.ip}:{f.port}"
        if key not in targets:
            targets[key] = {"sources": set(), "timestamps": [], "services": set()}
        targets[key]["sources"].add(f.source)
        targets[key]["timestamps"].append(f.timestamp)
        targets[key]["services"].add(f.service)

    scores = {}
    for key, data in targets.items():
        source_score = min(len(data["sources"]) / 3.0, 1.0) * 0.4
        recency = max(data["timestamps"])
        age_days = (datetime.now() - recency).days
        recency_score = max(0, 1.0 - (age_days / 90.0)) * 0.3
        consistency_score = (1.0 if len(data["services"]) == 1 else 0.5) * 0.3
        scores[key] = round(source_score + recency_score + consistency_score, 2)
    return scores
```

### Automated Deduplication and Merging

```bash
# Merge and deduplicate results from multiple scan tools
merge_scan_results() {
  local output="$1"
  shift
  local inputs=("$@")
  
  # Normalize all inputs to IP:PORT format
  for file in "${inputs[@]}"; do
    case "$file" in
      *.gnmap) grep "Ports:" "$file" | awk -F'[:/]' '{
        host=$1; gsub(/Host: /,"",host); gsub(/ .*/,"",host)
        for(i=1;i<=NF;i++) if($i~/open/) print host":"$(i-1)
      }' ;;
      *.json) jq -r '.[] | "\(.ip):\(.port)"' "$file" 2>/dev/null ;;
      *) grep -oP '\d+\.\d+\.\d+\.\d+:\d+' "$file" ;;
    esac
  done | sort -u -t: -k1,1 -k2,2n > "$output"
  
  echo "[+] Merged $(wc -l < "$output") unique targets from ${#inputs[@]} sources"
}

merge_scan_results evidence/merged_targets.txt \
  scans/nmap.gnmap evidence/shodan.json evidence/censys.txt
```

### Source Reliability Weighting

```python
#!/usr/bin/env python3
"""Weight search results by source reliability for prioritized targeting."""

SOURCE_WEIGHTS = {
    "nmap_direct": 1.0,      # Direct scan — highest confidence
    "shodan": 0.8,           # Passive — may be stale
    "censys": 0.8,           # Passive — may be stale
    "exploitdb": 0.7,        # Exploit exists — needs version confirm
    "nvd": 0.6,              # Vulnerability reported — needs validation
    "github_poc": 0.5,       # PoC exists — quality varies
    "google_dork": 0.4,      # Indexed info — may be outdated
}

def weighted_priority(findings: list[dict]) -> list[dict]:
    """Sort findings by weighted confidence for engagement prioritization."""
    for f in findings:
        base_weight = SOURCE_WEIGHTS.get(f["source"], 0.3)
        # Boost for multiple confirmations
        confirmation_bonus = min(f.get("confirmed_by", 1) * 0.1, 0.3)
        # Penalty for age
        age_penalty = min(f.get("age_days", 0) * 0.005, 0.3)
        f["priority_score"] = round(base_weight + confirmation_bonus - age_penalty, 3)
    return sorted(findings, key=lambda x: x["priority_score"], reverse=True)
```

---

## Automated Search Pipelines

### Scheduled Queries with Change Detection

```bash
#!/bin/bash
# scheduled-search.sh — Run periodic searches and alert on changes
SEARCH_DIR="$HOME/.search_monitor"
mkdir -p "$SEARCH_DIR/history"

monitor_target() {
  local target="$1"
  local current="$SEARCH_DIR/current_${target}.txt"
  local previous="$SEARCH_DIR/previous_${target}.txt"
  
  # Rotate previous results
  [ -f "$current" ] && mv "$current" "$previous"
  
  # Run fresh scan
  shodan search "hostname:$target" --fields ip_str,port 2>/dev/null | sort > "$current"
  
  # Detect changes
  if [ -f "$previous" ]; then
    local new_entries=$(comm -13 "$previous" "$current")
    local removed_entries=$(comm -23 "$previous" "$current")
    
    if [ -n "$new_entries" ]; then
      echo "[ALERT] New services detected for $target:"
      echo "$new_entries"
      echo "$new_entries" >> "$SEARCH_DIR/history/$(date +%Y%m%d)_new.txt"
    fi
    if [ -n "$removed_entries" ]; then
      echo "[INFO] Services removed for $target:"
      echo "$removed_entries"
    fi
  fi
}

# Run for all monitored targets
while read -r target; do
  monitor_target "$target"
done < "$SEARCH_DIR/targets.txt"
```

### Continuous Monitoring Pipeline

```python
#!/usr/bin/env python3
"""Continuous search monitoring with alerting for attack surface changes."""
import json
import time
import hashlib
import smtplib
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText

MONITOR_DIR = Path.home() / ".search_monitor"
CHECK_INTERVAL = 3600  # 1 hour

class SearchMonitor:
    def __init__(self, targets: list[str]):
        self.targets = targets
        self.state_file = MONITOR_DIR / "state.json"
        MONITOR_DIR.mkdir(exist_ok=True)
        self.state = self._load_state()

    def _load_state(self) -> dict:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {}

    def _save_state(self):
        self.state_file.write_text(json.dumps(self.state, indent=2))

    def check_target(self, target: str) -> list[str]:
        """Run searches and return list of changes."""
        # Implementation would call Shodan/Censys APIs
        changes = []
        current_hash = hashlib.md5(f"{target}:{time.time()//3600}".encode()).hexdigest()
        prev_hash = self.state.get(target, {}).get("hash", "")
        if prev_hash and prev_hash != current_hash:
            changes.append(f"Attack surface changed for {target}")
        self.state[target] = {"hash": current_hash, "last_check": datetime.now().isoformat()}
        self._save_state()
        return changes

    def alert(self, changes: list[str]):
        """Send alert for detected changes."""
        if not changes:
            return
        print(f"[ALERT] {len(changes)} changes detected at {datetime.now().isoformat()}")
        for change in changes:
            print(f"  - {change}")
```

### Alerting Integration

```bash
#!/bin/bash
# alert-on-change.sh — Send alerts via multiple channels
ALERT_FILE="/tmp/search_alerts_$$.txt"

send_slack_alert() {
  local message="$1"
  curl -s -X POST "$SLACK_WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"[Search Monitor] $message\"}"
}

send_email_alert() {
  local subject="$1"
  local body="$2"
  echo "$body" | mail -s "[Search Monitor] $subject" "$ALERT_EMAIL"
}

# Check for new CVEs affecting monitored products
check_new_cves() {
  local product="$1"
  local since=$(date -d "1 day ago" +%Y-%m-%dT00:00:00)
  local results=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$product&pubStartDate=$since" \
    | jq '.totalResults')
  
  if [ "$results" -gt 0 ]; then
    local msg="$results new CVE(s) found for $product in last 24h"
    echo "$msg" >> "$ALERT_FILE"
    send_slack_alert "$msg"
  fi
}

# Monitor for leaked credentials
check_breach_exposure() {
  local domain="$1"
  # Check Have I Been Pwned API (requires API key)
  local breaches=$(curl -s -H "hibp-api-key: $HIBP_KEY" \
    "https://haveibeenpwned.com/api/v3/breaches?domain=$domain" | jq 'length')
  [ "$breaches" -gt 0 ] && send_slack_alert "Domain $domain appears in $breaches breach(es)"
}
```

### Pipeline Orchestration

```yaml
# search-pipeline.yml — Declarative search pipeline configuration
pipeline:
  name: "target-recon"
  schedule: "0 */6 * * *"  # Every 6 hours
  targets:
    - domain: "target.com"
      searches:
        - engine: shodan
          query: "hostname:target.com"
          fields: [ip_str, port, product, version]
        - engine: censys
          query: "services.tls.certificates.leaf.subject.common_name:target.com"
        - engine: nvd
          query: "target product"
          severity_filter: [critical, high]
  
  correlation:
    min_sources: 2
    max_age_hours: 168
    
  alerts:
    channels: [slack, email]
    conditions:
      - type: new_port
        severity: high
      - type: new_cve
        severity: critical
      - type: service_change
        severity: medium
```

### Incremental Search with State Management

```bash
#!/bin/bash
# incremental-search.sh — Only search for new/changed data since last run
STATE_FILE="$HOME/.search_state/last_run.json"
mkdir -p "$(dirname "$STATE_FILE")"

get_last_run() {
  [ -f "$STATE_FILE" ] && jq -r ".${1}_last_run // empty" "$STATE_FILE"
}

update_last_run() {
  local source="$1"
  local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ -f "$STATE_FILE" ]; then
    jq ".${source}_last_run = \"$timestamp\"" "$STATE_FILE" > "${STATE_FILE}.tmp" \
      && mv "${STATE_FILE}.tmp" "$STATE_FILE"
  else
    echo "{\"${source}_last_run\": \"$timestamp\"}" > "$STATE_FILE"
  fi
}

# NVD incremental search (only new CVEs since last check)
nvd_last=$(get_last_run "nvd")
if [ -n "$nvd_last" ]; then
  curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$TARGET&lastModStartDate=$nvd_last" \
    | jq '.vulnerabilities[].cve | {id, description: .descriptions[0].value}' > evidence/new_cves.json
fi
update_last_run "nvd"

# GitHub incremental search (repos created/updated since last check)
gh_last=$(get_last_run "github")
[ -n "$gh_last" ] && gh search repos "$TARGET exploit" --sort updated --limit 20 \
  --json fullName,updatedAt | jq "[.[] | select(.updatedAt > \"$gh_last\")]" > evidence/new_repos.json
update_last_run "github"
```

---

## Search Result Validation

### Source Verification

```bash
#!/bin/bash
# verify-source.sh — Validate search result authenticity and reliability
verify_github_repo() {
  local repo="$1"
  echo "=== Verifying: $repo ==="
  
  # Check repo age and activity
  gh repo view "$repo" --json createdAt,pushedAt,stargazerCount,forkCount,isArchived \
    | jq '{
      created: .createdAt,
      last_push: .pushedAt,
      stars: .stargazerCount,
      forks: .forkCount,
      archived: .isArchived,
      age_days: ((now - (.createdAt | fromdateiso8601)) / 86400 | floor)
    }'
  
  # Check for known malicious indicators
  gh repo view "$repo" --json description | jq -r '.description' | \
    grep -iE "free|hack|crack|keygen" && echo "[WARN] Suspicious description"
  
  # Verify author reputation
  local owner=$(echo "$repo" | cut -d'/' -f1)
  gh api "users/$owner" | jq '{login, public_repos, followers, created_at}'
}

verify_exploit_safety() {
  local file="$1"
  echo "=== Safety check: $file ==="
  
  # Check for obvious backdoors
  grep -nE "curl.*\|.*sh|wget.*\|.*bash|nc.*-e|/dev/tcp" "$file" \
    && echo "[CRITICAL] Potential backdoor detected!"
  
  # Check for data exfiltration
  grep -nE "curl.*POST.*\$|wget.*--post" "$file" \
    && echo "[WARN] Outbound data transfer detected"
  
  # Check for encoded payloads
  grep -nE "base64.*decode|eval\(|exec\(" "$file" \
    && echo "[WARN] Encoded/dynamic execution detected"
}
```

### Freshness Checking

```python
#!/usr/bin/env python3
"""Validate search result freshness and flag stale data."""
from datetime import datetime, timedelta
from dataclasses import dataclass

FRESHNESS_THRESHOLDS = {
    "critical": timedelta(days=7),    # Must be < 7 days old
    "high": timedelta(days=30),       # Must be < 30 days old
    "medium": timedelta(days=90),     # Must be < 90 days old
    "low": timedelta(days=365),       # Must be < 1 year old
}

@dataclass
class FreshnessResult:
    is_fresh: bool
    age_days: int
    confidence_modifier: float
    warning: str

def check_freshness(timestamp: datetime, severity: str = "medium") -> FreshnessResult:
    """Check if a search result is fresh enough for the given severity."""
    age = datetime.now() - timestamp
    threshold = FRESHNESS_THRESHOLDS.get(severity, timedelta(days=90))
    is_fresh = age <= threshold
    
    # Calculate confidence modifier (1.0 = fresh, 0.0 = very stale)
    modifier = max(0.0, 1.0 - (age.days / threshold.days))
    
    warning = ""
    if not is_fresh:
        warning = f"Result is {age.days} days old (threshold: {threshold.days} days for {severity})"
    elif age.days > threshold.days * 0.7:
        warning = f"Result approaching staleness ({age.days}/{threshold.days} days)"
    
    return FreshnessResult(
        is_fresh=is_fresh,
        age_days=age.days,
        confidence_modifier=round(modifier, 2),
        warning=warning
    )
```

### Bias Detection and Cross-Validation

```bash
#!/bin/bash
# cross-validate.sh — Validate findings by checking multiple independent sources
cross_validate_cve() {
  local cve_id="$1"
  local confirmed=0
  local sources_checked=0
  
  echo "=== Cross-validating: $cve_id ==="
  
  # Source 1: NVD
  nvd_result=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id" \
    | jq '.totalResults')
  ((sources_checked++))
  [ "$nvd_result" -gt 0 ] && ((confirmed++)) && echo "[+] Confirmed in NVD"
  
  # Source 2: ExploitDB
  edb_result=$(searchsploit "$cve_id" 2>/dev/null | grep -c "$cve_id")
  ((sources_checked++))
  [ "$edb_result" -gt 0 ] && ((confirmed++)) && echo "[+] Exploit exists in ExploitDB"
  
  # Source 3: GitHub PoC
  gh_result=$(gh search repos "$cve_id" --json fullName 2>/dev/null | jq 'length')
  ((sources_checked++))
  [ "$gh_result" -gt 0 ] && ((confirmed++)) && echo "[+] PoC found on GitHub ($gh_result repos)"
  
  # Source 4: Nuclei template
  nuclei_result=$(nuclei -tl -tags "$cve_id" 2>/dev/null | wc -l)
  ((sources_checked++))
  [ "$nuclei_result" -gt 0 ] && ((confirmed++)) && echo "[+] Nuclei template available"
  
  echo "Confidence: $confirmed/$sources_checked sources confirm"
  [ "$confirmed" -ge 2 ] && echo "VERDICT: HIGH confidence" || echo "VERDICT: LOW confidence — needs manual verification"
}
```

### False Positive Filtering

```python
#!/usr/bin/env python3
"""Filter false positives from search results using heuristics."""
import re
from typing import Optional

FALSE_POSITIVE_PATTERNS = [
    r"honeypot",
    r"canary",
    r"decoy",
    r"test\.example\.com",
    r"localhost|127\.0\.0\.1",
    r"documentation|tutorial|example",
]

KNOWN_HONEYPOT_SIGNATURES = {
    "cowrie": ["SSH-2.0-OpenSSH_6.0p1"],
    "dionaea": ["Microsoft-IIS/7.5"],
    "conpot": ["Siemens, SIMATIC"],
}

def is_likely_false_positive(result: dict) -> tuple[bool, Optional[str]]:
    """Check if a search result is likely a false positive or honeypot."""
    text = f"{result.get('title', '')} {result.get('description', '')} {result.get('banner', '')}"
    
    # Check against known patterns
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, f"Matches false positive pattern: {pattern}"
    
    # Check for honeypot signatures
    banner = result.get("banner", "")
    for hp_name, signatures in KNOWN_HONEYPOT_SIGNATURES.items():
        for sig in signatures:
            if sig in banner:
                return True, f"Possible honeypot ({hp_name}): banner matches '{sig}'"
    
    # Check for impossibly many open ports (likely honeypot)
    open_ports = result.get("open_ports", [])
    if len(open_ports) > 100:
        return True, f"Suspicious: {len(open_ports)} open ports (likely honeypot)"
    
    return False, None

def filter_results(results: list[dict]) -> list[dict]:
    """Remove likely false positives and return clean results."""
    clean = []
    for r in results:
        is_fp, reason = is_likely_false_positive(r)
        if is_fp:
            print(f"[FILTERED] {r.get('ip', 'unknown')}: {reason}")
        else:
            clean.append(r)
    return clean
```

### Version Accuracy Verification

```bash
# Verify reported service versions match actual deployment
verify_service_version() {
  local target="$1"
  local port="$2"
  local expected_service="$3"
  local expected_version="$4"
  
  echo "[*] Verifying $expected_service $expected_version on $target:$port"
  
  # Direct banner grab
  actual_banner=$(echo "" | nc -w 3 "$target" "$port" 2>/dev/null | head -1)
  
  # Nmap service detection
  nmap_result=$(nmap -sV -p "$port" "$target" -oG - 2>/dev/null | grep "open")
  
  # Compare with search result claim
  if echo "$nmap_result" | grep -qi "$expected_version"; then
    echo "[CONFIRMED] Version matches: $expected_version"
    return 0
  else
    echo "[MISMATCH] Expected: $expected_version"
    echo "           Actual: $nmap_result"
    echo "           Banner: $actual_banner"
    return 1
  fi
}

# Batch verification of search results
while IFS=',' read -r ip port service version; do
  verify_service_version "$ip" "$port" "$service" "$version"
done < evidence/search_results.csv | tee evidence/verification_report.txt
```
