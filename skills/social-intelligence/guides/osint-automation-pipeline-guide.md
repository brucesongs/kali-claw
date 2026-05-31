# OSINT Automation Pipeline Guide

> Building automated OSINT collection and enrichment pipelines using SpiderFoot, Maltego, and custom scripts. Covers data correlation, API integration, automated reconnaissance workflows, and structured output for penetration testing engagements.

---

## 1. SpiderFoot Automated Reconnaissance

SpiderFoot provides modular OSINT collection with 200+ data source integrations. Run headless scans for automated pipeline integration.

```bash
# Start SpiderFoot in headless mode with CLI
# Full scan against a target domain
spiderfoot -s target.com -t DOMAIN_NAME -o json > /tmp/sf_results.json

# Scan specific modules only (faster, focused)
spiderfoot -s target.com -t DOMAIN_NAME \
  -m sfp_dnsresolve,sfp_sublist3r,sfp_certspotter,sfp_crt,sfp_hackertarget \
  -o json > /tmp/sf_subdomains.json

# Scan a person (email pivot)
spiderfoot -s "john.doe@target.com" -t EMAILADDR \
  -m sfp_haveibeenpwned,sfp_hunter,sfp_emailformat,sfp_gravatar \
  -o json > /tmp/sf_email_results.json

# Parse SpiderFoot JSON output for actionable data
cat /tmp/sf_results.json | jq '[.[] | select(.type == "INTERNET_NAME") | .data]' | sort -u > subdomains.txt
cat /tmp/sf_results.json | jq '[.[] | select(.type == "IP_ADDRESS") | .data]' | sort -u > ips.txt
cat /tmp/sf_results.json | jq '[.[] | select(.type == "EMAILADDR") | .data]' | sort -u > emails.txt

# SpiderFoot with API server for pipeline integration
spiderfoot -l 127.0.0.1:5001 &
# Query via REST API
curl -s "http://127.0.0.1:5001/api/scan/start?target=target.com&modules=sfp_dnsresolve,sfp_crt"
```

---

## 2. Maltego Transform Automation

Maltego transforms can be scripted for batch processing using the Maltego Transform Library (TRX) or command-line execution.

```python
# Custom Maltego local transform — domain to subdomains
# Save as: transforms/domain_to_subdomains.py

import sys
import requests

def run_transform(domain):
    """Query crt.sh for certificate transparency subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        resp = requests.get(url, timeout=30)
        entries = resp.json()
    except Exception as e:
        print(f"<error>{e}</error>", file=sys.stderr)
        return []
    
    subdomains = set()
    for entry in entries:
        name = entry.get("name_value", "")
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            if sub.endswith(f".{domain}") and "*" not in sub:
                subdomains.add(sub)
    
    # Output in Maltego entity format
    for sub in sorted(subdomains):
        print(f"<Entity Type=\"maltego.DNSName\"><Value>{sub}</Value></Entity>")
    
    return subdomains

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "target.com"
    results = run_transform(target)
    print(f"[*] Found {len(results)} subdomains", file=sys.stderr)
```

---

## 3. Automated Enrichment Pipeline

Chain multiple OSINT tools into a single pipeline that takes a domain and produces enriched intelligence.

```bash
#!/bin/bash
# osint_pipeline.sh — Automated OSINT enrichment pipeline
# Usage: ./osint_pipeline.sh target.com

TARGET="$1"
OUTDIR="/tmp/osint_${TARGET}_$(date +%Y%m%d)"
mkdir -p "$OUTDIR"

echo "[*] Starting OSINT pipeline for: $TARGET"

# Phase 1: Subdomain enumeration (parallel sources)
echo "[*] Phase 1: Subdomain discovery"
subfinder -d "$TARGET" -silent -o "$OUTDIR/subfinder.txt" &
amass enum -passive -d "$TARGET" -o "$OUTDIR/amass.txt" 2>/dev/null &
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | jq -r '.[].name_value' | sort -u > "$OUTDIR/crt.txt" &
wait

# Merge and deduplicate
cat "$OUTDIR"/{subfinder,amass,crt}.txt 2>/dev/null | sort -u > "$OUTDIR/all_subdomains.txt"
echo "[+] Found $(wc -l < "$OUTDIR/all_subdomains.txt") unique subdomains"

# Phase 2: DNS resolution and live host detection
echo "[*] Phase 2: Resolving and probing"
dnsx -l "$OUTDIR/all_subdomains.txt" -a -resp -silent -o "$OUTDIR/resolved.txt"
httpx -l "$OUTDIR/all_subdomains.txt" -silent -status-code -title -tech-detect -o "$OUTDIR/live_http.txt"

# Phase 3: Technology fingerprinting
echo "[*] Phase 3: Technology detection"
cat "$OUTDIR/live_http.txt" | awk '{print $1}' | nuclei -t technologies/ -silent -o "$OUTDIR/tech_stack.txt"

# Phase 4: Email and personnel discovery
echo "[*] Phase 4: Email harvesting"
theHarvester -d "$TARGET" -b all -f "$OUTDIR/harvester" 2>/dev/null

echo "[+] Pipeline complete. Results in: $OUTDIR"
ls -la "$OUTDIR"
```

---

## 4. API-Driven Intelligence Gathering

Integrate commercial and free OSINT APIs for deeper enrichment.

```python
import requests
import json
import os
from concurrent.futures import ThreadPoolExecutor

class OSINTEnricher:
    """Multi-source OSINT enrichment using APIs."""
    
    def __init__(self):
        self.shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self.vt_key = os.environ.get("VT_API_KEY", "")
        self.censys_id = os.environ.get("CENSYS_API_ID", "")
        self.censys_secret = os.environ.get("CENSYS_API_SECRET", "")
    
    def enrich_ip(self, ip):
        """Gather intelligence on an IP from multiple sources."""
        results = {"ip": ip, "sources": {}}
        
        # Shodan
        if self.shodan_key:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                results["sources"]["shodan"] = {
                    "ports": data.get("ports", []),
                    "os": data.get("os"),
                    "org": data.get("org"),
                    "vulns": data.get("vulns", [])
                }
        
        # VirusTotal
        if self.vt_key:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                results["sources"]["virustotal"] = {
                    "reputation": data.get("reputation"),
                    "country": data.get("country"),
                    "as_owner": data.get("as_owner")
                }
        
        return results
    
    def enrich_bulk(self, ip_list):
        """Enrich multiple IPs in parallel."""
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(self.enrich_ip, ip_list))
        return results

# Usage
enricher = OSINTEnricher()
ips = ["93.184.216.34", "104.26.10.78", "172.67.74.152"]
intel = enricher.enrich_bulk(ips)

with open("/tmp/enriched_intel.json", "w") as f:
    json.dump(intel, f, indent=2)
```

---

## 5. Recon-ng Workspace Automation

Recon-ng provides a modular framework with database-backed results for structured OSINT collection.

```bash
# Create workspace and run automated recon
recon-ng -w target_recon << 'EOF'
marketplace install all
modules load recon/domains-hosts/hackertarget
options set SOURCE target.com
run
modules load recon/domains-hosts/certificate_transparency
options set SOURCE target.com
run
modules load recon/hosts-hosts/resolve
run
modules load recon/hosts-ports/shodan_ip
run
show hosts
EOF

# Export results from recon-ng database
recon-ng -w target_recon -C "show hosts" > /tmp/recon_hosts.txt

# Recon-ng API keys setup (one-time)
recon-ng << 'EOF'
keys add shodan_api SHODAN_KEY_HERE
keys add virustotal_api VT_KEY_HERE
keys add github_api GITHUB_TOKEN_HERE
keys list
EOF

# Automated module chain via script
cat > /tmp/recon_script.rc << 'EOF'
workspaces create auto_recon
modules load recon/domains-contacts/whois_pocs
options set SOURCE target.com
run
modules load recon/contacts-profiles/fullcontact
run
modules load recon/profiles-profiles/profiler
run
EOF
recon-ng --no-analytics -r /tmp/recon_script.rc
```

---

## 6. Data Correlation and Reporting

Correlate findings from multiple sources into actionable intelligence reports.

```python
import json
from collections import defaultdict
from pathlib import Path

def correlate_osint_data(results_dir):
    """Correlate OSINT findings from multiple tools into unified view."""
    
    correlated = defaultdict(lambda: {
        "subdomains": set(),
        "ips": set(),
        "emails": set(),
        "technologies": set(),
        "ports": set(),
        "findings": []
    })
    
    results_path = Path(results_dir)
    
    # Parse subdomain results
    subdomain_file = results_path / "all_subdomains.txt"
    if subdomain_file.exists():
        for line in subdomain_file.read_text().splitlines():
            domain = line.strip()
            base = ".".join(domain.split(".")[-2:])
            correlated[base]["subdomains"].add(domain)
    
    # Parse HTTP probe results
    http_file = results_path / "live_http.txt"
    if http_file.exists():
        for line in http_file.read_text().splitlines():
            parts = line.split()
            if parts:
                url = parts[0]
                host = url.split("//")[-1].split("/")[0].split(":")[0]
                base = ".".join(host.split(".")[-2:])
                if len(parts) > 2:
                    correlated[base]["technologies"].add(" ".join(parts[2:]))
    
    # Parse enriched intelligence
    enriched_file = results_path / "enriched_intel.json"
    if enriched_file.exists():
        intel = json.loads(enriched_file.read_text())
        for entry in intel:
            ip = entry["ip"]
            for source, data in entry.get("sources", {}).items():
                if "ports" in data:
                    for port in data["ports"]:
                        correlated[ip]["ports"].add(port)
    
    # Generate summary report
    report = {"targets": {}}
    for target, data in correlated.items():
        report["targets"][target] = {
            "subdomain_count": len(data["subdomains"]),
            "unique_ips": len(data["ips"]),
            "emails_found": len(data["emails"]),
            "technologies": list(data["technologies"]),
            "open_ports": sorted(data["ports"]) if data["ports"] else []
        }
    
    return report

# Generate report
report = correlate_osint_data("/tmp/osint_target.com_20260530")
print(json.dumps(report, indent=2))
```

---

## 7. Scheduled Pipeline Execution

Run OSINT pipelines on a schedule for continuous monitoring of target changes.

```yaml
# osint_monitor.yml — Cron-based OSINT monitoring config
targets:
  - domain: target.com
    frequency: daily
    modules:
      - subdomain_enum
      - certificate_monitor
      - dns_changes
  - domain: target.org
    frequency: weekly
    modules:
      - full_recon
      - email_harvest
```

```bash
# Cron job for continuous OSINT monitoring
# Add to crontab: crontab -e

# Daily subdomain monitoring at 2 AM
0 2 * * * /opt/osint/osint_pipeline.sh target.com >> /var/log/osint/daily.log 2>&1

# Compare results with previous run to detect changes
diff_osint() {
    local target="$1"
    local today="/tmp/osint_${target}_$(date +%Y%m%d)/all_subdomains.txt"
    local yesterday="/tmp/osint_${target}_$(date -d yesterday +%Y%m%d)/all_subdomains.txt"
    
    if [ -f "$yesterday" ] && [ -f "$today" ]; then
        NEW=$(comm -13 "$yesterday" "$today")
        REMOVED=$(comm -23 "$yesterday" "$today")
        
        if [ -n "$NEW" ]; then
            echo "[+] New subdomains detected:"
            echo "$NEW"
            # Alert via webhook
            curl -s -X POST "$SLACK_WEBHOOK" \
              -H "Content-Type: application/json" \
              -d "{\"text\": \"New subdomains for ${target}: $(echo $NEW | tr '\n' ', ')\"}"
        fi
    fi
}

diff_osint "target.com"
```

---

## Key Takeaways

- Automate repetitive OSINT tasks — manual collection does not scale across large target surfaces
- SpiderFoot headless mode and REST API enable integration into CI/CD-style pipelines
- Run subdomain enumeration from multiple sources in parallel for maximum coverage
- API enrichment (Shodan, VirusTotal, Censys) adds depth that passive tools cannot provide
- Correlate data across tools to identify patterns invisible in individual tool outputs
- Schedule recurring scans to detect infrastructure changes between engagement phases
- Store results in structured formats (JSON) for programmatic analysis and reporting
