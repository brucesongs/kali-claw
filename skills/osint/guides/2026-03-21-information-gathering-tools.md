# 2026-03-21 Information Gathering Command Line Tools Learning

## Mastered Tools

### 1. theHarvester (v4.10.1)
- **Functionality**: OSINT information gathering, supports 50+ data sources
- **Core Commands**: `-d domain -b source -r -c -n -f file`
- **Practical Points**:
  - Primarily passive collection, requires API keys for full functionality
  - Supports DNS resolution, brute force, Shodan integration
  - Rich output formats (XML/JSON)

#### Advanced theHarvester Techniques

**Multi-Source Correlation Workflow:**

```bash
# Run theHarvester against multiple sources and merge results
for source in baidu bing google duckduckgo linkedin twitter; do
  theHarvester -d target.com -b $source -f json_results/${source}.json
done

# Merge and deduplicate all results
jq -s '[.[].hosts[]] | unique' json_results/*.json > unique_hosts.json
jq -s '[.[].emails[]] | unique' json_results/*.json > unique_emails.json
```

**API Integration for Enrichment:**

```python
import json

def enrich_harvester_results(harvest_file, shodan_api_key):
    """Enrich theHarvester output with Shodan service data."""
    with open(harvest_file) as f:
        data = json.load(f)

    enriched_hosts = []
    for host in data.get("hosts", []):
        ip = resolve_to_ip(host)
        if ip:
            shodan_data = query_shodan(ip, shodan_api_key)
            enriched_hosts.append({
                "host": host,
                "ip": ip,
                "ports": shodan_data.get("ports", []),
                "os": shodan_data.get("os", "unknown"),
                "vulns": shodan_data.get("vulns", []),
            })
    return enriched_hosts
```

**Rate-Limited Source Enumeration:**

When running against many sources, stagger requests to avoid temporary blocks. Use `--delay` flags or wrap calls with `sleep` intervals of 2-5 seconds between sources. For large engagements, split domain lists and run in parallel across different API keys to distribute load.

### 2. Sublist3r
- **Functionality**: Subdomain enumeration tool
- **Core Commands**: `-d domain -b -e engines -p ports -o output`
- **Practical Points**:
  - Combines multiple search engines for better coverage
  - Built-in brute force module (subbrute)
  - Can directly scan discovered subdomain ports

#### Advanced Sublist3r Techniques

**Engine-Specific Tuning:**

Not all search engines return the same results. For maximum coverage, run Sublist3r multiple times with different engine combinations:

```bash
# Phase 1: Broad sweep with all engines
sublist3r -d target.com -b -o broad_sweep.txt

# Phase 2: Targeted enumeration with specific engines
sublist3r -d target.com -e google,bing,yahoo -o search_engines.txt
sublist3r -d target.com -e baidu,ask -o alt_engines.txt

# Phase 3: Brute force with custom wordlist
sublist3r -d target.com -b -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o bruteforce.txt

# Merge and deduplicate
sort -u broad_sweep.txt search_engines.txt alt_engines.txt bruteforce.txt > final_subdomains.txt
```

**Port Scanning Integration:**

Sublist3r can scan discovered subdomains directly with the `-p` flag. For efficiency, focus on high-value ports first:

```bash
# Quick service discovery on common web ports
sublist3r -d target.com -p 80,443,8080,8443,3000,9090 -o subdomains_with_ports.txt
```

### 3. DNSRecon
- **Functionality**: Comprehensive DNS enumeration and reconnaissance tool
- **Core Commands**: `-d domain -t type -D wordlist -j json_output`
- **Practical Points**:
  - Supports 9 enumeration types (std, axfr, brt, rvl, crt, etc.)
  - Zone transfer testing, reverse DNS, brute force
  - Multi-format output (JSON/XML/CSV/SQLite)

#### Advanced DNSRecon Techniques

**Zone Transfer Exploitation:**

Misconfigured DNS servers sometimes allow zone transfers to any requester. This reveals the entire DNS zone:

```bash
# Test all nameservers for zone transfer
dnsrecon -d target.com -t axfr

# Target specific nameserver
dnsrecon -d target.com -t axfr -n ns1.target.com
```

If zone transfer succeeds, you obtain the complete DNS map including internal records that may reveal:
- Internal server hostnames (mail, intranet, vpn, dev, staging)
- Service records (SRV) for SIP, LDAP, Kerberos
- TXT records with SPF, DMARC, and verification tokens

**Reverse DNS Sweeps:**

When you know an IP range belongs to the target, reverse DNS can reveal hostnames not findable through forward enumeration:

```bash
# Reverse lookup on a CIDR range
dnsrecon -r 10.0.0.0/24 -j reverse_results.json

# For larger ranges, split into /24 blocks
for i in $(seq 0 10); do
  dnsrecon -r 10.0.${i}.0/24 -j rev_${i}.json
done
```

**Cache Snooping:**

DNS cache snooping checks whether a DNS server has cached records for specific domains, revealing what domains users on that network have recently visited:

```bash
dnsrecon -t snoop -n target_dns_server -D /usr/share/wordlists/dns_cache_snoop.txt
```

### 4. Masscan
- **Functionality**: Ultra-fast port scanner (10M pps)
- **Core Commands**: `targets -p ports --rate speed --banners -oJ json`
- **Practical Points****
  - Requires root privileges to run
  - Extremely high scanning speed, suitable for large-scale scans
  - Supports service banner grabbing

#### Advanced Masscan Techniques

**Banner Grabbing at Scale:**

```bash
# Fast scan with banner grabbing on top 100 ports
masscan -p1-65535 --rate=10000 --banners --open-only -oJ full_scan.json 10.0.0.0/16

# Targeted scan for specific services
masscan -p80,443,8080 --rate=5000 --banners --http-user-agent "Mozilla/5.0" -oJ web_services.json targets.txt
```

**Optimizing Scan Rates:**

- Local networks: `--rate=10000` or higher
- Internet-facing targets with authorization: `--rate=1000` to stay under detection thresholds
- Always verify with `--open-only` to reduce output noise
- Use `--excludefile` to exclude ranges that should not be scanned
- Combine with `--shard` to distribute scans across multiple machines

**Output Parsing:**

```python
import json

def parse_masscan_results(json_file):
    """Parse Masscan JSON output into structured host:port mapping."""
    with open(json_file) as f:
        raw = json.load(f)

    hosts = {}
    for entry in raw:
        ip = entry.get("ip", "unknown")
        for port_info in entry.get("ports", []):
            port = port_info["port"]
            proto = port_info["proto"]
            banner = port_info.get("service", {}).get("banner", "")
            hosts.setdefault(ip, []).append({
                "port": port,
                "proto": proto,
                "banner": banner[:200],
            })
    return hosts
```

### 5. Amass
- **Functionality**: Attack surface mapping and asset discovery
- **Core Commands**: `enum -d domain -passive/-active -config file -o output`
- **Practical Points**:
  - Combines passive and active modes
  - Requires API key configuration for best results
  - Enterprise-grade attack surface management tool

#### Advanced Amass Techniques

**Configuration for Maximum Coverage:**

Create an optimized `amass.ini` configuration file:

```ini
# amass.ini - Optimized configuration
[datasources]
# Configure API keys for maximum data source coverage
[shodan]
apikey = YOUR_SHODAN_KEY

[censys]
apikey = YOUR_CENSYS_KEY
secret = YOUR_CENSYS_SECRET

[securitytrails]
apikey = YOUR_ST_KEY

[virustotal]
apikey = YOUR_VT_KEY

# DNS resolution settings
[network]
resolvers = /etc/resolvers.txt
max_dns_queries = 200
```

**Passive vs Active Mode Selection:**

```bash
# Passive mode - zero direct interaction with target
amass enum -passive -d target.com -config amass.ini -o passive_results.txt

# Active mode - includes DNS resolution, certificate checks, port scanning
amass enum -active -d target.com -config amass.ini -o active_results.txt

# Intel mode - discover related domains and ASNs
amass intel -org "Target Corporation" -whois
amass intel -active -asn AS12345 -ip
amass intel -d target.com -whois -ip
```

**Database-Backed Tracking:**

Amass can store results in a graph database for longitudinal tracking:

```bash
# Initialize graph database storage
amass db -d target.com -show

# Track changes over time
amass track -d target.com -last 7d

# Compare snapshots
amass db -diff snapshot_before.json snapshot_after.json
```

## Tool Combination Strategy

### Information Gathering Workflow
1. **Initial Reconnaissance**: theHarvester + Sublist3r (passive discovery)
2. **Deep DNS**: DNSRecon (active verification and expansion)
3. **IP Discovery**: Extract IPs from domain results
4. **Port Scanning**: Masscan (fast port discovery)
5. **Attack Surface Mapping**: Amass (comprehensive analysis)

### Automation Workflows Combining Multiple Tools

**End-to-End Automated Pipeline:**

```bash
#!/bin/bash
# Automated recon pipeline - requires proper authorization
DOMAIN="$1"
RESULTS_DIR="recon_${DOMAIN}_$(date +%Y%m%d)"
mkdir -p "$RESULTS_DIR"

echo "[*] Phase 1: Passive subdomain enumeration"
sublist3r -d "$DOMAIN" -b -o "$RESULTS_DIR/sublist3r.txt" &
theHarvester -d "$DOMAIN" -b all -f "$RESULTS_DIR/harvester.json" &
amass enum -passive -d "$DOMAIN" -o "$RESULTS_DIR/amass_passive.txt" &
wait

echo "[*] Phase 2: Merge and deduplicate subdomains"
cat "$RESULTS_DIR"/*.txt | sort -u > "$RESULTS_DIR/all_subdomains.txt"

echo "[*] Phase 3: DNS resolution and expansion"
dnsrecon -d "$DOMAIN" -t std,crt,brt -D /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -j "$RESULTS_DIR/dnsrecon.json"

echo "[*] Phase 4: Live host detection"
cat "$RESULTS_DIR/all_subdomains.txt" | httpx -silent -status-code -title -tech-detect -o "$RESULTS_DIR/live_hosts.txt"

echo "[*] Phase 5: Port scanning on resolved IPs"
grep -oP '\d+\.\d+\.\d+\.\d+' "$RESULTS_DIR/live_hosts.txt" | sort -u > "$RESULTS_DIR/resolved_ips.txt"
masscan -iL "$RESULTS_DIR/resolved_ips.txt" -p1-65535 --rate=10000 --open-only -oJ "$RESULTS_DIR/masscan.json"

echo "[*] Phase 6: Comprehensive correlation"
amass enum -active -d "$DOMAIN" -config amass.ini -o "$RESULTS_DIR/amass_active.txt"
```

**Cross-Validation Pipeline:**

Validate findings across multiple tools to reduce false positives:

```python
def cross_validate_results(tool_outputs):
    """Validate subdomain findings across multiple tool outputs."""
    from collections import Counter

    all_findings = []
    for tool_name, file_path in tool_outputs.items():
        with open(file_path) as f:
            domains = set(line.strip() for line in f if line.strip())
            all_findings.append((tool_name, domains))

    # Count how many tools confirmed each subdomain
    domain_counts = Counter()
    for tool_name, domains in all_findings:
        for domain in domains:
            domain_counts[domain] += 1

    total_tools = len(tool_outputs)
    confirmed = {d: c for d, c in domain_counts.items() if c >= 2}
    single_source = {d: c for d, c in domain_counts.items() if c == 1}

    return {
        "high_confidence": confirmed,
        "requires_verification": single_source,
        "total_unique": len(domain_counts),
        "confirmation_rate": len(confirmed) / len(domain_counts) * 100,
    }
```

### Data Integration
- All tools support JSON output for automated processing
- Build unified data storage and analysis pipeline
- Cross-validate results from different tools to improve accuracy

### Output Parsing and Analysis

**Unified Result Format:**

```python
def normalize_tool_output(tool_name, raw_output):
    """Normalize output from different tools into a common schema."""
    normalized = {
        "tool": tool_name,
        "timestamp": datetime.utcnow().isoformat(),
        "findings": {
            "domains": set(),
            "ips": set(),
            "emails": set(),
            "urls": set(),
            "technologies": set(),
        },
    }

    if tool_name == "theharvester":
        data = json.loads(raw_output)
        normalized["findings"]["domains"].update(data.get("hosts", []))
        normalized["findings"]["emails"].update(data.get("emails", []))

    elif tool_name == "amass":
        for line in raw_output.strip().split("\n"):
            normalized["findings"]["domains"].add(line.strip())

    elif tool_name == "masscan":
        data = json.loads(raw_output)
        for entry in data:
            ip = entry.get("ip")
            normalized["findings"]["ips"].add(ip)
            for port in entry.get("ports", []):
                normalized["findings"]["urls"].add(f"{ip}:{port['port']}")

    return normalized
```

## Practical Considerations

### Legal Compliance
- Always obtain authorization before scanning
- Comply with target system terms of use
- Control scanning rates to avoid impact

### Technical Optimization
- Use latest SecLists wordlist files
- Configure API keys to improve data source coverage
- Adjust scanning parameters based on network environment
- Verify and deduplicate discovered results

### Counter-OSINT Considerations

When conducting information gathering, be aware that targets may employ counter-OSINT measures:

**Detection and Blocking Mechanisms:**
- WAF rules that block known scanner user agents
- Rate limiting that slows or blocks enumeration attempts
- Honeypot subdomains that alert defenders when accessed
- DNS Canary tokens that trigger alerts on specific record lookups
- TLS certificate monitoring for unauthorized certificate requests

**Evading Detection While Staying Ethical:**
- Prefer passive collection methods first (certificate transparency, search engine cached data)
- Use throttled rates that mimic normal traffic patterns
- Rotate data sources to distribute query load
- Avoid accessing discovered resources beyond initial verification
- Document all actions for the authorized engagement report

**Identifying Counter-OSINT Deployments:**

```bash
# Check for canary DNS tokens - unusual subdomains with high entropy names
for sub in $(cat subdomains.txt); do
  entropy=$(echo -n "$sub" | calculate_entropy)
  if (( $(echo "$entropy > 3.5" | bc -l) )); then
    echo "[!] Potential canary token: $sub (entropy: $entropy)"
  fi
done

# Detect WAF presence that may indicate defensive maturity
wafw00f https://target.com
```

## File Locations
- Detailed command reference: `/home/parallels/.openclaw/workspace/security-tools-67/information-gathering-cli-reference.md`
- This learning record: current file
- Tool classification statistics: `/home/parallels/.openclaw/workspace/kali-517-analysis/`

## Follow-up Learning Plan
- Deep study of web application security tools (Burp Suite CLI, ZAP CLI, etc.)
- Master password attack tools (hashcat, john, etc.)
- Learn post-exploitation tools (crackmapexec, mimikatz, etc.)

## Hands-on Exercises

Practice the techniques described in this guide against authorized targets or lab environments. Document your findings and methodology for each exercise.
## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- PTES Technical Guidelines — http://www.pentest-standard.org/
