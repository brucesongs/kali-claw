# Attack Surface Discovery Guide

> Companion to `skills/security-bounty-hunter/SKILL.md`. This guide covers subdomain enumeration, JavaScript analysis, API endpoint discovery, and comprehensive asset inventory techniques for maximizing attack surface visibility.

---

## 1. Subdomain Enumeration

Subdomain discovery is the foundation of attack surface mapping. Use multiple data sources for comprehensive coverage:

```bash
# Passive enumeration — no direct target interaction
# Subfinder: aggregates 40+ passive sources
subfinder -d target.com -all -o subdomains_passive.txt

# Amass passive mode with multiple data sources
amass enum -passive -d target.com -o amass_passive.txt \
  -config ~/.config/amass/config.ini

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u | \
  grep -v "^\*" > crt_subdomains.txt

# Merge and deduplicate all passive results
cat subdomains_passive.txt amass_passive.txt crt_subdomains.txt | \
  sort -u > all_subdomains.txt

echo "Total unique subdomains: $(wc -l < all_subdomains.txt)"
```

Active enumeration for deeper discovery:

```bash
# DNS brute-force with targeted wordlists
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  target.com -r resolvers.txt -w brute_subdomains.txt

# Permutation-based discovery (finds dev-api, api-staging, etc.)
gotator -sub all_subdomains.txt \
  -perm /usr/share/seclists/Discovery/DNS/dns-prefixes.txt \
  -depth 1 | puredns resolve -r resolvers.txt > permuted_subdomains.txt

# Combine all results
cat all_subdomains.txt brute_subdomains.txt permuted_subdomains.txt | \
  sort -u > final_subdomains.txt
```

---

## 2. HTTP Probing and Technology Fingerprinting

Resolve discovered subdomains to live web services and identify their technology stacks:

```bash
# Probe for live HTTP services
httpx -l final_subdomains.txt \
  -ports 80,443,8080,8443,3000,5000,8000,9090 \
  -title -tech-detect -status-code -content-length \
  -follow-redirects -o live_hosts.json -json

# Extract interesting targets (non-standard tech, custom apps)
cat live_hosts.json | jq -r 'select(.tech != null) | 
  "\(.url) | \(.status_code) | \(.title) | \(.tech | join(", "))"' | \
  grep -v "WordPress\|Squarespace\|Wix" > custom_apps.txt

# Screenshot all live hosts for visual review
gowitness file -f <(cat live_hosts.json | jq -r '.url') \
  --screenshot-path ./screenshots/ \
  --threads 10
```

---

## 3. JavaScript Analysis for Hidden Endpoints

Modern SPAs embed API endpoints, secrets, and internal paths in JavaScript bundles:

```bash
# Extract all JavaScript file URLs from live hosts
cat live_hosts.json | jq -r '.url' | \
  hakrawler -d 3 -insecure | grep "\.js$" | sort -u > js_files.txt

# Alternative: use gau for historical JS file discovery
gau target.com --threads 5 --blacklist png,jpg,gif,css,svg | \
  grep "\.js$" | sort -u >> js_files.txt

# Download all JS files for analysis
mkdir -p js_downloads
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk "$url" -o "js_downloads/$filename" 2>/dev/null
done < js_files.txt
```

Extract secrets and endpoints from JavaScript:

```bash
# Use LinkFinder for endpoint extraction
linkfinder -i "https://target.com/static/app.js" -o cli | \
  grep -E "^/" | sort -u > js_endpoints.txt

# Extract potential secrets with trufflehog
trufflehog filesystem js_downloads/ --json | \
  jq '{detector: .DetectorName, raw: .Raw}' > js_secrets.txt

# Custom regex extraction for API keys and tokens
grep -rhoP '(?:api[_-]?key|token|secret|password|auth)["\s:=]+["\x27]([a-zA-Z0-9_\-]{20,})' \
  js_downloads/ | sort -u > potential_secrets.txt

# Find hardcoded internal URLs
grep -rhoP 'https?://[a-zA-Z0-9._\-]+\.internal[a-zA-Z0-9./_\-]*' \
  js_downloads/ | sort -u > internal_urls.txt
```

---

## 4. API Endpoint Discovery

Discover undocumented API endpoints through multiple techniques:

```bash
# Wordlist-based API path discovery
ffuf -u "https://api.target.com/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 \
  -o api_fuzz_results.json \
  -t 50

# Version enumeration (v1, v2, v3...)
for version in v1 v2 v3 v4 internal beta staging; do
  ffuf -u "https://api.target.com/$version/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200,201,204,301,302,401,403 \
    -o "api_${version}_results.json" \
    -t 30 -s
done

# Swagger/OpenAPI spec discovery
for path in /swagger.json /openapi.json /api-docs /swagger-ui.html \
  /v2/api-docs /v3/api-docs /.well-known/openapi.yaml /docs; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://api.target.com$path")
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[${status}] https://api.target.com$path"
  fi
done
```

---

## 5. Wayback Machine and Historical Analysis

Historical data reveals removed endpoints, old API versions, and forgotten assets:

```bash
# Fetch all historical URLs from Wayback Machine
waybackurls target.com | sort -u > wayback_urls.txt

# Filter for interesting patterns
grep -iE "(admin|api|internal|debug|test|staging|backup|config)" \
  wayback_urls.txt > interesting_historical.txt

# Find removed but potentially still-accessible endpoints
grep -iE "\.(json|xml|yaml|yml|conf|bak|sql|env|log)" \
  wayback_urls.txt > sensitive_files.txt

# Check if historical endpoints are still live
httpx -l sensitive_files.txt -mc 200 -silent > still_accessible.txt

# Find old API versions that may lack security controls
grep -oP '/api/v[0-9]+' wayback_urls.txt | sort -u
# Often v1 endpoints lack auth that v2+ enforces
```

---

## 6. Cloud Asset Discovery

Identify cloud resources associated with the target:

```bash
# S3 bucket enumeration
# Check common naming patterns
for prefix in target target-com target-prod target-dev target-staging \
  target-backup target-assets target-uploads; do
  aws s3 ls "s3://${prefix}" --no-sign-request 2>/dev/null && \
    echo "[OPEN] s3://${prefix}"
done

# Cloud IP range identification
# Resolve all subdomains and check against cloud provider ranges
dig +short -f final_subdomains.txt | sort -u > resolved_ips.txt

# Check which IPs belong to AWS/GCP/Azure
for ip in $(cat resolved_ips.txt); do
  whois "$ip" 2>/dev/null | grep -qi "amazon\|google\|microsoft" && \
    echo "[CLOUD] $ip"
done

# GitHub dorking for leaked infrastructure details
gh search code "target.com" --language yaml -- "amazonaws.com" | head -20
gh search code "target.com" -- "AKIA" | head -20  # AWS access keys
```

---

## 7. Comprehensive Asset Inventory Script

Combine all discovery techniques into a single automated pipeline:

```python
#!/usr/bin/env python3
"""Attack surface discovery pipeline — orchestrates all enumeration phases."""

import subprocess
import json
from pathlib import Path
from dataclasses import dataclass

@dataclass(frozen=True)
class Asset:
    url: str
    asset_type: str
    technology: str
    status_code: int
    notes: str

def run_command(cmd: str, timeout: int = 300) -> str:
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout.strip()

def discover_subdomains(domain: str, output_dir: Path) -> list[str]:
    """Run passive and active subdomain enumeration."""
    run_command(f"subfinder -d {domain} -all -o {output_dir}/subfinder.txt")
    run_command(
        f"amass enum -passive -d {domain} -o {output_dir}/amass.txt"
    )
    all_subs = set()
    for f in output_dir.glob("*.txt"):
        all_subs.update(f.read_text().splitlines())
    return sorted(all_subs)

def probe_live_hosts(subdomains: list[str], output_dir: Path) -> list[dict]:
    """Identify live HTTP services from subdomain list."""
    sub_file = output_dir / "all_subs.txt"
    sub_file.write_text("\n".join(subdomains))
    run_command(
        f"httpx -l {sub_file} -json -o {output_dir}/httpx.json "
        f"-ports 80,443,8080,8443 -tech-detect -title -status-code"
    )
    results = []
    for line in (output_dir / "httpx.json").read_text().splitlines():
        if line.strip():
            results.append(json.loads(line))
    return results

def generate_inventory(hosts: list[dict]) -> list[Asset]:
    """Convert probe results to structured asset inventory."""
    return [
        Asset(
            url=h.get("url", ""),
            asset_type="web" if h.get("status_code", 0) < 400 else "restricted",
            technology=", ".join(h.get("tech", [])),
            status_code=h.get("status_code", 0),
            notes=h.get("title", "")
        )
        for h in hosts
    ]
```

---

## 8. Prioritizing Attack Surface

Not all discovered assets are equal. Prioritize based on likelihood of vulnerabilities:

```yaml
# Asset prioritization matrix
high_priority:
  - description: "Admin panels and internal tools exposed externally"
    indicators: ["admin.", "internal.", "portal.", "manage."]
    reason: "Often have weaker auth, more sensitive functionality"

  - description: "API endpoints without authentication"
    indicators: ["401→200 on removing auth header", "no CORS restrictions"]
    reason: "Direct data access without barriers"

  - description: "Legacy or deprecated services"
    indicators: ["old API versions (v1)", "outdated tech stack", "wayback-only"]
    reason: "Likely unpatched, forgotten by security team"

  - description: "Development and staging environments"
    indicators: ["dev.", "staging.", "test.", "uat.", "sandbox."]
    reason: "Weaker security controls, debug features enabled"

medium_priority:
  - description: "Third-party integrations and webhooks"
  - description: "File upload functionality"
  - description: "Search and filtering features (injection vectors)"

low_priority:
  - description: "Static marketing sites"
  - description: "Well-known CMS with current patches"
  - description: "CDN-served assets"
```

A thorough attack surface discovery phase typically reveals 3-5x more testable endpoints than what is visible from the main application alone. The hidden assets — forgotten subdomains, undocumented APIs, exposed internal tools — are where the highest-severity bugs live.

---

## 9. Parameter Discovery and Testing

Hidden parameters are a goldmine for bug bounty hunters. Many applications accept undocumented parameters that control authorization, filtering, and internal behavior.

```bash
# Discover hidden parameters with arjun
arjun -u "https://target.com/api/users" -m GET,POST -oJ hidden_params.json

# Use ffuf for parameter fuzzing
ffuf -u "https://target.com/api/users?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,301,302,403,500 -o param_fuzz.json

# Test for mass assignment (try adding admin fields to profile update)
curl -X PATCH "https://target.com/api/v1/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"test","role":"admin","is_admin":true}'

# Check for debug parameters
for param in debug test admin internal verbose trace; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/users?${param}=1")
  [ "$status" != "404" ] && echo "[INTERESTING] ?${param}=1 → $status"
done
```

**Parameter priority matrix:**

| Parameter Name | Likelihood of Finding | Typical Impact |
|---------------|----------------------|----------------|
| `admin`, `role`, `is_admin` | Medium | Privilege escalation |
| `debug`, `test`, `internal` | High | Information disclosure |
| `redirect`, `next`, `return_to` | High | Open redirect, SSRF |
| `file`, `path`, `include` | Medium | Path traversal, LFI |
| `url`, `uri`, `dest` | Medium | SSRF |
| `callback`, `jsonp` | Low | XSS, information disclosure |
| `limit`, `offset`, `count` | High | Data exposure, DoS |

---

## 10. Cloud Asset Enumeration

Cloud resources are frequently exposed due to misconfigured permissions. Systematic enumeration can uncover S3 buckets, Azure blobs, GCP storage, and leaked cloud credentials.

```bash
# S3 bucket enumeration with permutations
for prefix in target target-com target-prod target-dev target-staging \
  target-backup target-assets target-uploads target-reports target-data \
  target-static target-media target-cdn target-logs target-config; do
  if aws s3 ls "s3://${prefix}" --no-sign-request 2>/dev/null | head -1 | grep -q "."; then
    echo "[PUBLIC BUCKET] s3://${prefix}"
    aws s3 ls "s3://${prefix}" --no-sign-request --recursive | head -20
  fi
done

# Azure blob storage enumeration
for container in target target-backup target-data target-uploads; do
  az storage blob list --account-name "$container" --auth-mode login 2>/dev/null | \
    jq '.[].name' && echo "[ACCESSIBLE] $container"
done

# Check for exposed .env files on discovered subdomains
for host in $(cat live_hosts.txt | jq -r '.url'); do
  for path in /.env /.env.production /.env.local /.env.staging /app.env; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" "${host}${path}")
    if [ "$status" = "200" ]; then
      echo "[LEAKED ENV] ${host}${path}"
      curl -sk "${host}${path}" | grep -iE "key|secret|password|token" | head -5
    fi
  done
done
```

**Cloud asset discovery tools comparison:**

| Tool | Cloud Provider | Speed | Coverage | Notes |
|------|---------------|-------|----------|-------|
| `aws s3 ls` | AWS | Fast | Single bucket | Manual but reliable |
| `s3scanner` | AWS | Medium | Bulk scanning | Best for batch enumeration |
| `CloudEnum` | Multi-cloud | Slow | Comprehensive | Tests AWS, Azure, GCP |
| `ScoutSuite` | Multi-cloud | Slow | Audit-focused | Finds misconfigurations |
| `Prowler` | AWS | Medium | CIS compliance | Best for AWS audits |

---

## Hands-on Exercises

1. **Exercise 1**: Run the complete subdomain enumeration pipeline against a target with wildcard scope. Document how many subdomains are discovered by each source (subfinder, crt.sh, brute force, permutations) and calculate the overlap
2. **Exercise 2**: Perform JavaScript analysis on a target SPA application. Extract all API endpoints from JS bundles, identify hardcoded secrets, and map undocumented routes. Compare discovered endpoints against the documented API
3. **Exercise 3**: Set up the automated asset inventory pipeline from Section 7. Run it against a target, then run it again one week later. Document any new assets that appeared and investigate whether they introduce new attack surfaces
4. **Exercise 4**: Enumerate cloud assets for a target organization using the techniques in Section 10. Identify any publicly accessible storage buckets and document the type of data exposed
