# Bug Bounty Automation Guide

> Guide for the security-bounty-hunter skill — covers automation patterns that multiply bounty hunting effectiveness through structured reconnaissance pipelines, continuous monitoring, automated triage, and ECC orchestration integration.

## Overview

Automation transforms bounty hunting from a manual, session-by-session effort into a scalable, repeatable operation. The goal is not to replace human intuition and creativity — it is to eliminate repetitive manual work so that human effort is spent where it matters most: analyzing complex vulnerabilities and crafting exploits.

This guide covers three automation layers:
1. **Reconnaissance automation**: Discover attack surfaces without manual effort
2. **Continuous monitoring**: Detect changes that create new opportunities
3. **Triage automation**: Filter noise so you focus on real findings

---

## Automated Reconnaissance Pipeline

### Subdomain Discovery Automation

Chain subdomain enumeration tools into a single pipeline that produces a deduplicated, resolved, HTTP-probed asset inventory:

```bash
#!/bin/bash
# Automated subdomain discovery pipeline
# Input: target domain
# Output: resolved subdomains with HTTP metadata

TARGET="$1"
OUTDIR="recon/${TARGET}_$(date +%Y%m%d)"
mkdir -p "$OUTDIR"

# Step 1: Passive subdomain collection from multiple sources
subfinder -d "$TARGET" -silent -all | sort -u > "$OUTDIR/subs_subfinder.txt"
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  jq -r '.[].name_value' | sort -u > "$OUTDIR/subs_crt.txt"

# Step 2: Combine and deduplicate
cat "$OUTDIR"/subs_*.txt | sort -u > "$OUTDIR/subs_all.txt"

# Step 3: DNS resolution
cat "$OUTDIR/subs_all.txt" | dnsx -silent -a -resp -o "$OUTDIR/resolved.txt"

# Step 4: HTTP probing with metadata
cat "$OUTDIR/resolved.txt" | httpx -silent -status-code -title -tech-detect \
  -content-length -web-server -o "$OUTDIR/httpx_results.txt"

# Step 5: Generate JSON output for triage input
cat "$OUTDIR/httpx_results.txt" | httpx -silent -json -o "$OUTDIR/services.json"

echo "[+] Reconnaissance complete: $(wc -l < "$OUTDIR/resolved.txt") resolved hosts"
echo "[+] Output directory: $OUTDIR"
```

**Output format**: Each line in `services.json` contains URL, status code, title, technology stack, content length, and web server.

### Technology Detection Automation

Automatically fingerprint the technology stack of all discovered services:

```bash
# Batch technology detection
cat "$OUTDIR/resolved.txt" | whatweb -a 3 -q --color=never > "$OUTDIR/tech_stack.txt"

# Extract unique technologies across all targets
cat "$OUTDIR/tech_stack.txt" | grep -oP '\[.*?\]' | tr '[]' '\n' | \
  sort | uniq -c | sort -rn > "$OUTDIR/tech_summary.txt"
```

**Why this matters**: Technology detection drives vulnerability testing priority. A target running a known-vulnerable framework version gets higher priority than one running the latest patched version.

### JavaScript Analysis Automation

Discover and analyze JavaScript files for hidden endpoints, secrets, and parameters:

```bash
# Step 1: Discover JS files
cat "$OUTDIR/httpx_results.txt" | awk '{print $1}' | \
  hakrawler -js -depth 2 -insecure | sort -u > "$OUTDIR/js_urls.txt"

# Step 2: Download and analyze JS files for secrets
while read -r js_url; do
  content=$(curl -s "$js_url")

  # Check for API keys and tokens
  echo "$content" | grep -oP '(api[_-]?key|token|secret|password|auth)\s*[:=]\s*["\x27][^"'\'']{8,}["\x27]' \
    >> "$OUTDIR/js_secrets.txt"

  # Check for internal API endpoints
  echo "$content" | grep -oP '(https?://[^\s"'\''<>]+(?:api|admin|internal|staging|v[0-9]+)[^\s"'\''<>]*)' \
    >> "$OUTDIR/js_endpoints.txt"

  # Check for interesting parameters
  echo "$content" | grep -oP '(callback|redirect|url|path|file|template|query|cmd|exec|run)\s*[:=]' \
    >> "$OUTDIR/js_params.txt"
done < "$OUTDIR/js_urls.txt"

# Deduplicate findings
sort -u "$OUTDIR/js_secrets.txt" -o "$OUTDIR/js_secrets.txt"
sort -u "$OUTDIR/js_endpoints.txt" -o "$OUTDIR/js_endpoints.txt"
sort -u "$OUTDIR/js_params.txt" -o "$OUTDIR/js_params.txt"
```

### URL Parameter Mining

Collect and deduplicate URL parameters from multiple sources:

```bash
# Collect URLs from multiple sources
echo "$TARGET" | waybackurls | sort -u > "$OUTDIR/urls_wayback.txt"
echo "$TARGET" | gau | sort -u > "$OUTDIR/urls_gau.txt"
cat "$OUTDIR/httpx_results.txt" | awk '{print $1}' | \
  hakrawler -depth 3 -plain -insecure | sort -u > "$OUTDIR/urls_crawl.txt"

# Combine all discovered URLs
cat "$OUTDIR"/urls_*.txt | sort -u > "$OUTDIR/urls_all.txt"

# Extract URLs with parameters
cat "$OUTDIR/urls_all.txt" | grep "=" | uro | sort -u > "$OUTDIR/urls_with_params.txt"

# Extract unique parameter names
cat "$OUTDIR/urls_with_params.txt" | grep -oP '[?&]([^=]+)=' | \
  sed 's/[?&]//g;s/=//g' | sort -u > "$OUTDIR/param_names.txt"
```

**Output format**: The final `urls_with_params.txt` file is the primary triage input. Each line contains a URL with at least one parameter, ready for fuzzing or injection testing.

---

## Continuous Monitoring with ECC Watch Loop

### Why Monitor Continuously

Targets change constantly: new endpoints are deployed, old vulnerabilities are patched, and new attack surfaces emerge. One-time reconnaissance misses these changes. Continuous monitoring detects new opportunities as they appear.

### ECC Watch Loop Configuration

Integrate with the Watch Loop pattern from the `autonomous-loops` skill:

```markdown
### ECC Watch Loop Configuration
- Pattern: Watch Loop (from autonomous-loops skill)
- Trigger: Scheduled scan interval (daily/weekly per target)
- Action on change: Alert -> Analyze -> Test new surface
- Safety: Scope-locked to authorized targets only
```

### Change Detection Workflow

```bash
#!/bin/bash
# Watch Loop: Detect changes in target attack surface
# Runs on schedule (daily or weekly per target)

TARGET="$1"
BASELINE="recon/${TARGET}/baseline"
CURRENT="recon/${TARGET}/$(date +%Y%m%d)"
mkdir -p "$CURRENT"

# Step 1: Run current recon (same pipeline as initial recon)
subfinder -d "$TARGET" -silent -all | sort -u > "$CURRENT/subs.txt"
cat "$CURRENT/subs.txt" | dnsx -silent -a -resp > "$CURRENT/resolved.txt"
cat "$CURRENT/resolved.txt" | httpx -silent -status-code -title -tech-detect \
  > "$CURRENT/httpx.txt"

# Step 2: Diff against baseline
# New subdomains
comm -13 "$BASELINE/subs.txt" "$CURRENT/subs.txt" > "$CURRENT/new_subs.txt"

# New resolved hosts
comm -13 "$BASELINE/resolved.txt" "$CURRENT/resolved.txt" > "$CURRENT/new_hosts.txt"

# New live services
comm -13 "$BASELINE/httpx.txt" "$CURRENT/httpx.txt" > "$CURRENT/new_services.txt"

# Changed technology stack (services that changed their tech)
diff "$BASELINE/httpx.txt" "$CURRENT/httpx.txt" | grep ">" | \
  sed 's/^> //' > "$CURRENT/changed_services.txt"

# Step 3: Alert on changes
CHANGES=$(cat "$CURRENT/new_subs.txt" "$CURRENT/new_hosts.txt" \
  "$CURRENT/changed_services.txt" 2>/dev/null | wc -l)

if [ "$CHANGES" -gt 0 ]; then
  echo "[ALERT] $TARGET: $CHANGES changes detected"
  echo "  New subdomains: $(wc -l < "$CURRENT/new_subs.txt")"
  echo "  New hosts: $(wc -l < "$CURRENT/new_hosts.txt")"
  echo "  Changed services: $(wc -l < "$CURRENT/changed_services.txt")"

  # Trigger analysis of new surface
  # (Feeds into triage pipeline below)
fi

# Step 4: Update baseline if significant time has passed
# (Weekly baseline refresh prevents stale alerts)
```

### Alert Prioritization

| Change Type | Priority | Action |
|------------|----------|--------|
| New subdomain with live HTTP | High | Immediate fingerprint and test |
| New API endpoint discovered | High | Add to triage queue |
| Changed technology stack | Medium | Re-evaluate attack surface |
| New JS file with secrets | Critical | Immediate manual analysis |
| New parameter on known endpoint | Medium | Add to fuzzing queue |
| Removed service | Low | Note for baseline update |

---

## Automated Triage

### Semgrep Scan with Bounty-Specific Rules

Run static analysis with rules tuned for bounty-worthy findings:

```bash
# Run semgrep with custom bounty rules
semgrep --config=bounty-rules.yml \
  --severity=ERROR --severity=WARNING \
  --exclude="*.test.*" --exclude="*.spec.*" --exclude="*test*" \
  --exclude="vendor" --exclude="node_modules" --exclude="fixtures" \
  --json target_code/ \
  -o "$OUTDIR/semgrep_results.json"

# Filter for network-reachable findings only
cat "$OUTDIR/semgrep_results.json" | \
  jq '.results[] | select(
    .extra.metadata.confidence == "HIGH" or
    .extra.severity == "ERROR"
  )' > "$OUTDIR/semgrep_filtered.json"
```

### Nuclei Scan with Custom Templates

Run dynamic analysis with bounty-focused templates:

```bash
# Update nuclei templates first
nuclei -update-templates

# Run with custom bounty templates
nuclei -u "$TARGET" \
  -t bounty-templates/ \
  -t cves/ \
  -t vulnerabilities/ \
  -severity critical,high,medium \
  -exclude "dos,fuzz" \
  -o "$OUTDIR/nuclei_results.txt" \
  -jsonl "$OUTDIR/nuclei_results.json"

# Filter out known false positive patterns
grep -v -E "(demo|example|test|localhost|127\.0\.0\.1)" \
  "$OUTDIR/nuclei_results.txt" > "$OUTDIR/nuclei_filtered.txt"
```

### Auto-Filter False Positives

Reduce noise by automatically excluding common false positive sources:

**Exclude patterns:**
- Test files: `*test*`, `*spec*`, `*.test.*`, `*.spec.*`
- Demo code: `*demo*`, `*example*`, `*sample*`
- Vendor code: `vendor/`, `node_modules/`, `third_party/`
- Documentation: `*.md`, `*.rst`, `*.txt` (unless containing secrets)
- Build artifacts: `dist/`, `build/`, `*.min.js`
- Local-only paths: `localhost`, `127.0.0.1`, `0.0.0.0`

**False positive indicators:**
- Finding only triggers on internal/test endpoints
- Sink is in a debugging or logging utility
- Input is hardcoded or comes from configuration, not users
- Vulnerability is in a dependency that is not actually used

### Confidence Scoring

Assign a confidence score to each automated finding:

| Factor | Points |
|--------|--------|
| Network-reachable endpoint | +30 |
| User-controlled input confirmed | +25 |
| No intervening sanitization | +20 |
| Known vulnerability pattern match | +15 |
| Matches previous bounty-winning pattern | +10 |

| Confidence Range | Action |
|-----------------|--------|
| 80-100 | Prioritize for manual exploitation |
| 60-79 | Add to testing queue |
| 40-59 | Review manually before investing time |
| Below 40 | Archive, revisit only if time permits |

---

## Automation Pipeline Architecture

### Full Pipeline Flow

```
Target List -> Recon -> Triage -> Manual Review -> Exploit -> Report
     ^                         |
     +--- Watch Loop <---------+
         (monitor for changes)
```

### Pipeline Stages

**Stage 1: Target List**

Maintain a structured list of authorized targets:

```markdown
## Target Inventory

| Target | Scope | Priority | Last Scan | Status |
|--------|-------|----------|-----------|--------|
| target-a.com | *.target-a.com, api.target-a.com | High | YYYY-MM-DD | Active |
| target-b.com | app.target-b.com | Medium | YYYY-MM-DD | Active |
| target-c.com | *.target-c.com | Low | YYYY-MM-DD | Monitoring |
```

**Stage 2: Reconnaissance** (automated)

Runs the full recon pipeline for each target. Output feeds directly into triage.

**Stage 3: Triage** (automated)

Runs semgrep, nuclei, and false positive filtering. Produces a prioritized finding list.

**Stage 4: Manual Review** (human)

Human reviews the prioritized findings, confirms exploitability, and decides whether to proceed.

**Stage 5: Exploitation** (human)

Human develops and executes PoC. This stage is never automated — exploitation requires human judgment for safety and scope compliance.

**Stage 6: Reporting** (semi-automated)

Uses article-writing skill for report generation. Human reviews and approves before submission.

---

## Tool Integration

### Burp Suite Automation

Configure Burp Suite for automated headless scanning:

```
1. Project Options:
   - Connections: Set threading to 5 (avoid overwhelming target)
   - HTTP: Set follow redirects to on-redirect-only
   - Spider: Set maximum depth to 3

2. Scan Configuration:
   - Active scan: selected URLs only (scope-enforced)
   - Passive scan: always on (no risk of disruption)
   - Audit checks: disable DoS and heavy brute force

3. Intruder for Parameter Fuzzing:
   - Attack type: cluster bomb
   - Payload positions: all parameters from param mining
   - Payload sets: common injection strings per vulnerability type
   - Grep-match: error patterns, interesting responses
```

### Nuclei Scheduled Scanning

```bash
# Schedule weekly nuclei scans per target
# Crontab format: 0 3 * * 0 = every Sunday at 3 AM

# Step 1: Update templates
nuclei -update-templates

# Step 2: Run scan
nuclei -l target_list.txt \
  -t cves/ -t vulnerabilities/ -t misconfiguration/ \
  -severity critical,high,medium \
  -o "recon/nuclei_$(date +%Y%m%d).txt" \
  -jsonl "recon/nuclei_$(date +%Y%m%d).json"

# Step 3: Diff against previous scan for new findings
diff "recon/nuclei_previous.txt" "recon/nuclei_$(date +%Y%m%d).txt" | \
  grep ">" > "recon/nuclei_new_$(date +%Y%m%d).txt"
```

### Custom Semgrep Rule Management

Maintain a custom rule set that grows with each bounty finding:

```bash
# Rule directory structure
bounty-rules/
  sqli.yml          # SQL injection patterns
  ssrf.yml          # SSRF patterns
  xss.yml           # XSS patterns
  auth-bypass.yml   # Authentication bypass patterns
  idor.yml          # IDOR patterns
  cmd-injection.yml # Command injection patterns
  secrets.yml       # Hardcoded secret patterns

# Run all custom rules
semgrep --config=bounty-rules/ --json target/ -o results.json
```

### Finding Deduplication

Track findings across scan runs to avoid re-investigating:

```bash
# Generate a hash for each finding based on its key attributes
cat results.json | jq '.results[] | {
  rule: .check_id,
  file: .path,
  line: .start.line,
  hash: (.check_id + .path + (.start.line | tostring)) | @base64
}' > finding_hashes.json

# Compare against previous run
comm -23 previous_hashes.txt current_hashes.txt > new_findings.txt
```

---

## ECC Orchestration Integration

### Watch Loop: Continuous Target Monitoring

Uses the Watch Loop pattern from `autonomous-loops` skill:

```
Pattern: Watch Loop
Target: All targets in inventory
Polling interval: Daily for high-priority, weekly for low-priority
Trigger: Any change detected in recon output
Action: Alert -> Queue new surface for triage
Safety: Scope-locked, rate-limited, evidence-logged
```

### Batch Processing: Multi-Target Parallel Scanning

Uses the Batch Processing pattern from `autonomous-loops` skill:

```
Pattern: Batch Processing
Concurrency: 5 targets simultaneously
Operation: Run recon pipeline on each target
Rate limit: 2-second delay between batches
Output: Per-target results in structured directory
Safety: Maximum 20 targets per batch run
```

### Sequential Pipeline: Recon to Report Flow

Uses the Sequential Pipeline pattern from `autonomous-loops` skill:

```
Pattern: Sequential Pipeline
Steps:
  1. Recon (automated)
  2. Triage (automated)
  3. Manual review (human gate)
  4. Exploit (human gate)
  5. Report (semi-automated)
Safety: Stop on critical error, log all steps
```

### Learning Cycle: Improving Automation Rules

Uses the Learning Cycle pattern from `autonomous-loops` skill:

```
Pattern: Learning Cycle
Objective: Improve automation accuracy over time
Feedback: Bounty results (accepted, rejected, duplicate)
Adjustment: Update rules based on what findings get accepted
  - Promote rules that lead to accepted findings
  - Demote rules that consistently produce duplicates or rejections
  - Add new rules when manual testing reveals automatable patterns
Safety: Maximum 50 rule iterations before human review
```

---

## Safety Guardrails

### Scope Enforcement

All automated tools must enforce scope boundaries:

1. **Scope file**: Maintain a machine-readable scope definition for each target
2. **Pre-scan check**: Every automated scan validates targets against scope before execution
3. **Runtime enforcement**: Tools are configured with explicit target lists, not open-ended discovery
4. **Post-scan audit**: Verify that no out-of-scope targets were contacted

```markdown
## Scope Definition: [Target Name]

### In Scope
- *.target.com (all subdomains)
- api.target.com (all endpoints)
- 192.0.2.0/24 (specific IP range)

### Out of Scope
- payments.target.com (third-party)
- admin.target.com (explicitly excluded)
- Any .onion or internal-only addresses
```

### Rate Limiting

| Tool | Max Requests/Second | Max Concurrent |
|------|--------------------|---------------|
| httpx | 50 | 25 |
| nuclei | 25 | 10 |
| ffuf | 100 | 20 |
| nmap | N/A (per-host timing) | 5 hosts |
| semgrep | N/A (local analysis) | unlimited |

**Rate limit handling:**
- If a 429 (Too Many Requests) response is received, pause for 60 seconds
- If a 503 (Service Unavailable) response is received, pause for 120 seconds
- If WAF blocking is detected (403 with challenge page), stop and alert

### Safe Payload Verification

Before running automated exploitation:

1. **Payload review**: All automated payloads must be reviewed against safe payload guidelines
2. **Impact assessment**: Verify that automated payloads cannot cause data modification or service disruption
3. **Dry run mode**: Run payloads in dry-run mode first (log what would be sent, without sending)
4. **Human approval gate**: Automated exploitation never proceeds without human confirmation

### Human Approval Gates

| Stage | Automation Level | Human Gate Required |
|-------|-----------------|-------------------|
| Reconnaissance | Fully automated | No |
| Triage | Fully automated | No |
| Finding prioritization | Semi-automated | Yes (review prioritized list) |
| Exploitation | Manual only | Always |
| Report submission | Semi-automated | Yes (review before submit) |

---

## Output Management

### Structured Finding Storage

Store findings in a consistent format that feeds into knowledge-ops:

```markdown
## Finding: [ID]

**Target**: [target name]
**Type**: [vulnerability class]
**Severity**: [Critical/High/Medium/Low]
**Confidence**: [score]/100
**Status**: [New/Confirmed/Reported/Accepted/Duplicate/Closed]

### Discovery
- **Date**: YYYY-MM-DD
- **Method**: [automated/manual]
- **Tool**: [semgrep/nuclei/manual]
- **Rule/Template**: [rule ID if applicable]

### Technical Details
- **Endpoint**: [URL]
- **Parameter**: [parameter name]
- **Payload**: [sanitized payload]
- **Response**: [relevant response excerpt]

### Impact
[Description of what this vulnerability enables]

### Evidence
[Full request/response or tool output]
```

### Cross-Session Finding Correlation

Link related findings across sessions and targets:

1. **By vulnerability pattern**: Findings with the same CWE across different targets
2. **By technology stack**: Findings in the same framework or library version
3. **By attack chain**: Findings that could be combined into a multi-step exploit

### Deduplication Across Targets and Time

Before submitting any finding:

1. Check internal finding database for existing reports on the same target
2. Check bug bounty platform for publicly reported duplicates
3. Check CVE databases for known vulnerabilities in the same component
4. Check vendor advisories for already-patched issues

### Integration with Article-Writing

Use the article-writing skill for report generation:

1. **Finding data feeds directly into report templates**
2. **CVSS scoring uses the cvss-scoring guide** from article-writing
3. **Report structure follows the report-structure guide** from article-writing
4. **Vulnerability descriptions use the vulnerability-writing guide** from article-writing

---

## Integration with Other Skills

| Skill | Integration Point |
|-------|------------------|
| `autonomous-loops` | Watch Loop, Batch Processing, Sequential Pipeline, Learning Cycle |
| `knowledge-ops` | Finding storage, cross-session correlation, pattern documentation |
| `article-writing` | Report generation, CVSS scoring, advisory drafting |
| `recon-osint` | Reconnaissance pipeline tools and techniques |
| `deep-research` | Researching new vulnerability patterns for automation rules |
| `safety-guard` | Pre-execution safety checks, scope enforcement |
| `vulnerability-assessment` | Scanner integration and finding triage |
