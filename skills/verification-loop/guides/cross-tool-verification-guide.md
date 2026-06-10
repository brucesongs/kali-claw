# Cross-Tool Verification and Correlation Guide

## Introduction

Single-tool verification is insufficient for high-confidence vulnerability assessment. Cross-tool verification uses multiple independent tools to confirm findings, reducing false positives and increasing confidence in reported results. This guide covers methodology for correlating results across different security tools and building verification workflows that leverage tool diversity.

Cross-tool verification follows the principle that if three independent tools all report the same vulnerability, the likelihood of a false positive approaches zero. Conversely, if only one tool reports a finding that others miss, additional manual investigation is required before confirmation.

The core value of cross-tool verification is independence. Two tools that share the same detection engine or signature set provide less corroboration than two tools built on entirely different methodologies. For example, both Nuclei and Nikto detecting a missing header is weaker corroboration than Nuclei (template-based) and Burp Suite (behavioral analysis) independently reaching the same conclusion.

## Practical Steps

### 1. Multi-Tool Verification Strategy

```bash
# Cross-tool verification for web applications
python3 -c "
verification_matrix = {
    'sql_injection': {
        'primary': 'sqlmap',
        'secondary': ['nuclei', 'nikto', 'burp_suite'],
        'confirm_threshold': 2,  # Need 2+ tools to confirm
    },
    'xss': {
        'primary': 'dalfox',
        'secondary': ['nuclei', 'xsser', 'burp_suite'],
        'confirm_threshold': 2,
    },
    'ssrf': {
        'primary': 'nuclei',
        'secondary': ['burp_suite', 'ffuf'],
        'confirm_threshold': 1,  # Manual verification required
    },
}
for vuln, config in verification_matrix.items():
    print(f'{vuln}: primary={config[\"primary\"]}, need {config[\"confirm_threshold\"]}+ confirmations')
"
```

### 2. Vulnerability-to-Tool Mapping Reference

Use this reference to select the right combination of tools for each vulnerability class. The table includes recommended primary and secondary tools, along with the minimum confirmation threshold:

| Vulnerability Class | Primary Tool | Secondary Tools | Threshold | Notes |
|--------------------|--------------|-----------------|-----------|-------|
| SQL Injection | sqlmap | Nuclei, Burp Suite, manually crafted payloads | 2 | sqlmap alone is high confidence if --level 3+ |
| XSS (Reflected) | Dalfox | Nuclei, XSSer, browser DevTools | 2 | Always verify in browser manually |
| XSS (Stored) | Burp Suite | Manual browser testing, XSSer | 1 | Manual verification essential due to context |
| SSRF | Nuclei | Burp Suite, ffuf with callback | 1 | Use OOB callback for confirmation |
| LFI/RFI | ffuf | Nuclei, Burp Suite, manually crafted paths | 2 | Verify with /etc/passwd or equivalent |
| Command Injection | Commix | Nuclei, manual curl with time-delay | 1 | Time-based confirmation is high confidence |
| SSTI | tplmap | Nuclei, manual mathematical expression | 1 | Verify with simple math expression first |
| Open Redirect | Nuclei | Manual curl with redirect tracking | 2 | Easy to verify manually with -L flag |
| Authentication Bypass | Burp Suite | Manual session analysis, Nuclei | 1 | Requires understanding of auth mechanism |
| Information Disclosure | Nuclei | WhatWeb, curl headers, manual inspection | 2 | Many disclosures are environmental FPs |
| Broken Access Control | Manual testing | Burp Suite Autorize, ZAP | 1 | Automated tools are weak at IDOR detection |
| CSRF | Burp Suite | Manual form analysis | 1 | Verify token presence and validation |

### 3. Result Correlation Pipeline

```bash
# Correlate results from multiple scanners
python3 -c "
import json
from collections import defaultdict

def correlate_results(*result_files):
    findings = defaultdict(list)
    for filepath in result_files:
        with open(filepath) as f:
            data = json.load(f)
            for item in data:
                key = f\"{item.get('host')}:{item.get('port')}{item.get('path', '')}\"
                findings[key].append({
                    'tool': filepath.split('/')[-1].replace('.json', ''),
                    'type': item.get('type'),
                    'severity': item.get('severity'),
                })
    
    confirmed = {k: v for k, v in findings.items() if len(v) >= 2}
    print(f'Total unique findings: {len(findings)}')
    print(f'Cross-confirmed (2+ tools): {len(confirmed)}')
    return confirmed
"
```

### 4. Advanced Correlation Engine

For larger engagements, build a correlation engine that normalizes findings from different tools into a common schema:

```python
#!/usr/bin/env python3
"""Cross-tool result correlation engine with deduplication."""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


# Normalization mapping: different tools use different names for the same thing
VULN_ALIASES = {
    "sql_injection": ["sqli", "sql-injection", "sql_inj", "CWE-89"],
    "xss": ["cross-site-scripting", "xss-reflected", "xss-stored", "CWE-79"],
    "ssrf": ["server-side-request-forgery", "ssrf-url", "CWE-918"],
    "lfi": ["local-file-inclusion", "path-traversal", "directory-traversal", "CWE-22", "CWE-98"],
    "rce": ["remote-code-execution", "command-injection", "os-command-injection", "CWE-78"],
    "open_redirect": ["open-redirect", "url-redirection", "CWE-601"],
    "info_disclosure": ["information-disclosure", "info-leak", "sensitive-data-exposure", "CWE-200"],
}

SEVERITY_MAP = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
    "unknown": -1,
}


def normalize_vuln_type(raw_type: str) -> str:
    """Normalize vulnerability type across tools."""
    raw_lower = raw_type.lower().strip()
    for canonical, aliases in VULN_ALIASES.items():
        if raw_lower in aliases or raw_lower == canonical:
            return canonical
    return raw_lower


def generate_finding_signature(finding: Dict) -> str:
    """Create a deduplication signature based on finding characteristics."""
    signature_parts = [
        finding.get("host", ""),
        str(finding.get("port", "")),
        finding.get("path", ""),
        normalize_vuln_type(finding.get("type", "")),
    ]
    signature_str = "|".join(signature_parts)
    return hashlib.sha256(signature_str.encode()).hexdigest()[:16]


class CorrelationEngine:
    """Correlate findings from multiple tools into unified results."""

    def __init__(self):
        self.findings: Dict[str, Dict] = {}
        self.tool_counts: Dict[str, int] = defaultdict(int)

    def ingest(self, tool_name: str, findings: List[Dict]) -> int:
        """Ingest findings from a single tool."""
        added = 0
        for finding in findings:
            sig = generate_finding_signature(finding)
            self.tool_counts[tool_name] += 1

            if sig not in self.findings:
                self.findings[sig] = {
                    "signature": sig,
                    "host": finding.get("host", ""),
                    "port": finding.get("port", ""),
                    "path": finding.get("path", ""),
                    "vuln_type": normalize_vuln_type(finding.get("type", "")),
                    "severity_raw": finding.get("severity", "unknown"),
                    "severity_rank": SEVERITY_MAP.get(
                        finding.get("severity", "unknown").lower(), -1
                    ),
                    "tools_reported": [tool_name],
                    "evidence": [{tool_name: finding}],
                    "first_seen": datetime.utcnow().isoformat() + "Z",
                    "confirmation_count": 1,
                }
                added += 1
            else:
                existing = self.findings[sig]
                if tool_name not in existing["tools_reported"]:
                    existing["tools_reported"].append(tool_name)
                    existing["confirmation_count"] += 1
                existing["evidence"].append({tool_name: finding})
        return added

    def get_confirmed(self, min_tools: int = 2) -> List[Dict]:
        """Return findings confirmed by multiple tools."""
        return [
            f for f in self.findings.values()
            if f["confirmation_count"] >= min_tools
        ]

    def get_single_source(self) -> List[Dict]:
        """Return findings reported by only one tool."""
        return [
            f for f in self.findings.values()
            if f["confirmation_count"] == 1
        ]

    def generate_correlation_report(self) -> Dict:
        """Generate a comprehensive correlation summary."""
        all_findings = list(self.findings.values())
        confirmed = self.get_confirmed(min_tools=2)
        single = self.get_single_source()

        severity_summary = defaultdict(int)
        for f in confirmed:
            severity_summary[f["severity_raw"]] += 1

        return {
            "total_unique_findings": len(all_findings),
            "cross_confirmed": len(confirmed),
            "single_source": len(single),
            "tools_used": dict(self.tool_counts),
            "confirmed_by_severity": dict(severity_summary),
            "correlation_rate": round(
                (len(confirmed) / len(all_findings) * 100) if all_findings else 0, 1
            ),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }


# Example usage
if __name__ == "__main__":
    engine = CorrelationEngine()

    nuclei_results = [
        {"host": "target.com", "port": 443, "path": "/api/users", "type": "sqli", "severity": "high"},
        {"host": "target.com", "port": 443, "path": "/search", "type": "xss-reflected", "severity": "medium"},
        {"host": "target.com", "port": 443, "path": "/fetch", "type": "ssrf", "severity": "high"},
    ]

    burp_results = [
        {"host": "target.com", "port": 443, "path": "/api/users", "type": "sql_injection", "severity": "high"},
        {"host": "target.com", "port": 443, "path": "/search", "type": "cross-site-scripting", "severity": "medium"},
    ]

    engine.ingest("nuclei", nuclei_results)
    engine.ingest("burp_suite", burp_results)

    report = engine.generate_correlation_report()
    print(json.dumps(report, indent=2))

    print("\nConfirmed findings:")
    for f in engine.get_confirmed():
        print(f"  {f['vuln_type']} at {f['host']}{f['path']} "
              f"(tools: {', '.join(f['tools_reported'])})")
```

### 5. Manual Verification Checklist

```bash
# Automated verification script for common findings
python3 -c "
import subprocess

def verify_sqli(url, param):
    '''Verify SQL injection with multiple techniques.'''
    tests = [
        f\"sqlmap -u '{url}?{param}=1' --batch --level=1\",
        f\"curl -s '{url}?{param}=1\\'' --output /dev/null -w '%{{http_code}}'\",
    ]
    results = []
    for test in tests:
        result = subprocess.run(test, shell=True, capture_output=True, text=True)
        results.append(result.stdout)
    return results
"
```

### 6. Tool-Specific Verification Commands

Each vulnerability class has specific verification commands that use different detection approaches. Using complementary approaches reduces the chance of shared false positives:

```bash
# === SQL Injection verification with three independent methods ===

# Method 1: sqlmap (automated, parameterized testing)
sqlmap -u "https://target.com/api/user?id=1" --batch --level=3 --risk=2 --threads=4

# Method 2: Manual time-based verification (independent of sqlmap logic)
echo "Baseline:" && time curl -s -o /dev/null "https://target.com/api/user?id=1"
echo "Test (sleep 5):" && time curl -s -o /dev/null "https://target.com/api/user?id=1'+PG_SLEEP(5)--"

# Method 3: Error-based verification (different SQL syntax)
curl -s "https://target.com/api/user?id=1'" | grep -iE "(sql|syntax|mysql|postgres|oracle|sqlite)"

# === XSS verification with three independent methods ===

# Method 1: Dalfox (parameter fuzzing with built-in browser engine)
dalfox url "https://target.com/search?q=test" --blind https://callback.example.com

# Method 2: Manual curl with reflection check
curl -s "https://target.com/search?q=test123xyz" | grep -c "test123xyz"

# Method 3: Browser-based verification (most reliable for DOM XSS)
# Open in browser and observe if JavaScript executes:
echo "Open browser to: https://target.com/search?q=<img/src=x onerror=alert(document.domain)>"

# === SSRF verification with multiple callback methods ===

# Method 1: Nuclei with interactsh callback
nuclei -u "https://target.com/fetch" -t ssrf/ -o nuclei-ssrf-results.txt

# Method 2: Manual callback with Burp Collaborator
# In Burp: Insert collaborator URL into target parameter

# Method 3: Direct verification with internal IP
curl -v "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/" 2>&1 | grep -i "ami-id"
```

### 7. Confidence Scoring

```python
# Assign confidence scores based on verification method
def calculate_confidence(finding):
    score = 0
    if finding.get('automated_scan'):
        score += 25
    if finding.get('manual_reproduction'):
        score += 35
    if finding.get('cross_tool_confirm'):
        score += 25
    if finding.get('exploit demonstrated'):
        score += 15
    return min(score, 100)

# Confidence levels
# 0-25: Unverified (investigate further)
# 26-50: Partially verified (needs confirmation)
# 51-75: Likely confirmed (proceed with caution)
# 76-100: Fully confirmed (report with confidence)
```

### 8. Enhanced Confidence Scoring with Tool Reliability Weights

Not all tools are equally reliable for all vulnerability types. This enhanced scoring system weights confirmations based on the tool's known accuracy for each vulnerability class:

```python
#!/usr/bin/env python3
"""Confidence scoring with tool reliability weights."""

from typing import Dict, List


# Reliability weights per tool per vulnerability type (0.0 to 1.0)
# Based on empirical testing across multiple engagements
TOOL_RELIABILITY: Dict[str, Dict[str, float]] = {
    "sqlmap": {
        "sql_injection": 0.95,  # Extremely reliable for SQLi
        "xss": 0.0,             # Not designed for XSS
        "ssrf": 0.0,            # Not designed for SSRF
    },
    "nuclei": {
        "sql_injection": 0.70,
        "xss": 0.75,
        "ssrf": 0.65,
        "lfi": 0.70,
        "info_disclosure": 0.85,
        "open_redirect": 0.90,
    },
    "burp_suite": {
        "sql_injection": 0.80,
        "xss": 0.85,
        "ssrf": 0.75,
        "broken_access_control": 0.70,
    },
    "dalfox": {
        "xss": 0.90,
        "sql_injection": 0.20,  # Not a SQLi tool
    },
    "manual_verification": {
        "sql_injection": 0.95,
        "xss": 0.95,
        "ssrf": 0.90,
        "broken_access_control": 0.95,
    },
}


def calculate_weighted_confidence(
    finding_type: str,
    tools_reported: List[str],
    manual_verified: bool = False,
    exploit_demonstrated: bool = False,
) -> Dict:
    """Calculate confidence score using weighted tool reliability."""
    total_weight = 0.0
    contributing_tools = []

    for tool in tools_reported:
        weight = TOOL_RELIABILITY.get(tool, {}).get(finding_type, 0.30)
        if weight > 0:
            total_weight += weight
            contributing_tools.append((tool, weight))

    if manual_verified:
        mw = TOOL_RELIABILITY["manual_verification"].get(finding_type, 0.90)
        total_weight += mw
        contributing_tools.append(("manual_verification", mw))

    # Cap at 1.0 for weighted sum, then scale to 100
    raw_score = min(total_weight, 2.0)
    confidence = int((raw_score / 2.0) * 85)  # Max 85 from tools alone

    if exploit_demonstrated:
        confidence += 15  # Demonstrated exploit adds full confidence

    confidence = min(confidence, 100)

    # Classify confidence level
    if confidence >= 76:
        level = "Confirmed"
    elif confidence >= 51:
        level = "Likely"
    elif confidence >= 26:
        level = "Suspected"
    else:
        level = "Unverified"

    return {
        "finding_type": finding_type,
        "confidence_score": confidence,
        "confidence_level": level,
        "contributing_tools": contributing_tools,
        "manual_verified": manual_verified,
        "exploit_demonstrated": exploit_demonstrated,
    }


# Example: Three tools report SQL injection
result = calculate_weighted_confidence(
    finding_type="sql_injection",
    tools_reported=["sqlmap", "nuclei", "burp_suite"],
    manual_verified=True,
    exploit_demonstrated=True,
)

import json
print(json.dumps(result, indent=2))
```

### 9. Verification Workflow Automation

Automate the cross-tool verification pipeline for common scenarios:

```bash
#!/bin/bash
# cross-verify.sh — Automated cross-tool verification pipeline
# Usage: ./cross-verify.sh <target_url> <output_dir>

TARGET="${1:?Usage: $0 <target_url> <output_dir>}"
OUTDIR="${2:-./cross-verify-results}"
mkdir -p "$OUTDIR"

echo "[*] Starting cross-tool verification for: $TARGET"
echo "[*] Results directory: $OUTDIR"

# Phase 1: Reconnaissance
echo "[Phase 1] Running Nuclei scan..."
nuclei -u "$TARGET" -o "$OUTDIR/nuclei-results.txt" -jsonl 2>/dev/null

echo "[Phase 1] Running Nikto scan..."
nikto -h "$TARGET" -o "$OUTDIR/nikto-results.txt" -Format json 2>/dev/null

# Phase 2: Targeted verification based on Nuclei findings
echo "[Phase 2] Verifying SQL injection findings..."
grep -i "sqli\|sql-injection" "$OUTDIR/nuclei-results.txt" | while read -r line; do
    endpoint=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('matched-at',''))" 2>/dev/null)
    if [ -n "$endpoint" ]; then
        echo "  [verify] Testing: $endpoint"
        sqlmap -u "$endpoint" --batch --level=1 --smart -o "$OUTDIR/sqlmap-verify.txt" 2>/dev/null
    fi
done

echo "[Phase 2] Verifying XSS findings..."
grep -i "xss\|cross-site" "$OUTDIR/nuclei-results.txt" | while read -r line; do
    endpoint=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('matched-at',''))" 2>/dev/null)
    if [ -n "$endpoint" ]; then
        echo "  [verify] Testing: $endpoint"
        dalfox url "$endpoint" --silent -o "$OUTDIR/dalfox-verify.txt" 2>/dev/null
    fi
done

# Phase 3: Correlation
echo "[Phase 3] Correlating results..."
python3 -c "
import json
from collections import defaultdict

findings = defaultdict(list)

# Load Nuclei results
try:
    with open('$OUTDIR/nuclei-results.txt') as f:
        for line in f:
            item = json.loads(line.strip())
            key = item.get('matched-at', 'unknown')
            findings[key].append({'tool': 'nuclei', 'type': item.get('type', 'unknown')})
except Exception:
    pass

# Load Nikto results
try:
    with open('$OUTDIR/nikto-results.txt') as f:
        data = json.load(f)
        for vuln in data.get('vulnerabilities', []):
            key = vuln.get('url', 'unknown')
            findings[key].append({'tool': 'nikto', 'type': vuln.get('id', 'unknown')})
except Exception:
    pass

# Report correlation
confirmed = {k: v for k, v in findings.items() if len(v) >= 2}
single = {k: v for k, v in findings.items() if len(v) == 1}

print(f'Total unique endpoints with findings: {len(findings)}')
print(f'Cross-confirmed (2+ tools): {len(confirmed)}')
print(f'Single-source findings: {len(single)}')

with open('$OUTDIR/correlation-report.json', 'w') as f:
    json.dump({'confirmed': dict(confirmed), 'single_source': dict(single)}, f, indent=2)
"

echo "[*] Cross-tool verification complete. See $OUTDIR/correlation-report.json"
```

### 10. Handling Disagreements Between Tools

When tools disagree, follow this decision matrix:

| Scenario | Tool A Says | Tool B Says | Action |
|----------|-------------|-------------|--------|
| Agreement | Vulnerable | Vulnerable | Report as confirmed |
| Partial | Vulnerable | Possible | Manual verification required |
| Disagreement | Vulnerable | Not found | Investigate: different scan depth, parameters, or false positive |
| Contradiction | Vulnerable | Patched | Verify patch version, check for bypass |
| Silent Disagree | Not found | Vulnerable | Re-scan with Tool A at higher depth |

Key factors in resolving disagreements:

1. **Scan depth differences**: Tool A may have scanned at depth 1 while Tool B used depth 3. Always check scan configurations before concluding.
2. **Authentication state**: One tool may have been authenticated, the other not. Authentication reveals different attack surfaces.
3. **Timing**: Scans run at different times may encounter different application states (e.g., WAF rule updates, deployments).
4. **Detection method**: Pattern-matching vs. behavioral analysis vs. active exploitation produce different coverage.

## Hands-on Exercises

### Exercise 1: Multi-Tool Correlation

Run three different tools against the same target and correlate results to identify high-confidence findings.

**Steps:**

1. Select a target from your authorized scope.
2. Run Nuclei, Nikto, and one manual testing technique against the same endpoint.
3. Save all results in JSON format.
4. Use the CorrelationEngine from Section 4 to merge and correlate findings.
5. Identify findings confirmed by 2+ tools and single-source findings.
6. For single-source findings, perform targeted manual verification.
7. Document the correlation rate and FP rate for each tool.

**Expected outcome**: A correlation report showing which findings are cross-confirmed and which require additional verification. Target: process 20+ findings in under 60 minutes.

### Exercise 2: Confidence Scoring Practice

Score a set of findings using the confidence methodology and justify each score.

**Steps:**

1. Use the sample findings below (or generate your own).
2. Apply both the basic confidence scoring from Section 7 and the weighted scoring from Section 8.
3. For each finding, write a one-sentence justification for the score.
4. Identify findings where the two scoring methods disagree and explain why.

```python
# Sample findings for scoring practice
sample_findings = [
    {
        "id": "F-001", "type": "sql_injection", "host": "target.com",
        "path": "/api/users", "tools": ["sqlmap", "nuclei"],
        "manual_verified": True, "exploit_demonstrated": True,
    },
    {
        "id": "F-002", "type": "xss", "host": "target.com",
        "path": "/search", "tools": ["dalfox"],
        "manual_verified": False, "exploit_demonstrated": False,
    },
    {
        "id": "F-003", "type": "ssrf", "host": "target.com",
        "path": "/fetch", "tools": ["nuclei", "burp_suite"],
        "manual_verified": True, "exploit_demonstrated": False,
    },
    {
        "id": "F-004", "type": "info_disclosure", "host": "target.com",
        "path": "/.env", "tools": ["nuclei"],
        "manual_verified": False, "exploit_demonstrated": False,
    },
]
```

### Exercise 3: Build a Custom Verification Pipeline

Using the `cross-verify.sh` script from Section 9 as a starting point, build a custom verification pipeline for your specific engagement. Add at least two additional tools and a correlation step.

**Steps:**

1. Identify the tools available in your testing environment.
2. Map each tool to the vulnerability classes from the table in Section 2.
3. Build the scan pipeline with proper error handling and output formatting.
4. Run the pipeline against an authorized target.
5. Analyze the correlation results and write a brief summary of findings.

### Exercise 4: Disagreement Resolution

Using the decision matrix from Section 10, resolve five simulated tool disagreements. For each, document which factor explained the disagreement (scan depth, authentication, timing, or detection method).

## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- PTES Verification Standards — http://www.pentest-standard.org/
- NIST SP 800-115 — Technical Guide to Information Security Testing
- Nuclei Templates Documentation — https://docs.projectdiscovery.io/nuclei/
- sqlmap User Manual — https://sqlmap.org/
- Dalfox Documentation — https://github.com/hahwul/dalfox
- Burp Suite Documentation — https://portswigger.net/burp/documentation
