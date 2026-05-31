# Regression Testing for Security Guide

> Practical reference for re-testing previously fixed vulnerabilities, verifying patches are effective, and detecting bypass techniques. Covers automated regression suites, patch validation workflows, and continuous re-verification.

## 1. Security Regression Testing Principles

Fixed vulnerabilities can resurface through code changes, dependency updates, or incomplete patches.

```yaml
# Regression test categories
regression_types:
  patch_verification:
    description: Confirm the fix actually prevents exploitation
    timing: Immediately after patch deployment
    
  bypass_detection:
    description: Test variations that might circumvent the fix
    timing: After patch + during subsequent code reviews
    
  dependency_regression:
    description: Check if dependency updates reintroduce vulns
    timing: On every dependency update
    
  refactor_regression:
    description: Verify security controls survive code refactoring
    timing: After any refactoring of security-critical code

# Test retention policy
# Keep regression tests FOREVER for:
# - Critical/High severity findings
# - Authentication/authorization bypasses
# - Injection vulnerabilities
# - Data exposure issues
```

## 2. Building Regression Test Suites

```python
#!/usr/bin/env python3
"""Security regression test framework using pytest."""
import pytest
import requests

BASE_URL = "http://target.com"

class TestSQLInjectionRegression:
    """Regression tests for SQL injection fix in /search endpoint.
    Original finding: PT-2025-001-SQLI-01
    Fix date: 2025-03-15
    Fix: Parameterized queries in search_controller.py
    """
    
    @pytest.fixture
    def session(self):
        s = requests.Session()
        s.verify = False
        return s
    
    def test_original_payload_blocked(self, session):
        """Original exploit payload should no longer work."""
        resp = session.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"})
        assert "error" not in resp.text.lower() or resp.status_code == 400
        assert "sql" not in resp.text.lower()
    
    def test_union_injection_blocked(self, session):
        """UNION-based injection variant."""
        resp = session.get(f"{BASE_URL}/search", params={"q": "' UNION SELECT null,null--"})
        assert resp.status_code in (400, 200)
        # Should not return extra columns
        assert "null" not in resp.text
    
    def test_blind_boolean_blocked(self, session):
        """Boolean-based blind injection."""
        resp_true = session.get(f"{BASE_URL}/search", params={"q": "' AND 1=1--"})
        resp_false = session.get(f"{BASE_URL}/search", params={"q": "' AND 1=2--"})
        # Both should return same response (no information leakage)
        assert resp_true.status_code == resp_false.status_code
    
    def test_time_based_blocked(self, session):
        """Time-based blind injection should not cause delay."""
        import time
        start = time.time()
        session.get(f"{BASE_URL}/search", params={"q": "' AND SLEEP(5)--"})
        elapsed = time.time() - start
        assert elapsed < 3, f"Response took {elapsed}s — possible time-based SQLi"
    
    def test_encoding_bypass_blocked(self, session):
        """URL-encoded and double-encoded bypass attempts."""
        payloads = [
            "%27%20OR%201%3D1--",           # URL encoded
            "%2527%2520OR%25201%253D1--",   # Double encoded
            "' /**/OR/**/1=1--",             # Comment bypass
        ]
        for payload in payloads:
            resp = session.get(f"{BASE_URL}/search?q={payload}")
            assert resp.status_code in (400, 200)
```

## 3. Patch Verification Workflow

```bash
#!/bin/bash
# patch_verify.sh — Verify a security patch is effective
VULN_ID="${1:-PT-2025-001}"
TARGET="${2:-http://target.com}"
RESULTS_DIR="./regression_results/$VULN_ID/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo "=== Patch Verification: $VULN_ID ==="
echo "Target: $TARGET"
echo "Date: $(date -u)"

# Load original exploit from findings database
EXPLOIT_FILE="./findings/$VULN_ID/exploit.sh"
if [ ! -f "$EXPLOIT_FILE" ]; then
    echo "[-] No exploit file found for $VULN_ID"
    exit 1
fi

# Run original exploit — should FAIL now
echo "[*] Running original exploit (should fail)..."
bash "$EXPLOIT_FILE" "$TARGET" > "$RESULTS_DIR/original_exploit.txt" 2>&1
ORIG_EXIT=$?

if [ $ORIG_EXIT -eq 0 ]; then
    echo "[!] CRITICAL: Original exploit still works! Patch ineffective."
    exit 1
else
    echo "[+] Original exploit blocked (exit code: $ORIG_EXIT)"
fi

# Run bypass variants
echo "[*] Testing bypass variants..."
for variant in ./findings/$VULN_ID/bypasses/*.sh; do
    [ -f "$variant" ] || continue
    variant_name=$(basename "$variant" .sh)
    echo "  [*] Testing: $variant_name"
    bash "$variant" "$TARGET" > "$RESULTS_DIR/bypass_${variant_name}.txt" 2>&1
    if [ $? -eq 0 ]; then
        echo "  [!] WARNING: Bypass successful — $variant_name"
    else
        echo "  [+] Bypass blocked: $variant_name"
    fi
done

echo "=== Verification complete. Results: $RESULTS_DIR ==="
```

## 4. Automated Bypass Detection

```python
#!/usr/bin/env python3
"""Generate and test bypass variants for patched vulnerabilities."""
from dataclasses import dataclass
from typing import List
import requests
import urllib.parse

@dataclass(frozen=True)
class BypassVariant:
    name: str
    payload: str
    technique: str

def generate_xss_bypasses(original_payload: str) -> List[BypassVariant]:
    """Generate XSS filter bypass variants."""
    return [
        BypassVariant("case_variation", "<ScRiPt>alert(1)</ScRiPt>", "case mixing"),
        BypassVariant("event_handler", "<img src=x onerror=alert(1)>", "event handler"),
        BypassVariant("svg_onload", "<svg onload=alert(1)>", "SVG element"),
        BypassVariant("encoded_entities", "&#60;script&#62;alert(1)&#60;/script&#62;", "HTML entities"),
        BypassVariant("double_encoding", "%253Cscript%253Ealert(1)%253C/script%253E", "double URL encode"),
        BypassVariant("null_byte", "<scr\x00ipt>alert(1)</script>", "null byte insertion"),
        BypassVariant("template_literal", "${alert(1)}", "template literal"),
        BypassVariant("unicode_escape", "<script>alert(1)</script>", "unicode"),
    ]

def test_bypasses(url: str, param: str, variants: List[BypassVariant]) -> dict:
    """Test each bypass variant and report results."""
    results = {"blocked": [], "bypassed": []}
    
    for variant in variants:
        resp = requests.get(url, params={param: variant.payload}, verify=False)
        # Check if payload is reflected unescaped
        if variant.payload in resp.text or "alert(1)" in resp.text:
            results["bypassed"].append(variant)
            print(f"  [!] BYPASS: {variant.name} ({variant.technique})")
        else:
            results["blocked"].append(variant)
            print(f"  [+] Blocked: {variant.name}")
    
    return results
```

## 5. Nuclei-Based Regression Scanning

```yaml
# regression-templates/sqli-regression.yaml
id: sqli-regression-PT2025001
info:
  name: SQLi Regression Test - PT-2025-001
  severity: critical
  tags: regression,sqli
  metadata:
    original_finding: PT-2025-001
    fix_date: "2025-03-15"
    fix_commit: "abc123def"

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q={{payload}}"
    payloads:
      payload:
        - "' OR 1=1--"
        - "' UNION SELECT null--"
        - "'; WAITFOR DELAY '0:0:5'--"
        - "' AND SUBSTRING(@@version,1,1)='5'--"
    stop-at-first-match: false
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-"
          - "PostgreSQL"
        condition: or
      - type: dsl
        dsl:
          - "duration >= 5"
```

```bash
# Run regression suite
nuclei -t ./regression-templates/ -l targets.txt -o regression_results.json -json

# Schedule weekly regression scans
# crontab entry:
# 0 2 * * 1 /opt/security/run_regression.sh >> /var/log/regression.log 2>&1

# Compare results over time
nuclei -t ./regression-templates/ -l targets.txt -json | \
  jq -r '[.info.name, .matched_at, .timestamp] | @tsv' >> regression_history.tsv
```

## 6. CI/CD Integration for Security Regression

```yaml
# .github/workflows/security-regression.yml
name: Security Regression Tests
on:
  push:
    branches: [main, develop]
  pull_request:
    paths:
      - 'src/controllers/**'
      - 'src/middleware/auth**'
      - 'src/models/**'

jobs:
  regression:
    runs-on: ubuntu-latest
    services:
      app:
        image: myapp:test
        ports: ['8080:8080']
    steps:
      - uses: actions/checkout@v4
      
      - name: Run security regression suite
        run: |
          pip install pytest requests
          pytest tests/security/regression/ -v --tb=short \
            --junitxml=regression-results.xml
      
      - name: Run nuclei regression templates
        run: |
          nuclei -t ./security/regression-templates/ \
            -u http://localhost:8080 \
            -severity critical,high \
            -json -o nuclei-regression.json
          
          # Fail if any regression found
          if [ -s nuclei-regression.json ]; then
            echo "SECURITY REGRESSION DETECTED"
            cat nuclei-regression.json | jq .
            exit 1
          fi
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: regression-results
          path: |
            regression-results.xml
            nuclei-regression.json
```

## 7. Dependency Update Regression

```bash
# Check if dependency updates reintroduce vulnerabilities
#!/bin/bash
echo "=== Dependency Update Security Regression ==="

# Snapshot current dependency state
pip freeze > deps_before.txt  # or npm list --json

# Update dependencies
pip install --upgrade -r requirements.txt  # or npm update

# Snapshot after update
pip freeze > deps_after.txt

# Diff to see what changed
diff deps_before.txt deps_after.txt > deps_changes.txt

# Run security scan on updated deps
pip-audit --strict 2>&1 | tee dep_audit.txt

# Run application security regression tests
pytest tests/security/regression/ -v 2>&1 | tee regression_after_update.txt

# Check for known regression patterns
if grep -q "FAILED" regression_after_update.txt; then
    echo "[!] Security regression detected after dependency update!"
    echo "Changed packages:"
    cat deps_changes.txt
    exit 1
fi

echo "[+] No regressions detected after dependency update"
```

## 8. Tracking and Metrics

```bash
# Regression test coverage tracking
cat > track_regression_coverage.py <<'EOF'
#!/usr/bin/env python3
"""Track regression test coverage against historical findings."""
import json
import os
from pathlib import Path

findings_dir = Path("./findings")
regression_dir = Path("./tests/security/regression")

# Count findings by severity
findings = list(findings_dir.glob("*/metadata.json"))
total_findings = len(findings)

# Count regression tests
regression_tests = list(regression_dir.glob("**/test_*.py"))

# Check coverage
covered = set()
for test_file in regression_tests:
    content = test_file.read_text()
    for finding in findings:
        finding_id = finding.parent.name
        if finding_id in content:
            covered.add(finding_id)

coverage_pct = (len(covered) / total_findings * 100) if total_findings else 0

print(f"Total findings: {total_findings}")
print(f"Regression tests: {len(regression_tests)}")
print(f"Findings with regression coverage: {len(covered)}")
print(f"Coverage: {coverage_pct:.1f}%")
print(f"\nUncovered findings:")
for f in findings:
    if f.parent.name not in covered:
        meta = json.loads(f.read_text())
        print(f"  - {f.parent.name}: {meta.get('title', 'Unknown')} [{meta.get('severity', '?')}]")
EOF

python3 track_regression_coverage.py
```
