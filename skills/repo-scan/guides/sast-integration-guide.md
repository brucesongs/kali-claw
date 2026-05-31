# SAST Integration Guide

> Integrate static application security testing tools (Semgrep, CodeQL, Bandit) into CI pipelines for automated vulnerability detection.

## Prerequisites

- Semgrep CLI (`pip install semgrep`)
- CodeQL CLI (GitHub releases)
- Bandit (`pip install bandit`)
- CI platform access (GitHub Actions, GitLab CI, or Jenkins)

## 1. Semgrep — Pattern-Based SAST

### Local Scanning

```bash
# Install semgrep
pip install semgrep

# Scan with default rulesets (auto-detects language)
semgrep scan --config auto .

# Scan with specific security rulesets
semgrep scan --config p/security-audit .
semgrep scan --config p/owasp-top-ten .

# JSON output for CI parsing
semgrep scan --config auto --json -o semgrep-results.json .

# Only errors (high confidence findings)
semgrep scan --config auto --severity ERROR .

# Scan specific files
semgrep scan --config p/python --include "*.py" .
```

### Custom Rules

```yaml
# .semgrep/custom-rules.yml
rules:
  - id: hardcoded-secret-in-source
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: (password|secret|api_key|token)
      - pattern-not: $VAR = ""
      - pattern-not: $VAR = "placeholder"
    message: "Hardcoded secret detected in variable $VAR"
    severity: ERROR
    languages: [python, javascript, typescript]

  - id: sql-injection-format-string
    pattern: |
      cursor.execute(f"..." % ...)
    message: "Potential SQL injection via string formatting"
    severity: ERROR
    languages: [python]
```

```bash
# Run custom rules
semgrep scan --config .semgrep/custom-rules.yml .
```

### GitHub Actions Integration

```yaml
# .github/workflows/semgrep.yml
name: Semgrep SAST
on:
  pull_request: {}
  push:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: semgrep scan --config auto --json -o results.json .
      - run: |
          CRITICAL=$(cat results.json | jq '[.results[] | select(.extra.severity == "ERROR")] | length')
          echo "Critical findings: $CRITICAL"
          [ "$CRITICAL" -gt 0 ] && exit 1 || exit 0
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: semgrep-results
          path: results.json
```

## 2. CodeQL — Deep Semantic Analysis

### Database Creation and Querying

```bash
# Create CodeQL database for a Python project
codeql database create codeql-db --language=python --source-root=.

# Create for JavaScript/TypeScript
codeql database create codeql-db --language=javascript --source-root=.

# Run security queries
codeql database analyze codeql-db codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=codeql-results.sarif

# Run specific query pack
codeql database analyze codeql-db codeql/python-queries --format=csv --output=results.csv

# Convert SARIF to readable format
cat codeql-results.sarif | jq '.runs[].results[] | {rule: .ruleId, message: .message.text, location: .locations[0].physicalLocation.artifactLocation.uri}'
```

### GitHub Actions Integration

```yaml
# .github/workflows/codeql.yml
name: CodeQL Analysis
on:
  pull_request: {}
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday scan

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [python, javascript]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

## 3. Bandit — Python Security Linter

### Local Scanning

```bash
# Scan entire project
bandit -r . -f json -o bandit-results.json

# Scan with specific severity
bandit -r . -ll  # Only medium and above
bandit -r . -lll # Only high severity

# Exclude test directories
bandit -r . --exclude ./tests,./test -f json

# Scan specific files
bandit -r src/ -f html -o bandit-report.html

# Show confidence level
bandit -r . -ll --confidence-level high
```

### Configuration File

```ini
# .bandit.yml
exclude_dirs:
  - tests
  - test
  - venv
  - .venv

skips:
  - B101  # assert_used (acceptable in tests)
  - B601  # paramiko_calls (if intentional)

tests:
  - B102  # exec_used
  - B103  # set_bad_file_permissions
  - B104  # hardcoded_bind_all_interfaces
  - B105  # hardcoded_password_string
  - B106  # hardcoded_password_funcarg
  - B107  # hardcoded_password_default
  - B108  # hardcoded_tmp_directory
  - B110  # try_except_pass
  - B201  # flask_debug_true
  - B301  # pickle
  - B302  # marshal
  - B303  # md5/sha1
  - B501  # request_with_no_cert_validation
  - B502  # ssl_with_bad_version
  - B506  # yaml_load
  - B608  # hardcoded_sql_expressions
```

```bash
# Run with config
bandit -r . -c .bandit.yml -f json -o results.json
```

### GitLab CI Integration

```yaml
# .gitlab-ci.yml (SAST stage)
sast:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install bandit semgrep
  script:
    - bandit -r src/ -ll -f json -o bandit.json || true
    - semgrep scan --config auto --json -o semgrep.json src/ || true
    - |
      BANDIT_HIGH=$(cat bandit.json | python3 -c "import sys,json; r=json.load(sys.stdin); print(len([i for i in r.get('results',[]) if i['issue_severity']=='HIGH']))")
      SEMGREP_ERR=$(cat semgrep.json | python3 -c "import sys,json; r=json.load(sys.stdin); print(len([i for i in r.get('results',[]) if i['extra']['severity']=='ERROR']))")
      echo "Bandit HIGH: $BANDIT_HIGH | Semgrep ERROR: $SEMGREP_ERR"
      [ "$BANDIT_HIGH" -gt 0 ] || [ "$SEMGREP_ERR" -gt 0 ] && exit 1
  artifacts:
    paths:
      - bandit.json
      - semgrep.json
    when: always
```

## 4. Unified SAST Pipeline Script

```bash
#!/bin/bash
# sast-pipeline.sh — Run all SAST tools and aggregate results

set -euo pipefail
RESULTS_DIR="./sast-results"
mkdir -p "$RESULTS_DIR"
FAIL=0

echo "=== SAST Pipeline ==="

# Semgrep (multi-language)
echo "[1/3] Running Semgrep..."
semgrep scan --config auto --json -o "$RESULTS_DIR/semgrep.json" . 2>/dev/null || true
SEMGREP_ERRORS=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "$RESULTS_DIR/semgrep.json")
echo "  Semgrep critical findings: $SEMGREP_ERRORS"
[ "$SEMGREP_ERRORS" -gt 0 ] && FAIL=1

# Bandit (Python)
if find . -name "*.py" -not -path "./venv/*" | head -1 | grep -q .; then
    echo "[2/3] Running Bandit..."
    bandit -r . --exclude ./venv,./tests -ll -f json -o "$RESULTS_DIR/bandit.json" 2>/dev/null || true
    BANDIT_HIGH=$(jq '[.results[] | select(.issue_severity == "HIGH")] | length' "$RESULTS_DIR/bandit.json")
    echo "  Bandit high findings: $BANDIT_HIGH"
    [ "$BANDIT_HIGH" -gt 0 ] && FAIL=1
fi

# CodeQL (if database exists)
if [ -d "codeql-db" ]; then
    echo "[3/3] Running CodeQL..."
    codeql database analyze codeql-db --format=sarif-latest --output="$RESULTS_DIR/codeql.sarif" 2>/dev/null || true
    CODEQL_FINDINGS=$(jq '[.runs[].results[]] | length' "$RESULTS_DIR/codeql.sarif")
    echo "  CodeQL findings: $CODEQL_FINDINGS"
fi

echo "=== Results in $RESULTS_DIR ==="
exit $FAIL
```

## Quick Reference

| Tool | Best For | Command |
|------|----------|---------|
| Semgrep | Multi-language pattern matching | `semgrep scan --config auto .` |
| CodeQL | Deep dataflow analysis | `codeql database analyze` |
| Bandit | Python-specific security | `bandit -r . -ll` |

## Integration with Other Skills

- **repo-scan**: SAST as part of comprehensive repository audit
- **supply-chain-security**: Detecting malicious code patterns in dependencies
- **container-security**: Scanning application code before containerization
