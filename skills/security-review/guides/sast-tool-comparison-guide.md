# SAST Tool Comparison Guide

> Practical reference comparing Semgrep, CodeQL, and Bandit for static application security testing. Covers rule writing, CI integration, and choosing the right tool for your stack.

## 1. Tool Overview and Selection

Each SAST tool has distinct strengths. Choose based on language coverage and workflow needs.

```yaml
# Quick comparison matrix
semgrep:
  languages: 30+ (Python, JS/TS, Java, Go, Ruby, C, etc.)
  speed: Fast (single-pass, no compilation needed)
  rules: Pattern-based (easy to write)
  ci_integration: Native (semgrep ci)
  cost: Free OSS + paid Pro rules

codeql:
  languages: 10 (C/C++, Java, C#, Python, JS/TS, Go, Ruby, Swift)
  speed: Slow (requires database build from source)
  rules: Query language (powerful dataflow analysis)
  ci_integration: GitHub Actions native
  cost: Free for OSS, paid for private repos

bandit:
  languages: Python only
  speed: Very fast
  rules: AST-based plugins
  ci_integration: Any CI (pip install)
  cost: Free
```

## 2. Semgrep Quick Start

```bash
# Install and run with default rules
pip install semgrep
semgrep scan --config=auto .

# Run specific rulesets
semgrep scan --config=p/owasp-top-ten .
semgrep scan --config=p/security-audit .
semgrep scan --config=p/secrets .

# Target specific languages
semgrep scan --config=p/python --lang=python src/

# Output formats for CI
semgrep scan --config=auto --json -o results.json .
semgrep scan --config=auto --sarif -o results.sarif .

# Ignore paths and rules
semgrep scan --config=auto --exclude='tests/*' --exclude='vendor/*' .
```

## 3. Writing Custom Semgrep Rules

```yaml
# custom-rules/sql-injection.yaml
rules:
  - id: raw-sql-format-string
    patterns:
      - pattern: |
          cursor.execute(f"...$X...")
      - pattern-not: |
          cursor.execute(f"...", ...)
    message: >
      SQL query uses f-string interpolation. Use parameterized queries instead.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-89
      owasp: A03:2021

  - id: hardcoded-jwt-secret
    patterns:
      - pattern: |
          jwt.encode($PAYLOAD, "...", ...)
    message: >
      JWT secret is hardcoded. Use environment variable or secret manager.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-798

  - id: ssrf-requests-user-input
    patterns:
      - pattern: |
          requests.get($URL, ...)
      - pattern-where-python: |
          # URL comes from user input (Flask)
          "request." in str($URL)
    message: >
      Potential SSRF: URL derived from user input passed to requests.get()
    severity: WARNING
    languages: [python]
```

```bash
# Run custom rules
semgrep scan --config=custom-rules/ src/
```

## 4. CodeQL Setup and Queries

```bash
# Install CodeQL CLI
gh extension install github/gh-codeql

# Create database from source (required step)
codeql database create my-db --language=python --source-root=./src
codeql database create java-db --language=java --source-root=./src --command="mvn compile"

# Run standard security queries
codeql database analyze my-db codeql/python-queries:Security --format=sarif-latest --output=results.sarif

# Run specific query
codeql database analyze my-db ./custom-queries/sql-injection.ql --format=csv --output=results.csv
```

```python
# custom-queries/sql-injection.ql (CodeQL query)
/**
 * @name SQL injection from user input
 * @description Finds SQL queries built from user-controlled data
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @id py/sql-injection
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.", source.getNode(), "user input"
```

## 5. Bandit for Python Projects

```bash
# Install and basic scan
pip install bandit
bandit -r src/ -f json -o bandit_results.json

# Scan with specific severity and confidence
bandit -r src/ -ll -ii  # Only HIGH severity + HIGH confidence

# Skip specific tests
bandit -r src/ --skip B101,B601
# B101 = assert usage, B601 = paramiko shell

# Generate baseline (ignore existing issues)
bandit -r src/ -f json -o baseline.json
# Future runs compare against baseline
bandit -r src/ -b baseline.json

# Common test IDs to focus on:
# B102 - exec_used
# B301 - pickle usage
# B303 - insecure hash (MD5/SHA1)
# B501 - request with verify=False
# B602 - subprocess with shell=True
# B608 - SQL injection via string formatting

# Configuration file (.bandit)
cat > .bandit <<'EOF'
[bandit]
exclude = tests,venv
skips = B101
severity = medium
confidence = medium
EOF
```

## 6. CI/CD Integration

```yaml
# GitHub Actions — Semgrep
name: SAST
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            ./custom-rules/
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python, javascript
      - uses: github/codeql-action/analyze@v3

  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install bandit
      - run: bandit -r src/ -f json -o results.json -ll
      - uses: actions/upload-artifact@v4
        with:
          name: bandit-results
          path: results.json
```

## 7. Comparing Results and Reducing False Positives

```bash
# Semgrep — inline suppression
def process_query(user_input):
    # nosemgrep: raw-sql-format-string
    cursor.execute(f"SELECT * FROM safe_table WHERE id={validated_id}")

# Bandit — inline suppression
subprocess.call(cmd, shell=True)  # nosec B602

# CodeQL — query filters in qlpack.yml
# Exclude test files from analysis
exclude:
  - "**/test_*.py"
  - "**/tests/**"

# Compare tool outputs — find consensus vulnerabilities
python3 -c "
import json

with open('semgrep_results.json') as f:
    semgrep = json.load(f)
with open('bandit_results.json') as f:
    bandit = json.load(f)

semgrep_files = {r['path'] for r in semgrep.get('results', [])}
bandit_files = {r['filename'] for r in bandit.get('results', [])}

consensus = semgrep_files & bandit_files
print(f'Files flagged by both tools: {len(consensus)}')
for f in sorted(consensus):
    print(f'  {f}')
"
```

## 8. Rule Development Workflow

```bash
# Semgrep rule testing with --test
mkdir -p tests/
cat > tests/test_sql_injection.py <<'EOF'
# ruleid: raw-sql-format-string
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")

# ok: raw-sql-format-string
cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
EOF

semgrep --test custom-rules/

# Semgrep playground for rapid iteration
# https://semgrep.dev/playground — paste code and pattern

# Validate SARIF output for GitHub integration
pip install sarif-tools
sarif summary results.sarif
sarif diff baseline.sarif current.sarif
```
