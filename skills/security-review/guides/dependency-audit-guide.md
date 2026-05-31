# Dependency Audit Guide

> Practical reference for auditing software dependencies for known vulnerabilities. Covers npm audit, pip-audit, Snyk CLI, SBOM generation, and integrating dependency checks into CI pipelines.

## 1. npm Audit for JavaScript/Node.js

```bash
# Basic audit — shows known vulnerabilities in dependencies
npm audit

# JSON output for programmatic processing
npm audit --json > npm_audit_results.json

# Only production dependencies (skip devDependencies)
npm audit --omit=dev

# Auto-fix compatible vulnerabilities
npm audit fix

# Force fix (may include breaking changes)
npm audit fix --force

# Audit specific severity levels
npm audit --audit-level=high

# Check lock file without installing
npm audit --package-lock-only

# Generate detailed report
npm audit --json | jq '.vulnerabilities | to_entries[] | {name: .key, severity: .value.severity, via: .value.via[0].title}'
```

## 2. pip-audit for Python

```bash
# Install pip-audit
pip install pip-audit

# Audit current environment
pip-audit

# Audit a requirements file
pip-audit -r requirements.txt

# Output in JSON format
pip-audit -f json -o audit_results.json

# Strict mode — fail on any vulnerability
pip-audit --strict

# Audit with fix suggestions
pip-audit --fix --dry-run

# Use OSV database (default) or PyPI advisory DB
pip-audit --vulnerability-service osv
pip-audit --vulnerability-service pypi

# Ignore specific vulnerabilities (with justification)
pip-audit --ignore-vuln PYSEC-2023-001 --ignore-vuln GHSA-xxxx-yyyy

# Audit a specific package
pip-audit --requirement=- <<< "requests==2.25.0"
```

## 3. Snyk CLI for Multi-Language Support

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Test project for vulnerabilities
snyk test

# Test specific manifest file
snyk test --file=requirements.txt
snyk test --file=pom.xml
snyk test --file=go.mod

# Monitor project (continuous tracking)
snyk monitor

# Test container image
snyk container test nginx:latest
snyk container test myapp:v1.0 --file=Dockerfile

# Infrastructure as Code scanning
snyk iac test terraform/

# Output formats
snyk test --json > snyk_results.json
snyk test --sarif > snyk_results.sarif

# Filter by severity
snyk test --severity-threshold=high

# Ignore specific vulnerabilities
snyk ignore --id=SNYK-JS-LODASH-590103 --reason="Not exploitable in our context"
```

## 4. SBOM Generation

Software Bill of Materials provides a complete inventory of all components.

```bash
# Generate SBOM with syft (supports many formats)
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate CycloneDX SBOM from directory
syft dir:./src -o cyclonedx-json > sbom.cdx.json

# Generate SPDX SBOM
syft dir:./src -o spdx-json > sbom.spdx.json

# SBOM from container image
syft alpine:latest -o cyclonedx-json > alpine_sbom.cdx.json

# Generate SBOM with npm (built-in)
npm sbom --sbom-format cyclonedx > npm_sbom.cdx.json

# Python — use cyclonedx-bom
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.cdx.json --format json

# Scan SBOM for vulnerabilities with grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype sbom:sbom.cdx.json
grype sbom:sbom.cdx.json -o json > grype_results.json
```

## 5. Automated CI Integration

```yaml
# GitHub Actions — comprehensive dependency audit
name: Dependency Audit
on:
  push:
    paths: ['package-lock.json', 'requirements.txt', 'go.sum', 'Cargo.lock']
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  npm-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm audit --audit-level=high
      
  pip-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install pip-audit
      - run: pip-audit -r requirements.txt --strict

  snyk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - uses: anchore/scan-action@v4
        with:
          sbom: sbom.cdx.json
          fail-build: true
          severity-cutoff: high
```

## 6. License Compliance Auditing

```bash
# Check licenses with license-checker (npm)
npx license-checker --summary
npx license-checker --failOn "GPL-3.0;AGPL-3.0"
npx license-checker --json > licenses.json

# Python license check
pip install pip-licenses
pip-licenses --format=json --output-file=licenses.json
pip-licenses --fail-on="GPL-3.0-or-later;AGPL-3.0-or-later"

# Comprehensive license scan with scancode
pip install scancode-toolkit
scancode --license --json-pp licenses_scan.json src/

# SBOM-based license extraction
syft dir:. -o cyclonedx-json | jq '.components[].licenses'
```

## 7. Vulnerability Prioritization

```python
#!/usr/bin/env python3
"""Prioritize vulnerabilities by exploitability and reachability."""
import json
import sys

def prioritize_vulns(audit_file: str) -> None:
    with open(audit_file) as f:
        data = json.load(f)
    
    vulns = data.get('vulnerabilities', {})
    prioritized = []
    
    for name, info in vulns.items():
        severity = info.get('severity', 'unknown')
        fixable = info.get('fixAvailable', False)
        direct = info.get('isDirect', False)
        
        # Priority score: direct + fixable + severity
        score = 0
        score += 10 if direct else 0
        score += 5 if fixable else 0
        score += {'critical': 20, 'high': 15, 'moderate': 10, 'low': 5}.get(severity, 0)
        
        prioritized.append({
            'package': name,
            'severity': severity,
            'direct': direct,
            'fixable': fixable,
            'score': score
        })
    
    prioritized.sort(key=lambda x: x['score'], reverse=True)
    
    print("Priority | Package | Severity | Direct | Fixable")
    print("-" * 60)
    for v in prioritized[:20]:
        print(f"  {v['score']:3d}    | {v['package']:<20s} | {v['severity']:<8s} | {v['direct']} | {v['fixable']}")

if __name__ == '__main__':
    prioritize_vulns(sys.argv[1])
```

```bash
# Run prioritization
npm audit --json > audit.json
python3 prioritize_vulns.py audit.json
```

## 8. Remediation Workflow

```bash
# Step 1: Identify what needs updating
npm outdated
pip list --outdated

# Step 2: Check if update is safe (breaking changes)
npm info lodash versions --json | jq '.[-5:]'
pip install --dry-run --upgrade requests

# Step 3: Update with constraints
# npm — update within semver range
npm update
# npm — update to latest (may break)
npm install lodash@latest

# pip — update with upper bound
pip install "requests>=2.31.0,<3.0.0"

# Step 4: Verify no regressions
npm test
pytest

# Step 5: Document exceptions
cat > .snyk <<'EOF'
version: v1.5.0
ignore:
  SNYK-JS-EXAMPLE-12345:
    - '*':
        reason: 'Not exploitable — input is server-controlled'
        expires: 2025-12-31T00:00:00.000Z
EOF

# Step 6: Lock dependencies after remediation
npm shrinkwrap  # or commit package-lock.json
pip freeze > requirements.txt
```
