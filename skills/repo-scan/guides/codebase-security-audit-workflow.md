# Codebase Security Audit Workflow

Step-by-step methodology for conducting systematic security audits of source code repositories using the four-phase repo-scan process: Surface Classification, Dependency Detection, Hotspot Prioritization, and Verdict Generation.

---

## 1. Four-Phase Audit Methodology

The repo-scan audit follows a progressive narrowing approach. Each phase reduces the scope of what the next phase must examine.

```
Phase 1: SURFACE CLASSIFICATION
  Enumerate every file. Tag as project code, third-party, config, test, or artifact.
  Output: File inventory with classifications.
       │
       ▼
Phase 2: DEPENDENCY DETECTION
  Identify all third-party libraries (declared and embedded).
  Scan for known CVEs in dependencies.
  Output: Dependency inventory with vulnerability status.
       │
       ▼
Phase 3: HOTSPOT PRIORITIZATION
  Focus on security-critical code: auth, crypto, input handling, SQL, file ops.
  Run SAST tools against hotspots.
  Output: Ranked list of security-critical files and findings.
       │
       ▼
Phase 4: VERDICT GENERATION
  Assign a verdict to each module: Core Asset, Extract & Update, Rebuild, Deprecate.
  Produce the final audit report with remediation recommendations.
  Output: Actionable audit report.
```

### Time Allocation

For a medium-sized codebase (50k-200k lines of code):

| Phase | Time | Purpose |
|-------|------|---------|
| Surface Classification | 15% | Understand what you are auditing |
| Dependency Detection | 25% | Find known vulnerabilities |
| Hotspot Prioritization | 40% | Deep analysis of critical code |
| Verdict Generation | 20% | Synthesize findings into actions |

---

## 2. Phase 1: Attack Surface Classification

Before analyzing code for vulnerabilities, understand what code exists and how it is organized.

### File Type Inventory

```bash
# Count lines of code by language
cloc --by-file . --json > surface-cloc.json

# Summary view
cloc . --quiet
# Example output:
# Language          files     blank   comment      code
# Python             142      3200      1800     18500
# JavaScript          87      1500       900     12000
# HTML                23       200       100      3400
# YAML                15        80        40       600

# File extension breakdown
find . -type f -not -path './.git/*' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20
```

### Framework Detection

Identify the frameworks in use to focus on framework-specific vulnerability patterns:

```bash
# Python frameworks
grep -rl "from flask\|from django\|from fastapi\|from tornado" --include="*.py" . | head -5

# JavaScript frameworks
grep -rl "require('express')\|from 'next'\|from 'react'" --include="*.js" --include="*.ts" . | head -5

# Java frameworks
grep -rl "springframework\|javax.servlet\|io.quarkus" --include="*.java" . | head -5

# PHP frameworks
grep -rl "Illuminate\\\|Symfony\\\|CodeIgniter" --include="*.php" . | head -5
```

### Entry Point Mapping

Entry points are where external data enters the application. These are the highest-priority attack surface.

```bash
# API route definitions (Python/Flask)
grep -rn "@app.route\|@blueprint.route\|@router." --include="*.py" .

# API route definitions (Node/Express)
grep -rn "router.get\|router.post\|router.put\|router.delete\|app.get\|app.post" --include="*.js" --include="*.ts" .

# API route definitions (Java/Spring)
grep -rn "@GetMapping\|@PostMapping\|@RequestMapping\|@PutMapping\|@DeleteMapping" --include="*.java" .

# GraphQL endpoints
grep -rn "type Query\|type Mutation\|@Query\|@Mutation" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" .

# File upload handlers
grep -rn "upload\|multipart\|FormData\|multer\|FileField" --include="*.py" --include="*.js" --include="*.ts" .
```

### Third-Party Directory Detection

```bash
# Find vendored/third-party directories
find . -type d \( \
  -name "vendor" -o -name "node_modules" -o -name "third_party" \
  -o -name "external" -o -name "libs" -o -name "deps" \
  -o -name "packages" -o -name "bundle" -o -name "dist" \
  -o -name ".venv" -o -name "venv" -o -name "__pycache__" \
\) -prune

# Calculate third-party code ratio
total=$(cloc . --quiet --csv | tail -1 | cut -d',' -f5)
vendor=$(cloc vendor/ node_modules/ third_party/ --quiet --csv 2>/dev/null | tail -1 | cut -d',' -f5)
echo "Third-party ratio: $(( vendor * 100 / total ))%"
```

### Classification Output Template

```markdown
## Surface Classification Summary

| Category | Files | Lines | Percentage |
|----------|-------|-------|------------|
| Project Code | 142 | 18,500 | 55% |
| Third-Party (vendored) | 340 | 12,000 | 36% |
| Configuration | 15 | 600 | 2% |
| Test Code | 45 | 2,400 | 7% |

**Primary Language**: Python (55%)
**Frameworks**: Flask 2.x, SQLAlchemy, Celery
**Entry Points**: 47 API routes, 3 WebSocket handlers, 2 CLI commands
**Build System**: setuptools + Docker
```

---

## 3. Phase 2: Dependency Analysis Deep-Dive

Identify every third-party dependency, check for known vulnerabilities, and assess supply chain risk.

### Package Manager Audits

Run the native audit tool for each detected package manager:

```bash
# Node.js / npm
npm audit --json > audit-npm.json
npm audit --audit-level=high

# Node.js / yarn
yarn audit --json > audit-yarn.json

# Python / pip
pip-audit --format json --output audit-pip.json
# or with safety
safety check --json > audit-safety.json

# Go
go list -m all | nancy sleuth
# or
govulncheck ./...

# Rust
cargo audit --json > audit-cargo.json

# Ruby
bundle-audit check --update

# PHP / Composer
composer audit --format=json > audit-composer.json

# Java / Gradle
gradle dependencyCheckAnalyze
# Output: build/reports/dependency-check-report.html

# Java / Maven
mvn org.owasp:dependency-check-maven:check
```

### Trivy Filesystem Scan

Trivy scans all detected package managers and Dockerfiles in one pass:

```bash
# Full vulnerability scan
trivy fs --scanners vuln --format json --output trivy-report.json .

# High and critical only
trivy fs --scanners vuln --severity HIGH,CRITICAL .

# Include license scanning
trivy fs --scanners vuln,license .

# Scan a specific Dockerfile
trivy config Dockerfile
```

### Grype Deep Scan

Grype provides an alternative vulnerability database and can catch issues Trivy misses:

```bash
# Scan the project directory
grype dir:. --output json > grype-report.json

# Filter by severity
grype dir:. --fail-on high

# Scan a container image
grype docker:myapp:latest --output json > grype-image-report.json
```

### Snyk Integration

For projects with a Snyk account, run deeper analysis:

```bash
# Test project dependencies
snyk test --json > snyk-report.json

# Monitor for new vulnerabilities
snyk monitor

# Test a container image
snyk container test myapp:latest --json > snyk-container-report.json
```

### Embedded Library Detection

Not all third-party code is declared in package manifests. Detect vendored or copy-pasted libraries:

```bash
# Find version strings in vendored code
grep -rn "VERSION\|version\|__version__" vendor/ libs/ third_party/ 2>/dev/null

# Detect common libraries by signature
grep -rl "jQuery\|lodash\|moment\|axios" --include="*.js" . | grep -v node_modules

# Detect known library file hashes
find . -name "*.min.js" -exec md5sum {} \; | sort

# Check for outdated vendored copies
# Compare found versions against latest releases
```

### Dependency Analysis Output Template

```markdown
## Dependency Analysis Summary

**Total dependencies**: 187 (direct: 42, transitive: 145)
**Known vulnerabilities**: 12 (Critical: 2, High: 4, Medium: 6)

### Critical Vulnerabilities

| Package | Version | CVE | CVSS | Fix Available |
|---------|---------|-----|------|---------------|
| lodash | 4.17.15 | CVE-2021-23337 | 7.2 | Yes (4.17.21) |
| log4j-core | 2.14.1 | CVE-2021-44228 | 10.0 | Yes (2.17.1) |

### Vendored Libraries (Not in Package Manager)

| Library | Location | Version | Latest | CVEs |
|---------|----------|---------|--------|------|
| jQuery | vendor/js/jquery.min.js | 2.2.4 | 3.7.1 | 4 |
```

---

## 4. Phase 3: Security Hotspot Identification

Focus deep analysis on the code most likely to contain exploitable vulnerabilities.

### Authentication and Authorization

```bash
# Password handling
grep -rn "password\|passwd\|pwd\|credential" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" . | \
  grep -v "node_modules\|vendor\|test\|spec\|__pycache__"

# Session management
grep -rn "session\|cookie\|token\|jwt\|bearer\|oauth" \
  --include="*.py" --include="*.js" --include="*.ts" . | \
  grep -v "node_modules\|vendor\|test"

# Authentication bypass indicators
grep -rn "isAdmin\|is_admin\|role.*=\|privilege\|bypass\|skip.*auth" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" . | \
  grep -v "node_modules\|vendor\|test"
```

### Input Handling (Injection Vectors)

```bash
# SQL query construction (potential injection)
grep -rn "execute\|raw\|query\|cursor\|SELECT.*%s\|SELECT.*\+\|SELECT.*\$\|SELECT.*concat" \
  --include="*.py" --include="*.js" --include="*.java" --include="*.php" . | \
  grep -v "node_modules\|vendor\|test\|migration"

# Command execution
grep -rn "exec\|system\|popen\|subprocess\|child_process\|eval\|spawn" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.php" . | \
  grep -v "node_modules\|vendor\|test"

# File path construction (path traversal)
grep -rn "open(\|readFile\|writeFile\|path.join\|os.path\|include\|require" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.php" . | \
  grep -v "node_modules\|vendor\|test"

# Deserialization
grep -rn "pickle\|yaml.load\|json.loads\|unserialize\|readObject\|deserialize\|marshal" \
  --include="*.py" --include="*.js" --include="*.java" --include="*.php" . | \
  grep -v "node_modules\|vendor\|test"
```

### Cryptographic Usage

```bash
# Weak algorithms
grep -rn "md5\|sha1\|DES\|RC4\|ECB\|PKCS1v15" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" . | \
  grep -v "node_modules\|vendor\|test"

# Hardcoded keys and secrets
grep -rn "secret.*=.*['\"].*['\"]$\|key.*=.*['\"].*['\"]$\|password.*=.*['\"].*['\"]$" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" . | \
  grep -v "node_modules\|vendor\|test\|example\|template"

# Certificate validation
grep -rn "verify.*False\|verify.*false\|InsecureSkipVerify\|CERT_NONE\|rejectUnauthorized.*false" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" .
```

### Secret Detection

```bash
# TruffleHog - scan git history for leaked secrets
trufflehog git file://. --since-commit HEAD~200 --json > secrets-trufflehog.json

# Scan only the current filesystem (no git history)
trufflehog filesystem . --json > secrets-filesystem.json

# Gitleaks - pattern-based secret detection
gitleaks detect --source . --report-format json --report-path secrets-gitleaks.json

# Gitleaks - scan specific commits
gitleaks detect --source . --log-opts="HEAD~50..HEAD" --report-format json \
  --report-path secrets-recent.json

# Custom high-signal patterns
grep -rn "AKIA[0-9A-Z]\{16\}" .                    # AWS Access Key
grep -rn "ghp_[a-zA-Z0-9]\{36\}" .                  # GitHub PAT
grep -rn "sk-[a-zA-Z0-9]\{48\}" .                   # OpenAI API Key
grep -rn "xox[bpas]-[a-zA-Z0-9-]\+" .               # Slack Token
grep -rn "-----BEGIN.*PRIVATE KEY-----" .            # Private Keys
```

### Hotspot Ranking

After running all hotspot searches, rank files by the number of security-relevant hits:

```bash
# Count security-relevant grep matches per file
{
  grep -rl "password\|secret\|token\|credential" --include="*.py" --include="*.js" .
  grep -rl "execute\|query\|cursor" --include="*.py" --include="*.js" .
  grep -rl "exec\|system\|eval\|spawn" --include="*.py" --include="*.js" .
  grep -rl "open(\|readFile\|include" --include="*.py" --include="*.js" .
} | sort | uniq -c | sort -rn | head -20

# Output: files with the most security-relevant code, ranked by count
# These are your highest-priority targets for manual review
```

---

## 5. SAST Integration

Static Application Security Testing tools automate vulnerability detection. Run multiple tools for coverage.

### Semgrep

Semgrep is the most versatile SAST tool, supporting many languages with community and custom rules.

```bash
# Run with auto-detection (uses recommended rules per language)
semgrep --config=auto --json --output semgrep-report.json .

# Run OWASP Top 10 rules
semgrep --config "p/owasp-top-ten" --json --output semgrep-owasp.json .

# Run language-specific security rules
semgrep --config "p/python-security-audit" .
semgrep --config "p/javascript-security-audit" .
semgrep --config "p/java-security-audit" .

# Run with specific severity filter
semgrep --config=auto --severity ERROR --json .

# Custom rule for project-specific patterns
semgrep --config ./custom-rules/ .
```

### CodeQL

CodeQL performs deep dataflow analysis and catches complex vulnerabilities that pattern-based tools miss.

```bash
# Create a CodeQL database
codeql database create codeql-db --language=python --source-root=.

# Run security queries
codeql database analyze codeql-db \
  codeql/python-queries:codeql-suites/python-security-and-quality.qls \
  --format=csv --output=codeql-results.csv

# Run for JavaScript/TypeScript
codeql database create codeql-db-js --language=javascript --source-root=.
codeql database analyze codeql-db-js \
  codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls \
  --format=csv --output=codeql-js-results.csv
```

### Language-Specific SAST Tools

```bash
# Python: Bandit
bandit -r . -f json -o bandit-report.json --exclude ./.venv,./test
bandit -r . -ll  # Only high-severity and above

# Go: gosec
gosec -fmt json -out gosec-report.json ./...

# Ruby: Brakeman (Rails)
brakeman --format json --output brakeman-report.json

# PHP: phpstan + security rules
phpstan analyse --level max src/ --error-format json > phpstan-report.json

# Java: SpotBugs with FindSecBugs plugin
spotbugs -textui -effort:max -low -xml:withMessages -output spotbugs.xml build/classes/
```

### Correlating SAST Results

Different tools have different strengths. Cross-reference findings:

```bash
# Extract unique file:line pairs from semgrep
jq -r '.results[] | "\(.path):\(.start.line)"' semgrep-report.json | sort -u > semgrep-locations.txt

# Extract from bandit
jq -r '.results[] | "\(.filename):\(.line_number)"' bandit-report.json | sort -u > bandit-locations.txt

# Find locations flagged by multiple tools (high confidence)
comm -12 semgrep-locations.txt bandit-locations.txt
```

---

## 6. Phase 4: Generating Actionable Verdicts

Synthesize all findings into a prioritized, actionable report.

### Severity Scoring

Use the CVSS-like scoring framework adapted for code audit findings:

| Factor | Weight | Scoring |
|--------|--------|---------|
| Exploitability | 30% | How easy is it to exploit? (network vs local, auth required?) |
| Impact | 30% | What is the blast radius? (RCE, data leak, DoS?) |
| Confidence | 20% | How certain are we? (tool-confirmed, manual-verified, theoretical?) |
| Exposure | 20% | Is it internet-facing? In a critical path? |

Score each finding 1-10 on each factor, then compute the weighted total.

### Module Verdict Assignment

After analyzing all findings, assign a verdict to each module:

```markdown
| Module | Verdict | Rationale | Priority |
|--------|---------|-----------|----------|
| auth/ | Core Asset | Custom auth logic, 3 high-severity findings | CRITICAL |
| api/v2/ | Core Asset | 47 routes, handles user input, 5 SQL hotspots | HIGH |
| vendor/jwt/ | Extract & Update | Vendored JWT lib v1.2, 2 known CVEs | HIGH |
| utils/legacy/ | Deprecate | Unused module, 800 lines, no callers | MEDIUM |
| lib/cache/ | Rebuild | Duplicated Redis wrapper, race conditions | MEDIUM |
| scripts/ | Core Asset | Deployment scripts, hardcoded credentials | HIGH |
```

### Verdict Definitions

**Core Asset**: Custom business logic written by the project team. Requires deep manual security review. Cannot be replaced by a library.

**Extract and Update**: Third-party code that has been vendored or copy-pasted. Should be replaced with the official package managed through the dependency system. Check for CVEs in the vendored version.

**Rebuild**: Code that is structurally unsound (duplicated logic, race conditions, poor error handling) and should be rewritten using current security patterns.

**Deprecate**: Dead code, unused modules, or abandoned features. Should be removed entirely to reduce the attack surface.

### Remediation Prioritization

Order remediation by impact and effort:

```markdown
## Remediation Priority

### Immediate (This Sprint)
1. **Rotate exposed AWS keys** found in config/deploy.py (line 47)
2. **Update log4j** from 2.14.1 to 2.17.1 (CVE-2021-44228, CVSS 10.0)
3. **Fix SQL injection** in api/v2/search.py (line 112) - use parameterized queries

### Short-Term (Next 2 Sprints)
4. **Replace vendored JWT library** with managed dependency (2 known CVEs)
5. **Add input validation** to all 47 API routes (semgrep rule: python.flask.security)
6. **Enable CSRF protection** on state-changing endpoints

### Medium-Term (Next Quarter)
7. **Remove deprecated utils/legacy/ module** (800 lines of dead code)
8. **Rebuild cache layer** with proper locking (race condition risk)
9. **Implement secret management** (replace 12 hardcoded config values)
```

---

## 7. Automation with CI/CD Integration

Integrate repo-scan phases into the CI/CD pipeline for continuous security monitoring.

### GitHub Actions Example

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'HIGH,CRITICAL'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep Scan
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/security-audit

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for secret scanning

      - name: Gitleaks Secret Detection
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: TruffleHog Secret Scan
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
```

### Pre-Commit Hook Integration

Run lightweight checks on every commit, heavy scans in CI:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/semgrep/semgrep
    rev: v1.50.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/secrets', '--error']

  - repo: https://github.com/PyCQA/bandit
    rev: '1.7.7'
    hooks:
      - id: bandit
        args: ['-ll', '-q']
```

### Scan Result Aggregation Script

Combine results from multiple tools into a unified view:

```bash
#!/bin/bash
# aggregate-scan-results.sh
# Combine findings from Trivy, Semgrep, Bandit, and Gitleaks

echo "# Aggregated Security Scan Report"
echo "**Date**: $(date +%Y-%m-%d)"
echo ""

echo "## Dependency Vulnerabilities (Trivy)"
if [ -f trivy-report.json ]; then
  jq '.Results[].Vulnerabilities[]? | "\(.Severity): \(.PkgName) \(.InstalledVersion) - \(.VulnerabilityID)"' \
    trivy-report.json | sort | uniq -c | sort -rn
fi

echo ""
echo "## SAST Findings (Semgrep)"
if [ -f semgrep-report.json ]; then
  jq '.results[] | "\(.extra.severity): \(.check_id) at \(.path):\(.start.line)"' \
    semgrep-report.json | sort
fi

echo ""
echo "## Python Security (Bandit)"
if [ -f bandit-report.json ]; then
  jq '.results[] | "\(.issue_severity): \(.issue_text) at \(.filename):\(.line_number)"' \
    bandit-report.json | sort
fi

echo ""
echo "## Leaked Secrets (Gitleaks)"
if [ -f secrets-gitleaks.json ]; then
  jq '.[] | "\(.RuleID): \(.File):\(.StartLine)"' \
    secrets-gitleaks.json | sort
fi
```

---

## 8. Complete Audit Walkthrough

End-to-end example auditing a Python Flask application.

### Step 1: Clone and Classify

```bash
git clone https://github.com/example/target-app.git
cd target-app

# Phase 1: Surface classification
cloc . --quiet
find . -type f -not -path './.git/*' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -15

# Identify framework
grep -rl "from flask" --include="*.py" . | head -5
# Result: Flask application confirmed
```

### Step 2: Dependency Scan

```bash
# Phase 2: Dependency detection
pip-audit --format json --output audit-pip.json
trivy fs --scanners vuln --severity HIGH,CRITICAL .
grype dir:. --fail-on high
```

### Step 3: Hotspot Analysis

```bash
# Phase 3: Hotspot prioritization
# Map entry points
grep -rn "@app.route" --include="*.py" . | wc -l
# Result: 34 routes

# Find SQL hotspots
grep -rn "execute\|text(\|raw(" --include="*.py" . | grep -v "test\|migration"

# Find auth code
grep -rn "login\|authenticate\|session\|jwt" --include="*.py" . | grep -v test

# Run SAST
semgrep --config "p/python-security-audit" --json --output semgrep-flask.json .
bandit -r . -f json -o bandit-flask.json --exclude ./.venv,./tests
```

### Step 4: Secret Scan

```bash
# Check for leaked secrets
gitleaks detect --source . --report-format json --report-path secrets.json
trufflehog git file://. --since-commit HEAD~100 --json > secrets-history.json
```

### Step 5: Generate Verdicts

Review all tool outputs. Cross-reference findings. Assign module verdicts. Produce the final report using the template from the repo-scan SKILL.md.

```bash
# Count findings by severity across all tools
echo "=== Finding Summary ==="
echo "Trivy Critical: $(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' trivy-report.json)"
echo "Semgrep Errors: $(jq '[.results[] | select(.extra.severity=="ERROR")] | length' semgrep-flask.json)"
echo "Bandit High: $(jq '[.results[] | select(.issue_severity=="HIGH")] | length' bandit-flask.json)"
echo "Secrets Found: $(jq '. | length' secrets.json)"
```

---

## Integration Notes

This workflow implements the four-phase methodology described in `skills/repo-scan/SKILL.md`. It integrates with:

- **search-first**: Before building custom scanning rules, search for existing semgrep rules and CodeQL queries
- **security-review**: Consumes repo-scan output for targeted manual review of high-priority findings
- **terminal-ops**: Evidence capture protocol applies to all scan outputs
- **continuous-learning**: Patterns discovered during audits feed back into the knowledge base
