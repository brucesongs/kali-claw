# Repository Scan — Payloads & Commands

> Companion to `SKILL.md`. Contains repository scanning commands, classification scripts, and analysis payloads organized by scan phase.

---

## Quick Start Checklist

```
1. Surface classify → 2. Library detect → 3. Hotspot grep → 4. Secret scan → 5. Verdict
```

---

## Phase 1: Surface Classification Commands

### File Type Inventory

```bash
# Count files by extension
find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -30

# Lines of code by language
cloc --by-file . --json --quiet

# Directory structure overview (depth 3)
find . -type d -not -path '*/\.*' | head -50 | sort

# Identify large files (>1MB, potential binary blobs)
find . -type f -size +1M -exec ls -lh {} \; | awk '{print $5, $9}' | sort -rh
```

### Third-Party Directory Detection

```bash
# Common vendored dependency directories
find . -type d \( \
  -name "vendor" -o -name "node_modules" -o -name "third_party" \
  -o -name "external" -o -name "libs" -o -name "deps" \
  -o -name "Pods" -o -name ".venv" -o -name "packages" \
  -o -name "submodules" -o -name "contrib" \
\) -prune -print

# Package manager lock files (indicate managed dependencies)
find . -type f \( \
  -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \
  -name "Gemfile.lock" -o -name "poetry.lock" -o -name "Pipfile.lock" \
  -name "Cargo.lock" -o -name "go.sum" -o -name "composer.lock" \
\)

# Build artifact directories
find . -type d \( \
  -name "build" -o -name "dist" -o -name "out" -o -name "target" \
  -o -name "bin" -o -name "obj" -o -name "__pycache__" \
  -o -name ".gradle" -o -name ".mvn" \
\)
```

---

## Phase 2: Library Detection Commands

### Dependency Scanning

```bash
# Trivy filesystem scan (dependencies + misconfigs)
trivy fs --scanners vuln,misconfig --format json . | jq '.Results[] | {Target: .Target, Vulnerabilities: (.Vulnerabilities | length)}'

# Grype vulnerability matching
grype dir:. --output json | jq '.matches[] | {artifact: .artifact.name, version: .artifact.version, vuln: .vulnerability.id, severity: .vulnerability.severity}'

# Check specific ecosystem
trivy fs --scanners vuln --language <python|javascript|go|java|php|rust> .
```

### Embedded Library Identification

```bash
# Detect vendored libraries by known file patterns
grep -rl "Copyright.*All rights reserved" --include="*.js" --include="*.c" --include="*.h" . | head -20

# Check for vendored copy of known projects
find . -name "LICENSE" -exec sh -c 'echo "--- {} ---"; head -3 {}' \;

# Identify library version strings
grep -rn "version.*[0-9]\+\.[0-9]\+\.[0-9]\+" --include="*.js" --include="*.py" --include="*.h" . \
  | grep -i "jquery\|angular\|react\|lodash\|bootstrap\|openssl\|sqlite\|zlib" | head -20

# Python vendored packages detection
find . -path "*/vendor/*" -name "__init__.py" -exec dirname {} \; | sort -u
```

---

## Phase 3: Security Hotspot Grep Patterns

### Authentication & Session Code

```bash
# Password handling
grep -rn "password\|passwd\|pwd\|secret\|token\|api_key\|apikey" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.php" --include="*.go" . \
  | grep -v "node_modules\|vendor\|\.min\." | head -40

# Authentication flows
grep -rn "auth\|login\|session\|cookie\|jwt\|oauth\|saml" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" . \
  | grep -v "node_modules\|vendor\|test" | head -40

# Encryption and hashing
grep -rn "encrypt\|decrypt\|hash\|sha[0-9]\|md5\|aes\|rsa\|hmac\|bcrypt\|scrypt" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" . \
  | grep -v "node_modules\|vendor\|\.lock" | head -30
```

### Database & Query Code

```bash
# SQL interaction points
grep -rn "query\|execute\|cursor\|select.*from\|insert.*into\|update.*set\|delete.*from" \
  --include="*.py" --include="*.php" --include="*.java" --include="*.go" . \
  | grep -v "node_modules\|vendor\|test\|migration" | head -40

# ORM usage patterns
grep -rn "sequelize\|sqlalchemy\|django\.db\|typeorm\|prisma\|gorm\|hibernate" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" . \
  | grep -v "node_modules\|vendor" | head -30

# NoSQL interaction
grep -rn "mongo\|redis\|couch\|cassandra\|dynamodb" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" . \
  | grep -v "node_modules\|vendor\|config\|\.lock" | head -30
```

### File Operations & Deserialization

```bash
# File read/write operations
grep -rn "open(\|readfile\|file_get_contents\|FileInputStream\|os\.ReadFile\|upload\|download" \
  --include="*.py" --include="*.php" --include="*.java" --include="*.go" . \
  | grep -v "node_modules\|vendor\|test" | head -30

# Dangerous deserialization
grep -rn "pickle\.load\|yaml\.load\|unserialize\|ObjectInputStream\|json\.parse.*reviver" \
  --include="*.py" --include="*.php" --include="*.java" --include="*.js" . \
  | grep -v "node_modules\|vendor\|test" | head -20

# Command execution
grep -rn "system(\|exec(\|os\.popen\|subprocess\.\|Runtime\.exec\|child_process" \
  --include="*.py" --include="*.php" --include="*.java" --include="*.js" --include="*.go" . \
  | grep -v "node_modules\|vendor\|test" | head -30
```

---

## Phase 4: Secret Scanning Commands

### Git History Secret Scan

```bash
# TruffleHog — scan git history for secrets
trufflehog git file://. --since-commit HEAD~500 --json

# Gitleaks — detect secrets in repo
gitleaks detect --source . --report-format json --report-path gitleaks-report.json

# Search for high-entropy strings (potential secrets)
grep -rn "[A-Za-z0-9+/]{40,}" --include="*.py" --include="*.js" --include="*.ts" --include="*.env" --include="*.yml" --include="*.json" . \
  | grep -v "node_modules\|vendor\|\.lock\|\.map" | head -30
```

### Common Secret Patterns

```bash
# AWS keys
grep -rn "AKIA[0-9A-Z]{16}" --include="*.py" --include="*.js" --include="*.env" --include="*.yml" .

# GitHub tokens
grep -rn "gh[pousr]_[A-Za-z0-9_]{36,255}" --include="*.py" --include="*.js" --include="*.env" --include="*.yml" .

# Private keys
grep -rn "-----BEGIN.*PRIVATE KEY-----" .

# Generic API key patterns
grep -rn -E "(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][^'\"]{10,}" \
  --include="*.py" --include="*.js" --include="*.env" --include="*.yml" --include="*.json" . \
  | grep -v "node_modules\|vendor\|test\|example\|sample"
```

---

## Phase 5: Verdict Decision Aid

### Automated Verdict Suggestions

```bash
# Count custom vs vendored code lines
echo "=== Custom Code ===" && cloc --not-match-d="vendor|node_modules|Pods|third_party|external" . --quiet
echo "=== Vendored Code ===" && cloc --match-d="vendor|node_modules|Pods|third_party|external" . --quiet

# Identify dead code (unreferenced files)
# Python: find modules not imported elsewhere
for f in $(find . -name "*.py" -not -path "*/vendor/*" -not -path "*/node_modules/*" -not -name "__init__.py"); do
  module=$(echo "$f" | sed 's|\.py$||;s|/|.|g;s|^\.||;s|^\.||')
  if ! grep -rq "$module\|$(basename $f .py)" --include="*.py" . --exclude="$f" 2>/dev/null; then
    echo "UNREFERENCED: $f"
  fi
done

# Find duplicate code blocks
find . -name "*.py" -not -path "*/vendor/*" | while read f; do
  md5sum "$f"
done | awk '{print $1}' | sort | uniq -d | while read hash; do
  md5sum *.py 2>/dev/null | grep "$hash"
done
```

### Verdict Classification Table

| Signal | Verdict | Rationale |
|--------|---------|-----------|
| Custom business logic, processes user input | **Core Asset** | High security value, deep review needed |
| Vendored copy of library with package manager | **Extract & Update** | Replace with managed dependency, check CVEs |
| Duplicated utility code across modules | **Rebuild** | Consolidate into shared module with tests |
| No imports, no references, dead code | **Deprecate** | Remove to reduce attack surface |
| Configuration with hardcoded values | **Core Asset** | Review for secrets and misconfigurations |
| Test fixtures with mock data | **Review** | Ensure no real PII/secrets in test data |

---

## Cross-Stack Quick Reference

| Stack | Key Files | One-Liner Scan |
|-------|-----------|---------------|
| JavaScript | `package.json` | `cat package.json \| jq '.dependencies'` |
| Python | `requirements.txt`, `Pipfile` | `pip-audit -r requirements.txt` |
| Java | `pom.xml`, `build.gradle` | `grep -E "<dependency|implementation" pom.xml build.gradle` |
| Go | `go.mod` | `go list -m all \| nancy sleuth` |
| PHP | `composer.json` | `composer audit` |
| Rust | `Cargo.toml` | `cargo audit` |
| Docker | `Dockerfile` | `trivy config Dockerfile` |
| Terraform | `*.tf` | `trivy conf .` |

---

## Phase 6: Advanced Secret Detection

### TruffleHog Deep Scanning

```bash
# Scan entire git history with verified-only results
trufflehog git file://. --only-verified --json | jq '{detector: .DetectorName, raw: .Raw, source: .SourceMetadata}'

# Scan specific branches for secrets
trufflehog git file://. --branch develop --since-commit HEAD~1000 --json

# Scan remote repositories without cloning
trufflehog github --org target-org --token "$GITHUB_TOKEN" --json

# Scan filesystem (non-git) with entropy analysis
trufflehog filesystem --directory /path/to/code --json | jq 'select(.Raw != "") | {type: .DetectorName, file: .SourceMetadata.Data.Filesystem.file}'
```

### Gitleaks Custom Rules

```bash
# Run gitleaks with custom config
gitleaks detect --source . --config custom-gitleaks.toml --report-format sarif --report-path results.sarif

# Scan only staged changes (pre-commit use)
gitleaks protect --staged --config custom-gitleaks.toml

# Scan specific commits range
gitleaks detect --source . --log-opts="--since=2024-01-01" --report-format json --report-path secrets.json

# Baseline mode — ignore known false positives
gitleaks detect --source . --baseline-path .gitleaks-baseline.json --report-format json --report-path new-secrets.json
```

### Custom Gitleaks Configuration

```yaml
# custom-gitleaks.toml — extended rules
title = "Custom Secret Detection Rules"

[[rules]]
id = "internal-api-key"
description = "Internal API Key Pattern"
regex = '''(?i)(internal[_-]?api[_-]?key|int[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9\-_]{20,})['"]'''
tags = ["internal", "api-key"]

[[rules]]
id = "database-connection-string"
description = "Database Connection String"
regex = '''(?i)(mongodb|postgres|mysql|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+'''
tags = ["database", "credential"]

[[rules]]
id = "jwt-token"
description = "JWT Token"
regex = '''eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'''
tags = ["jwt", "token"]

[[rules]]
id = "slack-webhook"
description = "Slack Webhook URL"
regex = '''https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'''
tags = ["slack", "webhook"]

[allowlist]
paths = [
  '''(.*?)test(.*?)''',
  '''(.*?)mock(.*?)''',
  '''vendor/''',
  '''node_modules/'''
]
```

### High-Entropy String Detection

```bash
# Custom entropy scanner — find base64/hex strings likely to be secrets
find . -type f \( -name "*.env" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.conf" -o -name "*.cfg" \) \
  -not -path "*/node_modules/*" -not -path "*/vendor/*" | while read f; do
  grep -nP '[A-Za-z0-9+/=]{40,}' "$f" 2>/dev/null | while read line; do
    entropy=$(echo "$line" | awk -F'[=:]' '{print $NF}' | tr -d ' "'"'" | python3 -c "
import sys, math, collections
s = sys.stdin.read().strip()
if len(s) > 10:
    freq = collections.Counter(s)
    entropy = -sum((c/len(s)) * math.log2(c/len(s)) for c in freq.values())
    if entropy > 4.5: print(f'HIGH_ENTROPY ({entropy:.2f}): {s[:60]}')
" 2>/dev/null)
    [ -n "$entropy" ] && echo "$f: $entropy"
  done
done

# Detect hardcoded IPs and internal URLs
grep -rn -E "(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.yml" --include="*.json" . \
  | grep -v "node_modules\|vendor\|\.lock" | head -30
```

---

## Phase 7: Infrastructure-as-Code Scanning

### Terraform Security Scanning (tfsec / trivy)

```bash
# tfsec — Terraform static analysis
tfsec . --format json --out tfsec-results.json
tfsec . --format sarif --out tfsec.sarif

# tfsec with custom checks
tfsec . --custom-check-dir ./custom-checks --minimum-severity HIGH

# Trivy IaC scanning for Terraform
trivy config --severity HIGH,CRITICAL --format json --output trivy-iac.json .

# Scan specific Terraform modules
trivy config --tf-vars terraform.tfvars --severity MEDIUM,HIGH,CRITICAL ./modules/
```

### Checkov Multi-Framework Scanning

```bash
# Checkov — scan all supported IaC frameworks
checkov -d . --output json --output-file checkov-results.json

# Scan specific framework
checkov -d . --framework terraform --check CKV_AWS_18,CKV_AWS_21 --compact

# Checkov with custom policies
checkov -d . --external-checks-dir ./custom-policies --soft-fail-on LOW

# Scan Kubernetes manifests
checkov -d ./k8s/ --framework kubernetes --output sarif

# Scan CloudFormation templates
checkov -f cloudformation-template.yaml --framework cloudformation
```

### KICS (Keeping Infrastructure as Code Secure)

```bash
# KICS full scan
kics scan -p . -o kics-results/ --report-formats "json,sarif" --type "Terraform,Kubernetes,Docker,CloudFormation"

# KICS with severity filter
kics scan -p ./terraform/ --type Terraform --exclude-severities info,low --ci

# KICS scan Helm charts
kics scan -p ./charts/ --type Kubernetes --exclude-queries "CIS Benchmark"

# KICS with custom queries
kics scan -p . --queries-path ./custom-queries/ --exclude-paths "test/,vendor/"
```

### Kubernetes Manifest Security

```bash
# kubesec — risk scoring for K8s resources
find . -name "*.yaml" -path "*/k8s/*" -exec kubesec scan {} \; | jq '.[] | {object: .object, score: .score, critical: [.scoring.critical[].reason]}'

# kube-linter — check K8s YAML for best practices
kube-linter lint ./k8s/ --config .kube-linter.yaml --format json

# Polaris audit for K8s manifests
polaris audit --audit-path ./k8s/ --format json --only-show-failed-tests

# Detect privileged containers and host mounts
grep -rn "privileged: true\|hostNetwork: true\|hostPID: true\|hostIPC: true" --include="*.yaml" --include="*.yml" .
grep -rn "hostPath:" --include="*.yaml" --include="*.yml" . | grep -v "#"
```

---

## Phase 8: Container Image Scanning

### Trivy Container Scanning

```bash
# Scan a Docker image for vulnerabilities
trivy image --severity HIGH,CRITICAL --format json target-image:latest

# Scan Dockerfile for misconfigurations
trivy config --file-patterns "dockerfile:Dockerfile*" .

# Scan image with SBOM generation
trivy image --format cyclonedx --output sbom.json target-image:latest

# Scan local image tarball
docker save target-image:latest -o image.tar
trivy image --input image.tar --severity CRITICAL --format table
```

### Grype Image Analysis

```bash
# Grype vulnerability scan on image
grype target-image:latest --output json | jq '.matches[] | select(.vulnerability.severity == "Critical") | {pkg: .artifact.name, version: .artifact.version, vuln: .vulnerability.id, fix: .vulnerability.fix.versions}'

# Grype scan from SBOM
syft target-image:latest -o spdx-json > sbom-spdx.json
grype sbom:sbom-spdx.json --output table

# Grype with custom vulnerability database
grype db update
grype dir:. --add-cpes-if-none --output json

# Scan all images in docker-compose
grep -oP 'image:\s*\K[^\s]+' docker-compose.yml | while read img; do
  echo "=== Scanning: $img ==="
  grype "$img" --output table --only-fixed
done
```

### Dockerfile Security Audit

```bash
# Hadolint — Dockerfile linter
hadolint Dockerfile --format json | jq '.[] | {line: .line, code: .code, message: .message, level: .level}'

# Find Dockerfiles running as root
grep -rn "^USER" --include="Dockerfile*" . || echo "WARNING: No USER directive found — container runs as root"

# Detect use of latest tag
grep -rn "FROM.*:latest\|FROM.*[^:]*$" --include="Dockerfile*" .

# Check for secrets in Docker build layers
docker history --no-trunc target-image:latest | grep -iE "env|arg|secret|key|token|password"

# Scan multi-stage build for leaked secrets
grep -n "COPY --from\|ARG\|ENV" Dockerfile | grep -iE "secret|key|token|pass"
```

### Container Runtime Security

```bash
# Dive — analyze image layers for efficiency and secrets
dive target-image:latest --ci --highestWastedBytes 50MB --lowestEfficiency 0.9

# Check for SUID binaries in image
docker run --rm --entrypoint="" target-image:latest find / -perm -4000 -type f 2>/dev/null

# List installed packages in image
docker run --rm --entrypoint="" target-image:latest sh -c "apk list --installed 2>/dev/null || dpkg -l 2>/dev/null || rpm -qa 2>/dev/null"

# Check for writable sensitive paths
docker run --rm --entrypoint="" target-image:latest find /etc /usr/bin /usr/sbin -writable -type f 2>/dev/null
```

---

## Phase 9: License Compliance Scanning

### LicenseFinder Analysis

```bash
# LicenseFinder — detect all dependency licenses
license_finder --format json > license-report.json

# Check for copyleft/restricted licenses
license_finder --decisions-file ./license-decisions.yml action_items | grep -iE "GPL|AGPL|SSPL|EUPL|CPAL"

# Approve specific licenses for the project
license_finder permitted_licenses add MIT
license_finder permitted_licenses add "Apache-2.0"
license_finder permitted_licenses add "BSD-2-Clause"
license_finder permitted_licenses add "BSD-3-Clause"

# Generate compliance report
license_finder report --format html > license-compliance.html
```

### FOSSA-Style License Detection

```bash
# Scan package.json for license fields
cat package.json | jq '{dependencies: (.dependencies // {} | keys), devDependencies: (.devDependencies // {} | keys)}' | \
  jq -r '.dependencies[]' | while read pkg; do
    license=$(npm view "$pkg" license 2>/dev/null)
    echo "$pkg: $license"
  done

# Python license extraction
pip-licenses --format json --with-urls --with-description | jq '.[] | {Name, License, URL}'

# Go module license check
go-licenses csv ./... 2>/dev/null | column -t -s,

# Detect SPDX identifiers in source files
grep -rn "SPDX-License-Identifier:" --include="*.go" --include="*.py" --include="*.js" --include="*.rs" . | sort -t: -k3
```

### License Risk Assessment

```bash
# Categorize licenses by risk level
cat license-report.json | jq -r '.[] | "\(.license) \(.name)"' | sort | while read license pkg; do
  case "$license" in
    *GPL*|*AGPL*|*SSPL*) echo "HIGH-RISK: $pkg ($license)" ;;
    *LGPL*|*MPL*|*EPL*) echo "MEDIUM-RISK: $pkg ($license)" ;;
    *MIT*|*BSD*|*Apache*|*ISC*) echo "LOW-RISK: $pkg ($license)" ;;
    *) echo "UNKNOWN: $pkg ($license)" ;;
  esac
done

# Find files without license headers
find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.go" -o -name "*.java" \) \
  -not -path "*/vendor/*" -not -path "*/node_modules/*" | while read f; do
  head -5 "$f" | grep -qiE "license|copyright|SPDX" || echo "MISSING HEADER: $f"
done
```

---

## Phase 10: Code Quality Security Metrics

### Semgrep Custom Security Rules

```bash
# Semgrep — run OWASP Top 10 rules
semgrep scan --config "p/owasp-top-ten" --json --output semgrep-owasp.json .

# Semgrep with multiple rulesets
semgrep scan --config "p/security-audit" --config "p/secrets" --config "p/default" --severity ERROR --json .

# Semgrep scan specific languages
semgrep scan --config "p/python" --config "p/flask" --lang python --json .

# Run custom semgrep rules from file
semgrep scan --config ./custom-rules.yaml --json --output custom-findings.json .
```

### Custom Semgrep Rule Definitions

```yaml
# custom-rules.yaml — project-specific security rules
rules:
  - id: hardcoded-database-credentials
    patterns:
      - pattern: |
          $DB.connect($URL, ...)
      - metavariable-regex:
          metavariable: $URL
          regex: ".*(password|passwd|pwd).*"
    message: "Database connection with hardcoded credentials detected"
    severity: ERROR
    languages: [python, javascript, typescript]

  - id: unsafe-yaml-load
    pattern: yaml.load($X)
    fix: yaml.safe_load($X)
    message: "Use yaml.safe_load() instead of yaml.load() to prevent code execution"
    severity: ERROR
    languages: [python]

  - id: missing-rate-limit
    patterns:
      - pattern: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @limiter.limit(...)
          @app.route(...)
          def $FUNC(...):
              ...
    message: "API endpoint missing rate limiting"
    severity: WARNING
    languages: [python]

  - id: sql-string-concat
    patterns:
      - pattern: |
          $QUERY = "..." + $INPUT + "..."
      - metavariable-regex:
          metavariable: $QUERY
          regex: ".*(SELECT|INSERT|UPDATE|DELETE|DROP).*"
    message: "SQL query built with string concatenation — use parameterized queries"
    severity: ERROR
    languages: [python, javascript, typescript, java]
```

### CodeQL Query Patterns

```bash
# Initialize CodeQL database
codeql database create codeql-db --language=python --source-root=.

# Run security queries
codeql database analyze codeql-db codeql/python-queries:Security --format=sarif-latest --output=codeql-results.sarif

# Run specific CWE queries
codeql database analyze codeql-db \
  codeql/python-queries:Security/CWE-078 \
  codeql/python-queries:Security/CWE-089 \
  codeql/python-queries:Security/CWE-079 \
  --format=csv --output=cwe-findings.csv

# Custom CodeQL query for taint tracking
codeql query run --database=codeql-db ./custom-queries/taint-analysis.ql
```

### Bandit and Safety (Python-Specific)

```bash
# Bandit — Python security linter
bandit -r . -f json -o bandit-results.json --exclude ./tests,./venv -ll

# Bandit with specific tests
bandit -r . -t B101,B102,B103,B104,B105,B106,B107,B108,B110 -f json

# Safety — check Python dependencies for known vulnerabilities
safety check --json --full-report -r requirements.txt

# pip-audit — modern alternative to safety
pip-audit --format json --output pip-audit.json -r requirements.txt
```

---

## Phase 11: CI/CD Pipeline Security Audit

### GitHub Actions Security Review

```bash
# Find all GitHub Actions workflow files
find .github/workflows -name "*.yml" -o -name "*.yaml" | while read f; do
  echo "=== $f ==="
  # Check for dangerous patterns
  grep -n "pull_request_target" "$f" && echo "  WARNING: pull_request_target can expose secrets to forks"
  grep -n "workflow_dispatch" "$f" && echo "  INFO: Manual trigger enabled"
  grep -n "\${{.*github\.event\." "$f" && echo "  WARNING: Potential injection via event context"
done

# Detect unpinned actions (supply chain risk)
grep -rn "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}" | grep -v "@v[0-9]" | head -20

# Check for secrets in workflow files
grep -rn "password\|secret\|token\|key" .github/workflows/ | grep -v "\${{.*secrets\." | grep -v "#"

# Detect overly permissive permissions
grep -A5 "permissions:" .github/workflows/*.yml | grep -E "write-all|contents: write|packages: write"
```

### GitHub Actions Injection Detection

```bash
# Detect expression injection vulnerabilities
grep -rn '\${{.*github\.event\.(issue|pull_request|comment)\..*}}' .github/workflows/ | \
  grep -v "if:" | grep -v "#"

# Check for unsafe run commands with user-controlled input
grep -B2 -A5 "run:" .github/workflows/*.yml | grep -E '\$\{\{.*title|body|head_ref|comment'

# Audit third-party action versions
grep -rn "uses:" .github/workflows/ | awk -F'uses: ' '{print $2}' | sort -u | while read action; do
  owner=$(echo "$action" | cut -d'/' -f1)
  repo=$(echo "$action" | cut -d'/' -f2 | cut -d'@' -f1)
  ref=$(echo "$action" | cut -d'@' -f2)
  echo "$owner/$repo @ $ref"
  # Flag if not pinned to SHA
  echo "$ref" | grep -qE "^[a-f0-9]{40}$" || echo "  NOT SHA-PINNED"
done

# Check for GITHUB_TOKEN permissions escalation
grep -rn "GITHUB_TOKEN\|github\.token" .github/workflows/ | grep -v "secrets\.GITHUB_TOKEN"
```

### GitLab CI Security Checks

```bash
# Scan .gitlab-ci.yml for security issues
grep -n "allow_failure: true" .gitlab-ci.yml && echo "WARNING: Security jobs may be allowed to fail"

# Check for exposed variables
grep -rn "variables:" .gitlab-ci.yml | grep -v "CI_\|DOCKER_\|GIT_"

# Detect unprotected deployment stages
grep -B5 -A10 "deploy" .gitlab-ci.yml | grep -v "only:\|rules:\|when: manual"

# Check for insecure script patterns
grep -A20 "script:" .gitlab-ci.yml | grep -E "curl.*\|.*sh|wget.*\|.*bash|eval "
```

### Pipeline Secret Exposure Detection

```bash
# Check if CI configs echo or print secrets
grep -rn "echo\|print\|printf\|cat" .github/workflows/ .gitlab-ci.yml 2>/dev/null | \
  grep -iE "secret|token|key|password|credential"

# Detect secrets passed as command-line arguments (visible in process list)
grep -rn "\-\-password\|\-\-token\|\-\-secret\|\-p " .github/workflows/ .gitlab-ci.yml Jenkinsfile 2>/dev/null

# Check for artifacts that might contain secrets
grep -A5 "artifacts:" .github/workflows/*.yml .gitlab-ci.yml 2>/dev/null | grep -E "path:|name:"

# Audit environment variable usage
grep -rn "env:" .github/workflows/*.yml | grep -v "secrets\." | grep -iE "key|token|secret|pass"
```

---

## Phase 12: Pre-commit Hook Security

### Pre-commit Framework Setup

```bash
# Install pre-commit and initialize
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg

# Run all hooks against entire repo
pre-commit run --all-files

# Update hooks to latest versions
pre-commit autoupdate

# Run specific hook
pre-commit run gitleaks --all-files
pre-commit run detect-private-key --all-files
```

### Security-Focused Pre-commit Configuration

```yaml
# .pre-commit-config.yaml — security hooks
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master']

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/returntocorp/semgrep
    rev: v1.50.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/secrets', '--error']

  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
        entry: hadolint

  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.83.0
    hooks:
      - id: terraform_tfsec
      - id: terraform_checkov
```

### Custom Git Hooks for Secret Prevention

```bash
#!/bin/bash
# .git/hooks/pre-commit — custom secret detection hook

echo "[pre-commit] Scanning for secrets..."

# Patterns that should never be committed
FORBIDDEN_PATTERNS=(
  "AKIA[0-9A-Z]{16}"                          # AWS Access Key
  "-----BEGIN.*PRIVATE KEY-----"               # Private keys
  "ghp_[A-Za-z0-9_]{36}"                      # GitHub PAT
  "sk-[A-Za-z0-9]{48}"                        # OpenAI API key
  "xox[baprs]-[A-Za-z0-9-]+"                  # Slack tokens
  "AIza[0-9A-Za-z_-]{35}"                     # Google API key
  "mongodb\+srv://[^:]+:[^@]+@"               # MongoDB connection string
  "postgres://[^:]+:[^@]+@"                   # PostgreSQL connection string
)

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
VIOLATIONS=0

for file in $STAGED_FILES; do
  for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
    matches=$(grep -nP "$pattern" "$file" 2>/dev/null)
    if [ -n "$matches" ]; then
      echo "BLOCKED: Potential secret in $file"
      echo "  Pattern: $pattern"
      echo "  $matches"
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done
done

if [ $VIOLATIONS -gt 0 ]; then
  echo ""
  echo "Commit blocked: $VIOLATIONS potential secret(s) detected."
  echo "Use 'git diff --cached' to review staged changes."
  echo "If false positive, add to .gitallowed or use SKIP=secret-scan git commit"
  exit 1
fi

echo "[pre-commit] No secrets detected."
exit 0
```

### Detect-Secrets Baseline Management

```bash
# Initialize secrets baseline
detect-secrets scan --all-files > .secrets.baseline

# Audit baseline for false positives
detect-secrets audit .secrets.baseline

# Update baseline after adding new files
detect-secrets scan --baseline .secrets.baseline

# Scan only staged files
git diff --cached --name-only | xargs detect-secrets scan --list-all-plugins

# Custom plugin configuration
detect-secrets scan --all-files \
  --disable-plugin KeywordDetector \
  --disable-plugin HexHighEntropyString \
  > .secrets.baseline
```

---

## Phase 13: Automated Remediation Patterns

### Dependency Update Automation

```bash
# Generate dependency update PRs with Renovate (local mode)
npx renovate --platform=local --dry-run

# npm audit with auto-fix
npm audit fix --force 2>&1 | tee npm-audit-fix.log
npm audit fix --dry-run --json | jq '.actions[] | {module: .module, resolves: [.resolves[].id]}'

# Python dependency updates with safety
pip-audit --fix --dry-run -r requirements.txt
pip-audit --fix -r requirements.txt 2>&1 | tee pip-fix.log

# Go vulnerability fix
govulncheck ./...
go get -u ./...
go mod tidy
```

### Auto-Fix Scripts for Common Vulnerabilities

```bash
#!/bin/bash
# auto-remediate.sh — fix common security findings

# Fix 1: Replace yaml.load with yaml.safe_load (Python)
find . -name "*.py" -not -path "*/vendor/*" -exec \
  sed -i 's/yaml\.load(\([^,)]*\))/yaml.safe_load(\1)/g' {} \;

# Fix 2: Add CSRF protection to Flask apps
grep -rl "from flask import" --include="*.py" . | while read f; do
  if ! grep -q "CSRFProtect\|csrf" "$f"; then
    echo "NEEDS CSRF: $f"
  fi
done

# Fix 3: Replace HTTP with HTTPS in URLs
find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.yml" \) \
  -not -path "*/vendor/*" -not -path "*/node_modules/*" \
  -exec grep -l "http://" {} \; | while read f; do
  sed -i 's|http://|https://|g' "$f"
  echo "FIXED HTTP->HTTPS: $f"
done

# Fix 4: Pin Docker base image tags
find . -name "Dockerfile*" -exec sh -c '
  if grep -qE "^FROM .+:latest" "$1"; then
    echo "NEEDS PINNING: $1"
    # Get current digest for pinning
    img=$(grep -oP "^FROM \K[^:]+:latest" "$1" | head -1)
    digest=$(docker inspect --format="{{index .RepoDigests 0}}" "$img" 2>/dev/null)
    [ -n "$digest" ] && echo "  Pin to: $digest"
  fi
' _ {} \;
```

### PR Generation for Vulnerability Fixes

```bash
#!/bin/bash
# generate-security-pr.sh — create PR with security fixes

BRANCH="security/auto-fix-$(date +%Y%m%d)"
BASE_BRANCH="main"

git checkout -b "$BRANCH"

# Run automated fixes
echo "Running automated security fixes..."

# Update vulnerable dependencies
npm audit fix 2>/dev/null
pip-audit --fix -r requirements.txt 2>/dev/null

# Run semgrep autofix
semgrep scan --config "p/security-audit" --autofix --json > /tmp/semgrep-fixes.json

# Stage and commit changes
git add -A
FIXES=$(cat /tmp/semgrep-fixes.json | jq '.results | length' 2>/dev/null || echo "0")

git commit -m "fix: automated security remediation

- Updated vulnerable dependencies
- Applied semgrep autofix rules ($FIXES findings)
- Generated by auto-remediation pipeline"

# Push and create PR
git push -u origin "$BRANCH"
gh pr create \
  --title "Security: Automated vulnerability remediation" \
  --body "## Automated Security Fixes

### Changes
- Dependency updates (npm audit fix / pip-audit)
- Semgrep autofix applied ($FIXES findings)

### Verification
- [ ] CI passes
- [ ] No functional regressions
- [ ] Manual review of changes

Generated by \`generate-security-pr.sh\`" \
  --base "$BASE_BRANCH" \
  --label "security,automated"
```

### Scheduled Scan and Report Generation

```bash
#!/bin/bash
# scheduled-security-scan.sh — comprehensive repo security report

REPORT_DIR="./security-reports/$(date +%Y-%m-%d)"
mkdir -p "$REPORT_DIR"

echo "=== Repository Security Scan Report ===" | tee "$REPORT_DIR/summary.txt"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$REPORT_DIR/summary.txt"
echo "" | tee -a "$REPORT_DIR/summary.txt"

# Secret scan
echo "[1/6] Secret scanning..." | tee -a "$REPORT_DIR/summary.txt"
gitleaks detect --source . --report-format json --report-path "$REPORT_DIR/secrets.json" 2>/dev/null
SECRETS=$(cat "$REPORT_DIR/secrets.json" | jq 'length' 2>/dev/null || echo "0")
echo "  Secrets found: $SECRETS" | tee -a "$REPORT_DIR/summary.txt"

# Dependency vulnerabilities
echo "[2/6] Dependency scanning..." | tee -a "$REPORT_DIR/summary.txt"
trivy fs --scanners vuln --format json --output "$REPORT_DIR/dependencies.json" . 2>/dev/null
VULNS=$(cat "$REPORT_DIR/dependencies.json" | jq '[.Results[].Vulnerabilities // [] | length] | add' 2>/dev/null || echo "0")
echo "  Vulnerabilities: $VULNS" | tee -a "$REPORT_DIR/summary.txt"

# IaC misconfigurations
echo "[3/6] IaC scanning..." | tee -a "$REPORT_DIR/summary.txt"
trivy config --format json --output "$REPORT_DIR/iac.json" . 2>/dev/null
MISCONFIGS=$(cat "$REPORT_DIR/iac.json" | jq '[.Results[].Misconfigurations // [] | length] | add' 2>/dev/null || echo "0")
echo "  Misconfigurations: $MISCONFIGS" | tee -a "$REPORT_DIR/summary.txt"

# SAST findings
echo "[4/6] SAST scanning..." | tee -a "$REPORT_DIR/summary.txt"
semgrep scan --config "p/security-audit" --json --output "$REPORT_DIR/sast.json" . 2>/dev/null
SAST=$(cat "$REPORT_DIR/sast.json" | jq '.results | length' 2>/dev/null || echo "0")
echo "  SAST findings: $SAST" | tee -a "$REPORT_DIR/summary.txt"

# License compliance
echo "[5/6] License scanning..." | tee -a "$REPORT_DIR/summary.txt"
license_finder --format json > "$REPORT_DIR/licenses.json" 2>/dev/null
echo "  License report generated" | tee -a "$REPORT_DIR/summary.txt"

# Container scanning (if Dockerfiles exist)
echo "[6/6] Container scanning..." | tee -a "$REPORT_DIR/summary.txt"
find . -name "Dockerfile*" -exec trivy config --format json {} \; > "$REPORT_DIR/containers.json" 2>/dev/null
echo "  Container scan complete" | tee -a "$REPORT_DIR/summary.txt"

echo "" | tee -a "$REPORT_DIR/summary.txt"
echo "=== TOTALS ===" | tee -a "$REPORT_DIR/summary.txt"
echo "Secrets: $SECRETS | Vulns: $VULNS | Misconfigs: $MISCONFIGS | SAST: $SAST" | tee -a "$REPORT_DIR/summary.txt"
echo "Reports saved to: $REPORT_DIR" | tee -a "$REPORT_DIR/summary.txt"
```
