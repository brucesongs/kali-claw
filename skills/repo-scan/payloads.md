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
