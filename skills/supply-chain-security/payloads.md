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
