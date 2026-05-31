# Dependency and Supply Chain Analysis Guide

> Techniques for rapidly understanding a project's dependency tree, identifying security-relevant components, and assessing supply chain risk during codebase onboarding.

---

## 1. Dependency Tree Extraction

### Multi-Ecosystem Commands

```bash
# Node.js / npm
npm ls --all --json 2>/dev/null | jq '{dependencies: .dependencies | keys | length, total: [.. | .dependencies? // empty | keys[]] | length}'

# Python / pip
pip show -f <package> 2>/dev/null
pipdeptree --json | jq '.[].package.package_name'

# Go
go mod graph | head -20

# Rust
cargo tree --depth 2

# Java / Maven
mvn dependency:tree -DoutputType=dot 2>/dev/null | grep -v "^\[INFO\]"
```

### Quick Dependency Audit

```bash
# npm audit (Node.js)
npm audit --json | jq '{critical: .metadata.vulnerabilities.critical, high: .metadata.vulnerabilities.high, total: .metadata.vulnerabilities.total}'

# pip-audit (Python)
pip-audit --format=json 2>/dev/null | jq '[.[] | select(.fix_versions != [])] | length'

# cargo audit (Rust)
cargo audit --json 2>/dev/null | jq '.vulnerabilities.found'

# govulncheck (Go)
govulncheck ./... 2>&1 | grep -c "Vulnerability"
```

---

## 2. Security-Critical Dependency Identification

### High-Risk Categories

```python
HIGH_RISK_CATEGORIES = {
    "authentication": ["passport", "oauth", "jwt", "bcrypt", "argon2"],
    "cryptography": ["crypto", "openssl", "sodium", "tls"],
    "serialization": ["pickle", "yaml", "xml", "protobuf", "msgpack"],
    "network": ["requests", "axios", "fetch", "urllib", "httpx"],
    "database": ["sqlalchemy", "sequelize", "prisma", "mongoose"],
    "file_operations": ["fs-extra", "glob", "archiver", "tar"],
}

def identify_critical_deps(lockfile_deps: list[str]) -> dict:
    """Flag dependencies in security-critical categories."""
    flagged = {}
    for dep in lockfile_deps:
        dep_lower = dep.lower()
        for category, keywords in HIGH_RISK_CATEGORIES.items():
            if any(k in dep_lower for k in keywords):
                flagged.setdefault(category, []).append(dep)
    return flagged
```

### Transitive Dependency Risk

```bash
# Find deeply nested dependencies (supply chain risk)
npm ls --all 2>/dev/null | grep -E "^\s{8,}" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10

# Check for known malicious packages
npm audit signatures 2>/dev/null

# Verify package integrity
npm pack --dry-run <package> 2>&1 | grep "integrity"
```

---

## 3. Supply Chain Attack Surface

### Package Metadata Analysis

```bash
# Check package publish history (npm)
npm view <package> time --json | jq 'to_entries | sort_by(.value) | reverse | .[0:5]'

# Check maintainer count (bus factor)
npm view <package> maintainers --json | jq 'length'

# Check download trends (popularity = scrutiny)
curl -s "https://api.npmjs.org/downloads/point/last-month/<package>" | jq '.downloads'

# Check repository match (typosquatting detection)
npm view <package> repository.url
```

### Lockfile Integrity Verification

```bash
# Verify npm lockfile hasn't been tampered
npm ci --ignore-scripts 2>&1 | grep -i "error\|warn"

# Check for lockfile drift
npm ls --package-lock-only 2>&1 | grep -c "missing"

# Python: verify hashes
pip install --require-hashes -r requirements.txt --dry-run 2>&1 | grep -i "hash"
```

---

## 4. Rapid Onboarding Checklist

```bash
#!/bin/bash
# supply-chain-audit.sh — Quick supply chain health check
PROJECT_DIR="${1:-.}"

echo "=== Supply Chain Audit: $PROJECT_DIR ==="

# Detect ecosystem
if [ -f "$PROJECT_DIR/package.json" ]; then
    echo "[npm] Found package.json"
    echo "  Dependencies: $(jq '.dependencies | length' "$PROJECT_DIR/package.json")"
    echo "  DevDeps: $(jq '.devDependencies | length' "$PROJECT_DIR/package.json")"
    cd "$PROJECT_DIR" && npm audit --json 2>/dev/null | jq '.metadata.vulnerabilities'
fi

if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    echo "[pip] Found requirements.txt"
    echo "  Packages: $(wc -l < "$PROJECT_DIR/requirements.txt")"
    echo "  Pinned: $(grep -c '==' "$PROJECT_DIR/requirements.txt")"
    echo "  Unpinned: $(grep -cv '==' "$PROJECT_DIR/requirements.txt")"
fi

if [ -f "$PROJECT_DIR/go.mod" ]; then
    echo "[go] Found go.mod"
    echo "  Direct deps: $(grep -c 'require' "$PROJECT_DIR/go.sum" 2>/dev/null || echo 'N/A')"
fi

echo ""
echo "=== Recommendations ==="
echo "- Run ecosystem-specific audit tool"
echo "- Check for outdated dependencies"
echo "- Verify lockfile is committed"
echo "- Review maintainer trust for critical deps"
```

---

## 5. SBOM Generation

```bash
# Generate Software Bill of Materials
# Node.js
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Python
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json

# Multi-ecosystem (Syft)
syft . -o cyclonedx-json > sbom.json

# Scan SBOM for known vulnerabilities
grype sbom:sbom.json --output json | jq '[.matches[] | {package: .artifact.name, vulnerability: .vulnerability.id, severity: .vulnerability.severity}]'
```
