# Package Integrity Verification Guide

> Practical techniques for verifying package authenticity including signature verification, hash pinning, provenance attestation, and tamper detection across package ecosystems.

---

## 1. Hash Pinning for Dependencies

Hash pinning ensures that the exact bytes of a dependency match what was audited, preventing supply chain substitution attacks.

```bash
# npm - verify package integrity via package-lock.json
# package-lock.json contains integrity hashes (SHA-512)
cat package-lock.json | jq '.packages["node_modules/express"].integrity'
# Output: "sha512-abc123..."

# Verify integrity during install (npm ci enforces lockfile)
npm ci  # Fails if any hash doesn't match lockfile

# Manually verify a downloaded package
npm pack express@4.18.2
sha512sum express-4.18.2.tgz | awk '{print $1}' | xxd -r -p | base64

# Python - generate requirements with hashes
pip-compile --generate-hashes requirements.in -o requirements.txt
# Output format:
# flask==3.0.0 \
#     --hash=sha256:abc123... \
#     --hash=sha256:def456...

# Install with hash verification (fails if hash mismatch)
pip install --require-hashes -r requirements.txt
```

```bash
# Go - verify module checksums via go.sum
# go.sum contains expected hashes for all dependencies
cat go.sum | head -5
# Example: github.com/gin-gonic/gin v1.9.1 h1:abc123=
# Example: github.com/gin-gonic/gin v1.9.1/go.mod h1:def456=

# Verify against Go checksum database (sum.golang.org)
GONOSUMCHECK="" go mod verify
# Output: "all modules verified"

# Check if a specific module has been tampered with
go mod verify 2>&1 | grep "SECURITY ERROR"
```

---

## 2. Package Signature Verification

```bash
# Verify npm package signatures (npm v9+)
npm audit signatures
# Reports packages with valid/invalid/missing signatures

# Verify individual package provenance
npm pack express@4.18.2 --pack-destination /tmp
npm verify /tmp/express-4.18.2.tgz

# Python - verify PGP signatures on PyPI packages
pip download flask==3.0.0 --no-deps -d /tmp/pkgs
# Check if .asc signature file is available
curl -s "https://pypi.org/simple/flask/" | grep -o 'href="[^"]*3.0.0[^"]*\.asc"'

# Verify GPG signature
gpg --verify flask-3.0.0.tar.gz.asc flask-3.0.0.tar.gz

# Ruby gems - verify gem signatures
gem cert --add author-public.pem
gem install package_name -P HighSecurity  # Requires valid signature
```

```bash
# Container image signature verification with cosign
# Verify image before pulling/deploying
cosign verify \
  --key cosign.pub \
  ghcr.io/company/app:v1.0.0

# Verify with keyless (Sigstore transparency log)
cosign verify \
  --certificate-identity "release@company.com" \
  --certificate-oidc-issuer "https://accounts.google.com" \
  ghcr.io/company/app:v1.0.0

# Verify image digest matches expected
EXPECTED_DIGEST="sha256:abc123..."
ACTUAL_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/company/app:v1.0.0 | cut -d@ -f2)
[ "$EXPECTED_DIGEST" = "$ACTUAL_DIGEST" ] && echo "VERIFIED" || echo "MISMATCH"
```

---

## 3. Provenance Attestation

```bash
# Generate SLSA provenance for build artifacts
# Using SLSA GitHub Generator
# In .github/workflows/release.yml:
cat << 'WORKFLOW'
name: Release with Provenance
on:
  push:
    tags: ['v*']

jobs:
  build:
    outputs:
      digest: ${{ steps.hash.outputs.digest }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
      - name: Generate hash
        id: hash
        run: |
          DIGEST=$(sha256sum dist/app.tar.gz | awk '{print $1}')
          echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with:
          name: release-artifact
          path: dist/app.tar.gz

  provenance:
    needs: build
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
    with:
      base64-subjects: ${{ needs.build.outputs.digest }}
WORKFLOW
```

```python
# Verify SLSA provenance attestation
import json
import subprocess
import sys

def verify_provenance(artifact_path, provenance_path, expected_source):
    """Verify SLSA provenance for an artifact."""
    # Use slsa-verifier CLI
    result = subprocess.run([
        "slsa-verifier", "verify-artifact",
        artifact_path,
        "--provenance-path", provenance_path,
        "--source-uri", expected_source,
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"VERIFIED: Artifact provenance confirmed")
        print(f"  Source: {expected_source}")
        print(f"  Builder: GitHub Actions (trusted)")
        return True
    else:
        print(f"FAILED: Provenance verification failed")
        print(f"  Error: {result.stderr}")
        return False

# Parse provenance for detailed inspection
def inspect_provenance(provenance_path):
    with open(provenance_path) as f:
        provenance = json.load(f)
    
    predicate = provenance.get("predicate", {})
    builder = predicate.get("builder", {}).get("id", "unknown")
    source = predicate.get("invocation", {}).get("configSource", {})
    materials = predicate.get("materials", [])
    
    print(f"Builder: {builder}")
    print(f"Source: {source.get('uri', 'unknown')}")
    print(f"Commit: {source.get('digest', {}).get('sha1', 'unknown')}")
    print(f"Materials: {len(materials)} dependencies recorded")
    
    return provenance

verify_provenance("app.tar.gz", "provenance.intoto.jsonl", "github.com/company/repo")
```

---

## 4. Tamper Detection in Package Registries

```python
# Monitor packages for unexpected changes (version mutation)
import requests
import hashlib
import json
import time

class PackageMonitor:
    def __init__(self, state_file="package_state.json"):
        self.state_file = state_file
        try:
            with open(state_file) as f:
                self.state = json.load(f)
        except FileNotFoundError:
            self.state = {}
    
    def check_npm_package(self, name, version):
        """Check if a published npm package has been modified."""
        resp = requests.get(f"https://registry.npmjs.org/{name}/{version}")
        if resp.status_code != 200:
            return {"status": "NOT_FOUND"}
        
        data = resp.json()
        tarball_url = data.get("dist", {}).get("tarball", "")
        shasum = data.get("dist", {}).get("shasum", "")
        integrity = data.get("dist", {}).get("integrity", "")
        
        key = f"{name}@{version}"
        if key in self.state:
            if self.state[key]["shasum"] != shasum:
                return {
                    "status": "TAMPERED",
                    "previous_hash": self.state[key]["shasum"],
                    "current_hash": shasum,
                    "alert": f"Package {key} hash changed!"
                }
            return {"status": "UNCHANGED"}
        
        # First observation - record baseline
        self.state[key] = {
            "shasum": shasum,
            "integrity": integrity,
            "first_seen": time.time(),
        }
        self.save_state()
        return {"status": "BASELINED"}
    
    def save_state(self):
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)

monitor = PackageMonitor()
packages_to_watch = [
    ("express", "4.18.2"),
    ("lodash", "4.17.21"),
    ("axios", "1.6.0"),
]

for name, version in packages_to_watch:
    result = monitor.check_npm_package(name, version)
    print(f"{name}@{version}: {result['status']}")
```

---

## 5. Lock File Integrity

```bash
# Verify lockfile hasn't been tampered with
# npm - check for lockfile/package.json drift
npm ci 2>&1 | grep -i "error\|warn"

# Detect lockfile manipulation in PRs
git diff origin/main -- package-lock.json | grep "resolved\|integrity" | head -20

# Verify all resolved URLs point to expected registries
UNEXPECTED=$(jq -r '.. | .resolved? // empty' package-lock.json | grep -v "registry.npmjs.org" | grep -v "npm.company.com")
if [ -n "$UNEXPECTED" ]; then
  echo "WARNING: Unexpected registry URLs in lockfile:"
  echo "$UNEXPECTED"
fi

# Python - verify pip freeze matches requirements
pip freeze > actual_deps.txt
diff <(sort requirements.txt | grep -v "^#\|^-") <(sort actual_deps.txt) 

# Go - verify go.sum hasn't been modified unexpectedly
go mod verify
GOFLAGS="-mod=readonly" go build ./...  # Fails if go.sum needs updating
```

```yaml
# CI/CD lockfile verification step
name: Verify Dependencies
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check lockfile integrity
        run: |
          # Ensure lockfile is in sync with package.json
          npm ci
          # Verify no unexpected registry URLs
          SUSPICIOUS=$(jq -r '.. | .resolved? // empty' package-lock.json | \
            grep -v "registry.npmjs.org" | grep -v "^$")
          if [ -n "$SUSPICIOUS" ]; then
            echo "::error::Suspicious registry URLs detected in lockfile"
            echo "$SUSPICIOUS"
            exit 1
          fi
          
      - name: Verify package signatures
        run: npm audit signatures
```

---

## 6. Verification Automation

```bash
# Pre-install verification hook for npm
# Add to .npmrc:
# script-shell=/bin/bash

# package.json preinstall script for verification
cat > scripts/verify-deps.sh << 'EOF'
#!/bin/bash
set -e

echo "Verifying dependency integrity..."

# Check for known malicious packages
MALICIOUS_PACKAGES="event-stream flatmap-stream ua-parser-js"
for pkg in $MALICIOUS_PACKAGES; do
  if grep -q "\"$pkg\"" package.json; then
    echo "ERROR: Known malicious package detected: $pkg"
    exit 1
  fi
done

# Verify lockfile exists and is committed
if [ ! -f package-lock.json ]; then
  echo "ERROR: No lockfile found. Run 'npm install' and commit package-lock.json"
  exit 1
fi

# Check for typosquatting (common misspellings of popular packages)
TYPOSQUAT_PATTERNS="lodahs|axois|expresss|reacct|angualr"
SUSPICIOUS=$(jq -r '.dependencies // {} | keys[]' package.json | grep -iE "$TYPOSQUAT_PATTERNS")
if [ -n "$SUSPICIOUS" ]; then
  echo "WARNING: Possible typosquatting detected: $SUSPICIOUS"
fi

echo "Dependency verification passed"
EOF
chmod +x scripts/verify-deps.sh
```

Package integrity verification should be automated and enforced at every stage: development (lockfiles), CI/CD (hash verification), and deployment (signature checks). Trust but verify at every boundary.
