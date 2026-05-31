# Docker Security Scanning Guide

> Techniques for identifying vulnerabilities in Docker images, containers, and orchestration configurations.

---

## 1. Image Vulnerability Scanning

### Trivy Image Scan

```bash
# Scan local image
trivy image --severity HIGH,CRITICAL myapp:latest

# Scan with JSON output for automation
trivy image --format json --output results.json myapp:latest

# Scan remote image without pulling
trivy image --remote docker.io/library/nginx:1.25

# Scan with specific vulnerability database
trivy image --db-repository ghcr.io/aquasecurity/trivy-db myapp:latest

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed myapp:latest
```

### Grype Image Analysis

```bash
# Scan image
grype myapp:latest

# Output as JSON
grype myapp:latest -o json > grype_results.json

# Only show fixable vulnerabilities
grype myapp:latest --only-fixed

# Scan from SBOM
syft myapp:latest -o cyclonedx-json | grype
```

### Docker Scout

```bash
# Quick vulnerability overview
docker scout quickview myapp:latest

# Detailed CVE listing
docker scout cves myapp:latest --only-severity critical,high

# Compare two image versions
docker scout compare myapp:v1 myapp:v2

# Recommendations for base image
docker scout recommendations myapp:latest
```

---

## 2. Dockerfile Security Analysis

### Hadolint Static Analysis

```bash
# Lint Dockerfile
hadolint Dockerfile

# JSON output
hadolint --format json Dockerfile

# Ignore specific rules
hadolint --ignore DL3008 --ignore DL3009 Dockerfile

# Check for security-specific issues
hadolint Dockerfile | grep -iE "DL3002|DL3007|DL4006|SC2086"
```

### Common Security Anti-Patterns

```bash
# Detect running as root
grep -n "^USER" Dockerfile || echo "WARNING: No USER directive (runs as root)"

# Detect secrets in build args
grep -n "ARG.*PASSWORD\|ARG.*SECRET\|ARG.*TOKEN\|ARG.*KEY" Dockerfile

# Detect ADD instead of COPY (ADD can fetch remote URLs)
grep -n "^ADD " Dockerfile | grep -v "\.tar"

# Detect latest tag usage
grep -n "FROM.*:latest\|FROM.*[^:]*$" Dockerfile
```

---

## 3. Container Runtime Security

### Container Escape Detection

```bash
# Check for privileged containers
docker ps --format '{{.Names}}' | while read c; do
    privileged=$(docker inspect "$c" --format '{{.HostConfig.Privileged}}')
    [ "$privileged" = "true" ] && echo "PRIVILEGED: $c"
done

# Check for dangerous capabilities
docker ps --format '{{.Names}}' | while read c; do
    caps=$(docker inspect "$c" --format '{{.HostConfig.CapAdd}}')
    [ "$caps" != "[]" ] && [ "$caps" != "<nil>" ] && echo "CAPS: $c → $caps"
done

# Check for host mounts
docker ps --format '{{.Names}}' | while read c; do
    docker inspect "$c" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' | grep -q "/var/run/docker.sock\|/proc\|/sys" && echo "DANGEROUS MOUNT: $c"
done
```

### Network Isolation Verification

```bash
# List container networks
docker network ls
docker network inspect bridge --format '{{range .Containers}}{{.Name}} {{end}}'

# Check for host network mode
docker ps --format '{{.Names}}' | while read c; do
    net=$(docker inspect "$c" --format '{{.HostConfig.NetworkMode}}')
    [ "$net" = "host" ] && echo "HOST NETWORK: $c"
done

# Verify inter-container isolation
docker exec container_a ping -c 1 container_b 2>/dev/null && echo "CONNECTED" || echo "ISOLATED"
```

---

## 4. Docker Compose Security Audit

### Compose File Analysis

```bash
# Find security issues in docker-compose.yml
audit_compose() {
    local file="${1:-docker-compose.yml}"
    
    echo "=== Security Audit: $file ==="
    
    # Privileged mode
    grep -n "privileged: true" "$file" && echo "[CRITICAL] Privileged container found"
    
    # Host network
    grep -n "network_mode.*host" "$file" && echo "[HIGH] Host network mode"
    
    # Exposed ports on 0.0.0.0
    grep -n "ports:" -A5 "$file" | grep -v "127.0.0.1" | grep -E "^\s+-\s+\"?[0-9]" && echo "[MEDIUM] Ports exposed on all interfaces"
    
    # Volume mounts
    grep -n "/var/run/docker.sock" "$file" && echo "[CRITICAL] Docker socket mounted"
    grep -n "/proc\|/sys\|/dev" "$file" && echo "[HIGH] Sensitive host path mounted"
    
    # Environment secrets
    grep -n "PASSWORD\|SECRET\|TOKEN\|API_KEY" "$file" | grep -v "_FILE" && echo "[HIGH] Secrets in environment variables"
}
```

### Secret Management Patterns

```bash
# Use Docker secrets instead of env vars
docker secret create db_password - <<< "supersecret"

# Reference in compose
cat <<'EOF'
services:
  app:
    secrets:
      - db_password
secrets:
  db_password:
    external: true
EOF

# Verify no secrets in image layers
docker history --no-trunc myapp:latest | grep -iE "secret|password|token|key"
```

---

## 5. Registry Security

### Private Registry Scanning

```bash
# Scan all images in a registry
skopeo list-tags docker://registry.example.com/myapp | jq -r '.Tags[]' | while read tag; do
    echo "Scanning: myapp:$tag"
    trivy image "registry.example.com/myapp:$tag" --severity CRITICAL --quiet
done

# Check image signatures
cosign verify --key cosign.pub registry.example.com/myapp:latest

# Inspect image without pulling
skopeo inspect docker://registry.example.com/myapp:latest | jq '{created: .Created, layers: (.Layers | length)}'
```

### Image Provenance

```bash
# Check image build history for suspicious layers
docker history --no-trunc myapp:latest | grep -iE "curl.*\|.*sh|wget|apt-get install.*-y"

# Verify base image digest
docker inspect myapp:latest --format '{{index .RepoDigests 0}}'

# Compare with known-good digest
expected="sha256:abc123..."
actual=$(docker inspect myapp:latest --format '{{index .RepoDigests 0}}' | cut -d@ -f2)
[ "$expected" = "$actual" ] && echo "VERIFIED" || echo "MISMATCH"
```

---

## 6. Automated Security Pipeline

```bash
#!/bin/bash
# docker-security-scan.sh — Full security audit pipeline
IMAGE="$1"

echo "=== Docker Security Scan: $IMAGE ==="

echo "[1/4] Vulnerability scan..."
trivy image --severity HIGH,CRITICAL --quiet "$IMAGE"

echo "[2/4] Dockerfile lint..."
docker history --no-trunc "$IMAGE" 2>/dev/null | head -20

echo "[3/4] Secret detection..."
docker save "$IMAGE" | tar -xO | strings | grep -iE "password|secret|api.key|token" | head -5

echo "[4/4] Configuration check..."
docker inspect "$IMAGE" --format '
  User: {{.Config.User}}
  ExposedPorts: {{.Config.ExposedPorts}}
  Entrypoint: {{.Config.Entrypoint}}
  Cmd: {{.Config.Cmd}}'

echo "[+] Scan complete"
```
