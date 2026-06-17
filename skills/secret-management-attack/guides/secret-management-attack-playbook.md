# Secret Management Attack Playbook — End-to-End Workflow Guide

> Deep-dive companion to `skills/secret-management-attack/SKILL.md`.
>
> Audience: pentesters who already understand security-review and repo-scan, and want a battle-tested playbook for the secret-hunting specialty — from scope definition through breadth scanning, triage and verification, secrets-management platform exploitation, lateral pivoting, and OPSEC-safe report assembly.

---

## 1. Why a Workflow, Not Just Commands

Secret management attack is the single highest-leverage finding type in a real engagement. One leaked AWS access key grants production infrastructure. One stale Vault token grants every secret an entire service can read. One CI variable carries deploy credentials across hundreds of environments. The discipline is therefore **breadth first, depth second**: scan everything before going deep on verification and exploitation.

A defensible secret-management attack requires:

1. **Scope discipline** — never scan a remote repo's full history during recon; never verify a credential against a live API without explicit per-test approval.
2. **OPSEC awareness** — every live verification generates real provider-side events (CloudTrail, GitHub audit log, Vault audit device, GitGuardian honeytoken callback). Plan around this.
3. **Canary-token paranoia** — assume every unknown secret is a honeytoken until proven otherwise. Treat AWS keys found in suspicious locations as potential decoys.
4. **Blast-radius thinking** — a secret by itself is a string; its value is what it grants. Quantify the reachable-node expansion from each harvested credential.
5. **Report discipline** — never include raw secret values in the deliverable. Use masked forms (`AKIA...XYZ9`) sufficient for identification but not weaponization.

This guide walks through all five, in order, with the exact commands, decision points, and report templates.

---

## 2. Pre-Flight: Scope, Authorization, OPSEC Limits

Before any active scanning, answer these — in writing:

- **Who authorized this?** A signed Statement of Work must name the repos, hosts, images, mobile binaries, web apps, cloud accounts, vaults, and CI/CD pipelines in scope. Unauthorized scanning of credentials you do not own is a crime in most jurisdictions (CFAA, CMA, equivalents).
- **What's the verification budget?** Define a per-day cap on live API verifications. Example: max 20 verifications per day to avoid triggering provider-side anomaly detection.
- **What's the canary-token policy?** Heuristic checks (Section 8) before any API call. If heuristics fail, treat as honeytoken and do NOT verify.
- **What's the egress path?** Where will harvested secrets live? Tmpfs, encrypted vault, retention period, destruction protocol.
- **What's the rotation coordination?** Pre-engagement agreement on how the client will be notified of verified live secrets (immediate vs end-of-engagement) and the rotation ceremony.

If any of these are unclear, stop and resolve before proceeding.

---

## 3. Phase 1 — Scope & Inventory

### 3.1 Target Inventory

The single most common scoping failure is under-enumerating target types. Secrets live in:

| Target Type | Examples | Notes |
|-------------|----------|-------|
| **Repository** | GitHub, GitLab, Bitbucket, self-hosted | Full history, all branches, all tags |
| **Filesystem** | Compromised host, CI runner, dev laptop | `/home`, `/etc`, `/var/log`, `/root`, `/opt` |
| **Container image** | Docker registry, OCI registry | All layers — base, intermediate, final |
| **Mobile binary** | Android APK, iOS IPA | Static + dynamic analysis |
| **Web app** | Live JS bundles, sourcemaps, HTML | Crawl + extract |
| **Cloud account** | AWS, GCP, Azure | IAM + Secrets Manager + Parameter Store |
| **Vault** | HashiCorp Vault, Infisical, Doppler, Conjur | Token discovery first |
| **CI/CD** | GitHub Actions, GitLab CI, Jenkins, CircleCI, Argo | Workflows + secrets + runner state |
| **K8s cluster** | Service account, etcd, RBAC | All namespaces the SA can reach |
| **Build artifact** | npm package, JAR, wheel, Go binary | Reverse + extract |

### 3.2 OPSEC Limits Per Target

| Target | OPSEC Risk | Default Mode |
|--------|-----------|--------------|
| Remote repo | HIGH (provider-side scanning) | Local mirror-clone, scan filesystem |
| Filesystem | LOW | Direct scan, no API calls |
| Container image | LOW (local) / MEDIUM (registry pull) | Pull once, scan locally |
| Mobile binary | LOW | Local extraction |
| Web app | MEDIUM (target sees crawl) | Distributed crawl, low concurrency |
| Cloud account | HIGH (CloudTrail, GuardDuty) | Single lightest-touch verification first |
| Vault | HIGH (audit device) | Read-only, spread over time |
| CI/CD | LOW (config review) | Read YAMLs; don't trigger workflows |
| K8s | LOW (audit logged, normal pattern) | Use existing SA, don't create new |
| Build artifact | LOW | Local reverse |

### 3.3 Inventory Template

```bash
cat <<EOF > secret_targets.tsv
kind        location                                notes                                   opsec_mode
repo        github.com/client/monorepo              full history + all branches             local-clone
host        10.0.1.5 (bastion)                      /home /etc /var/log                     direct-scan
image       registry.client/api:2024.11             all layers                              local-pull
apk         com.client.app (Play Store)             production binary                       local-extract
webapp      https://app.client.com                  crawl + JS                              distributed-crawl
cloud       aws:123456789012                        IAM + Secrets Manager                   single-verify-first
vault       https://vault.infra.client.local        token from sidecar leak                 read-only-spread
ci          github.com/client/monorepo/.github      workflows + secrets                     read-yaml-only
k8s         https://k8s.api.client.local            all namespaces                          use-existing-sa
artifact    npm:@client/internal-lib@1.4.2         packed tarball                          local-reverse
EOF
```

---

## 4. Phase 2 — Breadth Scan

The goal of Phase 2 is **breadth, not depth**. Find every candidate. Do NOT verify yet.

### 4.1 Repository (Local-Clone Rule)

```bash
# NEVER scan a remote repo's history during recon
# DO clone locally and scan the filesystem

git clone --mirror <repo_url> repo-bare
cd repo-bare

# gitleaks — all refs
gitleaks detect --source . \
  --report-path gitleaks.json \
  --log-opts=" --all" \
  --redact

# trufflehog — unverified
trufflehog git file://. \
  --no-verification \
  --no-update \
  --json > trufflehog_unverified.jsonl

# semgrep — built-in + custom
cd .. && git clone <repo_url> repo-src
semgrep --config p/secret-detection --config custom_secrets.yml \
  repo-src --json -o semgrep.json

# bearer — dataflow
bearer scan repo-src --dataflow --format json -o bearer.json
```

### 4.2 Filesystem

```bash
gitleaks detect --source /target --no-git --report-path fs_gitleaks.json
trufflehog filesystem /target --json > fs_trufflehog.jsonl

# Manual sweep of common credential file paths
for f in \
  ~/.aws/credentials \
  ~/.aws/config \
  ~/.kube/config \
  ~/.docker/config.json \
  ~/.npmrc \
  ~/.pypirc \
  ~/.netrc \
  ~/.ssh/id_rsa \
  ~/.ssh/id_ed25519 \
  ~/.config/gcloud/credentials.db \
  ~/.azure/msal_token_cache.json \
  ~/.vault-token ; do
  [ -f "$f" ] && echo "FOUND: $f"
done
```

### 4.3 Container Image

```bash
dive <image_ref>                          # interactive layer walk
trivy image --scanners secret --format json <image_ref> -o trivy_image.json

# Manual extraction
docker save <image_ref> -o image.tar
mkdir image && tar xf image.tar -C image

# Walk layers for credential files
for layer in image/*/layer.tar; do
  echo "=== $layer ==="
  tar tvf "$layer" 2>/dev/null | \
    grep -E '(\.env|credentials|\.key|\.pem|config\.json|\.npmrc|\.pypirc|\.netrc|\.kube/config)'
done
```

### 4.4 Mobile APK

```bash
apkleaks -f app.apk -o apkleaks.json
unzip -p app.apk classes.dex > classes.dex
trufflehog filesystem --json . > apk_th.jsonl
jadx -d app_src app.apk
grep -rE "BuildConfig\.(API_KEY|SECRET)|google_api_key|firebase_url" app_src/
```

### 4.5 Web App

```bash
cariddi -u https://app.target.com -e -s -d 3 -json -o cariddi.json

# Or katana for better JS coverage
katana -u https://app.target.com -jc -d 3 | grep "\.js$" > js_urls.txt

for url in $(cat js_urls.txt); do
  curl -s "$url" >> bundle.js
done

# Extract secrets
grep -oE "(AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{24,}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_\-]{35})" \
  bundle.js | sort -u

# Sourcemaps may expose original source paths
curl -s https://app.target.com/bundle.js.map | jq .sources
```

### 4.6 Output Aggregation

After all scans, aggregate into a single JSONL for Phase 3:

```bash
# Normalize each scanner's output to a common schema:
# {scanner, rule, file, line, secret_hash, secret_masked, context}

python3 <<'EOF'
import json, hashlib

def norm(scanner, finding):
    secret = finding.get('secret') or finding.get('raw') or finding.get('match')
    if not secret: return None
    h = hashlib.sha256(secret.encode()).hexdigest()[:16]
    return {
        'scanner': scanner,
        'rule': finding.get('rule') or finding.get('detectorName') or finding.get('check_id'),
        'file': finding.get('file') or finding.get('path'),
        'line': finding.get('lineStart') or finding.get('start_line'),
        'secret_hash': h,
        'secret_masked': secret[:4] + '...' + secret[-4:],
    }

findings = []
# gitleaks.json
for f in json.load(open('gitleaks.json')):
    n = norm('gitleaks', f); 
    if n: findings.append(n)
# trufflehog jsonl
for line in open('trufflehog_unverified.jsonl'):
    obj = json.loads(line)
    n = norm('trufflehog', obj.get('SourceMetadata', {}).get('Data', {}).get('Git', {}))
    if n: findings.append(n)
# ... repeat for semgrep, bearer, etc.

# Dedupe by secret_hash
seen = set()
deduped = [f for f in findings if f['secret_hash'] not in seen and not seen.add(f['secret_hash'])]
json.dump(deduped, open('deduped.json', 'w'), indent=2)
print(f"Deduped: {len(findings)} -> {len(deduped)}")
EOF
```

---

## 5. Phase 3 — Triage & Verify

### 5.1 Triage Order

Rank candidates by **apparent blast radius** (most likely to be exploitable first):

1. AWS / GCP / Azure access keys
2. HashiCorp Vault tokens
3. CI/CD deploy tokens (GitHub PAT, GitLab token, Jenkins API token)
4. Database connection strings
5. Cloud provider service-account JSON files
6. Stripe / payment processor keys
7. Internal API keys (proprietary format)
8. JWT session tokens
9. Generic secrets in env

### 5.2 Heuristic Pre-Check (No API Call)

For every candidate, before any verification:

```bash
# Context grep — does surrounding text suggest a placeholder?
grep -B2 -A2 "$SECRET" /path/to/findings | grep -iE \
  "(example|test|fake|YOUR_|REPLACE|<|>|xxxx|\$\{|process\.env|canary|honey|decoy|sample)"
# If match: skip verification

# File context — README/docs/example paths are likely placeholders
[[ "$FILE" =~ (README|example|sample|docs?|test|fixture) ]] && echo "SKIP"

# Commit age — older commits more likely already rotated
git log -1 --format=%ci "$COMMIT_SHA"
```

### 5.3 Format Validation

```bash
# Use payloads.md §15.1 patterns
PATTERNS=(
  "AKIA[0-9A-Z]{16}"                # AWS
  "sk_live_[A-Za-z0-9]{24,}"        # Stripe
  "ghp_[A-Za-z0-9]{36}"             # GitHub PAT
  "hvs\.[A-Za-z0-9_\-]{80,}"        # Vault
  "AIza[0-9A-Za-z_\-]{35}"          # GCP
  "eyJ[A-Za-z0-9_\-]+\.eyJ"         # JWT
)

for pat in "${PATTERNS[@]}"; do
  echo "$SECRET" | grep -qE "$pat" && echo "MATCH: $pat"
done
```

### 5.4 Entropy Check

```bash
python3 -c "
import math, collections, sys
s = sys.argv[1]
freq = collections.Counter(s)
n = len(s)
e = -sum((c/n) * math.log2(c/n) for c in freq.values())
print(f'Entropy: {e:.2f}')
print('Likely real' if e > 4.5 else 'Likely low-entropy (placeholder?)')
" "$SECRET"
```

### 5.5 Canary-Token Check

```bash
# AWS honey-key accounts (well-known honeypot account IDs)
HONEY_ACCOUNTS=(123456789012 111111111111 999999999999 000000000000)
# Note: account ID is not directly recoverable from AKIA prefix alone,
# but if a key is paired with a clearly-visible account ID in context,
# check against the list.

# thinkst canarytokens.org domain
grep -rE "canarytokens\.(com|org)" /target/

# Generic honeytoken hint words
grep -iE "(canary|honeytoken|honey pot|thinkst|decoy|tripwire)" /target/
```

### 5.6 Verification (After All Heuristics Pass)

ONLY with explicit per-test client approval:

```bash
# AWS — STS GetCallerIdentity (lightest-touch)
aws sts get-caller-identity

# GitHub PAT — /user is lightest-touch
curl -sI -H "Authorization: token $GH_PAT" https://api.github.com/user | head -1

# Stripe — /v1/balance
curl -s https://api.stripe.com/v1/balance -u "$STRIPE_KEY:"

# HashiCorp Vault — token lookup
vault token lookup
```

### 5.7 OPSEC Verification Budget

```bash
# Enforce max verifications per day
COUNT_FILE=/tmp/verify_count_$(date +%Y%m%d)
touch $COUNT_FILE
COUNT=$(wc -l < $COUNT_FILE)
MAX=20

if [ $COUNT -ge $MAX ]; then
  echo "Verification budget reached for today; restaging"
  exit 1
fi

# ... verify ...
echo "$(date -u +%FT%TZ) $PROVIDER $SECRET_HASH $IP_USED" >> $COUNT_FILE
```

---

## 6. Phase 4 — Platform Exploit

Once a credential is verified, expand to its native platform. The discipline is **graph expansion**: each verified secret defines a new set of reachable nodes.

### 6.1 AWS Pivot Tree

```
Verified AWS Key
├── STS GetCallerIdentity
│   ├── Account ID
│   ├── IAM User / Role ARN
│   └── Permissions boundary
├── Secrets Manager enumeration
│   ├── List all secrets
│   ├── Read each (CloudTrail event)
│   └── Pivot: each secret's downstream service
│       ├── DB password → RDS auth
│       ├── Another AWS key → recurse
│       └── API token → external service
├── SSM Parameter Store
│   ├── List parameters
│   └── Decrypt SecureString (KMS event)
├── S3 (if policies allow)
│   ├── List buckets
│   └── Read objects (CloudTrail data event)
├── DynamoDB (if policies allow)
│   └── Scan tables
└── EC2 metadata (if running on EC2 with this role)
    └── Instance profile credentials (new key!)
```

### 6.2 HashiCorp Vault Pivot Tree

```
Verified Vault Token
├── Token introspection (vault token lookup)
│   ├── Policies
│   ├── TTL remaining
│   └── Renewable
├── Policy enumeration (vault policy read)
├── Capabilities per path (vault token capabilities)
├── Recursive secret walker (payloads.md §9.3)
│   ├── Read every secret at every reachable path
│   └── Pivot: each harvested secret's downstream service
├── Cubbyhole (token's private storage)
├── Auth methods (if token has auth capabilities)
│   └── Generate new tokens via AppRole / Kubernetes auth
└── Secrets engines
    ├── PKI (cert minting)
    ├── Database (dynamic creds)
    └── AWS / GCP secrets engines (dynamic cloud creds)
```

### 6.3 Kubernetes Pivot Tree

```
Verified SA Token
├── Self capabilities (kubectl auth can-i --list)
├── Secret enumeration (all namespaces the SA can reach)
│   ├── Generic secrets (decoded)
│   ├── ImagePullSecrets (private registry creds)
│   ├── Service-account tokens (recurse)
│   └── TLS keys (private CAs)
├── Pod enumeration
│   └── Exec into privileged pods
├── RBAC escalation paths
│   ├── CSR creation → cluster-admin (payloads.md §12.6)
│   ├── Role/ClusterRole binding creation
│   └── Pod creation with hostPath / privileged
└── etcd direct access (if RBAC allows)
    └── Snapshot extraction
```

### 6.4 CI/CD Pivot Tree

```
Verified CI Token (GitHub PAT, GitLab token)
├── Repository enumeration
│   ├── Read .github/workflows
│   ├── Read .gitlab-ci.yml
│   ├── Read Jenkinsfile
│   └── Identify workflows with secrets
├── Secret enumeration (if token has repo:secret scope)
│   └── List repo secrets via API
├── Workflow triggering
│   ├── workflow_dispatch with controlled input
│   ├── pull_request_target via fork PR
│   └── Self-hosted runner compromise
└── Lateral to other repos / orgs the token reaches
```

---

## 7. Phase 5 — Lateral Pivot

### 7.1 Pivot Graph Discipline

Maintain a running graph of reachable nodes. Every harvested secret expands the graph.

```mermaid
graph TD
    Start[Initial access: leaked AWS key] --> AWS1[STS: identify account]
    AWS1 --> AWS2[Secrets Manager: 200 secrets]
    AWS2 --> RDS[RDS password → DB access]
    AWS2 --> Vault1[Vault token in secrets/dev/vault]
    Vault1 --> Vault2[Vault enumeration: 184 secrets]
    Vault2 --> K8s1[K8s SA token]
    K8s1 --> K8s2[Cluster secrets dump]
    K8s2 --> ImagePull[Private registry creds]
    ImagePull --> Image[Pull + analyze prod images]
```

### 7.2 Pivot Tracking

```bash
# Maintain pivot_log.jsonl
# Each line: {from, to, via, timestamp, opsec_event}

cat <<'EOF' > pivot_log.jsonl
{"from":"leaked-aws-key","to":"aws-account-123456789012","via":"sts","ts":"...","opsec":true}
{"from":"aws-account-...","to":"secrets-manager-200","via":"list+get","ts":"...","opsec":true}
{"from":"secrets-manager-200","to":"vault-token-hvs.xxxx","via":"read","ts":"...","opsec":true}
{"from":"vault-token-hvs.xxxx","to":"vault-184-secrets","via":"read-all","ts":"...","opsec":true}
{"from":"vault-184-secrets","to":"k8s-sa-token","via":"read","ts":"...","opsec":false}
EOF

# Query blast radius
jq -s 'map(.to) | unique | length' pivot_log.jsonl   # reachable-node count
```

### 7.3 OPSEC-Safe Pivot Patterns

- **Spread reads over time** — bulk Vault reads spike audit-device anomaly
- **Use existing credentials, don't create new ones** — new IAM users, new SA tokens are immediate red flags
- **Avoid privileged operations** — `AssumeRole`, `kubectl exec`, `docker push` are all logged differently than read-only
- **One verification per credential** — if you've verified an AWS key, don't re-verify on every read

---

## 8. Phase 6 — Report & Rotated-Keys Map

### 8.1 Masking Discipline

NEVER include raw secret values in the report deliverable. Use masked forms:

```bash
mask() {
  local s=$1
  local len=${#s}
  if [ $len -le 8 ]; then
    echo "${s:0:2}...${s: -2}"
  else
    echo "${s:0:4}...${s: -4}"
  fi
}

mask "AKIAABCDEFGHIJKLMNOP"     # AKIA...MNOP
mask "sk_live_abc123def456..."  # sk_l...456...
```

### 8.2 Blast-Radius Graph

```mermaid
graph LR
    A[1 leaked Vault token] --> B[47 secrets in prod/]
    B --> C[RDS password]
    B --> D[Slack webhook]
    B --> E[AWS access keys]
    B --> F[3rd-party API tokens]
    C --> G[(RDS: full DB read)]
    D --> H[Slack: msg injection]
    E --> I[(AWS: S3 + Secrets Mgr)]
    F --> J[Stripe / Twilio / SendGrid]
```

### 8.3 Rotation Status Table

| Secret | Found In | Verified | Owner | Last Rotated | Status | Compensating Control |
|--------|----------|----------|-------|--------------|--------|---------------------|
| AWS AKIA...XYZ9 | git commit 4yr old | yes | infra@client | 2 days ago | ROTATED | (none outstanding) |
| Vault hvs...4pq2 | CI runner env | yes | platform@ | pending | NOT ROTATED | Token TTL=24h limits window |
| Stripe sk_live_...AB | mobile APK | yes | payments@ | 1 day ago | ROTATED | Webhook signing also rotated |
| Internal ct_...Z9Y8 | web JS bundle | yes | api@ | pending | NOT ROTATED | Rate-limited; rotation scheduled |

### 8.4 Full Report Template

```markdown
# Secret Audit Report — <Client>
*Date: YYYY-MM-DD | Auditor: <name> | Scope: <inventory summary>*

## Executive Summary
- Total candidate secrets found: 312
- Verified live: 47
- Already rotated by client: 12
- Outstanding (unrotated): 35
- Critical-path blast radius: 1 Vault token → 184 production secrets

## Methodology
- Breadth scan: gitleaks + trufflehog (unverified) + semgrep + bearer + apkleaks + cariddi + dive + trivy
- Triage: dedupe, heuristic pre-check, entropy + format validation, canary-token check
- Verification: lightest-touch per provider (STS, /user, /balance)
- Platform exploitation: Vault enumeration, AWS Secrets Manager dump, K8s secret dump, CI extraction
- OPSEC: max 20 verifications per day, no remote repo scanning, no token revocation

## Findings by Severity
| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 18 |
| MEDIUM | 21 |
| LOW | 3 |

## Blast-Radius Graph
[mermaid diagram]

## Findings Table
[masked-secret table]

## Rotation Status
[rotation table]

## Recommendations
1. **Immediate**: Rotate F-001 (verified AWS production key)
2. **30 days**: Install pre-commit hook (gitleaks) on all repos
3. **30 days**: Add trufflehog + gitleaks scan to every PR build
4. **90 days**: Vault policy audit — reduce blast radius; replace `secret/*` grants with per-path policies
5. **90 days**: Replace long-lived CI tokens with OIDC federation
6. **90 days**: Deploy canary tokens in high-leverage locations (README, sample configs)

## Appendix: OPSEC Audit Trail
[List of all live verification events with timestamp, IP, provider, response code]
```

### 8.5 Post-Engagement Cleanup

```bash
# Shred working files
shred -u harvested.jsonl vault_dump.json k8s_secrets.json

# Unmount tmpfs
sudo umount /mnt/harvest

# Encrypt final deliverable
gpg --encrypt --recipient security@client.com secret_audit_report.md

# Confirm with client: rotation status, audit trail, lessons learned
```

---

## 9. Common Pitfalls

### 9.1 Over-Verification

Verifying every candidate against live APIs triggers every provider-side detector at once. Apply heuristics first; verify only high-confidence, high-blast-radius candidates.

### 9.2 Under-Scanning

Scanning only `HEAD` of `main` misses 90% of secrets. Always mirror-clone and scan all refs.

### 9.3 Trusting Masked CI Variables

CI/CD masking (GitHub Actions, GitLab CI) only masks variables that match format requirements. Short or base64-with-padding values appear in plaintext in logs and artifacts. Audit the actual format of every masked variable.

### 9.4 Revoking Vault Tokens Mid-Engagement

A revoked Vault token immediately alerts the admin and closes the access path. Keep tokens alive; rely on TTL expiry post-engagement.

### 9.5 Including Raw Secrets in Reports

If the report itself leaks, raw secrets become a second breach. Always mask; identify-by-hash in the appendix if needed.

### 9.6 Forgetting Image Layers

"Deleted" files in Docker images still exist in earlier layers. Always walk every layer with `dive`, not just the final filesystem.

### 9.7 Treating Mobile BuildConfig as Safe

BuildConfig values are baked into the APK at compile time. They are not obfuscated; `apkleaks` and `jadx` extract them trivially. Never embed production secrets in BuildConfig.

### 9.8 Ignoring Sourcemaps

Production web apps that ship `.map` files expose original source paths, often including `.env` and config references. Always check for sourcemaps.

---

## 10. Real-World Reference Incidents

### 10.1 Codecov Supply Chain (2021)

Codecov's bash uploader was compromised to exfiltrate CI environment variables from thousands of projects. The payload targeted env vars containing cloud credentials, tokens, and SSH keys.

**Lesson**: Pin third-party CI actions/uploaders to a SHA, not a tag. Audit every external script the CI runs.

### 10.2 CircleCI Secret Leak (2023)

CircleCI orb leaked env vars from affected projects. Customers were forced to rotate all secrets.

**Lesson**: Audit orb usage; treat any third-party CI integration as a potential exfil channel; rotate on incident.

### 10.3 LastPass Source Code Theft (2022)

Dev environment compromise exposed source code, which was then used to target a senior dev for credential theft.

**Lesson**: Production secrets live in dev environments too. Scan and harden dev as rigorously as prod.

### 10.4 Capital One (2019)

SSRF on a misconfigured WAF allowed reaching EC2 metadata, retrieving instance-profile creds, and exfiltrating 100M+ records from S3.

**Lesson**: Block IMDSv1; require IMDSv2; constrain SSRF-prone services; least-privilege on instance profiles.

### 10.5 GitHub Actions `tj-actions/changed-files` (2025)

Maintainer account takeover led to a malicious update that exfiltrated CI secrets across thousands of dependent workflows.

**Lesson**: Pin actions to SHA, not tag. Audit high-popularity actions; prefer vendor-maintained over community.

### 10.6 Toyota (2022)

Access key committed to a public repo led to a customer-data breach.

**Lesson**: Pre-commit hooks are the highest-ROI control. A single `gitleaks detect` in pre-commit prevents this class of incident entirely.

### 10.7 Twitch (2021)

A 125GB git repo dump exposed source code and embedded secrets across the entire codebase.

**Lesson**: Scan + rotate after every push to a shared source of truth. Secrets in git history are forever.

---

## 11. Defense Cross-Reference

This playbook is offensive; the defensive counterpart layers controls at every phase:

| Phase | Offensive Action | Defensive Counter |
|-------|------------------|-------------------|
| Breadth scan | gitleaks, trufflehog on history | Pre-commit hooks block at commit; CI scans fail the build |
| Triage & verify | Live API verification | Canary tokens alert on verification |
| Platform exploit | Vault enumeration | Per-path least-privilege policies; audit-device anomaly detection |
| Lateral pivot | Use harvested creds | Short TTLs; OIDC federation; rotation discipline |
| Report | Document blast radius | Provider-side leak detection (GitHub Secret Scanning, GitGuardian, AWS CloudTrail detector) |

The defensive posture should assume eventual exposure and design for blast-radius containment. Secrets will leak; the question is what they grant when they do.

---

## 12. Decision Tree — "Found a Secret, What Next?"

```
Secret candidate found
│
├── Heuristic check: example/test/canary?
│   ├── YES → Document as LOW/INFO; skip verification
│   └── NO → Continue
│
├── Format + entropy check
│   ├── FAIL → Document as LOW (low-entropy placeholder)
│   └── PASS → Continue
│
├── Canary-token check
│   ├── SUSPICIOUS → Document as MEDIUM (honeytoken?); do NOT verify
│   └── CLEAN → Continue
│
├── OPSEC budget available?
│   ├── NO → Restage for tomorrow
│   └── YES → Continue
│
├── Client approval for verification?
│   ├── NO → Document as unverified finding; ask for approval
│   └── YES → Verify with lightest-touch call
│       ├── FAIL → Document as rotated/invalid
│       └── PASS → Continue to platform exploit
│
├── Platform exploit
│   ├── AWS key → STS → Secrets Manager → S3 → RDS
│   ├── Vault token → token lookup → recursive walk
│   ├── K8s SA → kubectl auth can-i → secret dump → RBAC pivot
│   └── CI token → repo enumeration → workflow triggering
│
└── Report
    ├── Mask secret
    ├── Document blast radius
    ├── Track rotation status
    └── Recommend compensating controls
```

---

## 13. Closing Notes

Secret management attack is the discipline of treating credentials as first-class attack surface. The credential itself is rarely the bug — the bug is the architectural assumption that credentials stay where they were put. They don't. They leak through git history, image layers, mobile binaries, JS bundles, log files, env vars, and memory. The offensive playbook scans everywhere; the defensive posture assumes breach and contains blast radius.

The highest-leverage defensive controls, in order:

1. **Pre-commit hooks** — block 80% of leaks at the source
2. **CI scanning** — catch the next 15% that escape pre-commit
3. **Runtime scanning** — catch the last 5%
4. **Short TTLs** — limit the value of any single leaked credential
5. **Least privilege** — limit what a leaked credential can do
6. **Canary tokens** — detect the leak in real time
7. **Rotation discipline** — reduce the half-life of leaked credentials

A mature secret-management program implements all seven. A mature offensive playbook checks all seven for gaps.

---

## Cross-References

- **`skills/secret-management-attack/SKILL.md`** — skill definition and methodology
- **`skills/secret-management-attack/payloads.md`** — every command catalogued by section
- **`skills/secret-management-attack/test-cases.md`** — TC-SM-001 through TC-SM-012
- **`skills/security-review/SKILL.md`** — broader checklist framework
- **`skills/repo-scan/SKILL.md`** — codebase classification input
- **`skills/cloud-security/SKILL.md`** — IAM context for cloud secret findings
- **`skills/container-security/SKILL.md`** — runtime container protection
- **`skills/post-exploitation/SKILL.md`** — host takeover after credential access
- **`skills/anti-forensics/SKILL.md`** — defender-side reconstruction
- **`skills/digital-forensics/SKILL.md`** — defensive counterpart on the same artifact set
- **`skills/supply-chain-security/SKILL.md`** — CI/CD and third-party integration overlap
