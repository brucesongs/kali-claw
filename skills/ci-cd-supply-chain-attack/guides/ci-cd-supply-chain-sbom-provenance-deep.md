# CI/CD Supply Chain — SBOM, Provenance, and Attestation Deep Dive

> Deep-dive companion to `skills/ci-cd-supply-chain-attack/SKILL.md`.
>
> Audience: pentesters who need to assess and recommend software supply chain integrity controls — SBOM (Software Bill of Materials), SLSA framework, Sigstore / Cosign / Rekor, in-toto attestations, Syft / Trivy SBOM generation, Conforma / GUAC graph, OpenSSF Scorecard, and real-world Kubernetes image pull policy bypasses. This guide covers the defender's durable fixes for the supply chain attack classes documented in the rest of the skill.

---

## Overview

The defender's durable fix for supply chain attacks is not "be more careful" — it is **provenance verification**. Every artifact (binary, container, package) should carry cryptographically-signed metadata describing how it was built, from what source, by what workflow, with what dependencies. Consumers verify this metadata before use. The goal is end-to-end: a deployment system should refuse to run an artifact that lacks a valid provenance attestation, regardless of how the artifact arrived.

This guide covers the seven technologies that make up the modern supply-chain integrity stack:

1. **SLSA framework** (Supply Chain Levels for Software Artifacts) — the maturity model.
2. **Sigstore / Cosign / Rekor** — the signature, signing tool, and transparency log.
3. **in-toto attestations** — the metadata format.
4. **Syft / Trivy** — SBOM (Software Bill of Materials) generators.
5. **Conforma / GUAC** — graph-based supply chain analysis.
6. **OpenSSF Scorecard** — security posture scoring for open-source projects.
7. **Kubernetes Image Pull Policy bypass** — a real-world failure mode that provenance fixes.

For pentesters, the value of this guide is two-fold: (1) you will encounter these technologies in client environments and must know how to assess their correctness, and (2) every finding you write should pair the attack with the provenance-based fix. A finding that says "fix: implement SLSA Level 3 with cosign verification in your admission controller" is far more actionable than "fix: be more careful about dependencies".

---

## 1. SLSA Framework (Levels 1–4)

### What SLSA Is

SLSA (pronounced "salsa") is a framework from Google / OpenSSF that defines increasing levels of supply chain integrity. Each level adds a control that closes a class of attack. SLSA is to supply chain what maturity models like CMMI are to process — a ladder, not a binary.

### SLSA Levels

| Level | Requirement | Closes |
|-------|-------------|--------|
| **L1** | Build process documented (provenance exists) | "Where did this come from?" |
| **L2** | Hosted build service + signed provenance | Tampering by build-system insider |
| **L3** | Hardened, isolated builds + non-forgeable provenance | Build-system compromise (SolarWinds-class) |
| **L4** | Two-party reviewed build + reproducible | Malicious insider / maintainer (xz-class) |

### SLSA v1.0 Spec

SLSA v1.0 (released April 2023) simplified the framework to focus on build integrity. The four levels remain. The key concept is **provenance**: an attestation that records the build's source, build system, and build parameters. The provenance must be:

- **Authenticated** (signed by the build system).
- **Non-forgeable** (an attacker cannot construct a valid provenance for an artifact they didn't build).
- **Verifiable** (consumers can independently verify).

### Hands-on: Generate SLSA L3 Provenance for a GitHub Actions Build

GitHub's `slsa-framework/slsa-github-generator` action generates provenance for artifacts built in GitHub Actions. For a container image:

```yaml
# .github/workflows/build-and-sign.yml
name: Build and Sign
on: { push: { tags: ['v*'] } }
permissions: { contents: read, id-token: write, packages: write }
jobs:
  build:
    runs-on: ubuntu-latest
    outputs: { digest: ${{ steps.build.outputs.digest }} }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          provenance: true   # Docker BuildKit provenance
      - uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
        with:
          image: ghcr.io/${{ github.repository }}
          digest: ${{ steps.build.outputs.digest }}
          registry-username: ${{ github.actor }}
        secrets:
          registry-password: ${{ secrets.GITHUB_TOKEN }}

  verify:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: |
          cosign verify \
            --certificate-identity https://github.com/${{ github.repository }}/.github/workflows/build-and-sign.yml@refs/tags/${{ github.ref_name }} \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            ghcr.io/${{ github.repository }}@${{ needs.build.outputs.digest }}
```

### Pentester's Assessment

When assessing a client's SLSA posture:

- **L1** (most orgs): build docs exist, but no signed provenance. Vulnerable to all classes.
- **L2** (some orgs): signed provenance from a hosted build (GitHub Actions, GitLab CI). Closes build-docs tampering.
- **L3** (few orgs): isolated builds (ephemeral runners, no shared state), non-forgeable provenance. Closes SolarWinds-class build compromise.
- **L4** (very few orgs): two-party review + reproducible builds. Closes xz-class maintainer compromise.

The gap between L2 and L3 is the most-common finding: orgs sign their artifacts but use self-hosted runners with persistent state, which means an attacker who compromises one build can forge provenance for the next. The fix is ephemeral runners (Actions Runner Controller on Kubernetes, or AWS AMI-based runners).

---

## 2. Sigstore / Cosign / Rekor

### Sigstore

Sigstore is a Linux Foundation project (founded 2021 by Google, Red Hat, Purdue University) that provides free, open-source code signing. The three components:

- **Cosign**: the signing / verification CLI.
- **Rekor**: an append-only transparency log of signatures.
- **Fulcio**: a short-lived certificate authority that issues 10-minute signing certs to OIDC-authenticated identities (e.g., GitHub Actions).

The key innovation is **keyless signing**: there is no long-lived signing key to steal. The signer authenticates to Fulcio via OIDC (e.g., GitHub Actions's `id-token: write`), Fulcio issues a 10-minute cert bound to the OIDC identity, and the signer signs with that cert. The signature and cert are published to Rekor's transparency log.

### Cosign Hands-on

```bash
# Install
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo install cosign-linux-amd64 /usr/local/bin/cosign

# Keyless sign a container image (from GitHub Actions)
cosign sign --yes ghcr.io/myorg/app@sha256:abc...

# Verify a signed image (with identity binding)
cosign verify \
  --certificate-identity "https://github.com/myorg/repo/.github/workflows/build.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/app@sha256:abc...

# Sign arbitrary artifacts (binaries, packages)
cosign sign-blob --yes --output-certificate cert.pem --output-signature sig.bin \
  ./mybinary
cosign verify-blob --certificate cert.pem --signature sig.bin \
  --certificate-identity "https://github.com/myorg/repo/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ./mybinary
```

### Rekor Transparency Log

Rekor is an append-only Merkle tree of all signatures. Consumers can query Rekor to verify that a signature was published (and when). The transparency property means an attacker cannot forge a signature retroactively without leaving a trace.

```bash
# Search Rekor for signatures on a hash
rekor-cli search --sha sha256:abc123...
```

### Pentester's Assessment

- **No Sigstore usage**: artifacts are unsigned. Critical finding — trivially forgeable.
- **Cosign with long-lived keys**: better than nothing, but the key is the SPOF. If compromised, all artifacts can be re-signed.
- **Cosign keyless + identity binding**: the gold standard. Verify that consumers enforce `--certificate-identity` (most orgs don't, which means any GitHub Actions workflow can sign anything).

---

## 3. in-toto Attestations

### What in-toto Is

in-toto is a metadata format (CNCF graduated project) for describing a supply chain as a sequence of steps, each with a signed attestation. Where SLSA defines the maturity model and Sigstore provides the crypto primitives, in-toto defines the **metadata format** that ties them together.

The SLSA provenance format is itself an in-toto statement. The current spec (in-toto v1.0 statements) is:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "ghcr.io/myorg/app", "digest": { "sha256": "abc..." } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": { ... },
    "runDetails": { ... }
  }
}
```

### Hands-on: Generate an in-toto SBOM Attestation

```bash
# Generate an SBOM with Syft, attach as a cosign attestation
syft ghcr.io/myorg/app@sha256:abc... -o spdx-json > sbom.spdx.json

# Attach the SBOM as an in-toto attestation to the image
cosign attest --yes --predicate sbom.spdx.json \
  --type spdxjson \
  ghcr.io/myorg/app@sha256:abc...

# Verify the SBOM attestation
cosign verify-attestation \
  --certificate-identity "https://github.com/myorg/repo/.github/workflows/build.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type spdxjson \
  ghcr.io/myorg/app@sha256:abc...
```

---

## 4. SBOM Generation — Syft / Trivy

### Syft

Syft (from Anchore) is a CLI tool that generates SBOMs from container images, filesystems, and archives. Output formats include SPDX, CycloneDX, and Syft's own JSON.

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM from a container image
syft ghcr.io/myorg/app:v1.0.0 -o spdx-json > sbom.spdx.json
syft ghcr.io/myorg/app:v1.0.0 -o cyclonedx-json > sbom.cyclonedx.json

# Generate SBOM from a directory (good for source repos)
syft dir:. -o spdx-json > sbom.json
```

### Trivy

Trivy (from Aqua Security) is a vulnerability scanner that also generates SBOMs. Trivy is the standard for Kubernetes admission controllers because of its speed and accuracy.

```bash
# Install
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM + vulnerability scan in one shot
trivy image --format spdx-json --output sbom.spdx.json ghcr.io/myorg/app:v1.0.0
trivy image --format json --output vulns.json ghcr.io/myorg/app:v1.0.0

# Scan a Kubernetes cluster
trivy k8s --report summary

# Scan IaC (Terraform, CloudFormation, Kustomize)
trivy config ./terraform/
```

### Hands-on: CI Integration

```yaml
# .github/workflows/sbom.yml
name: Generate SBOM
on: [push, pull_request]
jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/myorg/app:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json
          upload-artifact: true
          upload-attestation: true   # uploads as GitHub artifact attestation
```

---

## 5. GUAC (Graph for Understanding Artifact Composition) and Conforma

### GUAC

GUAC (from Kusari / Google / OpenSSF) ingests SBOMs, SLSA provenance, and vulnerability databases into a graph database. The graph enables queries like: "Which of my running containers contain log4j?", "Which of my artifacts were built by a workflow that used an action that was later compromised?".

```bash
# Install
go install github.com/guacsec/guac/cmd/guaccollect@latest
go install github.com/guacsec/guac/cmd/guacone@latest

# Ingest SBOMs and provenance into the graph
guaccollect files --deps ./sboms/
# Query: which artifacts are affected by CVE-2021-44228 (log4shell)?
guacone query vuln CVE-2021-44228
# Query: which artifacts passed through a given builder?
guacone query path --from ghcr.io/myorg/app --to github.com/myorg/repo
```

### Conforma (formerly conftest)

Conforma is a policy engine that evaluates Kubernetes manifests and OCI artifacts against Open Policy Agent (OPA) policies. It's commonly used in admission controllers to enforce that images are signed, have valid provenance, and have acceptable SBOMs.

```rego
# conforms-policies/signed.rego
package main

deny[msg] {
  some i
  input[i].kind == "Pod"
  container := input[i].spec.containers[_]
  not image_signed(container.image)
  msg := sprintf("image not signed: %s", [container.image])
}

image_signed(img) {
  # cosign verification done by the admission webhook
  # this is a placeholder; real impl uses Kyverno / cosign webhook
  true
}
```

---

## 6. OpenSSF Scorecard

OpenSSF Scorecard is a CLI that scores open-source projects on a set of supply-chain security checks. It's the standard for evaluating third-party dependencies.

```bash
# Install
go install github.com/ossf/scorecard/v5@latest

# Score a public repo
scorecard --repo=https://github.com/sigstore/cosign

# Score across all of an org's dependencies (with all-checks)
for repo in $(cat dependencies.txt); do
  scorecard --repo=$repo --format=json >> scores.jsonl
done
```

The 13 checks include: Branch-Protection, Code-Review, Dangerous-Workflow, Dependency-Update-Tool, Maintained, Pinned-Dependencies, SAST, SBOM, Security-Policy, Signed-Releases, Token-Permissions, Vulnerabilities, CII-Best-Practices. Each is scored 0–10.

### Pentester's Assessment

When assessing a client's third-party risk:

- **No Scorecard usage**: dependencies are unvetted.
- **Scorecard only on new deps**: org has no continuous evaluation — once a dependency is added, it's never re-scored.
- **Scorecard + Kyverno policy blocking < 7**: gold standard.

---

## 7. Real-World Failure: Kubernetes Image Pull Policy Bypass

### The Failure Mode

The default `imagePullPolicy: IfNotPresent` means Kubernetes reuses a locally-cached image if the tag matches. An attacker who can plant a malicious image in the local cache (via a compromised node, a malicious init container, or a CI-pushed image with the same tag) can bypass pull-time verification.

Worse: `imagePullPolicy: Always` does NOT help if the admission controller does not enforce signature verification. The image is pulled, but its signature is never checked.

### The Fix: Kyverno / OPA Gatekeeper with Cosign Verification

```yaml
# kyverno-policy.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/*/.github/workflows/*"
                    issuer: "https://token.actions.githubusercontent.com"
          mutateDigest: true   # pins to immutable digest
```

With `mutateDigest: true`, Kyverno rewrites the pod's image reference to the immutable digest (`@sha256:abc...`) before the kubelet pulls, defeating tag-replay attacks.

### Hands-on: Test the Admission Controller

```bash
# Try to deploy an unsigned image (should be rejected)
kubectl run evil --image=ghcr.io/myorg/evil:v1.0.0
# Expected: Error from server: admission webhook "verify-image-signatures" denied the request

# Try to deploy a signed image (should be allowed, mutated to digest)
kubectl run good --image=ghcr.io/myorg/app:v1.0.0
# Expected: pod/good created; image rewritten to @sha256:abc...
kubectl get pod good -o jsonpath='{.spec.containers[0].image}'
```

---

## Hands-on: End-to-End Provenance Assessment

### Step-by-step: Audit a Client's Provenance Posture

```bash
# 1. Do artifacts carry signatures?
for img in $(kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u); do
  cosign verify --certificate-identity "*" --certificate-oidc-issuer "*" "$img" 2>&1 | grep -q "Verified" \
    && echo "SIGNED: $img" || echo "UNSIGNED: $img"
done

# 2. Are SBOMs generated and stored?
gh api /repos/myorg/app/attestations --jq '.attestations[].predicate_type' 2>/dev/null
syft ghcr.io/myorg/app:v1.0.0 -o json | jq '.artifacts | length'

# 3. Is SLSA provenance attached?
cosign verify-attestation --type slsaprovenance \
  --certificate-identity "*" --certificate-oidc-issuer "*" \
  ghcr.io/myorg/app:v1.0.0

# 4. Does the admission controller enforce signatures?
kubectl get clusterpolicy -o json | jq '.items[] | select(.spec.validationFailureAction == "Enforce")'

# 5. Are runners ephemeral?
gh api /repos/myorg/app/actions/runners --jq '.runners[] | .labels[].name' | sort -u
# Expected: "self-hosted", "ephemeral", "kubernetes" — NOT persistent VMs
```

### Step-by-step: Build the Provenance Pipeline (Engagement Deliverable)

The engagement deliverable is a CI pipeline that produces signed, provenance-attested artifacts. Template:

```yaml
name: Release
on: { push: { tags: ['v*'] } }
permissions: { contents: read, id-token: write, packages: write, attestations: write }
jobs:
  build:
    runs-on: ubuntu-latest
    outputs: { digest: ${{ steps.build.outputs.digest }} }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          provenance: true
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
      - uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/${{ github.repository }}:${{ steps.build.outputs.digest }}
          format: spdx-json
          upload-attestation: true
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
        with:
          image: ghcr.io/${{ github.repository }}
          digest: ${{ steps.build.outputs.digest }}
          registry-username: ${{ github.actor }}
        secrets: { registry-password: ${{ secrets.GITHUB_TOKEN }} }
```

---

## References

1. SLSA Framework — Specification v1.0 — https://slsa.dev/spec/v1.0/
2. SLSA — Build Levels — https://slsa.dev/spec/v1.0/levels
3. Sigstore — Project home — https://www.sigstore.dev/
4. Cosign — Documentation — https://docs.sigstore.dev/cosign/
5. Rekor — Transparency log — https://docs.sigstore.dev/rekor/
6. Fulcio — Short-lived CA — https://docs.sigstore.dev/fulcio/
7. in-toto — Attestation framework — https://in-toto.io/
8. in-toto Statement v1 — https://github.com/in-toto/attestation/blob/main/spec/README.md
9. Syft — SBOM generator — https://github.com/anchore/syft
10. Trivy — Vulnerability + SBOM scanner — https://github.com/aquasecurity/trivy
11. GUAC — Graph for Understanding Artifact Composition — https://guac.sh/
12. Conforma (formerly conftest) — Policy engine — https://github.com/opensourcecorp/conforma
13. OpenSSF Scorecard — https://github.com/ossf/scorecard
14. Kyverno — verifyImages policy — https://kyverno.io/docs/policies/verify-images/
15. OPA Gatekeeper — admission control — https://github.com/open-policy-agent/gatekeeper
16. Kubernetes — imagePullPolicy documentation — https://kubernetes.io/docs/concepts/containers/images/
17. CISA — Software Supply Chain Security Guide (ESF) — https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain
18. Google SRE — Build Provenance chapter — https://sre.google/sre-book/
19. NIST — Software Supply Chain Security (SP 800-218 SSDF) — https://csrc.nist.gov/Projects/ssdf
20. GitHub Artifact Attestations — https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds
