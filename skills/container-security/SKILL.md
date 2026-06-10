---
name: container-security
description: "Container security covers the complete lifecycle from image building, registry management, runtime protection, to orchestration platform (Kubernetes) security."
origin: openclaw
version: "0.1.18"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: cloud
  tool_count: 6
  guide_count: 5
  mitre: "TA0008-Lateral Movement"
---




# Skill: Container Security

> **Supplementary Files**:
> - `payloads.md` — Container security testing attack payloads, categorized by image analysis, escape techniques, Kubernetes security, runtime security, registry security, network policies, secret detection, and privilege escalation
> - `test-cases.md` — 11 structured test cases covering image security, container runtime, Kubernetes, networking, and advanced scenarios

## Summary

Container Security skill domain covering cloud operations.

**Tools**: trivy, docker-bench-security, kubeaudit, falco, clair, grype

**Domain**: cloud

**MITRE ATT&CK**: TA0008-Lateral Movement

## Description

Container security covers the complete lifecycle from image building, registry management, runtime protection, to orchestration platform (Kubernetes) security. The core objective is to identify configuration flaws, known vulnerabilities, and privilege abuse in container environments, and to verify the effectiveness of container isolation mechanisms.

Mastering this skill requires a deep understanding of Docker architecture (namespaces, cgroups, union filesystem), Kubernetes RBAC and Network Policy, as well as the underlying principles of container escape. The attacker's perspective focuses on breaking out of container isolation from within to obtain host privileges, while the defender's perspective focuses on trusted image signing, least privilege, and runtime monitoring.

---

## Use Cases

1. **Container Image Vulnerability Assessment** - Scan images for known CVEs, configuration flaws, and hardcoded secrets
2. **Container Escape Testing** - Verify whether privileged containers, mounted volumes, and kernel vulnerabilities can be exploited to escape to the host
3. **Kubernetes Security Audit** - Check RBAC configuration, Pod Security Standards, and Network Policies
4. **CI/CD Shift-Left Security** - Integrate image scanning and security policies into build pipelines
5. **Runtime Anomaly Detection** - Monitor in-container processes, network connections, and filesystem changes
6. **CIS Benchmark Compliance** - Evaluate Docker and Kubernetes configurations against CIS security benchmarks

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **trivy** | All-in-one image/filesystem/repository/K8s configuration scanner | `trivy image nginx:latest` |
| **docker-bench-security** | CIS Docker Benchmark automated checks | `docker-bench-security -c 1,2,3` |
| **kubeaudit** | Kubernetes security configuration audit | `kubeaudit all` |
| **falco** | Runtime behavior monitoring and anomaly detection | `falco -r rules.yaml` |
| **clair** | Static container vulnerability analysis service | `clairctl analyze --image nginx:latest` |
| **grype** | Fast vulnerability scanning with SBOM input support | `grype nginx:latest` |

---

## Methodology

### Attack Chain

```
Image Analysis      Registry Security   Runtime Escape     Orchestration      Host Compromise
(trivy scan,      (Unauthenticated    (Privileged       Attack             (Post-escape
 CVE matching)     access, image       container,        (RBAC abuse,       privilege
                    tampering)         kernel vuln)      ServiceAccount)    escalation)
    |               |                  |                |               |
    v               v                  v                v               v
 Credential       Malicious Image     Namespace        Cluster-level     Root Access
 Leakage          Injection           Breakout         Lateral Movement  (Host Control)
 (Env vars,       (Supply chain       (cgroup/ptrace)  (Secret theft)
  hardcoded keys)  attack)
```

**Phase Details**:

1. **Image Analysis** - Scan image layer filesystems to identify known vulnerabilities (CVEs), sensitive file leakage, and improper configurations
2. **Registry Security** - Detect unauthenticated Docker Registry access, verify image signatures and integrity
3. **Runtime Escape** - Exploit privileged mode, sensitive path mounts (/var/run/docker.sock), and kernel vulnerabilities to break container isolation
4. **Orchestration Platform Attack** - Abuse overly permissive RBAC, default ServiceAccount tokens, and unprotected API Servers
5. **Host Compromise** - Obtain host root privileges from the escaped container, completing lateral movement and persistence

### Defense Perspective

- **Image Signing** - Use cosign/Notary to sign and verify images, preventing supply chain attacks
- **Read-Only Filesystem** - Set container root filesystem to read-only, limiting attacker write capability
- **Network Policy** - Use K8s Network Policy to restrict inter-Pod communication, implementing micro-segmentation
- **Pod Security Standards** - Enforce Restricted/Baseline policies, prohibiting privileged containers
- **Runtime Monitoring** - Use Falco to detect anomalous processes, sensitive file access, and privilege escalation behavior
- **Minimal Base Images** - Use distroless or scratch images to reduce attack surface

---

## Practical Steps

### 1. Image Vulnerability Scanning and Analysis

Use trivy, grype, dockle, and other tools to scan images for CVEs, configuration flaws, and sensitive information leakage.

### 2. Container Escape Detection and Exploitation

Detect container environment indicators, privileged mode, and sensitive mount points; exploit docker.sock mounts and kernel vulnerabilities for escape.

### 3. Kubernetes Security Audit

Enumerate RBAC bindings, ServiceAccount permissions, and Secret mounts; use kubeaudit for automated auditing.

### 4. Runtime Security Monitoring

Check container process capability configurations; use Falco rules to detect shell execution, sensitive file access, and escape behavior.

### 5. CIS Benchmark Compliance Checks

Use docker-bench-security and kube-bench for Docker/Kubernetes security baseline assessment.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

---

## Common Pitfalls

- **Scanning images without checking runtime configuration**: A clean vulnerability scan does not mean a container is secure. A fully patched image running in privileged mode with docker.sock mounted is more dangerous than an outdated image running with least privilege and a read-only filesystem.
- **Ignoring ServiceAccount tokens in Kubernetes**: Every Pod receives an automatically mounted ServiceAccount token by default. If the ServiceAccount has excessive RBAC permissions, any code running in the Pod (including attacker code after exploitation) inherits those cluster-level privileges.
- **Neglecting supply chain verification**: Pulling images by tag (e.g., `nginx:latest`) rather than by digest means the image content can change without notice. An upstream image compromise or tag hijacking can introduce malicious code into your infrastructure without any configuration change on your end.

## Automation and Scripting

Automate container security scanning by integrating trivy into CI/CD pipelines to block builds with Critical/High CVEs from being pushed to production registries. Use kubeaudit in scheduled CronJobs to continuously audit Kubernetes RBAC configurations and alert on deviations. Script falco rule testing by generating expected benign and malicious events in a test cluster and verifying that alerts fire correctly. Build custom Python scripts using the Docker SDK to enumerate all running containers and their mount points for rapid privilege escalation surface assessment.

## Reporting and Documentation

Container security reports should separate findings by layer: image vulnerabilities (CVE list with CVSS scores), runtime configuration issues (privileged mode, cap-add, sensitive mounts), orchestration misconfigurations (RBAC, Network Policies, Pod Security Standards), and supply chain risks (unsigned images, unverified registries). For each container escape finding, document the escape path from inside the container to host access with specific commands and outputs. Include CIS Benchmark compliance scores as a measurable baseline for tracking improvement over time.

## Legal and Ethical Considerations

Container escape testing in shared Kubernetes clusters (multi-tenant environments) carries significant risk of affecting other tenants. Verify that the engagement scope covers escape attempts and coordinate with the cluster operations team to ensure testing occurs in an isolated namespace or during a maintenance window. Container security tools like trivy and kubeaudit are generally safe to run in production for scanning, but active exploitation techniques (escape attempts, privilege escalation) should be performed in dedicated test environments whenever possible.

## Integration with Other Tools

Container security findings connect to multiple adjacent skill domains. Image vulnerability results from trivy feed into vulnerability-assessment for CVE tracking and remediation prioritization. Kubernetes RBAC misconfigurations discovered by kubeaudit inform post-exploitation lateral movement planning. Container escape techniques that reach the host transition to host-level post-exploitation methodology. Cloud metadata access from within containers (via SSRF or direct access) connects to cloud-security assessment of the broader infrastructure.

## Case Studies and Examples

- **docker.sock escape**: A web application container had the Docker socket mounted for "log collection." An attacker who gained RCE in the web app used the Docker CLI to create a new privileged container mounting the host's root filesystem, achieving full host compromise in under 60 seconds.
- **Kubernetes ServiceAccount escalation**: A pod's default ServiceAccount had `cluster-admin` RBAC bindings due to a misconfigured Helm chart. An attacker who compromised the application used the mounted token to read all Secrets across all namespaces, including database credentials and TLS private keys.
- **Supply chain attack via image poisoning**: A development team used `node:latest` as their base image. An upstream compromise of the Node.js Docker image (before it was detected and pulled) would have deployed malicious code to all downstream builds. Shifting to pinned digests and cosign verification prevented this vector.

## Detection and Evasion

Container runtime detection relies on tools like Falco that monitor system calls and alert on anomalous behavior: unexpected shell execution inside containers, sensitive file access (`/etc/shadow`, `/proc/sysrq-trigger`), network connections to unusual destinations, and privilege escalation syscalls. Kubernetes audit logs capture API server requests including RBAC changes, Secret access, and Pod creation events. To evade container security monitoring: use static binaries instead of interpreted scripts, leverage capabilities already present in the container rather than downloading new tools, and perform escape attempts through less commonly monitored kernel system calls. In Kubernetes, use existing ServiceAccount tokens rather than creating new RBAC bindings to avoid API server audit logging.

## Advanced Techniques

Advanced container security testing includes: kernel exploit chains from within containers (CVE-2022-0185, CVE-2024-1086 for netfilter escape), cgroup and namespace manipulation for container breakout, seccomp profile bypass through allowed syscalls, Kubernetes admission controller bypass through direct API server access, and etcd database manipulation for cluster-level persistence. For CI/CD pipeline testing, explore build cache poisoning, dependency confusion attacks, and malicious build argument injection.

## Tool Comparison Matrix

| Tool | Best For | Speed | Coverage | Skill Level |
|------|----------|-------|----------|-------------|
| **trivy** | All-in-one scanning (image/K8s/filesystem) | Fast | Very broad | Beginner |
| **grype** | Fast vulnerability scanning with SBOM | Fast | Broad | Beginner |
| **falco** | Runtime behavior monitoring | Real-time | Broad | Intermediate |
| **kubeaudit** | K8s security configuration audit | Fast | K8s-specific | Beginner |
| **docker-bench-security** | CIS Docker Benchmark checks | Fast | Docker-specific | Beginner |
| **clair** | Static vulnerability analysis service | Moderate | Broad | Intermediate |

## Performance and Remediation

Image scanning performance varies significantly by tool and image size. Trivy and grype complete scans of typical application images (500MB-2GB) in 10-30 seconds, while larger base images with extensive package lists can take 2-5 minutes. For large-scale deployments, use trivy in server mode with a centralized vulnerability database. Falco runtime monitoring has minimal performance impact (<2% CPU overhead). Prioritize container security remediation in order: fix Critical CVEs in base images immediately, remove privileged mode and docker.sock mounts, enforce Pod Security Standards, implement Network Policies, deploy image signing (cosign/Notary) in CI/CD, and rotate all ServiceAccount tokens after any suspected compromise.

## Hacker Laws

| Law | Application in Container Security |
|-----|-----------------------------------|
| **Defense in Depth** | Containers are not a security boundary. Image scanning + signature verification + runtime monitoring + network policies must be layered together; no single layer can be trusted as the sole defense |
| **Least Privilege** | Containers should not run as root by default, should not mount docker.sock, and should not use privileged mode. Every unnecessary permission is an escape vector |
| **Assume Breach** | Design monitoring systems assuming the container has already been compromised. Falco detects anomalous processes, file access, and network connections for rapid response when escape occurs |
| **Supply Chain Trust** | Images pass through multiple layers from build to runtime. Pulling images without verifying signatures means trusting all upstream sources, which breeds supply chain attacks |
| **Minimize Attack Surface** | Distroless images have no shell or package manager; even if an attacker is inside the container, they lack tools. Reducing attack surface is more effective than adding defenses |

---

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md
  **Related skills**: skills/cloud-security/SKILL.md, skills/post-exploitation/SKILL.md
  **External resources**:
- [Trivy Official Documentation](https://aquasecurity.github.io/trivy/) - All-in-one scanner reference
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) - Docker security configuration baseline
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) - K8s security configuration baseline
- [Falco Official Documentation](https://falco.org/docs/) - Runtime security monitoring rule authoring
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) - Pod Security Standards and RBAC
- [Container Security (Liz Rice)](https://containersecurity.tech/) - Underlying principles of container isolation
