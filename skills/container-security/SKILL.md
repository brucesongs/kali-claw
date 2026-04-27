# Skill: Container Security

> **Supplementary Files**:
> - `payloads.md` — Container security testing attack payloads, categorized by image analysis, escape techniques, Kubernetes security, runtime security, registry security, network policies, secret detection, and privilege escalation
> - `test-cases.md` — 11 structured test cases covering image security, container runtime, Kubernetes, networking, and advanced scenarios

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
