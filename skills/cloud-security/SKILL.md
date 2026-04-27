# Skill: Cloud Security

> **Supplementary Files**:
> - `payloads.md` -- Cloud security attack payloads organized by category (AWS/Azure/GCP enumeration, IAM analysis, S3 exposure, metadata exploitation, container/K8s exploitation)
> - `test-cases.md` -- Structured test cases covering cloud reconnaissance, IAM & access testing, storage security, network security, and advanced exploitation

## Description

Cloud security covers security assessment for major cloud platforms including AWS, Azure, and GCP, with core focus on IAM misconfiguration detection, storage bucket exposure scanning, metadata service attacks, container escape, and Kubernetes RBAC auditing. The fundamental difference between cloud environments and traditional networks is: blurred boundaries, API-driven everything, and identity as the perimeter.

Mastering this skill requires deep understanding of cloud service architecture and the Shared Responsibility Model, the ability to identify cloud misconfigurations, abuse overly permissive IAM policies, and leverage metadata services and SSRF chains to complete attack chains from information leakage to lateral movement.

---

## Use Cases

1. **Cloud Environment Security Assessment** - Conduct comprehensive security audits of AWS/Azure/GCP accounts to discover configuration flaws and excessive permissions
2. **IAM Permission Audit** - Enumerate and analyze IAM users, roles, and policies to identify over-privilege and privilege escalation paths
3. **Storage Bucket Exposure Detection** - Scan publicly accessible S3/Azure Blob/GCS storage buckets, assess data leakage risk
4. **Container and Orchestration Security** - Assess Docker container escape risks and Kubernetes cluster RBAC configurations
5. **Cloud Metadata Attack Verification** - Test IMDSv1 exposure risk and IAM credential theft feasibility through SSRF

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **pacu** | AWS penetration testing framework, modular IAM enumeration and exploitation | `pacu -> run iam__enum_users` |
| **scoutsuite** | Multi-cloud security audit, generates compliance reports | `scout aws -p default` |
| **awscli** | AWS CLI operations, IAM/S3/EC2 manual enumeration | `aws iam list-users --output json` |
| **s3scanner** | S3 bucket public access scanning | `s3scanner scan --bucket target-bucket` |
| **kubeaudit** | Kubernetes security audit, detects RBAC and Pod configuration issues | `kubeaudit all` |
| **trivy** | Container image and IaC vulnerability scanning | `trivy image alpine:latest` |

---

## Methodology

### Attack Chain

```
Cloud Asset Discovery -> IAM Enumeration -> Storage Bucket Exposure -> Network Misconfig
(awscli, cloud enum)     (pacu, iam__enum)   (s3scanner, awscli)       (scoutsuite, nmap)
      |                      |                      |                      |
      v                      v                      v                      v
Metadata Attack       Container Security      Kubernetes Audit        Lateral Movement
(IMDSv1 SSRF,        Assessment              (kubeaudit, RBAC)       (stolen credentials,
 credential theft)    (trivy, docker escape)                           cross-service exploit)
```

**Phase Details**:

1. **Cloud Asset Discovery** - Enumerate EC2, S3, Lambda, RDS, and other resources in AWS accounts, build cloud asset inventory
2. **IAM Enumeration** - Analyze users, roles, policies, and trust relationships, identify privilege escalation paths and over-privilege
3. **Storage Bucket Exposure** - Detect publicly accessible S3 buckets, assess data leakage scope and sensitive information exposure
4. **Network Misconfiguration** - Audit security groups, NACLs, VPC configurations, discover overly permissive network rules
5. **Metadata Attacks** - Leverage SSRF to access IMDSv1 and obtain IAM temporary credentials
6. **Container Security Assessment** - Scan container image vulnerabilities, detect privileged containers and mount risks
7. **Kubernetes Audit** - Check RBAC rules, Pod security policies, and secrets management

### Defense Perspective

- **Least Privilege IAM** - Each role should only be granted the precise permissions needed to complete its tasks; disable wildcard `*:*`
- **Encryption at Rest and in Transit** - S3 SSE-KMS encryption, RDS TDE, TLS enforcement, full-chain data protection
- **Security Group Minimization** - Inbound rules should only open necessary ports and IP ranges; outbound rules restricted by default
- **CSPM Continuous Monitoring** - Use ScoutSuite or AWS Config for continuous detection of configuration drift and violations
- **IMDSv2 Enforcement** - Disable IMDSv1, require PUT request to obtain token, block SSRF metadata attacks
- **CloudTrail Full Logging** - Enable multi-region, global service logging; record all API calls for forensics

---

## Practical Steps

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

### AWS IAM Enumeration and Privilege Escalation

Use pacu or awscli to enumerate IAM users, roles, and policies, scan for privilege escalation paths. Key operations: `set_keys` to configure credentials, `iam__privesc_scan` to discover escalation paths, `sts get-caller-identity` to confirm current identity.

### S3 Storage Bucket Security Assessment

Check bucket ACLs and policies, test anonymous access, bulk scan public buckets. Core commands are in the "S3 bucket enumeration" section of `payloads.md`.

### Multi-Cloud Security Audit

Use ScoutSuite for comprehensive security audits of AWS/Azure/GCP, with focus on IAM policies, bucket public status, security group rules, and encryption configurations.

### Container and Kubernetes Security

Use trivy to scan image vulnerabilities and IaC configurations, use kubeaudit to audit RBAC rules and Pod security contexts. Detect privileged containers and anonymous bindings.

---

## Hacker Laws

| Law | Manifestation in Cloud Security |
|------|---------------------------------|
| **Least Privilege** | `*:*` in IAM policies is the biggest enemy. Each role should only have the precise permissions needed for its function; pacu's privesc_scan is specifically designed to find paths that violate this principle |
| **Assume Breach** | Assume Breach means cloud architecture design must assume attackers have already gained initial access. VPC segmentation, IMDSv2, temporary credentials (STS) are all defenses based on this assumption |
| **Minimize Attack Surface** | Public S3 buckets, open security groups, IMDSv1 reachability — each is an unnecessary attack surface. The core of ScoutSuite reports is enumerating these overexposures |
| **Defense in Depth** | IAM alone is not enough. Need IAM + encryption + network segmentation + log monitoring + CSPM in multiple layers, ensuring a single misconfiguration does not lead to total compromise |
| **Trust but Verify** | Do not trust cloud provider default configurations. S3 is not public by default but policies may change it to public; IMDSv1 is enabled by default but can be upgraded to v2 — always verify |
| **First Principles** | Understand how cloud APIs work. Without understanding IAM policy evaluation logic, you cannot understand privilege escalation; without understanding metadata services, you cannot understand SSRF credential theft |

---

## Learning Resources

- [Pacu Official Repository](https://github.com/RhinoSecurityLabs/pacu) - AWS penetration testing framework, modular attack tools
- [ScoutSuite Official Documentation](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security audit tool
- [Trivy Official Documentation](https://aquasecurity.github.io/trivy/) - Container and IaC vulnerability scanning
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) - Authoritative guide for IAM security configuration
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/) - K8s security model and RBAC
- [Cloud Security Alliance](https://cloudsecurityalliance.org/) - Cloud security industry standards and whitepapers

---

**Supplementary files for this skill**: payloads.md, test-cases.md
**Related skills**: skills/container-security/SKILL.md, skills/network-pentest/SKILL.md
**External resources**: https://github.com/RhinoSecurityLabs/pacu, https://github.com/nccgroup/ScoutSuite, https://aquasecurity.github.io/trivy/, https://cloudsecurityalliance.org/
