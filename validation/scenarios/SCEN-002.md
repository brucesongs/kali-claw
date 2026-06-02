# SCEN-002: Cloud Environment Attack Chain

| Field | Value |
|-------|-------|
| **ID** | SCEN-002 |
| **Name** | Cloud Environment Attack Chain |
| **Type** | Attack Chain (Cloud) |
| **Kill Chain Phase** | Reconnaissance → Initial Access → Privilege Escalation → Container Escape → Supply Chain |
| **Difficulty** | Advanced |
| **Estimated Duration** | 4-6 hours |

---

## Objective

Simulate a cloud-based attack chain from information leakage discovery through container escape and supply chain compromise, targeting an authorized cloud environment (AWS/Azure/GCP).

---

## Skill Chain

```
osint → cloud-security → container-security → api-security → supply-chain-security
```

| Step | Skill Domain | Key Actions | Tools |
|------|-------------|-------------|-------|
| 1 | osint | Cloud resource discovery: S3 bucket enumeration, GitHub secret leaks, DNS records | amass, s3scanner, trufflehog |
| 2 | cloud-security | Cloud exploitation: IAM abuse, metadata service attacks, S3 ACL bypass | pacu, scoutsuite, cloud-enum |
| 3 | container-security | Container escape: Docker socket exploitation, K8s RBAC abuse, pod security | trivy, kube-bench, kubeaudit |
| 4 | api-security | API exploitation: authentication bypass, parameter tampering, rate limiting tests | burpsuite, arjun, ffuf |
| 5 | supply-chain-security | Supply chain attack: dependency confusion, CI/CD pipeline poisoning | safety, npm-audit, grype |

---

## Prerequisites

- Authorized cloud environment (sandbox or test account)
- Cloud CLI tools configured (aws, az, gcloud)
- kubectl access to test cluster
- Scope limited to non-production resources

---

## Execution Steps

### Phase 1: Cloud OSINT (osint)

1. S3 bucket discovery: `s3scanner -d target.com`
2. GitHub organization scanning for leaked secrets: `trufflehog github --org target-org`
3. DNS reconnaissance for cloud resources: `amass enum -d target.com`
4. Cloud metadata exposure check on web servers

### Phase 2: Cloud Security Exploitation (cloud-security)

1. IAM enumeration: `pacu -m iam__enum_users_roles_policies`
2. S3 bucket access testing: try public access to discovered buckets
3. Instance metadata service: test SSRF to `169.254.169.254`
4. Cloud security audit: `scoutsuite aws`

### Phase 3: Container Security (container-security)

1. Container image scanning: `trivy image target-image:latest`
2. Kubernetes RBAC audit: `kubeaudit all`
3. Test for Docker socket exposure: `curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json`
4. K8s pod security policy check: `kube-bench run`

### Phase 4: API Security Testing (api-security)

1. API endpoint discovery from previous phases
2. Authentication testing: missing auth, weak tokens, API key leakage
3. Parameter tampering: mass assignment, IDOR on API objects
4. Rate limiting verification: `ffuf -u https://api.target.com/endpoint -w payloads.txt -rate 1000`

### Phase 5: Supply Chain Verification (supply-chain-security)

1. Dependency audit: `safety check` / `npm audit`
2. Container base image vulnerability check: `grype image:latest`
3. CI/CD pipeline security review
4. Software integrity verification: checksums, signing

---

## Verification Points

- [ ] At least one cloud misconfiguration discovered and documented
- [ ] Container escape vector identified OR documented why not possible
- [ ] API vulnerability with PoC (authentication bypass, IDOR, etc.)
- [ ] Dependency vulnerability found with CVE reference
- [ ] All findings mapped to MITRE ATT&CK Cloud matrix

---

## Data Handoff Between Skills

| From | To | Data Format |
|------|----|-------------|
| osint | cloud-security | S3 bucket URLs, leaked credentials, cloud resource IPs |
| cloud-security | container-security | Instance metadata, container registry URLs |
| container-security | api-security | Exposed API endpoints from containers |
| api-security | supply-chain-security | API dependencies, third-party integrations |
