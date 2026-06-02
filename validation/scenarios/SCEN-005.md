# SCEN-005: Purple Team Defense Validation

| Field | Value |
|-------|-------|
| **ID** | SCEN-005 |
| **Name** | Purple Team Defense Validation |
| **Type** | Defense Chain (Purple Team) |
| **Kill Chain Phase** | Assessment → Detection → Hardening → Monitoring → Verification |
| **Difficulty** | Advanced |
| **Estimated Duration** | 4-6 hours |

---

## Objective

Execute a purple team exercise focusing on the defensive perspective: assess vulnerabilities, implement security hardening, deploy monitoring, and verify the effectiveness of all controls through re-testing.

---

## Skill Chain

```
vulnerability-assessment → security-review → security-misconfiguration → logging-monitoring → container-security
```

| Step | Skill Domain | Key Actions | Tools |
|------|-------------|-------------|-------|
| 1 | vulnerability-assessment | Automated + manual vulnerability assessment, risk rating | openvas, nuclei, nikto |
| 2 | security-review | OWASP Top 10 code audit, secrets detection, dependency scan | semgrep, sonarqube, trufflehog |
| 3 | security-misconfiguration | Hardening: default credentials, verbose errors, CORS, headers | nikto, nuclei, testssl |
| 4 | logging-monitoring | Deploy monitoring: log collection, alert rules, SIEM integration | ELK stack, auditd, ossec |
| 5 | container-security | Container hardening: image scanning, runtime policy, RBAC | trivy, falco, kube-bench |

---

## Prerequisites

- Target environment (application + infrastructure) for assessment
- Administrative access for hardening changes
- Monitoring infrastructure (SIEM/log server)
- Approval for security changes in the environment

---

## Execution Steps

### Phase 1: Vulnerability Assessment (vulnerability-assessment)

1. Automated scan: `nuclei -u https://target.com -t cves/,vulnerabilities/`
2. Infrastructure scan: `openvas -q -T html -o report.html target_ip`
3. Web application scan: `nikto -h https://target.com`
4. Risk-rate all findings using CVSS: document severity, exploitability, impact
5. Prioritize remediation by risk score

### Phase 2: Security Review (security-review)

1. Source code audit: `semgrep --config auto src/`
2. Dependency vulnerability scan: `safety check` / `npm audit`
3. Secrets detection: `trufflehog filesystem src/`
4. OWASP Top 10 checklist review
5. Document code-level vulnerabilities with remediation guidance

### Phase 3: Security Hardening (security-misconfiguration)

1. Fix default credentials on all services
2. Remove verbose error messages and stack traces
3. Configure security headers: CSP, HSTS, X-Frame-Options
4. Fix CORS misconfigurations
5. TLS hardening: remove weak ciphers, enable HSTS

### Phase 4: Monitoring Deployment (logging-monitoring)

1. Configure application logging (access logs, error logs, audit logs)
2. Set up centralized log collection (ELK/Graylog)
3. Create alert rules for: brute force, injection attempts, privilege escalation
4. Configure log retention and rotation
5. Test alert pipeline with simulated attack traffic

### Phase 5: Container Security (container-security)

1. Base image scanning: `trivy image app:latest`
2. Runtime security policy: configure Falco rules
3. Kubernetes hardening: `kube-bench run` and remediate
4. RBAC review: least privilege for all service accounts
5. Network policy enforcement: restrict pod-to-pod communication

---

## Verification Points

- [ ] All critical/high vulnerabilities remediated or risk-accepted
- [ ] Zero secrets in source code (verified by trufflehog)
- [ ] Security headers properly configured (verified by curl)
- [ ] Alert pipeline triggers on simulated attacks
- [ ] Container images pass vulnerability scan with zero critical findings

---

## Data Handoff Between Skills

| From | To | Data Format |
|------|----|-------------|
| vulnerability-assessment | security-review | Vulnerability list with locations and severity |
| security-review | security-misconfiguration | Code findings requiring config changes |
| security-misconfiguration | logging-monitoring | Hardened config → what to monitor |
| logging-monitoring | container-security | Log infrastructure ready → container log integration |

---

## Metrics

| Metric | Before | Target | Measurement |
|--------|--------|--------|-------------|
| Critical/High vulns | Baseline count | 0 | Vulnerability scan |
| Secrets in code | Baseline count | 0 | Trufflehog scan |
| Security headers missing | Baseline count | 0 | curl header check |
| Alert coverage | 0% | 80%+ | Simulated attack test |
| Container image vulns | Baseline count | 0 critical | Trivy scan |
