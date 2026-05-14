# Council Test Cases

## Test Case Summary

| ID | Name | Scenario | Status |
|----|------|----------|--------|
| TC-CL-001 | Web Application Security Review | E-commerce platform with payment flow | Active |
| TC-CL-002 | Cloud Architecture Security Assessment | Multi-cloud K8s deployment | Active |
| TC-CL-003 | Mobile Application Security Evaluation | Fintech app with biometric auth | Active |
| TC-CL-004 | Incident Response Decision Simulation | Active breach with lateral movement | Active |

Total: 4 test cases

---

## TC-CL-001: Web Application Security Review

**Objective**: Validate council analysis produces balanced attack/defense/audit perspectives for a web application security review

**Scenario**: E-commerce platform with payment processing, user authentication, product catalog, and admin panel. PCI-DSS compliance required.

**Phase 1 — Scope Definition**

```
GIVEN: E-commerce platform (shop.example.com)
  - Tech stack: Node.js + Express, PostgreSQL, Redis session store
  - Features: user accounts, payment flow (Stripe integration), admin panel, product search
  - Compliance: PCI-DSS Level 1, GDPR
WHEN: defining council scope
THEN: scope document includes:
  - Systems in scope: web app, API, database, payment integration, admin panel
  - Compliance requirements: PCI-DSS (12 requirements), GDPR (data handling)
  - Time constraint: 2-week assessment window
  - Key question: "Is the platform adequately secured for PCI-DSS certification?"
```

**Phase 2 — Perspective Generation**

```
WHEN: generating attacker perspective
THEN: produce analysis covering:
  - Attack surface: login, search, payment callback, file upload, admin panel
  - Top attack paths:
    1. SQL injection via search (product catalog query)
    2. XSS via product reviews (stored XSS)
    3. CSRF on payment confirmation (missing token validation)
    4. Admin panel brute force (no rate limiting)
  - Exploit chain: stored XSS -> session hijack -> admin access -> data exfiltration
  - Blast radius: customer PII, payment data, order history

WHEN: generating defender perspective
THEN: produce analysis covering:
  - Controls present: parameterized queries (mostly), CSP headers, HTTPS enforcement
  - Controls missing: rate limiting on auth, WAF, input sanitization on reviews
  - Detection gaps: no alerting on repeated failed logins, no anomalous query detection
  - Hardening priorities: (1) add rate limiting, (2) deploy WAF, (3) sanitize review input
  - Estimated MTTD for top attack paths: 4-24 hours (without improvements)

WHEN: generating auditor perspective
THEN: produce analysis covering:
  - PCI-DSS Requirement 6 (secure coding): partially met (parameterized queries present)
  - PCI-DSS Requirement 8 (authentication): gap found (no MFA for admin, no rate limiting)
  - PCI-DSS Requirement 10 (logging): gap found (insufficient audit trail for admin actions)
  - GDPR Article 32 (security of processing): partially met
  - Evidence gaps: missing penetration test report, incomplete vulnerability scan records
```

**Phase 3 — Cross-Validation**

```
WHEN: cross-validating perspectives
THEN: identify:
  - Agreement: All perspectives flag authentication weaknesses as top risk
  - Agreement: All perspectives flag admin panel as critical exposure
  - Disagreement: Attacker rates search injection as Critical (score 20), Defender rates
    it as High (score 12) due to parameterized queries on most endpoints
  - Discovery: Auditor identifies logging gap that Attacker overlooked (no audit trail
    means attacker activity is harder to detect post-breach)
```

**Phase 4 — Consensus Building**

```
WHEN: building consensus
THEN: produce:
  - Agreed: Admin panel requires immediate hardening (MFA + rate limiting)
  - Agreed: Review input sanitization is high priority (stored XSS risk)
  - Disagreed: Severity of search endpoint SQLi (attacker says Critical, defender says High)
  - Open question: Is Stripe webhook signature validation implemented? (needs code review)
  - Recommendation: Harden admin panel first, then search endpoint, then logging gaps
  - Confidence: High (4/5)
```

**Pass Criteria**:
- [ ] All three perspectives generated with distinct viewpoints
- [ ] At least one finding unique to each perspective
- [ ] Cross-validation identified at least 2 agreements and 1 disagreement
- [ ] Consensus produced a prioritized recommendation with confidence level
- [ ] PCI-DSS compliance gaps documented with specific requirement numbers

---

## TC-CL-002: Cloud Architecture Security Assessment

**Objective**: Validate council analysis for complex multi-cloud Kubernetes infrastructure

**Scenario**: Organization running workloads across AWS and GCP with Kubernetes clusters, managed databases, serverless functions, and CI/CD pipelines. SOC 2 Type II audit upcoming.

**Phase 1 — Scope Definition**

```
GIVEN: Multi-cloud deployment
  - AWS: EKS clusters (3), RDS PostgreSQL, S3 buckets, Lambda functions
  - GCP: GKE cluster (1), Cloud SQL, Cloud Functions, GCS buckets
  - CI/CD: GitHub Actions with self-hosted runners
  - Compliance: SOC 2 Type II, internal security policy
WHEN: defining council scope
THEN: scope covers:
  - Cloud infrastructure, K8s clusters, IAM policies, network configuration
  - CI/CD pipeline security, secret management, logging/monitoring
  - Key question: "Are cloud workloads secured for SOC 2 Type II certification?"
```

**Phase 2 — Perspective Generation**

```
WHEN: generating attacker perspective
THEN: produce analysis covering:
  - Cloud enumeration: public S3 buckets, exposed API endpoints, SSRF via Lambda
  - IAM analysis: over-permissive service accounts, cross-account trust policies
  - K8s attack surface: default ServiceAccount tokens, missing network policies
  - CI/CD risks: self-hosted runner compromise, supply chain via dependency confusion
  - Top exploit chain: SSRF in Lambda -> IMDS credential theft -> cross-service access

WHEN: generating defender perspective
THEN: produce analysis covering:
  - Network segmentation: VPC configuration, security group rules, firewall policies
  - Encryption: at rest (KMS-managed keys), in transit (TLS everywhere verified)
  - IAM least privilege: gaps in 3 service accounts with admin-level permissions
  - Logging: CloudTrail enabled (AWS), Cloud Audit Logs (GCP), but gaps in Lambda logs
  - Backup: automated snapshots for RDS, but no tested restore procedure

WHEN: generating auditor perspective
THEN: produce analysis covering:
  - SOC 2 CC6 (logical access): IAM policies documented but 3 exceptions found
  - SOC 2 CC7 (system operations): monitoring gaps on 2 Lambda functions
  - SOC 2 CC8 (change management): CI/CD pipeline lacks security scan step
  - Evidence: IAM policy review document outdated (last updated 6 months ago)
  - Gap: No formal cloud security architecture review on record
```

**Phase 3 — Cross-Validation**

```
WHEN: cross-validating
THEN: identify:
  - Agreement: Over-permissive service accounts are the top risk across all perspectives
  - Agreement: CI/CD pipeline needs security hardening before SOC 2 audit
  - Discovery: Attacker found SSRF path that Defender assumed was blocked by IMDSv2
    (Attacker: "IMDSv2 not enforced on 1 of 3 EKS clusters")
  - Discovery: Auditor identified missing architecture review that both Attacker and
    Defender assumed existed
```

**Phase 4 — Consensus Building**

```
WHEN: building consensus
THEN: produce:
  - Critical: Enforce IMDSv2 on all EKS clusters immediately
  - Critical: Reduce IAM permissions for 3 over-permissive service accounts
  - High: Add security scanning step to CI/CD pipeline
  - Medium: Complete cloud security architecture review documentation
  - Open question: Are GCS buckets using uniform bucket-level access? (needs verification)
  - Confidence: Medium-High (3.5/5) — cloud environments are complex, some areas unverified
```

**Pass Criteria**:
- [ ] Both AWS and GCP environments analyzed
- [ ] Kubernetes-specific risks identified from attacker perspective
- [ ] SOC 2 control families mapped to specific findings
- [ ] Cross-cloud risks (IAM, networking) addressed
- [ ] Remediation prioritized with cloud-specific action items

---

## TC-CL-003: Mobile Application Security Evaluation

**Objective**: Validate council analysis for mobile app security with biometric authentication

**Scenario**: Fintech mobile application (iOS and Android) with biometric login, API communication, transaction signing, and local data storage. PCI-DSS and PSD2 compliance required.

**Phase 1 — Scope Definition**

```
GIVEN: Fintech mobile app (PaySecure)
  - Platforms: iOS (Swift), Android (Kotlin)
  - Features: biometric auth, PIN fallback, transaction signing, push notifications
  - Backend: REST API with JWT, transaction service, notification service
  - Compliance: PCI-DSS (payment data), PSD2 (Strong Customer Authentication)
WHEN: defining council scope
THEN: scope covers:
  - Mobile app (both platforms), API backend, authentication flow, data storage
  - Key question: "Is the biometric authentication implementation secure against bypass?"
```

**Phase 2 — Perspective Generation**

```
WHEN: generating attacker perspective
THEN: produce analysis covering:
  - Biometric bypass: Frida instrumentation to hook LAContext.evaluatePolicy on iOS
  - APK/IPA analysis: decompile to find hardcoded keys, API endpoints, logic flaws
  - Certificate pinning: test bypass via SSL kill switch or Frida scripts
  - Local storage: check Keychain/Keystore usage vs. SharedPreferences/plist storage
  - API security: test token refresh flow, session management, rate limiting
  - Top exploit chain: bypass certificate pinning -> intercept API traffic ->
    replay transaction signing token

WHEN: generating defender perspective
THEN: produce analysis covering:
  - Biometric implementation: uses Keychain (iOS) and Keystore (Android) — secure
  - Certificate pinning: implemented but with fallback (potential weakness)
  - Data storage: sensitive data in Keychain/Keystore, non-sensitive in UserDefaults
  - Detection: no runtime integrity checking (jailbreak/root detection bypass possible)
  - Hardening: add runtime integrity checks, remove certificate pinning fallback,
    implement app attestation

WHEN: generating auditor perspective
THEN: produce analysis covering:
  - PSD2 SCA: biometric auth meets requirement, but PIN fallback needs rate limiting
  - PCI-DSS 3.4: payment data rendered unreadable during local storage — verified
  - PCI-DSS 6.5: secure coding practices — certificate pinning fallback is a deviation
  - Gap: no documented mobile security testing report
  - Gap: privacy policy does not disclose biometric data handling practices
```

**Phase 3 — Cross-Validation**

```
WHEN: cross-validating
THEN: identify:
  - Agreement: Certificate pinning fallback is a shared concern across perspectives
  - Agreement: Runtime integrity checks are missing (jailbreak/root detection)
  - Conflict: Attacker rates biometric bypass as High risk (Frida hooking is reliable),
    Defender rates it as Medium (requires physical access or compromised device)
  - Discovery: Auditor found PSD2 compliance gap in PIN fallback that neither
    Attacker nor Defender flagged (no rate limiting on PIN = SCA bypass)
```

**Phase 4 — Consensus Building**

```
WHEN: building consensus
THEN: produce:
  - Critical: Add rate limiting to PIN fallback (PSD2 compliance gap + brute force risk)
  - High: Remove certificate pinning fallback or add additional verification
  - High: Implement runtime integrity checks (jailbreak/root detection)
  - Medium: Update privacy policy for biometric data handling
  - Open question: Is transaction signing performed server-side or client-side?
  - Confidence: High (4/5) — biometric implementation fundamentally sound,
    gaps are in surrounding controls
```

**Pass Criteria**:
- [ ] Both iOS and Android platforms addressed
- [ ] Biometric authentication bypass tested from attacker perspective
- [ ] PSD2 SCA compliance verified with specific requirements
- [ ] Certificate pinning implementation evaluated
- [ ] Local data storage security assessed per platform

---

## TC-CL-004: Incident Response Decision Simulation

**Objective**: Validate council analysis under incident conditions with time pressure

**Scenario**: Active security breach detected. Monitoring shows unauthorized lateral movement from a compromised web server to internal database server. Data exfiltration suspected. Customer PII may be affected.

**Phase 1 — Scope Definition (Compressed)**

```
GIVEN: Active breach detected 45 minutes ago
  - Compromised: web server (DMZ) -> database server (internal)
  - Indicator: unusual outbound traffic from DB server, 2GB transferred
  - Data at risk: customer PII (names, emails, hashed passwords)
  - Compliance: GDPR (72-hour notification requirement), breach insurance policy active
  - Urgency: HIGH — attacker may still be active
WHEN: defining council scope (5-minute timebox)
THEN: scope covers:
  - Immediate containment decision
  - Evidence preservation requirements
  - Regulatory notification obligations
  - Key question: "Contain now or observe to gather more intelligence?"
```

**Phase 2 — Perspective Generation (Compressed, 15 minutes)**

```
WHEN: generating attacker perspective
THEN: rapid analysis:
  - Current position: has DB access, likely establishing persistence
  - Predicted next move: privilege escalation to domain admin, or exfiltrate remaining
    data before detection response
  - If contained now: attacker may have already planted backdoor, containment triggers
    attacker awareness
  - If observed: risk of additional data exfiltration, but better intelligence
  - Attacker recommendation: observe for 30 minutes, monitor outbound traffic

WHEN: generating defender perspective
THEN: rapid analysis:
  - Containment options: isolate DB server at network level, block outbound traffic
  - Risk of containment: attacker may have persistence mechanisms elsewhere
  - Risk of NOT containing: 2GB already exfiltrated, more at risk
  - Evidence preservation: need memory dump and disk image before containment
  - Defender recommendation: block outbound traffic immediately, isolate DB server,
    preserve evidence in parallel

WHEN: generating auditor perspective
THEN: rapid analysis:
  - GDPR 72-hour clock started when breach was detected (45 minutes ago)
  - Evidence chain of custody: must be preserved BEFORE containment actions
  - Notification: DPA and affected individuals within 72 hours
  - Documentation: every decision and action must be timestamped and logged
  - Auditor recommendation: preserve evidence first (15 minutes), then contain,
    start GDPR notification clock documentation immediately
```

**Phase 3 — Cross-Validation (5 minutes)**

```
WHEN: cross-validating under pressure
THEN: identify:
  - Agreement: outbound traffic must be blocked (prevents further exfiltration)
  - Conflict: Attacker says observe, Defender says contain now, Auditor says preserve
    evidence first then contain
  - Resolution: Auditor's approach satisfies Defender's containment need AND
    preserves evidence. Attacker's observation desire is overridden by ongoing
    exfiltration risk.
  - Decision: 15 minutes for evidence preservation -> then full containment
```

**Phase 4 — Decision Output**

```
WHEN: producing decision
THEN: output:
  - Decision: 15-minute evidence preservation window, then isolate DB server
  - Immediate actions (next 15 minutes):
    1. Start forensic imaging of DB server memory and disk
    2. Block outbound traffic from DB server (prevent further exfiltration)
    3. Capture network traffic logs from last 48 hours
    4. Begin GDPR breach documentation
  - Containment actions (after 15 minutes):
    5. Isolate DB server at network level
    6. Disable compromised service account
    7. Force password reset for all admin accounts
  - Notification (within 72 hours):
    8. Notify DPA (Data Protection Authority)
    9. Prepare customer notification
  - Confidence: Medium (3/5) — decisions made under uncertainty, may need revision
  - Dissent: Attacker perspective notes 15-minute window may allow attacker to
    plant additional persistence. Accepted as residual risk.
```

**Pass Criteria**:
- [ ] Decision produced within 30-minute timebox
- [ ] All three perspectives contributed to the decision
- [ ] GDPR 72-hour requirement explicitly addressed
- [ ] Evidence preservation prioritized before containment
- [ ] Dissenting views documented (attacker's observation preference)
- [ ] Action items have clear owners and timeframes
- [ ] Decision confidence explicitly stated as lower due to time pressure
