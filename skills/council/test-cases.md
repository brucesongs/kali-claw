# Council Test Cases

## Test Case Summary

| ID | Name | Scenario | Status |
|----|------|----------|--------|
| TC-CL-001 | Web Application Security Review | E-commerce platform with payment flow | Active |
| TC-CL-002 | Cloud Architecture Security Assessment | Multi-cloud K8s deployment | Active |
| TC-CL-003 | Mobile Application Security Evaluation | Fintech app with biometric auth | Active |
| TC-CL-004 | Incident Response Decision Simulation | Active breach with lateral movement | Active |
| TC-CL-005 | Automated Consensus Scoring | Quantitative agreement measurement across perspectives | Active |

Total: 5 test cases

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

---

## TC-CL-005: Automated Consensus Scoring

**Objective**: Validate quantitative consensus measurement across three perspectives using weighted voting

**Severity**: MEDIUM

**Prerequisites**: Council session with 10+ findings from all three perspectives, scoring algorithm implemented

**Scenario**: Automated system processes findings from attacker, defender, and auditor perspectives, calculates agreement scores, resolves disagreements via weighted voting, and produces a confidence-rated recommendation.

**Phase 1 — Input Preparation**

```
GIVEN: 12 findings across 3 perspectives:
  - Attacker: 5 findings (2 Critical, 2 High, 1 Medium)
  - Defender: 4 findings (1 Critical, 2 High, 1 Medium)
  - Auditor: 3 findings (1 Critical, 1 High, 1 Medium)
  
  Overlapping topics:
  - "Auth bypass" flagged by all 3 (agreement)
  - "Rate limiting" flagged by Attacker (Critical) and Defender (High) — disagreement
  - "Logging gap" flagged only by Auditor (unique insight)
```

**Phase 2 — Consensus Calculation**

```
WHEN: Running consensus algorithm with weights:
  - Attacker weight: 0.40 (offensive expertise)
  - Defender weight: 0.35 (operational context)
  - Auditor weight: 0.25 (compliance authority)

THEN: Calculate:
  - Agreement score: topics where all perspectives align / total topics
  - Weighted severity for disagreements
  - Unique insight bonus (findings from single perspective get flagged for review)
  
Expected output:
  - Agreement rate: 0.60 (6/10 topics agreed)
  - Disagreement resolution: 3 topics resolved via weighted vote
  - Unique insights: 1 (auditor logging gap)
  - Overall confidence: 0.72
```

**Phase 3 — Output Validation**

```
THEN: Verify output contains:
  - Ranked finding list (by final risk score)
  - Agreement/disagreement classification for each finding
  - Confidence score between 0 and 1
  - Dissenting views preserved (not discarded)
  - Actionable recommendation with owner assignment
```

**Steps**:
1. Prepare 12 findings with known overlaps and disagreements
2. Run consensus scoring algorithm
3. Verify agreement detection is correct
4. Verify weighted voting resolves disagreements correctly
5. Verify unique insights are flagged (not lost)
6. Validate final confidence score calculation

**Expected Output**:
- Consensus report with agreement rate, resolved disagreements, and confidence score
- All findings ranked by final severity
- Dissenting views documented with perspective attribution
- Recommendation with confidence level

**Pass Criteria**:
- [ ] Agreement detection correctly identifies overlapping topics
- [ ] Weighted voting produces deterministic severity resolution
- [ ] Unique insights (single-perspective findings) are preserved and flagged
- [ ] Confidence score reflects actual agreement level (not inflated)
- [ ] Dissenting views retained in output (not silently dropped)
- [ ] Final recommendation is actionable with assigned owners

**Verification**: Compare algorithm output against manually calculated expected values for the 12-finding test set

---

## TC-CL-006: Consensus on Conflicting Findings

**Objective**: Validate that the council resolves contradictory findings from different perspectives where the attacker perspective claims a vulnerability is exploitable (Critical) while the defender perspective provides evidence that a compensating control blocks exploitation, requiring the council to reach a consensus severity.

**Severity**: HIGH

**Prerequisites**: Council session with at least three perspectives, conflicting evidence for the same finding, mediator role defined

**Scenario**: An internal API endpoint has no authentication token validation (attacker finding) but sits behind a VPN that requires mutual TLS and hardware token authentication (defender evidence). The auditor notes this violates the defense-in-depth principle but agrees the practical exploitability is limited.

**Phase 1 — Conflicting Evidence Presentation**

```
GIVEN: Finding "Unauthenticated API endpoint at /api/v2/admin/users"
  - Attacker perspective:
    - Confirmed: no Authorization header required
    - Confirmed: returns 200 with user data
    - Severity: Critical (unauthenticated data access)
    - Evidence: curl -s http://internal-api.corp/api/v2/admin/users returns full user list
  - Defender perspective:
    - Confirmed: endpoint requires VPN connection (mutual TLS + hardware token)
    - Confirmed: endpoint is not accessible from corporate LAN, only from VPN CIDR
    - Confirmed: VPN session timeout is 8 hours with re-authentication required
    - Severity: Low (compensating controls block external access)
    - Evidence: network diagram + VPN configuration + firewall rules
  - Auditor perspective:
    - Finding: violates defense-in-depth (no application-layer auth)
    - Risk: if VPN is compromised, API has no additional protection
    - Compliance: internal policy requires application-layer auth for PII data
    - Severity: Medium (policy violation + residual risk)
```

**Phase 2 — Structured Debate**

```
WHEN: mediator facilitates structured debate
THEN:
  1. Attacker presents exploitation evidence (curl from VPN-connected machine)
  2. Defender presents compensating control evidence (VPN MFA, network segmentation)
  3. Auditor presents policy compliance gap (no defense-in-depth)
  4. Each perspective rates exploitability:
     - Attacker: exploitable IF VPN access obtained (conditional)
     - Defender: not exploitable from external (blocked by VPN)
     - Auditor: exploitable under VPN compromise scenario (plausible)
```

**Phase 3 — Consensus Resolution**

```
WHEN: building consensus
THEN: produce:
  - Agreed severity: MEDIUM (not Critical — compensating controls exist; not Low — policy gap present)
  - Exploitability: conditional on VPN compromise (reduced from Critical)
  - Business impact: PII exposure if VPN is compromised (retained from Critical)
  - Compliance impact: policy violation confirmed (retained from Auditor)
  - Recommendation: add application-layer authentication to API endpoint (defense-in-depth)
  - Confidence: High (4/5) — all perspectives agree on the finding, disagreement is on severity
  - Dissent: Attacker maintains severity should be High (not Medium) due to VPN compromise risk
  - Dissent documented and preserved
```

**Steps**:
1. Present all three perspectives with evidence
2. Facilitate structured debate (5 minutes per perspective)
3. Calculate weighted severity scores (attacker 0.40, defender 0.35, auditor 0.25)
4. Identify points of agreement and disagreement
5. Reach consensus on severity with documented dissent
6. Produce recommendation with action items

**Expected Result**: Consensus severity of Medium with documented attacker dissent, actionable remediation (add app-layer auth), and preserved dissenting opinion

**Remediation**: Add application-layer authentication (JWT or API key) to the admin API endpoint, implement defense-in-depth

**Pass Criteria**:
- [ ] All three perspectives presented with distinct evidence
- [ ] Compensating controls evaluated and weighed against exploitability
- [ ] Final severity reflects both exploitability (reduced by VPN) and compliance gap (policy violation)
- [ ] Dissenting view (attacker's High severity preference) explicitly documented
- [ ] Recommendation is actionable (specific fix, not "review security")
- [ ] Confidence level reflects the disagreement (not inflated to 5/5)

---

## TC-CL-007: Cross-Domain Risk Assessment

**Objective**: Validate that the council can assess risks spanning multiple security domains (network, application, cloud, compliance) for a single finding that has implications across all domains, producing a unified risk score and domain-specific remediation actions.

**Severity**: HIGH

**Prerequisites**: Council session with experts covering network security, application security, cloud security, and compliance domains; complex finding with cross-domain impact

**Scenario**: A misconfigured AWS S3 bucket is publicly accessible and contains database backup files with customer PII. This single finding impacts cloud security (misconfiguration), data security (PII exposure), compliance (GDPR breach), application security (data used by application), and network security (public internet exposure).

**Phase 1 — Domain-Specific Analysis**

```
GIVEN: Finding "Public S3 bucket with customer PII database backups"
  EACH domain expert produces independent assessment:

  Network Security:
    - Exposure: publicly accessible from any IP
    - Access log: S3 access logs show 47 downloads from 12 unique IPs
    - Blast radius: internet-scale exposure
    - Domain severity: Critical

  Application Security:
    - Data: backups contain user table (email, password hash, address)
    - Password hashing: bcrypt (work factor 10) — moderate protection
    - Data currency: backup from 3 months ago (some stale data)
    - Domain severity: High

  Cloud Security:
    - Misconfiguration: S3 bucket ACL allows public read
    - Root cause: no S3 Bucket Policy enforcing private access
    - Similar buckets: scan shows 3 other buckets with same ACL pattern
    - Domain severity: Critical (systemic misconfiguration)

  Compliance:
    - GDPR Article 5: personal data processed without appropriate security
    - GDPR Article 32: encryption not applied to data at rest
    - GDPR Article 33: 72-hour breach notification required
    - Breach scope: estimated 50,000+ customer records
    - Domain severity: Critical (mandatory notification)
```

**Phase 2 — Cross-Domain Impact Correlation**

```
WHEN: correlating domain assessments
THEN: identify:
  - Amplification: network exposure + cloud misconfiguration = systemic risk
  - Compliance trigger: PII + public access = mandatory GDPR notification
  - Secondary impact: similar buckets not yet confirmed leaking = potential scope expansion
  - Root cause: cloud infrastructure-as-code template lacks S3 policy controls
  - Timeline: 47 downloads already occurred — data already exfiltrated
```

**Phase 3 — Unified Risk Scoring**

```
WHEN: producing unified risk assessment
THEN: output:
  - Overall severity: Critical
  - Domain breakdown: Network (Critical), Application (High), Cloud (Critical), Compliance (Critical)
  - Unified CVSS-like score: 9.1 (calculated from domain maximums weighted by business impact)
  - Time sensitivity: IMMEDIATE (GDPR 72-hour clock started when discovered)
  - Financial impact estimate: regulatory fine potential ($2M-$10M range for GDPR)
  - Remediation priority matrix:
    1. IMMEDIATE: restrict S3 bucket access (5 minutes)
    2. IMMEDIATE: assess data scope for breach notification (1 hour)
    3. URGENT: scan and fix remaining 3 similar buckets (4 hours)
    4. SHORT-TERM: fix IaC template to prevent recurrence (1 week)
    5. ONGOING: GDPR notification and customer communication (per regulatory timeline)
```

**Steps**:
1. Each domain expert produces independent assessment with domain-specific severity
2. Correlate domain assessments to identify amplification and secondary impacts
3. Calculate unified risk score from domain maximums
4. Prioritize remediation actions across domains
5. Assign domain-specific action owners with deadlines
6. Produce unified risk report

**Expected Result**: Unified risk assessment with domain breakdown, unified severity (Critical), time-sensitive remediation priorities, and domain-specific action owners

**Remediation**: Restrict S3 bucket immediately, assess breach scope for GDPR notification, fix IaC templates, scan remaining buckets

**Pass Criteria**:
- [ ] Each security domain produced independent assessment with domain-specific severity
- [ ] Cross-domain amplification effects identified (exposure + PII + compliance)
- [ ] Unified risk score calculated from domain assessments (not arbitrary)
- [ ] Remediation actions assigned to domain experts with deadlines
- [ ] GDPR notification timeline explicitly addressed
- [ ] Similar infrastructure patterns flagged for proactive scanning
- [ ] Financial impact estimate included for business context

---

## TC-CL-008: Bias Detection in Multi-Perspective Analysis

**Objective**: Validate that the council can detect and mitigate analytical biases in multi-perspective analysis, specifically: confirmation bias (seeking only supporting evidence), anchoring bias (overweighting the first finding), and authority bias (deferring to the most experienced perspective without challenge).

**Severity**: MEDIUM

**Prerequisites**: Council session with known bias injection points, mediator role trained in bias detection, multiple perspectives with varying experience levels

**Scenario**: A security assessment of a web application where the attacker perspective (senior pentester) immediately identifies SQL injection and anchors the entire council discussion around it, potentially causing other perspectives to overlook a more critical but less obvious finding (business logic flaw allowing fund transfers).

**Phase 1 — Baseline Assessment (Bias Injection)**

```
GIVEN: Web application assessment for fintech platform
  INJECTED BIASES:
  1. Anchoring bias:
     - Attacker (senior, 15 years) immediately finds SQL injection
     - All subsequent discussion centers on SQLi severity
     - Other perspectives unconsciously frame their findings relative to SQLi

  2. Confirmation bias:
     - Defender perspective only looks for controls related to SQL injection
     - Ignores business logic endpoints because they "don't have SQL"

  3. Authority bias:
     - Auditor defers to attacker's severity rating without independent assessment
     - Says "if [senior pentester] says Critical, I trust that"

  HIDDEN CRITICAL FINDING (that bias causes council to deprioritize):
  - Business logic flaw: /api/transfer allows negative amounts (money reversal)
  - No SQL injection, no auth bypass — pure logic error
  - Impact: attacker can transfer money from any account to their own
```

**Phase 2 — Bias Detection**

```
WHEN: mediator runs bias detection checklist
THEN: detect:

  1. Anchoring bias detection:
     - Check: has the council discussed findings OTHER than SQLi?
     - Check: has any perspective independently assessed severity without referencing SQLi?
     - Flag: 80% of discussion time spent on SQLi — anchoring detected

  2. Confirmation bias detection:
     - Check: has defender assessed controls for ALL finding types?
     - Check: has auditor verified SQLi severity independently (not just agreed)?
     - Flag: defender only assessed SQLi-related controls — confirmation bias detected

  3. Authority bias detection:
     - Check: has auditor provided independent severity rationale?
     - Check: has any perspective challenged the attacker's assessment?
     - Flag: auditor used "I trust that" language — authority bias detected
```

**Phase 3 — Bias Mitigation**

```
WHEN: applying bias mitigation techniques
THEN:
  1. Blind re-assessment:
     - Ask each perspective to independently rate ALL findings without seeing others' ratings
     - Compare blind ratings to see if anchoring influenced scores

  2. Mandatory alternative analysis:
     - Each perspective must identify at least 1 finding NOT related to SQLi
     - Forces exploration beyond the anchored finding
     - This surfaces the business logic flaw

  3. Devil's advocate rotation:
     - Assign each perspective to argue AGAINST the current consensus
     - Defender argues why SQLi is less severe than claimed
     - Attacker argues why business logic flaw is MORE severe than SQLi

  4. Structured re-ranking:
     - All findings re-ranked after bias mitigation
     - Business logic flaw promoted from "Low" (buried by anchoring) to "Critical"
     - SQLi correctly rated as "High" (not inflated by anchoring)
```

**Phase 4 — Bias-Adjusted Consensus**

```
WHEN: producing final consensus
THEN: output:
  - Original consensus (biased): SQLi = Critical, Business Logic = Low
  - Bias-adjusted consensus: Business Logic = Critical, SQLi = High
  - Bias incidents detected: 3 (anchoring, confirmation, authority)
  - Mitigation actions applied: 4 (blind re-assessment, alternative analysis, devil's advocate, re-ranking)
  - Confidence: Medium (3/5) — bias was significant, some residual bias may remain
  - Lesson learned: always run bias detection before final consensus
```

**Steps**:
1. Conduct initial assessment with injected biases
2. Run bias detection checklist (3 bias types)
3. Apply mitigation techniques (blind re-assessment, alternative analysis, devil's advocate)
4. Re-rank findings after bias mitigation
5. Compare pre- and post-mitigation severity rankings
6. Document bias incidents and their impact on initial assessment

**Expected Result**: Bias-adjusted consensus that correctly identifies the business logic flaw as Critical (previously deprioritized due to anchoring), with documented bias incidents and mitigation actions

**Remediation**: Implement mandatory bias detection checklist for all council sessions, include blind re-assessment step in methodology

**Pass Criteria**:
- [ ] At least 2 of 3 bias types detected during analysis
- [ ] Bias mitigation changed at least one finding's severity ranking
- [ ] Business logic flaw correctly promoted to Critical after bias mitigation
- [ ] Blind re-assessment produced different severity rankings than biased assessment
- [ ] Devil's advocate rotation generated insights not previously discussed
- [ ] Bias incidents documented with specific examples of biased reasoning
- [ ] Final report includes bias detection section alongside findings
